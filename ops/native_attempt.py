"""One ordinary Slurm attempt owner. Operational evidence never accepts science.

Production entry points construct their own native readers. The Python constructor
seams are for SOURCE/L fixtures; passing a dictionary or an instance is no authority.
There is no retry worker, cancellation, profile bootstrap or scientific decoder.
"""
from contextlib import contextmanager
import base64
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import struct
import sys
import time
import uuid

import application_release as engine
from host_resource_backends import trusted_root_path
from host_resource_operations import ResourceError, strict_json
from release_trust import protected_directory, trusted_stat

POLICY = Path('/etc/qcl-negf/native-attempt/policy.json')
SOCKET = '/run/qcl-negf/native-attempt.sock'
FILES = {'plan': 'plan.json', 'source_graph': 'source-graph.json',
         'native_execution': 'native-execution.json', 'submit_script': '_aiidasubmit.sh'}
CLOSE_FILES = ('series_result.json', 'native-selection.json', '_scheduler-stdout.txt', '_scheduler-stderr.txt')
ID = r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}'
SHA = r'[0-9a-f]{64}'
JOB = r'[1-9][0-9]{0,9}'
LIMIT_KEYS = {'request_bytes', 'response_bytes', 'script_bytes', 'metadata_bytes', 'memory_bytes',
              'operation_seconds', 'command_seconds', 'cleanup_seconds', 'maximum_pids',
              'maximum_calls', 'maximum_files'}
POLICY_KEYS = {'schema', 'role', 'private_root', 'spool_root', 'socket_path', 'jobs_root',
               'native_result_prefix', 'nfs_source', 'storage_identity_file', 'release_runtime',
               'client_uid', 'daemon_unit', 'server_unit_prefix', 'slurmd_unit', 'tools', 'slurm',
               'facts_service_config', 'worker_routes', 'qualification_file', 'limits'}


class Hold(RuntimeError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def need(condition, reason='shape'):
    if not condition:
        raise Hold(reason)


def exact(value, keys):
    need(type(value) is dict and set(value) == set(keys))
    return value


def matches(value, pattern):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def canonical_uuid(value):
    try:
        need(type(value) is str and str(uuid.UUID(value)) == value and uuid.UUID(value).int != 0)
    except (ValueError, AttributeError) as error:
        raise Hold('shape') from error
    return value


def path_value(value, *, absolute):
    need(type(value) is str and len(value.encode()) <= 4096 and '\x00' not in value)
    need(value.startswith('/') == absolute)
    parts = value.split('/')[1:] if absolute else value.split('/')
    need(parts and all(p not in ('', '.', '..') for p in parts))
    return value


def within(path, root):
    return path == root or path.startswith(root.rstrip('/') + '/')


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def validate_limits(value):
    exact(value, LIMIT_KEYS)
    for key, item in value.items():
        need(type(item) in (int, float) and math.isfinite(item) and item > 0, 'policy_limits')
        if not key.endswith('_seconds'):
            need(type(item) is int, 'policy_limits')
    for key, cap in [('request_bytes', 65536), ('response_bytes', 262144),
                     ('script_bytes', 65536), ('maximum_pids', 256)]:
        need(value[key] <= cap, 'policy_limits')
    need(value['cleanup_seconds'] < value['command_seconds'] < value['operation_seconds'], 'policy_limits')
    need(value['metadata_bytes'] <= value['memory_bytes'] // 4, 'policy_limits')
    return value


class Operation:
    """One nonrefundable budget shared by socket, files, commands and journal."""
    def __init__(self, limits):
        self.limits = validate_limits(limits)
        self.started = time.monotonic()
        self.deadline = self.started + limits['operation_seconds']
        self.bytes = self.actual_bytes = self.calls = self.files = 0

    def before(self):
        need(time.monotonic() < self.deadline, 'operation_deadline')

    def reserve(self, size):
        self.before()
        need(type(size) is int and size >= 0, 'operation_bound')
        self.bytes += size
        need(self.bytes <= self.limits['metadata_bytes'], 'operation_bound')

    def file(self):
        self.before(); self.files += 1
        need(self.files <= self.limits['maximum_files'], 'operation_file_bound')

    def command(self, argv, *, env=None, run=engine.command, output_bytes=None):
        self.before(); self.calls += 1
        need(self.calls <= self.limits['maximum_calls'], 'operation_call_bound')
        cap = min(output_bytes or 65536, self.limits['response_bytes'])
        self.reserve(cap * 4)
        result = run(argv, timeout_seconds=self.limits['command_seconds'], output_bytes=cap,
                     deadline=self.deadline, cleanup_seconds=self.limits['cleanup_seconds'], env=env)
        self.before()
        return result

    def read(self, path, limit=65536):
        self.file(); raw = bytearray()
        with open(path, 'rb') as stream:
            while len(raw) <= limit:
                size = min(4096, limit + 1 - len(raw)); self.reserve(size)
                chunk = stream.read(size); self.actual_bytes += len(chunk)
                if not chunk:
                    self.before(); return bytes(raw)
                raw.extend(chunk)
        raise Hold('operation_bound')

    def stat(self, path, *, follow_symlinks=False):
        self.file(); result = os.stat(path, follow_symlinks=follow_symlinks); self.before()
        return result

    def link(self, path):
        self.reserve(4097); result = os.readlink(path); self.before()
        need(len(os.fsencode(result)) <= 4096, 'operation_bound')
        return result

    def entries(self, path, kind):
        with os.scandir(path) as iterator:
            for item in iterator:
                self.file()
                if kind != 'pid' or item.name.isdigit():
                    yield Path(item.path)


def validate_request(document):
    exact(document, {'version', 'action', 'calcjob_uuid', 'launch', 'controls'})
    need(type(document['version']) is int and document['version'] == 1)
    need(document['action'] in {'submit', 'reconcile', 'start', 'close', 'status'})
    canonical_uuid(document['calcjob_uuid'])
    launch = exact(document['launch'], {'request_id', 'run_uuid', 'execution_id', 'transport_attempt',
                    'code_uuid', 'release_id', 'native_execution_uuid', 'input_plan_uuid',
                    'source_graph_uuid', 'relative_execution_root', 'remote_workdir', 'files'})
    for key in ('request_id', 'run_uuid', 'code_uuid', 'native_execution_uuid', 'input_plan_uuid', 'source_graph_uuid'):
        canonical_uuid(launch[key])
    need(matches(launch['execution_id'], ID) and matches(launch['release_id'], ID))
    need(type(launch['transport_attempt']) is int and launch['transport_attempt'] > 0)
    path_value(launch['relative_execution_root'], absolute=False)
    path_value(launch['remote_workdir'], absolute=True)
    exact(launch['files'], FILES)
    for claim in launch['files'].values():
        exact(claim, {'bytes', 'sha256'})
        need(type(claim['bytes']) is int and claim['bytes'] >= 0 and matches(claim['sha256'], SHA))
    controls = document['controls']
    if document['action'] == 'close':
        need(type(controls) is list and len(controls) <= 5)
        for claim in controls:
            exact(claim, {'path', 'bytes', 'sha256'})
            path_value(claim['path'], absolute=False)
            need(type(claim['bytes']) is int and claim['bytes'] >= 0 and matches(claim['sha256'], SHA))
        need(len({c['path'] for c in controls}) == len(controls))
    else:
        need(controls is None)
    return document


def reply(document, state, *, job=None, reason=None, receipt=None, controls=None):
    return dict(version=1, state=state, calcjob_uuid=document.get('calcjob_uuid'), receipt_ref=receipt,
                job=job, controls=controls, reason=reason)


def validate_job(job):
    exact(job, {'job_id', 'cluster', 'submit_time', 'controller_machine_id', 'controller_boot_id',
                'dispatch_id', 'generation', 'node_name', 'start_time', 'worker_machine_id', 'worker_boot_id'})
    need(matches(job['job_id'], JOB) and matches(job['cluster'], ID) and matches(job['generation'], SHA), 'job_binding')
    need(matches(job['controller_machine_id'], r'[0-9a-f]{32}'), 'job_binding')
    for key in ('controller_boot_id', 'dispatch_id'):
        canonical_uuid(job[key])
    need(type(job['submit_time']) is str and 0 < len(job['submit_time']) <= 64, 'job_binding')
    allocation = [job[key] for key in ('node_name', 'start_time', 'worker_machine_id', 'worker_boot_id')]
    need(all(value is None for value in allocation) or all(value is not None for value in allocation), 'job_binding')
    if allocation[0] is not None:
        need(matches(job['node_name'], ID) and matches(job['worker_machine_id'], r'[0-9a-f]{32}') and
             matches(job['start_time'], r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}'), 'job_binding')
        canonical_uuid(job['worker_boot_id'])
    return job


def validate_reply(document):
    exact(document, {'version', 'state', 'calcjob_uuid', 'receipt_ref', 'job', 'controls', 'reason'})
    need(type(document['version']) is int and document['version'] == 1 and
         document['state'] in {'bound', 'started', 'closed', 'hold', 'rejected'}, 'reply_shape')
    if document['calcjob_uuid'] is not None:
        canonical_uuid(document['calcjob_uuid'])
    if document['receipt_ref'] is not None:
        need(type(document['receipt_ref']) is str and len(document['receipt_ref']) <= 256, 'reply_shape')
    if document['job'] is not None:
        validate_job(document['job'])
    if document['state'] in {'hold', 'rejected'}:
        need(matches(document['reason'], ID) and document['controls'] is None, 'reply_shape')
    else:
        need(document['job'] is not None and document['calcjob_uuid'] is not None and document['reason'] is None, 'reply_shape')
        need(document['state'] == 'closed' or document['controls'] is None, 'reply_shape')
        if document['state'] == 'started':
            need(document['job']['node_name'] is not None, 'reply_shape')
        if document['state'] == 'closed':
            need(type(document['controls']) is list and 0 < len(document['controls']) <= 5, 'reply_shape')
            for control in document['controls']:
                exact(control, {'path', 'bytes', 'sha256'}); path_value(control['path'], absolute=False)
                need(type(control['bytes']) is int and control['bytes'] >= 0 and matches(control['sha256'], SHA), 'reply_shape')
            _close_controls(document['controls'])
            need(document['receipt_ref'] == document['calcjob_uuid'] + '/close.json', 'reply_binding')
    return document


def _close_controls(controls):
    need(type(controls) is list and len(controls) == 4, 'q1_controls_unavailable')
    result = []
    for name, cap, row in zip(CLOSE_FILES, (33554432, 262144, 65536, 65536), controls):
        exact(row, {'path','bytes','sha256'})
        need(row['path'] == name and type(row['bytes']) is int and 0 <= row['bytes'] <= cap and
             matches(row['sha256'], SHA), 'q1_controls_unavailable')
        result.append(dict(row))
    return result


def signature(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_fd(fd, limit, budget):
    budget.file(); initial = os.fstat(fd)
    need(stat.S_ISREG(initial.st_mode) and initial.st_nlink == 1 and initial.st_size <= limit, 'file_identity')
    raw = bytearray()
    while len(raw) <= limit:
        budget.reserve(min(65536, limit + 1 - len(raw)))
        chunk = os.read(fd, min(65536, limit + 1 - len(raw)))
        budget.actual_bytes += len(chunk)
        if not chunk:
            break
        raw.extend(chunk)
    budget.before()
    need(len(raw) <= limit and len(raw) == initial.st_size and signature(os.fstat(fd)) == signature(initial), 'file_changed')
    return bytes(raw), initial


def protected_read(path, budget, limit=65536):
    """Protected ancestry and same-FD + named-inode readback; no pathname reopen."""
    path = Path(path)
    with protected_directory(path.parent, budget=budget) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            raw, info = read_fd(fd, limit, budget)
            trusted_stat(info, directory=False)
            need(signature(info) == signature(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'file_changed')
            return raw
        finally:
            os.close(fd)


class AttemptStore:
    """Root-local append-only records. Existing partial records are never repaired."""
    def __init__(self, root):
        self.root = Path(root)

    @contextmanager
    def directory(self, path, *, create=False):
        if create:
            try:
                path.mkdir(mode=0o700)
            except FileExistsError:
                pass
            else:
                parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077, 'journal_namespace')
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            need(signature(info) == signature(os.fstat(fd)), 'journal_namespace')
            yield fd
            named = path.lstat()
            need((named.st_dev, named.st_ino) == (info.st_dev, info.st_ino), 'journal_namespace')
        finally:
            os.close(fd)

    @contextmanager
    def locked(self, calcjob, budget):
        canonical_uuid(calcjob)
        with self.directory(self.root):
            locks = self.root / 'locks'
            with self.directory(locks, create=True) as parent:
                budget.file()
                fd = os.open(calcjob, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
                try:
                    info = os.fstat(fd)
                    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
                         not info.st_mode & 0o077 and info.st_nlink == 1, 'journal_namespace')
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError as error:
                        raise Hold('attempt_busy') from error
                    budget.before(); yield
                finally:
                    os.close(fd)

    def path(self, calcjob):
        canonical_uuid(calcjob)
        return self.root / 'attempts' / calcjob

    def claim_domain(self, calcjob, domain, budget):
        path_value(domain, absolute=False)
        # A short admission lock covers only bounded metadata, never a solve.
        admission = str(uuid.uuid5(uuid.NAMESPACE_URL, 'qcl-native-output-domain-admission'))
        with self.locked(admission, budget):
            directory = self.root / 'domains'
            with self.directory(directory, create=True) as parent:
                for path in budget.entries(directory, 'domain'):
                    need(matches(path.name, SHA), 'journal_namespace')
                    fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                    try:
                        raw, info = read_fd(fd, 65536, budget)
                        need(info.st_uid == os.geteuid() and not info.st_mode & 0o077, 'journal_namespace')
                        record = exact(strict_json(raw.decode()), {'calcjob_uuid', 'domain'})
                        canonical_uuid(record['calcjob_uuid']); path_value(record['domain'], absolute=False)
                        need(hashlib.sha256(record['domain'].encode()).hexdigest() == path.name and
                             signature(info) == signature(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'journal_namespace')
                        if within(domain, record['domain']) or within(record['domain'], domain):
                            need(record == {'calcjob_uuid': calcjob, 'domain': domain}, 'output_domain_claimed')
                            return
                    finally:
                        os.close(fd)
                raw = encoded({'calcjob_uuid': calcjob, 'domain': domain}); budget.reserve(len(raw)); budget.file()
                name = hashlib.sha256(domain.encode()).hexdigest()
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
                try:
                    offset = 0
                    while offset < len(raw):
                        budget.before(); count = os.write(fd, raw[offset:]); need(count > 0, 'journal_short_write'); offset += count
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(parent)

    def read(self, calcjob, name, budget):
        path = self.path(calcjob)
        if not path.exists():
            return None
        with self.directory(path) as parent:
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            except FileNotFoundError:
                return None
            try:
                raw, info = read_fd(fd, 65536, budget)
                need(info.st_uid == os.geteuid() and not info.st_mode & 0o077 and
                     signature(info) == signature(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'journal_namespace')
                return strict_json(raw.decode())
            finally:
                os.close(fd)

    def put(self, calcjob, name, value, budget):
        raw = encoded(value)
        need(len(raw) <= 65536, 'journal_bound')
        budget.reserve(len(raw)); budget.file()
        with self.directory(self.root / 'attempts', create=True) as attempts:
            path = self.path(calcjob)
            with self.directory(path, create=True) as parent:
                os.fsync(attempts)
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
                try:
                    offset = 0
                    while offset < len(raw):
                        budget.before(); written = os.write(fd, raw[offset:])
                        need(written > 0, 'journal_short_write'); offset += written
                    budget.before(); os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(parent)
        budget.before()


def parse_ack(output, cluster):
    need(type(output) is engine.CommandOutput, 'dispatch_ack_unqualified')
    try:
        raw = output.encode('ascii')
    except UnicodeError as error:
        raise Hold('dispatch_ack_invalid') from error
    need(type(getattr(output, 'output_bytes', None)) is int and output.output_bytes == len(raw), 'dispatch_ack_invalid')
    match = re.fullmatch('(' + JOB + r')(?:;(' + ID + r'))?\n?', str(output))
    need(match is not None and (match[2] is None or match[2] == cluster), 'dispatch_ack_invalid')
    return {'job_id': match[1], 'cluster': match[2] or cluster}


def _preclaim_diagnostic(error, retained=None):
    """Best-effort protected stderr; a sink failure cannot replace primary HOLD."""
    try:
        if retained is None:
            raw = encoded(error.record)
            retained = {'original_prefix_base64':base64.b64encode(raw[:24576]).decode('ascii'),
                        'original_bytes':len(raw),'original_sha256':hashlib.sha256(raw).hexdigest(),
                        'truncated':len(raw)>24576}
        print('native-attempt preclaim HOLD: ' + encoded(retained).decode('ascii'), file=sys.stderr)
    except BaseException:
        # The original failure still determines HOLD; there is no dispatch,
        # alternate logger, public diagnostic payload or new retry authority.
        pass


def _read_close_payload(store, calcjob_uuid, name, budget):
    """Only the two fixed close records, with exact original payload readback."""
    need(name in ('close.json','close-observation.json'), 'journal_namespace')
    with store.directory(store.path(calcjob_uuid)) as parent:
        try:
            budget.file()
            fd = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC, dir_fd=parent)
        except FileNotFoundError:
            return None
        try:
            raw, info = read_fd(fd,65536,budget)
            need(info.st_uid == os.geteuid() and not info.st_mode&0o077, 'journal_namespace')
            budget.reserve(len(raw)*8)
            value = strict_json(raw.decode());need(type(value) is dict and encoded(value)==raw, 'q1_close_conflict')
            if name=='close.json':
                validate_reply(value)
                need(value['state']=='closed' and value['calcjob_uuid']==calcjob_uuid, 'q1_close_conflict')
            budget.before(); os.fsync(fd); budget.before(); os.fsync(parent)
            need(signature(info)==signature(os.fstat(fd))==signature(os.stat(name,dir_fd=parent,follow_symlinks=False)),
                 'q1_close_conflict')
            return value,raw
        finally:
            os.close(fd)


def _read_close_record(store, calcjob_uuid, budget):
    return _read_close_payload(store,calcjob_uuid,'close.json',budget)


def _close_mount_line(raw, prefix, source):
    rows = []
    for line in raw.splitlines():
        left,separator,right = line.partition(' - ');fields=left.split();tail=right.split()
        need(separator and len(fields)>=6 and len(tail)>=3, 'writer_domain_not_closed')
        if fields[4]==prefix:rows.append((line,fields,tail))
    need(len(rows)==1, 'writer_domain_not_closed')
    line,fields,tail = rows[0]
    need('ro' in fields[5].split(',') and tail[0] in ('nfs','nfs4') and tail[1]==source,
         'writer_domain_not_closed')
    return line


class OrdinaryAttemptOwner:
    def __init__(self, policy, store, sources, budget):
        self.policy, self.store, self.sources, self.budget = policy, store, sources, budget

    def _run(self, document, action):
        job = None; receipt = None; claimed = False
        try:
            validate_request(document); need(document['action'] == action)
        except (Hold, TypeError, ValueError, KeyError):
            return reply({}, 'rejected', reason='shape')
        calcjob = document['calcjob_uuid']; launch = document['launch']
        try:
            controls = _close_controls(document['controls']) if action=='close' else None
            context = self.sources.preflight(launch, self.budget, calcjob_uuid=calcjob, action=action)
            with self.store.locked(calcjob, self.budget):
                claim = self.store.read(calcjob, 'claim.json', self.budget)
                if claim is not None:
                    claimed = True; receipt = calcjob + '/claim.json'
                    need(claim['launch'] == launch, 'launch_conflict')
                else:
                    # A directory without its complete claim is an unknown prior outcome.
                    need(not self.store.path(calcjob).exists(), 'partial_claim')
                    need(action == 'submit', 'attempt_unknown')
                    self.store.claim_domain(calcjob, launch['relative_execution_root'], self.budget)
                    claim = {'launch': launch, 'dispatch_id': str(uuid.uuid4()), 'context': context}
                    self.store.put(calcjob, 'claim.json', claim, self.budget)
                    claimed = True; receipt = calcjob + '/claim.json'
                    snapshot = self.sources.snapshot(launch, claim['dispatch_id'], self.budget)
                    intent = {'dispatch_id': claim['dispatch_id'], 'snapshot': snapshot, 'context': context,
                              'native': self.sources._intent(launch, snapshot, claim['dispatch_id'])}
                    self.store.put(calcjob, 'dispatch.json', intent, self.budget)
                    try:
                        output = self.sources.dispatch(launch, snapshot, claim['dispatch_id'], self.budget)
                        ack = parse_ack(output, self.policy.get('slurm', {}).get('cluster', 'cluster'))
                        self.store.put(calcjob, 'ack.json', ack, self.budget)
                    except (engine.CommandFailure, Hold, OSError) as error:
                        # Keep the command engine's primary record, including ambiguous cleanup.
                        failure = error.record if isinstance(error, engine.CommandFailure) else {'failure': str(error)}
                        try:
                            self.store.put(calcjob, 'failure.json', failure, self.budget)
                        except BaseException as secondary:
                            error.journal_error = repr(secondary)
                            raise error
                        raise Hold('dispatch_outcome_unknown') from error
                dispatch = self.store.read(calcjob, 'dispatch.json', self.budget)
                need(dispatch is not None, 'partial_claim')
                ack = self.store.read(calcjob, 'ack.json', self.budget)
                # Never infer a negative from scheduler absence or issue another sbatch.
                need(ack is not None, 'dispatch_outcome_unknown')
                need(claim['context'] == context, 'controller_generation_changed')
                job = self.store.read(calcjob, 'job.json', self.budget)
                if job is None:
                    job = validate_job(self.sources.bind_job(ack, launch, claim['dispatch_id'], context, self.budget))
                    self.store.put(calcjob, 'job.json', job, self.budget)
                allocation = self.store.read(calcjob, 'allocation.json', self.budget)
                if allocation is not None:
                    need(all(allocation[k] == job[k] for k in job if k not in
                             {'node_name', 'start_time', 'worker_machine_id', 'worker_boot_id'}), 'native_job_changed')
                    job = validate_job(allocation)
                if action in {'start', 'close'}:
                    observed = self.sources.worker(job, calcjob, 'start' if action == 'start' else 'close', self.budget)
                    if action == 'start':
                        need(observed['before'] is not None, 'native_start_not_observed')
                        fields = observed['job']['fields']; identity = observed['identity']['identity']
                        attached = validate_job({**job, 'node_name': fields['NodeList'], 'start_time': fields['StartTime'],
                                               'worker_machine_id': identity['machine_id'], 'worker_boot_id': identity['boot_id']})
                        if allocation is None:
                            self.store.put(calcjob, 'allocation.json', attached, self.budget)
                        else:
                            need(allocation == attached, 'worker_generation_changed')
                        job = attached
                        return reply(document, 'started', job=job, receipt=receipt)
                    need(observed['after'] is not None, 'native_stop_not_observed')
                    need(allocation is not None and observed['before'] is not None, 'native_start_not_observed')
                    return self._close(document,job,context,observed,controls)
                return reply(document, 'bound', job=job, receipt=receipt)
        except (Hold, ResourceError, OSError, ValueError, KeyError, engine.CommandFailure) as error:
            reason = error.reason if isinstance(error, Hold) else getattr(error, 'code', 'native_observation_failed')
            if isinstance(error, engine.CommandFailure):
                raw = encoded(error.record)
                retained = {'original_prefix_base64': base64.b64encode(raw[:24576]).decode('ascii'),
                            'original_bytes': len(raw), 'original_sha256': hashlib.sha256(raw).hexdigest(),
                            'truncated': len(raw) > 24576}
                if claimed:
                    try:
                        self.store.put(calcjob, 'observation-failure-' + uuid.uuid4().hex + '.json', retained, self.budget)
                    except BaseException as secondary:
                        error.journal_error = repr(secondary)
                        raise error
                else:
                    _preclaim_diagnostic(error,retained)
            elif action=='close':
                try:
                    _preclaim_diagnostic(engine.CommandFailure(dict(failure='close_observation_failed',phase='close',
                        original_type=type(error).__name__,message=str(error)[:4096])))
                except BaseException:
                    pass  # A diagnostic failure cannot replace the original HOLD.
            # Read-only retained identity remains useful after current policy or
            # native observation failed. It is explicitly not current authority.
            if job is None:
                try:
                    old_claim = self.store.read(calcjob, 'claim.json', self.budget)
                    if old_claim is not None and old_claim['launch'] == launch:
                        job = self.store.read(calcjob, 'allocation.json', self.budget) or self.store.read(calcjob, 'job.json', self.budget)
                        if job is not None:
                            validate_job(job)
                        receipt = calcjob + '/claim.json'
                except (Hold, ResourceError, OSError, ValueError, KeyError):
                    pass
            return reply(document, 'hold' if claimed or not isinstance(error, Hold) or reason != 'shape' else 'rejected',
                         job=job, reason=reason, receipt=receipt)

    def _close(self, document, job, context, observed, controls):
        launch = document['launch']; calcjob = document['calcjob_uuid']; budget = self.budget
        need(isinstance(self.sources,NativeSources), 'q1_controls_unavailable')
        previous = _read_close_record(self.store,calcjob,budget)
        retained = _read_close_payload(self.store,calcjob,'close-observation.json',budget)
        need((previous is None)==(retained is None), 'q1_close_publication_unknown')
        need(observed['identity']['identity']['machine_id']==job['worker_machine_id'] and
             observed['identity']['identity']['boot_id']==job['worker_boot_id'], 'worker_generation_changed')
        before = self.sources.close_writers(job,launch,observed,budget)
        readback = _read_submitted_files_as_owner(self.policy,launch,budget,controls=controls)
        need(readback['controls']==controls, 'q1_control_changed')
        need(self.sources.qualify()==context, 'controller_generation_changed')
        _authenticate_server(self.sources)
        caller = self.sources._refresh_caller('close')
        latest = self.sources.worker(job,calcjob,'close',budget)
        need(latest['before'] is not None and latest['after'] is not None, 'native_stop_not_observed')
        need(latest['identity']['identity']==observed['identity']['identity'], 'worker_generation_changed')
        after = self.sources.close_writers(job,launch,latest,budget)
        for key in ('storage_identity','native_prefix','retention_ref'):
            need(before[key]==after[key], 'writer_domain_not_closed')
        need([(r['unit'],r['state']) for r in before['controller_units']]==
             [(r['unit'],r['state']) for r in after['controller_units']], 'writer_domain_not_closed')
        prefix = self.policy['jobs_root']+'/'+self.policy['native_result_prefix']
        need([_close_mount_line(r['mountinfo'],prefix,self.policy['nfs_source']) for r in before['controller_units']]==
             [_close_mount_line(r['mountinfo'],prefix,self.policy['nfs_source']) for r in after['controller_units']],
             'writer_domain_not_closed')
        need([(r['node'],r['reply']['identity']['identity']) for r in before['workers']]==
             [(r['node'],r['reply']['identity']['identity']) for r in after['workers']], 'worker_generation_changed')
        candidate = validate_reply(reply(document,'closed',job=job,controls=controls,receipt=calcjob+'/close.json'))
        _reserve_private_record(candidate,budget)
        raw = encoded(candidate); digest = hashlib.sha256(raw).hexdigest()
        if previous is not None:
            need(previous[0]==candidate and retained[0].get('reply_sha256')==digest, 'q1_close_conflict')
            return previous[0]
        witness = dict(reply_sha256=digest,job=job,launch=launch,worker_close=observed,
                       w1_before=before,control_read=readback,w1_after=after,caller=caller)
        _reserve_private_record(witness,budget); need(len(encoded(witness))<=65536, 'journal_bound')
        self.store.put(calcjob,'close-observation.json',witness,budget)
        witness_readback = _read_close_payload(self.store,calcjob,'close-observation.json',budget)
        need(witness_readback is not None and witness_readback[1]==encoded(witness), 'q1_close_conflict')
        self.store.put(calcjob,'close.json',candidate,budget)
        stored = _read_close_record(self.store,calcjob,budget)
        need(stored is not None and stored[1]==raw, 'q1_close_conflict')
        return stored[0]

    def submit(self, request):
        return self._run(request, 'submit')

    def reconcile(self, request):
        return self._run(request, 'reconcile')

    def observe_start(self, request):
        return self._run(request, 'start')

    def qualify_close(self, request):
        return self._run(request, 'close')

    def status(self, request):
        return self._run(request, 'status')


def _bootstrap_operation():
    return Operation(dict(request_bytes=65536, response_bytes=262144, script_bytes=65536,
                          metadata_bytes=8 * 1024 * 1024, memory_bytes=134217728,
                          operation_seconds=90, command_seconds=15, cleanup_seconds=2,
                          maximum_pids=256, maximum_calls=64, maximum_files=2048))


def _load_policy(role, budget):
    need(os.geteuid() == 0, 'root_required')
    try:
        raw = protected_read(POLICY, budget)
    except FileNotFoundError as error:
        raise Hold('native_policy_missing') from error
    policy = exact(strict_json(raw.decode()), POLICY_KEYS)
    need(policy['schema'] == 'qcl-negf.native-attempt-policy.v1' and policy['role'] == role, 'policy_role')
    need(policy['client_uid'] == 3000 and type(policy['client_uid']) is int, 'policy_owner')
    need(policy['socket_path'] == SOCKET and policy['daemon_unit'] == 'qcl-negf-aiida.service' and
         policy['server_unit_prefix'] == 'qcl-negf-native-attempt@' and policy['slurmd_unit'] == 'slurmd.service', 'policy_unit')
    exact(policy['tools'], {'systemctl', 'runuser', 'sbatch', 'scontrol', 'slurmd', 'slurmstepd', 'python'})
    exact(policy['slurm'], {'cluster', 'version', 'config_file', 'cgroup_scope'})
    need(matches(policy['slurm']['cluster'], ID), 'policy_cluster')
    for key in ('private_root', 'spool_root', 'jobs_root', 'storage_identity_file', 'release_runtime',
                'facts_service_config', 'qualification_file'):
        path_value(policy[key], absolute=True)
    path_value(policy['native_result_prefix'], absolute=False)
    for tool in policy['tools'].values():
        path_value(tool, absolute=True)
        need(tool.startswith('/nix/store/'), 'policy_tool')
    need(type(policy['worker_routes']) is dict and 1 <= len(policy['worker_routes']) <= 64, 'policy_routes')
    for name, route in policy['worker_routes'].items():
        need(matches(name, ID), 'policy_routes')
        exact(route, {'target', 'known_hosts', 'identity_file', 'helper', 'role'})
        need(route['role'] == 'facts', 'policy_routes')
    limits = validate_limits(policy['limits'])
    # Keep all bootstrap charges and the original deadline; policy can only tighten.
    need(all(limits[k] <= budget.limits[k] for k in LIMIT_KEYS), 'policy_limits')
    budget.deadline = min(budget.deadline, budget.started + limits['operation_seconds'])
    budget.limits = limits
    budget.before(); need(budget.bytes <= limits['metadata_bytes'] and budget.files <= limits['maximum_files'], 'policy_limits')
    policy['_policy_sha256'] = hashlib.sha256(raw).hexdigest()
    return policy


def load_native_attempt_policy(role):
    return _load_policy(role, _bootstrap_operation())


def _caller_generation(row):
    need(engine.process_state_class(row) == 'live', 'peer_not_live')
    need(type(row['pid']) is int and type(row['start_ticks']) is int and row['start_ticks'] > 0, 'peer_credentials')
    return {key: row[key] for key in ('pid','ppid','start_ticks','uids','cgroup','executable','comm')}


def _caller_role(sources, row, argv, role, action, context):
    cfg = context['configuration']; client = cfg['client']
    if role == 'client':
        need(argv == client['argv_prefix'] + [action] and row['executable'] == sources.origin(client['argv_prefix'][0]),
             'peer_client_origin')
        return
    if role == 'shell':
        alias = '/run/current-system/sw/bin/qcl-negf-native-attempt-client'
        need(sources.origin(alias) == sources.origin(client['entrypoint']) and
             row['executable'] == sources.origin(client['bash_executable']) and
             argv == ['bash','--noprofile','--norc','-c',shlex.join([alias,action])], 'peer_shell_origin')
        return
    tail = {'worker':['daemon','worker'], 'circus':['daemon','start-circus','1','--foreground'],
            'main':['daemon','start','--foreground']}[role]
    suffix = ['-p',cfg['profile'],*tail]
    # A currently resolved mutable profile or shared canonical core script
    # cannot certify which APP this already-running Python loaded at startup.
    entrypoints = {context['app']+'/bin/verdi'}
    need(row['executable'] == sources.qualification['unit_origins'][sources.policy['daemon_unit']]['executable'],
         'application_origin')
    if len(argv) == len(suffix) + 1:
        need(argv[0] in entrypoints and sources.origin(argv[0]) == row['executable'] and argv[1:] == suffix,
             'application_origin')
    else:
        need(len(argv) == len(suffix)+2 and argv[1] in entrypoints and argv[2:] == suffix and
             sources.origin(argv[0]) == row['executable'], 'application_origin')


def _review_native_script(raw, launch, solver, bash, sources, *, calcjob_uuid):
    """One stock script subset; never execute or interpret arbitrary shell."""
    canonical_uuid(calcjob_uuid)
    lines = [line for line in raw.decode('utf-8').splitlines() if line]
    need(lines and lines[0].startswith('#!'), 'native_script')
    interpreter = lines.pop(0)[2:]
    need(interpreter in (bash,'/run/current-system/sw/bin/bash') and
         sources.origin(interpreter)==sources.origin(bash), 'native_script_interpreter')
    sources.origin('/run/current-system/sw/bin/qcl-negf-release')
    headers = {}
    while lines and lines[0].startswith('#SBATCH '):
        line = lines.pop(0)[len('#SBATCH '):]; key,sep,value = line.partition('=')
        need(key not in headers, 'native_script_directive')
        allowed = {'--no-requeue','--job-name','--get-user-env','--output','--error','--nodes',
                   '--ntasks-per-node','--cpus-per-task','--partition','--account','--qos','--time','--mem'}
        need(key in allowed, 'native_script_directive'); headers[key] = value
        if key in ('--no-requeue','--get-user-env'): need(not sep, 'native_script_directive')
        elif key=='--job-name': need(re.fullmatch(r'"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"',value), 'native_script_directive')
        elif key in ('--partition','--account','--qos'): need(matches(value,ID), 'native_script_directive')
        elif key=='--time': need(re.fullmatch(r'(?:[0-9]+-)?[0-9]{2}:[0-5][0-9]:[0-5][0-9]',value), 'native_script_directive')
        elif key=='--mem': need(re.fullmatch(r'[0-9]+',value), 'native_script_directive')
    need(headers.get('--no-requeue')=='' and '--job-name' in headers and
         headers.get('--output')=='_scheduler-stdout.txt' and headers.get('--error')=='_scheduler-stderr.txt' and
         headers.get('--nodes')==headers.get('--ntasks-per-node')=='1' and
         re.fullmatch(r'[1-9][0-9]*',headers.get('--cpus-per-task','')), 'native_script_resources')
    need(len(lines)==7 and lines[0]=='# ENVIRONMENT VARIABLES BEGIN ###' and
         lines[3]=='# ENVIRONMENT VARIABLES END ###', 'native_script')
    expected_exports = {"export JULIA_NUM_THREADS='"+headers['--cpus-per-task']+"'", "export OPENBLAS_NUM_THREADS='1'"}
    need(set(lines[1:3])==expected_exports, 'native_script_environment')
    guard = ('/run/current-system/sw/bin/qcl-negf-release guard --release-id '+shlex.quote(launch['release_id'])+
             ' --solver-executable '+shlex.quote(solver)+' || exit 78')
    need(lines[4]==guard and lines[5]=='unset QCL_NEGF_CAPTURE_SPEC', 'native_script_guard')
    argv = [solver,'run-plan','plan.json',sources.policy['jobs_root']+'/'+launch['relative_execution_root'],
            '--execution-id',launch['execution_id'],'--source-graph','source-graph.json']
    # Stock Scheduler single-quotes every code argument. A free shell token or
    # extra flag never becomes authority by merely producing the same shlex words.
    literal = lambda word: "'"+word.replace("'", "'\"'\"'")+"'"
    native_argv = argv + ['--native-execution','native-execution.json','--native-calcjob-uuid',calcjob_uuid]
    expected = [' '.join(literal(word) for word in words)+"  > 'solver.stdout' 2> 'solver.stderr'"
                for words in (argv,native_argv)]
    if '--scratch-root' in lines[6]: raise Hold('native_scratch_binding_unavailable')
    # The legacy seven-argument class stays unmapped; neither branch is itself
    # proof of invocation birth or of a qualified native producer.
    need(lines[6] in expected, 'native_script_argv')


def _reserve_private_record(value, budget, depth=0):
    """Prepay only the existing journal's JSON encoding, with no new codec."""
    need(depth<=16, 'private_record_bound'); budget.reserve(32)
    if type(value) is str: budget.reserve(12*len(value))
    elif type(value) is int: budget.reserve(value.bit_length()*30103//100000+2)
    elif type(value) is dict:
        for key,item in value.items():
            need(type(key) is str, 'private_record_bound')
            _reserve_private_record(key,budget,depth+1); _reserve_private_record(item,budget,depth+1)
    elif type(value) in (list,tuple):
        for item in value: _reserve_private_record(item,budget,depth+1)
    else: need(value is None or type(value) in (bool,int,float), 'private_record_bound')


def authenticate_socket_peer(connection, policy, sources, *, action):
    pid, uid, gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    need(pid > 0 and uid == gid == policy['client_uid'], 'peer_credentials')
    context = sources.actor_context(); unit = sources.unit(policy['daemon_unit'])
    need(unit['ActiveState'] == 'active' and matches(unit['InvocationID'], r'[0-9a-f]{32}') and
         int(unit['MainPID']) > 0, 'peer_unit')
    chain = []; current = pid; seen = set()
    for _ in range(16):
        need(current > 1 and current not in seen, 'peer_ancestry')
        seen.add(current); row = sources.process(current); _caller_generation(row)
        need(row['pid'] == current and row['uids'] == [uid]*4 and
             engine.daemon_scope_bound(row['cgroup'],unit['ControlGroup']), 'peer_unit')
        argv = sources.command_line(current); env = sources.selected_environment(current)
        chain.append({'process':row,'argv':argv,'environment':env})
        if current == int(unit['MainPID']): break
        current = row['ppid']
    else: raise Hold('peer_ancestry_bound')
    need(len(chain) in (4,5), 'peer_ancestry')
    roles = ['client'] + (['shell'] if len(chain)==5 else []) + ['worker','circus','main']
    for index,(entry,role) in enumerate(zip(chain,roles)):
        row = entry['process']; _caller_role(sources,row,entry['argv'],role,action,context)
        # Pinned AiiDA 2.9.2 MainPID starts with the configured base, while
        # DaemonClient.get_env propagates its actual config dir to descendants.
        cfg = context['configuration']
        need(entry['environment'] == {'AIIDA_PATH':cfg['aiida_path']+('' if role=='main' else '/.aiida'),
                                     'QCL_NEGF_NATIVE_JOBS_ROOT':cfg['jobs_root']}, 'peer_environment')
        if index+1 < len(chain):
            parent = chain[index+1]['process']
            need(row['ppid'] == parent['pid'] and parent['start_ticks'] <= row['start_ticks'], 'peer_birth_join')
        need(_caller_generation(row) == _caller_generation(sources.process(row['pid'])) and
             entry['argv'] == sources.command_line(row['pid']) and
             entry['environment'] == sources.selected_environment(row['pid']), 'peer_generation_changed')
    profile = sources.profile_view(int(unit['MainPID']),context)
    need(unit == sources.unit(policy['daemon_unit']) and context == sources.actor_context() and
         profile == sources.profile_view(int(unit['MainPID']),context), 'peer_generation_changed')
    sources._connection = connection
    return {'pid':pid,'chain':chain,'unit':unit,'application':context,'profile':profile}


def read_frame(connection, budget, limit):
    def receive(size):
        raw = bytearray()
        while len(raw) < size:
            budget.before(); connection.settimeout(max(.001, budget.deadline - time.monotonic()))
            chunk = connection.recv(size - len(raw))
            need(chunk, 'frame_truncated'); raw.extend(chunk)
        return bytes(raw)
    size = struct.unpack('!I', receive(4))[0]
    need(0 < size <= limit, 'frame_bound'); budget.reserve(size * 2)
    raw = receive(size)
    budget.before(); need(connection.recv(1) == b'', 'frame_extra')
    try:
        document = strict_json(raw.decode('utf-8'))
        need(type(document) is dict, 'frame_shape')
        return document
    except (ValueError, UnicodeError, ResourceError) as error:
        raise Hold('frame_json') from error


def write_frame(connection, document, budget, limit):
    raw = encoded(document); need(len(raw) <= limit, 'frame_bound'); budget.reserve(len(raw))
    budget.before(); connection.settimeout(max(.001, budget.deadline - time.monotonic()))
    connection.sendall(struct.pack('!I', len(raw)) + raw)


def _original_input_limit(role, policy):
    # Fixed original roles: only plan follows the existing capture plan allowance.
    return 1048576 if role == 'plan' else policy['limits']['script_bytes'] if role == 'submit_script' else 65536


def _owner_read(policy, launch, budget, *, controls=None):
    """Runs ONLY after dropping credentials in production; no root NFS access."""
    need(os.getuid() == os.geteuid() == policy['client_uid'], 'owner_read_credentials')
    if controls is not None:
        return _owner_close_read(policy,launch,budget,controls)
    work = path_value(launch['remote_workdir'], absolute=True)
    need(within(work, policy['jobs_root']) and work != policy['jobs_root'], 'upload_namespace')
    # Walk every component using directory FDs. Symlinks, including parent aliases, fail.
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    walked = []
    try:
        for part in Path(work).parts[1:]:
            budget.file(); next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            walked.append((os.dup(parent), part, os.fstat(next_fd)))
            os.close(parent); parent = next_fd
        original = os.fstat(parent); result = {}; script = None
        for role, name in FILES.items():
            claim = launch['files'][role]
            limit = _original_input_limit(role, policy)
            need(claim['bytes'] <= limit, 'submitted_bound')
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                raw, info = read_fd(fd, limit, budget)
                need(info.st_uid == policy['client_uid'] and not info.st_mode & 0o022 and
                     signature(info) == signature(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'submitted_identity')
                observed = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
                need(observed == claim, 'submitted_digest')
                result[role] = observed
                if role == 'submit_script':
                    script = base64.b64encode(raw).decode('ascii')
            finally:
                os.close(fd)
        need(signature(original) == signature(os.fstat(parent)), 'submitted_directory_changed')
        for directory, name, info in walked:
            need(signature(info) == signature(os.stat(name, dir_fd=directory, follow_symlinks=False)), 'submitted_directory_changed')
        return {'files': result, 'script': script}
    finally:
        os.close(parent)
        for directory, _, _ in walked:
            os.close(directory)


def _owner_close_read(policy, launch, budget, controls):
    need(os.getuid()==os.geteuid()==policy['client_uid'], 'owner_read_credentials')
    controls = _close_controls(controls); rows = []; roots = []; actual = []
    initial_bytes, initial_files = budget.actual_bytes, budget.files
    result = path_value(policy['jobs_root']+'/'+launch['relative_execution_root'],absolute=True)
    work = path_value(launch['remote_workdir'],absolute=True)
    need(within(result,policy['jobs_root']+'/'+policy['native_result_prefix']) and
         within(work,policy['jobs_root']) and not within(work,result) and not within(result,work), 'output_namespace')
    for role,path,selected in (('result',result,controls[:2]),('workdir',work,controls[2:])):
        parent = os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); walked = []
        try:
            for name in Path(path).parts[1:]:
                budget.file(); child = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                info = os.fstat(child)
                if info.st_uid not in (0,policy['client_uid']) or info.st_mode&0o022:
                    os.close(child);raise Hold('q1_directory_identity')
                walked.append((os.dup(parent),name,info));os.close(parent);parent=child
            directory = os.fstat(parent)
            for claim in selected:
                fd = os.open(claim['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
                try:
                    raw,info = read_fd(fd,claim['bytes'],budget)
                    need(info.st_uid==policy['client_uid'] and not info.st_mode&0o022 and
                         signature(info)==signature(os.stat(claim['path'],dir_fd=parent,follow_symlinks=False)), 'q1_file_identity')
                    observed = dict(path=claim['path'],bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
                    need(observed==claim, 'q1_control_changed');actual.append(observed)
                    rows.append(dict(path=claim['path'],root=role,signature=signature(info)))
                    del raw
                finally:os.close(fd)
            need(signature(directory)==signature(os.fstat(parent)), 'q1_directory_changed')
            for ancestor,name,info in walked:
                need(signature(info)==signature(os.stat(name,dir_fd=ancestor,follow_symlinks=False)), 'q1_directory_changed')
            roots.append(dict(role=role,path=path,directory=signature(directory),
                ancestors=[dict(name=name,signature=signature(info)) for _,name,info in walked]))
        finally:
            os.close(parent)
            for ancestor,_,_ in walked:os.close(ancestor)
    return dict(controls=actual,roots=roots,files=rows,
                io=dict(actual_bytes=budget.actual_bytes-initial_bytes,file_operations=budget.files-initial_files))


def _read_submitted_files_as_owner(policy, launch, budget, *, controls=None):
    import selectors
    need(os.geteuid() == 0, 'root_required')
    # Reserve the complete bounded child envelope before forking. Charges never reset.
    cap = min(policy['limits']['response_bytes'], 131072 if controls is None else 65536)
    if controls is not None:
        controls = _close_controls(controls)
        paths = (path_value(policy['jobs_root']+'/'+launch['relative_execution_root'],absolute=True),
                 path_value(launch['remote_workdir'],absolute=True))
        depth = sum(len(Path(path).parts)-1 for path in paths)
        budget.reserve(8*(sum(row['bytes'] for row in controls)+4)+16*65536+4096*(depth+4)+8*len(encoded(controls)))
        for _ in range(8*depth+64):budget.file()
    else:
        budget.reserve(cap * 3); budget.file()
    read_end, write_end = os.pipe2(os.O_CLOEXEC)
    pid = os.fork()
    if pid == 0:
        initial_actual = budget.actual_bytes
        try:
            os.close(read_end); os.setgroups([]); os.setgid(policy['client_uid']); os.setuid(policy['client_uid'])
            raw = encoded(_owner_read(policy, launch, budget,controls=controls)) if controls is not None else encoded(_owner_read(policy, launch, budget))
            need(len(raw) <= cap, 'owner_read_bound')
            offset = 0
            while offset < len(raw):
                budget.before(); count = os.write(write_end, raw[offset:]); need(count > 0, 'owner_read_short_write'); offset += count
            os._exit(0)
        except BaseException as error:
            if controls is not None:
                try:
                    raw = encoded(dict(failure=type(error).__name__,message=str(error)[:4096],
                                       reason=error.reason if isinstance(error,Hold) else 'owner_read_failed',
                                       actual_bytes=budget.actual_bytes-initial_actual))
                    budget.before();os.write(write_end,raw)
                except BaseException:pass
            os._exit(1)
    os.close(write_end); selector = selectors.DefaultSelector(); raw = bytearray(); reaped = False
    try:
        selector.register(read_end, selectors.EVENT_READ)
        while True:
            budget.before()
            if not selector.select(min(.1, max(.001, budget.deadline - time.monotonic()))):
                continue
            chunk = os.read(read_end, min(65536, cap + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk); need(len(raw) <= cap, 'owner_read_bound')
            if controls is not None:budget.actual_bytes += len(chunk)
        while True:
            budget.before(); waited, status = os.waitpid(pid, os.WNOHANG)
            if waited:
                reaped = True
                if controls is not None and os.waitstatus_to_exitcode(status)!=0:
                    failure = strict_json(raw.decode()) if raw else dict(failure='unknown child outcome')
                    if 'actual_bytes' in failure:
                        count=failure['actual_bytes']
                        need(type(count) is int and 0<=count<=sum(row['bytes'] for row in controls)+4, 'owner_read_bound')
                        budget.actual_bytes+=count
                    primary = engine.CommandFailure(failure);_preclaim_diagnostic(primary)
                    raise Hold('owner_read_failed') from primary
                need(os.waitstatus_to_exitcode(status) == 0, 'owner_read_failed'); break
            time.sleep(.005)
        result = strict_json(raw.decode())
        if controls is not None:
            count = result['io']['actual_bytes']
            need(type(count) is int and 0<=count<=sum(row['bytes'] for row in controls), 'owner_read_bound')
            budget.actual_bytes += count
        return result
    finally:
        selector.close(); os.close(read_end)
        if not reaped:
            # Only this credential-drop metadata child, never a native job.
            try:
                os.kill(pid, 9)
            except ProcessLookupError:
                pass
            # Do not block on uninterruptible hard-NFS IO; systemd owns the cgroup.
            os.waitpid(pid, os.WNOHANG)


class NativeSources:
    """Fixed native readers. Expectations are re-observed, never accepted as proof."""
    def __init__(self, policy, budget):
        self.policy, self.budget = policy, budget
        self.qualification = None

    def run(self, argv, *, output_bytes=None):
        return self.budget.command(argv, run=engine.command, output_bytes=output_bytes,
                                   env={'PATH': '/empty', 'LANG': 'C', 'LC_ALL': 'C',
                                        'SLURM_CONF': self.policy['slurm']['config_file']})

    def origin(self, path):
        return engine.public_binary_origin(self.budget,path)['path']

    def command_line(self, pid):
        raw = self.budget.read('/proc/'+str(pid)+'/cmdline',16384)
        need(raw.endswith(b'\0'), 'peer_command_line')
        return [part.decode('utf-8') for part in raw[:-1].split(b'\0')]

    def selected_environment(self, pid):
        raw = self.budget.read('/proc/'+str(pid)+'/environ',65536); result = {}
        for entry in raw.split(b'\0'):
            key,sep,value = entry.partition(b'=')
            if key in (b'AIIDA_PATH',b'QCL_NEGF_NATIVE_JOBS_ROOT'):
                name = key.decode('ascii'); need(sep and name not in result, 'peer_environment')
                result[name] = value.decode('utf-8')
        return result  # Other environment entries, including secrets, are never retained.

    def actor_configuration(self):
        need(hasattr(self,'_server_unit'), 'server_unit')
        path = os.environ.get('QCL_NEGF_NATIVE_ACTOR_CONFIG'); path_value(path,absolute=True)
        environment = self.run([self.policy['tools']['systemctl'],'show',self._server_unit,'--property=Environment','--value'])
        selected = [entry for entry in shlex.split(environment) if entry.startswith('QCL_NEGF_NATIVE_ACTOR_CONFIG=')]
        need(selected == ['QCL_NEGF_NATIVE_ACTOR_CONFIG='+path], 'actor_configuration')
        origin = engine.public_binary_origin(self.budget,path,executable=False)['path']
        raw = engine.immutable_public_bytes(self.budget,origin,65536)
        cfg = exact(strict_json(raw.decode()), {'schema','profile','aiida_path','application_profile','jobs_root','client'})
        need(cfg['schema'] == 'qcl-negf.native-actor-launch.v1' and matches(cfg['profile'],ID) and
             cfg['aiida_path'] == '/var/lib/qcl-negf/aiida' and
             cfg['application_profile'] == '/nix/var/nix/profiles/qcl-negf-application' and
             cfg['jobs_root'] == self.policy['jobs_root'], 'actor_configuration')
        client = exact(cfg['client'], {'entrypoint','argv_prefix','bash_executable'})
        prefix = client['argv_prefix']
        need(type(prefix) is list and len(prefix)==4 and prefix[1:3]==['-I','-c'] and
             type(prefix[3]) is str and 0<len(prefix[3])<=8192, 'actor_configuration')
        for executable in (prefix[0],client['entrypoint'],client['bash_executable']):
            need(type(executable) is str and executable.startswith('/nix/store/'), 'actor_configuration')
            self.origin(executable)
        return cfg

    def actor_context(self):
        cfg = self.actor_configuration()
        raw = protected_read(Path(self.policy['release_runtime'])/'release.json',self.budget)
        app = engine.release_envelope(strict_json(raw.decode()))['application_path']
        profile = cfg['application_profile']
        origin = engine.public_binary_origin(self.budget,profile+'/bin/verdi')
        need(any(path==app and stat.S_ISDIR(info[2]) and info[3]==0 for path,info,_ in origin['chain']), 'application_profile_changed')
        need(any(path==profile and stat.S_ISLNK(info[2]) and info[3]==0 for path,info,_ in origin['chain']), 'application_profile_changed')
        for path,info,_ in origin['chain']:
            # Store admission belongs to the existing public immutable-origin
            # reader. The managed store directory may be group-writable; this
            # bridge protects the mutable profile selectors, without changing it.
            need(info[3]==0 and (path=='/nix/store' or stat.S_ISLNK(info[2]) or not info[2]&0o022),
                 'application_profile_changed')
        self.origin(app+'/bin/qcl-negf-native-actor')
        return {'configuration':cfg,'app':app,'profile_origin':origin,'release_sha256':hashlib.sha256(raw).hexdigest()}

    def profile_view(self, main_pid, context):
        cfg = context['configuration']; views = []
        for pid in (os.getpid(),main_pid):
            parent = os.open('/proc/'+str(pid)+'/root',os.O_RDONLY|os.O_DIRECTORY)
            try:
                for part in (cfg['aiida_path'].lstrip('/')+'/.aiida').split('/'):
                    self.budget.file(); child = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                    info = os.fstat(child)
                    if info.st_uid not in (0,self.policy['client_uid']) or info.st_mode&0o022:
                        os.close(child); raise Hold('profile_path')
                    os.close(parent); parent = child
                fd = os.open('config.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
                try:
                    raw,info = read_fd(fd,65536,self.budget)
                    need(info.st_uid in (0,self.policy['client_uid']) and not info.st_mode&0o022 and
                         signature(info)==signature(os.stat('config.json',dir_fd=parent,follow_symlinks=False)), 'profile_config')
                    identity = signature(info)
                finally: os.close(fd)
                for path in ('access/'+cfg['profile'],'log'):
                    directory = parent; opened = []
                    try:
                        for part in path.split('/'):
                            self.budget.file(); directory = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
                            opened.append(directory); info = os.fstat(directory)
                            need(info.st_uid==self.policy['client_uid'] and not info.st_mode&0o022, 'profile_operational_path')
                        if path=='log':
                            with os.scandir(directory) as iterator:
                                for item in iterator:
                                    self.budget.file()
                                    need(re.fullmatch(re.escape('aiida-'+cfg['profile']+'.log')+r'(?:\.(?:[1-9]|10))?',item.name),
                                         'profile_log_namespace')
                                    info = os.stat(item.name,dir_fd=directory,follow_symlinks=False)
                                    need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and
                                         info.st_uid==self.policy['client_uid'] and not info.st_mode&0o022, 'profile_log_namespace')
                    finally:
                        for directory in reversed(opened): os.close(directory)
                rows = self.budget.read('/proc/'+str(pid)+'/mountinfo',65536).decode().splitlines()
                wanted = cfg['aiida_path']+'/.aiida/config.json'
                need(any(line.split(' - ',1)[0].split()[4]==wanted and
                         'ro' in line.split(' - ',1)[0].split()[5].split(',') for line in rows), 'profile_config_not_readonly')
                need(identity == signature(os.stat('config.json',dir_fd=parent,follow_symlinks=False)), 'profile_config_changed')
                views.append({'identity':identity,'sha256':hashlib.sha256(raw).hexdigest()})
            finally: os.close(parent)
        need(views[0]==views[1], 'profile_view_changed')
        return views[0]

    def _refresh_caller(self, action):
        need(hasattr(self,'_connection'), 'peer_missing')
        fresh = authenticate_socket_peer(self._connection,self.policy,self,action=action)
        def stable(packet):
            return {'chain':[(_caller_generation(row['process']),row['argv'],row['environment']) for row in packet['chain']],
                    **{key:packet[key] for key in ('unit','application','profile')}}
        if hasattr(self,'_caller'): need(stable(self._caller)==stable(fresh), 'peer_generation_changed')
        self._caller = fresh
        return fresh

    def process(self, pid):
        row = engine.process_record(self.budget, Path('/proc') / str(pid))
        raw = self.budget.read(Path('/proc') / str(pid) / 'stat').decode()
        fields = raw[raw.rfind(')') + 2:].split()
        need(int(fields[19]) == row['start_ticks'], 'process_changed')
        def retain(value):
            if isinstance(value, bytes):
                return {'base64': base64.b64encode(value).decode('ascii')}
            if isinstance(value, dict):
                return {key: retain(item) for key, item in value.items()}
            return value
        # Keep original raw process samples in privileged journals/facts, never
        # expose them as a standalone caller-created certificate.
        need(fields[0] == row['state'], 'process_changed')
        return {**{key: row[key] for key in ('pid', 'uids', 'start_ticks', 'cgroup', 'executable', 'state', 'comm')},
                'ppid': int(fields[1]), 'observations': retain(row['observations'])}

    def host(self):
        first = {'machine_id': self.budget.read('/etc/machine-id', 64).decode().strip(),
                 'boot_id': self.budget.read('/proc/sys/kernel/random/boot_id', 64).decode().strip()}
        need(matches(first['machine_id'], r'[0-9a-f]{32}'), 'host_identity')
        canonical_uuid(first['boot_id'])
        image = engine.public_binary_origin(self.budget, '/run/current-system/nixos-version', executable=False)['path']
        first['image_id'] = str(Path(image).parent)
        return first

    def unit(self, name):
        need(matches(name, r'[A-Za-z0-9@_.:-]+\.service'), 'unit_name')
        fields = ('InvocationID', 'ControlGroup', 'MainPID', 'ActiveState', 'FragmentPath', 'MemoryMax', 'RuntimeMaxUSec')
        output = self.run([self.policy['tools']['systemctl'], 'show', name,
                           *('--property=' + key for key in fields)])
        values = dict(line.split('=', 1) for line in output.splitlines())
        need(set(values) == set(fields), 'unit_observation')
        if self.qualification is not None:
            kind = 'server' if name.startswith(self.policy['server_unit_prefix']) else name
            expected = exact(self.qualification['unit_origins'][kind], {'fragment_path', 'fragment_sha256', 'executable'})
            origin = engine.public_binary_origin(self.budget, values['FragmentPath'], executable=False)['path']
            need(origin == expected['fragment_path'] and hashlib.sha256(
                engine.immutable_public_bytes(self.budget, origin, 65536)).hexdigest() == expected['fragment_sha256'], 'unit_origin')
        return values

    def qualify(self):
        policy = self.policy
        try:
            raw = protected_read(policy['qualification_file'], self.budget)
        except FileNotFoundError as error:
            raise Hold('native_qualification_missing') from error
        q = exact(strict_json(raw.decode()), {'protocol_id', 'policy_sha256', 'controller_binding',
                    'worker_bindings', 'unit_origins', 'tool_origins', 'write_domain', 'qualification_receipt_ref'})
        need(q['protocol_id'] == 'p07-ordinary-slurm-v1' and q['policy_sha256'] == policy['_policy_sha256'], 'native_protocol_changed')
        host = self.host()
        binding = q['controller_binding'] if policy['role'] == 'controller' else q['worker_bindings'].get(host['machine_id'])
        need(binding == host, 'host_generation_changed')
        exact(q['tool_origins'], policy['tools'])
        for key, path in policy['tools'].items():
            origin = engine.public_binary_origin(self.budget, path)['path']
            need(origin == q['tool_origins'][key], 'native_tool_changed')
        need(self.run([policy['tools']['scontrol'], '--version']).strip() == policy['slurm']['version'], 'slurm_version_changed')
        config = protected_read(policy['slurm']['config_file'], self.budget).decode()
        cluster = re.findall(r'^ClusterName\s*=\s*([^\s#]+)', config, re.M)
        need(cluster == [policy['slurm']['cluster']], 'slurm_cluster_changed')
        # Local journals and readable script spool must never be NFS namespaces.
        for root in (policy['private_root'], policy['spool_root']):
            trusted_root_path(root, directory=True)
            need(not within(root, policy['jobs_root']) and self.mount(root)['fstype'] not in {'nfs', 'nfs4'}, 'journal_not_local')
        mount = self.mount(policy['jobs_root'])
        need(mount['fstype'] in {'nfs', 'nfs4'} and mount['source'] == policy['nfs_source'] and
             'hard' in mount['options'], 'storage_binding_changed')
        domain = q['write_domain']
        need(protected_read(policy['storage_identity_file'], self.budget).decode().strip() == domain['storage_identity'], 'storage_binding_changed')
        need(type(q['qualification_receipt_ref']) is str and 0 < len(q['qualification_receipt_ref']) <= 256, 'native_qualification_missing')
        # Receipt locator is retained context, never a boolean certificate.
        self.qualification = q
        unit = policy['daemon_unit'] if policy['role'] == 'controller' else policy['slurmd_unit']
        observed = self.unit(unit)
        need(observed['ActiveState'] == 'active' and matches(observed['InvocationID'], r'[0-9a-f]{32}') and
             int(observed['MainPID']) > 0, 'native_unit_changed')
        return host

    def mount(self, path):
        rows = []
        for line in self.budget.read('/proc/self/mountinfo', 65536).decode().splitlines():
            left, right = line.split(' - ', 1); fields = left.split(); tail = right.split()
            mountpoint = fields[4]
            if within(path, mountpoint):
                rows.append((len(mountpoint), dict(mountpoint=mountpoint, fstype=tail[0], source=tail[1],
                                                options=set(fields[5].split(',')) | set(tail[2].split(',')))))
        need(rows, 'mount_not_observed')
        return max(rows, key=lambda row: row[0])[1]

    def _submit_admission(self, launch):
        current = strict_json(protected_read(Path(self.policy['release_runtime'])/'release.json',self.budget).decode())
        need(current.get('ready') is True and current.get('release_id')==launch['release_id'] and
             current.get('code_uuid')==launch['code_uuid'], 'native_admission_closed')
        gate = Path(self.policy['jobs_root'])/'.release-admission.json'
        # Existing G credential switch for its fixed NFS gate, no root-squash bypass.
        need(gate==engine.GATE, 'native_admission_namespace')
        with engine.admission_reader(gate):
            admission = strict_json(self.budget.read(gate,65536).decode())
        need(admission.get('open') is True and admission.get('release_id')==launch['release_id'], 'native_admission_closed')

    def _actor_read(self, kind, calcjob, launch, context):
        files = exact(launch['files'], FILES)
        counts = [(files[role]['bytes'], _original_input_limit(role, self.policy)) for role in FILES]
        need(all(type(size) is int and 0<=size<=cap for size,cap in counts), 'actor_input_bound')
        # Prepay complete raw/JSON chunk and EOF workspace for each original role
        # before the actor command; the inherited outer ledger can still refuse.
        ceiling = 30*16384 + 8*sum(min(cap+1,4096*math.ceil(size/4096)+4096) for size,cap in counts)
        self.budget.reserve(ceiling)
        cfg = context['configuration']; app = context['app']
        argv = [self.policy['tools']['runuser'],'-u','qcl-negf','--',app+'/bin/qcl-negf-native-actor',
                '--profile',cfg['profile'],kind,calcjob,'--maximum-metadata-bytes',str(ceiling)]
        output = self.budget.command(argv,run=engine.command,output_bytes=65536,
            env={'AIIDA_PATH':cfg['aiida_path'],'PATH':app+'/bin:/empty','LANG':'C','LC_ALL':'C'})
        need(type(output) is engine.CommandOutput, 'actor_output_unqualified')
        raw = output.encode('utf-8')
        need(type(getattr(output,'output_bytes',None)) is int and output.output_bytes==len(raw), 'actor_output_partial')
        return raw

    def preflight(self, launch, budget, *, calcjob_uuid, action):
        canonical_uuid(calcjob_uuid)
        need(action in {'submit','reconcile','status','start','close'} and budget is self.budget, 'actor_request')
        host = self.qualify(); policy = self.policy
        peer = self._refresh_caller(action); context = peer['application']
        root = policy['jobs_root'] + '/' + launch['relative_execution_root']
        need(within(launch['relative_execution_root'], policy['native_result_prefix']) and
             within(launch['remote_workdir'], policy['jobs_root']) and
             not within(launch['remote_workdir'], policy['jobs_root'] + '/' + policy['native_result_prefix']) and
             not within(root, launch['remote_workdir']), 'output_namespace')
        retained = strict_json(protected_read(Path(policy['release_runtime']) / 'records' /
                               ('release-' + launch['release_id'] + '.json'), budget).decode())
        envelope = engine.release_envelope(retained)
        need(retained['code_uuid'] == launch['code_uuid'] and envelope['release_id'] == launch['release_id'], 'release_binding_changed')
        graph_hash = envelope['solver_build']['source_graph_sha256']
        graph = protected_read(Path(policy['release_runtime']) / 'records' / ('source-graph-' + graph_hash + '.json'), budget)
        need(hashlib.sha256(graph).hexdigest() == graph_hash == launch['files']['source_graph']['sha256'] and
             len(graph) == launch['files']['source_graph']['bytes'], 'release_graph_changed')
        need(retained['quantum_runtime_context'] == engine.quantum_context(envelope), 'release_binding_changed')
        if action=='submit': self._submit_admission(launch)
        actual = strict_json(self._actor_read('launch',calcjob_uuid,launch,context).decode())
        need(actual==launch, 'actor_launch_changed')
        raw = self._actor_read('execution',calcjob_uuid,launch,context)
        need(len(raw)==launch['files']['native_execution']['bytes'] and
             hashlib.sha256(raw).hexdigest()==launch['files']['native_execution']['sha256'], 'actor_execution_changed')
        native = strict_json(raw.decode())  # The fixed public actor owns full scientific-schema validation.
        need(native['schema']=='qcl-negf.aiida-native-execution.v1' and native['request_id']==launch['request_id'] and
             native['execution_id']==launch['execution_id'], 'actor_execution_binding')
        for key,node in (('input_plan','input_plan_uuid'),('source_graph','source_graph_uuid')):
            role = 'plan' if key=='input_plan' else key
            need(native[key]=={'node_uuid':launch[node],'bytes':str(launch['files'][role]['bytes']),
                               'sha256':launch['files'][role]['sha256']}, 'actor_original_reference')
        code = native['code']; storage = native['storage']
        need(code['code_uuid']==launch['code_uuid'] and code['release_id']==launch['release_id'] and
             code['solver_executable']==envelope['solver_executable'] and
             code['computer_uuid']==storage['computer_uuid'] and
             storage['execution_binding_uuid']==launch['native_execution_uuid'] and
             storage['relative_execution_root']==launch['relative_execution_root'] and
             storage['storage_identity']==self.qualification['write_domain']['storage_identity'], 'actor_native_binding')
        submitted = _read_submitted_files_as_owner(policy,launch,budget)
        need(submitted['files']==launch['files'], 'submitted_digest')
        budget.reserve(launch['files']['submit_script']['bytes']*8)
        script = base64.b64decode(submitted['script'],validate=True)
        need(len(script)==launch['files']['submit_script']['bytes'] and
             hashlib.sha256(script).hexdigest()==launch['files']['submit_script']['sha256'], 'submitted_digest')
        _review_native_script(script,launch,envelope['solver_executable'],context['configuration']['client']['bash_executable'],self,
                              calcjob_uuid=calcjob_uuid)
        self._refresh_caller(action)
        self._actor = {'calcjob_uuid':calcjob_uuid,'action':action,'launch':actual,
                       'execution_sha256':hashlib.sha256(raw).hexdigest()}
        return host

    def snapshot(self, launch, dispatch, budget):
        result = _read_submitted_files_as_owner(self.policy, launch, budget)
        raw = base64.b64decode(result['script'], validate=True)
        need(result['files'] == launch['files'] and len(raw) == launch['files']['submit_script']['bytes'] and
             hashlib.sha256(raw).hexdigest() == launch['files']['submit_script']['sha256'], 'submitted_digest')
        root = Path(self.policy['spool_root'])
        with protected_directory(root, budget=budget) as parent:
            name = dispatch + '.sh'; budget.file(); budget.reserve(len(raw))
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=parent)
            try:
                offset = 0
                while offset < len(raw):
                    budget.before(); count = os.write(fd, raw[offset:]); need(count > 0, 'snapshot_short_write'); offset += count
                os.fchown(fd, 0, self.policy['client_uid']); os.fchmod(fd, 0o440); os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(parent)
        return {'script_path': str(root / name), 'script_sha256': hashlib.sha256(raw).hexdigest()}

    def _check_snapshot(self, snapshot):
        need(Path(snapshot['script_path']).parent == Path(self.policy['spool_root']), 'snapshot_namespace')
        raw = protected_read(snapshot['script_path'], self.budget, self.policy['limits']['script_bytes'])
        need(hashlib.sha256(raw).hexdigest() == snapshot['script_sha256'], 'snapshot_changed')

    def dispatch(self, launch, snapshot, dispatch, budget):
        self._check_snapshot(snapshot)
        for key in ('runuser', 'sbatch'):
            trusted_root_path(self.policy['tools'][key], executable=True)
        return self.run(self._argv(launch, snapshot, dispatch), output_bytes=4096)

    def _argv(self, launch, snapshot, dispatch):
        return [self.policy['tools']['runuser'], '-u', 'qcl-negf', '--', self.policy['tools']['sbatch'],
                '--parsable', '--no-requeue', '--chdir', launch['remote_workdir'], '--comment', dispatch,
                snapshot['script_path']]

    def _intent(self, launch, snapshot, dispatch):
        _authenticate_server(self)
        need(hasattr(self,'_actor') and self._actor['launch']==launch, 'actor_input_binding_unavailable')
        caller = self._refresh_caller(self._actor['action'])
        self._submit_admission(launch)
        process = self.process(os.getpid()); unit = self.unit(process['cgroup'].rsplit('/', 1)[-1])
        packet = {'argv': self._argv(launch,snapshot,dispatch),'script_sha256':snapshot['script_sha256'],
                  'owner': {'process':process,'unit':unit,'host':self.host(),'caller':caller,'actor':self._actor}}
        _reserve_private_record(packet,self.budget)
        need(len(encoded(packet))<=49152, 'private_record_bound')
        return packet

    def native_job(self, job_id):
        need(matches(job_id, JOB), 'job_selector')
        raw = self.run([self.policy['tools']['scontrol'], '--oneliner', 'show', 'job', job_id])
        lines = [line for line in raw.splitlines() if line.strip()]
        need(len(lines) == 1, 'native_job_ambiguous')
        fields = dict(re.findall(r'(?<!\S)(\w+)=([^\s]+)', lines[0]))
        need(fields.get('JobId') == job_id and fields.get('UserId') == 'qcl-negf(3000)' and
             matches(fields.get('SubmitTime'), r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}') and
             fields.get('Restarts') == '0' and fields.get('NumNodes') == '1' and fields.get('NumTasks') == '1' and
             fields.get('ArrayJobId', '0') == fields.get('HetJobId', '0') == '0', 'native_job_changed')
        return {'raw': str(raw), 'fields': fields}

    def bind_job(self, ack, launch, dispatch, context, budget):
        observed = self.native_job(ack['job_id']); fields = observed['fields']
        need(fields.get('WorkDir') == launch['remote_workdir'] and fields.get('Comment') == dispatch and
             fields.get('Command') == str(Path(self.policy['spool_root']) / (dispatch + '.sh')),
             'native_dispatch_join_missing')
        generation = hashlib.sha256(encoded({'controller': context, 'job_id': ack['job_id'],
                          'submit_time': fields['SubmitTime'], 'dispatch_id': dispatch,
                          'command': fields['Command'], 'workdir': fields['WorkDir']})).hexdigest()
        return dict(job_id=ack['job_id'], cluster=ack['cluster'], submit_time=fields['SubmitTime'],
                    controller_machine_id=context['machine_id'], controller_boot_id=context['boot_id'],
                    dispatch_id=dispatch, generation=generation, node_name=None, start_time=None,
                    worker_machine_id=None, worker_boot_id=None)

    def worker(self, job, calcjob, phase, budget):
        from host_resource_facts import trusted_rpc
        self._calcjob = calcjob
        native = self.native_job(job['job_id'])['fields']
        need(native['SubmitTime'] == job['submit_time'] and native.get('Comment') == job['dispatch_id'], 'native_job_changed')
        node = native.get('NodeList'); route = self.policy['worker_routes'].get(node)
        need(route is not None, 'worker_not_enrolled')
        packet = trusted_rpc(route, 'attempt-facts', dict(version=1, calcjob_uuid=calcjob,
                             dispatch_id=job['dispatch_id'], job_id=job['job_id'],
                             generation=job['generation'], phase=phase),
                             run=lambda argv, **kw: self.run(argv, output_bytes=kw.get('output_bytes')),
                             trust_snapshot_root=self._trust_root(), existing_budget=budget)
        validate_worker_reply(packet)
        actual = packet['identity']['identity']
        expected = self.qualification['worker_bindings'].get(actual['machine_id'])
        need(expected is not None and all(actual[k] == expected[k] for k in expected), 'worker_generation_changed')
        need(packet['job']['fields']['SubmitTime'] == job['submit_time'] and
             packet['job']['fields'].get('Comment') == job['dispatch_id'], 'native_job_changed')
        need(packet['prolog_ref'] is not None, 'native_prolog_not_observed')
        if phase == 'close':
            need(packet['epilog_ref'] is not None, 'native_epilog_not_observed')
        return packet

    def close_writers(self, job, launch, observed, budget):
        from host_resource_facts import trusted_rpc
        domain = self.qualification['write_domain']
        exact(domain, {'storage_identity', 'native_prefix', 'retention_ref', 'writer_hosts', 'controller_units'})
        need(domain['native_prefix'] == self.policy['native_result_prefix'] and
             set(domain['writer_hosts']) == set(self.policy['worker_routes']) and
             type(domain['retention_ref']) is str and 0 < len(domain['retention_ref']) <= 256,
             'writer_domain_not_closed')
        prefix = self.policy['jobs_root'] + '/' + domain['native_prefix']
        # Actual per-service mount namespaces, not the root helper's mount view.
        units = []
        for name in domain['controller_units']:
            need(name in {'qcl-negf-aiida.service', 'qcl-negf-api.service'}, 'writer_domain_not_closed')
            unit = self.unit(name); pid = int(unit['MainPID'])
            need(unit['ActiveState'] == 'active' and pid > 0, 'writer_domain_not_closed')
            raw = budget.read('/proc/' + str(pid) + '/mountinfo', 65536).decode()
            _close_mount_line(raw,prefix,self.policy['nfs_source'])
            need(unit == self.unit(name), 'writer_domain_not_closed')
            units.append(dict(unit=name,state=unit,mountinfo=raw))
        need(set(domain['controller_units']) == {'qcl-negf-aiida.service', 'qcl-negf-api.service'}, 'writer_domain_not_closed')
        inventories = []; workers = []
        for node, route in self.policy['worker_routes'].items():
            packet = trusted_rpc(route, 'attempt-facts', dict(version=1, calcjob_uuid=self._calcjob,
                                 dispatch_id=job['dispatch_id'], job_id=job['job_id'],
                                 generation=job['generation'], phase='status'),
                                 run=lambda argv, **kw: self.run(argv, output_bytes=kw.get('output_bytes')),
                                 trust_snapshot_root=self._trust_root(), existing_budget=budget)
            validate_worker_reply(packet)
            identity = packet['identity']['identity']; expected = self.qualification['worker_bindings'].get(identity['machine_id'])
            need(expected is not None and all(identity[k] == expected[k] for k in expected), 'writer_domain_not_closed')
            need(identity['machine_id'] == domain['writer_hosts'][node], 'writer_domain_not_closed')
            inventories.append(packet['writer_snapshot'])
            workers.append(dict(node=node,reply=packet))
        known = self.managed_writers()
        enforce_writer_closure(launch['relative_execution_root'], inventories, known, job['generation'])
        return dict(storage_identity=domain['storage_identity'],native_prefix=domain['native_prefix'],
                    retention_ref=domain['retention_ref'],controller_units=units,workers=workers,managed=known)

    def _trust_root(self):
        root = Path(self.policy['private_root']) / 'trust-snapshots'
        with AttemptStore(self.policy['private_root']).directory(root, create=True):
            pass
        return root

    def managed_writers(self):
        rows = []; attempts = Path(self.policy['private_root']) / 'attempts'
        store = AttemptStore(self.policy['private_root'])
        for path in self.budget.entries(attempts, 'attempt'):
            canonical_uuid(path.name)
            claim = store.read(path.name, 'claim.json', self.budget)
            job = store.read(path.name, 'job.json', self.budget)
            need(claim is not None and job is not None, 'writer_domain_not_closed')
            rows.append({'job_id': job['job_id'], 'generation': job['generation'],
                         'dispatch_id': claim['dispatch_id'], 'domain': claim['launch']['relative_execution_root'],
                         'submit_time': job['submit_time']})
        return rows


def enforce_writer_closure(target, inventories, known, closing_generation):
    """Finite admitted managed allocations, never universal process detection."""
    path_value(target, absolute=False)
    by_job = {row['job_id']: row for row in known}
    need(len(by_job) == len(known), 'writer_domain_not_closed')
    for inventory in inventories:
        # capture_guest_facts already rejects unjoined owner processes and incomplete scans.
        need(inventory['schema'] == 'qcl.host-resource-guest-facts.v1' and
             inventory['identity_before'] == inventory['identity_after'] and inventory['slurm_registered'] is True,
             'writer_domain_not_closed')
        for key, native in inventory['jobs'].items():
            row = by_job.get(key)
            need(row is not None and native['owner_uid'] == 3000 and
                 native['submit_time'] == row['submit_time'], 'writer_domain_not_closed')
            if native['terminal']:
                # Terminal state alone is insufficient for an intersecting writer.
                group = inventory['groups'][key]
                need(group.get('populated') == 0 and not group.get('processes'), 'writer_domain_not_closed')
                continue
            need(row['generation'] != closing_generation and
                 not within(row['domain'], target) and not within(target, row['domain']), 'writer_domain_not_closed')


def validate_worker_request(document):
    exact(document, {'version', 'calcjob_uuid', 'dispatch_id', 'job_id', 'generation', 'phase'})
    need(type(document['version']) is int and document['version'] == 1)
    canonical_uuid(document['calcjob_uuid']); canonical_uuid(document['dispatch_id'])
    need(matches(document['job_id'], JOB) and matches(document['generation'], SHA) and
         document['phase'] in {'start', 'close', 'status'})
    return document


def validate_worker_reply(document):
    exact(document, {'version', 'identity', 'job', 'prolog_ref', 'epilog_ref', 'before', 'after', 'writer_snapshot'})
    need(type(document['version']) is int and document['version'] == 1, 'worker_reply')
    need(document['identity']['schema'] == 'qcl.host-resource-guest-identity.v1', 'worker_reply')
    return document


def authenticate_hook(sources):
    need(os.getuid() == os.geteuid() == 0, 'hook_credentials')
    unit = sources.unit(sources.policy['slurmd_unit']); first = sources.process(os.getpid())
    need(unit['ActiveState'] == 'active' and matches(unit['InvocationID'], r'[0-9a-f]{32}') and
         int(unit['MainPID']) > 0, 'hook_unit')
    row = first; chain = []
    for _ in range(16):
        need(row['uids'] == [0] * 4 and engine.daemon_scope_bound(row['cgroup'], unit['ControlGroup']), 'hook_ancestry')
        chain.append(row)
        if row['pid'] == int(unit['MainPID']):
            need(row['executable'] == sources.policy['tools']['slurmd'], 'hook_ancestry')
            break
        need(row['ppid'] > 1 and row['ppid'] != row['pid'], 'hook_ancestry')
        row = sources.process(row['ppid'])
    else:
        raise Hold('hook_ancestry')
    need(first == sources.process(os.getpid()) and unit == sources.unit(sources.policy['slurmd_unit']), 'hook_generation_changed')
    return {'unit': unit, 'chain': chain}


def _hook_path(policy, job, dispatch, phase):
    need(matches(job, JOB) and phase in {'prolog', 'epilog'}, 'hook_selector')
    canonical_uuid(dispatch)
    return Path(policy['private_root']) / 'hooks' / (job + '-' + dispatch + '-' + phase + '.json')


def record_slurm_hook(phase):
    budget = _bootstrap_operation(); policy = _load_policy('worker', budget)
    sources = NativeSources(policy, budget); identity = sources.qualify()
    need(phase in {'prolog', 'epilog'}, 'hook_phase')
    selector = os.environ.get('SLURM_JOB_ID'); need(matches(selector, JOB), 'hook_selector')
    job = sources.native_job(selector); fields = job['fields']; dispatch = fields.get('Comment', '')
    # A foreign job is never enrolled or blocked merely by its scheduler name.
    if not matches(dispatch, r'[0-9a-f-]{36}') or fields.get('Command') != str(Path(policy['spool_root']) / (dispatch + '.sh')):
        return
    canonical_uuid(dispatch); context = authenticate_hook(sources)
    root = Path(policy['private_root']); store = AttemptStore(root)
    with store.directory(root / 'hooks', create=True) as parent:
        raw = encoded({'identity': identity, 'job': job, 'context': context, 'phase': phase})
        budget.reserve(len(raw)); budget.file()
        path = _hook_path(policy, selector, dispatch, phase)
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            offset = 0
            while offset < len(raw):
                budget.before(); count = os.write(fd, raw[offset:]); need(count > 0, 'hook_short_write'); offset += count
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)


def _worker_capture(sources, document, identity, job):
    """Reuse unchanged scientific-independent membership/whole-stop validators."""
    import slurm_job_evidence as evidence
    p = sources.policy; budget = sources.budget; host = identity['identity']
    expected = dict(job_id=document['job_id'], owner_uid=3000, slurmstepd_executable=p['tools']['slurmstepd'],
                    cgroup_scope=p['slurm']['cgroup_scope'], identity={k: host[k] for k in ('machine_id', 'boot_id')})
    store = AttemptStore(p['private_root']); key = document['calcjob_uuid']
    before = None; after = None
    with store.locked(key, budget):
        binding = {key: value for key, value in document.items() if key != 'phase'}
        prior = store.read(key, 'worker-binding.json', budget)
        if prior is None:
            store.put(key, 'worker-binding.json', binding, budget)
        else:
            need(prior == binding, 'native_job_changed')
        before = store.read(key, 'before.json', budget)
        if before is None and document['phase'] == 'start':
            text = sources.run([p['tools']['scontrol'], 'listpids', document['job_id']])
            lines = text.splitlines(); need(lines and lines[0].split()[:2] == ['PID', 'JOBID'], 'native_start_not_observed')
            rows = []
            for line in lines[1:]:
                if not line.strip():
                    continue
                parts = line.split(); need(len(parts) >= 3 and parts[0].isdigit(), 'native_start_not_observed')
                rows.append(dict(pid=int(parts[0]), job_id=parts[1], step_id=parts[2]))
                need(len(rows) <= p['limits']['maximum_pids'], 'operation_pid_bound')
            processes = []
            for row in rows:
                observed = sources.process(row['pid'])
                processes.append({**observed, 'exe': observed['executable'], 'error': None})
            current_identity = sources.host()
            raw = {'identity_before': expected['identity'], 'identity_after': {k: current_identity[k] for k in expected['identity']},
                   'listpids': {'rc': 0, 'rows': rows}, 'processes': processes}
            store.put(key, 'before-raw.json', raw, budget)
            try:
                before = evidence.classify_before(raw, expected)
            except ValueError as error:
                raise Hold('native_start_not_observed') from error
            store.put(key, 'before.json', before, budget)
        if document['phase'] == 'close':
            need(before is not None, 'native_start_not_observed')
            evidence.validate_before(before, expected); seen = []
            for old in before['processes']:
                try:
                    row = sources.process(old['pid'])
                    seen.append({**row, 'absent': False, 'error': None})
                except FileNotFoundError:
                    need(not Path('/proc/' + str(old['pid'])).exists(), 'native_stop_not_observed')
                    seen.append({'pid': old['pid'], 'absent': True, 'error': None})
            group_path = before['job_cgroup']; path = Path('/sys/fs/cgroup' + group_path)
            try:
                events = dict(line.split() for line in budget.read(path / 'cgroup.events', 4096).decode().splitlines())
                group = dict(path=group_path, absent=False, populated=int(events['populated']))
            except FileNotFoundError:
                need(not path.exists(), 'native_stop_not_observed'); group = dict(path=group_path, absent=True, populated=None)
            last = sources.host()
            raw = {'identity_before': expected['identity'], 'identity_after': {k: last[k] for k in expected['identity']},
                   'processes': seen, 'job_cgroup': group,
                   'scheduler': dict(rc=0, job_id=document['job_id'], owner_uid=3000, state=job['fields']['JobState'])}
            # Each sample has an exclusive identity; previous failed samples survive.
            store.put(key, 'after-' + uuid.uuid4().hex + '.json', raw, budget)
            try:
                after = evidence.verify_after(before, raw, expected)
            except ValueError as error:
                raise Hold('native_stop_not_observed') from error
    return before, after


def read_attempt_facts(document):
    from host_resource_facts import LocalSources, capture_guest_identity
    validate_worker_request(document)
    budget = _bootstrap_operation(); policy = _load_policy('worker', budget)
    sources = NativeSources(policy, budget); sources.qualify()
    config = strict_json(protected_read(policy['facts_service_config'], budget).decode())
    need(config['schema'] == 'qcl.host-resource-service.v1' and config['role'] == 'guest' and
         config['client_uid'] == 3000, 'facts_config')
    facts_config = config
    class SharedSources(LocalSources):
        def read(self, path, limit=65536):
            return budget.read(path, limit).decode()
        def run(self, argv):
            return sources.run(argv)
        def processes(self):
            rows = []
            for path in budget.entries('/proc', 'pid'):
                need(len(rows) < policy['limits']['maximum_pids'], 'operation_pid_bound')
                classification = engine.process_classification(budget, path)
                if engine.process_state_class(classification) == 'nonexecuting':
                    rows.append({**classification, 'executable': '[nonexecuting]'}); continue
                raw = budget.read(path / 'stat').decode(); fields = raw[raw.rfind(')') + 2:].split()
                if int(fields[6]) & 0x00200000:
                    need(classification['uids'] == [0] * 4, 'incomplete_probe')
                    rows.append({**classification, 'executable': '[kernel]'}); continue
                rows.append(sources.process(int(path.name)))
            return rows
    local = SharedSources(facts_config, None)
    identity = capture_guest_identity(facts_config, local); job = sources.native_job(document['job_id'])
    fields = job['fields']; dispatch = document['dispatch_id']
    need(fields.get('Comment') == dispatch and fields.get('Command') == str(Path(policy['spool_root']) / (dispatch + '.sh')), 'native_dispatch_join_missing')
    generation = hashlib.sha256(encoded({'controller': sources.qualification['controller_binding'],
                    'job_id': document['job_id'], 'submit_time': fields['SubmitTime'], 'dispatch_id': dispatch,
                    'command': fields['Command'], 'workdir': fields['WorkDir']})).hexdigest()
    need(document['generation'] == generation, 'native_job_changed')
    refs = {}
    for phase in ('prolog', 'epilog'):
        path = _hook_path(policy, document['job_id'], dispatch, phase)
        try:
            record = strict_json(protected_read(path, budget).decode())
            current_unit = sources.unit(policy['slurmd_unit'])
            need(record['context']['unit'] == current_unit and record['identity'] == sources.host() and
                 record['job']['fields']['SubmitTime'] == fields['SubmitTime'] and
                 record['job']['fields']['Command'] == fields['Command'] and record['phase'] == phase, 'hook_generation_changed')
            refs[phase] = str(path.relative_to(policy['private_root']))
        except FileNotFoundError:
            refs[phase] = None
    if document['phase'] != 'status':
        need(refs['prolog'] is not None, 'native_prolog_not_observed')
    if document['phase'] == 'close':
        need(refs['epilog'] is not None, 'native_epilog_not_observed')
    before, after = _worker_capture(sources, document, identity, job) if document['phase'] != 'status' else (None, None)
    return dict(version=1, identity=identity, job=job, prolog_ref=refs['prolog'], epilog_ref=refs['epilog'],
                before=before, after=after, writer_snapshot=_capture_writer_snapshot(facts_config, local, budget))


def _capture_writer_snapshot(config, local, budget):
    """Bounded existing facts subset; every admitted UID3000 process is joined."""
    from host_resource_facts import capture_scheduler
    first = local.host(); processes = local.processes(); all_jobs = capture_scheduler(config, local)
    jobs = {key: value for key, value in all_jobs.items() if value['node'] == config['node']}
    need(all(j['owner_uid'] == 3000 for j in jobs.values()), 'writer_domain_not_closed')
    root = path_value(config['slurm_cgroup_root'], absolute=True)
    groups = {}
    for key in jobs:
        scope = root + '/job_' + key
        members = [p for p in processes if engine.daemon_scope_bound(p['cgroup'], scope)]
        try:
            events = dict(line.split() for line in budget.read('/sys/fs/cgroup' + scope + '/cgroup.events', 4096).decode().splitlines())
            need(events.get('populated') in {'0', '1'}, 'writer_domain_not_closed')
            populated = events['populated'] == '1'
        except FileNotFoundError:
            need(not Path('/sys/fs/cgroup' + scope).exists(), 'writer_domain_not_closed'); populated = False
        need(populated == bool(members), 'writer_domain_not_closed')
        groups[key] = {'populated': populated, 'processes': members}
    for process in processes:
        if 3000 not in process['uids']:
            continue
        managed = any(engine.daemon_scope_bound(process['cgroup'], root + '/job_' + job) for job in jobs)
        infrastructure = any(process['cgroup'] == row['cgroup'] and process['executable'] == row['executable']
                             for row in config['infrastructure_processes'])
        need(managed or infrastructure, 'writer_domain_not_closed')
    last = local.host()
    need(all(first[k] == last[k] for k in ('machine_id', 'boot_id', 'kernel', 'dmi_uuid')), 'writer_domain_not_closed')
    unit = engine.unit_state(lambda argv: local.run([config['systemctl'], *argv[1:]]), 'slurmd.service')
    main = next((p for p in processes if str(p['pid']) == unit['MainPID']), None)
    need(main is not None and main['uids'] == [0] * 4 and main['cgroup'] == unit['ControlGroup'] and
         main['executable'] == config['slurmd_executable'] and unit['ActiveState'] == 'active', 'writer_domain_not_closed')
    identity = {k: first[k] for k in ('machine_id', 'boot_id', 'kernel', 'dmi_uuid')}
    return dict(schema='qcl.host-resource-guest-facts.v1', identity_before=identity, identity_after=identity,
                jobs=jobs, groups=groups, slurm_registered=True)


def _authenticate_server(sources):
    process = sources.process(os.getpid()); unit_name = process['cgroup'].rsplit('/', 1)[-1]
    need(unit_name.startswith(sources.policy['server_unit_prefix']) and unit_name.endswith('.service') and
         process['uids'] == [0] * 4, 'server_unit')
    unit = sources.unit(unit_name)
    need(unit['ActiveState'] == 'active' and matches(unit['InvocationID'], r'[0-9a-f]{32}') and
         unit['ControlGroup'] == process['cgroup'] and int(unit['MainPID']) == os.getpid(), 'server_unit')
    need(unit['MemoryMax'].isdigit() and int(unit['MemoryMax']) >= sources.policy['limits']['memory_bytes'] and
         int(unit['MemoryMax']) <= 134217728, 'server_limits')
    # systemctl renders RuntimeMaxUSec as a human duration; require the fixed module bound.
    need(unit['RuntimeMaxUSec'] in {'1min 30s', '90s'}, 'server_limits')
    expected = sources.qualification['unit_origins']['server']['executable']
    need(process['executable'] == expected and _caller_generation(process) == _caller_generation(sources.process(os.getpid())) and
         unit == sources.unit(unit_name), 'server_generation_changed')
    sources._server_unit = unit_name


def handle_connection(connection):
    budget = _bootstrap_operation(); document = {}; result = None
    try:
        policy = _load_policy('controller', budget); sources = NativeSources(policy, budget)
        sources.qualify(); _authenticate_server(sources)
        document = read_frame(connection, budget, policy['limits']['request_bytes'])
        action = validate_request(document)['action']
        sources._caller = authenticate_socket_peer(connection,policy,sources,action=action)
        owner = OrdinaryAttemptOwner(policy, AttemptStore(policy['private_root']), sources, budget)
        result = {'submit': owner.submit, 'reconcile': owner.reconcile, 'start': owner.observe_start,
                  'close': owner.qualify_close, 'status': owner.status}[action](document)
    except (Hold, OSError, ValueError, ResourceError, KeyError, engine.CommandFailure) as error:
        reason = error.reason if isinstance(error, Hold) else getattr(error, 'code', 'native_observation_failed')
        if isinstance(error,engine.CommandFailure): _preclaim_diagnostic(error)
        result = reply({}, 'hold', reason=reason)
    write_frame(connection, result, budget, budget.limits['response_bytes'])


def server_main():
    need(len(sys.argv) == 1, 'server_arguments')
    with socket.socket(fileno=os.dup(0)) as connection:
        handle_connection(connection)
    return 0


def _client_operation():
    need(len(sys.argv) == 2 and sys.argv[1] in {'submit', 'reconcile', 'start', 'close', 'status'}, 'client_arguments')
    budget = _bootstrap_operation()
    raw = sys.stdin.buffer.read(65537); need(0 < len(raw) <= 65536, 'frame_bound')
    document = validate_request(strict_json(raw.decode('utf-8')))
    need(document['action'] == sys.argv[1], 'client_action')
    with protected_directory(Path(SOCKET).parent, budget=budget) as parent:
        first = os.stat(Path(SOCKET).name, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISSOCK(first.st_mode) and first.st_uid == 0 and first.st_gid == 3000 and
             stat.S_IMODE(first.st_mode) == 0o660, 'socket_namespace')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(budget.limits['operation_seconds']); connection.connect(SOCKET)
            need(signature(first) == signature(os.stat(Path(SOCKET).name, dir_fd=parent, follow_symlinks=False)), 'socket_namespace')
            _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            need(uid == 0, 'server_credentials')  # PID1 is legitimate under socket activation.
            write_frame(connection, document, budget, 65536); connection.shutdown(socket.SHUT_WR)
            result = read_frame(connection, budget, 262144)
    validate_reply(result)
    need(result['calcjob_uuid'] in (None, document['calcjob_uuid']), 'reply_binding')
    print(encoded(result).decode())
    return 0 if result['state'] in {'bound', 'started', 'closed'} else 75


def client_main():
    try:
        return _client_operation()
    except (Hold, OSError, ValueError, ResourceError, KeyError) as error:
        reason = error.reason if isinstance(error, Hold) else getattr(error, 'code', 'transport_outcome_unknown')
        print(encoded(reply({}, 'hold', reason=reason)).decode())
        return 75


def hook_main():
    need(len(sys.argv) == 2 and sys.argv[1] in {'prolog', 'epilog'}, 'hook_arguments')
    try:
        record_slurm_hook(sys.argv[1])
    except engine.CommandFailure as error:
        # Qualification/query can fail before this global hook knows whether
        # the job is managed. Preserve bounded original context, no lifecycle.
        raw = encoded(error.record)
        diagnostic = {'reason': 'native_command_failed',
                      'original_prefix_base64': base64.b64encode(raw[:2048]).decode('ascii'),
                      'original_bytes': len(raw), 'original_sha256': hashlib.sha256(raw).hexdigest(),
                      'truncated': len(raw) > 2048}
        print('native-attempt hook HOLD: ' + encoded(diagnostic).decode(), file=sys.stderr)
    except (Hold, OSError, ValueError, ResourceError, KeyError) as error:
        # Missing hook evidence blocks subsequent managed close. Do not fail a
        # foreign Slurm job or create another job/retry owner from a global hook.
        print('native-attempt hook HOLD: ' + getattr(error, 'reason', getattr(error, 'code', 'native_observation_failed')), file=sys.stderr)
    return 0
