"""Fixed private Task3 readers and canonical worker mirror storage.

This is an internal Source adapter, never a public action or a scheduler. A
Python object and root UID do not authenticate administrative transport. Native
writers require their separately admitted existing worker/Root transport owner.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import time
import uuid

import native_attempt as native
from host_resource_operations import integer, require, strict_json
from host_resource_qualification_gate import (decode_permit, demands, digest, exact,
    mirror_record, sha, store_path)

PRIVATE_ROOT = Path('/var/lib/qcl-negf-native-attempt')
ROLE_SCHEMA = 'qcl.host-resource-calibration-role-view.v1'
SUBSET_SCHEMA = 'qcl.host-resource-calibration-role-subset.v1'
SUBSET_LIMIT = 65536


def _protected_owner_uid():
    return 0


def _reader_source(budget):
    path = native.engine.public_binary_origin(budget, __file__, executable=False)['path']
    store_path(path)
    data = native.engine.immutable_public_bytes(budget, path, 262144)
    return dict(path=path, sha256=hashlib.sha256(data).hexdigest())


def _receiver_native_id(source):
    value = source.budget.read('/sys/class/dmi/id/product_uuid', 64).decode().strip().lower()
    return native.canonical_uuid(value)


def decode_selector(value):
    exact(value, {'schema', 'role', 'operation_id', 'permit_sha256', 'parent_plan_sha256',
        'fence_sha256', 'capacity_report_sha256', 'source_graph_sha256', 'native_host',
        'receiver', 'reader_source'})
    require(value['schema'] == ROLE_SCHEMA and value['role'] in ('controller', 'worker'),
        'qualification_selector', 'fixed role selector required')
    native.canonical_uuid(value['operation_id'])
    for key in ('permit_sha256', 'parent_plan_sha256', 'fence_sha256',
            'capacity_report_sha256', 'source_graph_sha256'):
        sha(value[key])
    host = exact(value['native_host'], {'host_id', 'host_boot_id', 'policy_sha256', 'baseline_state_sha256'})
    require(native.matches(host['host_id'], native.ID), 'qualification_selector', 'native host identity required')
    native.canonical_uuid(host['host_boot_id'])
    sha(host['policy_sha256']); sha(host['baseline_state_sha256'])
    receiver = exact(value['receiver'], {'native_id', 'machine_id', 'boot_id', 'native_policy_sha256'})
    native.canonical_uuid(receiver['native_id']); native.canonical_uuid(receiver['boot_id'])
    require(native.matches(receiver['machine_id'], r'[0-9a-f]{32}'),
        'qualification_selector', 'receiver machine identity required')
    sha(receiver['native_policy_sha256'])
    reader = exact(value['reader_source'], {'path', 'sha256'})
    store_path(reader['path']); sha(reader['sha256'])
    return value


def _private_directory(path):
    info = Path(path).lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == _protected_owner_uid() and
        stat.S_IMODE(info.st_mode) == 0o700,
        'qualification_namespace', 'root0700 private role namespace required')


def _read_private(path, budget, limit=SUBSET_LIMIT):
    """Same held FD/named inode; strict private mode and bounded raw bytes."""
    path = Path(path)
    require(path.is_relative_to(PRIVATE_ROOT), 'qualification_namespace', 'fixed private root required')
    _private_directory(PRIVATE_ROOT)
    cursor = PRIVATE_ROOT
    for part in path.parent.relative_to(PRIVATE_ROOT).parts:
        cursor /= part
        _private_directory(cursor)
    with native.protected_directory(path.parent, budget=budget) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            opened = os.fstat(fd)
            require(stat.S_ISREG(opened.st_mode) and opened.st_size <= limit,
                'output_bound', 'bounded private regular record required')
            data, info = native.read_fd(fd, opened.st_size, budget)
            require(info.st_uid == _protected_owner_uid() and stat.S_IMODE(info.st_mode) == 0o600 and
                info.st_nlink == 1 and native.signature(info) == native.signature(
                    os.stat(path.name, dir_fd=parent, follow_symlinks=False)),
                'qualification_namespace', 'root0600 single held/named original required')
            return data
        finally:
            os.close(fd)


def _decode_clock(value):
    exact(value, {'clock', 'boot_id', 'nanoseconds', 'reader_source'})
    require(value['clock'] == 'CLOCK_BOOTTIME', 'qualification_clock', 'suspend-aware local clock required')
    native.canonical_uuid(value['boot_id']); integer(value['nanoseconds'], 'receiver boottime')
    exact(value['reader_source'], {'path', 'sha256'})
    store_path(value['reader_source']['path']); sha(value['reader_source']['sha256'])
    return value


def _mirror(permit, calc, value):
    require(calc in permit['jobs'], 'qualification_job', 'job outside finite original permit')
    if value is None:
        return None
    stage = mirror_record(permit, calc, None, revision=0, enabled=False)
    if value == stage or value == {**stage, 'revision': 2, 'enabled': False}:
        return value
    require(type(value) is dict and value.get('revision') in (1, 2),
        'qualification_mirror', 'exact canonical mirror required')
    expected = mirror_record(permit, calc, value.get('creator'), revision=value['revision'],
        enabled=value['revision'] == 1, command=value.get('command'),
        original_intent_sha256=value.get('original_intent_sha256'))
    require(value == expected, 'qualification_mirror', 'original mirror bytes differ')
    return value


class RoleView:
    """Read only fixed local originals. Construction confers no write authority."""
    def __init__(self, native_sources):
        self.sources = native_sources
        self.budget = native_sources.budget
        self.root = Path(native_sources.policy['private_root'])
        require(self.root == PRIVATE_ROOT and native_sources.policy['role'] in ('controller', 'worker'),
            'qualification_selector', 'fixed native role policy required')
        self.current_path = self.root / 'qualification/current.json'

    def _selector(self):
        raw = _read_private(self.current_path, self.budget)
        value = decode_selector(strict_json(raw.decode()))
        host = self.sources.host()
        require(value['role'] == self.sources.policy['role'] and
            value['receiver']['machine_id'] == host['machine_id'] and
            value['receiver']['boot_id'] == host['boot_id'] and
            value['receiver']['native_id'] == _receiver_native_id(self.sources) and
            value['receiver']['native_policy_sha256'] == self.sources.policy['_policy_sha256'] and
            value['reader_source'] == _reader_source(self.budget),
            'qualification_selector', 'actual role/receiver/policy/Source differs')
        return value, raw

    def snapshot(self):
        selector, original = self._selector()
        folder = self.root / 'qualification' / selector['operation_id']
        originals = {}
        for name, pin, limit in (('permit.json', 'permit_sha256', 1024**2),
                ('parent-plan.json', 'parent_plan_sha256', 1024**2),
                ('parent-fence.json', 'fence_sha256', 1024**2),
                ('capacity-report.json', 'capacity_report_sha256', 8*1024**2)):
            data = _read_private(folder / name, self.budget, limit)
            require(hashlib.sha256(data).hexdigest() == selector[pin],
                'qualification_parent', 'exact original protected parent reference differs')
            originals[name] = strict_json(data.decode())
        permit = decode_permit(originals['permit.json'])
        require(permit['operation_id'] == selector['operation_id'] and
            all(permit[key] == selector[key] for key in ('parent_plan_sha256', 'fence_sha256',
                'capacity_report_sha256', 'source_graph_sha256')),
            'qualification_parent', 'original permit/context differs')
        require(self._selector()[1] == original, 'qualification_changed', 'role selector changed')
        return selector, permit, folder, originals

    def current_permit(self):
        return self.snapshot()[1]

    def mirror_read(self, calc):
        native.canonical_uuid(calc)
        selector, permit, folder, originals = self.snapshot()
        require(selector['role'] == 'worker', 'qualification_role', 'canonical mirrors belong to worker')
        require(calc in permit['jobs'], 'qualification_job', 'job outside finite original permit')
        try:
            value = strict_json(_read_private(folder / 'mirrors' / (calc + '.json'), self.budget).decode())
        except FileNotFoundError:
            value = None
        return _mirror(permit, calc, value)

    def capture_clock(self):
        selector, original = self._selector()
        first = self.sources.host()
        stamp = dict(clock='CLOCK_BOOTTIME', boot_id=first['boot_id'],
            nanoseconds=time.clock_gettime_ns(time.CLOCK_BOOTTIME), reader_source=_reader_source(self.budget))
        _decode_clock(stamp)
        require(first == self.sources.host() and self._selector()[1] == original and
            stamp['boot_id'] == selector['receiver']['boot_id'],
            'qualification_clock', 'role receiver changed during clock capture')
        return stamp

    def readonly_subset(self):
        selector, permit, folder, originals = self.snapshot()
        mirrors = {calc: self.mirror_read(calc) for calc in permit['jobs']} if selector['role'] == 'worker' else {}
        value = dict(schema=SUBSET_SCHEMA, selector=selector, selector_sha256=hashlib.sha256(
            _read_private(self.current_path, self.budget)).hexdigest(), permit=permit,
            permit_sha256=selector['permit_sha256'], mirrors=mirrors, capture_clock=self.capture_clock())
        require(len(native.encoded(value)) <= SUBSET_LIMIT, 'output_bound', 'fixed readonly qualification subset overflow')
        require(self.snapshot()[:2] == (selector, permit), 'qualification_changed', 'role originals changed')
        if selector['role'] == 'worker':
            require(all(self.mirror_read(calc) == mirror for calc, mirror in mirrors.items()),
                'qualification_changed', 'canonical mirror changed during subset capture')
        return value


class CanonicalMirrorStore:
    """Atomic CAS mechanism; only an admitted internal Root transport may call it.

    This mechanism is not returned by either read factory. The production QGA
    entry must authenticate its original transport before reaching this class.
    """
    def __init__(self, view):
        self.view = view

    def cas(self, calc, expected, desired):
        view = self.view
        native.canonical_uuid(calc)
        selector, permit, folder, originals = view.snapshot()
        require(selector['role'] == 'worker', 'qualification_role', 'worker canonical CAS only')
        stage = mirror_record(permit, calc, None, revision=0, enabled=False)
        require((expected is None and desired == stage) or
            (expected == stage and type(desired) is dict and
                (desired == {**stage, 'revision': 2, 'enabled': False} or
                 (desired.get('revision') == 1 and _mirror(permit, calc, desired) == desired))) or
            (type(expected) is dict and expected.get('revision') == 1 and
                _mirror(permit, calc, expected) == expected and
                desired == {**expected, 'revision': 2, 'enabled': False}),
            'qualification_cas', 'exact original None/0/1/2 or disabled0-to2 transition required')
        store = native.AttemptStore(view.root)
        with store.locked(calc, view.budget):
            require(view.mirror_read(calc) == expected, 'qualification_cas', 'original canonical expected bytes differ')
            require(view.snapshot()[:2] == (selector, permit), 'qualification_changed', 'role originals changed before CAS')
            directory = folder / 'mirrors'
            _private_directory(directory)
            data = native.encoded(desired)
            view.budget.reserve(len(data)); view.budget.file()
            with native.protected_directory(directory, budget=view.budget) as parent:
                temporary = '.cas-' + str(uuid.uuid4())
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600, dir_fd=parent)
                try:
                    offset = 0
                    while offset < len(data):
                        view.budget.before()
                        count = os.write(fd, data[offset:])
                        require(count > 0, 'qualification_cas', 'short canonical mirror write')
                        offset += count
                    os.fsync(fd)
                finally:
                    os.close(fd)
                # Initial install is exclusive; subsequent replacement is under
                # the same existing nonblocking per-CalcJob owner lock.
                if expected is None:
                    os.link(temporary, calc + '.json', src_dir_fd=parent, dst_dir_fd=parent,
                        follow_symlinks=False)
                    os.unlink(temporary, dir_fd=parent)
                else:
                    os.rename(temporary, calc + '.json', src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
            require(view.mirror_read(calc) == desired, 'qualification_cas', 'canonical CAS readback differs')
            return desired


def _worker_role_packet(native_sources, row):
    from host_resource_facts import trusted_rpc
    route = native_sources.policy['worker_routes'].get(row['node_name'])
    require(route is not None, 'qualification_role', 'original enrolled worker route required')
    packet = trusted_rpc(route, 'guest-facts', {},
        run=lambda argv, **kw: native_sources.run(argv, output_bytes=kw.get('output_bytes')),
        existing_budget=native_sources.budget)
    require(type(packet) is dict and type(packet.get('qualification')) is dict,
        'qualification_observations_required', 'canonical worker readonly subset missing')
    return packet['qualification']


class ControllerQualificationView:
    """No PVE object or mutable mirror replica on the controller."""
    def __init__(self, view):
        self.view = view

    def mirror_read(self, calc):
        selector, permit, folder, originals = self.view.snapshot()
        require(selector['role'] == 'controller' and calc in permit['jobs'],
            'qualification_role', 'fixed controller finite member required')
        packet = _worker_role_packet(self.view.sources, permit['jobs'][calc])
        exact(packet, {'schema', 'selector', 'selector_sha256', 'permit', 'permit_sha256', 'mirrors', 'capture_clock'})
        worker = decode_selector(packet['selector'])
        row = permit['jobs'][calc]
        require(packet['schema'] == SUBSET_SCHEMA and len(native.encoded(packet)) <= SUBSET_LIMIT and
            worker['role'] == 'worker' and worker['operation_id'] == selector['operation_id'] and
            all(worker[k] == selector[k] for k in ('permit_sha256', 'parent_plan_sha256', 'fence_sha256',
                'capacity_report_sha256', 'source_graph_sha256', 'native_host', 'reader_source')) and
            worker['receiver']['machine_id'] == row['worker_machine_id'] and
            worker['receiver']['boot_id'] == row['worker_boot_id'] and
            packet['permit'] == permit and packet['permit_sha256'] == selector['permit_sha256'] and
            type(packet['mirrors']) is dict and set(packet['mirrors']) == set(permit['jobs']),
            'qualification_mirror', 'authenticated canonical worker context differs')
        sha(packet['selector_sha256'])
        stamp = _decode_clock(packet['capture_clock'])
        require(stamp['boot_id'] == row['worker_boot_id'] and stamp['reader_source'] == worker['reader_source'],
            'qualification_clock', 'worker source clock differs')
        for key, value in packet['mirrors'].items():
            _mirror(permit, key, value)
        return packet['mirrors'][calc]

    def submit_permit(self, launch, *, calcjob_uuid, actor=None, fixture=None):
        permit = self.view.current_permit()
        exact(actor, {'calcjob_uuid', 'action', 'launch', 'execution_sha256'})
        require(calcjob_uuid in permit['jobs'] and actor['calcjob_uuid'] == calcjob_uuid,
            'qualification_job', 'authenticated finite original actor required')
        mirrors = {calc: self.mirror_read(calc) for calc in permit['jobs']}
        require(all(mirror is not None and mirror['revision'] in (0, 1) for mirror in mirrors.values()) and
            mirrors[calcjob_uuid] == mirror_record(permit, calcjob_uuid, None, revision=0, enabled=False),
            'qualification_mirror', 'complete unrevoked set and original staged candidate required')
        from host_resource_qualification_gate import calibration_submit_allowed
        calibration_submit_allowed(launch, actor, permit, self, fixture=fixture)
        return permit

    def held_argv(self, launch, snapshot, dispatch):
        # Same existing historical API as QualificationJobs. It returns only
        # whether the original argv was held; it cannot authorize dispatch.
        permit = self.view.current_permit()
        selected = []
        for calc, row in permit['jobs'].items():
            mirror = self.mirror_read(calc)
            if row['launch'] != launch or mirror is None or mirror['creator'] is None:
                continue
            if mirror['creator']['dispatch_id'] == dispatch:
                require(snapshot == dict(script_path=mirror['command'],
                    script_sha256=launch['files']['submit_script']['sha256']),
                    'qualification_creator', 'historical original snapshot differs')
                selected.append(calc)
        require(len(selected) <= 1, 'qualification_creator', 'ambiguous historical original')
        return bool(selected)

    def protect_commitments(self, permit, commitments, phase):
        return _protect_role_commitments(self.view, permit, commitments, phase)


def open_controller_jobs(native_sources):
    require(native_sources.policy['role'] == 'controller' and
        type(native_sources.qualification) is dict and hasattr(native_sources, '_caller') and
        hasattr(native_sources, '_server_unit'),
        'qualification_controller', 'existing qualified socket owner required')
    view = RoleView(native_sources)
    try:
        view._selector()
    except FileNotFoundError:
        # Only absence of the selector permits ordinary CLOSED behavior.
        require(not view.current_path.exists() and not view.current_path.is_symlink(),
            'qualification_selector', 'unknown present selector is not absent')
        return None
    view.current_permit()
    return ControllerQualificationView(view)


def _protect_role_commitments(view, permit, commitments, phase):
    require(view.current_permit() == permit and tuple(commitments) == demands(permit),
        'qualification_parent', 'complete original finite demand set required')
    proof = read_host_proof(view, permit)
    _validate_reservation_capacity(view, permit, proof)
    return proof


def open_native_jobs(service):
    raise native.Hold('qualification_worker_phase_required')


def import_role_snapshot(payload):
    ingress = _admit_root_transport()
    return _import_role_snapshot(ingress, payload)


def cas_worker_mirror(calc, expected, desired):
    ingress = _admit_root_transport()
    return CanonicalMirrorStore(ingress.view).cas(calc, expected, desired)


def _open_role_sources(role):
    budget = native._bootstrap_operation()
    policy = native._load_policy(role, budget)
    sources = native.NativeSources(policy, budget)
    sources.qualify()
    return sources


def open_role_readonly_subset(role):
    """Fixed root read, including controller clocks without worker facts."""
    require(role in ('controller', 'worker'), 'qualification_role', 'fixed native role required')
    path = PRIVATE_ROOT / 'qualification/current.json'
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    return RoleView(_open_role_sources(role)).readonly_subset()


def open_guest_gate_sources(local_sources):
    require(local_sources.config['role'] == 'guest', 'qualification_role', 'local worker gate only')
    sources = _open_role_sources('worker')
    view = RoleView(sources)
    view.current_permit()
    return GuestGateSources(view, local_sources)


class GuestGateSources:
    """Twelve read ports and three ingress ports over the existing actual owner.

    Raw membership survives every refusal. Only exact authenticated own ancestry
    and the original P11 child have a separate, retained exclusion witness.
    """
    def __init__(self, view, local_sources):
        self.view, self.sources, self.local = view, view.sources, local_sources
        self.membership_observations = []

    def current_permit(self):
        return self.view.current_permit()

    def mirror_read(self, calc):
        return self.view.mirror_read(calc)

    def scheduler_job(self, job):
        return self.sources.native_job(job)['fields']

    def original_prolog(self, job, dispatch):
        path = native._hook_path(self.sources.policy, job, dispatch, 'prolog')
        value = strict_json(_read_private(path, self.sources.budget, 1024**2).decode())
        exact(value, {'phase', 'identity', 'job', 'context'})
        require(value['phase'] == 'prolog' and value['job']['fields']['JobId'] == job and
            value['job']['fields'].get('Comment') == dispatch,
            'qualification_prolog', 'original root prolog selector differs')
        return value

    def slurmd_unit(self):
        return self.sources.unit(self.sources.policy['slurmd_unit'])

    def process(self, pid):
        integer(pid, 'actual process PID', 1)
        return self.sources.process(pid)

    def command_line(self, pid):
        integer(pid, 'actual process PID', 1)
        return self.sources.command_line(pid)

    def origin(self, path):
        return self.sources.origin(path)

    def _loaded_source(self, pid, kind):
        from host_resource_qualification_gate import process_identity
        permit = self.current_permit()
        selected = permit[kind]
        before = self.process(pid); argv = self.command_line(pid)
        source = selected['source_path']; ops = str(Path(source).parent)
        module = 'application_release' if kind == 'guard' else 'host_resource_service'
        call = 'm.main()' if kind == 'guard' else "sys.exit(m.main('client'))"
        expression = f"import sys; sys.path.insert(0, '{ops}'); import {module} as m; {call}"
        require(selected['argv_prefix'][3] == expression and argv[:4] == selected['argv_prefix'] and
            before['executable'] == selected['executable'] == self.origin(selected['argv_prefix'][0]) and
            self.origin(before['executable']) == before['executable'],
            'qualification_origin', 'actual isolated immutable interpreter/loader chain differs')
        actual_path = native.engine.public_binary_origin(self.sources.budget, source, executable=False)['path']
        require(actual_path == source and Path(source).name == module + '.py',
            'qualification_origin', 'immutable loaded module origin differs')
        data = native.engine.immutable_public_bytes(self.sources.budget, source, 1024**2)
        require(hashlib.sha256(data).hexdigest() == selected['source_sha256'] and
            self.command_line(pid) == argv and process_identity(self.process(pid)) == process_identity(before),
            'qualification_changed', 'loaded Source/process changed')
        return dict(path=source, sha256=selected['source_sha256'])

    def loaded_guard_source(self, pid):
        return self._loaded_source(pid, 'guard')

    def batch_script(self, bash_pid):
        """Actual held script inode, not a same-hash file selected by caller."""
        from host_resource_qualification_gate import process_identity
        before = self.process(bash_pid); argv = self.command_line(bash_pid)
        permit = self.current_permit()
        require(len(argv) == 2 and argv[0] == permit['bash_executable'] and
            before['executable'] == permit['bash_executable'],
            'qualification_script', 'original direct bash argv required')
        native.path_value(argv[1], absolute=True)
        path = Path(argv[1]); budget = self.sources.budget
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            data, named = native.read_fd(fd, self.sources.policy['limits']['script_bytes'], budget)
            matches = []
            for item in budget.entries('/proc/' + str(bash_pid) + '/fd', 'fd'):
                require(len(matches) <= 1, 'qualification_script', 'unique held original script required')
                require(item.name.isdigit(), 'qualification_script', 'literal proc FD required')
                try:
                    info = item.stat()
                except FileNotFoundError as error:
                    raise native.Hold('qualification_script_changed') from error
                if stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) == (named.st_dev, named.st_ino):
                    held = os.open(item, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                    try:
                        held_data, held_info = native.read_fd(held, self.sources.policy['limits']['script_bytes'], budget)
                        require(native.signature(held_info) == native.signature(named) and held_data == data,
                            'qualification_script', 'held and named script differ')
                        matches.append((item.name, held_info))
                    finally:
                        os.close(held)
            require(len(matches) == 1 and native.signature(os.fstat(fd)) == native.signature(path.lstat()) and
                process_identity(self.process(bash_pid)) == process_identity(before) and
                self.command_line(bash_pid) == argv,
                'qualification_script', 'unique original script FD/process join required')
            return dict(path=str(path), sha256=hashlib.sha256(data).hexdigest())
        finally:
            os.close(fd)

    def _membership_cohort(self, permit):
        """Re-observe only this interpreter's authenticated original ancestry."""
        from host_resource_qualification_gate import process_identity
        caller = process_identity(self.authenticated_caller())
        own = self.root_ingress()
        root = process_identity(own['process'])
        selected = permit['client_root']
        require(root['pid'] == os.getpid() and root['uids'] == [0]*4 and
            root['executable'] == selected['executable'] and root['cgroup'] == caller['cgroup'] and
            own['source'] == dict(path=selected['source_path'], sha256=selected['source_sha256']) and
            len(own['argv']) == len(selected['argv_prefix'])+2 and
            own['argv'][:-1] == selected['argv_prefix']+['qualification-gate'] and
            self.origin(selected['argv_prefix'][0]) == root['executable'],
            'qualification_membership_owner_required', 'actual fixed own root Source/ancestry required')
        chain = [dict(process=root, argv_sha256=native.engine.command_argv_sha256(own['argv']), kind='client-root')]
        pid = root['ppid']
        for _ in range(8):
            item = process_identity(self.process(pid))
            if pid == caller['pid']:
                require(item == caller, 'qualification_changed', 'original authenticated caller changed')
                break
            require(item['executable'] in self.local.config['sudo_executables'] and
                item['uids'] in ([0]*4, [permit['client_uid'], 0, 0, 0], [permit['client_uid']]*4) and
                self.origin(item['executable']) == item['executable'],
                'qualification_membership_owner_required', 'only own enrolled sudo ancestors may be excluded')
            chain.append(dict(process=item, argv_sha256=native.engine.command_argv_sha256(self.command_line(pid)), kind='sudo'))
            pid = item['ppid']
        else:
            raise native.Hold('qualification_membership_owner_required')
        require(len(chain) >= 2 and chain[0]['process']['ppid'] == chain[1]['process']['pid'] and
            all(child['process']['ppid'] == parent['process']['pid'] and
                child['process']['start_ticks'] >= parent['process']['start_ticks'] > 0 and
                child['process']['cgroup'] == parent['process']['cgroup'] for child, parent in
                zip(chain, chain[1:]+[dict(process=caller)])),
            'qualification_membership_owner_required', 'original direct sudo/root birth chain required')
        return dict(caller=caller, chain=chain)

    def batch_membership(self, creator):
        import slurm_job_evidence as evidence
        from host_resource_qualification_gate import process_identity
        from collections.abc import Mapping
        def retained(value):
            if isinstance(value, Mapping):
                return {key: retained(item) for key, item in value.items()}
            if isinstance(value, tuple):
                return [retained(item) for item in value]
            return value
        permit = self.current_permit()
        host = self.sources.host()
        candidates = [row for row in permit['jobs'].values() if
            row['worker_machine_id'] == host['machine_id'] and row['worker_boot_id'] == host['boot_id']]
        require(candidates, 'qualification_membership', 'original worker binding required')
        identity = {key: host[key] for key in ('machine_id', 'boot_id')}
        raw = dict(identity_before=identity, identity_after=None, listpids=dict(rc=None, rows=[]),
            processes=[], command_observations=[])
        self.membership_observations.append(raw)
        require(len(self.membership_observations) <= 2, 'output_bound', 'two original readonly membership samples only')
        argv = [self.sources.policy['tools']['scontrol'], 'listpids', creator['job_id']]
        def observer(event):
            observed = retained(event)
            raw['command_observations'].append(observed)
            require(len(raw['command_observations']) <= 2, 'output_bound', 'one original child birth and terminal only')
            if observed['phase'] == 'spawned':
                cohort = self._membership_cohort(permit)
                child = process_identity(observed['child'])
                root = cohort['chain'][0]['process']
                require(observed['schema'] == 'qcl.command-owned-readonly-observation.v1' and
                    observed['command_owner'] == root and child['ppid'] == root['pid'] and
                    child['start_ticks'] >= root['start_ticks'] and child['uids'] == root['uids'] and
                    child['cgroup'] == root['cgroup'] and child['executable'] == self.origin(argv[0]) and
                    observed['argv_sha256'] == native.engine.command_argv_sha256(argv),
                    'qualification_membership_owner_required', 'actual same-owner original listpids child required')
                raw['cohort_before'] = cohort
        try:
            text = self.sources.run(argv, process_observer=observer)
        except Exception as error:
            record = getattr(error, 'record', getattr(error, 'command_record', None))
            raw['command_failure'] = record if record is not None else dict(error=type(error).__name__)
            raise native.Hold('qualification_membership_owner_required') from error
        raw['listpids']['stdout'] = str(text)
        lines = text.splitlines()
        require(lines and lines[0].split()[:2] == ['PID', 'JOBID'],
            'qualification_membership', 'actual listpids protocol required')
        raw['listpids']['rc'] = 0
        for line in lines[1:]:
            if not line.strip():
                continue
            parts = line.split()
            require(len(parts) >= 3 and parts[0].isdigit(),
                'qualification_membership', 'literal complete listpids row required')
            pid = int(parts[0])
            raw['listpids']['rows'].append(dict(pid=pid, job_id=parts[1], step_id=parts[2]))
            require(len(raw['listpids']['rows']) <= self.sources.budget.limits['maximum_pids'],
                'output_bound', 'bounded complete batch membership required')
            try:
                process = self.process(pid)
                captured = {**process, 'exe': process['executable'], 'error': None, 'absent': False}
            except (OSError, ValueError, native.Hold) as error:
                captured = dict(pid=pid, error=type(error).__name__, absent=None)
                # Missing /proc/PID/exe alone may be a zombie, never absence.
                try:
                    self.sources.budget.stat(Path('/proc')/str(pid))
                except FileNotFoundError:
                    captured['absent'] = True
                except (OSError, ValueError, native.Hold) as presence_error:
                    captured['presence_error'] = type(presence_error).__name__
                else:
                    captured['absent'] = False
            raw['processes'].append(captured)
        after = self.sources.host()
        raw['identity_after'] = {key: after[key] for key in identity}
        try:
            events = raw['command_observations']
            require(len(events) == 2 and [e['phase'] for e in events] == ['spawned', 'terminal'] and
                all(e['schema'] == 'qcl.command-owned-readonly-observation.v1' for e in events) and
                all(events[0][key] == events[1][key] for key in ('command_owner', 'child', 'argv_sha256')) and
                events[0]['argv_sha256'] == native.engine.command_argv_sha256(argv),
                'qualification_membership_owner_required', 'original P11 observations required')
            cohort = raw['cohort_before']
            raw['cohort_after'] = self._membership_cohort(permit)
            require(raw['cohort_after'] == cohort, 'qualification_changed', 'own sudo/root/source cohort changed')
            child = events[0]['child']
            eligible = {row['process']['pid']: row for row in cohort['chain']}
            require(child['pid'] not in eligible, 'qualification_membership_owner_required', 'distinct original child required')
            eligible[child['pid']] = dict(process=child, argv_sha256=events[0]['argv_sha256'], kind='owned-listpids-child')
            excluded = []
            by_pid = {row['pid']: row for row in raw['processes']}
            for listing in raw['listpids']['rows']:
                pid = listing['pid']
                if pid not in eligible:
                    continue
                witness = eligible[pid]
                actual = by_pid[pid]
                require(listing['job_id'] == creator['job_id'] and listing['step_id'] == 'batch',
                    'qualification_membership_owner_required', 'own cohort outside original batch row')
                if pid == child['pid'] and actual.get('absent') is True:
                    require(events[1]['current_child'] == dict(status='absent'),
                        'qualification_changed', 'actual post-reap absence differs from terminal observation')
                else:
                    require(actual.get('error') is None and process_identity(actual) == witness['process'],
                        'qualification_changed', 'listed cohort birth/UID/executable/cgroup changed')
                    if pid == child['pid']:
                        require(events[1]['current_child'] == dict(status='observed', process=child),
                            'qualification_changed', 'original child PID has a different current birth')
                excluded.append(dict(pid=pid, **witness))
            require(len({row['pid'] for row in raw['listpids']['rows']}) == len(raw['listpids']['rows']),
                'qualification_membership', 'duplicate scheduler PID')
            removed = {row['pid'] for row in excluded}
            projection = dict(identity_before=identity, identity_after=raw['identity_after'],
                listpids=dict(rc=0, rows=[row for row in raw['listpids']['rows'] if row['pid'] not in removed]),
                processes=[row for row in raw['processes'] if row['pid'] not in removed])
            raw['exclusion_witness'] = dict(schema='qcl.host-resource-calibration-owned-census-exclusions.v1', excluded=excluded)
            raw['projection'] = projection
            expected = dict(job_id=creator['job_id'], owner_uid=permit['client_uid'],
                slurmstepd_executable=permit['slurmstepd_executable'], cgroup_scope=permit['cgroup_scope'], identity=identity)
            result = evidence.classify_before(projection, expected)
            evidence.validate_before(result, expected)
            require(all(process_identity(self.process(row['pid'])) == process_identity(row) for row in raw['processes']
                if row['pid'] != child['pid']), 'qualification_changed', 'batch member birth/credentials changed')
            return result
        except (ValueError, KeyError, OSError) as error:
            raise native.Hold('qualification_membership_owner_required') from error

    def _validate_actual_body(self, permit, proof):
        return _validate_guest_actual_body(self, permit, proof)

    def protect_commitments(self, permit, commitments, phase):
        proof = _protect_role_commitments(self.view, permit, commitments, phase)
        require(phase == 'guard', 'qualification_role', 'readonly guest body guard only')
        self._validate_actual_body(permit, proof)
        return proof

    def authenticated_caller(self):
        from host_resource_facts import authenticate_sudo_caller
        config = self.local.config
        from host_resource_qualification_gate import process_identity
        return authenticate_sudo_caller(os.environ, parent_pid=os.getppid(),
            process=lambda pid: process_identity(self.process(pid)),
            sudo_executables=tuple(config['sudo_executables']), allowed_uid=config['client_uid'])

    def root_ingress(self):
        pid = os.getpid()
        return dict(process=self.process(pid), argv=self.command_line(pid), source=self._loaded_source(pid, 'client_root'))

    def guard_context(self, caller):
        actual = self.process(caller['pid'])
        from host_resource_qualification_gate import process_identity
        require(process_identity(actual) == process_identity(caller),
            'qualification_caller', 'actual caller changed')
        permit = self.current_permit()
        match = re.fullmatch(re.escape(permit['cgroup_scope']) + r'/job_([1-9][0-9]{0,9})/step_batch/user/.+', caller['cgroup'])
        require(match is not None, 'qualification_caller', 'actual original batch task cgroup required')
        job = match[1]
        mirrors = [self.mirror_read(calc) for calc in permit['jobs']]
        matches = [mirror for mirror in mirrors if mirror is not None and mirror['creator'] is not None and
            mirror['creator']['job_id'] == job]
        require(len(matches) == 1, 'qualification_mirror', 'actual cgroup must select unique original mirror')
        creator = matches[0]['creator']
        return dict(permit=permit, scheduler=self.scheduler_job(job), original_hook=self.original_prolog(job, creator['dispatch_id']))

    def actual_task_limit(self, pid, demand):
        """Finite effective kernel limit across every actual memory ancestor."""
        from host_resource_qualification_gate import process_identity
        before = self.process(pid); native.path_value(before['cgroup'], absolute=True)
        require(before['cgroup'] != '/', 'qualification_actual_limit', 'actual job cgroup required')
        budget = self.sources.budget
        root = Path('/sys/fs/cgroup')
        require('memory' in budget.read(root/'cgroup.controllers', 4096).decode().split(),
            'qualification_actual_limit', 'actual memory controller required')
        limits, originals = [], {}
        group = Path(before['cgroup'])
        while str(group) != '/':
            path = root/str(group).lstrip('/')/'memory.max'
            data = budget.read(path, 128)
            originals[path] = data
            value = data.decode().strip()
            require(value == 'max' or re.fullmatch(r'[1-9][0-9]*', value),
                'qualification_actual_limit', 'actual finite or kernel max memory value required')
            if value != 'max':
                limits.append(int(value)); integer(int(value), 'actual enforced ancestor limit', 1)
            parent = root/str(group.parent).lstrip('/')/'cgroup.subtree_control'
            raw = budget.read(parent, 4096); originals[parent] = raw
            require('memory' in raw.decode().split(), 'qualification_actual_limit', 'memory delegation required at every ancestor')
            group = group.parent
        integer(demand, 'original authorized demand', 1)
        require(limits and 0 < min(limits) <= demand and
            all(budget.read(path, 4096) == value for path, value in originals.items()) and
            process_identity(self.process(pid)) == process_identity(before),
            'qualification_actual_limit', 'actual finite stable enforced limit no larger than D required')
        return min(limits)


def decode_qga_started(raw):
    """Installed PVE API2 Agent.pm exec reply, not guessed CLI output."""
    require(type(raw) is str and len(raw.encode()) <= SUBSET_LIMIT,
        'qualification_qga', 'bounded original QGA exec reply required')
    value = exact(strict_json(raw), {'pid'})
    integer(value['pid'], 'original QGA exec PID', 1)
    return value['pid']


def decode_qga_status(raw):
    """Installed qemu_exec_status emits int0/1 and DECODED output strings."""
    require(type(raw) is str and len(raw.encode()) <= 256*1024,
        'qualification_qga', 'bounded original QGA status reply required')
    value = strict_json(raw)
    require(type(value) is dict and 'exited' in value and set(value) <=
        {'exited', 'exitcode', 'signal', 'out-data', 'err-data', 'out-truncated', 'err-truncated'},
        'qualification_qga', 'closed installed exec-status schema required')
    require(type(value['exited']) is int and value['exited'] in (0, 1),
        'qualification_qga', 'actual installed integer exited flag required')
    for key in ('out-truncated', 'err-truncated'):
        require(key not in value or (type(value[key]) is int and value[key] == 0),
            'qualification_qga', 'truncated or unknown QGA output is incomplete')
    for key in ('out-data', 'err-data'):
        require(key not in value or (type(value[key]) is str and len(value[key].encode()) <= 256*1024),
            'qualification_qga', 'actual already-decoded QGA output string required')
    for key in ('exitcode', 'signal'):
        if key in value:
            integer(value[key], 'literal QGA '+key)
    require((value['exited'] == 0 and not ({'exitcode', 'signal'} & value.keys())) or
        (value['exited'] == 1 and len({'exitcode', 'signal'} & value.keys()) == 1),
        'qualification_qga', 'known terminal exit or explicit nonterminal required')
    return value


def validate_receiver_age(view, original_before, request_seconds):
    """Upper bound host age by its ORIGINAL receiver-before boottime.

    Import/arrival time is intentionally absent from this interface. Native host
    transport must establish that the actual host capture followed this sample.
    """
    original_before = _decode_clock(original_before)
    integer(request_seconds, 'actual protected request horizon', 1)
    selector, original = view._selector()
    now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    age = now - original_before['nanoseconds']
    require(original_before['boot_id'] == selector['receiver']['boot_id'] and
        original_before['reader_source'] == selector['reader_source'] and
        0 <= age <= request_seconds*10**9 and view._selector()[1] == original,
        'qualification_stale_host', 'original same-boot receiver-before evidence expired or changed')
    return age


QGA_ACTIONS = frozenset(('clock', 'readonly', 'import', 'mirror-cas'))
PROOF_PHASES = frozenset(('stage', 'submit', 'bind', 'release', 'guard', 'revoke', 'close'))


def _qga_expression(reader_path):
    return "import sys; sys.path.insert(0, '" + str(Path(reader_path).parent) + "'); import host_resource_qualification_sources as m; sys.exit(m.root_transport_main())"


def qga_exec_arguments(node, vm_id, role, action, payload):
    require(native.matches(node, r'[A-Za-z0-9][A-Za-z0-9_-]*') and action in QGA_ACTIONS,
        'qualification_qga', 'fixed native node/internal QGA action required')
    integer(vm_id, 'enrolled actual PVE VMID', 1)
    store_path(role['python_executable']); store_path(role['reader_source']['path'])
    data = native.encoded(payload).decode()
    require(len(data.encode()) <= 65536, 'output_bound', 'installed PVE API stdin bound exceeded')
    argv = [role['python_executable'], '-I', '-c', _qga_expression(role['reader_source']['path']), action]
    # Installed PVE JSONSchema uses Getopt::Long '=s@'. Each equal-form arg
    # is a separate array element, including literal leading -I/-c.
    return ['create', f'/nodes/{node}/qemu/{vm_id}/agent/exec',
        *('--command='+item for item in argv), '--input-data', data]


class RootQgaTransport:
    """Existing P11/backend command owner, original receipts, one exec per ID.

    Production construction uses the protected role inventory and actual complete
    host ownership read in capture_host_proof; this class adds no shell/SSH path.
    """
    def __init__(self, parent, backend, roles):
        self.parent, self.backend, self.roles = parent, backend, roles
        self.repo = parent.repository

    def execute(self, role, action, payload, phase, request_id):
        native.canonical_uuid(request_id)
        require(role in ('controller', 'worker') and role in self.roles and phase in PROOF_PHASES,
            'qualification_qga', 'fixed original role/phase required')
        target = self.roles[role]
        argv = qga_exec_arguments(self.backend.node, target['vm_id'], target, action, payload)
        base = self.repo.folder(self.parent.operation)/'source-observations'
        intent_path = base/(request_id+'-intent.json')
        intent = dict(schema='qcl.host-resource-calibration-qga-intent.v1', operation_id=self.parent.operation,
            request_id=request_id, phase=phase, role=role, target=target, action=action,
            argv=argv, input_sha256=hashlib.sha256(native.encoded(payload)).hexdigest(),
            native_started_boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME))
        # Exclusive original intent precedes the effect. Re-entry with same ID
        # fails before transport, even after timeout or a lost ACK.
        self.repo.exclusive(intent_path, intent)
        started = time.monotonic()
        horizon = self.parent.policy.timeouts.request_seconds
        try:
            original_start = self.backend._run(argv, timeout=horizon)
            pid = decode_qga_started(original_start)
            self.repo.exclusive(base/(request_id+'-started.json'), dict(
                schema='qcl.host-resource-calibration-qga-started.v1', request_id=request_id,
                intent_sha256=self.repo.digest(intent_path), original_stdout=original_start, pid=pid))
            sequence = 0
            while True:
                remaining = horizon-(time.monotonic()-started)
                require(remaining > 0, 'qualification_qga_unknown', 'original QGA completion not established')
                original_status = self.backend._run(['get', f'/nodes/{self.backend.node}/qemu/{target["vm_id"]}/agent/exec-status',
                    '--pid', str(pid)], timeout=remaining)
                sequence += 1
                observed = dict(schema='qcl.host-resource-calibration-qga-status.v1', request_id=request_id,
                    intent_sha256=self.repo.digest(intent_path), sequence=sequence, pid=pid,
                    original_stdout=original_status, native_ended_boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME))
                status_path = base/(request_id+'-status-'+str(sequence)+'.json')
                self.repo.exclusive(status_path, observed)
                status = decode_qga_status(original_status)
                if status['exited'] == 1:
                    require(status.get('exitcode') == 0 and not status.get('err-data', ''),
                        'qualification_qga_failed', 'actual role collector did not complete successfully')
                    packet = strict_json(status.get('out-data', ''))
                    require(type(packet) is dict, 'qualification_qga', 'bounded original role reply required')
                    return packet, dict(request_id=request_id, intent_sha256=self.repo.digest(intent_path),
                        status_name=status_path.name, status_sha256=self.repo.digest(status_path))
                # Re-observe the same actual PID; never issue another exec.
                time.sleep(min(0.05, max(0.0, horizon-(time.monotonic()-started))))
        except BaseException as error:
            failure = dict(schema='qcl.host-resource-calibration-qga-unknown.v1', request_id=request_id,
                intent_sha256=self.repo.digest(intent_path), reason=type(error).__name__,
                native_ended_boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME))
            original = getattr(error, 'record', None)
            if type(original) is dict and len(native.encoded(original)) <= 512*1024:
                failure['original_command_record'] = original
            try:
                self.repo.exclusive(base/(request_id+'-unknown.json'), failure)
            except BaseException as journal_error:
                error.add_note('original QGA unknown receipt failed: '+type(journal_error).__name__)
            raise


def _transport_sources():
    budget = native._bootstrap_operation()
    original = native.protected_read(native.POLICY, budget)
    policy_row = strict_json(original.decode())
    require(type(policy_row) is dict and policy_row.get('role') in ('controller', 'worker'),
        'qualification_root_transport_required', 'actual installed role policy required')
    policy = native._load_policy(policy_row['role'], budget)
    require(hashlib.sha256(original).hexdigest() == policy['_policy_sha256'],
        'qualification_root_transport_required', 'native policy changed')
    return native.NativeSources(policy, budget)


def _immutable_ref(source, ref, *, executable=False):
    exact(ref, {'path', 'sha256'}); store_path(ref['path']); sha(ref['sha256'])
    origin = native.engine.public_binary_origin(source.budget, ref['path'], executable=executable)['path']
    data = native.engine.immutable_public_bytes(source.budget, origin, 64*1024**2)
    require(origin == ref['path'] and hashlib.sha256(data).hexdigest() == ref['sha256'],
        'qualification_root_transport_required', 'actual immutable transport Source differs')
    return origin


def _admit_root_transport():
    """Authenticate the actual direct QGA child before decoding caller data."""
    from types import SimpleNamespace
    from host_resource_qualification_gate import process_identity
    try:
        require(os.getuid() == os.geteuid() == 0,
            'qualification_root_transport_required', 'actual root QGA child required')
        source = _transport_sources()
        pin_path = PRIVATE_ROOT/'qualification/root-transport.json'
        original = _read_private(pin_path, source.budget)
        pin = exact(strict_json(original.decode()), {'schema', 'role', 'receiver', 'python_executable',
            'python_origin', 'reader_source', 'agent'})
        require(pin['schema'] == 'qcl.host-resource-calibration-root-transport.v1' and
            pin['role'] == source.policy['role'], 'qualification_root_transport_required', 'fixed local role transport pin required')
        own = source.process(os.getpid())
        agent = exact(pin['agent'], {'unit', 'executable', 'fragment_path', 'fragment_sha256'})
        require(agent['unit'] == 'qemu-guest-agent.service' and own['uids'] == [0]*4 and
            native.engine.daemon_scope_bound(own['cgroup'], '/system.slice/'+agent['unit']),
            'qualification_root_transport_required', 'direct actual QGA unit child required')
        host = source.host()
        receiver = exact(pin['receiver'], {'native_id', 'machine_id', 'boot_id', 'native_policy_sha256'})
        require(receiver == dict(native_id=_receiver_native_id(source), machine_id=host['machine_id'],
            boot_id=host['boot_id'], native_policy_sha256=source.policy['_policy_sha256']) and
            pin['reader_source'] == _reader_source(source.budget),
            'qualification_root_transport_required', 'actual receiver/reader generation differs')
        store_path(pin['python_executable'])
        require(source.origin(pin['python_executable']) == _immutable_ref(source, pin['python_origin'], executable=True) ==
            own['executable'], 'qualification_root_transport_required', 'actual isolated interpreter origin differs')
        _immutable_ref(source, pin['reader_source'])
        fields = ('MainPID', 'ControlGroup', 'ActiveState', 'InvocationID', 'FragmentPath')
        def unit():
            output = source.run([source.policy['tools']['systemctl'], 'show', agent['unit'],
                *('--property='+key for key in fields)])
            row = dict(line.split('=', 1) for line in output.splitlines())
            require(set(row) == set(fields), 'qualification_root_transport_required', 'complete actual QGA unit required')
            return row
        observed = unit()
        require(observed['ActiveState'] == 'active' and native.matches(observed['InvocationID'], r'[0-9a-f]{32}') and
            observed['MainPID'] == str(own['ppid']) and observed['ControlGroup'] == '/system.slice/'+agent['unit'],
            'qualification_root_transport_required', 'actual direct QGA MainPID owner required')
        parent = source.process(own['ppid'])
        store_path(agent['executable']); store_path(agent['fragment_path']); sha(agent['fragment_sha256'])
        fragment = native.engine.public_binary_origin(source.budget, observed['FragmentPath'], executable=False)['path']
        require(fragment == agent['fragment_path'] and hashlib.sha256(native.engine.immutable_public_bytes(
            source.budget, fragment, 65536)).hexdigest() == agent['fragment_sha256'] and
            parent['uids'] == [0]*4 and parent['executable'] == source.origin(agent['executable']) == agent['executable'] and
            parent['cgroup'] == own['cgroup'] and 0 < parent['start_ticks'] <= own['start_ticks'],
            'qualification_root_transport_required', 'actual QGA parent birth/Source/scope differs')
        argv = source.command_line(own['pid'])
        require(len(argv) == 5 and argv[:4] == [pin['python_executable'], '-I', '-c',
            _qga_expression(pin['reader_source']['path'])] and argv[4] in QGA_ACTIONS,
            'qualification_root_transport_required', 'fixed immutable QGA argv required')
        require(process_identity(source.process(own['pid'])) == process_identity(own) and
            process_identity(source.process(parent['pid'])) == process_identity(parent) and unit() == observed and
            source.command_line(own['pid']) == argv and source.host() == host and
            _read_private(pin_path, source.budget) == original and _reader_source(source.budget) == pin['reader_source'],
            'qualification_root_transport_required', 'QGA ingress changed during authentication')
        return SimpleNamespace(sources=source, view=RoleView(source), receiver=receiver,
            reader_source=pin['reader_source'], process=own, parent=parent, unit=observed, argv=argv)
    except (OSError, ValueError, KeyError, TypeError, native.Hold) as error:
        raise native.Hold('qualification_root_transport_required') from error


def _exclusive_private(path, data, budget):
    require(type(data) is bytes and len(data) <= 8*1024**2,
        'output_bound', 'bounded original private payload required')
    _private_directory(path.parent)
    budget.reserve(len(data)); budget.file()
    with native.protected_directory(path.parent, budget=budget) as parent:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        try:
            offset = 0
            while offset < len(data):
                budget.before(); count = os.write(fd, data[offset:])
                require(count > 0, 'qualification_import', 'short original private write')
                offset += count
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
    require(_read_private(path, budget, len(data)) == data,
        'qualification_import', 'original private import readback differs')


def _import_role_snapshot(ingress, payload):
    if type(payload) is dict and payload.get('schema') == 'qcl.host-resource-calibration-host-import.v1':
        return _import_host_proof(ingress, payload)
    exact(payload, {'schema', 'selector', 'documents'})
    require(payload['schema'] == 'qcl.host-resource-calibration-role-import.v1' and
        len(native.encoded(payload)) <= 65536, 'output_bound', 'bounded fixed initial role capsule required')
    selector = decode_selector(payload['selector'])
    require(selector['role'] == ingress.sources.policy['role'] and selector['receiver'] == ingress.receiver and
        selector['reader_source'] == ingress.reader_source,
        'qualification_import', 'actual local receiver/Source differs')
    pins = {'permit.json': 'permit_sha256', 'parent-plan.json': 'parent_plan_sha256',
        'parent-fence.json': 'fence_sha256', 'capacity-report.json': 'capacity_report_sha256'}
    documents = exact(payload['documents'], pins)
    for name, key in pins.items():
        require(type(documents[name]) is str and hashlib.sha256(documents[name].encode()).hexdigest() == selector[key],
            'qualification_import', 'exact original raw capsule hash differs')
        strict_json(documents[name])
    permit = decode_permit(strict_json(documents['permit.json']))
    require(permit['operation_id'] == selector['operation_id'] and all(permit[key] == selector[key] for key in
        ('parent_plan_sha256', 'fence_sha256', 'capacity_report_sha256', 'source_graph_sha256')),
        'qualification_import', 'exact original permit/context differs')
    view = ingress.view
    lock = str(uuid.uuid5(uuid.NAMESPACE_URL, 'qcl-task3-role-selector-import'))
    with native.AttemptStore(view.root).locked(lock, view.budget):
        require(not view.current_path.exists() and not view.current_path.is_symlink(),
            'qualification_operation_exists', 'present/unknown operation cannot be replaced or adopted')
        folder = view.root/'qualification'/selector['operation_id']
        # Every leaf is exclusive. A partial prior import remains a refusal.
        folder.mkdir(mode=0o700)
        (folder/'mirrors').mkdir(mode=0o700)
        for name in pins:
            _exclusive_private(folder/name, documents[name].encode(), view.budget)
        _exclusive_private(view.current_path, native.encoded(selector), view.budget)
        require(view.current_permit() == permit, 'qualification_import', 'final role selector readback differs')
    return dict(operation_id=selector['operation_id'], permit_sha256=selector['permit_sha256'])


def root_transport_main():
    """Internal QGA-only Source entry; no SSH/sudo/public action registration."""
    import json
    import sys
    ingress = _admit_root_transport()
    require(len(sys.argv) == 2 and sys.argv[1] == ingress.argv[4],
        'qualification_root_transport_required', 'actual fixed QGA action required')
    data = sys.stdin.buffer.read(65537)
    require(len(data) <= 65536, 'output_bound', 'installed PVE API input bound required')
    payload = strict_json(data.decode())
    action = sys.argv[1]
    if action == 'clock':
        exact(payload, set())
        result = dict(schema='qcl.host-resource-calibration-role-clock.v1', receiver=ingress.receiver,
            reader_source=ingress.reader_source, clock=ingress.view.capture_clock(),
            ingress=dict(process=ingress.process, parent=ingress.parent, unit=ingress.unit))
    elif action == 'readonly':
        exact(payload, set()); result = ingress.view.readonly_subset()
    elif action == 'import':
        result = _import_role_snapshot(ingress, payload)
    else:
        exact(payload, {'calcjob_uuid', 'expected', 'desired'})
        result = CanonicalMirrorStore(ingress.view).cas(payload['calcjob_uuid'], payload['expected'], payload['desired'])
    require(len(native.encoded(result)) <= 256*1024, 'output_bound', 'bounded actual role reply required')
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0


def decode_role_inventory(value):
    exact(value, {'schema', 'operation_id', 'parent_plan_sha256', 'native_host', 'roles', 'source_refs'})
    require(value['schema'] == 'qcl.host-resource-calibration-role-inventory.v1',
        'qualification_roles', 'fixed protected Root role inventory required')
    native.canonical_uuid(value['operation_id']); sha(value['parent_plan_sha256'])
    host = exact(value['native_host'], {'host_id', 'host_boot_id', 'policy_sha256', 'baseline_state_sha256'})
    native.canonical_uuid(host['host_boot_id']); sha(host['policy_sha256']); sha(host['baseline_state_sha256'])
    roles = exact(value['roles'], {'controller', 'worker'})
    for role, row in roles.items():
        exact(row, {'vm_id', 'native_id', 'machine_id', 'boot_id', 'python_executable', 'python_origin',
            'reader_source', 'native_policy_sha256', 'agent'})
        integer(row['vm_id'], 'actual enrolled PVE VMID', 1)
        native.canonical_uuid(row['native_id']); native.canonical_uuid(row['boot_id'])
        require(native.matches(row['machine_id'], r'[0-9a-f]{32}'), 'qualification_roles', 'actual enrolled machine ID required')
        store_path(row['python_executable']); sha(row['native_policy_sha256'])
        for name in ('python_origin', 'reader_source'):
            exact(row[name], {'path', 'sha256'}); store_path(row[name]['path']); sha(row[name]['sha256'])
        agent = exact(row['agent'], {'unit', 'executable', 'fragment_path', 'fragment_sha256'})
        require(agent['unit'] == 'qemu-guest-agent.service', 'qualification_roles', 'fixed QGA unit required')
        store_path(agent['executable']); store_path(agent['fragment_path']); sha(agent['fragment_sha256'])
    require(all(roles['controller'][key] != roles['worker'][key] for key in
        ('vm_id', 'native_id', 'machine_id')), 'qualification_roles', 'distinct original controller/worker required')
    refs = value['source_refs']
    require(type(refs) is dict and len(refs) <= 32, 'output_bound', 'finite actual Source refs required')
    for name, ref in refs.items():
        require(native.matches(name, native.ID), 'qualification_roles', 'fixed simple Source role required')
        exact(ref, {'path', 'sha256'}); native.path_value(ref['path'], absolute=True); sha(ref['sha256'])
    return value


def _retained_root_raw(store, path, limit):
    """Existing root store trust with the report owner's separate eight-MiB cap."""
    path = Path(path)
    require(path.is_relative_to(store.directory), 'trust', 'fixed original parent namespace required')
    cursor = store.directory
    for part in path.parent.relative_to(store.directory).parts:
        cursor /= part; store._check_path(cursor, directory=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        store._check_fd(fd); before = os.fstat(fd)
        require(before.st_size <= limit, 'output_bound', 'bounded retained original required')
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit+1-len(data)))
            if not chunk: break
            data.extend(chunk)
        require(len(data) == before.st_size <= limit and native.signature(before) ==
            native.signature(os.fstat(fd)) == native.signature(path.lstat()),
            'trust', 'retained original changed during held/named read')
        return bytes(data)
    finally:
        os.close(fd)


def _validate_role_inventory_current(service, parent, permit, inventory):
    from host_resource_operations import policy_digest
    inventory = decode_role_inventory(inventory)
    plan = parent.repository.plan(parent.operation)
    require(inventory['operation_id'] == parent.operation and inventory['parent_plan_sha256'] == permit['parent_plan_sha256'] and
        inventory['native_host'] == {key: plan[key] for key in
            ('host_id', 'host_boot_id', 'policy_sha256', 'baseline_state_sha256')} and
        inventory['native_host']['policy_sha256'] == policy_digest(parent.policy),
        'qualification_roles', 'actual Root operation/paid/policy/source context differs')
    provider = service.provider
    host, rows, agreement = provider._host_inventory()
    require(host['boot_id'] == plan['host_boot_id'], 'qualification_roles', 'actual native host boot differs')
    backend = getattr(provider.backend, 'native_backend', provider.backend)
    from host_resource_backends import ProxmoxMemoryBackend
    require(type(backend) is ProxmoxMemoryBackend, 'qualification_roles', 'existing local PVE backend required')
    by_id = {row['native_id'].lower(): row for row in rows}
    for role, selected in inventory['roles'].items():
        require(selected['native_id'] in by_id and by_id[selected['native_id']]['running'] is True,
            'qualification_roles', 'role must remain in complete actual native inventory')
        # The fixed Root registry supplies ownership/VMID. Actual PVE readback
        # prevents a known UUID being used with a different numeric VM target.
        path = f'/nodes/{backend.node}/qemu/{selected["vm_id"]}'
        configuration = strict_json(backend._run(['get', path+'/config', '--current', '1']))
        actual_uuid = re.findall(r'(?:^|,)uuid=([^,]+)(?:,|$)', configuration.get('smbios1', ''))
        status = strict_json(backend._run(['get', path+'/status/current']))
        require(actual_uuid == [selected['native_id']] and status.get('status') == 'running' and
            str(status.get('pid')) == str(by_id[selected['native_id']]['process_id']),
            'qualification_roles', 'actual PVE VMID/UUID/process differs from protected owned role')
    worker = inventory['roles']['worker']
    require(all(row['worker_machine_id'] == worker['machine_id'] and row['worker_boot_id'] == worker['boot_id'] and
        plan['bindings'][row['vm_id']]['native_id'].lower() == worker['native_id'] and
        plan['bindings'][row['vm_id']]['guest_boot_id'] == worker['boot_id'] for row in permit['jobs'].values()),
        'qualification_roles', 'finite original workers differ from fixed Root role inventory')
    require({'collector', 'pvesh', 'runtime'} <= inventory['source_refs'].keys() and
        inventory['source_refs']['pvesh']['path'] == backend.tool,
        'qualification_roles', 'actual protected collector/tool/runtime refs required')
    budget = native._bootstrap_operation()
    for ref in inventory['source_refs'].values():
        raw = native.protected_read(ref['path'], budget, 1024**2)
        require(hashlib.sha256(raw).hexdigest() == ref['sha256'], 'qualification_roles', 'actual native Source bytes changed')
    return inventory


def _host_capture_owner(service, inventory):
    from host_resource_qualification_gate import process_identity
    source = native.NativeSources({}, native._bootstrap_operation())
    process = source.process(os.getpid())
    require(os.getuid() == os.geteuid() == 0 and process['uids'] == [0]*4,
        'qualification_capture_owner', 'actual native Root collector required')
    collector = inventory['source_refs']['collector']
    require(str(Path(__file__).resolve()) == collector['path'] and hashlib.sha256(
        native.protected_read(collector['path'], source.budget, 1024**2)).hexdigest() == collector['sha256'],
        'qualification_capture_owner', 'actual protected collector Source differs')
    require(process_identity(source.process(process['pid'])) == process_identity(process),
        'qualification_capture_owner', 'actual native collector birth changed')
    return dict(process=process_identity(process), collector=collector,
        native_host_boot_id=inventory['native_host']['host_boot_id'])


def _clock_reply(packet, role):
    exact(packet, {'schema', 'receiver', 'reader_source', 'clock', 'ingress'})
    expected = {key: role[key] for key in ('native_id', 'machine_id', 'boot_id', 'native_policy_sha256')}
    require(packet['schema'] == 'qcl.host-resource-calibration-role-clock.v1' and packet['receiver'] == expected and
        packet['reader_source'] == role['reader_source'] and _decode_clock(packet['clock'])['boot_id'] == role['boot_id'] and
        packet['clock']['reader_source'] == role['reader_source'] and type(packet['ingress']) is dict,
        'qualification_clock', 'authenticated original receiver/Source clock differs')
    return packet


def capture_host_proof(service, permit, phase):
    """Collect clocks THEN actual full-host/guest sources; never accept raw input.

    Raw proof is retained before capacity assessment/import. This does not create
    a readiness flag, a grant, a new C, a job, a report PASS or a closure.
    """
    from dataclasses import asdict
    from host_resource_service import NativeResourceService
    from host_resource_qualification import NativeQualificationService, check_baseline, _exists
    from host_resource_qualification_gate import QualificationJobs
    from host_resource_qualification_runtime import _original_context
    from host_resource_operations import policy_digest
    require(type(service) is NativeResourceService and phase in PROOF_PHASES,
        'qualification_capture_owner', 'existing actual native service and finite phase required')
    decode_permit(permit)
    proofs = getattr(service.provider, 'native_proofs', None)
    require(proofs is not None, 'qualification_capture_owner', 'existing native Source owner required')
    parent = NativeQualificationService(service.controller.policy, service.controller.store, proofs,
        operation_id=permit['operation_id'])
    repo = parent.repository
    with parent.store.operation():
        plan = repo.plan(parent.operation); state = parent._state()
        check_baseline(parent.policy, parent.store, plan, state); repo.active(parent.operation, plan)
        canonical_permit = repo.folder(parent.operation)/'jobs/permit.json'
        permit_path = canonical_permit if _exists(canonical_permit) else repo.folder(parent.operation)/'source-context/jobs-permit.json'
        require(_exists(canonical_permit) or (phase == 'stage' and not _exists(canonical_permit.parent)),
            'qualification_parent', 'only original frozen pre-stage permit may precede canonical namespace')
        require(repo.read(permit_path) == permit and
            repo.digest(repo.folder(parent.operation)/'plan.json') == permit['parent_plan_sha256'] and
            repo.digest(repo.directory/'active.json') == permit['fence_sha256'] and
            plan['source_graph_sha256'] == permit['source_graph_sha256'],
            'qualification_parent', 'original active parent/jobs/fence/Source differs')
        base = repo.folder(parent.operation)/'source-context'
        inventory = _validate_role_inventory_current(service, parent, permit, repo.read(base/'roles.json'))
        report_raw = _retained_root_raw(parent.store, base/'capacity-report.json', 8*1024**2)
        require(hashlib.sha256(report_raw).hexdigest() == permit['capacity_report_sha256'],
            'qualification_parent', 'original retained report bytes differ')
        strict_json(report_raw.decode())
        owner = _host_capture_owner(service, inventory)
        transport = RootQgaTransport(parent, getattr(service.provider.backend, 'native_backend', service.provider.backend), inventory['roles'])
        receiver_before, references = {}, []
        for role in ('controller', 'worker'):
            packet, ref = transport.execute(role, 'clock', {}, phase, str(uuid.uuid4()))
            receiver_before[role] = _clock_reply(packet, inventory['roles'][role]); references.append(ref)
        started = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        child_jobs = QualificationJobs(parent, None).evidence() if _exists(canonical_permit) else None
        host, native_inventory, agreement = service.provider._host_inventory()
        processes = service.provider.sources.processes()
        paid_raw = _retained_root_raw(parent.store, parent.store.state_path, 1024**2)
        require(hashlib.sha256(paid_raw).hexdigest() == plan['baseline_state_sha256'] and
            host['boot_id'] == plan['host_boot_id'], 'qualification_parent', 'actual unchanged full-paid native baseline required')
        guests = {}
        try:
            for vm in parent.policy.vms:
                ctx = _original_context(service, plan, vm)
                ctx['output_owner'] = service.provider.config.get('output_owner', {})
                read, guest, original = service.provider._calibration_pair(ctx)
                guests[vm.vm_id] = dict(context=ctx, readback=asdict(read), guest=guest, original=original)
        except BaseException as error:
            partial = getattr(error, 'calibration_pair', None)
            if partial is not None:
                read, guest, original = partial
                guests[vm.vm_id] = dict(context=ctx, readback=asdict(read), guest=guest, original=original)
            # Failed raw reads survive before an assessment error propagates.
            repo.exclusive(repo.folder(parent.operation)/'source-observations'/(phase+'-failed-'+str(uuid.uuid4())+'.json'),
                dict(schema='qcl.host-resource-calibration-host-failed-source.v1', receiver_before=receiver_before,
                    host=host, inventory=native_inventory, agreement=agreement, captured_guests=guests,
                    original_transcript_refs=references, reason=getattr(error, 'code', type(error).__name__)))
            raise
        ended = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        require(0 <= ended-started <= parent.policy.timeouts.request_seconds*10**9,
            'qualification_stale_host', 'actual native capture exceeded original protected horizon')
        check_baseline(parent.policy, parent.store, plan, parent._state())
        require(_retained_root_raw(parent.store, parent.store.state_path, 1024**2) == paid_raw and repo.plan(parent.operation) == plan,
            'qualification_changed', 'actual original paid/plan changed during host capture')
        proof = dict(schema='qcl.host-resource-calibration-host-source.v1', operation_id=parent.operation,
            parent_refs=dict(parent_plan_sha256=permit['parent_plan_sha256'], fence_sha256=permit['fence_sha256'],
                source_graph_sha256=permit['source_graph_sha256'], baseline_state_sha256=plan['baseline_state_sha256']),
            permit_ref=dict(sha256=repo.digest(permit_path)),
            capacity_report_ref=dict(sha256=permit['capacity_report_sha256']),
            native_host_context=dict(policy=asdict(parent.policy), policy_sha256=policy_digest(parent.policy),
                roles=inventory, request_seconds=parent.policy.timeouts.request_seconds),
            receiver_before=receiver_before, authorized_demand_set={calc: row['demand_bytes'] for calc, row in permit['jobs'].items()},
            captured_host=dict(host=host, inventory=native_inventory, agreement=agreement, processes=processes,
                paid_state_raw=paid_raw.decode(), paid_state_sha256=hashlib.sha256(paid_raw).hexdigest(), child_jobs=child_jobs),
            captured_guests=guests, native_capture_interval=dict(clock='CLOCK_BOOTTIME', host_boot_id=host['boot_id'],
                started_nanoseconds=started, ended_nanoseconds=ended), capture_owner=owner, original_transcript_refs=references)
        data = native.encoded(proof)
        require(len(data) <= 1024**2, 'output_bound', 'original whole-host raw proof exceeds retained record bound')
        path = repo.folder(parent.operation)/'source-observations'/(phase+'-host-'+str(uuid.uuid4())+'.json')
        repo.exclusive(path, proof)
        return dict(path=str(path), sha256=repo.digest(path), bytes=len(data),
            import_staging='measure_complete_envelope' if len(data) <= 65536 else 'requires_bounded_staging')


def _decode_host_proof(proof, selector, permit):
    exact(proof, {'schema', 'operation_id', 'parent_refs', 'permit_ref', 'capacity_report_ref',
        'native_host_context', 'receiver_before', 'authorized_demand_set', 'captured_host', 'captured_guests',
        'native_capture_interval', 'capture_owner', 'original_transcript_refs'})
    require(proof['schema'] == 'qcl.host-resource-calibration-host-source.v1' and
        proof['operation_id'] == selector['operation_id'] == permit['operation_id'] and
        proof['parent_refs'] == dict(parent_plan_sha256=selector['parent_plan_sha256'], fence_sha256=selector['fence_sha256'],
            source_graph_sha256=selector['source_graph_sha256'], baseline_state_sha256=selector['native_host']['baseline_state_sha256']) and
        proof['permit_ref'] == dict(sha256=selector['permit_sha256']) and
        proof['capacity_report_ref'] == dict(sha256=selector['capacity_report_sha256']) and
        proof['authorized_demand_set'] == {calc: row['demand_bytes'] for calc, row in permit['jobs'].items()},
        'qualification_host_source', 'original parent/Source/report/allD proof differs')
    ctx = exact(proof['native_host_context'], {'policy', 'policy_sha256', 'roles', 'request_seconds'})
    require(type(ctx['policy']) is dict and hashlib.sha256(native.encoded(ctx['policy'])).hexdigest() ==
        ctx['policy_sha256'] == selector['native_host']['policy_sha256'] and
        ctx['request_seconds'] == ctx['policy']['timeouts']['request_seconds'],
        'qualification_host_source', 'actual protected native policy/horizon differs')
    integer(ctx['request_seconds'], 'actual native request horizon', 1)
    roles = decode_role_inventory(ctx['roles'])
    require(roles['native_host'] == selector['native_host'] and roles['operation_id'] == selector['operation_id'] and
        roles['parent_plan_sha256'] == selector['parent_plan_sha256'],
        'qualification_host_source', 'original protected Root roles differ')
    host = exact(proof['captured_host'], {'host', 'inventory', 'agreement', 'processes', 'paid_state_raw',
        'paid_state_sha256', 'child_jobs'})
    require(type(host['paid_state_raw']) is str and hashlib.sha256(host['paid_state_raw'].encode()).hexdigest() ==
        host['paid_state_sha256'] == selector['native_host']['baseline_state_sha256'] and
        host['host']['boot_id'] == selector['native_host']['host_boot_id'],
        'qualification_host_source', 'literal original full-paid baseline/host boot differs')
    strict_json(host['paid_state_raw'])
    interval = exact(proof['native_capture_interval'], {'clock', 'host_boot_id', 'started_nanoseconds', 'ended_nanoseconds'})
    integer(interval['started_nanoseconds'], 'native capture start')
    integer(interval['ended_nanoseconds'], 'native capture end')
    require(interval['clock'] == 'CLOCK_BOOTTIME' and interval['host_boot_id'] == selector['native_host']['host_boot_id'] and
        0 <= interval['ended_nanoseconds']-interval['started_nanoseconds'] <= ctx['request_seconds']*10**9,
        'qualification_host_source', 'original same-host bounded capture interval required')
    owner = exact(proof['capture_owner'], {'process', 'collector', 'native_host_boot_id'})
    from host_resource_qualification_gate import process_identity
    process_identity(owner['process'])
    require(owner['process']['uids'] == [0]*4 and
        owner['native_host_boot_id'] == selector['native_host']['host_boot_id'] and
        owner['collector'] == roles['source_refs'].get('collector'),
        'qualification_host_source', 'actual original Root collector/Source/boot differs')
    exact(proof['receiver_before'], {'controller', 'worker'})
    for role, packet in proof['receiver_before'].items():
        _clock_reply(packet, roles['roles'][role])
    return proof


def _verify_clock_transcripts(view, proof):
    references = proof['original_transcript_refs']
    require(type(references) is list and len(references) == 2,
        'qualification_host_source', 'both original authenticated receiver transcripts required')
    folder = view.root/'qualification'/proof['operation_id']/'source-observations'
    roles_seen = set()
    for ref in references:
        exact(ref, {'request_id', 'intent_sha256', 'status_name', 'status_sha256'})
        request = native.canonical_uuid(ref['request_id']); sha(ref['intent_sha256']); sha(ref['status_sha256'])
        require(type(ref['status_name']) is str and re.fullmatch(re.escape(request)+r'-status-[1-9][0-9]*\.json', ref['status_name']),
            'qualification_host_source', 'fixed original QGA status leaf required')
        def original(name, pin=None):
            data = _read_private(folder/name, view.budget, 1024**2)
            require(pin is None or hashlib.sha256(data).hexdigest() == pin,
                'qualification_host_source', 'original transcript raw bytes differ')
            return strict_json(data.decode())
        intent = original(request+'-intent.json', ref['intent_sha256'])
        started = original(request+'-started.json')
        status = original(ref['status_name'], ref['status_sha256'])
        role = intent['role']; require(role in ('controller', 'worker') and role not in roles_seen,
            'qualification_host_source', 'distinct original role transcripts required')
        roles_seen.add(role)
        target = proof['native_host_context']['roles']['roles'][role]
        require(intent['schema'] == 'qcl.host-resource-calibration-qga-intent.v1' and intent['operation_id'] == proof['operation_id'] and
            intent['request_id'] == started['request_id'] == status['request_id'] == request and intent['target'] == target and
            intent['action'] == 'clock' and intent['input_sha256'] == hashlib.sha256(b'{}').hexdigest() and
            started['schema'] == 'qcl.host-resource-calibration-qga-started.v1' and
            status['schema'] == 'qcl.host-resource-calibration-qga-status.v1' and
            started['intent_sha256'] == status['intent_sha256'] == ref['intent_sha256'] and
            started['pid'] == status['pid'] == decode_qga_started(started['original_stdout']),
            'qualification_host_source', 'original one-exec/PID/Source/receiver transcript join differs')
        # Derive the original node from its one fixed exec endpoint; no network
        # destination or command is accepted from a body or proof selector.
        require(type(intent['argv']) is list and len(intent['argv']) > 2, 'qualification_host_source', 'original QGA argv required')
        match = re.fullmatch(r'/nodes/([A-Za-z0-9][A-Za-z0-9_-]*)/qemu/'+str(target['vm_id'])+r'/agent/exec', intent['argv'][1])
        require(match is not None and intent['argv'] == qga_exec_arguments(match[1], target['vm_id'], target, 'clock', {}) and
            0 <= intent['native_started_boottime_ns'] <= status['native_ended_boottime_ns'] <=
            proof['native_capture_interval']['started_nanoseconds'],
            'qualification_host_source', 'actual host capture must follow both returned original clock samples')
        result = decode_qga_status(status['original_stdout'])
        require(result['exited'] == 1 and result.get('exitcode') == 0 and not result.get('err-data', '') and
            strict_json(result.get('out-data', '')) == proof['receiver_before'][role],
            'qualification_host_source', 'original receiver sample cannot be restamped at import')


def read_host_proof(view, permit):
    selector, current_permit, folder, originals = view.snapshot()
    require(current_permit == permit, 'qualification_host_source', 'fixed original permit changed')
    try:
        raw = _read_private(folder/'host-current.json', view.budget)
        current = exact(strict_json(raw.decode()), {'schema', 'operation_id', 'permit_sha256', 'proof_sha256'})
        sha(current['proof_sha256'])
        require(current['schema'] == 'qcl.host-resource-calibration-host-current.v1' and
            current['operation_id'] == selector['operation_id'] and current['permit_sha256'] == selector['permit_sha256'],
            'qualification_host_source', 'fixed original host proof reference differs')
        data = _read_private(folder/'host-proofs'/(current['proof_sha256']+'.json'), view.budget, 1024**2)
        require(hashlib.sha256(data).hexdigest() == current['proof_sha256'],
            'qualification_host_source', 'original host proof hash differs')
        proof = _decode_host_proof(strict_json(data.decode()), selector, permit)
        _verify_clock_transcripts(view, proof)
        validate_receiver_age(view, proof['receiver_before'][selector['role']]['clock'], proof['native_host_context']['request_seconds'])
        require(_read_private(folder/'host-current.json', view.budget) == raw and view.current_permit() == permit,
            'qualification_changed', 'host reference/original permit changed while reading')
        return proof
    except FileNotFoundError as error:
        raise native.Hold('qualification_host_source_required') from error


def _capacity_for_proof(view, permit, proof):
    from host_resource_qualification_observations import capacity_document, expected_capacity, context
    from host_resource_capacity import decode_capacity_qualification_v2
    selector, current, folder, originals = view.snapshot()
    report = originals['capacity-report.json']
    try:
        ctx = context(report['permit']['context'])
        require(ctx['policy_sha256'] == selector['native_host']['policy_sha256'] and
            ctx['host_boot_id'] == selector['native_host']['host_boot_id'] and
            ctx['source_graph_sha256'] == permit['source_graph_sha256'] and
            ctx['baseline_state_sha256'] == selector['native_host']['baseline_state_sha256'] and
            all(row['vm_id'] == ctx['binding']['vm_id'] for row in permit['jobs'].values()) and
            proof['captured_guests'][ctx['binding']['vm_id']]['context']['binding'] == ctx['binding'],
            'qualification_capacity_profile_required', 'original measured profile/current context differs')
        capacity = decode_capacity_qualification_v2(capacity_document(report['permit'], report_sha256=selector['capacity_report_sha256']),
            **expected_capacity(ctx, selector['capacity_report_sha256']))
        require(capacity is not None, 'qualification_capacity_profile_required', 'actual measured capacity required')
        return capacity, ctx
    except (KeyError, TypeError, ValueError) as error:
        raise native.Hold('qualification_capacity_profile_required') from error


def _validate_reservation_capacity(view, permit, proof):
    """Full charged V/allD native and physical floors; no future task-L claim."""
    from host_resource_capacity import rounded_native_floor, physical_floor
    from host_resource_facts import validate_inventory
    from host_resource_qualification_observations import context, validate_accounting
    policy = proof['native_host_context']['policy']; host = proof['captured_host']
    plan = view.snapshot()[3]['parent-plan.json']; paid = strict_json(host['paid_state_raw'])
    vms = {vm['vm_id']: vm for vm in policy['vms']}
    require(set(vms) == set(proof['captured_guests']) == set(plan['bindings']) and
        type(paid['grants']) is list and len(paid['grants']) == len(vms),
        'qualification_host_source', 'complete actual resident/paid guest set required')
    grants = {row['vm_id']: row for row in paid['grants']}
    require(set(grants) == set(vms) and all(grants[vm]['guest_bytes'] == vms[vm]['maximum_bytes'] for vm in vms),
        'qualification_host_source', 'literal full reservation for every resident required')
    reserves = policy['reserves']
    total = sum(reserves[key] for key in ('host_services_bytes', 'control_plane_bytes', 'safety_bytes', 'foreign_max_bytes'))
    total += sum(vm['maximum_bytes']+vm['overhead_bytes'] for vm in vms.values())
    require(total <= policy['physical_ram_bytes'] == host['host']['MemTotal'] and
        host['host']['MemAvailable'] >= reserves['safety_bytes'],
        'qualification_host_capacity', 'actual H/F/O and full resident charge do not fit physical host')
    enrollment = {vm: dict(native_id=plan['bindings'][vm]['native_id'], maximum_bytes=row['maximum_bytes']) for vm, row in vms.items()}
    qemu = {str(row['pid']) for row in host['processes'] if 'qemu-system-' in Path(row['executable']).name or
        Path(row['executable']).name in {'kvm', 'qemu-kvm'}}
    require(host['agreement']['policy_sha256'] == proof['native_host_context']['policy_sha256'] and
        host['agreement']['agreement_ref'] == policy['owned_pool']['agreement_ref'],
        'qualification_host_source', 'actual protected foreign agreement differs')
    validate_inventory(host['inventory'], enrollment, host['agreement']['foreign'],
        foreign_budget=reserves['foreign_max_bytes'], observed_qemu_pids=qemu)
    child = host['child_jobs']
    require(child is None or (child['permit'] == permit and child['permit_sha256'] == digest(permit) and
        set(child['jobs']) == set(permit['jobs'])), 'qualification_host_source', 'original full child set differs')
    allowed = {vm: set() for vm in vms}
    if child is not None:
        for calc, refs in child['jobs'].items():
            bound = refs['bound']
            if bound is None: continue
            require(type(bound) is dict and bound['sha256'] == digest(bound['record']),
                'qualification_host_source', 'original bound receipt differs')
            mirror = _mirror(permit, calc, bound['record'])
            allowed[permit['jobs'][calc]['vm_id']].add(mirror['creator']['job_id'])
    for vm, row in proof['captured_guests'].items():
        ctx = context(row['context']); read = row['readback']; guest = row['guest']
        amounts = [r['demand_bytes'] for r in permit['jobs'].values() if r['vm_id'] == vm]
        require(ctx['binding'] == plan['bindings'][vm] and ctx['source_graph_sha256'] == permit['source_graph_sha256'] and
            ctx['policy_sha256'] == proof['native_host_context']['policy_sha256'] and ctx['baseline_state_sha256'] ==
            proof['parent_refs']['baseline_state_sha256'] and
            all(read[key] == ctx['binding'][key] for key in ('vm_id', 'native_id', 'process_id', 'config_fingerprint')) and
            read['running'] is True and
            read['assigned_bytes'] == read['configured_bytes'] == grants[vm]['guest_bytes'] and
            rounded_native_floor(vms[vm]['minimum_bytes'], amounts, ctx['quantum_bytes']) <= read['assigned_bytes'] and
            guest['identity_before'] == guest['identity_after'] and
            guest['identity_before']['machine_id'] == ctx['worker_machine_id'] and
            guest['identity_before']['boot_id'] == ctx['binding']['guest_boot_id'] and
            set(guest['jobs']) == set(guest['groups']) and set(guest['jobs']) <= allowed[vm],
            'qualification_host_source', 'actual resident allocation/native job census differs from originals')
        accounting = validate_accounting(guest.get('calibration_accounting'), ctx)
        # The complete actual accounting identity is already joined to the
        # original context, including image/kernel/DMI. Every supplied guest
        # identity field must agree; missing facts are never filled from paid V.
        identity = accounting['identity']; guest_identity = guest['identity_before']
        require(type(guest_identity) is dict and {'machine_id', 'boot_id'} <= set(guest_identity) <= set(identity) and
            all(value == identity[key] for key, value in guest_identity.items()),
            'qualification_host_source', 'actual guest/accounting identity differs from original binding')
        actual = guest.get('output_generation')
        require(type(actual) is dict and set(actual) == {'worker', 'runner'},
            'qualification_host_source', 'actual complete worker/Source generation required')
        native._output_worker(actual['worker']); native._output_runner(actual['runner'])
        require(actual['worker']['identity'] == {key: identity[key] for key in ('machine_id', 'boot_id', 'kernel', 'dmi_uuid')} and
            actual['runner']['source_graph_sha256'] == permit['source_graph_sha256'],
            'qualification_host_source', 'actual worker identity or Source graph differs')
    capacity, ctx = _capacity_for_proof(view, permit, proof)
    target = proof['captured_guests'][ctx['binding']['vm_id']]
    amounts = list(demands(permit)); memory = target['guest']['memory']; scheduler = target['guest']['slurm_memory_bytes']
    require(physical_floor(capacity.os_reserve_bytes, amounts) <= memory['MemTotal'] <= capacity.maximum_guest_total_bytes and
        memory['MemAvailable'] <= memory['MemTotal'] and
        max(amounts) <= memory['MemAvailable'] and sum(amounts) <= scheduler <=
        capacity.maximum_guest_total_bytes-capacity.os_reserve_bytes and
        max(0, target['readback']['assigned_bytes']-memory['MemTotal']) <= capacity.native_gap_bound_bytes and
        target['guest'].get('slurm_registered') is True,
        'qualification_guest_capacity', 'actual T/A/S/R/K and every authorized D do not fit before allocation')
    return capacity, ctx


def _validate_guest_actual_body(self, permit, proof):
    from host_resource_facts import LocalSources, capture_guest_facts
    from host_resource_backends import NativeCommandRunner
    from host_resource_capacity import validate_guest_admission
    from host_resource_qualification_observations import expected_capacity
    capacity, ctx = _capacity_for_proof(self.view, permit, proof)
    config = strict_json(native.protected_read(self.sources.policy['facts_service_config'], self.sources.budget).decode())
    runner = NativeCommandRunner(config['tools'], slurm_conf=config['slurm_conf'])
    local = LocalSources(config, runner)
    guest = capture_guest_facts(config, local, calibration=True)
    identity = guest['identity_before']
    require(identity == guest['identity_after'] and identity['machine_id'] == ctx['worker_machine_id'] and
        identity['boot_id'] == ctx['binding']['guest_boot_id'] and guest.get('slurm_registered') is True,
        'qualification_actual_limit', 'actual local physical/registration generation differs')
    limits, candidate_index = [], None
    caller = self.authenticated_caller()
    allowed = set()
    for index, (calc, row) in enumerate(permit['jobs'].items()):
        mirror = self.mirror_read(calc)
        require(mirror is not None and mirror['revision'] == 1 and mirror['creator'] is not None,
            'qualification_actual_limits_missing', 'every body needs actual original allocation; planned L is unavailable')
        job = mirror['creator']['job_id']; allowed.add(job)
        require(job in guest['jobs'] and guest['jobs'][job]['state'] == 'RUNNING' and
            guest['jobs'][job]['submit_time'] == mirror['creator']['submit_time'],
            'qualification_actual_limits_missing', 'every original current allocation must be observed')
        group = guest['groups'][job]
        pids = [p['pid'] for p in group['processes'] if p['uids'] == [permit['client_uid']]*4]
        require(pids, 'qualification_actual_limits_missing', 'actual original task process required')
        limits.append(max(self.actual_task_limit(pid, row['demand_bytes']) for pid in pids))
        if caller['pid'] in pids:
            require(candidate_index is None, 'qualification_actual_limit', 'unique actual candidate required')
            candidate_index = index
    require(set(guest['jobs']) == allowed and set(guest['groups']) == allowed and candidate_index is not None,
        'qualification_actual_limits_missing', 'complete local native census/candidate required')
    read = proof['captured_guests'][ctx['binding']['vm_id']]['readback']
    validate_guest_admission(qualification=capacity, native_minimum_bytes=ctx['native_minimum_bytes'],
        paid_grant_bytes=ctx['paid_grant_bytes'], assigned_bytes=read['assigned_bytes'], configured_bytes=read['configured_bytes'],
        total_bytes=guest['memory']['MemTotal'], available_bytes=guest['memory']['MemAvailable'], demands=list(demands(permit)),
        task_limits=limits, candidate_index=candidate_index, slurm_memory_bytes=guest['slurm_memory_bytes'],
        quantum_bytes=ctx['quantum_bytes'], limits_enforced=True, **expected_capacity(ctx, capacity.report_sha256))
    validate_receiver_age(self.view, proof['receiver_before']['worker']['clock'], proof['native_host_context']['request_seconds'])



def _replace_private(path, data, budget, *, absent):
    """Caller holds the existing operation/CAS lock; publish after file fsync."""
    temporary = '.proof-'+str(uuid.uuid4())
    _private_directory(path.parent)
    budget.reserve(len(data)); budget.file()
    with native.protected_directory(path.parent, budget=budget) as parent:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        try:
            offset = 0
            while offset < len(data):
                budget.before(); count = os.write(fd, data[offset:])
                require(count > 0, 'qualification_import', 'short proof reference write')
                offset += count
            os.fsync(fd)
        finally:
            os.close(fd)
        if absent:
            os.link(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
            os.unlink(temporary, dir_fd=parent)
        else:
            os.rename(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    require(_read_private(path, budget, len(data)) == data,
        'qualification_import', 'actual proof reference readback differs')


def _import_host_proof(ingress, payload):
    exact(payload, {'schema', 'expected', 'proof_raw', 'observations'})
    require(len(native.encoded(payload)) <= 65536, 'output_bound', 'large immutable proof needs a separately qualified bounded staging protocol')
    if payload['expected'] is not None: sha(payload['expected'])
    require(type(payload['proof_raw']) is str, 'qualification_import', 'exact original proof bytes required')
    view = ingress.view
    selector, permit, folder, originals = view.snapshot()
    proof = _decode_host_proof(strict_json(payload['proof_raw']), selector, permit)
    data = payload['proof_raw'].encode(); digest_value = hashlib.sha256(data).hexdigest()
    observations = payload['observations']
    require(type(observations) is dict and len(observations) == 6,
        'qualification_import', 'both original intent/started/status transcripts required')
    names = set()
    for ref in proof['original_transcript_refs']:
        request = native.canonical_uuid(ref['request_id'])
        require(re.fullmatch(re.escape(request)+r'-status-[1-9][0-9]*\.json', ref['status_name']),
            'qualification_import', 'fixed original status leaf required')
        names.update((request+'-intent.json', request+'-started.json', ref['status_name']))
    require(set(observations) == names and all(type(raw) is str for raw in observations.values()),
        'qualification_import', 'fixed exact original transcript set required')
    for raw in observations.values(): strict_json(raw)
    stamp = proof['receiver_before'][selector['role']]['clock']
    validate_receiver_age(view, stamp, proof['native_host_context']['request_seconds'])
    lock = str(uuid.uuid5(uuid.NAMESPACE_URL, 'qcl-task3-host-proof-'+selector['operation_id']))
    with native.AttemptStore(view.root).locked(lock, view.budget):
        path = folder/'host-current.json'
        try:
            previous_raw = _read_private(path, view.budget)
            previous = exact(strict_json(previous_raw.decode()), {'schema', 'operation_id', 'permit_sha256', 'proof_sha256'})
            require(previous['schema'] == 'qcl.host-resource-calibration-host-current.v1' and
                previous['operation_id'] == selector['operation_id'] and previous['permit_sha256'] == selector['permit_sha256'] and
                payload['expected'] is not None and previous['proof_sha256'] == payload['expected'],
                'qualification_cas', 'exact previous original host reference required')
        except FileNotFoundError:
            previous_raw = None
            require(payload['expected'] is None, 'qualification_cas', 'missing original expected host proof')
        for name in ('source-observations', 'host-proofs'):
            directory = folder/name
            try: directory.mkdir(mode=0o700)
            except FileExistsError: _private_directory(directory)
        for name, raw in observations.items():
            _exclusive_private(folder/'source-observations'/name, raw.encode(), view.budget)
        _exclusive_private(folder/'host-proofs'/(digest_value+'.json'), data, view.budget)
        # Validate actual retained original copies before publishing the pointer.
        _verify_clock_transcripts(view, proof)
        validate_receiver_age(view, stamp, proof['native_host_context']['request_seconds'])
        if previous_raw is not None:
            require(_read_private(path, view.budget) == previous_raw, 'qualification_cas', 'original host reference changed')
        current = dict(schema='qcl.host-resource-calibration-host-current.v1', operation_id=selector['operation_id'],
            permit_sha256=selector['permit_sha256'], proof_sha256=digest_value)
        _replace_private(path, native.encoded(current), view.budget, absent=previous_raw is None)
        require(view.current_permit() == permit, 'qualification_changed', 'original role context changed during import')
    return current


def host_import_payload(parent, reference, *, expected=None):
    """Build only from this owner's retained raw proof and original receipts."""
    path = Path(reference['path'])
    require(path.parent == parent.repository.folder(parent.operation)/'source-observations' and
        re.fullmatch(r'(stage|submit|bind|release|guard|revoke|close)-host-[0-9a-f-]{36}\.json', path.name),
        'qualification_import', 'original protected owner proof reference required')
    data = _retained_root_raw(parent.store, path, 1024**2)
    require(hashlib.sha256(data).hexdigest() == reference['sha256'],
        'qualification_import', 'retained original proof bytes changed')
    proof = strict_json(data.decode()); observations = {}
    for ref in proof['original_transcript_refs']:
        request = native.canonical_uuid(ref['request_id'])
        require(re.fullmatch(re.escape(request)+r'-status-[1-9][0-9]*\.json', ref['status_name']),
            'qualification_import', 'fixed original status name required')
        for name in (request+'-intent.json', request+'-started.json', ref['status_name']):
            observations[name] = _retained_root_raw(parent.store, path.parent/name, 1024**2).decode()
    result = dict(schema='qcl.host-resource-calibration-host-import.v1', expected=expected,
        proof_raw=data.decode(), observations=observations)
    require(len(native.encoded(result)) <= 65536, 'output_bound', 'large raw proof requires reviewed bounded staging before use; never restamp')
    return result
