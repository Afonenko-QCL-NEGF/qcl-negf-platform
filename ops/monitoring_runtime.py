"""Fixed-role P31 runtime. Polling reads only; sampler and retention are separate root roles."""
import base64
import copy
import hashlib
import json
import grp
import pwd
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import time
from urllib.parse import urlsplit

CONFIG = Path('/etc/qcl-negf/monitoring/service.json')
CACHE = Path('/run/qcl-negf-monitoring/latest.json')
SCHEMAS = Path(__file__).resolve().parents[1] / 'schemas'
IDENTIFIER = r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}'


def reason(code, source_id):
    return dict(code=code, source_id=source_id)


def canonical(path):
    return (isinstance(path, str) and path.startswith('/') and len(path) <= 1024
            and not any(x in ('', '.', '..') for x in path.split('/')[1:])
            and not any(x in path for x in ('\n', '\r', '\x00')))


def validate_config(value):
    from jsonschema import Draft202012Validator
    try:
        Draft202012Validator(json.loads((SCHEMAS / 'monitoring-config.schema.json').read_text())).validate(value)
        storage = value['storage']
        if storage['binding'] == 'unqualified' and any(storage[k] is not None for k in ('maximum_bytes', 'device', 'quota_project')):
            raise ValueError('unqualified_storage_fields')
        if storage['binding'] != 'unqualified' and (storage['maximum_bytes'] is None or storage['device'] is None):
            raise ValueError('missing_storage_binding')
        if storage['binding'] == 'dedicated_mount' and storage['quota_project'] is not None:
            raise ValueError('unexpected_quota_scope')
        if storage['binding'] == 'project_quota' and storage['quota_project'] is None:
            raise ValueError('missing_quota_scope')
        if value['reader_uid'] == value['observer_uid']:
            raise ValueError('distinct_uids_required')
        paths = [*value['tools'].values(), value['storage']['directory']]
        for target in value['targets']:
            paths += [target[k] for k in ('helper', 'known_hosts', 'identity_file')]
            if not re.fullmatch(r'[A-Za-z0-9_.-]+@[A-Za-z0-9][A-Za-z0-9_.-]*', target['target']):
                raise ValueError('invalid_target')
        for group in value['scopes']['cgroups']:
            if not group['path'].startswith('/sys/fs/cgroup/'):
                raise ValueError('invalid_cgroup_scope')
            paths.append(group['path'])
        if not all(canonical(p) for p in paths):
            raise ValueError('noncanonical_path')
        if value['scopes']['backend'] == 'disabled' and value['scopes']['vms']:
            raise ValueError('disabled_vm_scope')
        if value['scopes']['backend'] == 'pve' and (value['scopes']['node'] is None or any(not re.fullmatch(r'[1-9][0-9]{0,8}', vm['native_id']) for vm in value['scopes']['vms'])):
            raise ValueError('invalid_pve_scope')
        for field in ('vms', 'services', 'cgroups'):
            key = {'vms': 'vm_id', 'services': 'service_id', 'cgroups': 'workload'}[field]
            ids = [x[key] for x in value['scopes'][field]]
            if len(ids) != len(set(ids)):
                raise ValueError('duplicate_scope')
        for field in ('targets',):
            ids = [x['host_id'] for x in value[field]]
            if len(ids) != len(set(ids)):
                raise ValueError('duplicate_target')
        if value['role'] != 'controller' and value['targets']:
            raise ValueError('role_scope_mismatch')
        if value['role'] == 'controller' and (value['scopes']['vms'] or value['scopes']['cgroups'] or value['scopes']['services'] or value['scopes']['journal'] or value['scopes']['backend'] != 'disabled'):
            raise ValueError('role_scope_mismatch')
        if value['role'] != 'worker' and value['scopes']['cgroups']:
            raise ValueError('guest_cgroup_role_required')
        if value['role'] == 'worker' and (value['scopes']['vms'] or value['scopes']['backend'] != 'disabled'):
            raise ValueError('role_scope_mismatch')
        if value['bounds']['command_seconds'] <= 2 or value['bounds']['sample_seconds'] <= value['bounds']['command_seconds']:
            raise ValueError('cleanup_reserve_required')
        for link in value['graph_links']:
            href, origin = urlsplit(link['href']), urlsplit(link['origin'])
            if (any(ord(ch) < 32 for ch in link['href'] + link['origin']) or href.scheme != 'https' or origin.scheme != 'https' or not href.hostname or
                    href.username or href.password or href.query or href.fragment or
                    origin.username or origin.password or origin.path not in ('', '/') or origin.query or origin.fragment or
                    (href.scheme, href.netloc) != (origin.scheme, origin.netloc)):
                raise ValueError('unsafe_graph_link')
    except Exception as error:
        raise ValueError('invalid_monitoring_config') from error
    return value


def validate_query(query):
    if (not isinstance(query, dict) or set(query) != {'schema', 'request_id', 'cursor', 'limit'} or
            query['schema'] != 'qcl.cluster-query.v1' or type(query['limit']) is not int or not 1 <= query['limit'] <= 128 or
            query['request_id'] is not None and not re.fullmatch(IDENTIFIER, str(query['request_id'])) or
            query['request_id'] is not None and not isinstance(query['request_id'], str) or
            query['cursor'] is not None and (not isinstance(query['cursor'], str) or len(query['cursor']) > 8192)):
        raise ValueError('invalid_query')
    return query


def unique_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate_json_key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid_json_constant')))


def encode_token(value):
    return base64.urlsafe_b64encode(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).decode().rstrip('=')


def decode_token(token):
    if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,8192}', token):
        raise ValueError('invalid_token')
    try:
        value = unique_json(base64.b64decode(token + '=' * (-len(token) % 4), altchars=b'-_', validate=True))
        if not isinstance(value, dict):
            raise ValueError('invalid_token')
        return value
    except Exception as error:
        raise ValueError('invalid_token') from error


def encode_query(value):
    token = encode_token(validate_query(value))
    if len(token) > 8192:
        raise ValueError('query_bound')
    return token


def decode_query(token):
    return validate_query(decode_token(token))


def forced_command(command, *, helper):
    parts = shlex.split(command)
    if len(parts) != 3 or parts[:2] != [helper, 'observe']:
        raise ValueError('invalid_forced_command')
    decode_query(parts[2])
    return parts[2]


def authenticate(environment, parent_pid, process, sudo_path, allowed_uid):
    """An environment variable is not authority. Bind actual sudo + originating process."""
    if type(allowed_uid) is not int or allowed_uid <= 0 or environment.get('SUDO_UID') != str(allowed_uid):
        raise ValueError('caller_identity')
    chain = []
    pid = parent_pid
    for _ in range(8):
        record = process(pid); chain.append(record)
        if record['executable'] == sudo_path:
            if record['uids'][1:] != [0, 0, 0]:
                raise ValueError('sudo_credentials')
            caller = process(record['ppid'])
            if caller['uids'] != [allowed_uid] * 4 or caller['cgroup'] != record['cgroup'] or caller['start_ticks'] > record['start_ticks']:
                raise ValueError('caller_identity')
            if process(caller['pid']) != caller or any(process(x['pid']) != x for x in chain):
                raise ValueError('caller_changed')
            return caller
        if record['uids'][1:] != [0, 0, 0] or record['ppid'] <= 1:
            break
        pid = record['ppid']
    raise ValueError('sudo_parent_required')


def process_identity(pid):
    # Read only a selected PID. Never scan /proc or return command lines publicly.
    raw = Path('/proc', str(pid), 'stat').read_text()
    fields = raw[raw.rfind(')')+2:].split()
    status = Path('/proc', str(pid), 'status').read_text()
    uids = re.search(r'^Uid:\s+(.+)$', status, re.M)
    return dict(pid=pid, ppid=int(fields[1]), start_ticks=int(fields[19]),
                uids=[int(x) for x in uids[1].split()],
                executable=os.readlink('/proc/' + str(pid) + '/exe'),
                cgroup=Path('/proc', str(pid), 'cgroup').read_text())


def load_config():
    from release_trust import read_protected_file
    return validate_config(unique_json(read_protected_file(CONFIG, 65536)))


def read_cache(config):
    from release_trust import read_protected_file
    from application_release import unique_json
    try:
        value = unique_json(read_protected_file(CACHE, config['bounds']['output_bytes']))
        if set(value) != {'config_generation', 'native', 'services', 'journal_cursor', 'cgroups', 'storage'} or value['config_generation'] != digest(config):
            return None
        # Reuse the public shape validator: never relay arbitrary cache keys or text.
        from cluster_projection import validate_cluster_projection
        validate_cluster_projection(dict(schema='qcl.cluster-projection.v1', read_at=int(time.time()), status='ok',
            registry_generation=digest(config), hosts=[dict(host_id=config['scopes']['host_id'], resource=None,
            native=value['native'], services=value['services'], storage=value['storage'], graph_links=[], reasons=[])],
            complete=True, next_cursor=None, coverage=dict(sources=[], reasons=[])))
        return value
    except (OSError, ValueError):
        return None


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def unknown_storage(observed_at=None):
    return dict(schema='qcl.telemetry-storage.v1', status='unknown', binding_kind='unqualified',
                maximum_bytes=None, used_bytes=None, available_bytes=None, keep_free_bytes=None,
                inodes_available=None, retention_seconds=None, persist_enabled=False,
                observed_at=observed_at, reasons=[reason('capacity_not_qualified', 'telemetry')])


from dataclasses import dataclass


@dataclass(frozen=True)
class CapacityEvidence:
    """Internal capacity-oracle output, not a public/config trust flag.

    No installed backing/reserve producer exists in v1. Native readback returns
    proof=None. Tests inject this value solely to exercise scoped retention logic.
    A future owning producer needs native qualification before enabling persistence.
    """
    device: int
    maximum_bytes: int
    scientific_reserve_bytes: int
    independent_backing: bool
    thin_or_shared: bool


class StorageBoundary:
    """Only a native scoped hard capacity binding permits persistence or own-file pruning.

    DI observe is a fixture boundary, not a JSON/native qualification flag.
    Production reads an existing dedicated local mount, without a backing/reserve
    producer; persist stays unknown. Quota readback is explicit unsupported: no portable project-quota assumptions or quota mutation.
    """
    def __init__(self, config, *, clock=time.time, observe=None, owner_uid=0):
        self.config, self.clock, self.owner_uid = config, clock, owner_uid
        self.observe = observe or self._observe

    def _observe(self):
        c = self.config['storage']; directory = Path(c['directory'])
        if c['binding'] != 'dedicated_mount':
            raise ValueError('quota_readback_unsupported' if c['binding'] == 'project_quota' else 'capacity_not_qualified')
        fd = self._directory()
        try:
            info = os.fstat(fd); fs = os.fstatvfs(fd)
            parent = directory.parent.stat()
            if info.st_dev == parent.st_dev or info.st_dev != c['device']:
                raise ValueError('dedicated_mount_not_verified')
            maximum = fs.f_blocks * fs.f_frsize
            if maximum <= 0 or maximum > c['maximum_bytes']:
                raise ValueError('capacity_not_bounded')
            return dict(qualified=False, proof=None, binding='dedicated_mount', device=info.st_dev,
                maximum_bytes=maximum, used_bytes=(fs.f_blocks-fs.f_bfree)*fs.f_frsize,
                available_bytes=fs.f_bavail*fs.f_frsize, inodes_available=fs.f_favail, owner_uid=info.st_uid)
        finally:
            os.close(fd)

    def _directory(self):
        from release_trust import protected_directory
        path = Path(self.config['storage']['directory'])
        # Test-only injected owner does not relax installed root-owned parents.
        if self.owner_uid == 0:
            with protected_directory(path.parent) as parent:
                fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        else:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(fd)
        allowed_group = grp.getgrnam('qcl-monitoring').gr_gid if info.st_mode & 0o020 else None
        if (info.st_uid != self.owner_uid or info.st_mode & 0o002 or
                info.st_mode & 0o020 and info.st_gid != allowed_group):
            os.close(fd); raise ValueError('untrusted_storage')
        return fd

    def read(self):
        c = self.config['storage']; view = unknown_storage(int(self.clock()))
        view.update(binding_kind=c['binding'], keep_free_bytes=c['keep_free_bytes'], retention_seconds=c['retention_seconds'])
        if c['binding'] == 'unqualified':
            return view
        try:
            facts = self.observe()
            if (facts['binding'] != c['binding'] or facts['device'] != c['device'] or
                    facts['owner_uid'] != self.owner_uid or type(c['maximum_bytes']) is not int or
                    any(type(facts[k]) is not int or facts[k] < 0 for k in ('maximum_bytes', 'used_bytes', 'available_bytes', 'inodes_available')) or
                    facts['maximum_bytes'] > c['maximum_bytes'] or facts['used_bytes'] > facts['maximum_bytes']):
                raise ValueError('capacity_not_qualified')
            view.update({k: facts[k] for k in ('maximum_bytes', 'used_bytes', 'available_bytes', 'inodes_available')})
            proof = facts.get('proof')
            if (facts.get('qualified') is not True or not isinstance(proof, CapacityEvidence) or
                    proof.maximum_bytes != facts['maximum_bytes'] or proof.scientific_reserve_bytes < c['keep_free_bytes'] or
                    not proof.independent_backing or proof.thin_or_shared or proof.device != facts['device']):
                view['reasons'] = [reason('backing_reserve_not_measured', 'telemetry')]
                return view
            view.update(status='qualified', reasons=[], persist_enabled=facts['available_bytes'] >= c['keep_free_bytes'] and facts['inodes_available'] >= c['minimum_inodes'])
            if not view['persist_enabled']:
                view.update(status='degraded', reasons=[reason('reserve_threshold', 'telemetry')])
        except (OSError, ValueError, TypeError, KeyError):
            if c['binding'] == 'project_quota':
                view.update(status='unsupported', reasons=[reason('quota_readback_unsupported', 'telemetry')])
        return view

    def _writer_uids(self):
        if self.owner_uid != 0:
            return {self.owner_uid}
        try:
            return {0, pwd.getpwnam('qcl-monitoring').pw_uid}
        except KeyError:
            return {0}

    def maintain(self):
        view = self.read()
        if not view['persist_enabled']:
            return view
        c = self.config['storage']; now = int(self.clock()); rejected = False
        deadline = time.monotonic() + self.config['bounds']['command_seconds']
        # Fixed owning scope, finite enumeration; retain current UTC day, reject all symlinks.
        fd = self._directory()
        try:
            root = os.fstat(fd)
            if root.st_uid != self.owner_uid:
                return {**view, 'status': 'unknown', 'persist_enabled': False, 'reasons': [reason('untrusted_storage', 'telemetry')]}
            with os.scandir(fd) as entries:
                for count, entry in enumerate(entries):
                    if count >= self.config['bounds']['retention_entries'] or time.monotonic() >= deadline:
                        rejected = True; break
                    if not re.fullmatch(r'events-\d{4}-\d{2}-\d{2}\.ndjson', entry.name):
                        continue
                    info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                    if not stat.S_ISREG(info.st_mode) or info.st_uid not in self._writer_uids() or info.st_nlink != 1 or info.st_dev != root.st_dev:
                        rejected = True; continue
                    if (entry.name == time.strftime('events-%Y-%m-%d.ndjson', time.gmtime(now)) or
                            now-info.st_mtime <= c['retention_seconds']):
                        continue
                    again = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                    if (info.st_ino, info.st_dev, info.st_mtime_ns, info.st_size) != (again.st_ino, again.st_dev, again.st_mtime_ns, again.st_size):
                        rejected = True; continue
                    os.unlink(entry.name, dir_fd=fd)
        finally:
            os.close(fd)
        if rejected:
            view.update(status='degraded', reasons=[reason('retention_incomplete', 'telemetry')])
        return view


def validate_tool(tool):
    from release_trust import protected_directory, protected_parts, trusted_stat
    parts = protected_parts(tool)
    if tool.startswith('/nix/store/'):
        with protected_directory('/nix') as root:
            fd = os.open('store', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
        try:
            info = os.fstat(fd)
            if info.st_uid != 0 or not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o002 or (info.st_mode & 0o020 and not info.st_mode & stat.S_ISVTX):
                raise ValueError('untrusted_store')
            for index, part in enumerate(parts[2:]):
                directory = index < len(parts[2:])-1
                child = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | (os.O_DIRECTORY if directory else os.O_NONBLOCK), dir_fd=fd)
                os.close(fd); fd = child
                trusted_stat(os.fstat(fd), directory=directory)
            if not os.fstat(fd).st_mode & 0o111:
                raise ValueError('nonexecutable_tool')
        finally:
            os.close(fd)
    else:
        with protected_directory(Path(tool).parent) as parent:
            fd = os.open(Path(tool).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                trusted_stat(os.fstat(fd), directory=False)
                if not os.fstat(fd).st_mode & 0o111:
                    raise ValueError('nonexecutable_tool')
            finally:
                os.close(fd)


def _command_size(output, bound):
    from application_release import CommandOutput
    if not isinstance(output, CommandOutput):
        raise ValueError('command_contract')
    size = getattr(output, 'output_bytes', None)
    if type(size) is not int or not len(output.encode()) <= size <= bound:
        raise ValueError('command_contract')
    return size


def _failure_size(record, bound):
    # P11 counts retained stdout AND stderr, including failed commands. A missing
    # or malformed counter exhausts this call's budget rather than undercharging.
    size = record.get('output_bytes')
    return size if type(size) is int and 0 <= size <= bound else bound


class NativeSources:
    def __init__(self, config):
        self.config = config
        self.deadline = time.monotonic() + config['bounds']['sample_seconds']
        self.bytes = 0

    def read(self, path, limit=65536):
        if time.monotonic() >= self.deadline or self.bytes + limit > self.config['bounds']['output_bytes']:
            raise ValueError('sample_budget')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            raw = os.read(fd, limit+1)
            if len(raw) > limit:
                raise ValueError('source_output_bound')
            self.bytes += len(raw)
            return raw.decode()
        finally:
            os.close(fd)

    def run(self, argv, output_bytes=None):
        from application_release import command, CommandFailure
        tool = argv[0]
        if tool not in self.config['tools'].values():
            raise ValueError('tool_not_allowlisted')
        # Path ownership checked without reading the complete executable.
        validate_tool(tool)
        remaining = self.config['bounds']['output_bytes'] - self.bytes
        bound = min(output_bytes or remaining, remaining)
        if bound < 1:
            raise ValueError('sample_budget')
        try:
            output = command(argv, timeout_seconds=self.config['bounds']['command_seconds'], output_bytes=bound,
                             deadline=self.deadline, env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
        except CommandFailure as error:
            self.bytes += _failure_size(error.record, bound)
            raise  # preserve the owning failure/record; no partial stdout is accepted
        self.bytes += _command_size(output, bound)
        return output

    def process(self, pid):
        before = self.read('/proc/' + str(pid) + '/stat')
        fields = before[before.rfind(')')+2:].split()
        status = self.read('/proc/' + str(pid) + '/status')
        args = self.read('/proc/' + str(pid) + '/cmdline').split('\x00')
        rss = re.search(r'^VmRSS:\s+(\d+) kB$', status, re.M)
        if self.read('/proc/' + str(pid) + '/stat').split(')')[-1].split()[19] != fields[19]:
            raise ValueError('pid_reused')
        return dict(start_ticks=int(fields[19]), rss_bytes=int(rss[1])*1024 if rss else None, arguments=args)

    def cgroup(self, path, boot, generation):
        from release_trust import protected_directory
        with protected_directory(path) as fd:
            info = os.fstat(fd)
            item = os.open('memory.events', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                raw = os.read(item, 4097)
                if len(raw) > 4096: raise ValueError('cgroup_bound')
            finally: os.close(item)
            fields = dict(line.split() for line in raw.decode().splitlines())
            return dict(identity=boot + ':' + str(info.st_ino) + ':' + str(info.st_ctime_ns) + ':' + generation, oom_kill=nonnegative_counter(fields['oom_kill']))


def nonnegative_counter(value):
    if not re.fullmatch(r'[0-9]+', value):
        raise ValueError('invalid_cgroup_counter')
    return int(value)


def sample_native_status():
    if os.geteuid() != 0:
        raise ValueError('root_sampler_required')
    config = load_config()
    if config['role'] not in ('native_host', 'worker'):
        raise ValueError('sampler_role_required')
    from native_monitoring import NativeSampler
    sampler = NativeSampler(config, NativeSources(config), previous=read_cache(config))
    sample = sampler.sample()
    value = dict(config_generation=digest(config), **sample,
                 journal_cursor=getattr(sampler, 'journal_cursor', None), cgroups=getattr(sampler, 'cgroups', {}),
                 storage=StorageBoundary(config).read())
    from cluster_projection import validate_cluster_projection
    validate_cluster_projection(dict(schema='qcl.cluster-projection.v1', read_at=int(time.time()), status='ok',
        registry_generation=digest(config), hosts=[dict(host_id=config['scopes']['host_id'], resource=None,
        native=sample['native'], services=sample['services'], storage=value['storage'], graph_links=[], reasons=[])],
        complete=True, next_cursor=None, coverage=dict(sources=[], reasons=[])))
    raw = json.dumps(value, separators=(',', ':')).encode()
    if len(raw) > config['bounds']['output_bytes']:
        raise ValueError('cache_bound')
    from release_trust import protected_directory
    with protected_directory(CACHE.parent) as parent:
        # Single root systemd oneshot owns this directory; no public filename input.
        temp = '.latest-' + str(os.getpid())
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            remaining = memoryview(raw)
            while remaining:
                count = os.write(fd, remaining)
                if count <= 0: raise OSError('cache_write')
                remaining = remaining[count:]
            os.rename(temp, CACHE.name, src_dir_fd=parent, dst_dir_fd=parent)
        finally:
            os.close(fd)
            try: os.unlink(temp, dir_fd=parent)
            except FileNotFoundError: pass
    return sample['native']


def read_telemetry_storage():
    return StorageBoundary(load_config()).read()


def maintain_telemetry_storage():
    if os.geteuid() != 0:
        raise ValueError('root_maintenance_required')
    return StorageBoundary(load_config()).maintain()


def _normalize_observer_packet(packet, *, now, fresh_seconds):
    """Derive presentation freshness on a copy; never mutate resource DTO/cache."""
    from native_monitoring import _normalize_native_status, _normalize_coverage
    result = copy.deepcopy(packet)
    if result['native'] is not None:
        result['native'] = _normalize_native_status(result['native'], now=now, fresh_seconds=fresh_seconds)
    for entry in result['services']:
        _normalize_coverage(entry['coverage'], measurement_at=entry['observed_at'], now=now, fresh_seconds=fresh_seconds)
    storage = result['storage']
    if storage is not None:
        at = storage['observed_at']
        if at is None or at > now or now-at > fresh_seconds:
            storage.update(status='unknown', persist_enabled=False)
            new = reason('clock_future' if at is not None and at > now else 'storage_stale', 'telemetry')
            if new not in storage['reasons']:
                storage['reasons'] = storage['reasons'][:127] + [new]
    return result


def observe_local(query):
    config = load_config()
    if config['role'] not in ('native_host', 'worker'):
        raise ValueError('observer_role_required')
    validate_query(query)
    cache = read_cache(config)
    from native_monitoring import empty_native
    resource = None
    if config['role'] == 'native_host':
        try:
            from host_resource_projection import read_resource_projection
            resource = read_resource_projection(request_id=query['request_id'], cursor=query['cursor'], limit=query['limit'])
        except Exception as error:
            if query['cursor']:
                raise ValueError('stale_cursor') from error
    packet = dict(resource=resource, native=cache['native'] if cache else empty_native(config['scopes']['host_id']),
                  services=cache['services'] if cache else [], storage=cache['storage'] if cache else unknown_storage())
    return _normalize_observer_packet(packet, now=int(time.time()), fresh_seconds=config['bounds']['fresh_seconds'])


def observe_remote(target, query):
    from application_release import ssh, command, CommandFailure
    from release_trust import read_protected_file
    config = load_config()
    known = read_protected_file(target['known_hosts'])
    key = read_protected_file(target['identity_file'])
    snapshot = dict(path=target['known_hosts'], sha256=hashlib.sha256(known).hexdigest())
    def run(argv):
        # P11 fixed transport options, explicit private key, no ambient agent/env.
        bound = config['bounds']['output_bytes']
        try:
            output = command([argv[0], '-i', target['identity_file'], '-oIdentitiesOnly=yes',
                              '-oForwardAgent=no', '-oClearAllForwardings=yes', '-oRequestTTY=no', *argv[1:]],
                timeout_seconds=config['bounds']['command_seconds'], output_bytes=bound,
                env={'PATH': '/run/current-system/sw/bin:/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
        except CommandFailure as failure:
            record = failure.record
            # Only P11's completed nonzero outcome is a remote reply. Leader
            # exit1 can coexist with timeout while inherited output pipes drain.
            if (record.get('failure') == 'nonzero' and record.get('returncode') == 1
                    and record.get('cleanup_confirmed') is True
                    and not record.get('output_truncated', False)
                    and type(record.get('output_bytes')) is int
                    and 0 <= record['output_bytes'] <= bound):
                try:
                    error = unique_json(record.get('stderr', ''))
                except (ValueError, TypeError):
                    error = None
                if error == {'schema': 'qcl.monitoring-error.v1', 'reason': 'stale_cursor'}:
                    raise ValueError('stale_cursor') from failure
            raise ValueError('observer_transport_unavailable') from failure
        _command_size(output, bound)
        return output
    result = ssh(target['target'], [target['helper'], 'observe', encode_query(query)], run, trust_snapshot=snapshot)
    if read_protected_file(target['known_hosts']) != known or read_protected_file(target['identity_file']) != key:
        raise ValueError('ssh_trust_changed')
    return unique_json(result)


def main(action):
    try:
        if action in ('sample', 'maintain', 'storage-check'):
            if os.geteuid() != 0 or len(sys.argv) != 1:
                raise ValueError('root_fixed_role_required')
            result = sample_native_status() if action == 'sample' else (maintain_telemetry_storage() if action == 'maintain' else read_telemetry_storage())
            if action == 'storage-check':
                return 0 if result['persist_enabled'] and load_config()['storage']['directory'] == '/var/log/qcl-negf-monitoring' else 1
        else:
            config = load_config()
            validate_tool(config['tools']['sudo'])
            authenticate(os.environ, os.getppid(), process_identity, config['tools']['sudo'],
                         config['reader_uid'] if action == 'read' else config['observer_uid'])
            if len(sys.argv) != 2:
                raise ValueError('fixed_token_required')
            query = decode_query(sys.argv[1])
            if action == 'read':
                from cluster_projection import read_cluster_projection
                result = read_cluster_projection(**{k: query[k] for k in ('request_id', 'cursor', 'limit')})
            elif action == 'observer':
                result = observe_local(query)
            else:
                raise ValueError('invalid_role')
        raw = json.dumps(result, separators=(',', ':'))
        if len(raw.encode()) > load_config()['bounds']['output_bytes']:
            raise ValueError('output_bound')
        print(raw)
        return 0
    except Exception as error:
        code = 'stale_cursor' if isinstance(error, ValueError) and str(error) == 'stale_cursor' else 'monitoring_unavailable'
        print(json.dumps(dict(schema='qcl.monitoring-error.v1', reason=code)), file=sys.stderr)
        return 1


def client_main(read_helper='/run/current-system/sw/bin/qcl-negf-monitor-read'):
    # Config and sudo path are protected, not caller-selected. No ambient env forwarded.
    if len(sys.argv) != 3 or sys.argv[1] != '--query-base64':
        raise SystemExit('fixed query required')
    token = encode_query(decode_query(sys.argv[2])); c = load_config()
    validate_tool(c['tools']['sudo'])
    os.execve(c['tools']['sudo'], [c['tools']['sudo'], '-n', '--', read_helper, token], {'PATH': '/run/current-system/sw/bin:/usr/bin:/bin'})


def ssh_main(helper='/run/current-system/sw/bin/qcl-negf-monitor-rpc', observer_helper='/run/current-system/sw/bin/qcl-negf-monitor-observer'):
    token = forced_command(os.environ.get('SSH_ORIGINAL_COMMAND', ''), helper=helper)
    c = load_config()
    validate_tool(c['tools']['sudo'])
    if os.getuid() != c['observer_uid']:
        raise ValueError('observer_uid_required')
    os.execve(c['tools']['sudo'], [c['tools']['sudo'], '-n', '--', observer_helper, token], {'PATH': '/run/current-system/sw/bin:/usr/bin:/bin'})
