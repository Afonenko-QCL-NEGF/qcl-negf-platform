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
import socket
import stat
import struct
import sys
import time
from urllib.parse import urlsplit

CONFIG = Path('/etc/qcl-negf/monitoring/service.json')
CACHE = Path('/run/qcl-negf-monitoring/latest.json')
SCHEMAS = Path(__file__).resolve().parents[1] / 'schemas'
IDENTIFIER = r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}'
PORTAL_CACHE_SOCKET = '/run/qcl-negf-monitoring-portal/read.sock'
PORTAL_CACHE_SERVER_UID = 0
PORTAL_CACHE_BYTES = 1048576
PORTAL_CACHE_SECONDS = 5


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
        allocation = storage['allocation']
        if storage['binding'] == 'preallocated_loop_linear_v1':
            if allocation is None or value['role'] != 'native_host' or storage['quota_project'] is not None:
                raise ValueError('invalid_allocation_role')
            mount = allocation['mount_path']
            files = [allocation[k] for k in ('data_dir','state_dir','reserve_file')]
            if (len(set(files)) != 3 or any(not p.startswith(mount+'/') or not canonical(p) or any(ch.isspace() for ch in p) for p in files) or
                    any(a.startswith(b+'/') for a in files for b in files if a != b) or
                    allocation['backing_file'].startswith(mount+'/') or storage['directory'] != allocation['data_dir'] or
                    allocation['maximum_bytes'] != storage['maximum_bytes'] or allocation['reserve_bytes'] >= allocation['maximum_bytes'] or
                    not allocation['physical_ids'] or not allocation['science_devices']):
                raise ValueError('invalid_allocation_scope')
            for k in ('backing_file','loop_device','mount_path'):
                if not canonical(allocation[k]) or any(ch.isspace() for ch in allocation[k]):
                    raise ValueError('invalid_allocation_path')
            for device in [allocation, *allocation['science_devices']]:
                if len(set(device['physical_ids'])) != len(device['physical_ids']) or not device['physical_ids']:
                    raise ValueError('invalid_physical_scope')
            if len({x['device'] for x in allocation['science_devices']}) != len(allocation['science_devices']):
                raise ValueError('duplicate_scientific_scope')
        elif allocation is not None:
            raise ValueError('unexpected_allocation')
        context = value['context']
        if context['enabled'] and (value['role'] != 'controller' or not context['cluster_id'] or not context['owner_uids']):
            raise ValueError('invalid_context_role')
        if len(set(context['owner_uids'])) != len(context['owner_uids']) or not canonical(context['slurm_conf']):
            raise ValueError('invalid_context_scope')
        units = value['scopes']['units']
        if units and value['role'] != 'native_host':
            raise ValueError('invalid_unit_role')
        if len({x['unit_id'] for x in units}) != len(units) or len({x['unit'] for x in units}) != len(units):
            raise ValueError('duplicate_unit_scope')
        vm_ids = {x['vm_id'] for x in value['scopes']['vms']}
        if any(x['vm_id'] is not None and x['vm_id'] not in vm_ids or not canonical(x['manager_executable']) for x in units):
            raise ValueError('invalid_unit_binding')
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
        if value['role'] == 'controller' and (value['scopes']['vms'] or value['scopes']['cgroups'] or value['scopes']['services'] or value['scopes']['journal'] or value['scopes']['units'] or value['scopes']['backend'] != 'disabled'):
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
        if set(value) != {'config_generation', 'native', 'services', 'journal_cursor', 'cgroups', 'storage', 'current_context', 'host_packets', 'sampler_boot_id'} or value['config_generation'] != digest(config):
            return None
        # Reuse the public shape validator: never relay arbitrary cache keys or text.
        from cluster_projection import validate_cluster_projection
        validate_cluster_projection(dict(schema='qcl.cluster-projection.v2', read_at=int(time.time()), status='ok',
            registry_generation=digest(config), hosts=[dict(host_id=config['scopes']['host_id'], resource=None,
            native=value['native'], services=value['services'], storage=value['storage'], graph_links=[], reasons=[])],
            complete=True, next_cursor=None, coverage=dict(sources=[], reasons=[]), current_context=value['current_context']))
        if not isinstance(value['host_packets'],list) or len(value['host_packets']) > 128:
            return None
        for host in value['host_packets']:
            if set(host) != {'host_id','fetched_at','pages'} or host['fetched_at'] is not None and type(host['fetched_at']) is not int or not isinstance(host['pages'],list) or len(host['pages']) > config['bounds']['retention_entries']:
                return None
            for page in host['pages']:
                if set(page) != {'cursor','packet'} or set(page['packet']) != {'resource','native','services','storage'}:
                    return None
                validate_cluster_projection(dict(schema='qcl.cluster-projection.v2',read_at=int(time.time()),status='ok',
                    registry_generation=digest(config),hosts=[dict(host_id=host['host_id'],**page['packet'],graph_links=[],reasons=[])],
                    complete=True,next_cursor=None,coverage=dict(sources=[],reasons=[]),current_context=None))
        return value
    except (OSError, ValueError, KeyError, TypeError):
        return None


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def unknown_storage(observed_at=None):
    return dict(schema='qcl.telemetry-storage.v2', status='unknown', binding_kind='unqualified',
                maximum_bytes=None, used_bytes=None, available_bytes=None, keep_free_bytes=None,
                inodes_available=None, retention_seconds=None, persist_permitted=False,
                observed_at=observed_at, allocation_bytes=None, allocated_reserve_bytes=None, science_charge_bytes=None,
                capacity_generation=None, collector_state='unknown', reasons=[reason('capacity_not_qualified', 'telemetry')])


from dataclasses import dataclass
import struct

FIEMAP_IOCTL = 0xC020660B
LOOP_GET_STATUS64 = 0x4C05
BLKGETSIZE64 = 0x80081272


@dataclass(frozen=True)
class NativeCapacityEvidence:
    status: str
    observed_at: int
    host_boot_id: str | None = None
    generation: str | None = None
    allocation_bytes: int | None = None
    allocated_reserve_bytes: int | None = None
    science_charge_bytes: int | None = None
    available_bytes: int | None = None
    available_inodes: int | None = None
    maximum_bytes: int | None = None
    used_bytes: int | None = None
    binding_identity: str | None = None
    collector_state: str = 'unknown'
    reasons: tuple = ()
    device: int | None = None


def _initialized_file(value, size):
    if (value['uid'] != 0 or value['mode'] != stat.S_IFREG | 0o600 or value['nlink'] != 1 or
            value['size'] != size or value['blocks'] * 512 < size or size < 4096 or size % 4096):
        raise ValueError('allocation_file_identity')
    raw = value['fiemap']
    start, length, flags, mapped, count, reserved = struct.unpack_from('=QQIIII', raw)
    if start != 0 or length != size or flags or reserved or count != 1024 or not 1 <= mapped <= count or len(raw) < 32+mapped*56:
        raise ValueError('allocation_extent_bound')
    end = 0; physical = []
    for i in range(mapped):
        logical, address, length, r1, r2, flags, r3, r4, r5 = struct.unpack_from('=QQQQQIIII', raw, 32+56*i)
        if logical != end or length <= 0 or flags != (1 if i == mapped-1 else 0) or any((r1,r2,r3,r4,r5)) or address % 4096 or length % 4096 or any(address < b and a < address+length for a,b in physical):
            raise ValueError('allocation_not_initialized')
        physical.append((address,address+length)); end += length
    if end < size:
        raise ValueError('allocation_hole')
    return {k:value[k] for k in ('device','inode','size','blocks','mode','uid','gid','nlink')}


def _dm_identity(node, vg, lv):
    if node['dm_uuid'] != 'LVM-'+vg.replace('-','')+lv.replace('-',''):
        raise ValueError('allocation_lv_identity')


def _physical_leaves(sources, device, *, linear_backing=False):
    nodes = {}; visiting = set()
    def walk(dev, depth):
        if depth > 16 or dev in visiting or len(nodes) >= 64:
            raise ValueError('allocation_topology_bound')
        if dev in nodes:
            return nodes[dev]
        visiting.add(dev)
        node = sources.block_node(dev)
        if linear_backing and depth > 0 and (node['dm_uuid'] or node['slaves']):
            raise ValueError('backing_graph_unsupported')
        children = node['slaves'] + ([node['parent']] if node['parent'] else [])
        if len(children) != len(set(children)):
            raise ValueError('allocation_topology_identity')
        if children:
            leaves = set().union(*(walk(child, depth+1) for child in children))
        elif not node['dm_uuid'] and isinstance(node['wwid'], str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,256}', node['wwid']):
            leaves = {'wwid:'+node['wwid']}
        else:
            raise ValueError('physical_identity_unknown')
        visiting.remove(dev); nodes[dev] = leaves
        return leaves
    return walk(str(os.major(device))+':'+str(os.minor(device)), 0)


def _collector_identity(properties, binding):
    required = dict(Id='vector.service',User='qcl-monitoring',Group='qcl-monitoring',
        ProtectSystem='strict',ProtectHome='yes',PrivateDevices='yes',NoNewPrivileges='yes',
        CapabilityBoundingSet='',StateDirectory='',LogsDirectory='',CacheDirectory='',RuntimeDirectory='',
        StandardOutput='null',StandardError='null',PrivateTmp='no',RootDirectory='',RootImage='',BindPaths='',BindReadOnlyPaths='',TemporaryFileSystem='')
    if any(properties.get(k) != v for k,v in required.items()) or set(properties.get('ReadWritePaths','').split()) != {binding['data_dir'], binding['state_dir']}:
        raise ValueError('collector_binding_unverified')
    return 'active' if properties.get('ActiveState') == 'active' else ('inactive' if properties.get('ActiveState') in ('inactive','failed') else 'unknown')


def read_native_capacity(binding, sources, *, now):
    """Actual native reader output is assembled here; no config boolean can qualify a binding."""
    try:
        boot = sources.read('/proc/sys/kernel/random/boot_id').strip()
        before = sources.allocation_file(binding['backing_file'])
        identity = _initialized_file(before, binding['maximum_bytes'])
        host = sources.backing_mount(binding['backing_file'])
        if host['device'] != before['device'] or host['fstype'] != 'ext4' or host['available_bytes'] < binding['host_keep_free_bytes']:
            raise ValueError('host_capacity_or_backing')
        loop, block_size, loop_device = sources.loop_status(binding['loop_device'])
        device, inode, rdevice, offset, size, number, encryption, key_size, flags = struct.unpack_from('=QQQQQIIII',loop)
        if (device != identity['device'] or inode != identity['inode'] or offset != 0 or size != binding['maximum_bytes'] or
                block_size != size or os.major(loop_device) != 7 or number != os.minor(loop_device) or encryption or key_size or flags & ~16):
            raise ValueError('loop_binding_identity')
        mount = sources.mount_metadata(binding['mount_path'])
        if mount['device'] != loop_device or mount['root'] != '/' or mount['fstype'] != 'ext4' or mount['uuid'] != binding['filesystem_uuid'] or not 0 < mount['blocks']*mount['frsize'] <= size or mount['inodes'] <= 0:
            raise ValueError('loop_mount_identity')
        uid, gid = sources.writer_identity()
        if uid <= 0 or gid <= 0:
            raise ValueError('collector_binding_unverified')
        for path in (binding['data_dir'], binding['state_dir']):
            meta = sources.directory_metadata(path)
            if meta != dict(device=mount['device'],uid=0,gid=gid,mode=stat.S_IFDIR | 0o770):
                raise ValueError('collector_directory_identity')
        reserve_parent = sources.directory_metadata(str(Path(binding['reserve_file']).parent))
        if reserve_parent != dict(device=mount['device'],uid=0,gid=0,mode=stat.S_IFDIR | 0o700):
            raise ValueError('reserve_directory_identity')
        reserve = sources.allocation_file(binding['reserve_file'])
        reserve_identity = _initialized_file(reserve,binding['reserve_bytes'])
        if reserve['device'] != mount['device']:
            raise ValueError('reserve_not_in_allocation')
        root_dev = str(os.major(before['device']))+':'+str(os.minor(before['device']))
        _dm_identity(sources.block_node(root_dev),binding['backing_vg_uuid'],binding['backing_lv_uuid'])
        fields = 'lv_uuid,vg_uuid,segtype,pool_lv,origin,lv_size,lv_attr,devices'
        raw = sources.run([sources.config['tools']['lvs'], 'lvs', '--readonly', '--nohints', '--segments', '--units', 'b', '--nosuffix',
            '--reportformat', 'json', '--options', fields, '--select', 'lv_uuid='+binding['backing_lv_uuid']], output_bytes=16384)
        packet = unique_json(raw)
        rows = packet['report'][0]['lv']
        if len(packet['report']) != 1 or not 1 <= len(rows) <= 64 or packet.get('log') not in (None,[]):
            raise ValueError('allocation_lvm_bound')
        for row in rows:
            if (row['lv_uuid'] != binding['backing_lv_uuid'] or row['vg_uuid'] != binding['backing_vg_uuid'] or
                    row['segtype'] != 'linear' or row['origin'] or row['pool_lv'] or
                    not re.fullmatch(r'[0-9]+',row['lv_size']) or int(row['lv_size']) < size or
                    not re.fullmatch(r'-wi-a[o-]----',row['lv_attr']) or not row['devices']):
                raise ValueError('allocation_not_linear')
        leaves = _physical_leaves(sources,before['device'],linear_backing=True)
        if leaves != set(binding['physical_ids']) or not binding['science_devices']:
            raise ValueError('physical_identity_unknown')
        for science in binding['science_devices']:
            dev = str(os.major(science['device']))+':'+str(os.minor(science['device']))
            _dm_identity(sources.block_node(dev),science['vg_uuid'],science['lv_uuid'])
            protected = _physical_leaves(sources,science['device'])
            if protected != set(science['physical_ids']) or leaves & protected:
                raise ValueError('scientific_backing_not_independent')
        state = _collector_identity(sources.collector_properties(),binding)
        if (sources.allocation_file(binding['backing_file']) != before or
                sources.allocation_file(binding['reserve_file']) != reserve or
                sources.loop_status(binding['loop_device']) != (loop,block_size,loop_device) or
                {k:v for k,v in sources.mount_metadata(binding['mount_path']).items() if k not in ('bfree','bavail','favail')} !=
                {k:v for k,v in mount.items() if k not in ('bfree','bavail','favail')} or
                sources.read('/proc/sys/kernel/random/boot_id').strip() != boot or
                _physical_leaves(sources,before['device'],linear_backing=True) != leaves):
            raise ValueError('allocation_changed')
        maximum = mount['blocks']*mount['frsize']
        available = mount['bavail']*mount['frsize']; used = (mount['blocks']-mount['bfree'])*mount['frsize']
        if not 0 <= available <= maximum or not 0 <= used <= maximum or mount['favail'] < 0:
            raise ValueError('allocation_capacity_inconsistent')
        generation = digest(dict(boot=boot, file=identity, reserve=reserve_identity, loop=loop.hex(),
            mount={k:v for k,v in mount.items() if k not in ('bfree','bavail','favail')}, physical=sorted(leaves)))
        return NativeCapacityEvidence('qualified',now,boot,generation,size,binding['reserve_bytes'],0,available,mount['favail'],maximum,used,generation,state,device=loop_device)
    except Exception as error:
        # Only these owned fixed codes may escape. Native failure text/paths never do.
        safe = {'allocation_file_identity','allocation_extent_bound','allocation_not_initialized','allocation_hole',
            'allocation_lv_identity','allocation_topology_bound','allocation_topology_identity','physical_identity_unknown',
            'backing_graph_unsupported','collector_binding_unverified','host_capacity_or_backing','loop_binding_identity',
            'loop_mount_identity','collector_directory_identity','reserve_directory_identity','reserve_not_in_allocation',
            'allocation_lvm_bound','allocation_not_linear','scientific_backing_not_independent','allocation_changed',
            'allocation_capacity_inconsistent','allocation_submount','allocation_mount_identity',
            'allocation_device_identity','allocation_filesystem_unsupported','block_graph_incomplete','sample_budget'}
        code = str(error) if type(error) is ValueError and str(error) in safe else 'native_capacity_unverified'
        return NativeCapacityEvidence('unknown',now,reasons=(code,))

class StorageBoundary:
    """Only the installed native typed producer can enable persistence/pruning."""
    def __init__(self, config, *, clock=time.time, observe=None, owner_uid=0, sources=None):
        self.config, self.clock, self.owner_uid = config, clock, owner_uid
        self.sources = sources
        self.observe = observe or self._observe

    def _observe(self):
        if self.config['storage']['binding'] != 'preallocated_loop_linear_v1':
            raise ValueError('capacity_binding_unsupported')
        return read_native_capacity(self.config['storage']['allocation'],
            self.sources or NativeSources(self.config), now=int(self.clock()))

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
        c = self.config['storage']; now = int(self.clock()); view = unknown_storage(now)
        view.update(binding_kind=c['binding'], keep_free_bytes=c['keep_free_bytes'], retention_seconds=c['retention_seconds'])
        if c['binding'] == 'unqualified':
            return view
        if c['binding'] != 'preallocated_loop_linear_v1':
            view.update(status='unsupported',reasons=[reason('capacity_binding_unsupported','telemetry')])
            return view
        try:
            proof = self.observe()
            checked_at = int(self.clock())
            if not isinstance(proof,NativeCapacityEvidence):
                return view
            view['observed_at'] = proof.observed_at
            if proof.status != 'qualified':
                view['reasons'] = [reason(code,'telemetry') for code in proof.reasons or ('native_capacity_unverified',)]
                return view
            # Native observation may consume the whole TTL or span a wall-clock change.
            code = ('clock_rollback' if checked_at < now else
                    'clock_future' if proof.observed_at > checked_at else
                    'capacity_stale' if checked_at-proof.observed_at > self.config['bounds']['fresh_seconds'] else None)
            if code:
                view['reasons'] = [reason(code,'telemetry')]
                return view
            if (not proof.generation or proof.maximum_bytes is None or proof.maximum_bytes > c['maximum_bytes'] or
                    proof.device != c['device'] or proof.allocation_bytes != c['allocation']['maximum_bytes'] or
                    proof.allocated_reserve_bytes < c['allocation']['reserve_bytes'] or proof.science_charge_bytes != 0):
                return view
            view.update(maximum_bytes=proof.maximum_bytes,used_bytes=proof.used_bytes,available_bytes=proof.available_bytes,
                inodes_available=proof.available_inodes,observed_at=proof.observed_at,allocation_bytes=proof.allocation_bytes,
                allocated_reserve_bytes=proof.allocated_reserve_bytes,science_charge_bytes=proof.science_charge_bytes,
                capacity_generation=proof.generation,collector_state=proof.collector_state,status='qualified',reasons=[])
            view['persist_permitted'] = proof.available_bytes >= c['keep_free_bytes'] and proof.available_inodes >= c['minimum_inodes']
            if not view['persist_permitted']:
                view.update(status='degraded',reasons=[reason('reserve_threshold','telemetry')])
        except (OSError,ValueError,TypeError,KeyError):
            pass
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
        if not view['persist_permitted']:
            return view
        c = self.config['storage']; now = int(self.clock()); rejected = False
        deadline = time.monotonic() + self.config['bounds']['command_seconds']
        # Fixed owning scope, finite enumeration; retain current UTC day, reject all symlinks.
        fd = self._directory()
        try:
            root = os.fstat(fd)
            if root.st_uid != self.owner_uid:
                return {**view, 'status': 'unknown', 'persist_permitted': False, 'reasons': [reason('untrusted_storage', 'telemetry')]}
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

    def run(self, argv, output_bytes=None, *, env=None, deadline=None):
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
                             deadline=min(self.deadline, deadline) if deadline is not None else self.deadline,
                             env=env if env is not None else {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
        except CommandFailure as error:
            self.bytes += _failure_size(error.record, bound)
            raise  # preserve the owning failure/record; no partial stdout is accepted
        self.bytes += _command_size(output, bound)
        return output

    def _metadata_budget(self, size):
        if time.monotonic() >= self.deadline or size < 0 or self.bytes+size > self.config['bounds']['output_bytes']:
            raise ValueError('sample_budget')
        self.bytes += size

    def allocation_file(self, path):
        import fcntl
        from release_trust import protected_directory
        with protected_directory(Path(path).parent) as parent:
            fd = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode != stat.S_IFREG | 0o600 or before.st_nlink != 1 or before.st_size < 4096:
                raise ValueError('allocation_file_identity')
            self._metadata_budget(32+56*1024)
            data = bytearray(32+56*1024)
            struct.pack_into('=QQIIII',data,0,0,before.st_size,0,0,1024,0)
            fcntl.ioctl(fd,FIEMAP_IOCTL,data,True)  # flags=0: no sync, no setter, no payload read
            after = os.fstat(fd)
            names = ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_blocks')
            if any(getattr(before,k) != getattr(after,k) for k in names):
                raise ValueError('allocation_changed')
            mapped = struct.unpack_from('=I',data,20)[0]
            if mapped > 1024:
                raise ValueError('allocation_extent_bound')
            return dict(device=before.st_dev,inode=before.st_ino,uid=before.st_uid,gid=before.st_gid,
                mode=before.st_mode,nlink=before.st_nlink,size=before.st_size,blocks=before.st_blocks,
                fiemap=bytes(data[:32+56*mapped]))
        finally:
            os.close(fd)

    def loop_status(self, path):
        import fcntl
        fd = os.open(path,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISBLK(info.st_mode) or os.major(info.st_rdev) != 7:
                raise ValueError('loop_not_block_device')
            self._metadata_budget(240)
            data = bytearray(232); size = bytearray(8)
            fcntl.ioctl(fd,LOOP_GET_STATUS64,data,True)
            fcntl.ioctl(fd,BLKGETSIZE64,size,True)
            if struct.unpack_from('=I',data,40)[0] != os.minor(info.st_rdev):
                raise ValueError('loop_device_number_mismatch')
            return bytes(data),struct.unpack('=Q',size)[0],info.st_rdev
        finally:
            os.close(fd)

    def directory_metadata(self, path):
        from release_trust import protected_directory
        with protected_directory(Path(path).parent) as parent:
            fd = os.open(Path(path).name,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,dir_fd=parent)
        try:
            self._metadata_budget(128); info = os.fstat(fd)
            return dict(device=info.st_dev,uid=info.st_uid,gid=info.st_gid,mode=info.st_mode)
        finally:
            os.close(fd)

    def mount_metadata(self, path):
        from release_trust import protected_directory
        with protected_directory(path) as fd:
            info = os.fstat(fd); fs = os.fstatvfs(fd)
        lines = self.read('/proc/self/mountinfo',65536).splitlines()
        selected = []
        for line in lines:
            left,right = line.split(' - ',1); a,b = left.split(),right.split()
            if a[4] == path:
                selected.append((a,b))
            elif a[4].startswith(path+'/'):
                raise ValueError('allocation_submount')
        if len(selected) != 1:
            raise ValueError('allocation_mount_identity')
        a,b = selected[0]
        if a[2] != str(os.major(info.st_dev))+':'+str(os.minor(info.st_dev)) or a[3] != '/' or b[0] != 'ext4' or 'discard' in (a[5]+','+b[2]).split(',') or not canonical(b[1]):
            raise ValueError('allocation_mount_identity')
        fd = os.open(b[1],os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            if not stat.S_ISBLK(os.fstat(fd).st_mode) or os.fstat(fd).st_rdev != info.st_dev:
                raise ValueError('allocation_device_identity')
            self._metadata_budget(1024)
            raw = os.pread(fd,1024,1024)  # selected technical ext4 superblock only, no file payload
        finally:
            os.close(fd)
        if len(raw) != 1024 or struct.unpack_from('<H',raw,0x38)[0] != 0xEF53 or struct.unpack_from('<I',raw,0x64)[0] & 0x200:
            raise ValueError('allocation_filesystem_unsupported')
        import uuid
        return dict(device=info.st_dev,root=a[3],fstype=b[0],uuid=str(uuid.UUID(bytes=raw[0x68:0x78])),
            blocks=fs.f_blocks,frsize=fs.f_frsize,bfree=fs.f_bfree,bavail=fs.f_bavail,favail=fs.f_favail,inodes=fs.f_files)

    def backing_mount(self, path):
        from release_trust import protected_directory
        with protected_directory(Path(path).parent) as fd:
            info = os.fstat(fd); fs = os.fstatvfs(fd)
        selected = []
        for line in self.read('/proc/self/mountinfo',65536).splitlines():
            left,right = line.split(' - ',1); a,b = left.split(),right.split()
            if path.startswith(a[4].rstrip('/')+'/') and a[2] == str(os.major(info.st_dev))+':'+str(os.minor(info.st_dev)):
                selected.append((len(a[4]),b[0]))
        if not selected:
            raise ValueError('backing_mount_unknown')
        return dict(device=info.st_dev,fstype=max(selected)[1],available_bytes=fs.f_bavail*fs.f_frsize)

    def block_node(self, dev):
        if not re.fullmatch(r'[0-9]+:[0-9]+',dev):
            raise ValueError('invalid_block_device')
        self._metadata_budget(256)
        path = Path('/sys/dev/block',dev).resolve(strict=True)
        if not str(path).startswith('/sys/devices/') or self.read(str(path/'dev'),64).strip() != dev:
            raise ValueError('block_device_identity')
        slaves = []
        if (path/'slaves').exists():
            with os.scandir(path/'slaves') as items:
                for index,item in enumerate(items):
                    if index >= 64:
                        raise ValueError('block_graph_bound')
                    target = Path(item.path).resolve(strict=True)
                    if not str(target).startswith('/sys/devices/'):
                        raise ValueError('block_graph_identity')
                    slaves.append(self.read(str(target/'dev'),64).strip())
        elif not (path/'partition').exists():
            raise ValueError('block_graph_incomplete')
        parent = self.read(str(path.parent/'dev'),64).strip() if (path/'partition').exists() else None
        wwid = None
        for name in ('wwid','device/wwid'):
            target = path/name
            if target.exists():
                wwid = self.read(str(target.resolve(strict=True)),512).strip(); break
        dm = self.read(str(path/'dm/uuid'),256).strip() if (path/'dm/uuid').exists() else None
        return dict(slaves=sorted(slaves),parent=parent,wwid=wwid,dm_uuid=dm)

    def trusted_config_identity(self, path):
        from release_trust import protected_directory, trusted_stat
        with protected_directory(Path(path).parent) as parent:
            fd = os.open(Path(path).name,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,dir_fd=parent)
        try:
            info = os.fstat(fd); trusted_stat(info,directory=False)
            self._metadata_budget(128)
            return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
        finally:
            os.close(fd)

    def writer_identity(self):
        user = pwd.getpwnam('qcl-monitoring'); group = grp.getgrnam('qcl-monitoring')
        return user.pw_uid,group.gr_gid

    def collector_properties(self):
        keys = 'Id,User,Group,ProtectSystem,ProtectHome,PrivateDevices,NoNewPrivileges,CapabilityBoundingSet,ReadWritePaths,StateDirectory,LogsDirectory,CacheDirectory,RuntimeDirectory,StandardOutput,StandardError,ActiveState,PrivateTmp,RootDirectory,RootImage,BindPaths,BindReadOnlyPaths,TemporaryFileSystem'
        raw = self.run([self.config['tools']['systemctl'],'show','--no-pager','--property='+keys,'--','vector.service'],output_bytes=8192)
        fields = {}
        for line in raw.splitlines():
            key,value = line.split('=',1)
            if key in fields or key not in keys.split(','):
                raise ValueError('collector_properties_invalid')
            fields[key] = value
        if set(fields) != set(keys.split(',')):
            raise ValueError('collector_properties_incomplete')
        return fields

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


def _guard_collector(config, sources, view):
    if config['storage']['binding'] != 'preallocated_loop_linear_v1' or view['persist_permitted']:
        return view
    try:
        properties = sources.collector_properties()
        state = _collector_identity(properties,config['storage']['allocation'])
        view['collector_state'] = state
        if state == 'active':
            sources.run([config['tools']['systemctl'],'stop','--no-block','--','vector.service'],output_bytes=4096)
            view['collector_state'] = _collector_identity(sources.collector_properties(),config['storage']['allocation'])
    except Exception:
        view['collector_state'] = 'unknown'
    return view


def _fetch_host_packets(config, sources):
    packets = []
    for target in config['targets']:
        host = dict(host_id=target['host_id'],fetched_at=None,pages=[])
        cursor = None; identity = None
        for _ in range(config['bounds']['retention_entries']):
            if time.monotonic() >= sources.deadline:
                break
            try:
                packet = observe_remote(target,dict(schema='qcl.cluster-query.v1',request_id=None,cursor=cursor,limit=64),sources=sources)
                from cluster_projection import validate_cluster_projection
                validate_cluster_projection(dict(schema='qcl.cluster-projection.v2',read_at=int(time.time()),status='ok',
                    registry_generation=digest(config),hosts=[dict(host_id=host['host_id'],**packet,graph_links=[],reasons=[])],
                    complete=True,next_cursor=None,coverage=dict(sources=[],reasons=[]),current_context=None))
                native,resource = packet['native'],packet['resource']
                if native is not None and native['host_id'] != host['host_id'] or resource is not None and resource['host'] is not None and resource['host']['host_id'] != host['host_id']:
                    raise ValueError('cached_host_identity')
                current = ((native or {}).get('host_boot_id'),(native or {}).get('sample_generation'),(resource or {}).get('state_generation'))
                if identity is not None and current != identity:
                    break
                identity = current
                host['pages'].append(dict(cursor=cursor,packet=packet))
                host['fetched_at'] = int(time.time())
                if len(json.dumps(packets+[host]).encode()) > config['bounds']['output_bytes']//2:
                    host['pages'].pop(); break
                if resource is None or resource['complete']:
                    break
                cursor = resource['next_cursor']
                if cursor is None or any(p['cursor'] == cursor for p in host['pages']):
                    break
            except Exception:
                break
        packets.append(host)
    return packets


def sample_native_status():
    if os.geteuid() != 0:
        raise ValueError('root_sampler_required')
    config = load_config(); sources = NativeSources(config); previous = read_cache(config)
    from native_monitoring import NativeSampler,empty_native
    from slurm_context import sample_current_context,empty_context
    if config['role'] == 'controller':
        boot = sources.read('/proc/sys/kernel/random/boot_id').strip()
        if sources.read('/etc/machine-id').strip() != config['scopes']['machine_id']:
            raise ValueError('controller_identity_mismatch')
        current = sample_current_context(config,sources,previous['current_context'] if previous else None,now=int(time.time()))
        sample = dict(native=empty_native(config['scopes']['host_id']),services=[])
        value = dict(config_generation=digest(config),**sample,journal_cursor=None,cgroups={},
            storage=unknown_storage(),current_context=current,host_packets=_fetch_host_packets(config,sources),sampler_boot_id=boot)
        if sources.read('/proc/sys/kernel/random/boot_id').strip() != boot:
            raise ValueError('controller_boot_changed')
    else:
        sampler = NativeSampler(config,sources,previous=previous)
        sample = sampler.sample()
        storage = _guard_collector(config,sources,StorageBoundary(config,sources=sources).read())
        value = dict(config_generation=digest(config),**sample,journal_cursor=getattr(sampler,'journal_cursor',None),
            cgroups=getattr(sampler,'cgroups',{}),storage=storage,current_context=empty_context(config),host_packets=[],sampler_boot_id=sample['native']['host_boot_id'])
    from cluster_projection import validate_cluster_projection
    validate_cluster_projection(dict(schema='qcl.cluster-projection.v2',read_at=int(time.time()),status='ok',
        registry_generation=digest(config),hosts=[dict(host_id=config['scopes']['host_id'],
        resource=None,native=sample['native'],services=sample['services'],storage=value['storage'],graph_links=[],reasons=[])],
        complete=True,next_cursor=None,coverage=dict(sources=[],reasons=[]),current_context=value['current_context']))
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
    config = load_config(); cache = read_cache(config)
    return _normalize_observer_packet(dict(native=None,services=[],storage=cache['storage'] if cache else unknown_storage()),
        now=int(time.time()),fresh_seconds=config['bounds']['fresh_seconds'])['storage']


def maintain_telemetry_storage():
    if os.geteuid() != 0:
        raise ValueError('root_maintenance_required')
    config = load_config(); sources = NativeSources(config)
    return _guard_collector(config,sources,StorageBoundary(config,sources=sources).maintain())


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
            storage.update(status='unknown', persist_permitted=False)
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


def observe_remote(target, query, *, sources=None):
    from application_release import ssh, command, CommandFailure
    from release_trust import read_protected_file
    config = load_config()
    known = read_protected_file(target['known_hosts'])
    key = read_protected_file(target['identity_file'])
    snapshot = dict(path=target['known_hosts'], sha256=hashlib.sha256(known).hexdigest())
    def run(argv):
        # P11 fixed transport options, explicit private key, no ambient agent/env.
        bound = config['bounds']['output_bytes'] if sources is None else config['bounds']['output_bytes']-sources.bytes
        if bound < 1 or sources is not None and time.monotonic() >= sources.deadline:
            raise ValueError('sample_budget')
        try:
            output = command([argv[0], '-i', target['identity_file'], '-oIdentitiesOnly=yes',
                              '-oForwardAgent=no', '-oClearAllForwardings=yes', '-oRequestTTY=no', *argv[1:]],
                timeout_seconds=config['bounds']['command_seconds'], output_bytes=bound,
                deadline=sources.deadline if sources is not None else None,
                env={'PATH': '/run/current-system/sw/bin:/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
        except CommandFailure as failure:
            record = failure.record
            if sources is not None:
                sources.bytes += _failure_size(record,bound)
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
        size = _command_size(output, bound)
        if sources is not None:
            sources.bytes += size
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
            result = sample_native_status() if action == 'sample' else (maintain_telemetry_storage() if action == 'maintain' else StorageBoundary(load_config()).read())
            if action == 'storage-check':
                return 0 if result['persist_permitted'] else 1
        else:
            config = load_config()
            validate_tool(config['tools']['sudo'])
            authenticate(os.environ, os.getppid(), process_identity, config['tools']['sudo'],
                         config['reader_uid'] if action in ('read','context') else config['observer_uid'])
            if len(sys.argv) != 2:
                raise ValueError('fixed_token_required')
            query = decode_query(sys.argv[1])
            if action == 'read':
                from cluster_projection import read_cluster_projection
                result = read_cluster_projection(**{k: query[k] for k in ('request_id', 'cursor', 'limit')})
            elif action == 'context':
                if config['role'] != 'controller' or query['request_id'] is not None:
                    raise ValueError('context_controller_query_required')
                from slurm_context import read_current_context
                result = read_current_context(cursor=query['cursor'],limit=query['limit'])
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


def _portal_timeout(connection, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError('monitoring_unavailable')
    connection.settimeout(remaining)


def _portal_frame(connection, limit, deadline):
    raw = bytearray()
    while True:
        _portal_timeout(connection, deadline)
        chunk = connection.recv(min(4096, limit + 1 - len(raw)))
        if not chunk:
            break
        raw.extend(chunk)
        if len(raw) > limit:
            raise ValueError('monitoring_unavailable')
    if not raw.endswith(b'\n') or raw.count(b'\n') != 1:
        raise ValueError('monitoring_unavailable')
    return bytes(raw[:-1])


def _portal_query(token):
    query = decode_query(token)
    if query['request_id'] is not None:
        raise ValueError('monitoring_unavailable')
    # Bound the complete encoded query, including a potentially large cursor.
    return query, encode_query(query)


def _portal_error(error):
    code = 'stale_cursor' if isinstance(error, ValueError) and str(error) == 'stale_cursor' else 'monitoring_unavailable'
    return dict(schema='qcl.monitoring-error.v1', reason=code)


def portal_cache_handle(connection):
    """One authenticated cache-only query on an accepted local socket."""
    deadline = time.monotonic() + PORTAL_CACHE_SECONDS
    try:
        _portal_timeout(connection, deadline)
        if connection.family != socket.AF_UNIX:
            raise ValueError('monitoring_unavailable')
        _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        expected = pwd.getpwnam('qcl-negf').pw_uid
        if expected <= 0 or uid != expected:
            raise ValueError('monitoring_unavailable')
        token = _portal_frame(connection, 8193, deadline).decode('ascii')
        query, _ = _portal_query(token)
        _portal_timeout(connection, deadline)
        from cluster_projection import read_cluster_projection, validate_cluster_projection
        result = read_cluster_projection(request_id=None, cursor=query['cursor'], limit=query['limit'])
        _portal_timeout(connection, deadline)
        validate_cluster_projection(result)
        raw = json.dumps(result, separators=(',', ':'), allow_nan=False).encode('utf-8')
        if len(raw) > PORTAL_CACHE_BYTES:
            raise ValueError('monitoring_unavailable')
    except Exception as error:
        raw = json.dumps(_portal_error(error), separators=(',', ':')).encode('ascii')
    try:
        _portal_timeout(connection, deadline)
        connection.sendall(raw + b'\n')
    except (OSError, ValueError):
        # Timeout/disconnection cannot make a partial frame successful.
        pass


def portal_cache_server_main():
    if os.geteuid() != 0 or len(sys.argv) != 1:
        return 1
    with socket.socket(fileno=os.dup(0)) as connection:
        portal_cache_handle(connection)
    return 0


def portal_cache_decode_response(raw):
    if len(raw) > PORTAL_CACHE_BYTES + 1 or not raw.endswith(b'\n') or raw.count(b'\n') != 1:
        raise ValueError('monitoring_unavailable')
    result = unique_json(raw[:-1])
    if (isinstance(result, dict) and set(result) == {'schema', 'reason'}
            and result['schema'] == 'qcl.monitoring-error.v1'
            and result['reason'] in ('stale_cursor', 'monitoring_unavailable')):
        raise ValueError(result['reason'])
    from cluster_projection import validate_cluster_projection
    return validate_cluster_projection(result)


def portal_cache_query(token):
    """Nonprivileged fixed-socket client; never reads private config/cache."""
    _, token = _portal_query(token)
    deadline = time.monotonic() + PORTAL_CACHE_SECONDS
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        _portal_timeout(connection, deadline)
        connection.connect(PORTAL_CACHE_SOCKET)
        _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != PORTAL_CACHE_SERVER_UID:
            raise ValueError('monitoring_unavailable')
        _portal_timeout(connection, deadline)
        connection.sendall(token.encode('ascii') + b'\n')
        connection.shutdown(socket.SHUT_WR)
        raw = _portal_frame(connection, PORTAL_CACHE_BYTES + 1, deadline) + b'\n'
        _portal_timeout(connection, deadline)
        result = portal_cache_decode_response(raw)
        _portal_timeout(connection, deadline)
        return result


def portal_cache_client_main():
    try:
        if len(sys.argv) != 3 or sys.argv[1] != '--query-base64':
            raise ValueError('monitoring_unavailable')
        result = portal_cache_query(sys.argv[2])
        raw = json.dumps(result, separators=(',', ':'), allow_nan=False)
        if len(raw.encode('utf-8')) > PORTAL_CACHE_BYTES:
            raise ValueError('monitoring_unavailable')
        print(raw)
        return 0
    except Exception as error:
        print(json.dumps(_portal_error(error), separators=(',', ':')), file=sys.stderr)
        return 1


def ssh_main(helper='/run/current-system/sw/bin/qcl-negf-monitor-rpc', observer_helper='/run/current-system/sw/bin/qcl-negf-monitor-observer'):
    token = forced_command(os.environ.get('SSH_ORIGINAL_COMMAND', ''), helper=helper)
    c = load_config()
    validate_tool(c['tools']['sudo'])
    if os.getuid() != c['observer_uid']:
        raise ValueError('observer_uid_required')
    os.execve(c['tools']['sudo'], [c['tools']['sudo'], '-n', '--', observer_helper, token], {'PATH': '/run/current-system/sw/bin:/usr/bin:/bin'})
