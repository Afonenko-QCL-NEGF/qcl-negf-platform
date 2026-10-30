"""Closed native/trust/storage fixtures, never invoke a host command."""
import copy
import importlib
import json
import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / 'ops'))


def module(name):
    assert (ROOT / 'ops' / (name + '.py')).exists(), 'missing P31 owner: ' + name
    return importlib.import_module(name)


def config(role='native_host'):
    return {'schema': 'qcl.monitoring-config.v2', 'role': role,
        'reader_uid': 2001, 'observer_uid': 2002,
        'tools': {'sudo': '/usr/bin/sudo', 'systemctl': '/usr/bin/systemctl',
                  'journalctl': '/usr/bin/journalctl', 'pvesh': '/usr/bin/pvesh',
                  'virsh': '/usr/bin/virsh','lvs':'/usr/sbin/lvm','squeue':'/usr/bin/squeue','scontrol':'/usr/bin/scontrol'},
        'targets': [],
        'scopes': {'host_id': 'host-a', 'machine_id': '1' * 32, 'backend': 'disabled',
                   'node': None, 'version': None, 'vms': [], 'services': [],
                   'cgroups': [], 'journal': False,'units':[],'manager_version':None},
        'bounds': {'command_seconds': 5, 'sample_seconds': 15, 'fresh_seconds': 10,
                   'output_bytes': 524288, 'journal_bytes': 131072, 'journal_events': 64,
                   'lookback_seconds': 60, 'retention_entries': 128},
        'storage': {'binding': 'unqualified', 'directory': '/var/log/qcl-negf-monitoring',
                    'maximum_bytes': None, 'keep_free_bytes': 1048576, 'retention_seconds': 604800,
                    'minimum_inodes': 16, 'device': None, 'quota_project': None,'allocation':None},
        'context':dict(enabled=False,cluster_id=None,owner_uids=[],slurm_conf='/etc/slurm/slurm.conf',version_profile='25.11.8'),
        'graph_links': []}


def test_unknown_storage_never_deletes_or_disables_read_projection(tmp_path):
    m = module('monitoring_runtime')
    value = config()
    value['storage']['directory'] = str(tmp_path)
    sentinel = tmp_path / 'unrelated.log'
    sentinel.write_text('preserve')
    view = m.StorageBoundary(value, clock=lambda: 100).read()
    assert view['status'] == 'unknown' and view['persist_permitted'] is False
    assert m.StorageBoundary(value, clock=lambda: 100).maintain()['persist_permitted'] is False
    assert sentinel.read_text() == 'preserve'


def test_config_and_fixed_transport_reject_untrusted_inputs():
    m = module('monitoring_runtime')
    assert m.validate_config(config())['role'] == 'native_host'
    for mutate in [lambda c: c.update(reader_uid=0),
                   lambda c: c.update(observer_uid=c['reader_uid']),
                   lambda c: c['tools'].update(sudo='/tmp/../sudo'),
                   lambda c: c.update(path='/private/ledger'),
                   lambda c: c['graph_links'].append({'host_id': 'host-a', 'label': 'PVE',
                       'href': 'https://user:password@example.invalid/', 'origin': 'https://example.invalid'})]:
        broken = copy.deepcopy(config()); mutate(broken)
        with pytest.raises(ValueError): m.validate_config(broken)
    good = m.encode_query({'schema': 'qcl.cluster-query.v1', 'request_id': None, 'cursor': None, 'limit': 64})
    assert m.decode_query(good)['limit'] == 64
    for token in [';', 'A' * 12000, m.encode_token({'schema': 'qcl.cluster-query.v1', 'path': '/secret'})]:
        with pytest.raises(ValueError): m.decode_query(token)
    assert m.forced_command('/helper/qcl-negf-monitor-rpc observe ' + good,
                            helper='/helper/qcl-negf-monitor-rpc') == good
    with pytest.raises(ValueError): m.forced_command('/helper/qcl-negf-monitor-rpc sample ' + good,
                                                    helper='/helper/qcl-negf-monitor-rpc')


def test_sudo_environment_does_not_authorize_without_actual_parent_chain():
    m = module('monitoring_runtime')
    caller = {'pid': 11, 'ppid': 1, 'uids': [2001] * 4, 'start_ticks': 10,
              'cgroup': '/user.slice/session.scope', 'executable': '/usr/bin/client'}
    sudo = {'pid': 12, 'ppid': 11, 'uids': [2001, 0, 0, 0], 'start_ticks': 11,
            'cgroup': caller['cgroup'], 'executable': '/usr/bin/sudo'}
    records = {11: caller, 12: sudo}
    assert m.authenticate({'SUDO_UID': '2001'}, 12, records.__getitem__, '/usr/bin/sudo', 2001) == caller
    with pytest.raises(ValueError): m.authenticate({'SUDO_UID': '2001'}, 11, records.__getitem__, '/usr/bin/sudo', 2001)
    with pytest.raises(ValueError): m.authenticate({'SUDO_UID': '2002'}, 12, records.__getitem__, '/usr/bin/sudo', 2001)


def test_scoped_retention_only_removes_closed_owned_ndjson(tmp_path):
    m = module('monitoring_runtime')
    value = allocation_config(); value['storage'].update(directory=str(tmp_path), binding='preallocated_loop_linear_v1',
        maximum_bytes=1048576, device=7, keep_free_bytes=100, retention_seconds=10, minimum_inodes=1)
    old = tmp_path / 'events-1970-01-01.ndjson'; old.write_text('old'); os.utime(old, (1, 1))
    foreign = tmp_path / 'foreign.log'; foreign.write_text('untouched')
    link = tmp_path / 'events-1970-01-02.ndjson'; link.symlink_to(foreign)
    facts = m.NativeCapacityEvidence('qualified',172900,'boot','gen',1048576,65536,0,9000,100,1048576,1000,'identity','inactive',device=7)
    store = m.StorageBoundary(value, clock=lambda: 172900, observe=lambda: facts, owner_uid=os.getuid())
    assert store.read()['persist_permitted'] is True
    result = store.maintain()
    assert not old.exists() and foreign.read_text() == 'untouched' and link.is_symlink()
    assert result['status'] == 'degraded'  # rejected link is visible, never followed
    from dataclasses import replace
    facts = replace(facts,available_bytes=0)
    assert store.read()['persist_permitted'] is False


def test_same_statvfs_shape_is_not_backing_or_reserve_proof(tmp_path):
    m = module('monitoring_runtime'); c = allocation_config()
    c['storage'].update(directory=str(tmp_path), binding='preallocated_loop_linear_v1', device=7, maximum_bytes=10000,
                        keep_free_bytes=100, minimum_inodes=1, retention_seconds=10)
    sentinel = tmp_path / 'events-1970-01-01.ndjson'; sentinel.write_text('keep'); os.utime(sentinel, (1, 1))
    facts = dict(qualified=True, binding='dedicated_mount', device=7, maximum_bytes=10000,
                 used_bytes=1000, available_bytes=9000, inodes_available=100, owner_uid=os.getuid(), proof=None)
    for proof in [None, {'independent_backing': True},
                  m.NativeCapacityEvidence('unknown',172900),
                  m.NativeCapacityEvidence('qualified',172900,'boot','g',1048576,0,0,9000,100,10000,1000)]:
        facts['proof'] = proof
        store = m.StorageBoundary(c, clock=lambda: 172900, observe=lambda: facts, owner_uid=os.getuid())
        view = store.maintain()
        assert not view['persist_permitted'] and view['status'] == 'unknown'
        assert view['maximum_bytes'] is None and view['available_bytes'] is None
        assert sentinel.read_text() == 'keep'
    c['storage']['binding'] = 'project_quota'
    view = m.StorageBoundary(c).read()
    assert view['status'] == 'unsupported' and not view['persist_permitted']


def test_bounded_command_engine_drops_partial_output_and_has_global_sample_deadline(monkeypatch):
    m = module('monitoring_runtime'); import application_release
    c = config(); calls = []
    monkeypatch.setattr(m, 'validate_tool', lambda p: None)
    def failed(argv, **kwargs):
        calls.append((argv, kwargs))
        raise application_release.CommandFailure(dict(failure='output_limit', returncode=-9, cleanup_confirmed=True,
                    output_truncated=True, output_bytes=4096, stdout='SECRET partial', stderr=''))
    monkeypatch.setattr(application_release, 'command', failed)
    source = m.NativeSources(c)
    with pytest.raises(application_release.CommandFailure) as caught:
        source.run([c['tools']['journalctl'], '--lines=64'])
    assert caught.value.record['output_bytes'] == 4096
    assert calls[0][1]['deadline'] == source.deadline
    assert calls[0][1]['timeout_seconds'] == 5
    assert source.bytes == 4096
    source.deadline = 0
    with pytest.raises(ValueError, match='sample_budget'):
        source.read('/NEVER/READ')


def test_query_json_duplicate_keys_and_sudo_generation_drift_fail_closed():
    m = module('monitoring_runtime'); import base64
    token = base64.urlsafe_b64encode(b'{"schema":"qcl.cluster-query.v1","schema":"bad"}').decode().rstrip('=')
    with pytest.raises(ValueError): m.decode_query(token)
    calls = 0
    caller = dict(pid=11, ppid=1, uids=[2001]*4, start_ticks=1, cgroup='same', executable='/client')
    sudo = dict(pid=12, ppid=11, uids=[2001,0,0,0], start_ticks=2, cgroup='same', executable='/sudo')
    def process(pid):
        nonlocal calls
        calls += 1
        if calls > 2: return {**caller, 'start_ticks': 99}
        return caller if pid == 11 else sudo
    with pytest.raises(ValueError, match='caller_changed'):
        m.authenticate({'SUDO_UID':'2001'}, 12, process, '/sudo', 2001)



def test_native_source_accepts_real_command_output_and_charges_stderr_bytes(monkeypatch):
    m = module('monitoring_runtime'); import application_release as engine
    c = config(); monkeypatch.setattr(m, 'validate_tool', lambda _: None)
    output = engine.CommandOutput('native-μ-output')
    output.output_bytes = len(output.encode()) + 11  # owning count includes stderr
    calls = []
    def command(argv, **kw): calls.append(kw); return output
    monkeypatch.setattr(engine, 'command', command)
    source = m.NativeSources(c)
    assert source.run([c['tools']['journalctl'], '--lines=1']) is output
    assert source.bytes == output.output_bytes
    assert source.run([c['tools']['journalctl'], '--lines=1']) == 'native-μ-output'
    assert calls[1]['output_bytes'] == c['bounds']['output_bytes'] - output.output_bytes


def test_native_source_accounts_real_failure_and_never_accepts_partial_stdout(monkeypatch):
    m = module('monitoring_runtime'); import application_release as engine
    c = config(); monkeypatch.setattr(m, 'validate_tool', lambda _: None)
    record = dict(failure='nonzero', returncode=1, cleanup_confirmed=True, output_truncated=False,
                  output_bytes=37, stdout='bounded partial', stderr='bounded failure')
    failure = engine.CommandFailure(record)
    def command(*a, **kw): raise failure
    monkeypatch.setattr(engine, 'command', command)
    source = m.NativeSources(c)
    with pytest.raises(engine.CommandFailure) as caught:
        source.run([c['tools']['journalctl'], '--lines=1'])
    assert caught.value is failure and caught.value.record is record
    assert source.bytes == 37


def test_observer_real_command_output_uses_str_and_fixed_p11_ssh(monkeypatch):
    m = module('monitoring_runtime'); import application_release as engine
    from test_cluster_projection import packet, target
    import release_trust
    monkeypatch.setattr(m, 'load_config', lambda: config('controller'))
    reads = []
    def protected(path, *args): reads.append(path); return b'key' if str(path).endswith('/key') else b'host key'
    monkeypatch.setattr(release_trust, 'read_protected_file', protected)
    expected = packet(); result = engine.CommandOutput(json.dumps(expected)); result.output_bytes = len(result.encode())
    calls = []
    def command(argv, **kwargs): calls.append((argv, kwargs)); return result
    monkeypatch.setattr(engine, 'command', command)
    query = dict(schema='qcl.cluster-query.v1', request_id=None, cursor=None, limit=64)
    assert m.observe_remote(target('host-a'), query) == expected
    assert len(reads) == 4  # trust/key before and after; no trust snapshot write
    assert calls[0][0][0] == 'ssh' and '-oStrictHostKeyChecking=yes' in calls[0][0]
    assert '-oIdentitiesOnly=yes' in calls[0][0] and '-oClearAllForwardings=yes' in calls[0][0]
    assert calls[0][1]['output_bytes'] == config()['bounds']['output_bytes']
    assert 'SSH_AUTH_SOCK' not in calls[0][1]['env']


@pytest.mark.parametrize('variant,expected', [('stale', 'stale_cursor'), ('timeout', 'observer_transport_unavailable'),
    ('timeout_exit_one', 'observer_transport_unavailable'),
    ('truncated', 'observer_transport_unavailable'), ('unclean', 'observer_transport_unavailable'),
    ('malformed', 'observer_transport_unavailable')])
def test_observer_real_failure_maps_only_clean_typed_cursor_error(monkeypatch, variant, expected):
    m = module('monitoring_runtime'); import application_release as engine
    from test_cluster_projection import target
    import release_trust
    monkeypatch.setattr(m, 'load_config', lambda: config('controller'))
    monkeypatch.setattr(release_trust, 'read_protected_file', lambda *a: b'protected bytes')
    record = dict(failure='nonzero', returncode=1, cleanup_confirmed=True, output_truncated=False,
                  output_bytes=100, stdout='discard partial',
                  stderr=json.dumps(dict(schema='qcl.monitoring-error.v1', reason='stale_cursor')))
    if variant == 'timeout': record.update(failure='timeout', returncode=-9)
    if variant == 'timeout_exit_one': record.update(failure='timeout', returncode=1)
    if variant == 'truncated': record.update(failure='output_limit', output_truncated=True)
    if variant == 'unclean': record['cleanup_confirmed'] = False
    if variant == 'malformed': record['stderr'] = 'PRIVATE malformed transport detail'
    failure = engine.CommandFailure(record)
    def command(*a, **kw): raise failure
    monkeypatch.setattr(engine, 'command', command)
    with pytest.raises(ValueError, match='^' + expected + '$') as caught:
        m.observe_remote(target('host-a'), dict(schema='qcl.cluster-query.v1', request_id=None, cursor=None, limit=64))
    assert caught.value.__cause__ is failure
    assert 'PRIVATE' not in str(caught.value)


def test_command_success_dict_is_not_a_supported_p11_contract(monkeypatch):
    m = module('monitoring_runtime'); import application_release as engine
    monkeypatch.setattr(m, 'validate_tool', lambda _: None)
    monkeypatch.setattr(engine, 'command', lambda *a, **kw: dict(stdout='wrong API', stderr='', output_bytes=9,
        failure=None, returncode=0, cleanup_confirmed=True))
    with pytest.raises(ValueError, match='command_contract'):
        m.NativeSources(config()).run([config()['tools']['journalctl'], '--lines=1'])


def test_failed_command_exhausts_sample_output_budget_before_next_executor(monkeypatch):
    m = module('monitoring_runtime'); import application_release as engine
    c = config(); c['bounds']['output_bytes'] = 16384; calls = []
    monkeypatch.setattr(m, 'validate_tool', lambda _: None)
    record = dict(failure='output_limit', returncode=-9, cleanup_confirmed=True,
                  output_truncated=True, output_bytes=16384, stdout='partial', stderr='')
    def command(*a, **kw): calls.append(kw); raise engine.CommandFailure(record)
    monkeypatch.setattr(engine, 'command', command)
    source = m.NativeSources(c)
    with pytest.raises(engine.CommandFailure): source.run([c['tools']['journalctl'], '--lines=1'])
    assert source.bytes == c['bounds']['output_bytes']
    with pytest.raises(ValueError, match='sample_budget'):
        source.run([c['tools']['journalctl'], '--lines=1'])
    assert len(calls) == 1


# Raw native metadata fixtures: no qualified/independent_backing booleans.
def allocation_config():
    c=config(); b=dict(backing_file='/owned/allocation.img',loop_device='/dev/loop7',
        mount_path='/owned/telemetry',data_dir='/owned/telemetry/data',state_dir='/owned/telemetry/state',
        reserve_file='/owned/telemetry/reserve/space',backing_lv_uuid='LVROOT-aaaa-bbbb-cccc-dddd-eeee-ffffff',backing_vg_uuid='VGROOT-aaaa-bbbb-cccc-dddd-eeee-ffffff',
        filesystem_uuid='11111111-1111-1111-1111-111111111111',maximum_bytes=1048576,reserve_bytes=65536,
        host_keep_free_bytes=1048576,physical_ids=['wwid:disk-a'],
        science_devices=[dict(device=64769,lv_uuid='LVSCIE-aaaa-bbbb-cccc-dddd-eeee-ffffff',vg_uuid='VGSCIE-aaaa-bbbb-cccc-dddd-eeee-ffffff',physical_ids=['wwid:disk-b'])])
    c['storage'].update(binding='preallocated_loop_linear_v1',directory=b['data_dir'],allocation=b,
        device=1799,maximum_bytes=1048576,keep_free_bytes=4096,minimum_inodes=1)
    c['tools']['lvs']='/usr/sbin/lvm'
    return c


class CapacitySources:
    def __init__(self):
        import struct
        self.config=allocation_config(); self.calls=[]
        def file(size,device,inode):
            # Linux fiemap header32 + one initialized LAST extent56.
            fm=struct.pack('=QQIIII',0,size,0,1,1024,0)+struct.pack('=QQQQQIIII',0,4096,size,0,0,1,0,0,0)
            return dict(device=device,inode=inode,uid=0,gid=0,mode=0o100600,nlink=1,size=size,blocks=size//512,fiemap=fm)
        self.files={'/owned/allocation.img':file(1048576,64768,90),
            '/owned/telemetry/reserve/space':file(65536,1799,91)}
        self.loop=struct.pack('=QQQQQIIII64s64s32sQQ',64768,90,0,0,1048576,7,0,0,0,b'',b'',b'',0,0)
        self.mount=dict(device=1799,root='/',fstype='ext4',uuid='11111111-1111-1111-1111-111111111111',
            blocks=256,frsize=4096,bfree=128,bavail=120,favail=100,inodes=256)
        self.directories={p:dict(device=1799,uid=0,gid=2003,mode=0o40770) for p in ['/owned/telemetry/data','/owned/telemetry/state']}
        self.nodes={'253:0':dict(slaves=['8:1'],parent=None,wwid=None,dm_uuid='LVM-VGROOTaaaabbbbccccddddeeeeffffffLVROOTaaaabbbbccccddddeeeeffffff'),
            '253:1':dict(slaves=['253:2'],parent=None,wwid=None,dm_uuid='LVM-VGSCIEaaaabbbbccccddddeeeeffffffLVSCIEaaaabbbbccccddddeeeeffffff'),
            '253:2':dict(slaves=['8:17'],parent=None,wwid=None,dm_uuid='LVM-pool'),
            '8:1':dict(slaves=[],parent='8:0',wwid=None,dm_uuid=None),
            '8:17':dict(slaves=[],parent='8:16',wwid=None,dm_uuid=None),
            '8:0':dict(slaves=[],parent=None,wwid='disk-a',dm_uuid=None),
            '8:16':dict(slaves=[],parent=None,wwid='disk-b',dm_uuid=None)}
        self.lv=dict(lv_uuid='LVROOT-aaaa-bbbb-cccc-dddd-eeee-ffffff',vg_uuid='VGROOT-aaaa-bbbb-cccc-dddd-eeee-ffffff',segtype='linear',pool_lv='',origin='',
            lv_size='16777216',lv_attr='-wi-ao----',devices='/dev/fixture(0)')
    def read(self,path,**kw):
        if path.endswith('/boot_id'): return 'boot-a'
        raise AssertionError('unexpected read')
    def allocation_file(self,path): self.calls.append(('file',path));return copy.deepcopy(self.files[path])
    def loop_status(self,path): return self.loop,1048576,1799
    def mount_metadata(self,path): return copy.deepcopy(self.mount)
    def directory_metadata(self,path):
        if path=='/owned/telemetry/reserve':return dict(device=self.mount['device'],uid=0,gid=0,mode=0o40700)
        return copy.deepcopy(self.directories[path])
    def backing_mount(self,path): return dict(device=64768,fstype='ext4',available_bytes=8388608)
    def block_node(self,dev): return copy.deepcopy(self.nodes[dev])
    def run(self,argv,**kw): self.calls.append(('run',argv));return json.dumps(dict(report=[dict(lv=[self.lv])],log=[]))
    def writer_identity(self): return 2003,2003
    def collector_properties(self):
        return dict(Id='vector.service',User='qcl-monitoring',Group='qcl-monitoring',
            ProtectSystem='strict',ProtectHome='yes',PrivateDevices='yes',NoNewPrivileges='yes',
            CapabilityBoundingSet='',ReadWritePaths='/owned/telemetry/data /owned/telemetry/state',
            StateDirectory='',LogsDirectory='',CacheDirectory='',RuntimeDirectory='',
            StandardOutput='null',StandardError='null',ActiveState='inactive',PrivateTmp='no',RootDirectory='',RootImage='',BindPaths='',BindReadOnlyPaths='',TemporaryFileSystem='')


def test_native_initialized_allocation_has_real_bounded_capacity_producer():
    m=module('monitoring_runtime')
    assert hasattr(m,'read_native_capacity'), 'missing native capacity/backing/reserve producer'
    s=CapacitySources(); proof=m.read_native_capacity(s.config['storage']['allocation'],s,now=100)
    assert isinstance(proof,m.NativeCapacityEvidence) and proof.status=='qualified'
    assert proof.allocation_bytes==1048576 and proof.allocated_reserve_bytes==65536
    assert proof.science_charge_bytes==0 and proof.available_bytes==491520
    assert proof.observed_at==100 and proof.host_boot_id=='boot-a'
    assert not any('qualified' in str(call) for call in s.calls)


@pytest.mark.parametrize('bad', ['thin','shared','uninitialized','wrong_inode','wrong_offset','nlink','reserve',
    'physical_unknown','same_device','wrong_lv','mount_changed','writer_escape'])
def test_same_shape_statvfs_cannot_hide_bad_native_backing_or_reserve(bad):
    import struct
    m=module('monitoring_runtime'); assert hasattr(m,'read_native_capacity')
    s=CapacitySources()
    if bad=='thin':s.lv['segtype']='thin'
    if bad in ('shared','uninitialized'):
        f=s.files['/owned/allocation.img']; raw=bytearray(f['fiemap']);struct.pack_into('=I',raw,72,0x2001 if bad=='shared' else 0x801); f['fiemap']=bytes(raw)
    if bad=='wrong_inode': s.files['/owned/allocation.img']['inode']=100
    if bad=='wrong_offset': raw=bytearray(s.loop);struct.pack_into('=Q',raw,24,4096);s.loop=bytes(raw)
    if bad=='nlink':s.files['/owned/allocation.img']['nlink']=2
    if bad=='reserve':s.files['/owned/telemetry/reserve/space']['blocks']=0
    if bad=='physical_unknown':s.nodes['8:0']['wwid']=None
    if bad=='same_device':s.nodes['8:16']['wwid']='disk-a'
    if bad=='wrong_lv':s.nodes['253:0']['dm_uuid']='LVM-foreign'
    if bad=='mount_changed':
        calls=[]
        def mount(path):
            calls.append(path);return {**s.mount,'device':1799 if len(calls)==1 else 1800}
        s.mount_metadata=mount
    if bad=='writer_escape':s.collector_properties=lambda:dict(User='root',ActiveState='active')
    proof=m.read_native_capacity(s.config['storage']['allocation'],s,now=100)
    assert proof.status in ('unknown','unsupported') and proof.science_charge_bytes is None


def test_native_allocation_syscalls_are_read_only_and_bounded(monkeypatch):
    m=module('monitoring_runtime');import fcntl,stat
    from types import SimpleNamespace
    raw=CapacitySources().loop;calls=[];opens=[]
    monkeypatch.setattr(m.os,'open',lambda path,flags:opens.append((path,flags)) or 11)
    monkeypatch.setattr(m.os,'close',lambda fd:None)
    monkeypatch.setattr(m.os,'fstat',lambda fd:SimpleNamespace(st_mode=stat.S_IFBLK|0o600,st_rdev=1799))
    def ioctl(fd,op,buffer,mutate):
        import struct
        calls.append(op)
        if op==0x4C05:buffer[:]=raw
        elif op==0x80081272:struct.pack_into('=Q',buffer,0,1048576)
        else:raise AssertionError('setter/unknown ioctl forbidden')
    monkeypatch.setattr(fcntl,'ioctl',ioctl)
    result=m.NativeSources(config()).loop_status('/dev/loop7')
    assert result==(raw,1048576,1799) and calls==[0x4C05,0x80081272]
    assert opens[0][1] & (os.O_WRONLY|os.O_RDWR)==0


def test_actual_fiemap_reader_issues_only_bounded_read_ioctl_without_payload(monkeypatch):
    m=module('monitoring_runtime');import fcntl,release_trust,contextlib
    from types import SimpleNamespace
    fixture=CapacitySources().files['/owned/allocation.img'];calls=[]
    monkeypatch.setattr(release_trust,'protected_directory',lambda p:contextlib.nullcontext(10))
    monkeypatch.setattr(m.os,'open',lambda *a,**k:11)
    monkeypatch.setattr(m.os,'close',lambda fd:None)
    info=SimpleNamespace(**{'st_'+k:v for k,v in dict(dev=fixture['device'],ino=fixture['inode'],uid=0,gid=0,mode=0o100600,nlink=1,size=1048576,blocks=2048).items()})
    monkeypatch.setattr(m.os,'fstat',lambda fd:info)
    def ioctl(fd,op,buffer,mutate):
        import struct
        assert struct.unpack_from('=I',buffer,16)[0]==0
        calls.append((op,len(buffer)));buffer[:len(fixture['fiemap'])]=fixture['fiemap']
    monkeypatch.setattr(fcntl,'ioctl',ioctl)
    def forbidden(*a,**k):raise AssertionError('file payload read forbidden')
    monkeypatch.setattr(m.os,'read',forbidden);monkeypatch.setattr(m.os,'pread',forbidden)
    s=m.NativeSources(config());raw=s.allocation_file('/owned/allocation.img')
    assert m._initialized_file(raw,1048576)['inode']==90
    assert calls==[(0xC020660B,57376)] and s.bytes==57376


def test_unknown_proof_can_stop_only_exact_owned_collector_and_never_claim_stopped():
    m=module('monitoring_runtime');s=CapacitySources();calls=[]
    properties=s.collector_properties();properties['ActiveState']='active'
    s.collector_properties=lambda:properties
    s.run=lambda argv,**kw:calls.append(argv) or ''
    view=m._guard_collector(s.config,s,m.unknown_storage(100))
    assert calls==[['/usr/bin/systemctl','stop','--no-block','--','vector.service']]
    assert not view['persist_permitted'] and view['collector_state']=='active'
    properties['User']='foreign';calls.clear()
    view=m._guard_collector(s.config,s,m.unknown_storage(100))
    assert not calls and view['collector_state']=='unknown'


def test_identical_uuid_geometry_on_other_loop_mount_never_qualifies():
    m=module('monitoring_runtime');s=CapacitySources()
    s.mount['device']=1800
    for meta in s.directories.values():meta['device']=1800
    s.files['/owned/telemetry/reserve/space']['device']=1800
    proof=m.read_native_capacity(s.config['storage']['allocation'],s,now=100)
    assert proof.status=='unknown', 'mount must join actual loop device, not just copied FS UUID/statvfs'


@pytest.mark.parametrize('bad', ['loop_number','writer_bind_escape'])
def test_native_identity_rejects_loop_number_and_writer_mount_namespace_escape(bad):
    import struct
    m=module('monitoring_runtime');s=CapacitySources()
    if bad=='loop_number':
        raw=bytearray(s.loop);struct.pack_into('=I',raw,40,8);s.loop=bytes(raw)
    else:
        props=s.collector_properties();props['BindPaths']='/outside:/owned/telemetry/data'
        s.collector_properties=lambda:props
    assert m.read_native_capacity(s.config['storage']['allocation'],s,now=100).status=='unknown'


def test_linear_lv_above_another_thin_mapper_does_not_prove_hard_backing():
    m=module('monitoring_runtime');s=CapacitySources()
    s.nodes['253:0']['slaves']=['253:3']
    s.nodes['253:3']=dict(slaves=['8:1'],parent=None,wwid=None,dm_uuid='LVM-intermediate-thin')
    assert m.read_native_capacity(s.config['storage']['allocation'],s,now=100).status=='unknown'


def test_native_capacity_through_storage_boundary_and_config_policy():
    m=module('monitoring_runtime');s=CapacitySources()
    assert m.validate_config(s.config)==s.config
    view=m.StorageBoundary(s.config,clock=lambda:100,sources=s).read()
    assert view['persist_permitted'] and view['status']=='qualified'
    assert view['collector_state']=='inactive' and view['allocated_reserve_bytes']==65536
    assert view['available_bytes']==491520 and view['science_charge_bytes']==0
    assert view['capacity_generation']
    assert [argv[1:3] for kind,argv in s.calls if kind=='run']==[['lvs','--readonly']]
    for key in ('data_dir','state_dir','reserve_file'):
        broken=copy.deepcopy(s.config);broken['storage']['allocation'][key]='/outside'
        with pytest.raises(ValueError):m.validate_config(broken)
    broken=copy.deepcopy(s.config);broken['storage']['allocation']['qualified']=True
    with pytest.raises(ValueError):m.validate_config(broken)


def test_native_capacity_failure_reason_is_closed_and_reaches_public_storage():
    m=module('monitoring_runtime');s=CapacitySources();s.lv['segtype']='thin'
    p=m.read_native_capacity(s.config['storage']['allocation'],s,now=100)
    assert p.reasons==('allocation_not_linear',)
    v=m.StorageBoundary(s.config,clock=lambda:100,sources=s).read()
    assert not v['persist_permitted'] and v['reasons']==[dict(code='allocation_not_linear',source_id='telemetry')]
    s.allocation_file=lambda path:(_ for _ in ()).throw(ValueError('/private/SECRET'))
    p=m.read_native_capacity(s.config['storage']['allocation'],s,now=100)
    assert p.reasons==('native_capacity_unverified',)


@pytest.mark.parametrize('started,observed,finished,permitted,code', [
    (100,100,100,True,None),
    (100,100,110,True,None),  # TTL boundary is inclusive
    (100,100,111,False,'capacity_stale'),
    (100,100,112,False,'capacity_stale'),
    (100,99,99,False,'clock_rollback'),
    (100,110,105,False,'clock_future'),
    (100,105,106,True,None),  # native sampling may start after the outer read
])
def test_storage_rechecks_completion_clock_with_actual_native_producer(started,observed,finished,permitted,code):
    m=module('monitoring_runtime');source=CapacitySources()
    moments=iter([started,observed,finished]);seen=[]
    def clock():
        value=next(moments);seen.append(value);return value
    view=m.StorageBoundary(source.config,sources=source,clock=clock).read()
    assert seen==[started,observed,finished], 'post-observation current-time read required'
    assert view['observed_at']==observed  # do not restamp old/future evidence to obtain pass
    assert view['persist_permitted'] is permitted
    if code:
        assert view['status']=='unknown' and view['reasons']==[dict(code=code,source_id='telemetry')]
    else:
        assert view['status']=='qualified' and view['reasons']==[]

# Breaks caught: accepting the wrong kernel UID, a second request/frame, or
# replacing a cache-only read with an observer/probe on an ordinary API poll.
def portal_socket_fixture(monkeypatch):
    import socket
    from types import SimpleNamespace
    m = module('monitoring_runtime')
    # Explicit authority fixture only: kernel peer credentials stay real, but
    # local test UID stands in for the enrolled service account and server UID.
    monkeypatch.setattr(m.pwd, 'getpwnam', lambda name: SimpleNamespace(pw_uid=os.getuid())
                        if name == 'qcl-negf' else pytest.fail('unexpected account'))
    return m, socket


def portal_query(m, **changes):
    value = dict(schema='qcl.cluster-query.v1', request_id=None, cursor=None, limit=64)
    value.update(changes)
    return m.encode_query(value).encode() + b'\n'


def portal_exchange(m, socket, frame):
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        left.sendall(frame); left.shutdown(socket.SHUT_WR)
        m.portal_cache_handle(right)
        right.shutdown(socket.SHUT_WR)
        raw = bytearray()
        while chunk := left.recv(65536): raw.extend(chunk)
        return json.loads(raw)
    finally:
        left.close(); right.close()


def test_portal_socket_cache_read_keeps_unknown_and_observation_time(monkeypatch):
    m, socket = portal_socket_fixture(monkeypatch)
    cluster = module('cluster_projection')
    c = config('controller')
    from test_cluster_projection import target
    c['targets'] = [target('host-a')]
    monkeypatch.setattr(m, 'load_config', lambda: c)
    monkeypatch.setattr(m, 'read_cache', lambda _: None)
    def forbidden(*args, **kwargs): pytest.fail('public poll performed fresh effect')
    for name in ('observe_local','observe_remote','sample_native_status','NativeSources'):
        monkeypatch.setattr(m, name, forbidden)
    result = portal_exchange(m, socket, portal_query(m))
    assert result['schema'] == 'qcl.cluster-projection.v2'
    assert result['status'] == 'unknown'
    assert result['hosts'][0]['native'] is None and result['hosts'][0]['resource'] is None
    assert result['hosts'][0]['reasons']
    cluster.validate_cluster_projection(result)


@pytest.mark.parametrize('frame', [b'', b'bad\n', b'A'*8193+b'\n', b'e30\nextra\n',
    b'e30\n\n', b'e30', b'e30\r\n', b'\xff\n'], ids=['empty','bad-token','oversize','extra','second-line','unclosed','crlf','nonascii'])
def test_portal_socket_rejects_unclosed_or_oversized_frame_before_cache(monkeypatch, frame):
    m, socket = portal_socket_fixture(monkeypatch)
    cluster = module('cluster_projection')
    monkeypatch.setattr(cluster, 'read_cluster_projection', lambda **kw: pytest.fail('effect before validation'))
    assert portal_exchange(m, socket, frame) == {'schema':'qcl.monitoring-error.v1','reason':'monitoring_unavailable'}


def test_portal_socket_rejects_lookup_and_wrong_kernel_peer_before_cache(monkeypatch):
    from types import SimpleNamespace
    m, socket = portal_socket_fixture(monkeypatch)
    cluster = module('cluster_projection')
    monkeypatch.setattr(cluster, 'read_cluster_projection', lambda **kw: pytest.fail('unauthorized cache read'))
    assert portal_exchange(m, socket, portal_query(m, request_id='exact-request'))['reason'] == 'monitoring_unavailable'
    monkeypatch.setattr(m.pwd, 'getpwnam', lambda _: SimpleNamespace(pw_uid=os.getuid()+1))
    assert portal_exchange(m, socket, portal_query(m))['reason'] == 'monitoring_unavailable'


def test_portal_socket_stale_error_is_typed_and_redacts_other_errors(monkeypatch):
    m, socket = portal_socket_fixture(monkeypatch)
    cluster = module('cluster_projection')
    def fail(**kw): raise ValueError('stale_cursor')
    monkeypatch.setattr(cluster, 'read_cluster_projection', fail)
    assert portal_exchange(m, socket, portal_query(m, cursor='opaque'))['reason'] == 'stale_cursor'
    def private(**kw): raise RuntimeError('private config /secret/tool')
    monkeypatch.setattr(cluster, 'read_cluster_projection', private)
    assert portal_exchange(m, socket, portal_query(m)) == {'schema':'qcl.monitoring-error.v1','reason':'monitoring_unavailable'}


def test_portal_socket_expired_deadline_has_no_read_or_write(monkeypatch):
    m, socket = portal_socket_fixture(monkeypatch)
    cluster = module('cluster_projection')
    monkeypatch.setattr(cluster, 'read_cluster_projection', lambda **kw: pytest.fail('expired cache read'))
    ticks = iter([0, 6, 6])
    monkeypatch.setattr(m.time, 'monotonic', lambda: next(ticks, 6))
    left, right = socket.socketpair()
    try:
        left.sendall(portal_query(m)); left.shutdown(socket.SHUT_WR)
        m.portal_cache_handle(right)
        right.shutdown(socket.SHUT_WR)
        assert left.recv(1) == b''
    finally: left.close(); right.close()


@pytest.mark.parametrize('raw', [b'{}\n', b'{"schema":1,"schema":2}\n', b'{"x":NaN}\n',
    b'{}\n{}\n', b'{}', b'x'*(1048577)+b'\n'], ids=['shape','duplicate','nonfinite','extra','unclosed','oversize'])
def test_portal_client_rejects_bad_complete_response_without_partial_stdout(monkeypatch, raw, capsys):
    m, socket = portal_socket_fixture(monkeypatch)
    monkeypatch.setattr(m, 'portal_cache_query', lambda token: m.portal_cache_decode_response(raw))
    monkeypatch.setattr(sys, 'argv', ['client','--query-base64',portal_query(m).decode().strip()])
    assert m.portal_cache_client_main() == 1
    out = capsys.readouterr()
    assert out.out == '' and json.loads(out.err) == {'schema':'qcl.monitoring-error.v1','reason':'monitoring_unavailable'}


def test_portal_client_uses_real_owned_unix_socket_and_closes(monkeypatch, tmp_path):
    import threading
    m, socket = portal_socket_fixture(monkeypatch)
    # Root/PID1 server peer UID=0 is qualified separately. Test substitutes only
    # that expected UID; the actual getsockopt(SO_PEERCRED) call is still real.
    monkeypatch.setattr(m, 'PORTAL_CACHE_SERVER_UID', os.getuid())
    path = str(tmp_path / 'cache.sock')
    monkeypatch.setattr(m, 'PORTAL_CACHE_SOCKET', path)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path); listener.listen(1)
    seen = []
    def serve():
        connection, _ = listener.accept()
        with connection:
            frame = bytearray()
            while chunk := connection.recv(8194): frame.extend(chunk)
            seen.append(bytes(frame))
            connection.sendall(b'{"schema":"qcl.monitoring-error.v1","reason":"stale_cursor"}\n')
    worker = threading.Thread(target=serve); worker.start()
    try:
        with pytest.raises(ValueError, match='stale_cursor'):
            m.portal_cache_query(portal_query(m).decode().strip())
        worker.join(2)
        assert not worker.is_alive() and seen == [portal_query(m)]
    finally:
        listener.close(); worker.join(2)
        Path(path).unlink()


def test_portal_client_rejects_invalid_query_before_connect(monkeypatch):
    m, socket = portal_socket_fixture(monkeypatch)
    monkeypatch.setattr(m.socket, 'socket', lambda *a, **k: pytest.fail('connect before query validation'))
    with pytest.raises(ValueError): m.portal_cache_query('bad')
    with pytest.raises(ValueError): m.portal_cache_query(portal_query(m, request_id='lookup').decode().strip())


def test_portal_client_wrong_server_uid_fails_before_request(monkeypatch, tmp_path):
    import threading
    m, socket = portal_socket_fixture(monkeypatch)
    path = str(tmp_path / 'wrong.sock'); monkeypatch.setattr(m,'PORTAL_CACHE_SOCKET',path)
    monkeypatch.setattr(m,'PORTAL_CACHE_SERVER_UID',os.getuid()+1)
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); listener.bind(path); listener.listen(1)
    received=[]
    def serve():
        connection,_=listener.accept()
        with connection: received.append(connection.recv(1))
    worker=threading.Thread(target=serve); worker.start()
    try:
        with pytest.raises(ValueError,match='monitoring_unavailable'):
            m.portal_cache_query(portal_query(m).decode().strip())
        worker.join(2)
        assert not worker.is_alive() and received==[b'']
    finally: listener.close(); worker.join(2); Path(path).unlink()


def test_portal_client_validates_full_dto_before_stdout_and_never_loads_config(monkeypatch,capsys):
    m,socket=portal_socket_fixture(monkeypatch)
    cluster=module('cluster_projection')
    value=json.loads((ROOT/'examples/cluster-projection.json.example').read_text())
    cluster.validate_cluster_projection(value)
    for name in ('load_config','read_cache','sample_native_status','observe_remote'):
        monkeypatch.setattr(m,name,lambda *a,**kw:pytest.fail('nonprivileged client opened private/fresh source'))
    monkeypatch.setattr(m,'portal_cache_query',lambda token:m.portal_cache_decode_response(json.dumps(value).encode()+b'\n'))
    monkeypatch.setattr(sys,'argv',['client','--query-base64',portal_query(m).decode().strip()])
    assert m.portal_cache_client_main()==0
    out=capsys.readouterr()
    assert json.loads(out.out)==value and out.err==''


def test_portal_server_overflow_never_relays_partial_or_private_payload(monkeypatch):
    m,socket=portal_socket_fixture(monkeypatch)
    cluster=module('cluster_projection')
    value=json.loads((ROOT/'examples/cluster-projection.json.example').read_text())
    monkeypatch.setattr(cluster,'read_cluster_projection',lambda **kw:value)
    monkeypatch.setattr(m,'PORTAL_CACHE_BYTES',32)
    result=portal_exchange(m,socket,portal_query(m))
    assert result=={'schema':'qcl.monitoring-error.v1','reason':'monitoring_unavailable'}


def test_portal_full_owned_socket_roundtrip_does_not_touch_private_client_sources(monkeypatch,tmp_path):
    import threading
    m,socket=portal_socket_fixture(monkeypatch)
    cluster=module('cluster_projection')
    value=json.loads((ROOT/'examples/cluster-projection.json.example').read_text())
    monkeypatch.setattr(cluster,'read_cluster_projection',lambda **kw:copy.deepcopy(value))
    monkeypatch.setattr(m,'load_config',lambda:pytest.fail('transport opened config itself'))
    monkeypatch.setattr(m,'PORTAL_CACHE_SERVER_UID',os.getuid())
    path=str(tmp_path/'round.sock'); monkeypatch.setattr(m,'PORTAL_CACHE_SOCKET',path)
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); listener.bind(path); listener.listen(1)
    failures=[]
    def serve():
        try:
            connection,_=listener.accept()
            with connection: m.portal_cache_handle(connection)
        except Exception as error: failures.append(type(error).__name__)
    worker=threading.Thread(target=serve);worker.start()
    try:
        result=m.portal_cache_query(portal_query(m).decode().strip())
        assert result==value
        worker.join(2)
        assert not worker.is_alive() and failures==[]
    finally:listener.close();worker.join(2);Path(path).unlink()


def test_portal_client_timeout_closes_connection_and_redacts_detail(monkeypatch,tmp_path,capsys):
    import threading
    m,socket=portal_socket_fixture(monkeypatch)
    monkeypatch.setattr(m,'PORTAL_CACHE_SERVER_UID',os.getuid())
    monkeypatch.setattr(m,'PORTAL_CACHE_SECONDS',.05)
    path=str(tmp_path/'timeout.sock');monkeypatch.setattr(m,'PORTAL_CACHE_SOCKET',path)
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(path);listener.listen(1)
    release=threading.Event(); closed=[]
    def serve():
        connection,_=listener.accept()
        with connection:
            while connection.recv(8194):pass
            release.wait(1)
            closed.append(connection.recv(1))
    worker=threading.Thread(target=serve);worker.start()
    monkeypatch.setattr(sys,'argv',['client','--query-base64',portal_query(m).decode().strip()])
    try:
        assert m.portal_cache_client_main()==1
        out=capsys.readouterr()
        assert out.out=='' and json.loads(out.err)=={'schema':'qcl.monitoring-error.v1','reason':'monitoring_unavailable'}
        release.set();worker.join(2)
        assert not worker.is_alive() and closed==[b'']
    finally:release.set();listener.close();worker.join(2);Path(path).unlink()
