"""Literal native parser and OOM controls; no real process/journal/backend reads."""
import copy
import json

import pytest

from test_monitoring_runtime import config, module


def test_native_memory_units_keep_rss_assignment_and_max_distinct():
    m = module('native_monitoring')
    assert m.parse_meminfo('MemTotal: 32768 kB\nMemAvailable: 16384 kB\n') == (33554432, 16777216)
    row = m.pve_memory({'memory': 8192, 'balloon': 4096, 'smbios1': 'uuid=vm-native'},
                       {'pid': 43, 'balloon': 4294967296, 'mem': 64, 'maxmem': 8589934592,
                        'status': 'running', 'cpus': 2}, 'vm-native')
    assert row['assigned_bytes'] == 4294967296
    assert row['configured_bytes'] == 4294967296 and row['configured_max_bytes'] == 8589934592
    assert row['qemu_rss_bytes'] is None
    xml = '<domain><uuid>native</uuid><memory unit="MiB">8192</memory><currentMemory unit="KiB">4194304</currentMemory><vcpu>2</vcpu></domain>'
    row = m.libvirt_memory(xml, 'actual 4194304\nrss 65536\n', 'native')
    assert row['assigned_bytes'] == 4294967296 and row['qemu_rss_bytes'] == 67108864
    for raw in ['MemTotal: 1 kB\n', 'MemTotal: 1 kB\nMemAvailable: 2 kB\n']:
        with pytest.raises(ValueError): m.parse_meminfo(raw)
    with pytest.raises(ValueError): m.libvirt_memory('<!DOCTYPE x>' + xml, '', 'native')


def test_oom_source_pid_boot_and_counter_generation_are_required():
    m = module('native_monitoring')
    binding = {'vm_id': 'vm-a', 'pid': 43, 'start_ticks': 12, 'boot_id': 'boot-a',
               'from': 80, 'until': 100, 'cgroup': '/machine.slice/vm.scope', 'generation': 'pid-12'}
    kernel = {'_BOOT_ID': 'boot-a', '_TRANSPORT': 'kernel', '__REALTIME_TIMESTAMP': '90000000',
              '__CURSOR': 'cursor-1', 'MESSAGE': 'Out of memory: Killed process 43 (qemu-system-x86)'}
    events = m.classify_journal([kernel], [binding], host_boot_id='boot-a')
    assert events[0]['cause'] == 'host_kernel_qemu_oom' and events[0]['confidence'] == 'observed'
    assert 'MESSAGE' not in json.dumps(events) and 'Out of memory' not in json.dumps(events)
    for wrong in [{**binding, 'boot_id': 'other'}, {**binding, 'from': 95}, {**binding, 'pid': 44}]:
        assert m.classify_journal([kernel], [wrong], host_boot_id='boot-a')[0]['confidence'] == 'unknown'
    oomd = {**kernel, '_TRANSPORT': 'journal', '_SYSTEMD_UNIT': 'systemd-oomd.service',
            'MESSAGE': 'Killed /machine.slice/vm.scope due to memory pressure'}
    assert m.classify_journal([oomd], [binding], host_boot_id='boot-a')[0]['cause'] == 'systemd_oomd'
    old = {'identity': 'boot-a:inode7:job42', 'oom_kill': 1}
    assert m.cgroup_delta(old, {**old, 'oom_kill': 2}) == 1
    assert m.cgroup_delta(old, {'identity': 'boot-b:inode7:job42', 'oom_kill': 2}) is None
    assert m.cgroup_delta(None, old) is None


class LiteralSources:
    def __init__(self):
        self.calls = []
        self.boot = 'boot-a'
    def read(self, path, limit=65536):
        self.calls.append(('read', path))
        return {'/proc/sys/kernel/random/boot_id': self.boot, '/etc/machine-id': '1' * 32,
                '/proc/meminfo': 'MemTotal: 32768 kB\nMemAvailable: 16384 kB\n'}[path]
    def run(self, argv):
        self.calls.append(('run', argv)); raise AssertionError('disabled sampler must not run native tools')


def test_disabled_native_adapter_keeps_measurements_unknown_without_bootstrapping():
    m = module('native_monitoring'); sources = LiteralSources()
    view = m.NativeSampler(config(), sources, clock=lambda: 100).sample()
    assert view['native']['host_memory']['total_bytes'] == 33554432
    assert any(r['code'] == 'backend_disabled' for r in view['native']['coverage']['reasons'])
    assert view['native']['vms'] == []
    assert all(call[0] == 'read' for call in sources.calls)
    assert not any('verify' in str(call) for call in sources.calls)


def test_journal_gap_keeps_unknown_loss_and_never_scans_unbounded_history():
    m = module('native_monitoring'); c = config(); c['scopes']['journal'] = True
    previous = dict(native=m.empty_native('host-a', observed_at=90), services=[], journal_cursor='saved-cursor', cgroups={})
    previous['native']['host_boot_id'] = 'boot-a'
    row = m.vm_row('vm-a'); row.update(power_state='running', qemu_pid=43, qemu_start_ticks=12, native_generation='boot-a:43:12')
    previous['native']['vms'] = [row]
    class Sources(LiteralSources):
        def run(self, argv, **kwargs):
            self.calls.append(('run', argv)); raise ValueError('vacuumed cursor')
    source = Sources(); sample = m.NativeSampler(c, source, clock=lambda: 100, previous=previous).sample()
    assert sample['native']['oom']['events'][0]['cause'] == 'unknown_vm_loss'
    assert sample['native']['oom']['coverage']['status'] == 'not_measured'
    calls = [a for kind, a in source.calls if kind == 'run']
    assert len(calls) == 1
    assert '--after-cursor=saved-cursor' in calls[0] and '--lines=64' in calls[0] and '--since=@40' in calls[0]
    assert not any('vacuum' in a for a in calls[0])


def test_guest_counter_generation_is_not_inferred_from_nonzero_baseline():
    m = module('native_monitoring'); c = config('worker')
    c['scopes']['cgroups'] = [dict(vm_id='guest-a', workload='job-42', path='/sys/fs/cgroup/qcl/job42', generation='allocation-42')]
    class Sources(LiteralSources):
        def cgroup(self, *args): return dict(identity='boot-a:inode1:allocation-42', oom_kill=2)
    sampler = m.NativeSampler(c, Sources(), clock=lambda: 100)
    first = sampler.sample()
    assert first['native']['oom']['events'] == []
    assert any(r['code'] == 'prior_count_unknown_time' for r in first['native']['oom']['coverage']['reasons'])
    prev = dict(**first, cgroups={'job-42':dict(identity='boot-a:inode1:allocation-42', oom_kill=1)})
    second = m.NativeSampler(c, Sources(), clock=lambda: 101, previous=prev).sample()
    event = second['native']['oom']['events'][0]
    assert event['cause'] == 'guest_cgroup_oom' and event['guest_boot_id'] == 'boot-a' and event['host_boot_id'] is None


def test_clock_or_boot_change_and_protocol_mismatch_preserve_previous_cache():
    m = module('native_monitoring'); c = config(); c['scopes']['backend'] = 'libvirt'; c['scopes']['version'] = 'expected'
    class Sources(LiteralSources):
        def run(self, argv, **kwargs): return 'unexpected'
    with pytest.raises(ValueError, match='protocol_version_mismatch'):
        m.NativeSampler(c, Sources(), clock=lambda: 100).sample()
    c['scopes']['backend'] = 'disabled'
    class Reboot(LiteralSources):
        def read(self, path, limit=65536):
            value = super().read(path, limit)
            if path.endswith('boot_id'): self.boot = 'boot-b'
            return value
    with pytest.raises(ValueError, match='boot_changed'):
        m.NativeSampler(c, Reboot(), clock=lambda: 100).sample()


def test_conflicting_native_oom_sources_are_indication_not_double_certainty():
    m = module('native_monitoring')
    binding = dict(vm_id='v', pid=43, start_ticks=12, boot_id='boot-a', cgroup='/vm.scope', generation='birth-12', **{'from':80, 'until':100})
    base = dict(_BOOT_ID='boot-a', __REALTIME_TIMESTAMP='90000000')
    records = [{**base, '_TRANSPORT':'kernel', '__CURSOR':'c1', 'MESSAGE':'Out of memory: Killed process 43 (qemu-system-x86)'},
               {**base, '_SYSTEMD_UNIT':'systemd-oomd.service', '__CURSOR':'c2', 'MESSAGE':'Killed /vm.scope due to memory pressure'}]
    events = m.classify_journal(records, [binding], host_boot_id='boot-a')
    assert {e['cause'] for e in events} == {'host_kernel_qemu_oom', 'systemd_oomd'}
    assert all(e['confidence'] == 'indication' for e in events)


def test_wall_clock_rollback_is_inconsistent_even_with_current_meminfo():
    m = module('native_monitoring'); previous = dict(native=m.empty_native('host-a', observed_at=200), services=[], cgroups={})
    previous['native']['host_boot_id'] = 'boot-a'
    value = m.NativeSampler(config(), LiteralSources(), clock=lambda: 100, previous=previous).sample()
    assert value['native']['coverage']['status'] == 'inconsistent'
    assert any(r['code'] == 'clock_rollback' for r in value['native']['coverage']['reasons'])


def test_positive_pve_sampler_scopes_only_enrolled_vm_and_service():
    m = module('native_monitoring'); c = config()
    c['scopes'].update(backend='pve', node='node-a', version='fixture-v1',
        vms=[dict(vm_id='vm-a', native_id='1001', uuid='uuid-a')],
        services=[dict(service_id='slurmd', unit='slurmd.service')])
    class Sources(LiteralSources):
        def run(self, argv, **kwargs):
            self.calls.append(('run', argv))
            if argv[1:] == ['get', '/version', '--output-format', 'json']: return 'fixture-v1'
            if '/nodes/node-a/qemu/1001/config' in argv:
                return json.dumps(dict(memory=8192, balloon=4096, smbios1='uuid=uuid-a', cores=2, sockets=1))
            if '/nodes/node-a/qemu/1001/status/current' in argv:
                return json.dumps(dict(pid=43, balloon=4294967296, status='running', cpus=2))
            if argv[1] == 'show': return 'ActiveState=active\nSubState=running\nResult=success\nInvocationID=synthetic-id\n'
            raise AssertionError('unexpected native command')
        def process(self, pid):
            assert pid == 43
            return dict(start_ticks=12, rss_bytes=67108864, arguments=['qemu-system-x86_64','-uuid','uuid-a'])
    source = Sources(); sample = m.NativeSampler(c, source, clock=lambda: 100).sample()
    row = sample['native']['vms'][0]
    assert row['assigned_bytes'] == 4294967296 and row['qemu_rss_bytes'] == 67108864
    assert row['configured_max_bytes'] == 8589934592 and row['qemu_start_ticks'] == 12
    assert row['online_vcpus'] == row['configured_vcpus'] == 2
    assert row['coverage']['generation'] == 'boot-a:43:12'
    assert sample['services'][0]['active_state'] == 'active'
    native_calls = [a for kind,a in source.calls if kind == 'run']
    assert len(native_calls) == 4 and all('list' not in a for a in native_calls)
    assert all(not any(word in ' '.join(a) for word in ['start ', 'set ', 'refresh', 'qualify']) for a in native_calls)


def test_positive_libvirt_sampler_keeps_birth_and_online_cpu_unknown():
    m = module('native_monitoring'); c = config()
    c['scopes'].update(backend='libvirt', version='fixture-v1', vms=[dict(vm_id='vm-a', native_id='uuid-a', uuid='uuid-a')])
    class Sources(LiteralSources):
        def run(self, argv, **kwargs):
            self.calls.append(('run', argv))
            if 'version' in argv: return 'fixture-v1'
            assert argv[:3] == [c['tools']['virsh'], '--connect', 'qemu:///system']
            assert argv[-1] == 'uuid-a'
            if 'dumpxml' in argv: return '<domain><uuid>uuid-a</uuid><memory unit="MiB">8192</memory><currentMemory unit="MiB">4096</currentMemory><vcpu>2</vcpu></domain>'
            if 'dommemstat' in argv: return 'actual 4194304\nrss 65536\n'
            if 'domstate' in argv: return 'running\n'
            raise AssertionError('unexpected native command')
    row = m.NativeSampler(c, Sources(), clock=lambda: 100).sample()['native']['vms'][0]
    assert row['power_state'] == 'running' and row['assigned_bytes'] == 4294967296
    assert row['qemu_pid'] is row['qemu_start_ticks'] is row['online_vcpus'] is None
    assert row['qemu_rss_bytes'] == 67108864
    assert any(r['code'] == 'qemu_birth_not_measured' for r in row['coverage']['reasons'])



@pytest.mark.parametrize('now,expected', [(100, 'fresh'), (200, 'stale'), (50, 'inconsistent')])
def test_public_native_read_normalizes_actual_protected_cache_without_effects(monkeypatch, now, expected):
    m = module('native_monitoring'); r = module('monitoring_runtime')
    import release_trust, time, os
    c = config(); sample = m.NativeSampler(c, LiteralSources(), clock=lambda: 100).sample()
    vm = m.vm_row('vm-a'); vm.update(observed_at=100)
    vm['coverage'].update(observed_at=100, status='fresh', complete=True)
    sample['native']['vms'] = [vm]
    sample['native']['oom']['coverage'].update(observed_at=100, status='fresh', complete=True, reasons=[])
    service = dict(service_id='svc', active_state='active', sub_state='running', result='success',
                   invocation_id='synthetic', observed_at=100, coverage=m.coverage('svc', 100, status='fresh'))
    sample['services'] = [service]
    storage = r.unknown_storage(100); storage.update(status='qualified', persist_permitted=True)
    from slurm_context import empty_context
    value = dict(config_generation=r.digest(c), **sample, journal_cursor=None, cgroups={}, storage=storage,
        current_context=empty_context(c,now=100),host_packets=[],sampler_boot_id='boot-a')
    wire = json.dumps(value).encode(); original = copy.deepcopy(value)
    monkeypatch.setattr(r, 'load_config', lambda: c)
    monkeypatch.setattr(release_trust, 'read_protected_file', lambda *a, **kw: wire)
    monkeypatch.setattr(time, 'time', lambda: now)
    def forbidden(*a, **kw): raise AssertionError('read must not write/probe')
    monkeypatch.setattr(r, 'sample_native_status', forbidden)
    monkeypatch.setattr(r.StorageBoundary, 'read', forbidden)
    import application_release, host_resource_projection
    monkeypatch.setattr(application_release, 'command', forbidden)
    monkeypatch.setattr(host_resource_projection, 'read_resource_projection', lambda **kw: None)
    for name in ('mkdir', 'write', 'fsync', 'rename', 'unlink'):
        monkeypatch.setattr(os, name, forbidden)
    view = m.read_native_status()
    assert view['observed_at'] == 100 and view['coverage']['status'] == expected
    assert view['vms'][0]['coverage']['status'] == expected
    assert view['oom']['coverage']['status'] == expected
    packet = r.observe_local(dict(schema='qcl.cluster-query.v1', request_id=None, cursor=None, limit=64))
    assert packet['native']['coverage']['status'] == expected
    assert packet['services'][0]['coverage']['status'] == expected
    assert packet['services'][0]['observed_at'] == 100
    assert packet['storage']['observed_at'] == 100
    assert packet['storage']['persist_permitted'] is (now == 100)
    assert json.loads(wire) == original  # timestamp/source cache never rewritten


def test_native_freshness_is_per_source_and_preserves_unknown_and_event_evidence(monkeypatch):
    m = module('native_monitoring'); r = module('monitoring_runtime'); import time
    c = config(); native = m.empty_native('host-a', observed_at=100)
    native['coverage'].update(observed_at=100, status='fresh')
    vm = m.vm_row('vm-a'); vm.update(observed_at=80); vm['coverage'].update(observed_at=80, status='fresh')
    other = m.vm_row('vm-b'); other['coverage']['status'] = 'unsupported'
    native['vms'] = [vm, other]
    native['oom']['coverage'].update(observed_at=120, status='fresh')
    event = dict(event_id='e', cause='unknown', scope='unknown', vm_id=None, workload=None,
                 host_boot_id='boot-a', guest_boot_id=None, event_at=1, source_id='journal',
                 native_generation=None, confidence='unknown', reasons=[])
    native['oom']['events'] = [event]
    original = copy.deepcopy(native)
    monkeypatch.setattr(r, 'load_config', lambda: c)
    monkeypatch.setattr(r, 'read_cache', lambda _: dict(native=native))
    monkeypatch.setattr(time, 'time', lambda: 100)
    view = m.read_native_status()
    assert view['coverage']['status'] == 'fresh'
    assert view['vms'][0]['coverage']['status'] == 'stale'
    assert view['vms'][1]['coverage']['status'] == 'unsupported'
    assert view['oom']['coverage']['status'] == 'inconsistent'
    assert view['oom']['events'] == [event] and native == original


def test_structured_manager_unit_oom_is_observed_but_never_qemu_victim():
    import native_monitoring as m
    assert hasattr(m,'parse_manager_oom'), 'missing native unit OOM source'
    record=dict(MESSAGE_ID='fe6faa94e7774663a0da52717891d8ef', UNIT='qemu-fixture.scope',
        INVOCATION_ID='a'*32, _PID='1', _UID='0', _COMM='systemd', _EXE='/usr/lib/systemd/systemd',
        _BOOT_ID='boot-a', __MONOTONIC_TIMESTAMP='2000000', __REALTIME_TIMESTAMP='100000000', __CURSOR='cursor-a')
    bindings=[dict(unit_id='unit-a',unit='qemu-fixture.scope',invocation_id='a'*32,vm_id='vm-a',
        manager_executable='/usr/lib/systemd/systemd',monotonic_us=3000000)]
    event=m.parse_manager_oom([record],bindings,host_boot_id='boot-a')[0]
    assert event['cause']=='native_unit_kernel_oom' and event['victim_kind']=='unknown'
    assert event['confidence']=='observed' and event['vm_id']=='vm-a'
    assert event['unit_invocation_id']=='a'*32
    old={**record,'INVOCATION_ID':'b'*32}
    assert m.parse_manager_oom([old],bindings,host_boot_id='boot-a')[0]['vm_id'] is None
    for change in [dict(_PID='2'),dict(_UID='1000'),dict(_EXE='/fake/systemd'),dict(_BOOT_ID='other'),dict(__MONOTONIC_TIMESTAMP='4000000')]:
        assert not m.parse_manager_oom([{**record,**change}],bindings,host_boot_id='boot-a')
    record['MESSAGE_ID']='d989611b15e44c9dbf31e3c81256e4ed'
    assert m.parse_manager_oom([record],bindings,host_boot_id='boot-a')[0]['cause']=='native_unit_oomd'
    assert m.empty_native('host-a')['capabilities']['kernel_qemu_victim_join']['status']=='unsupported'


@pytest.mark.parametrize('cycle_drift', [False,True])
def test_actual_sampler_integrates_structured_unit_protocol_without_victim_guess(cycle_drift):
    m=module('native_monitoring');c=config();c['scopes'].update(journal=True,manager_version='systemd 257 (257.13)',
        units=[dict(unit_id='unit-a',unit='fixture.scope',vm_id=None,manager_executable='/usr/lib/systemd/systemd')])
    record=dict(MESSAGE_ID='fe6faa94e7774663a0da52717891d8ef',UNIT='fixture.scope',INVOCATION_ID='a'*32,
        _PID='1',_UID='0',_COMM='systemd',_EXE='/usr/lib/systemd/systemd',_BOOT_ID='boot-a',
        __MONOTONIC_TIMESTAMP='1',__REALTIME_TIMESTAMP='90000000',__CURSOR='fixture-cursor')
    class Sources(LiteralSources):
        count=0
        def run(self,argv,**kw):
            self.calls.append(('run',argv))
            if argv[0].endswith('journalctl'):return json.dumps(record)
            if argv[1:]==['--version']:return 'systemd 257 (257.13)'
            if argv[1]=='show':
                self.count+=1
                invocation='b' if cycle_drift and self.count>2 else 'a'
                return 'Id=fixture.scope\nControlGroup=/qemu.slice/fixture.scope\nInvocationID='+invocation*32+'\n'
            raise AssertionError('unexpected protocol argv')
    s=Sources();native=m.NativeSampler(c,s,clock=lambda:100).sample()['native']
    assert native['capabilities']['kernel_qemu_victim_join']['status']=='unsupported'
    if cycle_drift:
        assert native['capabilities']['systemd_manager_unit_oom']['status']=='inconsistent' and native['oom']['events']==[]
    else:
        assert native['capabilities']['systemd_manager_unit_oom']['status']=='fresh'
        assert native['oom']['events'][0]['cause']=='native_unit_kernel_oom'
        assert native['oom']['events'][0]['victim_kind']=='unknown'


def test_unit_oom_does_not_replace_unknown_vm_loss_with_a_victim_claim():
    m=module('native_monitoring');c=config()
    c['scopes'].update(backend='pve',node='node-a',version='fixture-version',journal=True,
        manager_version='systemd 257 (257.13)',vms=[dict(vm_id='vm-a',native_id='17',uuid='uuid-a')],
        units=[dict(unit_id='unit-a',unit='fixture.scope',vm_id='vm-a',manager_executable='/usr/lib/systemd/systemd')])
    record=dict(MESSAGE_ID='fe6faa94e7774663a0da52717891d8ef',UNIT='fixture.scope',INVOCATION_ID='a'*32,
        _PID='1',_UID='0',_COMM='systemd',_EXE='/usr/lib/systemd/systemd',_BOOT_ID='boot-a',
        __MONOTONIC_TIMESTAMP='1',__REALTIME_TIMESTAMP='90000000',__CURSOR='fixture-cursor')
    class Sources(LiteralSources):
        def process(self,pid):return dict(arguments=['uuid-a'],start_ticks=12,rss_bytes=4096)
        def run(self,argv,**kw):
            if argv[0].endswith('journalctl'):return json.dumps(record)
            if argv[1:]==['--version']:return 'systemd 257 (257.13)'
            if argv[1]=='show':return 'Id=fixture.scope\nControlGroup=/qemu.slice/fixture.scope\nInvocationID='+'a'*32+'\n'
            if '/version' in argv:return 'fixture-version'
            if any(x.endswith('/config') for x in argv):return json.dumps(dict(memory=1024,smbios1='uuid=uuid-a'))
            if any(x.endswith('/status/current') for x in argv):return json.dumps(dict(status='paused',pid=43))
            raise AssertionError('unexpected source command')
    prior=m.empty_native('host-a',observed_at=80);prior['host_boot_id']='boot-a'
    row=m.vm_row('vm-a');row.update(power_state='running',native_generation='boot-a:43:12');prior['vms']=[row]
    value=m.NativeSampler(c,Sources(),clock=lambda:100,previous=dict(native=prior,journal_cursor=None,cgroups={})).sample()['native']
    causes={e['cause'] for e in value['oom']['events']}
    assert {'native_unit_kernel_oom','unknown_vm_loss'}<=causes
    assert 'host_kernel_qemu_oom' not in causes
