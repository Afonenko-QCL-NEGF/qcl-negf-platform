"""Closed native packets; never invoke a live scheduler, hypervisor or SSH."""
from dataclasses import replace
import json
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops'))
from test_host_resource_operations import setup


def test_slurm_identity_native_generation_and_no_low_guest_fit_precheck():
    from host_resource_facts import parse_slurm_jobs,workload_identity
    raw='JobId=42 UserId=qcl-negf(3000) JobState=RUNNING NumNodes=1 NumTasks=1 NodeList=worker-a SubmitTime=2026-10-28T10:00:00 StartTime=2026-10-28T10:00:01 Restarts=0 MinMemoryNode=512M ArrayJobId=0 HetJobId=0\n'
    jobs=parse_slurm_jobs(raw,cluster='cluster-one')
    row=jobs['42'];assert row['limit_bytes']==512*1024**2
    assert workload_identity(row)==workload_identity(parse_slurm_jobs(raw,cluster='cluster-one')['42'])
    assert workload_identity(row)!=workload_identity({**row,'start_time':'2026-10-28T11:00:00'})
    for bad in (raw.replace('NumNodes=1','NumNodes=2'),raw.replace('512M','0'),raw.replace('Restarts=0','Restarts=1')):
        with pytest.raises(Exception):parse_slurm_jobs(bad,cluster='cluster-one')
    assert parse_slurm_jobs(raw.replace('RUNNING','COMPLETING'),cluster='cluster-one')['42']['terminal'] is False


def test_caller_requires_real_sudo_parent_and_unprivileged_generation_not_environment():
    from host_resource_facts import authenticate_sudo_caller
    records={100:dict(pid=100,ppid=90,uids=[0]*4,start_ticks=10,cgroup='/jobs/job_42/step_batch/user/task_0',executable='/usr/bin/sudo'),
        90:dict(pid=90,ppid=80,uids=[3000]*4,start_ticks=9,cgroup='/jobs/job_42/step_batch/user/task_0',executable='/bin/python')}
    actual=authenticate_sudo_caller({'SUDO_UID':'3000','SUDO_PID':'90'},parent_pid=100,
        process=lambda pid:dict(records[pid]),sudo_executables=('/usr/bin/sudo',),allowed_uid=3000)
    assert actual['pid']==90 and actual['start_ticks']==9
    for change in ('uid','exe','birth','group','fake-env'):
        rows={key:dict(value) for key,value in records.items()};calls={}
        def process(pid):
            calls[pid]=calls.get(pid,0)+1
            row=dict(rows[pid])
            if change=='birth' and calls[pid]>1:row['start_ticks']+=1
            return row
        env={'SUDO_UID':'3000','SUDO_PID':'90'}
        if change=='uid':rows[90]['uids']=[1000]*4
        if change=='exe':rows[100]['executable']='/tmp/sudo'
        if change=='group':rows[90]['cgroup']='/other'
        if change=='fake-env':env['SUDO_UID']='0'
        with pytest.raises(Exception):authenticate_sudo_caller(env,parent_pid=100,process=process,
            sudo_executables=('/usr/bin/sudo',),allowed_uid=3000)


def test_whole_workload_inventory_excludes_only_exact_gate_and_never_unknown_children():
    from host_resource_facts import classify_guest_workloads
    jobs={'42':dict(native_id='42',generation='g42',owner_uid=3000,node='worker-a',terminal=False,state='RUNNING',limit_bytes=321),
          '43':dict(native_id='43',generation='g43',owner_uid=3000,node='worker-a',terminal=False,state='RUNNING',limit_bytes=321)}
    packets={'42':dict(populated=True,processes=[dict(pid=11,start_ticks=1,executable='/gate',uids=[3000]*4)]),
        '43':dict(populated=True,processes=[dict(pid=12,start_ticks=1,executable='/solver',uids=[3000]*4)])}
    known={'slurm:g43':dict(native_id='43',generation='g43',phase='RUN')}
    assert classify_guest_workloads(jobs,packets,known,gate_executables=('/gate',))==('slurm:g43',)
    packets['42']['processes'].append(dict(pid=13,start_ticks=1,executable='/solver',uids=[3000]*4))
    with pytest.raises(Exception):classify_guest_workloads(jobs,packets,known,gate_executables=('/gate',))
    packets['42']['processes'].pop();packets['43']['processes']=[]
    with pytest.raises(Exception):classify_guest_workloads(jobs,packets,known,gate_executables=('/gate',))


def test_inventory_capacity_foreign_bound_and_unmanaged_qemu():
    from host_resource_facts import validate_inventory
    rows=[dict(kind='qemu',native_id='owned',maximum_bytes=100,running=True,process_id='12',config_fingerprint='x'),
          dict(kind='lxc',native_id='foreign',maximum_bytes=200,running=False,process_id=None,config_fingerprint='f')]
    enroll={'vm-a':{'native_id':'owned','maximum_bytes':100}}
    agreement={'foreign':{'maximum_bytes':200,'overhead_bytes':0,'config_fingerprint':'f'}}
    assert validate_inventory(rows,enroll,agreement,foreign_budget=250,observed_qemu_pids={'12'})==200
    for bad in (rows[:-1],rows+[{**rows[1],'native_id':'new'}],[rows[0],{**rows[1],'maximum_bytes':201}]):
        with pytest.raises(Exception):validate_inventory(bad,enroll,agreement,foreign_budget=250,observed_qemu_pids={'12'})
    with pytest.raises(Exception):validate_inventory(rows,enroll,agreement,foreign_budget=250,observed_qemu_pids={'12','13'})



def test_native_guest_cgroup_scan_gates_completion_and_output(tmp_path):
    from host_resource_facts import scan_job_group
    root=tmp_path/'cg';root.mkdir();(root/'memory.max').write_text('321');(root/'cgroup.events').write_text('populated 1\n')
    procs=[dict(pid=11,start_ticks=10,cgroup='/scope/job_42/step_batch/user/task_0',uids=[3000]*4,executable='/gate')]
    assert scan_job_group(root,'/scope/job_42',procs)['memory_max_bytes']==321
    (root/'cgroup.events').write_text('populated 0\n')
    with pytest.raises(Exception):scan_job_group(root,'/scope/job_42',procs)


@pytest.mark.parametrize('foreign_overhead',[0,32])
def test_provider_uses_actual_fixed_inventory_exact_qualification_and_whole_live_snapshot(tmp_path,monkeypatch,foreign_overhead):
    import host_resource_facts as f
    from dataclasses import asdict
    m,c,b,store,e=setup(tmp_path,mechanism='conservative_reservation')
    host=dict(boot_id='host-boot-1',machine_id='machine-host',dmi_uuid='dmi-host',kernel='host-kernel-1',MemTotal=4096,MemAvailable=1024)
    config=dict(host_identity={'machine_id':'machine-host','dmi_uuid':'dmi-host'},agreement='private-agreement',qualification='private-qualification',
        state_directory=str(store.directory),evidence=str(store.directory/'probe.json'),readback_version='readback-v1',
        enrollment={vm.vm_id:dict(native_id='native-'+vm.vm_id,maximum_bytes=1536,machine_id='machine-'+vm.vm_id,os_reserve_bytes=128) for vm in c.policy.vms},
        qualified_protocols={vm.vm_id:dict(guest_protocol='synthetic-protocol',qemu_birth_ticks=9,gate_executables=['/gate']) for vm in c.policy.vms})
    agreement=dict(schema='qcl.host-resource-native-agreement.v1',policy_sha256=m.policy_digest(c.policy),agreement_ref='synthetic-agreement',foreign={'foreign':dict(maximum_bytes=224,overhead_bytes=foreign_overhead,config_fingerprint='f')})
    qualifications=dict(schema='qcl.host-resource-qualification.v1',qualifications=[asdict(q) for q in e.qualifications])
    monkeypatch.setattr(f,'read_root_json',lambda path:agreement if path=='private-agreement' else qualifications)
    monkeypatch.setattr(f,'collect_native_runtime',lambda backend,read:__import__('host_resource_backends').NativeRuntimeFacts('host-boot-1','host-kernel-1','qemu-1','backend-1'))
    for vm,row in list(b.rows.items()):b.rows[vm]=replace(row,process_id='12' if vm=='vm-a' else '13')
    # Exact protected bindings are administrative input; actual process and guest
    # identities still have to match every field, no injected true flags suffice.
    for q in qualifications['qualifications']:q['binding']['process_id']='12' if q['binding']['vm_id']=='vm-a' else '13'
    class Sources:
        bad=False
        def host(self):return dict(host)
        def inventory(self,backend):
            rows=[dict(kind='qemu',native_id='native-'+vm.vm_id,maximum_bytes=1536,running=True,
                process_id='12' if vm.vm_id=='vm-a' else '13',config_fingerprint='config-1') for vm in c.policy.vms]
            return rows+[dict(kind='lxc',native_id='foreign',maximum_bytes=224,running=False,process_id=None,config_fingerprint='drift' if self.bad else 'f')]
        def processes(self):return [dict(pid=pid,executable='/usr/bin/qemu-system-x86_64') for pid in (12,13)]
        def process(self,pid):return {'start_ticks':9}
        def guest(self,vm):
            identity=dict(machine_id='machine-'+vm,dmi_uuid='native-'+vm,boot_id='guest-boot-1',image_id='image-1',kernel='guest-kernel-1')
            return dict(schema='qcl.host-resource-guest-facts.v1',protocol='synthetic-protocol',observed_at=100,
                identity_before=identity,identity_after=identity,jobs={},groups={},outputs={},memory={'MemTotal':1536,'MemAvailable':1},slurm_memory_bytes=1408)
    source=Sources();p=f.NativeFactsProvider(c.policy,config,b,None,sources=source,clock=lambda:100)
    monkeypatch.setattr(p,'_persist',lambda *args:None)
    facts=p.request_facts(None,owner_state=store.load())
    assert facts.physical_ram_bytes==4096 and facts.foreign_max_bytes==256
    assert facts.live_workloads=={'vm-a':(),'vm-b':()}
    # Guest available=1 did not preempt a future host grant; capacity is admitted later.
    source.bad=True
    with pytest.raises(m.ResourceError,match='capacity_evidence'):p.request_facts(None,owner_state=store.load())
    assert p.cleanup('request',owner_state=store.load()) is None


def test_store_trust_reuses_exact_p12_reader_only_for_store_members(monkeypatch):
    import host_resource_backends as b
    import runtime_bindings as r
    called=[]
    monkeypatch.setattr(r,'read_store_file',lambda path,limit:called.append((str(path),limit)) or b'version')
    assert str(b.trusted_root_path('/nix/store/synthetic-system',directory=True))=='/nix/store/synthetic-system'
    assert called==[('/nix/store/synthetic-system/nixos-version',4096)]
    with pytest.raises(Exception):b.trusted_root_path('/tmp/not-trusted')
    assert len(called)==1


def test_cold_facts_reports_actual_configured_max_never_policy_substitution():
    import host_resource_facts as f
    class VM:vm_id='vm-a';maximum_bytes=1024
    class Policy:
        vms=(VM(),);host_id='host';owner_id='owner';capacity_evidence_ref='capacity'
        class reserves:foreign_max_bytes=0;safety_bytes=64
        class owned_pool:agreement_ref='agreement'
    provider=f.NativeFactsProvider.__new__(f.NativeFactsProvider)
    provider.policy=Policy();provider.clock=lambda:100
    provider.config={'enrollment':{'vm-a':{'native_id':'native-a'}}}
    provider._host_inventory=lambda:({'boot_id':'boot','MemTotal':4096,'MemAvailable':3000},
        [dict(native_id='native-a',maximum_bytes=2048,config_fingerprint='config',running=False)],{})
    original=f.policy_digest
    try:
        f.policy_digest=lambda policy:'digest'
        result=provider.cold_facts()
    finally:f.policy_digest=original
    assert result.vms[0].configured_max_bytes==2048 and result.vms[0].initial_peak_bytes==2048


def test_closed_fixed_native_packets_use_full_allocation_never_rss_or_config_only():
    import host_resource_backends as b
    from test_host_resource_backends import Commands
    packet=json.loads((Path(__file__).parent/'fixtures/host-resources/synthetic-native-packets.json').read_text())
    pve=('/usr/bin/pvesh','get','/nodes/synthetic-node/qemu/101')
    commands=Commands([(pve[:-1]+(pve[-1]+'/config','--current','1','--output-format','json'),json.dumps(packet['pve_config'])),
        (pve[:-1]+(pve[-1]+'/status/current','--output-format','json'),json.dumps(packet['pve_status']))])
    backend=b.ProxmoxMemoryBackend(commands,'/usr/bin/pvesh','synthetic-node',{'vm-a':b.ProxmoxVM(101,'11111111-1111-4111-8111-111111111111')},dynamic=False)
    row=backend.readback('vm-a');assert row.configured_bytes==row.assigned_bytes==1024**3
    assert row.assigned_bytes!=packet['pve_status']['mem']
    native=__import__('host_resource_facts').parse_slurm_jobs(packet['slurm_oneline'],cluster='synthetic-cluster')['42']
    assert native['limit_bytes']==512*1024**2


def test_scheduler_generation_joins_actual_cluster_and_controller_not_config_label(monkeypatch):
    import host_resource_facts as f
    packet=json.loads((Path(__file__).parent/'fixtures/host-resources/synthetic-native-packets.json').read_text())
    monkeypatch.setattr(f,'trusted_root_path',lambda path,**kw:Path(path))
    config={'slurm_conf':'/protected/slurm.conf','scontrol':'/protected/scontrol','slurm_version':'slurm synthetic-1',
        'cluster':'synthetic-cluster','slurmctld_hosts':['controller-a(primary)']}
    class Source:
        controller='controller-a(primary)';calls=[]
        def run(self,argv):
            self.calls.append(argv)
            if argv[-1]=='--version':return 'slurm synthetic-1'
            if argv[-1]=='config':return 'ClusterName = synthetic-cluster\nSlurmctldHost[0] = '+self.controller+'\n'
            return packet['slurm_oneline']
    source=Source();assert f.capture_scheduler(config,source)['42']['native_id']=='42'
    assert ['/protected/scontrol','show','config'] in source.calls
    source.controller='other-controller(primary)'
    with pytest.raises(Exception):f.capture_scheduler(config,source)


def test_native_trust_rejects_traversal_before_any_filesystem_observation(monkeypatch):
    import host_resource_backends as b
    calls=[]
    from types import SimpleNamespace
    import stat
    def info(path):
        calls.append(str(path))
        return SimpleNamespace(st_uid=0,st_mode=(stat.S_IFREG|0o644) if path.name=='leaf' else (stat.S_IFDIR|0o755))
    monkeypatch.setattr(Path,'lstat',info);monkeypatch.setattr(Path,'stat',info)
    with pytest.raises(b.ResourceError,match='trust'):b.trusted_root_path('/protected/../protected/leaf')
    assert calls==[]


def inventory_packet():
    rows=[dict(kind='qemu',native_id='owned',maximum_bytes=100,running=True,process_id='12',config_fingerprint='x'),
          dict(kind='lxc',native_id='foreign',maximum_bytes=200,running=False,process_id=None,config_fingerprint='f')]
    return rows,{'vm-a':dict(native_id='owned',maximum_bytes=100)}, {'foreign':dict(maximum_bytes=200,overhead_bytes=0,config_fingerprint='f')}


@pytest.mark.parametrize('overhead', [0,50])
def test_inventory_pays_full_foreign_maximum_plus_explicit_overhead(overhead):
    from host_resource_facts import validate_inventory
    rows,enrolled,foreign=inventory_packet();foreign['foreign']['overhead_bytes']=overhead
    assert validate_inventory(rows,enrolled,foreign,foreign_budget=250,observed_qemu_pids={'12'})==200+overhead
    with pytest.raises(__import__('host_resource_operations').ResourceError,match='capacity_evidence'):
        validate_inventory(rows,enrolled,foreign,foreign_budget=199+overhead,observed_qemu_pids={'12'})


@pytest.mark.parametrize('field', ['native_maximum','enrollment_maximum','foreign_maximum','overhead','foreign_budget'])
@pytest.mark.parametrize('bad', [-1000,True,False,1.0,'200',None,2**63])
def test_inventory_all_contributing_bytes_are_strict_integers(field,bad):
    from host_resource_facts import validate_inventory
    rows,enrolled,foreign=inventory_packet();budget=256
    if field=='native_maximum':rows[1]['maximum_bytes']=bad
    if field=='enrollment_maximum':enrolled['vm-a']['maximum_bytes']=bad
    if field=='foreign_maximum':foreign['foreign']['maximum_bytes']=bad
    if field=='overhead':foreign['foreign']['overhead_bytes']=bad
    if field=='foreign_budget':budget=bad
    with pytest.raises(__import__('host_resource_operations').ResourceError,match='shape'):
        validate_inventory(rows,enrolled,foreign,foreign_budget=budget,observed_qemu_pids={'12'})


@pytest.mark.parametrize('change', ['missing_native_max','missing_enrolled_max','missing_agreed_max','missing_overhead',
    'missing_fingerprint','missing_native_id','missing_foreign','unknown_native','duplicate_native','duplicate_enrollment',
    'foreign_is_owned','agreement_max_drift','config_drift','zero_native_max','zero_agreed_max','zero_enrolled_max'])
def test_inventory_incomplete_or_conflicting_administration_fails_closed(change):
    from host_resource_facts import validate_inventory
    from host_resource_operations import ResourceError
    rows,enrolled,foreign=inventory_packet()
    if change=='missing_native_max':del rows[1]['maximum_bytes']
    if change=='missing_enrolled_max':del enrolled['vm-a']['maximum_bytes']
    if change=='missing_agreed_max':del foreign['foreign']['maximum_bytes']
    if change=='missing_overhead':del foreign['foreign']['overhead_bytes']
    if change=='missing_fingerprint':del foreign['foreign']['config_fingerprint']
    if change=='missing_native_id':del rows[1]['native_id']
    if change=='missing_foreign':rows.pop()
    if change=='unknown_native':rows.append({**rows[1],'native_id':'unknown'})
    if change=='duplicate_native':rows.append(dict(rows[1]))
    if change=='duplicate_enrollment':enrolled['vm-b']=dict(enrolled['vm-a'])
    if change=='foreign_is_owned':foreign['owned']=foreign.pop('foreign')
    if change=='agreement_max_drift':foreign['foreign']['maximum_bytes']=199
    if change=='config_drift':foreign['foreign']['config_fingerprint']='changed'
    if change=='zero_native_max':rows[1]['maximum_bytes']=0
    if change=='zero_agreed_max':foreign['foreign']['maximum_bytes']=0
    if change=='zero_enrolled_max':enrolled['vm-a']['maximum_bytes']=0
    with pytest.raises(ResourceError):
        validate_inventory(rows,enrolled,foreign,foreign_budget=256,observed_qemu_pids={'12'})


@pytest.mark.parametrize('route', ['cold','live'])
@pytest.mark.parametrize('overhead', [0,56,-744,-1000,True,1.0,'0',None,'healthy-zero','healthy-positive','wrong-policy','wrong-agreement'])
def test_native_facts_cold_and_live_share_same_foreign_capacity_boundary(tmp_path,monkeypatch,route,overhead):
    import host_resource_facts as f
    m,c,b,store,e=setup(tmp_path,mechanism='conservative_reservation')
    config=dict(host_identity={'machine_id':'host-machine','dmi_uuid':'host-dmi'},agreement='protected-agreement',
        enrollment={vm.vm_id:dict(native_id='native-'+vm.vm_id,maximum_bytes=vm.maximum_bytes) for vm in c.policy.vms})
    healthy=overhead in ('healthy-zero','healthy-positive')
    actual=200 if healthy else 1000
    agreement=dict(schema='qcl.host-resource-native-agreement.v1',policy_sha256=m.policy_digest(c.policy),
        agreement_ref=c.policy.owned_pool.agreement_ref,foreign={'foreign':dict(maximum_bytes=actual,overhead_bytes=(56 if overhead=='healthy-positive' else 0) if healthy else overhead,config_fingerprint='foreign-static')})
    if overhead=='wrong-policy':agreement['policy_sha256']='0'*64
    if overhead=='wrong-agreement':agreement['agreement_ref']='other-agreement'
    class Sources:
        def host(self):return dict(boot_id='host-boot-1',machine_id='host-machine',dmi_uuid='host-dmi',kernel='host-kernel-1',MemTotal=4096,MemAvailable=2048)
        def inventory(self,backend):return [dict(kind='qemu',native_id='native-'+vm.vm_id,maximum_bytes=vm.maximum_bytes,running=False,process_id=None,config_fingerprint='config-1') for vm in c.policy.vms]+[dict(kind='lxc',native_id='foreign',maximum_bytes=actual,running=False,process_id=None,config_fingerprint='foreign-static')]
        def processes(self):return []
    monkeypatch.setattr(f,'read_root_json',lambda path:agreement)
    provider=f.NativeFactsProvider(c.policy,config,b,None,sources=Sources(),clock=lambda:100)
    before=store.state_path.read_bytes()
    if healthy and route=='live':
        # Exercise the exact shared capacity gate; full live qualification is
        # covered separately by the running-provider positive controls.
        host,rows,observed=provider._host_inventory()
        assert host['MemTotal']==4096 and rows[-1]['maximum_bytes']==200 and observed==agreement
    elif healthy:
        import os
        from host_resource_startup import StartupManager
        cold_store=m.FileReceiptStore(tmp_path/'cold',owner_uid=os.getuid())
        startup=StartupManager(c.policy,cold_store,b,clock=lambda:100)
        views=startup.prepare_start_reservations(cold_evidence=provider.cold_facts())
        assert sum(v['charged_bytes'] for v in views)==3072
    else:
        # Stopped owned VMs are not a live request snapshot, even with healthy F.
        with pytest.raises(m.ResourceError):
            if route=='cold':provider.cold_facts()
            else:provider.request_facts(None,owner_state=store.load())
    assert store.state_path.read_bytes()==before and not b.calls


def _pve_inventory_source(memory, *, lxc_only=False):
    from host_resource_facts import LocalSources
    class Backend:
        node = 'synthetic-node'
        def _run(self, args):
            if args == ['get', '/nodes/synthetic-node/qemu']:
                return json.dumps([] if lxc_only else [{'vmid': 101}])
            if args == ['get', '/nodes/synthetic-node/lxc']:
                return json.dumps([{'vmid': 102}])
            if args[-2:] == ['--current', '1']:
                return json.dumps({'memory': memory, 'digest': 'raw-digest', 'smbios1': 'uuid=owned'})
            return json.dumps({'status': 'stopped'})
    return LocalSources({'backend_config': {'backend': 'proxmox'}}, None), Backend()


@pytest.mark.parametrize('memory', ['4096', 4096])
def test_pve_cold_inventory_converts_qemu_and_lxc_mib_preserving_raw_fingerprint(memory, monkeypatch):
    import host_resource_backends as m
    fingerprint = m.pve_config_fingerprint
    seen = []
    def capture(raw):
        seen.append(dict(raw))
        return fingerprint(raw)
    monkeypatch.setattr(m, 'pve_config_fingerprint', capture)
    sources, backend = _pve_inventory_source(memory)
    rows = sources.inventory(backend)
    raw = {'memory': memory, 'digest': 'raw-digest', 'smbios1': 'uuid=owned'}
    expected = fingerprint(raw)
    assert [r['kind'] for r in rows] == ['qemu', 'lxc']
    assert all(r['maximum_bytes'] == 4096 * 1024**2 and r['config_fingerprint'] == expected for r in rows)
    assert all(not r['running'] and r['process_id'] is None for r in rows)
    assert seen == [raw, raw] and all(type(row['memory']) is type(memory) for row in seen)


@pytest.mark.parametrize('memory', [True, False, 1.0, None, -1, '-1', '0', 0,
    '', '01', '+1', ' 1', '1 ', '1.0', '1MiB', '١', pytest.param('9' * 5000, id='oversize'),
    str(((2**63-1)//(1024**2))+1), ((2**63-1)//(1024**2))+1])
def test_pve_cold_inventory_rejects_invalid_memory_before_byte_arithmetic(memory):
    from host_resource_operations import ResourceError
    sources, backend = _pve_inventory_source(memory)
    with pytest.raises(ResourceError):
        sources.inventory(backend)


@pytest.mark.parametrize('memory', ['01', True, str(2**43)])
def test_pve_lxc_only_inventory_rejects_invalid_memory(memory):
    from host_resource_operations import ResourceError
    sources, backend = _pve_inventory_source(memory, lxc_only=True)
    with pytest.raises(ResourceError):
        sources.inventory(backend)
