"""Synthetic Source/L fixed qualification; no native commands or policy migration."""
from copy import deepcopy
from dataclasses import asdict, replace
import os
import hashlib
import json
from types import SimpleNamespace
from pathlib import Path

import pytest

from test_native_attempt import p20_worker, p20_runner
from test_host_resource_facts import output_packet


@pytest.fixture
def fixed_provider(tmp_path, monkeypatch):
    import host_resource_facts as f
    import host_resource_operations as m
    from host_resource_backends import NativeRuntimeFacts,pve_config_fingerprint
    MiB = 1024**2
    policy = m.validate_host_resource_policy(dict(schema='qcl.host-resource-policy.v1',
        host_id='host',owner_id='owner',physical_ram_bytes=4096*MiB,capacity_evidence_ref='capacity',
        reserves=dict(host_services_bytes=128*MiB,control_plane_bytes=64*MiB,safety_bytes=64*MiB,
            foreign_max_bytes=256*MiB,evidence_ref='reserves'),
        owned_pool=dict(capacity_bytes=3584*MiB,agreement_ref='agreement',enforceable=True,
            foreign_growth_bounded=True,active_grants_protected=True),
        active_grant=dict(mechanism='conservative_reservation',qualification_ref='fixed-proof'),
        timeouts=dict(request_seconds=30,grow_seconds=30,shrink_seconds=30,reconcile_seconds=60),
        vms=[dict(vm_id='vm',owner_id='owner',resident=True,minimum_bytes=100*MiB,startup_bytes=1000*MiB,
            maximum_bytes=1000*MiB,overhead_bytes=64*MiB,overhead_evidence_ref='overhead',cpu_weight=100,memory_weight=100)]))
    worker=p20_worker('worker-a');runner=p20_runner();identity={**worker['identity'],'image_id':'/nix/store/synthetic-image'}
    native_config=dict(memory=1000,balloon=0,shares=0,smbios1='uuid='+identity['dmi_uuid'],digest='fixed-revision')
    config_fingerprint=pve_config_fingerprint(native_config)
    binding=m.RuntimeBinding('vm',identity['dmi_uuid'],'12',''+identity['boot_id'],identity['image_id'],identity['kernel'],
        'host-kernel','qemu-version','backend-version','qcl.native-memory.fixed.v1',config_fingerprint)
    row=asdict(m.BackendQualification('host','owner',binding,m.policy_digest(policy),'fixed-proof',False,True,True,True))
    bundle=dict(schema='qcl.host-resource-qualification.v1',qualifications=[row])
    owner=deepcopy(next(iter(output_packet()['outputs'].values()))['owner']);owner['source_graph_sha256']=runner['source_graph_sha256']
    config=dict(qualification='/protected/qualification',client_uid=3000,agreement='/protected/agreement',
        state_directory=str(tmp_path/'state'),evidence=str(tmp_path/'state'/'probe.json'),
        readback_version='qcl.native-memory.fixed.v1',host_identity=dict(machine_id='host-machine',dmi_uuid='host-dmi'),
        nodes={'worker-a':'vm'},guests={'vm':{}},scheduler_route={},
        enrollment={'vm':dict(native_id=binding.native_id,maximum_bytes=1000*MiB,machine_id=identity['machine_id'],os_reserve_bytes=60*MiB)},
        qualified_protocols={'vm':dict(guest_protocol='fixed-guest-protocol',qemu_birth_ticks=9,gate_executables=['/gate'])},
        output_owner=dict(owner=owner,controller_identity=deepcopy(worker['identity']),runner=deepcopy(runner),
            worker_generations={'worker-a':deepcopy(worker)}))
    guest=dict(schema='qcl.host-resource-guest-facts.v1',protocol='fixed-guest-protocol',identity_before=identity,
        identity_after=deepcopy(identity),output_generation=dict(worker=worker,runner=runner),observed_at=100,
        memory=dict(MemTotal=980*MiB,MemAvailable=900*MiB),slurm_memory_bytes=900*MiB,slurm_registered=True,
        jobs={},groups={},outputs={})
    host=dict(boot_id='host-boot',machine_id='host-machine',dmi_uuid='host-dmi',kernel='host-kernel',MemTotal=4096*MiB,MemAvailable=1024*MiB)
    agreement=dict(schema='qcl.host-resource-native-agreement.v1',policy_sha256=m.policy_digest(policy),agreement_ref='agreement',foreign={})
    data={'/protected/qualification':bundle,'/protected/agreement':agreement,
        str(f.SERVICE_CONFIG):dict(schema='qcl.host-resource-service.v1',role='native_host',client_uid=3000,facts=deepcopy(config))}
    monkeypatch.setattr(f,'read_root_json',lambda path:deepcopy(data[str(path)]))
    runtime=NativeRuntimeFacts('host-boot','host-kernel','qemu-version','backend-version')
    monkeypatch.setattr(f,'collect_native_runtime',lambda backend,read:runtime)
    read=m.VMReadback('vm',binding.native_id,'12',config_fingerprint,'fixed-revision',1000*MiB,1000*MiB,True)
    backend=SimpleNamespace(quantum_bytes=MiB,readback=lambda vm:read)
    class Sources:
        birth=9
        full_reads=0
        identity_reads=0
        def host(self):return deepcopy(host)
        def inventory(self,backend):return [dict(kind='qemu',native_id=binding.native_id,maximum_bytes=1000*MiB,running=True,
            process_id='12',config_fingerprint=config_fingerprint)]
        def processes(self):return [dict(pid=12,executable='/usr/bin/qemu-system-x86_64')]
        def process(self,pid):assert pid==12;return dict(start_ticks=self.birth)
        def fixed_native(self,backend,vm):assert vm=='vm';return dict(backend='proxmox',configuration=deepcopy(native_config))
        def guest(self,vm):assert vm=='vm';self.full_reads+=1;return deepcopy(guest)
        def guest_identity(self,vm):assert vm=='vm';self.identity_reads+=1;return dict(identity=deepcopy(identity))
    sources=Sources();provider=f.NativeFactsProvider(policy,config,backend,None,sources=sources,clock=lambda:100)
    store=m.FileReceiptStore(tmp_path/'state',owner_uid=os.getuid())
    # Actual file persistence and journal remain real; only the Root-owned path
    # boundary maps to this explicit unprivileged fixture directory.
    def fixture_path(path,**kwargs):
        path=Path(path)
        assert path in (store.directory,store.directory/'probe.json')
        return path
    monkeypatch.setattr(f,'trusted_root_path',fixture_path)
    open_existing=m.FileReceiptStore.open_existing
    monkeypatch.setattr(m.FileReceiptStore,'open_existing',lambda path,**kwargs:open_existing(path,owner_uid=os.getuid()))
    controller=m.HostResourceController(policy,store,backend,clock=lambda:100)
    return SimpleNamespace(f=f,m=m,p=provider,bundle=bundle,binding=binding,g=guest,data=data,host=host,source=sources,
        read=read,controller=controller,store=store,MiB=MiB,agreement=agreement,native_config=native_config)


def qualify(x):
    return x.p._qualification(x.bundle,x.binding,x.g,host_boot_id='host-boot')


def test_fixed_positive_profile_has_no_dynamic_capacity_or_dynamic_claim(fixed_provider):
    x=fixed_provider;value=qualify(x)
    assert type(value)is x.m.BackendQualification
    assert value.qualified_dynamic is False
    assert value.active_floor_protection and value.readback_verified and value.slurm_registration_verified
    assert not hasattr(value,'capacity')


@pytest.mark.parametrize('fault',['dynamic-policy','dynamic-claim','not-full','unsettled','process-drift','wrong-protocol',
    'unregistered','stale','image-drift','future','missing-source','missing-pins','runner-drift','worker-birth',
    'native-birth','guest-protocol','enrollment-machine','invalid-total','invalid-available','slurm-too-large',
    'wrong-ref','partial-positive','native-stopped','host-runtime','protected-drift','qualification-drift',
    'balloon-enabled','missing-native-config','native-config-drift','native-birth-drift','source-pin-drift'])
def test_fixed_metadata_cannot_supply_unsupported_or_stale_authority(fixed_provider,monkeypatch,fault):
    x=fixed_provider;g=x.g;p=x.p;row=x.bundle['qualifications'][0]
    if fault=='dynamic-policy':p.policy=replace(p.policy,active_grant=replace(p.policy.active_grant,mechanism='qualified_dynamic'));row['policy_sha256']=x.m.policy_digest(p.policy)
    elif fault=='dynamic-claim':row['qualified_dynamic']=True
    elif fault in {'not-full','unsettled','process-drift','native-stopped'}:
        changes={'not-full':dict(assigned_bytes=200*x.MiB,configured_bytes=200*x.MiB),'unsettled':dict(assigned_bytes=200*x.MiB),
            'process-drift':dict(process_id='13'),'native-stopped':dict(running=False)}[fault]
        p.backend.readback=lambda vm:replace(x.read,**changes)
    elif fault=='wrong-protocol':p.config['readback_version']='qcl.native-memory.balloon.v1'
    elif fault=='unregistered':g['slurm_registered']=False
    elif fault in {'stale','future'}:g['observed_at']=0 if fault=='stale'else 101
    elif fault=='image-drift':g['identity_before']['image_id']='other-image';g['identity_after']=deepcopy(g['identity_before'])
    elif fault=='missing-source':g.pop('output_generation')
    elif fault=='missing-pins':p.config.pop('output_owner');x.data[str(x.f.SERVICE_CONFIG)]['facts'].pop('output_owner')
    elif fault=='runner-drift':g['output_generation']['runner']['runner_revision']='b'*40
    elif fault=='worker-birth':g['output_generation']['worker']['unit']['main']['start_ticks']+=1
    elif fault=='native-birth':x.source.birth=10
    elif fault=='guest-protocol':g['protocol']='other-protocol'
    elif fault=='enrollment-machine':p.config['enrollment']['vm']['machine_id']='a'*32;x.data[str(x.f.SERVICE_CONFIG)]['facts']=deepcopy(p.config)
    elif fault=='invalid-total':g['memory']['MemTotal']=0
    elif fault=='invalid-available':g['memory']['MemAvailable']=g['memory']['MemTotal']+1
    elif fault=='slurm-too-large':g['slurm_memory_bytes']=950*x.MiB
    elif fault=='wrong-ref':row['evidence_ref']='other-proof'
    elif fault=='partial-positive':row['readback_verified']=False
    elif fault=='host-runtime':monkeypatch.setattr(x.f,'collect_native_runtime',lambda *a:SimpleNamespace(host_boot_id='other-host'))
    elif fault=='protected-drift':x.data[str(x.f.SERVICE_CONFIG)]['facts']['qualified_protocols']['vm']['qemu_birth_ticks']=10
    elif fault=='qualification-drift':x.data['/protected/qualification']=deepcopy(x.bundle);x.data['/protected/qualification']['qualifications'][0]['evidence_ref']='new-proof'
    elif fault=='balloon-enabled':x.native_config['balloon']=1000
    elif fault=='missing-native-config':x.source.fixed_native=lambda *args:None
    elif fault=='native-config-drift':
        old=x.source.fixed_native;calls=[]
        def changed(*args):
            value=old(*args);calls.append(True)
            if len(calls)>1:value['configuration']['balloon']=1000
            return value
        x.source.fixed_native=changed
    elif fault=='native-birth-drift':
        calls=[]
        def birth(pid):calls.append(pid);return dict(start_ticks=9 if len(calls)==1 else 10)
        x.source.process=birth
    elif fault=='source-pin-drift':
        old=x.source.fixed_native
        def drift(*args):
            x.data[str(x.f.SERVICE_CONFIG)]['facts']['output_owner']['runner']['runner_revision']='b'*40
            return old(*args)
        x.source.fixed_native=drift
    with pytest.raises(x.f.ResourceError):qualify(x)


def test_full_fixed_source_roundtrips_through_capture_and_controller_ready(fixed_provider):
    x=fixed_provider;e=x.p.request_facts(None,owner_state=None)
    grant=x.m.ResidentGrant('host','vm','owner',1000*x.MiB,100*x.MiB,'idle')
    x.controller.bootstrap((grant,),e)
    assert x.controller._load()['startups']['vm']['phase']=='binding_ready'
    assert type(e.qualifications[0])is x.m.BackendQualification
    assert e.qualifications[0].qualified_dynamic is False
    assert x.controller.snapshot()[0].guest_bytes==1000*x.MiB


def test_fixed_binding_facts_reads_full_source_but_negative_v1_uses_identity(fixed_provider):
    x=fixed_provider
    e=x.p.binding_facts(x.binding.native_id,owner_state=None)
    assert type(e.qualifications[0])is x.m.BackendQualification and e.qualifications[0].readback_verified
    assert x.source.full_reads==1 and x.source.identity_reads==0
    for flag in ('qualified_dynamic','active_floor_protection','readback_verified','slurm_registration_verified'):
        x.bundle['qualifications'][0][flag]=False
    e=x.p.binding_facts(x.binding.native_id,owner_state=None)
    assert e.qualifications[0].active_floor_protection is False
    assert x.source.identity_reads==1


def test_fixed_binding_source_reaches_ready_from_cold_full_reservation(fixed_provider):
    from host_resource_startup import StartupManager,ColdHostEvidence,ColdVMRecord
    x=fixed_provider;manager=StartupManager(x.p.policy,x.store,x.p.backend,clock=lambda:100)
    cold=ColdHostEvidence('host','owner','host-boot',x.m.policy_digest(x.p.policy),100,4096*x.MiB,256*x.MiB,
        'capacity','agreement','synthetic-root-enforcement',True,
        (ColdVMRecord('vm',x.binding.native_id,x.binding.config_fingerprint,1000*x.MiB,1000*x.MiB,'stopped'),))
    manager.prepare_start_reservations(cold_evidence=cold)
    evidence=x.p.binding_facts(x.binding.native_id,owner_state=x.store.load())
    view=manager.bind_running_startup(x.binding.native_id,evidence)
    assert view['phase']=='binding_ready'
    assert x.source.full_reads==1 and x.source.identity_reads==0
    assert x.store.load()['grants'][0]['guest_bytes']==1000*x.MiB


@pytest.mark.parametrize('fault',['host-pressure','foreign','unknown-live','aggregate'])
def test_fixed_reader_preserves_host_and_all_d_guards(fixed_provider,fault):
    x=fixed_provider
    if fault=='host-pressure':x.host['MemAvailable']=0
    if fault=='foreign':x.agreement['foreign']={'unknown':dict(maximum_bytes=1,overhead_bytes=0,config_fingerprint='unknown')}
    if fault=='unknown-live':
        x.g['jobs']=x.f.parse_slurm_jobs('JobId=42 UserId=qcl-negf(3000) JobState=RUNNING NumNodes=1 NumTasks=1 NodeList=worker-a SubmitTime=2026-10-28T10:00:00 StartTime=2026-10-28T10:00:01 Restarts=0 MinMemoryNode=64M',cluster='cluster')
        x.g['groups']={'42':dict(populated=True,processes=[dict(uids=[3000]*4,executable='/unpaid/solver',start_ticks=9)])}
    if fault in {'foreign','unknown-live'}:
        with pytest.raises(x.f.ResourceError):
            e=x.p.request_facts(None,owner_state=None)
            x.controller.bootstrap((x.m.ResidentGrant('host','vm','owner',1000*x.MiB,100*x.MiB,'idle'),),e)
        return
    e=x.p.request_facts(None,owner_state=None)
    if fault=='host-pressure':
        with pytest.raises(x.f.ResourceError):x.controller.bootstrap((x.m.ResidentGrant('host','vm','owner',1000*x.MiB,100*x.MiB,'idle'),),e)
    else:
        x.controller.bootstrap((x.m.ResidentGrant('host','vm','owner',1000*x.MiB,100*x.MiB,'idle'),),e)
        req=x.m.ResourceRequest('one','host','vm','owner',600*x.MiB,'work-one')
        x.controller.request(req,e)
        with pytest.raises(x.f.ResourceError):x.controller.request(replace(req,request_id='two',workload_id='work-two',workload_bytes=400*x.MiB),e)


@pytest.mark.parametrize('backend_name',['proxmox','libvirt'])
def test_actual_fixed_config_getter_uses_only_existing_readonly_native_argv(backend_name):
    import host_resource_facts as f
    from host_resource_backends import ProxmoxMemoryBackend,ProxmoxVM,LibvirtMemoryBackend,LibvirtVM
    native_id='22222222-2222-4222-8222-222222222222';calls=[]
    payload='{"balloon":0,"memory":1000}' if backend_name=='proxmox'else '<domain><uuid>'+native_id+'</uuid></domain>'
    class Runner:
        def run(self,argv,**kwargs):
            calls.append(argv)
            assert kwargs==dict(timeout_seconds=30,max_output_bytes=256*1024)
            return payload
    backend=(ProxmoxMemoryBackend(Runner(),'/fixed/pvesh','node',{'vm':ProxmoxVM(713,native_id)},dynamic=False)
        if backend_name=='proxmox'else LibvirtMemoryBackend(Runner(),'/fixed/virsh','qemu:///system',{'vm':LibvirtVM(native_id,'worker')},dynamic=False))
    value=f.LocalSources({},None).fixed_native(backend,'vm')
    assert value==dict(backend=backend_name,configuration=json.loads(payload)if backend_name=='proxmox'else payload)
    assert calls==([['/fixed/pvesh','get','/nodes/node/qemu/713/config','--current','1','--output-format','json']]
        if backend_name=='proxmox'else [['/fixed/virsh','--connect','qemu:///system','dumpxml',native_id]])
    backend.dynamic=True
    with pytest.raises(f.ResourceError):f.LocalSources({},None).fixed_native(backend,'vm')
    assert len(calls)==1


@pytest.mark.parametrize('current_mib',[1000,999])
def test_fixed_libvirt_original_xml_must_cover_full_configured_maximum(fixed_provider,current_mib):
    import xml.etree.ElementTree as ET
    from host_resource_backends import libvirt_config_fingerprint
    x=fixed_provider
    raw=f'<domain><uuid>{x.binding.native_id}</uuid><memory unit="MiB">1000</memory><currentMemory unit="MiB">{current_mib}</currentMemory></domain>'
    binding=replace(x.binding,config_fingerprint=libvirt_config_fingerprint(ET.fromstring(raw)))
    read=replace(x.read,config_fingerprint=binding.config_fingerprint,revision=hashlib.sha256(raw.encode()).hexdigest())
    x.p.backend.readback=lambda vm:read;x.binding=binding;x.bundle['qualifications'][0]['binding']=asdict(binding)
    x.source.fixed_native=lambda *args:dict(backend='libvirt',configuration=raw)
    if current_mib==1000:assert type(qualify(x))is x.m.BackendQualification
    else:
        with pytest.raises(x.f.ResourceError):qualify(x)


@pytest.mark.parametrize('producer',['qualification','capture','binding'])
@pytest.mark.parametrize('finished_at',[130,131])
def test_fixed_freshness_covers_all_native_reads_without_retimestamp(fixed_provider,producer,finished_at):
    x=fixed_provider;now=[100];x.p.clock=lambda:now[0];original=x.source.fixed_native;calls=[]
    def delayed(*args):
        value=original(*args);calls.append(True)
        if len(calls)==2:now[0]=finished_at
        return value
    x.source.fixed_native=delayed
    def capture():
        if producer=='qualification':return qualify(x)
        if producer=='capture':return x.p.request_facts(None,owner_state=None)
        return x.p.binding_facts(x.binding.native_id,owner_state=None)
    if finished_at==131:
        with pytest.raises(x.f.ResourceError):capture()
    else:
        result=capture()
        if producer!='qualification':assert result.observed_at==100
    assert x.g['observed_at']==100


@pytest.mark.parametrize('phase',['persist','host','monotonic'])
def test_fixed_capture_refuses_expiry_outside_initial_guest_check(fixed_provider,monkeypatch,phase):
    x=fixed_provider;now=[100];x.p.clock=lambda:now[0]
    if phase=='persist':
        original=x.p._persist
        def delayed(*args):original(*args);now[0]=131
        monkeypatch.setattr(x.p,'_persist',delayed)
    elif phase=='host':
        original=x.source.inventory
        def delayed(*args):
            value=original(*args);now[0]=131;x.g['observed_at']=131
            return value
        x.source.inventory=delayed
    else:
        nanos=[0];monkeypatch.setattr(x.f.time,'monotonic_ns',lambda:nanos[0]);original=x.source.fixed_native;calls=[]
        def delayed(*args):
            value=original(*args);calls.append(True)
            if len(calls)==2:nanos[0]=31*10**9
            return value
        x.source.fixed_native=delayed
    with pytest.raises(x.f.ResourceError):x.p.request_facts(None,owner_state=None)
    assert x.p.last is None and not x.store.state_path.exists()


def live_guest(x,executable='/gate'):
    jobs=x.f.parse_slurm_jobs('JobId=42 UserId=qcl-negf(3000) JobState=RUNNING NumNodes=1 NumTasks=1 NodeList=worker-a SubmitTime=2026-10-28T10:00:00 StartTime=2026-10-28T10:00:01 Restarts=0 MinMemoryNode=64M',cluster='cluster')
    x.g['jobs']=jobs;x.g['groups']={'42':dict(populated=True,memory_max_bytes=64*x.MiB,
        processes=[dict(uids=[3000]*4,executable=executable,start_ticks=9)])}
    return 'slurm:'+jobs['42']['generation']


def test_fixed_startup_binding_refuses_actual_unpaid_body(fixed_provider):
    from host_resource_startup import StartupManager,ColdHostEvidence,ColdVMRecord
    x=fixed_provider;live_guest(x,'/unpaid/solver')
    manager=StartupManager(x.p.policy,x.store,x.p.backend,clock=lambda:100)
    cold=ColdHostEvidence('host','owner','host-boot',x.m.policy_digest(x.p.policy),100,4096*x.MiB,256*x.MiB,
        'capacity','agreement','synthetic-root-enforcement',True,
        (ColdVMRecord('vm',x.binding.native_id,x.binding.config_fingerprint,1000*x.MiB,1000*x.MiB,'stopped'),))
    manager.prepare_start_reservations(cold_evidence=cold)
    with pytest.raises(x.f.ResourceError):
        evidence=x.p.binding_facts(x.binding.native_id,owner_state=x.store.load())
        manager.bind_running_startup(x.binding.native_id,evidence)
    assert x.store.load()['startups']['vm']['phase']!='binding_ready'


@pytest.mark.parametrize('fault',[None,'missing-job','missing-group','changed-generation'])
def test_fixed_binding_inventory_preserves_actual_paid_run(fixed_provider,fault):
    x=fixed_provider;e=x.p.request_facts(None,owner_state=None)
    x.controller.bootstrap((x.m.ResidentGrant('host','vm','owner',1000*x.MiB,100*x.MiB,'idle'),),e)
    work=live_guest(x)
    req=x.m.ResourceRequest('run','host','vm','owner',64*x.MiB,work)
    x.controller.request(req,e);x.controller.grow('run',e)
    state=x.controller._load();actual=x.p.request_facts(None,owner_state=state)
    x.controller.admit('run',x.p.guest_admission('run',owner_state=state),actual)
    x.g['groups']['42']['processes'][0]['executable']='/paid/solver'
    if fault=='missing-job':x.g['jobs']={};x.g['groups']={}
    if fault=='missing-group':x.g['groups']={}
    if fault=='changed-generation':x.g['jobs']['42']['generation']='b'*64
    state=x.controller._load()
    if fault:
        with pytest.raises(x.f.ResourceError):x.p.binding_facts(x.binding.native_id,owner_state=state)
    else:
        evidence=x.p.binding_facts(x.binding.native_id,owner_state=state)
        assert evidence.live_workloads=={'vm':(work,)}
        x.controller._guard(state,evidence)
