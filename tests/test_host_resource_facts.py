"""Closed native packets; never invoke a live scheduler, hypervisor or SSH."""
from dataclasses import replace
import json
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops'))
from test_host_resource_operations import setup


@pytest.mark.parametrize('extra',[{'forged':True},{'outputs':[]},{'outputs':{'a'*64:{}}}])
def test_scheduler_output_projection_rejects_unknown_or_malformed_before_resolution(monkeypatch,extra):
    """Authenticated transport never makes an arbitrary output map authority."""
    from types import SimpleNamespace
    import host_resource_facts as f
    from host_resource_operations import ResourceError
    native=dict(native_id='42',generation='b'*64,owner_uid=3000,node='worker-a',limit_bytes=1024)
    packet=dict(schema='qcl.host-resource-scheduler-facts.v1',jobs={'42':native},**extra)
    monkeypatch.setattr(f,'trusted_rpc',lambda *a,**k:packet)
    config=dict(scheduler_route={},client_uid=3000,nodes={'worker-a':'vm-a'},enrollment={'vm-a':{}})
    monkeypatch.setattr(f,'read_root_json',lambda path:dict(schema='qcl.host-resource-service.v1',role='native_host',client_uid=3000,facts=config))
    provider=f.NativeFactsProvider(None,config,None,None,sources=object())
    with pytest.raises(ResourceError):provider.resolve(SimpleNamespace(kind='slurm_allocation',native_id='42'))
    assert provider.native=={}


def output_packet():
    """Typed synthetic metadata only, never a root/native completion certificate."""
    import host_resource_facts as f
    raw='JobId=42 UserId=qcl-negf(3000) JobState=COMPLETED ExitCode=0:0 NumNodes=1 NumTasks=1 NodeList=worker-a SubmitTime=2026-10-28T10:00:00 StartTime=2026-10-28T10:00:01 Restarts=0 MinMemoryNode=512M'
    native=f.parse_slurm_jobs(raw,cluster='cluster-one')['42'];generation=native['generation']
    identity=dict(machine_id='a'*32,boot_id='11111111-1111-4111-8111-111111111111',kernel='synthetic-kernel',dmi_uuid='22222222-2222-4222-8222-222222222222')
    observation=dict(generation=generation,durable=True,scope='completed_final',observed_at=100,
        controller_identity=dict(identity),worker_identity={**identity,'machine_id':'b'*32},
        owner=dict(policy_sha256='1'*64,qualification_sha256='2'*64,source_graph_sha256='3'*64,
            unit_generation_sha256='4'*64,storage_identity='synthetic-storage',retention_ref='synthetic-retention'),
        attempt=dict(calcjob_uuid='33333333-3333-4333-8333-333333333333',dispatch_id='44444444-4444-4444-8444-444444444444',generation='5'*64),
        native_tuple=dict(cluster='cluster-one',job_id='42',raw_user_id='qcl-negf(3000)',owner_uid=3000,node='worker-a',
            submit_time=native['submit_time'],start_time=native['start_time'],restarts=0,limit_bytes=native['limit_bytes']),
        publication=dict(close_sha256='6'*64,close_observation_sha256='7'*64,result_sha256='8'*64,selection_sha256='9'*64))
    return dict(schema='qcl.host-resource-scheduler-facts.v1',jobs={'42':native},outputs={generation:observation})


def output_join_fixture(monkeypatch):
    """Typed SOURCE/L binding, not Root production qualification."""
    import copy
    import host_resource_facts as f
    from test_native_attempt import p20_worker,p20_runner
    from types import SimpleNamespace
    packet=output_packet();generation=next(iter(packet['outputs']));output=packet['outputs'][generation]
    worker=p20_worker('worker-a');worker['identity']=dict(output['worker_identity']);runner=p20_runner()
    runner['source_graph_sha256']=output['owner']['source_graph_sha256']
    expected=dict(owner=dict(output['owner']),controller_identity=dict(output['controller_identity']),runner=runner,
        worker_generations={'worker-a':worker})
    config=dict(scheduler_route={},client_uid=3000,nodes={'worker-a':'vm-a'},enrollment={'vm-a':{}},guests={'vm-a':{}},output_owner=expected)
    service=dict(schema='qcl.host-resource-service.v1',role='native_host',client_uid=3000,facts=copy.deepcopy(config))
    monkeypatch.setattr(f,'trusted_rpc',lambda *a,**k:packet)
    def protected(path):
        assert str(path)=='/etc/qcl-negf/host-resources/service.json';return service
    monkeypatch.setattr(f,'read_root_json',protected)
    provider=f.NativeFactsProvider(SimpleNamespace(timeouts=SimpleNamespace(request_seconds=30)),config,None,None,sources=object(),clock=lambda:100)
    provider.resolve(SimpleNamespace(kind='slurm_allocation',native_id='42'))
    identity={**worker['identity'],'image_id':'/nix/store/synthetic-image'}
    guests={'vm-a':dict(identity_before=identity,identity_after=dict(identity),observed_at=100,jobs=copy.deepcopy(packet['jobs']),
        output_generation=dict(worker=copy.deepcopy(worker),runner=copy.deepcopy(runner)),outputs={},groups={'42':dict(populated=False,processes=[])},
        memory={'MemTotal':1000,'MemAvailable':900})}
    return provider,packet,guests,service


@pytest.mark.parametrize('fault',[None,'stale','future','guest_before','scope','false','owner','controller','identity','image_only',
    'worker_birth','worker_mount','worker_namespace','runner','tuple_uid','tuple_memory','native_hash','missing_tuple','exit_code','epoch','config_drift','no_guest_tuple'])
def test_pending_output_requires_fresh_exact_guest_and_protected_owner_join(monkeypatch,fault):
    import host_resource_facts as f
    provider,packet,guests,service=output_join_fixture(monkeypatch);generation=next(iter(packet['outputs']))
    output=provider._pending_outputs[generation];guest=guests['vm-a']
    if fault=='stale':output['observed_at']=69
    if fault=='future':output['observed_at']=101
    if fault=='guest_before':guest['observed_at']=99
    if fault=='scope':output.update(scope='controls',durable=False)
    if fault=='false':output['durable']=False
    if fault=='owner':output['owner']['policy_sha256']='d'*64
    if fault=='controller':output['controller_identity']['boot_id']='99999999-9999-4999-8999-999999999999'
    if fault=='identity':guest['identity_before']['boot_id']='99999999-9999-4999-8999-999999999999'
    if fault=='image_only':guest['output_generation']['worker']['identity']={'boot_id':guest['identity_before']['boot_id']}
    if fault=='worker_birth':guest['output_generation']['worker']['unit']['main']['start_ticks']+=1
    if fault=='worker_mount':guest['output_generation']['worker']['unit']['mount_line']+=' changed'
    if fault=='worker_namespace':guest['output_generation']['worker']['unit']['mount_namespace']['inode']+=1
    if fault=='runner':guest['output_generation']['runner']['runner_revision']='c'*40
    if fault=='tuple_uid':guest['jobs']['42']['raw_user_id']='other(3000)'
    if fault=='tuple_memory':guest['jobs']['42']['limit_bytes']+=1
    if fault=='native_hash':guest['jobs']['42']['generation']=output['attempt']['generation']
    if fault=='missing_tuple':guest['jobs']['42'].pop('cluster',None)
    if fault=='exit_code':guest['jobs']['42']['exit_code']='00:0'
    if fault=='epoch':provider._output_epoch=object()
    if fault=='config_drift':service['facts']['output_owner']['owner']['retention_ref']='changed'
    if fault=='no_guest_tuple':del guest['output_generation']
    if fault is None:
        provider._join_scheduler_outputs(guests,observed_now=100)
        assert provider._joined_outputs==provider._pending_outputs and provider._joined_epoch is provider._output_epoch
        assert guest['outputs']=={}
    else:
        with pytest.raises(f.ResourceError):provider._join_scheduler_outputs(guests,observed_now=100)
        assert provider._pending_outputs==provider._joined_outputs=={} and provider._output_epoch is None


@pytest.mark.parametrize('fault',[None,'age','future','config','worker','epoch','populated'])
def test_completion_repeats_join_and_discards_every_failed_invocation(monkeypatch,fault):
    from types import SimpleNamespace
    import host_resource_facts as f
    provider,packet,guests,service=output_join_fixture(monkeypatch);generation=next(iter(packet['outputs']))
    provider._join_scheduler_outputs(guests,observed_now=100)
    provider.last=(SimpleNamespace(live_workloads={'vm-a':()}),guests)
    state=dict(receipts=[dict(request=dict(request_id='request',vm_id='vm-a',workload_id='slurm:'+generation))])
    if fault=='age':provider.clock=lambda:131
    if fault=='future':provider.clock=lambda:99
    if fault=='config':service['facts']['output_owner']['owner']['retention_ref']='requalified'
    if fault=='worker':guests['vm-a']['output_generation']['worker']['unit']['main']['start_ticks']+=1
    if fault=='epoch':provider._output_epoch=object()
    if fault=='populated':guests['vm-a']['groups']['42'].update(populated=True,processes=[{'pid':1}])
    if fault is None:
        result=provider.completion('request',owner_state=state)
        assert result.outputs_durable is True and result.live_workload_ids==()
    else:
        with pytest.raises(f.ResourceError):provider.completion('request',owner_state=state)
        assert provider._output_epoch is provider.last is None and provider._pending_outputs==provider._joined_outputs=={}


@pytest.mark.parametrize('kind',['recoverable','fatal','cancel'])
def test_failed_resolve_clears_current_invocation_and_preserves_primary(monkeypatch,kind):
    from types import SimpleNamespace
    import host_resource_facts as f
    provider,packet,guests,service=output_join_fixture(monkeypatch)
    primary={'recoverable':f.ResourceError('transport','actual RPC failed'),'fatal':MemoryError('actual allocation'),
        'cancel':KeyboardInterrupt('actual cancellation')}[kind]
    def rpc(*args,**kwargs):raise primary
    monkeypatch.setattr(f,'trusted_rpc',rpc)
    with pytest.raises(type(primary)) as caught:provider.resolve(SimpleNamespace(kind='slurm_allocation',native_id='42'))
    assert caught.value is primary and provider._output_epoch is provider.last is None
    assert provider._pending_outputs==provider._joined_outputs=={}


@pytest.mark.parametrize('seam',['guest','attempt'])
@pytest.mark.parametrize('mode',['present','absent','drift'])
def test_root_guest_and_attempt_snapshots_sample_same_worker_tuple_twice(monkeypatch,seam,mode):
    """Closed native source observations; no service/Root qualification claim."""
    import copy
    import host_resource_facts as f
    import native_attempt as m
    from test_native_attempt import p20_worker,p20_runner,limits
    worker=p20_worker();identity=worker['identity'];budget=m.Operation({**limits(),'maximum_files':2048})
    native=m.NativeSources({},budget);events=[]
    class Local:
        def host(self):events.append('host');return {**identity,'MemTotal':1024**3,'MemAvailable':512*1024**2}
        def processes(self):events.append('processes');return [dict(worker['unit']['main'])]
        def run(self,argv):return 'RealMemory=512 State=IDLE'
    local=Local();config=dict(node='node-a',client_uid=3000,slurm_cgroup_root='/jobs',infrastructure_processes=[],
        slurmd_executable=worker['unit']['main']['executable'],guest_protocol='synthetic',scontrol='/fixed/scontrol',systemctl='/fixed/systemctl')
    value=dict(worker=worker,runner=p20_runner());count=[]
    def generation(sources):
        assert sources is native and sources.budget is budget;events.append('generation');count.append(True)
        if mode=='absent':return None
        result=copy.deepcopy(value)
        if mode=='drift' and len(count)>1:result['worker']['unit']['mount_namespace']['inode']+=1
        return result
    monkeypatch.setattr(m,'_worker_output_generation',generation);monkeypatch.setattr(m,'_worker_output_sources',lambda:native)
    monkeypatch.setattr(f,'capture_scheduler',lambda *a:{})
    monkeypatch.setattr(m.engine,'unit_state',lambda *a,**k:{**worker['unit']['state'],'LoadState':'loaded'})
    monkeypatch.setattr(f.os.path,'realpath',lambda path:'/nix/store/synthetic-image')
    monkeypatch.setattr(f,'trusted_root_path',lambda path,**kwargs:Path(path))
    def capture():
        if seam=='guest':return f.capture_guest_facts(config,local,clock=lambda:100)
        return m._capture_writer_snapshot(config,local,budget,output_sources=native)
    if mode=='drift':
        with pytest.raises((m.Hold,f.ResourceError)):capture()
    else:
        packet=capture()
        assert packet.get('output_generation')==(None if mode=='absent' else value)
        assert ('output_generation' in packet)==(mode!='absent')
    assert len(count)==2 and events[0]==events[-1]=='generation'


@pytest.mark.parametrize('outputs',[False,True])
def test_scheduler_resolve_preserves_no_output_default_and_detaches_pending(monkeypatch,outputs):
    from types import SimpleNamespace
    import host_resource_facts as f
    packet=output_packet()
    if not outputs:del packet['outputs']
    monkeypatch.setattr(f,'trusted_rpc',lambda *a,**k:packet)
    config=dict(scheduler_route={},client_uid=3000,nodes={'worker-a':'vm-a'},enrollment={'vm-a':{}})
    monkeypatch.setattr(f,'read_root_json',lambda path:dict(schema='qcl.host-resource-service.v1',role='native_host',client_uid=3000,facts=config))
    provider=f.NativeFactsProvider(None,config,None,None,sources=object())
    native,vm,identity,request=provider.resolve(SimpleNamespace(kind='slurm_allocation',native_id='42'))
    assert vm=='vm-a' and identity=='slurm:'+native['generation'] and request.startswith('native-')
    assert provider._joined_outputs=={} and bool(provider._pending_outputs)==outputs
    if outputs:
        generation=native['generation'];packet['outputs'][generation]['owner']['storage_identity']='changed'
        assert provider._pending_outputs[generation]['owner']['storage_identity']=='synthetic-storage'
    epoch=provider._output_epoch;packet['unexpected']=True
    with pytest.raises(f.ResourceError):provider.resolve(SimpleNamespace(kind='slurm_allocation',native_id='42'))
    assert provider._pending_outputs=={} and provider._joined_outputs=={} and provider._output_epoch is not epoch


def test_guest_output_dictionary_alone_never_certifies_completion():
    import host_resource_facts as f
    from types import SimpleNamespace
    provider=f.NativeFactsProvider(None,{},None,None,sources=object(),clock=lambda:100);generation='a'*64
    native=dict(native_id='42',generation=generation,terminal=True,state='COMPLETED')
    guest=dict(jobs={'42':native},groups={'42':dict(populated=False,processes=[])},
        outputs={generation:dict(generation=generation,durable=True)},identity_before={'boot_id':'synthetic'},
        observed_at=100,memory={'MemTotal':1000,'MemAvailable':900})
    provider.last=(SimpleNamespace(live_workloads={'vm-a':()}),{'vm-a':guest})
    state={'receipts':[dict(request=dict(request_id='request',vm_id='vm-a',workload_id='slurm:'+generation))]}
    with pytest.raises(f.ResourceError,match='cleanup'):provider.completion('request',owner_state=state)


@pytest.mark.parametrize('kind',['recoverable','fatal','cancel'])
def test_failed_capture_discards_pending_join_epoch_and_old_guest(monkeypatch,kind):
    import host_resource_facts as f
    provider=f.NativeFactsProvider(None,{},None,None,sources=object())
    provider._output_epoch=provider._joined_epoch=object()
    provider._pending_outputs={'old':'pending'};provider._joined_outputs={'old':'joined'};provider.last=('old','guest')
    error={'recoverable':f.ResourceError('cleanup','synthetic failure'),
        'fatal':MemoryError('primary allocation failure'),'cancel':KeyboardInterrupt('primary cancellation')}[kind]
    def capture(*args,**kwargs):raise error
    monkeypatch.setattr(provider,'_capture',capture)
    with pytest.raises(type(error)) as caught:provider.request_facts(None,owner_state={})
    assert caught.value is error and provider.last is None
    assert provider._output_epoch is provider._joined_epoch is None
    assert provider._pending_outputs==provider._joined_outputs=={}


@pytest.mark.parametrize('fault',['extra','missing','integer_durable','controls_durable','epoch_swap','negative_time','future_type',
    'worker_boot','controller_machine','kernel_bound','owner_extra','owner_sha','retention_bound','attempt_uuid',
    'raw_uid','owner_bool','restarts_bool','restarts_nonzero','memory_bool','node_array','wrong_tuple_time',
    'native_generation_swap','publication_missing','publication_sha','map_count','packet_bytes'])
def test_scheduler_projection_closed_fields_original_tuple_and_bounds(fault):
    import host_resource_facts as f
    packet=output_packet();generation=next(iter(packet['outputs']));row=packet['outputs'][generation]
    if fault=='extra':row['extra']=True
    elif fault=='missing':del row['attempt']
    elif fault=='integer_durable':row['durable']=1
    elif fault=='controls_durable':row['scope']='controls'
    elif fault=='epoch_swap':row['generation']=row['attempt']['generation']
    elif fault=='negative_time':row['observed_at']=-1
    elif fault=='future_type':row['observed_at']=100.0
    elif fault=='worker_boot':row['worker_identity']['boot_id']='boot'
    elif fault=='controller_machine':row['controller_identity']['machine_id']='machine'
    elif fault=='kernel_bound':row['worker_identity']['kernel']='x'*257
    elif fault=='owner_extra':row['owner']['root_verified']=True
    elif fault=='owner_sha':row['owner']['source_graph_sha256']='A'*64
    elif fault=='retention_bound':row['owner']['retention_ref']='x'*257
    elif fault=='attempt_uuid':row['attempt']['calcjob_uuid']='latest'
    elif fault=='raw_uid':row['native_tuple']['raw_user_id']='qcl-negf(0)'
    elif fault=='owner_bool':row['native_tuple']['owner_uid']=True
    elif fault=='restarts_bool':row['native_tuple']['restarts']=False
    elif fault=='restarts_nonzero':row['native_tuple']['restarts']=1
    elif fault=='memory_bool':row['native_tuple']['limit_bytes']=True
    elif fault=='node_array':row['native_tuple']['node']='worker-[a,b]'
    elif fault=='wrong_tuple_time':row['native_tuple']['start_time']='2026-10-28T10:00:02'
    elif fault=='native_generation_swap':packet['outputs']={row['attempt']['generation']:dict(row,generation=row['attempt']['generation'])}
    elif fault=='publication_missing':del row['publication']['result_sha256']
    elif fault=='publication_sha':row['publication']['close_sha256']='unknown'
    elif fault=='map_count':packet['outputs']={str(i):{} for i in range(9)}
    elif fault=='packet_bytes':packet['jobs']['unrelated']={'raw':'x'*f.MAX_OUTPUT_BYTES}
    with pytest.raises(f.ResourceError):f._scheduler_output_observations(packet)


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
