"""SOURCE/L fixtures. Synthetic observations never qualify an installed backend."""
import copy
import hashlib
import importlib.util
import json
import os
import socket
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ops'))


def module():
    assert importlib.util.find_spec('native_attempt'), 'ordinary attempt owner is missing'
    import native_attempt
    return native_attempt


@pytest.mark.parametrize('kind',[None,MemoryError,KeyboardInterrupt,RuntimeError])
@pytest.mark.parametrize('outer_close',[False,True])
def test_revision2_original_leaf_cleanup_preserves_primary_identity(tmp_path,monkeypatch,kind,outer_close):
    m=module();root=tmp_path/'private';root.mkdir(mode=0o700);store=m.AttemptStore(root)
    budget=m.Operation(limits());calc='11111111-1111-4111-8111-111111111111'
    with store.locked(calc,budget):store.put(calc,'claim.json',{'original':'metadata'},budget)
    primary=None if kind is None else kind('original decoder failure');secondary=OSError('leaf close failure')
    close=os.close;opened=os.open;target={'leaf':None,'entered':False};closed=[]
    def opening(path,*args,**kwargs):
        fd=opened(path,*args,**kwargs)
        if path=='claim.json':target['leaf']=fd;target['entered']=True
        return fd
    def closing(fd):
        is_leaf=fd==target['leaf'];is_outer=outer_close and target['entered'] and m.stat.S_ISDIR(os.fstat(fd).st_mode)
        close(fd);closed.append(fd)
        with pytest.raises(OSError):os.fstat(fd)
        if is_leaf:target['leaf']=None;raise secondary
        if is_outer:raise OSError('secondary original directory close')
    if primary is not None:monkeypatch.setattr(m,'strict_json',lambda raw:(_ for _ in ()).throw(primary))
    monkeypatch.setattr(m.os,'open',opening);monkeypatch.setattr(m.os,'close',closing)
    with pytest.raises(kind or OSError) as caught:store.read(calc,'claim.json',budget)
    assert caught.value is (primary or secondary) and target['leaf'] is None and len(closed)>=2
    assert all(len(note)<=256 for note in getattr(caught.value,'__notes__',[]))


@pytest.mark.parametrize('kind',[None,MemoryError,KeyboardInterrupt,RuntimeError])
@pytest.mark.parametrize('outer_close',[False,True])
def test_revision2_protected_leaf_and_actual_outer_cleanup_preserve_primary(monkeypatch,kind,outer_close):
    """Actual local root-owned proc metadata FDs/trust; no native-site claim."""
    m=module();primary=None if kind is None else kind('original source read failure')
    secondary=OSError('leaf close failure');close=os.close;target={'leaf':None,'entered':False};closed=[]
    def reading(fd,limit,budget):
        target.update(leaf=fd,entered=True)
        if primary is not None:raise primary
        return b'controlled read seam',os.fstat(fd)
    def closing(fd):
        is_leaf=fd==target['leaf'];is_outer=outer_close and target['entered'] and m.stat.S_ISDIR(os.fstat(fd).st_mode)
        close(fd)
        with pytest.raises(OSError):os.fstat(fd)
        if is_leaf:target['leaf']=None;closed.append('leaf');raise secondary
        if is_outer:closed.append('outer');raise OSError('secondary protected-directory close')
    monkeypatch.setattr(m,'read_fd',reading);monkeypatch.setattr(m.os,'close',closing)
    with pytest.raises(kind or OSError) as caught:m.protected_read('/proc/sys/kernel/osrelease',m.Operation(limits()))
    assert caught.value is (primary or secondary) and closed==(['leaf','outer'] if outer_close else ['leaf'])
    assert all(len(note)<=256 for note in getattr(caught.value,'__notes__',[]))


def p20_runner():
    """Explicit synthetic immutable-source metadata, never installed proof."""
    m=module();root='/nix/store/synthetic-p20-solver'
    relative=dict(launcher='bin/qcl-negf',julia_launcher='bin/.qcl-negf-julia',project='share/qcl-negf/julia/Project.toml',
        manifest='share/qcl-negf/julia/Manifest.toml',runner_entry='share/qcl-negf/components/QCLNEGFRunner.jl/scripts/scientific_workflow.jl',
        runner_module='share/qcl-negf/components/QCLNEGFRunner.jl/src/QCLNEGFRunner.jl',cli='share/qcl-negf/components/QCLNEGFRunner.jl/src/cli.jl',
        native_lane='share/qcl-negf/components/QCLNEGFRunner.jl/src/composition/scratch_execution.jl',
        execution='share/qcl-negf/components/QCLNEGFRunner.jl/src/composition/scientific_execution.jl',
        publication='share/qcl-negf/components/QCLNEGFRunner.jl/src/infrastructure/persistence/point_artifacts.jl')
    paths={key:root+'/'+value for key,value in relative.items()}
    paths.update(capture_entry='/nix/store/synthetic-p20-capture/bin/qcl-negf-results',
        capture_cli='/nix/store/synthetic-p20-capture/lib/python/site-packages/qcl_negf_results/cli.py',
        capture_runtime='/nix/store/synthetic-p20-capture/lib/python/site-packages/qcl_negf_results/capture.py')
    files={key:dict(path=path,bytes=3,sha256=hashlib.sha256(b'abc').hexdigest()) for key,path in paths.items()}
    return dict(solver_executable=paths['launcher'],runner_revision='a'*40,source_graph_sha256='b'*64,
        julia_manifest_sha256=files['manifest']['sha256'],capture_executable=paths['capture_entry'],files=files)


def p20_unit(name='slurmd.service'):
    worker=name=='slurmd.service';uid=0 if worker else 3000
    return dict(name=name,state=dict(InvocationID='1'*32,ControlGroup='/system.slice/'+name,MainPID='123',ActiveState='active',
        FragmentPath='/nix/store/synthetic-units/'+name,MemoryMax='134217728',RuntimeMaxUSec='90s'),
        main=dict(pid=123,start_ticks=99,uids=[uid]*4,cgroup='/system.slice/'+name,executable='/nix/store/synthetic-python/bin/python'),
        mount_namespace=dict(device=4,inode=8),mount_line='1 0 0:1 / /srv/qcl-negf/jobs/native '+('rw' if worker else 'ro')+' - nfs4 storage:/jobs rw,hard')


def p20_worker(node='node-a'):
    return dict(node=node,identity=dict(machine_id='c'*32,boot_id='11111111-1111-4111-8111-111111111111',
        kernel='synthetic-kernel',dmi_uuid='22222222-2222-4222-8222-222222222222'),unit=p20_unit())


def p20_metadata_profile():
    """Only typed metadata-profile operands; not a full scientific/native proof.

    No declared manifest/HDF references below stand for existing payloads. The
    installed-source and genuine producer/creator gates remain separate.
    """
    m=module();launch=copy.deepcopy(request()['launch']);launch['transport_attempt']=2
    calcjob=request()['calcjob_uuid'];runner=p20_runner()
    boot=p20_worker()['identity']['boot_id'];root='/srv/qcl-negf/jobs/'+launch['relative_execution_root']
    digest=lambda raw:hashlib.sha256(raw).hexdigest()
    plan=dict(schema='qcl-negf-scientific-plan-v2',fingerprint=digest(b'plan-profile'),scientific_fingerprint=digest(b'science-profile'),
        points=[dict(id='point-a',execution_id=launch['execution_id'],effective_inputs=dict(model_sha256=digest(b'model-profile')))])
    graph=dict(format='qcl-negf.git-graph.v1',revision='d'*40,components=[dict(path='components/QCLNEGFRunner.jl',revision=runner['runner_revision'],url='fixture')])
    runner['source_graph_sha256']=digest(m.encoded(graph))
    native=dict(schema='qcl-negf.aiida-native-execution.v1',request_id=launch['request_id'],execution_id=launch['execution_id'],
        input_plan=dict(node_uuid=launch['input_plan_uuid'],bytes=str(len(m.encoded(plan))),sha256=digest(m.encoded(plan))),
        source_graph=dict(node_uuid=launch['source_graph_uuid'],bytes=str(len(m.encoded(graph))),sha256=digest(m.encoded(graph))),
        code=dict(code_uuid=launch['code_uuid'],computer_uuid=launch['code_uuid'],solver_executable=runner['solver_executable'],release_id=launch['release_id'],build_receipt_ref='fixture'),
        storage=dict(namespace_id='fixture',storage_identity='fixture-storage',relative_execution_root=launch['relative_execution_root'],
            computer_uuid=launch['code_uuid'],execution_binding_uuid=launch['native_execution_uuid'],retention_policy_id='fixture',retention_owner_id='fixture',hold_ref='fixture',access_binding_ref='fixture'),access_receipt_ref='fixture')
    def ref(path,schema,media='application/json'):
        return dict(path=path,bytes='1',sha256=digest(path.encode()),schema=schema,media_type=media)
    epoch='c1-'+calcjob.replace('-','')+'-'+launch['native_execution_uuid'].replace('-','')+'-1'
    identity=dict(run_id='scientific-profile',execution_id=launch['execution_id'],point_id='point-a',attempt='1',branch_id='branch',
        model_sha256=plan['points'][0]['effective_inputs']['model_sha256'],plan_sha256=digest(m.encoded(plan)))
    state=dict(identity=identity,state_id=epoch+'-state-1',state_sequence='1',manifest=ref('executions/point-a/'+epoch+'-manifest.json','qcl-negf.result-manifest.v1'))
    source=dict(schema='qcl-negf.native-point-source.v1',kind='final',artifact_root='.',relation='current_point_attempt',selected_state=state,
        diagnostics=ref('diagnostics.h5','qcl-negf-physics-analysis-v5','application/x-hdf5'),
        observations=ref('observations.h5','qcl-negf-physics-analysis-v5','application/x-hdf5'),reason=None)
    result=dict(schema='qcl-negf-series-result-v4',contract_set='qcl-negf.results.v2',status='completed',plan_fingerprint=plan['fingerprint'],
        plan_scientific_fingerprint=plan['scientific_fingerprint'],expected_point_count=1,available_point_count=1,attempt_history=[],
        executions=[dict(id=launch['execution_id'],point_ids=['point-a'])],points=[dict(id='point-a',execution_id=launch['execution_id'],attempt=1,status='completed',data=dict(native_source=source))])
    planref=ref('retained-plan.json',plan['schema']);planref.update(bytes=str(len(m.encoded(plan))),sha256=digest(m.encoded(plan)))
    selection=dict(version=1,selected_inputs=[dict(artifact_root='.',selected_state=copy.deepcopy(state),plan=planref,model=ref('model.json','qcl-negf-resolved-configuration-v3'))])
    spec=dict(schema='qcl-negf.capture-spec.v3',capture_token='a'*32,selection=dict(calcjob_uuid=calcjob,execution_id=launch['execution_id'],
        attempt=launch['transport_attempt'],plan_fingerprint=plan['fingerprint']),plan=dict(path='plan.json',bytes=len(m.encoded(plan)),sha256=digest(m.encoded(plan))),
        allocation_id='calcjob-process:'+calcjob+':'+str(launch['transport_attempt']),allocated_logical_cpus=None,scratch_root=None,
        credits=dict(performance_bytes=32*1024**2,scalar_bytes=64*1024**2,io_bytes=128*1024**2,reserve_bytes=4096),native_performance=dict(run_uuid=launch['run_uuid']))
    locator=dict(schema='qcl-negf.capture-source.v3',capture_token=spec['capture_token'],execution_id=launch['execution_id'],plan_fingerprint=plan['fingerprint'],
        mode='direct',actual_root=root,epoch=0,root_birth=dict(boot_id=boot,mount_namespace_device='4',mount_namespace_inode='8',producer_pid='123',
            producer_start_ticks='99',device='11',inode='12'))
    documents={'plan.json':plan,'source-graph.json':graph,'native-execution.json':native,'capture-spec.json':spec,'capture-source.json':locator,
        'series_result.json':result,'native-selection.json':selection}
    raws={key:m.encoded(value) for key,value in documents.items()}
    for role,name in m.FILES.items():
        raw=raws.get(name,b'fixed script fixture')
        launch['files'][role]=dict(bytes=len(raw),sha256=digest(raw))
    return launch,dict(calcjob_uuid=calcjob,runner=runner,worker_boot_id=boot,output_root=root),raws


def p20_original_records():
    """Typed root-local journal operands; not live original creator evidence."""
    m=module();document=request();launch=document['launch'];calc=document['calcjob_uuid'];dispatch='88888888-8888-4888-8888-888888888888'
    context=dict(machine_id='d'*32,boot_id='99999999-9999-4999-8999-999999999999',image_id='/nix/store/controller')
    policy=dict(spool_root='/local/spool',tools=dict(runuser='/nix/store/runuser',sbatch='/nix/store/sbatch'))
    snapshot=dict(script_path='/local/spool/'+dispatch+'.sh',script_sha256=launch['files']['submit_script']['sha256'])
    fields=dict(JobId='42',UserId='qcl-negf(3000)',JobState='COMPLETED',ExitCode='0:0',NumNodes='1',NumTasks='1',NodeList='node-a',
        SubmitTime='2026-10-30T01:00:00',StartTime='2026-10-30T01:00:01',Restarts='0',MinMemoryNode='256',
        Command=snapshot['script_path'],Comment=dispatch,WorkDir=launch['remote_workdir'])
    generation=hashlib.sha256(m.encoded(dict(controller=context,job_id='42',submit_time=fields['SubmitTime'],dispatch_id=dispatch,
        command=fields['Command'],workdir=fields['WorkDir']))).hexdigest()
    job=dict(job_id='42',cluster='cluster',submit_time=fields['SubmitTime'],controller_machine_id=context['machine_id'],
        controller_boot_id=context['boot_id'],dispatch_id=dispatch,generation=generation,node_name='node-a',start_time=fields['StartTime'],
        worker_machine_id='c'*32,worker_boot_id='11111111-1111-4111-8111-111111111111')
    source=m.NativeSources(policy,m._bootstrap_operation())
    actor=dict(calcjob_uuid=calc,action='submit',launch=copy.deepcopy(launch),execution_sha256=launch['files']['native_execution']['sha256'])
    process=dict(pid=50,ppid=1,start_ticks=10,uids=[0]*4,state='S',comm='python',
        cgroup='/system.slice/qcl-negf-native-attempt@original.service',executable='/nix/store/python')
    caller=dict(application=dict(configuration=dict(client=dict(bash_executable='/nix/store/bash'))),unit={'original':'fixture'},profile={'original':'fixture'},chain=[{'original':'fixture'}])
    owner=dict(process=process,host=context,unit=dict(MainPID='50',ControlGroup=process['cgroup'],InvocationID='a'*32,ActiveState='active'),caller=caller,actor=actor)
    records={'claim.json':dict(launch=launch,dispatch_id=dispatch,context=context),
        'dispatch.json':dict(dispatch_id=dispatch,snapshot=snapshot,context=context,native=dict(argv=source._argv(launch,snapshot,dispatch),script_sha256=snapshot['script_sha256'],owner=owner)),
        'ack.json':dict(job_id='42',cluster='cluster'),'job.json':job,'allocation.json':copy.deepcopy(job)}
    native=__import__('host_resource_facts').parse_slurm_jobs(' '.join(k+'='+v for k,v in fields.items()),cluster='cluster')['42']
    return source,calc,records,native,fields


@pytest.mark.parametrize('fault',[None,'dispatch','ack','context','native_generation','resource_generation','command','workdir','actor','owner','allocation','partial'])
def test_completed_original_journal_join_keeps_generation_domains_distinct(fault):
    m=module();source,calc,records,native,fields=p20_original_records()
    if fault=='dispatch':records['dispatch.json']['dispatch_id']=calc
    if fault=='ack':records['ack.json']['job_id']='43'
    if fault=='context':records['dispatch.json']['context']={'other':'controller'}
    if fault=='native_generation':records['allocation.json']['generation']='e'*64
    if fault=='resource_generation':records['allocation.json']['generation']=native['generation']
    if fault=='command':fields['Command']='/other/script.sh'
    if fault=='workdir':fields['WorkDir']='/other/workdir'
    if fault=='actor':records['dispatch.json']['native']['owner']['actor']['calcjob_uuid']=records['claim.json']['dispatch_id']
    if fault=='owner':records['dispatch.json']['native']['owner']['process']['uids']=[3000]*4
    if fault=='allocation':records['allocation.json']['worker_boot_id']='77777777-7777-4777-8777-777777777777'
    if fault=='partial':records['ack.json']=None
    q=dict(worker_bindings={'c'*32:dict(machine_id='c'*32,boot_id='11111111-1111-4111-8111-111111111111')},
        unit_origins={'server':dict(executable='/nix/store/python')},write_domain=dict(writer_hosts={'node-a':'c'*32}))
    source.qualification=q
    if fault is None:
        value=m._output_original_records(source,calc,records,native,fields,records['claim.json']['context'])
        assert value['job']['generation']!=native['generation'] and value['launch']==records['claim.json']['launch']
        assert 'durable' not in value
    else:
        with pytest.raises(m.Hold):m._output_original_records(source,calc,records,native,fields,records['claim.json']['context'])


@pytest.mark.parametrize('fault',[None,'current_release','code','graph','runner','manifest','script','legacy'])
def test_completed_release_source_is_current_and_original_not_hash_only(actor_bridge,monkeypatch,fault):
    s=actor_bridge;m=s['m'];source=s['sources'];launch=s['document']['launch'];runner=p20_runner()
    value=s['value'];runner.update(solver_executable=value['solver_executable'],source_graph_sha256=launch['files']['source_graph']['sha256'],
        julia_manifest_sha256=value['solver_build']['julia_manifest_sha256'],runner_revision=next(row['revision'] for row in value['sources']['components'] if row['path']=='components/QCLNEGFRunner.jl'))
    snapshot=dict(script_path='/local/spool/original.sh',script_sha256=launch['files']['submit_script']['sha256'])
    source.policy['spool_root']='/local/spool';raw=s['files']['submit_script']
    # This original stock scheduler fixture uses legacy unset/native-free argv.
    # Upgrade only this synthetic script to the approved fixed capture subset.
    raw=raw.replace(b'unset QCL_NEGF_CAPTURE_SPEC',b'export QCL_NEGF_CAPTURE_SPEC=capture-spec.json QCL_NEGF_NATIVE_CAPTURE_INPUT=native-execution.json')
    raw=raw.replace(b"  > 'solver.stdout'",(" '--native-execution' 'native-execution.json' '--native-calcjob-uuid' '"+s['document']['calcjob_uuid']+"'  > 'solver.stdout'").encode())
    launch['files']['submit_script']=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest());snapshot['script_sha256']=launch['files']['submit_script']['sha256']
    original=m.protected_read
    def reading(path,budget,limit=65536):
        if str(path)==snapshot['script_path']:return raw
        data=original(path,budget,limit)
        if fault=='current_release' and str(path).endswith('/release.json'):
            doc=json.loads(data);doc['release_id']='other-release';return m.encoded(doc)
        if fault=='code' and '/records/release-' in str(path):
            doc=json.loads(data);doc['code_uuid']=s['document']['calcjob_uuid'];return m.encoded(doc)
        return data
    monkeypatch.setattr(m,'protected_read',reading)
    if fault=='graph':runner['source_graph_sha256']='e'*64
    if fault=='runner':runner['runner_revision']='e'*40
    if fault=='manifest':runner['julia_manifest_sha256']='e'*64
    if fault=='script':snapshot['script_sha256']='e'*64
    if fault=='legacy':raw=raw.replace(b'export QCL_NEGF_CAPTURE_SPEC=capture-spec.json QCL_NEGF_NATIVE_CAPTURE_INPUT=native-execution.json',b'unset QCL_NEGF_CAPTURE_SPEC')
    caller=dict(application=dict(configuration=dict(client=dict(bash_executable='/nix/store/bash/bin/bash'))))
    joined=dict(launch=launch,snapshot=snapshot,caller=caller)
    if fault is None:assert m._output_release_source(source,s['document']['calcjob_uuid'],joined,runner) is None
    else:
        with pytest.raises((m.Hold,ValueError)):m._output_release_source(source,s['document']['calcjob_uuid'],joined,runner)


@pytest.mark.parametrize('state',['missing_policy','missing_qualification','old_qualification','malformed_policy','bad_ingress'])
def test_noarg_scheduler_factory_preserves_complete_jobs_without_optional_authority(monkeypatch,state):
    """Explicit factory I/O seams; no root/native authority is supplied by jobs."""
    m=module();import host_resource_service as service,host_resource_facts as facts
    jobs={str(i):dict(state='RUNNING',unchanged=i) for i in range(10)};events=[]
    config=dict(schema='qcl.host-resource-service.v1',role='controller',client_uid=3000,
        facts_uid=3002,sudo_executables=['/nix/store/sudo'],tools=['/nix/store/scontrol'],
        slurm_conf='/protected/slurm.conf',scontrol='/nix/store/scontrol',cluster='cluster')
    monkeypatch.setattr(m.os,'getuid',lambda:0);monkeypatch.setattr(m.os,'geteuid',lambda:0)
    monkeypatch.setattr(m,'protected_read',lambda path,budget,limit=65536:m.encoded(config))
    def ingress(*a):
        events.append('ingress')
        if state=='bad_ingress':raise m.Hold('facts_entry_unavailable')
        return {'actual':'explicit SOURCE fixture'}
    monkeypatch.setattr(service,'_scheduler_facts_ingress',ingress)
    def policy(role,budget):
        events.append('policy')
        if state=='malformed_policy':raise m.Hold('shape')
        if state=='missing_policy':raise m.Hold('native_policy_missing')
        return dict(facts_service_config=str(service.CONFIG),worker_routes={'node-a':{}},
            tools=dict(scontrol=config['scontrol']),slurm=dict(config_file=config['slurm_conf'],cluster='cluster'),
            qualification_file='/protected/native-q',limits=budget.limits)
    monkeypatch.setattr(m,'_load_policy',policy)
    def q(self):
        if state=='missing_qualification':raise m.Hold('native_qualification_missing')
        self.qualification={};return {}
    monkeypatch.setattr(m.NativeSources,'qualify',q)
    monkeypatch.setattr(facts,'NativeCommandRunner',lambda *a,**kw:object(),raising=False)
    monkeypatch.setattr(service,'NativeCommandRunner',lambda *a,**kw:object())
    monkeypatch.setattr(facts,'capture_scheduler',lambda config,sources:events.append(('scheduler',sources)) or jobs)
    monkeypatch.setattr(m,'_scheduler_output_entries',lambda *a:pytest.fail('old/absent binding attempted close'),raising=False)
    if state in ('malformed_policy','bad_ingress'):
        with pytest.raises(m.Hold):m.capture_scheduler_output_facts()
    else:
        packet=m.capture_scheduler_output_facts()
        assert packet==dict(schema='qcl.host-resource-scheduler-facts.v1',jobs=jobs,outputs={})
        assert packet['jobs'] is jobs and len([x for x in events if isinstance(x,tuple)])==1
    assert events[0]=='ingress'


@pytest.mark.parametrize('fault',[None,'no_close','legacy','technical','partial_pair','partial_original','forged_generation',
    'duplicate','nine','cancel','late_source','raw_corruption','fixture_positive','fixture_ordinary_script',
    'fixture_ordinary_r','fixture_wrong_held_plan','fixture_late_held_plan'])
def test_scheduler_output_selection_is_finite_atomic_and_uses_original_owner(tmp_path,monkeypatch,fault):
    """Composition L: real private store/read/lock and original join; mocked OS,
    installed-source and held-reader operands remain explicit synthetic seams.
    Actual held-FD/close adversaries are exercised separately below.
    """
    import contextlib,uuid
    import host_resource_facts as facts
    m=module();source,calc,records,native,fields=p20_original_records();budget=source.budget
    source.policy.update(private_root=str(tmp_path),jobs_root='/srv/qcl-negf/jobs',native_result_prefix='native',
        slurm=dict(cluster='cluster'),limits=budget.limits,_policy_sha256='e'*64)
    store=m.AttemptStore(tmp_path);worker=p20_worker();runner=p20_runner()
    publication=fault.startswith('fixture_') if isinstance(fault,str) else False
    metadata=None;fixture_script=None
    if publication:
        launch,inputs,raws=publication_metadata_profile();runner=inputs['runner'];metadata=(launch,inputs,raws)
        if fault=='fixture_ordinary_r':del runner['engineering_fixture']
        fixture_script=NATIVE_ORIGIN_SCRIPT.replace(b"'run-plan'",b"'native-publication-fixture'").replace(b"'execution'",b"'execution-1'")
        fixture_script=fixture_script.replace(b'unset QCL_NEGF_CAPTURE_SPEC',b'export QCL_NEGF_CAPTURE_SPEC=capture-spec.json QCL_NEGF_NATIVE_CAPTURE_INPUT=native-execution.json')
        fixture_script=fixture_script.replace(b'fixture-release',launch['release_id'].encode()).replace(b'/nix/store/synthetic/bin/qcl-negf',runner['solver_executable'].encode())
        fixture_script=fixture_script.replace(b'/srv/qcl-negf/jobs/native/new-domain',('/srv/qcl-negf/jobs/'+launch['relative_execution_root']).encode()).replace(NATIVE_ORIGIN_CALCJOB.encode(),calc.encode())
        if fault=='fixture_ordinary_script':fixture_script=fixture_script.replace(b"'native-publication-fixture'",b"'run-plan'")
        launch['files']['submit_script']=dict(bytes=len(fixture_script),sha256=hashlib.sha256(fixture_script).hexdigest())
        records['claim.json']['launch']=launch
        records['dispatch.json']['snapshot']['script_sha256']=launch['files']['submit_script']['sha256']
        original=records['dispatch.json']['native'];original['script_sha256']=launch['files']['submit_script']['sha256']
        original['argv']=source._argv(launch,records['dispatch.json']['snapshot'],records['claim.json']['dispatch_id'])
        original['owner']['actor'].update(launch=copy.deepcopy(launch),execution_sha256=launch['files']['native_execution']['sha256'])
        monkeypatch.setattr(source,'origin',lambda path:path)
    controller=dict(identity=dict(machine_id=records['claim.json']['context']['machine_id'],boot_id=records['claim.json']['context']['boot_id'],
        kernel='synthetic-kernel',dmi_uuid='33333333-3333-4333-8333-333333333333'),units=[p20_unit('qcl-negf-aiida.service'),p20_unit('qcl-negf-api.service')])
    generation=dict(controller=controller,workers=[worker]);gsha=hashlib.sha256(m.encoded(generation)).hexdigest()
    source.qualification=dict(completed_final=dict(runner=runner,unit_generation_sha256=gsha,worker_generations={'node-a':worker}),
        unit_origins={'server':dict(executable='/nix/store/python')},worker_bindings={'c'*32:{key:worker['identity'][key] for key in ('machine_id','boot_id')}},
        write_domain=dict(writer_hosts={'node-a':'c'*32},storage_identity='storage',retention_ref='retained'))
    source._qualification_sha256='f'*64
    jobs={};allrecords={};fields_by_job={};closed_by_calc={};witnesses={}
    count=9 if fault=='nine' else 2 if fault=='duplicate' else 1
    for i in range(count):
        current=copy.deepcopy(records);cid=calc if publication else str(uuid.UUID(int=i+1));jobid='42' if fault=='duplicate' else str(42+i)
        for name in ('ack.json','job.json','allocation.json'):current[name]['job_id']=jobid
        current['dispatch.json']['native']['owner']['actor']['calcjob_uuid']=cid
        f={**fields,'JobId':jobid};raw=' '.join(k+'='+v for k,v in f.items());jobs[jobid]=facts.parse_slurm_jobs(raw,cluster='cluster')[jobid]
        for name in ('job.json','allocation.json'):
            current[name]['generation']=hashlib.sha256(m.encoded(dict(controller=current['claim.json']['context'],job_id=jobid,
                submit_time=f['SubmitTime'],dispatch_id=current['claim.json']['dispatch_id'],command=f['Command'],workdir=f['WorkDir']))).hexdigest()
        if fault=='forged_generation':current['allocation.json']['generation']=jobs[jobid]['generation']
        controls=[dict(path=name,bytes=2,sha256=hashlib.sha256(b'{}').hexdigest()) for name in m.CLOSE_FILES]
        document=dict(version=3,action='close',calcjob_uuid=cid,launch=current['claim.json']['launch'],controls=controls,
            technical_control=dict(status='absent',path=m.TECHNICAL_FILE,reason='not_published'))
        closed=m.reply(document,'closed',job=current['allocation.json'],controls=controls,technical_control=document['technical_control'],receipt=cid+'/close.json')
        if fault=='legacy':closed.pop('technical_control');closed['version']=1
        if fault=='technical':closed['technical_control']=dict(status='present',path=m.TECHNICAL_FILE,bytes='2',sha256=controls[0]['sha256'])
        observed=dict(job=dict(raw=raw,fields=f),prolog_ref='original-prolog',epilog_ref='original-epilog',before=None,after=None)
        witness=dict(job=current['allocation.json'],launch=current['claim.json']['launch'],worker_close={**observed,'before':{'processes':[]},'after':{'original':'stop'}})
        with store.locked(cid,budget):
            for name,value in current.items():
                if fault=='partial_original' and name=='ack.json':continue
                store.put(cid,name,value,budget)
            if fault!='no_close':store.put(cid,'close.json',closed,budget)
            if fault not in ('no_close','partial_pair'):store.put(cid,'close-observation.json',witness,budget)
        allrecords[cid]=current;fields_by_job[jobid]=observed;closed_by_calc[cid]=closed;witnesses[cid]=witness
    calls=[];guards=[];source_calls=[];primary=KeyboardInterrupt('actual original cancel')
    monkeypatch.setattr(source,'native_job',lambda job:copy.deepcopy(fields_by_job[job]['job']))
    monkeypatch.setattr(source,'worker',lambda job,calc,phase,budget:copy.deepcopy(fields_by_job[job['job_id']]))
    monkeypatch.setattr(m,'protected_read',lambda path,budget,limit=65536:m.encoded(dict(calcjob_uuid=next(iter(allrecords)),domain=records['claim.json']['launch']['relative_execution_root'])))
    def release(*args):
        source_calls.append(True)
        if publication:
            m._review_native_script(fixture_script,args[2]['launch'],runner['solver_executable'],'/bin/bash',source,
                calcjob_uuid=args[1],engineering_fixture=runner.get('engineering_fixture'))
        if fault=='late_source' and len(source_calls)>1:raise m.Hold('release_binding_changed')
    monkeypatch.setattr(m,'_output_release_source',release)
    def close(owner,document,job,context,observed,controls,**kwargs):
        calls.append(document['calcjob_uuid']);assert kwargs['facts_guard'] is guard and kwargs['facts_inputs']['runner']==runner
        if fault=='cancel':raise primary
        if publication:
            launch,inputs,raws=metadata
            assert document['launch']==launch and kwargs['facts_inputs']==inputs
            changed=copy.deepcopy(raws)
            if fault=='fixture_wrong_held_plan':
                plan=json.loads(changed['plan.json']);plan['root_definition_id']='ordinary';changed['plan.json']=m.encoded(plan)
            proof=m._completed_metadata(launch,inputs,changed,(11,12),budget=source.budget)
            if fault=='fixture_late_held_plan':
                changed['plan.json']+=b' ';m._completed_metadata(launch,inputs,changed,(11,12),budget=source.budget)
        cid=document['calcjob_uuid'];closed=closed_by_calc[cid];witness=witnesses[cid]
        return dict(original_close=(closed,m.encoded(closed)),original_observation=(witness,m.encoded(witness)),
            current_worker=observed,w1_before={'output_generation':generation},w1_after={'output_generation':generation},
            control_read={'binding':{'root_birth':dict(producer_pid='123',producer_start_ticks='99')}})
    monkeypatch.setattr(m.OrdinaryAttemptOwner,'_close',close)
    def guard():guards.append(True)
    if fault=='raw_corruption':fields_by_job['42']['job']['raw']+=' JobId=42'
    frozen={str(p.relative_to(store.root)):p.read_bytes() for p in store.root.rglob('*') if p.is_file()}
    selected=lambda:m._scheduler_output_entries(source,store,jobs,records['claim.json']['context'],runner,guard)
    if fault in ('fixture_ordinary_script','fixture_ordinary_r','fixture_wrong_held_plan','fixture_late_held_plan'):
        with pytest.raises(m.Hold):selected()
        assert {str(p.relative_to(store.root)):p.read_bytes() for p in store.root.rglob('*') if p.is_file()}==frozen
        assert calls==([] if fault in ('fixture_ordinary_script','fixture_ordinary_r') else [calc])
    elif fault in ('partial_pair','partial_original','forged_generation','duplicate','nine','cancel','late_source','raw_corruption'):
        with pytest.raises(KeyboardInterrupt if fault=='cancel' else m.Hold) as caught:selected()
        if fault=='cancel':assert caught.value is primary
        if fault in ('partial_pair','partial_original','duplicate','nine','forged_generation','raw_corruption'):assert calls==[]
    else:
        values=selected()
        if fault in ('no_close','legacy','technical'):assert values=={} and calls==[]
        else:
            assert len(calls)==len(values)==1;value=values[native['generation']]
            assert value['scope']=='completed_final' and value['attempt']['generation']!=value['generation']
            assert facts._scheduler_output_observations(dict(schema='qcl.host-resource-scheduler-facts.v1',jobs=jobs,outputs=values))==values


@pytest.mark.parametrize('fault',[None,'missing','populated','process','tuple','identity','nonzero'])
def test_completed_current_worker_requires_actual_empty_original_allocation(fault):
    m=module();source,calc,records,native,fields=p20_original_records();job=records['allocation.json']
    identity=dict(machine_id=job['worker_machine_id'],boot_id=job['worker_boot_id'])
    raw=' '.join(k+'='+v for k,v in fields.items())
    observed=dict(job=dict(raw=raw,fields=fields),prolog_ref='original-prolog',epilog_ref='original-epilog',
        identity={'identity':identity},writer_snapshot=dict(schema='qcl.host-resource-guest-facts.v1',identity_before=identity,
            identity_after=dict(identity),jobs={'42':native},groups={'42':dict(populated=False,processes=[])}))
    if fault=='missing':observed['writer_snapshot']['jobs']={}
    if fault=='populated':observed['writer_snapshot']['groups']['42']['populated']=True
    if fault=='process':observed['writer_snapshot']['groups']['42']['processes']=[{'pid':123}]
    if fault=='tuple':native['start_time']='2026-10-30T02:00:00'
    if fault=='identity':observed['writer_snapshot']['identity_after']['boot_id']='77777777-7777-4777-8777-777777777777'
    if fault=='nonzero':observed['job']['fields']['ExitCode']='1:0'
    if fault is None:assert m._completed_worker_status(observed,job)==native
    else:
        with pytest.raises((m.Hold,m.ResourceError)):m._completed_worker_status(observed,job)


@pytest.mark.parametrize('fault',[None,'token','boot','root_inode','producer_zero','mode','epoch','calcjob','transport','run','plan_path','plan_digest',
    'graph_revision','native_code','native_uuid','history','history_type','count_bool','actual_root','absent','checkpoint','retained','old_epoch','point_attempt','model','extra_selection','missing_point','failed','traversal'])
def test_completed_metadata_profile_never_substitutes_locator_for_creator(monkeypatch,fault):
    m=module();launch,inputs,raws=p20_metadata_profile();docs={key:json.loads(raw) for key,raw in raws.items()}
    spec=docs['capture-spec.json'];locator=docs['capture-source.json'];result=docs['series_result.json'];selected=docs['native-selection.json']
    if fault=='token':locator['capture_token']='b'*32
    if fault=='boot':locator['root_birth']['boot_id']='99999999-9999-4999-8999-999999999999'
    if fault=='root_inode':locator['root_birth']['inode']='13'
    if fault=='producer_zero':locator['root_birth']['producer_pid']='0'
    if fault=='mode':locator['mode']='staged'
    if fault=='epoch':locator['epoch']=1
    if fault=='calcjob':spec['selection']['calcjob_uuid']=launch['request_id']
    if fault=='transport':spec['selection']['attempt']+=1
    if fault=='run':spec['native_performance']['run_uuid']=launch['request_id']
    if fault=='plan_path':spec['plan']['path']='other-plan.json'
    if fault=='plan_digest':spec['plan']['sha256']='f'*64
    if fault=='graph_revision':docs['source-graph.json']['components'][0]['revision']='e'*40
    if fault=='native_code':docs['native-execution.json']['code']['solver_executable']='/nix/store/other/bin/qcl-negf'
    if fault=='native_uuid':docs['native-execution.json']['storage']['execution_binding_uuid']=launch['request_id']
    if fault=='history':result['attempt_history']=[copy.deepcopy(result['points'][0])]
    if fault=='history_type':result['attempt_history']={}
    if fault=='count_bool':result['expected_point_count']=result['available_point_count']=True
    if fault=='actual_root':locator['actual_root']='/foreign/alias/'+launch['relative_execution_root']
    source=result['points'][0]['data']['native_source']
    if fault=='absent':source['kind']='absent'
    if fault=='checkpoint':source['kind']='checkpoint'
    if fault=='retained':source['relation']='retained_source'
    if fault=='old_epoch':source['selected_state']['state_id']='epoch-1-state-1'
    if fault=='point_attempt':result['points'][0]['attempt']=2
    if fault=='model':source['selected_state']['identity']['model_sha256']='e'*64
    if fault=='extra_selection':selected['selected_inputs'].append(copy.deepcopy(selected['selected_inputs'][0]))
    if fault=='missing_point':result['points']=[]
    if fault=='failed':result['status']='failed'
    if fault=='traversal':source['artifact_root']='../foreign'
    raws={key:m.encoded(value) for key,value in docs.items()}
    if fault is None:
        proof=m._completed_metadata(launch,inputs,raws,(11,12))
        assert proof['selected_points']==1 and proof['root_birth']==locator['root_birth']
        assert 'creator_verified' not in proof and 'durable' not in proof
    else:
        with pytest.raises(m.Hold):m._completed_metadata(launch,inputs,raws,(11,12))


@pytest.mark.parametrize('fault',[None,'extra','missing','path','roles','alias','manifest','size','total','revision','capture_path'])
def test_completed_final_runner_closed_fixed_roles_and_bounds(fault):
    m=module();runner=p20_runner()
    if fault=='extra':runner['certificate']=True
    if fault=='missing':del runner['runner_revision']
    if fault=='path':runner['files']['execution']['path']='/tmp/unchecked.jl'
    if fault=='roles':runner['files']['other']=runner['files'].pop('native_lane')
    if fault=='alias':runner['files']['capture_cli']['path']=runner['files']['capture_runtime']['path']
    if fault=='manifest':runner['julia_manifest_sha256']='e'*64
    if fault=='size':runner['files']['launcher']['bytes']=1048577
    if fault=='total':
        for row in runner['files'].values():row['bytes']=200000
    if fault=='revision':runner['runner_revision']='dirty-main'
    if fault=='capture_path':runner['files']['capture_cli']['path']='/nix/store/foreign/cli.py'
    if fault is None:assert m._output_runner(runner)==runner
    else:
        with pytest.raises(m.Hold):m._output_runner(runner)


@pytest.mark.parametrize('fault',[None,'extra','bool_pid','birth','uid','invocation','state','namespace','line','bytes'])
def test_completed_final_worker_unit_projection_is_closed_and_finite(fault):
    m=module();worker=p20_worker()
    if fault=='extra':worker['unit']['main']['raw_proc']=b'not admitted'
    if fault=='bool_pid':worker['unit']['main']['pid']=True
    if fault=='birth':worker['unit']['main']['start_ticks']=0
    if fault=='uid':worker['unit']['main']['uids']=[3000]*4
    if fault=='invocation':worker['unit']['state']['InvocationID']='0'*32
    if fault=='state':worker['unit']['state']['ActiveState']='inactive'
    if fault=='namespace':worker['unit']['mount_namespace']['inode']=0
    if fault=='line':worker['unit']['mount_line']+='\n'
    if fault=='bytes':worker['unit']['mount_line']='x'*8193
    if fault is None:assert m._output_worker(worker)==worker
    else:
        with pytest.raises(m.Hold):m._output_worker(worker)


@pytest.mark.parametrize('engineering',[False,True])
@pytest.mark.parametrize('fault',[None,'capture_selector','capture_selector_wrong','absent','null','extra','worker_omitted','corrupt','origin_drift','alias','read_failure','cancel'])
def test_completed_runner_qualifies_all_exact_sources_before_return(monkeypatch,fault,engineering):
    m=module();runner=p20_runner();binding=dict(runner=runner,unit_generation_sha256='d'*64,worker_generations={'node-a':p20_worker()})
    if engineering:runner['engineering_fixture']='native-publication-v1'
    if fault=='null':binding=None
    if fault=='extra':binding['pending']=True
    if fault=='worker_omitted':binding['worker_generations']={}
    source=m.NativeSources(dict(worker_routes={'node-a':{}}),m.Operation({**limits(),'maximum_files':2048}))
    if fault in ('capture_selector','capture_selector_wrong'):runner['capture_executable']='/nix/store/synthetic-selector/bin/qcl-negf-results'
    source.qualification={} if fault=='absent' else {'completed_final':binding}
    calls=[];seen={};paths=list(runner['files'].values());index={row['path']:i+1 for i,row in enumerate(paths)}
    def origin(budget,path,**kwargs):
        if path==runner['capture_executable'] and path not in index:
            actual=runner['files']['capture_entry']['path']
            return dict(path='/nix/store/wrong/bin/qcl-negf-results' if fault=='capture_selector_wrong' else actual,
                chain=[(path,(4,999,m.stat.S_IFLNK|0o777,0,3,1,1),actual),
                       (actual,(4,index[actual],m.stat.S_IFREG|0o555,0,3,1,1),None)])
        seen[path]=seen.get(path,0)+1;inode=index[path]
        if fault=='alias' and path==runner['files']['capture_cli']['path']:inode=index[runner['files']['capture_entry']['path']]
        if fault=='origin_drift' and seen[path]>1:inode+=100
        return dict(path=path,chain=[(path,(4,inode,m.stat.S_IFREG|0o444,0,3,1,1),None)])
    primary=KeyboardInterrupt('actual source cancellation')
    def read(budget,path,limit):
        assert limit==3 and budget is source.budget and budget.bytes>=4
        calls.append(path)
        if fault=='read_failure':raise OSError('actual source read failure')
        if fault=='cancel':raise primary
        return b'abd' if fault=='corrupt' else b'abc'
    monkeypatch.setattr(m.engine,'public_binary_origin',origin);monkeypatch.setattr(m.engine,'immutable_public_bytes',read)
    if fault in (None,'capture_selector'):assert source.completed_final_runner()==runner and len(calls)==13
    else:
        with pytest.raises(KeyboardInterrupt if fault=='cancel' else OSError if fault=='read_failure' else m.Hold) as caught:
            source.completed_final_runner()
        if fault=='cancel':assert caught.value is primary
        if fault in ('absent','null','extra','worker_omitted'):assert calls==[] and seen=={}


@pytest.mark.parametrize('fault',[None,'unit_drift','birth_drift','namespace_drift','mount_rw','mount_hard','mount_alias','executable'])
def test_unit_generation_reads_actual_process_and_mount_namespace_before_after(monkeypatch,fault):
    from types import SimpleNamespace
    m=module();expected=p20_unit('qcl-negf-aiida.service');budget=m.Operation({**limits(),'maximum_files':2048})
    source=m.NativeSources(dict(client_uid=3000,jobs_root='/srv/qcl-negf/jobs',native_result_prefix='native',nfs_source='storage:/jobs'),budget)
    source.qualification={'unit_origins':{expected['name']:dict(executable=expected['main']['executable'])}}
    calls={'unit':0,'main':0,'ns':0};reads=[]
    def unit(name):
        assert name==expected['name'];calls['unit']+=1;value=copy.deepcopy(expected['state'])
        if fault=='unit_drift' and calls['unit']>1:value['InvocationID']='2'*32
        return value
    def process(pid):
        assert pid==123;calls['main']+=1;value={**expected['main'],'state':'S'}
        if fault=='birth_drift' and calls['main']>1:value['start_ticks']+=1
        if fault=='executable':value['executable']='/tmp/python'
        return value
    def namespace(path,**kwargs):
        assert str(path)=='/proc/123/ns/mnt' and kwargs=={'follow_symlinks':True};calls['ns']+=1
        return SimpleNamespace(st_dev=4,st_ino=9 if fault=='namespace_drift' and calls['ns']>1 else 8)
    def read(path,limit=65536):
        reads.append(str(path));assert str(path)=='/proc/123/mountinfo';raw=expected['mount_line']
        if fault=='mount_rw':raw=raw.replace('native ro','native rw')
        if fault=='mount_hard':raw=raw.replace(',hard','')
        if fault=='mount_alias':raw+='\n'+raw
        return (raw+'\n').encode()
    monkeypatch.setattr(source,'unit',unit);monkeypatch.setattr(source,'process',process)
    monkeypatch.setattr(source,'origin',lambda path:path)
    monkeypatch.setattr(budget,'stat',namespace);monkeypatch.setattr(budget,'read',read)
    if fault is None:
        assert source.output_unit_generation(expected['name'],readonly=True)==expected
        assert calls=={'unit':2,'main':2,'ns':2} and reads==['/proc/123/mountinfo']
    else:
        with pytest.raises(m.Hold):source.output_unit_generation(expected['name'],readonly=True)


@pytest.mark.parametrize('fault',[None,'absent','null','unit','identity','runner','qualification_drift'])
def test_worker_output_tuple_is_current_local_expected_branch_on_same_operation(monkeypatch,fault):
    m=module();worker=p20_worker();runner=p20_runner();budget=m.Operation({**limits(),'maximum_files':2048})
    binding=dict(runner=runner,unit_generation_sha256='d'*64,worker_generations={'node-a':worker})
    source=m.NativeSources(dict(worker_routes={'node-a':{}}),budget)
    source.qualification={} if fault=='absent' else dict(completed_final=None if fault=='null' else binding,
        write_domain=dict(writer_hosts={'node-a':worker['identity']['machine_id']}))
    host={key:worker['identity'][key] for key in ('machine_id','boot_id')};host['image_id']='/nix/store/synthetic-image'
    calls=[]
    def qualify():
        calls.append('qualify');source._qualification_sha256=('c' if fault=='qualification_drift' and len(calls)>1 else 'a')*64
        return host
    def actual_runner():
        value=copy.deepcopy(runner)
        if fault=='runner':value['runner_revision']='c'*40
        return value
    def unit(name,*,readonly):
        assert name=='slurmd.service' and readonly is False;value=copy.deepcopy(worker['unit'])
        if fault=='unit':value['main']['start_ticks']+=1
        return value
    def read(path,limit=65536):
        if str(path)=='/proc/sys/kernel/osrelease':return b'synthetic-kernel\n'
        assert str(path)=='/sys/class/dmi/id/product_uuid'
        return ((('9' if fault=='identity' else '2')*8)+'-2222-4222-8222-222222222222\n').encode()
    monkeypatch.setattr(source,'qualify',qualify);monkeypatch.setattr(source,'host',lambda:host)
    monkeypatch.setattr(source,'completed_final_runner',actual_runner);monkeypatch.setattr(source,'output_unit_generation',unit)
    monkeypatch.setattr(budget,'read',read)
    if fault=='absent':assert m._worker_output_generation(source) is None and calls==[]
    elif fault is None:
        value=m._worker_output_generation(source);assert value==dict(worker=worker,runner=runner) and source.budget is budget
    else:
        with pytest.raises(m.Hold):m._worker_output_generation(source)


@pytest.mark.parametrize('fault',[None,'missing_controller','controller_rw','worker_omitted','worker_only_hash','worker_source','worker_birth','controller_kernel','duplicate_worker'])
def test_full_generation_joins_two_controller_ro_units_and_all_enrolled_workers(monkeypatch,fault):
    m=module();worker=p20_worker();runner=p20_runner();identity={**worker['identity'],'machine_id':'a'*32,
        'boot_id':'88888888-8888-4888-8888-888888888888'}
    units=[dict(unit=name,output_unit=p20_unit(name)) for name in ('qcl-negf-aiida.service','qcl-negf-api.service')]
    workers=[dict(node='node-a',reply=dict(writer_snapshot=dict(output_generation=dict(worker=copy.deepcopy(worker),runner=copy.deepcopy(runner)))))]
    expected=dict(controller=dict(identity=identity,units=[row['output_unit'] for row in units]),workers=[worker])
    binding=dict(runner=runner,unit_generation_sha256=hashlib.sha256(m.encoded(expected)).hexdigest(),worker_generations={'node-a':worker})
    source=m.NativeSources(dict(worker_routes={'node-a':{}},jobs_root='/srv/qcl-negf/jobs',native_result_prefix='native',nfs_source='storage:/jobs'),m.Operation({**limits(),'maximum_files':2048}))
    source.qualification=dict(completed_final=binding,write_domain=dict(writer_hosts={'node-a':worker['identity']['machine_id']}))
    actual_identity=dict(identity)
    if fault=='missing_controller':units.pop()
    if fault=='controller_rw':units[0]['output_unit']['mount_line']=units[0]['output_unit']['mount_line'].replace('native ro','native rw')
    if fault=='worker_omitted':workers=[]
    if fault=='worker_only_hash':binding['unit_generation_sha256']=hashlib.sha256(m.encoded(worker)).hexdigest()
    if fault=='worker_source':workers[0]['reply']['writer_snapshot']['output_generation']['runner']['runner_revision']='b'*40
    if fault=='worker_birth':workers[0]['reply']['writer_snapshot']['output_generation']['worker']['unit']['main']['start_ticks']+=1
    if fault=='controller_kernel':actual_identity['kernel']='different-kernel'
    if fault=='duplicate_worker':workers.append(copy.deepcopy(workers[0]))
    monkeypatch.setattr(m,'_output_host',lambda actual:actual_identity)
    if fault is None:assert m._full_output_generation(source,units,workers)==expected
    else:
        with pytest.raises(m.Hold):m._full_output_generation(source,units,workers)


@pytest.mark.parametrize('state',['missing_directory','missing_file','existing','busy','symlink'])
def test_facts_attempt_lock_existing_only_never_creates_or_adopts(tmp_path,monkeypatch,state):
    """Real nofollow/flock in an explicit own unprivileged fixture namespace."""
    from contextlib import contextmanager
    m=module();store=m.AttemptStore(tmp_path);calcjob='11111111-1111-4111-8111-111111111111'
    @contextmanager
    def directory(path,create=False):
        if create:Path(path).mkdir(mode=0o700,exist_ok=True)
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:yield fd
        finally:os.close(fd)
    monkeypatch.setattr(store,'directory',directory)
    locks=tmp_path/'locks'
    if state!='missing_directory':locks.mkdir(mode=0o700)
    if state in ('existing','busy'):(locks/calcjob).write_bytes(b'');(locks/calcjob).chmod(0o600)
    if state=='symlink':
        (tmp_path/'foreign').write_bytes(b'preserve');(locks/calcjob).symlink_to(tmp_path/'foreign')
    before=sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob('*'));budget=m.Operation(limits())
    if state=='existing':
        with store.locked(calcjob,budget,existing_only=True):pass
    elif state=='busy':
        fd=os.open(locks/calcjob,os.O_RDWR);m.fcntl.flock(fd,m.fcntl.LOCK_EX|m.fcntl.LOCK_NB)
        try:
            with pytest.raises(m.Hold,match='attempt_busy'):
                with store.locked(calcjob,budget,existing_only=True):pytest.fail('busy lock admitted')
        finally:os.close(fd)
    else:
        with pytest.raises(OSError):
            with store.locked(calcjob,budget,existing_only=True):pytest.fail('unknown namespace admitted')
    assert sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob('*'))==before


@pytest.mark.parametrize('kind',['invariant','fatal','cancel'])
def test_existing_journal_directory_cleanup_preserves_its_primary(tmp_path,monkeypatch,kind):
    m=module();root=tmp_path/'owned-journal';root.mkdir(mode=0o700);store=m.AttemptStore(root)
    primary={'invariant':RuntimeError('original invariant'),
        'fatal':MemoryError('original allocation'),'cancel':KeyboardInterrupt('original cancellation')}[kind]
    close=m.os.close;closed=[]
    def closing(fd):close(fd);closed.append(fd);raise OSError('secondary held directory close failure')
    monkeypatch.setattr(m.os,'close',closing)
    with pytest.raises(type(primary)) as caught:
        with store.directory(root):raise primary
    assert caught.value is primary and closed and any('close' in note for note in primary.__notes__)
    for fd in closed:
        with pytest.raises(OSError):os.fstat(fd)


def request(action='submit'):
    claim = {'bytes': 3, 'sha256': hashlib.sha256(b'abc').hexdigest()}
    return {'version': 1, 'action': action, 'calcjob_uuid': '11111111-1111-4111-8111-111111111111',
            'launch': {'request_id': '22222222-2222-4222-8222-222222222222',
                       'run_uuid': '33333333-3333-4333-8333-333333333333', 'execution_id': 'execution-1',
                       'transport_attempt': 1, 'code_uuid': '44444444-4444-4444-8444-444444444444',
                       'release_id': 'release-1', 'native_execution_uuid': '55555555-5555-4555-8555-555555555555',
                       'input_plan_uuid': '66666666-6666-4666-8666-666666666666',
                       'source_graph_uuid': '77777777-7777-4777-8777-777777777777',
                       'relative_execution_root': 'native/run-1/execution-1',
                       'remote_workdir': '/srv/qcl-negf/jobs/upload/one',
                       'files': {name: copy.deepcopy(claim) for name in
                                 ('plan', 'source_graph', 'native_execution', 'submit_script')}},
            'controls': None}


def limits():
    return dict(request_bytes=65536, response_bytes=262144, script_bytes=65536,
                metadata_bytes=4 * 1024 * 1024, memory_bytes=134217728,
                operation_seconds=30, command_seconds=10, cleanup_seconds=1,
                maximum_pids=256, maximum_calls=64, maximum_files=128)


class Observations:
    """Private seam: production NativeSources body is tested separately."""
    def __init__(self, m):
        self.m, self.calls, self.fault = m, [], None

    def preflight(self, launch, budget, *, calcjob_uuid=None, action=None):
        budget.before()
        if self.fault == 'policy':
            raise self.m.Hold('native_qualification_missing')
        return {'machine_id': 'a' * 32, 'boot_id': '88888888-8888-4888-8888-888888888888'}

    def snapshot(self, launch, dispatch, budget):
        budget.reserve(3)
        return {'script_path': '/nix/store/' + 'a' * 32 + '-fixture/script',
                'script_sha256': launch['files']['submit_script']['sha256']}

    def dispatch(self, launch, snapshot, dispatch, budget):
        self.calls.append(dispatch)
        if self.fault == 'lost_ack':
            raise self.m.engine.CommandFailure({'failure': 'timeout', 'child_started': True,
                                               'cleanup_confirmed': True, 'stderr': 'original'})
        result = self.m.engine.CommandOutput('42;cluster\n')
        result.output_bytes = len(result) + (1 if self.fault == 'extra_bytes' else 0)
        return result

    def _intent(self, launch, snapshot, dispatch):
        return {'argv': ['fixture-sbatch', snapshot['script_path']], 'script_sha256': snapshot['script_sha256'],
                'owner': {'fixture_only': 'not native authority'}}

    def bind_job(self, ack, launch, dispatch, context, budget):
        return {'job_id': ack['job_id'], 'cluster': ack['cluster'], 'submit_time': '2026-10-29T01:00:00',
                'controller_machine_id': context['machine_id'], 'controller_boot_id': context['boot_id'],
                'dispatch_id': dispatch, 'generation': 'b' * 64, 'node_name': None, 'start_time': None,
                'worker_machine_id': None, 'worker_boot_id': None}


class MemoryConnection:
    """Bounded byte stream; sandbox socket IO is a separate native gate."""
    def __init__(self, raw):
        self.raw = raw

    def recv(self, size):
        result, self.raw = self.raw[:size], self.raw[size:]
        return result

    def settimeout(self, timeout):
        assert timeout > 0


def owner(tmp_path, observations=None):
    m = module()
    policy = {'private_root': str(tmp_path), 'limits': limits()}
    sources = observations or Observations(m)
    return m.OrdinaryAttemptOwner(policy, m.AttemptStore(tmp_path), sources, m.Operation(limits())), sources


def test_one_dispatch_durable_ack_and_fresh_owner_same_key(tmp_path):
    m = module()
    first, sources = owner(tmp_path)
    result = first.submit(request())
    assert result['state'] == 'bound' and result['job']['job_id'] == '42'
    assert len(sources.calls) == 1
    again = m.OrdinaryAttemptOwner(first.policy, m.AttemptStore(tmp_path), sources, m.Operation(limits()))
    assert again.submit(request())['job'] == result['job']
    assert len(sources.calls) == 1
    directory = tmp_path / 'attempts' / request()['calcjob_uuid']
    assert (directory / 'dispatch.json').is_file() and (directory / 'ack.json').is_file()
    assert json.loads((directory / 'dispatch.json').read_bytes())['native']['argv'][1].endswith('/script')


def test_lost_ack_repeated_key_never_dispatches_again_and_retains_primary(tmp_path):
    m = module()
    first, sources = owner(tmp_path)
    sources.fault = 'lost_ack'
    result = first.submit(request())
    assert result['state'] == 'hold' and result['reason'] == 'dispatch_outcome_unknown'
    directory = tmp_path / 'attempts' / request()['calcjob_uuid']
    failure = (directory / 'failure.json').read_bytes()
    assert json.loads(failure)['stderr'] == 'original'
    sources.fault = None
    for action in ('submit', 'reconcile', 'status'):
        fresh = m.OrdinaryAttemptOwner(first.policy, m.AttemptStore(tmp_path), sources, m.Operation(limits()))
        assert getattr(fresh, action)(request(action))['state'] == 'hold'
    assert len(sources.calls) == 1 and (directory / 'failure.json').read_bytes() == failure


def test_conflicting_launch_and_missing_qualification_do_not_claim_or_dispatch(tmp_path):
    first, sources = owner(tmp_path)
    sources.fault = 'policy'
    assert first.submit(request())['reason'] == 'native_qualification_missing'
    assert not (tmp_path / 'attempts').exists() and not sources.calls
    sources.fault = None
    assert first.submit(request())['state'] == 'bound'
    other = request(); other['launch']['transport_attempt'] = 2
    assert first.submit(other)['reason'] == 'launch_conflict'
    assert len(sources.calls) == 1


@pytest.mark.parametrize('mutate', [
    lambda r: r.update(untrusted_authority=True),
    lambda r: r['launch'].update(transport_attempt=True),
    lambda r: r['launch'].update(relative_execution_root='../escape'),
    lambda r: r['launch']['files']['plan'].update(bytes=True),
    lambda r: r.update(controls=[]),
])
def test_closed_request_shapes_before_effects(tmp_path, mutate):
    first, sources = owner(tmp_path)
    document = request(); mutate(document)
    assert first.submit(document)['state'] == 'rejected'
    assert not sources.calls and not (tmp_path / 'attempts').exists()


@pytest.mark.parametrize('raw', [b'42;cluster\n', b'42\n'])
def test_ack_strict_positive(raw):
    m = module(); output = m.engine.CommandOutput(raw.decode()); output.output_bytes = len(raw)
    assert m.parse_ack(output, 'cluster') == {'job_id': '42', 'cluster': 'cluster'}


@pytest.mark.parametrize('raw,extra', [(b'0\n', 0), (b'42;other\n', 0), (b'42\nnoise', 0),
                                       (b'42\n', 1), ('42é\n'.encode(), 0)])
def test_ack_stderr_ignored_octets_and_ambiguous_output_hold(raw, extra):
    m = module(); output = m.engine.CommandOutput(raw.decode()); output.output_bytes = len(raw) + extra
    with pytest.raises(m.Hold):
        m.parse_ack(output, 'cluster')


@pytest.mark.parametrize('raw', [b'{"a":1,"a":2}', b'{"a":NaN}', b'{}{}', b'\xff'])
def test_strict_frame_rejects_duplicate_nonfinite_trailing_or_non_utf8(raw):
    m = module(); connection = MemoryConnection(struct.pack('!I', len(raw)) + raw)
    with pytest.raises(m.Hold):
        m.read_frame(connection, m.Operation(limits()), 65536)


def test_frame_positive_extra_frame_and_bound():
    m = module()
    for payload, accepted in [(struct.pack('!I', 2) + b'{}', True),
                              (struct.pack('!I', 2) + b'{}x', False),
                              (struct.pack('!I', 65537), False)]:
        connection = MemoryConnection(payload)
        if accepted:
            assert m.read_frame(connection, m.Operation(limits()), 65536) == {}
        else:
            with pytest.raises(m.Hold):
                m.read_frame(connection, m.Operation(limits()), 65536)


class PeerSources:
    def __init__(self):
        self.count = 0; self.fault = None; self.changing_counters = True
        self.policy = dict(client_uid=3000,daemon_unit='qcl-negf-aiida.service')
        self.python = '/nix/store/' + 'a'*32 + '-python/bin/python3'
        self.app = '/nix/store/application'; self.profile = '/nix/var/nix/profiles/qcl-negf-application'
        self.qualification = {'unit_origins': {self.policy['daemon_unit']: {'executable':self.python}}}
        self.configuration = dict(profile='qcl-negf',aiida_path='/var/lib/qcl-negf/aiida',
            application_profile=self.profile,jobs_root='/srv/qcl-negf/jobs',client=dict(
                entrypoint='/nix/store/client/bin/qcl-negf-native-attempt-client',
                argv_prefix=[self.python,'-I','-c','fixed generated source'],bash_executable='/nix/store/bash/bin/bash'))

    def process(self, pid):
        self.count += 1
        parent = {456:345,345:234,234:123,123:1}[pid]
        return dict(pid=pid,ppid=parent,start_ticks={456:40,345:30,234:20,123:10}[pid] + (self.fault == 'reuse' and self.count > 4),
                    uids=[3000] * 4, cgroup=('/system.slice/qcl-negf-api.service' if self.fault == 'api'
                                          else '/system.slice/qcl-negf-aiida.service/worker'),
                    executable=self.python, state='S',comm='python3',
                    observations={'raw_counter':self.count if self.changing_counters else 0})

    def unit(self, name):
        return dict(InvocationID='a' * 32, ControlGroup='/system.slice/' + name,
                    MainPID='123', ActiveState='active')

    def application_origin(self, process):
        if self.fault == 'shell':
            raise module().Hold('application_origin')

    def actor_context(self):return {'app':self.app,'configuration':self.configuration}
    def origin(self,path):return path
    def profile_view(self,pid,context):return {'fixture_metadata_only':'not native authority'}
    def command_line(self,pid):
        tails={345:['worker'],234:['start-circus','1','--foreground'],123:['start','--foreground']}
        if pid==456:return self.configuration['client']['argv_prefix']+['submit']
        if self.fault=='shell':return ['/bin/sh','unrelated']
        return [self.python,self.app+'/bin/verdi','-p','qcl-negf','daemon',*tails[pid]]
    def selected_environment(self,pid):return {'AIIDA_PATH':self.configuration['aiida_path']+('' if pid==123 else '/.aiida'),
                                            'QCL_NEGF_NATIVE_JOBS_ROOT':self.configuration['jobs_root']}


@pytest.mark.parametrize('fault', [None, 'reuse', 'api', 'shell'])
def test_real_peer_observation_boundary_distinguishes_same_uid_and_pid_reuse(fault):
    m = module(); sources = PeerSources(); sources.fault = fault
    class Connection:
        def getsockopt(self, *args):
            return struct.pack('3i', 456, 3000, 3000)
    policy = dict(client_uid=3000, daemon_unit='qcl-negf-aiida.service')
    if fault:
        with pytest.raises(m.Hold):
            m.authenticate_socket_peer(Connection(), policy, sources,action='submit')
    else:
        assert m.authenticate_socket_peer(Connection(), policy, sources,action='submit')['pid'] == 456


@pytest.mark.parametrize('fault',['action','parent','birth','worker_argv','environment','mainpid','loop','dead'])
def test_actual_causal_chain_rejects_each_unjoined_peer(fault):
    m=module();sources=PeerSources();sources.changing_counters=False
    original_process=sources.process;original_command=sources.command_line;original_unit=sources.unit
    def process(pid):
        row=original_process(pid)
        if fault=='parent' and pid==345:row['ppid']=123
        if fault=='loop' and pid==345:row['ppid']=456
        if fault=='birth' and pid==123:row['start_ticks']=99
        if fault=='dead' and pid==345:row['state']='Z'
        return row
    sources.process=process
    sources.command_line=lambda pid: ['/bin/sh','manual'] if fault=='worker_argv' and pid==345 else original_command(pid)
    if fault=='environment':sources.selected_environment=lambda pid: {'AIIDA_PATH':'/other'}
    if fault=='mainpid':sources.unit=lambda name:{**original_unit(name),'MainPID':'456'}
    class Connection:
        def getsockopt(self,*args):return struct.pack('3i',456,3000,3000)
    with pytest.raises(m.Hold):
        m.authenticate_socket_peer(Connection(),sources.policy,sources,action='status' if fault=='action' else 'submit')


def stock_aiida_descendant_environment(base,jobs_root):
    """Execute only two pinned upstream AST functions, without importing AiiDA."""
    import ast
    import importlib.metadata
    import types
    distribution=importlib.metadata.distribution('aiida-core')
    assert distribution.version=='2.9.2'
    class NoProfilePath(type(Path())):
        def is_dir(self):return False
    environment=types.SimpleNamespace(environ={'AIIDA_PATH':base,'PATH':'/APP/bin:/empty',
        'QCL_NEGF_NATIVE_JOBS_ROOT':jobs_root},path=os.path)
    def isolated(relative,name,namespace):
        path=distribution.locate_file(relative)
        tree=ast.parse(path.read_text())
        node=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name==name)
        node.decorator_list=[]
        exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),str(path),'exec'),namespace)
        return namespace[name]()
    directory=isolated('aiida/manage/configuration/settings.py','_get_configuration_directory_from_envvar',
        {'os':environment,'pathlib':types.SimpleNamespace(Path=NoProfilePath),'sys':sys,
         'DEFAULT_AIIDA_PATH_VARIABLE':'AIIDA_PATH','DEFAULT_AIIDA_PATH':'/unused','DEFAULT_CONFIG_DIR_NAME':'.aiida'})
    child=isolated('aiida/engine/daemon/client.py','get_env',
        {'os':environment,'sys':sys,'get_config':lambda:types.SimpleNamespace(dirpath=str(directory))})
    assert str(directory)==base+'/.aiida' and child['AIIDA_PATH']==str(directory)
    return {key:child[key] for key in ('AIIDA_PATH','QCL_NEGF_NATIVE_JOBS_ROOT')}


@pytest.mark.parametrize('fault',[None,'main_derived','all_base','leaf_base','worker_base','circus_base','jobs',
    'changed','changed_main','changed_worker','changed_circus'])
def test_pinned_stock_aiida_role_environments_and_distinguishing_negatives(fault):
    m=module();sources=PeerSources();cfg=sources.configuration
    child=stock_aiida_descendant_environment(cfg['aiida_path'],cfg['jobs_root']);counts={}
    def environment(pid):
        counts[pid]=counts.get(pid,0)+1
        value={**child,'AIIDA_PATH':cfg['aiida_path']} if pid==123 else dict(child)
        if fault=='main_derived' and pid==123:value=dict(child)
        if fault=='all_base' or pid=={'leaf_base':456,'worker_base':345,'circus_base':234}.get(fault):
            value['AIIDA_PATH']=cfg['aiida_path']
        if fault=='jobs' and pid==345:value['QCL_NEGF_NATIVE_JOBS_ROOT']='/other'
        if pid=={'changed':456,'changed_main':123,'changed_worker':345,'changed_circus':234}.get(fault) and counts[pid]>1:
            value['AIIDA_PATH']='/changed/.aiida'
        return value
    sources.selected_environment=environment
    class Connection:
        def getsockopt(self,*args):return struct.pack('3i',456,3000,3000)
    if fault:
        with pytest.raises(m.Hold):m.authenticate_socket_peer(Connection(),sources.policy,sources,action='submit')
    else:
        packet=m.authenticate_socket_peer(Connection(),sources.policy,sources,action='submit')
        assert [entry['environment']['AIIDA_PATH'] for entry in packet['chain']]==[child['AIIDA_PATH']]*3+[cfg['aiida_path']]


def test_native_fixed_dispatch_uses_snapshot_and_shared_command_budget(monkeypatch):
    m = module(); calls = []
    policy = dict(client_uid=3000, tools={'runuser': '/nix/store/runuser', 'sbatch': '/nix/store/sbatch'},
                  slurm={'config_file': '/etc/slurm.conf'}, limits=limits())
    sources = m.NativeSources(policy, m.Operation(limits()))
    def run(argv, **kw):
        calls.append((argv, kw)); result = m.engine.CommandOutput('42\n'); result.output_bytes = 3
        return result
    monkeypatch.setattr(m.engine, 'command', run)
    monkeypatch.setattr(m, 'trusted_root_path', lambda path, **kw: Path(path))
    snapshot = {'script_path': '/var/lib/qcl-negf-native-spool/original.sh', 'script_sha256': 'a' * 64}
    monkeypatch.setattr(sources, '_check_snapshot', lambda snapshot: None)
    result = sources.dispatch(request()['launch'], snapshot, request()['calcjob_uuid'], sources.budget)
    argv, kw = calls[0]
    assert argv == ['/nix/store/runuser', '-u', 'qcl-negf', '--', '/nix/store/sbatch', '--parsable',
                    '--no-requeue', '--chdir', request()['launch']['remote_workdir'], '--comment',
                    request()['calcjob_uuid'], snapshot['script_path']]
    assert kw['deadline'] == sources.budget.deadline and kw['env']['SLURM_CONF'] == '/etc/slurm.conf'
    assert m.parse_ack(result, 'cluster')['job_id'] == '42' and sources.budget.calls == 1


def test_owner_file_reader_reads_original_bytes_and_rejects_aliases(tmp_path):
    m = module(); launch = request()['launch']; work = tmp_path / 'upload'; work.mkdir()
    launch['remote_workdir'] = str(work)
    for name in m.FILES.values():
        (work / name).write_bytes(b'abc')
    (work/'plan.json').write_bytes(b'{}');launch['files']['plan']=dict(bytes=2,sha256=hashlib.sha256(b'{}').hexdigest())
    policy = dict(jobs_root=str(tmp_path), client_uid=os.getuid(), limits=limits())
    assert m._owner_read(policy, launch, m.Operation(limits()))['script'] == base64_script(b'abc')
    (work / 'plan.json').unlink(); (work / 'plan.json').symlink_to('source-graph.json')
    with pytest.raises((m.Hold, OSError)):
        m._owner_read(policy, launch, m.Operation(limits()))


def base64_script(raw):
    import base64
    return base64.b64encode(raw).decode()


def test_opt_in_package_and_module_source_envelopes():
    root = Path(__file__).resolve().parents[1]
    paths = ['nix/native-attempt.nix', 'tests/infrastructure/native-attempt.nix']
    for name in paths:
        assert (root / name).is_file(), name
    app = (root / 'modules/application.nix').read_text()
    cluster = (root / 'modules/cluster.nix').read_text()
    assert 'nativeAttempts' in app and 'NoNewPrivileges = true;' in app
    assert 'qcl-negf-native-attempt@' in app and 'Accept = true' in app
    assert 'nativeAttempts' in cluster and 'Prolog=' in cluster and 'Epilog=' in cluster


def test_distinct_calcjob_cannot_claim_overlapping_canonical_output_domain(tmp_path):
    first, sources = owner(tmp_path)
    assert first.submit(request())['state'] == 'bound'
    second = request(); second['calcjob_uuid'] = '99999999-9999-4999-8999-999999999999'
    second['launch']['relative_execution_root'] += '/child'
    assert first.submit(second)['reason'] == 'output_domain_claimed'
    assert len(sources.calls) == 1


def test_missing_policy_after_bound_preserves_original_trustworthy_job(tmp_path):
    first, sources = owner(tmp_path)
    original = first.submit(request())['job']; sources.fault = 'policy'
    result = first.status(request('status'))
    assert result['state'] == 'hold' and result['job'] == original


def test_partial_dispatch_record_never_becomes_an_authorization_to_repeat(tmp_path, monkeypatch):
    first, sources = owner(tmp_path); original = first.store.put
    def fault(calcjob, name, value, budget):
        if name == 'dispatch.json':
            (first.store.path(calcjob) / name).write_bytes(b'{partial')
            raise OSError('original fsync ambiguity')
        return original(calcjob, name, value, budget)
    monkeypatch.setattr(first.store, 'put', fault)
    assert first.submit(request())['state'] == 'hold'
    original_bytes = (first.store.path(request()['calcjob_uuid']) / 'dispatch.json').read_bytes()
    monkeypatch.setattr(first.store, 'put', original)
    assert first.submit(request())['state'] == 'hold' and not sources.calls
    assert (first.store.path(request()['calcjob_uuid']) / 'dispatch.json').read_bytes() == original_bytes


def test_original_ack_survives_failed_job_lookup_and_reconciles_same_key(tmp_path):
    first, sources = owner(tmp_path); original = sources.bind_job
    def missing(*args):
        raise module().Hold('native_job_changed')
    sources.bind_job = missing
    assert first.submit(request())['reason'] == 'native_job_changed'
    sources.bind_job = original
    assert first.reconcile(request('reconcile'))['state'] == 'bound' and len(sources.calls) == 1


@pytest.mark.parametrize('fault', ['extra_bytes', 'lost_ack'])
def test_unknown_dispatch_does_not_hide_original_marker(tmp_path, fault):
    first, sources = owner(tmp_path); sources.fault = fault
    assert first.submit(request())['state'] == 'hold'
    assert first.store.read(request()['calcjob_uuid'], 'dispatch.json', module().Operation(limits()))
    assert len(sources.calls) == 1


def writer_fixture():
    known = [dict(job_id='42', generation='b' * 64, dispatch_id='a', domain='native/run-1/execution-1', submit_time='today'),
             dict(job_id='43', generation='c' * 64, dispatch_id='b', domain='native/run-2/execution-1', submit_time='today')]
    inventory = dict(schema='qcl.host-resource-guest-facts.v1', identity_before={'boot_id': 'same'},
                     identity_after={'boot_id': 'same'}, slurm_registered=True,
                     jobs={'42': dict(owner_uid=3000, submit_time='today', terminal=True),
                           '43': dict(owner_uid=3000, submit_time='today', terminal=False)},
                     groups={'42': dict(populated=False, processes=[]), '43': dict(populated=True, processes=[1])})
    return known, inventory


@pytest.mark.parametrize('change', [None, 'overlap', 'unknown', 'populated', 'boot', 'submit', 'unregistered'])
def test_whole_writer_closure_finite_managed_domains(change):
    m = module(); known, inventory = writer_fixture()
    if change == 'overlap': known[1]['domain'] = known[0]['domain'] + '/child'
    if change == 'unknown': known.pop()
    if change == 'populated': inventory['groups']['42']['populated'] = True
    if change == 'boot': inventory['identity_after']['boot_id'] = 'new'
    if change == 'submit': inventory['jobs']['43']['submit_time'] = 'different'
    if change == 'unregistered': inventory['slurm_registered'] = False
    if change:
        with pytest.raises(m.Hold):
            m.enforce_writer_closure('native/run-1/execution-1', [inventory], known, 'b' * 64)
    else:
        m.enforce_writer_closure('native/run-1/execution-1', [inventory], known, 'b' * 64)


@pytest.mark.parametrize('kind', ['live', 'fast', 'unknown_root', 'same_pid', 'empty', 'completing'])
def test_worker_collector_reuses_original_before_and_whole_stop_oracles(tmp_path, monkeypatch, kind):
    m = module()
    from test_slurm_job_evidence import EXPECTED, sample
    identity = {'schema': 'qcl.host-resource-guest-identity.v1', 'identity': EXPECTED['identity']}
    document = dict(version=1, calcjob_uuid=request()['calcjob_uuid'], dispatch_id=request()['launch']['request_id'],
                    job_id='7', generation='b' * 64, phase='start')
    policy = dict(private_root=str(tmp_path), tools={'slurmstepd': EXPECTED['slurmstepd_executable'], 'scontrol': '/fixed/scontrol'},
                  slurm={'cgroup_scope': EXPECTED['cgroup_scope']}, limits=limits())
    sources = m.NativeSources(policy, m.Operation(limits())); samples = sample()['processes']
    def process(pid):
        old = copy.deepcopy(next(p for p in samples if p['pid'] == pid))
        if document['phase'] == 'close' and kind != 'same_pid':
            raise FileNotFoundError('original process absent')
        if kind == 'unknown_root': old['uids'] = [0] * 4
        return {**old, 'executable': old['exe']}
    monkeypatch.setattr(sources, 'process', process)
    monkeypatch.setattr(sources, 'host', lambda: EXPECTED['identity'])
    monkeypatch.setattr(sources, 'run', lambda argv: 'PID JOBID STEPID\n' + ('' if kind == 'fast' else '101 7 batch\n102 7 batch\n'))
    monkeypatch.setattr(sources.budget, 'read', lambda path, limit: (_ for _ in ()).throw(FileNotFoundError()))
    monkeypatch.setattr(m.Path, 'exists', lambda path: False if str(path).startswith(('/proc/', '/sys/fs/cgroup')) else original_exists(path))
    if kind in {'fast', 'unknown_root'}:
        with pytest.raises(m.Hold, match='native_start_not_observed'):
            m._worker_capture(sources, document, identity, {'fields': {} })
    else:
        before, after = m._worker_capture(sources, document, identity, {'fields': {}})
        assert before['status'] == 'pass_live_job_membership' and after is None
        document['phase'] = 'close'
        state = 'COMPLETING' if kind == 'completing' else 'COMPLETED'
        if kind in {'same_pid', 'completing'}:
            with pytest.raises(m.Hold, match='native_stop_not_observed'):
                m._worker_capture(sources, document, identity, {'fields': {'JobState': state}})
        else:
            _, after = m._worker_capture(sources, document, identity, {'fields': {'JobState': state}})
            assert after['status'] == 'pass_physical_job_stop' and after['scientific_accepted'] is False


original_exists = Path.exists


def test_actor_preflight_receives_actual_calcjob_and_action_before_claim(tmp_path):
    m = module()
    class ActualRequest(Observations):
        def preflight(self, launch, budget, *, calcjob_uuid=None, action=None):
            self.observed = (calcjob_uuid, action)
            return super().preflight(launch, budget)
    sources = ActualRequest(m); selected, _ = owner(tmp_path, sources)
    assert selected.submit(request())['state'] == 'bound'
    assert sources.observed == (request()['calcjob_uuid'], 'submit')


def bridge_inputs():
    """Public actor output fixture, stock scheduler bytes; no ORM/profile load."""
    from aiida.schedulers.plugins.slurm import SlurmScheduler
    from aiida.schedulers.datastructures import JobTemplate, JobTemplateCodeInfo
    from aiida.common.datastructures import CodeRunMode
    from test_application_release import RetainedReleaseSourcesTests, delivery_manifest
    m = module(); document = request(); launch = document['launch']
    graph = RetainedReleaseSourcesTests.RAW
    value = {**delivery_manifest(False), 'sources': json.loads(graph), 'solver_build': {
        'source_graph_sha256': hashlib.sha256(graph).hexdigest(), 'julia_manifest_sha256': 'd'*64,
        'drv_path': '/nix/store/solver.drv', 'output_path': '/nix/store/solver'}}
    launch['release_id'] = value['release_id']; plan = b' \n{"original":"frozen-plan"}\n'
    def ref(node, raw): return dict(node_uuid=node, bytes=str(len(raw)), sha256=hashlib.sha256(raw).hexdigest())
    native = dict(schema='qcl-negf.aiida-native-execution.v1', request_id=launch['request_id'],
        execution_id=launch['execution_id'], input_plan=ref(launch['input_plan_uuid'], plan),
        source_graph=ref(launch['source_graph_uuid'], graph), access_receipt_ref='untrusted-locator',
        code=dict(code_uuid=launch['code_uuid'], computer_uuid=document['calcjob_uuid'],
            solver_executable=value['solver_executable'], release_id=value['release_id'], build_receipt_ref='locator'),
        storage=dict(namespace_id='managed', storage_identity='storage',
            relative_execution_root=launch['relative_execution_root'], computer_uuid=document['calcjob_uuid'],
            execution_binding_uuid=launch['native_execution_uuid'], retention_policy_id='retain',
            retention_owner_id='team', hold_ref='locator', access_binding_ref='locator'))
    raw_native = b' \n' + m.encoded(native) + b'\n'
    scheduler = SlurmScheduler(); template = JobTemplate()
    template.shebang = '#!/nix/store/bash/bin/bash'; template.rerunnable = False
    template.job_name = 'aiida-1'; template.import_sys_environment = True
    template.sched_output_path = '_scheduler-stdout.txt'; template.sched_error_path = '_scheduler-stderr.txt'
    template.job_resource = scheduler.create_job_resource(num_machines=1, num_mpiprocs_per_machine=1, num_cores_per_mpiproc=2)
    template.job_environment = {'JULIA_NUM_THREADS':'2', 'OPENBLAS_NUM_THREADS':'1'}
    template.prepend_text = ('/run/current-system/sw/bin/qcl-negf-release guard --release-id release-a '
                            '--solver-executable /nix/store/solver/bin/qcl-negf || exit 78\nunset QCL_NEGF_CAPTURE_SPEC')
    code = JobTemplateCodeInfo(); code.prepend_cmdline_params = [value['solver_executable']]
    code.cmdline_params = ['run-plan', 'plan.json', '/srv/qcl-negf/jobs/'+launch['relative_execution_root'],
                          '--execution-id', launch['execution_id'], '--source-graph', 'source-graph.json']
    code.use_double_quotes = [False,False]; code.stdout_name = 'solver.stdout'; code.stderr_name = 'solver.stderr'
    template.codes_info = [code]; template.codes_run_mode = CodeRunMode.SERIAL
    script = scheduler.get_submit_script(template).encode()
    files = dict(plan=plan, source_graph=graph, native_execution=raw_native, submit_script=script)
    launch['files'] = {key:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()) for key,raw in files.items()}
    return document, value, files, native


@pytest.fixture
def actor_bridge(monkeypatch):
    m = module(); document, value, files, native = bridge_inputs(); launch = document['launch']
    policy = dict(jobs_root='/srv/qcl-negf/jobs',native_result_prefix='native',release_runtime='/protected/runtime',
        client_uid=3000, tools=dict(runuser='/nix/store/runuser'), limits={**limits(), 'metadata_bytes':8*1024*1024})
    sources = m.NativeSources(policy,m.Operation(policy['limits']))
    host = dict(machine_id='a'*32,boot_id=launch['request_id'],image_id='/nix/store/image')
    sources.qualification = dict(write_domain={'storage_identity':'storage'})
    monkeypatch.setattr(sources,'qualify',lambda:host)
    context = dict(app=value['application_path'],configuration=PeerSources().configuration)
    monkeypatch.setattr(sources,'_refresh_caller',lambda action: {'application':context},raising=False)
    def read(path,*args):
        path = str(path)
        if path.endswith('source-graph-'+hashlib.sha256(files['source_graph']).hexdigest()+'.json'):return files['source_graph']
        if '/records/release-' in path:return m.encoded({**value,'code_uuid':launch['code_uuid'],
            'quantum_runtime_context':m.engine.quantum_context(value)})
        if path.endswith('/release.json'):return m.encoded({**value,'ready':True,'code_uuid':launch['code_uuid']})
        raise AssertionError(path)
    monkeypatch.setattr(m,'protected_read',read)
    monkeypatch.setattr(m,'_read_submitted_files_as_owner',lambda *args:dict(files=launch['files'],script=base64_script(files['submit_script'])))
    monkeypatch.setattr(m.engine,'public_binary_origin',lambda budget,path,**kw: {'path':path})
    monkeypatch.setattr(m.engine,'admission_reader',lambda path: __import__('contextlib').nullcontext())
    monkeypatch.setattr(sources.budget,'read',lambda path,limit=65536:m.encoded(dict(open=True,release_id=value['release_id'])))
    calls=[]; actor_launch=copy.deepcopy(launch)
    state=dict(m=m,document=document,value=value,files=files,native=native,sources=sources,host=host,
               actor_launch=actor_launch,context=context,calls=calls,gate=True,ready=True,fault=None)
    def run(argv,**kw):
        calls.append((argv,kw))
        if state['fault']=='query':raise m.engine.CommandFailure(dict(failure='timeout',cleanup_confirmed=False,
            stdout='original actor prefix',stderr='original query failure',child_started=True))
        raw=m.encoded(actor_launch) if 'launch' in argv else files['native_execution']
        output=m.engine.CommandOutput(raw.decode());output.output_bytes=len(raw)+(1 if state['fault']=='partial' else 0)
        return output
    monkeypatch.setattr(m.engine,'command',run)
    def read_current(path,*args):
        if str(path).endswith('/release.json'):return m.encoded({**value,'ready':state['ready'],'code_uuid':launch['code_uuid']})
        return read(path,*args)
    monkeypatch.setattr(m,'protected_read',read_current)
    monkeypatch.setattr(sources.budget,'read',lambda path,limit=65536:m.encoded(dict(open=state['gate'],release_id=value['release_id'])))
    state['run']=run
    return state


def test_original_actor_launch_raw_bytes_and_stock_script_join_preflight(actor_bridge):
    state=actor_bridge;sources=state['sources'];document=state['document'];launch=document['launch'];calls=state['calls']
    assert sources.preflight(launch,sources.budget,calcjob_uuid=document['calcjob_uuid'],action='submit')==state['host']
    assert [row[0][-4] for row in calls]==['launch','execution']
    assert all(row[1]['deadline']==sources.budget.deadline for row in calls)


@pytest.mark.parametrize('fault',['launch','partial','raw','fullref','code','storage','legacy_attempt','extra_shell',
    'directive','duplicate_header','scratch','output','thread','unquoted','gate','ready','budget','query'])
def test_actor_script_reference_and_budget_negatives_precede_claim(actor_bridge,tmp_path,fault):
    state=actor_bridge;m=state['m'];document=state['document'];launch=document['launch'];files=state['files'];sources=state['sources']
    if fault=='launch':state['actor_launch']['transport_attempt']+=1
    if fault in {'partial','query'}:state['fault']=fault
    if fault=='raw':files['native_execution']+=b' '
    if fault in {'fullref','code','storage'}:
        native=state['native']
        if fault=='fullref':native['input_plan']['node_uuid']=document['calcjob_uuid']
        if fault=='code':native['code']['solver_executable']='/nix/store/foreign/bin/qcl-negf'
        if fault=='storage':native['storage']['storage_identity']='foreign'
        files['native_execution']=m.encoded(native)
    if fault in {'legacy_attempt','extra_shell','directive','duplicate_header','scratch','output','thread','unquoted'}:
        script=files['submit_script']
        if fault=='legacy_attempt':script=script.replace(b"  >",b" '--attempt' '1'  >")
        if fault=='extra_shell':script+=b'\necho unsafe\n'
        if fault=='directive':script=script.replace(b'#SBATCH --no-requeue',b'#SBATCH --wrap=unsafe')
        if fault=='duplicate_header':script=script.replace(b'#SBATCH --nodes=1',b'#SBATCH --nodes=1\n#SBATCH --nodes=1')
        if fault=='scratch':script=script.replace(b"  >",b" '--scratch-root' '/free/path'  >")
        if fault=='output':script=script.replace(b'/srv/qcl-negf/jobs/native/',b'/outside/native/')
        if fault=='thread':script=script.replace(b"JULIA_NUM_THREADS='2'",b"JULIA_NUM_THREADS='3'")
        if fault=='unquoted':script=script.replace(b"'run-plan'",b'run-plan')
        files['submit_script']=script
    if fault in {'fullref','code','storage','legacy_attempt','extra_shell','directive','duplicate_header','scratch','output','thread','unquoted'}:
        launch['files']={key:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()) for key,raw in files.items()}
        state['actor_launch'].update(copy.deepcopy(launch))
    if fault=='gate':state['gate']=False
    if fault=='ready':state['ready']=False
    if fault=='budget':sources.budget.bytes=sources.budget.limits['metadata_bytes']
    selected=m.OrdinaryAttemptOwner(sources.policy,m.AttemptStore(tmp_path),sources,sources.budget)
    result=selected.submit(document)
    assert result['state']=='hold' and not (tmp_path/'attempts').exists()
    assert not any('--parsable' in row[0] for row in state['calls'])


# Exact synthetic presubmit bytes frozen by the AiiDA owner on 2026-10-30.
# This exercises its actual literal output without importing mutable producer source.
NATIVE_ORIGIN_SCRIPT = b"""#!/bin/bash
#SBATCH --no-requeue
#SBATCH --job-name="aiida-16"
#SBATCH --get-user-env
#SBATCH --output=_scheduler-stdout.txt
#SBATCH --error=_scheduler-stderr.txt
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=1
#SBATCH --time=01:00:00

# ENVIRONMENT VARIABLES BEGIN ###
export JULIA_NUM_THREADS='1'
export OPENBLAS_NUM_THREADS='1'
# ENVIRONMENT VARIABLES END ###

/run/current-system/sw/bin/qcl-negf-release guard --release-id fixture-release --solver-executable /nix/store/synthetic/bin/qcl-negf || exit 78
unset QCL_NEGF_CAPTURE_SPEC

'/nix/store/synthetic/bin/qcl-negf' 'run-plan' 'plan.json' '/srv/qcl-negf/jobs/native/new-domain' '--execution-id' 'execution' '--source-graph' 'source-graph.json' '--native-execution' 'native-execution.json' '--native-calcjob-uuid' 'e3fd840b-a169-4061-ab35-0b68bd97215f'  > 'solver.stdout' 2> 'solver.stderr'
"""
NATIVE_ORIGIN_CALCJOB = 'e3fd840b-a169-4061-ab35-0b68bd97215f'


def test_native_origin_actual_frozen_presubmit_literal_and_legacy_unmapped(monkeypatch):
    m = module(); sources = m.NativeSources({'jobs_root':'/srv/qcl-negf/jobs'},m.Operation(limits()))
    monkeypatch.setattr(sources,'origin',lambda path:path)
    assert hashlib.sha256(NATIVE_ORIGIN_SCRIPT).hexdigest() == '4f15f14ac98ff6a5a7c38d2bc096ec4ee8165fa28052d12f372ac0eee8d05c6b'
    launch = request()['launch']
    launch.update(release_id='fixture-release',execution_id='execution',relative_execution_root='native/new-domain')
    assert m._review_native_script(NATIVE_ORIGIN_SCRIPT,launch,'/nix/store/synthetic/bin/qcl-negf',
        '/bin/bash',sources,calcjob_uuid=NATIVE_ORIGIN_CALCJOB) is None
    # The old seven-argument class remains accepted without an origin assertion.
    suffix = (" '--native-execution' 'native-execution.json' '--native-calcjob-uuid' '"+
              NATIVE_ORIGIN_CALCJOB+"'").encode()
    legacy = NATIVE_ORIGIN_SCRIPT.replace(suffix,b'')
    assert legacy != NATIVE_ORIGIN_SCRIPT
    assert m._review_native_script(legacy,launch,'/nix/store/synthetic/bin/qcl-negf',
        '/bin/bash',sources,calcjob_uuid=request()['calcjob_uuid']) is None
    assert not hasattr(sources,'_actor')


@pytest.mark.parametrize('calcjob',[
    NATIVE_ORIGIN_CALCJOB.upper(), NATIVE_ORIGIN_CALCJOB.replace('-',''),
    NATIVE_ORIGIN_CALCJOB+'\n', '00000000-0000-0000-0000-000000000000', None])
def test_native_origin_script_requires_canonical_authenticated_uuid(monkeypatch,calcjob):
    m = module(); sources = m.NativeSources({'jobs_root':'/srv/qcl-negf/jobs'},m.Operation(limits()))
    monkeypatch.setattr(sources,'origin',lambda path:path)
    launch = request()['launch']
    launch.update(release_id='fixture-release',execution_id='execution',relative_execution_root='native/new-domain')
    script = NATIVE_ORIGIN_SCRIPT.replace(NATIVE_ORIGIN_CALCJOB.encode(),str(calcjob).encode())
    with pytest.raises(m.Hold):
        m._review_native_script(script,launch,'/nix/store/synthetic/bin/qcl-negf',
            '/bin/bash',sources,calcjob_uuid=calcjob)


def native_origin_bridge_script(state):
    suffix = (" '--native-execution' 'native-execution.json' '--native-calcjob-uuid' '"+
              state['document']['calcjob_uuid']+"'  >").encode()
    return state['files']['submit_script'].replace(b'  >',suffix)


def replace_bridge_script(state,script):
    state['files']['submit_script'] = script
    claim = dict(bytes=len(script),sha256=hashlib.sha256(script).hexdigest())
    state['document']['launch']['files']['submit_script'] = claim
    state['actor_launch']['files']['submit_script'] = copy.deepcopy(claim)


@pytest.mark.parametrize('native_origin',[False,True])
def test_native_origin_preflight_passes_actual_request_uuid(actor_bridge,monkeypatch,native_origin):
    state=actor_bridge;m=state['m'];sources=state['sources'];document=state['document']
    if native_origin: replace_bridge_script(state,native_origin_bridge_script(state))
    original = m._review_native_script; observed=[]
    def review(*args,**kwargs):
        observed.append(kwargs.copy())
        return original(*args,**kwargs)
    monkeypatch.setattr(m,'_review_native_script',review)
    assert sources.preflight(document['launch'],sources.budget,
        calcjob_uuid=document['calcjob_uuid'],action='submit')==state['host']
    assert observed==[{'calcjob_uuid':document['calcjob_uuid'],'engineering_fixture':None}]
    assert all(document['calcjob_uuid'] in row[0] for row in state['calls'])
    assert not any(document['launch'][key]==document['calcjob_uuid'] for key in
        ('request_id','native_execution_uuid','input_plan_uuid','source_graph_uuid','code_uuid'))


@pytest.mark.parametrize('fault',[
    'request_uuid','native_uuid','plan_uuid','missing_native','missing_calcjob','missing_value',
    'native_alias','native_absolute','extra','duplicate','reordered','unquoted','doublequoted',
    'substitution','extra_shell','environment','capture','scratch'])
def test_native_origin_script_controls_hold_before_claim(actor_bridge,tmp_path,fault):
    state=actor_bridge;m=state['m'];document=state['document'];launch=document['launch'];sources=state['sources']
    script=native_origin_bridge_script(state)
    native=b" '--native-execution' 'native-execution.json'"
    calcjob=(" '--native-calcjob-uuid' '"+document['calcjob_uuid']+"'").encode()
    if fault in {'request_uuid','native_uuid','plan_uuid'}:
        key={'request_uuid':'request_id','native_uuid':'native_execution_uuid','plan_uuid':'input_plan_uuid'}[fault]
        script=script.replace(calcjob,(" '--native-calcjob-uuid' '"+launch[key]+"'").encode())
    if fault=='missing_native':script=script.replace(native,b'')
    if fault=='missing_calcjob':script=script.replace(calcjob,b'')
    if fault=='missing_value':script=script.replace(calcjob,b" '--native-calcjob-uuid'")
    if fault=='native_alias':script=script.replace(b"'native-execution.json'",b"'./native-execution.json'")
    if fault=='native_absolute':script=script.replace(b"'native-execution.json'",b"'/srv/qcl-negf/jobs/upload/one/native-execution.json'")
    if fault=='extra':script=script.replace(b'  >',b" '--attempt' '1'  >")
    if fault=='duplicate':script=script.replace(calcjob,calcjob+calcjob)
    if fault=='reordered':script=script.replace(native+calcjob,calcjob+native)
    if fault=='unquoted':script=script.replace(b"'--native-execution'",b'--native-execution')
    if fault=='doublequoted':script=script.replace(b"'native-execution.json'",b'"native-execution.json"')
    if fault=='substitution':script=script.replace(b"'native-execution.json'",b'"$(echo native-execution.json)"')
    if fault=='extra_shell':script+=b'\necho unsafe\n'
    if fault=='environment':script=script.replace(b"'run-plan'",b"QCL_ORIGIN=1 'run-plan'")
    if fault=='capture':script=script.replace(b'unset QCL_NEGF_CAPTURE_SPEC',b"export QCL_NEGF_CAPTURE_SPEC='capture.json'")
    if fault=='scratch':script=script.replace(b'  >',b" '--scratch-root' '/free/path'  >")
    replace_bridge_script(state,script)
    selected=m.OrdinaryAttemptOwner(sources.policy,m.AttemptStore(tmp_path),sources,sources.budget)
    result=selected.submit(document)
    assert result['state']=='hold' and not (tmp_path/'attempts').exists()
    assert result['reason']==('native_scratch_binding_unavailable' if fault=='scratch' else
                             'native_script' if fault=='extra_shell' else
                             'native_script_guard' if fault=='capture' else 'native_script_argv')
    assert not any('--parsable' in row[0] for row in state['calls'])


@pytest.mark.parametrize('action',['reconcile','status','start','close'])
def test_operational_original_input_reads_remain_possible_with_admission_closed(actor_bridge,action):
    state=actor_bridge;state['gate']=state['ready']=False;sources=state['sources']
    assert sources.preflight(state['document']['launch'],sources.budget,
        calcjob_uuid=state['document']['calcjob_uuid'],action=action)==state['host']


def test_actor_query_failure_keeps_bounded_original_before_claim(actor_bridge,tmp_path,capsys):
    state=actor_bridge;m=state['m'];state['fault']='query';sources=state['sources']
    selected=m.OrdinaryAttemptOwner(sources.policy,m.AttemptStore(tmp_path),sources,sources.budget)
    assert selected.submit(state['document'])['state']=='hold'
    diagnostic=json.loads(capsys.readouterr().err.split('native-attempt preclaim HOLD: ',1)[1])
    import base64
    original=json.loads(base64.b64decode(diagnostic['original_prefix_base64']))
    assert original['stdout']=='original actor prefix' and original['cleanup_confirmed'] is False
    assert not (tmp_path/'attempts').exists()


@pytest.mark.parametrize('large',[False,True])
def test_actual_ingress_environment_command_failure_keeps_bounded_original(monkeypatch,capsys,large):
    import base64
    m=module();budget=m._bootstrap_operation();captured=[];commands=[]
    policy={'client_uid':3000,'daemon_unit':'qcl-negf-aiida.service',
        'tools':{'systemctl':'/nix/store/systemctl'},'limits':budget.limits}
    source=m.NativeSources(policy,budget);source._server_unit='qcl-negf-native-attempt@one.service'
    monkeypatch.setattr(source,'qualify',lambda:None)
    original={'failure':'timeout','returncode':None,'stdout':'unique-original-P3-prefix'+('x'*40000 if large else ''),
        'stderr':'original fixture diagnostic','cleanup_confirmed':False}
    primary=m.engine.CommandFailure(original)
    def failed(argv):
        commands.append(argv)
        assert argv==['/nix/store/systemctl','show',source._server_unit,'--property=Environment','--value']
        raise primary
    monkeypatch.setattr(source,'run',failed)
    monkeypatch.setattr(m,'_bootstrap_operation',lambda:budget)
    monkeypatch.setattr(m,'_load_policy',lambda *args:policy)
    monkeypatch.setattr(m,'_authenticate_server',lambda sources:None)
    monkeypatch.setattr(m,'NativeSources',lambda policy,budget:source)
    monkeypatch.setattr(m,'read_frame',lambda *args:request())
    monkeypatch.setattr(m,'write_frame',lambda connection,result,*args:captured.append(result))
    def no_owner(*args):raise AssertionError('preowner failure must not construct an AttemptStore')
    monkeypatch.setattr(m,'AttemptStore',no_owner)
    monkeypatch.setenv('QCL_NEGF_NATIVE_ACTOR_CONFIG','/nix/store/config/actor.json')
    class Connection:
        def getsockopt(self,*args):return struct.pack('3i',456,3000,3000)
    m.handle_connection(Connection())
    assert len(commands)==1 and captured==[m.reply({},'hold',reason='native_observation_failed')]
    assert 'unique-original-P3-prefix' not in json.dumps(captured)
    stderr=capsys.readouterr().err
    retained=json.loads(stderr.split('native-attempt preclaim HOLD: ',1)[1])
    raw=m.encoded(original)
    assert base64.b64decode(retained['original_prefix_base64'])==raw[:24576]
    assert retained=={'original_prefix_base64':base64.b64encode(raw[:24576]).decode('ascii'),
        'original_bytes':len(raw),'original_sha256':hashlib.sha256(raw).hexdigest(),'truncated':len(raw)>24576}
    assert primary.record is original and original['cleanup_confirmed'] is False and len(stderr)<34000


@pytest.mark.parametrize('secondary',[OSError('stderr unavailable'),KeyboardInterrupt('secondary write')])
def test_preclaim_diagnostic_write_failure_cannot_replace_primary_hold(monkeypatch,secondary):
    m=module();budget=m._bootstrap_operation();captured=[];calls=[]
    primary=m.engine.CommandFailure({'failure':'timeout','stdout':'original','cleanup_confirmed':False})
    def failed(*args,**kwargs):calls.append('original');raise primary
    monkeypatch.setattr(m,'_bootstrap_operation',lambda:budget)
    monkeypatch.setattr(m,'_load_policy',failed)
    monkeypatch.setattr(m,'write_frame',lambda connection,result,*args:captured.append(result))
    class BrokenStderr:
        def write(self,*args):raise secondary
        def flush(self):pass
    monkeypatch.setattr(m.sys,'stderr',BrokenStderr())
    m.handle_connection(object())
    assert calls==['original'] and captured==[m.reply({},'hold',reason='native_observation_failed')]
    assert primary.record=={'failure':'timeout','stdout':'original','cleanup_confirmed':False}


@pytest.mark.parametrize('scenario',['bound','lost_ack','withdraw_before_intent'])
def test_joined_native_owner_caller_actor_script_and_same_key_reentry(actor_bridge,tmp_path,monkeypatch,scenario):
    """Production owner/preflight/auth/intent/dispatch/join; OS/CLI facts are fixtures."""
    state=actor_bridge;m=state['m'];policy=state['sources'].policy
    policy.update(spool_root='/local/spool',daemon_unit='qcl-negf-aiida.service',server_unit_prefix='qcl-negf-native-attempt@',
                  slurm=dict(cluster='cluster',config_file='/etc/slurm.conf'))
    policy['tools'].update(sbatch='/nix/store/sbatch',scontrol='/nix/store/scontrol')
    dispatches=[];state['lost']=scenario=='lost_ack'
    root_executable='/nix/store/root-python';server_unit='qcl-negf-native-attempt@fixture.service'
    peers=PeerSources();current={'peer':456,'action':'submit'}
    qualification={'write_domain':{'storage_identity':'storage'},'unit_origins':{
        'server':{'executable':root_executable},policy['daemon_unit']:{'executable':peers.python}}}
    original_command=m.engine.command
    def command(argv,**kw):
        if '--parsable' in argv:
            dispatch=argv[argv.index('--comment')+1];dispatches.append((dispatch,argv[-1]))
            if state['lost']:raise m.engine.CommandFailure(dict(failure='timeout',cleanup_confirmed=False,
                child_started=True,stdout='lost original ACK',stderr=''))
            text='42;cluster\n'
        elif policy['tools']['scontrol'] in argv:
            dispatch,path=dispatches[0]
            text=('JobId=42 UserId=qcl-negf(3000) SubmitTime=2026-10-30T01:00:00 WorkDir='+state['document']['launch']['remote_workdir']+
                  ' Comment='+dispatch+' Command='+path+' Restarts=0 NumNodes=1 NumTasks=1')
        else:return original_command(argv,**kw)
        result=m.engine.CommandOutput(text);result.output_bytes=len(text);return result
    monkeypatch.setattr(m.engine,'command',command)
    monkeypatch.setattr(m,'trusted_root_path',lambda path,**kw:Path(path))
    class Connection:
        def getsockopt(self,*args):return struct.pack('3i',current['peer'],3000,3000)
    def fresh(action,pid):
        current.update(action=action,peer=pid)
        source=m.NativeSources(policy,m.Operation(policy['limits']));source.qualification=qualification
        monkeypatch.setattr(source,'qualify',lambda:state['host']);monkeypatch.setattr(source,'host',lambda:state['host'])
        monkeypatch.setattr(source,'actor_context',lambda:state['context'])
        monkeypatch.setattr(source,'profile_view',peers.profile_view);monkeypatch.setattr(source,'origin',lambda path:path)
        monkeypatch.setattr(source,'selected_environment',peers.selected_environment)
        def process(which):
            if which==os.getpid():return dict(pid=which,ppid=1,start_ticks=2,uids=[0]*4,state='S',comm='python',
                cgroup='/system.slice/'+server_unit,executable=root_executable,observations={'changing':peers.count})
            row=peers.process(456 if which==pid else which)
            if which==pid:row.update(pid=pid,start_ticks=50)
            return row
        monkeypatch.setattr(source,'process',process)
        monkeypatch.setattr(source,'command_line',lambda which:peers.configuration['client']['argv_prefix']+[action]
            if which==pid else peers.command_line(which))
        monkeypatch.setattr(source,'unit',lambda name:dict(MainPID=str(os.getpid()),ControlGroup='/system.slice/'+server_unit,
            InvocationID='b'*32,ActiveState='active',MemoryMax='134217728',RuntimeMaxUSec='90s')
            if name==server_unit else peers.unit(name))
        monkeypatch.setattr(source,'snapshot',lambda launch,dispatch,budget:dict(script_path='/local/spool/'+dispatch+'.sh',
            script_sha256=launch['files']['submit_script']['sha256']))
        monkeypatch.setattr(source,'_check_snapshot',lambda snapshot:None)
        monkeypatch.setattr(source.budget,'read',lambda path,limit=65536:m.encoded(dict(open=state['gate'],release_id=state['value']['release_id'])))
        m._authenticate_server(source)
        source._caller=m.authenticate_socket_peer(Connection(),policy,source,action=action)
        if scenario=='withdraw_before_intent' and action=='submit' and not (tmp_path/'attempts').exists():
            refresh=source._refresh_caller;calls=[0]
            def withdrawing(selected):
                calls[0]+=1
                if calls[0]==3:state['gate']=False
                return refresh(selected)
            monkeypatch.setattr(source,'_refresh_caller',withdrawing)
        return m.OrdinaryAttemptOwner(policy,m.AttemptStore(tmp_path),source,source.budget)
    first=fresh('submit',456).submit(state['document'])
    directory=tmp_path/'attempts'/state['document']['calcjob_uuid']
    assert (directory/'claim.json').is_file()
    if scenario=='withdraw_before_intent':
        assert first['state']=='hold' and dispatches==[]
        state['gate']=True
        again=fresh('reconcile',567).reconcile({**state['document'],'action':'reconcile'})
        assert again['state']=='hold' and again['reason']=='partial_claim' and dispatches==[]
    elif scenario=='lost_ack':
        assert first['reason']=='dispatch_outcome_unknown' and len(dispatches)==1
        original=(directory/'failure.json').read_bytes();state['lost']=False
        again=fresh('reconcile',567).reconcile({**state['document'],'action':'reconcile'})
        assert again['reason']=='dispatch_outcome_unknown' and len(dispatches)==1
        assert (directory/'failure.json').read_bytes()==original
    else:
        assert first['state']=='bound' and len(dispatches)==1
        state['ready']=state['gate']=False
        again=fresh('status',567).status({**state['document'],'action':'status'})
        assert again['state']=='bound' and again['job']==first['job'] and len(dispatches)==1
        retained=json.loads((directory/'dispatch.json').read_bytes())['native']['owner']
        assert retained['caller']['pid']==456 and retained['actor']['calcjob_uuid']==state['document']['calcjob_uuid']
        assert set(json.loads((directory/'claim.json').read_bytes())['context'])=={'machine_id','boot_id','image_id'}


@pytest.mark.parametrize('fault',[None,'alias_target','alias_owner','mutable_ancestor'])
def test_actor_app_selection_reuses_public_nix_origin_and_root_profile(monkeypatch,fault):
    m=module();from test_application_release import delivery_manifest
    sources=m.NativeSources({'release_runtime':'/protected/runtime'},m.Operation(limits()))
    cfg=PeerSources().configuration;value=delivery_manifest(False);app=value['application_path']
    monkeypatch.setattr(sources,'actor_configuration',lambda:cfg)
    monkeypatch.setattr(m,'protected_read',lambda *args:m.encoded(value))
    def info(mode,uid=0):return (1,1,mode,uid,0,0,0)
    chain=[('/nix',info(m.stat.S_IFDIR|0o755),None),('/nix/store',info(m.stat.S_IFDIR|0o1775),None),
        ('/nix/var/nix/profiles',info(m.stat.S_IFDIR|(0o777 if fault=='mutable_ancestor' else 0o755)),None),
        (cfg['application_profile'],info(m.stat.S_IFLNK|0o777,3000 if fault=='alias_owner' else 0),app),
        ('/nix/store/other' if fault=='alias_target' else app,info(m.stat.S_IFDIR|0o555),None)]
    monkeypatch.setattr(m.engine,'public_binary_origin',lambda budget,path,**kw:{'path':path,'chain':chain})
    if fault:
        with pytest.raises(m.Hold):sources.actor_context()
    else:assert sources.actor_context()['app']==app


def test_exact_s1_bash_hop_and_fixed_client_alias_are_joined():
    m=module();sources=PeerSources();original_process=sources.process;original_command=sources.command_line
    def process(pid):
        if pid==400:return dict(pid=400,ppid=345,start_ticks=35,uids=[3000]*4,state='S',comm='bash',
            cgroup='/system.slice/qcl-negf-aiida.service/worker',executable='/nix/store/bash/bin/bash',observations={})
        row=original_process(pid)
        if pid==456:row['ppid']=400
        return row
    sources.process=process
    sources.command_line=lambda pid:['bash','--noprofile','--norc','-c',
        '/run/current-system/sw/bin/qcl-negf-native-attempt-client submit'] if pid==400 else original_command(pid)
    sources.origin=lambda path:sources.configuration['client']['entrypoint'] if path=='/run/current-system/sw/bin/qcl-negf-native-attempt-client' else path
    class Connection:
        def getsockopt(self,*args):return struct.pack('3i',456,3000,3000)
    assert [row['process']['pid'] for row in m.authenticate_socket_peer(Connection(),sources.policy,sources,action='submit')['chain']]==[456,400,345,234,123]


def test_existing_journal_encoding_is_prepaid_for_long_original_transport_int():
    m=module();budget=m.Operation(limits());value={'transport_attempt':10**1000}
    m._reserve_private_record(value,budget)
    assert budget.bytes>=len(m.encoded(value))
    first=budget.bytes;m._reserve_private_record(value,budget)
    assert budget.bytes==2*first


def test_native_off_evaluator_preserves_two_coerced_script_identity_assertion():
    source=(Path(__file__).parent/'infrastructure/native-attempt.nix').read_text()
    assert 'assert toString off.systemd.services.qcl-negf-aiida.serviceConfig.ExecStart == toString originalDaemonStart;' in source


def test_current_profile_alias_argv_cannot_certify_already_loaded_app():
    m=module();sources=PeerSources();command=sources.command_line
    sources.command_line=lambda pid:[part.replace(sources.app+'/bin/verdi',sources.profile+'/bin/verdi')
                                     for part in command(pid)]
    class Connection:
        def getsockopt(self,*args):return struct.pack('3i',456,3000,3000)
    with pytest.raises(m.Hold,match='application_origin'):
        m.authenticate_socket_peer(Connection(),sources.policy,sources,action='submit')


def test_old_mainpid_immutable_argv_does_not_follow_retargeted_profile():
    m=module();sources=PeerSources();command=sources.command_line
    sources.actor_context=lambda:{'app':'/nix/store/new-application','configuration':sources.configuration}
    sources.command_line=command  # Actual old PID keeps the old immutable APP argv.
    class Connection:
        def getsockopt(self,*args):return struct.pack('3i',456,3000,3000)
    with pytest.raises(m.Hold,match='application_origin'):
        m.authenticate_socket_peer(Connection(),sources.policy,sources,action='submit')


@pytest.mark.parametrize('fault',[None,'unit_selection','extra','jobs_root'])
def test_fixed_actor_configuration_joins_qualified_unit_and_immutable_source(monkeypatch,fault):
    m=module();sources=m.NativeSources(dict(jobs_root='/srv/qcl-negf/jobs',tools={'systemctl':'/nix/store/systemctl'}),m.Operation(limits()))
    sources._server_unit='qcl-negf-native-attempt@one.service'
    config={'schema':'qcl-negf.native-actor-launch.v1','profile':'qcl-negf',
        'aiida_path':'/var/lib/qcl-negf/aiida','application_profile':'/nix/var/nix/profiles/qcl-negf-application',
        'jobs_root':'/srv/qcl-negf/jobs','client':PeerSources().configuration['client']}
    if fault=='extra':config['verified']=True
    if fault=='jobs_root':config['jobs_root']='/other'
    path='/nix/store/config/actor.json';monkeypatch.setenv('QCL_NEGF_NATIVE_ACTOR_CONFIG',path)
    monkeypatch.setattr(m.engine,'public_binary_origin',lambda budget,path,**kw:{'path':path})
    monkeypatch.setattr(m.engine,'immutable_public_bytes',lambda *args:m.encoded(config))
    monkeypatch.setattr(sources,'run',lambda argv:'QCL_NEGF_NATIVE_ACTOR_CONFIG='+('/other' if fault=='unit_selection' else path))
    if fault:
        with pytest.raises(m.Hold):sources.actor_configuration()
    else:assert sources.actor_configuration()==config


@pytest.mark.parametrize('fault',[None,'alias','writable','log_alias','config_rw','view_changed'])
def test_existing_profile_view_actual_fd_reads_no_bootstrap_or_lock_cleanup(tmp_path,monkeypatch,fault):
    m=module();config=PeerSources().configuration;root=tmp_path/'namespace'
    folder=root/'var/lib/qcl-negf/aiida/.aiida';(folder/'access/qcl-negf').mkdir(parents=True);(folder/'log').mkdir()
    (folder/'config.json').write_bytes(b'{"fixture":"not a real profile or credential"}')
    (folder/'access/qcl-negf/unknown.lock').write_bytes(b'unknown owner; preserve')
    if fault=='alias':(folder/'config.json').rename(folder/'original');(folder/'config.json').symlink_to('original')
    if fault=='writable':(folder/'config.json').chmod(0o666)
    if fault=='log_alias':(folder/'log/aiida-qcl-negf.log').symlink_to('../config.json')
    sources=m.NativeSources({'client_uid':os.getuid()},m.Operation(limits()));opened=os.open
    def namespace(path,*args,**kwargs):
        text=str(path)
        if text.startswith('/proc/') and text.endswith('/root'):return opened(root,*args,**kwargs)
        return opened(path,*args,**kwargs)
    monkeypatch.setattr(m.os,'open',namespace)
    def mountinfo(path,limit=65536):
        assert str(path).endswith('/mountinfo')
        if fault=='view_changed' and '/123/' in str(path):(folder/'config.json').write_bytes(b'changed')
        return ('1 0 0:1 / /var/lib/qcl-negf/aiida/.aiida/config.json '+
                ('rw' if fault=='config_rw' else 'ro')+' - ext4 /dev/fixture rw\n').encode()
    monkeypatch.setattr(sources.budget,'read',mountinfo)
    if fault:
        with pytest.raises((m.Hold,OSError)):sources.profile_view(123,{'configuration':config})
    else:
        result=sources.profile_view(123,{'configuration':config})
        assert result['sha256']==hashlib.sha256((folder/'config.json').read_bytes()).hexdigest()
    assert (folder/'access/qcl-negf/unknown.lock').read_bytes()==b'unknown owner; preserve'


@pytest.mark.parametrize('manual', [False, True])
def test_hook_auth_requires_actual_slurmd_ancestry_not_root_or_environment(monkeypatch, manual):
    m = module()
    monkeypatch.setattr(m.os, 'getuid', lambda: 0); monkeypatch.setattr(m.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(m.os, 'getpid', lambda: 500)
    class Sources:
        policy = {'slurmd_unit': 'slurmd.service', 'tools': {'slurmd': '/nix/store/slurmd'}}
        def unit(self, name):
            return dict(MainPID='100', ControlGroup='/system.slice/slurmd.service',
                        InvocationID='a' * 32, ActiveState='active')
        def process(self, pid):
            return dict(pid=pid, ppid=(1 if manual else 100), start_ticks=pid, uids=[0] * 4,
                        cgroup=('/user.slice/shell' if manual else '/system.slice/slurmd.service'),
                        executable='/nix/store/slurmd' if pid == 100 else '/nix/store/python')
    if manual:
        with pytest.raises(m.Hold): m.authenticate_hook(Sources())
    else:
        assert [p['pid'] for p in m.authenticate_hook(Sources())['chain']] == [500, 100]


def test_native_job_parser_and_dispatch_join_positive_reused_generation_negative(monkeypatch):
    m = module(); launch = request()['launch']; dispatch = request()['calcjob_uuid']
    sources = m.NativeSources(dict(tools={'scontrol': '/fixed/scontrol'}, spool_root='/local/spool'), m.Operation(limits()))
    text = ('JobId=42 UserId=qcl-negf(3000) SubmitTime=2026-10-29T01:00:00 WorkDir=' + launch['remote_workdir'] +
            ' Comment=' + dispatch + ' Command=/local/spool/' + dispatch + '.sh Restarts=0 NumNodes=1 NumTasks=1')
    monkeypatch.setattr(sources, 'run', lambda argv: text)
    context = {'machine_id': 'a' * 32, 'boot_id': '88888888-8888-4888-8888-888888888888'}
    result = sources.bind_job(dict(job_id='42', cluster='cluster'), launch, dispatch, context, sources.budget)
    assert result['job_id'] == '42' and len(result['generation']) == 64
    text = text.replace('Restarts=0', 'Restarts=1')
    with pytest.raises(m.Hold):
        sources.bind_job(dict(job_id='42', cluster='cluster'), launch, dispatch, context, sources.budget)


def test_closed_native_stop_never_bypasses_missing_q1(tmp_path):
    m = module(); first, sources = owner(tmp_path)
    first.submit(request())
    sources.worker = lambda *args: {'before': {'measured': 'fixture'}, 'after': {'scientific_accepted': False}}
    sources.close_writers = lambda *args: None
    close = request('close'); close['controls'] = []
    result = first.qualify_close(close)
    assert result['state'] == 'hold' and result['reason'] == 'q1_controls_unavailable'
    assert result['controls'] is None and len(sources.calls) == 1


def test_limits_are_inherited_not_reset_and_debit_before_command(monkeypatch):
    m = module(); operation = m.Operation(limits()); calls = []
    def run(argv, **kw): calls.append(kw); return m.engine.CommandOutput('observed')
    operation.command(['/fixed/readonly'], run=run, output_bytes=100)
    first = operation.bytes
    operation.command(['/fixed/readonly'], run=run, output_bytes=100)
    assert operation.bytes == first * 2 and calls[0]['deadline'] == calls[1]['deadline']
    operation.bytes = operation.limits['metadata_bytes']
    with pytest.raises(m.Hold): operation.command(['/fixed/readonly'], run=run)
    assert len(calls) == 2
    operation.deadline = 0
    with pytest.raises(m.Hold): operation.command(['/fixed/readonly'], run=run)
    assert len(calls) == 2


@pytest.mark.parametrize('change', [None, 'boot', 'tool', 'version', 'cluster', 'storage', 'journal_nfs', 'pass_flag'])
def test_native_policy_qualification_joins_observed_host_tools_units_and_storage(monkeypatch, change):
    m = module(); host = dict(machine_id='a' * 32, boot_id=request()['launch']['request_id'], image_id='/nix/store/image')
    tools = {key: '/nix/store/' + key for key in ('systemctl', 'runuser', 'sbatch', 'scontrol', 'slurmd', 'slurmstepd', 'python')}
    policy = dict(role='controller', tools=tools, slurm=dict(cluster='cluster', version='slurm 1', config_file='/fixed/slurm.conf'),
                  private_root='/local/attempts', spool_root='/local/spool', jobs_root='/jobs', nfs_source='storage:/jobs',
                  qualification_file='/protected/qualification', storage_identity_file='/protected/storage',
                  _policy_sha256='b' * 64, daemon_unit='qcl-negf-aiida.service', server_unit_prefix='qcl-negf-native-attempt@')
    fragment = b'actual immutable unit source'
    qualification = dict(protocol_id='p07-ordinary-slurm-v1', policy_sha256='b' * 64,
                         controller_binding=copy.deepcopy(host), worker_bindings={}, tool_origins=copy.deepcopy(tools),
                         unit_origins={'qcl-negf-aiida.service': dict(fragment_path='/nix/store/unit',
                                      fragment_sha256=hashlib.sha256(fragment).hexdigest(), executable='/nix/store/python')},
                         write_domain={'storage_identity': 'actual-storage'}, qualification_receipt_ref='fixture-N-receipt')
    if change == 'boot': qualification['controller_binding']['boot_id'] = request()['calcjob_uuid']
    if change == 'tool': qualification['tool_origins']['sbatch'] += '-changed'
    if change == 'pass_flag': qualification['verified'] = True
    sources = m.NativeSources(policy, m.Operation(limits()))
    monkeypatch.setattr(sources, 'host', lambda: host)
    def mount(path):
        if path == '/jobs': return dict(fstype='nfs4', source='storage:/jobs', options={'hard'})
        return dict(fstype=('nfs4' if change == 'journal_nfs' else 'ext4'))
    monkeypatch.setattr(sources, 'mount', mount)
    monkeypatch.setattr(m, 'trusted_root_path', lambda path, **kw: Path(path))
    monkeypatch.setattr(m.engine, 'public_binary_origin', lambda budget, path, **kw: {'path': path})
    monkeypatch.setattr(m.engine, 'immutable_public_bytes', lambda *args: fragment)
    def read(path, *args):
        if str(path) == policy['qualification_file']: return m.encoded(qualification)
        if str(path) == policy['storage_identity_file']: return b'changed-storage' if change == 'storage' else b'actual-storage'
        if str(path) == policy['slurm']['config_file']: return b'ClusterName=other' if change == 'cluster' else b'ClusterName=cluster'
        raise AssertionError(path)
    monkeypatch.setattr(m, 'protected_read', read)
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if '--version' in argv: text = 'slurm changed' if change == 'version' else 'slurm 1'
        else: text = ('InvocationID=' + 'a' * 32 + '\nControlGroup=/system.slice/qcl-negf-aiida.service\nMainPID=123\n'
                      'ActiveState=active\nFragmentPath=/nix/store/unit\nMemoryMax=134217728\nRuntimeMaxUSec=1min 30s\n')
        output = m.engine.CommandOutput(text); output.output_bytes = len(text); return output
    monkeypatch.setattr(m.engine, 'command', run)
    if change:
        with pytest.raises(m.Hold): sources.qualify()
    else:
        assert sources.qualify() == host and len(calls) == 2 and sources.budget.calls == 2


def test_attempt_facts_uses_existing_flat_guest_config_not_a_new_nested_policy(monkeypatch):
    m = module(); import host_resource_facts as facts
    document = dict(version=1, calcjob_uuid=request()['calcjob_uuid'], dispatch_id=request()['launch']['request_id'],
                    job_id='42', generation='b' * 64, phase='status')
    host = dict(machine_id='a' * 32, boot_id=request()['calcjob_uuid'], image_id='/nix/store/image')
    config = dict(schema='qcl.host-resource-service.v1', role='guest', client_uid=3000, node='node-a')
    policy = dict(facts_service_config='/protected/service.json', private_root='/local', spool_root='/spool')
    fields = dict(SubmitTime='today', Comment=document['dispatch_id'], Command='/spool/' + document['dispatch_id'] + '.sh', WorkDir='/jobs/upload')
    generation = hashlib.sha256(m.encoded(dict(controller=host, job_id='42', submit_time='today',
                               dispatch_id=document['dispatch_id'], command=fields['Command'], workdir=fields['WorkDir']))).hexdigest()
    document['generation'] = generation
    monkeypatch.setattr(m, '_load_policy', lambda *args: policy)
    monkeypatch.setattr(m.NativeSources, 'qualify', lambda self: setattr(self, 'qualification', {'controller_binding': host}) or host)
    monkeypatch.setattr(m.NativeSources, 'native_job', lambda *args: {'fields': fields, 'raw': 'original'})
    def read(path, *args):
        if str(path) == policy['facts_service_config']: return m.encoded(config)
        raise FileNotFoundError('hook absent on this unrelated status host')
    monkeypatch.setattr(m, 'protected_read', read)
    def identity(actual, sources):
        assert actual is config or actual == config
        return {'schema': 'qcl.host-resource-guest-identity.v1', 'identity': host}
    monkeypatch.setattr(facts, 'capture_guest_identity', identity)
    monkeypatch.setattr(m, '_capture_writer_snapshot', lambda actual, *args,**kwargs: {'flat_config': actual == config and
        isinstance(kwargs['output_sources'],m.NativeSources)})
    result = m.read_attempt_facts(document)
    assert result['writer_snapshot']['flat_config'] is True and result['prolog_ref'] is None


def test_client_unknown_transport_returns_typed_hold_and_no_retry(monkeypatch, capsys):
    m = module(); calls = []
    def disconnected(context):
        assert context=={}
        calls.append('one'); raise OSError('lost response')
    monkeypatch.setattr(m, '_client_operation', disconnected, raising=False)
    assert m.client_main() == 75
    result = json.loads(capsys.readouterr().out)
    assert result['state'] == 'hold' and result['reason'] == 'transport_outcome_unknown' and calls == ['one']


def test_started_response_attaches_real_worker_without_replacing_native_generation(tmp_path):
    first, sources = owner(tmp_path); result = first.submit(request()); original = result['job']
    identity = dict(machine_id='c' * 32, boot_id=request()['launch']['run_uuid'])
    sources.worker = lambda *args: dict(before={'status': 'pass_live_job_membership'},
        identity={'identity': identity}, job={'fields': {'NodeList': 'node-a', 'StartTime': '2026-10-29T01:00:01'}})
    started = first.observe_start(request('start'))
    assert started['state'] == 'started' and started['job']['worker_machine_id'] == identity['machine_id']
    assert started['job']['node_name'] == 'node-a' and started['job']['generation'] == original['generation']
    original_bytes = (first.store.path(request()['calcjob_uuid']) / 'allocation.json').read_bytes()
    sources.worker = lambda *args: dict(before={'status': 'pass_live_job_membership'},
        identity={'identity': {**identity, 'boot_id': request()['launch']['request_id']}},
        job={'fields': {'NodeList': 'node-a', 'StartTime': '2026-10-29T01:00:01'}})
    assert first.observe_start(request('start'))['state'] == 'hold'
    assert (first.store.path(request()['calcjob_uuid']) / 'allocation.json').read_bytes() == original_bytes


def test_facts_command_failure_retains_bounded_original_and_known_job(tmp_path):
    m = module(); first, sources = owner(tmp_path); original = first.submit(request())['job']
    primary = {'failure': 'timeout', 'stdout': 'original facts prefix', 'child_started': True, 'cleanup_confirmed': False}
    def failed(*args): raise m.engine.CommandFailure(primary)
    sources.worker = failed
    result = first.observe_start(request('start'))
    assert result['state'] == 'hold' and result['job'] == original
    records = list(first.store.path(request()['calcjob_uuid']).glob('observation-failure-*.json'))
    assert len(records) == 1
    import base64
    retained = json.loads(records[0].read_bytes())
    assert json.loads(base64.b64decode(retained['original_prefix_base64'])) == primary


def test_policy_tightens_original_deadline_without_a_new_window(monkeypatch):
    m = module(); budget = m._bootstrap_operation(); initial = budget.deadline - budget.limits['operation_seconds']
    policy = dict(schema='qcl-negf.native-attempt-policy.v1', role='controller', private_root='/local/attempts',
        spool_root='/local/spool', socket_path=m.SOCKET, jobs_root='/jobs', native_result_prefix='native',
        nfs_source='storage:/jobs', storage_identity_file='/protected/storage', release_runtime='/protected/runtime',
        client_uid=3000, daemon_unit='qcl-negf-aiida.service', server_unit_prefix='qcl-negf-native-attempt@',
        slurmd_unit='slurmd.service', tools={key: '/nix/store/' + key for key in
            ('systemctl', 'runuser', 'sbatch', 'scontrol', 'slurmd', 'slurmstepd', 'python')},
        slurm=dict(cluster='cluster', version='slurm 1', config_file='/fixed/conf', cgroup_scope='/system.slice/slurmstepd.scope'),
        facts_service_config='/protected/facts', worker_routes={'worker': dict(target='facts@worker', known_hosts='/protected/hosts',
            identity_file='/protected/key', helper='/fixed/rpc', role='facts')}, qualification_file='/protected/qualification', limits=limits())
    monkeypatch.setattr(m.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(m, 'protected_read', lambda *args: m.encoded(policy))
    m._load_policy('controller', budget)
    assert budget.deadline <= initial + limits()['operation_seconds']


def test_protected_script_snapshot_positive_survives_original_upload_mutation(tmp_path, monkeypatch):
    from contextlib import contextmanager
    m = module(); work = tmp_path / 'upload'; work.mkdir(); spool = tmp_path / 'spool'; spool.mkdir()
    launch = request()['launch']; launch['remote_workdir'] = str(work)
    for name in m.FILES.values(): (work / name).write_bytes(b'abc')
    (work/'plan.json').write_bytes(b'{}');launch['files']['plan']=dict(bytes=2,sha256=hashlib.sha256(b'{}').hexdigest())
    policy = dict(jobs_root=str(tmp_path), spool_root=str(spool), client_uid=3000, limits=limits())
    sources = m.NativeSources(policy, m.Operation(limits()))
    monkeypatch.setattr(m, '_read_submitted_files_as_owner', lambda p, l, b: m._owner_read({**p, 'client_uid': os.getuid()}, l, b))
    @contextmanager
    def fixture_directory(path, **kwargs):
        assert Path(path) == spool
        fd = os.open(spool, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: yield fd
        finally: os.close(fd)
    monkeypatch.setattr(m, 'protected_directory', fixture_directory)
    ownership = []
    monkeypatch.setattr(m.os, 'fchown', lambda fd, uid, gid: ownership.append((uid, gid)))
    monkeypatch.setattr(m, 'trusted_stat', lambda info, **kw: None)  # explicit unprivileged fixture namespace
    snapshot = sources.snapshot(launch, request()['calcjob_uuid'], sources.budget)
    assert ownership == [(0, 3000)] and Path(snapshot['script_path']).read_bytes() == b'abc'
    (work / '_aiidasubmit.sh').write_bytes(b'changed after upload hash')
    sources._check_snapshot(snapshot)
    assert Path(snapshot['script_path']).read_bytes() == b'abc'
    (work / '_aiidasubmit.sh').write_bytes(b'abc')
    with pytest.raises(FileExistsError): sources.snapshot(launch, request()['calcjob_uuid'], sources.budget)


@pytest.mark.parametrize('image_kind', ['nonexecuting', 'writable', 'foreign_origin', 'non_root'])
def test_f1_actual_host_reader_immutable_data_origin(tmp_path, monkeypatch, image_kind):
    """Actual host/helper bodies; only filesystem/kernel identity is projected.

    Mode/type/symlink metadata come from real temporary files. UID0 is an
    explicit private ownership fixture, never an observation of native NixOS.
    """
    import stat
    from types import SimpleNamespace
    m = module(); tree = tmp_path / 'filesystem'; tree.mkdir()
    image = ('/images/foreign' if image_kind == 'foreign_origin' else
             '/nix/store/' + 'a' * 32 + '-nixos-system-fixture')
    def physical(path): return tree / str(path).lstrip('/')
    for path in ('/run', '/etc', '/proc/sys/kernel/random', image):
        physical(path).mkdir(parents=True, exist_ok=True)
    physical('/run/current-system').symlink_to(image)
    marker = physical(image + '/nixos-version'); marker.write_bytes(b'fixture NixOS image data')
    marker.chmod(0o644 if image_kind == 'writable' else 0o444)
    assert not marker.stat().st_mode & 0o111
    physical('/etc/machine-id').write_text('a' * 32 + '\n')
    physical('/proc/sys/kernel/random/boot_id').write_text(request()['calcjob_uuid'] + '\n')
    budget = m.Operation(limits()); original_read, original_stat, original_link = budget.read, budget.stat, budget.link
    monkeypatch.setattr(budget, 'read', lambda path, limit=65536: original_read(physical(path), limit))
    def projected_stat(path, **kwargs):
        info = original_stat(physical(path), **kwargs)
        fields = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
        fields['st_uid'] = 1000 if image_kind == 'non_root' and str(path) == image + '/nixos-version' else 0
        return SimpleNamespace(**fields)
    monkeypatch.setattr(budget, 'stat', projected_stat)
    monkeypatch.setattr(budget, 'link', lambda path: original_link(physical(path)))
    monkeypatch.setattr(m.engine, 'command', lambda *args, **kwargs: pytest.fail('host reader launched a command'))
    assert stat.S_ISREG(marker.stat().st_mode)
    sources = m.NativeSources({}, budget)
    if image_kind == 'nonexecuting':
        assert sources.host() == dict(machine_id='a' * 32, boot_id=request()['calcjob_uuid'], image_id=image)
    else:
        with pytest.raises(ValueError, match='Untrusted public executable origin'):
            sources.host()


@pytest.mark.parametrize('large', [False, True])
def test_f1_actual_hook_contains_original_command_failure_before_foreign_classification(monkeypatch, capsys, large):
    """Run actual hook -> qualification -> run/command boundary, without a job."""
    import base64
    m = module(); host = dict(machine_id='a' * 32, boot_id=request()['calcjob_uuid'], image_id='/nix/store/image')
    tools = {key: '/nix/store/' + key for key in ('systemctl', 'runuser', 'sbatch', 'scontrol', 'slurmd', 'slurmstepd', 'python')}
    policy = dict(role='worker', tools=tools, qualification_file='/protected/qualification', _policy_sha256='b' * 64,
                  slurm=dict(cluster='cluster', version='slurm 1', config_file='/fixed/slurm.conf'))
    qualification = dict(protocol_id='p07-ordinary-slurm-v1', policy_sha256='b' * 64,
                         controller_binding=host, worker_bindings={host['machine_id']: host},
                         unit_origins={}, tool_origins=tools, write_domain={}, qualification_receipt_ref='fixture-only')
    monkeypatch.setattr(m.sys, 'argv', ['qcl-negf-native-attempt-hook', 'prolog'])
    monkeypatch.setattr(m, '_load_policy', lambda role, budget: policy)
    monkeypatch.setattr(m, 'protected_read', lambda path, budget: m.encoded(qualification))
    monkeypatch.setattr(m.NativeSources, 'host', lambda self: host)
    monkeypatch.setattr(m.engine, 'public_binary_origin', lambda budget, path: {'path': path})
    record = dict(failure='timeout', returncode=None, elapsed_seconds=5.0,
                  stdout='original stdout' + ('X' * 20000 if large else ''), stderr='original stderr',
                  output_truncated=False, cleanup_confirmed=False, child_started=True, output_bytes=31)
    primary = m.engine.CommandFailure(record); original = copy.deepcopy(record); calls = []
    def failure(argv, **kwargs):
        calls.append((argv, kwargs)); raise primary
    monkeypatch.setattr(m.engine, 'command', failure)
    monkeypatch.setattr(m.NativeSources, 'native_job', lambda *args: pytest.fail('foreign classification happened after failed qualification'))
    monkeypatch.setattr(m, 'authenticate_hook', lambda *args: pytest.fail('fabricated hook proof'))
    monkeypatch.setattr(m.AttemptStore, 'put', lambda *args: pytest.fail('fabricated lifecycle journal'))
    assert m.hook_main() == 0
    captured = capsys.readouterr()
    assert captured.out == '' and len(captured.err.encode()) <= 4096
    diagnostic = json.loads(captured.err.split('native-attempt hook HOLD: ', 1)[1])
    raw = m.encoded(original); prefix = base64.b64decode(diagnostic['original_prefix_base64'], validate=True)
    assert diagnostic['reason'] == 'native_command_failed' and prefix == raw[:2048]
    assert diagnostic['original_bytes'] == len(raw) and diagnostic['original_sha256'] == hashlib.sha256(raw).hexdigest()
    assert diagnostic['truncated'] is (len(raw) > 2048) and primary.record is record and record == original
    assert len(calls) == 1 and calls[0][0] == [tools['scontrol'], '--version']
    assert calls[0][1]['deadline'] > 0 and calls[0][1]['output_bytes'] <= 262144


@pytest.mark.parametrize('phase,missing', [('start', 'native_prolog_not_observed'), ('close', 'native_epilog_not_observed')])
def test_f1_missing_hook_proof_still_holds_only_the_dependent_managed_attempt(tmp_path, monkeypatch, phase, missing):
    m = module(); import host_resource_facts as facts
    first, observed = owner(tmp_path); bound = first.submit(request())['job']
    host = dict(machine_id='c' * 32, boot_id=request()['calcjob_uuid'])
    packet = dict(version=1, identity={'schema': 'qcl.host-resource-guest-identity.v1', 'identity': host},
                  job={'fields': dict(SubmitTime=bound['submit_time'], Comment=bound['dispatch_id'])},
                  prolog_ref=None if phase == 'start' else 'hooks/original-prolog.json', epilog_ref=None,
                  before=None, after=None, writer_snapshot={})
    native = m.NativeSources({'worker_routes': {'node-a': {}}}, first.budget)
    native.qualification = {'worker_bindings': {host['machine_id']: host}}
    monkeypatch.setattr(native, 'native_job', lambda job: {'fields': dict(SubmitTime=bound['submit_time'],
                         Comment=bound['dispatch_id'], NodeList='node-a')})
    monkeypatch.setattr(native, '_trust_root', lambda: '/private/fixture-only')
    monkeypatch.setattr(facts, 'trusted_rpc', lambda *args, **kwargs: packet)
    observed.worker = native.worker
    document = request(phase); document['controls'] = [dict(path=name,bytes=0,sha256=hashlib.sha256(b'').hexdigest())
        for name in ('series_result.json','native-selection.json','_scheduler-stdout.txt','_scheduler-stderr.txt')] if phase == 'close' else None
    result = first.observe_start(document) if phase == 'start' else first.qualify_close(document)
    assert result['state'] == 'hold' and result['reason'] == missing and result['job'] == bound
    assert result['controls'] is None and len(observed.calls) == 1
    assert not (first.store.path(document['calcjob_uuid']) / 'allocation.json').exists()


def q1_controls(root,launch):
    names=('series_result.json','native-selection.json','_scheduler-stdout.txt','_scheduler-stderr.txt')
    result=root/launch['relative_execution_root'];work=root/Path(launch['remote_workdir']).relative_to('/srv/qcl-negf/jobs')
    result.mkdir(parents=True);work.mkdir(parents=True)
    contents=(b'original failed result bytes\n',b'{"version":1,"selected_inputs":[]}',b'',b'original log\x00bytes')
    claims=[]
    for index,(name,raw) in enumerate(zip(names,contents)):
        path=(result if index<2 else work)/name;path.write_bytes(raw);path.chmod(0o640)
        claims.append(dict(path=name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
    return claims,result,work


@pytest.mark.parametrize('fault',[None,'replacement','content','missing_log','fsync'])
def test_held_output_files_sync_and_survive_actual_post_w1_boundary(tmp_path,monkeypatch,fault):
    """Actual FDs/files, explicit own UID namespace; not native UID3000 proof."""
    m=module();namespace=tmp_path/'namespace';jobs=namespace/'srv/qcl-negf/jobs';launch=request()['launch']
    controls,result,work=q1_controls(jobs,launch)
    for name in ('solver.stdout','solver.stderr'):(work/name).write_bytes(b'synthetic logger bytes')
    if fault=='missing_log':(work/'solver.stderr').unlink()
    policy=dict(client_uid=os.getuid(),jobs_root='/srv/qcl-negf/jobs',native_result_prefix='native')
    opened=m.os.open;synced=[];handles={};boundary=[];sync=m.os.fsync
    names={row['path'] for row in controls}|{'solver.stdout','solver.stderr'}
    def opening(path,*args,**kwargs):
        fd=opened(namespace if str(path)=='/' else path,*args,**kwargs)
        if str(path) in names:handles[str(path)]=fd
        return fd
    def fsync(fd):
        sync(fd);synced.append(fd)
        if fault=='fsync' and fd==handles.get('series_result.json'):raise OSError('original fsync failure')
    monkeypatch.setattr(m.os,'open',opening);monkeypatch.setattr(m.os,'fsync',fsync)
    monkeypatch.setattr(m.os,'scandir',lambda *a,**k:pytest.fail('finite close must not enumerate trees'))
    def post_w1(metadata):
        boundary.append(True)
        assert set(handles)==names and all(fd in synced for fd in handles.values())
        assert all(m.stat.S_ISREG(os.fstat(fd).st_mode) for fd in handles.values())
        assert metadata['controls']==controls
        if fault=='replacement':
            (result/'series_result.json').rename(result/'retained-original')
            (result/'series_result.json').write_bytes(b'original failed result bytes\n')
        elif fault=='content':(result/'series_result.json').write_bytes(b'changed')
    budget=m.Operation({**limits(),'maximum_files':2048})
    def call():return m._owner_close_read(policy,launch,budget,controls,
        technical_control=dict(status='absent',path=m.TECHNICAL_FILE,reason='not_published'),
        durable=True,solver_logs=True,barrier=post_w1)
    if fault is None:
        observed=call();assert observed['controls']==controls and boundary==[True]
        assert {r['path'] for r in observed['logs']}=={'solver.stdout','solver.stderr'}
        assert observed['io']['actual_bytes']==2*(sum(r['bytes'] for r in controls)+2*len(b'synthetic logger bytes'))
    else:
        with pytest.raises((m.Hold,OSError)):call()
        assert boundary==([] if fault in ('missing_log','fsync') else [True])
    for fd in handles.values():
        with pytest.raises(OSError):os.fstat(fd)


@pytest.fixture
def q1_joined(tmp_path,monkeypatch):
    """Actual owner/preflight/W1/reader/store; OS/RPC facts are SOURCE fixtures."""
    m=module();real_reader=m._read_submitted_files_as_owner
    state=actor_bridge.__wrapped__(monkeypatch);source=state['sources'];policy=source.policy
    journal=tmp_path/'journal';journal.mkdir(mode=0o700)
    namespace=tmp_path/'namespace';jobs=namespace/'srv/qcl-negf/jobs'
    controls,result,work=q1_controls(jobs,state['document']['launch'])
    policy.update(private_root=str(journal),spool_root='/local/spool',daemon_unit='qcl-negf-aiida.service',
        server_unit_prefix='qcl-negf-native-attempt@',worker_routes={'node-a':{'fixture':'authenticated RPC boundary'}},
        nfs_source='storage:/jobs',limits={**policy['limits'],'maximum_files':2048})
    source.budget=m.Operation(policy['limits']);host=state['host'];dispatch=state['document']['calcjob_uuid']
    store=m.AttemptStore(journal);launch=state['document']['launch']
    job=dict(job_id='42',cluster='cluster',submit_time='2026-10-30T01:00:00',controller_machine_id=host['machine_id'],
        controller_boot_id=host['boot_id'],dispatch_id=dispatch,generation='b'*64,node_name='node-a',
        start_time='2026-10-30T01:00:01',worker_machine_id='c'*32,worker_boot_id=dispatch)
    for name,value in [('claim.json',dict(launch=launch,dispatch_id=dispatch,context=host)),
        ('dispatch.json',dict(original='retained source fixture')),('ack.json',dict(job_id='42',cluster='cluster')),
        ('job.json',job),('allocation.json',job)]:store.put(dispatch,name,value,source.budget)
    source.qualification=dict(write_domain=dict(storage_identity='storage',native_prefix='native',retention_ref='qualified-site-locator',
        writer_hosts={'node-a':'c'*32},controller_units=['qcl-negf-aiida.service','qcl-negf-api.service']),
        worker_bindings={'c'*32:dict(machine_id='c'*32,boot_id=dispatch)},unit_origins={'server':{'executable':'/nix/store/root-python'}})
    monkeypatch.setattr(source,'host',lambda:host)
    monkeypatch.setattr(source,'native_job',lambda job_id:dict(fields=dict(SubmitTime=job['submit_time'],Comment=dispatch,NodeList='node-a')))
    server='qcl-negf-native-attempt@fixture.service'
    monkeypatch.setattr(source,'process',lambda pid:dict(pid=pid,ppid=1,start_ticks=2,uids=[0]*4,state='S',comm='python',
        cgroup='/system.slice/'+server,executable='/nix/store/root-python'))
    def unit(name):return dict(InvocationID='d'*32,ControlGroup='/system.slice/'+name,
        MainPID=str(os.getpid()) if name==server else ('123' if name==policy['daemon_unit'] else '124'),
        ActiveState='active',MemoryMax='134217728',RuntimeMaxUSec='90s')
    monkeypatch.setattr(source,'unit',unit)
    original_read=source.budget.read
    def read(path,limit=65536):
        if str(path).endswith('/mountinfo'):
            return ('1 0 0:1 / /srv/qcl-negf/jobs/native ro - nfs4 storage:/jobs rw\n').encode()
        return original_read(path,limit)
    monkeypatch.setattr(source.budget,'read',read)
    inventory=dict(schema='qcl.host-resource-guest-facts.v1',identity_before={'boot':'fixture'},identity_after={'boot':'fixture'},
        slurm_registered=True,jobs={},groups={})
    packet=dict(version=1,identity=dict(schema='qcl.host-resource-guest-identity.v1',identity=dict(machine_id='c'*32,boot_id=dispatch)),
        job=dict(fields=dict(SubmitTime=job['submit_time'],Comment=dispatch)),prolog_ref='prolog',epilog_ref='epilog',
        before={'original_live_before':'RPC fixture'},after={'whole_stop':'RPC fixture'},writer_snapshot=inventory)
    import host_resource_facts as facts
    monkeypatch.setattr(facts,'trusted_rpc',lambda *args,**kw:copy.deepcopy(packet))
    fake_reader=m._read_submitted_files_as_owner;uid=os.getuid();euid=os.geteuid()
    # This tests the production fork/FD code using only our synthetic child and
    # own temp files. Real UID3000/NFS qualification remains Root's native gate.
    def owner_reader(p,launch,budget,*,controls=None,technical_control=None,barrier=None,solver_logs=False,native_inputs=None):
        if controls is None:return fake_reader(p,launch,budget)
        opened=m.os.open;fork=m.os.fork
        child={'dropped':False,'parent_after_fork':False}
        with monkeypatch.context() as patch:
            patch.setattr(m.os,'geteuid',lambda:uid if child['dropped'] or child['parent_after_fork'] else 0)
            patch.setattr(m.os,'setgroups',lambda groups:None if groups==[] else pytest.fail('groups'))
            patch.setattr(m.os,'setgid',lambda value:None)
            patch.setattr(m.os,'setuid',lambda value:child.update(dropped=True))
            def forking():
                pid=fork()
                if pid>0:child['parent_after_fork']=True
                return pid
            patch.setattr(m.os,'fork',forking)
            def open_path(path,*args,**kw):
                if str(path)=='/':
                    assert child['dropped'],'root must not open NFS payload/ancestry'
                    return opened(namespace,*args,**kw)
                return opened(path,*args,**kw)
            patch.setattr(m.os,'open',open_path)
            options={} if technical_control is None else {'technical_control':technical_control}
            if barrier is not None:options['barrier']=barrier
            if solver_logs:options['solver_logs']=True
            if native_inputs is not None:options['native_inputs']=native_inputs
            return real_reader({**p,'client_uid':uid},launch,budget,controls=controls,**options)
    monkeypatch.setattr(m,'_read_submitted_files_as_owner',owner_reader)
    state.update(store=store,controls=controls,result=result,work=work,packet=packet,job=job,journal=journal,unit=unit)
    state['owner']=m.OrdinaryAttemptOwner(policy,store,source,source.budget)
    return state


@pytest.mark.parametrize('fault',[None,'replacement','cancel','late_close'])
def test_actual_private_child_holds_fds_through_parent_w1_and_closes_before_return(q1_joined,monkeypatch,fault):
    s=q1_joined;m=s['m'];parent=os.getpid();boundary=[]
    for name in ('solver.stdout','solver.stderr'):(s['work']/name).write_bytes(b'logger')
    document=q1t_document(s,None);inode=(s['result']/'series_result.json').stat().st_ino
    close=m.os.close;primary=KeyboardInterrupt('parent post-W1 cancelled')
    if fault=='late_close':
        def closing(fd):
            target=False
            if os.getpid()!=parent:
                try:target=os.fstat(fd).st_ino==inode
                except OSError:pass
            close(fd)
            if target:raise OSError('original held-file close failure')
        monkeypatch.setattr(m.os,'close',closing)
    def post_w1(value):
        assert os.getpid()==parent
        boundary.append(True);assert value['controls']==s['controls']
        if fault=='replacement':
            (s['result']/'series_result.json').rename(s['result']/'held-original')
            (s['result']/'series_result.json').write_bytes(b'original failed result bytes\n')
        if fault=='cancel':raise primary
    def read():return m._read_submitted_files_as_owner(s['sources'].policy,document['launch'],s['sources'].budget,
        controls=document['controls'],technical_control=document['technical_control'],solver_logs=True,barrier=post_w1)
    if fault is None:
        value=read();assert value['controls']==s['controls']
        assert value['io']['actual_bytes']==2*(sum(c['bytes'] for c in s['controls'])+2*len(b'logger'))
    elif fault=='cancel':
        with pytest.raises(KeyboardInterrupt) as caught:read()
        assert caught.value is primary
    else:
        with pytest.raises(m.Hold):read()
    assert boundary==[True]
    assert not (s['store'].path(document['calcjob_uuid'])/'close.json').exists()


@pytest.mark.parametrize('case',['exact','bytes_short','files_short','expired','child_overrun','failed_unconsumed'])
def test_held_child_spends_only_parent_prepaid_credit_before_first_effect(q1_joined,monkeypatch,case):
    s=q1_joined;m=s['m'];document=q1t_document(s,None);policy=s['sources'].policy
    for name in ('solver.stdout','solver.stderr'):(s['work']/name).write_bytes(b'logger')
    read_bytes,file_ops,envelope,_=m._held_read_forecast(policy,document['launch'],document['controls'],
        document['technical_control'],True,65536)
    full_bytes=read_bytes+envelope
    budget=m.Operation({**policy['limits'],'metadata_bytes':full_bytes-(case=='bytes_short'),
        'maximum_files':file_ops-(case=='files_short')})
    if case=='expired':budget.deadline=m.time.monotonic()-1
    pipe=m.os.pipe2;fork=m.os.fork;effects=[];boundaries=[]
    def pipe2(*args):effects.append('pipe');return pipe(*args)
    def forking():effects.append('fork');return fork()
    monkeypatch.setattr(m.os,'pipe2',pipe2);monkeypatch.setattr(m.os,'fork',forking)
    if case=='child_overrun':
        def overrun(*args,**kwargs):m._owner_read_reserve(budget,read_bytes+1)
        monkeypatch.setattr(m,'_owner_close_read',overrun)
    if case=='failed_unconsumed':(s['work']/'solver.stderr').unlink()
    def call():return m._read_submitted_files_as_owner(policy,document['launch'],budget,
        controls=document['controls'],technical_control=document['technical_control'],solver_logs=True,
        barrier=lambda value:boundaries.append(value))
    if case=='exact':
        result=call();assert boundaries and result['io']['actual_bytes']>0
        assert result['io']['file_operations']<file_ops and result['io']['actual_bytes']<read_bytes
    else:
        with pytest.raises(m.Hold):call()
        assert boundaries==[]
    if case in ('bytes_short','files_short','expired'):assert effects==[]
    else:assert effects==['pipe','pipe','fork']
    # Failed/unused child slices remain charged to the same parent operation.
    assert budget.bytes==(0 if case=='expired' else full_bytes)
    assert budget.files==(0 if case in ('expired','bytes_short') else file_ops)
    assert not hasattr(budget,'_owner_read_credit')


def test_parent_cancellation_retains_already_reported_actual_child_read_bytes(q1_joined,monkeypatch):
    s=q1_joined;m=s['m'];document=q1t_document(s,None);budget=s['sources'].budget
    for name in ('solver.stdout','solver.stderr'):(s['work']/name).write_bytes(b'logger')
    parent=os.getpid();read=m.os.read;transport=[];reported=[];primary=KeyboardInterrupt('original parent cancellation')
    def reading(fd,size):
        raw=read(fd,size)
        if os.getpid()==parent and m.stat.S_ISFIFO(os.fstat(fd).st_mode):transport.append(len(raw))
        return raw
    def boundary(value):reported.append(value['io']['actual_bytes']);raise primary
    monkeypatch.setattr(m.os,'read',reading);initial=budget.actual_bytes
    with pytest.raises(KeyboardInterrupt) as caught:
        m._read_submitted_files_as_owner(s['sources'].policy,document['launch'],budget,controls=document['controls'],
            technical_control=document['technical_control'],solver_logs=True,barrier=boundary)
    assert caught.value is primary and reported[0]>0
    assert budget.actual_bytes-initial==sum(transport)+reported[0]


def test_prepaid_owner_read_uses_held_file_size_before_read_not_unknown_leaf_ceiling(tmp_path,monkeypatch):
    m=module();path=tmp_path/'tiny-original';path.write_bytes(b'abc');budget=m.Operation(limits())
    budget.reserve(16)
    for _ in range(4):budget.file()
    budget._owner_read_credit=[16,4];read=m.os.read;sizes=[]
    def reading(fd,size):sizes.append(size);return read(fd,size)
    monkeypatch.setattr(m.os,'read',reading)
    fd=os.open(path,os.O_RDONLY)
    try:raw,_=m.read_fd(fd,65536,budget)
    finally:os.close(fd)
    assert raw==b'abc' and budget.actual_bytes==3 and budget.bytes==16
    assert sizes==[4,1] and budget._owner_read_credit==[11,3]


@pytest.mark.parametrize('fault',[None,'token','root','source','late','cancel'])
def test_actual_owned_held_metadata_inputs_share_w1_and_never_return_partial(q1_joined,monkeypatch,fault):
    s=q1_joined;m=s['m'];launch,inputs,raws=p20_metadata_profile();locator=json.loads(raws['capture-source.json'])
    info=s['result'].stat();locator['root_birth'].update(device=str(info.st_dev),inode=str(info.st_ino))
    if fault=='token':locator['capture_token']='b'*32
    if fault=='root':locator['actual_root']='/foreign/'+launch['relative_execution_root']
    raws['capture-source.json']=m.encoded(locator)
    for name in ('series_result.json','native-selection.json'):(s['result']/name).write_bytes(raws[name])
    for name in ('plan.json','source-graph.json','native-execution.json','capture-spec.json','capture-source.json'):
        (s['work']/name).write_bytes(raws[name])
    (s['work']/'_aiidasubmit.sh').write_bytes(b'fixed script fixture')
    for name in ('solver.stdout','solver.stderr'):(s['work']/name).write_bytes(b'closed log')
    if fault=='source':(s['work']/'source-graph.json').write_bytes(b'changed original')
    controls=[]
    for index,name in enumerate(m.CLOSE_FILES):
        raw=((s['result'] if index<2 else s['work'])/name).read_bytes()
        controls.append(dict(path=name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
    boundary=[];primary=KeyboardInterrupt('actual metadata W1 cancellation')
    def guard(value):
        boundary.append(True)
        assert value['binding']['selected_points']==1 and value['binding']['root_birth']['inode']==str(info.st_ino)
        if fault=='late':(s['work']/'capture-source.json').write_bytes(b'late writer')
        if fault=='cancel':raise primary
    def call():return m._read_submitted_files_as_owner(s['sources'].policy,launch,s['sources'].budget,controls=controls,
        technical_control=dict(status='absent',path=m.TECHNICAL_FILE,reason='not_published'),solver_logs=True,barrier=guard,native_inputs=inputs)
    if fault is None:
        value=call();assert value['binding']['selected_points']==1 and boundary==[True]
        assert set(row['path'] for row in value['files'])==set(m.CLOSE_FILES)|set(m.FILES.values())|{'capture-spec.json','capture-source.json','solver.stdout','solver.stderr'}
    else:
        with pytest.raises(KeyboardInterrupt if fault=='cancel' else m.Hold) as caught:call()
        if fault=='cancel':assert caught.value is primary
        assert boundary==([] if fault in ('token','root','source') else [True])


@pytest.mark.parametrize('kind',['memory','invariant','assertion','cancel','exit'])
@pytest.mark.parametrize('secondary_close',[False,True])
def test_delivered_native_child_fatal_class_survives_owned_cleanup(q1_joined,monkeypatch,kind,secondary_close):
    """Process identity cannot cross fork/JSON; delivered primary type/cause can."""
    s=q1_joined;m=s['m'];parent=os.getpid();close=m.os.close;failed={'metadata':False,'cleanup':False}
    cls={'memory':MemoryError,'invariant':RuntimeError,'assertion':AssertionError,'cancel':KeyboardInterrupt,'exit':SystemExit}[kind]
    primary=cls('original native metadata '+kind)
    def metadata(*args,**kwargs):failed['metadata']=True;raise primary
    def closing(fd):
        target=False
        if os.getpid()!=parent and failed['metadata'] and secondary_close and not failed['cleanup']:
            try:target=m.stat.S_ISREG(os.fstat(fd).st_mode)
            except OSError:pass
        close(fd)
        if target:failed['cleanup']=True;raise OSError('secondary held FD close')
    monkeypatch.setattr(m,'_completed_metadata',metadata);monkeypatch.setattr(m.os,'close',closing)
    with pytest.raises(cls,match='original native metadata') as caught:
        test_actual_owned_held_metadata_inputs_share_w1_and_never_return_partial(s,monkeypatch,None)
    assert type(caught.value) is cls and caught.value.__cause__.record['failure']==cls.__name__


@pytest.mark.parametrize('fault',[None,'guard','late_metadata','late_plan','cancel'])
def test_original_closed_bytes_requalify_through_actual_private_child_metadata(q1_joined,monkeypatch,fault):
    """Genuine Q1 close/read/fork/reclose code on declared synthetic metadata.
    OS/source authority is explicitly fixture-only, not native creator proof.
    """
    s=q1_joined;m=s['m'];source=s['sources'];launch,inputs,raws=p20_metadata_profile()
    native=json.loads(raws['native-execution.json']);native['storage']['storage_identity']='storage'
    raws['native-execution.json']=m.encoded(native)
    launch['files']['native_execution']=dict(bytes=len(raws['native-execution.json']),sha256=hashlib.sha256(raws['native-execution.json']).hexdigest())
    locator=json.loads(raws['capture-source.json']);root=s['result'].stat()
    locator['root_birth'].update(device=str(root.st_dev),inode=str(root.st_ino));raws['capture-source.json']=m.encoded(locator)
    for name,raw in raws.items():((s['result'] if name in m.CLOSE_FILES[:2] else s['work'])/name).write_bytes(raw)
    (s['work']/'_aiidasubmit.sh').write_bytes(b'fixed script fixture')
    for name in ('solver.stdout','solver.stderr'):(s['work']/name).write_bytes(b'closed logger')
    controls=[]
    for i,name in enumerate(m.CLOSE_FILES):
        raw=((s['result'] if i<2 else s['work'])/name).read_bytes()
        controls.append(dict(path=name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
    document=dict(version=3,action='close',calcjob_uuid=inputs['calcjob_uuid'],launch=launch,controls=controls,
        technical_control=dict(status='absent',path=m.TECHNICAL_FILE,reason='not_published'))
    observed=source.worker(s['job'],document['calcjob_uuid'],'close',source.budget)
    original=s['owner']._close(document,s['job'],s['host'],observed,controls)
    assert original['state']=='closed'
    journal=s['store'].path(document['calcjob_uuid']);before={p.name:p.read_bytes() for p in journal.iterdir()}
    worker=p20_worker();controller=dict(identity=dict(machine_id=s['host']['machine_id'],boot_id=s['host']['boot_id'],
        kernel='synthetic-kernel',dmi_uuid='33333333-3333-4333-8333-333333333333'),units=[p20_unit('qcl-negf-aiida.service'),p20_unit('qcl-negf-api.service')])
    full=dict(controller=controller,workers=[worker]);gsha=hashlib.sha256(m.encoded(full)).hexdigest()
    source.qualification['completed_final']=dict(runner=inputs['runner'],unit_generation_sha256=gsha,worker_generations={'node-a':worker})
    raw=('JobId=42 UserId=qcl-negf(3000) JobState=COMPLETED ExitCode=0:0 NumNodes=1 NumTasks=1 '
        'NodeList=node-a SubmitTime=2026-10-30T01:00:00 StartTime=2026-10-30T01:00:01 Restarts=0 MinMemoryNode=512M Comment='+s['job']['dispatch_id'])
    native_job=__import__('host_resource_facts').parse_slurm_jobs(raw,cluster='cluster')['42']
    packet=copy.deepcopy(s['packet']);packet.update(before=None,after=None,job=dict(raw=raw,fields=dict(m.re.findall(r'(?<!\S)(\w+)=([^\s]+)',raw))))
    identity=packet['identity']['identity'];packet['writer_snapshot'].update(identity_before=identity,identity_after=identity,
        jobs={'42':native_job},groups={'42':dict(populated=False,processes=[])})
    old_writers=source.close_writers
    def writers(*args):
        # Real close reuses existing W1 validation; its native unit/RPC readers
        # are separately covered and represented here by fresh explicit rows.
        with monkeypatch.context() as patch:
            q=source.qualification;patch.setattr(source,'qualification',{k:v for k,v in q.items() if k!='completed_final'})
            value=old_writers(*args)
        value['output_generation']=full;return value
    monkeypatch.setattr(source,'close_writers',writers);monkeypatch.setattr(source,'worker',lambda *a:copy.deepcopy(packet))
    source.budget=m.Operation(source.policy['limits']);s['owner'].budget=source.budget
    actual_read=source.budget.read
    monkeypatch.setattr(source.budget,'read',lambda path,limit=65536:b'1 0 0:1 / /srv/qcl-negf/jobs/native ro - nfs4 storage:/jobs rw\n'
        if str(path).endswith('/mountinfo') else actual_read(path,limit))
    calls=[];primary=KeyboardInterrupt('original metadata cancellation')
    def guard():
        calls.append(True)
        if len(calls)>1:
            if fault=='guard':raise m.Hold('facts_entry_changed')
            if fault=='late_metadata':(s['work']/'capture-source.json').write_bytes(b'late writer')
            if fault=='late_plan':(s['work']/'plan.json').write_bytes(b'late original plan')
            if fault=='cancel':raise primary
    monkeypatch.setattr(s['store'],'put',lambda *a:pytest.fail('facts wrote journal'))
    def call():return s['owner']._close(document,s['job'],s['host'],packet,controls,facts_guard=guard,facts_inputs=inputs)
    if fault is None:
        proof=call();assert proof['original_close'][1]==before['close.json']
        assert proof['original_observation'][1]==before['close-observation.json']
        assert proof['control_read']['binding']['storage_identity']=='storage'
        assert proof['control_read']['binding']['selected_points']==1
    else:
        with pytest.raises(KeyboardInterrupt if fault=='cancel' else m.Hold) as caught:call()
        if fault=='cancel':assert caught.value is primary
    assert {p.name:p.read_bytes() for p in journal.iterdir()}==before


def q1t_document(state, raw=b'{"original":"technical index bytes"}\n'):
    document={**state['document'],'version':3,'action':'close','controls':copy.deepcopy(state['controls'])}
    if raw is None:
        document['technical_control']={'status':'absent','path':'performance-source.json','reason':'not_published'}
    else:
        path=state['result']/'performance-source.json';path.write_bytes(raw);path.chmod(0o640)
        document['technical_control']={'status':'present','path':'performance-source.json',
            'bytes':str(len(raw)),'sha256':hashlib.sha256(raw).hexdigest()}
    return document


@pytest.mark.parametrize('fault',[None,'controller_unit','storage','worker_identity','nonzero','running','cancel','entry_drift','epilog'])
def test_existing_close_can_be_requalified_with_status_only_w1_and_no_put(q1_joined,monkeypatch,fault):
    """Private Source/L owner seam, never production facts caller authority."""
    s=q1_joined;m=s['m'];document=q1t_document(s,None)
    original=s['owner'].qualify_close(document);assert original['state']=='closed'
    directory=s['store'].path(document['calcjob_uuid'])
    original_bytes={p.name:p.read_bytes() for p in directory.iterdir() if p.is_file()}
    for name in ('solver.stdout','solver.stderr'):(s['work']/name).write_bytes(b'closed logger')
    raw=('JobId=42 UserId=qcl-negf(3000) JobState=COMPLETED ExitCode=0:0 NumNodes=1 NumTasks=1 '
         'NodeList=node-a SubmitTime=2026-10-30T01:00:00 StartTime=2026-10-30T01:00:01 Restarts=0 '
         'MinMemoryNode=512M ArrayJobId=0 HetJobId=0 Comment='+s['job']['dispatch_id'])
    s['packet'].update(before=None,after=None)
    s['packet']['job']={'raw':raw,'fields':dict(m.re.findall(r'(?<!\S)(\w+)=([^\s]+)',raw))}
    s['packet']['job']['fields']['Comment']=s['job']['dispatch_id']
    if fault=='nonzero':s['packet']['job']['fields']['ExitCode']='1:0'
    if fault=='running':s['packet']['job']['fields']['JobState']='RUNNING'
    if fault=='epilog':s['packet']['epilog_ref']=None
    source=s['sources'];source.budget=m.Operation(source.policy['limits']);s['owner'].budget=source.budget
    actual_read=source.budget.read
    monkeypatch.setattr(source.budget,'read',lambda path,limit=65536:
        b'1 0 0:1 / /srv/qcl-negf/jobs/native ro - nfs4 storage:/jobs rw\n'
        if str(path).endswith('/mountinfo') else actual_read(path,limit))
    phases=[];worker=source.worker;writers=source.close_writers;captures=[];guards=[]
    def status(job,calcjob,phase,budget):
        phases.append(phase);assert phase=='status'
        return worker(job,calcjob,phase,budget)
    def closed_writers(*args):
        row=writers(*args);captures.append(True)
        if len(captures)>1:
            if fault=='controller_unit':row['controller_units'][0]['state']['InvocationID']='e'*32
            if fault=='storage':row['storage_identity']='other-storage'
            if fault=='worker_identity':row['workers'][0]['reply']['identity']['identity']['boot_id']='22222222-2222-4222-8222-222222222222'
        return row
    def guard():
        guards.append(True)
        if len(guards)>1:
            if fault=='cancel':raise KeyboardInterrupt('actual facts cancellation')
            if fault=='entry_drift':raise m.Hold('facts_entry_changed')
    monkeypatch.setattr(source,'worker',status);monkeypatch.setattr(source,'close_writers',closed_writers)
    monkeypatch.setattr(source,'_refresh_caller',lambda *a:pytest.fail('facts must not impersonate daemon caller'))
    monkeypatch.setattr(m,'_authenticate_server',lambda *a:pytest.fail('facts must not impersonate server unit'))
    monkeypatch.setattr(s['store'],'put',lambda *a:pytest.fail('facts must never write close/worker records'))
    def read():return s['owner']._close(document,s['job'],s['host'],copy.deepcopy(s['packet']),s['controls'],facts_guard=guard)
    if fault is None:
        value=read();assert value['control_read']['controls']==s['controls'] and len(value['control_read']['logs'])==2
        assert value['original_close'][1]==original_bytes['close.json']
        assert value['original_observation'][1]==original_bytes['close-observation.json']
        assert value['current_worker']['before'] is value['current_worker']['after'] is None
        assert len(guards)>=3 and captures==[True,True] and phases==['status']
    else:
        with pytest.raises(KeyboardInterrupt if fault=='cancel' else m.Hold):read()
    assert {p.name:p.read_bytes() for p in directory.iterdir() if p.is_file()}==original_bytes


@pytest.mark.parametrize('raw',[None,b'',b'{"original":"technical index bytes"}\n'])
def test_q1t_v3_closes_only_observed_present_whole_bytes_or_actual_absence(q1_joined,raw):
    s=q1_joined;m=s['m'];document=q1t_document(s,raw)
    closed=s['owner'].qualify_close(document)
    assert closed['state']=='closed' and closed['version']==3
    assert set(closed)=={'version','state','calcjob_uuid','receipt_ref','job','controls','technical_control','reason'}
    assert closed['technical_control']==document['technical_control'] and closed['controls']==s['controls']
    assert m.validate_reply(closed)==closed
    directory=s['store'].path(document['calcjob_uuid']);receipt=(directory/'close.json').read_bytes()
    witness=json.loads((directory/'close-observation.json').read_bytes())
    assert witness['control_read']['technical_control']==document['technical_control']
    assert witness['control_read']['io']['actual_bytes']==sum(c['bytes'] for c in s['controls'])+(0 if raw is None else len(raw))
    assert witness['reply_sha256']==hashlib.sha256(receipt).hexdigest()
    assert [r['root'] for r in witness['control_read']['files'] if r['path']=='performance-source.json']==([] if raw is None else ['result'])


@pytest.mark.parametrize('kind',['invariant','fatal','cancel'])
def test_close_record_read_preserves_primary_when_its_fd_close_also_fails(q1_joined,monkeypatch,kind):
    s=q1_joined;m=s['m'];document=q1t_document(s,None)
    assert s['owner'].qualify_close(document)['state']=='closed'
    primary={'invariant':RuntimeError('original invariant'),
        'fatal':MemoryError('original allocation'),'cancel':KeyboardInterrupt('original cancellation')}[kind]
    read=m.read_fd;close=m.os.close;target=set()
    def reading(fd,limit,budget):
        if os.readlink('/proc/self/fd/'+str(fd)).endswith('/close.json'):
            target.add(fd);raise primary
        return read(fd,limit,budget)
    def closing(fd):
        close(fd)
        if fd in target:target.remove(fd);raise OSError('secondary original-record close failure')
    monkeypatch.setattr(m,'read_fd',reading);monkeypatch.setattr(m.os,'close',closing)
    with pytest.raises(type(primary)) as caught:
        m._read_close_record(s['store'],document['calcjob_uuid'],m.Operation(s['sources'].policy['limits']))
    assert caught.value is primary and any('close' in note for note in primary.__notes__)
    assert not target


@pytest.mark.parametrize('mutate',[
    lambda r:r.update(version=2),
    lambda r:r.update(version=True),
    lambda r:r.update(action='status',controls=None),
    lambda r:r['technical_control'].update(path='../performance-source.json'),
    lambda r:r['technical_control'].update(bytes=1),
    lambda r:r['technical_control'].update(bytes='01'),
    lambda r:r['technical_control'].update(bytes='1048577'),
    lambda r:r['technical_control'].update(bytes='18446744073709551616'),
    lambda r:r['technical_control'].update(verified=True),
    lambda r:r.update(technical_control={'status':'absent','path':'performance-source.json','reason':'zero'}),
    lambda r:r.update(technical_control=None),
    lambda r:r['controls'].reverse(),
])
def test_q1t_bad_wire_is_rejected_before_preflight_lock_or_durable_effects(tmp_path,monkeypatch,mutate):
    m=module();first,_=owner(tmp_path)
    document=request('close');document.update(version=3,
        controls=[dict(path=name,bytes=0,sha256='0'*64) for name in
            ('series_result.json','native-selection.json','_scheduler-stdout.txt','_scheduler-stderr.txt')],
        technical_control=dict(status='present',path='performance-source.json',bytes='1',sha256='0'*64))
    mutate(document)
    monkeypatch.setattr(first.sources,'preflight',lambda *a,**kw:pytest.fail('invalid wire reached preflight'))
    result=first.qualify_close(document)
    assert result['state']=='rejected' and not list(tmp_path.iterdir())


@pytest.mark.parametrize('valid',[True,False])
def test_q1t_socket_failure_preserves_v3_shape_only_after_valid_request(monkeypatch,valid):
    m=module();document=request('close');document.update(version=3,
        controls=[dict(path=name,bytes=0,sha256='0'*64) for name in
            ('series_result.json','native-selection.json','_scheduler-stdout.txt','_scheduler-stderr.txt')],
        technical_control=dict(status='absent',path='performance-source.json',reason='not_published'))
    if not valid:document['version']=2
    sources=type('SocketSources',(),{'qualify':lambda self:None})()
    monkeypatch.setattr(m,'_load_policy',lambda *a:{'limits':limits()})
    monkeypatch.setattr(m,'NativeSources',lambda *a:sources)
    monkeypatch.setattr(m,'_authenticate_server',lambda *a:None)
    monkeypatch.setattr(m,'read_frame',lambda *a:document)
    def peer(*args,**kwargs):raise m.Hold('peer_origin')
    monkeypatch.setattr(m,'authenticate_socket_peer',peer)
    captured=[];monkeypatch.setattr(m,'write_frame',lambda connection,result,*a:captured.append(result))
    m.handle_connection(object());result=captured[0]
    assert result['version']==(3 if valid else 1)
    assert result['state']==('hold' if valid else 'rejected')
    if valid:assert result['technical_control'] is None and result['controls'] is None


@pytest.mark.parametrize('version,state',[(True,'rejected'),(1.0,'rejected'),(False,'rejected'),
    (2.0,'rejected'),(3,'rejected'),('1','rejected'),(1,'hold')])
def test_q1t_server_classifies_only_integer_v1_as_legacy_before_authentication(monkeypatch,version,state):
    m=module();document=request('close');document['version']=version
    sources=type('SocketSources',(),{'qualify':lambda self:None})()
    monkeypatch.setattr(m,'_load_policy',lambda *a:{'limits':limits()})
    monkeypatch.setattr(m,'NativeSources',lambda *a:sources)
    monkeypatch.setattr(m,'_authenticate_server',lambda *a:None)
    monkeypatch.setattr(m,'read_frame',lambda *a:document)
    monkeypatch.setattr(m,'authenticate_socket_peer',lambda *a,**kw:pytest.fail('invalid request reached authentication'))
    monkeypatch.setattr(m,'AttemptStore',lambda *a:pytest.fail('invalid request reached durable store'))
    captured=[];monkeypatch.setattr(m,'write_frame',lambda connection,result,*a:captured.append(result))
    m.handle_connection(object());result=captured[0]
    assert result=={'version':1,'state':state,'calcjob_uuid':None,'receipt_ref':None,
        'job':None,'controls':None,'reason':'shape'}


@pytest.mark.parametrize('version',[1,3])
@pytest.mark.parametrize('fault',['namespace','connect','response_frame'])
def test_q1t_client_main_transport_errors_preserve_only_validated_v3_context(monkeypatch,capsys,version,fault):
    import io
    from contextlib import contextmanager
    m=module();document=request('close')
    document['controls']=[dict(path=name,bytes=0,sha256='0'*64) for name in
        ('series_result.json','native-selection.json','_scheduler-stdout.txt','_scheduler-stderr.txt')]
    if version==3:
        document.update(version=3,technical_control=dict(status='absent',path='performance-source.json',reason='not_published'))
    raw=m.encoded(document);stdin=io.BytesIO(raw);calls=[]
    monkeypatch.setattr(m.sys,'argv',['client','close'])
    monkeypatch.setattr(m.sys,'stdin',type('Input',(),{'buffer':stdin})())
    @contextmanager
    def directory(*args,**kw):
        if fault=='namespace':calls.append('namespace');raise OSError('primary synthetic namespace failure')
        yield 999
    class Connection:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def settimeout(self,value):pass
        def connect(self,path):
            calls.append('connect')
            if fault=='connect':raise OSError('primary synthetic connect failure')
        def shutdown(self,how):pass
        def getsockopt(self,*args):return struct.pack('3i',1,0,0)
    info=os.stat_result((m.stat.S_IFSOCK|0o660,1,1,1,0,3000,0,1,1,1))
    monkeypatch.setattr(m,'protected_directory',directory)
    monkeypatch.setattr(m.os,'stat',lambda *a,**kw:info)
    monkeypatch.setattr(m.socket,'socket',lambda *a:Connection())
    monkeypatch.setattr(m,'write_frame',lambda *a:None)
    def failed_frame(*args):calls.append('response_frame');raise m.Hold('frame_bound')
    monkeypatch.setattr(m,'read_frame',failed_frame)
    assert m.client_main()==75
    output=capsys.readouterr().out;result=json.loads(output)
    expected={'version':version,'state':'hold','calcjob_uuid':document['calcjob_uuid'] if version==3 else None,
        'receipt_ref':None,'job':None,'controls':None,
        'reason':'frame_bound' if fault=='response_frame' else 'transport_outcome_unknown'}
    if version==3:expected['technical_control']=None
    assert result==expected and output.encode()==m.encoded(expected)+b'\n'
    assert stdin.tell()==len(raw) and calls==({'namespace':['namespace'],'connect':['connect'],
        'response_frame':['connect','response_frame']}[fault])


@pytest.mark.parametrize('raw',[b'{',b'\xff',b'{"version":2,"version":2}',
    b'{"version":true}',b'{"version":1.0}',b'{"version":2.0}',b'{"version":3}'])
def test_q1t_client_main_early_invalid_parse_never_gains_v3_context_or_transport(monkeypatch,capsys,raw):
    import io
    m=module();monkeypatch.setattr(m.sys,'argv',['client','close'])
    monkeypatch.setattr(m.sys,'stdin',type('Input',(),{'buffer':io.BytesIO(raw)})())
    monkeypatch.setattr(m,'protected_directory',lambda *a,**kw:pytest.fail('invalid input reached transport'))
    assert m.client_main()==75
    result=json.loads(capsys.readouterr().out)
    assert set(result)=={'version','state','calcjob_uuid','receipt_ref','job','controls','reason'}
    assert result['version']==1 and result['state']=='hold' and result['calcjob_uuid'] is None and result['controls'] is None


@pytest.mark.parametrize('fault',['hash','missing','unexpected_present','symlink','hardlink','writable','oversize','owner','ancestor'])
def test_q1t_technical_foreign_or_changed_file_never_publishes_receipt(q1_joined,monkeypatch,fault):
    s=q1_joined;m=s['m'];document=q1t_document(s);path=s['result']/'performance-source.json'
    if fault=='hash':document['technical_control']['sha256']='0'*64
    if fault=='missing':path.unlink()
    if fault=='unexpected_present':document['technical_control']={'status':'absent','path':'performance-source.json','reason':'not_published'}
    if fault=='symlink':path.rename(path.with_name('original'));path.symlink_to('original')
    if fault=='hardlink':os.link(path,path.with_name('alias'))
    if fault=='writable':path.chmod(0o666)
    if fault=='oversize':path.write_bytes(b'x'*1048577)
    inode=path.stat().st_ino if fault in ('owner','ancestor') else None;fstat=m.os.fstat;read=m.read_fd
    if fault=='owner':
        def info(fd):
            result=fstat(fd)
            if result.st_ino==inode:
                values=list(result);values[4]=os.getuid()+1;return os.stat_result(values)
            return result
        monkeypatch.setattr(m.os,'fstat',info)
    if fault=='ancestor':
        def reading(fd,limit,budget):
            result=read(fd,limit,budget)
            if fstat(fd).st_ino==inode:
                s['result'].rename(s['result'].with_name('retained'));s['result'].mkdir()
            return result
        monkeypatch.setattr(m,'read_fd',reading)
    result=s['owner'].qualify_close(document)
    assert result['version']==3 and result['state']=='hold' and result['technical_control'] is None
    assert result['controls'] is None and not (s['store'].path(document['calcjob_uuid'])/'close.json').exists()


@pytest.mark.parametrize('fault',['replace','tamper','absent_published','late_writer'])
def test_q1t_late_file_or_writer_change_cannot_certify_technical_context(q1_joined,monkeypatch,fault):
    s=q1_joined;m=s['m'];document=q1t_document(s,None if fault=='absent_published' else b'original')
    path=s['result']/'performance-source.json';read=m.read_fd;stat=m.os.stat
    if fault=='absent_published':
        def stat_path(name,*args,**kw):
            if name=='performance-source.json':
                path.write_bytes(b'late');path.chmod(0o640)
                raise FileNotFoundError('leaf was absent before late publish')
            return stat(name,*args,**kw)
        monkeypatch.setattr(m.os,'stat',stat_path)
    elif fault in ('replace','tamper'):
        inode=path.stat().st_ino
        def reading(fd,limit,budget):
            value=read(fd,limit,budget)
            if os.fstat(fd).st_ino==inode:
                if fault=='replace':path.unlink()
                path.write_bytes(value[0] if fault=='replace' else b'tampered');path.chmod(0o640)
            return value
        monkeypatch.setattr(m,'read_fd',reading)
    else:
        reader=m._read_submitted_files_as_owner
        def reading_owner(*args,**kwargs):
            value=reader(*args,**kwargs)
            if kwargs.get('technical_control') is not None:
                s['packet']['writer_snapshot']['jobs']['99']=dict(owner_uid=3000,submit_time='foreign',terminal=False)
            return value
        monkeypatch.setattr(m,'_read_submitted_files_as_owner',reading_owner)
    result=s['owner'].qualify_close(document)
    assert result['state']=='hold' and result['technical_control'] is None
    assert not (s['store'].path(document['calcjob_uuid'])/'close.json').exists()


@pytest.mark.parametrize('first_version,second_version,changed',[(3,3,False),(3,3,True),(1,3,False),(3,1,False)])
def test_q1t_retry_preserves_exact_receipts_and_never_relabels_v1(q1_joined,first_version,second_version,changed):
    s=q1_joined;m=s['m'];document=q1t_document(s)
    if first_version==1:document.pop('technical_control');document['version']=1
    closed=s['owner'].qualify_close(document);assert closed['state']=='closed'
    directory=s['store'].path(document['calcjob_uuid'])
    before={name:(directory/name).read_bytes() for name in ('close.json','close-observation.json')}
    document=q1t_document(s,b'changed' if changed else b'{"original":"technical index bytes"}\n')
    if second_version==1:document.pop('technical_control');document['version']=1
    source=copy.copy(s['sources']);source.budget=m.Operation(source.policy['limits']);source.budget.read=s['sources'].budget.read
    result=m.OrdinaryAttemptOwner(source.policy,s['store'],source,source.budget).qualify_close(document)
    if first_version==second_version and not changed:assert result==closed
    else:assert result['state']=='hold' and result['reason']=='q1_close_conflict'
    assert {name:(directory/name).read_bytes() for name in before}==before


def test_q1t_cleanup_uncertainty_retains_primary_failure_and_no_close(q1_joined,monkeypatch):
    s=q1_joined;m=s['m'];document=q1t_document(s)
    primary=dict(failure='timeout',stdout='original W1 prefix',cleanup_confirmed=False)
    def failed(*args):raise m.engine.CommandFailure(primary)
    monkeypatch.setattr(s['sources'],'close_writers',failed)
    result=s['owner'].qualify_close(document)
    assert result['state']=='hold' and result['technical_control'] is None
    directory=s['store'].path(document['calcjob_uuid']);failures=list(directory.glob('observation-failure-*.json'))
    import base64
    assert len(failures)==1 and json.loads(base64.b64decode(json.loads(failures[0].read_bytes())['original_prefix_base64']))==primary
    assert not (directory/'close.json').exists() and not (directory/'close-observation.json').exists()


def test_q1t_partial_publication_is_not_repaired_or_overwritten(q1_joined,monkeypatch):
    s=q1_joined;m=s['m'];document=q1t_document(s);put=s['store'].put
    def failed(calcjob,name,value,budget):
        put(calcjob,name,value,budget)
        if name=='close-observation.json':raise OSError('original v3 publication uncertainty')
    monkeypatch.setattr(s['store'],'put',failed)
    result=s['owner'].qualify_close(document)
    assert result['state']=='hold' and result['technical_control'] is None
    directory=s['store'].path(document['calcjob_uuid']);original=(directory/'close-observation.json').read_bytes()
    monkeypatch.setattr(s['store'],'put',put)
    monkeypatch.setattr(m.os,'fork',lambda:pytest.fail('partial publication must not reread'))
    result=s['owner'].qualify_close(document)
    assert result['state']=='hold' and result['reason']=='q1_close_publication_unknown'
    assert (directory/'close-observation.json').read_bytes()==original and not (directory/'close.json').exists()


@pytest.mark.parametrize('reply_version',[1,2,3])
def test_q1t_fixed_client_requires_exact_v3_reply_without_v1_fallback(q1_joined,monkeypatch,capsys,reply_version):
    import io
    from contextlib import contextmanager
    s=q1_joined;m=s['m'];document=q1t_document(s)
    result=s['owner'].qualify_close(document);assert result['state']=='closed'
    if reply_version!=3:
        if reply_version==1:result.pop('technical_control')
        result['version']=reply_version
    @contextmanager
    def directory(*args,**kwargs):yield 999
    class Connection:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def settimeout(self,value):pass
        def connect(self,path):assert path=='/run/qcl-negf/native-attempt.sock'
        def shutdown(self,how):pass
        def getsockopt(self,*args):return struct.pack('3i',1,0,0)
    info=os.stat_result((m.stat.S_IFSOCK|0o660,1,1,1,0,3000,0,1,1,1))
    monkeypatch.setattr(m,'protected_directory',directory)
    monkeypatch.setattr(m.os,'stat',lambda *args,**kw:info)
    monkeypatch.setattr(m.socket,'socket',lambda *args:Connection())
    monkeypatch.setattr(m.sys,'argv',['client','close'])
    monkeypatch.setattr(m.sys,'stdin',type('Input',(),{'buffer':io.BytesIO(m.encoded(document))})())
    monkeypatch.setattr(m,'write_frame',lambda connection,value,*args:None)
    monkeypatch.setattr(m,'read_frame',lambda *args:result)
    if reply_version!=3:
        with pytest.raises(m.Hold,match='reply_shape' if reply_version==2 else 'reply_version'):m._client_operation()
        assert capsys.readouterr().out==''
    else:
        assert m._client_operation()==0
        assert capsys.readouterr().out.encode()==m.encoded(result)+b'\n'


@pytest.mark.parametrize('delta',[-1,0])
def test_q1t_technical_cap_keeps_original_full_byte_hash_with_sufficient_existing_credit(q1_joined,delta):
    s=q1_joined;m=s['m'];raw=b'x'*(1048576+delta);document=q1t_document(s,raw)
    source=s['sources'];source.policy['limits']['metadata_bytes']=32*1024*1024
    budget=m.Operation(source.policy['limits']);budget.read=source.budget.read;source.budget=budget
    result=m.OrdinaryAttemptOwner(source.policy,s['store'],source,budget).qualify_close(document)
    assert result['state']=='closed' and result['technical_control']==document['technical_control']


def test_q1t_technical_budget_is_charged_before_any_child_or_payload_open(monkeypatch):
    m=module();budget=m.Operation({**limits(),'maximum_files':2048})
    policy=dict(limits=budget.limits,jobs_root='/srv/qcl-negf/jobs')
    controls=[dict(path=name,bytes=0,sha256='0'*64) for name in
        ('series_result.json','native-selection.json','_scheduler-stdout.txt','_scheduler-stderr.txt')]
    technical=dict(status='present',path='performance-source.json',bytes='1048576',sha256='0'*64)
    monkeypatch.setattr(m.os,'geteuid',lambda:0)
    def forbidden(*args):pytest.fail('aggregate refusal must precede pipe/fork/payload open')
    monkeypatch.setattr(m.os,'pipe2',forbidden);monkeypatch.setattr(m.os,'fork',forbidden)
    with pytest.raises(m.Hold,match='operation_bound'):
        m._read_submitted_files_as_owner(policy,request()['launch'],budget,controls=controls,technical_control=technical)
    assert budget.bytes>budget.limits['metadata_bytes']


def test_q1t_additional_leaf_file_credit_is_charged_before_fork(monkeypatch):
    m=module();budget=m.Operation({**limits(),'maximum_files':152})
    policy=dict(limits=budget.limits,jobs_root='/srv/qcl-negf/jobs')
    controls=[dict(path=name,bytes=0,sha256='0'*64) for name in
        ('series_result.json','native-selection.json','_scheduler-stdout.txt','_scheduler-stderr.txt')]
    technical=dict(status='absent',path='performance-source.json',reason='not_published')
    monkeypatch.setattr(m.os,'geteuid',lambda:0)
    def forbidden(*args):pytest.fail('technical file debit must precede pipe/fork')
    monkeypatch.setattr(m.os,'pipe2',forbidden);monkeypatch.setattr(m.os,'fork',forbidden)
    with pytest.raises(m.Hold,match='operation_file_bound'):
        m._read_submitted_files_as_owner(policy,request()['launch'],budget,controls=controls,technical_control=technical)
    assert budget.files>152


def test_q1t_absence_retry_and_later_publication_preserve_original_absent_receipt(q1_joined):
    s=q1_joined;m=s['m'];document=q1t_document(s,None)
    first=s['owner'].qualify_close(document);assert first['state']=='closed'
    directory=s['store'].path(document['calcjob_uuid']);original=(directory/'close.json').read_bytes()
    for publish in (False,True):
        source=copy.copy(s['sources']);source.budget=m.Operation(source.policy['limits']);source.budget.read=s['sources'].budget.read
        if publish:q1t_document(s,b'late index')
        result=m.OrdinaryAttemptOwner(source.policy,s['store'],source,source.budget).qualify_close(document)
        if publish:assert result['state']=='hold' and result['technical_control'] is None
        else:assert result==first
        assert (directory/'close.json').read_bytes()==original


@pytest.mark.parametrize('mutate',[
    lambda r:r.update(version=True),
    lambda r:r.update(version=1),
    lambda r:r.update(state='bound'),
    lambda r:r.update(technical_control=None),
    lambda r:r['technical_control'].update(bytes=0),
    lambda r:r['technical_control'].update(bytes='00'),
    lambda r:r['technical_control'].update(path='/performance-source.json'),
    lambda r:r['technical_control'].update(extra=True),
    lambda r:r.update(technical_control={'status':'absent','path':'performance-source.json','reason':'not_published','bytes':'0'}),
    lambda r:r['controls'].reverse(),
])
def test_q1t_reply_rejects_malformed_or_v1_relabelled_technical_authority(q1_joined,mutate):
    s=q1_joined;m=s['m'];document=q1t_document(s,b'')
    result=s['owner'].qualify_close(document);assert result['state']=='closed'
    mutate(result)
    with pytest.raises(m.Hold):m.validate_reply(result)


def test_q1_actual_owner_w1_credential_fd_store_and_lost_close_ack(q1_joined):
    s=q1_joined;m=s['m'];document={**s['document'],'action':'close','controls':s['controls']}
    closed=s['owner'].qualify_close(document)
    assert closed['state']=='closed' and closed['controls']==s['controls'] and closed['job']==s['job']
    directory=s['store'].path(document['calcjob_uuid']);raw=(directory/'close.json').read_bytes()
    witness=(directory/'close-observation.json').read_bytes()
    assert raw==m.encoded(closed) and not raw.endswith(b'\n')
    retained=json.loads(witness);assert retained['reply_sha256']==hashlib.sha256(raw).hexdigest()
    assert retained['control_read']['controls']==s['controls'] and len(retained['control_read']['files'])==4
    assert retained['control_read']['io']['actual_bytes']==sum(row['bytes'] for row in s['controls'])
    source=copy.copy(s['sources']);source.budget=m.Operation(source.policy['limits'])
    source.budget.read=s['sources'].budget.read  # immutable fixture OS observations, not budget credit
    again=m.OrdinaryAttemptOwner(source.policy,s['store'],source,source.budget).qualify_close(document)
    assert again==closed and (directory/'close.json').read_bytes()==raw and (directory/'close-observation.json').read_bytes()==witness
    assert not any('--parsable' in call[0] for call in s['calls'])


def test_q1_native_tuple_observations_compare_exact_encoded_bytes(q1_joined):
    s=q1_joined;s['context']['profile_origin']={'chain':[('/nix/profile',(1,2,3,0,0,1,1,1,1),None)]}
    closed=s['owner'].qualify_close({**s['document'],'action':'close','controls':s['controls']})
    assert closed['state']=='closed'


def test_q1_original_publication_error_and_partial_observation_survive(q1_joined,monkeypatch,capsys):
    import base64
    s=q1_joined;m=s['m'];put=s['store'].put;original=OSError('unique original close sync failure')
    def failed(calcjob,name,value,budget):
        put(calcjob,name,value,budget)
        if name=='close-observation.json':raise original
    monkeypatch.setattr(s['store'],'put',failed)
    reply=s['owner'].qualify_close({**s['document'],'action':'close','controls':s['controls']})
    assert reply['state']=='hold' and reply['job']==s['job']
    path=s['store'].path(s['document']['calcjob_uuid'])
    assert (path/'close-observation.json').is_file() and not (path/'close.json').exists()
    diagnostic=json.loads(capsys.readouterr().err.split('native-attempt preclaim HOLD: ',1)[1])
    assert b'unique original close sync failure' in base64.b64decode(diagnostic['original_prefix_base64'])


def test_q1_real_observation_fsync_error_and_repeat_never_repair(q1_joined,monkeypatch,capsys):
    import base64
    s=q1_joined;m=s['m'];fsync=m.os.fsync;document={**s['document'],'action':'close','controls':s['controls']}
    def sync(fd):
        if os.readlink('/proc/self/fd/'+str(fd)).endswith('/close-observation.json'):
            raise OSError('unique original observation fsync error')
        return fsync(fd)
    monkeypatch.setattr(m.os,'fsync',sync)
    assert s['owner'].qualify_close(document)['state']=='hold'
    directory=s['store'].path(document['calcjob_uuid']);original=(directory/'close-observation.json').read_bytes()
    diagnostic=json.loads(capsys.readouterr().err.split('native-attempt preclaim HOLD: ',1)[1])
    assert b'unique original observation fsync error' in base64.b64decode(diagnostic['original_prefix_base64'])
    monkeypatch.setattr(m.os,'fsync',fsync)
    source=copy.copy(s['sources']);source.budget=m.Operation(source.policy['limits']);source.budget.read=s['sources'].budget.read
    monkeypatch.setattr(m.os,'fork',lambda:pytest.fail('partial publication must not reread/repair'))
    result=m.OrdinaryAttemptOwner(source.policy,s['store'],source,source.budget).qualify_close(document)
    assert result['state']=='hold' and result['reason']=='q1_close_publication_unknown'
    assert (directory/'close-observation.json').read_bytes()==original and not (directory/'close.json').exists()


@pytest.mark.parametrize('fault',['mount_source','mount_switch','mount_root_switch','mount_malformed','writer_after','unit_after','worker_boot'])
def test_q1_after_read_changes_are_not_a_closed_access_pass(q1_joined,monkeypatch,fault):
    import host_resource_facts as facts
    s=q1_joined;m=s['m'];source=s['sources'];reader=m._read_submitted_files_as_owner;read=source.budget.read
    reached={'read':False};unit=source.unit
    def read_controls(*args,**kwargs):
        value=reader(*args,**kwargs)
        if kwargs.get('controls') is not None:reached['read']=True
        return value
    monkeypatch.setattr(m,'_read_submitted_files_as_owner',read_controls)
    def mount(path,limit=65536):
        raw=read(path,limit)
        if str(path).endswith('/mountinfo') and (fault=='mount_source' or fault=='mount_switch' and reached['read']):
            raw=raw.replace(b'storage:/jobs',b'foreign:/jobs')
        if str(path).endswith('/mountinfo') and fault=='mount_root_switch' and reached['read']:
            raw=raw.replace(b' / /srv',b' /foreign /srv')
        if str(path).endswith('/mountinfo') and fault=='mount_malformed':raw=b'broken - nfs4 storage:/jobs rw\n'
        return raw
    monkeypatch.setattr(source.budget,'read',mount)
    def state(name):
        value=unit(name)
        if fault=='unit_after' and reached['read'] and name=='qcl-negf-api.service':value['InvocationID']='e'*32
        return value
    monkeypatch.setattr(source,'unit',state)
    def rpc(*args,**kwargs):
        packet=copy.deepcopy(s['packet'])
        if reached['read'] and fault=='writer_after':
            packet['writer_snapshot']['jobs']['99']=dict(owner_uid=3000,submit_time='unknown',terminal=False)
        if reached['read'] and fault=='worker_boot':
            packet['identity']['identity']['boot_id']=s['document']['launch']['request_id']
            source.qualification['worker_bindings']['c'*32]['boot_id']=packet['identity']['identity']['boot_id']
        return packet
    monkeypatch.setattr(facts,'trusted_rpc',rpc)
    reply=s['owner'].qualify_close({**s['document'],'action':'close','controls':s['controls']})
    assert reply['state']=='hold' and reply['controls'] is None
    assert not (s['store'].path(s['document']['calcjob_uuid'])/'close.json').exists()


@pytest.mark.parametrize('fault',['bytes','files','deadline'])
def test_q1_gross_child_debit_refuses_before_fork(monkeypatch,fault):
    m=module();budget=m.Operation({**limits(),'maximum_files':2048})
    policy=dict(limits=budget.limits,jobs_root='/srv/qcl-negf/jobs')
    claims=[dict(path=name,bytes=0,sha256=hashlib.sha256(b'').hexdigest())
        for name in ('series_result.json','native-selection.json','_scheduler-stdout.txt','_scheduler-stderr.txt')]
    if fault=='bytes':budget.bytes=budget.limits['metadata_bytes']
    if fault=='files':budget.files=budget.limits['maximum_files']
    if fault=='deadline':budget.deadline=0
    before=(budget.bytes,budget.files,budget.deadline)
    monkeypatch.setattr(m.os,'geteuid',lambda:0)
    def forbidden(*args):raise AssertionError('budget refusal must precede pipes/fork/NFS')
    monkeypatch.setattr(m.os,'pipe2',forbidden);monkeypatch.setattr(m.os,'fork',forbidden)
    with pytest.raises(m.Hold):m._read_submitted_files_as_owner(policy,request()['launch'],budget,controls=claims)
    assert budget.bytes>=before[0] and budget.files>=before[1] and budget.deadline==before[2]


@pytest.mark.parametrize('fault',['whitespace','observation_only','close_conflict','oversized','qualification'])
def test_q1_journal_partial_conflict_and_current_access_remain_hold(q1_joined,monkeypatch,fault):
    s=q1_joined;m=s['m'];document={**s['document'],'action':'close','controls':s['controls']}
    directory=s['store'].path(document['calcjob_uuid']);put=s['store'].put
    if fault in ('whitespace','observation_only'):
        def writing(calcjob,name,value,budget):
            put(calcjob,name,value,budget)
            if name=='close-observation.json':
                if fault=='whitespace':
                    with (directory/name).open('ab') as stream:stream.write(b' ')
                else:raise OSError('retained partial publication')
        monkeypatch.setattr(s['store'],'put',writing)
    if fault=='oversized':s['context']['bounded_raw_observation']='x'*70000
    if fault in ('close_conflict','qualification'):
        assert s['owner'].qualify_close(document)['state']=='closed'
        original=(directory/'close.json').read_bytes()
        source=copy.copy(s['sources']);source.budget=m.Operation(source.policy['limits']);source.budget.read=s['sources'].budget.read
        if fault=='close_conflict':
            value=json.loads(original);value['job']['submit_time']='foreign'
            (directory/'close.json').write_bytes(m.encoded(value));original=(directory/'close.json').read_bytes()
        else:
            def unavailable():raise m.Hold('native_qualification_missing')
            monkeypatch.setattr(source,'qualify',unavailable)
        s['owner']=m.OrdinaryAttemptOwner(source.policy,s['store'],source,source.budget)
    result=s['owner'].qualify_close(document)
    assert result['state']=='hold' and result['controls'] is None
    if fault in ('close_conflict','qualification'):assert (directory/'close.json').read_bytes()==original
    else:assert not (directory/'close.json').exists()


@pytest.mark.parametrize('fault',['hash','symlink','hardlink','writable','missing','order','extra','allocation','before','after','new_writer'])
def test_q1_close_negatives_never_publish_closed(q1_joined,fault):
    s=q1_joined;document={**s['document'],'action':'close','controls':copy.deepcopy(s['controls'])}
    if fault=='hash':document['controls'][0]['sha256']='0'*64
    if fault=='symlink':
        path=s['result']/'series_result.json';path.rename(s['result']/'original');path.symlink_to('original')
    if fault=='hardlink':os.link(s['result']/'series_result.json',s['result']/'alias')
    if fault=='writable':(s['result']/'series_result.json').chmod(0o666)
    if fault=='missing':(s['work']/'_scheduler-stderr.txt').unlink()
    if fault=='order':document['controls'].reverse()
    if fault=='extra':document['controls'].append(dict(path='native-close.json',bytes=0,sha256='0'*64))
    if fault=='allocation':(s['store'].path(document['calcjob_uuid'])/'allocation.json').unlink()
    if fault in ('before','after'):s['packet'][fault]=None
    if fault=='new_writer':s['packet']['writer_snapshot']['jobs']['99']=dict(owner_uid=3000,submit_time='foreign',terminal=False)
    reply=s['owner'].qualify_close(document)
    assert reply['state'] in ('hold','rejected') and reply['controls'] is None
    assert not (s['store'].path(document['calcjob_uuid'])/'close.json').exists()


@pytest.mark.parametrize('fault',['named_file','shrink','ancestor','directory_mode','file_owner'])
def test_q1_same_open_file_and_ancestor_replacements_hold(q1_joined,monkeypatch,fault):
    s=q1_joined;m=s['m'];read=m.read_fd;target=s['result']/'series_result.json'
    inode=target.stat().st_ino;fstat=m.os.fstat
    def reading(fd,limit,budget):
        value=read(fd,limit,budget)
        if fstat(fd).st_ino==inode:
            if fault=='named_file':
                target.unlink();target.write_bytes(value[0]);target.chmod(0o640)
            if fault=='shrink':target.write_bytes(b'')
            if fault=='ancestor':
                ancestor=s['result'].parent;ancestor.rename(ancestor.with_name('retained-original'))
                ancestor.mkdir();s['result'].mkdir()
            if fault=='directory_mode':s['result'].chmod(0o777)
        return value
    monkeypatch.setattr(m,'read_fd',reading)
    if fault=='file_owner':
        def info(fd):
            result=fstat(fd)
            if result.st_ino==inode:
                fields=list(result);fields[4]=os.getuid()+1;return os.stat_result(fields)
            return result
        monkeypatch.setattr(m.os,'fstat',info)
    result=s['owner'].qualify_close({**s['document'],'action':'close','controls':s['controls']})
    assert result['state']=='hold' and result['controls'] is None
    assert not (s['store'].path(s['document']['calcjob_uuid'])/'close.json').exists()


@pytest.mark.parametrize('fault',['boolean','negative','over_cap','relative_alias','absolute','row_extra'])
def test_q1_fixed_four_claim_domains_are_not_caller_authority(q1_joined,fault):
    s=q1_joined;controls=copy.deepcopy(s['controls']);row=controls[0]
    if fault=='boolean':row['bytes']=True
    if fault=='negative':row['bytes']=-1
    if fault=='over_cap':row['bytes']=33554433
    if fault=='relative_alias':row['path']='./series_result.json'
    if fault=='absolute':row['path']='/series_result.json'
    if fault=='row_extra':row['verified']=True
    result=s['owner'].qualify_close({**s['document'],'action':'close','controls':controls})
    assert result['state'] in ('hold','rejected') and result['controls'] is None
    assert not (s['store'].path(s['document']['calcjob_uuid'])/'close.json').exists()


@pytest.mark.parametrize('role,cap', [('plan',1048576),('source_graph',65536),
                                     ('native_execution',65536),('submit_script',65536)])
@pytest.mark.parametrize('delta', [-1,0,1])
def test_original_input_role_limits_and_full_raw_claims(tmp_path,role,cap,delta):
    """A global cap raise or a plan still capped at64KiB breaks this reader check."""
    m=module();launch=request()['launch'];work=tmp_path/'upload';work.mkdir()
    launch['remote_workdir']=str(work)
    for name,filename in m.FILES.items():
        raw=b'{"original":true}\n'
        if name==role:raw+=b' '*(cap+delta-len(raw))
        (work/filename).write_bytes(raw)
        launch['files'][name]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    policy=dict(jobs_root=str(tmp_path),client_uid=os.getuid(),limits={**limits(),'metadata_bytes':8*1024*1024})
    budget=m.Operation(policy['limits'])
    if delta>0:
        with pytest.raises(m.Hold,match='submitted_bound'):m._owner_read(policy,launch,budget)
    else:
        observed=m._owner_read(policy,launch,budget)
        assert observed['files']==launch['files']
        assert budget.actual_bytes==sum(row['bytes'] for row in launch['files'].values())
        assert all((work/name).is_file() for name in m.FILES.values())


@pytest.mark.parametrize('role,size,reason', [
    ('plan',1048575,'operation_bound'),('plan',1048576,'operation_bound'),('plan',1048577,'actor_input_bound'),
    ('source_graph',65537,'actor_input_bound'),('native_execution',65537,'actor_input_bound'),
    ('submit_script',65537,'actor_input_bound')])
def test_actor_role_limit_and_unchanged_outer_budget_hold_before_command(monkeypatch,role,size,reason):
    m=module();launch=request()['launch'];launch['files'][role]['bytes']=size
    policy=dict(tools={'runuser':'/nix/store/runuser'},limits={**limits(),'metadata_bytes':8*1024*1024})
    budget=m.Operation(policy['limits']);source=m.NativeSources(policy,budget)
    context=dict(app='/nix/store/app',configuration=dict(profile='existing',aiida_path='/existing'))
    def forbidden(*args,**kw):raise AssertionError('actor must not start beyond role/outer bound')
    monkeypatch.setattr(m.engine,'command',forbidden)
    with pytest.raises(m.Hold,match=reason):source._actor_read('launch',request()['calcjob_uuid'],launch,context)
    assert budget.calls==0
    assert (budget.bytes>8*1024*1024) if reason=='operation_bound' else budget.bytes==0


@pytest.mark.parametrize('outcome', ['success','failure','cancel'])
def test_actor_actual_sizes_eof_workspace_prepay_is_exact_nonrefundable(monkeypatch,outcome):
    """A stale64KiB min, missing EOF charge or postcommand reserve breaks accounting."""
    m=module();launch=request()['launch']
    for role,size in [('plan',113111),('source_graph',108),('native_execution',1048),('submit_script',4096)]:
        launch['files'][role]['bytes']=size
    policy=dict(tools={'runuser':'/nix/store/runuser'},limits={**limits(),'metadata_bytes':8*1024*1024})
    budget=m.Operation(policy['limits']);source=m.NativeSources(policy,budget)
    context=dict(app='/nix/store/app',configuration=dict(profile='existing',aiida_path='/existing'))
    # Hand-derived chunk/EOF workspace: plan29*4096, graph8192, native8192,
    # script8192, plus30 query slabs. Command has its separate fixed4*65536 debit.
    ceiling=1638400
    class Cancelled(BaseException):pass
    def command(argv,**kw):
        assert argv[-2:]==['--maximum-metadata-bytes',str(ceiling)]
        assert budget.bytes==ceiling+262144 and budget.calls==1
        assert kw['deadline']==budget.deadline
        if outcome=='failure':raise m.engine.CommandFailure(dict(failure='timeout',cleanup_confirmed=False))
        if outcome=='cancel':raise Cancelled()
        output=m.engine.CommandOutput('{}');output.output_bytes=2;return output
    monkeypatch.setattr(m.engine,'command',command)
    if outcome=='success':assert source._actor_read('launch',request()['calcjob_uuid'],launch,context)==b'{}'
    else:
        with pytest.raises(m.engine.CommandFailure if outcome=='failure' else Cancelled):
            source._actor_read('launch',request()['calcjob_uuid'],launch,context)
    assert budget.bytes==1900544 and budget.calls==1 and budget.actual_bytes==0
    # Exhaust the SAME nonrefundable ledger; no command or reset/refund follows.
    budget.reserve(8*1024*1024-budget.bytes)
    with pytest.raises(m.Hold,match='operation_bound'):
        source._actor_read('launch',request()['calcjob_uuid'],launch,context)
    assert budget.calls==1 and budget.bytes>8*1024*1024


@pytest.mark.parametrize('fault', ['unknown_role','missing_role','unknown_claim','missing_bytes','negative','bool'])
def test_launch12_invalid_claims_refuse_before_actor(monkeypatch,tmp_path,fault):
    m=module();document=request();files=document['launch']['files']
    if fault=='unknown_role':files['other']=copy.deepcopy(files['plan'])
    if fault=='missing_role':del files['plan']
    if fault=='unknown_claim':files['plan']['extra']=True
    if fault=='missing_bytes':del files['plan']['bytes']
    if fault=='negative':files['plan']['bytes']=-1
    if fault=='bool':files['plan']['bytes']=True
    def forbidden(*args,**kw):raise AssertionError('invalid Launch12 must not start actor')
    monkeypatch.setattr(m.engine,'command',forbidden)
    policy={'limits':limits()}
    budget=m.Operation(policy['limits']);sources=m.NativeSources(policy,budget)
    selected=m.OrdinaryAttemptOwner(policy,m.AttemptStore(tmp_path),sources,budget)
    assert selected.submit(document)['state']=='rejected'
    assert budget.calls==0 and not (tmp_path/'attempts').exists()


@pytest.mark.parametrize('raw',[None,b'original result technical bytes'])
def test_q1t_v3_result_is_only_technical_domain_even_with_workdir_decoy(q1_joined,raw):
    s=q1_joined;document=q1t_document(s,raw)
    (s['work']/'performance-source.json').write_bytes(b'foreign workdir decoy')
    result=s['owner'].qualify_close(document)
    assert result['state']=='closed' and result['version']==3
    assert result['technical_control']==document['technical_control']
    witness=json.loads((s['store'].path(document['calcjob_uuid'])/'close-observation.json').read_bytes())
    assert all(row['root']=='result' for row in witness['control_read']['files'] if row['path']=='performance-source.json')


@pytest.mark.parametrize('version',[1,2,3])
def test_q1t_historical_v2_close_is_immutable_and_never_migrated(q1_joined,monkeypatch,version):
    s=q1_joined;m=s['m'];document=q1t_document(s)
    old=dict(version=2,state='closed',calcjob_uuid=document['calcjob_uuid'],receipt_ref=document['calcjob_uuid']+'/close.json',
        job=s['job'],controls=s['controls'],technical_control=document['technical_control'],reason=None)
    witness=dict(reply_sha256=hashlib.sha256(m.encoded(old)).hexdigest(),
        control_read=dict(technical_control=document['technical_control'],roots=[dict(role='workdir',path=document['launch']['remote_workdir'])]))
    for name,value in [('close-observation.json',witness),('close.json',old)]:
        s['store'].put(document['calcjob_uuid'],name,value,s['sources'].budget)
    directory=s['store'].path(document['calcjob_uuid'])
    before={name:(directory/name).read_bytes() for name in ('close.json','close-observation.json')}
    document['version']=version
    if version==1:document.pop('technical_control')
    reader=m._read_submitted_files_as_owner
    def no_close_read(*args,**kwargs):
        if kwargs.get('controls') is not None:pytest.fail('version conflict must precede close payload read')
        return reader(*args,**kwargs)
    monkeypatch.setattr(m,'_read_submitted_files_as_owner',no_close_read)
    result=s['owner'].qualify_close(document)
    assert result['state']==('rejected' if version==2 else 'hold')
    if version!=2:assert result['reason']=='q1_close_conflict'
    assert {name:(directory/name).read_bytes() for name in before}==before


@pytest.mark.parametrize('mutate',[
    lambda d:d.update(root='native_execution'),lambda d:d.update(path='performance-source.json'),
    lambda d:d['technical_control'].update(root='result'),lambda d:d['technical_control'].update(provider='native_execution'),
])
def test_q1t_v3_has_no_caller_root_path_or_provider_selector(q1_joined,monkeypatch,mutate):
    s=q1_joined;document=q1t_document(s,None);mutate(document)
    monkeypatch.setattr(s['sources'],'preflight',lambda *a,**kw:pytest.fail('selector reached preflight'))
    assert s['owner'].qualify_close(document)['state']=='rejected'


@pytest.mark.parametrize('native',[True,False])
def test_native_capture_fixed_export_only_for_exact_native_argv(actor_bridge,tmp_path,native):
    s=actor_bridge;m=s['m'];script=native_origin_bridge_script(s) if native else s['files']['submit_script']
    script=script.replace(b'unset QCL_NEGF_CAPTURE_SPEC',
        b'export QCL_NEGF_CAPTURE_SPEC=capture-spec.json QCL_NEGF_NATIVE_CAPTURE_INPUT=native-execution.json')
    replace_bridge_script(s,script)
    if native:
        assert s['sources'].preflight(s['document']['launch'],s['sources'].budget,
            calcjob_uuid=s['document']['calcjob_uuid'],action='submit')==s['host']
    else:
        selected=m.OrdinaryAttemptOwner(s['sources'].policy,m.AttemptStore(tmp_path),s['sources'],s['sources'].budget)
        assert selected.submit(s['document'])['state']=='hold'
        assert not (tmp_path/'attempts').exists()


@pytest.mark.parametrize('change',[
    b'export QCL_NEGF_NATIVE_CAPTURE_INPUT=native-execution.json QCL_NEGF_CAPTURE_SPEC=capture-spec.json',
    b'export QCL_NEGF_CAPTURE_SPEC=capture-spec.json',
    b'export QCL_NEGF_CAPTURE_SPEC=./capture-spec.json QCL_NEGF_NATIVE_CAPTURE_INPUT=native-execution.json',
    b'export QCL_NEGF_CAPTURE_SPEC=capture-spec.json QCL_NEGF_NATIVE_CAPTURE_INPUT=./native-execution.json',
    b'export QCL_NEGF_CAPTURE_SPEC="capture-spec.json" QCL_NEGF_NATIVE_CAPTURE_INPUT=native-execution.json',
    b'export QCL_NEGF_CAPTURE_SPEC=capture-spec.json QCL_NEGF_NATIVE_CAPTURE_INPUT=native-execution.json OTHER=1',
    b'export QCL_NEGF_CAPTURE_SPEC=capture-spec.json QCL_NEGF_NATIVE_CAPTURE_INPUT=native-execution.json; printf x',
    b'export QCL_NEGF_CAPTURE_SPEC=capture-spec.json\nexport QCL_NEGF_NATIVE_CAPTURE_INPUT=native-execution.json',
])
def test_native_capture_export_rejects_grammar_variants_before_effects(actor_bridge,tmp_path,change):
    s=actor_bridge;m=s['m'];script=native_origin_bridge_script(s).replace(b'unset QCL_NEGF_CAPTURE_SPEC',change)
    replace_bridge_script(s,script)
    selected=m.OrdinaryAttemptOwner(s['sources'].policy,m.AttemptStore(tmp_path),s['sources'],s['sources'].budget)
    assert selected.submit(s['document'])['state']=='hold'
    assert not (tmp_path/'attempts').exists() and not any('--parsable' in row[0] for row in s['calls'])


@pytest.mark.parametrize('fault',['root_path','root_role','technical_role'])
def test_q1t_v3_retained_root_mismatch_is_not_reused_or_repaired(q1_joined,fault):
    s=q1_joined;m=s['m'];document=q1t_document(s)
    assert s['owner'].qualify_close(document)['state']=='closed'
    directory=s['store'].path(document['calcjob_uuid']);path=directory/'close-observation.json'
    witness=json.loads(path.read_bytes())
    if fault=='root_path':witness['control_read']['roots'][0]['path']=document['launch']['remote_workdir']
    if fault=='root_role':witness['control_read']['roots'][0]['role']='workdir'
    if fault=='technical_role':
        next(row for row in witness['control_read']['files'] if row['path']=='performance-source.json')['root']='workdir'
    path.write_bytes(m.encoded(witness))
    before={name:(directory/name).read_bytes() for name in ('close.json','close-observation.json')}
    source=copy.copy(s['sources']);source.budget=m.Operation(source.policy['limits']);source.budget.read=s['sources'].budget.read
    result=m.OrdinaryAttemptOwner(source.policy,s['store'],source,source.budget).qualify_close(document)
    assert result['state']=='hold' and result['reason']=='q1_close_conflict'
    assert {name:(directory/name).read_bytes() for name in before}==before


def test_q1t_v3_reduced_leaf_fits_existing_eight_mib_close_budget(q1_joined):
    s=q1_joined;m=s['m'];raw=b'r'*65536;document=q1t_document(s,raw)
    budget=s['sources'].budget
    assert budget.limits['metadata_bytes']==8*1024*1024
    result=s['owner'].qualify_close(document)
    assert result['state']=='closed' and result['technical_control']==document['technical_control']
    assert budget.bytes<=8*1024*1024 and budget.actual_bytes>=len(raw)


@pytest.mark.parametrize('delta',[-1,0])
def test_q1t_v3_prepaid_leaf_boundary_before_pipe_fork_or_read(monkeypatch,delta):
    m=module();controls=[dict(path=name,bytes=0,sha256='0'*64) for name in m.CLOSE_FILES]
    technical=dict(status='present',path='performance-source.json',bytes='65536',sha256='0'*64)
    launch=request()['launch'];jobs='/srv/qcl-negf/jobs'
    depth=sum(len(Path(path).parts)-1 for path in (jobs+'/'+launch['relative_execution_root'],launch['remote_workdir']))
    total=8*4+16*65536+4096*(depth+4)+8*len(m.encoded(controls))+8*(65536+1)+8*len(m.encoded(technical))+65536
    budget=m.Operation({**limits(),'metadata_bytes':total+delta,'maximum_files':2048})
    policy=dict(limits=budget.limits,jobs_root=jobs);reached=[]
    monkeypatch.setattr(m.os,'geteuid',lambda:0)
    class Prepaid(Exception):pass
    def pipe(*args):reached.append('pipe');raise Prepaid()
    monkeypatch.setattr(m.os,'pipe2',pipe)
    monkeypatch.setattr(m.os,'fork',lambda:pytest.fail('no fork before synthetic pipe'))
    with pytest.raises(m.Hold if delta<0 else Prepaid):
        m._read_submitted_files_as_owner(policy,launch,budget,controls=controls,technical_control=technical)
    assert reached==([] if delta<0 else ['pipe']) and budget.bytes==total and budget.actual_bytes==0


def test_q1t_v3_cancelled_technical_read_never_publishes_close(q1_joined,monkeypatch,capsys):
    s=q1_joined;m=s['m'];document=q1t_document(s);target=(s['result']/'performance-source.json').stat().st_ino
    read=m.read_fd
    def cancelled(fd,limit,budget):
        if os.fstat(fd).st_ino==target:raise OSError('synthetic cancelled technical read')
        return read(fd,limit,budget)
    monkeypatch.setattr(m,'read_fd',cancelled)
    result=s['owner'].qualify_close(document)
    assert result['state']=='hold' and result['technical_control'] is None
    diagnostics=capsys.readouterr().err.splitlines()
    import base64
    retained=[json.loads(line.split(': ',1)[1]) for line in diagnostics]
    assert any(b'synthetic cancelled technical read' in base64.b64decode(row['original_prefix_base64']) for row in retained)
    directory=s['store'].path(document['calcjob_uuid'])
    assert not (directory/'close.json').exists() and not (directory/'close-observation.json').exists()


def test_q1t_v3_root_replacement_between_retries_is_hold_even_with_same_bytes(q1_joined):
    s=q1_joined;m=s['m'];document=q1t_document(s)
    assert s['owner'].qualify_close(document)['state']=='closed'
    directory=s['store'].path(document['calcjob_uuid'])
    before={name:(directory/name).read_bytes() for name in ('close.json','close-observation.json')}
    s['result'].rename(s['result'].with_name('original-result'))
    s['result'].mkdir(mode=0o755)
    for path in s['result'].with_name('original-result').iterdir():
        target=s['result']/path.name;target.write_bytes(path.read_bytes());target.chmod(0o640)
    source=copy.copy(s['sources']);source.budget=m.Operation(source.policy['limits']);source.budget.read=s['sources'].budget.read
    result=m.OrdinaryAttemptOwner(source.policy,s['store'],source,source.budget).qualify_close(document)
    assert result['state']=='hold' and result['reason']=='q1_close_conflict'
    assert {name:(directory/name).read_bytes() for name in before}==before


def test_q1t_v3_retry_timestamps_do_not_change_original_domain_identity(q1_joined):
    s=q1_joined;m=s['m'];document=q1t_document(s)
    first=s['owner'].qualify_close(document);assert first['state']=='closed'
    for root in (s['result'],s['work']):
        info=root.stat();os.utime(root,ns=(info.st_atime_ns,info.st_mtime_ns+1000000))
    source=copy.copy(s['sources']);source.budget=m.Operation(source.policy['limits']);source.budget.read=s['sources'].budget.read
    result=m.OrdinaryAttemptOwner(source.policy,s['store'],source,source.budget).qualify_close(document)
    assert result==first


@pytest.mark.parametrize('fault',['read_null','roots_null','root_null','directory_null','files_null','file_null'])
def test_q1t_v3_malformed_retained_domain_is_hold_with_immutable_records(q1_joined,fault):
    s=q1_joined;m=s['m'];document=q1t_document(s)
    assert s['owner'].qualify_close(document)['state']=='closed'
    directory=s['store'].path(document['calcjob_uuid']);path=directory/'close-observation.json'
    witness=json.loads(path.read_bytes());prior=witness['control_read']
    if fault=='read_null':witness['control_read']=None
    if fault=='roots_null':prior['roots']=None
    if fault=='root_null':prior['roots'][0]=None
    if fault=='directory_null':prior['roots'][0]['directory']=None
    if fault=='files_null':prior['files']=None
    if fault=='file_null':prior['files'][0]=None
    path.write_bytes(m.encoded(witness))
    before={name:(directory/name).read_bytes() for name in ('close.json','close-observation.json')}
    source=copy.copy(s['sources']);source.budget=m.Operation(source.policy['limits']);source.budget.read=s['sources'].budget.read
    result=m.OrdinaryAttemptOwner(source.policy,s['store'],source,source.budget).qualify_close(document)
    assert result['state']=='hold' and result['reason']=='q1_close_conflict'
    assert {name:(directory/name).read_bytes() for name in before}==before


@pytest.mark.parametrize('version',[1,3])
@pytest.mark.parametrize('state',['hold',[],{},None,False,1,1.0])
def test_q1t_external_client_typed_state_refusal_preserves_exact_wire(monkeypatch,capsys,version,state):
    import io
    from contextlib import contextmanager
    from types import SimpleNamespace
    m=module();document=request('close')
    document['controls']=[dict(path=name,bytes=0,sha256='0'*64) for name in m.CLOSE_FILES]
    response=dict(version=version,state=state,calcjob_uuid=document['calcjob_uuid'],receipt_ref=None,
        job=None,controls=None,reason='synthetic_hold')
    if version==3:
        document.update(version=3,technical_control=dict(status='absent',path=m.TECHNICAL_FILE,reason='not_published'))
        response['technical_control']=None
    raw_response=m.encoded(response);connections=[]
    class Connection:
        def __init__(self):
            self.raw=struct.pack('!I',len(raw_response))+raw_response;self.sent=bytearray();connections.append(self)
        def recv(self,size):
            chunk=self.raw[:size];self.raw=self.raw[size:];return chunk
        def sendall(self,data):self.sent.extend(data)
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def settimeout(self,*args):pass
        def connect(self,path):assert path==m.SOCKET
        def shutdown(self,*args):pass
        def getsockopt(self,*args):return struct.pack('3i',1,0,0)
    @contextmanager
    def directory(*args,**kwargs):yield 999
    info=SimpleNamespace(st_dev=1,st_ino=2,st_uid=0,st_gid=3000,st_mode=m.stat.S_IFSOCK|0o660,
        st_nlink=1,st_size=0,st_mtime_ns=1,st_ctime_ns=1)
    original_stat=m.os.stat
    monkeypatch.setattr(m.os,'stat',lambda path,*a,**kw:info if path==Path(m.SOCKET).name else original_stat(path,*a,**kw))
    monkeypatch.setattr(m,'protected_directory',directory)
    monkeypatch.setattr(m.socket,'socket',lambda *a,**kw:Connection())
    monkeypatch.setattr(m.sys,'argv',['client','close'])
    monkeypatch.setattr(m.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(m.encoded(document))))
    assert m.client_main()==75
    output=capsys.readouterr().out
    if state=='hold':expected=response
    else:
        context=dict(version=3,action='close',calcjob_uuid=document['calcjob_uuid']) if version==3 else {}
        expected=m.reply(context,'hold',reason='reply_shape')
    assert output.encode()==m.encoded(expected)+b'\n'
    assert set(json.loads(output))==set(expected) and expected['version']==version
    assert expected['job'] is expected['controls'] is expected['receipt_ref'] is None
    if version==3:assert expected['technical_control'] is None and expected['calcjob_uuid']==document['calcjob_uuid']
    raw_request=m.encoded(document)
    assert connections[0].sent==struct.pack('!I',len(raw_request))+raw_request
    assert connections[0].raw==b''


def publication_fixture_plan(*,original_bytes=False):
    """Portable original input metadata, not source/creator/native evidence.

    Source Runner original19cf3545; portable AiiDA original24136301.
    Full v3 canonical profile376aedbb is independently matched by the owners.
    No numerical payload or execution is embedded here.
    """
    import base64
    import zlib
    raw=zlib.decompress(base64.b85decode(
        'c-'
        'rlKTd(X!cHX;wMT36T?!#M?&6$@7W7+X&qD*W>Kp<!cHd*ZEY&O{<yZ1g@f&kCNuw(ck2;e6>FaqQu$eUtFV<nPjfFRFj&iM)QFU'
        'hLny{bqSdv}xF`)mO-'
        '(m7qM>#9}j@~ySLcxN_~{2*GRWS0cdUi#5YTB)vX_>0xTTF92SlnvQ&)s>|#Rm*f2ifJL_B5k31GEyvc<u6wn{M+<3RbLvar%LbQ'
        'PSH!`9`->TrO@Xm@HeyB7v%rpw_Ot7p~#6`1iux33xA)+hr~r`<1e%3-'
        'oeFv%{M`~Ldo8C<M6PpbzQc7;Ri4GhXlPy4pD@X7wDz4-GwN9;l`04tY0L^M+t(FZ&X>aZcO=h{@`pwsn*M<@74#85BuF=KTn-IW'
        'beXwf5I`}9o9|c?1MXWvpcN9z;*C;+~i-'
        '7?*3qn;45d3ydPzAzS+gl@S%NaX&m06WWJ9>_ztF*&Noi7PY@bmTl2BubNJU9e>sPdBX7QSUfKy-Cn!x}g(J))I&4t_8ye2>{;eP'
        'EeR4?m_SQ+(!5HJG`-Ar|k9T`K2OD{7WS1v0!tk}r<!+FByNiJh*a%ML!3H`)$#}$2BSe@*n#Pg6b`EPa-'
        'YtjCAe1+U^}{ZN@!Ix-aEuAuq9j5g@U<uf`peD(u0pUqY+)Ml?O|s}v4_&p2(o@NooIaso#fOrI2-'
        '><;Xw=04OxiD#oxwTIBwW!*zs|%91vUJ9pK)(n?rOv#@L&OG+VQirnZNoG}u3kFm5Rh%$>tNo^OMQkoFdBV_-'
        'C}4Jd&JcJ;6yk;Kc-Y&enA-'
        't&n`o5xLZF0za7N8#xup@C2rdG;L&V|N@<bHa6;1pCc4g%jR8iHAHOFt}qokZwjKt{vJ3O#%4Y$%?wf_i=KY?i{#3Zj8r$X*)^cJ'
        'f!vxC3Y@Mt>D;ir<5n}gUE~T#}gsKV7<Z8<4e1IRftG6qORhhy8sSljbH-%1fFu|4sM<uqG-'
        'L}jC%pY_}&JQ?iQ{?NQiM%*_M?nUFVQG;W&J#k}u$r>;qsx)5=dy<b)4I%ee6ZXC1{U{NWsYrT0Jz!M2d{gFR+Lm&__VmIV6=gq5'
        '+oafL_N%D{iHeSdE!_>ql$e?)^w<m}Q-JhrMxD{3$*$dXR@gsd{q3#<wr<hkR<2YgBG-'
        '6oDsX$%?ba#R8X$f2+ar@SH8$Nh5J1<5c56Q&m=$lZhXGsZ)hF{w)7A=)3|xg(73#akzcY{zqUdndDOz(Y8E;G;LbCXfIbMk#Qt6'
        'qWMXn95MF-5nAvjHNEvStGdQ_B~jZK~z|ctCfL7iV{DQ-IGi>gNJxD5s{V5Zc*qxq?<AKpk%Ke^5bNiZNV<y162g4d{Kma3s{A6k'
        '^qZCCw4Okzonj&ZdNfU%wrintLNdDhcIyL{RZ@O?+S&$lB6mQJDNa9$<(R4axOujz8r0%#$?hRJh=&IVu6P*`Pk+tC-UIs0dn`CP'
        'vHI2*hP+ee6NixYJzud@x9VF3^sQ|kd6XB@AVS5O3d^EUk0C_cnw1?8*roKFv>$x^4~C?O0uf$Jc1!T@2LCz$TQE4uIVQ5_g6)?j'
        '1ztvT-U{GF})@M_UGRR-Y8Oai#+M3ccTh(E8w4}m*qqZCY4qL2C?-'
        'f0;%@;gh`(B4*n}}_Y>g|N~N{H0gP$GubGg@3uCVw_ZA#GlRRk=I$-f}9Kn$zx>fAR{_H^JF$V|d8tp-'
        '2dkJn%;%S;>XU0PkFn+ee5}m$PLhUe&Uk?%OVmQ3uZkz+GkO80rf$b$*llw4{kcPe0L43?h^+;iD8@wDx2jpp>0I|fZe02SwhY%C'
        '=*#Ye09(jNW<HxXDP{+oB1u<+bUSVL8vkFHUzXc?fi^QWt#6X$aqwNke9O(ZFJZ!bu-'
        'heqQ74o7M=FjsuGDo*Sdf+KcKm$Y|6pZ&Mi{0)q(HFH7#yBMq9KqTj?XT}-b9tu*&fdY4f|uj-'
        'BP#fUz`U}(9TAmWc}X(N=39WSTOB+i;)9Sh)?-aJyT(qR&MxzWp-'
        'qrtM?CP$-8kOQ8pI<EV;C4H8gQz~TkWl3!VWG2Hh1Q0UI=+a?!XXbpa?L)Ok+Naqu_H8z6*oT6{7K2#Ah6a!APNGr4R<Ol-q#lE-'
        'nf~`wl;t=&J15JUieW$ZlSSk|^GyDPRg|u#Sj#F2W$Hb+At-3Q-%;W<oKI5F7o#5}F2?p&iU$p*Nab0BFQL&_Lm-86{?_#-'
        '%_ly;eLVOGP7tciBg_j8b@7uPl#JM~lOtpZI2w+n92EMsEeqel&|?XLNU*x<MF@Wp`}&L{I4mo!YWrdYo5>wY~BD#c1pU#F@RbMw'
        'tO1vz|X0zEJ^Wu`Jvac1DdE${zQleG?b*(y<%>#JFvM&thD`MaVvx>0o2dt0cD#xHEy!!2JQA<F_IYm)qg^mi+{Brtbuy4aA=*qV'
        'RO20FZV^#D=FR^h+6Y0#{iXx>z7<@gF8aZ00tCbH>Z{&8MdPWg)d`B|7dgtxUotFC#O><-'
        '`_IQF#~)epO}%F+QE4p=_)XZg=}}uR{qx0p@%cq=z$LY)?!x7b2)uxpgA!PapMl%_Y{e2&}`i8cmVZ>ZDehF&F{SG$svIIG<`!pj'
        '6XwC7Rr(yE+78%G?~mp-8kgve-'
        '}ueQX?v0NsO?{*+?n)rt)zZw9RcLGrs&j2I~puyULbqdJfZ(Cj$r_bRj#h!YsQ|5PDQ)sqm$5qM1w9?qL!Ux@wpGQ$Nc6?7W7IgU'
        '!6G=?kKI&cjgP$fo6o>hCU>IQ(!33<{h`B)uf3fkzI(*%-r>5Ln1FKQ$LUF^q3ML}TK=7LSKk4S@=-'
        '?it5K<Khf&zvD&#<;MS46JsB3>hORl;tA)05Xl(tH7BCHj-'
        'a5oacF>aK6H3T2st+PLQM*^Nfv`3WipHHixYfWwz5vBH0MscQlv+k2ogD)7X`R{In+QVaTQ+niMOMdwn1r>fnxxmZ(T_Z0HQmzX9'
        'Thn*_UYmrVSfzLQQ9K8sCZQ$=@20YO=hon@XS`xI>SQQcB_T^8#s$KDiKcJsiTYxMNhk=h4HL>J-kB9Jbl!$^T^86eUL-'
        '2=9L+C?1>5C?WR1oi27A6g?GCv_4(KHxFMIVIi65Ht9}ik$5=5DIi~Qzkw;27hw4+;T%|biDQE2?||IGVG5Wj9Fk$$4p_%k|jS`K'
        '#q|bEolIC9Q9y*8}!+Agz5HjLa-sfCwM;ZonU0#Ozr&{IiEot0ghhoa0D|H_qql7a%`t_5!^R=3Zp*U>!?{Sc(|DRG3$)A=p3a40'
        'pX9hK;dcc?KI#yE{i13_-'
        'OpG%zB<4u0l!@M77n_uh?}DyNre&=@fWe>clK$0L#NDz1ln%giZSgh?*q}c|vs^n9#e6@VA`}<rX>*C>d8r-'
        '~(I62~cfG0DAHO9+7fG2pIk<i5-'
        'vR!M&<Cj4w_95+syyH5^W%gfgY5y+PPMex6yB|NUkDUthjkmQ6k+fR96@Ml<xX!BT8_CKB>}P{xS-5&<PPt0+qpud&``egY-'
        'mMjyj(H}YJo{fw!JuE@NGytcLv7ULxQM4l@P$|^!|gK(TXU@M?&kjSPK*hqtj>KzgLDIQ6g>sI5RWwYy|r|JuNE-NbaQIo35y%GN'
        'gvVa4$4mb6kFhwo><;$0$v*r$9O2tubP=T;))Uu9xAJy@5P6+#BvbLP_E0R7-;6=nL-'
        'Y#?^iJ_r8$ex4~Cj=fLBS681L4+zQ0x=Cskwjnwl077aBvYd$pl+HVatoN${+is}DL2e;S$UX-yGMHccdx&C{m-'
        'v|3;+A}&0oF#=FP8O|DV_2zW(2{*S~xH75w3MuYddI&)@ud_U13(Z~v**=C`=b_wcW;Uw`xZyVu{&{@qW0_Tw2e`ReuW-uy@0B>T'
        'hH(9M5&^XoUidh?%WFvwT%+h4u@=Qn@z`uiF5_A6-'
        'k9dz(Dbo7s8Cf~xJzMo4paWqrJOVqPiKfdf~ptr26P@tjHIwUdJQeEK7$;*YIQ+%2!W?Xjog8T%gcL<E8KB^VgV(6a`T>&)%M-'
        'u&G3yQcJHfz8ew&{UiP`@%2N+J*xYfZkSZdk5zuosw@O-'
        ';%K&Zf}DuX3g|8`W#WvtzZDccC{<Y6SwQvc6=yWNjIo9yw7;><k+*<m}I!f>lyJc=nUTSuY8-'
        '?^q)3SY9Y<*Uslo3hH9;lK^Yf;u;bedxz-qn36JI&bC{cGAl_=mub3erg@i?g*<!p{Z?wF%*Iw?G7b0X3(Os*PReQ7)Vk}sh5Q-'
        '{74Cq`s7eu%;Z+@iwWPq)HH)^txKWz3?}nK-'
        '4~gzmo*UdgDHT`c{8*h+^OiP19TFCD<QcrCO{Ja+C)K$<6jQX=4%)@6T#{<a<v?ocVzzDR1<olY_dAP(kd`vrl+KYxNg?dEa}U1C'
        'uEU;um28KlEw(@*+lHT$pVJqe36Ikio1cs{;;xB<b)Xm5nb=-'
        'IH!>yE@~}}@Zj)7t@Eeu3RZ8#^N~0yuRf@^TbLKD1MXUZ&1g%r3j)kI8Mv1(x0K-'
        '&TU?IkWdto?OLO!KcW;6OQI;?0C?lY4~@6b!?uGEUHNIsr5u*?nA8*DZ!GYCjn0Cf`T7PW*LNSJR*JP1t@M3=L2?)~LT<P@d2&2@'
        'ghqvXs6z+J)#eIf4`2%j|H$}(B9k6Tq~N@<cIp=T-wIFNkv6~+P?l^fG&ebkDC3G5`=E)F#mm1sfk5bQW*-'
        'KE<El#nE~Zxdh>>*faW%RZLcP76uZ-je1^PyucvNZ`en`ZI-qBJ!5}wY2SlMIlNG%lm7Q2+a<J67<0SFJ>Qi7_@RE3`Q!m98aMRq'
        '$qoruPPVKJC;=newy0ss}qaE6;9DUD43{1y?!KoSjsGy6h(9<w>7a$^Ffz+h)sdVeV=RgUiMzl2H;Pr3&CW!pc^n5Qt1XPYU0!St'
        '>O}H<*{U_w*{Ol^Dak`CYl^EV;ZUD<K~KKg>#tJgqv}@or+ykWux9;Zs~015d_)@JW!s>>8J~XtC=_Vqq!oE+gB>myLNR}Dw}+pP'
        '+=&g52;pZ88~VLvzItt!un)t2hQph+!R3UzS9Lfn_ECtglhhX4ZZB$=u9@gq{*CLDWR=dYpz|!a?)mgRvC*2KOv_^H*C)Z2sTt&<'
        'SQpkeYJYX)gMJS^`&O$Oa8oB5DML}E6F&1AgJa%tdZW@C4THe^wM^c#CgcR$|pwp!Gxgpa-'
        '$4Z%cv!lvX1pcp7@pNXbPjEwG_dI)fy&u22A;CdNRc`0~!!&kp;+|V{R%h!xc<f`~hLH988-'
        'YTV1IG@U!VGnbu9L2(enTJvL%v`EA%-'
        'Yph(686_xXpru(AG{hf|TPLffuX>#dEECIYi#8aQp)+k8iGs0KX)sN?%id^>=3ln(2o{{FGV;C%UQTW4pPPJ)ZcHLqcr=J@bf9nG'
        '=Pf%%b<XZ8KQ~~@A+f1M6`9j#8A(91;@Z;c5jLP^cW$=;qDEtcu#7(t4uYHKz9HJe*pEe$+rKE+*{(J*X<!+*U4_YFc?~5iaqfjw'
        '&$W&Tz2#ZTV;?zJfx}(slc$&qZ<s305}qXeeN_|(e{1r;wb#y}m?X2zJXnV}{|)G(P=2<h^G5kVUe7eI<E^e%R+q!+YJ8BtHJMF{'
        'yR$uPPvQn>@OFV$W*fJ&nAtQrBQqkCeuCGi2!kev-Aepy8X}g&TN4^mk8;gK%QTc1ty5?((XMgZaXBvEtX9Ak7&(a#!eQ967q_^&'
        'bEDk>vr3p!W2v;bTDSC2Q5cFkx7a7SGRl<SVVNx3$E9g5I7}a#smVH}_rgDR-'
        'b*E>O~daX+A+{{{sw>)A9)3j0tr%;p*<}{X7k?!?rm<*mbAHQU`e#=@i@)4%jev6!|dGi<93|WY3qLX@3c9$tZ{bwnZRq?u3&%HG'
        'l7pl;LEvw{7!RKyyuPPZnXML(j)EkVy<vr$5!*YU^aA6_?8yW^U-'
        'vCNDE`Or9J(H=h{O)7P>RnWi7J}JTt6&pG{9FvF4|)^qx%XStU78f2|N~0O#*D(AucI{It*GUO`r|O^ls0Klx$d26>l@2&j}WNi*'
        'gq2b+MkMf(ncu`fF>X`upV+rFT^mrPor4FAFSyRf~kQs1P7rkJza^^5H<G-'
        'iqd3*lFIpxmStMgTyHh~PHB>I0~`12_qj;sNEuUj~0t9h@5{8PUV!DqE*DXHSkTqTO`1@aw@!`h0;DeFk$-'
        'ss6gdscH5kHPR`uKEIYiXn1_ZSOO5*nlZ;$S!ipPTucoe*ys|sS^&YCkX3Mx2X`!vxrPg7QO*K5XK|$SQCR2W(9Xx<ox2gwLYQX('
        ')N?=Xxy=udIQJcxWG*WCak%8`L?(-1lWDsI7oR)`q1=U07DOo@iBs-HD);+8jz=r^;gtmt%RB>f8){h`w=9TU?!_(-Krau$FN-'
        '6Xg)z*%DCWU9=58eO5G=DGnpq6bEP!Yh#x!@MnuT!9Ed7dMn}yNMefZ{ngfq?V+EC6%;+%&eoyD=vJ!t1Xyt5eMxexO!gnI75Jr6'
        ')W55hk8qMy6*&oo)IVxap_&|)}faU`@57Fq-iO|P&Y5j_|aEsl!r#YKxEqi0;hEQ5|_@X?f(ER2!vLP?9_q(za^^og~irCAIreT{'
        '@*(S5+^LC|P1aP$Cpv;aU_7$V&TlJ15{3j(EkpwjF+*$S5y226KDrg@U(K-'
        'ly^;Is&IdJxdRomX?P)q?11aeQ?L!dehx%|%(Wd}sjDS`ce3jJ6((x9&z<cVn*mP}f}CHM?D+*y|qfTtEI=0D&!l!R|$2Hx1!mwq'
        '%duP`d~kTL6#UgUIf~WDB6Og>l)!$ZP>@wir5l06tp;p-'
        'rD(8%nz$r#%FzJq)Yeht}@FYque`2V%B`QQJr0wg(`$2Vl2{qPLI7Zx29l55{ndp|~G|<L=^TTr_tNp1TjxEsE)8g0OpV-'
        'L1%OW>GwJw;;Z||B>QiJX<NP7X^GQ4tO9ExC09;hz1^r2Np&IcVmJDQNfIGeH1cS92<NLI#@J5pw~h^G)6!yN<b`5U_hjRaI8Row'
        '7{@<0g;G-VKD<jQ3C_x2AXV{)ed{n;obOf8i>n5k92~=Md0B=0C5qBcppf-'
        '4<;@K6z_zJ_kqO);NoI{@m|PyA85P>HZB$~BM2QA2agND#{~i8EwK%qmqh?gJ_t`Pj40>C|A?W=#c}0~4$8-tx1-'
        'BvyeEbWmgcZDVJPlE4Bb(1TroiIk&xWuK)Eymu}>`NJBk8LEq)a8xle+H9*Q6ukHRz#MKzv!_X|+<^F^5aA{40W=Zi4KMNkJ{gy-'
        'Ea6}HE2eu2(@-uzRLey8)|SY-PEZ2Ph3c0qi5H^QBdai6t|d~G=Q7Nk47qr=hegYfP{5bxrccX8DF0NlGM@?8}B{s{E@QTX@c5b*'
        'sN_~9t{;W+p{B>a(Bcp)@=8)O<TzXRwyqWarFm<emQk$w^<=tpVdzR0ZMFG|D-'
        '@dkrxIR7OfP0d37Qgu~X)qGWzVNQy>v<!Cz|5HuRvt*>IXbBD6m1Zf(u#mUVk*4~pB3r7_MEIAZ=2*P6N{#*k>#_NuzN>pn-'
        '86mG^L5QzIhN}zz+)n>RAu34nrp3KDCDWCYACv{X)DuPsS90!DVnaSv<#Xr6@}Q)fNypFANi=}!Zlr_D5ha(%Z0WwG{CRAzPU0T6'
        ')>hqHH?+4`M#;^=F-%bj^iyg&65{P!_jqj(H!+pNh)|UZV<s;D={=hQuqd_y_f<*2JX-_bzjjIE7(D#tW3j!btBb+MJk@_D-LXn?'
        '>goRX~>aH%SE!~s)}m$?KVE!Ee4Oh$PhclDLa<x89+9=t2>TvYAYXkj^d%EC;JO;fqW0?p6dF@@t2D3!MR!s!&i~IbbMoBxZNARf'
        '7qd7BwvSb47|~*YkInA8J+=KYb`YoxxVjuE8kTYKs?CRW!W*n?xZc3hUOclhD>E8zQW39Y8OzUViHRo8IB3`38d_q3)o2AaTmI(I'
        '6%jms~QU#PT2E3b*00eEMa!C0t60|cXZgOmSjKR>)v8Vv-Fu8-b85a-xP3}o5o>7=z-'
        'Kov|l3LzTnwkZ0sutInFbZ@88Ct|21K@84fAPF8i09c$J(P;3*C!&wrI}9PqUN=&>aF2X>D7qE<&u_mCoPJ{fpjGShs8CTf95m5)'
        '${gnP+=mg;R7{~;%C65j0Hp>#2UB#p2QwyV?HlWc#$_rM$gp@)0>fG2K(wegS}Z+pE^Fh9JL#Vbdo#jVyoD7=5#W5)%sDh!pDIIh'
        'H5;et54z*Cr;>%h#??pf{9$Igl2@caQ?aBK&#O~sa_0k>Uq!&J`XYSUxFJh(F~)F2<b;_D(3D?U&$SPeRDYh5hADH67{Zuq)6zXy'
        '>U9y}bh0XWiVjXIo#CE<I)7Vl~1;_W>y7`ddIf^<oYSO<}yk69_Qk4`$x>6PXK5h-'
        '{Lgm)h@zbp2k3=X5}WY3(mXj!#1CRF7Uc8w>fH^b4Ws#z3pr+G_=)C5zSct;xHQYRe$-'
        'QiuGpg>vwQacK<J+<|AMLSMFY3<QvlTM}{mo_au2v=ghoZG|+qnv_;QYGr>SivbD8YWzJ%E>VC$P-'
        'M47w|j5H0mLkQ$4$VwVNloJk1E%DXFy?i9YQk(G35dieQ-7;wdJ=4g9{?m-'
        'EPF6@d_wo%E@X_afy}P9B7dUh*aGqG)~Iad~$wg~`(<;zo{+NoBhd@jm4&xQTHlm{6H>=4nu0cNFx6IY4r=p{U<uKu)IatW3grnU'
        '2oPB#@g)B=+Pn`I-'
        '7NGzsNs;)naR=V=;}sYy6jlR&nnLHU}7Wo#OfvuQxqrX$ia38Z@J%iT0Ady{bfCZXI+oa{{9zNT(R6A9>8%8h?iA<t81>L(`o(_`'
        'l-D+_j3{oYKGgjfTTP7O#q)t`7uB=yuO9ZVgGs|NX)%6{flf~m{aCVGXLYF&-'
        'o5Z9}0GYg`!VvQ*&vYQ)3Ph@kM3?6TfUt`ENF}YBlw~4n+RC>Q@?r3*L!snA4uxV2sBbztzDezl5Z{<@HJD#tZ7=wJ?rz<m6RSJl'
        'pwd&PB@e}J)5WXJ#9+e-SuPJ_L-'
        '*Pp>5AEOoB{#p(hxX^3jIr>;`#H;h#FVYx>3;Tk|0vrYXroeT`~qOu5A78<P0#zeB!BdBabn@#(f^J8{v)Yi**nJ1vm{<z%h`waX'
        'P>vw$NOx;Vw@7=@#kZ-pU#;q1YJ3d2bl;8RQ{ZaXB$%xDrdnBeVk+_g7KS^%&jk2Z<<MUNAyiHr{3_`NoLg^Fgew9nsEcy;v1~Z`'
        'UW!Iq{k3zI@PZ8163!P3McS%Dng{gug9E6^`_42WdN>RX{{c3CU$y~LuNA%OhaqjyZ~<j=W9*nHOjVA84f18-'
        'u(I;SANlJ>tm{lJR7LE9I-'
        'p|!&Jn{R(p9WPf%N8jO(>^R{|wB&&tG#7$;B8L`2QjO?oOc&1Uy`0@U2daC1hIxhkW0&E_U(6(_XO3Mu-NKl;<w-'
        '+uOQ+Y689SE;o@N13ownjpoBj193xa(bM%RNWerjq#>c77CksBHRK}Q%|b1wA|E_6RbTq_Oz&)c~eiPrDWdJ)9NU$_xwy{&s3i1O'
        'Z1HzS_X1RAxMEzkmAK4XDvCAIRzm(B_VkPCR!G<yD+49X-M(nkf(g7yGlzAdY-'
        'F}=54hi$7Bz+>2T{EjyadI`qvy+%$g6Ws5H@*QS~+_nnhWHWWvL0s|q&JmhkIvPP0GlwdN+;oQ{g3pNy+2Q$*BS#ciUEs#gUbd1q'
        '>~psEB<#_F>AyVL7RwMi8<iswwp;c2cqT`2O(&2#mu&@4iIz1BG%NmFH^CwxXbOM*^)$*QW~7a<k0<vS<ZpsKX|^<Il=m#Jd56YX'
        'iUO#OuP)?UMQ%1Lz>%AHzVdR(x|iMV^owlZ}bJo#uhI)<|4+*&I$PdK;M642AkiK*s&0mnvF-kxwqyqeS#ol{kp{W&n{N{rhzW2T'
        '^eyApA5@lQ5OL|s#cssUih1*_c#s#tImO3)Wus!C2soFdw}Z3}W+M94{`uIjZ7E2@O^Oh_EtarP|Ol{Bkx%;{w_Mzh4#PSrLyOQE'
        'Fa88$kGr(Y$bt-@)cazWXitO7*nM7%Nq4NIi7`+O&HY6{ndDpIo-'
        'ga(lJB#w82V+@vV69+=tQu`Lt<OiIh+kCT|RMhj}O*>P;Y)S=_+grBzP1<R)CXTRiZ5_ri2|E?CYSDM-'
        'rF5<!BnY8?c%)N-^ntVBqkV7&SL|6)xVT__h;FiN=to15l>+{0Ujp1upISq37Px2*F2#b&-%Vx>%chc7qj-zXeDpK}*(?Yz09OZe'
        'a9Q!|=iU7JvM($k{oD($Qo|)NPI&h=9rb19uo;uTOp=W|n@BAz<*Dy^6*HG#uBU#toY2L!(2!lo4sgahkk_92!Xdlk<_facoRD>1'
        'R+hB$t~<{+ke)5!z;r9VE^Iwnf}lyKMY7?=GqB3m<MPw=rY5Pe3wA!D)Yh4T_2b?Yto`{{Ir+icG{P*UE62*hzJI)WgHnrdqN!}3'
        'oo`HQO5vK}fbFuVb(q~0j@hSAV(C1J54w-'
        'SWb?s@90gBZJa0ao8u#aqMeB>7az<n%ZeAniZTXa2ppsV8J{>8oPR*YC$h10TM>H_vEeG?}Hl~(1eY)Z@7Y3@SZ4VG_;6YaPOK{p'
        'fd+m=P=hK&fdd9>*Jv90=T=sh4vQG>-S7Tng4U|x@_mH09vXc)_66#-'
        'V6Y%xGf3N{afO9KEUhMnR2?#}5oJ*=W_~^}k#xFhNmrjTMzocNQ%ZU?e=OJg%z$WI{*&PL$^APQy5_f!J@jA5=yBt>k9MW=yAuSg'
        'Hp09J*0xEw|c<_sW@n3F2feEAIFFQK@assd~F4+0W#F;(^)Lm0R-CG>|bX5q4)=-'
        'glm_v(0fsGenU5uLARi~I#wIIb#xi0&x2sF6NZ`)c>T9v}_VPkt@&p4S70s%Kk@rKB4p(KSiz^i=SG+nkNO>9qsBoZYwC{Ac-'
        'q>xCg(BNnx;dr6p5kulJLxZA*2F48uMh*>%9Xd98=!p2CArVB!#1M%_5gi{##08SHx%6cYP>MXJx!zcKk}Xx$G*gu|W4X{xbFq|7'
        '7DdH1!gCX|F+OzQ=sabOV@Fq7vg4+tB6^lWpIh<U%V9K%%q6e<_%JZZz9(6kZ6ET+CHZaReUz1LhYJSUTIM6otC#nl2S@po3VE(?'
        'AIjqNXTsW)GQ%UGHdo?jzCgY1(y&37Xe)oR7S~I)bzZ22@gkJs=L9d$DNLSIm^?!Oo*@8NYzV64UO_uh?T|qghz?Hp*wiHL;$DmO'
        '1gIVt&vZMDCw$pq$u)OyuXI<_R;I1D+Ywl9%Clv(N#Yu>ar=`i&lO&Fa;fJ%R2ALSmztq3+t<NLz`Vv?k`fLI;(WqmWO`@U{W_I^'
        'R!U3Ktg21PSjzdTD2M2=Y0<MzY5~Ed#vNfF<JVilGnuM*CLVi?a=+JBGzgQJAgc!(Ao9Dzy>8c?mB{Cctf@;=UM@97gTOs>qxE0N'
        'pZ&|P|J>f@^&S}BBE9;~{yF|}IhQT4IxQ8`GF5Y_vSkw9#~ndH8exabuRn!fyBGJ~3`(u5T?<roO;<D>?1HK}x3uNb>|Gt1)K7`^'
        '+mKboGz?A0G{$ZCxL7+yXsdgQ&36q!4rrucI1k=@C>iT`&Tj9Vz);8Z_lVp-Pg+7`H(ro^tdsbDziB@Fi`KFyR8XfPa|3;g2wJGx'
        '$BCaU`+B(p|3@B%%laPoSm3M+SD22CbG_<B7JlrjPC9AiMW_@T`!f*2p=QoJlS-$u-'
        '{x~HJwXta0{$u}EI;`?B6PsciV5ndvd0D+5_veL6T3IDe`9<TnHVwcu_6Lud+-'
        'uGZp4W;`8nn+0w)ESd@d7Jjn3v#cfL;&CMZTiS#kBd$+oF>TtL7n_WQ4$!&Jo6Nd1<p;l;E{)JZzc+-e2D?gQ{)-'
        '=|e}I`UdhWX%_&vs)++`;cxfa&B3vHXGM!-R}02A2j<EW#@e{4`Y5Y0OoO+kl<L(agoG@5p4w`CM9-'
        'UTsIzMN|a8%Z?1DlCzQDgRp8tlb_!=XyV;mWU(Cyq3nmx#ZlsXwDymQPs!{Qr`*uhY43x$A!XP?ag3tvH5AZHHs}QA^BXVIt-'
        '9<gad?uc=tqWo1mn>mT{Lu8xE+$5_dncG)_$%JTvtEJgkJx9)zl6I6p!V-'
        'Cg48Y|QT?a~SIab7+lZT846PqdbzLWavKpGl{petxZo#R<i$j_AB)&tZN5D=mM#W(mq?e$0){K19ThJdLU3<dW1X~B3F%IBYCP*Y'
        'FD#4LQ_CmzB3o^u}*tl~D(PbLzroM7L^FtASnWlH_O_*^kpG=`2U5fXka_hyZ8-$^A8Agw6TJTl_s1iGwC-'
        'x2ZkoRT1GNACDdluJ)9m{|Wg5Zx=|BIls0EEPad=znwT3d)Uu^wiIx<2SA9_!VAZ$WuA-'
        'B`R1mEj4<`$b}Y3~aj%O65jpiWr8}j&ZogZ<QM_oZ+;&`Q;g~g34Q57P86VGyIhOWzS81smLvTmo{4-'
        '5W2SHy5k7oMr^`+Zie>^R74<7c#|>07(Xkbhtibww0Aoxrd$b+LRhZYb}E%Dz>765p!%)8$0hfR1_u^B#Y(zlK~>xjSe#Nv?{%yL'
        '{R#gI7P%riR&M4L9H%rq(#ux(BwX1RL<eZI9U3~feYZPM>n;B9C6`lI4p5d^SI;G%Q6}~u=3Aoh?vnlQb2>4(zy72R15AF+QC%I8'
        '>WTe9XAf{79rOSVUVYd3ePN*K=;7yo_J^Gld@mos;{J*$tn>4l5Z>O1yp8Rv_<83EMV%+~)AoA~zvf=a_6Asy@0@xL^=j|o)o(h#'
        'Pf6YjZmpbi)$AZ?83<WEs$xgp4a7de3EOuF;#tO5-'
        '^*F#rGm~@mr8sl8^}=s@*7U&6S)tS_yx1t2Kz~j9Oc|V1Uw}8JxE=Ey^=$|cOZMw0aBkNlT9jum&4DZrIKvBfQZM4jA@^f1F4#bj'
        'N>66OB`fMyLgYCD^57otit%B4i2VMs|R&Ob>M2Vz5$P8dJM6qQ|-'
        'DJgA5EgpAblp(_nndsZ=q1lb9syga}2zqOu6sRP#t7Z5W(MMriJ2)5z2v*o{(1nC4VKtqXuQ-'
        'Z~x;IuBXCt4X$<gwsyU7*ZUE<zANTvr8c5A(@Sf!qC3M!T0F8>(P{t5@gxSEg}=a89BlnXnyNWg!7|qNZPi^M7c1GAI>GaO?Bda0'
        'EQrY6*%d${l7{XTWGd|9)J!$%{6GY*`IrYksATY+FUiTHHFjaORmZ6)i*zUL(C)U+~PLy;vHEYHx&tK@zQ=TBt`~a!VMBdU*rkNh'
        'Qc*aA(te#?fXCc=D+rD1NyjcA7C;vj3K-'
        'Ypn`!`Pp+@@Uiin(dnvz`?DmJ>eAifoh<*KRrwt+Z)?}wGiypRNp82TdqmEhdkPUOvBUa|t^L>6>?(=f4KVRo3eVx^FUFTLG=<@-'
        'OdccdhVm#mB@sGGyxA~(&o$1K+^D)kMq;w|ySz3@+4vuQEke8~d_a}4u5c0?D{_j8j@by<cd4_s2E$Iun{tvUmoJ33g*{k{zDD@B'
        'WnVt5ot8+)y0V{g-w;$U?-'
        '+tVxjNXBKJ4fTNS4#Tqhp)f=;p^|mTz8LGfXmFfIacRY73G(LL$vCoCmu(^DIe>1gqNM`45MmFV^oztYA=I&^$(AsYEyuW?s{o<m'
        'iAEXLe+&X>fitH^*2BK=D+>$_3s{$UCo*|SROe~tAFhO*`L$x7g{H)oi7w)3AU^L!9D_J&^^`%ou?+UnIB~g=iI}*`rA{SnL?czz'
        '7C4O;NKA1<OxC2?|(&-A$BHV#1D7pnJzR%<ch3qe#SJI-@p8)f5`BeOLmH%KQ4`+$npHY|MC0379oV*CtYL2rxQYf-r@9;m4vF7-'
        'vR%T3weHX+%Sd()x|ynM}-<G029qZ8@_1NDT&;;sQdJp8{R}{?ccZ#cxQ>tn<VnRxoa{pNQVkSG$~<}W$?qHQ=~-'
        'DE`~(O*$iyvBVs<rUn%;^khPU7dkFa}%RxG12{w_cS;$pavgT>#QukDEsd?UF=`B>#*EMhHnb@KLuS2y(#RiqzgR!76dSjK6lein'
        '$8hYtO4A>$t>qD`tynqvpN|fT=K8Ig13Ii!k1+dVF{7h?%7`^;U<Q5Q1@-_E3p|(_vOVY3>Qvh<=k#QX-a9-'
        '#BPaY6kqEj&&rUGeGn@CRy|ClFK#`coM(y}ytVKsXq`veqk0|qpXvXsTkhM-kn&K`vTTHg;_&+6d&IN35T&6Z|`j5^LZbXJHcIDh'
        'sZKK$rkzyHyn{A8ASif1)X@htbL%<hyQ&!QMAzPSPRDfxjrdohEA*a#ORD@hdgYlrqh0UIy>8kVw&JqXms;}tHETE#0UxJAmP;p>'
        '|<YIj=K?-'
        '3AIRT!>zkE#Y4(m0@MH)MYeQpG!z;3GjPx&Ui`fKf)yZF%mBrO8$ac9gO?mRZ_s;)z5epK1J{M6l@lxCYzp!nI4V4RG1O+l8~R=O'
        'x_o6e9Hmn^KMdWbY(N00Z>|5im7yN0QP}us`w6USVYLrpZ(as68+@IKK#o(|2(P%rUV8%q}*oxz_Ajk@9FM3C%Bev8K03<hU6`ro'
        '?;$8H%+fb>AT8_bs6HImu>$=XyBv4XWL0auX~%mv3I<jnt8Yblez}k5b^exCkTMuq_)3z|^VZG^sM`+j;#v*MWj(oR({hX|plO5@'
        'ATwDfBqWmhB`}=!9KnSjUostn){<i$wd`&4`n(b*v9i$F9*Y-'
        '4w4APO@IuP+2S%D!&;_d5;Yzq#fNA4o|EPrC63hVV@ht{YXhaLIDah9*F{j!^(>3)q7P9U8YAaE4(#^*J<RnlsNZL(Gn8Z1N0?7z'
        'Lc{N*CA0A_0DuyO8YKDVL)y-'
        '1*wupA44t)Y$#5g9Dl6f5_j}5=LP2OgFV3+l%?KGQ>EMDMErn^$hWf~2#Ux#yIWr1dk5wOBuc`$RaK`W9I_nz^^Jgc&uB+svmBNC'
        '_+e{`i>GSiCw+s<PZVD@YlOnP;-vT?u@k%%{5DV*A<B5gCk;jeWl4iADu-xtM0N_z-'
        '?QflA8oX!cxi1)6%(y#*1&jNlFPsbuAi0R07551Y{^e+tx3@dhD#FIfsJVfigDVNP`FqwJp^gp6~|S4U0Lats#pudMaIfqf{dt|D'
        '+euBzPFH_CH##cy9)A5xY4?S0Ey6C3t*E=CQtB}#W1?HLaO8IfKxDhUv&%x84F)us@BS1$spGlGV&bPv^2vvk-'
        '1!%s%tu~BU_d$TS$|*=S~EJqBNpZVMemZ84#Yxo*yDy(Q`!*YxRw)QeoSzLJ~B>m@GJ*qO>HRW{TRi4v=*Q-'
        '>R25l`>5M_rgz;ZPg{Ycn>QmD|?V)w{64bZ(>(>G}*Rwg&!6YrXo3aAVc8&ka#PAB|bmF&rk646a4%H*I982H)iWJ%o&B$e^b0tO'
        '@l^FbAkvBpg_#H+lR}v3jF`%X@m!r08@`uM#)4nt*+AazIdm}S8FwkT^!|EDl}{$mHjal)}E_;h2B`{i=cA5b(2v;6%y#UG%Z!Ht'
        'EIb+y7Vm5bHSyj$_p?uJDR4d@VMe~$4f==p>~T353aH@7M>y-'
        's<+ZC1ud7d;w>clO)c<;HrTvyc#))O8Uizr?5%u71<63s{FS4629!#%Oa=N^Tz`d32lE+A^(@CSprQ&wDokeKuhho7`x2P8v)hFM'
        '$LBBM5$)mTF{uVcC-I^+YjLHB*7V!VY*2p$rCig6F+WmXz}<$cR6FxhdAB>1`54N4Ck;zR>%1ybE-'
        'p$%3nEs9dKEJql327cje<#%OX)#ftZXCmKVgGUxfIVS%m`)G4JV_{vQ4d+R&M4i#ZJ4BH9=;^j0@)$KwfzfbEN4ktLydS87Zwk!{'
        ')mgc|&JGI;&X_X0bopZ_uog<7T-DahBW4-'
        'pS8WN@BRog*2S*4_;=#$^QNb(@<s8O(SOqA>Ei&a2XnIbkn#aWgjk}haHFtt&vr^sd*_q5XQ>w1SaE#hqRHpv1C9{I=vaz*Ru%5E'
        'cIApoka1ma<X-5Kh_8bNDf4dZ1fGR-'
        '!aMnSHEuW)PdL4JtDIQD^pH2*qY^sIjX)qkwQkMHoUrUl%P);@>0T{gPia{9B{(8Y0u1q_t9OcnS4?m3whoXk~{#mZjBNMxFDHEK'
        'y6duwFb^=f+gOR-KF7x=H*!)l*ZB*3kw6gtrbAMW!d*Nv{01Q%F}dUyXtCbErv3xY$8EQa-ZZdcltDd1+D@QR?)H;n0uUL+Kybe^'
        '<e`ztxDAgEG{lKP$rP54|a<L57pY1Kj4dyHiyj^MrvpA8(bnFBuwwHxzJ40UoBUvk7QT%T@Owc=}TWW;4NI5pnw|4@_k>i07DN}c'
        '^BNLrmX9R2GDvZbIkDsoodJ%EdSozWzSvyOee5;dBzo~^w!*vB?7B08{_>s<mxEI)siVI?|k{r{|8m8F?j'
    ))
    assert len(raw)==127844 and hashlib.sha256(raw).hexdigest()=='24136301c403b0319759d054f3393a83843fcc70fbe7bfd24a7bedab6d6cb9b6'
    return raw if original_bytes else json.loads(raw)


def publication_owner_read(tmp_path,plan,*,budget=None):
    m=module();launch=copy.deepcopy(request()['launch']);launch['execution_id']='execution-1'
    work=tmp_path/'original';work.mkdir();launch['remote_workdir']=str(work)
    for role,name in m.FILES.items():
        raw=m.encoded(plan) if role=='plan' else b'{}'
        (work/name).write_bytes(raw)
        launch['files'][role]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    policy=dict(jobs_root=str(tmp_path),client_uid=os.getuid(),limits={**limits(),'metadata_bytes':8*1024**2})
    budget=budget or m.Operation(policy['limits'])
    return m._owner_read(policy,launch,budget),budget


@pytest.mark.parametrize('fault',[None,'ordinary','foreign_execution','extra','purpose','label','point','shape','telemetry',
    'configuration','model_hash','scientific_fingerprint','history_order','history_append','fragment','unknown_source','rule_origin','relative_source'])
def test_publication_original_reader_derives_only_complete_source_profile(tmp_path,fault):
    m=module();plan=publication_fixture_plan();execution=plan['executions'][0]
    if fault=='ordinary':plan={'schema':'ordinary-plan'}
    if fault=='foreign_execution':execution['id']='other-execution'
    if fault=='extra':plan['engineering_fixture']='native-publication-v1'
    if fault=='purpose':execution['purpose']='production'
    if fault=='label':execution['label']='ordinary'
    if fault=='point':plan['points'][0]['initialization']='continuation'
    if fault=='shape':execution['resolved_configuration']['numerical']['energy_nodes']=11
    if fault=='telemetry':execution['output']['telemetry']['enabled']=True
    if fault=='configuration':execution['resolved_configuration']['physical']['donor_sheet_density']='1e12 m^-2'
    if fault=='model_hash':plan['points'][0]['effective_inputs']['model_sha256']='f'*64
    if fault=='scientific_fingerprint':plan['scientific_fingerprint']='f'*64
    sources=execution['provenance']['sources'];key=next(k for k,v in sources.items() if len(v)>1)
    if fault=='history_order':sources[key].reverse()
    if fault=='history_append':sources[key].append('invented-rule')
    if fault=='fragment':sources[key][0]+='#changed-rule'
    if fault=='unknown_source':sources[key][0]='/relocated/foreign.yaml#same'
    if fault=='relative_source':sources[key][0]='relative/'+sources[key][0].rsplit('/',1)[-1]
    if fault=='rule_origin':execution['resolved_snapshot']['default_rule_sources']['Core:src/domain/types.jl']='f'*64
    if fault in (None,'ordinary'):
        value,budget=publication_owner_read(tmp_path,plan)
        assert value.get('engineering_fixture')==(None if fault=='ordinary' else 'native-publication-v1')
        assert value['files']['plan']['sha256']==hashlib.sha256(m.encoded(plan)).hexdigest()
    else:
        with pytest.raises(m.Hold):publication_owner_read(tmp_path,plan)


def test_publication_profile_allows_only_explicit_locator_prefix_and_capacity_normalization(tmp_path):
    plan=publication_fixture_plan();execution=plan['executions'][0];plan['fingerprint']='e'*64
    execution['resource_estimate']['worker_capacity']=7
    histories=[execution['provenance']['sources']]+[s['input_assigning_histories'] for s in execution['resolved_snapshot']['sections'].values()]
    for history in histories:
        for key,values in history.items():
            history[key]=['/independent/prefix/'+v.rsplit('/',1)[-1] if v.startswith('/') else v for v in values]
    value,budget=publication_owner_read(tmp_path,plan)
    assert value['engineering_fixture']=='native-publication-v1' and budget.bytes<8*1024**2


@pytest.mark.parametrize('value',['native-publication-v1',None,'','unknown',True,{}])
def test_publication_protected_runner_scope_is_finite(value):
    m=module();runner=p20_runner();runner['engineering_fixture']=value
    if value=='native-publication-v1':assert m._output_runner(runner)==runner
    else:
        with pytest.raises(m.Hold):m._output_runner(runner)


def test_publication_engineering_qualification_cannot_review_ordinary_stock_script(monkeypatch):
    m=module();sources=m.NativeSources({'jobs_root':'/srv/qcl-negf/jobs'},m.Operation(limits()))
    monkeypatch.setattr(sources,'origin',lambda path:path)
    runner=p20_runner();runner['engineering_fixture']='native-publication-v1'
    sources.qualification=dict(completed_final=dict(runner=runner))
    launch=request()['launch'];launch.update(release_id='fixture-release',execution_id='execution',relative_execution_root='native/new-domain')
    with pytest.raises(m.Hold):m._review_native_script(NATIVE_ORIGIN_SCRIPT,launch,'/nix/store/synthetic/bin/qcl-negf',
        '/bin/bash',sources,calcjob_uuid=NATIVE_ORIGIN_CALCJOB)


def publication_metadata_profile():
    """Full real plan plus explicit synthetic metadata, with honest failed science."""
    m=module();launch,inputs,raws=p20_metadata_profile();docs={name:json.loads(raw) for name,raw in raws.items()}
    plan=publication_fixture_plan();docs['plan.json']=plan;launch['execution_id']='execution-1'
    inputs['runner']['engineering_fixture']='native-publication-v1'
    plan_raw=m.encoded(plan);sha=hashlib.sha256(plan_raw).hexdigest()
    native=docs['native-execution.json'];native['execution_id']='execution-1';native['input_plan'].update(bytes=str(len(plan_raw)),sha256=sha)
    spec=docs['capture-spec.json'];spec['selection'].update(execution_id='execution-1',plan_fingerprint=plan['fingerprint']);spec['plan'].update(bytes=len(plan_raw),sha256=sha)
    docs['capture-source.json'].update(execution_id='execution-1',plan_fingerprint=plan['fingerprint'])
    result=docs['series_result.json'];result.update(status='failed',plan_fingerprint=plan['fingerprint'],plan_scientific_fingerprint=plan['scientific_fingerprint'],selected_execution_id='execution-1')
    result['executions']=[dict(id='execution-1',point_ids=['point-1'])]
    point=result['points'][0];point.update(id='point-1',execution_id='execution-1',status='failed',quality='invalid',converged=False,
        warnings=[dict(code='SYNTHETIC_NATIVE_PUBLICATION_FIXTURE',scope='execution',message='synthetic; not_scientific; constructor-only; no SCBA/Poisson')],observables=dict(scientific_accepted=False))
    point['data'].update(optical_attachment=None,phase_source=dict(status='disabled',session_id=None,current_path=None,reason='synthetic_fixture'))
    state=point['data']['native_source']['selected_state'];state['identity'].update(execution_id='execution-1',point_id='point-1',plan_sha256=sha,
        model_sha256=plan['points'][0]['effective_inputs']['model_sha256'])
    row=docs['native-selection.json']['selected_inputs'][0];row['selected_state']=copy.deepcopy(state);row['plan'].update(bytes=str(len(plan_raw)),sha256=sha)
    raws={name:m.encoded(value) for name,value in docs.items()}
    for role,name in m.FILES.items():
        raw=raws.get(name,b'fixed script fixture');launch['files'][role]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    return launch,inputs,raws


@pytest.mark.parametrize('fault',[None,'ordinary_r','ordinary_plan','completed_result','completed_point','quality','converged','accepted',
    'warning_missing','warning_scope','warning_message','declaration','phase','optical'])
def test_publication_metadata_requires_honest_failed_science_and_exact_original_scope(fault):
    m=module();launch,inputs,raws=publication_metadata_profile();docs={name:json.loads(raw) for name,raw in raws.items()}
    result=docs['series_result.json'];point=result['points'][0]
    if fault=='ordinary_r':del inputs['runner']['engineering_fixture']
    if fault=='ordinary_plan':docs['plan.json']['root_definition_id']='ordinary'
    if fault=='completed_result':result['status']='completed'
    if fault=='completed_point':point['status']='completed'
    if fault=='quality':point['quality']='accepted'
    if fault=='converged':point['converged']=True
    if fault=='accepted':point['observables']['scientific_accepted']=True
    if fault=='warning_missing':point['warnings']=[]
    if fault=='warning_scope':point['warnings'][0]['scope']='point'
    if fault=='warning_message':point['warnings'][0]['message']='scientific success'
    if fault=='declaration':result['selected_execution_id']='foreign'
    if fault=='phase':point['data']['phase_source']['status']='available'
    if fault=='optical':point['data']['optical_attachment']={'present':True}
    raws={name:m.encoded(value) for name,value in docs.items()}
    if fault=='ordinary_plan':
        # Rebind every raw claim too; a coherent ordinary input cannot borrow R scope.
        sha=hashlib.sha256(raws['plan.json']).hexdigest();launch['files']['plan'].update(bytes=len(raws['plan.json']),sha256=sha)
        native=docs['native-execution.json'];native['input_plan'].update(bytes=str(len(raws['plan.json'])),sha256=sha)
        raws['native-execution.json']=m.encoded(native);launch['files']['native_execution'].update(bytes=len(raws['native-execution.json']),sha256=hashlib.sha256(raws['native-execution.json']).hexdigest())
    budget=m.Operation({**limits(),'metadata_bytes':8*1024**2})
    if fault is None:
        proof=m._completed_metadata(launch,inputs,raws,(11,12),budget=budget)
        assert proof['selected_points']==1 and json.loads(raws['series_result.json'])['points'][0]['observables']['scientific_accepted'] is False
    else:
        with pytest.raises(m.Hold):m._completed_metadata(launch,inputs,raws,(11,12),budget=budget)


@pytest.mark.parametrize('fault',[None,'ordinary_r','ordinary_command','unset','legacy','extra','unquoted','wrong_uuid'])
def test_publication_script_keeps_exact_eleven_native_arguments_and_protected_scope(monkeypatch,fault):
    m=module();sources=m.NativeSources({'jobs_root':'/srv/qcl-negf/jobs'},m.Operation(limits()));monkeypatch.setattr(sources,'origin',lambda path:path)
    runner=p20_runner();runner['engineering_fixture']='native-publication-v1'
    if fault=='ordinary_r':del runner['engineering_fixture']
    sources.qualification=dict(completed_final=dict(runner=runner))
    launch=request()['launch'];launch.update(release_id='fixture-release',execution_id='execution-1',relative_execution_root='native/new-domain')
    raw=NATIVE_ORIGIN_SCRIPT.replace(b"'run-plan'",b"'native-publication-fixture'").replace(b"'execution'",b"'execution-1'")
    raw=raw.replace(b'unset QCL_NEGF_CAPTURE_SPEC',b'export QCL_NEGF_CAPTURE_SPEC=capture-spec.json QCL_NEGF_NATIVE_CAPTURE_INPUT=native-execution.json')
    if fault=='ordinary_command':raw=raw.replace(b"'native-publication-fixture'",b"'run-plan'")
    if fault=='unset':raw=raw.replace(b'export QCL_NEGF_CAPTURE_SPEC=capture-spec.json QCL_NEGF_NATIVE_CAPTURE_INPUT=native-execution.json',b'unset QCL_NEGF_CAPTURE_SPEC')
    if fault=='legacy':raw=raw.replace((" '--native-execution' 'native-execution.json' '--native-calcjob-uuid' '"+NATIVE_ORIGIN_CALCJOB+"'").encode(),b'')
    if fault=='extra':raw=raw.replace(b"  >",b" '--arbitrary'  >")
    if fault=='unquoted':raw=raw.replace(b"'native-publication-fixture'",b'native-publication-fixture')
    if fault=='wrong_uuid':raw=raw.replace(NATIVE_ORIGIN_CALCJOB.encode(),request()['calcjob_uuid'].encode())
    def check():return m._review_native_script(raw,launch,'/nix/store/synthetic/bin/qcl-negf','/bin/bash',sources,
        calcjob_uuid=NATIVE_ORIGIN_CALCJOB,engineering_fixture='native-publication-v1')
    if fault is None:assert check() is None
    else:
        with pytest.raises(m.Hold):check()


@pytest.mark.parametrize('fault',[None,'late_metadata','late_plan','cancel'])
def test_publication_actual_held_fd_requalification_keeps_originals_and_late_guards(q1_joined,monkeypatch,fault):
    # Exercise the real private fork, full original metadata, W1 handshake,
    # original close pair and checked FD cleanup; no live-site source authority.
    metadata=publication_metadata_profile()
    monkeypatch.setattr(sys.modules[__name__],'p20_metadata_profile',lambda:copy.deepcopy(metadata))
    test_original_closed_bytes_requalify_through_actual_private_child_metadata(q1_joined,monkeypatch,fault)


@pytest.mark.parametrize('fault',['budget','duplicate','depth','cardinality'])
def test_publication_original_parser_prepays_and_refuses_malformed_input(tmp_path,monkeypatch,fault):
    m=module();raw=m.encoded(publication_fixture_plan());launch={'execution_id':'execution-1'}
    budget=m.Operation({**limits(),'metadata_bytes':8*1024**2})
    if fault=='budget':
        budget.limits['metadata_bytes']=1
        monkeypatch.setattr(m,'strict_json',lambda raw:pytest.fail('decoded before full prospective charge'))
    if fault=='duplicate':raw=b'{"root_definition_id":"native-publication-fixture-v1","root_definition_id":"ordinary"}'
    if fault=='depth':raw=b'{"root_definition_id":"native-publication-fixture-v1","nested":'+b'['*66+b'0'+b']'*66+b'}'
    if fault=='cardinality':raw=b'{"root_definition_id":"native-publication-fixture-v1","nested":['+b'0,'*16385+b'0]}'
    with pytest.raises(m.Hold):m._submitted_plan_mode(raw,launch,budget)
    assert budget.bytes>0


@pytest.mark.parametrize('fault',[None,'ordinary_r','ordinary_plan','ordinary_script'])
def test_publication_original_preflight_derives_mode_before_fixed_script(actor_bridge,monkeypatch,fault):
    s=actor_bridge;m=s['m'];source=s['sources'];launch=s['document']['launch'];files=s['files'];native=s['native']
    files['plan']=m.encoded(publication_fixture_plan()) if fault!='ordinary_plan' else b'{"schema":"ordinary"}'
    native['input_plan'].update(bytes=str(len(files['plan'])),sha256=hashlib.sha256(files['plan']).hexdigest())
    files['native_execution']=m.encoded(native)
    script=native_origin_bridge_script(s).replace(b'unset QCL_NEGF_CAPTURE_SPEC',b'export QCL_NEGF_CAPTURE_SPEC=capture-spec.json QCL_NEGF_NATIVE_CAPTURE_INPUT=native-execution.json')
    if fault!='ordinary_script':script=script.replace(b"'run-plan'",b"'native-publication-fixture'")
    files['submit_script']=script
    launch['files']={key:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()) for key,raw in files.items()}
    s['actor_launch'].update(copy.deepcopy(launch))
    runner=p20_runner()
    if fault!='ordinary_r':runner['engineering_fixture']='native-publication-v1'
    source.qualification['completed_final']=dict(runner=runner)
    def originals(policy,actual,budget):
        assert actual==launch and budget is source.budget
        return dict(files=launch['files'],script=base64_script(script),
            engineering_fixture=m._submitted_plan_mode(files['plan'],launch,budget))
    monkeypatch.setattr(m,'_read_submitted_files_as_owner',originals)
    def check():return source.preflight(launch,source.budget,calcjob_uuid=s['document']['calcjob_uuid'],action='submit')
    if fault is None:assert check()==s['host'] and source.budget.bytes<source.budget.limits['metadata_bytes']
    else:
        with pytest.raises(m.Hold):check()
        assert not hasattr(source,'_actor')


def publication_fork_originals(tmp_path):
    """Owned regular originals and actual reader/strict profile; no native authority."""
    m=module();folder=tmp_path/'fork-originals';folder.mkdir()
    launch={'execution_id':'execution-1','remote_workdir':str(folder),'files':{}}
    for role,name in m.FILES.items():
        raw=m.encoded(publication_fixture_plan()) if role=='plan' else b'{}'
        (folder/name).write_bytes(raw)
        launch['files'][role]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    return launch,dict(client_uid=os.getuid(),jobs_root=str(tmp_path),limits={**m._bootstrap_operation().limits,'metadata_bytes':8*1024**2})


def publication_real_fork_seam(monkeypatch):
    """Only drop-credential authority is synthetic; retain real fork/pipe/FDs."""
    m=module();uid=os.getuid;euid=os.geteuid;owner=m._owner_read;parent=os.getpid()
    def actual_owner(*args,**kwargs):
        assert os.getpid()!=parent
        m.os.getuid=uid;m.os.geteuid=euid
        return owner(*args,**kwargs)
    monkeypatch.setattr(m,'_owner_read',actual_owner)
    monkeypatch.setattr(m.os,'geteuid',lambda:0)
    monkeypatch.setattr(m.os,'setgroups',lambda value:None)
    monkeypatch.setattr(m.os,'setgid',lambda value:None)
    monkeypatch.setattr(m.os,'setuid',lambda value:None)


@pytest.mark.parametrize('next_action',['reserve','retry'])
def test_publication_real_fork_preserves_full_debit_in_inherited_operation(tmp_path,monkeypatch,next_action):
    m=module();launch,policy=publication_fork_originals(tmp_path)
    direct=m.Operation(policy['limits']);expected=m._owner_read(policy,launch,direct)
    assert direct.bytes>2*1024**2
    parent=m.Operation(policy['limits']);parent.reserve(3*1024**2);before=parent.bytes
    publication_real_fork_seam(monkeypatch)
    observed=m._read_submitted_files_as_owner(policy,launch,parent)
    assert observed==expected and parent.bytes-before>=direct.bytes
    assert parent.actual_bytes>=sum(row['bytes'] for row in launch['files'].values())
    assert not hasattr(parent,'_owner_read_credit')
    charged=parent.bytes
    with pytest.raises(m.Hold):
        if next_action=='reserve':parent.reserve(policy['limits']['metadata_bytes']-charged+1)
        else:m._read_submitted_files_as_owner(policy,launch,parent)
    assert parent.bytes>=charged
    if next_action=='retry':assert parent.bytes<=parent.limits['metadata_bytes']


@pytest.mark.parametrize('failure',['profile','child_cancel','parent_cancel','parent_cancel_close'])
def test_publication_real_fork_failure_or_cancel_never_returns_free_credit(tmp_path,monkeypatch,failure):
    m=module();launch,policy=publication_fork_originals(tmp_path)
    if failure=='profile':
        path=Path(launch['remote_workdir'])/'plan.json';plan=json.loads(path.read_bytes());plan['name']='wrong profile'
        raw=m.encoded(plan);path.write_bytes(raw);launch['files']['plan']=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    budget=m.Operation(policy['limits']);budget.reserve(3*1024**2);before=budget.bytes
    primary=KeyboardInterrupt('original profile cancellation');parent=os.getpid();original=m._native_publication_fixture_mode
    if failure=='child_cancel':
        def cancel(*args,**kwargs):original(*args,**kwargs);raise primary
        monkeypatch.setattr(m,'_native_publication_fixture_mode',cancel)
    reserve=budget.reserve
    cancelling={'active':False,'closed':False};close=os.close
    if failure.startswith('parent_cancel'):
        def debit(size):
            reserve(size)
            if os.getpid()==parent and size==655360:
                cancelling['active']=True;raise primary
        monkeypatch.setattr(budget,'reserve',debit)
    if failure=='parent_cancel_close':
        def closing(fd):
            selected=os.getpid()==parent and cancelling['active'] and not cancelling['closed']
            close(fd)
            if selected:
                cancelling['closed']=True;raise OSError('secondary original pipe close')
        monkeypatch.setattr(m.os,'close',closing)
    publication_real_fork_seam(monkeypatch)
    with pytest.raises(KeyboardInterrupt if failure!='profile' else m.Hold) as caught:
        m._read_submitted_files_as_owner(policy,launch,budget)
    if failure.startswith('parent_cancel'):assert caught.value is primary
    if failure=='parent_cancel_close':assert cancelling['closed'] and primary.__notes__
    assert budget.bytes-before>2*1024**2 and not hasattr(budget,'_owner_read_credit')
    paid=budget.bytes
    monkeypatch.setattr(budget,'reserve',reserve)
    monkeypatch.setattr(m,'_native_publication_fixture_mode',original)
    with pytest.raises(m.Hold):m._read_submitted_files_as_owner(policy,launch,budget)
    assert paid<=budget.bytes<=budget.limits['metadata_bytes']


@pytest.mark.parametrize('kind',['ordinary','whitespace'])
def test_original_real_fork_keeps_ordinary_json_and_parent_accounting(tmp_path,monkeypatch,kind):
    m=module();launch,policy=publication_fork_originals(tmp_path);path=Path(launch['remote_workdir'])/'plan.json'
    raw=b'{"ordinary":true}'
    if kind=='whitespace':raw+=b' '*(1048576-len(raw))
    path.write_bytes(raw);launch['files']['plan']=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    direct=m.Operation(policy['limits']);expected=m._owner_read(policy,launch,direct)
    budget=m.Operation(policy['limits']);before=budget.bytes
    publication_real_fork_seam(monkeypatch)
    result=m._read_submitted_files_as_owner(policy,launch,budget)
    assert result==expected and result['engineering_fixture'] is None
    assert budget.bytes-before>=direct.bytes and budget.actual_bytes>=len(raw)+6
    assert budget.bytes<=budget.limits['metadata_bytes'] and budget.files>=direct.files



def publication_preflight_accounting_case(tmp_path,monkeypatch,*,cap,raw=None):
    """Real bootstrap/load-policy/preflight/owner child on SOURCE/L operands.

    Actual protected-root/caller/actor authorities are synthetic. The protected
    JSON read_fd, actor reply/command/decoder prepay, original FD/strict JSON,
    private fork/pipe/debit and inherited counters remain the production code.
    """
    m=module();real_reader=m._read_submitted_files_as_owner
    state=actor_bridge.__wrapped__(monkeypatch);source=state['sources'];launch=state['document']['launch']
    files=state['files'];native=state['native'];folder=tmp_path/'jobs';work=folder/'upload'/'one';work.mkdir(parents=True)
    if raw is None:
        raw=publication_fixture_plan(original_bytes=True);raw+=b' '*(131473-len(raw))
    files['plan']=raw;launch['remote_workdir']=str(work)
    native['input_plan'].update(bytes=str(len(raw)),sha256=hashlib.sha256(raw).hexdigest());files['native_execution']=m.encoded(native)
    script=native_origin_bridge_script(state).replace(b'unset QCL_NEGF_CAPTURE_SPEC',b'export QCL_NEGF_CAPTURE_SPEC=capture-spec.json QCL_NEGF_NATIVE_CAPTURE_INPUT=native-execution.json')
    script=script.replace(b"'run-plan'",b"'native-publication-fixture'").replace(b'/srv/qcl-negf/jobs',str(folder).encode())
    files['submit_script']=script
    launch['files']={key:dict(bytes=len(value),sha256=hashlib.sha256(value).hexdigest()) for key,value in files.items()}
    state['actor_launch'].update(copy.deepcopy(launch))
    for role,name in m.FILES.items():(work/name).write_bytes(files[role])
    policy=dict(schema='qcl-negf.native-attempt-policy.v1',role='controller',private_root='/local/attempts',spool_root='/local/spool',
        socket_path=m.SOCKET,jobs_root=str(folder),native_result_prefix='native',nfs_source='storage:/jobs',storage_identity_file='/protected/storage',
        release_runtime='/protected/runtime',client_uid=3000,daemon_unit='qcl-negf-aiida.service',server_unit_prefix='qcl-negf-native-attempt@',
        slurmd_unit='slurmd.service',tools={key:'/nix/store/'+key for key in ('systemctl','runuser','sbatch','scontrol','slurmd','slurmstepd','python')},
        slurm=dict(cluster='cluster',version='slurm 1',config_file='/fixed/conf',cgroup_scope='/system.slice/slurmstepd.scope'),
        facts_service_config='/protected/facts',worker_routes={'worker':dict(target='facts@worker',known_hosts='/protected/hosts',identity_file='/protected/key',helper='/fixed/rpc',role='facts')},
        qualification_file='/protected/q',limits={**m._bootstrap_operation().limits,'metadata_bytes':cap})
    budget=m._bootstrap_operation();source.budget=budget;trace=[];stage={'name':'bootstrap'};reserve=budget.reserve
    def reserved(size):
        before=budget.bytes;reserve(size);trace.append(dict(stage=stage['name'],bytes=size,before=before,after=budget.bytes))
    monkeypatch.setattr(budget,'reserve',reserved)
    protected=m.protected_read;counter={'value':0}
    def local_read(data,limit):
        counter['value']+=1;path=tmp_path/('protected-input-'+str(counter['value']));path.write_bytes(data)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:return m.read_fd(fd,limit,budget)[0]
        finally:os.close(fd)
    def root_json(path,actual,limit=65536):
        assert actual is budget
        stage['name']='policy' if Path(path)==m.POLICY else 'graph' if '/source-graph-' in str(path) else 'release'
        return local_read(m.encoded(policy) if Path(path)==m.POLICY else protected(path,actual,limit),limit)
    monkeypatch.setattr(m,'protected_read',root_json)
    monkeypatch.setattr(m.os,'geteuid',lambda:0)
    def gate(path,limit=65536):
        stage['name']='admission';return local_read(m.encoded(dict(open=True,release_id=launch['release_id'])),limit)
    monkeypatch.setattr(budget,'read',gate);monkeypatch.setattr(m.engine,'GATE',folder/'.release-admission.json')
    actor=source._actor_read
    def read_actor(kind,*args):stage['name']='actor:'+kind;return actor(kind,*args)
    monkeypatch.setattr(source,'_actor_read',read_actor)
    runner=p20_runner();runner['engineering_fixture']='native-publication-v1';source.qualification['completed_final']=dict(runner=runner)
    reader=real_reader;owner=m._owner_read;uid=os.getuid
    def owner_local(p,*args,**kwargs):
        m.os.geteuid=lambda:uid()
        return owner({**p,'client_uid':uid()},*args,**kwargs)
    monkeypatch.setattr(m,'_owner_read',owner_local)
    monkeypatch.setattr(m.os,'setgroups',lambda value:None);monkeypatch.setattr(m.os,'setgid',lambda value:None);monkeypatch.setattr(m.os,'setuid',lambda value:None)
    def originals(*args,**kwargs):
        stage['name']='originals';value=reader(*args,**kwargs);stage['name']='script';return value
    monkeypatch.setattr(m,'_read_submitted_files_as_owner',originals)
    def check():
        source.policy=m._load_policy('controller',budget)
        return source.preflight(launch,budget,calcjob_uuid=state['document']['calcjob_uuid'],action='submit')
    state.update(check=check,trace=trace,cap=cap,protected_reads=counter,plan_raw=raw)
    return state


@pytest.mark.parametrize('cap',[8*1024**2,16*1024**2])
def test_publication_whole_preflight_loads_policy_and_pays_real_fork(tmp_path,monkeypatch,cap):
    state=publication_preflight_accounting_case(tmp_path,monkeypatch,cap=cap);m=state['m'];source=state['sources']
    if cap==8*1024**2:
        with pytest.raises(m.Hold,match='operation_bound'):state['check']()
        assert not hasattr(source,'_actor')
    else:
        assert state['check']()==state['host'] and source.budget.bytes<=cap
        assert source.policy['limits']['metadata_bytes']==cap
        assert any(row['stage']=='originals' and row['bytes']==655360 for row in state['trace'])
    assert len(state['plan_raw'])==131473 and source.budget.bytes>0


@pytest.mark.parametrize('cap',[16*1024**2+1,32*1024**2])
def test_uniform_bootstrap_never_admits_policy_above_metadata_ceiling(tmp_path,monkeypatch,cap):
    m=module();state=publication_preflight_accounting_case(tmp_path,monkeypatch,cap=cap)
    assert m._bootstrap_operation().limits['metadata_bytes']==16*1024**2
    with pytest.raises(m.Hold,match='policy_limits'):state['check']()
    assert state['calls']==[] and not hasattr(state['sources'],'_actor')
