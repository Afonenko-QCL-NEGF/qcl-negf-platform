"""Source/L only: synthetic protected records/processes, no Slurm or sudo effect."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ops'))

OP = '1b2f9137-3b02-4b3b-a38c-3cebb3a03f5b'
CALC = '11111111-1111-4111-8111-111111111111'
SECOND = '22222222-2222-4222-8222-222222222222'
DISPATCH = '33333333-3333-4333-8333-333333333333'
BOOT = '44444444-4444-4444-8444-444444444444'
D = 128*1024


def gate():
    import host_resource_qualification_gate
    return host_resource_qualification_gate


def sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def fixture():
    import test_native_attempt as a
    launch = a.request()['launch']
    row = dict(launch=launch, demand_bytes=D, vm_id='vm-a',
        solver_executable='/nix/store/solver/bin/qcl-negf', node_name='worker',
        worker_machine_id='b'*32, worker_boot_id=BOOT)
    guard = dict(executable='/nix/store/python/bin/python3',
        argv_prefix=['/nix/store/python/bin/python3', '-I', '-c', 'immutable release launcher'],
        source_path='/nix/store/resource-source/ops/application_release.py', source_sha256='a'*64)
    permit = dict(schema='qcl.host-resource-calibration-jobs.v1', operation_id=OP,
        parent_plan_sha256='1'*64, fence_sha256='2'*64, source_graph_sha256='3'*64,
        capacity_report_sha256='4'*64, client_uid=3000, guard=guard,client_root={**guard,
            'argv_prefix':guard['argv_prefix'][:-1]+['immutable client-root launcher'],
            'source_path':'/nix/store/resource-source/ops/host_resource_service.py'},
        bash_executable='/nix/store/bash/bin/bash', slurmstepd_executable='/nix/store/'+'a'*32+'-slurm/bin/slurmstepd',
        cgroup_scope='/system.slice/slurmstepd.scope',
        slurmd_executable='/nix/store/slurm/bin/slurmd',submit=dict(runuser='/nix/store/runuser',
        sbatch='/nix/store/sbatch',spool_root='/protected/spool'), jobs={CALC:row, SECOND:copy.deepcopy(row)})
    permit['jobs'][SECOND]['launch']['request_id']=SECOND
    actor = dict(calcjob_uuid=CALC, action='submit', launch=launch,
        execution_sha256=launch['files']['native_execution']['sha256'])
    context=dict(machine_id='a'*32, boot_id=BOOT, image_id='/nix/store/image')
    command='/protected/spool/'+DISPATCH+'.sh'
    fields=dict(JobId='42',UserId='qcl-negf(3000)',SubmitTime='2026-11-03T12:00:00',
        Comment=DISPATCH,Command=command,WorkDir=launch['remote_workdir'],Restarts='0',
        NumNodes='1',NumTasks='1',MinMemoryNode='128K',JobState='PENDING',Reason='JobHeldUser',Priority='0',
        StartTime='Unknown',NodeList='(null)')
    generation=sha(dict(controller=context,job_id='42',submit_time=fields['SubmitTime'],
        dispatch_id=DISPATCH,command=command,workdir=fields['WorkDir']))
    creator=dict(job_id='42',cluster='cluster',submit_time=fields['SubmitTime'],
        controller_machine_id=context['machine_id'],controller_boot_id=BOOT,dispatch_id=DISPATCH,
        generation=generation,node_name=None,start_time=None,worker_machine_id=None,worker_boot_id=None)
    snapshot=dict(script_path=command,script_sha256=launch['files']['submit_script']['sha256'])
    intent=dict(dispatch_id=DISPATCH,snapshot=snapshot,context=context,
        native=dict(argv=['/nix/store/runuser','-u','qcl-negf','--','/nix/store/sbatch','--hold',
            '--parsable','--no-requeue','--chdir',launch['remote_workdir'],'--comment',DISPATCH,command],
            script_sha256=snapshot['script_sha256'],owner=dict(actor=actor)))
    return permit,actor,creator,fields,intent


class Observed:
    """Explicit owner-port fixture; no installed implementation is implied."""
    def __init__(self, permit, actor, creator, fields, intent):
        self.permit=permit;self.actor=actor;self.creator=creator;self.fields=fields;self.intent=intent
        self.events=[];self.mirrors={};self.fault=None
    def protect_commitments(self, permit, commitments, phase):
        self.events.append(('protect', phase, tuple(commitments)))
        assert tuple(commitments)==(D,D)
        if self.fault=='capacity':raise RuntimeError('actual aggregate capacity refused')
    def mirror_cas(self, calc, expected, desired):
        self.events.append(('cas',calc,desired['revision']))
        assert self.mirrors.get(calc)==expected
        if self.fault=='cas':raise RuntimeError('partial CAS unknown')
        self.mirrors[calc]=copy.deepcopy(desired)
    def mirror_read(self, calc):
        value=copy.deepcopy(self.mirrors.get(calc))
        if self.fault=='readback' and value is not None and value['enabled']:value['revision']+=1
        return value
    def held_submission(self, calc):
        return dict(creator=copy.deepcopy(self.creator), fields=copy.deepcopy(self.fields),
            intent=copy.deepcopy(self.intent))
    def release_held(self, creator):
        self.events.append(('release',creator['generation']))
        if self.fault=='release':raise RuntimeError('release result unknown')
        return dict(job_id=creator['job_id'],generation=creator['generation'],released=True)
    def closure(self, creator):
        if self.fault=='closure':raise RuntimeError('guard/subtree result unknown')
        return dict(creator=creator,completed_final_sha256='9'*64,terminal_state='COMPLETED',
            whole_subtree_absent=True,guards_absent=True,sudo_absent=True)


def setup_jobs(tmp_path):
    from test_host_resource_qualification import calibration
    q,n,m,c,b,store,e,p,s,r,parent,raw,plan=calibration(tmp_path)
    parent.repository.activate(OP,plan)
    permit,actor,creator,fields,intent=fixture()
    permit.update(parent_plan_sha256=parent.repository.digest(parent.repository.folder(OP)/'plan.json'),
        fence_sha256=parent.repository.digest(parent.repository.directory/'active.json'),
        source_graph_sha256=plan['source_graph_sha256'])
    obs=Observed(permit,actor,creator,fields,intent)
    jobs=gate().QualificationJobs(parent,obs)
    return jobs,obs,permit,raw


def test_finite_authorized_demands_precede_hold_mirror_and_exact_release(tmp_path):
    jobs,obs,permit,raw=setup_jobs(tmp_path)
    jobs.stage(permit)
    assert jobs.commitments()==(D,D)
    assert all(not x['enabled'] for x in obs.mirrors.values())
    jobs.bind_held(CALC)
    assert obs.mirrors[CALC]['creator']==obs.creator
    assert obs.mirrors[CALC]['creator']['start_time'] is None
    jobs.release(CALC)
    assert [x[0] for x in obs.events].index('protect') < [x[0] for x in obs.events].index('release')
    assert jobs.parent.store.state_path.read_bytes()==raw
    assert jobs.commitments()==(D,D)


def test_root_release_intent_is_durable_before_enabled_mirror_and_unknown_ack_is_not_gate_input(tmp_path):
    jobs,obs,permit,raw=setup_jobs(tmp_path);jobs.stage(permit);original=obs.mirror_cas;seen=[]
    def cas(calc,expected,desired):
        if desired['enabled']:
            intent=jobs.repo.read(jobs.path(calc,'release-intent.json'))
            assert desired['release_intent']==intent and desired['release_intent_sha256']==sha(intent)
            assert intent['generation']==desired['creator']['generation']
            seen.append('prepublished-root-intent')
        return original(calc,expected,desired)
    obs.mirror_cas=cas
    jobs.bind_held(CALC);assert seen==['prepublished-root-intent']
    obs.fault='release'
    with pytest.raises(RuntimeError):jobs.release(CALC)
    assert jobs.commitments()==(D,D) and jobs.path(CALC,'release-dispatch.json').exists()
    assert not jobs.path(CALC,'released.json').exists()


def test_interrupted_root_release_intent_cannot_publish_enabled_mirror(tmp_path,monkeypatch):
    jobs,obs,permit,raw=setup_jobs(tmp_path);jobs.stage(permit);original=jobs.repo.exclusive
    def interrupted(path,record):
        if path.name=='release-intent.json':raise OSError('root intent fsync unknown')
        return original(path,record)
    monkeypatch.setattr(jobs.repo,'exclusive',interrupted)
    with pytest.raises(OSError):jobs.bind_held(CALC)
    assert not obs.mirrors[CALC]['enabled'] and jobs.commitments()==(D,D)


def test_new_release_reestablishes_durability_of_original_mirror_and_intent(tmp_path,monkeypatch):
    jobs,obs,permit,raw=setup_jobs(tmp_path);jobs.stage(permit);jobs.bind_held(CALC);synced=[]
    original=jobs.repo.sync_record;release=obs.release_held
    def sync(path):synced.append(path.name);return original(path)
    def releasing(creator):
        assert {'plan.json','active.json','permit.json','bound.json','release-intent.json'}<=set(synced)
        return release(creator)
    monkeypatch.setattr(jobs.repo,'sync_record',sync);obs.release_held=releasing
    jobs.release(CALC)


def test_bounded_evidence_preserves_original_child_membership_and_missing_is_none(tmp_path):
    jobs,obs,permit,raw=setup_jobs(tmp_path);jobs.stage(permit);jobs.bind_held(CALC);jobs.release(CALC)
    before={str(p):p.read_bytes() for p in jobs.folder.rglob('*.json')}
    snapshot=jobs.evidence()
    assert snapshot['permit']==permit and snapshot['permit_sha256']==sha(permit)
    assert set(snapshot['jobs'])=={CALC,SECOND}
    assert snapshot['jobs'][SECOND]['bound'] is None and snapshot['jobs'][CALC]['closed'] is None
    assert snapshot['jobs'][CALC]['bound']['record']['creator']==obs.creator
    ref=snapshot['jobs'][CALC]['release-intent']
    assert ref['sha256']==sha(ref['record']) and ref['path'].endswith(CALC+'/release-intent.json')
    assert before=={str(p):p.read_bytes() for p in jobs.folder.rglob('*.json')}
    assert jobs.parent.store.state_path.read_bytes()==raw


@pytest.mark.parametrize('method',['evidence','commitments','closure_ready','held_argv'])
def test_readonly_child_view_reuses_actual_parent_operation_lock_without_reentering_operation(tmp_path,method):
    jobs,obs,permit,raw=setup_jobs(tmp_path);jobs.stage(permit);jobs.bind_held(CALC)
    with jobs.parent.store.operation():
        original_owner=jobs.parent.store._lock_owner
        if method=='held_argv':
            result=jobs.held_argv(permit['jobs'][CALC]['launch'],obs.intent['snapshot'],DISPATCH)
            assert result is True
        else:getattr(jobs,method)()
        assert jobs.parent.store._lock_owner==original_owner and jobs.parent.store._lock_reentrant is True
    assert jobs.parent.store.state_path.read_bytes()==raw


@pytest.mark.parametrize('fault',['cas','readback','release'])
def test_crash_boundaries_retain_original_intent_and_never_release_twice(tmp_path,fault):
    jobs,obs,permit,raw=setup_jobs(tmp_path);jobs.stage(permit)
    if fault!='release':obs.fault=fault
    if fault=='release':jobs.bind_held(CALC);obs.fault=fault
    with pytest.raises((RuntimeError,ValueError)):
        (jobs.release if fault=='release' else jobs.bind_held)(CALC)
    obs.fault=None
    reloaded=gate().QualificationJobs(jobs.parent,obs)
    with pytest.raises((RuntimeError,ValueError)):
        (reloaded.release if fault=='release' else reloaded.bind_held)(CALC)
    assert sum(x[0]=='release' for x in obs.events)==(fault=='release')
    assert jobs.parent.store.state_path.read_bytes()==raw
    assert jobs.commitments()==(D,D)


@pytest.mark.parametrize('fault',['job_id','submit','dispatch','script','actor','start','hold','argv','generation'])
def test_original_held_creator_and_unchanged_actor_grammar_required(tmp_path,fault):
    jobs,obs,permit,raw=setup_jobs(tmp_path);jobs.stage(permit)
    if fault=='job_id':obs.fields['JobId']='43'
    if fault=='submit':obs.fields['SubmitTime']='2026-11-03T12:00:01'
    if fault=='dispatch':obs.fields['Comment']=SECOND
    if fault=='script':obs.intent['native']['script_sha256']='0'*64
    if fault=='actor':obs.intent['native']['owner']['actor']['engineering_fixture']='native-publication-v1'
    if fault=='start':obs.creator['start_time']='2026-11-03T12:00:02'
    if fault=='hold':obs.fields['Reason']='Resources'
    if fault=='argv':obs.intent['native']['argv'].remove('--hold')
    if fault=='generation':obs.creator['generation']='0'*64
    with pytest.raises((RuntimeError,ValueError)):jobs.bind_held(CALC)
    assert not any(x[0]=='release' for x in obs.events)


def test_revoke_readback_precedes_closure_and_delayed_guard_stays_counted(tmp_path):
    jobs,obs,permit,raw=setup_jobs(tmp_path);jobs.stage(permit);jobs.bind_held(CALC);jobs.release(CALC)
    with pytest.raises((RuntimeError,ValueError)):jobs.close(CALC)
    jobs.revoke()
    assert all(not x['enabled'] for x in obs.mirrors.values())
    assert jobs.commitments()==(D,D) and jobs.closure_ready() is False
    obs.fault='closure'
    with pytest.raises(RuntimeError):jobs.close(CALC)
    assert jobs.commitments()==(D,D)
    obs.fault=None;jobs.close(CALC)
    assert jobs.commitments()==(D,) and jobs.closure_ready() is False
    assert (jobs.parent.repository.directory/'active.json').exists()


@pytest.mark.parametrize('receipt',['closed.json','staged.json','bound.json','released.json','revoked.json'])
def test_corrupt_child_receipts_cannot_remove_demand_or_grant_later_authority(tmp_path,receipt):
    jobs,obs,permit,raw=setup_jobs(tmp_path);jobs.stage(permit);jobs.bind_held(CALC);jobs.release(CALC)
    path=jobs.path(CALC,receipt)
    if path.exists():path.write_text('{"corrupt":true}')
    else:jobs.repo.exclusive(path,{'corrupt':True})
    with pytest.raises((RuntimeError,ValueError)):jobs.commitments()
    assert jobs.parent.store.state_path.read_bytes()==raw


def test_unknown_revocation_keeps_all_demands_and_cannot_replay(tmp_path):
    jobs,obs,permit,raw=setup_jobs(tmp_path);jobs.stage(permit);jobs.bind_held(CALC);jobs.release(CALC)
    obs.fault='cas'
    with pytest.raises(RuntimeError):jobs.revoke()
    assert jobs.commitments()==(D,D) and jobs.closure_ready() is False
    obs.fault=None
    with pytest.raises(RuntimeError):gate().QualificationJobs(jobs.parent,obs).revoke()


def process(pid, ppid, ticks, exe, uid=3000):
    return dict(pid=pid,ppid=ppid,start_ticks=ticks,uids=[uid]*4,
        cgroup='/system.slice/slurmstepd.scope/job_42/step_batch/user/task_0',executable=exe,comm='process',state='S')


def gate_fixture():
    permit,actor,creator,fields,intent=fixture();g=gate()
    mirror=g.mirror_record(permit,CALC,creator,revision=1,enabled=True,
        command=fields['Command'],original_intent_sha256=sha(intent))
    fields.update(JobState='RUNNING',Reason='None',StartTime='2026-11-03T12:00:02',NodeList='worker')
    guard=process(30,20,300,permit['guard']['executable'])
    bash=process(20,10,200,permit['bash_executable'])
    step=process(10,5,100,permit['slurmstepd_executable'],0)
    step['cgroup']='/system.slice/slurmstepd.scope/job_42/step_batch/slurm'
    slurmd=process(5,1,50,permit['slurmd_executable'],0)
    slurmd['cgroup']='/system.slice/slurmd.service'
    argv={30:permit['guard']['argv_prefix']+['guard','--release-id',actor['launch']['release_id'],
        '--solver-executable',permit['jobs'][CALC]['solver_executable']],
        20:[permit['bash_executable'],'/var/spool/slurmd/job00042/slurm_script'],10:['slurmstepd: [42.batch]'],5:['slurmd']}
    hook=dict(phase='prolog',identity={'identity':dict(machine_id='b'*32,boot_id=BOOT)},
        job=dict(fields=copy.deepcopy(fields),raw='original native job'),
        context=dict(unit={'MainPID':'5','InvocationID':'a'*32,'ControlGroup':'/system.slice/slurmd.service','ActiveState':'active'},chain=[slurmd]))
    class Sources:
        def __init__(self):self.rows={x['pid']:copy.deepcopy(x) for x in (guard,bash,step,slurmd)};self.mirror=mirror;self.calls=0
        def process(self,pid):return copy.deepcopy(self.rows[pid])
        def command_line(self,pid):return copy.deepcopy(argv[pid])
        def origin(self,path):return path
        def loaded_guard_source(self,pid):return dict(path=permit['guard']['source_path'],sha256=permit['guard']['source_sha256'])
        def batch_script(self,pid):return dict(path=argv[20][1],sha256=actor['launch']['files']['submit_script']['sha256'])
        def scheduler_job(self,job):return copy.deepcopy(fields)
        def original_prolog(self,job,dispatch):return copy.deepcopy(hook)
        def mirror_read(self,calc):
            return copy.deepcopy(self.mirror) if calc==CALC else g.mirror_record(permit,calc,None,revision=0,enabled=False)
        def protect_commitments(self,p,demands,phase):assert demands==(D,D)
        def current_permit(self):return copy.deepcopy(permit)
        def slurmd_unit(self):return copy.deepcopy(hook['context']['unit'])
        def batch_membership(self,creator):
            return dict(schema='qcl-negf.slurm-job-before.v1',status='pass_live_job_membership',
                identity=dict(machine_id='b'*32,boot_id=BOOT),job_id='42',owner_uid=3000,
                job_cgroup=permit['cgroup_scope']+'/job_42',
                processes=[dict(self.process(pid),exe=self.rows[pid]['executable'],error=None) for pid in (20,10)],
                listpids_rows=[dict(pid=pid,job_id='42',step_id='batch') for pid in (20,10)])
    return permit,creator,fields,hook,guard,Sources()


def test_closed_gate_is_readonly_exact_original_guard_and_prolog():
    permit,creator,fields,hook,caller,sources=gate_fixture();before=copy.deepcopy(vars(sources))
    result=gate().calibration_gate_allowed(caller,hook,fields,permit,sources)
    assert result==dict(schema='qcl.host-resource-calibration-gate.v1',purpose='calibration',allowed=True,
        operation_id=OP,calcjob_uuid=CALC,generation=creator['generation'])
    assert vars(sources)==before and 'ready' not in result and 'RUN' not in str(result)


def test_exact_immutable_python_launcher_alias_must_resolve_to_actual_interpreter():
    permit,creator,fields,hook,caller,sources=gate_fixture()
    launcher=permit['guard']['argv_prefix'][0];actual=launcher+'.14'
    permit['guard']['executable']=actual;caller['executable']=actual;sources.rows[30]['executable']=actual
    sources.mirror=gate().mirror_record(permit,CALC,creator,revision=1,enabled=True,
        command=fields['Command'],original_intent_sha256=sources.mirror['original_intent_sha256'])
    sources.origin=lambda path:actual if path==launcher else path
    assert gate().calibration_gate_allowed(caller,hook,fields,permit,sources)['allowed'] is True


def test_original_sudo_return_schema_is_joined_to_live_rich_process_reader():
    permit,creator,fields,hook,caller,sources=gate_fixture()
    minimal={k:caller[k] for k in ('pid','ppid','start_ticks','uids','cgroup','executable')}
    assert gate().calibration_gate_allowed(minimal,hook,fields,permit,sources)['allowed'] is True


def test_live_process_raw_counters_and_scheduler_runtime_can_change_without_rebinding():
    permit,creator,fields,hook,caller,sources=gate_fixture();read=sources.process;scheduler=sources.scheduler_job
    def counters(pid):
        sources.calls+=1;row=read(pid);row['observations']={'raw_counter':sources.calls};row['state']='R'
        return row
    def runtime(job):
        value=scheduler(job);value['RunTime']=str(sources.calls);return value
    sources.process=counters;sources.scheduler_job=runtime
    assert gate().calibration_gate_allowed(caller,hook,fields,permit,sources)['allowed'] is True


@pytest.mark.parametrize('fault',['terminal_after','zombie_parent'])
def test_terminal_scheduler_or_nonexecuting_parent_refuses_body(fault):
    permit,creator,fields,hook,caller,sources=gate_fixture()
    if fault=='zombie_parent':sources.rows[20]['state']='Z'
    else:
        read=sources.scheduler_job
        def terminal(job):
            sources.calls+=1;value=read(job)
            if sources.calls>1:value['JobState']='COMPLETED'
            return value
        sources.scheduler_job=terminal
    with pytest.raises((RuntimeError,ValueError)):
        gate().calibration_gate_allowed(caller,hook,fields,permit,sources)


@pytest.mark.parametrize('fault',[None,'root_argv','root_origin','root_source','caller_changed','root_changed'])
def test_private_local_ingress_matches_exact_actual_root_and_returned_sudo_caller(fault):
    permit,creator,fields,hook,caller,sources=gate_fixture();row=permit['jobs'][CALC]
    request=dict(schema='qcl.host-resource-calibration-guard-request.v1',release_id=row['launch']['release_id'],
        solver_executable=row['solver_executable'])
    token=base64.urlsafe_b64encode(json.dumps(request).encode()).decode()
    own=dict(process=process(40,35,400,permit['client_root']['executable'],0),
        argv=permit['client_root']['argv_prefix']+['qualification-gate',token],
        source=dict(path=permit['client_root']['source_path'],sha256=permit['client_root']['source_sha256']))
    sources.root_ingress=lambda:copy.deepcopy(own)
    sources.authenticated_caller=lambda:copy.deepcopy(caller)
    sources.guard_context=lambda actual:dict(permit=permit,original_hook=hook,scheduler=fields)
    if fault=='root_argv':own['argv'].insert(-2,'--runtime')
    if fault=='root_origin':own['process']['executable']='/tmp/python'
    if fault=='root_source':own['source']['sha256']='0'*64
    if fault=='caller_changed':sources.authenticated_caller=lambda:{**caller,'start_ticks':caller['start_ticks']+1}
    if fault=='root_changed':
        def changing():
            sources.calls+=1;value=copy.deepcopy(own)
            if sources.calls>1:value['process']['start_ticks']+=1
            return value
        sources.root_ingress=changing
    if fault is None:
        assert gate().read_qualification_gate(request,caller,sources)['purpose']=='calibration'
    else:
        with pytest.raises((RuntimeError,ValueError)):gate().read_qualification_gate(request,caller,sources)


@pytest.mark.parametrize('fault',['before_mirror','prolog','uid','manual','argv','origin','source','script',
    'pid_birth','batch_parent','step','job','submit','dispatch','start','worker','revoked','changed_after','pre_intent'])
def test_same_uid_cgroup_uuid_or_environment_never_substitutes_original_guard(fault):
    permit,creator,fields,hook,caller,sources=gate_fixture()
    if fault=='before_mirror':sources.mirror=None
    if fault=='prolog':hook['phase']='epilog'
    if fault=='uid':caller['uids']=[0]*4;sources.rows[30]=copy.deepcopy(caller)
    if fault=='manual':sources.rows[20]['executable']='/nix/store/python/bin/python3'
    if fault=='argv':sources.command_line=lambda pid:['manual','qualification-gate']
    if fault=='origin':sources.origin=lambda path:'/nix/store/changed'
    if fault=='source':sources.loaded_guard_source=lambda pid:dict(path=permit['guard']['source_path'],sha256='0'*64)
    if fault=='script':sources.batch_script=lambda pid:dict(path='/wrong',sha256='0'*64)
    if fault=='pid_birth':sources.rows[30]['start_ticks']+=1
    if fault=='batch_parent':sources.rows[20]['ppid']=5
    if fault=='step':sources.rows[10]['uids']=[3000]*4
    if fault=='job':fields['JobId']='43'
    if fault=='submit':fields['SubmitTime']='2026-11-03T12:00:01'
    if fault=='dispatch':fields['Comment']=SECOND
    if fault=='start':fields['StartTime']='2026-11-03T12:00:03'
    if fault=='worker':hook['identity']['identity']['boot_id']=SECOND
    if fault=='revoked':sources.mirror['enabled']=False;sources.mirror['revision']=2
    if fault=='pre_intent':sources.mirror['release_intent']=None;sources.mirror['release_intent_sha256']=None
    if fault=='changed_after':
        original=sources.current_permit
        def changed():
            sources.calls+=1;value=original()
            if sources.calls>1:value['source_graph_sha256']='f'*64
            return value
        sources.current_permit=changed
    with pytest.raises((RuntimeError,ValueError,KeyError)):
        gate().calibration_gate_allowed(caller,hook,fields,permit,sources)


@pytest.mark.parametrize('fault',['fixture','actor_extra','launch','execution','capacity'])
def test_submit_requires_complete_authenticated_original_fixture(fault):
    permit,actor,creator,fields,intent=fixture();mode='native-publication-v1';observed=Observed(permit,actor,creator,fields,intent)
    if fault=='fixture':mode=None
    if fault=='actor_extra':actor['engineering_fixture']=mode
    if fault=='launch':actor['launch']=copy.deepcopy(actor['launch']);actor['launch']['transport_attempt']+=1
    if fault=='execution':actor['execution_sha256']='0'*64
    if fault=='capacity':observed.fault='capacity'
    with pytest.raises((RuntimeError,ValueError)):
        gate().calibration_submit_allowed(permit['jobs'][CALC]['launch'],actor,permit,observed,fixture=mode)


@pytest.mark.parametrize('field,value',[('MinMemoryNode','129K'),('MinMemoryNode','127K'),
    ('MinMemoryNode','0'),('MinMemoryNode','1.0G'),('UserId','other(3000)'),('Restarts','1'),('NumTasks','2')])
def test_held_real_request_must_match_frozen_demand_before_any_release(tmp_path,field,value):
    jobs,obs,permit,raw=setup_jobs(tmp_path);jobs.stage(permit);obs.fields[field]=value
    with pytest.raises((RuntimeError,ValueError)):jobs.bind_held(CALC)
    assert not any(x[0]=='release' for x in obs.events) and jobs.commitments()==(D,D)
