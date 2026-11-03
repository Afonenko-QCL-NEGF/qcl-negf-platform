"""Synthetic SOURCE/L snapshots; no operational measurement or positive site claim."""
from dataclasses import asdict
import copy,hashlib,importlib,importlib.util,json
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops'))
MiB=1024**2
J1='33333333-3333-4333-8333-333333333333'
J2='66666666-6666-4666-8666-666666666666'

def api():
    assert importlib.util.find_spec('host_resource_qualification_observations'),'missing actual observation/predicate owner'
    return importlib.import_module('host_resource_qualification_observations')

def sha(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def context():
    from test_host_resource_facts import output_packet
    output=next(iter(output_packet()['outputs'].values()));worker=output['worker_identity']
    return dict(host_id='host',owner_id='owner',host_boot_id='host-boot-1',policy_sha256='a'*64,
        source_graph_sha256='3'*64,qualification_ref='accepted-native-profile',baseline_state_sha256='b'*64,
        worker_machine_id=worker['machine_id'],output_owner=output['owner'],
        binding=dict(vm_id='vm',native_id=worker['dmi_uuid'],process_id='77',guest_boot_id=worker['boot_id'],
            image_id='/nix/store/synthetic-image',guest_kernel_id=worker['kernel'],host_kernel_id='host-kernel',
            qemu_version_id='qemu',backend_version_id='backend',readback_version='readback-v1',config_fingerprint='config'),
        native_minimum_bytes=100*MiB,native_maximum_bytes=1000*MiB,quantum_bytes=MiB,paid_grant_bytes=1000*MiB)

def os_accounting(amount=40):
    from test_host_resource_facts import accounting_sources
    f,source,files,identity,jobs,groups,processes=accounting_sources();ctx=context();binding=ctx['binding']
    identity=dict(machine_id=ctx['worker_machine_id'],boot_id=binding['guest_boot_id'],kernel=binding['guest_kernel_id'],dmi_uuid=binding['native_id'],image_id=binding['image_id'])
    files['/proc/meminfo']=files['/proc/meminfo'].replace('1024000 kB','1003520 kB').replace('983040 kB',str((980-amount)*1024)+' kB').replace('1000000 kB','921600 kB')
    return f.capture_guest_accounting(dict(slurm_cgroup_root='/jobs'),source,identity=identity,jobs=jobs,groups=groups,processes=processes,clock=lambda:100)

def permit(measured=True):
    os_samples=[dict(observed_os_bytes=n*MiB,evidence_sha256=sha(os_accounting(n)),accounting=os_accounting(n))for n in [40,35,38]]
    mapping=[dict(assigned_bytes=g*MiB,configured_bytes=g*MiB,total_bytes=t*MiB,available_bytes=a*MiB,evidence_sha256=str(i)*64)
        for i,g,t,a in [(4,1000,980,900),(5,200,180,120),(6,100,80,20),(7,250,230,170)]]
    measurement=dict(state='measured',scope='synthetic image/kernel/services/fixture; observed finite samples plus explicit margin',
        evidence_sha256=sha(os_samples),mapping_evidence_sha256=sha(mapping),observed_os_bytes=40*MiB,
        safety_allowance_bytes=20*MiB,os_reserve_bytes=60*MiB,native_gap_bound_bytes=20*MiB,
        maximum_guest_total_bytes=980*MiB,native_maximum_bytes=1000*MiB)
    return dict(schema='qcl.host-resource-calibration-evidence-permit.v1',context=context(),
        authorized_demands={J1:100*MiB,J2:50*MiB},capacity_measurement=(dict(measurement=measurement,os_samples=os_samples,mapping_samples=mapping)if measured else None))

@pytest.fixture
def witness(tmp_path):
    from test_host_resource_native_cleanup import fixture
    from test_host_resource_operations import request
    n,m,c,b,store,e,p,s,r,profiles=fixture(tmp_path);req=request(m);c.request(req,e);c.grow(req.request_id,e)
    return p.read(store.load()['receipts'][0]['mutation_id'])

def effect(witness,old,target,*,status='returned_success',reply='returned'):
    mid=sha([old,target])[:32];w=json.loads(json.dumps(witness).replace(witness['intent']['mutation_id'],mid));ctx=context();intent=w['intent']
    intent.update(host_id=ctx['host_id'],owner_id=ctx['owner_id'],policy_sha256=ctx['policy_sha256'],binding=ctx['binding'],
        old_bytes=old*MiB,target_bytes=target*MiB,before_revision='native-1',operation='shrink'if target<old else'grow')
    w['intent_sha256']=sha(intent)
    return dict(status=status,mutation_id=intent['mutation_id'],old_bytes=old*MiB,target_bytes=target*MiB,
        before_revision=intent['before_revision'],dispatches=1,witness=w,readback_sha256='7'*64,
        original_evidence_sha256='8'*64,reply_status=reply,failure_code=None)

def job(number,closed=False):
    from test_host_resource_facts import output_packet
    from host_resource_facts import parse_slurm_jobs
    calc,amount=(J1,100)if number==42 else(J2,50)
    native=parse_slurm_jobs(f'JobId={number} UserId=qcl-negf(3000) JobState={"COMPLETED"if closed else"RUNNING"} ExitCode=0:0 NumNodes=1 NumTasks=1 NodeList=worker-a SubmitTime=2026-10-28T10:00:00 StartTime=2026-10-28T10:00:01 Restarts=0 MinMemoryNode={amount}M',cluster='cluster-one')[str(number)]
    output=copy.deepcopy(next(iter(output_packet()['outputs'].values())))
    output.update(generation=native['generation']);output['native_tuple'].update(job_id=str(number),limit_bytes=amount*MiB)
    output['attempt'].update(calcjob_uuid=calc,generation=('5'if number==42 else'6')*64)
    group=dict(populated=not closed,processes=[]if closed else[dict(pid=1000+number,start_ticks=2,executable='/nix/store/synthetic/guard',uids=[3000]*4)],memory_max_bytes=amount*MiB)
    return dict(calcjob_uuid=calc,creator_generation=output['attempt']['generation'],native=native,demand_bytes=amount*MiB,
        task_limit_bytes=amount*MiB,state='closed'if closed else'live',creator_sha256='1'*64,prolog_sha256='2'*64,
        cgroup=group,cgroup_sha256=sha(group),completed_final=output if closed else None,absence_sha256='4'*64 if closed else None,
        revoked_sha256='5'*64 if closed else None)

def sample(sequence,g,*,jobs=(),eff=None,proposed=None,pressure=None,closure=None):
    ctx=context();read=dict(vm_id='vm',native_id=ctx['binding']['native_id'],process_id='77',config_fingerprint='config',
        revision='native-'+str(sequence),configured_bytes=g*MiB,assigned_bytes=g*MiB,running=True)
    return dict(context=ctx,sequence=sequence,readback=read,total_bytes=(g-20)*MiB,available_bytes=max(0,g-80)*MiB,
        slurm_memory_bytes=900*MiB,slurm_registered=True,jobs=list(jobs),effect=eff,
        proposed_target_bytes=None if proposed is None else proposed*MiB,pressure=pressure,closure=closure,evidence_sha256=str(sequence%9+1)*64)

def observations(rows):return tuple(api().CalibrationObservation(**row)for row in rows)

def all_cases(witness):
    both=[job(42),job(43)];one=[job(42,True),job(43)];done=[job(42,True),job(43,True)]
    rejection=dict(status='pre_dispatch_refused',mutation_id=None,old_bytes=250*MiB,target_bytes=249*MiB,before_revision='native-2',
        dispatches=0,witness=None,readback_sha256=None,original_evidence_sha256='9'*64,reply_status='not_dispatched',failure_code='aggregate_floor')
    pressure=dict(scope='synthetic actual PSI stall and cgroup memory.current',some_total_before=10,some_total_after=20,
        memory_current_before=20*MiB,memory_current_after=50*MiB,evidence_sha256='8'*64)
    closure=dict(revoked_sequence=1,jobs_closed_sequence=2,native_restored_sequence=3,fence_closed_sequence=4,
        revocation_sha256='1'*64,jobs_closed_sha256='2'*64,native_restored_sha256='3'*64,fence_closed_sha256='4'*64,
        unresolved_mutation_ids=[],guard_processes=[],sudo_processes=[])
    lost=effect(witness,100,250,reply='lost_outer')
    result={
        'idle-shrink':[sample(1,1000),sample(2,100,eff=effect(witness,1000,100))],
        'idle-grow':[sample(1,100),sample(2,200,eff=effect(witness,100,200))],
        'restore-full':[sample(1,200),sample(2,1000,eff=effect(witness,200,1000))],
        'near-floor':[sample(1,100),sample(2,250,jobs=both,eff=effect(witness,100,250)),sample(3,250,jobs=both,eff=rejection,proposed=249)],
        'active-floor-protection':[sample(1,250,jobs=both),sample(2,250,jobs=both,eff=rejection,proposed=249),sample(3,200,jobs=one)],
        'pressure':[sample(1,250,jobs=both),sample(2,250,jobs=both,pressure=pressure)],
        'supported-rejection':[sample(1,250,jobs=both),sample(2,250,jobs=both,eff=rejection,proposed=249)],
        'lost-outer-response':[sample(1,250,jobs=both,eff=lost),sample(2,250,jobs=both,eff=lost)],
        'closure':[sample(1,1000,jobs=done,closure=closure)]}
    result['near-floor'][-1]['readback']['revision']='native-2'
    result['supported-rejection'][0]['readback']['revision']='native-2'
    for row in result['lost-outer-response']:row['readback']['revision']='native-2'
    for index,row in enumerate(result['pressure']):
        accounting=os_accounting();accounting['jobs']['43']=copy.deepcopy(accounting['jobs']['42'])
        accounting['jobs']['43'].update(generation=job(43)['native']['generation'],cgroup='/sys/fs/cgroup/jobs/job_43',memory_max_bytes=50*MiB,memory_current_bytes=0)
        accounting['pressure']['some']['total']=(10,20)[index];accounting['jobs']['42']['memory_current_bytes']=(20,50)[index]*MiB
        row['accounting']=accounting
    result['pressure'][-1]['pressure']=api().observed_pressure(*observations(result['pressure']))
    return result

def test_missing_reserve_never_becomes_administrative_or_idle_scalar_measurement(witness):
    m=api();p=permit(False);rows=all_cases(witness)
    result=m.evaluate_case('near-floor',observations(rows['near-floor']),p)
    assert result.status=='NOT_MEASURED'
    assert m.qualification_candidate(m.build_qualification_report(p,{k:observations(v)for k,v in rows.items()})) is None


def test_ordinary_near_floor_uses_physical_reserve_not_native_minimum(witness):
    m=api();rows=all_cases(witness)['near-floor'];result=m.evaluate_case('near-floor',observations(rows),permit())
    assert rows[1]['total_bytes']<250*MiB and rows[1]['total_bytes']>=210*MiB
    assert result.status=='PASS'


@pytest.mark.parametrize('field,value',[('total_bytes',209*MiB),('available_bytes',99*MiB),('slurm_memory_bytes',921*MiB)])
def test_current_capacity_contradiction_fails_near_floor(witness,field,value):
    m=api();rows=all_cases(witness)['near-floor'];rows[1][field]=value
    assert m.evaluate_case('near-floor',observations(rows),permit()).status=='FAIL'


@pytest.mark.parametrize('missing',['overlap','final','pressure','mapping','os-samples','max','closure','registration'])
def test_missing_actual_evidence_does_not_promote_candidate(witness,missing):
    m=api();p=permit();rows=all_cases(witness)
    if missing=='overlap':rows['active-floor-protection']=[rows['active-floor-protection'][-1]]
    if missing=='final':rows['active-floor-protection'][-1]['jobs'][0]['completed_final']=None
    if missing=='pressure':rows['pressure'][-1]['pressure']=None
    if missing=='mapping':p['capacity_measurement']['mapping_samples']=[]
    if missing=='os-samples':p['capacity_measurement']['os_samples']=[]
    if missing=='max':p['capacity_measurement']['measurement']['maximum_guest_total_bytes']=None
    if missing=='closure':rows['closure'][0]['closure']=None
    if missing=='registration':rows['idle-shrink'][-1]['slurm_registered']=None
    report=m.build_qualification_report(p,{k:observations(v)for k,v in rows.items()})
    assert m.qualification_candidate(report) is None
    assert any(case['status']!='PASS'for case in report['cases'].values())


def test_healthy_complete_synthetic_metadata_produces_unattached_noncyclic_candidate(witness):
    m=api();report=m.build_qualification_report(permit(),{k:observations(v)for k,v in all_cases(witness).items()})
    assert {case['status']for case in report['cases'].values()}=={'PASS'}
    candidate=m.qualification_candidate(report)
    assert candidate['capacity']['report_sha256']==sha(report)
    assert candidate['capacity']['measurement']['os_reserve_bytes']==60*MiB
    assert candidate['qualified_dynamic'] is True and 'ready'not in candidate


@pytest.mark.parametrize('tamper',['status','context','reserve','source','binding','exit-only','revoke-order','replay','server-unknown'])
def test_tampered_or_unclosed_report_has_no_candidate(witness,tamper):
    m=api();p=permit();rows=all_cases(witness)
    if tamper=='context':rows['near-floor'][1]['context']['baseline_state_sha256']='0'*64
    if tamper=='reserve':p['capacity_measurement']['measurement']['observed_os_bytes']=100*MiB
    if tamper=='source':rows['near-floor'][1]['context']['source_graph_sha256']='0'*64
    if tamper=='binding':rows['near-floor'][1]['context']['binding']['image_id']='/nix/store/other-image'
    if tamper=='exit-only':rows['closure'][0]['jobs'][0]['completed_final']={'exit_code':0}
    if tamper=='revoke-order':rows['closure'][0]['closure']['revoked_sequence']=5
    if tamper=='replay':rows['lost-outer-response'][-1]['effect']['dispatches']=2
    if tamper=='server-unknown':rows['lost-outer-response'][-1]['effect']['status']='unknown'
    report=m.build_qualification_report(p,{k:observations(v)for k,v in rows.items()})
    if tamper=='status':report['cases']['pressure']['status']='NOT_MEASURED'
    assert m.qualification_candidate(report) is None
    if tamper=='server-unknown':assert report['cases']['lost-outer-response']['status']=='UNKNOWN'

@pytest.mark.parametrize('fault',['controls','not-durable','still-populated','memory-max','pending-limit'])
def test_final_and_limit_require_actual_cgroup_and_completed_final_not_flags(witness,fault):
    m=api();p=permit();rows=all_cases(witness)
    if fault=='controls':rows['closure'][0]['jobs'][0]['completed_final'].update(scope='controls',durable=False)
    if fault=='not-durable':rows['closure'][0]['jobs'][0]['completed_final']['durable']=False
    if fault=='still-populated':rows['closure'][0]['jobs'][0]['cgroup']=dict(populated=True,processes=[dict(pid=1,start_ticks=1,executable='/gate',uids=[3000]*4)],memory_max_bytes=100*MiB)
    if fault=='memory-max':rows['near-floor'][1]['jobs'][0]['cgroup']=dict(populated=True,processes=[],memory_max_bytes=200*MiB)
    if fault=='pending-limit':rows['near-floor'][1]['jobs'][1].update(state='held',task_limit_bytes=None)
    report=m.build_qualification_report(p,{k:observations(v)for k,v in rows.items()})
    assert m.qualification_candidate(report) is None


def test_unknown_native_result_stays_unknown_when_other_observations_are_missing(witness):
    m=api();rows=all_cases(witness)['lost-outer-response'];rows[-1]['effect']['status']='unknown';rows[-1]['total_bytes']=None
    assert m.evaluate_case('lost-outer-response',observations([rows[-1]]),permit(False)).status=='UNKNOWN'


def test_measured_balloon_mapping_may_keep_total_above_current_native(witness):
    m=api();p=permit();rows=all_cases(witness)['near-floor']
    for row in p['capacity_measurement']['mapping_samples']:row.update(total_bytes=980*MiB,available_bytes=900*MiB)
    p['capacity_measurement']['measurement']['mapping_evidence_sha256']=sha(p['capacity_measurement']['mapping_samples'])
    for row in rows:row.update(total_bytes=980*MiB,available_bytes=900*MiB)
    assert m.evaluate_case('near-floor',observations(rows),p).status=='PASS'

@pytest.mark.parametrize('fault',['higher-targets','missing-lower','missing-target','idle-total','native-final-tuple','reused-job','changed-original-c','pending-owner','guard-alive','sudo-alive'])
def test_actual_mapping_original_generation_and_closure_catalog_cannot_be_replaced(witness,fault):
    m=api();p=permit();rows=all_cases(witness)
    if fault=='higher-targets':
        for index,row in enumerate(p['capacity_measurement']['mapping_samples'][1:]):row.update(assigned_bytes=(1100+index*100)*MiB,configured_bytes=(1100+index*100)*MiB,total_bytes=(1080+index*100)*MiB)
    if fault=='missing-lower':p['capacity_measurement']['mapping_samples']=p['capacity_measurement']['mapping_samples'][:1]
    if fault=='missing-target':
        p['capacity_measurement']['mapping_samples']=[row for row in p['capacity_measurement']['mapping_samples']if row['assigned_bytes']!=250*MiB]
    if fault in {'higher-targets','missing-lower','missing-target'}:p['capacity_measurement']['measurement']['mapping_evidence_sha256']=sha(p['capacity_measurement']['mapping_samples'])
    if fault=='idle-total':rows['idle-shrink'][-1]['total_bytes']=2000*MiB
    if fault=='native-final-tuple':rows['closure'][0]['jobs'][0]['native']['start_time']='2026-10-28T10:00:02'
    if fault=='reused-job':
        j=rows['active-floor-protection'][-1]['jobs'][0]
        j['creator_generation']='f'*64;j['completed_final']['attempt']['generation']='f'*64
    if fault=='changed-original-c':
        rows['lost-outer-response'][-1]['effect']=effect(witness,200,250,reply='lost_outer')
    if fault=='pending-owner':rows['closure'][0]['closure']['unresolved_mutation_ids']=['a'*32]
    if fault=='guard-alive':rows['closure'][0]['closure']['guard_processes']=[dict(pid=1,start_ticks=3)]
    if fault=='sudo-alive':rows['closure'][0]['closure']['sudo_processes']=[dict(pid=1,start_ticks=3)]
    assert m.qualification_candidate(m.build_qualification_report(p,{key:observations(value)for key,value in rows.items()})) is None


def test_actual_profile_builder_requires_accounting_not_idle_scalar_or_admin_reserve(witness):
    m=api();p=permit();rows=all_cases(witness)
    assert hasattr(m,'capacity_measurement_from_observations'),'missing actual accounting profile producer'
    plain=[sample(1,1000),sample(2,200),sample(3,100)]
    with pytest.raises(m.MissingEvidence):m.capacity_measurement_from_observations(p['context'],observations(plain),safety_allowance_bytes=20*MiB,native_gap_bound_bytes=20*MiB,scope='finite literal conditions')
    for index,row in enumerate(plain):row['accounting']=os_accounting((40,35,38)[index])
    measured=m.capacity_measurement_from_observations(p['context'],observations(plain),safety_allowance_bytes=20*MiB,native_gap_bound_bytes=20*MiB,scope='finite literal image/services/pressure plus explicit margin')
    assert measured['measurement']['observed_os_bytes']==40*MiB and measured['measurement']['os_reserve_bytes']==60*MiB
    assert measured['measurement']['maximum_guest_total_bytes']==980*MiB


@pytest.mark.parametrize('fault',['no-raw','idle-scalar','hash','binding','only-idle','counter-missing'])
def test_os_reserve_profile_requires_retained_actual_accounting_and_supported_scope(witness,fault):
    m=api();p=permit();rows=all_cases(witness)
    for sample_row in p['capacity_measurement']['os_samples']:
        if fault=='no-raw':sample_row.pop('accounting',None)
        if fault=='idle-scalar':sample_row['accounting']={'MemAvailable':sample_row['observed_os_bytes']}
        if fault=='binding':sample_row['accounting']['identity']['boot_id']='other'
        if fault=='only-idle':sample_row['accounting']['jobs']={}
        if fault=='counter-missing':sample_row['accounting']['vmstat_counters'].pop('balloon_inflate')
        if fault=='hash':sample_row['evidence_sha256']='0'*64
    if fault!='hash':
        for sample_row in p['capacity_measurement']['os_samples']:
            if 'accounting'in sample_row:sample_row['evidence_sha256']=sha(sample_row['accounting'])
        p['capacity_measurement']['measurement']['evidence_sha256']=sha(p['capacity_measurement']['os_samples'])
    assert m.qualification_candidate(m.build_qualification_report(p,{key:observations(value)for key,value in rows.items()})) is None

@pytest.mark.parametrize('fault',['missing-pressure-raw','pressure-delta','same-uuid-other-intent','missing-r','missing-k','missing-tmax'])
def test_report_requires_actual_raw_pressure_immutable_c_and_measured_operands(witness,fault):
    m=api();p=permit();rows=all_cases(witness)
    if fault=='missing-pressure-raw':
        for row in rows['pressure']:row.pop('accounting',None)
    if fault=='pressure-delta':rows['pressure'][-1]['pressure']['memory_current_after']+=1
    if fault=='same-uuid-other-intent':rows['idle-grow'][-1]['effect']['witness']['intent']['old_bytes']+=1;rows['idle-grow'][-1]['effect']['witness']['intent_sha256']=sha(rows['idle-grow'][-1]['effect']['witness']['intent']);rows['idle-grow'][-1]['effect']['old_bytes']+=1
    if fault.startswith('missing-')and fault not in {'missing-pressure-raw'}:
        key={'missing-r':'os_reserve_bytes','missing-k':'native_gap_bound_bytes','missing-tmax':'maximum_guest_total_bytes'}[fault]
        p['capacity_measurement']['measurement'][key]=None
    assert m.qualification_candidate(m.build_qualification_report(p,{key:observations(value)for key,value in rows.items()})) is None


def test_same_original_c_uuid_cannot_identify_two_distinct_valid_effects(witness):
    m=api();p=permit();rows=all_cases(witness)
    original=rows['idle-shrink'][-1]['effect']['mutation_id'];changed=rows['idle-grow'][-1]['effect']
    old=changed['mutation_id'];replacement=json.loads(json.dumps(changed).replace(old,original))
    replacement['witness']['intent_sha256']=sha(replacement['witness']['intent']);rows['idle-grow'][-1]['effect']=replacement
    assert m.evaluate_case('idle-grow',observations(rows['idle-grow']),p).status=='PASS'
    assert m.qualification_candidate(m.build_qualification_report(p,{key:observations(value)for key,value in rows.items()}))is None


def test_missing_original_authorized_job_is_unmeasured_not_an_empty_commitment_set(witness):
    m=api();rows=all_cases(witness)['near-floor'];rows[1]['jobs'].pop()
    assert m.evaluate_case('near-floor',observations(rows),permit()).status=='NOT_MEASURED'


def test_malformed_measurement_object_has_no_candidate(witness):
    m=api();p=permit();p['capacity_measurement']['measurement']=None
    assert m.qualification_candidate(m.build_qualification_report(p,{key:observations(value)for key,value in all_cases(witness).items()}))is None


@pytest.mark.parametrize('case',['idle-shrink','idle-grow','restore-full','near-floor'])
@pytest.mark.parametrize('changed',['old','before-revision','target'])
def test_each_actual_transition_joins_original_c_before_and_after_readbacks(witness,case,changed):
    m=api();p=permit();allrows=all_cases(witness);rows=allrows[case]
    assert m.evaluate_case(case,observations(rows),p).status=='PASS'
    e=rows[1]['effect'];intent=e['witness']['intent']
    if changed=='old':e['old_bytes']+=MiB;intent['old_bytes']=e['old_bytes']
    if changed=='before-revision':e['before_revision']='different-native-revision';intent['before_revision']=e['before_revision']
    if changed=='target':e['target_bytes']+=MiB;intent['target_bytes']=e['target_bytes']
    e['witness']['intent_sha256']=sha(intent)
    assert m.evaluate_case(case,observations(rows),p).status!='PASS'
    assert m.qualification_candidate(m.build_qualification_report(p,{key:observations(value)for key,value in allrows.items()}))is None


@pytest.mark.parametrize('changed',['old','target','before-revision','after-revision'])
def test_predispatch_refusal_joins_original_unchanged_native_readback(witness,changed):
    m=api();p=permit();allrows=all_cases(witness);rows=allrows['supported-rejection']
    assert m.evaluate_case('supported-rejection',observations(rows),p).status=='PASS'
    e=rows[-1]['effect']
    if changed=='old':e['old_bytes']+=MiB
    if changed=='target':e['target_bytes']-=MiB
    if changed=='before-revision':e['before_revision']='different-native-revision'
    if changed=='after-revision':rows[-1]['readback']['revision']='changed-despite-refusal'
    assert m.evaluate_case('supported-rejection',observations(rows),p).status!='PASS'


@pytest.mark.parametrize('case,index',[('pressure',0),('pressure',1),('near-floor',2),('supported-rejection',0),('supported-rejection',1),('lost-outer-response',0),('lost-outer-response',1)])
@pytest.mark.parametrize('contradiction',['native','physical','available','scheduler'])
def test_every_observed_live_frame_preserves_complete_capacity(witness,case,index,contradiction):
    m=api();p=permit();allrows=all_cases(witness);row=allrows[case][index]
    assert m.evaluate_case(case,observations(allrows[case]),p).status=='PASS'
    if contradiction=='native':row['readback'].update(assigned_bytes=200*MiB,configured_bytes=200*MiB);row.update(total_bytes=180*MiB,available_bytes=120*MiB)
    if contradiction=='physical':row.update(total_bytes=209*MiB,available_bytes=120*MiB)
    if contradiction=='available':row['available_bytes']=99*MiB
    if contradiction=='scheduler':row['slurm_memory_bytes']=149*MiB
    assert m.evaluate_case(case,observations(allrows[case]),p).status=='FAIL'
    assert m.qualification_candidate(m.build_qualification_report(p,{key:observations(value)for key,value in allrows.items()}))is None


@pytest.mark.parametrize('changed',['path','job-id','generation','limit','unknown-job'])
def test_pressure_raw_accounting_joins_original_scope_and_allocated_generation(witness,changed):
    m=api();p=permit();allrows=all_cases(witness);rows=allrows['pressure'];raw=rows[-1]['accounting']['jobs']
    if changed=='path':raw['42']['cgroup']='/sys/fs/cgroup/other-scope/job_42'
    if changed=='job-id':raw['42']['cgroup']='/sys/fs/cgroup/jobs/job_99'
    if changed=='generation':
        for row in rows:row['accounting']['jobs']['42']['generation']='e'*64
    if changed=='limit':
        for row in rows:row['accounting']['jobs']['42']['memory_max_bytes']=99*MiB
    if changed=='unknown-job':
        for row in rows:row['accounting']['jobs']['99']=row['accounting']['jobs'].pop('42')
    try:rows[-1]['pressure']=m.observed_pressure(*observations(rows))
    except (m.ResourceError,ValueError):return
    assert m.evaluate_case('pressure',observations(rows),p).status!='PASS'
