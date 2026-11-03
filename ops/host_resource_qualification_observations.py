"""Bounded private calibration metadata predicates, never a native executor.

Python constructors are SOURCE/L seams, not authentication. Actual producers must
use the existing protected C/output/guest readers. A finite scoped OS observation
plus an explicit margin is not a theorem about future kernel/service peaks.
"""
from collections.abc import Mapping
from dataclasses import dataclass,fields,is_dataclass
import json,re
from pathlib import PurePosixPath
from types import MappingProxyType

from host_resource_operations import BackendQualification,GuestEvidence,RuntimeBinding,VMReadback,ResourceError,require
from host_resource_backends import fingerprint
from host_resource_capacity import (BINDING_FIELDS,GuestCapacityQualification,CapacityValidationError,
    decode_capacity_qualification_v2,rounded_native_floor,validate_guest_admission)

REPORT_SCHEMA='qcl.host-resource-calibration-report.v1'
PERMIT_SCHEMA='qcl.host-resource-calibration-evidence-permit.v1'
REQUIRED_CASES=('idle-shrink','idle-grow','restore-full','near-floor','active-floor-protection',
    'pressure','supported-rejection','lost-outer-response','closure')
CONTEXT_FIELDS={'host_id','owner_id','host_boot_id','policy_sha256','source_graph_sha256','qualification_ref',
    'baseline_state_sha256','worker_machine_id','output_owner','binding','native_minimum_bytes',
    'native_maximum_bytes','quantum_bytes','paid_grant_bytes'}
JOB_FIELDS={'calcjob_uuid','creator_generation','native','demand_bytes','task_limit_bytes','state',
    'creator_sha256','prolog_sha256','cgroup','cgroup_sha256','completed_final','absence_sha256','revoked_sha256'}
EFFECT_FIELDS={'status','mutation_id','old_bytes','target_bytes','before_revision','dispatches','witness',
    'readback_sha256','original_evidence_sha256','reply_status','failure_code'}

class MissingEvidence(ValueError):pass
class UnknownOutcome(ValueError):pass

def plain(value):
    if is_dataclass(value):return {f.name:plain(getattr(value,f.name))for f in fields(value)}
    if isinstance(value,Mapping):return {k:plain(v)for k,v in value.items()}
    if isinstance(value,(tuple,list)):return [plain(v)for v in value]
    return value

def frozen(value):
    if isinstance(value,dict):return MappingProxyType({k:frozen(v)for k,v in value.items()})
    if isinstance(value,(tuple,list)):return tuple(frozen(v)for v in value)
    return value

def exact(value,names):require(isinstance(value,Mapping)and set(value)==set(names),'shape','exact private observation fields required')
def number(value,*,positive=False):require(type(value)is int and (1 if positive else 0)<=value<2**63,'shape','explicit bounded integer required');return value
def text(value):require(type(value)is str and 0<len(value.encode())<=4096 and '\x00'not in value,'shape','bounded explicit text required');return value
def sha(value):require(type(value)is str and re.fullmatch(r'[0-9a-f]{64}',value)is not None,'shape','SHA256 required');return value
def present(value):
    if value is None:raise MissingEvidence('actual_observation_missing')
    return value

def context(value):
    exact(value,CONTEXT_FIELDS);exact(value['binding'],BINDING_FIELDS)
    for key in ('host_id','owner_id','host_boot_id','qualification_ref','worker_machine_id'):text(value[key])
    for key in ('policy_sha256','source_graph_sha256','baseline_state_sha256'):sha(value[key])
    for val in value['binding'].values():text(val)
    for key in ('native_minimum_bytes','native_maximum_bytes','quantum_bytes','paid_grant_bytes'):number(value[key],positive=True)
    require(value['native_minimum_bytes']<=value['paid_grant_bytes']==value['native_maximum_bytes'],
        'capacity_evidence','unchanged full paid native maximum required')
    return value

@dataclass(frozen=True)
class MeasuredBackendQualification(BackendQualification):
    """Private subtype rejected by the original controller before positive readiness."""
    capacity:GuestCapacityQualification
    supported_targets:tuple
    def __post_init__(self):
        require(type(self.capacity)is GuestCapacityQualification,'qualification','typed measured capacity required')
        require(type(self.supported_targets)is tuple and 3<=len(self.supported_targets)<=64 and
            tuple(sorted(set(self.supported_targets)))==self.supported_targets and
            all(type(n)is int and 0<n<=self.capacity.native_maximum_bytes for n in self.supported_targets),
            'qualification','finite original measured native target scope required')

@dataclass(frozen=True)
class MeasuredGuestEvidence(GuestEvidence):
    """Private typed distinction; frozen controller intentionally rejects until integration."""
    capacity:GuestCapacityQualification
    commitments:tuple
    def __post_init__(self):
        require(type(self.capacity)is GuestCapacityQualification,'qualification','typed measured capacity required')
        require(type(self.commitments)is tuple and 0<len(self.commitments)<=64 and
            all(type(row)is tuple and len(row)==3 for row in self.commitments),
            'qualification','complete immutable original workload/D/actual-limit tuple required')
        for workload,demand,limit in self.commitments:text(workload);number(demand,positive=True);number(limit,positive=True)
        require(len({row[0]for row in self.commitments})==len(self.commitments),'qualification','unique original commitments required')

@dataclass(frozen=True)
class CalibrationObservation:
    context:dict
    sequence:int
    readback:dict
    total_bytes:int|None
    available_bytes:int|None
    slurm_memory_bytes:int|None
    slurm_registered:bool|None
    jobs:tuple
    effect:dict|None
    proposed_target_bytes:int|None
    pressure:dict|None
    closure:dict|None
    evidence_sha256:str
    accounting:dict|None=None
    source_records:dict|None=None
    def __post_init__(self):
        require(len(json.dumps(plain(self),sort_keys=True,allow_nan=False).encode())<=1024**2,'output_bound','bounded calibration snapshot required')
        for name in ('context','readback','jobs','effect','pressure','closure','accounting','source_records'):object.__setattr__(self,name,frozen(plain(getattr(self,name))))

@dataclass(frozen=True)
class CaseResult:
    status:str
    reason:str
    original_evidence:tuple
    applicability:Mapping

def decode_permit(value):
    exact(value,{'schema','context','authorized_demands','capacity_measurement'})
    require(value['schema']==PERMIT_SCHEMA,'shape','private evidence permit version');context(value['context'])
    require(isinstance(value['authorized_demands'],Mapping)and len(value['authorized_demands'])<=64,'shape','finite original authorized set required')
    from uuid import UUID
    for key,demand in value['authorized_demands'].items():
        text(key);require(str(UUID(key))==key,'shape','original CalcJob UUID required');number(demand,positive=True)
    return value

def validate_accounting(value,ctx):
    value=present(value)
    if isinstance(value,Mapping)and value.get('state')=='NOT_MEASURED':raise MissingEvidence('actual_Linux_accounting_not_measured')
    exact(value,{'schema','identity','observed_at','scope','meminfo_bytes','meminfo_after_bytes','vmstat_counters','pressure',
        'processes','jobs','os_upper_bound_bytes','balloon_current_bytes'})
    require(value['schema']=='qcl.host-resource-guest-accounting.v1','capacity_evidence','actual Linux accounting version required')
    b=ctx['binding'];require(plain(value['identity'])==dict(machine_id=ctx['worker_machine_id'],boot_id=b['guest_boot_id'],
        kernel=b['guest_kernel_id'],dmi_uuid=b['native_id'],image_id=b['image_id']),
        'identity_mismatch','accounting actual image/kernel/worker binding differs')
    text(value['scope']);number(value['observed_at']);number(value['os_upper_bound_bytes'],positive=True)
    memory=value['meminfo_bytes'];after=value['meminfo_after_bytes']
    required={'MemTotal','MemFree','MemAvailable','Buffers','Cached','SReclaimable','SUnreclaim','KernelStack','PageTables','Percpu'}
    require(isinstance(memory,Mapping)and isinstance(after,Mapping)and required<=memory.keys()and required<=after.keys(),
        'capacity_evidence','actual complete OS/kernel counters required')
    for row in (memory,after):
        for val in row.values():number(val)
        require(0<row['MemTotal']and row['MemAvailable']<=row['MemTotal']and row['MemFree']<=row['MemTotal'],
            'capacity_evidence','actual OS counters contradict physical memory')
    require(memory['MemTotal']==after['MemTotal']and value['os_upper_bound_bytes']==max(
        memory['MemTotal']-memory['MemFree'],after['MemTotal']-after['MemFree']),
        'capacity_evidence','conservative finite non-free upper differs; MemAvailable is not reserve')
    counters=value['vmstat_counters'];require(isinstance(counters,Mapping)and
        {'nr_free_pages','nr_anon_pages','nr_file_pages','balloon_inflate','balloon_deflate','balloon_migrate'}<=counters.keys(),
        'capacity_evidence','actual resident/balloon counters unavailable')
    for val in counters.values():number(val)
    require(value['balloon_current_bytes']is None,'capacity_evidence','cumulative balloon counters are not current balloon bytes')
    require(isinstance(value['processes'],(list,tuple))and 0<len(value['processes'])<=1024 and
        isinstance(value['jobs'],Mapping)and len(value['jobs'])<=64,'capacity_evidence','finite actual resident/cgroup inventory required')
    for process in value['processes']:
        exact(process,{'pid','start_ticks','executable','uids','cgroup','rss_bytes','pss_bytes'})
        number(process['pid'],positive=True);number(process['start_ticks'],positive=True);text(process['executable']);text(process['cgroup'])
        if process['executable']not in {'[kernel]','[nonexecuting]'}:
            number(present(process['rss_bytes']));number(present(process['pss_bytes']))
            require(process['pss_bytes']<=process['rss_bytes'],'capacity_evidence','actual RSS/PSS differs')
    # PSI and original cgroup resident data are retained rather than replaced by a
    # positive pressure flag. The separate pressure case requires a real increase.
    for pressure in (value['pressure'],*[row['pressure']for row in value['jobs'].values()if row['scope']=='present']):
        exact(pressure,{'some','full'})
        for row in pressure.values():
            exact(row,{'avg10','avg60','avg300','total'});number(row['total'])
            for key in ('avg10','avg60','avg300'):require(type(row[key])is str and re.fullmatch(r'[0-9]+\.[0-9]{2}',row[key]),'capacity_evidence','literal PSI averages required')
    for job,row in value['jobs'].items():
        exact(row,{'generation','cgroup','scope','memory_current_bytes','memory_max_bytes','memory_events','memory_stat','pressure'})
        sha(row['generation']);text(row['cgroup'])
        require(row['scope']in {'present','absent'},'capacity_evidence','actual cgroup presence required')
        if row['scope']=='present':
            number(row['memory_current_bytes']);number(row['memory_max_bytes'],positive=True)
            require(isinstance(row['memory_events'],Mapping)and {'low','high','max','oom','oom_kill'}<=row['memory_events'].keys()and
                isinstance(row['memory_stat'],Mapping)and {'anon','file','kernel'}<=row['memory_stat'].keys(),
                'capacity_evidence','actual cgroup events/resident counters required')
            for key,val in row['memory_events'].items():
                number(val);require(not key.startswith('oom')or val==0,'capacity_evidence','actual OOM event invalidates profile')
            for val in row['memory_stat'].values():number(val)
    return value


def capacity_measurement_from_observations(ctx,observations,*,safety_allowance_bytes,native_gap_bound_bytes,scope):
    """Project retained actual accounting; never infer R/K/Tmax from admin floors.

    K and future safety allowance are explicit scoped measured-profile inputs.
    This creates metadata only. Authentication and acceptance belong to Root.
    """
    context(ctx);number(safety_allowance_bytes);number(native_gap_bound_bytes);text(scope)
    require(type(observations)in (list,tuple)and 0<len(observations)<=64,'shape','finite actual paired observations required')
    os_samples=[];mapping=[];maximum=[]
    for observation in observations:
        require(type(observation)is CalibrationObservation and plain(observation.context)==plain(ctx),
            'identity_mismatch','actual observation context differs')
        accounting=validate_accounting(observation.accounting,ctx)
        os_samples.append(dict(observed_os_bytes=accounting['os_upper_bound_bytes'],evidence_sha256=fingerprint(plain(accounting)),accounting=plain(accounting)))
        mapping.append(dict(assigned_bytes=observation.readback['assigned_bytes'],configured_bytes=observation.readback['configured_bytes'],
            total_bytes=present(observation.total_bytes),available_bytes=present(observation.available_bytes),evidence_sha256=observation.evidence_sha256))
        if observation.readback['assigned_bytes']==ctx['native_maximum_bytes']:maximum.append(observation.total_bytes)
    if not maximum:raise MissingEvidence('actual_maximum_target_not_measured')
    require(len(set(maximum))==1,'capacity_evidence','actual maximum guest total changed')
    peak=max(row['observed_os_bytes']for row in os_samples)
    result=dict(measurement=dict(state='measured',scope=scope,evidence_sha256=fingerprint(os_samples),mapping_evidence_sha256=fingerprint(mapping),
        observed_os_bytes=peak,safety_allowance_bytes=safety_allowance_bytes,os_reserve_bytes=peak+safety_allowance_bytes,
        native_gap_bound_bytes=native_gap_bound_bytes,maximum_guest_total_bytes=maximum[0],native_maximum_bytes=ctx['native_maximum_bytes']),
        os_samples=os_samples,mapping_samples=mapping)
    capacity_document(dict(schema=PERMIT_SCHEMA,context=plain(ctx),authorized_demands={},capacity_measurement=result),report_sha256=fingerprint(result))
    return result


def capacity_document(permit,*,report_sha256):
    decode_permit(permit);ctx=permit['context'];measured=present(permit['capacity_measurement'])
    exact(measured,{'measurement','os_samples','mapping_samples'});m=present(measured['measurement'])
    exact(m,{'state','scope','evidence_sha256','mapping_evidence_sha256','observed_os_bytes','safety_allowance_bytes','os_reserve_bytes',
        'native_gap_bound_bytes','maximum_guest_total_bytes','native_maximum_bytes'})
    os_samples=measured['os_samples'];mapping=measured['mapping_samples']
    if not os_samples or not mapping:raise MissingEvidence('reserve_or_mapping_not_measured')
    require(isinstance(os_samples,(list,tuple))and 0<len(os_samples)<=64 and isinstance(mapping,(list,tuple))and 0<len(mapping)<=64,
        'shape','bounded independent reserve/mapping samples required')
    peak=0;workload_accounting=False
    for row in os_samples:
        exact(row,{'observed_os_bytes','evidence_sha256','accounting'});accounting=validate_accounting(row['accounting'],ctx)
        require(row['observed_os_bytes']==accounting['os_upper_bound_bytes']and row['evidence_sha256']==fingerprint(plain(accounting)),
            'capacity_evidence','original actual OS accounting/digest differs')
        workload_accounting|=any(j['scope']=='present'for j in accounting['jobs'].values())
        peak=max(peak,number(row['observed_os_bytes'],positive=True));sha(row['evidence_sha256'])
    if not workload_accounting:raise MissingEvidence('workload_resident_reserve_scope_not_measured')
    for key in ('observed_os_bytes','safety_allowance_bytes','os_reserve_bytes','native_gap_bound_bytes','maximum_guest_total_bytes','native_maximum_bytes'):
        present(m.get(key));number(m[key],positive=key not in {'safety_allowance_bytes','native_gap_bound_bytes'})
    require(m['observed_os_bytes']==peak and m['evidence_sha256']==fingerprint(plain(os_samples))and
        m['mapping_evidence_sha256']==fingerprint(plain(mapping)),'capacity_evidence','actual reserve/mapping projection differs')
    targets=set();maximum=False
    for row in mapping:
        exact(row,{'assigned_bytes','configured_bytes','total_bytes','available_bytes','evidence_sha256'})
        for key in ('assigned_bytes','configured_bytes','total_bytes'):number(row[key],positive=True)
        number(row['available_bytes']);sha(row['evidence_sha256']);targets.add(row['assigned_bytes'])
        require(row['assigned_bytes']==row['configured_bytes']and ctx['native_minimum_bytes']<=row['assigned_bytes']<=ctx['native_maximum_bytes']and
            row['available_bytes']<=row['total_bytes']<=m['maximum_guest_total_bytes']and
            max(0,row['assigned_bytes']-row['total_bytes'])<=m['native_gap_bound_bytes'],
            'capacity_evidence','observed native/guest mapping contradicts bound')
        maximum|=row['assigned_bytes']==ctx['native_maximum_bytes']and row['total_bytes']==m['maximum_guest_total_bytes']
    if not maximum or len(targets)<3:raise MissingEvidence('maximum_and_multiple_lower_targets_not_measured')
    require(ctx['native_minimum_bytes']>=m['os_reserve_bytes']+m['native_gap_bound_bytes'],
        'capacity_evidence','native minimum does not cover independently measured R+K')
    return dict(schema='qcl.host-resource-capacity-qualification.v2',**{key:plain(ctx[key])for key in
        ('host_id','owner_id','policy_sha256','binding','source_graph_sha256')},report_sha256=sha(report_sha256),measurement=plain(m))

def expected_capacity(ctx,report_sha256):
    return dict(expected_host_id=ctx['host_id'],expected_owner_id=ctx['owner_id'],expected_policy_sha256=ctx['policy_sha256'],
        expected_binding=plain(ctx['binding']),expected_source_graph_sha256=ctx['source_graph_sha256'],
        expected_report_sha256=report_sha256,expected_native_maximum_bytes=ctx['native_maximum_bytes'])

def measured_capacity(permit):
    # A case uses the captured measurement fragment identity. This is not an
    # installed/accepted qualification. The separate candidate binds the full report.
    fragment=fingerprint(plain(present(permit['capacity_measurement'])))
    return decode_capacity_qualification_v2(capacity_document(permit,report_sha256=fragment),**expected_capacity(permit['context'],fragment))

def _samples(observations,permit):
    decode_permit(permit)
    if not observations:raise MissingEvidence('case_not_measured')
    require(type(observations)in(tuple,list)and len(observations)<=64,'shape','finite ordered snapshots required')
    previous=0;ctx=permit['context']
    for observation in observations:
        require(type(observation)is CalibrationObservation,'shape','typed actual snapshot required')
        number(observation.sequence,positive=True);require(observation.sequence>previous,'stale_evidence','ordered distinct root observations required');previous=observation.sequence
        require(plain(observation.context)==plain(ctx),'identity_mismatch','runtime/source/policy/paid baseline changed')
        exact(observation.readback,VMReadback.__dataclass_fields__);r=observation.readback;b=ctx['binding']
        require(r['vm_id']==b['vm_id']and r['native_id']==b['native_id']and r['process_id']==b['process_id']and
            r['config_fingerprint']==b['config_fingerprint']and r['running']is True,'identity_mismatch','actual native runtime changed')
        number(r['assigned_bytes'],positive=True);number(r['configured_bytes'],positive=True);text(r['revision'])
        require(r['assigned_bytes']==r['configured_bytes']and ctx['native_minimum_bytes']<=r['assigned_bytes']<=ctx['paid_grant_bytes'],
            'readback','unsettled or undercharged native allocation')
        if observation.effect is not None and observation.effect.get('status')=='unknown':raise UnknownOutcome('original_native_outcome_unknown')
        if any(isinstance(j,Mapping)and j.get('state')=='unknown'for j in observation.jobs):raise UnknownOutcome('original_job_outcome_unknown')
        for value in (observation.total_bytes,observation.available_bytes,observation.slurm_memory_bytes):number(present(value))
        require(0<observation.total_bytes and observation.available_bytes<=observation.total_bytes,'guest_capacity','actual guest memory invalid')
        if observation.slurm_registered is None:raise MissingEvidence('registration_not_measured')
        require(observation.slurm_registered is True,'qualification','actual Slurm registration failed');sha(observation.evidence_sha256)
        if observation.source_records is not None:require(fingerprint(plain(observation.source_records))==observation.evidence_sha256,'capacity_evidence','original Source projection digest differs')
    q=measured_capacity(permit);supported={row['assigned_bytes']for row in permit['capacity_measurement']['mapping_samples']}
    for observation in observations:
        if observation.readback['assigned_bytes']not in supported:raise MissingEvidence('actual_target_mapping_not_measured')
        require(observation.total_bytes<=q.maximum_guest_total_bytes and
            max(0,observation.readback['assigned_bytes']-observation.total_bytes)<=q.native_gap_bound_bytes,
            'capacity_evidence','current native/guest mapping contradicts scoped measurements')
        if any(j.get('state')!='closed'for j in observation.jobs):_physical(observation,permit)
    return ctx

def _effect(observation,ctx):
    e=present(observation.effect);exact(e,EFFECT_FIELDS);sha(e['original_evidence_sha256'])
    require(e['status']=='returned_success'and type(e['dispatches'])is int and e['dispatches']==1,'cleanup_evidence','one completed original native effect required')
    from host_resource_native_cleanup import decode_witness
    witness=plain(present(e['witness']));intent=decode_witness(witness)
    require(witness['phase']=='RETURNED_SUCCESS'and intent.mutation_id==e['mutation_id']and
        intent.old_bytes==e['old_bytes']and intent.target_bytes==e['target_bytes']and intent.before_revision==e['before_revision']and
        intent.host_id==ctx['host_id']and intent.owner_id==ctx['owner_id']and intent.host_boot_id==ctx['host_boot_id']and
        intent.policy_sha256==ctx['policy_sha256']and as_binding(intent.binding)==plain(ctx['binding'])and
        observation.readback['assigned_bytes']==e['target_bytes'],'cleanup_evidence','original C witness/readback/context differs')
    sha(present(e['readback_sha256']));return e

def _transition(before,after,ctx):
    e=_effect(after,ctx)
    require(e['old_bytes']==before.readback['assigned_bytes']==before.readback['configured_bytes']and
        e['target_bytes']==after.readback['assigned_bytes']==after.readback['configured_bytes']and
        e['before_revision']==before.readback['revision']and e['old_bytes']!=e['target_bytes'],
        'cleanup_evidence','original C old/target/revision must join actual before/after transition')
    return e

def as_binding(binding):return {f.name:getattr(binding,f.name)for f in fields(binding)}

def _closed_job(job,ctx):
    final=present(job['completed_final']);sha(present(job['absence_sha256']));sha(present(job['revoked_sha256']))
    from host_resource_facts import _scheduler_output_observations,_output_native_tuple
    native=plain(job['native']);generation=native['generation']
    outputs=_scheduler_output_observations(dict(schema='qcl.host-resource-scheduler-facts.v1',jobs={native['native_id']:native},outputs={generation:plain(final)}))
    output=outputs[generation];b=ctx['binding']
    require(output['scope']=='completed_final'and output['durable']is True and output['native_tuple']==_output_native_tuple(native)and
        output['owner']==plain(present(ctx['output_owner']))and output['owner']['source_graph_sha256']==ctx['source_graph_sha256']and
        output['attempt']['calcjob_uuid']==job['calcjob_uuid']and output['attempt']['generation']==job['creator_generation']and
        output['worker_identity']==dict(machine_id=ctx['worker_machine_id'],boot_id=b['guest_boot_id'],kernel=b['guest_kernel_id'],dmi_uuid=b['native_id']),
        'cleanup','genuine completed_final owner/source/worker/original creator differs')

def _jobs(observation,permit):
    require(type(observation.jobs)is tuple,'shape','explicit complete authorized snapshot required')
    expected=permit['authorized_demands'];jobs={}
    for j in observation.jobs:
        exact(j,JOB_FIELDS);key=j['calcjob_uuid'];require(key in expected and key not in jobs,'incomplete_workloads','extra or repeated job in authorized snapshot')
        require(j['demand_bytes']==expected[key]and type(j['demand_bytes'])is int,'capacity_evidence','real authorized commitment differs')
        sha(j['creator_generation']);sha(j['creator_sha256']);native=j['native']
        require(isinstance(native,Mapping)and native.get('owner_uid')==3000,'ownership','actual owned scheduler allocation required')
        exact(native,{'native_id','kind','generation','owner_uid','node','state','terminal','limit_bytes','submit_time','start_time','cluster','raw_user_id','exit_code'})
        require(native['kind']=='slurm_allocation'and type(native['native_id'])is str and re.fullmatch(r'[1-9][0-9]{0,18}',native['native_id'])and
            re.fullmatch(r'[^()\s]+\(3000\)',native['raw_user_id'])and native['generation']==fingerprint([native[k]for k in
                ('cluster','native_id','raw_user_id','submit_time','start_time')]+['0']),
            'native_generation','original literal allocated tuple/generation differs')
        group=present(j['cgroup']);exact(group,{'populated','processes','memory_max_bytes'})
        require(type(group['populated'])is bool and isinstance(group['processes'],(tuple,list))and
            group['populated']==bool(group['processes'])and fingerprint(plain(group))==j['cgroup_sha256'],
            'incomplete_workloads','actual complete cgroup projection differs')
        if j['state']=='unknown':raise UnknownOutcome('original_job_outcome_unknown')
        if j['state']=='closed':
            require(group['populated']is False and not group['processes'],'cleanup','original subtree still populated')
            _closed_job(j,permit['context'])
        elif j['state']=='live':
            require(native.get('terminal')is False and native.get('state')=='RUNNING','native_state','actual live generation required')
            sha(present(j['prolog_sha256']));sha(present(j['cgroup_sha256']));number(present(j['task_limit_bytes']),positive=True)
            require(group['populated']is True and group['memory_max_bytes']==j['task_limit_bytes']==native.get('limit_bytes')<=j['demand_bytes'],
                'guest_capacity','actual native/cgroup task limit differs')
        elif j['state']not in {'held','authorized','revoked'}:require(False,'shape','unknown private job phase')
        jobs[key]=j
    if set(jobs)!=set(expected):raise MissingEvidence('every_original_authorized_job_not_measured')
    return jobs

def _physical(observation,permit):
    q=measured_capacity(permit);ctx=permit['context'];jobs=_jobs(observation,permit)
    active=[j for j in jobs.values()if j['state']!='closed']
    if not active:raise MissingEvidence('actual_workload_not_measured')
    for j in active:
        present(j['task_limit_bytes'])
        if j['state']!='live':raise MissingEvidence('actual_pending_body_cgroup_not_measured')
    validate_guest_admission(qualification=q,native_minimum_bytes=ctx['native_minimum_bytes'],paid_grant_bytes=ctx['paid_grant_bytes'],
        assigned_bytes=observation.readback['assigned_bytes'],configured_bytes=observation.readback['configured_bytes'],
        total_bytes=observation.total_bytes,available_bytes=observation.available_bytes,demands=[j['demand_bytes']for j in active],
        task_limits=[j['task_limit_bytes']for j in active],candidate_index=max(range(len(active)),key=lambda i:active[i]['demand_bytes']),
        slurm_memory_bytes=observation.slurm_memory_bytes,quantum_bytes=ctx['quantum_bytes'],
        limits_enforced=all(j['cgroup']['memory_max_bytes']==j['task_limit_bytes']for j in active),**expected_capacity(ctx,q.report_sha256))
    return jobs

def _rejected(observation,permit):
    jobs=_jobs(observation,permit);ctx=permit['context'];e=present(observation.effect);exact(e,EFFECT_FIELDS)
    floor=rounded_native_floor(ctx['native_minimum_bytes'],[j['demand_bytes']for j in jobs.values()if j['state']!='closed'],ctx['quantum_bytes'])
    require(number(present(observation.proposed_target_bytes),positive=True)<floor and
        e['status']=='pre_dispatch_refused'and e['mutation_id']is None and type(e['dispatches'])is int and e['dispatches']==0 and e['witness']is None and
        e['old_bytes']==observation.readback['assigned_bytes']==observation.readback['configured_bytes']and
        e['target_bytes']==observation.proposed_target_bytes and e['before_revision']==observation.readback['revision']and
        e['reply_status']=='not_dispatched'and e['failure_code']=='aggregate_floor','cleanup_evidence','actual below-aggregate refusal must precede any C dispatch')
    sha(e['original_evidence_sha256'])

def observed_pressure(before,after):
    """Pair actual PSI/cgroup counters; missing pressure remains unmeasured."""
    require(type(before)is CalibrationObservation and type(after)is CalibrationObservation and
        plain(before.context)==plain(after.context)and before.sequence<after.sequence,
        'identity_mismatch','ordered same-scope raw pressure pair required')
    a=validate_accounting(before.accounting,before.context);b=validate_accounting(after.accounting,after.context)
    require(set(a['jobs'])==set(b['jobs'])and a['jobs']and all(a['jobs'][key]['generation']==b['jobs'][key]['generation']and a['jobs'][key]['cgroup']==b['jobs'][key]['cgroup']and
        a['jobs'][key]['scope']==b['jobs'][key]['scope']=='present'for key in a['jobs']),
        'native_generation','same actual cgroups required across pressure observation')
    for observation,accounting in ((before,a),(after,b)):
        allocated={j['native']['native_id']:j for j in observation.jobs if j['state']=='live'}
        require(set(allocated)==set(accounting['jobs']),'native_generation','raw accounting must cover exactly original live allocated jobs')
        for key,row in accounting['jobs'].items():
            job=allocated[key];path=row['cgroup']
            require(type(path)is str and str(PurePosixPath(path))==path and '..'not in PurePosixPath(path).parts and
                path.startswith('/sys/fs/cgroup/')and path.endswith('/job_'+key)and
                row['generation']==job['native']['generation']and row['memory_max_bytes']==job['task_limit_bytes']==job['cgroup']['memory_max_bytes'],
                'native_generation','raw cgroup path/generation/limit differs from original allocation')
            if observation.source_records is not None and 'child_jobs'in observation.source_records:
                root=observation.source_records['child_jobs']['permit']['cgroup_scope']
                require(path=='/sys/fs/cgroup'+root+'/job_'+key,'native_generation','raw accounting outside original protected child cgroup scope')
    return dict(scope='actual PSI stall and original cgroup memory.current',some_total_before=a['pressure']['some']['total'],
        some_total_after=b['pressure']['some']['total'],memory_current_before=sum(row['memory_current_bytes']for row in a['jobs'].values()),
        memory_current_after=sum(row['memory_current_bytes']for row in b['jobs'].values()),
        evidence_sha256=fingerprint(dict(before=plain(a),after=plain(b))))


def evaluate_case(name,observations,permit):
    require(name in REQUIRED_CASES,'shape','implemented native case required')
    rows=tuple(observations);app=frozen(plain(permit.get('context',{})))
    try:
        ctx=_samples(rows,permit);last=rows[-1]
        if name in {'idle-shrink','idle-grow','restore-full'}:
            if len(rows)<2:raise MissingEvidence('unequal_transition_not_measured')
            e=_transition(rows[0],last,ctx);old=rows[0].readback['assigned_bytes'];target=last.readback['assigned_bytes']
            require(e['old_bytes']==old and old!=target,'readback','no-op is not a transition')
            require((target<old if name=='idle-shrink'else target>old),'readback','actual transition direction differs')
            if name=='restore-full':require(target==ctx['native_maximum_bytes'],'readback','full native restoration missing')
        elif name=='near-floor':
            jobs=_physical(rows[1]if len(rows)>1 else last,permit);after=rows[1]if len(rows)>1 else last
            _transition(rows[0],after,ctx);demands=[j['demand_bytes']for j in jobs.values()if j['state']!='closed']
            require(rows[0].readback['assigned_bytes']==rounded_native_floor(ctx['native_minimum_bytes'],(),ctx['quantum_bytes'])and
                after.readback['assigned_bytes']==rounded_native_floor(ctx['native_minimum_bytes'],demands,ctx['quantum_bytes'])and
                after.readback['assigned_bytes']<ctx['native_maximum_bytes'],'guest_capacity','actual ordinary low-idle-to-rounded-floor target required')
            if len(rows)<3:raise MissingEvidence('both_floor_boundary_sides_not_measured')
            _rejected(rows[-1],permit)
        elif name=='active-floor-protection':
            first=None;closed=None;rejected=False;originals=None
            for o in rows:
                jobs=_physical(o,permit);live={key:j for key,j in jobs.items()if j['state']=='live'}
                identities={key:(j['creator_generation'],j['creator_sha256'],j['native']['generation'])for key,j in jobs.items()}
                if originals is None:originals=identities
                require(identities==originals,'native_generation','overlap/final substituted an original creator or allocated generation')
                if len(live)>=2 and first is None:first=live
                if first is not None and any(j['state']=='closed'for key,j in jobs.items()if key in first)and any(key in first for key in live):closed=jobs
                if o.proposed_target_bytes is not None:_rejected(o,permit);rejected=True
            if first is None or closed is None or not rejected:raise MissingEvidence('synchronized_overlap_final_and_other_floor_not_measured')
        elif name=='pressure':
            _physical(last,permit);p=present(last.pressure)
            if len(rows)<2:raise MissingEvidence('raw_pressure_pair_not_measured')
            require(plain(p)==observed_pressure(rows[0],last),'capacity_evidence','pressure projection differs from original actual counters')
            exact(p,{'scope','some_total_before','some_total_after','memory_current_before','memory_current_after','evidence_sha256'})
            text(p['scope']);sha(p['evidence_sha256'])
            for key in ('some_total_before','some_total_after','memory_current_before','memory_current_after'):number(p[key])
            if p['some_total_after']<=p['some_total_before']or p['memory_current_after']<=p['memory_current_before']:
                raise MissingEvidence('actual_pressure_not_measured')
        elif name=='supported-rejection':
            if len(rows)<2:raise MissingEvidence('refusal_before_after_not_measured')
            _rejected(last,permit);require(plain(rows[0].readback)==plain(last.readback),'readback','refused target changed original native readback/revision')
        elif name=='lost-outer-response':
            if len(rows)<2:raise MissingEvidence('original_reload_not_measured')
            effects=[_effect(o,ctx)for o in rows]
            require(len({fingerprint(plain(e))for e in effects})==1 and all(e['reply_status']=='lost_outer'for e in effects),
                'cleanup_evidence','durable original C success and one UUID on outer-reply loss required')
        else:
            measured_capacity(permit);jobs=_jobs(last,permit)
            if any(j['state']!='closed'for j in jobs.values()):raise MissingEvidence('all_original_jobs_not_closed')
            c=present(last.closure);exact(c,{'revoked_sequence','jobs_closed_sequence','native_restored_sequence','fence_closed_sequence',
                'revocation_sha256','jobs_closed_sha256','native_restored_sha256','fence_closed_sha256',
                'unresolved_mutation_ids','guard_processes','sudo_processes'})
            for key in ('revoked_sequence','jobs_closed_sequence','native_restored_sequence','fence_closed_sequence'):number(c[key],positive=True)
            for key in ('revocation_sha256','jobs_closed_sha256','native_restored_sha256','fence_closed_sha256'):sha(c[key])
            require(isinstance(c['unresolved_mutation_ids'],(list,tuple))and isinstance(c['guard_processes'],(list,tuple))and
                isinstance(c['sudo_processes'],(list,tuple)),'cleanup','explicit original owner/process closure inventories required')
            if c['unresolved_mutation_ids']:raise UnknownOutcome('original_native_owner_unresolved')
            require(not c['guard_processes']and not c['sudo_processes'],'cleanup','issued guard/sudo ancestry still live')
            require(c['revoked_sequence']<=c['jobs_closed_sequence']<c['fence_closed_sequence']and
                c['native_restored_sequence']<c['fence_closed_sequence']and last.readback['assigned_bytes']==ctx['native_maximum_bytes'],
                'cleanup','revocation/job/native restoration/fence closure barrier differs')
        return CaseResult('PASS','observed_predicates_pass',rows,app)
    except MissingEvidence as error:return CaseResult('NOT_MEASURED',str(error),rows,app)
    except UnknownOutcome as error:return CaseResult('UNKNOWN',str(error),rows,app)
    except (ResourceError,CapacityValidationError,KeyError,TypeError,ValueError)as error:
        return CaseResult('FAIL',getattr(error,'code','malformed_observation'),rows,app)

def build_qualification_report(permit,case_observations):
    decode_permit(permit);require(isinstance(case_observations,Mapping)and set(case_observations)<=set(REQUIRED_CASES),'shape','finite implemented case map required')
    cases={}
    for name in REQUIRED_CASES:
        r=evaluate_case(name,case_observations.get(name,()),permit)
        cases[name]=dict(status=r.status,reason=r.reason,original_evidence=plain(r.original_evidence),applicability=plain(r.applicability))
    report=dict(schema=REPORT_SCHEMA,permit=plain(permit),cases=cases,native_recovery_limit='PVE_SERVER_TERMINAL_OPEN')
    require(len(json.dumps(report,sort_keys=True,allow_nan=False).encode())<=8*1024**2,'output_bound','bounded private metadata report required')
    return report

def qualification_candidate(report):
    try:
        exact(report,{'schema','permit','cases','native_recovery_limit'});require(report['schema']==REPORT_SCHEMA,'shape','private report schema')
        require(set(report['cases'])==set(REQUIRED_CASES),'shape','all required cases must remain visible')
        observed={name:tuple(CalibrationObservation(**row)for row in case['original_evidence'])for name,case in report['cases'].items()}
        rebuilt=build_qualification_report(report['permit'],observed)
        if rebuilt!=report or any(c['status']!='PASS'for c in rebuilt['cases'].values()):return None
        originals={}
        for rows in observed.values():
            for row in rows:
                e=row.effect
                if e is None or e.get('status')!='returned_success':continue
                identity=fingerprint(dict(witness=plain(e['witness']),original_evidence_sha256=e['original_evidence_sha256']))
                require(e['mutation_id']not in originals or originals[e['mutation_id']]==identity,
                    'cleanup_evidence','one original C UUID cannot identify different immutable effects')
                originals[e['mutation_id']]=identity
        ctx=report['permit']['context'];cap=capacity_document(report['permit'],report_sha256=fingerprint(report))
        decode_capacity_qualification_v2(cap,**expected_capacity(ctx,fingerprint(report)))
        return dict(host_id=ctx['host_id'],owner_id=ctx['owner_id'],binding=plain(ctx['binding']),policy_sha256=ctx['policy_sha256'],
            evidence_ref=ctx['qualification_ref'],qualified_dynamic=True,active_floor_protection=True,readback_verified=True,
            slurm_registration_verified=True,capacity=cap)
    except (MissingEvidence,UnknownOutcome,ResourceError,CapacityValidationError,KeyError,TypeError,ValueError):return None
