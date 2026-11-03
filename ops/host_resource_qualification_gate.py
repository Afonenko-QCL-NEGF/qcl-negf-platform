"""Private calibration job permits; never production admission or a second grant.

All I/O/effect ports belong to the existing authenticated Root/Slurm owners.
NativeSources has no installed owner by default. Dictionaries, UID, environment,
and these Source/L seams alone do not authenticate a process or a measurement.
"""
import base64
import hashlib
from pathlib import Path
import re

import native_attempt as native
from host_resource_operations import integer, require, strict_json
from host_resource_qualification import (CalibrationRepository, check_baseline,
    operation_id, catalog_names, _exists, _raw)

SCHEMA = 'qcl.host-resource-calibration-jobs.v1'
MIRROR = 'qcl.host-resource-calibration-job-mirror.v1'
DECISION = 'qcl.host-resource-calibration-gate.v1'
MAX_JOBS = 16                 # bounded finite metadata, not a campaign quota


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys), 'qualification_shape', 'exact private record required')
    return value


def digest(value):
    return hashlib.sha256(native.encoded(value)).hexdigest()


def sha(value):
    require(native.matches(value, native.SHA) and value != '0'*64,
        'qualification_shape', 'nonzero SHA256 required')


def store_path(value):
    native.path_value(value, absolute=True)
    require(value.startswith('/nix/store/'), 'qualification_shape', 'immutable Source path required')


def decode_permit(value):
    exact(value, {'schema','operation_id','parent_plan_sha256','fence_sha256','source_graph_sha256',
        'capacity_report_sha256','client_uid','guard','client_root','bash_executable','slurmstepd_executable',
        'slurmd_executable','cgroup_scope','submit','jobs'})
    require(value['schema'] == SCHEMA, 'qualification_shape', 'private jobs version required')
    operation_id(value['operation_id'])
    for key in ('parent_plan_sha256','fence_sha256','source_graph_sha256','capacity_report_sha256'):sha(value[key])
    require(type(value['client_uid']) is int and value['client_uid'] > 0,
        'qualification_shape', 'configured nonroot UID required')
    for role in ('guard','client_root'):
        identity=exact(value[role], {'executable','argv_prefix','source_path','source_sha256'})
        store_path(identity['executable']);store_path(identity['source_path']);sha(identity['source_sha256'])
        prefix=identity['argv_prefix']
        require(type(prefix) is list and len(prefix)==4 and all(type(x) is str for x in prefix) and
            prefix[1:3]==['-I','-c'] and 0<len(prefix[3])<=8192,
            'qualification_shape','exact immutable interpreter launcher required')
        store_path(prefix[0])
    for key in ('bash_executable','slurmstepd_executable','slurmd_executable'):store_path(value[key])
    native.path_value(value['cgroup_scope'],absolute=True)
    submit=exact(value['submit'],{'runuser','sbatch','spool_root'})
    store_path(submit['runuser']);store_path(submit['sbatch']);native.path_value(submit['spool_root'],absolute=True)
    jobs=value['jobs']
    require(type(jobs) is dict and 0<len(jobs)<=MAX_JOBS, 'qualification_shape', 'finite exact jobs required')
    for calc,row in jobs.items():
        native.canonical_uuid(calc)
        exact(row,{'launch','demand_bytes','vm_id','solver_executable','node_name','worker_machine_id','worker_boot_id'})
        integer(row['demand_bytes'],'authorized demand',1)
        require(native.matches(row['vm_id'],native.ID) and native.matches(row['node_name'],native.ID) and
            native.matches(row['worker_machine_id'],r'[0-9a-f]{32}'), 'qualification_shape','exact worker binding required')
        native.canonical_uuid(row['worker_boot_id']);store_path(row['solver_executable'])
        native.validate_request(dict(version=1,action='submit',calcjob_uuid=calc,launch=row['launch'],controls=None))
    require(len(native.encoded(value))<=1024**2,'state_full','bounded job permit required')
    return value


def demands(permit):
    return tuple(row['demand_bytes'] for row in decode_permit(permit)['jobs'].values())


def calibration_submit_allowed(launch, actor, permit, sources, *, fixture):
    decode_permit(permit)
    exact(actor,{'calcjob_uuid','action','launch','execution_sha256'})
    calc=actor['calcjob_uuid'];row=permit['jobs'].get(calc)
    require(row is not None and actor['action']=='submit' and actor['launch']==launch==row['launch'] and
        actor['execution_sha256']==launch['files']['native_execution']['sha256'] and
        fixture=='native-publication-v1','qualification_fixture','original authenticated publication input required')
    sources.protect_commitments(permit,demands(permit),'submit')
    return True


def mirror_record(permit, calc, creator, *, revision, enabled, command=None, original_intent_sha256=None):
    decode_permit(permit);require(calc in permit['jobs'],'qualification_job','job outside finite permit')
    require(type(revision) is int and revision in (0,1,2) and type(enabled) is bool,
        'qualification_shape','fixed mirror revision required')
    require((revision==0 and not enabled and creator is None and command is None and original_intent_sha256 is None) or
        (revision in (1,2) and enabled==(revision==1) and creator is not None),
        'qualification_shape','disabled/bound/revoked mirror order required')
    if creator is not None:
        native.validate_job(creator);sha(original_intent_sha256);native.path_value(command,absolute=True)
        require(all(creator[k] is None for k in ('node_name','start_time','worker_machine_id','worker_boot_id')),
            'qualification_creator','original held creator required')
    intent=None if creator is None else release_intent(permit,calc,creator,command,original_intent_sha256)
    return dict(schema=MIRROR,operation_id=permit['operation_id'],permit_sha256=digest(permit),
        calcjob_uuid=calc,revision=revision,enabled=enabled,creator=creator,command=command,
        original_intent_sha256=original_intent_sha256,release_intent=intent,
        release_intent_sha256=None if intent is None else digest(intent))


def release_intent(permit,calc,creator,command,original_intent_sha256):
    return dict(schema='qcl.host-resource-calibration-release-intent.v1',operation_id=permit['operation_id'],
        permit_sha256=digest(permit),calcjob_uuid=calc,generation=creator['generation'],
        job_id=creator['job_id'],submit_time=creator['submit_time'],dispatch_id=creator['dispatch_id'],
        command=command,original_intent_sha256=original_intent_sha256)


def submission_argv(permit, launch, snapshot, dispatch):
    p=permit['submit']
    return [p['runuser'],'-u','qcl-negf','--',p['sbatch'],'--hold','--parsable','--no-requeue',
        '--chdir',launch['remote_workdir'],'--comment',dispatch,snapshot['script_path']]


def check_native_demand(permit,row,fields):
    # Same literal memory grammar as the existing allocated reader, without
    # pretending pending StartTime/NodeList form an allocated generation.
    memory=re.fullmatch(r'([1-9][0-9]*)([KMGT]?)',fields.get('MinMemoryNode',''))
    require(memory is not None,'qualification_demand','explicit real native demand required')
    scale={'':1024**2,'K':1024,'M':1024**2,'G':1024**3,'T':1024**4}
    value=int(memory[1])*scale[memory[2]]
    integer(value,'native demand',1)
    require(value==row['demand_bytes'] and fields.get('UserId')=='qcl-negf('+str(permit['client_uid'])+')' and
        fields.get('Restarts')=='0' and fields.get('NumNodes')==fields.get('NumTasks')=='1' and
        fields.get('ArrayJobId','0')==fields.get('HetJobId','0')=='0',
        'qualification_demand','real original non-restarted single allocation demand differs')


def check_held(permit, calc, submission):
    exact(submission,{'creator','fields','intent'})
    creator=native.validate_job(submission['creator']);fields=submission['fields'];intent=submission['intent']
    row=permit['jobs'][calc];launch=row['launch']
    check_native_demand(permit,row,fields)
    exact(intent,{'dispatch_id','snapshot','context','native'})
    require(creator['dispatch_id']==intent['dispatch_id'] and all(creator[k] is None for k in
        ('node_name','start_time','worker_machine_id','worker_boot_id')),'qualification_creator','stable held creator required')
    original=intent['native'];actor=original['owner']['actor']
    exact(actor,{'calcjob_uuid','action','launch','execution_sha256'})
    require(actor==dict(calcjob_uuid=calc,action='submit',launch=launch,
        execution_sha256=launch['files']['native_execution']['sha256']),
        'qualification_creator','original actor tuple differs')
    snapshot=exact(intent['snapshot'],{'script_path','script_sha256'})
    command=str(Path(permit['submit']['spool_root'])/(creator['dispatch_id']+'.sh'))
    require(snapshot==dict(script_path=command,script_sha256=launch['files']['submit_script']['sha256']) and
        original['script_sha256']==snapshot['script_sha256'] and
        original['argv']==submission_argv(permit,launch,snapshot,creator['dispatch_id']),
        'qualification_creator','original held argv/script differs')
    require(fields.get('JobId')==creator['job_id'] and fields.get('SubmitTime')==creator['submit_time'] and
        fields.get('Comment')==creator['dispatch_id'] and fields.get('Command')==command and
        fields.get('WorkDir')==launch['remote_workdir'] and fields.get('JobState')=='PENDING' and
        fields.get('Reason')=='JobHeldUser' and fields.get('Priority')=='0' and
        fields.get('StartTime') in ('Unknown','N/A') and fields.get('NodeList') in ('(null)','None'),
        'qualification_creator','fresh held native fields required')
    expected=digest(dict(controller=intent['context'],job_id=creator['job_id'],submit_time=creator['submit_time'],
        dispatch_id=creator['dispatch_id'],command=command,workdir=launch['remote_workdir']))
    require(creator['generation']==expected and creator['controller_machine_id']==intent['context']['machine_id'] and
        creator['controller_boot_id']==intent['context']['boot_id'],
        'qualification_creator','original bind_job generation differs')
    return mirror_record(permit,calc,creator,revision=1,enabled=True,command=command,original_intent_sha256=digest(intent))


class QualificationJobs:
    """Small attached receipt owner using the original store.operation/flock.

    Unknown effects retain their exclusive intent and cannot be retried here.
    No method removes a fence, rewrites main state, submits or resubmits a job.
    """
    def __init__(self,parent,sources):
        self.parent,self.sources=parent,sources
        self.repo=CalibrationRepository(parent.store)
        self.folder=self.repo.folder(parent.operation)/'jobs'

    def path(self,calc,name):
        native.canonical_uuid(calc);return self.folder/calc/name

    def _parent(self):
        plan=self.repo.plan(self.parent.operation)
        check_baseline(self.parent.policy,self.parent.store,plan,self.parent._state())
        self.repo.active(self.parent.operation,plan)
        return plan

    def _load(self):
        plan=self._parent();p=decode_permit(self.repo.read(self.folder/'permit.json'))
        require(p['operation_id']==self.parent.operation and p['parent_plan_sha256']==self.repo.digest(
            self.repo.folder(self.parent.operation)/'plan.json') and
            p['fence_sha256']==self.repo.digest(self.repo.directory/'active.json') and
            p['source_graph_sha256']==plan['source_graph_sha256'] and
            all(x['vm_id'] in plan['bindings'] for x in p['jobs'].values()),
            'qualification_parent','original operation/fence/source binding differs')
        allowed={'stage-intent.json','staged.json','bind-intent.json','bound.json','release-intent.json','release-dispatch.json',
            'released.json','revoke-intent.json','revoked.json','closed.json'}
        require(set(catalog_names(self.parent.store,self.folder,MAX_JOBS+1))<=set(p['jobs'])|{'permit.json'},
            'qualification_catalog','unknown child job namespace')
        for calc in p['jobs']:
            require(set(catalog_names(self.parent.store,self.folder/calc,len(allowed)))<=allowed,
                'qualification_catalog','unknown child receipt')
            self._validate_receipts(p,calc)
        return p

    def _validate_receipts(self,p,calc):
        rows={name:self._read(calc,name+'.json') for name in ('stage-intent','staged','bind-intent','bound',
            'release-intent','release-dispatch','released','revoke-intent','revoked','closed')}
        def check(condition):require(condition,'qualification_catalog','inconsistent original child receipts')
        stage=mirror_record(p,calc,None,revision=0,enabled=False)
        if rows['stage-intent'] is not None:check(rows['stage-intent']==stage)
        if rows['staged'] is not None:check(rows['staged']==stage and rows['stage-intent']==stage)
        bound=rows['bind-intent']
        if bound is not None:
            check(rows['staged']==stage)
            check(bound==mirror_record(p,calc,bound.get('creator'),revision=1,enabled=True,
                command=bound.get('command'),original_intent_sha256=bound.get('original_intent_sha256')))
        if rows['release-intent'] is not None:check(bound is not None and rows['release-intent']==bound['release_intent'])
        if rows['bound'] is not None:check(bound is not None and rows['bound']==bound and rows['release-intent']==bound['release_intent'])
        if rows['release-dispatch'] is not None:
            check(rows['bound'] is not None and rows['release-dispatch']==rows['release-intent'])
        if rows['released'] is not None:
            check(rows['release-dispatch'] is not None and rows['released']==dict(job_id=bound['creator']['job_id'],
                generation=bound['creator']['generation'],released=True))
        revoked=rows['revoke-intent']
        if revoked is not None:
            previous=rows['bound'] or rows['staged']
            check(previous is not None and revoked=={**previous,'revision':2,'enabled':False})
        if rows['revoked'] is not None:check(revoked is not None and rows['revoked']==revoked)
        if rows['closed'] is not None:
            check(rows['released'] is not None and rows['revoked'] is not None)
            validate_closure(rows['closed'],bound['creator'])

    def _read(self,calc,name):
        path=self.path(calc,name)
        return self.repo.read(path) if _exists(path) else None

    def _put(self,calc,name,row):self.repo.exclusive(self.path(calc,name),row)

    def _durable(self,p):
        # A prior fsync/outer response may have failed after creating a name.
        # Re-establish original bytes/identity durability before NEW authority;
        # never infer completion, replay a CAS or repeat a Slurm command.
        self.repo.sync_record(self.repo.folder(self.parent.operation)/'plan.json')
        self.repo.sync_record(self.repo.directory/'active.json')
        self.repo.sync_record(self.folder/'permit.json')
        for calc in p['jobs']:
            for name in catalog_names(self.parent.store,self.folder/calc,10):
                self.repo.sync_record(self.path(calc,name))

    def _commitments(self,p):
        return tuple(row['demand_bytes'] for calc,row in p['jobs'].items() if self._read(calc,'closed.json') is None)

    def commitments(self):
        with self.parent.store.locked(read_only=True):return self._commitments(self._load())

    def evidence(self):
        """Bounded read-only originals for the independent observation owner.

        Missing receipts remain None. This does not manufacture current native
        allocation, cgroup limits, prolog, completed_final or physical capacity.
        """
        with self.parent.store.locked(read_only=True):
            p=self._load();jobs={};refs=[]
            names=('stage-intent','staged','bind-intent','release-intent','bound',
                'release-dispatch','released','revoke-intent','revoked','closed')
            for calc in p['jobs']:
                jobs[calc]={}
                for name in names:
                    path=self.path(calc,name+'.json');ref=None
                    if _exists(path):
                        raw=_raw(self.parent.store,path)
                        ref=dict(path=str(path.relative_to(self.parent.store.directory)),
                            sha256=hashlib.sha256(raw).hexdigest(),record=strict_json(raw.decode()))
                        refs.append((path,ref['sha256']))
                    jobs[calc][name]=ref
            result=dict(schema='qcl.host-resource-calibration-job-evidence.v1',operation_id=self.parent.operation,
                permit=p,permit_sha256=digest(p),jobs=jobs)
            require(len(native.encoded(result))<=2*1024**2,'state_full','bounded attached job evidence required')
            require(self._load()==p and all(self.repo.digest(path)==sha256 for path,sha256 in refs),
                'qualification_changed','original child evidence changed during snapshot')
            return result

    def _protect(self,p,phase):self.sources.protect_commitments(p,self._commitments(p),phase)

    def stage(self,permit):
        with self.parent.store.operation():
            self._parent();decode_permit(permit)
            require(not _exists(self.folder),'qualification_partial','retain original staged/unknown operation')
            self.sources.protect_commitments(permit,demands(permit),'stage')
            self.repo.exclusive(self.folder/'permit.json',permit);self._load();self._durable(permit)
            for calc in permit['jobs']:
                mirror=mirror_record(permit,calc,None,revision=0,enabled=False)
                self._put(calc,'stage-intent.json',mirror)
                self.sources.mirror_cas(calc,None,mirror)
                require(self.sources.mirror_read(calc)==mirror,'qualification_mirror','disabled mirror readback differs')
                self._put(calc,'staged.json',mirror)

    def submit_permit(self,launch,*,calcjob_uuid,actor=None,fixture=None):
        with self.parent.store.operation():
            p=self._load();row=p['jobs'].get(calcjob_uuid)
            require(row is not None and row['launch']==launch,'qualification_job','original authorized launch required')
            for calc in p['jobs']:
                require(self._read(calc,'staged.json') is not None and self._read(calc,'revoke-intent.json') is None,
                    'qualification_order','complete unrevoked disabled set required before submit')
            self._durable(p);self._protect(p,'submit-preflight')
            if actor is not None:calibration_submit_allowed(launch,actor,p,self.sources,fixture=fixture)
            return p

    def held_argv(self,launch,snapshot,dispatch):
        """Historical original Q1 argv only; not submit/release authority."""
        with self.parent.store.locked(read_only=True):
            p=self._load();selected=[]
            for calc,row in p['jobs'].items():
                mirror=self._read(calc,'bound.json')
                if row['launch']==launch and mirror is not None and mirror['creator']['dispatch_id']==dispatch:
                    require(snapshot==dict(script_path=mirror['command'],script_sha256=launch['files']['submit_script']['sha256']),
                        'qualification_creator','original held snapshot differs')
                    selected.append(calc)
            require(len(selected)<=1,'qualification_creator','ambiguous held original')
            return bool(selected)

    def bind_held(self,calc):
        with self.parent.store.operation():
            p=self._load();require(calc in p['jobs'],'qualification_job','authorized CalcJob required')
            require(self._read(calc,'bind-intent.json') is None and self._read(calc,'revoke-intent.json') is None,
                'qualification_partial','original bind/revoke intent retained; no replay')
            previous=self._read(calc,'staged.json')
            require(previous is not None and self.sources.mirror_read(calc)==previous,'qualification_order','disabled mirror required')
            self._durable(p)
            bound=check_held(p,calc,self.sources.held_submission(calc));self._protect(p,'bind')
            self._put(calc,'bind-intent.json',bound)
            # Root's exact release authorization is durable BEFORE enabling a
            # mirror. The original is carried intact into that one CAS/readback.
            self._put(calc,'release-intent.json',bound['release_intent'])
            self.sources.mirror_cas(calc,previous,bound)
            require(self.sources.mirror_read(calc)==bound,'qualification_mirror','bound mirror readback differs')
            self._put(calc,'bound.json',bound)

    def release(self,calc):
        with self.parent.store.operation():
            p=self._load();require(calc in p['jobs'],'qualification_job','authorized CalcJob required')
            require(self._read(calc,'release-dispatch.json') is None and self._read(calc,'revoke-intent.json') is None,
                'qualification_partial','original release dispatch/revoke retained; no replay')
            mirror=self._read(calc,'bound.json')
            require(mirror is not None and self.sources.mirror_read(calc)==mirror and
                check_held(p,calc,self.sources.held_submission(calc))==mirror,
                'qualification_order','fresh original held job and mirror required before release')
            require(self._read(calc,'release-intent.json')==mirror['release_intent'],
                'qualification_order','original prepublished root release intent required')
            self._durable(p);self._protect(p,'release');self._put(calc,'release-dispatch.json',mirror['release_intent'])
            result=self.sources.release_held(mirror['creator'])
            require(result==dict(job_id=mirror['creator']['job_id'],generation=mirror['creator']['generation'],released=True),
                'qualification_release','exact owner release acknowledgement required')
            self._put(calc,'released.json',result)

    def revoke(self):
        with self.parent.store.operation():
            p=self._load()
            self._durable(p)
            for calc in p['jobs']:
                require(self._read(calc,'revoke-intent.json') is None,'qualification_partial','retain original revoke; no replay')
                previous=self._read(calc,'bound.json') or self._read(calc,'staged.json')
                require(previous is not None and self.sources.mirror_read(calc)==previous,
                    'qualification_mirror','original mirror required before revoke')
                revoked={**previous,'revision':2,'enabled':False}
                self._put(calc,'revoke-intent.json',revoked)
                self.sources.mirror_cas(calc,previous,revoked)
                require(self.sources.mirror_read(calc)==revoked,'qualification_mirror','revocation readback differs')
                self._put(calc,'revoked.json',revoked)

    def close(self,calc):
        with self.parent.store.operation():
            p=self._load();require(calc in p['jobs'],'qualification_job','authorized CalcJob required')
            require(all(self._read(c,'revoked.json') is not None and self.sources.mirror_read(c)==self._read(c,'revoked.json')
                for c in p['jobs']),'qualification_order','revoke/read back every permit before closure')
            bound=self._read(calc,'bound.json')
            require(bound is not None and self._read(calc,'released.json') is not None,
                'qualification_closure','original released creator required')
            self._durable(p);proof=self.sources.closure(bound['creator'])
            validate_closure(proof,bound['creator'])
            self._put(calc,'closed.json',proof)

    def closure_ready(self):
        with self.parent.store.locked(read_only=True):
            p=self._load()
            return all(self._read(c,'closed.json') is not None and self._read(c,'revoked.json') is not None and
                self.sources.mirror_read(c)==self._read(c,'revoked.json') for c in p['jobs'])


def validate_closure(proof,creator):
    exact(proof,{'creator','completed_final_sha256','terminal_state','whole_subtree_absent','guards_absent','sudo_absent'})
    sha(proof['completed_final_sha256'])
    require(proof['creator']==creator and proof['terminal_state']=='COMPLETED' and
        all(proof[k] is True for k in ('whole_subtree_absent','guards_absent','sudo_absent')),
        'qualification_closure','genuine final and complete job/guard/sudo absence required')


def scheduler_generation(fields):
    keys=('JobId','UserId','SubmitTime','Comment','Command','WorkDir','Restarts','NumNodes','NumTasks','StartTime','NodeList','MinMemoryNode')
    require(type(fields) is dict and all(k in fields for k in keys),'qualification_scheduler','complete original scheduler fields required')
    return {k:fields[k] for k in keys}


def process_identity(row):
    # The actual authenticate_sudo_caller/LocalSources result has these six
    # fields. NativeSources additionally carries live state/comm/raw counters;
    # those volatile raw bytes are retained by its owner, not identity fields.
    keys=('pid','ppid','start_ticks','uids','cgroup','executable')
    require(type(row) is dict and all(k in row for k in keys),
        'qualification_caller','original process identity required')
    require(all(type(row[k]) is int and row[k]>0 for k in ('pid','ppid','start_ticks')),
        'qualification_caller','actual process PID/birth required')
    return {k:row[k] for k in keys}


def running_generation(fields):
    require(fields.get('JobState')=='RUNNING','qualification_scheduler','job no longer running')
    return scheduler_generation(fields)


def membership_identity(membership):
    return dict(identity=membership['identity'],job_id=membership['job_id'],job_cgroup=membership['job_cgroup'],
        owner_uid=membership['owner_uid'],
        processes=[dict(process_identity(p),exe=p['exe']) for p in sorted(membership['processes'],key=lambda p:p['pid'])],
        rows=sorted(membership['listpids_rows'],key=lambda p:p['pid']))


def calibration_gate_allowed(caller, original_hook, scheduler, permit, sources):
    """Readonly after authenticate_sudo_caller; supplied selectors confer no right.

    Source ports must read protected held mirrors/prolog and current process,
    script-FD, loaded-module and scheduler generations with bounded capture.
    This function never creates/adopts a generation on first guard invocation.
    """
    decode_permit(permit)
    require(sources.current_permit()==permit,'qualification_changed','protected permit changed')
    mirrors={calc:sources.mirror_read(calc) for calc in permit['jobs']}
    matches=[(calc,m) for calc,m in mirrors.items() if type(m) is dict and m.get('creator') is not None and
        m['creator']['job_id']==scheduler.get('JobId')]
    require(len(matches)==1,'qualification_mirror','exact original mirror required')
    calc,mirror=matches[0];row=permit['jobs'][calc];creator=mirror['creator']
    require(mirror==mirror_record(permit,calc,creator,revision=1,enabled=True,
        command=mirror.get('command'),original_intent_sha256=mirror.get('original_intent_sha256')),
        'qualification_mirror','unrevoked bound mirror required')
    fields=scheduler
    check_native_demand(permit,row,fields)
    generation=scheduler_generation(fields)
    # Root publishes/readbacks the exact enabled mirror before release. Do not
    # require a post-start ACK mirror CAS: an unknown release still retains the
    # complete commitment/fence. Original release intent/ACK remain report gates.
    require(running_generation(sources.scheduler_job(creator['job_id']))==generation and fields.get('JobId')==creator['job_id'] and
        fields.get('SubmitTime')==creator['submit_time'] and fields.get('Comment')==creator['dispatch_id'] and
        fields.get('Command')==mirror['command'] and fields.get('WorkDir')==row['launch']['remote_workdir'] and
        fields.get('JobState')=='RUNNING' and fields.get('NodeList')==row['node_name'] and
        native.matches(fields.get('StartTime'),r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}') and
        fields.get('UserId')=='qcl-negf('+str(permit['client_uid'])+')' and fields.get('Restarts')=='0',
        'qualification_scheduler','current original running job required')
    hook=original_hook
    exact(hook,{'phase','identity','job','context'})
    require(hook['phase']=='prolog' and scheduler_generation(hook['job']['fields'])==generation and
        hook['identity']['identity']['machine_id']==row['worker_machine_id'] and
        hook['identity']['identity']['boot_id']==row['worker_boot_id'] and
        sources.original_prolog(creator['job_id'],creator['dispatch_id'])==hook,
        'qualification_prolog','original authenticated root prolog required')
    unit=hook['context']['unit'];chain=hook['context']['chain']
    require(sources.slurmd_unit()==unit and unit['ActiveState']=='active' and
        native.matches(unit['InvocationID'],r'[0-9a-f]{32}') and type(chain) is list and 0<len(chain)<=16 and
        str(chain[-1]['pid'])==unit['MainPID'] and chain[-1]['executable']==permit['slurmd_executable'] and
        all(x['uids']==[0]*4 and native.engine.daemon_scope_bound(x['cgroup'],unit['ControlGroup']) for x in chain),
        'qualification_prolog','original root slurmd ancestry required')
    guard=sources.process(caller['pid']);native._caller_generation(guard)
    require(process_identity(guard)==process_identity(caller),'qualification_caller','actual returned sudo caller changed')
    bash=sources.process(guard['ppid']);step=sources.process(bash['ppid'])
    native._caller_generation(bash);native._caller_generation(step)
    for child,parent in ((guard,bash),(bash,step)):
        require(child['ppid']==parent['pid'] and child['start_ticks']>=parent['start_ticks']>0 and
            (child is bash or child['cgroup']==parent['cgroup']),
            'qualification_ancestry','original direct birth/cgroup join required')
    # Existing Slurm classifier has distinct user/task and privileged /slurm
    # cgroups. Do not invent equality between bash and root slurmstepd groups.
    import slurm_job_evidence as evidence
    membership_expected=dict(job_id=creator['job_id'],owner_uid=permit['client_uid'],
        slurmstepd_executable=permit['slurmstepd_executable'],cgroup_scope=permit['cgroup_scope'],
        identity=dict(machine_id=row['worker_machine_id'],boot_id=row['worker_boot_id']))
    membership=sources.batch_membership(creator)
    evidence.validate_before(membership,membership_expected)
    by_pid={x['pid']:x for x in membership['processes']}
    require(all(x['pid'] in by_pid and all(by_pid[x['pid']].get(k)==x.get(k) for k in
        ('pid','start_ticks','uids','cgroup')) for x in (bash,step)),
        'qualification_ancestry','actual scheduler batch membership required')
    require(guard['uids']==bash['uids']==[permit['client_uid']]*4 and step['uids']==[0]*4 and
        guard['executable']==permit['guard']['executable'] and bash['executable']==permit['bash_executable'] and
        step['executable']==permit['slurmstepd_executable'] and
        guard['cgroup'].startswith(permit['cgroup_scope']+'/job_'+creator['job_id']+'/step_batch/user/') and
        step['cgroup']==permit['cgroup_scope']+'/job_'+creator['job_id']+'/step_batch/slurm',
        'qualification_ancestry','original guard/bash/batch-step required')
    expected=permit['guard']['argv_prefix']+['guard','--release-id',row['launch']['release_id'],
        '--solver-executable',row['solver_executable']]
    argv={x['pid']:sources.command_line(x['pid']) for x in (guard,bash,step)}
    script=sources.batch_script(bash['pid'])
    require(argv[guard['pid']]==expected and type(script) is dict and
        script.get('sha256')==row['launch']['files']['submit_script']['sha256'] and
        argv[bash['pid']]==[permit['bash_executable'],script.get('path')] and
        argv[step['pid']]==['slurmstepd: ['+creator['job_id']+'.batch]'] and
        sources.loaded_guard_source(guard['pid'])==dict(path=permit['guard']['source_path'],sha256=permit['guard']['source_sha256']),
        'qualification_origin','exact guard argv/loaded source/original batch bytes required')
    expected_origins={permit['guard']['argv_prefix'][0]:guard['executable'],guard['executable']:guard['executable'],
        bash['executable']:bash['executable'],step['executable']:step['executable']}
    origins={p:sources.origin(p) for p in expected_origins}
    require(origins==expected_origins,'qualification_origin','immutable executable origins differ')
    sources.protect_commitments(permit,demands(permit),'guard')
    later_membership=sources.batch_membership(creator);evidence.validate_before(later_membership,membership_expected)
    later_processes=[sources.process(x['pid']) for x in (guard,bash,step)]
    for current in later_processes:native._caller_generation(current)
    require(all(process_identity(current)==process_identity(original) and
        sources.command_line(original['pid'])==argv[original['pid']] for original,current in zip((guard,bash,step),later_processes)) and
        sources.batch_script(bash['pid'])==script and sources.loaded_guard_source(guard['pid'])==
        dict(path=permit['guard']['source_path'],sha256=permit['guard']['source_sha256']) and
        sources.current_permit()==permit and all(sources.mirror_read(c)==m for c,m in mirrors.items()) and
        sources.original_prolog(creator['job_id'],creator['dispatch_id'])==hook and
        running_generation(sources.scheduler_job(creator['job_id']))==generation and sources.slurmd_unit()==unit and
        membership_identity(later_membership)==membership_identity(membership) and
        all(sources.origin(k)==v for k,v in origins.items()),
        'qualification_changed','caller/permit/mirror/prolog/source changed during readonly decision')
    return dict(schema=DECISION,purpose='calibration',allowed=True,operation_id=permit['operation_id'],
        calcjob_uuid=calc,generation=creator['generation'])


def read_qualification_gate(document,caller,sources):
    """Only the local client-root role may wire this after actual sudo auth.

    No new sudo/SSH/public resource action is registered by this module. Root
    Source collectors are deliberately mandatory, without positive defaults.
    """
    exact(document,{'schema','release_id','solver_executable'})
    require(document['schema']=='qcl.host-resource-calibration-guard-request.v1' and
        native.matches(document['release_id'],native.ID),'qualification_shape','private guard request required')
    store_path(document['solver_executable'])
    require(process_identity(sources.authenticated_caller())==process_identity(caller),
        'qualification_caller','actual sudo caller changed')
    context=exact(sources.guard_context(caller),{'permit','original_hook','scheduler'})
    p=decode_permit(context['permit']);own=exact(sources.root_ingress(),{'process','argv','source'})
    process=own['process'];native._caller_generation(process)
    argv=own['argv'];root=p['client_root']
    require(process['uids']==[0]*4 and process['executable']==root['executable'] and
        process['cgroup']==caller['cgroup'] and process['start_ticks']>=caller['start_ticks'] and
        type(argv) is list and len(argv)==len(root['argv_prefix'])+2 and
        argv[:-1]==root['argv_prefix']+['qualification-gate'] and type(argv[-1]) is str and len(argv[-1])<=4096 and
        own['source']==dict(path=root['source_path'],sha256=root['source_sha256']) and
        sources.origin(root['argv_prefix'][0])==root['executable'] and sources.origin(process['executable'])==root['executable'],
        'qualification_ingress','actual immutable client-root interpreter/argv/source required')
    try:original=strict_json(base64.b64decode(argv[-1],altchars=b'-_',validate=True).decode())
    except (ValueError,UnicodeError) as error:
        raise native.Hold('qualification_ingress') from error
    require(original==document,'qualification_ingress','actual root argv request differs')
    result=calibration_gate_allowed(caller,context['original_hook'],context['scheduler'],p,sources)
    row=p['jobs'][result['calcjob_uuid']]
    later=exact(sources.root_ingress(),{'process','argv','source'});native._caller_generation(later['process'])
    require(document['release_id']==row['launch']['release_id'] and document['solver_executable']==row['solver_executable'] and
        process_identity(later['process'])==process_identity(own['process']) and later['argv']==own['argv'] and
        later['source']==own['source'] and process_identity(sources.authenticated_caller())==process_identity(caller),
        'qualification_changed','actual root/caller/request changed during decision')
    return result
