"""Root calibration effect plumbing. No production readiness or measured N producer.

Private execution requires a staged actual idle runtime and the original resource
worker. Explicit injected sources are a synthetic test seam only.
Paid state v3 is never rewritten by this owner.
"""
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace
import uuid

from host_resource_operations import (HostResourceController, ResourceError, RuntimeBinding,
    VMReadback, integer, policy_digest, require, strict_json, text)
from host_resource_native_cleanup import MutationEffect, UUID, exact, digest_string
from host_resource_backends import fingerprint

PLAN_SCHEMA='qcl.host-resource-calibration-plan.v1'
EFFECT_SCHEMA='qcl.host-resource-calibration-effect.v1'
OWNER_SCHEMA='qcl.host-resource-native-effect-owner.v1'
FENCE_SCHEMA='qcl.host-resource-calibration-fence.v1'
CASE_SCHEMA='qcl.host-resource-calibration-case.v1'
CASES={'idle-shrink','idle-grow','restore-full'}
FIELDS=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
MAX_CATALOG_ENTRIES=4096
MAX_CATALOG_BYTES=16*1024**2

def operation_id(value):
    require(type(value)is str,'shape','operation UUID required')
    try:parsed=uuid.UUID(value)
    except(ValueError,AttributeError):raise ResourceError('shape','operation UUID required')from None
    require(str(parsed)==value,'shape','canonical operation UUID required');return value

def _raw(store,path):
    """Bounded held/named read in the already trusted store, no symlink descendants."""
    path=Path(path);parts=path.relative_to(store.directory).parts
    require(parts and all(p not in {'','..','.'}for p in parts),'trust','store-relative read required')
    parent=store.directory
    for part in parts[:-1]:parent=parent/part;store._check_path(parent,directory=True)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        store._check_fd(fd);before=os.fstat(fd)
        require(before.st_size<=1024**2,'state_full','bounded calibration metadata required')
        data=bytearray()
        while len(data)<=1024**2:
            block=os.read(fd,min(65536,1024**2+1-len(data)))
            if not block:break
            data.extend(block)
        after=os.fstat(fd);named=path.lstat()
        require(len(data)<=1024**2 and all(getattr(before,k)==getattr(after,k)==getattr(named,k)for k in FIELDS),
            'trust','calibration file changed during read')
        return bytes(data)
    finally:os.close(fd)

def _exists(path):
    try:path.lstat();return True
    except FileNotFoundError:return False

def decode_plan(doc):
    exact(doc,{'schema','operation_id','host_id','owner_id','host_boot_id','policy_sha256',
        'baseline_state_sha256','source_graph_sha256','bindings','cases'},'calibration plan')
    require(doc['schema']==PLAN_SCHEMA,'shape','calibration plan version');operation_id(doc['operation_id'])
    for n in ('host_id','owner_id','host_boot_id'):text(doc[n],n)
    for n in ('policy_sha256','baseline_state_sha256','source_graph_sha256'):digest_string(doc[n])
    require(type(doc['bindings'])is dict and doc['bindings'],'shape','explicit complete bindings required')
    for vm,row in doc['bindings'].items():
        binding=RuntimeBinding(**row);require(binding.vm_id==vm,'shape','binding VM differs')
        for n,v in asdict(binding).items():text(v,n)
    require(type(doc['cases'])is dict and 0<len(doc['cases'])<=len(CASES)and set(doc['cases'])<=CASES,
        'shape','finite implemented idle calibration cases required')
    for row in doc['cases'].values():
        exact(row,{'vm_id','target_bytes'},'calibration case');text(row['vm_id'],'vm_id')
        require(row['vm_id']in doc['bindings'],'ownership','case VM not bound');integer(row['target_bytes'],'target_bytes',1)
    return doc


def decode_case(doc,op,name):
    exact(doc,{'schema','operation_id','case','mutation_id'},'calibration case marker')
    require(doc['schema']==CASE_SCHEMA and doc['operation_id']==op and doc['case']==name,
        'calibration_catalog','original case marker identity changed')
    mid=doc['mutation_id']
    require(mid is None or type(mid)is str and UUID.fullmatch(mid),'shape','case mutation UUID required')
    return doc


def decode_owner_reference(doc,mid):
    exact(doc,{'schema','kind','operation_id','case','mutation_id','effect_sha256','plan_sha256'},'native effect owner')
    require(doc['schema']==OWNER_SCHEMA and doc['kind']=='calibration' and doc['mutation_id']==mid and
        type(mid)is str and UUID.fullmatch(mid) and type(doc['case'])is str and doc['case']in CASES,
        'effect_owner','unknown or mismatched native effect owner')
    operation_id(doc['operation_id']);digest_string(doc['effect_sha256']);digest_string(doc['plan_sha256'])
    return doc


def catalog_names(store,directory,limit):
    if not _exists(directory):return ()
    store._check_path(directory,directory=True);before=directory.lstat();names=[]
    with os.scandir(directory)as entries:
        for entry in entries:
            require(len(names)<limit,'state_full','bounded calibration metadata inventory required')
            names.append(entry.name)
    store._check_path(directory,directory=True);after=directory.lstat()
    require((before.st_dev,before.st_ino,before.st_mtime_ns,before.st_ctime_ns)==
        (after.st_dev,after.st_ino,after.st_mtime_ns,after.st_ctime_ns),'trust','calibration inventory changed during read')
    return tuple(sorted(names))


class CalibrationRepository:
    def __init__(self,store):self.store=store;self.directory=store.directory/'native-qualification'
    def folder(self,op):return self.directory/operation_id(op)
    def read(self,path):return strict_json(_raw(self.store,path).decode())
    def digest(self,path):return hashlib.sha256(_raw(self.store,path)).hexdigest()
    def plan(self,op):return decode_plan(self.read(self.folder(op)/'plan.json'))
    def exclusive(self,path,record):
        # Every name comes from a fixed schema/canonical UUID/case enum.
        require(path.is_relative_to(self.directory),'trust','calibration record outside owner')
        parent=self.directory
        parent.mkdir(mode=0o700,exist_ok=True);self.store._check_path(parent,directory=True)
        self.store._sync_directory(parent.parent)
        for part in path.relative_to(parent).parts[:-1]:
            parent=parent/part;parent.mkdir(mode=0o700,exist_ok=True);self.store._check_path(parent,directory=True)
            self.store._sync_directory(parent.parent)
        raw=json.dumps(record,sort_keys=True,separators=(',',':')).encode();require(len(raw)<=1024**2,'state_full','calibration record bound')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            self.store._check_fd(fd);view=memoryview(raw)
            while view:
                n=os.write(fd,view);require(n>0,'state','short calibration write');view=view[n:]
            os.fsync(fd)
        finally:os.close(fd)
        self.store._sync_directory(path.parent);self.store._sync_directory(self.directory);self.store._sync_directory(self.store.directory)
    def activate(self,op,plan):
        self.sync_record(self.folder(op)/'plan.json')
        path=self.directory/'active.json';record=dict(schema=FENCE_SCHEMA,operation_id=op,
            plan_sha256=self.digest(self.folder(op)/'plan.json'),baseline_state_sha256=plan['baseline_state_sha256'])
        if _exists(path):
            require(self.read(path)==record,'calibration_active','another original calibration fence exists')
            self.sync_record(path)
        else:self.exclusive(path,record)
        return record
    def active(self,op,plan):
        row=self.read(self.directory/'active.json')
        exact(row,{'schema','operation_id','plan_sha256','baseline_state_sha256'},'calibration fence')
        require(row==dict(schema=FENCE_SCHEMA,operation_id=op,plan_sha256=self.digest(self.folder(op)/'plan.json'),
            baseline_state_sha256=plan['baseline_state_sha256']),'calibration_active','original calibration fence changed')
    def case_path(self,op,name):
        require(name in CASES,'shape','implemented calibration case required');return self.folder(op)/'cases'/(name+'.json')
    def effect_path(self,op,mid):
        require(type(mid)is str and UUID.fullmatch(mid),'shape','native mutation UUID required');return self.folder(op)/'effects'/(mid+'.json')
    def readback_path(self,op,mid):return self.effect_path(op,mid).with_suffix('.readback.json')
    def sync_record(self,path):
        # Re-establish durability of an original record after an interrupted
        # fsync. Never replace bytes or infer native completion from existence.
        original=_raw(self.store,path);parents=[];parent=path.parent
        while True:
            self.store._check_path(parent,directory=True);parents.append((parent,parent.lstat()))
            if parent==self.store.directory:break
            parent=parent.parent
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            self.store._check_fd(fd);before=os.fstat(fd);os.fsync(fd)
            for parent,_ in parents:self.store._sync_directory(parent)
            self.store._check_fd(fd)
            after=os.fstat(fd);named=path.lstat()
            require(all(getattr(before,k)==getattr(after,k)==getattr(named,k)for k in FIELDS),
                'trust','original record inode changed during sync')
            require(_raw(self.store,path)==original,'trust','original record changed during sync')
            for parent,old in parents:
                self.store._check_path(parent,directory=True);now=parent.lstat()
                require((old.st_dev,old.st_ino)==(now.st_dev,now.st_ino),'trust','original record ancestor changed during sync')
        finally:os.close(fd)
    def record_readback(self,owner,witness,readback):
        row=readback_record(owner,witness,readback)
        self.exclusive(self.readback_path(owner.operation,owner.record['mutation_id']),row);return row


def readback_record(owner,witness,readback):
    r=owner.record;binding=RuntimeBinding(**r['binding'])
    require(readback.vm_id==binding.vm_id and readback.native_id==binding.native_id and
        readback.process_id==binding.process_id and readback.config_fingerprint==binding.config_fingerprint,
        'identity_mismatch','calibration target runtime/configuration changed')
    text(readback.revision,'revision')
    require(readback.running is True and type(readback.assigned_bytes)is int and
        type(readback.configured_bytes)is int and readback.assigned_bytes==readback.configured_bytes==r['target_bytes'],
        'readback','full calibration target not observed')
    return dict(schema='qcl.host-resource-calibration-readback.v1',operation_id=owner.operation,
        case=r['case'],mutation_id=r['mutation_id'],effect_sha256=owner.reference['effect_sha256'],
        witness_sha256=fingerprint(witness),readback=asdict(readback),status='READBACK_CONFIRMED',native_qualification='NOT_MEASURED')



def require_no_active_calibration(store):
    root=store.directory/'native-qualification'
    if not _exists(root):return
    store._check_path(root,directory=True)
    if _exists(root/'active.json'):
        # Task 1 never closes/adopts a fence. Full measured job/restore/revocation
        # closure belongs to the later report task; malformed fences also block.
        _raw(store,root/'active.json')
        raise ResourceError('calibration_active','original calibration fence requires full owner reconciliation')


def check_baseline(policy,store,plan,state):
    raw=_raw(store,store.state_path)
    require(hashlib.sha256(raw).hexdigest()==plan['baseline_state_sha256']and strict_json(raw.decode())==state,
        'calibration_baseline','original paid baseline changed')
    require(plan['host_id']==policy.host_id and plan['owner_id']==policy.owner_id and
        plan['host_boot_id']==state['host_boot_id']and plan['policy_sha256']==state['policy_sha256']==policy_digest(policy)
        and plan['bindings']==state['bindings'],'identity_mismatch','calibration host/policy/runtime changed')
    require(state['blocked']is None and state['receipts']==[],'reconciliation_required','calibration requires no earlier paid operation')
    for grant in state['grants']:
        vm=next(v for v in policy.vms if v.vm_id==grant['vm_id']);startup=state['startups'][vm.vm_id]
        require(grant['guest_bytes']==vm.maximum_bytes and grant['active_floor_bytes']==vm.minimum_bytes and
            grant['state']=='idle'and state['desired'][vm.vm_id]==vm.maximum_bytes and startup['phase']=='running_quarantined'
            and state['bindings'][vm.vm_id]is not None,'calibration_baseline','full paid maxima and quarantine required')


def observed_guard(proofs,plan,state,before,target,*,case_name):
    guard=getattr(proofs.sources,'calibration_guard',None)
    require(callable(guard),'qualification_observations_required','actual calibration observation guard is not installed')
    # Installed NativeCleanupSources has no positive default or injected plan
    # capability. Later tasks must supply a real source-authenticated guard.
    return guard(plan,state,before,target,case_name=case_name)


class CalibrationEffectOwner:
    def __init__(self,proofs,reference,*,mutation_id):
        self.proofs=proofs;self.repository=CalibrationRepository(proofs.store)
        decode_owner_reference(reference,mutation_id)
        self.reference=reference;self.operation=operation_id(reference['operation_id']);digest_string(reference['effect_sha256']);digest_string(reference['plan_sha256'])
        self.plan=self.repository.plan(self.operation);self.repository.active(self.operation,self.plan)
        path=self.repository.effect_path(self.operation,mutation_id)
        require(self.repository.digest(path)==reference['effect_sha256']and self.repository.digest(self.repository.folder(self.operation)/'plan.json')==reference['plan_sha256'],
            'effect_owner','original calibration effect/plan changed')
        self.record=self.repository.read(path)
        exact(self.record,{'schema','operation_id','case','mutation_id','request_id','vm_id','binding','operation','old_bytes','target_bytes','mutation_started_at','native_context','before_revision','plan_sha256'},'calibration native effect')
        r=self.record;require(r['schema']==EFFECT_SCHEMA and r['operation_id']==self.operation and r['case']==reference['case']and
            r['case']in self.plan['cases']and r['mutation_id']==mutation_id and r['plan_sha256']==reference['plan_sha256'],
            'effect_owner','calibration effect selector changed')
        require(r['vm_id']==self.plan['cases'][r['case']]['vm_id']and r['target_bytes']==self.plan['cases'][r['case']]['target_bytes']and
            r['binding']==self.plan['bindings'][r['vm_id']],'effect_owner','original case/binding differs')
        for k in ('old_bytes','target_bytes'):integer(r[k],k,1)
        integer(r['mutation_started_at'],'mutation_started_at');text(r['request_id'],'request_id');text(r['before_revision'],'before_revision')
        require(r['operation']==('shrink'if r['target_bytes']<r['old_bytes']else'grow')and r['target_bytes']!=r['old_bytes'],'effect_owner','effect direction/no-op differs')
        require(self.repository.read(self.repository.case_path(self.operation,r['case']))==dict(schema='qcl.host-resource-calibration-case.v1',operation_id=self.operation,case=r['case'],mutation_id=mutation_id),
            'effect_owner','original case is not this effect')
    def effect(self,state,mutation_id):
        require(mutation_id==self.record['mutation_id'],'effect_owner','effect UUID differs')
        check_baseline(self.proofs.policy,self.proofs.store,self.plan,state)
        r=self.record
        return MutationEffect(r['request_id'],r['vm_id'],mutation_id,r['operation'],r['old_bytes'],r['target_bytes'],
            r['mutation_started_at'],r['native_context'],r['before_revision'],
            binding=RuntimeBinding(**r['binding']),owner_sha256=fingerprint(self.reference))
    def proof_effect(self,state,mutation_id):return self.effect(state,mutation_id)
    def check(self,state,effect,before):
        require(not _exists(self.repository.readback_path(self.operation,effect.mutation_id)),'cleanup_evidence','calibration effect already confirmed; no replay')
        check_baseline(self.proofs.policy,self.proofs.store,self.plan,state)
        service=NativeQualificationService(self.proofs.policy,self.proofs.store,self.proofs,operation_id=self.operation)
        require(service._catalog(self.plan,state)==[effect.mutation_id],
            'calibration_pending','one original owned calibration slot required')
        observed_guard(self.proofs,self.plan,state,before,effect.target_bytes,case_name=self.record['case'])


class NativeQualificationService:
    def __init__(self,policy,store,proofs,*,operation_id):
        self.policy,self.store,self.proofs=policy,store,proofs;self.operation=globals()['operation_id'](operation_id)
        self.repository=CalibrationRepository(store)
    def _state(self):return HostResourceController(self.policy,self.store,self.proofs.backend)._load()
    def _plan_pin(self,expected):
        if expected is not None:
            digest_string(expected)
            require(self.repository.digest(self.repository.folder(self.operation)/'plan.json')==expected,
                'calibration_plan_changed','original worker plan pin changed')
    def inspect(self):
        with self.store.locked(read_only=True):
            plan=self.repository.plan(self.operation);state=self._state();check_baseline(self.policy,self.store,plan,state)
            return dict(state='CALIBRATION_SOURCE_ONLY_NOT_QUALIFIED',operation_id=self.operation,native_qualification='NOT_MEASURED',baseline_state_sha256=plan['baseline_state_sha256'])
    def _catalog(self,plan,state):
        """Cross-check independent protected records; a null marker releases no slot."""
        folder=self.repository.folder(self.operation);cases=folder/'cases';effects=folder/'effects'
        marked=[]
        for filename in catalog_names(self.store,cases,len(CASES)):
            require(filename.endswith('.json') and filename[:-5]in plan['cases'],
                'calibration_catalog','unknown original case marker')
            row=decode_case(self.repository.read(cases/filename),self.operation,filename[:-5])
            if row['mutation_id']is not None:marked.append(row['mutation_id'])
        require(len(marked)==len(set(marked)),'calibration_catalog','mutation shared by different cases')
        effect_ids=set();readback_ids=set()
        for filename in catalog_names(self.store,effects,2*len(plan['cases'])):
            match=re.fullmatch(r'([0-9a-f]{32})(\.readback)?\.json',filename)
            require(match is not None,'calibration_catalog','unknown attached effect record')
            (readback_ids if match[2]else effect_ids).add(match[1])
        # Production C witnesses have no owner selector. Inspect fixed C file
        # families to find original calibration provenance even if its marker,
        # effect or selector was independently lost/corrupted. This is bounded
        # metadata inspection, never cleanup, state repair or native replay.
        owner_ids=set();native_ids=set();remaining=MAX_CATALOG_BYTES
        prefix='calibration:'+self.operation+':'
        for filename in catalog_names(self.store,self.proofs.directory,MAX_CATALOG_ENTRIES):
            match=re.fullmatch(r'([0-9a-f]{32})(\.(?:owner|intent|target|storage))?\.json',filename)
            require(match is not None,'calibration_catalog','unknown native ownership record')
            raw=_raw(self.store,self.proofs.directory/filename);remaining-=len(raw)
            require(remaining>=0,'state_full','bounded native calibration provenance required')
            doc=strict_json(raw.decode());require(type(doc)is dict,'shape','native ownership object required')
            mid=match[1]
            if match[2]=='.owner':
                reference=decode_owner_reference(doc,mid)
                if reference['operation_id']==self.operation:owner_ids.add(mid)
            else:
                subject=doc.get('intent',doc.get('subject',doc))
                require(type(subject)is dict,'shape','native ownership subject required')
                request=subject.get('request_id')
                if type(request)is str and request.startswith(prefix):
                    require(subject.get('mutation_id')==mid,'calibration_catalog','native provenance mutation differs')
                    native_ids.add(mid)
        ids=set(marked)
        require(ids==effect_ids==owner_ids and native_ids<=ids and readback_ids<=ids,
            'calibration_catalog','missing, dangling or hidden original effect/owner/native record')
        pending=[]
        for mid in sorted(ids):
            owner=self.proofs.owner_for(mid)
            require(type(owner)is CalibrationEffectOwner and owner.operation==self.operation,
                'calibration_catalog','effect catalog owner differs')
            owner.effect(state,mid)
            if mid in readback_ids:self._confirmed(mid,state)
            else:pending.append(mid)
        require(len(pending)<=1,'calibration_pending','multiple unresolved original calibration effects')
        return pending
    def _prepare_case(self,name):
        plan=self.repository.plan(self.operation);require(name in plan['cases'],'shape','case not in original plan')
        state=self._state();check_baseline(self.policy,self.store,plan,state);case=plan['cases'][name]
        marker=self.repository.case_path(self.operation,name)
        require(not _exists(marker),'calibration_case_exists','retain original case; no replay/adoption')
        require(not self._catalog(plan,state),'calibration_pending','original effect needs reconciliation before another case')
        before=self.proofs.backend.readback(case['vm_id']);target=case['target_bytes']
        vm=next(v for v in self.policy.vms if v.vm_id==case['vm_id'])
        require(vm.minimum_bytes<=target<=vm.maximum_bytes and target%self.proofs.backend.quantum_bytes==0,
            'calibration_target','target outside paid policy/quantum')
        binding=RuntimeBinding(**state['bindings'][vm.vm_id])
        require(before.running and before.native_id==binding.native_id and before.process_id==binding.process_id and before.config_fingerprint==binding.config_fingerprint,
            'identity_mismatch','actual calibration native binding changed')
        observed_guard(self.proofs,plan,state,before,target,case_name=name)
        self.proofs.profile(binding,state['host_boot_id']);self.repository.activate(self.operation,plan)
        if before.assigned_bytes==before.configured_bytes==target:
            self.repository.exclusive(marker,dict(schema='qcl.host-resource-calibration-case.v1',operation_id=self.operation,case=name,mutation_id=None))
            return dict(status='NO_OP',operation_id=self.operation,case=name,mutation_id=None,native_qualification='NOT_MEASURED')
        require(before.assigned_bytes==before.configured_bytes,'readback','calibration before memory unsettled')
        mid=uuid.uuid4().hex;context=self.proofs.sources.context({'mutation_id':mid})
        record=dict(schema=EFFECT_SCHEMA,operation_id=self.operation,case=name,mutation_id=mid,
            request_id='calibration:'+self.operation+':'+name+':'+mid,vm_id=vm.vm_id,binding=asdict(binding),
            operation='shrink'if target<before.assigned_bytes else'grow',old_bytes=before.assigned_bytes,target_bytes=target,
            mutation_started_at=int(self.proofs.sources.clock()),native_context=context,before_revision=before.revision,
            plan_sha256=self.repository.digest(self.repository.folder(self.operation)/'plan.json'))
        self.repository.exclusive(marker,dict(schema='qcl.host-resource-calibration-case.v1',operation_id=self.operation,case=name,mutation_id=mid))
        path=self.repository.effect_path(self.operation,mid);self.repository.exclusive(path,record)
        self.proofs.exclusive(self.proofs.owner_path(mid),dict(schema=OWNER_SCHEMA,kind='calibration',operation_id=self.operation,case=name,mutation_id=mid,effect_sha256=self.repository.digest(path),plan_sha256=record['plan_sha256']))
        return dict(status='PREPARED',operation_id=self.operation,case=name,mutation_id=mid,native_qualification='NOT_MEASURED')
    def prepare_case(self,name):
        with self.store.operation():return self._prepare_case(name)
    def _proof(self,owner,state,effect):
        evidence=SimpleNamespace(bindings=tuple(RuntimeBinding(**r)for r in state['bindings'].values()),host_boot_id=state['host_boot_id'],policy_sha256=state['policy_sha256'])
        return self.proofs._proof(effect,state,evidence)
    def _confirmed(self,mid,state):
        owner=self.proofs.owner_for(mid);require(type(owner)is CalibrationEffectOwner,'effect_owner','calibration owner required')
        require(owner.operation==self.operation,'effect_owner','different calibration operation')
        effect=owner.effect(state,mid);witness=self._proof(owner,state,effect)
        path=self.repository.readback_path(self.operation,mid);doc=self.repository.read(path)
        require(type(doc)is dict and type(doc.get('readback'))is dict,'shape','original readback record required')
        exact(doc['readback'],VMReadback.__dataclass_fields__,'calibration readback')
        require(doc==readback_record(owner,witness,VMReadback(**doc['readback'])),
            'cleanup_evidence','readback does not join original effect/terminal witness')
        self.repository.sync_record(path);return doc
    def _confirm(self,mid):
        owner=self.proofs.owner_for(mid);require(type(owner)is CalibrationEffectOwner,'effect_owner','calibration owner required')
        require(owner.operation==self.operation,'effect_owner','different calibration operation')
        state=self._state();effect=owner.effect(state,mid);current=self.proofs.backend.readback(effect.vm_id)
        require(self._catalog(owner.plan,state)==[mid],'calibration_pending','one exact original pending effect required')
        self.repository.active(self.operation,owner.plan)
        witness=self._proof(owner,state,effect)
        guard=getattr(self.proofs.sources,'calibration_settlement_guard',None)
        require(callable(guard),'qualification_observations_required','actual native settlement guard is not installed')
        guard(owner.plan,state,current,mutation_id=mid)
        check_baseline(self.policy,self.store,owner.plan,state)
        return self.repository.record_readback(owner,witness,current)
    def _assess_settled(self,mid):
        state=self._state();confirmed=self._confirmed(mid,state)
        owner=self.proofs.owner_for(mid)
        assessor=getattr(self.proofs.sources,'calibration_assess_settled',None)
        require(callable(assessor),'qualification_observations_required','strict post-settlement assessor is not installed')
        # This is deliberately outside execute's native UNKNOWN handler. A
        # physical refusal cannot erase the durable original terminal readback.
        assessor(owner.plan,state,mutation_id=mid)
        return confirmed
    def run_case(self,name,*,expected_plan_sha256=None):
        with self.store.operation():
            self._plan_pin(expected_plan_sha256)
            prepared=self._prepare_case(name)
            if prepared['mutation_id']is None:return prepared
            state=self._state();effect=self.proofs.effect(state,prepared['mutation_id'])
            before=self.proofs.backend.readback(effect.vm_id);intent=self.proofs.intent(effect,state,before)
            try:
                self.proofs.execute(intent,timeout_seconds=self.policy.timeouts.shrink_seconds if effect.operation=='shrink'else self.policy.timeouts.grow_seconds)
            except Exception as error:
                if hasattr(error,'native_output') and hasattr(error,'native_argv'):
                    try:self.store.save_failure(effect.request_id,'CALIBRATION_UNKNOWN',error)
                    except Exception as log_error:
                        error.native_log_error=type(log_error).__name__;error.native_log_exception=log_error
                        raise error from log_error
                raise
            self._confirm(effect.mutation_id)
            return self._assess_settled(effect.mutation_id)
    def reconcile(self,*,expected_plan_sha256=None):
        with self.store.operation():
            self._plan_pin(expected_plan_sha256)
            plan=self.repository.plan(self.operation);state=self._state();check_baseline(self.policy,self.store,plan,state)
            pending=self._catalog(plan,state)
            require(len(pending)==1,'calibration_pending','one original pending effect required; no new dispatch')
            self._confirm(pending[0])
            return self._assess_settled(pending[0])
    def report(self):
        result=self.inspect();result.update(candidate=None,limitation='Task 1 attaches C ownership only; capacity/workload/final measurements are not implemented.')
        return result


def open_calibration(op):
    require(os.getuid()==os.geteuid()==0 and os.environ.get('SUDO_UID')in(None,'0'),
        'root_required','root administrative calibration only')
    from host_resource_service import open_service
    service=open_service();proofs=getattr(service.provider,'native_proofs',None)
    require(proofs is not None,'qualification','installed dynamic C owner required')
    return NativeQualificationService(service.controller.policy,service.controller.store,proofs,operation_id=op)


def admin_qualification_main(args):
    require(os.getuid()==os.geteuid()==0 and os.environ.get('SUDO_UID')in(None,'0'),'root_required','root administrative calibration only')
    require(type(args)is list and len(args)in(2,3),'shape','qualification UUID phase only')
    op,phase=args[:2];operation_id(op)
    require((phase=='case'and len(args)==3 and args[2]in CASES)or(phase in{'inspect','report','reconcile'}and len(args)==2),'action','finite calibration phase required')
    if phase in {'inspect','report'}:return getattr(open_calibration(op),phase)()
    return dispatch_calibration_worker(op,phase,args[2] if phase=='case' else None)


# Private root-worker transport only. These records are not capabilities,
# production DTOs or a second receipt ledger.
WORKER_REQUEST='qcl.host-resource-calibration-worker-request.v1'
WORKER_RESPONSE='qcl.host-resource-calibration-worker-response.v1'
_WORKER_ID={'operation_id','plan_sha256','phase','case'}
_WORKER_REPLY={'schema',*_WORKER_ID,'status','mutation_id','native_outcome','physical_status',
    'native_qualification','receipt_ref','native_ref','evidence_refs','failure_code','failure_detail','capture_error'}


def _worker_bound(document):
    from host_resource_client import MAX_PACKET
    require(len(json.dumps(document,separators=(',',':'),allow_nan=False).encode())<=MAX_PACKET,
        'output_bound','private calibration packet exceeds bound')


def decode_calibration_worker_request(document):
    exact(document,{'schema',*_WORKER_ID},'private calibration request')
    require(document['schema']==WORKER_REQUEST,'shape','private calibration request version')
    operation_id(document['operation_id']);digest_string(document['plan_sha256'])
    require((document['phase']=='case' and type(document['case'])is str and document['case']in CASES)or
        (document['phase']=='reconcile' and document['case']is None),'action','finite private calibration phase/case required')
    _worker_bound(document);return document


def decode_calibration_worker_response(document,request):
    decode_calibration_worker_request(request);exact(document,_WORKER_REPLY,'private calibration response')
    require(document['schema']==WORKER_RESPONSE and all(document[k]==request[k] for k in _WORKER_ID),
        'calibration_reply','worker response identity changed')
    require(all(type(document[k])is str for k in ('status','native_outcome','physical_status')) and
        document['status']in {'READBACK_CONFIRMED','NO_OP','HOLD'} and
        document['native_outcome']in {'RETURNED_SUCCESS','UNKNOWN','NOT_DISPATCHED_OR_UNPROVEN'} and
        document['physical_status']in {'FAIL','NOT_MEASURED'} and document['native_qualification']=='NOT_MEASURED',
        'calibration_reply','private calibration result classification changed')
    mid=document['mutation_id']
    require(mid is None or type(mid)is str and UUID.fullmatch(mid),'calibration_reply','invalid original mutation selector')
    require((mid is None)==(document['native_outcome']=='NOT_DISPATCHED_OR_UNPROVEN'),
        'calibration_reply','native outcome requires exact original mutation')
    receipt=document['receipt_ref'];native=document['native_ref']
    if receipt is not None:
        exact(receipt,{'kind','sha256'},'original receipt ref');digest_string(receipt['sha256'])
        require(type(receipt['kind'])is str and receipt['kind']in {'case','readback'} and
            (receipt['kind']!='case' or request['case']is not None and mid is None) and
            (receipt['kind']!='readback' or mid is not None),'calibration_reply','receipt scope changed')
    if native is not None:
        exact(native,{'sha256'},'original native ref');digest_string(native['sha256'])
        require(mid is not None and document['native_outcome']=='RETURNED_SUCCESS',
            'calibration_reply','native ref requires original terminal proof')
    refs=document['evidence_refs']
    require(type(refs)is list and len(refs)<=64,'calibration_reply','bounded original evidence refs required')
    paths=set()
    for ref in refs:
        exact(ref,{'path','sha256'},'original evidence ref');digest_string(ref['sha256'])
        require(type(ref['path'])is str and re.fullmatch(r'(?:observations|physical-failures)/[0-9a-f]{32}\.json',ref['path'])
            and ref['path']not in paths,'calibration_reply','fixed unique original evidence leaf required')
        paths.add(ref['path'])
    failure=document['failure_code'];capture=document['capture_error']
    require(failure is None or type(failure)is str and re.fullmatch(r'[a-z][a-z0-9_]{0,127}',failure),
        'calibration_reply','bounded failure code required')
    require(capture is None or type(capture)is str and 0<len(capture.encode())<=4096,
        'calibration_reply','bounded secondary capture description required')
    detail=document['failure_detail']
    if detail is not None:
        exact(detail,{'type','message','truncated'},'bounded original failure')
        require(type(detail['type'])is str and 0<len(detail['type'])<=128 and
            type(detail['message'])is str and len(detail['message'].encode())<=4096 and
            type(detail['truncated'])is bool,'calibration_reply','bounded original failure detail required')
    if document['status']=='NO_OP':
        require(mid is None and native is None and receipt is not None and receipt['kind']=='case' and
            document['native_outcome']=='NOT_DISPATCHED_OR_UNPROVEN' and document['physical_status']=='NOT_MEASURED'
            and not refs and failure is None and detail is None and capture is None,'calibration_reply','NO_OP is not a native transition')
    elif document['status']=='READBACK_CONFIRMED':
        require(mid is not None and native is not None and receipt is not None and receipt['kind']=='readback' and
            document['native_outcome']=='RETURNED_SUCCESS' and document['physical_status']=='NOT_MEASURED' and
            failure is None and detail is None and capture is None,'calibration_reply','original confirmed readback required')
    else:require(failure is not None and detail is not None,'calibration_reply','HOLD requires original failure')
    _worker_bound(document);return document


def _calibration_root_config():
    from host_resource_service import CONFIG,validate_service_config,read_root_json
    require(os.getuid()==os.geteuid()==0 and os.environ.get('SUDO_UID')in(None,'0'),
        'root_required','root administrative calibration only')
    config=validate_service_config(read_root_json(CONFIG))
    require(config['role']=='native_host','trust','calibration worker is native-host root only')
    return config


def _calibration_worker_admission():
    from host_resource_native_cleanup import NativeCleanupSources
    from host_resource_backends import NativeCommandRunner
    config=_calibration_root_config()
    sources=NativeCleanupSources(config,NativeCommandRunner([config['systemctl']]))
    own=sources.local.process(os.getpid());scope=own['cgroup'];unit=scope.rsplit('/',1)[-1]
    require(scope=='/system.slice/'+unit and re.fullmatch(r'qcl-resource-[0-9a-f]{32}\.service',unit) and
        own['pid']==os.getpid() and own['uids']==[0]*4 and type(own['start_ticks'])is int and own['start_ticks']>0,
        'native_owner','actual root calibration worker required')
    before=sources.unit(unit);boot=sources.local.host()['boot_id']
    require(before['LoadState']=='loaded' and before['ActiveState']=='active' and
        int(before['MainPID'])==own['pid'] and before['ControlGroup']==scope and
        re.fullmatch(r'[0-9a-f]{32}',before['InvocationID']),
        'native_owner','calibration must be actual resource unit MainPID')
    again=sources.local.process(own['pid'])
    require(all(again[k]==own[k] for k in ('pid','ppid','start_ticks','uids','cgroup','executable')) and
        sources.unit(unit)==before and sources.local.host()['boot_id']==boot,
        'native_owner','calibration worker generation changed')
    return config


def _worker_staged(owner,request):
    from host_resource_qualification_runtime import NativeCalibrationRuntime
    runtime=getattr(owner.proofs.sources,'idle_qualification_runtime',None)
    require(type(runtime)is NativeCalibrationRuntime and runtime.proofs is owner.proofs and
        runtime.store is owner.store and runtime.parent.operation==request['operation_id'],
        'qualification_observations_required','same protected actual idle runtime required')
    with owner.store.locked(read_only=True):
        owner._plan_pin(request['plan_sha256'])
        require(runtime._load()==(runtime.plan,runtime.bootstrap_report,runtime.permit),
            'calibration_runtime','protected activation/report changed')
        plan=owner.repository.plan(owner.operation);check_baseline(owner.policy,owner.store,plan,owner._state())
        require(not _exists(owner.repository.folder(owner.operation)/'jobs'),
            'calibration_jobs_unsupported','idle worker refuses child namespace')
        require(request['case']is None or request['case']in plan['cases'],'action','case absent from original plan')


def _worker_reply(request):
    return dict(schema=WORKER_RESPONSE,**{k:request[k]for k in _WORKER_ID},status='HOLD',mutation_id=None,
        native_outcome='NOT_DISPATCHED_OR_UNPROVEN',physical_status='NOT_MEASURED',native_qualification='NOT_MEASURED',
        receipt_ref=None,native_ref=None,evidence_refs=[],failure_code=None,failure_detail=None,capture_error=None)


def _worker_native_ref(owner,mid,state):
    original=owner.proofs.owner_for(mid)
    require(type(original)is CalibrationEffectOwner and original.operation==owner.operation,
        'effect_owner','native result belongs to another original owner')
    effect=original.effect(state,mid);witness=owner._proof(original,state,effect)
    raw=_raw(owner.store,owner.proofs.path(mid))
    require(strict_json(raw.decode())==witness,'calibration_reply','original terminal changed after proof')
    return dict(sha256=hashlib.sha256(raw).hexdigest())


def _worker_receipts(owner,request,reply,*,result=None,error=None):
    """Project existing protected originals only; never create/assess/replay an effect."""
    repo=owner.repository
    with owner.store.locked(read_only=True):
        owner._plan_pin(request['plan_sha256']);state=owner._state()
        mid=getattr(error,'mutation_id',None) if error is not None else result['mutation_id']
        if mid is None and request['case']is not None:
            path=repo.case_path(owner.operation,request['case'])
            if _exists(path):
                marker=decode_case(repo.read(path),owner.operation,request['case']);mid=marker['mutation_id']
                if mid is None:reply['receipt_ref']=dict(kind='case',sha256=repo.digest(path))
        if mid is None and error is not None and request['phase']=='reconcile':
            pending=owner._catalog(repo.plan(owner.operation),state)
            if len(pending)==1:mid=pending[0]
        if mid is not None:
            require(type(mid)is str and UUID.fullmatch(mid),'calibration_reply','invalid original effect selector')
            original=owner.proofs.owner_for(mid)
            require(type(original)is CalibrationEffectOwner and original.operation==owner.operation and
                (request['case']is None or original.record['case']==request['case']),
                'effect_owner','worker result belongs to another original effect')
            reply['mutation_id']=mid
            if reply['native_outcome']!='RETURNED_SUCCESS':reply['native_outcome']='UNKNOWN'
            path=owner.proofs.path(mid)
            if _exists(path):
                reply['native_ref']=_worker_native_ref(owner,mid,state)
                reply['native_outcome']='RETURNED_SUCCESS'
            else:require(reply['native_outcome']!='RETURNED_SUCCESS',
                'calibration_reply','original retained native success witness unavailable')
            path=repo.readback_path(owner.operation,mid)
            if _exists(path):
                owner._confirmed(mid,state)
                reply['receipt_ref']=dict(kind='readback',sha256=repo.digest(path))
        refs=getattr(error,'calibration_evidence_refs',[]) if error is not None else []
        require(type(refs)is list and len(refs)<=64,'output_bound','bounded retained failure refs required')
        for ref in refs:
            path=Path(ref['path']);relative=str(path.relative_to(repo.folder(owner.operation)))
            require(re.fullmatch(r'(?:observations|physical-failures)/[0-9a-f]{32}\.json',relative) and
                repo.digest(path)==ref['sha256'],'calibration_reply','original failure ref changed')
            item=dict(path=relative,sha256=ref['sha256'])
            if item not in reply['evidence_refs']:reply['evidence_refs'].append(item)


def calibration_worker_main(document):
    request=decode_calibration_worker_request(document);reply=_worker_reply(request);owner=None
    try:
        _calibration_worker_admission()
        owner=open_calibration(request['operation_id']);_worker_staged(owner,request)
        if request['phase']=='case':result=owner.run_case(request['case'],expected_plan_sha256=request['plan_sha256'])
        else:result=owner.reconcile(expected_plan_sha256=request['plan_sha256'])
        reply['status']=result['status']
        if result['status']=='READBACK_CONFIRMED':
            reply.update(native_outcome='RETURNED_SUCCESS',mutation_id=result['mutation_id'])
        _worker_receipts(owner,request,reply,result=result)
    except (ResourceError,OSError,ValueError) as error:
        if hasattr(error,'native_journal_error') or hasattr(error,'native_log_error'):
            raise  # Original P11/native error and failed journal must escape intact.
        reply['status']='HOLD';reply['failure_code']=getattr(error,'code',None)or('calibration_io'if isinstance(error,OSError)else'calibration_shape')
        message=str(error)
        reply['failure_detail']=dict(type=type(error).__name__[:128],message=message[:1024],truncated=len(message)>1024)
        if getattr(error,'native_outcome',None)in {'RETURNED_SUCCESS','UNKNOWN','NOT_DISPATCHED_OR_UNPROVEN'}:
            reply['native_outcome']=error.native_outcome
        if getattr(error,'physical_status',None)in {'FAIL','NOT_MEASURED'}:reply['physical_status']=error.physical_status
        if getattr(error,'mutation_id',None)is not None:reply['mutation_id']=error.mutation_id
        if owner is not None:
            try:_worker_receipts(owner,request,reply,error=error)
            except Exception as secondary:reply['capture_error']=type(secondary).__name__
        if getattr(error,'calibration_record_error',None):
            reply['capture_error']=(reply['capture_error']or'')+' original_retention_failed'
    return decode_calibration_worker_response(reply,request)


def _verify_worker_reply(owner,request,reply):
    decode_calibration_worker_response(reply,request)
    repo=owner.repository
    with owner.store.locked(read_only=True):
        owner._plan_pin(request['plan_sha256'])
        mid=reply['mutation_id'];receipt=reply['receipt_ref']
        if receipt is not None:
            if receipt['kind']=='case':
                path=repo.case_path(owner.operation,request['case'])
                require(decode_case(repo.read(path),owner.operation,request['case'])['mutation_id']is None,
                    'calibration_reply','NO_OP original marker differs')
            else:
                owner._confirmed(mid,owner._state());path=repo.readback_path(owner.operation,mid)
                effect=owner.proofs.owner_for(mid)
                require(request['case']is None or effect.record['case']==request['case'],
                    'calibration_reply','readback belongs to another case')
            require(repo.digest(path)==receipt['sha256'],'calibration_reply','original receipt hash differs')
        if reply['native_outcome']=='RETURNED_SUCCESS':
            native=_worker_native_ref(owner,mid,owner._state())
            if reply['native_ref']is not None:
                require(native==reply['native_ref'],'calibration_reply','original native witness differs')
        for ref in reply['evidence_refs']:
            require(repo.digest(repo.folder(owner.operation)/ref['path'])==ref['sha256'],
                'calibration_reply','original evidence hash differs')
    return reply


def dispatch_calibration_worker(op,phase,case_name=None):
    import base64
    import application_release as engine
    from host_resource_facts import LocalSources
    from host_resource_backends import trusted_root_path
    config=_calibration_root_config();sources=LocalSources(config,None)
    for pid in (os.getpid(),os.getppid()):
        process=sources.process(pid)
        require(process['pid']==pid and process['uids']==[0]*4 and process['start_ticks']>0,
            'root_required','actual administrative root ancestry required')
    owner=open_calibration(op)
    with owner.store.locked(read_only=True):
        digest=owner.repository.digest(owner.repository.folder(op)/'plan.json')
    request=decode_calibration_worker_request(dict(schema=WORKER_REQUEST,operation_id=op,
        plan_sha256=digest,phase=phase,case=case_name))
    _worker_staged(owner,request)
    trusted_root_path(config['systemd_run'],executable=True);trusted_root_path(config['worker_helper'],executable=True)
    token=base64.urlsafe_b64encode(json.dumps(request,separators=(',',':')).encode()).decode()
    output=engine.command([config['systemd_run'],'--quiet','--wait','--pipe','--unit=qcl-resource-'+uuid.uuid4().hex,
        '--service-type=exec','--property=KillMode=control-group','--property=TimeoutStopSec=10s',
        config['worker_helper'],'qualification',token],timeout_seconds=120,output_bytes=256*1024)
    try:return _verify_worker_reply(owner,request,strict_json(output))
    except (ResourceError,OSError,ValueError) as error:
        # Refusing admin acceptance must retain the original bounded worker result.
        error.calibration_worker_output=output;error.calibration_worker_request=dict(request)
        raise
