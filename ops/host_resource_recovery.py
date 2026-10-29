"""Root-only retirement of an uncertain native incarnation; never resize replay.

The original receipt stays UNKNOWN. Attached proofs/fences are not a budget ledger.
PVE has no accepted per-client drain protocol and always holds before controls.
"""
from dataclasses import asdict, dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid
import xml.etree.ElementTree as ET

from host_resource_operations import (ResourceError, RuntimeBinding, HostEvidence, VMReadback,
    UNKNOWN, PENDING, ResidentGrant, PolicyValidationError, integer, policy_digest, require, text, validate_host_grants)
from host_resource_backends import fingerprint, read_root_json, trusted_root_path, MAX_OUTPUT_BYTES
from host_resource_native_cleanup import (UUID, SHA, exact, decode_birth, decode_peer, source_ref,
    NativeCleanupSources, libvirt_endpoint)

LIBVIRT='libvirt-local-uuid-retirement-v1'
PVE='pve-local-vmid-retirement-v1'
CONFIG_SCHEMA='qcl.host-resource-native-recovery-config.v1'
TARGET_SCHEMA='qcl.host-resource-native-target.v1'
RETIRE_SCHEMA='qcl.host-resource-retired.v1'
PROFILE_SCHEMA='qcl.host-resource-native-retirement-qualification.v1'
BUNDLE_SCHEMA='qcl.host-resource-native-retirement-qualifications.v1'
TARGET_FIELDS={'schema','request_id','mutation_id','intent_sha256','dispatch_sha256','host_id','owner_id',
    'host_boot_id','policy_sha256','binding','protocol_id','qualification_sha256','source_ids',
    'native_peer_identity','target','qemu_birth','qemu_executable','vm_scope','owned_helpers','config_sha256',
    'storage_namespace_sha256','storage_devices','worker_birth','cli_birth'}
EXTRA_SOURCES={
 'src/conf/domain_conf.c':'5f2bdcf4a6d43c70bd471f2a485d06c893c0f59c0ca95da567344491ce2080a7',
 'src/datatypes.c':'7aeb62bba862acbfdce91057a07adc0a4497346f08633686de1706128abe314e',
 'src/qemu/qemu_domain.c':'1ac4a096ed2e8430f4aa04a18bfdabc8c8870fe0ef1ee828ecaac701d8a88a7f',
 'src/qemu/qemu_process.c':'ff7f79fd8429ea3954f11709b3ac53858263fb8af9be499903f69d0fcd9379e5',
 'src/conf/virdomainjob.c':'1b5a035cb1e59dc3692363aaebc030d924b1a5b97be768e046f74fa7af11cd35',
 'src/conf/virdomainobjlist.c':'f81fae3133e48a61217d303055651cfb9d9cf8b18b2e8ffd0b8e75cce97fd9cb'}


def sha(value):require(type(value) is str and SHA.fullmatch(value),'shape','exact SHA256 required')
def uid(value):require(type(value) is str and UUID.fullmatch(value),'shape','exact UUID required')
def native_uuid(value):require(type(value) is str and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',value),'shape','canonical native UUID required')


def decode_storage_devices(devices):
    """Shape/alias validation only, never evidence that a closure is complete."""
    require(type(devices) is list,'shape','sealed complete storage closure required')
    paths=set();identities=set()
    for device in devices:
        exact(device,{'path','device','inode','kind'},'local regular storage identity')
        path=device['path'];text(path,'storage path')
        require(path.startswith('/') and str(Path(path))==path and '..' not in Path(path).parts and '\x00' not in path,
            'shape','canonical absolute storage path required')
        require(device['kind']=='local_regular','source_protocol_unavailable','non-local/regular backing closure unqualified')
        integer(device['device'],'storage device');integer(device['inode'],'storage inode',1)
        identity=(device['device'],device['inode'])
        require(path not in paths and identity not in identities,'ownership','duplicate storage path/identity')
        paths.add(path);identities.add(identity)
    return devices


def assert_storage_disjoint(retired,candidate):
    """Caller must supply both backend-qualified complete closures, not XML top disks."""
    decode_storage_devices(retired);decode_storage_devices(candidate)
    paths={d['path'] for d in retired};ids={(d['device'],d['inode']) for d in retired}
    require(all(d['path'] not in paths and (d['device'],d['inode']) not in ids for d in candidate),
        'retired_target','retired backing storage cannot be attached to replacement')


@dataclass(frozen=True)
class NativeRecoveryRequest:
    recovery_id:str
    request_id:str
    mutation_id:str
    def __post_init__(self):
        uid(self.recovery_id);uid(self.mutation_id);text(self.request_id,'request_id')


@dataclass(frozen=True)
class RecoveryFacts:
    evidence:HostEvidence
    readbacks:dict
    workload_closures:dict


def decode_target(doc):
    exact(doc,TARGET_FIELDS,'target seal');require(doc['schema']==TARGET_SCHEMA,'shape','target schema')
    for key in ('mutation_id',):uid(doc[key])
    for key in ('intent_sha256','dispatch_sha256','policy_sha256','qualification_sha256','config_sha256','storage_namespace_sha256'):sha(doc[key])
    for key in ('request_id','host_id','owner_id','host_boot_id','protocol_id'):text(doc[key],key)
    exact(doc['binding'],RuntimeBinding.__dataclass_fields__,'sealed binding')
    for value in doc['binding'].values():text(value,'binding identity')
    for key in ('qemu_birth','worker_birth','cli_birth'):decode_birth(doc[key])
    source_ref(doc['qemu_executable']);decode_peer(doc['native_peer_identity'])
    t=doc['target'];require(type(t) is dict,'shape','native target')
    if t.get('kind')=='libvirt':
        exact(t,{'kind','system_namespace','uuid','name','connect_endpoint'},'libvirt target')
        native_uuid(t['uuid']);require(t['uuid']==doc['binding']['native_id'] and t['system_namespace']=='system' and
            re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',t['name']) and t['connect_endpoint']==libvirt_endpoint(doc['native_peer_identity']),
            'identity_mismatch','sealed libvirt target/route differs')
    else:
        exact(t,{'kind','node','vmid','uuid'},'PVE target');require(t['kind']=='pve','shape','native target kind')
        integer(t['vmid'],'VMID',1);native_uuid(t['uuid']);text(t['node'],'node')
    scope=doc['vm_scope'];exact(scope,{'cgroup','device','inode','invocation_id'},'VM memory scope')
    require(type(scope['cgroup']) is str and scope['cgroup'].startswith('/machine.slice/') and
        scope['cgroup'].endswith('.scope') and '..' not in Path(scope['cgroup']).parts,'qualification','qualified VM scope required')
    integer(scope['device'],'scope device');integer(scope['inode'],'scope inode',1);uid(scope['invocation_id'])
    require(doc['owned_helpers']==[],'qualification','external memory holders are not qualified')
    decode_storage_devices(doc['storage_devices'])
    return doc



def decode_context(doc):
    exact(doc,{'unit','invocation_id','cgroup','host_boot_id','mutation_id'},'native context')
    from host_resource_native_cleanup import UNIT
    require(type(doc['unit']) is str and UNIT.fullmatch(doc['unit']),'shape','owned resource unit required')
    uid(doc['invocation_id']);uid(doc['mutation_id']);text(doc['host_boot_id'],'boot');text(doc['cgroup'],'cgroup')
    require(doc['cgroup']=='/system.slice/'+doc['unit'],'native_owner','owned native cgroup differs')


def decode_recovery_intent(doc):
    exact(doc,{'schema','recovery','original_state_sha256','original_row_sha256','target_sha256','profile_sha256','worker_birth','stages'},'recovery intent')
    require(doc['schema']=='qcl.host-resource-recovery-intent.v1','shape','intent schema')
    NativeRecoveryRequest(**doc['recovery'])
    for key in ('original_state_sha256','original_row_sha256','target_sha256','profile_sha256'):sha(doc[key])
    decode_birth(doc['worker_birth']);exact(doc['stages'],{'destroy','undefine'},'native stages')
    for value in doc['stages'].values():uid(value)
    require(len(set(doc['stages'].values()))==2,'shape','unique native mutation stages')
    return doc


def decode_stage(doc,kind):
    fields={'schema','intent_sha256','stage_id','worker_birth','native_context'}
    if kind=='claim':fields|={'recovery_id','stage','cli_birth'}
    exact(doc,fields,'recovery '+kind)
    require(doc['schema']=='qcl.host-resource-recovery-'+kind+'.v1','shape','stage schema')
    sha(doc['intent_sha256']);uid(doc['stage_id']);decode_birth(doc['worker_birth']);decode_context(doc['native_context'])
    require(doc['native_context']['mutation_id']==doc['stage_id'],'identity_mismatch','stage context differs')
    if kind=='claim':
        uid(doc['recovery_id']);decode_birth(doc['cli_birth']);require(doc['stage'] in {'destroy','undefine'} and doc['worker_birth']!=doc['cli_birth'],'shape','native stage/child required')
    return doc


def decode_fence(doc):
    exact(doc,{'schema','backend','aliases','recovery_id','target_sha256'},'retirement fence')
    require(doc['schema']=='qcl.host-resource-native-tombstone.v1' and doc['backend'] in {'libvirt','pve'},'shape','fence schema/backend')
    exact(doc['aliases'],{'uuid','name'} if doc['backend']=='libvirt' else {'uuid','vmid'},'native aliases')
    native_uuid(doc['aliases']['uuid']);uid(doc['recovery_id']);sha(doc['target_sha256'])
    for value in doc['aliases'].values():text(value,'native alias')
    return doc


def decode_retirement_proof(doc):
    exact(doc,{'schema','recovery_id','intent_sha256','target_sha256','original_state_sha256','profile_sha256','observed_at','host_boot_id','native_peer_identity','stage_records','workload_closures','physical_quiescence','namespace_fence'},'retirement proof')
    require(doc['schema']=='qcl.host-resource-native-retirement.v1','shape','retirement proof schema')
    uid(doc['recovery_id']);integer(doc['observed_at'],'proof observation');text(doc['host_boot_id'],'boot')
    for key in ('intent_sha256','target_sha256','original_state_sha256','profile_sha256'):sha(doc[key])
    decode_peer(doc['native_peer_identity']);decode_fence(doc['namespace_fence'])
    require(doc['namespace_fence']['recovery_id']==doc['recovery_id'] and doc['namespace_fence']['target_sha256']==doc['target_sha256'],'identity_mismatch','proof fence differs')
    require(type(doc['stage_records']) is list and len(doc['stage_records'])<=2,'shape','native retirement stages required')
    seen=set()
    for stage in doc['stage_records']:
        decode_stage(stage,'claim');require(stage['recovery_id']==doc['recovery_id'] and stage['intent_sha256']==doc['intent_sha256'] and stage['stage_id'] not in seen,'identity_mismatch','proof stages differ');seen.add(stage['stage_id'])
    # Native namespace removal is observed independently even when no control
    # was needed; no fabricated successful undefine claim is minted.
    require(type(doc['workload_closures']) is dict and doc['workload_closures'],'shape','exact workload closures required')
    for key,closure in doc['workload_closures'].items():
        text(key,'request');exact(closure,{'request_sha256','native_generation','output_provenance'},'workload closure');sha(closure['request_sha256']);text(closure['native_generation'],'generation');text(closure['output_provenance'],'output closure')
    exact(doc['physical_quiescence'],{'cgroup','device','inode','invocation_id'},'sealed memory scope')
    integer(doc['physical_quiescence']['device'],'device');integer(doc['physical_quiescence']['inode'],'inode',1);uid(doc['physical_quiescence']['invocation_id']);text(doc['physical_quiescence']['cgroup'],'scope')
    return doc


def immutable(store,path,document):
    """O_EXCL + fsync; a partial file after IO failure is a durable fail-closed barrier."""
    path.parent.mkdir(mode=0o700,exist_ok=True);store._check_path(path.parent,directory=True)
    data=json.dumps(document,sort_keys=True).encode();require(len(data)<=MAX_OUTPUT_BYTES,'output_bound','recovery artifact bound')
    try:fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    except FileExistsError:
        store._sync_immutable(path,document,conflict_code='reconciliation_required');return False
    try:
        store._check_fd(fd)
        with os.fdopen(fd,'wb',closefd=False) as f:f.write(data);f.flush();os.fsync(fd)
    finally:os.close(fd)
    store._sync_immutable(path,document,conflict_code='reconciliation_required');return True


def aliases(target):
    t=target['target'];return {'uuid':t['uuid'],'name':t['name']} if t['kind']=='libvirt' else {'uuid':t['uuid'],'vmid':str(t['vmid'])}


def check_start_fence(store,backend,**identities):
    directory=store.directory/'retired-targets'
    try:directory.lstat()
    except FileNotFoundError:return
    store._check_path(directory,directory=True)
    kind='pve' if backend=='proxmox' else backend
    for key,value in identities.items():
        text(value,'native alias');path=directory/store._key(kind+':'+key+':'+value)
        try:path.lstat()
        except FileNotFoundError:continue
        record=store._read(path)
        decode_fence(record)
        require(record['schema']=='qcl.host-resource-native-tombstone.v1' and record['backend']==kind and
            record['aliases'].get(key)==value,'state','invalid retirement fence')
        uid(record['recovery_id']);sha(record['target_sha256'])
        raise ResourceError('retired_target','native identity is permanently retired')


def validate_retired(store,record,request_id):
    exact(record,{'schema','receipt','context','recovery_id','recovery_proof_sha256'},'retired archive')
    require(record['schema']==RETIRE_SCHEMA and record['receipt']['request']['request_id']==request_id,'state','retired identity differs')
    uid(record['recovery_id']);sha(record['recovery_proof_sha256'])
    store._check_path(store.directory/'native-recoveries',directory=True)
    proof=decode_retirement_proof(store._read(store.directory/'native-recoveries'/(record['recovery_id']+'.proof.json')))
    require(fingerprint(proof)==record['recovery_proof_sha256'] and proof['recovery_id']==record['recovery_id'] and
        proof['workload_closures'][request_id]['request_sha256']==fingerprint(record['receipt']),
        'state','retirement archive lacks exact original closure/proof')
    intent=decode_recovery_intent(store._read(store.directory/'native-recoveries'/(record['recovery_id']+'.intent.json')))
    require(proof['intent_sha256']==fingerprint(intent) and proof['original_state_sha256']==intent['original_state_sha256'] and proof['target_sha256']==intent['target_sha256'] and proof['profile_sha256']==intent['profile_sha256'],'state','retirement intent/proof mismatch')
    closures=store._read(store.directory/'native-recoveries'/(record['recovery_id']+'.closure.json'))
    require(closures==proof['workload_closures'],'state','original precontrol closure changed')
    mid=intent['recovery']['mutation_id'];store._check_path(store.directory/'native-mutations',directory=True)
    target=decode_target(store._read(store.directory/'native-mutations'/(mid+'.target.json')))
    require(fingerprint(target)==proof['target_sha256'] and record['context']==dict(host_boot_id=target['host_boot_id'],policy_sha256=target['policy_sha256'],binding=target['binding']),'state','original retired context differs')
    from host_resource_operations import ResourceRequest,RECEIPT_FIELDS,PHASES
    row=record['receipt'];exact(row,RECEIPT_FIELDS,'original receipt');ResourceRequest(**row['request'])
    require(row['phase'] in PHASES and type(row['finished']) is bool and type(row['native_cleanup_confirmed']) is bool,'state','original receipt shape')
    for key in ('old_bytes','target_bytes'):integer(row[key],key,1)
    if request_id==intent['recovery']['request_id']:require(fingerprint(row)==intent['original_row_sha256'],'state','original uncertain row changed')
    return row


class NativeRecoveryService:
    def __init__(self,controller,provider,proofs,protected_config,runner,*,sources=None):
        exact(protected_config,{'schema','qualification'},'recovery config')
        require(protected_config['schema']==CONFIG_SCHEMA,'shape','recovery config schema')
        self.c,self.provider,self.proofs,self.config,self.runner=controller,provider,proofs,protected_config,runner
        self.store=controller.store;self.directory=self.store.directory/'native-recoveries'
        self.sources=sources if sources is not None else NativeRecoverySources(self)
    def path(self,rid,suffix='intent'):
        uid(rid);return self.directory/(rid+'.'+suffix+'.json')
    def _read(self,rid,suffix='intent'):
        self.store._check_path(self.directory,directory=True);doc=self.store._read(self.path(rid,suffix))
        if suffix=='intent':decode_recovery_intent(doc)
        elif suffix=='proof':decode_retirement_proof(doc)
        elif suffix in {'claim','dispatch'}:decode_stage(doc,suffix)
        return doc
    def _target(self,row,state):
        path=self.proofs.path(row['mutation_id']).with_suffix('.target.json')
        target=decode_target(self.store._read(path));claim=self.proofs.read(row['mutation_id']);dispatch=self.proofs.dispatch(row['mutation_id'])
        require(target['intent_sha256']==fingerprint(claim['intent'])==fingerprint(dispatch['intent']) and
            target['dispatch_sha256']==fingerprint(dispatch) and target['binding']==state['bindings'][row['request']['vm_id']] and
            target['request_id']==row['request']['request_id'] and target['mutation_id']==row['mutation_id'] and
            target['worker_birth']==claim['worker_birth'] and target['cli_birth']==claim['cli_birth'] and
            target['native_peer_identity']==claim['native_peer'] and target['source_ids']==claim['source_ids'] and
            target['host_boot_id']==state['host_boot_id'] and target['policy_sha256']==state['policy_sha256']==policy_digest(self.c.policy),
            'identity_mismatch','original target/claim/dispatch/journal differ')
        intent=claim['intent']
        require(intent['request_id']==row['request']['request_id'] and intent['mutation_id']==row['mutation_id'] and
            intent['old_bytes']==row['old_bytes'] and intent['target_bytes']==row['target_bytes'] and intent['native_context']==row['native_context'] and
            intent['qualification_sha256']==target['qualification_sha256'] and intent['protocol_id']==target['protocol_id'],
            'identity_mismatch','original request/resize/context changed')
        return target,claim
    def _view(self,request,state,phase,failure=None):
        row=next((r for r in state['receipts'] if r['request']['request_id']==request.request_id),None)
        if row is None:row=self.store.completed(request.request_id)
        vm=row['request']['vm_id'] if row else None
        grant=next((g for g in state['grants'] if g['vm_id']==vm),None)
        return dict(schema='qcl.host-resource-recovery.v1',**asdict(request),host_id=self.c.policy.host_id,vm_id=vm,
            phase=phase,original_outcome='unknown',charged_bytes=grant['guest_bytes'] if grant else None,
            replacement_native_id=state['startups'][vm]['native_id'] if vm and state['bindings'][vm] is None and phase=='replacement_reserved' else None,
            failure_code=failure,state_generation=fingerprint(state),observed_at=int(self.sources.clock()))
    def read(self,recovery_id):
        with self.store.locked(read_only=True):
            intent=self._read(recovery_id);req=NativeRecoveryRequest(**intent['recovery']);state=self.c._load()
            phase='target_retired' if self.path(recovery_id,'proof').exists() and not any(r['request']['request_id']==req.request_id for r in state['receipts']) else 'retiring_unknown'
            return self._view(req,state,phase)
    def _facts(self,request,state,target):
        facts=self.sources.recovery_facts(request,owner_state=state,target=target)
        return self._validate_facts(facts,state,target)
    def _validate_facts(self,facts,state,target):
        require(type(facts) is RecoveryFacts and type(facts.evidence) is HostEvidence,'shape','actual recovery facts required')
        e=facts.evidence;p=self.c.policy;vm=target['binding']['vm_id'];self.c._fresh(e.observed_at)
        require((e.host_id,e.owner_id,e.host_boot_id,e.policy_sha256,e.physical_ram_bytes,e.foreign_max_bytes,e.capacity_evidence_ref,e.agreement_ref)==
            (p.host_id,p.owner_id,state['host_boot_id'],policy_digest(p),p.physical_ram_bytes,p.reserves.foreign_max_bytes,p.capacity_evidence_ref,p.owned_pool.agreement_ref) and
            e.foreign_growth_bounded is True and e.active_grants_protected is True,'capacity_evidence','fresh protected host agreement changed')
        require(e.pressure_ok is True,'host_pressure','fresh host pressure closes replacement admission')
        require(type(e.live_workloads) is dict and type(e.bindings) is tuple and type(e.qualifications) is tuple,'shape','complete native snapshot required')
        require(len({b.vm_id for b in e.bindings})==len(e.bindings) and len({b.native_id for b in e.bindings})==len(e.bindings) and len({b.process_id for b in e.bindings})==len(e.bindings),'ownership','duplicate native/process binding')
        require(len({q.binding.vm_id for q in e.qualifications})==len(e.qualifications),'qualification','duplicate qualification')
        expected=set(state['bindings'])-{vm};require(set(facts.readbacks)==expected,'incomplete_bindings','every other VM readback required')
        for other in expected:
            binding=next((b for b in e.bindings if b.vm_id==other),None);read=facts.readbacks[other]
            require(binding is not None and asdict(binding)==state['bindings'][other] and state['startups'][other]['phase']=='binding_ready', 'identity_mismatch','other VM binding/quarantine changed')
            q=next((q for q in e.qualifications if q.binding==binding),None)
            require(q is not None and q.host_id==p.host_id and q.owner_id==p.owner_id and q.evidence_ref==p.active_grant.qualification_ref and q.qualified_dynamic is True and q.active_floor_protection is True and q.readback_verified is True and q.slurm_registration_verified is True and q.policy_sha256==e.policy_sha256,'qualification','other VM protection unqualified')
            grant=self.c._grant(state,other);floor=self.c._floor(state,other)
            require(type(read) is VMReadback and read.running and (read.native_id,read.process_id,read.config_fingerprint)==(binding.native_id,binding.process_id,binding.config_fingerprint) and
                floor<=min(read.assigned_bytes,read.configured_bytes)<=max(read.assigned_bytes,read.configured_bytes)<=grant.guest_bytes,'readback','other VM floor/allocation changed')
            live={r['request']['workload_id'] for r in state['receipts'] if r['request']['vm_id']==other and r['phase']=='RUN'}
            require(set(e.live_workloads.get(other,()))==live and all(r['native_cleanup_confirmed'] for r in state['receipts'] if r['request']['vm_id']==other),'incomplete_workloads','other VM native work/cleanup changed')
        affected=[r for r in state['receipts'] if r['request']['vm_id']==vm]
        require(set(facts.workload_closures)=={r['request']['request_id'] for r in affected},'cleanup','all affected workload outputs/terminal generations required')
        for row in affected:
            closure=facts.workload_closures[row['request']['request_id']]
            exact(closure,{'request_sha256','native_generation','output_provenance'},'workload closure')
            require(closure['request_sha256']==fingerprint(row),'cleanup','workload closure changed');text(closure['native_generation'],'generation');text(closure['output_provenance'],'output provenance')
        return facts
    def _argv(self,target,stage):
        t=target['target'];require(t['kind']=='libvirt','source_protocol_unavailable','PVE native drain protocol is open')
        base=(target['source_ids']['cli']['path'],'--connect',t['connect_endpoint'],stage,t['uuid'])
        return base+('--keep-nvram','--keep-tpm') if stage=='undefine' else base
    def claim(self,recovery_id,stage_id):
        uid(stage_id);intent=self._read(recovery_id);state=self.c._load();req=NativeRecoveryRequest(**intent['recovery'])
        require(fingerprint(state)==intent['original_state_sha256'],'identity_mismatch','original charged state changed before control')
        stage=next((key for key,value in intent['stages'].items() if value==stage_id),None);require(stage is not None,'shape','exact stage UUID required')
        row=next(r for r in state['receipts'] if r['request']['request_id']==req.request_id);target,old=self._target(row,state)
        require(fingerprint(target)==intent['target_sha256'],'identity_mismatch','target changed')
        require(fingerprint(self.sources.validate_target(target))==intent['profile_sha256'],'identity_mismatch','profile changed after immutable dispatch')
        dispatch=self._read(stage_id,'dispatch')
        require(dispatch['intent_sha256']==fingerprint(intent) and dispatch['stage_id']==stage_id,'identity_mismatch','stage dispatch authority changed')
        context=self.sources.context(dict(mutation_id=stage_id));worker,cli=self.sources.claim_process(context)
        require(worker==dispatch['worker_birth'] and context==dispatch['native_context'],'native_owner','administrative worker changed after stage dispatch')
        if stage=='undefine':require(self.sources.quiescent(target),'cleanup','old physical memory still active')
        record=dict(schema='qcl.host-resource-recovery-claim.v1',recovery_id=recovery_id,stage_id=stage_id,stage=stage,
            intent_sha256=fingerprint(intent),native_context=context,worker_birth=worker,cli_birth=cli)
        require(not self.path(stage_id,'claim').exists(),'reconciliation_required','claimed control is never replayed')
        immutable(self.store,self.path(stage_id,'claim'),record);return self._argv(target,stage)
    def _step(self,intent,target,stage):
        sid=intent['stages'][stage];path=self.path(sid,'claim')
        if path.exists():
            record=self._read(sid,'claim')
            require(record['stage_id']==sid and record['stage']==stage and record['recovery_id']==intent['recovery']['recovery_id'],'identity_mismatch','stage claim identity changed')
            immutable(self.store,path,record)
            require(record['intent_sha256']==fingerprint(intent) and self.sources.command_absent(record),'cleanup','administrative command cleanup unknown')
            require(self.sources.quiescent(target) if stage=='destroy' else self.sources.removed(target),'reconciliation_required','native step outcome unknown; no replay')
            return record
        require(not self.path(sid,'dispatch').exists(),'reconciliation_required','prepared stage without claim is unknown; no redispatch')
        context=self.sources.context(dict(mutation_id=sid));worker=self.sources.worker(context)
        immutable(self.store,self.path(sid,'dispatch'),dict(schema='qcl.host-resource-recovery-dispatch.v1',intent_sha256=fingerprint(intent),stage_id=sid,worker_birth=worker,native_context=context))
        try:self.runner.run([self.proofs.config['helper'],'recovery',intent['recovery']['recovery_id'],sid],timeout_seconds=self.c.policy.timeouts.reconcile_seconds,max_output_bytes=MAX_OUTPUT_BYTES)
        except Exception as error:
            try:self.store.save_failure(intent['recovery']['request_id'],'retire-'+sid,error)
            except Exception as secondary:error.native_log_error=repr(secondary)
            raise
        record=self._read(sid,'claim');require(record['stage_id']==sid and record['stage']==stage and record['recovery_id']==intent['recovery']['recovery_id'],'identity_mismatch','native stage identity changed');require(self.sources.command_absent(record),'cleanup','native control descendant remains')
        require(self.sources.quiescent(target) if stage=='destroy' else self.sources.removed(target),'reconciliation_required','native control readback incomplete')
        return record
    def retire(self,request):
        require(type(request) is NativeRecoveryRequest,'shape','Root recovery IDs required')
        with self.store.operation():
            state=self.c._load()
            try:
                if self.path(request.recovery_id).exists():
                    intent=self._read(request.recovery_id);require(intent['recovery']==asdict(request),'identity_mismatch','recovery UUID already belongs to another operation')
                    if not any(r['request']['request_id']==request.request_id for r in state['receipts']):return self._view(request,state,'target_retired')
                row=next((r for r in state['receipts'] if r['request']['request_id']==request.request_id),None)
                require(row is not None and row['phase'] in UNKNOWN and row['mutation_id']==request.mutation_id,'identity_mismatch','latest original UNKNOWN required')
                from host_resource_operations import CLEANUP_BLOCK
                require(state['blocked'] in (None,CLEANUP_BLOCK),'reconciliation_required','unrelated block is not a retirement proof')
                target,old=self._target(row,state);profile=self.sources.profile(target)
                require(profile['protocol_id']==LIBVIRT,'source_protocol_unavailable','PVE exact per-client drain/confinement is not implemented')
                require(profile['host_boot_id']==state['host_boot_id'],'identity_mismatch','host rebooted')
                self.sources.validate_target(target)
                facts=self._facts(request,state,target)
                require(self.proofs.sources.absent(old),'cleanup','original native command is not quiescent')
                if not self.path(request.recovery_id).exists():
                    worker=self.sources.worker(self.sources.context(dict(mutation_id=request.recovery_id)))
                    intent=dict(schema='qcl.host-resource-recovery-intent.v1',recovery=asdict(request),original_state_sha256=fingerprint(state),original_row_sha256=fingerprint(row),
                        target_sha256=fingerprint(target),profile_sha256=fingerprint(profile),worker_birth=worker,stages={s:uuid.uuid4().hex for s in ('destroy','undefine')})
                immutable(self.store,self.path(request.recovery_id),intent)
                require(fingerprint(state)==intent['original_state_sha256'] and fingerprint(profile)==intent['profile_sha256'],'identity_mismatch','original recovery authority changed')
                fence=dict(schema='qcl.host-resource-native-tombstone.v1',backend=target['target']['kind'],aliases=aliases(target),recovery_id=request.recovery_id,target_sha256=fingerprint(target))
                for key,value in fence['aliases'].items():immutable(self.store,self.store.directory/'retired-targets'/self.store._key(fence['backend']+':'+key+':'+value),fence)
                immutable(self.store,self.path(request.recovery_id,'closure'),facts.workload_closures)
                stages=[]
                if self.sources.removed(target):
                    for stage,sid in intent['stages'].items():
                        require(not self.path(sid,'dispatch').exists() or self.path(sid,'claim').exists(),'reconciliation_required','prepared native control still has unknown ownership')
                        if self.path(sid,'claim').exists():stages.append(self._step(intent,target,stage))
                else:
                    # A naturally dead original target needs no destructive destroy call.
                    if self.path(intent['stages']['destroy'],'claim').exists() or not self.sources.quiescent(target):stages.append(self._step(intent,target,'destroy'))
                    stages.append(self._step(intent,target,'undefine'))
                require(self.sources.quiescent(target) and self.sources.removed(target),'cleanup','old target is not retired')
                self.sources.validate_target(target);facts=self._facts(request,state,target)
                proof=dict(schema='qcl.host-resource-native-retirement.v1',recovery_id=request.recovery_id,intent_sha256=fingerprint(intent),target_sha256=fingerprint(target),original_state_sha256=fingerprint(state),
                    profile_sha256=fingerprint(profile),observed_at=int(self.sources.clock()),host_boot_id=state['host_boot_id'],native_peer_identity=target['native_peer_identity'],stage_records=stages,
                    workload_closures=facts.workload_closures,physical_quiescence=target['vm_scope'],namespace_fence=fence)
                if self.path(request.recovery_id,'proof').exists():
                    previous=self._read(request.recovery_id,'proof')
                    require({k:v for k,v in previous.items() if k!='observed_at'}=={k:v for k,v in proof.items() if k!='observed_at'},'identity_mismatch','original retirement proof changed')
                    proof=previous  # fresh observations revalidated; immutable causal witness is retained
                immutable(self.store,self.path(request.recovery_id,'proof'),proof)
                self._land(state,target,request,proof)
                return self._view(request,self.c._load(),'target_retired')
            except ResourceError as error:
                if hasattr(error,'native_argv'):raise
                return self._view(request,state,'hold',error.code)
    def _land(self,state,target,request,proof):
        vm=target['binding']['vm_id'];new=json.loads(json.dumps(state));spec=self.c._vm(vm)
        for i,g in enumerate(self.c._grants(new)):
            if g.vm_id==vm:new['grants'][i]=asdict(replace(g,guest_bytes=spec.maximum_bytes,active_floor_bytes=spec.minimum_bytes,state='idle'))
        try:validate_host_grants(self.c.policy,tuple(ResidentGrant(**g) for g in new['grants']))
        except PolicyValidationError as error:
            if error.code not in {'pool_overcommit','physical_overcommit'}:raise
            raise ResourceError(error.code,str(error)) from error
        rows=[r for r in state['receipts'] if r['request']['vm_id']==vm]
        for row in rows:self.store.archive_retired(row,dict(host_boot_id=state['host_boot_id'],policy_sha256=state['policy_sha256'],binding=state['bindings'][vm]),request.recovery_id,fingerprint(proof))
        new['receipts']=[r for r in new['receipts'] if r['request']['vm_id']!=vm]
        new['bindings'][vm]=None;new['desired'][vm]=spec.maximum_bytes
        new['startups'][vm].update(phase='boot_unknown',reservation_id=fingerprint(asdict(request)),initial_peak_bytes=spec.maximum_bytes)
        # All other VM/runtime/workload/foreign facts have been freshly validated;
        # only the unchanged original block is discharged by this retirement.
        new['blocked']=None
        self.store.save(new)
    def reserve_replacement(self,recovery_id,native_id):
        native_uuid(native_id)
        with self.store.operation():
            intent=self._read(recovery_id);req=NativeRecoveryRequest(**intent['recovery']);state=self.c._load()
            archived=self.store.completed(req.request_id);require(archived is not None,'reconciliation_required','retire first')
            target=decode_target(self.store._read(self.proofs.path(req.mutation_id).with_suffix('.target.json')))
            check_start_fence(self.store,'libvirt',uuid=native_id)
            vm=archived['request']['vm_id'];require(state['bindings'][vm] is None,'identity_mismatch','replacement already bound')
            try:
                if type(self.sources) is NativeRecoverySources:
                    candidate=self.sources.replacement_storage(native_id,target,recovery_id=recovery_id)
                else:candidate=self.sources.replacement_storage(native_id,target)  # explicit synthetic seam
                assert_storage_disjoint(target['storage_devices'],candidate)
                spec=self.c._vm(vm);record=self.sources.replacement(native_id,owner_state=state,target=target)
                require(record.vm_id==vm and record.native_id==native_id and record.observed_power_state=='stopped' and record.configured_max_bytes==record.initial_peak_bytes==spec.maximum_bytes,'startup_peak','full stopped replacement must match current protected enrollment')
                validate=getattr(self.sources,'validate_replacement_use',None)
                if validate is not None:validate(native_id,target)
                state['startups'][vm].update(native_id=native_id,static_config_fingerprint=record.static_config_fingerprint,phase='cold_reserved',reservation_id=fingerprint([recovery_id,native_id,record.static_config_fingerprint]))
                self.store.save(state)
                from host_resource_startup import StartupManager
                return StartupManager(self.c.policy,self.store,self.c.backend)._view(state,vm)
            finally:
                if type(self.sources) is NativeRecoverySources:
                    storage=getattr(self.sources,'storage',None)
                    if storage is not None and native_id in storage.handles:storage.handles[native_id].close()


class NativeRecoverySources:
    """Production facts, rooted in protected enrollment and native/kernel observations.

    No test true flag and no fallback to client evidence. The owning output producer
    is still absent; an affected workload without its actual output closure holds.
    """
    def __init__(self,service):
        require(os.geteuid()==0 and service.store.owner_uid==0,'root_required','production root owner required')
        self.s=service;self.native=service.proofs.sources
        require(type(self.native) is NativeCleanupSources,'trust','production native sources required')
        self.local=self.native.local
    def clock(self):return self.native.clock()
    def context(self,row):return self.native.context(row)
    def worker(self,context):return self.native.worker(context)
    def claim_process(self,context):return self.native.claim_process(context)
    def _profiles(self):
        bundle=read_root_json(self.s.config['qualification']);exact(bundle,{'schema','profiles'},'retirement bundle')
        require(bundle['schema']==BUNDLE_SCHEMA and type(bundle['profiles']) is list and bundle['profiles'],'qualification','retirement bundle required')
        seen=set()
        for p in bundle['profiles']:
            exact(p,{'schema','protocol_id','host_id','owner_id','host_boot_id','policy_sha256','binding','source_ids','native_peer_identity','memory_scope_protocol','storage_namespace_sha256','start_fence_protocol','evidence_ref'},'retirement profile')
            require(p['schema']==PROFILE_SCHEMA and p['protocol_id'] in {LIBVIRT,PVE},'qualification','reviewed protocol required')
            exact(p['binding'],RuntimeBinding.__dataclass_fields__,'retirement binding')
            for value in p['binding'].values():text(value,'binding')
            vm=p['binding']['vm_id'];require(vm not in seen,'qualification','duplicate VM retirement profile');seen.add(vm)
            for key in ('host_id','owner_id','host_boot_id','evidence_ref'):text(p[key],key)
            sha(p['policy_sha256']);sha(p['storage_namespace_sha256']);decode_peer(p['native_peer_identity'])
        return bundle['profiles']
    def _profile(self,binding,boot):
        matches=[p for p in self._profiles() if p['binding']==binding]
        require(len(matches)==1,'qualification','one exact per-VM retirement profile required');p=matches[0]
        require(p['protocol_id']==LIBVIRT,'source_protocol_unavailable','PVE per-client drain protocol remains open')
        policy=self.s.c.policy
        require((p['host_id'],p['owner_id'],p['host_boot_id'],p['policy_sha256'])==(policy.host_id,policy.owner_id,boot,policy_digest(policy)), 'qualification','retirement host/policy/boot mismatch')
        require(p['memory_scope_protocol']=='linux-private-cgroup-v2-v1' and p['start_fence_protocol']=='qcl-native-retirement-hook-v1','qualification','memory and permanent start fence protocols required')
        from host_resource_native_cleanup import PROTOCOL_SOURCE_DIGESTS
        ids=p['source_ids'];exact(ids,{'cli','client','driver','protocol','support'},'retirement source identities')
        require(p['native_peer_identity']['kind']=='libvirt_unix','qualification','libvirt retirement requires local system peer')
        conf='native_config/'+p['native_peer_identity']['unit'].removesuffix('.service')+'.conf'
        from host_resource_service import CONFIG
        configs={'resource_config/service':str(CONFIG),'resource_config/runtime':str(self.native.config['runtime']), 'native_config/qemu.conf':'/etc/libvirt/qemu.conf',conf:'/etc/libvirt/'+conf.split('/')[-1],'native_config/start-hook':'/etc/libvirt/hooks/qemu'}
        required={**PROTOCOL_SOURCE_DIGESTS['libvirt-local-setmem-v1'],**EXTRA_SOURCES}
        require(type(ids['support']) is dict and set(ids['support'])==set(required)|set(configs),'qualification','complete source/config/fence profile required')
        for name,ref in ids['support'].items():
            source_ref(ref)
            if name in required:require(ref['sha256']==required[name],'qualification','unreviewed retirement source')
            else:require(ref['path']==configs[name],'qualification','native config/hook source substitution')
        for ref in [ids[k] for k in ('cli','client','driver','protocol')]+list(ids['support'].values()):
            source_ref(ref);require(self.native.file_digest(ref['path'])==ref['sha256'],'qualification','actual source/config/hook changed')
        require(ids['cli']['path']==self.s.proofs.backend.tool,'qualification','native tool substitution')
        host=self.local.host();require(host['boot_id']==boot and host['kernel']==binding['host_kernel_id'],'identity_mismatch','host rebooted/kernel changed')
        peer=p['native_peer_identity'];decode_peer(peer);require(peer['kind']=='libvirt_unix','qualification','local libvirt peer required')
        path=Path(peer['socket_path']);trusted_root_path(path.parent,directory=True);st=path.lstat()
        require(st.st_uid==0 and stat.S_ISSOCK(st.st_mode) and (st.st_dev,st.st_ino)==(peer['socket_device'],peer['socket_inode']),'identity_mismatch','native socket changed')
        unit=self.native.unit(peer['unit']);birth=self.native.birth(int(unit['MainPID']),root=True)
        process=self.local.process(birth['pid'])
        require(unit['ActiveState']=='active' and unit['InvocationID']==peer['invocation_id'] and birth==peer['daemon_birth'] and
            process['cgroup']==unit['ControlGroup'] and process['executable']==ids['driver']['path'] and self.native.running_digest(birth['pid'])==ids['driver']['sha256'], 'identity_mismatch','native daemon incarnation changed')
        self.native.listener_owned(str(path),birth)
        backend=self.s.proofs.backend;require(backend.connect_endpoint==libvirt_endpoint(peer) and backend.runtime_version()==binding['backend_version_id'],'identity_mismatch','same backend/explicit endpoint required')
        return p
    def profile(self,target):
        decode_target(target);p=self._profile(target['binding'],target['host_boot_id'])
        require(p['native_peer_identity']==target['native_peer_identity'] and p['storage_namespace_sha256']==target['storage_namespace_sha256'],'identity_mismatch','original peer/storage authority changed')
        for key in ('cli','client','driver','protocol'):require(p['source_ids'][key]==target['source_ids'][key],'qualification','original native client/source changed')
        for key,ref in target['source_ids']['support'].items():require(p['source_ids']['support'][key]==ref,'qualification','original mutation source changed')
        require(self.native.file_digest(target['qemu_executable']['path'])==target['qemu_executable']['sha256'] and target['binding']['qemu_version_id']=='sha256:'+target['qemu_executable']['sha256'],'qualification','QEMU binary changed')
        return p
    def validate_target(self,target):
        profile=self.profile(target);backend=self.s.proofs.backend;t=target['target']
        storage=getattr(self,'storage',None)
        require(storage is not None,'qualification','production retirement requires attached storage owner')
        storage.validate_retirement(target)
        ids=backend._run(['list','--all','--uuid']).split()
        require(len(ids)==len(set(ids)),'incomplete_inventory','unique complete domain inventory')
        old_present=False
        from host_resource_backends import libvirt_config_fingerprint
        for native in ids:
            native_uuid(native);raw=backend._run(['dumpxml',native])
            require('<!DOCTYPE' not in raw and '<!ENTITY' not in raw,'shape','bounded plain native XML required')
            xml=ET.fromstring(raw);require(xml.findtext('uuid')==native,'identity_mismatch','native UUID changed')
            if native!=t['uuid']:
                require(xml.findtext('name')!=t['name'],'retired_target','retired name reused by another UUID');continue
            old_present=True
            require(xml.findtext('name')==t['name'] and libvirt_config_fingerprint(xml)==target['config_sha256'],'identity_mismatch','original native static config changed')
            state=backend._run(['domstate',native]).strip()
            if state=='running':
                read=backend.readback(target['binding']['vm_id'])
                require(read.native_id==native and read.process_id==str(target['qemu_birth']['pid']) and
                    self.native.birth(int(read.process_id))==target['qemu_birth'],'identity_mismatch','old UUID now identifies another native incarnation')
            else:require(state=='shut off' and self.quiescent(target),'cleanup','old native state/physical memory unknown')
        if not old_present:require(self.quiescent(target),'cleanup','old definition absent but physical scope remains')
        return profile
    def _xml(self,native_id):
        raw=self.s.proofs.backend._run(['dumpxml',native_id,'--inactive'])
        require('<!DOCTYPE' not in raw and '<!ENTITY' not in raw,'shape','XML entities unsupported')
        xml=ET.fromstring(raw);require(xml.findtext('uuid')==native_id,'identity_mismatch','native XML identity differs');return xml
    def storage_closure(self,xml,handle=None):
        from host_resource_storage import StorageCaptureHandle
        storage=getattr(self,'storage',None)
        require(storage is not None and type(handle) is StorageCaptureHandle and handle.owner is storage and not handle.closed and xml.findtext('uuid')==handle.binding['native_uuid'],'qualification','same-process qualified storage capture required')
        return [dict(path=f['path'],device=f['device'],inode=f['inode'],kind='local_regular') for f in handle.observation['files']]
    def replacement_storage(self,native_id,target,*,recovery_id=None):
        require(getattr(self,'storage',None) is not None and recovery_id is not None,'qualification','configured replacement capture owner required')
        handle=self.storage.capture_replacement(recovery_id,native_id)
        try:return self.storage_closure(self._xml(native_id),handle)
        except BaseException:handle.close();raise
    def validate_replacement_use(self,native_id,target):
        require(getattr(self,'storage',None) is not None and native_id in self.storage.handles,'qualification','process-local replacement handle missing')
        handle=self.storage.handles[native_id]
        try:assert_storage_disjoint(target['storage_devices'],self.storage.validate_use(handle))
        except BaseException:handle.close();raise
    def target_before_exec(self,intent,dispatch,p,backend,worker,cli):
        from host_resource_backends import libvirt_config_fingerprint
        profile=self._profile(asdict(intent.binding),intent.host_boot_id)
        require(p['protocol_id']=='libvirt-local-setmem-v1','source_protocol_unavailable','PVE recovery cannot be enabled')
        xml=self._xml(intent.binding.native_id);vm=backend.vms[intent.binding.vm_id]
        require(xml.findtext('name')==vm.name and xml.find('memoryBacking') is None and xml.find('devices/hostdev') is None and
            xml.find('devices/filesystem') is None and xml.find('devices/tpm') is None and xml.find('devices/shmem') is None and
            xml.find('qemu:commandline') is None,'qualification','external/shared memory holder topology unqualified')
        for elem in xml.iter():require(not elem.tag.startswith('{'),'qualification','custom namespace extensions unqualified')
        allowed={'disk','controller','interface','input','graphics','video','audio','sound','serial','console','channel','memballoon','rng','watchdog','panic'}
        devices=xml.find('devices')
        require(devices is not None and all(device.tag in allowed for device in devices),'qualification','unknown/external memory-holding device unqualified')
        for disk in xml.findall('devices/disk'):require(disk.get('type') in {'file','block'},'qualification','external storage process unqualified')
        for accel in xml.findall('devices/video/model/acceleration'):require(accel.get('accel3d','no')=='no','qualification','external 3D renderer unqualified')
        for interface in xml.findall('devices/interface'):
            driver=interface.find('driver');require(interface.get('type')=='user' or (driver is not None and driver.get('name')=='qemu'),'qualification','external vhost memory backing unqualified')
        require(getattr(self,'storage',None) is not None,'qualification','production target requires configured owned storage collector')
        handle=self.storage.capture_mutation(intent,dispatch)
        try:
            self.storage.seal(handle)
            storage_devices=decode_storage_devices(self.storage_closure(xml,handle))
        except BaseException:handle.close();raise
        storage=fingerprint([ET.tostring(x,encoding='unicode') for x in xml.findall('devices/disk')])
        require(storage==profile['storage_namespace_sha256'],'qualification','exact private storage namespace changed')
        process=self.local.process(int(intent.binding.process_id))
        argv=self.local.read('/proc/'+str(process['pid'])+'/cmdline').split('\0')
        require(argv.count('-uuid')==1 and argv[argv.index('-uuid')+1]==vm.native_id,'ownership','actual QEMU command line is not the owned native UUID')
        scope=process['cgroup'];root=Path('/sys/fs/cgroup'+scope)
        st=root.lstat();require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022,'trust','protected actual VM cgroup required')
        unit=scope.rsplit('/',1)[-1];require(scope.startswith('/machine.slice/') and unit.endswith('.scope'),'qualification','native VM scope required')
        raw=self.local.run([self.native.config['systemctl'],'show',unit,'--property=InvocationID','--property=ControlGroup'])
        fields=dict(line.split('=',1) for line in raw.splitlines());require(fields.get('ControlGroup')==scope,'identity_mismatch','VM scope unit differs');uid(fields.get('InvocationID'))
        executable=dict(path=process['executable'],sha256=self.native.running_digest(process['pid']));source_ref(executable)
        doc=dict(schema=TARGET_SCHEMA,request_id=intent.request_id,mutation_id=intent.mutation_id,intent_sha256=fingerprint(asdict(intent)),dispatch_sha256=fingerprint(dispatch),
            host_id=intent.host_id,owner_id=intent.owner_id,host_boot_id=intent.host_boot_id,policy_sha256=intent.policy_sha256,binding=asdict(intent.binding),protocol_id=intent.protocol_id,qualification_sha256=intent.qualification_sha256,
            source_ids=p['source_ids'],native_peer_identity=p['native_peer_identity'],target=dict(kind='libvirt',system_namespace='system',uuid=vm.native_id,name=vm.name,connect_endpoint=backend.connect_endpoint),
            qemu_birth=self.native.birth(process['pid']),qemu_executable=executable,vm_scope=dict(cgroup=scope,device=st.st_dev,inode=st.st_ino,invocation_id=fields['InvocationID']),owned_helpers=[],
            config_sha256=libvirt_config_fingerprint(xml),storage_namespace_sha256=storage,storage_devices=storage_devices,worker_birth=worker,cli_birth=cli)
        return decode_target(doc)
    def quiescent(self,target):
        birth=target['qemu_birth']
        try:
            if self.native.birth(birth['pid'])==birth:return False
        except (FileNotFoundError,ProcessLookupError):pass
        scope=target['vm_scope'];path=Path('/sys/fs/cgroup'+scope['cgroup'])
        try:before=path.lstat()
        except FileNotFoundError:return True  # sealed nondelegated scope removed: no migrated holders qualified
        require(stat.S_ISDIR(before.st_mode) and before.st_uid==0 and (before.st_dev,before.st_ino)==(scope['device'],scope['inode']),'identity_mismatch','old VM cgroup replaced')
        from application_release import UpdateScan
        budget=UpdateScan(time.monotonic()+10)
        require(not any(stat.S_ISDIR(budget.stat(p).st_mode) for p in budget.entries(path,'cgroup')),'cleanup','nested VM scope unqualified')
        raw=budget.read(path/'cgroup.events').decode();events=dict(line.split() for line in raw.splitlines())
        require('populated' in events,'incomplete_probe','complete VM cgroup events required')
        empty=events['populated']=='0' and not budget.read(path/'cgroup.procs').strip() and not budget.read(path/'cgroup.threads').strip()
        final=path.lstat();require((before.st_dev,before.st_ino)==(final.st_dev,final.st_ino),'identity_mismatch','old VM scope raced')
        return empty
    def command_absent(self,record):
        return self.native.absent(dict(intent=dict(native_context=record['native_context']),worker_birth=record['worker_birth'],cli_birth=record['cli_birth']))
    def removed(self,target):
        self.profile(target);t=target['target'];backend=self.s.proofs.backend
        raw=backend._run(['list','--all','--uuid']);ids=raw.split();require(len(ids)==len(set(ids)),'incomplete_inventory','unique complete native UUID inventory')
        for value in ids:native_uuid(value)
        if t['uuid'] in ids:return False
        for value in ids:
            xml=self._xml(value);require(xml.findtext('name')!=t['name'],'retired_target','retired name reused')
        for path in [Path('/etc/libvirt/qemu')/(t['name']+'.xml'),Path('/etc/libvirt/qemu/autostart')/(t['name']+'.xml'),Path('/etc/libvirt/qemu/autostart')/(t['name']+'.xml.once')]:
            trusted_root_path(path.parent,directory=True)
            try:path.lstat();return False
            except FileNotFoundError:pass
        return True
    def recovery_facts(self,request,*,owner_state,target):
        vm=target['binding']['vm_id'];self.profile(target)
        evidence,reads=self.s.provider.recovery_snapshot(vm,owner_state=owner_state)
        path=self.s.path(request.recovery_id,'closure')
        if path.exists():closures=self.s.store._read(path)
        else:
            # Before destructive control, ask the existing authenticated owning
            # producer for every exact native terminal + output closure. It
            # currently emits no output receipt: that real SOURCE gap holds.
            self.s.provider.request_facts(None,owner_state=owner_state);closures={}
            for row in owner_state['receipts']:
                if row['request']['vm_id']!=vm:continue
                self.s.provider.completion(row['request']['request_id'],owner_state=owner_state)
                native=row['native_workload'];require(native is not None,'native_generation','historical native generation missing')
                closures[row['request']['request_id']]=dict(request_sha256=fingerprint(row),native_generation=native['generation'],output_provenance=fingerprint(self.s.provider.last[1][vm]['outputs'][native['generation']]))
        return RecoveryFacts(evidence,reads,closures)
    def replacement(self,native_id,*,owner_state,target):
        vm=target['binding']['vm_id'];backend=self.s.proofs.backend
        enrolled=backend.vms[vm];require(enrolled.native_id==native_id and native_id!=target['target']['uuid'] and enrolled.name!=target['target']['name'],'identity_mismatch','new protected native identity/name required')
        check_start_fence(self.s.store,'libvirt',uuid=native_id,name=enrolled.name)
        evidence,reads=self.s.provider.recovery_snapshot(vm,owner_state=owner_state)
        # The regular cold reader also validates all foreign bounds and complete
        # inventory, while this scoped snapshot preserves other running VMs.
        self.s._validate_facts(RecoveryFacts(evidence,reads,{}),owner_state,target)
        host,rows,agreement=self.s.provider._host_inventory();row=next(r for r in rows if r['native_id']==native_id)
        from host_resource_startup import ColdVMRecord
        return ColdVMRecord(vm,native_id,row['config_fingerprint'],row['maximum_bytes'],row['maximum_bytes'],'running' if row['running'] else 'stopped')


def prepare_target_seal(native_sources,intent,dispatch,profile,backend,worker,cli):
    config=native_sources.config.get('native_recovery')
    if config is None:return None
    if native_sources.config.get('native_storage') is not None:
        owner=getattr(native_sources,'recovery_sources',None)
        require(owner is not None,'qualification','same-service recovery/storage owner missing')
        return owner.target_before_exec(intent,dispatch,profile,backend,worker,cli)
    from host_resource_service import open_service
    # Existing source owner/factory; no recursion into claim/exec, no public path.
    service=open_service();return service.recovery.sources.target_before_exec(intent,dispatch,profile,backend,worker,cli)


def native_exec(recovery_id,stage_id):
    from host_resource_service import open_service
    require(os.geteuid()==0,'root_required','root recovery exec only')
    service=open_service();require(hasattr(service,'recovery'),'qualification','protected recovery source not configured')
    argv=service.recovery.claim(recovery_id,stage_id)
    os.execve(argv[0],list(argv),service.recovery.runner.environment)


def read_recovery_status(recovery_id):
    """Existing-file projection only; no factory, native calls, fsync or refresh."""
    from host_resource_operations import FileReceiptStore,HostResourceController,validate_host_resource_policy
    from host_resource_service import CONFIG
    config=read_root_json(CONFIG);runtime=read_root_json(config['runtime']);uid(recovery_id)
    require(config.get('role')=='native_host','trust','native host status only')
    store=FileReceiptStore.open_existing(trusted_root_path(runtime['state_directory'],directory=True))
    class OfflineBackend:quantum_bytes=1
    controller=HostResourceController(validate_host_resource_policy(read_root_json(runtime['policy'])),store,OfflineBackend())
    with store.locked(read_only=True):
        intent=decode_recovery_intent(store._read(store.directory/'native-recoveries'/(recovery_id+'.intent.json')))
        request=NativeRecoveryRequest(**intent['recovery']);state=controller._load()
        row=next((r for r in state['receipts'] if r['request']['request_id']==request.request_id),None) or store.completed(request.request_id)
        require(row is not None,'request_unknown','exact original receipt required')
        vm=row['request']['vm_id'];grant=controller._grant(state,vm)
        phase='retiring_unknown' if any(r['request']['request_id']==request.request_id for r in state['receipts']) else 'target_retired'
        return dict(schema='qcl.host-resource-recovery.v1',**asdict(request),host_id=controller.policy.host_id,vm_id=vm,
            phase=phase,original_outcome='unknown',charged_bytes=grant.guest_bytes,replacement_native_id=None,
            failure_code='readback_not_measured',state_generation=fingerprint(state),observed_at=int(time.time()))


def admin_recovery(args):
    """No new sudo role: actual root ancestry and fixed administrative argv only."""
    from host_resource_service import CONFIG,open_service
    from host_resource_facts import LocalSources
    config=read_root_json(CONFIG);sources=LocalSources(config,None)
    for pid in (os.getpid(),os.getppid()):
        process=sources.process(pid);require(process['uids']==[0]*4 and process['start_ticks']>0,'root_required','actual administrative root ancestry required')
    if len(args)==2 and args[0]=='recovery-status':return read_recovery_status(args[1])
    if len(args)==4 and args[0]=='retire':
        request=NativeRecoveryRequest(*args[1:])
        import application_release as engine
        import base64
        trusted_root_path(config['systemd_run'],executable=True);trusted_root_path(config['worker_helper'],executable=True)
        token=base64.urlsafe_b64encode(json.dumps(asdict(request),separators=(',',':')).encode()).decode()
        output=engine.command([config['systemd_run'],'--quiet','--wait','--pipe','--unit=qcl-resource-'+uuid.uuid4().hex,
            '--service-type=exec','--property=KillMode=control-group','--property=TimeoutStopSec=10s',config['worker_helper'],'retirement',token],timeout_seconds=120,output_bytes=MAX_OUTPUT_BYTES)
        from host_resource_operations import strict_json
        return strict_json(output)
    if len(args)==3 and args[0]=='reserve-replacement':
        service=open_service();require(hasattr(service,'recovery'),'qualification','retirement source not configured')
        return service.recovery.reserve_replacement(args[1],args[2])
    raise ResourceError('shape','fixed administrative retirement action/IDs required')
