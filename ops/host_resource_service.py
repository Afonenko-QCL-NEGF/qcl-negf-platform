"""Installed privileged ingress and one native-host owner. No launch wiring."""
from dataclasses import asdict
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sys
import time
import uuid

import application_release as engine
from host_resource_operations import (HostResourceController,ResourceError,ResourceRequest,
    UNKNOWN,FileReceiptStore,validate_host_resource_policy,integer,require,strict_json)
from host_resource_backends import (RootNativeBoundary,NativeCommandRunner,read_root_json,trusted_root_path)
from host_resource_client import ACTIONS,NativeDemand,decode_action,MAX_PACKET
from host_resource_facts import (NativeFactsProvider,LocalSources,authenticate_sudo_caller,
    capture_guest_facts,capture_guest_identity,capture_scheduler,trusted_rpc)
from host_resource_startup import StartupManager

CONFIG=Path('/etc/qcl-negf/host-resources/service.json')


def generation(state):return hashlib.sha256(json.dumps(state,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def operation_view(ref,*,state=None,row=None,failure=None,native=None,observed_at=None):
    state=state or {};req=row['request'] if row else {};vm=req.get('vm_id')
    grant=next((g for g in state.get('grants',[]) if g['vm_id']==vm),None)
    phase=row['phase'] if row else 'NOT_INITIALIZED';code=failure or (row and row['failure'])
    if code in {'unsupported','qualification','native_mutation_protocol'}:admission='unsupported'
    elif phase in UNKNOWN or state.get('blocked') or code in {'cleanup','cleanup_evidence','identity_mismatch','native_generation','reconciliation_required','upgrade_required','transport_unknown','state','incomplete_workloads','incomplete_bindings','incomplete_inventory','startup_binding_required','native_owner'}:admission='reconciliation_required'
    elif phase=='RUN' and not code:admission='ready'
    elif code and code not in {'host_busy','host_locked','capacity','maximum','guest_capacity','host_pressure','readback_pending'}:admission='rejected'
    else:admission='resource_wait'
    if not row and code:phase='UNSUPPORTED' if admission=='unsupported' else 'REJECTED'
    mapping=row.get('native_workload') if row else native
    return dict(schema='qcl.host-resource-operation.v1',request_id=req.get('request_id'),workload=asdict(ref),
        native_generation=mapping.get('generation') if mapping else None,host_id=req.get('host_id'),vm_id=vm,
        state_generation=generation(state) if state else None,phase=phase,admission=admission,failure_code=code,
        requested_workload_bytes=req.get('workload_bytes'),target_bytes=row['target_bytes'] if row else None,
        charged_bytes=grant['guest_bytes'] if grant else None,current_assigned_bytes=None,current_configured_bytes=None,
        protected_floor_bytes=grant['active_floor_bytes'] if grant else None,
        cleanup=('not_started' if not row or not row['mutation_id'] else 'confirmed' if row['native_cleanup_confirmed'] else 'unknown'),
        native_freshness=dict(status='fresh' if observed_at is not None else 'not_measured',observed_at=observed_at))


class NativeResourceService:
    def __init__(self,controller,provider,*,clock=time.time):
        self.controller,self.provider,self.clock=controller,provider,clock
        self.startup=StartupManager(controller.policy,controller.store,controller.backend,clock)
    def _active_row(self,state,ref):
        matches=[r for r in state['receipts'] if r.get('native_workload') and
            r['native_workload']['kind']==ref.kind and r['native_workload']['native_id']==ref.native_id]
        require(len(matches)<=1,'native_generation','reused native ID has multiple active generations')
        return matches[0] if matches else None
    def read_native_status(self,ref):
        # NO resolve/provider refresh, no state creation, no history scan.
        c=self.controller
        try:
            with c.store.locked(read_only=True):
                state=c._load();view=operation_view(ref,state=state,row=self._active_row(state,ref))
                if view['admission']=='ready':
                    view.update(admission='reconciliation_required',failure_code='readback_not_measured')
                return view
        except (FileNotFoundError,ResourceError) as error:
            return operation_view(ref,failure=getattr(error,'code',None))
    def _invoke(self,action,value):
        ref=value.workload if type(value) is NativeDemand else value;c=self.controller;row=None;state=None
        admitted_now=False
        try:
            with c.store.operation():
                state=c._load();native,vm,workload_id,request_id=self.provider.resolve(ref)
                mapping=dict(kind=ref.kind,native_id=ref.native_id,generation=native['generation'])
                previous=self._active_row(state,ref)
                require(previous is None or previous['native_workload']==mapping,'native_generation','native ID reused; retain original charge')
                row=next((r for r in state['receipts'] if r['request']['request_id']==request_id),None)
                if row is None:row=c.store.completed(request_id)
                if row and (row['phase']=='RELEASE' or c.store.is_retired(request_id)):
                    return operation_view(ref,state=state,row=row,failure='reconciliation_required' if c.store.is_retired(request_id) else None)
                if type(value) is NativeDemand:
                    require(value.workload_bytes>=native['limit_bytes'],'demand','demand below actual native allocation')
                    req=ResourceRequest(request_id,c.policy.host_id,vm,c.policy.owner_id,value.workload_bytes,workload_id)
                else:require(row is not None,'request_unknown','no active exact native generation request')
                evidence=self.provider.request_facts(value,owner_state=state)
                if type(value) is NativeDemand:
                    c.request(req,evidence);state=c._load();row=c._row(state,request_id)
                    require(row['native_workload'] in (None,mapping),'native_generation','stored mapping changed')
                    if row['native_workload'] is None:row['native_workload']=mapping;c._save(state)
                if action in {'request','launch-gate'}:
                    # Progress metadata/grow once. UNKNOWN is never replayed.
                    if row['phase']=='HOST_GRANT':c.grow(request_id,evidence);state=c._load();row=c._row(state,request_id)
                    if row['phase']=='GUEST_ADMIT':
                        guest=self.provider.guest_admission(request_id,owner_state=state);c.admit(request_id,guest,evidence)
                        admitted_now=True
                elif action=='finish':
                    completion=self.provider.completion(request_id,owner_state=state)
                    if row['phase']=='RUN':c.finish(request_id,completion,evidence)
                    state=c._load();row=c._row(state,request_id)
                    if row['phase']=='SHRINK_READY':c.shrink(request_id,evidence)
                    state=c._load();row=c._row(state,request_id)
                    if row['phase']=='SHRINK_UNKNOWN':c.reconcile(request_id,evidence,completion,
                        cleanup_evidence=self.provider.cleanup(request_id,owner_state=state))
                elif action=='reconcile':
                    cleanup=self.provider.cleanup(request_id,owner_state=state)
                    completion=None
                    if row['finished']:completion=self.provider.completion(request_id,owner_state=state)
                    c.reconcile(request_id,evidence,completion,cleanup_evidence=cleanup)
                state=c._load();row=c._row(state,request_id)
                # Idempotent receipts are durable identities, not fresh launch
                # authority. Every existing RUN response must pass the same
                # host-wide guard, including reconcile/no-op completion paths.
                # admit() already guarded the pre-admit live snapshot and full
                # target readback before adding this candidate to RUN.
                if row['phase']=='RUN' and not admitted_now:c._guard(state,evidence)
                return operation_view(ref,state=state,row=row,observed_at=evidence.observed_at)
        except ResourceError as error:
            # Native exceptions retain their private records on the original
            # object/controller log. Public DTO exposes a stable bounded code.
            if hasattr(error,'native_journal_error') or hasattr(error,'native_log_error'):raise
            if state is not None:
                try:state=c.store.load();row=self._active_row(state,ref) or row
                except (OSError,ResourceError):pass
            return operation_view(ref,state=state,row=row,failure=error.code)
    def request_native(self,demand):return self._invoke('request',demand)
    def reconcile_native(self,ref):return self._invoke('reconcile',ref)
    def finish_native(self,ref):return self._invoke('finish',ref)


def validate_service_config(config):
    require(type(config) is dict and config.get('schema')=='qcl.host-resource-service.v1' and
        config.get('role') in {'native_host','controller','guest'},'trust','protected service config required')
    integer(config.get('client_uid'),'client_uid',1)
    roles=[config['client_uid']]
    for key in ('authority_uid','facts_uid'):
        if key in config:
            integer(config[key],key,1);roles.append(config[key])
    require(len(roles)==len(set(roles)),'trust','client/authority/facts real UIDs must be distinct')
    return config


def open_service():
    require(os.geteuid()==0,'root_required','installed root native helper required')
    config=validate_service_config(read_root_json(CONFIG));require(config['schema']=='qcl.host-resource-service.v1' and config['role']=='native_host','trust','native-host root config required')
    boundary=RootNativeBoundary(config['runtime']);policy,store,backend=boundary.open_owner()
    facts={**config['facts'],'backend_config':boundary.config['backend_config'],'state_directory':str(store.directory),
        'evidence':boundary.config['evidence'],'qualification':boundary.config['qualification'],'client_uid':config['client_uid']}
    dynamic=policy.active_grant.mechanism=='qualified_dynamic'
    expected='qcl.native-memory.balloon.v1' if dynamic else 'qcl.native-memory.fixed.v1'
    require(facts['readback_version']==expected,'qualification','production readback protocol changed')
    tools=[boundary.config['backend_config']['tool'],*config['tools']]
    proofs=None
    if dynamic:
        from host_resource_native_cleanup import (decode_config,NativeCleanupSources,
            NativeMutationProofs,QualifiedMutationBackend)
        from host_resource_backends import ProxmoxMemoryBackend,LibvirtMemoryBackend
        cleanup=decode_config(config.get('native_cleanup'))
        if type(backend) is ProxmoxMemoryBackend:
            require(cleanup['protocol_id']=='pve-local-put-balloon-v1','qualification','PVE protocol mismatch')
            backend.local_only=True
        else:
            require(type(backend) is LibvirtMemoryBackend and cleanup['protocol_id']=='libvirt-local-setmem-v1',
                'qualification','local libvirt protocol required')
        tools.append(cleanup['helper'])
        runner=NativeCommandRunner(tools)
        proofs=NativeMutationProofs(policy,store,backend,cleanup,runner,
            sources=NativeCleanupSources(config,runner))
        backend=QualifiedMutationBackend(backend,proofs)
    else:runner=NativeCommandRunner(tools)
    provider=NativeFactsProvider(policy,facts,backend,runner)
    if proofs is not None:provider.native_proofs=proofs
    controller=HostResourceController(policy,store,backend)
    service=NativeResourceService(controller,provider)
    if config.get('native_recovery') is not None:
        require(proofs is not None,'qualification','retirement requires existing dynamic source owner')
        from host_resource_recovery import NativeRecoveryService
        service.recovery=NativeRecoveryService(controller,provider,proofs,config['native_recovery'],runner)
    if config.get('native_storage') is not None:
        require(proofs is not None and hasattr(service,'recovery'),'qualification','owned storage requires existing C/F1 owner')
        from host_resource_storage import LibvirtStorageCollector
        service.storage=LibvirtStorageCollector(controller,proofs.sources,proofs.backend,runner,config['native_storage'])
        service.recovery.sources.storage=service.storage
        proofs.sources.storage_collector=service.storage
        proofs.sources.recovery_sources=service.recovery.sources
    return service


def native_unit_context(row,*,sources,systemctl):
    process=sources.process(os.getpid());scope=process['cgroup']
    unit=scope.rsplit('/',1)[-1]
    require(re.fullmatch(r'qcl-resource-[0-9a-f]{32}\.service',unit),'native_owner','resource worker has no native unit owner')
    raw=sources.run([systemctl,'show',unit,'--property=InvocationID','--property=ControlGroup','--property=ActiveState'])
    properties=dict(line.split('=',1) for line in raw.splitlines())
    require(properties.get('ControlGroup')==scope and properties.get('ActiveState')=='active' and
        re.fullmatch(r'[0-9a-f]{32}',properties.get('InvocationID','')),
        'native_owner','actual native unit invocation/cgroup changed')
    return dict(unit=unit,invocation_id=properties['InvocationID'],cgroup=scope,
        host_boot_id=sources.host()['boot_id'],mutation_id=row['mutation_id'])


def decode_token(token):
    require(type(token) is str and len(token)<=MAX_PACKET and re.fullmatch(r'[A-Za-z0-9_=-]+',token),'shape','bounded base64 JSON packet required')
    try:raw=base64.b64decode(token,altchars=b'-_',validate=True)
    except ValueError as error:raise ResourceError('shape','invalid RPC packet') from error
    require(len(raw)<=MAX_PACKET,'output_bound','RPC packet too large')
    try:return strict_json(raw.decode())
    except (ValueError,UnicodeError) as error:raise ResourceError('shape','invalid RPC JSON') from error


def dispatch(action,document):
    value=decode_action(action,document)
    if action=='status':
        # Separate open-existing path: no FileReceiptStore constructor, fsync,
        # backend/qualification construction, facts refresh or native unit.
        config=read_root_json(CONFIG);require(config['role']=='native_host','trust','native status only')
        runtime=read_root_json(config['runtime'])
        policy=validate_host_resource_policy(read_root_json(runtime['policy']))
        try:
            trusted_root_path(runtime['state_directory'],directory=True)
            store=FileReceiptStore.open_existing(runtime['state_directory'])
        except FileNotFoundError:return operation_view(value)
        class ReadOnlyBackend:quantum_bytes=1
        return NativeResourceService(HostResourceController(policy,store,ReadOnlyBackend()),None).read_native_status(value)
    return open_service()._invoke(action,value)


def route_public(config,action,document,caller):
    value=decode_action(action,document);ref=value.workload if type(value) is NativeDemand else value
    require(ref.kind=='slurm_allocation','unsupported','per-build Nix daemon join source is not implemented')
    if config['role']=='guest':
        require(caller['cgroup'].startswith(config['slurm_cgroup_root']+'/job_'+ref.native_id+'/'),
                'caller','real caller must belong to exact native allocation cgroup')
        return trusted_rpc(config['controller_route'],action,document,run=engine.command)
    require(config['role']=='controller','trust','client ingress role required')
    if action=='status':
        routes={json.dumps(route,sort_keys=True):route for route in config['host_routes'].values()}
        views=[trusted_rpc(route,action,document,run=engine.command) for route in routes.values()]
        active=[view for view in views if view.get('request_id') is not None]
        require(len(active)<=1,'native_generation','native ID has multiple retained host owners')
        return active[0] if active else operation_view(ref)
    runner=NativeCommandRunner(config['tools'],slurm_conf=config['slurm_conf']);sources=LocalSources(config,runner)
    jobs=capture_scheduler(config,sources);native=jobs.get(ref.native_id)
    require(ref.kind=='slurm_allocation' and native is not None and native['owner_uid']==config['client_uid'],
            'ownership','root observed enrolled native allocation required')
    route=config['host_routes'].get(native['node']);require(route is not None,'ownership','native node has no enrolled host route')
    return trusted_rpc(route,action,document,run=engine.command)


def root_main(role,argv=None):
    argv=list(sys.argv[1:] if argv is None else argv)
    require(os.geteuid()==0,'root_required','root helper only')
    config=validate_service_config(read_root_json(CONFIG))
    if role=='worker' and len(argv)==2 and argv[0]=='retirement':
        from host_resource_recovery import NativeRecoveryRequest
        service=open_service();require(hasattr(service,'recovery'),'qualification','protected retirement owner missing')
        return service.recovery.retire(NativeRecoveryRequest(**decode_token(argv[1])))
    require(len(argv)==2,'shape','action and bounded token required');action,token=argv;document=decode_token(token)
    if role in {'client','authority'}:
        allowed_uid=config['client_uid'] if role=='client' else config['authority_uid']
        sources=LocalSources(config,None)
        for executable in config['sudo_executables']:trusted_root_path(executable,executable=True)
        caller=authenticate_sudo_caller(os.environ,parent_pid=os.getppid(),process=sources.process,
            sudo_executables=tuple(config['sudo_executables']),allowed_uid=allowed_uid)
        if role=='client':return route_public(config,action,document,caller)
        require(config['role']=='native_host','trust','authority reaches native host only')
        decode_action(action,document)
        if action=='status':return dispatch(action,document)
        # Native ownership survives ingress disconnect. P11 owns this wait
        # process; systemd owns the actual worker cgroup. No second supervisor.
        trusted_root_path(config['systemd_run'],executable=True)
        trusted_root_path(config['worker_helper'],executable=True)
        unit='qcl-resource-'+uuid.uuid4().hex
        output=engine.command([config['systemd_run'],'--quiet','--wait','--pipe','--unit='+unit,
            '--service-type=exec','--property=KillMode=control-group','--property=TimeoutStopSec=10s',
            config['worker_helper'],action,token],timeout_seconds=120,output_bytes=MAX_PACKET)
        return strict_json(output)
    if role=='worker':
        require(config['role']=='native_host','trust','worker is native host root only')
        return dispatch(action,document)
    if role=='facts':
        if os.environ.get('SUDO_UID') is not None:
            sources=LocalSources(config,None)
            for executable in config['sudo_executables']:trusted_root_path(executable,executable=True)
            authenticate_sudo_caller(os.environ,parent_pid=os.getppid(),process=sources.process,
                sudo_executables=tuple(config['sudo_executables']),allowed_uid=config['facts_uid'])
        require(document=={} and action in {'guest-facts','guest-identity','scheduler-facts'},'action','facts route is read-only')
        if action=='guest-identity':return capture_guest_identity(config,LocalSources(config,None))
        sources=LocalSources(config,NativeCommandRunner(config['tools'],slurm_conf=config['slurm_conf']))
        if action=='scheduler-facts':return dict(schema='qcl.host-resource-scheduler-facts.v1',jobs=capture_scheduler(config,sources))
        return capture_guest_facts(config,sources)
    raise ResourceError('action','privileged role unavailable')


def ssh_main(role,*,helper_prefix='/run/current-system/sw/bin'):
    """Unprivileged forced-command parser; sudo entrypoint authenticates again."""
    require(role in {'client','authority','facts'},'trust','fixed enrolled SSH role required')
    parts=shlex.split(os.environ.get('SSH_ORIGINAL_COMMAND',''))
    require(len(parts)==4 and parts[0]==helper_prefix+'/qcl-negf-resource-rpc' and parts[1]==role,
        'trust','unexpected SSH resource command')
    action,token=parts[2:];decode_token(token)
    require(action in (ACTIONS if role!='facts' else {'guest-facts','guest-identity','scheduler-facts'}),'action','fixed resource action required')
    executable=helper_prefix+'/qcl-negf-resource-'+('client-root' if role=='client' else role)
    os.execvp('sudo',['sudo','-n',executable,action,token])


def main(role):
    try:result=root_main(role)
    except ResourceError as error:
        if role=='worker' and len(sys.argv)==3 and sys.argv[1]=='retirement':
            from host_resource_recovery import NativeRecoveryRequest,read_recovery_status
            try:
                request=NativeRecoveryRequest(**decode_token(sys.argv[2]))
                result=read_recovery_status(request.recovery_id)
                result.update(phase='hold',failure_code=error.code)
            except Exception as secondary:
                error.native_journal_error=repr(secondary)
                raise error
        else:
            from host_resource_client import NativeWorkloadRef
            ref=NativeWorkloadRef('slurm_allocation','unknown')
            try:
                action,token=sys.argv[1:];value=decode_action(action,decode_token(token))
                ref=value.workload if type(value) is NativeDemand else value
            except (ValueError,ResourceError):ref=None
            result=operation_view(ref or NativeWorkloadRef('slurm_allocation','unknown'),failure=error.code)
            if ref is None:result['workload']=None
    data=json.dumps(result,separators=(',',':'));require(len(data.encode())<=MAX_PACKET,'output_bound','response bound')
    print(data);return 0  # transport success; public client interprets admission
