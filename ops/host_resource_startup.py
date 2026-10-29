"""Cold full-charge reservation and offline start gate. Never starts/stops a VM."""
from dataclasses import asdict, dataclass, replace
import hashlib
import json
from pathlib import Path
import time
from typing import Literal, TypedDict

from host_resource_operations import (HostResourceController, ResidentGrant, RuntimeBinding,
    STATE_SCHEMA, ResourceError, policy_digest, require, strict_json, text, validate_host_grants)


@dataclass(frozen=True)
class ColdVMRecord:
    vm_id: str
    native_id: str
    static_config_fingerprint: str
    configured_max_bytes: int
    initial_peak_bytes: int
    observed_power_state: Literal['stopped', 'running', 'unknown']


@dataclass(frozen=True)
class ColdHostEvidence:
    host_id: str
    owner_id: str
    host_boot_id: str
    policy_sha256: str
    observed_at: int
    physical_ram_bytes: int
    foreign_max_bytes: int
    capacity_evidence_ref: str
    agreement_ref: str
    enforcement_ref: str
    pressure_ok: bool
    vms: tuple[ColdVMRecord, ...]


class StartupReservationView(TypedDict):
    schema: Literal['qcl.host-resource-startup.v1']
    reservation_id: str
    host_id: str
    vm_id: str
    native_vm_id: str
    host_boot_id: str
    policy_sha256: str
    static_config_fingerprint: str
    phase: Literal['cold_reserved','boot_unknown','running_quarantined','binding_ready','reconciliation_required','rejected']
    charged_bytes: int
    initial_peak_bytes: int
    binding: dict[str,str] | None
    admission_closed: bool
    failure_code: str | None
    observed_at: int


class StartupManager:
    def __init__(self, policy, store, backend, clock=time.time):
        self.controller = HostResourceController(policy, store, backend, clock)
        self.policy, self.store, self.clock = policy, store, clock

    def _view(self, state, vm_id):
        row = state['startups'][vm_id]
        require(row['reservation_id'] is not None,'startup_scope','running typed adoption has no cold reservation view')
        grant = self.controller._grant(state, vm_id)
        return dict(schema='qcl.host-resource-startup.v1', reservation_id=row['reservation_id'],
            host_id=self.policy.host_id, vm_id=vm_id, native_vm_id=row['native_id'],
            host_boot_id=state['host_boot_id'], policy_sha256=state['policy_sha256'],
            static_config_fingerprint=row['static_config_fingerprint'], phase=row['phase'],
            charged_bytes=grant.guest_bytes, initial_peak_bytes=row['initial_peak_bytes'],
            binding=state['bindings'][vm_id], admission_closed=row['phase']!='binding_ready',
            failure_code=None, observed_at=int(self.clock()))

    def prepare_start_reservations(self, *, cold_evidence):
        e, p = cold_evidence, self.policy
        require(type(e) is ColdHostEvidence, 'shape', 'trusted cold facts required')
        self.controller._fresh(e.observed_at)
        require((e.host_id,e.owner_id,e.policy_sha256,e.physical_ram_bytes,e.foreign_max_bytes,
                 e.capacity_evidence_ref,e.agreement_ref) == (p.host_id,p.owner_id,policy_digest(p),
                 p.physical_ram_bytes,p.reserves.foreign_max_bytes,p.capacity_evidence_ref,
                 p.owned_pool.agreement_ref), 'capacity_evidence', 'cold identity/capacity agreement differs')
        text(e.host_boot_id,'host_boot_id');text(e.enforcement_ref,'enforcement_ref')
        require(e.pressure_ok is True, 'host_pressure', 'cold startup admission closed')
        require(type(e.vms) is tuple and all(type(v) is ColdVMRecord for v in e.vms) and
                len(e.vms)==len(p.vms) and {v.vm_id for v in e.vms}=={v.vm_id for v in p.vms},
                'incomplete_inventory','complete cold owned inventory required')
        require(len({v.native_id for v in e.vms})==len(e.vms),'ownership','native VM reused')
        for row in e.vms:
            vm=self.controller._vm(row.vm_id)
            text(row.native_id,'native_id');text(row.static_config_fingerprint,'config')
            require(row.observed_power_state=='stopped','adoption_required','running/unknown VM needs verified adoption')
            require(row.configured_max_bytes==row.initial_peak_bytes==vm.maximum_bytes,
                    'startup_peak','first supported startup reserves the complete maximum')
        grants=tuple(ResidentGrant(p.host_id,vm.vm_id,p.owner_id,vm.maximum_bytes,
                                   vm.minimum_bytes,'idle') for vm in p.vms)
        validate_host_grants(p,grants)
        with self.store.locked():
            from host_resource_recovery import check_start_fence
            for row in e.vms:
                check_start_fence(self.store,'libvirt',uuid=row.native_id)
                check_start_fence(self.store,'proxmox',uuid=row.native_id)
            if self.store.state_path.exists():
                state=self.controller._load()
                require(state['host_boot_id']==e.host_boot_id and state['policy_sha256']==e.policy_sha256
                        and not state['receipts'] and state['blocked'] is None,
                        'reconciliation_required','retain prior grants/unknown work')
                require(all(state['startups'][v.vm_id]['phase']=='cold_reserved' and
                    state['startups'][v.vm_id]['native_id']==v.native_id and
                    state['startups'][v.vm_id]['static_config_fingerprint']==v.static_config_fingerprint
                    for v in e.vms),'already_initialized','existing startup binding differs')
            else:
                state=dict(schema=STATE_SCHEMA,policy_sha256=e.policy_sha256,host_boot_id=e.host_boot_id,
                    grants=[asdict(g) for g in grants],bindings={v.vm_id:None for v in e.vms},
                    desired={g.vm_id:g.guest_bytes for g in grants},receipts=[],blocked=None,
                    startups={v.vm_id:dict(phase='cold_reserved',native_id=v.native_id,
                        static_config_fingerprint=v.static_config_fingerprint,initial_peak_bytes=v.initial_peak_bytes,
                        reservation_id=hashlib.sha256((e.host_boot_id+e.policy_sha256+v.native_id+
                            v.static_config_fingerprint).encode()).hexdigest()) for v in e.vms})
                self.store.save(state)
            return tuple(self._view(state,vm.vm_id) for vm in p.vms)

    def verify_start_permit(self,native_vm_id,phase,native_config,*,host_boot_id):
        # Input is a normalized packet from the owning root hook (not a client
        # chosen path). No backend calls, shell, SSH or libvirt recursion here.
        require(phase in {'pre-start','prepare-begin','start-begin'},'unsupported','offline start phase required')
        require(type(native_config) is bytes and len(native_config)<=256*1024,'shape','bounded native config required')
        config=strict_json(native_config.decode())
        require(set(config)=={'native_id','maximum_bytes','config_fingerprint'},'shape','actual static config required')
        with self.store.locked(read_only=True):
            state=self.controller._load()
            from host_resource_recovery import check_start_fence
            check_start_fence(self.store,'libvirt',uuid=native_vm_id)
            check_start_fence(self.store,'proxmox',uuid=native_vm_id)
            matches=[vm for vm,row in state['startups'].items() if row['native_id']==native_vm_id]
            require(len(matches)==1,'ownership','native VM is not uniquely enrolled')
            vm_id=matches[0];row=state['startups'][vm_id];grant=self.controller._grant(state,vm_id)
            require(host_boot_id==state['host_boot_id'] and state['policy_sha256']==policy_digest(self.policy)
                and state['blocked'] is None,'reconciliation_required','boot/policy/previous outcome changed')
            require(config['native_id']==native_vm_id and config['maximum_bytes']==self.controller._vm(vm_id).maximum_bytes
                and config['config_fingerprint']==row['static_config_fingerprint'] and
                grant.guest_bytes>=config['maximum_bytes'],'startup_permit','full current start peak is not reserved')
            return self._view(state,vm_id)

    def bind_running_startup(self,native_vm_id,evidence):
        with self.store.locked():
            from host_resource_recovery import check_start_fence
            check_start_fence(self.store,'libvirt',uuid=native_vm_id)
            check_start_fence(self.store,'proxmox',uuid=native_vm_id)
            state=self.controller._load();self.controller._fresh(evidence.observed_at)
            require(state['host_boot_id']==evidence.host_boot_id and
                    state['policy_sha256']==evidence.policy_sha256,'identity_mismatch','startup host changed')
            matches=[b for b in evidence.bindings if type(b) is RuntimeBinding and b.native_id==native_vm_id]
            require(len(matches)==1,'identity_mismatch','one fresh running binding required')
            binding=matches[0];vm_id=binding.vm_id;row=state['startups'][vm_id]
            require(row['native_id']==native_vm_id and row['static_config_fingerprint']==binding.config_fingerprint,
                    'identity_mismatch','startup native/config identity changed')
            actual=self.controller.backend.readback(vm_id)
            require(actual.running and actual.native_id==native_vm_id and actual.process_id==binding.process_id
                    and actual.config_fingerprint==binding.config_fingerprint and
                    actual.assigned_bytes==actual.configured_bytes==self.controller._grant(state,vm_id).guest_bytes,
                    'readback','full startup allocation unconfirmed')
            state['bindings'][vm_id]=asdict(binding);row['phase']='running_quarantined'
            self.store.save(state)  # identity quarantine durable before readiness checks
            # Identity binding is independent of slurmd. Full policy/runtime
            # qualification and idle registration are required before all READY.
            if (all(state['bindings'].values()) and len(evidence.bindings)==len(self.policy.vms)
                    and all(q.slurm_registration_verified is True for q in evidence.qualifications)):
                self.controller._evidence(evidence)
                require(all(q.slurm_registration_verified is True for q in evidence.qualifications),
                        'qualification','startup remains DRAIN/quarantined until registered')
                for startup in state['startups'].values():startup['phase']='binding_ready'
                self.controller._guard(state,evidence)
            self.store.save(state)
            return self._view(state,vm_id)


def _manager():
    from host_resource_service import open_service
    return open_service().startup


def prepare_start_reservations(*,cold_evidence: ColdHostEvidence) -> tuple[StartupReservationView,...]:
    return _manager().prepare_start_reservations(cold_evidence=cold_evidence)


def verify_start_permit(native_vm_id: str,phase: str,native_config: bytes) -> StartupReservationView:
    from pathlib import Path
    from host_resource_backends import read_root_json
    from host_resource_service import CONFIG
    from host_resource_operations import FileReceiptStore,validate_host_resource_policy
    config=read_root_json(CONFIG);runtime=read_root_json(config['runtime'])
    class OfflineBackend:quantum_bytes=1
    manager=StartupManager(validate_host_resource_policy(read_root_json(runtime['policy'])),
        FileReceiptStore.open_existing(runtime['state_directory']),OfflineBackend())
    return manager.verify_start_permit(native_vm_id,phase,native_config,
        host_boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())


def bind_running_startup(native_vm_id: str) -> StartupReservationView:
    service=__import__('host_resource_service').open_service()
    with service.controller.store.operation():
        state=service.controller._load()
        facts=service.provider.binding_facts(native_vm_id,owner_state=state)
        # Identity collection deliberately has no Slurm prerequisite and cannot
        # fabricate an idle/registered whole guest snapshot from empty tuples.
        identity=replace(facts,qualifications=tuple(replace(q,slurm_registration_verified=False)
            for q in facts.qualifications))
        view=service.startup.bind_running_startup(native_vm_id,identity)
        state=service.controller._load()
        if all(state['bindings'].values()):
            try:
                complete=service.provider.request_facts(None,owner_state=state)
                view=service.startup.bind_running_startup(native_vm_id,complete)
            except ResourceError as error:
                view['failure_code']=error.code  # durable quarantine/charge retained
        return view


def normalize_native_config(backend,native_id,raw):
    from host_resource_backends import pve_config_fingerprint,libvirt_config_fingerprint,LibvirtMemoryBackend
    import xml.etree.ElementTree as ET
    require(type(raw) is bytes and len(raw)<=256*1024,'output_bound','bounded native hook config required')
    if backend=='libvirt':
        require(b'<!DOCTYPE' not in raw and b'<!ENTITY' not in raw,'shape','XML entity declaration unsupported')
        xml=ET.fromstring(raw)
        require(xml.findtext('uuid')==native_id,'identity_mismatch','offline native UUID differs')
        maximum=LibvirtMemoryBackend._memory(xml.find('memory'));config_hash=libvirt_config_fingerprint(xml)
    elif backend=='proxmox':
        config={}
        for line in raw.decode().splitlines():
            if not line.strip() or line.lstrip().startswith('#'):continue
            key,sep,value=line.partition(': ')
            require(sep and key not in config and not key.startswith('['),'unsupported','pending/duplicate PVE config is unsupported')
            config[key]=value
        import re
        uuids=re.findall(r'(?:^|,)uuid=([^,]+)(?:,|$)',config.get('smbios1',''))
        require(uuids==[native_id] and config.get('memory','').isdigit(),'identity_mismatch','offline PVE native config differs')
        maximum=int(config['memory'])*1024**2;config_hash=pve_config_fingerprint(config)
    else:require(False,'unsupported','offline backend not supported')
    return json.dumps(dict(native_id=native_id,maximum_bytes=maximum,config_fingerprint=config_hash),sort_keys=True).encode()


def hook_main(argv=None):
    """Offline owned-only PVE/libvirt hook. No native API/guest/service calls."""
    import os,sys
    from host_resource_backends import read_root_json
    from host_resource_service import CONFIG
    require(os.geteuid()==0,'root_required','native hook runs as root')
    args=list(sys.argv[1:] if argv is None else argv);require(bool(args),'shape','native hook arguments required')
    config=read_root_json(CONFIG);runtime=read_root_json(config['runtime']);native=runtime['backend_config']
    backend=args.pop(0);require(backend==native['backend'],'ownership','hook backend mismatch')
    from host_resource_operations import FileReceiptStore
    from host_resource_recovery import check_start_fence
    fence_store=None
    require('state_directory' in runtime or config.get('native_recovery') is None,'trust','recovery requires protected state')
    if 'state_directory' in runtime:
        try:fence_store=FileReceiptStore.open_existing(runtime['state_directory'])
        except FileNotFoundError:pass
    if backend=='libvirt':
        require(len(args)>=3,'shape','libvirt name/operation/suboperation required')
        name,operation,suboperation=args[:3]
        if operation not in {'prepare','start'} or suboperation!='begin':return 0
        if fence_store is not None:
            check_start_fence(fence_store,'libvirt',name=name)
        matches=[v for v in native['vms'].values() if v['name']==name]
        phase=operation+'-begin'
        if not matches and (fence_store is None or not (fence_store.directory/'retired-targets').exists()):return 0
        raw=sys.stdin.buffer.read(256*1024+1)
        import xml.etree.ElementTree as ET
        require(len(raw)<=256*1024 and b'<!DOCTYPE' not in raw and b'<!ENTITY' not in raw,'shape','bounded native hook XML')
        hook_uuid=ET.fromstring(raw).findtext('uuid')
        if fence_store is not None and hook_uuid:check_start_fence(fence_store,'libvirt',uuid=hook_uuid)
        if not matches:return 0  # positive foreign namespace: no native calls
        native_id=matches[0]['native_id']
    else:
        require(len(args)==2 and args[0].isdigit(),'shape','PVE VMID and phase required')
        vmid,phase=args
        if fence_store is not None:check_start_fence(fence_store,'proxmox',vmid=vmid)
        matches=[v for v in native['vms'].values() if str(v['vmid'])==vmid]
        if not matches or phase!='pre-start':return 0
        native_id=matches[0]['native_id']
        from host_resource_backends import trusted_root_path
        import re
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*',native['node']),'trust','enrolled PVE node required')
        path=trusted_root_path(Path('/etc/pve/nodes',native['node'],'qemu-server',vmid+'.conf'))
        with path.open('rb') as stream:raw=stream.read(256*1024+1)
    require(len(matches)==1,'ownership','unique owned native enrollment required')
    verify_start_permit(native_id,phase,normalize_native_config(backend,native_id,raw))
    return 0


def admin_main(argv=None):
    import os,sys
    from host_resource_service import open_service
    require(os.geteuid()==0 and os.environ.get('SUDO_UID','0')=='0','root_required','administrative root only')
    args=list(sys.argv[1:] if argv is None else argv);require(bool(args),'shape','administrative action required')
    if args[0] in {'storage-import','storage-definition','storage-bind'}:
        require(len(args)==2,'action','storage preparation accepts one install UUID only')
        from host_resource_storage import import_storage,storage_definition,bind_storage
        action={'storage-import':import_storage,'storage-definition':storage_definition,'storage-bind':bind_storage}[args[0]]
        result=action(args[1])
        if type(result) is bytes:sys.stdout.buffer.write(result+b'\n')
        else:print(json.dumps(result))
        return 0
    if args[0] in {'retire','recovery-status','reserve-replacement'}:
        from host_resource_recovery import admin_recovery
        print(json.dumps(admin_recovery(args)));return 0
    service=open_service()
    if args==['prepare']:
        with service.controller.store.operation():
            result=service.startup.prepare_start_reservations(cold_evidence=service.provider.cold_facts())
    else:
        require(len(args)==2 and args[0]=='bind','action','prepare or bind native-id only')
        result=bind_running_startup(args[1])
    print(json.dumps(result));return 0
