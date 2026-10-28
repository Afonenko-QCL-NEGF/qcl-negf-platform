"""Cold reservation/lock tests: synthetic files and backend, never start a VM."""
from dataclasses import replace
import json
from pathlib import Path
import os
import sys
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ops'))
from test_host_resource_operations import setup, request


def cold_setup(tmp_path):
    import host_resource_startup as s
    (tmp_path / 'running').mkdir(parents=True)
    m, controller, backend, _, evidence = setup(tmp_path / 'running')
    store = m.FileReceiptStore(tmp_path / 'cold', owner_uid=os.getuid())
    cold = s.ColdHostEvidence(evidence.host_id, evidence.owner_id, evidence.host_boot_id,
        evidence.policy_sha256, 100, 4096, 256, 'synthetic-capacity', 'synthetic-agreement',
        'synthetic-root-enforcement', True, tuple(s.ColdVMRecord(vm.vm_id,
            'native-' + vm.vm_id, 'config-1', vm.maximum_bytes, vm.maximum_bytes, 'stopped')
            for vm in controller.policy.vms))
    # Full maxima 4096 exceed this host's actual owned capacity3584; healthy policy
    # uses two max1536 VMs, matching the conservative example's independent math.
    document = json.loads(json.dumps(__import__('dataclasses').asdict(controller.policy)))
    document['schema']='qcl.host-resource-policy.v1'
    for vm in document['vms']:
        vm['maximum_bytes'] = 1536
    policy = m.validate_host_resource_policy(document)
    cold = replace(cold, policy_sha256=m.policy_digest(policy),
        vms=tuple(replace(vm, configured_max_bytes=1536, initial_peak_bytes=1536) for vm in cold.vms))
    return s, m, s.StartupManager(policy, store, backend, clock=lambda:100), store, cold, evidence


def test_cold_reserves_full_maxima_before_any_guest_and_never_calls_backend(tmp_path):
    s,m,c,store,e,_ = cold_setup(tmp_path)
    results = c.prepare_start_reservations(cold_evidence=e)
    assert [r['charged_bytes'] for r in results] == [1536,1536]
    assert all(r['admission_closed'] and r['phase']=='cold_reserved' for r in results)
    assert c.controller.backend.calls == []
    state=json.loads(store.state_path.read_text())
    assert state['bindings']=={'vm-a':None,'vm-b':None}
    assert c.prepare_start_reservations(cold_evidence=e)==results


@pytest.mark.parametrize('change', ['foreign','running','config','stale','overcommit'])
def test_cold_bad_or_unpaid_inventory_refuses_without_initializing(tmp_path,change):
    s,m,c,store,e,_=cold_setup(tmp_path)
    if change=='foreign':e=replace(e,foreign_max_bytes=0)
    if change=='running':e=replace(e,vms=(replace(e.vms[0],observed_power_state='running'),e.vms[1]))
    if change=='config':e=replace(e,vms=(replace(e.vms[0],configured_max_bytes=999),e.vms[1]))
    if change=='stale':e=replace(e,observed_at=89)
    if change=='overcommit':e=replace(e,physical_ram_bytes=3000)
    with pytest.raises(m.ResourceError):c.prepare_start_reservations(cold_evidence=e)
    assert not store.state_path.exists()
    assert c.controller.backend.calls==[]


def test_offline_permit_requires_actual_config_and_current_boot_not_ack_flags(tmp_path):
    s,m,c,store,e,_=cold_setup(tmp_path)
    c.prepare_start_reservations(cold_evidence=e)
    native=json.dumps({'native_id':'native-vm-a','maximum_bytes':1536,'config_fingerprint':'config-1'}).encode()
    assert c.verify_start_permit('native-vm-a','pre-start',native,host_boot_id='host-boot-1')['charged_bytes']==1536
    for changed in (native.replace(b'1536',b'1537'),native.replace(b'config-1',b'other')):
        with pytest.raises(m.ResourceError):c.verify_start_permit('native-vm-a','pre-start',changed,host_boot_id='host-boot-1')
    with pytest.raises(m.ResourceError):c.verify_start_permit('native-vm-a','pre-start',native,host_boot_id='new-boot')
    assert c.controller.backend.calls==[]


def test_readonly_open_and_nested_owner_lock_have_no_status_writes(tmp_path):
    from host_resource_operations import FileReceiptStore
    path=tmp_path/'absent'
    with pytest.raises(FileNotFoundError):FileReceiptStore.open_existing(path,owner_uid=os.getuid())
    assert not path.exists()
    (tmp_path/'live').mkdir()
    m,c,b,store,e=setup(tmp_path/'live')
    before={p.name:(p.stat().st_mtime_ns,p.read_bytes()) for p in store.directory.iterdir() if p.is_file()}
    read=FileReceiptStore.open_existing(store.directory,owner_uid=os.getuid())
    with read.locked(read_only=True):
        assert read.load()['host_boot_id']=='host-boot-1'
    after={p.name:(p.stat().st_mtime_ns,p.read_bytes()) for p in store.directory.iterdir() if p.is_file()}
    assert before==after
    with store.operation():
        with store.locked():assert c.snapshot()[0].guest_bytes==256


def test_v2_upgrade_refuses_without_touching_old_unknown_state(tmp_path):
    m,c,b,store,e=setup(tmp_path)
    c.request(request(m),e)
    state=json.loads(store.state_path.read_text());state['schema']='qcl.host-resource-state.v2'
    state.pop('startups',None);store.save(state)
    original=store.state_path.read_bytes()
    with pytest.raises(m.ResourceError,match='upgrade_required'):c.snapshot()
    assert store.state_path.read_bytes()==original


def test_postboot_identity_is_durable_quarantine_without_slurmd(tmp_path):
    s,m,c,store,e,running=cold_setup(tmp_path)
    c.prepare_start_reservations(cold_evidence=e)
    evidence=replace(running,policy_sha256=e.policy_sha256,
        qualifications=tuple(replace(q,policy_sha256=e.policy_sha256,
            slurm_registration_verified=False) for q in running.qualifications))
    for name,b in c.controller.backend.rows.items():
        c.controller.backend.rows[name]=replace(b,assigned_bytes=1536,configured_bytes=1536)
    assert c.bind_running_startup('native-vm-a',evidence)['phase']=='running_quarantined'
    assert c.bind_running_startup('native-vm-b',evidence)['phase']=='running_quarantined'
    assert all(v['phase']=='running_quarantined' for v in store.load()['startups'].values())
    with pytest.raises(m.ResourceError,match='startup_binding_required'):
        c.controller.request(request(m),evidence)
    ready=replace(evidence,qualifications=tuple(replace(q,slurm_registration_verified=True)
        for q in evidence.qualifications))
    assert c.bind_running_startup('native-vm-b',ready)['phase']=='binding_ready'


def test_cold_state_cannot_be_forged_with_underpaid_or_partial_binding(tmp_path):
    s,m,c,store,e,_=cold_setup(tmp_path);c.prepare_start_reservations(cold_evidence=e)
    bad=store.load();bad['grants'][0]['guest_bytes']=256;store.save(bad)
    with pytest.raises(m.ResourceError,match='state'):c.controller.snapshot()


def test_offline_pve_and_libvirt_use_same_static_fingerprint_as_readback():
    from host_resource_startup import normalize_native_config
    from host_resource_backends import pve_config_fingerprint,libvirt_config_fingerprint
    import xml.etree.ElementTree as ET
    from test_host_resource_backends import XML,pve_config
    config=pve_config();raw='\n'.join(k+': '+str(v) for k,v in config.items() if k!='digest').encode()
    packet=json.loads(normalize_native_config('proxmox',config['smbios1'].split('=')[1],raw))
    assert packet['config_fingerprint']==pve_config_fingerprint(config)
    packet=json.loads(normalize_native_config('libvirt','11111111-1111-4111-8111-111111111111',XML.encode()))
    assert packet['config_fingerprint']==libvirt_config_fingerprint(ET.fromstring(XML))
    live=XML.replace('<domain type="kvm">','<domain type="kvm" id="7">').replace('<memballoon model="virtio"/>','<memballoon model="virtio"><alias name="balloon0"/></memballoon>')
    assert packet['config_fingerprint']==libvirt_config_fingerprint(ET.fromstring(live))
    for unsafe in (raw+b'\n[pending]\nmemory: 32',raw+b'\nmemory: 32'):
        with pytest.raises(Exception):normalize_native_config('proxmox',config['smbios1'].split('=')[1],unsafe)


def test_offline_hook_source_never_invokes_native_api_or_guest():
    import ast,host_resource_startup as s
    tree=ast.parse(Path(s.__file__).read_text())
    hook=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='hook_main')
    calls={ast.unparse(n.func) for n in ast.walk(hook) if isinstance(n,ast.Call)}
    assert not any(any(word in call for word in ('virsh','ssh','run','systemctl','request_facts')) for call in calls)


def test_owned_pve_hook_uses_canonical_enrolled_file_and_offline_permit_only(tmp_path,monkeypatch):
    import host_resource_startup as s
    import host_resource_backends as b
    from test_host_resource_backends import pve_config
    config=pve_config();raw='\n'.join(k+': '+str(v) for k,v in config.items() if k!='digest')
    source=tmp_path/'101.conf';source.write_text(raw)
    native={'backend':'proxmox','node':'synthetic-node','vms':{'vm-a':{'vmid':101,'native_id':'11111111-1111-4111-8111-111111111111'}}}
    monkeypatch.setattr(os,'geteuid',lambda:0)
    monkeypatch.setattr(b,'read_root_json',lambda path:{'runtime':'runtime'} if str(path)!='runtime' else {'backend_config':native})
    seen=[]
    def trusted(path,**kw):
        assert str(path)=='/etc/pve/nodes/synthetic-node/qemu-server/101.conf';return source
    monkeypatch.setattr(b,'trusted_root_path',trusted)
    monkeypatch.setattr(s,'verify_start_permit',lambda *args:seen.append(args))
    assert s.hook_main(['proxmox','101','pre-start'])==0
    assert seen[0][:2]==('11111111-1111-4111-8111-111111111111','pre-start')
    assert json.loads(seen[0][2])['maximum_bytes']==4096*1024**2
    assert s.hook_main(['proxmox','999','pre-start'])==0 and len(seen)==1


@pytest.mark.parametrize('complete_snapshot',[False,True])
def test_public_bind_cannot_open_admission_from_identity_only_empty_workloads(tmp_path,monkeypatch,complete_snapshot):
    import host_resource_service as service_module
    from types import SimpleNamespace
    s,m,c,store,cold,e=cold_setup(tmp_path);c.prepare_start_reservations(cold_evidence=cold)
    e=replace(e,policy_sha256=cold.policy_sha256,
        qualifications=tuple(replace(q,policy_sha256=cold.policy_sha256) for q in e.qualifications))
    for vm,row in c.controller.backend.rows.items():
        c.controller.backend.rows[vm]=replace(row,assigned_bytes=1536,configured_bytes=1536)
    c.bind_running_startup('native-vm-a',replace(e,qualifications=tuple(replace(q,slurm_registration_verified=False) for q in e.qualifications)))
    class Provider:
        calls=[]
        def binding_facts(self,*a,**kw):self.calls.append('identity');return e
        def request_facts(self,*a,**kw):
            self.calls.append('complete')
            if complete_snapshot:return e
            raise m.ResourceError('incomplete_workloads','unexpected native child')
    provider=Provider();service=SimpleNamespace(controller=c.controller,startup=c,provider=provider)
    monkeypatch.setattr(service_module,'open_service',lambda:service)
    view=s.bind_running_startup('native-vm-b')
    assert provider.calls==['identity','complete']
    if complete_snapshot:
        assert view['phase']=='binding_ready' and not view['admission_closed']
    else:
        assert view['phase']=='running_quarantined' and view['admission_closed']
        assert view['failure_code']=='incomplete_workloads'
    assert all(v['phase']==view['phase'] for v in store.load()['startups'].values())
