"""Synthetic source/owner/native protocol packets. No real native command or probe."""
from dataclasses import asdict, replace
import copy
import json
import os
from pathlib import Path
import sys

import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops'))
from test_host_resource_operations import setup, request, guest, completion


def test_production_exception_local_group_cleanup_is_not_server_cleanup(tmp_path):
    m,c,b,store,e=setup(tmp_path)
    b.requires_native_cleanup_proof=True
    c.request(request(m),e);b.fault='timeout-after-change'
    result=c.grow('request-1',e)
    assert result.phase=='GROW_UNKNOWN'
    row=store.load()['receipts'][0]
    assert row['native_cleanup_confirmed'] is False and store.load()['blocked'] is not None
    with pytest.raises(m.ResourceError,match='reconciliation_required'):
        c.reconcile('request-1',e)
    assert len(b.calls)==1 and c.snapshot()[0].guest_bytes==512


def profile(m,c,e,vm='vm-a',protocol='pve-local-put-balloon-v1'):
    binding=next(b for b in e.bindings if b.vm_id==vm)
    source=dict(path='/protected/tool',sha256='a'*64)
    ids={**{key:dict(source) for key in ('cli','client','driver','protocol')},'support':{name:dict(path=('/usr/share/perl5/PVE/' if protocol.startswith('pve-') else '/protected/sources/')+name,sha256=digest) for name,digest in __import__('host_resource_native_cleanup').PROTOCOL_SOURCE_DIGESTS[protocol].items()}}
    if protocol.startswith('pve-'):
        for key,name in [('client','QMPClient.pm'),('driver','QemuServer.pm'),('protocol','API2/Qemu.pm')]:ids[key]=dict(ids['support'][name])
    return dict(schema='qcl.host-resource-native-mutation-qualification.v1',protocol_id=protocol,
        host_id=c.policy.host_id,owner_id=c.policy.owner_id,host_boot_id=e.host_boot_id,
        policy_sha256=m.policy_digest(c.policy),binding=asdict(binding),
        source_ids=ids,
        native_peer_identity=dict(kind='pve_local',node='synthetic-node',qemu_birth=dict(pid=77,start_ticks=10,boot_id=e.host_boot_id)),
        evidence_ref='synthetic-source-qualified-protocol')


def test_profile_bundle_is_per_vm_strict_and_current(tmp_path):
    import host_resource_native_cleanup as n
    m,c,b,store,e=setup(tmp_path)
    profiles=[profile(m,c,e,vm) for vm in ('vm-a','vm-b')]
    bundle=dict(schema='qcl.host-resource-native-mutation-qualifications.v1',profiles=profiles)
    assert len(n.decode_qualifications(bundle))==2
    for changed in ({**bundle,'extra':True},{**bundle,'profiles':[]},{**bundle,'profiles':[profiles[0],profiles[0]]},
                    {**bundle,'profiles':[{**profiles[0],'qualified':True}]}):
        with pytest.raises(m.ResourceError):n.decode_qualifications(changed)


def fixture(tmp_path,*,protocol='pve-local-put-balloon-v1'):
    import host_resource_native_cleanup as n
    m,c,b,store,e=setup(tmp_path)
    profiles=[profile(m,c,e,vm,protocol) for vm in ('vm-a','vm-b')]
    if protocol.startswith('libvirt-'):
        for p in profiles:p['native_peer_identity']=dict(kind='libvirt_unix',socket_path='/run/libvirt/libvirt-sock',socket_device=1,socket_inode=9,unit='libvirtd.service',invocation_id='c'*32,daemon_birth=dict(pid=77,start_ticks=10,boot_id=e.host_boot_id))
    config=dict(schema=n.CONFIG_SCHEMA,helper='/protected/native-exec',qualification='/protected/qualifications',protocol_id=protocol)
    b.tool='/protected/tool';b.mutation_argv=lambda vm,target,before:(b.tool,'set',vm,str(target),before.revision)
    original=b.resize
    class Sources:
        clean=True;lock=True;changed_source=False;changed_peer=False;calls=[]
        def clock(self):return 100
        def trusted(self,path,**kw):return Path(path)
        def root_json(self,path):assert path==config['qualification'];return copy.deepcopy(dict(schema=n.BUNDLE_SCHEMA,profiles=profiles))
        def file_digest(self,path):
            if self.changed_source:return '0'*64
            for p in profiles:
                for ref in [p['source_ids'][k] for k in ('cli','client','driver','protocol')]+list(p['source_ids']['support'].values()):
                    if ref['path']==path:return ref['sha256']
            pytest.fail('unexpected source path '+path)
        def peer(self,p,backend):return {**p['native_peer_identity'],'node':'other'} if self.changed_peer else copy.deepcopy(p['native_peer_identity'])
        def context(self,row):return dict(unit='qcl-resource-'+'1'*32+'.service',invocation_id='2'*32,cgroup='/system.slice/qcl-resource-'+'1'*32+'.service',host_boot_id=e.host_boot_id,mutation_id=row['mutation_id'])
        def worker(self,context):return dict(pid=101,start_ticks=1,boot_id=e.host_boot_id)
        def claim_process(self,context):return (dict(pid=101,start_ticks=1,boot_id=e.host_boot_id),dict(pid=102,start_ticks=2,boot_id=e.host_boot_id))
        def preflight(self,*args):self.calls.append('preflight')
        def absent(self,witness):return self.clean
        def lock_released(self,*args):return self.lock
    sources=Sources()
    class Runner:
        calls=[];fault=None;error=None
        def run(self,argv,**kw):
            self.calls.append(tuple(argv))
            assert next(row for row in store.load()['receipts'] if row['mutation_id']==argv[1])['native_cleanup_confirmed'] is False
            if self.fault=='no-claim':return 'null'
            args=proofs.claim(argv[1]);assert args[0]==b.tool
            row=next(r for r in store.load()['receipts'] if r['mutation_id']==argv[1])
            vm=row['request']['vm_id'];original(vm,row['target_bytes'],b.rows[vm],30)
            if self.fault=='crash':raise SystemExit(77)
            if self.fault=='timeout':
                self.error=m.ResourceError('native_timeout','synthetic server reply lost')
                self.error.native_record=dict(failure='timeout',cleanup_confirmed=True,stdout='original',stderr='',output_bytes=8,output_truncated=False,child_started=True,returncode=-9,elapsed_seconds=1)
                self.error.native_output='original';self.error.native_argv=tuple(argv)
                raise self.error
            return 'native successful return'
    runner=Runner();proofs=n.NativeMutationProofs(c.policy,store,b,config,runner,sources=sources)
    wrapped=n.QualifiedMutationBackend(b,proofs);c.backend=wrapped
    return n,m,c,b,store,e,proofs,sources,runner,profiles


@pytest.mark.parametrize('protocol',['pve-local-put-balloon-v1','libvirt-local-setmem-v1'])
def test_healthy_terminal_witness_admits_and_lost_outer_reply_reconciles(tmp_path,protocol):
    n,m,c,b,store,e,p,s,r,profiles=fixture(tmp_path,protocol=protocol)
    c.request(request(m),e);assert c.grow('request-1',e).phase=='GUEST_ADMIT'
    state=store.load();row=state['receipts'][0];w=p.read(row['mutation_id'])
    assert w['phase']=='RETURNED_SUCCESS' and w['intent']['binding']==asdict(e.bindings[0])
    assert w['cli_birth']['pid']==102 and w['worker_birth']['pid']==101
    assert len(r.calls)==len(b.calls)==1
    proof=p.cleanup('request-1',owner_state=state,evidence=e);assert proof.mutation_id==row['mutation_id']
    p.validate_state(state,evidence=e)
    c.admit('request-1',guest(m),e);e.live_workloads['vm-a']=('work-1',)
    p.validate_state(store.load(),evidence=e)
    # A new proof reader/owner invocation reuses durable proof, never native replay.
    reload=n.NativeMutationProofs(c.policy,store,b,p.config,r,sources=s)
    assert reload.cleanup('request-1',owner_state=store.load(),evidence=e)==proof
    c.reconcile('request-1',e);assert len(r.calls)==1


@pytest.mark.parametrize('fault',['timeout','crash','no-claim','live-descendant','lock-busy','terminal-io'])
def test_unknown_never_clears_from_ram_or_local_cleanup_and_never_replays(tmp_path,monkeypatch,fault):
    n,m,c,b,store,e,p,s,r,profiles=fixture(tmp_path);c.request(request(m),e)
    if fault in {'timeout','crash','no-claim'}:r.fault=fault
    if fault=='live-descendant':s.clean=False
    if fault=='lock-busy':s.lock=False
    if fault=='terminal-io':
        original=store._atomic
        def fail(path,data):
            if Path(path).parent.name=='native-mutations':raise OSError('synthetic terminal fsync lost')
            return original(path,data)
        monkeypatch.setattr(store,'_atomic',fail)
    if fault=='crash':
        with pytest.raises(SystemExit):c.grow('request-1',e)
    else:assert c.grow('request-1',e).phase=='GROW_UNKNOWN'
    state=store.load();row=state['receipts'][0]
    assert row['native_cleanup_confirmed'] is False and row['target_bytes']==512
    assert c.snapshot()[0].guest_bytes==512
    assert p.cleanup('request-1',owner_state=state,evidence=e) is None
    calls=list(r.calls)
    with pytest.raises(m.ResourceError):c.reconcile('request-1',e)
    assert r.calls==calls
    if fault=='timeout':assert r.error.native_record['cleanup_confirmed'] is True and r.error.native_record['stdout']=='original'


@pytest.mark.parametrize('change',['source','peer','hostboot','policy','binding','target','context','operation','old-bytes','proof-uuid','partial'])
def test_exact_latest_witness_identity_required(tmp_path,change):
    n,m,c,b,store,e,p,s,r,profiles=fixture(tmp_path);c.request(request(m),e);c.grow('request-1',e)
    state=store.load();row=state['receipts'][0];path=p.path(row['mutation_id']);w=json.loads(path.read_text())
    if change=='source':s.changed_source=True
    if change=='peer':s.changed_peer=True
    if change=='hostboot':e=replace(e,host_boot_id='new-boot')
    if change=='policy':e=replace(e,policy_sha256='0'*64)
    if change=='binding':e=replace(e,bindings=(replace(e.bindings[0],guest_boot_id='new'),e.bindings[1]))
    if change=='target':w['intent']['target_bytes']+=64
    if change=='context':w['intent']['native_context']['invocation_id']='3'*32
    if change=='operation':w['intent']['operation']='shrink'
    if change=='old-bytes':w['intent']['old_bytes']+=64
    if change=='proof-uuid':w['intent']['mutation_id']='9'*32;w['intent']['native_context']['mutation_id']='9'*32
    if change=='partial':w['phase']='CLAIMED';w.update(terminal_at=None,local_cleanup_confirmed=False,result_sha256=None)
    w['intent_sha256']=n.fingerprint(w['intent']);path.write_text(json.dumps(w))
    assert p.cleanup('request-1',owner_state=state,evidence=e) is None
    assert len(r.calls)==1


def test_legacy_local_cleanup_true_without_native_proof_not_adopted(tmp_path):
    n,m,c,b,store,e,p,s,r,profiles=fixture(tmp_path);c.request(request(m),e);r.fault='timeout';c.grow('request-1',e)
    state=store.load();state['blocked']=None;state['receipts'][0]['native_cleanup_confirmed']=True;store.save(state)
    with pytest.raises(m.ResourceError):p.validate_state(state,evidence=e)
    assert c.snapshot()[0].guest_bytes==512


def test_noop_does_not_create_native_claim_or_dispatch(tmp_path):
    n,m,c,b,store,e,p,s,r,profiles=fixture(tmp_path);c.request(request(m,amount=1),e)
    assert c.grow('request-1',e).phase=='GUEST_ADMIT'
    assert store.load()['receipts'][0]['mutation_id'] is None and not p.directory.exists() and not r.calls


def test_pve_local_only_and_pure_native_argv_preserve_default_constructor():
    from host_resource_backends import ProxmoxMemoryBackend,ProxmoxVM
    backend=ProxmoxMemoryBackend(None,'/usr/bin/pvesh','synthetic-node',{'vm-a':ProxmoxVM(101,'uuid')},dynamic=True,local_only=True)
    m=__import__('host_resource_operations');before=m.VMReadback('vm-a','uuid','77','config','revision',1024**2,1024**2,True)
    assert backend.mutation_argv('vm-a',2*1024**2,before)==('/usr/bin/pvesh','--noproxy','set','/nodes/synthetic-node/qemu/101/config','--balloon','2','--digest','revision','--output-format','json')
    legacy=ProxmoxMemoryBackend(None,'/usr/bin/pvesh','synthetic-node',{},dynamic=True)
    assert not legacy.local_only


def test_factory_assembles_dynamic_proofs_without_changing_fixed_prerequisites(tmp_path,monkeypatch):
    import host_resource_service as service
    import host_resource_native_cleanup as n
    from types import SimpleNamespace
    from host_resource_backends import ProxmoxMemoryBackend,ProxmoxVM
    m,c,b,store,e=setup(tmp_path)
    base=ProxmoxMemoryBackend(None,'/protected/tool','synthetic-node',{'vm-a':ProxmoxVM(101,'native-vm-a')},dynamic=True)
    cfg=dict(schema='qcl.host-resource-service.v1',role='native_host',client_uid=3000,runtime='runtime',tools=[],systemctl='/protected/systemctl',
        facts={'readback_version':'qcl.native-memory.balloon.v1'},native_cleanup=dict(schema=n.CONFIG_SCHEMA,helper='/protected/native-exec',qualification='/protected/profiles',protocol_id='pve-local-put-balloon-v1'))
    boundary=SimpleNamespace(config={'backend_config':{'backend':'proxmox','tool':'/protected/tool'},'evidence':'probe','qualification':'qual'},open_owner=lambda:(c.policy,store,base))
    monkeypatch.setattr(service.os,'geteuid',lambda:0)
    monkeypatch.setattr(service,'read_root_json',lambda path:cfg)
    monkeypatch.setattr(service,'RootNativeBoundary',lambda path:boundary)
    class Sources:
        def __init__(self,*a):pass
        def trusted(self,*a,**k):return Path('/protected/native-exec')
        def root_json(self,path):return dict(schema=n.BUNDLE_SCHEMA,profiles=[profile(m,c,e)])
    monkeypatch.setattr(n,'NativeCleanupSources',Sources)
    monkeypatch.setattr(service,'NativeCommandRunner',lambda tools:SimpleNamespace(tools=tools))
    monkeypatch.setattr(service,'NativeFactsProvider',lambda *a:SimpleNamespace())
    opened=service.open_service()
    assert isinstance(opened.controller.backend,n.QualifiedMutationBackend)
    assert opened.provider.native_proofs is opened.controller.backend.proofs and base.local_only


def test_provider_cleanup_delegates_only_after_actual_host_evidence_capture(tmp_path):
    from host_resource_facts import NativeFactsProvider
    n,m,c,b,store,e,p,s,r,profiles=fixture(tmp_path)
    provider=NativeFactsProvider.__new__(NativeFactsProvider);provider.native_proofs=p;provider.last=None
    with pytest.raises(m.ResourceError):provider.cleanup('request-1',owner_state=store.load())
    c.request(request(m),e);c.grow('request-1',e);provider.last=(e,{})
    assert provider.cleanup('request-1',owner_state=store.load()).mutation_id==store.load()['receipts'][0]['mutation_id']


@pytest.mark.parametrize('change',['healthy','pending','delete','bool-delete','unknown-field','duplicate-key','cloudinit','digest','shares-bool','balloon-bool'])
def test_actual_pve_preflight_closed_packet_protocol(change):
    import host_resource_native_cleanup as n
    from types import SimpleNamespace
    rows=[dict(key='memory',value='4096')]
    cfg=dict(digest='revision',memory=4096,balloon=512,shares=0)
    if change=='pending':rows[0]['pending']='9000'
    if change=='delete':rows[0]['delete']=1
    if change=='bool-delete':rows[0]['delete']=False
    if change=='unknown-field':rows[0]['unknown']=True
    if change=='duplicate-key':rows.append(dict(rows[0]))
    if change=='cloudinit':cfg['hotplug']='network,disk,cloudinit'
    if change=='digest':cfg['digest']='changed'
    if change=='shares-bool':cfg['shares']=False
    if change=='balloon-bool':cfg['balloon']=True
    packets=[json.dumps(rows),json.dumps(cfg)]
    backend=SimpleNamespace(_run=lambda args:packets.pop(0),_path=lambda vm:'/nodes/synthetic/qemu/101')
    source=n.NativeCleanupSources.__new__(n.NativeCleanupSources)
    if change=='healthy':source.preflight({'protocol_id':'pve-local-put-balloon-v1'},backend,'vm-a',SimpleNamespace(revision='revision'))
    else:
        with pytest.raises(n.ResourceError):source.preflight({'protocol_id':'pve-local-put-balloon-v1'},backend,'vm-a',SimpleNamespace(revision='revision'))


@pytest.mark.parametrize('change',['source-path','copied-source','missing-vm','wrong-binding','profile-boot','extra-profile-field'])
def test_profile_facts_not_private_true_flag(tmp_path,change):
    n,m,c,b,store,e,p,s,r,profiles=fixture(tmp_path)
    if change=='source-path':profiles[0]['source_ids']['cli']['path']='/other/cli'
    if change=='copied-source':profiles[0]['source_ids']['support']['QMPClient.pm']['path']='/protected/copied-source'
    if change=='missing-vm':profiles.pop(0)
    if change=='wrong-binding':profiles[0]['binding']['guest_boot_id']='changed'
    if change=='profile-boot':profiles[0]['host_boot_id']='new'
    if change=='extra-profile-field':profiles[0]['qualified']=True
    c.request(request(m),e);receipt=c.grow('request-1',e)
    assert receipt.phase=='GROW_UNKNOWN' and store.load()['receipts'][0]['native_cleanup_confirmed'] is False
    assert not r.calls and not b.calls and c.snapshot()[0].guest_bytes==512


def test_original_cas_revision_cannot_be_replaced_by_helper_reread(tmp_path):
    n,m,c,b,store,e,p,s,r,profiles=fixture(tmp_path);c.request(request(m),e)
    original=r.run
    def changed(argv,**kw):
        b.rows['vm-a']=replace(b.rows['vm-a'],revision='foreign-revision')
        return original(argv,**kw)
    r.run=changed
    assert c.grow('request-1',e).phase=='GROW_UNKNOWN'
    row=store.load()['receipts'][0];assert p.dispatch(row['mutation_id'])['intent']['before_revision']=='revision-1'
    assert not b.calls and not row['native_cleanup_confirmed']


@pytest.mark.parametrize('where',['intent','claim','state-after-native','log-after-native'])
def test_journal_io_prevents_dispatch_or_preserves_original_native_error(tmp_path,monkeypatch,where):
    n,m,c,b,store,e,p,s,r,profiles=fixture(tmp_path);c.request(request(m),e)
    if where in {'intent','claim'}:
        original=p.exclusive
        def failed(path,doc):
            if (where=='intent')==str(path).endswith('.intent.json'):raise OSError('synthetic proof IO')
            return original(path,doc)
        monkeypatch.setattr(p,'exclusive',failed)
        assert c.grow('request-1',e).phase=='GROW_UNKNOWN'
        assert not b.calls and len(r.calls)==(1 if where=='claim' else 0)
    elif where=='state-after-native':
        r.fault='timeout';original=store._atomic
        def failed(path,data):
            if Path(path)==store.state_path and r.error is not None:raise OSError('synthetic blocked-state save IO')
            return original(path,data)
        monkeypatch.setattr(store,'_atomic',failed)
        with pytest.raises(m.ResourceError) as caught:c.grow('request-1',e)
        assert caught.value is r.error and caught.value.native_record['stdout']=='original'
        assert isinstance(caught.value.native_journal_exception,OSError)
    else:
        r.fault='timeout'
        def failed(*a):raise OSError('synthetic failure log IO')
        monkeypatch.setattr(store,'save_failure',failed)
        with pytest.raises(m.ResourceError) as caught:c.grow('request-1',e)
        assert caught.value is r.error and caught.value.native_record['stdout']=='original'
        assert isinstance(caught.value.native_log_exception,OSError)
    assert c.snapshot()[0].guest_bytes==512
    assert store.load()['receipts'][0]['native_cleanup_confirmed'] is False
    with pytest.raises(m.ResourceError):c.reconcile('request-1',e)


def test_claim_never_replays_and_older_grow_proof_cannot_clear_shrink(tmp_path):
    n,m,c,b,store,e,p,s,r,profiles=fixture(tmp_path);c.request(request(m),e);c.grow('request-1',e)
    grow=store.load()['receipts'][0]['mutation_id'];c.admit('request-1',guest(m),e)
    c.finish('request-1',completion(m),e);r.fault='timeout';c.shrink('request-1',e)
    state=store.load();row=state['receipts'][0]
    assert row['mutation_id']!=grow and row['phase']=='SHRINK_UNKNOWN' and c.snapshot()[0].guest_bytes==512
    # Root-owned old grow witness copied to newer slot must never count as proof.
    p.path(row['mutation_id']).write_bytes(p.path(grow).read_bytes())
    assert p.cleanup('request-1',owner_state=state,evidence=e) is None
    with pytest.raises(Exception):p.claim(row['mutation_id'])
    assert len(r.calls)==2


def test_preexec_uses_real_parent_birth_credentials_cgroup_not_environment(monkeypatch):
    import host_resource_native_cleanup as n
    from types import SimpleNamespace
    context=dict(unit='qcl-resource-'+'1'*32+'.service',invocation_id='2'*32,cgroup='/system.slice/qcl-resource-'+'1'*32+'.service',host_boot_id='boot',mutation_id='3'*32)
    source=n.NativeCleanupSources.__new__(n.NativeCleanupSources)
    worker=dict(pid=101,start_ticks=1,boot_id='boot')
    source.worker=lambda value:worker
    monkeypatch.setattr(n.os,'getpid',lambda:102)
    row=dict(pid=102,ppid=101,uids=[0]*4,start_ticks=2,cgroup=context['cgroup'])
    source.local=SimpleNamespace(process=lambda pid:dict(row),host=lambda:{'boot_id':'boot'})
    assert source.claim_process(context)==(worker,dict(pid=102,start_ticks=2,boot_id='boot'))
    for key,value in [('uids',[3000]*4),('ppid',100),('cgroup','/fake')]:
        old=row[key];row[key]=value
        with pytest.raises(n.ResourceError):source.claim_process(context)
        row[key]=old


def test_readonly_status_does_not_open_probe_or_witness(tmp_path,monkeypatch):
    from host_resource_service import NativeResourceService
    n,m,c,b,store,e,p,s,r,profiles=fixture(tmp_path)
    c.request(request(m),e);c.grow('request-1',e)
    monkeypatch.setattr(p,'read',lambda *a:pytest.fail('readonly opened native witness'))
    from host_resource_client import NativeWorkloadRef
    view=NativeResourceService(c,None).read_native_status(NativeWorkloadRef('slurm_allocation','42'))
    assert view['admission']!='ready' and view['native_freshness']['status']=='not_measured'


def test_source_package_installs_only_root_native_exec_no_client_right():
    root=Path(__file__).resolve().parents[1]
    nix=(root/'nix/host-resources.nix').read_text();play=(root/'ansible/host-resources.yml').read_text()
    template=(root/'ansible/templates/host-resources/helper.j2').read_text()
    assert 'ops/host_resource_native_cleanup.py' in nix and 'qcl-negf-resource-native-exec' in nix
    assert 'host_resource_native_cleanup' in play and 'native-exec' in template and 'native_exec_main' in template
    sudo=(root/'ansible/templates/host-resources/sudoers.j2').read_text()
    assert 'native-exec' not in sudo
    import ast,host_resource_native_cleanup as n
    tree=ast.parse(Path(n.__file__).read_text())
    entry=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=='native_exec_main')
    calls={ast.unparse(x.func) for x in ast.walk(entry) if isinstance(x,ast.Call)}
    assert 'os.execve' in calls and not any(any(word in call for word in ('Popen','fork','kill','sleep')) for call in calls)


def test_terminal_witness_survives_crash_before_controller_metadata_save(tmp_path,monkeypatch):
    n,m,c,b,store,e,p,s,r,profiles=fixture(tmp_path);c.request(request(m),e)
    original=store._atomic
    def lost(path,data):
        if Path(path)==store.state_path and json.loads(data)['receipts'][0]['phase']=='GUEST_ADMIT':raise OSError('synthetic metadata publication lost')
        return original(path,data)
    monkeypatch.setattr(store,'_atomic',lost)
    with pytest.raises(OSError):c.grow('request-1',e)
    state=store.load();row=state['receipts'][0]
    assert row['phase']=='GROW_UNKNOWN' and not row['native_cleanup_confirmed'] and c.snapshot()[0].guest_bytes==512
    proof=p.cleanup('request-1',owner_state=state,evidence=e);assert proof is not None
    monkeypatch.setattr(store,'_atomic',original)
    assert c.reconcile('request-1',e,cleanup_evidence=proof).phase=='GUEST_ADMIT'
    assert len(r.calls)==1


@pytest.mark.parametrize('change',['extra','bad-source-sha','missing-support','unreviewed-support','bool-birth','duplicate-vm','wrong-protocol-kind','null-peer'])
def test_strict_qualification_structure_and_pinned_source_set(tmp_path,change):
    import host_resource_native_cleanup as n
    m,c,b,store,e=setup(tmp_path);p=profile(m,c,e)
    bundle=dict(schema=n.BUNDLE_SCHEMA,profiles=[p])
    if change=='extra':p['native_peer_identity']['complete']=True
    if change=='bad-source-sha':p['source_ids']['client']['sha256']='no'
    if change=='missing-support':p['source_ids']['support'].pop(next(iter(p['source_ids']['support'])))
    if change=='unreviewed-support':next(iter(p['source_ids']['support'].values()))['sha256']='0'*64
    if change=='bool-birth':p['native_peer_identity']['qemu_birth']['pid']=True
    if change=='duplicate-vm':bundle['profiles'].append(copy.deepcopy(p))
    if change=='wrong-protocol-kind':p['protocol_id']='libvirt-local-setmem-v1'
    if change=='null-peer':p['native_peer_identity']=None
    with pytest.raises(m.ResourceError):n.decode_qualifications(bundle)


def test_hardlink_and_symlink_private_proof_never_qualify(tmp_path):
    n,m,c,b,store,e,p,s,r,profiles=fixture(tmp_path);c.request(request(m),e);c.grow('request-1',e)
    state=store.load();path=p.path(state['receipts'][0]['mutation_id']);raw=path.read_bytes()
    link=p.directory/'hardlink';os.link(path,link)
    assert p.cleanup('request-1',owner_state=state,evidence=e) is None
    link.unlink();path.unlink();target=p.directory/'other';target.write_bytes(raw);path.symlink_to(target)
    assert p.cleanup('request-1',owner_state=state,evidence=e) is None


def test_native_exec_never_accepts_client_argv_paths_or_uid(tmp_path,monkeypatch):
    import host_resource_native_cleanup as n
    monkeypatch.setattr(n.os,'geteuid',lambda:0)
    for payload in ([],['/tmp/x'],['1'*32,'extra']):
        with pytest.raises(n.ResourceError):n.native_exec_main(payload)
    monkeypatch.setattr(n.os,'geteuid',lambda:3000)
    with pytest.raises(n.ResourceError,match='root_required'):n.native_exec_main(['1'*32])


@pytest.mark.parametrize('change',['unit-list','native-argv-type','witness-source-extra','witness-source-missing'])
def test_malformed_private_packets_fail_with_typed_error(tmp_path,monkeypatch,change):
    n,m,c,b,store,e,p,s,r,profiles=fixture(tmp_path,protocol='libvirt-local-setmem-v1')
    if change=='unit-list':
        profiles[0]['native_peer_identity']['unit']=[]
        with pytest.raises(m.ResourceError):n.decode_qualifications(dict(schema=n.BUNDLE_SCHEMA,profiles=profiles))
    elif change=='native-argv-type':
        monkeypatch.setattr(n.os,'geteuid',lambda:0)
        with pytest.raises(m.ResourceError):n.native_exec_main([42])
    else:
        c.request(request(m),e);c.grow('request-1',e);w=p.read(store.load()['receipts'][0]['mutation_id'])
        if change=='witness-source-extra':w['source_ids']['extra']=True
        else:w['source_ids'].pop('client')
        with pytest.raises(m.ResourceError):n.decode_witness(w)


def test_actual_worker_birth_requires_root_and_native_cgroup():
    import host_resource_native_cleanup as n
    from types import SimpleNamespace
    context=dict(unit='qcl-resource-'+'1'*32+'.service',invocation_id='2'*32,cgroup='/system.slice/qcl-resource-'+'1'*32+'.service')
    source=n.NativeCleanupSources.__new__(n.NativeCleanupSources)
    source.unit=lambda unit:dict(LoadState='loaded',ActiveState='active',MainPID='101',InvocationID=context['invocation_id'],ControlGroup=context['cgroup'])
    row=dict(pid=101,uids=[0]*4,start_ticks=1,cgroup=context['cgroup'])
    source.local=SimpleNamespace(process=lambda pid:dict(row),host=lambda:{'boot_id':'boot'})
    assert source.worker(context)==dict(pid=101,start_ticks=1,boot_id='boot')
    for key,value in [('uids',[3000]*4),('cgroup','/other')]:
        old=row[key];row[key]=value
        with pytest.raises(n.ResourceError):source.worker(context)
        row[key]=old


def test_published_synthetic_witness_schema_and_private_bundle():
    import host_resource_native_cleanup as n
    import jsonschema
    root=Path(__file__).resolve().parents[1]
    schema=json.loads((root/'schemas/host-resource-native-cleanup-witness.schema.json').read_text())
    packet=json.loads((root/'tests/fixtures/host-resources/synthetic-native-cleanup.json').read_text())
    validator=jsonschema.Draft202012Validator(schema);validator.check_schema(schema)
    assert packet['synthetic'] is True and len(packet['cases'])==2
    for case in packet['cases']:
        for key in ('returned_success','claimed_unknown'):
            validator.validate(case[key]);n.decode_witness(case[key])
            changed=copy.deepcopy(case[key]);changed['source_ids']['client']['sha256']='malformed'
            assert list(validator.iter_errors(changed))
            with pytest.raises(n.ResourceError):n.decode_witness(changed)
        for key,definition in [('qualification_bundle','qualificationBundle'),('config','config'),('dispatch','dispatch')]:
            jsonschema.Draft202012Validator({'$ref':'#/$defs/'+definition,'$defs':schema['$defs']}).validate(case[key])
        assert n.decode_qualifications(case['qualification_bundle'])
        n.decode_config(case['config'])
        unknown=copy.deepcopy(case['claimed_unknown']);unknown['local_cleanup_confirmed']=True
        assert list(validator.iter_errors(unknown))


def test_completed_sync_call_does_not_replace_actual_balloon_readback(tmp_path):
    n,m,c,b,store,e,p,s,r,profiles=fixture(tmp_path);c.request(request(m),e);b.fault='readback-old'
    assert c.grow('request-1',e).phase=='GROW_UNKNOWN'
    state=store.load();row=state['receipts'][0]
    assert row['native_cleanup_confirmed'] and c.snapshot()[0].guest_bytes==512
    assert p.read(row['mutation_id'])['phase']=='RETURNED_SUCCESS'
    p.validate_state(state,evidence=e)
    assert c.reconcile('request-1',e).phase=='GROW_UNKNOWN'
    with pytest.raises(m.ResourceError):c.admit('request-1',guest(m),e)
    b.rows['vm-a']=replace(b.rows['vm-a'],configured_bytes=512,assigned_bytes=512)
    assert c.reconcile('request-1',e).phase=='GUEST_ADMIT'
    assert len(r.calls)==1


def test_two_workloads_keep_aggregate_floor_and_latest_individual_proofs(tmp_path):
    n,m,c,b,store,e,p,s,r,profiles=fixture(tmp_path)
    c.request(request(m),e);c.grow('request-1',e);c.admit('request-1',guest(m),e)
    e.live_workloads['vm-a']=('work-1',)
    second=request(m,'request-2',amount=129,workload='work-2')
    c.request(second,e);c.grow('request-2',e)
    c.admit('request-2',replace(guest(m),workload_id='work-2',task_limit_bytes=129,total_bytes=640,live_workload_ids=('work-1',)),e)
    e.live_workloads['vm-a']=('work-1','work-2')
    state=store.load();p.validate_state(state,evidence=e)
    assert len({row['mutation_id'] for row in state['receipts']})==2 and len(r.calls)==2
    first_done=replace(completion(m),live_workload_ids=('work-2',))
    e.live_workloads['vm-a']=('work-2',)
    assert c.finish('request-1',first_done,e).phase=='RELEASE'
    e.live_workloads['vm-a']=('work-2',)
    state=store.load();p.validate_state(state,evidence=e)
    grant=c.snapshot()[0]
    assert grant.active_floor_bytes==128+129 and grant.guest_bytes>=grant.active_floor_bytes
    assert len(r.calls)==2  # finishing one workload cannot shrink another's grant


def test_explicit_libvirt_socket_route_is_same_for_queries_and_mutation():
    import host_resource_native_cleanup as n
    from host_resource_backends import LibvirtMemoryBackend,LibvirtVM
    from types import SimpleNamespace
    calls=[];runner=SimpleNamespace(run=lambda argv,**kw:calls.append(tuple(argv)) or '')
    endpoint='qemu+unix:///system?socket=%2Frun%2Flibvirt%2Flibvirt-sock'
    vm=LibvirtVM('12345678-1234-1234-1234-123456789abc','synthetic')
    b=LibvirtMemoryBackend(runner,'/usr/bin/virsh','qemu:///system',{'vm-a':vm},dynamic=True,connect_endpoint=endpoint)
    b._run(['list','--uuid'])
    assert calls[0][1:3]==('--connect',endpoint)
    assert b.mutation_argv('vm-a',1024,SimpleNamespace())[1:3]==('--connect',endpoint)
    assert b.uri=='qemu:///system'
    for bad in ('qemu+ssh://foreign/system','qemu:///session',endpoint+'&command=x',endpoint+'&mode=direct',endpoint.replace('libvirt-sock','other')):
        with pytest.raises(n.ResourceError):LibvirtMemoryBackend(runner,'/usr/bin/virsh','qemu:///system',{},dynamic=True,connect_endpoint=bad)
    legacy=LibvirtMemoryBackend(runner,'/usr/bin/virsh','qemu:///system',{},dynamic=True)
    assert legacy.connect_endpoint=='qemu:///system'


def test_profile_bundle_binds_one_exact_local_libvirt_endpoint(tmp_path):
    n,m,c,b,store,e,p,s,r,profiles=fixture(tmp_path,protocol='libvirt-local-setmem-v1')
    assert b.connect_endpoint=='qemu+unix:///system?socket=%2Frun%2Flibvirt%2Flibvirt-sock'
    profiles[1]['native_peer_identity']['socket_path']='/run/libvirt/virtqemud-sock'
    with pytest.raises(m.ResourceError):n.NativeMutationProofs(c.policy,store,b,p.config,r,sources=s)


@pytest.mark.parametrize('change',['healthy','not-listening','duplicate','other-daemon','birth-changed'])
def test_exact_libvirt_listener_is_owned_by_current_root_daemon(monkeypatch,change):
    import host_resource_native_cleanup as n
    import application_release as engine
    from types import SimpleNamespace
    birth=dict(pid=77,start_ticks=10,boot_id='boot')
    row='00000000: 00000002 00000000 00010000 0001 01 12345 /run/libvirt/libvirt-sock'
    if change=='not-listening':row=row.replace('00010000','00000000')
    packet='Num RefCount Protocol Flags Type St Inode Path\n'+row+'\n'
    if change=='duplicate':packet+=row+'\n'
    class Budget:
        def __init__(self,*a):pass
        def entries(self,path,kind):assert str(path)=='/proc/77/fd';return [Path('/proc/77/fd/3')]
        def link(self,path):return 'socket:[999]' if change=='other-daemon' else 'socket:[12345]'
    monkeypatch.setattr(engine,'UpdateScan',Budget)
    source=n.NativeCleanupSources.__new__(n.NativeCleanupSources)
    source.local=SimpleNamespace(read=lambda path:packet)
    source.birth=lambda pid,**kw:{**birth,'start_ticks':11} if change=='birth-changed' else dict(birth)
    if change=='healthy':source.listener_owned('/run/libvirt/libvirt-sock',birth)
    else:
        with pytest.raises(n.ResourceError):source.listener_owned('/run/libvirt/libvirt-sock',birth)


@pytest.mark.parametrize('log_fails',[False,True])
def test_terminal_proof_io_retains_successful_native_output_and_secondary_log_error(tmp_path,monkeypatch,log_fails):
    n,m,c,b,store,e,p,s,r,profiles=fixture(tmp_path);c.request(request(m),e)
    original=store._atomic;failure=OSError('synthetic terminal proof write failed')
    def failed(path,data):
        if Path(path).parent==p.directory:raise failure
        return original(path,data)
    monkeypatch.setattr(store,'_atomic',failed)
    if log_fails:
        def log_failed(*a):raise OSError('synthetic log IO failure')
        monkeypatch.setattr(store,'save_failure',log_failed)
        with pytest.raises(OSError) as caught:c.grow('request-1',e)
        assert caught.value is failure and isinstance(failure.native_log_exception,OSError)
    else:
        assert c.grow('request-1',e).phase=='GROW_UNKNOWN'
        logs=list(store.directory.glob('failure-*.json'))
        assert len(logs)==1 and json.loads(logs[0].read_text())['output']=='native successful return'
    assert failure.native_output=='native successful return'
    assert failure.native_argv==r.calls[0]
    assert c.snapshot()[0].guest_bytes==512 and not store.load()['receipts'][0]['native_cleanup_confirmed']


def test_claim_older_than_durable_mutation_never_returns_qualified_success(tmp_path):
    n,m,c,b,store,e,p,s,r,profiles=fixture(tmp_path);c.request(request(m),e)
    s.clock=lambda:99  # controller intent was durably created at100
    assert c.grow('request-1',e).phase=='GROW_UNKNOWN'
    state=store.load()
    assert not state['receipts'][0]['native_cleanup_confirmed'] and c.snapshot()[0].guest_bytes==512
    assert p.cleanup('request-1',owner_state=state,evidence=e) is None
    assert len(r.calls)==1


def test_worker_restart_between_dispatch_and_claim_cannot_run_native(tmp_path):
    n,m,c,b,store,e,p,s,r,profiles=fixture(tmp_path);c.request(request(m),e)
    original=s.claim_process
    def restarted(context):
        worker,cli=original(context);return {**worker,'start_ticks':99},cli
    s.claim_process=restarted
    assert c.grow('request-1',e).phase=='GROW_UNKNOWN'
    row=store.load()['receipts'][0]
    assert p.dispatch(row['mutation_id'])['worker_birth']['start_ticks']==1
    assert not p.path(row['mutation_id']).exists() and not b.calls and c.snapshot()[0].guest_bytes==512


@pytest.mark.parametrize('change',['healthy','wrong-link','no-sticky','wrong-uid','writable-child','symlink-lock','hardlink-lock','replaced-inode','missing-lock','foreign-contention'])
def test_fixed_pve_native_lock_layout_uses_anchored_owned_inodes(tmp_path,change):
    import host_resource_native_cleanup as n
    import fcntl
    import stat
    root=tmp_path/'synthetic-native-root';root.mkdir()
    (root/'var').mkdir();(root/'run').mkdir();runlock=root/'run/lock';runlock.mkdir(mode=0o1777);runlock.chmod(0o1777)
    (root/'var/lock').symlink_to('/run/lock' if change!='wrong-link' else '/foreign/lock')
    child=runlock/'qemu-server';child.mkdir();path=child/'lock-101.conf';path.write_text('');path.chmod(0o644)
    if change=='no-sticky':runlock.chmod(0o777)
    if change=='writable-child':child.chmod(0o777)
    if change=='symlink-lock':path.unlink();path.symlink_to(child/'other')
    if change=='hardlink-lock':os.link(path,child/'hardlink')
    if change=='missing-lock':path.unlink()
    live=set()
    class SyntheticNativeOS:
        # Only this fixture redirects / and synthetic ownership; no production flag.
        def open(self,p,flags,**kw):
            fd=os.open(root if str(p)=='/' else p,flags,**kw);live.add(fd);return fd
        def close(self,fd):os.close(fd);live.remove(fd)
        def readlink(self,*a,**k):return os.readlink(*a,**k)
        def stat(self,p,**kw):return self.owned(os.stat(root if str(p)=='/' else p,**kw))
        def fstat(self,*a):return self.owned(os.fstat(*a))
        def owned(self,st):
            values=list(st);values[4]=1 if change=='wrong-uid' and stat.S_ISREG(st.st_mode) else 0
            return os.stat_result(values)
    def lock(fd,flags):
        if change=='foreign-contention':raise BlockingIOError('synthetic foreign lock holder')
        fcntl.flock(fd,flags)
        if change=='replaced-inode':
            replacement=child/'new';replacement.write_text('');os.replace(replacement,path)
    if change=='healthy':assert n._pve_lock_released(101,native_os=SyntheticNativeOS(),lock=lock)
    elif change=='foreign-contention':assert not n._pve_lock_released(101,native_os=SyntheticNativeOS(),lock=lock)
    else:
        with pytest.raises((OSError,n.ResourceError)):n._pve_lock_released(101,native_os=SyntheticNativeOS(),lock=lock)
    assert not live
