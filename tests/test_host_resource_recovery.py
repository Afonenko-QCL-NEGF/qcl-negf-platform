"""Explicit synthetic native protocol, real controller/store/claims; no native calls."""
from dataclasses import asdict, replace
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops'))
from test_host_resource_native_cleanup import fixture as cleanup_fixture
from test_host_resource_operations import request


def module():
    assert importlib.util.find_spec('host_resource_recovery'), 'retirement producer is missing'
    return __import__('host_resource_recovery')


def fixture(tmp_path,protocol='libvirt-local-setmem-v1'):
    d=module();n,m,c,b,store,e,proofs,cs,cr,profiles=cleanup_fixture(tmp_path,protocol=protocol)
    state=store.load();bindings=[]
    for i,old in enumerate(e.bindings,1):
        new=replace(old,native_id=f'{i:08d}-1111-4111-8111-111111111111',process_id=str(70+i))
        bindings.append(new);state['bindings'][new.vm_id]=asdict(new)
        state['startups'][new.vm_id]['native_id']=new.native_id
        b.rows[new.vm_id]=replace(b.rows[new.vm_id],native_id=new.native_id,process_id=new.process_id)
        profiles[i-1]['binding']=asdict(new)
    e=replace(e,bindings=tuple(bindings),qualifications=tuple(replace(q,binding=bindings[i]) for i,q in enumerate(e.qualifications)))
    store.save(state)
    class Sources:
        """Synthetic facts only. Production has no synthetic/qualified boolean."""
        protocol=d.LIBVIRT;boot=e.host_boot_id;failure=None;live=True;defined=True;peer=True;controls=[];clock=lambda self:100
        def target_before_exec(self,intent,dispatch,p,backend,worker,cli):
            return {
                'schema':d.TARGET_SCHEMA,'request_id':intent.request_id,'mutation_id':intent.mutation_id,
                'intent_sha256':n.fingerprint(asdict(intent)),'dispatch_sha256':n.fingerprint(dispatch),
                'host_id':e.host_id,'owner_id':e.owner_id,'host_boot_id':e.host_boot_id,'policy_sha256':e.policy_sha256,
                'binding':asdict(intent.binding),'protocol_id':intent.protocol_id,'qualification_sha256':intent.qualification_sha256,
                'source_ids':copy.deepcopy(p['source_ids']),'native_peer_identity':copy.deepcopy(p['native_peer_identity']),
                'target':dict(kind='libvirt',system_namespace='system',uuid=intent.binding.native_id,name='synthetic-a',connect_endpoint='qemu+unix:///system?socket=%2Frun%2Flibvirt%2Flibvirt-sock'),
                'qemu_birth':dict(pid=71,start_ticks=10,boot_id=e.host_boot_id),'qemu_executable':dict(path='/protected/qemu',sha256='a'*64),
                'vm_scope':dict(cgroup='/machine.slice/machine-qemu-synthetic.scope',device=1,inode=11,invocation_id='d'*32),
                'owned_helpers':[],'config_sha256':'a'*64,'storage_namespace_sha256':'b'*64,'storage_devices':[dict(path='/synthetic/private/disk.raw',device=1,inode=21,kind='local_regular')],'worker_birth':worker,'cli_birth':cli}
        def profile(self,target):
            if not self.peer:raise m.ResourceError('identity_mismatch','synthetic daemon changed')
            return dict(protocol_id=self.protocol,host_boot_id=self.boot,target_sha256=n.fingerprint(target))
        def recovery_facts(self,req,*,owner_state,target):
            if self.failure:raise m.ResourceError(self.failure,'synthetic incomplete actual observation')
            return d.RecoveryFacts(e, {vm:b.readback(vm) for vm in ('vm-a','vm-b') if vm!='vm-a'},
                {r['request']['request_id']:dict(request_sha256=n.fingerprint(r),native_generation='synthetic-terminal',output_provenance='synthetic-owning-output-closure') for r in owner_state['receipts'] if r['request']['vm_id']=='vm-a'})
        def worker(self,context):return cs.worker(context)
        def context(self,row):return cs.context(row)
        def claim_process(self,context):return cs.claim_process(context)
        def validate_target(self,target):return self.profile(target)
        def quiescent(self,target):return not self.live
        def command_absent(self,record):return cs.clean
        def removed(self,target):return not self.defined
        def stage_observation(self,target):return dict(quiescent=not self.live,removed=not self.defined)
        def replacement_storage(self,native_id,target):return [dict(path='/synthetic/replacement/disk.raw',device=1,inode=22,kind='local_regular')]
        def replacement(self,native_id,*,owner_state,target):
            from host_resource_startup import ColdVMRecord
            return ColdVMRecord('vm-a',native_id,'new-config',2048,2048,'stopped')
    sources=Sources();cs.target_before_exec=sources.target_before_exec
    c.request(request(m),e);cr.fault='timeout';c.grow('request-1',e)
    state=store.load();row=state['receipts'][0]
    class Runner:
        fault=None
        def run(self,argv,**kwargs):
            args=service.claim(argv[-2],argv[-1]);sources.controls.append(args)
            assert store.load()['grants'][0]['guest_bytes']==512
            assert store.load()['receipts'][0]['native_cleanup_confirmed'] is False
            if args[3]=='destroy':sources.live=False
            else:sources.defined=False
            if self.fault:
                error=m.ResourceError('native_timeout','synthetic server reply lost')
                error.native_argv=tuple(argv);error.native_output='original output'
                error.native_record=dict(cleanup_confirmed=True,stdout='original output')
                raise error
            return 'native completed response'
    runner=Runner();config=dict(schema=d.CONFIG_SCHEMA,qualification='/protected/recovery-profiles')
    service=d.NativeRecoveryService(c,None,proofs,config,runner,sources=sources)
    req=d.NativeRecoveryRequest('e'*32,'request-1',row['mutation_id'])
    return d,m,c,b,store,e,service,sources,runner,req


def test_libvirt_retirement_preserves_unknown_fullmax_and_other_vm(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path)
    before=store.load();other=copy.deepcopy(before['grants'][1])
    view=s.retire(req)
    assert view['phase']=='target_retired' and view['original_outcome']=='unknown'
    state=store.load();assert state['grants'][0]['guest_bytes']==2048 and state['grants'][1]==other
    assert state['bindings']['vm-a'] is None and state['startups']['vm-a']['phase']=='boot_unknown'
    archived=store.completed('request-1');assert archived['phase']=='GROW_UNKNOWN' and not archived['native_cleanup_confirmed']
    assert archived==before['receipts'][0] and store.workload_exists('work-1')
    assert s.retire(req)['phase']=='target_retired' and len(f.controls)==2
    assert [a[3] for a in f.controls]==['destroy','undefine']
    assert all(a[:3]==('/protected/tool','--connect','qemu+unix:///system?socket=%2Frun%2Flibvirt%2Flibvirt-sock') for a in f.controls)
    assert f.controls[-1][-2:]==('--keep-nvram','--keep-tpm')


@pytest.mark.parametrize('fault',['cleanup','incomplete_workloads','native_generation','capacity_evidence','host_pressure','identity_mismatch'])
def test_missing_fresh_facts_never_stops_or_archives(tmp_path,fault):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);f.failure=fault;before=store.state_path.read_bytes()
    assert s.retire(req)['phase']=='hold';assert not f.controls and store.state_path.read_bytes()==before


def test_pve_source_gap_is_hold_and_zero_controls(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);f.protocol=d.PVE
    assert s.retire(req)['failure_code']=='source_protocol_unavailable' and not f.controls
    assert c.snapshot()[0].guest_bytes==512


def test_lost_control_reply_reload_no_replay_and_matching_memory_is_not_proof(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);r.fault='timeout'
    with pytest.raises(m.ResourceError) as error:s.retire(req)
    assert error.value.native_record['stdout']=='original output'
    assert c.snapshot()[0].guest_bytes==512 and len(f.controls)==1
    f.live=True
    assert s.retire(req)['phase']=='hold' and len(f.controls)==1
    f.live=False;r.fault=None
    assert s.retire(req)['phase']=='target_retired' and len(f.controls)==2


def test_archive_io_failure_retains_old_charge_and_durable_fence(tmp_path,monkeypatch):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);original=store._immutable
    def fail(path,value):
        if Path(path).parent==store.completed_directory:raise OSError('synthetic archive disk failure')
        return original(path,value)
    monkeypatch.setattr(store,'_immutable',fail)
    with pytest.raises(OSError):s.retire(req)
    assert c.snapshot()[0].guest_bytes==512 and store.load()['receipts'][0]['phase']=='GROW_UNKNOWN'
    with pytest.raises(m.ResourceError):d.check_start_fence(store,'libvirt',uuid=e.bindings[0].native_id,name='synthetic-a')
    monkeypatch.setattr(store,'_immutable',original)
    assert s.retire(req)['phase']=='target_retired' and len(f.controls)==2


def test_readonly_and_replacement_do_not_replay_old_request(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);s.retire(req)
    before={str(p): (p.stat().st_mtime_ns,p.read_bytes()) for p in store.directory.rglob('*') if p.is_file()}
    assert s.read(req.recovery_id)['original_outcome']=='unknown'
    after={str(p): (p.stat().st_mtime_ns,p.read_bytes()) for p in store.directory.rglob('*') if p.is_file()};assert before==after
    view=s.reserve_replacement(req.recovery_id,'99999999-1111-4111-8111-111111111111')
    assert view['charged_bytes']==2048 and view['admission_closed']
    assert c.request(request(m),e).phase=='GROW_UNKNOWN' and len(f.controls)==2
    with pytest.raises(m.ResourceError):s.reserve_replacement(req.recovery_id,e.bindings[0].native_id)


def test_production_sources_do_not_accept_synthetic_flags_or_payload_paths(tmp_path):
    d=module()
    for document in [dict(recovery_id='e'*32,request_id='x',mutation_id='f'*32,qualified=True),dict(recovery_id='../x',request_id='x',mutation_id='f'*32)]:
        with pytest.raises((TypeError,__import__('host_resource_operations').ResourceError)):d.NativeRecoveryRequest(**document)


def test_direct_start_permit_rejects_retired_even_with_full_slot(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);s.retire(req)
    from host_resource_startup import StartupManager
    packet=json.dumps(dict(native_id=e.bindings[0].native_id,maximum_bytes=2048,config_fingerprint='config-1')).encode()
    with pytest.raises(m.ResourceError,match='retired_target'):
        StartupManager(c.policy,store,b).verify_start_permit(e.bindings[0].native_id,'prepare-begin',packet,host_boot_id=e.host_boot_id)


def test_fence_dangling_link_cannot_be_treated_as_absent(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);s.retire(req)
    path=store.directory/'retired-targets'/store._key('libvirt:uuid:'+e.bindings[0].native_id)
    path.unlink();path.symlink_to('missing')
    with pytest.raises((m.ResourceError,OSError)):d.check_start_fence(store,'libvirt',uuid=e.bindings[0].native_id)


def test_unknown_extra_block_and_other_vm_underallocation_do_not_control(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path)
    state=store.load();state['blocked']='unrelated administrator incident';store.save(state)
    assert s.retire(req)['phase']=='hold' and not f.controls
    state['blocked']=m.CLEANUP_BLOCK;store.save(state)
    b.rows['vm-b']=replace(b.rows['vm-b'],assigned_bytes=64)
    assert s.retire(req)['phase']=='hold' and not f.controls


@pytest.mark.parametrize('change',['row-old','row-target','native-context','boot','binding','intent','dispatch','missing-target'])
def test_exact_original_authority_changes_hold_without_native_call(tmp_path,change):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);state=store.load();row=state['receipts'][0]
    if change=='row-old':row['old_bytes']+=64
    if change=='row-target':row['target_bytes']-=64
    if change=='native-context':row['native_context']['invocation_id']='9'*32
    if change=='boot':state['host_boot_id']='other-boot'
    if change=='binding':state['bindings']['vm-a']['guest_boot_id']='other-guest'
    if change in {'row-old','row-target','native-context','boot','binding'}:store.save(state)
    if change in {'intent','dispatch'}:
        path=s.proofs.path(req.mutation_id) if change=='intent' else s.proofs.dispatch_path(req.mutation_id)
        data=json.loads(path.read_text());data['intent']['target_bytes']+=64;path.write_text(json.dumps(data))
    if change=='missing-target':s.proofs.path(req.mutation_id).with_suffix('.target.json').unlink()
    try:view=s.retire(req)
    except (m.ResourceError,OSError):pass
    else:assert view['phase']=='hold'
    assert not f.controls and store.load()['receipts'][0]['phase']=='GROW_UNKNOWN'


def test_primary_native_error_survives_secondary_log_io(tmp_path,monkeypatch):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);r.fault='timeout'
    def fail(*a,**k):raise OSError('synthetic failure log unavailable')
    monkeypatch.setattr(store,'save_failure',fail)
    with pytest.raises(m.ResourceError) as error:s.retire(req)
    assert error.value.code=='native_timeout' and error.value.native_record['stdout']=='original output'
    assert 'synthetic failure log unavailable' in error.value.native_log_error
    assert c.snapshot()[0].guest_bytes==512


def test_archive_reload_old_request_and_native_projection_are_idempotent(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);s.retire(req)
    from host_resource_projection import ResourceProjection
    view=ResourceProjection(store.directory,policy=c.policy,owner_uid=os.getuid(),clock=lambda:100).read(request_id='request-1')
    assert view['operations'][0]['phase']=='GROW_UNKNOWN' and view['operations'][0]['admission']=='reconciliation_required'
    old=m.FileReceiptStore.open_existing(store.directory,owner_uid=os.getuid())
    assert old.completed('request-1')['native_cleanup_confirmed'] is False
    with pytest.raises(m.ResourceError):c.grow('request-1',e)
    assert len(f.controls)==2 and len(b.calls)==1


def test_retired_receipt_without_matching_proof_is_not_accepted(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);s.retire(req)
    path=s.path(req.recovery_id,'proof');value=json.loads(path.read_text());value['workload_closures']['request-1']['request_sha256']='0'*64;path.write_text(json.dumps(value))
    with pytest.raises(m.ResourceError):store.completed('request-1')


def test_new_owned_worker_can_continue_new_stage_but_never_replay_old_stage(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path)
    run=r.run
    def interrupted(argv,**kw):
        out=run(argv,**kw)
        if f.controls[-1][3]=='destroy':raise SystemExit(77)
        return out
    r.run=interrupted
    with pytest.raises(SystemExit):s.retire(req)
    f.worker=lambda context:dict(pid=201,start_ticks=3,boot_id=e.host_boot_id)
    f.claim_process=lambda context:(f.worker(context),dict(pid=202,start_ticks=4,boot_id=e.host_boot_id))
    r.run=run
    assert s.retire(req)['phase']=='target_retired' and [a[3] for a in f.controls]==['destroy','undefine']


def test_prepared_stage_crash_before_claim_cannot_be_dispatched_again(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);calls=[]
    def interrupted(argv,**kw):calls.append(tuple(argv));raise SystemExit(77)
    r.run=interrupted
    with pytest.raises(SystemExit):s.retire(req)
    assert s.retire(req)['phase']=='hold' and len(calls)==1 and not f.controls


def test_recovery_intent_unknown_fields_do_not_authorize_reload(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);s.retire(req)
    path=s.path(req.recovery_id);data=json.loads(path.read_text());data['administrator_confirmed']=True;path.write_text(json.dumps(data))
    with pytest.raises(m.ResourceError):s.read(req.recovery_id)


def test_proof_unknown_fields_cannot_be_adopted_by_rehashing_archive(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);s.retire(req)
    path=s.path(req.recovery_id,'proof');proof=json.loads(path.read_text());proof['admin_true']=True;path.write_text(json.dumps(proof))
    archive_path=store.completed_directory/store._key(req.request_id);archive=json.loads(archive_path.read_text());archive['recovery_proof_sha256']=d.fingerprint(proof);archive_path.write_text(json.dumps(archive))
    with pytest.raises(m.ResourceError):store.completed(req.request_id)


def test_recovery_schema_covers_actual_files_and_rejects_client_proof_fields(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);s.retire(req)
    path=Path(__file__).resolve().parents[1]/'schemas/host-resource-native-recovery.schema.json'
    assert path.is_file(),'exact recovery schema is missing'
    import jsonschema
    schema=json.loads(path.read_text())
    for name in ('target','intent','proof','retired'):
        value=(store._read(s.proofs.path(req.mutation_id).with_suffix('.target.json')) if name=='target' else
            store._read(s.path(req.recovery_id,'intent' if name=='intent' else 'proof')) if name!='retired' else
            store._read(store.completed_directory/store._key(req.request_id)))
        jsonschema.validate(value,{'$ref':'#/$defs/'+name,**schema})
        with pytest.raises(jsonschema.ValidationError):jsonschema.validate({**value,'qualified':True},{'$ref':'#/$defs/'+name,**schema})


def test_metadata_commit_after_proof_io_failure_survives_clock_progress(tmp_path,monkeypatch):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);save=store.save
    def fail(state):raise OSError('synthetic state commit lost')
    monkeypatch.setattr(store,'save',fail)
    with pytest.raises(OSError):s.retire(req)
    assert store.load()['grants'][0]['guest_bytes']==512
    f.clock=lambda:101;c.clock=lambda:101;monkeypatch.setattr(store,'save',save)
    assert s.retire(req)['phase']=='target_retired' and len(f.controls)==2


def test_many_same_vm_commitments_archive_without_lifetime_quota_or_old_admission(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);state=store.load();original=copy.deepcopy(state['receipts'][0])
    for i in range(256):
        row=copy.deepcopy(original);row['request']=asdict(request(m,'older-'+str(i),'older-work-'+str(i),amount=1))
        row.update(phase='RUN' if i==0 else 'SHRINK_DEFERRED',old_bytes=512,target_bytes=512,finished=i!=0,mutation_id=None,mutation_started_at=None,native_cleanup_confirmed=True,native_context=None)
        state['receipts'].append(row)
    state['grants'][0]['active_floor_bytes']=450;store.save(state)
    assert s.retire(req)['phase']=='target_retired' and len(f.controls)==2
    reload=m.FileReceiptStore.open_existing(store.directory,owner_uid=os.getuid())
    assert len(list(reload.completed_directory.iterdir()))==257
    assert reload.workload_exists('work-1') and reload.workload_exists('older-work-255')
    assert c.request(request(m),e).phase=='GROW_UNKNOWN'
    from host_resource_projection import ResourceProjection
    view=ResourceProjection(store.directory,policy=c.policy,owner_uid=os.getuid()).read(request_id='older-255')
    assert view['operations'][0]['admission']=='reconciliation_required'


def test_one_unfinished_same_vm_output_blocks_entire_retirement(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);capture=f.recovery_facts
    def incomplete(*args,**kw):
        facts=capture(*args,**kw);return replace(facts,workload_closures={})
    f.recovery_facts=incomplete
    assert s.retire(req)['phase']=='hold' and not f.controls and c.snapshot()[0].guest_bytes==512


def test_worker_native_error_returns_recovery_hold_dto_not_job_admission(tmp_path,monkeypatch,capsys):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);s.retire(req)
    import host_resource_service as service
    import base64
    error=m.ResourceError('native_timeout','synthetic lost server reply');error.native_argv=('synthetic',)
    def fail(*a,**k):raise error
    monkeypatch.setattr(service,'root_main',fail)
    monkeypatch.setattr(d,'read_recovery_status',lambda rid:s.read(rid))
    monkeypatch.setattr(sys,'argv',['worker','retirement',base64.urlsafe_b64encode(json.dumps(asdict(req)).encode()).decode()])
    assert service.main('worker')==0
    view=json.loads(capsys.readouterr().out)
    assert view['schema']=='qcl.host-resource-recovery.v1' and view['phase']=='hold' and view['failure_code']=='native_timeout'


@pytest.mark.parametrize('change',['pid-reused','static-config','foreign-name-reuse'])
def test_real_namespace_validator_rejects_a_new_native_incarnation(tmp_path,change):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path)
    target=store._read(s.proofs.path(req.mutation_id).with_suffix('.target.json'))
    source=d.NativeRecoverySources.__new__(d.NativeRecoverySources);source.s=s;source.profile=lambda t:{'protocol_id':d.LIBVIRT}
    # This test isolates F1 native namespace/birth validation. The production
    # attached-capture parser and descriptor checks have separate fixtures.
    source.storage=type('SyntheticStorageBoundary',(),{'validate_retirement':lambda self,t: d.decode_storage_devices(t['storage_devices'])})()
    source.native=type('BirthReader',(),{'birth':lambda self,pid:dict(pid=pid,start_ticks=999,boot_id=e.host_boot_id)})()
    xml='<domain><name>synthetic-a</name><uuid>'+target['target']['uuid']+'</uuid><memory unit="bytes">2048</memory><currentMemory unit="bytes">512</currentMemory></domain>'
    if change!='static-config':target['config_sha256']=__import__('host_resource_backends').libvirt_config_fingerprint(__import__('xml.etree.ElementTree',fromlist=['']).fromstring(xml))
    foreign='99999999-1111-4111-8111-111111111111'
    def run(argv):
        if argv==['list','--all','--uuid']:return foreign if change=='foreign-name-reuse' else target['target']['uuid']
        if argv[0]=='dumpxml':return xml.replace(target['target']['uuid'],argv[1])
        if argv[0]=='domstate':return 'running'
        pytest.fail('unexpected synthetic native read '+repr(argv))
    b._run=run
    with pytest.raises(m.ResourceError):source.validate_target(target)


@pytest.mark.parametrize('change',['owner','qualification-ref','duplicate-binding','process-alias'])
def test_other_vm_qualification_identity_is_not_a_true_flag(tmp_path,change):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);capture=f.recovery_facts
    def wrong(*a,**k):
        facts=capture(*a,**k);evidence=facts.evidence
        if change=='owner':evidence=replace(evidence,qualifications=(evidence.qualifications[0],replace(evidence.qualifications[1],owner_id='foreign')))
        elif change=='qualification-ref':evidence=replace(evidence,qualifications=(evidence.qualifications[0],replace(evidence.qualifications[1],evidence_ref='unrelated')))
        elif change=='duplicate-binding':evidence=replace(evidence,bindings=evidence.bindings+(evidence.bindings[1],))
        else:evidence=replace(evidence,bindings=(evidence.bindings[0],replace(evidence.bindings[1],process_id=evidence.bindings[0].process_id)))
        return replace(facts,evidence=evidence)
    f.recovery_facts=wrong
    assert s.retire(req)['phase']=='hold' and not f.controls


def test_real_namespace_validator_healthy_control_uses_old_birth(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);target=store._read(s.proofs.path(req.mutation_id).with_suffix('.target.json'))
    source=d.NativeRecoverySources.__new__(d.NativeRecoverySources);source.s=s;source.profile=lambda t:{'protocol_id':d.LIBVIRT}
    source.storage=type('SyntheticStorageBoundary',(),{'validate_retirement':lambda self,t: d.decode_storage_devices(t['storage_devices'])})()
    source.native=type('BirthReader',(),{'birth':lambda self,pid:dict(pid=pid,start_ticks=10,boot_id=e.host_boot_id)})()
    xml='<domain><name>synthetic-a</name><uuid>'+target['target']['uuid']+'</uuid><memory unit="bytes">2048</memory><currentMemory unit="bytes">512</currentMemory></domain>'
    target['config_sha256']=__import__('host_resource_backends').libvirt_config_fingerprint(__import__('xml.etree.ElementTree',fromlist=['']).fromstring(xml))
    def run(argv):
        if argv==['list','--all','--uuid']:return target['target']['uuid']
        if argv[0]=='dumpxml':return xml
        if argv[0]=='domstate':return 'running'
        pytest.fail('unexpected synthetic native read '+repr(argv))
    b._run=run
    assert source.validate_target(target)['protocol_id']==d.LIBVIRT and not f.controls


def test_native_source_constructor_never_treats_injected_flags_as_root_proof(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path)
    with pytest.raises(m.ResourceError):d.NativeRecoverySources(s)
    assert not f.controls


def test_qualified_native_absence_needs_no_blind_undefine_call(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);f.live=False;f.defined=False
    assert s.retire(req)['phase']=='target_retired' and not f.controls


def test_closed_protocol_fixture_exercises_waiting_rpc_and_lost_undefine_reply(tmp_path):
    path=Path(__file__).parent/'fixtures/host-resources/synthetic-recovery.json'
    assert path.is_file(),'closed synthetic recovery fixture is missing'
    packet=json.loads(path.read_text());assert packet['source_kind']=='synthetic'
    for scenario in packet['scenarios']:
        local=tmp_path/scenario['name'];local.mkdir();d,m,c,b,store,e,s,f,r,req=fixture(local)
        run=r.run
        if scenario['event']=='server_undefine_waits_for_old_modify':
            def queued(argv,**kw):
                if len(f.controls)==1:
                    args=s.claim(argv[-2],argv[-1]);f.controls.append(args)
                    err=m.ResourceError('native_timeout','synthetic MODIFY still waits');err.native_argv=tuple(argv);err.native_output='queued';raise err
                return run(argv,**kw)
            r.run=queued
            with pytest.raises(m.ResourceError):s.retire(req)
            assert store.load()['grants'][0]['guest_bytes']==512 and len(f.controls)==2
            f.defined=False  # pinned object-removal barrier finishes on the server
            assert s.retire(req)['phase']=='target_retired' and len(f.controls)==2
        elif scenario['event']=='daemon_changed':
            f.peer=False;assert s.retire(req)['phase']=='hold' and not f.controls
        elif scenario['event']=='descendant_after_cli_exit':
            s.proofs.sources.clean=False;assert s.retire(req)['phase']=='hold' and not f.controls
        else:pytest.fail('unconsumed synthetic scenario')


@pytest.mark.parametrize('device',["<vsock model='virtio'/>","<memory model='nvdimm'/>","<filesystem type='mount'/>"])
def test_production_target_capture_rejects_external_memory_topology_before_kernel_read(tmp_path,device):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path)
    import types,xml.etree.ElementTree as ET
    source=d.NativeRecoverySources.__new__(d.NativeRecoverySources);source.s=s
    xml=ET.fromstring('<domain><name>synthetic-a</name><uuid>'+e.bindings[0].native_id+'</uuid><devices>'+device+'</devices></domain>')
    source._xml=lambda _:xml;source._profile=lambda *a:dict(storage_namespace_sha256=d.fingerprint([]))
    def forbidden(pid):raise AssertionError('external topology reached kernel reader')
    source.local=types.SimpleNamespace(process=forbidden)
    b.vms={'vm-a':types.SimpleNamespace(name='synthetic-a',native_id=e.bindings[0].native_id)}
    intent=__import__('host_resource_native_cleanup').decode_intent(s.proofs.read(req.mutation_id)['intent'])
    with pytest.raises(m.ResourceError):source.target_before_exec(intent,s.proofs.dispatch(req.mutation_id),{'protocol_id':'libvirt-local-setmem-v1'},b,{}, {})


def test_preexec_profile_change_does_not_inherit_parent_authorization(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);original=f.validate_target
    def changed(target):
        result=original(target)
        if list(s.directory.glob('*.dispatch.json')):result['unexpected_new_qualification']='changed'
        return result
    f.validate_target=changed
    assert s.retire(req)['phase']=='hold' and not f.controls


def test_rehashing_retired_row_cannot_replace_original_precontrol_closure(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);s.retire(req)
    archive_path=store.completed_directory/store._key(req.request_id);record=store._read(archive_path)
    record['receipt']['request']['workload_bytes']+=1
    proof_path=s.path(req.recovery_id,'proof');proof=store._read(proof_path)
    proof['workload_closures'][req.request_id]['request_sha256']=d.fingerprint(record['receipt'])
    proof_path.write_text(json.dumps(proof));record['recovery_proof_sha256']=d.fingerprint(proof);archive_path.write_text(json.dumps(record))
    with pytest.raises(m.ResourceError):store.completed(req.request_id)


def test_cold_enrollment_cannot_adopt_a_permanently_retired_uuid(tmp_path):
    from test_host_resource_startup import cold_setup
    from host_resource_startup import ColdVMRecord
    startup,m,manager,store,e,_=cold_setup(tmp_path)
    d=module();old='11111111-1111-4111-8111-111111111111'
    e=replace(e,vms=(replace(e.vms[0],native_id=old),e.vms[1]))
    fence=dict(schema='qcl.host-resource-native-tombstone.v1',backend='libvirt',aliases=dict(uuid=old,name='retired-synthetic'),recovery_id='e'*32,target_sha256='a'*64)
    d.immutable(store,store.directory/'retired-targets'/store._key('libvirt:uuid:'+old),fence)
    with pytest.raises(m.ResourceError,match='retired_target'):manager.prepare_start_reservations(cold_evidence=e)
    assert not store.state_path.exists()


def test_running_enrollment_refuses_retired_uuid_before_quarantine_write(tmp_path):
    from host_resource_startup import StartupManager
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);s.retire(req)
    b.rows['vm-a']=replace(b.rows['vm-a'],assigned_bytes=2048,configured_bytes=2048)
    before=store.state_path.read_bytes()
    with pytest.raises(m.ResourceError,match='retired_target'):
        StartupManager(c.policy,store,b,clock=lambda:100).bind_running_startup(e.bindings[0].native_id,e)
    assert store.state_path.read_bytes()==before


@pytest.mark.parametrize('alias',['name','uuid'])
def test_offline_hook_checks_fence_before_foreign_passthrough(tmp_path,monkeypatch,alias):
    import io
    import host_resource_startup as startup
    import host_resource_backends as backends
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);s.retire(req)
    config=dict(runtime='/protected/runtime',native_recovery={'configured':True})
    runtime=dict(state_directory=str(store.directory),backend_config=dict(backend='libvirt',vms={}))
    monkeypatch.setattr(backends,'read_root_json',lambda path:config if str(path)!='' and str(path)!='/protected/runtime' else runtime)
    monkeypatch.setattr(startup.os if hasattr(startup,'os') else os,'geteuid',lambda:0)
    monkeypatch.setattr(m.FileReceiptStore,'open_existing',lambda path:store)
    name='synthetic-a' if alias=='name' else 'otherwise-foreign'
    monkeypatch.setattr(sys,'stdin',io.TextIOWrapper(io.BytesIO(('<domain><uuid>'+e.bindings[0].native_id+'</uuid></domain>').encode())))
    with pytest.raises(m.ResourceError,match='retired_target'):startup.hook_main(['libvirt',name,'prepare','begin'])


def retirement_profile(d,target):
    sources=copy.deepcopy(target['source_ids'])
    for name,digest in d.EXTRA_SOURCES.items():sources['support'][name]=dict(path='/protected/source/'+name,sha256=digest)
    for name,path in {'resource_config/service':'/etc/qcl-negf/host-resources/service.json','resource_config/runtime':'/protected/runtime',
            'native_config/qemu.conf':'/etc/libvirt/qemu.conf','native_config/libvirtd.conf':'/etc/libvirt/libvirtd.conf',
            'native_config/start-hook':'/etc/libvirt/hooks/qemu'}.items():sources['support'][name]=dict(path=path,sha256='c'*64)
    return dict(schema=d.PROFILE_SCHEMA,protocol_id=d.LIBVIRT,host_id=target['host_id'],owner_id=target['owner_id'],host_boot_id=target['host_boot_id'],
        policy_sha256=target['policy_sha256'],binding=target['binding'],source_ids=sources,native_peer_identity=target['native_peer_identity'],
        memory_scope_protocol='linux-private-cgroup-v2-v1',storage_namespace_sha256=target['storage_namespace_sha256'],
        start_fence_protocol='qcl-native-retirement-hook-v1',evidence_ref='synthetic-reference-not-native-qualification')


def test_exact_qualification_schema_and_runtime_bundle_reject_substitution(tmp_path,monkeypatch):
    from types import SimpleNamespace
    import jsonschema
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path)
    target=store._read(s.proofs.path(req.mutation_id).with_suffix('.target.json'));profile=retirement_profile(d,target)
    schema=json.loads((Path(__file__).resolve().parents[1]/'schemas/host-resource-native-recovery.schema.json').read_text())
    assert 'qualification' in schema['$defs'] and 'qualificationBundle' in schema['$defs']
    bundle=dict(schema=d.BUNDLE_SCHEMA,profiles=[profile]);jsonschema.validate(bundle,{'$ref':'#/$defs/qualificationBundle',**schema})
    for alter in ('unknown','source','config','peer'):
        bad=copy.deepcopy(profile)
        if alter=='unknown':bad['admin_confirmed']=True
        if alter=='source':bad['source_ids']['support']['src/qemu/qemu_domain.c']['sha256']='0'*64
        if alter=='config':del bad['source_ids']['support']['native_config/start-hook']
        if alter=='peer':bad['native_peer_identity']['socket_path']='/tmp/client-socket'
        with pytest.raises(jsonschema.ValidationError):jsonschema.validate(bad,{'$ref':'#/$defs/qualification',**schema})
    native=d.NativeRecoverySources.__new__(d.NativeRecoverySources);native.s=SimpleNamespace(config={'qualification':'/protected/profiles'})
    monkeypatch.setattr(d,'read_root_json',lambda path:bundle)
    assert native._profiles()==[profile]
    bundle['profiles'].append(copy.deepcopy(profile))
    with pytest.raises(m.ResourceError,match='duplicate'):native._profiles()
    bundle['profiles']=[dict(profile,qualified=True)]
    with pytest.raises(m.ResourceError):native._profiles()


@pytest.mark.parametrize('change',['missing','block','bool','relative','unknown','duplicate'])
def test_sealed_storage_shape_is_not_a_client_backing_proof(tmp_path,change):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path)
    path=s.proofs.path(req.mutation_id).with_suffix('.target.json');target=store._read(path)
    if change=='missing':target.pop('storage_devices',None)
    else:
        device=dict(path='/synthetic/private/disk.raw',device=1,inode=21,kind='local_regular')
        if change=='block':device['kind']='block'
        if change=='bool':device['device']=True
        if change=='relative':device['path']='caller-disk'
        if change=='unknown':device['complete']=True
        target['storage_devices']=[device,dict(device)] if change=='duplicate' else [device]
    with pytest.raises(m.ResourceError):d.decode_target(target)


@pytest.mark.parametrize('xml',[
    '<domain/>',
    '<domain><devices><disk type="file"><source file="/disk.qcow2"/></disk></devices></domain>',
    '<domain><devices><disk type="file"><driver type="raw"/><source file="/disk.raw"/><backingStore><source file="/base"/></backingStore></disk></devices></domain>',
    '<domain><devices><disk type="file"><readonly/><source file="/shared-template"/></disk></devices></domain>',
    '<domain><devices><disk type="block"><source dev="/dev/disk/by-id/alias"/></disk></devices></domain>',
    '<domain><devices><disk type="network"><source protocol="rbd"/></disk></devices></domain>'
])
def test_top_xml_without_process_local_qualified_capture_never_proves_closure(xml):
    import xml.etree.ElementTree as ET
    d=module();source=d.NativeRecoverySources.__new__(d.NativeRecoverySources)
    with pytest.raises(__import__('host_resource_operations').ResourceError,match='qualification'):
        source.storage_closure(ET.fromstring(xml))


def test_storage_alias_predicate_uses_full_validated_closure_not_one_top_disk(tmp_path):
    d=module();disk=tmp_path/'old.raw';disk.write_bytes(b'synthetic metadata fixture')
    st=disk.stat();old=dict(path=str(disk),device=st.st_dev,inode=st.st_ino,kind='local_regular')
    hardlink=tmp_path/'same-backing.raw';hardlink.hardlink_to(disk);alias=hardlink.stat()
    second=dict(path=str(hardlink),device=alias.st_dev,inode=alias.st_ino,kind='local_regular')
    fresh=tmp_path/'fresh.raw';fresh.write_bytes(b'synthetic metadata fixture');new=fresh.stat()
    newref=dict(path=str(fresh),device=new.st_dev,inode=new.st_ino,kind='local_regular')
    d.assert_storage_disjoint([old],[newref])
    for candidate in ([old],[newref,second],[dict(newref,path=old['path'])]):
        with pytest.raises(__import__('host_resource_operations').ResourceError):d.assert_storage_disjoint([old],candidate)


def test_replacement_must_pass_native_storage_predicate_before_reservation(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);s.retire(req)
    before=store.state_path.read_bytes()
    target=store._read(s.proofs.path(req.mutation_id).with_suffix('.target.json'))
    f.replacement_storage=lambda native_id,target:copy.deepcopy(target['storage_devices'])
    with pytest.raises(m.ResourceError):s.reserve_replacement(req.recovery_id,'99999999-1111-4111-8111-111111111111')
    assert store.state_path.read_bytes()==before


def test_final_replacement_barrier_runs_after_facts_and_before_save(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);s.retire(req);before=store.state_path.read_bytes();calls=[]
    original=f.replacement
    def observed(*a,**kw):calls.append('facts');return original(*a,**kw)
    f.replacement=observed
    def changed(native,target):
        assert calls==['facts'] and store.state_path.read_bytes()==before
        calls.append('final-use');raise m.ResourceError('identity_mismatch','synthetic graph race at final barrier')
    f.validate_replacement_use=changed
    with pytest.raises(m.ResourceError):s.reserve_replacement(req.recovery_id,'99999999-1111-4111-8111-111111111111')
    assert calls==['facts','final-use'] and store.state_path.read_bytes()==before


def test_native_final_barrier_follows_durable_claim_and_keeps_unknown_charge(tmp_path):
    from test_host_resource_native_cleanup import fixture as cleanup
    n,m,c,b,store,e,proofs,sources,runner,profiles=cleanup(tmp_path,protocol='libvirt-local-setmem-v1')
    checked=[]
    def final(mutation_id):
        claim=proofs.read(mutation_id);assert claim['phase']=='CLAIMED'
        assert proofs.dispatch(mutation_id)['intent']==claim['intent']
        checked.append(mutation_id);raise m.ResourceError('identity_mismatch','synthetic final storage use race')
    sources.validate_target_use=final
    c.request(request(m),e);result=c.grow('request-1',e)
    assert result.phase=='GROW_UNKNOWN' and len(checked)==1 and not b.calls
    row=store.load()['receipts'][0]
    assert row['native_cleanup_confirmed'] is False and store.load()['grants'][0]['guest_bytes']==512


@pytest.mark.parametrize('position',json.loads((Path(__file__).parent/'fixtures/host-resources/synthetic-recovery.json').read_text())['late_rpc_positions'])
def test_four_position_libvirt_barrier_model_preserves_original_unknown(tmp_path,position):
    """Closed synthetic native model, not an installed-daemon qualification."""
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);run=r.run;events=[];old_job_pending=True
    def server(argv,**kwargs):
        nonlocal old_job_pending
        if len(f.controls)==1 and position=='running_modify_before_getdefs':
            args=s.claim(argv[-2],argv[-1]);f.controls.append(args)
            # Undefine shares MODIFY and must wait for the old running job;
            # command exit/timeout cannot let the service archive/prune early.
            events.append('undefine_waits');error=m.ResourceError('native_timeout','synthetic MODIFY lock still owned')
            error.native_argv=tuple(argv);raise error
        out=run(argv,**kwargs)
        if len(f.controls)==2:
            if position=='before_uuid_lookup':events.append('old_uuid_lookup_absent')
            elif position=='waiting_modify_after_old_object_lookup':events.append('old_reference_rejected_by_removing')
            elif position=='qmp_tail_on_old_qemu':
                assert not f.live;events.append('qmp_tail_confined_to_dead_old_qemu')
            old_job_pending=False
        return out
    r.run=server
    if position=='running_modify_before_getdefs':
        with pytest.raises(m.ResourceError):s.retire(req)
        assert old_job_pending and c.snapshot()[0].guest_bytes==512 and store.load()['receipts']
        # Exact same server object completes its old job and pending undefine;
        # no new virsh invocation or guessed FIFO claim is introduced.
        old_job_pending=False;f.defined=False;events.append('old_modify_end_then_object_removed')
    assert s.retire(req)['phase']=='target_retired' and not old_job_pending
    assert len(f.controls)==2 and store.completed(req.request_id)['phase']=='GROW_UNKNOWN'
    assert events and c.snapshot()[0].guest_bytes==2048


@pytest.mark.parametrize('where',['intent','fence','closure','claim','proof','workload-index'])
def test_artifact_sync_or_index_failure_keeps_charge_and_never_replays_native(tmp_path,monkeypatch,where):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);sync=store._sync_directory;save=store._immutable
    fired=False
    def fail_sync(directory):
        nonlocal fired
        directory=Path(directory)
        suffix={'intent':'.intent.json','closure':'.closure.json','claim':'.claim.json','proof':'.proof.json'}.get(where)
        selected=(directory.name=='retired-targets' if where=='fence' else suffix is not None and any(directory.glob('*'+suffix)))
        if selected and not fired:fired=True;raise OSError('synthetic '+where+' directory fsync failure')
        return sync(directory)
    def fail_index(path,value):
        nonlocal fired
        if where=='workload-index' and Path(path).parent==store.workload_directory and not fired:
            fired=True;raise OSError('synthetic workload index write failure')
        return save(path,value)
    monkeypatch.setattr(store,'_sync_directory',fail_sync);monkeypatch.setattr(store,'_immutable',fail_index)
    with pytest.raises(OSError):s.retire(req)
    assert fired and store.load()['receipts'] and c.snapshot()[0].guest_bytes==512
    before=list(f.controls)
    monkeypatch.setattr(store,'_sync_directory',sync);monkeypatch.setattr(store,'_immutable',save)
    result=s.retire(req)
    if where=='claim':assert result['phase']=='hold' and f.controls==before
    else:assert result['phase']=='target_retired' and len(f.controls)==2


@pytest.mark.parametrize('writer_kind',['recovery','completed'])
def test_equal_existing_file_retry_reestablishes_file_parent_and_ancestor_barriers(tmp_path,monkeypatch,writer_kind):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path)
    path=store.completed_directory/'sync-fixture.json';document={'exact':'immutable original'}
    write=(lambda:d.immutable(store,path,document)) if writer_kind=='recovery' else (lambda:store._immutable(path,document))
    write();before=(path.read_bytes(),path.stat().st_ino,path.stat().st_mtime_ns)
    fsync=m.os.fsync;events=[]
    def observe(fd):
        endpoint=Path(os.readlink('/proc/self/fd/'+str(fd)))
        events.append(endpoint)
        if endpoint==path:raise OSError('F1 persistent file fsync failure')
        return fsync(fd)
    monkeypatch.setattr(m.os,'fsync',observe)
    with pytest.raises(OSError,match='persistent file fsync'):write()
    assert events==[path]
    events.clear()
    monkeypatch.setattr(m.os,'fsync',lambda fd:(events.append(Path(os.readlink('/proc/self/fd/'+str(fd)))),fsync(fd))[1])
    write()
    assert path in events and path.parent in events and store.directory in events and store.directory.parent in events
    assert events.index(path)<events.index(path.parent)<=events.index(store.directory)
    assert (path.read_bytes(),path.stat().st_ino,path.stat().st_mtime_ns)==before


@pytest.mark.parametrize('where',['intent','second-alias','proof','completed','workload-index'])
@pytest.mark.parametrize('barrier',['file','parent','ancestor','store-parent'])
def test_durable_retry_requires_each_existing_artifact_barrier_before_control_or_prune(tmp_path,monkeypatch,where,barrier):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path)
    path={'intent':s.path(req.recovery_id),'second-alias':store.directory/'retired-targets'/store._key('libvirt:name:synthetic-a'),
          'proof':s.path(req.recovery_id,'proof'),'completed':store.completed_directory/store._key(req.request_id),
          'workload-index':store.workload_directory/store._key('work-1')}[where]
    fsync=m.os.fsync;events=[];fired=False
    def fail_selected(fd):
        nonlocal fired
        endpoint=Path(os.readlink('/proc/self/fd/'+str(fd)))
        selected=endpoint==({'file':path,'parent':path.parent,'ancestor':store.directory,'store-parent':store.directory.parent}[barrier])
        if selected and path.exists():fired=True;raise OSError('F1 '+where+' '+barrier+' sync failure')
        return fsync(fd)
    monkeypatch.setattr(m.os,'fsync',fail_selected)
    with pytest.raises(OSError):s.retire(req)
    assert fired and store.load()['receipts'] and c.snapshot()[0].guest_bytes==512
    before=(path.read_bytes(),path.stat().st_ino,path.stat().st_mtime_ns);controls=list(f.controls)
    # A continuing durability failure on the existing exact artifact must still
    # hold before any new control or state prune, rather than being bypassed.
    with pytest.raises(OSError):s.retire(req)
    assert f.controls==controls and store.load()['receipts'] and c.snapshot()[0].guest_bytes==512
    monkeypatch.setattr(m.os,'fsync',lambda fd:(events.append(Path(os.readlink('/proc/self/fd/'+str(fd)))),fsync(fd))[1])
    run=r.run;save=store.save
    def check():
        assert path in events and path.parent in events and store.directory in events
        file_at=events.index(path);parent_at=events.index(path.parent,file_at+1)
        root_at=events.index(store.directory,parent_at+1)
        assert events.index(store.directory.parent,root_at+1)>root_at
    def control(argv,**kwargs):check();return run(argv,**kwargs)
    def commit(state):
        if not state['receipts']:check()
        return save(state)
    monkeypatch.setattr(r,'run',control);monkeypatch.setattr(store,'save',commit)
    assert s.retire(req)['phase']=='target_retired' and len(f.controls)==2
    assert (path.read_bytes(),path.stat().st_ino,path.stat().st_mtime_ns)==before


@pytest.mark.parametrize('writer_kind',['recovery','completed'])
@pytest.mark.parametrize('change',['content','symlink','hardlink','writable','replace-file-during-sync','replace-parent-during-sync','replace-store-during-sync'])
def test_equal_retry_verifies_protected_same_file_and_parent_identity(tmp_path,monkeypatch,writer_kind,change):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path)
    parent=store.directory/'identity-fixture';parent.mkdir(mode=0o700);path=parent/'artifact.json';document={'exact':'original'}
    write=(lambda:d.immutable(store,path,document)) if writer_kind=='recovery' else (lambda:store._immutable(path,document))
    write();original=path.read_bytes()
    if change=='content':path.write_text(json.dumps({'exact':'replacement'}))
    elif change=='symlink':path.unlink();other=parent/'other';other.write_bytes(original);path.symlink_to(other)
    elif change=='hardlink':(parent/'other').hardlink_to(path)
    elif change=='writable':path.chmod(0o622)
    else:
        fsync=m.os.fsync;fired=False
        def replace_during_sync(fd):
            nonlocal fired
            endpoint=Path(os.readlink('/proc/self/fd/'+str(fd)))
            selected=path if change=='replace-file-during-sync' else store.directory if change=='replace-store-during-sync' else parent
            if not fired and endpoint==selected:
                fired=True
                if change=='replace-file-during-sync':path.rename(parent/'old');path.write_bytes(original);path.chmod(0o600)
                elif change=='replace-parent-during-sync':parent.rename(store.directory/'old-parent');parent.mkdir(mode=0o700);path.write_bytes(original);path.chmod(0o600)
                else:
                    old=store.directory.parent/'old-store';store.directory.rename(old);store.directory.mkdir(mode=0o700)
                    (old/parent.name).rename(parent)
            return fsync(fd)
        monkeypatch.setattr(m.os,'fsync',replace_during_sync)
    with pytest.raises((m.ResourceError,OSError)):write()
    if change!='content':assert path.read_bytes()==original


def test_full_cold_pool_overcommit_is_exact_root_hold_without_prune_or_native_replay(tmp_path):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path)
    state=store.load();state['grants'][1]['guest_bytes']=c._vm('vm-b').maximum_bytes;store.save(state)
    before=store.state_path.read_bytes();view=s.retire(req)
    assert view==dict(schema='qcl.host-resource-recovery.v1',recovery_id=req.recovery_id,request_id=req.request_id,mutation_id=req.mutation_id,
        host_id=c.policy.host_id,vm_id='vm-a',phase='hold',original_outcome='unknown',charged_bytes=512,
        replacement_native_id=None,failure_code='pool_overcommit',state_generation=d.fingerprint(state),observed_at=100)
    assert store.state_path.read_bytes()==before and store.completed(req.request_id) is None
    assert store.load()['receipts'][0]['phase']=='GROW_UNKNOWN' and len(f.controls)==2
    assert s.retire(req)==view and len(f.controls)==2


def test_reused_native_claim_is_resynced_before_metadata_recovery_without_replay(tmp_path,monkeypatch):
    d,m,c,b,store,e,s,f,r,req=fixture(tmp_path);sync=store._sync_directory
    def fail_proof(directory):
        if Path(directory)==s.directory and s.path(req.recovery_id,'proof').exists():raise OSError('F1 proof publication failure')
        return sync(directory)
    monkeypatch.setattr(store,'_sync_directory',fail_proof)
    with pytest.raises(OSError):s.retire(req)
    assert len(f.controls)==2 and c.snapshot()[0].guest_bytes==512
    monkeypatch.setattr(store,'_sync_directory',sync)
    claim_path=s.path(s._read(req.recovery_id)['stages']['destroy'],'claim');original=claim_path.read_bytes()
    fsync=m.os.fsync
    def fail_claim(fd):
        if Path(os.readlink('/proc/self/fd/'+str(fd)))==claim_path:raise OSError('F1 reused claim fsync failure')
        return fsync(fd)
    monkeypatch.setattr(m.os,'fsync',fail_claim)
    with pytest.raises(OSError,match='reused claim'):s.retire(req)
    assert store.load()['receipts'] and c.snapshot()[0].guest_bytes==512 and len(f.controls)==2
    monkeypatch.setattr(m.os,'fsync',fsync)
    assert s.retire(req)['phase']=='target_retired' and len(f.controls)==2 and claim_path.read_bytes()==original
