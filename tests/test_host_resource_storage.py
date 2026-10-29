"""Production decoder transcripts and real temporary descriptor barriers; no native VM."""
import copy
import json
import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).parents[1]/'ops'))
from host_resource_operations import ResourceError
from host_resource_storage import (decode_live_graph, decode_offline_info, decode_ring_fdinfo,
    PinnedNamespace, decode_binding, decode_install_bundle, decode_qualifications, decode_capture,
    StorageCaptureHandle, LIVE_QUERIES)

FIXTURE=json.loads((Path(__file__).parent/'fixtures/host-resources/synthetic-storage.json').read_text())

def test_pinned_query_transcript_accounts_every_native_node_and_edge():
    graph=decode_live_graph(FIXTURE['replies'],FIXTURE['roots'])
    assert graph['roots']==[{'target':'vda','node_id':'format'}]
    assert graph['edges']==[{'parent':'format','child':'file','role':'file'}]
    assert next(n for n in graph['nodes'] if n['driver']=='file')['file_id']=='/private/inc/root-vda.qcow2'
    assert [q['execute'] for _,q in LIVE_QUERIES]==['query-named-block-nodes','x-debug-query-block-graph','query-block','query-jobs','query-block-jobs']

@pytest.mark.parametrize('damage',['orphan','child_missing','edge_missing','job','qmp_error','external_false','snapshot','direct','unknown_driver','duplicate','missing_required','root_mismatch'])
def test_live_decoder_holds_incomplete_or_unsupported_actual_graph(damage):
    x=copy.deepcopy(FIXTURE)
    r=x['replies']; n=r['named']['return'][0]
    if damage=='orphan':
        orphan=copy.deepcopy(r['named']['return'][1]);orphan['node-name']='orphan';r['named']['return'].append(orphan)
        r['debug']['return']['nodes'].append({'id':4,'type':'block-driver','name':'orphan'})
    elif damage=='child_missing':n.pop('children')
    elif damage=='edge_missing':r['debug']['return']['edges'].pop()
    elif damage=='job':r['jobs']['return']=[{'id':'work','type':'backup','status':'running'}]
    elif damage=='qmp_error':r['named']={'error':{'class':'GenericError','desc':'failed'}}
    elif damage=='external_false':n['image']['format-specific']['data']['data-file-raw']=False
    elif damage=='snapshot':n['image']['snapshots']=[{'id':'1'}]
    elif damage=='direct':n['cache']['direct']=True
    elif damage=='unknown_driver':n['drv']='throttle'
    elif damage=='duplicate':r['named']['return'].append(copy.deepcopy(n))
    elif damage=='missing_required':n.pop('backing_file_depth')
    elif damage=='root_mismatch':x['roots'][0]['backend']='other'
    with pytest.raises(ResourceError):decode_live_graph(r,x['roots'])

def test_offline_is_block_graph_info_with_explicit_leaf_not_guessed_chain():
    info=decode_offline_info(FIXTURE['offline'],'qcow2')
    assert info['backing'] is None
    x=copy.deepcopy(FIXTURE['offline']);x.pop('children')
    with pytest.raises(ResourceError):decode_offline_info(x,'qcow2')
    x=copy.deepcopy(FIXTURE['offline']);x['format-specific']['data']['data-file-raw']=False
    with pytest.raises(ResourceError):decode_offline_info(x,'qcow2')

def test_ring_fdinfo_missing_mutex_trylock_details_is_not_zero():
    assert decode_ring_fdinfo(FIXTURE['ring'])['user_files']==0
    for text in [FIXTURE['ring'].replace('UserFiles:\t0\n',''),FIXTURE['ring'].replace('UserBufs:\t0','UserBufs:\t1'),FIXTURE['ring'].replace('SqThread:\t-1','SqThread:\t5'),FIXTURE['ring'].replace('PollList:\n','PollList:\n  op=22, task_works=0\n')]:
        with pytest.raises(ResourceError):decode_ring_fdinfo(text)

def test_real_descriptor_identity_survives_write_but_rejects_path_replacement(tmp_path):
    directory=tmp_path/'inc';directory.mkdir(mode=0o700);f=directory/'root-vda.raw';f.write_bytes(b'fixture')
    f.chmod(0o600)
    # Explicit synthetic seam: production never accepts a caller-owned trusted root.
    with PinnedNamespace(directory,owner_uid=os.getuid(),synthetic_root=tmp_path) as ns:
        ident=ns.pin(f)
        f.write_bytes(b'guest growth is not a new inode')
        assert ns.validate()==[ident]
        f.rename(directory/'old');f.write_bytes(b'replacement');f.chmod(0o600)
        with pytest.raises(ResourceError):ns.validate()
    assert ns.closed

def test_descriptor_barrier_rejects_hardlink_symlink_and_unknown_permissions(tmp_path):
    d=tmp_path/'inc';d.mkdir(mode=0o700);f=d/'a';f.write_bytes(b'a');f.chmod(0o600)
    with PinnedNamespace(d,owner_uid=os.getuid(),synthetic_root=tmp_path) as ns:
        os.link(f,d/'hard')
        with pytest.raises(ResourceError):ns.pin(f)
        (d/'hard').unlink();(d/'sym').symlink_to(f)
        with pytest.raises((ResourceError,OSError)):ns.pin(d/'sym')
        f.chmod(0o666)
        with pytest.raises(ResourceError):ns.pin(f)

def test_closed_or_deserialized_handle_cannot_authorize_use():
    with pytest.raises(ResourceError):StorageCaptureHandle.from_document({})

def test_boolean_numeric_identity_is_never_integer():
    with pytest.raises(ResourceError):decode_binding({'schema':'qcl.host-resource-storage-binding.v1','dac':{'uid':True,'gid':1}})


def collector_fixture(tmp_path):
    """Actual collector/parser/store/FDs; only native system observations injected.

    This fixture never represents an installed/native qualification. It does not
    replace the collector with a complete/owned flag or mock its use barrier.
    """
    from types import SimpleNamespace
    import host_resource_storage as s
    from host_resource_operations import FileReceiptStore
    directory=tmp_path/'private';directory.mkdir(mode=0o750);disk=directory/'root-vda.qcow2';disk.write_bytes(b'synthetic transcript, no qcow2 execution');disk.chmod(0o600)
    store=FileReceiptStore(tmp_path/'state',owner_uid=os.getuid())
    with PinnedNamespace(directory,owner_uid=os.getuid(),synthetic_root=tmp_path) as ns:
        identity=ns.pin(disk);namespace=dict(path=str(directory),**{k:ns.identity[k] for k in ('device','inode','mount_id')})
    specdisk=dict(target='vda',role='root',format='qcow2',access='rw',**identity,creation_receipt_sha256='c'*64)
    binding=dict(schema=s.BINDING_SCHEMA,host_id='host',owner_id='owner',vm_id='vm',native_uuid='11111111-1111-4111-8111-111111111111',domain_name='fixture',incarnation_id='b'*32,namespace=namespace,dac=dict(uid=os.getuid(),gid=os.getgid()),disks=[specdisk],install_receipt_sha256='a'*64,definition_sha256='d'*64,source_profile_sha256='e'*64)
    # Nonroot CI UIDs satisfy production binding shape; fixture UID 0 isn't a
    # supported per-incarnation UID and must remain rejected there.
    if os.getuid()==0:pytest.skip('fixture requires a nonroot reserved UID; production never uses DAC UID 0')
    qemu=dict(pid=71,start_ticks=7,boot_id='boot');worker=dict(pid=72,start_ticks=8,boot_id='boot');owner=dict(pid=os.getpid(),start_ticks=9,boot_id='boot')
    peer=dict(kind='libvirt_unix',socket_path='/run/libvirt/virtqemud-sock',socket_device=1,socket_inode=2,unit='virtqemud.service',invocation_id='a'*32,daemon_birth=dict(pid=10,start_ticks=1,boot_id='boot'))
    profile=dict(protocol_id=s.LIVE,native_peer_identity=peer,tool_ids={'qemu':dict(path='/protected/qemu',sha256='a'*64)})
    xml=('<domain type="kvm"><name>fixture</name><uuid>'+binding['native_uuid']+'</uuid><memory unit="bytes">1048576</memory><currentMemory unit="bytes">1048576</currentMemory><devices><disk type="file" device="disk"><driver name="qemu" type="qcow2" io="threads" cache="writeback"/><source file="'+str(disk)+'"/><target dev="vda"/><alias name="virtio-disk0"/></disk></devices><seclabel type="static" model="dac" relabel="no"><label>+'+str(os.getuid())+':+'+str(os.getgid())+'</label></seclabel></domain>')
    binding['definition_sha256']=__import__('host_resource_backends').libvirt_config_fingerprint(s.plain_xml(xml))
    replies=json.loads(json.dumps(FIXTURE['replies']).replace('/private/inc/root-vda.qcow2',str(disk)))
    argv=['qemu','-uuid',binding['native_uuid'],'-blockdev',json.dumps({'driver':'file','node-name':'file','filename':str(disk),'aio':'threads','cache':{'direct':False,'no-flush':False}}),'-blockdev',json.dumps({'driver':'qcow2','node-name':'format','file':'file'}),'-device',json.dumps({'driver':'virtio-blk-pci','id':'virtio-disk0','drive':'format'})]
    context=dict(unit='qcl-resource-'+'d'*32+'.service',invocation_id='d'*32,cgroup='/system.slice/qcl-resource-'+'d'*32+'.service',host_boot_id='boot',mutation_id='f'*32)
    runtime={k:'identity' for k in s.RuntimeBinding.__dataclass_fields__};runtime.update(vm_id='vm',native_id=binding['native_uuid'],process_id='71')
    subject=dict(kind='mutation',request_id='request',mutation_id='f'*32,intent_sha256='a'*64,dispatch_sha256='b'*64,host_boot_id='boot',policy_sha256='c'*64,binding=runtime,worker_birth=worker,cli_birth=owner,native_context=context)
    class Sources:
        def inventory(self,b):return dict(domains=[dict(uuid=binding['native_uuid'],state='running',name='fixture',xml_sha256=binding['definition_sha256'])],pools=[])
        def xml(self,native,live=False):return xml
        def live_graph(self,native):return copy.deepcopy(replies)
        def read_binding(self,path):return copy.deepcopy(binding)
        def digest(self,path):return s.hashlib.sha256(Path(path).read_bytes()).hexdigest()
        def process_inventory(self,b,birth=None,**kwargs):
            assert kwargs['own_fds'] and all(os.fstat(fd).st_ino==identity['inode'] for fd in kwargs['own_fds'])
            return dict(records=[dict(birth=qemu,uid=os.getuid())],holders=[dict(birth=qemu,uid=os.getuid(),gid=os.getgid(),cgroup='/machine.slice/fixture.scope',mount_namespace=1,user_namespace=1,refs=[dict(kind='fd',file_id=str(disk),task_birth=qemu,fd=5,access='rw')])],rings=[],raw=[],owner=owner)
    collector=s.LibvirtStorageCollector.__new__(s.LibvirtStorageCollector);collector.c=SimpleNamespace(policy=SimpleNamespace(host_id='host',owner_id='owner',timeouts=SimpleNamespace(request_seconds=60)));collector.store=store;collector.config=dict(bindings=str(store.directory/'native-storage'));collector.sources=Sources();collector.handles={}
    collector.native=SimpleNamespace(birth=lambda pid:qemu if pid==71 else owner,running_digest=lambda pid:'a'*64,claim_process=lambda ctx:(worker,owner),local=SimpleNamespace(read=lambda path:'\0'.join(argv)+'\0'))
    collector._profile=lambda b,kind:(profile,{'limits':{'probe_seconds':30,'max_rings':1}})
    def pin(b):
        ns=PinnedNamespace(directory,owner_uid=os.getuid(),synthetic_root=tmp_path)
        for d in b['disks']:ns.pin(d['path'],d)
        return ns
    collector._pin=pin
    return s,collector,binding,subject,qemu,replies,disk


def test_production_capture_seal_use_and_attached_retirement_join(tmp_path):
    s,c,b,subject,qemu,replies,disk=collector_fixture(tmp_path)
    with c._capture(b,subject,qemu) as handle:
        assert c.seal(handle)==s.fingerprint(handle.observation)
        flat=c.validate_use(handle);assert flat==[dict(path=str(disk),device=disk.stat().st_dev,inode=disk.stat().st_ino,kind='local_regular')]
        attached=c.store._read(c.store.directory/'native-mutations'/(subject['mutation_id']+'.storage.json'))
        assert decode_capture(attached)==handle.observation
        assert attached['native_observation']['query_set']==[q for _,q in LIVE_QUERIES]
        target=dict(subject,storage_devices=flat,target={'uuid':b['native_uuid']},qemu_birth=qemu,native_peer_identity=attached['native_peer_identity'])
        c.validate_retirement(target)
        target['storage_devices'][0]['inode']+=1
        with pytest.raises(ResourceError):c.validate_retirement(target)
    with pytest.raises(ResourceError):c.validate_use(handle)


@pytest.mark.parametrize('race',['graph','path','deadline','unsealed','subject','raw_ref'])
def test_production_final_use_or_retirement_holds_changed_authority(tmp_path,race):
    s,c,b,subject,qemu,replies,disk=collector_fixture(tmp_path)
    with c._capture(b,subject,qemu) as handle:
        if race!='unsealed':c.seal(handle)
        if race=='graph':replies['debug']['return']['edges'].pop()
        elif race=='path':disk.rename(disk.with_suffix('.old'));disk.write_bytes(b'replaced');disk.chmod(0o600)
        elif race=='deadline':handle.deadline=0
        elif race=='subject':handle.observation['subject']['cli_birth']['start_ticks']+=1
        elif race=='raw_ref':
            ref=handle.observation['native_observation']['raw_refs'][0];Path(ref['path']).write_text('{}')
            target=dict(subject,storage_devices=[dict(path=str(disk),device=disk.stat().st_dev,inode=disk.stat().st_ino,kind='local_regular')],target={'uuid':b['native_uuid']},qemu_birth=qemu,native_peer_identity=handle.observation['native_peer_identity'])
            with pytest.raises(ResourceError):c.validate_retirement(target)
            return
        with pytest.raises(ResourceError):c.validate_use(handle)


def test_actual_adapter_uses_only_fixed_owned_qmp_and_offline_argv():
    from types import SimpleNamespace
    from host_resource_storage import NativeStorageSources
    called=[];native='11111111-1111-4111-8111-111111111111'
    def run(argv,**kwargs):called.append(argv);return '{"return":[]}'
    sources=NativeStorageSources(SimpleNamespace(local=None),SimpleNamespace(_run=run),SimpleNamespace(run=run))
    sources.live_graph(native)
    assert [json.loads(a[2]) for a in called]==[q for _,q in LIVE_QUERIES]
    assert all(a[:2]==['qemu-monitor-command',native] for a in called)
    called.clear();sources.offline_info('/private/root.qcow2','qcow2',{'tool_ids':{'qemu_img':{'path':'/protected/qemu-img'}}})
    assert called==[['/protected/qemu-img','info','--output=json','-f','qcow2','--','/private/root.qcow2']]


def test_source_typed_ordinary_ram_and_rng_defaults_do_not_admit_exports():
    from host_resource_storage import decode_launch_objects
    ram={'qom-type':'memory-backend-ram','id':'pc.ram','size':1048576}
    machine={'type':'pc-q35-11.1','memory-backend':'pc.ram','dump-guest-core':'off'}
    rng={'qom-type':'rng-random','id':'rng0','filename':'/dev/urandom'}
    def args(r=ram,m=machine,g=rng):return ['-object',json.dumps(r),'-machine',json.dumps(m),'-object',json.dumps(g)]
    assert set(decode_launch_objects(args()))=={'pc.ram','rng0'}
    for bad in [dict(ram,share=True),dict(ram,**{'qom-type':'memory-backend-memfd'}),dict(ram,**{'guest-memfd':True}),dict(ram,reserve=False),dict(ram,**{'prealloc-context':'helper'})]:
        with pytest.raises(ResourceError):decode_launch_objects(args(r=bad))
    for bad in [dict(machine,**{'confidential-guest-support':'cgs'}),dict(machine,**{'dump-guest-core':'on'}),dict(machine,**{'memory-backend':'foreign'})]:
        with pytest.raises(ResourceError):decode_launch_objects(args(m=bad))
    with pytest.raises(ResourceError):decode_launch_objects(args(g=dict(rng,filename='/private/storage')))


def test_only_source_derived_libvirt_master_key_metadata_object_is_allowed():
    import host_resource_storage as s
    xml=s.plain_xml('<domain id="7"/>');binding=dict(domain_name='ordinary-worker-name-long')
    path=s.master_key_path(xml,binding)
    assert path=='/var/lib/libvirt/qemu/domain-7-ordinary-worker-name/master-key.aes'
    master=dict(**{'qom-type':'secret'},id='masterKey0',format='raw',file=path)
    assert s.decode_launch_objects(['-object',json.dumps(master)],master_key=path)=={'masterKey0':master}
    for bad in [dict(master,id='other'),dict(master,file='/arbitrary/secret'),dict(master,format='base64'),dict(master,data='never-read'),dict(master,keyid='key'),dict(master,iv='iv')]:
        with pytest.raises(ResourceError):s.decode_launch_objects(['-object',json.dumps(bad)],master_key=path)
    with pytest.raises(ResourceError):s.decode_launch_objects(['-object',json.dumps(master)])
    with pytest.raises(ResourceError):s.master_key_path(s.plain_xml('<domain/>'),binding)


def test_runtime_master_key_reader_only_opath_stats_synthetic_metadata(tmp_path,monkeypatch):
    import host_resource_storage as s
    from types import SimpleNamespace
    parent=tmp_path/'domain-7-fixture';parent.mkdir(mode=0o750);path=parent/'master-key.aes';path.write_bytes(b'X'*32);path.chmod(0o600)
    original_open=os.open;opened=[];real_os=os
    class OS:
        def __getattr__(self,name):return getattr(real_os,name)
        def open(self,p,flags,*args,**kw):
            if str(p) in {str(path),'master-key.aes'}:
                assert flags&os.O_PATH and flags&os.O_NOFOLLOW and flags&os.O_CLOEXEC;opened.append(str(p))
            return original_open(p,flags,*args,**kw)
    monkeypatch.setattr(s,'os',OS());monkeypatch.setattr(s,'trusted_root_path',lambda p,**kw:Path(p))
    source=s.NativeStorageSources(SimpleNamespace(local=None),None,None);binding=dict(dac=dict(uid=os.getuid(),gid=os.getgid()));birth=dict(pid=os.getpid())
    metadata=source.master_key_metadata(str(path),binding,birth)
    assert opened==['master-key.aes'] and metadata['size']==32 and metadata['inode']==path.stat().st_ino
    assert set(metadata)=={'path','device','inode','mount_id','uid','gid','mode','nlink','size','parent'}
    path.chmod(0o644)
    with pytest.raises(ResourceError):source.master_key_metadata(str(path),binding,birth)


def test_master_key_is_metadata_not_block_file_and_identity_drift_holds(tmp_path):
    s,c,b,subject,qemu,replies,disk=collector_fixture(tmp_path)
    xml=c.sources.xml(b['native_uuid']);xml=xml.replace('<domain type="kvm">','<domain type="kvm" id="7">');c.sources.xml=lambda *a,**kw:xml
    key=s.master_key_path(s.plain_xml(xml),b);cmdline=c.native.local.read('/synthetic/cmdline').rstrip('\0').split('\0');cmdline+=['-object',json.dumps({'qom-type':'secret','id':'masterKey0','format':'raw','file':key})];c.native.local.read=lambda path:'\0'.join(cmdline)+'\0'
    metadata=dict(path=key,device=1,inode=17,mount_id=1,uid=0,gid=0,mode=0o600,nlink=1,size=32,parent={})
    c.sources.master_key_metadata=lambda *a:copy.deepcopy(metadata)
    with c._capture(b,subject,qemu) as handle:
        c.seal(handle);assert c.validate_use(handle)
        assert [f['path'] for f in handle.observation['files']]==[str(disk)]
        assert any(r['slot']=='master_key_metadata' for r in handle.observation['native_observation']['raw_refs'])
        metadata['inode']+=1
        with pytest.raises(ResourceError):c.validate_use(handle)


def test_closed_schema_matches_production_binding_capture_and_source_profile(tmp_path):
    import jsonschema
    import host_resource_storage as storage
    s,c,b,subject,qemu,replies,disk=collector_fixture(tmp_path)
    schema=json.loads((Path(__file__).parents[1]/'schemas/host-resource-storage.schema.json').read_text())
    def check(value,name):jsonschema.validate(value,{'$schema':schema['$schema'],'$defs':schema['$defs'],'$ref':'#/$defs/'+name})
    check(b,'storageBinding')
    with c._capture(b,subject,qemu) as handle:
        check(handle.observation,'capture')
        bad=copy.deepcopy(handle.observation);bad['files'][0]['inode']=True
        with pytest.raises(jsonschema.ValidationError):check(bad,'capture')
        with pytest.raises(ResourceError):decode_capture(bad)
        bad=copy.deepcopy(handle.observation);bad['native_observation']['complete']=True
        with pytest.raises(jsonschema.ValidationError):check(bad,'capture')
        with pytest.raises(ResourceError):decode_capture(bad)
    ref=dict(path='/protected/source',sha256='a'*64)
    profile=dict(protocol_id=s.LIVE,subject='mutation',binding_sha256=s.fingerprint(b),host_id='host',owner_id='owner',policy_sha256='c'*64,host_boot_id='boot',source_ids={k:dict(ref,sha256=v) for k,v in s.SOURCE_DIGESTS.items()},tool_ids={k:dict(ref) for k in schema['$defs']['toolIds']['required']},native_peer_identity=c._profile(b,'mutation')[0]['native_peer_identity'],host_kernel_id='kernel',filesystem_protocol='linux-btrfs-private-regular-v1',graph_protocol=s.LIVE,holder_protocol=s.HOLDER,dac_protocol='libvirt-12.8.0-static-dac-private-v1',evidence_ref=ref)
    bundle=dict(schema=s.QUAL_SCHEMA,profiles=[profile]);assert decode_qualifications(bundle)==[profile];check(bundle,'qualificationBundle')
    for damage in ('daemon','source','true','subject'):
        bad=copy.deepcopy(bundle)
        if damage=='daemon':bad['profiles'][0]['tool_ids'].pop('libvirt_daemon')
        elif damage=='source':bad['profiles'][0]['source_ids'][next(iter(s.SOURCE_DIGESTS))]['sha256']='0'*64
        elif damage=='true':bad['profiles'][0]['complete']=True
        else:bad['profiles'][0]['subject']='replacement'
        with pytest.raises(ResourceError):decode_qualifications(bad)
        with pytest.raises(jsonschema.ValidationError):check(bad,'qualificationBundle')


def test_install_spec_decoder_rejects_adoption_unknowns_and_duplicate_dac(tmp_path):
    import host_resource_storage as s
    spec=dict(install_id='a'*32,vm_id='vm',native_uuid='11111111-1111-4111-8111-111111111111',domain_name='fresh',incarnation_id='b'*32,namespace_parent='/private/storage',dac=dict(user='qcl_vm_a',group='qcl_vm_a',uid=30001,gid=30001),distribution=dict(bundle='/private/bundle',expected_manifest_sha256='a'*64),disks=[dict(kind='fresh_scratch',target='vdb',role='scratch',format='raw',access='rw',virtual_bytes=1048576)],definition_ref=dict(path='/private/candidate.xml',sha256='a'*64),copy_budget_bytes=2097152,timeout_seconds=30)
    bundle=dict(schema=s.INSTALL_SCHEMA,host_id='host',owner_id='owner',specs=[spec]);assert decode_install_bundle(bundle)==bundle
    for damage in ('uid','unknown','duplicate','path','scratch','distribution'):
        bad=copy.deepcopy(bundle)
        if damage=='uid':bad['specs'][0]['dac']['uid']=True
        elif damage=='unknown':bad['specs'][0]['owned']=True
        elif damage=='duplicate':
            other=copy.deepcopy(spec);other.update(install_id='c'*32,native_uuid='22222222-1111-4111-8111-111111111111',domain_name='other',incarnation_id='d'*32);bad['specs'].append(other)
        elif damage=='path':bad['specs'][0]['namespace_parent']='/private/../foreign'
        elif damage=='scratch':bad['specs'][0]['disks'][0]['access']='ro'
        else:bad['specs'][0]['distribution']['manifest_accepted']=True
        with pytest.raises(ResourceError):decode_install_bundle(bad)


def test_partial_import_intent_cannot_recopy_or_adopt_existing_directory(tmp_path,monkeypatch):
    import host_resource_storage as s
    from types import SimpleNamespace
    from host_resource_operations import FileReceiptStore
    store=FileReceiptStore(tmp_path/'state',owner_uid=os.getuid());bindings=store.directory/'native-storage';bindings.mkdir(mode=0o700)
    spec=dict(install_id='a'*32,namespace_parent=str(tmp_path),incarnation_id='b'*32)
    collector=SimpleNamespace(store=store,config=dict(bindings=str(bindings)))
    monkeypatch.setattr(s,'_spec',lambda c,i:spec);monkeypatch.setattr(s,'_account',lambda c,x:{'synthetic':'account-boundary'});monkeypatch.setattr(s,'_source_profiles',lambda c:{'synthetic':'source-boundary'});monkeypatch.setattr(s,'trusted_root_path',lambda path,**kwargs:Path(path))
    from host_resource_recovery import immutable
    immutable(store,bindings/('a'*32+'.intent.json'),{'schema':'synthetic-already-prepared'})
    # Existing intent blocks before verify/copy/scratch creation. No production
    # adoption seam is exposed by these explicit synthetic preflight sources.
    with pytest.raises(ResourceError,match='reconciliation_required'):s._install_import(collector,'a'*32)
    assert not (tmp_path/('b'*32)).exists()


def test_install_task_inline_python_is_valid_source_and_no_native_actions():
    import ast,yaml
    tasks=yaml.safe_load((Path(__file__).parents[1]/'ansible/tasks/host-resource-storage.yml').read_text())
    for task in tasks:
        if 'ansible.builtin.command' in task:
            argv=task['ansible.builtin.command']['argv'];assert argv[1:3]==['-I','-c'];ast.parse(argv[3])
    source=(Path(__file__).parents[1]/'ansible/tasks/host-resource-storage.yml').read_text()
    assert 'qemu-img' not in source.replace('# SOURCE only: no image copy, qemu-img, define/start, hook, daemon/global policy.','')


def test_binding_uses_existing_c_static_fingerprint_and_only_candidate_normalization(tmp_path):
    from host_resource_backends import libvirt_config_fingerprint
    import host_resource_storage as s
    s,c,b,subject,qemu,replies,disk=collector_fixture(tmp_path)
    original=c.sources.xml(b['native_uuid']);xml=s.plain_xml(original)
    base=libvirt_config_fingerprint(xml);xml.find('currentMemory').text='524288';xml.set('id','9');xml.find('devices/disk/alias').set('name','another-runtime-alias')
    assert libvirt_config_fingerprint(xml)==base==b['definition_sha256']
    for damage in ('memory','maxMemory','DAC','driver','source','feature'):
        changed=s.plain_xml(original)
        if damage=='memory':changed.find('memory').text='2097152'
        elif damage=='maxMemory':s.ET.SubElement(changed,'maxMemory',slots='4',unit='bytes').text='2097152'
        elif damage=='DAC':changed.find('seclabel/label').text='+999:+999'
        elif damage=='driver':changed.find('devices/disk/driver').set('io','native')
        elif damage=='source':changed.find('devices/disk/source').set('file','/foreign')
        else:s.ET.SubElement(changed,'features')
        assert libvirt_config_fingerprint(changed)!=base
    pretty=s.plain_xml(original)
    s.ET.indent(pretty,space='    ')
    for node in pretty.iter():node.attrib=dict(reversed(list(node.attrib.items())))
    assert s._candidate_static(pretty)==s._candidate_static(s.plain_xml(original))


def test_offline_complete_private_backing_chain_and_termination(tmp_path):
    s,c,b,subject,qemu,replies,disk=collector_fixture(tmp_path)
    # Use production offline recursion and decoder with a second real pinned file.
    backing=disk.parent/'backing-vdc.raw';backing.write_bytes(b'synthetic base');backing.chmod(0o440)
    with PinnedNamespace(disk.parent,owner_uid=os.getuid(),synthetic_root=tmp_path) as ns:identity=ns.pin(backing)
    # readonly file owner is Root in production; synthetic IO boundary retains
    # CI ownership, while codec receives the explicit qualified expected identity.
    base=dict(target='vdc',role='backing',format='raw',access='ro',**identity,creation_receipt_sha256='c'*64)
    # Here _observation itself is tested, not published decode_binding (which
    # independently refuses non-Root readonly production ownership).
    b['disks'].append(base);old_inventory=c.sources.inventory
    c.sources.inventory=lambda binding:dict(domains=[dict(uuid=b['native_uuid'],state='shut off',name=b['domain_name'],xml_sha256=b['definition_sha256'])],pools=[])
    info=copy.deepcopy(FIXTURE['offline']);encoded=json.dumps(info).replace('/private/inc/root-vda.qcow2',str(disk));info=json.loads(encoded);info.update({'backing-filename':str(backing),'full-backing-filename':str(backing),'backing-filename-format':'raw'})
    raw_info=dict(filename=str(backing),format='raw',**{'virtual-size':1048576},children=[dict(name='file',info=dict(filename=str(backing),format='file',**{'virtual-size':1048576},children=[]))])
    c.sources.offline_info=lambda path,format,profile:copy.deepcopy(info if path==str(disk) else raw_info)
    owner=c.native.birth(os.getpid());c.sources.process_inventory=lambda *args,**kwargs:dict(records=[],holders=[],rings=[],raw=[],owner=owner)
    with c._pin(b) as ns:
        data=c._observation(b,c._profile(b,'replacement')[0],{'limits':{}},{},ns)
        assert len(data['files'])==2 and {'parent':str(disk),'child':str(backing),'role':'backing'} in data['graph']['edges']
        info['full-backing-filename']='/outside/base'
        with pytest.raises(ResourceError):c._observation(b,c._profile(b,'replacement')[0],{'limits':{}},{},ns)


def test_actual_process_fd_maps_credential_parser_with_real_temporary_inode(tmp_path,monkeypatch):
    """Redirect proc metadata only; no host proc census, ring, KVM or VM probe."""
    import host_resource_storage as s
    from types import SimpleNamespace
    real_path=Path;real_os=os;proc=tmp_path/'synthetic-proc';proc.mkdir();pid=71;base=proc/str(pid);task=base/'task'/str(pid);(task/'fd').mkdir(parents=True);(task/'fdinfo').mkdir()
    disk=tmp_path/'owned.raw';disk.write_bytes(b'temporary FD fixture');st=disk.stat();(task/'fd'/'5').symlink_to(disk);(base/'root').symlink_to('/')
    creds='Uid:\t30001 30001 30001 30001\nGid:\t30001 30001 30001 30001\nGroups:\t30001\nCapEff:\t0000000000000000\n'
    (base/'status').write_text(creds);(task/'status').write_text(creds);(task/'fdinfo'/'5').write_text('pos:\t0\nflags:\t0100002\nmnt_id:\t1\nino:\t'+str(st.st_ino)+'\n')
    (task/'maps').write_text('1000-2000 rw-p 00000000 '+format(os.major(st.st_dev),'x')+':'+format(os.minor(st.st_dev),'x')+' '+str(st.st_ino)+' '+str(disk)+'\n')
    def mapped(path):
        path=str(path)
        return str(proc)+path[5:] if path=='/proc' or path.startswith('/proc/') else path
    class OS:
        def __getattr__(self,name):return getattr(real_os,name)
        def open(self,path,*args,**kw):return real_os.open(mapped(path),*args,**kw)
        def stat(self,path,*args,**kw):return real_os.stat(mapped(path),*args,**kw)
    monkeypatch.setattr(s,'os',OS())
    monkeypatch.setattr(s,'Path',lambda *parts:real_path(mapped(real_path(*parts))))
    boot='synthetic-boot';qemu=dict(pid=pid,start_ticks=1,boot_id=boot)
    native=SimpleNamespace(local=SimpleNamespace(host=lambda:dict(boot_id=boot),process=lambda p:dict(cgroup='/machine.slice/synthetic.scope')),birth=lambda p:dict(pid=p,start_ticks=1,boot_id=boot))
    source=s.NativeStorageSources(native,None,None);source.read=lambda path,limit=s.MAX_OUTPUT_BYTES:real_path(mapped(path)).read_text();source.namespace=lambda p,kind:1
    binding=dict(dac=dict(uid=30001,gid=30001),disks=[dict(path=str(disk),device=st.st_dev,inode=st.st_ino,access='rw')])
    result=source.process_inventory(binding,qemu,limits={'probe_seconds':10,'max_rings':1})
    assert [r['kind'] for r in result['holders'][0]['refs']]==['fd','map']
    assert any(slot=='fds-71' for slot,_ in result['raw'])
    (base/'status').write_text(creds.replace('Groups:\t30001','Groups:\t'))
    (task/'status').write_text(creds.replace('Groups:\t30001','Groups:\t'))
    assert source.process_inventory(binding,qemu,limits={'probe_seconds':10,'max_rings':1})['holders']
    (base/'status').write_text(creds);(task/'status').write_text(creds)
    (task/'fdinfo'/'5').write_text('flags:\t040002\n')
    with pytest.raises(ResourceError,match='buffered'):source.process_inventory(binding,qemu,limits={'probe_seconds':10,'max_rings':1})
    (task/'fdinfo'/'5').write_text('flags:\t02\n');(task/'status').write_text(creds.replace('30001 30001 30001 30001','30001 30001 30001 99999',1))
    with pytest.raises(ResourceError,match='credential'):source.process_inventory(binding,qemu,limits={'probe_seconds':10,'max_rings':1})


@pytest.mark.parametrize('bad_copy',[False,True])
def test_import_real_exclusive_copy_once_complete_retry_and_partial_hold(tmp_path,monkeypatch,bad_copy):
    """Only new temporary synthetic bytes; no VM image or scientific payload."""
    import host_resource_storage as s
    import worker_distribution as wd
    from host_resource_operations import FileReceiptStore
    from types import SimpleNamespace
    bundle=tmp_path/'bundle';bundle.mkdir();artifact=bundle/'fixture.raw';artifact.write_bytes(b'new approved synthetic input')
    original_chown=os.chown;original_fchown=os.fchown;uid=os.getuid();gid=os.getgid();original_ns=PinnedNamespace
    if uid==0:pytest.skip('explicit nonroot temporary writer seam')
    spec=dict(install_id='a'*32,vm_id='vm',native_uuid='11111111-1111-4111-8111-111111111111',domain_name='fresh',incarnation_id='b'*32,namespace_parent=str(tmp_path),dac=dict(user='fixture',group='fixture',uid=uid,gid=gid),distribution=dict(bundle=str(bundle),expected_manifest_sha256='c'*64),disks=[dict(kind='artifact',target='vda',role='root',format='raw',access='rw',file_ref=dict(path='fixture.raw',bytes=artifact.stat().st_size,sha256='0'*64 if bad_copy else s.hashlib.sha256(artifact.read_bytes()).hexdigest()))],definition_ref=dict(path=str(tmp_path/'candidate.xml'),sha256='d'*64),copy_budget_bytes=1024*1024,timeout_seconds=30)
    store=FileReceiptStore(tmp_path/'state',owner_uid=uid);c=SimpleNamespace(store=store,config=dict(bindings=str(store.directory/'native-storage')))
    calls=[]
    def verified(*args,**kwargs):calls.append((args,kwargs));return {'synthetic':'verified-worker-distribution-boundary'}
    monkeypatch.setattr(wd,'verify',verified);monkeypatch.setattr(wd,'shape',lambda m:{'fixture.raw':spec['disks'][0]['file_ref']})
    monkeypatch.setattr(s,'_spec',lambda c,i:spec);monkeypatch.setattr(s,'_account',lambda c,x:{'synthetic':'new-account-receipt'});monkeypatch.setattr(s,'_source_profiles',lambda c:{'synthetic':'source-boundary'});monkeypatch.setattr(s,'trusted_root_path',lambda path,**kwargs:Path(path))
    monkeypatch.setattr(s,'PinnedNamespace',lambda path:original_ns(path,owner_uid=uid,synthetic_root=tmp_path))
    monkeypatch.setattr(s.os,'chown',lambda path,u,g:original_chown(path,uid if u==0 else u,g))
    monkeypatch.setattr(s.os,'fchown',lambda fd,u,g:original_fchown(fd,uid if u==0 else u,g))
    if bad_copy:
        with pytest.raises(ResourceError,match='digest'):s._install_import(c,spec['install_id'])
        partial=tmp_path/spec['incarnation_id']/'root-vda.raw';assert partial.exists()
        before=partial.read_bytes()
        with pytest.raises(ResourceError,match='reconciliation_required'):s._install_import(c,spec['install_id'])
        assert partial.read_bytes()==before and len(calls)==1
    else:
        complete=s._install_import(c,spec['install_id']);copied=Path(complete['disks'][0]['path']);assert copied.read_bytes()==artifact.read_bytes()
        assert copied.stat().st_ino!=artifact.stat().st_ino and len(calls)==1
        assert s._install_import(c,spec['install_id'])==complete and len(calls)==1
        copied.rename(copied.with_suffix('.old'));copied.write_bytes(b'different inode');copied.chmod(0o600)
        with pytest.raises(ResourceError):s._install_import(c,spec['install_id'])


def test_native_case_cannot_be_reused_across_binding_or_query_subject():
    import host_resource_storage as s
    p=dict(source_ids={},tool_ids={},filesystem_protocol='fixture',holder_protocol=s.HOLDER,dac_protocol='fixture',binding_sha256='a'*64,subject='mutation')
    host=dict(boot_id='boot',kernel='kernel');case=dict(schema='qcl.host-resource-storage-native-case.v1',case='N-H2',result='pass',host_boot_id='boot',host_kernel_id='kernel',source_profile_sha256=s.source_profile_digest(p),binding_sha256=p['binding_sha256'],subject=p['subject'],evidence_refs=[dict(path='/protected/native-evidence',sha256='b'*64)])
    assert s.decode_native_case(case,'N-H2',p,host)==case
    import jsonschema
    schema=json.loads((Path(__file__).parents[1]/'schemas/host-resource-storage.schema.json').read_text())
    jsonschema.validate(case,{'$defs':schema['$defs'],'$ref':'#/$defs/nativeCase'})
    replacement=dict(p,binding_sha256='c'*64,subject='replacement');other=dict(case,binding_sha256='c'*64,subject='replacement')
    assert s.decode_native_case(other,'N-H2',replacement,host)==other
    for changed in [dict(case,binding_sha256='c'*64),dict(case,subject='replacement'),dict(case,result='not_measured'),dict(case,host_boot_id='other'),dict(case,source_profile_sha256='0'*64)]:
        with pytest.raises(ResourceError):s.decode_native_case(changed,'N-H2',p,host)


def test_creation_account_receipt_does_not_admit_another_primary_group_member(monkeypatch):
    import host_resource_storage as s
    from types import SimpleNamespace
    spec=dict(install_id='a'*32,dac=dict(user='owned',group='owned',uid=30001,gid=30001));receipt=dict(schema='qcl.host-resource-storage-account.v1',install_id='a'*32,spec_sha256=s.fingerprint(spec),dac=spec['dac'])
    account=SimpleNamespace(pw_name='owned',pw_uid=30001,pw_gid=30001,pw_dir='/nonexistent',pw_shell='/usr/bin/nologin');group=SimpleNamespace(gr_name='owned',gr_gid=30001,gr_mem=[])
    others=[];monkeypatch.setattr(s.pwd,'getpwnam',lambda name:account);monkeypatch.setattr(s.pwd,'getpwall',lambda:[account,*others]);monkeypatch.setattr(s.grp,'getgrnam',lambda name:group);monkeypatch.setattr(s.grp,'getgrall',lambda:[group])
    c=SimpleNamespace(store=SimpleNamespace(_read=lambda path:receipt),config=dict(bindings='/protected/native-storage'))
    assert s._account(c,spec)==receipt
    others.append(SimpleNamespace(pw_name='foreign',pw_uid=30002,pw_gid=30001))
    with pytest.raises(ResourceError):s._account(c,spec)


@pytest.mark.parametrize('autostart_once',['disable','enable',None])
def test_primary_inventory_cli_labels_are_strict_and_never_refresh(autostart_once):
    import host_resource_storage as s
    from types import SimpleNamespace
    native='11111111-1111-4111-8111-111111111111';pool='22222222-1111-4111-8111-111111111111';calls=[]
    xml='<domain><name>owned</name><uuid>'+native+'</uuid></domain>'
    info='Managed save: no\nAutostart: disable\n'+('Autostart Once: '+autostart_once+'\n' if autostart_once else '')
    def run(argv):
        calls.append(argv)
        values={('list','--all','--uuid'):native,('dumpxml',native,'--inactive'):xml,('domstate',native):'shut off',('dominfo',native):info,('snapshot-list',native,'--name'):'',('domjobinfo',native):'Job type: None',('pool-list','--all','--uuid'):pool,('pool-dumpxml',pool):'<pool type="dir"><uuid>'+pool+'</uuid><target><path>/foreign-pool</path></target></pool>',('vol-list','--pool',pool):' Name Path\n--------------------\n foreign /foreign-pool/foreign.raw\n'}
        assert tuple(argv) in values;return values[tuple(argv)]
    sources=s.NativeStorageSources(SimpleNamespace(local=None),SimpleNamespace(_run=run),None);binding=dict(native_uuid=native,domain_name='owned',namespace={'path':'/owned/private'})
    if autostart_once=='disable':assert sources.inventory(binding)['pools'][0]['volumes']==[['foreign','/foreign-pool/foreign.raw']]
    else:
        with pytest.raises(ResourceError,match='autostart'):sources.inventory(binding)
    assert not any('refresh' in arg for argv in calls for arg in argv)


def _launch_change(collector,node,key,value):
    argv=collector.native.local.read('/proc/71/cmdline').rstrip('\0').split('\0')
    for i,arg in enumerate(argv[:-1]):
        if arg=='-blockdev':
            item=json.loads(argv[i+1])
            if item['node-name']==node:item[key]=value;argv[i+1]=json.dumps(item)
    collector.native.local.read=lambda path:'\0'.join(argv)+'\0'


@pytest.mark.parametrize('node,key,value',[
    ('format','driver','raw'),('format','read-only',True),('file','read-only',True),
    ('format','read-only',0),('format','read-only','false'),('file','auto-read-only','true'),
    ('format','backing','file'),('format','backing',False),
    ('file','cache',{'direct':False,'no-flush':False,'unknown':False}),
    ('format','cache',{'direct':True}),('format','discard','sometimes'),
])
def test_launch_node_facts_cannot_contradict_native_graph_or_binding(tmp_path,node,key,value):
    # QMP/XML/creation facts stay unchanged; only actual argv differs.
    s,c,b,subject,qemu,replies,disk=collector_fixture(tmp_path)
    _launch_change(c,node,key,value)
    with pytest.raises(ResourceError):c._capture(b,subject,qemu)


@pytest.mark.parametrize('variant',['defaults','explicit-false','file-auto','format-cache-defaults','explicit-null-backing','alias'])
def test_launch_source_defaults_and_aliases_preserve_healthy_capture_and_final_use(tmp_path,variant):
    s,c,b,subject,qemu,replies,disk=collector_fixture(tmp_path)
    if variant=='explicit-false':
        _launch_change(c,'format','read-only',False);_launch_change(c,'file','read-only',False)
    elif variant=='file-auto':_launch_change(c,'file','auto-read-only',True)
    elif variant=='format-cache-defaults':_launch_change(c,'format','cache',{})
    elif variant=='explicit-null-backing':_launch_change(c,'format','backing',None)
    elif variant=='alias':
        new_xml=c.sources.xml(b['native_uuid']).replace('virtio-disk0','scsi-disk99');c.sources.xml=lambda *args,**kwargs:new_xml
        replies['debug']['return']['nodes'][0]['name']='scsi-disk99';replies['block']['return'][0]['qdev']='scsi-disk99'
        argv=c.native.local.read('/proc/71/cmdline').replace('virtio-disk0','scsi-disk99');c.native.local.read=lambda path:argv
    with c._capture(b,subject,qemu) as handle:
        c.seal(handle)
        assert c.validate_use(handle)==[dict(path=str(disk),device=disk.stat().st_dev,inode=disk.stat().st_ino,kind='local_regular')]


def _private_live_chain(tmp_path):
    """Real private files + independent native chain. Like the existing offline
    backing fixture, RO files keep CI ownership; this is never Root DAC admission.
    Original single-file fixture/native oracle are unchanged.
    """
    s,c,b,subject,qemu,replies,disk=collector_fixture(tmp_path)
    middle=disk.parent/'middle.qcow2';tail=disk.parent/'tail.raw'
    for target,path,format in [('vdb',middle,'qcow2'),('vdc',tail,'raw')]:
        path.write_bytes(b'synthetic private backing');path.chmod(0o440)
        with PinnedNamespace(disk.parent,owner_uid=os.getuid(),synthetic_root=tmp_path) as ns:identity=ns.pin(path)
        b['disks'].append(dict(target=target,role='backing',format=format,access='ro',**identity,creation_receipt_sha256='c'*64))
    root=replies['named']['return'][0];root['children'].append({'child':'backing','node-name':'middle-format'})
    root['backing_file']=str(middle);root['backing_file_depth']=2
    root['image'].update({'backing-filename':str(middle),'full-backing-filename':str(middle),'backing-filename-format':'qcow2'})
    def node(name,driver,path,children,depth=0):
        n=copy.deepcopy(FIXTURE['replies']['named']['return'][1 if driver=='file' else 0])
        n.update({'node-name':name,'drv':driver,'ro':True,'file':str(path),'children':children,'backing_file_depth':depth})
        n['image']={'filename':str(path),'format':driver,'virtual-size':1048576}
        if driver=='qcow2':n['image']['format-specific']=copy.deepcopy(root['image']['format-specific'])
        return n
    mid=node('middle-format','qcow2',middle,[{'child':'file','node-name':'middle-file'},{'child':'backing','node-name':'tail-format'}],1)
    mid['backing_file']=str(tail);mid['image'].update({'backing-filename':str(tail),'full-backing-filename':str(tail),'backing-filename-format':'raw'})
    replies['named']['return']+=[mid,node('middle-file','file',middle,[]),node('tail-format','raw',tail,[{'child':'file','node-name':'tail-file'}]),node('tail-file','file',tail,[])]
    debug=replies['debug']['return'];debug['nodes']+=[dict(id=i,type='block-driver',name=name) for i,name in [(4,'middle-format'),(5,'middle-file'),(6,'tail-format'),(7,'tail-file')]]
    debug['edges']+=[dict(parent=a,child=z,name=role,perm=['consistent-read'],**{'shared-perm':['consistent-read','write-unchanged']}) for a,z,role in [(2,4,'backing'),(4,5,'file'),(4,6,'backing'),(6,7,'file')]]
    replies['block']['return'][0]['inserted']=copy.deepcopy(root)
    original=c.native.local.read('/proc/71/cmdline').rstrip('\0').split('\0');argv=original[:3]
    # Children precede their parents, as actual blockdev-add references require.
    # Ordinary libvirt protocol auto-RO; effective RO formats are explicit.
    for name,driver,path,file,backing in [('middle-file','file',middle,None,None),('tail-file','file',tail,None,None),('tail-format','raw',tail,'tail-file',None),('middle-format','qcow2',middle,'middle-file','tail-format')]:
        item={'driver':driver,'node-name':name}
        if driver=='file':item.update(filename=str(path),aio='threads',cache={'direct':False,'no-flush':False},**{'auto-read-only':True})
        else:
            item.update(file=file,**{'read-only':True})
            if driver=='qcow2':item['backing']=backing
        argv+=['-blockdev',json.dumps(item)]
    argv+=original[3:]
    c.native.local.read=lambda path:'\0'.join(argv)+'\0';_launch_change(c,'format','backing','middle-format')
    def holders(binding,birth=None,**kwargs):
        assert {(os.fstat(fd).st_dev,os.fstat(fd).st_ino) for fd in kwargs['own_fds']}=={(d['device'],d['inode']) for d in binding['disks']}
        return dict(records=[dict(birth=qemu,uid=os.getuid())],holders=[dict(birth=qemu,uid=os.getuid(),gid=os.getgid(),cgroup='/machine.slice/fixture.scope',mount_namespace=1,user_namespace=1,refs=[dict(kind='fd',file_id=d['path'],task_birth=qemu,fd=i+5,access=d['access']) for i,d in enumerate(binding['disks'])])],rings=[],raw=[],owner=c.native.birth(os.getpid()))
    c.sources.process_inventory=holders
    return s,c,b,subject,qemu,replies,disk,middle,tail


@pytest.mark.parametrize('protocol_access',['auto','explicit-readonly'])
def test_launch_all_private_backing_nodes_and_protocol_auto_readonly_are_joined(tmp_path,protocol_access):
    s,c,b,subject,qemu,replies,disk,middle,tail=_private_live_chain(tmp_path)
    if protocol_access=='explicit-readonly':
        for name in ('middle-file','tail-file'):
            _launch_change(c,name,'read-only',True);_launch_change(c,name,'auto-read-only',False)
    with c._capture(b,subject,qemu) as handle:
        c.seal(handle)
        assert {n['id'] for n in handle.observation['graph']['nodes']}=={'format','file','middle-format','middle-file','tail-format','tail-file'}
        assert handle.observation['graph']['edges']==[
            {'parent':'format','child':'file','role':'file'},
            {'parent':'format','child':'middle-format','role':'backing'},
            {'parent':'middle-format','child':'middle-file','role':'file'},
            {'parent':'middle-format','child':'tail-format','role':'backing'},
            {'parent':'tail-format','child':'tail-file','role':'file'}]
        assert {f['path'] for f in handle.observation['files']}=={str(disk),str(middle),str(tail)}


@pytest.mark.parametrize('damage',['middle-driver','tail-driver','middle-access','backing-edge','middle-file-edge','file-path-swap','missing-backing-edge'])
def test_launch_every_backing_node_edge_and_path_must_match_native_chain(tmp_path,damage):
    s,c,b,subject,qemu,replies,disk,middle,tail=_private_live_chain(tmp_path)
    if damage=='middle-driver':_launch_change(c,'middle-format','driver','raw')
    elif damage=='tail-driver':_launch_change(c,'tail-format','driver','qcow2')
    elif damage=='middle-access':_launch_change(c,'middle-format','read-only',False)
    elif damage=='backing-edge':_launch_change(c,'format','backing','tail-format')
    elif damage=='middle-file-edge':_launch_change(c,'middle-format','file','tail-file')
    elif damage=='file-path-swap':
        _launch_change(c,'middle-file','filename',str(tail));_launch_change(c,'tail-file','filename',str(middle))
    else:_launch_change(c,'middle-format','backing',None)
    with pytest.raises(ResourceError):c._capture(b,subject,qemu)


@pytest.mark.parametrize('node,key,value',[('format','driver','raw'),('format','read-only',True),('file','read-only',True),('format','backing','file')])
def test_launch_contradiction_appearing_only_at_final_use_cannot_return_projection(tmp_path,node,key,value):
    s,c,b,subject,qemu,replies,disk=collector_fixture(tmp_path)
    with c._capture(b,subject,qemu) as handle:
        c.seal(handle);_launch_change(c,node,key,value)
        with pytest.raises(ResourceError):c.validate_use(handle)
