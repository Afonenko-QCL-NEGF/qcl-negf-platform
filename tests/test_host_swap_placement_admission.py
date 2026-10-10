"""Literal independent mapping/ancestor/isolation vectors, no native discovery."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

BASE=Path(__file__).resolve().parents[1]


def encoded(value):return json.dumps(value,sort_keys=True,separators=(',', ':'),ensure_ascii=False,allow_nan=False).encode()
def hashed(value):return hashlib.sha256(encoded(value)).hexdigest()
def ordered(values):return sorted(values,key=encoded)


def validator():
    spec=importlib.util.spec_from_file_location('placement_oracle',BASE/'ops/host_swap_placement_admission.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def fixture(cfg):
    h=copy.deepcopy(cfg);w=h['swap'];life='protected-host-infrastructure';host='mnt:[fixture-host]'
    old=[dict(name='/dev/mapper/old-swap',type='partition',size=8388608,prio=-2,identity=dict(kind='block',rdev=[253,1]))]
    fragment='[Unit]\nDescription=Protected additive host swap\nRequiresMountsFor='+w['mount']['path']+' '+w['path']+'\nConditionPathIsMountPoint='+w['mount']['path']+'\n\n[Swap]\nWhat='+w['path']+'\nTimeoutSec='+str(w['budgets']['activation_seconds'])+'\n\n[Install]\nWantedBy=swap.target\n'
    context=dict(schema='qcl.host-swap.context.v2',host_id=h['host_id'],path=w['path'],parent=w['parent'],target_bytes=w['target_mib']*1048576,page_bytes=w['support']['page_bytes'],header_uuid=w['header_uuid'],lifetime=life,final_mount=dict(path=w['mount']['path'],unit=w['mount']['unit'],fs_uuid=w['mount']['fs_uuid'],device_rdev=[253,4],lv_uuid=w['mount']['lv_uuid'],vg_uuid=w['mount']['vg_uuid'],pool_uuid=w['mount']['pool_uuid']),unit_declaration=dict(name=w['unit'],fragment_path='/etc/systemd/system/'+w['unit'],fragment_sha256=hashlib.sha256(fragment.encode()).hexdigest(),timeout_usec=w['budgets']['activation_seconds']*1000000),original_swaps=old)
    identity=dict(source=h['accepted_source'],host_id=h['host_id'],boot_id=h['boot_id'],attempt_id=h['attempt_id'],operation_owner=h['admission']['operation_owner'],admission_receipt=h['admission']['receipt'],original_receipt=h['original_receipt'],expires_at_epoch=h['admission']['expires_at_epoch'],cutover_receipt=w['mount']['cutover_receipt'])
    window=dict(held=True,owner=h['attempt_id'],expires_at_epoch=h['admission']['expires_at_epoch'],scope=['file-content','cached-workers','direct-paths','hooks','vm-transitions','automation'])
    evidence=ordered([dict(id=name,kind=kind,sha256=char*64) for name,kind,char in [('block','block-topology','b'),('lvm','lvm','c'),('support','native-support','d'),('thin','native-thin-mapping','e')]])
    ids=['block','lvm','support','thin']
    def node(name,kind,rdev,**kw):
        return dict(id=name,kind=kind,rdev=rdev,device_class=None,device_id=None,pv_uuid=None,lv_uuid=None,vg_uuid=None,pool_uuid=None,fs_uuid=None,thin_id=None,evidence_ids=ids.copy(),**{})|kw
    nodes=ordered([
        node('disk','device',[8,16],device_class='disk',device_id='native-disk'),
        node('pv','device',[8,17],device_class='partition',device_id='native-partition',pv_uuid='pv-id',vg_uuid='vg-id'),
        node('data','lvm-lv',[253,2],lv_uuid='data-lv',vg_uuid='vg-id'),
        node('meta','lvm-lv',[253,3],lv_uuid='meta-lv',vg_uuid='vg-id'),
        node('pool','thin-pool',[253,5],lv_uuid='pool-id',vg_uuid='vg-id',pool_uuid='pool-id'),
        node('image','lvm-lv',[253,4],lv_uuid=w['mount']['lv_uuid'],vg_uuid=w['mount']['vg_uuid'],pool_uuid=w['mount']['pool_uuid'],fs_uuid=w['mount']['fs_uuid'],thin_id=10),
        node('peer','lvm-lv',[253,6],lv_uuid='foreign-peer',vg_uuid='vg-id',pool_uuid='pool-id',thin_id=11),
        node('root-disk','device',[8,0],device_class='disk',device_id='native-root-disk'),
        node('root-fs','device',[8,1],device_class='partition',device_id='native-root-partition',fs_uuid='root-fs-id'),
        node('unrelated','device',[9,0],device_class='disk',device_id='native-other-disk'),
    ])
    edges=ordered([{'from':a,'to':b,'kind':kind,'evidence_ids':ids.copy()} for a,b,kind in [('disk','pv','partition'),('pv','data','mapping'),('pv','meta','mapping'),('data','pool','thin-data'),('meta','pool','thin-metadata'),('pool','image','thin-volume'),('pool','peer','thin-volume'),('root-disk','root-fs','partition')]])
    graph=dict(protected_node_id='image',nodes=nodes,edges=edges,isolated_peers=[dict(node_id='peer',protection='kernel-thin-id-isolation',evidence_ids=['support','thin'])])
    receipt=dict(schema='qcl.host-swap.backing-capture.v1',accepted=True,complete=True,identity_sha256=hashed(identity),window_sha256=hashed(window),context_sha256=hashed(context),graph_sha256=hashed(graph),evidence=evidence)
    excluded=dict(final_filesystem=dict(mount_path=w['mount']['path'],mount_unit=w['mount']['unit'],fs_uuid=w['mount']['fs_uuid'],rdev=[253,4],lv_uuid=w['mount']['lv_uuid'],vg_uuid=w['mount']['vg_uuid'],pool_uuid=w['mount']['pool_uuid'],lifetime=life),parent=dict(path=w['parent'],lifetime=life),file=dict(path=w['path'],lifetime=life),receipts=dict(path=w['receipts'],lifetime=life),unit=dict(name=w['unit'],fragment_path='/etc/systemd/system/'+w['unit'],lifetime=life),placement_admission=dict(path=w['placement_admission']['path'],lifetime=life))
    configurations=[dict(kind='storage',id='local',sha256='f'*64)]
    record=dict(schema='qcl.host-swap.placement-admission.v1',accepted=True,identity=identity,context_sha256=hashed(context),receipts=w['receipts'],window=window,pve=dict(complete=True,configuration_frozen=True,configuration_set_sha256=hashed(configurations),configurations=configurations,managed_roots=[],volume_references=[],absolute_references=[],backing_references=[]),consumers=dict(complete=True,namespace_complete=True,host_namespace=host,scope=['fd','cwd','root','maps','loop-backing','mount-namespaces','direct-paths','hooks','automation'],mount_namespaces=[dict(id=host,representative_pid=1,view_sha256='a'*64,complete=True)],references=[],aliases=[]),wipe=dict(complete=True,d04_accepted=True,d04_receipt_sha256='c'*64,executor_sha256='d'*64,exact_set_sha256=hashed([]),targets=[],excluded=excluded),backing=dict(receipt=receipt,receipt_sha256=hashed(receipt),**graph))
    expected=dict(h=h,w=w,attempt_id=h['attempt_id'],context_sha256=hashed(context),fs_pair=[253,4],fragment_path='/etc/systemd/system/'+w['unit'],host_namespace=host,protected_objects=protected_frame(w))
    refresh(record,expected)
    return record,expected


def protected_frame(w,state=None):
    state=state or {};mount=w['mount']['path'];fragment='/etc/systemd/system/'+w['unit'];admission=w['placement_admission']['path']
    paths=[admission,w['parent'],w['path'],w['receipts'],fragment]
    parents=[str(Path(path).parent) for path in paths]
    existence=[True,state.get('parent_exists',False),state.get('exists',False),state.get('receipts_exists',False),state.get('unit_exists',False)]
    devices=[[8,1],[253,4],[253,4],[8,1],[8,1]]
    inodes=[100,80,state.get('file',{}).get('inode',81),90,99];nearest=[admission,mount,mount,parents[3],parents[4]]
    ancestor_inodes=[100,84,84,91,92]
    frame=[]
    for index,path in enumerate(paths):
        frame.append(dict(path=path,observed_path=path if existence[index] else nearest[index],exists=existence[index],device=devices[index],inode=inodes[index] if existence[index] else ancestor_inodes[index]))
    for index,path in enumerate(parents):
        exists=index!=2 or existence[1]
        frame.append(dict(path=path,observed_path=path if exists else mount,exists=exists,device=[[8,1],[253,4],[253,4],[8,1],[8,1]][index],inode=[91,84,80 if exists else 84,91,92][index]))
    return frame


def refresh(record,expected):
    b=record['backing'];graph={k:b[k] for k in ('protected_node_id','nodes','edges','isolated_peers')}
    b['receipt']['graph_sha256']=hashed(graph);b['receipt']['identity_sha256']=hashed(record['identity']);b['receipt']['window_sha256']=hashed(record['window']);b['receipt_sha256']=hashed(b['receipt'])
    record['wipe']['exact_set_sha256']=hashed(record['wipe']['targets'])
    expected['w']['placement_admission']['sha256']=hashlib.sha256(encoded(record)).hexdigest()


def location(path,relative,*,dev=(253,4),namespace='mnt:[fixture-host]',exists=False,inode=None,mount=None,fsroot='/'):
    return dict(namespace_id=namespace,path=path,device=list(dev),mount_target=path if mount is None else mount,fsroot=fsroot,root_relative_path=relative,exists=exists,inode=inode)


def run(record,expected,cap=256):return validator().validate(encoded(record),expected,maximum_bytes=16384,maximum_entries=cap)


@pytest.fixture
def admitted():
    from test_proxmox_host_swap_contract import settings
    cfg=settings();cfg['swap'].update(path='/var/lib/vz/protected-swap/swapfile',parent='/var/lib/vz/protected-swap');cfg['swap']['mount']['path']='/var/lib/vz'
    return fixture(cfg)


@pytest.mark.parametrize('where,dev',[('pve',[253,4]),('pve',[8,16]),('pve',[8,17]),('pve',[253,2]),('pve',[253,3]),('pve',[253,5]),('wipe',[253,4]),('wipe',[8,16]),('wipe',[8,17]),('wipe',[253,2]),('wipe',[253,3]),('wipe',[253,5])])
def test_raw_image_and_different_rdev_ancestors_refuse(admitted,where,dev):
    record,expected=admitted
    if where=='pve':record['pve']['backing_references']=[dict(id='literal-raw',origin='foreign raw slot',resource=dict(kind='block',rdev=dev))]
    else:record['wipe']['targets']=[dict(id='literal-wipe',resource=dict(kind='block',rdev=dev))]
    refresh(record,expected)
    with pytest.raises(ValueError,match='raw ancestor'):run(record,expected)


@pytest.mark.parametrize('where,dev',[('pve',[9,0]),('pve',[253,6]),('wipe',[9,0]),('wipe',[253,6])])
def test_disjoint_disk_and_explicitly_isolated_peer_allow(admitted,where,dev):
    record,expected=admitted
    if where=='pve':record['pve']['volume_references']=[dict(id='literal-other',origin='independent foreign slot',resource=dict(kind='block',rdev=dev))]
    else:record['wipe']['targets']=[dict(id='literal-other-wipe',resource=dict(kind='block',rdev=dev))]
    refresh(record,expected);assert run(record,expected)['entry_count']<=256


@pytest.mark.parametrize('case',['images','snippets','custom','alias','same-inode','neighbor'])
def test_component_physical_paths_have_independent_outcomes(admitted,case):
    record,expected=admitted
    path={'images':'/var/lib/vz','snippets':'/var/lib/vz/protected-swap','custom':'/var/lib/vz/protected-swap','alias':'/elsewhere','same-inode':'/disjoint','neighbor':'/var/lib/vz2'}[case]
    relative={'images':'/','snippets':'/protected-swap','custom':'/protected-swap','alias':'/protected-swap','same-inode':'/disjoint','neighbor':'/protected-swap-extra'}[case]
    loc=location(path,relative,fsroot=relative)
    if case=='same-inode':
        loc.update(exists=True,inode=81);expected['protected_objects'][2].update(exists=True,observed_path=expected['w']['path'],inode=81)
    record['pve']['managed_roots']=[dict(storage_id='native-local',content_type=case,location=loc)];refresh(record,expected)
    if case=='neighbor':assert run(record,expected)
    else:
        with pytest.raises(ValueError):run(record,expected)


@pytest.mark.parametrize('case',['missing-isolation','same-thin-id','unknown-endpoint','reversed-edge','incomplete-parent','graph-hash','receipt-hash','identity-hash','window-hash','closed-window','wrong-source','wrong-host','wrong-boot','wrong-owner','wrong-expiry','wrong-context','unknown-namespace','mapping-algebra','duplicate-id','noncanonical-path','bool-integer','incomplete-pve','incomplete-consumers','incomplete-wipe','consumer','missing-exclusion','wrong-sha','entry-cap'])
def test_strict_typed_hash_and_capture_refusals(admitted,case):
    record,expected=admitted;b=record['backing']
    if case=='missing-isolation':b['isolated_peers']=[];record['pve']['volume_references']=[dict(id='peer',origin='foreign',resource=dict(kind='block',rdev=[253,6]))]
    elif case=='same-thin-id':next(n for n in b['nodes'] if n['id']=='peer')['thin_id']=10;b['nodes']=ordered(b['nodes'])
    elif case=='unknown-endpoint':b['edges'][0]['to']='unknown';b['edges']=ordered(b['edges'])
    elif case=='reversed-edge':b['edges'][0]['from'],b['edges'][0]['to']=b['edges'][0]['to'],b['edges'][0]['from'];b['edges']=ordered(b['edges'])
    elif case=='incomplete-parent':b['edges']=[e for e in b['edges'] if e['kind']!='thin-metadata']
    elif case=='closed-window':record['window']['held']=False
    elif case.startswith('wrong-') and case not in ('wrong-context','wrong-sha'):
        key={'wrong-source':'source','wrong-host':'host_id','wrong-boot':'boot_id','wrong-owner':'operation_owner','wrong-expiry':'expires_at_epoch'}[case];record['identity'][key]=201 if key=='expires_at_epoch' else 'foreign'
    elif case=='wrong-context':record['context_sha256']='0'*64
    elif case in ('unknown-namespace','mapping-algebra','noncanonical-path'):
        loc=location('/disjoint','/disjoint',fsroot='/disjoint')
        if case=='unknown-namespace':loc['namespace_id']='missing'
        elif case=='mapping-algebra':loc['root_relative_path']='/unrelated'
        else:loc['path']='/bad/../disjoint'
        record['pve']['managed_roots']=[dict(storage_id='local',content_type='custom',location=loc)]
    elif case=='duplicate-id':b['nodes'][1]['id']=b['nodes'][0]['id'];b['nodes']=ordered(b['nodes'])
    elif case=='bool-integer':b['nodes'][0]['rdev'][1]=False;b['nodes']=ordered(b['nodes'])
    elif case.startswith('incomplete-'):record[{'incomplete-pve':'pve','incomplete-consumers':'consumers','incomplete-wipe':'wipe'}[case]]['complete']=False
    elif case=='consumer':record['consumers']['references']=[dict(id='fd1',origin='fd',resource=dict(kind='block',rdev=[253,4]))]
    elif case=='missing-exclusion':record['wipe']['excluded'].pop('unit')
    refresh(record,expected)
    if case in ('graph-hash','receipt-hash','identity-hash','window-hash'):
        if case=='receipt-hash':b['receipt_sha256']='0'*64
        else:b['receipt'][{'graph-hash':'graph_sha256','identity-hash':'identity_sha256','window-hash':'window_sha256'}[case]]='0'*64;b['receipt_sha256']=hashed(b['receipt'])
        expected['w']['placement_admission']['sha256']=hashlib.sha256(encoded(record)).hexdigest()
    if case=='wrong-sha':expected['w']['placement_admission']['sha256']='0'*64
    with pytest.raises(ValueError):run(record,expected,cap=1 if case=='entry-cap' else 256)


@pytest.mark.parametrize('case',['duplicate-json','float','newline'])
def test_canonical_raw_encoding_refuses(admitted,case):
    record,expected=admitted;raw=encoded(record)
    if case=='duplicate-json':raw=raw.replace(b'{',b'{"accepted":true,',1)
    elif case=='float':raw=raw.replace(b'"representative_pid":1',b'"representative_pid":1.0')
    else:raw+=b'\n'
    expected['w']['placement_admission']['sha256']=hashlib.sha256(raw).hexdigest()
    with pytest.raises(ValueError):validator().validate(raw,expected,maximum_bytes=16384,maximum_entries=256)


@pytest.mark.parametrize('object_index',range(10))
def test_every_metadata_carrier_and_absent_support_refuses_root_wipe(admitted,object_index):
    record,expected=admitted
    # Final image is on disk8:16; root FS8:1 is on disjoint disk8:0.
    record['wipe']['targets']=[dict(id='root-fs-wipe',resource=dict(kind='block',rdev=[8,1]))]
    # Any single root-hosted requested object is enough; no missing future-object fallback to final LV.
    for obj in expected['protected_objects']:obj['device']=[253,4]
    expected['protected_objects'][object_index]['device']=[8,1]
    refresh(record,expected)
    with pytest.raises(ValueError,match='raw ancestor'):run(record,expected)


@pytest.mark.parametrize('case',['unknown-device','missing-fs-uuid','missing-frame','carrier-peer'])
def test_protected_carriers_never_assume_disjoint_or_isolated(admitted,case):
    record,expected=admitted
    if case=='unknown-device':expected['protected_objects'][0]['device']=[77,77]
    elif case=='missing-fs-uuid':next(n for n in record['backing']['nodes'] if n['id']=='root-fs')['fs_uuid']=None;record['backing']['nodes']=ordered(record['backing']['nodes'])
    elif case=='missing-frame':expected['protected_objects'].pop()
    else:
        expected['protected_objects'][0]['device']=[253,6]
        next(n for n in record['backing']['nodes'] if n['id']=='peer')['fs_uuid']='peer-fs-id';record['backing']['nodes']=ordered(record['backing']['nodes'])
        record['pve']['volume_references']=[dict(id='peer',origin='foreign',resource=dict(kind='block',rdev=[253,6]))]
    refresh(record,expected)
    with pytest.raises(ValueError):run(record,expected)


def test_isolated_peer_preserved_with_linear_root_on_same_pv(admitted):
    record,expected=admitted;b=record['backing']
    node=copy.deepcopy(next(n for n in b['nodes'] if n['id']=='data'));node.update(id='linear-root',rdev=[253,0],lv_uuid='root-lv',fs_uuid='linear-root-fs');b['nodes']=ordered(b['nodes']+[node])
    b['edges']=ordered(b['edges']+[{'from':'pv','to':'linear-root','kind':'mapping','evidence_ids':['block','lvm','support','thin']}])
    for obj in expected['protected_objects']:
        if obj['device']==[8,1]:obj['device']=[253,0]
    record['pve']['volume_references']=[dict(id='peer',origin='foreign',resource=dict(kind='block',rdev=[253,6]))]
    refresh(record,expected);assert run(record,expected)


@pytest.mark.parametrize('case',['existing','absent','symlink','non-directory','changed-stat'])
def test_current_guard_metadata_observes_only_exact_owned_fixture(case,tmp_path,monkeypatch):
    import ast,os,yaml
    code=yaml.safe_load((BASE/'ansible/proxmox-host-swap.yml').read_text())[0]['vars']['placement_entry_code']
    # Compile the metadata function alone; never run placement_main/native transport.
    tree=ast.parse(code);function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='protected_object')
    import stat
    ticks=[];ns=dict(os=os,stat=stat,parts=validator().parts,guard=lambda *args:ticks.append(1),observed_stat=lambda value:dict(dev=value.st_dev,inode=value.st_ino,mode=value.st_mode,size=value.st_size,mtime_ns=value.st_mtime_ns,ctime_ns=value.st_ctime_ns))
    exec(compile(ast.Module(body=[function],type_ignores=[]),'exact-owned-metadata-function','exec'),ns)
    parent=tmp_path/'owned';parent.mkdir();path=parent/'file';path.write_bytes(b'fixture')
    if case=='absent':path=parent/'absent/subdir/file'
    elif case=='symlink':path.unlink();path.symlink_to(parent/'missing')
    elif case=='non-directory':path=path/'child'
    elif case=='changed-stat':
        original=os.lstat;counter={'n':0}
        def changed(name,*args,**kwargs):
            result=original(name,*args,**kwargs)
            if str(name)==str(path):
                counter['n']+=1
                if counter['n']==2:path.write_bytes(b'changed after stat')
            return result
        monkeypatch.setattr(os,'lstat',changed)
    if case in ('symlink','non-directory','changed-stat'):
        with pytest.raises((ValueError,OSError)):ns['protected_object'](str(path),False,{},'preflight')
    else:
        result=ns['protected_object'](str(path),False,{},'preflight')
        assert result['path']==str(path) and result['exists'] is (case=='existing')
        assert result['observed_path']==str(path if case=='existing' else parent)
        actual=os.lstat(path if case=='existing' else parent)
        assert result['device']==[os.major(actual.st_dev),os.minor(actual.st_dev)] and result['inode']==actual.st_ino
    assert ticks and not (parent/'absent').exists()
