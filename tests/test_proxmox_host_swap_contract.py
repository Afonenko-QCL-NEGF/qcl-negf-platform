"""Bounded actual Ansible contract; every native host action is recorded/faked.

Read-only FIEMAP helper uses only owned tiny files and injected ioctl/hole calls.
No host DD, mkswap, swapon, systemd, mount, SSH or physical FIEMAP is executed.
"""
import importlib.util
import json
import os
from pathlib import Path
import struct

import pytest
import yaml

BASE = Path(__file__).resolve().parents[1]
MIB = 1048576
UUID = '33333333-3333-4333-8333-333333333333'
FS = '22222222-2222-4222-8222-222222222222'
PATH = '/srv/final/protected-swap/swapfile'
UNIT = 'srv-final-protected\\x2dswap-swapfile.swap'
REC = '/var/lib/host-infrastructure/swap-attempts'
OLD = {'name': '/dev/mapper/old-swap', 'type': 'partition', 'size': 8388608, 'used': 1024, 'prio': -2}


def settings():
    return dict(apply=True, preflight_only=False, attempt_id='swap-new-2', original_receipt='old-failed-1',
        accepted_source='fixture-source', host_id='fixture-host', boot_id='fixture-boot',
        admission=dict(fresh=True, exclusive=True, receipt='fresh-private', expires_at_epoch=200, operation_owner='swap-new-2'),
        tools={n:'/usr/bin/'+n.replace('_','-') for n in ['python3','dd','mkswap','swapon','blkid','timeout','systemctl','systemd_escape','findmnt','realpath','lvs','df','getconf','busctl','wipefs']},
        swap=dict(enabled=True, path=PATH, parent='/srv/final/protected-swap', unit=UNIT,
            target_mib=4, authorized_cap_mib=8, header_uuid=UUID, lifetime='protected-host-infrastructure',
            receipts=REC, binding_sha256=None, mount=dict(path='/srv/final', unit='srv-final.mount',
                device='/dev/mapper/final', rdev='253:4', fs_uuid=FS, lv_uuid='image-lv', vg_uuid='vg-id', pool_uuid='pool-id',
                cutover_receipt='accepted-native-final', accepted=True),
            support=dict(fresh=True, receipt='tools-ext4-fiemap', page_bytes=4096, minimum_file_pages=10,
                maximum_file_pages=4294967295, direct=True, fiemap=True, ext4=True, swapon_json=True, systemd_version=257,busctl_json=True,wipefs_json=True,header_write_bytes=4096,synchronous_child_scope=True),
            ledger=dict(fresh=True, receipt='physical-reservation', expires_at_epoch=200,
                incremental_swap_bytes=4*MIB, protected_data_growth_bytes=8*MIB, data_reserve_bytes=8*MIB,
                data_overhead_bytes=MIB, metadata_growth_bytes=MIB, metadata_reserve_bytes=MIB,
                filesystem_growth_bytes=MIB, filesystem_reserve_bytes=MIB),
            budgets=dict(preflight_seconds=100, allocation_seconds=100, activation_seconds=40, aggregate_seconds=240,
                maximum_write_bytes=4*MIB+4096+65536,maximum_metadata_write_bytes=65536, maximum_extents=16, maximum_probe_bytes=4096, maximum_record_bytes=16384,
                maximum_output_bytes=524288, maximum_swap_rows=16)))


def file_stat(size=0):
    return dict(dev=os.makedev(253,4), dev_major=253,dev_minor=4,inode=81, nlink=1, uid=0, gid=0, mode=384, size=size, blocks=(size+511)//512,
                mtime_ns=100, ctime_ns=100, kind='regular')


def state():
    return dict(trace=[], probes=[], native_queries=[],exists=False, file=file_stat(), parent_exists=False, receipts_exists=False,
        owned=False, signature=None, active=False, unit_exists=False, unit_active=False, unit_enabled=False,
        records={}, malformed=None, layout_bad=False, old_changed=False, used_changes=False, failure=None,
        page_bytes=4096, fs=FS, fs_type='ext4', pool_healthy=True, pool_free=128*MIB, metadata_free=16*MIB,
        fs_free=64*MIB, mount_loaded=True, policy_bad=False, changed_inode=False, binding_orphan=False)


def seed_legacy_owned(cfg, s, *, full=False, header=False, active=False, filesystem_dev=None):
    s.update(exists=True, parent_exists=True, receipts_exists=True, owned=True)
    s['file']=file_stat(4*MIB if full or header or active else MIB)
    if filesystem_dev is not None:
        s['file']['dev']=filesystem_dev;s['file']['dev_major']=os.major(filesystem_dev);s['file']['dev_minor']=os.minor(filesystem_dev);s['parent_dev']=filesystem_dev
    binding=dict(file={k:s['file'][k] for k in ['dev','inode','nlink','uid','gid','mode','kind']},
                 parent=dict(dev=s.get('parent_dev',14),inode=80,uid=0,gid=0,mode=448), receipts=dict(dev=1,inode=90,uid=0,gid=0,mode=448))
    payload=json.dumps(binding,sort_keys=True,separators=(',',':'))
    import hashlib
    cfg['swap']['binding_sha256']=hashlib.sha256(payload.encode()).hexdigest()
    s['records']['binding']=binding
    if full:s['records']['allocation']={'file':s['file'],'layout_hash':'layout','attempt_id':'previous-1'}
    if header:
        s['signature']={'TYPE':'swap','UUID':UUID}
        s['records']['format_intent']={'header_uuid':UUID,'file':binding['file']}
        s['records']['header']={'header_uuid':UUID,'file':binding['file']}
    if active:
        s.update(active=True,unit_exists=True,unit_active=True)
        s['records']['unit']={'unit':UNIT,'path':PATH}
        s['records']['activation_intent']={'file':binding['file'],'header_uuid':UUID}


def fixture_layout_hash(size):
    import hashlib
    layout=[] if size==0 else [(0,8192,size,1)]
    return hashlib.sha256(json.dumps(layout,separators=(',',':')).encode()).hexdigest()


def fixture_sample_hash(header_uuid,length,other_page=False):
    import hashlib,uuid
    page=bytearray(4096)
    if header_uuid is not None:
        struct.pack_into('=III',page,1024,1,63 if other_page else 1023,0)
        page[1036:1052]=uuid.UUID(header_uuid).bytes
        if not other_page:page[-10:]=b'SWAPSPACE2'
    return hashlib.sha256(page[:length]).hexdigest()


def expected_fragment(cfg):
    w=cfg['swap']
    return '[Unit]\nDescription=Protected additive host swap\nRequiresMountsFor='+w['mount']['path']+' '+w['path']+'\nConditionPathIsMountPoint='+w['mount']['path']+'\n\n[Swap]\nWhat='+w['path']+'\nTimeoutSec='+str(w['budgets']['activation_seconds'])+'\n\n[Install]\nWantedBy=swap.target\n'


def fragment_fixture(text):
    import base64,hashlib
    return dict(exists=True,stat=dict(dev=os.makedev(8,1),inode=99,nlink=1,uid=0,gid=0,mode=420,size=len(text),kind='regular'),bytes=len(text),sha256=hashlib.sha256(text.encode()).hexdigest(),content_b64=base64.b64encode(text.encode()).decode())


def stored_budget_fixture(cfg):
    b=cfg['swap']['budgets']
    return dict(schema='qcl.host-swap.budget.v1',attempt_id='stored-attempt',boot_id='stored-boot',sequence=10,started_monotonic_ns=100000000000,deadline_monotonic_ns=100000000000+b['aggregate_seconds']*1000000000,last_monotonic_ns=101000000000,admission_expires_epoch_ns=200000000000,ledger_expires_epoch_ns=200000000000,phase_elapsed_ns=dict(preflight=1000000000,allocation=0,activation=0),output_bytes=65536,write_bytes_reserved=4*MIB+4096+32768,metadata_bytes_reserved=32768,limits=dict(preflight_ns=b['preflight_seconds']*1000000000,allocation_ns=b['allocation_seconds']*1000000000,activation_ns=b['activation_seconds']*1000000000,aggregate_ns=b['aggregate_seconds']*1000000000,output_bytes=b['maximum_output_bytes'],write_bytes=b['maximum_write_bytes'],metadata_write_bytes=b['maximum_metadata_write_bytes']))


STAGES=('partial','full_blank','formatted','active','completed')
PHASE_CHAIN=('binding','allocation','format_intent','header','unit','activation_intent','completion')


def canonical_fixture(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def fixture_hash(value):
    import hashlib
    return hashlib.sha256(canonical_fixture(value)).hexdigest()


def phase_envelope(cfg,s,phase,payload):
    assert phase in PHASE_CHAIN[1:]
    binding=s['records']['binding']
    assert binding['schema']=='qcl.host-swap.binding.v2'
    assert fixture_hash(binding)==cfg['swap']['binding_sha256']
    assert fixture_hash(binding['context'])==binding['context_sha256']
    return dict(schema='qcl.host-swap.'+phase+'.v2',context_sha256=binding['context_sha256'],binding_sha256=cfg['swap']['binding_sha256'],payload=payload,provenance=dict(binding['provenance']))


def assert_seed_coherent(cfg,s,stage):
    assert stage in STAGES
    count={'partial':1,'full_blank':2,'formatted':4,'active':6,'completed':7}[stage]
    assert set(s['records'])==set(PHASE_CHAIN[:count])
    binding=s['records']['binding'];context=binding['context'];static=binding['payload']['file']
    assert fixture_hash(binding)==cfg['swap']['binding_sha256']
    assert fixture_hash(context)==binding['context_sha256']
    assert context['header_uuid']==cfg['swap']['header_uuid']
    assert context['unit_declaration']['fragment_sha256']==__import__('hashlib').sha256(expected_fragment(cfg).encode()).hexdigest()
    assert static=={k:s['file'][k] for k in static}
    assert binding['payload']['parent']['dev']==s.get('parent_dev',s['file']['dev'])
    assert context['original_swaps']==[dict(name=OLD['name'],type=OLD['type'],size=OLD['size'],prio=OLD['prio'],identity=dict(kind='block',rdev=[253,1]))]
    assert all(type(OLD[k]) is int for k in ('size','used','prio'))
    for phase in PHASE_CHAIN[1:count]:
        record=s['records'][phase]
        assert record==phase_envelope(cfg,s,phase,record['payload'])
        if 'file_identity' in record['payload']:assert record['payload']['file_identity']==static
    if count>=2:
        allocation=s['records']['allocation']['payload']
        assert allocation['target_bytes']==s['file']['size']==4*MIB
        assert allocation['layout_hash']==fixture_layout_hash(4*MIB)
        assert allocation['observed_file_stat']==s['file']
    if count>=4:
        assert s['signature']=={'TYPE':'swap','UUID':UUID,'VERSION':'1'}
        assert s['records']['format_intent']['payload']['header_uuid']==UUID
        assert s['records']['header']['payload']['signature']==s['signature']
        assert s['records']['header']['payload']['sample_sha256']==fixture_sample_hash(UUID,4096)
    if count>=6:
        unit=s['records']['unit']['payload'];intent=s['records']['activation_intent']['payload']
        assert s['active'] and s['unit_exists'] and s['unit_active']
        assert unit['fragment_stat']=={k:fragment_fixture(expected_fragment(cfg))['stat'][k] for k in unit['fragment_stat']}
        assert intent['unit_record_sha256']==fixture_hash(s['records']['unit'])
        assert intent['original_swaps']==context['original_swaps']
    if count==7:
        completion=s['records']['completion']['payload']
        assert s['unit_enabled'] and completion['old_static_swaps']==context['original_swaps']
        assert completion['budget_usage']==stored_budget_fixture(cfg)


def seed_owned(cfg,s,*,stage):
    import hashlib
    assert stage in STAGES
    s.update(exists=True,parent_exists=True,receipts_exists=True,owned=True)
    s['file']=file_stat(MIB if stage=='partial' else 4*MIB)
    w=cfg['swap'];f=s['file'];f.update(dev=os.makedev(253,4),dev_major=253,dev_minor=4)
    static={k:f[k] for k in ('dev','inode','nlink','uid','gid','mode','kind')}
    old=[dict(name=OLD['name'],type=OLD['type'],size=OLD['size'],prio=OLD['prio'],identity=dict(kind='block',rdev=[253,1]))]
    context=dict(schema='qcl.host-swap.context.v2',host_id=cfg['host_id'],path=PATH,parent=w['parent'],target_bytes=4*MIB,page_bytes=4096,header_uuid=UUID,lifetime=w['lifetime'],final_mount=dict(path='/srv/final',unit='srv-final.mount',fs_uuid=FS,device_rdev=[253,4],lv_uuid='image-lv',vg_uuid='vg-id',pool_uuid='pool-id'),unit_declaration=dict(name=UNIT,fragment_path='/etc/systemd/system/'+UNIT,fragment_sha256=hashlib.sha256(expected_fragment(cfg).encode()).hexdigest(),timeout_usec=w['budgets']['activation_seconds']*1000000),original_swaps=old)
    provenance=dict(source='independent-old-source',attempt_id='independent-old-attempt',boot_id='independent-old-boot')
    canonical=lambda v:json.dumps(v,sort_keys=True,separators=(',',':')).encode()
    ch=hashlib.sha256(canonical(context)).hexdigest()
    binding=dict(schema='qcl.host-swap.binding.v2',context=context,context_sha256=ch,payload=dict(file=static,parent=dict(dev=os.makedev(253,4),inode=80,nlink=2,uid=0,gid=0,mode=448,kind='directory'),receipts=dict(dev=os.makedev(8,1),inode=90,nlink=2,uid=0,gid=0,mode=448,kind='directory')),provenance=provenance)
    bh=hashlib.sha256(canonical(binding)).hexdigest();cfg['swap']['binding_sha256']=bh;s['records']={'binding':binding}
    def envelope(phase,payload):s['records'][phase]=phase_envelope(cfg,s,phase,payload)
    if stage!='partial':envelope('allocation',dict(file_identity=static,target_bytes=4*MIB,layout_hash=fixture_layout_hash(4*MIB),observed_file_stat=f.copy()))
    if stage in ('formatted','active','completed'):
        s['signature']={'TYPE':'swap','UUID':UUID,'VERSION':'1'}
        envelope('format_intent',dict(file_identity=static,target_bytes=4*MIB,page_bytes=4096,header_uuid=UUID))
        envelope('header',dict(file_identity=static,target_bytes=4*MIB,page_bytes=4096,header_uuid=UUID,layout_hash=fixture_layout_hash(4*MIB),sample_bytes=4096,sample_sha256=fixture_sample_hash(UUID,4096),signature=s['signature'].copy()))
    if stage in ('active','completed'):
        s.update(active=True,unit_exists=True,unit_active=True)
        fragment=fragment_fixture(expected_fragment(cfg))
        envelope('unit',dict(name=UNIT,path=PATH,fragment_path='/etc/systemd/system/'+UNIT,fragment_sha256=fragment['sha256'],fragment_stat={k:fragment['stat'][k] for k in ('dev','inode','nlink','uid','gid','mode','size')},timeout_usec=w['budgets']['activation_seconds']*1000000))
        envelope('activation_intent',dict(file_identity=static,header_uuid=UUID,header_sample_sha256=fixture_sample_hash(UUID,4096),final_mount=context['final_mount'],unit_record_sha256=hashlib.sha256(canonical(s['records']['unit'])).hexdigest(),original_swaps=old))

    if stage=='completed':
        s['unit_enabled']=True
        envelope('completion',dict(file_identity=static,header_uuid=UUID,header_sample_sha256=fixture_sample_hash(UUID,4096),usable_bytes=4*MIB-4096,boot_enabled=True,lifetime=context['lifetime'],old_static_swaps=old,actual_swaps_observation={'swaps':[dict(OLD),dict(name=PATH,type='file',size=4*MIB-4096,used=0,prio=-3)]},budget_usage=stored_budget_fixture(cfg)))
    assert_seed_coherent(cfg,s,stage)


CASES=[
 'fresh','disabled','preflight-only','stale-admission','bool-target','false-apply','wrong-fs','wrong-rdev',
 'wrong-mount-policy','unknown-file','unknown-directory','hardlink','creation-collision','parent-sync-failure',
 'receipt-sync-failure','partial-resume','formatted-resume','active-resume','active-changed-policy','signature-error',
 'layout-gap','layout-unwritten','wrong-page-usable','old-used-changes','old-swap-missing',
 'activation-timeout-late','completion-failure','sticky-intent-inactive','thin-reserve','metadata-unknown']


def configure(name,cfg,s):
    if name=='disabled':return {},s
    if name=='preflight-only':cfg.update(apply=False,preflight_only=True)
    if name=='stale-admission':cfg['admission']['expires_at_epoch']=99
    if name=='bool-target':cfg['swap']['target_mib']=True
    if name=='false-apply':cfg['apply']=False
    if name=='wrong-fs':s['fs']='foreign'
    if name=='wrong-rdev':cfg['swap']['mount']['rdev']='253:9'
    if name=='wrong-mount-policy':s['mount_loaded']=False
    if name=='unknown-file':s.update(exists=True,parent_exists=True,safe_parent=True)
    if name=='unknown-directory':s['parent_exists']=True
    if name=='hardlink':seed_owned(cfg,s,stage='partial');s['file']['nlink']=2
    if name in ('creation-collision','parent-sync-failure','receipt-sync-failure','completion-failure'):
        s['failure']=name
    if name=='partial-resume':seed_owned(cfg,s,stage='partial')
    if name=='formatted-resume':seed_owned(cfg,s,stage='formatted')
    if name=='active-resume':seed_owned(cfg,s,stage='active')
    if name=='active-changed-policy':seed_owned(cfg,s,stage='active');s['policy_bad']=True
    if name=='signature-error':s['failure']='signature-error'
    if name in ('layout-gap','layout-unwritten'):s['layout_bad']=name
    if name=='wrong-page-usable':s['malformed']='usable'
    if name=='old-used-changes':s['used_changes']=True
    if name=='old-swap-missing':s['old_changed']=True
    if name=='activation-timeout-late':s['failure']='activation-timeout-late'
    if name=='sticky-intent-inactive':seed_owned(cfg,s,stage='active');s.update(active=False,unit_active=False)
    if name=='thin-reserve':s['pool_free']=MIB
    if name=='metadata-unknown':s['metadata_free']=None
    return cfg,s


UNIT_PROPERTIES=('Id','FragmentPath','DropInPaths','NeedDaemonReload','DefaultDependencies','LoadState','ActiveState','UnitFileState','Requires','After','RequiresMountsFor','Conditions','ConditionResult')
SWAP_PROPERTIES=('What','Options','TimeoutUSec')
FIND_FIELDS='TARGET,SOURCE,UUID,FSTYPE,FSROOT,MAJ:MIN'
SWAP_FIELDS='NAME,TYPE,SIZE,USED,PRIO'
LV_FIELDS='lv_uuid,vg_uuid,lv_name,segtype,lv_size,lv_metadata_size,data_percent,metadata_percent,lv_attr,lv_health_status,pool_lv,lv_path'


def parse_native_cli(argv,cfg):
    """Finite CLI semantic boundary; no execution, native discovery or option guessing."""
    cmd=Path(argv[0]).name
    assert argv[0]==cfg['tools'][cmd.replace('-','_')], ('foreign executable',argv)
    w=cfg['swap'];args=argv[1:]
    if cmd=='dd':
        pairs=[x.split('=',1) for x in args]
        assert all(len(x)==2 for x in pairs) and len({x[0] for x in pairs})==len(pairs)
        options=dict(pairs)
        assert set(options)=={'if','of','bs','count','conv','oflag'}
        assert {k:options[k] for k in ('if','of','bs','count')}=={'if':'/dev/zero','of':w['path'],'bs':'1M','count':str(w['target_mib'])}
        for name,expected in (('conv',{'nocreat','notrunc','fsync'}),('oflag',{'direct','nofollow'})):
            values=options[name].split(',');assert len(values)==len(set(values)) and set(values)==expected
        return dict(command=cmd,options=options,operands=[])
    flags={'findmnt':{'--json'},'swapon':{'--show','--json','--bytes'},'lvs':{'--nosuffix'},'busctl':{'--system'},'blkid':{'--probe'},'wipefs':{'--no-act','--json'},'systemctl':set(),'mkswap':set(),'df':set(),'getconf':set(),'systemd-escape':{'--path'}}.get(cmd)
    assert flags is not None, ('unsupported CLI',argv)
    values={'findmnt':{'--mountpoint','--target','--output'},'swapon':{'--output'},'lvs':{'--reportformat','--units','--options'},'busctl':{'--json'},'blkid':{'--output'},'wipefs':set(),'systemctl':{'--property'},'mkswap':{'--uuid','--pagesize'},'df':{'--block-size','--output'},'getconf':set(),'systemd-escape':{'--suffix'}}[cmd]
    options={};operands=[];i=0
    while i<len(args):
        token=args[i];i+=1
        if token.startswith('--'):
            name,sep,value=token.partition('=')
            assert name not in options, ('duplicate option',argv)
            if name in flags:
                assert not sep;options[name]=True
            else:
                assert name in values, ('unknown option',argv)
                if not sep:
                    assert cmd!='busctl' or name!='--json', 'busctl documented --json=MODE'
                    assert i<len(args) and not args[i].startswith('--');value=args[i];i+=1
                assert value;options[name]=value
        else:operands.append(token)
    if cmd=='findmnt':
        assert set(options) in ({'--json','--mountpoint','--output'},{'--json','--target','--output'}) and not operands
        assert options['--output']==FIND_FIELDS
        assert options.get('--mountpoint',w['mount']['path'])==w['mount']['path']
        assert options.get('--target',w['parent']) in (w['mount']['path'],w['parent'],w['path'])
    elif cmd=='swapon':assert options=={'--show':True,'--json':True,'--bytes':True,'--output':SWAP_FIELDS} and not operands
    elif cmd=='lvs':assert options=={'--reportformat':'json','--units':'b','--nosuffix':True,'--options':LV_FIELDS} and not operands
    elif cmd=='busctl':
        assert options=={'--system':True,'--json':'short'}
        if operands[0]=='call':assert operands==['call','org.freedesktop.systemd1','/org/freedesktop/systemd1','org.freedesktop.systemd1.Manager','GetUnit','s',w['unit']]
        else:
            assert operands[:3]==['get-property','org.freedesktop.systemd1','/org/freedesktop/systemd1/unit/fixture_swap']
            interface=operands[3]
            assert tuple(operands[4:])==(UNIT_PROPERTIES if interface=='org.freedesktop.systemd1.Unit' else SWAP_PROPERTIES)
            assert interface in ('org.freedesktop.systemd1.Unit','org.freedesktop.systemd1.Swap')
    elif cmd=='systemctl':
        assert operands and operands[0] in ('show','start','enable','daemon-reload')
        if operands[0]=='show':
            assert len(operands)==2 and operands[1] in (w['mount']['unit'],w['unit']) and set(options)=={'--property'}
            expected='LoadState,What,Where,Type,FragmentPath,DropInPaths,NeedDaemonReload,ForceUnmount,LazyUnmount,Options' if operands[1]==w['mount']['unit'] else None
            assert options['--property']==expected if expected else options['--property'] in ('LoadState','LoadState,ActiveState,UnitFileState')
        else:assert not options and operands==(['daemon-reload'] if operands[0]=='daemon-reload' else [operands[0],w['unit']])
    elif cmd=='mkswap':assert options=={'--uuid':w['header_uuid'],'--pagesize':str(w['support']['page_bytes'])} and operands==[w['path']]
    elif cmd=='blkid':assert options=={'--probe':True,'--output':'export'} and operands==[w['path']]
    elif cmd=='wipefs':assert options=={'--no-act':True,'--json':True} and operands==[w['path']]
    elif cmd=='df':assert options=={'--block-size':'1','--output':'avail'} and operands==[w['mount']['path']]
    elif cmd=='getconf':assert not options and operands==['PAGE_SIZE']
    elif cmd=='systemd-escape':assert options=={'--path':True,'--suffix':'swap'} and operands==[w['path']]
    return dict(command=cmd,options=options,operands=operands)


def execute(cfg,s,tmp_path,monkeypatch,*,syntax=False):
    monkeypatch.setenv('ANSIBLE_COLLECTIONS_PATH','/tmp/qcl-host-storage-ansible')
    monkeypatch.setenv('ANSIBLE_LOCAL_TEMP',str(tmp_path/'ansible-local'))
    from ansible import context
    from ansible.module_utils.common.collections import ImmutableDict
    from ansible.parsing.dataloader import DataLoader
    from ansible.inventory.manager import InventoryManager
    from ansible.vars.manager import VariableManager
    from ansible.executor.playbook_executor import PlaybookExecutor
    from ansible.executor.task_executor import TaskExecutor
    from ansible.plugins.action import ActionBase
    from ansible.plugins.loader import init_plugin_loader
    from ansible.plugins.connection.local import Connection
    from ansible.utils.collection_loader import AnsibleCollectionConfig
    assert json.loads(Path('/tmp/qcl-host-storage-ansible/ansible_collections/community/general/MANIFEST.json').read_text())['collection_info']['version']=='13.4.0'
    if AnsibleCollectionConfig.collection_finder is None:init_plugin_loader()
    recording=tmp_path/'recording.json';recording.write_text(json.dumps(s))
    original=TaskExecutor._get_action_handler_with_module_context
    def forbidden(*args,**kwargs):raise AssertionError('native host operation escaped fake boundary')
    monkeypatch.setattr(Connection,'exec_command',forbidden)
    monkeypatch.setattr(ActionBase,'_execute_module',forbidden)
    class Fake(ActionBase):
        def run(self,tmp=None,task_vars=None):
            args=self._templar.template(self._task.args)
            action=self._task.action
            s=json.loads(recording.read_text());out={'changed':False,'rc':0,'stdout':''}
            event=dict(index=len(s.setdefault('events',[])),task=self._task.get_name(),action=action,phase=None,sequence=None)
            s['events'].append(event)
            def trace(kind):
                import hashlib
                compact=list(argv) if action=='ansible.builtin.command' else []
                if len(compact)>2 and compact[1]=='-c':compact[2]={'inline_python_sha256':hashlib.sha256(compact[2].encode()).hexdigest()}
                s['trace'].append(dict(index=event['index'],task=event['task'],phase=event['phase'],sequence=event['sequence'],kind=kind,args={'argv':compact} if compact else dict(args)))
            if action=='ansible.builtin.command':
                argv=args['argv']
                wire_usage=None;incoming=None;write=metadata=0
                if Path(argv[0]).name=='python3' and argv[3]=='clock-v2':
                    config=json.loads(argv[4]);wire_usage=dict(schema='qcl.host-swap.budget.v1',sequence=1,started_monotonic_ns=100000000000,last_monotonic_ns=100000000000,deadline_monotonic_ns=100000000000+config['limits']['aggregate_ns'],phase_elapsed_ns={'preflight':0,'allocation':0,'activation':0},output_bytes=0,write_bytes_reserved=0,metadata_bytes_reserved=0,**config)
                    argv=['/fixture/clock-done']
                    if min(wire_usage['admission_expires_epoch_ns'],wire_usage['ledger_expires_epoch_ns'])<=100000000000:out.update(rc=125);argv=['/fixture/budget-refusal']
                elif Path(argv[0]).name=='python3' and argv[3]=='run-v2':
                    wire_usage=json.loads(argv[4]);incoming=json.loads(argv[4]);phase=argv[5];write=int(argv[6]);metadata=int(argv[7]);event['phase']=phase
                    assert wire_usage['schema']=='qcl.host-swap.budget.v1' and phase in wire_usage['phase_elapsed_ns']
                    assert wire_usage['limits']['output_bytes']==cfg['swap']['budgets']['maximum_output_bytes']
                    wire_usage['sequence']+=1;wire_usage['write_bytes_reserved']+=write;wire_usage['metadata_bytes_reserved']+=metadata
                    wire_usage['last_monotonic_ns']+=1000000;wire_usage['phase_elapsed_ns'][phase]+=1000000
                    argv=json.loads(argv[8]);argv=[json.dumps(wire_usage) if a=='@BUDGET@' else a for a in argv]
                    if wire_usage['write_bytes_reserved']>wire_usage['limits']['write_bytes'] or wire_usage['metadata_bytes_reserved']>wire_usage['limits']['metadata_write_bytes'] or wire_usage['phase_elapsed_ns'][phase]>=wire_usage['limits'][phase+'_ns'] or wire_usage['last_monotonic_ns']>=wire_usage['deadline_monotonic_ns'] or min(wire_usage['admission_expires_epoch_ns'],wire_usage['ledger_expires_epoch_ns'])<=100000000000:
                        out.update(rc=125,stdout='',stderr='');argv=['/fixture/budget-refusal']
                cmd=Path(argv[0]).name
                if cmd=='timeout':
                    assert argv[1:3]==['--signal=TERM','--kill-after=5']
                    argv=argv[4:];cmd=Path(argv[0]).name
                event['sequence']=None if wire_usage is None else wire_usage['sequence']
                shape=parse_native_cli(argv,cfg) if cmd in ('dd','mkswap','findmnt','swapon','systemctl','busctl','lvs','df','getconf','systemd-escape','blkid','wipefs') else None
                s['probes'].append(cmd)
                if cmd in ('clock-done','budget-refusal'):pass
                elif cmd=='date':out['stdout']='100'
                elif cmd=='cat':out['stdout']='fixture-host' if argv[-1]=='/etc/machine-id' else 'fixture-boot'
                elif cmd=='getconf':out['stdout']=str(s['page_bytes'])
                elif cmd=='systemd-escape':out['stdout']=UNIT
                elif cmd=='realpath':out['stdout']='/dev/dm-4'
                elif cmd=='stat':out['stdout']='253:4'
                elif cmd=='findmnt':
                    row=dict(target='/srv/final',source='/dev/mapper/final',uuid=s['fs'],fstype=s['fs_type'],fsroot='/',**{'maj:min':'253:4'})
                    if '--target' in shape['options'] and s.get('submount'):
                        requested=shape['options']['--target']
                        if requested==s['submount']['target'] or requested.startswith(s['submount']['target']+'/'):
                            row=dict(s['submount'])
                    out['stdout']=json.dumps({'filesystems':[row]})
                elif cmd=='lvs':
                    out['stdout']=json.dumps({'report':[{'lv':[
                        dict(lv_uuid='pool-id',vg_uuid='vg-id',lv_name='hostpool',segtype='thin-pool',lv_size=str(256*MIB),lv_metadata_size=str(32*MIB),
                            data_percent=str(100*(1-s['pool_free']/(256*MIB))),metadata_percent='' if s['metadata_free'] is None else str(100*(1-s['metadata_free']/(32*MIB))),
                            lv_attr=s.get('pool_attr','twi-a-tz--' if s['pool_healthy'] else 'twi-a-Fz--'),lv_health_status='' if s['pool_healthy'] else 'failed'),
                        dict(lv_uuid='image-lv',vg_uuid='vg-id',lv_name='final',segtype='thin',pool_lv='hostpool',lv_size=str(512*MIB),lv_path='/dev/mapper/final')]}]})
                elif cmd=='df':out['stdout']='Avail\n  '+str(s['fs_free'])
                elif cmd=='swapon':
                    old=dict(OLD)
                    if s['used_changes']:old['used']+=1234
                    rows=[] if s['old_changed'] and s['active'] else [old]
                    if s['active']:rows.append(dict(name=PATH,type='file',size=4*MIB-(8192 if s['malformed']=='usable' else 4096),used=0,prio=-3))
                    out['stdout']=json.dumps({'swaps':rows})
                elif cmd=='wipefs':
                    signatures=[] if s['signature'] is None else [dict(type=s['signature']['TYPE'],uuid=s['signature']['UUID'])]
                    out['stdout']=json.dumps({'signatures':signatures})
                elif cmd=='busctl':
                    operands=shape['operands']
                    if operands[0]=='call':out['stdout']=json.dumps({'type':'o','data':['/org/freedesktop/systemd1/unit/fixture_swap']})
                    elif operands[3]=='org.freedesktop.systemd1.Unit':
                        props=['Id','FragmentPath','DropInPaths','NeedDaemonReload','DefaultDependencies','LoadState','ActiveState','UnitFileState','Requires','After','RequiresMountsFor','Conditions','ConditionResult']
                        assert operands[4:]==props
                        values=[UNIT,'/etc/systemd/system/'+UNIT,[],False,True,'loaded','active' if s['unit_active'] else 'inactive','enabled' if s['unit_enabled'] else 'disabled',['srv-final.mount'],['srv-final.mount'],['/srv/final',cfg['swap']['path']],s.get('conditions',[['ConditionPathIsMountPoint',False,False,'/srv/final',1 if s['unit_active'] else 0]]),s['unit_active']]
                        signatures=['s','s','as','b','b','s','s','s','as','as','as','a(sbbsi)','b']
                        out['stdout']='\n'.join(json.dumps({'type':t,'data':v}) for t,v in zip(signatures,values))
                    else:
                        assert operands[3]=='org.freedesktop.systemd1.Swap' and operands[4:]==['What','Options','TimeoutUSec']
                        out['stdout']='\n'.join(json.dumps({'type':t,'data':v}) for t,v in [('s','/foreign' if s['policy_bad'] else PATH),('s',''),('t',cfg['swap']['budgets']['activation_seconds']*1000000)])
                elif cmd=='blkid':
                    if s['failure']=='signature-error':out.update(failed=True,rc=4,stderr='unknown signature')
                    elif s['signature']:out['stdout']='\n'.join(k+'='+v for k,v in s['signature'].items())
                    else:out['rc']=2
                elif cmd=='dd':
                    assert s['owned'] and not s['active'] and s['signature'] is None
                    previous=dict(s['file']);trace('fill');s['file']=file_stat(4*MIB)
                    if s.get('submount'):
                        for key in ['dev','inode','nlink','uid','gid','mode','kind']:s['file'][key]=previous[key]
                    if s.get('charge_after_fill'):
                        s['pool_free']-=4*MIB;s['fs_free']-=4*MIB
                    if 'after_fill_pool' in s:s['pool_free']=s['after_fill_pool']
                    if 'after_fill_fs' in s:s['fs_free']=s['after_fill_fs']
                elif cmd=='mkswap':
                    assert s['file']['size']==4*MIB and s['records'].get('allocation') and not s['active']
                    trace('format');s['signature']={'TYPE':'swap','UUID':cfg['swap']['header_uuid'],'VERSION':'1'}
                elif cmd=='systemctl':
                    operation=shape['operands'][0]
                    if operation=='show':
                        if shape['operands'][1]=='srv-final.mount':
                            out['stdout']='\n'.join(k+'='+v for k,v in dict(LoadState='loaded' if s['mount_loaded'] else 'not-found',What='/dev/mapper/final',Where='/srv/final',Type='ext4',FragmentPath='/etc/systemd/system/srv-final.mount',DropInPaths='',NeedDaemonReload='no',ForceUnmount='no',LazyUnmount='no',Options='rw').items())
                        else:out['stdout']='\n'.join(k+'='+v for k,v in dict(LoadState='loaded' if s['unit_exists'] else 'not-found',ActiveState='active' if s['unit_active'] else 'inactive',UnitFileState='enabled' if s['unit_enabled'] else 'disabled',What='/foreign' if s['policy_bad'] else PATH,FragmentPath='/etc/systemd/system/'+UNIT,DropInPaths='',NeedDaemonReload='no',Options='',DefaultDependencies='yes',Requires='srv-final.mount',After='srv-final.mount').items())
                        requested=shape['options']['--property'].split(',')
                        fields=dict(row.split('=',1) for row in out['stdout'].splitlines())
                        assert all(key in fields for key in requested)
                        out['stdout']='\n'.join(key+'='+fields[key] for key in requested)
                    elif operation=='start':
                        assert shape['operands'][1]==UNIT and s['records'].get('activation_intent')
                        trace('start');s.update(active=True,unit_active=True)
                        if s['failure']=='activation-timeout-late':out.update(failed=True,rc=124,stderr='late activation')
                        if s['failure']=='start-inactive':s.update(active=False,unit_active=False);out.update(rc=1,stderr='failed inactive')
                        if s['failure'] in ('start-cleanup-unknown','start-exhausted','start-malformed-usage'):out.update(rc=124,stderr='cleanup uncertain')
                    elif operation=='enable':trace('enable');s['unit_enabled']=True
                    elif operation=='daemon-reload':trace('daemon-reload');s['unit_exists']=True
                    else:raise AssertionError('prohibited systemctl mutation '+repr(argv))
                elif cmd=='python3':
                    if 'machine-id' in argv[2]:out['stdout']='fixture-host'
                    elif 'boot_id' in argv[2] and len(argv)==3:out['stdout']='fixture-boot'
                    elif argv[2]==data[0]['vars']['probe_code']:
                        assert len(argv)==8 and argv[5]==PATH
                        parent_dev=s.get('parent_dev',os.makedev(253,4))
                        parent=dict(exists=s['parent_exists'],path=cfg['swap']['parent'],dev=parent_dev,dev_major=os.major(parent_dev),dev_minor=os.minor(parent_dev),inode=80,nlink=2,uid=0 if s['owned'] or not s['parent_exists'] or s.get('safe_parent') else 1000,gid=0,mode=448,kind='directory')
                        ancestor=dict(parent,exists=True,path=cfg['swap']['parent'] if s['parent_exists'] else '/srv/final')
                        if not s['parent_exists']:ancestor.update(dev=os.makedev(253,4),dev_major=253,dev_minor=4)
                        f=dict(s['file']);f.update(dev_major=os.major(f['dev']),dev_minor=os.minor(f['dev']))
                        out['stdout']=json.dumps(dict(exists=s['exists'],stat=f,parent=parent,ancestor=ancestor,coverage_complete=s['exists'] and not s['layout_bad'],unsupported_flags=2 if s['layout_bad']=='layout-unwritten' else 0,layout_hash=fixture_layout_hash(f['size']),stable=True,hole_offset=f['size'],observed_bytes=min(f['size'],4096),sample_sha256=fixture_sample_hash(s['signature']['UUID'] if s['signature'] else None,min(f['size'],4096),s.get('other_header_page',False)),header_metadata=dict(magic_hex='00000000000000000000' if s.get('other_header_page') else '53574150535041434532' if s['signature'] else '00000000000000000000',version=1 if s['signature'] else 0,last_page=63 if s.get('other_header_page') else 1023 if s['signature'] else 0,badpages=0,uuid=s['signature']['UUID'] if s['signature'] else '00000000-0000-0000-0000-000000000000')))
                    elif argv[2]==data[0]['vars']['old_observer_code']:
                        rows=json.loads(argv[5]);assert int(argv[6])==16
                        out['stdout']=json.dumps([dict(name=r['name'],type=r['type'],size=r['size'],prio=r['prio'],identity={'kind':'block','rdev':[253,1]}) for r in sorted(rows,key=lambda r:r['name'])])
                    elif argv[2]==data[0]['vars']['primitive_code']:
                        operation=argv[5];parameters=argv[6:]
                        if operation=='block':out['stdout']=json.dumps({'path':'/dev/dm-4','kind':'block','rdev':[253,4]})
                        elif operation=='records':
                            import hashlib
                            binding=s['records'].get('binding');digest=None if binding is None else hashlib.sha256(json.dumps(binding,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                            out['stdout']=json.dumps(dict(exists=s['receipts_exists'],stat=dict(dev=os.makedev(8,1),inode=90,nlink=2,uid=0,gid=0,mode=448,kind='directory'),records=s['records'],binding_sha256=digest,retained_bytes=sum(len(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()) for v in s['records'].values())))
                        elif operation=='budget-shape':
                            value=json.loads(parameters[0]);assert value['schema']=='qcl.host-swap.budget.v1' and set(value)==set(stored_budget_fixture(cfg));out['stdout']=json.dumps(value)
                        elif operation=='fragment':
                            text=expected_fragment(cfg);out['stdout']=json.dumps(dict(exists=False) if not s['unit_exists'] else fragment_fixture(text))
                        elif operation=='mkdir':
                            path=parameters[0];is_parent=path==cfg['swap']['parent'];trace('mkdir-parent' if is_parent else 'mkdir-receipts')
                            failure='parent-sync-failure' if is_parent else 'receipt-sync-failure'
                            if s['failure']==failure:out.update(rc=1,stderr='ancestor fsync failed')
                            else:trace('sync-parent-entry' if is_parent else 'sync-receipts-entry');s['parent_exists' if is_parent else 'receipts_exists']=True;s['owned']=True
                            out['stdout']='{}'
                        elif operation=='create':
                            trace('create-exclusive')
                            if s['failure']=='creation-collision':out.update(rc=1,stderr='O_EXCL collision')
                            else:s.update(exists=True,owned=True)
                            out['stdout']=json.dumps(s['file'])
                        elif operation=='atomic':
                            import base64
                            path=parameters[0];raw=base64.b64decode(parameters[1]);mode=int(parameters[2]);assert len(raw)<=int(parameters[3])
                            if path==cfg['swap']['receipts']+'/binding.json':assert 'binding' not in s['records']
                            if path.startswith(REC+'/'):
                                assert mode==384;phase=Path(path).stem;trace('record-'+phase)
                                if phase=='completion' and s['failure']=='completion-failure':out.update(rc=1,stderr='completion durability failed')
                                else:assert phase not in s['records'];s['records'][phase]=json.loads(raw);trace('seal-'+phase)
                            else:
                                assert path=='/etc/systemd/system/'+UNIT and mode==420 and not s['unit_exists']
                                assert raw.decode()==expected_fragment(cfg);trace('unit');s['unit_exists']=True
                            out['stdout']='{}'
                        else:raise AssertionError('unexpected primitive '+operation)
                    else:raise AssertionError('unexpected inline native Python')
                else:raise AssertionError('unexpected native argv '+repr(argv))
                if cmd in ('findmnt','lvs','swapon','busctl','blkid','wipefs','getconf','systemd-escape','df') or (cmd=='systemctl' and shape['operands'][0]=='show') or cmd=='python3':
                    s['native_queries'].append(dict(index=event['index'],task=event['task'],phase=event['phase'],sequence=event['sequence'],argv=list(argv) if cmd!='python3' else [argv[0],'-c',{'inline_python_sha256':__import__('hashlib').sha256(argv[2].encode()).hexdigest()},*argv[3:]],rc=out['rc'],stdout=out.get('stdout',''),stderr=out.get('stderr','')))
                if wire_usage is not None:
                    import base64
                    result=dict(schema='qcl.host-swap.io-result.v1',rc=out['rc'],stdout_b64=base64.b64encode(out.get('stdout','').encode()).decode(),stderr_b64=base64.b64encode(out.get('stderr','').encode()).decode(),usage=wire_usage,owned_children_complete=True,failure='budget_or_io_refusal' if cmd=='budget-refusal' else None)
                    if cmd=='systemctl' and shape['operands'][0]=='start' and s['failure'] in ('start-cleanup-unknown','start-exhausted','start-malformed-usage'):
                        result.update(owned_children_complete=False,failure='cleanup_unknown')
                        if s['failure']=='start-exhausted':wire_usage['admission_expires_epoch_ns']=100000000000
                    before=wire_usage['output_bytes']
                    for _ in range(8):
                        size=len(json.dumps(result,sort_keys=True,separators=(',',':')).encode())+1
                        if wire_usage['output_bytes']==before+size:break
                        wire_usage['output_bytes']=before+size
                    assert wire_usage['output_bytes']<=wire_usage['limits']['output_bytes']
                    if cmd=='systemctl' and shape['operands'][0]=='start' and s['failure']=='start-malformed-usage':wire_usage['output_bytes']=True
                    s.setdefault('wire_usage_history',[]).append(dict(index=event['index'],task=event['task'],phase=event['phase'],incoming=incoming,returned=json.loads(json.dumps(wire_usage)),precharge=dict(write=write,metadata=metadata),owned_children_complete=result['owned_children_complete'],failure=result['failure'],native_rc=result['rc']))
                    out=dict(changed=False,rc=0,stdout=json.dumps(result,sort_keys=True,separators=(',',':')))
            elif action=='ansible.builtin.copy':
                assert args['force'] is False and args['mode']=='0600'
                assert args['dest'].startswith(REC+'/')
                phase=Path(args['dest']).name.split('.')[0]
                trace('record-'+phase)
                if phase=='completion' and s['failure']=='completion-failure':out.update(failed=True,rc=1,msg='completion durability failed')
                else:s['records'][phase]=json.loads(args['content'])
            else:raise AssertionError('unexpected action '+str(action))
            recording.write_text(json.dumps(s));return out
    def handler(executor,templar):
        if executor._task.action in ('ansible.builtin.assert','ansible.builtin.set_fact','ansible.builtin.debug','ansible.builtin.fail'):
            return original(executor,templar)
        from ansible.template import Templar
        return Fake(task=executor._task,connection=executor._connection,play_context=executor._play_context,
            loader=executor._loader,templar=Templar._from_template_engine(templar),shared_loader_obj=executor._shared_loader_obj),None
    monkeypatch.setattr(TaskExecutor,'_get_action_handler_with_module_context',handler)
    context.CLIARGS=ImmutableDict(connection='local',forks=1,become=False,check=False,diff=False,verbosity=0,syntax=syntax,start_at_task=None,tags=[],skip_tags=[])
    loader=DataLoader();loader.set_basedir(str(BASE/'ansible'))
    inv=InventoryManager(loader=loader,sources='proxmox_hypervisors,');vm=VariableManager(loader=loader,inventory=inv)
    source=BASE/'ansible/proxmox-host-swap.yml'
    data=yaml.safe_load(source.read_text()) if source.exists() else [dict(hosts='proxmox_hypervisors',gather_facts=False,tasks=[])]
    data[0]['become']=False;data[0]['vars']=dict(data[0].get('vars',{}),qcl_host_storage=cfg)
    pb=tmp_path/'playbook.yml';pb.write_text(yaml.safe_dump(data,sort_keys=False))
    if (BASE/'ansible/templates').exists():(tmp_path/'templates').symlink_to(BASE/'ansible/templates',target_is_directory=True)
    rc=PlaybookExecutor(playbooks=[str(pb)],inventory=inv,variable_manager=vm,loader=loader,passwords={}).run()
    return rc,json.loads(recording.read_text())


def retained_output(capfd):
    output=capfd.readouterr()
    print(output.out,end='');print(output.err,end='')
    return output.out+output.err


def assert_boundary(rc,observed,output,predicate,*,query=None,forbidden=None,phase=None):
    import re
    assert rc!=0
    tasks=re.findall(r'TASK \[([^\]]+)\]',output)
    fatal=re.search(r'(?:fatal:|\[ERROR\]:)',output)
    assert fatal is not None, 'missing actual fatal output'
    prefix=output[:fatal.start()]
    task=re.findall(r'TASK \[([^\]]+)\]',prefix)[-1]
    # Ansible may emit a source diagnostic before the recap fatal; first error is still bounded to the current TASK.
    assert task==predicate, (task,predicate)
    message='host_swap:'+predicate if ' ' not in predicate else 'Host swap refusal:'
    assert message in output[fatal.start():]
    queries=observed['native_queries']
    if query is not None:
        matches=[q for q in queries if q['task']==query]
        assert matches and all(q['rc']==0 for q in matches)
        if phase is not None:assert all(q['phase']==phase for q in matches)
    kinds=[r['kind'] for r in observed['trace']]
    if forbidden is None:assert kinds==[]
    else:assert not set(kinds)&set(forbidden)
    assert not any('unexpected native argv' in text or 'unexpected primitive' in text or 'native host operation escaped' in text for text in (output,))


@pytest.mark.parametrize('name',CASES)
def test_actual_additive_swap_boundary(name,tmp_path,monkeypatch,capfd):
    cfg,s=configure(name,settings(),state())
    rc,observed=execute(cfg,s,tmp_path,monkeypatch)
    kinds=[row['kind'] for row in observed['trace']]
    success=name in ('fresh','disabled','preflight-only','partial-resume','formatted-resume','active-resume','old-used-changes')
    output=retained_output(capfd)
    assert (rc==0) is success
    if success and name not in ('disabled','preflight-only'):
        assert_lifecycle_history(observed)
    early={'stale-admission':'clock_origin','bool-target':'Finite exact geometry','false-apply':'Strict opt in','wrong-fs':'final_mount_entry','wrong-rdev':'final_mount_entry','wrong-mount-policy':'final_mount_entry','unknown-file':'owned_existing','unknown-directory':'owned_existing','hardlink':'owned_existing','creation-collision':'create_exclusive_transport','parent-sync-failure':'mkdir_parent_transport','receipt-sync-failure':'mkdir_receipts_transport','signature-error':'blkid_entry_transport','layout-gap':'full_allocated','layout-unwritten':'full_allocated','thin-reserve':'capacity_entry','metadata-unknown':'pool_semantics_entry'}
    if name in early:
        mutation_before=name in ('creation-collision','parent-sync-failure','receipt-sync-failure','layout-gap','layout-unwritten')
        assert_boundary(rc,observed,output,early[name],forbidden=('format','start','enable','record-completion') if mutation_before else None)
    if name in ('wrong-page-usable','old-swap-missing','completion-failure'):
        predicate={'wrong-page-usable':'actual_new_swap','old-swap-missing':'original_old_set_post','completion-failure':'write_completion_transport'}[name]
        assert_boundary(rc,observed,output,predicate,forbidden=('enable','record-completion','seal-completion') if name!='completion-failure' else ('seal-completion',))
    if name in ('fresh','partial-resume','old-used-changes'):
        assert kinds.count('fill')==1 and kinds.count('format')==1 and kinds.count('start')==1
    if name in ('fresh','old-used-changes'):
        assert cfg['swap']['binding_sha256'] is None and not s['exists']
        assert kinds.count('create-exclusive')==1
        assert kinds.index('create-exclusive')<kinds.index('seal-binding')<kinds.index('fill')
    if name=='partial-resume':
        assert type(cfg['swap']['binding_sha256']) is str and s['exists']
        assert s['file']['size']<cfg['swap']['target_mib']*MIB
        assert 'create-exclusive' not in kinds and 'record-binding' not in kinds
    if name in ('fresh','old-used-changes'):
        assert kinds.index('sync-parent-entry')<kinds.index('seal-binding')
        assert kinds.index('sync-receipts-entry')<kinds.index('seal-binding')
    if name=='formatted-resume':assert 'fill' not in kinds and 'format' not in kinds and 'start' in kinds
    if name=='active-resume':assert 'fill' not in kinds and 'format' not in kinds and 'start' not in kinds and 'unit' not in kinds
    if name in ('disabled','preflight-only'):assert kinds==[]
    if name=='disabled':assert observed['probes']==[]
    if name in ('parent-sync-failure','receipt-sync-failure','creation-collision'):
        assert 'fill' not in kinds and 'format' not in kinds and 'start' not in kinds
    if name in ('layout-gap','layout-unwritten'):assert 'format' not in kinds and 'start' not in kinds
    if name in ('activation-timeout-late','completion-failure'):
        assert observed['active'] and observed['records'].get('activation_intent')
        assert kinds.count('fill')==1 and kinds.count('format')==1 and kinds.count('start')==1
    if name=='activation-timeout-late':
        assert_boundary(rc,observed,output,'start_failed_outcome_observed',forbidden=('enable','record-completion','seal-completion'))
        start=next(r for r in observed['trace'] if r['kind']=='start')
        late=[q for q in observed['native_queries'] if q['index']>start['index']]
        assert [Path(q['argv'][0]).name for q in late]==['swapon','systemctl']
    if name=='sticky-intent-inactive':assert_boundary(rc,observed,output,'activation_existing')
    if name=='active-changed-policy':assert_boundary(rc,observed,output,'unit_policy_entry',query='swap_properties_entry')
    assert not any('swapoff' in str(row) or 'restart' in str(row) or 'stopped' in str(row) for row in observed['trace'])
    if name not in ('disabled','preflight-only') and success:assert observed['active'] and observed['unit_enabled']


def helper():
    path=BASE/'ops/host_swap_file_probe.py'
    if not path.exists():pytest.fail('missing bounded readonly swap file probe',pytrace=False)
    spec=importlib.util.spec_from_file_location('swap_probe',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def fiemap(extents):
    header=struct.pack('=QQIIII',0,4096,1,len(extents),16,0)
    return header+b''.join(struct.pack('=QQQQQIIII',logical,physical,length,0,0,flags,0,0,0) for logical,physical,length,flags in extents)+bytes((16-len(extents))*56)


@pytest.mark.parametrize('case',['dense','past-eof','gap','unwritten','shared','delalloc','unknown','cap','inode-race','hardlink','symlink','negative-cap'])
def test_readonly_fiemap_probe(case,tmp_path,monkeypatch):
    module=helper();path=tmp_path/'file';path.write_bytes(bytes(4096))
    before=path.read_bytes()
    extents=[(0,8192,4096,1)]
    if case=='past-eof':extents=[(0,8192,8192,1)]
    if case=='gap':extents=[(1024,8192,3072,1)]
    flags={'unwritten':0x800,'shared':0x2000,'delalloc':0x4,'unknown':0x2}
    if case in flags:extents=[(0,8192,4096,flags[case]|1)]
    if case=='cap':extents=[(0,8192,4096,0)]
    if case=='hardlink':os.link(path,tmp_path/'other')
    if case=='symlink':path.unlink();path.symlink_to(tmp_path/'missing')
    def injected(fd,request,buffer,mutate=True):
        assert request==0xC020660B
        encoded=fiemap(extents);buffer[:len(encoded)]=encoded
        if case=='inode-race':
            path.write_bytes(b'x'*4096)
        return 0
    if case in ('symlink','negative-cap'):
        with pytest.raises((ValueError,OSError)):
            module.probe(path,maximum_extents=-1 if case=='negative-cap' else 16,maximum_bytes=4096,ioctl_fn=injected,hole_fn=lambda fd:4096)
        return
    result=module.probe(path,maximum_extents=16,maximum_bytes=4096,ioctl_fn=injected,hole_fn=lambda fd:4096)
    if case in ('dense','past-eof'):assert result['coverage_complete'] and result['stable'] and result['unsupported_flags']==0
    if case=='gap':assert not result['coverage_complete']
    if case in flags:assert result['unsupported_flags']!=0
    if case=='cap':assert result['scan_capped'] and not result['coverage_complete']
    if case=='inode-race':assert not result['stable']
    if case=='hardlink':assert result['stat']['nlink']==2
    if case!='inode-race':assert path.read_bytes()==before


def primitive_namespace():
    code=yaml.safe_load((BASE/'ansible/proxmox-host-swap.yml').read_text())[0]['vars']['run_code']
    ns={'__name__':'saved_primitive'};exec(compile(code,'saved-budget-primitive','exec'),ns)
    return ns


def primitive_usage(ns,seconds=5,output=65536):
    import time
    return ns['init_usage'](dict(attempt_id='owned-test',boot_id='owned-boot',admission_expires_epoch_ns=time.time_ns()+10**10,ledger_expires_epoch_ns=time.time_ns()+10**10,limits=dict(preflight_ns=int(seconds*10**9),allocation_ns=int(seconds*10**9),activation_ns=int(seconds*10**9),aggregate_ns=int(seconds*10**9),output_bytes=output,write_bytes=8192,metadata_write_bytes=8192)))


def test_directory_primitive_parent_entry_durability(tmp_path,monkeypatch):
    ns=primitive_namespace();code=yaml.safe_load((BASE/'ansible/proxmox-host-swap.yml').read_text())[0]['vars']['primitive_code']
    exec(compile(code,'saved-directory-primitive','exec'),ns)
    target=tmp_path/'owned';seen=[]
    def fsync(fd):seen.append(Path(os.readlink('/proc/self/fd/'+str(fd))))
    monkeypatch.setattr(os,'fsync',fsync)
    usage,_=ns['precharge'](primitive_usage(ns),'allocation',1024,1024)
    ns['mkdir_one'](usage,'allocation',str(target))
    assert target.is_dir() and target in seen and tmp_path in seen
    assert seen.index(tmp_path)<seen.index(target)


def test_actual_engine_syntax(tmp_path,monkeypatch):
    import ast
    data=yaml.safe_load((BASE/'ansible/proxmox-host-swap.yml').read_text())
    for name,code in data[0]['vars'].items():
        if name.endswith('_code'):ast.parse(code,filename=name)
    ast.parse((BASE/'ops/host_swap_file_probe.py').read_text(),filename='readonly-helper')
    assert data[0]['hosts']=='proxmox_hypervisors' and data[0]['gather_facts'] is False


@pytest.fixture(scope='session',autouse=True)
def actual_engine_syntax_after_whole_file(request,tmp_path_factory):
    yield
    if request.session.testsfailed:
        return
    with pytest.MonkeyPatch.context() as patch:
        rc,observed=execute({},state(),tmp_path_factory.mktemp('accepted-whole-file-syntax'),patch,syntax=True)
        assert rc==0 and observed['trace']==[] and observed['probes']==[]
        print('ACTUAL_ENGINE_SYNTAX_AFTER_WHOLE_FILE_PASS rc=0 native_probes=0')


@pytest.mark.parametrize('case',['closed-streams-timeout','leader-exited-descendant-streams','closed-streams-success'])
def test_capture_primitive_bounded_wait(case,monkeypatch):
    """The saved capture function sees synthetic own-anchor metadata, never a real child."""
    import selectors,signal,subprocess,time
    from types import SimpleNamespace
    ns=primitive_namespace();usage=primitive_usage(ns);usage,deadline=ns['precharge'](usage,'preflight')
    calls=[];killed=[];anchor=(424242,99,424242,424242,b'S')
    process=SimpleNamespace(pid=anchor[0],stdout=SimpleNamespace(close=lambda:None),stderr=SimpleNamespace(close=lambda:None))
    def popen(argv,**kw):
        assert argv[0]==ns['sys'].executable and argv[2]==ns['SUPERVISOR']
        assert json.loads(argv[4])==['/fixture/never-executed']
        assert kw['start_new_session'] is True and kw['stdout']==subprocess.PIPE and kw['stderr']==subprocess.PIPE
        return process
    def wait(timeout=None):
        assert type(timeout) in (int,float) and 0<timeout<=5;calls.append(timeout);return -9 if killed else 0
    process.wait=wait;process.poll=lambda:0 if case=='leader-exited-descendant-streams' else None
    class Selector:
        def __init__(self):self.rows={}
        def register(self,stream,event,output):self.rows[id(stream)]=SimpleNamespace(fd=id(stream),fileobj=stream,data=output)
        def get_map(self):return self.rows
        def select(self,timeout):return [(r,1) for r in list(self.rows.values())]
        def unregister(self,stream):self.rows.pop(id(stream))
        def close(self):pass
    def read(fd,size):
        # Status uses an owned synthetic completion message; all capture streams close immediately.
        row=next((r for r in selector.rows.values() if r.fd==fd),None)
        if row and row.data=='status' and not getattr(process,'status_sent',False):
            process.status_sent=True
            return b'{"complete":true,"rc":0}\n' if case=='closed-streams-success' else b''
        return b''
    selector=Selector();monkeypatch.setattr(selectors,'DefaultSelector',lambda:selector)
    monkeypatch.setattr(os,'read',read);monkeypatch.setattr(os,'write',lambda fd,payload:len(payload))
    def killpg(pgid,sig):assert pgid==anchor[2] and sig in (signal.SIGTERM,signal.SIGKILL);killed.append(sig)
    monkeypatch.setattr(os,'killpg',killpg)
    clock=SimpleNamespace(now=usage['last_monotonic_ns'])
    def monotonic():clock.now+=100000000;return clock.now
    monkeypatch.setattr(time,'monotonic_ns',monotonic)
    result=ns['capture'](['/fixture/never-executed'],usage,'preflight',deadline,popen_fn=popen,stat_fn=lambda pid:anchor,member_fn=lambda a:[anchor]+([] if case=='closed-streams-success' else [(424243,100,424242,424242,b'S')]))
    assert result[3] is (case=='closed-streams-success') and calls
    assert killed==([] if case=='closed-streams-success' else [signal.SIGTERM,signal.SIGKILL])


@pytest.mark.parametrize('case',['expiry-before-popen','expiry-before-write','cumulative-output','precharge-total','precharge-metadata','no-overwrite'])
def test_actual_budget_atomic_guards(case,tmp_path,monkeypatch):
    import time
    ns=primitive_namespace();code=yaml.safe_load((BASE/'ansible/proxmox-host-swap.yml').read_text())[0]['vars']['primitive_code'];exec(compile(code,'saved-atomic-primitive','exec'),ns)
    u=primitive_usage(ns);target=tmp_path/'file';called=[]
    if case.startswith('expiry'):
        u['admission_expires_epoch_ns']=time.time_ns()-1
        if case=='expiry-before-popen':
            with pytest.raises(TimeoutError):ns['capture'](['/never'],u,'preflight',u['deadline_monotonic_ns'],popen_fn=lambda *a,**k:called.append('Popen'))
        else:
            with pytest.raises(TimeoutError):ns['mkdir_one'](dict(u,write_bytes_reserved=1024,metadata_bytes_reserved=1024),'allocation',str(target))
        assert not called and not target.exists()
    elif case=='cumulative-output':
        first=ns['finish'](u,'preflight',0,b'x'*20000,b'',True,None);u=json.loads(first)['usage']
        with pytest.raises(ValueError):ns['finish'](u,'preflight',0,b'x'*40000,b'',True,None)
        assert u['output_bytes']==len(first) and not target.exists()
    elif case.startswith('precharge'):
        u['limits']['write_bytes' if case=='precharge-total' else 'metadata_write_bytes']=1024
        with pytest.raises(ValueError):ns['precharge'](u,'allocation',2048,2048)
        assert u['write_bytes_reserved']==u['metadata_bytes_reserved']==0
    else:
        target.write_bytes(b'original');u,_=ns['precharge'](u,'allocation',4096,4096)
        with pytest.raises(FileExistsError):ns['atomic_bytes'](u,'allocation',str(target),b'new',384,4096)
        assert target.read_bytes()==b'original'


@pytest.mark.parametrize('case',['closed-streams-descendant','unrelated-survives','bounded-normal-success'])
def test_actual_owned_group_lifetime(case,tmp_path):
    import subprocess,sys,time
    ns=primitive_namespace();u=primitive_usage(ns,seconds=3);u,deadline=ns['precharge'](u,'preflight')
    other=None
    try:
        if case=='unrelated-survives':other=subprocess.Popen([sys.executable,'-c','import time;time.sleep(5)'],start_new_session=True)
        if case=='bounded-normal-success':code='print("owned-complete")'
        else:code='import subprocess,sys,os; subprocess.Popen([sys.executable,"-c","import os,time;os.close(1);os.close(2);time.sleep(5)"]);os.close(1);os.close(2)'
        started=time.monotonic();result=ns['capture']([sys.executable,'-c',code],u,'preflight',deadline)
        assert time.monotonic()-started<3.5
        assert result[3] is (case=='bounded-normal-success')
        if case=='bounded-normal-success':assert result[1]==b'owned-complete\n'
        if other is not None:assert other.poll() is None
    finally:
        if other is not None:other.terminate();other.wait(timeout=2)


REVIEW_RED_CASES=['foreign-file-fs','healthy-open-pool','stale-format-intent','missing-condition',
                  'write-cap-target-only','charge-once','preflight-wrong-uuid']


def review_configuration(name):
    cfg,s=settings(),state()
    cfg['tools'].update(busctl='/usr/bin/busctl',wipefs='/usr/sbin/wipefs')
    cfg['swap']['support'].update(busctl_json=True,wipefs_json=True,header_write_bytes=4096,synchronous_child_scope=True)
    cfg['swap']['budgets'].update(maximum_metadata_write_bytes=65536,maximum_write_bytes=4*MIB+4096+65536,
                                maximum_output_bytes=524288)
    if name=='foreign-file-fs':
        # Existing owned partial file on a mounted foreign filesystem, not invented O_EXCL device.
        seed_owned(cfg,s,stage='partial')
        s['parent_dev']=os.makedev(8,2)
        s['file'].update(dev=os.makedev(8,2),dev_major=8,dev_minor=2)
        binding=s['records']['binding']
        binding['payload']['file']['dev']=s['file']['dev']
        binding['payload']['parent']['dev']=s['parent_dev']
        cfg['swap']['binding_sha256']=fixture_hash(binding)
        assert_seed_coherent(cfg,s,'partial')
        s['submount']=dict(target=cfg['swap']['parent'],source='/dev/mapper/foreign',
            uuid='55555555-5555-4555-8555-555555555555',fstype='ext4',fsroot='/',**{'maj:min':'8:2'})
    if name=='healthy-open-pool':s['pool_attr']='twi-aotz--'
    if name=='stale-format-intent':
        seed_owned(cfg,s,stage='full_blank')
        static=s['records']['binding']['payload']['file']
        s['records']['format_intent']=phase_envelope(cfg,s,'format_intent',dict(file_identity=static,target_bytes=4*MIB,page_bytes=4096,header_uuid=UUID))
    if name=='missing-condition':
        seed_owned(cfg,s,stage='active');s['conditions']=[]
    if name=='write-cap-target-only':cfg['swap']['budgets']['maximum_write_bytes']=4*MIB
    if name=='charge-once':
        s.update(pool_free=21*MIB,fs_free=6*MIB,charge_after_fill=True)
    if name=='preflight-wrong-uuid':
        seed_owned(cfg,s,stage='formatted');s['signature']['UUID']='44444444-4444-4444-8444-444444444444'
        cfg.update(apply=False,preflight_only=True)
    return cfg,s


@pytest.mark.parametrize('name',REVIEW_RED_CASES)
def test_review_seven_gaps(name,tmp_path,monkeypatch,capfd):
    cfg,s=review_configuration(name)
    if name=='foreign-file-fs':
        import hashlib
        binding=s['records']['binding']
        assert s['exists'] and s['parent_exists'] and s['owned'] and not s['active']
        assert binding['payload']['file']['dev']==s['file']['dev']==binding['payload']['parent']['dev']==os.makedev(8,2)
        assert binding['payload']['file']['inode']==s['file']['inode']==81 and binding['payload']['parent']['inode']==80
        assert cfg['swap']['binding_sha256']==hashlib.sha256(json.dumps(binding,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        assert cfg['swap']['mount']['rdev']=='253:4' and s['submount']['target']==cfg['swap']['parent']
    rc,observed=execute(cfg,s,tmp_path,monkeypatch)
    output=retained_output(capfd)
    if name not in ('healthy-open-pool','charge-once'):
        predicate={'foreign-file-fs':'finalfs_device_entry','stale-format-intent':'format_intent_existing','missing-condition':'unit_conditions_entry','write-cap-target-only':'fresh_write_allowance','preflight-wrong-uuid':'signature_detection_entry'}[name]
        assert_boundary(rc,observed,output,predicate)
    assert (rc==0) is (name in ('healthy-open-pool','charge-once'))
    if name not in ('healthy-open-pool','charge-once'):
        assert observed['trace']==[], 'refuse before writes, formatting, reload, start or enable'
    else:
        kinds=[r['kind'] for r in observed['trace']]
        assert kinds.count('fill')==1 and kinds.count('format')==1 and kinds.count('start')==1
        assert observed['active'] and observed['unit_enabled']


@pytest.mark.parametrize('case',['foreign-existing-parent','same-fs-bind','context-header','missing-predecessor','format-uuid','unit-stat','completion-baseline','header-geometry'])
def test_independent_v2_native_and_record_guards(case,tmp_path,monkeypatch,capfd):
    import hashlib
    cfg,s=settings(),state()
    if case in ('foreign-existing-parent','same-fs-bind'):
        s.update(parent_exists=True,safe_parent=True)
        dev=os.makedev(8,2) if case=='foreign-existing-parent' else os.makedev(253,4)
        s['parent_dev']=dev
        s['submount']=dict(target=cfg['swap']['parent'],source='/dev/mapper/foreign' if case=='foreign-existing-parent' else '/dev/mapper/final',uuid='55555555-5555-4555-8555-555555555555' if case=='foreign-existing-parent' else FS,fstype='ext4',fsroot='/' if case=='foreign-existing-parent' else '/bound-parent',**{'maj:min':'8:2' if case=='foreign-existing-parent' else '253:4'})
        assert not s['exists'] and not s['records'] and cfg['swap']['binding_sha256'] is None
    else:
        seed_owned(cfg,s,stage='completed' if case=='completion-baseline' else 'active' if case=='unit-stat' else 'formatted')
        if case=='header-geometry':
            s['other_header_page']=True
            s['records']['header']['payload']['sample_sha256']=fixture_sample_hash(UUID,4096,True)
        if case=='context-header':cfg['swap']['header_uuid']='44444444-4444-4444-8444-444444444444'
        if case=='missing-predecessor':del s['records']['allocation']
        if case=='format-uuid':s['records']['format_intent']['payload']['header_uuid']='44444444-4444-4444-8444-444444444444'
        if case=='unit-stat':s['records']['unit']['payload']['fragment_stat']['inode']=100
        if case=='completion-baseline':s['records']['completion']['payload']['old_static_swaps']=[]
    rc,observed=execute(cfg,s,tmp_path,monkeypatch)
    output=retained_output(capfd)
    assert rc!=0 and observed['trace']==[]
    predicate={'foreign-existing-parent':'finalfs_device_entry','same-fs-bind':'finalfs_target_entry','context-header':'binding_v2','missing-predecessor':'phase_format_intent','format-uuid':'format_intent_existing','unit-stat':'unit_existing','completion-baseline':'completion_existing','header-geometry':'header_geometry_entry'}[case]
    required={'foreign-existing-parent':'longest_mount_entry','same-fs-bind':'longest_mount_entry','context-header':'records_entry','missing-predecessor':'records_entry','format-uuid':'blkid_entry','unit-stat':'fragment_entry','completion-baseline':'completion_budget_shape','header-geometry':'file_entry'}
    assert_boundary(rc,observed,output,predicate,query=required[case])
    if case in ('foreign-existing-parent','same-fs-bind'):
        assert 'findmnt' in observed['probes'] and 'lvs' not in observed['probes']
        longest=[q for q in observed['native_queries'] if Path(q['argv'][0]).name=='findmnt' and '--target' in q['argv']]
        assert len(longest)==1 and longest[0]['argv'][longest[0]['argv'].index('--target')+1]==cfg['swap']['parent']
        actual=json.loads(longest[0]['stdout'])['filesystems'][0]
        assert actual==s['submount'] and longest[0]['rc']==0 and longest[0]['stderr']=='' 


@pytest.mark.parametrize('case',['duplicate-json','float-json','bool-counter','unknown-budget-key'])
def test_actual_strict_protocol_shapes(case):
    ns=primitive_namespace()
    if case in ('duplicate-json','float-json'):
        with pytest.raises(ValueError):ns['strict_load']('{"rc":0,"rc":1}' if case=='duplicate-json' else '{"rc":0.0}')
    else:
        u=primitive_usage(ns)
        if case=='bool-counter':u['output_bytes']=True
        else:u['foreign_key']=0
        with pytest.raises(ValueError):ns['validate_usage'](u)


@pytest.mark.parametrize('case',['matching-header','magic-other-page','last-page-mismatch','bad-pages-present'])
def test_readonly_header_metadata(case,tmp_path):
    import uuid
    module=helper();page=bytearray(4096);struct.pack_into('=III',page,1024,1,0 if case=='last-page-mismatch' else 1023,1 if case=='bad-pages-present' else 0);page[1036:1052]=uuid.UUID(UUID).bytes
    if case!='magic-other-page':page[-10:]=b'SWAPSPACE2'
    path=tmp_path/'owned-header';path.write_bytes(page)
    def injected(fd,request,buffer,mutate=True):buffer[:]=fiemap([(0,8192,4096,1)])
    observed=module.probe(path,maximum_extents=16,maximum_bytes=4096,ioctl_fn=injected,hole_fn=lambda fd:4096)
    raw=observed['header_metadata']
    assert raw==dict(magic_hex=page[-10:].hex(),version=1,last_page=0 if case=='last-page-mismatch' else 1023,badpages=1 if case=='bad-pages-present' else 0,uuid=UUID)
    assert path.read_bytes()==page and observed['observed_bytes']==4096 and observed['stable']



def assert_lifecycle_history(observed):
    history=observed['wire_usage_history']
    assert history
    for previous,current in zip(history,history[1:]):
        before=current['incoming'];after=current['returned']
        assert before==previous['returned']
        assert after['sequence']==before['sequence']+1
        assert after['started_monotonic_ns']==before['started_monotonic_ns']
        assert after['deadline_monotonic_ns']==before['deadline_monotonic_ns']
        assert after['limits']==before['limits']
        assert after['output_bytes']>before['output_bytes']
        assert after['write_bytes_reserved']==before['write_bytes_reserved']+current['precharge']['write']
        assert after['metadata_bytes_reserved']==before['metadata_bytes_reserved']+current['precharge']['metadata']
    starts=[r for r in observed['trace'] if r['kind']=='start']
    if starts:
        assert len(starts)==1
        seal=next(r for r in observed['trace'] if r['kind']=='seal-activation_intent')
        assert seal['index']<starts[0]['index']
        reads=[q for q in observed['native_queries'] if seal['index']<q['index']<starts[0]['index']]
        assert any(q['task']=='file_start_guard' for q in reads)
        assert any(Path(q['argv'][0]).name=='findmnt' for q in reads)
        assert any(Path(q['argv'][0]).name=='blkid' for q in reads)
    if 'completion' in observed['records']:
        stored=observed['records']['completion']['payload']['budget_usage']
        publication=[h for h in history if h['task']=='write_completion']
        if publication:
            assert publication[-1]['incoming']==stored
            assert publication[-1]['returned']['write_bytes_reserved']>stored['write_bytes_reserved']


@pytest.mark.parametrize('stage',STAGES)
def test_factory_stage_coherence(stage):
    cfg,s=settings(),state();seed_owned(cfg,s,stage=stage)
    assert_seed_coherent(cfg,s,stage)
    assert expected_fragment(cfg).endswith('\n') and not expected_fragment(cfg).endswith('\n\n')
    assert not expected_fragment(cfg).endswith('\\n')


@pytest.mark.parametrize('case',['ledger-above-target','ledger-below-target','reserve-pool-minus-one','reserve-fs-minus-one','completed-resume','legacy-refusal','format-uuid-stale','blank-format-intent','preflight-known-header'])
def test_whole_repair_vectors(case,tmp_path,monkeypatch,capfd):
    cfg,s=settings(),state()
    if case=='ledger-above-target':cfg['swap']['ledger']['incremental_swap_bytes']=8*MIB;s['pool_free']=21*MIB
    if case=='ledger-below-target':
        cfg['swap']['ledger']['incremental_swap_bytes']=2*MIB
        s.update(pool_free=19*MIB,fs_free=4*MIB,after_fill_pool=17*MIB,after_fill_fs=2*MIB)
    if case.startswith('reserve-'):
        s.update(pool_free=21*MIB,fs_free=6*MIB,after_fill_pool=17*MIB-(case=='reserve-pool-minus-one'),after_fill_fs=2*MIB-(case=='reserve-fs-minus-one'))
    if case=='completed-resume':seed_owned(cfg,s,stage='completed')
    if case=='legacy-refusal':seed_legacy_owned(cfg,s)
    if case=='format-uuid-stale':
        seed_owned(cfg,s,stage='formatted');s['records']['format_intent']['payload']['header_uuid']='44444444-4444-4444-8444-444444444444'
    if case=='blank-format-intent':
        seed_owned(cfg,s,stage='full_blank')
        s['records']['format_intent']=phase_envelope(cfg,s,'format_intent',dict(file_identity=s['records']['binding']['payload']['file'],target_bytes=4*MIB,page_bytes=4096,header_uuid=UUID))
    if case=='preflight-known-header':seed_owned(cfg,s,stage='formatted');cfg.update(apply=False,preflight_only=True)
    rc,observed=execute(cfg,s,tmp_path,monkeypatch);output=retained_output(capfd)
    success=case in ('ledger-below-target','completed-resume','preflight-known-header')
    assert (rc==0) is success
    if success:
        if case!='preflight-known-header':assert_lifecycle_history(observed)
        if case=='ledger-below-target':
            kinds=[r['kind'] for r in observed['trace']];assert kinds.count('fill')==kinds.count('format')==kinds.count('start')==1
        else:assert observed['trace']==[]
    else:
        predicate='capacity_entry' if case=='ledger-above-target' else 'capacity_allocated' if case.startswith('reserve-') else 'owned_existing' if case=='legacy-refusal' else 'format_intent_existing'
        assert_boundary(rc,observed,output,predicate,forbidden=('format','start','enable','record-completion') if case.startswith('reserve-') else None)
        if case=='ledger-above-target':
            queries=[q for q in observed['native_queries'] if Path(q['argv'][0]).name=='lvs']
            assert queries and cfg['swap']['ledger']['incremental_swap_bytes']==8*MIB
            assert json.loads(queries[-1]['stdout'])['report'][0]['lv'][0]['data_percent']==str(100*(1-21*MIB/(256*MIB)))


@pytest.mark.parametrize('case',['cleanup-unknown-finish-error','oversized-attempt','oversized-boot'])
def test_actual_main_io_certainty(case,monkeypatch,capfd):
    import sys
    ns=primitive_namespace();called=[]
    if case=='cleanup-unknown-finish-error':
        u=primitive_usage(ns);argv=['fixture','run-v2',json.dumps(u),'preflight','0','0','["/fixture/never"]']
        def capture(*args):called.append('capture');return 124,b'x'*65536,b'',False,'cleanup_unknown'
        monkeypatch.setitem(ns,'capture',capture)
    else:
        u=primitive_usage(ns)
        config={k:u[k] for k in ('attempt_id','boot_id','admission_expires_epoch_ns','ledger_expires_epoch_ns','limits')}
        config['attempt_id' if case=='oversized-attempt' else 'boot_id']='é'*65
        argv=['fixture','clock-v2',json.dumps(config)]
        monkeypatch.setitem(ns,'capture',lambda *args:called.append('capture'))
    monkeypatch.setattr(sys,'argv',argv)
    try:ns['main_io']()
    except SystemExit as error:assert error.code==125
    output=retained_output(capfd)
    if case=='cleanup-unknown-finish-error':
        result=json.loads(output)
        assert called==['capture'] and result['owned_children_complete'] is False and result['failure']=='cleanup_unknown'
        assert len(output.encode())<=u['limits']['output_bytes']
    else:assert not called and not output


CLI_CONTROLS=('busctl-unit-order','swapon-option-order','systemctl-property-separate','findmnt-option-order','dd-operand-order','mkswap-option-order','duplicate-option','unknown-option','extra-operand')


@pytest.mark.parametrize('case',CLI_CONTROLS)
def test_cli_semantic_controls(case):
    cfg=settings()
    vectors={
      'busctl-unit-order':['/usr/bin/busctl','get-property','--json=short','org.freedesktop.systemd1','--system','/org/freedesktop/systemd1/unit/fixture_swap','org.freedesktop.systemd1.Unit',*UNIT_PROPERTIES],
      'swapon-option-order':['/usr/bin/swapon','--output='+SWAP_FIELDS,'--bytes','--show','--json'],
      'systemctl-property-separate':['/usr/bin/systemctl','--property','LoadState','show',UNIT],
      'findmnt-option-order':['/usr/bin/findmnt','--output='+FIND_FIELDS,'--target='+PATH,'--json'],
      'dd-operand-order':['/usr/bin/dd','count=4','oflag=nofollow,direct','of='+PATH,'if=/dev/zero','conv=fsync,notrunc,nocreat','bs=1M'],
      'mkswap-option-order':['/usr/bin/mkswap',PATH,'--pagesize=4096','--uuid='+UUID],
      'duplicate-option':['/usr/bin/swapon','--show','--show','--json','--bytes','--output',SWAP_FIELDS],
      'unknown-option':['/usr/bin/swapon','--foreign'],
      'extra-operand':['/usr/bin/swapon','--show','--json','--bytes','--output',SWAP_FIELDS,PATH]}
    if case in ('duplicate-option','unknown-option','extra-operand'):
        with pytest.raises(AssertionError):parse_native_cli(vectors[case],cfg)
    else:parse_native_cli(vectors[case],cfg)



@pytest.mark.parametrize('case',['start-inactive','start-cleanup-unknown','start-exhausted','start-malformed-usage'])
def test_failed_start_readonly_outcome(case,tmp_path,monkeypatch,capfd):
    cfg,s=settings(),state();s['failure']=case
    rc,observed=execute(cfg,s,tmp_path,monkeypatch);output=retained_output(capfd)
    start=next(r for r in observed['trace'] if r['kind']=='start')
    late=[q for q in observed['native_queries'] if q['index']>start['index']]
    known=case in ('start-inactive','start-cleanup-unknown')
    predicate='start_failed_outcome_observed' if known else 'start_failed_outcome_unknown'
    assert_boundary(rc,observed,output,predicate,forbidden=('enable','record-completion','seal-completion'))
    assert observed['records'].get('activation_intent') and len([r for r in observed['trace'] if r['kind']=='start'])==1
    if known:
        assert len(late)==2 and [Path(q['argv'][0]).name for q in late]==['swapon','systemctl']
        assert late[0]['index']<late[1]['index'] and all(q['phase']=='activation' for q in late)
        rows=json.loads(late[0]['stdout'])['swaps']
        assert any(row['name']==PATH for row in rows) is (case!='start-inactive')
    else:assert not late


@pytest.mark.parametrize('value',[None,True,1.0,9223372036854775808],ids=['null','boolean','float','oversize'])
def test_unknown_incremental_ledger(value,tmp_path,monkeypatch,capfd):
    cfg,s=settings(),state();cfg['swap']['ledger']['incremental_swap_bytes']=value
    rc,observed=execute(cfg,s,tmp_path,monkeypatch)
    assert_boundary(rc,observed,retained_output(capfd),'ledger_incremental')


@pytest.mark.parametrize('failure',[None,'cleanup_unknown','budget_or_io_refusal','post_budget_expired'])
def test_minimal_response_unicode_counter_bound(failure,monkeypatch):
    # Largest allowed identities and counters remain a bounded canonical 4096-byte envelope.
    import time
    ns=primitive_namespace();u=primitive_usage(ns,seconds=5,output=4096)
    u.update(attempt_id='é'*64,boot_id='é'*64,sequence=9223372036854775807,
             admission_expires_epoch_ns=9223372036854775807,ledger_expires_epoch_ns=9223372036854775807)
    u['limits'].update(write_bytes=9223372036854775807,metadata_write_bytes=9223372036854775807)
    u.update(write_bytes_reserved=9223372036854775807,metadata_bytes_reserved=9223372036854775807)
    monkeypatch.setattr(time,'monotonic_ns',lambda:u['last_monotonic_ns'])
    wire=ns['finish'](u,'preflight',125,b'',b'',failure is None,failure)
    result=json.loads(wire)
    assert len(wire)<=4096 and result['usage']['output_bytes']==len(wire)
    assert result['owned_children_complete'] is (failure is None) and result['failure']==failure
