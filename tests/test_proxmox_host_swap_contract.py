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
        tools={n:'/usr/bin/'+n.replace('_','-') for n in ['python3','dd','mkswap','swapon','blkid','timeout','systemctl','systemd_escape','findmnt','realpath','lvs','df','getconf']},
        swap=dict(enabled=True, path=PATH, parent='/srv/final/protected-swap', unit=UNIT,
            target_mib=4, authorized_cap_mib=8, header_uuid=UUID, lifetime='protected-host-infrastructure',
            receipts=REC, binding_sha256=None, mount=dict(path='/srv/final', unit='srv-final.mount',
                device='/dev/mapper/final', rdev='253:4', fs_uuid=FS, lv_uuid='image-lv', vg_uuid='vg-id', pool_uuid='pool-id',
                cutover_receipt='accepted-native-final', accepted=True),
            support=dict(fresh=True, receipt='tools-ext4-fiemap', page_bytes=4096, minimum_file_pages=10,
                maximum_file_pages=4294967295, direct=True, fiemap=True, ext4=True, swapon_json=True, systemd_version=257),
            ledger=dict(fresh=True, receipt='physical-reservation', expires_at_epoch=200,
                incremental_swap_bytes=4*MIB, protected_data_growth_bytes=8*MIB, data_reserve_bytes=8*MIB,
                data_overhead_bytes=MIB, metadata_growth_bytes=MIB, metadata_reserve_bytes=MIB,
                filesystem_growth_bytes=MIB, filesystem_reserve_bytes=MIB),
            budgets=dict(preflight_seconds=30, allocation_seconds=120, activation_seconds=30, aggregate_seconds=240,
                maximum_write_bytes=4*MIB+4096, maximum_extents=16, maximum_probe_bytes=4096, maximum_record_bytes=16384,
                maximum_output_bytes=65536, maximum_swap_rows=16)))


def file_stat(size=0):
    return dict(dev=14, inode=81, nlink=1, uid=0, gid=0, mode=384, size=size, blocks=(size+511)//512,
                mtime_ns=100, ctime_ns=100, kind='regular')


def state():
    return dict(trace=[], probes=[], exists=False, file=file_stat(), parent_exists=False, receipts_exists=False,
        owned=False, signature=None, active=False, unit_exists=False, unit_active=False, unit_enabled=False,
        records={}, malformed=None, layout_bad=False, old_changed=False, used_changes=False, failure=None,
        page_bytes=4096, fs=FS, fs_type='ext4', pool_healthy=True, pool_free=128*MIB, metadata_free=16*MIB,
        fs_free=64*MIB, mount_loaded=True, policy_bad=False, changed_inode=False, binding_orphan=False)


def seed_owned(cfg, s, *, full=False, header=False, active=False):
    s.update(exists=True, parent_exists=True, receipts_exists=True, owned=True)
    s['file']=file_stat(4*MIB if full or header or active else MIB)
    binding=dict(file={k:s['file'][k] for k in ['dev','inode','nlink','uid','gid','mode','kind']},
                 parent=dict(dev=14,inode=80,uid=0,gid=0,mode=448), receipts=dict(dev=1,inode=90,uid=0,gid=0,mode=448))
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
    if name=='unknown-file':s['exists']=True
    if name=='unknown-directory':s['parent_exists']=True
    if name=='hardlink':seed_owned(cfg,s);s['file']['nlink']=2
    if name in ('creation-collision','parent-sync-failure','receipt-sync-failure','completion-failure'):
        s['failure']=name
    if name=='partial-resume':seed_owned(cfg,s)
    if name=='formatted-resume':seed_owned(cfg,s,full=True,header=True)
    if name=='active-resume':seed_owned(cfg,s,full=True,header=True,active=True)
    if name=='active-changed-policy':seed_owned(cfg,s,full=True,header=True,active=True);s['policy_bad']=True
    if name=='signature-error':s['failure']='signature-error'
    if name in ('layout-gap','layout-unwritten'):s['layout_bad']=name
    if name=='wrong-page-usable':s['malformed']='usable'
    if name=='old-used-changes':s['used_changes']=True
    if name=='old-swap-missing':s['old_changed']=True
    if name=='activation-timeout-late':s['failure']='activation-timeout-late'
    if name=='sticky-intent-inactive':seed_owned(cfg,s,full=True,header=True,active=True);s.update(active=False,unit_active=False)
    if name=='thin-reserve':s['pool_free']=MIB
    if name=='metadata-unknown':s['metadata_free']=None
    return cfg,s


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
            def trace(kind):s['trace'].append(dict(kind=kind,args=dict(args)))
            if action=='ansible.builtin.command':
                argv=args['argv']
                if Path(argv[0]).name=='python3' and argv[3]=='run':
                    assert 0<int(argv[4])<=240 and int(argv[5])==65536
                    argv=json.loads(argv[6])
                cmd=Path(argv[0]).name
                if cmd=='timeout':
                    assert argv[1:3]==['--signal=TERM','--kill-after=5']
                    argv=argv[4:];cmd=Path(argv[0]).name
                s['probes'].append(cmd)
                if cmd=='date':out['stdout']='100'
                elif cmd=='cat':out['stdout']='fixture-host' if argv[-1]=='/etc/machine-id' else 'fixture-boot'
                elif cmd=='getconf':out['stdout']=str(s['page_bytes'])
                elif cmd=='systemd-escape':out['stdout']=UNIT
                elif cmd=='realpath':out['stdout']='/dev/dm-4'
                elif cmd=='stat':out['stdout']='253:4'
                elif cmd=='findmnt':out['stdout']=json.dumps({'filesystems':[dict(target='/srv/final',source='/dev/mapper/final',uuid=s['fs'],fstype=s['fs_type'],fsroot='/',**{'maj:min':'253:4'})]})
                elif cmd=='lvs':
                    out['stdout']=json.dumps({'report':[{'lv':[
                        dict(lv_uuid='pool-id',vg_uuid='vg-id',lv_name='hostpool',segtype='thin-pool',lv_size=str(256*MIB),lv_metadata_size=str(32*MIB),
                            data_percent=str(100*(1-s['pool_free']/(256*MIB))),metadata_percent='' if s['metadata_free'] is None else str(100*(1-s['metadata_free']/(32*MIB))),
                            lv_attr='twi-a-tz--' if s['pool_healthy'] else 'twi-a-Fz--',lv_health_status='' if s['pool_healthy'] else 'failed'),
                        dict(lv_uuid='image-lv',vg_uuid='vg-id',lv_name='final',segtype='thin',pool_lv='hostpool',lv_size=str(512*MIB),lv_path='/dev/mapper/final')]}]})
                elif cmd=='df':out['stdout']='Avail\n'+str(s['fs_free'])
                elif cmd=='swapon':
                    old=dict(OLD)
                    if s['used_changes']:old['used']+=1234
                    rows=[] if s['old_changed'] and s['active'] else [old]
                    if s['active']:rows.append(dict(name=PATH,type='file',size=4*MIB-(8192 if s['malformed']=='usable' else 4096),used=0,prio=-3))
                    out['stdout']=json.dumps({'swaps':rows})
                elif cmd=='blkid':
                    if s['failure']=='signature-error':out.update(failed=True,rc=4,stderr='unknown signature')
                    elif s['signature']:out['stdout']='\n'.join(k+'='+v for k,v in s['signature'].items())
                    else:out['rc']=2
                elif cmd=='dd':
                    assert argv==['/usr/bin/dd','if=/dev/zero','of='+PATH,'bs=1M','count=4','conv=nocreat,notrunc,fsync','oflag=direct,nofollow']
                    assert s['owned'] and not s['active'] and s['signature'] is None
                    trace('fill');s['file']=file_stat(4*MIB)
                elif cmd=='mkswap':
                    assert argv==['/usr/bin/mkswap','--uuid',UUID,PATH]
                    assert s['file']['size']==4*MIB and s['records'].get('allocation') and not s['active']
                    trace('format');s['signature']={'TYPE':'swap','UUID':UUID}
                elif cmd=='systemctl':
                    if argv[1]=='show':
                        if argv[2]=='srv-final.mount':
                            out['stdout']='\n'.join(k+'='+v for k,v in dict(LoadState='loaded' if s['mount_loaded'] else 'not-found',What='/dev/mapper/final',Where='/srv/final',Type='ext4',FragmentPath='/etc/systemd/system/srv-final.mount',DropInPaths='',NeedDaemonReload='no',ForceUnmount='no',LazyUnmount='no',Options='rw').items())
                        else:out['stdout']='\n'.join(k+'='+v for k,v in dict(LoadState='loaded' if s['unit_exists'] else 'not-found',ActiveState='active' if s['unit_active'] else 'inactive',UnitFileState='enabled' if s['unit_enabled'] else 'disabled',What='/foreign' if s['policy_bad'] else PATH,FragmentPath='/etc/systemd/system/'+UNIT,DropInPaths='',NeedDaemonReload='no',Options='',DefaultDependencies='yes',Requires='srv-final.mount',After='srv-final.mount').items())
                    elif argv[1]=='start':
                        assert argv[2]==UNIT and s['records'].get('activation_intent')
                        trace('start');s.update(active=True,unit_active=True)
                        if s['failure']=='activation-timeout-late':out.update(failed=True,rc=124,stderr='late activation')
                    elif argv[1]=='enable':trace('enable');s['unit_enabled']=True
                    elif argv[1]=='daemon-reload':trace('daemon-reload')
                    else:raise AssertionError('prohibited systemctl mutation '+repr(argv))
                elif cmd=='python3':
                    operation=argv[3]
                    if operation=='probe-file':
                        f=s['file'];dense=s['exists'] and f['size']==4*MIB and not s['layout_bad']
                        out['stdout']=json.dumps(dict(exists=s['exists'],stat=f,parent=dict(exists=s['parent_exists'],dev=14,inode=80,uid=0,gid=0,mode=448),coverage_complete=dense,unsupported_flags=2 if s['layout_bad']=='layout-unwritten' else 0,layout_hash='layout',stable=True))
                    elif operation=='records':
                        import hashlib
                        binding=s['records'].get('binding')
                        digest=None if binding is None else hashlib.sha256(json.dumps(binding,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                        out['stdout']=json.dumps(dict(exists=s['receipts_exists'],stat=dict(dev=1,inode=90,uid=0,gid=0,mode=448),records=s['records'],binding_sha256=digest))
                    elif operation=='mkdir':
                        path=argv[4]
                        if path==cfg['swap']['parent']:
                            trace('mkdir-parent')
                            if s['failure']=='parent-sync-failure':out.update(failed=True,rc=1,stderr='ancestor fsync failed')
                            else:trace('sync-parent-entry');s['parent_exists']=True
                            out['stdout']=json.dumps(dict(dev=14,inode=80,uid=0,gid=0,mode=448))
                        else:
                            trace('mkdir-receipts')
                            if s['failure']=='receipt-sync-failure':out.update(failed=True,rc=1,stderr='receipt ancestor fsync failed')
                            else:trace('sync-receipts-entry');s['receipts_exists']=True
                            out['stdout']=json.dumps(dict(dev=1,inode=90,uid=0,gid=0,mode=448))
                    elif operation=='create':
                        trace('create-exclusive')
                        if s['failure']=='creation-collision':out.update(failed=True,rc=1,stderr='O_EXCL collision')
                        else:s.update(exists=True,owned=True);out['stdout']=json.dumps(s['file'])
                    elif operation=='seal':
                        phase=Path(argv[4]).name.split('.')[0]
                        trace('seal-'+phase);out['stdout']=json.dumps(s['records'][phase])
                    else:raise AssertionError('unexpected primitive '+str(operation))
                else:raise AssertionError('unexpected native argv '+repr(argv))
            elif action=='ansible.builtin.copy':
                assert args['force'] is False and args['mode']=='0600'
                assert args['dest'].startswith(REC+'/')
                phase=Path(args['dest']).name.split('.')[0]
                trace('record-'+phase)
                if phase=='completion' and s['failure']=='completion-failure':out.update(failed=True,rc=1,msg='completion durability failed')
                else:s['records'][phase]=json.loads(args['content'])
            elif action=='ansible.builtin.template':
                from ansible._internal._datatag._tags import TrustedAsTemplate
                text=self._templar.template(TrustedAsTemplate().tag((BASE/'ansible'/args['src']).read_text()))
                assert '[Swap]\nWhat='+PATH in text and 'RequiresMountsFor=/srv/final' in text
                assert 'ConditionPathIsMountPoint=/srv/final' in text and 'TimeoutSec=30' in text and 'WantedBy=swap.target' in text
                assert 'Priority=' not in text and 'Options=' not in text and '@' not in args['dest']
                trace('unit');s['unit_exists']=True
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


@pytest.mark.parametrize('name',CASES)
def test_actual_additive_swap_boundary(name,tmp_path,monkeypatch):
    cfg,s=configure(name,settings(),state())
    rc,observed=execute(cfg,s,tmp_path,monkeypatch)
    kinds=[row['kind'] for row in observed['trace']]
    success=name in ('fresh','disabled','preflight-only','partial-resume','formatted-resume','active-resume','old-used-changes')
    assert (rc==0) is success
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
    if name=='sticky-intent-inactive':assert kinds==[]
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


def test_directory_primitive_parent_entry_durability(tmp_path,monkeypatch):
    source=BASE/'ansible/proxmox-host-swap.yml'
    if not source.exists():pytest.fail('missing directory durability primitive',pytrace=False)
    import sys
    data=yaml.safe_load(source.read_text());code=data[0]['vars']['mkdir_code']
    target=tmp_path/'owned';seen=[]
    monkeypatch.setattr(sys,'argv',['python','mkdir',str(target)])
    def fsync(fd):seen.append(Path(os.readlink('/proc/self/fd/'+str(fd))))
    monkeypatch.setattr(os,'fsync',fsync)
    exec(compile(code,'owned-directory-primitive','exec'),{'__name__':'__main__'})
    assert target.is_dir() and target in seen and tmp_path in seen
    assert seen.index(tmp_path)<seen.index(target)


def test_actual_engine_syntax(tmp_path,monkeypatch):
    assert (BASE/'ansible/proxmox-host-swap.yml').exists(), 'missing additive swap playbook'
    rc,observed=execute({},state(),tmp_path,monkeypatch,syntax=True)
    assert rc==0 and observed['trace']==[] and observed['probes']==[]


@pytest.mark.parametrize('case',['closed-streams-timeout','leader-exited-descendant-streams','closed-streams-success'])
def test_capture_primitive_bounded_wait(case,monkeypatch):
    """Execute saved primitive with fake Popen/selectors; never create a child."""
    import selectors
    import signal
    import subprocess
    import sys
    import time
    from types import SimpleNamespace
    code=yaml.safe_load((BASE/'ansible/proxmox-host-swap.yml').read_text())[0]['vars']['run_code']
    calls=[];killed=[]
    process=SimpleNamespace(pid=424242,stdout=object(),stderr=object())
    def popen(argv,**kw):
        assert argv==['/fixture/never-executed'] and kw['start_new_session'] is True
        assert kw['stdout']==subprocess.PIPE and kw['stderr']==subprocess.PIPE
        return process
    def wait(timeout=None):
        # Independent oracle: every wait, including cleanup, remains finite.
        assert type(timeout) in (int,float) and 0 < timeout <= 4.0
        calls.append(timeout)
        if case=='closed-streams-timeout' and not killed:
            raise subprocess.TimeoutExpired('/fixture/never-executed',timeout)
        return 0 if case!='closed-streams-timeout' else -9
    process.wait=wait
    process.poll=lambda:0 if case=='leader-exited-descendant-streams' else None
    class Selector:
        def __init__(self):self.rows={}
        def register(self,stream,event,output):
            self.rows[id(stream)]=SimpleNamespace(fd=id(stream),fileobj=stream,data=output)
        def get_map(self):return self.rows
        def select(self,timeout):return [(r,1) for r in list(self.rows.values())]
        def unregister(self,stream):self.rows.pop(id(stream))
    def killpg(pid,sig):
        assert pid==process.pid and sig==signal.SIGKILL
        killed.append(pid)
    monkeypatch.setattr(subprocess,'Popen',popen)
    monkeypatch.setattr(selectors,'DefaultSelector',Selector)
    monkeypatch.setattr(os,'read',lambda fd,size:b'overflow' if case=='leader-exited-descendant-streams' else b'')
    monkeypatch.setattr(os,'killpg',killpg)
    # First observation is start; subsequent observations consume one second.
    def clock():
        value=11.0 if getattr(process,'clock_started',False) else 10.0
        process.clock_started=True
        return value
    monkeypatch.setattr(time,'monotonic',clock)
    monkeypatch.setattr(time,'time',lambda:1001.0)
    monkeypatch.setattr(sys,'argv',['python','run','5','4','["/fixture/never-executed"]','1005'])
    with pytest.raises(SystemExit) as exc:
        exec(compile(code,'saved-capture-primitive','exec'),{'__name__':'__main__'})
    assert exc.value.code==(0 if case=='closed-streams-success' else 124)
    assert calls
    assert killed==([] if case=='closed-streams-success' else [process.pid])
