"""Root-owned witnesses for qualified *completed synchronous* native mutations.

A local command-group result is not daemon/QMP completion. Missing terminal proof
holds UNKNOWN; operational recovery of a lost server reply is deliberately open.
Injected sources are only a synthetic fixture boundary, never a public packet.
"""
from dataclasses import asdict, dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

from host_resource_operations import (NativeCleanupEvidence, ResourceError, RuntimeBinding,
    UNKNOWN, HostResourceController, integer, policy_digest, require, strict_json, text)
from host_resource_backends import (MAX_OUTPUT_BYTES, fingerprint,
    read_root_json, trusted_root_path)

PROTOCOLS={'pve-local-put-balloon-v1','libvirt-local-setmem-v1'}
PROFILE_SCHEMA='qcl.host-resource-native-mutation-qualification.v1'
BUNDLE_SCHEMA='qcl.host-resource-native-mutation-qualifications.v1'
CONFIG_SCHEMA='qcl.host-resource-native-cleanup-config.v1'
WITNESS_SCHEMA='qcl.host-resource-native-cleanup-witness.v1'
SHA=re.compile(r'[0-9a-f]{64}\Z')
UUID=re.compile(r'[0-9a-f]{32}\Z')
UNIT=re.compile(r'qcl-resource-[0-9a-f]{32}\.service\Z')

# Published primary source protocols; a different source chain needs owner review.
PROTOCOL_SOURCE_DIGESTS = {'pve-local-put-balloon-v1': {'API2/Qemu.pm': '33c9b0dca650341e76e39c85c8d54ba1ee38474266632a26c8921121f055697f',
                              'QemuConfig.pm': '4e437fad79b04bd0b3dc6b1450e7b70ff60de4d3d7d7380e308852e0a874d0c8',
                              'QemuServer.pm': '3cd036382bf796f996e74bf8206d57a0388056c63e7eab148fbd64a2b26e5912',
                              'QemuServer/Memory.pm': '2025cae6ee0537b78a0799ffcd9423e3a8309549ddad6d368ea244b65d958cbd',
                              'QemuServer/Monitor.pm': '668ee99382f1eb18f98ed178e8ef68d121be814f47ce820c340e0d9e1a5d4763',
                              'QMPClient.pm': 'dea717bbdebca302d6b5bea8d4d126bb9bbb4aa0784bc48ec56fc0c85780ad3f',
                              'RPCEnvironment.pm': '36474324b346ef285a846df36fef936418231e8143413b509ae977d4dad4f55f',
                              'RESTEnvironment.pm': '57a2b3f15460d74fc813a73510c8bc409ec02683d577a851d76610928fc9e700',
                              'CLI/pvesh.pm': 'dfff48157f503d2c75cee4afc71294d0f0e5d7af8093bc72261647c96e915818',
                              'ProcFSTools.pm': '9ede6e7e13f640cad498374fc0d2d1a7cdac804dc809165b5b525e7996aa8c36',
                              'Tools.pm': 'ce4641907636040569b7de3f71f05e3e11d6614bb59470bfb5c9307c55db895f',
                              'AbstractConfig.pm': '70432cce604f3bc7ff525c2c20028a97173394d5aa2b585c36b50d0761871494',
                              'API2/Tasks.pm': '9d33bd4487c238246216536eadd8fbc01adc5d289ab5e11c59afca5dedb9f2ba'},
 'libvirt-local-setmem-v1': {'tools/virsh-domain.c': '92e7e12f5301ce6267dd641e45048686189fb8589ca7ad168bd90499f05fdc39',
                             'src/libvirt-domain.c': '974888fd2d6a87b96727645cc7212630b945b7ed2fb598a9f0cc8923fd4065fa',
                             'src/remote/remote_driver.c': '0db5a06f70493f2e6d84ef5070d92fade8cddf9181f9ea0fd093f88356994741',
                             'src/qemu/qemu_driver.c': '17a2dbfb6f36901fd2549cfc9451b4c35045983586584a9d738be0ccdc9e2337',
                             'src/qemu/qemu_monitor_json.c': '37836f3799fe18fe1c68a4c2928879f92085dee550afdc2940100398c359618d',
                             'src/rpc/virnetclient.c': '3d27f2fccf5963e8a9318ef8edd5fefc6634f38c34f777ce7033038cf294d539',
                             'src/remote/remote_daemon_dispatch.c': 'df237fe56c440c4a2b53f8ab76487273185ecd88c18296b3b6357ed792a4b28d',
                             'src/remote/remote_protocol.x': '2fd3184165828e1118ab90a8b9597eeb2f79f1b828a860fda6f13d04951304ec',
                             'src/rpc/gendispatch.pl': '22769797a68cb515fcbbe1cd80a12629c0fd66564036d9d22e2d714a9756b234',
                             'src/rpc/virnetclientprogram.c': 'd6a8fde9d561d3462ba34a7be11fb01517a1f4518b95d07b0f3c636a937da250',
                             'src/remote/remote_sockets.c': '8272998dbf22f8f4c1fc9315a72a40ee61a3874821018f3aff1601c97cab7fdb',
                             'src/remote/remote_sockets.h': '0d42cfafbcc95a1794170a950dff6572b626ba01e7547cfab132d99d92ee576b',
                             'src/libvirt.c': '3edd4514cb34c7529dbfbdff99ea0cb7eddf6ffddc63f026531e5f7b3b2e201c'}}


def exact(value,fields,name):
    require(type(value) is dict and set(value)==set(fields),'shape',name)


def digest_string(value):
    require(type(value) is str and SHA.fullmatch(value),'shape','SHA256 required')


def source_ref(value):
    exact(value,{'path','sha256'},'source reference')
    text(value['path'],'source path');digest_string(value['sha256'])
    require(Path(value['path']).is_absolute() and '..' not in Path(value['path']).parts,'trust','canonical source path required')


def decode_birth(value):
    exact(value,{'pid','start_ticks','boot_id'},'process birth')
    integer(value['pid'],'pid',1);integer(value['start_ticks'],'start_ticks',1);text(value['boot_id'],'boot_id')
    return value


@dataclass(frozen=True)
class ProcessBirth:
    pid:int
    start_ticks:int
    boot_id:str


def decode_peer(peer):
    require(type(peer) is dict,'shape','native peer required')
    if peer.get('kind')=='pve_local':
        exact(peer,{'kind','node','qemu_birth'},'local PVE peer')
        require(type(peer['node']) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*',peer['node']), 'shape','native node')
        decode_birth(peer['qemu_birth'])
    else:
        exact(peer,{'kind','socket_path','socket_device','socket_inode','unit','invocation_id','daemon_birth'},'local libvirt peer')
        require(peer['kind']=='libvirt_unix' and type(peer['unit']) is str and peer['unit'] in {'virtqemud.service','libvirtd.service'},'qualification','local system libvirt peer required')
        text(peer['socket_path'],'socket_path')
        require(peer['socket_path'] in {'/run/libvirt/virtqemud-sock','/run/libvirt/libvirt-sock'},'qualification','qualified default local libvirt socket required')
        integer(peer['socket_device'],'socket device');integer(peer['socket_inode'],'socket inode',1)
        require(type(peer['invocation_id']) is str and UUID.fullmatch(peer['invocation_id']),'shape','daemon InvocationID')
        decode_birth(peer['daemon_birth'])


def libvirt_endpoint(peer):
    decode_peer(peer)
    require(peer['kind']=='libvirt_unix','qualification','local libvirt socket required')
    from urllib.parse import quote
    return 'qemu+unix:///system?socket='+quote(peer['socket_path'],safe='')


def decode_source_ids(ids,protocol):
    exact(ids,{'cli','client','driver','protocol','support'},'source identities')
    for key in ('cli','client','driver','protocol'):source_ref(ids[key])
    require(type(ids['support']) is dict and set(ids['support'])==set(PROTOCOL_SOURCE_DIGESTS[protocol]),'qualification','complete pinned source protocol required')
    for name,ref in ids['support'].items():
        source_ref(ref);require(ref['sha256']==PROTOCOL_SOURCE_DIGESTS[protocol][name],'qualification','unreviewed source protocol')


def decode_qualifications(document):
    exact(document,{'schema','profiles'},'qualification bundle')
    require(document['schema']==BUNDLE_SCHEMA and type(document['profiles']) is list and document['profiles'], 'qualification','explicit nonempty per-VM bundle required')
    seen=set()
    for p in document['profiles']:
        exact(p,{'schema','protocol_id','host_id','owner_id','host_boot_id','policy_sha256','binding','source_ids','native_peer_identity','evidence_ref'},'native mutation profile')
        require(p['schema']==PROFILE_SCHEMA and type(p['protocol_id']) is str and p['protocol_id'] in PROTOCOLS,'qualification','known completed-call protocol required')
        for key in ('host_id','owner_id','host_boot_id','evidence_ref'):text(p[key],key)
        digest_string(p['policy_sha256'])
        exact(p['binding'],RuntimeBinding.__dataclass_fields__,'runtime binding')
        for key,value in p['binding'].items():text(value,key)
        vm=p['binding']['vm_id'];require(vm not in seen,'qualification','duplicate VM profile');seen.add(vm)
        decode_source_ids(p['source_ids'],p['protocol_id'])
        decode_peer(p['native_peer_identity'])
        require((p['protocol_id'].startswith('pve-'))==(p['native_peer_identity']['kind']=='pve_local'),'qualification','backend peer protocol mismatch')
    return document['profiles']


def decode_config(config):
    exact(config,{'schema','helper','qualification','protocol_id'},'native cleanup config')
    require(config['schema']==CONFIG_SCHEMA and type(config['protocol_id']) is str and config['protocol_id'] in PROTOCOLS,'qualification','native cleanup protocol required')
    for key in ('helper','qualification'):
        text(config[key],key)
        require(Path(config[key]).is_absolute() and '..' not in Path(config[key]).parts,'trust','protected absolute helper/profile path')
    return config


@dataclass(frozen=True)
class NativeMutationIntent:
    request_id:str
    mutation_id:str
    operation:str
    host_id:str
    owner_id:str
    host_boot_id:str
    policy_sha256:str
    binding:RuntimeBinding
    native_context:dict
    old_bytes:int
    target_bytes:int
    before_revision:str
    protocol_id:str
    qualification_sha256:str


def decode_intent(doc):
    exact(doc,NativeMutationIntent.__dataclass_fields__,'mutation intent')
    require(type(doc['mutation_id']) is str and UUID.fullmatch(doc['mutation_id']) and type(doc['operation']) is str and doc['operation'] in {'grow','shrink'},'shape','exact mutation identity')
    for key in ('request_id','host_id','owner_id','host_boot_id','before_revision'):text(doc[key],key)
    for key in ('policy_sha256','qualification_sha256'):digest_string(doc[key])
    for key in ('old_bytes','target_bytes'):integer(doc[key],key,1)
    exact(doc['binding'],RuntimeBinding.__dataclass_fields__,'intent binding')
    for key,value in doc['binding'].items():text(value,key)
    context=doc['native_context'];exact(context,{'unit','invocation_id','cgroup','host_boot_id','mutation_id'},'native invocation')
    require(type(context['unit']) is str and UNIT.fullmatch(context['unit']) and
        type(context['invocation_id']) is str and UUID.fullmatch(context['invocation_id']) and
        context['cgroup']=='/system.slice/'+context['unit'] and context['host_boot_id']==doc['host_boot_id'] and context['mutation_id']==doc['mutation_id'], 'native_owner','native invocation mismatch')
    require(type(doc['protocol_id']) is str and doc['protocol_id'] in PROTOCOLS,'qualification','intent protocol')
    return NativeMutationIntent(**{**doc,'binding':RuntimeBinding(**doc['binding'])})


def decode_witness(doc):
    exact(doc,{'schema','intent','intent_sha256','phase','worker_birth','cli_birth','cgroup','source_ids','native_peer','claimed_at','terminal_at','local_cleanup_confirmed','result_sha256'},'native witness')
    require(doc['schema']==WITNESS_SCHEMA,'shape','native witness version')
    intent=decode_intent(doc['intent']);digest_string(doc['intent_sha256'])
    require(doc['intent_sha256']==fingerprint(asdict(intent)),'cleanup_evidence','intent digest changed')
    for key in ('worker_birth','cli_birth'):decode_birth(doc[key])
    require(doc['worker_birth']!=doc['cli_birth'] and doc['worker_birth']['boot_id']==doc['cli_birth']['boot_id']==intent.host_boot_id and
        doc['cgroup']==intent.native_context['cgroup'],'cleanup_evidence','witness process scope changed')
    require(type(doc['phase']) is str and doc['phase'] in {'CLAIMED','RETURNED_SUCCESS'} and type(doc['local_cleanup_confirmed']) is bool,'shape','witness phase/cleanup')
    integer(doc['claimed_at'],'claimed_at')
    if doc['phase']=='CLAIMED':
        require(doc['terminal_at'] is None and doc['result_sha256'] is None and not doc['local_cleanup_confirmed'],'shape','claim is not terminal')
    else:
        integer(doc['terminal_at'],'terminal_at');digest_string(doc['result_sha256'])
        require(doc['terminal_at']>=doc['claimed_at'] and doc['local_cleanup_confirmed'],'shape','terminal owned cleanup required')
    decode_peer(doc['native_peer'])
    decode_source_ids(doc['source_ids'],intent.protocol_id)
    return intent


def _pve_lock_released(vmid,*,native_os=os,lock=fcntl.flock):
    """Fixed PVE native lock layout; not a general writable-path exception.

    /run is protected. Its root sticky lock directory protects the root-owned
    qemu-server child. The sole compatibility link is /var/lock -> /run/lock.
    Test-only syscall injection models root metadata; clients cannot supply it.
    """
    integer(vmid,'native VMID',1)
    flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC
    descriptors=[];chain=[]
    def identity(meta):return meta.st_dev,meta.st_ino
    def protected(meta,kind):
        require(meta.st_uid==0 and (stat.S_ISREG(meta.st_mode) if kind=='file' else stat.S_ISDIR(meta.st_mode)),'trust','native lock ownership/type')
        require((not meta.st_mode&0o022 or kind=='sticky' and meta.st_mode&stat.S_ISVTX) and
            (kind!='file' or meta.st_nlink==1),'trust','native lock write/link boundary')
    def opened(parent,name,kind):
        fd=native_os.open(name,flags|(0 if kind=='file' else os.O_DIRECTORY),**({} if parent is None else {'dir_fd':parent}))
        descriptors.append(fd);meta=native_os.fstat(fd);protected(meta,kind)
        chain.append((parent,name,fd,meta,kind));return fd
    try:
        root=opened(None,'/','directory');var=opened(root,'var','directory');run=opened(root,'run','directory')
        compatibility=native_os.stat('lock',dir_fd=var,follow_symlinks=False)
        require(compatibility.st_uid==0 and stat.S_ISLNK(compatibility.st_mode) and native_os.readlink('lock',dir_fd=var)=='/run/lock','trust','exact root-owned native lock compatibility link required')
        lockroot=opened(run,'lock','sticky');child=opened(lockroot,'qemu-server','directory')
        fd=opened(child,'lock-'+str(vmid)+'.conf','file')
        try:lock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return False
        for parent,name,current,original,kind in chain:
            held=native_os.fstat(current)
            named=native_os.stat(name,follow_symlinks=False,**({} if parent is None else {'dir_fd':parent}))
            protected(held,kind);protected(named,kind)
            require(identity(original)==identity(held)==identity(named),'trust','native lock ancestor/inode replaced')
        final=native_os.stat('lock',dir_fd=var,follow_symlinks=False)
        require(identity(final)==identity(compatibility) and final.st_uid==0 and stat.S_ISLNK(final.st_mode) and native_os.readlink('lock',dir_fd=var)=='/run/lock','trust','native lock compatibility link changed')
        return True
    finally:
        for fd in reversed(descriptors):native_os.close(fd)


class NativeCleanupSources:
    """Narrow native metadata readers; no mutation, new supervisor or filesystem walker."""
    def __init__(self,config,runner):
        from host_resource_facts import LocalSources
        self.local=LocalSources(config,runner);self.config,self.runner=config,runner
    def clock(self):return int(time.time())
    def root_json(self,path):return read_root_json(path)
    def trusted(self,path,*,executable=False):return trusted_root_path(path,executable=executable)
    def file_digest(self,path):
        path=self.trusted(path);require(path.stat().st_size<=128*1024**2,'output_bound','source executable bound')
        h=hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
        return h.hexdigest()
    def running_digest(self,pid):
        h=hashlib.sha256()
        with open('/proc/'+str(pid)+'/exe','rb') as stream:
            meta=os.fstat(stream.fileno())
            require(stat.S_ISREG(meta.st_mode) and meta.st_size<=128*1024**2,'qualification','bounded running executable required')
            for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
        return h.hexdigest()
    def birth(self,pid,*,root=False):
        p=self.local.process(pid)
        require(not root or p['uids']==[0]*4,'native_owner','root native process required')
        return dict(pid=p['pid'],start_ticks=p['start_ticks'],boot_id=self.local.host()['boot_id'])
    def unit(self,name):
        require(UNIT.fullmatch(name) or name in {'libvirtd.service','virtqemud.service'},'native_owner','qualified native unit required')
        props=('LoadState','ActiveState','MainPID','ControlGroup','InvocationID')
        raw=self.local.run([self.config['systemctl'],'show',name,*['--property='+key for key in props]])
        fields={}
        for line in raw.splitlines():
            key,sep,value=line.partition('=');require(sep and key in props and key not in fields,'incomplete_probe','native unit properties')
            fields[key]=value
        require(set(fields)==set(props) and fields['MainPID'].isdigit(),'incomplete_probe','complete native unit properties')
        return fields
    def context(self,row):
        from host_resource_service import native_unit_context
        return native_unit_context(row,sources=self.local,systemctl=self.config['systemctl'])
    def worker(self,context):
        unit=self.unit(context['unit'])
        require(unit['LoadState']=='loaded' and unit['ActiveState']=='active' and unit['InvocationID']==context['invocation_id'] and unit['ControlGroup']==context['cgroup'] and int(unit['MainPID'])>0, 'native_owner','actual worker invocation changed')
        process=self.local.process(int(unit['MainPID']))
        require(process['uids']==[0]*4 and process['cgroup']==context['cgroup'],'native_owner','actual root worker cgroup changed')
        return dict(pid=process['pid'],start_ticks=process['start_ticks'],boot_id=self.local.host()['boot_id'])
    def claim_process(self,context):
        worker=self.worker(context);process=self.local.process(os.getpid())
        require(process['uids']==[0]*4 and process['ppid']==worker['pid'] and process['cgroup']==context['cgroup'], 'native_owner','pre-exec must be direct child of actual root worker')
        return worker,self.birth(os.getpid(),root=True)
    def listener_owned(self,socket_path,birth):
        # Join the filesystem endpoint to the actual daemon's listening FD;
        # another active root daemon/socket is not the selected peer.
        rows=[line.split() for line in self.local.read('/proc/net/unix').splitlines()[1:]]
        matches=[row for row in rows if len(row)==8 and row[-1]==socket_path]
        require(len(matches)==1,'qualification','one actual native UNIX listener required')
        row=matches[0]
        require(row[3]=='00010000' and row[4]=='0001' and row[5]=='01' and row[6].isdigit() and int(row[6])>0,'qualification','native stream listener required')
        from application_release import UpdateScan
        budget=UpdateScan(time.monotonic()+10)
        owners=[p for p in budget.entries(Path('/proc')/str(birth['pid'])/'fd','cgroup') if budget.link(p)=='socket:['+row[6]+']']
        require(owners and self.birth(birth['pid'],root=True)==birth,'qualification','socket not owned by exact current root daemon')
    def peer(self,profile,backend):
        peer=profile['native_peer_identity'];binding=profile['binding']
        if peer['kind']=='libvirt_unix':
            require(backend.connect_endpoint==libvirt_endpoint(peer),'qualification','explicit native peer routing changed')
        from host_resource_backends import collect_native_runtime,NativeRuntimeFacts
        actual=collect_native_runtime(backend,backend.readback(binding['vm_id']))
        require(actual==NativeRuntimeFacts(profile['host_boot_id'],binding['host_kernel_id'],binding['qemu_version_id'],binding['backend_version_id']),'qualification','actual QEMU/backend/host runtime changed')
        if peer['kind']=='pve_local':
            require(getattr(backend,'local_only',False) and backend.node==peer['node'],'qualification','local PVE route required')
            return dict(kind='pve_local',node=backend.node,qemu_birth=self.birth(int(binding['process_id'])))
        socket_path=Path(peer['socket_path']);trusted_root_path(socket_path.parent,directory=True)
        st=socket_path.lstat();require(st.st_uid==0 and stat.S_ISSOCK(st.st_mode) ,'trust','root-owned local libvirt socket required')
        unit=self.unit(peer['unit']);require(unit['ActiveState']=='active','qualification','actual libvirt daemon inactive')
        birth=self.birth(int(unit['MainPID']),root=True)
        daemon=self.local.process(birth['pid'])
        require(daemon['cgroup']==unit['ControlGroup'] and daemon['executable']==profile['source_ids']['driver']['path'] and self.running_digest(birth['pid'])==profile['source_ids']['driver']['sha256'],'qualification','actual daemon executable/source profile changed')
        self.listener_owned(str(socket_path),birth)
        return dict(kind='libvirt_unix',socket_path=str(socket_path),socket_device=st.st_dev,socket_inode=st.st_ino,unit=peer['unit'],invocation_id=unit['InvocationID'],daemon_birth=birth)
    def preflight(self,profile,backend,vm,before):
        if profile['protocol_id'].startswith('pve-'):
            pending=strict_json(backend._run(['get',backend._path(vm)+'/pending']))
            require(type(pending) is list,'qualification','complete native pending array required')
            seen=set()
            for row in pending:
                require(type(row) is dict and 'key' in row and set(row)<={'key','value','pending','delete'},'qualification','known pending row fields required')
                text(row['key'],'pending key')
                require(row['key'] not in seen,'qualification','duplicate native pending key');seen.add(row['key'])
                require('pending' not in row and type(row.get('delete',0)) is int and row.get('delete',0)==0,'qualification','dirty pending/delete config not balloon-only')
            config=strict_json(backend._run(['get',backend._path(vm)+'/config','--current','1']))
            require(type(config) is dict,'readback','native current config required')
            integer(config.get('balloon'),'PVE enabled balloon',1)
            integer(config.get('memory'),'PVE native maximum',1)
            hotplug=config.get('hotplug','1')
            require(type(hotplug) is str and set(hotplug.split(','))<={'0','1','network','disk','cpu','memory','usb'},'qualification','cloudinit/unknown hotplug path excluded')
            require(config.get('digest')==before.revision and config.get('balloon',0)>0 and type(config.get('shares')) is int and config['shares']==0,'identity_mismatch','PVE revision/manual balloon changed')
        else:require(backend.uri=='qemu:///system' and backend.connect_endpoint==libvirt_endpoint(profile['native_peer_identity']),'qualification','exact local libvirt endpoint required')
    def absent(self,witness):
        context=witness['intent']['native_context'];worker=witness['worker_birth'];cli=witness['cli_birth']
        # PID reuse is not the old process; unavailable process visibility is not absence.
        try:
            if self.birth(cli['pid'])==cli:return False
        except (FileNotFoundError,ProcessLookupError):pass
        unit=self.unit(context['unit'])
        root=Path('/sys/fs/cgroup'+context['cgroup'])
        if unit['ActiveState']!='active':
            try:
                if self.birth(worker['pid'])==worker:return False
            except (FileNotFoundError,ProcessLookupError):pass
            return not root.exists() and not unit['ControlGroup'] and unit['MainPID']=='0'
        if unit['InvocationID']!=context['invocation_id'] or self.worker(context)!=worker:return False
        # This protocol permits no nested native cgroups; refuse, never walk them.
        from application_release import UpdateScan
        budget=UpdateScan(time.monotonic()+10);initial=budget.stat(root)
        require(stat.S_ISDIR(initial.st_mode) and initial.st_uid==0,'trust','owned cgroup root')
        members=budget.read(root/'cgroup.procs')
        for p in budget.entries(root,'cgroup'):
            require(not stat.S_ISDIR(budget.stat(p).st_mode),'cleanup_evidence','nested native cgroup unsupported')
        require(members.decode().split()==[str(worker['pid'])] and budget.read(root/'cgroup.procs')==members,'cleanup_evidence','extra owned native descendants')
        final=budget.stat(root);return (initial.st_dev,initial.st_ino)==(final.st_dev,final.st_ino)
    def target_before_exec(self,intent,dispatch,profile,backend,worker,cli):
        from host_resource_recovery import prepare_target_seal
        return prepare_target_seal(self,intent,dispatch,profile,backend,worker,cli)
    def validate_target_use(self,mutation_id):
        if self.config.get('native_storage') is None:return
        owner=getattr(self,'storage_collector',None)
        require(owner is not None,'qualification','configured process-local storage owner missing')
        return owner.validate_target_use(mutation_id)
    def lock_released(self,backend,vm):
        if not hasattr(backend,'node'):return True  # libvirt EndJob is in its qualified successful RPC reply
        return _pve_lock_released(backend.vms[vm].vmid)


class NativeMutationProofs:
    def __init__(self,policy,store,native_backend,protected_config,runner,*,sources=None):
        if sources is None:
            require(os.geteuid()==0 and store.owner_uid==0,'root_required','root production owner required')
            from host_resource_service import CONFIG
            sources=NativeCleanupSources(read_root_json(CONFIG),runner)
        self.policy,self.store,self.backend,self.runner=policy,store,native_backend,runner
        self.config=decode_config(protected_config);self.sources=sources
        self.sources.trusted(self.config['helper'],executable=True)
        self.directory=store.directory/'native-mutations'
        try:
            profiles=self.profiles()
            if self.config['protocol_id']=='libvirt-local-setmem-v1':
                endpoints={libvirt_endpoint(p['native_peer_identity']) for p in profiles if p['protocol_id']==self.config['protocol_id']}
                require(len(endpoints)==1,'qualification','one exact local system daemon route required')
                self.backend.connect_endpoint=endpoints.pop()
        except (OSError,ValueError) as error:raise ResourceError('qualification','protected native source profile unavailable') from error
    def profiles(self):return decode_qualifications(self.sources.root_json(self.config['qualification']))
    def profile(self,binding,boot):
        matches=[p for p in self.profiles() if p['binding']==asdict(binding) and p['protocol_id']==self.config['protocol_id']]
        require(len(matches)==1,'qualification','exact current per-VM mutation profile required');p=matches[0]
        require(p['host_id']==self.policy.host_id and p['owner_id']==self.policy.owner_id and p['host_boot_id']==boot and p['policy_sha256']==policy_digest(self.policy),'qualification','profile host/policy/boot changed')
        if p['protocol_id'].startswith('pve-'):
            require(all(ref['path']=='/usr/share/perl5/PVE/'+name for name,ref in p['source_ids']['support'].items()),'qualification','PVE source must be actual installed module paths')
            for key,name in [('client','QMPClient.pm'),('driver','QemuServer.pm'),('protocol','API2/Qemu.pm')]:
                require(p['source_ids'][key]==p['source_ids']['support'][name],'qualification','PVE source aliases must identify installed implementation')
        refs=[p['source_ids'][k] for k in ('cli','client','driver','protocol')]+list(p['source_ids']['support'].values())
        require(p['source_ids']['cli']['path']==self.backend.tool,'qualification','profile native CLI differs')
        for ref in refs:require(self.sources.file_digest(ref['path'])==ref['sha256'],'qualification','actual source/executable changed')
        require(self.sources.peer(p,self.backend)==p['native_peer_identity'],'qualification','actual native peer incarnation changed')
        return p
    def path(self,mutation_id):
        require(type(mutation_id) is str and UUID.fullmatch(mutation_id),'shape','exact mutation UUID required')
        return self.directory/(mutation_id+'.json')
    def state(self):return HostResourceController(self.policy,self.store,self.backend)._load()
    def row(self,state,mutation_id):
        rows=[r for r in state['receipts'] if r['mutation_id']==mutation_id]
        require(len(rows)==1 and rows[0]['phase'] in UNKNOWN,'cleanup_evidence','latest durable UNKNOWN intent required')
        return rows[0]
    def intent(self,row,state,before):
        vm=row['request']['vm_id'];binding=RuntimeBinding(**state['bindings'][vm]);p=self.profile(binding,state['host_boot_id'])
        require(before.vm_id==vm and before.native_id==binding.native_id and before.process_id==binding.process_id and before.config_fingerprint==binding.config_fingerprint and before.running,'identity_mismatch','actual before runtime/configuration changed')
        doc=dict(request_id=row['request']['request_id'],mutation_id=row['mutation_id'],operation='shrink' if row['phase']=='SHRINK_UNKNOWN' else 'grow',host_id=self.policy.host_id,owner_id=self.policy.owner_id,host_boot_id=state['host_boot_id'],policy_sha256=state['policy_sha256'],binding=asdict(binding),native_context=row['native_context'],old_bytes=row['old_bytes'],target_bytes=row['target_bytes'],before_revision=before.revision,protocol_id=p['protocol_id'],qualification_sha256=fingerprint(p))
        return decode_intent(doc)
    def read(self,mutation_id):
        self.store._check_path(self.directory,directory=True)
        doc=self.store._read(self.path(mutation_id));decode_witness(doc);return doc
    def exclusive(self,path,document):
        self.directory.mkdir(mode=0o700,exist_ok=True);self.store._check_path(self.directory,directory=True)
        data=json.dumps(document,sort_keys=True).encode();require(len(data)<=MAX_OUTPUT_BYTES,'output_bound','witness bound')
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            self.store._check_fd(fd)
            with os.fdopen(fd,'wb',closefd=False) as stream:stream.write(data);stream.flush();os.fsync(fd)
        finally:os.close(fd)
        self.store._sync_directory(self.directory);self.store._sync_directory(self.store.directory)
    def dispatch_path(self,mutation_id):return self.path(mutation_id).with_suffix('.intent.json')
    def dispatch(self,mutation_id):
        self.store._check_path(self.directory,directory=True)
        doc=self.store._read(self.dispatch_path(mutation_id))
        exact(doc,{'schema','intent','worker_birth'},'dispatch envelope')
        require(doc['schema']=='qcl.host-resource-native-dispatch.v1','shape','dispatch version')
        decode_intent(doc['intent']);decode_birth(doc['worker_birth']);return doc
    def claim(self,mutation_id):
        state=self.state();row=self.row(state,mutation_id);before=self.backend.readback(row['request']['vm_id'])
        require(row['native_cleanup_confirmed'] is False,'cleanup_evidence','intent already settled')
        intent=self.intent(row,state,before);p=self.profile(intent.binding,intent.host_boot_id)
        dispatch=self.dispatch(mutation_id)
        require(dispatch['intent']==asdict(intent),'identity_mismatch','native before/revision changed after durable dispatch preparation')
        charged=next(g for g in state['grants'] if g['vm_id']==intent.binding.vm_id)
        require(charged['guest_bytes']>=max(intent.old_bytes,intent.target_bytes),'cleanup_evidence','full charge must precede native execution')
        self.sources.preflight(p,self.backend,intent.binding.vm_id,before)
        worker,cli=self.sources.claim_process(intent.native_context)
        require(worker==dispatch['worker_birth'] and worker!=cli,'native_owner','actual root worker/CLI generation changed')
        doc=dict(schema=WITNESS_SCHEMA,intent=asdict(intent),intent_sha256=fingerprint(asdict(intent)),phase='CLAIMED',worker_birth=worker,cli_birth=cli,cgroup=intent.native_context['cgroup'],source_ids=p['source_ids'],native_peer=p['native_peer_identity'],claimed_at=self.sources.clock(),terminal_at=None,local_cleanup_confirmed=False,result_sha256=None)
        try:
            capture=getattr(self.sources,'target_before_exec',None)
            if capture is not None:
                target=capture(intent,dispatch,p,self.backend,worker,cli)
                if target is not None:
                    from host_resource_recovery import decode_target
                    decode_target(target);self.exclusive(self.path(mutation_id).with_suffix('.target.json'),target)
            decode_witness(doc);self.exclusive(self.path(mutation_id),doc)
            validate=getattr(self.sources,'validate_target_use',None)
            if validate is not None:validate(mutation_id)
            return self.backend.mutation_argv(intent.binding.vm_id,intent.target_bytes,before)
        except BaseException:
            storage=getattr(self.sources,'storage_collector',None)
            if storage is not None and mutation_id in storage.handles:storage.handles[mutation_id].close()
            raise
    def execute(self,intent,*,timeout_seconds):
        state=self.state();row=self.row(state,intent.mutation_id)
        require(self.intent(row,state,self.backend.readback(intent.binding.vm_id))==intent,'identity_mismatch','durable intent changed before dispatch')
        require(not self.path(intent.mutation_id).exists() and not self.dispatch_path(intent.mutation_id).exists(),'cleanup_evidence','native intent already dispatched/prepared; no replay')
        worker=self.sources.worker(intent.native_context)
        self.exclusive(self.dispatch_path(intent.mutation_id),dict(schema='qcl.host-resource-native-dispatch.v1',intent=asdict(intent),worker_birth=worker))
        output=self.runner.run([self.config['helper'],intent.mutation_id],timeout_seconds=timeout_seconds,max_output_bytes=MAX_OUTPUT_BYTES)
        try:
            doc=self.read(intent.mutation_id)
            require(doc['phase']=='CLAIMED' and doc['intent']==asdict(intent) and doc['worker_birth']==worker and doc['claimed_at']>=row['mutation_started_at'],'cleanup_evidence','exact fresh pre-exec claim required')
            p=self.profile(intent.binding,intent.host_boot_id)
            require(doc['source_ids']==p['source_ids'] and doc['native_peer']==p['native_peer_identity'] and self.sources.absent(doc) and self.sources.lock_released(self.backend,intent.binding.vm_id),'cleanup_evidence','owned command/lock cleanup not confirmed')
            doc.update(phase='RETURNED_SUCCESS',terminal_at=self.sources.clock(),local_cleanup_confirmed=True,result_sha256=hashlib.sha256(str(output).encode()).hexdigest())
            decode_witness(doc);self.store._atomic(self.path(intent.mutation_id),json.dumps(doc,sort_keys=True).encode())
        except Exception as error:
            # Native success followed by proof IO/validation failure is still
            # UNKNOWN. Preserve its bounded response in the existing failure log.
            error.native_argv=(self.config['helper'],intent.mutation_id)
            error.native_output=output
            error.native_output_truncated=False
            raise
    def _proof(self,row,state,evidence):
        require(row['native_context'] is not None,'cleanup_evidence','no exact production native owner')
        doc=self.read(row['mutation_id']);intent=decode_witness(doc)
        dispatch=self.dispatch(row['mutation_id'])
        require(dispatch['intent']==doc['intent'] and dispatch['worker_birth']==doc['worker_birth'],'cleanup_evidence','immutable dispatch and terminal witness differ')
        p=self.profile(intent.binding,state['host_boot_id'])
        binding=next((b for b in evidence.bindings if b.vm_id==row['request']['vm_id']),None)
        require(intent.operation==('shrink' if row['target_bytes']<row['old_bytes'] else 'grow') and intent.host_id==self.policy.host_id and intent.owner_id==self.policy.owner_id and intent.protocol_id==p['protocol_id'] and doc['phase']=='RETURNED_SUCCESS' and intent.request_id==row['request']['request_id'] and intent.mutation_id==row['mutation_id'] and intent.target_bytes==row['target_bytes'] and intent.old_bytes==row['old_bytes'] and intent.native_context==row['native_context'] and intent.binding==binding and asdict(intent.binding)==state['bindings'][intent.binding.vm_id] and intent.host_boot_id==evidence.host_boot_id==state['host_boot_id'] and intent.policy_sha256==evidence.policy_sha256==state['policy_sha256']==policy_digest(self.policy) and intent.qualification_sha256==fingerprint(p) and doc['source_ids']==p['source_ids'] and doc['native_peer']==p['native_peer_identity'],'cleanup_evidence','latest witness/runtime/policy mismatch')
        require(doc['claimed_at']>=row['mutation_started_at'] and doc['terminal_at']<=self.sources.clock() and self.sources.absent(doc) and self.sources.lock_released(self.backend,intent.binding.vm_id),'cleanup_evidence','fresh exact owned absence required')
        return doc
    def cleanup(self,request_id,*,owner_state,evidence):
        row=next((r for r in owner_state['receipts'] if r['request']['request_id']==request_id),None)
        require(row is not None,'request_unknown','active exact request required')
        if row['mutation_id'] is None:return None
        try:doc=self._proof(row,owner_state,evidence)
        except (OSError,ValueError,ResourceError):return None
        return NativeCleanupEvidence(request_id,row['mutation_id'],evidence.host_id,evidence.owner_id,evidence.host_boot_id,evidence.policy_sha256,RuntimeBinding(**owner_state['bindings'][row['request']['vm_id']]),self.sources.clock(),True,'native-witness-sha256:'+fingerprint(doc))
    def validate_state(self,owner_state,*,evidence):
        for row in owner_state['receipts']:
            if row['mutation_id'] is not None and row['native_cleanup_confirmed']:
                try:self._proof(row,owner_state,evidence)
                except (OSError,ValueError) as error:raise ResourceError('cleanup_evidence','legacy/local cleanup has no valid native terminal witness') from error


class QualifiedMutationBackend:
    requires_native_cleanup_proof=True
    def __init__(self,native_backend,proofs):
        self.native_backend,self.proofs=native_backend,proofs;self.quantum_bytes=native_backend.quantum_bytes
    def runtime_version(self):return self.native_backend.runtime_version()
    def prepare_mutation(self,row):return self.proofs.sources.context(row)
    def readback(self,vm_id):return self.native_backend.readback(vm_id)
    def resize(self,vm_id,target_bytes,before,timeout_seconds):
        actual=self.readback(vm_id);require(actual==before,'identity_mismatch','native memory changed before intent')
        state=self.proofs.store.load();rows=[r for r in state['receipts'] if r['request']['vm_id']==vm_id and r['phase'] in UNKNOWN and r['target_bytes']==target_bytes]
        require(len(rows)==1,'cleanup_evidence','one exact durable native intent required')
        intent=self.proofs.intent(rows[0],state,before)
        self.proofs.execute(intent,timeout_seconds=timeout_seconds)
        return self.readback(vm_id)


def native_exec_main(argv=None):
    require(os.geteuid()==0,'root_required','root native pre-exec only')
    argv=sys.argv[1:] if argv is None else argv
    if type(argv) is list and len(argv)==3 and argv[0]=='recovery':
        from host_resource_recovery import native_exec
        return native_exec(argv[1],argv[2])
    require(type(argv) is list and len(argv)==1 and type(argv[0]) is str and UUID.fullmatch(argv[0]),'shape','one native mutation UUID required')
    from host_resource_service import open_service
    service=open_service();backend=service.controller.backend
    require(type(backend) is QualifiedMutationBackend,'qualification','qualified dynamic owner required')
    native=backend.proofs.claim(argv[0])
    # No spawn/supervision here: PID/birth and the P11-owned session survive exec.
    os.execve(native[0],list(native),backend.proofs.runner.environment)
