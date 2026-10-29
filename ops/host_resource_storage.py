"""B1 owned local storage: strict source-pinned observations and Root-only preparation.

No public proof input, payload scan, foreign monitor, refresh, resize, define or start.
This conditional protocol supplements C/F1; it never releases their memory charge.
Native admission requires the separate N-H0..H8 qualification, including actual
compiled/runtime/library identities. See docs/host-resource-storage.md.
"""
from dataclasses import asdict, dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import pwd
import grp
import re
import stat
import time
import xml.etree.ElementTree as ET

from host_resource_operations import ResourceError, RuntimeBinding, integer, policy_digest, require, strict_json, text
from host_resource_backends import MAX_OUTPUT_BYTES, fingerprint, read_root_json, trusted_root_path
from host_resource_native_cleanup import exact, decode_birth, decode_peer, source_ref, SHA, UUID, libvirt_endpoint

CONFIG_SCHEMA='qcl.host-resource-storage-config.v1'
BINDING_SCHEMA='qcl.host-resource-storage-binding.v1'
CAPTURE_SCHEMA='qcl.host-resource-storage-capture.v1'
QUAL_SCHEMA='qcl.host-resource-storage-qualifications.v1'
INSTALL_SCHEMA='qcl.host-resource-storage-installs.v1'
LIVE='qemu-11.1.2-owned-live-v1'
OFFLINE='qemu-img-11.1.2-owned-offline-v1'
HOLDER='linux-qemu-threads-buffered-owned-v1'
LIVE_QUERIES=(('named',{'execute':'query-named-block-nodes','arguments':{'flat':True}}),
    ('debug',{'execute':'x-debug-query-block-graph'}),
    ('block',{'execute':'query-block','arguments':{'flat':True}}),
    ('jobs',{'execute':'query-jobs'}),('block_jobs',{'execute':'query-block-jobs'}))
MAX_NODES=256
MAX_FILES=64
MAX_RAW_BYTES=4*1024*1024
MAX_PROCESSES=65536
MAX_TASKS=4096
MAX_FDS=8192
PERMISSIONS={'consistent-read','write','write-unchanged','resize'}
BINDING_FIELDS={'schema','host_id','owner_id','vm_id','native_uuid','domain_name','incarnation_id','namespace','dac','disks','install_receipt_sha256','definition_sha256','source_profile_sha256'}
DISK_FIELDS={'target','role','format','access','path','device','inode','mount_id','uid','gid','mode','nlink','creation_receipt_sha256'}
FILE_FIELDS=DISK_FIELDS-{'target'}|{'id'}
CAPTURE_FIELDS={'schema','subject','binding_sha256','profile_sha256','native_peer_identity','started_at','completed_at','monotonic_start_ns','monotonic_end_ns','domain_inventory_sha256','pool_inventory_sha256','process_inventory_sha256','graph','files','holders','closure_sha256','native_observation'}


def sha(value):require(type(value) is str and SHA.fullmatch(value),'shape','exact SHA256 required')
def uid(value):require(type(value) is str and UUID.fullmatch(value),'shape','exact operation UUID required')
def native_uuid(value):require(type(value) is str and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',value),'shape','canonical native UUID required')
def bounded(value,name='identifier'):
    require(type(value) is str and 0<len(value)<=256 and '\x00' not in value,'shape','bounded '+name+' required');return value
def absolute(value):
    bounded(value,'path');require(value.startswith('/') and str(Path(value))==value and '..' not in Path(value).parts,'trust','canonical absolute path required');return value
def keys(value,required,optional=(),name='native object'):
    require(type(value) is dict and set(required)<=set(value)<=set(required)|set(optional),'shape',name+' keys differ')
def array(value,name,limit=MAX_NODES):
    require(type(value) is list and len(value)<=limit,'output_bound','bounded '+name+' required');return value
def boolean(value,name):require(type(value) is bool,'shape',name+' boolean required')
def plain_xml(raw):
    require(type(raw) in {str,bytes} and len(raw)<=MAX_OUTPUT_BYTES and (b'<!' not in raw if type(raw) is bytes else '<!' not in raw),'shape','bounded plain XML required')
    try:return ET.fromstring(raw)
    except ET.ParseError as error:raise ResourceError('shape','native XML invalid') from error
def _candidate_static(xml):
    """Bind comparison only. Existing C fingerprint/serialization is unchanged."""
    from host_resource_backends import libvirt_config_fingerprint
    copy=ET.fromstring(ET.tostring(xml))
    for node in copy.iter():
        node.text=node.text.strip() if node.text and node.text.strip() else None
        node.tail=None
        attributes=sorted(node.attrib.items());node.attrib.clear();node.attrib.update(attributes)
    return libvirt_config_fingerprint(copy)
def qmp_reply(value):
    exact(value,{'return'},'QMP successful reply (error also holds)');return value['return']
def decode_config(config,store):
    exact(config,{'schema','bindings','qualification','install_specs'},'protected storage config')
    require(config['schema']==CONFIG_SCHEMA and config['bindings']==str(store.directory/'native-storage'),'trust','derived protected binding directory required')
    for key in ('qualification','install_specs'):absolute(config[key])
    return config


def decode_disk(disk):
    exact(disk,DISK_FIELDS,'created storage disk')
    require(type(disk['target']) is str and re.fullmatch(r'[a-z][a-z0-9]{0,15}',disk['target']),'shape','disk target required')
    require(disk['role'] in {'root','scratch','seed','backing'} and disk['format'] in {'raw','qcow2'} and disk['access'] in {'ro','rw'},'qualification','local storage variant required')
    absolute(disk['path'])
    for key in ('device','mode','uid'):integer(disk[key],key)
    for key in ('inode','mount_id','gid','nlink'):integer(disk[key],key,1)
    require(disk['nlink']==1 and disk['mode'] in {0o600,0o440},'ownership','private regular single-link file required')
    sha(disk['creation_receipt_sha256']);return disk


def decode_binding(doc):
    exact(doc,BINDING_FIELDS,'storage binding');require(doc['schema']==BINDING_SCHEMA,'shape','storage binding schema')
    for key in ('host_id','owner_id','vm_id','domain_name'):bounded(doc[key],key)
    native_uuid(doc['native_uuid']);uid(doc['incarnation_id'])
    exact(doc['namespace'],{'path','device','inode','mount_id'},'owned namespace');absolute(doc['namespace']['path'])
    for key in ('device','inode','mount_id'):integer(doc['namespace'][key],key,0 if key=='device' else 1)
    exact(doc['dac'],{'uid','gid'},'private numeric DAC')
    for value in doc['dac'].values():integer(value,'DAC ID',1)
    disks=array(doc['disks'],'private disks',MAX_FILES);require(disks,'ownership','empty disk binding unqualified')
    seen=set();ids=set()
    for d in disks:
        decode_disk(d);require(Path(d['path']).parent==Path(doc['namespace']['path']) and d['target'] not in seen and (d['device'],d['inode']) not in ids,'ownership','disk outside namespace or duplicate')
        require(d['gid']==doc['dac']['gid'] and (d['uid'],d['mode'])==((doc['dac']['uid'],0o600) if d['access']=='rw' else (0,0o440)),'ownership','created DAC/access differs')
        seen.add(d['target']);ids.add((d['device'],d['inode']))
    for key in ('install_receipt_sha256','definition_sha256','source_profile_sha256'):sha(doc[key])
    return doc


def decode_install_bundle(doc):
    exact(doc,{'schema','host_id','owner_id','specs'},'install spec bundle');require(doc['schema']==INSTALL_SCHEMA,'shape','install schema')
    bounded(doc['host_id']);bounded(doc['owner_id']);array(doc['specs'],'install specs',MAX_FILES)
    ids=set();natives=set();dacs=set();names=set();incarnations=set()
    for s in doc['specs']:
        exact(s,{'install_id','vm_id','native_uuid','domain_name','incarnation_id','namespace_parent','dac','distribution','disks','definition_ref','copy_budget_bytes','timeout_seconds'},'install spec')
        uid(s['install_id']);uid(s['incarnation_id']);native_uuid(s['native_uuid']);bounded(s['vm_id']);bounded(s['domain_name']);absolute(s['namespace_parent'])
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',s['domain_name']),'shape','native domain name')
        exact(s['dac'],{'user','group','uid','gid'},'new DAC account')
        for key in ('user','group'):require(type(s['dac'][key]) is str and re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}',s['dac'][key]),'shape','account name')
        for key in ('uid','gid'):integer(s['dac'][key],key,1)
        require(s['install_id'] not in ids and s['native_uuid'] not in natives and s['domain_name'] not in names and s['incarnation_id'] not in incarnations and all(s['dac'][k] not in dacs for k in ('uid','gid')),'ownership','reused install/native/account identity')
        ids.add(s['install_id']);natives.add(s['native_uuid']);names.add(s['domain_name']);incarnations.add(s['incarnation_id']);dacs.update(s['dac'][k] for k in ('uid','gid'))
        exact(s['distribution'],{'bundle','expected_manifest_sha256'},'trusted distribution');absolute(s['distribution']['bundle']);sha(s['distribution']['expected_manifest_sha256']);source_ref(s['definition_ref'])
        integer(s['copy_budget_bytes'],'copy budget',1);integer(s['timeout_seconds'],'timeout',1)
        targets=set();require(array(s['disks'],'new disks',MAX_FILES),'ownership','new disks required')
        for d in s['disks']:
            kind=d.get('kind') if type(d) is dict else None
            exact(d,{'kind','target','role','format','access','file_ref'} if kind=='artifact' else {'kind','target','role','format','access','virtual_bytes'},'install disk')
            require(kind in {'artifact','fresh_scratch'} and d['format'] in {'raw','qcow2'} and d['access'] in {'ro','rw'} and d['role'] in {'root','scratch','seed','backing'} and type(d['target']) is str and re.fullmatch(r'[a-z][a-z0-9]{0,15}',d['target']) and d['target'] not in targets,'shape','new disk variant')
            targets.add(d['target'])
            if kind=='artifact':
                exact(d['file_ref'],{'path','bytes','sha256'},'artifact reference');ref=d['file_ref'];bounded(ref['path']);require(not Path(ref['path']).is_absolute() and '..' not in Path(ref['path']).parts,'trust','relative artifact path');integer(ref['bytes'],'artifact bytes',1);sha(ref['sha256'])
            else:
                integer(d['virtual_bytes'],'scratch bytes',1);require(d['role']=='scratch' and d['access']=='rw','shape','fresh writable scratch required')
    return doc


def decode_qualifications(doc):
    exact(doc,{'schema','profiles'},'storage qualifications');require(doc['schema']==QUAL_SCHEMA,'qualification','storage qualification schema')
    require(array(doc['profiles'],'storage profiles',MAX_FILES),'qualification','per-subject profiles required');seen=set()
    for p in doc['profiles']:
        exact(p,{'protocol_id','subject','binding_sha256','host_id','owner_id','policy_sha256','host_boot_id','source_ids','tool_ids','native_peer_identity','host_kernel_id','filesystem_protocol','graph_protocol','holder_protocol','dac_protocol','evidence_ref'},'storage profile')
        require(p['subject'] in {'mutation','replacement'} and p['protocol_id']==(LIVE if p['subject']=='mutation' else OFFLINE) and p['graph_protocol']==p['protocol_id'] and p['holder_protocol']==HOLDER and p['filesystem_protocol']=='linux-btrfs-private-regular-v1' and p['dac_protocol']=='libvirt-12.8.0-static-dac-private-v1','qualification','unreviewed storage protocol')
        for key in ('binding_sha256','policy_sha256'):sha(p[key])
        for key in ('host_id','owner_id','host_boot_id','host_kernel_id'):bounded(p[key])
        key=(p['subject'],p['binding_sha256']);require(key not in seen,'qualification','duplicate storage subject profile');seen.add(key)
        exact(p['source_ids'],SOURCE_DIGESTS,'complete pinned source identities')
        for name,ref in p['source_ids'].items():source_ref(ref);require(ref['sha256']==SOURCE_DIGESTS[name],'qualification','unreviewed source bytes')
        exact(p['tool_ids'],{'virsh','qemu','qemu_img','libvirt_daemon','libvirt_driver','libvirt_client','liburing','kernel_config','kernel_notes','runtime_config','installation_mapping'},'compiled/runtime tool identities')
        for ref in p['tool_ids'].values():source_ref(ref)
        decode_peer(p['native_peer_identity']);require(p['native_peer_identity']['kind']=='libvirt_unix','qualification','local libvirt peer required');source_ref(p['evidence_ref'])
    return doc['profiles']


def _image(info,*,graph=False,expected=None):
    keys(info,{'filename','format','virtual-size'}|({'children'} if graph else set()),{'dirty-flag','actual-size','cluster-size','encrypted','compressed','backing-filename','full-backing-filename','backing-filename-format','snapshots','limits','format-specific','backing-image'},'QEMU BlockNodeInfo')
    absolute(info['filename']);require(info['format'] in {'file','raw','qcow2'} and (expected is None or info['format']==expected),'qualification','unsupported image driver')
    integer(info['virtual-size'],'virtual size')
    for k in ('actual-size','cluster-size'):
        if k in info:integer(info[k],k)
    for k in ('dirty-flag','encrypted','compressed'):
        if k in info:boolean(info[k],k)
    require(info.get('encrypted',False) is False and ('snapshots' not in info or info['snapshots']==[]),'qualification','encrypted/internal snapshot storage unsupported')
    if info['format']=='qcow2':
        exact(info.get('format-specific'),{'type','data'},'explicit qcow2 metadata');f=info['format-specific'];require(f['type']=='qcow2','qualification','qcow2 metadata required')
        keys(f['data'],{'compat','refcount-bits','compression-type'},{'lazy-refcounts','corrupt','extended-l2'},'qcow2 nonexternal metadata')
        require(f['data']['compat'] in {'0.10','1.1'} and f['data']['compression-type'] in {'zlib','zstd'},'qualification','qcow2 variant unsupported');integer(f['data']['refcount-bits'],'refcount bits',1)
        for k in ('lazy-refcounts','corrupt','extended-l2'):
            if k in f['data']:boolean(f['data'][k],k)
        require(f['data'].get('corrupt',False) is False,'qualification','corrupt qcow2')
    else:require('format-specific' not in info and not any(k in info for k in ('backing-filename','full-backing-filename','backing-filename-format','backing-image')),'qualification','raw/file cannot have backing metadata')
    if 'backing-image' in info:_image(info['backing-image'])
    if 'backing-filename' in info:
        bounded(info['backing-filename']);absolute(info.get('full-backing-filename'));require(info.get('backing-filename-format') in {'raw','qcow2'},'qualification','explicit backing format required')
    else:require(not any(k in info for k in ('full-backing-filename','backing-filename-format','backing-image')),'qualification','partial backing metadata')
    return info


def _block_device(n):
    required={'file','node-name','ro','drv','backing_file_depth','children','active','encrypted','detect_zeroes','bps','bps_rd','bps_wr','iops','iops_rd','iops_wr','image','cache','write_threshold'}
    optional={'backing_file','dirty-bitmaps','group','iops_size'}|{x+y for x in ('bps','bps_rd','bps_wr','iops','iops_rd','iops_wr') for y in ('_max','_max_length')}
    keys(n,required,optional,'BlockDeviceInfo');bounded(n['node-name']);absolute(n['file'])
    require(n['drv'] in {'file','raw','qcow2'},'qualification','unsupported native driver')
    for k in ('ro','active','encrypted'):boolean(n[k],k)
    require(n['active'] and not n['encrypted'] and n.get('dirty-bitmaps',[])==[] and n['detect_zeroes'] in {'off','on','unmap'},'qualification','inactive/encrypted/bitmap graph unsupported')
    for k in required&{'backing_file_depth','bps','bps_rd','bps_wr','iops','iops_rd','iops_wr','write_threshold'}:integer(n[k],k)
    exact(n['cache'],{'writeback','direct','no-flush'},'native cache flags')
    for k,v in n['cache'].items():boolean(v,k)
    require(n['cache']['direct'] is False and n['cache']['no-flush'] is False,'qualification','buffered flushing B1 storage required')
    _image(n['image'],expected=n['drv']);require(n['image']['filename']==n['file'],'identity_mismatch','native filename differs')
    seen=set()
    for c in array(n['children'],'native children'):
        exact(c,{'child','node-name'},'native named child');require(c['child'] in {'file','backing'} and c['child'] not in seen,'qualification','unknown/repeated native edge');bounded(c['node-name']);seen.add(c['child'])
    require(seen==(set() if n['drv']=='file' else {'file'}|({'backing'} if 'backing-filename' in n['image'] else set())),'qualification','native children/metadata termination differs')
    return n


def decode_live_graph(replies,roots):
    """QEMU 11.1.2 QAPI + debug entire graph; debug IDs local to this response."""
    exact(replies,{slot for slot,_ in LIVE_QUERIES},'fixed live query set')
    require(qmp_reply(replies['jobs'])==[] and qmp_reply(replies['block_jobs'])==[],'qualification','native jobs active/unknown')
    named={}
    for n in array(qmp_reply(replies['named']),'all named nodes'):
        _block_device(n);require(n['node-name'] not in named,'ownership','duplicate native node name');named[n['node-name']]=n
    require(named,'qualification','empty native graph')
    debug=qmp_reply(replies['debug']);exact(debug,{'nodes','edges'},'debug graph');dn={};drivers={};backends={}
    for n in array(debug['nodes'],'debug nodes'):
        exact(n,{'id','type','name'},'debug node');integer(n['id'],'debug ID');require(n['id']<2**64 and n['id'] not in dn,'shape','duplicate/invalid debug ID');bounded(n['name'])
        require(n['type'] in {'block-driver','block-backend'},'qualification','block job/unknown graph object')
        dest=drivers if n['type']=='block-driver' else backends;require(n['name'] not in dest,'ownership','duplicate debug name');dest[n['name']]=n['id'];dn[n['id']]=n
    require(set(drivers)==set(named),'incomplete_inventory','named/debug node sets differ')
    expected={(n['node-name'],c['node-name'],c['child']) for n in named.values() for c in n['children']};actual=set();be={}
    for e in array(debug['edges'],'debug edges',MAX_NODES*2):
        exact(e,{'parent','child','name','perm','shared-perm'},'debug edge')
        for k in ('parent','child'):integer(e[k],k);require(e[k] in dn,'shape','dangling debug edge')
        for k in ('perm','shared-perm'):require(type(e[k]) is list and len(e[k])==len(set(e[k])) and set(e[k])<=PERMISSIONS,'qualification','unknown graph permissions')
        a,b=dn[e['parent']],dn[e['child']];require(b['type']=='block-driver','qualification','edge to non-driver')
        if a['type']=='block-backend':
            require(e['name']=='root' and a['name'] not in be,'qualification','unknown/duplicate backend root');be[a['name']]=b['name']
        else:
            edge=(a['name'],b['name'],e['name']);require(edge not in actual,'shape','duplicate graph edge');actual.add(edge)
    require(actual==expected,'incomplete_inventory','native child/debug edges differ')
    blocks={}
    for b in array(qmp_reply(replies['block']),'native block backends'):
        keys(b,{'device','type','removable','locked','inserted'},{'qdev','tray_open','io-status'},'BlockInfo')
        for k in ('removable','locked'):boolean(b[k],k)
        require(not b['removable'] and not b['locked'] and b.get('io-status','ok')=='ok' and b.get('tray_open',False) is False,'qualification','removable/locked/failed block device')
        _block_device(b['inserted']);name=b.get('qdev') or b['device'];bounded(name)
        inserted=b['inserted'];standalone=named.get(inserted['node-name'])
        # block/qapi.c:bdrv_block_device_info uses writeback=true when blk=NULL
        # for named nodes; query-block uses the actual backend write cache.
        require(name not in blocks and standalone is not None and {k:v for k,v in inserted.items() if k!='cache'}=={k:v for k,v in standalone.items() if k!='cache'} and all(inserted['cache'][k]==standalone['cache'][k] for k in ('direct','no-flush')),'identity_mismatch','root descriptor differs');blocks[name]=inserted['node-name']
    wanted={};targets=set()
    for root in array(roots,'XML/argv roots',MAX_FILES):
        exact(root,{'target','node_id','backend'},'qualified native root');require(root['target'] not in targets and root['backend'] not in wanted,'ownership','duplicate root');targets.add(root['target']);wanted[root['backend']]=root['node_id']
    require(wanted and wanted==blocks==be and set(backends)==set(be),'incomplete_inventory','XML/argv/query-block/backend root mismatch')
    reached=set();visiting=set()
    def visit(name):
        require(name in named and name not in visiting,'qualification','dangling/cyclic block graph')
        if name in reached:return
        visiting.add(name)
        for c in named[name]['children']:visit(c['node-name'])
        visiting.remove(name);reached.add(name)
    for name in wanted.values():visit(name)
    require(reached==set(named),'incomplete_inventory','unattached/orphan native node')
    for name,n in named.items():
        children={c['child']:named[c['node-name']] for c in n['children']}
        if n['drv']!='file':require(children['file']['drv']=='file' and children['file']['file']==n['file'],'qualification','format must have direct local file leaf')
        if 'backing' in children:
            b=children['backing'];require(b['drv'] in {'raw','qcow2'} and b['ro'] is True and n.get('backing_file')==b['file']==n['image']['full-backing-filename'] and n['image']['backing-filename-format']==b['drv'],'qualification','native backing metadata/format/access differs')
        else:require('backing_file' not in n,'qualification','unaccounted native backing reference')
    # Backing depth is independently cross-checked; absence is not a universal default.
    def depth(name):return sum(1+depth(c['node-name']) for c in named[name]['children'] if c['child']=='backing')
    for name,n in named.items():require(n['backing_file_depth']==depth(name),'qualification','backing depth/termination mismatch')
    return dict(roots=sorted([{'target':r['target'],'node_id':r['node_id']} for r in roots],key=lambda x:x['target']),
        nodes=[dict(id=name,driver=n['drv'],read_only=n['ro'],file_id=n['file'] if n['drv']=='file' else None) for name,n in sorted(named.items())],
        edges=[dict(parent=a,child=b,role=role) for a,b,role in sorted(actual)])


def decode_offline_info(info,format):
    """-f FORMAT info --output=json, NO_BACKING|NO_IO: inspect each private backing separately."""
    _image(info,graph=True,expected=format)
    children=array(info['children'],'offline graph children')
    require(len(children)==1,'qualification','offline format must expose one file child')
    c=children[0];exact(c,{'name','info'},'offline child');require(c['name']=='file','qualification','unexpected offline child');_image(c['info'],graph=True,expected='file')
    require(c['info']['children']==[] and c['info']['filename']==info['filename'] and 'backing-image' not in info,'qualification','offline file leaf/NO_BACKING differs')
    return dict(path=info['filename'],format=format,backing=None if 'backing-filename' not in info else dict(path=info['full-backing-filename'],format=info['backing-filename-format']))


def decode_ring_fdinfo(raw):
    require(type(raw) is str and len(raw.encode())<=MAX_OUTPUT_BYTES,'output_bound','bounded ring fdinfo required')
    fields={};ops=[];poll=False
    for line in raw.splitlines():
        m=re.fullmatch(r'([A-Za-z_]+):\s*(.*)',line)
        if m:
            require(m[1] not in fields,'shape','duplicate ring counter');fields[m[1]]=m[2];poll=m[1]=='PollList';continue
        if poll:
            m=re.fullmatch(r'\s+op=(\d+), task_works=[01]',line);require(m is not None and int(m[1]) in {6,7,11},'qualification','ring unknown submitted operation');ops.append(int(m[1]));continue
        if 'opcode:' in line:
            m=re.fullmatch(r'\s*\d+: opcode:(POLL_ADD|POLL_REMOVE|TIMEOUT), fd:-?\d+, flags:0, off:\d+, addr:0x[0-9a-f]+, rw_flags:0x[0-9a-f]+, buf_index:0 user_data:\d+',line)
            require(m is not None,'qualification','ring SQE outside fdmon B1')
        elif line.strip():require(re.fullmatch(r'\s*\d+: user_data:\d+, res:-?\d+, flags:[0-9a-f]+',line) is not None,'qualification','unparsed ring fdinfo entry')
    required={'SqMask','CqMask','SqHead','SqTail','CachedSqHead','CqHead','CqTail','CachedCqTail','SQEs','CQEs','SqThread','SqThreadCpu','SqTotalTime','SqWorkTime','UserFiles','UserBufs','PollList','CqOverflowList'}
    require(required<=set(fields),'incomplete_probe','ring fdinfo mutex details missing; retry/HOLD')
    require(set(fields)<=required|{'pos','flags','mnt_id','ino','NAPI'} and ('NAPI' not in fields or fields['NAPI']=='disabled'),'qualification','unknown ring fields/NAPI registration')
    require(fields['UserFiles']=='0' and fields['UserBufs']=='0' and fields['SqThread']=='-1' and fields['SqThreadCpu']=='-1' and fields['SqMask']=='0x7f' and fields['CqMask']=='0xff','qualification','registered resources/SQPOLL/unknown ring size')
    for k in required-{'SqMask','CqMask','SqThread','SqThreadCpu','PollList','CqOverflowList'}:require(fields[k].isdigit(),'shape','ring numeric counter missing')
    return dict(user_files=0,user_bufs=0,sq_thread=-1,sq_mask=127,cq_mask=255,observed_poll_ops=ops)


def fd_identity(fd):
    st=os.fstat(fd)
    raw=Path('/proc/self/fdinfo',str(fd)).read_text();m=re.findall(r'^mnt_id:\s*(\d+)$',raw,re.M)
    require(len(m)==1,'incomplete_probe','actual descriptor mount ID required')
    return dict(device=st.st_dev,inode=st.st_ino,mount_id=int(m[0]),uid=st.st_uid,gid=st.st_gid,mode=stat.S_IMODE(st.st_mode),nlink=st.st_nlink)


class PinnedNamespace:
    """O_PATH pins + protected parent ancestry. No lifetime lock inferred from FD."""
    def __init__(self,path,*,owner_uid=0,synthetic_root=None):
        self.path=Path(absolute(str(path)));self.owner_uid=owner_uid;self.synthetic_root=None if synthetic_root is None else Path(synthetic_root);self.closed=False;self.files={};self.parents=[]
        require(synthetic_root is not None or owner_uid==0,'trust','production namespace requires Root')
        try:
            chain=list(reversed([self.path,*self.path.parents]));start=False
            for p in chain:
                if self.synthetic_root is not None and not start:
                    if p!=self.synthetic_root:continue
                    start=True
                fd=os.open(p,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);i=fd_identity(fd);self.parents.append((p,fd,i))
                require(i['uid']==owner_uid and i['mode']&0o022==0,'trust','root nonwritable namespace ancestry required')
                self._no_acl(fd)
            require(self.parents and self.parents[-1][0]==self.path,'trust','namespace not beneath synthetic root')
            self.identity=self.parents[-1][2]
        except BaseException:self.close();raise
    @staticmethod
    def _no_acl(fd):
        # O_PATH cannot fgetxattr; narrow self FD read resolves the already pinned
        # directory/inode. ENODATA means absent; EACCES/unknown is not absence.
        for key in ('system.posix_acl_access','system.posix_acl_default'):
            try:os.getxattr('/proc/self/fd/'+str(fd),key);raise ResourceError('ownership','ACL outside private DAC protocol')
            except OSError as e:
                if e.errno not in {errno.ENODATA,errno.ENOTSUP}:raise
    def pin(self,path,expected=None):
        require(not self.closed,'identity_mismatch','closed namespace handle');p=Path(absolute(str(path)));require(p.parent==self.path,'ownership','file outside owned namespace')
        require(str(p) not in self.files,'ownership','duplicate file path')
        fd=os.open(p.name,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.parents[-1][1])
        try:
            st=os.fstat(fd);i=fd_identity(fd);require(stat.S_ISREG(st.st_mode) and i['nlink']==1 and i['mode'] in {0o600,0o440} and i['mount_id']==self.identity['mount_id'],'ownership','regular private nonalias storage required');self._no_acl(fd)
            require(not any((x['device'],x['inode'])==(i['device'],i['inode']) for _,x in self.files.values()),'ownership','same inode through multiple paths')
            if expected is not None:require(all(expected[k]==i[k] for k in i),'identity_mismatch','actual created file identity/DAC differs')
            self.files[str(p)]=(fd,i);return dict(path=str(p),**i)
        except BaseException:os.close(fd);raise
    def validate(self):
        require(not self.closed,'identity_mismatch','closed namespace handle')
        for p,fd,i in self.parents:
            require(fd_identity(fd)==i,'identity_mismatch','pinned parent metadata changed')
            st=p.lstat();require(stat.S_ISDIR(st.st_mode) and (st.st_dev,st.st_ino)==(i['device'],i['inode']),'identity_mismatch','parent path replaced');self._no_acl(fd)
            current=os.open(p,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:require(fd_identity(current)==i,'identity_mismatch','namespace path mount identity changed')
            finally:os.close(current)
        out=[]
        for p,(fd,i) in self.files.items():
            require(fd_identity(fd)==i,'identity_mismatch','pinned inode metadata changed');st=Path(p).lstat()
            require(stat.S_ISREG(st.st_mode) and (st.st_dev,st.st_ino)==(i['device'],i['inode']),'identity_mismatch','storage path replaced');self._no_acl(fd);out.append(dict(path=p,**i))
            current=os.open(Path(p).name,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.parents[-1][1])
            try:require(fd_identity(current)==i,'identity_mismatch','storage path mount identity changed')
            finally:os.close(current)
        return out
    def close(self):
        if self.closed:return
        self.closed=True
        for fd,_ in self.files.values():os.close(fd)
        for _,fd,_ in reversed(self.parents):os.close(fd)
    def __enter__(self):return self
    def __exit__(self,*args):self.close()


@dataclass(eq=False)
class StorageCaptureHandle:
    owner:object
    namespace:PinnedNamespace
    observation:dict
    before:dict
    deadline:float
    binding:dict
    profile:dict
    source_context:dict
    seal_sha256:str|None=None
    closed:bool=False
    def close(self):
        if not self.closed:self.namespace.close();self.closed=True
    def __enter__(self):require(not self.closed,'identity_mismatch','closed capture');return self
    def __exit__(self,*args):self.close()
    @staticmethod
    def from_document(_):raise ResourceError('trust','capture handle is process-local and cannot be deserialized')


def source_profile_digest(profile):
    return fingerprint({k:profile[k] for k in ('source_ids','tool_ids','filesystem_protocol','holder_protocol','dac_protocol')})


def decode_native_case(result,case,profile,host):
    exact(result,{'schema','case','result','host_boot_id','host_kernel_id','source_profile_sha256','binding_sha256','subject','evidence_refs'},'native qualification case')
    require(result['schema']=='qcl.host-resource-storage-native-case.v1' and result['case']==case and result['result']=='pass' and result['host_boot_id']==host['boot_id'] and result['host_kernel_id']==host['kernel'] and result['source_profile_sha256']==source_profile_digest(profile) and result['binding_sha256']==profile['binding_sha256'] and result['subject']==profile['subject'],'qualification','native case absent/failed/not_measured or reused for another binding/subject')
    require(type(result['evidence_refs']) is list and result['evidence_refs'],'qualification','native primary evidence references required')
    for ref in result['evidence_refs']:source_ref(ref)
    return result


def validate_definition(xml,binding,*,live=False):
    """Positive B1 XML lane. Namespace/custom argv, helpers and disk defaults HOLD."""
    require(xml.tag=='domain' and xml.get('type')=='kvm' and xml.findtext('uuid')==binding['native_uuid'] and xml.findtext('name')==binding['domain_name'],'identity_mismatch','owned KVM definition differs')
    for elem in xml.iter():require(not elem.tag.startswith('{'),'qualification','custom XML namespace outside B1')
    for path in ('memoryBacking','iothreads','iothreadids','launchSecurity','devices/hostdev','devices/filesystem','devices/tpm','devices/shmem','devices/crypto'):
        require(xml.find(path) is None,'qualification','external/shared memory/storage feature outside B1')
    labels=xml.findall('seclabel');dac=[x for x in labels if x.get('model')=='dac']
    require(len(dac)==1 and dac[0].attrib=={'type':'static','model':'dac','relabel':'no'} and dac[0].findtext('label')=='+%d:+%d'%(binding['dac']['uid'],binding['dac']['gid']) and dac[0].find('imagelabel') is None,'ownership','literal static DAC +UID:+GID required')
    require(all(x.get('model') in {'dac','none'} for x in labels),'qualification','unqualified security model')
    devices=xml.find('devices');require(devices is not None,'shape','devices required')
    allowed={'emulator','disk','controller','interface','input','graphics','video','audio','sound','serial','console','channel','memballoon','rng','watchdog','panic'}
    require(all(x.tag in allowed for x in devices),'qualification','unknown memory-holding device')
    for x in xml.findall('devices/video/model/acceleration'):require(x.get('accel3d','no')=='no','qualification','external GPU renderer')
    for x in xml.findall('devices/interface'):
        driver=x.find('driver');require(x.get('type')=='user' or (x.get('type')=='bridge' and driver is not None and driver.get('name')=='qemu'),'qualification','network vhost/helper outside B1')
    expected={d['target']:d for d in binding['disks'] if d['role']!='backing'};seen=set();roots=[]
    for x in xml.findall('devices/disk'):
        target=x.find('target');driver=x.find('driver');source=x.find('source');alias=x.find('alias')
        require(target is not None and target.get('dev') in expected and target.get('dev') not in seen,'identity_mismatch','unknown/duplicate definition disk');d=expected[target.get('dev')];seen.add(d['target'])
        require(x.get('type')=='file' and x.get('device')=='disk' and driver is not None and driver.get('name')=='qemu' and driver.get('type')==d['format'] and driver.get('io')=='threads' and driver.get('cache') in {'writeback','writethrough'} and not any(k in driver.attrib for k in ('iothread','iothreads','queues')),'qualification','explicit threads/buffered local file driver required')
        require(source is not None and source.attrib=={'file':d['path']} and x.find('shareable') is None and (x.find('readonly') is not None)==(d['access']=='ro'),'ownership','source/access differs')
        require(x.find('mirror') is None and x.find('auth') is None and x.find('encryption') is None and x.find('reservations') is None and x.find('transient') is None,'qualification','unsupported disk operation/helper')
        for seclabel in source.findall('seclabel'):require(False,'qualification','per-source security override unsupported')
        if live:require(alias is not None and re.fullmatch(r'[A-Za-z0-9_.-]+',alias.get('name','')),'qualification','actual live disk alias required')
        roots.append(dict(target=d['target'],alias=alias.get('name') if alias is not None else None,path=d['path']))
    require(seen==set(expected),'incomplete_inventory','definition omits private roots')
    return sorted(roots,key=lambda x:x['target'])


def master_key_path(xml,binding):
    """Pinned privileged libvirt default + virDomainDefGetShortName ASCII lane."""
    domain_id=xml.get('id');name=binding['domain_name']
    require(type(domain_id) is str and domain_id.isdigit() and int(domain_id)>0 and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',name),'qualification','actual native ID/ASCII name required for libvirt metadata path')
    return '/var/lib/libvirt/qemu/domain-'+str(int(domain_id))+'-'+name[:20]+'/master-key.aes'


def decode_launch_objects(argv,*,master_key=None):
    """Ordinary RAM/RNG and derived host master-key metadata, from pinned source.

    Optional share=false and RNG filename=/dev/urandom below are documented
    version-specific defaults, unlike an invented general optional-field rule.
    Confidential guest object/machine properties and guest-memfd remain excluded.
    """
    objects={};machine={}
    for i,a in enumerate(argv):
        if a not in {'-object','-machine'}:continue
        require(i+1<len(argv),'shape','truncated object/machine argv');raw=argv[i+1]
        if raw.startswith('{'):o=strict_json(raw)
        else:
            parts=raw.split(',');o={'qom-type' if a=='-object' else 'type':parts[0]}
            for part in parts[1:]:
                k,sep,v=part.partition('=');require(sep and k not in o,'shape','ambiguous object/machine property');o[k]=v
            if a=='-object':
                for k in ('share','reserve','prealloc','dump','merge','opened','x-use-canonical-path-for-ramblock-id'):
                    if k in o:require(o[k] in {'on','off'},'shape','boolean object option');o[k]=o[k]=='on'
                for k in ('size','prealloc-threads'):
                    if k in o:require(o[k].isdigit(),'shape','object integer bytes required');o[k]=int(o[k])
        require(type(o) is dict,'shape','object/machine record')
        if a=='-machine':
            require(not machine,'qualification','multiple machine records');keys(o,{'type'},{'accel','usb','vmport','dump-guest-core','memory-backend','hpet','acpi','smm','kernel_irqchip'},'B1 ordinary machine')
            require(type(o['type']) is str and re.fullmatch(r'(?:pc-q35|pc-i440fx)-11\.1',o['type']),'qualification','pinned ordinary PC machine required');machine=o
        else:
            kind=o.get('qom-type');require(kind in {'memory-backend-ram','rng-random','secret'},'qualification','shared/file/memfd/confidential/unknown object');bounded(o.get('id'));require(o['id'] not in objects,'shape','duplicate object ID')
            if kind=='memory-backend-ram':
                keys(o,{'qom-type','id','size'},{'share','reserve','prealloc','prealloc-threads','dump','merge','x-use-canonical-path-for-ramblock-id'},'ordinary private RAM object');integer(o['size'],'RAM bytes',1)
                for k in ('share','reserve','prealloc','dump','merge','x-use-canonical-path-for-ramblock-id'):
                    if k in o:boolean(o[k],k)
                require(o.get('share',False) is False and o.get('reserve',True) is True,'qualification','shared/noreserve RAM unsupported')
                if 'prealloc-threads' in o:integer(o['prealloc-threads'],'prealloc threads',1)
            elif kind=='rng-random':
                keys(o,{'qom-type','id'},{'filename','opened'},'ordinary RNG object');require(o.get('filename','/dev/urandom')=='/dev/urandom' and o.get('opened',False) is False,'qualification','RNG file/backend outside ordinary entropy device')
            else:
                exact(o,{'qom-type','id','format','file'},'libvirt master-key metadata object');require(master_key is not None and o['id']=='masterKey0' and o['format']=='raw' and o['file']==master_key,'qualification','arbitrary secret/keyid/IV/data/path object unsupported')
            objects[o['id']]=o
    ram=[x for x in objects.values() if x['qom-type']=='memory-backend-ram']
    if ram:
        require(len(ram)==1 and machine.get('memory-backend')==ram[0]['id'],'qualification','ordinary private RAM/machine join required')
        require(ram[0].get('dump',machine.get('dump-guest-core')=='on') is False and ('dump' in ram[0] or machine.get('dump-guest-core')=='off'),'qualification','external core dump memory holder excluded')
    elif machine:require('memory-backend' not in machine,'qualification','unaccounted machine RAM backend')
    return objects


def launch_roots(argv,xml_roots,binding,*,master_key=None):
    """Join actual -device id/drive and explicit JSON -blockdev file aio/cache.

    QOM qdev strings are not guessed from libvirt aliases. This supported lane
    requires QAPI id itself in query-block (N-H2), otherwise holds.
    """
    require(type(argv) is list and argv.count('-uuid')==1 and argv[argv.index('-uuid')+1]==binding['native_uuid'],'ownership','actual QEMU UUID differs')
    forbidden={'-drive','-add-fd','-incoming','-export','-block-export','-plugin','-chardev-fd','-readconfig','-set','-mem-path','-mem-prealloc'}
    require(not forbidden.intersection(argv),'qualification','unsupported launch FD/storage/memory extension')
    for i,arg in enumerate(argv):
        if arg=='-global':require(i+1<len(argv) and re.fullmatch(r'(?:ICH9-LPC|PIIX4_PM)\.disable_s[34]=[01]',argv[i+1]),'qualification','global property override outside libvirt ordinary PM controls')
    decode_launch_objects(argv,master_key=master_key)
    blocks={};devices={}
    for i,a in enumerate(argv):
        if a not in {'-blockdev','-device'}:continue
        require(i+1<len(argv),'shape','truncated actual QEMU argv');raw=argv[i+1]
        if raw.startswith('{'):o=strict_json(raw)
        else:
            require(a=='-device','qualification','JSON blockdev required');parts=raw.split(',');o={'driver':parts[0]}
            for part in parts[1:]:
                k,sep,v=part.partition('=');require(sep and k not in o,'shape','ambiguous device options');o[k]=v
        require(type(o) is dict,'shape','actual launch object')
        if a=='-blockdev':
            name=o.get('node-name');bounded(name);require(name not in blocks and o.get('driver') in {'file','raw','qcow2'},'qualification','unknown launch block node');blocks[name]=o
            for key in ('read-only','auto-read-only'):
                if key in o:boolean(o[key],'launch '+key)
            if 'cache' in o:
                keys(o['cache'],{'direct','no-flush'} if o['driver']=='file' else set(),{'direct','no-flush'},'launch cache')
                require(all(type(v) is bool and v is False for v in o['cache'].values()),'qualification','launch cache outside buffered flushing B1')
            if 'discard' in o:require(o['discard'] in {'ignore','unmap'},'qualification','unknown launch discard mode')
            if 'detect-zeroes' in o:require(o['detect-zeroes'] in {'off','on','unmap'},'qualification','unknown launch zero detection')
            if 'locking' in o:require(o['locking'] in {'on','off','auto'},'qualification','unknown launch locking mode')
            if o['driver']=='file':
                keys(o,{'driver','node-name','filename','aio','cache'},{'auto-read-only','discard','read-only','locking'},'B1 file launch')
                require(o['aio']=='threads' and o['filename'] in {d['path'] for d in binding['disks']} and type(o['cache']) is dict and o['cache'].get('direct') is False and o['cache'].get('no-flush') is False,'qualification','actual explicit threads/buffered file path differs')
            else:
                keys(o,{'driver','node-name','file'},{'backing','read-only','cache','discard','detect-zeroes'},'B1 format launch');require(type(o['file']) is str,'qualification','inline/filter launch graph unsupported')
        elif 'drive' in o:
            require(o.get('driver') in {'virtio-blk-pci','scsi-hd','ide-hd'} and type(o.get('id')) is str and o['id'] not in devices and type(o['drive']) is str,'qualification','qualified emulated block device required');devices[o['id']]=o['drive']
        else:require(not str(o.get('driver','')).startswith(('vhost','vfio','ivshmem')),'qualification','external device launch')
    result=[]
    for r in xml_roots:
        require(r['alias'] in devices and devices[r['alias']] in blocks,'identity_mismatch','live alias/actual drive join missing')
        top=devices[r['alias']];n=blocks[top];require(n['driver'] in {'raw','qcow2'} and n['file'] in blocks and blocks[n['file']].get('filename')==r['path'],'identity_mismatch','launch root file differs')
        result.append(dict(target=r['target'],node_id=top,backend=r['alias']))
    require(set(devices)=={r['alias'] for r in xml_roots},'incomplete_inventory','unaccounted launch disk')
    return result,blocks


def _launch_graph(blocks,roots,binding):
    """Typed launch closure, independently bound to created file format/access.

    QAPI BlockdevOptions +blockdev.c:bds_tree_init default read-only=false;
    auto-read-only defaults false. Explicit file auto-RO may fall back to RO
    (QAPI, block.c:bdrv_apply_auto_read_only); libvirt's protocol layer normally
    enables it. Bound access and the full native graph remain independent checks.
    Omitted qcow2 backing means image metadata, not null: this explicit-node lane
    accepts that omission only when the entire observed graph also has no edge.
    """
    disks={d['path']:d for d in binding['disks']};nodes=[];edges=[]
    def file_for(name):
        require(type(name) is str and name in blocks and blocks[name]['driver']=='file','identity_mismatch','launch format requires direct named file child')
        path=blocks[name]['filename'];require(path in disks,'ownership','launch file outside creation binding');return path
    for name,o in sorted(blocks.items()):
        driver=o['driver'];path=o['filename'] if driver=='file' else file_for(o['file'])
        require(path in disks,'ownership','launch file outside creation binding');disk=disks[path];ro=disk['access']=='ro'
        require(driver=='file' or driver==disk['format'],'identity_mismatch','launch format differs from bound file')
        requested=o.get('read-only',False);auto=o.get('auto-read-only',False)
        require(ro==requested or (ro and not requested and auto),'identity_mismatch','launch read-only/auto-read-only differs from bound access')
        nodes.append(dict(id=name,driver=driver,read_only=ro,file_id=path if driver=='file' else None))
        if driver=='file':continue
        edges.append(dict(parent=name,child=o['file'],role='file'))
        if 'backing' in o:
            require(driver=='qcow2','qualification','raw launch cannot carry a backing option')
            child=o['backing']
            require(child is None or (type(child) is str and child in blocks and blocks[child]['driver'] in {'raw','qcow2'}),'qualification','launch backing requires named format or explicit null')
            if child is not None:
                backing=disks[file_for(blocks[child]['file'])]
                require(backing['role']=='backing' and backing['access']=='ro','ownership','launch backing is not private readonly creation')
                edges.append(dict(parent=name,child=child,role='backing'))
    return dict(roots=sorted([dict(target=r['target'],node_id=r['node_id']) for r in roots],key=lambda r:r['target']),nodes=nodes,edges=sorted(edges,key=lambda e:(e['parent'],e['child'],e['role'])))


class NativeStorageSources:
    """Bounded real metadata adapters. Test injection substitutes this whole seam only."""
    def __init__(self,native,backend,runner):self.native,self.local,self.backend,self.runner=native,native.local,backend,runner
    def read(self,path,limit=MAX_OUTPUT_BYTES):
        with open(path,'rb') as f:data=f.read(limit+1)
        require(len(data)<=limit,'output_bound','native metadata bound');return data.decode()
    def birth(self,pid):return self.native.birth(pid)
    def namespace(self,pid,kind):
        link=os.readlink('/proc/'+str(pid)+'/ns/'+kind);m=re.fullmatch(kind+r':\[(\d+)\]',link);require(m is not None,'incomplete_probe','namespace identity');return int(m[1])
    def read_binding(self,path):return read_root_json(path)
    def digest(self,path):return self.native.file_digest(path)
    def master_key_metadata(self,path,binding,qemu_birth):
        """Metadata-only read: never open for read, hash or retain secret contents."""
        parent=Path(path).parent;trusted_root_path(parent.parent,directory=True)
        directory=os.open(parent,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            p=fd_identity(directory);require(p['uid'] in {0,binding['dac']['uid']} and p['gid'] in {0,binding['dac']['gid']} and p['mode'] in {0o700,0o750},'ownership','unknown libvirt runtime metadata directory')
            PinnedNamespace._no_acl(directory);fd=os.open('master-key.aes',os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
            try:
                st=os.fstat(fd);i=fd_identity(fd);require(stat.S_ISREG(st.st_mode) and st.st_size==32 and i['nlink']==1 and i['mode']==0o600 and i['uid'] in {0,binding['dac']['uid']} and i['gid'] in {0,binding['dac']['gid']},'ownership','unknown libvirt32-byte runtime metadata identity');PinnedNamespace._no_acl(fd)
                mapped=os.stat('/proc/'+str(qemu_birth['pid'])+'/root'+path);require((mapped.st_dev,mapped.st_ino)==(i['device'],i['inode']),'ownership','master-key namespace mapping differs')
                return dict(path=path,**i,size=32,parent=p)
            finally:os.close(fd)
        finally:os.close(directory)
    def inventory(self,binding):
        domains=[];ids=self.backend._run(['list','--all','--uuid']).split();require(len(ids)==len(set(ids)) and len(ids)<=MAX_NODES,'incomplete_inventory','complete unique native inventory')
        for native in sorted(ids):
            native_uuid(native);raw=self.backend._run(['dumpxml',native,'--inactive']);xml=plain_xml(raw);require(xml.findtext('uuid')==native,'identity_mismatch','domain UUID changed')
            state=self.backend._run(['domstate',native]).strip();require(state in {'running','shut off'},'incomplete_inventory','transitional domain state')
            if native!=binding['native_uuid']:
                require(state=='shut off','incomplete_inventory','foreign active domain has no accepted non-tainting complete closure')
                require(xml.findtext('name')!=binding['domain_name'],'ownership','owned name reused')
                for s in xml.findall('.//disk/source')+xml.findall('.//backingStore/source'):
                    p=s.get('file');require(p is not None and not _overlap(p,binding['namespace']['path']),'ownership','foreign source overlaps/unknown protocol')
            else:
                info=self.backend._run(['dominfo',native]);props={}
                for line in info.splitlines():
                    k,sep,v=line.partition(':')
                    if sep:require(k.strip() not in props,'shape','duplicate dominfo');props[k.strip()]=v.strip()
                require(props.get('Managed save')=='no' and props.get('Autostart')=='disable' and props.get('Autostart Once')=='disable','qualification','managed-save/autostart/autostart-once must explicitly be disabled')
                require(self.backend._run(['snapshot-list',native,'--name']).strip()=='','qualification','domain snapshot present')
                stats=self.backend._run(['domjobinfo',native]);job={}
                for line in stats.splitlines():
                    k,sep,v=line.partition(':')
                    if sep:job[k.strip()]=v.strip()
                require(job.get('Job type')=='None','qualification','domain job active/unknown')
            domains.append(dict(uuid=native,name=xml.findtext('name'),state=state,xml_sha256=hashlib.sha256(raw.encode()).hexdigest()))
        pools=[];poolids=self.backend._run(['pool-list','--all','--uuid']).split();require(len(poolids)==len(set(poolids)) and len(poolids)<=MAX_NODES,'incomplete_inventory','unique pool inventory')
        for pid in sorted(poolids):
            native_uuid(pid);raw=self.backend._run(['pool-dumpxml',pid]);pool=plain_xml(raw);require(pool.findtext('uuid')==pid,'identity_mismatch','pool UUID changed')
            require(pool.get('type')=='dir' and pool.findtext('target/path') is not None,'qualification','unqualified pool exclusion protocol');path=pool.findtext('target/path');absolute(path)
            require(not _overlap(path,binding['namespace']['path']),'ownership','pool namespace overlaps owned storage')
            # Every volume path is observed without refresh or contents read.
            listing=self.backend._run(['vol-list','--pool',pid]);lines=listing.splitlines();nonempty=[x for x in lines if x.strip()]
            require(len(nonempty)>=2 and nonempty[0].split()==['Name','Path'] and re.fullmatch(r'[- ]+',nonempty[1]),'incomplete_inventory','volume table incomplete')
            volumes=[]
            for line in nonempty[2:]:
                parts=line.split();require(len(parts)==2 and re.fullmatch(r'[A-Za-z0-9_.-]+',parts[0]),'qualification','ambiguous volume name/path');absolute(parts[1]);require(not _overlap(parts[1],binding['namespace']['path']),'ownership','pool volume overlaps owned closure');volumes.append(parts)
            pools.append(dict(uuid=pid,xml_sha256=hashlib.sha256(raw.encode()).hexdigest(),volumes=volumes))
        return dict(domains=domains,pools=pools)
    def xml(self,native,*,live=False):return self.backend._run(['dumpxml',native]+([] if live else ['--inactive']))
    def live_graph(self,native):
        result={}
        for slot,query in LIVE_QUERIES:
            raw=self.backend._run(['qemu-monitor-command',native,json.dumps(query,separators=(',',':'))]);require(len(raw.encode())<=MAX_OUTPUT_BYTES,'output_bound','QMP output bound');result[slot]=strict_json(raw)
        return result
    def offline_info(self,path,format,profile):
        raw=self.runner.run([profile['tool_ids']['qemu_img']['path'],'info','--output=json','-f',format,'--',path],timeout_seconds=30,max_output_bytes=MAX_OUTPUT_BYTES)
        return strict_json(raw)
    def process_inventory(self,binding,qemu_birth=None,*,own_fds=(),limits=None):
        """Dedicated UID birth exclusion + relevant task FDs/maps, not proc-empty proof.

        Root and approved management are trusted sole topology owners throughout
        inode life. Everyone else is excluded by new private DAC; unexpected task
        with reserved UID/GID, capability, mapping, transfer or registered IO holds.
        """
        limits=limits or {};deadline=time.monotonic()+limits.get('probe_seconds',30);boot=self.local.host()['boot_id'];owner=self.birth(os.getpid())
        native_user=self.namespace(os.getpid(),'user');native_mnt=self.namespace(os.getpid(),'mnt');files={(d['device'],d['inode']):d for d in binding['disks']};records=[];holders=[];rings=[];raw=[]
        pids=sorted(int(p.name) for p in Path('/proc').iterdir() if p.name.isdigit());require(len(pids)<=MAX_PROCESSES,'output_bound','process inventory bound');ring_keys=set()
        def check():require(time.monotonic()<deadline,'incomplete_probe','process observation timed out')
        for pid in pids:
            check()
            try:
                birth=self.birth(pid);status=self.read('/proc/'+str(pid)+'/status');props={}
                for line in status.splitlines():
                    k,sep,v=line.partition(':')
                    if sep:require(k not in props,'shape','duplicate proc status');props[k]=v.strip()
                uids=[int(x) for x in props['Uid'].split()];gids=[int(x) for x in props['Gid'].split()];groups=[int(x) for x in props['Groups'].split()]
                require(len(uids)==len(gids)==4,'incomplete_probe','actual full credentials');caps=int(props['CapEff'],16);userns=self.namespace(pid,'user');mntns=self.namespace(pid,'mnt')
                reserved=binding['dac']['uid'] in uids or binding['dac']['gid'] in gids+groups
                is_qemu=qemu_birth is not None and birth==qemu_birth
                if reserved:require(is_qemu and uids==[binding['dac']['uid']]*4 and gids==[binding['dac']['gid']]*4 and set(groups)<={binding['dac']['gid']} and caps==0 and userns==native_user,'ownership','reserved identity/helper/credentials/namespace unqualified')
                if is_qemu:
                    for d in binding['disks']:
                        st=os.stat('/proc/'+str(pid)+'/root'+d['path']);require(stat.S_ISREG(st.st_mode) and (st.st_dev,st.st_ino)==(d['device'],d['inode']),'ownership','libvirt private mount namespace source mapping differs')
                relevant=reserved or 0 in uids or bool(caps & 6)
                record=dict(birth=birth,uids=uids,gids=gids,groups=groups,cap_eff=caps,user_namespace=userns,mount_namespace=mntns)
                refs=[];task_records=[]
                if relevant:
                    require(userns==native_user,'incomplete_probe','privileged holder in unknown user namespace')
                    tasks=sorted(int(p.name) for p in Path('/proc',str(pid),'task').iterdir());require(len(tasks)<=MAX_TASKS,'output_bound','task inventory bound')
                    for tid in tasks:
                        check();taskbirth=self.birth(tid);base='/proc/'+str(pid)+'/task/'+str(tid);taskstatus=self.read(base+'/status');task_records.append(dict(birth=taskbirth,status_sha256=hashlib.sha256(taskstatus.encode()).hexdigest()))
                        # Per-task credentials may differ. Reserved process/thread
                        # or privileged credential escapes are never inferred away.
                        tu=re.findall(r'^Uid:[ \t]*(.*)$',taskstatus,re.M);tg=re.findall(r'^Gid:[ \t]*(.*)$',taskstatus,re.M)
                        tc=re.findall(r'^CapEff:[ \t]*([0-9a-fA-F]+)$',taskstatus,re.M);tgroups=re.findall(r'^Groups:[ \t]*(.*)$',taskstatus,re.M)
                        require(len(tu)==len(tg)==len(tc)==len(tgroups)==1,'incomplete_probe','task credentials')
                        task_uids=[int(x) for x in tu[0].split()];task_gids=[int(x) for x in tg[0].split()];task_groups=[int(x) for x in tgroups[0].split()];task_caps=int(tc[0],16)
                        task_records[-1].update(uids=task_uids,gids=task_gids,groups=task_groups,cap_eff=task_caps)
                        if is_qemu:require(task_uids==uids and task_gids==gids and set(task_groups)<={binding['dac']['gid']} and task_caps==0 and self.namespace(tid,'user')==userns and self.namespace(tid,'mnt')==mntns,'ownership','QEMU thread credential/namespace differs')
                        else:require(binding['dac']['uid'] not in task_uids and binding['dac']['gid'] not in task_gids+task_groups,'ownership','reserved identity in unrelated thread')
                        # Keep the directory FD alive: enumerating /proc/self/fd
                        # and closing its iterator before stat would manufacture
                        # a missing FD from the enumeration itself.
                        scanfd=os.open(base+'/fd',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
                        fdrecords=[]
                        try:
                            entries=sorted([Path(base,'fd',name) for name in os.listdir(scanfd)],key=lambda p:int(p.name));require(len(entries)<=MAX_FDS,'output_bound','FD inventory bound')
                            for f in entries:
                                check();number=int(f.name);link=os.readlink(f);st=f.stat();fdinfo=self.read(base+'/fdinfo/'+f.name);flags=re.findall(r'^flags:\s*([0-7]+)$',fdinfo,re.M);require(len(flags)==1,'incomplete_probe','FD access flags missing');flag=int(flags[0],8)
                                fdrecords.append(dict(fd=number,link=link,device=st.st_dev,inode=st.st_ino,flags=flag))
                                if is_qemu and link in {'anon_inode:[io_uring]','anon_inode:io_uring'}:
                                    ring=decode_ring_fdinfo(fdinfo);ring_key=(pid,number,st.st_dev,st.st_ino)
                                    if ring_key not in ring_keys:ring_keys.add(ring_key);rings.append(dict(task_birth=taskbirth,fd=number,**ring))
                                    raw.append(('ring-'+str(tid)+'-'+str(number),fdinfo))
                                if link.startswith(('anon_inode:kvm','anon_inode:[kvm')):require(is_qemu,'qualification','KVM descriptor outside sealed QEMU')
                                identity=(st.st_dev,st.st_ino)
                                if identity in files:
                                    if birth==owner and number in own_fds:
                                        require(flag&os.O_PATH,'ownership','collector descriptor must be O_PATH');continue
                                    require(is_qemu and flag&os.O_DIRECT==0 and flag&os.O_PATH==0,'ownership','storage holder outside QEMU/buffered protocol');access='ro' if flag&os.O_ACCMODE==os.O_RDONLY else 'rw'
                                    require(access=='ro' or files[identity]['access']=='rw','ownership','readonly file writable FD');refs.append(dict(kind='fd',file_id=files[identity]['path'],task_birth=taskbirth,fd=number,access=access))
                        finally:os.close(scanfd)
                        maps=self.read(base+'/maps');raw.extend([('fds-'+str(tid),fdrecords),('maps-'+str(tid),maps),('status-'+str(tid),taskstatus)])
                        for line in maps.splitlines():
                            m=re.fullmatch(r'([0-9a-f]+)-([0-9a-f]+) ([-rwxps]{4}) ([0-9a-f]+) ([0-9a-f]+):([0-9a-f]+) (\d+)(?:\s+(.*))?',line);require(m is not None,'incomplete_probe','unparsed proc maps')
                            identity=(os.makedev(int(m[5],16),int(m[6],16)),int(m[7]))
                            if identity in files:
                                require(is_qemu,'ownership','storage mapping outside owned QEMU');access='rw' if 'w' in m[3] else 'ro';require(access=='ro' or files[identity]['access']=='rw','ownership','readonly writable mapping');refs.append(dict(kind='map',file_id=files[identity]['path'],task_birth=taskbirth,start=int(m[1],16),end=int(m[2],16),offset=int(m[4],16),permissions=m[3],access=access))
                        require(self.birth(tid)==taskbirth,'incomplete_probe','task birth raced');task_records[-1]['fds_sha256']=fingerprint(fdrecords);task_records[-1]['maps_sha256']=hashlib.sha256(maps.encode()).hexdigest()
                    record['tasks']=task_records
                if refs:holders.append(dict(birth=birth,uid=uids[0],gid=gids[0],cgroup=self.local.process(pid)['cgroup'],mount_namespace=mntns,user_namespace=userns,refs=refs))
                require(self.birth(pid)==birth,'incomplete_probe','process birth raced');records.append(record)
            except (FileNotFoundError,ProcessLookupError):
                # A relevant disappearing task makes the whole observation
                # incomplete; do not mint an empty negative holder result.
                raise ResourceError('incomplete_probe','process/task/FD inventory changed during capture')
        require(len(rings)<=limits.get('max_rings',MAX_TASKS),'qualification','ring count exceeds qualified host reserve envelope')
        if qemu_birth is not None:require(any(h['birth']==qemu_birth for h in holders),'incomplete_probe','owned QEMU storage FDs not observed')
        return dict(records=records,holders=holders,rings=rings,raw=raw,owner=owner)


def _overlap(a,b):
    absolute(a);absolute(b);a=Path(a);b=Path(b);return a==b or a in b.parents or b in a.parents


class LibvirtStorageCollector:
    def __init__(self,controller,native_sources,backend,runner,protected_config):
        from host_resource_backends import LibvirtMemoryBackend,NativeCommandRunner
        from host_resource_native_cleanup import NativeCleanupSources
        require(os.geteuid()==0 and controller.store.owner_uid==0 and type(native_sources) is NativeCleanupSources and type(backend) is LibvirtMemoryBackend,'root_required','actual local Root collector required')
        for commands in (runner,backend.runner):
            require(type(commands) is NativeCommandRunner and commands.environment.get('LC_ALL')=='C','trust','fixed native C locale required');commands.environment['LANG']='C'
        self.c,self.store,self.native,self.backend,self.runner=controller,controller.store,native_sources,backend,runner
        self.config=decode_config(protected_config,self.store);self.sources=NativeStorageSources(native_sources,backend,runner);self.handles={}
    def _binding(self,native):
        native_uuid(native);doc=decode_binding(self.sources.read_binding(Path(self.config['bindings'])/(native+'.binding.json')))
        require(doc['native_uuid']==native and (doc['host_id'],doc['owner_id'])==(self.c.policy.host_id,self.c.policy.owner_id),'ownership','protected storage binding differs')
        if type(self.sources) is NativeStorageSources:self._binding_provenance(doc)
        return doc
    def _binding_provenance(self,binding):
        bundle=decode_install_bundle(read_root_json(self.config['install_specs']));matches=[s for s in bundle['specs'] if s['native_uuid']==binding['native_uuid'] and s['incarnation_id']==binding['incarnation_id']];require(len(matches)==1,'ownership','binding has no unique original creation spec');spec=matches[0];created=_created(self,spec)
        require(fingerprint(created)==binding['install_receipt_sha256'] and created['namespace']==binding['namespace'] and created['dac']==binding['dac'] and created['disks']==binding['disks'] and spec['vm_id']==binding['vm_id'] and spec['domain_name']==binding['domain_name'],'identity_mismatch','binding differs from original import')
        for d in binding['disks']:
            record=self.store._read(_record_path(self,spec['install_id'],'created-'+d['target']));exact(record,{'schema','install_id','spec_sha256','target','path','artifact','virtual_bytes','identity'},'original inode creation')
            require(record['schema']=='qcl.host-resource-storage-created.v1' and record['install_id']==spec['install_id'] and record['spec_sha256']==fingerprint(spec) and record['target']==d['target'] and record['path']==d['path'] and record['identity']=={k:d[k] for k in ('device','inode','mount_id','uid','gid','mode','nlink')} and fingerprint(record)==d['creation_receipt_sha256'],'identity_mismatch','original inode creation authority differs')
    def _profile(self,binding,subject):
        profiles=decode_qualifications(read_root_json(self.config['qualification']));matches=[p for p in profiles if p['subject']==subject and p['binding_sha256']==fingerprint(binding)];require(len(matches)==1,'qualification','one exact storage profile required');p=matches[0];host=self.native.local.host()
        require((p['host_id'],p['owner_id'],p['policy_sha256'],p['host_boot_id'],p['host_kernel_id'])==(self.c.policy.host_id,self.c.policy.owner_id,policy_digest(self.c.policy),host['boot_id'],host['kernel']) and binding['source_profile_sha256']==source_profile_digest(p),'qualification','actual storage host/source profile differs')
        for ref in list(p['source_ids'].values())+list(p['tool_ids'].values())+[p['evidence_ref']]:require(self.sources.digest(ref['path'])==ref['sha256'],'qualification','actual protected source/tool/evidence changed')
        require(p['tool_ids']['virsh']['path']==self.backend.tool and self.backend.connect_endpoint==libvirt_endpoint(p['native_peer_identity']),'qualification','storage native route/tool differs')
        self._peer(p)
        evidence=read_root_json(p['evidence_ref']['path']);exact(evidence,{'schema','protocol_id','cases','host_boot_id','host_kernel_id','mount_namespace','user_namespace','limits','authority'},'N-H qualified envelope')
        require(evidence['schema']=='qcl.host-resource-storage-native-qualification.v1' and evidence['protocol_id']==HOLDER and evidence['host_boot_id']==host['boot_id'] and evidence['host_kernel_id']==host['kernel'] and evidence['authority']=='root-sole-lifecycle-owner-from-inode-birth-v1','qualification','native lifetime exclusion not qualified')
        exact(evidence['cases'],{'N-H'+str(i) for i in range(9)},'complete native witness matrix')
        for case,ref in evidence['cases'].items():
            source_ref(ref);require(self.sources.digest(ref['path'])==ref['sha256'],'qualification','native qualification case changed');result=read_root_json(ref['path'])
            decode_native_case(result,case,p,host)
            if case=='N-H0':
                paths={r['path'] for r in result['evidence_refs']}
                current=('host_resource_storage','host_resource_recovery','host_resource_native_cleanup','host_resource_service','host_resource_startup','host_resource_operations','host_resource_backends','host_resource_facts','worker_distribution','image_stage')
                require({str(Path(__file__).parent/(name+'.py')) for name in current}<=paths,'qualification','N-H0 must bind actual installed current producer sources, separately from historical primary snapshots')
            for item in result['evidence_refs']:source_ref(item);require(self.sources.digest(item['path'])==item['sha256'],'qualification','native primary evidence changed')
        exact(evidence['limits'],{'probe_seconds','max_rings'},'qualified observation bounds')
        for v in evidence['limits'].values():integer(v,'observation limit',1)
        require(evidence['mount_namespace']==self.sources.namespace(os.getpid(),'mnt') and evidence['user_namespace']==self.sources.namespace(os.getpid(),'user'),'qualification','actual native namespace differs')
        return p,evidence
    def _peer(self,p):
        peer=p['native_peer_identity'];path=Path(peer['socket_path']);trusted_root_path(path.parent,directory=True);st=path.lstat()
        require(stat.S_ISSOCK(st.st_mode) and st.st_uid==0 and (st.st_dev,st.st_ino)==(peer['socket_device'],peer['socket_inode']),'identity_mismatch','actual libvirt endpoint changed')
        unit=self.native.unit(peer['unit']);birth=self.native.birth(int(unit['MainPID']),root=True);process=self.native.local.process(birth['pid'])
        require(unit['LoadState']=='loaded' and unit['ActiveState']=='active' and unit['InvocationID']==peer['invocation_id'] and birth==peer['daemon_birth'] and process['cgroup']==unit['ControlGroup'] and process['executable']==p['tool_ids']['libvirt_daemon']['path'] and self.native.running_digest(birth['pid'])==p['tool_ids']['libvirt_daemon']['sha256'],'identity_mismatch','actual libvirt daemon birth/executable changed')
        self.native.listener_owned(str(path),birth)
        for key in ('libvirt_driver','libvirt_client'):self._mapped_ref(birth['pid'],p['tool_ids'][key])
    def _mapped_ref(self,pid,ref):
        st=Path(ref['path']).stat();mapped=[]
        for line in self.native.local.read('/proc/'+str(pid)+'/maps',limit=MAX_OUTPUT_BYTES).splitlines():
            parts=line.split(None,5)
            if len(parts)==6 and parts[5]==ref['path']:
                dev=parts[3].split(':');mapped.append((os.makedev(int(dev[0],16),int(dev[1],16)),int(parts[4])))
            require(len(parts)<6 or parts[5]!=ref['path']+' (deleted)','qualification','qualified loaded library replaced')
        require(mapped and all(x==(st.st_dev,st.st_ino) for x in mapped),'qualification','actual loaded library identity differs')
    def _pin(self,binding):
        ns=PinnedNamespace(binding['namespace']['path'])
        try:
            require(all(ns.identity[k]==binding['namespace'][k] for k in ('device','inode','mount_id')) and ns.identity['uid']==0 and ns.identity['gid']==binding['dac']['gid'] and ns.identity['mode']==0o750,'ownership','created private namespace differs')
            self._filesystem(ns.identity['mount_id'])
            for d in binding['disks']:ns.pin(d['path'],d)
            require({p.name for p in ns.path.iterdir()}=={Path(d['path']).name for d in binding['disks']},'ownership','unaccounted namespace member')
            return ns
        except BaseException:ns.close();raise
    def _filesystem(self,mount_id):
        rows=[]
        for line in self.native.local.read('/proc/self/mountinfo',limit=MAX_OUTPUT_BYTES).splitlines():
            before,sep,after=line.partition(' - ');parts=before.split();tail=after.split()
            require(sep and len(parts)>=6 and len(tail)==3 and parts[0].isdigit(),'incomplete_probe','complete native mountinfo required')
            if int(parts[0])==mount_id:rows.append((parts,tail))
        require(len(rows)==1 and rows[0][1][0]=='btrfs' and 'rw' in rows[0][0][5].split(',') and 'ro' not in rows[0][0][5].split(','),'qualification','actual private writable Btrfs mount required')
    def _raw_refs(self,subject,items):
        from host_resource_recovery import immutable
        ident=subject['mutation_id'] if subject['kind']=='mutation' else subject['recovery_id'];refs=[];total=0;require(len(items)<=256,'output_bound','raw observation slot count exceeded')
        for slot,value in items:
            require(re.fullmatch(r'[A-Za-z0-9_-]{1,100}',slot),'shape','fixed native observation slot')
            data=json.dumps({'schema':'qcl.host-resource-storage-raw.v1','slot':slot,'value':value},sort_keys=True).encode();require(len(data)<=MAX_OUTPUT_BYTES,'output_bound','raw observation bound');total+=len(data);require(total<=MAX_RAW_BYTES,'output_bound','aggregate observation bound')
            digest=hashlib.sha256(data).hexdigest();path=Path(self.config['bindings'])/(ident+'.'+slot+'.'+digest+'.raw.json');immutable(self.store,path,strict_json(data.decode()));refs.append(dict(slot=slot,path=str(path),bytes=len(data),sha256=digest))
        return refs
    def _observation(self,binding,profile,evidence,subject,ns,qemu_birth=None):
        inv=self.sources.inventory(binding);present=[d for d in inv['domains'] if d['uuid']==binding['native_uuid']];require(len(present)==1 and present[0]['state']==('running' if qemu_birth else 'shut off'),'identity_mismatch','owned power state changed')
        from host_resource_backends import libvirt_config_fingerprint
        inactive=self.sources.xml(binding['native_uuid']);require(libvirt_config_fingerprint(plain_xml(inactive))==binding['definition_sha256'],'identity_mismatch','accepted inactive static definition changed')
        xml=plain_xml(self.sources.xml(binding['native_uuid'],live=qemu_birth is not None));xmlroots=validate_definition(xml,binding,live=qemu_birth is not None);raw=[('domain_inventory',inv['domains']),('pool_inventory',inv['pools']),('definition',inactive)]
        master_metadata=None
        if qemu_birth:
            require(self.native.birth(qemu_birth['pid'])==qemu_birth and self.native.running_digest(qemu_birth['pid'])==profile['tool_ids']['qemu']['sha256'],'identity_mismatch','actual QEMU incarnation/tool differs')
            if type(self.sources) is NativeStorageSources:self._mapped_ref(qemu_birth['pid'],profile['tool_ids']['liburing'])
            argv=self.native.local.read('/proc/'+str(qemu_birth['pid'])+'/cmdline').rstrip('\0').split('\0')
            expected_master=master_key_path(xml,binding) if xml.get('id') is not None else None
            objects=decode_launch_objects(argv,master_key=expected_master)
            if type(self.sources) is NativeStorageSources:require('masterKey0' in objects,'qualification','pinned ordinary libvirt master-key metadata object missing')
            if 'masterKey0' in objects:
                master_metadata=self.sources.master_key_metadata(expected_master,binding,qemu_birth);raw.append(('master_key_metadata',master_metadata))
            roots,blocks=launch_roots(argv,xmlroots,binding,master_key=expected_master);replies=self.sources.live_graph(binding['native_uuid']);graph=decode_live_graph(replies,roots)
            require(graph==_launch_graph(blocks,roots,binding),'identity_mismatch','actual launch/native/creation graph driver, access, path or edges differ')
            raw.extend((slot,replies[slot]) for slot,_ in LIVE_QUERIES);raw.append(('argv',argv))
        else:
            graph=dict(roots=[],nodes=[],edges=[]);visited=set();visiting=set();by_path={d['path']:d for d in binding['disks']}
            def visit(path,format):
                require(path in by_path and by_path[path]['format']==format and path not in visiting,'ownership','offline backing escapes private created graph')
                if path in visited:return path
                visiting.add(path);info=self.sources.offline_info(path,format,profile);item=decode_offline_info(info,format);require(item['path']==path,'identity_mismatch','offline filename differs');raw.append(('offline-'+str(len(visited))+'-'+str(len(visiting)),info))
                graph['nodes']+= [dict(id=path,driver=format,read_only=by_path[path]['access']=='ro',file_id=None),dict(id='file:'+path,driver='file',read_only=by_path[path]['access']=='ro',file_id=path)];graph['edges'].append(dict(parent=path,child='file:'+path,role='file'))
                if item['backing'] is not None:
                    b=item['backing'];require(by_path.get(b['path'],{}).get('role')=='backing' and by_path[b['path']]['access']=='ro','ownership','private readonly backing required');visit(b['path'],b['format']);graph['edges'].append(dict(parent=path,child=b['path'],role='backing'))
                visiting.remove(path);visited.add(path);return path
            for d in binding['disks']:
                if d['role']!='backing':graph['roots'].append(dict(target=d['target'],node_id=visit(d['path'],d['format'])))
            require(visited==set(by_path),'ownership','unattached/orphan created disk')
            graph['nodes'].sort(key=lambda x:x['id']);graph['edges'].sort(key=lambda x:(x['parent'],x['child'],x['role']));graph['roots'].sort(key=lambda x:x['target'])
        filepaths={n['file_id'] for n in graph['nodes'] if n['driver']=='file'};require(filepaths=={d['path'] for d in binding['disks']},'ownership','actual graph file set differs from full private binding')
        disks={d['path']:d for d in binding['disks']}
        for n in graph['nodes']:
            if n['driver']=='file':require(n['read_only']==(disks[n['file_id']]['access']=='ro'),'ownership','native file access differs')
            else:
                children=[e['child'] for e in graph['edges'] if e['parent']==n['id'] and e['role']=='file'];require(len(children)==1,'qualification','format file edge missing');file=next(f for f in graph['nodes'] if f['id']==children[0]);d=disks[file['file_id']]
                require(n['driver']==d['format'] and n['read_only']==(d['access']=='ro'),'ownership','actual format-node access/format differs')
        ownfds=[fd for fd,_ in ns.files.values()];procs=self.sources.process_inventory(binding,qemu_birth,own_fds=ownfds,limits=evidence['limits']);raw.extend(procs['raw']);raw.append(('process_inventory',procs['records']))
        require(qemu_birth is not None or procs['holders']==[],'ownership','stopped candidate retains holders')
        ns.validate();files=[dict(id=d['path'],**{k:v for k,v in d.items() if k!='target'}) for d in sorted(binding['disks'],key=lambda x:x['path'])]
        return dict(inventory=inv,graph=graph,files=files,procs=procs,raw=raw,master_key_metadata=master_metadata)
    def _capture(self,binding,subject,qemu_birth=None):
        profile,evidence=self._profile(binding,subject['kind']);ns=self._pin(binding);start=int(time.time());mono=time.monotonic_ns()
        try:
            data=self._observation(binding,profile,evidence,subject,ns,qemu_birth);refs=self._raw_refs(subject,data['raw']);end=int(time.time());now=time.monotonic_ns()
            observation=dict(schema=CAPTURE_SCHEMA,subject=subject,binding_sha256=fingerprint(binding),profile_sha256=fingerprint(profile),native_peer_identity=profile['native_peer_identity'],started_at=start,completed_at=end,monotonic_start_ns=mono,monotonic_end_ns=now,domain_inventory_sha256=fingerprint(data['inventory']['domains']),pool_inventory_sha256=fingerprint(data['inventory']['pools']),process_inventory_sha256=fingerprint(data['procs']['records']),graph=data['graph'],files=data['files'],holders=data['procs']['holders'],closure_sha256=fingerprint(dict(graph=data['graph'],files=data['files'])),native_observation=dict(schema='qcl.host-resource-storage-native-observation.v1',protocol_id=profile['protocol_id'],query_set=[q for _,q in LIVE_QUERIES] if qemu_birth else [{'execute':'qemu-img-info-per-file','format':'explicit','backing':'NO_BACKING'}],raw_refs=refs,task_inventory_sha256=fingerprint(data['procs']['records']),ring_observations=data['procs']['rings'],operation_owner=data['procs']['owner']))
            require(now-mono<=self.c.policy.timeouts.request_seconds*10**9,'stale','capture exceeded operation freshness window')
            decode_capture(observation);return StorageCaptureHandle(self,ns,observation,data,mono/10**9+self.c.policy.timeouts.request_seconds,binding,profile,dict(subject=subject,qemu_birth=qemu_birth,evidence=evidence))
        except BaseException:ns.close();raise
    def capture_mutation(self,intent,dispatch):
        require(dispatch['intent']==asdict(intent),'identity_mismatch','storage capture dispatch differs');context=intent.native_context;worker,cli=self.native.claim_process(context);binding=self._binding(intent.binding.native_id)
        require(binding['vm_id']==intent.binding.vm_id,'identity_mismatch','storage/runtime VM differs')
        subject=dict(kind='mutation',request_id=intent.request_id,mutation_id=intent.mutation_id,intent_sha256=fingerprint(asdict(intent)),dispatch_sha256=fingerprint(dispatch),host_boot_id=intent.host_boot_id,policy_sha256=intent.policy_sha256,binding=asdict(intent.binding),worker_birth=worker,cli_birth=cli,native_context=context)
        qemu=self.native.birth(int(intent.binding.process_id));handle=self._capture(binding,subject,qemu);self.handles[intent.mutation_id]=handle;return handle
    def capture_replacement(self,recovery_id,native_uuid):
        uid(recovery_id);binding=self._binding(native_uuid);path=self.store.directory/'native-recoveries'/(recovery_id+'.intent.json');intent=self.store._read(path);request_id=intent['recovery']['request_id'];archived=self.store.completed(request_id);require(archived is not None,'reconciliation_required','replacement requires retired archive')
        subject=dict(kind='replacement',recovery_id=recovery_id,archive_sha256=fingerprint(archived),native_uuid=native_uuid,domain_name=binding['domain_name'],definition_sha256=binding['definition_sha256'],storage_binding_sha256=fingerprint(binding),host_boot_id=self.native.local.host()['boot_id'],policy_sha256=policy_digest(self.c.policy))
        handle=self._capture(binding,subject);self.handles[native_uuid]=handle;return handle
    def seal(self,handle):
        self._handle(handle);require(handle.observation['subject']['kind']=='mutation','shape','only original mutation gets attached capture');from host_resource_recovery import immutable
        path=self.store.directory/'native-mutations'/(handle.observation['subject']['mutation_id']+'.storage.json');immutable(self.store,path,handle.observation);handle.seal_sha256=fingerprint(handle.observation);return handle.seal_sha256
    def _handle(self,handle):
        require(type(handle) is StorageCaptureHandle and handle.owner is self and not handle.closed and not handle.namespace.closed,'trust','live process-local storage handle required')
        require(time.monotonic()<=handle.deadline and 0<=int(time.time())-handle.observation['completed_at']<=self.c.policy.timeouts.request_seconds,'stale','storage capture expired')
    def validate_use(self,handle):
        self._handle(handle);s=handle.source_context;binding=self._binding(handle.binding['native_uuid']);require(binding==handle.binding,'identity_mismatch','binding replaced before use');profile,evidence=self._profile(binding,s['subject']['kind']);require(profile==handle.profile and evidence==s['evidence'],'qualification','storage profile changed before use')
        require(self.native.birth(os.getpid())==handle.observation['native_observation']['operation_owner'],'native_owner','capture owner changed')
        if s['subject']['kind']=='mutation':
            require(self.native.claim_process(s['subject']['native_context'])==(s['subject']['worker_birth'],s['subject']['cli_birth']),'native_owner','worker/CLI changed');require(handle.seal_sha256==fingerprint(handle.observation),'reconciliation_required','original capture not durably sealed')
        fresh=self._observation(binding,profile,evidence,s['subject'],handle.namespace,s['qemu_birth']);old=handle.before
        require(fresh['inventory']==old['inventory'] and fresh['graph']==old['graph'] and fresh['files']==old['files'] and fresh['master_key_metadata']==old['master_key_metadata'],'identity_mismatch','native topology/path/access/metadata changed before final use')
        self._handle(handle)
        # Live FD numbers, thread-pool population and directory command children
        # may change. Both passes independently enforce all holder exclusions;
        # equality alone is never the lifetime/ABA argument.
        return [dict(path=f['path'],device=f['device'],inode=f['inode'],kind='local_regular') for f in handle.observation['files']]
    def validate_target_use(self,mutation_id):
        require(mutation_id in self.handles,'reconciliation_required','configured storage capture handle missing');h=self.handles[mutation_id]
        try:
            projection=self.validate_use(h);target=self.store._read(self.store.directory/'native-mutations'/(mutation_id+'.target.json'));claim=self.store._read(self.store.directory/'native-mutations'/(mutation_id+'.json'))
            require(target['storage_devices']==projection and target['intent_sha256']==h.observation['subject']['intent_sha256']==claim['intent_sha256'] and target['dispatch_sha256']==h.observation['subject']['dispatch_sha256'],'identity_mismatch','final durable target/claim/capture differs');return projection
        except BaseException:h.close();raise
    def validate_retirement(self,target):
        """Read original graph only from attached proof; never reconstruct UNKNOWN."""
        path=self.store.directory/'native-mutations'/(target['mutation_id']+'.storage.json')
        try:capture=decode_capture(self.store._read(path))
        except FileNotFoundError as error:raise ResourceError('reconciliation_required','original attached storage capture missing; no reconstruction') from error
        s=capture['subject'];binding=self._binding(target['target']['uuid']);profile,evidence=self._profile(binding,'mutation')
        require(s['kind']=='mutation' and all(s[k]==target[k] for k in ('request_id','mutation_id','intent_sha256','dispatch_sha256','binding','worker_birth','cli_birth','host_boot_id','policy_sha256')) and capture['binding_sha256']==fingerprint(binding) and capture['profile_sha256']==fingerprint(profile) and capture['native_peer_identity']==target['native_peer_identity'],'identity_mismatch','attached storage authority differs from original target')
        require(target['storage_devices']==[dict(path=f['path'],device=f['device'],inode=f['inode'],kind='local_regular') for f in capture['files']],'identity_mismatch','target flat closure differs from original capture')
        for ref in capture['native_observation']['raw_refs']:
            expected=Path(self.config['bindings'])/(target['mutation_id']+'.'+ref['slot']+'.'+ref['sha256']+'.raw.json');require(ref['path']==str(expected) and self.sources.digest(ref['path'])==ref['sha256'],'identity_mismatch','derived raw capture evidence differs')
        with self._pin(binding) as ns:
            try:live=self.native.birth(target['qemu_birth']['pid'])==target['qemu_birth']
            except (FileNotFoundError,ProcessLookupError):live=False
            if live:
                fresh=self._observation(binding,profile,evidence,s,ns,target['qemu_birth']);require(fresh['graph']==capture['graph'] and fresh['files']==capture['files'],'identity_mismatch','old native graph changed before retirement')
                metadata=[ref for ref in capture['native_observation']['raw_refs'] if ref['slot']=='master_key_metadata']
                require((len(metadata)==1 and self.store._read(Path(metadata[0]['path']))['value']==fresh['master_key_metadata']) if fresh['master_key_metadata'] is not None else metadata==[],'identity_mismatch','old runtime metadata object identity changed')
            else:
                self.sources.inventory(binding)
                self.sources.process_inventory(binding,None,own_fds=[fd for fd,_ in ns.files.values()],limits=evidence['limits']);ns.validate()
        # Existing F1 validate_target/quiescent continues to establish old exact
        # process + sealed nondelegated memory scope shutdown. No proc-empty substitute.


def _spec(collector,install_id):
    uid(install_id);bundle=decode_install_bundle(read_root_json(collector.config['install_specs']))
    require((bundle['host_id'],bundle['owner_id'])==(collector.c.policy.host_id,collector.c.policy.owner_id),'ownership','install host/owner differs')
    matches=[s for s in bundle['specs'] if s['install_id']==install_id];require(len(matches)==1,'ownership','one protected install spec required');return matches[0]


def _record_path(collector,install_id,suffix):return Path(collector.config['bindings'])/(install_id+'.'+suffix+'.json')


def _account(collector,spec):
    """Account birth receipt is written by opt-in installer before any inode birth."""
    doc=collector.store._read(_record_path(collector,spec['install_id'],'account'));exact(doc,{'schema','install_id','spec_sha256','dac'},'account creation receipt')
    require(doc==dict(schema='qcl.host-resource-storage-account.v1',install_id=spec['install_id'],spec_sha256=fingerprint(spec),dac=spec['dac']),'ownership','new account creation receipt differs')
    account=pwd.getpwnam(spec['dac']['user']);group=grp.getgrnam(spec['dac']['group'])
    require(account.pw_uid==spec['dac']['uid'] and account.pw_gid==group.gr_gid==spec['dac']['gid'] and group.gr_mem==[] and account.pw_dir=='/nonexistent' and account.pw_shell in {'/usr/bin/nologin','/sbin/nologin','/usr/sbin/nologin'} and [p.pw_name for p in pwd.getpwall() if p.pw_uid==account.pw_uid]==[account.pw_name] and [p.pw_name for p in pwd.getpwall() if p.pw_gid==group.gr_gid]==[account.pw_name] and [g.gr_name for g in grp.getgrall() if g.gr_gid==group.gr_gid]==[group.gr_name] and not any(account.pw_name in g.gr_mem for g in grp.getgrall()),'ownership','dedicated nonlogin account/membership changed')
    return doc


def _created(collector,spec):
    _account(collector,spec);doc=collector.store._read(_record_path(collector,spec['install_id'],'complete'));exact(doc,{'schema','install_id','spec_sha256','distribution_sha256','namespace','dac','disks','account_sha256'},'complete import receipt')
    require(doc['schema']=='qcl.host-resource-storage-import.v1' and doc['install_id']==spec['install_id'] and doc['spec_sha256']==fingerprint(spec) and doc['distribution_sha256']==spec['distribution']['expected_manifest_sha256'] and doc['dac']=={k:spec['dac'][k] for k in ('uid','gid')} and doc['account_sha256']==fingerprint(_account(collector,spec)),'identity_mismatch','complete import authority differs')
    for d in doc['disks']:decode_disk(d)
    return doc


def _source_profiles(collector):
    profiles=decode_qualifications(read_root_json(collector.config['qualification']));p=profiles[0]
    require(all(source_profile_digest(q)==source_profile_digest(p) for q in profiles),'qualification','one installed source/tool envelope required before import')
    for ref in list(p['source_ids'].values())+list(p['tool_ids'].values()):require(collector.sources.digest(ref['path'])==ref['sha256'],'qualification','preparation source/tool changed')
    return p


def _install_import(collector,install_id):
    """Future Root IO only. Existing/partial namespace is never silently adopted."""
    from host_resource_recovery import immutable
    spec=_spec(collector,install_id);account=_account(collector,spec);profile=_source_profiles(collector);directory=Path(spec['namespace_parent'])/spec['incarnation_id'];trusted_root_path(directory.parent,directory=True)
    complete=_record_path(collector,install_id,'complete')
    if complete.exists():
        record=_created(collector,spec)
        with PinnedNamespace(directory) as ns:
            require(all(ns.identity[k]==record['namespace'][k] for k in ('device','inode','mount_id')),'identity_mismatch','import namespace replaced')
            for d in record['disks']:ns.pin(d['path'],d)
            ns.validate()
        collector.store._sync_immutable(complete,record,conflict_code='reconciliation_required');return record
    intent=_record_path(collector,install_id,'intent');require(not intent.exists() and not directory.exists(),'reconciliation_required','prepared/partial import requires explicit reconciliation, never recopy')
    intent_doc=dict(schema='qcl.host-resource-storage-import-intent.v1',install_id=install_id,spec_sha256=fingerprint(spec),account_sha256=fingerprint(account),namespace=str(directory))
    immutable(collector.store,intent,intent_doc)
    # Verify once, explicitly, before byte copy. No bundle scripts execute.
    import worker_distribution
    bundle=trusted_root_path(spec['distribution']['bundle'],directory=True)
    manifest=worker_distribution.verify(bundle,spec['distribution']['expected_manifest_sha256'],timeout_seconds=spec['timeout_seconds']);inventory=worker_distribution.shape(manifest)
    needed=sum(d['file_ref']['bytes'] if d['kind']=='artifact' else d['virtual_bytes'] for d in spec['disks']);require(needed<=spec['copy_budget_bytes'],'capacity','copy exceeds explicit install budget')
    space=os.statvfs(directory.parent);require(space.f_bavail*space.f_frsize>=spec['copy_budget_bytes'],'capacity','actual available filesystem space below explicit copy guard')
    deadline=time.monotonic()+spec['timeout_seconds'];directory.mkdir(mode=0o750);os.chown(directory,0,spec['dac']['gid']);os.chmod(directory,0o750)
    parentfd=os.open(directory.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(parentfd)
    finally:os.close(parentfd)
    disks=[]
    with PinnedNamespace(directory) as ns:
        for d in spec['disks']:
            require(time.monotonic()<deadline,'incomplete_probe','import IO deadline exceeded');path=directory/(d['role']+'-'+d['target']+'.'+d['format']);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
            try:
                if d['kind']=='artifact':
                    ref=d['file_ref'];require(inventory.get(ref['path'])==ref,'ownership','artifact not exact accepted distribution member');src=trusted_root_path(bundle/ref['path']);sourcefd=os.open(src,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
                    try:
                        st=os.fstat(sourcefd);require(stat.S_ISREG(st.st_mode) and st.st_size==ref['bytes'] and st.st_nlink==1,'ownership','accepted copy source changed');total=0;digest=hashlib.sha256()
                        while True:
                            require(time.monotonic()<deadline,'incomplete_probe','bounded import deadline');data=os.read(sourcefd,65536)
                            if not data:break
                            total+=len(data);require(total<=ref['bytes'],'identity_mismatch','artifact grew');digest.update(data);view=memoryview(data)
                            while view:view=view[os.write(fd,view):]
                        require(total==ref['bytes'] and digest.hexdigest()==ref['sha256'],'identity_mismatch','artifact copy digest differs')
                    finally:os.close(sourcefd)
                elif d['format']=='raw':
                    # Allocate the declared new private scratch, rather than
                    # inventing capacity from a sparse file's virtual size.
                    os.posix_fallocate(fd,0,d['virtual_bytes'])
                else:
                    # Placeholder was O_EXCL-created by this exact intent. The
                    # fixed tool may initialize only this just-created file.
                    os.close(fd);fd=None
                    collector.runner.run([profile['tool_ids']['qemu_img']['path'],'create','-f','qcow2','--',str(path),str(d['virtual_bytes'])],timeout_seconds=max(1,int(deadline-time.monotonic())),max_output_bytes=MAX_OUTPUT_BYTES)
                    fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
                os.fchown(fd,spec['dac']['uid'] if d['access']=='rw' else 0,spec['dac']['gid']);os.fchmod(fd,0o600 if d['access']=='rw' else 0o440);os.fsync(fd);identity=fd_identity(fd)
                creation=dict(schema='qcl.host-resource-storage-created.v1',install_id=install_id,spec_sha256=fingerprint(spec),target=d['target'],path=str(path),artifact=d.get('file_ref'),virtual_bytes=d.get('virtual_bytes'),identity=identity)
                creation_path=_record_path(collector,install_id,'created-'+d['target']);immutable(collector.store,creation_path,creation);sha_created=fingerprint(creation)
                disk=dict(target=d['target'],role=d['role'],format=d['format'],access=d['access'],path=str(path),**identity,creation_receipt_sha256=sha_created);decode_disk(disk);ns.pin(path,disk);disks.append(disk)
            finally:
                if fd is not None:os.close(fd)
        dirfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:os.fsync(dirfd)
        finally:os.close(dirfd)
        ns.validate();record=dict(schema='qcl.host-resource-storage-import.v1',install_id=install_id,spec_sha256=fingerprint(spec),distribution_sha256=spec['distribution']['expected_manifest_sha256'],namespace=dict(path=str(directory),**{k:ns.identity[k] for k in ('device','inode','mount_id')}),dac={k:spec['dac'][k] for k in ('uid','gid')},disks=disks,account_sha256=fingerprint(account));immutable(collector.store,complete,record);return record


def _storage_definition(collector,install_id):
    from host_resource_recovery import immutable
    spec=_spec(collector,install_id);created=_created(collector,spec);ref=spec['definition_ref'];require(collector.sources.digest(ref['path'])==ref['sha256'],'identity_mismatch','protected definition template changed')
    with open(trusted_root_path(ref['path']),'rb') as stream:raw=stream.read(MAX_OUTPUT_BYTES+1)
    xml=plain_xml(raw);require(xml.findtext('uuid')==spec['native_uuid'] and xml.findtext('name')==spec['domain_name'],'ownership','fresh recipe identity differs');disks={d['target']:d for d in created['disks'] if d['role']!='backing'};seen=set()
    for x in xml.findall('devices/disk'):
        target=x.find('target');require(target is not None and target.get('dev') in disks and target.get('dev') not in seen,'ownership','recipe disk target differs');d=disks[target.get('dev')];seen.add(d['target']);x.set('type','file');x.set('device','disk')
        driver_pos=next((i for i,e in enumerate(x) if e.tag=='driver'),0)
        source_pos=next((i for i,e in enumerate(x) if e.tag=='source'),1)
        for name in ('source','driver','readonly','backingStore'):
            for old in x.findall(name):x.remove(old)
        x.insert(driver_pos,ET.Element('driver',name='qemu',type=d['format'],io='threads',cache='writeback'));x.insert(source_pos,ET.Element('source',file=d['path']))
        if d['access']=='ro':ET.SubElement(x,'readonly')
    require(seen==set(disks),'incomplete_inventory','recipe omitted disk')
    for old in xml.findall('seclabel'):xml.remove(old)
    dac=ET.SubElement(xml,'seclabel',type='static',model='dac',relabel='no');ET.SubElement(dac,'label').text='+%d:+%d'%(created['dac']['uid'],created['dac']['gid'])
    binding=dict(native_uuid=spec['native_uuid'],domain_name=spec['domain_name'],dac=created['dac'],disks=created['disks']);validate_definition(xml,binding)
    data=ET.tostring(xml,encoding='utf-8');require(len(data)<=MAX_OUTPUT_BYTES,'output_bound','candidate XML bound');record=dict(schema='qcl.host-resource-storage-definition.v1',install_id=install_id,spec_sha256=fingerprint(spec),import_sha256=fingerprint(created),template_sha256=ref['sha256'],definition_sha256=hashlib.sha256(data).hexdigest(),xml=data.decode(),power_intent='stopped-no-autostart')
    immutable(collector.store,_record_path(collector,install_id,'definition'),record);return data


def _bind_storage(collector,install_id):
    from host_resource_recovery import immutable
    from host_resource_backends import libvirt_config_fingerprint
    spec=_spec(collector,install_id);created=_created(collector,spec);definition=collector.store._read(_record_path(collector,install_id,'definition'));expected=_storage_definition(collector,install_id)
    require(definition['definition_sha256']==hashlib.sha256(expected).hexdigest(),'identity_mismatch','emitted definition changed')
    actual=collector.sources.xml(spec['native_uuid']);xml=plain_xml(actual);require(_candidate_static(xml)==_candidate_static(plain_xml(expected)),'identity_mismatch','actual static native definition differs from candidate')
    profile=_source_profiles(collector);binding=dict(schema=BINDING_SCHEMA,host_id=collector.c.policy.host_id,owner_id=collector.c.policy.owner_id,vm_id=spec['vm_id'],native_uuid=spec['native_uuid'],domain_name=spec['domain_name'],incarnation_id=spec['incarnation_id'],namespace=created['namespace'],dac=created['dac'],disks=created['disks'],install_receipt_sha256=fingerprint(created),definition_sha256=libvirt_config_fingerprint(xml),source_profile_sha256=source_profile_digest(profile));decode_binding(binding);validate_definition(xml,binding)
    p,e=collector._profile(binding,'replacement')
    with collector._pin(binding) as ns:
        observation=collector._observation(binding,p,e,{},ns);require(observation['procs']['holders']==[],'ownership','candidate has live holders')
        # Repeat the entire stopped graph after metadata/holder reads; no launch
        # or attach occurs. Root's sole-operation/lifetime authority excludes ABA.
        final=collector._observation(binding,p,e,{},ns);require(final['graph']==observation['graph'] and final['inventory']==observation['inventory'],'identity_mismatch','stopped graph changed at bind')
        path=Path(collector.config['bindings'])/(spec['native_uuid']+'.binding.json');immutable(collector.store,path,binding)
    return binding


def _admin(install_id,action):
    from host_resource_service import open_service
    require(os.geteuid()==0,'root_required','Root storage preparation only');uid(install_id);service=open_service();require(hasattr(service,'storage'),'qualification','protected storage owner not configured')
    with service.controller.store.operation():return action(service.storage,install_id)
def import_storage(install_id):return _admin(install_id,_install_import)
def storage_definition(install_id):return _admin(install_id,_storage_definition)
def bind_storage(install_id):return _admin(install_id,_bind_storage)


def decode_capture(doc):
    exact(doc,CAPTURE_FIELDS,'attached storage capture');require(doc['schema']==CAPTURE_SCHEMA,'shape','capture schema')
    for k in ('binding_sha256','profile_sha256','domain_inventory_sha256','pool_inventory_sha256','process_inventory_sha256','closure_sha256'):sha(doc[k])
    for k in ('started_at','completed_at','monotonic_start_ns','monotonic_end_ns'):integer(doc[k],k)
    require(doc['completed_at']>=doc['started_at'] and doc['monotonic_end_ns']>=doc['monotonic_start_ns'],'shape','capture time order');decode_peer(doc['native_peer_identity'])
    s=doc['subject'];require(type(s) is dict,'shape','capture subject')
    if s.get('kind')=='mutation':
        exact(s,{'kind','request_id','mutation_id','intent_sha256','dispatch_sha256','host_boot_id','policy_sha256','binding','worker_birth','cli_birth','native_context'},'mutation capture subject');uid(s['mutation_id']);bounded(s['request_id']);exact(s['binding'],RuntimeBinding.__dataclass_fields__,'capture runtime binding')
        for k in ('worker_birth','cli_birth'):decode_birth(s[k])
        from host_resource_recovery import decode_context
        decode_context(s['native_context'])
        for k in ('intent_sha256','dispatch_sha256','policy_sha256'):sha(s[k])
    else:
        exact(s,{'kind','recovery_id','archive_sha256','native_uuid','domain_name','definition_sha256','storage_binding_sha256','host_boot_id','policy_sha256'},'replacement capture subject');require(s['kind']=='replacement','shape','capture kind');uid(s['recovery_id']);native_uuid(s['native_uuid'])
        for k in ('archive_sha256','definition_sha256','storage_binding_sha256','policy_sha256'):sha(s[k])
    files=array(doc['files'],'capture files',MAX_FILES);require(files,'qualification','empty B1 file closure unsupported');file_ids=set();inodes=set()
    for f in files:
        exact(f,FILE_FIELDS,'capture file');bounded(f['id']);decode_disk({k:v for k,v in f.items() if k!='id'}|{'target':'x'})
        require(f['id'] not in file_ids and (f['device'],f['inode']) not in inodes,'ownership','capture alias');file_ids.add(f['id']);inodes.add((f['device'],f['inode']))
    g=doc['graph'];exact(g,{'roots','nodes','edges'},'normalized graph');nodes={}
    for n in array(g['nodes'],'normalized nodes'):
        exact(n,{'id','driver','read_only','file_id'},'normalized node');bounded(n['id']);boolean(n['read_only'],'node access');require(n['id'] not in nodes and n['driver'] in {'file','raw','qcow2'} and (n['file_id'] in file_ids if n['driver']=='file' else n['file_id'] is None),'shape','node/file reference');nodes[n['id']]=n
    used=set();children={n:[] for n in nodes}
    for e in array(g['edges'],'normalized edges',MAX_NODES*2):
        exact(e,{'parent','child','role'},'normalized edge');require(e['parent'] in nodes and e['child'] in nodes and e['role'] in {'file','backing'} and (e['parent'],e['role']) not in used,'shape','normalized duplicate/dangling edge');used.add((e['parent'],e['role']));children[e['parent']].append(e['child'])
    visited=set();stack=set()
    def visit(n):
        require(n in nodes and n not in stack,'shape','cyclic/dangling normalized graph')
        if n in visited:return
        stack.add(n)
        for c in children[n]:visit(c)
        stack.remove(n);visited.add(n)
    require(g['roots'] and nodes,'qualification','empty B1 graph unsupported');targets=set()
    for r in array(g['roots'],'normalized roots',MAX_FILES):
        exact(r,{'target','node_id'},'normalized root');bounded(r['target']);require(r['target'] not in targets,'shape','duplicate normalized root');targets.add(r['target']);visit(r['node_id'])
    require(visited==set(nodes) and {n['file_id'] for n in nodes.values() if n['driver']=='file'}==file_ids,'incomplete_inventory','normalized graph/file closure incomplete')
    for name,n in nodes.items():
        edges={e['role']:nodes[e['child']] for e in g['edges'] if e['parent']==name}
        require((not edges if n['driver']=='file' else 'file' in edges and edges['file']['driver']=='file' and set(edges)<=({'file','backing'} if n['driver']=='qcow2' else {'file'})),'qualification','normalized driver/edge termination differs')
        if 'backing' in edges:require(edges['backing']['driver'] in {'raw','qcow2'} and edges['backing']['read_only'],'qualification','normalized backing access differs')
    for h in array(doc['holders'],'holders',MAX_TASKS):
        exact(h,{'birth','uid','gid','cgroup','mount_namespace','user_namespace','refs'},'storage holder');decode_birth(h['birth']);bounded(h['cgroup'])
        for k in ('uid','gid','mount_namespace','user_namespace'):integer(h[k],k)
        for ref in array(h['refs'],'holder refs',MAX_FDS):
            exact(ref,{'kind','file_id','task_birth','fd','access'} if ref.get('kind')=='fd' else {'kind','file_id','task_birth','start','end','offset','permissions','access'},'holder reference');require(ref['kind'] in {'fd','map'} and ref['file_id'] in file_ids and ref['access'] in {'ro','rw'},'shape','holder reference variant');decode_birth(ref['task_birth'])
            for k in ({'fd'} if ref['kind']=='fd' else {'start','end','offset'}):integer(ref[k],k)
            if ref['kind']=='map':require(ref['end']>ref['start'] and type(ref['permissions']) is str and re.fullmatch(r'[-rwxps]{4}',ref['permissions']),'shape','map range/permissions invalid')
    o=doc['native_observation'];exact(o,{'schema','protocol_id','query_set','raw_refs','task_inventory_sha256','ring_observations','operation_owner'},'native observation')
    require(o['schema']=='qcl.host-resource-storage-native-observation.v1' and o['protocol_id'] in {LIVE,OFFLINE} and o['query_set']==([q for _,q in LIVE_QUERIES] if o['protocol_id']==LIVE else [{'execute':'qemu-img-info-per-file','format':'explicit','backing':'NO_BACKING'}]),'qualification','fixed query set differs')
    require(o['protocol_id']==(LIVE if s['kind']=='mutation' else OFFLINE),'qualification','capture subject/query protocol differs')
    sha(o['task_inventory_sha256']);decode_birth(o['operation_owner'])
    slots=set()
    for r in array(o['raw_refs'],'raw observations',256):
        exact(r,{'slot','path','bytes','sha256'},'raw observation ref');bounded(r['slot']);absolute(r['path']);integer(r['bytes'],'raw bytes',1);sha(r['sha256']);require(r['bytes']<=MAX_OUTPUT_BYTES and r['slot'] not in slots,'output_bound','duplicate/oversized native observation');slots.add(r['slot'])
    fixed={'domain_inventory','pool_inventory','definition','process_inventory'}
    if o['protocol_id']==LIVE:fixed|={slot for slot,_ in LIVE_QUERIES}|{'argv'}
    allowed=fixed|({'master_key_metadata'} if o['protocol_id']==LIVE else set())
    require(fixed<=slots and all(slot in allowed or re.fullmatch(r'(?:fds|maps|status)-[0-9]+|ring-[0-9]+-[0-9]+|offline-[0-9]+-[0-9]+',slot) for slot in slots),'incomplete_probe','missing/unknown raw native observation slot')
    require(not any(slot.startswith('offline-') for slot in slots) if o['protocol_id']==LIVE else any(slot.startswith('offline-') for slot in slots),'qualification','live/offline raw protocol mixed/incomplete')
    require(sum(r['bytes'] for r in o['raw_refs'])<=MAX_RAW_BYTES,'output_bound','aggregate native observations exceeded')
    for r in array(o['ring_observations'],'ring observations',MAX_TASKS):
        exact(r,{'task_birth','fd','user_files','user_bufs','sq_thread','sq_mask','cq_mask','observed_poll_ops'},'qualified ring observation');decode_birth(r['task_birth']);integer(r['fd'],'ring FD');require(r['user_files']==0 and type(r['user_files']) is int and r['user_bufs']==0 and type(r['user_bufs']) is int and r['sq_thread']==-1 and type(r['sq_thread']) is int and r['sq_mask']==127 and type(r['sq_mask']) is int and r['cq_mask']==255 and type(r['cq_mask']) is int and type(r['observed_poll_ops']) is list and all(type(x) is int and x in {6,7,11} for x in r['observed_poll_ops']),'qualification','unqualified ring resources/opcodes')
    require(doc['closure_sha256']==fingerprint(dict(graph=g,files=files)),'identity_mismatch','capture closure digest differs')
    return doc


# SOURCE_DIGESTS is filled below from the frozen S1/H1 primary source receipts.
SOURCE_DIGESTS={'HAIO': 'de3feb639616e371d5c11e26da45e2a5636de3401d12e62da3a8022fef0ec519', 'HCHAR': 'fa414b863afc85192e7eda2206e9e0cbce0822d608ddae9560e0e0528e8f7236', 'HCHFE': '47d98ed0c25f342388cc276dcacbda4faeb9ea7a573c3f07b7bc75081be16b0b', 'HCHIO': '8e9025f8181559f4bc665a82cee20c275776fa134f34c4a2b8bd45f14451feee', 'HCPU': 'd3ead98db2a9354e49217d631f316e95487f7ab156ab4be9adad32dd5fae4acc', 'HDR': 'd08595953bd0560ad5bc274731ea28eac9a54e2d610af8c8dc08e65dcaef6077', 'HFDM': '56ea83f2b9bd0a59f24dfaa2c3e57ddfaf1e45bbe3e8f40f045363b89c922707', 'HIO': '9218894fbdd34e456fa2c7ba71d7a3899e1c0ebb713d91153489518db547d578', 'HKVM': '5bd7be012bd6a858c30c9bb6b7ec861cbce5e3e611b794aa32c4d25874a0a0f8', 'HMAIN': '5209f230ab4a0d0794d3a2669b2a6d8154349283d8560eb8670044877122c242', 'HMIG': 'be90c932e045bc0fdd207acee1cc414c3ddea9e87f7663bc0b5f906030ca3888', 'HMISC': '7bce935ac076d1b9e63bb105bdc3608c8126b025dba46f47d8ce7ec1772d99a1', 'HMON': '50aa5ddf578e2e629cf5951d9937718fdfa187e28b21efab974fe2513fecbcff', 'HPOOL': 'cd7848272ace041fa9e991369b216657d7b7ba076f22b9029a204f60c42a8c75', 'HPR': 'f6514ffc8846511ae520b1f30ad9c4f9684fc198c52faa95e4147faefaf8fe7b', 'HRUN': 'cc0ceeffd2dd2b8c61eed5d9bf14c25d211c2259df3de537ebf8f2927c1ae7ab', 'HSEC': 'fa45c2fceb986158ed98d6c412efab6714604b58a2591782bcc3c8758f7aad46', 'HSOCK': '24b67f6b8092a34befdbb50133fee9c41cfb6f8e3137aeb7f070272a76111bbf', 'HVHOST': '8ff3ae4c8d4b4fce2f210f27a2ab58722e1e4de7ec6699659e852656943720a9', 'KBTRFS': 'bd7dec8b8b8fe0586a73a1c48bd4aa11cc3c14fea7d574017712776700bd9ba8', 'KCG': '1f3198c8146f3b2046a77c22ef840b74c36fc9c1cc1482bd2cb250ada602be03', 'KEXIT': 'ecca06ee0bf8e50177e955788f183798fc7f82add2f609f8f961a30b31440595', 'KFDINFO': 'e8127d7f9ee087856eed281787eb2f470edd4861e1372a76f2e72d1d92669843', 'KFILE': '4d06c4c911801f19846fb1e155c3eb90522c80dbc657f15212a8f7947cbeaca1', 'KFORK': 'b6ef045e24dd4c9b29b633cec6e45dedf15158940448ffec5fa81c28d283fe9e', 'KFT': 'f4395a9db6620f5b4ea7dea04088826f0e4edc3ac51228cbe06703d5aaabec4e', 'KIRQ': 'bd26c2971114ab22e096c8d88005151142ad3e4dd045727f1bb56059bc6db935', 'KKVM': '607eae128bb389767e46fab409966cd4155fb1a12e3580e4864ec8276444978d', 'KMAPS': '1c4e03e5ad6f07287c951cf7231840e4f7d5f70cd16806c913af946104a99a46', 'KMM': '449b858385c7ece0ff88a8b41893efadb70a437fb8585a296c4ef0461a4c1545', 'KPROC': '5aba6d410e9aee3283b9007e33668a99f5d4c506deffa8b9816be415966eca0b', 'KRSRC': '64fec9b3f6bc2acf150619d7360926fb68f69b350602019fa20b4361add88c51', 'KUR': '7e4540b9a3d457fa599834ad5754c0acfc533dd976a337ee0de4de16c4d5a7ec', 'LB': 'ecb7bedb37de96d18635397f72d98eb66b9402118e3354e82157c623eb5f1b0f', 'LCMD': '680d735d02b236d040ecc72d81392c87d6f9a09121d90c8269c0749d9e0e0ebb', 'LDAC': '154b1ca96d6c4c3316ebaec3450772a76970ea14bd357492973463e74b314e82', 'LDOM': '1ac4a096ed2e8430f4aa04a18bfdabc8c8870fe0ef1ee828ecaac701d8a88a7f', 'LDR': '17a2dbfb6f36901fd2549cfc9451b4c35045983586584a9d738be0ccdc9e2337', 'LEXEC': '7da374df3b3085d34ddc63f383fa998353c607c2a72ca71b7ebd3def0ed6ac08', 'LFD': '003a9845f88dc8601e040c23047abbbdcd638ce87ddb3172f2db9de88be70a1d', 'LIBVIRT_INVENTORY/tools/virsh-domain-monitor.c': '8ad8cc525f2a0f5eeca047bf835426b6d0867f998850da1c156f9e5bab03fd16', 'LIBVIRT_INVENTORY/tools/virsh-pool.c': '951cdc090ab3652ab6a6a12560bde40a853cb0972ea401e7081a6f73e1be6610', 'LIBVIRT_INVENTORY/tools/virsh-snapshot.c': '67128b5c478407d77b359ee38d76730435b1790e3936032df63bbcb7fb715772', 'LIBVIRT_INVENTORY/tools/virsh-volume.c': '76b270d292569df1854ec8bbbdfee8802947f1209d5a79dbc998ebedbf95cea6', 'LMON': '37836f3799fe18fe1c68a4c2928879f92085dee550afdc2940100398c359618d', 'LNS': '0cd5dc6737fccfa421ce875b61bdb344f2d4c7a4afe0cb7d3c552d51b0551a09', 'LPROC': 'ff7f79fd8429ea3954f11709b3ac53858263fb8af9be499903f69d0fcd9379e5', 'LTERM': '5f420c985f1ac65fac4c92e0d81990a8eee6b5d0888efdd64c00702e6030c0ca', 'LUTIL': '34dfd0625ddb6f645df62a5f1a2e9a3f5332662ef056b24bd73dc4fa1acffc58', 'LXML': '5f2bdcf4a6d43c70bd471f2a485d06c893c0f59c0ca95da567344491ce2080a7', 'MASTER_LIBVIRT/src/qemu/qemu_alias.c': '11e913c82cb16f48bf48be2390bb930f00a883866b5f2d25d3a6a131452405cc', 'MASTER_LIBVIRT/src/qemu/qemu_conf.c': '764ee00c4b1591c5c074f382611179e398f731ab9619016bcdaeced02e57d2eb', 'MASTER_QEMU/crypto/secret.c': 'edd3cb118753d5651baac7be0bf7baec8a0d2686a0f17892116a1fc603a00650', 'MASTER_QEMU/crypto/secret_common.c': '3807b8fce266b849515e6fdf88bcaf6b10f9935fd0c93ebe20627f05a8d4a3de', 'MASTER_QEMU/qapi/crypto.json': 'f7056cf09b8e47690acd531e4f280e681f41a9f23a261703696e968b4e44853c', 'PF1': '887ac86830b7b75004c12baf9a02502a80f1fc0c326cd2c2090821acb77d61a8', 'QAIO': '976bfc8deb2e888805184d84a7452bc7dc3310d89b95f62923e00cac71c21ed9', 'QAPI': '22b1d036051344b7d3d13efe6d10da249e36c10ac31139f01a5635b80a001e98', 'QB': 'ff92b23632d0a43b55da99c1d81a24c97eadd10368a14010543562547bd3e2b3', 'QBACK': '6ecbe68523d2eec780792b3dc7dbf7736f4dcb52ef9e8728f5fd3fd5633b5877', 'QBJ': 'c5c85852aa1697fd3330a174938464d1fa33e7a516b5765d60da21901a0c8463', 'QC': '5c32e63cfd0a2330709dad76374b862ac22ccd8952f473e7ead80365668ae513', 'QCS': '3e7055ef8d41dacd422291c6db3a589d9376688c3b69e23dec5c9e9aabba91d3', 'QDEV': '8576ce411d38750a9ef59af14f2ed165b7dc78e3094e7713b52ebf2067d0f35f', 'QEMU_OBJECT/backends/hostmem-ram.c': '1eed956ce437f286b9fe3f0677b165f23d25898129b6ea2de8f857f04850a08b', 'QEMU_OBJECT/backends/hostmem.c': '785258c441c0691978eb30e22a4ebae1b7a87e682adb8de06b3942a37a7aabd1', 'QEMU_OBJECT/backends/rng-random.c': '01944d4e40326e016388bf27bacb8ffcc90b2e0eefe841d3e3ae73444b7389cc', 'QEMU_OBJECT/hw/core/machine.c': '189c891714f0928cdd6648f7d2799b529029345a4c47fcf1fc92adb01a9d6e27', 'QEMU_OBJECT/include/system/hostmem.h': 'be5a95acbc1dfcfc61edbc7fa883c5498b77ea70858aada071f4283f1e6f42bd', 'QEMU_OBJECT/qapi/qom.json': 'cd63b7670b98d9c7ed1ca14786e427d9d852f8da87f9604f5c9125fb6d9ab199', 'QF': '970575234caffc506bcb7fb320ff5de2837c673f0d6495d744e1bf28a94d5a4d', 'QI': '80fb427d344317aaacce4c5670915d7a9e6d11abdd226fcf7ef795a76e55b6c1', 'QJAPI': 'd4691cad6d4ef116666964820670b5995a9b022b1a61707cdd282bf033fe2c06', 'QJOB': '2bbd9b8b3cc0c4634ebb9118d57eb79aa2e748ea2038ac4ec27bee01a5b6eac4', 'QLOCK': '0b1a4c2e45b7b8b5720458f9b853a59bee1c07cdf7102051fd1f0ef78c3923f0', 'QQ': 'b3bec38007548d323ee891ff8adf0b326731ec20f79f214bd03335761b915fea', 'QRAW': '93c375a7679cbbc655208fb2936307390c6379dacdc1a3d34aaaedae488aa2d8', 'QSN': '332aec8138f7cdb832ee225038d556e215e1b44f7df28d64d98f46fb0a6bc50d', 'QUR': 'fa18ab5687bfd2a5f7b263bc6edb42988ef7e72bff5cb2ab981d4c23c62f25e9'}
