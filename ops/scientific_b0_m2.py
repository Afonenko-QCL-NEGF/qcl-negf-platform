"""Retained Linux S native registry, exact M2 addendum1/correction1.

No scientific equations, controller issuer, HDF imports or observer callbacks.
Root descriptors and pinned kit source establish the trusted-source boundary;
worker JSON is a request/locator, never an actual measurement or new allowance.
"""
from dataclasses import asdict
import ctypes
import fcntl
import hashlib
import mmap
import os
import resource
import signal
import socket
import stat
import struct
import sys
import time

from scientific_b0_provider import (Budget, Settlement, ProviderRefusal, NativeDelegation,
    DomainProof,_need, _uint, _plus, _fits, _SEALS, partition_budget, seal_job_capsule)
from scientific_b0_site import (canonical, decode, exact, digest, token, read_fd,
    root_file, live_identity, _secondary, DescriptorCustody)

SCHEMA = 'qcl.b0.m2.registration.addendum1.correction2'
ADDENDUM = '415506d14d436e2d0c2913049f5e8ead0a91500130a728d3ffd2b82502b1106d'
CORRECTION = '629548eed5e203236f9bf30175e089267f3f2c67723983a78b31755365a5eea3'
CAPACITY_CORRECTION = 'bed3d83069908fac290891782027af767454462398748c9d41d4fb83074e73e1'
DIGEST_CODEC = '2b2831a9b5ed4fc8ca2745f49145ec3ae28db9851dc3aecb8c4a572cc12a65f1'
PACKET = 65536
MAX_FILES = 64
MAX_SCOPES = 1024
DIMS = ('read', 'write', 'log', 'resident', 'allocated_bytes', 'inodes', 'calls',
        'scopes', 'wall_ns', 'memory', 'cpu_ns')
OPS = frozenset(('open', 'read', 'write', 'pread', 'pwrite', 'seek', 'stat', 'sync', 'chmod',
    'mkdir', 'temp', 'rename_from', 'rename_to', 'unlink', 'dirsync', 'fadvise', 'seal',
    'mmap_ro', 'munmap', 'close'))
KINDS = frozenset(('capture_publication', 'text', 'hash_read', 'history', 'terminal', 'stop', 'bootstrap'))
FILE_KEYS = ('file_id', 'kind', 'root_index', 'name', 'access', 'acquire', 'state', 'fd_index',
    'expected_dev', 'expected_ino', 'expected_mode', 'initial_extent', 'max_extent',
    'max_opens', 'max_calls', 'create_mode', 'publish_mode', 'seals', 'allowed_ops', 'rename_targets')
FD_KEYS = ('index', 'role', 'dev', 'ino', 'access', 'length', 'domain_id', 'file_id')
GRANT_KEYS = ('abi', 'capsule_digest', 'operation_id', 'delegate_id', 'index', 'grant_sequence',
    'worker_identity_digest', 'issuer_identity_digest', 'authority_epoch', 'counter_epoch',
    'clock_domain', 'deadline_ns', 'profile_digest', 'descriptor_digest', 'payload_binding_digest',
    'native_kit_digest', 'kind', 'role', 'bound', 'native_limits', 'files', 'fd_table', 'stop_binding_digest')
ACCESS = dict(read=os.O_RDONLY, write=os.O_WRONLY, read_write=os.O_RDWR,
              append=os.O_WRONLY, directory=os.O_RDONLY)
F_FUTURE = getattr(fcntl, 'F_SEAL_FUTURE_WRITE', 0x10)
IDENTITY_KEYS = ('campaign','plan','execution','attempt','point','source','admission','operation','generation')
DOMAIN_KEYS = ('filesystem','namespace','boot','ownership','parent','binding')
INV_KEYS = ('identity','domain','writer','digest','payload_digest','stop_reference','logical','physical','inodes','slots')


def hexid(value):
    _need(type(value) is str and len(value) == 32 and all(c in '0123456789abcdef' for c in value), 'invalid native ID')
    return value


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def epoch_sha(value):
    _need(type(value) is str and '\0' not in value,'invalid epoch')
    try:
        raw=value.encode('utf-8',errors='strict')
    except UnicodeError as error:
        raise ProviderRefusal('invalid epoch UTF-8') from error
    _need(0<len(raw)<=1024,'invalid epoch byte length')
    return hashlib.sha256(raw).digest()


def triple(values):
    _need(type(values) in (list,tuple) and len(values) == 3, 'resident triple required')
    return tuple(_uint(value) for value in values)


def vadd(a,b):
    return tuple(_uint(x+y) for x,y in zip(a,b))


def vsub(a,b):
    _need(all(x >= y for x,y in zip(a,b)), 'resident subtraction underflow')
    return tuple(x-y for x,y in zip(a,b))


def within(a,b):
    return all(x <= y for x,y in zip(a,b))


def object_facts(info):
    return dict(dev=info.st_dev,ino=info.st_ino,mode=info.st_mode,extent=info.st_size,
                allocated=info.st_blocks*512,nlink=info.st_nlink,mtime_ns=info.st_mtime_ns,
                ctime_ns=info.st_ctime_ns)


def native_vector(bound, limits):
    budget = Budget(**exact(bound, tuple(Budget.__dataclass_fields__)))
    exact(limits, ('allocated_bytes','cpu_ns'))
    values = dict(asdict(budget), allocated_bytes=_uint(limits['allocated_bytes']), cpu_ns=_uint(limits['cpu_ns']))
    return tuple(values[name] for name in DIMS)


def round_page(value, page):
    _need(type(page) is int and page > 0 and page & (page-1) == 0, 'qualified page size')
    return _uint((_uint(value)+page-1)//page*page)


def basename(value):
    _need(type(value) is str and value not in ('','.','..') and '/' not in value and '\0' not in value,
          'exact basename required')
    try:
        raw = value.encode('ascii')
    except UnicodeError as error:
        raise ProviderRefusal('ASCII basename required') from error
    _need(0 < len(raw) <= 255, 'basename bound')
    return value


def validate_files(files, fd_table=None):
    _need(type(files) is list and len(files) <= MAX_FILES, 'native file table bound')
    ids = set()
    for index,row in enumerate(files):
        exact(row,FILE_KEYS); fid=hexid(row['file_id'])
        _need(fid not in ids,'duplicate file slot'); ids.add(fid)
        kind,acquire,state=row['kind'],row['acquire'],row['state']
        _need(kind in ('regular','directory','snapshot','capture_metadata') and
              state in ('existing','not_acquired') and row['access'] in (*ACCESS,'none'), 'file kind/state/access')
        root=row['root_index']
        if root is not None:
            _need(_uint(root) < index and files[root]['kind']=='directory','cyclic/unregistered parent')
        if row['name'] is None:
            _need(kind=='directory' and root is None and acquire=='inherit_fd','missing file basename')
        else:
            basename(row['name'])
        allowed=row['allowed_ops']; targets=row['rename_targets']
        _need(type(allowed) is list and len(allowed)==len(set(allowed)) and set(allowed)<=OPS,
              'unknown/duplicate native operation')
        _need(type(targets) is list and len(targets)==len(set(targets)), 'rename target set')
        for target in targets:
            _need(_uint(target)<len(files) and target!=index and 'rename_from' in allowed and
                  files[target]['root_index']==root,'unapproved rename pair')
        for name in ('max_extent','max_opens','max_calls'):
            _uint(row[name])
        _need(row['max_calls']>0 and ('rename_from' in allowed or not targets), 'file call/pair bound')
        if state=='existing':
            for name in ('expected_dev','expected_ino','expected_mode','initial_extent'):
                _uint(row[name])
            _need(row['expected_ino']>0 and row['expected_mode']<=0o7777 and
                  row['initial_extent']<=row['max_extent'],'existing file extent/mode/identity')
        else:
            _need(all(row[name] is None for name in ('expected_dev','expected_ino','expected_mode','initial_extent')),
                  'future object cannot have fabricated identity')
        _need(row['seals']==('full_before_read' if kind in ('snapshot','capture_metadata') else 'none'),
              'file seal policy')
        create=acquire in ('create_exclusive','mkdir_exclusive','memfd_new')
        _need((type(row['create_mode']) is int and 0<=row['create_mode']<=0o7777) if create else
              row['create_mode'] is None, 'create mode policy')
        _need((type(row['publish_mode']) is int and 0<=row['publish_mode']<=0o7777) if 'chmod' in allowed else
              row['publish_mode'] is None, 'publish mode policy')
        if acquire=='inherit_fd':
            _need(state=='existing' and row['fd_index'] is not None,'inherited descriptor binding')
            _uint(row['fd_index'])
        elif acquire=='open_existing':
            _need(state=='existing' and root is not None and row['fd_index'] is None and
                  kind in ('regular','directory'),'existing child binding')
        elif acquire=='create_exclusive':
            _need(state=='not_acquired' and kind=='regular' and root is not None and row['fd_index'] is None,
                  'exclusive create binding')
        elif acquire=='mkdir_exclusive':
            _need(state=='not_acquired' and kind=='directory' and root is not None and row['fd_index'] is None,
                  'exclusive mkdir binding')
        elif acquire=='memfd_new':
            _need(state=='not_acquired' and kind in ('snapshot','capture_metadata') and root is None and
                  row['fd_index'] is None,'anonymous acquisition binding')
        elif acquire=='path_only':
            _need(state=='existing' and root is not None and row['fd_index'] is None and
                  row['access']=='none' and kind in ('regular','directory'),'path-only binding')
        else:
            raise ProviderRefusal('unknown acquire policy')
        if row['access']=='append':
            _need(not {'pwrite','seek'} & set(allowed),'append rewrite forbidden')
        if fd_table is not None and acquire=='inherit_fd':
            _need(row['fd_index']<len(fd_table) and fd_table[row['fd_index']]['file_id']==fid,
                  'file/fd namespaces mismatch')
    return files


def inventory(row, depth=0):
    _need(depth<=32,'resident subtree depth'); exact(row,INV_KEYS)
    exact(row['identity'],IDENTITY_KEYS); exact(row['domain'],DOMAIN_KEYS)
    _uint(row['identity']['generation'])
    for name,value in row['identity'].items():
        if name!='generation':
            _need(type(value) is str and 0<len(value)<=1024,'resident identity')
    for value in row['domain'].values():
        _need(type(value) is str and 0<len(value)<=4096,'storage domain')
    parent=row['domain']['parent']
    _need(parent.startswith('/') and '..' not in parent.split('/'),'storage parent locator')
    digest(row['digest']); digest(row['payload_digest'])
    _need(type(row['writer']) is str and type(row['stop_reference']) is str,'writer/STOP reference')
    bound=triple([row['logical'],row['physical'],row['inodes']])
    _need(type(row['slots']) is list and len(row['slots'])<=MAX_SCOPES,'resident slot bound')
    total=(0,0,0)
    for child in row['slots']:
        part=inventory(child,depth+1)
        _need(child['identity']==row['identity'] and child['domain']==row['domain'], 'resident child domain')
        total=vadd(total,part)
    _need(within(total,bound),'resident child partition exceeds parent')
    return bound


class AtomicObserver:
    def __init__(self, path, expected):
        _need(path.startswith('/nix/store/'),'immutable supervisor atomic helper required')
        fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
        try:
            info=os.fstat(fd); raw=read_fd(fd,8<<20)
            _need(info.st_uid==0 and info.st_mode&0o022==0 and sha(raw)==digest(expected),
                  'supervisor atomic helper changed')
        finally:
            os.close(fd)
        self.lib=ctypes.CDLL(path,use_errno=True)
        for name,restype,args in (
            ('qcl_b0_s_atomic_qualified',ctypes.c_int,[ctypes.c_void_p]),
            ('qcl_b0_s_load32',ctypes.c_uint32,[ctypes.c_void_p]),
            ('qcl_b0_s_load64',ctypes.c_uint64,[ctypes.c_void_p]),
            ('qcl_b0_s_store32',None,[ctypes.c_void_p,ctypes.c_uint32]),
            ('qcl_b0_s_store64',None,[ctypes.c_void_p,ctypes.c_uint64]),
            ('qcl_b0_s_acquire_fence',None,[])):
            fn=getattr(self.lib,name); fn.restype=restype; fn.argtypes=args
        self.lib.qcl_b0_s_map_ro.restype=ctypes.c_void_p
        self.lib.qcl_b0_s_map_ro.argtypes=[ctypes.c_int,ctypes.c_size_t]
        self.lib.qcl_b0_s_unmap.restype=ctypes.c_int
        self.lib.qcl_b0_s_unmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
    def pointer(self,mapping,offset=0):
        return ctypes.addressof(ctypes.c_ubyte.from_buffer(mapping,offset))
    def store32(self,mapping,offset,value):
        self.lib.qcl_b0_s_store32(self.pointer(mapping,offset),value)
    def store64(self,mapping,offset,value):
        self.lib.qcl_b0_s_store64(self.pointer(mapping,offset),value)
    def load32(self,mapping,offset):
        return self.lib.qcl_b0_s_load32(self.pointer(mapping,offset))
    def load64(self,mapping,offset):
        return self.lib.qcl_b0_s_load64(self.pointer(mapping,offset))


class Carrier:
    def __init__(self, registry, label, length, raw=b'', control=False, immutable=False):
        self.registry=registry; self.mapping=None; self.read_mapping=None; self.seal_attempted=False
        self.unknown_mappings={}
        self.native_read_pointer=None
        self.fd=None; self.read_fd=None
        _need(len(registry.carriers)<MAX_SCOPES*2+1,'bounded carrier resource capacity')
        registry.carriers.append(self)  # exact S owner before acquisition/assignment
        fd=os.memfd_create(label,os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC)
        registry.owner.adopt((fd,)); self.fd=fd
        os.ftruncate(fd,length)
        if raw:
            _need(len(raw)<=length,'carrier content exceeds admitted extent')
            offset=0
            while offset<len(raw):
                count=os.pwrite(fd,raw[offset:],offset); _need(count>0,'carrier short write'); offset+=count
        self.length=length; self.info=os.fstat(fd)
        if control:
            self.mapping=mmap.mmap(fd,length,flags=mmap.MAP_SHARED,prot=mmap.PROT_READ|mmap.PROT_WRITE)
            _need(registry.atomic.lib.qcl_b0_s_atomic_qualified(registry.atomic.pointer(self.mapping)),
                  'lock-free aligned native atomics unavailable')
            fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|F_FUTURE|fcntl.F_SEAL_SEAL)
        else:
            seals=fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK
            if immutable:
                seals|=fcntl.F_SEAL_WRITE|fcntl.F_SEAL_SEAL
            fcntl.fcntl(fd,fcntl.F_ADD_SEALS,seals)
        self.read_fd=os.open('/proc/self/fd/'+str(fd),os.O_RDONLY|os.O_CLOEXEC)
        registry.owner.adopt((self.read_fd,))
        read_info=os.fstat(self.read_fd)
        _need((read_info.st_dev,read_info.st_ino)==(self.info.st_dev,self.info.st_ino),'carrier readonly reopen changed object')
        # Actual O_RDONLY file description, not PROT_READ atop O_RDWR.
        _need(fcntl.fcntl(self.read_fd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY,'carrier readonly description')
        if not immutable and not control:
            self.native_read_pointer=registry.atomic.lib.qcl_b0_s_map_ro(self.read_fd,length)
            _need(self.native_read_pointer is not None,'actual S readonly native mapping failed')
            _need(registry.atomic.lib.qcl_b0_s_atomic_qualified(self.native_read_pointer),
                  'counter atomic alignment/lock-free observation unavailable')

    def seal_terminal(self):
        _need(not self.seal_attempted,'counter seal is one-shot')
        self.seal_attempted=True
        fcntl.fcntl(self.fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_SEAL)
        _need(fcntl.fcntl(self.fd,fcntl.F_GET_SEALS)&_SEALS==_SEALS,'counter final seal unknown')
        return self.bytes()

    def bytes(self):
        before=os.fstat(self.read_fd)
        _need((before.st_dev,before.st_ino,before.st_size)==(self.info.st_dev,self.info.st_ino,self.length),
              'retained carrier changed')
        raw=os.pread(self.read_fd,self.length+1,0)
        _need(len(raw)==self.length,'carrier read extent')
        return raw


def header(magic, length, registry, operation=None, delegate=None, sequence=0):
    raw=bytearray(320)
    struct.pack_into('<8sIIQQ',raw,0,magic,1,1 if magic==b'QCLB0CT1' else 2,length,1)
    raw[32:64]=bytes.fromhex(registry.capsule.digest)
    raw[64:96]=bytes.fromhex(registry.site.intent['native_kit'])
    raw[96:128]=bytes.fromhex(registry.worker_digest)
    raw[128:160]=epoch_sha(registry.config['authority_epoch'])
    raw[160:192]=epoch_sha(registry.config['counter_epoch'])
    raw[192:224]=epoch_sha(registry.config['clock_domain'])
    raw[224:240]=bytes.fromhex(operation) if operation else bytes(16)
    raw[240:256]=bytes.fromhex(delegate) if delegate else bytes(16)
    struct.pack_into('<QQQQ',raw,256,sequence,registry.site.worker.pid,
                     registry.site.worker.start_ticks,registry.capsule.deadline_ns)
    return raw


def counter_length(files, page, capture=False, snapshots=0):
    _need(type(files) is int and 0<=files<=MAX_FILES and
          snapshots==(1 if capture else 0),'counter native cardinality')
    transfer=168+16*snapshots if capture else 0
    return round_page(_uint(832+96*files+8+transfer+files),page)


def parse_counter(raw, grant, page, capture=False):
    """Exact readonly coherent carrier codec; F1 stripe is not zero padding."""
    _need(len(raw)>=840,'counter truncated')
    _need(raw[:8]==b'QCLB0CN1' and struct.unpack_from('<II',raw,8)==(1,2),'counter magic/ABI')
    _need(struct.unpack_from('<Q',raw,16)[0]==len(raw),'counter total length')
    sequence,effect,state,refs=struct.unpack_from('<QQII',raw,320)
    _need(sequence%2==0 and state in range(6),'counter torn/state')
    requested=struct.unpack_from('<11Q',raw,344)
    actual=struct.unpack_from('<11Q',raw,432)
    outstanding=struct.unpack_from('<11Q',raw,520)
    unknown=struct.unpack_from('<Q',raw,608)[0]
    count=struct.unpack_from('<Q',raw,824)[0]
    _need(count==len(grant['files']) and count<=MAX_FILES,'counter file cardinality')
    rows=[]
    for index in range(count):
        offset=832+96*index
        _need(offset+96<=len(raw),'counter file extent')
        fid=raw[offset:offset+16].hex(); values=struct.unpack_from('<10Q',raw,offset+16)
        _need(fid==grant['files'][index]['file_id'],'counter file ID substitution')
        rows.append(dict(file_id=fid,dev=values[0],ino=values[1],logical_extent=values[2],
            allocated_bytes=values[3],opens_requested=values[4],opens_actual=values[5],
            syscalls_requested=values[6],syscalls_actual=values[7],read_actual=values[8],write_actual=values[9]))
    cursor=832+96*count
    _need(cursor+8<=len(raw),'counter custody length')
    transfers=struct.unpack_from('<Q',raw,cursor)[0]; cursor+=8
    region_start=cursor
    reserved=184 if capture else 0
    _need(transfers<=(1 if capture else 0),'undeclared custody transfer')
    if capture:
        _need(grant['kind']=='capture_publication' and
              sum(row['kind']=='snapshot' and row['acquire']=='memfd_new' for row in grant['files'])==1 and
              sum(row['kind']=='capture_metadata' and row['acquire']=='memfd_new' for row in grant['files'])==1,
              'capture capacity/profile/file discriminator')
    if not transfers:
        _need(not any(raw[cursor:cursor+reserved]),'nonzero unused capture transfer region')
    custody=[]
    for _ in range(transfers):
        _need(cursor+80<=len(raw),'transfer truncated')
        snapshots=struct.unpack_from('<Q',raw,cursor+72)[0]
        _need(snapshots==1 and cursor+184<=len(raw),'transfer snapshot bound')
        end=cursor+168+16*snapshots; body=raw[cursor:end]
        tail=80+16*snapshots
        record=dict(capsule_digest=body[:32].hex(),operation_id=body[32:48].hex(),
            capture_delegate_id=body[48:64].hex(),capture_token=struct.unpack_from('<Q',body,64)[0],
            snapshot_file_ids=[body[80+16*i:96+16*i].hex() for i in range(snapshots)],
            metadata_file_id=body[tail:tail+16].hex(),source_counter_id=body[tail+16:tail+32].hex(),
            source_effect_sequence=struct.unpack_from('<Q',body,tail+32)[0],
            destination_child_index=struct.unpack_from('<Q',body,tail+40)[0],
            logical_bytes=struct.unpack_from('<Q',body,tail+48)[0],
            allocated_bytes=struct.unpack_from('<Q',body,tail+56)[0],
            mapping_bytes=struct.unpack_from('<Q',body,tail+64)[0],transfer_nonce=body[tail+72:tail+88].hex())
        _need(record['transfer_nonce']==sha(body[:-16])[:32],'transfer nonce not canonical primitive hash')
        _need(record['capsule_digest']==grant['capsule_digest'] and record['operation_id']==grant['operation_id'] and
              record['capture_delegate_id']==grant['delegate_id'] and record['source_counter_id']==grant['delegate_id'] and
              record['source_effect_sequence']==effect,'transfer identity/sequence mismatch')
        custody.append(record); cursor=end
    cursor=region_start+reserved
    _need(cursor+count<=len(raw),'missing acquisition stripe')
    for row,validity in zip(rows,raw[cursor:cursor+count]):
        _need(validity<=4,'invalid acquisition state')
        row['state']=validity
        if validity in (0,1,4):
            _need(not any(row[key] for key in ('dev','ino','logical_extent','allocated_bytes')),
                  'invalid observation fields must have canonical zero storage')
        else:
            _need(row['ino']>0,'known object inode policy')
        _need(row['opens_actual']<=row['opens_requested'] and row['syscalls_actual']<=row['syscalls_requested'],
              'native actual calls exceed requested')
    cursor+=count
    _need(round_page(cursor,page)==len(raw) and not any(raw[cursor:]),'counter stripe/length/padding')
    bound=native_vector(grant['bound'],grant['native_limits'])
    _need(within(requested,bound) and within(actual,requested) and requested[2]<=requested[1],
          'native requested/actual exceeds delegate')
    _need(raw[32:64].hex()==grant['capsule_digest'] and raw[64:96].hex()==grant['native_kit_digest'] and
          raw[96:128].hex()==grant['worker_identity_digest'] and raw[224:240].hex()==grant['operation_id'] and
          raw[240:256].hex()==grant['delegate_id'],'counter header binding')
    for offset,name in ((128,'authority_epoch'),(160,'counter_epoch'),(192,'clock_domain')):
        _need(raw[offset:offset+32]==epoch_sha(grant[name]),'counter epoch changed')
    _need(struct.unpack_from('<Q',raw,256)[0]==grant['grant_sequence'] and
          struct.unpack_from('<Q',raw,280)[0]==grant['deadline_ns'] and not any(raw[304:320]),'counter sequence/reserved')
    return dict(seqlock=sequence,effect_sequence=effect,state=state,refs=refs,requested=requested,
                actual=actual,outstanding=outstanding,unknown=unknown,files=rows,custody=custody,
                first_status=struct.unpack_from('<I',raw,616)[0])


class NativeRegistry:
    """The same S allowance/claim, retained carriers and resident projection.

    All manifest/profile values originate in protected Root admission. No callback
    observes a file, scheduler, native counter or grants a scientific permit.
    """
    def __init__(self,site,config):
        self.site,self.owner,self.config=site,site.custody.owner,config
        self.carriers=[]
        self.owner.retain_resource('native-registry',self)
        _need(os.listdir('/proc/self/task')==[str(os.getpid())], 'one retained native S task required')
        exact(config,('registration_schema','addendum_sha256','correction_sha256','capacity_correction_sha256','digest_codec_sha256','header_path','header_sha256',
            'library_path','library_sha256','library_identity','observer_path','observer_sha256',
            'authority_epoch','counter_epoch','clock_domain','page_size','fd_capacity','native_limits',
            'profiles','storage','stop_profile','tail_bound','scalar_codes','observer_bound','observer_limits',
            'observer_stop_bound','observer_stop_limits','dispatch_bounds'))
        _need(config['registration_schema']==SCHEMA and config['addendum_sha256']==ADDENDUM and
              config['correction_sha256']==CORRECTION and config['capacity_correction_sha256']==CAPACITY_CORRECTION and
              config['digest_codec_sha256']==DIGEST_CODEC,
              'native registration version/pins')
        _need(sys.byteorder=='little' and struct.calcsize('P')==8,'qualified Linux64 little-endian required')
        # One Root-preconsumed disjoint S observer/setup partition; no slab or
        # worker request creates observer allowance. The closed dispatch cost
        # table is part of the pinned source/native producer manifest.
        self.observer_total=native_vector(config['observer_bound'],config['observer_limits'])
        self.observer_stop=native_vector(config['observer_stop_bound'],config['observer_stop_limits'])
        self.observer_used=(0,)*11; self.observer_stop_used=(0,)*11
        self.site._ledger.reserve(Budget(**config['observer_bound']))
        self.page=os.sysconf('SC_PAGE_SIZE')
        _need(_uint(config['page_size'])==self.page,'actual native page size changed')
        for path_key,sha_key in (('header_path','header_sha256'),('library_path','library_sha256')):
            path=config[path_key]; _need(type(path) is str and path.startswith('/nix/store/'),'immutable kit path')
            fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
            try:
                info=os.fstat(fd)
                _need(info.st_uid==0 and info.st_mode&0o022==0 and sha(read_fd(fd,32<<20))==digest(config[sha_key]),
                      'native kit source/ELF changed')
                if path_key=='library_path':
                    _need((info.st_dev,info.st_ino)==tuple(config['library_identity']),'native ELF identity')
            finally:
                os.close(fd)
        cap=_uint(config['fd_capacity'])
        _need(256<=cap<=256+MAX_SCOPES*(MAX_FILES+6) and resource.getrlimit(resource.RLIMIT_NOFILE)[0]>=cap,
              'finite admitted S descriptor capacity')
        self.owner.capacity=cap
        self.atomic=AtomicObserver(config['observer_path'],config['observer_sha256'])
        self.control=None; self.capsule=None; self.worker_digest=None
        self.operations={}; self.delegates={}; self.candidates={}; self.leases={}; self.objects={}; self.transfers={}
        self.observation=0; self.revision=0; self.grant_sequence=0; self.operation_sequence=0; self.generation=0
        self.stop_request=None; self.last_verified=None; self.final_receipt=None
        self.normal_vector=self.observer_total
        self.stop_vector=native_vector(config['stop_profile']['bound'],config['stop_profile']['native_limits'])
        self._validate_profiles()
        expected_codes={}
        for code,size in enumerate((8,16,8,8,1,1,8),1):
            encoded=b'\x04'+struct.pack('<Q',2)+b'\x03'+struct.pack('<Q',1)+b'\x03'+struct.pack('<Q',code)
            expected_codes[str(code)]=dict(type_code=encoded.hex(),bytes=size)
        _need(config['scalar_codes']==expected_codes,'source3 tensor scalar/type-code ABI changed')

    def _validate_profiles(self):
        _need(type(self.config['profiles']) is dict and self.config['profiles'],'approved native producer graph missing')
        _need(len(self.config['profiles'])<=MAX_SCOPES,'approved native registry capacity')
        all_stop=self.observer_stop
        exact(self.config['stop_profile'],('digest','bound','native_limits','stop_id','ack_file_id','bindings'))
        digest(self.config['stop_profile']['digest'])
        for profile_digest,profile in self.config['profiles'].items():
            digest(profile_digest)
            exact(profile,('kind','descriptor','storage_id','stop_ids','commit_files','required_files','root_indices','stop_ack'))
            _need(profile['kind'] in KINDS,'unknown producer family')
            self._descriptor(profile['descriptor'])
            for child in profile['descriptor']['delegates']:
                if child['role']=='stop':
                    all_stop=vadd(all_stop,native_vector(child['bound'],child['native_limits']))
            _need(profile['descriptor']['profile_digest']==profile_digest,'profile digest substitution')
            storage=self._storage(profile['storage_id'])
            _need(profile['descriptor']['resident']['inventory']['domain']==storage['domain'],'profile storage binding')
            _need(type(profile['root_indices']) is dict and type(profile['stop_ids']) is list,'profile roots/STOP IDs')
            for fid,index in profile['root_indices'].items():
                hexid(fid); _need(_uint(index)<len(self.site.custody.directory_fds),'root descriptor index')
        _need(within(all_stop,self.stop_vector),'preissued STOP native partitions overlap/exceed global reservation')
        for storage in self.config['storage']:
            exact(storage,('id','kind','identity','domain','E','P','S','A','H','protected','root_index','stop_entries','baseline_ref','consumers'))
            inventory_domain=storage['domain']; exact(inventory_domain,DOMAIN_KEYS); exact(storage['identity'],IDENTITY_KEYS)
            for key in ('E','P','S','A','H','protected'):
                triple(storage[key])
            _need(storage['kind'] in ('fixed_thick','memory_snapshot'),'native storage backend kind')
            if storage['kind']=='fixed_thick':
                _need(_uint(storage['root_index'])<len(self.site.custody.directory_fds),'storage root index')
                adopted=[row for row in self.site.admission['domains'] if row['domain']==storage['id']]
                _need(len(adopted)==1 and adopted[0]['root_index']==storage['root_index'],
                      'storage ledger is not the native adopted backing')
            else:
                _need(storage['root_index'] is None,'memory snapshot is not a block root')
            _need(type(storage['stop_entries']) is dict,'STOP entries must be named disjoint IDs')
            summed=(0,0,0)
            for sid,value in storage['stop_entries'].items():
                hexid(sid); summed=vadd(summed,triple(value))
            _need(summed==triple(storage['S']),'STOP resident partition')
        _need(sum(row['kind']=='memory_snapshot' for row in self.config['storage'])==1,
              'exact native memory snapshot domain required')
        _need(len({row['id'] for row in self.config['storage']})==len(self.config['storage']),
              'duplicate native storage ledger ID')

    def _memory(self):
        observed=self.site._cgroup_readback()
        cgroups=self.site.admission['cgroups']; limits=[]; currents=[]
        from scientific_b0_site import cgroup_of
        spath=cgroup_of(self.site.issuer.pid); cpath=self.site.admission['scheduler']['cgroup']
        for row,facts in zip(cgroups,observed):
            path=row['path']
            applicable=path=='/' or ((spath==path or spath.startswith(path+'/')) and
                                     (cpath==path or cpath.startswith(path+'/')))
            if applicable and facts['memory.max'].isdigit():
                limits.append(int(facts['memory.max'])); currents.append(int(facts['memory.current']))
                _need(facts['memory.swap.max']=='0','snapshot swap backing not adopted')
        _need(limits and 0<min(limits)<=128*1024**3,'finite S+C memory enclosure missing')
        return min(limits),max(currents)

    def memory_proof(self):
        capacity,current=self._memory()
        storage=next(row for row in self.config['storage'] if row['kind']=='memory_snapshot')
        ref=sha(canonical(dict(boot=self.site.issuer.boot,capacity=capacity,
                              cgroups=self.site.admission['cgroups'],fd_capacity=self.owner.capacity)))
        return DomainProof(storage['id'],('memory-cgroup',self.site.issuer.boot,self.site.issuer.cgroup_namespace),
            'memory_snapshot',capacity,self.owner.capacity,self.site.issuer.mount_namespace,
            tuple(storage['consumers']),'native-memory:'+ref)

    def capture(self,args,rights):
        return verify_capture_immutable(self,args,rights)

    def capture_descriptor(self,descriptor):
        profile=self._profile(descriptor.profile_digest)
        expected=profile['descriptor']
        _need(expected['digest']==descriptor.digest and
              canonical(expected['shape_type_bytes'])==canonical(descriptor.shape_type_bytes) and
              expected['inclusive']==asdict(descriptor.inclusive) and
              [row['bound'] for row in expected['delegates']]==[asdict(row) for row in descriptor.delegates] and
              expected['capture_index']==descriptor.capture_index,'capture/native descriptor mismatch')
        result=self.current(dict(digest=self.capsule.digest,projection=dict(action='snapshot',
            profile_digest=descriptor.profile_digest,inventory=expected['resident']['inventory'])))
        copied=decode(canonical(expected))
        copied['resident']['expected_revision']=result['projection']['data']['revision']
        return copied

    def freeze(self,primary):
        return _freeze(self,primary)

    def stop(self,args):
        return _stop_pending(self,args)

    def observe_terminal(self,status):
        return _observe_terminal(self,status)

    def close_mappings(self):
        return _close_mappings(self)

    def _descriptor(self,descriptor):
        exact(descriptor,('digest','profile_digest','shape_type_bytes','inclusive','delegates','capture_index',
                          'native_limits','files','resident'))
        digest(descriptor['digest']); digest(descriptor['profile_digest'])
        parent=native_vector(descriptor['inclusive'],descriptor['native_limits'])
        validate_files(descriptor['files'])
        exact(descriptor['resident'],('expected_revision','inventory'))
        inventory(descriptor['resident']['inventory'])
        _need(type(descriptor['delegates']) is list and 0<len(descriptor['delegates'])<=MAX_SCOPES,
              'native delegate partition')
        total=(0,)*11
        for child in descriptor['delegates']:
            exact(child,('bound','native_limits','files','kind','role','payload_binding_digest','scope_digest'))
            _need(child['kind'] in KINDS and child['role'] in ('normal','stop'),'child kind/role')
            digest(child['scope_digest'])
            if child['payload_binding_digest'] is not None:
                digest(child['payload_binding_digest'])
            validate_files(child['files']); total=vadd(total,native_vector(child['bound'],child['native_limits']))
        _need(within(total,parent),'overlapping native child partition')
        if descriptor['capture_index'] is not None:
            _need(_uint(descriptor['capture_index'])<len(descriptor['delegates']),'capture child index')
        for entry in descriptor['shape_type_bytes']:
            _need(type(entry) is list and len(entry)==6,'closed tensor descriptor row')
            path,dtype,shape,axes,offset,length=entry
            _need(type(path) is list and type(dtype) is int and 1<=dtype<=7 and
                  type(shape) is list and type(axes) is list and shape==axes and len(shape)<=8,
                  'tensor descriptor semantic path/dtype/shape')
            for count in shape:
                _uint(count)
            _uint(_uint(offset)+_uint(length))
        return descriptor

    def _storage(self,identity):
        rows=[row for row in self.config['storage'] if row['id']==identity]
        _need(len(rows)==1,'storage domain not uniquely admitted')
        return rows[0]

    def bind(self,capsule):
        _need(self.control is None and capsule==self.site.capsule,'native authority replay')
        self.capsule=capsule; self.worker_digest=sha(canonical(asdict(self.site.worker)))
        total=native_vector(asdict(capsule.total),self.config['native_limits'])
        _need(within(vadd(self.normal_vector,self.stop_vector),total),'native observer/STOP exceeds consumed total')
        raw=header(b'QCLB0CT1',round_page(624,self.page),self)
        raw.extend(bytes(round_page(624,self.page)-len(raw)))
        struct.pack_into('<11Q',raw,320,*total)
        struct.pack_into('<11Q',raw,408,*self.normal_vector)
        struct.pack_into('<11Q',raw,496,*self.stop_vector)
        self.control=Carrier(self,'qcl-b0-control',len(raw),raw,control=True)
        self._native_process()

    def _native_process(self):
        _need(self.site.worker is not None and live_identity(self.site.worker.pid)==self.site.worker,
              'native worker identity changed')
        with open('/proc/'+str(self.site.worker.pid)+'/maps','rb') as stream:
            raw=stream.read((1<<20)+1)
        _need(len(raw)<=1<<20,'native mapping observation cap')
        expected=tuple(self.config['library_identity']); found=False
        for line in raw.decode('utf-8').splitlines():
            parts=line.split(None,5)
            if len(parts)==6 and parts[5]==self.config['library_path'] and 'x' in parts[1]:
                dev=parts[3].split(':')
                actual=os.makedev(int(dev[0],16),int(dev[1],16))
                found=found or (actual,int(parts[4]))==expected
        _need(found,'qualified native kit not mapped by actual C')

    def _fresh(self,normal=True):
        _need(self.control is not None and time.monotonic_ns()<self.capsule.deadline_ns,'native registry stale')
        self.site.issuer_identity(); self._native_process(); self.site._cgroup_readback()
        self.site._scheduler(self.site.worker)
        if normal:
            _need(self.site.primary is None,'native normal grants frozen')
        self.observation=_uint(self.observation+1)
        self.atomic.store64(self.control.mapping,584,self.observation)

    def dispatch_cost(self,opcode,args):
        costs=self.config['dispatch_bounds']
        _need(type(costs) is dict and opcode in costs,'S dispatch family not prebound')
        row=exact(costs[opcode],('bound','native_limits'))
        cost=native_vector(row['bound'],row['native_limits'])
        if self.site.primary is None:
            proposed=vadd(self.observer_used,cost)
            _need(within(proposed,self.observer_total),'S normal observer partition exhausted')
            self.observer_used=proposed
        else:
            proposed=vadd(self.observer_stop_used,cost)
            _need(within(proposed,self.observer_stop),'S STOP observer partition exhausted')
            self.observer_stop_used=proposed

    def _id(self,kind,sequence,extra=0):
        return sha(canonical(dict(capsule=self.capsule.digest,kind=kind,sequence=sequence,extra=extra)))[:32]

    def _capacity(self,storage,exclude_stop=()):
        usage=None
        if storage['kind']=='fixed_thick':
            root=self.site.custody.directory_fds[storage['root_index']]
            usage=os.fstatvfs(root)
        else:
            memory_max,memory_current=self._memory()
        E=triple(storage['E']); U=(0,0,0)
        for lease in self.leases.values():
            if lease['storage_id']==storage['id'] and lease['state'] in ('active','committed'):
                U=vadd(U,lease['native_remaining'])
        actual_E=list(E)
        if usage is not None:
            actual_E[1]=max(actual_E[1],(usage.f_blocks-usage.f_bfree)*usage.f_frsize)
            actual_E[2]=max(actual_E[2],usage.f_files-usage.f_ffree)
        else:
            actual_E[1]=max(actual_E[1],memory_current)
        for obj in self.objects.values():
            if obj['storage_id']==storage['id'] and not obj.get('retired',False):
                actual_E[0]=_uint(actual_E[0]+max(0,obj['accounted'][0]-obj['baseline_logical']))
        P=triple(storage['P']); S=(0,0,0)
        owned_stop={sid for lease in self.leases.values() if lease['state']!='released' for sid in lease['stop_ids']}
        for sid,value in storage['stop_entries'].items():
            if sid not in owned_stop and sid not in exclude_stop:
                S=vadd(S,triple(value))
        H=list(triple(storage['H'])); protected=triple(storage['protected'])
        if usage is not None:
            H[1]=min(H[1],max(0,usage.f_bavail*usage.f_frsize-protected[1]))
            H[2]=min(H[2],max(0,usage.f_favail-protected[2]))
        else:
            H[1]=min(H[1],max(0,memory_max-memory_current-protected[1]))
        A=triple(storage['A']); total=vadd(vadd(vadd(tuple(actual_E),U),P),S)
        growth=vadd(vadd(U,P),S)
        _need(within(total,A) and within(growth,tuple(H)),'native resident capacity exhausted')
        return tuple(actual_E),U,P,S,A,tuple(H)

    def _snapshot(self,storage,inventory_row,exclude_stop=()):
        E,U,P,S,A,H=self._capacity(storage,exclude_stop)
        now=time.monotonic_ns()
        return dict(identity=inventory_row['identity'],domain=storage['domain'],revision=str(self.revision),
            issued_ns=now,expires_ns=self.capsule.deadline_ns,E=list(E),U=list(U),P=list(P),S=list(S),A=list(A),H=list(H),
            inventory_digest=inventory_row['digest'],authority_epoch=self.config['authority_epoch'])

    def _all_capacity(self,candidate=None,growth=(0,0,0),exclude_stop=()):
        total=(0,0,0)
        for storage in self.config['storage']:
            E,U,P,S,A,H=self._capacity(storage,exclude_stop if candidate==storage['id'] else ())
            added=growth if candidate==storage['id'] else (0,0,0)
            U=vadd(U,added)
            current=vadd(vadd(vadd(E,U),P),S)
            _need(within(current,A) and within(vadd(vadd(U,P),S),H),'native all-used domain headroom')
            total=vadd(total,current)
        _need(within(total,(self.capsule.total.resident,self.config['native_limits']['allocated_bytes'],
                            self.capsule.total.inodes)),'aggregate all-used attempt resident ceiling')

    def _phase_memory(self,next_future):
        remaining_stop=self.stop_vector[9]
        observed=self.site._cgroup_readback()
        for facts in observed:
            if facts['memory.max'].isdigit():
                _need(_uint(int(facts['memory.current'])+next_future+remaining_stop)<=int(facts['memory.max']),
                      'ancestor current + next future + remaining STOP RAM exceeds hard ceiling')

    def _projection(self,action,data):
        evidence='native-observation:'+str(self.observation)
        return dict(digest=self.capsule.digest,projection=dict(schema='qcl.b0.resident-projection.v1',action=action,
            authority_epoch=self.config['authority_epoch'],counter_epoch=self.config['counter_epoch'],
            clock_domain=self.config['clock_domain'],observation_sequence=self.observation,evidence_ref=evidence,data=data))

    def _profile(self,profile_digest,descriptor=None):
        profile=self.config['profiles'].get(digest(profile_digest))
        _need(profile is not None,'producer profile not approved')
        if descriptor is not None:
            self._descriptor(descriptor)
            expected=dict(profile['descriptor']); actual=dict(descriptor)
            expected['resident']=dict(expected['resident'],expected_revision=actual['resident']['expected_revision'])
            _need(canonical(expected)==canonical(actual),'unapproved native producer descriptor')
        return profile

    def _stop_binding(self,operation):
        root=operation['lease']['inventory']
        templates=self.config['stop_profile']['bindings']
        template=templates.get(root['digest'])
        _need(template is not None,'Root-admitted same-ledger STOP binding missing')
        exact(template,('identity','root_descriptor_digest','stop_descriptor','inventory_digest','envelope_token',
                        'owner_scope_digest','cpu_ns','ram_total_bytes','ram_future_bytes','wall_ns','filesystems'))
        _need(template['identity']==root['identity'] and template['root_descriptor_digest']==root['digest'] and
              template['owner_scope_digest'] in operation['lease']['scopes'],'STOP owner/root identity')
        inventory(template['stop_descriptor'])
        _need(template['stop_descriptor']['digest'] in operation['lease']['scopes'] and
              template['ram_future_bytes']<=template['ram_total_bytes']<=self.capsule.stop.memory and
              _uint(template['cpu_ns'])<=self.config['stop_profile']['native_limits']['cpu_ns'] and
              _uint(template['wall_ns'])<=self.capsule.stop.wall_ns,'STOP typed/native limits')
        _need(type(template['filesystems']) is list,'STOP filesystem partition')
        totals=(0,0,0)
        for row in template['filesystems']:
            exact(row,('domain','logical_future_bytes','physical_future_bytes','future_inodes',
                       'read_bytes','write_bytes','log_bytes'))
            exact(row['domain'],DOMAIN_KEYS)
            for key in ('logical_future_bytes','physical_future_bytes','future_inodes','read_bytes','write_bytes','log_bytes'):
                _uint(row[key])
            _need(row['log_bytes']<=row['write_bytes'],'STOP log included in writes')
            totals=vadd(totals,(row['read_bytes'],row['write_bytes'],row['log_bytes']))
        _need(within(totals,(self.capsule.stop.read,self.capsule.stop.write,self.capsule.stop.log)),
              'STOP cumulative filesystem partition')
        binding=dict(template,issuer=sha(canonical(asdict(self.site.issuer))),
            authority_epoch=self.config['authority_epoch'],counter_epoch=self.config['counter_epoch'],
            clock_domain=self.config['clock_domain'],deadline_ns=self.capsule.deadline_ns)
        return dict(binding=binding,digest=sha(canonical(binding)))

    def current(self,args):
        exact(args,('digest','projection')); _need(args['digest']==self.capsule.digest,'projection capsule')
        query=args['projection']; _need(type(query) is dict,'closed projection required')
        action=query.get('action'); self._fresh(normal=False)
        if action=='snapshot':
            _need(self.site.primary is None,'new resident candidate after freeze')
            exact(query,('action','profile_digest','inventory'))
            profile=self._profile(query['profile_digest'])
            _need(query['inventory']==profile['descriptor']['resident']['inventory'],'foreign inventory')
            inv=query['inventory']; inventory(inv)
            storage=self._storage(profile['storage_id'])
            _need(inv['identity']==storage['identity'],'resident identity not admitted')
            snapshot=self._snapshot(storage,inv,profile['stop_ids'])
            self.candidates[inv['digest']]=dict(profile=profile,snapshot=snapshot,revision=snapshot['revision'],
                                               observation=self.observation)
            return self._projection(action,snapshot)
        if action=='binding':
            _need(self.site.primary is None,'new resident binding after freeze')
            exact(query,('action','descriptor_digest','snapshot_revision'))
            candidate=self.candidates.get(digest(query['descriptor_digest']))
            _need(candidate is not None and candidate['revision']==query['snapshot_revision']==str(self.revision),
                  'stale/unregistered resident candidate')
            return self._projection(action,dict(descriptor_digest=query['descriptor_digest'],
                 snapshot_revision=query['snapshot_revision'],outcome='binding_verified'))
        if action in ('writer','created','materialization'):
            keys={'writer':('action','lease_id','scope_digest','writer','file_id','payload_binding_digest'),
                  'created':('action','lease_id','scope_digest','file_id'),
                  'materialization':('action','lease_id','scope_digest')}
            exact(query,keys[action]); lease,scope=self._scope(query['lease_id'],query['scope_digest'])
            if self.site.primary is not None:
                _need(self._is_stop_scope(lease,scope),'normal resident projection after freeze')
            if action=='writer':
                row=self._file_slot(lease,query['file_id'])
                _need(query['writer']==scope['inventory']['writer'] and
                      query['payload_binding_digest']==lease['operation']['payload_binding_digest'],
                      'writer/captured publication binding')
                _need(row['file_id'] in scope['file_ids'],'writer outside registered scope')
                data=dict(lease_id=lease['id'],scope_digest=query['scope_digest'],file_id=row['file_id'],
                          payload_binding_digest=query['payload_binding_digest'],outcome='writer_verified')
            elif action=='created':
                obj=self._observe_file(lease,query['file_id'])
                data=dict(lease_id=lease['id'],scope_digest=query['scope_digest'],file_id=query['file_id'],
                    object_ref=obj['reference'],dev=obj['dev'],ino=obj['ino'],mount_id=obj['mount_id'],
                    logical_extent=obj['extent'],allocated_bytes=obj['allocated'],outcome='created_verified')
            else:
                observation=self._materialization(lease,scope)
                data=dict(lease_id=lease['id'],scope_digest=query['scope_digest'],resident_sequence=lease['sequence'],
                    delta=list(observation['delta']),object_inventory_ref=observation['reference'],outcome='observed')
            return self._projection(action,data)
        raise ProviderRefusal('unknown resident projection')

    def reserve(self,args):
        exact(args,('digest','operation_kind','profile_digest','descriptor'))
        _need(args['digest']==self.capsule.digest and args['operation_kind'] in KINDS,'operation capsule/kind')
        profile=self._profile(args['profile_digest'],args['descriptor']); descriptor=args['descriptor']
        _need(profile['kind']==args['operation_kind'],'operation family/profile mismatch')
        self._fresh(normal=args['operation_kind']!='stop')
        candidate=self.candidates.get(descriptor['resident']['inventory']['digest'])
        _need(candidate is not None and candidate['profile']==profile and
              candidate['revision']==descriptor['resident']['expected_revision']==str(self.revision),
              'resident reservation CAS stale/unregistered')
        _need(descriptor['digest'] not in {op['descriptor']['digest'] for op in self.operations.values()},
              'producer operation replay')
        self._prebook_cardinality(len(descriptor['delegates']))
        vector=native_vector(descriptor['inclusive'],descriptor['native_limits'])
        stop_part=(0,)*11
        for child in descriptor['delegates']:
            if child['role']=='stop':
                stop_part=vadd(stop_part,native_vector(child['bound'],child['native_limits']))
        normal_part=vsub(vector,stop_part)
        cumulative={0,1,2,6,7,8,10}
        live=list(self.observer_total)
        for operation in self.operations.values():
            if operation['state'] not in ('committed','released'):
                for dimension in (3,4,5,9):
                    live[dimension]=_uint(live[dimension]+operation['normal_vector'][dimension])
        proposed=tuple(_uint(self.normal_vector[i]+normal_part[i]) if i in cumulative else
                       _uint(live[i]+normal_part[i]) for i in range(11))
        total=native_vector(asdict(self.capsule.total),self.config['native_limits'])
        if args['operation_kind']=='stop':
            _need(self.site.primary is None and self.stop_request is None and within(vector,self.stop_vector),
                  'STOP root must be prebooked before failure, never minted after freeze')
        else:
            _need(within(vadd(proposed,self.stop_vector),total),'native inclusive operation plus remaining STOP exceeds slot')
        storage=self._storage(profile['storage_id']); inv=descriptor['resident']['inventory']
        growth=inventory(inv); values=self._capacity(storage,profile['stop_ids'])
        E,U,P,S,A,H=values
        _need(within(vadd(vadd(vadd(E,vadd(U,growth)),P),S),A) and
              within(vadd(vadd(vadd(U,growth),P),S),H),'resident inclusive candidate does not fit')
        self._all_capacity(storage['id'],growth,profile['stop_ids'])
        self._phase_memory(vector[9])
        used_stop={sid for lease in self.leases.values() for sid in lease['stop_ids']}
        _need(not used_stop.intersection(profile['stop_ids']) and set(profile['stop_ids'])<=set(storage['stop_entries']),
              'STOP resident identity partition reused/missing')
        # This single retained transaction is spent before any allocation/carrier
        # or producer effect. Failure below leaves its native/root debt in place.
        operation_id=self._id('operation',self.operation_sequence); self.operation_sequence+=1
        lease_id=self._id('resident-lease',self.operation_sequence)
        lease=dict(id=lease_id,revision=candidate['revision'],descriptor_digest=inv['digest'],storage_id=storage['id'],
            inventory=inv,native_remaining=growth,remaining=growth,sequence=0,state='active',stop_ids=tuple(profile['stop_ids']),
            scopes={},observations={},profile=profile)
        op=dict(id=operation_id,descriptor=descriptor,kind=args['operation_kind'],profile=profile,lease=lease,
            delegates={},capture=None,payload_binding_digest=None,state='reserved',sequence=self.operation_sequence,
            normal_vector=normal_part,pending_children=set(range(len(descriptor['delegates']))))
        lease['operation']=op
        def scopes(item,parent=None):
            key=item['digest']; _need(key not in lease['scopes'],'duplicate resident scope digest')
            owned={row['file_id'] for child in descriptor['delegates'] if child['scope_digest']==key
                   for row in child['files']}
            if parent is None:
                owned={row['file_id'] for row in descriptor['files']}
            lease['scopes'][key]=dict(inventory=item,parent=parent,remaining=triple([item['logical'],item['physical'],item['inodes']]),
                file_ids=owned,state='active',materialized=(0,0,0))
            for child in item['slots']:
                scopes(child,key)
        scopes(inv)
        self.operations[operation_id]=op; self.leases[lease_id]=lease
        self.normal_vector=proposed if args['operation_kind']!='stop' else self.normal_vector
        normal_budget=Budget(**{name:(normal_part[DIMS.index(name)] if name not in ('resident','inodes','memory') else 0)
                               for name in Budget.__dataclass_fields__})
        self.site._ledger.reserve(normal_budget) if args['operation_kind']!='stop' else None
        self.atomic.store64(self.control.mapping,584,self.observation)
        struct.pack_into('<11Q',self.control.mapping,408,*self.normal_vector)
        self.revision+=1
        snapshot=self._snapshot(storage,inv)
        return dict(operation_id=operation_id,resident=dict(schema='qcl.b0.resident-lease.v1',
            lease=dict(lease_id=lease_id,revision=lease['revision'],descriptor_digest=lease['descriptor_digest']),
            post_snapshot=snapshot,stop_reservation_id=inv['stop_reference'],evidence_ref='native-reservation:'+operation_id))

    def _reserved_cardinality(self):
        # Control root + every operation + all its issued AND unissued children.
        # Tombstones never refund slots, so late STOP cannot compete with a new
        # normal issuance for already promised capacity.
        total=1
        issued_ids=set()
        for operation in self.operations.values():
            issued=set(operation['delegates'])
            pending=operation['pending_children']
            _need(not issued.intersection(pending) and issued|pending==
                  set(range(len(operation['descriptor']['delegates']))),'native slot partition corrupt')
            for record in operation['delegates'].values():
                _need(record['id'] not in issued_ids and self.delegates.get(record['id']) is record,
                      'native global/operation registry identity mismatch')
                issued_ids.add(record['id'])
            total=_uint(total+1+len(issued)+len(pending))
        _need(issued_ids==set(self.delegates),'native orphan delegate/tombstone record')
        _need(total<=MAX_SCOPES,'native reserved registry overflow')
        return total

    def _prebook_cardinality(self,children):
        _need(self._reserved_cardinality()+1+_uint(children)<=MAX_SCOPES,
              'native parent/all-children capacity including pending STOP')

    def _register_delegate(self,operation,index,record):
        self._reserved_cardinality()
        _need(index in operation['pending_children'] and index not in operation['delegates'] and
              record['id'] not in self.delegates,'native child slot was not prebooked')
        self.delegates[record['id']]=record
        operation['delegates'][index]=record
        operation['pending_children'].remove(index)

    def _before_capture_bootstrap(self,operation,index):
        _need(self.operations.get(operation['id']) is operation,'bootstrap operation not retained/admitted')
        child=operation['descriptor']['delegates'][index]
        return (index!=operation['descriptor']['capture_index'] and child['role']=='normal' and
                child['kind']=='bootstrap' and not child['files'] and
                child['scope_digest']==operation['lease']['descriptor_digest'] and
                child['payload_binding_digest'] is None)

    def _refine_stage_aliases(self,operation,files):
        _need(self.operations.get(operation['id']) is operation,'directory alias operation not retained')
        for row in files:
            if row['kind']!='directory' or row['acquire']!='mkdir_exclusive':
                continue
            prior=[]
            for record in operation['delegates'].values():
                if record['grant'] is None:
                    continue
                for old in record['grant']['files']:
                    if old['file_id']==row['file_id']:
                        prior.append((record,old))
            if not prior:
                continue  # first owning creation remains create-exclusive
            _need(row['root_index'] is not None,'directory alias cannot create a new inherited top root')
            prior.sort(key=lambda item:item[0]['grant']['grant_sequence'])
            record,old=prior[-1]
            _need(record['state']=='settled' and old['kind']=='directory' and old['root_index'] is not None and
                  old['name']==row['name'] and
                  record['grant']['files'][old['root_index']]['file_id']==files[row['root_index']]['file_id'],
                  'directory alias parent/name/phase not the admitted same-op slot')
            observed=next(item for item in record['observed']['files'] if item['file_id']==row['file_id'])
            known=record['objects'].get(row['file_id'])
            _need(observed['state']==2 and not record['observed']['unknown'] and
                  not any(record['observed']['outstanding']) and known is not None and not known['retired'],
                  'directory alias lacks prior S-verified acquisition/lifetime')
            parent_id=files[row['root_index']]['file_id']
            parent=self._observe_file(operation['lease'],parent_id,allow_tombstone=True)
            fd=os.open(basename(row['name']),os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,
                       dir_fd=parent['fd'])
            self.owner.adopt((fd,))
            try:
                info=os.fstat(fd)
                _need(stat.S_ISDIR(info.st_mode) and info.st_nlink>0 and
                      (info.st_dev,info.st_ino)==(known['dev'],known['ino'])==
                      (observed['dev'],observed['ino']) and
                      (info.st_size,info.st_blocks*512)==(observed['logical_extent'],observed['allocated_bytes']) and
                      info.st_size<=row['max_extent'],
                      'directory alias actual namespace/lifetime mismatch')
                row.update(acquire='open_existing',state='existing',fd_index=None,
                    expected_dev=info.st_dev,expected_ino=info.st_ino,expected_mode=info.st_mode&0o7777,
                    initial_extent=info.st_size,create_mode=None,
                    allowed_ops=[name for name in row['allowed_ops'] if name not in ('mkdir','temp')])
            finally:
                _need(self.owner.close_one(fd),'directory alias readback close unknown')

    def _is_stop_scope(self,lease,scope):
        stop_scopes={child['scope_digest'] for child in lease['operation']['descriptor']['delegates']
                     if child['role']=='stop'}
        lineage=scope
        while lineage['inventory']['digest'] not in stop_scopes and lineage['parent'] is not None:
            lineage=lease['scopes'][lineage['parent']]
        return lineage['inventory']['digest'] in stop_scopes

    def _scope(self,lease_id,scope_digest):
        lease=self.leases.get(hexid(lease_id)); digest(scope_digest)
        _need(lease is not None and lease['state'] in ('active','committed'),'unknown/terminal resident lease')
        scope=lease['scopes'].get(scope_digest)
        _need(scope is not None and scope['state']=='active','unknown/terminal resident scope')
        _need(lease['state']=='active' or self._is_stop_scope(lease,scope),
              'closed normal root only retains preissued STOP scopes')
        return lease,scope

    def _file_slot(self,lease,file_id):
        rows=[row for row in lease['operation']['descriptor']['files'] if row['file_id']==hexid(file_id)]
        _need(len(rows)==1,'unregistered logical file slot')
        return rows[0]

    def _fd_entry(self,index,role,fd,domain,file_id):
        info=os.fstat(fd); flags=fcntl.fcntl(fd,fcntl.F_GETFL)
        access={os.O_RDONLY:'read',os.O_WRONLY:'write',os.O_RDWR:'read_write'}[flags&os.O_ACCMODE]
        if role=='root':
            _need(stat.S_ISDIR(info.st_mode) and access=='read','readonly directory root required'); access='directory'
        if role in ('grant','control','snapshot','capture_metadata'):
            _need(access=='read','actual readonly carrier/file description required')
        if role in ('grant','control','counter'):
            _need(info.st_uid==0 and stat.S_ISREG(info.st_mode),'S-owned carrier required')
        return dict(index=index,role=role,dev=info.st_dev,ino=info.st_ino,access=access,length=info.st_size,
                    domain_id=domain,file_id=file_id)

    def delegate(self,args):
        exact(args,('digest','operation_id','index')); _need(args['digest']==self.capsule.digest,'delegate capsule')
        op=self.operations.get(hexid(args['operation_id'])); index=_uint(args['index'])
        _need(op is not None and index<len(op['descriptor']['delegates']) and index not in op['delegates'],'delegate replay/index')
        child=op['descriptor']['delegates'][index]
        self._fresh(normal=child['role']!='stop')
        self._reserved_cardinality()
        _need(index in op['pending_children'],'native child slot was not prebooked')
        capture_index=op['descriptor']['capture_index']
        if capture_index is not None and index!=capture_index and child['role']=='normal':
            bootstrap=self._before_capture_bootstrap(op,index)
            _need(op['capture'] is not None or bootstrap,'publication delegate before authenticated capture')
        did=self._id('delegate',self.grant_sequence,index); sequence=self.grant_sequence; self.grant_sequence+=1
        record=dict(id=did,operation=op,index=index,child=child,state='issuing',counter=None,grant=None,
                    receipt=None,objects={},object_bindings={},baselines={},last_effect=0,transferred=set(),read_mappings=[],sealed=False)
        self._register_delegate(op,index,record)  # pending -> issued tombstone BEFORE any effect
        files=[dict(row) for row in child['files']]
        _need(len(self.owner.entries)+len(files)+8+256<=self.owner.capacity,
              'S descriptor/custody emergency tail capacity')
        self._refine_stage_aliases(op,files)
        if op['capture'] is not None:
            for row in files:
                captured=op['capture']['files'].get(row['file_id'])
                if captured is not None:
                    info=captured['info']
                    row.update(acquire='inherit_fd',state='existing',access='read',fd_index=0,
                        expected_dev=info.st_dev,expected_ino=info.st_ino,expected_mode=info.st_mode&0o7777,
                        initial_extent=info.st_size,create_mode=None,publish_mode=None,
                        allowed_ops=[name for name in row['allowed_ops'] if name in
                                     ('open','read','pread','seek','stat','mmap_ro','munmap','close')])
        # Observe existing identities BEFORE granting C an effect-capable file.
        # Their initial resident bytes/inodes already belong to E, not fresh U.
        opened={}
        for position,row in enumerate(files):
            if row['state']!='existing':
                continue
            fid=row['file_id']
            if fid in op['profile']['root_indices']:
                fd=self.site.custody.directory_fds[op['profile']['root_indices'][fid]]
            elif op['capture'] is not None and fid in op['capture']['files']:
                fd=op['capture']['files'][fid]['fd']
            else:
                _need(row['root_index'] in opened,'existing parent not observed before grant')
                flags=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW
                if row['kind']=='directory':
                    flags|=os.O_DIRECTORY
                fd=os.open(basename(row['name']),flags,dir_fd=opened[row['root_index']])
                self.owner.adopt((fd,))
            info=os.fstat(fd)
            _need((info.st_dev,info.st_ino,info.st_mode&0o7777,info.st_size)==
                  (row['expected_dev'],row['expected_ino'],row['expected_mode'],row['initial_extent']),
                  'existing pre-effect baseline identity/extent mismatch')
            opened[position]=fd
            record['baselines'][fid]=object_facts(info)
        descriptors=[]; table=[]
        # Allocate fixed counter capacity before source/C attach. Capture capacity
        # includes its declared one-snapshot persistent transfer from the start.
        is_capture=capture_index==index
        length=counter_length(len(files),self.page,is_capture,1 if is_capture else 0)
        raw=header(b'QCLB0CN1',length,self,op['id'],did,sequence); raw.extend(bytes(length-len(raw)))
        struct.pack_into('<Q',raw,824,len(files))
        for position,row in enumerate(files):
            raw[832+96*position:848+96*position]=bytes.fromhex(row['file_id'])
        counter=Carrier(self,'qcl-b0-counter-'+did,length,raw); record['counter']=counter
        # The grant identity/length is self-referential only in file extent, not
        # hash. Resolve its JSON byte length to a stable bounded fixed point.
        table=[dict(index=0,role='grant',dev=0,ino=0,access='read',length=0,domain_id=None,file_id=None),
               self._fd_entry(1,'control',self.control.read_fd,None,None),
               self._fd_entry(2,'counter',counter.fd,None,None)]
        descriptors=[None,self.control.read_fd,counter.fd]
        for row in files:
            if row['acquire']!='inherit_fd':
                continue
            fid=row['file_id']; fd=None; role=None; domain=op['profile']['storage_id']
            if fid in op['profile']['root_indices']:
                fd=self.site.custody.directory_fds[op['profile']['root_indices'][fid]]; role='root'
            elif op['capture'] is not None and fid in op['capture']['files']:
                fd=op['capture']['files'][fid]['fd']; role=row['kind']
                domain=op['capture']['files'][fid]['domain_id']
            _need(fd is not None,'unregistered inherited file descriptor')
            position=len(descriptors); row['fd_index']=position
            info=os.fstat(fd)
            _need((info.st_dev,info.st_ino,info.st_mode&0o7777,info.st_size)==
                  (row['expected_dev'],row['expected_ino'],row['expected_mode'],row['initial_extent']),
                  'inherited native object changed')
            table.append(self._fd_entry(position,role,fd,domain,fid)); descriptors.append(fd)
        grant=dict(abi='qcl.b0.native-delegate.v1',capsule_digest=self.capsule.digest,operation_id=op['id'],delegate_id=did,
            index=index,grant_sequence=sequence,worker_identity_digest=self.worker_digest,
            issuer_identity_digest=sha(canonical(asdict(self.site.issuer))),authority_epoch=self.config['authority_epoch'],
            counter_epoch=self.config['counter_epoch'],clock_domain=self.config['clock_domain'],deadline_ns=self.capsule.deadline_ns,
            profile_digest=op['descriptor']['profile_digest'],descriptor_digest=op['descriptor']['digest'],
            payload_binding_digest=op['payload_binding_digest'],native_kit_digest=self.site.intent['native_kit'],
            kind=child['kind'],role=child['role'],bound=child['bound'],native_limits=child['native_limits'],
            files=files,fd_table=table,stop_binding_digest=self._stop_binding(op)['digest'])
        exact(grant,GRANT_KEYS)
        # Create the grant inode first; sealing waits for the exact fd_table row.
        grant_fd=os.memfd_create('qcl-b0-grant-'+did,os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC)
        self.owner.adopt((grant_fd,)); info=os.fstat(grant_fd)
        table[0].update(dev=info.st_dev,ino=info.st_ino)
        for _ in range(8):
            body=canonical(grant); _need(len(body)<=PACKET,'grant packet limit')
            if table[0]['length']==len(body):
                break
            table[0]['length']=len(body)
        else:
            raise ProviderRefusal('grant length fixed point did not converge')
        os.ftruncate(grant_fd,len(body)); offset=0
        while offset<len(body):
            n=os.pwrite(grant_fd,body[offset:],offset); _need(n>0,'grant short write'); offset+=n
        fcntl.fcntl(grant_fd,fcntl.F_ADD_SEALS,_SEALS)
        readonly=os.open('/proc/self/fd/'+str(grant_fd),os.O_RDONLY|os.O_CLOEXEC); self.owner.adopt((readonly,))
        descriptors[0]=readonly
        validate_files(files,table)
        record.update(grant=grant,descriptors=tuple(descriptors),grant_fd=readonly,state='issued')
        result=dict(operation_id=op['id'],delegate_id=did,index=index,bound=child['bound'],
                    native_kit=self.site.intent['native_kit'],fd_table=table)
        return result,tuple(descriptors)

    def _counter(self,record,terminal=False):
        carrier=record['counter']; _need(carrier is not None,'delegate carrier not retained')
        if terminal:
            raw=carrier.seal_terminal(); record['sealed']=True
        else:
            # Finite independent reads, not an adaptive retry loop until an even
            # snapshot happens. A changing/odd carrier is an unknown observation.
            _need(carrier.native_read_pointer is not None,'retained S readonly atomic mapping missing')
            first=self.atomic.lib.qcl_b0_s_load64(carrier.native_read_pointer+320)
            _need(first%2==0,'counter seqlock odd')
            self.atomic.lib.qcl_b0_s_acquire_fence()
            raw=carrier.bytes()
            self.atomic.lib.qcl_b0_s_acquire_fence()
            last=self.atomic.lib.qcl_b0_s_load64(carrier.native_read_pointer+320)
            _need(first==last==struct.unpack_from('<Q',raw,320)[0],'counter changed during observation')
        is_capture=record['operation']['descriptor']['capture_index']==record['index']
        observed=parse_counter(raw,record['grant'],self.page,is_capture)
        _need(observed['effect_sequence']>=record['last_effect'],'native effect sequence reset')
        record['last_effect']=observed['effect_sequence']
        _need(struct.unpack_from('<QQ',raw,264)==(self.site.worker.pid,self.site.worker.start_ticks),
              'counter worker PID/start mismatch')
        return observed,raw

    def _file_native_row(self,lease,file_id,allow_tombstone=False):
        matches=[]
        for record in lease['operation']['delegates'].values():
            if record['grant'] is None:
                continue
            observed,_raw=self._counter(record)
            for row in observed['files']:
                if row['file_id']==file_id and row['state'] in (2,3):
                    matches.append((record,row,observed))
        _need(matches,'file not actually acquired/observed')
        # Logical file slot transitions are ordered by native grant issuance.
        # A known tombstone retains history; it never fabricates a current path.
        matches.sort(key=lambda item:item[0]['grant']['grant_sequence'])
        record,row,observed=matches[-1]
        _need(not observed['unknown'] and not any(observed['outstanding']) and
              (row['state']==2 or (allow_tombstone and row['state']==3)),
              'file object observation has unresolved effect/tombstone')
        return record,row

    def _observe_file(self,lease,file_id,allow_tombstone=False):
        slot=self._file_slot(lease,file_id); record,row=self._file_native_row(lease,file_id,allow_tombstone)
        cached=record['objects'].get(file_id)
        if cached is not None and cached['retired']:
            cached=None  # its closed fd/old generation cannot observe inode reuse
        fd_owned=False
        if cached is not None:
            fd=cached['fd']
        elif slot['kind'] in ('snapshot','capture_metadata'):
            capture=lease['operation']['capture']
            _need(capture is not None and file_id in capture['files'],'anonymous file not transferred to S')
            fd=capture['files'][file_id]['fd']
        elif slot['root_index'] is None:
            index=lease['profile']['root_indices'].get(file_id)
            _need(index is not None,'root file not registered')
            fd=self.site.custody.directory_fds[index]
        else:
            files=lease['operation']['descriptor']['files']; parent_slot=files[slot['root_index']]
            parent=self._observe_file(lease,parent_slot['file_id'],allow_tombstone=allow_tombstone)
            flags=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW
            if slot['kind']=='directory':
                flags|=os.O_DIRECTORY
            fd=os.open(basename(slot['name']),flags,dir_fd=parent['fd'])
            self.owner.adopt((fd,))  # S retains the independently opened inode
            fd_owned=True
        info=os.fstat(fd)
        _need((stat.S_ISDIR(info.st_mode) if slot['kind']=='directory' else stat.S_ISREG(info.st_mode)) and
              (info.st_dev,info.st_ino,info.st_size,info.st_blocks*512)==
              (row['dev'],row['ino'],row['logical_extent'],row['allocated_bytes']),
              'native/kernel object readback mismatch')
        _need(info.st_size<=slot['max_extent'] and info.st_ino>0,'actual object extent/inode policy')
        fdinfo=os.open('/proc/self/fdinfo/'+str(fd),os.O_RDONLY|os.O_CLOEXEC)
        try:
            text=os.read(fdinfo,8193); _need(len(text)<=8192,'fdinfo cap')
            entries=dict(line.split(':',1) for line in text.decode('ascii').splitlines() if ':' in line)
            mount_id=int(entries['mnt_id'].strip())
        finally:
            os.close(fdinfo)
        captured=lease['operation']['capture']
        storage=self._storage(captured['files'][file_id]['domain_id'] if captured is not None and
                              file_id in captured['files'] else lease['storage_id'])
        key=(self.site.worker.boot,self.site.issuer.mount_namespace,mount_id,info.st_dev,info.st_ino)
        obj=self.objects.get(key)
        if obj is None or obj.get('retired',False):
            self.generation+=1
            primitive=dict(boot=key[0],namespace=key[1],mount_id=mount_id,dev=info.st_dev,ino=info.st_ino,
                           lifetime_generation=self.generation)
            baseline=record['baselines'].get(file_id)
            if baseline is not None:
                _need((baseline['dev'],baseline['ino'])==(info.st_dev,info.st_ino),'baseline object replaced')
            accounted=(baseline['extent'],baseline['allocated'],1) if baseline is not None else (0,0,0)
            obj=dict(reference='linux-object:'+sha(canonical(primitive)),fd=fd,fd_owned=fd_owned,
                     dev=info.st_dev,ino=info.st_ino,
                     mount_id=mount_id,extent=info.st_size,allocated=info.st_blocks*512,
                     accounted=accounted,baseline_logical=accounted[0],retired=False,
                     storage_id=storage['id'],generation=self.generation,
                     identities=set(),last_effect=record['last_effect'])
            self.objects[key]=obj
        _need(obj['storage_id']==storage['id'],'cross-domain native alias')
        obj['extent']=max(obj['extent'],info.st_size); obj['allocated']=max(obj['allocated'],info.st_blocks*512)
        obj['identities'].add(file_id); record['objects'][file_id]=obj
        record.setdefault('object_bindings',{})[file_id]=self._object_binding(record,row,obj)
        return obj

    def _object_binding(self,record,row,obj):
        return dict(record_id=record['id'],operation_id=record['operation']['id'],
            grant_sequence=record['grant']['grant_sequence'],file_id=row['file_id'],
            acquisitions=row['opens_actual'],object_ref=obj['reference'],generation=obj['generation'],
            boot=self.site.worker.boot,namespace=self.site.issuer.mount_namespace,mount_id=obj['mount_id'],
            dev=obj['dev'],ino=obj['ino'])

    def _bound_object(self,record,row):
        obj=record['objects'].get(row['file_id'])
        binding=record.get('object_bindings',{}).get(row['file_id'])
        if obj is None or binding is None or (obj['dev'],obj['ino'])!=(row['dev'],row['ino']):
            return None
        return obj if binding==self._object_binding(record,row,obj) else None

    def _bound_tombstone(self,lease,file_id):
        record,row=self._file_native_row(lease,file_id,allow_tombstone=True)
        obj=self._bound_object(record,row)
        _need(row['state']==3 and obj is not None and not obj['retired'],
              'tombstone lacks current S-observed slot/acquisition lifetime')
        info=os.fstat(obj['fd'])
        _need((info.st_dev,info.st_ino,info.st_size,info.st_blocks*512)==
              (row['dev'],row['ino'],row['logical_extent'],row['allocated_bytes']),
              'bound tombstone current kernel identity/extent changed')
        obj['extent']=max(obj['extent'],info.st_size); obj['allocated']=max(obj['allocated'],info.st_blocks*512)
        return obj

    def _materialization(self,lease,scope):
        delta=(0,0,0); objects={}
        for fid in scope['file_ids']:
            slots=[row for record in lease['operation']['delegates'].values() if record['grant'] is not None
                   for row in record['grant']['files'] if row['file_id']==fid]
            if not slots:
                continue
            try:
                obj=self._observe_file(lease,fid)
            except ProviderRefusal:
                try:
                    # No generic state3 admission: only a current S-observed
                    # grant/slot/acquisition/lifetime can reach materialize.
                    obj=self._bound_tombstone(lease,fid)
                except ProviderRefusal:
                    # An untouched future slot is absent only if its retained
                    # native counter explicitly has state0/no acquiring effect.
                    known=[]
                    for record in lease['operation']['delegates'].values():
                        if record['grant'] is not None:
                            observed,_raw=self._counter(record)
                            known.extend(row for row in observed['files'] if row['file_id']==fid)
                    _need(known and all(row['state']==0 and row['opens_actual']==0 for row in known),
                          'unresolved native acquisition has no materialization proof')
                    continue
            if obj['storage_id']==lease['storage_id']:
                objects[obj['reference']]=obj
        for obj in objects.values():
            current=(obj['extent'],obj['allocated'],1)
            growth=tuple(max(0,new-old) for new,old in zip(current,obj['accounted']))
            delta=vadd(delta,growth)
        _need(within(delta,scope['remaining']) and within(delta,lease['native_remaining']),
              'native materialization exceeds reservation')
        body=dict(lease=lease['id'],scope=scope['inventory']['digest'],sequence=lease['sequence'],
                  delta=list(delta),objects=sorted(objects),observation=self.observation)
        observation=dict(delta=delta,objects=objects,reference='materialization:'+sha(canonical(body)),body=body)
        lease['observations'][scope['inventory']['digest']]=observation
        return observation

    def settle(self,args):
        exact(args,('digest','operation_id','delegate_id','index','native_receipt'))
        _need(args['digest']==self.capsule.digest,'settlement capsule')
        record=self.delegates.get(hexid(args['delegate_id']))
        _need(record is not None and record['operation']['id']==hexid(args['operation_id']) and
              record['index']==_uint(args['index']),'unregistered delegate settlement')
        receipt=args['native_receipt']; _need(type(receipt) is dict,'typed native receipt')
        if receipt.get('abi')=='qcl.b0.resident-transition.v1':
            return self._resident_transition(record,receipt)
        exact(receipt,('abi','carrier_id','carrier_dev','carrier_ino','effect_sequence','carrier_sha256'))
        _need(receipt['abi']=='qcl.b0.native-terminal.v1' and record['state']=='issued' and
              hexid(receipt['carrier_id'])==record['id'],'native terminal replay/substitution')
        self._fresh(normal=record['child']['role']!='stop')
        carrier=record['counter']; info=os.fstat(carrier.fd)
        _need((info.st_dev,info.st_ino)==(_uint(receipt['carrier_dev']),_uint(receipt['carrier_ino'])),
              'terminal locator not retained S carrier')
        record['state']='settling'  # uncertain seal never retried
        observed,raw=self._counter(record,terminal=True)
        _need(sha(raw)==digest(receipt['carrier_sha256']) and observed['effect_sequence']==_uint(receipt['effect_sequence']) and
              observed['state']==4 and observed['refs']==0 and not observed['unknown'] and
              not any(observed['outstanding']) and observed['first_status']==0,
              'native terminal unknown/not finished')
        _need(not any(row['state'] in (1,4) for row in observed['files']),'unresolved native acquisition')
        if record['operation']['descriptor']['capture_index']==record['index']:
            _need(len(observed['custody'])==1,'normal capture requires actual persistent transfer')
        required=set(record['operation']['profile']['required_files'])
        for row in observed['files']:
            if row['file_id'] in required:
                _need(row['state'] in (2,3),'required producer file unobserved')
            slot=next(item for item in record['grant']['files'] if item['file_id']==row['file_id'])
            _need(row['opens_requested']<=slot['max_opens'] and row['syscalls_requested']<=slot['max_calls'] and
                  row['logical_extent']<=slot['max_extent'],'native per-file bounds')
            if row['state']==2 and slot['kind'] not in ('snapshot','capture_metadata'):
                self._observe_file(record['operation']['lease'],row['file_id'])
            elif row['state']==3 and slot['kind'] not in ('snapshot','capture_metadata'):
                # A namespace tombstone is not an inode-deallocation claim.
                # Only a known unlinked object with drained native references
                # can retire S's own independent fd; rename aliases stay live.
                for obj in self.objects.values():
                    if (obj['dev'],obj['ino'])!=(row['dev'],row['ino']) or obj['retired']:
                        continue
                    info=os.fstat(obj['fd'])
                    if info.st_nlink==0 and obj['fd_owned']:
                        _need(self.owner.close_one(obj['fd']),'retired object close unknown')
                        obj['retired']=True
        for transfer in observed['custody']:
            op=record['operation']; destination=transfer['destination_child_index']
            _need(destination<len(op['descriptor']['delegates']) and destination!=record['index'] and
                  destination not in op['delegates'] and transfer['transfer_nonce'] not in self.transfers,
                  'persistent custody destination/replay')
            file_ids={row['file_id'] for row in record['grant']['files']}
            _need(set(transfer['snapshot_file_ids'])|{transfer['metadata_file_id']}<=file_ids,
                  'transfer file outside capture grant')
            self.transfers[transfer['transfer_nonce']]=dict(transfer=transfer,record=record,state='pending')
        actual=dict(zip(DIMS,observed['actual'])); requested=dict(zip(DIMS,observed['requested']))
        actual_budget=Budget(**{name:actual[name] for name in Budget.__dataclass_fields__})
        requested_budget=Budget(**{name:requested[name] for name in Budget.__dataclass_fields__})
        settlement=Settlement(record['index'],requested_budget,actual_budget,(), 'native-settlement:'+record['id'])
        record.update(state='settled',receipt=settlement,observed=observed,terminal_sha=sha(raw))
        _release_capture(self,record)
        return asdict(settlement)

    def _verify_tree(self,lease,scope,tree):
        exact(tree,('descriptor','remaining','children'))
        _need(tree['descriptor']==scope['inventory']['digest'] and triple(tree['remaining'])==scope['remaining'] and
              type(tree['children']) is list and len(tree['children'])==len(scope['inventory']['slots']),
              'resident subtree caller remaining mismatch')
        for child,branch in zip(scope['inventory']['slots'],tree['children']):
            self._verify_tree(lease,lease['scopes'][child['digest']],branch)

    def _reconcile_commit(self,lease):
        """No implicit U refund: all normal attributable live growth is in E.

        Explicit materialize owns the R2 sequence transition; this guard only
        repeats real observations and requires equality before root U closure.
        """
        objects={}
        for index,child in enumerate(lease['operation']['descriptor']['delegates']):
            if child['role']!='normal':
                continue
            record=lease['operation']['delegates'].get(index)
            _need(record is not None and record['state']=='settled' and record['sealed'],
                  'normal phase not terminal before root reconciliation')
            observed=record['observed']
            _need(not observed['unknown'] and not any(observed['outstanding']) and not observed['refs'],
                  'root reconciliation has unresolved native effects')
            for row in observed['files']:
                _need(row['state'] not in (1,4),'unknown acquisition before root closure')
                if row['state']==0:
                    continue
                slot=next(item for item in record['grant']['files'] if item['file_id']==row['file_id'])
                if slot['kind'] in ('snapshot','capture_metadata'):
                    capture=lease['operation']['capture']
                    _need(capture is not None and capture['state']=='retired','live capture before root closure')
                    continue
                if row['state']==3:
                    obj=self._bound_object(record,row)
                    if obj is not None and obj['retired']:
                        continue
                    # A closed namespace slot may still name a live inode. Do
                    # not interpret native tombstone as logical E=0. Reopen the
                    # actual path or retain an already observed alias lifetime;
                    # absent/unobserved deletion proof refuses root closure.
                    if obj is not None:
                        obj=self._bound_tombstone(lease,row['file_id'])
                    else:
                        obj=self._observe_file(lease,row['file_id'],allow_tombstone=True)
                else:
                    obj=self._observe_file(lease,row['file_id'])
                _need(not obj['retired'],'live native file has retired S object')
                if obj['storage_id']==lease['storage_id']:
                    objects[obj['reference']]=obj
        for obj in objects.values():
            _need(obj['accounted']==(obj['extent'],obj['allocated'],1),
                  'unmaterialized actual object growth before root commit')
        return tuple(sorted(objects))

    def _prove_no_mutation(self,lease):
        readonly={'open','read','pread','seek','stat','fadvise','mmap_ro','munmap','close'}
        members=[]
        for index,child in enumerate(lease['operation']['descriptor']['delegates']):
            if child['role']!='normal':
                continue
            record=lease['operation']['delegates'].get(index)
            _need(record is not None and record['state']=='settled' and record['sealed'],
                  'no-mutation native producer phase missing')
            observed=record['observed']; members.append(record)
            _need(not observed['unknown'] and not any(observed['outstanding']) and not observed['refs'] and
                  observed['requested'][1]==0,'no-mutation unresolved/native write effects')
            _need(len(record['grant']['files'])==len(observed['files']),'no-mutation file coverage incomplete')
            for slot,row in zip(record['grant']['files'],observed['files']):
                _need(slot['acquire'] in ('inherit_fd','open_existing','path_only') and
                      slot['access'] in ('read','directory','none') and set(slot['allowed_ops'])<=readonly and
                      slot['create_mode'] is None and slot['publish_mode'] is None and not slot['rename_targets'],
                      'producer closure permits unproved metadata mutation')
                baseline=record['baselines'].get(slot['file_id'])
                _need(baseline is not None and row['state'] in (2,3) and row['opens_actual']>0 and
                      row['syscalls_actual']>=row['opens_actual'] and row['write_actual']==0,
                      'positive readonly acquisition history absent')
                if slot['root_index'] is None:
                    root_index=lease['profile']['root_indices'].get(slot['file_id'])
                    _need(root_index is not None,'readonly root identity not admitted')
                    info=os.fstat(self.site.custody.directory_fds[root_index])
                else:
                    parent_slot=lease['operation']['descriptor']['files'][slot['root_index']]
                    parent=self._observe_file(lease,parent_slot['file_id'],allow_tombstone=True)
                    flags=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW
                    if slot['kind']=='directory':
                        flags|=os.O_DIRECTORY
                    fd=os.open(basename(slot['name']),flags,dir_fd=parent['fd'])
                    self.owner.adopt((fd,))
                    try:
                        info=os.fstat(fd)
                    finally:
                        _need(self.owner.close_one(fd),'readonly namespace observation close unknown')
                _need(object_facts(info)==baseline,'readonly namespace/mode/lifetime differs from baseline')
        _need(members,'no registered readonly producer coverage')
        return True

    def _resident_transition(self,record,request):
        exact(request,('abi','action','lease_id','scope_digest','resident_sequence','tree','verified',
                       'delta','refundable','object_inventory_ref'))
        lease,scope=self._scope(request['lease_id'],request['scope_digest'])
        _need(lease is record['operation']['lease'] and request['scope_digest'] in
              {record['child']['scope_digest'],lease['descriptor_digest']},'delegate does not own resident scope')
        action=request['action']; _need(action in ('materialize','commit','release'),'resident transition kind')
        self._fresh(normal=record['child']['role']!='stop')
        _need(record['state'] in ('issued','settled') if action=='materialize' else record['state']=='settled',
              'resident acknowledgement before native phase boundary')
        sequence=_uint(request['resident_sequence'])
        if action=='materialize':
            _need(sequence==lease['sequence']+1 and request['tree'] is None and request['verified'] is None and
                  request['refundable'] is None,'materialize sequence/unused fields')
            before=lease['observations'].get(scope['inventory']['digest'])
            _need(before is not None and request['object_inventory_ref']==before['reference'],'missing native materialization observation')
            now=self._materialization(lease,scope)
            delta=triple(request['delta'])
            _need(now['delta']==before['delta']==delta and sorted(now['objects'])==sorted(before['objects']),
                  'materialization native observation changed')
            lease['native_remaining']=vsub(lease['native_remaining'],delta)
            scope['remaining']=(scope['remaining'][0]-delta[0],scope['remaining'][1],scope['remaining'][2])
            scope['materialized']=vadd(scope['materialized'],delta)
            # Existing R2 updates only this permit.remaining logical view;
            # parent/child diagnostic trees retain their independent bounds.
            # The one S native_remaining/global E/U ledger changes exactly once.
            for obj in now['objects'].values():
                obj['accounted']=(obj['extent'],obj['allocated'],1)
            lease['sequence']=sequence; outcome='materialized'; data=dict(delta=list(delta))
        else:
            _need(sequence==lease['sequence'] and request['delta'] is None and request['object_inventory_ref'] is None,
                  'resident commit/release sequence/unused fields')
            self._verify_tree(lease,scope,request['tree'])
            if action=='commit':
                _need(request['refundable'] is None,'commit refundable field')
                exact(request['verified'],('file_id','sha256'))
                fid=request['verified']['file_id']; digest(request['verified']['sha256'])
                _need(fid in lease['profile']['commit_files'],'unapproved durability acknowledgement file')
                obj=self._observe_file(lease,fid)
                slot=self._file_slot(lease,fid)
                raw=os.pread(obj['fd'],slot['max_extent']+1,0)
                _need(len(raw)<=slot['max_extent'] and sha(raw)==request['verified']['sha256'],
                      'durable receipt readback hash')
                # S's prepaid observer partition supplies an independent actual
                # durability barrier, followed by the same retained inode read.
                os.fsync(obj['fd'])
                _need(slot['root_index'] is not None,'durability file requires registered parent')
                parent_slot=lease['operation']['descriptor']['files'][slot['root_index']]
                parent=self._observe_file(lease,parent_slot['file_id'])
                os.fsync(parent['fd'])
                after=os.fstat(obj['fd'])
                _need((after.st_dev,after.st_ino)==(obj['dev'],obj['ino']) and
                      sha(os.pread(obj['fd'],slot['max_extent']+1,0))==request['verified']['sha256'],
                      'durable receipt changed across S barrier')
                required=[item for item in lease['operation']['delegates'].values() if
                          item['child']['scope_digest']==scope['inventory']['digest']]
                _need(required and all(item['state']=='settled' for item in required),'native producer phase not closed')
                if scope['parent'] is None:
                    normal=[(i,item) for i,item in enumerate(lease['operation']['descriptor']['delegates']) if item['role']=='normal']
                    _need(all(i in lease['operation']['delegates'] and
                              lease['operation']['delegates'][i]['state']=='settled' for i,_item in normal) and
                          not any(t['state']!='retired' for t in self.transfers.values() if t['record']['operation'] is lease['operation']),
                          'root publication custody not complete')
                    self._reconcile_commit(lease)
                    lease['state']='committed'
                    lease['operation']['state']='committed'
                    remaining_stop=(0,0,0)
                    for sid in lease['stop_ids']:
                        remaining_stop=vadd(remaining_stop,triple(self._storage(lease['storage_id'])['stop_entries'][sid]))
                    lease['native_remaining']=remaining_stop
                scope['state']='committed'; outcome='committed'
                self.last_verified=dict(file_id=fid,sha256=request['verified']['sha256'],object_ref=obj['reference'],
                    operation_id=lease['operation']['id'],reference='verified-artifact:'+sha(raw))
                data=dict(scope_kind='root' if scope['parent'] is None else 'child',verified=request['verified'])
            else:
                _need(request['verified'] is None and triple(request['refundable'])==scope['remaining'],
                      'release is not exact unmutated resident subtree')
                _need(scope['parent'] is None and scope['materialized']==(0,0,0),
                      'only whole unmutated root reservation can release')
                self._prove_no_mutation(lease)
                refund=triple(request['refundable']); lease['native_remaining']=vsub(lease['native_remaining'],refund)
                scope['state']='released'; outcome='no_mutation_proven'
                if scope['parent'] is None:
                    lease['state']='released'
                    lease['operation']['state']='released'
                data=dict(refundable=list(refund))
        self.revision+=1
        data['post_snapshot']=self._snapshot(self._storage(lease['storage_id']),lease['inventory'])
        return dict(schema='qcl.b0.resident-ack.v1',action=action,lease_id=lease['id'],revision=lease['revision'],
            current_revision=str(self.revision),descriptor_digest=lease['descriptor_digest'],scope_digest=request['scope_digest'],
            resident_sequence=lease['sequence'],authority_epoch=self.config['authority_epoch'],counter_epoch=self.config['counter_epoch'],
            clock_domain=self.config['clock_domain'],observation_sequence=self.observation,evidence_ref='resident-transition:'+str(self.revision),
            outcome=outcome,data=data)


class CanonicalSource3:
    """Bounded closed tag decoder; preserves raw canonical bytes, no constructors.

    Capture tags0..9; final identity additionally has tag10 tensor backrefs in
    the primary frozen encoder. No Python object graph can invoke user code.
    """
    def __init__(self,raw,identity=False):
        _need(type(raw) is bytes and len(raw)<=16<<20,'source3 canonical metadata bound')
        self.raw=raw; self.offset=0; self.identity=identity; self.nodes=set(); self.active=set()
        self.tensors=set(); self.tensor_metadata=[]; self.visits=0
    def uint(self):
        _need(self.offset+8<=len(self.raw),'canonical scalar truncated')
        value=struct.unpack_from('<Q',self.raw,self.offset)[0]; self.offset+=8; return value
    def take(self,count):
        _need(_uint(count)<=len(self.raw)-self.offset,'canonical byte extent')
        result=self.raw[self.offset:self.offset+count]; self.offset+=count; return result
    def value(self,depth=0):
        self.visits+=1; _need(depth<=256 and self.visits<=len(self.raw)+1,'canonical node/depth bound')
        start=self.offset; tag=self.take(1)[0]
        if tag==0:
            value=None
        elif tag in (1,2):
            text=self.take(self.uint()); text.decode('utf-8'); value=(tag,text)
        elif tag==3:
            value=(tag,self.uint())
        elif tag==4:
            count=self.uint(); _need(count<=len(self.raw)-self.offset,'canonical tuple cardinality')
            value=(tag,tuple(self.value(depth+1) for _ in range(count)))
        elif tag==5:
            typecode=self.value(depth+1); bits=self.take(self.uint()); value=(tag,typecode,bits)
        elif tag==6:
            index=self.uint(); _need(index>0,'source3 tensor index is one-based')
            if self.identity:
                _need(index==len(self.tensors)+1,'identity tensor numbering'); self.tensors.add(index)
                metadata=self.value(depth+1); self.tensor_metadata.append(metadata)
                value=(tag,index,metadata)
            else:
                self.tensors.add(index); value=(tag,index)
        elif tag==7:
            index=self.uint(); _need(index in self.nodes and index not in self.active,
                                    'canonical unresolved/cyclic node reference'); value=(tag,index)
        elif tag in (8,9):
            index=self.uint(); _need(index>0 and index not in self.nodes,'canonical duplicate node ID')
            self.nodes.add(index)
            self.active.add(index)
            if tag==8:
                if self.identity:
                    typecode=self.value(depth+1); length=self.uint()
                    value=(tag,index,typecode,length,self.value(depth+1))
                else:
                    length=self.uint(); value=(tag,index,length,self.value(depth+1))
            else:
                value=(tag,index,self.value(depth+1),self.value(depth+1),self.value(depth+1))
            self.active.remove(index)
        elif tag==10 and self.identity:
            index=self.uint(); _need(index in self.tensors,'identity unresolved tensor backref'); value=(tag,index)
        else:
            raise ProviderRefusal('unsupported source3 canonical tag')
        return (start,self.offset,value)
    def all(self):
        values=[]
        while self.offset<len(self.raw):
            values.append(self.value())
        return values


def _node_value(record):
    return record[2]


def _tuple_value(record):
    value=_node_value(record); _need(value is not None and value[0]==4,'canonical tuple required')
    return value[1]


def _integer_value(record):
    value=_node_value(record); _need(value is not None and value[0]==3,'canonical integer required')
    return value[1]


def _string_value(record):
    value=_node_value(record); _need(value is not None and value[0] in (1,2),'canonical text required')
    return value[1]


def _path_wire(record):
    result=[]
    for component in _tuple_value(record):
        value=_node_value(component)
        _need(value is not None and value[0] in (1,2,3),'canonical path scalar type')
        if value[0]==3:
            number=value[1] if value[1]<(1<<63) else value[1]-(1<<64)
            result.append(['integer',number])
        else:
            result.append(['string' if value[0]==1 else 'symbol',value[1].decode('utf-8')])
    return result


def parse_metadata(raw,metadata,snapshots,scalar_codes,expected_shapes):
    expected_count=len(expected_shapes)
    _need(len(raw)>=128 and raw[:8]==b'QCLB0MD1' and struct.unpack_from('<II',raw,8)==(1,128),'capture metadata header')
    total,capture_len,identity_len,count,index_len=struct.unpack_from('<5Q',raw,16)
    _need(total==len(raw)==128+capture_len+identity_len+index_len and
          capture_len<=16<<20 and identity_len<=16<<20 and count==expected_count and not any(raw[120:128]),
          'metadata section lengths/padding')
    capture=raw[128:128+capture_len]; identity=raw[128+capture_len:128+capture_len+identity_len]
    _need(sha(capture)==raw[56:88].hex() and sha(identity)==raw[88:120].hex(),'canonical capture/identity digest')
    capture_parser=CanonicalSource3(capture); capture_values=capture_parser.all()
    identity_parser=CanonicalSource3(identity,True); identity_values=identity_parser.all()
    _need(len(capture_values)==1+count and len(identity_values)==1,'canonical metadata record count')
    _need(capture_parser.tensors<=set(range(1,count+1)) and identity_parser.tensors<=set(range(1,count+1)),
          'canonical tensor reference outside approved index')
    _need(len(snapshots)==1,'source3 single snapshot backend')
    cursor=128+capture_len+identity_len; records=[]; ranges=[]
    for index in range(count):
        _need(cursor+104<=len(raw),'tensor index prefix truncated')
        length,tid=struct.unpack_from('<QQ',raw,cursor)
        path_digest=raw[cursor+16:cursor+48].hex()
        dtype,rank=struct.unpack_from('<II',raw,cursor+48)
        offset,bytes_count=struct.unpack_from('<QQ',raw,cursor+56)
        tensor_digest=raw[cursor+72:cursor+104].hex()
        _need(rank<=8 and 1<=dtype<=7 and length==104+16*rank and cursor+length<=len(raw),
              'tensor index dtype/rank/record extent')
        shape=struct.unpack_from('<'+'Q'*rank,raw,cursor+104)
        axes=struct.unpack_from('<'+'Q'*rank,raw,cursor+104+8*rank)
        _need(shape==axes and tid==index+1,'tensor shape/axes/index mismatch')
        code=scalar_codes[str(dtype)]
        exact(code,('type_code','bytes'))
        itemsize=_uint(code['bytes']); product=itemsize
        for extent in shape:
            product=_uint(product*extent)
        _need(product==bytes_count and _uint(offset+bytes_count)<=snapshots[0]['bytes'], 'tensor native byte extent')
        row=_tuple_value(capture_values[index+1]); _need(len(row)==8,'canonical tensor row arity')
        path=row[0]; path_raw=capture[path[0]:path[1]]
        type_raw=capture[row[1][0]:row[1][1]]
        _need(sha(path_raw)==path_digest and type_raw.hex()==code['type_code'] and
              tuple(_integer_value(v) for v in _tuple_value(row[2]))==shape and
              tuple(_integer_value(v) for v in _tuple_value(row[3]))==axes and
              _integer_value(row[4])==offset and _integer_value(row[5])==bytes_count and
              _string_value(row[6])==b'LE' and _string_value(row[7]).decode('ascii')==tensor_digest,
              'tensor canonical/scalar/index binding')
        described=[_path_wire(path),dtype,list(shape),list(axes),offset,bytes_count]
        _need(described==expected_shapes[index],'actual tensor index differs from reserved shape/type/path')
        if bytes_count:
            _need(not any(offset<end and offset+bytes_count>start for start,end in ranges),'overlapping tensor extents')
            ranges.append((offset,offset+bytes_count))
        records.append(dict(tensor_id=tid,offset=offset,bytes=bytes_count,dtype=dtype,shape=shape,sha256=tensor_digest))
        cursor+=length
    _need(cursor==len(raw),'metadata index trailing bytes')
    for tensor in identity_parser.tensor_metadata:
        fields=_tuple_value(tensor); _need(len(fields)==7,'final identity tensor row arity')
        code=identity[fields[0][0]:fields[0][1]].hex()
        rank=_integer_value(fields[1]); shape=tuple(_integer_value(v) for v in _tuple_value(fields[2]))
        axes=tuple(_integer_value(v) for v in _tuple_value(fields[3]))
        count=_integer_value(fields[4]); endian=_string_value(fields[5]); checksum=_string_value(fields[6]).decode('ascii')
        _need(rank==len(shape) and axes==shape and endian==b'LE' and any(
            scalar_codes[str(row['dtype'])]['type_code']==code and row['shape']==shape and
            row['bytes']==count and row['sha256']==checksum for row in records),
            'final identity tensor not bound to captured actual tensor')
    return dict(capture_digest=sha(capture),publication_digest=sha(identity),records=records,
                capture=tuple(capture_values),identity=tuple(identity_values))


# Registry methods below stay on the retained issuer object; no injected observer
# or worker-side tuple can substitute a retained carrier or kernel file readback.
def verify_capture_immutable(self,args,rights):
    exact(args,('digest','operation_id','descriptor_digest','content_digest','publication_digest','snapshots','metadata'))
    _need(args['digest']==self.capsule.digest,'capture capsule')
    op=self.operations.get(hexid(args['operation_id'])); _need(op is not None and op['capture'] is None,'capture operation/replay')
    self._fresh()
    _need(args['descriptor_digest']==op['descriptor']['digest'] and type(args['snapshots']) is list and
          len(args['snapshots'])==1,'capture descriptor/single snapshot')
    metadata=exact(args['metadata'],('fd_index','bytes','sha256','format'))
    _need(metadata['format']=='qcl.source3.capture-metadata.v1','capture metadata codec')
    for row in args['snapshots']:
        exact(row,('fd_index','bytes','shape','dtype','offset'))
        _uint(row['bytes']); _uint(row['offset'])
        _need(row['fd_index']==0 and row['offset']==0 and row['dtype']=='UInt8' and
              row['shape']==[row['bytes']],'single backing snapshot byte view')
        for extent in row['shape']:
            _uint(extent)
    indexes=[_uint(row['fd_index']) for row in args['snapshots']]+[_uint(metadata['fd_index'])]
    _need(metadata['fd_index']==1,'metadata follows backing snapshot')
    _need(len(rights)==len(indexes)==len(set(indexes)) and sorted(indexes)==list(range(len(rights))),
          'capture descriptor/rights exact table')
    candidates=[value for value in self.transfers.values() if value['record']['operation'] is op and value['state']=='pending']
    _need(len(candidates)==1,'capture native transfer not uniquely registered')
    transfer=candidates[0]; proof=transfer['transfer']; record=transfer['record']
    _need(record['state']=='settled' and proof['destination_child_index'] not in op['delegates'],'capture IO not settled/destination spent')
    files={}; logical=allocated=0
    specifications=list(zip(args['snapshots'],proof['snapshot_file_ids']))+[(metadata,proof['metadata_file_id'])]
    for spec,fid in specifications:
        fd=rights[spec['fd_index']]; info=os.fstat(fd)
        _need(stat.S_ISREG(info.st_mode) and info.st_uid==self.site.worker.uid and info.st_size==_uint(spec['bytes']) and
              fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY and
              fcntl.fcntl(fd,fcntl.F_GET_SEALS)&_SEALS==_SEALS,'capture actual readonly/sealed inode')
        row=next(item for item in record['observed']['files'] if item['file_id']==fid)
        _need(row['state'] in (2,3) and (info.st_dev,info.st_ino,info.st_size,info.st_blocks*512)==
              (row['dev'],row['ino'],row['logical_extent'],row['allocated_bytes']),'transferred file not actual native member')
        memory_domain=next(row['id'] for row in self.config['storage'] if row['kind']=='memory_snapshot')
        files[fid]=dict(fd=fd,domain_id=memory_domain,info=info)
        logical+=info.st_size; allocated+=info.st_blocks*512
    _need((logical,allocated)==(proof['logical_bytes'],proof['allocated_bytes']),'capture transfer resident inventory')
    tensor_count=len(op['descriptor']['shape_type_bytes'])
    _need(_uint(metadata['bytes'])<=128+32*1024**2+tensor_count*(104+16*8),'metadata finite section cap')
    raw=os.pread(rights[metadata['fd_index']],metadata['bytes']+1,0)
    _need(len(raw)==metadata['bytes'] and sha(raw)==digest(metadata['sha256']),'metadata carrier whole hash')
    parsed=parse_metadata(raw,metadata,args['snapshots'],self.config['scalar_codes'],op['descriptor']['shape_type_bytes'])
    _need(parsed['capture_digest']==digest(args['content_digest']) and
          parsed['publication_digest']==digest(args['publication_digest']),'capture/final identity mismatch')
    snapshot_fd=rights[args['snapshots'][0]['fd_index']]
    for row in parsed['records']:
        hasher=hashlib.sha256(); remaining=row['bytes']; offset=row['offset']
        while remaining:
            count=min(1<<20,remaining); chunk=os.pread(snapshot_fd,count,offset)
            _need(len(chunk)==count,'snapshot tensor short read'); hasher.update(chunk)
            remaining-=count; offset+=count
        _need(hasher.hexdigest()==row['sha256'],'independent tensor range digest')
    # Membership and ALL validation precede long-lived handoff. Malformed or
    # nonmember rights stay in temporary receive custody and close once. A late
    # failure after handoff retains only these authenticated registered objects.
    unowned=tuple(fd for fd in rights if fd not in self.owner.entries or
                  self.owner.entries[fd]['state']!='owned')
    if unowned:
        receiver=getattr(self.site,'_receive_owner',None)
        if receiver is None:
            self.owner.adopt(unowned)
        else:
            receiver.handoff(self.owner,unowned)
    transfer['state']='registered'; op['payload_binding_digest']=args['publication_digest']
    op['capture']=dict(files=files,parsed=parsed,transfer=transfer,metadata_sha=metadata['sha256'],state='held')
    return dict(capture_id=self._id('capture',op['sequence']),operation_id=op['id'],
                content_digest=args['content_digest'],publication_digest=args['publication_digest'])




def _freeze(self,primary):
    try:
        if self.control is not None:
            control=self.control.mapping
            current=self.atomic.load32(control,288)
            if not current:
                # First cause bytes precede release-store of the shared latch.
                encoded=canonical(dict(primary=str(primary)[:512],capsule=self.capsule.digest))
                control[592:624]=bytes.fromhex(sha(encoded))
                epoch=self.atomic.load64(control,296)+1
                self.atomic.store64(control,296,epoch)
                self.atomic.store32(control,288,1)
    finally:
        # An uncertain shared store never reopens S's local authority.
        for operation in self.operations.values():
            if operation['kind']!='stop':
                operation['state']='frozen'
        for record in self.delegates.values():
            if record['child']['role']=='normal' and record['state'] not in ('settled','failed'):
                record['state']='frozen'


def _stop_pending(self,args):
    exact(args,('digest','stop_id','primary'))
    _need(args['digest']==self.capsule.digest and self.site.primary is not None and
          args['primary']==self.site.primary and self.site.stop_reserved,'STOP binding/first cause')
    stop=self.config['stop_profile']
    _need(args['stop_id']==stop['stop_id'] and self.stop_request is None,'STOP replay/id')
    self._fresh(normal=False); self.freeze(self.site.primary)
    acknowledgements=[item for item in self.operations.values() if any(
        row['child']['role']=='stop' and row['state']=='settled' for row in item['delegates'].values())]
    ack=None
    for op in acknowledgements:
        fid=stop['ack_file_id']
        if fid is None or not any(row['file_id']==fid for row in op['descriptor']['files']):
            continue
        obj=self._observe_file(op['lease'],fid); slot=self._file_slot(op['lease'],fid)
        raw=os.pread(obj['fd'],slot['max_extent']+1,0)
        _need(len(raw)<=slot['max_extent'],'STOP acknowledgement read cap')
        # ACK schemas remain owning Runner data. S checks actual finite durable
        # registered file identity/hash; it never accepts ACK JSON from caller.
        ack='stop-ack:'+sha(raw)
    deadline=min(self.capsule.deadline_ns,time.monotonic_ns()+_uint(stop['bound']['wall_ns']))
    request_id=self._id('stop-request',self.observation)
    self.stop_request=dict(schema='qcl.b0.stop-pending.v1',status='pending',stop_id=args['stop_id'],
        request_id=request_id,ack_ref=ack,primary_ref='first-cause:'+sha(canonical(self.site.primary)),
        deadline_ns=deadline,quiescence=None,final_result_ref=None)
    if self.site.once.state=='FREEZING':
        self.site.once.advance('FREEZING','STOPPING',dict(request_id=request_id,ack_ref=ack))
    return self.stop_request


def _observe_terminal(self,wait_status):
    """Only retained S can prove C reaped and payload subtree population0.

    This method executes after waitpid returned actual C, while S still owns
    carriers/fds. It stores payload evidence; outer job proof is never invented.
    """
    _need(type(wait_status) is int and self.site.worker is not None,'actual reap receipt required')
    payload_empty=self.site._payload_empty()
    counters=self.site._cgroup_readback()
    unknown=[]
    for record in self.delegates.values():
        if record['state']!='settled':
            unknown.append('delegate:'+record['id'])
    for transfer in self.transfers.values():
        if transfer['state']!='retired':
            unknown.append('persistent-custody:'+transfer['transfer']['transfer_nonce'])
    if not payload_empty:
        unknown.append('payload_descendants')
    if self.owner.state=='close_unknown':
        unknown.append('descriptor_close')
    status='PAYLOAD_QUIESCENT' if not unknown else 'SPENT_UNKNOWN'
    body=dict(schema='qcl.b0.payload-terminal.v1',status=status,issuer=asdict(self.site.issuer),
        worker=asdict(self.site.worker),wait_status=wait_status,job=self.site.admission['scheduler']['job'],
        native_observation_sequence=self.observation,counters=counters,unknown=unknown,
        primary=self.site.primary,stop_request=self.stop_request,last_verified=self.last_verified,
        whole_job_terminal='outer_root_slurm_observer_required',scientific_accepted=False)
    self.final_receipt=body
    if status=='PAYLOAD_QUIESCENT' and self.site.once.state=='STOPPING':
        self.site.once.advance('STOPPING','PAYLOAD_QUIESCENT',dict(receipt=sha(canonical(body))))
    self.site._write_receipt(body)
    if status=='PAYLOAD_QUIESCENT':
        self.site._launch_started=False
    return body


def _release_capture(self,record):
    op=record['operation']; capture=op['capture']
    if capture is None:
        return
    transfer=capture['transfer']; destination=transfer['transfer']['destination_child_index']
    if record['index']!=destination:
        return
    ids=set(capture['files'])
    terminal={row['file_id']:row for row in record['observed']['files']}
    _need(ids<=set(terminal) and all(terminal[fid]['state']==3 for fid in ids) and
          not record['observed']['refs'] and not any(record['observed']['outstanding']),
          'publication snapshot fd/mapping cleanup incomplete')
    for value in capture['files'].values():
        _need(self.owner.close_one(value['fd']),'snapshot readonly custody close unknown')
        info=value['info']
        for obj in self.objects.values():
            if (obj['dev'],obj['ino'])==(info.st_dev,info.st_ino):
                obj['retired']=True
    transfer['state']='retired'; capture['state']='retired'


def _close_mappings(self):
    unknown=[]
    for carrier in self.carriers:
        pointer=carrier.native_read_pointer
        if pointer is not None:
            carrier.native_read_pointer=None  # one unmap attempt per lifetime
            if self.atomic.lib.qcl_b0_s_unmap(pointer,carrier.length)!=0:
                carrier.unknown_mappings['native_read_pointer']=(pointer,carrier.length)
                unknown.append('native_munmap')
        for name in ('mapping','read_mapping'):
            mapping=getattr(carrier,name)
            if mapping is None:
                continue
            setattr(carrier,name,None)
            try:
                mapping.close()
            except BaseException as error:
                carrier.unknown_mappings[name]=mapping  # retained, never retried/GC-abandoned
                unknown.append(type(error).__name__)
    if unknown:
        self.owner.retain_unknown('native_supervisor_mapping_close_unknown')
    return tuple(unknown)
