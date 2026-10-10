"""Bounded read-only observations of one regular file; no allocation or policy."""
import argparse
import fcntl
import hashlib
import json
import os
import stat
import struct
import uuid

FIEMAP = 0xC020660B
EXTENT = struct.Struct("=QQQQQIIII")
HEADER = struct.Struct("=QQIIII")

def normalize_swapon_raw(text, maximum_rows):
    """Normalize exact seven-column util-linux raw output into existing typed rows.

    UUID must be fully measured and LABEL is empty or one safe token. Raw escapes,
    ambiguous whitespace, unknown paths/units and duplicate rows are refusals.
    Independent named inode/rdev and header UUID checks remain in the playbook.
    """
    import re
    if not isinstance(text, str) or len(text.encode('utf-8')) > 65536:
        raise ValueError('bounded raw swap table required')
    if not isinstance(maximum_rows, int) or isinstance(maximum_rows, bool) or not 0 < maximum_rows <= 65536:
        raise ValueError('finite swap row bound required')
    if any(c in text for c in ('\\', '\r', '\t', '\x00')):
        raise ValueError('escaped or control swap table')
    if not text:
        return {'swaps': []}
    if not text.endswith('\n'):
        raise ValueError('complete raw swap rows required')
    lines = text[:-1].split('\n')
    if len(lines) > maximum_rows:
        raise ValueError('swap row bound')
    rows=[]; names=set()
    pattern=re.compile(r'(/[A-Za-z0-9_./+-]+) (file|partition) ([0-9]+) ([0-9]+) (-?[0-9]+) ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}) ([A-Za-z0-9_.+-]{0,128})')
    for line in lines:
        match=pattern.fullmatch(line)
        if match is None:
            raise ValueError('unknown raw swap row')
        name,kind,size,used,prio,identifier,label=match.groups()
        if os.path.normpath(name)!=name or name in names or identifier=='00000000-0000-0000-0000-000000000000':
            raise ValueError('noncanonical/duplicate swap identity')
        size=int(size); used=int(used); prio=int(prio)
        if not 0<size<=9223372036854775807 or not 0<=used<=size or not -9223372036854775807<=prio<=9223372036854775807:
            raise ValueError('invalid swap byte counters/priority')
        names.add(name)
        rows.append(dict(name=name,type=kind,size=size,used=used,prio=prio))
    return {'swaps':rows}



def identity(s):
    return dict(dev=s.st_dev, dev_major=os.major(s.st_dev), dev_minor=os.minor(s.st_dev), inode=s.st_ino, nlink=s.st_nlink, uid=s.st_uid,
                gid=s.st_gid, mode=stat.S_IMODE(s.st_mode), size=s.st_size,
                blocks=s.st_blocks, mtime_ns=s.st_mtime_ns, ctime_ns=s.st_ctime_ns,
                kind="regular" if stat.S_ISREG(s.st_mode) else "other")


def safe_components(path):
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        raise ValueError("absolute canonical path required")
    parts=path.split("/")[1:]
    cursor="/"
    for part in parts[:-1]:
        cursor=os.path.join(cursor,part)
        s=os.lstat(cursor)
        if not stat.S_ISDIR(s.st_mode):
            raise ValueError("symlink or nondirectory component")


def probe(path, *, maximum_extents, maximum_bytes, ioctl_fn=fcntl.ioctl, hole_fn=None):
    path=os.fspath(path)
    if type(maximum_extents) is not int or not 0 < maximum_extents <= 65536:
        raise ValueError("finite extent bound required")
    if type(maximum_bytes) is not int or not 0 < maximum_bytes <= 1048576:
        raise ValueError("finite byte bound required")
    safe_components(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):raise ValueError("regular file required")
        size=before.st_size
        buffer=bytearray(HEADER.size+EXTENT.size*maximum_extents)
        HEADER.pack_into(buffer,0,0,size,1,0,maximum_extents,0)
        if size:ioctl_fn(fd,FIEMAP,buffer,True)
        _,_,_,count,_,_=HEADER.unpack_from(buffer)
        if count>maximum_extents:raise ValueError("invalid FIEMAP count")
        covered=0;unsupported=0;last=(size==0);layout=[];aligned=True
        for i in range(count):
            logical,physical,length,_,_,flags,_,_,_=EXTENT.unpack_from(buffer,HEADER.size+i*EXTENT.size)
            if length<=0:raise ValueError("invalid FIEMAP length")
            end=min(size,logical+length)
            if logical<size:
                unsupported|=flags & ~1
                aligned=aligned and logical%512==0 and physical%512==0 and length%512==0
                if logical!=covered:aligned=False
                covered=end
                layout.append((logical,physical,end-logical,flags))
            if flags&1:last=True
        capped=not last and size>0
        try:
            hole=hole_fn(fd) if hole_fn else os.lseek(fd,0,os.SEEK_HOLE)
        except OSError:hole=None
        observed=os.pread(fd,min(maximum_bytes,size),0)
        header_metadata=None
        if len(observed)>=1052:
            version,last_page,badpages=struct.unpack_from("=III",observed,1024)
            header_metadata=dict(magic_hex=observed[-10:].hex(),version=version,last_page=last_page,badpages=badpages,uuid=str(uuid.UUID(bytes=observed[1036:1052])))
        after=os.fstat(fd)
        try:named=os.lstat(path)
        except FileNotFoundError:named=None
        stable=identity(before)==identity(after) and named is not None and identity(named)==identity(after)
        return dict(exists=True,stat=identity(after),stable=stable,coverage_complete=covered==size and aligned and not capped and unsupported==0,
                    scan_capped=capped,unsupported_flags=unsupported,hole_offset=hole,
                    observed_bytes=len(observed),header_metadata=header_metadata,sample_sha256=hashlib.sha256(observed).hexdigest(),
                    layout_hash=hashlib.sha256(json.dumps(layout,separators=(",",":")).encode()).hexdigest())
    finally:os.close(fd)


def main():
    p=argparse.ArgumentParser();p.add_argument("path");p.add_argument("--maximum-extents",type=int,required=True)
    p.add_argument("--maximum-bytes",type=int,required=True);p.add_argument("--maximum-output-bytes",type=int,required=True)
    a=p.parse_args();out=json.dumps(probe(a.path,maximum_extents=a.maximum_extents,maximum_bytes=a.maximum_bytes),sort_keys=True)
    if not 0<len(out.encode())<=a.maximum_output_bytes:raise ValueError("output bound exceeded")
    print(out)


if __name__=="__main__":main()
