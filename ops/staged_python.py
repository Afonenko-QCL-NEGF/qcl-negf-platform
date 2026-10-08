"""Pure argv construction for a SHA-bound Python checker staged by its caller."""
import posixpath
import re


def staged_python_argv(interpreter, script_path, sha256, *, owner_uid=0, max_bytes=65536):
    """Return argv; do not read, stage, execute or contact the remote host.

    The loader checks an owner-only parent and read-only regular script before
    replacing itself with the same interpreter and ``-I -B script_path``.
    The caller owns staging, interpreter identity, time/output caps and logging.
    """
    for path in (interpreter, script_path):
        if (not isinstance(path, str) or not path.startswith('/') or '\0' in path
                or path.startswith('//') or posixpath.normpath(path) != path):
            raise ValueError('Canonical absolute interpreter and script paths required')
    if not isinstance(sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', sha256):
        raise ValueError('Exact lowercase SHA256 required')
    if type(owner_uid) is not int or owner_uid < 0:
        raise ValueError('Explicit nonnegative owner UID required')
    if type(max_bytes) is not int or not 0 < max_bytes <= 1048576:
        raise ValueError('Script byte cap must be between 1 and 1048576')
    # Only paths and public identity parameters are interpolated, never checker
    # bytes or its process-search patterns. argv is for exec, not a shell string.
    loader = f'''import hashlib,os,pathlib,stat
p=pathlib.Path({script_path!r});s=p.lstat();t=p.parent.lstat()
assert stat.S_ISREG(s.st_mode) and not p.is_symlink() and s.st_uid=={owner_uid} and stat.S_IMODE(s.st_mode)==0o400 and s.st_size<={max_bytes}
assert stat.S_ISDIR(t.st_mode) and not p.parent.is_symlink() and t.st_uid=={owner_uid} and stat.S_IMODE(t.st_mode)==0o700 and str(p.resolve(strict=True))==str(p)
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW);f=os.fstat(fd)
assert (f.st_dev,f.st_ino,f.st_uid,f.st_mode,f.st_size)==(s.st_dev,s.st_ino,s.st_uid,s.st_mode,s.st_size)
with os.fdopen(fd,'rb') as stream: data=stream.read({max_bytes}+1)
assert len(data)==s.st_size and hashlib.sha256(data).hexdigest()=={sha256!r}
def unchanged(a,b):
 return (a.st_dev,a.st_ino,a.st_uid,a.st_mode,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_uid,b.st_mode,b.st_size,b.st_mtime_ns,b.st_ctime_ns)
assert unchanged(p.lstat(),s) and unchanged(p.parent.lstat(),t)
os.execv({interpreter!r},[{interpreter!r},'-I','-B',str(p)])
'''
    return [interpreter, '-I', '-B', '-c', loader]
