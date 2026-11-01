"""Bounded reads from root-owned, non-writable, symlink-free namespaces."""
from contextlib import contextmanager
import os
from pathlib import Path
import stat

def protected_parts(path):
    if not isinstance(path, (str, Path)):
        raise ValueError("Protected path must be absolute")
    path = str(path)
    if not path.startswith("/") or any(part in ("", ".", "..") for part in path.split("/")[1:]):
        raise ValueError("Protected path must be absolute without traversal")
    return path.split("/")[1:]


def trusted_stat(info, *, directory):
    if info.st_uid != 0 or info.st_mode & 0o022 or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ValueError("Unprotected namespace owner/mode/type")


@contextmanager
def protected_directory(path, *, budget=None):
    parts = [] if str(path) == "/" else protected_parts(path)
    descriptor = None
    primary = None
    try:
        if budget:budget.before()
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        if budget:budget.before()
        trusted_stat(os.fstat(descriptor), directory=True)
        for part in parts:
            if budget:budget.before()
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            previous = descriptor
            # Own the new FD before the previous close can fail. The previous
            # numeric FD is never retried after an uncertain close outcome.
            descriptor = following
            os.close(previous)
            if budget:budget.before()
            trusted_stat(os.fstat(descriptor), directory=True)
        yield descriptor
    except BaseException as error:
        primary = error
        raise
    finally:
        if descriptor is not None:
            try:os.close(descriptor)
            except BaseException as cleanup:
                if primary is None:raise
                primary.add_note('protected directory close also raised '+type(cleanup).__name__[:128])


def read_protected_file(path, limit=65536, *, budget=None):
    if budget:budget.reserve(min(4096,limit+1))
    parts = protected_parts(path)
    first_read=True
    with protected_directory("/" + "/".join(parts[:-1]),budget=budget) as parent:
        if budget:budget.before()
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        primary = None
        try:
            if budget:budget.before()
            trusted_stat(os.fstat(descriptor), directory=False)
            chunks = bytearray()
            while len(chunks) <= limit:
                n=min(4096,limit+1-len(chunks))
                if budget and not first_read:budget.reserve(n)
                first_read=False
                chunk = os.read(descriptor,n)
                if budget:budget.actual_bytes+=len(chunk);budget.before()
                if not chunk:
                    return bytes(chunks)
                chunks.extend(chunk)
            raise ValueError("Protected metadata exceeds bound")
        except BaseException as error:
            primary = error
            raise
        finally:
            try:os.close(descriptor)
            except BaseException as cleanup:
                if primary is None:raise
                primary.add_note('protected file close also raised '+type(cleanup).__name__[:128])
