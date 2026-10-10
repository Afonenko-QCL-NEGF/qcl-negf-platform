#!/usr/bin/env python3
"""Bounded read-only retained-tree oracle. No subprocess, policy or mutation."""
import array
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

LIMIT_KEYS = {"entries", "hash_bytes", "logical_bytes", "allocated_bytes", "output_bytes", "seconds"}


def inode_flags(fd):
    # Linux FS_IOC_GETFLAGS: actual read-only flag observation, no lsattr parsing.
    flags = array.array("L", [0])
    fcntl.ioctl(fd, 0x80086601, flags, True)
    return flags[0]


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def snapshot(root, limits, empty_lost_found=None):
    if type(limits) is not dict or set(limits) != LIMIT_KEYS or any(type(v) is not int or v <= 0 for v in limits.values()): raise ValueError("exact positive finite manifest limits required")
    root = Path(root)
    if not root.is_absolute() or root.resolve() != root or not stat.S_ISDIR(root.lstat().st_mode): raise ValueError("canonical no-symlink tree required")
    start = time.monotonic()
    entries, identities, groups, allocation = {}, {}, {}, {}
    hashed = logical = allocated = 0
    base = root.lstat()
    def bounded():
        if time.monotonic() - start > limits["seconds"]: raise ValueError("manifest deadline")
        if len(entries) > limits["entries"] or hashed > limits["hash_bytes"] or logical > limits["logical_bytes"] or allocated > limits["allocated_bytes"]: raise ValueError("manifest entry/byte/allocation cap")
    def visit(path, relative):
        nonlocal hashed, logical, allocated
        bounded()
        before = path.lstat()
        if before.st_dev != base.st_dev: raise ValueError("cross-filesystem retained entry")
        identities[relative] = (path, fingerprint(before))
        if relative == "lost+found" and empty_lost_found is not None:
            expected = {"dev": before.st_dev, "ino": before.st_ino, "uid": before.st_uid, "gid": before.st_gid, "mode": stat.S_IMODE(before.st_mode)}
            if type(empty_lost_found) is not dict or empty_lost_found != expected or not stat.S_ISDIR(before.st_mode) or os.listdir(path): raise ValueError("not exact empty admitted created lost+found")
            return
        kind = "directory" if stat.S_ISDIR(before.st_mode) else "file" if stat.S_ISREG(before.st_mode) else "symlink" if stat.S_ISLNK(before.st_mode) else None
        if kind is None: raise ValueError("unsupported special file")
        attrs = {name: base64.b64encode(os.getxattr(path, name, follow_symlinks=False)).decode() for name in sorted(os.listxattr(path, follow_symlinks=False))}
        item = {"type": kind, "mode": stat.S_IMODE(before.st_mode), "uid": before.st_uid, "gid": before.st_gid, "mtime_ns": before.st_mtime_ns, "xattrs": attrs}
        entries[relative] = item
        bounded()
        if kind == "directory": allocated += before.st_blocks * 512; bounded()
        if kind == "symlink": item["target"] = os.readlink(path)
        else:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | (os.O_DIRECTORY if kind == "directory" else 0))
            try:
                if fingerprint(os.fstat(fd)) != fingerprint(before): raise ValueError("entry raced before open")
                # Format-derived extents/index flags are not transferable semantics.
                if inode_flags(fd) & ~(0x80000 | 0x1000): raise ValueError("unsupported semantic inode flags")
                if kind == "file":
                    key = (before.st_dev, before.st_ino)
                    groups.setdefault(key, []).append(relative)
                    logical += before.st_size
                    allocation[relative] = before.st_blocks * 512
                    if len(groups[key]) == 1: allocated += before.st_blocks * 512
                    bounded()
                    digest = hashlib.sha256()
                    total = 0
                    while True:
                        chunk = os.read(fd, min(1048576, limits["hash_bytes"] - hashed + 1))
                        if not chunk: break
                        hashed += len(chunk); total += len(chunk); bounded(); digest.update(chunk)
                    if total != before.st_size: raise ValueError("file length changed")
                    item.update(size=total, sha256=digest.hexdigest())
                if fingerprint(os.fstat(fd)) != fingerprint(before): raise ValueError("entry changed during read")
            finally: os.close(fd)
        if kind == "directory":
            names = []
            with os.scandir(path) as children:
                for child in children:
                    names.append(child.name)
                    if len(entries) + len(names) > limits["entries"]: raise ValueError("directory enumeration entry cap")
                    bounded()
            for name in sorted(names):
                visit(path / name, name if relative == "." else relative + "/" + name)
        if fingerprint(path.lstat()) != fingerprint(before): raise ValueError("entry topology/metadata changed")
    visit(root, ".")
    for key, names in groups.items():
        names.sort()
        if identities[names[0]][0].lstat().st_nlink != len(names): raise ValueError("external retained hardlink")
        for name in names: entries[name]["hardlinks"] = names
    for path, observed in identities.values():
        if fingerprint(path.lstat()) != observed: raise ValueError("retained source changed after enumeration")
    result = {"schema": 1, "identity": {"dev": base.st_dev, "ino": base.st_ino}, "entries": entries,
              "allocation": allocation, "summary": {"entries": len(entries), "hash_bytes": hashed, "logical_bytes": logical, "allocated_bytes": allocated}}
    if len(json.dumps(result, sort_keys=True, allow_nan=False).encode()) > limits["output_bytes"]: raise ValueError("manifest output cap")
    return result


def equal(source, destination):
    if source["entries"] != destination["entries"]: return False
    for name, amount in source["allocation"].items():
        size = source["entries"][name]["size"]
        if amount < size and destination["allocation"][name] >= size: return False
    return True


def subset(source, partial):
    # Existing partial bytes may differ, but unknown paths/types are never deleted.
    return all(name in source["entries"] and item["type"] == source["entries"][name]["type"]
               for name, item in partial["entries"].items())


def main():
    raw = sys.stdin.buffer.read(1048577)
    if len(raw) > 1048576: raise ValueError("request cap")
    request = json.loads(raw)
    if request.get("action", "snapshot") == "snapshot": result = snapshot(request["root"], request["limits"], request.get("empty_lost_found"))
    elif request["action"] == "equal": result = {"equal": equal(request["source"], request["destination"])}
    elif request["action"] == "subset": result = {"subset": subset(request["source"], request["partial"])}
    else: raise ValueError("unknown read-only manifest action")
    print(json.dumps(result, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    try: main()
    except (ValueError, OSError, KeyError, TypeError) as error:
        print("manifest refusal: " + str(error), file=sys.stderr); sys.exit(1)
