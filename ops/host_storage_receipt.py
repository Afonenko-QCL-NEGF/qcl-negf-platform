#!/usr/bin/env python3
"""Bounded local cutover receipt IO only; no native operations or resource policy."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

PHASES = ("admitted", "gate_disable_intent", "gate_disabled", "copy_started", "copy_verified",
          "rename_intent", "source_renamed", "final_activation_intent", "final_verified",
          "reopening_intent", "reopened", "complete", "rollback_intent", "rolled_back", "reconcile_required")
IDENTITY = {"attempt_id", "host_id", "boot_id", "source_ref", "storage_id", "storage_digest",
            "source", "rollback", "stage", "lv_uuid", "fs_uuid", "source_dev", "source_ino", "parent_dev", "parent_ino"}
UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")


def positive(value):
    if type(value) is not int or value <= 0: raise ValueError("positive finite integer required")
    return value


def validate_identity(identity):
    if type(identity) is not dict or set(identity) != IDENTITY: raise ValueError("exact immutable identity required")
    for key, value in identity.items():
        if key.endswith("_dev") or key.endswith("_ino"): positive(value)
        elif type(value) is not str or not value or len(value) > 4096: raise ValueError("unknown immutable identity")
    if not re.fullmatch(r"[0-9a-f]{40}", identity["source_ref"]): raise ValueError("component ref required")
    if not re.fullmatch(r"[0-9a-f]{40}", identity["storage_digest"]): raise ValueError("PVE digest required")
    if not UUID.fullmatch(identity["fs_uuid"]) or identity["fs_uuid"] == "00000000-0000-0000-0000-000000000000": raise ValueError("canonical nonzero UUID required")
    for key in ("source", "rollback", "stage"):
        path = Path(identity[key])
        if not path.is_absolute() or str(path) != identity[key] or ".." in path.parts: raise ValueError("canonical absolute identity required")


def encode(value, maximum):
    positive(maximum)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode() + b"\n"
    if len(raw) > maximum: raise ValueError("receipt/manifest byte cap exceeded")
    return raw


def owned_parent(path):
    path = Path(path)
    if not path.is_absolute() or str(path) != os.path.abspath(path): raise ValueError("canonical receipt path required")
    parent = path.parent
    if parent.resolve() != parent: raise ValueError("symlink receipt parent refused")
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.geteuid(): raise ValueError("owned parent0700 required")
    return path


def read(path, maximum):
    positive(maximum)
    path = owned_parent(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > maximum: raise ValueError("owned bounded record0600 required")
        raw = bytearray()
        while len(raw) <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not chunk: break
            raw.extend(chunk)
        if len(raw) > maximum or (os.fstat(fd).st_ino, os.fstat(fd).st_size, os.fstat(fd).st_mtime_ns, os.fstat(fd).st_ctime_ns) != (info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns): raise ValueError("record changed or capped")
        value = json.loads(raw, parse_constant=lambda x: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
        return value, hashlib.sha256(raw).hexdigest()
    finally: os.close(fd)


def inspect(path, identity, max_bytes):
    validate_identity(identity)
    positive(max_bytes)
    try: value, digest = read(path, max_bytes)
    except FileNotFoundError: return {"record": None, "sha256": None}
    if type(value) is not dict or set(value) != {"schema", "identity", "phase", "payload", "reopening"} or value["schema"] != 1 or value["identity"] != identity or value["phase"] not in PHASES or type(value["payload"]) is not dict: raise ValueError("untrusted/corrupt immutable receipt")
    marker = value["reopening"]
    if marker is not None and (type(marker) is not dict or set(marker) != {"intended_tree"} or marker["intended_tree"] not in ("new_final", "restored_original")): raise ValueError("corrupt sticky marker")
    if value["phase"] in ("reopening_intent", "reopened", "complete") and marker is None: raise ValueError("missing sticky reopening marker")
    if marker and value["phase"] not in ("reopening_intent", "reopened", "complete", "reconcile_required"): raise ValueError("downgraded sticky reopening marker")
    return {"record": value, "sha256": digest}


def atomic(path, value, maximum):
    path = owned_parent(path)
    raw = encode(value, maximum)
    if path.exists(): read(path, maximum)  # never replace an unowned/symlink record
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(raw); out.flush(); os.fsync(out.fileno())
        os.replace(temporary, path)
        os.fsync(directory)
        observed, digest = read(path, maximum)
        if observed != value or digest != hashlib.sha256(raw).hexdigest(): raise ValueError("durable readback mismatch")
        return {"sha256": digest, "path": str(path), "bytes": len(raw)}
    finally:
        os.close(directory)
        try: os.unlink(temporary)
        except FileNotFoundError: pass


def transition(path, identity, phase, payload, max_bytes, expected_sha256=None, *, intended_tree=None):
    if phase not in PHASES or type(payload) is not dict: raise ValueError("finite phase/payload required")
    old = inspect(path, identity, max_bytes)
    if old["sha256"] != expected_sha256: raise ValueError("receipt digest changed; no retry")
    record = old["record"]
    marker = record["reopening"] if record else None
    previous = record["phase"] if record else None
    if previous is None:
        if phase != "admitted" or expected_sha256 is not None: raise ValueError("missing mutated receipt; reconciliation required")
    elif marker:
        if phase not in {"reopened", "complete", "reconcile_required"} or (previous == "complete" and phase != "reconcile_required") or (previous == "reconcile_required" and phase != "reconcile_required"): raise ValueError("sticky reopening forbids downgrade/retry")
        if phase == "complete" and previous != "reopened": raise ValueError("observed reopening required")
    elif phase == "reconcile_required": pass
    elif phase == "rollback_intent":
        if previous in ("admitted", "rolled_back", "rollback_intent", "reconcile_required"): raise ValueError("no rollback permission")
    elif phase == "rolled_back":
        if previous != "rollback_intent": raise ValueError("rollback intent required")
    elif phase == "reopening_intent":
        if previous not in ("final_verified", "rolled_back") or intended_tree != ("new_final" if previous == "final_verified" else "restored_original"): raise ValueError("verified intended tree required")
        marker = {"intended_tree": intended_tree}
    else:
        normal = PHASES[:12]
        if previous not in normal or normal.index(previous) + 1 >= len(normal) or normal[normal.index(previous)+1] != phase: raise ValueError("phase skip/downgrade refused")
    if intended_tree is not None and phase != "reopening_intent": raise ValueError("marker only at reopening intent")
    retained = record["payload"] if record else {}
    for key in ("original_storage", "foreign", "window", "manifest", "source_dev", "source_ino", "parent_dev", "parent_ino", "rollback", "mountpoint_dev", "mountpoint_ino"):
        if key in payload and key in retained and payload[key] != retained[key]: raise ValueError("immutable receipt evidence changed")
    value = {"schema": 1, "identity": identity, "phase": phase, "payload": retained | payload, "reopening": marker}
    atomic(path, value, max_bytes)
    return inspect(path, identity, max_bytes)


def persist_manifest(path, manifest, max_bytes):
    if type(manifest) is not dict: raise ValueError("manifest object required")
    return atomic(path, manifest, max_bytes)


def main():
    raw = sys.stdin.buffer.read(1048577)
    if len(raw) > 1048576: raise ValueError("request cap")
    request = json.loads(raw)
    action = request.pop("action")
    if action == "inspect": result = inspect(**request)
    elif action == "transition": result = transition(**request)
    elif action == "persist_manifest": result = persist_manifest(**request)
    elif action == "read_manifest":
        value, digest = read(request["path"], request["max_bytes"])
        if digest != request["sha256"]: raise ValueError("retained manifest changed")
        result = {"manifest": value, "sha256": digest}
    elif action == "sync_manifest":
        value, digest = read(request["path"], request["max_bytes"])
        result = atomic(request["path"], value, request["max_bytes"])
        if result["sha256"] != request["sha256"] or result["sha256"] != digest: raise ValueError("manifest readback mismatch")
    else: raise ValueError("unknown receipt IO action")
    print(json.dumps(result, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    try: main()
    except (ValueError, OSError, KeyError, TypeError) as error:
        print("receipt refusal: " + str(error), file=sys.stderr); sys.exit(1)
