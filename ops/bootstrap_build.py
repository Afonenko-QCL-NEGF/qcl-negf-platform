#!/usr/bin/env python3
"""Finite bootstrap preflight and root-owned disk accounting; no deployment/signing."""
import argparse
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time

ROLES = {"storage", "control", "compute", "ci"}
DRV = r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._-]+[.]drv"


class CommandFailure(RuntimeError):
    def __init__(self, record):
        self.record = record
        super().__init__("Bootstrap command failed; inspect retained stdout/stderr")


def run(argv, seconds=60, cap=1024 * 1024):
    """Combined streaming bound, deadline, and unconditional owned-group cleanup."""
    if not Path(argv[0]).is_absolute() or seconds <= 0 or cap <= 0:
        raise ValueError("Explicit absolute executable and positive budget required")
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    poller = selectors.DefaultSelector()
    for name in streams:
        poller.register(getattr(process, name), selectors.EVENT_READ, name)
    deadline = time.monotonic() + seconds
    failure = None
    try:
        while poller.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "deadline"
                break
            for key, _ in poller.select(min(remaining, 0.1)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    poller.unregister(key.fileobj)
                    continue
                room = cap - sum(map(len, streams.values()))
                streams[key.data].extend(chunk[:room])
                if len(chunk) > room:
                    failure = "output limit"
                    break
            if failure:
                break
        if not failure:
            try:
                process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                failure = "deadline"
    finally:
        # Descendants can retain pipes after the immediate parent has exited.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        poller.close()
        process.stdout.close()
        process.stderr.close()
    record = {"argv": argv, "exit_code": process.returncode, "failure": failure,
              **{name: data.decode("utf-8", "replace") for name, data in streams.items()}}
    if failure or process.returncode != 0:
        raise CommandFailure(record)
    return record


def validate_preflight(value):
    if not isinstance(value, dict) or not isinstance(value.get("roles"), dict):
        raise ValueError("Invalid preflight object")
    if set(value.get("roles", {})) != ROLES or not all(
            isinstance(path, str) and re.fullmatch(DRV, path) for path in value["roles"].values()):
        raise ValueError("Exactly four evaluated production roles required")
    nginx = value.get("nginx", {})
    if not isinstance(nginx, dict):
        raise ValueError("Invalid nginx preflight object")
    if nginx.get("enabled") is not True or nginx.get("validated") is not True:
        raise ValueError("Strict validated control nginx configuration required")
    targets = nginx.get("targets")
    if not isinstance(targets, list) or len(targets) != 1 or not isinstance(targets[0], str) or not re.fullmatch(r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-nginx[.]conf[.]drv\^out", targets[0]):
        raise ValueError("Exactly one nginx.conf derivation output required")
    return value


def account(roots, images, limit, du):
    if os.geteuid() != 0:
        raise ValueError("Complete release/history accounting requires root")
    roots = [Path(path) for path in roots]
    images = [Path(path) for path in images]
    if not roots or len(set(roots)) != len(roots) or len(set(images)) != len(images) or limit <= 0:
        raise ValueError("Unique accounting roots/images and positive budget required")
    for root in roots:
        if not root.is_absolute() or root.is_symlink() or not root.is_dir():
            raise ValueError("Accounting roots must be real absolute directories")
    holes = 0
    records = []
    identities = set()
    def fingerprint(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_blocks, info.st_mtime_ns, info.st_ctime_ns)
    for image in images:
        info = image.lstat()
        if not image.is_absolute() or not stat.S_ISREG(info.st_mode) or image.suffix != ".qcow2" or not any(
                image.resolve().is_relative_to(root.resolve()) for root in roots):
            raise ValueError("QCOW images must be regular files inside accounted roots")
        identity = (info.st_dev, info.st_ino)
        if identity in identities:
            raise ValueError("Duplicate QCOW inode")
        identities.add(identity)
        extra = max(0, info.st_size - info.st_blocks * 512)
        holes += extra
        records.append({"path": str(image), "resolved_path": str(image.resolve()),
                        "logical_bytes": info.st_size, "allocated_bytes": info.st_blocks * 512,
                        "sparse_extra_bytes": extra, "fingerprint": fingerprint(info)})
    # One invocation deduplicates shared hardlinks across every root; no history exclusion.
    record = run([du, "-B1", "-s", "--", *map(str, roots)])
    for image, before in zip(images, records):
        if fingerprint(image.lstat()) != before["fingerprint"] or str(image.resolve()) != before["resolved_path"]:
            raise ValueError("QCOW image changed during accounting")
    lines = record["stdout"].splitlines()
    if len(lines) != len(roots):
        raise ValueError("Incomplete du result")
    sizes = []
    for line, root in zip(lines, roots):
        size, separator, path = line.partition("\t")
        if not separator or path != str(root) or not size.isdecimal():
            raise ValueError("Invalid du result")
        sizes.append(int(size))
    allocated = sum(sizes)
    total = allocated + holes
    if total > limit:
        raise ValueError("Aggregate disk budget exceeded")
    return {"allocated_bytes": allocated, "sparse_extra_bytes": holes,
            "combined_bytes": total, "limit_bytes": limit, "images": records, "roots": list(map(str, roots)), "du": record}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", required=True, type=Path)
    sub = parser.add_subparsers(dest="operation", required=True)
    preflight = sub.add_parser("preflight")
    preflight.add_argument("--site", required=True, type=Path)
    preflight.add_argument("--nix", required=True)
    preflight.add_argument("--check-nginx", action="store_true", help="Build only the strict nginx.conf output")
    usage = sub.add_parser("account")
    usage.add_argument("--root", action="append", required=True, type=Path)
    usage.add_argument("--image", action="append", default=[], type=Path)
    usage.add_argument("--limit-bytes", required=True, type=int)
    usage.add_argument("--du", required=True)
    args = parser.parse_args()
    result = {"schema": "qcl.bootstrap-preflight.v1", "operation": args.operation, "status": "failed"}
    try:
        if args.operation == "account":
            result.update(account(args.root, args.image, args.limit_bytes, args.du))
        else:
            if not args.site.is_absolute():
                raise ValueError("Private site must be absolute")
            expression = Path(__file__).resolve().parents[1] / "nix/site-preflight.nix"
            record = run([args.nix, "eval", "--json", "--impure", "--offline", "--no-write-lock-file",
                          "--file", str(expression), "--apply", "f: f " + json.dumps(str(args.site))])
            result["evaluation"] = record
            value = validate_preflight(json.loads(record["stdout"]))
            result["configuration"] = value
            result["nginx_build"] = "not_measured"
            result["nginx_severity_counters"] = "not_measured"
            if args.check_nginx:
                result["nginx_build"] = run([args.nix, "build", "--no-link", "--json", "--offline",
                                            "--no-write-lock-file", value["nginx"]["targets"][0]])
        result["status"] = "evaluation_only" if args.operation == "preflight" and not args.check_nginx else "pass"
    except CommandFailure as error:
        result["failed_command"] = error.record
    except (ValueError, OSError) as error:
        result["error"] = str(error)
    # O_EXCL keeps earlier evidence. chmod defeats an inherited restrictive umask.
    with args.receipt.open("x") as stream:
        os.chmod(args.receipt, 0o600)
        json.dump(result, stream, indent=2)
        stream.write("\n")
    if result["status"] not in ("pass", "evaluation_only"):
        raise SystemExit("Bootstrap check failed; inspect receipt diagnostics")


if __name__ == "__main__":
    main()
