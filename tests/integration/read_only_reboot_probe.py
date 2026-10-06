"""Read existing controller test receipts; never create or repair them.

The host sends these exact saved bytes in a hash-verified Python envelope before
and after a bounded reboot, before any writable local_lab probe is rerun.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import socket


def read_receipt(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Require an existing regular receipt: {path}")
    before = path.stat()
    body = path.read_bytes()
    after = path.stat()
    fields = ("st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_uid", "st_gid")
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        raise ValueError("Receipt changed while reading")
    return {"path": str(path), "sha256": hashlib.sha256(body).hexdigest(),
            "body": body.decode(), **{field: getattr(after, field) for field in fields}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--domain-uuid", required=True)
    parser.add_argument("--image-sha256", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"qcl-[a-z0-9][a-z0-9-]{1,30}", args.namespace):
        raise ValueError("Require a lab namespace")
    if not re.fullmatch(r"[0-9a-f]{64}", args.image_sha256):
        raise ValueError("Require an immutable image hash")
    uuid = Path("/sys/class/dmi/id/product_uuid").read_text().strip().lower()
    if uuid != args.domain_uuid or socket.gethostname() != "control":
        raise ValueError("Guest identity differs from the owned controller")
    state = read_receipt(Path("/var/lib/qcl-negf-state") / (args.namespace + "-durable-probe.json"))
    if json.loads(state["body"]) != {"namespace": args.namespace, "role": "control",
                                    "image_sha256": args.image_sha256}:
        raise ValueError("Existing state receipt has another identity")
    user = pwd.getpwnam("qcl-negf")
    if user.pw_uid != 3000 or user.pw_gid != 3000:
        raise ValueError("Shared scientific UID/GID differ from the contract")
    previous_uid, previous_gid = os.geteuid(), os.getegid()
    try:
        os.setegid(user.pw_gid)
        os.seteuid(user.pw_uid)
        shared = read_receipt(Path("/srv/qcl-negf/jobs") / (args.namespace + "-uid3000-probe.json"))
    finally:
        os.seteuid(previous_uid)
        os.setegid(previous_gid)
    if shared["body"] != args.namespace or shared["st_uid"] != 3000:
        raise ValueError("Existing NFS receipt has another identity")
    print(json.dumps({"schema": "qcl-local-lab-read-only-reboot.v1",
                      "producer_sha256": globals().get("_producer_sha256", "not_recorded"),
                      "domain_uuid": uuid,
                      "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                      "state": state, "shared": shared}))


if __name__ == "__main__":
    main()
