#!/usr/bin/env python3
"""Host-initiated, checksum-pinned image staging invoked by proxmox-images.yml."""

import argparse
import base64
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading

ROLES = ("storage", "control", "compute", "ci")
CHUNK_BYTES = 65536
IMAGE_PATH = r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._-]+/[A-Za-z0-9._-]+[.]qcow2"


def validate_image(image):
    if (not isinstance(image, dict)
            or not re.fullmatch(IMAGE_PATH, str(image.get("image_path", "")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(image.get("image_sha256", "")))
            or type(image.get("image_bytes")) is not int or image["image_bytes"] < 72):
        raise ValueError("Images require a Nix-store QCOW2 path, SHA-256 and measured byte count")


def validate_header(header):
    if len(header) < 8 or header[:4] != b"QFI\xfb" or struct.unpack(">I", header[4:8])[0] not in (2, 3):
        raise ValueError("Expected a QCOW2 version 2 or version 3 header")


def file_name(role, image):
    if role not in ROLES:
        raise ValueError("Unknown Proxmox VM role")
    validate_image(image)
    return f"qcl-negf-{role}-{image['image_sha256']}.qcow2"


def provider_inputs(base, images, datastore):
    if (not isinstance(base, dict) or not isinstance(base.get("vms"), dict)
            or set(base["vms"]) != set(ROLES) or not isinstance(images, dict)
            or set(images) not in (set(ROLES), set(ROLES) | {"arch-worker"})
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", datastore)):
        raise ValueError("Require all four Proxmox roles and an explicit image datastore")
    result = copy.deepcopy(base)
    for role in ROLES:
        image = images[role]
        name = file_name(role, image)
        vm = result["vms"][role]
        if not isinstance(vm, dict):
            raise ValueError("Invalid VM role object")
        if vm.get("image_sha256", image["image_sha256"]) != image["image_sha256"]:
            raise ValueError("Provider inputs and image manifest have different SHA-256 identities")
        vm.pop("image_path", None)
        vm["image_sha256"] = image["image_sha256"]
        vm["image_file_id"] = f"{datastore}:import/{name}"
    result["image_datastore"] = datastore
    return result


def ssh_command(source, image_path):
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", str(source.get("host", "")))
            or not re.fullmatch(r"[a-z_][a-z0-9_-]*", str(source.get("user", "")))
            or type(source.get("port")) is not int or not 1 <= source["port"] <= 65535
            or not re.fullmatch(IMAGE_PATH, image_path)):
        raise ValueError("Invalid SSH source or image path")
    for field in ("identity_file", "known_hosts_file"):
        path = source.get(field)
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("/nix/store/"):
            raise ValueError("SSH credentials and pinned host keys require runtime absolute paths")
    options = [
        "BatchMode=yes", "IdentitiesOnly=yes", "IdentityAgent=none", "ForwardAgent=no",
        "StrictHostKeyChecking=yes", "UpdateHostKeys=no", "GlobalKnownHostsFile=/dev/null",
        "KnownHostsCommand=none", f"UserKnownHostsFile={source['known_hosts_file']}",
        "PreferredAuthentications=publickey", "HostbasedAuthentication=no", "GSSAPIAuthentication=no",
        "PasswordAuthentication=no", "KbdInteractiveAuthentication=no", "ConnectTimeout=30",
        "ControlMaster=no", "ControlPath=none", "LogLevel=ERROR",
    ]
    command = ["ssh", "-F", "/dev/null", "-T", "-n", "-i", source["identity_file"],
               "-p", str(source["port"])]
    for option in options:
        command.extend(("-o", option))
    return command + [f"{source['user']}@{source['host']}", f"qcl-negf-image-read {image_path}"]


def verify_existing(path, image):
    if path.is_symlink() or path.resolve(strict=True) != path:
        raise ValueError("Existing image must not be a symlink")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != image["image_bytes"]:
            raise ValueError("Existing immutable image has a different byte count")
        digest = hashlib.sha256()
        first = True
        while block := source.read(CHUNK_BYTES):
            if first:
                validate_header(block[:8])
                first = False
            digest.update(block)
        if digest.hexdigest() != image["image_sha256"]:
            raise ValueError("Existing immutable image has a different SHA-256")


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def transfer_image(image, destination, command, *, reserve_bytes=64 * 1024**2, timeout_seconds=1800):
    validate_image(image)
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        verify_existing(destination, image)
        return False
    if shutil.disk_usage(destination.parent).free < image["image_bytes"] + reserve_bytes:
        raise OSError("Insufficient host staging space for the complete image and reserve")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".qcl-image-", suffix=".partial",
                                                dir=destination.parent)
    temporary = Path(temporary_name)
    process = None
    timer = None
    published = False
    expired = threading.Event()
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, start_new_session=True)

        def cancel_timeout():
            expired.set()
            if process.poll() is None:
                process.kill()

        timer = threading.Timer(timeout_seconds, cancel_timeout)
        timer.daemon = True
        timer.start()
        digest = hashlib.sha256()
        total = 0
        header = bytearray()
        while block := process.stdout.read(CHUNK_BYTES):
            total += len(block)
            if total > image["image_bytes"]:
                raise ValueError("SSH stream exceeds the reviewed image byte count")
            if len(header) < 8:
                header.extend(block[:8 - len(header)])
            digest.update(block)
            remaining = memoryview(block)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("Incomplete image write")
                remaining = remaining[written:]
        result = process.wait(timeout=5)
        if expired.is_set():
            raise TimeoutError("Image transfer exceeded its finite wall-time budget")
        if result != 0:
            raise RuntimeError(f"Restricted image SSH reader failed with exit code {result}")
        if total != image["image_bytes"]:
            raise ValueError("SSH stream is incomplete: reviewed image byte count differs")
        if digest.hexdigest() != image["image_sha256"]:
            raise ValueError("SSH stream SHA-256 differs from the reviewed image")
        validate_header(header)
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        # link is an exclusive, same-filesystem publication: never overwrite an
        # existing object even if another operator publishes while we stream.
        os.link(temporary, destination)
        published = True
        temporary.unlink()
        sync_directory(destination.parent)
        return True
    except BaseException:
        if published:
            destination.unlink(missing_ok=True)
        raise
    finally:
        if timer is not None:
            timer.cancel()
        if process is not None:
            if process.poll() is None:
                process.kill()
            if process.stdout is not None:
                process.stdout.close()
            process.wait(timeout=5)
        if descriptor is not None:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def require_private_file(path):
    path = Path(path)
    if path.is_symlink() or path.resolve(strict=True) != path:
        raise ValueError("SSH credential path must be canonical and must not be a symlink")
    metadata = path.stat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size == 0):
        raise ValueError("SSH identity and pinned known_hosts must be root:root mode 0600 nonempty files")


def require_owned_directory(path):
    if not path.is_absolute() or path.is_symlink() or path.resolve(strict=True) != path:
        raise ValueError("Image datastore directory must be canonical and must not be a symlink")
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        # run() requires root; checking the caller's ownership also lets this
        # filesystem primitive be exercised without a privileged test runner.
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise ValueError("Image datastore directory must be root-owned and not writable by other users")
    finally:
        os.close(fd)


def prepare_import_directory(directory, *, create=False):
    directory = Path(directory)
    if directory.name != "import":
        raise ValueError("Only the datastore's exact import directory may be created")
    require_owned_directory(directory.parent)
    if directory.exists() or directory.is_symlink():
        require_owned_directory(directory)
        return False
    if not create:
        return True
    directory.mkdir(mode=0o755)
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fchmod(fd, 0o755)
            os.fsync(fd)
        finally:
            os.close(fd)
        require_owned_directory(directory)
        sync_directory(directory.parent)
    except BaseException:
        directory.rmdir()
        raise
    return True


def storage_path(file_id):
    result = subprocess.run(["pvesm", "path", file_id], capture_output=True, text=True, check=True,
                            timeout=30)
    path = Path(result.stdout.strip())
    if not path.is_absolute() or path.name != file_id.split("/", 1)[1]:
        raise ValueError("Proxmox datastore did not resolve the expected import filename")
    prepare_import_directory(path.parent, create=False)
    return path


def run(request, check=False):
    if os.geteuid() != 0:
        raise ValueError("Run image staging on the Proxmox host as root through Ansible")
    source, images, datastore = request["source"], request["images"], request["datastore"]
    prepared = provider_inputs(request["base"], images, datastore)
    for field in ("identity_file", "known_hosts_file"):
        require_private_file(source[field])
    timeout = request.get("timeout_seconds", 1800)
    reserve = request.get("reserve_bytes", 64 * 1024**2)
    if type(timeout) is not int or not 30 <= timeout <= 3600 or type(reserve) is not int or reserve < 0:
        raise ValueError("Require a finite 30..3600 second transfer budget and nonnegative storage reserve")
    destinations = {role: storage_path(prepared["vms"][role]["image_file_id"]) for role in ROLES}
    commands = {role: ssh_command(source, images[role]["image_path"]) for role in ROLES}
    directories = sorted({path.parent for path in destinations.values()})
    missing = [str(path) for path in directories if prepare_import_directory(path, create=False)]
    if check:
        return {"changed": bool(missing), "checked": True, "create_import_directories": missing}
    lock_fd = os.open("/run/lock/qcl-negf-image-stage.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(lock_fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0
                or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise ValueError("Image staging lock must be a root:root mode 0600 regular file")
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        changed = False
        for directory in directories:
            changed = prepare_import_directory(directory, create=True) or changed
        for role in ROLES:
            changed = transfer_image(images[role], destinations[role], commands[role],
                                     reserve_bytes=reserve, timeout_seconds=timeout) or changed
        return {"changed": changed, "checked": False, "provider_inputs": prepared}
    finally:
        os.close(lock_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, help="Base64 JSON metadata; never secret bytes")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    request = json.loads(base64.b64decode(args.request, validate=True))
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(InterruptedError("Staging cancelled")))
    print(json.dumps(run(request, args.check), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError) as error:
        print(f"Image staging failed: {error}", file=sys.stderr)
        sys.exit(1)
