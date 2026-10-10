#!/usr/bin/env python3
"""Finite bootstrap preflight and root-owned disk accounting; no deployment/signing."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

ROLES = {"storage", "control", "compute", "ci"}
DRV = r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._-]+[.]drv"
STORE_CONFIG = r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-nginx[.]conf"

# This child checks isolation before its first mount. Only namespace-private
# runtime directories and generated test TLS material are writable.
NGINX_NAMESPACE_TEST = r'''
import os
from pathlib import Path
import subprocess
import sys
mount, nginx, directory, parent_mount, parent_net = sys.argv[1:]
if (os.geteuid() != 0 or os.readlink('/proc/self/ns/mnt') == parent_mount
        or os.readlink('/proc/self/ns/net') == parent_net):
    raise SystemExit('Separate root mount/network engineering namespace required')
base = Path(directory)
material = {name: (base / name).read_bytes() for name in ['cert.pem', 'key.pem', 'nginx.conf']}
subprocess.run([mount, '--make-rprivate', '/'], check=True, timeout=5)
for path in ['/run', '/var/log', '/var/cache', '/tmp']:
    subprocess.run([mount, '-t', 'tmpfs', '-o', 'mode=0755,nosuid,nodev', 'tmpfs', path], check=True, timeout=5)
for path in ['/run/nginx', '/var/log/nginx', '/var/cache/nginx', '/run/qcl-nginx-test']:
    Path(path).mkdir(mode=0o700, parents=True, exist_ok=True)
test = Path('/run/qcl-nginx-test')
for name, data in material.items():
    with (test / name).open('xb') as stream:
        stream.write(data)
    (test / name).chmod(0o600)
subprocess.run([nginx, '-t', '-p', str(test) + '/', '-c', str(test / 'nginx.conf'), '-e', 'stderr'],
               check=True, timeout=30)
'''


class CommandFailure(RuntimeError):
    def __init__(self, record):
        self.record = record
        super().__init__("Bootstrap command failed; inspect retained stdout/stderr")


class _CommandOwner:
    """Per-supervisor ownership: baseline exclusion, ancestry, UID/birth and pidfds."""
    def __init__(self, deadline):
        self.deadline = deadline
        self.owned = {}
        self.fds = {}
        self.baseline = self.scan()

    def row(self, pid):
        try:
            path = Path('/proc') / str(pid)
            uid = path.stat().st_uid
            raw = (path / 'stat').read_bytes()
            if len(raw) > 4096:
                raise ValueError('proc identity bound')
            fields = raw.rsplit(b') ', 1)[1].split()
            return (int(fields[19]), int(fields[1]), fields[0], uid)
        except (FileNotFoundError, ProcessLookupError):
            return None

    def scan(self):
        result = {}
        for path in Path('/proc').iterdir():
            if time.monotonic() >= self.deadline:
                raise TimeoutError('ownership observation deadline')
            if not path.name.isdecimal():
                continue
            if len(result) >= 8192:
                raise ValueError('proc enumeration bound')
            row = self.row(int(path.name))
            if row is not None:
                result[int(path.name)] = row
        return result

    def observe(self):
        rows = self.scan()
        changed = True
        while changed:
            changed = False
            for pid, row in rows.items():
                key = (pid, row[0], row[3])
                if pid == os.getpid() or key in self.owned or self.baseline.get(pid, (None,))[0] == row[0]:
                    continue
                if any(old[0] == pid and old[1] == row[0] and old[2] != row[3] for old in self.owned):
                    raise ValueError('owned process UID drift')
                parent = rows.get(row[1])
                if row[1] == os.getpid() or parent is not None and (row[1], parent[0], parent[3]) in self.owned:
                    self.owned[key] = True
                    changed = True
        return {pid: row for pid, row in rows.items() if (pid, row[0], row[3]) in self.owned}

    def signal(self, sig):
        for pid, row in self.observe().items():
            if row[2] == b'Z':
                continue
            key = (pid, row[0], row[3])
            fd = self.fds.get(key)
            if fd is None:
                try:
                    fd = os.pidfd_open(pid, 0)
                except ProcessLookupError:
                    continue
                current = self.row(pid)
                if current is None or (current[0], current[3]) != (row[0], row[3]):
                    os.close(fd)
                    continue
                self.fds[key] = fd
            current = self.row(pid)
            if current is None or (current[0], current[3]) != (row[0], row[3]):
                continue
            try:
                signal.pidfd_send_signal(fd, sig, None, 0)
            except ProcessLookupError:
                pass

    def reap(self, leader):
        leader.poll()
        for pid, row in self.observe().items():
            if pid == leader.pid or row[2] != b'Z' or row[1] != os.getpid():
                continue
            current = self.row(pid)
            if current is None or current[0] != row[0] or current[3] != row[3]:
                continue
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass

    def close(self):
        for fd in self.fds.values():
            os.close(fd)


def _command_supervisor(status_fd, gate_fd, argv, end, work_end, cap):
    """Fresh private subreaper holds its identity until the caller's ACK."""
    import ctypes
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        raise RuntimeError('private command subreaper unavailable')
    owner = _CommandOwner(end)
    selector = selectors.DefaultSelector()
    streams = {'stdout': bytearray(), 'stderr': bytearray()}
    process = None
    failure = None
    cleaning = False

    def interrupted(signum, frame):
        if not cleaning:
            raise TimeoutError('caller cancelled command')

    def drain_ready():
        # Cleanup keeps the same combined cap and deadline as the work loop.
        nonlocal failure
        for key, _ in selector.select(0):
            chunk = os.read(key.fd, 65536)
            if not chunk:
                selector.unregister(key.fileobj)
                continue
            room = max(0, cap-sum(map(len, streams.values())))
            streams[key.data].extend(chunk[:room])
            if len(chunk) > room:
                failure = failure or 'output limit'
                # Further bytes exceed the evidence budget; do not busy-drain them.
                selector.unregister(key.fileobj)

    signal.signal(signal.SIGTERM, interrupted)
    os.set_blocking(gate_fd, False)
    try:
        # No command starts until the caller has pinned this supervisor's identity.
        while True:
            if time.monotonic() >= work_end:
                raise TimeoutError('deadline before command dispatch')
            try:
                permission = os.read(gate_fd, 1)
                if permission != b'g':
                    raise RuntimeError('caller cancelled before command dispatch')
                break
            except BlockingIOError:
                time.sleep(.001)
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        identity = owner.row(process.pid)
        if identity is None:
            raise RuntimeError('command leader identity unavailable')
        owner.owned[(process.pid, identity[0], identity[3])] = True
        for name in streams:
            pipe = getattr(process, name)
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        while True:
            if time.monotonic() >= work_end:
                failure = 'deadline'
                break
            try:
                if os.read(gate_fd, 1) == b'':
                    failure = 'caller cancelled command'
                    break
            except BlockingIOError:
                pass
            owner.reap(process)
            rows = owner.observe()
            if process.returncode is not None and not selector.get_map() and not rows:
                break
            for key, _ in selector.select(min(.01, max(0, work_end-time.monotonic()))):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                room = max(0, cap-sum(map(len, streams.values())))
                streams[key.data].extend(chunk[:room])
                if len(chunk) > room:
                    failure = 'output limit'
                    break
            if failure:
                break
    except BaseException as error:
        failure = failure or ('deadline' if isinstance(error, TimeoutError) else 'command supervision failed')
    finally:
        cleaning = True
        try:
            if process is not None:
                owner.signal(signal.SIGTERM)
                kill_at = min(end-.005, time.monotonic()+max(0, (end-time.monotonic())/3))
                while time.monotonic() < end-.005:
                    drain_ready()
                    owner.reap(process)
                    if not owner.observe():
                        break
                    if time.monotonic() >= kill_at:
                        owner.signal(signal.SIGKILL)
                    time.sleep(.001)
                owner.reap(process)
                if owner.observe() or process.returncode is None:
                    failure = (failure+'; ' if failure else '')+'cleanup uncertain'
        except BaseException:
            failure = (failure+'; ' if failure else '')+'cleanup uncertain'
        try:
            # Reaped producers can still leave queued bytes in both pipes.
            while selector.get_map() and time.monotonic() < end-.005:
                drain_ready()
                if selector.get_map():
                    time.sleep(.001)
        except BaseException:
            failure = (failure+'; ' if failure else '')+'cleanup uncertain'
        selector.close()
        if process is not None:
            process.stdout.close()
            process.stderr.close()
        owner.close()
    record = {'exit_code': process.returncode if process is not None else None, 'failure': failure,
              **{name: data.decode('utf-8', 'replace') for name, data in streams.items()}}
    raw = json.dumps(record, ensure_ascii=False).encode('utf-8')
    if len(raw) > 6*cap+65536:
        raise ValueError('supervisor response bound')
    os.set_blocking(status_fd, False)
    pending = memoryview(raw)
    while pending:
        if time.monotonic() >= end:
            raise TimeoutError('supervisor publication deadline')
        try:
            pending = pending[os.write(status_fd, pending[:65536]):]
        except BlockingIOError:
            time.sleep(.001)
    os.close(status_fd)
    # Parent closes or ACKs the gate after it reads the bounded completion record.
    while time.monotonic() < end:
        try:
            os.read(gate_fd, 1)
            break
        except BlockingIOError:
            time.sleep(.001)
    os.close(gate_fd)


def run(argv, seconds=60, cap=1024 * 1024):
    """Bounded command record with fresh per-command ownership supervision."""
    if not Path(argv[0]).is_absolute() or seconds <= 0 or cap <= 0:
        raise ValueError('Explicit absolute executable and positive budget required')
    start = time.monotonic()
    end = start+seconds
    reserve = min(.5, seconds/5)
    work_end = end-reserve
    status_read, status_write = os.pipe()
    gate_read, gate_write = os.pipe()
    process = None
    pidfd = None
    raw = bytearray()
    record = {'argv': argv, 'exit_code': None, 'failure': 'command supervision failed',
              'stdout': '', 'stderr': ''}
    try:
        # Reuse the owning same-file private child/ACK pattern, not a global subreaper.
        process = subprocess.Popen([str(Path(sys.executable).resolve()), str(Path(__file__).resolve()),
                                    '__command_supervisor', str(status_write), str(gate_read),
                                    json.dumps(argv), str(end), str(work_end), str(cap)],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, pass_fds=(status_write, gate_read),
                                   start_new_session=True)
        os.close(status_write); status_write = None
        os.close(gate_read); gate_read = None
        owner = _CommandOwner(end)
        identity = owner.row(process.pid)
        if identity is None or identity[1] != os.getpid():
            raise RuntimeError('private supervisor identity unavailable')
        pidfd = os.pidfd_open(process.pid, 0)
        current = owner.row(process.pid)
        if current is None or (current[0], current[3]) != (identity[0], identity[3]):
            raise RuntimeError('private supervisor identity drift')
        os.write(gate_write, b'g')
        os.set_blocking(status_read, False)
        selector = selectors.DefaultSelector()
        selector.register(status_read, selectors.EVENT_READ)
        try:
            while selector.get_map():
                if time.monotonic() >= end:
                    raise TimeoutError('deadline')
                for key, _ in selector.select(min(.01, max(0, end-time.monotonic()))):
                    chunk = os.read(key.fd, min(65536, 6*cap+65537-len(raw)))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    raw.extend(chunk)
                    if len(raw) > 6*cap+65536:
                        raise ValueError('supervisor response bound')
        finally:
            selector.close()
        result = json.loads(raw)
        if set(result) != {'exit_code', 'failure', 'stdout', 'stderr'}:
            raise ValueError('supervisor completion shape')
        record.update(result)
        os.write(gate_write, b'1')
        os.close(gate_write); gate_write = None
        process.wait(timeout=max(.001, end-time.monotonic()))
        if process.returncode != 0:
            record['failure'] = record['failure'] or 'command supervision failed'
    except BaseException as error:
        record['failure'] = 'deadline' if isinstance(error, TimeoutError) else (record['failure'] or 'command supervision failed')
    finally:
        for fd in (status_read, status_write, gate_read, gate_write):
            if fd is not None:
                os.close(fd)
        if process is not None and process.poll() is None:
            # Kernel handle pins ONLY this continuously owned private supervisor.
            if pidfd is not None:
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGTERM, None, 0)
                    process.wait(timeout=max(.001, end-time.monotonic()))
                except subprocess.TimeoutExpired:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
                    try:
                        process.wait(timeout=.001)
                    except subprocess.TimeoutExpired:
                        record['failure'] = (record['failure']+'; ' if record['failure'] else '')+'cleanup uncertain'
                except ProcessLookupError:
                    pass
            try:
                process.wait(timeout=max(.001, end-time.monotonic()))
            except subprocess.TimeoutExpired:
                record['failure'] = (record['failure']+'; ' if record['failure'] else '')+'cleanup uncertain'
            record['failure'] = record['failure'] or 'cleanup uncertain'
        if pidfd is not None:
            os.close(pidfd)
    if time.monotonic() >= end:
        record['failure'] = record['failure'] or 'deadline'
    if record['failure'] or record['exit_code'] != 0:
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


def namespace_prefix(value):
    """An operator explicitly selects root or supported user-namespace entry."""
    try:
        argv = json.loads(value)
    except (TypeError, ValueError) as error:
        raise ValueError("--nginx-namespace requires an explicit JSON argv array") from error
    if (not isinstance(argv, list) or not 1 <= len(argv) <= 32
            or not all(isinstance(arg, str) and arg and '\0' not in arg for arg in argv)
            or not Path(argv[0]).is_absolute() or sum(map(len, argv)) > 8192):
        raise ValueError("Namespace argv needs an absolute executable and bounded string arguments")
    return argv


def nginx_test_config(text, credentials):
    """Replace declared TLS paths, without reading production credentials."""
    if not isinstance(credentials, list):
        raise ValueError("Evaluated certificate credentials required")
    expected = set()
    for item in credentials:
        if (not isinstance(item, dict) or item.get("directive") not in ("ssl_certificate", "ssl_certificate_key")
                or not isinstance(item.get("path"), str) or not Path(item["path"]).is_absolute()):
            raise ValueError("Invalid evaluated certificate credential")
        expected.add((item["directive"], item["path"]))
    seen = set()
    def replace(match):
        words = shlex.split(match.group(2))
        if len(words) != 1 or (match.group(1), words[0]) not in expected:
            raise ValueError("Config certificate directive differs from evaluated credentials")
        seen.add((match.group(1), words[0]))
        name = "key.pem" if match.group(1) == "ssl_certificate_key" else "cert.pem"
        return match.group(1) + " /run/qcl-nginx-test/" + name + ";"
    output = re.sub(r"\b(ssl_certificate(?:_key)?)\s+([^;\n]+);", replace, text)
    if seen != expected:
        raise ValueError("Missing configured certificate directive in actual nginx config")
    return output


def check_nginx(value, built, openssl, mount, namespace, receipt):
    """Test actual generated bytes/executable; writer/gixy success is insufficient."""
    prefix = namespace_prefix(namespace)
    cfg = value["nginx"]
    executable = cfg.get("executable")
    if (not isinstance(executable, str)
            or not re.fullmatch(r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._-]+/bin/nginx", executable)):
        raise ValueError("Actual evaluated nginx executable required")
    command = shlex.split(cfg.get("exec_start", ""))
    if len(command) != 3 or command[:2] != [executable, "-c"]:
        raise ValueError("Actual nginx ExecStart must bind its executable and config")
    outputs = json.loads(built["stdout"])
    if (not isinstance(outputs, list) or len(outputs) != 1
            or outputs[0].get("drvPath") != cfg["targets"][0].removesuffix("^out")
            or not isinstance(outputs[0].get("outputs"), dict) or set(outputs[0]["outputs"]) != {"out"}):
        raise ValueError("Exactly the evaluated nginx config derivation output required")
    path = outputs[0]["outputs"]["out"]
    if not isinstance(path, str) or not re.fullmatch(STORE_CONFIG, path):
        raise ValueError("Actual nginx config must be the built store output")
    expected_path = cfg.get("config_file") if cfg.get("reload") is True else command[2]
    if path != expected_path or (cfg.get("reload") is True and command[2] != "/etc/nginx/nginx.conf"):
        raise ValueError("Built config differs from actual nginx ExecStart/etс source")
    for program in (executable, openssl, mount):
        if not program or not Path(program).is_absolute() or not os.access(program, os.X_OK):
            raise ValueError("Available absolute nginx/openssl/mount executables required")
    info = Path(path).lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
        raise ValueError("Actual nginx config must be a bounded regular file")
    raw = Path(path).read_bytes()
    text = nginx_test_config(raw.decode(), cfg.get("tls_credentials"))
    receipt["nginx_actual_config"] = {"path": path, "sha256": hashlib.sha256(raw).hexdigest(),
                                      "executable": executable, "exec_start": cfg["exec_start"],
                                      "test_sha256": hashlib.sha256(text.encode()).hexdigest(),
                                      "tls_substitutions": cfg["tls_credentials"]}
    with tempfile.TemporaryDirectory(prefix="qcl-nginx-engineering-") as temporary:
        directory = Path(temporary)
        (directory / "nginx.conf").write_text(text)
        receipt["nginx_test_tls"] = run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                                        "-keyout", str(directory / "key.pem"), "-out", str(directory / "cert.pem"),
                                        "-days", "1", "-subj", "/CN=localhost"])
        receipt["nginx_test"] = run([*prefix, str(Path(sys.executable).resolve()), "-c", NGINX_NAMESPACE_TEST,
                                     mount, executable, temporary, os.readlink("/proc/self/ns/mnt"),
                                     os.readlink("/proc/self/ns/net")])
    output = receipt["nginx_test"]["stdout"] + receipt["nginx_test"]["stderr"]
    counters = {severity: len(re.findall(r"\[" + severity + r"\]", output))
                for severity in ("warn", "error", "crit", "alert", "emerg")}
    receipt["nginx_severity_counters"] = counters
    if any(counters.values()) or "syntax is ok" not in output or "test is successful" not in output:
        raise ValueError("Strict actual nginx syntax test did not pass with zero severity counters")


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
    preflight.add_argument("--check-nginx", action="store_true", help="Build actual nginx.conf and run isolated nginx -t")
    preflight.add_argument("--nginx-namespace", help="Explicit JSON argv prefix entering root mount/network namespaces")
    preflight.add_argument("--openssl", default=shutil.which("openssl"), help="Absolute test-certificate generator")
    preflight.add_argument("--mount", default=shutil.which("mount"), help="Absolute namespace mount executable")
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
            result["nginx_test"] = "not_measured"
            result["nginx_severity_counters"] = "not_measured"
            if args.check_nginx:
                result["nginx_build"] = run([args.nix, "build", "--no-link", "--json", "--offline",
                                            "--no-write-lock-file", value["nginx"]["targets"][0]])
                check_nginx(value, result["nginx_build"], args.openssl, args.mount, args.nginx_namespace, result)
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
    if len(sys.argv) > 1 and sys.argv[1] == "__command_supervisor":
        _command_supervisor(int(sys.argv[2]), int(sys.argv[3]), json.loads(sys.argv[4]), float(sys.argv[5]), float(sys.argv[6]), int(sys.argv[7]))
    else:
        main()
