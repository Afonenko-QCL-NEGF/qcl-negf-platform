#!/usr/bin/env python3
"""Private local KVM orchestration. No host sudo, production mutation or solver."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
ROLES = {"control": 10, "storage": 11, "worker-1": 21, "worker-2": 22}
DEFAULT_RESOURCES = {"control": {"memory_mib": 2048, "vcpus": 2},
                     "storage": {"memory_mib": 768, "vcpus": 1},
                     "worker-1": {"memory_mib": 2304, "vcpus": 2},
                     "worker-2": {"memory_mib": 2304, "vcpus": 2}}
OUTPUT_LIMIT = 1024**2


def require(condition, message):
    if not condition:
        raise ValueError(message)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + ".new")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    temporary.chmod(0o600)
    temporary.replace(path)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024**2):
            digest.update(block)
    return digest.hexdigest()


def is_ignored(path):
    # The superproject owns the ignored runtime tree, outside the submodule.
    for repository in (ROOT, ROOT.parent.parent):
        completed = subprocess.run(["git", "-C", str(repository), "check-ignore", "--quiet", str(path)],
                                   capture_output=True, timeout=10, shell=False)
        if completed.returncode == 0:
            return True
    return False


def private_directory(path):
    require(path.is_absolute() and path == path.resolve(), "Use an absolute normalized private directory")
    require(is_ignored(path), "Runtime directory must be Git-ignored, never tracked")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    path.chmod(0o700)
    return path


class Commands:
    """Literal argv execution with bounded capture, finite timeouts and evidence."""
    def __init__(self, directory, timeout=300, source=None):
        require(type(timeout) is int and 1 <= timeout <= 7200, "Finite command timeout must be 1..7200 seconds")
        self.directory, self.timeout = Path(directory), timeout
        self.source = source or {"status": "not_measured"}
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    def run(self, argv, *, timeout=None, input=None, check=True):
        argv = [str(item) for item in argv]
        duration = self.timeout if timeout is None else timeout
        require(type(duration) is int and 1 <= duration <= 7200, "Finite command timeout required")
        started = time.monotonic()
        event = {"argv": argv, "source": self.source, "timeout_seconds": duration, "started_at": dt.datetime.now(dt.UTC).isoformat()}
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                process = subprocess.run(argv, input=input.encode() if isinstance(input, str) else input,
                                         stdout=stdout, stderr=stderr, timeout=duration, shell=False)
                event["returncode"] = process.returncode
            except subprocess.TimeoutExpired:
                event.update(returncode=None, timed_out=True)
            except OSError as error:
                event.update(returncode=None, error=str(error))
            stdout.seek(0)
            stderr.seek(0)
            out, err = stdout.read(OUTPUT_LIMIT + 1), stderr.read(OUTPUT_LIMIT + 1)
        event.update(elapsed_seconds=round(time.monotonic() - started, 3),
                     stdout_sha256=hashlib.sha256(out).hexdigest(),
                     stdout=out[:32768].decode(errors="replace"), stderr=err[:32768].decode(errors="replace"),
                     output_truncated=len(out) > 32768 or len(err) > 32768)
        with (self.directory / "commands.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, ensure_ascii=False) + "\n")
        if event["returncode"] is None or (check and event["returncode"] != 0):
            raise RuntimeError(f"Command failed: {argv[0]} status={event['returncode']} {event.get('error', '')} {event['stderr'][-2000:]}")
        require(len(out) <= OUTPUT_LIMIT and len(err) <= OUTPUT_LIMIT, "Command output exceeds 1 MiB capture budget")
        return subprocess.CompletedProcess(argv, event["returncode"], out.decode(errors="replace"), err.decode(errors="replace"))


def machines(config):
    network = ipaddress.ip_network(config["network_cidr"])
    require(network.version == 4 and network.prefixlen == 24 and network.is_private, "Require private IPv4 /24")
    namespace = config["namespace"]
    require(re.fullmatch(r"qcl-[a-z0-9][a-z0-9-]{1,30}", namespace), "Invalid dedicated qcl- namespace")
    digest = hashlib.sha256(namespace.encode()).hexdigest()
    return {role: {"role": role, "domain": namespace + "-" + role,
                   "ip": str(network.network_address + suffix),
                   "mac": f"52:54:{digest[:2]}:{digest[2:4]}:00:{suffix:02x}"}
            for role, suffix in ROLES.items()}


def admit(config, measured, owned_running):
    resources = config["resources"]
    require(set(resources) == set(ROLES), "Exactly four role resources are required")
    require(all(type(r["memory_mib"]) is int and r["memory_mib"] >= 512
                and type(r["vcpus"]) is int and r["vcpus"] >= 1 for r in resources.values()), "Invalid RAM/CPU resources")
    require(measured["kvm_rw"], "KVM must be readable and writable by the caller")
    planned_ram = sum(r["memory_mib"] for r in resources.values())
    planned_cpu = sum(r["vcpus"] for r in resources.values())
    running = measured["running"]
    already = sum(r["memory_mib"] for name, r in running.items() if name in owned_running)
    additional = max(0, planned_ram - already)
    require(measured["memory_available_mib"] >= additional + config["host_reserve_mib"], "Insufficient actual MemAvailable RAM plus host reserve")
    foreign_cpu = sum(r["vcpus"] for name, r in running.items() if name not in owned_running)
    require(planned_cpu + foreign_cpu + config["host_reserved_cpus"] <= measured["logical_cpus"], "Insufficient actual CPU count plus host reserve")
    require(measured["disk_free_bytes"] >= config["image_bytes"] + config["disk_reserve_bytes"], "Insufficient actual pool disk free space")
    return {"planned_guest_memory_mib": planned_ram, "planned_guest_vcpus": planned_cpu,
            "additional_guest_memory_mib": additional, "foreign_guest_vcpus": foreign_cpu,
            "measured": measured, "status": "pass"}


def read_state(path):
    result = {key: {} for key in ("domains", "networks", "pools", "volumes")}
    if not path.exists():
        return result
    mapping = {"libvirt_domain": "domains", "libvirt_network": "networks",
               "libvirt_pool": "pools", "libvirt_volume": "volumes"}
    for resource in json.loads(path.read_text()).get("resources", []):
        if resource.get("type") not in mapping:
            continue
        for instance in resource.get("instances", []):
            attributes = instance.get("attributes", {})
            if attributes.get("id") and attributes.get("name"):
                result[mapping[resource["type"]]][attributes["name"]] = attributes["id"]
    return result


def verify_ownership(config, actual, tracked):
    expected = {"domains": {m["domain"] for m in machines(config).values()},
                "networks": {config["namespace"] + "-network"},
                "pools": {config["namespace"] + "-pool"}}
    owned = set()
    for kind, names in expected.items():
        for name in names:
            if name not in actual[kind]:
                continue
            identity = actual[kind][name]
            if isinstance(identity, dict):
                identity = identity["uuid"]
            require(identity and tracked.get(kind, {}).get(name) == identity, f"Refusing foreign {kind} collision: {name}")
            if kind == "domains":
                owned.add(name)
    selected = Path(config["pool_path"])
    for name, pool in actual["pools"].items():
        path = Path(pool["path"])
        if path == selected or path in selected.parents or selected in path.parents:
            require(name in expected["pools"] and path == selected
                    and tracked.get("pools", {}).get(name) == pool["uuid"], "Refusing foreign pool path collision")
    return owned


def check_overlaps(cidr, sources, owned_ids):
    desired = ipaddress.ip_network(cidr)
    for source in sources:
        network = ipaddress.ip_network(source["cidr"], strict=False)
        if network.version != 4 or network.prefixlen == 0:
            continue
        if source.get("owner") in owned_ids and network == desired:
            continue
        require(not network.overlaps(desired), f"Network overlap with {source['cidr']} ({source.get('owner')})")


def ensure_keys(private, runner):
    private.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = private / "id_ed25519"
    if not key.exists():
        require(not key.with_suffix(".pub").exists(), "Orphan public key requires explicit resolution")
        runner.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "qcl-local-lab", "-f", key])
    key.chmod(0o600)
    public = key.with_suffix(".pub")
    if not public.exists():
        public.write_text(runner.run(["ssh-keygen", "-y", "-f", key]).stdout)
    require(public.read_text().startswith("ssh-ed25519 ") and "PRIVATE KEY" not in public.read_text(), "Require SSH public key only")
    munge = private / "munge.key"
    if not munge.exists():
        with munge.open("xb") as stream:
            stream.write(secrets.token_bytes(1024))
    require(munge.stat().st_size == 1024, "Munge key must be 1024 bytes; refusing overwrite")
    munge.chmod(0o600)


def provider_vars(config, private):
    return {"libvirt_uri": config["libvirt_uri"], "namespace": config["namespace"],
            "pool_path": config["pool_path"], "network_cidr": config["network_cidr"],
            "resources": config["resources"], "bootstrap_image": config["image"],
            "bootstrap_sha256": config["image_sha256"],
            "ssh_public_key": (private / "id_ed25519.pub").read_text().strip(),
            "seed_images": {role: str(private / "seeds" / (role + ".iso")) for role in ROLES},
            "ownership_verified": False}


def source_identity():
    commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True,
                            text=True, timeout=10, shell=False).stdout.strip()
    files = [Path(__file__), ROOT / "ansible/local-lab.yml", *(ROOT / "tofu/local-lab").glob("*.tf")]
    return {"commit": commit, "files": {str(path.relative_to(ROOT)): sha256(path) for path in files}}


def load_config(directory):
    path = directory / "private/local-lab.json"
    config = json.loads(path.read_text())
    require(config["schema"] == "qcl-local-lab.v1", "Unknown private configuration")
    machines(config)
    return config


def validate_systems(path):
    systems = json.loads(path.read_text())
    require(isinstance(systems, dict) and set(systems) == set(ROLES), "Systems JSON must cover exactly four roles")
    require(all(isinstance(value, str) and re.fullmatch(r"/nix/store/[0-9a-z]{32}-nixos-system-[A-Za-z0-9+._-]+", value)
                for value in systems.values()), "Each system must be an exact NixOS store closure")
    return systems


def create_seeds(config, private, runner):
    public = (private / "id_ed25519.pub").read_text().strip()
    seeds = private / "seeds"
    seeds.mkdir(mode=0o700, exist_ok=True)
    for role in ROLES:
        source = seeds / role
        source.mkdir(mode=0o700, exist_ok=True)
        payloads = {"meta-data": json.dumps({"instance-id": config["namespace"] + "-" + role, "local-hostname": role}),
                    "user-data": "#cloud-config\n" + json.dumps({"users": [{"name": "root", "ssh_authorized_keys": [public], "lock_passwd": True}],
                        "disable_root": False, "ssh_pwauth": False}),
                    "network-config": json.dumps({"version": 2, "ethernets": {"eth0": {"dhcp4": True}}})}
        unchanged = all((source / name).exists() and (source / name).read_text() == body for name, body in payloads.items())
        iso = seeds / (role + ".iso")
        if unchanged and iso.exists():
            continue
        for name, body in payloads.items():
            (source / name).write_text(body)
        if shutil.which("cloud-localds"):
            runner.run(["cloud-localds", "--network-config=" + str(source / "network-config"), iso,
                        source / "user-data", source / "meta-data"])
        else:
            require(shutil.which("genisoimage"), "Install cloud-localds or genisoimage for public-only NoCloud ISO")
            runner.run(["genisoimage", "-quiet", "-output", iso, "-volid", "cidata", "-joliet", "-rock",
                        *(source / name for name in payloads)])


def prepare(args, runner):
    private = args.directory / "private"
    private.mkdir(mode=0o700, exist_ok=True)
    ensure_keys(private, runner)
    require(args.libvirt_uri in ("qemu:///system", "qemu:///session"), "Require a local libvirt API URI")
    require(args.image.is_absolute() and str(args.image).startswith("/nix/store/") and args.image.is_file(), "Image must be a built Nix-store QCOW2 file")
    with args.image.open("rb") as stream:
        header = stream.read(8)
    require(header[:4] == b"QFI\xfb" and int.from_bytes(header[4:], "big") in (2, 3), "Image must be QCOW2 v2/v3")
    pool = args.pool_path
    require(pool.is_absolute() and pool == pool.resolve() and pool not in (Path("/"), Path("/var/lib/libvirt/images"))
            and Path.home() not in pool.parents and Path("/tmp") not in pool.parents and pool != Path("/tmp"),
            "Pool requires a dedicated disk-backed directory outside private home and /tmp")
    require(args.host_reserve_mib >= 512 and args.host_reserved_cpus >= 1 and args.disk_reserve_bytes >= 1024**3, "Finite host reserves must remain positive")
    resources = json.loads(args.resources.read_text()) if args.resources else DEFAULT_RESOURCES
    config = {"schema": "qcl-local-lab.v1", "namespace": args.namespace, "network_cidr": args.network_cidr,
              "pool_path": str(pool), "image": str(args.image), "image_sha256": sha256(args.image),
              "image_bytes": args.image.stat().st_size, "systems": validate_systems(args.systems),
              "resources": resources, "libvirt_uri": args.libvirt_uri,
              "host_reserve_mib": args.host_reserve_mib, "host_reserved_cpus": args.host_reserved_cpus,
              "disk_reserve_bytes": args.disk_reserve_bytes, "source": source_identity()}
    machines(config)
    existing = private / "local-lab.json"
    if existing.exists():
        previous = json.loads(existing.read_text())
        for key in ("namespace", "network_cidr", "pool_path", "image_sha256", "libvirt_uri"):
            require(previous[key] == config[key], "Prepared lab identity is immutable: " + key)
    write_json(existing, config)
    create_seeds(config, private, runner)
    tofu = args.directory / "tofu"
    tofu.mkdir(mode=0o700, exist_ok=True)
    write_json(tofu / "lab.auto.tfvars.json", provider_vars(config, private))
    result = {"status": "prepared", "directory": str(args.directory), "image_sha256": config["image_sha256"],
              "machines": machines(config), "source": config["source"], "vm_execution": "not_measured"}
    write_json(private / "prepare-evidence.json", result)
    return result


def virsh(config, runner, *arguments):
    return runner.run(["virsh", "--connect", config["libvirt_uri"], *arguments]).stdout.strip()


def actual_inventory(config, runner):
    actual = {"domains": {}, "networks": {}, "pools": {}}
    running, sources, bridges = {}, [], {}
    active = set(virsh(config, runner, "list", "--name").splitlines())
    for name in virsh(config, runner, "list", "--all", "--name").splitlines():
        xml = ET.fromstring(virsh(config, runner, "dumpxml", name))
        actual["domains"][name] = xml.findtext("uuid")
        if name in active:
            memory = xml.find("memory")
            scale = {"KiB": 1 / 1024, "MiB": 1, "GiB": 1024, "bytes": 1 / 1024**2}.get(memory.get("unit", "KiB"))
            require(scale is not None, "Unknown running guest memory unit")
            running[name] = {"memory_mib": int(int(memory.text) * scale), "vcpus": int(xml.findtext("vcpu"))}
    for name in virsh(config, runner, "net-list", "--all", "--name").splitlines():
        xml = ET.fromstring(virsh(config, runner, "net-dumpxml", name))
        identifier = xml.findtext("uuid")
        actual["networks"][name] = identifier
        bridge = xml.find("bridge")
        if bridge is not None:
            bridges[bridge.get("name")] = identifier
        for item in xml.findall("ip"):
            address = item.get("address")
            if address and ":" not in address:
                prefix = item.get("prefix") or item.get("netmask")
                require(prefix is not None, "Libvirt network has unknown IPv4 prefix")
                sources.append({"cidr": str(ipaddress.ip_network(address + "/" + prefix, strict=False)), "owner": identifier})
    for name in virsh(config, runner, "pool-list", "--all", "--name").splitlines():
        xml = ET.fromstring(virsh(config, runner, "pool-dumpxml", name))
        path = xml.findtext("target/path")
        if path:
            actual["pools"][name] = {"uuid": xml.findtext("uuid"), "path": path}
    for item in json.loads(runner.run(["ip", "-j", "-4", "address", "show"]).stdout):
        for address in item.get("addr_info", []):
            if address.get("family") == "inet":
                sources.append({"cidr": address["local"] + "/" + str(address["prefixlen"]),
                                "owner": bridges.get(item["ifname"], "host-address:" + item["ifname"])})
    for route in json.loads(runner.run(["ip", "-j", "-4", "route", "show", "table", "all"]).stdout):
        if route.get("dst") not in (None, "default") and route.get("type") not in ("local", "broadcast"):
            sources.append({"cidr": route["dst"], "owner": bridges.get(route.get("dev"), "host-route")})
    return actual, running, sources


def measure_host(config, running, runner):
    meminfo = {key: int(value.split()[0]) for key, value in
               (line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())}
    disk = Path(config["pool_path"])
    while not disk.exists():
        disk = disk.parent
    filesystem = runner.run(["findmnt", "-n", "-o", "FSTYPE", "-T", disk]).stdout.strip()
    require(filesystem and filesystem not in ("tmpfs", "ramfs", "devtmpfs"), "Pool must be on a disk-backed filesystem")
    return {"kvm_rw": os.access("/dev/kvm", os.R_OK | os.W_OK), "disk_fstype": filesystem,
            "logical_cpus": os.cpu_count(), "memory_available_mib": meminfo["MemAvailable"] // 1024,
            "disk_free_bytes": shutil.disk_usage(disk).free, "disk_measurement_path": str(disk), "running": running}


def preflight(directory, config, runner):
    require(sha256(Path(config["image"])) == config["image_sha256"], "Bootstrap image SHA256 mismatch")
    actual, running, sources = actual_inventory(config, runner)
    state = read_state(directory / "tofu/terraform.tfstate")
    owned = verify_ownership(config, actual, state)
    pool_name = config["namespace"] + "-pool"
    pool = Path(config["pool_path"])
    if pool.exists():
        require(pool.is_dir() and not pool.is_symlink(), "Pool must be a real directory")
        allowed = set(state["volumes"])
        require(all(path.name in allowed and path.is_file() and not path.is_symlink() for path in pool.iterdir()),
                "Pool directory contains untracked/foreign files")
    if pool_name in actual["pools"]:
        for name in virsh(config, runner, "vol-list", pool_name, "--name").splitlines():
            key = virsh(config, runner, "vol-key", name, "--pool", pool_name)
            require(state["volumes"].get(name) == key, "Refusing untracked/foreign pool volume: " + name)
    network_name = config["namespace"] + "-network"
    owned_networks = {actual["networks"][network_name]} if network_name in actual["networks"] else set()
    check_overlaps(config["network_cidr"], sources, owned_networks)
    receipt = {"schema": "qcl-local-lab-admission.v1", "source": source_identity(),
               "ownership": actual, "tracked": state, "network_sources": sources,
               **admit(config, measure_host(config, running, runner), owned & set(running))}
    write_json(directory / "private/admission.json", receipt)
    return receipt


def apply(directory, runner, operation_timeout):
    config = load_config(directory)
    preflight(directory, config, runner)
    tofu = directory / "tofu"
    tofu.mkdir(mode=0o700, exist_ok=True)
    for source in (ROOT / "tofu/local-lab").iterdir():
        if source.suffix == ".tf" or source.name == ".terraform.lock.hcl":
            shutil.copyfile(source, tofu / source.name)
    values = provider_vars(config, directory / "private")
    values["ownership_verified"] = True
    write_json(tofu / "lab.auto.tfvars.json", values)
    base = ["tofu", "-chdir=" + str(tofu)]
    runner.run([*base, "init", "-input=false"], timeout=operation_timeout)
    runner.run([*base, "plan", "-input=false", "-out=local-lab.tfplan"], timeout=operation_timeout)
    plan = json.loads(runner.run([*base, "show", "-json", "local-lab.tfplan"]).stdout)
    require(not any("delete" in change.get("change", {}).get("actions", []) for change in plan.get("resource_changes", [])),
            "Refusing destructive/replacement plan; requires separate migration")
    runner.run([*base, "apply", "-input=false", "local-lab.tfplan"], timeout=operation_timeout)
    actual, _, _ = actual_inventory(config, runner)
    state = read_state(tofu / "terraform.tfstate")
    verify_ownership(config, actual, state)
    receipt = {"schema": "qcl-local-lab-ownership.v1", "source": source_identity(), "tracked": state,
               "actual": actual, "status": "pass"}
    write_json(directory / "private/ownership.json", receipt)
    return receipt


def ssh_command(directory, ip, *, enrolling=False):
    require(ipaddress.ip_address(ip).version == 4, "SSH requires an inventory IPv4 address")
    private = directory / "private"
    return ["ssh", "-F", "/dev/null", "-T", "-i", str(private / "id_ed25519"),
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
            "-o", "ConnectTimeout=10", "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "UserKnownHostsFile=" + str(private / "known_hosts"),
            "-o", "StrictHostKeyChecking=" + ("accept-new" if enrolling else "yes"), "root@" + ip]


def inventory(directory, runner, *, enroll=False):
    config = load_config(directory)
    output = json.loads(runner.run(["tofu", "-chdir=" + str(directory / "tofu"), "output", "-json"]).stdout)
    observed = output["inventory"]["value"]
    require(set(observed) == set(ROLES), "Actual Tofu output must cover four roles")
    expected = machines(config)
    for role, machine in observed.items():
        require(all(machine[key] == expected[role][key] for key in ("domain", "role", "ip", "mac")), "Actual machine identity mismatch: " + role)
    actual, _, _ = actual_inventory(config, runner)
    owned = verify_ownership(config, actual, read_state(directory / "tofu/terraform.tfstate"))
    require(owned == {machine["domain"] for machine in expected.values()}, "All four actual domains must match state before SSH")
    private = directory / "private"
    known_hosts = private / "known_hosts"
    known_hosts.touch(mode=0o600, exist_ok=True)
    if enroll:
        enrollment = private / "ssh-enrollment.json"
        recorded = json.loads(enrollment.read_text()) if enrollment.exists() else {}
        for role in ROLES:
            identity = {"ip": expected[role]["ip"], "uuid": actual["domains"][expected[role]["domain"]]}
            require(role not in recorded or recorded[role] == identity, "SSH enrollment belongs to another domain identity")
            runner.run([*ssh_command(directory, identity["ip"], enrolling=role not in recorded), "true"])
            recorded[role] = identity
            write_json(enrollment, recorded)
    variables = {"ansible_user": "root", "ansible_python_interpreter": "/run/current-system/sw/bin/python3",
                 "ansible_ssh_private_key_file": str(private / "id_ed25519"),
                 "ansible_ssh_common_args": "-o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/dev/null -o UserKnownHostsFile=" + shlex.quote(str(known_hosts)),
                 "qcl_lab_namespace": config["namespace"], "qcl_lab_libvirt_uri": config["libvirt_uri"],
                 "qcl_lab_munge_key_file": str(private / "munge.key")}
    if (private / "api-token").exists():
        variables["qcl_lab_api_token_file"] = str(private / "api-token")
    result = {"all": {"vars": variables, "children": {"local_lab": {"hosts": {
        role: {"ansible_host": machine["ip"], "qcl_lab_role": role, "qcl_lab_system": config["systems"][role]}
        for role, machine in observed.items()}}, "orchestrator": {"hosts": {
            "localhost": {"ansible_connection": "local", "ansible_python_interpreter": sys.executable}}}}}}
    write_json(private / "inventory.json", result)
    write_json(private / "inventory-evidence.json", {"source": source_identity(), "observed": observed,
                                                       "ssh_enrollment": "pass" if enroll else "not_measured"})
    return result


def bootstrap(directory, runner, operation_timeout):
    inventory(directory, runner, enroll=True)
    runner.run(["ansible-playbook", "-i", directory / "private/inventory.json", ROOT / "ansible/local-lab.yml"], timeout=operation_timeout)
    result = {"status": "pass", "source": source_identity(), "systems": load_config(directory)["systems"]}
    write_json(directory / "private/bootstrap-evidence.json", result)
    return result


GUEST_PROBE = r'''
import json, os, pathlib, pwd, socket, subprocess
def command(arguments):
    value = subprocess.run(arguments, capture_output=True, text=True, timeout=30)
    if value.returncode:
        raise RuntimeError(str(arguments) + ": " + value.stderr)
    return value.stdout.strip()
settings = SETTINGS
role = settings["role"]
paths = ["/"] + (["/srv/qcl-negf"] if role == "storage" else
    ["/srv/qcl-negf/jobs", "/var/lib/qcl-negf-state"] if role == "control" else
    ["/srv/qcl-negf/jobs", "/scratch"])
mounts = {}
for path in paths:
    mounts[path] = {"device": os.stat(path).st_dev,
        "findmnt": json.loads(command(["findmnt", "-J", "-o", "TARGET,SOURCE,FSTYPE,UUID", "-T", path]))["filesystems"][0]}
result = {"hostname": socket.gethostname(), "system": os.path.realpath("/run/current-system"),
    "boot_id": pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    "uid": pwd.getpwnam("qcl-negf").pw_uid, "mounts": mounts,
    "resolution": {name: socket.gethostbyname(name) for name in settings["hosts"]},
    "cgroup_v2": pathlib.Path("/sys/fs/cgroup/cgroup.controllers").is_file()}
local = "/srv/qcl-negf" if role == "storage" else "/var/lib/qcl-negf-state" if role == "control" else "/scratch"
serial = "qcl-data" if role == "storage" else "qcl-state" if role == "control" else "qcl-scratch"
result["durable_device"] = os.stat("/dev/disk/by-id/virtio-" + serial).st_rdev
marker = pathlib.Path(local) / (settings["namespace"] + "-durable-probe.json")
body = json.dumps({"namespace": settings["namespace"], "role": role, "image_sha256": settings["image_sha256"]}, sort_keys=True)
if marker.exists():
    if marker.read_text() != body:
        raise RuntimeError("Existing durable probe belongs to another identity")
else:
    marker.write_text(body)
result["durable_receipt"] = {"path": str(marker), "bytes": marker.stat().st_size, "content": marker.read_text()}
if role == "storage":
    result["exports"] = command(["exportfs", "-v"])
else:
    target = pathlib.Path("/srv/qcl-negf/jobs") / (settings["namespace"] + "-root-squash-probe")
    try:
        with target.open("x") as stream:
            stream.write("unexpected root write")
    except PermissionError:
        result["root_write_denied"] = True
    else:
        target.unlink()
        raise RuntimeError("NFS root write unexpectedly succeeded")
    marker = "/srv/qcl-negf/jobs/" + settings["namespace"] + "-uid3000-probe.json"
    program = "import pathlib; p=pathlib.Path(" + repr(marker) + "); body=" + repr(settings["namespace"]) + "; assert not p.exists() or p.read_text()==body; p.write_text(body); print(p.stat().st_uid)"
    result["nfs_receipt_uid"] = int(command(["runuser", "-u", "qcl-negf", "--", "/run/current-system/sw/bin/python3", "-c", program]))
if role == "control":
    result["sinfo"] = command(["sinfo", "--noheader", "--format=%N|%T"])
print(json.dumps(result))
'''

SLURM_PROBE = r'''
import json, os, pathlib, subprocess, time
settings = SETTINGS
directory = "/srv/qcl-negf/jobs/" + settings["namespace"] + "-slurm-probe"
subprocess.run(["runuser", "-u", "qcl-negf", "--", "mkdir", "-p", directory], check=True, timeout=10)
results = []
for worker in ("worker-1", "worker-2"):
    output = directory + "/" + worker + "-%j.out"
    arguments = ["runuser", "-u", "qcl-negf", "--", "sbatch", "--parsable", "--wait", "--nodes=1", "--ntasks=1",
        "--cpus-per-task=1", "--mem=64M", "--time=00:01:00", "--nodelist=" + worker,
        "--job-name=" + settings["namespace"] + "-probe", "--chdir=" + directory,
        "--output=" + output, "--wrap=hostname; cat /proc/self/cgroup"]
    # Record the parsable owned job ID before waiting for terminal state.
    with pathlib.Path(directory, worker + "-submission.stderr").open("w") as errors:
        process = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=errors, text=True, cwd=directory)
        job = process.stdout.readline().strip().split(";", 1)[0]
        if not job.isdigit():
            raise RuntimeError("Slurm did not return an owned job ID")
        pathlib.Path(directory, worker + "-job.json").write_text(json.dumps({"job_id": job, "worker": worker, "uid": 3000}))
        try:
            status = process.wait(timeout=120)
        except subprocess.TimeoutExpired:
            # The scheduler's finite one-minute limit remains authoritative.
            process.terminate()
            raise RuntimeError("Owned Slurm probe wait exceeded 120 seconds; inspect job " + job)
    text = pathlib.Path(output.replace("%j", job)).read_text()
    if status or text.splitlines()[0] != worker or "0::" not in text or "job_" + job not in text:
        raise RuntimeError("Owned Slurm hostname/cgroup probe failed: " + job + " " + text)
    results.append({"job_id": job, "worker": worker, "returncode": status, "output": text,
                    "output_uid": pathlib.Path(output.replace("%j", job)).stat().st_uid})
print(json.dumps(results))
'''


def verify_guest(config, role, result):
    require(result["hostname"] == role and result["system"] == config["systems"][role], "Guest hostname/system identity mismatch: " + role)
    require(result["uid"] == 3000 and result["cgroup_v2"], "Guest UID3000/cgroup v2 check failed")
    require(result["resolution"] == {name: m["ip"] for name, m in machines(config).items()}, "Guest hostname resolution mismatch")
    root_device = result["mounts"]["/"]["device"]
    require(all(mount["device"] != root_device for path, mount in result["mounts"].items() if path != "/"), "Guest state/data/scratch/NFS is on root filesystem")
    local = "/srv/qcl-negf" if role == "storage" else "/var/lib/qcl-negf-state" if role == "control" else "/scratch"
    durable = result["mounts"][local]
    require(durable["device"] == result["durable_device"] and durable["findmnt"]["fstype"] == "ext4"
            and durable["findmnt"]["uuid"], "Durable mount must use the assigned serial disk and measured UUID")
    if role == "storage":
        require("root_squash" in result["exports"] and "/srv/qcl-negf/jobs" in result["exports"], "Actual NFS export must declare root_squash")
    else:
        require(result["root_write_denied"] and result["nfs_receipt_uid"] == 3000, "NFS root_squash/UID3000 write check failed")
        require(result["mounts"]["/srv/qcl-negf/jobs"]["findmnt"]["fstype"] in ("nfs", "nfs4"), "Shared jobs must be a real NFS mount")


def remote_python(directory, ip, script, settings, runner, timeout=None):
    program = script.replace("SETTINGS", repr(settings), 1)
    return json.loads(runner.run([*ssh_command(directory, ip), "/run/current-system/sw/bin/python3", "-"],
                                 input=program, timeout=timeout).stdout)


def probe(directory, runner):
    config = load_config(directory)
    # A probe must not SSH to an unowned name reused with another domain UUID.
    actual, _, _ = actual_inventory(config, runner)
    expected = machines(config)
    require(verify_ownership(config, actual, read_state(directory / "tofu/terraform.tfstate")) ==
            {machine["domain"] for machine in expected.values()}, "Probe requires all four owned actual domains")
    settings = {"namespace": config["namespace"], "image_sha256": config["image_sha256"], "hosts": list(ROLES)}
    guests = {}
    for role, machine in expected.items():
        result = remote_python(directory, machine["ip"], GUEST_PROBE, settings | {"role": role}, runner)
        verify_guest(config, role, result)
        guests[role] = result
    jobs = remote_python(directory, expected["control"]["ip"], SLURM_PROBE, settings, runner)
    require(len(jobs) == 2 and all(job["output_uid"] == 3000 for job in jobs), "Two owned UID3000 Slurm jobs required")
    result = {"schema": "qcl-local-lab-probe.v1", "status": "pass", "source": source_identity(), "guests": guests,
              "slurm_jobs": jobs, "scientific_validation": "not_performed", "controller_reboot": "not_measured"}
    previous = directory / "private/probe-evidence.json"
    if previous.exists():
        before = json.loads(previous.read_text())
        for role, guest in guests.items():
            for path, mount in guest["mounts"].items():
                if path != "/" and mount["findmnt"]["fstype"] not in ("nfs", "nfs4"):
                    require(mount["findmnt"]["uuid"] == before["guests"][role]["mounts"][path]["findmnt"]["uuid"], "Durable filesystem UUID changed: " + role)
        result["durable_uuid_retained"] = "pass"
        result["controller_reboot"] = "pass" if before["guests"]["control"]["boot_id"] != guests["control"]["boot_id"] else "not_measured"
    write_json(previous, result)
    return result


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "apply", "inventory", "bootstrap", "probe"):
        command = commands.add_parser(name)
        command.add_argument("--directory", type=Path, required=True)
        command.add_argument("--timeout", type=int, default=300)
        command.add_argument("--operation-timeout", type=int, default=1800)
        if name == "prepare":
            command.add_argument("--namespace", required=True)
            command.add_argument("--network-cidr", default="192.168.231.0/24")
            command.add_argument("--image", type=Path, required=True)
            command.add_argument("--systems", type=Path, required=True)
            command.add_argument("--pool-path", type=Path, required=True)
            command.add_argument("--libvirt-uri", default="qemu:///system")
            command.add_argument("--resources", type=Path)
            command.add_argument("--host-reserve-mib", type=int, default=1024)
            command.add_argument("--host-reserved-cpus", type=int, default=1)
            command.add_argument("--disk-reserve-bytes", type=int, default=2 * 1024**3)
        elif name == "inventory":
            command.add_argument("--enroll", action="store_true")
    args = parser.parse_args(arguments)
    require(1 <= args.operation_timeout <= 7200, "Operation timeout must be finite: 1..7200 seconds")
    os.umask(0o077)
    private_directory(args.directory)
    runner = Commands(args.directory / "evidence", args.timeout, source_identity())
    if args.command == "prepare":
        result = prepare(args, runner)
    elif args.command == "apply":
        result = apply(args.directory, runner, args.operation_timeout)
    elif args.command == "inventory":
        result = inventory(args.directory, runner, enroll=args.enroll)
    elif args.command == "bootstrap":
        result = bootstrap(args.directory, runner, args.operation_timeout)
    else:
        result = probe(args.directory, runner)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
