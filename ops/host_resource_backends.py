"""Local authenticated native adapters and a root-only private input boundary.

No SSH, remote URI, arbitrary argv, raw QMP, service installation or automatic
fallback. Protected production probes, installed helper/transport and launch
wiring remain P20-B source integration; native qualification is a separate gate.
This module never promotes an exit status or configured maximum to proof.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import xml.etree.ElementTree as ET

import application_release as release_commands

from host_resource_operations import (BackendQualification, CompletionEvidence, FileReceiptStore,
    GuestEvidence, HostEvidence, HostResourceController, NativeCleanupEvidence, ResourceError, ResourceRequest,
    Receipt, RuntimeBinding, VMReadback, integer, require, strict_json, text,
    validate_host_resource_policy)

MAX_OUTPUT_BYTES = 256 * 1024


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def trusted_root_path(path, *, directory=False, executable=False):
    """Reject symlinks and writable/user-owned ancestors, including /tmp."""
    try:
        release_commands.protected_parts(str(path))
    except ValueError as error:
        raise ResourceError("trust", "canonical protected path required") from error
    path = Path(path)
    if str(path).startswith("/nix/store/"):
        # Reuse P12's exact native-store exception; never relax /tmp or another
        # writable ancestor. Store descendants are still root-owned/no-symlink.
        from runtime_bindings import read_store_file
        leaf = path / "nixos-version" if directory else path
        limit = 4096 if directory else 128 * 1024**2
        read_store_file(leaf, limit=limit)
        if executable:
            require(path.stat().st_mode & 0o111 != 0, "trust", "native tool is not executable")
        return path
    require(path.is_absolute() and path == path.absolute(), "trust", "absolute canonical path required")
    for item in (path, *path.parents):
        st = item.lstat()
        require(not stat.S_ISLNK(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
                "trust", "root-owned non-writable path ancestry required")
    st = path.stat()
    require(stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode),
            "trust", "unexpected private path type")
    if executable:
        require(st.st_mode & 0o111 != 0, "trust", "native tool is not executable")
    return path


def read_root_json(path):
    path = trusted_root_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        require(st.st_uid == 0 and not st.st_mode & 0o022 and st.st_nlink == 1 and
                st.st_size <= MAX_OUTPUT_BYTES, "trust", "unsafe private input")
        data = os.read(fd, MAX_OUTPUT_BYTES + 1)
        require(len(data) <= MAX_OUTPUT_BYTES, "output_bound", "private input is too large")
        result = strict_json(data.decode())
        require(type(result) is dict, "shape", "private input must be an object")
        return result
    finally:
        os.close(fd)


class NativeCommandRunner:
    """Bounded local argv execution. Only root-enrolled absolute tools are allowed."""
    def __init__(self, tools, *, slurm_conf=None):
        require(os.geteuid() == 0, "root_required", "native resource helper runs as root")
        self.tools = frozenset(str(trusted_root_path(p, executable=True)) for p in tools)
        self.environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "TZ": "UTC"}
        if slurm_conf is not None:
            self.environment["SLURM_CONF"] = str(trusted_root_path(slurm_conf))

    def run(self, argv, *, timeout_seconds, max_output_bytes=MAX_OUTPUT_BYTES):
        require(type(argv) in (list, tuple) and bool(argv) and argv[0] in self.tools,
                "argv", "tool is not enrolled")
        for arg in argv:
            require(type(arg) is str and "\x00" not in arg, "argv", "invalid native argument")
        trusted_root_path(argv[0], executable=True)
        integer(timeout_seconds, "timeout_seconds", 1)
        integer(max_output_bytes, "max_output_bytes", 1)
        require(max_output_bytes <= MAX_OUTPUT_BYTES, "output_bound", "native output bound exceeded")
        try:
            # Reuse P11/P12's owned group cleanup, including an exited leader.
            # Its cleanup reserve is inside the operation's original timeout.
            return release_commands.command(argv, timeout_seconds=timeout_seconds,
                output_bytes=max_output_bytes, cleanup_seconds=min(2.0, timeout_seconds / 2),
                env=self.environment)
        except release_commands.CommandFailure as exc:
            record = dict(exc.record)
            if record.get("cleanup_confirmed") is not True:
                code = "native_cleanup_unconfirmed"
            else:
                code = {"timeout": "native_timeout", "deadline": "native_timeout",
                        "output_limit": "output_bound"}.get(record["failure"], "native_command")
            error = ResourceError(code, "native outcome requires readback and confirmed owned cleanup")
            error.native_argv = tuple(argv)
            error.native_record = record
            error.native_output = record["stdout"] + record["stderr"]
            error.native_output_truncated = record["output_truncated"]
            raise error from exc


def pve_config_fingerprint(config):
    require(type(config) is dict and all(type(v) in {str,int,bool} for v in config.values()),
        "unsupported", "qualified scalar PVE static config required")
    stable={key: str(int(value)) if type(value) is bool else str(value)
        for key,value in config.items() if key not in {"digest","balloon"}}
    return fingerprint(stable)


@dataclass(frozen=True)
class ProxmoxVM:
    vmid: int
    native_id: str  # actual enrolled SMBIOS UUID, never just a display name


class ProxmoxMemoryBackend:
    quantum_bytes = 1024**2

    def __init__(self, runner, tool, node, vms, *, dynamic, local_only=False):
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", node or "") is not None,
                "argv", "invalid Proxmox node")
        require(Path(tool).is_absolute(), "argv", "absolute pvesh path required")
        self.runner, self.tool, self.node, self.vms, self.dynamic = runner, tool, node, dict(vms), dynamic
        require(type(local_only) is bool, "shape", "local_only must be explicit bool")
        self.local_only = local_only
        for vm in self.vms.values():
            require(type(vm) is ProxmoxVM, "shape", "Proxmox enrollment required")
            integer(vm.vmid, "vmid", 1)
            text(vm.native_id, "native_id")
        require(len({vm.vmid for vm in self.vms.values()}) == len(self.vms) and
                len({vm.native_id.lower() for vm in self.vms.values()}) == len(self.vms),
                "ownership", "one logical VM must identify one distinct native VM")

    def _path(self, vm_id):
        require(vm_id in self.vms, "ownership", "VM is not enrolled")
        return f"/nodes/{self.node}/qemu/{self.vms[vm_id].vmid}"

    def _run(self, arguments, timeout=30):
        return self.runner.run([self.tool, *(["--noproxy"] if self.local_only else []), *arguments, "--output-format", "json"],
                               timeout_seconds=timeout, max_output_bytes=MAX_OUTPUT_BYTES)

    def runtime_version(self):
        return fingerprint(strict_json(self._run(["get", "/version"])))

    def readback(self, vm_id: str) -> VMReadback:
        path = self._path(vm_id)
        config = strict_json(self._run(["get", path + "/config", "--current", "1"]))
        status = strict_json(self._run(["get", path + "/status/current"]))
        require(type(config) is dict and type(status) is dict, "readback", "PVE object expected")
        for key in ("memory", "balloon"):
            integer(config.get(key), "PVE " + key)
        require(config["memory"] > 0 and config["balloon"] <= config["memory"],
                "readback", "unsupported PVE memory format/range")
        if self.dynamic:
            require(config["balloon"] > 0 and type(config.get("shares")) is int and
                    config["shares"] == 0, "unsupported", "manual enabled balloon shares=0 required")
        actual_uuid = re.findall(r"(?:^|,)uuid=([^,]+)(?:,|$)", config.get("smbios1", ""))
        require(actual_uuid == [self.vms[vm_id].native_id], "ownership", "enrolled PVE UUID changed")
        integer(status.get("pid"), "PVE pid", 1)
        text(config.get("digest"), "PVE digest")
        configured = (config["balloon"] or config["memory"]) * self.quantum_bytes
        # Balloon is logical assignment in bytes. mem/RSS/maxmem cannot replace it.
        assigned = status.get("balloon") if config["balloon"] else status.get("maxmem")
        integer(assigned, "PVE actual balloon/fixed allocation", 1)
        if not config["balloon"]:
            require(not self.dynamic and assigned == configured, "readback", "fixed reservation mismatch")
        stable = pve_config_fingerprint(config)
        return VMReadback(vm_id, actual_uuid[0], str(status["pid"]), stable,
                          config["digest"], configured, assigned, status.get("status") == "running")

    def resize(self, vm_id: str, target_bytes: int, before: VMReadback,
               timeout_seconds: int) -> VMReadback:
        require(self.dynamic, "unsupported", "conservative reservation is never ballooned")
        integer(target_bytes, "target_bytes", 1)
        require(target_bytes % self.quantum_bytes == 0, "rounding", "PVE target must be full MiB")
        actual = self.readback(vm_id)
        require(actual == before and actual.running, "identity_mismatch", "PVE state changed before mutation")
        self.runner.run(self.mutation_argv(vm_id, target_bytes, before), timeout_seconds=timeout_seconds,
                        max_output_bytes=MAX_OUTPUT_BYTES)
        return self.readback(vm_id)

    def mutation_argv(self, vm_id, target_bytes, before):
        require(self.dynamic, "unsupported", "fixed reservation is never ballooned")
        integer(target_bytes, "target_bytes", 1)
        require(target_bytes % self.quantum_bytes == 0, "rounding", "PVE full MiB target required")
        return (self.tool, *(("--noproxy",) if self.local_only else ()), "set", self._path(vm_id) + "/config",
                "--balloon", str(target_bytes // self.quantum_bytes), "--digest", before.revision,
                "--output-format", "json")


@dataclass(frozen=True)
class LibvirtVM:
    native_id: str
    name: str
    pid_file: str | None = None  # actual libvirt runtime PID locator, qualified for this site


def libvirt_config_fingerprint(xml):
    """Static domain identity excludes runtime domain ID/aliases and target RAM."""
    xml = ET.fromstring(ET.tostring(xml))
    xml.attrib.pop("id", None)
    current = xml.find("currentMemory")
    require(current is not None, "readback", "explicit currentMemory required")
    current.text = "CONTROLLED_MEMORY_TARGET"
    for parent in xml.iter():
        for child in list(parent):
            if child.tag == "alias": parent.remove(child)
    return fingerprint(ET.tostring(xml, encoding="unicode"))


class LibvirtMemoryBackend:
    quantum_bytes = 1024

    def __init__(self, runner, tool, uri, vms, *, dynamic, connect_endpoint=None):
        require(uri == "qemu:///system", "unsupported", "only authenticated local system libvirt supported")
        require(Path(tool).is_absolute(), "argv", "absolute virsh path required")
        self.runner, self.tool, self.uri, self.vms, self.dynamic = runner, tool, uri, dict(vms), dynamic
        self.connect_endpoint = uri if connect_endpoint is None else connect_endpoint
        for vm in self.vms.values():
            require(type(vm) is LibvirtVM and re.fullmatch(r"[0-9a-fA-F-]{36}", vm.native_id) and
                    re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", vm.name),
                    "argv", "enrolled libvirt UUID/name required")
        pid_files = [vm.pid_file for vm in self.vms.values() if vm.pid_file is not None]
        require(len({vm.native_id.lower() for vm in self.vms.values()}) == len(self.vms) and
                len({vm.name for vm in self.vms.values()}) == len(self.vms) and
                len(set(pid_files)) == len(pid_files),
                "ownership", "one logical VM must identify one distinct domain/process")

    @property
    def connect_endpoint(self):
        return self._connect_endpoint

    @connect_endpoint.setter
    def connect_endpoint(self, value):
        require(type(value) is str and value in {"qemu:///system",
                "qemu+unix:///system?socket=%2Frun%2Flibvirt%2Flibvirt-sock",
                "qemu+unix:///system?socket=%2Frun%2Flibvirt%2Fvirtqemud-sock"},
                "qualification", "exact local system libvirt endpoint required")
        self._connect_endpoint = value

    def _run(self, arguments, timeout=30):
        return self.runner.run([self.tool, "--connect", self.connect_endpoint, *arguments],
                               timeout_seconds=timeout, max_output_bytes=MAX_OUTPUT_BYTES)

    def runtime_version(self):
        return hashlib.sha256(self._run(["version", "--daemon"]).encode()).hexdigest()

    def _vm(self, vm_id):
        require(vm_id in self.vms, "ownership", "domain is not enrolled")
        return self.vms[vm_id]

    @staticmethod
    def _memory(element):
        require(element is not None and (element.text or "").strip().isdigit(),
                "readback", "explicit domain memory required")
        scale = {"KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "bytes": 1,
                 "b": 1, "k": 1000, "M": 1000**2, "G": 1000**3}
        require(element.get("unit", "KiB") in scale, "readback", "unknown libvirt memory unit")
        result = int(element.text.strip()) * scale[element.get("unit", "KiB")]
        integer(result, "libvirt memory", 1)
        return result

    def readback(self, vm_id: str) -> VMReadback:
        vm = self._vm(vm_id)
        raw_xml = self._run(["dumpxml", vm.native_id])
        require("<!DOCTYPE" not in raw_xml and "<!ENTITY" not in raw_xml,
                "readback", "unsupported XML entity declaration")
        xml = ET.fromstring(raw_xml)
        require(xml.tag == "domain" and xml.findtext("uuid") == vm.native_id and
                xml.findtext("name") == vm.name, "ownership", "libvirt UUID/name changed")
        running = self._run(["domstate", vm.native_id]).strip() == "running"
        stats = {}
        for line in self._run(["dommemstat", vm.native_id]).splitlines():
            parts = line.split()
            require(len(parts) == 2 and parts[0] not in stats and parts[1].isdigit(),
                    "readback", "unrecognized or duplicate dommemstat row")
            stats[parts[0]] = int(parts[1])
        integer(stats.get("actual"), "libvirt actual balloon KiB", 1)
        domain_id = self._run(["domid", vm.native_id]).strip()
        require(domain_id.isdigit() and int(domain_id) > 0, "readback", "running domain identity missing")
        current, maximum = xml.find("currentMemory"), self._memory(xml.find("memory"))
        configured = self._memory(current)
        require(configured <= maximum, "readback", "libvirt target exceeds maximum")
        if self.dynamic:
            balloon = xml.find("devices/memballoon")
            require(balloon is not None and balloon.get("model") == "virtio",
                    "unsupported", "qualified virtio balloon device required")
        stable = libvirt_config_fingerprint(xml)
        process_id = "domid:" + domain_id  # only fixture/source mode; never accepted by native verifier
        if vm.pid_file is not None:
            path = trusted_root_path(vm.pid_file)
            require(path.stat().st_size <= 32, "readback", "oversized libvirt PID file")
            process_id = path.read_text().strip()
            require(process_id.isdigit() and int(process_id) > 0, "readback", "invalid libvirt QEMU PID")
        return VMReadback(vm_id, vm.native_id, process_id, stable,
                          hashlib.sha256(raw_xml.encode()).hexdigest(), configured,
                          stats["actual"] * 1024, running)

    def resize(self, vm_id: str, target_bytes: int, before: VMReadback,
               timeout_seconds: int) -> VMReadback:
        require(self.dynamic, "unsupported", "conservative reservation is never ballooned")
        integer(target_bytes, "target_bytes", 1)
        require(target_bytes % self.quantum_bytes == 0, "rounding", "libvirt target must be full KiB")
        actual = self.readback(vm_id)
        require(actual == before and actual.running, "identity_mismatch", "libvirt state changed before mutation")
        self.runner.run(self.mutation_argv(vm_id, target_bytes, before), timeout_seconds=timeout_seconds,
                        max_output_bytes=MAX_OUTPUT_BYTES)
        return self.readback(vm_id)

    def mutation_argv(self, vm_id, target_bytes, before):
        require(self.dynamic, "unsupported", "fixed reservation is never ballooned")
        integer(target_bytes, "target_bytes", 1)
        require(target_bytes % self.quantum_bytes == 0, "rounding", "libvirt full KiB target required")
        return (self.tool, "--connect", self.connect_endpoint, "setmem", self._vm(vm_id).native_id,
                str(target_bytes // self.quantum_bytes), "--live", "--config")


def backend_from_config(config, runner, *, dynamic):
    backend = config.get("backend")
    if backend == "proxmox":
        return ProxmoxMemoryBackend(runner, config["tool"], config["node"],
            {vm_id: ProxmoxVM(**vm) for vm_id, vm in config["vms"].items()}, dynamic=dynamic)
    if backend == "libvirt":
        return LibvirtMemoryBackend(runner, config["tool"], config["uri"],
            {vm_id: LibvirtVM(**vm) for vm_id, vm in config["vms"].items()}, dynamic=dynamic)
    raise ResourceError("unsupported", "backend is not supported/qualified; Hyper-V awaits native preparation")


def decode_host_evidence(document: dict, qualifications: list[dict]) -> HostEvidence:
    require(type(document) is dict and document.get("schema") == "qcl.host-resource-evidence.v1",
            "shape", "protected host probe schema required")
    doc = {key: value for key, value in document.items() if key != "schema"}
    try:
        doc["bindings"] = tuple(RuntimeBinding(**row) for row in doc["bindings"])
        doc["qualifications"] = tuple(BackendQualification(**{**row,
            "binding": RuntimeBinding(**row["binding"])}) for row in qualifications)
        doc["live_workloads"] = {key: tuple(value) for key, value in doc["live_workloads"].items()}
        return HostEvidence(**doc)
    except (KeyError, TypeError, AttributeError) as exc:
        raise ResourceError("shape", "incomplete protected host probe/qualification") from exc


@dataclass(frozen=True)
class NativeRuntimeFacts:
    host_boot_id: str
    host_kernel_id: str
    qemu_version_id: str
    backend_version_id: str


def collect_native_runtime(backend, readback):
    require(os.geteuid() == 0, "root_required", "native facts require the local root helper")
    require(readback.process_id.isdigit() and int(readback.process_id) > 0,
            "unsupported", "actual QEMU PID readback required; libvirt domid is not a PID")
    digest = hashlib.sha256()
    # /proc/<pid>/exe intentionally follows the kernel-owned symlink to the
    # *running* executable, including an old unlinked binary after an upgrade.
    with open(f"/proc/{readback.process_id}/exe", "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode) and
                os.fstat(stream.fileno()).st_size <= 128 * 1024**2,
                "unsupported", "unqualified executable size/type")
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return NativeRuntimeFacts(Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                              platform.release(), "sha256:" + digest.hexdigest(),
                              backend.runtime_version())


class VerifiedNativeBackend:
    """Cross-check protected qualification against current authenticated native facts."""
    def __init__(self, backend, evidence, *, collector=collect_native_runtime):
        self.backend, self.evidence, self.collector = backend, evidence, collector
        self.quantum_bytes = backend.quantum_bytes

    def _verify(self, row):
        binding = next((b for b in self.evidence.bindings if b.vm_id == row.vm_id), None)
        require(binding is not None, "qualification", "missing exact native runtime binding")
        facts = self.collector(self.backend, row)
        require(facts == NativeRuntimeFacts(self.evidence.host_boot_id, binding.host_kernel_id,
                                           binding.qemu_version_id, binding.backend_version_id),
                "qualification", "actual host/kernel/QEMU/backend changed; qualification invalid")
        return row

    def readback(self, vm_id: str) -> VMReadback:
        return self._verify(self.backend.readback(vm_id))

    def resize(self, vm_id: str, target_bytes: int, before: VMReadback,
               timeout_seconds: int) -> VMReadback:
        actual = self.readback(vm_id)
        require(actual == before, "identity_mismatch", "native state changed before mutation")
        return self._verify(self.backend.resize(vm_id, target_bytes, before, timeout_seconds))


class RootNativeBoundary:
    """Callable native entrypoint. Job payload has no evidence/path/command fields.

    A native helper must install this callable through its own accepted P12
    interface. No sudo rule, daemon or install action is created by this module.
    """
    def __init__(self, private_config_path):
        require(os.geteuid() == 0, "root_required", "native resource helper runs as root")
        self.config_path = trusted_root_path(private_config_path)
        self.config = read_root_json(self.config_path)
        require(set(self.config) == {"schema", "policy", "evidence", "qualification", "state_directory",
                "backend_config"} and self.config["schema"] == "qcl.host-resource-runtime.v1",
                "shape", "protected runtime configuration required")
        trusted_root_path(self.config["state_directory"], directory=True)
        self.runner = NativeCommandRunner([self.config["backend_config"]["tool"]])

    def open_owner(self):
        """Open the single owner without a stale/generated evidence prerequisite.

        Production provider captures fresh facts inside store.operation(). Cold
        preparation has no guest/probe dependency. Existing typed open is kept.
        """
        require(read_root_json(self.config_path) == self.config, "identity_mismatch", "runtime config changed")
        policy = validate_host_resource_policy(read_root_json(self.config["policy"]))
        backend = backend_from_config(self.config["backend_config"], self.runner,
            dynamic=policy.active_grant.mechanism == "qualified_dynamic")
        store = FileReceiptStore(Path(self.config["state_directory"]))
        return policy, store, backend

    def open(self):
        # Every call rereads the protected inputs. No client can substitute facts.
        require(read_root_json(self.config_path) == self.config, "identity_mismatch", "runtime config changed")
        policy = validate_host_resource_policy(read_root_json(self.config["policy"]))
        qualification = read_root_json(self.config["qualification"])
        require(set(qualification) == {"schema", "qualifications"} and
                qualification["schema"] == "qcl.host-resource-qualification.v1",
                "qualification", "protected qualification schema required")
        probe = read_root_json(self.config["evidence"])
        require(set(probe) == {"schema", "host", "guests", "completions", "cleanups"} and
                probe["schema"] == "qcl.host-resource-probe.v2" and type(probe["cleanups"]) is dict,
                "shape", "protected probe v2 bundle required")
        evidence = decode_host_evidence(probe["host"], qualification["qualifications"])
        backend = backend_from_config(self.config["backend_config"], self.runner,
                         dynamic=policy.active_grant.mechanism == "qualified_dynamic")
        backend = VerifiedNativeBackend(backend, evidence)
        trusted_root_path(self.config["state_directory"], directory=True)
        store = FileReceiptStore(Path(self.config["state_directory"]))
        return HostResourceController(policy, store, backend), evidence, probe

    def invoke(self, action: str, *, request: ResourceRequest | None = None,
               request_id: str | None = None) -> Receipt:
        require(action in {"request", "grow", "admit", "finish", "shrink", "reconcile"},
                "action", "resource action is not supported")
        controller, evidence, probe = self.open()
        if action == "request":
            require(type(request) is ResourceRequest and request_id is None, "shape", "demand only required")
            return controller.request(request, evidence)
        require(request is None, "shape", "only request_id accepted for lifecycle actions")
        text(request_id, "request_id")
        if action == "admit":
            doc = dict(probe["guests"][request_id])
            doc["live_workload_ids"] = tuple(doc["live_workload_ids"])
            return controller.admit(request_id, GuestEvidence(**doc), evidence)
        if action in {"finish", "reconcile"}:
            doc = probe["completions"].get(request_id)
            completion = None
            if doc is not None:
                doc = dict(doc)
                doc["live_workload_ids"] = tuple(doc["live_workload_ids"])
                completion = CompletionEvidence(**doc)
            if action == "finish":
                return controller.finish(request_id, completion, evidence)
            cleanup = probe["cleanups"].get(request_id)
            if cleanup is not None:
                require(type(cleanup) is dict and set(cleanup) == set(NativeCleanupEvidence.__dataclass_fields__) and
                        type(cleanup["binding"]) is dict, "shape", "protected native cleanup record required")
                cleanup = dict(cleanup)
                cleanup["binding"] = RuntimeBinding(**cleanup["binding"])
                cleanup = NativeCleanupEvidence(**cleanup)
            return controller.reconcile(request_id, evidence, completion, cleanup_evidence=cleanup)
        return getattr(controller, action)(request_id, evidence)
