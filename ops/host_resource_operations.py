"""Per-host resident grants. Public requests carry demand, never proof or native argv.

Production callers must obtain evidence through the root-protected native boundary
in host_resource_backends. Dependency injection is for controlled local fixtures;
these Python objects alone are not an authentication or privilege boundary.
"""
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import time
import uuid
from typing import Callable, Protocol, Sequence

from host_resource_policy import (HostResourcePolicy, PolicyValidationError, ResidentGrant,
                                 validate_host_grants, validate_host_resource_policy, validate_resize)

STATE_SCHEMA = "qcl.host-resource-state.v2"
MAX_STATE_BYTES = 1024 * 1024
PENDING = {"HOST_GRANT", "GROW_UNKNOWN", "GUEST_ADMIT", "SHRINK_READY", "SHRINK_UNKNOWN"}
PHASES = PENDING | {"RUN", "RELEASE", "SHRINK_DEFERRED"}
UNKNOWN = {"GROW_UNKNOWN", "SHRINK_UNKNOWN"}
CLEANUP_BLOCK = "native owned cleanup unconfirmed; administrator reconciliation required"
RECEIPT_FIELDS = {"request", "phase", "target_bytes", "old_bytes", "failure", "finished",
                  "mutation_id", "mutation_started_at", "native_cleanup_confirmed"}


class ResourceError(RuntimeError):
    def __init__(self, code: str, detail: str):
        self.code = code
        super().__init__(f"{code}: {detail}")


def require(condition, code, detail):
    if not condition:
        raise ResourceError(code, detail)


def integer(value, name, minimum=0):
    require(type(value) is int and minimum <= value < 2**63, "shape", name)


def text(value, name):
    require(type(value) is str and bool(value) and value.strip() == value and
            all(ord(c) >= 32 for c in value), "shape", name)


def strict_json(data: str) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json", key)
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda value: require(False, "shape", value))


def policy_digest(policy: HostResourcePolicy) -> str:
    return hashlib.sha256(json.dumps(asdict(policy), sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def decode_resource_request(document: dict) -> "ResourceRequest":
    require(type(document) is dict and set(document) == {"schema", "request_id", "host_id", "vm_id",
            "owner_id", "workload_bytes", "workload_id"} and
            document["schema"] == "qcl.host-resource-request.v1", "shape", "demand-only request required")
    return ResourceRequest(**{key: value for key, value in document.items() if key != "schema"})


@dataclass(frozen=True)
class ResourceRequest:
    request_id: str
    host_id: str
    vm_id: str
    owner_id: str
    workload_bytes: int  # additional commitment above the resident OS floor
    workload_id: str

    def __post_init__(self):
        for name in ("request_id", "host_id", "vm_id", "owner_id", "workload_id"):
            text(getattr(self, name), name)
        integer(self.workload_bytes, "workload_bytes", 1)


@dataclass(frozen=True)
class RuntimeBinding:
    """Fresh authenticated runtime facts, not values taken from a job request."""
    vm_id: str
    native_id: str
    process_id: str
    guest_boot_id: str
    image_id: str
    guest_kernel_id: str
    host_kernel_id: str
    qemu_version_id: str
    backend_version_id: str
    readback_version: str
    config_fingerprint: str  # excludes only the controlled memory target/revision


@dataclass(frozen=True)
class BackendQualification:
    host_id: str
    owner_id: str
    binding: RuntimeBinding
    policy_sha256: str
    evidence_ref: str
    qualified_dynamic: bool
    active_floor_protection: bool
    readback_verified: bool
    slurm_registration_verified: bool


@dataclass(frozen=True)
class HostEvidence:
    """A fresh protected host/guest probe and an exact administrator agreement.

    RootNativeBoundary reads this from a root-owned private probe file. Its writer
    must authenticate actual host/guest facts; clients cannot submit this object.
    A declaration/reference is never itself native qualification.
    """
    host_id: str
    owner_id: str
    host_boot_id: str
    policy_sha256: str
    observed_at: int
    physical_ram_bytes: int
    foreign_max_bytes: int
    capacity_evidence_ref: str
    agreement_ref: str
    foreign_growth_bounded: bool
    active_grants_protected: bool
    pressure_ok: bool
    evidence_ref: str
    bindings: tuple[RuntimeBinding, ...]
    qualifications: tuple[BackendQualification, ...]
    live_workloads: dict[str, tuple[str, ...]]  # complete authenticated actual guest inventory


@dataclass(frozen=True)
class VMReadback:
    vm_id: str
    native_id: str
    process_id: str
    config_fingerprint: str
    revision: str
    configured_bytes: int
    assigned_bytes: int
    running: bool


@dataclass(frozen=True)
class GuestEvidence:
    vm_id: str
    guest_boot_id: str
    workload_id: str
    observed_at: int
    total_bytes: int
    available_bytes: int
    os_reserve_bytes: int
    task_limit_bytes: int
    slurm_memory_bytes: int
    limits_enforced: bool
    live_workload_ids: tuple[str, ...]


@dataclass(frozen=True)
class CompletionEvidence:
    vm_id: str
    guest_boot_id: str
    workload_id: str
    observed_at: int
    completed_workload_children: int
    outputs_durable: bool
    cleanup_verified: bool
    total_bytes: int
    available_bytes: int
    live_workload_ids: tuple[str, ...]


@dataclass(frozen=True)
class NativeCleanupEvidence:
    """Fresh protected admin observation, never inferred from memory or job demand.

    Its absent production writer must establish actual mutator/descendant absence
    for this exact latest intent. This Python type/boolean is not authentication.
    """
    request_id: str
    mutation_id: str
    host_id: str
    owner_id: str
    host_boot_id: str
    policy_sha256: str
    binding: RuntimeBinding
    observed_at: int
    native_mutators_absent: bool
    evidence_ref: str


@dataclass(frozen=True)
class Receipt:
    request_id: str
    workload_id: str
    vm_id: str
    phase: str
    target_bytes: int
    failure: str | None


class MemoryBackend(Protocol):
    """A successful resize returns only after all owned native commands are cleaned.

    Exceptions may carry the shared command engine's native_record. Missing
    confirmed cleanup, including a process crash, requires explicit admin proof.
    """
    quantum_bytes: int

    def readback(self, vm_id: str) -> VMReadback: ...

    def resize(self, vm_id: str, target_bytes: int, before: VMReadback,
               timeout_seconds: int) -> VMReadback: ...


class FileReceiptStore:
    """One small durable host receipt file. No TTL, automatic pruning or daemon.

    Native callers use owner_uid=0 and a trusted ancestry; owner_uid is injectable
    only for unprivileged synthetic fixtures. A store instance never proves root
    authority: RootNativeBoundary is the mandatory privileged entrypoint.
    """
    def __init__(self, directory: Path, *, owner_uid: int = 0):
        self.directory = Path(directory).absolute()
        self.owner_uid = owner_uid
        self.state_path = self.directory / "state.json"
        created = not self.directory.exists()
        if created:
            self.directory.mkdir(mode=0o700)
        self._check_path(self.directory, directory=True)
        self.completed_directory = self.directory / "completed"
        self.workload_directory = self.directory / "workload-ids"
        for path in (self.completed_directory, self.workload_directory):
            path.mkdir(mode=0o700, exist_ok=True)
            self._check_path(path, directory=True)
        self._sync_directory(self.directory)
        if created:
            self._sync_directory(self.directory.parent)

    def _check_path(self, path, *, directory=False):
        st = path.lstat()
        require(not path.is_symlink() and st.st_uid == self.owner_uid and
                not (st.st_mode & 0o022) and
                (stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)),
                "trust", "unsafe host state path")

    def _check_fd(self, fd):
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == self.owner_uid and
                not st.st_mode & 0o022 and st.st_nlink == 1, "trust", "unsafe host state file")

    @contextmanager
    def locked(self):
        self._check_path(self.directory, directory=True)
        fd = os.open(self.directory / "host.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            self._check_fd(fd)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ResourceError("host_locked", "another host operation owns the lock") from exc
            yield
        finally:
            os.close(fd)

    def load(self):
        return self._read(self.state_path)

    def _read(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            self._check_fd(fd)
            require(os.fstat(fd).st_size <= MAX_STATE_BYTES, "state_full", "receipt is too large")
            data = os.read(fd, MAX_STATE_BYTES + 1)
            require(len(data) <= MAX_STATE_BYTES, "state_full", "receipt is too large")
            return strict_json(data.decode())
        finally:
            os.close(fd)

    @staticmethod
    def _key(value):
        return hashlib.sha256(value.encode()).hexdigest() + ".json"

    def completed(self, request_id):
        """O(1) durable idempotency lookup; no lifetime request counter or scan."""
        self._check_path(self.completed_directory, directory=True)
        path = self.completed_directory / self._key(request_id)
        if not path.exists():
            return None
        record = self._read(path)
        require(type(record) is dict and set(record) == {"schema", "receipt", "context"} and
                record["schema"] == "qcl.host-resource-completed.v2", "state", "invalid completed receipt")
        require(type(record["context"]) is dict and
                set(record["context"]) == {"host_boot_id", "policy_sha256", "binding"},
                "state", "missing original host/policy/runtime context")
        row = record["receipt"]
        require(type(row) is dict and set(row) == RECEIPT_FIELDS and
                row["phase"] == "RELEASE" and row["finished"] is True and
                row["native_cleanup_confirmed"] is True and
                row["request"]["request_id"] == request_id, "state", "invalid completed identity")
        ResourceRequest(**row["request"])
        return row

    def workload_exists(self, workload_id):
        self._check_path(self.workload_directory, directory=True)
        path = self.workload_directory / self._key(workload_id)
        if not path.exists():
            return False
        record = self._read(path)
        require(type(record) is dict and set(record) == {"schema", "workload_id", "request_id"} and
                record["schema"] == "qcl.host-resource-workload-id.v1" and
                record["workload_id"] == workload_id, "state", "invalid workload identity index")
        row = self.completed(record["request_id"])
        require(row is not None and row["request"]["workload_id"] == workload_id,
                "state", "orphan/conflicting workload identity index")
        return True

    def _immutable(self, path, record):
        self._check_path(path.parent, directory=True)
        if path.exists():
            require(self._read(path) == record, "state", "completed idempotency record conflicts")
        else:
            self._atomic(path, json.dumps(record, sort_keys=True).encode())

    def archive_completed(self, row, context):
        require(row["phase"] == "RELEASE" and row["finished"] is True,
                "state", "active/unknown grants cannot be archived")
        req = row["request"]
        self._immutable(self.completed_directory / self._key(req["request_id"]),
                        {"schema": "qcl.host-resource-completed.v2", "receipt": row, "context": context})
        self._immutable(self.workload_directory / self._key(req["workload_id"]),
                        {"schema": "qcl.host-resource-workload-id.v1",
                         "workload_id": req["workload_id"], "request_id": req["request_id"]})

    def save(self, state):
        data = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
        require(len(data) <= MAX_STATE_BYTES, "state_full", "retain old journal; no mutation")
        self._atomic(self.state_path, data)

    def save_failure(self, request_id, phase, error):
        """Retain bounded original native output privately; never scientific arrays."""
        key = hashlib.sha256((request_id + ":" + phase).encode()).hexdigest()
        record = {"request_id": request_id, "phase": phase,
                  "argv": list(error.native_argv),
                  "output_truncated": getattr(error, "native_output_truncated", False)}
        if hasattr(error, "native_record"):
            record["command_record"] = error.native_record
        else:
            record["output"] = error.native_output
        data = json.dumps(record, sort_keys=True).encode()
        require(len(data) <= 3 * MAX_STATE_BYTES, "output_bound", "oversized native failure evidence")
        self._atomic(self.directory / ("failure-" + key + ".json"), data)

    def _atomic(self, path, data):
        fd, name = tempfile.mkstemp(prefix=".state-", dir=self.directory)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, path)
            self._sync_directory(path.parent)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    @staticmethod
    def _sync_directory(path):
        directory_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


class HostResourceController:
    def __init__(self, policy: HostResourcePolicy, store: FileReceiptStore, backend: MemoryBackend,
                 clock: Callable[[], float] = time.time):
        require(type(policy) is HostResourcePolicy, "shape", "validated P19 policy required")
        integer(backend.quantum_bytes, "backend.quantum_bytes", 1)
        self.policy, self.store, self.backend, self.clock = policy, store, backend, clock

    def _grants(self, state):
        grants = tuple(ResidentGrant(**row) for row in state["grants"])
        validate_host_grants(self.policy, grants)
        return grants

    def _load(self):
        state = self.store.load()
        require(type(state) is dict and set(state) == {"schema", "policy_sha256", "host_boot_id",
                "grants", "bindings", "desired", "receipts", "blocked"} and
                state["schema"] == STATE_SCHEMA, "state", "invalid journal shape/schema")
        self._grants(state)
        require(type(state["receipts"]) is list, "state", "invalid receipts")
        ids, workloads = set(), set()
        for row in state["receipts"]:
            require(type(row) is dict and set(row) == RECEIPT_FIELDS, "state", "invalid receipt")
            req = ResourceRequest(**row["request"])
            self._request_owner(req)
            require(row["phase"] in PHASES and req.request_id not in ids and
                    req.workload_id not in workloads and type(row["finished"]) is bool,
                    "state", "invalid phase or duplicate identity")
            integer(row["target_bytes"], "target_bytes", 1)
            integer(row["old_bytes"], "old_bytes", 1)
            require(type(row["native_cleanup_confirmed"]) is bool and
                    (row["native_cleanup_confirmed"] or row["phase"] in UNKNOWN),
                    "state", "unconfirmed native cleanup outside unknown phase")
            if row["mutation_id"] is None:
                require(row["mutation_started_at"] is None and row["native_cleanup_confirmed"],
                        "state", "missing native mutation identity")
            else:
                text(row["mutation_id"], "mutation_id")
                integer(row["mutation_started_at"], "mutation_started_at")
            require((row["phase"] in {"RELEASE", "SHRINK_READY", "SHRINK_UNKNOWN", "SHRINK_DEFERRED"}) ==
                    row["finished"], "state", "phase/completion mismatch")
            ids.add(req.request_id)
            workloads.add(req.workload_id)
        require(sum(row["phase"] in PENDING for row in state["receipts"]) <= 1,
                "state", "multiple pending mutations")
        vm_ids = {vm.vm_id for vm in self.policy.vms}
        require(type(state["bindings"]) is dict and set(state["bindings"]) == vm_ids and
                type(state["desired"]) is dict and set(state["desired"]) == vm_ids,
                "state", "incomplete native/desired snapshot")
        for grant in self._grants(state):
            floor = self._floor(state, grant.vm_id)
            require(grant.active_floor_bytes >= floor, "state", "unpaid aggregate commitments")
            if self._live(state, grant.vm_id):
                require(grant.state in {"active", "ambiguous"}, "state", "live commitment is idle")
        return state

    def _save(self, state):
        # Publish both immutable identity records durably before pruning the
        # bounded active state. A crash at either barrier retains the old charge.
        for row in state["receipts"]:
            if row["phase"] == "RELEASE":
                self.store.archive_completed(row, {"host_boot_id": state["host_boot_id"],
                    "policy_sha256": state["policy_sha256"],
                    "binding": state["bindings"][row["request"]["vm_id"]]})
        state["receipts"] = [row for row in state["receipts"] if row["phase"] != "RELEASE"]
        if not any(row["phase"] in PENDING for row in state["receipts"]):
            deferred = next((row for row in state["receipts"]
                             if row["phase"] == "SHRINK_DEFERRED"), None)
            if deferred is not None:
                deferred["phase"] = "SHRINK_READY"  # durable metadata only, under the same host lock
        self.store.save(state)

    def snapshot(self) -> tuple[ResidentGrant, ...]:
        with self.store.locked():
            return self._grants(self._load())

    def _fresh(self, observed_at):
        integer(observed_at, "observed_at")
        require(0 <= self.clock() - observed_at <= self.policy.timeouts.request_seconds,
                "stale_evidence", "fresh authenticated probe required")

    def _evidence(self, evidence, *, pressure=True):
        require(type(evidence) is HostEvidence, "shape", "HostEvidence required")
        self._fresh(evidence.observed_at)
        p = self.policy
        integer(evidence.physical_ram_bytes, "physical_ram_bytes", 1)
        integer(evidence.foreign_max_bytes, "foreign_max_bytes")
        require(evidence.host_id == p.host_id and evidence.owner_id == p.owner_id,
                "ownership", "host/owner mismatch")
        require(evidence.physical_ram_bytes == p.physical_ram_bytes and
                evidence.foreign_max_bytes == p.reserves.foreign_max_bytes and
                evidence.capacity_evidence_ref == p.capacity_evidence_ref and
                evidence.agreement_ref == p.owned_pool.agreement_ref and
                evidence.foreign_growth_bounded is True and
                evidence.active_grants_protected is True, "capacity_evidence",
                "actual protected capacity agreement no longer matches policy")
        if pressure:
            require(evidence.pressure_ok is True, "host_pressure", "new admission is closed")
        text(evidence.evidence_ref, "evidence_ref")
        text(evidence.host_boot_id, "host_boot_id")
        require(type(evidence.bindings) is tuple and type(evidence.qualifications) is tuple,
                "shape", "explicit complete probe/qualification snapshot required")
        vm_ids = {vm.vm_id for vm in p.vms}
        bindings = {b.vm_id: b for b in evidence.bindings if type(b) is RuntimeBinding}
        require(len(bindings) == len(evidence.bindings) and set(bindings) == vm_ids,
                "incomplete_bindings", "every resident VM requires runtime identity")
        require(len({b.native_id for b in bindings.values()}) == len(bindings) and
                len({b.process_id for b in bindings.values()}) == len(bindings),
                "ownership", "resident VMs must have distinct native/process identities")
        qualifications = {q.binding.vm_id: q for q in evidence.qualifications
                          if type(q) is BackendQualification and type(q.binding) is RuntimeBinding}
        require(len(qualifications) == len(evidence.qualifications) and
                set(qualifications) == vm_ids, "qualification", "complete qualification required")
        for vm_id, binding in bindings.items():
            for name, value in asdict(binding).items():
                text(value, name)
            q = qualifications[vm_id]
            require(q.host_id == p.host_id and q.owner_id == p.owner_id and q.binding == binding and
                    q.policy_sha256 == policy_digest(p) and
                    q.evidence_ref == p.active_grant.qualification_ref and
                    q.active_floor_protection is True and q.readback_verified is True,
                    "qualification", "exact backend/image/runtime qualification required")
            if p.active_grant.mechanism == "qualified_dynamic":
                require(q.qualified_dynamic is True and q.slurm_registration_verified is True,
                        "qualification", "dynamic floor/readback/Slurm path is unsupported")
        return bindings

    def _block(self, state, detail):
        state["blocked"] = detail
        state["grants"] = [asdict(replace(g, state="ambiguous")) for g in self._grants(state)]
        self._save(state)
        raise ResourceError("identity_mismatch", detail)

    def _guard(self, state, evidence, *, pressure=True, completing=None):
        require(type(evidence) is HostEvidence, "shape", "HostEvidence required")
        require(state["blocked"] is None, "reconciliation_required", str(state["blocked"]))
        require(all(row["native_cleanup_confirmed"] for row in state["receipts"]),
                "reconciliation_required", "latest native mutation cleanup requires exact admin proof")
        if evidence.host_boot_id != state["host_boot_id"] or \
                evidence.policy_sha256 != state["policy_sha256"] or \
                state["policy_sha256"] != policy_digest(self.policy):
            self._block(state, "host boot or policy changed; administrator reconciliation required")
        bindings = self._evidence(evidence, pressure=pressure)
        if {key: asdict(value) for key, value in bindings.items()} != state["bindings"]:
            self._block(state, "runtime binding changed")
        require(type(evidence.live_workloads) is dict and
                set(evidence.live_workloads) == set(bindings),
                "incomplete_workloads", "complete host workload inventory required")
        for vm_id, actual_work in evidence.live_workloads.items():
            expected_work = {r["request"]["workload_id"] for r in state["receipts"]
                             if r["request"]["vm_id"] == vm_id and r["phase"] == "RUN" and
                             r["request"]["workload_id"] != completing}
            require(type(actual_work) is tuple and len(set(actual_work)) == len(actual_work) and
                    set(actual_work) == expected_work, "incomplete_workloads",
                    "unknown/missing live workload requires reconciliation")
        readbacks = {}
        for grant in self._grants(state):
            row = self.backend.readback(grant.vm_id)
            require(type(row) is VMReadback, "readback", "typed actual memory readback required")
            binding = bindings[grant.vm_id]
            if row.vm_id != grant.vm_id or row.native_id != binding.native_id or \
                    row.process_id != binding.process_id or \
                    row.config_fingerprint != binding.config_fingerprint or row.running is not True:
                self._block(state, "VM process, configuration, ownership or running state changed")
            integer(row.assigned_bytes, "assigned_bytes", 1)
            integer(row.configured_bytes, "configured_bytes", 1)
            text(row.revision, "revision")
            if max(row.assigned_bytes, row.configured_bytes) > grant.guest_bytes:
                self._block(state, "observed memory exceeds the charged grant")
            # A HOST_GRANT reserves future capacity before grow. Only already
            # running commitments establish the lower live allocation bound.
            # finish() validates exact fresh cleanup before excluding its work.
            live_floor = self._vm(grant.vm_id).minimum_bytes + sum(
                r["request"]["workload_bytes"] for r in state["receipts"]
                if r["request"]["vm_id"] == grant.vm_id and r["phase"] == "RUN" and
                r["request"]["workload_id"] != completing)
            if min(row.assigned_bytes, row.configured_bytes) < live_floor:
                self._block(state, "observed allocation is below the protected live RUN floor")
            readbacks[grant.vm_id] = row
        return readbacks

    def bootstrap(self, grants: Sequence[ResidentGrant], evidence: HostEvidence) -> None:
        """Initialize once from a complete independently established idle baseline.

        Active/unknown prior work is never reset by this method. Missing private
        state on an already used host must be reconciled by its administrator.
        """
        with self.store.locked():
            require(not self.store.state_path.exists(), "already_initialized", "retain old journal")
            validate_host_grants(self.policy, grants)
            require(all(g.state == "idle" for g in grants), "baseline", "verified idle baseline required")
            bindings = self._evidence(evidence)
            state = {"schema": STATE_SCHEMA, "policy_sha256": policy_digest(self.policy),
                     "host_boot_id": evidence.host_boot_id,
                     "grants": [asdict(g) for g in grants],
                     "bindings": {key: asdict(b) for key, b in bindings.items()},
                     "desired": {g.vm_id: g.guest_bytes for g in grants},
                     "receipts": [], "blocked": None}
            self._guard(state, evidence)
            self._save(state)

    def _vm(self, vm_id):
        result = next((vm for vm in self.policy.vms if vm.vm_id == vm_id), None)
        require(result is not None, "ownership", "unknown/foreign VM")
        return result

    def _request_owner(self, req):
        require(req.host_id == self.policy.host_id and req.owner_id == self.policy.owner_id,
                "ownership", "request host/owner mismatch")
        self._vm(req.vm_id)

    def _live(self, state, vm_id):
        return [row for row in state["receipts"] if row["request"]["vm_id"] == vm_id and
                not row["finished"]]

    def _floor(self, state, vm_id):
        return self._vm(vm_id).minimum_bytes + sum(row["request"]["workload_bytes"]
                                                  for row in self._live(state, vm_id))

    def _grant(self, state, vm_id):
        return next(g for g in self._grants(state) if g.vm_id == vm_id)

    def _set_grant(self, state, grant):
        state["grants"] = [asdict(grant if g.vm_id == grant.vm_id else g)
                           for g in self._grants(state)]
        validate_host_grants(self.policy, self._grants(state))

    def _receipt(self, row):
        req = row["request"]
        return Receipt(req["request_id"], req["workload_id"], req["vm_id"], row["phase"],
                       row["target_bytes"], row["failure"])

    def _row(self, state, request_id, phases=None):
        row = next((r for r in state["receipts"] if r["request"]["request_id"] == request_id), None)
        if row is None:
            row = self.store.completed(request_id)
        require(row is not None, "request_unknown", "request does not belong to this host")
        self._request_owner(ResourceRequest(**row["request"]))
        require(phases is None or row["phase"] in phases, "phase", "operation is invalid in this phase")
        return row

    def _rounded(self, value):
        quantum = self.backend.quantum_bytes
        return ((value + quantum - 1) // quantum) * quantum

    def request(self, request: ResourceRequest, evidence: HostEvidence) -> Receipt:
        require(type(request) is ResourceRequest, "shape", "ResourceRequest required")
        self._request_owner(request)
        with self.store.locked():
            state = self._load()
            previous = next((r for r in state["receipts"] if
                             r["request"]["request_id"] == request.request_id), None)
            if previous is None:
                previous = self.store.completed(request.request_id)
            if previous is not None:
                require(previous["request"] == asdict(request), "request_conflict", "id payload changed")
                return self._receipt(previous)
            self._guard(state, evidence)
            require(not any(r["phase"] in PENDING for r in state["receipts"]),
                    "host_busy", "another host mutation needs completion/reconciliation")
            require(not any(r["request"]["workload_id"] == request.workload_id
                            for r in state["receipts"]) and
                    not self.store.workload_exists(request.workload_id),
                    "workload_conflict", "workload id already exists")
            vm, grant = self._vm(request.vm_id), self._grant(state, request.vm_id)
            floor = self._floor(state, request.vm_id) + request.workload_bytes
            target = max(grant.guest_bytes, self._rounded(floor))
            if self.policy.active_grant.mechanism == "conservative_reservation":
                target = vm.maximum_bytes
            validate_resize(self.policy, self._grants(state), request.vm_id, target)
            require(floor <= target, "maximum", "aggregate commitments exceed protected guest capacity")
            row = {"request": asdict(request), "phase": "HOST_GRANT", "target_bytes": target,
                   "old_bytes": grant.guest_bytes, "failure": None, "finished": False,
                   "mutation_id": None, "mutation_started_at": None, "native_cleanup_confirmed": True}
            state["receipts"].append(row)
            self._set_grant(state, replace(grant, guest_bytes=target, active_floor_bytes=floor,
                                           state="active"))
            state["desired"][request.vm_id] = target
            self._save(state)  # the entire rounded grant precedes native mutation
            return self._receipt(row)

    def _target_readback(self, state, row, readback):
        binding = state["bindings"][row["request"]["vm_id"]]
        return (type(readback) is VMReadback and readback.running is True and
                readback.native_id == binding["native_id"] and
                readback.process_id == binding["process_id"] and
                readback.config_fingerprint == binding["config_fingerprint"] and
                readback.configured_bytes == row["target_bytes"] and
                readback.assigned_bytes == row["target_bytes"])

    def _change(self, request_id, evidence, *, shrink):
        with self.store.locked():
            state = self._load()
            row = self._row(state, request_id, {"SHRINK_READY", "SHRINK_DEFERRED"} if shrink else {"HOST_GRANT"})
            before = self._guard(state, evidence, pressure=not shrink)[row["request"]["vm_id"]]
            require(row["phase"] != "SHRINK_DEFERRED", "host_busy", "another pending mutation owns the host")
            vm_id = row["request"]["vm_id"]
            grant = self._grant(state, vm_id)
            if shrink:
                require(not self._live(state, vm_id), "protected_grant", "other work is active")
                target = (self._vm(vm_id).maximum_bytes if self.policy.active_grant.mechanism ==
                          "conservative_reservation" else self._rounded(self._vm(vm_id).minimum_bytes))
                validate_resize(self.policy, self._grants(state), vm_id, target)
                row["old_bytes"], row["target_bytes"] = grant.guest_bytes, target
                state["desired"][vm_id] = target
            row["phase"] = "SHRINK_UNKNOWN" if shrink else "GROW_UNKNOWN"
            needs_resize = (before.assigned_bytes != row["target_bytes"] or
                            before.configured_bytes != row["target_bytes"])
            row["mutation_id"] = uuid.uuid4().hex if needs_resize else None
            row["mutation_started_at"] = int(self.clock()) if needs_resize else None
            row["native_cleanup_confirmed"] = not needs_resize
            self._set_grant(state, replace(grant, state="ambiguous"))
            self._save(state)  # cleanup-pending barrier MUST be durable before actual resize
            try:
                actual = (before if not needs_resize else
                          self.backend.resize(vm_id, row["target_bytes"], before,
                            self.policy.timeouts.shrink_seconds if shrink else
                            self.policy.timeouts.grow_seconds))
                row["native_cleanup_confirmed"] = True  # successful backend's owned cleanup contract
                if self._target_readback(state, row, actual) and not shrink:
                    row["phase"] = "GUEST_ADMIT"
                    self._set_grant(state, replace(self._grant(state, vm_id), state="active"))
                elif not self._target_readback(state, row, actual):
                    row["failure"] = "readback_pending"
            except Exception as exc:
                row["failure"] = getattr(exc, "code", type(exc).__name__)
                native_record = getattr(exc, "native_record", None)
                if needs_resize:
                    row["native_cleanup_confirmed"] = (native_record is not None and
                                                        native_record.get("cleanup_confirmed") is True)
                if not row["native_cleanup_confirmed"]:
                    state["blocked"] = CLEANUP_BLOCK
                secondary = None
                try:
                    self._save(state)
                except Exception as journal_error:
                    exc.native_journal_error = type(journal_error).__name__
                    exc.native_journal_exception = journal_error
                    secondary = journal_error
                if hasattr(exc, "native_output") and hasattr(exc, "native_argv"):
                    try:
                        self.store.save_failure(request_id, row["phase"], exc)
                    except Exception as log_error:
                        exc.native_log_error = type(log_error).__name__
                        exc.native_log_exception = log_error
                        secondary = log_error
                if secondary is not None:
                    raise exc from secondary  # original native failure/record must not be masked
                return self._receipt(row)
            self._save(state)
            return self._receipt(row)

    def grow(self, request_id: str, evidence: HostEvidence) -> Receipt:
        return self._change(request_id, evidence, shrink=False)

    def shrink(self, request_id: str, evidence: HostEvidence) -> Receipt:
        return self._change(request_id, evidence, shrink=True)

    def _guest(self, state, row, evidence):
        self._fresh(evidence.observed_at)
        req = row["request"]
        require(evidence.vm_id == req["vm_id"] and evidence.workload_id == req["workload_id"] and
                evidence.guest_boot_id == state["bindings"][req["vm_id"]]["guest_boot_id"],
                "identity_mismatch", "guest boot/workload identity changed")
        for name in ("total_bytes", "available_bytes"):
            integer(getattr(evidence, name), name)
        require(0 < evidence.total_bytes and evidence.available_bytes <= evidence.total_bytes,
                "guest_capacity", "invalid measured guest capacity")
        expected = {r["request"]["workload_id"] for r in self._live(state, req["vm_id"])
                    if r is not row and r["phase"] == "RUN"}
        require(type(evidence.live_workload_ids) is tuple and
                len(set(evidence.live_workload_ids)) == len(evidence.live_workload_ids) and
                set(evidence.live_workload_ids) == expected,
                "incomplete_workloads", "exact other-live-workload snapshot is required")

    def admit(self, request_id: str, guest_evidence: GuestEvidence, evidence: HostEvidence) -> Receipt:
        require(type(guest_evidence) is GuestEvidence, "shape", "GuestEvidence required")
        with self.store.locked():
            state = self._load()
            row = self._row(state, request_id, {"GUEST_ADMIT"})
            readback = self._guard(state, evidence)[row["request"]["vm_id"]]
            require(self._target_readback(state, row, readback), "readback", "full grow is unconfirmed")
            self._guest(state, row, guest_evidence)
            vm, req, g = self._vm(row["request"]["vm_id"]), row["request"], guest_evidence
            for name in ("os_reserve_bytes", "task_limit_bytes", "slurm_memory_bytes"):
                integer(getattr(g, name), name, 1)
            grant = self._grant(state, vm.vm_id)
            require(g.limits_enforced is True and g.os_reserve_bytes <= vm.minimum_bytes and
                    g.task_limit_bytes <= req["workload_bytes"] and
                    g.slurm_memory_bytes <= grant.guest_bytes - g.os_reserve_bytes and
                    g.total_bytes >= self._floor(state, vm.vm_id) and
                    g.available_bytes >= req["workload_bytes"], "guest_capacity",
                    "guest reserve/cgroup/Slurm/available memory does not fit the aggregate grant")
            row["phase"], row["failure"] = "RUN", None
            self._save(state)
            return self._receipt(row)

    def _completion(self, state, row, completion):
        require(type(completion) is CompletionEvidence, "shape", "CompletionEvidence required")
        self._guest(state, row, completion)
        integer(completion.completed_workload_children, "completed_workload_children")
        require(completion.completed_workload_children == 0 and completion.outputs_durable is True and
                completion.cleanup_verified is True, "cleanup", "live descendants/output/cleanup unknown")

    def finish(self, request_id: str, completion_evidence: CompletionEvidence,
               evidence: HostEvidence) -> Receipt:
        with self.store.locked():
            state = self._load()
            row = self._row(state, request_id, {"RUN"})
            self._completion(state, row, completion_evidence)
            self._guard(state, evidence, pressure=False,
                        completing=row["request"]["workload_id"])
            row["finished"] = True
            vm_id = row["request"]["vm_id"]
            grant = self._grant(state, vm_id)
            others = self._live(state, vm_id)
            other_pending = any(r is not row and r["phase"] in PENDING for r in state["receipts"])
            row["phase"] = ("RELEASE" if others else "SHRINK_DEFERRED" if other_pending else "SHRINK_READY")
            next_state = ("ambiguous" if grant.state == "ambiguous" else
                          "active" if others else "idle")
            self._set_grant(state, replace(grant, active_floor_bytes=self._floor(state, vm_id),
                                           state=next_state))
            self._save(state)
            return self._receipt(row)

    def _cleanup(self, state, row, cleanup, evidence):
        require(type(cleanup) is NativeCleanupEvidence and type(evidence) is HostEvidence,
                "cleanup_evidence", "fresh protected native cleanup proof required")
        self._fresh(cleanup.observed_at)
        text(cleanup.evidence_ref, "cleanup evidence_ref")
        req = row["request"]
        require(row["phase"] in UNKNOWN and row["mutation_id"] is not None and
                cleanup.request_id == req["request_id"] and cleanup.mutation_id == row["mutation_id"] and
                cleanup.host_id == self.policy.host_id and cleanup.owner_id == self.policy.owner_id and
                cleanup.host_boot_id == state["host_boot_id"] == evidence.host_boot_id and
                cleanup.policy_sha256 == state["policy_sha256"] == policy_digest(self.policy) and
                type(cleanup.binding) is RuntimeBinding and
                asdict(cleanup.binding) == state["bindings"][req["vm_id"]] and
                cleanup.observed_at >= row["mutation_started_at"] and
                cleanup.native_mutators_absent is True, "cleanup_evidence",
                "cleanup proof must identify the exact latest native mutation/runtime")
        row["native_cleanup_confirmed"] = True
        if state["blocked"] == CLEANUP_BLOCK:
            state["blocked"] = None  # identity/config/reboot blocks are never cleared here

    def reconcile(self, request_id: str, evidence: HostEvidence,
                  completion_evidence: CompletionEvidence | None = None, *,
                  cleanup_evidence: NativeCleanupEvidence | None = None) -> Receipt:
        """Read only native state; never resubmit an uncertain mutation or expire a grant."""
        with self.store.locked():
            state = self._load()
            row = self._row(state, request_id)
            vm_id = row["request"]["vm_id"]
            uses_cleanup = cleanup_evidence is not None and row["phase"] in UNKNOWN
            if uses_cleanup:
                self._cleanup(state, row, cleanup_evidence, evidence)
            actual = self._guard(state, evidence, pressure=False)[vm_id]
            if row["phase"] in {"GROW_UNKNOWN", "SHRINK_UNKNOWN"} and \
                    self._target_readback(state, row, actual):
                grant = self._grant(state, vm_id)
                if row["phase"] == "GROW_UNKNOWN":
                    row["phase"] = "GUEST_ADMIT"
                    self._set_grant(state, replace(grant, state="active"))
                elif completion_evidence is not None:
                    self._completion(state, row, completion_evidence)
                    require(not self._live(state, vm_id) and
                            completion_evidence.total_bytes <= row["target_bytes"],
                            "guest_readback", "fresh guest shrink/cleanup is unconfirmed")
                    row["phase"] = "RELEASE"
                    self._set_grant(state, replace(grant, guest_bytes=row["target_bytes"],
                                  active_floor_bytes=self._vm(vm_id).minimum_bytes, state="idle"))
                row["failure"] = None
                self._save(state)
            elif uses_cleanup:
                self._save(state)  # retain cleanup proof; allocation outcome may still be unknown
            return self._receipt(row)
