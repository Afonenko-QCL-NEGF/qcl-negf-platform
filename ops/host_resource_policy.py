"""Pure per-host resident memory contract, with no discovery or native mutations.

Validated declarations are inputs to a native admission protocol, not proof that an
administrator agreement, measurement or backend qualification is true. All amounts
are integer bytes; every resident VM needs an explicit, still-charged grant.
"""
from dataclasses import dataclass, replace
from typing import Literal, Mapping, Sequence

SCHEMA = "qcl.host-resource-policy.v1"
MAX_INTEGER = (1 << 63) - 1
GrantState = Literal["idle", "active", "ambiguous"]
GrantMechanism = Literal["conservative_reservation", "qualified_dynamic"]


class PolicyValidationError(ValueError):
    """Fail-closed contract violation; ``code`` is suitable for consumer reasons."""

    def __init__(self, code: str, detail: str):
        self.code = code
        super().__init__(f"{code}: {detail}")


def _fail(code: str, detail: str) -> None:
    raise PolicyValidationError(code, detail)


def _text(value: object, name: str) -> None:
    if type(value) is not str or not value or value.strip() != value or "\x00" in value:
        _fail("unknown_value", f"{name} must be explicit nonempty text")


def _integer(value: object, name: str, *, positive: bool = False) -> None:
    lower = 1 if positive else 0
    if type(value) is not int or not lower <= value <= MAX_INTEGER:
        _fail("unknown_value", f"{name} must be an integer in [{lower}, {MAX_INTEGER}]")


def _object(value: object, names: str, name: str) -> dict:
    if type(value) is not dict or set(value) != set(names.split()):
        _fail("shape", f"{name} requires exactly: {names}")
    return value


@dataclass(frozen=True)
class HostReserves:
    host_services_bytes: int
    control_plane_bytes: int
    safety_bytes: int
    foreign_max_bytes: int
    evidence_ref: str

    def __post_init__(self) -> None:
        for name in ("host_services_bytes", "control_plane_bytes", "safety_bytes", "foreign_max_bytes"):
            _integer(getattr(self, name), name)
        _text(self.evidence_ref, "reserves.evidence_ref")


@dataclass(frozen=True)
class OwnedPool:
    capacity_bytes: int
    agreement_ref: str
    enforceable: bool
    foreign_growth_bounded: bool
    active_grants_protected: bool

    def __post_init__(self) -> None:
        _integer(self.capacity_bytes, "owned_pool.capacity_bytes", positive=True)
        _text(self.agreement_ref, "owned_pool.agreement_ref")
        for name in ("enforceable", "foreign_growth_bounded", "active_grants_protected"):
            if getattr(self, name) is not True:
                _fail("capacity_agreement", f"owned_pool.{name} must be explicitly true")


@dataclass(frozen=True)
class ActiveGrantMechanism:
    mechanism: GrantMechanism
    qualification_ref: str

    def __post_init__(self) -> None:
        if self.mechanism not in ("conservative_reservation", "qualified_dynamic"):
            _fail("grant_mechanism", "unsupported active-grant mechanism")
        _text(self.qualification_ref, "active_grant.qualification_ref")


@dataclass(frozen=True)
class PolicyTimeouts:
    request_seconds: int
    grow_seconds: int
    shrink_seconds: int
    reconcile_seconds: int

    def __post_init__(self) -> None:
        for name in ("request_seconds", "grow_seconds", "shrink_seconds", "reconcile_seconds"):
            _integer(getattr(self, name), f"timeouts.{name}", positive=True)


@dataclass(frozen=True)
class ResidentVMPolicy:
    vm_id: str
    owner_id: str
    resident: bool
    minimum_bytes: int
    startup_bytes: int
    maximum_bytes: int
    overhead_bytes: int
    overhead_evidence_ref: str
    cpu_weight: int
    memory_weight: int

    def __post_init__(self) -> None:
        for name in ("vm_id", "owner_id", "overhead_evidence_ref"):
            _text(getattr(self, name), f"vm.{name}")
        if self.resident is not True:
            _fail("resident_policy", "every managed VM must remain resident")
        for name in ("minimum_bytes", "startup_bytes", "maximum_bytes", "cpu_weight", "memory_weight"):
            _integer(getattr(self, name), f"vm.{name}", positive=True)
        _integer(self.overhead_bytes, "vm.overhead_bytes")
        if not self.minimum_bytes <= self.startup_bytes <= self.maximum_bytes:
            _fail("resident_order", "require minimum_bytes <= startup_bytes <= maximum_bytes")


@dataclass(frozen=True)
class MemoryBudget:
    host_reserve_bytes: int
    foreign_reserve_bytes: int
    guest_grant_bytes: int
    vm_overhead_bytes: int
    owned_charge_bytes: int
    total_charge_bytes: int
    pool_headroom_bytes: int
    physical_headroom_bytes: int


def _budget(policy: "HostResourcePolicy", guest_bytes: int) -> MemoryBudget:
    reserves = policy.reserves
    host = reserves.host_services_bytes + reserves.control_plane_bytes + reserves.safety_bytes
    overhead = sum(vm.overhead_bytes for vm in policy.vms)
    owned = guest_bytes + overhead
    total = host + reserves.foreign_max_bytes + owned
    if owned > policy.owned_pool.capacity_bytes:
        _fail("pool_overcommit", "full guest grants plus VM overhead exceed the owned pool")
    if total > policy.physical_ram_bytes:
        _fail("physical_overcommit", "H + F + sum(B_i + O_i) exceeds physical RAM")
    return MemoryBudget(host, reserves.foreign_max_bytes, guest_bytes, overhead, owned, total,
                        policy.owned_pool.capacity_bytes - owned, policy.physical_ram_bytes - total)


@dataclass(frozen=True)
class HostResourcePolicy:
    host_id: str
    owner_id: str
    physical_ram_bytes: int
    capacity_evidence_ref: str
    reserves: HostReserves
    owned_pool: OwnedPool
    active_grant: ActiveGrantMechanism
    timeouts: PolicyTimeouts
    vms: tuple[ResidentVMPolicy, ...]

    def __post_init__(self) -> None:
        for name in ("host_id", "owner_id", "capacity_evidence_ref"):
            _text(getattr(self, name), name)
        _integer(self.physical_ram_bytes, "physical_ram_bytes", positive=True)
        for name, expected in (("reserves", HostReserves), ("owned_pool", OwnedPool),
                               ("active_grant", ActiveGrantMechanism), ("timeouts", PolicyTimeouts)):
            if type(getattr(self, name)) is not expected:
                _fail("shape", f"{name} requires {expected.__name__}")
        if type(self.vms) is not tuple or not self.vms:
            _fail("shape", "vms must be a nonempty immutable tuple")
        seen = set()
        for vm in self.vms:
            if type(vm) is not ResidentVMPolicy:
                _fail("shape", "vms requires ResidentVMPolicy values")
            if vm.vm_id in seen:
                _fail("ownership", "duplicate VM identity")
            if vm.owner_id != self.owner_id:
                _fail("ownership", f"VM {vm.vm_id} is not owned by the declared host operator")
            seen.add(vm.vm_id)
        h = self.reserves.host_services_bytes + self.reserves.control_plane_bytes + self.reserves.safety_bytes
        if h + self.reserves.foreign_max_bytes + self.owned_pool.capacity_bytes > self.physical_ram_bytes:
            _fail("pool_exceeds_physical", "owned pool conflicts with physical RAM and H/F reserves")
        # All resident startup reservations must fit. Conservative fallback also
        # charges every maximum; dynamic mode never substitutes sum(max) for RAM.
        _budget(self, sum(vm.startup_bytes for vm in self.vms))
        if self.active_grant.mechanism == "conservative_reservation":
            _budget(self, sum(vm.maximum_bytes for vm in self.vms))


@dataclass(frozen=True)
class ResidentGrant:
    """Full charged reservation, including idle floor; no TTL releases it.

    ``active_floor_bytes`` includes the resident floor and every live job/build
    commitment. ``ambiguous`` retains the full last conservative reservation
    until native reconciliation; timeouts never turn it into an idle grant.
    """
    host_id: str
    vm_id: str
    owner_id: str
    guest_bytes: int
    active_floor_bytes: int
    state: GrantState


def validate_host_resource_policy(document: Mapping[str, object]) -> HostResourcePolicy:
    """Validate strict public v1 declarations and return immutable typed values.

    Structural JSON Schema validation alone does not check cross-field safety.
    No file is read, lock acquired, native mode enabled, or evidence verified.
    """
    doc = _object(document, "schema host_id owner_id physical_ram_bytes capacity_evidence_ref "
                  "reserves owned_pool active_grant timeouts vms", "host policy")
    if doc["schema"] != SCHEMA:
        _fail("schema", f"expected {SCHEMA}")
    reserves = HostReserves(**_object(doc["reserves"], "host_services_bytes control_plane_bytes "
                              "safety_bytes foreign_max_bytes evidence_ref", "reserves"))
    pool = OwnedPool(**_object(doc["owned_pool"], "capacity_bytes agreement_ref enforceable "
                              "foreign_growth_bounded active_grants_protected", "owned_pool"))
    mechanism = ActiveGrantMechanism(**_object(doc["active_grant"], "mechanism qualification_ref",
                                             "active_grant"))
    timeouts = PolicyTimeouts(**_object(doc["timeouts"], "request_seconds grow_seconds shrink_seconds "
                                      "reconcile_seconds", "timeouts"))
    if type(doc["vms"]) is not list:
        _fail("shape", "vms must be an array")
    vms = tuple(ResidentVMPolicy(**_object(vm, "vm_id owner_id resident minimum_bytes startup_bytes "
                  "maximum_bytes overhead_bytes overhead_evidence_ref cpu_weight memory_weight", "vm"))
                for vm in doc["vms"])
    return HostResourcePolicy(doc["host_id"], doc["owner_id"], doc["physical_ram_bytes"],
                              doc["capacity_evidence_ref"], reserves, pool, mechanism, timeouts, vms)


def validate_host_grants(policy: HostResourcePolicy, grants: Sequence[ResidentGrant]) -> MemoryBudget:
    """Check complete owned grants and H + F + Σ(B + O) <= physical RAM.

    The full proposed reservation is charged before grow, independently of RSS,
    guest reclaimability, virtual maxima, Slurm settings or MemAvailable. The
    returned budget is arithmetic evidence, not native admission/readback.
    """
    if type(policy) is not HostResourcePolicy:
        _fail("shape", "policy must be a validated HostResourcePolicy")
    if not isinstance(grants, (tuple, list)):
        _fail("shape", "grants must be an explicit list or tuple")
    vms = {vm.vm_id: vm for vm in policy.vms}
    seen = set()
    charged = 0
    for grant in grants:
        if type(grant) is not ResidentGrant:
            _fail("shape", "grants must contain ResidentGrant values")
        for name in ("host_id", "vm_id", "owner_id"):
            _text(getattr(grant, name), f"grant.{name}")
        if (grant.host_id != policy.host_id or grant.owner_id != policy.owner_id
                or grant.vm_id not in vms or grant.vm_id in seen):
            _fail("ownership", "grant host/VM/owner must match exactly once")
        seen.add(grant.vm_id)
        vm = vms[grant.vm_id]
        _integer(grant.guest_bytes, "grant.guest_bytes", positive=True)
        _integer(grant.active_floor_bytes, "grant.active_floor_bytes", positive=True)
        if grant.state not in ("idle", "active", "ambiguous"):
            _fail("grant_state", "unknown grant state requires reconciliation")
        if grant.guest_bytes < vm.minimum_bytes:
            _fail("resident_floor", "grant is below the resident minimum")
        if grant.guest_bytes > vm.maximum_bytes:
            _fail("maximum", "grant exceeds the VM maximum")
        if not vm.minimum_bytes <= grant.active_floor_bytes <= grant.guest_bytes:
            _fail("active_floor", "resident minimum <= active floor <= full grant is required")
        if grant.state == "idle" and grant.active_floor_bytes != vm.minimum_bytes:
            _fail("active_floor", "idle grant must have exactly the resident minimum as floor")
        if (policy.active_grant.mechanism == "conservative_reservation"
                and grant.guest_bytes != vm.maximum_bytes):
            _fail("conservative_reservation", "unqualified mode charges every full VM maximum")
        charged += grant.guest_bytes
    if seen != set(vms):
        _fail("incomplete_grants", "every resident VM requires an explicit current charged grant")
    return _budget(policy, charged)


def validate_resize(policy: HostResourcePolicy, grants: Sequence[ResidentGrant],
                    vm_id: str, target_bytes: int) -> MemoryBudget:
    """Check a proposed full grant without changing policy, grants or a VM.

    Active/ambiguous grants never shrink. An idle shrink result is only a
    proposal: native consumers keep charging the old grant until confirmed
    host/guest readback and cleanup. This function does not authorize release.
    """
    validate_host_grants(policy, grants)
    _text(vm_id, "vm_id")
    _integer(target_bytes, "target_bytes", positive=True)
    current = next((grant for grant in grants if grant.vm_id == vm_id), None)
    if current is None:
        _fail("ownership", "cannot resize an unknown/foreign VM")
    if target_bytes < current.guest_bytes and current.state in ("active", "ambiguous"):
        _fail("protected_grant", "active or ambiguous full grant cannot shrink")
    proposed = tuple(replace(grant, guest_bytes=target_bytes) if grant.vm_id == vm_id else grant
                     for grant in grants)
    return validate_host_grants(policy, proposed)
