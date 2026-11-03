"""Pure native-accounting and guest-physical capacity predicates.

This module performs no discovery, I/O, mutation, or authentication. A decoded
declaration is not itself evidence that its referenced measurements happened.
All memory values are checked integer bytes; unknown values never become zero.
"""
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import re
from types import MappingProxyType

MAX_INTEGER = (1 << 63) - 1
SCHEMA = "qcl.host-resource-capacity-qualification.v2"
BINDING_FIELDS = frozenset((
    "vm_id", "native_id", "process_id", "guest_boot_id", "image_id", "guest_kernel_id",
    "host_kernel_id", "qemu_version_id", "backend_version_id", "readback_version", "config_fingerprint",
))


class CapacityValidationError(ValueError):
    """Fail-closed capacity violation with a bounded consumer reason code."""

    def __init__(self, code: str, detail: str):
        self.code = code
        super().__init__(f"{code}: {detail}")


def _require(condition, code, detail):
    if not condition:
        raise CapacityValidationError(code, detail)


def _integer(value, name, *, positive=False):
    _require(type(value) is int and (1 if positive else 0) <= value <= MAX_INTEGER,
             "unknown_value", f"{name} must be explicit integer bytes")
    return value


def _text(value, name):
    _require(type(value) is str and 0 < len(value) <= 4096 and value.strip() == value and
             "\x00" not in value, "unknown_value", f"{name} must be explicit bounded text")
    return value


def _sha(value, name):
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
             "unknown_value", f"{name} must be a SHA-256 digest")
    return value


def _object(value, fields, name):
    _require(type(value) is dict and set(value) == set(fields), "shape", f"exact {name} fields required")
    return value


def _binding(value):
    _require(isinstance(value, Mapping) and set(value) == BINDING_FIELDS,
             "shape", "exact RuntimeBinding fields required")
    return {key: _text(value[key], f"binding.{key}") for key in BINDING_FIELDS}


@dataclass(frozen=True)
class GuestCapacityQualification:
    """Validated private declaration, bound by the caller to accepted actual evidence.

    Construction/decoding never authenticates a report or performs a measurement.
    Immutable binding data cannot be changed through a decoded input alias.
    """

    host_id: str
    owner_id: str
    policy_sha256: str
    binding: Mapping[str, str]
    source_graph_sha256: str
    report_sha256: str
    measurement_scope: str
    evidence_sha256: str
    mapping_evidence_sha256: str
    observed_os_bytes: int
    safety_allowance_bytes: int
    os_reserve_bytes: int
    native_gap_bound_bytes: int
    maximum_guest_total_bytes: int
    native_maximum_bytes: int

    def __post_init__(self):
        for name in ("host_id", "owner_id", "measurement_scope"):
            _text(getattr(self, name), name)
        for name in ("policy_sha256", "source_graph_sha256", "report_sha256", "evidence_sha256",
                     "mapping_evidence_sha256"):
            _sha(getattr(self, name), name)
        object.__setattr__(self, "binding", MappingProxyType(_binding(self.binding)))
        for name in ("observed_os_bytes", "os_reserve_bytes", "maximum_guest_total_bytes", "native_maximum_bytes"):
            _integer(getattr(self, name), name, positive=True)
        for name in ("safety_allowance_bytes", "native_gap_bound_bytes"):
            _integer(getattr(self, name), name)
        _require(self.observed_os_bytes + self.safety_allowance_bytes == self.os_reserve_bytes,
                 "capacity_profile", "reserve must join measured OS observation and explicit safety allowance")
        _require(self.os_reserve_bytes < self.maximum_guest_total_bytes <= self.native_maximum_bytes,
                 "capacity_profile", "measured maximum must fit native maximum and leave guest capacity")
        _require(self.native_maximum_bytes - self.maximum_guest_total_bytes <= self.native_gap_bound_bytes <
                 self.native_maximum_bytes, "capacity_profile", "native gap bound contradicts maximum observation")


def _join(qualification, *, expected_host_id, expected_owner_id, expected_policy_sha256,
          expected_binding, expected_source_graph_sha256, expected_report_sha256,
          expected_native_maximum_bytes):
    expected = (_text(expected_host_id, "expected_host_id"), _text(expected_owner_id, "expected_owner_id"),
                _sha(expected_policy_sha256, "expected_policy_sha256"), _binding(expected_binding),
                _sha(expected_source_graph_sha256, "expected_source_graph_sha256"),
                _sha(expected_report_sha256, "expected_report_sha256"),
                _integer(expected_native_maximum_bytes, "expected_native_maximum_bytes", positive=True))
    actual = (qualification.host_id, qualification.owner_id, qualification.policy_sha256,
              dict(qualification.binding), qualification.source_graph_sha256, qualification.report_sha256,
              qualification.native_maximum_bytes)
    _require(actual == expected, "identity_mismatch", "capacity profile differs from actual owner/runtime/source/report")


def decode_capacity_qualification_v2(document, *, expected_host_id, expected_owner_id,
                                     expected_policy_sha256, expected_binding,
                                     expected_source_graph_sha256, expected_report_sha256,
                                     expected_native_maximum_bytes):
    """Decode one per-VM ``capacity`` block, or return None for absent capacity.

    Existing outer negative-v1 metadata stays with its owning bundle decoder.
    This new block accepts only v2 and never upgrades legacy positive flags.
    Expected operands must come from the protected actual owner, not the job.
    """
    if document is None:
        return None
    root = _object(document, ("schema", "host_id", "owner_id", "policy_sha256", "binding",
                              "source_graph_sha256", "report_sha256", "measurement"), "capacity block")
    _require(root["schema"] == SCHEMA, "schema", "measured capacity v2 required")
    measured = _object(root["measurement"], ("state", "scope", "evidence_sha256", "mapping_evidence_sha256",
                        "observed_os_bytes", "safety_allowance_bytes", "os_reserve_bytes", "native_gap_bound_bytes",
                        "maximum_guest_total_bytes", "native_maximum_bytes"), "measurement")
    _require(measured["state"] == "measured", "capacity_unqualified", "actual measured capacity declaration required")
    qualification = GuestCapacityQualification(
        **{name: root[name] for name in ("host_id", "owner_id", "policy_sha256", "binding",
                                        "source_graph_sha256", "report_sha256")},
        measurement_scope=measured["scope"],
        **{name: measured[name] for name in ("evidence_sha256", "mapping_evidence_sha256", "observed_os_bytes",
          "safety_allowance_bytes", "os_reserve_bytes", "native_gap_bound_bytes", "maximum_guest_total_bytes",
          "native_maximum_bytes")},
    )
    _join(qualification, expected_host_id=expected_host_id, expected_owner_id=expected_owner_id,
          expected_policy_sha256=expected_policy_sha256, expected_binding=expected_binding,
          expected_source_graph_sha256=expected_source_graph_sha256, expected_report_sha256=expected_report_sha256,
          expected_native_maximum_bytes=expected_native_maximum_bytes)
    return qualification


def _demands(values):
    _require(type(values) in (tuple, list), "shape", "explicit complete demand sequence required")
    return tuple(_integer(value, "demand", positive=True) for value in values)


def _floor(reserve, demands):
    reserve = _integer(reserve, "reserve", positive=True)
    result = reserve + sum(_demands(demands))
    return _integer(result, "aggregate floor", positive=True)


def native_floor(minimum_bytes: int, demands: Sequence[int]) -> int:
    """Native M plus every authorized/live D; the empty set retains M."""
    return _floor(minimum_bytes, demands)


def physical_floor(os_reserve_bytes: int, demands: Sequence[int]) -> int:
    """Guest-physical R plus every authorized/live D, independently of native M."""
    return _floor(os_reserve_bytes, demands)


def rounded_native_floor(minimum_bytes: int, demands: Sequence[int], quantum_bytes: int) -> int:
    """Round the complete native floor up, rejecting overflow instead of wrapping."""
    quantum = _integer(quantum_bytes, "quantum_bytes", positive=True)
    floor = native_floor(minimum_bytes, demands)
    return _integer(((floor + quantum - 1) // quantum) * quantum,
                    "rounded native floor", positive=True)


def validate_guest_admission(*, qualification, native_minimum_bytes, paid_grant_bytes,
                             assigned_bytes, configured_bytes, total_bytes, available_bytes,
                             demands, task_limits, candidate_index, slurm_memory_bytes,
                             quantum_bytes, limits_enforced, expected_host_id, expected_owner_id,
                             expected_policy_sha256, expected_binding, expected_source_graph_sha256,
                             expected_report_sha256, expected_native_maximum_bytes):
    """Validate one candidate against every authorized/live commitment.

    ``demands`` and ``task_limits`` are complete matching sequences, including
    authorized but not-yet-started bodies, not only resident/touched pages.
    ``candidate_index`` identifies the new body whose available capacity must be
    checked. A root owner must authenticate completeness, actual cgroups and the
    expected context before calling this pure predicate. This function neither
    creates admission authority nor replaces the whole-host H/F/O guard.
    """
    _require(type(qualification) is GuestCapacityQualification, "capacity_unqualified",
             "measured v2 capacity profile required")
    _join(qualification, expected_host_id=expected_host_id, expected_owner_id=expected_owner_id,
          expected_policy_sha256=expected_policy_sha256, expected_binding=expected_binding,
          expected_source_graph_sha256=expected_source_graph_sha256, expected_report_sha256=expected_report_sha256,
          expected_native_maximum_bytes=expected_native_maximum_bytes)
    values = {
        "native_minimum_bytes": native_minimum_bytes, "paid_grant_bytes": paid_grant_bytes,
        "assigned_bytes": assigned_bytes, "configured_bytes": configured_bytes, "total_bytes": total_bytes,
        "slurm_memory_bytes": slurm_memory_bytes,
    }
    for name, value in values.items():
        _integer(value, name, positive=True)
    _integer(available_bytes, "available_bytes")
    amounts, limits = _demands(demands), _demands(task_limits)
    _require(len(amounts) == len(limits) and type(candidate_index) is int and
             0 <= candidate_index < len(amounts), "shape", "complete commitments/limits and exact candidate required")
    native = rounded_native_floor(native_minimum_bytes, amounts, quantum_bytes)
    physical = physical_floor(qualification.os_reserve_bytes, amounts)
    _require(native_minimum_bytes >= qualification.os_reserve_bytes + qualification.native_gap_bound_bytes,
             "capacity_profile", "native minimum does not cover measured OS reserve and native reserved gap")
    _require(assigned_bytes == configured_bytes, "readback", "configured and assigned allocation differ")
    _require(native <= assigned_bytes <= paid_grant_bytes <= qualification.native_maximum_bytes,
             "native_capacity", "all native commitments must fit actual allocation and paid maximum")
    _require(total_bytes <= qualification.maximum_guest_total_bytes and
             max(0, assigned_bytes - total_bytes) <= qualification.native_gap_bound_bytes,
             "capacity_profile", "current guest/native observation contradicts measured capacity profile")
    _require(limits_enforced is True and all(limit <= demand for limit, demand in zip(limits, amounts)) and
             physical <= total_bytes and amounts[candidate_index] <= available_bytes <= total_bytes and
             sum(amounts) <= slurm_memory_bytes <= qualification.maximum_guest_total_bytes - qualification.os_reserve_bytes,
             "guest_capacity", "actual guest capacity/availability/limits or scheduler commitments do not fit")
