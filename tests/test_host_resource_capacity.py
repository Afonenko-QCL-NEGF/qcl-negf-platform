"""Pure capacity arithmetic and profile predicates; no native/service operations."""
import importlib
import importlib.util
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ops"))


def api():
    assert importlib.util.find_spec("host_resource_capacity") is not None, (
        "missing pure native/physical capacity contract"
    )
    return importlib.import_module("host_resource_capacity")


@pytest.mark.parametrize("minimum,demands,native,physical", [
    (100, (), 100, 60),
    (100, (100,), 200, 160),
    (100, (100, 50), 250, 210),
])
def test_native_and_physical_floors_keep_distinct_reserves(minimum, demands, native, physical):
    # Replacing guest reserve R with native minimum M must break these literals.
    m = api()
    assert m.native_floor(minimum, demands) == native
    assert m.physical_floor(60, demands) == physical


@pytest.mark.parametrize("minimum,demands,quantum,want", [
    (100, (100,), 64, 256),
    (128, (128,), 64, 256),
    (100, (100, 50), 64, 256),
])
def test_native_floor_rounds_up_without_losing_any_concurrent_demand(minimum, demands, quantum, want):
    assert api().rounded_native_floor(minimum, demands, quantum) == want


@pytest.mark.parametrize("minimum,demands", [
    (True, (1,)), (0, (1,)), (-1, (1,)), (1.0, (1,)), ("1", (1,)),
    (1, (True,)), (1, (0,)), (1, (-1,)), (1, (None,)), (1, (1.0,)),
    (1, {"hidden": 100}), (1, iter([100])), (2**63 - 1, (1,)),
])
def test_floor_rejects_unknown_coerced_or_overflowing_values(minimum, demands):
    m = api()
    with pytest.raises(m.CapacityValidationError):
        m.native_floor(minimum, demands)
    with pytest.raises(m.CapacityValidationError):
        m.physical_floor(minimum, demands)


@pytest.mark.parametrize("quantum", [True, 0, -1, 1.5, None, 2**63])
def test_rounding_requires_explicit_positive_integer_quantum(quantum):
    m = api()
    with pytest.raises(m.CapacityValidationError):
        m.rounded_native_floor(100, (100,), quantum)


def test_rounding_overflow_does_not_wrap_or_return_an_unpaid_floor():
    m = api()
    with pytest.raises(m.CapacityValidationError):
        m.rounded_native_floor(2**63 - 1, (), 64)


def context():
    return dict(
        expected_host_id="synthetic-host", expected_owner_id="synthetic-owner",
        expected_policy_sha256="a" * 64,
        expected_binding={
            "vm_id": "vm", "native_id": "native", "process_id": "pid-birth",
            "guest_boot_id": "guest-boot", "image_id": "image", "guest_kernel_id": "guest-kernel",
            "host_kernel_id": "host-kernel", "qemu_version_id": "qemu", "backend_version_id": "backend",
            "readback_version": "readback", "config_fingerprint": "config",
        },
        expected_source_graph_sha256="b" * 64, expected_report_sha256="c" * 64,
        expected_native_maximum_bytes=1000,
    )


def profile():
    c = context()
    return dict(
        schema="qcl.host-resource-capacity-qualification.v2",
        host_id=c["expected_host_id"], owner_id=c["expected_owner_id"],
        policy_sha256=c["expected_policy_sha256"], binding=c["expected_binding"],
        source_graph_sha256=c["expected_source_graph_sha256"], report_sha256=c["expected_report_sha256"],
        measurement=dict(state="measured", scope="synthetic services and bounded workload profile",
                         evidence_sha256="d" * 64, mapping_evidence_sha256="e" * 64,
                         observed_os_bytes=40, safety_allowance_bytes=20, os_reserve_bytes=60,
                         native_gap_bound_bytes=20, maximum_guest_total_bytes=980,
                         native_maximum_bytes=1000),
    )


def decode(document):
    m = api()
    decoder = getattr(m, "decode_capacity_qualification_v2", None)
    assert callable(decoder), "missing strict measured capacity decoder"
    return decoder(document, **context())


def test_measured_profile_decodes_without_inventing_native_equal_guest_capacity():
    q = decode(profile())
    assert q.os_reserve_bytes == 60
    assert q.native_gap_bound_bytes == 20
    assert q.maximum_guest_total_bytes == 980
    assert q.native_maximum_bytes == 1000


def test_absent_capacity_is_readable_as_unqualified_and_never_filled():
    assert decode(None) is None


def test_decoded_profile_cannot_be_changed_through_input_binding_alias():
    document = profile()
    q = decode(document)
    document["binding"]["guest_boot_id"] = "new-boot"
    assert q.binding["guest_boot_id"] == "guest-boot"
    with pytest.raises(TypeError):
        q.binding["guest_boot_id"] = "new-boot"


@pytest.mark.parametrize("field", [
    "host_id", "owner_id", "policy_sha256", "source_graph_sha256", "report_sha256",
])
def test_profile_rejects_different_actual_owner_source_policy_or_report(field):
    document = profile()
    document[field] = "f" * 64 if field.endswith("sha256") else "other"
    with pytest.raises(api().CapacityValidationError, match="identity_mismatch"):
        decode(document)


@pytest.mark.parametrize("field", ["vm_id", "process_id", "guest_boot_id", "image_id", "config_fingerprint"])
def test_profile_rejects_changed_actual_runtime_binding(field):
    document = profile()
    document["binding"][field] = "different-generation"
    with pytest.raises(api().CapacityValidationError, match="identity_mismatch"):
        decode(document)


@pytest.mark.parametrize("mutation", [
    {"state": "not_measured"}, {"state": True}, {"evidence_sha256": None},
    {"mapping_evidence_sha256": ""}, {"scope": ""}, {"scope": "   "},
    {"observed_os_bytes": None}, {"observed_os_bytes": True}, {"safety_allowance_bytes": -1},
    {"os_reserve_bytes": 100}, {"native_gap_bound_bytes": 0},
    {"maximum_guest_total_bytes": 1001}, {"native_maximum_bytes": 980},
    {"maximum_guest_total_bytes": True}, {"native_gap_bound_bytes": 2**63},
])
def test_profile_refuses_unmeasured_missing_or_contradictory_capacity(mutation):
    document = profile()
    document["measurement"].update(mutation)
    with pytest.raises(api().CapacityValidationError):
        decode(document)


@pytest.mark.parametrize("location,field", [
    ("root", "measurement"), ("root", "report_sha256"),
    ("measurement", "safety_allowance_bytes"), ("measurement", "mapping_evidence_sha256"),
    ("binding", "process_id"),
])
def test_profile_requires_every_explicit_measurement_and_identity_field(location, field):
    document = profile()
    target = document if location == "root" else document[location]
    del target[field]
    with pytest.raises(api().CapacityValidationError, match="shape"):
        decode(document)


@pytest.mark.parametrize("location", ["root", "measurement", "binding"])
def test_profile_rejects_unknown_fields_instead_of_ignoring_new_meanings(location):
    document = profile()
    target = document if location == "root" else document[location]
    target["unknown_authority"] = True
    with pytest.raises(api().CapacityValidationError, match="shape"):
        decode(document)


@pytest.mark.parametrize("schema", [
    "qcl.host-resource-qualification.v1", "qcl.host-resource-capacity-qualification.v1", "unknown", None,
])
def test_capacity_decoder_never_upgrades_legacy_or_unknown_schema(schema):
    document = profile()
    document["schema"] = schema
    with pytest.raises(api().CapacityValidationError, match="schema"):
        decode(document)


def admission(**changes):
    values = dict(qualification=decode(profile()), native_minimum_bytes=100, paid_grant_bytes=1000,
                  assigned_bytes=200, configured_bytes=200, total_bytes=180, available_bytes=110,
                  demands=(100,), task_limits=(100,), candidate_index=0, slurm_memory_bytes=900,
                  quantum_bytes=1, limits_enforced=True, **context())
    values.update(changes)
    validator = getattr(api(), "validate_guest_admission", None)
    assert callable(validator), "missing native/physical admission predicates"
    return validator(**values)


def test_guest_below_native_floor_but_above_physical_floor_can_be_admitted():
    # G=N=200, T=180<N, P=R+D=160; all literal values are hand checked.
    assert admission() is None


def test_fixed_maximum_slurm_capacity_is_not_current_native_demand():
    # S=900 is valid against measured maximum 980-60, although G-R is only 140.
    assert admission(slurm_memory_bytes=920) is None


def test_balloon_mapping_may_keep_guest_memtotal_above_native_allocation():
    # The profile references accepted mapping evidence; actual A and native floor still constrain admission.
    assert admission(total_bytes=980, available_bytes=110) is None


def test_all_authorized_demands_fit_before_any_body_can_be_admitted():
    assert admission(assigned_bytes=250, configured_bytes=250, total_bytes=230,
                     demands=(100, 50), task_limits=(100, 50), candidate_index=1) is None


@pytest.mark.parametrize("changes,reason", [
    ({"total_bytes": 159}, "capacity_profile"),
    ({"available_bytes": 99}, "guest_capacity"),
    ({"total_bytes": 981}, "capacity_profile"),
    ({"available_bytes": 181}, "guest_capacity"),
    ({"task_limits": (101,)}, "guest_capacity"),
    ({"limits_enforced": False}, "guest_capacity"),
    ({"assigned_bytes": 199, "configured_bytes": 199}, "native_capacity"),
    ({"assigned_bytes": 201}, "readback"),
    ({"paid_grant_bytes": 199}, "native_capacity"),
    ({"paid_grant_bytes": 1001}, "native_capacity"),
    ({"native_minimum_bytes": 70}, "capacity_profile"),
    ({"slurm_memory_bytes": 921}, "guest_capacity"),
    ({"slurm_memory_bytes": 99}, "guest_capacity"),
    ({"demands": (100, 50), "task_limits": (100, 50)}, "native_capacity"),
    ({"demands": (100, 50), "task_limits": (100, 50),
      "assigned_bytes": 250, "configured_bytes": 250, "total_bytes": 205}, "capacity_profile"),
    ({"demands": (100, 50), "task_limits": (100,)}, "shape"),
    ({"candidate_index": 1}, "shape"),
    ({"qualification": None}, "capacity_unqualified"),
    ({"expected_report_sha256": "f" * 64}, "identity_mismatch"),
    ({"expected_native_maximum_bytes": 999}, "identity_mismatch"),
    ({"quantum_bytes": 64}, "native_capacity"),
])
def test_admission_refuses_capacity_or_identity_violation(changes, reason):
    with pytest.raises(api().CapacityValidationError, match=reason):
        admission(**changes)


def test_exact_rounded_native_floor_accepts_without_unrounded_underallocation():
    assert admission(assigned_bytes=256, configured_bytes=256, total_bytes=236, quantum_bytes=64) is None


@pytest.mark.parametrize("field", [
    "native_minimum_bytes", "paid_grant_bytes", "assigned_bytes", "configured_bytes", "total_bytes",
    "available_bytes", "candidate_index", "slurm_memory_bytes", "quantum_bytes",
])
def test_admission_rejects_boolean_numeric_values(field):
    with pytest.raises(api().CapacityValidationError):
        admission(**{field: True})


def test_real_limits_boolean_is_required_instead_of_truthy_string():
    with pytest.raises(api().CapacityValidationError, match="guest_capacity"):
        admission(limits_enforced="yes")


def test_profile_is_rejoined_to_actual_guest_generation_at_each_admission():
    changed = context()["expected_binding"]
    changed["guest_boot_id"] = "new-actual-boot"
    with pytest.raises(api().CapacityValidationError, match="identity_mismatch"):
        admission(expected_binding=changed)


def test_maximum_profile_does_not_infer_the_reported_guest_maximum_from_native_cap():
    document = profile()
    del document["measurement"]["maximum_guest_total_bytes"]
    with pytest.raises(api().CapacityValidationError, match="shape"):
        decode(document)


def test_administrative_reserve_equal_to_minimum_cannot_hide_positive_native_gap():
    document = profile()
    document["measurement"].update(observed_os_bytes=80, os_reserve_bytes=100)
    with pytest.raises(api().CapacityValidationError, match="capacity_profile"):
        admission(qualification=decode(document))
