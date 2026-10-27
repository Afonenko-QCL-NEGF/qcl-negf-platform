"""Synthetic safety contracts: no inventory, native calls or scientific work."""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import importlib.util
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


def policy_module():
    path = ROOT / "ops/host_resource_policy.py"
    assert path.is_file(), "P19 pure host policy implementation is missing"
    spec = importlib.util.spec_from_file_location("host_resource_policy", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def api():
    return policy_module()


@pytest.fixture
def document():
    # Deliberately small synthetic byte counts; all expected sums are hand-derived.
    return {
        "schema": "qcl.host-resource-policy.v1",
        "host_id": "synthetic-host",
        "owner_id": "synthetic-owner",
        "physical_ram_bytes": 1000,
        "capacity_evidence_ref": "synthetic-capacity",
        "reserves": {
            "host_services_bytes": 40,
            "control_plane_bytes": 20,
            "safety_bytes": 40,
            "foreign_max_bytes": 200,
            "evidence_ref": "synthetic-inclusive-foreign-bound",
        },
        "owned_pool": {
            "capacity_bytes": 700,
            "agreement_ref": "synthetic-admin-agreement",
            "enforceable": True,
            "foreign_growth_bounded": True,
            "active_grants_protected": True,
        },
        "active_grant": {
            "mechanism": "qualified_dynamic",
            "qualification_ref": "synthetic-qualification-only",
        },
        "timeouts": {"request_seconds": 10, "grow_seconds": 30,
                     "shrink_seconds": 30, "reconcile_seconds": 60},
        "vms": [
            {"vm_id": "synthetic-ci", "owner_id": "synthetic-owner", "resident": True,
             "minimum_bytes": 100, "startup_bytes": 150, "maximum_bytes": 400,
             "overhead_bytes": 20, "overhead_evidence_ref": "synthetic-ci-overhead",
             "cpu_weight": 100, "memory_weight": 100},
            {"vm_id": "synthetic-worker", "owner_id": "synthetic-owner", "resident": True,
             "minimum_bytes": 150, "startup_bytes": 200, "maximum_bytes": 500,
             "overhead_bytes": 30, "overhead_evidence_ref": "synthetic-worker-overhead",
             "cpu_weight": 200, "memory_weight": 300},
        ],
    }


def grants(api, *, worker_bytes=400, state="active", floor=350):
    return (
        api.ResidentGrant("synthetic-host", "synthetic-ci", "synthetic-owner", 150, 100, "idle"),
        api.ResidentGrant("synthetic-host", "synthetic-worker", "synthetic-owner",
                          worker_bytes, floor, state),
    )


def test_budget_charges_full_grants_overhead_and_all_reserves(document):
    api = policy_module()
    original = deepcopy(document)
    policy = api.validate_host_resource_policy(document)
    budget = api.validate_host_grants(policy, grants(api))
    assert (budget.host_reserve_bytes, budget.foreign_reserve_bytes) == (100, 200)
    assert (budget.guest_grant_bytes, budget.vm_overhead_bytes) == (550, 50)
    assert (budget.owned_charge_bytes, budget.total_charge_bytes) == (600, 900)
    assert (budget.pool_headroom_bytes, budget.physical_headroom_bytes) == (100, 100)
    assert document == original
    with pytest.raises(FrozenInstanceError):
        policy.physical_ram_bytes = 1


def test_budget_accepts_exact_physical_and_pool_boundary(api, document):
    budget = api.validate_host_grants(api.validate_host_resource_policy(document),
                                    grants(api, worker_bytes=500))
    assert budget.total_charge_bytes == 1000
    assert budget.physical_headroom_bytes == budget.pool_headroom_bytes == 0


def test_pool_cannot_claim_capacity_reserved_for_host_or_foreign(api, document):
    document["owned_pool"]["capacity_bytes"] = 701
    with pytest.raises(api.PolicyValidationError, match="pool_exceeds_physical"):
        api.validate_host_resource_policy(document)


def test_new_full_grant_is_charged_before_any_residency_readback(api, document):
    policy = api.validate_host_resource_policy(document)
    current = grants(api)
    # Only 100 bytes remain; raising CI by 101 must fail even before native grow.
    with pytest.raises(api.PolicyValidationError, match="pool_overcommit"):
        api.validate_resize(policy, current, "synthetic-ci", 251)


def test_smaller_owned_pool_is_enforced_independently_of_physical_ram(api, document):
    document["owned_pool"]["capacity_bytes"] = 599
    policy = api.validate_host_resource_policy(document)
    with pytest.raises(api.PolicyValidationError, match="pool_overcommit"):
        api.validate_host_grants(policy, grants(api))


@pytest.mark.parametrize("field", ["host_services_bytes", "control_plane_bytes", "safety_bytes",
                                 "foreign_max_bytes"])
@pytest.mark.parametrize("unknown", [None, "unknown"])
def test_unknown_reserves_are_never_zero(api, document, field, unknown):
    document["reserves"][field] = unknown
    with pytest.raises(api.PolicyValidationError):
        api.validate_host_resource_policy(document)


@pytest.mark.parametrize("field", ["overhead_bytes", "overhead_evidence_ref", "owner_id"])
def test_missing_vm_knowledge_is_not_defaulted(api, document, field):
    del document["vms"][0][field]
    with pytest.raises(api.PolicyValidationError):
        api.validate_host_resource_policy(document)


@pytest.mark.parametrize("field", ["physical_ram_bytes", "capacity_evidence_ref"])
def test_missing_physical_capacity_evidence_is_rejected(api, document, field):
    del document[field]
    with pytest.raises(api.PolicyValidationError):
        api.validate_host_resource_policy(document)


@pytest.mark.parametrize("field", ["enforceable", "foreign_growth_bounded", "active_grants_protected"])
def test_resource_pool_grouping_without_admin_guarantee_cannot_admit(api, document, field):
    document["owned_pool"][field] = False
    with pytest.raises(api.PolicyValidationError, match="capacity_agreement"):
        api.validate_host_resource_policy(document)


@pytest.mark.parametrize("mutation", ["foreign-owner", "duplicate", "nonresident", "floor-order",
                                    "startup-order", "cpu-weight", "memory-weight", "bool-bytes",
                                    "negative-overhead", "missing-overhead", "unknown-field"])
def test_invalid_resident_contracts_fail_closed(api, document, mutation):
    vm = document["vms"][0]
    if mutation == "foreign-owner":
        vm["owner_id"] = "foreign"
    elif mutation == "duplicate":
        document["vms"].append(deepcopy(vm))
    elif mutation == "nonresident":
        vm["resident"] = False
    elif mutation == "floor-order":
        vm["minimum_bytes"] = 151
    elif mutation == "startup-order":
        vm["startup_bytes"] = 401
    elif mutation == "cpu-weight":
        vm["cpu_weight"] = 0
    elif mutation == "memory-weight":
        vm["memory_weight"] = -1
    elif mutation == "bool-bytes":
        vm["overhead_bytes"] = False
    elif mutation == "negative-overhead":
        vm["overhead_bytes"] = -1
    elif mutation == "missing-overhead":
        vm["overhead_bytes"] = None
    else:
        vm["mem_available_bytes"] = 999
    with pytest.raises(api.PolicyValidationError):
        api.validate_host_resource_policy(document)


def test_startup_reservation_for_all_resident_vms_must_fit(api, document):
    document["owned_pool"]["capacity_bytes"] = 399
    with pytest.raises(api.PolicyValidationError, match="pool_overcommit"):
        api.validate_host_resource_policy(document)


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "unknown-vm", "foreign-owner",
                                    "wrong-host", "below-minimum", "above-maximum", "floor",
                                    "idle-floor", "unknown-state", "bool-bytes"])
def test_grant_snapshot_is_complete_owned_typed_and_bounded(api, document, mutation):
    policy = api.validate_host_resource_policy(document)
    snapshot = list(grants(api))
    if mutation == "missing":
        snapshot.pop()
    elif mutation == "duplicate":
        snapshot.append(snapshot[0])
    else:
        key, value = {
            "unknown-vm": ("vm_id", "foreign-vm"), "foreign-owner": ("owner_id", "foreign"),
            "wrong-host": ("host_id", "other-host"), "below-minimum": ("guest_bytes", 99),
            "above-maximum": ("guest_bytes", 401), "floor": ("active_floor_bytes", 151),
            "idle-floor": ("active_floor_bytes", 101), "unknown-state": ("state", "expired"),
            "bool-bytes": ("guest_bytes", True),
        }[mutation]
        # Dataclasses are values; validation occurs at the public safety boundary.
        snapshot[0] = replace(snapshot[0], **{key: value})
    with pytest.raises(api.PolicyValidationError):
        api.validate_host_grants(policy, snapshot)


@pytest.mark.parametrize("state", ["active", "ambiguous"])
@pytest.mark.parametrize("target", [149, 349, 350, 399])
def test_no_planned_shrink_during_active_or_ambiguous_work(api, document, state, target):
    policy = api.validate_host_resource_policy(document)
    with pytest.raises(api.PolicyValidationError, match="protected_grant"):
        api.validate_resize(policy, grants(api, state=state), "synthetic-worker", target)


def test_idle_resize_preserves_resident_floor_and_does_not_mutate_grants(api, document):
    policy = api.validate_host_resource_policy(document)
    snapshot = grants(api, state="idle", floor=150)
    budget = api.validate_resize(policy, snapshot, "synthetic-worker", 150)
    assert budget.total_charge_bytes == 650
    assert snapshot[1].guest_bytes == 400
    with pytest.raises(api.PolicyValidationError, match="resident_floor"):
        api.validate_resize(policy, snapshot, "synthetic-worker", 149)


def test_invalid_existing_snapshot_cannot_be_repaired_to_free_unknown_capacity(api, document):
    policy = api.validate_host_resource_policy(document)
    snapshot = grants(api)[:1]
    with pytest.raises(api.PolicyValidationError, match="incomplete_grants"):
        api.validate_resize(policy, snapshot, "synthetic-ci", 100)


def test_conservative_mode_charges_maximum_without_dynamic_qualification(api, document):
    document["active_grant"]["mechanism"] = "conservative_reservation"
    document["vms"][1]["maximum_bytes"] = 250
    policy = api.validate_host_resource_policy(document)
    snapshot = (
        api.ResidentGrant("synthetic-host", "synthetic-ci", "synthetic-owner", 400, 100, "idle"),
        api.ResidentGrant("synthetic-host", "synthetic-worker", "synthetic-owner", 250, 150, "idle"),
    )
    assert api.validate_host_grants(policy, snapshot).total_charge_bytes == 1000
    with pytest.raises(api.PolicyValidationError, match="conservative_reservation"):
        api.validate_resize(policy, snapshot, "synthetic-ci", 100)


def test_unqualified_fallback_cannot_overcommit_maximums(api, document):
    document["active_grant"]["mechanism"] = "conservative_reservation"
    with pytest.raises(api.PolicyValidationError, match="pool_overcommit"):
        api.validate_host_resource_policy(document)


def test_unsupported_mechanism_is_not_implicitly_dynamic(api, document):
    document["active_grant"]["mechanism"] = "pve-resource-pool"
    with pytest.raises(api.PolicyValidationError, match="grant_mechanism"):
        api.validate_host_resource_policy(document)


def test_public_example_passes_both_structural_schema_and_pure_safety_validation(api):
    import jsonschema

    schema = json.loads((ROOT / "schemas/host-resource-policy.schema.json").read_text())
    example = json.loads((ROOT / "examples/host-resource-policy.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(example, schema)
    policy = api.validate_host_resource_policy(example)
    assert policy.active_grant.mechanism == "conservative_reservation"


@pytest.mark.parametrize("field", ["overhead_bytes", "cpu_weight", "memory_weight", "minimum_bytes"])
def test_public_schema_rejects_missing_required_vm_fields(api, document, field):
    import jsonschema

    schema = json.loads((ROOT / "schemas/host-resource-policy.schema.json").read_text())
    del document["vms"][0][field]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(document, schema)
