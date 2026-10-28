"""Synthetic behavioural host grant tests. No native executable is invoked."""
from dataclasses import replace
import json
import os
from pathlib import Path
import stat
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ops"))


def api():
    import host_resource_operations as module
    return module


def setup(tmp_path, *, mechanism="qualified_dynamic", vm_ids=("vm-a", "vm-b")):
    m = api()
    document = {
        "schema": "qcl.host-resource-policy.v1", "host_id": "synthetic-host",
        "owner_id": "synthetic-owner", "physical_ram_bytes": 4096,
        "capacity_evidence_ref": "synthetic-capacity",
        "reserves": {"host_services_bytes": 128, "control_plane_bytes": 64,
                     "safety_bytes": 64, "foreign_max_bytes": 256,
                     "evidence_ref": "synthetic-reserves"},
        "owned_pool": {"capacity_bytes": 3584, "agreement_ref": "synthetic-agreement",
                       "enforceable": True, "foreign_growth_bounded": True,
                       "active_grants_protected": True},
        "active_grant": {"mechanism": mechanism, "qualification_ref": "synthetic-qualification"},
        "timeouts": {"request_seconds": 10, "grow_seconds": 30, "shrink_seconds": 30,
                     "reconcile_seconds": 60},
        "vms": [{"vm_id": name, "owner_id": "synthetic-owner", "resident": True,
                 "minimum_bytes": 128, "startup_bytes": 256, "maximum_bytes": 2048,
                 "overhead_bytes": 64, "overhead_evidence_ref": "synthetic-overhead",
                 "cpu_weight": 100, "memory_weight": 100} for name in vm_ids],
    }
    if mechanism == "conservative_reservation":
        for vm in document["vms"]:
            vm["maximum_bytes"] = 1536
    policy = m.validate_host_resource_policy(document)
    bindings = tuple(m.RuntimeBinding(vm, "native-" + vm, "process-" + vm, "guest-boot-1",
                                     "image-1", "guest-kernel-1", "host-kernel-1", "qemu-1",
                                     "backend-1", "readback-v1", "config-1")
                     for vm in vm_ids)
    qualifications = tuple(m.BackendQualification(policy.host_id, policy.owner_id, binding,
                          m.policy_digest(policy), "synthetic-qualification", True, True,
                          True, True) for binding in bindings)
    evidence = m.HostEvidence(policy.host_id, policy.owner_id, "host-boot-1", m.policy_digest(policy),
                             100, 4096, 256, "synthetic-capacity", "synthetic-agreement",
                             True, True, True, "synthetic-authenticated-probe", bindings,
                             qualifications, {vm: () for vm in vm_ids})

    class Backend:
        quantum_bytes = 64

        def __init__(self):
            size = 1536 if mechanism == "conservative_reservation" else 256
            self.rows = {vm: m.VMReadback(vm, "native-" + vm, "process-" + vm, "config-1",
                                       "revision-1", size, size, True)
                         for vm in vm_ids}
            self.calls = []
            self.fault = None

        def readback(self, vm_id):
            return self.rows[vm_id]

        def resize(self, vm_id, target_bytes, before, timeout_seconds):
            # The real durable store is inspected at the external mutation boundary.
            state = json.loads(store.state_path.read_text())
            row = next(g for g in state["grants"] if g["vm_id"] == vm_id)
            assert row["guest_bytes"] >= max(before.assigned_bytes, target_bytes)
            assert state["desired"][vm_id] == target_bytes
            intent = next(r for r in state["receipts"] if r["phase"] in m.UNKNOWN)
            assert intent["native_cleanup_confirmed"] is False and intent["mutation_id"]
            self.calls.append((vm_id, target_bytes))
            self.rows[vm_id] = replace(before, configured_bytes=target_bytes,
                                      assigned_bytes=target_bytes, revision="revision-2")
            if self.fault == "timeout-after-change":
                error = TimeoutError("synthetic lost response after confirmed owned cleanup")
                error.native_record = {"failure": "timeout", "cleanup_confirmed": True,
                    "stdout": "synthetic response lost\n", "stderr": "", "child_started": True,
                    "returncode": -9, "elapsed_seconds": 1, "output_truncated": False,
                    "output_bytes": 24}
                error.native_output = error.native_record["stdout"]
                error.native_argv = ("synthetic-native-tool", "grow", vm_id)
                raise error
            if self.fault == "process-crash":
                raise SystemExit(77)
            if self.fault == "native-failure":
                error = m.ResourceError("native_command", "synthetic API response lost")
                error.native_argv = ("synthetic-native-tool", "grow", vm_id)
                error.native_output = "synthetic original failed output\n"
                raise error
            if self.fault == "native-cleanup-unconfirmed":
                error = m.ResourceError("native_cleanup_unconfirmed", "synthetic live descendant")
                error.native_argv = ("synthetic-native-tool", "grow", vm_id)
                error.native_output = "original stdout\noriginal stderr\n"
                error.native_record = {"failure": "cleanup_unconfirmed", "returncode": 0,
                    "elapsed_seconds": 1, "stdout": "original stdout\n",
                    "stderr": "original stderr\n", "output_truncated": False,
                    "cleanup_confirmed": False, "child_started": True, "output_bytes": 32}
                raise error
            if self.fault == "readback-old":
                self.rows[vm_id] = before
            return self.rows[vm_id]

    store = m.FileReceiptStore(tmp_path / "host-state", owner_uid=os.getuid())
    backend = Backend()
    controller = m.HostResourceController(policy, store, backend, clock=lambda: 100)
    size = 1536 if mechanism == "conservative_reservation" else 256
    grants = tuple(m.ResidentGrant(policy.host_id, vm, policy.owner_id, size, 128, "idle")
                   for vm in vm_ids)
    controller.bootstrap(grants, evidence)
    return m, controller, backend, store, evidence


def request(m, request_id="request-1", workload="work-1", amount=321, vm="vm-a"):
    return m.ResourceRequest(request_id, "synthetic-host", vm, "synthetic-owner", amount, workload)


def guest(m, workload="work-1", live=(), *, total=512, available=400):
    return m.GuestEvidence("vm-a", "guest-boot-1", workload, 100, total, available,
                           128, 321, 384, True, tuple(live))


def completion(m, workload="work-1", live=(), *, available=400):
    return m.CompletionEvidence("vm-a", "guest-boot-1", workload, 100, 0, True, True,
                                512, available, tuple(live))


def native_cleanup(m, store, evidence, request_id="request-1"):
    """Synthetic trusted admin probe; never derived from the memory readback."""
    state = json.loads(store.state_path.read_text())
    row = next(r for r in state["receipts"] if r["request"]["request_id"] == request_id)
    binding = next(b for b in evidence.bindings if b.vm_id == row["request"]["vm_id"])
    return m.NativeCleanupEvidence(request_id, row["mutation_id"], evidence.host_id,
        evidence.owner_id, evidence.host_boot_id, evidence.policy_sha256, binding,
        100, True, "synthetic-authenticated-admin-mutator-absence")


def running(m, controller, evidence, *, req=None, live=()):
    req = req or request(m)
    controller.request(req, evidence)
    controller.grow(req.request_id, evidence)
    g = guest(m, req.workload_id, live, total=1024, available=900)
    g = replace(g, task_limit_bytes=req.workload_bytes, slurm_memory_bytes=896)
    # Slurm cannot advertise more than the full grant less OS reserve.
    grant = next(g for g in controller.snapshot() if g.vm_id == req.vm_id)
    g = replace(g, slurm_memory_bytes=grant.guest_bytes - 128,
                vm_id=req.vm_id,
                total_bytes=grant.guest_bytes, available_bytes=grant.guest_bytes - 128)
    result = controller.admit(req.request_id, g, evidence)
    evidence.live_workloads[req.vm_id] = (*live, req.workload_id)
    return result


def finish(controller, request_id, done, evidence):
    # Synthetic authenticated guest probe, supplied independently of controller state.
    evidence.live_workloads[done.vm_id] = done.live_workload_ids
    return controller.finish(request_id, done, evidence)


def test_request_rounds_full_charge_before_grow_and_guest_check(tmp_path):
    m, c, b, store, e = setup(tmp_path)
    receipt = c.request(request(m), e)
    assert receipt.phase == "HOST_GRANT"
    # minimum 128 + workload 321 = 449; quantum 64 rounds to 512.
    assert (receipt.target_bytes, c.snapshot()[0].guest_bytes) == (512, 512)
    assert json.loads(store.state_path.read_text())["desired"]["vm-a"] == 512
    assert b.calls == []
    assert c.grow(receipt.request_id, e).phase == "GUEST_ADMIT"
    with pytest.raises(m.ResourceError, match="guest_capacity"):
        c.admit(receipt.request_id, guest(m, available=1), e)
    assert c.admit(receipt.request_id, guest(m), e).phase == "RUN"


def test_timeout_after_grow_retains_charge_and_reconciles_without_repeat(tmp_path):
    m, c, b, store, e = setup(tmp_path)
    c.request(request(m), e)
    b.fault = "timeout-after-change"
    assert c.grow("request-1", e).phase == "GROW_UNKNOWN"
    assert (c.snapshot()[0].guest_bytes, c.snapshot()[0].state) == (512, "ambiguous")
    restored = m.HostResourceController(c.policy, store, b, clock=lambda: 100)
    assert restored.reconcile("request-1", e).phase == "GUEST_ADMIT"
    assert b.calls == [("vm-a", 512)]
    assert restored.snapshot()[0].guest_bytes == 512


def test_process_crash_after_native_growth_has_a_durable_unknown_receipt(tmp_path):
    m, c, b, store, e = setup(tmp_path)
    c.request(request(m), e)
    b.fault = "process-crash"
    with pytest.raises(SystemExit):
        c.grow("request-1", e)
    state = json.loads(store.state_path.read_text())
    assert state["receipts"][0]["phase"] == "GROW_UNKNOWN"
    assert state["grants"][0]["guest_bytes"] == 512
    assert state["receipts"][0]["native_cleanup_confirmed"] is False
    restored = m.HostResourceController(c.policy, store, b, clock=lambda: 100)
    with pytest.raises(m.ResourceError, match="reconciliation_required"):
        restored.reconcile("request-1", e)
    assert restored.reconcile("request-1", e,
                              cleanup_evidence=native_cleanup(m, store, e)).phase == "GUEST_ADMIT"
    assert b.calls == [("vm-a", 512)]


def test_native_failure_preserves_original_bounded_private_output_and_unknown_charge(tmp_path):
    m, c, b, store, e = setup(tmp_path)
    c.request(request(m), e)
    b.fault = "native-failure"
    assert c.grow("request-1", e).phase == "GROW_UNKNOWN"
    records = list(store.directory.glob("failure-*.json"))
    assert len(records) == 1
    record = json.loads(records[0].read_text())
    assert record["output"] == "synthetic original failed output\n"
    assert record["request_id"] == "request-1"
    assert record["argv"] == ["synthetic-native-tool", "grow", "vm-a"]
    assert records[0].stat().st_mode & 0o777 == 0o600
    assert c.snapshot()[0].guest_bytes == 512


def test_native_cleanup_unknown_cannot_reconcile_from_matching_allocation_alone(tmp_path):
    m, c, b, store, e = setup(tmp_path)
    c.request(request(m), e)
    b.fault = "native-cleanup-unconfirmed"
    result = c.grow("request-1", e)
    assert (result.phase, result.failure) == ("GROW_UNKNOWN", "native_cleanup_unconfirmed")
    assert b.rows["vm-a"].assigned_bytes == 512  # CLI/actual target alone is insufficient.
    restored = m.HostResourceController(c.policy, store, b, clock=lambda: 100)
    with pytest.raises(m.ResourceError, match="reconciliation_required"):
        restored.reconcile("request-1", e)
    with pytest.raises(m.ResourceError, match="reconciliation_required"):
        restored.request(request(m, "request-2", "work-2", vm="vm-b"), e)
    assert [g.state for g in restored.snapshot()] == ["ambiguous", "idle"]
    assert restored.snapshot()[0].guest_bytes == 512
    record = json.loads(next(store.directory.glob("failure-*.json")).read_text())
    assert record["command_record"]["cleanup_confirmed"] is False
    assert record["command_record"]["stdout"] == "original stdout\n"
    assert record["command_record"]["stderr"] == "original stderr\n"
    assert b.calls == [("vm-a", 512)]


def test_native_cleanup_block_is_durable_and_original_failure_survives_log_io_error(tmp_path, monkeypatch):
    m, c, b, store, e = setup(tmp_path)
    c.request(request(m), e)
    b.fault = "native-cleanup-unconfirmed"

    def unavailable(*args):
        raise OSError("synthetic evidence storage unavailable")

    monkeypatch.setattr(store, "save_failure", unavailable)
    with pytest.raises(m.ResourceError, match="native_cleanup_unconfirmed") as observed:
        c.grow("request-1", e)
    assert observed.value.native_record["stdout"] == "original stdout\n"
    assert observed.value.native_record["cleanup_confirmed"] is False
    assert observed.value.native_log_error == "OSError"
    restored = m.HostResourceController(c.policy, store, b, clock=lambda: 100)
    with pytest.raises(m.ResourceError, match="reconciliation_required"):
        restored.reconcile("request-1", e)
    state = json.loads(store.state_path.read_text())
    assert state["receipts"][0]["failure"] == "native_cleanup_unconfirmed"
    assert restored.snapshot()[0].guest_bytes == 512


@pytest.mark.parametrize("failed_save", ["blocked", "all-post-native"])
def test_cleanup_barrier_survives_native_error_then_journal_io_failure(tmp_path, monkeypatch, failed_save):
    m, c, b, store, e = setup(tmp_path)
    c.request(request(m), e)
    b.fault = "native-cleanup-unconfirmed"
    original = store.save

    def failed(state):
        if (failed_save == "blocked" and state["blocked"] is not None) or (
                failed_save == "all-post-native" and b.calls):
            raise OSError("synthetic post-native persistence failure")
        return original(state)

    with monkeypatch.context() as patch:
        patch.setattr(store, "save", failed)
        with pytest.raises(m.ResourceError, match="native_cleanup_unconfirmed") as caught:
            c.grow("request-1", e)
    assert caught.value.native_journal_error == "OSError"
    assert caught.value.native_record["cleanup_confirmed"] is False
    assert caught.value.native_record["stdout"] == "original stdout\n"
    state = json.loads(store.state_path.read_text())
    assert state["receipts"][0]["native_cleanup_confirmed"] is False
    assert state["receipts"][0]["mutation_id"]
    restored = m.HostResourceController(c.policy, store, b, clock=lambda: 100)
    with pytest.raises(m.ResourceError, match="reconciliation_required"):
        restored.reconcile("request-1", e)
    with pytest.raises(m.ResourceError):
        restored.admit("request-1", guest(m), e)
    proof = native_cleanup(m, store, e)
    assert restored.reconcile("request-1", e, cleanup_evidence=proof).phase == "GUEST_ADMIT"
    assert restored.admit("request-1", guest(m), e).phase == "RUN"
    assert b.calls == [("vm-a", 512)]


def test_pre_native_cleanup_barrier_must_be_durable_before_actual_resize(tmp_path, monkeypatch):
    m, c, b, store, e = setup(tmp_path)
    c.request(request(m), e)
    save = store.save

    def fail_intent(state):
        if state["receipts"][0]["phase"] == "GROW_UNKNOWN":
            raise OSError("synthetic intent persistence failure")
        return save(state)

    monkeypatch.setattr(store, "save", fail_intent)
    with pytest.raises(OSError, match="intent persistence"):
        c.grow("request-1", e)
    assert b.calls == []
    assert json.loads(store.state_path.read_text())["receipts"][0]["phase"] == "HOST_GRANT"


@pytest.mark.parametrize("field,value", [
    ("request_id", "different-request"), ("mutation_id", "old-mutation"),
    ("host_id", "different-host"), ("owner_id", "different-owner"),
    ("host_boot_id", "old-boot"), ("policy_sha256", "old-policy"),
    ("observed_at", 89), ("observed_at", 99),
    ("native_mutators_absent", False), ("evidence_ref", "")])
def test_unknown_cleanup_requires_fresh_exact_administrative_proof(tmp_path, field, value):
    m, c, b, store, e = setup(tmp_path)
    c.request(request(m), e)
    b.fault = "native-cleanup-unconfirmed"
    c.grow("request-1", e)
    proof = replace(native_cleanup(m, store, e), **{field: value})
    with pytest.raises(m.ResourceError):
        c.reconcile("request-1", e, cleanup_evidence=proof)
    assert json.loads(store.state_path.read_text())["receipts"][0]["native_cleanup_confirmed"] is False
    assert c.snapshot()[0].guest_bytes == 512


def test_cleanup_proof_binding_and_old_grow_proof_cannot_clear_new_shrink_intent(tmp_path):
    m, c, b, store, e = setup(tmp_path)
    c.request(request(m), e)
    b.fault = "native-cleanup-unconfirmed"
    c.grow("request-1", e)
    grow_proof = native_cleanup(m, store, e)
    with pytest.raises(m.ResourceError, match="cleanup_evidence"):
        c.reconcile("request-1", e, cleanup_evidence=replace(grow_proof,
            binding=replace(grow_proof.binding, process_id="different-process")))
    c.reconcile("request-1", e, cleanup_evidence=grow_proof)
    c.admit("request-1", guest(m), e)
    e.live_workloads["vm-a"] = ("work-1",)
    finish(c, "request-1", completion(m), e)
    assert c.shrink("request-1", e).phase == "SHRINK_UNKNOWN"
    shrink_proof = native_cleanup(m, store, e)
    assert shrink_proof.mutation_id != grow_proof.mutation_id
    with pytest.raises(m.ResourceError, match="cleanup_evidence"):
        c.reconcile("request-1", e, cleanup_evidence=grow_proof)
    assert c.snapshot()[0].guest_bytes == 512
    assert c.reconcile("request-1", e, replace(completion(m), total_bytes=128, available_bytes=128),
        cleanup_evidence=shrink_proof).phase == "RELEASE"
    assert c.snapshot()[0].guest_bytes == 128
    assert b.calls == [("vm-a", 512), ("vm-a", 128)]


def test_no_resize_unknown_metadata_crash_does_not_require_native_cleanup_proof(tmp_path, monkeypatch):
    m, c, b, store, e = setup(tmp_path)
    req = request(m, amount=64)  # resident128 +64 fits current256, no resize.
    c.request(req, e)
    original, calls = store.save, []

    def fail_result(state):
        calls.append(state["receipts"][0]["phase"])
        if state["receipts"][0]["phase"] == "GUEST_ADMIT":
            raise OSError("synthetic metadata result crash")
        return original(state)

    with monkeypatch.context() as patch:
        patch.setattr(store, "save", fail_result)
        with pytest.raises(OSError, match="metadata result"):
            c.grow(req.request_id, e)
    row = json.loads(store.state_path.read_text())["receipts"][0]
    assert row["phase"] == "GROW_UNKNOWN" and row["native_cleanup_confirmed"] is True
    assert row["mutation_id"] is None and b.calls == []
    restored = m.HostResourceController(c.policy, store, b, clock=lambda: 100)
    assert restored.reconcile(req.request_id, e).phase == "GUEST_ADMIT"


def test_confirmed_cleanup_timeout_with_failed_result_save_requires_admin_proof_after_reload(tmp_path, monkeypatch):
    m, c, b, store, e = setup(tmp_path)
    c.request(request(m), e)
    b.fault = "timeout-after-change"
    original = store.save

    def unavailable_after_native(state):
        if b.calls:
            raise OSError("synthetic lost durable confirmation")
        return original(state)

    with monkeypatch.context() as patch:
        patch.setattr(store, "save", unavailable_after_native)
        with pytest.raises(TimeoutError) as caught:
            c.grow("request-1", e)
    assert caught.value.native_record["cleanup_confirmed"] is True
    assert caught.value.native_journal_error == "OSError"
    restored = m.HostResourceController(c.policy, store, b, clock=lambda: 100)
    with pytest.raises(m.ResourceError, match="reconciliation_required"):
        restored.reconcile("request-1", e)
    assert restored.reconcile("request-1", e,
        cleanup_evidence=native_cleanup(m, store, e)).phase == "GUEST_ADMIT"
    assert b.calls == [("vm-a", 512)]


def test_native_error_preserved_when_both_journal_and_failure_log_writes_fail(tmp_path, monkeypatch):
    m, c, b, store, e = setup(tmp_path)
    c.request(request(m), e)
    b.fault = "native-cleanup-unconfirmed"
    original = store.save

    def unavailable_after_native(state):
        if b.calls:
            raise OSError("synthetic journal unavailable")
        return original(state)

    def unavailable_log(*args):
        raise PermissionError("synthetic failure evidence unavailable")

    monkeypatch.setattr(store, "save", unavailable_after_native)
    monkeypatch.setattr(store, "save_failure", unavailable_log)
    with pytest.raises(m.ResourceError, match="native_cleanup_unconfirmed") as caught:
        c.grow("request-1", e)
    assert caught.value.native_journal_error == "OSError"
    assert caught.value.native_log_error == "PermissionError"
    assert str(caught.value.native_journal_exception) == "synthetic journal unavailable"
    assert str(caught.value.native_log_exception) == "synthetic failure evidence unavailable"
    assert caught.value.native_record["stdout"] == "original stdout\n"
    assert caught.value.native_record["cleanup_confirmed"] is False
    restored = m.HostResourceController(c.policy, store, b, clock=lambda: 100)
    with pytest.raises(m.ResourceError, match="reconciliation_required"):
        restored.reconcile("request-1", e)


def test_successful_actual_resize_then_result_save_crash_retains_pre_native_barrier(tmp_path, monkeypatch):
    m, c, b, store, e = setup(tmp_path)
    c.request(request(m), e)
    original = store.save

    def fail_result(state):
        if b.calls:
            raise OSError("synthetic successful resize result crash")
        return original(state)

    with monkeypatch.context() as patch:
        patch.setattr(store, "save", fail_result)
        with pytest.raises(OSError, match="result crash"):
            c.grow("request-1", e)
    restored = m.HostResourceController(c.policy, store, b, clock=lambda: 100)
    with pytest.raises(m.ResourceError, match="reconciliation_required"):
        restored.reconcile("request-1", e)
    assert restored.reconcile("request-1", e,
        cleanup_evidence=native_cleanup(m, store, e)).phase == "GUEST_ADMIT"
    assert b.calls == [("vm-a", 512)]


@pytest.mark.parametrize("failed_proof_save", [False, True])
def test_cleanup_proof_does_not_substitute_allocation_readback_or_bypass_its_own_save(
        tmp_path, monkeypatch, failed_proof_save):
    m, c, b, store, e = setup(tmp_path)
    c.request(request(m), e)
    b.fault = "native-cleanup-unconfirmed"
    c.grow("request-1", e)
    proof = native_cleanup(m, store, e)
    b.rows["vm-a"] = replace(b.rows["vm-a"], assigned_bytes=256, configured_bytes=256)
    with monkeypatch.context() as patch:
        if failed_proof_save:
            patch.setattr(store, "save", lambda state: (_ for _ in ()).throw(
                OSError("synthetic proof commit crash")))
            with pytest.raises(OSError, match="proof commit"):
                c.reconcile("request-1", e, cleanup_evidence=proof)
        else:
            assert c.reconcile("request-1", e, cleanup_evidence=proof).phase == "GROW_UNKNOWN"
    restored = m.HostResourceController(c.policy, store, b, clock=lambda: 100)
    assert restored.snapshot()[0].guest_bytes == 512
    if failed_proof_save:
        with pytest.raises(m.ResourceError, match="reconciliation_required"):
            restored.reconcile("request-1", e)
        assert restored.reconcile("request-1", e, cleanup_evidence=proof).phase == "GROW_UNKNOWN"
    b.rows["vm-a"] = replace(b.rows["vm-a"], assigned_bytes=512, configured_bytes=512)
    assert restored.reconcile("request-1", e).phase == "GUEST_ADMIT"
    assert b.calls == [("vm-a", 512)]  # no native replay by cleanup/reconcile


def test_unpublished_v1_state_and_completed_archive_are_rejected_without_reset(tmp_path):
    m, c, b, store, e = setup(tmp_path)
    state = json.loads(store.state_path.read_text())
    state["schema"] = "qcl.host-resource-state.v1"
    store.save(state)
    with pytest.raises(m.ResourceError, match="state"):
        c.snapshot()
    assert json.loads(store.state_path.read_text())["schema"].endswith(".v1")
    state["schema"] = m.STATE_SCHEMA
    store.save(state)
    running(m, c, e)
    finish(c, "request-1", completion(m), e)
    c.shrink("request-1", e)
    c.reconcile("request-1", e, replace(completion(m), total_bytes=128, available_bytes=128))
    archive = next(store.completed_directory.glob("*.json"))
    document = json.loads(archive.read_text())
    document["schema"] = "qcl.host-resource-completed.v1"
    archive.write_text(json.dumps(document))
    with pytest.raises(m.ResourceError, match="state"):
        c.request(request(m), e)


def test_administrative_cleanup_proof_cannot_clear_runtime_identity_block(tmp_path):
    m, c, b, store, e = setup(tmp_path)
    c.request(request(m), e)
    b.fault = "native-cleanup-unconfirmed"
    c.grow("request-1", e)
    proof = native_cleanup(m, store, e)
    changed_binding = replace(e.bindings[0], image_id="changed-image")
    changed = replace(e, bindings=(changed_binding, e.bindings[1]), qualifications=(
        replace(e.qualifications[0], binding=changed_binding), e.qualifications[1]))
    with pytest.raises(m.ResourceError, match="identity_mismatch"):
        c.reconcile("request-1", changed, cleanup_evidence=proof)
    with pytest.raises(m.ResourceError, match="reconciliation_required"):
        c.reconcile("request-1", e, cleanup_evidence=proof)
    assert c.snapshot()[0].guest_bytes == 512


def test_cleanup_recovery_preserves_other_deferred_grants_and_metadata_slot_progression(tmp_path):
    m, c, b, store, e = setup(tmp_path, vm_ids=("vm-a", "vm-b", "vm-c"))
    running(m, c, e)
    running(m, c, e, req=request(m, "request-c", "work-c", vm="vm-c"))
    c.request(request(m, "request-b", "work-b", vm="vm-b"), e)
    finish(c, "request-1", completion(m), e)
    done_c = replace(completion(m, "work-c"), vm_id="vm-c")
    finish(c, "request-c", done_c, e)
    b.fault = "native-cleanup-unconfirmed"
    c.grow("request-b", e)
    proof = native_cleanup(m, store, e, "request-b")
    c.reconcile("request-b", e, cleanup_evidence=proof)
    guest_b = replace(guest(m, "work-b"), vm_id="vm-b")
    assert c.admit("request-b", guest_b, e).phase == "RUN"
    e.live_workloads["vm-b"] = ("work-b",)
    assert c.reconcile("request-1", e).phase == "SHRINK_READY"
    assert c.reconcile("request-c", e).phase == "SHRINK_DEFERRED"
    assert [g.guest_bytes for g in c.snapshot()] == [512, 512, 512]
    b.fault = None
    c.shrink("request-1", e)
    c.reconcile("request-1", e, replace(completion(m), total_bytes=128, available_bytes=128))
    assert c.reconcile("request-c", e).phase == "SHRINK_READY"
    c.shrink("request-c", e)
    c.reconcile("request-c", e, replace(done_c, total_bytes=128, available_bytes=128))
    assert [g.guest_bytes for g in c.snapshot()] == [128, 512, 128]
    assert c.snapshot()[1].state == "active"


def test_duplicate_request_is_idempotent_but_payload_and_workload_reuse_fail(tmp_path):
    m, c, b, _, e = setup(tmp_path)
    first = c.request(request(m), e)
    assert c.request(request(m), e) == first
    with pytest.raises(m.ResourceError, match="request_conflict"):
        c.request(request(m, amount=322), e)
    running(m, c, e)
    with pytest.raises(m.ResourceError, match="workload_conflict"):
        c.request(request(m, request_id="request-2"), e)
    assert len(b.calls) == 1


def test_multiple_workloads_aggregate_floor_and_finish_cannot_shrink_other_work(tmp_path):
    m, c, b, _, e = setup(tmp_path)
    running(m, c, e)
    second = request(m, "request-2", "work-2", 200)
    r = c.request(second, e)
    # 128 + 321 + 200 = 649 -> 704, not max(449, 328).
    assert r.target_bytes == c.snapshot()[0].guest_bytes == 704
    c.grow("request-2", e)
    with pytest.raises(m.ResourceError, match="incomplete_workloads"):
        c.admit("request-2", replace(guest(m, "work-2"), task_limit_bytes=200,
                                    slurm_memory_bytes=576), e)
    c.admit("request-2", replace(guest(m, "work-2", ("work-1",), total=704),
                                task_limit_bytes=200, slurm_memory_bytes=576), e)
    e.live_workloads["vm-a"] = ("work-1", "work-2")
    with pytest.raises(m.ResourceError, match="incomplete_workloads"):
        finish(c, "request-1", completion(m), e)
    assert finish(c, "request-1", completion(m, live=("work-2",)), e).phase == "RELEASE"
    assert (c.snapshot()[0].guest_bytes, c.snapshot()[0].state) == (704, "active")
    with pytest.raises(m.ResourceError, match="phase"):
        c.shrink("request-1", e)
    assert b.calls == [("vm-a", 512), ("vm-a", 704)]
    assert finish(c, "request-2", completion(m, "work-2"), e).phase == "SHRINK_READY"
    assert c.shrink("request-2", e).phase == "SHRINK_UNKNOWN"
    assert c.snapshot()[0].guest_bytes == 704  # guest readback still needed
    assert c.reconcile("request-2", e, replace(completion(m, "work-2"), total_bytes=128,
                                               available_bytes=128)).phase == "RELEASE"
    assert (c.snapshot()[0].guest_bytes, c.snapshot()[0].state) == (128, "idle")


def test_failed_shrink_readback_keeps_larger_charge_and_blocks_new_mutation(tmp_path):
    m, c, b, _, e = setup(tmp_path)
    running(m, c, e)
    finish(c, "request-1", completion(m), e)
    b.fault = "readback-old"
    assert c.shrink("request-1", e).phase == "SHRINK_UNKNOWN"
    assert c.snapshot()[0].guest_bytes == 512
    assert c.reconcile("request-1", e, completion(m)).phase == "SHRINK_UNKNOWN"
    with pytest.raises(m.ResourceError, match="host_busy"):
        c.request(request(m, "request-2", "work-2", vm="vm-b"), e)


def test_confirmed_host_shrink_without_fresh_guest_readback_never_releases(tmp_path):
    m, c, _, _, e = setup(tmp_path)
    running(m, c, e)
    finish(c, "request-1", completion(m), e)
    c.shrink("request-1", e)
    assert c.reconcile("request-1", e).phase == "SHRINK_UNKNOWN"
    with pytest.raises(m.ResourceError, match="guest_readback"):
        c.reconcile("request-1", e, completion(m))
    assert c.snapshot()[0].guest_bytes == 512


@pytest.mark.parametrize("field,value", [("host_boot_id", "host-boot-2"),
                                         ("policy_sha256", "wrong-policy")])
def test_reboot_or_policy_change_never_releases_unknown_charge(tmp_path, field, value):
    m, c, _, _, e = setup(tmp_path)
    running(m, c, e)
    with pytest.raises(m.ResourceError, match="identity_mismatch"):
        finish(c, "request-1", completion(m), replace(e, **{field: value}))
    assert (c.snapshot()[0].guest_bytes, c.snapshot()[0].state) == (512, "ambiguous")
    with pytest.raises(m.ResourceError, match="reconciliation_required"):
        c.request(request(m, "request-2", "work-2"), e)


@pytest.mark.parametrize("field,value", [("process_id", "process-2"),
                                         ("config_fingerprint", "foreign-config")])
def test_native_identity_or_config_drift_fails_closed(tmp_path, field, value):
    m, c, b, _, e = setup(tmp_path)
    c.request(request(m), e)
    b.rows["vm-a"] = replace(b.rows["vm-a"], **{field: value})
    with pytest.raises(m.ResourceError, match="identity_mismatch"):
        c.grow("request-1", e)
    assert c.snapshot()[0].state == "ambiguous"
    assert b.calls == []


@pytest.mark.parametrize("field,value", [("foreign_max_bytes", 257), ("pressure_ok", False),
    ("foreign_growth_bounded", False), ("active_grants_protected", False),
    ("physical_ram_bytes", 4000), ("owner_id", "foreign-owner"), ("observed_at", 70)])
def test_unsafe_foreign_capacity_ownership_or_stale_probe_refuses(tmp_path, field, value):
    m, c, b, _, e = setup(tmp_path)
    with pytest.raises(m.ResourceError):
        c.request(request(m), replace(e, **{field: value}))
    assert b.calls == []


@pytest.mark.parametrize("field", ["guest_kernel_id", "host_kernel_id", "qemu_version_id",
                                  "backend_version_id", "image_id", "readback_version"])
def test_actual_runtime_change_invalidates_exact_qualification(tmp_path, field):
    m, c, b, _, e = setup(tmp_path)
    binding = replace(e.bindings[0], **{field: "new-version"})
    with pytest.raises(m.ResourceError, match="qualification"):
        c.request(request(m), replace(e, bindings=(binding, e.bindings[1])))
    assert b.calls == []


def test_conservative_mode_charges_maximum_and_never_uses_balloon_for_release(tmp_path):
    m, c, b, _, e = setup(tmp_path, mechanism="conservative_reservation")
    assert c.request(request(m), e).target_bytes == 1536
    c.grow("request-1", e)
    c.admit("request-1", replace(guest(m), total_bytes=1536), e)
    e.live_workloads["vm-a"] = ("work-1",)
    finish(c, "request-1", completion(m), e)
    c.shrink("request-1", e)
    c.reconcile("request-1", e, replace(completion(m), total_bytes=1536))
    assert c.snapshot()[0].guest_bytes == 1536
    assert b.calls == []


def test_no_ttl_can_shrink_or_release_run_and_host_lock_has_single_owner(tmp_path):
    m, c, _, store, e = setup(tmp_path)
    running(m, c, e)
    c.clock = lambda: 100000
    with pytest.raises(m.ResourceError):
        c.shrink("request-1", e)
    assert c.snapshot()[0].guest_bytes == 512
    with store.locked():
        with pytest.raises(m.ResourceError, match="host_locked"):
            c.request(request(m, "request-2", "work-2"), e)


def test_pool_capacity_failure_happens_before_backend_and_charge_is_unchanged(tmp_path):
    m, c, b, _, e = setup(tmp_path)
    running(m, c, e, req=request(m, amount=1800))
    with pytest.raises(m.PolicyValidationError, match="pool_overcommit"):
        c.request(request(m, "request-2", "work-2", 1800, vm="vm-b"), e)
    assert len(b.calls) == 1
    assert c.snapshot()[1].guest_bytes == 256


def test_persisted_duplicate_keys_and_untrusted_store_are_rejected(tmp_path):
    m, c, _, store, _ = setup(tmp_path)
    store.state_path.write_text('{"schema":1,"schema":2}')
    with pytest.raises(m.ResourceError, match="duplicate_json"):
        c.snapshot()
    store.state_path.chmod(0o666)
    with pytest.raises(m.ResourceError, match="trust"):
        c.snapshot()


def test_unknown_or_missing_host_workload_snapshot_refuses_request_and_bootstrap(tmp_path):
    m, c, b, _, e = setup(tmp_path)
    e.live_workloads["vm-a"] = ("untracked-foreign-work",)
    with pytest.raises(m.ResourceError, match="incomplete_workloads"):
        c.request(request(m), e)
    assert b.calls == []
    e.live_workloads.pop("vm-a")
    with pytest.raises(m.ResourceError, match="incomplete_workloads"):
        c.request(request(m), e)


def test_finishing_one_workload_during_unknown_growth_preserves_ambiguous_charge(tmp_path):
    m, c, b, _, e = setup(tmp_path)
    running(m, c, e)
    c.request(request(m, "request-2", "work-2", 200), e)
    b.fault = "timeout-after-change"
    c.grow("request-2", e)
    assert finish(c, "request-1", completion(m), e).phase == "RELEASE"
    assert (c.snapshot()[0].guest_bytes, c.snapshot()[0].state) == (704, "ambiguous")


def test_forged_aggregate_floor_in_persisted_state_is_not_accepted(tmp_path):
    m, c, _, store, e = setup(tmp_path)
    running(m, c, e)
    state = json.loads(store.state_path.read_text())
    state["grants"][0]["active_floor_bytes"] = 128
    store.state_path.write_text(json.dumps(state))
    with pytest.raises(m.ResourceError, match="aggregate"):
        c.request(request(m, "request-2", "work-2", 1), e)


def test_public_request_schema_allows_only_demand_and_never_client_evidence():
    import jsonschema
    m = api()
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "schemas/host-resource-request.schema.json").read_text())
    example = json.loads((root / "examples/host-resource-request.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(example, schema)
    req = m.decode_resource_request(example)
    assert req.workload_bytes == 1073741824
    forged = {**example, "active_grants_protected": True}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(forged, schema)
    with pytest.raises(m.ResourceError, match="shape"):
        m.decode_resource_request(forged)


def test_incomplete_host_inventory_prevents_initialization(tmp_path):
    m, c, b, _, e = setup(tmp_path)
    store = m.FileReceiptStore(tmp_path / "new-uninitialized-state", owner_uid=os.getuid())
    fresh = m.HostResourceController(c.policy, store, b, clock=lambda: 100)
    e.live_workloads["vm-a"] = ("existing-untracked-job",)
    with pytest.raises(m.ResourceError, match="incomplete_workloads"):
        fresh.bootstrap(c.snapshot(), e)
    assert not store.state_path.exists()


def test_duplicate_runtime_process_binding_cannot_initialize_two_resident_vms(tmp_path):
    m, c, b, _, e = setup(tmp_path)
    store = m.FileReceiptStore(tmp_path / "duplicate-process-state", owner_uid=os.getuid())
    fresh = m.HostResourceController(c.policy, store, b, clock=lambda: 100)
    second = replace(e.bindings[1], process_id=e.bindings[0].process_id)
    changed = replace(e, bindings=(e.bindings[0], second),
                      qualifications=(e.qualifications[0], replace(e.qualifications[1], binding=second)))
    b.rows["vm-b"] = replace(b.rows["vm-b"], process_id=second.process_id)
    with pytest.raises(m.ResourceError, match="ownership"):
        fresh.bootstrap(c.snapshot(), changed)
    assert not store.state_path.exists()


def test_more_than_256_completed_requests_reload_and_old_idempotency_have_no_lifetime_limit(tmp_path):
    m, c, b, store, e = setup(tmp_path)
    first_request = request(m, "request-0", "work-0")
    first_release = None
    for number in range(260):
        req = request(m, f"request-{number}", f"work-{number}")
        running(m, c, e, req=req)
        finish(c, req.request_id, completion(m, req.workload_id), e)
        c.shrink(req.request_id, e)
        released = c.reconcile(req.request_id, e, replace(completion(m, req.workload_id),
                                  total_bytes=128, available_bytes=128))
        assert released.phase == "RELEASE"
        if number == 0:
            first_release = released
    restored = m.HostResourceController(c.policy, store, b, clock=lambda: 100)
    assert restored.request(first_request, e) == first_release
    assert restored.reconcile(first_request.request_id, e) == first_release
    assert json.loads(store.state_path.read_text())["receipts"] == []
    assert len(b.calls) == 520
    with pytest.raises(m.ResourceError, match="request_conflict"):
        restored.request(replace(first_request, workload_bytes=322), e)
    with pytest.raises(m.ResourceError, match="workload_conflict"):
        restored.request(request(m, "new-request-id", "work-0"), e)
    assert len(b.calls) == 520


@pytest.mark.parametrize("fault", ["archive-index", "prune-state"])
def test_crash_between_completed_archive_and_state_prune_keeps_charge_and_no_blind_replay(
        tmp_path, monkeypatch, fault):
    m, c, b, store, e = setup(tmp_path)
    running(m, c, e)
    finish(c, "request-1", completion(m), e)
    c.shrink("request-1", e)
    original_atomic = store._atomic
    failed = []

    def crash_once(path, data):
        selected = path.parent == store.workload_directory if fault == "archive-index" else path == store.state_path
        if selected and not failed:
            failed.append(True)
            raise OSError("synthetic interrupted publication")
        return original_atomic(path, data)

    monkeypatch.setattr(store, "_atomic", crash_once)
    after_shrink = replace(completion(m), total_bytes=128, available_bytes=128)
    with pytest.raises(OSError, match="interrupted publication"):
        c.reconcile("request-1", e, after_shrink)
    restored = m.HostResourceController(c.policy, store, b, clock=lambda: 100)
    assert restored.snapshot()[0].guest_bytes == 512
    assert restored.request(request(m), e).phase == "SHRINK_UNKNOWN"
    assert restored.reconcile("request-1", e, after_shrink).phase == "RELEASE"
    assert restored.request(request(m), e).phase == "RELEASE"
    assert restored.snapshot()[0].guest_bytes == 128
    assert b.calls == [("vm-a", 512), ("vm-a", 128)]


def test_completed_identity_records_fsync_their_actual_parent_and_retain_original_context(
        tmp_path, monkeypatch):
    m, c, _, store, e = setup(tmp_path)
    synced_directories = set()
    fsync = m.os.fsync

    def record_fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            synced_directories.add(Path(os.readlink(f"/proc/self/fd/{fd}")))
        return fsync(fd)

    monkeypatch.setattr(m.os, "fsync", record_fsync)
    running(m, c, e)
    finish(c, "request-1", completion(m), e)
    c.shrink("request-1", e)
    c.reconcile("request-1", e, replace(completion(m), total_bytes=128, available_bytes=128))
    assert {store.directory, store.completed_directory, store.workload_directory} <= synced_directories
    record = json.loads((store.completed_directory / store._key("request-1")).read_text())
    assert record["context"]["host_boot_id"] == "host-boot-1"
    assert record["context"]["policy_sha256"] == e.policy_sha256
    assert record["context"]["binding"]["native_id"] == "native-vm-a"


@pytest.mark.parametrize("assigned,configured", [(128, 512), (512, 128), (128, 128)])
def test_run_floor_readback_contradiction_closes_new_admission_and_retains_charge(
        tmp_path, assigned, configured):
    m, c, b, store, e = setup(tmp_path)
    running(m, c, e)
    b.rows["vm-a"] = replace(b.rows["vm-a"], assigned_bytes=assigned, configured_bytes=configured)
    with pytest.raises(m.ResourceError, match="identity_mismatch"):
        c.request(request(m, "request-b", "work-b", 64, vm="vm-b"), e)
    assert (c.snapshot()[0].guest_bytes, c.snapshot()[0].state) == (512, "ambiguous")
    assert c.snapshot()[1].guest_bytes == 256
    b.rows["vm-a"] = replace(b.rows["vm-a"], assigned_bytes=512, configured_bytes=512)
    restored = m.HostResourceController(c.policy, store, b, clock=lambda: 100)
    with pytest.raises(m.ResourceError, match="reconciliation_required"):
        restored.request(request(m, "request-b", "work-b", 64, vm="vm-b"), e)
    assert b.calls == [("vm-a", 512)]


def test_live_floor_guard_allows_current_allocation_before_future_same_vm_grow(tmp_path):
    m, c, b, _, e = setup(tmp_path)
    running(m, c, e)
    assert c.request(request(m, "request-2", "work-2", 200), e).target_bytes == 704
    assert b.rows["vm-a"].assigned_bytes == 512  # below future floor649, above live floor449
    assert c.grow("request-2", e).phase == "GUEST_ADMIT"


def test_finishing_work_is_excluded_only_after_fresh_cleanup_and_descendant_proof(tmp_path):
    m, c, b, _, e = setup(tmp_path)
    running(m, c, e)
    b.rows["vm-a"] = replace(b.rows["vm-a"], assigned_bytes=128, configured_bytes=128)
    # The workload is still in the authenticated live inventory. An attempted
    # finish cannot remove it using the request-id before checking this proof.
    bad = replace(completion(m), completed_workload_children=1)
    with pytest.raises(m.ResourceError, match="cleanup"):
        c.finish("request-1", bad, e)
    assert c.snapshot()[0].state == "active"
    with pytest.raises(m.ResourceError, match="identity_mismatch"):
        c.request(request(m, "request-b", "work-b", 64, vm="vm-b"), e)


def test_cross_vm_completion_defers_shrink_until_other_host_grant_is_admitted(tmp_path):
    m, c, b, store, e = setup(tmp_path)
    running(m, c, e)
    c.request(request(m, "request-b", "work-b", 64, vm="vm-b"), e)
    assert finish(c, "request-1", completion(m), e).phase == "SHRINK_DEFERRED"
    assert c.snapshot()[0].guest_bytes == 512
    restored = m.HostResourceController(c.policy, store, b, clock=lambda: 100)
    with pytest.raises(m.ResourceError, match="host_busy"):
        restored.shrink("request-1", e)
    assert restored.grow("request-b", e).phase == "GUEST_ADMIT"
    guest_b = replace(guest(m, "work-b"), vm_id="vm-b", total_bytes=256, available_bytes=128,
                      task_limit_bytes=64, slurm_memory_bytes=128)
    assert restored.admit("request-b", guest_b, e).phase == "RUN"
    e.live_workloads["vm-b"] = ("work-b",)
    assert restored.reconcile("request-1", e).phase == "SHRINK_READY"
    assert b.calls == [("vm-a", 512)]  # promotion was metadata only
    assert restored.snapshot()[0].guest_bytes == 512
    restored.shrink("request-1", e)
    assert restored.snapshot()[0].guest_bytes == 512
    restored.reconcile("request-1", e, replace(completion(m), total_bytes=128, available_bytes=128))
    assert restored.snapshot()[0].guest_bytes == 128
    assert restored.snapshot()[1].state == "active"


@pytest.mark.parametrize("interrupt_promotion", [False, True])
def test_multiple_deferred_completions_serialize_durable_slot_release_and_reload(
        tmp_path, monkeypatch, interrupt_promotion):
    m, c, b, store, e = setup(tmp_path, vm_ids=("vm-a", "vm-b", "vm-c"))
    running(m, c, e)
    running(m, c, e, req=request(m, "request-c", "work-c", vm="vm-c"))
    c.request(request(m, "request-b", "work-b", 64, vm="vm-b"), e)
    assert finish(c, "request-1", completion(m), e).phase == "SHRINK_DEFERRED"
    done_c = replace(completion(m, "work-c"), vm_id="vm-c")
    assert finish(c, "request-c", done_c, e).phase == "SHRINK_DEFERRED"
    assert [r["phase"] for r in json.loads(store.state_path.read_text())["receipts"]] == [
        "SHRINK_DEFERRED", "SHRINK_DEFERRED", "HOST_GRANT"]
    restored = m.HostResourceController(c.policy, store, b, clock=lambda: 100)
    assert [g.guest_bytes for g in restored.snapshot()] == [512, 256, 512]
    restored.grow("request-b", e)
    guest_b = replace(guest(m, "work-b"), vm_id="vm-b", total_bytes=256, available_bytes=128,
                      task_limit_bytes=64, slurm_memory_bytes=128)
    if interrupt_promotion:
        atomic, failed = store._atomic, []

        def fail_slot_commit(path, data):
            if path == store.state_path and not failed:
                failed.append(True)
                raise OSError("synthetic deferred promotion crash")
            return atomic(path, data)

        monkeypatch.setattr(store, "_atomic", fail_slot_commit)
        with pytest.raises(OSError, match="promotion crash"):
            restored.admit("request-b", guest_b, e)
        restored = m.HostResourceController(c.policy, store, b, clock=lambda: 100)
        assert restored.reconcile("request-b", e).phase == "GUEST_ADMIT"
        assert restored.reconcile("request-1", e).phase == "SHRINK_DEFERRED"
    restored.admit("request-b", guest_b, e)
    e.live_workloads["vm-b"] = ("work-b",)
    assert restored.reconcile("request-1", e).phase == "SHRINK_READY"
    assert restored.reconcile("request-c", e).phase == "SHRINK_DEFERRED"
    assert b.calls == [("vm-a", 512), ("vm-c", 512)]
    restored.shrink("request-1", e)
    reloaded = m.HostResourceController(c.policy, store, b, clock=lambda: 100)
    assert reloaded.reconcile("request-1", e).phase == "SHRINK_UNKNOWN"
    assert reloaded.reconcile("request-c", e).phase == "SHRINK_DEFERRED"
    assert reloaded.snapshot()[0].guest_bytes == 512
    reloaded.reconcile("request-1", e, replace(completion(m), total_bytes=128, available_bytes=128))
    assert reloaded.reconcile("request-c", e).phase == "SHRINK_READY"
    assert reloaded.snapshot()[2].guest_bytes == 512
    assert b.calls == [("vm-a", 512), ("vm-c", 512), ("vm-a", 128)]
    reloaded.shrink("request-c", e)
    reloaded.reconcile("request-c", e, replace(done_c, total_bytes=128, available_bytes=128))
    assert [g.guest_bytes for g in reloaded.snapshot()] == [128, 256, 128]
    assert reloaded.snapshot()[1].state == "active"
