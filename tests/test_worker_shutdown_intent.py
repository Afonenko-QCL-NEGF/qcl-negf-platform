"""Persistent node intent/interleavings: independent fake identities, real temp JSON/flock."""
import base64
import copy
import fcntl
import json
import multiprocessing
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "ops"))
import application_release as release
import worker_lifecycle as worker
from test_node_enrollment import CONTROLLER, WORKER, SECOND, TRUST, registry, pool, manifest_fixture

def authorized_event(node, record, authority):
    # Literal fake authenticated principal, separate from observed guest health.
    return {"schema": "qcl-negf-startup-event-v1", "event_id": "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
            "node": "worker", "inventory_id": registry()["inventory_id"],
            "enrollment_id": registry()["nodes"][1]["enrollment_id"],
            "controller_machine_uuid": CONTROLLER["machine_uuid"], "actor_uid": 0,
            "entrypoint": "privileged-controller-operator"}

NEW_BOOT = "dddddddd-dddd-dddd-dddd-dddddddddddd"

class FakeCommands:
    def __init__(self):
        self.calls = []
        self.lines = []
        self.verified = set()
        self.identity = dict(WORKER)
        self.on_call = None
    def __call__(self, args):
        self.calls.append(args)
        if self.on_call:
            self.on_call(args)
        if args[0] == "ssh":
            actual = CONTROLLER if "controller" in args[-2] else self.identity
            if args[-1].endswith(" identity"):
                return json.dumps(actual)
            if " activate " in args[-1]:
                return ""
            if " check " in args[-1]:
                return json.dumps({"schema": "qcl-negf-node-release-check-v1", "node_identity": actual,
                                   "release": {**manifest_fixture(), "ready": True}})
        if args[0] == "squeue":
            return "\n".join(self.lines)
        if "verify-stop" in args:
            if args[args.index("--execution-id") + 1] not in self.verified:
                raise RuntimeError("synthetic scoped stop proof unavailable")
            return "verified by fake scoped Runner"
        if args[0] in ("scontrol", "systemctl", "runuser") or args[:2] == ["nix", "copy"]:
            return ""
        if args[:3] == ["nix", "path-info", "--json"]:
            return json.dumps({item["path"]: {"narHash": item["narHash"]} for item in manifest_fixture()["closures"]})
        raise AssertionError("Unexpected non-fake boundary: " + args[0])

class ShutdownIntentTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="cr02-")
        self.addCleanup(temp.cleanup)
        self.runtime = Path(temp.name)
        self.state = self.runtime / "shutdown"
        self.gate = self.runtime / "gate"
        self.gate.write_text(json.dumps({"open": True, "release_id": "release-a"}))
        (self.runtime / "release.json").write_text(json.dumps({**manifest_fixture(), "ready": True}))
        self.run = FakeCommands()
        self.enrollment = "/protected/enrollment.json"
        for name, callback in (("load_enrollment", lambda _: {"registry": registry(), "registry_sha256": "e" * 64, "known_hosts_bytes": b"synthetic"}),
                               ("observe_node_identity", lambda **_: CONTROLLER),
                               ("freeze_ssh_trust", lambda *a, **k: TRUST)):
            mocker = patch.object(release, name, callback)
            mocker.start()
            self.addCleanup(mocker.stop)
    def shutdown(self):
        return worker.shutdown_step("worker", self.state, enrollment=self.enrollment,
                                    target="admin@worker.invalid", run=self.run)
    def startup(self, target="admin@worker.invalid"):
        with patch.object(worker, "_authorized_startup_event", authorized_event):
            return worker.startup("worker", target, enrollment=self.enrollment,
                                  runtime=self.runtime, gate=self.gate, run=self.run)
    def intent(self):
        return json.loads((self.state / "worker.json").read_text())
    def no_resume(self):
        self.assertFalse(any("State=RESUME" in args for args in self.run.calls))
    def test_idle_safe_stop_retains_durable_inhibit_before_any_allocation(self):
        original_gate = self.gate.read_bytes()
        self.assertTrue(self.shutdown())
        path = self.state / "worker.json"
        self.assertTrue(path.exists(), "idle safe stop must retain persistent normal-shutdown intent")
        intent = json.loads(path.read_text())
        self.assertEqual(intent["phase"], "safe_to_power_off")
        self.assertTrue(intent["capture_complete"])
        self.assertEqual(intent["jobs"], {})
        self.assertEqual(intent["boot_id"], WORKER["boot_id"])
        before = list(self.run.calls)
        with self.assertRaises(RuntimeError):
            release.deliver_cli(manifest_fixture(), pool(), run=self.run, enrollment=self.enrollment,
                                runtime=self.runtime, gate=self.gate)
        self.assertEqual(self.run.calls, before)
        self.assertEqual(self.gate.read_bytes(), original_gate)
        self.assertFalse(any("State=RESUME" in args for args in self.run.calls))

    def test_intent_is_durable_before_drain_and_common_lock_free_during_runner(self):
        from test_worker_lifecycle import job
        self.run.lines = [job("101", "alice")]
        facts = []
        def hook(args):
            if "State=DRAIN" in args:
                value = self.intent()
                facts.append((value["phase"], value["capture_complete"]))
            if "pause" in args:
                with release.lifecycle_owner(self.runtime):
                    self.assertEqual(self.intent()["jobs"]["101"]["owner"], "alice")
        self.run.on_call = hook
        self.assertFalse(self.shutdown())
        self.assertEqual(facts, [("capture_pending", False)])
        self.run.lines = []
        self.assertFalse(self.shutdown())
        self.run.verified.add("execution-101")
        self.assertTrue(self.shutdown())
        self.assertEqual(self.intent()["phase"], "safe_to_power_off")
        self.assertEqual(self.intent()["jobs"], {})

    def test_same_boot_denied_new_boot_authorized_and_idempotent(self):
        self.assertTrue(self.shutdown())
        old = (self.state / "worker.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "NEW boot"):
            self.startup()
        self.assertEqual((self.state / "worker.json").read_bytes(), old)
        self.no_resume()
        self.run.identity = {**WORKER, "boot_id": NEW_BOOT}
        result = self.startup()
        self.assertEqual(result["phase"], "resumed")
        self.assertEqual(self.intent()["return_boot_id"], NEW_BOOT)
        self.assertEqual(self.intent()["boot_id"], WORKER["boot_id"])
        self.assertEqual(sum("State=RESUME" in args for args in self.run.calls), 1)
        release.lifecycle_guard(self.runtime)
        old = (self.state / "worker.json").read_bytes()
        self.startup()
        self.assertEqual((self.state / "worker.json").read_bytes(), old)
        self.assertEqual(sum("State=RESUME" in args for args in self.run.calls), 1)

    def test_foreign_machine_and_wrong_event_cannot_clear_safe_scope(self):
        self.shutdown()
        old = (self.state / "worker.json").read_bytes()
        self.run.identity = {**SECOND, "boot_id": NEW_BOOT}
        with self.assertRaises(ValueError):
            self.startup()
        self.run.identity = {**WORKER, "boot_id": NEW_BOOT}
        for event in (None, {"trusted": True}, {**authorized_event(None,None,None), "enrollment_id": "ffffffff-ffff-ffff-ffff-ffffffffffff"}):
            with patch.object(worker, "_authorized_startup_event", lambda *a: event), self.assertRaises(PermissionError):
                worker.startup("worker", "admin@worker.invalid", enrollment=self.enrollment,
                               runtime=self.runtime, gate=self.gate, run=self.run)
            self.assertEqual((self.state / "worker.json").read_bytes(), old)
        self.no_resume()

    def test_health_boot_drift_is_unknown_no_resume_and_no_retry_dispatch(self):
        self.shutdown()
        self.run.identity = {**WORKER, "boot_id": NEW_BOOT}
        def drift(args):
            if args[0] == "ssh" and " check " in args[-1]:
                self.run.identity = {**WORKER, "boot_id": "ffffffff-ffff-ffff-ffff-ffffffffffff"}
        self.run.on_call = drift
        with self.assertRaises(ValueError):
            self.startup()
        self.no_resume()
        self.assertTrue(self.intent()["requires_reconciliation"])
        before = list(self.run.calls)
        with self.assertRaises(RuntimeError):
            self.startup()
        self.assertEqual(self.run.calls, before)

    def test_orphan_capture_empty_retry_and_new_boot_never_clear(self):
        real = worker._state_write
        def crash(path, value):
            if value["phase"] == "awaiting_jobs":
                raise OSError("crash before durable capture")
            real(path, value)
        with patch.object(worker, "_state_write", crash), self.assertRaises(OSError):
            self.shutdown()
        self.assertFalse(self.intent()["capture_complete"])
        with self.assertRaisesRegex(RuntimeError, "Orphan"):
            self.shutdown()
        self.assertTrue(self.intent()["requires_reconciliation"])
        self.run.identity = {**WORKER, "boot_id": NEW_BOOT}
        with self.assertRaises(RuntimeError):
            self.startup()
        self.no_resume()

    def test_v1_bytes_retained_and_malformed_missing_boot_fail_closed(self):
        self.state.mkdir()
        path = self.state / "worker.json"
        old = b'{ "schema":"qcl-negf-shutdown-pending-v1", "node":"worker", "jobs":{} }\n'
        path.write_bytes(old)
        with self.assertRaisesRegex(RuntimeError, "Legacy"):
            self.shutdown()
        self.assertEqual(base64.b64decode(self.intent()["legacy_evidence_base64"]), old)
        self.assertIsNone(self.intent()["boot_id"])
        self.assertTrue(self.intent()["requires_reconciliation"])
        for raw in (b'{broken', json.dumps({**self.intent(), "schema": release.SHUTDOWN_SCHEMA, "origin": "normal_shutdown", "boot_id": None}).encode()):
            path.write_bytes(raw)
            with self.assertRaises(ValueError):
                self.shutdown()
            self.assertEqual(path.read_bytes(), raw)
        self.no_resume()

    def test_global_busy_lock_cannot_mutate_shutdown(self):
        with release.lifecycle_owner(self.runtime), self.assertRaises(BlockingIOError):
            self.shutdown()
        self.assertFalse((self.state / "worker.json").exists())
        self.assertTrue(all(args[0] == "ssh" and args[-1].endswith(" identity") for args in self.run.calls))
        self.assertTrue(self.shutdown())

    def test_unknown_receipt_and_update_guard_precede_snapshot_and_remote(self):
        paths = self.runtime / "delivery-attempts"
        paths.mkdir()
        file = paths / "old.json"
        raw = b'{"schema":"qcl-negf-admission-intent-v1","opaque":"preserve"}\n'
        file.write_bytes(raw)
        before_gate = self.gate.read_bytes()
        for action in (self.shutdown, self.startup):
            with self.assertRaises(RuntimeError):
                action()
            self.assertEqual(self.run.calls, [])
            self.assertEqual(file.read_bytes(), raw)
            self.assertEqual(self.gate.read_bytes(), before_gate)
        file.unlink()  # Fixture-owned synthetic evidence only.
        (self.runtime / "cluster-update.json").write_text('{"ownership":"unknown"}')
        with self.assertRaises(RuntimeError):
            self.startup()
        self.assertEqual(self.run.calls, [])

    def test_terminal_replace_failure_after_resume_keeps_independent_blocker(self):
        self.shutdown()
        self.run.identity = {**WORKER, "boot_id": NEW_BOOT}
        real = worker._state_write
        def broken_terminal(path, value):
            if value["phase"] in ("resumed", "reconciliation_required"):
                real(path, value)  # Model replace succeeds, directory fsync then fails.
                raise OSError("synthetic terminal directory fsync failed after replace")
            real(path, value)
        with patch.object(worker, "_state_write", broken_terminal), self.assertRaises(OSError):
            self.startup()
        self.assertEqual(sum("State=RESUME" in args for args in self.run.calls), 1)
        self.assertTrue(self.intent()["requires_reconciliation"])
        markers = list((self.runtime / "delivery-attempts").glob("*.startup-admission-intent.json"))
        self.assertEqual(len(markers), 1)
        old = markers[0].read_bytes()
        before = list(self.run.calls)
        with self.assertRaises(RuntimeError):
            self.startup()
        self.assertEqual(before, self.run.calls)
        self.assertEqual(old, markers[0].read_bytes())

    def test_attempt_collision_never_overwrites_and_initial_admission_has_no_fake_old_boot(self):
        path = self.runtime / "same.json"
        path.write_bytes(b'original evidence')
        with self.assertRaises(FileExistsError):
            worker._exclusive_attempt_json(path, {"replace": "forbidden"})
        self.assertEqual(path.read_bytes(), b'original evidence')
        self.startup()
        self.assertEqual(self.intent()["origin"], "initial_enrollment")
        self.assertIsNone(self.intent()["boot_id"])
        self.assertIsNone(self.intent()["shutdown_id"])
        self.assertIsNone(self.intent()["capture_complete"])
        release.lifecycle_guard(self.runtime)


    def test_owned_client_process_exit_leaves_idle_inhibit_and_free_lock(self):
        # One OWN forked fake client; no production subprocess/remote boundary.
        context = multiprocessing.get_context("fork")
        acknowledged = context.Event()
        release_client = context.Event()
        def client():
            self.shutdown()
            acknowledged.set()
            if not release_client.wait(3):
                raise RuntimeError("fixture release deadline")
        child = context.Process(target=client)
        child.start()
        try:
            self.assertTrue(acknowledged.wait(3))
            self.assertEqual(self.intent()["phase"], "safe_to_power_off")
            release_client.set()
            child.join(3)
            self.assertFalse(child.is_alive(), "OWN fake child must be reaped")
            self.assertEqual(child.exitcode, 0)
            with release.lifecycle_owner(self.runtime):
                with self.assertRaises(RuntimeError):
                    release.lifecycle_guard(self.runtime)
            with self.assertRaises(RuntimeError):
                release.deliver_cli(manifest_fixture(), pool(), run=self.run, enrollment=self.enrollment,
                                    runtime=self.runtime, gate=self.gate)
            self.assertEqual(self.run.calls, [])
        finally:
            release_client.set()
            if child.is_alive():
                child.terminate()
            child.join(3)
            self.assertFalse(child.is_alive())
            child.close()

    def test_authorized_alias_and_omitted_pool_worker_inhibit(self):
        self.shutdown()
        reduced = pool()
        reduced["nodes"] = [item for item in reduced["nodes"] if item["name"] != "worker"]
        before = list(self.run.calls)
        with self.assertRaises(RuntimeError):
            release.deliver_cli(manifest_fixture(), reduced, run=self.run, enrollment=self.enrollment,
                                runtime=self.runtime, gate=self.gate)
        self.assertEqual(before, self.run.calls)
        self.run.identity = {**WORKER, "boot_id": NEW_BOOT}
        result = self.startup("admin@worker-alias.invalid")
        self.assertEqual(result["boot_id"], NEW_BOOT)
        self.assertEqual(self.intent()["target"], "admin@worker.invalid")
        release.lifecycle_guard(self.runtime)

    def test_creation_and_unlink_failure_never_trust_completion(self):
        self.shutdown()
        self.run.identity = {**WORKER, "boot_id": NEW_BOOT}
        with patch.object(worker, "_exclusive_attempt_json", side_effect=OSError("storage unavailable")), self.assertRaises(OSError):
            self.startup()
        self.no_resume()
        self.assertTrue(self.intent()["requires_reconciliation"])
        # Independent filesystem/attempt; no reset or clear of the failed scope.
        with tempfile.TemporaryDirectory(prefix="cr02-unlink-") as temporary:
            old_runtime, old_state, old_gate = self.runtime, self.state, self.gate
            try:
                self.runtime = Path(temporary); self.state = self.runtime / "shutdown"; self.gate = self.runtime / "gate"
                self.gate.write_text(json.dumps({"open": True, "release_id": "release-a"}))
                (self.runtime / "release.json").write_text(json.dumps({**manifest_fixture(), "ready": True}))
                real_unlink = Path.unlink
                def fail_marker(path, *args, **kwargs):
                    if path.name.endswith(".startup-admission-intent.json"):
                        raise OSError("fixture unlink failed")
                    return real_unlink(path, *args, **kwargs)
                with patch.object(Path, "unlink", fail_marker), self.assertRaises(OSError):
                    self.startup()
                self.assertTrue(self.intent()["requires_reconciliation"])
                self.assertEqual(len(list((self.runtime / "delivery-attempts").glob("*.startup-admission-intent.json"))), 1)
                before = list(self.run.calls)
                with self.assertRaises(RuntimeError): self.startup()
                self.assertEqual(before, self.run.calls)
            finally:
                self.runtime, self.state, self.gate = old_runtime, old_state, old_gate

    def test_wrong_local_never_reads_runtime_or_mutates(self):
        with patch.object(release, "observe_node_identity", lambda **_: WORKER), \
             patch.object(release, "lifecycle_guard", side_effect=AssertionError("runtime read too early")):
            for action in (self.shutdown, self.startup):
                with self.assertRaises(ValueError): action()
        self.assertEqual(self.run.calls, [])
        self.assertFalse((self.state / "worker.json").exists())


    def namespace_fsync(self, trace, fail_path=None):
        def sync(fd):
            observed = os.fstat(fd)
            if not __import__("stat").S_ISDIR(observed.st_mode):
                return  # Synthetic syscall observation; no production FS flushing.
            paths = [self.runtime, self.state, self.runtime / "delivery-attempts"]
            paths += list(self.runtime.parents)
            for path in paths:
                if path.exists():
                    actual = path.stat()
                    if (actual.st_dev, actual.st_ino) == (observed.st_dev, observed.st_ino):
                        trace.append(str(path))
                        if path == fail_path and self.state.exists():
                            trace.append("failed-containing-entry")
                            raise OSError("synthetic containing-directory fsync failure")
                        break
        return sync

    def test_namespace_first_state_parent_barrier_and_retry_failure_before_drain(self):
        trace = []
        # First attempt sync failure may leave directory present; retry must resync.
        with patch.object(os, "fsync", self.namespace_fsync(trace, self.runtime)), self.assertRaises(OSError):
            self.shutdown()
        self.no_resume()
        self.assertFalse(any("State=DRAIN" in args for args in self.run.calls))
        self.assertTrue(self.state.exists())
        before = list(self.run.calls)
        with patch.object(os, "fsync", self.namespace_fsync(trace, self.runtime)), self.assertRaises(OSError):
            self.shutdown()
        self.assertTrue(all(args[0] == "ssh" for args in self.run.calls[len(before):]))
        self.assertEqual(trace.count("failed-containing-entry"), 2)
        self.assertFalse(any("State=DRAIN" in args for args in self.run.calls))

    def test_namespace_marker_parent_failure_precedes_resume_and_preserves_unknown(self):
        self.shutdown()
        self.run.identity = {**WORKER, "boot_id": NEW_BOOT}
        trace = []
        observe = self.namespace_fsync(trace)
        failed = [False]
        def sync(fd):
            observe(fd)
            if (self.runtime / "delivery-attempts").exists() and not failed[0]:
                value, expected = os.fstat(fd), self.runtime.stat()
                if (value.st_dev, value.st_ino) == (expected.st_dev, expected.st_ino):
                    failed[0] = True
                    raise OSError("marker containing-directory barrier failed")
        with patch.object(os, "fsync", sync), self.assertRaises(OSError):
            self.startup()
        self.no_resume()
        self.assertTrue(self.intent()["requires_reconciliation"])
        before = list(self.run.calls)
        with self.assertRaises(RuntimeError): self.startup()
        self.assertEqual(before, self.run.calls)

    def test_namespace_nested_entries_are_reachable_before_state_publication(self):
        root = self.runtime
        self.runtime = root / "nested" / "runtime"
        self.state = self.runtime / "shutdown"
        trace = []
        # Actual directory descriptors/mkdir; fsync effects are handwritten observations.
        value = {"schema": "synthetic", "phase": "requested"}
        real_publish = worker.publish_json
        def publish(path, payload, **kwargs):
            self.assertIn(str(root), trace)
            self.assertIn(str(root / "nested"), trace)
            self.assertIn(str(self.runtime), trace)
            trace.append("publish-state")
            return real_publish(path, payload, **kwargs)
        with patch.object(os, "fsync", self.namespace_fsync(trace)), patch.object(worker, "publish_json", publish):
            worker._state_write(self.state / "worker.json", value)
        self.assertLess(trace.index(str(root)), trace.index("publish-state"))
        self.assertLess(trace.index(str(root / "nested")), trace.index("publish-state"))
        self.assertLess(trace.index(str(self.runtime)), trace.index("publish-state"))


if __name__ == "__main__":
    unittest.main()
