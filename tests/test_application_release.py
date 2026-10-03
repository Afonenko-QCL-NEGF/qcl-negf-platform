"""Exercise release activation at the Nix/SSH/systemd command boundary.

No services, SSH connections, solver or Nix closures are built by these tests.
The real activation writes profiles/configuration, guards jobs and gates the pool.
"""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "application_release", Path(__file__).parents[1] / "ops" / "application_release.py"
)


class Commands:
    def __init__(self):
        self.calls = []
        self.failure = None
        self.registered = "12345678-1234-1234-1234-123456789abc"

    def __call__(self, args):
        self.calls.append(args)
        if self.failure and self.failure in args:
            raise RuntimeError("injected command failure")
        if args[0] == "nix-env":
            profile = Path(args[args.index("--profile") + 1])
            profile.unlink(missing_ok=True)
            profile.symlink_to(args[-1])
        if "register_aiida.py" in " ".join(args):
            return json.dumps({"code_uuid": self.registered,
                               "solver_executable": "/nix/store/solver/bin/qcl-negf"})
        return ""


def release():
    return {"schema": "qcl-negf-release-v1", "release_id": "release-a",
            "application_path": "/nix/store/application",
            "solver_executable": "/nix/store/solver/bin/qcl-negf"}


class ApplicationReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ops = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(cls.ops)

    def test_activation_publishes_only_after_identity_and_health_check_then_retry_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            commands = Commands()
            arguments = dict(profile=root / "profile", runtime=root / "runtime",
                             role="worker", run=commands)
            first = self.ops.activate(release(), **arguments)
            self.assertEqual(first["release_id"], "release-a")
            self.assertEqual(json.loads((root / "runtime/release.json").read_text())["release_id"], "release-a")
            self.assertTrue(any(call[:2] == ["nix-store", "--verify-path"] for call in commands.calls))
            before = len([call for call in commands.calls if call[0] == "nix-env"])
            second = self.ops.activate(release(), **arguments)
            self.assertEqual(first, second)
            self.assertEqual(len([call for call in commands.calls if call[0] == "nix-env"]), before)

    def test_failed_health_check_does_not_publish_ready_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            commands = Commands()
            commands.failure = "slurmd.service"
            with self.assertRaisesRegex(RuntimeError, "injected"):
                self.ops.activate(release(), profile=root / "profile", runtime=root / "runtime",
                                  role="worker", run=commands)
            self.assertIsNot(json.loads((root / "runtime/release.json").read_text()).get("ready"), True)

    def test_partial_fleet_delivery_closes_admission_until_every_selected_node_verifies(self):
        with tempfile.TemporaryDirectory() as temporary:
            gate = Path(temporary) / "admission.json"
            gate.write_text(json.dumps({"open": True, "release_id": "old"}))
            completed = []

            def deliver(node, manifest):
                self.assertFalse(json.loads(gate.read_text())["open"])
                if node == "worker-b":
                    raise RuntimeError("worker offline")
                completed.append(node)
                return {**manifest, "ready": True}

            report = self.ops.deliver_pool(release(), ["worker-a", "worker-b"], gate,
                                           deliver=deliver, quiesce=lambda: None)
            self.assertFalse(report["open"])
            self.assertEqual(report["nodes"]["worker-b"]["status"], "failed")
            self.assertFalse(json.loads(gate.read_text())["open"])
            report = self.ops.deliver_pool(release(), ["worker-a", "worker-b"], gate,
                                           deliver=lambda _n, m: {**m, "ready": True}, quiesce=lambda: None)
            self.assertTrue(report["open"])
            self.assertEqual(json.loads(gate.read_text()),
                             {"open": True, "release_id": "release-a"})

    def test_quiesce_failure_keeps_gate_closed_and_no_node_activates(self):
        with tempfile.TemporaryDirectory() as temporary:
            gate = Path(temporary) / "admission.json"
            delivered = []

            def quiesce():
                raise RuntimeError("running or queued old jobs")

            with self.assertRaisesRegex(RuntimeError, "old jobs"):
                self.ops.deliver_pool(release(), ["worker"], gate, quiesce=quiesce,
                                      deliver=lambda n, _m: delivered.append(n))
            self.assertFalse(json.loads(gate.read_text())["open"])
            self.assertEqual(delivered, [])

    def test_gate_rejects_stale_worker_and_queued_job_then_allows_exact_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            gate = root / "admission.json"
            runtime = root / "release.json"
            gate.write_text(json.dumps({"open": True, "release_id": "release-a"}))
            runtime.write_text(json.dumps({**release(), "ready": True}))
            self.ops.guard("release-a", "/nix/store/solver/bin/qcl-negf", runtime, gate)
            for pin in ["old-queued-release", "offline-stale-release"]:
                with self.assertRaisesRegex(ValueError, "release"):
                    self.ops.guard(pin, "/nix/store/solver/bin/qcl-negf", runtime, gate)
            with self.assertRaisesRegex(ValueError, "solver"):
                self.ops.guard("release-a", "/nix/store/old-solver/bin/qcl-negf", runtime, gate)
            gate.write_text(json.dumps({"open": False, "release_id": "release-a"}))
            with self.assertRaisesRegex(ValueError, "closed"):
                self.ops.guard("release-a", "/nix/store/solver/bin/qcl-negf", runtime, gate)

    def test_unverified_node_identity_cannot_open_admission(self):
        with tempfile.TemporaryDirectory() as temporary:
            gate = Path(temporary) / "admission.json"
            report = self.ops.deliver_pool(release(), ["worker"], gate, quiesce=lambda: None,
                                          deliver=lambda _n, _m: {**release(), "release_id": "stale"})
            self.assertFalse(report["open"])
            self.assertEqual(report["nodes"]["worker"]["status"], "failed")

    def test_controller_activation_registers_immutable_code_before_ready_and_publishes_uuid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            commands = Commands()
            result = self.ops.activate(release(), profile=root / "profile", runtime=root / "runtime",
                                       role="controller", email="test@example.invalid", run=commands,
                                       allowed_codes_file=root / "code-uuid")
            self.assertEqual(result["code_uuid"], "12345678-1234-1234-1234-123456789abc")
            self.assertEqual((root / "code-uuid").read_text().strip(), result["code_uuid"])
            registration = next(call for call in commands.calls if call[0] == "runuser")
            self.assertIn("/nix/store/solver/bin/qcl-negf", registration)
            self.assertEqual(registration[-1], "qcl-negf-release-a")

    def test_failed_final_resume_leaves_admission_closed_with_node_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            gate = Path(temporary) / "admission.json"

            def admit():
                raise RuntimeError("resume failed")

            report = self.ops.deliver_pool(release(), ["worker"], gate, quiesce=lambda: None,
                                          deliver=lambda _n, m: {**m, "ready": True}, admit=admit)
            self.assertFalse(report["open"])
            self.assertIn("resume failed", report["admission_error"])
            self.assertFalse(json.loads(gate.read_text())["open"])

    def test_check_rejects_profile_path_that_mismatches_runtime_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "release.json").write_text(json.dumps(release()))
            (root / "profile").symlink_to("/nix/store/old-application")
            with self.assertRaisesRegex(ValueError, "profile"):
                self.ops.check(release(), profile=root / "profile", runtime=root, run=Commands())

    def test_pending_node_identity_cannot_run_job_or_open_pool(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            gate, runtime = root / "admission.json", root / "release.json"
            gate.write_text(json.dumps({"open": True, "release_id": "release-a"}))
            runtime.write_text(json.dumps({**release(), "ready": False}))
            with self.assertRaisesRegex(ValueError, "ready"):
                self.ops.guard("release-a", "/nix/store/solver/bin/qcl-negf", runtime, gate)
            report = self.ops.deliver_pool(release(), ["worker"], gate, quiesce=lambda: None,
                                          deliver=lambda _n, m: {**m, "ready": False})
            self.assertFalse(report["open"])

    def test_worker_boot_refuses_stale_release_but_allows_prepared_selected_release_with_closed_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            gate, runtime = root / "admission.json", root / "release.json"
            gate.write_text(json.dumps({"open": False, "release_id": "release-a"}))
            runtime.write_text(json.dumps({**release(), "ready": False}))
            (root / "profile").symlink_to("/nix/store/application")
            self.ops.node_check(runtime, gate, root / "profile", run=Commands())
            gate.write_text(json.dumps({"open": True, "release_id": "new-release"}))
            with self.assertRaisesRegex(ValueError, "release"):
                self.ops.node_check(runtime, gate, root / "profile", run=Commands())

    def test_bootstrap_after_reboot_uses_selected_solver_code_instead_of_image_seed(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "release.json"
            self.assertEqual(self.ops.bootstrap_selection(runtime, "/nix/store/seed/bin/qcl-negf", "seed-code"),
                             ("/nix/store/seed/bin/qcl-negf", "seed-code"))
            runtime.write_text(json.dumps({**release(), "ready": True}))
            self.assertEqual(self.ops.bootstrap_selection(runtime, "/nix/store/seed/bin/qcl-negf", "seed-code"),
                             ("/nix/store/solver/bin/qcl-negf", "qcl-negf-release-a"))


if __name__ == "__main__":
    unittest.main()
