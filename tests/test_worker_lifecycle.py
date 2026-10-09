"""Controller-side Windows bridge tests; fake Slurm/runner command boundary."""
import base64
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import sys
from unittest.mock import patch
from test_node_enrollment import CONTROLLER, WORKER, TRUST, registry

sys.path.insert(0, str(Path(__file__).parents[1] / "ops"))

SPEC = importlib.util.spec_from_file_location(
    "worker_lifecycle", Path(__file__).parents[1] / "ops" / "worker_lifecycle.py"
)


def job(job_id, owner, attempt=1):
    descriptor = {"execution_id": "execution-" + job_id, "attempt": attempt,
                  "output_directory": "results", "solver_executable": "/nix/store/solver/bin/qcl-negf"}
    comment = "qcl-negf-attempt-v1:" + base64.urlsafe_b64encode(json.dumps(descriptor).encode()).decode()
    return f"{job_id}|{owner}|{comment}|/srv/qcl-negf/jobs/{job_id}|worker|RUNNING"


class Slurm:
    def __init__(self, lines):
        self.lines = lines
        self.calls = []
        self.verified = set()
        self.paused = []

    def __call__(self, args):
        self.calls.append(args)
        if args[0] == "squeue":
            return "\n".join(self.lines)
        if "pause" in args:
            self.paused.append(args[args.index("--execution-id") + 1])
        if "verify-stop" in args:
            if args[args.index("--execution-id") + 1] not in self.verified:
                raise RuntimeError("durable receipt unavailable on permanent node")
            return json.dumps({"verified": True})
        return ""


class WorkerLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ops = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(cls.ops)

    def test_idle_drains_and_returns_without_waiting_for_a_checkpoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            slurm = Slurm([])
            self.assertTrue(self.ops.shutdown_step("worker", Path(temporary), run=slurm))
            self.assertEqual(slurm.paused, [])
            self.assertEqual(slurm.calls[0][:2], ["scontrol", "update"])

    def test_every_owner_is_paused_and_both_durable_verification_and_exit_are_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            slurm = Slurm([job("101", "alice"), job("102", "bob", attempt=2)])
            self.assertFalse(self.ops.shutdown_step("worker", state, run=slurm))
            self.assertEqual(set(slurm.paused), {"execution-101", "execution-102"})
            pauses = [args for args in slurm.calls if "pause" in args]
            self.assertEqual({args[2] for args in pauses}, {"alice", "bob"})
            slurm.verified.add("execution-101")
            slurm.lines = [job("102", "bob", attempt=2)]
            self.assertFalse(self.ops.shutdown_step("worker", state, run=slurm))
            slurm.verified.add("execution-102")
            self.assertFalse(self.ops.shutdown_step("worker", state, run=slurm))
            slurm.lines = []
            self.assertTrue(self.ops.shutdown_step("worker", state, run=slurm))

    def test_disappeared_job_without_receipt_is_retained_across_repeated_shutdown(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            slurm = Slurm([job("101", "alice")])
            self.assertFalse(self.ops.shutdown_step("worker", state, run=slurm))
            slurm.lines = []
            self.assertFalse(self.ops.shutdown_step("worker", state, run=slurm))
            self.assertTrue((state / "worker.json").exists())
            slurm.verified.add("execution-101")
            self.assertTrue(self.ops.shutdown_step("worker", state, run=slurm))
            self.assertFalse((state / "worker.json").exists())

    def test_unmanaged_job_cannot_be_treated_as_idle_or_safe(self):
        with tempfile.TemporaryDirectory() as temporary:
            slurm = Slurm(["101|alice|unknown|/srv/qcl-negf/jobs/101|worker|RUNNING"])
            with self.assertRaisesRegex(ValueError, "descriptor"):
                self.ops.shutdown_step("worker", Path(temporary), run=slurm)
            self.assertEqual(slurm.paused, [])

    def test_suspended_allocation_blocks_shutdown_instead_of_becoming_false_idle(self):
        class StateFilteringSlurm(Slurm):
            def __call__(self, args):
                if args[0] == "squeue" and args[args.index("--states") + 1] != "all":
                    return ""
                return super().__call__(args)

        with tempfile.TemporaryDirectory() as temporary:
            slurm = StateFilteringSlurm([job("101", "alice").replace("|RUNNING", "|SUSPENDED")])
            with self.assertRaisesRegex(ValueError, "SUSPENDED"):
                self.ops.shutdown_step("worker", Path(temporary), run=slurm)

    def test_configuring_allocation_waits_for_stop_proof(self):
        class StateFilteringSlurm(Slurm):
            def __call__(self, args):
                if args[0] == "squeue" and args[args.index("--states") + 1] != "all":
                    return ""
                return super().__call__(args)

        with tempfile.TemporaryDirectory() as temporary:
            slurm = StateFilteringSlurm([job("101", "alice").replace("|RUNNING", "|CONFIGURING")])
            self.assertFalse(self.ops.shutdown_step("worker", Path(temporary), run=slurm))
            self.assertEqual(slurm.paused, ["execution-101"])

    def test_terminal_and_unallocated_pending_records_do_not_require_new_checkpoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            slurm = Slurm([job("101", "alice").replace("|RUNNING", "|COMPLETED"),
                           job("102", "bob").replace("|worker|RUNNING", "|(null)|PENDING")])
            self.assertTrue(self.ops.shutdown_step("worker", Path(temporary), run=slurm))
            self.assertEqual(slurm.paused, [])

    def test_escaping_shared_directory_is_rejected_before_pause(self):
        with tempfile.TemporaryDirectory() as temporary:
            slurm = Slurm([job("101", "alice").replace("/srv/qcl-negf/jobs/101", "/tmp/outside")])
            with self.assertRaisesRegex(ValueError, "shared"):
                self.ops.shutdown_step("worker", Path(temporary), run=slurm)
            self.assertEqual(slurm.paused, [])

    def test_new_allocation_does_not_need_to_exist_for_shutdown_to_finish(self):
        with tempfile.TemporaryDirectory() as temporary:
            slurm = Slurm([job("101", "alice")])
            self.assertFalse(self.ops.shutdown_step("worker", Path(temporary), run=slurm))
            slurm.verified.add("execution-101")
            slurm.lines = []
            self.assertTrue(self.ops.shutdown_step("worker", Path(temporary), run=slurm))
            self.assertFalse(any(args[0] in ("sbatch", "srun", "scancel") for args in slurm.calls))

    def test_returning_worker_only_resumes_after_current_ready_identity_is_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = {"schema": "qcl-negf-release-v1", "release_id": "release-a", "ready": True,
                        "application_path": "/nix/store/application", "solver_executable": "/nix/store/solver/bin/qcl-negf"}
            (root / "release.json").write_text(json.dumps(expected))
            gate = root / "admission.json"
            gate.write_text(json.dumps({"release_id": "release-a", "open": True}))
            calls = []
            ready = False

            def run(args):
                calls.append(args)
                if args[0] == "ssh":
                    actual = CONTROLLER if "controller" in args[-2] else WORKER
                    if args[-1].endswith(" identity"):
                        return json.dumps(actual)
                    if " check " in args[-1]:
                        return json.dumps({"schema": "qcl-negf-node-release-check-v1", "node_identity": actual,
                                           "release": {**expected, "ready": ready}})
                return ""

            with patch.object(self.ops.release, "load_enrollment", lambda _: {"registry": registry(), "registry_sha256": "e" * 64, "known_hosts_bytes": b"synthetic"}), \
                 patch.object(self.ops.release, "observe_node_identity", lambda **_: CONTROLLER), \
                 patch.object(self.ops.release, "freeze_ssh_trust", lambda *a, **k: TRUST):
                with self.assertRaisesRegex(ValueError, "verification"):
                    self.ops.startup("worker", "admin@worker.invalid", enrollment="/synthetic/enrollment.json", runtime=root, gate=gate, run=run)
                self.assertFalse(any("State=RESUME" in args for args in calls))
                ready = True
                self.ops.startup("worker", "admin@worker.invalid", enrollment="/synthetic/enrollment.json", runtime=root, gate=gate, run=run)
                self.assertIn("State=RESUME", calls[-1])


if __name__ == "__main__":
    unittest.main()
