"""Pure admission policy; no SSH, hypervisor, services or builds."""
import copy
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("build_admission", Path(__file__).parents[1] / "ops/build_admission.py")
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)


def snapshot():
    return {
        "schema": "qcl-build-admission.v1",
        "captured_at": 1000,
        "complete_host_inventory": True,
        "host": {"memory_total_mib": 65536, "memory_available_mib": 50000, "logical_cpus": 32},
        "roles": {"builder": 709, "pnetlab": 201, "control": 712, "compute": 713},
        "vms": [
            {"vm_id": 709, "status": "running", "memory_mib": 8192, "vcpus": 4},
            {"vm_id": 201, "status": "running", "memory_mib": 8192, "vcpus": 8},
        ],
        "idle": {"build_jobs": 0, "nix_builds": 0, "runner_jobs": 0},
        "queue": {"status": "undeployed", "jobs": 0},
    }


class BuildAdmissionTests(unittest.TestCase):
    def test_snapshot_fifo_refused_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "snapshot"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, "regular"):
                admission.read_snapshot(fifo)

    def test_snapshot_oversize_refused_before_json_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            with path.open("wb") as stream:
                stream.truncate(1024 * 1024 + 1)
            with self.assertRaisesRegex(ValueError, "1 MiB"):
                admission.read_snapshot(path)

    def test_initial_install_requires_both_roles_absent(self):
        accepted = admission.admit(snapshot(), "burst", now=1010)
        self.assertEqual(accepted["profile"], "burst")
        self.assertEqual(accepted["planned_guest_memory_mib"], 32768)
        self.assertEqual(accepted["required_available_memory_mib"], 32768)
        partial = snapshot()
        partial["vms"].append({"vm_id": 712, "status": "stopped", "memory_mib": 6144, "vcpus": 4})
        with self.assertRaisesRegex(ValueError, "queue"):
            admission.admit(partial, "burst", now=1010)

    def test_deployed_queue_must_be_read_successfully_and_empty(self):
        value = snapshot()
        value["vms"].extend([
            {"vm_id": 712, "status": "running", "memory_mib": 6144, "vcpus": 4},
            {"vm_id": 713, "status": "stopped", "memory_mib": 28672, "vcpus": 12},
        ])
        for status, jobs in [("unreachable", 0), ("read", 1), ("undeployed", 0)]:
            bad = copy.deepcopy(value)
            bad["queue"] = {"status": status, "jobs": jobs}
            with self.assertRaisesRegex(ValueError, "queue"):
                admission.admit(bad, "burst", now=1010)
        value["queue"] = {"status": "read", "jobs": 0}
        admission.admit(value, "burst", now=1010)

    def test_burst_rejects_running_compute(self):
        value = snapshot()
        value["vms"].append({"vm_id": 713, "status": "running", "memory_mib": 28672, "vcpus": 12})
        with self.assertRaisesRegex(ValueError, "compute"):
            admission.admit(value, "burst", now=1010)

    def test_rejects_any_active_build(self):
        for activity in ("build_jobs", "nix_builds", "runner_jobs"):
            value = snapshot()
            value["idle"][activity] = 1
            with self.assertRaisesRegex(ValueError, "idle"):
                admission.admit(value, "burst", now=1010)

    def test_reserves_host_and_pnetlab_growth(self):
        low = snapshot()
        low["host"]["memory_available_mib"] = 32767
        with self.assertRaisesRegex(ValueError, "available"):
            admission.admit(low, "burst", now=1010)
        too_large = snapshot()
        too_large["vms"][1]["memory_mib"] = 8193
        with self.assertRaisesRegex(ValueError, "pnetlab"):
            admission.admit(too_large, "burst", now=1010)

    def test_budgets_other_running_guests_and_cpu(self):
        value = snapshot()
        value["vms"].append({"vm_id": 800, "status": "running", "memory_mib": 32768, "vcpus": 1})
        with self.assertRaisesRegex(ValueError, "memory budget"):
            admission.admit(value, "burst", now=1010)
        value = snapshot()
        value["host"]["logical_cpus"] = 20
        with self.assertRaisesRegex(ValueError, "CPU budget"):
            admission.admit(value, "burst", now=1010)

    def test_rejects_stale_future_incomplete_or_duplicate_inventory(self):
        for now in (999, 1061):
            with self.assertRaisesRegex(ValueError, "fresh"):
                admission.admit(snapshot(), "burst", now=now)
        value = snapshot()
        value["complete_host_inventory"] = False
        with self.assertRaisesRegex(ValueError, "complete"):
            admission.admit(value, "burst", now=1010)
        value = snapshot()
        value["vms"].append(value["vms"][0])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            admission.admit(value, "burst", now=1010)

    def test_standard_uses_shared_profile_and_also_requires_idle(self):
        accepted = admission.admit(snapshot(), "standard", now=1010)
        self.assertEqual(accepted["planned_guest_memory_mib"], 16384)
        self.assertEqual(accepted["required_available_memory_mib"], 16384)
        self.assertEqual(accepted["planned_guest_vcpus"], 12)


if __name__ == "__main__":
    unittest.main()
