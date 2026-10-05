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


def production_snapshot():
    value = snapshot()
    value["temporary_bootstrap"] = True
    value["builder_memory"] = {"resident_anonymous_mib": 8192, "source": "RssAnon", "vm_id": 709, "pid": 1234}
    return value


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

    def test_local_debug_admits_small_unchanged_resource_budget(self):
        accepted = admission.admit(snapshot(), "local-debug", now=1010)
        self.assertEqual(accepted["planned_guest_memory_mib"], 16384)
        self.assertEqual(accepted["planned_guest_vcpus"], 12)

    def test_production_bootstrap_allows_shared_cpus_without_guest_oversizing(self):
        value = production_snapshot()
        value["host"]["memory_available_mib"] = 60000
        accepted = admission.admit(value, "production-build", now=1010,
                                   resources={"vcpus": 32, "memory_mib": 49152})
        self.assertEqual(accepted["planned_guest_vcpus"], 40)
        self.assertEqual(accepted["planned_guest_memory_mib"], 57344)
        self.assertEqual(accepted["required_available_memory_mib"], 57600)
        self.assertTrue(accepted["shared_host_cpus"])
        self.assertEqual(accepted["builder_resources"]["memory_max"], "47104M")
        self.assertEqual(accepted["builder_resources"]["cpu_quota"], "3200%")

    def test_production_resources_need_explicit_temporary_bootstrap(self):
        with self.assertRaisesRegex(ValueError, "temporary bootstrap"):
            admission.admit(snapshot(), "production-build", now=1010,
                            resources={"vcpus": 24, "memory_mib": 32768})

    def test_dynamic_profile_requires_complete_integer_resources(self):
        value = production_snapshot()
        for resources in (None, {}, {"vcpus": 32}, {"vcpus": True, "memory_mib": 49152},
                          {"vcpus": 0, "memory_mib": 49152}, {"vcpus": 32, "memory_mib": 2048},
                          {"vcpus": 32, "memory_mib": 49152, "ignored": 1}):
            with self.subTest(resources=resources), self.assertRaises(ValueError):
                admission.admit(value, "production-build", now=1010, resources=resources)
        with self.assertRaisesRegex(ValueError, "only production-build"):
            admission.admit(value, "standard", now=1010,
                            resources={"vcpus": 32, "memory_mib": 49152})

    def test_production_shared_cpu_exception_never_weakens_memory_or_physical_cpu_gate(self):
        value = production_snapshot()
        for cpus, memory, expected in ((33, 32768, "host CPU"), (32, 50176, "memory budget"),
                                       (32, 49152, "available")):
            bad = copy.deepcopy(value)
            if expected == "available":
                bad["host"]["memory_available_mib"] = 57343
            with self.subTest(cpus=cpus, memory=memory), self.assertRaisesRegex(ValueError, expected):
                admission.admit(bad, "production-build", now=1010,
                                resources={"vcpus": cpus, "memory_mib": memory})

    def test_production_rejects_compute_activity_queue_and_running_builds(self):
        value = production_snapshot()
        for reason in ("compute", "queue", "idle", "fresh"):
            bad = copy.deepcopy(value)
            now = 1010
            if reason == "compute":
                bad["vms"].append({"vm_id": 713, "status": "running", "memory_mib": 4096, "vcpus": 2})
            elif reason == "queue":
                bad["vms"].append({"vm_id": 712, "status": "stopped", "memory_mib": 4096, "vcpus": 2})
                bad["queue"] = {"status": "read", "jobs": 1}
            elif reason == "idle":
                bad["idle"]["nix_builds"] = 1
            else:
                now = 1061
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                admission.admit(bad, "production-build", now=now,
                                resources={"vcpus": 24, "memory_mib": 32768})

    def test_production_credit_uses_anonymous_resident_not_unused_configured_maximum(self):
        value = production_snapshot()
        value["vms"][0]["memory_mib"] = 24576
        value["host"]["memory_available_mib"] = 37132
        value["builder_memory"]["resident_anonymous_mib"] = 20192
        accepted = admission.admit(value, "production-build", now=1010,
                                   resources={"vcpus": 32, "memory_mib": 39936})
        self.assertEqual(accepted["builder_memory_credit_mib"], 19936)
        self.assertEqual(accepted["required_available_memory_mib"], 36384)
        with self.assertRaisesRegex(ValueError, "available"):
            admission.admit(value, "production-build", now=1010,
                            resources={"vcpus": 32, "memory_mib": 40960})

    def test_production_rejects_missing_wrong_owner_or_raw_rss_measurement(self):
        for measurement in (None, {"rss_mib": 8192},
                            {"resident_anonymous_mib": 8192, "source": "VmRSS", "vm_id": 709, "pid": 1234},
                            {"resident_anonymous_mib": 8192, "source": "RssAnon", "vm_id": 710, "pid": 1234},
                            {"resident_anonymous_mib": 8192, "source": "RssAnon", "vm_id": 709, "pid": 0}):
            value = production_snapshot()
            value["builder_memory"] = measurement
            with self.subTest(measurement=measurement), self.assertRaisesRegex(ValueError, "measurement|anonymous|owner|PID"):
                admission.admit(value, "production-build", now=1010,
                                resources={"vcpus": 24, "memory_mib": 32768})

    def test_production_credit_caps_oversized_measurement_and_stopped_builder_gets_zero(self):
        value = production_snapshot()
        value["builder_memory"]["resident_anonymous_mib"] = 10000
        accepted = admission.admit(value, "production-build", now=1010,
                                   resources={"vcpus": 24, "memory_mib": 32768})
        self.assertEqual(accepted["builder_memory_credit_mib"], 7936)
        value["vms"][0]["status"] = "stopped"
        value["builder_memory"] = {"resident_anonymous_mib": 0, "source": "stopped", "vm_id": 709, "pid": None}
        accepted = admission.admit(value, "production-build", now=1010,
                                   resources={"vcpus": 24, "memory_mib": 32768})
        self.assertEqual(accepted["builder_memory_credit_mib"], 0)


if __name__ == "__main__":
    unittest.main()
