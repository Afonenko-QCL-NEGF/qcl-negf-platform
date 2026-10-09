"""Independent synthetic enrollment facts; never read production namespace/identity."""
import copy
import base64
import hashlib
import os
import shlex
import stat
from contextlib import ExitStack
from types import SimpleNamespace
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "ops"))
import application_release as ops

CONTROLLER = {"schema": "qcl-negf-node-identity-v1", "role": "controller", "hostname": "controller.invalid",
              "node_name": None, "machine_uuid": "11111111-1111-1111-1111-111111111111",
              "machine_id": "1" * 32, "boot_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}
WORKER = {"schema": "qcl-negf-node-identity-v1", "role": "worker", "hostname": "worker.invalid",
          "node_name": "worker", "machine_uuid": "22222222-2222-2222-2222-222222222222",
          "machine_id": "2" * 32, "boot_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}
SECOND = {"schema": "qcl-negf-node-identity-v1", "role": "worker", "hostname": "second.invalid",
          "node_name": "second", "machine_uuid": "33333333-3333-3333-3333-333333333333",
          "machine_id": "3" * 32, "boot_id": "cccccccc-cccc-cccc-cccc-cccccccccccc"}
ENROLL_IDS = ("10000000-0000-0000-0000-000000000001", "20000000-0000-0000-0000-000000000002",
              "30000000-0000-0000-0000-000000000003")
TRUST = {"path": "/protected/snapshots/fixture/known_hosts", "sha256": "d" * 64}

def registry():
    return {"schema": "qcl-negf-node-enrollment-v1", "inventory_id": "99999999-9999-9999-9999-999999999999",
            "known_hosts_file": "/protected/known_hosts", "nodes": [
        {"enrollment_id": ENROLL_IDS[0], "name": "controller", "role": "controller", "hostname": "controller.invalid",
         "node_name": None, "machine_uuid": CONTROLLER["machine_uuid"], "machine_id": CONTROLLER["machine_id"],
         "primary_target": "admin@controller.invalid", "targets": ["admin@controller.invalid", "admin@controller-alias.invalid"]},
        {"enrollment_id": ENROLL_IDS[1], "name": "worker", "role": "worker", "hostname": "worker.invalid",
         "node_name": "worker", "machine_uuid": WORKER["machine_uuid"], "machine_id": WORKER["machine_id"],
         "targets": ["admin@worker.invalid", "admin@worker-alias.invalid"]},
        {"enrollment_id": ENROLL_IDS[2], "name": "second", "role": "worker", "hostname": "second.invalid",
         "node_name": "second", "machine_uuid": SECOND["machine_uuid"], "machine_id": SECOND["machine_id"],
         "targets": ["admin@second.invalid"]}]}

def pool():
    return {"schema": "qcl-negf-active-pool-v2", "nodes": [
        {"name": "controller", "role": "controller", "target": "admin@controller.invalid", "enrollment_id": ENROLL_IDS[0]},
        {"name": "worker", "role": "worker", "target": "admin@worker.invalid", "enrollment_id": ENROLL_IDS[1]},
        {"name": "second", "role": "worker", "target": "admin@second.invalid", "enrollment_id": ENROLL_IDS[2]}]}

def selected_context():
    records = registry()["nodes"]
    return {"schema": "qcl-negf-controller-authority-v1", "registry": registry(),
            "registry_sha256": "e" * 64, "controller_binding": {**records[0], "target": "admin@controller.invalid"},
            "local_identity": dict(CONTROLLER), "remote_identity": dict(CONTROLLER),
            "trust_snapshot": dict(TRUST), "used_output_bytes": 0,
            "bindings": tuple({**record, "target": record["targets"][0]} for record in records)}


def manifest_fixture():
    digest = "sha256-" + "A" * 43 + "="
    return {"schema": "qcl-negf-release-v1", "release_id": "release-a",
            "application_path": "/nix/store/application", "solver_executable": "/nix/store/solver/bin/qcl-negf",
            "closures": [{"path": "/nix/store/application", "narHash": digest},
                         {"path": "/nix/store/solver", "narHash": digest}]}


class SyntheticCommands:
    def __init__(self, *, mismatch=None):
        self.calls = []
        self.kwargs = []
        self.mismatch = mismatch
        self.copy_started = False
        self.observations = {"admin@controller.invalid": dict(CONTROLLER),
                             "admin@controller-alias.invalid": dict(CONTROLLER),
                             "admin@worker.invalid": dict(WORKER),
                             "admin@worker-alias.invalid": dict(WORKER),
                             "admin@second.invalid": dict(SECOND)}
    def __call__(self, args, **kwargs):
        self.calls.append(args)
        self.kwargs.append(kwargs)
        if args[0] == "ssh":
            actual = dict(self.observations[args[-2]])
            remote = shlex.split(args[-1])
            if remote[-1] == "identity":
                if self.mismatch == "boot_after_copy" and self.copy_started and actual["role"] == "worker":
                    actual["boot_id"] = CONTROLLER["boot_id"]
                return json.dumps(actual)
            if "activate" in remote:
                return ""
            if "check" in remote:
                if self.mismatch == "legacy":
                    return json.dumps({**manifest_fixture(), "ready": True})
                if self.mismatch == "partial":
                    return '{"schema":'
                return json.dumps({"schema": "qcl-negf-node-release-check-v1", "node_identity": actual,
                                   "release": {**manifest_fixture(), "ready": True, "code_uuid": "synthetic-code"}})
            raise AssertionError("Unexpected synthetic SSH action")
        if args[:3] == ["nix", "path-info", "--json"]:
            return json.dumps({item["path"]: {"narHash": item["narHash"]} for item in manifest_fixture()["closures"]})
        if args[:3] == ["nix", "copy", "--to"]:
            self.copy_started = True
            return ""
        if args[0] in ("systemctl", "scontrol", "squeue") or args[:3] == ["nix", "copy", "--from"]:
            return ""
        raise AssertionError("Unexpected real boundary: " + args[0])


class FakeProtectedFS:
    """Handwritten syscall/inode facts; /tmp is never represented as trusted."""
    def __init__(self):
        self.nodes = {"/": {"mode": stat.S_IFDIR | 0o755, "uid": 0},
                      "/protected": {"mode": stat.S_IFDIR | 0o700, "uid": 0},
                      "/protected/snapshots": {"mode": stat.S_IFDIR | 0o700, "uid": 0},
                      "/protected/known_hosts": {"mode": stat.S_IFREG | 0o600, "uid": 0, "bytes": b"independent synthetic key bytes"}}
        self.fds = {}
        self.serial = 9
        self.opens = []
        self.syncs = []
    def open(self, path, flags, mode=0o777, *, dir_fd=None):
        path = str(path)
        if dir_fd is not None:
            path = self.fds[dir_fd]["path"].rstrip("/") + "/" + path
        self.opens.append((path, flags, dir_fd))
        node = self.nodes.get(path)
        if node is not None and stat.S_ISLNK(node["mode"]):
            raise OSError("Synthetic symlink rejected by O_NOFOLLOW")
        if flags & os.O_CREAT:
            if node is not None and flags & os.O_EXCL:
                raise FileExistsError(path)
            node = {"mode": stat.S_IFREG | mode, "uid": 0, "bytes": b""}
            self.nodes[path] = node
        if node is None:
            raise FileNotFoundError(path)
        if flags & os.O_DIRECTORY and not stat.S_ISDIR(node["mode"]):
            raise NotADirectoryError(path)
        self.serial += 1
        self.fds[self.serial] = {"path": path, "position": 0}
        return self.serial
    def fstat(self, fd):
        node = self.nodes[self.fds[fd]["path"]]
        return SimpleNamespace(st_uid=node["uid"], st_mode=node["mode"])
    def read(self, fd, size):
        handle = self.fds[fd]
        raw = self.nodes[handle["path"]]["bytes"]
        result = raw[handle["position"]:handle["position"] + size]
        handle["position"] += len(result)
        return result
    def write(self, fd, raw):
        node = self.nodes[self.fds[fd]["path"]]
        node["bytes"] += bytes(raw)
        return len(raw)
    def mkdir(self, name, mode, *, dir_fd):
        self.nodes[self.fds[dir_fd]["path"].rstrip("/") + "/" + name] = {"mode": stat.S_IFDIR | mode, "uid": 0}
    def close(self, fd):
        del self.fds[fd]
    def fsync(self, fd):
        self.syncs.append(self.fds[fd]["path"])
    def patches(self):
        stack = ExitStack()
        for name in ("open", "fstat", "read", "write", "mkdir", "close", "fsync"):
            stack.enter_context(patch.object(ops.os, name, getattr(self, name)))
        return stack


class EnrollmentTests(unittest.TestCase):
    def test_duplicate_routes_enrollment_and_permanent_clones_are_rejected(self):
        for change in ("target", "enrollment", "uuid", "machine_id"):
            r, p = registry(), pool()
            if change == "target":
                p["nodes"][2]["target"] = p["nodes"][1]["target"]
            elif change == "enrollment":
                p["nodes"][2]["enrollment_id"] = p["nodes"][1]["enrollment_id"]
            elif change == "uuid":
                r["nodes"][2]["machine_uuid"] = r["nodes"][1]["machine_uuid"]
            else:
                r["nodes"][2]["machine_id"] = r["nodes"][1]["machine_id"]
            with self.subTest(change=change), self.assertRaises(ValueError):
                ops.validate_enrollment(p, r)

    def test_observed_wrong_node_machine_role_and_boot_are_not_ready(self):
        binding = {**registry()["nodes"][1], "target": "admin@worker.invalid"}
        for key, value in (("node_name", "other"), ("role", "controller"),
                           ("machine_uuid", SECOND["machine_uuid"]), ("boot_id", SECOND["boot_id"])):
            with self.subTest(key=key), self.assertRaises(ValueError):
                ops.bind_node_observation(binding, {**WORKER, key: value}, prior_boot=WORKER["boot_id"])

    def test_local_wrong_controller_fails_before_snapshot_remote_or_lock(self):
        calls = []
        snapshot = []
        loaded = {"registry": registry(), "registry_sha256": "e" * 64, "known_hosts_bytes": b"synthetic host-key bytes"}
        with patch.object(ops, "load_enrollment", lambda _: loaded), \
             patch.object(ops, "observe_node_identity", lambda **_: WORKER), \
             patch.object(ops, "freeze_ssh_trust", lambda *a, **k: snapshot.append(True)):
            with self.assertRaises(ValueError):
                ops.preflight_controller_authority("/protected/enrollment.json", pool(),
                    run=lambda args: calls.append(args) or "", deadline=10**12,
                    command_timeout_seconds=7, command_output_bytes=16384, delivery_output_bytes=32768)
        self.assertEqual(calls, [])
        self.assertEqual(snapshot, [])

    def test_protected_ancestors_and_snapshot_have_independent_syscall_evidence(self):
        fs = FakeProtectedFS()
        original = fs.nodes["/protected/known_hosts"]["bytes"]
        with fs.patches():
            self.assertEqual(ops.read_protected_file("/protected/known_hosts"), original)
            frozen = ops.freeze_ssh_trust(original, snapshot_root="/protected/snapshots")
            self.assertEqual(fs.nodes[frozen["path"]]["bytes"], original)
            self.assertEqual(frozen["sha256"], hashlib.sha256(original).hexdigest())
            self.assertEqual(fs.nodes[frozen["path"]]["mode"] & 0o777, 0o600)
            fs.nodes["/protected/known_hosts"]["bytes"] = b"substituted source bytes"
            self.assertEqual(fs.nodes[frozen["path"]]["bytes"], original)
            self.assertIn(frozen["path"], fs.syncs)
            self.assertTrue(all(flags & os.O_NOFOLLOW for _, flags, _ in fs.opens))
        for unsafe in (stat.S_IFDIR | 0o777, stat.S_IFLNK | 0o777):
            fs = FakeProtectedFS()
            fs.nodes["/protected"]["mode"] = unsafe
            with fs.patches(), self.assertRaises((ValueError, OSError)):
                ops.read_protected_file("/protected/known_hosts")
            with fs.patches(), self.assertRaises((ValueError, OSError)):
                ops.freeze_ssh_trust(original, snapshot_root="/protected/snapshots")
        for path in ("relative", "/protected/../known_hosts", "/protected//known_hosts"):
            with self.assertRaises(ValueError):
                ops.read_protected_file(path)

    def test_remote_wrong_controller_boot_and_local_change_fail_before_runtime(self):
        for mismatch in ("machine", "boot", "local_change"):
            run = SyntheticCommands()
            if mismatch == "machine":
                run.observations["admin@controller.invalid"] = dict(WORKER)
            if mismatch == "boot":
                run.observations["admin@controller.invalid"]["boot_id"] = WORKER["boot_id"]
            counter = [0]
            def observe(**kwargs):
                counter[0] += 1
                return {**CONTROLLER, "boot_id": WORKER["boot_id"]} if mismatch == "local_change" and counter[0] > 1 else CONTROLLER
            with patch.object(ops, "load_enrollment", lambda _: {"registry": registry(), "registry_sha256": "e" * 64, "known_hosts_bytes": b"synthetic"}), \
                 patch.object(ops, "observe_node_identity", observe), \
                 patch.object(ops, "freeze_ssh_trust", lambda *a, **k: TRUST), tempfile.TemporaryDirectory() as temporary:
                runtime = Path(temporary) / "not-created"
                with self.assertRaises(ValueError):
                    ops.deliver_cli(manifest_fixture(), pool(), run=run, enrollment="/protected/registry.json", runtime=runtime)
                self.assertFalse(runtime.exists())
                self.assertTrue(all(args[0] == "ssh" and shlex.split(args[-1])[-1] == "identity" for args in run.calls))

    def test_unresolved_local_precheck_precedes_snapshot_and_remote(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary)
            attempts = runtime / "delivery-attempts"
            attempts.mkdir()
            (attempts / "old.json").write_text(json.dumps({"status": "failed", "requires_reconciliation": True}))
            gate = runtime / "gate"
            gate.write_bytes(b"prior gate bytes")
            run, snapshots = SyntheticCommands(), []
            with patch.object(ops, "load_enrollment", lambda _: {"registry": registry(), "registry_sha256": "e" * 64, "known_hosts_bytes": b"synthetic"}), \
                 patch.object(ops, "observe_node_identity", lambda **_: CONTROLLER), \
                 patch.object(ops, "freeze_ssh_trust", lambda *a, **k: snapshots.append(True)):
                with self.assertRaisesRegex(RuntimeError, "reconciliation"):
                    ops.deliver_cli(manifest_fixture(), pool(), run=run, enrollment="/protected/registry.json", runtime=runtime, gate=gate)
            self.assertEqual(run.calls, [])
            self.assertEqual(snapshots, [])
            self.assertEqual(gate.read_bytes(), b"prior gate bytes")

    def test_positive_fleet_uses_frozen_trust_and_exact_final_bindings(self):
        run = SyntheticCommands()
        reads = []
        def loaded(path):
            reads.append(path)
            return {"registry": registry(), "registry_sha256": "e" * 64, "known_hosts_bytes": b"synthetic"}
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(ops, "load_enrollment", loaded), \
             patch.object(ops, "observe_node_identity", lambda **_: CONTROLLER), \
             patch.object(ops, "freeze_ssh_trust", lambda *a, **k: TRUST), patch.object(ops, "command", run):
            runtime, gate = Path(temporary) / "runtime", Path(temporary) / "gate"
            gate.write_text(json.dumps({"open": True, "release_id": "old"}))
            result = ops.deliver_cli(manifest_fixture(), pool(), run=run, enrollment="/protected/registry.json", runtime=runtime, gate=gate)
            self.assertTrue(result["open"])
            self.assertEqual(result["nodes"]["controller"]["identity"]["code_uuid"], "synthetic-code")
            resume = [args for args in run.calls if "State=RESUME" in args]
            self.assertEqual([args[2] for args in resume], ["NodeName=worker", "NodeName=second"])
            first_mutation = next(i for i, args in enumerate(run.calls) if args[0] == "systemctl")
            before = run.calls[:first_mutation]
            self.assertTrue(all(any(args[0] == "ssh" and args[-2] == target for args in before)
                                for target in ("admin@controller.invalid", "admin@worker.invalid", "admin@second.invalid")))
            for args, kwargs in zip(run.calls, run.kwargs):
                if args[0] == "ssh":
                    self.assertIn("-oUserKnownHostsFile=" + TRUST["path"], args)
                    self.assertIn("-oGlobalKnownHostsFile=/dev/null", args)
                if args[:2] == ["nix", "copy"]:
                    self.assertIn(TRUST["path"], kwargs["env"]["NIX_SSHOPTS"])
            self.assertEqual(reads, ["/protected/registry.json"])
            receipt = json.loads(Path(result["receipt"]).read_text())
            self.assertEqual(receipt["controller_authority"]["trust_snapshot"], TRUST)
            self.assertEqual(receipt["manifest"], manifest_fixture())

    def test_initial_wrong_worker_node_and_alias_leave_gate_unchanged(self):
        for mismatch in ("node", "alias"):
            run = SyntheticCommands()
            run.observations["admin@worker.invalid"] = {**WORKER, "node_name": "other"} if mismatch == "node" else dict(SECOND)
            with tempfile.TemporaryDirectory() as temporary, \
                 patch.object(ops, "load_enrollment", lambda _: {"registry": registry(), "registry_sha256": "e" * 64, "known_hosts_bytes": b"synthetic"}), \
                 patch.object(ops, "observe_node_identity", lambda **_: CONTROLLER), \
                 patch.object(ops, "freeze_ssh_trust", lambda *a, **k: TRUST):
                runtime, gate = Path(temporary) / "runtime", Path(temporary) / "gate"
                gate.write_bytes(b"unchanged original admission")
                with self.assertRaises(ValueError):
                    ops.deliver_cli(manifest_fixture(), pool(), run=run, enrollment="/protected/registry.json", runtime=runtime, gate=gate)
                self.assertEqual(gate.read_bytes(), b"unchanged original admission")
                self.assertTrue(all(args[0] == "ssh" for args in run.calls))

    def test_legacy_partial_and_post_copy_boot_drift_keep_failed_closed(self):
        for mismatch in ("legacy", "partial", "boot_after_copy"):
            run = SyntheticCommands(mismatch=mismatch)
            with tempfile.TemporaryDirectory() as temporary, \
                 patch.object(ops, "load_enrollment", lambda _: {"registry": registry(), "registry_sha256": "e" * 64, "known_hosts_bytes": b"synthetic"}), \
                 patch.object(ops, "observe_node_identity", lambda **_: CONTROLLER), \
                 patch.object(ops, "freeze_ssh_trust", lambda *a, **k: TRUST):
                runtime, gate = Path(temporary) / "runtime", Path(temporary) / "gate"
                gate.write_text(json.dumps({"open": True, "release_id": "old"}))
                result = ops.deliver_cli(manifest_fixture(), pool(), run=run, enrollment="/protected/registry.json", runtime=runtime, gate=gate)
                self.assertFalse(result["open"])
                self.assertTrue(result["requires_reconciliation"])
                self.assertFalse(json.loads(gate.read_text())["open"])
                self.assertFalse(any("State=RESUME" in args for args in run.calls))

    def test_bound_activate_rejects_identity_before_runtime_or_commands(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(ops, "observe_node_identity", lambda **_: SECOND):
            runtime = Path(temporary) / "not-created"
            calls = []
            with self.assertRaises(ValueError):
                ops.activate(manifest_fixture(), expected_node_identity=WORKER, runtime=runtime,
                             run=lambda args: calls.append(args) or "")
            self.assertFalse(runtime.exists())
            self.assertEqual(calls, [])

    def test_direct_pool_cannot_admit_release_only_or_without_authority(self):
        expected = ops.manifest(manifest_fixture())
        binding = {**registry()["nodes"][1], "identity": WORKER}
        with tempfile.TemporaryDirectory() as temporary, patch.object(ops, "observe_node_identity", lambda **_: CONTROLLER):
            gate = Path(temporary) / "gate"
            gate.write_text("original")
            with self.assertRaises(ValueError):
                ops.deliver_pool(expected, ["worker"], gate, bindings={"worker": binding},
                                 deliver=lambda *a: {**expected, "ready": True}, quiesce=lambda: None)
            self.assertEqual(gate.read_text(), "original")
            result = ops.deliver_pool(expected, ["worker"], gate, authority=selected_context(), bindings={"worker": binding},
                                     deliver=lambda *a: {**expected, "ready": True}, quiesce=lambda: None)
            self.assertFalse(result["open"])
            self.assertTrue(result["requires_reconciliation"])

    def test_readonly_observer_rejects_unsupported_slurmd_without_expected_echo(self):
        files = {"/etc/qcl-negf/release-config.json": json.dumps({"role": "worker", "slurm_conf": "/protected/slurm.conf"}).encode(),
                 "/sys/class/dmi/id/product_uuid": WORKER["machine_uuid"].encode(), "/etc/machine-id": WORKER["machine_id"].encode(),
                 "/proc/sys/kernel/random/boot_id": WORKER["boot_id"].encode(), "/protected/slurm.conf": b"independent synthetic static configuration",
                 "/proc/42/cmdline": b"/nix/store/slurm/bin/slurmd\0-D\0-s\0", "/proc/42/environ": b"SLURM_CONF=/protected/slurm.conf\0"}
        invocation = "f" * 32
        def system(args):
            if args[0] == "systemctl":
                return "MainPID=42\nInvocationID=" + invocation + "\nEnvironment=SLURM_CONF=/protected/slurm.conf"
            if args[0] == "env":
                return "NodeName=worker"
            raise AssertionError("Unexpected observer boundary")
        with patch.object(ops, "local_metadata", lambda path, limit=16384: files[str(path)]), \
             patch.object(ops.socket, "gethostname", lambda: "worker.invalid"), patch.object(ops, "slurmd_pids", lambda: [42]):
            self.assertEqual(ops.observe_node_identity(run=system), WORKER)
            for args in (b"/slurmd\0-Nother\0", b"/slurmd\0-Z\0", b"/slurmd\0-f/other\0"):
                files["/proc/42/cmdline"] = args
                with self.assertRaisesRegex(ValueError, "Unsupported"):
                    ops.observe_node_identity(run=system)
            with self.assertRaises(ValueError):
                ops.observe_node_identity(run=system, controller_only=True)

    def test_missing_legacy_and_declared_alias_conflicts_dispatch_nothing(self):
        for case in ("missing", "legacy", "same_enrollment_alias"):
            run, snapshots = SyntheticCommands(), []
            p = pool()
            if case == "legacy":
                p.pop("schema")
            if case == "same_enrollment_alias":
                p["nodes"][2] = {**p["nodes"][1], "target": "admin@worker-alias.invalid", "name": "second"}
            def loaded(_):
                if case == "missing":
                    raise FileNotFoundError("synthetic missing inventory")
                return {"registry": registry(), "registry_sha256": "e" * 64, "known_hosts_bytes": b"synthetic"}
            with tempfile.TemporaryDirectory() as temporary, patch.object(ops, "load_enrollment", loaded), \
                 patch.object(ops, "observe_node_identity", lambda **_: CONTROLLER), \
                 patch.object(ops, "freeze_ssh_trust", lambda *a, **k: snapshots.append(True)):
                with self.assertRaises((ValueError, FileNotFoundError)):
                    ops.deliver_cli(manifest_fixture(), p, run=run, enrollment="/protected/registry.json", runtime=Path(temporary) / "runtime")
            self.assertEqual(run.calls, [])
            self.assertEqual(snapshots, [])

    def test_wrong_local_cli_does_not_create_runtime_or_flock_or_read_unresolved(self):
        calls, snapshots, unresolved = [], [], []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, selected = root / "manifest.json", root / "pool.json"
            source.write_text(json.dumps(manifest_fixture()))
            selected.write_text(json.dumps(pool()))
            runtime = root / "not-created"
            args = ["release", "deliver", "--manifest", str(source), "--pool", str(selected),
                    "--enrollment", "/protected/registry.json", "--runtime", str(runtime)]
            with patch.object(sys, "argv", args), patch.object(ops, "load_enrollment", lambda _: {"registry": registry(), "registry_sha256": "e" * 64, "known_hosts_bytes": b"synthetic"}), \
                 patch.object(ops, "observe_node_identity", lambda **_: WORKER), \
                 patch.object(ops, "freeze_ssh_trust", lambda *a, **k: snapshots.append(True)), \
                 patch.object(ops, "unresolved_deliveries", lambda _: unresolved.append(True)), \
                 patch.object(ops.fcntl, "flock", lambda *a: calls.append("lock")), patch("builtins.print"):
                with self.assertRaises(SystemExit) as caught:
                    ops.main()
            self.assertEqual(caught.exception.code, 1)
            self.assertFalse(runtime.exists())
            self.assertEqual(calls + snapshots + unresolved, [])

    def test_bound_release_check_before_after_boot_is_required(self):
        from test_application_release import Commands
        with tempfile.TemporaryDirectory() as temporary:
            root, run = Path(temporary), Commands()
            runtime = root / "runtime"
            runtime.mkdir()
            value = {**ops.manifest(manifest_fixture()), "ready": True, "code_uuid": "preserved-code"}
            (runtime / "release.json").write_text(json.dumps(value))
            (root / "profile").symlink_to("/nix/store/application")
            (root / "profile-solver").symlink_to("/nix/store/solver")
            with patch.object(ops, "observe_node_identity", lambda **_: WORKER):
                result = ops.check(value, runtime=runtime, profile=root / "profile", run=run, expected_node_identity=WORKER)
            self.assertEqual(result, {"schema": "qcl-negf-node-release-check-v1", "node_identity": WORKER, "release": value})
            observations = iter((WORKER, {**WORKER, "boot_id": SECOND["boot_id"]}))
            with patch.object(ops, "observe_node_identity", lambda **_: next(observations)), self.assertRaises(ValueError):
                ops.check(value, runtime=runtime, profile=root / "profile", run=run, expected_node_identity=WORKER)

    def test_startup_requires_local_authority_and_bound_worker_before_resume(self):
        import worker_lifecycle as worker
        for case in ("wrong_local", "wrong_worker", "success", "legacy"):
            run = SyntheticCommands(mismatch="legacy" if case == "legacy" else None)
            if case == "wrong_worker":
                run.observations["admin@worker.invalid"] = dict(SECOND)
            with tempfile.TemporaryDirectory() as temporary, \
                 patch.object(ops, "load_enrollment", lambda _: {"registry": registry(), "registry_sha256": "e" * 64, "known_hosts_bytes": b"synthetic"}), \
                 patch.object(ops, "observe_node_identity", lambda **_: WORKER if case == "wrong_local" else CONTROLLER), \
                 patch.object(ops, "freeze_ssh_trust", lambda *a, **k: TRUST):
                runtime, gate = Path(temporary), Path(temporary) / "gate"
                (runtime / "release.json").write_text(json.dumps({**ops.manifest(manifest_fixture()), "ready": True}))
                gate.write_text(json.dumps({"open": True, "release_id": "release-a"}))
                if case == "success":
                    actual = worker.startup("worker", "admin@worker.invalid", enrollment="/protected/registry.json", runtime=runtime, gate=gate, run=run)
                    self.assertTrue(actual["ready"])
                    self.assertEqual(sum("State=RESUME" in args for args in run.calls), 1)
                else:
                    with self.assertRaises(ValueError):
                        worker.startup("worker", "admin@worker.invalid", enrollment="/protected/registry.json", runtime=runtime, gate=gate, run=run)
                    self.assertFalse(any("State=RESUME" in args for args in run.calls))
                    if case == "wrong_local":
                        self.assertEqual(run.calls, [])
                    if case == "wrong_worker":
                        self.assertTrue(all(args[0] == "ssh" for args in run.calls))
                    if case == "legacy":
                        self.assertFalse(json.loads(gate.read_text())["open"])
                        before = list(run.calls)
                        with self.assertRaises(RuntimeError):
                            worker.startup("worker", "admin@worker.invalid", enrollment="/protected/registry.json", runtime=runtime, gate=gate, run=run)
                        self.assertEqual(before, run.calls)

    def test_source_trust_substitution_does_not_change_late_transport_snapshot(self):
        fs = FakeProtectedFS()
        original = b"independent synthetic key bytes"
        with fs.patches():
            verified = ops.read_protected_file("/protected/known_hosts")
            frozen = ops.freeze_ssh_trust(verified, snapshot_root="/protected/snapshots")
        opened_source = sum(path == "/protected/known_hosts" for path, _, _ in fs.opens)
        run = SyntheticCommands()
        def transport(args, **kwargs):
            fs.nodes["/protected/known_hosts"]["bytes"] = b"late source substitution"
            if args[0] == "ssh":
                self.assertIn("-oUserKnownHostsFile=" + frozen["path"], args)
            if args[:2] == ["nix", "copy"]:
                self.assertIn(frozen["path"], kwargs["env"]["NIX_SSHOPTS"])
            self.assertEqual(fs.nodes[frozen["path"]]["bytes"], original)
            self.assertEqual(frozen["sha256"], hashlib.sha256(original).hexdigest())
            return run(args, **kwargs)
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(ops, "load_enrollment", lambda _: {"registry": registry(), "registry_sha256": "e" * 64, "known_hosts_bytes": original}), \
             patch.object(ops, "observe_node_identity", lambda **_: CONTROLLER), \
             patch.object(ops, "freeze_ssh_trust", lambda *a, **k: frozen), patch.object(ops, "command", transport):
            runtime, gate = Path(temporary) / "runtime", Path(temporary) / "gate"
            gate.write_text(json.dumps({"open": True, "release_id": "old"}))
            result = ops.deliver_cli(manifest_fixture(), pool(), run=transport, enrollment="/protected/registry.json", runtime=runtime, gate=gate)
            self.assertTrue(result["open"])
        self.assertEqual(sum(path == "/protected/known_hosts" for path, _, _ in fs.opens), opened_source)
        self.assertNotEqual(fs.nodes["/protected/known_hosts"]["bytes"], original)

    def test_authority_probe_cost_is_in_same_delivery_deadline_and_output_budget(self):
        for cost in ("time", "output"):
            run = SyntheticCommands()
            clock = [100.0]
            def bounded_cost(args):
                result = run(args)
                if args[0] == "ssh":
                    clock[0] += .8
                return result
            with tempfile.TemporaryDirectory() as temporary, \
                 patch.object(ops, "load_enrollment", lambda _: {"registry": registry(), "registry_sha256": "e" * 64, "known_hosts_bytes": b"synthetic"}), \
                 patch.object(ops, "observe_node_identity", lambda **_: CONTROLLER), \
                 patch.object(ops, "freeze_ssh_trust", lambda *a, **k: TRUST), \
                 patch.object(ops.time, "monotonic", lambda: clock[0]):
                runtime, gate = Path(temporary) / "runtime", Path(temporary) / "gate"
                gate.write_bytes(b"unchanged gate")
                with self.assertRaises((ValueError, ops.CommandFailure)):
                    ops.deliver_cli(manifest_fixture(), pool(), run=bounded_cost, enrollment="/protected/registry.json", runtime=runtime, gate=gate,
                                    delivery_timeout_seconds=3 if cost == "time" else 1800,
                                    delivery_output_bytes=600 if cost == "output" else 8388608)
                self.assertEqual(gate.read_bytes(), b"unchanged gate")
                self.assertTrue(all(args[0] == "ssh" for args in run.calls))
                self.assertLessEqual(len(run.calls), 4)

    def test_cli_remote_activation_binding_precedes_its_own_runtime_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "manifest.json"
            source.write_text(json.dumps(manifest_fixture()))
            encoded = base64.urlsafe_b64encode(json.dumps(WORKER).encode()).decode()
            runtime = root / "not-created"
            args = ["release", "activate", "--manifest", str(source), "--expected-node-identity-base64", encoded,
                    "--runtime", str(runtime)]
            locks = []
            with patch.object(sys, "argv", args), patch.object(ops, "observe_node_identity", lambda **_: SECOND), \
                 patch.object(ops.fcntl, "flock", lambda *a: locks.append(True)):
                with self.assertRaises(ValueError):
                    ops.main()
            self.assertFalse(runtime.exists())
            self.assertEqual(locks, [])

    def test_first_target_drift_after_quiesce_stops_all_later_dispatch(self):
        # Literal independent facts distinguish pre-copy drift before ANY copy.
        before = {"schema": "qcl-negf-node-identity-v1", "role": "worker", "hostname": "worker.invalid",
                  "node_name": "worker", "machine_uuid": "22222222-2222-2222-2222-222222222222",
                  "machine_id": "22222222222222222222222222222222",
                  "boot_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}
        for key, value in (("boot_id", "dddddddd-dddd-dddd-dddd-dddddddddddd"),
                           ("machine_uuid", "44444444-4444-4444-4444-444444444444"),
                           ("node_name", "changed-worker")):
            with self.subTest(drift=key), tempfile.TemporaryDirectory() as temporary:
                run = SyntheticCommands()
                state = {"maintenance": False, "failure_index": None}
                def drift_after_quiesce(args):
                    result = run(args)
                    if args[:2] == ["systemctl", "stop"]:
                        state["maintenance"] = True
                    if (state["maintenance"] and args[0] == "ssh" and args[-2] == "admin@worker.invalid"
                            and args[-1].endswith(" identity")):
                        state["failure_index"] = len(run.calls)
                        return json.dumps({**before, key: value})
                    return result
                selected = pool()
                selected["nodes"] = [selected["nodes"][1], selected["nodes"][0], selected["nodes"][2]]
                runtime, gate = Path(temporary) / "runtime", Path(temporary) / "gate"
                gate.write_text(json.dumps({"open": True, "release_id": "old"}))
                with patch.object(ops, "load_enrollment", lambda _: {"registry": registry(), "registry_sha256": "e" * 64, "known_hosts_bytes": b"synthetic"}), \
                     patch.object(ops, "observe_node_identity", lambda **_: CONTROLLER), \
                     patch.object(ops, "freeze_ssh_trust", lambda *a, **k: TRUST):
                    result = ops.deliver_cli(manifest_fixture(), selected, run=drift_after_quiesce,
                        enrollment="/protected/registry.json", runtime=runtime, gate=gate)
                    self.assertTrue(state["maintenance"])
                    self.assertTrue(result["requires_reconciliation"])
                    self.assertEqual(result["remote_outcome"], "unknown")
                    self.assertEqual(result["nodes"]["worker"]["status"], "failed")
                    self.assertEqual(result["nodes"]["controller"]["status"], "not_attempted")
                    self.assertEqual(result["nodes"]["second"]["status"], "not_attempted")
                    self.assertFalse(json.loads(gate.read_text())["open"])
                    self.assertEqual(run.calls[state["failure_index"]:], [])
                    self.assertFalse(any(args[:3] == ["nix", "copy", "--to"] or "State=RESUME" in args or
                                         (args[0] == "ssh" and (" activate " in args[-1] or " check " in args[-1]))
                                         for args in run.calls))
                    receipt = json.loads(Path(result["receipt"]).read_text())
                    self.assertEqual(receipt["status"], "failed")
                    self.assertTrue(receipt["requires_reconciliation"])
                    self.assertEqual(receipt["node_bindings"]["worker"], before)
                    calls_before = list(run.calls)
                    with self.assertRaisesRegex(RuntimeError, "reconciliation"):
                        ops.deliver_cli(manifest_fixture(), selected, run=drift_after_quiesce,
                            enrollment="/protected/registry.json", runtime=runtime, gate=gate)
                    self.assertEqual(run.calls, calls_before)

if __name__ == "__main__":
    unittest.main()
