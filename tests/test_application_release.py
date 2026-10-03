"""Exercise release activation at the Nix/SSH/systemd command boundary.

No services, SSH connections, solver or Nix closures are built by these tests.
The real activation writes profiles/configuration, guards jobs and gates the pool.
"""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
import sys
from unittest.mock import patch

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
        if "self-check" in args:
            return json.dumps({"schema": "qcl-negf-self-check-v1", "status": "completed",
                               "scientific_accepted": False})
        return ""


class InitialCommands(Commands):
    """Simulate only Nix/Slurm; publication and profile identity checks stay real."""
    def __init__(self):
        super().__init__()
        self.queue = ""
        self.evidence = {"/nix/store/application": {"narHash": HASH},
                         "/nix/store/solver": {"narHash": HASH}}

    def __call__(self, args):
        result = super().__call__(args)
        if args[0] == "squeue":
            return self.queue
        if args[:3] == ["nix", "path-info", "--json"]:
            return json.dumps(self.evidence)
        if args[0] not in ("nix-store", "nix-env", "nix", "squeue"):
            raise AssertionError("Initial preparation must not run services, Code creation or solver")
        return result


def release():
    return {"schema": "qcl-negf-release-v1", "release_id": "release-a",
            "application_path": "/nix/store/application",
            "solver_executable": "/nix/store/solver/bin/qcl-negf"}


HASH = "sha256-" + "A" * 43 + "="
OTHER_HASH = "sha256-" + "B" * 43 + "="


def delivery_manifest(cache=True):
    value = {**release(), "closures": [{"path": "/nix/store/application", "narHash": HASH},
                                       {"path": "/nix/store/solver", "narHash": HASH}]}
    if cache:
        value["cache_uri"] = "https://cache.example.invalid"
    return value


POOL = {"nodes": [{"name": "controller", "target": "admin@controller", "role": "controller"},
                  {"name": "worker", "target": "admin@worker", "role": "worker"}]}


class DeliveryCommands:
    """Only local command boundaries are simulated; gate writes stay real."""
    def __init__(self, gate):
        self.gate = gate
        self.calls = []
        self.failure = False
        self.evidence = {"/nix/store/application": {"narHash": HASH},
                         "/nix/store/solver": {"narHash": HASH}}
        self.prefetch_gate_snapshots = []

    def __call__(self, args):
        self.calls.append(args)
        if args[:3] == ["nix", "copy", "--from"]:
            self.prefetch_gate_snapshots.append(self.gate.read_bytes())
            if self.failure:
                raise RuntimeError("cache fetch failed")
        if args[:3] == ["nix", "path-info", "--json"]:
            self.prefetch_gate_snapshots.append(self.gate.read_bytes())
            return self.evidence if isinstance(self.evidence, str) else json.dumps(self.evidence)
        if args[0] == "ssh" and " check " in args[-1]:
            return json.dumps({**release(), "ready": True})
        return ""


class ApplicationReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ops = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(cls.ops)

    def test_root_squashed_shared_gate_is_read_as_scientific_owner_without_relaxing_guards(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, run = Path(temporary), InitialCommands()
            gate, record = root / "gate", root / "runtime/release.json"
            record.parent.mkdir()
            record.write_text(json.dumps({**release(), "ready": False}))
            gate.write_text(json.dumps({"open": False, "release_id": "release-a"}))
            (root / "profile").symlink_to("/nix/store/application")
            credentials = {"uid": 0, "gid": 42}
            reads, original_read = [], Path.read_bytes
            original_text = Path.read_text
            def nfs_read(path):
                if path == gate:
                    reads.append(dict(credentials))
                    if credentials != {"uid": 3000, "gid": 3000}:
                        raise PermissionError("root_squash denies mode0750 jobs traversal")
                return original_read(path)
            def nfs_text(path, *args, **kwargs):
                return nfs_read(path).decode() if path == gate else original_text(path, *args, **kwargs)
            def change_uid(value):
                credentials["uid"] = value
            def change_gid(value):
                credentials["gid"] = value
            with patch.object(self.ops, "GATE", gate), \
                 patch.object(self.ops.os, "geteuid", lambda: credentials["uid"]), \
                 patch.object(self.ops.os, "getegid", lambda: credentials["gid"]), \
                 patch.object(self.ops.os, "seteuid", change_uid), \
                 patch.object(self.ops.os, "setegid", change_gid), \
                 patch.object(self.ops.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=3000, pw_gid=3000)), \
                 patch.object(Path, "read_bytes", nfs_read), patch.object(Path, "read_text", nfs_text):
                try:
                    self.ops.node_check(record, gate, root / "profile", run=run)
                    with self.assertRaisesRegex(ValueError, "closed"):
                        self.ops.guard("release-a", "/nix/store/solver/bin/qcl-negf", record, gate)
                    self.ops.prepare_initial(release(), profile=root / "profile", runtime=record.parent,
                        gate=gate, role="worker", run=run)
                except PermissionError as error:
                    self.fail("Shared gate must be read with UID3000 authority: " + str(error))
            self.assertTrue(reads)
            self.assertEqual(credentials, {"uid": 0, "gid": 42})

    def test_shared_gate_read_restores_credentials_after_missing_or_permission_error(self):
        self.assertTrue(callable(getattr(self.ops, "read_admission", None)))
        with tempfile.TemporaryDirectory() as temporary:
            gate = Path(temporary) / "gate"
            credentials = {"uid": 0, "gid": 42}
            def denied(path):
                self.assertEqual(path, gate)
                self.assertEqual(credentials, {"uid": 3000, "gid": 3000})
                raise PermissionError("NFS read denied")
            with patch.object(self.ops, "GATE", gate), \
                 patch.object(self.ops.os, "geteuid", lambda: credentials["uid"]), \
                 patch.object(self.ops.os, "getegid", lambda: credentials["gid"]), \
                 patch.object(self.ops.os, "seteuid", lambda value: credentials.update(uid=value)), \
                 patch.object(self.ops.os, "setegid", lambda value: credentials.update(gid=value)), \
                 patch.object(self.ops.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=3000, pw_gid=3000)):
                self.assertIsNone(self.ops.read_admission(gate, missing=True))
                self.assertEqual(credentials, {"uid": 0, "gid": 42})
                with patch.object(Path, "read_bytes", denied):
                    with self.assertRaises(PermissionError):
                        self.ops.read_admission(gate, missing=True)
                self.assertEqual(credentials, {"uid": 0, "gid": 42})

    def test_custom_gate_and_nonroot_reader_do_not_change_credentials(self):
        self.assertTrue(callable(getattr(self.ops, "read_admission", None)))
        with tempfile.TemporaryDirectory() as temporary:
            gate = Path(temporary) / "gate"
            gate.write_text('{"open":false,"release_id":"release-a"}')
            for uid, production_gate in ((0, self.ops.GATE), (3000, gate)):
                with self.subTest(uid=uid), patch.object(self.ops, "GATE", production_gate), \
                     patch.object(self.ops.os, "geteuid", lambda: uid), \
                     patch.object(self.ops.os, "seteuid", side_effect=AssertionError("Unexpected credential change")), \
                     patch.object(self.ops.os, "setegid", side_effect=AssertionError("Unexpected credential change")):
                    self.assertEqual(json.loads(self.ops.read_admission(gate)),
                        {"open": False, "release_id": "release-a"})

    def test_initial_controller_prepares_closed_identity_before_worker_role_switch(self):
        self.assertTrue(callable(getattr(self.ops, "prepare_initial", None)),
                        "Missing closed initial preparation phase")
        with tempfile.TemporaryDirectory() as temporary:
            root, run = Path(temporary), InitialCommands()
            profile, runtime, gate = root / "profile", root / "runtime", root / "admission.json"
            result = self.ops.prepare_initial(delivery_manifest(False), profile=profile,
                runtime=runtime, gate=gate, role="controller", run=run)
            self.assertEqual(result, {**release(), "ready": False})
            self.assertEqual(json.loads(gate.read_text()), {"open": False, "release_id": "release-a"})
            self.assertEqual(profile.resolve(), Path("/nix/store/application"))
            self.assertEqual((root / "profile-solver").resolve(), Path("/nix/store/solver"))
            self.assertEqual(json.loads((runtime / "release.json").read_text()), result)
            self.assertEqual((runtime / "service.env").read_text(),
                "QCL_NEGF_RELEASE_ID=release-a\nQCL_NEGF_SOLVER_EXECUTABLE=/nix/store/solver/bin/qcl-negf\n"
                + "QCL_NEGF_RELEASE_GATE=" + str(gate) + "\n")
            self.assertEqual(self.ops.bootstrap_selection(runtime / "release.json", "seed", "seed"),
                ("/nix/store/solver/bin/qcl-negf", "qcl-negf-release-a"))
            self.assertIn(["squeue", "--all", "--noheader", "--format", "%i"], run.calls)
            self.assertFalse(any(args[:2] == ["nix", "copy"] for args in run.calls))
            self.ops.node_check(runtime / "release.json", gate, profile, run=run)
            with self.assertRaisesRegex(ValueError, "closed"):
                self.ops.guard("release-a", "/nix/store/solver/bin/qcl-negf", runtime / "release.json", gate)
            gate.write_text(json.dumps({"open": True, "release_id": "release-a"}))
            with self.assertRaisesRegex(ValueError, "ready"):
                self.ops.guard("release-a", "/nix/store/solver/bin/qcl-negf", runtime / "release.json", gate)

    def test_initial_worker_requires_controller_gate_and_does_not_publish_one(self):
        self.assertTrue(callable(getattr(self.ops, "prepare_initial", None)))
        with tempfile.TemporaryDirectory() as temporary:
            root, run = Path(temporary), InitialCommands()
            arguments = dict(profile=root / "profile", runtime=root / "runtime",
                             gate=root / "gate", role="worker", run=run)
            with self.assertRaisesRegex(ValueError, "gate|controller"):
                self.ops.prepare_initial(release(), **arguments)
            self.assertEqual(list(root.iterdir()), [])
            self.assertEqual(run.calls, [])
            (root / "gate").write_text(json.dumps({"open": False, "release_id": "release-a"}))
            gate_bytes = (root / "gate").read_bytes()
            self.ops.prepare_initial(release(), **arguments)
            self.assertEqual((root / "gate").read_bytes(), gate_bytes)
            self.assertFalse(any(args[0] == "squeue" for args in run.calls))

    def test_repeated_initial_preparation_preserves_pending_and_ready_provenance(self):
        self.assertTrue(callable(getattr(self.ops, "prepare_initial", None)))
        for ready in (False, True):
            with self.subTest(ready=ready), tempfile.TemporaryDirectory() as temporary:
                root, run = Path(temporary), InitialCommands()
                arguments = dict(profile=root / "profile", runtime=root / "runtime",
                                 gate=root / "gate", role="controller", run=run)
                self.ops.prepare_initial(release(), **arguments)
                record = root / "runtime/release.json"
                preserved = {**release(), "ready": ready, "code_uuid": "existing-code",
                             "provenance": {"receipt": "original-health-evidence"}}
                record.write_text(json.dumps(preserved, indent=2) + "\n")
                paths = [record, root / "runtime/service.env", root / "gate"]
                before = [(path.read_bytes(), path.stat().st_mtime_ns) for path in paths]
                run.calls.clear()
                result = self.ops.prepare_initial(release(), **arguments)
                self.assertEqual(result, preserved)
                self.assertEqual([(path.read_bytes(), path.stat().st_mtime_ns) for path in paths], before)
                self.assertEqual(run.calls, [["nix-store", "--verify-path", "/nix/store/application", "/nix/store/solver"]])

    def test_initial_conflicts_refuse_before_any_state_or_profile_mutation(self):
        self.assertTrue(callable(getattr(self.ops, "prepare_initial", None)))
        conflicts = ("open-gate", "wrong-gate", "wrong-runtime", "wrong-application", "wrong-solver")
        for conflict in conflicts:
            with self.subTest(conflict=conflict), tempfile.TemporaryDirectory() as temporary:
                root, run = Path(temporary), InitialCommands()
                arguments = dict(profile=root / "profile", runtime=root / "runtime",
                                 gate=root / "gate", role="controller", run=run)
                self.ops.prepare_initial(release(), **arguments)
                if conflict in ("open-gate", "wrong-gate"):
                    (root / "gate").write_text(json.dumps({"open": conflict == "open-gate",
                        "release_id": "other" if conflict == "wrong-gate" else "release-a"}))
                elif conflict == "wrong-runtime":
                    (root / "runtime/release.json").write_text(json.dumps({**release(), "release_id": "other", "ready": False}))
                else:
                    profile = root / ("profile" if conflict == "wrong-application" else "profile-solver")
                    profile.unlink()
                    profile.symlink_to("/nix/store/other")
                original = {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}
                links = {str(path.relative_to(root)): str(path.readlink()) for path in root.rglob("*") if path.is_symlink()}
                run.calls.clear()
                with self.assertRaises(ValueError):
                    self.ops.prepare_initial(release(), **arguments)
                self.assertEqual({str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}, original)
                self.assertEqual({str(path.relative_to(root)): str(path.readlink()) for path in root.rglob("*") if path.is_symlink()}, links)
                self.assertEqual(run.calls, [])

    def test_initial_bad_closure_or_hash_leaves_prior_identity_and_gate_unchanged(self):
        self.assertTrue(callable(getattr(self.ops, "prepare_initial", None)))
        for failure in ("closure", "hash"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root, run = Path(temporary), InitialCommands()
                arguments = dict(profile=root / "profile", runtime=root / "runtime",
                                 gate=root / "gate", role="controller", run=run)
                self.ops.prepare_initial(release(), **arguments)
                paths = [root / "runtime/release.json", root / "runtime/service.env", root / "gate"]
                original = [path.read_bytes() for path in paths]
                run.calls.clear()
                if failure == "closure":
                    run.failure = "--verify-path"
                else:
                    run.evidence["/nix/store/solver"]["narHash"] = OTHER_HASH
                with self.assertRaises((RuntimeError, ValueError)):
                    self.ops.prepare_initial(delivery_manifest(), **arguments)
                self.assertEqual([path.read_bytes() for path in paths], original)
                self.assertFalse(any(args[0] in ("nix-env", "squeue") or args[:2] == ["nix", "copy"] for args in run.calls))

    def test_first_initial_controller_refuses_jobs_before_creating_gate_or_profiles(self):
        self.assertTrue(callable(getattr(self.ops, "prepare_initial", None)))
        with tempfile.TemporaryDirectory() as temporary:
            root, run = Path(temporary), InitialCommands()
            run.queue = "123\n"
            with self.assertRaisesRegex(RuntimeError, "jobs|queued"):
                self.ops.prepare_initial(release(), profile=root / "profile", runtime=root / "runtime",
                    gate=root / "gate", role="controller", run=run)
            self.assertEqual(list(root.iterdir()), [])
            self.assertFalse(any(args[0] == "nix-env" for args in run.calls))

    def test_initial_controller_does_not_recreate_deleted_gate_for_existing_identity(self):
        self.assertTrue(callable(getattr(self.ops, "prepare_initial", None)))
        with tempfile.TemporaryDirectory() as temporary:
            root, run = Path(temporary), InitialCommands()
            arguments = dict(profile=root / "profile", runtime=root / "runtime",
                             gate=root / "gate", role="controller", run=run)
            self.ops.prepare_initial(release(), **arguments)
            (root / "gate").unlink()
            record = (root / "runtime/release.json").read_bytes()
            run.calls.clear()
            with self.assertRaisesRegex(ValueError, "gate|initial"):
                self.ops.prepare_initial(release(), **arguments)
            self.assertFalse((root / "gate").exists())
            self.assertEqual((root / "runtime/release.json").read_bytes(), record)
            self.assertEqual(run.calls, [])

    def test_initial_malformed_existing_runtime_is_never_treated_as_absent(self):
        for current in (None, False, [], {**release()}, {**release(), "ready": 1}):
            with self.subTest(current=current), tempfile.TemporaryDirectory() as temporary:
                root, run = Path(temporary), InitialCommands()
                runtime, gate = root / "runtime", root / "gate"
                runtime.mkdir()
                record = runtime / "release.json"
                record.write_text(json.dumps(current))
                gate.write_text(json.dumps({"open": False, "release_id": "release-a"}))
                original = record.read_bytes(), gate.read_bytes()
                with self.assertRaises(ValueError):
                    self.ops.prepare_initial(release(), profile=root / "profile", runtime=runtime,
                        gate=gate, role="controller", run=run)
                self.assertEqual((record.read_bytes(), gate.read_bytes()), original)
                self.assertFalse((root / "profile").is_symlink())
                self.assertEqual(run.calls, [])

    def test_initial_gate_changed_during_closure_verification_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            gate = root / "gate"
            gate.write_text(json.dumps({"open": False, "release_id": "release-a"}))
            def racing_run(args):
                self.assertEqual(args, ["nix-store", "--verify-path", "/nix/store/application", "/nix/store/solver"])
                gate.write_text(json.dumps({"open": True, "release_id": "other"}))
                return ""
            with self.assertRaisesRegex(ValueError, "gate.*changed"):
                self.ops.prepare_initial(release(), profile=root / "profile", runtime=root / "runtime",
                    gate=gate, role="worker", run=racing_run)
            self.assertEqual(json.loads(gate.read_text()), {"open": True, "release_id": "other"})
            self.assertFalse((root / "runtime").exists())
            self.assertFalse((root / "profile").is_symlink())

    def test_cli_initial_phase_runs_real_preparation_with_activation_lock(self):
        self.assertTrue(callable(getattr(self.ops, "prepare_initial", None)))
        with tempfile.TemporaryDirectory() as temporary:
            root, run = Path(temporary), InitialCommands()
            source = root / "manifest.json"
            source.write_text(json.dumps(release()))
            prepare = self.ops.prepare_initial
            def initial(value, **kwargs):
                import fcntl
                with (root / "runtime/activation.lock").open("w") as competing:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(competing, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return prepare(value, profile=root / "profile", run=run, **kwargs)
            args = ["qcl-negf-release", "prepare-initial", "--manifest", str(source),
                    "--role", "controller", "--runtime", str(root / "runtime"), "--gate", str(root / "gate")]
            with patch.object(sys, "argv", args), patch.object(self.ops, "prepare_initial", initial), patch("builtins.print"):
                self.ops.main()
            self.assertEqual(json.loads((root / "runtime/release.json").read_text()), {**release(), "ready": False})
            self.assertFalse(json.loads((root / "gate").read_text())["open"])

    def test_controller_fetches_and_checks_both_hashes_before_closing_admission(self):
        with tempfile.TemporaryDirectory() as temporary:
            gate = Path(temporary) / "admission.json"
            gate.write_text(json.dumps({"open": True, "release_id": "old"}))
            original = gate.read_bytes()
            run = DeliveryCommands(gate)
            with patch.object(self.ops, "publish_admission", lambda _path, value: self.ops.publish_json(gate, value)):
                report = self.ops.deliver_cli(delivery_manifest(), POOL, run=run)
            self.assertTrue(report["open"])
            self.assertEqual(run.calls[:2], [
                ["nix", "copy", "--from", "https://cache.example.invalid", "/nix/store/application", "/nix/store/solver"],
                ["nix", "path-info", "--json", "/nix/store/application", "/nix/store/solver"]])
            self.assertEqual(run.prefetch_gate_snapshots, [original, original])
            self.assertEqual(run.calls[2][:2], ["systemctl", "stop"])

    def test_cache_fetch_failure_leaves_gate_and_services_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            gate = Path(temporary) / "admission.json"
            gate.write_text(json.dumps({"open": True, "release_id": "old"}))
            original, run = gate.read_bytes(), DeliveryCommands(gate)
            run.failure = True
            with patch.object(self.ops, "publish_admission", lambda _path, value: self.ops.publish_json(gate, value)):
                with self.assertRaisesRegex(RuntimeError, "cache fetch"):
                    self.ops.deliver_cli(delivery_manifest(), POOL, run=run)
            self.assertEqual(gate.read_bytes(), original)
            self.assertFalse(any(args[0] in ("systemctl", "scontrol", "ssh") for args in run.calls))

    def test_hash_mismatch_missing_paths_or_malformed_evidence_does_not_quiesce(self):
        evidence = ["malformed", [], {}, {"/nix/store/application": {"narHash": HASH}},
                    {"/nix/store/solver": {"narHash": HASH}},
                    {"/nix/store/application": {"narHash": OTHER_HASH}, "/nix/store/solver": {"narHash": HASH}},
                    [{"path": "/nix/store/application", "narHash": HASH}, {"path": "/nix/store/application", "narHash": HASH}],
                    {"/nix/store/application": None, "/nix/store/solver": {"narHash": HASH}}]
        for value in evidence:
            with self.subTest(evidence=value), tempfile.TemporaryDirectory() as temporary:
                gate = Path(temporary) / "admission.json"
                gate.write_text(json.dumps({"open": True, "release_id": "old"}))
                original, run = gate.read_bytes(), DeliveryCommands(gate)
                run.evidence = value
                with patch.object(self.ops, "publish_admission", lambda _path, value: self.ops.publish_json(gate, value)):
                    with self.assertRaisesRegex(ValueError, "closure|hash|evidence"):
                        self.ops.deliver_cli(delivery_manifest(), POOL, run=run)
                self.assertEqual(gate.read_bytes(), original)
                self.assertFalse(any(args[0] in ("systemctl", "scontrol", "ssh") for args in run.calls))

    def test_manifest_without_cache_uri_verifies_local_closures_before_quiesce(self):
        with tempfile.TemporaryDirectory() as temporary:
            gate = Path(temporary) / "admission.json"
            gate.write_text(json.dumps({"open": True, "release_id": "old"}))
            original, run = gate.read_bytes(), DeliveryCommands(gate)
            run.evidence = [{"path": path, **value} for path, value in run.evidence.items()]
            with patch.object(self.ops, "publish_admission", lambda _path, value: self.ops.publish_json(gate, value)):
                self.ops.deliver_cli(delivery_manifest(False), POOL, run=run)
            self.assertEqual(run.calls[0][:3], ["nix", "path-info", "--json"])
            self.assertFalse(any(args[:3] == ["nix", "copy", "--from"] for args in run.calls))
            self.assertEqual(run.prefetch_gate_snapshots, [original])

    def test_invalid_cache_argument_or_absent_manifest_hashes_refuses_before_commands(self):
        for cache in (None, "", " ", "-option", "https://cache.invalid\n--option", "https://cache.invalid path",
                      "https://user:password@cache.invalid", 123, True):
            value = delivery_manifest()
            value["cache_uri"] = cache
            with self.subTest(cache=cache), tempfile.TemporaryDirectory() as temporary:
                gate = Path(temporary) / "admission.json"
                gate.write_text("unchanged")
                run = DeliveryCommands(gate)
                with patch.object(self.ops, "publish_admission", lambda _path, value: self.ops.publish_json(gate, value)):
                    with self.assertRaisesRegex(ValueError, "cache"):
                        self.ops.deliver_cli(value, POOL, run=run)
                self.assertEqual(gate.read_text(), "unchanged")
                self.assertEqual(run.calls, [])
        calls = []
        with self.assertRaisesRegex(ValueError, "closure"):
            self.ops.deliver_cli(release(), POOL, run=lambda args: calls.append(args))
        self.assertEqual(calls, [])

    def test_malformed_manifest_closure_inventory_refuses_before_commands(self):
        for inventory in ([], [{"path": "/nix/store/application", "narHash": HASH}],
                          [{"path": ["invalid"], "narHash": HASH}, {"path": "/nix/store/solver", "narHash": HASH}],
                          [{"path": "/nix/store/application", "narHash": "invalid"},
                           {"path": "/nix/store/solver", "narHash": HASH}]):
            with self.subTest(inventory=inventory):
                value = delivery_manifest()
                value["closures"] = inventory
                calls = []
                with self.assertRaisesRegex(ValueError, "closure"):
                    self.ops.deliver_cli(value, POOL, run=lambda args: calls.append(args))
                self.assertEqual(calls, [])

    def test_cli_keeps_operational_cache_and_closure_fields_for_controller_prefetch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, pool = root / "release.json", root / "pool.json"
            source.write_text(json.dumps(delivery_manifest()))
            pool.write_text(json.dumps(POOL))
            observed = []
            def deliver(value, selected_pool):
                observed.append((value, selected_pool))
                return {"open": True}
            args = ["qcl-negf-release", "deliver", "--manifest", str(source), "--pool", str(pool),
                    "--runtime", str(root / "runtime")]
            with patch.object(sys, "argv", args), patch.object(self.ops, "deliver_cli", deliver), patch("builtins.print"):
                self.ops.main()
            self.assertEqual(observed, [(delivery_manifest(), POOL)])

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

    def test_malformed_remote_identity_is_reported_per_node(self):
        for response in (None, []):
            with self.subTest(response=response), tempfile.TemporaryDirectory() as temporary:
                gate = Path(temporary) / "admission.json"
                report = self.ops.deliver_pool(release(), ["worker"], gate, quiesce=lambda: None,
                    deliver=lambda _n, _m: response)
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

    def test_identical_controller_delivery_recovers_services_stopped_for_maintenance(self):
        class StatefulCommands(Commands):
            def __init__(self):
                super().__init__()
                self.active = set()

            def __call__(self, args):
                result = super().__call__(args)
                if args[:2] in (["systemctl", "start"], ["systemctl", "restart"]):
                    self.active.update(args[2:])
                elif args[:2] == ["systemctl", "stop"]:
                    self.active.difference_update(args[2:])
                elif args[:3] == ["systemctl", "is-active", "--quiet"]:
                    if not set(args[3:]) <= self.active:
                        raise RuntimeError("controller services stopped")
                return result

        with tempfile.TemporaryDirectory() as temporary:
            root, commands = Path(temporary), StatefulCommands()
            arguments = dict(profile=root / "profile", runtime=root / "runtime",
                             role="controller", email="test@example.invalid", run=commands,
                             allowed_codes_file=root / "code-uuid")
            first = self.ops.activate(release(), **arguments)
            commands(["systemctl", "stop", "qcl-negf-aiida.service", "qcl-negf-api.service"])
            before = len([call for call in commands.calls if call[0] == "nix-env"])
            self.assertEqual(self.ops.activate(release(), **arguments), first)
            self.assertEqual(len([call for call in commands.calls if call[0] == "nix-env"]), before)

    def test_one_failed_controller_unit_cannot_publish_ready(self):
        class OrHealthCommands(Commands):
            def __call__(self, args):
                result = super().__call__(args)
                if args[:3] == ["systemctl", "is-active", "--quiet"]:
                    # Actual systemctl succeeds if ANY requested unit is active.
                    if "qcl-negf-aiida.service" not in args[3:]:
                        raise RuntimeError("required API unit inactive")
                return result

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "API unit inactive"):
                self.ops.activate(release(), profile=root / "profile", runtime=root / "runtime",
                    role="controller", email="test@example.invalid", run=OrHealthCommands(),
                    allowed_codes_file=root / "code-uuid")
            self.assertIsNot(json.loads((root / "runtime/release.json").read_text()).get("ready"), True)

    def test_failed_pinned_solver_self_check_cannot_publish_ready(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, commands = Path(temporary), Commands()
            commands.failure = "self-check"
            with self.assertRaisesRegex(RuntimeError, "injected"):
                self.ops.activate(release(), profile=root / "profile", runtime=root / "runtime",
                                  role="worker", run=commands)
            self.assertIsNot(json.loads((root / "runtime/release.json").read_text()).get("ready"), True)

    def test_health_executes_pinned_solver_as_scientific_user_with_finite_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, commands = Path(temporary), Commands()
            self.ops.activate(release(), profile=root / "profile", runtime=root / "runtime",
                              role="worker", run=commands)
            call = next(call for call in commands.calls if "self-check" in call)
            self.assertEqual(call[:3], ["timeout", "--kill-after=10s", "300s"])
            self.assertIn("qcl-negf", call)
            self.assertEqual(call[-2:], ["/nix/store/solver/bin/qcl-negf", "self-check"])

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
