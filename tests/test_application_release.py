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
import os
import signal
import time
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

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.runtime = Path(temporary.name) / "runtime"
        self.gate = Path(temporary.name) / "gate"


    def test_native_bounded_prefix_and_retained_descendant_pipe(self):
        for parent_exits in (False, True):
            with self.subTest(parent_exits=parent_exits):
                pidfile = self.runtime.parent / "pid"
                code = ("import os,time; p=os.fork(); "
                        "open(" + repr(str(pidfile)) + ", 'w').write(str(os.getpid())) if p==0 else None; "
                        "print('prefix',flush=True); " +
                        ("os._exit(0) if p else time.sleep(10)" if parent_exits else "time.sleep(10)"))
                start = time.monotonic()
                try:
                    with self.assertRaises(self.ops.CommandFailure) as caught:
                        self.ops.command([sys.executable, "-c", code], timeout_seconds=.8,
                                         cleanup_seconds=.2, output_bytes=4096)
                    self.assertLess(time.monotonic() - start, 1.5)
                    record = caught.exception.record
                    self.assertIn("prefix", record["stdout"])
                    self.assertTrue(record["cleanup_confirmed"])
                    if pidfile.exists():
                        pid = int(pidfile.read_text())
                        stat = Path("/proc") / str(pid) / "stat"
                        acknowledged = time.monotonic() + .2
                        while stat.exists() and stat.read_text().split()[2] not in ("Z", "X") and time.monotonic() < acknowledged:
                            time.sleep(.005)
                        self.assertTrue(not stat.exists() or stat.read_text().split()[2] in ("Z", "X"))
                finally:
                    if pidfile.exists():
                        try:
                            os.kill(int(pidfile.read_text()), signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        pidfile.unlink()

    def test_native_combined_cap_nonzero_and_finite_validation(self):
        with self.assertRaises(self.ops.CommandFailure) as caught:
            self.ops.command([sys.executable, "-c",
                "import os,time; os.write(1,b'x'*3000); os.write(2,b'y'*3000); time.sleep(10)"],
                timeout_seconds=1, cleanup_seconds=.2, output_bytes=4096)
        record = caught.exception.record
        self.assertEqual(record["failure"], "output_limit")
        self.assertLessEqual(len(record["stdout"].encode()) + len(record["stderr"].encode()), 4096)
        with self.assertRaises(self.ops.CommandFailure) as caught:
            self.ops.command([sys.executable, "-c", "import sys; print('bad',file=sys.stderr); sys.exit(7)"],
                             timeout_seconds=1, cleanup_seconds=.2)
        self.assertEqual(caught.exception.record["returncode"], 7)
        self.assertIn("bad", caught.exception.record["stderr"])
        for value in (True, float('nan'), float('inf'), 0):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.ops.command([sys.executable], timeout_seconds=value)

    def test_uncertain_activation_receipt_blocks_retry(self):
        self.gate.write_text(json.dumps({"open": True, "release_id": "old"}))
        run = DeliveryCommands(self.gate)
        def loss(args):
            result = run(args)
            if args[0] == "ssh" and " activate " in args[-1]:
                raise self.ops.CommandFailure({"failure": "nonzero", "returncode": 255,
                    "stdout": "partial", "stderr": "lost", "child_started": True,
                    "cleanup_confirmed": True, "elapsed_seconds": .1, "output_truncated": False})
            return result
        result = self.ops.deliver_cli(delivery_manifest(), POOL, run=loss,
                                     runtime=self.runtime, gate=self.gate)
        self.assertTrue(result["requires_reconciliation"])
        self.assertFalse(json.loads(self.gate.read_text())["open"])
        self.assertEqual(result["nodes"]["worker"]["status"], "not_attempted")
        receipt = json.loads(Path(result["receipt"]).read_text())
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["manifest"]["closures"], delivery_manifest()["closures"])
        self.assertIn("partial", json.dumps(receipt))
        before = list(run.calls)
        with self.assertRaisesRegex(RuntimeError, "reconciliation"):
            self.ops.deliver_cli(delivery_manifest(), POOL, run=loss,
                                 runtime=self.runtime, gate=self.gate)
        self.assertEqual(before, run.calls)
        self.assertFalse(any(" check " in args[-1] or "State=RESUME" in args for args in run.calls))

    def test_aggregate_deadline_and_output_do_not_reset(self):
        for output_limit in (False, True):
            with self.subTest(output_limit=output_limit):
                self.gate.write_text(json.dumps({"open": True, "release_id": "old"}))
                run = DeliveryCommands(self.gate)
                clock = [100.0]
                def measured(args):
                    result = run(args)
                    clock[0] += 1.0
                    return result
                with patch.object(self.ops.time, "monotonic", lambda: clock[0]):
                    with self.assertRaises(self.ops.CommandFailure):
                        self.ops.deliver_cli(delivery_manifest(), POOL, run=measured,
                            runtime=self.runtime, gate=self.gate, delivery_timeout_seconds=3,
                            delivery_output_bytes=20 if output_limit else 8388608)
                self.assertLessEqual(len(run.calls), 3)
                self.assertFalse(any(args[0] == "ssh" for args in run.calls))
                receipt = json.loads(next((self.runtime / "delivery-attempts").glob("*.json")).read_text())
                self.assertEqual(receipt["status"], "failed")
                self.assertEqual(receipt["gate_changed"], not output_limit)
                if not output_limit:
                    self.assertFalse(json.loads(self.gate.read_text())["open"])
                # Different subtest must not share receipts.
                for path in (self.runtime / "delivery-attempts").glob("*.json"):
                    path.unlink()

    def test_malformed_remote_check_is_unknown_and_stops_pool(self):
        self.gate.write_text(json.dumps({"open": True, "release_id": "old"}))
        run = DeliveryCommands(self.gate)
        def incomplete(args):
            result = run(args)
            return '{"ready":' if args[0] == "ssh" and " check " in args[-1] else result
        result = self.ops.deliver_cli(delivery_manifest(), POOL, run=incomplete,
                                     runtime=self.runtime, gate=self.gate)
        self.assertTrue(result["requires_reconciliation"])
        self.assertEqual(result["nodes"]["worker"]["status"], "not_attempted")
        self.assertFalse(any("State=RESUME" in args for args in run.calls))
        self.assertEqual(next((self.runtime / "delivery-attempts").glob("*.json")).stat().st_mode & 0o777, 0o600)

    def test_native_ssh_options_and_nix_environment_are_isolated(self):
        calls = []
        self.ops.ssh("admin@worker", ["echo", "hello world"], run=lambda args: calls.append(args) or "")
        self.assertIn("-oControlMaster=no", calls[0])
        self.assertIn("-oConnectionAttempts=1", calls[0])
        self.assertEqual(calls[0][-1], "echo 'hello world'")
        # Popen sees the isolated environment without executing Nix or SSH.
        observed = []
        popen = self.ops.subprocess.Popen
        def fake_popen(args, **kwargs):
            observed.append((args, kwargs.get("env")))
            return popen([sys.executable, "-c", "print('{}')"], **kwargs)
        self.gate.write_text(json.dumps({"open": True, "release_id": "old"}))
        with patch.dict(os.environ, {"NIX_SSHOPTS": "-i /tmp/site-key"}), \
             patch.object(self.ops.subprocess, "Popen", fake_popen):
            with self.assertRaises(ValueError):
                self.ops.deliver_cli(delivery_manifest(), POOL, runtime=self.runtime, gate=self.gate)
            self.assertEqual(os.environ["NIX_SSHOPTS"], "-i /tmp/site-key")
        self.assertIn("-oConnectTimeout=10", observed[0][1]["NIX_SSHOPTS"])
        self.assertIn("/tmp/site-key", observed[0][1]["NIX_SSHOPTS"])

    def test_deadline_after_returned_mutation_retains_started_unknown(self):
        self.gate.write_text(json.dumps({"open": True, "release_id": "old"}))
        run = DeliveryCommands(self.gate)
        clock = [100.0]
        def completed_after_deadline(args):
            result = run(args)
            if args[0] == "ssh" and " activate " in args[-1]:
                clock[0] = 104.0
            return result
        with patch.object(self.ops.time, "monotonic", lambda: clock[0]):
            result = self.ops.deliver_cli(delivery_manifest(), POOL, run=completed_after_deadline,
                runtime=self.runtime, gate=self.gate, delivery_timeout_seconds=3)
        self.assertTrue(result["requires_reconciliation"])
        self.assertEqual(result["remote_outcome"], "unknown")
        self.assertTrue(result["command_failure"]["child_started"])
        self.assertEqual(result["command_failure"]["failure"], "deadline")
        self.assertEqual(result["nodes"]["worker"]["status"], "not_attempted")
        self.assertFalse(any(" check " in args[-1] or "State=RESUME" in args for args in run.calls))
        self.assertFalse(json.loads(self.gate.read_text())["open"])

    def test_review_gate_open_fsync_and_terminal_receipt_failure_keep_blocker(self):
        for failure in ("gate_fsync", "terminal_after_replace", "terminal_persistent", "close_failure"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                gate, runtime = root / "gate", root / "runtime"
                gate.write_text(json.dumps({"open": True, "release_id": "old"}))
                run = DeliveryCommands(gate)
                publish = self.ops.publish_json
                admission = self.ops.publish_admission
                fired = [False]
                def fail_receipt(path, value, **kwargs):
                    if Path(path).parent.name == "delivery-attempts" and value.get("phase") == "finished":
                        if failure == "terminal_persistent":
                            raise OSError("persistent terminal receipt failure")
                        if failure == "terminal_after_replace" and not fired[0]:
                            publish(path, value, **kwargs)
                            fired[0] = True
                            raise OSError("terminal directory fsync failed after replace")
                    return publish(path, value, **kwargs)
                def fail_admission(path, value):
                    if value["open"] and failure in ("gate_fsync", "close_failure"):
                        admission(path, value)
                        fired[0] = True
                        raise OSError("gate directory fsync failed after replace")
                    if not value["open"] and failure == "close_failure" and fired[0]:
                        raise OSError("cannot confirm closed gate")
                    return admission(path, value)
                with patch.object(self.ops, "publish_json", fail_receipt), \
                     patch.object(self.ops, "publish_admission", fail_admission):
                    if failure == "terminal_persistent":
                        with self.assertRaises(OSError):
                            self.ops.deliver_cli(delivery_manifest(), POOL, run=run, runtime=runtime, gate=gate)
                        result = None
                    else:
                        result = self.ops.deliver_cli(delivery_manifest(), POOL, run=run, runtime=runtime, gate=gate)
                self.assertEqual(json.loads(gate.read_text())["open"], failure == "close_failure")
                self.assertTrue(list((runtime / "delivery-attempts").glob("*.admission-intent.json")))
                if result:
                    self.assertEqual(result["status"], "failed")
                    self.assertTrue(result["requires_reconciliation"])
                    if failure == "close_failure":
                        self.assertIsNone(result["open"])
                        self.assertTrue(result["critical_admission_failure"])
                before = list(run.calls)
                with self.assertRaisesRegex(RuntimeError, "reconciliation"):
                    self.ops.deliver_cli(delivery_manifest(), POOL, run=run, runtime=runtime, gate=gate)
                self.assertEqual(before, run.calls)

    def test_review_native_environment_error_is_before_child(self):
        self.gate.write_text(json.dumps({"open": True, "release_id": "old"}))
        run = DeliveryCommands(self.gate)
        def fake_command(args, **kwargs):
            return run(args)
        original_split = self.ops.shlex.split
        def malformed_options(value):
            if "bad-site" in value:
                raise ValueError("malformed native options")
            return original_split(value)
        with patch.object(self.ops, "command", fake_command), \
             patch.object(self.ops.shlex, "split", malformed_options), \
             patch.dict(os.environ, {"NIX_SSHOPTS": "bad-site'"}):
            with self.assertRaises(ValueError):
                self.ops.deliver_cli(delivery_manifest(), POOL, run=fake_command,
                                     runtime=self.runtime, gate=self.gate)
        self.assertEqual(run.calls, [])
        receipt = json.loads(next((self.runtime / "delivery-attempts").glob("*.json")).read_text())
        self.assertFalse(receipt["commands"][-1]["record"]["child_started"])
        self.assertFalse(receipt.get("requires_reconciliation", False))
        # The same preparation failure during remote-copy stage is also known;
        # local prefetch verification/quiesce may run, but native copy never enters.
        other_runtime = self.runtime.parent / "remote-runtime"
        with patch.object(self.ops, "command", fake_command), \
             patch.object(self.ops.shlex, "split", malformed_options), \
             patch.dict(os.environ, {"NIX_SSHOPTS": "bad-site'"}):
            result = self.ops.deliver_cli(delivery_manifest(False), POOL, run=fake_command,
                                         runtime=other_runtime, gate=self.gate)
        self.assertFalse(result["requires_reconciliation"])
        self.assertFalse(any(args[:2] == ["nix", "copy"] or args[0] == "ssh" for args in run.calls))
        remote_receipt = json.loads(next((other_runtime / "delivery-attempts").glob("*.json")).read_text())
        failures = [item for item in remote_receipt["commands"] if item["status"] == "failed"]
        self.assertTrue(failures)
        self.assertTrue(all(not item["record"]["child_started"] for item in failures))

    def test_review_all_native_cli_actions_receive_selected_command_flags(self):
        for action in ("node-check", "prepare-initial"):
            observed = []
            def check_action(*args, **kwargs):
                kwargs["run"](["fake-verification"])
                return {}
            def adapter(args, **kwargs):
                observed.append(kwargs)
                return ""
            source = self.runtime.parent / "manifest.json"
            source.write_text(json.dumps(release()))
            args = ["release", action, "--runtime", str(self.runtime), "--gate", str(self.gate),
                    "--command-timeout-seconds", "7", "--command-output-bytes", "123"]
            if action == "prepare-initial":
                args += ["--manifest", str(source)]
            with patch.object(sys, "argv", args), patch.object(self.ops, "command", adapter), \
                 patch.object(self.ops, "node_check" if action == "node-check" else "prepare_initial", check_action), \
                 patch("builtins.print"):
                self.ops.main()
            self.assertEqual(observed, [{"timeout_seconds": 7, "output_bytes": 123}])

    def test_final_combined_cli_failure_prints_current_unknown_and_blocks_retry(self):
        self.gate.write_text(json.dumps({"open": True, "release_id": "old"}))
        source, pool = self.runtime.parent / "manifest.json", self.runtime.parent / "pool.json"
        source.write_text(json.dumps(delivery_manifest()))
        pool.write_text(json.dumps(POOL))
        run = DeliveryCommands(self.gate)
        original_deliver = self.ops.deliver_cli
        publish = self.ops.publish_json
        admission = self.ops.publish_admission
        opened = [False]
        def injected_delivery(value, selected, **kwargs):
            return original_deliver(value, selected, run=run, **kwargs)
        def persistent_terminal(path, value, **kwargs):
            if Path(path).parent.name == "delivery-attempts" and value.get("phase") == "finished":
                raise OSError("persistent terminal failure")
            return publish(path, value, **kwargs)
        def failed_close(path, value):
            if not value["open"] and opened[0]:
                raise OSError("failed recovery close")
            result = admission(path, value)
            if value["open"]:
                opened[0] = True
            return result
        args = ["release", "deliver", "--manifest", str(source), "--pool", str(pool),
                "--runtime", str(self.runtime), "--gate", str(self.gate)]
        with patch.object(sys, "argv", args), patch.object(self.ops, "deliver_cli", injected_delivery), \
             patch.object(self.ops, "publish_json", persistent_terminal), \
             patch.object(self.ops, "publish_admission", failed_close), patch("builtins.print") as printed:
            with self.assertRaises(SystemExit) as caught:
                self.ops.main()
        self.assertEqual(caught.exception.code, 1)
        payload = json.loads(printed.call_args.args[0])
        self.assertIsNone(payload["open"])
        self.assertEqual(payload["admission_state"], "unknown")
        self.assertTrue(payload["critical_admission_failure"])
        self.assertTrue(payload["requires_reconciliation"])
        self.assertTrue(json.loads(self.gate.read_text())["open"])
        self.assertFalse(json.loads((self.runtime / "delivery-report.json").read_text())["open"])
        self.assertNotIn("manifest", payload)
        self.assertNotIn("commands", payload)
        before = list(run.calls)
        with patch.object(sys, "argv", args), patch.object(self.ops, "deliver_cli", injected_delivery), \
             patch("builtins.print") as retry_printed:
            with self.assertRaises(SystemExit) as retry:
                self.ops.main()
        self.assertEqual(retry.exception.code, 1)
        self.assertEqual(before, run.calls)
        retry_payload = json.loads(retry_printed.call_args.args[0])
        self.assertIsNone(retry_payload["open"])
        self.assertTrue(retry_payload["requires_reconciliation"])
        self.assertTrue(list((self.runtime / "delivery-attempts").glob("*.admission-intent.json")))

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
                kwargs["run"] = run
                return prepare(value, profile=root / "profile", **kwargs)
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
                report = self.ops.deliver_cli(delivery_manifest(), POOL, runtime=self.runtime, gate=self.gate, run=run)
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
                    self.ops.deliver_cli(delivery_manifest(), POOL, runtime=self.runtime, gate=self.gate, run=run)
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
                        self.ops.deliver_cli(delivery_manifest(), POOL, runtime=self.runtime, gate=self.gate, run=run)
                self.assertEqual(gate.read_bytes(), original)
                self.assertFalse(any(args[0] in ("systemctl", "scontrol", "ssh") for args in run.calls))

    def test_manifest_without_cache_uri_verifies_local_closures_before_quiesce(self):
        with tempfile.TemporaryDirectory() as temporary:
            gate = Path(temporary) / "admission.json"
            gate.write_text(json.dumps({"open": True, "release_id": "old"}))
            original, run = gate.read_bytes(), DeliveryCommands(gate)
            run.evidence = [{"path": path, **value} for path, value in run.evidence.items()]
            with patch.object(self.ops, "publish_admission", lambda _path, value: self.ops.publish_json(gate, value)):
                self.ops.deliver_cli(delivery_manifest(False), POOL, runtime=self.runtime, gate=self.gate, run=run)
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
                        self.ops.deliver_cli(value, POOL, runtime=self.runtime, gate=self.gate, run=run)
                self.assertEqual(gate.read_text(), "unchanged")
                self.assertEqual(run.calls, [])
        calls = []
        with self.assertRaisesRegex(ValueError, "closure"):
            self.ops.deliver_cli(release(), POOL, runtime=self.runtime, gate=self.gate, run=lambda args: calls.append(args))
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
                    self.ops.deliver_cli(value, POOL, runtime=self.runtime, gate=self.gate, run=lambda args: calls.append(args))
                self.assertEqual(calls, [])

    def test_cli_keeps_operational_cache_and_closure_fields_for_controller_prefetch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, pool = root / "release.json", root / "pool.json"
            source.write_text(json.dumps(delivery_manifest()))
            pool.write_text(json.dumps(POOL))
            observed = []
            def deliver(value, selected_pool, **kwargs):
                observed.append((value, selected_pool))
                return {"open": True, "status": "completed"}
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

    def test_identical_retry_repairs_only_the_damaged_profile_and_preserves_identity(self):
        for role in ("worker", "controller"):
            for damaged in ("profile", "profile-solver"):
                for target in (None, "/nix/store/other"):
                    with self.subTest(role=role, damaged=damaged, target=target), tempfile.TemporaryDirectory() as temporary:
                        root, commands = Path(temporary), Commands()
                        arguments = dict(profile=root / "profile", runtime=root / "runtime", role=role,
                                         run=commands, email="test@example.invalid",
                                         allowed_codes_file=root / "code-uuid")
                        first = self.ops.activate(release(), **arguments)
                        self.assertEqual(first["release_id"], "release-a")
                        self.assertEqual(first["solver_executable"], "/nix/store/solver/bin/qcl-negf")
                        if role == "controller":
                            self.assertEqual(first["code_uuid"], "12345678-1234-1234-1234-123456789abc")
                        (root / damaged).unlink()
                        if target is not None:
                            (root / damaged).symlink_to(target)
                        commands.calls.clear()
                        self.assertEqual(self.ops.activate(release(), **arguments), first)
                        selected = "/nix/store/application" if damaged == "profile" else "/nix/store/solver"
                        self.assertEqual((root / damaged).resolve(), Path(selected))
                        self.assertEqual([call for call in commands.calls if call[0] == "nix-env"],
                                         [["nix-env", "--profile", str(root / damaged), "--set", selected]])
                        if role == "controller":
                            self.assertEqual((root / "code-uuid").read_text().strip(), first["code_uuid"])
                            registration = next(call for call in commands.calls if call[0] == "runuser")
                            self.assertEqual(registration[-2:],
                                             ["/nix/store/solver/bin/qcl-negf", "qcl-negf-release-a"])
                        self.assertEqual(self.ops.check(release(), profile=root / "profile",
                            runtime=root / "runtime", role=role, run=commands), first)

    def test_check_rejects_missing_or_wrong_solver_profile_before_health(self):
        for role in ("worker", "controller"):
            for target in (None, "/nix/store/other"):
                with self.subTest(role=role, target=target), tempfile.TemporaryDirectory() as temporary:
                    root, commands = Path(temporary), Commands()
                    (root / "release.json").write_text(json.dumps({**release(), "ready": True}))
                    (root / "profile").symlink_to("/nix/store/application")
                    if target is not None:
                        (root / "profile-solver").symlink_to(target)
                    with self.assertRaisesRegex(ValueError, "solver profile"):
                        self.ops.check(release(), profile=root / "profile", runtime=root, role=role, run=commands)
                    self.assertEqual(commands.calls, [])

    def test_profile_setter_failure_or_wrong_result_cannot_publish_ready(self):
        class SetterCommands(Commands):
            broken_profile = None
            mode = None

            def __call__(self, args):
                if args[0] == "nix-env" and args[args.index("--profile") + 1] == str(self.broken_profile):
                    if self.mode == "failure":
                        raise RuntimeError("profile setter failed")
                    super().__call__([*args[:-1], "/nix/store/other"])
                    return ""
                return super().__call__(args)

        for role in ("worker", "controller"):
            for damaged in ("profile", "profile-solver"):
                for mode in ("failure", "wrong-result"):
                    with self.subTest(role=role, damaged=damaged, mode=mode), tempfile.TemporaryDirectory() as temporary:
                        root, commands = Path(temporary), SetterCommands()
                        arguments = dict(profile=root / "profile", runtime=root / "runtime", role=role,
                                         run=commands, email="test@example.invalid",
                                         allowed_codes_file=root / "code-uuid")
                        self.ops.activate(release(), **arguments)
                        commands.broken_profile, commands.mode = root / damaged, mode
                        commands.broken_profile.unlink()
                        commands.calls.clear()
                        error = RuntimeError if mode == "failure" else ValueError
                        with self.assertRaisesRegex(error, "profile"):
                            self.ops.activate(release(), **arguments)
                        record = root / "runtime/release.json"
                        self.assertFalse(record.exists() and json.loads(record.read_text()).get("ready") is True)
                        self.assertFalse(any(call[0] == "systemctl" or "self-check" in call for call in commands.calls))

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
            (root / "release.json").write_text(json.dumps({**release(), "ready": True}))
            (root / "profile").symlink_to("/nix/store/old-application")
            (root / "profile-solver").symlink_to("/nix/store/solver")
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
