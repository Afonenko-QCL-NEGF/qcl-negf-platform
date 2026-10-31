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
        from test_application_release import NativeUpdateModel, Commands
        self.model, self.local = NativeUpdateModel(), Commands()
        self.local.registered = 'synthetic-code'
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
            from test_application_release import control_response
            if "activate" in remote:
                self.model.activate(actual['node_name'])
                return ""
            response = control_response(args, actual, model=self.model)
            if response is not None:
                return response
            if "check" in remote:
                if self.mismatch == "legacy":
                    return json.dumps({**manifest_fixture(), "ready": True})
                if self.mismatch == "partial":
                    return '{"schema":'
                from test_application_release import selected_release_response
                return json.dumps({"schema": "qcl-negf-node-release-check-v1", "node_identity": actual,
                                   "release": {**selected_release_response(remote), "ready": True, "code_uuid": "synthetic-code"}})
            raise AssertionError("Unexpected synthetic SSH action")
        if args[:3] == ["nix", "path-info", "--json"]:
            return json.dumps({item["path"]: {"narHash": item["narHash"]} for item in manifest_fixture()["closures"]})
        if args[:3] == ["nix", "copy", "--to"]:
            self.copy_started = True
            return ""
        from test_application_release import clear_aiida, controller_stop_state
        if args == ['id', '-u']: return '1000\n'
        if args == ['id', '-un']: return 'operator\n'
        if args == ['env', 'TZ=UTC', 'LC_ALL=C', 'date', '+%s']: return '1791504120\n'
        if 'aiida_update_check.py' in ' '.join(args): return json.dumps(clear_aiida())
        if args[:2] == ['systemctl', 'show']: return controller_stop_state()
        if args[0] == 'findmnt':
            return json.dumps({'filesystems': [{'target': args[args.index('--target')+1],
                'source': 'storage.invalid:/srv/qcl-negf/jobs', 'fstype': 'nfs4'}]})
        if args[0] == 'scontrol': return ''
        if 'scontrol' in args: return self.model.command(args)
        if args[0] in ('nix-env', 'nix-store', 'systemctl', 'runuser', 'timeout'):
            return self.local(args)
        if args[0] == 'squeue' or args[:3] == ['nix', 'copy', '--from']: return ''
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


class BoundaryProtectedFS(FakeProtectedFS):
    """Script syscall outcomes without creating a native FIFO or root namespace."""
    def __init__(self, *, read_fragment=None, writes=(), fail_sync=None):
        super().__init__()
        self.read_fragment = read_fragment
        self.write_results = iter(writes)
        self.fail_sync = fail_sync
        self.reads = []
        self.writes = []
        self.closed = []

    def read(self, fd, size):
        requested = size
        result = super().read(fd, min(size, self.read_fragment) if self.read_fragment else size)
        self.reads.append((self.fds[fd]["path"], requested, len(result)))
        return result

    def write(self, fd, raw):
        outcome = next(self.write_results, len(raw))
        if isinstance(outcome, Exception):
            raise outcome
        if not 0 <= outcome <= len(raw):
            raise AssertionError("Invalid synthetic short write")
        self.writes.append((len(raw), outcome))
        super().write(fd, raw[:outcome])
        return outcome

    def close(self, fd):
        self.closed.append(fd)
        super().close(fd)

    def fsync(self, fd):
        super().fsync(fd)
        if len(self.syncs) == self.fail_sync:
            raise OSError("Synthetic fsync failure")


class ProtectedInputBoundaryTests(unittest.TestCase):
    def assert_readonly_opens(self, fs):
        # Include attempted opens that fail before returning a descriptor.
        for path, flags, _ in fs.opens:
            with self.subTest(open_path=path):
                self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)

    def assert_closed(self, fs):
        self.assertEqual(fs.fds, {})
        self.assertEqual(len(fs.closed), len(fs.opens))
        self.assertEqual(len(fs.closed), len(set(fs.closed)))

    def test_regular_empty_single_and_exact_limit_with_fragmented_reads(self):
        for size in (0, 1, 65536):
            for fragment in (None, 997):
                with self.subTest(size=size, fragment=fragment):
                    fs = BoundaryProtectedFS(read_fragment=fragment)
                    payload = b"x" * size
                    fs.nodes["/protected/known_hosts"]["bytes"] = payload
                    with fs.patches():
                        actual = ops.read_protected_file("/protected/known_hosts")
                    self.assertEqual(actual, payload)
                    self.assertEqual(sum(count for _, _, count in fs.reads), size)
                    self.assertTrue(all(flags & os.O_NOFOLLOW for _, flags, _ in fs.opens))
                    self.assertTrue(fs.opens[-1][1] & os.O_NONBLOCK)
                    self.assert_readonly_opens(fs)
                    self.assert_closed(fs)

    def test_oversize_reads_at_most_limit_plus_one_and_closes(self):
        for size in (65537, 65538):
            for fragment in (None, 997):
                with self.subTest(size=size, fragment=fragment):
                    fs = BoundaryProtectedFS(read_fragment=fragment)
                    fs.nodes["/protected/known_hosts"]["bytes"] = b"x" * size
                    with fs.patches(), self.assertRaisesRegex(ValueError, "bound"):
                        ops.read_protected_file("/protected/known_hosts")
                    actual = 0
                    for _, requested, delivered in fs.reads:
                        self.assertGreater(requested, 0)
                        self.assertLessEqual(requested, 65537 - actual)
                        actual += delivered
                    self.assertLessEqual(actual, 65537)
                    self.assertEqual(actual, 65537)
                    if size > 65537:
                        self.assertLess(actual, size, "Independent tail must remain unread")
                    self.assert_readonly_opens(fs)
                    self.assert_closed(fs)

    def test_fifo_socket_and_directory_are_rejected_before_any_read(self):
        for kind in (stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFDIR):
            with self.subTest(kind=kind):
                fs = BoundaryProtectedFS()
                fs.nodes["/protected/known_hosts"]["mode"] = kind | 0o600
                with fs.patches(), self.assertRaisesRegex(ValueError, "owner/mode/type"):
                    ops.read_protected_file("/protected/known_hosts")
                self.assertEqual(fs.reads, [])
                self.assertEqual(fs.opens[-1][0], "/protected/known_hosts")
                self.assertTrue(fs.opens[-1][1] & os.O_NONBLOCK)
                self.assertTrue(all(flags & os.O_NOFOLLOW for _, flags, _ in fs.opens))
                self.assert_readonly_opens(fs)
                self.assert_closed(fs)

    def test_root_ancestor_and_leaf_owner_and_write_modes_refuse_before_read(self):
        for path in ("/", "/protected", "/protected/known_hosts"):
            for change in ("uid", "group_write", "other_write"):
                with self.subTest(path=path, change=change):
                    fs = BoundaryProtectedFS()
                    if change == "uid":
                        fs.nodes[path]["uid"] = 1000
                    else:
                        fs.nodes[path]["mode"] |= 0o020 if change == "group_write" else 0o002
                    with fs.patches(), self.assertRaisesRegex(ValueError, "owner/mode/type"):
                        ops.read_protected_file("/protected/known_hosts")
                    self.assertEqual(fs.reads, [])
                    self.assert_readonly_opens(fs)
                    self.assert_closed(fs)

    def test_symlink_at_root_ancestor_or_leaf_requires_nofollow(self):
        for path in ("/", "/protected", "/protected/known_hosts"):
            with self.subTest(path=path):
                fs = BoundaryProtectedFS()
                fs.nodes[path]["mode"] = stat.S_IFLNK | 0o777
                # A failed open has no descriptor; assert the attempted syscall independently.
                def nofollow_open(name, flags, mode=0o777, *, dir_fd=None):
                    self.assertTrue(flags & os.O_NOFOLLOW)
                    return fs.open(name, flags, mode, dir_fd=dir_fd)
                with fs.patches(), patch.object(ops.os, "open", nofollow_open), self.assertRaises(OSError):
                    ops.read_protected_file("/protected/known_hosts")
                self.assertEqual(fs.reads, [])
                self.assertEqual(fs.fds, {})
                self.assertEqual(len(fs.closed), len(fs.opens) - 1)
                self.assert_readonly_opens(fs)

    def test_root_and_ancestor_must_be_directories(self):
        for path in ("/", "/protected"):
            for kind in (stat.S_IFREG, stat.S_IFIFO, stat.S_IFSOCK):
                with self.subTest(path=path, kind=kind):
                    fs = BoundaryProtectedFS()
                    fs.nodes[path]["mode"] = kind | 0o600
                    with fs.patches(), self.assertRaises(NotADirectoryError):
                        ops.read_protected_file("/protected/known_hosts")
                    self.assertEqual(fs.reads, [])
                    self.assertEqual(fs.fds, {})
                    self.assertEqual(len(fs.closed), len(fs.opens) - 1)
                    self.assertTrue(fs.opens[-1][1] & os.O_DIRECTORY)
                    self.assertTrue(fs.opens[-1][1] & os.O_NOFOLLOW)
                    self.assert_readonly_opens(fs)

    def test_invalid_paths_refuse_before_open(self):
        for path in ("", "relative", "/protected/./known_hosts", "/protected/../known_hosts",
                     "/protected//known_hosts", "/protected/known_hosts/"):
            with self.subTest(path=path):
                fs = BoundaryProtectedFS()
                with fs.patches(), self.assertRaises(ValueError):
                    ops.read_protected_file(path)
                self.assertEqual(fs.opens, [])
                self.assert_readonly_opens(fs)

    def test_empty_enrollment_and_known_hosts_are_rejected_by_consumer(self):
        for raw in (b"", json.dumps(registry()).encode()):
            with self.subTest(empty_enrollment=not raw):
                fs = BoundaryProtectedFS()
                fs.nodes["/protected/enrollment.json"] = {
                    "mode": stat.S_IFREG | 0o600, "uid": 0, "bytes": raw}
                fs.nodes["/protected/known_hosts"]["bytes"] = b""
                with fs.patches(), self.assertRaises(ValueError):
                    ops.load_enrollment("/protected/enrollment.json")
                self.assert_readonly_opens(fs)
                self.assert_closed(fs)

    def test_full_and_progressing_short_writes_return_exact_durable_snapshot(self):
        payload = b"synthetic verified trust bytes"
        for counts in ((), (1, 2, 3, 4)):
            with self.subTest(counts=counts):
                fs = BoundaryProtectedFS(writes=counts)
                with fs.patches():
                    frozen = ops.freeze_ssh_trust(payload, snapshot_root="/protected/snapshots")
                target = frozen["path"]
                self.assertEqual(fs.nodes[target]["bytes"], payload)
                self.assertEqual(frozen["sha256"], hashlib.sha256(payload).hexdigest())
                self.assertEqual(fs.nodes[target]["mode"], stat.S_IFREG | 0o600)
                self.assertEqual(fs.nodes[str(Path(target).parent)]["mode"], stat.S_IFDIR | 0o700)
                self.assertEqual(fs.syncs, [target, str(Path(target).parent), "/protected/snapshots"])
                self.assertEqual(sum(count for _, count in fs.writes), len(payload))
                self.assertTrue(all(flags & os.O_NOFOLLOW for _, flags, _ in fs.opens))
                self.assert_closed(fs)

    def test_failed_writes_retain_original_partial_attempt_and_return_no_trust(self):
        payload = b"synthetic verified trust bytes"
        for counts, prefix in (((0,), b""), ((3, 0), payload[:3]),
                               ((3, OSError("Synthetic incomplete write")), payload[:3])):
            with self.subTest(counts=tuple(type(c).__name__ for c in counts)):
                fs = BoundaryProtectedFS(writes=counts)
                with fs.patches(), self.assertRaises(OSError):
                    ops.freeze_ssh_trust(payload, snapshot_root="/protected/snapshots")
                attempts = [node["bytes"] for path, node in fs.nodes.items()
                            if path.startswith("/protected/snapshots/") and path.endswith("/known_hosts")]
                self.assertEqual(attempts, [prefix])
                self.assertEqual(fs.syncs, [])
                self.assert_closed(fs)

    def test_file_directory_and_parent_fsync_failures_retain_attempt_without_return(self):
        payload = b"synthetic verified trust bytes"
        for failure in (1, 2, 3):
            with self.subTest(failure=failure):
                fs = BoundaryProtectedFS(fail_sync=failure)
                with fs.patches(), self.assertRaisesRegex(OSError, "fsync"):
                    ops.freeze_ssh_trust(payload, snapshot_root="/protected/snapshots")
                attempts = [path for path in fs.nodes
                            if path.startswith("/protected/snapshots/") and path.endswith("/known_hosts")]
                self.assertEqual(len(attempts), 1)
                target = attempts[0]
                self.assertEqual(fs.nodes[target]["bytes"], payload)
                self.assertEqual(fs.syncs, [target, str(Path(target).parent), "/protected/snapshots"][:failure])
                self.assert_closed(fs)

    def test_invalid_frozen_input_refuses_before_namespace_mutation(self):
        for payload in (b"", b"x" * 65537, "synthetic", bytearray(b"synthetic"), None):
            with self.subTest(kind=type(payload).__name__, size=len(payload) if payload is not None else None):
                fs = BoundaryProtectedFS()
                before = copy.deepcopy(fs.nodes)
                with fs.patches(), self.assertRaises(ValueError):
                    ops.freeze_ssh_trust(payload, snapshot_root="/protected/snapshots")
                self.assertEqual(fs.nodes, before)
                self.assertEqual(fs.opens, [])


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        from test_application_release import install_controller_config_io
        temporary = tempfile.TemporaryDirectory(prefix='p11-enrollment-')
        self.addCleanup(temporary.cleanup)
        self.ops = ops
        install_controller_config_io(self, Path(temporary.name))
        generation = ops._process_generation
        hook = patch.object(ops, '_process_generation', lambda: (*generation()[:2], CONTROLLER['boot_id']))
        hook.start(); self.addCleanup(hook.stop)
        protected = ops.read_protected_file
        def receipt_read(path, limit=65536, **kwargs):
            if Path(path).parent.name == 'qualifications' and str(path).startswith('/tmp/'):
                raw = Path(path).read_bytes()
                if len(raw) > limit: raise ValueError('Synthetic receipt exceeds bound')
                return raw
            return protected(path, limit, **kwargs)
        hook = patch.object(ops, 'read_protected_file', receipt_read)
        hook.start(); self.addCleanup(hook.stop)

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
            self.assertEqual([next(word for word in args if word.startswith("NodeName=")) for args in resume], ["NodeName=worker", "NodeName=second"])
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
                ops.deliver_pool(expected, ["worker"], gate, runtime=Path(temporary), bindings={"worker": binding},
                                 deliver=lambda *a: {**expected, "ready": True}, quiesce=lambda: None)
            self.assertEqual(gate.read_text(), "original")
            result = ops.deliver_pool(expected, ["worker"], gate, runtime=Path(temporary), authority=selected_context(), bindings={"worker": binding},
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

    def test_wrong_local_engine_does_not_create_runtime_or_flock_or_read_unresolved(self):
        calls,snapshots,unresolved=[],[],[]
        with tempfile.TemporaryDirectory() as temporary:
            runtime=Path(temporary)/'not-created'
            with patch.object(ops,'load_enrollment',lambda _:{'registry':registry(),'registry_sha256':'e'*64,'known_hosts_bytes':b'synthetic'}), \
                 patch.object(ops,'observe_node_identity',lambda **_:WORKER), \
                 patch.object(ops,'freeze_ssh_trust',lambda *a,**k:snapshots.append(True)), \
                 patch.object(ops,'unresolved_deliveries',lambda _:unresolved.append(True)), \
                 patch.object(ops.fcntl,'flock',lambda *a:calls.append('lock')):
                with self.assertRaises(ValueError):
                    ops.deliver_cli(manifest_fixture(),pool(),enrollment='/protected/registry.json',
                        runtime=runtime,run=lambda args:calls.append(args))
            self.assertFalse(runtime.exists())
            self.assertEqual(calls+snapshots+unresolved,[])

    def test_complete_public_request_on_worker_refuses_before_request_store_or_service(self):
        import delivery_requests
        calls,snapshots,unresolved,refusals=[],[],[],[]
        submit=delivery_requests.submit_update
        # This CLI boundary consumes an already-proven immutable public source.
        # Config filesystem/origin faults are exercised by NativeControllerConfigTests.
        worker_config=b'{"role":"worker"}'
        config_path='/nix/store/fixture-release-config.json'
        origin={'path':config_path,'chain':[(config_path,
            (1,3,stat.S_IFREG|0o444,0,len(worker_config),1,1),None)]}
        root_info=SimpleNamespace(st_dev=1,st_ino=2,st_mode=stat.S_IFDIR|0o755,st_uid=0)
        def config_origin(budget,path,*,executable):
            self.assertEqual(path,'/etc/qcl-negf/release-config.json')
            self.assertFalse(executable)
            return copy.deepcopy(origin)
        def config_bytes(budget,path,limit):
            self.assertEqual((path,limit),(config_path,16384))
            return worker_config
        def config_root(budget,path,**kwargs):
            self.assertEqual(path,'/')
            return root_info
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);runtime=root/'not-created'
            source,selected=root/'manifest.json',root/'pool.json'
            source.write_text(json.dumps(manifest_fixture()));selected.write_text(json.dumps(pool()))
            args=['release','update','--manifest',str(source),'--pool',str(selected),
                '--enrollment','/protected/registry.json','--runtime',str(runtime),
                '--request-id','d3986590-cf69-4ca8-af7c-c3e065241ad2','--procedure','maintenance']
            def dispatch(value,**kwargs):
                try:
                    return submit(value,run=lambda *a,**k:calls.append(a),**kwargs)
                except ValueError as error:
                    refusals.append(str(error))
                    raise
            with patch.object(sys,'argv',args),patch.object(ops,'RUNTIME',runtime), \
                 patch.object(ops,'read_protected_file',return_value=json.dumps(registry()).encode()), \
                 patch.object(delivery_requests.engine,'public_binary_origin',config_origin), \
                 patch.object(delivery_requests.engine,'immutable_public_bytes',config_bytes), \
                 patch.object(delivery_requests.engine.UpdateScan,'stat',config_root), \
                 patch.object(delivery_requests,'submit_update',dispatch), \
                 patch.object(ops,'observe_node_identity',lambda **_:WORKER), \
                 patch.object(ops,'freeze_ssh_trust',lambda *a,**k:snapshots.append(True)), \
                 patch.object(ops,'unresolved_deliveries',lambda _:unresolved.append(True)), \
                 patch.object(ops.fcntl,'flock',lambda *a:calls.append('lock')):
                with patch('builtins.print') as printed, self.assertRaises(SystemExit) as caught:
                    ops.main()
                self.assertEqual(caught.exception.code,1)
                response=json.loads(printed.call_args.args[0])
                self.assertEqual(response,{'schema':'qcl-negf-delivery-response-error-v1',
                    'request_id':'d3986590-cf69-4ca8-af7c-c3e065241ad2','error_class':'ValueError'})
            self.assertFalse(runtime.exists())
            self.assertEqual(calls+snapshots+unresolved,[])
            self.assertEqual(refusals,['Delivery service belongs to protected controller role'])

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
        from test_worker_shutdown_intent import authorized_event
        from worker_startup_fixtures import ControllerFixture
        for case in ("wrong_local", "wrong_worker", "success", "legacy"):
            run = SyntheticCommands(mismatch="legacy" if case == "legacy" else None)
            if case == "wrong_worker":
                run.observations["admin@worker.invalid"] = dict(SECOND)
            with tempfile.TemporaryDirectory() as temporary, \
                 patch.object(ops, "load_enrollment", lambda _: {"registry": registry(), "registry_sha256": "e" * 64, "known_hosts_bytes": b"synthetic"}), \
                 patch.object(ops, "observe_node_identity", lambda **_: WORKER if case == "wrong_local" else CONTROLLER), \
                 patch.object(ops, "freeze_ssh_trust", lambda *a, **k: TRUST), \
                 patch.object(worker, "_authorized_startup_event", authorized_event), \
                 ControllerFixture(ops, Path(temporary)).patches():
                runtime, gate = Path(temporary), Path(temporary) / "gate"
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
        # Import only at test execution: this module also supplies enrollment facts
        # to the release tests. Reuse their independent current-update model.
        from test_application_release import (Commands, NativeUpdateModel, clear_aiida,
            control_response, controller_stop_state, install_controller_config_io)
        fs = FakeProtectedFS()
        original = b"independent synthetic key bytes"
        with fs.patches():
            verified = ops.read_protected_file("/protected/known_hosts")
            frozen = ops.freeze_ssh_trust(verified, snapshot_root="/protected/snapshots")
        opened_source = sum(path == "/protected/known_hosts" for path, _, _ in fs.opens)
        model, local = NativeUpdateModel(), Commands()
        calls, remote_actions = [], []
        observations = {"admin@controller.invalid": CONTROLLER,
                        "admin@worker.invalid": WORKER, "admin@second.invalid": SECOND}
        selected = ops.release_envelope(manifest_fixture())
        def transport(args, **kwargs):
            calls.append(args)
            fs.nodes["/protected/known_hosts"]["bytes"] = b"late source substitution"
            if args[0] == "ssh":
                self.assertIn("-oUserKnownHostsFile=" + frozen["path"], args)
                self.assertIn("-oStrictHostKeyChecking=yes", args)
                self.assertIn("-oGlobalKnownHostsFile=/dev/null", args)
            if args[:2] == ["nix", "copy"]:
                self.assertIn("-oUserKnownHostsFile=" + frozen["path"],
                              shlex.split(kwargs["env"]["NIX_SSHOPTS"]))
            self.assertEqual(fs.nodes[frozen["path"]]["bytes"], original)
            self.assertEqual(frozen["sha256"], hashlib.sha256(original).hexdigest())
            if args[0] == "ssh":
                self.assertIn(args[-2], observations)
                actual = observations[args[-2]]
                words = shlex.split(args[-1])
                self.assertEqual(words[:3], ["sudo", "-n", "qcl-negf-release"])
                action = words[3]
                self.assertIn(action, ("identity", "update-capabilities", "update-identity",
                    "stop-update", "stopped-identity", "activate", "check", "health-update", "finish-update"))
                remote_actions.append((actual["node_name"], action))
                if action == "identity":
                    return json.dumps(actual)
                if action not in ("update-capabilities", "update-identity"):
                    def argument(name):
                        return words[words.index(name) + 1]
                    self.assertEqual(json.loads(base64.urlsafe_b64decode(argument("--manifest-base64"))), selected)
                    self.assertEqual(json.loads(base64.urlsafe_b64decode(argument("--expected-node-identity-base64"))), actual)
                    self.assertTrue(argument("--update-attempt-id"))
                if action == "activate":
                    model.activate(actual["node_name"])
                    return ""
                if action == "check":
                    return json.dumps({"schema": "qcl-negf-node-release-check-v1",
                                       "node_identity": actual, "release": {**selected, "ready": True}})
                response = control_response(args, actual, model=model)
                self.assertIsNotNone(response, "Unmodelled update action")
                return response
            if args[:3] == ["nix", "path-info", "--json"]:
                self.assertEqual(args[3:], ["/nix/store/application", "/nix/store/solver"])
                return json.dumps({item["path"]: {"narHash": item["narHash"]}
                                   for item in manifest_fixture()["closures"]})
            if args[:3] == ["nix", "copy", "--to"]:
                self.assertIn(args[3], ("ssh-ng://admin@worker.invalid", "ssh-ng://admin@second.invalid"))
                self.assertEqual(args[4:], ["/nix/store/application", "/nix/store/solver"])
                self.assertEqual({name for name, action in remote_actions if action == "stop-update"}, {"worker", "second"})
                return ""
            if "scontrol" in args:
                return model.command(args)
            if args == ["id", "-u"]:return "1000\n"
            if args == ["id", "-un"]:return "operator\n"
            if args == ["env", "TZ=UTC", "LC_ALL=C", "date", "+%s"]:return "1791504120\n"
            if args == ["squeue", "--all", "--noheader", "--format", "%i"]:return ""
            if args[:2] == ["systemctl", "show"]:return controller_stop_state()
            if args[0] == "findmnt":
                return json.dumps({"filesystems": [{"target": str(gate.parent),
                    "source": "storage.invalid:/srv/qcl-negf/jobs", "fstype": "nfs4"}]})
            if args[0] == "runuser" and any(Path(word).name == "aiida_update_check.py" for word in args):
                return json.dumps(clear_aiida())
            if args[0] == "nix-env":
                self.assertEqual(Path(args[2]).parent, Path(temporary))
                return local(args)
            if args[0] == 'nix-store' and args[1] == '--verify-path' and set(args[2:]) <= {'/nix/store/application', '/nix/store/solver'}:
                return ''
            if args[0] == "systemctl" and args[1] in ("stop", "start", "restart", "is-active"):
                self.assertTrue(set(args[2:]) <= {"--quiet", "qcl-negf-api.service", "qcl-negf-aiida.service", "munged.service"})
                return ""
            if ((args[0] == "runuser" and any(Path(word).name == "register_aiida.py" for word in args))
                    or (args[0] == "timeout" and args[-2:] == [selected["solver_executable"], "self-check"])):
                return local(args)
            raise AssertionError("Unmodelled local command: " + args[0])
        generation = ops._process_generation
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as scope, \
             patch.object(ops, "load_enrollment", lambda _: {"registry": registry(), "registry_sha256": "e" * 64, "known_hosts_bytes": original}), \
             patch.object(ops, "observe_node_identity", lambda **_: CONTROLLER), \
             patch.object(ops, "_process_generation", lambda: (*generation()[:2], CONTROLLER["boot_id"])), \
             patch.object(ops, "read_protected_file", side_effect=AssertionError("Frozen source must not be reread")), \
             patch.object(ops, "freeze_ssh_trust", lambda *a, **k: frozen), patch.object(ops, "command", transport):
            install_controller_config_io(SimpleNamespace(ops=ops, addCleanup=scope.callback), Path(temporary))
            runtime, gate = Path(temporary) / "runtime", Path(temporary) / "gate"
            gate.write_text(json.dumps({"open": True, "release_id": "old"}))
            result = ops.deliver_cli(manifest_fixture(), pool(), run=transport, enrollment="/protected/registry.json", runtime=runtime, gate=gate)
            self.assertTrue(result["open"], result)
            self.assertEqual(result["status"], "completed")
            self.assertFalse(result["requires_reconciliation"])
            record = json.loads(Path(result["receipt"]).read_text())
            self.assertEqual(record["controller_authority"]["trust_snapshot"], dict(frozen))
            self.assertEqual(set(record["worker_stop"]), {"worker", "second"})
            self.assertEqual(set(record["fleet_health"]), {"controller", "worker", "second"})
            for name in ("worker", "second"):
                for action in ("update-capabilities", "stop-update", "stopped-identity", "activate", "check", "health-update", "finish-update"):
                    self.assertIn((name, action), remote_actions)
                self.assertEqual(record["worker_stop"][name]["attempt_id"], result["attempt_id"])
            self.assertEqual(sum(args[:3] == ["nix", "copy", "--to"] for args in calls), 2)
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
                            and 'stop-update' in shlex.split(args[-1])):
                        state["failure_index"] = len(run.calls)
                        response = json.loads(result)
                        response['node_identity'] = {**before, key: value}
                        return json.dumps(response)
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
                    self.assertTrue(all(value.get('status') != 'verified' for value in result['nodes'].values()))
                    self.assertFalse(json.loads(gate.read_text())["open"])
                    self.assertEqual(run.calls[state["failure_index"]:], [])
                    self.assertFalse(any(args[:3] == ["nix", "copy", "--to"] or "State=RESUME" in args or
                                         (args[0] == "ssh" and (" activate " in args[-1] or " check " in args[-1]))
                                         for args in run.calls))
                    receipt = json.loads(Path(result["receipt"]).read_text())
                    self.assertEqual(receipt["status"], "failed")
                    self.assertTrue(receipt["requires_reconciliation"])
                    self.assertEqual(receipt["node_bindings"]["worker"], before)
                    self.assertEqual(receipt['stopped_observation_failure']['node'], 'worker')
                    self.assertEqual(receipt['stopped_observation_failure']['action'], 'stop-update')
                    calls_before = list(run.calls)
                    with self.assertRaisesRegex(RuntimeError, "reconciliation"):
                        ops.deliver_cli(manifest_fixture(), selected, run=drift_after_quiesce,
                            enrollment="/protected/registry.json", runtime=runtime, gate=gate)
                    self.assertEqual(run.calls, calls_before)



class WorkerAliasResponseTests(unittest.TestCase):
    """Native-format compatibility at the existing daemon identity boundary."""
    def bind(self, aliases):
        files = {"/protected/slurm.conf": b"synthetic static config",
                 "/proc/42/cmdline": b"/nix/store/slurm/bin/slurmd\0-D\0-s\0",
                 "/proc/42/environ": b"SLURM_CONF=/protected/slurm.conf\0"}
        calls = []
        def system(args):
            calls.append(args)
            if args[0] == "systemctl":
                return "MainPID=42\nInvocationID=" + "f" * 32 + "\nEnvironment=SLURM_CONF=/protected/slurm.conf"
            self.assertEqual(args, ["env", "SLURM_CONF=/protected/slurm.conf", "scontrol", "show", "aliases", "worker.invalid"])
            return aliases
        with patch.object(ops, "local_metadata", lambda path, limit=16384: files[str(path)]), \
             patch.object(ops, "slurmd_pids", lambda: [42]):
            node, daemon = ops.worker_daemon_binding({"slurm_conf": "/protected/slurm.conf"}, "worker.invalid", system)
        self.assertEqual(daemon[1]["MainPID"], "42")
        self.assertEqual(daemon[1]["InvocationID"], "f" * 32)
        self.assertEqual(daemon[3], ("/protected/slurm.conf",))
        return node

    def test_native_single_name_and_legacy_label_bind_same_canonical_node(self):
        for response in ("worker", "worker\n", "NodeName=worker", "NodeName=worker\n"):
            with self.subTest(response=response):
                try:
                    node = self.bind(response)
                except ValueError as error:
                    self.fail(f"Supported native alias response was rejected: {error}")
                self.assertEqual(node, "worker")

    def test_ambiguous_or_unrecognized_alias_output_is_rejected(self):
        for response in ("", "\n", "worker\nother\n", "worker,other\n", " worker\n", "worker \n",
                         "worker\n\n", "worker\t", "worker other", "NodeName=worker extra",
                         "NodeName=worker,other", " NodeName=worker", "NodeName=worker ", "NodeName=worker\n\n", "NodeAddr=worker", "NodeName=", "worker\r\n", "-worker",
                         "w" * 65):
            with self.subTest(response=response):
                with self.assertRaisesRegex(ValueError, "ambiguous/missing canonical aliases"):
                    self.bind(response)

if __name__ == "__main__":
    unittest.main()
