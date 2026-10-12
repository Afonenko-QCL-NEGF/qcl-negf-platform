"""Protected admin consumers remain usable beside a service-owned AiiDA home."""
import stat
import unittest
from test_node_enrollment import FakeProtectedFS, ops


class AdminNamespaceTests(unittest.TestCase):
    def namespace(self):
        fs = FakeProtectedFS()
        # Handwritten native ownership model: the service DATA bind is not root-owned.
        for path, uid, mode in [("/var", 0, 0o755), ("/var/lib", 0, 0o755),
                                ("/var/lib/qcl-negf", 3000, 0o750),
                                ("/var/lib/qcl-negf/runtime", 0, 0o755),
                                ("/var/lib/qcl-negf/trust-snapshots", 0, 0o700),
                                ("/var/lib/qcl-negf-admin", 0, 0o755),
                                ("/var/lib/qcl-negf-admin/runtime", 0, 0o755),
                                ("/var/lib/qcl-negf-admin/trust-snapshots", 0, 0o700)]:
            fs.nodes[path] = {"uid": uid, "mode": stat.S_IFDIR | mode}
        for parent in ("/var/lib/qcl-negf/runtime", "/var/lib/qcl-negf-admin/runtime"):
            fs.nodes[parent + "/update-stop.json"] = {
                "uid": 0, "mode": stat.S_IFREG | 0o600, "bytes": b'{"attempt_id":"own-stop"}'}
        return fs

    def test_default_trust_and_stop_marker_consumers_do_not_traverse_service_home(self):
        fs = self.namespace()
        with fs.patches():
            snapshot = ops.freeze_ssh_trust(b"public-host-key")
            actual = ops.read_protected_file(ops.RUNTIME / "update-stop.json")
        self.assertEqual(actual, b'{"attempt_id":"own-stop"}')
        self.assertEqual(fs.nodes[snapshot["path"]]["bytes"], b"public-host-key")
        self.assertFalse(any(path == "/var/lib/qcl-negf" for path, _, _ in fs.opens))

    def test_service_home_is_still_rejected_as_protected_ancestor(self):
        fs = self.namespace()
        with fs.patches(), self.assertRaisesRegex(ValueError, "Unprotected namespace"):
            ops.read_protected_file("/var/lib/qcl-negf/runtime/update-stop.json")

    def test_default_admin_consumers_reject_untrusted_ancestor(self):
        for uid, mode in ((3000, stat.S_IFDIR | 0o755), (0, stat.S_IFDIR | 0o775),
                          (0, stat.S_IFLNK | 0o777)):
            with self.subTest(uid=uid, mode=mode):
                fs = self.namespace()
                fs.nodes["/var/lib/qcl-negf-admin"] = {"uid": uid, "mode": mode}
                with fs.patches(), self.assertRaises((ValueError, OSError)):
                    ops.freeze_ssh_trust(b"public-host-key")
