"""Fault-injection check of reconciliation; no AiiDA/database install or solver.

The in-memory adapter models the public ORM operations used by this script.
This check cannot establish AiiDA/PostgreSQL compatibility on a deployed host.
"""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
import uuid

spec = importlib.util.spec_from_file_location(
    "registration", Path(__file__).parents[1] / "ops" / "register_aiida.py"
)
registration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(registration)


def adapter():
    stored = {"users": {}, "computers": [], "codes": []}
    failure = {"configure": False}

    class User:
        is_stored = False

        def __init__(self, email):
            self.email = email

        def store(self):
            self.is_stored = True
            stored["users"][self.email] = self
            return self

    class Users:
        def get_or_create(self, email):
            return (False, stored["users"][email]) if email in stored["users"] else (True, User(email))

    User.collection = Users()

    class Computer:
        def __init__(self, **values):
            self.__dict__.update(values)
            self.uuid = str(uuid.uuid4())
            self.mpiprocs = None
            self.configured = False

        def get_workdir(self):
            return self.workdir

        def get_default_mpiprocs_per_machine(self):
            return self.mpiprocs

        def set_default_mpiprocs_per_machine(self, value):
            self.mpiprocs = value

        def store(self):
            stored["computers"].append(self)
            return self

        def configure(self, **_values):
            if failure["configure"]:
                raise RuntimeError("interrupted before AuthInfo.store")
            self.configured = True

    class Code:
        pass

    class InstalledCode(Code):
        def __init__(self, **values):
            self.__dict__.update(values)
            self.uuid = str(uuid.uuid4())

        def store(self):
            stored["codes"].append(self)
            return self

    class QueryBuilder:
        def append(self, cls, filters):
            items = stored["computers" if cls is Computer else "codes"]
            self.items = [item for item in items if item.label == filters["label"]]
            return self

        def all(self, flat):
            assert flat
            return self.items

    orm = SimpleNamespace(User=User, Computer=Computer, Code=Code,
                          InstalledCode=InstalledCode, QueryBuilder=QueryBuilder)
    manager = SimpleNamespace(get_profile=lambda: SimpleNamespace(name="qcl-negf"),
                              set_default_user_email=lambda *_args: None)
    return orm, manager, stored, failure


class RegistrationTests(unittest.TestCase):
    def test_retry_after_auth_failure_reuses_both_uuid_and_completes_configuration(self):
        orm, manager, stored, failure = adapter()
        failure["configure"] = True
        with self.assertRaisesRegex(RuntimeError, "interrupted"):
            registration.reconcile(orm, manager, "research@example.org", "/nix/store/one/bin/qcl-negf", "qcl-negf")
        original = (stored["computers"][0].uuid, stored["codes"][0].uuid)
        failure["configure"] = False
        identity = registration.reconcile(orm, manager, "research@example.org", "/nix/store/one/bin/qcl-negf", "qcl-negf")
        repeated = registration.reconcile(orm, manager, "research@example.org", "/nix/store/one/bin/qcl-negf", "qcl-negf")
        self.assertEqual(identity, repeated)
        self.assertEqual((identity["computer_uuid"], identity["code_uuid"]), original)
        self.assertEqual((len(stored["computers"]), len(stored["codes"])), (1, 1))
        self.assertTrue(stored["computers"][0].configured)

    def test_same_label_for_different_solver_fails_without_replacing_code(self):
        orm, manager, stored, _failure = adapter()
        first = registration.reconcile(orm, manager, "research@example.org", "/nix/store/one/bin/qcl-negf", "qcl-negf")
        with self.assertRaisesRegex(ValueError, "different solver"):
            registration.reconcile(orm, manager, "research@example.org", "/nix/store/two/bin/qcl-negf", "qcl-negf")
        self.assertEqual(stored["codes"][0].uuid, first["code_uuid"])
        self.assertEqual(len(stored["codes"]), 1)

    def test_existing_computer_configuration_mismatch_is_not_silently_changed(self):
        orm, manager, stored, _failure = adapter()
        registration.reconcile(orm, manager, "research@example.org", "/nix/store/one/bin/qcl-negf", "qcl-negf")
        stored["computers"][0].workdir = "/different"
        with self.assertRaisesRegex(ValueError, "differs"):
            registration.reconcile(orm, manager, "research@example.org", "/nix/store/one/bin/qcl-negf", "qcl-negf")
        self.assertEqual(stored["computers"][0].workdir, "/different")

    def test_identity_publication_replaces_complete_file_with_owner_only_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "code-uuid"
            path.write_text("old\n")
            registration.publish(path, "new\n")
            self.assertEqual(path.read_text(), "new\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(Path(directory).iterdir()), [path])


if __name__ == "__main__":
    unittest.main()
