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
            self.shebang = "#!/bin/bash"

        def get_workdir(self):
            return self.workdir

        def get_default_mpiprocs_per_machine(self):
            return self.mpiprocs

        def set_default_mpiprocs_per_machine(self, value):
            self.mpiprocs = value

        def get_shebang(self):
            return self.shebang

        def set_shebang(self, value):
            self.shebang = value

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
    def test_mutable_solver_path_is_rejected_before_any_provenance_object_is_stored(self):
        orm, manager, stored, _failure = adapter()
        with self.assertRaisesRegex(ValueError, "immutable"):
            registration.reconcile(orm, manager, "research@example.org",
                                   "/nix/var/nix/profiles/solver/bin/qcl-negf", "qcl-negf")
        self.assertEqual(stored, {"users": {}, "computers": [], "codes": []})

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

    def test_new_computer_declares_nixos_batch_interpreter(self):
        orm, manager, stored, _failure = adapter()
        registration.reconcile(orm, manager, "research@example.org", "/nix/store/one/bin/qcl-negf", "qcl-negf")
        self.assertEqual(stored["computers"][0].get_shebang(), "#!/run/current-system/sw/bin/bash")

    def test_new_computer_renders_nixos_interpreter_in_slurm_script(self):
        # Characterize the real AiiDA 2.9 scheduler boundary that rejected NEG2.
        # No database, profile, transport, scheduler submission or solver is used.
        import pytest
        pytest.importorskip("aiida", reason="Real renderer requires the application test environment")
        from aiida.common.datastructures import CodeRunMode
        from aiida.schedulers.datastructures import JobTemplate
        from aiida.schedulers.plugins.slurm import SlurmScheduler
        orm, manager, stored, _failure = adapter()
        registration.reconcile(orm, manager, "research@example.org", "/nix/store/one/bin/qcl-negf", "qcl-negf")
        template = JobTemplate()
        template.shebang = stored["computers"][0].get_shebang()
        scheduler = SlurmScheduler()
        template.job_resource = scheduler.create_job_resource(num_machines=1,
            num_mpiprocs_per_machine=1, num_cores_per_mpiproc=1)
        template.codes_info = []
        template.codes_run_mode = CodeRunMode.SERIAL
        script = scheduler.get_submit_script(template)
        self.assertEqual(script.splitlines()[0], "#!/run/current-system/sw/bin/bash")

    def test_existing_legacy_interpreter_fails_without_mutating_provenance(self):
        orm, manager, stored, _failure = adapter()
        original = registration.reconcile(orm, manager, "research@example.org", "/nix/store/one/bin/qcl-negf", "qcl-negf")
        computer = stored["computers"][0]
        computer.set_shebang("#!/bin/bash")
        with self.assertRaisesRegex(ValueError, "shebang"):
            registration.reconcile(orm, manager, "research@example.org", "/nix/store/one/bin/qcl-negf", "qcl-negf")
        self.assertEqual(computer.get_shebang(), "#!/bin/bash")
        self.assertEqual(computer.uuid, original["computer_uuid"])
        self.assertEqual(stored["codes"][0].uuid, original["code_uuid"])
        self.assertEqual((len(stored["computers"]), len(stored["codes"])), (1, 1))

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
