"""Called by verdi run after profile setup. No scientific execution or migration.

Each stored entity is queried on retry. An existing label with different settings
fails closed: provenance objects are never relabelled, replaced or deleted.
"""
import json
import os
from pathlib import Path
import re
import sys
import tempfile


NIXOS_BATCH_SHEBANG = "#!/run/current-system/sw/bin/bash"


def reconcile(orm, manager, email, executable, label):
    if not re.fullmatch(r"/nix/store/[A-Za-z0-9][A-Za-z0-9+._?-]*/bin/qcl-negf", executable):
        raise ValueError("InstalledCode requires an immutable /nix/store/.../bin/qcl-negf executable")
    profile = manager.get_profile()
    if profile.name != "qcl-negf":
        raise ValueError("Bootstrap requires the qcl-negf profile")
    user = orm.User.collection.get_or_create(email=email)[1]
    if not user.is_stored:
        user.first_name, user.last_name, user.institution = "Research", "Service", "QCL-NEGF"
        user.store()
    manager.set_default_user_email(profile, email)

    computers = orm.QueryBuilder().append(orm.Computer, filters={"label": "slurm"}).all(flat=True)
    if len(computers) > 1:
        raise ValueError("Ambiguous slurm computer label")
    if computers:
        computer = computers[0]
        actual = (computer.hostname, computer.transport_type, computer.scheduler_type,
                  computer.get_workdir(), computer.get_default_mpiprocs_per_machine(), computer.get_shebang())
        if actual != ("localhost", "core.local", "core.slurm", "/srv/qcl-negf/jobs", 1, NIXOS_BATCH_SHEBANG):
            raise ValueError("Existing slurm computer differs from declared local transport/scheduler/shebang")
    else:
        computer = orm.Computer(label="slurm", hostname="localhost", transport_type="core.local",
                                scheduler_type="core.slurm", workdir="/srv/qcl-negf/jobs")
        computer.set_default_mpiprocs_per_machine(1)
        computer.set_shebang(NIXOS_BATCH_SHEBANG)
        computer.store()

    codes = orm.QueryBuilder().append(orm.Code, filters={"label": label}).all(flat=True)
    if len(codes) > 1:
        raise ValueError("Ambiguous installed Code label")
    if codes:
        code = codes[0]
        if (not isinstance(code, orm.InstalledCode) or code.computer.uuid != computer.uuid
                or str(code.filepath_executable) != executable
                or code.default_calc_job_plugin != "qcl_negf.execution" or code.with_mpi is not False):
            raise ValueError("Code label already identifies a different solver; declare a new label")
    else:
        code = orm.InstalledCode(label=label, computer=computer, filepath_executable=executable,
                                 default_calc_job_plugin="qcl_negf.execution", with_mpi=False).store()

    # The local transport has a valid auth parameter; this stores AuthInfo even
    # after a failure between Computer.store() and configure(). No login PATH is
    # assumed: service PATH includes the immutable Slurm tools explicitly.
    computer.configure(user=user, use_login_shell=False)
    return {"profile": profile.name, "computer_uuid": computer.uuid,
            "code_uuid": code.uuid, "code_label": label, "solver_executable": executable}


def publish(path, value):
    """Atomically publish identity/readiness only after all reconciliation succeeds."""
    path = Path(path)
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    from aiida import orm
    from aiida.manage import get_manager

    if len(sys.argv) != 4:
        raise SystemExit("Expected service email, immutable solver executable and Code label")
    email, executable, label = sys.argv[1:]
    if not Path(executable).is_file() or not os.access(executable, os.X_OK):
        raise SystemExit("Immutable solver executable must be installed on the controller")
    identity = reconcile(orm, get_manager(), email, executable, label)
    directory = Path(os.environ["AIIDA_PATH"])
    publish(directory / "bootstrap.json", json.dumps(identity, sort_keys=True) + "\n")
    publish(directory / "code-uuid", identity["code_uuid"] + "\n")
    print(json.dumps(identity, sort_keys=True))
