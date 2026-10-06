"""Reconcile the declared peer-authenticated Unix-socket AiiDA profile.

The AiiDA profile CLI normalises away engine_kwargs. Its public Profile and
storage lifecycle retain this supported field. Never initialise an existing
profile, nonempty database, or even a partial object-store container.
"""
import argparse
from copy import deepcopy
import fcntl
import os
from pathlib import Path

BASE = {
    "database_hostname": "/run/postgresql", "database_port": 5432,
    "database_username": "qcl-negf", "database_password": "",
    "database_name": "qcl-negf",
    "repository_uri": "file:///var/lib/qcl-negf/aiida/repository",
}
CONNECT = {"host": "/run/postgresql", "dbname": "qcl-negf", "port": 5432}


def storage_config():
    from aiida.storage.psql_dos.backend import PsqlDosBackend
    storage = PsqlDosBackend.CliModel(**BASE).model_dump()
    storage["engine_kwargs"] = {"connect_args": dict(CONNECT)}
    return storage


def require_empty_repository(repository):
    repository = Path(repository)
    if repository.is_symlink() or (repository.exists() and not repository.is_dir()):
        raise ValueError("Existing repository requires manual inspection; never clear it")
    if repository.exists() and any(repository.iterdir()):
        raise ValueError("Nonempty or partial repository requires manual inspection; never clear it")


def require_empty_storage():
    import psycopg
    repository = Path("/var/lib/qcl-negf/aiida/repository")
    require_empty_repository(repository)
    with psycopg.connect(**CONNECT, user="qcl-negf", connect_timeout=3,
                         options="-c default_transaction_read_only=on") as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_user, current_database(), "
                           "current_setting('transaction_read_only'), "
                           "(SELECT count(*) FROM pg_class r JOIN pg_namespace n "
                           "ON n.oid=r.relnamespace WHERE n.nspname <> 'pg_catalog' "
                           "AND n.nspname NOT LIKE 'pg_toast%' "
                           "AND n.nspname <> 'information_schema' "
                           "AND r.relkind IN ('r','p','v','m','S','f'))")
            if cursor.fetchone() != ("qcl-negf", "qcl-negf", "on", 0):
                raise ValueError("Peer identity or empty database guard failed; never initialise")
        connection.rollback()
    require_empty_repository(repository)


def create_default_user(*args, **kwargs):
    from aiida.manage.configuration import create_default_user as create
    return create(*args, **kwargs)


def reconcile(config, email):
    from aiida.manage.configuration import Profile
    from aiida.storage.psql_dos.backend import PsqlDosBackend
    if "qcl-negf" in config.profile_names:
        profile = config.get_profile("qcl-negf")
        storage = deepcopy(profile.storage_config)
        if (profile.storage_backend != "core.psql_dos" or
                profile.process_control_backend != "core.zeromq" or
                any(storage.get(key) != value for key, value in BASE.items())):
            raise ValueError("Existing profile differs from the declared local storage/broker")
        engine_kwargs = storage.setdefault("engine_kwargs", {})
        if not isinstance(engine_kwargs, dict):
            raise ValueError("Existing engine_kwargs must be a mapping")
        connect_args = engine_kwargs.setdefault("connect_args", {})
        identity = {**CONNECT, "user": BASE["database_username"], "password": BASE["database_password"]}
        if (not isinstance(connect_args, dict) or
                any(key in connect_args and connect_args[key] != value for key, value in identity.items()) or
                any(key in connect_args for key in ("service", "hostaddr", "dsn"))):
            raise ValueError("Existing connect_args differs from the declared Unix socket")
        connect_args.update(CONNECT)
        profile.set_storage("core.psql_dos", storage)
        config.update_profile(profile)
        config.store()
        return
    require_empty_storage()
    profile = Profile("qcl-negf", {
        "storage": {"backend": "core.psql_dos", "config": storage_config()},
        "process_control": {"backend": "core.zeromq", "config": None}, "test_profile": False,
    })
    # reset=False alone is insufficient: AiiDA may internally clear a partial
    # repository. The empty-storage guard above excludes all such containers.
    PsqlDosBackend.initialise(profile, reset=False)
    config.add_profile(profile)
    config.store()
    create_default_user(profile, email, first_name="Research", last_name="Service", institution="QCL-NEGF")
    config.set_default_profile("qcl-negf", overwrite=True)
    config.store()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("email")
    args = parser.parse_args()
    root = Path("/var/lib/qcl-negf")
    if os.getuid() == 0 or os.getuid() != root.stat().st_uid:
        raise ValueError("Run profile bootstrap as the qcl-negf service account")
    if os.environ.get("AIIDA_PATH") != str(root / "aiida"):
        raise ValueError("Use the declared AIIDA_PATH")
    from aiida.manage.configuration import get_config
    with (root / "aiida/.bootstrap-profile.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        reconcile(get_config(create=True), args.email)


if __name__ == "__main__":
    main()
