"""Socket bootstrap without a PostgreSQL server or storage initialisation."""
import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

import pytest
pytest.importorskip("aiida", reason="Profile integration requires the application Python environment")
from aiida.manage.configuration import Profile
from aiida.manage.configuration.config import Config
from aiida.storage.psql_dos.backend import PsqlDosBackend
from aiida.storage.psql_dos.utils import create_sqlalchemy_engine

spec = importlib.util.spec_from_file_location(
    "bootstrap_profile", Path(__file__).parents[1] / "ops/bootstrap_profile.py")
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


def test_raw_socket_connect_args_reach_installed_dialect_without_uri_corruption():
    storage = bootstrap.storage_config()
    engine = create_sqlalchemy_engine(storage)
    with patch("psycopg.connect", side_effect=lambda **kwargs: kwargs):
        parameters = engine.pool._creator()
    assert parameters["host"] == "/run/postgresql"
    assert parameters["dbname"] == "qcl-negf"
    assert parameters["port"] == 5432
    assert parameters["user"] == "qcl-negf"
    assert storage["database_hostname"] == "/run/postgresql"


def test_cold_profile_stores_supported_runtime_config_with_public_lifecycle(tmp_path):
    config = Config(str(tmp_path / "config.json"), {})
    with patch.object(bootstrap, "require_empty_storage"), \
            patch.object(PsqlDosBackend, "initialise") as initialise, \
            patch.object(bootstrap, "create_default_user"):
        bootstrap.reconcile(config, "research@example.org")
    profile = config.get_profile("qcl-negf")
    initialise.assert_called_once_with(profile, reset=False)
    stored = json.loads((tmp_path / "config.json").read_text())
    assert stored["profiles"]["qcl-negf"]["storage"]["config"]["engine_kwargs"] == {
        "connect_args": {"host": "/run/postgresql", "dbname": "qcl-negf", "port": 5432}}
    assert config.default_profile_name == "qcl-negf"


def test_warm_profile_preserves_uuid_and_does_not_initialise_storage(tmp_path):
    config = Config(str(tmp_path / "config.json"), {})
    storage = bootstrap.storage_config()
    storage.pop("engine_kwargs")
    profile = Profile("qcl-negf", {"storage": {"backend": "core.psql_dos", "config": storage},
                                 "process_control": {"backend": "core.zeromq", "config": None}})
    config.add_profile(profile)
    identity = profile.uuid
    with patch.object(PsqlDosBackend, "initialise", side_effect=AssertionError("Never reset")), \
            patch.object(bootstrap, "create_default_user", side_effect=AssertionError("Preserve users")):
        bootstrap.reconcile(config, "research@example.org")
    assert config.get_profile("qcl-negf").uuid == identity
    assert config.get_profile("qcl-negf").storage_config["engine_kwargs"]["connect_args"]["host"] == "/run/postgresql"


def test_nonempty_or_partial_repository_is_never_cleared(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    original = repository / "config.json"
    original.write_bytes(b"original container identity")
    with pytest.raises(ValueError, match="repository"):
        bootstrap.require_empty_repository(repository)
    assert original.read_bytes() == b"original container identity"


@pytest.mark.parametrize("override", [
    {"host": "different-host"}, {"user": "different-user"},
    {"password": "different-password"}, {"service": "another-service"},
])
def test_conflicting_warm_connection_override_is_rejected(tmp_path, override):
    config = Config(str(tmp_path / "config.json"), {})
    storage = bootstrap.storage_config()
    storage["engine_kwargs"]["connect_args"].update(override)
    config.add_profile(Profile("qcl-negf", {
        "storage": {"backend": "core.psql_dos", "config": storage},
        "process_control": {"backend": "core.zeromq", "config": None}}))
    with pytest.raises(ValueError, match="connect_args"):
        bootstrap.reconcile(config, "research@example.org")
