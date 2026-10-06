"""Cold storage guards also run in the minimal platform test environment."""
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

spec = importlib.util.spec_from_file_location(
    "bootstrap_profile_guard", Path(__file__).parents[1] / "ops/bootstrap_profile.py")
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


@pytest.mark.parametrize("kind", ["data", "partial", "symlink", "fifo"])
def test_every_existing_repository_kind_is_preserved_instead_of_initialised(tmp_path, kind):
    import os
    repository = tmp_path / "repository"
    repository.mkdir()
    if kind in ("data", "partial"):
        (repository / ("scientific-object" if kind == "data" else "config.json")).write_bytes(b"keep")
    elif kind == "symlink":
        repository.rmdir()
        repository.symlink_to(tmp_path, target_is_directory=True)
    else:
        repository.rmdir()
        os.mkfifo(repository)
    before = repository.lstat()
    with pytest.raises(ValueError, match="repository"):
        bootstrap.require_empty_repository(repository)
    assert repository.lstat().st_ino == before.st_ino
    if kind in ("data", "partial"):
        assert next(repository.iterdir()).read_bytes() == b"keep"


@pytest.mark.parametrize("catalog", [
    ("qcl-negf", "qcl-negf", "on", 1),
    ("other-user", "qcl-negf", "on", 0),
    ("qcl-negf", "other-database", "on", 0),
    ("qcl-negf", "qcl-negf", "off", 0),
])
def test_nonempty_database_wrong_peer_or_write_transaction_blocks_initialisation(tmp_path, catalog):
    connection = MagicMock()
    connection.__enter__.return_value = connection
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = catalog
    connect = MagicMock(return_value=connection)
    with patch.dict(sys.modules, {"psycopg": SimpleNamespace(connect=connect)}), \
            patch.object(bootstrap, "Path", return_value=tmp_path):
        with pytest.raises(ValueError, match="database guard"):
            bootstrap.require_empty_storage()
    assert connect.call_args.kwargs["options"] == "-c default_transaction_read_only=on"
    assert connect.call_args.kwargs["host"] == "/run/postgresql"
    assert connect.call_args.kwargs["dbname"] == "qcl-negf"


def test_absolutely_empty_repository_can_be_created_without_touching_other_files(tmp_path):
    existing = tmp_path / "unrelated"
    existing.write_bytes(b"keep")
    repository = tmp_path / "repository"
    bootstrap.require_empty_repository(repository)
    repository.mkdir()
    bootstrap.require_empty_repository(repository)
    assert existing.read_bytes() == b"keep"
