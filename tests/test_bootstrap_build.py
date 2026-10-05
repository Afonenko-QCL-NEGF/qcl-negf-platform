"""Bootstrap boundaries use local files/processes, never Nix or a server."""
import importlib.util
import os
from pathlib import Path
import sys
import pytest

SOURCE = Path(__file__).parents[1] / "ops/bootstrap_build.py"


def load():
    assert SOURCE.exists(), "Missing reusable bootstrap preflight/accounting helper"
    spec = importlib.util.spec_from_file_location("bootstrap_build", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_accounting_includes_history_deduplicates_hardlinks_and_qcow_holes(tmp_path, monkeypatch):
    m = load()
    monkeypatch.setattr(m.os, "geteuid", lambda: 0)
    roots = [tmp_path / name for name in ("store", "releases", "artifacts")]
    for root in roots:
        root.mkdir()
    history = roots[1] / "old-root-only-history"
    history.mkdir(mode=0o700)
    payload = history / "old.bin"
    payload.write_bytes(b"x" * 8192)
    os.link(payload, roots[0] / "shared.bin")
    image = roots[2] / "ci.qcow2"
    with image.open("wb") as stream:
        stream.truncate(1024 * 1024)
    value = m.account(roots, [image], 2 * 1024 * 1024, "/usr/bin/du")
    assert value["sparse_extra_bytes"] == 1024 * 1024
    assert value["combined_bytes"] == value["allocated_bytes"] + 1024 * 1024
    with pytest.raises(ValueError, match="disk budget"):
        m.account(roots, [image], 1024, "/usr/bin/du")


def test_unprivileged_accounting_fails_before_process(tmp_path, monkeypatch):
    m = load()
    monkeypatch.setattr(m.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(m, "run", lambda *a, **k: pytest.fail("process invoked"))
    with pytest.raises(ValueError, match="root"):
        m.account([tmp_path], [], 100, "/usr/bin/du")


def test_failed_command_retains_diagnostics():
    m = load()
    with pytest.raises(m.CommandFailure) as error:
        m.run([sys.executable, "-c", "import sys; print('primary diagnostic',file=sys.stderr); sys.exit(7)"], 5, 4096)
    assert error.value.record["exit_code"] == 7
    assert "primary diagnostic" in error.value.record["stderr"]


def test_combined_output_and_deadline_are_bounded():
    m = load()
    for source, cap in [("import sys; sys.stdout.write('x'*8192); sys.stderr.write('y'*8192)", 1024),
                        ("import time; time.sleep(5)", 1024)]:
        with pytest.raises(m.CommandFailure) as error:
            m.run([sys.executable, "-c", source], 0.15, cap)
        assert error.value.record["failure"] in ("output limit", "deadline")
        assert len(error.value.record["stdout"].encode()) + len(error.value.record["stderr"].encode()) <= cap


def test_preflight_rejects_missing_role_or_unvalidated_nginx():
    m = load()
    good = {"roles": {name: "/nix/store/" + "a" * 32 + "-system.drv" for name in ("storage", "control", "compute", "ci")},
            "nginx": {"enabled": True, "validated": True, "targets": ["/nix/store/" + "b" * 32 + "-nginx.conf.drv^out"]}}
    assert m.validate_preflight(good) == good
    for change in ({"roles": {"ci": good["roles"]["ci"]}},
                   {"nginx": {"enabled": True, "validated": False, "targets": []}}):
        with pytest.raises(ValueError):
            m.validate_preflight({**good, **change})


def test_preflight_rejects_non_nginx_build_target():
    m = load()
    good = {"roles": {name: "/nix/store/" + "a" * 32 + "-system.drv" for name in ("storage", "control", "compute", "ci")},
            "nginx": {"enabled": True, "validated": True, "targets": ["/nix/store/" + "b" * 32 + "-system.drv^out"]}}
    with pytest.raises(ValueError, match="nginx.conf"):
        m.validate_preflight(good)


def test_accounting_rejects_symlink_parent_escape(tmp_path, monkeypatch):
    m = load()
    monkeypatch.setattr(m.os, "geteuid", lambda: 0)
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir(); outside.mkdir()
    (outside / "image.qcow2").write_bytes(b"x")
    (root / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="inside"):
        m.account([root], [root / "link/image.qcow2"], 1000000, "/usr/bin/du")


def test_accounting_rejects_image_changed_during_du(tmp_path, monkeypatch):
    m = load()
    monkeypatch.setattr(m.os, "geteuid", lambda: 0)
    image = tmp_path / "image.qcow2"
    image.write_bytes(b"x")
    original = m.run
    def mutate(*args, **kwargs):
        record = original(*args, **kwargs)
        image.write_bytes(b"x" * 8192)
        return record
    monkeypatch.setattr(m, "run", mutate)
    with pytest.raises(ValueError, match="changed"):
        m.account([tmp_path], [image], 1000000, "/usr/bin/du")
