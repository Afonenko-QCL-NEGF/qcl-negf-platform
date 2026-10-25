"""Offline controls of the owning wrapper; synthetic mount facts are not NFS proof."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


@pytest.fixture(scope="module")
def saved_scripts():
    nixpkgs = os.environ.get("QCL_TEST_NIXPKGS")
    if not nixpkgs:
        pytest.skip("QCL_TEST_NIXPKGS required; no install or NixOS evaluation")
    fixture = Path(__file__).parent / "infrastructure/application-saved-results.nix"
    expression = f"import (builtins.toPath {json.dumps(str(fixture))}) {{ nixpkgs = builtins.toPath {json.dumps(nixpkgs)}; }}"
    result = subprocess.run(
        ["nix-instantiate", "--eval", "--strict", "--json", "--expr", expression],
        check=True, capture_output=True, text=True, timeout=60,
    )
    return json.loads(result.stdout)


def test_saved_results_enabled_controls_are_live(saved_scripts):
    enabled, disabled = saved_scripts["enabled"], saved_scripts["disabled"]
    assert "findmnt -rn -M /run/qcl-negf-saved -o SOURCE" in enabled
    assert "findmnt -rn -M /run/qcl-negf-saved -o OPTIONS" in enabled
    assert "storage:/srv/qcl-negf/jobs" in enabled
    assert "storage-test-identity" in enabled
    assert "export QCL_NEGF_SAVED_RESULTS_BINDING_FILE=" in enabled
    assert "findmnt" not in disabled
    assert "export QCL_NEGF_SAVED_RESULTS_BINDING_FILE=" not in disabled
    assert "unset QCL_NEGF_SAVED_RESULTS_BINDING_FILE" in disabled


@pytest.mark.parametrize("condition", [
    "healthy", "missing-mount", "local-root", "foreign-export", "writable-alias",
    "wrong-identity", "missing-identity", "foreign-uid", "writable-identity",
    "symlink-root", "foreign-application", "disabled",
])
def test_saved_results_wrapper_has_no_local_or_inherited_fallback(saved_scripts, tmp_path, condition):
    """Run the actual wrapper with literal mount facts and a tiny external API."""
    application = tmp_path / "application"
    binary = application / "bin/qcl-negf-api"
    binary.parent.mkdir(parents=True)
    binary.write_text(f"#!{sys.executable}\nimport json, os\n"
                      "print(json.dumps(os.environ.get('QCL_NEGF_SAVED_RESULTS_BINDING_FILE')))\n")
    binary.chmod(0o755)
    profile = tmp_path / "profile"
    foreign = tmp_path / "foreign"
    if condition == "foreign-application":
        foreign_binary = foreign / "bin/qcl-negf-api"
        foreign_binary.parent.mkdir(parents=True)
        foreign_binary.write_text(binary.read_text())
        foreign_binary.chmod(0o755)
    profile.symlink_to(foreign if condition == "foreign-application" else application)
    root = tmp_path / "jobs"
    root.mkdir()
    if condition == "symlink-root":
        root.rmdir()
        target = tmp_path / "other-jobs"
        target.mkdir()
        root.symlink_to(target)
    alias = tmp_path / "alias"
    alias.mkdir()
    identity = tmp_path / "identity"
    if condition != "missing-identity":
        identity.write_text("wrong" if condition == "wrong-identity" else "storage-test-identity\n")
        identity.chmod(0o666 if condition == "writable-identity" else 0o644)
    tools = tmp_path / "tools"
    tools.mkdir()
    findmnt = tools / "findmnt"
    findmnt.write_text(f"#!{sys.executable}\nimport sys\n"
        f"condition = {condition!r}\n"
        "if condition == 'missing-mount': raise SystemExit(1)\n"
        "field = sys.argv[-1]\n"
        "print({'FSTYPE': 'ext4' if condition == 'local-root' else 'nfs4',\n"
        "       'SOURCE': 'foreign:/export' if condition == 'foreign-export' else 'storage:/srv/qcl-negf/jobs',\n"
        "       'OPTIONS': 'rw,hard' if condition == 'writable-alias' else 'ro,hard'}[field])\n")
    findmnt.chmod(0o755)
    stat = tools / "stat"
    stat.write_text(f"#!{sys.executable}\nimport os, sys\n"
        f"condition = {condition!r}\n"
        "info = os.stat(sys.argv[-1])\n"
        "print({'%u': 999 if condition == 'foreign-uid' else 0,\n"
        "       '%s': info.st_size, '%a': oct(info.st_mode & 0o777)[2:]}[sys.argv[-2]])\n")
    stat.chmod(0o755)
    script = saved_scripts["disabled" if condition == "disabled" else "enabled"]
    replacements = {
        "/nix/var/nix/profiles/qcl-negf-application": str(profile),
        "/nix/store/synthetic-application": str(application),
        "/srv/qcl-negf/jobs": str(root),
        "/run/qcl-negf-saved": str(alias),
        "/run/site/saved-storage-identity": str(identity),
        "/synthetic-util-linux/bin/findmnt": str(findmnt),
        "/synthetic-coreutils/bin/stat": str(stat),
    }
    # Preserve the literal NFS export while substituting only local operands.
    script = script.replace("storage:/srv/qcl-negf/jobs", "__EXPECTED_EXPORT__")
    for old, new in replacements.items():
        script = script.replace(old, new)
    script = script.replace("__EXPECTED_EXPORT__", "storage:/srv/qcl-negf/jobs")
    for command in ("readlink", "cat"):
        executable = shutil.which(command)
        assert executable
        script = script.replace(f"/synthetic-coreutils/bin/{command}", executable)
    result = subprocess.run(["/bin/sh", "-c", script], env={
        "PATH": "/usr/bin:/bin", "QCL_NEGF_SAVED_RESULTS_BINDING_FILE": "/stale/untrusted.json",
    }, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == ("/synthetic-binding.json" if condition == "healthy" else None)
