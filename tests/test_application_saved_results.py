"""Offline controls of the owning wrapper; synthetic mount facts are not NFS proof."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

import pytest


@pytest.fixture(scope="module")
def saved_scripts():
    nixpkgs = os.environ.get("QCL_TEST_NIXPKGS")
    if not nixpkgs:
        pytest.skip("QCL_TEST_NIXPKGS required; no install or NixOS evaluation")
    fixture = Path(__file__).parent / "infrastructure/application-saved-results.nix"
    expression = f"import (builtins.toPath {json.dumps(str(fixture), ensure_ascii=False)}) {{ nixpkgs = builtins.toPath {json.dumps(nixpkgs)}; }}"
    result = subprocess.run(
        ["nix-instantiate", "--eval", "--strict", "--json", "--expr", expression],
        check=True, capture_output=True, text=True, timeout=60,
    )
    return json.loads(result.stdout)


@pytest.mark.parametrize("condition", [
    "healthy", "missing-mount", "local-root", "foreign-export", "writable-alias",
    "wrong-identity", "missing-identity", "foreign-uid", "writable-identity",
    "symlink-root", "disabled",
])
def test_saved_results_runtime_has_no_local_or_inherited_fallback(saved_scripts, tmp_path, condition):
    """Use the evaluated module envelope with the real bounded findmnt subprocess."""
    from test_runtime_bindings import runtime_module
    module = runtime_module()
    arguments = shlex.split(saved_scripts["disabled" if condition == "disabled" else "enabled"])
    configuration = json.loads(arguments[arguments.index("--config") + 1])
    if condition == "disabled":
        assert configuration["saved_results"] is None
        return
    settings = configuration["saved_results"]
    assert settings["nfs_source"] == "storage:/srv/qcl-negf/jobs"
    root, alias = tmp_path / "jobs", tmp_path / "alias"
    root.mkdir(); alias.mkdir()
    if condition == "symlink-root":
        root.rmdir(); root.symlink_to(alias)
    identity = tmp_path / "identity"
    if condition != "missing-identity":
        identity.write_text("wrong" if condition == "wrong-identity" else "storage-test-identity\n")
        identity.chmod(0o666 if condition == "writable-identity" else 0o644)
    binding = tmp_path / "binding.json"
    binding.write_text(json.dumps({"storage_identity":"storage-test-identity","root":str(alias)}))
    settings.update(root=str(root),alias=str(alias),binding_file=str(binding),storage_identity_file=str(identity))
    findmnt = tmp_path / "findmnt"
    findmnt.write_text(f"#!{sys.executable}\nimport sys\ncondition={condition!r}\n"
        "if condition == 'missing-mount': raise SystemExit(1)\n"
        "print({'FSTYPE':'ext4' if condition=='local-root' else 'nfs4',"
        "'SOURCE':'foreign:/export' if condition=='foreign-export' else 'storage:/srv/qcl-negf/jobs',"
        "'OPTIONS':'rw,hard' if condition=='writable-alias' else 'ro,hard'}[sys.argv[-1]])\n")
    findmnt.chmod(0o755)
    def run(argv, **bounds):
        if argv[0] == sys.executable:
            return module.command(argv, **bounds)
        assert argv[0] == "findmnt"
        return module.command([str(findmnt),*argv[1:]],**bounds)
    def protected(path, limit=65536):
        if Path(path)==identity and condition in ("foreign-uid","writable-identity"):
            raise ValueError("Synthetic untrusted identity boundary")
        return Path(path).read_bytes()
    if condition == "healthy":
        assert module.saved_results_binding(settings,run=run,read_protected=protected) == {
            "QCL_NEGF_SAVED_RESULTS_BINDING_FILE":str(binding)}
    else:
        with pytest.raises((ValueError,OSError,module.CommandFailure)):
            module.saved_results_binding(settings,run=run,read_protected=protected)
