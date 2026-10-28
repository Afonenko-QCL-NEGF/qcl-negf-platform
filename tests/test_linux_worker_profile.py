"""Real NixOS source evaluation; no image build or native host mutation."""
import json
import os
from pathlib import Path
import subprocess

import pytest


@pytest.fixture(scope="module")
def evaluate():
    source = os.environ.get("QCL_TEST_NIXPKGS")
    if not source:
        pytest.skip("Set QCL_TEST_NIXPKGS to the locked Nixpkgs source; no implicit fetch")
    path = Path(source)
    if not path.is_absolute() or not (path / "nixos/lib/eval-config.nix").is_file():
        pytest.fail("QCL_TEST_NIXPKGS must be an existing absolute Nixpkgs source")
    fixture = Path(__file__).parent / "infrastructure/linux-worker.nix"

    def run(variant="valid"):
        expression = (f"import (builtins.toPath {json.dumps(str(fixture), ensure_ascii=False)}) "
                      f"{{ nixpkgs = builtins.toPath {json.dumps(str(path), ensure_ascii=False)}; "
                      f"variant = {json.dumps(variant)}; }}")
        result = subprocess.run(["nix-instantiate", "--eval", "--strict", "--json", "--expr", expression],
                                capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    return run


def test_portable_profile_preserves_worker_storage_identity_and_native_devices(evaluate):
    value = evaluate()
    assert value["failures"] == []
    assert value["architecture"] == "x86_64-linux"
    assert value["worker"] and not value["controller"] and not value["submit"]
    assert value["privateInterface"] == "cluster0"
    assert value["scratch"]["device"] == "/dev/disk/by-id/virtio-qcl-scratch"
    assert value["scratch"]["autoFormat"] is False
    assert value["root"] == "/dev/disk/by-label/nixos"
    assert value["nfs"] == "storage:/srv/qcl-negf/jobs"
    assert value["boot"]["device"] == "/dev/vda"
    assert "virtio_balloon" in value["boot"]["kernelModules"]
    assert {"virtio_net", "virtio_pci", "virtio_blk"} <= set(value["boot"]["availableKernelModules"])
    assert value["guestAgent"] and value["sshPassword"] is False
    assert value["cloudInit"]["datasource_list"] == ["NoCloud", "ConfigDrive"]
    assert value["cloudInitNetwork"] is True
    assert value["munge"] == {"path": "/run/secrets/munge.key", "requires": ["site-munge.service"]}
    assert value["guard"].endswith("/bin/qcl-negf-release node-check")
    assert value["firewall"]["allowedTCPPorts"] == [6818]
    assert value["firewall"]["allowedTCPPortRanges"] == [value["ports"]]


def test_public_private_site_template_keeps_runtime_secret_and_release_bindings(evaluate):
    value = evaluate("example")
    assert value["failures"] == []
    assert value["munge"]["path"] == "/run/secrets/munge.key"
    assert value["munge"]["requires"] == ["site-worker-secrets.service"]
    assert value["scratch"]["autoFormat"] is False
    assert value["guard"].endswith("/bin/qcl-negf-release node-check")


@pytest.mark.parametrize("variant,reason", [
    ("controller", "Linux worker profile must not enable controller, submit, storage or CI roles."),
    ("submit", "Linux worker profile must not enable controller, submit, storage or CI roles."),
    ("disabled-release", "Linux worker profile requires the ordinary release admission guard."),
    ("missing-secret-unit", "Linux worker profile requires explicit runtime secret provisioning units."),
    ("wrong-architecture", "Linux/libvirt worker profile currently supports x86_64-linux only."),
])
def test_profile_refuses_unbound_or_unqualified_role(variant, reason, evaluate):
    assert reason in evaluate(variant)["failures"]
