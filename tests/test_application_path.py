"""Exercise child executable lookup in the module's real generated wrappers."""
import json
import os
from pathlib import Path
import pwd
import shutil
import shlex
import subprocess
import sys

import pytest


@pytest.fixture(scope="module")
def starts():
    nixpkgs = os.environ.get("QCL_TEST_NIXPKGS")
    if not nixpkgs:
        pytest.skip("QCL_TEST_NIXPKGS is supplied by the Nix operations check")
    fixture = Path(__file__).parent / "infrastructure" / "application-starts.nix"
    expression = f"import (builtins.toPath {json.dumps(str(fixture), ensure_ascii=False)}) {{ nixpkgs = builtins.toPath {json.dumps(nixpkgs)}; }}"
    result = subprocess.run(
        ["nix-instantiate", "--eval", "--strict", "--json", "--expr", expression],
        check=True, capture_output=True, text=True, timeout=60,
    )
    return json.loads(result.stdout)


def materialize_api(script, tmp_path, profile):
    """Run the real helper with an explicit synthetic trusted-profile boundary."""
    arguments = shlex.split(script)
    payload = arguments[arguments.index("--config") + 1]
    configuration = tmp_path / "launch.json"
    configuration.write_text(payload)
    bridge = tmp_path / "launch.py"
    operations = Path(__file__).parents[1] / "ops"
    bridge.write_text(
        f"import sys; sys.path.insert(0, {str(operations)!r})\n"
        "import json\nfrom pathlib import Path\nimport runtime_bindings as runtime\n"
        "configuration=json.loads(Path(sys.argv[sys.argv.index('--config')+1]).read_text())\n"
        f"profile=Path({str(profile)!r})\n"
        "def unavailable(_): raise FileNotFoundError('no synthetic release record')\n"
        "runtime.launch(configuration,port=int(sys.argv[sys.argv.index('--port')+1]),"
        "target=lambda _:str(profile.resolve(strict=True)),read_json=unavailable)\n"
    )
    return script.replace("/synthetic-python/bin/python3",sys.executable).replace(
        "/synthetic-operations/ops/runtime_bindings.py",str(bridge)).replace(
        shlex.quote(payload),str(configuration))


@pytest.mark.parametrize("service,arguments", [
    ("daemon", ["-p", "qcl-negf", "daemon", "start", "--foreground"]),
    ("api", ["--host", "127.0.0.1", "--port", "8080"]),
])
def test_nested_verdi_tracks_current_profile(starts, tmp_path, service, arguments):
    profile = tmp_path / "application-profile"
    for version in ("first", "second"):
        binaries = tmp_path / version / "bin"
        binaries.mkdir(parents=True)
        # A stand-in for the external AiiDA process performs the same child lookup
        # as core.zeromq. It does not configure a profile or start a daemon.
        program = (
            f"#!{sys.executable}\n"
            "import json, shutil, subprocess, sys\n"
            f"version = {version!r}\n"
            "if sys.argv[1:] == ['--child']:\n"
            "    print(version)\n"
            "else:\n"
            "    child = shutil.which('verdi')\n"
            "    if child is None:\n"
            "        raise SystemExit('Unable to find verdi in PATH')\n"
            "    child_version = subprocess.check_output([child, '--child'], text=True).strip()\n"
            "    print(json.dumps({'parent': version, 'child': child_version, 'args': sys.argv[1:]}))\n"
        )
        for executable in ("verdi", "qcl-negf-api"):
            target = binaries / executable
            target.write_text(program)
            target.chmod(0o755)
        if profile.is_symlink():
            profile.unlink()
        profile.symlink_to(binaries.parent)
        script = (materialize_api(starts[service], tmp_path, profile) if service == "api" else
                  starts[service].replace("/nix/var/nix/profiles/qcl-negf-application", str(profile)))
        if script.startswith("/"):
            script = "exec " + script
        result = subprocess.run(
            ["/bin/sh", "-c", script], env={"PATH": "/usr/bin:/bin"},
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {"parent": version, "child": version, "args": arguments}


def test_daemon_path_supports_real_local_transport_whoami(starts, tmp_path, monkeypatch):
    """AiiDA invokes bash by name even when no scheduler job is submitted."""
    pytest.importorskip("aiida")
    from aiida.transports.plugins.local import LocalTransport

    bash = shutil.which("bash")
    whoami = shutil.which("whoami")
    assert bash and whoami, "the local regression fixture needs bash and whoami"
    binaries = {}
    for package in {"bash", "openssh", "slurm", "coreutils"}:
        binaries[package] = tmp_path / package / "bin"
        binaries[package].mkdir(parents=True)
    (binaries["bash"] / "bash").symlink_to(bash)
    (binaries["coreutils"] / "whoami").symlink_to(whoami)
    # NixOS supplies coreutils by default; the extra packages come directly
    # from the evaluated owning service. Do not inherit the host PATH.
    service_path = [binaries[package] for package in starts["daemonPath"]]
    monkeypatch.setenv("PATH", os.pathsep.join(map(str, service_path + [binaries["coreutils"]])))
    monkeypatch.setenv("AIIDA_PATH", str(tmp_path / "aiida"))
    with LocalTransport(use_login_shell=False) as transport:
        assert transport.whoami() == pwd.getpwuid(os.getuid()).pw_name


def test_api_wrapper_clears_unbound_configurator_environment(starts, tmp_path):
    """The disabled real launch script cannot inherit a stale runtime binding."""
    binaries = tmp_path / "application-profile" / "bin"
    binaries.mkdir(parents=True)
    executable = binaries / "qcl-negf-api"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import json, os\n"
        "print(json.dumps({k:v for k,v in os.environ.items() "
        "if k.startswith('QCL_NEGF_CONFIGURATOR_')}))\n"
    )
    executable.chmod(0o755)
    script = materialize_api(starts["api"], tmp_path, binaries.parent)
    result = subprocess.run(["/bin/sh", "-c", script], env={
        "PATH":"/usr/bin:/bin", "QCL_NEGF_CONFIGURATOR_EXECUTABLE":"/foreign/solver",
        "QCL_NEGF_CONFIGURATOR_CATALOG_ROOT":"/foreign/research",
        "QCL_NEGF_CONFIGURATOR_CATALOG_SOURCE_ID":"foreign-source",
        "QCL_NEGF_CONFIGURATOR_CGROUP_ROOT":"/foreign/cgroup",
    },capture_output=True,text=True,timeout=10)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {}


def test_api_mount_probe_has_explicit_native_executable_path(starts):
    assert "util-linux" in starts["apiPath"]


def test_enabled_api_uses_runtime_binding_without_disabling_base_api(starts, tmp_path):
    binaries = tmp_path / "active-application/bin"
    binaries.mkdir(parents=True)
    executable = binaries / "qcl-negf-api"
    executable.write_text(f"#!{sys.executable}\nimport json,os\n"
        "print(json.dumps({k:v for k,v in os.environ.items() if k.startswith('QCL_NEGF_CONFIGURATOR_')}))\n")
    executable.chmod(0o755)
    for enabled in (False, True):
        script = materialize_api(starts["configuratorApi" if enabled else "api"],tmp_path,binaries.parent)
        result = subprocess.run(["/bin/sh","-c",script],env={"PATH":"/usr/bin:/bin"},
                                capture_output=True,text=True,timeout=10)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {}
        assert ("invalid_runtime_binding" in result.stderr) is enabled


@pytest.mark.parametrize("script,expected", [
    ("configuratorApi", "/sys/fs/cgroup/system.slice/qcl-negf-api.service"),
    ("nestedApi", "/sys/fs/cgroup/research.slice/research-api.slice/qcl-negf-api.service"),
])
def test_runtime_configurator_envelope_tracks_native_unit_slice(starts, script, expected):
    arguments = shlex.split(starts[script])
    configuration = json.loads(arguments[arguments.index("--config")+1])
    assert configuration["configurator"] == {"cgroup_root":expected}
