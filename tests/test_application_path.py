"""Exercise child executable lookup in the module's real generated wrappers."""
import json
import os
from pathlib import Path
import pwd
import shutil
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
        script = starts[service].replace("/nix/var/nix/profiles/qcl-negf-application", str(profile))
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
    script = starts["api"].replace("/nix/var/nix/profiles/qcl-negf-application", str(binaries.parent))
    result = subprocess.run(["/bin/sh", "-c", script], env={
        "PATH":"/usr/bin:/bin", "QCL_NEGF_CONFIGURATOR_EXECUTABLE":"/foreign/solver",
        "QCL_NEGF_CONFIGURATOR_CATALOG_ROOT":"/foreign/research",
        "QCL_NEGF_CONFIGURATOR_CATALOG_SOURCE_ID":"foreign-source",
        "QCL_NEGF_CONFIGURATOR_CGROUP_ROOT":"/foreign/cgroup",
    },capture_output=True,text=True,timeout=10)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {}


@pytest.mark.parametrize('binding', ['exact','foreign-application','foreign-solver','missing-catalog'])
def test_opt_in_api_checks_current_release_without_disabling_old_api(starts, tmp_path, binding):
    """Execute the actual generated script with tiny immutable-package stand-ins."""
    application = tmp_path / 'application'
    foreign = tmp_path / 'foreign'
    solver = tmp_path / 'solver'
    research = tmp_path / 'research'
    profile = tmp_path / 'application-profile'
    for directory in (application/'bin', foreign/'bin', solver/'bin', research/'config'):
        directory.mkdir(parents=True)
    for root in (application,foreign):
        executable = root / 'bin/qcl-negf-api'
        executable.write_text(f'#!{sys.executable}\n'
            'import json, os\n'
            "print(json.dumps({k:v for k,v in os.environ.items() if k.startswith('QCL_NEGF_CONFIGURATOR_')}))\n")
        executable.chmod(0o755)
    (solver/'bin/qcl-negf').write_text('# synthetic, never executed\n')
    (solver/'bin/qcl-negf').chmod(0o755)
    if binding != 'missing-catalog':
        (research/'config/configurator-catalog.json').write_text('{}')
    profile.symlink_to(foreign if binding=='foreign-application' else application)
    readlink = shutil.which('readlink')
    assert readlink
    script = starts['configuratorApi']
    for old, new in {
        '/nix/var/nix/profiles/qcl-negf-application': str(profile),
        '/nix/store/synthetic-application': str(application),
        '/nix/store/synthetic-solver': str(solver),
        '/nix/store/synthetic-research': str(research),
        '/synthetic-coreutils/bin/readlink': readlink,
    }.items():
        script = script.replace(old,new)
    result = subprocess.run(['/bin/sh','-c',script],env={
        'PATH':'/usr/bin:/bin',
        'QCL_NEGF_SOLVER_EXECUTABLE':'/foreign/solver' if binding=='foreign-solver' else str(solver/'bin/qcl-negf'),
        'QCL_NEGF_CONFIGURATOR_EXECUTABLE':'/stale/solver',
        'QCL_NEGF_CONFIGURATOR_CATALOG_SOURCE_ID':'stale-source',
    },capture_output=True,text=True,timeout=10)
    assert result.returncode == 0, result.stderr
    expected = {
        'QCL_NEGF_CONFIGURATOR_EXECUTABLE':str(solver/'bin/qcl-negf'),
        'QCL_NEGF_CONFIGURATOR_CATALOG_ROOT':str(research),
        'QCL_NEGF_CONFIGURATOR_CATALOG_SOURCE_ID':'synthetic-source',
        'QCL_NEGF_CONFIGURATOR_CGROUP_ROOT':'/sys/fs/cgroup/system.slice/qcl-negf-api.service',
    } if binding=='exact' else {}
    assert json.loads(result.stdout) == expected


def test_enabled_configurator_fixture_contains_live_guards_and_exports(starts):
    """The execution cases must exercise the enabled branch, not empty fallback."""
    enabled, disabled = starts['configuratorApi'], starts['api']
    assert 'readlink -f /nix/var/nix/profiles/qcl-negf-application' in enabled
    assert 'QCL_NEGF_SOLVER_EXECUTABLE:-' in enabled
    assert '/nix/store/synthetic-application' in enabled
    assert '/nix/store/synthetic-solver/bin/qcl-negf' in enabled
    assert '/nix/store/synthetic-research/config/configurator-catalog.json' in enabled
    for variable in ('QCL_NEGF_CONFIGURATOR_EXECUTABLE',
                     'QCL_NEGF_CONFIGURATOR_CATALOG_ROOT',
                     'QCL_NEGF_CONFIGURATOR_CATALOG_SOURCE_ID',
                     'QCL_NEGF_CONFIGURATOR_CGROUP_ROOT'):
        assert f'export {variable}=' in enabled
        assert f'export {variable}=' not in disabled
    assert 'readlink -f' not in disabled
    assert 'QCL_NEGF_SOLVER_EXECUTABLE:-' not in disabled
    assert 'unset QCL_NEGF_CONFIGURATOR_EXECUTABLE QCL_NEGF_CONFIGURATOR_CATALOG_ROOT' in disabled
    assert 'unset QCL_NEGF_CONFIGURATOR_CATALOG_SOURCE_ID QCL_NEGF_CONFIGURATOR_CGROUP_ROOT' in disabled
