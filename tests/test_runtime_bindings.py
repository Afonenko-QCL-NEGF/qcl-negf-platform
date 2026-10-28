"""Runtime feature bindings follow the trusted active APP, without solver execution."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest


def runtime_module():
    source = Path(__file__).parents[1] / "ops/runtime_bindings.py"
    assert source.exists(), "the owning runtime descriptor helper is missing"
    sys.path.insert(0, str(source.parent))
    try:
        spec = importlib.util.spec_from_file_location("runtime_bindings", source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


def record(application="/nix/store/application-a", *, ready=False):
    return {"schema": "qcl-negf-release-v1", "release_id": "release-a",
            "application_path": application, "solver_executable": "/nix/store/solver/bin/qcl-negf",
            "ready": ready, "sources": {
                "format": "qcl-negf.git-graph.v1", "revision": "a" * 40,
                "components": [{"path": "components/qcl-negf-research", "revision": "b" * 40,
                                "url": "https://github.com/QCL/qcl-negf-research"}],
            }}


DESCRIPTOR = {"schema": "qcl-negf-application-runtime-v1", "configurator": {
    "catalog_root": "/nix/store/research-source/components/qcl-negf-research",
}}
CGROUP = "/sys/fs/cgroup/system.slice/qcl-negf-api.service"


def bind(module, value, descriptor=None, **changes):
    arguments = dict(application_target=value["application_path"], solver_target="/nix/store/solver",
                     cgroup_root=CGROUP, require_ready=False)
    arguments.update(changes)
    return module.runtime_bindings(value, descriptor or DESCRIPTOR, **arguments)


def test_compatible_app_switch_keeps_unchanged_solver_and_catalog_bindings():
    module = runtime_module()
    first = bind(module, record())
    second = bind(module, record("/nix/store/application-b"))
    assert first == second == {
        "QCL_NEGF_CONFIGURATOR_EXECUTABLE": "/nix/store/solver/bin/qcl-negf",
        "QCL_NEGF_CONFIGURATOR_CATALOG_ROOT": "/nix/store/research-source/components/qcl-negf-research",
        "QCL_NEGF_CONFIGURATOR_CATALOG_SOURCE_ID": "b" * 40,
        "QCL_NEGF_CONFIGURATOR_CGROUP_ROOT": CGROUP,
    }


def test_read_configuration_startup_and_current_execution_have_explicit_ready_policy():
    module = runtime_module()
    value = record(ready=False)
    assert bind(module, value)
    with pytest.raises(ValueError):
        bind(module, value, require_ready=True)
    value["ready"] = True
    assert bind(module, value, require_ready=True) == bind(module, value)


@pytest.mark.parametrize("change", [
    lambda v: v.update(ready="false"), lambda v: v.pop("ready"),
    lambda v: v.update(schema="unknown"), lambda v: v.update(solver_executable="/tmp/solver"),
    lambda v: v["sources"]["components"].clear(),
    lambda v: v["sources"]["components"].append(copy.deepcopy(v["sources"]["components"][0])),
])
def test_missing_unknown_and_unbound_release_fields_fail_closed(change):
    module = runtime_module()
    value = record()
    change(value)
    with pytest.raises(ValueError):
        bind(module, value)


@pytest.mark.parametrize("changes", [
    {"application_target": "/nix/store/foreign"}, {"solver_target": "/nix/store/foreign"},
    {"cgroup_root": "/sys/fs/cgroup/../foreign"},
])
def test_active_profile_and_cgroup_binding_mismatch_is_rejected(changes):
    with pytest.raises(ValueError):
        bind(runtime_module(), record(), **changes)


@pytest.mark.parametrize("descriptor", [
    {}, {**DESCRIPTOR, "schema": "unknown"}, {**DESCRIPTOR, "extra": True},
    {**DESCRIPTOR, "configurator": {"catalog_root": "/tmp/research"}},
    {**DESCRIPTOR, "configurator": {"catalog_root": "/nix/store/src/../research"}},
])
def test_unknown_or_mutable_application_descriptor_is_rejected(descriptor):
    with pytest.raises(ValueError):
        runtime_module().application_descriptor(descriptor)


def test_child_environment_drops_inherited_feature_and_quantum_bindings():
    module = runtime_module()
    environment = module.child_environment({
        "PATH": "/usr/bin", "QCL_NEGF_CONFIGURATOR_EXECUTABLE": "/foreign",
        "QCL_NEGF_SAVED_RESULTS_BINDING_FILE": "/foreign.json",
        "QCL_NEGF_QUANTUM_RUNTIME_CONTEXT": "untrusted",
        "QCL_NEGF_QUANTUM_RUNTIME_CONTEXT_SHA256": "a" * 64,
        "QCL_NEGF_QUANTUM_RUNTIME_RELEASE_FILE": "/foreign.json",
        "QCL_NEGF_API_TOKEN_FILE": "/run/credentials/token",
    })
    assert environment == {"PATH": "/usr/bin", "QCL_NEGF_API_TOKEN_FILE": "/run/credentials/token"}


def test_saved_provider_does_not_depend_on_baked_application(tmp_path):
    module = runtime_module()
    binding = tmp_path / "binding.json"
    identity = tmp_path / "identity"
    identity.write_text("storage-identity\n")
    root, alias = tmp_path / "jobs", tmp_path / "alias"
    root.mkdir()
    alias.mkdir()
    binding.write_text(json.dumps({"storage_identity": "storage-identity", "root": str(alias)}))
    calls = []

    def command(argv, **bounds):
        calls.append((argv, bounds))
        if argv[0] == sys.executable:
            return ""
        return {"FSTYPE": "nfs4", "SOURCE": "storage:/jobs", "OPTIONS": "ro,hard"}[argv[-1]] + "\n"

    # Root ownership is a separate read_protected_file boundary, injected here;
    # mounts are literal facts, never evidence of an actual NFS service.
    result = module.saved_results_binding({"binding_file": str(binding), "root": str(root),
        "alias": str(alias), "nfs_source": "storage:/jobs", "storage_identity_file": str(identity)},
        run=command, read_protected=lambda path, limit=65536: Path(path).read_bytes())
    assert result == {"QCL_NEGF_SAVED_RESULTS_BINDING_FILE": str(binding)}
    assert len(calls) == 6
    assert calls[0][0][0] == sys.executable
    assert all(call[0][0] == "findmnt" and call[1]["timeout_seconds"] > 0
               and call[1]["output_bytes"] <= 4096 for call in calls[1:])


def test_root_trusted_reader_rejects_user_owned_descriptor(tmp_path):
    source = tmp_path / "runtime.json"
    source.write_text(json.dumps(DESCRIPTOR))
    with pytest.raises((ValueError, OSError)):
        runtime_module().read_runtime_json(source)


def test_argv_is_literal_and_original_nonzero_output_has_private_log(tmp_path):
    module = runtime_module()
    marker = tmp_path / "injected"
    literal = "$(touch " + str(marker) + "); exit 99"
    output = module.logged_command([sys.executable, "-c", "import sys; print(sys.argv[1])", literal],
        log_directory=tmp_path, timeout_seconds=3, cleanup_seconds=.5, output_bytes=1024)
    assert output == literal + "\n"
    assert not marker.exists()
    with pytest.raises(module.CommandFailure) as observed:
        module.logged_command([sys.executable, "-c",
            "import sys; print('original stdout'); print('original stderr', file=sys.stderr); sys.exit(7)"],
            log_directory=tmp_path, timeout_seconds=3, cleanup_seconds=.5, output_bytes=1024)
    error = observed.value
    saved = json.loads(Path(error.log_path).read_text())
    assert saved == error.record
    assert saved["returncode"] == 7 and saved["failure"] == "nonzero"
    assert saved["stdout"] == "original stdout\n" and saved["stderr"] == "original stderr\n"
    assert stat.S_IMODE(Path(error.log_path).stat().st_mode) == 0o600


@pytest.mark.parametrize("script,reason", [
    ("import time; print('before timeout', flush=True); time.sleep(60)", "timeout"),
    ("import sys; sys.stdout.write('x'*65536); sys.stdout.flush()", "output_limit"),
])
def test_bounded_command_retains_failure_and_confirms_owned_group_cleanup(tmp_path, script, reason):
    module = runtime_module()
    with pytest.raises(module.CommandFailure) as observed:
        module.logged_command([sys.executable, "-c", script], log_directory=tmp_path,
            timeout_seconds=1, cleanup_seconds=.2, output_bytes=128)
    saved = json.loads(Path(observed.value.log_path).read_text())
    assert saved["failure"] == reason
    assert saved["output_bytes"] <= 128 and saved["cleanup_confirmed"] is True
    assert saved["elapsed_seconds"] < 1.5
    assert saved["stdout"].startswith("before timeout" if reason == "timeout" else "x")


def test_launcher_pins_parent_and_nested_lookup_to_same_active_application(tmp_path):
    module = runtime_module()
    for name in ("app-a", "app-b"):
        binaries = tmp_path / name / "bin"
        binaries.mkdir(parents=True)
        (binaries / "verdi").write_text("#!/bin/sh\nprintf '%s' " + name + "\n")
        (binaries / "verdi").chmod(0o755)
        api = binaries / "qcl-negf-api"
        api.write_text(f"#!{sys.executable}\nimport json, os, subprocess, sys\n"
                       "print(json.dumps({'child': subprocess.check_output(['verdi'], text=True),"
                       "'args': sys.argv[1:], 'stale':os.environ.get('QCL_NEGF_CONFIGURATOR_EXECUTABLE')}))\n")
        api.chmod(0o755)
        observed = []

        def execute(executable, argv, env):
            observed.append(subprocess.run(argv, executable=executable, env=env,
                check=True, capture_output=True, text=True, timeout=5))

        module.launch({"schema":"qcl-negf-application-launch-v1", "configurator":None,
                       "saved_results":None}, port=8080,
            environment={"PATH":"/usr/bin:/bin", "QCL_NEGF_CONFIGURATOR_EXECUTABLE":"/stale"},
            target=lambda _: str(binaries.parent), execve=execute)
        assert json.loads(observed[0].stdout) == {
            "child":name, "args":["--host","127.0.0.1","--port","8080"], "stale":None,
        }


@pytest.mark.parametrize("failure", ["missing", "wrong-profile", "wrong-solver", "missing-catalog"])
def test_feature_failure_keeps_base_api_available_with_explicit_reason(failure, capsys):
    module = runtime_module()
    selected = "/nix/store/application-a"
    value = record()
    seen = []

    def read(path):
        if failure == "missing":
            raise FileNotFoundError(path)
        return value if Path(path) == module.RECORD else DESCRIPTOR

    def target(path):
        if str(path).endswith("-solver"):
            return "/nix/store/foreign" if failure == "wrong-solver" else "/nix/store/solver"
        return "/nix/store/foreign" if failure == "wrong-profile" else selected

    def probe(_):
        if failure == "missing-catalog":
            raise FileNotFoundError("catalog")

    module.launch({"schema":"qcl-negf-application-launch-v1", "saved_results":None,
                   "configurator":{"cgroup_root":CGROUP}}, port=8080,
        environment={"PATH":"/usr/bin"}, read_json=read, target=target, probe=probe,
        execve=lambda executable, argv, env: seen.append((executable, argv, env)))
    assert len(seen) == 1 and seen[0][0].endswith("/bin/qcl-negf-api")
    assert not any(key.startswith("QCL_NEGF_CONFIGURATOR_") for key in seen[0][2])
    assert capsys.readouterr().err == "configurator binding unavailable: invalid_runtime_binding\n"


def test_current_quantum_context_becomes_ready_without_api_restart(monkeypatch):
    module = runtime_module()
    # Use the owning Portal public request validator; no service/profile/solver runs.
    portal_source = Path(__file__).parents[2] / "qcl-negf-portal/src"
    monkeypatch.syspath_prepend(str(portal_source))
    from qcl_negf_api.quantum_preview import runtime_context, ConfiguratorError
    from types import SimpleNamespace
    import hashlib
    selected = "/nix/store/" + "a" * 32 + "-application"
    solver = "/nix/store/" + "c" * 32 + "-solver"
    value = record(selected)
    value.update(release_id="f" * 64, solver_executable=solver + "/bin/qcl-negf")
    value["sources"]["components"].extend([
        {"path":"components/QCLNEGF.jl", "revision":"c"*40, "url":"https://github.com/QCL/QCLNEGF.jl"},
        {"path":"components/QCLNEGFRunner.jl", "revision":"d"*40, "url":"https://github.com/QCL/QCLNEGFRunner.jl"},
    ])
    value["closures"] = [{"path":selected,"narHash":"sha256-"+"A"*43+"="},
                         {"path":solver,"narHash":"sha256-"+"A"*43+"="}]
    raw = json.dumps(value["sources"], sort_keys=True, separators=(",",":"), ensure_ascii=True).encode()
    value["solver_build"] = {"source_graph_sha256":hashlib.sha256(raw).hexdigest(),
        "julia_manifest_sha256":"e"*64, "drv_path":solver+".drv", "output_path":solver}
    value["quantum_runtime_context"] = module.quantum_context(value)
    environment = bind(module, value, solver_target=solver)
    environment.update(QCL_NEGF_RELEASE_ID=value["release_id"],
                       QCL_NEGF_SOLVER_EXECUTABLE=value["solver_executable"])
    settings = SimpleNamespace(configurator_executable=value["solver_executable"])
    arguments = dict(environment=environment, read_record=lambda:value,
                     profile_targets=lambda:(selected,solver))
    with pytest.raises(ConfiguratorError):
        runtime_context(settings, **arguments)
    value["ready"] = True
    assert runtime_context(settings, **arguments)["runner_source_id"] == "d"*40


@pytest.mark.parametrize("condition", [
    "healthy", "store-without-sticky", "world-writable-store", "writable-member",
    "foreign-member-owner", "symlink-member", "oversize", "duplicate-key",
])
def test_native_sticky_store_exception_does_not_weaken_member_trust(tmp_path, monkeypatch, condition):
    from contextlib import contextmanager
    module = runtime_module()
    store = tmp_path / "store"
    store.mkdir(mode=0o755)
    store.chmod(0o1775)
    member = store / "application"
    member.mkdir(mode=0o755)
    metadata = member / "runtime.json"
    metadata.write_text(json.dumps(DESCRIPTOR))
    metadata.chmod(0o444)
    if condition == "store-without-sticky": store.chmod(0o775)
    if condition == "world-writable-store": store.chmod(0o1777)
    if condition == "writable-member": metadata.chmod(0o664)
    if condition == "oversize": metadata.chmod(0o644); metadata.write_bytes(b"x"*65537)
    if condition == "duplicate-key": metadata.chmod(0o644); metadata.write_text('{"schema":1,"schema":2}')
    if condition == "symlink-member":
        link = member / "link.json"
        link.symlink_to(metadata)
        metadata = link

    @contextmanager
    def namespace(path):
        assert path == "/nix"
        descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
        try: yield descriptor
        finally: os.close(descriptor)

    native = os.fstat
    def root_owned(descriptor):
        info = native(descriptor)
        values = list(info)
        values[4] = 999 if condition == "foreign-member-owner" and stat.S_ISREG(info.st_mode) else 0
        return os.stat_result(values)
    # Only OS ownership/namespace is synthetic. The reader opens actual files,
    # follows actual directory FDs and enforces actual mode, symlink and byte bounds.
    monkeypatch.setattr(module, "protected_directory", namespace)
    monkeypatch.setattr(os, "fstat", root_owned)
    path = "/nix/store/application/" + metadata.name
    if condition == "healthy":
        assert module.read_runtime_json(path) == DESCRIPTOR
    else:
        with pytest.raises((ValueError,OSError)):
            module.read_runtime_json(path)


def test_original_command_failure_survives_unavailable_log_directory(tmp_path):
    module = runtime_module()
    with pytest.raises(module.CommandFailure) as observed:
        module.logged_command([sys.executable,"-c","raise SystemExit(9)"],
            log_directory=tmp_path/"absent", timeout_seconds=3, cleanup_seconds=.5, output_bytes=128)
    assert observed.value.record["returncode"] == 9
    assert observed.value.log_error == "failure_log_unavailable"


def test_enabled_launch_follows_new_app_and_keeps_independent_results(tmp_path, monkeypatch):
    module = runtime_module()
    root, alias = tmp_path/"jobs", tmp_path/"alias"
    root.mkdir(); alias.mkdir()
    identity = tmp_path/"identity"
    identity.write_text("storage-id\n")
    binding = tmp_path/"binding.json"
    binding.write_text(json.dumps({"root":str(alias),"storage_identity":"storage-id"}))
    settings = {"binding_file":str(binding), "root":str(root), "alias":str(alias),
                "nfs_source":"storage:/jobs", "storage_identity_file":str(identity)}
    monkeypatch.setattr(module,"read_trusted_file",lambda path,limit=65536:Path(path).read_bytes())
    observed = []
    expected = {
        "QCL_NEGF_CONFIGURATOR_EXECUTABLE":"/nix/store/solver/bin/qcl-negf",
        "QCL_NEGF_CONFIGURATOR_CATALOG_ROOT":"/nix/store/research-source/components/qcl-negf-research",
        "QCL_NEGF_CONFIGURATOR_CATALOG_SOURCE_ID":"b"*40,
        "QCL_NEGF_CONFIGURATOR_CGROUP_ROOT":CGROUP,
        "QCL_NEGF_SAVED_RESULTS_BINDING_FILE":str(binding),
    }
    for application in ("/nix/store/application-a","/nix/store/application-b"):
        value = record(application)
        reads = []
        def read(path):
            if Path(path)==module.RECORD:
                reads.append(True)
                return {**value,"ready":len(reads)>1}
            assert str(path)==application+"/share/qcl-negf/runtime.json"
            return DESCRIPTOR
        def execute(executable, argv, env):
            assert executable==application+"/bin/qcl-negf-api" and argv[0]==executable
            child = subprocess.run([sys.executable,"-c", "import json,os; print(json.dumps({k:v for k,v in os.environ.items() if k.startswith('QCL_NEGF_CONFIGURATOR_') or k=='QCL_NEGF_SAVED_RESULTS_BINDING_FILE'}))"],
                env=env,check=True,capture_output=True,text=True,timeout=5)
            observed.append(json.loads(child.stdout))
        module.launch({"schema":"qcl-negf-application-launch-v1", "saved_results":settings,
                       "configurator":{"cgroup_root":CGROUP}},port=8080,
            environment={"PATH":"/usr/bin:/bin"},read_json=read,
            target=lambda p:"/nix/store/solver" if str(p).endswith("-solver") else application,
            probe=lambda _:None,execve=execute,
            run=lambda argv,**bounds:"" if argv[0]==sys.executable else {
                "FSTYPE":"nfs4","SOURCE":"storage:/jobs","OPTIONS":"ro,hard"}[argv[-1]])
    assert observed == [expected,expected]


@pytest.mark.parametrize("payload", ["", "x"*4097])
def test_authoritative_code_file_cannot_fall_back_or_grow_unbounded(tmp_path, payload):
    module = runtime_module()
    source = tmp_path/"codes"
    source.write_text(payload)
    with pytest.raises(ValueError):
        module.launch({"schema":"qcl-negf-application-launch-v1", "configurator":None,
                       "saved_results":None, "allowed_codes_file":str(source)},port=8080,
            environment={"QCL_NEGF_ALLOWED_CODES":"inherited"},target=lambda _:"/nix/store/app",
            execve=lambda *args:pytest.fail("invalid authoritative allowlist was executed"))


def test_authoritative_code_file_uses_bounded_native_read(tmp_path):
    module = runtime_module()
    source = tmp_path/"codes"
    source.write_text("11111111-1111-4111-8111-111111111111\n")
    observed = []
    module.launch({"schema":"qcl-negf-application-launch-v1", "configurator":None,
                   "saved_results":None, "allowed_codes_file":str(source)},port=8080,
        environment={"QCL_NEGF_ALLOWED_CODES":"inherited"},target=lambda _:"/nix/store/app",
        execve=lambda executable,argv,env:observed.append(env["QCL_NEGF_ALLOWED_CODES"]))
    assert observed == ["11111111-1111-4111-8111-111111111111"]
