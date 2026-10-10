"""Bootstrap boundaries use local files/processes, never Nix or a server."""
import importlib.util
import json
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


def test_check_nginx_never_accepts_writer_only_validation(tmp_path, monkeypatch):
    """A successful gixy writer is not evidence that nginx can parse the config."""
    m = load()
    value = {"roles": {name: "/nix/store/" + "a" * 32 + "-system.drv" for name in m.ROLES},
             "nginx": {"enabled": True, "validated": True,
                       "targets": ["/nix/store/" + "b" * 32 + "-nginx.conf.drv^out"]}}
    def external_nix(argv, *args, **kwargs):
        if argv[1] == "eval":
            return {"argv": argv, "stdout": json.dumps(value), "stderr": "", "exit_code": 0}
        if argv[1] == "build":
            return {"argv": argv, "stdout": json.dumps([{"outputs": {"out": "/nix/store/" + "c" * 32 + "-nginx.conf"}}]),
                    "stderr": "", "exit_code": 0}
        pytest.fail("Unexpected external operation")
    monkeypatch.setattr(m, "run", external_nix)
    receipt = tmp_path / "receipt.json"
    monkeypatch.setattr(sys, "argv", [str(SOURCE), "--receipt", str(receipt), "preflight",
                                    "--site", str(tmp_path), "--nix", "/fake/nix", "--check-nginx"])
    try:
        m.main()
    except SystemExit:
        pass
    result = json.loads(receipt.read_text())
    assert result["status"] == "failed", "gixy-only build was incorrectly accepted as real nginx validation"
    assert result.get("nginx_test", "not_measured") == "not_measured"


def test_engineering_config_changes_only_declared_tls_paths():
    m = load()
    assert callable(getattr(m, "nginx_test_config", None)), "Actual engineering config check is missing"
    source = """pid /run/nginx/nginx.pid;
http { server {
listen 127.0.0.1:443 ssl;
ssl_certificate /run/credentials/nginx.service/tls-cert;
ssl_certificate_key /run/credentials/nginx.service/tls-key;
location / { proxy_pass http://127.0.0.1:8080; }
} }
"""
    credentials = [{"directive": "ssl_certificate", "path": "/run/credentials/nginx.service/tls-cert"},
                   {"directive": "ssl_certificate_key", "path": "/run/credentials/nginx.service/tls-key"}]
    expected = source.replace("/run/credentials/nginx.service/tls-cert", "/run/qcl-nginx-test/cert.pem").replace(
        "/run/credentials/nginx.service/tls-key", "/run/qcl-nginx-test/key.pem")
    assert m.nginx_test_config(source, credentials) == expected
    for bad in [source.replace("ssl_certificate /run/credentials/nginx.service/tls-cert;", ""),
                source.replace("ssl_certificate_key", "unrelated_directive")]:
        with pytest.raises(ValueError, match="certificate"):
            m.nginx_test_config(bad, credentials)


def test_namespace_prefix_requires_explicit_absolute_executable():
    m = load()
    assert callable(getattr(m, "namespace_prefix", None)), "Explicit namespace admission is missing"
    assert m.namespace_prefix('["/usr/bin/sudo","-n","/usr/bin/unshare","--mount","--net"]') == [
        "/usr/bin/sudo", "-n", "/usr/bin/unshare", "--mount", "--net"]
    for value in [None, '[]', '["unshare","--mount"]', '"/usr/bin/unshare"', '["/usr/bin/unshare",3]']:
        with pytest.raises(ValueError):
            m.namespace_prefix(value)


@pytest.mark.parametrize("native_output,accepted", [
    ("nginx: configuration file syntax is ok\nnginx: configuration file test is successful\n", True),
    ("nginx: [warn] conflicting server name\nnginx: configuration file syntax is ok\nnginx: configuration file test is successful\n", False),
    ("gixy validation completed\n", False),
])
def test_actual_nginx_result_controls_acceptance(tmp_path, monkeypatch, native_output, accepted):
    """External Nix/namespace calls are stubbed; binding, files and acceptance are real."""
    m = load()
    config_path = "/nix/store/" + "c" * 32 + "-nginx.conf"
    executable = "/nix/store/" + "d" * 32 + "-nginx/bin/nginx"
    target = "/nix/store/" + "b" * 32 + "-nginx.conf.drv^out"
    source = tmp_path / "actual.conf"
    source.write_text("""pid /run/nginx/nginx.pid;
events {}
http { server {
listen 127.0.0.1:443 ssl;
ssl_certificate /run/secrets/test.crt;
ssl_certificate_key /run/secrets/test.key;
} }
""")
    credentials = [{"directive": "ssl_certificate", "path": "/run/secrets/test.crt"},
                   {"directive": "ssl_certificate_key", "path": "/run/secrets/test.key"}]
    cfg = {"targets": [target], "executable": executable, "exec_start": executable+" -c '"+config_path+"'",
           "reload": False, "config_file": None, "tls_credentials": credentials}
    original_read = Path.read_bytes
    original_stat = Path.lstat
    monkeypatch.setattr(Path, "read_bytes", lambda p: original_read(source if str(p) == config_path else p))
    monkeypatch.setattr(Path, "lstat", lambda p: original_stat(source if str(p) == config_path else p))
    monkeypatch.setattr(m.os, "access", lambda p, mode: p in (executable, "/fake/openssl", "/fake/mount"))
    def external(argv, *args, **kwargs):
        if argv[0] == "/fake/openssl":
            Path(argv[argv.index("-keyout")+1]).write_text("dummy test key")
            Path(argv[argv.index("-out")+1]).write_text("dummy test cert")
            output = ""
        elif argv[0] == "/fake/namespace":
            tested = Path(argv[-3]) / "nginx.conf"
            assert tested.read_text() == """pid /run/nginx/nginx.pid;
events {}
http { server {
listen 127.0.0.1:443 ssl;
ssl_certificate /run/qcl-nginx-test/cert.pem;
ssl_certificate_key /run/qcl-nginx-test/key.pem;
} }
"""
            assert argv[-4] == executable
            output = native_output
        else:
            pytest.fail("Unexpected external operation")
        return {"argv": argv, "stdout": "", "stderr": output, "exit_code": 0}
    monkeypatch.setattr(m, "run", external)
    built = {"stdout": json.dumps([{"drvPath": target.removesuffix("^out"), "outputs": {"out": config_path}}])}
    receipt = {}
    if accepted:
        m.check_nginx({"nginx": cfg}, built, "/fake/openssl", "/fake/mount", '["/fake/namespace"]', receipt)
        assert receipt["nginx_severity_counters"] == {x: 0 for x in ("warn", "error", "crit", "alert", "emerg")}
    else:
        with pytest.raises(ValueError, match="Strict actual nginx"):
            m.check_nginx({"nginx": cfg}, built, "/fake/openssl", "/fake/mount", '["/fake/namespace"]', receipt)
    assert receipt["nginx_test"]["stderr"] == native_output
    wrong = {"stdout": json.dumps([{"drvPath": target.removesuffix("^out"),
                                     "outputs": {"out": "/nix/store/" + "f" * 32 + "-nginx.conf"}}])}
    with pytest.raises(ValueError, match="differs"):
        m.check_nginx({"nginx": cfg}, wrong, "/fake/openssl", "/fake/mount", '["/fake/namespace"]', {})


def test_namespace_child_refuses_host_namespace_before_any_mount(tmp_path):
    m = load()
    with pytest.raises(m.CommandFailure) as error:
        m.run([sys.executable, "-c", m.NGINX_NAMESPACE_TEST, "/invalid/mount", "/invalid/nginx", str(tmp_path),
               os.readlink("/proc/self/ns/mnt"), os.readlink("/proc/self/ns/net")], 5, 4096)
    assert "Separate root mount/network engineering namespace required" in error.value.record["stderr"]
    assert "invalid/mount" not in error.value.record["stderr"]


def test_successfully_reaped_command_does_not_signal_obsolete_group(monkeypatch):
    """Completed command identity cannot authorize a later numeric group signal."""
    m = load()
    attempted = []
    # Never deliver a signal. The assertion diagnoses obsolete group signalling;
    # process ownership/descendant containment need separate GREEN evidence.
    monkeypatch.setattr(m.os, "killpg", lambda pgid, sig: attempted.append((pgid, sig)))
    result = m.run([str(Path(sys.executable).resolve()), "-c", "print('completed')"], seconds=2, cap=1024)
    assert result["exit_code"] == 0 and result["failure"] is None
    assert result["stdout"] == "completed\n"
    assert attempted == [], "obsolete numeric group identity signalled after reap"


@pytest.mark.parametrize('escaped', [False, True])
def test_command_supervision_reaps_descendants_and_preserves_foreign_sentinel(tmp_path, escaped):
    """Tiny local fork fixture: own descendants only, including a new session."""
    import subprocess
    import time
    m = load()
    sentinel = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)'])
    evidence = tmp_path / 'owned-child.json'
    source = """import json,os,pathlib,sys,time
pid=os.fork()
if pid==0:
 if sys.argv[2]=='true':os.setsid()
 fields=pathlib.Path('/proc/self/stat').read_text().rsplit(') ',1)[1].split()
 pathlib.Path(sys.argv[1]).write_text(json.dumps({'pid':os.getpid(),'birth':int(fields[19])}))
 print('owned child diagnostic',file=sys.stderr,flush=True)
 time.sleep(10)
else:os._exit(0)
"""
    try:
        with pytest.raises(m.CommandFailure) as error:
            m.run([str(Path(sys.executable).resolve()), '-c', source, str(evidence), str(escaped).lower()], 2, 4096)
        assert error.value.record['failure'] == 'deadline'
        assert 'owned child diagnostic' in error.value.record['stderr']
        assert sentinel.poll() is None, 'unrelated process was signalled'
        child = json.loads(evidence.read_text())
        path = Path('/proc') / str(child['pid']) / 'stat'
        if path.exists():
            fields = path.read_text().rsplit(') ', 1)[1].split()
            assert int(fields[19]) != child['birth'], 'owned descendant remains unreaped'
    finally:
        sentinel.terminate()
        sentinel.wait(timeout=2)


@pytest.mark.parametrize('drift', ['disappeared', 'birth', 'uid'])
def test_pidfd_guard_refuses_disappeared_or_replaced_identity(monkeypatch, drift):
    m = load()
    owner = m._CommandOwner.__new__(m._CommandOwner)
    owner.deadline = float('inf')
    owner.owned = {(43210, 123, 1000): True}
    owner.fds = {}
    monkeypatch.setattr(owner, 'observe', lambda: {43210: (123, 1, b'S', 1000)})
    def opened(pid, flags):
        assert pid == 43210
        if drift == 'disappeared':raise ProcessLookupError()
        return 8765
    monkeypatch.setattr(m.os, 'pidfd_open', opened)
    monkeypatch.setattr(m.os, 'close', lambda fd: None)
    monkeypatch.setattr(owner, 'row', lambda pid: (124 if drift == 'birth' else 123, 1, b'S', 1001 if drift == 'uid' else 1000))
    monkeypatch.setattr(m.signal, 'pidfd_send_signal', lambda *a: pytest.fail('foreign/reused process handle signalled'))
    owner.signal(m.signal.SIGKILL)


def test_timeout_preserves_sigterm_tail(tmp_path):
    """The command can emit useful diagnostics after the work deadline."""
    m = load()
    ready = tmp_path / 'handler-ready'
    source = """import signal,sys,time,pathlib
def stop(signum, frame):
 print('late-stdout',flush=True)
 print('late-stderr',file=sys.stderr,flush=True)
 raise SystemExit(0)
signal.signal(signal.SIGTERM,stop)
pathlib.Path(sys.argv[1]).write_text('SIGTERM handler armed')
time.sleep(30)
"""
    with pytest.raises(m.CommandFailure) as error:
        m.run([str(Path(sys.executable).resolve()), '-c', source, str(ready)], 2, 4096)
    assert ready.read_text() == 'SIGTERM handler armed'
    assert error.value.record['failure'] == 'deadline'
    assert error.value.record['exit_code'] == 0
    assert error.value.record['stdout'] == 'late-stdout\n'
    assert error.value.record['stderr'] == 'late-stderr\n'
