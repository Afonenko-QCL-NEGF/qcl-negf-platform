"""Existing-command adapter fixtures; command execution is replaced at its boundary."""
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ops"))


def api():
    import host_resource_backends as module
    return module


class Commands:
    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.calls = []

    def run(self, argv, *, timeout_seconds, max_output_bytes):
        self.calls.append(tuple(argv))
        assert 0 < timeout_seconds <= 60
        assert 0 < max_output_bytes <= 1024 * 1024
        assert self.outputs, "unexpected native command"
        expected, result = self.outputs.pop(0)
        assert tuple(argv) == expected
        return result


def pve_config():
    return {"digest": "digest-1", "memory": 4096, "balloon": 512, "shares": 0,
            "smbios1": "uuid=11111111-1111-4111-8111-111111111111", "cores": 4}


def pve_row(config=None, *, assigned=536870912):
    config = config or pve_config()
    status = {"status": "running", "pid": 1234, "balloon": assigned, "maxmem": 4294967296}
    return [(('/usr/bin/pvesh', 'get', '/nodes/synthetic-node/qemu/101/config', '--current',
              '1', '--output-format', 'json'), json.dumps(config)),
            (('/usr/bin/pvesh', 'get', '/nodes/synthetic-node/qemu/101/status/current',
              '--output-format', 'json'), json.dumps(status))]


def test_pve_digest_update_and_actual_balloon_readback_never_use_rss_or_maxmem():
    m = api()
    updated = {**pve_config(), "digest": "digest-2", "balloon": 1024}
    commands = Commands(pve_row() + pve_row() + [
        (('/usr/bin/pvesh', 'set', '/nodes/synthetic-node/qemu/101/config', '--balloon',
          '1024', '--digest', 'digest-1', '--output-format', 'json'), 'null')]
        + pve_row(updated, assigned=1073741824))
    backend = m.ProxmoxMemoryBackend(commands, '/usr/bin/pvesh', 'synthetic-node',
                                    {'vm-a': m.ProxmoxVM(101, '11111111-1111-4111-8111-111111111111')},
                                    dynamic=True)
    before = backend.readback('vm-a')
    assert before.assigned_bytes == before.configured_bytes == 536870912
    assert backend.quantum_bytes == 1048576
    actual = backend.resize('vm-a', 1073741824, before, 30)
    assert actual.assigned_bytes == 1073741824
    assert actual.config_fingerprint == before.config_fingerprint
    assert actual.revision == 'digest-2'
    assert commands.outputs == []


@pytest.mark.parametrize("mutation", ['auto-balloon', 'no-balloon', 'wrong-owner',
                                      'missing-actual', 'unrecognized-memory'])
def test_pve_unsafe_or_incomplete_native_readback_refuses(mutation):
    m = api()
    config = pve_config()
    if mutation == 'auto-balloon':
        config['shares'] = 1000
    elif mutation == 'no-balloon':
        config['balloon'] = 0
    elif mutation == 'wrong-owner':
        config['smbios1'] = 'uuid=22222222-2222-4222-8222-222222222222'
    elif mutation == 'unrecognized-memory':
        config['memory'] = 'current=4096,max=8192'
    outputs = pve_row(config)
    if mutation == 'missing-actual':
        outputs[1] = (outputs[1][0], '{"status":"running","pid":1234,"maxmem":4294967296}')
    backend = m.ProxmoxMemoryBackend(Commands(outputs), '/usr/bin/pvesh', 'synthetic-node',
                                    {'vm-a': m.ProxmoxVM(101, '11111111-1111-4111-8111-111111111111')},
                                    dynamic=True)
    with pytest.raises(m.ResourceError):
        backend.readback('vm-a')


XML = '''<domain type="kvm"><name>synthetic-domain</name>
<uuid>11111111-1111-4111-8111-111111111111</uuid>
<memory unit="KiB">4194304</memory><currentMemory unit="KiB">524288</currentMemory>
<vcpu>4</vcpu><devices><memballoon model="virtio"/></devices></domain>'''


def libvirt_row(xml=XML, *, actual='524288'):
    prefix = ('/usr/bin/virsh', '--connect', 'qemu:///system')
    uid = '11111111-1111-4111-8111-111111111111'
    return [(prefix + ('dumpxml', uid), xml),
            (prefix + ('domstate', uid), 'running\n'),
            (prefix + ('dommemstat', uid), 'actual ' + actual + '\nrss 123\n'),
            (prefix + ('domid', uid), '7\n')]


def test_libvirt_exact_kib_live_and_config_update_actual_readback():
    m = api()
    prefix = ('/usr/bin/virsh', '--connect', 'qemu:///system')
    uid = '11111111-1111-4111-8111-111111111111'
    updated = XML.replace('524288', '1048576')
    commands = Commands(libvirt_row() + libvirt_row() + [
        (prefix + ('setmem', uid, '1048576', '--live', '--config'), '')]
        + libvirt_row(updated, actual='1048576'))
    backend = m.LibvirtMemoryBackend(commands, '/usr/bin/virsh', 'qemu:///system',
                                    {'vm-a': m.LibvirtVM(uid, 'synthetic-domain')}, dynamic=True)
    before = backend.readback('vm-a')
    actual = backend.resize('vm-a', 1073741824, before, 30)
    assert backend.quantum_bytes == 1024
    assert before.assigned_bytes == 536870912
    assert actual.assigned_bytes == 1073741824
    assert before.config_fingerprint == actual.config_fingerprint
    assert commands.outputs == []


@pytest.mark.parametrize("mutation", ['foreign-uuid', 'foreign-name', 'missing-actual',
                                      'no-balloon', 'unknown-unit'])
def test_libvirt_unknown_or_foreign_domain_is_never_resized(mutation):
    m = api()
    xml = XML
    if mutation == 'foreign-uuid':
        xml = xml.replace('11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222')
    if mutation == 'foreign-name':
        xml = xml.replace('synthetic-domain', 'foreign-domain')
    if mutation == 'no-balloon':
        xml = xml.replace('model="virtio"', 'model="none"')
    if mutation == 'unknown-unit':
        xml = xml.replace('unit="KiB"', 'unit="pages"')
    outputs = libvirt_row(xml)
    if mutation == 'missing-actual':
        outputs[2] = (outputs[2][0], 'rss 524288\n')
    backend = m.LibvirtMemoryBackend(Commands(outputs), '/usr/bin/virsh', 'qemu:///system',
                 {'vm-a': m.LibvirtVM('11111111-1111-4111-8111-111111111111', 'synthetic-domain')},
                 dynamic=True)
    with pytest.raises(m.ResourceError):
        backend.readback('vm-a')


def test_argv_fields_reject_injection_and_remote_uri_before_command():
    m = api()
    for node in ('../foreign', 'node; reboot', '--node'):
        with pytest.raises(m.ResourceError):
            m.ProxmoxMemoryBackend(Commands([]), '/usr/bin/pvesh', node, {}, dynamic=True)
    with pytest.raises(m.ResourceError, match='local'):
        m.LibvirtMemoryBackend(Commands([]), '/usr/bin/virsh', 'qemu+ssh://foreign/system', {},
                              dynamic=True)


def test_duplicate_backend_enrollment_cannot_shrink_another_logical_vm_grant():
    m = api()
    same_pve = m.ProxmoxVM(101, '11111111-1111-4111-8111-111111111111')
    with pytest.raises(m.ResourceError, match='ownership'):
        m.ProxmoxMemoryBackend(Commands([]), '/usr/bin/pvesh', 'synthetic-node',
                                {'vm-a': same_pve, 'vm-b': same_pve}, dynamic=True)
    same_libvirt = m.LibvirtVM('11111111-1111-4111-8111-111111111111', 'synthetic-domain')
    with pytest.raises(m.ResourceError, match='ownership'):
        m.LibvirtMemoryBackend(Commands([]), '/usr/bin/virsh', 'qemu:///system',
                                {'vm-a': same_libvirt, 'vm-b': same_libvirt}, dynamic=True)


def test_native_root_boundary_refuses_unprivileged_caller_and_forged_paths(tmp_path):
    m = api()
    with pytest.raises(m.ResourceError, match='root_required'):
        m.RootNativeBoundary(tmp_path / 'client-controlled-config.json')
    path = tmp_path / 'policy.json'
    path.write_text('{}')
    with pytest.raises(m.ResourceError, match='trust'):
        m.read_root_json(path)
    link = tmp_path / 'linked-policy.json'
    link.symlink_to(path)
    with pytest.raises(m.ResourceError, match='trust'):
        m.read_root_json(link)


def test_root_probe_parser_rejects_duplicate_unknown_keys_and_incomplete_workload_inventory(tmp_path):
    m = api()
    with pytest.raises(m.ResourceError, match='duplicate_json'):
        m.strict_json('{"host_id":"a","host_id":"b"}')
    with pytest.raises(m.ResourceError):
        m.decode_host_evidence({'schema': 'qcl.host-resource-evidence.v1', 'host_id': 'synthetic'}, [])


def test_unsupported_backend_is_explicit_and_cannot_run_command():
    m = api()
    with pytest.raises(m.ResourceError, match='unsupported'):
        m.backend_from_config({'backend': 'hyper-v'}, Commands([]), dynamic=True)


def test_positive_protected_probe_decoding_keeps_exact_workload_inventory(tmp_path):
    from test_host_resource_operations import setup
    m = api()
    _, _, _, _, evidence = setup(tmp_path)
    raw = asdict(evidence)
    qualifications = raw.pop('qualifications')
    raw['schema'] = 'qcl.host-resource-evidence.v1'
    # Actual JSON transport turns all tuple fields into arrays.
    decoded = m.decode_host_evidence(json.loads(json.dumps(raw)),
                                    json.loads(json.dumps(qualifications)))
    assert decoded == evidence


@pytest.mark.parametrize('field', ['host_boot_id', 'host_kernel_id', 'qemu_version_id',
                                  'backend_version_id'])
def test_actual_native_runtime_change_refuses_before_mutation(tmp_path, field):
    from test_host_resource_operations import setup
    m = api()
    _, _, base, _, evidence = setup(tmp_path)
    facts = m.NativeRuntimeFacts('host-boot-1', 'host-kernel-1', 'qemu-1', 'backend-1')
    actual = [facts]
    backend = m.VerifiedNativeBackend(base, evidence, collector=lambda _b, _r: actual[0])
    before = backend.readback('vm-a')
    actual[0] = replace(facts, **{field: 'changed-native-runtime'})
    with pytest.raises(m.ResourceError, match='qualification'):
        backend.resize('vm-a', 512, before, 30)
    assert base.calls == []


def test_native_command_runner_bounds_output_and_reports_unknown_outcome(monkeypatch):
    m = api()
    # This executes only local synthetic Python, never pvesh/virsh/solver.
    monkeypatch.setattr(m.os, 'geteuid', lambda: 0)
    # The test container's system files are uid-mapped; root trust rejection has
    # its own test above. Replace only that external filesystem ownership check.
    monkeypatch.setattr(m, 'trusted_root_path', lambda path, **_: Path(path))
    python = str(Path(sys.executable).resolve())
    runner = m.NativeCommandRunner([python])
    assert runner.run([python, '-c', "print('synthetic')"], timeout_seconds=5,
                      max_output_bytes=128) == 'synthetic\n'
    with pytest.raises(m.ResourceError, match='output_bound'):
        runner.run([python, '-c', "print('x' * 4096)"], timeout_seconds=5, max_output_bytes=128)
    with pytest.raises(m.ResourceError, match='native_command'):
        runner.run([python, '-c', 'raise SystemExit(7)'], timeout_seconds=5, max_output_bytes=128)
    with pytest.raises(m.ResourceError, match='native_timeout'):
        runner.run([python, '-c', 'import time; time.sleep(5)'], timeout_seconds=1, max_output_bytes=128)
    with pytest.raises(m.ResourceError, match='argv'):
        runner.run(['/usr/bin/false'], timeout_seconds=5, max_output_bytes=128)


def cleanup_synthetic_group(identity, marker):
    """Failure-only fixture cleanup: verify our marker and group before signaling."""
    if identity is None:
        return
    path = Path('/proc') / str(identity['pid'])
    try:
        fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
        owned = marker.encode() in (path / 'cmdline').read_bytes() and int(fields[2]) == identity['pgid']
        if owned and fields[0] not in ('Z', 'X'):
            os.killpg(identity['pgid'], signal.SIGKILL)
    except (FileNotFoundError, ProcessLookupError):
        pass


def synthetic_process_state(pid):
    try:
        return (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()[0]
    except FileNotFoundError:
        return 'gone'


@pytest.mark.parametrize('leader_exits', [False, True])
def test_native_timeout_confirms_owned_descendant_cleanup_after_leader_exit(monkeypatch, leader_exits):
    m = api()
    monkeypatch.setattr(m.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(m, 'trusted_root_path', lambda path, **_: Path(path))
    python = str(Path(sys.executable).resolve())
    runner, identity = m.NativeCommandRunner([python]), None
    marker = 'qcl-p20-runner-' + uuid.uuid4().hex
    child = ("import json,os,time;print(json.dumps({'pid':os.getpid(),"
             "'pgid':os.getpgid(0)}),flush=True);time.sleep(30)")
    script = ("import subprocess,sys;subprocess.Popen([sys.executable,'-c'," + repr(child) +
              "," + repr(marker) + "])") if leader_exits else child
    try:
        with pytest.raises(m.ResourceError, match='native_timeout') as observed:
            runner.run([python, '-c', script, marker], timeout_seconds=1, max_output_bytes=4096)
        identity = json.loads(observed.value.native_output.strip())
        assert synthetic_process_state(identity['pid']) in ('gone', 'Z', 'X')
        assert observed.value.native_record['cleanup_confirmed'] is True
        assert observed.value.native_record['child_started'] is True
        assert observed.value.native_record['failure'] == 'timeout'
    finally:
        cleanup_synthetic_group(identity, marker)


def test_successful_native_leader_cannot_leave_owned_descendant_with_closed_output(monkeypatch):
    m = api()
    monkeypatch.setattr(m.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(m, 'trusted_root_path', lambda path, **_: Path(path))
    python = str(Path(sys.executable).resolve())
    marker, identity = 'qcl-p20-success-' + uuid.uuid4().hex, None
    script = ("import json,os,subprocess,sys;child=subprocess.Popen([sys.executable,'-c',"
              "'import time;time.sleep(30)'," + repr(marker) + "],stdout=subprocess.DEVNULL,"
              "stderr=subprocess.DEVNULL);print(json.dumps({'pid':child.pid,'pgid':os.getpgrp()}),flush=True)")
    try:
        output = m.NativeCommandRunner([python]).run([python, '-c', script], timeout_seconds=5,
                                                    max_output_bytes=4096)
        identity = json.loads(output)
        assert synthetic_process_state(identity['pid']) in ('gone', 'Z', 'X')
    finally:
        cleanup_synthetic_group(identity, marker)


def test_native_runner_preserves_shared_engine_original_failure_and_cleanup_evidence(monkeypatch):
    m = api()
    monkeypatch.setattr(m.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(m, 'trusted_root_path', lambda path, **_: Path(path))
    record = {'failure': 'cleanup_unconfirmed', 'returncode': 0, 'elapsed_seconds': 1,
              'stdout': 'original stdout\n', 'stderr': 'original stderr\n', 'output_truncated': False,
              'cleanup_confirmed': False, 'child_started': True, 'output_bytes': 32}

    def failed_owned_command(argv, **kwargs):
        raise m.release_commands.CommandFailure(record)

    monkeypatch.setattr(m.release_commands, 'command', failed_owned_command)
    python = str(Path(sys.executable).resolve())
    with pytest.raises(m.ResourceError, match='native_cleanup_unconfirmed') as observed:
        m.NativeCommandRunner([python]).run([python, '-c', 'pass'], timeout_seconds=1, max_output_bytes=4096)
    assert observed.value.native_record == record
    assert observed.value.native_output == 'original stdout\noriginal stderr\n'
    assert observed.value.native_argv == (python, '-c', 'pass')


def test_host_resource_shared_command_import_layout_runs_from_owning_ops_files(tmp_path):
    source = Path(__file__).resolve().parents[1] / 'ops'
    staged = tmp_path / 'ops'
    staged.mkdir()
    for name in ('host_resource_backends.py', 'host_resource_operations.py', 'host_resource_policy.py',
                 'application_release.py', 'release_identity.py', 'release_trust.py',
                 'release_qualification.py', 'release_health.py'):
        shutil.copyfile(source / name, staged / name)
    script = """import json,sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import host_resource_backends as resources
resources.os.geteuid = lambda: 0
resources.trusted_root_path = lambda path, **_: Path(path)
python = str(Path(sys.executable).resolve())
print(resources.NativeCommandRunner([python]).run([python, '-c', 'print(17)'],
    timeout_seconds=5, max_output_bytes=128).strip())
assert resources.release_commands.command.__module__ == 'application_release'
"""
    result = subprocess.run([sys.executable, '-I', '-c', script, str(staged)], check=True,
                            text=True, capture_output=True, timeout=10)
    assert result.stdout.strip() == '17'


def test_root_boundary_reconcile_uses_only_protected_cleanup_record_not_client_payload(tmp_path):
    from test_host_resource_operations import setup, request, native_cleanup
    m = api()
    operations, c, b, store, e = setup(tmp_path)
    c.request(request(operations), e)
    b.fault = 'native-cleanup-unconfirmed'
    c.grow('request-1', e)
    proof = native_cleanup(operations, store, e)
    boundary = m.RootNativeBoundary.__new__(m.RootNativeBoundary)
    # Synthetic protected-reader boundary; trust/path rejection is tested separately.
    probe = {'guests': {}, 'completions': {}, 'cleanups': {}}
    boundary.open = lambda: (c, e, probe)
    with pytest.raises(m.ResourceError, match='reconciliation_required'):
        boundary.invoke('reconcile', request_id='request-1')
    with pytest.raises(TypeError):
        boundary.invoke('reconcile', request_id='request-1', cleanup_evidence=proof)
    with pytest.raises(TypeError):
        boundary.invoke('reconcile', request_id='request-1', cleanup_path='/client/proof.json')
    with pytest.raises(m.ResourceError, match='shape'):
        boundary.invoke('reconcile', request_id='request-1', request=request(operations))
    probe['cleanups']['request-1'] = {**asdict(proof), 'client_path': '/client/proof.json'}
    with pytest.raises(m.ResourceError, match='shape'):
        boundary.invoke('reconcile', request_id='request-1')
    probe['cleanups']['request-1'] = asdict(proof)
    assert boundary.invoke('reconcile', request_id='request-1').phase == 'GUEST_ADMIT'
    assert boundary.invoke('reconcile', request_id='request-1').phase == 'GUEST_ADMIT'
    assert b.calls == [('vm-a', 512)]


@pytest.mark.parametrize('dynamic', [False, True])
@pytest.mark.parametrize('memory', ['4096', 4096])
def test_pve_memory_scalar_readback_keeps_raw_fingerprint_and_digest(dynamic, memory, monkeypatch):
    m = api()
    config = {**pve_config(), 'memory': memory, 'balloon': 512 if dynamic else 0}
    raw_before = dict(config)
    fingerprint = m.pve_config_fingerprint
    seen = []
    def capture(raw):
        seen.append(dict(raw))
        return fingerprint(raw)
    monkeypatch.setattr(m, 'pve_config_fingerprint', capture)
    backend = m.ProxmoxMemoryBackend(Commands(pve_row(config)), '/usr/bin/pvesh', 'synthetic-node',
        {'vm-a': m.ProxmoxVM(101, '11111111-1111-4111-8111-111111111111')}, dynamic=dynamic)
    row = backend.readback('vm-a')
    expected = (512 if dynamic else 4096) * 1024**2
    assert row.configured_bytes == row.assigned_bytes == expected
    assert row.revision == 'digest-1'
    assert row.config_fingerprint == fingerprint(raw_before)
    assert config == raw_before and seen == [raw_before]
    assert type(seen[0]['memory']) is type(memory)


@pytest.mark.parametrize('memory', [True, False, 1.0, None, -1, '-1', '0', 0,
    '', '01', '+1', ' 1', '1 ', '1.0', '1MiB', '١', pytest.param('9' * 5000, id='oversize'),
    str(((2**63-1)//(1024**2))+1), ((2**63-1)//(1024**2))+1])
def test_pve_memory_invalid_scalar_and_byte_overflow_refused(memory):
    m = api()
    config = {**pve_config(), 'memory': memory}
    backend = m.ProxmoxMemoryBackend(Commands(pve_row(config)), '/usr/bin/pvesh', 'synthetic-node',
        {'vm-a': m.ProxmoxVM(101, '11111111-1111-4111-8111-111111111111')}, dynamic=True)
    with pytest.raises(m.ResourceError):
        backend.readback('vm-a')


@pytest.mark.parametrize('as_string', [False, True])
def test_pve_memory_maximum_representable_bytes(as_string):
    m = api()
    maximum = (2**63 - 1) // 1024**2
    value = str(maximum) if as_string else maximum
    assert m.pve_memory_mib(value) * 1024**2 == maximum * 1024**2 < 2**63


@pytest.mark.parametrize('memory', ['2048', '4096', '8192', '36864'])
def test_pve_observed_memory_values_decode_exactly(memory):
    assert api().pve_memory_mib(memory) * 1024**2 == int(memory) * 1024**2


@pytest.mark.parametrize('balloon', [True, '512', 1.0, -1, None])
def test_pve_memory_string_does_not_relax_balloon_validation(balloon):
    m = api()
    config = {**pve_config(), 'memory': '4096', 'balloon': balloon}
    backend = m.ProxmoxMemoryBackend(Commands(pve_row(config)), '/usr/bin/pvesh', 'synthetic-node',
        {'vm-a': m.ProxmoxVM(101, '11111111-1111-4111-8111-111111111111')}, dynamic=True)
    with pytest.raises(m.ResourceError):
        backend.readback('vm-a')
