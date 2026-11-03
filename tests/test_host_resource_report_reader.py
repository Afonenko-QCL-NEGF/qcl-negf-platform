"""Dedicated large report reader bounds and held/named metadata joins; Source/L."""
import json
import os
from pathlib import Path
import stat
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ops'))
import host_resource_backends as m


@pytest.fixture
def protected_fixture(monkeypatch, tmp_path):
    # Only this file fixture substitutes protected ownership; production has no
    # owner override, and its real trusted_root_path is separately tested.
    original_fstat, original_lstat = os.fstat, os.lstat
    def root_owned(value):
        # stat_result(list) loses nanosecond extension fields; preserve them.
        class Snapshot:
            pass
        result = Snapshot()
        for name in dir(value):
            if name.startswith('st_'):
                setattr(result, name, 0 if name == 'st_uid' else getattr(value, name))
        return result
    monkeypatch.setattr(m, 'trusted_root_path', lambda path: Path(path))
    monkeypatch.setattr(m.os, 'fstat', lambda fd: root_owned(original_fstat(fd)))
    monkeypatch.setattr(m.os, 'lstat', lambda path: root_owned(original_lstat(path)))
    return tmp_path / 'report.json', root_owned, original_lstat


def reader():
    value = getattr(m, 'read_root_qualification_report', None)
    assert callable(value), 'missing dedicated bounded protected qualification report reader'
    return value


def test_report_larger_than_rpc_bound_is_read_without_changing_generic_limit(protected_fixture):
    path, _, _ = protected_fixture
    document = dict(schema='qcl.host-resource-calibration-report.v1', metadata='x' * (300 * 1024))
    path.write_text(json.dumps(document));path.chmod(0o600)
    assert reader()(path) == document
    assert m.MAX_OUTPUT_BYTES == 256 * 1024


@pytest.mark.parametrize('kind', ['oversize', 'wrong-schema', 'duplicate-key', 'hardlink', 'symlink', 'writable'])
def test_report_rejects_malformed_oversized_or_unsafe_input(protected_fixture, kind):
    path, _, _ = protected_fixture
    raw = b'{"schema":"qcl.host-resource-calibration-report.v1"}'
    if kind == 'oversize':
        raw += b' ' * (8 * 1024**2)
    elif kind == 'wrong-schema':
        raw = b'{"schema":"other"}'
    elif kind == 'duplicate-key':
        raw = b'{"schema":"qcl.host-resource-calibration-report.v1","x":1,"x":2}'
    path.write_bytes(raw);path.chmod(0o600)
    if kind == 'hardlink':
        path.with_suffix('.link').hardlink_to(path)
    elif kind == 'symlink':
        target = path.with_suffix('.target');path.rename(target);path.symlink_to(target)
    elif kind == 'writable':
        path.chmod(0o622)
    with pytest.raises((m.ResourceError, OSError, ValueError)):
        reader()(path)


def test_named_file_replacement_during_read_refuses(protected_fixture, monkeypatch):
    path, root_owned, original_lstat = protected_fixture
    path.write_text('{"schema":"qcl.host-resource-calibration-report.v1"}');path.chmod(0o600)
    original_read = os.read
    changed = []
    def replace_after_read(fd, count):
        data = original_read(fd, count)
        if not changed:
            changed.append(True)
            replacement = path.with_suffix('.replacement')
            replacement.write_text('{"schema":"qcl.host-resource-calibration-report.v1"}')
            replacement.chmod(0o600);replacement.replace(path)
        return data
    monkeypatch.setattr(m.os, 'read', replace_after_read)
    with pytest.raises(m.ResourceError, match='trust'):
        reader()(path)


def test_runtime_report_refuses_store_namespace_before_source_trust_payload_read(monkeypatch):
    import runtime_bindings
    calls = []
    def forbidden_source_read(path, *, limit):
        calls.append((str(path), limit))
        raise AssertionError('report must not enter generic store Source payload pre-read')
    monkeypatch.setattr(runtime_bindings, 'read_store_file', forbidden_source_read)
    with pytest.raises(m.ResourceError, match='trust'):
        reader()('/nix/store/' + 'a' * 32 + '-report-fixture/report.json')
    assert calls == []
