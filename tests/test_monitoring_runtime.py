"""Closed native/trust/storage fixtures, never invoke a host command."""
import copy
import importlib
import json
import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / 'ops'))


def module(name):
    assert (ROOT / 'ops' / (name + '.py')).exists(), 'missing P31 owner: ' + name
    return importlib.import_module(name)


def config(role='native_host'):
    return {'schema': 'qcl.monitoring-config.v1', 'role': role,
        'reader_uid': 2001, 'observer_uid': 2002,
        'tools': {'sudo': '/usr/bin/sudo', 'systemctl': '/usr/bin/systemctl',
                  'journalctl': '/usr/bin/journalctl', 'pvesh': '/usr/bin/pvesh',
                  'virsh': '/usr/bin/virsh'},
        'targets': [],
        'scopes': {'host_id': 'host-a', 'machine_id': '1' * 32, 'backend': 'disabled',
                   'node': None, 'version': None, 'vms': [], 'services': [],
                   'cgroups': [], 'journal': False},
        'bounds': {'command_seconds': 5, 'sample_seconds': 15, 'fresh_seconds': 10,
                   'output_bytes': 524288, 'journal_bytes': 131072, 'journal_events': 64,
                   'lookback_seconds': 60, 'retention_entries': 128},
        'storage': {'binding': 'unqualified', 'directory': '/var/log/qcl-negf-monitoring',
                    'maximum_bytes': None, 'keep_free_bytes': 1048576, 'retention_seconds': 604800,
                    'minimum_inodes': 16, 'device': None, 'quota_project': None},
        'graph_links': []}


def test_unknown_storage_never_deletes_or_disables_read_projection(tmp_path):
    m = module('monitoring_runtime')
    value = config()
    value['storage']['directory'] = str(tmp_path)
    sentinel = tmp_path / 'unrelated.log'
    sentinel.write_text('preserve')
    view = m.StorageBoundary(value, clock=lambda: 100).read()
    assert view['status'] == 'unknown' and view['persist_enabled'] is False
    assert m.StorageBoundary(value, clock=lambda: 100).maintain()['persist_enabled'] is False
    assert sentinel.read_text() == 'preserve'


def test_config_and_fixed_transport_reject_untrusted_inputs():
    m = module('monitoring_runtime')
    assert m.validate_config(config())['role'] == 'native_host'
    for mutate in [lambda c: c.update(reader_uid=0),
                   lambda c: c.update(observer_uid=c['reader_uid']),
                   lambda c: c['tools'].update(sudo='/tmp/../sudo'),
                   lambda c: c.update(path='/private/ledger'),
                   lambda c: c['graph_links'].append({'host_id': 'host-a', 'label': 'PVE',
                       'href': 'https://user:password@example.invalid/', 'origin': 'https://example.invalid'})]:
        broken = copy.deepcopy(config()); mutate(broken)
        with pytest.raises(ValueError): m.validate_config(broken)
    good = m.encode_query({'schema': 'qcl.cluster-query.v1', 'request_id': None, 'cursor': None, 'limit': 64})
    assert m.decode_query(good)['limit'] == 64
    for token in [';', 'A' * 12000, m.encode_token({'schema': 'qcl.cluster-query.v1', 'path': '/secret'})]:
        with pytest.raises(ValueError): m.decode_query(token)
    assert m.forced_command('/helper/qcl-negf-monitor-rpc observe ' + good,
                            helper='/helper/qcl-negf-monitor-rpc') == good
    with pytest.raises(ValueError): m.forced_command('/helper/qcl-negf-monitor-rpc sample ' + good,
                                                    helper='/helper/qcl-negf-monitor-rpc')


def test_sudo_environment_does_not_authorize_without_actual_parent_chain():
    m = module('monitoring_runtime')
    caller = {'pid': 11, 'ppid': 1, 'uids': [2001] * 4, 'start_ticks': 10,
              'cgroup': '/user.slice/session.scope', 'executable': '/usr/bin/client'}
    sudo = {'pid': 12, 'ppid': 11, 'uids': [2001, 0, 0, 0], 'start_ticks': 11,
            'cgroup': caller['cgroup'], 'executable': '/usr/bin/sudo'}
    records = {11: caller, 12: sudo}
    assert m.authenticate({'SUDO_UID': '2001'}, 12, records.__getitem__, '/usr/bin/sudo', 2001) == caller
    with pytest.raises(ValueError): m.authenticate({'SUDO_UID': '2001'}, 11, records.__getitem__, '/usr/bin/sudo', 2001)
    with pytest.raises(ValueError): m.authenticate({'SUDO_UID': '2002'}, 12, records.__getitem__, '/usr/bin/sudo', 2001)


def test_scoped_retention_only_removes_closed_owned_ndjson(tmp_path):
    m = module('monitoring_runtime')
    value = config(); value['storage'].update(directory=str(tmp_path), binding='dedicated_mount',
        maximum_bytes=10000, device=7, keep_free_bytes=100, retention_seconds=10, minimum_inodes=1)
    old = tmp_path / 'events-1970-01-01.ndjson'; old.write_text('old'); os.utime(old, (1, 1))
    foreign = tmp_path / 'foreign.log'; foreign.write_text('untouched')
    link = tmp_path / 'events-1970-01-02.ndjson'; link.symlink_to(foreign)
    facts = {'qualified': True, 'binding': 'dedicated_mount', 'device': 7, 'maximum_bytes': 10000,
             'used_bytes': 1000, 'available_bytes': 9000, 'inodes_available': 100, 'owner_uid': os.getuid(),
             'proof': m.CapacityEvidence(7, 10000, 100, True, False)}
    store = m.StorageBoundary(value, clock=lambda: 172900, observe=lambda: facts, owner_uid=os.getuid())
    assert store.read()['persist_enabled'] is True
    result = store.maintain()
    assert not old.exists() and foreign.read_text() == 'untouched' and link.is_symlink()
    assert result['status'] == 'degraded'  # rejected link is visible, never followed
    facts['available_bytes'] = 0
    assert store.read()['persist_enabled'] is False


def test_same_statvfs_shape_is_not_backing_or_reserve_proof(tmp_path):
    m = module('monitoring_runtime'); c = config()
    c['storage'].update(directory=str(tmp_path), binding='dedicated_mount', device=7, maximum_bytes=10000,
                        keep_free_bytes=100, minimum_inodes=1, retention_seconds=10)
    sentinel = tmp_path / 'events-1970-01-01.ndjson'; sentinel.write_text('keep'); os.utime(sentinel, (1, 1))
    facts = dict(qualified=True, binding='dedicated_mount', device=7, maximum_bytes=10000,
                 used_bytes=1000, available_bytes=9000, inodes_available=100, owner_uid=os.getuid(), proof=None)
    for proof in [None, {'independent_backing': True},
                  m.CapacityEvidence(7, 10000, 100, False, True),
                  m.CapacityEvidence(7, 10000, 0, True, False),
                  m.CapacityEvidence(8, 10000, 100, True, False)]:
        facts['proof'] = proof
        store = m.StorageBoundary(c, clock=lambda: 172900, observe=lambda: facts, owner_uid=os.getuid())
        view = store.maintain()
        assert not view['persist_enabled'] and view['status'] == 'unknown'
        assert view['maximum_bytes'] == 10000 and view['available_bytes'] == 9000
        assert sentinel.read_text() == 'keep'
    c['storage']['binding'] = 'project_quota'
    view = m.StorageBoundary(c).read()
    assert view['status'] == 'unsupported' and not view['persist_enabled']


def test_bounded_command_engine_drops_partial_output_and_has_global_sample_deadline(monkeypatch):
    m = module('monitoring_runtime'); import application_release
    c = config(); calls = []
    monkeypatch.setattr(m, 'validate_tool', lambda p: None)
    def failed(argv, **kwargs):
        calls.append((argv, kwargs))
        raise application_release.CommandFailure(dict(failure='output_limit', returncode=-9, cleanup_confirmed=True,
                    output_truncated=True, output_bytes=4096, stdout='SECRET partial', stderr=''))
    monkeypatch.setattr(application_release, 'command', failed)
    source = m.NativeSources(c)
    with pytest.raises(application_release.CommandFailure) as caught:
        source.run([c['tools']['journalctl'], '--lines=64'])
    assert caught.value.record['output_bytes'] == 4096
    assert calls[0][1]['deadline'] == source.deadline
    assert calls[0][1]['timeout_seconds'] == 5
    assert source.bytes == 4096
    source.deadline = 0
    with pytest.raises(ValueError, match='sample_budget'):
        source.read('/NEVER/READ')


def test_query_json_duplicate_keys_and_sudo_generation_drift_fail_closed():
    m = module('monitoring_runtime'); import base64
    token = base64.urlsafe_b64encode(b'{"schema":"qcl.cluster-query.v1","schema":"bad"}').decode().rstrip('=')
    with pytest.raises(ValueError): m.decode_query(token)
    calls = 0
    caller = dict(pid=11, ppid=1, uids=[2001]*4, start_ticks=1, cgroup='same', executable='/client')
    sudo = dict(pid=12, ppid=11, uids=[2001,0,0,0], start_ticks=2, cgroup='same', executable='/sudo')
    def process(pid):
        nonlocal calls
        calls += 1
        if calls > 2: return {**caller, 'start_ticks': 99}
        return caller if pid == 11 else sudo
    with pytest.raises(ValueError, match='caller_changed'):
        m.authenticate({'SUDO_UID':'2001'}, 12, process, '/sudo', 2001)



def test_native_source_accepts_real_command_output_and_charges_stderr_bytes(monkeypatch):
    m = module('monitoring_runtime'); import application_release as engine
    c = config(); monkeypatch.setattr(m, 'validate_tool', lambda _: None)
    output = engine.CommandOutput('native-μ-output')
    output.output_bytes = len(output.encode()) + 11  # owning count includes stderr
    calls = []
    def command(argv, **kw): calls.append(kw); return output
    monkeypatch.setattr(engine, 'command', command)
    source = m.NativeSources(c)
    assert source.run([c['tools']['journalctl'], '--lines=1']) is output
    assert source.bytes == output.output_bytes
    assert source.run([c['tools']['journalctl'], '--lines=1']) == 'native-μ-output'
    assert calls[1]['output_bytes'] == c['bounds']['output_bytes'] - output.output_bytes


def test_native_source_accounts_real_failure_and_never_accepts_partial_stdout(monkeypatch):
    m = module('monitoring_runtime'); import application_release as engine
    c = config(); monkeypatch.setattr(m, 'validate_tool', lambda _: None)
    record = dict(failure='nonzero', returncode=1, cleanup_confirmed=True, output_truncated=False,
                  output_bytes=37, stdout='bounded partial', stderr='bounded failure')
    failure = engine.CommandFailure(record)
    def command(*a, **kw): raise failure
    monkeypatch.setattr(engine, 'command', command)
    source = m.NativeSources(c)
    with pytest.raises(engine.CommandFailure) as caught:
        source.run([c['tools']['journalctl'], '--lines=1'])
    assert caught.value is failure and caught.value.record is record
    assert source.bytes == 37


def test_observer_real_command_output_uses_str_and_fixed_p11_ssh(monkeypatch):
    m = module('monitoring_runtime'); import application_release as engine
    from test_cluster_projection import packet, target
    import release_trust
    monkeypatch.setattr(m, 'load_config', lambda: config('controller'))
    reads = []
    def protected(path, *args): reads.append(path); return b'key' if str(path).endswith('/key') else b'host key'
    monkeypatch.setattr(release_trust, 'read_protected_file', protected)
    expected = packet(); result = engine.CommandOutput(json.dumps(expected)); result.output_bytes = len(result.encode())
    calls = []
    def command(argv, **kwargs): calls.append((argv, kwargs)); return result
    monkeypatch.setattr(engine, 'command', command)
    query = dict(schema='qcl.cluster-query.v1', request_id=None, cursor=None, limit=64)
    assert m.observe_remote(target('host-a'), query) == expected
    assert len(reads) == 4  # trust/key before and after; no trust snapshot write
    assert calls[0][0][0] == 'ssh' and '-oStrictHostKeyChecking=yes' in calls[0][0]
    assert '-oIdentitiesOnly=yes' in calls[0][0] and '-oClearAllForwardings=yes' in calls[0][0]
    assert calls[0][1]['output_bytes'] == config()['bounds']['output_bytes']
    assert 'SSH_AUTH_SOCK' not in calls[0][1]['env']


@pytest.mark.parametrize('variant,expected', [('stale', 'stale_cursor'), ('timeout', 'observer_transport_unavailable'),
    ('timeout_exit_one', 'observer_transport_unavailable'),
    ('truncated', 'observer_transport_unavailable'), ('unclean', 'observer_transport_unavailable'),
    ('malformed', 'observer_transport_unavailable')])
def test_observer_real_failure_maps_only_clean_typed_cursor_error(monkeypatch, variant, expected):
    m = module('monitoring_runtime'); import application_release as engine
    from test_cluster_projection import target
    import release_trust
    monkeypatch.setattr(m, 'load_config', lambda: config('controller'))
    monkeypatch.setattr(release_trust, 'read_protected_file', lambda *a: b'protected bytes')
    record = dict(failure='nonzero', returncode=1, cleanup_confirmed=True, output_truncated=False,
                  output_bytes=100, stdout='discard partial',
                  stderr=json.dumps(dict(schema='qcl.monitoring-error.v1', reason='stale_cursor')))
    if variant == 'timeout': record.update(failure='timeout', returncode=-9)
    if variant == 'timeout_exit_one': record.update(failure='timeout', returncode=1)
    if variant == 'truncated': record.update(failure='output_limit', output_truncated=True)
    if variant == 'unclean': record['cleanup_confirmed'] = False
    if variant == 'malformed': record['stderr'] = 'PRIVATE malformed transport detail'
    failure = engine.CommandFailure(record)
    def command(*a, **kw): raise failure
    monkeypatch.setattr(engine, 'command', command)
    with pytest.raises(ValueError, match='^' + expected + '$') as caught:
        m.observe_remote(target('host-a'), dict(schema='qcl.cluster-query.v1', request_id=None, cursor=None, limit=64))
    assert caught.value.__cause__ is failure
    assert 'PRIVATE' not in str(caught.value)


def test_command_success_dict_is_not_a_supported_p11_contract(monkeypatch):
    m = module('monitoring_runtime'); import application_release as engine
    monkeypatch.setattr(m, 'validate_tool', lambda _: None)
    monkeypatch.setattr(engine, 'command', lambda *a, **kw: dict(stdout='wrong API', stderr='', output_bytes=9,
        failure=None, returncode=0, cleanup_confirmed=True))
    with pytest.raises(ValueError, match='command_contract'):
        m.NativeSources(config()).run([config()['tools']['journalctl'], '--lines=1'])


def test_failed_command_exhausts_sample_output_budget_before_next_executor(monkeypatch):
    m = module('monitoring_runtime'); import application_release as engine
    c = config(); c['bounds']['output_bytes'] = 16384; calls = []
    monkeypatch.setattr(m, 'validate_tool', lambda _: None)
    record = dict(failure='output_limit', returncode=-9, cleanup_confirmed=True,
                  output_truncated=True, output_bytes=16384, stdout='partial', stderr='')
    def command(*a, **kw): calls.append(kw); raise engine.CommandFailure(record)
    monkeypatch.setattr(engine, 'command', command)
    source = m.NativeSources(c)
    with pytest.raises(engine.CommandFailure): source.run([c['tools']['journalctl'], '--lines=1'])
    assert source.bytes == c['bounds']['output_bytes']
    with pytest.raises(ValueError, match='sample_budget'):
        source.run([c['tools']['journalctl'], '--lines=1'])
    assert len(calls) == 1
