"""Bridge guard contracts. Only fake NM and offline libnm: never a system bus/client."""
import importlib.util
import os
import sys
from copy import deepcopy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def api():
    path = ROOT / 'ops/linux_bridge_nm.py'
    assert path.is_file(), 'NM bridge guard implementation is missing'
    spec = importlib.util.spec_from_file_location('linux_bridge_nm', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def settings():
    return {
        'connection': {'id': ['s', "'example bridge'"], 'uuid': ['s', "'master'"],
                       'type': ['s', "'bridge'"]},
        'bridge': {'stp': ['b', 'false']},
        '802-3-ethernet': {'mtu': ['u', 'uint32 1500']},
        'ipv4': {'method': ['s', "'auto'"], 'route-metric': ['x', 'int64 600']},
        'ipv6': {'method': ['s', "'auto'"]},
        'user': {'data': ['a{ss}', "{'example.owner': 'keep me'}"]},
    }


def snapshot(api, owner='PORT'):
    saved = settings()
    return {
        'exists': True, 'valid': True, 'reason': '', 'epoch': ['boot', 'bus', ':1.5'],
        'source': 'source-v1', 'policy': 'binding-v1', 'nm_version': '1.58.1',
        'identity': {'bridge_path': '/devices/bridge', 'bridge_ifindex': 21,
                     'profile_path': '/settings/master', 'bridge_uuid': 'master',
                     'port_uuid': 'port', 'permanent_mac': '02:00:00:00:00:01'},
        'owner': {'kind': owner, 'ifindex': 22, 'active_uuid': 'port' if owner == 'PORT'
                  else 'home', 'active_path': '/active/1', 'state': 100,
                  'attached': owner == 'PORT', 'carrier': owner == 'PORT'},
        'saved': saved, 'profile_hash': api.profile_hash(saved),
        'applied': deepcopy(saved), 'version': 41, 'token': None,
        'settlement': {'suspended': False, 'restored': True},
        'protected': {'l2': {'bridge': 21, 'mtu': 1500, 'tap': 23},
                      'foreign': {'home': ['192.0.2.20'], 'vpn': ['198.51.100.1']}},
    }


class FakeNM:
    """Independent owner, CAS acceptance, reply loss and delayed kernel stage3."""
    def __init__(self, api, initial):
        self.api, self.current = api, deepcopy(initial)
        self.calls, self.after_call, self.before_read = [], None, None
        self.fail, self.defer, self.queued = False, False, []
        self.reads = 0

    def snapshot(self):
        self.reads += 1
        if self.before_read:
            self.before_read(self)
        return deepcopy(self.current)

    def reapply(self, op):
        self.calls.append(deepcopy(op))
        if self.defer:
            self.queued.append(deepcopy(op))
        else:
            self.accept(op)
        if self.after_call:
            self.after_call(self)
        if self.fail:
            raise TimeoutError('reply lost after possible acceptance')
        # Native Reapply is void.

    def accept(self, op):
        if op['before_version'] != self.current['version']:
            return False
        self.current['applied'] = deepcopy(op['payload'])
        self.current['token'] = op['nonce']
        self.current['version'] += 1
        return True


def store(api, tmp_path):
    return api.Store(tmp_path / 'state' / 'state.json', tmp_path / 'run' / 'pending.json',
                     tmp_path / 'run' / 'guard.lock', owner_uid=os.getuid(),
                     ancestor_uids=(0, Path("/").stat().st_uid))


def wake(api, nm, state):
    state.initialize()
    nonce = state.notify()
    return api.reconcile(nm, state, nonce)


def test_empty_bridge_is_suspended_without_touching_l2_or_foreign(api, tmp_path):
    nm = FakeNM(api, snapshot(api, 'HOME'))
    before = deepcopy(nm.current)
    state = store(api, tmp_path)
    result = wake(api, nm, state)
    assert result['state'] == 'APPLIED_OBSERVED'
    assert result['worker_ready'] is False
    assert len(nm.calls) == 1
    payload = nm.calls[0]['payload']
    assert payload['ipv4'] == {'method': ['s', "'disabled'"],
                               'address-data': ['aa{sv}', '@aa{sv} []'],
                               'route-data': ['aa{sv}', '@aa{sv} []']}
    assert payload['ipv6'] == payload['ipv4']
    for section in ('connection', 'bridge', '802-3-ethernet'):
        assert payload[section] == before['applied'][section]
    assert api.user_data(payload) == {
        'example.owner': 'keep me', api.TOKEN_KEY: nm.calls[0]['nonce']}
    assert nm.current['saved'] == before['saved']
    assert nm.current['protected'] == before['protected']
    # Delayed kernel settlement does not become PASS from a void reply.
    nm.current['settlement'] = {'suspended': True, 'restored': False}
    result = wake(api, nm, state)
    assert result['state'] == 'SUSPENDED_SETTLED'
    assert len(nm.calls) == 1


def test_crash_after_accepted_disable_restores_only_own_intent(api, tmp_path):
    nm = FakeNM(api, snapshot(api, 'HOME'))
    nm.fail = True
    state = store(api, tmp_path)
    result = wake(api, nm, state)
    assert result['worker_ready'] is False
    nm.current['owner'] = snapshot(api)['owner']
    nm.fail = False
    nm.current['settlement'] = {'suspended': False, 'restored': False}
    result = wake(api, nm, state)
    assert len(nm.calls) == 2
    assert nm.calls[-1]['action'] == 'RESTORE_L3'
    assert nm.current['applied']['ipv4'] == nm.current['saved']['ipv4']
    assert result['state'] == 'APPLIED_OBSERVED'
    nm.current['settlement']['restored'] = True
    result = wake(api, nm, state)
    assert result['worker_ready'] is True
    assert result['state'] == 'RESTORED_SETTLED'


def test_prepared_wal_survives_caller_cancellation(api, tmp_path):
    nm = FakeNM(api, snapshot(api, 'HOME'))
    state = store(api, tmp_path)
    def killed(fake):
        raise KeyboardInterrupt()
    nm.after_call = killed
    with pytest.raises(KeyboardInterrupt):
        wake(api, nm, state)
    assert state.read()['op']['state'] == 'PREPARED'
    assert state.read()['op']['payload_hash'] == api.digest(nm.current['applied'])
    nm.after_call = None
    nm.current['settlement']['suspended'] = True
    assert wake(api, nm, state)['state'] == 'SUSPENDED_SETTLED'
    assert len(nm.calls) == 1


@pytest.mark.parametrize('change', ['epoch', 'source', 'policy', 'profile', 'higher_version'])
def test_external_change_revokes_restore_authority(api, tmp_path, change):
    nm = FakeNM(api, snapshot(api, 'HOME'))
    state = store(api, tmp_path)
    wake(api, nm, state)
    nm.current['owner'] = snapshot(api)['owner']
    if change == 'profile':
        nm.current['saved']['ipv4']['route-metric'] = ['x', 'int64 700']
        nm.current['profile_hash'] = api.profile_hash(nm.current['saved'])
    elif change == 'higher_version':
        nm.current['version'] += 1  # Even retained token/hash does not prove own edit.
    else:
        nm.current[change] = ['new', 'bus', ':1.6'] if change == 'epoch' else 'new'
    result = wake(api, nm, state)
    assert result['worker_ready'] is False
    assert len(nm.calls) == 1
    assert result['state'] == 'REVOKED'


def test_user_disabled_and_missing_bridge_never_restored(api, tmp_path):
    initial = snapshot(api)
    initial['applied']['ipv4'] = {'method': ['s', "'disabled'"]}
    initial['applied']['ipv6'] = {'method': ['s', "'disabled'"]}
    initial['settlement']['restored'] = False
    nm = FakeNM(api, initial)
    state = store(api, tmp_path)
    assert wake(api, nm, state)['state'] == 'REFUSED'
    assert not nm.calls
    nm.current = {'exists': False, 'valid': True}
    assert wake(api, nm, state)['state'] == 'NOOP_ABSENT'
    assert not nm.calls


def test_port_to_home_race_compensates_with_fresh_cas_at_most_twice(api, tmp_path):
    nm = FakeNM(api, snapshot(api, 'HOME'))
    state = store(api, tmp_path)
    wake(api, nm, state)
    nm.current['owner'] = snapshot(api)['owner']
    def home_after_restore(fake):
        if fake.calls[-1]['action'] == 'RESTORE_L3':
            fake.current['owner'] = snapshot(api, 'HOME')['owner']
    nm.after_call = home_after_restore
    count = len(nm.calls)
    result = wake(api, nm, state)
    assert len(nm.calls) - count == 2
    assert [x['action'] for x in nm.calls[-2:]] == ['RESTORE_L3', 'SUSPEND_L3']
    assert nm.calls[-1]['before_version'] == nm.calls[-2]['before_version'] + 1
    assert result['worker_ready'] is False


def test_tap_carrier_does_not_replace_physical_carrier(api, tmp_path):
    current = snapshot(api)
    current['owner']['carrier'] = False
    nm = FakeNM(api, current)
    result = wake(api, nm, store(api, tmp_path))
    assert nm.calls[0]['action'] == 'SUSPEND_L3'
    assert result['worker_ready'] is False


def test_unknown_old_disable_is_fenced_when_port_returns(api, tmp_path):
    nm = FakeNM(api, snapshot(api, 'HOME'))
    nm.defer, nm.fail = True, True
    state = store(api, tmp_path)
    assert wake(api, nm, state)['worker_ready'] is False
    old = deepcopy(nm.queued[0])
    nm.current['owner'] = snapshot(api)['owner']
    nm.defer, nm.fail = False, False
    result = wake(api, nm, state)
    assert nm.calls[-1]['action'] == 'FENCE_CURRENT'
    assert nm.calls[-1]['nonce'] != old['nonce']
    assert nm.calls[-1]['payload']['ipv4'] == old['before_applied']['ipv4']
    assert nm.accept(old) is False
    assert result['worker_ready'] is True


def test_unknown_same_goal_can_close_without_unbounded_retries(api, tmp_path):
    nm = FakeNM(api, snapshot(api, 'HOME'))
    nm.defer, nm.fail = True, True
    state = store(api, tmp_path)
    wake(api, nm, state)
    original = deepcopy(nm.calls[0])
    wake(api, nm, state)
    assert len(nm.calls) <= 3
    for op in nm.calls:
        assert (op['nonce'], op['before_version'], op['payload']) == (
            original['nonce'], original['before_version'], original['payload'])
    assert nm.accept(original)
    assert not nm.accept(original)


def test_status_is_read_only_and_new_dirty_generation_closes_ready(api, tmp_path):
    nm = FakeNM(api, snapshot(api))
    state = store(api, tmp_path)
    assert api.status(nm, state)['worker_ready'] is False  # Never initialized/processed.
    assert list(tmp_path.iterdir()) == []
    assert wake(api, nm, state)['worker_ready'] is True
    before = {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in tmp_path.rglob('*') if p.is_file()}
    assert api.status(nm, state)['worker_ready'] is True
    after = {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in tmp_path.rglob('*') if p.is_file()}
    assert after == before
    state.notify()
    assert api.status(nm, state)['worker_ready'] is False


def test_capture_processed_generation_before_readback_not_after(api, tmp_path):
    nm = FakeNM(api, snapshot(api))
    state = store(api, tmp_path)
    state.initialize()
    captured = state.notify()
    changed = []
    def event_during_read(fake):
        if not changed:
            changed.append(state.notify())
    nm.before_read = event_during_read
    result = api.reconcile(nm, state, captured)
    assert state.read()['processed'] == captured
    assert state.pending()['nonce'] == changed[0]
    assert result['worker_ready'] is False
    assert api.status(nm, state)['worker_ready'] is False
    nm.before_read = None
    assert wake(api, nm, state)['worker_ready'] is True


def test_busy_handoff_is_pending_and_next_explicit_wake_can_pick_up(api, tmp_path):
    nm = FakeNM(api, snapshot(api))
    state = store(api, tmp_path)
    state.initialize()
    with state.lock():
        nonce = state.notify()
        result = api.reconcile(nm, state, nonce, lock_timeout=0)
    assert result['state'] == 'PENDING_HANDOFF'
    assert result['worker_ready'] is False
    assert nm.reads == 0
    assert wake(api, nm, state)['worker_ready'] is True


def test_foreign_or_l2_change_after_rpc_never_settles(api, tmp_path):
    nm = FakeNM(api, snapshot(api, 'HOME'))
    nm.current['settlement']['suspended'] = True
    state = store(api, tmp_path)
    def external(fake):
        fake.current['protected']['l2']['mtu'] = 9000
    nm.after_call = external
    result = wake(api, nm, state)
    assert result['worker_ready'] is False
    assert result['state'] == 'REFUSED'
    assert len(nm.calls) == 1


def test_atomic_marker_symlink_and_malformed_state_refused(api, tmp_path):
    state = store(api, tmp_path)
    state.initialize()
    target = tmp_path / 'foreign'
    target.write_text('untouched')
    state.state_path.symlink_to(target)
    with pytest.raises(api.Refused):
        state.write({'schema': api.SCHEMA})
    assert target.read_text() == 'untouched'
    state.state_path.unlink()
    state.state_path.write_text('{broken')
    state.state_path.chmod(0o600)
    with pytest.raises(api.Refused):
        state.read()


def test_profile_timestamp_only_is_volatile(api):
    initial = settings()
    changed = deepcopy(initial)
    changed['connection']['timestamp'] = ['t', 'uint64 100']
    assert api.profile_hash(initial) == api.profile_hash(changed)
    changed['bridge']['stp'] = ['b', 'true']
    assert api.profile_hash(initial) != api.profile_hash(changed)


def test_offline_typed_payload_preserves_all_non_ip_settings(api):
    initial = settings()
    payload = api.payload(initial, initial, 'SUSPEND_L3', 'operation-one')
    variant = api.to_variant(payload)
    assert variant.get_type_string() == 'a{sa{sv}}'
    assert api.from_variant(variant) == payload
    assert api.user_data(payload)['example.owner'] == 'keep me'
    assert api.user_data(payload)[api.TOKEN_KEY] == 'operation-one'
    assert {k for k in payload if payload[k] != initial[k]} == {'ipv4', 'ipv6', 'user'}
    args = api.reapply_arguments(payload, 41)
    assert args.get_type_string() == '(a{sa{sv}}tu)'
    assert args.get_child_value(1).unpack() == 41
    assert args.get_child_value(2).unpack() == 1
    with pytest.raises(api.Refused):
        api.reapply_arguments(payload, 0)


def test_offline_rendered_profiles_native_parse_and_single_l3_owner(api):
    from gi.repository import NM, GLib
    from jinja2 import Environment, StrictUndefined
    values = {'qcl_nm_bridge_name': 'br-example',
              'qcl_nm_bridge_uuid': '11111111-1111-4111-8111-111111111111',
              'qcl_nm_port_uuid': '22222222-2222-4222-8222-222222222222',
              'qcl_nm_permanent_mac': '02:00:00:00:00:01',
              'qcl_nm_stage_directory': '/private/stage'}
    parsed = {}
    for name in ('bridge', 'uplink'):
        text = Environment(undefined=StrictUndefined).from_string((ROOT /
            f'ansible/templates/networkmanager/{name}.nmconnection.j2').read_text()).render(values)
        keyfile = GLib.KeyFile()
        keyfile.load_from_data(text, len(text.encode()), GLib.KeyFileFlags.NONE)
        connection = NM.keyfile_read(keyfile, '/', NM.KeyfileHandlerFlags.NONE)
        assert connection.verify()
        parsed[name] = connection
    bridge, port = parsed['bridge'], parsed['uplink']
    assert bridge.get_setting_connection().get_autoconnect() is False
    assert bridge.get_setting_connection().get_autoconnect_ports() == 0
    assert bridge.get_setting_ip4_config().get_method() == 'auto'
    assert bridge.get_setting_ip4_config().get_num_addresses() == 0
    assert bridge.get_setting_ip4_config().get_gateway() is None
    assert bridge.get_setting_ip4_config().get_dhcp_client_id() == '01:02:00:00:00:00:01'
    assert port.get_setting_connection().get_autoconnect() is True
    assert port.get_setting_connection().get_controller() == values['qcl_nm_bridge_uuid']
    assert port.get_setting_connection().get_interface_name() is None
    assert port.get_setting_wired().get_mac_address().lower() == values['qcl_nm_permanent_mac']
    assert port.get_setting_ip4_config() is None
    assert port.get_setting_ip6_config() is None


def test_returning_native_port_can_change_attachment_between_wakes(api, tmp_path):
    nm = FakeNM(api, snapshot(api, 'HOME'))
    state = store(api, tmp_path)
    wake(api, nm, state)
    nm.current['owner'] = snapshot(api)['owner']
    nm.current['protected']['l2']['physical_master'] = 21
    result = wake(api, nm, state)
    assert len(nm.calls) == 2
    assert nm.calls[-1]['action'] == 'RESTORE_L3'
    assert result['worker_ready'] is True


def test_third_unresolved_branch_is_not_created(api, tmp_path):
    nm = FakeNM(api, snapshot(api, 'HOME'))
    nm.defer, nm.fail = True, True
    state = store(api, tmp_path)
    wake(api, nm, state)
    nm.current['owner'] = snapshot(api)['owner']
    wake(api, nm, state)  # Unknown FENCE_CURRENT with original predecessor.
    count = len(nm.calls)
    nm.current['owner'] = snapshot(api, 'HOME')['owner']
    output = wake(api, nm, state)
    assert len(nm.calls) == count
    assert output['worker_ready'] is False


def test_native_l3_projection_rejects_stale_dns_routes_rules_and_async_stage3(api):
    saved = settings()
    v4 = {'AddressData': [{'address': '192.0.2.10', 'prefix': 24}],
          'RouteData': [{'dest': '0.0.0.0', 'prefix': 0, 'next-hop': '192.0.2.1',
                         'metric': 600, 'table': 254}],
          'NameserverData': [{'address': '192.0.2.53'}], 'Domains': ['example.test']}
    v6 = {'AddressData': [{'address': '2001:db8::10', 'prefix': 64}], 'RouteData': [],
          'Nameservers': [list(bytes.fromhex('20010db8000000000000000000000053'))],
          'Domains': ['example.test']}
    kernel = {'own_addresses': [{'family': 'inet', 'local': '192.0.2.10', 'prefixlen': 24},
                                {'family': 'inet6', 'local': '2001:db8::10', 'prefixlen': 64}],
              'own_routes': [{'family': 4, 'dst': 'default', 'gateway': '192.0.2.1',
                              'metric': 600, 'table': 'main'}],
              'own_rules': []}
    dns = [{'interface': 'br-example', 'nameservers': ['192.0.2.53', '2001:db8::53'],
            'domains': ['example.test']}]
    assert api.native_l3_settled(100, saved, saved, v4, v6, kernel, dns)
    bad = deepcopy(dns)
    bad[0]['domains'] = ['old.test']
    assert not api.native_l3_settled(100, saved, saved, v4, v6, kernel, bad)
    bad_kernel = deepcopy(kernel)
    bad_kernel['own_routes'][0]['table'] = 100
    assert not api.native_l3_settled(100, saved, saved, v4, v6, bad_kernel, dns)
    bad_kernel = deepcopy(kernel)
    bad_kernel['own_rules'] = [{'iif': 'br-example', 'table': 100}]
    assert not api.native_l3_settled(100, saved, saved, v4, v6, bad_kernel, dns)
    assert not api.native_l3_settled(100, saved, saved, {}, {}, kernel, dns)


def test_atomic_failure_before_replace_keeps_original_intent(api, tmp_path, monkeypatch):
    state = store(api, tmp_path)
    state.initialize()
    original = {'schema': api.SCHEMA, 'op': {'id': 'first'}}
    state.write(original)
    real_replace = api.os.replace
    def fail_replace(source, destination):
        raise OSError('synthetic power loss before atomic replace')
    monkeypatch.setattr(api.os, 'replace', fail_replace)
    with pytest.raises(OSError):
        state.write({'schema': api.SCHEMA, 'op': {'id': 'second'}})
    monkeypatch.setattr(api.os, 'replace', real_replace)
    assert state.read() == original
    assert not list(state.state_path.parent.glob('.*'))


def test_disabled_payload_survives_actual_libnm_serialization(api):
    from gi.repository import NM, GLib
    text = '''[connection]\nid=synthetic\nuuid=11111111-1111-4111-8111-111111111111\ntype=bridge\ninterface-name=br-example\n[bridge]\nstp=false\n[ipv4]\nmethod=auto\n[ipv6]\nmethod=auto\n'''
    keyfile = GLib.KeyFile()
    keyfile.load_from_data(text, len(text), GLib.KeyFileFlags.NONE)
    connection = NM.keyfile_read(keyfile, '/', NM.KeyfileHandlerFlags.NONE)
    connection.normalize()  # Activated native connections have mandatory settings.
    initial = api.from_variant(connection.to_dbus(NM.ConnectionSerializationFlags.NO_SECRETS))
    desired = api.payload(initial, initial, 'SUSPEND_L3', 'roundtrip-operation')
    normalized = NM.SimpleConnection.new_from_dbus(api.to_variant(desired))
    assert normalized.verify()
    assert api.from_variant(normalized.to_dbus(NM.ConnectionSerializationFlags.NO_SECRETS)) == desired


def test_native_rpc_targets_pinned_unique_owner_and_accepts_void(api):
    from gi.repository import Gio, GLib
    calls = []
    class FakeBus:
        def call_sync(self, *args):
            calls.append(args)
            return GLib.Variant('()', ())
    native = api.NativeNM.__new__(api.NativeNM)
    native.bus, native.unique, native.Gio, native.GLib = FakeBus(), ':1.5', Gio, GLib
    initial = snapshot(api, 'HOME')
    op = api._intent(initial, 'SUSPEND_L3', 'typed-operation', 'wake')
    assert native.reapply(op) is None
    assert calls[0][:4] == (':1.5', '/devices/bridge',
                            'org.freedesktop.NetworkManager.Device', 'Reapply')
    assert calls[0][4].get_type_string() == '(a{sa{sv}}tu)'
    op['context']['epoch'][2] = ':1.99'
    with pytest.raises(api.Refused):
        native.reapply(op)
    assert len(calls) == 1


def test_unattributed_extra_bridge_route_is_not_ready(api):
    saved = settings()
    saved['ipv6']['method'] = ['s', "'disabled'"]
    v4 = {'AddressData': [{'address': '192.0.2.10', 'prefix': 24}], 'RouteData': [],
          'NameserverData': [], 'Domains': []}
    projected = {'own_addresses': [{'family': 'inet', 'local': '192.0.2.10', 'prefixlen': 24}],
                 'own_routes': [], 'own_rules': []}
    assert api.native_l3_settled(100, saved, saved, v4, {}, projected, [])
    projected['own_routes'].append({'family': 4, 'dst': '198.51.100.0/24',
                                    'gateway': '192.0.2.99', 'metric': 1, 'protocol': 'static'})
    assert not api.native_l3_settled(100, saved, saved, v4, {}, projected, [])


def test_owner_change_after_wal_before_rpc_cancels_stale_action(api, tmp_path):
    nm = FakeNM(api, snapshot(api, 'HOME'))
    state = store(api, tmp_path)
    def changed(fake):
        if fake.reads == 2:
            fake.current['owner'] = snapshot(api)['owner']
    nm.before_read = changed
    output = wake(api, nm, state)
    assert output['state'] == 'PENDING'
    assert not nm.calls
    assert state.read()['op'] is None  # Prepared but never sent is not restore authority.


def test_native_snapshot_unsupported_api_is_closed(api):
    native = api.NativeNM.__new__(api.NativeNM)
    def unsupported():
        raise KeyError('unqualified native property')
    native._snapshot = unsupported
    assert native.snapshot() == {'valid': False, 'exists': False,
                                 'reason': "KeyError: 'unqualified native property'"}


def test_fence_preserves_only_already_proven_own_suspension(api, tmp_path):
    nm = FakeNM(api, snapshot(api, 'HOME'))
    state = store(api, tmp_path)
    wake(api, nm, state)  # Own disable accepted at42.
    nm.current['owner'] = snapshot(api)['owner']
    nm.defer, nm.fail = True, True
    wake(api, nm, state)  # Restore may still arrive; current applied still own disable.
    nm.current['owner'] = snapshot(api, 'HOME')['owner']
    nm.defer, nm.fail = False, False
    wake(api, nm, state)  # Fence the unresolved restore, preserve proven suspension origin.
    assert nm.calls[-1]['action'] == 'FENCE_CURRENT'
    nm.current['owner'] = snapshot(api)['owner']
    output = wake(api, nm, state)
    assert nm.calls[-1]['action'] == 'RESTORE_L3'
    assert output['worker_ready'] is True


def test_known_own_rpc_invariant_failure_stays_closed_across_wakes_and_status(api, tmp_path):
    nm = FakeNM(api, snapshot(api, 'HOME'))
    state = store(api, tmp_path)
    def damage(fake):
        fake.current['protected']['l2']['mtu'] = 9000
    nm.after_call = damage
    assert wake(api, nm, state)['state'] == 'REFUSED'
    nm.current['owner'] = snapshot(api)['owner']
    nm.current['settlement'] = {'suspended': False, 'restored': True}
    nm.after_call = None
    calls = len(nm.calls)
    assert wake(api, nm, state)['state'] == 'REFUSED'
    assert wake(api, nm, state)['worker_ready'] is False
    assert len(nm.calls) == calls
    before = {p: p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    assert api.status(nm, state)['worker_ready'] is False
    assert before == {p: p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    # Merely undoing the MTU symptom does not erase the known failed own operation.
    nm.current['protected']['l2']['mtu'] = 1500
    assert wake(api, nm, state)['worker_ready'] is False
    assert len(nm.calls) == calls


def test_second_rpc_invariant_failure_is_not_lost_at_wake_budget_boundary(api, tmp_path):
    nm = FakeNM(api, snapshot(api, 'HOME'))
    state = store(api, tmp_path)
    wake(api, nm, state)
    nm.current['owner'] = snapshot(api)['owner']
    def owner_then_damage(fake):
        if fake.calls[-1]['action'] == 'RESTORE_L3':
            fake.current['owner'] = snapshot(api, 'HOME')['owner']
        else:
            fake.current['protected']['l2']['mtu'] = 9000
    nm.after_call = owner_then_damage
    assert wake(api, nm, state)['state'] == 'REFUSED'
    nm.current['owner'] = snapshot(api)['owner']
    nm.after_call = None
    count = len(nm.calls)
    assert wake(api, nm, state)['worker_ready'] is False
    assert len(nm.calls) == count


def projected_ipv6(api, attributes):
    saved = settings()
    saved['ipv4']['method'] = ['s', "'disabled'"]
    address = {'family': 'inet6', 'local': '2001:db8::7', 'prefixlen': 64,
               'scope': 'global', 'valid_life_time': 100, 'preferred_life_time': 50}
    address.update(attributes)
    native = {'links': [{'ifindex': 21, 'ifname': 'br-example', 'mtu': 1500}],
              'addresses': [{'ifname': 'br-example', 'addr_info': [address]}],
              'routes4': [], 'routes6': [], 'rules4': [], 'rules6': []}
    projection = api.project_kernel(native, 'br-example')
    nm6 = {'AddressData': [{'address': '2001:db8::7', 'prefix': 64}],
           'RouteData': [], 'Nameservers': [], 'Domains': []}
    return api.native_l3_settled(100, saved, saved, {}, nm6, projection, []), projection


@pytest.mark.parametrize('attributes', [
    {'tentative': True}, {'dadfailed': True}, {'optimistic': True}, {'deprecated': True},
    {'flags': ['tentative']}, {'flags': ['dadfailed']}, {'flags': ['future-unqualified-state']},
    {'flags': 'unsupported-shape'}, {'valid_life_time': 0}, {'preferred_life_time': 0},
])
def test_projected_unusable_address_never_settles(api, attributes):
    ready, _ = projected_ipv6(api, attributes)
    assert ready is False


def test_clean_ipv6_and_lifetime_countdown_normalization_remain_supported(api):
    ready, projection = projected_ipv6(api, {'flags': ['dynamic', 'mngtmpaddr']})
    assert ready is True
    later, later_projection = projected_ipv6(api, {'flags': ['dynamic', 'mngtmpaddr'],
                                                 'valid_life_time': 99,
                                                 'preferred_life_time': 49})
    assert later is True
    assert projection == later_projection


def test_unknown_native_address_state_requires_qualification(api):
    ready, _ = projected_ipv6(api, {'future_unusable_state': True})
    assert ready is False
