"""One-shot, owned NetworkManager bridge L3 guard; no activation or saved-profile writes.

The policy/marker engine accepts an injected adapter. Gio is loaded lazily: importing
this module, typed offline serialization, and fake tests never connect to a bus.
Native installation/qualification is a separate operator transaction.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path

SCHEMA = 'qcl.nm-bridge.v1'
TOKEN_KEY = 'org.qcl-negf.bridge-guard.operation'
EVENTS = {'up', 'down', 'reapply', 'dhcp4-change', 'dhcp6-change'}
MAX_BYTES = 1024 * 1024


class Refused(RuntimeError):
    """An observation or protected file cannot support this action."""


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True).encode()).hexdigest()


def profile_hash(settings):
    result = deepcopy(settings)
    result.get('connection', {}).pop('timestamp', None)
    return digest(result)


def glib():
    import gi
    gi.require_version('NM', '1.0')
    from gi.repository import GLib
    return GLib


def from_variant(value):
    """Lossless property signatures/text, including nested variant dictionaries."""
    result = {}
    for i in range(value.n_children()):
        entry = value.get_child_value(i)
        section, properties = entry.get_child_value(0).unpack(), entry.get_child_value(1)
        result[section] = {}
        for j in range(properties.n_children()):
            prop = properties.get_child_value(j)
            name = prop.get_child_value(0).unpack()
            leaf = prop.get_child_value(1).get_variant()
            result[section][name] = [leaf.get_type_string(), leaf.print_(True)]
    return dict(sorted((k, dict(sorted(v.items()))) for k, v in result.items()))


def to_variant(settings):
    GLib = glib()
    try:
        return GLib.Variant('a{sa{sv}}', {
            section: {key: GLib.Variant.parse(GLib.VariantType.new(kind), text, None, None)
                      for key, (kind, text) in sorted(properties.items())}
            for section, properties in sorted(settings.items())})
    except Exception as exc:
        raise Refused('invalid typed settings') from exc


def user_data(settings):
    value = settings.get('user', {}).get('data')
    if value is None:
        return {}
    if value[0] != 'a{ss}':
        raise Refused('user.data has unexpected signature')
    GLib = glib()
    return GLib.Variant.parse(GLib.VariantType.new('a{ss}'), value[1], None, None).unpack()


def payload(applied, saved, action, nonce):
    result = deepcopy(applied)
    if action == 'SUSPEND_L3':
        for family in ('ipv4', 'ipv6'):
            result[family] = {'method': ['s', "'disabled'"],
                              'address-data': ['aa{sv}', '@aa{sv} []'],
                              'route-data': ['aa{sv}', '@aa{sv} []']}
    elif action == 'RESTORE_L3':
        for family in ('ipv4', 'ipv6'):
            if family in saved:
                result[family] = deepcopy(saved[family])
            else:
                result.pop(family, None)
    elif action != 'FENCE_CURRENT':
        raise Refused('unknown action')
    data = user_data(applied)
    data[TOKEN_KEY] = nonce
    result.setdefault('user', {})['data'] = [
        'a{ss}', glib().Variant('a{ss}', dict(sorted(data.items()))).print_(True)]
    # Canonical representation used both in WAL and returned by GetAppliedConnection.
    return from_variant(to_variant(result))


def reapply_arguments(settings, version):
    if not isinstance(version, int) or isinstance(version, bool) or version <= 0:
        raise Refused('Reapply requires a nonzero applied CAS version')
    GLib = glib()
    return GLib.Variant.new_tuple(to_variant(settings), GLib.Variant('t', version),
                                 GLib.Variant('u', 1))  # preserve-external-ip


def methods(settings):
    return tuple(settings.get(f, {}).get('method', ['s', "'disabled'"])[1]
                 for f in ('ipv4', 'ipv6'))


def disabled(settings):
    return methods(settings) == ("'disabled'", "'disabled'")


def ip_matches(applied, saved):
    return all(applied.get(f) == saved.get(f) for f in ('ipv4', 'ipv6'))


def physical_port(snapshot):
    owner = snapshot['owner']
    return (owner['kind'] == 'PORT' and owner['carrier'] is True
            and owner['attached'] is True and owner['state'] == 100)


def context(snapshot):
    return {k: deepcopy(snapshot[k]) for k in
            ('epoch', 'source', 'policy', 'nm_version', 'identity', 'profile_hash')}


def fence(snapshot):
    return {'context': context(snapshot), 'owner': snapshot['owner'],
            'version': snapshot['version'], 'applied_hash': digest(snapshot['applied']),
            'protected': snapshot['protected']}


def accepted(op, snapshot):
    return (op and context(snapshot) == op['context']
            and snapshot['version'] == op['before_version'] + 1
            and snapshot['token'] == op['nonce']
            and digest(snapshot['applied']) == op['payload_hash'])


def authority(op, snapshot):
    return bool(accepted(op, snapshot) and op['suspension_origin'] and disabled(snapshot['applied']))


def decide(snapshot, op=None):
    """Pure current-state goal; no filesystem, timer, activation or NM calls."""
    if not snapshot.get('valid'):
        return 'REFUSE', snapshot.get('reason', 'unsupported observation')
    if not snapshot.get('exists'):
        return 'NOOP_ABSENT', 'owned MASTER is absent'
    if snapshot['version'] <= 0:
        return 'REFUSE', 'zero applied version'
    if not physical_port(snapshot):
        if disabled(snapshot['applied']):
            return 'NOOP', 'L3 already disabled; no restore authority implied'
        return 'SUSPEND_L3', 'physical PORT is not the current attached carrier owner'
    if ip_matches(snapshot['applied'], snapshot['saved']):
        if disabled(snapshot['saved']):
            return 'REFUSE', 'saved profile intentionally disabled'
        return 'NOOP', 'native saved L3 already applied'
    if disabled(snapshot['applied']) and authority(op, snapshot):
        return 'RESTORE_L3', 'matching own suspension and current physical PORT'
    return 'REFUSE', 'runtime differs from saved profile without own suspension authority'


class Store:
    """Fixed WAL + coalesced wake marker, private root-owned in native use."""
    def __init__(self, state_path, pending_path, lock_path, *, owner_uid=0, ancestor_uids=(0,)):
        self.state_path, self.pending_path, self.lock_path = map(
            Path, (state_path, pending_path, lock_path))
        self.owner_uid = owner_uid
        self.ancestor_uids = (*ancestor_uids, owner_uid)

    def _ancestors(self, path):
        for parent in (path, *path.parents):
            if parent.is_symlink():
                raise Refused('symlink in protected path')
            if parent.exists() and parent.stat().st_uid not in self.ancestor_uids:
                raise Refused('unowned protected path')
            # /tmp is permitted only as a sticky ancestor of private unit fixtures.
            if (parent.exists() and parent.stat().st_mode & 0o022
                    and not (parent.stat().st_mode & stat.S_ISVTX and parent != path)):
                raise Refused('writable protected ancestor')

    def initialize(self):
        for path in (self.state_path.parent, self.pending_path.parent):
            self._ancestors(path)
            path.mkdir(parents=True, mode=0o700, exist_ok=True)
            self._ancestors(path)
            if path.stat().st_uid != self.owner_uid or stat.S_IMODE(path.stat().st_mode) != 0o700:
                raise Refused('private directory must have owner mode 0700')
        self._ancestors(self.lock_path.parent)

    def _read(self, path):
        self._ancestors(path.parent)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise Refused('cannot read protected file') from exc
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner_uid
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise Refused('unsafe protected file')
            raw = stream.read(MAX_BYTES + 1)
        try:
            value = json.loads(raw)
            if len(raw) > MAX_BYTES or not isinstance(value, dict) or value.get('schema') != SCHEMA:
                raise ValueError('schema/size')
            return value
        except (ValueError, UnicodeError) as exc:
            raise Refused('malformed private state') from exc

    def read(self):
        return self._read(self.state_path) or {'schema': SCHEMA, 'op': None, 'processed': None}

    def pending(self):
        return self._read(self.pending_path)

    def _write(self, path, value):
        self._read(path)  # Never replace a symlink, unowned, malformed or unsafe existing object.
        self._ancestors(path.parent)
        temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
        raw = json.dumps(value, sort_keys=True).encode()
        if len(raw) > MAX_BYTES:
            raise Refused('private marker too large')
        try:
            fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)

    def write(self, value):
        self._write(self.state_path, value)

    def notify(self):
        nonce = str(uuid.uuid4())
        self._write(self.pending_path, {'schema': SCHEMA, 'nonce': nonce})
        return nonce

    @contextmanager
    def lock(self, timeout=1.0):
        self._ancestors(self.lock_path.parent)
        try:
            fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        except OSError as exc:
            raise Refused('unsafe lock') from exc
        try:
            info = os.fstat(fd)
            if (info.st_uid != self.owner_uid or stat.S_IMODE(info.st_mode) != 0o600
                    or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                raise Refused('unsafe lock owner/mode/type')
            deadline = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError('owner busy; notification retained')
                    time.sleep(min(0.02, max(0, deadline - time.monotonic())))
            yield
        finally:
            os.close(fd)


def result(state, ready=False, reason=''):
    return {'state': state, 'worker_ready': bool(ready), 'reason': reason}


def observe(snapshot, op, processed, pending, observed_protected=None):
    if not snapshot.get('valid'):
        return result('REFUSED', reason=snapshot.get('reason', 'unsupported observation'))
    if not snapshot.get('exists'):
        return result('NOOP_ABSENT')
    if not pending or pending.get('nonce') != processed:
        return result('PENDING_HANDOFF', reason='unprocessed dirty generation')
    if op:
        if context(snapshot) != op['context']:
            return result('REVOKED', reason='epoch/source/profile/binding changed')
        if not accepted(op, snapshot):
            return result('PENDING' if snapshot['version'] == op['before_version'] else 'REVOKED',
                          reason='own accepted token/exact version/payload not proved')
        if snapshot['protected'] != (observed_protected if observed_protected is not None else op['protected']):
            return result('REFUSED', reason='L2 or foreign contribution changed')
    if not physical_port(snapshot):
        if disabled(snapshot['applied']) and snapshot['settlement']['suspended']:
            return result('SUSPENDED_SETTLED')
        return result('APPLIED_OBSERVED' if op and accepted(op, snapshot) else 'PENDING')
    if ip_matches(snapshot['applied'], snapshot['saved']) and not disabled(snapshot['saved']):
        if snapshot['settlement']['restored']:
            return result('RESTORED_SETTLED', True)
        return result('APPLIED_OBSERVED')
    return result('REFUSED', reason='no current native L3 or proven own suspension')


def status(adapter, store):
    """Strictly RO. Capture generation BEFORE snapshot, then verify it did not change."""
    pending_before = store.pending()
    state = store.read()
    if state.get('invariant_failure'):
        return result('REFUSED', reason='known own-operation invariant failure; explicit owner rebind required')
    snapshot = adapter.snapshot()
    pending_after = store.pending()
    if pending_before != pending_after:
        return result('PENDING_HANDOFF', reason='dirty generation changed during observation')
    return observe(snapshot, state.get('op'), state.get('processed'), pending_after,
                   state.get('observed_protected'))


def _intent(snapshot, action, nonce, wake, predecessor=None, origin=False):
    desired = payload(snapshot['applied'], snapshot['saved'], action, nonce)
    return {'schema': SCHEMA, 'id': str(uuid.uuid4()), 'action': action, 'state': 'PREPARED',
            'wake': wake, 'nonce': nonce, 'context': context(snapshot),
            'owner': deepcopy(snapshot['owner']), 'before_version': snapshot['version'],
            'before_hash': digest(snapshot['applied']), 'before_applied': snapshot['applied'],
            'payload': desired, 'payload_hash': digest(desired),
            'protected': snapshot['protected'],
            'suspension_origin': action == 'SUSPEND_L3' or origin,
            'predecessor': predecessor}


def reconcile(adapter, store, wake, *, lock_timeout=1.0):
    """One wake, <=2 CAS calls. Uncertain operations survive cancellation in the WAL."""
    try:
        with store.lock(lock_timeout):
            # Producer supplied wake is a hint. Capture latest generation BEFORE readback.
            pending = store.pending()
            generation = pending['nonce'] if pending else wake
            state = store.read()
            if state.get('invariant_failure'):
                return result('REFUSED', reason='known own-operation invariant failure; explicit owner rebind required')
            snapshot = adapter.snapshot()
            op = state.get('op')
            baseline = snapshot.get('protected')
            for _ in range(2):
                if not snapshot.get('valid') or not snapshot.get('exists'):
                    break
                if op and context(snapshot) != op['context']:
                    state.update(processed=generation)
                    store.write(state)
                    return result('REVOKED', reason='old epoch/source/profile/binding authority')
                own = accepted(op, snapshot)
                action, _reason = decide(snapshot, op)
                pending_old = bool(op and not own and snapshot['version'] == op['before_version']
                                   and digest(snapshot['applied']) == op['before_hash'])
                if op and not own and not pending_old:
                    state.update(processed=generation)
                    store.write(state)
                    return result('REVOKED', reason='external applied version/hash/token change')
                if pending_old:
                    if action == op['action'] and snapshot['owner'] == op['owner']:
                        # One same-payload/original-version duplicate per wake. The second
                        # iteration below only observes; never loops retries to PASS.
                        next_op = deepcopy(op)
                        if next_op.get('resubmitted_wake') == generation:
                            break
                        next_op['resubmitted_wake'] = generation
                    elif action in ('NOOP', 'SUSPEND_L3'):
                        if op.get('predecessor'):
                            break  # Two unresolved branches already exist; next authoritative wake.
                        # Original old CAS can still land. Bump using a FRESH user token.
                        # No inherited suspension authority from an unaccepted intent.
                        next_op = _intent(snapshot, 'FENCE_CURRENT' if action == 'NOOP' else action,
                                          str(uuid.uuid4()), generation,
                                          predecessor={k: op[k] for k in
                                                       ('id', 'before_version', 'nonce')},
                                          origin=bool(op['suspension_origin']
                                                      and disabled(op['before_applied'])))
                    else:
                        break
                elif action in ('NOOP', 'NOOP_ABSENT', 'REFUSE'):
                    break
                else:
                    next_op = _intent(snapshot, action, str(uuid.uuid4()), generation,
                                      origin=authority(op, snapshot))
                # Durable PREPARED before RPC. Read again immediately before RPC;
                # MASTER CAS never substitutes for the independent physical-owner fence.
                state['op'] = next_op
                store.write(state)
                current = adapter.snapshot()
                if not current.get('exists') or not current.get('valid') or fence(current) != fence(snapshot):
                    # This particular prepared call was not dispatched. Retain the older
                    # unresolved call, if any; do not invent authority from the new marker.
                    state['op'] = op
                    state['processed'] = generation
                    store.write(state)
                    return result('PENDING', reason='pre-call current-state fence changed')
                op = next_op
                baseline = op['protected']
                try:
                    adapter.reapply(op)
                except Exception:  # noqa: BLE001 - an arbitrary transport failure has unknown delivery
                    op['state'] = 'UNKNOWN'
                    state['op'] = op
                    store.write(state)
                # KeyboardInterrupt/SystemExit/SIGKILL intentionally leave PREPARED.
                snapshot = adapter.snapshot()
                if (snapshot.get('valid') and snapshot.get('exists')
                        and snapshot['protected'] != op['protected']):
                    # Persist an already observed failure, including after call2. A later
                    # wake must not silently adopt this failed operation's new baseline.
                    state.update(op=op, processed=generation, invariant_failure={
                        'op_id': op['id'], 'context': op['context'],
                        'expected_hash': digest(op['protected']),
                        'observed_hash': digest(snapshot['protected'])})
                    store.write(state)
                    return result('REFUSED', reason='L2 or foreign contribution changed; explicit owner rebind required')
                if snapshot.get('valid') and snapshot.get('exists') and accepted(op, snapshot):
                    op['state'] = 'APPLIED_OBSERVED'
                    state['op'] = op
                    store.write(state)
            state.update(op=op, processed=generation, observed_protected=baseline)
            store.write(state)
            return observe(snapshot, op, generation, store.pending(), baseline)
    except TimeoutError:
        return result('PENDING_HANDOFF', reason='owner busy; next event/explicit pickup required')


# Native D-Bus adapter: explicit unique destination, no NM.Client, no saved changes.
NM_PATH = '/org/freedesktop/NetworkManager'
NM_IFACE = 'org.freedesktop.NetworkManager'
DEVICE = NM_IFACE + '.Device'


class NativeNM:
    def __init__(self, binding):
        import gi
        gi.require_version('NM', '1.0')
        from gi.repository import Gio, GLib
        self.Gio, self.GLib, self.binding = Gio, GLib, binding
        self.deadline = time.monotonic() + 20
        self.bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        self.unique = self._bus_call('GetNameOwner', '(s)', (NM_IFACE,)).unpack()[0]
        self.bus_id = self._bus_call('GetId', None, None).unpack()[0]
        self.source = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        if self.source != binding['source_sha256']:
            raise Refused('source digest differs from reviewed binding')
        self.policy = digest(binding)

    def timeout_ms(self):
        remaining = getattr(self, 'deadline', time.monotonic() + 3) - time.monotonic()
        if remaining <= 0:
            raise Refused('native one-shot deadline exhausted')
        return max(1, min(3000, int(remaining * 1000)))

    def _bus_call(self, method, signature, args):
        return self.bus.call_sync('org.freedesktop.DBus', '/org/freedesktop/DBus',
                                  'org.freedesktop.DBus', method,
                                  self.GLib.Variant(signature, args) if signature else None,
                                  None, self.Gio.DBusCallFlags.NONE, self.timeout_ms(), None)

    def call(self, path, interface, method, args=None):
        return self.bus.call_sync(self.unique, path, interface, method, args, None,
                                  self.Gio.DBusCallFlags.NONE, self.timeout_ms(), None)

    def properties(self, path, interface):
        return self.call(path, 'org.freedesktop.DBus.Properties', 'GetAll',
                         self.GLib.Variant('(s)', (interface,))).unpack()[0]

    def _settings(self, path):
        return from_variant(self.call(path, NM_IFACE + '.Settings.Connection',
                                      'GetSettings').get_child_value(0))

    def _ip(self, path, family):
        return {} if path == '/' else self.properties(path, NM_IFACE + f'.IP{family}Config')

    def snapshot(self):
        try:
            return self._snapshot()
        except Exception as exc:  # noqa: BLE001 - malformed/unsupported observation must close
            # Unsupported/malformed/transient native observation is always closed.
            return {'valid': False, 'exists': False, 'reason': type(exc).__name__ + ': ' + str(exc)}

    def _snapshot(self):
        b = self.binding
        if self._bus_call('GetNameOwner', '(s)', (NM_IFACE,)).unpack()[0] != self.unique:
            raise Refused('NM unique owner changed')
        if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != b['source_sha256']:
            raise Refused('source changed')
        # Re-read private binding every snapshot; external edits revoke the old instance.
        if read_binding(b['_path']) != b:
            raise Refused('root binding changed')
        manager = self.properties(NM_PATH, NM_IFACE)
        if manager['Version'] != b['nm_version'] or not b['nm_version'].startswith('1.58.'):
            raise Refused('unqualified NM version')
        devices = {}
        for path in self.call(NM_PATH, NM_IFACE, 'GetDevices').unpack()[0]:
            devices[path] = self.properties(path, DEVICE)
        bridges = [(p, d) for p, d in devices.items() if d['Interface'] == b['bridge_name']]
        if not bridges:
            return {'valid': True, 'exists': False}
        if len(bridges) != 1 or bridges[0][1]['DeviceType'] != 13:
            raise Refused('bridge identity/type ambiguous')
        path, bridge = bridges[0]
        active = self.properties(bridge['ActiveConnection'], NM_IFACE + '.Connection.Active')
        if active['Uuid'] != b['bridge_uuid']:
            raise Refused('bridge is not the owned active profile')
        profile_path = self.call(NM_PATH + '/Settings', NM_IFACE + '.Settings',
                                 'GetConnectionByUuid', self.GLib.Variant('(s)',
                                 (b['bridge_uuid'],))).unpack()[0]
        if active['Connection'] != profile_path:
            raise Refused('active/saved profile object identity differs')
        saved = self._settings(profile_path)
        if profile_hash(saved) != b['profile_sha256']:
            raise Refused('saved MASTER profile changed; explicit rebind required')
        port_path = self.call(NM_PATH + '/Settings', NM_IFACE + '.Settings',
                              'GetConnectionByUuid', self.GLib.Variant('(s)',
                              (b['port_uuid'],))).unpack()[0]
        if profile_hash(self._settings(port_path)) != b['port_profile_sha256']:
            raise Refused('saved PORT profile changed')
        applied_reply = self.call(path, DEVICE, 'GetAppliedConnection',
                                  self.GLib.Variant('(u)', (0,)))
        applied = from_variant(applied_reply.get_child_value(0))
        version = applied_reply.get_child_value(1).unpack()
        kernel = kernel_snapshot(self.deadline)
        links = {d['ifname']: d for d in kernel['links']}
        if b['bridge_name'] not in links:
            raise Refused('bridge disappeared from kernel')
        owner = self.physical_owner()
        ip4, ip6 = self._ip(bridge['Ip4Config'], 4), self._ip(bridge['Ip6Config'], 6)
        dns = self.properties(NM_PATH + '/DnsManager', NM_IFACE + '.DnsManager')['Configuration']
        own_dns = [x for x in dns if x.get('interface') == b['bridge_name']]
        foreign_dns = [x for x in dns if x.get('interface') != b['bridge_name']]
        foreign_nm = {p: {'ip4': self._ip(d['Ip4Config'], 4),
                          'ip6': self._ip(d['Ip6Config'], 6),
                          'active': d['ActiveConnection']}
                      for p, d in devices.items() if p != path}
        projection = project_kernel(kernel, b['bridge_name'])
        suspended = (not projection['own_addresses'] and not projection['own_routes']
                     and not projection['own_rules'] and not own_dns and not ip4 and not ip6)
        restored = native_l3_settled(bridge['State'], applied, saved, ip4, ip6,
                                     projection, own_dns)
        final_applied = self.call(path, DEVICE, 'GetAppliedConnection',
                                  self.GLib.Variant('(u)', (0,)))
        if (self.physical_owner() != owner
                or final_applied.get_child_value(1).unpack() != version
                or from_variant(final_applied.get_child_value(0)) != applied
                or profile_hash(self._settings(profile_path)) != profile_hash(saved)
                or profile_hash(self._settings(port_path)) != b['port_profile_sha256']
                or read_binding(b['_path']) != b
                or self.properties(path, DEVICE)['ActiveConnection'] != bridge['ActiveConnection']
                or self._bus_call('GetNameOwner', '(s)', (NM_IFACE,)).unpack()[0] != self.unique):
            raise Refused('native state changed during readback')
        return {'valid': True, 'exists': True,
                'epoch': [Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                          self.bus_id, self.unique], 'source': self.source,
                'policy': self.policy, 'nm_version': manager['Version'],
                'identity': {'bridge_path': path, 'bridge_ifindex': links[b['bridge_name']]['ifindex'],
                             'profile_path': profile_path, 'bridge_uuid': b['bridge_uuid'],
                             'port_uuid': b['port_uuid'], 'permanent_mac': b['permanent_mac']},
                'owner': owner, 'saved': saved, 'profile_hash': profile_hash(saved),
                'applied': applied, 'version': version,
                'token': user_data(applied).get(TOKEN_KEY),
                'settlement': {'suspended': suspended, 'restored': restored},
                'protected': {'l2': projection['l2'], 'foreign': {
                    'kernel': projection['foreign'], 'dns': foreign_dns, 'nm': foreign_nm}}}

    def physical_owner(self):
        matches = []
        for path in self.call(NM_PATH, NM_IFACE, 'GetDevices').unpack()[0]:
            device = self.properties(path, DEVICE)
            if device['DeviceType'] == 1:
                wired = self.properties(path, DEVICE + '.Wired')
                if wired['PermHwAddress'].lower() == self.binding['permanent_mac']:
                    matches.append((device, wired))
        if len(matches) > 1:
            raise Refused('permanent MAC is not unique')
        if not matches:
            return {'kind': 'ABSENT', 'ifindex': None, 'active_uuid': None,
                    'active_path': '/', 'state': 0, 'attached': False, 'carrier': False}
        device, wired = matches[0]
        name = device['Interface']
        if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', name):
            raise Refused('unsafe physical interface name')
        sysfs = Path('/sys/class/net') / name
        active_path = device['ActiveConnection']
        active = {} if active_path == '/' else self.properties(
            active_path, NM_IFACE + '.Connection.Active')
        master = sysfs / 'master'
        return {'kind': 'PORT' if active.get('Uuid') == self.binding['port_uuid'] else 'OTHER',
                'ifindex': int((sysfs / 'ifindex').read_text()), 'active_uuid': active.get('Uuid'),
                'active_path': active_path, 'state': device['State'],
                'attached': master.is_symlink() and master.resolve().name == self.binding['bridge_name'],
                'carrier': bool(wired['Carrier']) and physical_carrier(name)}

    def relevant(self, interface):
        if interface == self.binding['bridge_name']:
            return True
        if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', interface):
            return False
        for path in self.call(NM_PATH, NM_IFACE, 'GetDevices').unpack()[0]:
            device = self.properties(path, DEVICE)
            if device['Interface'] == interface and device['DeviceType'] == 1:
                return self.properties(path, DEVICE + '.Wired')['PermHwAddress'].lower() == self.binding['permanent_mac']
        return False

    def reapply(self, op):
        if op['context']['epoch'][2] != self.unique:
            raise Refused('RPC destination does not match intent unique owner')
        # Empty reply is a valid void. No decoding or status inferred here.
        self.call(op['context']['identity']['bridge_path'], DEVICE, 'Reapply',
                  reapply_arguments(op['payload'], op['before_version']))


def physical_carrier(interface):
    if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', interface):
        raise Refused('unsafe kernel interface name')
    return (Path('/sys/class/net') / interface / 'carrier').read_text().strip() == '1'


def kernel_snapshot(deadline=None):
    def read(*args):
        remaining = 3 if deadline is None else min(3, deadline - time.monotonic())
        if remaining <= 0:
            raise Refused('kernel observation deadline exhausted')
        completed = subprocess.run(['/usr/bin/ip', '-j', *args], check=True,
                                   capture_output=True, timeout=remaining)
        if len(completed.stdout) > MAX_BYTES:
            raise Refused('kernel observation too large')
        return json.loads(completed.stdout)
    return {'links': read('-d', 'link', 'show'), 'addresses': read('address', 'show'),
            'routes4': read('-4', 'route', 'show', 'table', 'all'),
            'routes6': read('-6', 'route', 'show', 'table', 'all'),
            'rules4': read('-4', 'rule', 'show'), 'rules6': read('-6', 'rule', 'show')}


def project_kernel(kernel, bridge):
    # Preserve topology/configuration; volatile link traffic/carrier counters are not settings.
    l2_keys = ('ifindex', 'ifname', 'mtu', 'address', 'broadcast', 'master', 'linkinfo', 'link_index')
    l2 = [{k: deepcopy(d[k]) for k in l2_keys if k in d} for d in kernel['links']]
    for link in l2:
        data = link.get('linkinfo', {}).get('info_data', {})
        for timer in ('hello_timer', 'tcn_timer', 'topology_change_timer', 'gc_timer'):
            data.pop(timer, None)  # Kernel countdowns are observations, not L2 configuration.
    addresses, foreign_addresses = [], []
    for device in kernel['addresses']:
        for addr in device.get('addr_info', []):
            # Preserve usability state; normalize only countdown values. A zero
            # lifetime is an unusable-state boundary, not an ordinary ticking counter.
            item = {k: deepcopy(v) for k, v in addr.items()
                    if k not in ('valid_life_time', 'preferred_life_time')}
            for lifetime in ('valid_life_time', 'preferred_life_time'):
                if lifetime in addr:
                    value = addr[lifetime]
                    if value == 0:
                        item[lifetime + '_expired'] = True
                    elif value != 'forever' and (not isinstance(value, int)
                                                or isinstance(value, bool) or value < 0):
                        item['unsupported_lifetime_state'] = True
            item['dev'] = device['ifname']
            (addresses if device['ifname'] == bridge else foreign_addresses).append(item)
    own_routes, foreign_routes = [], []
    for family in (4, 6):
        for route in kernel[f'routes{family}']:
            item = {k: v for k, v in route.items() if k not in ('expires', 'cache')}
            item['family'] = family
            (own_routes if route.get('dev') == bridge else foreign_routes).append(item)
    own_rules, foreign_rules = [], {4: [], 6: []}
    for family in (4, 6):
        for rule in kernel[f'rules{family}']:
            own = any(rule.get(k) == bridge for k in ('iif', 'oif', 'iifname', 'oifname'))
            source = rule.get('src', rule.get('from', 'all'))
            if source != 'all':
                ipaddress.ip_network(source, strict=False)  # Reject malformed observations.
                own = True  # Unknown source-policy ownership remains closed after address removal.
            (own_rules if own else foreign_rules[family]).append(rule)
    return {'l2': l2, 'own_addresses': addresses, 'own_routes': own_routes, 'own_rules': own_rules,
            'foreign': {'addresses': foreign_addresses, 'routes': foreign_routes,
                        'rules4': foreign_rules[4], 'rules6': foreign_rules[6]}}


def table_id(value):
    return {'main': 254, 'local': 255, 'default': 253}.get(value, value)


def kernel_address_route(route, addresses):
    """Only the kernel's connected/local/broadcast routes derivable from own addresses."""
    if route.get('protocol') != 'kernel' or route.get('gateway'):
        return False
    family, table = route['family'], table_id(route.get('table', 254))
    destination = route.get('dst')
    if not destination or destination == 'default':
        return False
    target = ipaddress.ip_network(destination, strict=False)
    kind = route.get('type', 'unicast')
    for af, address, prefix in addresses:
        if af != family:
            continue
        network = ipaddress.ip_network(f'{address}/{prefix}', strict=False)
        if (table == 254 and kind == 'unicast' and route.get('scope') == 'link'
                and target == network):
            return True
        if table == 255:
            if kind == 'local' and target == ipaddress.ip_network(address):
                return True
            if (family == 4 and kind == 'broadcast'
                    and target.prefixlen == 32 and target.network_address in
                    (network.network_address, network.broadcast_address)):
                return True
            if family == 6 and destination == 'ff00::/8' and kind in ('multicast', 'unicast'):
                return True
    return False


def address_usable(address):
    """A matching address identity alone does not prove completed DAD/usability."""
    supported_keys = {
        'family', 'local', 'prefixlen', 'scope', 'label', 'broadcast', 'peer', 'dev',
        'metric', 'protocol', 'proto', 'flags', 'secondary', 'temporary', 'dynamic',
        'permanent', 'noprefixroute', 'mngtmpaddr', 'nodad', 'home', 'autojoin',
        'stable-privacy', 'tentative', 'dadfailed', 'optimistic', 'deprecated',
        'valid_life_time_expired', 'preferred_life_time_expired', 'unsupported_lifetime_state'}
    if set(address) - supported_keys or address.get('family') not in ('inet', 'inet6'):
        return False
    for key in ('tentative', 'dadfailed', 'optimistic', 'deprecated',
                'valid_life_time_expired', 'preferred_life_time_expired',
                'unsupported_lifetime_state'):
        if address.get(key, False) is not False:
            return False
    flags = address.get('flags', [])
    safe_flags = {'secondary', 'temporary', 'dynamic', 'permanent', 'noprefixroute',
                  'mngtmpaddr', 'nodad', 'home', 'autojoin', 'stable-privacy'}
    if not isinstance(flags, list) or any(not isinstance(flag, str) or flag not in safe_flags for flag in flags):
        return False  # Unknown address-state flags need a separate qualification.
    return 'state' not in address  # ip addr JSON uses flags; other state schemas are unqualified.


def native_l3_settled(device_state, applied, saved, ip4, ip6, projection, dns):
    """Conservative NM/kernel/per-link DNS projection; never certifies Internet DNS."""
    if (device_state != 100 or not ip_matches(applied, saved) or disabled(saved)
            or projection.get('own_rules')
            or any(not address_usable(a) for a in projection['own_addresses'])):
        return False
    nm_addresses, expected_dns, expected_domains = set(), set(), set()
    expected_routes = set()
    for family, config in ((4, ip4), (6, ip6)):
        method = saved.get(f'ipv{family}', {}).get('method', ['s', "'disabled'"])[1]
        if method == "'disabled'":
            if config:
                return False
            continue
        # Enabled family without native address/config remains pending (including DHCP stage3).
        if not config.get('AddressData'):
            return False
        for address in config['AddressData']:
            nm_addresses.add((family, address['address'], address['prefix']))
        if family == 4:
            expected_dns.update(x['address'] for x in config.get('NameserverData', []))
        else:
            expected_dns.update(str(ipaddress.IPv6Address(bytes(x)))
                                for x in config.get('Nameservers', []))
        expected_domains.update(config.get('Domains', []))
        expected_domains.update(config.get('Searches', []))
        for route in config.get('RouteData', []):
            # Unknown policy route attributes require a separate native qualification.
            if set(route) - {'dest', 'prefix', 'next-hop', 'metric', 'table'}:
                return False
            destination = route['dest'] + '/' + str(route['prefix'])
            if route['prefix'] == 0:
                destination = 'default'
            expected_routes.add((family, destination, route.get('next-hop', ''),
                                 route.get('metric', 0), route.get('table', 254)))
            matches = [r for r in projection['own_routes'] if r.get('type', 'unicast') == 'unicast'
                       and r['family'] == family
                       and r.get('dst') == destination
                       and r.get('gateway', '') == route.get('next-hop', '')
                       and r.get('metric', 0) == route.get('metric', 0)
                       and table_id(r.get('table', 254)) == route.get('table', 254)]
            if not matches:
                return False
    kernel_addresses = {(4 if a['family'] == 'inet' else 6, a['local'], a['prefixlen'])
                        for a in projection['own_addresses']}
    if nm_addresses != kernel_addresses:
        return False  # Extra/unattributed own-link addresses are not assumed safe.
    for route in projection['own_routes']:
        key = (route['family'], route.get('dst'), route.get('gateway', ''),
               route.get('metric', 0), table_id(route.get('table', 254)))
        if route.get('multipath') or route.get('nhid'):
            return False
        if key not in expected_routes and not kernel_address_route(route, nm_addresses):
            return False
    actual_dns = {server for entry in dns for server in entry.get('nameservers', [])}
    actual_domains = {domain for entry in dns for domain in entry.get('domains', [])}
    return expected_dns == actual_dns and expected_domains == actual_domains


def read_binding(path):
    path = Path(path)
    probe = Store(path, path, path)
    value = probe._read(path)
    required = {'schema', 'bridge_name', 'bridge_uuid', 'port_uuid', 'permanent_mac',
                'nm_version', 'source_sha256', 'profile_sha256', 'port_profile_sha256'}
    if value is None or set(value) != required:
        raise Refused('invalid binding keys')
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', value['bridge_name']):
        raise Refused('invalid bridge name')
    for key in ('bridge_uuid', 'port_uuid'):
        if str(uuid.UUID(value[key])) != value[key]:
            raise Refused('noncanonical UUID')
    if value['bridge_uuid'] == value['port_uuid']:
        raise Refused('MASTER and PORT UUID must differ')
    if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', value['permanent_mac']):
        raise Refused('invalid permanent MAC')
    for key in ('source_sha256', 'profile_sha256', 'port_profile_sha256'):
        if not re.fullmatch('[0-9a-f]{64}', value[key]):
            raise Refused('invalid digest')
    value['_path'] = str(path)
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--status', action='store_true')
    mode.add_argument('--reconcile', action='store_true')
    parser.add_argument('--binding', default='/etc/qcl-negf/nm-bridge/binding.json')
    parser.add_argument('--event', choices=sorted(EVENTS))
    parser.add_argument('--interface')
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise Refused('native guard requires root ownership; no sudo invoked')
        binding = read_binding(args.binding)
        adapter = NativeNM(binding)
        store = Store('/var/lib/qcl-negf/nm-bridge/state.json',
                      '/run/qcl-negf/nm-bridge/pending.json', '/run/lock/qcl-negf-nm-bridge.lock')
        if args.status:
            output = status(adapter, store)
        else:
            if bool(args.event) != bool(args.interface):
                raise Refused('dispatcher event and interface must be supplied together')
            if args.event and not adapter.relevant(args.interface):
                output = result('IGNORED', reason='unrelated dispatcher device')
            else:
                store.initialize()
                output = reconcile(adapter, store, store.notify())
        print(json.dumps(output, sort_keys=True))
        return 0 if output['state'] in ('IGNORED', 'NOOP_ABSENT', 'SUSPENDED_SETTLED',
                                         'RESTORED_SETTLED') else 2
    except Exception as exc:  # noqa: BLE001 - CLI boundary emits only a closed result
        print(json.dumps(result('REFUSED', reason=type(exc).__name__ + ': ' + str(exc))))
        return 2


if __name__ == '__main__':
    sys.exit(main())
