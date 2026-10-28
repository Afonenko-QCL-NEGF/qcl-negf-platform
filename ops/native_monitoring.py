"""Native observations, separate from admission. Parsers have literal fixture oracles."""
import copy
import hashlib
import json
import re
import time
import xml.etree.ElementTree as ET


def reason(code, source_id):
    return dict(code=code, source_id=source_id)


def coverage(source_id, observed_at=None, boot=None, generation=None, *, status='not_measured', reasons=()):
    return dict(source_id=source_id, status=status, observed_at=observed_at, host_boot_id=boot,
                generation=generation, complete=False, reasons=list(reasons))


def empty_native(host_id, *, observed_at=None):
    cov = coverage(host_id, observed_at, reasons=[reason('not_sampled', host_id)])
    return dict(schema='qcl.native-status.v2', observed_at=observed_at, host_id=host_id,
        host_boot_id=None, sample_generation=None, host_memory=dict(total_bytes=None, available_bytes=None),
        vms=[], oom=dict(events=[], coverage=coverage(host_id), next_cursor=None), coverage=cov,
        complete=True, next_cursor=None, capabilities=dict(
            kernel_qemu_victim_join=coverage('kernel_qemu_victim_join', status='unsupported', reasons=[reason('lifetime_protocol_unavailable', 'kernel_qemu_victim_join')]),
            systemd_manager_unit_oom=coverage('systemd_manager_unit_oom', status='unsupported', reasons=[reason('unit_protocol_not_measured', 'systemd_manager_unit_oom')])))


def nonnegative(value):
    if type(value) is not int or value < 0:
        raise ValueError('invalid_native_integer')
    return value


def parse_meminfo(raw):
    fields = {}
    for line in raw.splitlines():
        match = re.fullmatch(r'(MemTotal|MemAvailable):\s+(\d+) kB', line)
        if match:
            if match[1] in fields:
                raise ValueError('duplicate_meminfo')
            fields[match[1]] = int(match[2]) * 1024
    if set(fields) != {'MemTotal', 'MemAvailable'} or fields['MemAvailable'] > fields['MemTotal']:
        raise ValueError('incomplete_meminfo')
    return fields['MemTotal'], fields['MemAvailable']


def vm_row(vm_id):
    return dict(vm_id=vm_id, native_generation=None, power_state='unknown', qemu_pid=None,
        qemu_start_ticks=None, qemu_rss_bytes=None, assigned_bytes=None, configured_bytes=None,
        configured_max_bytes=None, configured_vcpus=None, online_vcpus=None, cpu_weight=None,
        observed_at=None, coverage=coverage(vm_id))


def pve_memory(config, status, native_id):
    if 'uuid=' + native_id not in config.get('smbios1', '').split(','):
        raise ValueError('native_identity_mismatch')
    row = vm_row(native_id)
    row['configured_max_bytes'] = nonnegative(config['memory']) * 1048576
    row['configured_bytes'] = nonnegative(config.get('balloon', config['memory']) or config['memory']) * 1048576
    row['power_state'] = status['status'] if status.get('status') in ('running', 'stopped') else 'unknown'
    row['qemu_pid'] = nonnegative(status['pid']) if status.get('pid') else None
    # PVE mem is guest use, never process RSS or balloon assignment.
    row['assigned_bytes'] = nonnegative(status['balloon']) if status.get('balloon') is not None else None
    row['online_vcpus'] = nonnegative(status['cpus']) if status.get('cpus') is not None else None
    row['configured_vcpus'] = nonnegative(config['cores']) * nonnegative(config['sockets']) if 'cores' in config and 'sockets' in config else None
    row['cpu_weight'] = nonnegative(config['cpuunits']) if 'cpuunits' in config else None
    return row


def libvirt_memory(xml, stats, native_id):
    if '<!DOCTYPE' in xml.upper() or '<!ENTITY' in xml.upper():
        raise ValueError('unsafe_xml')
    root = ET.fromstring(xml)
    if root.findtext('uuid') != native_id:
        raise ValueError('native_identity_mismatch')
    units = {'b': 1, 'bytes': 1, 'KiB': 1024, 'k': 1024, 'MiB': 1048576, 'GiB': 1073741824}
    def size(tag):
        element = root.find(tag)
        if element is None:
            return None
        if element.get('unit', 'KiB') not in units or not (element.text or '').isdigit():
            raise ValueError('unsupported_xml_unit')
        return int(element.text) * units[element.get('unit', 'KiB')]
    row = vm_row(native_id)
    row['configured_bytes'], row['configured_max_bytes'] = size('currentMemory'), size('memory')
    parsed = {}
    for line in stats.splitlines():
        match = re.fullmatch(r'(actual|rss) (\d+)', line)
        if match:
            if match[1] in parsed:
                raise ValueError('duplicate_dommemstat')
            parsed[match[1]] = int(match[2]) * 1024
    row['assigned_bytes'], row['qemu_rss_bytes'] = parsed.get('actual'), parsed.get('rss')
    vcpu = root.find('vcpu')
    if vcpu is not None and (vcpu.text or '').isdigit():
        row['configured_vcpus'] = int(vcpu.text)
    return row


def cgroup_delta(previous, current):
    if not previous or previous['identity'] != current['identity']:
        return None
    before, after = previous.get('oom_kill'), current.get('oom_kill')
    if type(before) is not int or type(after) is not int or not 0 <= before <= after:
        return None
    return after - before


def classify_journal(records, bindings, *, host_boot_id, scope='host'):
    events = []
    for record in records:
        message = record.get('MESSAGE', '')
        kernel = record.get('_TRANSPORT') == 'kernel'
        oomd = record.get('_SYSTEMD_UNIT') == 'systemd-oomd.service'
        killed = re.search(r'Out of memory: Killed process (\d+) \(qemu[^)]*\)', message) if kernel else None
        if not killed and not (oomd and 'Killed ' in message and 'memory pressure' in message):
            continue
        try:
            at = int(record['__REALTIME_TIMESTAMP']) // 1000000
        except (ValueError, KeyError, TypeError):
            at = None
        selected = [b for b in bindings if record.get('_BOOT_ID') == host_boot_id == b['boot_id']
                    and at is not None and b['from'] <= at <= b['until']
                    and type(b.get('start_ticks')) is int
                    and ((killed and int(killed[1]) == b['pid']) or
                         (oomd and re.search(r'(?<!\S)' + re.escape(b['cgroup']) + r'(?=\s|$)', message)))]
        binding = selected[0] if len(selected) == 1 else None
        cause = ('host_kernel_qemu_oom' if killed else 'systemd_oomd') if binding else 'unknown'
        events.append(dict(event_id=hashlib.sha256(str(record.get('__CURSOR', '')).encode()).hexdigest(),
            cause=cause, scope=scope if binding else 'unknown', vm_id=binding['vm_id'] if binding else None,
            workload=None, host_boot_id=record.get('_BOOT_ID') if scope == 'host' else None, guest_boot_id=record.get('_BOOT_ID') if scope == 'guest' else None, event_at=at,
            source_id='kernel' if kernel else 'oomd', native_generation=binding['generation'] if binding else None,
            confidence='observed' if binding else 'unknown', reasons=[] if binding else [reason('identity_unbound', 'journal')]))
    for event in events:
        peers = [other for other in events if other['vm_id'] is not None and other['vm_id'] == event['vm_id'] and other['event_at'] == event['event_at']]
        if len({e['cause'] for e in peers}) > 1:
            event['confidence'] = 'indication'
            event['reasons'].append(reason('conflicting_oom_sources', 'journal'))
    return events


UNIT_OOM_IDS = {'fe6faa94e7774663a0da52717891d8ef': 'native_unit_kernel_oom',
                'd989611b15e44c9dbf31e3c81256e4ed': 'native_unit_oomd'}


def parse_manager_oom(records, unit_bindings, *, host_boot_id):
    """Observed unit events never assert the identity/type of its killed process."""
    events = []
    for record in records:
        try:
            cause = UNIT_OOM_IDS[record.get('MESSAGE_ID')]
            selected = [b for b in unit_bindings if b['unit'] == record.get('UNIT')]
            if len(selected) != 1:
                continue
            binding = selected[0]
            invocation = record['INVOCATION_ID']
            cursor = record['__CURSOR']
            at_us, monotonic_us = int(record['__REALTIME_TIMESTAMP']), int(record['__MONOTONIC_TIMESTAMP'])
            if (record.get('_PID') != '1' or record.get('_UID') != '0' or record.get('_COMM') != 'systemd' or
                    record.get('_EXE') != binding['manager_executable'] or record.get('_BOOT_ID') != host_boot_id or
                    not re.fullmatch(r'[a-f0-9]{32}', invocation) or not isinstance(cursor, str) or not 1 <= len(cursor) <= 2048 or
                    not 0 <= monotonic_us <= binding['monotonic_us'] or at_us < 0):
                continue
            current = invocation == binding['invocation_id']
            events.append(dict(event_id=hashlib.sha256((host_boot_id+cursor).encode()).hexdigest(),
                cause=cause, scope='host', vm_id=binding.get('vm_id') if current else None, workload=None,
                host_boot_id=host_boot_id, guest_boot_id=None, event_at=at_us//1000000,
                source_id='systemd_manager_unit_oom', native_generation=host_boot_id+':'+invocation,
                confidence='observed', reasons=[] if current else [reason('historical_unit_only', 'systemd_manager_unit_oom')],
                unit_id=binding['unit_id'], unit_invocation_id=invocation, victim_kind='unknown'))
        except (KeyError, ValueError, TypeError):
            continue
    return events


class NativeSampler:
    def __init__(self, config, sources, *, clock=time.time, previous=None):
        self.config, self.sources, self.clock, self.previous = config, sources, clock, previous

    def sample(self):
        c = self.config; host = c['scopes']['host_id']; now = int(self.clock())
        native = empty_native(host, observed_at=now)
        boot = self.sources.read('/proc/sys/kernel/random/boot_id').strip()
        if self.sources.read('/etc/machine-id').strip() != c['scopes']['machine_id']:
            raise ValueError('machine_identity_mismatch')
        total, available = parse_meminfo(self.sources.read('/proc/meminfo'))
        native.update(host_boot_id=boot, host_memory=dict(total_bytes=total, available_bytes=available))
        cov = coverage(host, now, boot, status='fresh'); cov['complete'] = True
        native['coverage'] = cov
        if self.previous and type(self.previous['native']['observed_at']) is int and self.previous['native']['observed_at'] > now:
            cov.update(status='inconsistent', complete=False)
            cov['reasons'].append(reason('clock_rollback', host))
        backend = c['scopes']['backend']
        if backend == 'disabled':
            cov['reasons'].append(reason('backend_disabled', host))
        elif c['scopes']['version'] is None:
            cov.update(status='unsupported', complete=False)
            cov['reasons'].append(reason('protocol_not_qualified', host))
        else:
            version_args = [c['tools']['pvesh'], 'get', '/version', '--output-format', 'json'] if backend == 'pve' else [c['tools']['virsh'], '--connect', 'qemu:///system', 'version', '--daemon']
            version = self.sources.run(version_args).strip()
            if version != c['scopes']['version']:
                raise ValueError('protocol_version_mismatch')
            for vm in c['scopes']['vms']:
                row = vm_row(vm['vm_id'])
                try:
                    if backend == 'pve':
                        prefix = '/nodes/' + c['scopes']['node'] + '/qemu/' + vm['native_id']
                        conf = json.loads(self.sources.run([c['tools']['pvesh'], 'get', prefix + '/config', '--current', '1', '--output-format', 'json']))
                        status = json.loads(self.sources.run([c['tools']['pvesh'], 'get', prefix + '/status/current', '--output-format', 'json']))
                        row = pve_memory(conf, status, vm['uuid'])
                    else:
                        prefix = [c['tools']['virsh'], '--connect', 'qemu:///system']
                        xml = self.sources.run(prefix + ['dumpxml', vm['uuid']])
                        stats = self.sources.run(prefix + ['dommemstat', vm['uuid']])
                        row = libvirt_memory(xml, stats, vm['uuid'])
                        state = self.sources.run(prefix + ['domstate', vm['uuid']]).strip()
                        row['power_state'] = 'running' if state == 'running' else ('stopped' if state == 'shut off' else 'unknown')
                        # virsh does not offer a qualified PID/birth binding here. Keep unknown.
                        row['coverage']['reasons'].append(reason('qemu_birth_not_measured', vm['vm_id']))
                    row['vm_id'] = vm['vm_id']; row['observed_at'] = now
                    row['coverage'].update(observed_at=now, host_boot_id=boot, status='fresh')
                    if row['qemu_pid'] is not None:
                        pid = row['qemu_pid']
                        before = self.sources.process(pid)
                        if vm['uuid'] not in before['arguments']:
                            raise ValueError('qemu_identity_mismatch')
                        row.update(qemu_start_ticks=before['start_ticks'], qemu_rss_bytes=before['rss_bytes'],
                                   native_generation=boot + ':' + str(pid) + ':' + str(before['start_ticks']))
                        if self.sources.process(pid) != before:
                            raise ValueError('qemu_generation_changed')
                        row['coverage'].update(generation=row['native_generation'], complete=True)
                except Exception:
                    row = vm_row(vm['vm_id']); row['coverage']['reasons'].append(reason('vm_observation_unavailable', vm['vm_id']))
                    cov['complete'] = False
                native['vms'].append(row)
        services = []
        for service in c['scopes']['services']:
            entry = dict(service_id=service['service_id'], active_state=None, sub_state=None, result=None,
                         invocation_id=None, observed_at=None, coverage=coverage(service['service_id']))
            try:
                raw = self.sources.run([c['tools']['systemctl'], 'show', '--no-pager',
                    '--property=ActiveState,SubState,Result,InvocationID', '--', service['unit']])
                props = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
                for key, native_key in [('active_state', 'ActiveState'), ('sub_state', 'SubState'), ('result', 'Result'), ('invocation_id', 'InvocationID')]:
                    text = props.get(native_key)
                    entry[key] = text if text and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', text) else None
                entry['observed_at'] = now; entry['coverage'].update(observed_at=now, host_boot_id=boot, status='fresh', complete=True)
            except Exception:
                entry['coverage']['reasons'].append(reason('service_unavailable', service['service_id']))
            services.append(entry)
        self._events(native, boot, now)
        if self.sources.read('/proc/sys/kernel/random/boot_id').strip() != boot:
            raise ValueError('boot_changed')
        native['sample_generation'] = hashlib.sha256(json.dumps(native, sort_keys=True).encode()).hexdigest()
        native['coverage']['generation'] = native['sample_generation']
        return dict(native=native, services=services)

    def _unit_bindings(self, native, boot, now):
        c = self.config; units = c['scopes']['units']
        cap = native['capabilities']['systemd_manager_unit_oom']
        if c['role'] != 'native_host' or not units or c['scopes']['manager_version'] is None:
            return []
        try:
            version = self.sources.run([c['tools']['systemctl'], '--version'], output_bytes=4096).strip()
            if version != c['scopes']['manager_version'] or not re.match(r'^systemd 257 \(257\.13(?:[) -])', version):
                raise ValueError('unit_protocol_unsupported')
            bindings = []
            for unit in units:
                argv = [c['tools']['systemctl'], 'show', '--no-pager', '--property=Id,ControlGroup,InvocationID', '--', unit['unit']]
                before = self.sources.run(argv, output_bytes=8192)
                properties = dict(line.split('=', 1) for line in before.splitlines() if '=' in line)
                if (set(properties) != {'Id', 'ControlGroup', 'InvocationID'} or properties['Id'] != unit['unit'] or
                        not re.fullmatch(r'[a-f0-9]{32}', properties['InvocationID']) or
                        not re.fullmatch(r'/[A-Za-z0-9_.@/:-]+', properties['ControlGroup']) or
                        self.sources.run(argv, output_bytes=8192) != before):
                    raise ValueError('unit_cycle_changed')
                vm = next((v for v in native['vms'] if v['vm_id'] == unit['vm_id'] and v['native_generation'] is not None), None)
                bindings.append(dict(unit_id=unit['unit_id'], unit=unit['unit'],
                    invocation_id=properties['InvocationID'], vm_id=vm['vm_id'] if vm else None,
                    manager_executable=unit['manager_executable'], monotonic_us=time.monotonic_ns()//1000))
            cap.update(status='fresh', complete=True, observed_at=now, host_boot_id=boot, reasons=[])
            return bindings
        except Exception:
            cap.update(status='unsupported', complete=False, observed_at=now, host_boot_id=boot,
                       reasons=[reason('unit_protocol_or_identity_unavailable', 'systemd_manager_unit_oom')])
            return []

    def _events(self, native, boot, now):
        c = self.config; prev = self.previous
        same = prev and prev['native']['host_boot_id'] == boot and type(prev['native']['observed_at']) is int and prev['native']['observed_at'] <= now
        events = []
        bindings = []
        # Sampling supplies last-seen birth, not a proven death interval. Until an
        # enrolled interval source is available, journal kills stay identity_unbound;
        # a reused PID must never implicate an unrelated VM.
        oc = coverage('journal', now, boot, status='not_measured', reasons=[reason('journal_disabled', 'journal')])
        if prev and not same:
            oc['reasons'].append(reason('boot_or_clock_gap', 'journal'))
        if c['scopes']['journal']:
            # Finite lookback/last-N, never fall back to all history after cursor loss.
            oc['reasons'] = [reason('boot_or_clock_gap', 'journal')] if prev and not same else []
            args = [c['tools']['journalctl'], '--boot=' + boot, '--output=json', '--no-pager',
                    '--lines=' + str(c['bounds']['journal_events']), '--since=@' + str(max(0, now-c['bounds']['lookback_seconds'])),
                    '_TRANSPORT=kernel', '+', '_SYSTEMD_UNIT=systemd-oomd.service', '+',
                    'MESSAGE_ID=fe6faa94e7774663a0da52717891d8ef', '+', 'MESSAGE_ID=d989611b15e44c9dbf31e3c81256e4ed']
            cursor = prev.get('journal_cursor') if same else None
            if not cursor:
                oc['reasons'].append(reason('initial_or_gap_window', 'journal'))
            if cursor:
                args += ['--after-cursor=' + cursor]
            unit_before = self._unit_bindings(native,boot,now)
            try:
                raw = self.sources.run(args, output_bytes=c['bounds']['journal_bytes'])
                records = [json.loads(line) for line in raw.splitlines()]
                if len(records) >= c['bounds']['journal_events']:
                    oc['reasons'].append(reason('journal_window_truncated', 'journal'))
                events = classify_journal(records, bindings, host_boot_id=boot, scope='guest' if c['role'] == 'worker' else 'host')
                unit_bindings = self._unit_bindings(native, boot, now)
                keys = ('unit_id','unit','invocation_id','vm_id','manager_executable')
                if [[b[k] for k in keys] for b in unit_bindings] != [[b[k] for k in keys] for b in unit_before]:
                    unit_bindings = []
                    native['capabilities']['systemd_manager_unit_oom'].update(status='inconsistent',complete=False,
                        reasons=[reason('unit_cycle_changed','systemd_manager_unit_oom')])
                events += parse_manager_oom(records, unit_bindings, host_boot_id=boot)
                self.journal_cursor = records[-1].get('__CURSOR') if records else cursor
                oc.update(status='fresh', complete=not oc['reasons'])
            except Exception:
                oc.update(status='not_measured', complete=False, reasons=[reason('journal_gap', 'journal')])
        prior = prev.get('cgroups', {}) if same else {}; current = {}
        for group in c['scopes']['cgroups']:
            try:
                value = self.sources.cgroup(group['path'], boot, group['generation'])
                current[group['workload']] = value
                delta = cgroup_delta(prior.get(group['workload']), value)
                if delta:
                    events.append(dict(event_id=hashlib.sha256((value['identity']+str(value['oom_kill'])).encode()).hexdigest(),
                        cause='guest_cgroup_oom', scope='guest', vm_id=group['vm_id'], workload=group['workload'],
                        host_boot_id=None, guest_boot_id=boot, event_at=now, source_id='cgroup',
                        native_generation=value['identity'], confidence='observed', reasons=[]))
                elif delta is None:
                    oc['reasons'].append(reason('prior_count_unknown_time', 'cgroup'))
            except Exception:
                oc['reasons'].append(reason('cgroup_gap', 'cgroup'))
        if same:
            current_ids = {r['vm_id'] for r in native['vms'] if r['power_state'] == 'running'}
            for row in prev['native']['vms']:
                if row['power_state'] == 'running' and row['vm_id'] not in current_ids and not any(e['vm_id'] == row['vm_id'] and e['cause'] in ('host_kernel_qemu_oom','systemd_oomd') and e['confidence'] == 'observed' for e in events):
                    events.append(dict(event_id=hashlib.sha256((row['vm_id']+str(now)).encode()).hexdigest(),
                        cause='unknown_vm_loss', scope='unknown', vm_id=row['vm_id'], workload=None, host_boot_id=boot,
                        guest_boot_id=None, event_at=now, source_id='native', native_generation=row['native_generation'],
                        confidence='unknown', reasons=[reason('loss_without_bound_evidence', 'native')]))
        old_events = prev['native']['oom']['events'] if same else []
        for event in events:
            event.setdefault('unit_id', None); event.setdefault('unit_invocation_id', None); event.setdefault('victim_kind', 'unknown')
        ring = {e['event_id']: e for e in old_events + events}
        native['oom'] = dict(events=list(ring.values())[-c['bounds']['retention_entries']:], coverage=oc, next_cursor=None)
        self.cgroups = current


def _normalize_coverage(value, *, measurement_at, now, fresh_seconds):
    """Demote time claims, preserving source timestamps and capability/gap reasons."""
    times = (measurement_at, value['observed_at'])
    code = None
    if any(at is not None and at > now for at in times):
        value['status'] = 'inconsistent'; code = 'clock_future'
    elif any(at is None for at in times):
        if value['status'] in ('fresh', 'stale'):
            value['status'] = 'not_measured'; code = 'sample_not_measured'
    elif any(now-at > fresh_seconds for at in times):
        if value['status'] in ('fresh', 'stale'):
            value['status'] = 'stale'; code = 'sample_stale'
    if code:
        value['complete'] = False
        new = reason(code, value['source_id'])
        if new not in value['reasons']:
            value['reasons'] = value['reasons'][:127] + [new]
    return value


def _normalize_native_status(document, *, now, fresh_seconds):
    value = copy.deepcopy(document)
    _normalize_coverage(value['coverage'], measurement_at=value['observed_at'], now=now, fresh_seconds=fresh_seconds)
    for vm in value['vms']:
        _normalize_coverage(vm['coverage'], measurement_at=vm['observed_at'], now=now, fresh_seconds=fresh_seconds)
    for capability in value['capabilities'].values():
        _normalize_coverage(capability, measurement_at=capability['observed_at'], now=now, fresh_seconds=fresh_seconds)
    source = value['oom']['coverage']
    _normalize_coverage(source, measurement_at=source['observed_at'], now=now, fresh_seconds=fresh_seconds)
    # Historical event confidence/identity/time is evidence, not a freshness claim.
    return value


def read_native_status(*, cursor=None, limit=64):
    from monitoring_runtime import read_cache, load_config, validate_query, encode_token, decode_token
    validate_query(dict(schema='qcl.cluster-query.v1', request_id=None, cursor=None, limit=limit))
    config = load_config(); cache = read_cache(config)
    view = _normalize_native_status(cache['native'] if cache else empty_native(config['scopes']['host_id']),
                                    now=int(time.time()), fresh_seconds=config['bounds']['fresh_seconds'])
    offset = 0
    if cursor:
        token = decode_token(cursor)
        if set(token) != {'generation', 'offset'} or token['generation'] != view['sample_generation'] or type(token['offset']) is not int or token['offset'] < 0:
            raise ValueError('stale_cursor')
        offset = token['offset']
    rows = view['vms']; view['vms'] = rows[offset:offset+limit]
    view['complete'] = offset+limit >= len(rows)
    view['next_cursor'] = None if view['complete'] else encode_token(dict(generation=view['sample_generation'], offset=offset+limit))
    return view
