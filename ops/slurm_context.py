"""Bounded current Slurm context. Acquisition is separate from cache-only public reads."""
import copy
import datetime
import hashlib
import json
import re
import time


def empty_context(config, *, now=None):
    from native_monitoring import coverage, reason
    enabled = config['context']['enabled']
    return dict(schema='qcl.current-context.v1', read_at=int(time.time()) if now is None else now,
        observed_at=None, cluster_id=config['context']['cluster_id'], controller_boot_id=None,
        sample_generation=None, status='unknown' if enabled else 'disabled', jobs=[],
        coverage=coverage('slurm', reasons=[reason('not_sampled' if enabled else 'context_disabled', 'slurm')]),
        complete=False, next_cursor=None)


def _text(value, maximum=128):
    if not isinstance(value, str) or len(value) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('invalid_slurm_field')
    return value


def _date(value):
    if value in (None, 'Unknown', 'N/A', 'None'):
        return None
    if not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d', value):
        raise ValueError('invalid_slurm_time')
    parsed = datetime.datetime.fromisoformat(value).replace(tzinfo=datetime.timezone.utc)
    at = int(parsed.timestamp())
    if at < 0:
        raise ValueError('invalid_slurm_time')
    return at


def _memory(value):
    match = re.fullmatch(r'(\d+)([KMGT]?)', value)
    if not match:
        raise ValueError('invalid_slurm_memory')
    # scontrol MinMemory{Node,CPU}: unsuffixed MB is 1024**2 bytes in the pinned protocol.
    factor = {'': 1024**2, 'K': 1024, 'M': 1024**2, 'G': 1024**3, 'T': 1024**4}[match[2]]
    result = int(match[1]) * factor
    if result == 0:
        raise ValueError('slurm_memory_all_node')
    if result > 2**63-1:
        raise ValueError('invalid_slurm_memory')
    return result


def _state(value):
    if value in ('PENDING', 'CONFIGURING', 'REQUEUED', 'REQUEUE_FED', 'REQUEUE_HOLD', 'RESV_DEL_HOLD'):
        return 'queued'
    if value in ('RUNNING', 'SUSPENDED', 'RESIZING', 'SIGNALING', 'STOPPED'):
        return 'running'
    if value in ('COMPLETING', 'STAGE_OUT'):
        return 'finishing'
    if value in ('BOOT_FAIL', 'CANCELLED', 'COMPLETED', 'DEADLINE', 'FAILED', 'NODE_FAIL', 'OUT_OF_MEMORY', 'PREEMPTED', 'TIMEOUT', 'REVOKED', 'SPECIAL_EXIT'):
        return 'retained_terminal'
    return 'unknown'


def _job(line, allowed_uids, now, boot):
    from native_monitoring import coverage
    fields = line.split('|')
    if len(fields) != 5:
        raise ValueError('invalid_slurm_queue')
    identifier, uid, state, why, nodes = map(_text, fields)
    if not re.fullmatch(r'[0-9]+(?:_[0-9]+|\+[0-9]+)?', identifier) or not uid.isdigit() or int(uid) not in allowed_uids or not re.fullmatch(r'[A-Z_]+', state):
        raise ValueError('invalid_slurm_queue')
    return dict(job_id=identifier, owner_uid=int(uid), state=_state(state), native_state=state,
        reason=why, node_expression=nodes, submit_time=None, start_time=None, restarts=None, cpus=None,
        requested_memory=dict(per_node_bytes=None, per_cpu_bytes=None), generation=None,
        coverage=coverage('slurm', now, boot, status='not_measured'))


def _detail(raw, row, cluster, now, boot):
    from native_monitoring import coverage
    keys = r'JobId|UserId|JobState|NumCPUs|NodeList|SubmitTime|StartTime|Restarts|MinMemoryNode|MinMemoryCPU'
    fields = {}
    for key, value in re.findall(r'(?:^|\s)(' + keys + r')=([^\s]+)', raw):
        if key in fields:
            raise ValueError('duplicate_slurm_detail')
        fields[key] = value
    required = {'JobId', 'UserId', 'JobState', 'NumCPUs', 'NodeList', 'SubmitTime', 'StartTime', 'Restarts'}
    uid = re.fullmatch(r'[^()\s]+\(([0-9]+)\)', fields.get('UserId', ''))
    if (not required <= set(fields) or fields['JobId'] != row['job_id'] or uid is None or
            int(uid[1]) != row['owner_uid'] or fields['JobState'] != row['native_state'] or
            fields['NodeList'] != row['node_expression'] or
            not fields['NumCPUs'].isdigit() or not fields['Restarts'].isdigit() or
            len({'MinMemoryNode', 'MinMemoryCPU'} & set(fields)) != 1):
        raise ValueError('inconsistent_slurm_detail')
    submit, start = _date(fields['SubmitTime']), _date(fields['StartTime'])
    if submit is None or submit > now or start is not None and (start < submit or start > now):
        raise ValueError('inconsistent_slurm_time')
    row.update(submit_time=submit, start_time=start, restarts=int(fields['Restarts']), cpus=int(fields['NumCPUs']))
    memory_key = 'MinMemoryNode' if 'MinMemoryNode' in fields else 'MinMemoryCPU'
    row['requested_memory']['per_node_bytes' if memory_key == 'MinMemoryNode' else 'per_cpu_bytes'] = _memory(fields[memory_key])
    generation = hashlib.sha256(json.dumps(['observation-only', cluster, row['job_id'], row['owner_uid'], submit, start, row['restarts']]).encode()).hexdigest()
    row['generation'] = generation
    row['coverage'] = coverage('slurm', now, boot, generation, status='fresh'); row['coverage']['complete'] = True


def sample_current_context(config, sources, previous, *, now):
    """No raw show-config or failure record is persisted, relayed or used as an exception message."""
    from native_monitoring import coverage, reason
    value = empty_context(config, now=now)
    if not config['context']['enabled']:
        return value
    if config['role'] != 'controller':
        raise ValueError('context_controller_required')
    context = config['context']; consumed = 0
    deadline = time.monotonic() + 5
    environment = dict(PATH='/usr/bin:/bin', LC_ALL='C', LANG='C', TZ='UTC',
                       SLURM_TIME_FORMAT='standard', SLURM_CONF=context['slurm_conf'])

    def run(argv, bound):
        nonlocal consumed
        if time.monotonic() >= deadline or consumed >= 262144:
            raise ValueError('context_budget')
        bound = min(bound, 262144-consumed)
        raw = sources.run(argv, output_bytes=bound, env=environment, deadline=deadline)
        size = getattr(raw, 'output_bytes', len(raw.encode()))
        if type(size) is not int or not len(raw.encode()) <= size <= bound:
            raise ValueError('context_budget')
        consumed += size
        return raw

    try:
        config_identity = sources.trusted_config_identity(context['slurm_conf'])
        boot = sources.read('/proc/sys/kernel/random/boot_id').strip()
        if sources.read('/etc/machine-id').strip() != config['scopes']['machine_id']:
            raise ValueError('context_identity')
        version = run([config['tools']['scontrol'], '--version'], 1024).strip()
        if context['version_profile'] != '25.11.8' or version != 'slurm 25.11.8':
            value.update(status='unsupported'); value['coverage']['status'] = 'unsupported'
            value['coverage']['reasons'] = [reason('slurm_version_unsupported', 'slurm')]
            return value
        raw = run([config['tools']['scontrol'], 'show', 'config'], 65536)
        clusters = re.findall(r'^\s*ClusterName\s*=\s*([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\s*$', raw, re.M)
        candidates = re.findall(r'^\s*ClusterName\b.*$', raw, re.M)
        del raw  # discard all non-allowlisted fields before any durable/public value exists
        if len(clusters) != 1 or len(candidates) != 1 or clusters[0] != context['cluster_id']:
            raise ValueError('context_identity')
        del candidates
        raw = run([config['tools']['squeue'], '--local', '--array', '--noheader', '--states=all',
                   '--user=' + ','.join(map(str, context['owner_uids'])), '--format=%i|%U|%T|%r|%N'], 65536)
        lines = raw.splitlines(); del raw
        truncated = len(lines) > 128
        jobs = [_job(line, context['owner_uids'], now, boot) for line in lines[:128]]
        if len({j['job_id'] for j in jobs}) != len(jobs):
            raise ValueError('duplicate_slurm_job')
        detail_count = 0
        for row in jobs:
            try:
                if not row['job_id'].isdigit():
                    row['coverage'].update(status='unsupported',reasons=[reason('slurm_complex_job_detail_unsupported','slurm')])
                    continue
                if detail_count >= 32:
                    row['coverage']['reasons'] = [reason('slurm_detail_budget','slurm')]
                    continue
                detail_count += 1
                raw = run([config['tools']['scontrol'], '--oneliner', 'show', 'job', row['job_id']], 8192)
                candidate = copy.deepcopy(row)
                _detail(raw, candidate, context['cluster_id'], now, boot)
                del raw
                row.update(candidate)
            except Exception as error:
                code = 'slurm_memory_all_node' if type(error) is ValueError and str(error) == 'slurm_memory_all_node' else 'slurm_detail_unavailable'
                row['coverage']['reasons'] = [reason(code, 'slurm')]
        if sources.read('/proc/sys/kernel/random/boot_id').strip() != boot or sources.trusted_config_identity(context['slurm_conf']) != config_identity:
            raise ValueError('context_boot_changed')
        complete = not truncated and all(row['coverage']['complete'] for row in jobs)
        cov = coverage('slurm', now, boot, status='fresh'); cov['complete'] = complete
        if not complete:
            cov['reasons'] = [reason('current_context_partial', 'slurm')]
        generation = hashlib.sha256(json.dumps([boot, now, jobs], sort_keys=True).encode()).hexdigest()
        cov['generation'] = generation
        value.update(observed_at=now, controller_boot_id=boot, sample_generation=generation,
                     jobs=jobs, status='fresh' if complete else 'partial', coverage=cov, complete=complete)
    except Exception:
        # Never expose CommandFailure.record/stdout/stderr/config through logs, receipts or chaining.
        if previous and previous.get('schema') == 'qcl.current-context.v1' and previous.get('cluster_id') == context['cluster_id']:
            value = copy.deepcopy(previous); value.update(read_at=now, status='unknown', next_cursor=None, complete=False)
        value['coverage'] = coverage('slurm', value['observed_at'], value['controller_boot_id'],
            value['sample_generation'], reasons=[reason('current_context_unavailable', 'slurm')])
    return value


def normalize_context(document, *, now, fresh_seconds):
    from native_monitoring import _normalize_coverage
    value = copy.deepcopy(document); value['read_at'] = now
    at = value['observed_at']
    if at is not None:
        if at > now:
            value.update(status='unknown', complete=False)
        elif now-at > fresh_seconds:
            value.update(status='stale', complete=False)
    _normalize_coverage(value['coverage'], measurement_at=at, now=now, fresh_seconds=fresh_seconds)
    for row in value['jobs']:
        _normalize_coverage(row['coverage'], measurement_at=at, now=now, fresh_seconds=fresh_seconds)
    return value


def read_current_context(*, cursor=None, limit=64):
    from monitoring_runtime import load_config, read_cache, validate_query, encode_token, decode_token
    validate_query(dict(schema='qcl.cluster-query.v1', request_id=None, cursor=cursor, limit=limit))
    config = load_config()
    if config['role'] != 'controller':
        raise ValueError('context_controller_required')
    cache = read_cache(config)
    value = normalize_context(cache['current_context'] if cache else empty_context(config),
                              now=int(time.time()), fresh_seconds=config['bounds']['fresh_seconds'])
    identity = dict(generation=value['sample_generation'], boot=value['controller_boot_id'], cluster=value['cluster_id'])
    offset = 0
    if cursor is not None:
        token = decode_token(cursor)
        if set(token) != {*identity, 'offset'} or any(token[k] != v for k,v in identity.items()) or type(token['offset']) is not int or not 0 <= token['offset'] < len(value['jobs']):
            raise ValueError('stale_cursor')
        offset = token['offset']
    rows = value['jobs']; value['jobs'] = rows[offset:offset+limit]
    more = offset+limit < len(rows)
    value['complete'] = value['complete'] and not more
    value['next_cursor'] = encode_token({**identity, 'offset': offset+limit}) if more else None
    return value
