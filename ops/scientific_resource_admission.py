"""Fail-closed scientific capacity validation and explicit bounded metadata reads.

Internal records only: no wire schema, signer, reservation ledger or production
backend. A deployment-provided verifier must authenticate every fact, enforcement
capability and sole-C1 binding. This module never allocates, reserves or mutates a
scientific domain. A decision is not a lease or scientific preflight activation.
"""
from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import time
from types import MappingProxyType
from uuid import UUID

_MAX = (1 << 64) - 1
_VIEWS = ('logical_bytes', 'physical_bytes', 'inodes')
_BINDINGS = ('campaign_id', 'slot_id', 'plan_digest', 'criteria_digest',
             'source_graph_digest', 'release_id', 'runtime_id', 'execution_id',
             'attempt_id', 'point_id', 'admission_id', 'job_id', 'step_id',
             'owner_uid', 'pid', 'start_ticks', 'host_id', 'machine_id', 'boot_id',
             'mount_namespace', 'cgroup_namespace', 'vm_id', 'hypervisor_id',
             'resource_epoch', 'storage_epoch')
_COSTS = ('numerical', 'runtime', 'native', 'allocator', 'HDF5',
          'serialization', 'audit', 'stop')


def _freeze(value):
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


@dataclass(frozen=True)
class ScienceCapacityFacts:
    binding: Mapping
    observations: Mapping
    evidence: tuple

    def __post_init__(self):
        object.__setattr__(self, 'binding', _freeze(self.binding))
        object.__setattr__(self, 'observations', _freeze(self.observations))
        object.__setattr__(self, 'evidence', _freeze(self.evidence))


@dataclass(frozen=True)
class AggregateStorageProof:
    """Authenticated backend simultaneous attempt/owner/campaign proof, not a flag.

    Included inside facts returned by the trusted verifier. Domains are canonical
    backing identities; placements cover exactly USED roles, including controller
    ORM/repository/WAL/spool when used. Shared backing aliases use one domain.
    """
    binding: Mapping
    baseline_id: str
    operation_id: str
    operation_digest: str
    domain_backing: tuple
    placements: tuple
    scopes: tuple
    evidence: tuple

    def __post_init__(self):
        for name in ('binding', 'domain_backing', 'placements', 'scopes', 'evidence'):
            object.__setattr__(self, name, _freeze(getattr(self, name)))


@dataclass(frozen=True)
class ScienceCapacityDecision:
    cpu_ids: tuple
    workers: int
    memory_bytes: int
    storage_bounds: tuple
    binding: Mapping
    evidence: tuple
    authority_refs: tuple

    def __post_init__(self):
        object.__setattr__(self, 'storage_bounds', _freeze(self.storage_bounds))
        object.__setattr__(self, 'binding', _freeze(self.binding))
        object.__setattr__(self, 'evidence', _freeze(self.evidence))
        object.__setattr__(self, 'authority_refs', _freeze(self.authority_refs))


@dataclass(frozen=True)
class ScienceCapacityRefusal:
    status: str
    reason: str
    binding: Mapping
    evidence: tuple

    def __post_init__(self):
        if self.status not in ('needs_admission', 'needs_guard', 'refused'):
            raise ValueError('invalid refusal status')
        object.__setattr__(self, 'binding', _freeze(self.binding))
        object.__setattr__(self, 'evidence', _freeze(self.evidence))


class _Reject(Exception):
    def __init__(self, reason, status='refused'):
        self.reason, self.status = reason, status


def _need(ok, reason, status='refused'):
    if not ok:
        raise _Reject(reason, status)


def _int(value):
    _need(type(value) is int and 0 <= value <= _MAX, 'invalid_or_overflow_integer')
    return value


def _sum(values):
    total = 0
    for value in values:
        total += _int(value)
        _need(total <= _MAX, 'arithmetic_overflow')
    return total


def _sequence(value):
    _need(isinstance(value, (list, tuple)) and value, 'missing_sequence')
    return value


def _ids(value):
    values = tuple(_int(item) for item in _sequence(value))
    _need(len(set(values)) == len(values), 'duplicate_cpu_id')
    return set(values)


def _binding(value, expected):
    _need(isinstance(value, Mapping) and isinstance(expected, Mapping), 'missing_binding', 'needs_admission')
    _need(set(_BINDINGS) <= set(expected) and value == expected, 'identity_binding_mismatch', 'needs_admission')
    for key in _BINDINGS:
        item = expected[key]
        if key in ('owner_uid', 'pid', 'start_ticks', 'mount_namespace', 'cgroup_namespace', 'vm_id'):
            _need(_int(item) > 0, 'missing_numeric_identity', 'needs_admission')
        else:
            _need(type(item) is str and item, 'missing_identity', 'needs_admission')
    _need(expected['owner_uid'] == 3000, 'unexpected_owner', 'needs_admission')
    for key in ('plan_digest', 'criteria_digest', 'source_graph_digest'):
        _need(re.fullmatch(r'[0-9a-f]{64}', expected[key]) is not None,
              'invalid_binding_digest', 'needs_admission')
    _need(re.fullmatch(r'[1-9][0-9]{0,9}', expected['job_id']) is not None and
          re.fullmatch(r'[A-Za-z0-9_-]+', expected['step_id']) is not None,
          'invalid_scheduler_identity', 'needs_admission')
    _need(re.fullmatch(r'[0-9a-f]{32}', expected['machine_id']) is not None,
          'invalid_machine_identity', 'needs_admission')
    UUID(expected['boot_id'])


def _observation(facts, name, units, expected, now_ns, max_age, stop_lag):
    row = facts.observations[name]
    _need(isinstance(row, Mapping) and row['status'] == 'observed' and row['reason'] is None,
          'unobserved_' + name, 'needs_admission')
    _binding(row['identity'], expected)
    _need(row['units'] == units and row['subject'] == expected['attempt_id'] and
          row['scope'] == 'attempt' and row['coverage'] == 'complete',
          'incomplete_' + name, 'needs_admission')
    _need(all(type(row[key]) is str and row[key] for key in ('path', 'tool', 'version')) and
          bool(row['evidence']), 'missing_evidence_' + name, 'needs_admission')
    begin, end = _int(row['capture_begin_ns']), _int(row['capture_end_ns'])
    _need(begin <= end <= now_ns and _sum((now_ns - begin, stop_lag)) <= max_age,
          'stale_or_future_' + name, 'needs_admission')
    return row['value']


def _hierarchy(rows, epoch):
    rows = _sequence(rows)
    paths = []
    for row in rows:
        path = row['path']
        _need(type(path) is str and path.startswith('/') and '..' not in Path(path).parts and
              str(Path(path)) == path and path not in paths, 'invalid_ancestor_path', 'needs_admission')
        _need(_int(row['inode']) > 0 and row['epoch'] == epoch, 'ancestor_identity_epoch', 'needs_admission')
        paths.append(path)
    _need(paths[0] == '/' and all(Path(b).parent == Path(a) for a, b in zip(paths, paths[1:])),
          'missing_ancestor', 'needs_admission')
    return rows


def _cpu(value, request, epoch):
    _need(value['hierarchy_coverage'] in ('complete', 'host_attested'), 'hidden_host_bound', 'needs_admission')
    available = _ids(value['scheduler_ids']) & _ids(value['affinity_ids']) & _ids(value['owned_ids'])
    protected = value['protected_ids']
    _need(isinstance(protected, (list, tuple)), 'protected_cpu_ids', 'needs_admission')
    available -= {_int(item) for item in protected}
    quota_limit = None
    for row in _hierarchy(value['ancestors'], epoch):
        available &= _ids(row['cpu_ids'])
        quota = row['quota']
        if quota != 'max':
            _need(isinstance(quota, (list, tuple)) and len(quota) == 2, 'cpu_quota_pair')
            numerator, denominator = map(_int, quota)
            _need(denominator > 0, 'cpu_quota_period')
            # Integer rational floor, never ceil or max(1,...).
            cores = numerator // denominator
            quota_limit = cores if quota_limit is None else min(quota_limit, cores)
    workers = _int(request['workers'])
    _need(workers > 0 and request['blas_threads'] == 1 and type(request['blas_threads']) is int,
          'invalid_thread_request')
    pool = _ids(value['pool_ids'])
    available &= pool
    _need(available and workers <= len(available) and (quota_limit is None or workers <= quota_limit),
          'insufficient_full_core_grant')
    chosen = tuple(sorted(available)[:workers])
    return chosen, workers


def _ram(value, request, epoch):
    _need(value['inventory_complete'] is True and value['baseline_id'] == request['baseline_id'],
          'host_inventory_baseline', 'needs_admission')
    for row in _sequence(value['obligations']):
        _need(all(type(row[key]) is str and row[key] for key in ('owner', 'scope', 'id')) and
              row['baseline_id'] == value['baseline_id'] and row['units'] == 'bytes',
              'foreign_obligation_baseline', 'needs_admission')
        _int(row['unmaterialized_upper'])
    costs = request['memory_costs']
    _need(isinstance(costs, Mapping) and set(costs) == set(_COSTS) and
          type(request['estimator_digest']) is str and request['estimator_digest'], 'memory_estimator')
    total = _sum(costs.values())
    total_scopes = set()
    for row in _sequence(value['total_authorities']):
        _need(row['scope'] and row['id'], 'memory_authority_identity', 'needs_admission')
        _need(row['scope'] not in total_scopes, 'duplicate_memory_authority', 'needs_admission')
        total_scopes.add(row['scope'])
        _need(total <= _int(row['bytes']), 'memory_total_capacity')
    _need({'slurm', 'vm', 'host'} <= total_scopes, 'incomplete_memory_authorities', 'needs_admission')
    growth = _sum((request['incremental_memory'], request['unmaterialized_stop']))
    _need(growth <= _int(value['remaining_headroom']), 'memory_remaining_headroom')
    _need(request['memory_mode'] in ('allocation', 'phase'), 'memory_phase')
    if request['memory_mode'] == 'phase':
        _need(value.get('phase_burst_bounded') is True,
              'phase_burst_unavailable', 'needs_guard')
    finite = False
    for row in _hierarchy(value['ancestors'], epoch):
        current = _int(row['current']); _int(row['peak']); _int(row['swap'])
        _need(isinstance(row['events'], Mapping) and row['events'], 'memory_events', 'needs_admission')
        for count in row['events'].values():
            _int(count)
        for key in ('max', 'high'):
            limit = row[key]
            if limit != 'max':
                finite = True; limit = _int(limit)
                required = total if request['memory_mode'] == 'allocation' else _sum((current, growth))
                _need(required <= limit, 'phase_memory_bound')
    _need(finite, 'no_finite_memory_allocation', 'needs_admission')
    return total


def _headroom(row, scope):
    if 'H' in row:
        _need('net' not in row, 'headroom_correction_twice')
        return _int(row['H'])
    net = row['net']
    _need(net['corrected'] is False, 'headroom_correction_twice')
    seen = set(); credit = []; by_kind = {'U': [], 'S': []}
    for lease in _sequence(net['reservations']):
        _need(lease['id'] not in seen and lease['kind'] in ('U', 'S') and lease['materialized'] is False and
              lease['epoch'] == scope['epoch'] and lease['baseline_id'] == scope['baseline_id'] and
              lease['scope_id'] == scope['scope_id'],
              'invalid_headroom_addback')
        seen.add(lease['id']); amount = _int(lease['amount']); credit.append(amount)
        by_kind[lease['kind']].append(amount)
    _need(all(_sum(by_kind[kind]) <= _int(row[kind]) for kind in ('U', 'S')),
          'headroom_addback_overlap')
    _need(_sum(credit) <= _sum((row['U'], row['S'])), 'headroom_addback_overlap')
    return _sum((net['Hnet'], _sum(credit)))


def _storage(value, request, authority, epoch):
    _need(value['state'] == 'pre_descriptor' and value['operation_id'] == request['operation_id'] and
          value['operation_digest'] == request['operation_digest'] and
          value['baseline_id'] == request['baseline_id'], 'operation_replay_or_binding', 'needs_admission')
    c1 = authority.get('C1')
    _need(isinstance(c1, Mapping) and c1.get('id') and c1.get('baseline_id') == value['baseline_id'] and
          c1.get('atomic_all_scopes') is True and c1.get('reconcile_required_on_unknown') is True,
          'C1_unavailable', 'needs_admission')
    domains = set(request['storage_growth'])
    aggregate = authority.get('aggregate_storage')
    _need(len(domains) <= 1 or type(aggregate) is AggregateStorageProof,
          'aggregate_capacity_proof_unavailable')
    _need(domains and domains <= set(c1['domains']), 'C1_domain_coverage', 'needs_admission')
    enforcer = authority.get('enforcer')
    _need(isinstance(enforcer, Mapping) and enforcer.get('id') and enforcer.get('evidence') and
          domains <= set(enforcer.get('domains', ())) and
          all(enforcer.get(key) is True for key in ('physical_hard_bound', 'inode_hard_bound',
                                                   'all_roots_and_external_logs')),
          'resident_enforcement_unavailable', 'needs_guard')
    root_domains = set(); backing = {}
    roles = set()
    for root in _sequence(value['roots']):
        _need(root['canonical_descriptor_bound'] is True and root['containment_enforced'] is True and
              root['protected_or_foreign'] is False and root['owner_scope'] == 'attempt' and
              root['uid'] == 3000 and type(root['uid']) is int, 'root_containment', 'needs_admission')
        for key in ('role', 'domain', 'backing_id', 'inode_domain', 'filesystem'):
            _need(type(root[key]) is str and root[key], 'root_identity', 'needs_admission')
        for key in ('mount_namespace', 'mount_id', 'gid', 'project'):
            _need(_int(root[key]) > 0, 'root_identity', 'needs_admission')
        _need(isinstance(root['directory_identity'], (list, tuple)) and root['directory_identity'],
              'directory_identity', 'needs_admission')
        for item in root['directory_identity']:
            _need(_int(item) > 0, 'directory_identity', 'needs_admission')
        _need(root['mount_namespace'] == authority['binding']['mount_namespace'],
              'root_mount_namespace', 'needs_admission')
        if root['filesystem'].lower() in ('nfs', 'nfs4'):
            _need(root.get('server_id') and root.get('export_id') and root.get('server_quota_domain'),
                  'NFS_server_mapping', 'needs_admission')
        domain = root['domain']; identity = (root['backing_id'], root['inode_domain'])
        _need(domain not in backing or backing[domain] == identity, 'unproven_alias', 'needs_admission')
        backing[domain] = identity; root_domains.add(domain)
        _need(root['role'] not in roles, 'duplicate_root_role', 'needs_admission')
        roles.add(root['role'])
    _need(domains == root_domains, 'writable_root_coverage', 'needs_admission')
    _need(roles == set(_sequence(request['root_roles'])), 'writable_root_role_coverage', 'needs_admission')
    result = []; covered = {domain: set() for domain in domains}
    for scope in _sequence(value['scopes']):
        domain = scope['domain']
        _need(domain in domains and scope['scope'] in ('attempt', 'owner', 'filesystem', 'campaign') and
              scope['scope'] not in covered[domain] and scope['scope_id'] and scope['epoch'] == epoch and
              scope['baseline_id'] == value['baseline_id'], 'scope_binding', 'needs_admission')
        covered[domain].add(scope['scope']); bounds = {'domain': domain, 'scope': scope['scope']}
        _need(set(scope['views']) == set(_VIEWS) and set(request['storage_growth'][domain]) == set(_VIEWS),
              'missing_accounting_view', 'needs_admission')
        for name in _VIEWS:
            row = scope['views'][name]
            _need(_int(row['P']) == 0, 'descriptor_already_charged')
            growth = _sum((row['U'], request['storage_growth'][domain][name], row['S']))
            total = _sum((row['E'], growth))
            _need(total <= _int(row['A']), 'resident_total_capacity')
            _need(growth <= _headroom(row, scope), 'resident_remaining_headroom')
            bounds[name] = (growth, total)
        result.append(bounds)
    _need(all(scopes == {'attempt', 'owner', 'filesystem', 'campaign'} for scopes in covered.values()),
          'missing_scope', 'needs_admission')
    if len(domains) > 1:
        _aggregate_storage(aggregate, value, request, authority, backing, epoch)
    return tuple(result)


def _aggregate_storage(proof, value, request, authority, backing, epoch):
    _binding(proof.binding, authority['binding'])
    _need(proof.evidence and proof.baseline_id == value['baseline_id'] and
          proof.operation_id == request['operation_id'] and
          proof.operation_digest == request['operation_digest'], 'aggregate_binding', 'needs_admission')
    pairs = dict(proof.domain_backing)
    _need(len(pairs) == len(proof.domain_backing) and pairs == backing and
          len(set(pairs.values())) == len(pairs), 'aggregate_backing_alias', 'needs_admission')
    actual = tuple(sorted((root['role'], root['domain']) for root in value['roots']))
    _need(tuple(sorted(proof.placements)) == actual and len(set(proof.placements)) == len(actual),
          'aggregate_USED_placement_coverage', 'needs_admission')
    covered = set()
    for scope in _sequence(proof.scopes):
        kind = scope['scope']
        _need(kind in ('attempt', 'owner', 'campaign') and kind not in covered and
              scope['epoch'] == epoch and scope['baseline_id'] == value['baseline_id'] and
              scope['scope_id'] and set(scope['views']) == set(_VIEWS),
              'aggregate_scope_binding', 'needs_admission')
        if kind == 'attempt':
            _need(scope['scope_id'] == authority['binding']['attempt_id'] and
                  scope['units'] == 'logical_bytes;physical_bytes;inodes',
                  'aggregate_attempt_identity', 'needs_admission')
        covered.add(kind)
        rows = [row for row in value['scopes'] if row['scope'] == kind]
        _need(len(rows) == len(backing), 'aggregate_domain_coverage', 'needs_admission')
        for name in _VIEWS:
            row = scope['views'][name]
            # No anonymous extra copies: backend's simultaneous E/U/S must equal
            # exact deduplicated USED per-domain accounting at the same baseline.
            for key in ('E', 'U', 'S'):
                _need(_int(row[key]) == _sum(item['views'][name][key] for item in rows),
                      'aggregate_counter_mismatch', 'needs_admission')
            _need(_int(row['P']) == 0, 'descriptor_already_charged')
            pending = _sum(growth[name] for growth in request['storage_growth'].values())
            growth = _sum((row['U'], pending, row['S']))
            if kind == 'attempt' and name in ('logical_bytes', 'physical_bytes'):
                _need(_int(row['A']) <= 128 * 1024 ** 3, 'aggregate_attempt_slot_ceiling')
            _need(_sum((row['E'], growth)) <= _int(row['A']), 'aggregate_total_capacity')
            _need(growth <= _headroom(row, scope), 'aggregate_remaining_headroom')
    _need(covered == {'attempt', 'owner', 'campaign'}, 'aggregate_scope_coverage', 'needs_admission')


def admit_scientific_capacity(facts, request, *, expected, now_ns, verify_authority):
    """Validate authenticated facts; injected verifier is a deployment trust boundary.

    It must return ScienceCapacityFacts authenticated by its actual trusted backend,
    including C1/enforcer evidence. Caller booleans/digests/constructed records alone
    are insufficient. Local identity verifiers are fixture-only. This function does
    not reserve C1 capacity or issue a portable capability/token.
    """
    binding = expected if isinstance(expected, Mapping) else {}
    evidence = facts.evidence if isinstance(facts, ScienceCapacityFacts) else ()
    try:
        _need(callable(verify_authority), 'authority_unavailable', 'needs_admission')
        _need(isinstance(facts, ScienceCapacityFacts), 'invalid_facts', 'needs_admission')
        _binding(facts.binding, expected); _binding(request['binding'], expected); _int(now_ns)
        try:
            verified = verify_authority(facts, expected=expected, now_ns=now_ns)
        except Exception:
            raise _Reject('authority_verification_failed', 'needs_admission') from None
        _need(isinstance(verified, ScienceCapacityFacts), 'authority_unavailable', 'needs_admission')
        _binding(verified.binding, expected); facts = verified; evidence = facts.evidence
        authority = facts.observations['authority']; _binding(authority['binding'], expected)
        _need(authority['evidence'], 'authority_evidence', 'needs_admission')
        _need(authority['estimator_digest'] == request['estimator_digest'],
              'estimator_binding', 'needs_admission')
        max_age = _int(authority['max_age_ns']); stop_lag = _int(authority['stop_lag_ns'])
        _need(max_age > 0 and stop_lag <= max_age, 'authority_lifetime', 'needs_admission')
        cpu = _observation(facts, 'cpu', 'cpu_ids;quota_ticks', expected, now_ns, max_age, stop_lag)
        ram = _observation(facts, 'ram', 'bytes', expected, now_ns, max_age, stop_lag)
        storage = _observation(facts, 'storage', 'logical_bytes;physical_bytes;inodes', expected, now_ns, max_age, stop_lag)
        ids, workers = _cpu(cpu, request, expected['resource_epoch'])
        memory = _ram(ram, request, expected['resource_epoch'])
        bounds = _storage(storage, request, authority, expected['storage_epoch'])
        return ScienceCapacityDecision(ids, workers, memory, bounds, expected, evidence, tuple(authority['evidence']))
    except _Reject as error:
        return ScienceCapacityRefusal(error.status, error.reason, binding, evidence)
    except (KeyError, TypeError, ValueError, OverflowError, AttributeError):
        return ScienceCapacityRefusal('needs_admission', 'missing_or_malformed_fact', binding, evidence)


def _open_metadata(path):
    """No-follow every directory component and the final regular-file leaf."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('absolute canonical metadata path required')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=directory)
            os.close(directory); directory = next_fd
        return os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                       dir_fd=directory)
    finally:
        os.close(directory)


def _metadata_link(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('absolute canonical metadata link required')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=directory)
            os.close(directory); directory = next_fd
        return os.readlink(path.name, dir_fd=directory).encode()
    finally:
        os.close(directory)


def _namespace_metadata(path, pid, name):
    # Namespace pseudo-files are metadata targets, not readable regular files.
    _need(str(path) == '/proc/' + str(pid) + '/ns/' + name,
          'namespace_path_binding', 'needs_admission')
    descriptor = os.open('/proc/' + str(pid) + '/ns',
                         os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.stat(name, dir_fd=descriptor)
        return (str(info.st_dev) + ':' + str(info.st_ino)).encode()
    finally:
        os.close(descriptor)


def _collector_input_binding(expected, paths, job):
    """Validate admitted identities and canonical live sources before any capture."""
    binding = expected['binding']; _binding(binding, binding)
    slurm = expected['slurm']; job.expected_job(slurm)
    _need(slurm['job_id'] == binding['job_id'] and type(slurm['owner_uid']) is int and
          slurm['owner_uid'] == binding['owner_uid'] and slurm['identity'] == {
              'machine_id': binding['machine_id'], 'boot_id': binding['boot_id']},
          'collector_slurm_binding', 'needs_admission')
    listing = expected['slurm_listpids']; rows = _sequence(listing['rows'])
    _need(type(listing['rc']) is int and listing['rc'] == 0 and len(rows) <= 256 and
          len({row['pid'] for row in rows}) == len(rows),
          'collector_process_coverage', 'needs_admission')
    required = set()
    for row in rows:
        pid = _int(row['pid']); _need(pid > 0, 'collector_PID', 'needs_admission')
        _need(row['job_id'] == binding['job_id'] and type(row['step_id']) is str and
              re.fullmatch(r'[A-Za-z0-9_-]+', row['step_id']) is not None and
              (pid != binding['pid'] or row['step_id'] == binding['step_id']),
              'collector_listed_job_step', 'needs_admission')
        prefix = '' if pid == binding['pid'] and 'stat' in paths else 'pid.' + str(pid) + '.'
        for field in ('stat', 'status', 'cgroup', 'exe'):
            role = prefix + field; required.add(role)
            _need(str(paths[role]) == '/proc/' + str(pid) + '/' + field,
                  'collector_process_path_binding', 'needs_admission')
    _need(any(row['pid'] == binding['pid'] for row in rows),
          'collector_bound_PID_missing', 'needs_admission')
    fixed = {'machine_id': '/etc/machine-id', 'boot_id': '/proc/sys/kernel/random/boot_id',
             'mount_namespace': '/proc/' + str(binding['pid']) + '/ns/mnt',
             'cgroup_namespace': '/proc/' + str(binding['pid']) + '/ns/cgroup'}
    for role, path in fixed.items():
        _need(str(paths[role]) == path, 'collector_host_identity_path', 'needs_admission')
    required.update(fixed)
    kernel = {'memory.max', 'memory.high', 'memory.current', 'memory.peak',
              'memory.events', 'memory.swap.max', 'cpu.max', 'cpuset.cpus.effective'}
    for role in set(paths) - required:
        path = str(paths[role]); parsed = Path(path)
        _need((parsed.name in kernel and path.startswith('/sys/fs/cgroup/') and
               '..' not in parsed.parts and str(parsed) == path) or
              path == '/proc/' + str(binding['pid']) + '/mountinfo',
              'collector_unbound_extra_path', 'needs_admission')


def collect_job_capacity(expected, paths, budget):
    """Read only explicit metadata files; retain raw in memory before interpretation.

    No commands, autodiscovery, environment reads, quota changes or authority fallback.
    Caller supplies the already admitted Slurm listing/expected identity. The collector
    uses existing slurm_job_evidence validation; a collection never authenticates itself.
    Time checks bound progress at syscall boundaries; callers must apply an external
    wall limit for a filesystem whose kernel I/O may block. No hard I/O-latency or
    authority guarantee is inferred from O_NONBLOCK on a regular file.
    """
    binding = expected.get('binding', {}) if isinstance(expected, Mapping) else {}
    evidence = []; used = 0; start = time.monotonic(); values = {}
    allowed = {'stat', 'status', 'cgroup', 'exe', 'machine_id', 'machine-id', 'boot_id', 'mountinfo',
               'memory.max', 'memory.high', 'memory.current', 'memory.peak',
               'memory.events', 'memory.swap.max', 'cpu.max', 'cpuset.cpus.effective'}
    try:
        maximum = _int(budget['max_bytes']); entries = _int(budget['max_entries'])
        seconds = budget['max_seconds']
        _need(0 < maximum <= 8 * 1024 * 1024 and 0 < entries <= 1024 and type(seconds) in (int, float) and
              0 < seconds <= 60 and seconds == seconds, 'collector_budget', 'needs_admission')
        _need(isinstance(paths, Mapping) and 0 < len(paths) <= entries and
              all(Path(path).name in allowed or name in ('mount_namespace', 'cgroup_namespace')
                  for name, path in paths.items()),
              'collector_paths', 'needs_admission')
        spec = importlib.util.spec_from_file_location('_science_slurm_identity',
                                                       Path(__file__).with_name('slurm_job_evidence.py'))
        job = importlib.util.module_from_spec(spec); spec.loader.exec_module(job)
        _collector_input_binding(expected, paths, job)
        ordered = sorted(paths.items(), key=lambda pair: (pair[0] not in
                         ('machine_id', 'boot_id', 'mount_namespace', 'cgroup_namespace'), pair[0]))
        for name, path in ordered:
            _need(time.monotonic() - start <= seconds, 'collector_deadline', 'needs_admission')
            if name in ('mount_namespace', 'cgroup_namespace'):
                kind = 'mnt' if name == 'mount_namespace' else 'cgroup'
                raw = _namespace_metadata(path, binding['pid'], kind)
                retained = raw[:maximum - used]
                evidence.append({'path': str(path), 'name': name, 'raw': retained,
                                 'bytes': len(retained), 'sha256': hashlib.sha256(retained).hexdigest()})
                used += len(retained)
                _need(len(raw) == len(retained), 'collector_byte_cap', 'needs_admission')
                values[name] = raw
                continue
            if Path(path).name == 'exe':
                raw = _metadata_link(path)
                retained = raw[:maximum - used]
                evidence.append({'path': str(path), 'name': name, 'raw': retained,
                                 'bytes': len(retained), 'sha256': hashlib.sha256(retained).hexdigest()})
                used += len(retained)
                _need(len(raw) == len(retained), 'collector_byte_cap', 'needs_admission')
                values[name] = raw
                continue
            fd = _open_metadata(path)
            with os.fdopen(fd, 'rb') as stream:
                before = os.fstat(stream.fileno())
                _need(stat.S_ISREG(before.st_mode) and before.st_size <= maximum - used,
                      'collector_regular_or_size', 'needs_admission')
                raw = stream.read(maximum - used + 1)
                retained = raw[:maximum - used]
                ref = {'path': str(path), 'name': name, 'raw': retained,
                       'bytes': len(retained), 'sha256': hashlib.sha256(retained).hexdigest()}
                evidence.append(ref); used += len(retained)
                _need(len(raw) == len(retained), 'collector_byte_cap', 'needs_admission')
                after = os.fstat(stream.fileno())
                _need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                      (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                      'collector_file_changed', 'needs_admission')
                values[name] = raw
            _need(time.monotonic() - start <= seconds, 'collector_deadline', 'needs_admission')
        # Reuse owning identity checks without invoking its command collector or CLI.
        # Capacity collection never validates a caller-supplied process snapshot in
        # place of the raw bytes just read. Expected listing is an external input;
        # captured process identity and PID reuse are checked here independently.
        listing = expected['slurm_listpids']
        rows = _sequence(listing['rows'])
        _need(len(rows) <= 256 and len({row['pid'] for row in rows}) == len(rows),
              'collector_process_coverage', 'needs_admission')
        _need(entries >= len(paths) + len(rows) + 4,
              'collector_identity_reread_entry', 'needs_admission')
        after = {}
        stat_names = []
        for row in rows:
            pid = _int(row['pid']); _need(pid > 0, 'collector_PID', 'needs_admission')
            prefix = '' if pid == binding['pid'] and 'stat' in values else 'pid.' + str(pid) + '.'
            stat_names.append(prefix + 'stat')
        for name in tuple(stat_names) + ('machine_id', 'boot_id', 'mount_namespace', 'cgroup_namespace'):
            _need(time.monotonic() - start <= seconds, 'collector_deadline', 'needs_admission')
            if name in ('mount_namespace', 'cgroup_namespace'):
                kind = 'mnt' if name == 'mount_namespace' else 'cgroup'
                again = _namespace_metadata(paths[name], binding['pid'], kind)
            else:
                fd = _open_metadata(paths[name])
                with os.fdopen(fd, 'rb') as stream:
                    _need(stat.S_ISREG(os.fstat(stream.fileno()).st_mode),
                          'collector_reread_regular', 'needs_admission')
                    again = stream.read(maximum - used + 1)
            retained = again[:maximum - used]
            evidence.append({'path': str(paths[name]), 'name': name + '_after', 'raw': retained,
                             'bytes': len(retained), 'sha256': hashlib.sha256(retained).hexdigest()})
            used += len(retained)
            _need(len(again) == len(retained), 'collector_byte_cap', 'needs_admission')
            after[name] = again
        identity = {'machine_id': values['machine_id'].decode().strip(),
                    'boot_id': values['boot_id'].decode().strip()}
        identity_after = {'machine_id': after['machine_id'].decode().strip(),
                          'boot_id': after['boot_id'].decode().strip()}
        for name in ('mount_namespace', 'cgroup_namespace'):
            _need(values[name] == after[name] and int(values[name].decode().split(':')[1]) == binding[name],
                  'collector_namespace_changed', 'needs_admission')
        processes = []
        for row, stat_name in zip(rows, stat_names):
            pid = row['pid']; prefix = stat_name[:-4]
            ticks = int(values[stat_name].decode().rpartition(') ')[2].split()[19])
            later = int(after[stat_name].decode().rpartition(') ')[2].split()[19])
            _need(int(values[stat_name].partition(b' ')[0]) == pid and
                  int(after[stat_name].partition(b' ')[0]) == pid and
                  ticks == later and ticks > 0 and
                  (pid != binding['pid'] or ticks == binding['start_ticks']),
                  'collector_PID_reuse', 'needs_admission')
            uids = list(map(int, next(line for line in values[prefix + 'status'].decode().splitlines()
                                     if line.startswith('Uid:')).split()[1:]))
            status_pid = int(next(line for line in values[prefix + 'status'].decode().splitlines()
                                  if line.startswith('Pid:')).split()[1])
            _need(status_pid == pid, 'collector_status_PID', 'needs_admission')
            groups = values[prefix + 'cgroup'].decode().splitlines()
            _need(len(groups) == 1 and groups[0].startswith('0::/'),
                  'collector_cgroup', 'needs_admission')
            processes.append({'pid': pid, 'start_ticks': ticks, 'uids': uids,
                              'exe': values[prefix + 'exe'].decode(),
                              'cgroup': groups[0][3:], 'error': None})
        _need(any(process['pid'] == binding['pid'] for process in processes),
              'collector_bound_PID_missing', 'needs_admission')
        snapshot = {'identity_before': identity, 'identity_after': identity_after,
                    'listpids': listing, 'processes': processes}
        membership = job.classify_before(snapshot, expected['slurm'])
        _need(time.monotonic() - start <= seconds, 'collector_deadline', 'needs_admission')
        _binding(binding, binding)
        return ScienceCapacityFacts(binding, {'collected_raw': values, 'job_membership': membership,
            'collection': {'status': 'observed_metadata_only', 'coverage': 'explicit_visible_paths',
                           'bytes': used, 'files_and_identity_rereads': len(paths) + len(rows) + 4,
                           'elapsed_seconds': time.monotonic() - start,
                           'hard_IO_wall_bound': None, 'authority_status': 'unverified'},
            'authority': None}, tuple(evidence))
    except _Reject as error:
        return ScienceCapacityRefusal(error.status, error.reason, binding, tuple(evidence))
    except (OSError, KeyError, TypeError, ValueError, OverflowError, AttributeError, IndexError, StopIteration):
        return ScienceCapacityRefusal('needs_admission', 'partial_capacity_collection', binding, tuple(evidence))
