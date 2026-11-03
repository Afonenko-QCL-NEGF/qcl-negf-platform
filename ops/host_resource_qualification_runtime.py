"""Protected idle-only calibration readers. No submit, resize, readiness or fence close.

Root stages an explicit finite exploratory scope. Its K/headroom scope is an
independently reviewed input, not a theorem inferred here from G-T or balloon
counters. A Python object or a job-provided report never supplies authority.
"""
from dataclasses import asdict
import hashlib
import json
import os
import uuid

from host_resource_operations import (ResourceError, RuntimeBinding, VMReadback,
    ResidentGrant, integer, policy_digest, require, validate_host_grants)
from host_resource_backends import fingerprint, read_root_qualification_report
from host_resource_qualification import (NativeQualificationService,
    check_baseline, decode_plan, decode_case, CalibrationEffectOwner, operation_id, _exists, _raw, FIELDS)
from host_resource_qualification_observations import (CalibrationObservation, REPORT_SCHEMA,
    REQUIRED_CASES, build_qualification_report, context, decode_permit, plain,
    qualification_candidate, validate_accounting, MissingEvidence)

ACTIVATION_SCHEMA = 'qcl.host-resource-calibration-idle-runtime.v1'
ACTIVATION_NAME = 'idle-runtime.json'
REPORT_LIMIT = 8 * 1024**2


def _exact(value, keys):
    require(type(value) is dict and set(value) == set(keys), 'calibration_runtime', 'exact protected idle fields required')


def _sha(value):
    require(type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value),
            'calibration_runtime', 'explicit SHA256 required')


def decode_activation(value):
    _exact(value, {'schema', 'operation_id', 'plan_sha256', 'bootstrap_report_sha256', 'planned_targets', 'scope_sha256'})
    require(value['schema'] == ACTIVATION_SCHEMA, 'calibration_runtime', 'private idle activation required')
    operation_id(value['operation_id'])
    for key in ('plan_sha256', 'bootstrap_report_sha256', 'scope_sha256'):
        _sha(value[key])
    targets = value['planned_targets']
    require(type(targets) is list and 0 < len(targets) <= 3 and
            all(type(n) is int and 0 < n < 2**63 for n in targets) and targets == sorted(set(targets)),
            'calibration_runtime', 'finite distinct exploratory targets required')
    return value


def _canonical(document):
    return json.dumps(document, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _original_context(service, plan, vm):
    policy = service.controller.policy
    return dict(host_id=policy.host_id, owner_id=policy.owner_id, host_boot_id=plan['host_boot_id'],
        policy_sha256=policy_digest(policy), source_graph_sha256=plan['source_graph_sha256'],
        qualification_ref=policy.active_grant.qualification_ref, baseline_state_sha256=plan['baseline_state_sha256'],
        worker_machine_id=service.provider.config['enrollment'][vm.vm_id]['machine_id'],
        # Idle has no completed_final/output-owner claim. The context remains
        # explicitly unsuitable for jobs or positive workload qualification.
        output_owner={}, binding=plan['bindings'][vm.vm_id], native_minimum_bytes=vm.minimum_bytes,
        native_maximum_bytes=vm.maximum_bytes, quantum_bytes=service.provider.native_proofs.backend.quantum_bytes,
        paid_grant_bytes=vm.maximum_bytes)


def capture_idle_maximum(service, op, sequence):
    """Actual read-only first observation, before activation/R/K can exist.

    This does not authorize a lower target, accept a K bound, or write a fence.
    Existing provider and native Source owners perform all probes/qualification.
    """
    integer(sequence, 'sequence', 1)
    proofs = getattr(service.provider, 'native_proofs', None)
    require(proofs is not None, 'calibration_runtime', 'actual C source owner required')
    parent = NativeQualificationService(service.controller.policy, service.controller.store, proofs, operation_id=op)
    with parent.store.locked(read_only=True):
        plan = parent.repository.plan(op); state = parent._state()
        check_baseline(parent.policy, parent.store, plan, state)
        validate_host_grants(parent.policy, [ResidentGrant(**g) for g in state['grants']])
        require(not _exists(parent.repository.folder(op) / 'jobs'), 'calibration_jobs_unsupported', 'idle capture refuses child namespace')
        if _exists(parent.repository.directory / 'active.json'):
            parent.repository.active(op, plan)
        require(not parent._catalog(plan, state), 'calibration_pending', 'first maximum capture cannot adopt pending effect')
        selected = {row['vm_id'] for row in plan['cases'].values()}
        require(len(selected) == 1, 'calibration_runtime', 'one actual idle VM context required')
        result = None
        for vm in parent.policy.vms:
            ctx = _original_context(service, plan, vm); context(ctx)
            read, guest, original = service.provider._calibration_pair(ctx)
            NativeCalibrationRuntime._idle(guest, ctx)
            require(read.running is True and read.assigned_bytes == read.configured_bytes == vm.maximum_bytes,
                    'readback', 'actual maximum required before bootstrap')
            require(original['host']['boot_id'] == plan['host_boot_id'] and
                    original['host']['MemTotal'] == parent.policy.physical_ram_bytes and
                    type(original['host']['MemAvailable']) is int and original['host']['MemAvailable'] >= parent.policy.reserves.safety_bytes,
                    'host_pressure', 'current whole-host safety required before bootstrap')
            proofs.profile(RuntimeBinding(**ctx['binding']), plan['host_boot_id'])
            if vm.vm_id in selected:
                result = CalibrationObservation(ctx, sequence, asdict(read), guest['memory']['MemTotal'],
                    guest['memory']['MemAvailable'], guest.get('slurm_memory_bytes'), guest.get('slurm_registered'),
                    (), None, None, None, None, fingerprint(original), guest.get('calibration_accounting'), original)
            require(proofs.backend.readback(vm.vm_id) == read, 'identity_mismatch', 'maximum changed during bootstrap capture')
        check_baseline(parent.policy, parent.store, plan, parent._state())
        require(parent.repository.plan(op) == plan, 'calibration_runtime', 'bootstrap plan changed')
        return result


def build_idle_bootstrap_report(observations, *, safety_allowance_bytes, native_gap_bound_bytes, scope):
    """Pure incomplete report, never a positive measured-capacity profile.

    The explicit K and applicability/headroom are Root's separately evidenced
    scoped inputs; this function does not infer or authenticate them. Root must
    review that scope before staging activation. Missing inputs fail closed.
    """
    require(type(observations) in (tuple, list) and 0 < len(observations) <= 64,
            'calibration_scope', 'finite actual idle observations required')
    integer(safety_allowance_bytes, 'safety_allowance_bytes')
    integer(native_gap_bound_bytes, 'native_gap_bound_bytes')
    require(type(scope) is str and 0 < len(scope.encode()) <= 65536, 'calibration_scope', 'explicit independently evidenced scope required')
    ctx = plain(observations[0].context); context(ctx)
    require(type(ctx['output_owner']) is dict and ctx['output_owner'] == {},
            'calibration_runtime', 'idle bootstrap cannot carry output/final ownership')
    os_samples = []; mapping = []; maximum = []
    for o in observations:
        require(type(o) is CalibrationObservation and plain(o.context) == ctx and not o.jobs and o.source_records is not None,
                'calibration_scope', 'original actual idle primary records required')
        a = plain(validate_accounting(o.accounting, ctx))
        require(a['jobs'] == {}, 'calibration_jobs_unsupported', 'idle scope cannot contain cgroups')
        os_samples.append(dict(observed_os_bytes=a['os_upper_bound_bytes'], evidence_sha256=fingerprint(a), accounting=a))
        mapping.append(dict(assigned_bytes=o.readback['assigned_bytes'], configured_bytes=o.readback['configured_bytes'],
            total_bytes=o.total_bytes, available_bytes=o.available_bytes, evidence_sha256=o.evidence_sha256))
        if o.readback['assigned_bytes'] == o.readback['configured_bytes'] == ctx['native_maximum_bytes']:
            maximum.append(o.total_bytes)
    require(maximum and len(set(maximum)) == 1, 'calibration_scope', 'actual maximum guest total required')
    peak = max(row['observed_os_bytes'] for row in os_samples)
    fragment = dict(measurement=dict(state='measured', scope=scope, evidence_sha256=fingerprint(os_samples),
        mapping_evidence_sha256=fingerprint(mapping), observed_os_bytes=peak, safety_allowance_bytes=safety_allowance_bytes,
        os_reserve_bytes=peak+safety_allowance_bytes, native_gap_bound_bytes=native_gap_bound_bytes,
        maximum_guest_total_bytes=maximum[0], native_maximum_bytes=ctx['native_maximum_bytes']),
        os_samples=os_samples, mapping_samples=mapping)
    permit = dict(schema='qcl.host-resource-calibration-evidence-permit.v1', context=ctx, authorized_demands={}, capacity_measurement=fragment)
    report = build_qualification_report(permit, {'idle-grow': tuple(observations)})
    require(qualification_candidate(report) is None, 'calibration_runtime', 'idle report cannot qualify workloads')
    return report


def write_report_exclusive(parent, report):
    """Purpose-bound eight-MiB writer; ordinary metadata/RPC limits stay intact.

    Existing partial/corrupt originals are never overwritten or truncated.
    A report cannot be read back through CalibrationRepository's one-MiB reader.
    """
    _exact(report, {'schema', 'permit', 'cases', 'native_recovery_limit'})
    require(report['schema'] == REPORT_SCHEMA and set(report['cases']) == set(REQUIRED_CASES),
            'shape', 'complete finite calibration report required')
    decode_permit(report['permit'])
    raw = _canonical(report)
    require(len(raw) <= REPORT_LIMIT, 'output_bound', 'report exceeds eight-MiB producer bound')
    # This idle owner never promotes a candidate or accepts a positive report.
    require(qualification_candidate(report) is None, 'calibration_runtime', 'idle runtime cannot publish qualification')
    digest = hashlib.sha256(raw).hexdigest()
    repo = parent.repository
    for ancestor in (parent.store.directory, repo.directory, repo.folder(parent.operation)):
        parent.store._check_path(ancestor, directory=True)
    directory = repo.folder(parent.operation) / 'reports'
    directory.mkdir(mode=0o700, exist_ok=True)
    parent.store._check_path(directory, directory=True)
    parent.store._sync_directory(directory.parent)
    path = directory / (digest + '.json')
    if _exists(path):
        require(read_root_qualification_report(path) == report, 'calibration_runtime', 'original report conflicts')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            parent.store._check_fd(fd)
            held = os.fstat(fd)
            os.fsync(fd)
            named = path.lstat()
            require(all(getattr(held, k) == getattr(named, k) for k in FIELDS), 'trust', 'original report identity changed')
        finally:
            os.close(fd)
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            parent.store._check_fd(fd)
            view = memoryview(raw)
            while view:
                count = os.write(fd, view[:65536])
                require(count > 0, 'state', 'short protected report write')
                view = view[count:]
            os.fsync(fd)
            held, named = os.fstat(fd), path.lstat()
            require(held.st_size == len(raw) and all(getattr(held, k) == getattr(named, k) for k in FIELDS),
                    'trust', 'report changed during publication')
        finally:
            os.close(fd)
    for ancestor in (directory, directory.parent, repo.directory, parent.store.directory):
        parent.store._check_path(ancestor, directory=True)
        parent.store._sync_directory(ancestor)
    require(read_root_qualification_report(path) == report, 'trust', 'complete original report readback differs')
    return dict(path=str(path), sha256=digest, bytes=len(raw))


def open_native_runtime(service):
    """Reconstruct from the same fixed protected files in parent and claim child."""
    store = service.controller.store
    path = store.directory / 'native-qualification' / ACTIVATION_NAME
    if not _exists(path):
        return None
    store._check_path(path.parent, directory=True)
    activation = decode_activation(json.loads(_raw(store, path), object_pairs_hook=_unique_pairs))
    return NativeCalibrationRuntime(service, activation)


def _unique_pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'shape', 'duplicate protected idle key')
        result[key] = value
    return result


class NativeCalibrationRuntime:
    """Actual idle guard and bounded observation producer, without effect authority.

    planned_targets are exploratory Root-authorized geometry; they are not
    production supported_targets. Scope acceptance is a separate Root gate.
    """
    def __init__(self, service, activation):
        self.service, self.provider = service, service.provider
        self.policy, self.store = service.controller.policy, service.controller.store
        self.proofs = getattr(self.provider, 'native_proofs', None)
        require(self.proofs is not None and self.proofs.store is self.store and self.proofs.policy == self.policy and
                self.provider.policy == self.policy, 'calibration_runtime', 'same installed actual C/facts owner required')
        self.activation = decode_activation(activation)
        self.parent = NativeQualificationService(self.policy, self.store, self.proofs, operation_id=activation['operation_id'])
        self.repository = self.parent.repository
        self.plan, self.bootstrap_report, self.permit = self._load()
        self.ctx = self.permit['context']
        self.scope = self._scope()

    def _load(self):
        current = decode_activation(self.repository.read(self.repository.directory / ACTIVATION_NAME))
        require(current == self.activation, 'calibration_runtime', 'original activation changed')
        path = self.repository.folder(self.parent.operation) / 'plan.json'
        plan = decode_plan(self.repository.read(path))
        require(self.repository.digest(path) == current['plan_sha256'], 'calibration_runtime', 'original plan pin differs')
        report = read_root_qualification_report(self.repository.folder(self.parent.operation) / 'reports' /
                                                (current['bootstrap_report_sha256'] + '.json'))
        require(fingerprint(report) == current['bootstrap_report_sha256'] and qualification_candidate(report) is None,
                'calibration_runtime', 'actual preliminary report pin differs or is positive')
        _exact(report, {'schema', 'permit', 'cases', 'native_recovery_limit'})
        require(report['schema'] == REPORT_SCHEMA and set(report['cases']) == set(REQUIRED_CASES),
                'calibration_runtime', 'complete preliminary report required')
        permit = decode_permit(report['permit']); ctx = context(permit['context'])
        require(permit['authorized_demands'] == {} and type(ctx['output_owner']) is dict and ctx['output_owner'] == {} and
                fingerprint(permit['capacity_measurement']) == current['scope_sha256'],
                'calibration_runtime', 'idle-only exact scoped raw measurement required')
        vm = ctx['binding']['vm_id']
        require(vm in plan['bindings'] and ctx['binding'] == plan['bindings'][vm] and
                all(ctx[k] == plan[k] for k in ('host_id', 'owner_id', 'host_boot_id', 'policy_sha256',
                    'source_graph_sha256', 'baseline_state_sha256')) and
                all(row['vm_id'] == vm for row in plan['cases'].values()) and
                current['planned_targets'] == sorted({row['target_bytes'] for row in plan['cases'].values()}),
                'calibration_runtime', 'original single-VM plan/context/targets differ')
        require(ctx['qualification_ref'] == self.policy.active_grant.qualification_ref,
                'calibration_runtime', 'original policy qualification reference differs')
        policy_vm = next(v for v in self.policy.vms if v.vm_id == vm)
        require(ctx['native_minimum_bytes'] == policy_vm.minimum_bytes and
                ctx['native_maximum_bytes'] == ctx['paid_grant_bytes'] == policy_vm.maximum_bytes and
                ctx['quantum_bytes'] == self.proofs.backend.quantum_bytes and
                ctx['worker_machine_id'] == self.provider.config['enrollment'][vm]['machine_id'],
                'calibration_runtime', 'retained scope differs from actual policy/enrollment')
        return plan, report, permit

    def _scope(self):
        fragment = self.permit['capacity_measurement']
        _exact(fragment, {'measurement', 'os_samples', 'mapping_samples'})
        m = fragment['measurement']
        _exact(m, {'state', 'scope', 'evidence_sha256', 'mapping_evidence_sha256', 'observed_os_bytes',
            'safety_allowance_bytes', 'os_reserve_bytes', 'native_gap_bound_bytes', 'maximum_guest_total_bytes', 'native_maximum_bytes'})
        require(m['state'] == 'measured' and type(m['scope']) is str and 0 < len(m['scope'].encode()) <= 65536,
                'calibration_scope', 'independently reviewed explicit actual scope required')
        for key in ('observed_os_bytes', 'safety_allowance_bytes', 'os_reserve_bytes', 'native_gap_bound_bytes',
                    'maximum_guest_total_bytes', 'native_maximum_bytes'):
            integer(m[key], key, 0 if key in {'safety_allowance_bytes', 'native_gap_bound_bytes'} else 1)
        require(m['native_maximum_bytes'] == self.ctx['native_maximum_bytes'] and
                m['observed_os_bytes'] + m['safety_allowance_bytes'] == m['os_reserve_bytes'] and
                self.ctx['native_minimum_bytes'] >= m['os_reserve_bytes'] + m['native_gap_bound_bytes'],
                'calibration_scope', 'actual conservative reserve/gap do not fit original native floor')
        rows = []
        for case in self.bootstrap_report['cases'].values():
            for raw in case['original_evidence']:
                o = CalibrationObservation(**raw)
                require(plain(o.context) == self.ctx and not o.jobs and o.source_records is not None,
                        'calibration_scope', 'actual idle primary Source observations required')
                source = plain(o.source_records)
                b = self.ctx['binding']
                require(o.readback['vm_id'] == b['vm_id'] and o.readback['native_id'] == b['native_id'] and
                        o.readback['process_id'] == b['process_id'] and o.readback['config_fingerprint'] == b['config_fingerprint'] and
                        o.readback['running'] is True, 'calibration_scope', 'original primary native binding differs')
                require(fingerprint(source) == o.evidence_sha256 and source['native_before'] == source['native_after'] == plain(o.readback) and
                        source['guest']['calibration_accounting'] == plain(o.accounting) and
                        source['guest']['identity_before'] == source['guest']['identity_after'] == plain(o.accounting)['identity'] and
                        source['guest']['memory'] == dict(MemTotal=o.total_bytes, MemAvailable=o.available_bytes),
                        'calibration_scope', 'original actual primary pair/source digest differs')
                self._idle(source['guest'], self.ctx)
                # Every retained primary constrains the accepted scope. A
                # smaller mapping/os subset cannot hide an observed failure.
                r = plain(o.readback)
                _exact(r, VMReadback.__dataclass_fields__)
                for key in ('assigned_bytes', 'configured_bytes'):
                    integer(r[key], key, 1)
                integer(o.total_bytes, 'actual primary total', 1)
                integer(o.available_bytes, 'actual primary available')
                a = plain(o.accounting)
                require(r['assigned_bytes'] == r['configured_bytes'] and
                        self.ctx['native_minimum_bytes'] <= r['assigned_bytes'] <= self.ctx['native_maximum_bytes'] and
                        o.total_bytes == a['meminfo_bytes']['MemTotal'] == a['meminfo_after_bytes']['MemTotal'] and
                        m['os_reserve_bytes'] <= o.total_bytes <= m['maximum_guest_total_bytes'] and
                        m['safety_allowance_bytes'] <= o.available_bytes <= o.total_bytes and
                        a['os_upper_bound_bytes'] <= m['observed_os_bytes'] and
                        max(0, r['assigned_bytes'] - o.total_bytes) <= m['native_gap_bound_bytes'] and
                        (r['assigned_bytes'] != self.ctx['native_maximum_bytes'] or o.total_bytes == m['maximum_guest_total_bytes']),
                        'calibration_scope', 'retained primary contradicts accepted native/physical/reserve scope')
                rows.append(o)
        require(rows and type(fragment['os_samples']) is list and 0 < len(fragment['os_samples']) <= 64 and
                type(fragment['mapping_samples']) is list and 0 < len(fragment['mapping_samples']) <= 64,
                'calibration_scope', 'finite retained actual accounting/mapping samples required')
        observed = []
        for row in fragment['os_samples']:
            _exact(row, {'observed_os_bytes', 'evidence_sha256', 'accounting'})
            a = validate_accounting(row['accounting'], self.ctx)
            require(row['observed_os_bytes'] == a['os_upper_bound_bytes'] and row['evidence_sha256'] == fingerprint(a) and
                    any(plain(o.accounting) == a for o in rows), 'calibration_scope', 'unjoined raw OS accounting')
            observed.append(row['observed_os_bytes'])
        maximum = []
        for row in fragment['mapping_samples']:
            _exact(row, {'assigned_bytes', 'configured_bytes', 'total_bytes', 'available_bytes', 'evidence_sha256'})
            matches = [o for o in rows if row == dict(assigned_bytes=o.readback['assigned_bytes'],
                configured_bytes=o.readback['configured_bytes'], total_bytes=o.total_bytes,
                available_bytes=o.available_bytes, evidence_sha256=o.evidence_sha256)]
            require(matches and row['assigned_bytes'] == row['configured_bytes'] and
                    max(0, row['assigned_bytes'] - row['total_bytes']) <= m['native_gap_bound_bytes'],
                    'calibration_scope', 'unjoined actual native/guest scope')
            if row['assigned_bytes'] == self.ctx['native_maximum_bytes']:
                maximum.append(row['total_bytes'])
        require(max(observed) == m['observed_os_bytes'] and m['evidence_sha256'] == fingerprint(fragment['os_samples']) and
                m['mapping_evidence_sha256'] == fingerprint(fragment['mapping_samples']) and maximum and
                set(maximum) == {m['maximum_guest_total_bytes']} and 0 < m['maximum_guest_total_bytes'] <= m['native_maximum_bytes'],
                'calibration_scope', 'actual maximum/reserve pins differ')
        return m

    @staticmethod
    def _idle(guest, ctx):
        require(guest['jobs'] == {} and guest['groups'] == {} and guest['calibration_accounting']['jobs'] == {},
                'calibration_jobs_unsupported', 'idle slice refuses every actual or authorized job')
        validate_accounting(guest['calibration_accounting'], ctx)

    def _context(self, vm):
        ctx = dict(self.ctx, binding=self.plan['bindings'][vm.vm_id], native_minimum_bytes=vm.minimum_bytes,
                   native_maximum_bytes=vm.maximum_bytes, paid_grant_bytes=vm.maximum_bytes,
                   worker_machine_id=self.provider.config['enrollment'][vm.vm_id]['machine_id'])
        context(ctx)
        return ctx

    @staticmethod
    def _idle_binding(guest):
        # Source census is independent of whether raw physical accounting is
        # complete/valid. Missing actual census is never replaced by empty rows.
        require(type(guest['jobs']) is dict and guest['jobs'] == {} and
                type(guest['groups']) is dict and guest['groups'] == {},
                'calibration_jobs_unsupported', 'idle settlement refuses actual jobs/groups')
        accounting = guest.get('calibration_accounting')
        if type(accounting) is dict and 'jobs' in accounting:
            require(type(accounting['jobs']) is dict and accounting['jobs'] == {},
                    'calibration_jobs_unsupported', 'idle settlement refuses actual cgroups')

    def _pending_case(self, plan, state, before, target, case_name):
        require(type(before) is VMReadback and type(target) is int,
                'calibration_runtime', 'typed original before and target required')
        require(type(case_name) is str and case_name in plan['cases'] and
                plan['cases'][case_name] == dict(vm_id=before.vm_id, target_bytes=target),
                'calibration_runtime', 'exact protected case purpose/target required')
        pending = self.parent._catalog(plan, state)
        marker = self.repository.case_path(self.parent.operation, case_name)
        if not _exists(marker):
            require(not pending, 'calibration_pending', 'prepare requires no unresolved original effect')
            return
        row = decode_case(self.repository.read(marker), self.parent.operation, case_name)
        mid = row['mutation_id']
        require(mid is not None and pending == [mid], 'calibration_pending', 'claim requires exactly its original pending effect')
        owner = self.proofs.owner_for(mid)
        require(type(owner) is CalibrationEffectOwner and owner.operation == self.parent.operation and
                owner.record['case'] == case_name, 'effect_owner', 'same protected case owner required')
        effect = owner.effect(state, mid)
        require(effect.vm_id == before.vm_id and effect.old_bytes == before.assigned_bytes == before.configured_bytes and
                effect.target_bytes == target and effect.before_revision == before.revision,
                'identity_mismatch', 'original dispatch before/revision differs')

    def _confirmed_lower(self, state, before):
        matches = []
        for case_name in self.plan['cases']:
            path = self.repository.case_path(self.parent.operation, case_name)
            if not _exists(path):
                continue
            row = decode_case(self.repository.read(path), self.parent.operation, case_name)
            mid = row['mutation_id']
            if mid is None or not _exists(self.repository.readback_path(self.parent.operation, mid)):
                continue
            confirmed = self.parent._confirmed(mid, state)
            if confirmed['readback'] == asdict(before):
                owner = self.proofs.owner_for(mid); effect = owner.effect(state, mid)
                if effect.target_bytes == before.assigned_bytes:
                    matches.append(mid)
        require(len(matches) == 1, 'calibration_restore', 'one genuine original confirmed lower before required')

    def _observe(self, plan, state, before, target, originals, *, physical=True, host_safety=True, binding_only=False):
        require(self._load() == (self.plan, self.bootstrap_report, self.permit) and plan == self.plan,
                'calibration_runtime', 'original runtime/plan changed')
        check_baseline(self.policy, self.store, plan, state)
        validate_host_grants(self.policy, [ResidentGrant(**g) for g in state['grants']])
        if _exists(self.repository.directory / 'active.json'):
            self.repository.active(self.parent.operation, plan)
        require(not _exists(self.repository.folder(self.parent.operation) / 'jobs'),
                'calibration_jobs_unsupported', 'any child authorization namespace is unsupported')
        require(type(before) is VMReadback and before.vm_id == self.ctx['binding']['vm_id'] and
                type(target) is int and target in self.activation['planned_targets'],
                'calibration_runtime', 'exact original exploratory target required')
        for vm in self.policy.vms:
            ctx = self._context(vm)
            reader = self.provider._calibration_binding_pair if binding_only else self.provider._calibration_pair
            try:
                read, guest, source = reader(ctx)
            except ResourceError as error:
                failed = getattr(error, 'calibration_pair', None)
                if failed is not None:
                    originals.append((ctx, *failed))
                raise
            originals.append((ctx, read, guest, source))
            self._idle_binding(guest)
            if not binding_only:
                self._idle(guest, ctx)
            require(source['host']['boot_id'] == plan['host_boot_id'] and
                    source['host']['MemTotal'] == self.policy.physical_ram_bytes,
                    'identity_mismatch', 'current whole-host identity/capacity changed')
            if host_safety:
                require(type(source['host']['MemAvailable']) is int and
                        source['host']['MemAvailable'] >= self.policy.reserves.safety_bytes,
                        'host_pressure', 'current whole-host safety reserve required')
            require(read.running is True and read.assigned_bytes == read.configured_bytes and
                    vm.minimum_bytes <= read.assigned_bytes <= vm.maximum_bytes,
                    'readback', 'current actual allocation is unsettled or outside full paid scope')
            self.proofs.profile(RuntimeBinding(**ctx['binding']), plan['host_boot_id'])
            if vm.vm_id == before.vm_id:
                require(vm.minimum_bytes <= target <= vm.maximum_bytes,
                        'calibration_runtime', 'exploratory target outside paid native bounds')
                require(read == before, 'identity_mismatch', 'original paired readback changed')
                if physical:
                    m = self.scope; a = guest['calibration_accounting']; memory = guest['memory']
                    require(a['os_upper_bound_bytes'] <= m['os_reserve_bytes'] - m['safety_allowance_bytes'] and
                            memory['MemTotal'] == a['meminfo_bytes']['MemTotal'] == a['meminfo_after_bytes']['MemTotal'] and
                            memory['MemTotal'] <= m['maximum_guest_total_bytes'] and memory['MemTotal'] >= m['os_reserve_bytes'] and
                            m['safety_allowance_bytes'] <= memory['MemAvailable'] <= memory['MemTotal'] and
                            max(0, read.assigned_bytes - memory['MemTotal']) <= m['native_gap_bound_bytes'] and
                            target >= max(vm.minimum_bytes, m['os_reserve_bytes'] + m['native_gap_bound_bytes']) and
                            target % self.proofs.backend.quantum_bytes == 0,
                            'calibration_physical', 'fresh physical observations contradict retained exploratory scope')
            else:
                require(read.assigned_bytes == read.configured_bytes == vm.maximum_bytes,
                        'readback', 'unaffected resident must retain actual native maximum')
            require(self.proofs.backend.readback(vm.vm_id) == read, 'identity_mismatch', 'native pair changed after scope check')
        require(self._load() == (self.plan, self.bootstrap_report, self.permit), 'calibration_runtime', 'activation changed during decision')
        check_baseline(self.policy, self.store, plan, self.parent._state())

    def _retain_failure(self, error, state, originals, *, mutation_id=None):
        if mutation_id is not None:
            # The durable native fact remains available even if secondary
            # physical capture, hashing or persistence fails.
            error.native_outcome = 'RETURNED_SUCCESS'; error.mutation_id = mutation_id
            error.physical_status = 'FAIL' if error.code == 'calibration_physical' else 'NOT_MEASURED'
            path = self.repository.readback_path(self.parent.operation, mutation_id)
            error.calibration_readback_path = str(path)
            try:
                error.calibration_readback_sha256 = self.repository.digest(path)
            except Exception as secondary:
                error.calibration_record_error = repr(secondary)[:4096]
        if error.code == 'calibration_physical' or mutation_id is not None:
            try:
                self._physical_failure(error, state, originals, mutation_id=mutation_id)
            except Exception as capture_error:
                error.calibration_record_error = repr(capture_error)[:4096]

    def calibration_guard(self, plan, state, before, target, *, case_name):
        originals = []
        try:
            with self.store.locked(read_only=True):
                self._pending_case(plan, state, before, target, case_name)
                selected = next(vm for vm in self.policy.vms if vm.vm_id == before.vm_id)
                require(case_name != 'restore-full' or target == selected.maximum_bytes,
                        'calibration_restore', 'original restore-full target must equal full paid maximum')
                restore = case_name == 'restore-full' and before.assigned_bytes < target
                if restore:
                    self.repository.active(self.parent.operation, plan)
                    self._confirmed_lower(state, before)
                # Equal-V restore uses the ordinary strict path, hence NO_OP
                # requires neither a lower predecessor nor an exception.
                self._observe(plan, state, before, target, originals, physical=not restore)
        except ResourceError as error:
            self._retain_failure(error, state, originals)
            raise
        except (KeyError, TypeError, ValueError, MissingEvidence) as error:
            raise ResourceError('qualification_observations_required', 'missing/mismatched actual idle observations') from error

    def _retain_samples(self, originals, metadata, *, family, proposed_vm, proposed_target):
        """Keep each actual resident context/raw packet within the existing 1MiB schema.

        Per-row failures are returned explicitly so one oversized sample does
        not prevent retaining another resident's original failure. Callers own
        whether retention is mandatory or secondary to an existing refusal.
        """
        refs, errors = [], []
        for ctx, read, guest, source in originals:
            try:
                original = dict(source, **metadata)
                o = CalibrationObservation(ctx, 1, asdict(read), guest.get('memory', {}).get('MemTotal'),
                    guest.get('memory', {}).get('MemAvailable'), guest.get('slurm_memory_bytes'), guest.get('slurm_registered'),
                    (), None, proposed_target if read.vm_id == proposed_vm else None, None, None,
                    fingerprint(original), guest.get('calibration_accounting'), original)
                path = self.repository.folder(self.parent.operation) / family / (uuid.uuid4().hex + '.json')
                self.repository.exclusive(path, plain(o))
                refs.append(dict(vm_id=read.vm_id, path=str(path), sha256=self.repository.digest(path)))
            except Exception as capture_error:
                errors.append(capture_error)
        return refs, errors

    def settlement_guard(self, plan, state, current, *, mutation_id):
        with self.store.locked(read_only=True):
            require(self.parent._catalog(plan, state) == [mutation_id], 'calibration_pending', 'exact original settlement slot required')
            self.repository.active(self.parent.operation, plan)
            owner = self.proofs.owner_for(mutation_id)
            require(type(owner) is CalibrationEffectOwner and owner.operation == self.parent.operation,
                    'effect_owner', 'original calibration settlement owner required')
            effect = owner.effect(state, mutation_id)
            proof = self.parent._proof(owner, state, effect)
            require(type(current) is VMReadback and current.vm_id == effect.vm_id and current.assigned_bytes == current.configured_bytes == effect.target_bytes,
                    'readback', 'actual current target must equal original terminal effect')
            try:
                originals = []
                self._observe(plan, state, current, effect.target_bytes, originals, physical=False, host_safety=False, binding_only=True)
                require(self.proofs.backend.readback(effect.vm_id) == current, 'identity_mismatch', 'settlement target changed after paired Source checks')

            except (KeyError, TypeError, ValueError, MissingEvidence) as error:
                raise ResourceError('qualification_observations_required', 'actual settlement Source/binding unavailable') from error
            metadata = dict(native_settlement=dict(mutation_id=mutation_id, effect_vm_id=effect.vm_id,
                effect=owner.record, owner_sha256=fingerprint(owner.reference), witness=proof,
                physical_assessed=False, selected_readback=asdict(current)))
            refs, errors = self._retain_samples(originals, metadata, family='observations',
                proposed_vm=effect.vm_id, proposed_target=effect.target_bytes)
            if errors:
                error = errors[0]
                error.native_outcome = 'RETURNED_SUCCESS'; error.mutation_id = mutation_id
                error.calibration_evidence_refs = refs
                error.calibration_record_error = '; '.join(repr(e) for e in errors)[:4096]
                raise error


    def assess_settled(self, plan, state, *, mutation_id):
        originals = []
        with self.store.locked(read_only=True):
            confirmed = self.parent._confirmed(mutation_id, state)
            require(not self.parent._catalog(plan, state), 'calibration_pending', 'post-settlement assessment refuses pending effect')
            self.repository.active(self.parent.operation, plan)
            current = VMReadback(**confirmed['readback'])
            try:
                self._observe(plan, state, current, current.assigned_bytes, originals)
            except ResourceError as error:
                self._retain_failure(error, state, originals, mutation_id=mutation_id)
                raise
            except (KeyError, TypeError, ValueError, MissingEvidence) as cause:
                error = ResourceError('qualification_observations_required', 'strict post-settlement physical observations unavailable')
                error.physical_status = 'NOT_MEASURED'
                self._retain_failure(error, state, originals, mutation_id=mutation_id)
                raise error from cause

    def _physical_failure(self, error, state, originals, *, mutation_id=None):
        """Never rewrite genuine C success to server UNKNOWN; preserve both facts."""
        error.native_outcome = 'RETURNED_SUCCESS' if mutation_id is not None else 'NOT_DISPATCHED_OR_UNPROVEN'
        error.physical_status = 'FAIL' if error.code == 'calibration_physical' else 'NOT_MEASURED'
        mids = [mutation_id] if mutation_id is not None else self.parent._catalog(self.plan, state)
        for mid in mids:
            confirmed = self.parent._confirmed(mid, state) if mutation_id is not None else None
            owner = self.proofs.owner_for(mid); effect = owner.effect(state, mid)
            if mutation_id is not None:
                # Secondary reinspection cannot relabel the already validated
                # native receipt UNKNOWN if its proof capture now fails.
                witness = self.parent._proof(owner, state, effect)
            else:
                try:
                    witness = self.proofs.read(mid)
                except FileNotFoundError:
                    error.native_outcome = 'UNKNOWN'; error.mutation_id = mid
                    continue
            if witness['phase'] != 'RETURNED_SUCCESS':
                error.native_outcome = 'UNKNOWN'
                error.mutation_id = mid
            if witness['phase'] == 'RETURNED_SUCCESS':
                proof = self.parent._proof(owner, state, effect)
                error.native_outcome = 'RETURNED_SUCCESS'; error.mutation_id = mid
                metadata = dict(physical_failure=dict(code=error.code, native_outcome=error.native_outcome,
                    physical_status=error.physical_status, mutation_id=mid, effect_vm_id=effect.vm_id,
                    effect=owner.record, owner_sha256=fingerprint(owner.reference), witness=proof))
                if confirmed is not None:
                    path = self.repository.readback_path(self.parent.operation, mid)
                    metadata['confirmed_readback'] = confirmed
                    metadata['confirmed_readback_ref'] = dict(path=str(path), sha256=self.repository.digest(path))
                refs, errors = self._retain_samples(originals, metadata, family='physical-failures',
                    proposed_vm=effect.vm_id, proposed_target=effect.target_bytes)
                error.calibration_evidence_refs = refs
                if refs:
                    error.calibration_evidence_path = refs[-1]['path']
                    error.calibration_evidence_sha256 = refs[-1]['sha256']
                if errors:
                    error.calibration_record_error = '; '.join(repr(e) for e in errors)[:4096]

                return

    def capture_observation(self, sequence, *, case_name=None):
        """Real provider producer, preserving originals and one-MiB snapshot bound."""
        integer(sequence, 'sequence', 1)
        require(self._load() == (self.plan, self.bootstrap_report, self.permit), 'calibration_runtime', 'original runtime changed')
        require(not _exists(self.repository.folder(self.parent.operation) / 'jobs'),
                'calibration_jobs_unsupported', 'idle producer refuses child namespace')
        observation = self.provider.calibration_observation(self.parent, self.permit, sequence, case_name=case_name)
        self._idle(plain(observation.source_records)['guest'], self.ctx)
        path = self.repository.folder(self.parent.operation) / 'observations' / (str(sequence) + '.json')
        self.repository.exclusive(path, plain(observation))
        return dict(path=str(path), sha256=self.repository.digest(path), observation=observation)

    def report(self, case_observations):
        """No positive qualification, installation, production readiness or closure."""
        report = build_qualification_report(self.permit, case_observations)
        ref = write_report_exclusive(self.parent, report)
        return dict(**ref, candidate=None, native_qualification='NOT_MEASURED')
