"""Bounded settlement/restorative Source/L oracles; no actual C or qualification."""
import json
from pathlib import Path

import pytest

from test_host_resource_qualification_runtime import idle, runtime


def attach(idle, *, restore_target=2048):
    idle.plan['cases']['restore-full'] = dict(vm_id='vm-a', target_bytes=restore_target)
    path = idle.parent.repository.folder(idle.parent.operation)/'plan.json'
    path.write_text(json.dumps(idle.plan, sort_keys=True)); path.chmod(0o600)
    idle.stage()
    owner = runtime().open_native_runtime(idle.service)
    idle.s.calibration_guard = owner.calibration_guard
    # Deferred attribute lookup lets the baseline exercise its original flow.
    idle.s.calibration_settlement_guard = lambda *a, **kw: owner.settlement_guard(*a, **kw)
    idle.s.calibration_assess_settled = lambda *a, **kw: owner.assess_settled(*a, **kw)
    idle.provider._calibration_binding_pair = idle.provider._calibration_pair
    return owner


def lower_then_lose_headroom(idle):
    original = idle.r.run
    def run(*a, **kw):
        result = original(*a, **kw)
        idle.pairs['vm-a']['memory']['MemAvailable'] = 0
        return result
    idle.r.run = run
    with pytest.raises(idle.m.ResourceError) as caught:
        idle.parent.run_case('idle-shrink')
    assert caught.value.code == 'calibration_physical'
    return caught.value


def test_success_is_durable_before_failed_physical_assessment(idle):
    attach(idle)
    failure = lower_then_lose_headroom(idle)
    mid = idle.parent.repository.read(idle.parent.repository.case_path(idle.parent.operation, 'idle-shrink'))['mutation_id']
    path = idle.parent.repository.readback_path(idle.parent.operation, mid)
    assert path.exists(), 'genuine terminal native success must settle before physical assessment'
    confirmed = idle.parent._confirmed(mid, idle.store.load())
    assert confirmed['readback']['revision'] == 'revision-128'
    assert idle.p.dispatch(mid)['intent']['before_revision'] == 'revision-1'
    assert failure.native_outcome == 'RETURNED_SUCCESS' and failure.mutation_id == mid
    assert failure.physical_status == 'FAIL' and failure.calibration_evidence_path
    assert idle.parent._catalog(idle.plan, idle.store.load()) == []
    assert len(idle.r.calls) == 1 and idle.store.state_path.read_bytes() == idle.raw


def test_post_settlement_assessor_is_mandatory_and_not_native_unknown(idle):
    attach(idle)
    called = []
    def assessment(plan, state, *, mutation_id):
        called.append(mutation_id)
        assert idle.parent.repository.readback_path(idle.parent.operation, mutation_id).exists()
        raise idle.m.ResourceError('synthetic_assessment', 'strict assessor refusal')
    idle.s.calibration_assess_settled = assessment
    with pytest.raises(idle.m.ResourceError, match='synthetic_assessment'):
        idle.parent.run_case('idle-shrink')
    assert len(called) == 1 and idle.p.read(called[0])['phase'] == 'RETURNED_SUCCESS'
    assert idle.parent._catalog(idle.plan, idle.store.load()) == []
    assert not list(idle.store.directory.glob('failures/*CALIBRATION_UNKNOWN*'))


def test_original_restore_grows_after_confirmed_lower_physical_failure(idle):
    attach(idle)
    # A normal lower operation first supplies a genuine historical readback.
    first = idle.parent.run_case('idle-shrink')
    idle.pairs['vm-a']['memory']['MemAvailable'] = 0
    original = idle.r.run
    def restored(*a, **kw):
        result = original(*a, **kw)
        idle.pairs['vm-a']['memory']['MemAvailable'] = 1984
        return result
    idle.r.run = restored
    result = idle.parent.run_case('restore-full')
    assert result['status'] == 'READBACK_CONFIRMED' and result['mutation_id'] != first['mutation_id']
    intent = idle.p.dispatch(result['mutation_id'])['intent']
    assert (intent['old_bytes'], intent['target_bytes'], intent['before_revision']) == (128, 2048, 'revision-128')
    assert len(idle.r.calls) == 2 and idle.parent._catalog(idle.plan, idle.store.load()) == []
    assert idle.store.state_path.read_bytes() == idle.raw


def test_restore_purpose_reaches_prepare_execute_and_original_claim(idle):
    attach(idle)
    seen = []; original = idle.s.calibration_guard
    def guard(*a, **kw):
        seen.append(kw.get('case_name'))
        return original(*a, **kw)
    idle.s.calibration_guard = guard
    idle.parent.run_case('idle-shrink')
    assert seen == ['idle-shrink'] * 3, 'purpose must come from protected case at prepare, execute and claim'


def test_equal_full_restore_is_strict_noop_without_previous_lower(idle):
    attach(idle)
    result = idle.parent.run_case('restore-full')
    assert result['status'] == 'NO_OP' and result['mutation_id'] is None
    assert not idle.r.calls and not list(idle.p.directory.glob('*.owner.json'))
    assert idle.store.state_path.read_bytes() == idle.raw


def test_same_full_target_does_not_give_other_case_restorative_exception(idle):
    attach(idle); idle.parent.run_case('idle-shrink')
    idle.pairs['vm-a']['memory']['MemAvailable'] = 0
    with pytest.raises(idle.m.ResourceError, match='calibration_physical'):
        idle.parent.run_case('idle-grow')
    assert len(idle.r.calls) == 1


def test_equal_full_restore_keeps_strict_physical_guard(idle):
    attach(idle)
    idle.pairs['vm-a']['memory']['MemAvailable'] = 0
    with pytest.raises(idle.m.ResourceError, match='calibration_physical'):
        idle.parent.run_case('restore-full')
    assert not idle.r.calls
    assert not idle.parent.repository.case_path(idle.parent.operation, 'restore-full').exists()


def test_missing_physical_accounting_cannot_hide_genuine_native_settlement(idle):
    attach(idle)
    original = idle.r.run
    missing = dict(state='NOT_MEASURED', reason='original accounting read failed')
    def run(*a, **kw):
        result = original(*a, **kw)
        idle.pairs['vm-a']['calibration_accounting'] = missing
        return result
    idle.r.run = run
    with pytest.raises(idle.m.ResourceError) as caught:
        idle.parent.run_case('idle-shrink')
    error = caught.value
    assert error.code == 'qualification_observations_required'
    assert error.native_outcome == 'RETURNED_SUCCESS' and error.physical_status == 'NOT_MEASURED'
    confirmed = idle.parent._confirmed(error.mutation_id, idle.store.load())
    assert confirmed['native_qualification'] == 'NOT_MEASURED'
    original = idle.parent.repository.read(Path(error.calibration_evidence_path))
    assert original['accounting'] == missing
    assert idle.parent._catalog(idle.plan, idle.store.load()) == [] and len(idle.r.calls) == 1


@pytest.mark.parametrize('fault', ['host-pressure', 'other-vm-job', 'accounting-invalid', 'before-revision', 'unconfirmed-lower'])
def test_restore_exception_retains_source_host_idle_and_original_before_guards(idle, fault):
    from dataclasses import replace
    attach(idle)
    first = idle.parent.run_case('idle-shrink')
    idle.pairs['vm-a']['memory']['MemAvailable'] = 0
    if fault == 'host-pressure':
        idle.host['MemAvailable'] = 0
    if fault == 'other-vm-job':
        idle.pairs['vm-b']['jobs'] = {'unknown-generation': {}}
    if fault == 'accounting-invalid':
        idle.pairs['vm-a']['calibration_accounting']['os_upper_bound_bytes'] += 1
    if fault == 'before-revision':
        idle.b.rows['vm-a'] = replace(idle.b.rows['vm-a'], revision='unrelated-native-change')
    if fault == 'unconfirmed-lower':
        idle.parent.repository.readback_path(idle.parent.operation, first['mutation_id']).unlink()
    with pytest.raises((idle.m.ResourceError, ValueError)):
        idle.parent.run_case('restore-full')
    assert len(idle.r.calls) == 1
    assert not idle.parent.repository.case_path(idle.parent.operation, 'restore-full').exists()
    assert idle.store.state_path.read_bytes() == idle.raw


def test_restore_requires_original_full_target_and_genuine_lower_record(idle):
    from dataclasses import replace
    attach(idle)
    idle.parent.repository.activate(idle.parent.operation, idle.plan)
    idle.b.rows['vm-a'] = replace(idle.b.rows['vm-a'], assigned_bytes=128, configured_bytes=128)
    idle.pairs['vm-a']['memory']['MemAvailable'] = 0
    with pytest.raises(idle.m.ResourceError, match='calibration_restore'):
        idle.parent.run_case('restore-full')
    assert not idle.r.calls


def test_restore_case_cannot_dispatch_to_a_lower_numeric_target(idle):
    attach(idle, restore_target=128)
    with pytest.raises(idle.m.ResourceError, match='calibration_restore'):
        idle.parent.run_case('restore-full')
    assert not idle.r.calls


@pytest.mark.parametrize('fault', ['writer', 'constructor'])
def test_mandatory_raw_retention_refuses_publication_without_losing_native_status(idle, monkeypatch, fault):
    owner = attach(idle)
    original_writer = owner.repository.exclusive
    original_constructor = runtime().CalibrationObservation
    failure = OSError('original selected retention write failed') if fault == 'writer' else ValueError('original selected retention construction failed')
    def writer(path, document):
        if path.parent.name == 'observations' and document['context']['binding']['vm_id'] == 'vm-a':
            raise failure
        return original_writer(path, document)
    def construct(*args, **kwargs):
        if args[0]['binding']['vm_id'] == 'vm-a' and 'native_settlement' in args[-1]:
            raise failure
        return original_constructor(*args, **kwargs)
    monkeypatch.setattr(owner.repository, 'exclusive', writer)
    if fault == 'constructor':monkeypatch.setattr(runtime(), 'CalibrationObservation', construct)
    with pytest.raises(type(failure)) as caught:
        idle.parent.run_case('idle-shrink')
    assert caught.value is failure and failure.native_outcome == 'RETURNED_SUCCESS'
    mid = failure.mutation_id
    assert idle.p.read(mid)['phase'] == 'RETURNED_SUCCESS'
    assert not idle.parent.repository.readback_path(idle.parent.operation, mid).exists()
    assert idle.parent._catalog(idle.plan, idle.store.load()) == [mid]
    assert [ref['vm_id'] for ref in failure.calibration_evidence_refs] == ['vm-b']
    assert len(idle.r.calls) == 1 and idle.store.state_path.read_bytes() == idle.raw


def test_secondary_selected_retention_failure_does_not_drop_unaffected_raw_or_replace_refusal(idle, monkeypatch):
    owner = attach(idle)
    run = idle.r.run; strict = idle.provider._calibration_pair; write = owner.repository.exclusive
    executed = False
    original_failure = idle.m.ResourceError('qualification_observations_required', 'original vm-b accounting failure')
    def run_once(*args, **kwargs):
        nonlocal executed
        result = run(*args, **kwargs); executed = True; return result
    def pair(ctx):
        read, guest, source = strict(ctx)
        if executed and read.vm_id == 'vm-b':
            guest['calibration_accounting'] = dict(state='NOT_MEASURED', reason='original unrelated failure')
            source['guest'] = guest
            original_failure.calibration_pair = (read, guest, source)
            raise original_failure
        return read, guest, source
    def retain(path, document):
        if path.parent.name == 'physical-failures' and document['context']['binding']['vm_id'] == 'vm-a':
            raise OSError('secondary selected diagnostic failure')
        return write(path, document)
    monkeypatch.setattr(idle.r, 'run', run_once)
    monkeypatch.setattr(idle.provider, '_calibration_pair', pair)
    monkeypatch.setattr(owner.repository, 'exclusive', retain)
    with pytest.raises(idle.m.ResourceError) as caught:idle.parent.run_case('idle-shrink')
    assert caught.value is original_failure
    assert original_failure.native_outcome == 'RETURNED_SUCCESS' and original_failure.physical_status == 'NOT_MEASURED'
    assert 'secondary selected diagnostic failure' in original_failure.calibration_record_error
    records = [idle.parent.repository.read(Path(ref['path'])) for ref in original_failure.calibration_evidence_refs]
    assert len(records) == 1 and records[0]['context']['binding']['vm_id'] == 'vm-b'
    assert records[0]['readback']['vm_id'] == 'vm-b' and records[0]['proposed_target_bytes'] is None
    assert records[0]['source_records']['physical_failure']['effect_vm_id'] == 'vm-a'
    assert records[0]['source_records']['confirmed_readback']['mutation_id'] == original_failure.mutation_id
    assert records[0]['accounting']['reason'] == 'original unrelated failure'
    assert idle.parent._catalog(idle.plan, idle.store.load()) == [] and len(idle.r.calls) == 1
