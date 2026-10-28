"""Installed controller service for the existing maintenance delivery engine.

Operation projections are auxiliary. Failure to publish them never rolls back or
rewrites an engine outcome; absent completion evidence is reconciliation, not replay.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import time

import application_release as engine
import delivery_requests as requests
from delivery_requests import RUNTIME, command, require_controller
import release_trust as trust


def _native(run, argv, bounds, deadline):
    return run(argv, timeout_seconds=bounds['command_timeout_seconds'],
        output_bytes=bounds['command_output_bytes'], deadline=deadline)


def _unit_properties(identifier, run, bounds, deadline):
    raw = _native(run, ['systemctl','show',requests.unit_name(identifier),
        '--property=MainPID,InvocationID,ActiveState,ControlGroup','--no-pager'], bounds, deadline)
    properties = {}
    for line in raw.splitlines():
        key, sep, value = line.partition('=')
        if not sep or key in properties:
            raise ValueError('Malformed delivery unit observation')
        properties[key] = value
    if set(properties) != {'MainPID','InvocationID','ActiveState','ControlGroup'}:
        raise ValueError('Incomplete delivery unit observation')
    return properties


def observe_service_generation(identifier, *, run, bounds, deadline):
    props = _unit_properties(identifier,run,bounds,deadline)
    pid, start, boot = engine._process_generation()
    cgroup = engine.local_metadata('/proc/self/cgroup', 16384).decode().splitlines()
    if props['ActiveState'] not in ('active','activating') or props['MainPID'] != str(pid) or cgroup != ['0::'+props['ControlGroup']] or not props['ControlGroup'].endswith('/'+requests.unit_name(identifier)):
        raise ValueError('Caller is not the installed owning delivery service')
    generation = {'unit':requests.unit_name(identifier),'boot_id':boot,
        'invocation_id':props['InvocationID'],'pid':pid,'start_ticks':start}
    # Same strict validation as a projected generation, without environment trust.
    if not re.fullmatch('[0-9a-f]{32}',generation['invocation_id']) or int(generation['invocation_id'],16)==0:
        raise ValueError('Unknown delivery unit invocation')
    return generation


def _live_generation(identifier, generation, *, run, bounds, deadline):
    if generation is None:
        return False
    try:
        pid = generation['pid']
        boot = engine.local_metadata('/proc/sys/kernel/random/boot_id',256).decode().strip()
        fields = engine.local_metadata('/proc/'+str(pid)+'/stat',65536).decode().rsplit(')',1)[1].split()
        if boot != generation['boot_id'] or int(fields[19]) != generation['start_ticks'] or fields[0] in ('Z','X'):
            return False
        cgroup = engine.local_metadata('/proc/'+str(pid)+'/cgroup',16384).decode().splitlines()
        props = _unit_properties(identifier,run,bounds,deadline)
        return (boot==generation['boot_id'] and int(fields[19])==generation['start_ticks'] and
            fields[0] not in ('Z','X') and props['MainPID']==str(pid) and
            props['InvocationID']==generation['invocation_id'] and props['ActiveState'] in ('active','activating') and
            cgroup==['0::'+props['ControlGroup']] and props['ControlGroup'].endswith('/'+requests.unit_name(identifier)))
    except (OSError,ValueError,RuntimeError,IndexError):
        return False


def _primary(runtime, request, operation):
    ref = 'delivery-attempts/'+operation['attempt_id']+'.json'
    raw = trust.read_protected_file(Path(runtime)/ref, 1048576)
    receipt = engine.unique_json(raw,1048576)
    context = {'request_id':request['request_id'],'attempt_id':operation['attempt_id'],
        'request_sha256':operation['request_sha256'],'enrollment_sha256':request['enrollment']['sha256']}
    if receipt.get('schema') != 'qcl-negf-delivery-attempt-v1' or receipt.get('attempt_id') != operation['attempt_id'] or receipt.get('request_context') != context or receipt.get('operation') != 'whole_cluster_update':
        raise ValueError('Primary attempt/request identity differs')
    engine.require_same_metadata(receipt.get('manifest'), request['manifest'])
    if engine.release_envelope(receipt.get('manifest')) != engine.release_envelope(request['manifest']):
        raise ValueError('Primary release differs')
    return ref, raw, receipt


def _admission(request):
    try:
        value = engine.unique_json(engine.read_admission(engine.GATE), 65536)
        if value.get('release_id') != request['manifest']['release_id'] or type(value.get('open')) is not bool:
            return 'unknown'
        return 'open' if value['open'] else 'closed'
    except (OSError,ValueError,TypeError):
        return 'unknown'


def _pending(receipt):
    return bool(receipt.get('pending_command',{}).get('mutation') or
        receipt.get('pending_local_mutation') or receipt.get('pending_stopped_observation') or
        receipt.get('admission_pending'))


def _commit(directory, runtime, request, operation, *, deadline):
    """Witness existing success while the engine still owns its lifecycle lock.

    The final intent removals remain the engine's last fallible success action.
    These observational/witness failures never enter close_after_failure.
    """
    engine.deadline_check(deadline)
    ref, raw, receipt = _primary(runtime,request,operation)
    if receipt.get('status') != 'completed' or receipt.get('open') is not True or receipt.get('requires_reconciliation') or receipt.get('pending_command') or receipt.get('pending_local_mutation') or receipt.get('pending_stopped_observation'):
        raise ValueError('Primary engine completion is unconfirmed')
    with trust.protected_directory(Path(runtime)/'delivery-attempts') as attempts:
        try:
            os.stat(operation['attempt_id']+'.admission-intent.json',dir_fd=attempts,follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError('Own admission intent cleanup is unconfirmed')
        engine.lifecycle_guard(runtime)
        # Persist the observed own intent removals before a durable completion
        # witness. Failure here leaves the primary outcome and gate untouched.
        os.fsync(attempts)
    admission = _admission(request)
    if admission != 'open':
        raise ValueError('Current selected admission is not open')
    witness = {'schema':requests.COMMIT_SCHEMA,'request_id':request['request_id'],
        'attempt_id':operation['attempt_id'],'request_sha256':operation['request_sha256'],
        'engine_receipt':ref,'engine_receipt_sha256':hashlib.sha256(raw).hexdigest(),
        'intent_cleanup_confirmed':True,'admission':{'release_id':request['manifest']['release_id'],'open':True}}
    engine.deadline_check(deadline)
    requests.write_record(directory,'commit.json',witness,exclusive=True)
    return witness


def _progress_value(value, operation):
    keys = {'schema','request_id','attempt_id','request_sha256','phase','state','engine_receipt',
        'original_failure_log','admission_state','pending_mutation','requires_reconciliation'}
    if not isinstance(value,dict) or set(value)!=keys or value['schema']!=requests.PROGRESS_SCHEMA:
        raise ValueError('Invalid engine progress projection')
    for key in ('request_id','attempt_id','request_sha256'):
        if value[key]!=operation[key]:
            raise ValueError('Engine projection identity differs')
    if type(value['pending_mutation']) is not bool or value['state'] not in ('running','completed','failed','outcome_unknown'):
        raise ValueError('Engine progress requires a verified durable boundary')
    requests.validate_operation({**operation,**{key:value[key] for key in keys-{'schema'}}})
    return value


def run_update_service(identifier, *, runtime=RUNTIME, run=command):
    require_controller()
    requests.read_update_status(identifier,runtime=runtime)
    with requests.request_directory(runtime,identifier) as directory:
        request, _ = requests.read_binding(directory,identifier)
        deadline = time.monotonic()+request['bounds']['delivery_timeout_seconds']
        with requests.service_lock(runtime,deadline=deadline), requests.request_lock(directory,deadline=deadline):
            request, operation = requests.read_binding(directory,identifier)
            if operation['state'] in requests.TERMINAL:
                return operation
            if operation['state']!='queued' or operation['service_generation'] is not None:
                return requests.update_operation(directory,operation,state='reconciliation_required',
                    phase='service_reentry',pending_mutation=None,admission_state='unknown',
                    requires_reconciliation=True,error_class='StaleServiceGeneration')
            requests.guard_other_operations(runtime,identifier,deadline=deadline)
            generation = observe_service_generation(identifier,run=run,bounds=request['bounds'],deadline=deadline)
            # Durable service generation MUST precede engine entry. Any restart
            # sees running, not a new request; no signal/exit authorizes replay.
            operation = requests.update_operation(directory,operation,state='running',phase='service_started',
                service_generation=generation,pending_mutation=None)
            projection_error = None
            committed = False
            def progress(value):
                nonlocal operation, projection_error, committed
                try:
                    engine.deadline_check(deadline)
                    value = _progress_value(value,operation)
                    if value['state']=='completed':
                        _commit(directory,runtime,request,operation,deadline=deadline)
                        committed = True
                    changes = {key:value[key] for key in value if key not in ('schema','request_id','attempt_id','request_sha256')}
                    engine.deadline_check(deadline)
                    operation = requests.update_operation(directory,operation,**changes)
                except (OSError,ValueError,RuntimeError) as error:
                    # An auxiliary callback may not throw into command dispatch
                    # or the engine's final success/close-after-failure ordering.
                    projection_error = type(error).__name__
            context = {'request_id':identifier,'attempt_id':operation['attempt_id'],
                'request_sha256':operation['request_sha256'],'enrollment_sha256':request['enrollment']['sha256']}
            failure = None
            try:
                result = engine.deliver_cli(request['manifest'],request['pool'],run=run,
                    enrollment=request['enrollment']['path'],runtime=runtime,gate=engine.GATE,
                    **{**request['bounds'],'delivery_timeout_seconds':deadline-time.monotonic()},
                    request_context=context,progress=progress)
            except (OSError,ValueError,RuntimeError) as error:
                failure = type(error).__name__
                result = getattr(error,'delivery_summary',{})
            if committed and projection_error is None and operation['state']=='completed':
                return operation
            # Read back primary evidence, never infer absence of mutation from a
            # service exit/exception. Unknown boundary is nullable by contract.
            ref = operation['engine_receipt']
            pending = None
            try:
                ref, _, primary = _primary(runtime,request,operation)
                pending = _pending(primary)
            except (OSError,ValueError,TypeError):
                primary = None
            admission = _admission(request)
            known_failure = (failure is not None and primary is not None and
                primary.get('status')=='failed' and not primary.get('requires_reconciliation') and
                not pending and admission=='closed' and projection_error is None)
            changes = dict(state='failed' if known_failure else 'outcome_unknown',
                phase='engine_failed' if known_failure else 'outcome_unknown',engine_receipt=ref,
                original_failure_log=ref if failure or result.get('status')=='failed' else None,
                pending_mutation=pending,admission_state=admission,requires_reconciliation=not known_failure,
                error_class=projection_error or failure or 'UnconfirmedEngineOutcome')
            # If this publication also fails, leave the earlier durable running/
            # pending record. The CLI raises; readers never synthesize completed.
            engine.deadline_check(deadline)
            return requests.update_operation(directory,operation,**changes)


def reconcile_update_requests(*, runtime=RUNTIME, run=command):
    """Classify only. Never dispatch, clear intents, restore, close or open admission."""
    require_controller()
    base = Path(runtime)/'delivery-requests'
    try:
        with trust.protected_directory(base) as parent:
            identifiers = sorted(os.listdir(parent))
    except FileNotFoundError:
        return ()
    reports = []
    reconcile_deadline = time.monotonic()+360.0
    for identifier in identifiers:
        engine.deadline_check(reconcile_deadline)
        if identifier == 'owner.lock':
            continue
        try:
            requests.request_id(identifier)
            with requests.request_directory(runtime,identifier) as directory:
                request, operation = requests.read_binding(directory,identifier)
                deadline = min(reconcile_deadline,time.monotonic()+request['bounds']['command_timeout_seconds'])
                try:
                    with requests.request_lock(directory,deadline=deadline):
                        request, operation = requests.read_binding(directory,identifier)
                        if operation['state'] not in ('queued','running'):
                            if operation['state']=='completed':
                                requests.validate_completion(directory,request,operation,runtime)
                            # Terminal history stays on disk, not in every boot's output.
                            continue
                        if _live_generation(identifier,operation['service_generation'],run=run,bounds=request['bounds'],deadline=deadline):
                            reports.append(operation)
                            continue
                        pending = None
                        try:
                            _, _, primary = _primary(runtime,request,operation)
                            pending = _pending(primary)
                        except (OSError,ValueError,TypeError):
                            pass
                        operation = requests.update_operation(directory,operation,state='reconciliation_required',
                            phase='stale_service',pending_mutation=pending,admission_state='unknown',
                            requires_reconciliation=True,error_class='UnconfirmedServiceOutcome')
                        reports.append(operation)
                except engine.CommandFailure:
                    # A live service holds the same lock across the whole engine.
                    # Lock timeout is neither process loss nor completion.
                    reports.append(requests.read_update_status(identifier,runtime=runtime))
        except (OSError,ValueError,TypeError) as error:
            # Missing binding has no trustworthy attempt ID. Do not invent one.
            reports.append({'schema':'qcl-negf-delivery-reconcile-error-v1','request_id':identifier[:128],
                'state':'reconciliation_required','error_class':type(error).__name__})
        if len(requests.canonical(reports)) > 8388608:
            raise ValueError('Reconciliation output exceeds existing delivery output bound')
    return tuple(reports)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('run','reconcile'))
    parser.add_argument('--request-id')
    args = parser.parse_args()
    if args.action=='run':
        if not args.request_id:
            parser.error('Installed service requires --request-id')
        try:
            result = run_update_service(args.request_id)
        except (OSError,ValueError,RuntimeError) as error:
            print(json.dumps(requests.error_response(args.request_id,error),sort_keys=True))
            raise SystemExit(1)
    else:
        if args.request_id:
            parser.error('Boot reconciliation does not accept a new delivery request')
        try:
            result = reconcile_update_requests()
        except (OSError,ValueError,RuntimeError) as error:
            print(json.dumps(requests.error_response(None,error),sort_keys=True))
            raise SystemExit(1)
    print(json.dumps(result,sort_keys=True))
    if args.action=='run' and result['state']!='completed':
        raise SystemExit(1)


if __name__=='__main__':
    main()
