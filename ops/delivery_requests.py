"""Durable explicit maintenance requests, separate from authoritative engine journals.

No TTL or automatic replay: an old request ID remains reserved, including incomplete
publication. Only the installed controller service may enter the existing engine.
"""
from contextlib import contextmanager
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

import application_release as engine
import release_trust as trust

RUNTIME = engine.RUNTIME
command = engine.command
REQUEST_SCHEMA = 'qcl-negf-delivery-request-v1'
OPERATION_SCHEMA = 'qcl-negf-delivery-operation-v1'
PROGRESS_SCHEMA = 'qcl-negf-delivery-progress-v1'
COMMIT_SCHEMA = 'qcl-negf-delivery-commit-v1'
REQUEST_LIMIT = 262144
RECORD_LIMIT = 16384
SYMBOL = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
OPERATION_KEYS = {'schema','request_id','attempt_id','request_sha256','procedure','revision',
    'state','phase','service_generation','engine_receipt','original_failure_log',
    'admission_state','pending_mutation','requires_reconciliation','error_class'}
TERMINAL = {'completed','failed','outcome_unknown','reconciliation_required'}


def request_id(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value or uuid.UUID(value).int == 0:
        raise ValueError('Expected canonical non-nil request/attempt UUID')
    return value


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def require_controller():
    settings = engine.unique_json(trust.read_protected_file('/etc/qcl-negf/release-config.json', 16384), 16384)
    if settings.get('role') != 'controller':
        raise ValueError('Delivery service belongs to protected controller role')
    for helper in ('delivery_service.py', 'aiida_update_check.py'):
        if not Path(__file__).with_name(helper).is_file():
            raise ValueError('Uninstalled controller management helper')


def validate_update_request(value):
    keys = {'schema','request_id','procedure','manifest','pool','enrollment','bounds'}
    if not isinstance(value, dict) or set(value) != keys or value['schema'] != REQUEST_SCHEMA:
        raise ValueError('Expected exact delivery request v1')
    request_id(value['request_id'])
    if value['procedure'] != 'maintenance':
        raise ValueError('Only explicit maintenance is supported; no soft update fallback')
    engine.release_envelope(value['manifest'])
    engine.prefetch_controller_closures(value['manifest'], validate_only=True)
    if value['manifest'].get('requires_os_maintenance', False) is not False:
        raise ValueError('OS maintenance requires a separate procedure')
    pool = value['pool']
    if not isinstance(pool, dict) or set(pool) != {'schema','nodes'} or pool['schema'] != 'qcl-negf-active-pool-v2' or not isinstance(pool['nodes'], list) or not pool['nodes']:
        raise ValueError('Expected exact active pool v2')
    seen = {key: set() for key in ('name','target','enrollment_id')}
    for row in pool['nodes']:
        if not isinstance(row, dict) or set(row) != {'name','target','role','enrollment_id'}:
            raise ValueError('Expected enrolled route')
        request_id(row['enrollment_id'])
        if row['role'] not in ('controller','worker') or not engine.IDENTIFIER.fullmatch(str(row['name'])) or not engine.TARGET.fullmatch(str(row['target'])):
            raise ValueError('Invalid enrolled route')
        for key in seen:
            if row[key] in seen[key]:
                raise ValueError('Duplicate enrolled route')
            seen[key].add(row[key])
    if sum(row['role']=='controller' for row in pool['nodes']) != 1:
        raise ValueError('Select exactly one controller')
    enrollment = value['enrollment']
    if not isinstance(enrollment, dict) or set(enrollment) != {'path','sha256'}:
        raise ValueError('Expected protected enrollment reference')
    trust.protected_parts(enrollment['path'])
    if not isinstance(enrollment['sha256'], str) or not DIGEST.fullmatch(enrollment['sha256']):
        raise ValueError('Invalid enrollment digest')
    bounds = value['bounds']
    if not isinstance(bounds, dict) or set(bounds) != {'delivery_timeout_seconds','command_timeout_seconds','command_output_bytes','delivery_output_bytes'}:
        raise ValueError('Expected existing delivery bounds')
    for key in ('delivery_timeout_seconds','command_timeout_seconds'):
        if engine.duration(bounds[key], key) <= 2:
            raise ValueError('Duration must exceed cleanup reserve')
    for key in ('command_output_bytes','delivery_output_bytes'):
        engine.output_bound(bounds[key])
    if len(canonical(value)) > REQUEST_LIMIT:
        raise ValueError('Request metadata exceeds bound')
    return copy.deepcopy(value)


def validate_operation(value):
    if not isinstance(value, dict) or set(value) != OPERATION_KEYS or value['schema'] != OPERATION_SCHEMA:
        raise ValueError('Expected exact operation receipt')
    request_id(value['request_id']); request_id(value['attempt_id'])
    if value['procedure'] != 'maintenance' or not isinstance(value['request_sha256'], str) or not DIGEST.fullmatch(value['request_sha256']):
        raise ValueError('Invalid operation binding')
    if type(value['revision']) is not int or value['revision'] < 1 or value['state'] not in {'queued','running',*TERMINAL}:
        raise ValueError('Invalid operation revision/state')
    for key in ('phase','error_class'):
        if value[key] is None and key == 'error_class':
            continue
        if not isinstance(value[key], str) or not SYMBOL.fullmatch(value[key]):
            raise ValueError('Invalid operation symbol')
    if value['admission_state'] not in ('not_observed','open','closed','unknown') or value['pending_mutation'] is not None and type(value['pending_mutation']) is not bool or type(value['requires_reconciliation']) is not bool:
        raise ValueError('Invalid or fabricated operation boundary')
    for key in ('engine_receipt','original_failure_log'):
        ref = value[key]
        if ref is not None and ref != 'delivery-attempts/'+value['attempt_id']+'.json':
            raise ValueError('Invalid primary receipt reference')
    generation = value['service_generation']
    if generation is not None:
        if not isinstance(generation, dict) or set(generation) != {'unit','boot_id','invocation_id','pid','start_ticks'} or generation['unit'] != unit_name(value['request_id']):
            raise ValueError('Invalid service generation')
        request_id(generation['boot_id'])
        if not isinstance(generation['invocation_id'], str) or not re.fullmatch('[0-9a-f]{32}', generation['invocation_id']) or int(generation['invocation_id'],16)==0:
            raise ValueError('Invalid service invocation')
        if any(type(generation[k]) is not int or generation[k] <= 0 for k in ('pid','start_ticks')):
            raise ValueError('Invalid service process identity')
    return value


def unit_name(identifier):
    return 'qcl-negf-delivery@'+request_id(identifier)+'.service'


def _private_stat(info, *, directory=False):
    trust.trusted_stat(info, directory=directory)
    if stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600) or not directory and info.st_nlink != 1:
        raise ValueError('Private delivery namespace mode/link changed')


def _open_directory(parent, name, create=False):
    created = False
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
            created = True
            os.fsync(parent)
        except FileExistsError:
            pass
    fd = os.open(name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=parent)
    try:
        _private_stat(os.fstat(fd), directory=True)
    except BaseException:
        os.close(fd)
        raise
    return fd, created


@contextmanager
def request_directory(runtime, identifier, *, create=False, with_creation=False):
    request_id(identifier)
    with trust.protected_directory(runtime) as root:
        base, _ = _open_directory(root, 'delivery-requests', create)
        try:
            selected, created = _open_directory(base, identifier, create)
            try:
                yield (selected, created) if with_creation else selected
            finally:
                os.close(selected)
        finally:
            os.close(base)


def read_record(directory, name, limit=RECORD_LIMIT):
    fd = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK, dir_fd=directory)
    try:
        _private_stat(os.fstat(fd))
        chunks = bytearray()
        while len(chunks) <= limit:
            chunk = os.read(fd, min(4096, limit+1-len(chunks)))
            if not chunk:
                return engine.unique_json(bytes(chunks), limit)
            chunks.extend(chunk)
        raise ValueError('Delivery record exceeds bound')
    finally:
        os.close(fd)


def write_record(directory, name, value, *, exclusive=False):
    """fd anchored publication; never chmod a pre-existing/foreign path."""
    raw = canonical(value)
    if len(raw) > (REQUEST_LIMIT if name == 'request.json' else RECORD_LIMIT):
        raise ValueError('Delivery record exceeds bound')
    previous = None
    try:
        previous = os.stat(name, dir_fd=directory, follow_symlinks=False)
        _private_stat(previous)
        if exclusive:
            raise ValueError('Delivery record already exists; reconciliation required')
    except FileNotFoundError:
        pass
    temporary = '.'+str(uuid.uuid4())+'.tmp'
    fd = os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        _private_stat(os.fstat(fd))
        view = memoryview(raw)
        while view:
            n = os.write(fd, view)
            if n <= 0:
                raise OSError('Delivery publication made no progress')
            view = view[n:]
        os.fsync(fd)
        if previous is not None:
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (current.st_ino,current.st_dev) != (previous.st_ino,previous.st_dev):
                raise ValueError('Delivery publication target changed')
        if exclusive:
            os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
            os.unlink(temporary, dir_fd=directory)
        else:
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        os.close(fd)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


@contextmanager
def request_lock(directory, *, deadline, create=False, name='lock'):
    flags = os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK
    if name not in ('lock','owner.lock'):
        raise ValueError('Invalid delivery lock namespace')
    try:
        fd = os.open(name, flags|(os.O_CREAT if create else 0), 0o600, dir_fd=directory)
    except FileNotFoundError as error:
        raise ValueError('Missing delivery lock requires reconciliation') from error
    try:
        _private_stat(os.fstat(fd))
        while True:
            engine.deadline_check(deadline)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
                break
            except BlockingIOError:
                time.sleep(min(.01, max(0, deadline-time.monotonic())))
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (current.st_ino,current.st_dev) != (os.fstat(fd).st_ino,os.fstat(fd).st_dev):
            raise ValueError('Delivery lock changed')
        yield
    finally:
        os.close(fd)


def read_binding(directory, identifier):
    request = validate_update_request(read_record(directory, 'request.json', REQUEST_LIMIT))
    try:
        operation = validate_operation(read_record(directory, 'operation.json'))
    except OSError as error:
        raise ValueError('Incomplete request/operation publication; reconciliation required') from error
    if request['request_id'] != identifier or operation['request_id'] != identifier or operation['request_sha256'] != digest(request):
        raise ValueError('Request/operation binding differs')
    return request, operation


def _completion_evidence(directory, request, operation, runtime):
    if operation['requires_reconciliation'] is not False or operation['pending_mutation'] is not False or operation['admission_state'] != 'open':
        raise ValueError('Completed projection contains an unknown boundary')
    witness = read_record(directory,'commit.json')
    keys = {'schema','request_id','attempt_id','request_sha256','engine_receipt',
        'engine_receipt_sha256','intent_cleanup_confirmed','admission'}
    if not isinstance(witness,dict) or set(witness)!=keys or witness['schema']!=COMMIT_SCHEMA:
        raise ValueError('Missing exact engine completion witness')
    for key in ('request_id','attempt_id','request_sha256'):
        if witness[key]!=operation[key]:
            raise ValueError('Completion witness binding differs')
    ref = 'delivery-attempts/'+operation['attempt_id']+'.json'
    if witness['engine_receipt']!=ref or operation['engine_receipt']!=ref or witness['intent_cleanup_confirmed'] is not True or not isinstance(witness['admission'],dict) or set(witness['admission'])!={'release_id','open'} or witness['admission']['open'] is not True or witness['admission']['release_id']!=request['manifest']['release_id']:
        raise ValueError('Incomplete engine commit witness')
    # Only bounded primary JSON metadata is read, never closure verification,
    # self-check or native health. Receipt loss/corruption cannot become completed.
    raw = trust.read_protected_file(Path(runtime)/ref,1048576)
    if hashlib.sha256(raw).hexdigest()!=witness['engine_receipt_sha256']:
        raise ValueError('Primary completion receipt changed')
    primary = engine.unique_json(raw,1048576)
    context = {'request_id':request['request_id'],'attempt_id':operation['attempt_id'],
        'request_sha256':operation['request_sha256'],'enrollment_sha256':request['enrollment']['sha256']}
    if primary.get('schema')!='qcl-negf-delivery-attempt-v1' or primary.get('attempt_id')!=operation['attempt_id'] or primary.get('request_context')!=context or primary.get('status')!='completed' or primary.get('open') is not True:
        raise ValueError('Invalid primary completion identity/outcome')


def validate_completion(directory, request, operation, runtime):
    try:
        _completion_evidence(directory,request,operation,runtime)
    except (OSError,KeyError,TypeError) as error:
        raise ValueError('Missing or untrusted completion evidence') from error


def read_update_status(identifier, *, runtime=RUNTIME):
    try:
        with request_directory(runtime, identifier) as directory:
            request, operation = read_binding(directory, identifier)
            if operation['state']=='completed':
                validate_completion(directory,request,operation,runtime)
            return operation
    except (OSError, TypeError, KeyError, ValueError) as error:
        raise ValueError('Untrusted or missing delivery status binding') from error


def update_operation(directory, operation, **changes):
    updated = {**operation, **changes}
    if updated == operation:
        return operation
    updated['revision'] += 1
    validate_operation(updated)
    write_record(directory, 'operation.json', updated)
    return updated


def submit_update(value, *, runtime=RUNTIME, run=command):
    request = validate_update_request(value)
    require_controller()
    deadline = time.monotonic()+request['bounds']['command_timeout_seconds']
    with request_directory(runtime, request['request_id'], create=True, with_creation=True) as (directory, created):
        # Only this successful mkdir grants first-publication authority. An old
        # namespace with lost binding/lock stays unknown, even if supplied bytes
        # match surviving operation/witness digests. Never heal it on retry.
        with request_lock(directory, deadline=deadline, create=created):
            if created and set(os.listdir(directory)) != {'lock'}:
                raise ValueError('New delivery namespace changed before publication')
            try:
                existing = read_record(directory, 'request.json', REQUEST_LIMIT)
            except FileNotFoundError:
                existing = None
            if existing is not None:
                old_request, operation = read_binding(directory, request['request_id'])
                if digest(old_request) != digest(request):
                    raise ValueError('Request ID is permanently bound to another body')
                if operation['state']=='completed':
                    validate_completion(directory,old_request,operation,runtime)
                return operation
            if not created:
                raise ValueError('Missing immutable request requires reconciliation')
            reference = request['enrollment']
            raw = trust.read_protected_file(reference['path'])
            if hashlib.sha256(raw).hexdigest() != reference['sha256']:
                raise ValueError('Enrollment changed before durable dispatch')
            engine.validate_enrollment(request['pool'], engine.unique_json(raw))
            # A crash after request publication reserves this ID, even if the
            # operation/attempt publication did not finish. No retry invents it.
            write_record(directory, 'request.json', request, exclusive=True)
            operation = {'schema':OPERATION_SCHEMA,'request_id':request['request_id'],
                'attempt_id':str(uuid.uuid4()),'request_sha256':digest(request),'procedure':'maintenance',
                'revision':1,'state':'queued','phase':'queued','service_generation':None,
                'engine_receipt':None,'original_failure_log':None,'admission_state':'not_observed',
                'pending_mutation':None,'requires_reconciliation':False,'error_class':None}
            write_record(directory, 'operation.json', operation, exclusive=True)
            try:
                run(['systemctl','start','--no-block',unit_name(request['request_id'])],
                    timeout_seconds=request['bounds']['command_timeout_seconds'],
                    output_bytes=request['bounds']['command_output_bytes'], deadline=deadline)
            except (ValueError,RuntimeError,OSError) as error:
                # systemctl reply/cleanup says nothing about the service itself.
                operation = update_operation(directory, operation, state='outcome_unknown',
                    phase='dispatch_unknown',pending_mutation=None,admission_state='unknown',
                    requires_reconciliation=True,error_class=type(error).__name__)
            return operation


@contextmanager
def service_lock(runtime, *, deadline):
    # Serializes service request/commit bookkeeping, not command execution. The
    # existing engine lifecycle owner still grants all mutation authority.
    with trust.protected_directory(Path(runtime)/'delivery-requests') as directory:
        _private_stat(os.fstat(directory), directory=True)
        with request_lock(directory,deadline=deadline,create=True,name='owner.lock'):
            yield


def guard_other_operations(runtime, identifier, *, deadline):
    with trust.protected_directory(Path(runtime)/'delivery-requests') as directory:
        names = os.listdir(directory)
    for other in names:
        engine.deadline_check(deadline)
        if other in (identifier,'owner.lock'):
            continue
        try:
            with request_directory(runtime,other) as directory:
                _, operation = read_binding(directory,other)
            if operation['state']=='completed':
                read_update_status(other,runtime=runtime)
            if operation['state'] not in ('queued','completed','failed'):
                raise ValueError('Other delivery requires reconciliation')
        except (OSError,ValueError,TypeError) as error:
            raise ValueError('Other delivery requires reconciliation') from error


def error_response(identifier, error):
    """Bounded public error: no body, source path, command output or invented attempt."""
    try:
        identifier = request_id(identifier)
    except (ValueError,TypeError,AttributeError):
        identifier = None
    name = type(error).__name__
    return {'schema':'qcl-negf-delivery-response-error-v1','request_id':identifier,
        'error_class':name if SYMBOL.fullmatch(name) else 'DeliveryError'}
