"""Attempt-local bounded native file primitives, not a complete P2/C1 provider.

The caller injects an EXISTING trusted issuer, which authenticates the full
immutable capsule, current identity/epochs, native namespace/ownership/all-alias
admission and subordinate escrow. Returning a boolean/digest is insufficient.
No issuer, STOP authority, whole-process sandbox, HDF5 driver, physical-I/O
amplification bound, durable journal or scientific acceptance is implemented.

Deadlines bound dispatch, not completion of a blocking kernel syscall. Root fd
is borrowed from the admitted owner, which must retain exclusive descriptor and
namespace ownership for this object's lifetime. Arbitrary same-process syscall
or fd-table modification is outside this boundary. No automatic retries/refunds.
"""
from dataclasses import dataclass, field
import os
import stat
import threading
import time

_MAX = (1 << 64) - 1
_SLAB = 1 << 20
# Match the existing scientific-capacity binding; an issuer must also check its
# deployment's extra identities (including P0/model/frozen-plan references).
_BINDINGS = ('campaign_id', 'slot_id', 'plan_digest', 'criteria_digest',
             'source_graph_digest', 'release_id', 'runtime_id', 'execution_id',
             'attempt_id', 'point_id', 'admission_id', 'job_id', 'step_id',
             'owner_uid', 'pid', 'start_ticks', 'host_id', 'machine_id', 'boot_id',
             'mount_namespace', 'cgroup_namespace', 'vm_id', 'hypervisor_id',
             'resource_epoch', 'storage_epoch')
_RESOURCES = ('read', 'write', 'log', 'resident', 'inodes', 'extent', 'calls')


class LocalIORefusal(RuntimeError):
    pass


def _need(ok, reason):
    if not ok:
        raise LocalIORefusal(reason)


def _uint(value):
    _need(type(value) is int and 0 <= value <= _MAX, 'invalid unsigned integer')
    return value


def _add(a, b):
    value = _uint(a) + _uint(b)
    _need(value <= _MAX, 'integer overflow')
    return value


def _components(value):
    _need(type(value) is tuple and bool(value), 'path components required')
    for part in value:
        _need(type(part) is str and part not in ('', '.', '..') and
              '/' not in part and '\0' not in part, 'invalid path component')
    return value


@dataclass(frozen=True)
class PathGrant:
    components: tuple
    access: str
    extent: int


@dataclass(frozen=True)
class Bound:
    read: int
    write: int
    log: int
    resident: int
    inodes: int
    extent: int
    calls: int
    paths: tuple = ()


@dataclass(frozen=True)
class Capsule:
    binding: tuple
    root_identity: tuple
    limits: Bound
    deadline_ns: int
    escrow_ref: str
    namespace_admission_ref: str


@dataclass(frozen=True)
class IssuerAuthorization:
    capsule: Capsule
    current_binding: tuple
    root_identity: tuple
    verification_ref: str


class OperationHandle:
    """Opaque token; only exact objects registered by reserve are accepted."""
    __slots__ = ()


class FileHandle:
    __slots__ = ()


@dataclass(frozen=True)
class OperationReceipt:
    operation_id: str
    sequence: int
    bound: Bound
    calls: int
    read_requested: int
    write_requested: int
    log_requested: int
    growth_requested: int
    read_actual: int
    write_actual: int
    outstanding: int


@dataclass(frozen=True)
class Receipt:
    sequence: int
    reserved: Bound
    operations: tuple
    primary: str | None
    secondary: tuple
    unknowns: tuple


@dataclass
class _Operation:
    operation_id: str
    sequence: int
    bound: Bound
    calls: int = 0
    cleanup_slots: int = 0
    read_requested: int = 0
    write_requested: int = 0
    log_requested: int = 0
    growth_requested: int = 0
    read_actual: int = 0
    write_actual: int = 0
    opened_inodes: int = 0
    resident_sources: int = 0
    used_paths: set = field(default_factory=set)


@dataclass
class _File:
    fd: int
    op: _Operation
    grant: PathGrant
    identity: tuple
    size: int


class NativeBackend:
    """Explicit opt-in to local os primitives. No backend is selected by default."""
    __slots__ = ()

    def call(self, name, *args, **kwargs):
        return getattr(os, name)(*args, **kwargs)


def _validate_bound(bound, paths):
    _need(type(bound) is Bound, 'immutable bound required')
    for key in _RESOURCES:
        _uint(getattr(bound, key))
    _need(bound.log <= bound.write, 'log must be included in write')
    _need(type(bound.paths) is tuple and (not paths or bool(bound.paths)), 'paths required')
    seen = set()
    for grant in bound.paths:
        _need(type(grant) is PathGrant, 'immutable path grant required')
        _components(grant.components)
        _need(grant.components not in seen, 'duplicate path')
        seen.add(grant.components)
        _need(type(grant.access) is str and grant.access in ('read', 'pending', 'log'), 'unknown access')
        _need(_uint(grant.extent) <= bound.extent, 'path extent exceeds bound')
    _need(not bound.paths if not paths else True, 'capsule has operation paths')


class LocalSlotIO:
    def __init__(self, capsule, root_fd, verify_issuer, native_backend=None):
        self._lock = threading.RLock()
        self._primary = None
        self._secondary = []
        self._unknowns = []
        self._operations = {}
        self._files = {}
        self._ids = set()
        self._sequence = 0
        self._reserved = {key: 0 for key in _RESOURCES}
        _need(type(native_backend) is NativeBackend, 'native backend unavailable')
        _need(type(capsule) is Capsule, 'immutable capsule required')
        _validate_bound(capsule.limits, False)
        _need(type(capsule.binding) is tuple, 'immutable binding required')
        _need(all(type(row) is tuple and len(row) == 2 and type(row[0]) is str and
                  (type(row[1]) is str and bool(row[1]) or
                   type(row[1]) is int and 0 <= row[1] <= _MAX)
                  for row in capsule.binding), 'invalid immutable identity')
        keys = [row[0] for row in capsule.binding]
        _need(len(set(keys)) == len(keys) and set(_BINDINGS) <= set(keys), 'incomplete identity')
        _need(type(capsule.root_identity) is tuple and len(capsule.root_identity) == 3,
              'native root identity required')
        for value in capsule.root_identity:
            _uint(value)
        _uint(capsule.deadline_ns)
        _need(type(capsule.escrow_ref) is str and bool(capsule.escrow_ref) and
              type(capsule.namespace_admission_ref) is str and bool(capsule.namespace_admission_ref),
              'missing admission references')
        _uint(root_fd)
        _need(callable(verify_issuer), 'trusted issuer required')
        self._capsule, self._root = capsule, root_fd
        self._issuer, self._backend = verify_issuer, native_backend
        self._authorize()

    def _authorize(self):
        _need(time.monotonic_ns() < self._capsule.deadline_ns, 'deadline expired')
        try:
            auth = self._issuer(self._capsule)
        except Exception as exc:
            raise LocalIORefusal('issuer verification failed') from exc
        _need(type(auth) is IssuerAuthorization and auth.capsule == self._capsule and
              auth.current_binding == self._capsule.binding and
              auth.root_identity == self._capsule.root_identity and
              type(auth.verification_ref) is str and bool(auth.verification_ref),
              'issuer capsule or live binding mismatch')
        _need(time.monotonic_ns() < self._capsule.deadline_ns, 'deadline expired during verification')

    def _normal(self):
        _need(self._primary is None, 'slot frozen')
        self._authorize()
        _need(self._primary is None, 'slot frozen during issuer verification')

    def _failed(self, exc):
        reason = str(exc) or type(exc).__name__
        if self._primary is None:
            self._primary = reason
        else:
            self._secondary.append(reason)
        if isinstance(exc, LocalIORefusal):
            return exc
        return LocalIORefusal(reason)

    def reserve(self, operation_id, expected_sequence, inclusive_bound):
        with self._lock:
            try:
                self._normal()
                _need(type(operation_id) is str and bool(operation_id) and
                      operation_id not in self._ids, 'replayed or invalid operation id')
                _need(_uint(expected_sequence) == self._sequence, 'sequence mismatch')
                _need(self._sequence < _MAX, 'sequence exhausted')
                _validate_bound(inclusive_bound, True)
                proposed = {}
                for key in _RESOURCES:
                    proposed[key] = _add(self._reserved[key], getattr(inclusive_bound, key))
                    _need(proposed[key] <= getattr(self._capsule.limits, key), 'escrow exhausted: ' + key)
                handle = OperationHandle()
                self._operations[handle] = _Operation(operation_id, self._sequence, inclusive_bound)
                self._reserved = proposed
                self._ids.add(operation_id)
                self._sequence += 1
                return handle
            except Exception as exc:
                raise self._failed(exc) from exc

    def _operation(self, handle):
        _need(type(handle) is OperationHandle and handle in self._operations, 'unknown operation handle')
        return self._operations[handle]

    def _file(self, handle):
        _need(type(handle) is FileHandle and handle in self._files, 'unknown file handle')
        return self._files[handle]

    def _room(self, op, count):
        _need(_add(_add(op.calls, op.cleanup_slots), count) <= op.bound.calls, 'native call limit')

    def _call(self, op, name, *args, cleanup=False, **kwargs):
        if cleanup:
            _need(op.cleanup_slots > 0, 'missing reserved close')
            op.cleanup_slots -= 1
        else:
            self._normal()
            self._room(op, 1)
        op.calls = _add(op.calls, 1)
        try:
            return self._backend.call(name, *args, **kwargs)
        except BaseException as exc:
            self._unknowns.append((op.operation_id, name, type(exc).__name__))
            raise

    def _close_fd(self, op, fd):
        # Consume before dispatch; never retry a failed close on a reused fd.
        self._call(op, 'close', fd, cleanup=True)

    @staticmethod
    def _identity(info):
        return info.st_dev, info.st_ino, info.st_uid

    def _open(self, handle, components, access):
        with self._lock:
            opened = []
            op = None
            try:
                self._normal()
                op = self._operation(handle)
                _components(components)
                grant = next((p for p in op.bound.paths if p.components == components), None)
                _need(grant is not None and grant.access in access and components not in op.used_paths,
                      'path or access not reserved, or reused')
                # No refund/replay even when open fails.
                op.used_paths.add(components)
                root_info = self._call(op, 'fstat', self._root)
                _need(stat.S_ISDIR(root_info.st_mode) and
                      self._identity(root_info) == self._capsule.root_identity, 'root identity mismatch')
                parent = self._root
                for part in components[:-1]:
                    self._room(op, 2)  # open plus mandatory safe close
                    fd = self._call(op, 'open', part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    dir_fd=parent)
                    op.cleanup_slots += 1
                    opened.append(fd)
                    parent = fd
                is_new = grant.access != 'read'
                _need(op.opened_inodes < op.bound.inodes, 'inode allowance exhausted')
                op.opened_inodes += 1
                self._room(op, 3)  # open, pinned fstat, mandatory close
                flags = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
                flags |= (os.O_WRONLY | os.O_CREAT | os.O_EXCL) if is_new else os.O_RDONLY
                fd = self._call(op, 'open', components[-1], flags, 0o600, dir_fd=parent)
                op.cleanup_slots += 1
                opened.append(fd)
                info = self._call(op, 'fstat', fd)
                _need(stat.S_ISREG(info.st_mode) and info.st_uid == self._capsule.root_identity[2] and
                      info.st_nlink == 1 and _uint(info.st_size) <= grant.extent,
                      'leaf is not an admitted regular exclusive file')
                if not is_new:
                    total = _add(_add(op.resident_sources, op.growth_requested), info.st_size)
                    _need(total <= op.bound.resident, 'source resident allowance exhausted')
                    op.resident_sources = _add(op.resident_sources, info.st_size)
                if is_new:
                    _need(info.st_size == 0 and stat.S_IMODE(info.st_mode) == 0o600,
                          'pending file mode or extent mismatch')
                while len(opened) > 1:
                    intermediate = opened.pop(0)
                    self._close_fd(op, intermediate)
                token = FileHandle()
                self._files[token] = _File(fd, op, grant, self._identity(info), info.st_size)
                opened.pop()
                return token
            except BaseException as exc:
                error = self._failed(exc)
                if op is not None:
                    for fd in reversed(opened):
                        try:
                            self._close_fd(op, fd)
                        except BaseException as secondary:
                            self._failed(secondary)
                raise error from exc

    def open_read(self, handle, components):
        return self._open(handle, components, ('read',))

    def create_pending(self, handle, components):
        return self._open(handle, components, ('pending', 'log'))

    def _pinned(self, file):
        info = self._call(file.op, 'fstat', file.fd)
        _need(stat.S_ISREG(info.st_mode) and self._identity(info) == file.identity and
              info.st_nlink == 1 and info.st_size == file.size, 'file identity or extent changed')

    def _range(self, file, offset, count):
        _need(_uint(count) <= _SLAB, 'slab exceeds 1 MiB')
        end = _add(_uint(offset), count)
        _need(end <= file.grant.extent, 'file extent exceeded')
        return end

    def _debit(self, op, key, count):
        name = key + '_requested'
        total = _add(getattr(op, name), count)
        limit = (op.bound.resident - op.resident_sources) if key == 'growth' else getattr(op.bound, key)
        _need(total <= limit, key + ' allowance exhausted')
        setattr(op, name, total)

    def read_at(self, handle, offset, count):
        with self._lock:
            try:
                self._normal()
                file = self._file(handle)
                _need(file.grant.access == 'read', 'not a read handle')
                self._range(file, offset, count)
                self._room(file.op, 2)
                self._debit(file.op, 'read', count)
                self._pinned(file)
                data = self._call(file.op, 'pread', file.fd, count, offset)
                _need(type(data) is bytes and len(data) <= count, 'invalid read outcome')
                file.op.read_actual = _add(file.op.read_actual, len(data))
                return data
            except BaseException as exc:
                raise self._failed(exc) from exc

    def write_at(self, handle, offset, data):
        with self._lock:
            try:
                self._normal()
                file = self._file(handle)
                _need(file.grant.access in ('pending', 'log') and type(data) is bytes, 'not writable bytes')
                end = self._range(file, offset, len(data))
                op = file.op
                self._room(op, 2)
                # Validate every debit before committing any of them.
                growth = max(0, end - file.size)
                _need(_add(op.write_requested, len(data)) <= op.bound.write and
                      _add(_add(op.growth_requested, op.resident_sources), growth) <= op.bound.resident and
                      (file.grant.access != 'log' or _add(op.log_requested, len(data)) <= op.bound.log),
                      'write/log/resident allowance exhausted')
                self._debit(op, 'write', len(data))
                self._debit(op, 'growth', growth)
                if file.grant.access == 'log':
                    self._debit(op, 'log', len(data))
                self._pinned(file)
                actual = self._call(op, 'pwrite', file.fd, data, offset)
                _need(type(actual) is int and 0 <= actual <= len(data), 'invalid write outcome')
                op.write_actual = _add(op.write_actual, actual)
                if actual:
                    file.size = max(file.size, offset + actual)
                return actual
            except BaseException as exc:
                raise self._failed(exc) from exc

    def truncate(self, handle, size):
        with self._lock:
            try:
                self._normal()
                file = self._file(handle)
                _need(file.grant.access in ('pending', 'log'), 'immutable read file')
                _need(_uint(size) <= file.grant.extent, 'truncate extent exceeded')
                self._room(file.op, 2)
                self._debit(file.op, 'growth', max(0, size - file.size))
                self._pinned(file)
                self._call(file.op, 'ftruncate', file.fd, size)
                file.size = size
            except BaseException as exc:
                raise self._failed(exc) from exc

    def flush(self, handle):
        with self._lock:
            try:
                self._normal()
                file = self._file(handle)
                self._room(file.op, 2)
                self._pinned(file)
                self._call(file.op, 'fsync', file.fd)
            except BaseException as exc:
                raise self._failed(exc) from exc

    def close(self, handle):
        with self._lock:
            try:
                file = self._file(handle)
                del self._files[handle]
                self._close_fd(file.op, file.fd)
            except BaseException as exc:
                raise self._failed(exc) from exc

    def freeze(self, primary):
        with self._lock:
            _need(type(primary) is str and bool(primary), 'canonical primary required')
            if self._primary is None:
                self._primary = primary
            elif primary != self._primary:
                self._secondary.append(primary)

    def receipt(self):
        with self._lock:
            rows = tuple(OperationReceipt(
                op.operation_id, op.sequence, op.bound, op.calls,
                op.read_requested, op.write_requested, op.log_requested,
                op.growth_requested, op.read_actual, op.write_actual, op.cleanup_slots)
                for op in self._operations.values())
            return Receipt(self._sequence, Bound(**self._reserved), rows,
                           self._primary, tuple(self._secondary), tuple(self._unknowns))
