"""Single preconsumed B0 slot: owning adapters, never a campaign signer.

No deployment is selected by import. NativeBinding is the trusted-root deployment
port: its missing consume/domain/STOP implementation refuses. Constructing records,
passing a digest or returning True is not authentication. The retained supervisor
forks one blocked child, binds its actual PID/start, seals then transfers an fd;
it never execs over the issuer. No scientific acceptance is inferred here.
"""
from dataclasses import dataclass, fields
import array
import fcntl
import hashlib
import os
import socket
import signal
import stat
import struct
import threading
import time

_MAX = (1 << 64) - 1
_MAX_CAPSULE = 1 << 20
_CONSTRUCTION_KEY = object()
_SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL


class ProviderRefusal(RuntimeError):
    pass


def _need(ok, reason):
    if not ok:
        raise ProviderRefusal(reason)


def _uint(value):
    _need(type(value) is int and 0 <= value <= _MAX, 'invalid uint64')
    return value


@dataclass(frozen=True)
class Budget:
    read: int = 0
    write: int = 0
    log: int = 0
    resident: int = 0
    inodes: int = 0
    calls: int = 0
    scopes: int = 0
    wall_ns: int = 0
    memory: int = 0

    def __post_init__(self):
        for field in fields(self):
            _uint(getattr(self, field.name))
        _need(self.log <= self.write, 'log must be included in write')


def _plus(a, b):
    _need(type(a) is Budget and type(b) is Budget, 'typed budget required')
    return Budget(**{f.name: _uint(getattr(a, f.name) + getattr(b, f.name)) for f in fields(a)})


def _fits(a, b):
    return all(getattr(a, f.name) <= getattr(b, f.name) for f in fields(a))


def partition_budget(parent, children):
    _need(type(children) is tuple, 'immutable child partition required')
    total = Budget()
    for child in children:
        total = _plus(total, child)
    _need(_fits(total, parent), 'overlapping or excessive delegate allowance')
    return children


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    start_ticks: int
    uid: int
    boot: str
    executable: tuple
    mount_namespace: int
    cgroup_namespace: int


def live_identity(pid):
    """Fresh Linux identity, checked again around metadata capture for PID reuse."""
    _need(type(pid) is int and pid > 0, 'invalid PID')
    def start():
        with open('/proc/' + str(pid) + '/stat', 'rb') as stream:
            raw = stream.read(16384)
        return int(raw.rpartition(b') ')[2].split()[19])
    before = start()
    with open('/proc/' + str(pid) + '/status', encoding='ascii') as stream:
        lines = stream.read(32768).splitlines()
    uids = tuple(map(int, next(row for row in lines if row.startswith('Uid:')).split()[1:]))
    _need(len(uids) == 4 and len(set(uids)) == 1, 'mixed process credentials')
    with open('/proc/sys/kernel/random/boot_id', encoding='ascii') as stream:
        boot = stream.read(128).strip()
    info = os.stat('/proc/' + str(pid) + '/exe')
    mnt = os.stat('/proc/' + str(pid) + '/ns/mnt').st_ino
    cg = os.stat('/proc/' + str(pid) + '/ns/cgroup').st_ino
    _need(before == start() and before > 0, 'PID reused during identity read')
    return ProcessIdentity(pid, before, uids[0], boot, (info.st_dev, info.st_ino), mnt, cg)


@dataclass(frozen=True)
class DomainProof:
    domain: str
    backing: tuple
    kind: str
    carrier_bytes: int
    inode_ceiling: int
    mount_namespace: int
    consumers: tuple
    readback_ref: str


def validate_domains(proofs, placements):
    """Validate authenticated adopted thick carriers, dedup aliases by backing.

    Proof provenance and root dirfd/dev/ino/project/permissions/complete alias and
    metadata coverage are checked by NativeBinding.collect_bound_domain, before
    this structural check. A project quota alone cannot satisfy this interface.
    """
    _need(type(proofs) is tuple and proofs and type(placements) is tuple and placements,
          'domain backend unavailable')
    domains = {}; backings = set(); roles = set()
    for proof in proofs:
        _need(type(proof) is DomainProof and proof.kind == 'fixed_thick', 'unbounded backing')
        _need(type(proof.domain) is str and proof.domain and proof.domain not in domains,
              'duplicate domain')
        _need(type(proof.backing) is tuple and proof.backing and proof.backing not in backings,
              'duplicate backing alias must use one domain')
        _need(_uint(proof.carrier_bytes) > 0 and _uint(proof.inode_ceiling) > 0 and
              _uint(proof.mount_namespace) > 0 and type(proof.readback_ref) is str and
              proof.readback_ref and type(proof.consumers) is tuple and proof.consumers,
              'missing native domain readback')
        domains[proof.domain] = proof; backings.add(proof.backing)
    used = set()
    for row in placements:
        _need(type(row) is tuple and len(row) == 2, 'placement tuple required')
        role, domain = row
        _need(type(role) is str and role and role not in roles and domain in domains,
              'unaccounted or duplicate USED root')
        roles.add(role); used.add(domain)
    _need(used == set(domains), 'extra domain outside USED mapping')
    return tuple(sorted(used))


@dataclass(frozen=True)
class AdoptedDomainSpec:
    """Trusted deployment inventory; descriptors remain exclusively owned.

    inventory_ref authenticates complete fixed/thick/no-COW/no-snapshot backing
    map, role containment and metadata ceiling. This collector does not infer
    these facts from fstatvfs or turn an ordinary quota into a physical bound.
    """
    domain: str
    root_fd: int
    carrier_fd: int
    root_identity: tuple
    backing: tuple
    mount_id: int
    mount_namespace: int
    carrier_bytes: int
    inode_ceiling: int
    consumers: tuple
    inventory_ref: str
    owner_uid: int = 3000


def collect_bound_domain(specs):
    """Read back already owned fixed block filesystems; never create/format one.

    This is the native observation adapter after deployment authentication. Its
    result alone cannot authenticate inventory/containment or authorize a slot.
    Descriptors, mount and backing inventory must remain owned through STOP.
    """
    _need(type(specs) is tuple and specs, 'adopted domain inventory unavailable')
    output = []
    namespace = os.stat('/proc/self/ns/mnt').st_ino
    with open('/proc/self/mountinfo', encoding='utf-8') as stream:
        mountinfo = stream.read(1 << 20)
    _need(len(mountinfo) < 1 << 20, 'mount inventory exceeds bound')
    mounts = {int(row.split()[0]): row.split() for row in mountinfo.splitlines()}
    for spec in specs:
        _need(type(spec) is AdoptedDomainSpec and spec.inventory_ref and
              namespace == spec.mount_namespace, 'unbound domain inventory')
        root = os.fstat(spec.root_fd); carrier = os.fstat(spec.carrier_fd)
        _need(stat.S_ISDIR(root.st_mode) and
              (root.st_dev, root.st_ino, root.st_uid) == spec.root_identity and
              root.st_uid == _uint(spec.owner_uid) and stat.S_ISBLK(carrier.st_mode) and
              root.st_dev == carrier.st_rdev, 'native root/carrier identity changed')
        row = mounts.get(spec.mount_id)
        _need(row and row[2] == str(os.major(root.st_dev)) + ':' + str(os.minor(root.st_dev)),
              'mount/backing identity changed')
        separator = row.index('-')
        _need(row[separator + 1] == 'ext4' and 'rw' in row[5].split(','),
              'unsupported or readonly adopted filesystem')
        capacity = struct.unpack('Q', fcntl.ioctl(spec.carrier_fd, 0x80081272, bytes(8)))[0]
        usage = os.fstatvfs(spec.root_fd)
        _need(capacity == _uint(spec.carrier_bytes) and
              usage.f_blocks * usage.f_frsize <= capacity and
              0 < usage.f_files <= _uint(spec.inode_ceiling), 'fixed kernel ceiling mismatch')
        _need((os.fstat(spec.root_fd).st_dev, os.fstat(spec.root_fd).st_ino) ==
              spec.root_identity[:2] and os.stat('/proc/self/ns/mnt').st_ino == namespace,
              'domain changed during readback')
        output.append(DomainProof(spec.domain, spec.backing, 'fixed_thick', capacity,
                                  usage.f_files, namespace, spec.consumers, spec.inventory_ref))
    return tuple(output)


@dataclass(frozen=True)
class AuthenticatedCapsule:
    digest: str
    consume_ref: str
    cp_revision: str
    slot_id: str
    attempt_id: str
    nonce: str
    issuer: ProcessIdentity
    worker: ProcessIdentity
    binding: tuple
    deadline_ns: int
    total: Budget
    stop: Budget
    domains: tuple
    placements: tuple
    profiles_digest: str
    controller_receipt: str


@dataclass(frozen=True)
class CaptureDescriptor:
    digest: str
    profile_digest: str
    shape_type_bytes: tuple
    inclusive: Budget
    delegates: tuple
    capture_index: int = 0


@dataclass(frozen=True)
class CapturedContent:
    descriptor_digest: str
    content_digest: str
    publication_digest: str
    sealed_fds: tuple
    verification_ref: str


@dataclass(frozen=True)
class NativeDelegation:
    attempt_id: str
    descriptor_digest: str
    index: int
    bound: Budget
    native_handle: object
    reference: str


@dataclass(frozen=True)
class Settlement:
    sequence: int
    requested: Budget
    actual: Budget | None
    unknown: tuple
    reference: str


@dataclass(frozen=True)
class StopResult:
    status: str
    primary: str
    verified_generation: str | None
    quiescence_ref: str | None
    settlement: Settlement


class NativeBinding:
    """Deployment-owned trusted port; no Boolean or user JSON fallback.

    authenticate_consume verifies the existing Root CAS predebit and one slot,
    source/model/P0/criteria/runtime/job bindings, controller allowance already
    granted BEFORE ORM effects, and no refund/reissue after unknown. It does not
    consume again. claim_once is an irreversible issuer registry (survives worker
    death), never an in-worker set. collect_bound_domain authenticates all USED
    worker AND genuine AiiDA/controller roots and all backing aliases. Runtime
    adapters must provide native readback, not caller flags. No default backend.
    """
    def issuer_identity(self):
        # Must authenticate live S via the credentialled retained channel/pidfd;
        # worker need not read root-only /proc/S/exe.
        raise ProviderRefusal('live root issuer channel unavailable')

    def prepare_launch(self, consume):
        """Legacy test adapters have no Linux setup; Site overrides before fork."""

    def prepare_child(self, control_fd):
        """Site closes Root custody and contains the child before credential drop."""

    def authenticate_consume(self, record):
        raise ProviderRefusal('Root consume backend unavailable')

    def capsule_for_child(self, consume, issuer, blocked_child):
        raise ProviderRefusal('capsule construction backend unavailable')

    def verify_capsule(self, raw, envelope, issuer, worker):
        raise ProviderRefusal('capsule verification backend unavailable')

    def claim_once(self, capsule):
        raise ProviderRefusal('issuer single-use registry unavailable')

    def collect_bound_domain(self, capsule):
        raise ProviderRefusal('adopted thick domain backend unavailable')

    def check_current(self, capsule):
        raise ProviderRefusal('live scheduler/epoch backend unavailable')

    def reserve_stop(self, capsule):
        raise ProviderRefusal('STOP profile backend unavailable')

    def verify_descriptor(self, capsule, descriptor):
        raise ProviderRefusal('capture profile backend unavailable')

    def verify_capture(self, capsule, descriptor, captured):
        raise ProviderRefusal('sealed snapshot backend unavailable')

    def delegate(self, capsule, permit, index, bound):
        raise ProviderRefusal('native subordinate backend unavailable')

    def settle_delegate(self, capsule, permit, index, receipt):
        raise ProviderRefusal('native settlement backend unavailable')

    def freeze_normal(self, capsule, primary):
        raise ProviderRefusal('native normal-growth freeze unavailable')

    def quiesce_job(self, capsule, stop_permit, primary):
        raise ProviderRefusal('job/step/PID/fd STOP backend unavailable')

    def supervise_child(self, pid, pidfd, capsule_fd, control_channel):
        raise ProviderRefusal('retained supervisor backend unavailable')


def _typed_backend(backend):
    _need(isinstance(backend, NativeBinding), 'native binding unavailable')
    return backend


def seal_job_capsule(raw):
    """Root-only sealed immutable bytes; return read-only fd, never a pathname."""
    _need(os.geteuid() == 0 and type(raw) is bytes and 0 < len(raw) <= _MAX_CAPSULE,
          'root capsule bytes required')
    fd = os.memfd_create('qcl-b0-authority', os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    try:
        done = 0
        while done < len(raw):
            written = os.write(fd, raw[done:]); _need(written > 0, 'capsule short write')
            done += written
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, _SEALS)
        return os.open('/proc/self/fd/' + str(fd), os.O_RDONLY | os.O_CLOEXEC)
    finally:
        os.close(fd)


def _capsule_bytes(fd):
    _uint(fd); info = os.fstat(fd)
    _need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
          0 < info.st_size <= _MAX_CAPSULE, 'invalid root authority fd')
    _need(fcntl.fcntl(fd, fcntl.F_GET_SEALS) & _SEALS == _SEALS,
          'authority fd not sealed')
    _need(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY,
          'authority fd not readonly')
    raw = os.pread(fd, info.st_size + 1, 0)
    _need(len(raw) == info.st_size, 'incomplete authority fd')
    return raw


@dataclass(frozen=True)
class ChildTerminalReceipt:
    pid: int
    start_ticks: int
    wait_status: int
    quiescence_ref: str


def _start_ticks(pid):
    with open('/proc/' + str(pid) + '/stat', 'rb') as stream:
        return int(stream.read(16384).rpartition(b') ')[2].split()[19])


def _cleanup_owned_child(pid, pidfd, start_ticks, deadline_ns):
    """Exclusive fork custody; no other thread may reap this child.

    WNOHANG establishes an unreaped owned child before fallback PID signalling;
    boot/start readback excludes changed identity. No blocking wait syscall.
    ECHILD means this supervisor/backend has already reaped its owned child.
    """
    try:
        waited, status = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return
    if waited == pid:
        return
    if pidfd is not None:
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        except ProcessLookupError:
            pass
    else:
        # With exclusive wait custody this PID cannot be recycled: it is our
        # live, unreaped child. Validate captured start when available as well.
        if start_ticks is not None:
            _need(_start_ticks(pid) == start_ticks, 'cleanup child PID identity changed')
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    while time.monotonic_ns() < deadline_ns:
        try:
            waited, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return
        if waited == pid:
            return
        time.sleep(0.001)
    raise ProviderRefusal('child cleanup unknown: bounded reap deadline')


def _received_rights(ancillary):
    """Collect every complete installed fd before interpreting any message guard."""
    handles = set()
    for level, kind, payload in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            width = array.array('i').itemsize
            descriptors = array.array('i')
            descriptors.frombytes(payload[:len(payload) - len(payload) % width])
            handles.update(descriptors)
    return handles


def _close_rights(handles):
    for descriptor in handles:
        try:
            os.close(descriptor)
        except OSError:
            pass


class FixedRootSupervisor:
    """One retained root parent, one gated child; fixed approved argv only.

    Deployment constructs this with its immutable approved Code argv/environment.
    The unprivileged caller never supplies an executable, environment or shell.
    All pre-exec reads/calls belong to the admitted launch/STOP profile. Backend
    supervise_child must retain this issuer until complete native quiescence.
    """
    def __init__(self, backend, approved_argv, approved_env, bootstrap_timeout_seconds=None, approved_worker_executable=None):
        self.backend = _typed_backend(backend)
        _need(type(approved_argv) is tuple and approved_argv and
              approved_argv[0].startswith('/nix/store/'), 'immutable fixed solver required')
        _need(type(approved_env) is tuple, 'fixed environment required')
        _need(type(bootstrap_timeout_seconds) in (int, float) and
              0 < bootstrap_timeout_seconds <= 60, 'bounded bootstrap timeout required')
        _need(type(approved_worker_executable) is tuple and len(approved_worker_executable) == 2 and
              all(type(value) is int and value > 0 for value in approved_worker_executable),
              'fixed post-exec worker executable identity required')
        self._worker_executable = approved_worker_executable
        self.argv, self.env = approved_argv, approved_env
        self._bootstrap_timeout = bootstrap_timeout_seconds
        self._used = False

    def launch(self, consume_record):
        _need(os.geteuid() == 0 and not self._used, 'root launcher already used or unavailable')
        consume = self.backend.authenticate_consume(consume_record)
        _need(type(consume) is bytes and consume, 'authenticated consume record required')
        self._used = True  # no retry, even after uncertain fork/send
        self.backend.prepare_launch(consume)
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        child.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        parent_pid = os.getpid()
        pid = os.fork()
        if pid == 0:
            parent.close()
            try:
                # Linux PR_SET_PDEATHSIG, then close fork/parent-death race.
                import ctypes
                libc = ctypes.CDLL(None, use_errno=True)
                self.backend.prepare_child(child.fileno())
                os.setgroups([]); os.setgid(3000); os.setuid(3000)
                # Credential changes clear PDEATHSIG, so install it AFTER drop.
                _need(libc.prctl(1, 9, 0, 0, 0) == 0 and os.getppid() == parent_pid,
                      'parent death action unavailable')
                os.set_inheritable(child.fileno(), True)
                env = dict(self.env); env['QCL_B0_CONTROL_FD'] = str(child.fileno())
                # Approved Runner starts only its pre-reserved bootstrap recipe,
                # sends HELLO and blocks for authority before scientific effects.
                os.execve(self.argv[0], self.argv, env)
            finally:
                os._exit(126)
        child.close(); fd = None; pidfd = None; child_start = None; primary = None
        try:
            child_start = _start_ticks(pid)
            pidfd = os.pidfd_open(pid, 0)
            parent.settimeout(self._bootstrap_timeout)
            hello, ancillary, flags, _ = parent.recvmsg(5,
                socket.CMSG_SPACE(struct.calcsize('3i')) + socket.CMSG_SPACE(64),
                socket.MSG_CMSG_CLOEXEC)
            delivered = _received_rights(ancillary)
            _close_rights(delivered)  # HELLO never accepts any transferred fd
            _need(hello == b'HELLO' and flags & ~socket.MSG_CMSG_CLOEXEC == 0 and len(ancillary) == 1 and not delivered,
                  'missing credentialled worker hello')
            level, kind, payload = ancillary[0]
            _need(level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS,
                  'missing worker kernel credentials')
            peer_pid, peer_uid, peer_gid = struct.unpack('3i', payload)
            _need((peer_pid, peer_uid, peer_gid) == (pid, 3000, 3000), 'worker credentials mismatch')
            issuer, worker = live_identity(os.getpid()), live_identity(pid)
            _need(worker.uid == 3000 and worker.executable == self._worker_executable,
                  'worker did not exec approved solver')
            raw = self.backend.capsule_for_child(consume, issuer, worker)
            fd = seal_job_capsule(raw)
            parent.sendmsg([b'B'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))])
            terminal = self.backend.supervise_child(pid, pidfd, fd, parent)
            _need(type(terminal) is ChildTerminalReceipt and terminal.pid == pid and
                  terminal.start_ticks == child_start and type(terminal.wait_status) is int and
                  type(terminal.quiescence_ref) is str and terminal.quiescence_ref,
                  'missing typed child terminal/custody receipt')
            try:
                waited, status = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                waited, status = pid, terminal.wait_status
            _need(waited == pid and status == terminal.wait_status, 'backend returned before child terminal/reap')
            return terminal
        except BaseException as error:
            primary = error
            raise
        finally:
            parent.close()
            if fd is not None:
                os.close(fd)
            try:
                # STOP cleanup has its own finite tail, even after HELLO timeout.
                cleanup_deadline = time.monotonic_ns() + int(self._bootstrap_timeout * 1_000_000_000)
                _cleanup_owned_child(pid, pidfd, child_start, cleanup_deadline)
            except Exception as cleanup_error:
                if primary is not None:
                    primary.add_note('cleanup unknown: ' + str(cleanup_error))
                else:
                    raise
            finally:
                if pidfd is not None:
                    os.close(pidfd)



def receive_job_capsule(control_fd, native_binding):
    """Approved worker bootstrap, within its prepaid startup profile.

    Kernel credentials authenticate root peer; deployment backend pins exact live
    issuer PID/start/boot/executable via Root launch readback and retained channel.
    Keep this channel open for every lease and STOP; loss freezes the attempt.
    """
    backend = _typed_backend(native_binding)
    channel = socket.socket(fileno=os.dup(control_fd))
    handles = set()
    try:
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        channel.send(b'HELLO')
        raw, ancillary, flags, _ = channel.recvmsg(1,
            socket.CMSG_SPACE(struct.calcsize('3i')) + socket.CMSG_SPACE(64),
            socket.MSG_CMSG_CLOEXEC)
        handles = _received_rights(ancillary)
        _need(raw == b'B' and flags & ~socket.MSG_CMSG_CLOEXEC == 0 and len(ancillary) == 2, 'invalid root handshake')
        credentials = []; rights_count = 0
        for level, kind, payload in ancillary:
            _need(level == socket.SOL_SOCKET, 'unknown bootstrap ancillary')
            if kind == socket.SCM_RIGHTS:
                rights_count += 1
                _need(len(payload) == array.array('i').itemsize, 'invalid rights payload')
            elif kind == socket.SCM_CREDENTIALS:
                credentials.append(struct.unpack('3i', payload))
            else:
                raise ProviderRefusal('unknown bootstrap ancillary')
        _need(len(handles) == 1 and rights_count == 1 and len(credentials) == 1, 'ambiguous authority handshake')
        issuer = backend.issuer_identity()
        _need(type(issuer) is ProcessIdentity and
              credentials[0][:2] == (issuer.pid, 0) and issuer.uid == 0 and os.getppid() == issuer.pid,
              'root issuer credential mismatch')
        descriptor = next(iter(handles))
        _capsule_bytes(descriptor)
        handles.clear()  # exact one fd custody transferred to caller
        return descriptor
    except Exception:
        _close_rights(handles)
        raise
    finally:
        channel.close()  # original control_fd remains retained by owning backend


class _Ledger:
    def __init__(self, total, stop):
        _need(_fits(stop, total), 'STOP does not fit total')
        self.total, self.stop, self.used = total, stop, Budget()
        self.primary = None

    def reserve(self, bound):
        _need(self.primary is None, 'normal grants frozen')
        proposed = _plus(self.used, bound)
        _need(_fits(_plus(proposed, self.stop), self.total), 'inclusive operation plus STOP exceeds slot')
        self.used = proposed  # never refund failed/partial/EOF/unknown operations

    def freeze(self, primary):
        if self.primary is None:
            self.primary = str(primary) or 'unknown failure'


class CapturePermit:
    __slots__ = ()


class StopPermit:
    __slots__ = ()


class SingleB0Authority:
    """Opaque in-process handles; all effects use disjoint backend delegates.

    Descriptor-only reservation comes before snapshot allocation/read/copy/hash.
    A child debit is carved from its inclusive parent once, never charged twice.
    Native HDF callbacks use native counters; Python is not their callback path.
    """
    def __init__(self, capsule, backend, stop_binding, _key=None):
        _need(_key is _CONSTRUCTION_KEY, 'private authority constructor')
        self._freeze_unknown = None
        self._capsule, self._backend = capsule, backend
        self._lock = threading.RLock()
        self._thread = threading.get_ident()
        self._ledger = _Ledger(capsule.total, capsule.stop)
        self._permits = {}; self._seen = set(); self._sequence = 0
        self._stop = StopPermit(); self._stop_binding = stop_binding
        self._stop_used = False

    def _current(self):
        _need(threading.get_ident() == self._thread, 'foreign owning task')
        _need(time.monotonic_ns() < self._capsule.deadline_ns, 'slot deadline expired')
        _need(self._backend.issuer_identity() == self._capsule.issuer and
              os.getppid() == self._capsule.issuer.pid and
              live_identity(os.getpid()) == self._capsule.worker, 'live issuer/worker mismatch')
        observed = self._backend.check_current(self._capsule)
        _need(type(observed) is AuthenticatedCapsule and observed == self._capsule,
              'scheduler/epoch binding changed')

    def reserve_before_capture(self, descriptor, sequence):
        with self._lock:
            try:
                self._current()
                _need(type(descriptor) is CaptureDescriptor and type(sequence) is int and
                      sequence == self._sequence and descriptor.digest not in self._seen,
                      'descriptor replay or sequence mismatch')
                verified = self._backend.verify_descriptor(self._capsule, descriptor)
                _need(type(verified) is CaptureDescriptor and verified == descriptor,
                      'unverified complete capture/writer profile')
                partition_budget(descriptor.inclusive, descriptor.delegates)
                _need(type(descriptor.capture_index) is int and
                      len(descriptor.delegates) >= 2 and
                      0 <= descriptor.capture_index < len(descriptor.delegates),
                      'capture must have reserved delegate')
                self._ledger.reserve(descriptor.inclusive)
                permit = CapturePermit()
                self._permits[permit] = [descriptor, 'reserved', set(), {}]
                self._seen.add(descriptor.digest); self._sequence = _uint(self._sequence + 1)
                return permit
            except Exception as error:
                self._normal_failed(error); raise

    def bind_captured_content(self, permit, captured):
        with self._lock:
            try:
                self._current(); _need(self._ledger.primary is None, 'normal grants frozen')
                row = self._permits.get(permit)
                _need(row is not None and row[1] == 'reserved' and type(captured) is CapturedContent and
                      captured.descriptor_digest == row[0].digest and
                      row[0].capture_index in row[3], 'capture handle reused, unaccounted or foreign')
                verified = self._backend.verify_capture(self._capsule, row[0], captured)
                _need(type(verified) is CapturedContent and verified == captured,
                      'snapshot/envelope not authenticated')
                row[1] = 'captured'
                return permit
            except Exception as error:
                self._normal_failed(error); raise

    def delegate_native(self, permit, index):
        with self._lock:
            try:
                self._current(); _need(self._ledger.primary is None, 'normal grants frozen')
                row = self._permits.get(permit)
                _need(row is not None and type(index) is int and
                      0 <= index < len(row[0].delegates) and index not in row[2] and
                      ((row[1] == 'reserved' and index == row[0].capture_index) or
                       (row[1] == 'captured' and index != row[0].capture_index)),
                      'delegate reused or foreign')
                row[2].add(index)  # uncertain backend outcome spends this child
                child = self._backend.delegate(self._capsule, permit, index, row[0].delegates[index])
                _need(type(child) is NativeDelegation and child.attempt_id == self._capsule.attempt_id and
                      child.descriptor_digest == row[0].digest and child.index == index and
                      child.bound == row[0].delegates[index] and child.reference and
                      child.native_handle is not None and type(child.native_handle) is not bool,
                      'native delegate authentication unavailable')
                return child
            except Exception as error:
                self._normal_failed(error); raise

    def settle_native(self, permit, index, receipt):
        with self._lock:
            try:
                self._current()
                row = self._permits.get(permit)
                _need(row is not None and type(index) is int and index in row[2] and
                      index not in row[3] and type(receipt) is Settlement,
                      'foreign or duplicate settlement')
                verified = self._backend.settle_delegate(self._capsule, permit, index, receipt)
                _need(type(verified) is Settlement and verified == receipt and receipt.reference and
                      receipt.sequence == index and
                      _fits(receipt.requested, row[0].delegates[index]) and
                      receipt.actual is not None and _fits(receipt.actual, receipt.requested) and
                      not receipt.unknown, 'unknown or unverified native settlement')
                row[3][index] = receipt
                if len(row[3]) == len(row[0].delegates):
                    row[1] = 'finished'
                return receipt
            except Exception as error:
                self._normal_failed(error); raise

    def _normal_failed(self, primary):
        # Called under the same mutex by EVERY normal exception path; revoke
        # outstanding native siblings before exposing the failure to callers.
        self._ledger.freeze(primary)
        try:
            self._backend.freeze_normal(self._capsule, self._ledger.primary)
        except Exception as error:
            self._freeze_unknown = str(error) or type(error).__name__

    def freeze_normal(self, primary):
        with self._lock:
            self._normal_failed(primary)
            return self._stop

    def quiesce_job(self, permit):
        with self._lock:
            _need(permit is self._stop and not self._stop_used and self._ledger.primary is not None,
                  'invalid or reused STOP permit')
            self._stop_used = True
            result = self._backend.quiesce_job(self._capsule, self._stop_binding, self._ledger.primary)
            _need(type(result) is StopResult and result.primary == self._ledger.primary and
                  result.status in ('paused', 'failed', 'unknown') and
                  type(result.settlement) is Settlement and result.settlement.reference and
                  _fits(result.settlement.requested, self._capsule.stop) and
                  (result.settlement.actual is None or
                   _fits(result.settlement.actual, result.settlement.requested)),
                  'missing terminal STOP receipt')
            if result.status == 'paused':
                _need(self._freeze_unknown is None and result.quiescence_ref and
                      result.settlement.actual is not None and not result.settlement.unknown, 'unproved STOP cannot pass')
            return result


def verify_authority(capsule_fd, native_binding=None, envelope=None):
    """Authenticate exact inherited fd/live binding before allocation or grants."""
    backend = _typed_backend(native_binding)
    raw = _capsule_bytes(capsule_fd)
    issuer, worker = backend.issuer_identity(), live_identity(os.getpid())
    _need(type(issuer) is ProcessIdentity and os.getppid() == issuer.pid and
          issuer.uid == 0 and worker.uid == 3000, 'wrong issuer/worker UID')
    capsule = backend.verify_capsule(raw, envelope, issuer, worker)
    _need(type(capsule) is AuthenticatedCapsule and capsule.issuer == issuer and capsule.worker == worker and
          capsule.digest == hashlib.sha256(raw).hexdigest() and capsule.consume_ref and capsule.cp_revision and
          capsule.nonce and capsule.controller_receipt and capsule.binding and capsule.profiles_digest and
          time.monotonic_ns() < _uint(capsule.deadline_ns), 'unverified capsule identity')
    return capsule


def bind_single_b0(capsule_fd, native_binding=None, envelope=None):
    backend = _typed_backend(native_binding)
    capsule = verify_authority(capsule_fd, backend, envelope)
    # Claim precedes allocation/reservation; replay cannot mint another STOP.
    claimed = backend.claim_once(capsule)
    _need(type(claimed) is AuthenticatedCapsule and claimed == capsule, 'single-use claim refused')
    domains = backend.collect_bound_domain(capsule)
    _need(type(domains) is tuple and domains == capsule.domains, 'domain readback mismatch')
    validate_domains(domains, capsule.placements)
    stop = backend.reserve_stop(capsule)
    _need(type(stop) is Settlement and stop.reference and stop.requested == capsule.stop and
          stop.actual is not None and not stop.unknown, 'STOP reservation unavailable')
    return SingleB0Authority(capsule, backend, stop, _CONSTRUCTION_KEY)
