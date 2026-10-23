"""Linux worker half of one already consumed B0; no campaign issuer.

Source candidate only. M1 has no controller producer/induced-I/O proof and no
qualified native-kit attach transport. The public scientific entry refuses
before fork. Worker-only inventory and lifecycle code never implies full BIND.
Only Root's protected AF_UNIX publisher may supply descriptor custody. JSON is
finite technical data, never an executable, command, path callback or issuer.
"""
from dataclasses import asdict, dataclass, fields
import array
import ctypes
import fcntl
import hashlib
import json
import os
import re
import select
import signal
import socket
import stat
import struct
import time
import zlib
import slurm_job_evidence as job_evidence

from scientific_b0_provider import (
    NativeBinding, ProviderRefusal, ProcessIdentity, AdoptedDomainSpec,
    AuthenticatedCapsule, Budget, CaptureDescriptor, CapturedContent,
    NativeDelegation, Settlement, StopResult, ChildTerminalReceipt,
    FixedRootSupervisor, _need, _uint, _fits, _plus, _Ledger,
    _capsule_bytes, _received_rights, _close_rights, live_identity,
    collect_bound_domain as observe_domains, validate_domains,
    _cleanup_owned_child,
)

PACKET_MAX = 65536
RECORD_MAX = 4096
RECORD_COUNT = 32
TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,95}\Z')
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
STATES = ('PRECONSUMED', 'CONTROLLER_BOUND', 'NODES_BOUND', 'WORKER_CLAIMED',
          'CAPSULE_SENT', 'AUTHORITY_CLAIMED', 'NORMAL', 'FREEZING', 'STOPPING',
          'PAYLOAD_QUIESCENT', 'TERMINAL_VERIFIED', 'TERMINAL_FAILED', 'SPENT_UNKNOWN')
EDGES = {state: (STATES[index + 1], 'SPENT_UNKNOWN') for index, state in enumerate(STATES[:-3])}
EDGES['PAYLOAD_QUIESCENT'] = ('TERMINAL_VERIFIED', 'TERMINAL_FAILED', 'SPENT_UNKNOWN')
EDGES['TERMINAL_VERIFIED'] = EDGES['TERMINAL_FAILED'] = EDGES['SPENT_UNKNOWN'] = ()
# These are implementation coverage, not caller configuration booleans. B1 and
# Runner native attach need their own reviewed source before this can change.
CONTROLLER_IMPLEMENTED = False
NATIVE_ATTACH_IMPLEMENTED = False


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def decode(raw, limit=PACKET_MAX):
    _need(type(raw) is bytes and 0 < len(raw) <= limit, 'bounded canonical record required')
    def pairs(items):
        output = {}
        for key, value in items:
            _need(key not in output, 'duplicate key')
            output[key] = value
        return output
    def reject(_value):
        raise ProviderRefusal('float/nonfinite numeric value forbidden')
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_float=reject, parse_constant=reject)
        _need(type(value) is dict and canonical(value) == raw, 'noncanonical record')
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ProviderRefusal('invalid bounded JSON') from error


def exact(row, keys):
    _need(type(row) is dict and set(row) == set(keys), 'unknown/missing fields')
    return row


def token(value):
    _need(type(value) is str and TOKEN.fullmatch(value), 'invalid bounded identifier')
    return value


def digest(value):
    _need(type(value) is str and DIGEST.fullmatch(value), 'invalid SHA256')
    return value


def read_fd(fd, maximum):
    before = os.fstat(fd)
    _need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum, 'invalid descriptor size/type')
    raw = os.pread(fd, before.st_size + 1, 0)
    after = os.fstat(fd)
    _need(len(raw) == before.st_size and
          (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
          (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
          'descriptor changed during read')
    return raw


def root_file(fd, writable=False):
    info = os.fstat(fd)
    _need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
          stat.S_IMODE(info.st_mode) == 0o600, 'protected root file required')
    access = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
    _need(access == (os.O_RDWR if writable else os.O_RDONLY), 'descriptor access mismatch')
    return info


def bounded_proc(pid, name, maximum=32768):
    _need(type(pid) is int and pid > 0 and name in ('cgroup', 'stat', 'status', 'cmdline'),
          'invalid proc read')
    with open('/proc/' + str(pid) + '/' + name, 'rb') as stream:
        raw = stream.read(maximum + 1)
    _need(len(raw) <= maximum, 'proc read cap')
    return raw


def cgroup_of(pid):
    rows = bounded_proc(pid, 'cgroup').decode('ascii').splitlines()
    _need(len(rows) == 1 and rows[0].startswith('0::/'), 'unified cgroup required')
    path = rows[0][3:]
    _need('..' not in path.split('/') and path != '/', 'invalid cgroup')
    return path


def host_pid_namespace(pid):
    inode = os.stat('/proc/' + str(pid) + '/ns/pid').st_ino
    _need(inode == os.stat('/proc/1/ns/pid').st_ino, 'nested PID namespace unsupported')
    # NSpid also prevents treating namespace PID1 as the host namespace.
    status = bounded_proc(pid, 'status').decode('ascii').splitlines()
    ids = next(line for line in status if line.startswith('NSpid:')).split()[1:]
    _need(ids == [str(pid)], 'host PID identity unavailable')
    return inode


def _secondary(primary, label, secondary):
    """Bounded best-effort bookkeeping must never replace an original failure."""
    try:
        note = label + ': ' + type(secondary).__name__
        primary.add_note(note[:256])
    except BaseException:
        pass


class DescriptorCustody:
    """One explicit caller-owned attempt, no GC-based fd lifetime.

    Create before receive and retain this object in the Root adapter. Channel
    and config fd are borrowed. Only SCM_RIGHTS and explicitly adopted issuer
    pidfd belong here. Every close is dispatched at most once; uncertain closes
    are tombstones, never retried against a possibly reused descriptor number.
    A possible live payload retains this finite owner until Root reconciliation.
    """
    def __init__(self):
        self.entries = {}
        self.state = 'empty'
        self.reason = None

    def adopt(self, descriptors):
        _need(self.state in ('empty', 'owned') and
              len(self.entries) + len(descriptors) <= 256, 'custody capacity/state')
        for fd in descriptors:
            _need(type(fd) is int and fd >= 0 and fd not in self.entries, 'custody duplicate fd')
        for fd in descriptors:
            self.entries[fd] = dict(fd=fd, state='owned', error=None)
        self.state = 'owned'

    def retain_unknown(self, reason):
        self.state = 'retained_unknown'
        if self.reason is None:
            self.reason = reason[:128]
        return self.receipt()

    def receipt(self):
        return dict(state=self.state, reason=self.reason,
                    descriptors=tuple(dict(row) for row in self.entries.values()))

    def close(self):
        if self.state == 'retained_unknown':
            return self.receipt()
        for row in self.entries.values():
            if row['state'] != 'owned':
                continue
            row['state'] = 'close_dispatched'
            try:
                os.close(row['fd'])
            except BaseException as error:
                row['state'] = 'close_unknown'
                row['error'] = type(error).__name__
            else:
                row['state'] = 'closed'
        self.state = ('close_unknown' if any(row['state'] != 'closed'
                      for row in self.entries.values()) else 'closed')
        return self.receipt()


def _custody_note(primary, owner):
    """The caller also retains owner explicitly; the exception is a locator."""
    try:
        primary.b0_custody = owner
        if owner.state in ('retained_unknown', 'close_unknown'):
            primary.add_note('bounded descriptor custody unknown: inspect b0_custody.receipt()')
    except BaseException:
        pass


@dataclass(frozen=True)
class RootCustody:
    """Descriptors received from the one protected publisher connection.

    Constructor alone is not trust. SiteNativeBinding independently validates
    peer credentials, expected root publisher identity and all fd identities.
    Keep connection/fds alive until terminal. No worker accepts these objects.
    """
    channel: socket.socket
    intent_fd: int
    admission_fd: int
    once_fd: int
    receipt_fd: int
    directory_fds: tuple
    carrier_fds: tuple
    cgroup_fds: tuple
    owner: DescriptorCustody


def receive_custody(channel, expected_publisher, owner):
    """One root publisher packet, exact descriptor order, no path supplied by C."""
    _need(type(owner) is DescriptorCustody and owner.state == 'empty' and not owner.entries,
          'fresh explicit custody owner required')
    peer = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    _need(peer[1:] == (0, 0) and live_identity(peer[0]) == expected_publisher,
          'untrusted Root publisher peer')
    raw, ancillary, flags, _ = channel.recvmsg(PACKET_MAX,
        socket.CMSG_SPACE(256 * array.array('i').itemsize), socket.MSG_CMSG_CLOEXEC)
    installed = _received_rights(ancillary)
    owner.adopt(tuple(installed))  # owner exists before any packet/manifest guard
    try:
        _need(flags & ~socket.MSG_CMSG_CLOEXEC == 0 and len(ancillary) == 1,
              'truncated/unknown Root transfer')
        level, kind, payload = ancillary[0]
        _need((level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS) and
              len(payload) % array.array('i').itemsize == 0, 'invalid Root rights')
        ordered = array.array('i'); ordered.frombytes(payload)
        packet = exact(decode(raw), ('schema', 'directories', 'carriers', 'cgroups'))
        _need(packet['schema'] == 'qcl-b0-root-fds.v1', 'Root transport version')
        counts = tuple(_uint(packet[key]) for key in ('directories', 'carriers', 'cgroups'))
        _need(all(0 < value <= 64 for value in counts) and len(ordered) == 4 + sum(counts) and
              len(installed) == len(ordered), 'Root descriptor table mismatch')
        a, b, c = counts
        result = RootCustody(channel, *ordered[:4], tuple(ordered[4:4+a]),
                             tuple(ordered[4+a:4+a+b]), tuple(ordered[4+a+b:4+a+b+c]), owner)
        return result
    except BaseException as primary:
        owner.close()
        _custody_note(primary, owner)
        raise


class DurableOnce:
    """Subordinate receipt only. Never creates, truncates, reinitializes/refunds.

    Root creates PRECONSUMED after mirrored campaign debit. The exclusive lock
    lives for this S lifetime. An empty, torn, rebooted or terminal record cannot
    become a fresh claim. CRC detects torn bytes; authority comes from custody.
    """
    def __init__(self, fd, identity, nonce, boot):
        info = root_file(fd, writable=True)
        _need((info.st_dev, info.st_ino) == tuple(identity), 'once inode mismatch')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.fd, self.nonce, self.boot = fd, token(nonce), boot
        raw = read_fd(fd, RECORD_COUNT * RECORD_MAX)
        _need(raw.endswith(b'\n'), 'spent_unknown: torn once record')
        lines = raw.splitlines()
        _need(0 < len(lines) <= RECORD_COUNT, 'spent_unknown: invalid record count')
        previous = None
        for sequence, line in enumerate(lines):
            _need(len(line) < RECORD_MAX, 'spent_unknown: record cap')
            row = exact(decode(line, RECORD_MAX), ('sequence', 'nonce', 'boot', 'state', 'facts', 'crc32'))
            crc = row['crc32']; body = {key: value for key, value in row.items() if key != 'crc32'}
            _need(type(crc) is int and crc == zlib.crc32(canonical(body)) and
                  type(row['sequence']) is int and row['sequence'] == sequence and
                  row['nonce'] == self.nonce and row['boot'] == self.boot,
                  'spent_unknown: once integrity/boot mismatch')
            _need((previous is None and row['state'] == 'PRECONSUMED') or
                  row['state'] in EDGES.get(previous, ()), 'spent_unknown: invalid transition')
            previous = row['state']
        self.state, self.count = previous, len(lines)
        _need(self.state not in ('TERMINAL_VERIFIED', 'TERMINAL_FAILED', 'SPENT_UNKNOWN'),
              'spent once record')
        # A new S must not adopt an earlier S/C grant. CONTROLLER/NODES are Root
        # refinements, but WORKER_CLAIMED or later can only continue in this S.
        _need(self.state in ('PRECONSUMED', 'CONTROLLER_BOUND', 'NODES_BOUND'), 'worker replay')

    def advance(self, expected, target, facts):
        _need(self.state == expected and target in EDGES.get(expected, ()) and
              self.count < RECORD_COUNT and type(facts) is dict, 'once CAS refused')
        body = dict(sequence=self.count, nonce=self.nonce, boot=self.boot, state=target, facts=facts)
        raw = canonical(dict(body, crc32=zlib.crc32(canonical(body)))) + b'\n'
        _need(len(raw) <= RECORD_MAX, 'once record too large')
        # Change in-memory state first: any uncertain write/fsync remains spent.
        self.state, self.count = 'SPENT_UNKNOWN', self.count + 1
        offset = os.lseek(self.fd, 0, os.SEEK_END)
        _need(offset + len(raw) <= RECORD_COUNT * RECORD_MAX, 'once file cap')
        done = 0
        while done < len(raw):
            written = os.write(self.fd, raw[done:]); _need(written > 0, 'once short write')
            done += written
        os.fsync(self.fd)
        self.state = target


def process_record(row):
    exact(row, tuple(field.name for field in fields(ProcessIdentity)))
    values = dict(row); values['executable'] = tuple(values['executable'])
    for key in ('pid', 'start_ticks', 'uid', 'mount_namespace', 'cgroup_namespace'):
        _uint(values[key])
    _need(type(values['boot']) is str and len(values['executable']) == 2,
          'invalid process record')
    return ProcessIdentity(**values)


def budget_record(row):
    exact(row, tuple(field.name for field in fields(Budget)))
    return Budget(**row)


def observe_cgroup(fd):
    """Read one already retained cgroup; no writes to ancestor controls."""
    root = os.fstat(fd)
    _need(stat.S_ISDIR(root.st_mode) and root.st_uid == 0, 'owned cgroup fd required')
    result = {}
    names = ('cpuset.cpus.effective', 'cpu.max', 'memory.current', 'memory.high',
             'memory.max', 'memory.peak', 'memory.events', 'memory.swap.current',
             'memory.swap.max', 'pids.max', 'pids.current', 'cgroup.events', 'io.stat')
    for name in names:
        child = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=fd)
        try:
            raw = os.read(child, 65537)
            _need(len(raw) <= 65536, 'cgroup observation cap')
            result[name] = raw.decode('ascii').strip()
        finally:
            os.close(child)
    for name in ('memory.max', 'memory.swap.max', 'pids.max'):
        _need(result[name] == 'max' or result[name].isdigit(), 'invalid cgroup limit')
    _need(len(result['cpu.max'].split()) == 2, 'invalid CPU limit')
    return result


def thick_layout(spec):
    """First backend: direct non-dm/non-md non-loop physical block ext4 only.

    Reject rather than infer fixed allocation through a mapper, snapshot or
    overlay. A bounded ext4 superblock read independently checks native layout.
    Root admission must additionally enumerate aliases and exclusive ownership.
    """
    carrier = os.fstat(spec.carrier_fd)
    _need(stat.S_ISBLK(carrier.st_mode) and carrier.st_uid == 0 and
          fcntl.fcntl(spec.carrier_fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY,
          'readonly root carrier descriptor required')
    major, minor = os.major(carrier.st_rdev), os.minor(carrier.st_rdev)
    sys = '/sys/dev/block/' + str(major) + ':' + str(minor)
    actual = os.path.realpath(sys)
    _need(actual.startswith('/sys/devices/') and '/virtual/' not in actual and
          not os.path.exists(sys + '/dm') and not os.path.exists(sys + '/md') and
          not os.listdir(sys + '/slaves') and not os.listdir(sys + '/holders'),
          'unsupported backing topology: fixed_thick unknown')
    # Refuse partitions for M1: whole-device metadata/native enclosure is simpler.
    _need(not os.path.exists(sys + '/partition'), 'partition layout not qualified')
    raw = os.pread(spec.carrier_fd, 1024, 1024)
    _need(len(raw) == 1024 and struct.unpack_from('<H', raw, 56)[0] == 0xEF53,
          'ext4 superblock missing')
    inode_count, blocks_lo, log_block = (struct.unpack_from('<I', raw, offset)[0]
                                       for offset in (0, 4, 24))
    incompat = struct.unpack_from('<I', raw, 96)[0]
    ro = struct.unpack_from('<I', raw, 100)[0]
    # Standard extents/64bit/flex_bg/filetype only. Unknown features fail closed;
    # bigalloc, shared_blocks, inline_data, encrypt, verity require qualification.
    _need(incompat & ~0x2C2 == 0 and ro & ~0x47B == 0 and log_block <= 6,
          'ext4 feature layout not qualified')
    high = struct.unpack_from('<I', raw, 336)[0] if incompat & 0x80 else 0
    _need(((high << 32) | blocks_lo) * (1024 << log_block) <= spec.carrier_bytes and
          inode_count <= spec.inode_ceiling, 'ext4 native ceiling mismatch')
    return (major, minor, raw[104:120].hex(), hashlib.sha256(raw).hexdigest())


def finite_views(rows):
    """Literal T=E+U+P+S<=A and G=U+P+S<=H, no alias headroom sum."""
    _need(type(rows) is list and rows, 'missing native aggregate admission')
    seen = set()
    for row in rows:
        exact(row, ('scope', 'domain', 'view', 'E', 'U', 'P', 'S', 'A', 'H'))
        key = (row['scope'], row['domain'], row['view'])
        _need(key not in seen and row['scope'] in ('attempt', 'owner', 'filesystem', 'campaign') and
              row['view'] in ('logical_bytes', 'allocated_bytes', 'inodes'), 'capacity view coverage/alias')
        seen.add(key)
        values = {name: _uint(row[name]) for name in ('E', 'U', 'P', 'S', 'A', 'H')}
        growth = _uint(values['U'] + values['P'] + values['S'])
        _need(_uint(values['E'] + growth) <= values['A'] and growth <= values['H'], 'capacity exceeded')
    scopes = {(scope, domain) for scope, domain, _view in seen}
    _need(all((scope, domain, view) in seen for scope, domain in scopes
              for view in ('logical_bytes', 'allocated_bytes', 'inodes')), 'incomplete capacity views')
    _need({scope for scope, _domain in scopes} == {'attempt', 'owner', 'filesystem', 'campaign'},
          'missing aggregate capacity scope')


class SiteNativeBinding(NativeBinding):
    """Retained root worker backend. No callbacks replace Linux observations.

    Root publisher produces admission using the same consumed slot. Its protected
    admitted records and this worker's fresh native observations have distinct roles.
    The public authenticate_consume intentionally cannot cross missing B1 gates.
    """
    def __init__(self, custody, publisher):
        _need(type(custody) is RootCustody and type(custody.owner) is DescriptorCustody,
              'explicit Root custody owner required')
        self.custody = custody
        self._launch_started = False
        try:
            self._initialize(custody, publisher)
        except BaseException as primary:
            try:
                self.close(primary)
            except BaseException as teardown_error:
                custody.owner.retain_unknown('constructor_teardown_unknown')
                _secondary(primary, 'constructor teardown unknown', teardown_error)
                _custody_note(primary, custody.owner)
            raise

    def _initialize(self, custody, publisher):
        _need(os.geteuid() == 0 and type(custody) is RootCustody and publisher.uid == 0,
              'root custody required')
        peer = struct.unpack('3i', custody.channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        _need(peer == (publisher.pid, 0, 0) and live_identity(peer[0]) == publisher,
              'Root transport identity changed')
        host_pid_namespace(os.getpid())
        self.custody, self.publisher = custody, publisher
        root_file(custody.admission_fd)
        self.admission_raw = read_fd(custody.admission_fd, 1 << 20)
        self.admission = decode(self.admission_raw, 1 << 20)
        self.intent_raw = _capsule_bytes(custody.intent_fd)
        _need(self.intent_raw.endswith(b'\n'), 'Root envelope requires one final LF')
        envelope = exact(decode(self.intent_raw[:-1], 1 << 20),
                         ('schema', 'intent_id', 'checkpoint_sha256', 'checkpoint_revision', 'intent'))
        _need(envelope['schema'] == 'qcl.b0.consumed-intent.v1', 'Root envelope schema')
        self.intent = envelope['intent']
        _need(type(self.intent) is dict and token(envelope['intent_id']) == self.intent.get('consume_ref') and
              _uint(envelope['checkpoint_revision']) == _uint(self.intent.get('cp_revision')),
              'Root consumed revision/refinement mismatch')
        digest(envelope['checkpoint_sha256'])
        self.root_envelope = envelope
        self._validate_manifest()
        self.once = DurableOnce(custody.once_fd, self.admission['once_identity'],
                                self.intent['nonce'], self.admission['worker_boot'])
        self.receipt_info = root_file(custody.receipt_fd, writable=True)
        _need(self.receipt_info.st_size == 0, 'receipt already used')
        self.issuer = live_identity(os.getpid())
        self._mount_epoch = self.issuer.mount_namespace
        self.issuer_pidfd = os.pidfd_open(self.issuer.pid, 0)
        custody.owner.adopt((self.issuer_pidfd,))
        self.worker = self.capsule = self.raw = None
        self.primary = None; self.sequence = 0; self._rpc_sequence = 0; self.stop_reserved = False
        self._scheduler_calls = 0
        self._registry = {}; self._descriptors = {}; self._terminal = None
        self._ledger = _Ledger(budget_record(self.intent['total']), budget_record(self.intent['stop']))
        ceiling = Budget(read=4*1024**4, write=2*1024**4, log=1024**3,
                         resident=128*1024**3, memory=128*1024**3,
                         wall_ns=72*3600*1_000_000_000, inodes=(1 << 64)-1,
                         calls=(1 << 64)-1, scopes=1024)
        _need(_fits(self._ledger.total, ceiling), 'consumed slot exceeds fixed B0 ceilings')

    def close(self, primary=None):
        owner = self.custody.owner
        if self._launch_started:
            # Even a failed fork/handshake may have uncertain descendants. This
            # one bounded owner is retained by the Root caller, never abandoned
            # as integer fds or released on a guessed payload/STOP verdict.
            receipt = owner.retain_unknown('child_or_payload_custody_not_verified')
        else:
            receipt = owner.close()
        if primary is not None:
            _custody_note(primary, owner)
        return receipt

    def _validate_manifest(self):
        required = ('schema', 'intent_sha256', 'publisher', 'once_identity', 'worker_boot',
                    'worker_deadline_ns', 'source_graph', 'model', 'plan', 'criteria', 'runtime',
                    'native_kit', 'release', 'code', 'profiles_digest', 'domains', 'placements',
                    'capacity', 'scheduler', 'cgroups', 'writable_mounts', 'approved_argv',
                    'approved_env', 'worker_executable', 'controller_receipt', 'operation_profiles')
        exact(self.admission, required)
        exact(self.intent, ('schema', 'consume_ref', 'cp_revision', 'slot_id', 'attempt_id', 'nonce',
                            'admission_sha256', 'source_graph', 'model', 'plan', 'criteria', 'runtime',
                            'native_kit', 'release', 'code', 'profiles_digest', 'total', 'stop',
                            'root_boot', 'root_deadline_ns'))
        a, i = self.admission, self.intent
        _need(a['schema'] == 'qcl-b0-worker-admission.v1' and
              i['schema'] == 'qcl-b0-consumed-intent.v1', 'manifest schema')
        # No self-referential hash: admission digest covers its body excluding
        # intent_sha256; intent independently includes that body digest.
        body = {key: value for key, value in a.items() if key != 'intent_sha256'}
        _need(digest(a['intent_sha256']) == hashlib.sha256(self.intent_raw).hexdigest() and
              digest(i['admission_sha256']) == hashlib.sha256(canonical(body)).hexdigest(),
              'Root intent/admission binding')
        _need(process_record(a['publisher']) == self.publisher, 'publisher manifest mismatch')
        for name in ('source_graph', 'model', 'plan', 'criteria', 'runtime', 'native_kit',
                     'release', 'code', 'profiles_digest'):
            _need(digest(a[name]) == digest(i[name]), 'consumed source/model/profile mismatch')
        for name in ('slot_id', 'attempt_id', 'nonce'):
            token(i[name])
        token(i['consume_ref']); _uint(i['cp_revision'])
        # Root and worker monotonic domains are intentionally not compared.
        # Root transport producer must validate its root clock before delivery.
        boot = live_identity(os.getpid()).boot
        _need(a['worker_boot'] == boot and _uint(a['worker_deadline_ns']) > time.monotonic_ns(),
              'stale worker clock/boot')
        _uint(i['root_deadline_ns']); _need(type(i['root_boot']) is str, 'root clock anchor')
        _need(type(a['approved_argv']) is list and a['approved_argv'] and
              all(type(arg) is str and len(arg) <= 4096 for arg in a['approved_argv']) and
              a['approved_argv'][0].startswith('/nix/store/'), 'immutable Runner argv required')
        _need(type(a['approved_env']) is dict and all(type(k) is str and type(v) is str
              for k, v in a['approved_env'].items()) and not any(k.startswith(('LD_', 'PYTHON'))
              for k in a['approved_env']), 'unsafe worker environment')
        finite_views(a['capacity'])
        _need(len(a['domains']) == len(self.custody.carrier_fds) and
              len(a['cgroups']) == len(self.custody.cgroup_fds), 'descriptor count mismatch')

    def authenticate_consume(self, record):
        _need(type(record) is bytes and record == self.intent_raw, 'foreign consumed intent')
        # Mandatory implementation gates cannot be caller-supplied receipts.
        _need(CONTROLLER_IMPLEMENTED, 'controller_induced_bound_missing')
        _need(NATIVE_ATTACH_IMPLEMENTED, 'qualified_native_attach_missing')
        return self.intent_raw

    def prepare_launch(self, consume):
        _need(consume == self.intent_raw and self.once.state == 'NODES_BOUND', 'launch state mismatch')
        self._domain_readback()
        self._cgroup_readback()
        _need(self._payload_empty(), 'payload cgroup is not initially empty')
        # Retained S privatizes propagation BEFORE fork. C then clones its own
        # readonly mount view before drop; S's durable custody stays writable.
        private_namespace()
        self.issuer = live_identity(os.getpid())
        self._mount_epoch = self.issuer.mount_namespace
        self._launch_started = True  # before fork; uncertainty never loses owner

    def prepare_child(self, control_fd):
        prepare_containment(self.custody, self.admission['writable_mounts'])
        payload = [index for index, row in enumerate(self.admission['cgroups']) if row['role'] == 'payload']
        _need(len(payload) == 1, 'exact owned payload cgroup required')
        parent_fd = self.custody.cgroup_fds[payload[0]]
        own = os.open('cgroup.procs', os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            raw = str(os.getpid()).encode('ascii')
            _need(os.write(own, raw) == len(raw), 'child cgroup attach unknown')
        finally:
            os.close(own)
        _need(cgroup_of(os.getpid()) == self.admission['cgroups'][payload[0]]['path'],
              'child payload cgroup mismatch')
        # Child closes all Root, carrier, cgroup and publisher descriptors before
        # credential drop. No raw block/write capability reaches UID3000.
        keep = {0, 1, 2, control_fd}
        for name in os.listdir('/proc/self/fd'):
            if name.isdigit() and int(name) not in keep:
                try:
                    os.close(int(name))
                except OSError:
                    pass
        os.chdir('/')
        os.umask(0o077)

    def issuer_identity(self):
        _need(not select.select([self.issuer_pidfd], [], [], 0)[0] and
              live_identity(os.getpid()) == self.issuer, 'issuer lost')
        return self.issuer

    def _domain_readback(self):
        specs = []
        aliases = set()
        with open('/proc/self/mountinfo', 'rb') as stream:
            raw_mounts = stream.read((1 << 20) + 1)
        _need(len(raw_mounts) <= 1 << 20, 'mount alias read cap')
        mounts = [line.decode('utf-8').split() for line in raw_mounts.splitlines()]
        for index, row in enumerate(self.admission['domains']):
            exact(row, ('domain', 'root_index', 'root_identity', 'backing', 'mount_id',
                        'mount_namespace', 'carrier_bytes', 'inode_ceiling', 'consumers',
                        'inventory_ref', 'owner_uid', 'layout', 'aliases', 'exclusive'))
            root_index = _uint(row['root_index'])
            _need(root_index < len(self.custody.directory_fds) and row['exclusive'] is True and
                  type(row['aliases']) is list and row['aliases'], 'fixed_thick ownership/alias coverage missing')
            native_alias = tuple(row['backing'])
            _need(native_alias not in aliases, 'backing alias duplicate')
            aliases.add(native_alias)
            spec = AdoptedDomainSpec(row['domain'], self.custody.directory_fds[root_index],
                self.custody.carrier_fds[index], tuple(row['root_identity']), native_alias,
                _uint(row['mount_id']), self._mount_epoch, _uint(row['carrier_bytes']),
                _uint(row['inode_ceiling']), tuple(row['consumers']), row['inventory_ref'],
                _uint(row['owner_uid']))
            _need(thick_layout(spec) == tuple(row['layout']), 'native backing layout changed')
            root = os.fstat(spec.root_fd)
            _need(root.st_gid == spec.owner_uid and root.st_mode & 0o022 == 0,
                  'root write permissions not exclusive')
            device = str(os.major(root.st_dev)) + ':' + str(os.minor(root.st_dev))
            actual_aliases = sorted((int(entry[0]), entry[3], entry[4], entry[5])
                                    for entry in mounts if entry[2] == device)
            _need(actual_aliases == sorted(tuple(alias) for alias in row['aliases']),
                  'visible mount alias coverage changed')
            specs.append(spec)
        proofs = observe_domains(tuple(specs))
        validate_domains(proofs, tuple(tuple(row) for row in self.admission['placements']))
        return proofs

    def _cgroup_readback(self):
        result = []
        paths = [row['path'] for row in self.admission['cgroups']]
        _need(len(paths) == len(set(paths)), 'duplicate cgroup enclosure')
        payload = [row['path'] for row in self.admission['cgroups'] if row['role'] == 'payload']
        _need(len(payload) == 1 and cgroup_of(os.getpid()) != payload[0], 'payload includes retained S')
        required = set()
        for leaf in (cgroup_of(os.getpid()), payload[0]):
            while True:
                required.add(leaf)
                if leaf == '/':
                    break
                leaf = leaf.rpartition('/')[0] or '/'
        _need(set(paths) == required, 'all-ancestor cgroup coverage missing')
        for fd, expected in zip(self.custody.cgroup_fds, self.admission['cgroups']):
            exact(expected, ('identity', 'path', 'role', 'memory_max', 'pids_max', 'cpu_max'))
            info = os.fstat(fd)
            _need((info.st_dev, info.st_ino) == tuple(expected['identity']), 'cgroup inode changed')
            path = expected['path']
            _need(type(path) is str and path.startswith('/') and
                  (path == '/' or not any(part in ('', '.', '..') for part in path.split('/')[1:])) and
                  expected['role'] in ('ancestor', 'payload'), 'cgroup placement invalid')
            native = os.stat('/sys/fs/cgroup' + path)
            _need((native.st_dev, native.st_ino) == (info.st_dev, info.st_ino), 'cgroup descriptor/path mismatch')
            observed = observe_cgroup(fd)
            for key in ('memory_max', 'pids_max'):
                _need(expected[key] == 'max' or type(expected[key]) is int, 'typed cgroup ceiling')
                if expected[key] != 'max':
                    _uint(expected[key])
            _need(observed['memory.max'] == str(expected['memory_max']) and
                  observed['pids.max'] == str(expected['pids_max']) and
                  observed['cpu.max'] == expected['cpu_max'], 'native resource epoch changed')
            result.append(observed)
        for leaf in (cgroup_of(os.getpid()), payload[0]):
            applicable = [result[index] for index, path in enumerate(paths)
                          if path == '/' or leaf == path or leaf.startswith(path + '/')]
            _need(any(row['memory.max'].isdigit() and 0 < int(row['memory.max']) <= 128 * 1024**3
                      for row in applicable) and
                  any(row['memory.swap.max'] == '0' for row in applicable) and
                  any(row['pids.max'].isdigit() for row in applicable) and
                  any(row['cpu.max'].split()[0].isdigit() for row in applicable),
                  'finite enclosing CPU/memory/pids and swap0 required')
        return tuple(result)

    def _scheduler(self, worker):
        expected = self.admission['scheduler']
        exact(expected, ('scontrol', 'executable', 'sha256', 'job', 'step', 'node', 'partition',
                         'command', 'cgroup', 'scope', 'slurmstepd_executable', 'identity',
                         'calls', 'timeout_ns', 'output_bytes'))
        binary = expected['scontrol']
        _need(type(binary) is str and binary.startswith('/nix/store/') and binary.endswith('/bin/scontrol'),
              'fixed scontrol required')
        info = os.stat(binary)
        _need((info.st_dev, info.st_ino) == tuple(expected['executable']) and
              info.st_uid == 0 and info.st_mode & 0o022 == 0, 'scheduler executable changed')
        # Hash the exact executable under a finite pre-admitted setup bound.
        fd = os.open(binary, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            raw = read_fd(fd, 32 << 20)
        finally:
            os.close(fd)
        _need(hashlib.sha256(raw).hexdigest() == digest(expected['sha256']), 'scontrol digest changed')
        job = expected['job']; _need(type(job) is str and re.fullmatch(r'[1-9][0-9]{0,9}', job), 'job identity')
        limit = _uint(expected['calls'])
        _need(self._scheduler_calls + 2 <= limit, 'scheduler call allowance')
        self._scheduler_calls += 2  # debit before either CLI effect; never refund
        text = fixed_read_command((binary, '--oneliner', 'show', 'job', job), expected).decode('ascii')
        values = dict(re.findall(r'(?<!\S)(\w+)=([^\s]+)', text))
        _need(values.get('JobId') == job and re.fullmatch(r'[^()]+\(3000\)', values.get('UserId', '')) and
              values.get('JobState') == 'RUNNING' and values.get('Requeue') == '0' and
              values.get('Restarts') == '0' and values.get('NodeList') == expected['node'] and
              values.get('Partition') == expected['partition'] and values.get('Command') == expected['command'],
              'live scheduler binding mismatch')
        rows = fixed_read_command((binary, 'listpids', job), expected).decode('ascii').splitlines()
        _need(rows and rows[0].split()[:2] == ['PID', 'JOBID'], 'scheduler PID header')
        found = []
        listing = []; processes = []
        _need(len(rows) <= 257, 'scheduler process count cap')
        for line in rows[1:]:
            parts = line.split(); _need(len(parts) >= 3 and parts[0].isdigit(), 'scheduler PID row')
            observed_pid = int(parts[0]); observed = live_identity(observed_pid)
            exe = os.readlink('/proc/' + str(observed_pid) + '/exe')
            listing.append(dict(pid=observed_pid, job_id=parts[1], step_id=parts[2]))
            processes.append(dict(pid=observed_pid, start_ticks=observed.start_ticks,
                uids=[observed.uid]*4, exe=exe, cgroup=cgroup_of(observed_pid), error=None,
                executable_identity=list(observed.executable),
                command_digest=hashlib.sha256(bounded_proc(observed_pid, 'cmdline')).hexdigest()))
            if parts[0] == str(worker.pid):
                found.append(parts[1:3])
        _need(found == [[job, expected['step']]] and cgroup_of(worker.pid) == expected['cgroup'],
              'actual worker job/step/cgroup mismatch')
        _need([row for row in listing if row['pid'] == self.issuer.pid] ==
              [dict(pid=self.issuer.pid, job_id=job, step_id=expected['step'])],
              'retained issuer missing from exact scheduler allocation')
        with open('/etc/machine-id', 'rb') as stream:
            machine = stream.read(129)
        _need(len(machine) <= 128, 'machine identity cap')
        identity = dict(machine_id=machine.decode('ascii').strip(), boot_id=self.issuer.boot)
        _need(identity == expected['identity'], 'scheduler host identity mismatch')
        registered = job_evidence.SupervisorIdentity(self.issuer.pid, self.issuer.start_ticks,
            self.issuer.boot, job, cgroup_of(self.issuer.pid),
            os.readlink('/proc/self/exe'), self.issuer.executable,
            hashlib.sha256(bounded_proc(self.issuer.pid, 'cmdline')).hexdigest(),
            self.intent['nonce'], self.intent['consume_ref'])
        job_evidence.classify_before(dict(identity_before=identity, identity_after=identity,
            listpids=dict(rc=0, rows=listing), processes=processes),
            dict(job_id=job, owner_uid=3000, slurmstepd_executable=expected['slurmstepd_executable'],
                 cgroup_scope=expected['scope'], identity=identity), registered)
        _need(live_identity(worker.pid) == worker and self.issuer_identity() == self.issuer,
              'scheduler observation identity changed')

    def capsule_for_child(self, consume, issuer, blocked_child):
        _need(consume == self.intent_raw and issuer == self.issuer and blocked_child.uid == 3000,
              'foreign child')
        host_pid_namespace(blocked_child.pid)
        _need(blocked_child.boot == self.admission['worker_boot'] and
              blocked_child.executable == tuple(self.admission['worker_executable']), 'child identity mismatch')
        self._scheduler(blocked_child)
        domains = self._domain_readback(); self._cgroup_readback()
        # This remains compulsory even if worker-only tests exercise readbacks.
        _need(CONTROLLER_IMPLEMENTED and NATIVE_ATTACH_IMPLEMENTED,
              'controller/native coverage missing; no full capsule')
        self.once.advance('NODES_BOUND', 'WORKER_CLAIMED',
                          dict(issuer=asdict(issuer), worker=asdict(blocked_child),
                               scheduler=self.admission['scheduler']['job']))
        i = self.intent
        row = dict(consume_ref=i['consume_ref'], cp_revision=str(i['cp_revision']), slot_id=i['slot_id'],
                   attempt_id=i['attempt_id'], nonce=i['nonce'], issuer=asdict(issuer),
                   worker=asdict(blocked_child), binding=[['admission', hashlib.sha256(self.admission_raw).hexdigest()]],
                   deadline_ns=self.admission['worker_deadline_ns'], total=i['total'], stop=i['stop'],
                   domains=[asdict(proof) for proof in domains], placements=self.admission['placements'],
                   profiles_digest=i['profiles_digest'], controller_receipt=self.admission['controller_receipt'])
        self.raw = canonical(row)
        self.worker = blocked_child
        self.capsule = capsule_record(self.raw)
        # Durable CAPSULE_SENT precedes sendmsg in FixedRootSupervisor. A lost
        # send or response never returns this record to fresh/retry state.
        self.once.advance('WORKER_CLAIMED', 'CAPSULE_SENT', dict(capsule=self.capsule.digest))
        return self.raw

    def verify_capsule(self, raw, envelope, issuer, worker):
        _need(raw == self.raw and issuer == self.issuer and worker == self.worker and
              envelope == (str(self.intent['cp_revision']), self.intent['attempt_id']), 'foreign capsule envelope')
        return self.capsule

    def claim_once(self, capsule):
        self.check_current(capsule)
        self.once.advance('CAPSULE_SENT', 'AUTHORITY_CLAIMED', dict(capsule=capsule.digest))
        return self.capsule

    def collect_bound_domain(self, capsule):
        _need(capsule == self.capsule, 'foreign capsule')
        observed = self._domain_readback()
        _need(observed == capsule.domains, 'domain epoch changed')
        finite_views(self.admission['capacity'])
        return observed

    def check_current(self, capsule):
        _need(capsule == self.capsule and self.worker is not None and self.primary is None and
              time.monotonic_ns() < capsule.deadline_ns, 'frozen/stale/foreign grant')
        self.issuer_identity()
        _need(live_identity(self.worker.pid) == self.worker and
              int(bounded_proc(self.worker.pid, 'stat').rpartition(b') ')[2].split()[1]) == self.issuer.pid,
              'worker identity/parent changed')
        host_pid_namespace(self.worker.pid)
        self._scheduler(self.worker); self._cgroup_readback()
        self.sequence = _uint(self.sequence + 1)
        return self.capsule

    def reserve_stop(self, capsule):
        self.check_current(capsule)
        _need(not self.stop_reserved and self.once.state == 'AUTHORITY_CLAIMED', 'STOP replay')
        self.stop_reserved = True
        self.once.advance('AUTHORITY_CLAIMED', 'NORMAL', dict(stop=asdict(capsule.stop)))
        # actual0 is reservation only, never asserted I/O settlement.
        return Settlement(0, capsule.stop, Budget(), (), 'root-registry:stop-reservation')

    def verify_descriptor(self, capsule, descriptor):
        self.check_current(capsule)
        _need(type(descriptor) is CaptureDescriptor and descriptor.digest not in self._descriptors and
              len(self._registry) + len(descriptor.delegates) + 1 <= 1024, 'descriptor replay/capacity')
        expected = self.admission['operation_profiles'].get(descriptor.digest)
        _need(expected is not None and canonical(asdict(descriptor)) == canonical(expected),
              'unapproved complete serializer graph')
        self._ledger.reserve(descriptor.inclusive)
        self._descriptors[descriptor.digest] = descriptor
        return descriptor

    def verify_capture(self, capsule, descriptor, captured):
        self.check_current(capsule)
        _need(type(captured) is CapturedContent and self._descriptors.get(descriptor.digest) == descriptor,
              'unregistered capture')
        # Worker cannot make its own native settlement authoritative. Until the
        # qualified kit transport owns snapshot fd delivery, no receipt passes.
        raise ProviderRefusal('qualified native snapshot custody unavailable')

    def delegate(self, capsule, permit, index, bound):
        self.check_current(capsule)
        self.freeze_normal(capsule, 'qualified native attach unavailable')
        raise ProviderRefusal('qualified native attach unavailable')

    def settle_delegate(self, capsule, permit, index, receipt):
        self.freeze_normal(capsule, 'native settlement unknown')
        raise ProviderRefusal('native settlement unknown; debt retained')

    def freeze_normal(self, capsule, primary):
        _need(capsule == self.capsule, 'foreign freeze')
        if self.primary is None:
            self.primary = str(primary)[:512] or 'unknown failure'
            self._ledger.freeze(self.primary)
            try:
                if self.once.state in ('NORMAL', 'AUTHORITY_CLAIMED', 'CAPSULE_SENT'):
                    # Early failure skips normal successors, never back to fresh.
                    if self.once.state == 'NORMAL':
                        self.once.advance('NORMAL', 'FREEZING', dict(primary=self.primary))
                    else:
                        self.once.advance(self.once.state, 'SPENT_UNKNOWN', dict(primary=self.primary))
            finally:
                # Durable bookkeeping failure must not skip the local latch.
                for row in self._registry.values():
                    row['frozen'] = True
        else:
            for row in self._registry.values():
                row['frozen'] = True
        return self.primary

    def _payload_empty(self):
        index = next(index for index, row in enumerate(self.admission['cgroups'])
                     if row['role'] == 'payload')
        fd = self.custody.cgroup_fds[index]
        events = os.open('cgroup.events', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=fd)
        try:
            raw = os.read(events, 4097)
            _need(len(raw) <= 4096, 'payload events cap')
            rows = dict(line.split() for line in raw.decode('ascii').splitlines())
            _need(rows.get('populated') in ('0', '1'), 'payload population unknown')
            return rows['populated'] == '0'
        finally:
            os.close(events)

    def quiesce_job(self, capsule, stop_permit, primary):
        _need(capsule == self.capsule and self.stop_reserved and self.primary == primary,
              'foreign STOP')
        # No fabricated checkpoint/generation or successful fd drain. Native kit
        # has not supplied a verified generation and terminal I/O remains unknown.
        return StopResult('unknown', self.primary, None, None,
            Settlement(0, capsule.stop, None, ('native_stop', 'payload_quiescence',
                       'outer_job_terminal'), 'root-registry:stop-unknown'))

    def supervise_child(self, pid, pidfd, capsule_fd, control_channel):
        _need(self.worker is not None and (pid, self.worker.start_ticks) ==
              (self.worker.pid, live_identity(pid).start_ticks), 'foreign supervised child')
        control_channel.settimeout(1)
        end = self.capsule.deadline_ns
        grace = _uint(self.capsule.stop.wall_ns)
        _need(0 < grace <= 60_000_000_000, 'finite prepaid STOP grace required')
        status = None
        try:
            while time.monotonic_ns() < end:
                waited, status = os.waitpid(pid, os.WNOHANG)
                if waited == pid:
                    break
                try:
                    raw, ancillary, flags, _ = control_channel.recvmsg(PACKET_MAX,
                        socket.CMSG_SPACE(4096), socket.MSG_CMSG_CLOEXEC)
                except socket.timeout:
                    continue
                delivered = _received_rights(ancillary)
                try:
                    _need(flags & ~socket.MSG_CMSG_CLOEXEC == 0 and raw and not delivered and
                          len(ancillary) == 1 and ancillary[0][:2] ==
                          (socket.SOL_SOCKET, socket.SCM_CREDENTIALS) and
                          struct.unpack('3i', ancillary[0][2]) == (pid, 3000, 3000), 'RPC peer/EOF/rights')
                    reply = self.dispatch(decode(raw))
                    encoded = canonical(reply); _need(len(encoded) <= PACKET_MAX, 'RPC reply cap')
                    _need(control_channel.send(encoded) == len(encoded), 'RPC short reply')
                    if self.primary is not None:
                        end = min(end, time.monotonic_ns() + grace)
                finally:
                    _close_rights(delivered)
            else:
                raise ProviderRefusal('worker deadline')
            _need(status is not None, 'child reap unknown')
            counters = self._cgroup_readback()
            self._write_receipt(dict(status='SPENT_UNKNOWN', primary=self.primary or 'worker exited',
                worker=asdict(self.worker), issuer=asdict(self.issuer), wait_status=status,
                counters=counters, payload_quiescence='not_measured',
                whole_job_terminal='outer_observer_required', scientific_accepted=False))
            # A reaped C does not prove its descendants empty or native fd drain.
            raise ProviderRefusal('payload custody incomplete; outer terminal required')
        except BaseException as error:
            try:
                try:
                    self.freeze_normal(self.capsule, str(error))
                except BaseException as freeze_error:
                    _secondary(error, 'freeze persistence unknown', freeze_error)
            finally:
                # Always attempt owned-child cleanup, even if durable freeze or
                # secondary bookkeeping fails. Never replace the thrown primary.
                try:
                    _cleanup_owned_child(pid, pidfd, self.worker.start_ticks,
                                         time.monotonic_ns() + grace)
                except BaseException as cleanup_error:
                    _secondary(error, 'payload cleanup unknown', cleanup_error)
            raise

    def _write_receipt(self, receipt):
        raw = canonical(receipt)
        _need(len(raw) <= PACKET_MAX, 'receipt cap')
        done = 0
        while done < len(raw):
            count = os.write(self.custody.receipt_fd, raw[done:]); _need(count > 0, 'receipt short write')
            done += count
        os.fsync(self.custody.receipt_fd)

    def dispatch(self, packet):
        exact(packet, ('sequence', 'opcode', 'slot', 'attempt', 'nonce', 'args'))
        _need(type(packet['sequence']) is int and packet['sequence'] == self._rpc_sequence and
              (packet['slot'], packet['attempt'], packet['nonce']) ==
              (self.intent['slot_id'], self.intent['attempt_id'], self.intent['nonce']), 'RPC replay/identity')
        self._rpc_sequence = _uint(self._rpc_sequence + 1)
        opcode, args = packet['opcode'], packet['args']
        _need(type(args) is dict, 'RPC args')
        try:
            if opcode == 'issuer':
                exact(args, ()); result = asdict(self.issuer_identity())
            elif opcode == 'verify':
                exact(args, ('digest', 'envelope', 'worker'))
                _need(args['digest'] == self.capsule.digest and process_record(args['worker']) == self.worker and
                      tuple(args['envelope']) == (str(self.intent['cp_revision']), self.intent['attempt_id']), 'RPC capsule')
                result = dict(digest=self.capsule.digest, issuer=asdict(self.issuer), worker=asdict(self.worker))
            elif opcode in ('claim', 'current', 'domains', 'reserve_stop'):
                exact(args, ('digest',)); _need(args['digest'] == self.capsule.digest, 'RPC capsule digest')
                method = {'claim': self.claim_once, 'current': self.check_current,
                          'domains': self.collect_bound_domain, 'reserve_stop': self.reserve_stop}[opcode]
                value = method(self.capsule)
                result = ([asdict(row) for row in value] if opcode == 'domains' else
                          asdict(value) if opcode == 'reserve_stop' else dict(digest=value.digest))
            elif opcode == 'freeze':
                exact(args, ('digest', 'primary')); _need(args['digest'] == self.capsule.digest, 'foreign freeze')
                result = self.freeze_normal(self.capsule, args['primary'])
            else:
                raise ProviderRefusal('opcode/native operation unavailable')
            return dict(sequence=packet['sequence'], result=result, error=None)
        except Exception as error:
            try:
                self.freeze_normal(self.capsule, str(error))
            except BaseException as freeze_error:
                _secondary(error, 'freeze persistence unknown', freeze_error)
            return dict(sequence=packet['sequence'], result=None, error=str(error)[:512])


def capsule_record(raw):
    from scientific_b0_provider import DomainProof
    row = decode(raw, 1 << 20)
    exact(row, tuple(field.name for field in fields(AuthenticatedCapsule) if field.name != 'digest'))
    values = dict(row)
    values['digest'] = hashlib.sha256(raw).hexdigest()
    for name in ('issuer', 'worker'):
        values[name] = process_record(values[name])
    for name in ('total', 'stop'):
        values[name] = budget_record(values[name])
    domains = []
    for domain in values['domains']:
        exact(domain, tuple(field.name for field in fields(DomainProof)))
        domain = dict(domain)
        domain['backing'] = tuple(domain['backing']); domain['consumers'] = tuple(domain['consumers'])
        domains.append(DomainProof(**domain))
    values['domains'] = tuple(domains)
    values['binding'] = tuple(tuple(item) for item in values['binding'])
    values['placements'] = tuple(tuple(item) for item in values['placements'])
    _uint(values['deadline_ns']); token(values['slot_id']); token(values['attempt_id']); token(values['nonce'])
    return AuthenticatedCapsule(**values)


class WorkerNativeBindingClient(NativeBinding):
    """Synchronous client of the retained issuer, never a new allowance issuer.

    Every packet is credentialled by Linux. Duplicating this object/fd restarts
    sequence0 and the retained S rejects it. C only learns S identity via channel.
    """
    def __init__(self, control_fd, slot, attempt, nonce):
        self.channel = socket.socket(fileno=os.dup(control_fd))
        _need(self.channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET,
              'seqpacket control required')
        self.channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.channel.settimeout(5)
        self.slot, self.attempt, self.nonce = token(slot), token(attempt), token(nonce)
        self.sequence = 0; self.capsule = None; self.issuer = None; self.failed = False

    def _call(self, opcode, args):
        _need(not self.failed, 'client frozen')
        sequence = self.sequence; self.sequence = _uint(sequence + 1)
        packet = canonical(dict(sequence=sequence, opcode=opcode, slot=self.slot,
                                attempt=self.attempt, nonce=self.nonce, args=args))
        _need(len(packet) <= PACKET_MAX, 'RPC request cap')
        installed = set()
        try:
            _need(self.channel.send(packet) == len(packet), 'RPC short send')
            raw, ancillary, flags, _ = self.channel.recvmsg(PACKET_MAX,
                socket.CMSG_SPACE(4096), socket.MSG_CMSG_CLOEXEC)
            installed = _received_rights(ancillary)
            _need(flags & ~socket.MSG_CMSG_CLOEXEC == 0 and not installed and len(ancillary) == 1 and
                  ancillary[0][:2] == (socket.SOL_SOCKET, socket.SCM_CREDENTIALS), 'RPC ancillary/EOF')
            credentials = struct.unpack('3i', ancillary[0][2])
            _need(credentials == (os.getppid(), 0, 0), 'RPC root parent mismatch')
            reply = exact(decode(raw), ('sequence', 'result', 'error'))
            _need(type(reply['sequence']) is int and reply['sequence'] == sequence and reply['error'] is None,
                  'RPC refused/sequence mismatch')
            return reply['result']
        except BaseException:
            self.failed = True
            raise
        finally:
            _close_rights(installed)

    def issuer_identity(self):
        identity = process_record(self._call('issuer', {}))
        _need(identity.uid == 0 and identity.pid == os.getppid() and
              (self.issuer is None or self.issuer == identity), 'issuer identity changed')
        self.issuer = identity
        return identity

    def verify_capsule(self, raw, envelope, issuer, worker):
        local = capsule_record(raw)
        row = self._call('verify', dict(digest=local.digest, envelope=envelope, worker=asdict(worker)))
        exact(row, ('digest', 'issuer', 'worker'))
        _need(local.digest == row['digest'] and process_record(row['issuer']) == issuer == local.issuer and
              process_record(row['worker']) == worker == local.worker,
              'capsule not in retained registry')
        self.capsule = local
        return local

    def _bound(self, opcode, capsule):
        _need(capsule == self.capsule, 'foreign client capsule')
        return self._call(opcode, dict(digest=capsule.digest))

    def claim_once(self, capsule):
        row = self._bound('claim', capsule)
        exact(row, ('digest',)); _need(row['digest'] == capsule.digest, 'claim digest mismatch')
        return capsule

    def check_current(self, capsule):
        row = self._bound('current', capsule)
        exact(row, ('digest',)); _need(row['digest'] == capsule.digest, 'current digest mismatch')
        return capsule

    def collect_bound_domain(self, capsule):
        row = self._bound('domains', capsule)
        _need(canonical(row) == canonical([asdict(domain) for domain in capsule.domains]), 'domain registry mismatch')
        return capsule.domains

    def reserve_stop(self, capsule):
        row = exact(self._bound('reserve_stop', capsule), ('sequence', 'requested', 'actual', 'unknown', 'reference'))
        return Settlement(_uint(row['sequence']), budget_record(row['requested']),
                          budget_record(row['actual']), tuple(row['unknown']), row['reference'])

    def freeze_normal(self, capsule, primary):
        return self._call('freeze', dict(digest=capsule.digest, primary=str(primary)[:512]))

    # Native methods inherit fail-closed refusals; M1 does not impersonate the
    # qualified native kit or infer a successful settlement from caller JSON.


def fixed_read_command(argv, profile):
    """Only two fixed scontrol families; bounded pipes/calls/deadline, no shell."""
    import subprocess
    timeout = _uint(profile['timeout_ns']); cap = _uint(profile['output_bytes'])
    _need(0 < timeout <= 10_000_000_000 and 0 < cap <= PACKET_MAX, 'scheduler profile bound')
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env={}, close_fds=True, cwd='/')
    output = bytearray(); total = 0; end = time.monotonic_ns() + timeout
    pipes = [process.stdout, process.stderr]
    try:
        for pipe in pipes:
            os.set_blocking(pipe.fileno(), False)
        live = list(pipes)
        while live:
            _need(time.monotonic_ns() < end, 'scheduler read deadline')
            ready = select.select(live, [], [], min(0.05, max(0, (end-time.monotonic_ns())/1e9)))[0]
            for pipe in ready:
                chunk = os.read(pipe.fileno(), min(8192, cap-total+1))
                if not chunk:
                    live.remove(pipe); continue
                total += len(chunk); _need(total <= cap, 'scheduler output cap')
                if pipe is process.stdout:
                    output.extend(chunk)
        _need(process.wait(timeout=max(0.001, (end-time.monotonic_ns())/1e9)) == 0, 'scheduler command failed')
        return bytes(output)
    finally:
        if process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired as error:
                raise ProviderRefusal('scheduler cleanup unknown') from error
        for pipe in pipes:
            pipe.close()


def private_namespace():
    libc = ctypes.CDLL(None, use_errno=True)
    _need(libc.unshare(0x00020000) == 0, 'private mount namespace unavailable')
    _need(libc.mount(None, b'/', None, (1 << 18) | (1 << 14), None) == 0,
          'private propagation unavailable')


def prepare_containment(custody, writable):
    """Create private root read-only tree then reopen only admitted bind mounts.

    Requires Linux mount_setattr; unsupported hosts refuse before fork. Root-owned
    once/receipt descriptors stay on retained original mounts. UID3000 inherits
    neither those fds nor mount authority. No volume creation or quota mutation.
    """
    private_namespace()
    libc = ctypes.CDLL(None, use_errno=True)
    # Clone mounts onto /, leaving existing custody fds referencing originals.
    _need(libc.mount(b'/', b'/', None, 4096 | 16384, None) == 0, 'root bind clone unavailable')
    class MountAttr(ctypes.Structure):
        _fields_ = [('attr_set', ctypes.c_uint64), ('attr_clr', ctypes.c_uint64),
                    ('propagation', ctypes.c_uint64), ('userns_fd', ctypes.c_uint64)]
    attr = MountAttr(1, 0, 0, 0)
    # mount_setattr syscall number is 442 on supported x86_64/aarch64 Linux.
    _need(libc.syscall(442, -100, b'/', 0x8000, ctypes.byref(attr), ctypes.sizeof(attr)) == 0,
          'recursive readonly containment unavailable')
    targets = set()
    for row in writable:
        exact(row, ('root_index', 'target', 'identity'))
        index = _uint(row['root_index']); target = row['target']
        _need(index < len(custody.directory_fds) and type(target) is str and target.startswith('/') and
              target not in ('/', '/nix', '/nix/store', '/proc', '/sys', '/dev', '/run') and
              not any(part in ('', '.', '..') for part in target.split('/')[1:]) and
              target not in targets and not any(target.startswith(old + '/') or old.startswith(target + '/')
                                               for old in targets), 'unsafe writable containment target')
        fd = custody.directory_fds[index]; info = os.fstat(fd)
        _need((info.st_dev, info.st_ino) == tuple(row['identity']) and
              (os.stat(target).st_dev, os.stat(target).st_ino) == tuple(row['identity']), 'mount target identity')
        source = ('/proc/self/fd/' + str(fd)).encode()
        _need(libc.mount(source, target.encode(), None, 4096, None) == 0, 'writable bind unavailable')
        targets.add(target)


def fixed_entry(slot, config_fd, publisher_channel, custody_owner):
    """Reserved Root adapter entry; the trampoline never accepts either fd from C.

    Actual descriptor producer integration is owned by Root. No fallback opens a
    caller path or accepts env fd numbers. Missing B1 refuses before launch.
    """
    _need(type(custody_owner) is DescriptorCustody and custody_owner.state == 'empty',
          'Root caller must retain one fresh DescriptorCustody')
    site = None; primary = None
    try:
        token(slot)
        root_file(config_fd)
        config = exact(decode(read_fd(config_fd, PACKET_MAX)), ('publisher',))
        publisher = process_record(config['publisher'])
        custody = receive_custody(publisher_channel, publisher, custody_owner)
        site = SiteNativeBinding(custody, publisher)
        _need(site.intent['slot_id'] == slot, 'slot mismatch')
        a = site.admission
        return FixedRootSupervisor(site, tuple(a['approved_argv']), tuple(a['approved_env'].items()),
                                   5, tuple(a['worker_executable'])).launch(site.intent_raw)
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            receipt = site.close(primary) if site is not None else custody_owner.close()
        except BaseException as teardown_error:
            receipt = custody_owner.retain_unknown('entry_teardown_unknown')
            if primary is None:
                _custody_note(teardown_error, custody_owner)
                raise
            _secondary(primary, 'entry teardown unknown', teardown_error)
        if primary is not None:
            _custody_note(primary, custody_owner)
        elif receipt['state'] in ('retained_unknown', 'close_unknown'):
            error = ProviderRefusal('bounded Root custody unknown; explicit owner retained')
            _custody_note(error, custody_owner)
            raise error


def main():
    # This packaged source entry intentionally does not discover private Root
    # sockets/config. Root must supply the approved descriptor producer route.
    # The source package cannot make an incomplete installation authoritative.
    import sys
    _need(len(sys.argv) == 3 and sys.argv[1] == 'run-bound-b0', 'fixed opcode required')
    token(sys.argv[2])
    raise ProviderRefusal('Root descriptor producer not connected; controller_induced_bound_missing')


if __name__ == '__main__':
    main()
