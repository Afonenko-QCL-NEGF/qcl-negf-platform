"""Read-only Slurm job PID/cgroup evidence. Never submit, cancel or signal jobs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time
from uuid import UUID

TERMINAL = {'CANCELLED', 'COMPLETED', 'FAILED', 'TIMEOUT', 'OUT_OF_MEMORY', 'NODE_FAIL'}
STORE_EXE = re.compile(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/]+/bin/slurmstepd\Z')


def need(value, message):
    if not value:
        raise ValueError(message)


def expected_job(expected):
    job = expected['job_id']
    need(isinstance(job, str) and re.fullmatch(r'[1-9][0-9]{0,9}', job), 'Exact numeric job required')
    need(expected['owner_uid'] == 3000, 'QCL task owner must be UID3000')
    need(STORE_EXE.fullmatch(expected['slurmstepd_executable']), 'Exact immutable slurmstepd required')
    scope = expected['cgroup_scope']
    need(isinstance(scope, str) and scope.startswith('/') and scope != '/'
         and str(Path(scope)) == scope and '..' not in Path(scope).parts, 'Exact cgroup scope required')
    need(re.fullmatch(r'[0-9a-f]{32}', expected['identity']['machine_id']), 'Machine identity required')
    UUID(expected['identity']['boot_id'])
    return scope + '/job_' + job


def same_identity(snapshot, expected):
    need(snapshot['identity_before'] == snapshot['identity_after'] == expected['identity'],
         'Machine/boot changed during observation')


def classify_before(snapshot, expected):
    root = expected_job(expected)
    same_identity(snapshot, expected)
    listing = snapshot['listpids']
    need(listing['rc'] == 0 and 0 < len(listing['rows']) <= 256, 'Successful nonempty listpids required')
    rows = listing['rows']
    need(len({r['pid'] for r in rows}) == len(rows), 'Duplicate scheduler PID')
    processes = snapshot['processes']
    need(len(processes) == len(rows) and {p['pid'] for p in processes} == {r['pid'] for r in rows},
         'Every scheduler PID needs a capture')
    need(any(p.get('uids') == [3000] * 4 for p in processes), 'Live owner task required, not supervisor alone')
    by_pid = {p['pid']: p for p in processes}
    for row in rows:
        p = by_pid[row['pid']]
        need(type(row['pid']) is int and row['pid'] > 0 and row['job_id'] == expected['job_id'],
             'Foreign scheduler PID/job')
        step = row['step_id']
        need(isinstance(step, str) and re.fullmatch(r'[A-Za-z0-9_-]+', step), 'Exact step identity required')
        prefix = root + '/step_' + step + '/'
        need(p.get('error') is None and type(p.get('start_ticks')) is int and p['start_ticks'] > 0,
             'Partial capture or missing PID start ticks')
        group = p.get('cgroup', '')
        need(group.startswith(prefix) and '..' not in Path(group).parts, 'PID outside exact job/step subtree')
        if p.get('uids') == [3000] * 4:
            need(group != prefix + 'slurm' and isinstance(p.get('exe'), str) and p['exe'].startswith('/'),
                 'Task must have an observed executable and task cgroup')
        else:
            need(p.get('uids') == [0] * 4 and p.get('exe') == expected['slurmstepd_executable']
                 and group == prefix + 'slurm', 'Unknown privileged/foreign job process')
    return {'schema': 'qcl-negf.slurm-job-before.v1', 'status': 'pass_live_job_membership',
            'identity': expected['identity'], 'job_id': expected['job_id'], 'owner_uid': 3000,
            'job_cgroup': root, 'processes': processes, 'listpids_rows': rows}


def validate_before(before, expected):
    root = expected_job(expected)
    need(before['schema'] == 'qcl-negf.slurm-job-before.v1'
         and before['status'] == 'pass_live_job_membership' and before['identity'] == expected['identity']
         and before['job_id'] == expected['job_id'] and before['job_cgroup'] == root
         and before['owner_uid'] == 3000, 'Actual matching before proof required')
    classify_before({'identity_before': before['identity'], 'identity_after': before['identity'],
                     'listpids': {'rc': 0, 'rows': before['listpids_rows']},
                     'processes': before['processes']}, expected)


def verify_after(before, current, expected):
    root = expected_job(expected)
    same_identity(current, expected)
    validate_before(before, expected)
    old = before['processes']
    need(old and all(type(p.get('start_ticks')) is int and p['start_ticks'] > 0 for p in old),
         'Missing original start ticks')
    seen = current['processes']
    need(len(seen) == len(old) and len({p['pid'] for p in seen}) == len(seen)
         and {p['pid'] for p in seen} == {p['pid'] for p in old}, 'Incomplete current PID observation')
    by_pid = {p['pid']: p for p in seen}
    for p in old:
        now = by_pid[p['pid']]
        need(now.get('error') is None and (now.get('absent') is True or
             (now.get('absent') is False and type(now.get('start_ticks')) is int
              and now['start_ticks'] > 0 and now['start_ticks'] != p['start_ticks'])),
             'Original process still live or not measured')
    group = current['job_cgroup']
    need(group['path'] == root and (group['absent'] is True or
         (group['absent'] is False and type(group.get('populated')) is int and group['populated'] == 0)),
         'Whole job subtree still populated or unmeasured')
    scheduler = current['scheduler']
    need(scheduler['rc'] == 0 and scheduler['job_id'] == expected['job_id']
         and scheduler['owner_uid'] == 3000 and scheduler['state'] in TERMINAL,
         'Actual owned scheduler terminal required')
    return {'schema': 'qcl-negf.slurm-job-after.v1', 'status': 'pass_physical_job_stop',
            'identity': expected['identity'], 'job_id': expected['job_id'],
            'job_cgroup': group, 'processes': seen, 'scheduler': scheduler,
            'scientific_accepted': False}


class Ledger:
    def __init__(self, directory):
        self.path = Path(directory)
        self.path.mkdir(mode=0o700)
        self.used = 0

    def put(self, name, raw):
        if not isinstance(raw, bytes):
            raw = (json.dumps(raw, sort_keys=True) + '\n').encode()
        remaining = max(0, 128 * 1024 - self.used)
        retained = raw[:remaining]
        with os.fdopen(os.open(self.path / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                               0o600), 'wb') as f:
            f.write(retained); f.flush(); os.fsync(f.fileno())
        self.used += len(retained)
        need(len(raw) <= remaining, 'Evidence cap exceeded; bounded original prefix retained')


def identity():
    return {'machine_id': Path('/etc/machine-id').read_text().strip(),
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def capture_process(pid, ledger):
    """Persist all available raw fields before interpreting or validating any."""
    p = Path('/proc') / str(pid)
    raw = {}; errors = {}
    for name in ('stat', 'status', 'cgroup', 'exe', 'stat_after'):
        try:
            value = os.readlink(p / 'exe').encode() if name == 'exe' else (p / ('stat' if name == 'stat_after' else name)).read_bytes()
            raw[name] = value
            ledger.put(str(pid) + '.' + name, value)
        except OSError as e:
            errors[name] = type(e).__name__
            ledger.put(str(pid) + '.' + name + '.error.json', {'error': type(e).__name__})
    if errors:
        return {'pid': pid, 'absent': not p.exists(), 'error': errors}
    try:
        ticks = int(raw['stat'].decode().rpartition(') ')[2].split()[19])
        ticks_after = int(raw['stat_after'].decode().rpartition(') ')[2].split()[19])
        need(ticks == ticks_after, 'PID reused during capture')
        uids = list(map(int, next(l for l in raw['status'].decode().splitlines() if l.startswith('Uid:')).split()[1:]))
        groups = raw['cgroup'].decode().splitlines()
        need(len(groups) == 1 and groups[0].startswith('0::/'), 'Unified cgroup required')
        return {'pid': pid, 'absent': False, 'start_ticks': ticks, 'uids': uids,
                'exe': raw['exe'].decode(), 'cgroup': groups[0][3:], 'error': None}
    except (ValueError, IndexError, StopIteration) as e:
        return {'pid': pid, 'error': type(e).__name__}


def command(argv, ledger, stem, timeout=10):
    ledger.put(stem + '.started.json', {'argv': argv, 'rc': 'not_measured'})
    streams = {}
    process = None
    selector = selectors.DefaultSelector()
    output = bytearray()
    rc = 'not_measured'
    error = None
    try:
        for name in ('stdout', 'stderr'):
            streams[name] = os.fdopen(os.open(ledger.path / (stem + '.' + name),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb')
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
        selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
        end = time.monotonic() + timeout
        while selector.get_map():
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Readonly metadata command timed out')
            for key, _ in selector.select(min(0.1, remaining)):
                chunk = os.read(key.fd, 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                room = max(0, 128 * 1024 - ledger.used)
                streams[key.data].write(chunk[:room]); streams[key.data].flush()
                os.fsync(streams[key.data].fileno()); ledger.used += len(chunk[:room])
                need(len(chunk) <= room, 'Evidence cap exceeded; durable prefix retained')
                if key.data == 'stdout':
                    output.extend(chunk)
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Readonly metadata command timed out')
        rc = process.wait(timeout=remaining)
    except BaseException as e:
        rc = 'not_measured_timeout' if isinstance(e, (TimeoutError, subprocess.TimeoutExpired)) else 'not_measured'
        error = e
    finally:
        # Only this collector's readonly CLI child, never a Slurm job or daemon.
        if process is not None and process.poll() is None:
            process.kill(); process.wait(timeout=2)
        selector.close()
        for stream in streams.values():
            stream.close()
        if process is not None:
            process.stdout.close(); process.stderr.close()
    if ledger.used < 127 * 1024:
        ledger.put(stem + '.result.json', {'argv': argv, 'rc': rc})
    if error is not None:
        raise error
    return rc, output.decode()


def capture_before(expected, scontrol, ledger):
    first = identity()
    ledger.put('identity-before.json', first)
    rc, text = command([scontrol, 'listpids', expected['job_id']], ledger, 'listpids')
    rows = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3 and parts[0].isdigit():
            rows.append({'pid': int(parts[0]), 'job_id': parts[1], 'step_id': parts[2]})
    # No membership assertions until every scheduler row has been captured.
    processes = [capture_process(r['pid'], ledger) for r in rows]
    last = identity(); ledger.put('identity-after.json', last)
    need(text.splitlines() and text.splitlines()[0].split()[:2] == ['PID', 'JOBID'], 'Invalid listpids header')
    need(all(len(l.split()) >= 3 and l.split()[0].isdigit() for l in text.splitlines()[1:] if l.strip()),
         'Malformed listpids row; raw retained')
    return {'identity_before': first, 'identity_after': last,
            'listpids': {'rc': rc, 'rows': rows}, 'processes': processes}


def capture_after(before, expected, scontrol, ledger):
    # Validate the prior frozen path/PID set before using it for privileged reads.
    validate_before(before, expected)
    first = identity(); ledger.put('identity-before.json', first)
    processes = []
    for old in before['processes']:
        if not (Path('/proc') / str(old['pid'])).exists():
            row = {'pid': old['pid'], 'absent': True}
            ledger.put(str(old['pid']) + '.absent.json', row)
        else:
            row = capture_process(old['pid'], ledger)
        processes.append(row)
    path = Path('/sys/fs/cgroup' + before['job_cgroup'])
    if path.exists():
        raw = (path / 'cgroup.events').read_bytes(); ledger.put('cgroup.events', raw)
        group = {'path': before['job_cgroup'], 'absent': False,
                 'populated': int(dict(l.split() for l in raw.decode().splitlines())['populated'])}
    else:
        group = {'path': before['job_cgroup'], 'absent': True, 'populated': None}
    ledger.put('whole-job-cgroup.json', group)
    rc, text = command([scontrol, '--oneliner', 'show', 'job', expected['job_id']], ledger, 'scheduler')
    fields = dict(re.findall(r'(?<!\S)(\w+)=([^\s]+)', text))
    match = re.fullmatch(r'[^()\s]+\(([0-9]+)\)', fields.get('UserId', ''))
    scheduler = {'rc': rc, 'job_id': fields.get('JobId'), 'owner_uid': int(match[1]) if match else None,
                 'state': fields.get('JobState')}
    last = identity(); ledger.put('identity-after.json', last)
    return {'identity_before': first, 'identity_after': last, 'processes': processes,
            'job_cgroup': group, 'scheduler': scheduler}


def frozen(path, digest):
    path = Path(path)
    need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 65536,
         'Regular bounded frozen input required')
    raw = path.read_bytes()
    need(len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == digest, 'Frozen input mismatch')
    return json.loads(raw)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode', choices=('before', 'after'), required=True)
    p.add_argument('--expected', required=True); p.add_argument('--expected-sha256', required=True)
    p.add_argument('--before'); p.add_argument('--before-sha256')
    p.add_argument('--scontrol', required=True); p.add_argument('--out', required=True)
    a = p.parse_args()
    def deadline(_signal, _frame):
        raise TimeoutError('Whole collector deadline exceeded')
    signal.signal(signal.SIGALRM, deadline); signal.alarm(20)
    need(os.geteuid() == 0, 'Root read access required')
    expected = frozen(a.expected, a.expected_sha256); expected_job(expected)
    need(Path(a.scontrol).is_file() and os.access(a.scontrol, os.X_OK)
         and a.scontrol.startswith('/nix/store/') and Path(a.scontrol).name == 'scontrol',
         'Explicit installed scontrol required')
    ledger = Ledger(a.out); ledger.put('expected.json', expected)
    try:
        if a.mode == 'before':
            snapshot = capture_before(expected, a.scontrol, ledger)
            ledger.put('snapshot.json', snapshot)
            proof = classify_before(snapshot, expected)
        else:
            before = frozen(a.before, a.before_sha256)
            snapshot = capture_after(before, expected, a.scontrol, ledger)
            ledger.put('snapshot.json', snapshot)
            proof = verify_after(before, snapshot, expected)
        proof['observed_epoch'] = time.time(); ledger.put('proof.json', proof)
        print(json.dumps(proof))
    except BaseException as e:
        if ledger.used < 127 * 1024:
            ledger.put('failure.json', {'status': 'failed_or_partial', 'error': type(e).__name__,
                                       'physical_stop': 'not_measured'})
        raise


if __name__ == '__main__':
    main()
