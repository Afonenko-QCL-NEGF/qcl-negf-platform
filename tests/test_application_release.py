"""Exercise release activation at the Nix/SSH/systemd command boundary.

No services, SSH connections, solver or Nix closures are built by these tests.
The real activation writes profiles/configuration, guards jobs and gates the pool.
"""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
import sys
import os
import signal
import shlex
import base64
from contextlib import ExitStack, contextmanager
import io
import time
from unittest.mock import patch
from test_node_enrollment import CONTROLLER, WORKER, SECOND, TRUST, ENROLL_IDS, selected_context

SPEC = importlib.util.spec_from_file_location(
    "application_release", Path(__file__).parents[1] / "ops" / "application_release.py"
)


class Commands:
    def __init__(self):
        self.calls = []
        self.failure = None
        self.registered = "12345678-1234-1234-1234-123456789abc"

    def __call__(self, args):
        self.calls.append(args)
        if self.failure and self.failure in args:
            raise RuntimeError("injected command failure")
        if args[0] == "nix-env":
            profile = Path(args[args.index("--profile") + 1])
            profile.unlink(missing_ok=True)
            profile.symlink_to(args[-1])
        if "register_aiida.py" in " ".join(args):
            return json.dumps({"code_uuid": self.registered,
                               "solver_executable": "/nix/store/solver/bin/qcl-negf"})
        if "self-check" in args:
            return json.dumps({"schema": "qcl-negf-self-check-v1", "status": "completed",
                               "scientific_accepted": False})
        return ""


class InitialCommands(Commands):
    """Simulate only Nix/Slurm; publication and profile identity checks stay real."""
    def __init__(self):
        super().__init__()
        self.queue = ""
        self.evidence = {"/nix/store/application": {"narHash": HASH},
                         "/nix/store/solver": {"narHash": HASH}}

    def __call__(self, args):
        result = super().__call__(args)
        if args[0] == "squeue":
            return self.queue
        if args[:3] == ["nix", "path-info", "--json"]:
            return json.dumps(self.evidence)
        if args[0] not in ("nix-store", "nix-env", "nix", "squeue"):
            raise AssertionError("Initial preparation must not run services, Code creation or solver")
        return result


def release():
    return {"schema": "qcl-negf-release-v1", "release_id": "release-a",
            "application_path": "/nix/store/application",
            "solver_executable": "/nix/store/solver/bin/qcl-negf"}


HASH = "sha256-" + "A" * 43 + "="
OTHER_HASH = "sha256-" + "B" * 43 + "="


def delivery_manifest(cache=True):
    value = {**release(), "closures": [{"path": "/nix/store/application", "narHash": HASH},
                                       {"path": "/nix/store/solver", "narHash": HASH}]}
    if cache:
        value["cache_uri"] = "https://cache.example.invalid"
    return value


POOL = {"schema": "qcl-negf-active-pool-v2", "nodes": [
    {"name": "controller", "target": "admin@controller.invalid", "role": "controller", "enrollment_id": ENROLL_IDS[0]},
    {"name": "worker", "target": "admin@worker.invalid", "role": "worker", "enrollment_id": ENROLL_IDS[1]}]}


def update_capability():
    return {'schema':'qcl-negf-local-update-capability-v1','stop_update':True,'stopped_identity':True,'fleet_health':True,'aiida_two_workflow_types':True}

def clear_aiida():
    return {'schema':'qcl-negf-aiida-update-check-v1','profile':'qcl-negf','roots_checked':True,'calcjobs_checked':True,'active_root_found':False,'active_calcjob_found':False,'root_sample':None,'calcjob_sample':None}

def stopped_response(actual,attempt):
    return {'schema':'qcl-negf-update-stop-v1','attempt_id':attempt,'enrollment_id':ENROLL_IDS[2] if actual['node_name']=='second' else ENROLL_IDS[1],'node_identity':actual,
        'machine':{**{k:actual[k] for k in ('hostname','machine_uuid','machine_id','boot_id')},'release_config_sha256':'c'*64,'slurm_conf':'/etc/slurm.conf','slurm_conf_sha256':'d'*64},'stop_window':{'requested_epoch':1791504120,'captured_epoch':1791504121},
        'original_config_digest':'d'*64,'job_processes_measured':True,'job_processes_empty':True,
        'daemon_processes':[],'service_members':[],'service_members_measured':True,'service_scope_complete':True,'restart_inhibited':True,'forced_daemon_stop':False,
        'systemd':{'LoadState':'masked','UnitFileState':'masked-runtime','ActiveState':'inactive','SubState':'dead','MainPID':'0','ControlGroup':'','InvocationID':''}}

def control_response(args,actual,model=None):
    words=shlex.split(args[-1])
    if words[-1]=='update-capabilities':return json.dumps(update_capability())
    if 'update-identity' in words:return json.dumps(actual)
    if '--update-attempt-id' in words:
        attempt=words[words.index('--update-attempt-id')+1]
        if any(a in words for a in ('stop-update','stopped-identity')):return json.dumps(stopped_response(actual,attempt))
        if 'finish-update' in words:return json.dumps({'attempt_id':attempt,'marker_removed':True})
        if 'health-update' in words:
            value={'schema':'qcl-negf-node-release-check-v1','node_identity':actual,'release':{**release(),'ready':True},'auth_verified':True,'nfs_verified':True,'nfs_source':'storage.invalid:/srv/qcl-negf/jobs'}
            if actual['role']=='worker':value.update((model or NativeUpdateModel()).health(actual['node_name']))
            return json.dumps(value)
    return None

def controller_stop_state():
    return '\n'.join(k+'='+v for k,v in {'LoadState':'loaded','ActiveState':'inactive','SubState':'dead','MainPID':'0','ControlGroup':'','InvocationID':'','UnitFileState':'enabled','FragmentPath':'/nix/store/unit/service','DropInPaths':''}.items())

class DeliveryCommands:
    """Only local command boundaries are simulated; gate writes stay real."""
    def __init__(self, gate):
        self.gate = gate
        self.calls = []
        self.failure = False
        self.evidence = {"/nix/store/application": {"narHash": HASH},
                         "/nix/store/solver": {"narHash": HASH}}
        self.prefetch_gate_snapshots = []
        self.model = NativeUpdateModel()

    def __call__(self, args):
        self.calls.append(args)
        if args[:3] == ["nix", "copy", "--from"]:
            self.prefetch_gate_snapshots.append(self.gate.read_bytes())
            if self.failure:
                raise RuntimeError("cache fetch failed")
        if args[:3] == ["nix", "path-info", "--json"]:
            self.prefetch_gate_snapshots.append(self.gate.read_bytes())
            return self.evidence if isinstance(self.evidence, str) else json.dumps(self.evidence)
        if args[0] == "ssh":
            words, observed = release_ssh(args)
            if "activate" in words:self.model.activate(observed["node_name"])
            if args[-1].endswith(" identity"):
                return json.dumps(observed)
            extra=control_response(args,observed,model=self.model)
            if extra is not None:return extra
            if " check " in args[-1]:
                return json.dumps({"schema": "qcl-negf-node-release-check-v1", "node_identity": observed,
                                   "release": {**release(), "ready": True}})
        if args==['id','-u']:return '1000\n'
        if args==['id','-un']:return 'operator\n'
        if args==['env','TZ=UTC','LC_ALL=C','date','+%s']:return '1791504120\n'
        if 'aiida_update_check.py' in ' '.join(args):return json.dumps(clear_aiida())
        if args[:2]==['systemctl','show']:return controller_stop_state()
        if 'scontrol' in args:return self.model.command(args)
        return ""


def release_ssh(args):
    """Validate exactly the frozen SSH trust/options, target and sudo CLI."""
    targets={'admin@controller.invalid':CONTROLLER,'admin@worker.invalid':WORKER,'admin@second.invalid':SECOND}
    if args[0]!='ssh' or args[-2] not in targets:raise AssertionError('unbound SSH target')
    options=args[1:-2]
    required=['-oBatchMode=yes','-oConnectionAttempts=1','-oConnectTimeout=10',
              '-oServerAliveInterval=15','-oServerAliveCountMax=2','-oControlMaster=no','-oControlPath=none',
              '-F','/dev/null','-oStrictHostKeyChecking=yes','-oUserKnownHostsFile='+TRUST['path'],
              '-oGlobalKnownHostsFile=/dev/null','-oUpdateHostKeys=no','-oKnownHostsCommand=none']
    if options!=required:raise AssertionError('SSH trust or options changed')
    words=shlex.split(args[-1])
    if words[:3]!=['sudo','-n','qcl-negf-release']:raise AssertionError('unexpected privileged command')
    return words,targets[args[-2]]


def readonly_release_ssh(args):
    words,_=release_ssh(args)
    return len(words)==4 and words[3] in ('identity','update-capabilities')


class NativeUpdateModel:
    """Independent scheduler transitions; no production validator or output-derived oracle."""
    def __init__(self):
        self.nodes={name:{'NodeName':name,'CPUTot':'12','RealMemory':'28000','Version':'25.11.0',
            'BootTime':'2026-10-09T00:00:00','SlurmdStartTime':'2026-10-09T00:01:00',
            'CPUAlloc':'0','AllocMem':'0','State':'IDLE','Reason':'None'} for name in ('worker','second')}
        self.generation={name:1 for name in self.nodes};self.shows={name:0 for name in self.nodes}
        self.resume_reads={};self.transitions=[];self.before_show=None;self.after_drain=None;self.reason_form='suffix';self.reason_fault=None;self.volatile=False
    def activate(self,name):
        if name is None:return
        self.generation[name]+=1
        self.nodes[name]['SlurmdStartTime']='2026-10-09T00:02:00'
    def health(self,name):
        registration={k:self.nodes[name][k] for k in ('NodeName','CPUTot','RealMemory','Version','BootTime','SlurmdStartTime')}
        return {'registration':registration,'daemon_generation':{'pid':122+self.generation[name],
            'start_ticks':97+self.generation[name],'executable':'/nix/store/slurm/bin/slurmd',
            'InvocationID':('b'*32 if self.generation[name]>1 else 'a'*32),'slurm_conf_sha256':'d'*64},
            'restart_window':{'requested_epoch':1791504120,'captured_epoch':1791504121}}
    def command(self,args):
        if args[:5]!=['env','TZ=UTC','LC_ALL=C','SLURM_CONF=/etc/slurm.conf','scontrol']:raise AssertionError('native registration/update requires explicit UTC and selected SLURM_CONF')
        words=args[5:]
        if words[:2]==['show','node']:
            name=words[2];self.shows[name]+=1
            if self.before_show:self.before_show(name,self.shows[name])
            value=dict(self.nodes[name])
            if self.resume_reads.get(name):value.update(self.resume_reads[name].pop(0))
            if value.get('State')=='IDLE' and value.get('Reason')=='None':value.pop('Reason')
            if self.volatile:value.update(CPULoad=str(self.shows[name]),FreeMem=str(10000-self.shows[name]),LastBusyTime='2026-10-09T00:00:'+str(self.shows[name]).zfill(2))
            return ' '.join(k+'='+v for k,v in value.items())
        if words[0]!='update':raise AssertionError('unsupported synthetic scheduler action')
        fields=dict(word.split('=',1) for word in words[1:]);name=fields['NodeName']
        if fields['State']=='DRAIN':
            reason=fields['Reason']
            if self.reason_form=='suffix':reason+=' [operator@2026-10-09T00:02:00]'
            if self.reason_fault=='actor':reason=fields['Reason']+' [foreign@2026-10-09T00:02:00]'
            elif self.reason_fault=='tag':reason='application-release:99999999-9999-9999-9999-999999999999 [operator@2026-10-09T00:02:00]'
            elif self.reason_fault=='stale':reason=fields['Reason']+' [operator@2026-10-09T00:01:59]'
            elif self.reason_fault=='future':reason=fields['Reason']+' [operator@2026-10-09T00:02:01]'
            elif self.reason_fault=='calendar':reason=fields['Reason']+' [operator@2026-02-30T00:02:00]'
            elif self.reason_fault=='extra':reason+=' extra'
            self.nodes[name].update(State='IDLE+DRAIN',Reason=reason)
            if self.after_drain:self.after_drain(name)
        elif fields['State']=='RESUME':self.nodes[name].update(State='IDLE',Reason='None')
        else:raise AssertionError('unauthorized synthetic state transition')
        self.transitions.append((name,dict(fields)))
        return ''


def install_controller_config_io(test,root):
    path=root/'controller-release-config.json'
    path.write_text(json.dumps({'role':'controller','slurm_conf':'/etc/slurm.conf','nfs_source':'storage.invalid:/srv/qcl-negf/jobs'}))
    original=io.open
    def boundary(file,*args,**kwargs):
        return original(path if isinstance(file,(str,bytes,os.PathLike)) and os.fspath(file)=='/etc/qcl-negf/release-config.json' else file,*args,**kwargs)
    hook=patch.object(io,'open',boundary);hook.start();test.addCleanup(hook.stop)


class ApplicationReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ops = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(cls.ops)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.runtime = Path(temporary.name) / "runtime"
        self.gate = Path(temporary.name) / "gate"
        install_controller_config_io(self,Path(temporary.name))
        # Existing CR04 regressions use handwritten enrollment/observation facts;
        # CR03 tests exercise actual authority/protected helpers independently.
        context = selected_context()
        context["bindings"] = context["bindings"][:2]
        context["registry"]["nodes"] = context["registry"]["nodes"][:2]
        original_delivery, original_pool = self.ops.deliver_cli, self.ops.deliver_pool
        def preflight(*args, **kwargs):
            if kwargs.get("before_remote"):
                kwargs["before_remote"]()
            return context
        def delivery(*args, **kwargs):
            kwargs.setdefault("enrollment", "/synthetic/enrollment.json")
            return original_delivery(*args, **kwargs)
        def bound_pool(value, nodes, *args, **kwargs):
            kwargs.setdefault("runtime", self.runtime)
            if "bindings" not in kwargs:
                observations = {"worker": WORKER, "worker-a": {**WORKER, "node_name": "worker-a"},
                                "worker-b": {**SECOND, "node_name": "worker-b"}}
                bindings = {node: {**observations[node], "identity": observations[node]} for node in nodes}
                callback = kwargs["deliver"]
                def envelope(node, expected):
                    result = callback(node, expected)
                    return {"schema": "qcl-negf-node-release-check-v1", "node_identity": observations[node], "release": result}
                kwargs.update(bindings=bindings, authority=context, deliver=envelope)
            return original_pool(value, nodes, *args, **kwargs)
        for name, replacement in (("preflight_controller_authority", preflight), ("observe_node_identity", lambda **_: CONTROLLER),
                                  ("deliver_cli", delivery), ("deliver_pool", bound_pool)):
            mocker = patch.object(self.ops, name, replacement)
            mocker.start()
            self.addCleanup(mocker.stop)


    def test_native_bounded_prefix_and_retained_descendant_pipe(self):
        for parent_exits in (False, True):
            with self.subTest(parent_exits=parent_exits):
                pidfile = self.runtime.parent / "pid"
                code = ("import os,time; p=os.fork(); "
                        "open(" + repr(str(pidfile)) + ", 'w').write(str(os.getpid())) if p==0 else None; "
                        "print('prefix',flush=True); " +
                        ("os._exit(0) if p else time.sleep(10)" if parent_exits else "time.sleep(10)"))
                start = time.monotonic()
                try:
                    with self.assertRaises(self.ops.CommandFailure) as caught:
                        self.ops.command([sys.executable, "-c", code], timeout_seconds=.8,
                                         cleanup_seconds=.2, output_bytes=4096)
                    self.assertLess(time.monotonic() - start, 1.5)
                    record = caught.exception.record
                    self.assertIn("prefix", record["stdout"])
                    self.assertTrue(record["cleanup_confirmed"])
                    if pidfile.exists():
                        pid = int(pidfile.read_text())
                        stat = Path("/proc") / str(pid) / "stat"
                        acknowledged = time.monotonic() + .2
                        while stat.exists() and stat.read_text().split()[2] not in ("Z", "X") and time.monotonic() < acknowledged:
                            time.sleep(.005)
                        self.assertTrue(not stat.exists() or stat.read_text().split()[2] in ("Z", "X"))
                finally:
                    if pidfile.exists():
                        try:
                            os.kill(int(pidfile.read_text()), signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        pidfile.unlink()

    def test_native_combined_cap_nonzero_and_finite_validation(self):
        with self.assertRaises(self.ops.CommandFailure) as caught:
            self.ops.command([sys.executable, "-c",
                "import os,time; os.write(1,b'x'*3000); os.write(2,b'y'*3000); time.sleep(10)"],
                timeout_seconds=1, cleanup_seconds=.2, output_bytes=4096)
        record = caught.exception.record
        self.assertEqual(record["failure"], "output_limit")
        self.assertLessEqual(len(record["stdout"].encode()) + len(record["stderr"].encode()), 4096)
        with self.assertRaises(self.ops.CommandFailure) as caught:
            self.ops.command([sys.executable, "-c", "import sys; print('bad',file=sys.stderr); sys.exit(7)"],
                             timeout_seconds=1, cleanup_seconds=.2)
        self.assertEqual(caught.exception.record["returncode"], 7)
        self.assertIn("bad", caught.exception.record["stderr"])
        for value in (True, float('nan'), float('inf'), 0):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.ops.command([sys.executable], timeout_seconds=value)

    def test_uncertain_activation_receipt_blocks_retry(self):
        self.gate.write_text(json.dumps({"open": True, "release_id": "old"}))
        run = DeliveryCommands(self.gate)
        def loss(args):
            result = run(args)
            if args[0] == "ssh" and " activate " in args[-1]:
                raise self.ops.CommandFailure({"failure": "nonzero", "returncode": 255,
                    "stdout": "partial", "stderr": "lost", "child_started": True,
                    "cleanup_confirmed": True, "elapsed_seconds": .1, "output_truncated": False})
            return result
        result = self.ops.deliver_cli(delivery_manifest(), POOL, run=loss,
                                     runtime=self.runtime, gate=self.gate)
        self.assertTrue(result["requires_reconciliation"])
        self.assertFalse(json.loads(self.gate.read_text())["open"])
        self.assertEqual(result["nodes"]["worker"]["status"], "not_attempted")
        receipt = json.loads(Path(result["receipt"]).read_text())
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["manifest"]["closures"], delivery_manifest()["closures"])
        self.assertIn("partial", json.dumps(receipt))
        before = list(run.calls)
        with self.assertRaisesRegex(RuntimeError, "reconciliation"):
            self.ops.deliver_cli(delivery_manifest(), POOL, run=loss,
                                 runtime=self.runtime, gate=self.gate)
        self.assertEqual(before, run.calls)
        self.assertFalse(any(" check " in args[-1] or "State=RESUME" in args for args in run.calls))

    def test_aggregate_deadline_and_output_do_not_reset(self):
        for case in ('pre_gate_deadline','post_gate_deadline','output_limit'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as temporary:
                runtime=Path(temporary)/'runtime';gate=Path(temporary)/'gate'
                original_gate=json.dumps({'open':True,'release_id':'old'}).encode();gate.write_bytes(original_gate)
                run=DeliveryCommands(gate);clock=[100.0];events=[]
                copy=['nix','copy','--from','https://cache.example.invalid','/nix/store/application','/nix/store/solver']
                path_info=['nix','path-info','--json','/nix/store/application','/nix/store/solver']
                registration=['env','TZ=UTC','LC_ALL=C','SLURM_CONF=/etc/slurm.conf','scontrol','show','node','worker','--oneliner']
                quiesce=['systemctl','stop','qcl-negf-api.service','qcl-negf-aiida.service']
                charged=[copy,path_info,registration if case=='pre_gate_deadline' else quiesce]
                def measured(args):
                    before=clock[0];gate_before=gate.read_bytes();result=run(args)
                    if case!='output_limit' and args in charged:clock[0]+=1.0
                    events.append({'argv':list(args),'before':before,'after':clock[0],'gate':gate_before})
                    return result
                with patch.object(self.ops.time,'monotonic',lambda:clock[0]):
                    if case=='post_gate_deadline':
                        summary=self.ops.deliver_cli(delivery_manifest(),POOL,run=measured,runtime=runtime,gate=gate,delivery_timeout_seconds=3)
                        self.assertTrue(summary['requires_reconciliation']);self.assertEqual(summary['remote_outcome'],'unknown')
                        self.assertEqual(summary['status'],'failed')
                    else:
                        with self.assertRaises(self.ops.CommandFailure) as failure:
                            self.ops.deliver_cli(delivery_manifest(),POOL,run=measured,runtime=runtime,gate=gate,delivery_timeout_seconds=3,delivery_output_bytes=20 if case=='output_limit' else 8388608)
                        summary=failure.exception.delivery_summary
                        self.assertEqual(failure.exception.record['failure'],'output_limit' if case=='output_limit' else 'deadline')
                        self.assertIs(failure.exception.record['child_started'],True)
                receipt_path=Path(summary['receipt']);self.assertEqual(receipt_path.parent,runtime/'delivery-attempts')
                self.assertEqual(summary['attempt_id'],receipt_path.stem)
                current=[p for p in (runtime/'delivery-attempts').glob('*.json') if not p.name.endswith('.admission-intent.json')]
                self.assertEqual(current,[receipt_path]);receipt=json.loads(receipt_path.read_text())
                self.assertEqual(receipt['attempt_id'],receipt_path.stem);self.assertEqual(receipt['status'],'failed')
                failed=[c for c in receipt['commands'] if c['status']=='failed'];self.assertEqual(len(failed),1)
                pending=failed[0];self.assertIs(pending['record']['child_started'],True)
                self.assertEqual(pending['phase'],{'pre_gate_deadline':'slurm_original','post_gate_deadline':'quiesce','output_limit':'node_identity'}[case])
                self.assertEqual(pending['record']['failure'],'output_limit' if case=='output_limit' else 'deadline')
                self.assertIs(pending['mutation'],case=='post_gate_deadline')
                self.assertFalse(any('State=DRAIN' in a or 'State=RESUME' in a or a[:3]==['nix','copy','--to'] or a[0]=='ssh' and any(word in shlex.split(a[-1]) for word in ('stop-update','activate','check','finish-update')) for a in run.calls))
                charged_events=[event for event in events if event['after']!=event['before']]
                if case=='output_limit':
                    self.assertEqual(clock[0],100.0);self.assertEqual(charged_events,[])
                    self.assertEqual(len(run.calls),1);self.assertEqual(run.calls[0][0],'ssh');self.assertTrue(run.calls[0][-1].endswith(' identity'))
                    self.assertLessEqual(len(pending['record']['stdout'].encode())+len(pending['record']['stderr'].encode()),20)
                    self.assertEqual(gate.read_bytes(),original_gate);self.assertIs(receipt['gate_changed'],False)
                    self.assertFalse(any(a[0] in ('nix','systemctl') for a in run.calls))
                else:
                    self.assertEqual(clock[0],103.0)
                    self.assertEqual([(e['argv'],e['before'],e['after']) for e in charged_events],[(copy,100.0,101.0),(path_info,101.0,102.0),(charged[-1],102.0,103.0)])
                    self.assertEqual(sum(a==registration for a in run.calls),1)
                    self.assertEqual([e['gate'] for e in charged_events[:2]],[original_gate,original_gate])
                    if case=='pre_gate_deadline':
                        self.assertEqual(charged_events[-1]['gate'],original_gate);self.assertEqual(gate.read_bytes(),original_gate)
                        self.assertIs(receipt['gate_changed'],False);self.assertFalse(any(a[0]=='systemctl' for a in run.calls))
                    else:
                        self.assertEqual(json.loads(charged_events[-1]['gate']),{'open':False,'release_id':'release-a'})
                        self.assertEqual(json.loads(gate.read_bytes()),{'open':False,'release_id':'release-a'})
                        self.assertIs(receipt['gate_changed'],True);self.assertTrue(receipt['requires_reconciliation']);self.assertEqual(receipt['remote_outcome'],'unknown')
                        self.assertEqual([a for a in run.calls if a[0]=='systemctl'],[quiesce])

    def test_malformed_remote_check_is_unknown_and_stops_pool(self):
        self.gate.write_text(json.dumps({"open": True, "release_id": "old"}))
        run = DeliveryCommands(self.gate)
        def incomplete(args):
            result = run(args)
            return '{"ready":' if args[0] == "ssh" and " check " in args[-1] else result
        result = self.ops.deliver_cli(delivery_manifest(), POOL, run=incomplete,
                                     runtime=self.runtime, gate=self.gate)
        self.assertTrue(result["requires_reconciliation"])
        self.assertEqual(result["nodes"]["worker"]["status"], "not_attempted")
        self.assertFalse(any("State=RESUME" in args for args in run.calls))
        self.assertEqual(next((self.runtime / "delivery-attempts").glob("*.json")).stat().st_mode & 0o777, 0o600)

    def test_native_ssh_options_and_nix_environment_are_isolated(self):
        calls = []
        self.ops.ssh("admin@worker", ["echo", "hello world"], run=lambda args: calls.append(args) or "", trust_snapshot=TRUST)
        self.assertIn("-oControlMaster=no", calls[0])
        self.assertIn("-oConnectionAttempts=1", calls[0])
        self.assertEqual(calls[0][-1], "echo 'hello world'")
        self.assertIn("-oStrictHostKeyChecking=yes", calls[0])
        self.assertIn("-oUserKnownHostsFile=" + TRUST["path"], calls[0])
        # CR03 selected-node identity precedes Nix. Literal trusted observations
        # simulate SSH without consuming a native child or treating env=None as Nix.
        probes = []
        def identity(target, *, trust_snapshot, run):
            probes.append((target, trust_snapshot))
            observations = {"admin@controller.invalid": CONTROLLER,
                            "admin@worker.invalid": WORKER}
            return dict(observations[target])
        observed = []
        popen = self.ops.subprocess.Popen
        def fake_popen(args, **kwargs):
            if args[:2] != ["nix", "copy"]:
                raise ValueError("fixture stops after isolated native Nix copy before another child")
            observed.append((args, kwargs.get("env")))
            # Only our finite Python fixture executes; argv remains observed Nix.
            return popen([sys.executable, "-c", "print('{}')"], **kwargs)
        self.gate.write_text(json.dumps({"open": True, "release_id": "old"}))
        caller_environment = dict(os.environ)
        with patch.dict(os.environ, {"NIX_SSHOPTS": "-i /tmp/site-key"}), \
             patch.object(self.ops, "identity_probe", identity), \
             patch.object(self.ops, "ssh", lambda target,argv,*a,**k: json.dumps(update_capability()) if argv[-1]=='update-capabilities' else ''), \
             patch.object(self.ops.subprocess, "Popen", fake_popen):
            site_environment = dict(os.environ)
            with self.assertRaisesRegex(ValueError, "fixture stops"):
                self.ops.deliver_cli(delivery_manifest(), POOL, runtime=self.runtime, gate=self.gate,
                                     delivery_timeout_seconds=30, command_timeout_seconds=15)
            self.assertEqual(dict(os.environ), site_environment)
        self.assertEqual(dict(os.environ), caller_environment)
        self.assertEqual([target for target, _ in probes], ["admin@controller.invalid", "admin@worker.invalid"])
        self.assertTrue(all(snapshot == TRUST for _, snapshot in probes))
        nix_calls = [(args, env) for args, env in observed if args[:2] == ["nix", "copy"]]
        self.assertTrue(nix_calls, "actual CLI must reach native Nix Popen with isolated env")
        self.assertEqual(len(nix_calls), 1)  # One owned native child; RED consumed the other.
        for args, env in nix_calls:
            self.assertEqual(args[2:4], ["--from", "https://cache.example.invalid"])
            self.assertIsNotNone(env)
            self.assertIsNot(env, os.environ)
            for option in ("-oConnectTimeout=10", "-oControlMaster=no", "-oConnectionAttempts=1",
                           "-oStrictHostKeyChecking=yes", "-oUserKnownHostsFile=" + TRUST["path"],
                           "/tmp/site-key"):
                self.assertIn(option, env["NIX_SSHOPTS"])
            self.assertEqual({key: val for key, val in env.items() if key != "NIX_SSHOPTS"},
                             {key: val for key, val in site_environment.items() if key != "NIX_SSHOPTS"})

    def test_deadline_after_returned_mutation_retains_started_unknown(self):
        self.gate.write_text(json.dumps({"open": True, "release_id": "old"}))
        run = DeliveryCommands(self.gate)
        clock = [100.0]
        def completed_after_deadline(args):
            result = run(args)
            if args[0] == "ssh" and " activate " in args[-1]:
                clock[0] = 111.0
            return result
        with patch.object(self.ops.time, "monotonic", lambda: clock[0]):
            result = self.ops.deliver_cli(delivery_manifest(), POOL, run=completed_after_deadline,
                runtime=self.runtime, gate=self.gate, delivery_timeout_seconds=10)
        self.assertTrue(any(a[0] == "ssh" and "activate" in shlex.split(a[-1]) for a in run.calls), "intended activation effect was reached")
        self.assertTrue(result["requires_reconciliation"])
        self.assertEqual(result["remote_outcome"], "unknown")
        self.assertTrue(result["command_failure"]["child_started"])
        self.assertEqual(result["command_failure"]["failure"], "deadline")
        self.assertEqual(result["nodes"]["worker"]["status"], "not_attempted")
        self.assertFalse(any(" check " in args[-1] or "State=RESUME" in args for args in run.calls))
        self.assertFalse(json.loads(self.gate.read_text())["open"])

    def test_review_gate_open_fsync_and_terminal_receipt_failure_keep_blocker(self):
        for failure in ("gate_fsync", "terminal_after_replace", "terminal_persistent", "close_failure"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                gate, runtime = root / "gate", root / "runtime"
                gate.write_text(json.dumps({"open": True, "release_id": "old"}))
                run = DeliveryCommands(gate)
                publish = self.ops.publish_json
                admission = self.ops.publish_admission
                fired = [False]
                def fail_receipt(path, value, **kwargs):
                    if Path(path).parent.name == "delivery-attempts" and value.get("phase") == "finished":
                        if failure == "terminal_persistent":
                            raise OSError("persistent terminal receipt failure")
                        if failure == "terminal_after_replace" and not fired[0]:
                            publish(path, value, **kwargs)
                            fired[0] = True
                            raise OSError("terminal directory fsync failed after replace")
                    return publish(path, value, **kwargs)
                def fail_admission(path, value):
                    if value["open"] and failure in ("gate_fsync", "close_failure"):
                        admission(path, value)
                        fired[0] = True
                        raise OSError("gate directory fsync failed after replace")
                    if not value["open"] and failure == "close_failure" and fired[0]:
                        raise OSError("cannot confirm closed gate")
                    return admission(path, value)
                with patch.object(self.ops, "publish_json", fail_receipt), \
                     patch.object(self.ops, "publish_admission", fail_admission):
                    if failure == "terminal_persistent":
                        with self.assertRaises(OSError):
                            self.ops.deliver_cli(delivery_manifest(), POOL, run=run, runtime=runtime, gate=gate)
                        result = None
                    else:
                        result = self.ops.deliver_cli(delivery_manifest(), POOL, run=run, runtime=runtime, gate=gate)
                self.assertEqual(json.loads(gate.read_text())["open"], failure == "close_failure")
                self.assertTrue(list((runtime / "delivery-attempts").glob("*.admission-intent.json")))
                if result:
                    self.assertEqual(result["status"], "failed")
                    self.assertTrue(result["requires_reconciliation"])
                    if failure == "close_failure":
                        self.assertIsNone(result["open"])
                        self.assertTrue(result["critical_admission_failure"])
                before = list(run.calls)
                with self.assertRaisesRegex(RuntimeError, "reconciliation"):
                    self.ops.deliver_cli(delivery_manifest(), POOL, run=run, runtime=runtime, gate=gate)
                self.assertEqual(before, run.calls)

    def test_review_native_environment_error_is_before_child(self):
        self.gate.write_text(json.dumps({"open": True, "release_id": "old"}))
        run = DeliveryCommands(self.gate)
        def fake_command(args, **kwargs):
            return run(args)
        original_split = self.ops.shlex.split
        def malformed_options(value):
            if "bad-site" in value:
                raise ValueError("malformed native options")
            return original_split(value)
        with patch.object(self.ops, "command", fake_command), \
             patch.object(self.ops.shlex, "split", malformed_options), \
             patch.dict(os.environ, {"NIX_SSHOPTS": "bad-site'"}):
            with self.assertRaises(ValueError):
                self.ops.deliver_cli(delivery_manifest(), POOL, run=fake_command,
                                     runtime=self.runtime, gate=self.gate)
        self.assertTrue(all(args[0] == "ssh" and args[-1].endswith((" identity"," update-capabilities")) for args in run.calls))
        receipt = json.loads(next((self.runtime / "delivery-attempts").glob("*.json")).read_text())
        self.assertFalse(receipt["commands"][-1]["record"]["child_started"])
        self.assertFalse(receipt.get("requires_reconciliation", False))
        # The same preparation failure during remote-copy stage is also known;
        # local prefetch verification/quiesce may run, but native copy never enters.
        other_runtime = self.runtime.parent / "remote-runtime"
        with patch.object(self.ops, "command", fake_command), \
             patch.object(self.ops.shlex, "split", malformed_options), \
             patch.dict(os.environ, {"NIX_SSHOPTS": "bad-site'"}):
            result = self.ops.deliver_cli(delivery_manifest(False), POOL, run=fake_command,
                                         runtime=other_runtime, gate=self.gate)
        self.assertFalse(result["requires_reconciliation"])
        self.assertFalse(any(args[:2] == ["nix", "copy"] for args in run.calls))
        self.assertTrue(all(args[0] != "ssh" or any(token in shlex.split(args[-1]) for token in ('identity','update-capabilities','stop-update','stopped-identity')) for args in run.calls))
        self.assertFalse(any("State=RESUME" in args for args in run.calls))
        remote_receipt = json.loads(next((other_runtime / "delivery-attempts").glob("*.json")).read_text())
        failures = [item for item in remote_receipt["commands"] if item["status"] == "failed"]
        self.assertTrue(failures)
        self.assertTrue(all(not item["record"]["child_started"] for item in failures))

    def test_review_all_native_cli_actions_receive_selected_command_flags(self):
        for action in ("node-check", "prepare-initial"):
            observed = []
            def check_action(*args, **kwargs):
                kwargs["run"](["fake-verification"])
                return {}
            def adapter(args, **kwargs):
                observed.append(kwargs)
                return ""
            source = self.runtime.parent / "manifest.json"
            source.write_text(json.dumps(release()))
            args = ["release", action, "--runtime", str(self.runtime), "--gate", str(self.gate),
                    "--command-timeout-seconds", "7", "--command-output-bytes", "123"]
            if action == "prepare-initial":
                args += ["--manifest", str(source)]
            with patch.object(sys, "argv", args), patch.object(self.ops, "command", adapter), \
                 patch.object(self.ops, "node_check" if action == "node-check" else "prepare_initial", check_action), \
                 patch("builtins.print"):
                self.ops.main()
            self.assertEqual(observed, [{"timeout_seconds": 7, "output_bytes": 123}])

    def test_final_combined_cli_failure_prints_current_unknown_and_blocks_retry(self):
        self.gate.write_text(json.dumps({"open": True, "release_id": "old"}))
        source, pool = self.runtime.parent / "manifest.json", self.runtime.parent / "pool.json"
        source.write_text(json.dumps(delivery_manifest()))
        pool.write_text(json.dumps(POOL))
        run = DeliveryCommands(self.gate)
        original_deliver = self.ops.deliver_cli
        publish = self.ops.publish_json
        admission = self.ops.publish_admission
        opened = [False]
        def injected_delivery(value, selected, **kwargs):
            return original_deliver(value, selected, run=run, **kwargs)
        def persistent_terminal(path, value, **kwargs):
            if Path(path).parent.name == "delivery-attempts" and value.get("phase") == "finished":
                raise OSError("persistent terminal failure")
            return publish(path, value, **kwargs)
        def failed_close(path, value):
            if not value["open"] and opened[0]:
                raise OSError("failed recovery close")
            result = admission(path, value)
            if value["open"]:
                opened[0] = True
            return result
        args = ["release", "deliver", "--manifest", str(source), "--pool", str(pool), "--enrollment", "/synthetic/enrollment.json",
                "--runtime", str(self.runtime), "--gate", str(self.gate)]
        with patch.object(sys, "argv", args), patch.object(self.ops, "deliver_cli", injected_delivery), \
             patch.object(self.ops, "publish_json", persistent_terminal), \
             patch.object(self.ops, "publish_admission", failed_close), patch("builtins.print") as printed:
            with self.assertRaises(SystemExit) as caught:
                self.ops.main()
        self.assertEqual(caught.exception.code, 1)
        payload = json.loads(printed.call_args.args[0])
        self.assertIsNone(payload["open"])
        self.assertEqual(payload["admission_state"], "unknown")
        self.assertTrue(payload["critical_admission_failure"])
        self.assertTrue(payload["requires_reconciliation"])
        self.assertTrue(json.loads(self.gate.read_text())["open"])
        self.assertFalse(json.loads((self.runtime / "delivery-report.json").read_text())["open"])
        self.assertNotIn("manifest", payload)
        self.assertNotIn("commands", payload)
        before = list(run.calls)
        with patch.object(sys, "argv", args), patch.object(self.ops, "deliver_cli", injected_delivery), \
             patch("builtins.print") as retry_printed:
            with self.assertRaises(SystemExit) as retry:
                self.ops.main()
        self.assertEqual(retry.exception.code, 1)
        self.assertEqual(before, run.calls)
        retry_payload = json.loads(retry_printed.call_args.args[0])
        self.assertIsNone(retry_payload["open"])
        self.assertTrue(retry_payload["requires_reconciliation"])
        self.assertTrue(list((self.runtime / "delivery-attempts").glob("*.admission-intent.json")))

    def test_root_squashed_shared_gate_is_read_as_scientific_owner_without_relaxing_guards(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, run = Path(temporary), InitialCommands()
            gate, record = root / "gate", root / "runtime/release.json"
            record.parent.mkdir()
            record.write_text(json.dumps({**release(), "ready": False}))
            gate.write_text(json.dumps({"open": False, "release_id": "release-a"}))
            (root / "profile").symlink_to("/nix/store/application")
            credentials = {"uid": 0, "gid": 42}
            reads, original_read = [], Path.read_bytes
            original_text = Path.read_text
            def nfs_read(path):
                if path == gate:
                    reads.append(dict(credentials))
                    if credentials != {"uid": 3000, "gid": 3000}:
                        raise PermissionError("root_squash denies mode0750 jobs traversal")
                return original_read(path)
            def nfs_text(path, *args, **kwargs):
                return nfs_read(path).decode() if path == gate else original_text(path, *args, **kwargs)
            def change_uid(value):
                credentials["uid"] = value
            def change_gid(value):
                credentials["gid"] = value
            with patch.object(self.ops, "GATE", gate), \
                 patch.object(self.ops.os, "geteuid", lambda: credentials["uid"]), \
                 patch.object(self.ops.os, "getegid", lambda: credentials["gid"]), \
                 patch.object(self.ops.os, "seteuid", change_uid), \
                 patch.object(self.ops.os, "setegid", change_gid), \
                 patch.object(self.ops.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=3000, pw_gid=3000)), \
                 patch.object(Path, "read_bytes", nfs_read), patch.object(Path, "read_text", nfs_text):
                try:
                    self.ops.node_check(record, gate, root / "profile", run=run)
                    with self.assertRaisesRegex(ValueError, "closed"):
                        self.ops.guard("release-a", "/nix/store/solver/bin/qcl-negf", record, gate)
                    self.ops.prepare_initial(release(), profile=root / "profile", runtime=record.parent,
                        gate=gate, role="worker", run=run)
                except PermissionError as error:
                    self.fail("Shared gate must be read with UID3000 authority: " + str(error))
            self.assertTrue(reads)
            self.assertEqual(credentials, {"uid": 0, "gid": 42})

    def test_shared_gate_read_restores_credentials_after_missing_or_permission_error(self):
        self.assertTrue(callable(getattr(self.ops, "read_admission", None)))
        with tempfile.TemporaryDirectory() as temporary:
            gate = Path(temporary) / "gate"
            credentials = {"uid": 0, "gid": 42}
            def denied(path):
                self.assertEqual(path, gate)
                self.assertEqual(credentials, {"uid": 3000, "gid": 3000})
                raise PermissionError("NFS read denied")
            with patch.object(self.ops, "GATE", gate), \
                 patch.object(self.ops.os, "geteuid", lambda: credentials["uid"]), \
                 patch.object(self.ops.os, "getegid", lambda: credentials["gid"]), \
                 patch.object(self.ops.os, "seteuid", lambda value: credentials.update(uid=value)), \
                 patch.object(self.ops.os, "setegid", lambda value: credentials.update(gid=value)), \
                 patch.object(self.ops.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=3000, pw_gid=3000)):
                self.assertIsNone(self.ops.read_admission(gate, missing=True))
                self.assertEqual(credentials, {"uid": 0, "gid": 42})
                with patch.object(Path, "read_bytes", denied):
                    with self.assertRaises(PermissionError):
                        self.ops.read_admission(gate, missing=True)
                self.assertEqual(credentials, {"uid": 0, "gid": 42})

    def test_custom_gate_and_nonroot_reader_do_not_change_credentials(self):
        self.assertTrue(callable(getattr(self.ops, "read_admission", None)))
        with tempfile.TemporaryDirectory() as temporary:
            gate = Path(temporary) / "gate"
            gate.write_text('{"open":false,"release_id":"release-a"}')
            for uid, production_gate in ((0, self.ops.GATE), (3000, gate)):
                with self.subTest(uid=uid), patch.object(self.ops, "GATE", production_gate), \
                     patch.object(self.ops.os, "geteuid", lambda: uid), \
                     patch.object(self.ops.os, "seteuid", side_effect=AssertionError("Unexpected credential change")), \
                     patch.object(self.ops.os, "setegid", side_effect=AssertionError("Unexpected credential change")):
                    self.assertEqual(json.loads(self.ops.read_admission(gate)),
                        {"open": False, "release_id": "release-a"})

    def test_initial_controller_prepares_closed_identity_before_worker_role_switch(self):
        self.assertTrue(callable(getattr(self.ops, "prepare_initial", None)),
                        "Missing closed initial preparation phase")
        with tempfile.TemporaryDirectory() as temporary:
            root, run = Path(temporary), InitialCommands()
            profile, runtime, gate = root / "profile", root / "runtime", root / "admission.json"
            result = self.ops.prepare_initial(delivery_manifest(False), profile=profile,
                runtime=runtime, gate=gate, role="controller", run=run)
            self.assertEqual(result, {**release(), "ready": False})
            self.assertEqual(json.loads(gate.read_text()), {"open": False, "release_id": "release-a"})
            self.assertEqual(profile.resolve(), Path("/nix/store/application"))
            self.assertEqual((root / "profile-solver").resolve(), Path("/nix/store/solver"))
            self.assertEqual(json.loads((runtime / "release.json").read_text()), result)
            self.assertEqual((runtime / "service.env").read_text(),
                "QCL_NEGF_RELEASE_ID=release-a\nQCL_NEGF_SOLVER_EXECUTABLE=/nix/store/solver/bin/qcl-negf\n"
                + "QCL_NEGF_RELEASE_GATE=" + str(gate) + "\n")
            self.assertEqual(self.ops.bootstrap_selection(runtime / "release.json", "seed", "seed"),
                ("/nix/store/solver/bin/qcl-negf", "qcl-negf-release-a"))
            self.assertIn(["squeue", "--all", "--noheader", "--format", "%i"], run.calls)
            self.assertFalse(any(args[:2] == ["nix", "copy"] for args in run.calls))
            self.ops.node_check(runtime / "release.json", gate, profile, run=run)
            with self.assertRaisesRegex(ValueError, "closed"):
                self.ops.guard("release-a", "/nix/store/solver/bin/qcl-negf", runtime / "release.json", gate)
            gate.write_text(json.dumps({"open": True, "release_id": "release-a"}))
            with self.assertRaisesRegex(ValueError, "ready"):
                self.ops.guard("release-a", "/nix/store/solver/bin/qcl-negf", runtime / "release.json", gate)

    def test_initial_worker_requires_controller_gate_and_does_not_publish_one(self):
        self.assertTrue(callable(getattr(self.ops, "prepare_initial", None)))
        with tempfile.TemporaryDirectory() as temporary:
            root, run = Path(temporary), InitialCommands()
            arguments = dict(profile=root / "profile", runtime=root / "runtime",
                             gate=root / "gate", role="worker", run=run)
            with self.assertRaisesRegex(ValueError, "gate|controller"):
                self.ops.prepare_initial(release(), **arguments)
            self.assertEqual(list(root.iterdir()), [])
            self.assertEqual(run.calls, [])
            (root / "gate").write_text(json.dumps({"open": False, "release_id": "release-a"}))
            gate_bytes = (root / "gate").read_bytes()
            self.ops.prepare_initial(release(), **arguments)
            self.assertEqual((root / "gate").read_bytes(), gate_bytes)
            self.assertFalse(any(args[0] == "squeue" for args in run.calls))

    def test_repeated_initial_preparation_preserves_pending_and_ready_provenance(self):
        self.assertTrue(callable(getattr(self.ops, "prepare_initial", None)))
        for ready in (False, True):
            with self.subTest(ready=ready), tempfile.TemporaryDirectory() as temporary:
                root, run = Path(temporary), InitialCommands()
                arguments = dict(profile=root / "profile", runtime=root / "runtime",
                                 gate=root / "gate", role="controller", run=run)
                self.ops.prepare_initial(release(), **arguments)
                record = root / "runtime/release.json"
                preserved = {**release(), "ready": ready, "code_uuid": "existing-code",
                             "provenance": {"receipt": "original-health-evidence"}}
                record.write_text(json.dumps(preserved, indent=2) + "\n")
                paths = [record, root / "runtime/service.env", root / "gate"]
                before = [(path.read_bytes(), path.stat().st_mtime_ns) for path in paths]
                run.calls.clear()
                result = self.ops.prepare_initial(release(), **arguments)
                self.assertEqual(result, preserved)
                self.assertEqual([(path.read_bytes(), path.stat().st_mtime_ns) for path in paths], before)
                self.assertEqual(run.calls, [["nix-store", "--verify-path", "/nix/store/application", "/nix/store/solver"]])

    def test_initial_conflicts_refuse_before_any_state_or_profile_mutation(self):
        self.assertTrue(callable(getattr(self.ops, "prepare_initial", None)))
        conflicts = ("open-gate", "wrong-gate", "wrong-runtime", "wrong-application", "wrong-solver")
        for conflict in conflicts:
            with self.subTest(conflict=conflict), tempfile.TemporaryDirectory() as temporary:
                root, run = Path(temporary), InitialCommands()
                arguments = dict(profile=root / "profile", runtime=root / "runtime",
                                 gate=root / "gate", role="controller", run=run)
                self.ops.prepare_initial(release(), **arguments)
                if conflict in ("open-gate", "wrong-gate"):
                    (root / "gate").write_text(json.dumps({"open": conflict == "open-gate",
                        "release_id": "other" if conflict == "wrong-gate" else "release-a"}))
                elif conflict == "wrong-runtime":
                    (root / "runtime/release.json").write_text(json.dumps({**release(), "release_id": "other", "ready": False}))
                else:
                    profile = root / ("profile" if conflict == "wrong-application" else "profile-solver")
                    profile.unlink()
                    profile.symlink_to("/nix/store/other")
                original = {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}
                links = {str(path.relative_to(root)): str(path.readlink()) for path in root.rglob("*") if path.is_symlink()}
                run.calls.clear()
                with self.assertRaises(ValueError):
                    self.ops.prepare_initial(release(), **arguments)
                self.assertEqual({str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}, original)
                self.assertEqual({str(path.relative_to(root)): str(path.readlink()) for path in root.rglob("*") if path.is_symlink()}, links)
                self.assertEqual(run.calls, [])

    def test_initial_bad_closure_or_hash_leaves_prior_identity_and_gate_unchanged(self):
        self.assertTrue(callable(getattr(self.ops, "prepare_initial", None)))
        for failure in ("closure", "hash"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root, run = Path(temporary), InitialCommands()
                arguments = dict(profile=root / "profile", runtime=root / "runtime",
                                 gate=root / "gate", role="controller", run=run)
                self.ops.prepare_initial(release(), **arguments)
                paths = [root / "runtime/release.json", root / "runtime/service.env", root / "gate"]
                original = [path.read_bytes() for path in paths]
                run.calls.clear()
                if failure == "closure":
                    run.failure = "--verify-path"
                else:
                    run.evidence["/nix/store/solver"]["narHash"] = OTHER_HASH
                with self.assertRaises((RuntimeError, ValueError)):
                    self.ops.prepare_initial(delivery_manifest(), **arguments)
                self.assertEqual([path.read_bytes() for path in paths], original)
                self.assertFalse(any(args[0] in ("nix-env", "squeue") or args[:2] == ["nix", "copy"] for args in run.calls))

    def test_first_initial_controller_refuses_jobs_before_creating_gate_or_profiles(self):
        self.assertTrue(callable(getattr(self.ops, "prepare_initial", None)))
        with tempfile.TemporaryDirectory() as temporary:
            root, run = Path(temporary), InitialCommands()
            run.queue = "123\n"
            with self.assertRaisesRegex(RuntimeError, "jobs|queued"):
                self.ops.prepare_initial(release(), profile=root / "profile", runtime=root / "runtime",
                    gate=root / "gate", role="controller", run=run)
            self.assertEqual(list(root.iterdir()), [])
            self.assertFalse(any(args[0] == "nix-env" for args in run.calls))

    def test_initial_controller_does_not_recreate_deleted_gate_for_existing_identity(self):
        self.assertTrue(callable(getattr(self.ops, "prepare_initial", None)))
        with tempfile.TemporaryDirectory() as temporary:
            root, run = Path(temporary), InitialCommands()
            arguments = dict(profile=root / "profile", runtime=root / "runtime",
                             gate=root / "gate", role="controller", run=run)
            self.ops.prepare_initial(release(), **arguments)
            (root / "gate").unlink()
            record = (root / "runtime/release.json").read_bytes()
            run.calls.clear()
            with self.assertRaisesRegex(ValueError, "gate|initial"):
                self.ops.prepare_initial(release(), **arguments)
            self.assertFalse((root / "gate").exists())
            self.assertEqual((root / "runtime/release.json").read_bytes(), record)
            self.assertEqual(run.calls, [])

    def test_initial_malformed_existing_runtime_is_never_treated_as_absent(self):
        for current in (None, False, [], {**release()}, {**release(), "ready": 1}):
            with self.subTest(current=current), tempfile.TemporaryDirectory() as temporary:
                root, run = Path(temporary), InitialCommands()
                runtime, gate = root / "runtime", root / "gate"
                runtime.mkdir()
                record = runtime / "release.json"
                record.write_text(json.dumps(current))
                gate.write_text(json.dumps({"open": False, "release_id": "release-a"}))
                original = record.read_bytes(), gate.read_bytes()
                with self.assertRaises(ValueError):
                    self.ops.prepare_initial(release(), profile=root / "profile", runtime=runtime,
                        gate=gate, role="controller", run=run)
                self.assertEqual((record.read_bytes(), gate.read_bytes()), original)
                self.assertFalse((root / "profile").is_symlink())
                self.assertEqual(run.calls, [])

    def test_initial_gate_changed_during_closure_verification_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            gate = root / "gate"
            gate.write_text(json.dumps({"open": False, "release_id": "release-a"}))
            def racing_run(args):
                self.assertEqual(args, ["nix-store", "--verify-path", "/nix/store/application", "/nix/store/solver"])
                gate.write_text(json.dumps({"open": True, "release_id": "other"}))
                return ""
            with self.assertRaisesRegex(ValueError, "gate.*changed"):
                self.ops.prepare_initial(release(), profile=root / "profile", runtime=root / "runtime",
                    gate=gate, role="worker", run=racing_run)
            self.assertEqual(json.loads(gate.read_text()), {"open": True, "release_id": "other"})
            self.assertFalse((root / "runtime").exists())
            self.assertFalse((root / "profile").is_symlink())

    def test_cli_initial_phase_runs_real_preparation_with_activation_lock(self):
        self.assertTrue(callable(getattr(self.ops, "prepare_initial", None)))
        with tempfile.TemporaryDirectory() as temporary:
            root, run = Path(temporary), InitialCommands()
            source = root / "manifest.json"
            source.write_text(json.dumps(release()))
            prepare = self.ops.prepare_initial
            def initial(value, **kwargs):
                import fcntl
                with (root / "runtime/activation.lock").open("w") as competing:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(competing, fcntl.LOCK_EX | fcntl.LOCK_NB)
                kwargs["run"] = run
                return prepare(value, profile=root / "profile", **kwargs)
            args = ["qcl-negf-release", "prepare-initial", "--manifest", str(source),
                    "--role", "controller", "--runtime", str(root / "runtime"), "--gate", str(root / "gate")]
            with patch.object(sys, "argv", args), patch.object(self.ops, "prepare_initial", initial), patch("builtins.print"):
                self.ops.main()
            self.assertEqual(json.loads((root / "runtime/release.json").read_text()), {**release(), "ready": False})
            self.assertFalse(json.loads((root / "gate").read_text())["open"])

    def test_controller_fetches_and_checks_both_hashes_before_closing_admission(self):
        with tempfile.TemporaryDirectory() as temporary:
            gate = Path(temporary) / "admission.json"
            gate.write_text(json.dumps({"open": True, "release_id": "old"}))
            original = gate.read_bytes()
            run = DeliveryCommands(gate)
            with patch.object(self.ops, "publish_admission", lambda _path, value: self.ops.publish_json(gate, value)):
                report = self.ops.deliver_cli(delivery_manifest(), POOL, runtime=self.runtime, gate=self.gate, run=run)
            self.assertTrue(report["open"])
            self.assertEqual([args for args in run.calls if args[0] != "ssh"][:2], [
                ["nix", "copy", "--from", "https://cache.example.invalid", "/nix/store/application", "/nix/store/solver"],
                ["nix", "path-info", "--json", "/nix/store/application", "/nix/store/solver"]])
            self.assertEqual(run.prefetch_gate_snapshots, [original, original])
            first_stop=next(i for i,a in enumerate(run.calls) if a[:2]==["systemctl","stop"])
            self.assertTrue(any('scontrol' in a and 'show' in a for a in run.calls[:first_stop]),
                            "original registration captured before service mutation")

    def test_cache_fetch_failure_leaves_gate_and_services_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            gate = Path(temporary) / "admission.json"
            gate.write_text(json.dumps({"open": True, "release_id": "old"}))
            original, run = gate.read_bytes(), DeliveryCommands(gate)
            run.failure = True
            with patch.object(self.ops, "publish_admission", lambda _path, value: self.ops.publish_json(gate, value)):
                with self.assertRaisesRegex(RuntimeError, "cache fetch"):
                    self.ops.deliver_cli(delivery_manifest(), POOL, runtime=self.runtime, gate=self.gate, run=run)
            self.assertEqual(gate.read_bytes(), original)
            self.assertFalse(any(args[0] in ("systemctl", "scontrol") or
                                 (args[0] == "ssh" and not readonly_release_ssh(args)) for args in run.calls))

    def test_hash_mismatch_missing_paths_or_malformed_evidence_does_not_quiesce(self):
        evidence = ["malformed", [], {}, {"/nix/store/application": {"narHash": HASH}},
                    {"/nix/store/solver": {"narHash": HASH}},
                    {"/nix/store/application": {"narHash": OTHER_HASH}, "/nix/store/solver": {"narHash": HASH}},
                    [{"path": "/nix/store/application", "narHash": HASH}, {"path": "/nix/store/application", "narHash": HASH}],
                    {"/nix/store/application": None, "/nix/store/solver": {"narHash": HASH}}]
        for value in evidence:
            with self.subTest(evidence=value), tempfile.TemporaryDirectory() as temporary:
                gate = Path(temporary) / "admission.json"
                gate.write_text(json.dumps({"open": True, "release_id": "old"}))
                original, run = gate.read_bytes(), DeliveryCommands(gate)
                run.evidence = value
                with patch.object(self.ops, "publish_admission", lambda _path, value: self.ops.publish_json(gate, value)):
                    with self.assertRaisesRegex(ValueError, "closure|hash|evidence"):
                        self.ops.deliver_cli(delivery_manifest(), POOL, runtime=self.runtime, gate=self.gate, run=run)
                self.assertEqual(gate.read_bytes(), original)
                self.assertFalse(any(args[0] in ("systemctl", "scontrol") or
                                 (args[0] == "ssh" and not readonly_release_ssh(args)) for args in run.calls))

    def test_manifest_without_cache_uri_verifies_local_closures_before_quiesce(self):
        with tempfile.TemporaryDirectory() as temporary:
            gate = Path(temporary) / "admission.json"
            gate.write_text(json.dumps({"open": True, "release_id": "old"}))
            original, run = gate.read_bytes(), DeliveryCommands(gate)
            run.evidence = [{"path": path, **value} for path, value in run.evidence.items()]
            with patch.object(self.ops, "publish_admission", lambda _path, value: self.ops.publish_json(gate, value)):
                self.ops.deliver_cli(delivery_manifest(False), POOL, runtime=self.runtime, gate=self.gate, run=run)
            self.assertEqual(next(args for args in run.calls if args[0] != "ssh")[:3], ["nix", "path-info", "--json"])
            self.assertFalse(any(args[:3] == ["nix", "copy", "--from"] for args in run.calls))
            self.assertEqual(run.prefetch_gate_snapshots, [original])

    def test_invalid_cache_argument_or_absent_manifest_hashes_refuses_before_commands(self):
        for cache in (None, "", " ", "-option", "https://cache.invalid\n--option", "https://cache.invalid path",
                      "https://user:password@cache.invalid", 123, True):
            value = delivery_manifest()
            value["cache_uri"] = cache
            with self.subTest(cache=cache), tempfile.TemporaryDirectory() as temporary:
                gate = Path(temporary) / "admission.json"
                gate.write_text("unchanged")
                run = DeliveryCommands(gate)
                with patch.object(self.ops, "publish_admission", lambda _path, value: self.ops.publish_json(gate, value)):
                    with self.assertRaisesRegex(ValueError, "cache"):
                        self.ops.deliver_cli(value, POOL, runtime=self.runtime, gate=self.gate, run=run)
                self.assertEqual(gate.read_text(), "unchanged")
                self.assertEqual(run.calls, [])
        calls = []
        with self.assertRaisesRegex(ValueError, "closure"):
            self.ops.deliver_cli(release(), POOL, runtime=self.runtime, gate=self.gate, run=lambda args: calls.append(args))
        self.assertEqual(calls, [])

    def test_malformed_manifest_closure_inventory_refuses_before_commands(self):
        for inventory in ([], [{"path": "/nix/store/application", "narHash": HASH}],
                          [{"path": ["invalid"], "narHash": HASH}, {"path": "/nix/store/solver", "narHash": HASH}],
                          [{"path": "/nix/store/application", "narHash": "invalid"},
                           {"path": "/nix/store/solver", "narHash": HASH}]):
            with self.subTest(inventory=inventory):
                value = delivery_manifest()
                value["closures"] = inventory
                calls = []
                with self.assertRaisesRegex(ValueError, "closure"):
                    self.ops.deliver_cli(value, POOL, runtime=self.runtime, gate=self.gate, run=lambda args: calls.append(args))
                self.assertEqual(calls, [])

    def test_cli_keeps_operational_cache_and_closure_fields_for_controller_prefetch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, pool = root / "release.json", root / "pool.json"
            source.write_text(json.dumps(delivery_manifest()))
            pool.write_text(json.dumps(POOL))
            observed = []
            def deliver(value, selected_pool, **kwargs):
                observed.append((value, selected_pool))
                return {"open": True, "status": "completed"}
            args = ["qcl-negf-release", "deliver", "--manifest", str(source), "--pool", str(pool), "--enrollment", "/synthetic/enrollment.json",
                    "--runtime", str(root / "runtime")]
            with patch.object(sys, "argv", args), patch.object(self.ops, "deliver_cli", deliver), patch("builtins.print"):
                self.ops.main()
            self.assertEqual(observed, [(delivery_manifest(), POOL)])

    def test_activation_publishes_only_after_identity_and_health_check_then_retry_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            commands = Commands()
            arguments = dict(profile=root / "profile", runtime=root / "runtime",
                             role="worker", run=commands)
            first = self.ops.activate(release(), **arguments)
            self.assertEqual(first["release_id"], "release-a")
            self.assertEqual(json.loads((root / "runtime/release.json").read_text())["release_id"], "release-a")
            self.assertTrue(any(call[:2] == ["nix-store", "--verify-path"] for call in commands.calls))
            before = len([call for call in commands.calls if call[0] == "nix-env"])
            second = self.ops.activate(release(), **arguments)
            self.assertEqual(first, second)
            self.assertEqual(len([call for call in commands.calls if call[0] == "nix-env"]), before)

    def test_failed_health_check_does_not_publish_ready_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            commands = Commands()
            commands.failure = "slurmd.service"
            with self.assertRaisesRegex(RuntimeError, "injected"):
                self.ops.activate(release(), profile=root / "profile", runtime=root / "runtime",
                                  role="worker", run=commands)
            self.assertIsNot(json.loads((root / "runtime/release.json").read_text()).get("ready"), True)

    def test_identical_retry_repairs_only_the_damaged_profile_and_preserves_identity(self):
        for role in ("worker", "controller"):
            for damaged in ("profile", "profile-solver"):
                for target in (None, "/nix/store/other"):
                    with self.subTest(role=role, damaged=damaged, target=target), tempfile.TemporaryDirectory() as temporary:
                        root, commands = Path(temporary), Commands()
                        arguments = dict(profile=root / "profile", runtime=root / "runtime", role=role,
                                         run=commands, email="test@example.invalid",
                                         allowed_codes_file=root / "code-uuid")
                        first = self.ops.activate(release(), **arguments)
                        self.assertEqual(first["release_id"], "release-a")
                        self.assertEqual(first["solver_executable"], "/nix/store/solver/bin/qcl-negf")
                        if role == "controller":
                            self.assertEqual(first["code_uuid"], "12345678-1234-1234-1234-123456789abc")
                        (root / damaged).unlink()
                        if target is not None:
                            (root / damaged).symlink_to(target)
                        commands.calls.clear()
                        self.assertEqual(self.ops.activate(release(), **arguments), first)
                        selected = "/nix/store/application" if damaged == "profile" else "/nix/store/solver"
                        self.assertEqual((root / damaged).resolve(), Path(selected))
                        self.assertEqual([call for call in commands.calls if call[0] == "nix-env"],
                                         [["nix-env", "--profile", str(root / damaged), "--set", selected]])
                        if role == "controller":
                            self.assertEqual((root / "code-uuid").read_text().strip(), first["code_uuid"])
                            registration = next(call for call in commands.calls if call[0] == "runuser")
                            self.assertEqual(registration[-2:],
                                             ["/nix/store/solver/bin/qcl-negf", "qcl-negf-release-a"])
                        self.assertEqual(self.ops.check(release(), profile=root / "profile",
                            runtime=root / "runtime", role=role, run=commands), first)

    def test_check_rejects_missing_or_wrong_solver_profile_before_health(self):
        for role in ("worker", "controller"):
            for target in (None, "/nix/store/other"):
                with self.subTest(role=role, target=target), tempfile.TemporaryDirectory() as temporary:
                    root, commands = Path(temporary), Commands()
                    (root / "release.json").write_text(json.dumps({**release(), "ready": True}))
                    (root / "profile").symlink_to("/nix/store/application")
                    if target is not None:
                        (root / "profile-solver").symlink_to(target)
                    with self.assertRaisesRegex(ValueError, "solver profile"):
                        self.ops.check(release(), profile=root / "profile", runtime=root, role=role, run=commands)
                    self.assertEqual(commands.calls, [])

    def test_profile_setter_failure_or_wrong_result_cannot_publish_ready(self):
        class SetterCommands(Commands):
            broken_profile = None
            mode = None

            def __call__(self, args):
                if args[0] == "nix-env" and args[args.index("--profile") + 1] == str(self.broken_profile):
                    if self.mode == "failure":
                        raise RuntimeError("profile setter failed")
                    super().__call__([*args[:-1], "/nix/store/other"])
                    return ""
                return super().__call__(args)

        for role in ("worker", "controller"):
            for damaged in ("profile", "profile-solver"):
                for mode in ("failure", "wrong-result"):
                    with self.subTest(role=role, damaged=damaged, mode=mode), tempfile.TemporaryDirectory() as temporary:
                        root, commands = Path(temporary), SetterCommands()
                        arguments = dict(profile=root / "profile", runtime=root / "runtime", role=role,
                                         run=commands, email="test@example.invalid",
                                         allowed_codes_file=root / "code-uuid")
                        self.ops.activate(release(), **arguments)
                        commands.broken_profile, commands.mode = root / damaged, mode
                        commands.broken_profile.unlink()
                        commands.calls.clear()
                        error = RuntimeError if mode == "failure" else ValueError
                        with self.assertRaisesRegex(error, "profile"):
                            self.ops.activate(release(), **arguments)
                        record = root / "runtime/release.json"
                        self.assertFalse(record.exists() and json.loads(record.read_text()).get("ready") is True)
                        self.assertFalse(any(call[0] == "systemctl" or "self-check" in call for call in commands.calls))

    def test_partial_fleet_delivery_closes_admission_until_every_selected_node_verifies(self):
        with tempfile.TemporaryDirectory() as temporary:
            gate = Path(temporary) / "admission.json"
            gate.write_text(json.dumps({"open": True, "release_id": "old"}))
            completed = []

            def deliver(node, manifest):
                self.assertFalse(json.loads(gate.read_text())["open"])
                if node == "worker-b":
                    raise RuntimeError("worker offline")
                completed.append(node)
                return {**manifest, "ready": True}

            report = self.ops.deliver_pool(release(), ["worker-a", "worker-b"], gate,
                                           deliver=deliver, quiesce=lambda: None)
            self.assertFalse(report["open"])
            self.assertEqual(report["nodes"]["worker-b"]["status"], "failed")
            self.assertFalse(json.loads(gate.read_text())["open"])
            report = self.ops.deliver_pool(release(), ["worker-a", "worker-b"], gate,
                                           deliver=lambda _n, m: {**m, "ready": True}, quiesce=lambda: None)
            self.assertTrue(report["open"])
            self.assertEqual(json.loads(gate.read_text()),
                             {"open": True, "release_id": "release-a"})

    def test_quiesce_failure_keeps_gate_closed_and_no_node_activates(self):
        with tempfile.TemporaryDirectory() as temporary:
            gate = Path(temporary) / "admission.json"
            delivered = []

            def quiesce():
                raise RuntimeError("running or queued old jobs")

            with self.assertRaisesRegex(RuntimeError, "old jobs"):
                self.ops.deliver_pool(release(), ["worker"], gate, quiesce=quiesce,
                                      deliver=lambda n, _m: delivered.append(n))
            self.assertFalse(json.loads(gate.read_text())["open"])
            self.assertEqual(delivered, [])

    def test_gate_rejects_stale_worker_and_queued_job_then_allows_exact_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            gate = root / "admission.json"
            runtime = root / "release.json"
            gate.write_text(json.dumps({"open": True, "release_id": "release-a"}))
            runtime.write_text(json.dumps({**release(), "ready": True}))
            self.ops.guard("release-a", "/nix/store/solver/bin/qcl-negf", runtime, gate)
            for pin in ["old-queued-release", "offline-stale-release"]:
                with self.assertRaisesRegex(ValueError, "release"):
                    self.ops.guard(pin, "/nix/store/solver/bin/qcl-negf", runtime, gate)
            with self.assertRaisesRegex(ValueError, "solver"):
                self.ops.guard("release-a", "/nix/store/old-solver/bin/qcl-negf", runtime, gate)
            gate.write_text(json.dumps({"open": False, "release_id": "release-a"}))
            with self.assertRaisesRegex(ValueError, "closed"):
                self.ops.guard("release-a", "/nix/store/solver/bin/qcl-negf", runtime, gate)

    def test_unverified_node_identity_cannot_open_admission(self):
        with tempfile.TemporaryDirectory() as temporary:
            gate = Path(temporary) / "admission.json"
            report = self.ops.deliver_pool(release(), ["worker"], gate, quiesce=lambda: None,
                                          deliver=lambda _n, _m: {**release(), "release_id": "stale"})
            self.assertFalse(report["open"])
            self.assertEqual(report["nodes"]["worker"]["status"], "failed")

    def test_malformed_remote_identity_is_reported_per_node(self):
        for response in (None, []):
            with self.subTest(response=response), tempfile.TemporaryDirectory() as temporary:
                gate = Path(temporary) / "admission.json"
                report = self.ops.deliver_pool(release(), ["worker"], gate, quiesce=lambda: None,
                    deliver=lambda _n, _m: response)
                self.assertFalse(report["open"])
                self.assertEqual(report["nodes"]["worker"]["status"], "failed")

    def test_controller_activation_registers_immutable_code_before_ready_and_publishes_uuid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            commands = Commands()
            result = self.ops.activate(release(), profile=root / "profile", runtime=root / "runtime",
                                       role="controller", email="test@example.invalid", run=commands,
                                       allowed_codes_file=root / "code-uuid")
            self.assertEqual(result["code_uuid"], "12345678-1234-1234-1234-123456789abc")
            self.assertEqual((root / "code-uuid").read_text().strip(), result["code_uuid"])
            registration = next(call for call in commands.calls if call[0] == "runuser")
            self.assertIn("/nix/store/solver/bin/qcl-negf", registration)
            self.assertEqual(registration[-1], "qcl-negf-release-a")

    def test_identical_controller_delivery_recovers_services_stopped_for_maintenance(self):
        class StatefulCommands(Commands):
            def __init__(self):
                super().__init__()
                self.active = set()

            def __call__(self, args):
                result = super().__call__(args)
                if args[:2] in (["systemctl", "start"], ["systemctl", "restart"]):
                    self.active.update(args[2:])
                elif args[:2] == ["systemctl", "stop"]:
                    self.active.difference_update(args[2:])
                elif args[:3] == ["systemctl", "is-active", "--quiet"]:
                    if not set(args[3:]) <= self.active:
                        raise RuntimeError("controller services stopped")
                return result

        with tempfile.TemporaryDirectory() as temporary:
            root, commands = Path(temporary), StatefulCommands()
            arguments = dict(profile=root / "profile", runtime=root / "runtime",
                             role="controller", email="test@example.invalid", run=commands,
                             allowed_codes_file=root / "code-uuid")
            first = self.ops.activate(release(), **arguments)
            commands(["systemctl", "stop", "qcl-negf-aiida.service", "qcl-negf-api.service"])
            before = len([call for call in commands.calls if call[0] == "nix-env"])
            self.assertEqual(self.ops.activate(release(), **arguments), first)
            self.assertEqual(len([call for call in commands.calls if call[0] == "nix-env"]), before)

    def test_one_failed_controller_unit_cannot_publish_ready(self):
        class OrHealthCommands(Commands):
            def __call__(self, args):
                result = super().__call__(args)
                if args[:3] == ["systemctl", "is-active", "--quiet"]:
                    # Actual systemctl succeeds if ANY requested unit is active.
                    if "qcl-negf-aiida.service" not in args[3:]:
                        raise RuntimeError("required API unit inactive")
                return result

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "API unit inactive"):
                self.ops.activate(release(), profile=root / "profile", runtime=root / "runtime",
                    role="controller", email="test@example.invalid", run=OrHealthCommands(),
                    allowed_codes_file=root / "code-uuid")
            self.assertIsNot(json.loads((root / "runtime/release.json").read_text()).get("ready"), True)

    def test_failed_pinned_solver_self_check_cannot_publish_ready(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, commands = Path(temporary), Commands()
            commands.failure = "self-check"
            with self.assertRaisesRegex(RuntimeError, "injected"):
                self.ops.activate(release(), profile=root / "profile", runtime=root / "runtime",
                                  role="worker", run=commands)
            self.assertIsNot(json.loads((root / "runtime/release.json").read_text()).get("ready"), True)

    def test_health_executes_pinned_solver_as_scientific_user_with_finite_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, commands = Path(temporary), Commands()
            self.ops.activate(release(), profile=root / "profile", runtime=root / "runtime",
                              role="worker", run=commands)
            call = next(call for call in commands.calls if "self-check" in call)
            self.assertEqual(call[:3], ["timeout", "--kill-after=10s", "300s"])
            self.assertIn("qcl-negf", call)
            self.assertEqual(call[-2:], ["/nix/store/solver/bin/qcl-negf", "self-check"])

    def test_failed_final_resume_leaves_admission_closed_with_node_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            gate = Path(temporary) / "admission.json"

            def admit():
                raise RuntimeError("resume failed")

            report = self.ops.deliver_pool(release(), ["worker"], gate, quiesce=lambda: None,
                                          deliver=lambda _n, m: {**m, "ready": True}, admit=admit)
            self.assertFalse(report["open"])
            self.assertIn("resume failed", report["admission_error"])
            self.assertFalse(json.loads(gate.read_text())["open"])

    def test_check_rejects_profile_path_that_mismatches_runtime_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "release.json").write_text(json.dumps({**release(), "ready": True}))
            (root / "profile").symlink_to("/nix/store/old-application")
            (root / "profile-solver").symlink_to("/nix/store/solver")
            with self.assertRaisesRegex(ValueError, "profile"):
                self.ops.check(release(), profile=root / "profile", runtime=root, run=Commands())

    def test_pending_node_identity_cannot_run_job_or_open_pool(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            gate, runtime = root / "admission.json", root / "release.json"
            gate.write_text(json.dumps({"open": True, "release_id": "release-a"}))
            runtime.write_text(json.dumps({**release(), "ready": False}))
            with self.assertRaisesRegex(ValueError, "ready"):
                self.ops.guard("release-a", "/nix/store/solver/bin/qcl-negf", runtime, gate)
            report = self.ops.deliver_pool(release(), ["worker"], gate, quiesce=lambda: None,
                                          deliver=lambda _n, m: {**m, "ready": False})
            self.assertFalse(report["open"])

    def test_worker_boot_refuses_stale_release_but_allows_prepared_selected_release_with_closed_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            gate, runtime = root / "admission.json", root / "release.json"
            gate.write_text(json.dumps({"open": False, "release_id": "release-a"}))
            runtime.write_text(json.dumps({**release(), "ready": False}))
            (root / "profile").symlink_to("/nix/store/application")
            self.ops.node_check(runtime, gate, root / "profile", run=Commands())
            gate.write_text(json.dumps({"open": True, "release_id": "new-release"}))
            with self.assertRaisesRegex(ValueError, "release"):
                self.ops.node_check(runtime, gate, root / "profile", run=Commands())

    def test_bootstrap_after_reboot_uses_selected_solver_code_instead_of_image_seed(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "release.json"
            self.assertEqual(self.ops.bootstrap_selection(runtime, "/nix/store/seed/bin/qcl-negf", "seed-code"),
                             ("/nix/store/seed/bin/qcl-negf", "seed-code"))
            runtime.write_text(json.dumps({**release(), "ready": True}))
            self.assertEqual(self.ops.bootstrap_selection(runtime, "/nix/store/seed/bin/qcl-negf", "seed-code"),
                             ("/nix/store/solver/bin/qcl-negf", "qcl-negf-release-a"))


class I14UpdateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ops = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(cls.ops)

    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.runtime=self.root/'runtime';self.gate=self.root/'gate'
        install_controller_config_io(self,self.root)
        self.gate.write_text(json.dumps({'open':True,'release_id':'old'}))
        self.original_observer=self.ops.observe_node_identity
        self.context=selected_context()
        self.pool={'schema':POOL['schema'],'nodes':[*POOL['nodes'],
            {'name':'second','target':'admin@second.invalid','role':'worker','enrollment_id':ENROLL_IDS[2]}]}
        self.active=False;self.offline=None;self.stopped=set();self.calls=[];self.model=NativeUpdateModel()
        def preflight(_enrollment,pool,**kw):
            if kw.get('before_remote'):kw['before_remote']()
            ctx=dict(self.context);ctx['bindings']=tuple(b for b in self.context['bindings'] if b['name'] in {n['name'] for n in pool['nodes']})
            return ctx
        for name,value in (('preflight_controller_authority',preflight),('observe_node_identity',lambda **_:CONTROLLER)):
            fake=patch.object(self.ops,name,value);fake.start();self.addCleanup(fake.stop)

    def isolated_delivery_case(self):
        @contextmanager
        def scope():
            with tempfile.TemporaryDirectory() as temporary:
                old=(self.runtime,self.gate,self.calls,self.model)
                self.runtime=Path(temporary)/'runtime';self.gate=Path(temporary)/'gate'
                self.gate.write_text(json.dumps({'open':True,'release_id':'old'}))
                self.calls=[];self.model=NativeUpdateModel()
                try:yield
                finally:self.runtime,self.gate,self.calls,self.model=old
        return scope()

    def commands(self,args):
        self.calls.append(args)
        if args[:3]==['nix','path-info','--json']:
            return json.dumps({p:{'narHash':HASH} for p in ('/nix/store/application','/nix/store/solver')})
        if args[0]=='ssh':
            words,actual=release_ssh(args);text=args[-1]
            if self.offline is not None and actual['role']=='worker' and self.offline==actual['node_name']:raise RuntimeError('worker offline')
            if words[3]=='identity':return json.dumps(actual)
            if words[3]=='update-capabilities' and not getattr(self,'capability',True):return '{}'
            if words[3]=='stop-update':
                if getattr(self,'stop_fault',False):raise self.ops.CommandFailure({'failure':'timeout','child_started':True,'returncode':None,'stdout':'prefix','stderr':'timeout','cleanup_confirmed':False})
                self.stopped.add(actual['node_name'])
            if 'activate' in words:self.restarted=True;self.model.activate(actual['node_name'])
            response=control_response(args,actual,model=self.model)
            if response is not None:
                if words[3]=='health-update' and getattr(self,'nfs_fault',False):
                    value=json.loads(response);del value['nfs_source'];return json.dumps(value)
                return response
            if words[3]=='check':return json.dumps({'schema':'qcl-negf-node-release-check-v1','node_identity':actual,'release':{**release(),'ready':True}})
        if args==['id','-u']:return '1000\n'
        if args==['id','-un']:return 'operator\n'
        if args==['env','TZ=UTC','LC_ALL=C','date','+%s']:return '1791504120\n'
        if 'aiida_update_check.py' in ' '.join(args):
            if getattr(self,'query_fault',None)=='error':raise RuntimeError('DB inaccessible')
            if getattr(self,'query_fault',None)=='malformed':return '{}'
            if getattr(self,'query_result',None) is not None:return json.dumps(self.query_result)
            value=clear_aiida()
            active=self.active or getattr(self,'active_after_restart',False) and getattr(self,'restarted',False)
            value['active_root_found']=active
            value['root_sample']={'uuid':'55555555-5555-5555-5555-555555555555','process_type':'aiida.workflows:qcl_negf.execution_restart','process_state':'waiting','paused':True} if active else None
            if getattr(self,'active_calcjob',False):value.update(active_calcjob_found=True,calcjob_sample={'uuid':'66666666-6666-6666-6666-666666666666','process_state':'waiting'})
            return json.dumps(value)
        if args[:2]==['systemctl','show']:return controller_stop_state()
        if 'scontrol' in args:
            if getattr(self,'bad_reason',False):
                for value in self.model.nodes.values():value.update(State='DOWN',Reason='foreign-maintenance')
            return self.model.command(args)
        return ''

    def deliver(self,pool=None):
        return self.ops.deliver_cli(delivery_manifest(),pool or self.pool,run=self.commands,
            enrollment='/synthetic/enrollment.json',runtime=self.runtime,gate=self.gate)

    def test_i14_requires_complete_enrollment_before_gate_change(self):
        before=self.gate.read_bytes()
        with self.assertRaisesRegex(ValueError,'enrollment'):
            self.deliver(POOL)
        self.assertEqual(self.gate.read_bytes(),before,'named defect: incomplete enrolled worker coverage mutated admission')
        self.assertFalse(any(a[0]=='systemctl' for a in self.calls),'named defect: incomplete coverage stopped services')

    def test_i14_active_paused_retry_parent_blocks_empty_slurm(self):
        self.active=True
        with self.assertRaisesRegex(RuntimeError,'AiiDA'):
            self.deliver()
        self.assertTrue(any('aiida_update_check.py' in ' '.join(a) for a in self.calls))
        result={'open':json.loads(self.gate.read_text())['open']}
        self.assertFalse(result.get('open'),'named defect: paused retry WorkChain ignored with empty Slurm')
        self.assertFalse(any(a[:3]==['nix','copy','--to'] for a in self.calls),'named defect: active AiiDA copied before cancellation proof')

    def test_i14_all_worker_stop_barrier_precedes_first_copy(self):
        self.deliver()
        first=next(i for i,a in enumerate(self.calls) if a[:3]==['nix','copy','--to'])
        stop_calls=[a for a in self.calls[:first] if a[0]=='ssh' and ' stop-update ' in a[-1]]
        self.assertEqual(len(stop_calls),2,'named defect: first remote copy preceded the whole worker stopped barrier')

    def test_i14_orphan_active_calcjob_blocks(self):
        self.active_calcjob=True
        with self.assertRaisesRegex(RuntimeError,'AiiDA'):self.deliver()
        self.assertTrue(any('aiida_update_check.py' in ' '.join(a) for a in self.calls))
        self.assertFalse(json.loads(self.gate.read_text())['open'])
        self.assertFalse(any(' stop-update ' in a[-1] for a in self.calls if a[0]=='ssh'))

    def test_i14_null_query_or_db_error_is_unknown(self):
        for value in ('malformed','error'):
            with self.subTest(value=value), self.isolated_delivery_case():
                self.query_fault=value
                with self.assertRaisesRegex(ValueError if value=='malformed' else RuntimeError,'cancellation|DB inaccessible'):self.deliver()
                self.assertTrue(any('aiida_update_check.py' in ' '.join(a) for a in self.calls))
                self.assertFalse(json.loads(self.gate.read_text())['open'])
                self.assertFalse(any(a[:3]==['nix','copy','--to'] for a in self.calls))

    def test_i14_missing_offline_node_no_skip(self):
        self.offline='second'
        with self.assertRaisesRegex(RuntimeError,'offline'):self.deliver()
        self.assertTrue(json.loads(self.gate.read_text())['open'])
        self.assertFalse(any(a[0]=='systemctl' for a in self.calls))

    def test_i14_rejects_uninstalled_update_capability_before_gate(self):
        self.capability=False
        with self.assertRaisesRegex(ValueError,'capability'):self.deliver()
        self.assertTrue(json.loads(self.gate.read_text())['open'])

    def test_i14_final_fleet_recheck_after_all_mutations(self):
        result=self.deliver();self.assertTrue(result['open'])
        last=max(i for i,a in enumerate(self.calls) if a[0]=='ssh' and ' activate ' in a[-1])
        health=[i for i,a in enumerate(self.calls) if a[0]=='ssh' and ' health-update ' in a[-1]]
        self.assertGreaterEqual(len(health),3);self.assertTrue(all(i>last for i in health))
        self.assertEqual(set(result['fleet_health']),{'controller','worker','second'})

    def test_i14_unexpected_down_reason_no_resume(self):
        self.bad_reason=True
        with self.assertRaisesRegex(ValueError,'state|reason|original|Slurm'):
            self.deliver()
        self.assertTrue(json.loads(self.gate.read_text())['open'])
        self.assertFalse(any('State=RESUME' in a for a in self.calls))

    def test_i14_one_release_nfs_failure_closed(self):
        self.nfs_fault=True
        result=self.deliver();self.assertFalse(result['open'])
        self.assertTrue(any(a[0]=='ssh' and 'health-update' in shlex.split(a[-1]) for a in self.calls))
        self.assertFalse(any('State=RESUME' in a for a in self.calls))

    def test_i14_alias_cannot_bypass_update_guards(self):
        manifest_path=self.root/'release.json';manifest_path.write_text(json.dumps(delivery_manifest()))
        pool_path=self.root/'pool.json';pool_path.write_text(json.dumps(POOL))
        for action in ('update','deliver'):
            argv=['release',action,'--manifest',str(manifest_path),'--pool',str(pool_path),'--enrollment','/synthetic/enrollment.json','--runtime',str(self.runtime),'--gate',str(self.gate)]
            original=self.ops.deliver_cli
            def actual_guard(*args,**kwargs):return original(*args,run=self.commands,**kwargs)
            with self.isolated_delivery_case():
                argv[argv.index('--runtime')+1]=str(self.runtime);argv[argv.index('--gate')+1]=str(self.gate)
                with patch.object(sys,'argv',argv),patch.object(self.ops,'deliver_cli',side_effect=actual_guard) as operation,patch('builtins.print'):
                    with self.assertRaises(SystemExit):self.ops.main()
                    self.assertEqual(operation.call_count,1)
                    self.assertEqual(self.calls,[],"real incomplete enrollment guard before remote dispatch")
                    self.assertTrue(json.loads(self.gate.read_text())['open'])

    def test_i14_no_cancel_submit_retry_calls(self):
        self.deliver()
        text=' '.join(' '.join(a) for a in self.calls)
        for forbidden in ('scancel','sbatch','kill_run','submit_plan','requeue','nixos-rebuild','poweroff'):
            self.assertNotIn(forbidden,text)

    def test_i14_cap_deadline_cleanup_uncertain_no_admission(self):
        self.stop_fault=True
        result=self.deliver();self.assertFalse(result['open']);self.assertTrue(result['requires_reconciliation'])
        self.assertFalse(any(a[:3]==['nix','copy','--to'] for a in self.calls))

    def test_i14_crash_gate_write_failure_retains_intent(self):
        original=self.ops.publish_admission
        def gate(path,value):
            if value['open']:raise OSError('open fsync failed')
            return original(path,value)
        with patch.object(self.ops,'publish_admission',gate):
            result=self.deliver()
        self.assertFalse(result['open']);self.assertTrue(result['requires_reconciliation'])
        self.assertTrue(list((self.runtime/'delivery-attempts').glob('*.admission-intent.json')))

    def helper(self,rows):
        spec=importlib.util.spec_from_file_location('i14_readonly_query',Path(__file__).parents[1]/'ops/aiida_update_check.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        trace=[]
        class Query:
            def append(inner,kind,*,filters,project):
                inner.kind=kind;inner.filters=filters;inner.project=project;trace.append((kind,filters,project));return inner
            def limit(inner,n):
                if n!=1:raise AssertionError('bounded existence query required')
                return inner
            def all(inner):
                terms=inner.filters['or']
                self.assertIn({'attributes':{'!has_key':'process_state'}},terms)
                self.assertIn({'attributes.process_state':{'==':None}},terms)
                self.assertIn({'attributes.process_state':{'!in':['finished','killed','excepted']}},terms)
                self.assertEqual(set(inner.filters),{'process_type','or'}) # no parent/release/creator joins
                selected=[row for row in rows if row['kind']==inner.kind and row['type'] in inner.filters['process_type']['in'] and row.get('state') not in ('finished','killed','excepted')]
                return [[row['uuid'],row['type'],row.get('state'),row.get('paused')] if inner.kind=='workflow' else [row['uuid'],row.get('state')] for row in selected[:1]]
        orm=SimpleNamespace(QueryBuilder=Query,WorkChainNode='workflow',CalcJobNode='calcjob')
        result=module.inspect_profile(orm,'qcl-negf')
        self.assertEqual(len(trace),2);self.assertEqual(trace[0][1]['process_type']['in'],['aiida.workflows:qcl_negf.plan','aiida.workflows:qcl_negf.execution_restart'])
        return result

    def row(self,state='waiting',kind='workflow',entry='execution_restart',**values):
        return {'kind':kind,'type':'aiida.'+('workflows:qcl_negf.' if kind=='workflow' else 'calculations:qcl_negf.')+entry,'uuid':'55555555-5555-5555-5555-555555555555','state':state,**values}

    def test_i14_standalone_restart_waiting_without_plan_or_calcjob_blocks(self):
        result=self.helper([self.row()]);self.assertTrue(result['active_root_found']);self.assertFalse(result['active_calcjob_found'])
        self.query_result=result
        with self.assertRaisesRegex(RuntimeError,'AiiDA'):self.deliver()
        self.assertTrue(any('aiida_update_check.py' in ' '.join(a) for a in self.calls))
        self.assertFalse(self.stopped)

    def test_i14_terminal_plan_nonterminal_restart_child_blocks(self):
        result=self.helper([self.row('finished',entry='plan'),self.row('running')]);self.assertTrue(result['active_root_found'])
        self.query_result=result
        with self.assertRaisesRegex(RuntimeError,'AiiDA'):self.deliver()

    def test_i14_restart_paused_or_null_missing_state_blocks(self):
        for state in ('waiting',None,'unknown'):
            row=self.row(state,paused=True)
            result=self.helper([row]);self.assertTrue(result['active_root_found']);self.assertEqual(result['root_sample']['process_state'],state)
        missing=self.row();del missing['state'];self.assertTrue(self.helper([missing])['active_root_found'])

    def test_i14_terminal_owned_workflows_and_calcjobs_are_clear(self):
        rows=[self.row(s,entry=e) for s in ('finished','killed','excepted') for e in ('plan','execution_restart')]
        rows += [self.row(s,kind='calcjob',entry='execution') for s in ('finished','killed','excepted')]
        rows += [self.row('running',entry='foreign')]
        result=self.helper(rows);self.assertFalse(result['active_root_found']);self.assertFalse(result['active_calcjob_found'])

    def test_i14_post_restart_check_reuses_complete_two_workflow_type_guard(self):
        self.active_after_restart=True
        result=self.deliver();self.assertFalse(result['open'])
        queries=[a for a in self.calls if 'aiida_update_check.py' in ' '.join(a)]
        self.assertTrue(getattr(self,'restarted',False),'actual activation boundary reached before newly active retry')
        self.assertGreaterEqual(len(queries),3)
        self.assertFalse(any('State=RESUME' in a for a in self.calls))

    def stop_fixture(self,*,force=False,jobs=False,bad_readback=False):
        fs=IsolatedWorkerIO(self,self.ops,force=force,jobs=jobs).install()
        self.body_fixture=fs;self.runtime=fs.runtime;self.gate=fs.gate
        budget=self.ops.UpdateScan(200.)
        machine=self.ops.stopped_machine(budget)
        if bad_readback:fs.state['UnitFileState']='enabled'
        return fs.attempt,machine,fs.state,fs.native,fs.calls

    def test_i14_native_stop_readback_and_mask_not_argv_only(self):
        attempt,_,state,native,calls=self.stop_fixture()
        result=self.ops.stop_update(release(),attempt,WORKER,runtime=self.runtime,gate=self.gate,run=native,deadline=200.,enrollment_id=ENROLL_IDS[1])
        self.assertEqual(result['systemd']['LoadState'],'masked');self.assertTrue(result['restart_inhibited'])
        self.assertTrue(any(a[:3]==['systemctl','mask','--runtime'] for a in calls))
        state['UnitFileState']='enabled'
        with self.assertRaisesRegex(ValueError,'stopped/masked'):self.ops.observe_stopped_update(release(),attempt,runtime=self.runtime,gate=self.gate,run=native,deadline=200.)

    def test_i14_force_is_only_bound_daemon_after_empty_job_proof(self):
        attempt,_,_,native,calls=self.stop_fixture(force=True)
        result=self.ops.stop_update(release(),attempt,WORKER,runtime=self.runtime,gate=self.gate,run=native,deadline=200.,enrollment_id=ENROLL_IDS[1])
        self.assertTrue(result['forced_daemon_stop']);self.assertEqual(len([a for a in calls if a[:2]==['systemctl','kill']]),1)

    def test_i14_job_process_after_terminal_queue_blocks(self):
        attempt,_,_,native,calls=self.stop_fixture(jobs=True)
        with self.assertRaisesRegex(ValueError,'job process'):self.ops.stop_update(release(),attempt,WORKER,runtime=self.runtime,gate=self.gate,run=native,deadline=200.,enrollment_id=ENROLL_IDS[1])
        self.assertFalse(any(a[:2]==['systemctl','kill'] for a in calls))

    def test_i14_stopped_identity_requires_own_marker_same_boot_config(self):
        attempt,machine,_,native,_=self.stop_fixture()
        self.ops.stop_update(release(),attempt,WORKER,runtime=self.runtime,gate=self.gate,run=native,deadline=200.,enrollment_id=ENROLL_IDS[1])
        self.body_fixture.write('/proc/sys/kernel/random/boot_id',CONTROLLER['boot_id'])
        with self.assertRaisesRegex(ValueError,'boot/config'):self.ops.observe_stopped_update(release(),attempt,runtime=self.runtime,gate=self.gate,run=native,deadline=200.)
        with self.assertRaisesRegex(ValueError,'own update marker'):self.ops.observe_stopped_update(release(),'88888888-8888-8888-8888-888888888888',runtime=self.runtime,gate=self.gate,run=native,deadline=200.)

    def test_i14_ordinary_identity_still_requires_daemon(self):
        with patch.object(self.ops,'local_metadata',side_effect=lambda path,*a:b'{}' if str(path).endswith('release-config.json') else b'1'),patch.object(self.ops,'worker_daemon_binding',side_effect=ValueError('missing daemon')):
            config=b'{"role":"worker"}'
            with patch.object(self.ops,'local_metadata',side_effect=lambda path,*a:config if str(path).endswith('release-config.json') else b'1'):
                with self.assertRaisesRegex(ValueError,'missing daemon'):self.original_observer(run=lambda _: '')

    def test_i14_incomplete_proc_read_is_not_empty(self):
        fs=IsolatedWorkerIO(self,self.ops).install();raw=io.open;reached=[]
        def deny(path,*args,**kwargs):
            if str(path)=='/proc/123/status':
                reached.append(True);raise PermissionError('denied fixture metadata')
            return raw(path,*args,**kwargs)
        with patch.object(io,'open',deny):
            with self.assertRaises(PermissionError):fs.scan()
        self.assertTrue(reached)
        self.assertFalse(any(a[:2]==['systemctl','kill'] for a in fs.calls))


class IsolatedWorkerIO:
    """Remap low-level IO only. Scanner, protected reads and machine observer stay real.

    Every fixed /proc,/sys,/etc,/run path is under this private tree. Root ownership
    is the injected fstat metadata boundary for these own descriptors only; no
    production owner/mode/nofollow rule is patched. Native ownership is unproved.
    """
    def __init__(self,test,module,*,force=False,jobs=False,role='worker'):
        self.identity=CONTROLLER if role=='controller' else WORKER;self.role=role
        self.test=test;self.module=module;self.root=test.root/'body-root';self.root.mkdir(mode=0o700)
        self.trace=[];self.calls=[];self.clock=[100.];self.force=force;self.jobs=jobs;self.after_scan=None
        self.fd_paths={};self.budget=None;self.budget_objects=[];self.stack=ExitStack();test.addCleanup(self.stack.close)
        self.raw_open=os.open;self.raw_close=os.close;self.raw_read=os.read;self.raw_stat=os.stat
        self.raw_lstat=os.lstat;self.raw_fstat=os.fstat;self.raw_scandir=os.scandir
        self.raw_readlink=os.readlink;self.raw_listdir=os.listdir;self.raw_io_open=io.open;self.raw_unlink=os.unlink;self.raw_replace=os.replace;self.raw_mkdir=os.mkdir;self.raw_rmdir=os.rmdir
        self.model=NativeUpdateModel();self.restart_window=None
        self.state={'LoadState':'loaded','ActiveState':'active','SubState':'running','MainPID':'123',
            'ControlGroup':'/system.slice/slurmd.service','InvocationID':'a'*32,'UnitFileState':'enabled',
            'FragmentPath':'/nix/store/unit/slurmd.service','DropInPaths':''}
        self.attempt='77777777-7777-7777-7777-777777777777'
        self.runtime=Path('/var/lib/qcl-negf/runtime');self.gate=Path('/srv/qcl-negf/jobs/admission.json')
        self.write('/etc/qcl-negf/release-config.json',json.dumps({'role':role,'slurm_conf':'/etc/slurm.conf','nfs_source':'storage.invalid:/srv/qcl-negf/jobs','email':'test@example.invalid','allowed_codes_file':'/var/lib/qcl-negf/allowed-codes'}))
        self.write('/etc/slurm.conf','NodeName=worker CPUs=12 RealMemory=28000\n')
        self.write('/sys/class/dmi/id/product_uuid',self.identity['machine_uuid'])
        self.write('/etc/machine-id',self.identity['machine_id']);self.write('/proc/sys/kernel/random/boot_id',self.identity['boot_id'])
        self.write('/sys/fs/cgroup/cgroup.controllers','cpu memory pids\n')
        self.write('/sys/fs/cgroup/system.slice/slurmd.service/cgroup.procs','123\n')
        self.write(self.gate,json.dumps({'open':False,'release_id':'release-a'}))
        self.real(self.runtime).mkdir(parents=True,mode=0o700)
        self.process(123)
        if jobs:self.process(321,comm='slurmstepd',uid=3000,cgroup='/jobs/job_1');self.write('/sys/fs/cgroup/jobs/job_1/cgroup.procs','321\n')
        self.put_release()
    def real(self,path):
        return self.root/str(path).lstrip('/')
    def mapped(self,path):
        if isinstance(path,int):return path
        value=os.fspath(path)
        roots=('/proc','/sys','/etc','/run','/var/lib/qcl-negf','/srv/qcl-negf','/nix')
        if value=='/' or any(value==root or value.startswith(root+'/') for root in roots):
            actual=self.real(value)
            self.test.assertTrue(actual.is_relative_to(self.root),'covered logical IO remains in this fresh own root')
            return str(actual)
        return path
    def write(self,path,data):
        actual=self.real(path);actual.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        with self.raw_io_open(actual,'wb') as out:out.write(data.encode() if isinstance(data,str) else data)
        actual.chmod(0o600)
    def process(self,pid,*,comm='slurmd',uid=0,cgroup=None,ticks=42,executable='/nix/store/slurm/bin/slurmd'):
        cg=cgroup or self.state['ControlGroup'];base=Path('/proc')/str(pid)
        self.write(base/'comm',comm+'\n');self.write(base/'status',f'Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n')
        self.write(base/'cgroup','0::'+cg+'\n');self.write(base/'stat',f'{pid} ({comm}) S '+ ' '.join(['0']*18+[str(ticks)])+'\n')
        self.write(base/'cmdline',b'/nix/store/slurm/bin/slurmd\x00-D\x00');self.write(base/'environ',b'SLURM_CONF=/etc/slurm.conf\x00')
        link=self.real(base/'exe');link.unlink(missing_ok=True);link.symlink_to(executable)
    def remove_process(self,pid):
        base=self.real('/proc/'+str(pid))
        for child in base.iterdir():child.unlink()
        base.rmdir()
    def put_release(self):
        self.write(self.runtime/'release.json',json.dumps({**release(),'ready':True}))
        self.profile=self.module.PROFILE;self.real(self.profile).parent.mkdir(parents=True,exist_ok=True)
        self.real(self.profile).symlink_to('/nix/store/application')
        self.real(self.profile.with_name(self.profile.name+'-solver')).symlink_to('/nix/store/solver')
    def install(self):
        fixture=self
        def open_fd(path,flags,*args,**kw):
            mapped=fixture.mapped(path);fixture.trace.append(('open',str(path),flags,fixture.charge()))
            fd=fixture.raw_open(mapped,flags,*args,**kw);fixture.fd_paths[fd]=str(path);return fd
        def close_fd(fd):fixture.fd_paths.pop(fd,None);return fixture.raw_close(fd)
        def read_fd(fd,n):fixture.trace.append(('read',fixture.fd_paths.get(fd,'own-fd'),n,fixture.charge()));return fixture.raw_read(fd,n)
        def fstat(fd):
            value=fixture.raw_fstat(fd)
            if fd in fixture.fd_paths:
                actual=value
                class OwnRootStat:
                    st_uid=0
                    def __getattr__(self,name):return getattr(actual,name)
                value=OwnRootStat()
            return value
        class Reader:
            def __init__(self,handle,path):self.handle=handle;self.path=path
            def read(self,n=-1):
                fixture.trace.append(('read',str(self.path),n,fixture.charge()))
                return self.handle.read(n)
            def __enter__(self):self.handle.__enter__();return self
            def __exit__(self,*args):return self.handle.__exit__(*args)
            def __getattr__(self,key):return getattr(self.handle,key)
        def io_open(path,mode='r',*args,**kw):
            fixture.trace.append(('io.open',str(path),mode,fixture.charge()))
            handle=fixture.raw_io_open(fixture.mapped(path),mode,*args,**kw)
            return Reader(handle,path) if 'r' in mode else handle
        class Entry:
            def __init__(self,entry,logical):self.entry=entry;self.name=entry.name;self.path=str(Path(logical)/entry.name)
            def is_dir(self,*args,**kw):fixture.trace.append(('is_dir',self.path));return self.entry.is_dir(*args,**kw)
            def stat(self,*args,**kw):fixture.trace.append(('entry.stat',self.path));return self.entry.stat(*args,**kw)
            def is_symlink(self):return self.entry.is_symlink()
        class Directory:
            def __init__(self,path):self.path=path;self.iterator=fixture.raw_scandir(fixture.mapped(path))
            def __enter__(self):return self
            def __exit__(self,*args):self.iterator.close()
            def __iter__(self):return self
            def __next__(self):
                fixture.trace.append(('next',str(self.path),fixture.charge()))
                return Entry(next(self.iterator),self.path)
        def scandir(path):
            if isinstance(path,int):return fixture.raw_scandir(path)
            fixture.trace.append(('scandir',str(path),fixture.charge()));return Directory(path)
        def mkdir(path,*args,**kwargs):
            actual=fixture.mapped(path)
            own=fixture.raw_stat(fixture.root)
            fixture.trace.append(('mkdir-map',str(path),str(actual),own.st_dev,own.st_ino))
            return fixture.raw_mkdir(actual,*args,**kwargs)
        def stat(path,*args,**kw):fixture.trace.append(('stat',str(path),fixture.charge()));return fixture.raw_stat(fixture.mapped(path),*args,**kw)
        def lstat(path,*args,**kw):fixture.trace.append(('lstat',str(path),fixture.charge()));return fixture.raw_lstat(fixture.mapped(path),*args,**kw)
        def readlink(path,*args,**kw):fixture.trace.append(('readlink',str(path),fixture.charge()));return fixture.raw_readlink(fixture.mapped(path),*args,**kw)
        for obj,name,value in ((os,'open',open_fd),(os,'close',close_fd),(os,'read',read_fd),(os,'fstat',fstat),
            (os,'stat',stat),(os,'lstat',lstat),(os,'readlink',readlink),(os,'scandir',scandir),
            (os,'listdir',lambda path:fixture.raw_listdir(fixture.mapped(path))),
            (os,'unlink',lambda path,*a,**kw:fixture.raw_unlink(fixture.mapped(path),*a,**kw)),
            (os,'replace',lambda old,new,*a,**kw:fixture.raw_replace(fixture.mapped(old),fixture.mapped(new),*a,**kw)),
            (os,'mkdir',mkdir),
            (os,'rmdir',lambda path,*a,**kw:fixture.raw_rmdir(fixture.mapped(path),*a,**kw)),(io,'open',io_open),
            (self.module.socket,'gethostname',lambda:self.identity['hostname']),
            (self.module.pwd,'getpwnam',lambda name:SimpleNamespace(pw_uid=3000,pw_gid=3000)),
            (self.module.time,'monotonic',lambda:self.clock[0]),(self.module.time,'sleep',self.sleep)):
            self.stack.enter_context(patch.object(obj,name,value))
        original_init=self.module.UpdateScan.__init__
        def captured_init(scan,deadline):
            original_init(scan,deadline);self.budget=scan;self.budget_objects.append(scan)
        self.stack.enter_context(patch.object(self.module.UpdateScan,'__init__',captured_init))
        # Undo controller fixture at the identity boundary: use the real observer.
        self.stack.enter_context(patch.object(self.module,'observe_node_identity',self.test.original_observer))
        return self
    def charge(self):return self.budget.bytes if self.budget is not None else None
    def sleep(self,seconds):
        if not 0<seconds<=1:raise AssertionError('unbounded logical sleep')
        self.clock[0]+=seconds
    def native(self,args):
        self.calls.append(args)
        if self.role=='controller' and 'slurmd.service' in args:raise AssertionError('controller queried unrelated worker slurmd unit')
        if args[:2]==['systemctl','show']:
            props=[a.split('=',1)[1] for a in args if a.startswith('--property=')]
            fields={**self.state,'Environment':'SLURM_CONF=/etc/slurm.conf'}
            return '\n'.join(k+'='+fields[k] for k in props)
        if args[:3]==['systemctl','mask','--runtime']:self.state.update(LoadState='masked',UnitFileState='masked-runtime')
        elif args[:2]==['systemctl','stop'] and not self.force:self.clear_scope()
        elif args[:2]==['systemctl','kill']:
            self.test.assertEqual(args,['systemctl','kill','--kill-whom=all','--signal=SIGKILL','slurmd.service']);self.clear_scope()
        elif args[:2]==['systemctl','unmask']:self.state.update(LoadState='loaded',UnitFileState='enabled')
        elif args[:2] in (['systemctl','start'],['systemctl','restart']):
            self.state.update(ActiveState='active',SubState='running',MainPID='124',ControlGroup='/system.slice/slurmd.service',InvocationID='b'*32)
            self.process(124,ticks=99);self.write('/sys/fs/cgroup/system.slice/slurmd.service/cgroup.procs','124\n')
            self.model.activate('worker');self.restart_window={'requested_epoch':1791504120,'captured_epoch':1791504121}
        elif args==['env','SLURM_CONF=/etc/slurm.conf','scontrol','show','aliases',WORKER['hostname']]:return 'NodeName=worker'
        elif args[0]=='findmnt':return json.dumps({'filesystems':[{'target':str(self.gate.parent),'source':'storage.invalid:/srv/qcl-negf/jobs','fstype':'nfs4'}]})
        elif 'date' in args and '+%s' in args:return '1791504120' if self.restart_window is None else '1791504121'
        elif args[:3]==['scontrol','show','node'] or 'scontrol' in args and 'node' in args:return self.model.command(args)
        elif 'register_aiida.py' in ' '.join(args):return json.dumps({'code_uuid':'12345678-1234-1234-1234-123456789abc','solver_executable':'/nix/store/solver/bin/qcl-negf'})
        elif 'self-check' in args:return json.dumps({'schema':'qcl-negf-self-check-v1','status':'completed','scientific_accepted':False})
        return ''
    def clear_scope(self):
        if self.real('/proc/123').exists():self.remove_process(123)
        self.write('/sys/fs/cgroup/system.slice/slurmd.service/cgroup.procs','')
        self.state.update(ActiveState='inactive',SubState='dead',MainPID='0',ControlGroup='',InvocationID='')
    def stop(self):
        return self.module.stop_update(release(),self.attempt,WORKER,runtime=self.runtime,gate=self.gate,run=self.native,deadline=200.,enrollment_id=ENROLL_IDS[1])
    def scan(self):
        self.budget=self.module.UpdateScan(200.)
        return self.module.physical_stop_scan(self.budget,self.state)
    def health(self,*,deadline=200.):
        self.budget=self.module.UpdateScan(deadline)
        return self.module.fleet_health(release(),self.identity,runtime=self.runtime,gate=self.gate,run=self.native,deadline=deadline,metadata_budget=self.budget)



class I14WholeRepairTests(unittest.TestCase):
    """F1–F6 body oracles; original methods remain on their original classes."""
    @classmethod
    def setUpClass(cls):
        cls.ops = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(cls.ops)
    setUp=I14UpdateTests.setUp
    commands=I14UpdateTests.commands
    deliver=I14UpdateTests.deliver
    isolated_delivery_case=I14UpdateTests.isolated_delivery_case
    def fs(self,**kwargs):return IsolatedWorkerIO(self,self.ops,**kwargs).install()
    def no_later(self):
        self.assertFalse(any(a[:3]==['nix','copy','--to'] or a[0]=='ssh' and 'activate' in shlex.split(a[-1]) or 'State=RESUME' in a for a in self.calls))
    def receipt(self):
        files=[p for p in (self.runtime/'delivery-attempts').glob('*.json') if not p.name.endswith('.admission-intent.json')]
        self.assertTrue(files,'actual durable attempt reached');return json.loads(files[-1].read_text())
    def test_f1_unknown_root_member_forbids_force(self):
        fs=self.fs(force=True);fs.process(456,comm='foreign-helper',executable='/nix/store/foreign/bin/helper')
        fs.write('/sys/fs/cgroup/system.slice/slurmd.service/cgroup.procs','123\n456\n')
        with self.assertRaisesRegex(ValueError,'member|scope|singleton'):fs.stop()
        self.assertFalse(any(a[:2] in (['systemctl','mask'],['systemctl','kill']) for a in fs.calls))
        self.assertTrue(any(t[0]=='read' and t[1].endswith('/cgroup.procs') for t in fs.trace))
        self.assertTrue(any(t[0]=='readlink' and t[1]=='/proc/456/exe' for t in fs.trace))
        for suffix in ('/456/stat','/456/status','/456/cgroup'):
            self.assertTrue(any(t[0]=='read' and t[1].endswith(suffix) for t in fs.trace),suffix)
    def test_f1_empty_daemon_foreign_member_forbids_force(self):
        fs=self.fs(force=True)
        native=fs.native;injected=[False]
        def mutate(args):
            result=native(args)
            if args[:2]==['systemctl','stop'] and not injected[0]:
                fs.remove_process(123);fs.process(456,comm='foreign-helper',executable='/nix/store/foreign/bin/helper')
                fs.write('/sys/fs/cgroup/system.slice/slurmd.service/cgroup.procs','456\n');injected[0]=True
            return result
        fs.native=mutate
        with self.assertRaisesRegex(ValueError,'member|scope|daemon|PID'):fs.stop()
        self.assertTrue(injected[0]);self.assertFalse(any(a[:2]==['systemctl','kill'] for a in fs.calls))
    def test_f1_positive_singleton_scope_force_then_stopped(self):
        fs=self.fs(force=True);result=fs.stop()
        self.assertEqual(sum(a[:2]==['systemctl','kill'] for a in fs.calls),1)
        self.assertTrue(result['service_scope_complete']);self.assertTrue(result['service_members_measured'])
        self.assertEqual(result['service_members'],[]);self.assertGreater(result['metadata_bytes'],0)
        self.assertGreaterEqual(sum(a[:2]==['systemctl','show'] for a in fs.calls),30)
        for suffix in ('/cgroup.procs','/123/stat','/123/status','/release-config.json','/slurm.conf'):
            self.assertTrue(any(t[0]=='read' and t[1].endswith(suffix) for t in fs.trace),suffix)
    def test_f1_subgroup_pid_reuse_exec_invocation_and_race_refuse(self):
        for fault in ('subgroup','ticks','exe','invocation','snapshot_member'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                with ExitStack() as scope:
                    old=self.root;self.root=Path(temporary)
                    try:
                        fs=self.fs(force=True);scope.callback(fs.stack.close)
                        native=fs.native;changed=[False]
                        def mutate(args):
                            result=native(args)
                            if args[:2]==['systemctl','stop'] and not changed[0]:
                                changed[0]=True
                                if fault=='subgroup':
                                    fs.process(456,comm='helper',cgroup='/system.slice/slurmd.service/sub',executable='/nix/store/helper/bin/help')
                                    fs.write('/sys/fs/cgroup/system.slice/slurmd.service/sub/cgroup.procs','456\n')
                                elif fault=='ticks':fs.process(123,ticks=99)
                                elif fault=='exe':fs.process(123,executable='/nix/store/replaced/bin/slurmd')
                                elif fault=='invocation':fs.state['InvocationID']='b'*32
                                else:
                                    original_readlink=os.readlink
                                    race=[False]
                                    def between_snapshots(path,*a,**kw):
                                        result=original_readlink(path,*a,**kw)
                                        if str(path)=='/proc/123/exe' and not race[0]:
                                            race[0]=True;fs.process(456,comm='helper',executable='/nix/store/helper/bin/help')
                                            fs.write('/sys/fs/cgroup/system.slice/slurmd.service/cgroup.procs','123\n456\n')
                                        return result
                                    scope.enter_context(patch.object(os,'readlink',between_snapshots))
                            return result
                        fs.native=mutate
                        with self.assertRaisesRegex(ValueError,'scope|member|changed|identity|generation'):fs.stop()
                        self.assertTrue(changed[0]);self.assertFalse(any(a[:2]==['systemctl','kill'] for a in fs.calls))
                    finally:self.root=old
    def invalid_stopped(self,args):
        response=self.commands(args)
        if args[0]=='ssh' and self.corrupt_action in shlex.split(args[-1]):
            self.bad_reached+=1
            if self.bad_variant=='json':return '{'
            value=json.loads(response)
            if self.bad_variant=='boot':value['node_identity']={**value['node_identity'],'boot_id':CONTROLLER['boot_id']}
            elif self.bad_variant=='member':value['service_members']=[{'pid':987,'start_ticks':1}]
            elif self.bad_variant=='enrollment':value['enrollment_id']=ENROLL_IDS[0]
            elif self.bad_variant=='systemd':value['systemd']['MainPID']='1'
            elif self.bad_variant=='schema':value['schema']='wrong'
            elif self.bad_variant=='machine':value['node_identity']={**value['node_identity'],'machine_id':CONTROLLER['machine_id']}
            elif self.bad_variant=='member1':value['service_members']=[1]
            elif self.bad_variant=='memberNone':value['service_members']=[None]
            elif self.bad_variant=='memberstring':value['service_members']=['bad']
            elif self.bad_variant=='systemdNone':value['systemd']=None
            elif self.bad_variant=='systemd1':value['systemd']=1
            elif self.bad_variant=='systemdlist':value['systemd']=[]
            elif self.bad_variant=='node':value['node_identity']={**value['node_identity'],'node_name':'wrong'}
            return json.dumps(value)
        return response
    def bad_delivery(self):
        return self.ops.deliver_cli(delivery_manifest(),self.pool,run=self.invalid_stopped,enrollment='/synthetic/enrollment.json',runtime=self.runtime,gate=self.gate)
    def test_f2_post_stop_bad_receipt_halts_and_blocks_retry(self):
        for variant in ('json','schema','boot','machine','node','enrollment','systemd','member'):
            with self.subTest(variant=variant),self.isolated_delivery_case():
                self.corrupt_action='stop-update';self.bad_variant=variant;self.bad_reached=0
                result=self.bad_delivery();self.assertFalse(result['open']);self.assertTrue(result['requires_reconciliation'])
                self.assertEqual(self.bad_reached,1);self.no_later();record=self.receipt()
                self.assertEqual(record['remote_outcome'],'unknown')
                self.assertTrue(record.get('pending_stopped_observation') or record.get('requires_reconciliation'))
                before=len(self.calls)
                with self.assertRaisesRegex(RuntimeError,'reconciliation|Unresolved|pending'):self.deliver()
                self.assertEqual(len(self.calls),before,'retry must not dispatch readonly capability/identity either')
    def test_f2_precopy_stopped_drift_halts_later_nodes(self):
        self.pool['nodes']=[self.pool['nodes'][1],self.pool['nodes'][2],self.pool['nodes'][0]]
        self.corrupt_action='stopped-identity';self.bad_variant='boot';self.bad_reached=0
        result=self.bad_delivery();self.assertFalse(result['open']);self.assertTrue(result['requires_reconciliation'])
        self.assertEqual(len([a for a in self.calls if a[0]=='ssh' and 'stop-update' in shlex.split(a[-1])]),2)
        self.assertEqual(self.bad_reached,1);self.no_later()
        self.assertEqual(result['nodes']['second']['status'],'not_attempted')
    def test_f3_foreign_down_reason_not_overwritten(self):
        self.model.nodes['worker'].update(State='DOWN',Reason='foreign maintenance [operator@2026-10-09T00:01:00]')
        before=self.gate.read_bytes();state=dict(self.model.nodes['worker'])
        with self.assertRaisesRegex(ValueError,'original|state|reason|Slurm'):self.deliver()
        self.assertEqual(self.gate.read_bytes(),before);self.assertEqual(self.model.nodes['worker'],state)
        self.assertFalse(self.model.transitions);self.no_later()
        self.assertGreater(self.model.shows['worker'],0)
    def test_f3_reason_drift_before_drain_refuses(self):
        def drift(name,count):
            if name=='worker' and count==2:self.model.nodes[name]['Reason']='foreign operator race'
        self.model.before_show=drift
        with self.assertRaisesRegex(ValueError,'changed|drift|reason|Slurm'):self.deliver()
        self.assertGreaterEqual(self.model.shows['worker'],2);self.no_later()
        self.assertFalse(any(name=='worker' for name,_ in self.model.transitions))
        self.assertEqual(self.model.nodes['worker']['Reason'],'foreign operator race')
    def test_f3_known_retry_retains_original_provenance(self):
        self.query_fault='error'
        with self.assertRaisesRegex(RuntimeError,'DB inaccessible'):self.deliver()
        first=self.receipt();self.assertIn(first['slurm_before']['worker']['Reason'],('None',''));self.assertNotIn('Reason=',first['slurm_before']['worker']['_raw'])
        self.query_fault=None
        result=self.deliver();self.assertTrue(result['open'])
        second=json.loads(Path(result['receipt']).read_text())
        self.assertEqual(second['slurm_before']['worker'],first['slurm_before']['worker'])
        self.assertNotEqual(first['attempt_id'],second['attempt_id'])
    def test_f3_retry_without_retained_provenance_blocks(self):
        self.model.nodes['worker'].update(State='IDLE+DRAIN',Reason='application-release:99999999-9999-9999-9999-999999999999')
        before=dict(self.model.nodes['worker'])
        with self.assertRaisesRegex(ValueError,'original|provenance|reason|state|Slurm'):self.deliver()
        self.assertEqual(self.model.nodes['worker'],before);self.assertFalse(self.model.transitions)
        self.no_later();self.assertTrue(json.loads(self.gate.read_text())['open'])

    def test_f4_registration_shape_generation_stale_refuse(self):
        baseline=self.model.command(['env','TZ=UTC','LC_ALL=C','SLURM_CONF=/etc/slurm.conf','scontrol','show','node','worker','--oneliner'])
        valid=baseline.replace('State=IDLE','State=IDLE+DRAIN Reason=application-release')
        for raw in (valid.replace('Version=25.11.0','Version=25.11'),valid.replace('BootTime=2026-10-09','BootTime=2026-02-30'),
                    valid+'\n'+valid,valid+' CPUTot=12',valid.replace('SlurmdStartTime=2026-10-09T00:01:00','SlurmdStartTime=Unknown')):
            with self.subTest(raw=raw):
                calls=[]
                def read(args):calls.append(args);return raw
                with self.assertRaisesRegex(ValueError,'registration|timestamp|version|record|calendar|Ambiguous|Registered'):self.ops.final_registration(read,'worker',slurm_conf='/etc/slurm.conf')
                self.assertEqual(len(calls),1)
        healthy=self.model.health
        def stale(name):
            value=healthy(name)
            if name=='worker':value['registration']['SlurmdStartTime']='2026-10-09T00:01:00'
            return value
        self.model.health=stale
        result=self.deliver();self.assertFalse(result['open']);self.assertFalse(any('State=RESUME' in a for a in self.calls))
    def test_f4_postresume_wait_and_exact_idle(self):
        self.model.resume_reads['worker']=[{'State':'IDLE+NOT_RESPONDING','BootTime':'None','SlurmdStartTime':'None'}]*2
        # Responses apply only after RESUME, not during initial capture.
        queued=self.model.resume_reads.pop('worker');command=self.model.command
        def native(args):
            result=command(args)
            if 'State=RESUME' in args and 'NodeName=worker' in args:self.model.resume_reads['worker']=queued
            return result
        self.model.command=native
        result=self.deliver();self.assertTrue(result['open'])
        self.assertEqual(sum('State=RESUME' in a and 'NodeName=worker' in a for a in self.calls),1)
        resume=next(i for i,a in enumerate(self.calls) if 'State=RESUME' in a and 'NodeName=worker' in a)
        self.assertGreaterEqual(sum('scontrol' in a and 'worker' in a and 'show' in a for a in self.calls[resume+1:]),3)
    def test_f4_postresume_changed_or_down_never_opens(self):
        for changes in ({'State':'DOWN','Reason':'foreign failure'},{'CPUTot':'13'},{'SlurmdStartTime':'2026-10-09T00:03:00'}, {'State':'IDLE+NOT_RESPONDING','BootTime':'None','SlurmdStartTime':'None'}):
            with self.subTest(changes=changes),self.isolated_delivery_case():
                command=self.model.command
                def native(args):
                    result=command(args)
                    if 'State=RESUME' in args and 'NodeName=worker' in args:self.model.resume_reads['worker']=[changes]*10
                    return result
                self.model.command=native
                result=self.deliver();self.assertFalse(result['open'])
                self.assertEqual(sum('State=RESUME' in a and 'NodeName=worker' in a for a in self.calls),1)
                self.assertLessEqual(self.model.shows['worker'],14)
    def test_f5_read_reservation_precedes_access_and_sentinel(self):
        fs=self.fs();fs.write('/etc/large',b'x'*65537);scan=self.ops.UpdateScan(200.);fs.budget=scan
        scan.bytes=32*1024*1024-16;before=len(fs.trace)
        with self.assertRaisesRegex(ValueError,'bound|budget'):scan.read('/etc/large',65536)
        self.assertFalse(any(t[0] in ('open','io.open','read') for t in fs.trace[before:]),'reservation failure precedes actual IO')
        scan.bytes=32*1024*1024;before=len(fs.trace)
        with self.assertRaisesRegex(ValueError,'bound|budget'):scan.read('/etc/large',1)
        self.assertEqual(len(fs.trace),before)
        scan.bytes=0
        with self.assertRaisesRegex(ValueError,'bound|exceeds'):scan.read('/etc/large',65536)
        reads=[t for t in fs.trace[before:] if t[0]=='read'];self.assertTrue(reads)
        self.assertGreaterEqual(scan.bytes,65537)
        charged_before=0
        for _,_,requested,charged in reads:
            self.assertGreaterEqual(charged-charged_before,requested);charged_before=charged
    def test_f5_iterator_slot_before_next(self):
        fs=self.fs();fs.write('/proc/not-numeric','');scan=self.ops.UpdateScan(200.);fs.budget=scan
        scan.pid_entries=32768;before=len(fs.trace)
        with self.assertRaisesRegex(ValueError,'bound|enumeration'):list(scan.entries('/proc','pid'))
        self.assertFalse(any(t[0]=='next' for t in fs.trace[before:]))
        scan.pid_entries=32767;before=len(fs.trace)
        with self.assertRaisesRegex(ValueError,'bound|enumeration'):list(scan.entries('/proc','pid'))
        self.assertEqual(sum(t[0]=='next' for t in fs.trace[before:]),1)
        self.assertEqual(scan.pid_entries,32768)
        fs.write('/run/fd-control/only-entry','x')
        descriptor=os.open('/run/fd-control',os.O_RDONLY|os.O_DIRECTORY)
        try:
            with os.scandir(descriptor) as iterator:entries=list(iterator)
            self.assertEqual([(entry.name,entry.path) for entry in entries],[('only-entry','only-entry')])
        finally:os.close(descriptor)
    def test_f5_health_expiry_before_probe_write(self):
        fs=self.fs();fs.stop()
        self.ops.activate(release(),profile=fs.profile,runtime=fs.runtime,gate=fs.gate,run=fs.native,role='worker',expected_node_identity=WORKER,update_attempt_id=fs.attempt,deadline=200.)
        native=fs.native;reached=[]
        def expire(args):
            result=native(args)
            if args[0]=='findmnt':reached.append(True);fs.clock[0]=201.
            return result
        fs.native=expire
        with patch.object(self.ops.tempfile,'mkstemp',wraps=self.ops.tempfile.mkstemp) as create:
            with self.assertRaisesRegex(self.ops.CommandFailure,'deadline'):fs.health(deadline=200.)
            self.assertTrue(reached);self.assertEqual(create.call_count,0)
    def test_f5_finish_expiry_before_marker_unlink(self):
        fs=self.fs();fs.stop();fs.native(['systemctl','unmask','--runtime','slurmd.service']);fs.native(['systemctl','start','slurmd.service'])
        fs.process(124,ticks=99);fs.write('/sys/fs/cgroup/system.slice/slurmd.service/cgroup.procs','124\n')
        fs.write(fs.gate,json.dumps({'open':True,'release_id':'release-a'}));marker=fs.real(fs.runtime/'update-stop.json');before=marker.read_bytes()
        raw=Path.unlink;removed=[]
        def unlink(path,*a,**kw):removed.append(str(path));return raw(path,*a,**kw)
        native=fs.native
        def expire(args):
            result=native(args)
            if 'aliases' in args:fs.clock[0]=201.
            return result
        with patch.object(Path,'unlink',unlink):
            with self.assertRaisesRegex(self.ops.CommandFailure,'deadline'):self.ops.finish_update(release(),fs.attempt,WORKER,runtime=fs.runtime,gate=fs.gate,run=expire,deadline=200.)
        self.assertEqual(marker.read_bytes(),before);self.assertNotIn(str(fs.runtime/'update-stop.json'),removed)
    def test_f5_update_duration_validation_before_io(self):
        for invalid in (True,False,float('nan'),float('inf'),0,-1):
            with self.subTest(native_duration=repr(invalid)):
                with self.assertRaisesRegex(ValueError,'finite|positive'):self.ops.duration(invalid,'Update duration')
        encoded=base64.urlsafe_b64encode(json.dumps(release()).encode()).decode()
        node=base64.urlsafe_b64encode(json.dumps(WORKER).encode()).decode()
        for action in ('stop-update','stopped-identity','update-identity','health-update','finish-update'):
            for option,duration in ([('--delivery-timeout-seconds',v) for v in ('nan','inf','0','-1','2')] + [('--command-timeout-seconds',v) for v in ('nan','inf','0','2')] + [('--command-output-bytes','0'),('--delivery-output-bytes','0')]):
                with self.subTest(action=action,option=option,duration=duration):
                    argv=['release',action,'--manifest-base64',encoded,'--expected-node-identity-base64',node,'--update-attempt-id','77777777-7777-7777-7777-777777777777',option,duration]
                    with patch.object(sys,'argv',argv),patch.object(self.ops,'local_metadata',side_effect=AssertionError('unvalidated IO')) as metadata,patch.object(self.ops,'read_protected_file',side_effect=AssertionError('unvalidated protected IO')) as protected:
                        with self.assertRaises((ValueError,SystemExit)):self.ops.main()
                        self.assertEqual(metadata.call_count+protected.call_count,0)
    def test_f6_positive_factory_full_body_transition(self):
        result=self.deliver();self.assertTrue(result['open']);self.assertFalse(result['requires_reconciliation'])
        for action,count in (('identity',6),('update-capabilities',3),('stop-update',2),('stopped-identity',2),('activate',3),('check',3),('health-update',3),('finish-update',2)):
            self.assertGreaterEqual(sum(a[0]=='ssh' and action in shlex.split(a[-1]) for a in self.calls),count,action)
        self.assertTrue(any('aiida_update_check.py' in ' '.join(a) for a in self.calls))
        self.assertEqual(sum('State=RESUME' in a for a in self.calls),2)
        record=self.receipt();self.assertFalse(record.get('pending_stopped_observation'))
        self.assertEqual(set(record['slurm_before']),{'worker','second'})
    def test_f6_unmask_requires_actual_masked_observation(self):
        for fault in ('not_masked','mainpid','member','boot'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temporary,ExitStack() as scope:
                old=self.root;self.root=Path(temporary)
                try:
                    fs=self.fs();scope.callback(fs.stack.close);fs.stop();before=len(fs.calls)
                    if fault=='not_masked':fs.state['UnitFileState']='enabled'
                    elif fault=='mainpid':fs.state['MainPID']='123'
                    elif fault=='member':
                        fs.process(456,comm='helper',executable='/nix/store/helper/bin/help')
                        fs.write('/sys/fs/cgroup/system.slice/slurmd.service/cgroup.procs','456\n')
                    else:fs.write('/proc/sys/kernel/random/boot_id',CONTROLLER['boot_id'])
                    with self.assertRaisesRegex(ValueError,'stopped|masked|member|scope|boot|config|daemon'):
                        self.ops.activate(release(),profile=fs.profile,runtime=fs.runtime,gate=fs.gate,run=fs.native,
                            role='worker',expected_node_identity=WORKER,update_attempt_id=fs.attempt,deadline=200.)
                    self.assertFalse(any(a[:2]==['systemctl','unmask'] or a[0]=='nix-env' for a in fs.calls[before:]))
                finally:self.root=old

    def test_f6_actual_nfs_body_positive_and_io_failures(self):
        for fault in (None,'mount','write','read','fsync','unlink'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temporary,ExitStack() as scope:
                old=self.root;self.root=Path(temporary)
                try:
                    fs=self.fs();scope.callback(fs.stack.close);fs.stop()
                    self.ops.activate(release(),profile=fs.profile,runtime=fs.runtime,gate=fs.gate,run=fs.native,role='worker',expected_node_identity=WORKER,update_attempt_id=fs.attempt,deadline=200.)
                    writes=[];reads=[];syncs=[];unlinks=[]
                    native=fs.native
                    mount_query=['findmnt','--json','--target',str(fs.gate.parent),'--output','TARGET,SOURCE,FSTYPE']
                    if fault=='mount':
                        def mount_fault(args):
                            result=native(args)
                            return json.dumps({'filesystems':[]}) if args==mount_query else result
                        fs.native=mount_fault
                    raw_write=os.write;raw_read=os.read;raw_sync=os.fsync;raw_unlink=Path.unlink
                    def write(fd,data):
                        writes.append(data)
                        if fault=='write':raise OSError('probe write injected')
                        return raw_write(fd,data)
                    def read(fd,n):
                        value=raw_read(fd,n)
                        if n==32:
                            reads.append(value)
                            if fault=='read':return b'corrupt'
                        return value
                    def sync(fd):
                        syncs.append(fd)
                        if fault=='fsync':raise OSError('probe fsync injected')
                        return raw_sync(fd)
                    def unlink(path,*args,**kw):
                        if path.name.startswith('.update-probe-'):
                            unlinks.append(str(path))
                            if fault=='unlink':raise OSError('probe unlink injected')
                        return raw_unlink(path,*args,**kw)
                    for obj,key,value in ((os,'write',write),(os,'read',read),(os,'fsync',sync),(Path,'unlink',unlink)):
                        scope.enter_context(patch.object(obj,key,value))
                    health_calls_start=len(fs.calls)
                    if fault=='mount':
                        with self.assertRaisesRegex(ValueError,'^NFS endpoint/mount mismatch$'):fs.health()
                        self.assertEqual((writes,reads,syncs,unlinks),([],[],[],[]))
                    elif fault:
                        with self.assertRaisesRegex((OSError,ValueError),'probe|NFS'):fs.health()
                    else:
                        result=fs.health();self.assertTrue(result['nfs_verified']);self.assertEqual(writes,[b'qcl-negf-update\n'])
                        self.assertEqual(reads,[b'qcl-negf-update\n']);self.assertEqual(len(syncs),1);self.assertEqual(len(unlinks),1)
                    self.assertEqual([a for a in fs.calls[health_calls_start:] if a[0]=='findmnt'],[mount_query])
                finally:self.root=old

    def test_r1_global_classification_and_full_own_member(self):
        for case in ('kernel','zombie','job','denied','own_missing_exe','sub_missing_exe'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as temporary,ExitStack() as cleanup:
                old=self.root;self.root=Path(temporary)
                try:
                    fs=self.fs(force=True);cleanup.callback(fs.stack.close)
                    pid=2 if case in ('kernel','zombie','job','denied') else 123 if case=='own_missing_exe' else 456
                    if pid!=123:fs.process(pid,comm='kernel' if case!='job' else 'job-task',uid=3000 if case=='job' else 0,cgroup='/kernel' if pid==2 else '/system.slice/slurmd.service/sub',executable='/nix/store/helper/bin/helper')
                    if case=='zombie':fs.write('/proc/2/stat','2 (kernel) Z '+' '.join(['0']*18+['41'])+'\n')
                    if case in ('kernel','zombie','own_missing_exe','sub_missing_exe'):fs.real('/proc/'+str(pid)+'/exe').unlink()
                    if case=='sub_missing_exe':fs.write('/sys/fs/cgroup/system.slice/slurmd.service/sub/cgroup.procs','456\n')
                    if case=='denied':
                        native_open=io.open
                        def deny(path,*a,**kw):
                            if str(path)=='/proc/2/status':
                                fs.trace.append(('denied-open','/proc/2/status',fs.charge()))
                                raise PermissionError('denied global classification')
                            return native_open(path,*a,**kw)
                        cleanup.enter_context(patch.object(io,'open',deny))
                    if case in ('kernel','zombie'):
                        result=fs.stop();self.assertTrue(result['forced_daemon_stop']);self.assertEqual(sum(a[:2]==['systemctl','kill'] for a in fs.calls),1)
                        self.assertFalse(any(t[0]=='readlink' and t[1]=='/proc/2/exe' for t in fs.trace))
                        self.assertTrue(any(t[0]=='readlink' and t[1]=='/proc/123/exe' for t in fs.trace))
                    else:
                        if case=='denied':
                            with self.assertRaisesRegex(PermissionError,'^denied global classification$'):fs.stop()
                        else:
                            with self.assertRaisesRegex((ValueError,PermissionError,FileNotFoundError),'job process|denied|exe|generation|scope|No such'):fs.stop()
                        self.assertFalse(any(a[:2] in (['systemctl','kill'],['systemctl','mask']) for a in fs.calls))
                    if case=='denied':
                        denied=[t for t in fs.trace if t[0]=='denied-open'];self.assertEqual(len(denied),1)
                        self.assertEqual(denied[0][:2],('denied-open','/proc/2/status'));self.assertIsInstance(denied[0][2],int)
                        self.assertGreaterEqual(denied[0][2],4096,'status request is prepaid before denied open')
                        self.assertFalse(any(t[0]=='read' and t[1]=='/proc/2/status' for t in fs.trace))
                    else:self.assertTrue(any(t[0]=='read' and t[1].endswith('/status') for t in fs.trace))
                finally:self.root=old

    def test_r2_healthy_idle_optional_reason(self):
        native='NodeName=worker CPUTot=12 RealMemory=28000 Version=25.11.0 BootTime=2026-10-09T00:00:00 SlurmdStartTime=2026-10-09T00:01:00 CPUAlloc=0 AllocMem=0 State=IDLE'
        for suffix in ('',' Reason=',' Reason=None'):
            with self.subTest(suffix=suffix):
                raw=native+suffix;value=self.ops.registration_fields(raw)
                self.assertIn(value['Reason'],('','None'));self.assertEqual(value['_raw'],raw)
        for raw in (native.replace('State=IDLE','State=IDLE+DRAIN'),native.replace('State=IDLE','State=DOWN'),native.replace('State=IDLE','State=IDLE+NOT_RESPONDING'),native.replace(' CPUTot=12',''),native.replace('CPUAlloc=0','CPUAlloc=1'),native+' CPUTot=12'):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(ValueError,'Reason|Incomplete|Allocated|Ambiguous'):self.ops.registration_fields(raw)
        result=self.deliver();self.assertTrue(result['open'])
        record=self.receipt();self.assertNotIn('Reason=',record['slurm_before']['worker']['_raw'])
        self.assertTrue(any('State=DRAIN' in a for a in self.calls));self.assertTrue(any('State=RESUME' in a for a in self.calls))

    def test_r2_own_native_reason_causality_and_retry(self):
        for case in ('plain','suffix','actor','tag','stale','future','calendar','extra','retry','missing'):
            with self.subTest(case=case),self.isolated_delivery_case():
                self.model.reason_form='plain' if case=='plain' else 'suffix';self.model.reason_fault=case if case in ('actor','tag','stale','future','calendar','extra') else None
                self.query_fault='error' if case in ('retry','missing') else None
                if case in ('retry','missing'):
                    with self.assertRaisesRegex(RuntimeError,'DB inaccessible'):self.deliver()
                    first=self.receipt();drain=first['slurm_drain']['worker'];self.assertEqual(drain['reason_evidence']['actor_name'],'operator')
                    self.assertEqual(drain['after_readback']['Reason'],self.model.nodes['worker']['Reason']);self.assertIn('[operator@',drain['after_readback']['Reason'])
                    if case=='missing':
                        receipt_path=self.runtime/'delivery-attempts'/(first['attempt_id']+'.json');del first['slurm_drain']['worker']['reason_evidence'];receipt_path.write_text(json.dumps(first));before=len(self.calls)
                        with self.assertRaisesRegex(RuntimeError,'causal|reconciliation'):self.deliver()
                        self.assertEqual(len(self.calls),before)
                    else:
                        self.query_fault=None;result=self.deliver();self.assertTrue(result['open']);later=self.receipt()
                        self.assertEqual(later['slurm_before']['worker'],first['slurm_before']['worker'])
                    continue
                result=self.deliver();record=self.receipt()
                self.assertIn(['id','-u'],self.calls);self.assertIn(['id','-un'],self.calls)
                self.assertIn(['env','TZ=UTC','LC_ALL=C','date','+%s'],self.calls)
                for args in self.calls:
                    if 'scontrol' in args:self.assertEqual(args[:5],['env','TZ=UTC','LC_ALL=C','SLURM_CONF=/etc/slurm.conf','scontrol'])
                if case in ('plain','suffix'):
                    self.assertTrue(result['open']);drain=record['slurm_drain']['worker'];self.assertEqual(drain['status'],'completed')
                    self.assertEqual(drain['reason_evidence'],{'actor_uid':1000,'actor_name':'operator','requested_epoch':1791504120,'captured_epoch':1791504120})
                    self.assertIn(drain['requested_reason'],drain['after_readback']['Reason'])
                else:
                    self.assertFalse(result['open']);self.assertTrue(result['requires_reconciliation']);self.assertEqual(record['slurm_drain']['worker']['status'],'pending')
                    self.assertFalse(any(a[0]=='ssh' and 'stop-update' in shlex.split(a[-1]) for a in self.calls));self.no_later()

    def test_r3_identity_and_safety_ignore_only_accounting(self):
        # Real metadata IO mutates accounting/state without changing its generation.
        for case in ('accounting','ticks','uid','cgroup','executable','invocation'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as temporary,ExitStack() as cleanup:
                old=self.root;self.root=Path(temporary)
                try:
                    fs=self.fs(force=True);cleanup.callback(fs.stack.close);raw_open=io.open;count=[0]
                    def changing(path,*args,**kwargs):
                        if str(path)=='/proc/123/stat':
                            count[0]+=1;fields=['0']*18+['42'];fields[10]=str(count[0]);state='R' if count[0]%2 else 'S'
                            if case=='ticks' and count[0]>1:fields[-1]='99'
                            fs.write('/proc/123/stat','123 (slurmd) '+state+' '+' '.join(fields)+'\n')
                            if case=='uid' and count[0]>1:fs.write('/proc/123/status','Name:\tslurmd\nUid:\t1\t1\t1\t1\n')
                            if case=='cgroup' and count[0]>1:fs.write('/proc/123/cgroup','0::/foreign\n')
                        return raw_open(path,*args,**kwargs)
                    cleanup.enter_context(patch.object(io,'open',changing))
                    exe_events=[]
                    if case=='executable':
                        native_readlink=os.readlink
                        def between_full_captures(path,*args,**kwargs):
                            result=native_readlink(path,*args,**kwargs)
                            if str(path)=='/proc/123/exe':
                                exe_events.append(('capture',result))
                                if len(exe_events)==1:
                                    self.assertEqual(result,'/nix/store/slurm/bin/slurmd')
                                    link=fs.real('/proc/123/exe');link.unlink();link.symlink_to('/nix/store/replaced/bin/slurmd')
                                    exe_events.append(('mutation','/nix/store/replaced/bin/slurmd'))
                            return result
                        cleanup.enter_context(patch.object(os,'readlink',between_full_captures))
                    if case=='invocation':
                        native=fs.native
                        def drift(args):
                            result=native(args)
                            if args[:2]==['systemctl','stop']:fs.state['InvocationID']='c'*32
                            return result
                        fs.native=drift
                    if case=='accounting':
                        record=self.ops.process_record(self.ops.UpdateScan(200.),Path('/proc/123'))
                        self.assertNotEqual(record['observations']['before']['stat'],record['observations']['after']['stat'])
                        result=fs.stop();self.assertTrue(result['forced_daemon_stop']);self.assertEqual(sum(a[:2]==['systemctl','kill'] for a in fs.calls),1)
                    else:
                        if case=='executable':
                            with self.assertRaisesRegex(ValueError,'^Process generation/executable identity changed$'):fs.stop()
                            self.assertEqual(exe_events,[('capture','/nix/store/slurm/bin/slurmd'),('mutation','/nix/store/replaced/bin/slurmd'),('capture','/nix/store/replaced/bin/slurmd')])
                            self.assertFalse(any(a[:2]==['systemctl','mask'] for a in fs.calls))
                        else:
                            with self.assertRaisesRegex(ValueError,'changed|identity|classification|scope'):fs.stop()
                        self.assertFalse(any(a[:2]==['systemctl','kill'] for a in fs.calls))
                    self.assertGreater(count[0],1)
                finally:self.root=old
        with self.isolated_delivery_case():
            self.model.volatile=True;result=self.deliver();self.assertTrue(result['open']);record=self.receipt()
            original=record['slurm_before']['worker'];fresh=record['slurm_drain']['worker']['before_recheck']
            self.assertNotEqual(original['CPULoad'],fresh['CPULoad'])
            expected_keys=('NodeName','CPUTot','RealMemory','Version','BootTime','SlurmdStartTime','CPUAlloc','AllocMem','State','Reason')
            expected={key:original[key] for key in expected_keys};expected['Reason']=''
            self.assertEqual(self.ops.registration_safety(original),expected);self.assertEqual(self.ops.registration_safety(fresh),expected)
        with self.isolated_delivery_case():
            def foreign(name,count):
                if name=='worker' and count==2:self.model.nodes[name]['Reason']='foreign actor/time drift'
            self.model.before_show=foreign
            with self.assertRaisesRegex(ValueError,'original state/reason changed'):self.deliver()
            self.assertFalse(any('State=DRAIN' in a and 'NodeName=worker' in a for a in self.calls));self.no_later()

    def test_r4_actual_main_update_budget_routes(self):
        for role,action,case in (('worker','check','normal'),('controller','check','normal'),('controller','activate','normal'),('worker','check','expired_manifest'),('worker','check','oversized_release'),('controller','activate','expired_settings'),('controller','check','cap_manifest')):
            with self.subTest(role=role,action=action,case=case),tempfile.TemporaryDirectory() as temporary,ExitStack() as cleanup:
                old=self.root;self.root=Path(temporary)
                try:
                    fs=self.fs(role=role);cleanup.callback(fs.stack.close);fs.write('/etc/candidate.json',json.dumps(release()))
                    self.assertEqual(fs.mapped('/var/lib/qcl-negf'),str(fs.root/'var/lib/qcl-negf'))
                    self.assertEqual(fs.mapped('/var/lib/qcl-negf/allowed-codes'),str(fs.root/'var/lib/qcl-negf/allowed-codes'))
                    captured=[];original_init=self.ops.UpdateScan.__init__
                    def actual_init(scan,deadline):
                        original_init(scan,deadline);captured.append(scan);fs.budget=scan
                        if case=='expired_manifest':fs.clock[0]=deadline+1
                        if case=='cap_manifest':scan.bytes=32*1024*1024-16
                    cleanup.enter_context(patch.object(self.ops.UpdateScan,'__init__',actual_init))
                    if case=='oversized_release':fs.write(fs.runtime/'release.json',b' '*65537)
                    native=fs.native
                    def boundary(argv,**kwargs):return native(argv)
                    cleanup.enter_context(patch.object(self.ops,'command',boundary))
                    raw_read=os.read
                    def expire_gate(fd,n):
                        result=raw_read(fd,n)
                        if case=='expired_settings' and fs.fd_paths.get(fd)==str(fs.gate):fs.clock[0]=4000.
                        return result
                    # Gate uses io.open, so expire immediately after its actual read instead.
                    raw_open=io.open
                    class GateRead:
                        def __init__(inner,handle):inner.handle=handle
                        def __enter__(inner):inner.handle.__enter__();return inner
                        def __exit__(inner,*args):return inner.handle.__exit__(*args)
                        def read(inner,n=-1):
                            value=inner.handle.read(n);fs.clock[0]=4000.;return value
                    def gate_boundary(path,*a,**kw):
                        handle=raw_open(path,*a,**kw)
                        return GateRead(handle) if case=='expired_settings' and str(path)==str(fs.gate) else handle
                    cleanup.enter_context(patch.object(io,'open',gate_boundary))
                    argv=['release',action,'--manifest','/etc/candidate.json','--role',role,'--runtime',str(fs.runtime),'--gate',str(fs.gate),'--update-attempt-id',fs.attempt,'--expected-node-identity-base64',base64.urlsafe_b64encode(json.dumps(fs.identity).encode()).decode()]
                    with patch.object(sys,'argv',argv),patch('builtins.print'):
                        if case in ('normal',):self.ops.main()
                        else:
                            with self.assertRaisesRegex((ValueError,self.ops.CommandFailure),'deadline|bound|exceeds'):self.ops.main()
                    self.assertEqual(len(captured),1,'actual CLI creates one shared UpdateScan')
                    if case=='normal':self.assertGreater(captured[0].bytes,0);self.assertGreater(captured[0].actual_bytes,0)
                    if (role,action,case)==('controller','activate','normal'):
                        parent_events=[t for t in fs.trace if t[0]=='mkdir-map' and t[1]=='/var/lib/qcl-negf']
                        self.assertTrue(parent_events);own=fs.raw_stat(fs.root);parent=fs.raw_stat(fs.real('/var/lib/qcl-negf'))
                        self.assertEqual(parent.st_dev,own.st_dev)
                        for event in parent_events:self.assertEqual(event[2:],(str(fs.root/'var/lib/qcl-negf'),own.st_dev,own.st_ino))
                        self.assertEqual(fs.real('/var/lib/qcl-negf/allowed-codes').read_text(),'12345678-1234-1234-1234-123456789abc\n')
                    if case in ('expired_manifest','cap_manifest'):self.assertFalse(any(t[0] in ('read','io.open','open') and t[1]=='/etc/candidate.json' for t in fs.trace))
                    if case=='expired_settings':self.assertFalse(any(t[0]=='read' and t[1]=='/etc/qcl-negf/release-config.json' for t in fs.trace))
                    if case=='oversized_release':self.assertGreaterEqual(captured[0].bytes,65537)
                finally:self.root=old

    def test_r4_controller_code_publication_deadline(self):
        for case in ('after_register','during_publication'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as temporary,ExitStack() as cleanup:
                old=self.root;self.root=Path(temporary)
                try:
                    fs=self.fs(role='controller');cleanup.callback(fs.stack.close);code=Path('/var/lib/qcl-negf/allowed-codes');fs.write(code,'old-code\n');before=fs.real(code).read_bytes()
                    budget=self.ops.UpdateScan(200.);fs.budget=budget;native=fs.native;registered=[];writes=[]
                    def boundary(args):
                        result=native(args)
                        if 'register_aiida.py' in ' '.join(args):
                            registered.append(True)
                            if case=='after_register':fs.clock[0]=201.
                        return result
                    # Observe real file write inside actual publish, not replace publish/check body.
                    raw_open=io.open
                    class Writer:
                        def __init__(inner,handle):inner.handle=handle
                        def __enter__(inner):inner.handle.__enter__();return inner
                        def __exit__(inner,*args):return inner.handle.__exit__(*args)
                        def __getattr__(inner,key):return getattr(inner.handle,key)
                        def write(inner,value):
                            result=inner.handle.write(value);writes.append(value);fs.clock[0]=201.;return result
                    def publication_open(path,mode='r',*a,**kw):
                        handle=raw_open(path,mode,*a,**kw)
                        if case=='during_publication' and registered and 'w' in mode:return Writer(handle)
                        return handle
                    cleanup.enter_context(patch.object(io,'open',publication_open))
                    replacements=[];native_replace=os.replace
                    def publication_replace(source,destination,*args,**kwargs):
                        if str(destination)==str(code):replacements.append((str(source),str(destination)))
                        return native_replace(source,destination,*args,**kwargs)
                    cleanup.enter_context(patch.object(os,'replace',publication_replace))
                    with self.assertRaisesRegex(self.ops.CommandFailure,'deadline') as failure:
                        self.ops.activate(release(),profile=fs.profile,runtime=fs.runtime,gate=fs.gate,run=boundary,role='controller',email='test@example.invalid',allowed_codes_file=code,expected_node_identity=CONTROLLER,update_attempt_id=fs.attempt,deadline=200.,metadata_budget=budget)
                    self.assertTrue(registered);self.assertGreater(budget.actual_bytes,0)
                    if case=='after_register':self.assertEqual(fs.real(code).read_bytes(),before);self.assertFalse(writes)
                    else:
                        self.assertTrue(writes);self.assertTrue(getattr(failure.exception,'cleanup_pending',None))
                        parent_events=[t for t in fs.trace if t[0]=='mkdir-map' and t[1]=='/var/lib/qcl-negf']
                        self.assertTrue(parent_events);own=fs.raw_stat(fs.root)
                        for event in parent_events:self.assertEqual(event[2:],(str(fs.root/'var/lib/qcl-negf'),own.st_dev,own.st_ino))
                    self.assertFalse(replacements,'deadline forbids later Code replacement')
                    last=next(i for i,a in enumerate(fs.calls) if 'register_aiida.py' in ' '.join(a))
                    self.assertFalse(any(a[:2] in (['systemctl','start'],['systemctl','restart']) for a in fs.calls[last+1:]))
                finally:self.root=old

    def test_r5_nested_stopped_types_are_unknown(self):
        for case in ('member1','memberNone','memberstring','systemdNone','systemd1','systemdlist'):
            with self.subTest(case=case),self.isolated_delivery_case():
                self.corrupt_action='stop-update';self.bad_variant=case;self.bad_reached=0
                original=self.ops.deliver_cli
                def actual(*args,**kwargs):return original(*args,run=self.invalid_stopped,**kwargs)
                manifest_path=self.root/('candidate-'+case+'.json');manifest_path.write_text(json.dumps(delivery_manifest()))
                pool_path=self.root/('pool-'+case+'.json');pool_path.write_text(json.dumps(self.pool))
                argv=['release','update','--manifest',str(manifest_path),'--pool',str(pool_path),'--enrollment','/synthetic/enrollment.json','--runtime',str(self.runtime),'--gate',str(self.gate)]
                with patch.object(sys,'argv',argv),patch.object(self.ops,'deliver_cli',side_effect=actual),patch('builtins.print') as printed:
                    with self.assertRaises(SystemExit) as failure:self.ops.main()
                    self.assertEqual(failure.exception.code,1);self.assertTrue(printed.called)
                    summary=json.loads(printed.call_args[0][0]);self.assertEqual(summary['remote_outcome'],'unknown');self.assertTrue(summary['requires_reconciliation'])
                self.assertEqual(self.bad_reached,1);record=self.receipt();self.assertEqual(record['status'],'failed');self.assertEqual(record['stopped_observation_failure']['action'],'stop-update')
                self.assertLessEqual(len(record['stopped_observation_failure']['reason']),4096);self.no_later();self.assertFalse(json.loads(self.gate.read_text())['open'])
                before=len(self.calls)
                with self.assertRaisesRegex(RuntimeError,'Unresolved|reconciliation'):self.deliver()
                self.assertEqual(len(self.calls),before)

    def test_controller_fleet_health_body_uses_own_role_units(self):
        fs=self.fs(role='controller');budget=self.ops.UpdateScan(200.);fs.budget=budget
        # Native boundary derives only exact own role unit/probe responses; body is not patched.
        writes=[];reads=[];syncs=[];unlinks=[];write=os.write;read=os.read;sync=os.fsync;unlink=os.unlink
        def observe_write(fd,data):writes.append(data);return write(fd,data)
        def observe_read(fd,n):
            data=read(fd,n)
            if n==32:reads.append(data)
            return data
        def observe_sync(fd):syncs.append(fd);return sync(fd)
        def observe_unlink(path,*a,**kw):
            if Path(path).name.startswith('.update-probe-'):unlinks.append(str(path))
            return unlink(path,*a,**kw)
        with patch.object(os,'write',observe_write),patch.object(os,'read',observe_read),patch.object(os,'fsync',observe_sync),patch.object(os,'unlink',observe_unlink):
            result=self.ops.fleet_health(release(),CONTROLLER,runtime=fs.runtime,gate=fs.gate,run=fs.native,deadline=200.,metadata_budget=budget)
        self.assertTrue(result['nfs_verified']);self.assertEqual(result['node_identity'],CONTROLLER)
        for unit in ('qcl-negf-aiida.service','qcl-negf-api.service','munged.service'):self.assertIn(['systemctl','is-active','--quiet',unit],fs.calls)
        self.assertFalse(any('slurmd.service' in a for a in fs.calls));self.assertFalse(any(t[0]=='read' and t[1].startswith('/sys/fs/cgroup') for t in fs.trace))
        self.assertEqual(writes,[b'qcl-negf-update\n']);self.assertEqual(reads,[b'qcl-negf-update\n']);self.assertEqual(len(syncs),1);self.assertEqual(len(unlinks),1)
        self.assertGreater(budget.bytes,0);self.assertGreater(budget.actual_bytes,0)


if __name__ == "__main__":
    unittest.main()
