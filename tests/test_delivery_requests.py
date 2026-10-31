"""Synthetic durable controller admission; never runs native commands or services."""
import copy
from contextlib import contextmanager
import hashlib
import importlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

sys.path.insert(0, str(Path(__file__).parents[1] / 'ops'))
import application_release as engine
import release_trust
from test_application_release import delivery_manifest, POOL
from test_node_enrollment import selected_context

RID = 'd3986590-cf69-4ca8-af7c-c3e065241ad2'


@contextmanager
def fixture_trust(root):
    """Only the synthetic test root replaces the production root-owned ancestry."""
    original = release_trust.trusted_stat
    ancestors = {os.stat(p).st_ino for p in [root, *root.parents]}
    def trusted(info, *, directory):
        if directory and info.st_ino in ancestors:
            return
        values = list(info)
        values[4] = 0  # synthetic owner; all mode/type checks stay real
        if info.st_uid != os.geteuid():
            raise ValueError('Foreign fixture owner')
        original(os.stat_result(values), directory=directory)
    with patch.object(release_trust, 'trusted_stat', trusted):
        yield


class RequestFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runtime = self.root / 'runtime'
        self.runtime.mkdir(mode=0o700)
        self.enrollment = self.root / 'enrollment.json'
        self.enrollment.write_text(json.dumps(selected_context()['registry']))
        self.enrollment.chmod(0o600)
        self.request = {'schema': 'qcl-negf-delivery-request-v1', 'request_id': RID,
            'procedure': 'maintenance', 'manifest': delivery_manifest(False), 'pool': POOL,
            'enrollment': {'path': str(self.enrollment),
                'sha256': hashlib.sha256(self.enrollment.read_bytes()).hexdigest()},
            'bounds': {'delivery_timeout_seconds': 33, 'command_timeout_seconds': 7,
                'command_output_bytes': 65536, 'delivery_output_bytes': 1048576}}
        self.calls = []
        self.trust = fixture_trust(self.root)
        self.trust.__enter__()
        self.addCleanup(self.trust.__exit__, None, None, None)

    def requests(self):
        self.assertIsNotNone(importlib.util.find_spec('delivery_requests'),
            'Durable request admission/status is not implemented')
        module = importlib.import_module('delivery_requests')
        self.role = patch.object(module, 'require_controller', lambda: None)
        self.role.start()
        self.addCleanup(self.role.stop)
        return module

    def native(self, argv, **bounds):
        self.calls.append((argv, bounds))
        self.assertEqual(argv[:3], ['systemctl', 'start', '--no-block'])
        return ''


class DeliveryRequestTests(RequestFixture):
    def test_public_cli_requires_explicit_procedure_and_request_id_before_engine(self):
        manifest, pool = self.root/'manifest.json', self.root/'pool.json'
        manifest.write_text(json.dumps(self.request['manifest']))
        pool.write_text(json.dumps(POOL))
        argv = ['release', 'update', '--manifest', str(manifest), '--pool', str(pool),
                '--enrollment', str(self.enrollment), '--runtime', str(self.runtime)]
        with patch.object(sys, 'argv', argv), patch.object(engine, 'deliver_cli',
                return_value={'status':'completed','open':True}) as invoked, patch('builtins.print'):
            with self.assertRaises(SystemExit) as caught:
                engine.main()
        self.assertEqual(caught.exception.code, 2)
        invoked.assert_not_called()

    def test_same_request_returns_one_attempt_and_dispatch_in_every_state(self):
        requests = self.requests()
        first = requests.submit_update(self.request, runtime=self.runtime, run=self.native)
        for state in ('queued', 'running', 'failed', 'outcome_unknown', 'reconciliation_required'):
            path = self.runtime/'delivery-requests'/RID/'operation.json'
            record = json.loads(path.read_bytes())
            record.update(state=state, pending_mutation=None, requires_reconciliation=state in ('outcome_unknown','reconciliation_required'))
            path.write_text(json.dumps(record))
            result = requests.submit_update(copy.deepcopy(self.request), runtime=self.runtime, run=self.native)
            self.assertEqual(result['attempt_id'], first['attempt_id'])
            self.assertEqual(result['state'], state)
        self.assertEqual(len(self.calls), 1)
        self.assertNotEqual(first['attempt_id'], RID)

    def test_conflicting_old_id_or_unsupported_procedure_never_dispatches(self):
        requests = self.requests()
        requests.submit_update(self.request, runtime=self.runtime, run=self.native)
        before = list(self.calls)
        for field, value in [('procedure','soft_application'), ('bounds',{**self.request['bounds'],'delivery_timeout_seconds':99}),
                             ('manifest',{**self.request['manifest'],'release_id':'different'})]:
            candidate = copy.deepcopy(self.request)
            candidate[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                requests.submit_update(candidate, runtime=self.runtime, run=self.native)
        self.assertEqual(self.calls, before)

    def test_lost_launch_reply_keeps_original_attempt_and_no_retry(self):
        requests = self.requests()
        def uncertain(argv, **bounds):
            self.calls.append(argv)
            raise engine.CommandFailure({'failure':'timeout','child_started':True,'cleanup_confirmed':False})
        first = requests.submit_update(self.request, runtime=self.runtime, run=uncertain)
        self.assertEqual(first['state'], 'outcome_unknown')
        self.assertIsNone(first['pending_mutation'])
        again = requests.submit_update(self.request, runtime=self.runtime, run=self.native)
        self.assertEqual(first['attempt_id'], again['attempt_id'])
        self.assertEqual(len(self.calls), 1)

    def test_status_is_read_only_and_missing_binding_cannot_become_ready(self):
        requests = self.requests()
        first = requests.submit_update(self.request, runtime=self.runtime, run=self.native)
        files = list(self.runtime.rglob('*'))
        before = {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in files if p.is_file()}
        for _ in range(5):
            self.assertEqual(requests.read_update_status(RID, runtime=self.runtime), first)
        self.assertEqual(before, {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in files if p.is_file()})
        (self.runtime/'delivery-requests'/RID/'operation.json').unlink()
        with self.assertRaises(ValueError):
            requests.read_update_status(RID, runtime=self.runtime)
        with self.assertRaises(ValueError):
            requests.submit_update(self.request, runtime=self.runtime, run=self.native)
        self.assertEqual(len(self.calls), 1)

    def test_unknown_boundary_and_wrong_operation_identity_fail_closed(self):
        requests = self.requests()
        first = requests.submit_update(self.request, runtime=self.runtime, run=self.native)
        self.assertIsNone(first['pending_mutation'])
        path = self.runtime/'delivery-requests'/RID/'operation.json'
        body = json.loads(path.read_bytes())
        body['request_sha256'] = '0'*64
        path.write_text(json.dumps(body))
        with self.assertRaises(ValueError):
            requests.read_update_status(RID, runtime=self.runtime)

    def test_umask_and_symlink_namespace_never_chmod_foreign_target(self):
        requests = self.requests()
        old = os.umask(0o077)
        try:
            requests.submit_update(self.request, runtime=self.runtime, run=self.native)
        finally:
            os.umask(old)
        base = self.runtime/'delivery-requests'
        self.assertEqual(stat.S_IMODE(base.stat().st_mode), 0o700)
        for p in (base/RID).iterdir():
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        other = str(uuid.uuid4())
        (base/other).symlink_to(self.root, target_is_directory=True)
        candidate = {**self.request,'request_id':other}
        before = self.root.stat().st_mode
        with self.assertRaises((ValueError,OSError)):
            requests.submit_update(candidate, runtime=self.runtime, run=self.native)
        self.assertEqual(before, self.root.stat().st_mode)
        self.assertEqual(len(self.calls), 1)

    def test_worker_role_rejected_before_record_creation(self):
        requests = self.requests()
        with patch.object(requests, 'require_controller', side_effect=ValueError('controller')):
            with self.assertRaises(ValueError):
                requests.submit_update(self.request, runtime=self.runtime, run=self.native)
        self.assertEqual(self.calls, [])
        self.assertFalse((self.runtime/'delivery-requests').exists())

    def test_crash_between_request_and_attempt_publication_reserves_id(self):
        requests = self.requests()
        write = requests.write_record
        def interrupted(directory,name,value,**kwargs):
            if name=='operation.json':
                raise OSError('synthetic crash before attempt publication')
            return write(directory,name,value,**kwargs)
        with patch.object(requests,'write_record',interrupted), self.assertRaises(OSError):
            requests.submit_update(self.request,runtime=self.runtime,run=self.native)
        before = (self.runtime/'delivery-requests'/RID/'request.json').read_bytes()
        with self.assertRaises(ValueError):
            requests.submit_update(self.request,runtime=self.runtime,run=self.native)
        self.assertEqual(self.calls,[])
        self.assertEqual(before,(self.runtime/'delivery-requests'/RID/'request.json').read_bytes())

    def test_strict_values_and_duplicate_json_keys_refuse_before_dispatch(self):
        requests = self.requests()
        for field,value in [('request_id','../not-a-unit'),('request_id','00000000-0000-0000-0000-000000000000'),
                            ('procedure','docs'),('extra',True),('bounds',{**self.request['bounds'],'command_timeout_seconds':True})]:
            body = {**self.request,field:value}
            with self.subTest(field=field,value=str(value)),self.assertRaises(ValueError):
                requests.submit_update(body,runtime=self.runtime,run=self.native)
        with self.assertRaisesRegex(ValueError,'Duplicate'):
            engine.unique_json('{"request_id":"x","request_id":"y"}')
        self.assertEqual(self.calls,[])

    def test_public_submit_retains_artifacts_and_does_not_invoke_engine(self):
        requests = self.requests()
        manifest,pool=self.root/'manifest.json',self.root/'pool.json'
        manifest.write_text(json.dumps(self.request['manifest']));pool.write_text(json.dumps(POOL))
        argv=['release','update','--request-id',RID,'--procedure','maintenance',
              '--manifest',str(manifest),'--pool',str(pool),'--enrollment',str(self.enrollment)]
        observed=[]
        def submit(value,**kwargs):
            observed.append(value)
            return {'state':'queued','request_id':RID}
        with patch.object(sys,'argv',argv),patch.object(requests,'submit_update',submit),patch('builtins.print'),patch.object(engine,'deliver_cli',side_effect=AssertionError('client owns engine')):
            engine.main()
        self.assertEqual(observed[0]['manifest'],self.request['manifest'])
        self.assertEqual(observed[0]['pool'],POOL)
        self.assertEqual(observed[0]['enrollment']['sha256'],self.request['enrollment']['sha256'])

    def test_installed_layout_imports_command_without_new_frontend_dependency(self):
        import subprocess
        import shutil
        installed=self.root/'installed';installed.mkdir()
        ops=Path(engine.__file__).parent
        existing=('application_release.py','release_identity.py','release_trust.py','release_qualification.py','release_health.py')
        for name in existing:
            shutil.copyfile(ops/name,installed/name)
        result=subprocess.run([sys.executable,'-I','-c',
            'import sys;sys.path.insert(0,sys.argv[1]);from application_release import command,CommandFailure;print(command.__name__,CommandFailure.__name__)',str(installed)],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=7)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(result.stdout,b'command CommandFailure\n')
        for name in ('delivery_requests.py','delivery_service.py'):
            shutil.copyfile(ops/name,installed/name)
        result=subprocess.run([sys.executable,'-I','-c',
            'import sys;sys.path.insert(0,sys.argv[1]);import delivery_service;print(delivery_service.requests.COMMIT_SCHEMA)',str(installed)],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=7)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(result.stdout,b'qcl-negf-delivery-commit-v1\n')

    def test_old_id_remains_idempotent_after_enrollment_rotation_or_loss(self):
        requests=self.requests()
        first=requests.submit_update(self.request,runtime=self.runtime,run=self.native)
        self.enrollment.unlink()
        again=requests.submit_update(self.request,runtime=self.runtime,run=self.native)
        self.assertEqual(first,again)
        self.assertEqual(len(self.calls),1)

    def test_concurrent_submit_serializes_one_original_attempt(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        requests=self.requests()
        entered=threading.Event();release=threading.Event()
        def start(argv,**bounds):
            self.calls.append(argv);entered.set()
            if not release.wait(3):raise AssertionError('fixture did not release launch')
            return ''
        with ThreadPoolExecutor(max_workers=2) as pool:
            first=pool.submit(requests.submit_update,self.request,runtime=self.runtime,run=start)
            self.assertTrue(entered.wait(3))
            second=pool.submit(requests.submit_update,self.request,runtime=self.runtime,run=start)
            release.set()
            self.assertEqual(first.result(timeout=4),second.result(timeout=4))
        self.assertEqual(len(self.calls),1)

    def test_p2_abandoned_new_namespace_does_not_authorize_new_publication(self):
        requests=self.requests()
        for locked in (False,True):
            with self.subTest(lock_exists=locked):
                runtime=self.root/('p2-empty-'+str(locked));runtime.mkdir(mode=0o700)
                base=runtime/'delivery-requests';base.mkdir(mode=0o700)
                directory=base/RID;directory.mkdir(mode=0o700)
                if locked:
                    (directory/'lock').write_bytes(b'');(directory/'lock').chmod(0o600)
                before={p.name:(p.read_bytes(),p.stat().st_mtime_ns) for p in directory.iterdir()}
                mtime=directory.stat().st_mtime_ns
                with self.assertRaises(ValueError):
                    requests.submit_update(self.request,runtime=runtime,run=self.native)
                self.assertEqual(before,{p.name:(p.read_bytes(),p.stat().st_mtime_ns) for p in directory.iterdir()})
                self.assertEqual(mtime,directory.stat().st_mtime_ns)
                self.assertFalse((directory/'request.json').exists())
                self.assertFalse((directory/'operation.json').exists())
        self.assertEqual(self.calls,[])

    def test_p2_crash_before_first_request_publication_keeps_id_unbound(self):
        requests=self.requests()
        write=requests.write_record
        def interrupted(directory,name,value,**kwargs):
            if name=='request.json':raise OSError('synthetic crash before first publication')
            return write(directory,name,value,**kwargs)
        with patch.object(requests,'write_record',interrupted),self.assertRaises(OSError):
            requests.submit_update(self.request,runtime=self.runtime,run=self.native)
        directory=self.runtime/'delivery-requests'/RID
        before={p.name:(p.read_bytes(),p.stat().st_mtime_ns) for p in directory.iterdir()}
        with self.assertRaises(ValueError):
            requests.submit_update(self.request,runtime=self.runtime,run=self.native)
        self.assertEqual(before,{p.name:(p.read_bytes(),p.stat().st_mtime_ns) for p in directory.iterdir()})
        self.assertEqual(self.calls,[])
        self.assertFalse((directory/'request.json').exists())

    def test_p2_concurrent_arrival_before_new_creator_lock_cannot_publish(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        requests=self.requests()
        opened=requests._open_directory
        created=threading.Event();release=threading.Event()
        def pause_creator(parent,name,create=False):
            result=opened(parent,name,create)
            if name==RID and result[1]:
                created.set()
                if not release.wait(3):raise AssertionError('creator was not released')
            return result
        with patch.object(requests,'_open_directory',pause_creator),ThreadPoolExecutor(max_workers=2) as pool:
            first=pool.submit(requests.submit_update,self.request,runtime=self.runtime,run=self.native)
            self.assertTrue(created.wait(3))
            try:
                second=pool.submit(requests.submit_update,self.request,runtime=self.runtime,run=self.native)
                with self.assertRaises(ValueError):second.result(timeout=3)
                self.assertEqual(list((self.runtime/'delivery-requests'/RID).iterdir()),[])
                self.assertEqual(self.calls,[])
            finally:release.set()
            admitted=first.result(timeout=4)
        self.assertEqual(requests.submit_update(self.request,runtime=self.runtime,run=self.native),admitted)
        self.assertEqual(len(self.calls),1)


class NativeControllerConfigTests(unittest.TestCase):
    """Real public-source IO in a virtual NixOS tree; ownership is fixture-only."""
    CONFIG = '/etc/qcl-negf/release-config.json'
    STATIC = '/etc/static/qcl-negf/release-config.json'
    STORE = '/nix/store/config-release.json'

    def setUp(self):
        self.requests = importlib.import_module('delivery_requests')
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ('etc/qcl-negf', 'etc/static/qcl-negf', 'nix/store'):
            (self.root/name).mkdir(parents=True, exist_ok=True)
        self.write_config({'role': 'controller'})
        self.local(self.STATIC).symlink_to(self.STORE)
        self.local(self.CONFIG).symlink_to(self.STATIC)
        self.foreign = set()
        original_scan, original_open, original_fstat = engine.UpdateScan, os.open, os.fstat
        self.original_fstat = original_fstat
        self.original_open = original_open
        self.original_trusted = release_trust.trusted_stat
        fixture = self

        def root_stat(info, foreign=False):
            # Preserve nanosecond times and all real type/mode/inode properties.
            class RootStat:
                st_uid = 12345 if foreign else 0
                def __getattr__(self, name):
                    return getattr(info, name)
            if info.st_uid != os.geteuid():
                raise ValueError('Foreign fixture filesystem owner')
            return RootStat()

        class FixtureScan(original_scan):
            def stat(self, path, *, follow_symlinks=False):
                result = super().stat(fixture.local(path), follow_symlinks=follow_symlinks)
                return root_stat(result, str(path) in fixture.foreign)
            def link(self, path):
                return super().link(fixture.local(path))

        def open_public(path, *args, **kwargs):
            if str(path) == '/' or str(path).startswith(('/etc/', '/nix/')):
                path = self.local(path)
            return original_open(path, *args, **kwargs)

        self.public_open = open_public
        self.public_fstat = lambda fd: root_stat(original_fstat(fd))
        for hook in (patch.object(engine, 'UpdateScan', FixtureScan),
                     patch.object(os, 'open', open_public),
                     patch.object(os, 'fstat', lambda fd: root_stat(original_fstat(fd)))):
            hook.start()
            self.addCleanup(hook.stop)

    def local(self, path):
        return self.root/str(path).lstrip('/')

    def write_config(self, settings):
        target = self.local(self.STORE)
        if target.exists():
            target.chmod(0o644)
        target.write_text(json.dumps(settings))
        target.chmod(0o444)

    def test_native_etc_static_store_chain_admits_controller(self):
        self.assertIsNone(self.requests.require_controller())

    def test_native_sticky_group_writable_store_admits_controller(self):
        self.local('/nix/store').chmod(0o1775)
        self.assertIsNone(self.requests.require_controller())

    def test_store_exception_rejects_nonsticky_foreign_or_world_writable(self):
        store = self.local('/nix/store')
        for mode in (0o775, 0o1777):
            store.chmod(mode)
            with self.subTest(mode=oct(mode)), self.assertRaises(ValueError):
                self.requests.require_controller()
        store.chmod(0o1775)
        self.foreign.add('/nix/store')
        with self.assertRaises(ValueError):
            self.requests.require_controller()

    def test_store_exception_does_not_cover_other_sticky_ancestors(self):
        self.local('/etc/static/qcl-negf').chmod(0o1775)
        with self.assertRaises(ValueError):
            self.requests.require_controller()

    def test_native_static_directory_symlink_admits_controller(self):
        static = self.local('/etc/static')
        (static/'qcl-negf/release-config.json').unlink()
        (static/'qcl-negf').rmdir()
        static.rmdir()
        generation = self.local('/nix/store/etc-generation')
        (generation/'qcl-negf').mkdir(parents=True)
        (generation/'qcl-negf/release-config.json').symlink_to(self.STORE)
        static.symlink_to('/nix/store/etc-generation', target_is_directory=True)
        self.assertIsNone(self.requests.require_controller())

    def test_mutable_protected_reader_still_rejects_public_symlink(self):
        with self.assertRaises(OSError) as caught:
            release_trust.read_protected_file(self.CONFIG, 16384)
        self.assertEqual(caught.exception.errno, 40)

    def test_worker_role_is_rejected(self):
        self.write_config({'role': 'worker'})
        with self.assertRaisesRegex(ValueError, 'controller role'):
            self.requests.require_controller()

    def test_writable_or_foreign_store_file_is_rejected(self):
        self.local(self.STORE).chmod(0o644)
        with self.assertRaises(ValueError):
            self.requests.require_controller()
        self.local(self.STORE).chmod(0o444)
        self.foreign.add(self.STORE)
        with self.assertRaises(ValueError):
            self.requests.require_controller()

    def test_foreign_symlink_or_writable_ancestor_is_rejected(self):
        self.foreign.add(self.STATIC)
        with self.assertRaises(ValueError):
            self.requests.require_controller()
        self.foreign.clear()
        self.local('/etc/static/qcl-negf').chmod(0o777)
        with self.assertRaises(ValueError):
            self.requests.require_controller()

    def test_foreign_or_writable_root_is_rejected(self):
        self.foreign.add('/')
        with self.assertRaises(ValueError):
            self.requests.require_controller()
        self.foreign.clear()
        self.root.chmod(0o777)
        with self.assertRaises(ValueError):
            self.requests.require_controller()

    def test_escaping_mutable_target_is_rejected(self):
        mutable = self.local('/etc/mutable.json')
        mutable.write_text('{"role":"controller"}')
        self.local(self.STATIC).unlink()
        self.local(self.STATIC).symlink_to('/etc/mutable.json')
        with self.assertRaises(ValueError):
            self.requests.require_controller()

    def test_symlink_cycle_is_bounded(self):
        self.local(self.STATIC).unlink()
        self.local(self.STATIC).symlink_to(self.CONFIG)
        with self.assertRaisesRegex(ValueError, 'symlink bound'):
            self.requests.require_controller()

    def test_swapped_selection_during_read_is_rejected(self):
        other = '/nix/store/config-other.json'
        self.local(other).write_text('{"role":"controller"}')
        self.local(other).chmod(0o444)
        read = engine.immutable_public_bytes
        def swap_after_read(*args, **kwargs):
            value = read(*args, **kwargs)
            self.local(self.STATIC).unlink()
            self.local(self.STATIC).symlink_to(other)
            return value
        with patch.object(engine, 'immutable_public_bytes', swap_after_read):
            with self.assertRaisesRegex(ValueError, 'namespace changed'):
                self.requests.require_controller()

    def test_wrong_terminal_type_is_rejected_before_open(self):
        target = self.local(self.STORE)
        target.unlink()
        target.mkdir()
        with self.assertRaises(ValueError):
            self.requests.require_controller()
        target.rmdir()
        os.mkfifo(target)
        with self.assertRaises(ValueError):
            self.requests.require_controller()

    def test_oversize_config_is_rejected(self):
        self.write_config({'role':'controller', 'padding':'x'*16384})
        with self.assertRaises(ValueError):
            self.requests.require_controller()

    def test_missing_installed_helper_still_rejects_controller(self):
        with patch.object(self.requests, '__file__', str(self.root/'delivery_requests.py')):
            with self.assertRaisesRegex(ValueError, 'Uninstalled controller'):
                self.requests.require_controller()

    def test_empty_boot_reconcile_has_no_side_effect(self):
        service = importlib.import_module('delivery_service')
        runtime = self.root/'runtime'
        runtime.mkdir(mode=0o700)
        gate = runtime/'admission.json'
        gate.write_text('{"open":false}')
        before = (gate.read_bytes(), gate.stat().st_mtime_ns)
        def forbidden(*args, **kwargs):
            raise AssertionError('Empty boot must not invoke native commands or delivery')
        check = self.requests.require_controller
        def controller_check():
            with patch.object(os, 'fstat', self.public_fstat), \
                 patch.object(os, 'open', self.public_open), \
                 patch.object(release_trust, 'trusted_stat', self.original_trusted):
                check()
        with patch.object(service, 'require_controller', controller_check), \
             patch.object(os, 'open', self.original_open), \
             patch.object(os, 'fstat', self.original_fstat), \
             patch.object(engine, 'deliver_cli', forbidden), \
             fixture_trust(self.root):
            self.assertEqual(service.reconcile_update_requests(runtime=runtime, run=forbidden), ())
        self.assertEqual(list(runtime.iterdir()), [gate])
        self.assertEqual((gate.read_bytes(), gate.stat().st_mtime_ns), before)
