"""Service lifetime/projection faults at synthetic native and primary-journal boundaries."""
import copy
import importlib
import json
import os
from pathlib import Path
from unittest.mock import patch

from test_delivery_requests import RequestFixture, RID, engine


class DeliveryServiceTests(RequestFixture):
    def setUp(self):
        super().setUp()
        self.requests_module = self.requests()
        self.assertIsNotNone(importlib.util.find_spec('delivery_service'),
                             'Controller service/reconciliation is not implemented')
        self.service = importlib.import_module('delivery_service')
        self.generation = {'unit':self.requests_module.unit_name(RID),
            'boot_id':'9f8c1b22-1879-4ff6-839e-216159f67c34',
            'invocation_id':'a'*32,'pid':os.getpid(),'start_ticks':12345}
        self.entered = []
        self.gate = self.root/'gate.json'
        self.gate.write_text(json.dumps({'release_id':'old','open':False}))
        for name, value in [('require_controller',lambda:None),
            ('observe_service_generation',lambda *a,**kw:self.generation)]:
            hook = patch.object(self.service, name, value)
            hook.start(); self.addCleanup(hook.stop)
        hook = patch.object(engine, 'GATE', self.gate)
        hook.start(); self.addCleanup(hook.stop)
        hook = patch.object(engine, 'lifecycle_guard', lambda *a,**kw:None)
        hook.start(); self.addCleanup(hook.stop)

    def submit(self):
        return self.requests_module.submit_update(self.request, runtime=self.runtime, run=self.native)

    def complete_engine(self, expected, pool, *, request_context, progress, **kwargs):
        self.entered.append(copy.deepcopy(request_context))
        attempts = self.runtime/'delivery-attempts'
        attempts.mkdir(mode=0o700, exist_ok=True)
        receipt = {'schema':'qcl-negf-delivery-attempt-v1',
            'attempt_id':request_context['attempt_id'],'request_context':request_context,
            'manifest':expected,'identity':engine.manifest(expected),'status':'completed',
            'open':True,'operation':'whole_cluster_update','commands':[]}
        path = attempts/(request_context['attempt_id']+'.json')
        path.write_text(json.dumps(receipt)); path.chmod(0o600)
        self.gate.write_text(json.dumps({'release_id':expected['release_id'],'open':True}))
        projection = {'schema':'qcl-negf-delivery-progress-v1',**{k:request_context[k] for k in ('request_id','attempt_id','request_sha256')},
            'phase':'engine_returned','state':'completed','engine_receipt':'delivery-attempts/'+path.name,
            'original_failure_log':None,'admission_state':'open','pending_mutation':False,'requires_reconciliation':False}
        progress(projection)
        return {'status':'completed','open':True,'attempt_id':request_context['attempt_id'],'receipt':str(path)}

    def run_service(self):
        return self.service.run_update_service(RID, runtime=self.runtime, run=self.native)

    def test_service_owns_attempt_and_reentry_never_replays(self):
        submitted = self.submit()
        with patch.object(engine, 'deliver_cli', self.complete_engine):
            result = self.run_service()
            again = self.run_service()
        self.assertEqual(result['state'],'completed')
        self.assertEqual(again,result)
        self.assertEqual(len(self.entered),1)
        self.assertEqual(result['attempt_id'],submitted['attempt_id'])
        self.assertEqual(result['service_generation'],self.generation)
        self.assertTrue((self.runtime/'delivery-requests'/RID/'commit.json').is_file())

    def test_reboot_or_lost_primary_is_unknown_and_never_invokes_engine(self):
        self.submit()
        path = self.runtime/'delivery-requests'/RID/'operation.json'
        record = json.loads(path.read_bytes())
        record.update(state='running',service_generation=self.generation, pending_mutation=True)
        path.write_text(json.dumps(record))
        with patch.object(engine, 'deliver_cli', side_effect=AssertionError('blind replay')):
            reconciled = self.service.reconcile_update_requests(runtime=self.runtime,run=self.native)
            again = self.run_service()
        self.assertEqual(reconciled[0]['state'],'reconciliation_required')
        self.assertIsNone(reconciled[0]['pending_mutation'])
        self.assertEqual(again['state'],'reconciliation_required')
        self.assertEqual(again['admission_state'],'unknown')

    def test_projection_failure_after_commit_preserves_open_primary_and_witness(self):
        self.submit()
        write = self.requests_module.write_record
        def fail_projection(directory,name,value,**kwargs):
            if name=='operation.json' and value.get('state')=='completed':
                raise OSError('injected projection fsync failure after commit')
            return write(directory,name,value,**kwargs)
        with patch.object(engine,'deliver_cli',self.complete_engine), patch.object(self.requests_module,'write_record',fail_projection):
            result = self.run_service()
        self.assertEqual(result['state'],'outcome_unknown')
        self.assertEqual(result['admission_state'],'open')
        self.assertTrue(result['requires_reconciliation'])
        self.assertTrue(json.loads(self.gate.read_bytes())['open'])
        primary = self.runtime/result['engine_receipt']
        self.assertEqual(json.loads(primary.read_bytes())['status'],'completed')
        self.assertTrue((self.runtime/'delivery-requests'/RID/'commit.json').exists())

    def test_commit_witness_fsync_failure_does_not_close_or_rewrite_engine(self):
        self.submit()
        write = self.requests_module.write_record
        def fail_witness(directory,name,value,**kwargs):
            if name=='commit.json':
                raise OSError('injected witness fsync failure')
            return write(directory,name,value,**kwargs)
        with patch.object(engine,'deliver_cli',self.complete_engine), patch.object(self.requests_module,'write_record',fail_witness):
            result = self.run_service()
        self.assertEqual(result['state'],'outcome_unknown')
        self.assertEqual(result['admission_state'],'open')
        self.assertTrue(json.loads(self.gate.read_bytes())['open'])
        self.assertEqual(json.loads((self.runtime/result['engine_receipt']).read_bytes())['status'],'completed')

    def test_false_completion_or_wrong_primary_binding_never_commits(self):
        for change in ('wrong_attempt','missing_intent_cleanup','wrong_admission','unit_exit_only'):
            with self.subTest(change=change):
                self.runtime=self.root/change
                self.runtime.mkdir(mode=0o700)
                request = {**self.request,'request_id':__import__('uuid').uuid4().__str__()}
                rid = request['request_id']
                submitted = self.requests_module.submit_update(request,runtime=self.runtime,run=self.native)
                generation = {**self.generation,'unit':self.requests_module.unit_name(rid)}
                def false_engine(expected,pool,**kwargs):
                    self.complete_engine(expected,pool,**kwargs)
                    primary = self.runtime/'delivery-attempts'/(submitted['attempt_id']+'.json')
                    if change=='wrong_attempt':
                        body=json.loads(primary.read_bytes());body['attempt_id']=RID;primary.write_text(json.dumps(body))
                    elif change=='missing_intent_cleanup':
                        (primary.parent/(submitted['attempt_id']+'.admission-intent.json')).write_text('{}')
                    elif change=='wrong_admission':
                        self.gate.write_text(json.dumps({'release_id':'foreign','open':True}))
                    return {'status':'completed','open':True}
                # Defer the completion projection until after the injected primary fault.
                def engine_fault(expected,pool,**kwargs):
                    callback=kwargs['progress']; captured=[]
                    result=false_engine(expected,pool,**{**kwargs,'progress':captured.append})
                    if change!='unit_exit_only':callback(captured[-1])
                    return result
                with patch.object(engine,'deliver_cli',engine_fault),patch.object(self.service,'observe_service_generation',return_value=generation):
                    result=self.service.run_update_service(rid,runtime=self.runtime,run=self.native)
                self.assertNotEqual(result['state'],'completed')
                self.assertTrue(result['requires_reconciliation'])

    def test_generation_requires_observed_unit_process_and_cgroup_not_environment(self):
        real = importlib.reload(self.service).observe_service_generation
        generation=engine._process_generation()
        props='MainPID='+str(generation[0])+'\nInvocationID='+'a'*32+'\nActiveState=active\nControlGroup=/system.slice/'+self.requests_module.unit_name(RID)+'\n'
        local=engine.local_metadata
        def metadata(path,*args):
            if str(path)=='/proc/self/cgroup':
                return ('0::/system.slice/'+self.requests_module.unit_name(RID)+'\n').encode()
            return local(path,*args)
        with patch.object(engine,'local_metadata',metadata),patch.dict(os.environ,{'INVOCATION_ID':'b'*32}):
            observed=real(RID,run=lambda *a,**kw:props,bounds=self.request['bounds'],deadline=__import__('time').monotonic()+7)
            self.assertEqual(observed['invocation_id'],'a'*32)
            with self.assertRaises(ValueError):
                real(RID,run=lambda *a,**kw:props.replace('MainPID='+str(generation[0]),'MainPID=1'),bounds=self.request['bounds'],deadline=__import__('time').monotonic()+7)

    def test_precommit_projection_failure_keeps_original_engine_outcome(self):
        self.submit()
        write=self.requests_module.write_record
        def unavailable(directory,name,value,**kwargs):
            if name=='operation.json' and value.get('phase')=='pre_command':
                raise OSError('projection unavailable before native mutation')
            return write(directory,name,value,**kwargs)
        def engine_with_checkpoint(expected,pool,**kwargs):
            ctx=kwargs['request_context']
            kwargs['progress']({'schema':'qcl-negf-delivery-progress-v1',
                **{k:ctx[k] for k in ('request_id','attempt_id','request_sha256')},
                'phase':'pre_command','state':'running','engine_receipt':'delivery-attempts/'+ctx['attempt_id']+'.json',
                'original_failure_log':None,'admission_state':'closed','pending_mutation':True,'requires_reconciliation':False})
            return self.complete_engine(expected,pool,**kwargs)
        with patch.object(engine,'deliver_cli',engine_with_checkpoint),patch.object(self.requests_module,'write_record',unavailable):
            result=self.run_service()
        self.assertEqual(result['state'],'outcome_unknown')
        self.assertEqual(result['admission_state'],'open')
        self.assertEqual(json.loads((self.runtime/result['engine_receipt']).read_bytes())['status'],'completed')
        self.assertTrue((self.runtime/'delivery-requests'/RID/'commit.json').exists())

    def test_unknown_other_request_with_lost_primary_blocks_new_engine(self):
        self.submit()
        path=self.runtime/'delivery-requests'/RID/'operation.json'
        body=json.loads(path.read_bytes());body.update(state='outcome_unknown',pending_mutation=None,requires_reconciliation=True)
        path.write_text(json.dumps(body))
        other=str(__import__('uuid').uuid4())
        request={**self.request,'request_id':other}
        self.requests_module.submit_update(request,runtime=self.runtime,run=self.native)
        generation={**self.generation,'unit':self.requests_module.unit_name(other)}
        with patch.object(engine,'deliver_cli',self.complete_engine),patch.object(self.service,'observe_service_generation',return_value=generation):
            with self.assertRaisesRegex(ValueError,'reconciliation'):
                self.service.run_update_service(other,runtime=self.runtime,run=self.native)
        self.assertEqual(self.entered,[])

    def test_actual_directory_fsync_fault_after_completed_projection_replace(self):
        self.submit()
        fsync=os.fsync
        faulted=[]
        def fault(fd):
            target=os.readlink('/proc/self/fd/'+str(fd))
            if target==str(self.runtime/'delivery-requests'/RID):
                projection=self.runtime/'delivery-requests'/RID/'operation.json'
                if projection.exists() and json.loads(projection.read_bytes()).get('state')=='completed' and not faulted:
                    faulted.append(True)
                    raise OSError('actual directory fsync after projection replace')
            return fsync(fd)
        with patch.object(engine,'deliver_cli',self.complete_engine),patch.object(os,'fsync',fault):
            result=self.run_service()
        self.assertEqual(faulted,[True])
        self.assertEqual(result['state'],'outcome_unknown')
        self.assertEqual(result['admission_state'],'open')
        self.assertEqual(json.loads((self.runtime/result['engine_receipt']).read_bytes())['status'],'completed')
        self.assertTrue((self.runtime/'delivery-requests'/RID/'commit.json').exists())

    def test_completed_operation_requires_surviving_matching_commit_and_primary(self):
        self.submit()
        with patch.object(engine,'deliver_cli',self.complete_engine):
            result=self.run_service()
        requests=self.requests_module
        self.assertEqual(requests.read_update_status(RID,runtime=self.runtime)['state'],'completed')
        primary=self.runtime/result['engine_receipt']
        primary.unlink()
        with self.assertRaises(ValueError):
            requests.read_update_status(RID,runtime=self.runtime)
        with self.assertRaises(ValueError):
            requests.submit_update(self.request,runtime=self.runtime,run=self.native)
        self.assertEqual(len(self.calls),1)

    def test_p2_missing_immutable_binding_never_repairs_occupied_id(self):
        import time
        cases = {'request':('request.json',),
            'request_and_operation':('request.json','operation.json'),
            'request_and_lock':('request.json','lock'),
            'operation':('operation.json',)}
        for name, missing in cases.items():
            with self.subTest(missing=name):
                self.runtime=self.root/('p2-'+name)
                self.runtime.mkdir(mode=0o700)
                self.calls=[]; self.entered=[]
                submitted=self.submit()
                with patch.object(engine,'deliver_cli',self.complete_engine):
                    complete=self.run_service()
                self.assertEqual(complete['state'],'completed')
                directory=self.runtime/'delivery-requests'/RID
                for leaf in missing:
                    (directory/leaf).unlink()
                before={str(p.relative_to(self.runtime)):
                    (p.read_bytes(),p.stat().st_mtime_ns,p.stat().st_ino)
                    for p in self.runtime.rglob('*') if p.is_file()}
                directory_times={str(p.relative_to(self.runtime)):p.stat().st_mtime_ns
                    for p in self.runtime.rglob('*') if p.is_dir()}
                other='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
                def barrier():
                    return self.requests_module.guard_other_operations(self.runtime,other,
                        deadline=time.monotonic()+3)
                with self.assertRaises(ValueError):
                    self.requests_module.read_update_status(RID,runtime=self.runtime)
                with self.assertRaises(ValueError):barrier()
                with self.assertRaises(ValueError):
                    self.requests_module.submit_update(self.request,runtime=self.runtime,run=self.native)
                after={str(p.relative_to(self.runtime)):
                    (p.read_bytes(),p.stat().st_mtime_ns,p.stat().st_ino)
                    for p in self.runtime.rglob('*') if p.is_file()}
                self.assertEqual(after,before,'ordinary retry repaired or replaced lost immutable evidence')
                self.assertEqual(directory_times,{str(p.relative_to(self.runtime)):p.stat().st_mtime_ns
                    for p in self.runtime.rglob('*') if p.is_dir()})
                for leaf in missing:self.assertFalse((directory/leaf).exists())
                with self.assertRaises(ValueError):
                    self.requests_module.read_update_status(RID,runtime=self.runtime)
                with self.assertRaises(ValueError):barrier()
                self.assertEqual(len(self.calls),1)
                self.assertEqual(len(self.entered),1)
                self.assertEqual(submitted['attempt_id'],complete['attempt_id'])
