"""Idle runtime Source/L fixtures; no native command, measurement or qualification."""
from dataclasses import asdict, replace
import copy
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_host_resource_qualification import calibration, OP


def runtime():
    assert importlib.util.find_spec('host_resource_qualification_runtime') is not None, 'missing actual idle runtime module'
    return importlib.import_module('host_resource_qualification_runtime')


@pytest.fixture
def idle(tmp_path, monkeypatch):
    import host_resource_backends as backends
    import host_resource_facts as facts
    import host_resource_qualification_observations as observations
    from test_host_resource_qualification_observations import os_accounting
    q,n,m,c,b,store,e,p,s,r,parent,raw,plan=calibration(tmp_path)
    monkeypatch.setattr(backends,'trusted_root_path',lambda path,**kw:Path(path))
    # Explicit local fixture substitutes UID0 only in the dedicated reader;
    # store ownership and production code retain their real strict checks.
    def root_owned(meta):
        return SimpleNamespace(**{key:(0 if key=='st_uid'else getattr(meta,key))for key in dir(meta)if key.startswith('st_')})
    reader_os=SimpleNamespace(**{key:getattr(os,key)for key in dir(os)})
    reader_os.fstat=lambda fd:root_owned(os.fstat(fd))
    reader_os.lstat=lambda path:root_owned(os.lstat(path))
    monkeypatch.setattr(backends,'os',reader_os)
    contexts={};pairs={};calls=[]
    for vm in c.policy.vms:
        binding=state_binding=store.load()['bindings'][vm.vm_id]
        ctx=dict(host_id=c.policy.host_id,owner_id=c.policy.owner_id,host_boot_id=e.host_boot_id,
            policy_sha256=m.policy_digest(c.policy),source_graph_sha256=plan['source_graph_sha256'],
            qualification_ref=c.policy.active_grant.qualification_ref,baseline_state_sha256=plan['baseline_state_sha256'],
            worker_machine_id=('b'if vm.vm_id=='vm-a'else'c')*32,output_owner={},binding=state_binding,
            native_minimum_bytes=vm.minimum_bytes,native_maximum_bytes=vm.maximum_bytes,
            quantum_bytes=b.quantum_bytes,paid_grant_bytes=vm.maximum_bytes)
        a=os_accounting();a['identity']=dict(machine_id=ctx['worker_machine_id'],boot_id=binding['guest_boot_id'],
            kernel=binding['guest_kernel_id'],dmi_uuid=binding['native_id'],image_id=binding['image_id'])
        for key in ('meminfo_bytes','meminfo_after_bytes'):
            a[key]={name:0 for name in a[key]};a[key].update(MemTotal=vm.maximum_bytes,MemFree=vm.maximum_bytes-64,MemAvailable=vm.maximum_bytes-64)
        a['os_upper_bound_bytes']=64;a['jobs']={};a['processes']=a['processes'][:1]
        guest=dict(schema='qcl.host-resource-guest-facts.v1',identity_before=a['identity'],identity_after=a['identity'],
            observed_at=100,jobs={},groups={},memory=dict(MemTotal=vm.maximum_bytes,MemAvailable=vm.maximum_bytes-64),
            calibration_accounting=a,slurm_memory_bytes=vm.maximum_bytes-80,slurm_registered=True)
        contexts[vm.vm_id]=ctx;pairs[vm.vm_id]=guest
    provider=facts.NativeFactsProvider(c.policy,dict(client_uid=3000,enrollment={vm:dict(machine_id=ctx['worker_machine_id'])for vm,ctx in contexts.items()}),c.backend,None,clock=lambda:100)
    provider.native_proofs=p
    host=dict(boot_id=e.host_boot_id,MemTotal=c.policy.physical_ram_bytes,MemAvailable=4096)
    def pair(ctx):
        calls.append(ctx['binding']['vm_id']);vm=ctx['binding']['vm_id'];read=b.rows[vm];g=copy.deepcopy(pairs[vm])
        original=dict(host=copy.deepcopy(host),inventory=[dict(native_id=x.native_id)for x in b.rows.values()],agreement=dict(marker='actual synthetic agreement'),
            guest=g,native_before=asdict(read),native_after=asdict(read),capture_interval=dict(caller_started_at=100,caller_ended_at=100,
                caller_started_monotonic_ns=1,caller_ended_monotonic_ns=2,guest_observed_at=100))
        return read,g,original
    monkeypatch.setattr(provider,'_calibration_pair',pair)
    monkeypatch.setattr(provider,'_calibration_binding_pair',pair)
    service=SimpleNamespace(controller=c,provider=provider)
    def attach(owner):
        s.calibration_guard=owner.calibration_guard
        s.calibration_settlement_guard=owner.settlement_guard
        s.calibration_assess_settled=owner.assess_settled
    def observation(vm='vm-a',sequence=1):
        ctx=contexts[vm];read,g,original=pair(ctx)
        return observations.CalibrationObservation(context=ctx,sequence=sequence,readback=asdict(read),
            total_bytes=g['memory']['MemTotal'],available_bytes=g['memory']['MemAvailable'],slurm_memory_bytes=g['slurm_memory_bytes'],
            slurm_registered=g['slurm_registered'],jobs=(),effect=None,proposed_target_bytes=None,pressure=None,closure=None,
            evidence_sha256=backends.fingerprint(original),accounting=g['calibration_accounting'],source_records=original)
    sample=observation();account=observations.plain(sample.accounting)
    fragment=dict(measurement=dict(state='measured',scope='synthetic independently reviewed idle image/services/native target scope; not future OS theorem',
        evidence_sha256='',mapping_evidence_sha256='',observed_os_bytes=64,safety_allowance_bytes=16,os_reserve_bytes=80,
        native_gap_bound_bytes=16,maximum_guest_total_bytes=b.rows['vm-a'].assigned_bytes,native_maximum_bytes=b.rows['vm-a'].assigned_bytes),
        os_samples=[dict(observed_os_bytes=64,evidence_sha256=backends.fingerprint(account),accounting=account)],
        mapping_samples=[dict(assigned_bytes=sample.readback['assigned_bytes'],configured_bytes=sample.readback['configured_bytes'],
            total_bytes=sample.total_bytes,available_bytes=sample.available_bytes,evidence_sha256=sample.evidence_sha256)])
    fragment['measurement']['evidence_sha256']=backends.fingerprint(fragment['os_samples']);fragment['measurement']['mapping_evidence_sha256']=backends.fingerprint(fragment['mapping_samples'])
    permit=dict(schema=observations.PERMIT_SCHEMA,context=contexts['vm-a'],authorized_demands={},capacity_measurement=fragment)
    report=observations.build_qualification_report(permit,{'idle-grow':(sample,)})
    folder=parent.repository.folder(OP);reports=folder/'reports';reports.mkdir(mode=0o700)
    def stage(document=report,activation_change=None):
        digest=backends.fingerprint(document);path=reports/(digest+'.json');path.write_bytes(json.dumps(document,sort_keys=True,separators=(',',':')).encode());path.chmod(0o600)
        activation=dict(schema='qcl.host-resource-calibration-idle-runtime.v1',operation_id=OP,plan_sha256=parent.repository.digest(folder/'plan.json'),
            bootstrap_report_sha256=digest,planned_targets=sorted({row['target_bytes']for row in plan['cases'].values()}),scope_sha256=backends.fingerprint(document['permit']['capacity_measurement']))
        if activation_change:activation.update(activation_change)
        path=parent.repository.directory/'idle-runtime.json';path.write_text(json.dumps(activation));path.chmod(0o600)
        return activation
    return SimpleNamespace(**locals())


def test_missing_activation_keeps_factory_absent_without_writes(idle):
    rt=runtime();before=idle.raw
    assert rt.open_native_runtime(idle.service) is None
    assert idle.store.state_path.read_bytes()==before and not idle.calls[1:]


def test_actual_idle_guard_reopens_from_fixed_activation_and_keeps_main_bytes(idle):
    rt=runtime();idle.stage();first=rt.open_native_runtime(idle.service)
    assert first is not rt.open_native_runtime(idle.service)
    assert first.calibration_guard(idle.plan,idle.store.load(),idle.b.rows['vm-a'],128,case_name='idle-shrink') is None
    assert set(idle.calls)=={'vm-a','vm-b'} and idle.store.state_path.read_bytes()==idle.raw
    assert idle.r.calls==[] and not list(idle.p.directory.glob('*.owner.json'))


@pytest.mark.parametrize('change',[{'schema':'other'},{'planned_targets':[True]},{'plan_sha256':'0'*64},{'scope_sha256':'0'*64},{'extra':True}])
def test_malformed_activation_never_falls_back(idle,change):
    rt=runtime();idle.stage(activation_change=change)
    with pytest.raises((idle.m.ResourceError,ValueError)):rt.open_native_runtime(idle.service)
    assert idle.r.calls==[] and idle.store.state_path.read_bytes()==idle.raw


@pytest.mark.parametrize('kind',['symlink','hardlink','fifo'])
def test_activation_refuses_unsafe_file_type(idle,kind):
    rt=runtime();idle.stage();path=idle.parent.repository.directory/'idle-runtime.json'
    if kind=='symlink':target=path.with_suffix('.real');path.rename(target);path.symlink_to(target)
    elif kind=='hardlink':path.with_suffix('.link').hardlink_to(path)
    else:path.unlink();os.mkfifo(path,0o600)
    with pytest.raises((idle.m.ResourceError,OSError,ValueError)):rt.open_native_runtime(idle.service)


@pytest.mark.parametrize('fault',['child-directory','job','other-vm-job','group','accounting-job','host-pressure','readback','source','reserve','gap','max-inferred','scope-missing','primary-missing'])
def test_guard_rejects_missing_unsafe_or_unjoined_actual_observations(idle,fault):
    rt=runtime()
    if fault=='child-directory':(idle.parent.repository.folder(OP)/'jobs').mkdir()
    if fault in {'job','other-vm-job'}:idle.pairs['vm-b'if fault=='other-vm-job'else'vm-a']['jobs']={'42':{}}
    if fault=='group':idle.pairs['vm-a']['groups']={'42':{}}
    if fault=='accounting-job':idle.pairs['vm-a']['calibration_accounting']['jobs']={'42':{}}
    if fault=='host-pressure':idle.host['MemAvailable']=0
    if fault=='readback':idle.b.rows['vm-a']=replace(idle.b.rows['vm-a'],configured_bytes=2047)
    if fault=='source':idle.s.changed_source=True
    report=copy.deepcopy(idle.report)
    if fault=='reserve':report['permit']['capacity_measurement']['measurement']['os_reserve_bytes']=128
    if fault=='gap':report['permit']['capacity_measurement']['measurement']['native_gap_bound_bytes']=None
    if fault=='max-inferred':report['permit']['capacity_measurement']['mapping_samples'][0]['total_bytes']=999
    if fault=='scope-missing':report['permit']['capacity_measurement']['measurement']['scope']=''
    if fault=='primary-missing':report['cases']['idle-grow']['original_evidence'][0]['source_records']=None
    idle.stage(report)
    with pytest.raises((idle.m.ResourceError,ValueError,KeyError,TypeError)):
        rt.open_native_runtime(idle.service).calibration_guard(idle.plan,idle.store.load(),idle.b.rows['vm-a'],128,case_name='idle-shrink')
    assert idle.r.calls==[] and idle.store.state_path.read_bytes()==idle.raw


def test_scope_failure_after_genuine_c_success_is_separate_from_native_unknown(idle):
    rt=runtime();idle.stage();owner=rt.open_native_runtime(idle.service)
    idle.attach(owner)
    # Physical scope becomes unsafe only after original C succeeds at target.
    original=idle.r.run
    def run(argv,**kw):
        result=original(argv,**kw)
        idle.pairs['vm-a']['memory']['MemAvailable']=0
        return result
    idle.r.run=run
    with pytest.raises(idle.m.ResourceError)as caught:idle.parent.run_case('idle-shrink')
    assert caught.value.code=='calibration_physical'
    assert caught.value.native_outcome=='RETURNED_SUCCESS' and caught.value.physical_status=='FAIL'
    mid=idle.parent.repository.read(idle.parent.repository.case_path(OP,'idle-shrink'))['mutation_id']
    assert idle.p.read(mid)['phase']=='RETURNED_SUCCESS' and len(idle.r.calls)==1
    assert idle.parent.repository.readback_path(OP,mid).exists()
    with pytest.raises(idle.m.ResourceError):idle.parent.run_case('idle-grow')
    assert len(idle.r.calls)==1 and idle.store.state_path.read_bytes()==idle.raw


def test_purpose_report_writer_exceeds_generic_cap_without_changing_it(idle):
    rt=runtime();report=copy.deepcopy(idle.report)
    report['permit']['capacity_measurement']['measurement']['scope']+='x'*300000
    result=rt.write_report_exclusive(idle.parent,report)
    assert Path(result['path']).stat().st_size>256*1024
    assert idle.backends.read_root_qualification_report(result['path'])==report
    assert idle.backends.MAX_OUTPUT_BYTES==256*1024
    assert rt.write_report_exclusive(idle.parent,report)==result


@pytest.mark.parametrize('fault',['oversize','symlink','partial','file-fsync','dir-fsync','short-write'])
def test_writer_retains_original_failure_and_never_replaces_partial(idle,monkeypatch,fault):
    rt=runtime();report=copy.deepcopy(idle.report);digest=idle.backends.fingerprint(report)
    path=idle.parent.repository.folder(OP)/'reports'/(digest+'.json')
    path.unlink(missing_ok=True)
    if fault=='oversize':report['permit']['capacity_measurement']['measurement']['scope']='x'*(8*1024**2)
    if fault=='symlink':path.symlink_to(idle.parent.repository.folder(OP)/'plan.json')
    if fault=='partial':path.write_text('{');path.chmod(0o600)
    if fault in {'file-fsync','dir-fsync'}:
        original=os.fsync
        def fsync(fd):
            import stat
            if (stat.S_ISDIR(os.fstat(fd).st_mode))==(fault=='dir-fsync'):raise OSError('synthetic fsync')
            original(fd)
        monkeypatch.setattr(rt.os,'fsync',fsync)
    if fault=='short-write':monkeypatch.setattr(rt.os,'write',lambda *args:0)
    with pytest.raises((idle.m.ResourceError,OSError,ValueError)):rt.write_report_exclusive(idle.parent,report)
    if fault=='partial':assert path.read_text()=='{'
    assert idle.store.state_path.read_bytes()==idle.raw


def test_maximum_capture_precedes_activation_and_bootstrap_report_is_incomplete(idle):
    rt=runtime()
    capture=getattr(rt,'capture_idle_maximum',None)
    assert callable(capture),'missing actual pre-activation maximum producer'
    o=capture(idle.service,OP,1)
    assert o.readback['assigned_bytes']==2048 and o.accounting['os_upper_bound_bytes']==64
    make=getattr(rt,'build_idle_bootstrap_report',None)
    assert callable(make),'missing conservative incomplete bootstrap producer'
    report=make((o,),safety_allowance_bytes=16,native_gap_bound_bytes=16,scope='synthetic reviewed actual native target applicability')
    assert idle.observations.qualification_candidate(report)is None
    assert report['permit']['capacity_measurement']['measurement']['os_reserve_bytes']==80
    idle.stage(report)
    assert rt.open_native_runtime(idle.service).calibration_guard(idle.plan,idle.store.load(),idle.b.rows['vm-a'],128,case_name='idle-shrink')is None
    assert idle.store.state_path.read_bytes()==idle.raw and idle.r.calls==[]


@pytest.mark.parametrize('drift',['binding','maximum','other-native-low','report-primary'])
def test_actual_exact_policy_and_primary_scope_remain_bound(idle,drift):
    rt=runtime();report=copy.deepcopy(idle.report)
    if drift=='binding':idle.plan['bindings']['vm-a']['image_id']='changed'
    if drift=='maximum':
        idle.plan['cases']['idle-grow']['target_bytes']=4096
        path=idle.parent.repository.folder(OP)/'plan.json';path.write_text(json.dumps(idle.plan));path.chmod(0o600)
    if drift=='other-native-low':idle.b.rows['vm-b']=replace(idle.b.rows['vm-b'],assigned_bytes=128,configured_bytes=128)
    if drift=='report-primary':
        row=report['cases']['idle-grow']['original_evidence'][0];row['readback']['native_id']='other'
        row['source_records']['native_before']=copy.deepcopy(row['readback']);row['source_records']['native_after']=copy.deepcopy(row['readback'])
        row['evidence_sha256']=idle.backends.fingerprint(row['source_records'])
        report['permit']['capacity_measurement']['mapping_samples'][0]['evidence_sha256']=row['evidence_sha256']
        report['permit']['capacity_measurement']['measurement']['mapping_evidence_sha256']=idle.backends.fingerprint(report['permit']['capacity_measurement']['mapping_samples'])
    idle.stage(report)
    with pytest.raises((idle.m.ResourceError,ValueError)):
        rt.open_native_runtime(idle.service).calibration_guard(idle.plan,idle.store.load(),idle.b.rows['vm-a'],4096 if drift=='maximum' else 128,case_name='idle-shrink')


def test_report_writer_rejects_symlink_operation_ancestor(idle):
    rt=runtime();folder=idle.parent.repository.folder(OP);moved=folder.with_name(OP+'-moved');folder.rename(moved);folder.symlink_to(moved,target_is_directory=True)
    with pytest.raises((idle.m.ResourceError,OSError,ValueError)):rt.write_report_exclusive(idle.parent,idle.report)
    assert not list((moved/'reports').iterdir())


def test_scope_failure_record_survives_reopen_after_settlement_without_replay(idle):
    rt=runtime();idle.stage();owner=rt.open_native_runtime(idle.service);idle.attach(owner)
    original=idle.r.run
    def run(argv,**kw):
        result=original(argv,**kw);idle.pairs['vm-a']['memory']['MemAvailable']=0;return result
    idle.r.run=run
    with pytest.raises(idle.m.ResourceError)as caught:idle.parent.run_case('idle-shrink')
    assert Path(caught.value.calibration_evidence_path).exists()
    retained=idle.parent.repository.read(Path(caught.value.calibration_evidence_path))
    assert retained['source_records']['physical_failure']['native_outcome']=='RETURNED_SUCCESS'
    original_bytes=Path(caught.value.calibration_evidence_path).read_bytes()
    reopened=rt.open_native_runtime(idle.service)
    with pytest.raises(idle.m.ResourceError)as again:reopened.parent.reconcile()
    assert again.value.code=='calibration_pending' and len(idle.r.calls)==1
    assert reopened.parent._catalog(idle.plan,idle.store.load())==[]
    assert Path(caught.value.calibration_evidence_path).read_bytes()==original_bytes


@pytest.mark.parametrize('field,value',[('native_minimum_bytes',129),('quantum_bytes',1),('worker_machine_id','f'*32)])
def test_factory_joins_declared_scope_to_current_policy_and_enrollment(idle,field,value):
    rt=runtime();report=copy.deepcopy(idle.report)
    report['permit']['context'][field]=value
    for case in report['cases'].values():
        for row in case['original_evidence']:row['context'][field]=value
    if field=='worker_machine_id':
        for case in report['cases'].values():
            for row in case['original_evidence']:
                row['accounting']['identity']['machine_id']=value
                row['source_records']['guest']['calibration_accounting']['identity']['machine_id']=value
                row['source_records']['guest']['identity_before']['machine_id']=value
                row['source_records']['guest']['identity_after']['machine_id']=value
                row['evidence_sha256']=idle.backends.fingerprint(row['source_records'])
        fragment=report['permit']['capacity_measurement']
        fragment['os_samples'][0]['accounting']['identity']['machine_id']=value
        fragment['os_samples'][0]['evidence_sha256']=idle.backends.fingerprint(fragment['os_samples'][0]['accounting'])
        fragment['measurement']['evidence_sha256']=idle.backends.fingerprint(fragment['os_samples'])
        fragment['mapping_samples'][0]['evidence_sha256']=report['cases']['idle-grow']['original_evidence'][0]['evidence_sha256']
        fragment['measurement']['mapping_evidence_sha256']=idle.backends.fingerprint(fragment['mapping_samples'])
    idle.stage(report)
    with pytest.raises(idle.m.ResourceError):rt.open_native_runtime(idle.service)


def test_server_unknown_stays_unknown_when_fresh_physical_scope_also_fails(idle):
    rt=runtime();idle.stage();owner=rt.open_native_runtime(idle.service);idle.attach(owner)
    idle.r.fault='timeout'
    with pytest.raises(idle.m.ResourceError):idle.parent.run_case('idle-shrink')
    idle.pairs['vm-a']['memory']['MemAvailable']=0
    with pytest.raises(idle.m.ResourceError)as caught:idle.parent.reconcile()
    assert caught.value.code=='cleanup_evidence'
    mid=idle.parent.repository.read(idle.parent.repository.case_path(OP,'idle-shrink'))['mutation_id']
    assert idle.p.read(mid)['phase']=='CLAIMED'
    assert not idle.parent.repository.readback_path(OP,mid).exists()
    assert idle.parent._catalog(idle.plan,idle.store.load())==[mid]
    assert len(idle.r.calls)==1 and idle.store.state_path.read_bytes()==idle.raw


# Independent R1-R4 reproductions retained as regression checks.


def test_public_report_api_is_callable_after_real_factory(idle):
    rt = runtime()
    idle.stage()
    owner = rt.open_native_runtime(idle.service)
    result = owner.report({'idle-grow': (idle.sample,)})
    assert result['candidate'] is None
    assert result['native_qualification'] == 'NOT_MEASURED'
    assert Path(result['path']).is_file()
    assert idle.store.state_path.read_bytes() == idle.raw
    assert idle.r.calls == []


def test_idle_runtime_rejects_nonempty_final_output_owner(idle):
    rt = runtime()
    report = copy.deepcopy(idle.report)
    report['permit']['context']['output_owner'] = {'completed_final': 'not-an-idle-owner'}
    for case in report['cases'].values():
        for row in case['original_evidence']:
            row['context']['output_owner'] = {'completed_final': 'not-an-idle-owner'}
    idle.stage(report)
    with pytest.raises(idle.m.ResourceError):
        rt.open_native_runtime(idle.service)


def test_primary_gap_contradiction_outside_mapping_subset_is_rejected(idle):
    rt = runtime()
    report = copy.deepcopy(idle.report)
    row = copy.deepcopy(report['cases']['idle-grow']['original_evidence'][0])
    row['sequence'] = 2
    row['readback']['assigned_bytes'] = 128
    row['readback']['configured_bytes'] = 128
    row['total_bytes'] = 96
    row['available_bytes'] = 32
    for field in ('meminfo_bytes', 'meminfo_after_bytes'):
        row['accounting'][field].update(MemTotal=96, MemFree=32, MemAvailable=32)
    row['source_records']['guest']['calibration_accounting'] = copy.deepcopy(row['accounting'])
    row['source_records']['guest']['memory'] = dict(MemTotal=96, MemAvailable=32)
    row['source_records']['native_before'] = copy.deepcopy(row['readback'])
    row['source_records']['native_after'] = copy.deepcopy(row['readback'])
    row['evidence_sha256'] = idle.backends.fingerprint(row['source_records'])
    report['cases']['idle-grow']['original_evidence'].append(row)
    report = idle.observations.build_qualification_report(report['permit'], {'idle-grow': tuple(idle.observations.CalibrationObservation(**raw) for raw in report['cases']['idle-grow']['original_evidence'])})
    idle.stage(report)
    with pytest.raises(idle.m.ResourceError):
        rt.open_native_runtime(idle.service)


def test_physical_failure_preserved_when_retention_snapshot_overflows(idle, monkeypatch):
    rt = runtime()
    idle.stage()
    owner = rt.open_native_runtime(idle.service)
    idle.attach(owner)
    original_run = idle.r.run
    original_pair = idle.provider._calibration_pair
    def run(argv, **kw):
        result = original_run(argv, **kw)
        idle.pairs['vm-a']['memory']['MemAvailable'] = 0
        return result
    def pair(ctx):
        read, guest, source = original_pair(ctx)
        if guest['memory']['MemAvailable'] == 0:
            # Keep the original observation below the existing 1MiB bound.
            # The genuine C witness added by failure capture crosses that bound.
            template = idle.observations.CalibrationObservation(ctx, 1, __import__('dataclasses').asdict(read), guest['memory']['MemTotal'], guest['memory']['MemAvailable'], guest.get('slurm_memory_bytes'), guest.get('slurm_registered'), (), None, 128, None, None, idle.backends.fingerprint(source), guest['calibration_accounting'], source)
            base = len(__import__('json').dumps(idle.observations.plain(template), sort_keys=True, allow_nan=False).encode())
            source['bounded_capture_padding'] = 'x' * (1024**2 - base - 500)
            check = idle.observations.CalibrationObservation(ctx, 1, __import__('dataclasses').asdict(read), guest['memory']['MemTotal'], guest['memory']['MemAvailable'], guest.get('slurm_memory_bytes'), guest.get('slurm_registered'), (), None, 128, None, None, idle.backends.fingerprint(source), guest['calibration_accounting'], source)
            assert len(__import__('json').dumps(idle.observations.plain(check), sort_keys=True, allow_nan=False).encode()) < 1024**2
        return read, guest, source
    monkeypatch.setattr(idle.r, 'run', run)
    monkeypatch.setattr(idle.provider, '_calibration_pair', pair)
    with pytest.raises(idle.m.ResourceError) as caught:
        idle.parent.run_case('idle-shrink')
    assert caught.value.code == 'calibration_physical'
    assert caught.value.native_outcome == 'RETURNED_SUCCESS'
    assert caught.value.physical_status == 'FAIL'
    assert hasattr(caught.value, 'calibration_record_error')
    assert len(idle.r.calls) == 1


@pytest.mark.parametrize('contradiction',['omitted-os-peak','native-below-floor','available-below-margin'])
def test_every_retained_primary_is_checked_even_outside_scope_subsets(idle,contradiction):
    rt=runtime();report=copy.deepcopy(idle.report)
    row=copy.deepcopy(report['cases']['idle-grow']['original_evidence'][0]);row['sequence']=2
    if contradiction=='omitted-os-peak':
        for field in ('meminfo_bytes','meminfo_after_bytes'):row['accounting'][field]['MemFree']=2048-96
        row['accounting']['os_upper_bound_bytes']=96
    if contradiction=='native-below-floor':
        row['readback']['assigned_bytes']=row['readback']['configured_bytes']=64
    if contradiction=='available-below-margin':
        row['available_bytes']=0
        for field in ('meminfo_bytes','meminfo_after_bytes'):row['accounting'][field]['MemAvailable']=0
    row['source_records']['guest']['calibration_accounting']=copy.deepcopy(row['accounting'])
    row['source_records']['guest']['memory']=dict(MemTotal=row['total_bytes'],MemAvailable=row['available_bytes'])
    row['source_records']['native_before']=copy.deepcopy(row['readback']);row['source_records']['native_after']=copy.deepcopy(row['readback'])
    row['evidence_sha256']=idle.backends.fingerprint(row['source_records'])
    rows=(idle.sample,idle.observations.CalibrationObservation(**row))
    report=idle.observations.build_qualification_report(report['permit'],{'idle-grow':rows})
    idle.stage(report)
    with pytest.raises(idle.m.ResourceError):rt.open_native_runtime(idle.service)


def test_idle_builder_rejects_nonempty_output_owner_before_report(idle):
    rt=runtime();raw=idle.observations.plain(idle.sample);raw['context']['output_owner']={'final':'unqualified'}
    observation=idle.observations.CalibrationObservation(**raw)
    with pytest.raises(idle.m.ResourceError):
        rt.build_idle_bootstrap_report((observation,),safety_allowance_bytes=16,native_gap_bound_bytes=16,scope='synthetic explicit scope')


@pytest.mark.parametrize('fault',['confirmed-record','proof','writer'])
def test_secondary_failure_capture_preserves_original_physical_error(idle,monkeypatch,fault):
    rt=runtime();idle.stage();owner=rt.open_native_runtime(idle.service)
    idle.attach(owner)
    original_run=idle.r.run
    def run(argv,**kw):
        result=original_run(argv,**kw);idle.pairs['vm-a']['memory']['MemAvailable']=0
        return result
    monkeypatch.setattr(idle.r,'run',run)
    original_failure=owner._physical_failure
    def fail_during_capture(error,state,originals,**kwargs):
        if fault=='confirmed-record':monkeypatch.setattr(owner.parent,'_confirmed',lambda *args:(_ for _ in()).throw(OSError('secondary confirmed record')))
        if fault=='proof':monkeypatch.setattr(owner.parent,'_proof',lambda *args:(_ for _ in()).throw(OSError('secondary proof')))
        if fault=='writer':monkeypatch.setattr(owner.repository,'exclusive',lambda *args:(_ for _ in()).throw(OSError('secondary writer')))
        return original_failure(error,state,originals,**kwargs)
    monkeypatch.setattr(owner,'_physical_failure',fail_during_capture)
    with pytest.raises(idle.m.ResourceError)as caught:idle.parent.run_case('idle-shrink')
    assert caught.value.code=='calibration_physical' and caught.value.physical_status=='FAIL'
    assert hasattr(caught.value,'calibration_record_error') and len(idle.r.calls)==1
    if fault=='writer':assert caught.value.native_outcome=='RETURNED_SUCCESS'
