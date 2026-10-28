"""Public resource DTO survives polling intact; native observations are separate."""
import copy
import json
from pathlib import Path

import pytest

from test_monitoring_runtime import config, module, ROOT


def resource():
    return json.loads((ROOT / 'examples/host-resource-native-projection.json').read_text())


def packet(host='host-a'):
    m = module('native_monitoring')
    native = m.empty_native(host, observed_at=80)
    # Closed healthy literal sample; empty/not_measured is not a fresh source.
    native.update(host_boot_id='boot-synthetic', sample_generation='sample-synthetic',
                  host_memory=dict(total_bytes=33554432, available_bytes=16777216))
    native['coverage'].update(status='fresh', complete=True, host_boot_id='boot-synthetic',
                              generation='sample-synthetic', reasons=[])
    return {'resource': resource(), 'native': native, 'services': [],
            'storage': module('monitoring_runtime').unknown_storage(80)}


def target(host):
    return {'host_id': host, 'target': 'monitor@' + host + '.invalid',
            'helper': '/fixed/qcl-negf-monitor-rpc', 'known_hosts': '/protected/known_hosts',
            'identity_file': '/protected/key'}


def test_read_time_is_not_native_time_and_resource_dto_is_not_rewritten():
    m = module('cluster_projection'); c = config('controller'); c['targets'] = [target('host-a')]
    sample = packet(); original = copy.deepcopy(sample['resource']); calls = []
    def observe(t, query): calls.append(query); return copy.deepcopy(sample)
    p = m.ClusterProjection(c, observe, clock=lambda: 100)
    first = p.read(); second = p.read()
    assert first['read_at'] == 100 and first['hosts'][0]['native']['observed_at'] == 80
    assert first['hosts'][0]['resource'] == original == second['hosts'][0]['resource']
    assert first['hosts'][0]['native']['coverage']['status'] == 'stale'
    assert first['hosts'][0]['storage']['persist_permitted'] is False
    assert len(calls) == 2 and set(calls[0]) == {'schema', 'request_id', 'cursor', 'limit'}
    assert m.validate_cluster_projection(first) == first


def test_observer_failure_and_unsupported_storage_do_not_block_other_hosts():
    m = module('cluster_projection'); c = config('controller')
    c['targets'] = [target('host-a'), target('host-b')]
    def observe(t, q):
        if t['host_id'] == 'host-a': raise TimeoutError('secret transport detail')
        return packet('host-b')
    view = m.ClusterProjection(c, observe, clock=lambda: 100).read()
    assert view['status'] == 'partial' and len(view['hosts']) == 2
    assert view['hosts'][0]['resource'] is None
    assert 'secret transport' not in json.dumps(view)
    assert view['hosts'][1]['resource'] == resource()


def test_bounded_host_cursor_rejects_changed_registry_and_never_accepts_paths():
    m = module('cluster_projection'); c = config('controller')
    c['targets'] = [target('host-a'), target('host-b')]
    p = m.ClusterProjection(c, lambda t, q: packet(t['host_id']), clock=lambda: 100)
    page = p.read(limit=1); assert page['next_cursor'] and not page['complete']
    assert p.read(limit=1, cursor=page['next_cursor'])['complete']
    changed = copy.deepcopy(c); changed['targets'].append(target('host-c'))
    with pytest.raises(ValueError, match='stale_cursor'):
        m.ClusterProjection(changed, lambda t, q: packet(), clock=lambda: 100).read(cursor=page['next_cursor'])
    for query in [{'path': '/private/receipt'}, {'limit': 129}]:
        with pytest.raises((ValueError, TypeError)): p.read(**query)


def test_schema_does_not_turn_missing_or_boolean_memory_into_zero():
    m = module('cluster_projection'); c = config('controller'); c['targets'] = [target('host-a')]
    view = m.ClusterProjection(c, lambda t, q: packet(), clock=lambda: 100).read()
    bad = copy.deepcopy(view); bad['hosts'][0]['native']['host_memory']['total_bytes'] = False
    with pytest.raises(ValueError): m.validate_cluster_projection(bad)


def test_nested_cursor_pins_both_owner_and_native_generation():
    m = module('cluster_projection'); c = config('controller'); c['targets'] = [target('host-a')]
    value = packet(); value['native']['sample_generation'] = 'sample-1'
    value['resource'].update(state_generation='state-1', complete=False, next_cursor='opaque-B-token')
    calls = []
    def observe(t, q):
        calls.append(q)
        return copy.deepcopy(value)
    p = m.ClusterProjection(c, observe, clock=lambda: 100)
    first = p.read(limit=1)
    value['resource'].update(complete=True, next_cursor=None)
    assert p.read(limit=1, cursor=first['next_cursor'])['complete']
    assert calls[-1]['cursor'] == 'opaque-B-token'
    value['native']['sample_generation'] = 'sample-2'
    with pytest.raises(ValueError, match='stale_cursor'): p.read(cursor=first['next_cursor'])
    value['native']['sample_generation'] = 'sample-1'; value['resource']['state_generation'] = 'state-2'
    with pytest.raises(ValueError, match='stale_cursor'): p.read(cursor=first['next_cursor'])


def test_malformed_host_is_partial_and_budget_never_relays_large_output():
    m = module('cluster_projection'); c = config('controller'); c['targets'] = [target('host-a'), target('host-b')]
    def observe(t, q):
        value = packet(t['host_id'])
        if t['host_id'] == 'host-a': value['native']['host_memory']['total_bytes'] = False
        return value
    view = m.ClusterProjection(c, observe, clock=lambda: 100).read()
    assert view['status'] == 'partial' and view['hosts'][0]['native'] is None and view['hosts'][1]['native']
    c['targets'] = [target('host-a')]; c['bounds']['output_bytes'] = 16384
    value = packet(); value['native']['oom']['events'] = []
    # Service rows are valid individually but the aggregate response exceeds its bound.
    cov = module('native_monitoring').coverage('svc')
    service = dict(service_id='svc', active_state=None, sub_state=None, result=None,
                   invocation_id=None, observed_at=None, coverage=cov)
    value['services'] = [copy.deepcopy(service) for _ in range(128)]
    with pytest.raises(ValueError, match='output_bound'):
        m.ClusterProjection(c, lambda t, q: value, clock=lambda: 100).read()


def test_local_observer_only_calls_public_b_read_and_reads_cache(monkeypatch, tmp_path):
    runtime = module('monitoring_runtime'); import host_resource_projection
    c = config(); calls = []; sentinel = tmp_path / 'unrelated'; sentinel.write_text('keep')
    monkeypatch.setattr(runtime, 'load_config', lambda: c)
    monkeypatch.setattr(runtime, 'read_cache', lambda c: None)
    def public_read(**query): calls.append(query); return resource()
    monkeypatch.setattr(host_resource_projection, 'read_resource_projection', public_read)
    def forbidden(*a, **kw): raise AssertionError('poll must not probe/write/refresh storage')
    monkeypatch.setattr(runtime.StorageBoundary, 'read', forbidden)
    monkeypatch.setattr(runtime, 'sample_native_status', forbidden)
    query = dict(schema='qcl.cluster-query.v1', request_id='request-1', cursor=None, limit=2)
    before = sorted(tmp_path.iterdir())
    for _ in range(3):
        view = runtime.observe_local(query)
        assert view['resource'] == resource() and view['storage']['persist_permitted'] is False
    assert calls == [dict(request_id='request-1', cursor=None, limit=2)]*3
    assert sorted(tmp_path.iterdir()) == before and sentinel.read_text() == 'keep'


def test_production_cluster_read_and_cached_pagination_never_fetch_observer(monkeypatch):
    runtime=module('monitoring_runtime'); m=module('cluster_projection')
    from slurm_context import empty_context
    c=config('controller');c['targets']=[target('host-a')]
    first=packet();first['resource'].update(state_generation='b-gen',complete=False,next_cursor='b-next')
    second=copy.deepcopy(first);second['resource'].update(complete=True,next_cursor=None)
    cache=dict(sampler_boot_id='controller-boot',current_context=empty_context(c,now=100),host_packets=[dict(host_id='host-a',fetched_at=95,
        pages=[dict(cursor=None,packet=first),dict(cursor='b-next',packet=second)])])
    monkeypatch.setattr(runtime,'load_config',lambda:c)
    monkeypatch.setattr(runtime,'read_cache',lambda c:copy.deepcopy(cache))
    def forbidden(*a,**k):raise AssertionError('public read cannot run observer RPC/probe')
    monkeypatch.setattr(runtime,'observe_remote',forbidden)
    monkeypatch.setattr(runtime,'sample_native_status',forbidden)
    monkeypatch.setattr(m.time,'time',lambda:100)
    view=m.read_cluster_projection(limit=1)
    assert view['next_cursor'] and view['hosts'][0]['resource']==first['resource']
    result=m.read_cluster_projection(cursor=view['next_cursor'],limit=1)
    assert result['complete'] and result['hosts'][0]['resource']==second['resource']
    assert result['hosts'][0]['native']['observed_at']==80
    assert any(cov['observed_at']==95 for cov in result['coverage']['sources'])
    cache['host_packets'][0]['pages']=cache['host_packets'][0]['pages'][:1]
    partial=m.read_cluster_projection(limit=1)
    assert not partial['complete'] and partial['next_cursor'] is None
    assert any(r['code']=='resource_snapshot_partial' for r in partial['hosts'][0]['reasons'])
    assert m.read_cluster_projection(request_id='not-cached')['hosts'][0]['resource'] is None


def test_missing_controller_packet_is_unknown_not_zero_or_fresh(monkeypatch):
    runtime=module('monitoring_runtime');m=module('cluster_projection')
    c=config('controller');c['targets']=[target('host-a')]
    monkeypatch.setattr(runtime,'load_config',lambda:c);monkeypatch.setattr(runtime,'read_cache',lambda c:None)
    def forbidden(*a,**k):raise AssertionError('native read from public query')
    monkeypatch.setattr(runtime,'observe_remote',forbidden)
    v=m.read_cluster_projection()
    assert v['status']=='unknown' and v['hosts'][0]['native'] is None
    assert v['hosts'][0]['resource'] is None and v['hosts'][0]['reasons']


def test_existing_controller_sampler_fetches_bounded_pages_and_writes_only_owned_cache(monkeypatch,tmp_path):
    runtime=module('monitoring_runtime');import release_trust,contextlib,os,time
    from slurm_context import empty_context
    c=config('controller');c['targets']=[target('host-a')]
    first=packet();first['resource'].update(state_generation='one',complete=False,next_cursor='next')
    second=copy.deepcopy(first);second['resource'].update(state_generation='drift',complete=True,next_cursor=None)
    calls=[]
    class Sources:
        deadline=time.monotonic()+30
        bytes=0
        def read(self,path,**kw):return 'controller-boot' if path.endswith('/boot_id') else '1'*32
    source=Sources()
    def fetch(target,query,**kwargs):
        calls.append(query)
        assert kwargs['sources'] is source
        return copy.deepcopy(first if query['cursor'] is None else second)
    monkeypatch.setattr(runtime,'load_config',lambda:c)
    monkeypatch.setattr(runtime,'NativeSources',lambda cfg:source)
    monkeypatch.setattr(runtime,'read_cache',lambda cfg:None)
    monkeypatch.setattr(runtime,'observe_remote',fetch)
    monkeypatch.setattr(runtime.os,'geteuid',lambda:0)
    monkeypatch.setattr(runtime,'CACHE',tmp_path/'latest.json')
    @contextlib.contextmanager
    def protected(path):
        assert Path(path)==tmp_path
        fd=os.open(tmp_path,os.O_RDONLY|os.O_DIRECTORY)
        try:yield fd
        finally:os.close(fd)
    monkeypatch.setattr(release_trust,'protected_directory',protected)
    sentinel=tmp_path/'foreign';sentinel.write_text('keep')
    runtime.sample_native_status()
    saved=json.loads((tmp_path/'latest.json').read_text())
    assert len(calls)==2 and len(saved['host_packets'][0]['pages'])==1
    assert saved['sampler_boot_id']=='controller-boot'
    assert saved['host_packets'][0]['pages'][0]['packet']['native']['observed_at']==80
    assert saved['current_context']['status']=='disabled' and sentinel.read_text()=='keep'
    assert {p.name for p in tmp_path.iterdir()}=={'foreign','latest.json'}


def test_fresh_context_does_not_hide_unknown_host_or_enabled_context_failure():
    from test_slurm_context import context_config,Sources
    from slurm_context import sample_current_context
    m=module('cluster_projection');c=context_config();c['targets']=[target('host-a')]
    s=Sources();s.queue='';context=sample_current_context(c,s,None,now=100)
    def missing(*a,**kw):raise ValueError('missing host')
    view=m.ClusterProjection(c,missing,current_context=context,clock=lambda:100).read()
    assert view['status']=='partial' and view['hosts'][0]['native'] is None
    c['targets']=[]
    assert m.ClusterProjection(c,missing,current_context=context,clock=lambda:100).read()['status']=='ok'
