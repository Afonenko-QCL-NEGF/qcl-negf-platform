"""Current-only literal Slurm RPC fixtures. No scheduler executable is run."""
import copy
import importlib
import json
from pathlib import Path
import sys
import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / 'ops'))
from test_monitoring_runtime import config


def subject():
    assert (ROOT / 'ops/slurm_context.py').exists(), 'missing real current-context source'
    return importlib.import_module('slurm_context')


def context_config():
    c = config('controller')
    c['tools'].update(scontrol='/usr/bin/scontrol', squeue='/usr/bin/squeue')
    c['context'] = dict(enabled=True, cluster_id='fixture-cluster', owner_uids=[2001],
        slurm_conf='/etc/slurm/slurm.conf', version_profile='25.11.8')
    return c


class Sources:
    def __init__(self):
        self.version = 'slurm 25.11.8\n'
        self.configuration = 'ClusterName = fixture-cluster\nAuthInfo = SECRET_SENTINEL\n'
        self.queue = '17|2001|RUNNING|None|node-a\n18_2|2001|PENDING|Resources|(null)\n'
        self.detail = ('JobId=17 UserId=fixture(2001) JobState=RUNNING NumCPUs=4 NodeList=node-a '
            'SubmitTime=2026-10-28T10:00:00 StartTime=2026-10-28T10:01:00 Restarts=0 MinMemoryNode=512\n')
        self.calls = []
    def trusted_config_identity(self,path):
        assert path=='/etc/slurm/slurm.conf'
        return (1,2,3,4,5)
    def read(self, path, **kw):
        if path.endswith('/boot_id'): return 'boot-a'
        if path == '/etc/machine-id': return '1'*32
        raise AssertionError('unexpected native read: '+path)
    def run(self, argv, **kw):
        self.calls.append((argv, kw))
        if argv[1:] == ['--version']: return self.version
        if argv[1:] == ['show', 'config']: return self.configuration
        if argv[0].endswith('/squeue'): return self.queue
        if argv[1:] == ['--oneliner', 'show', 'job', '17']: return self.detail
        raise AssertionError('unexpected current-only command: '+repr(argv))


def test_current_context_uses_actual_selected_rpc_and_filters_identity_before_output():
    m = subject(); source = Sources()
    view = m.sample_current_context(context_config(), source, None, now=1793185200)
    assert view['schema'] == 'qcl.current-context.v1' and view['status'] == 'partial'
    assert view['cluster_id'] == 'fixture-cluster' and view['observed_at'] == 1793185200
    assert 'SECRET' not in json.dumps(view)
    assert view['jobs'][0]['requested_memory'] == dict(per_node_bytes=536870912, per_cpu_bytes=None)
    assert view['jobs'][0]['state'] == 'running' and view['jobs'][1]['job_id'] == '18_2'
    assert view['jobs'][1]['generation'] is None
    assert source.calls[0][0] == ['/usr/bin/scontrol', '--version']
    assert source.calls[1][0] == ['/usr/bin/scontrol', 'show', 'config']
    assert source.calls[2][0] == ['/usr/bin/squeue', '--local', '--array', '--noheader', '--states=all',
        '--user=2001', '--format=%i|%U|%T|%r|%N']
    assert all('--all' not in argv and 'sacct' not in argv[0] for argv,_ in source.calls)


@pytest.mark.parametrize('broken', ['wrong_version','wrong_cluster','duplicate','failure'])
def test_identity_failure_never_runs_queue_or_leaks_config(broken):
    m=subject(); s=Sources()
    if broken=='wrong_version': s.version='slurm 25.11.9'
    if broken=='wrong_cluster': s.configuration='ClusterName = other\nSecret = SECRET_SENTINEL'
    if broken=='duplicate': s.configuration='ClusterName = fixture-cluster\nClusterName = fixture-cluster'
    if broken=='failure':
        from application_release import CommandFailure
        def failed(*a,**k): raise CommandFailure(dict(failure='timeout',stdout='SECRET_SENTINEL',stderr='SECRET_SENTINEL'))
        s.run=failed
    result=m.sample_current_context(context_config(),s,None,now=100)
    assert result['status'] in ('unknown','unsupported') and result['jobs']==[]
    assert not any(argv[0].endswith('squeue') for argv,_ in s.calls)
    assert 'SECRET' not in json.dumps(result)


def test_clean_empty_is_fresh_failure_preserves_observation_and_disabled_has_no_rpc():
    m=subject(); s=Sources(); s.queue=''
    prior=m.sample_current_context(context_config(),s,None,now=100)
    assert prior['status']=='fresh' and prior['jobs']==[] and prior['complete']
    def failed(*a,**k): raise ValueError('SECRET')
    s.run=failed
    view=m.sample_current_context(context_config(),s,prior,now=110)
    assert view['status']=='unknown' and view['observed_at']==100 and 'SECRET' not in json.dumps(view)
    c=context_config(); c['context']['enabled']=False
    assert m.sample_current_context(c,s,None,now=110)['status']=='disabled'


def test_current_detail_reuse_and_foreign_uid_fail_closed():
    m=subject(); s=Sources(); s.queue='17|2002|RUNNING|None|node-a\n'
    view=m.sample_current_context(context_config(),s,None,now=100)
    assert view['status']=='unknown' and view['jobs']==[]
    s=Sources(); s.detail=s.detail.replace('JobId=17','JobId=19')
    view=m.sample_current_context(context_config(),s,None,now=100)
    assert view['jobs'][0]['generation'] is None and view['status']=='partial'


def test_context_cache_read_only_pagination_fresh_stale_future(monkeypatch):
    m=subject(); import monitoring_runtime as runtime
    s=Sources(); v=m.sample_current_context(context_config(),s,None,now=100)
    cache=dict(current_context=v)
    monkeypatch.setattr(runtime,'load_config',context_config)
    monkeypatch.setattr(runtime,'read_cache',lambda c: copy.deepcopy(cache))
    monkeypatch.setattr(m.time,'time',lambda:105)
    a=m.read_current_context(limit=1)
    assert a['read_at']==105 and a['observed_at']==100 and a['next_cursor']
    b=m.read_current_context(cursor=a['next_cursor'],limit=1)
    assert b['jobs'][0]['job_id']=='18_2' and cache['current_context']==v
    monkeypatch.setattr(m.time,'time',lambda:120)
    assert m.read_current_context()['status']=='stale'
    monkeypatch.setattr(m.time,'time',lambda:90)
    assert m.read_current_context()['status']=='unknown'
    cache['current_context']['sample_generation']='different'
    with pytest.raises(ValueError,match='stale_cursor'): m.read_current_context(cursor=a['next_cursor'])


def test_real_p11_source_filters_config_and_uses_exact_slurm_environment(monkeypatch):
    m=subject();import monitoring_runtime as runtime
    import application_release as engine
    c=context_config();fixture=Sources();calls=[]
    monkeypatch.setattr(runtime,'validate_tool',lambda p:None)
    monkeypatch.setattr(runtime.NativeSources,'read',lambda self,path,**kw:fixture.read(path,**kw))
    monkeypatch.setattr(runtime.NativeSources,'trusted_config_identity',lambda self,path:fixture.trusted_config_identity(path))
    def command(argv,**kw):
        calls.append((argv,kw));raw=fixture.run(argv)
        output=engine.CommandOutput(raw);output.output_bytes=len(output.encode())+3
        return output
    monkeypatch.setattr(engine,'command',command)
    source=runtime.NativeSources(c)
    v=m.sample_current_context(c,source,None,now=1793185200)
    assert v['jobs'] and 'SECRET' not in json.dumps(v)
    assert all(kw['env']==dict(PATH='/usr/bin:/bin',LC_ALL='C',LANG='C',TZ='UTC',SLURM_TIME_FORMAT='standard',SLURM_CONF='/etc/slurm/slurm.conf') for _,kw in calls)
    assert source.bytes==sum(len(fixture.run(argv).encode())+3 for argv,_ in list(calls))
    record=dict(failure='timeout',returncode=1,stdout='ClusterName = fixture-cluster SECRET_SENTINEL',stderr='SECRET_SENTINEL',output_bytes=80)
    def failed(*a,**kw):raise engine.CommandFailure(record)
    monkeypatch.setattr(engine,'command',failed)
    v=m.sample_current_context(c,runtime.NativeSources(c),v,now=1793185210)
    assert v['status']=='unknown' and v['observed_at']==1793185200 and 'SECRET' not in json.dumps(v)


def test_context_fixed_main_uses_reader_identity_and_rejects_extra_request(monkeypatch,capsys):
    m=subject();import monitoring_runtime as runtime
    c=context_config();seen=[]
    monkeypatch.setattr(runtime,'load_config',lambda:c)
    monkeypatch.setattr(runtime,'validate_tool',lambda p:None)
    monkeypatch.setattr(runtime,'authenticate',lambda *args:seen.append(args[-1]))
    monkeypatch.setattr(m,'read_current_context',lambda **kw:m.empty_context(c,now=100))
    token=runtime.encode_query(dict(schema='qcl.cluster-query.v1',request_id=None,cursor=None,limit=1))
    monkeypatch.setattr(sys,'argv',['helper',token])
    assert runtime.main('context')==0 and seen==[c['reader_uid']]
    assert json.loads(capsys.readouterr().out)['schema']=='qcl.current-context.v1'
    token=runtime.encode_query(dict(schema='qcl.cluster-query.v1',request_id='forbidden',cursor=None,limit=1))
    monkeypatch.setattr(sys,'argv',['helper',token])
    assert runtime.main('context')==1
    assert 'monitoring_unavailable' in capsys.readouterr().err
    c['role']='native_host';monkeypatch.setattr(sys,'argv',['helper'])
    assert runtime.main('context')==1


def test_current_context_observer_budget_is_not_a_job_or_lifetime_limit():
    m=subject();s=Sources();s.queue=''.join(str(i)+'|2001|PENDING|Resources|(null)\n' for i in range(1,131))
    v=m.sample_current_context(context_config(),s,None,now=100)
    assert len(v['jobs'])==128 and v['status']=='partial' and not v['complete']
    assert len([argv for argv,kw in s.calls if argv[1:4]==['--oneliner','show','job']])==32
    assert not any('sacct' in argv[0] or argv[1:]==['show','jobs'] for argv,kw in s.calls)
    s=Sources();s.queue='17|2001|RUNNING|None|node-a\n'
    s.detail=s.detail.replace('MinMemoryNode=512','MinMemoryCPU=512')
    v=m.sample_current_context(context_config(),s,None,now=1793185200)
    assert v['jobs'][0]['requested_memory']==dict(per_node_bytes=None,per_cpu_bytes=536870912)
    def changed(path):
        if not hasattr(s,'identity_calls'):s.identity_calls=0
        s.identity_calls+=1
        return s.identity_calls
    s.trusted_config_identity=changed
    assert m.sample_current_context(context_config(),s,v,now=1793185210)['status']=='unknown'


def test_native_zero_memory_is_not_reported_as_zero_byte_request():
    m=subject();s=Sources();s.queue='17|2001|RUNNING|None|node-a\n'
    s.detail=s.detail.replace('MinMemoryNode=512','MinMemoryNode=0')
    v=m.sample_current_context(context_config(),s,None,now=1793185200)
    assert v['jobs'][0]['requested_memory']==dict(per_node_bytes=None,per_cpu_bytes=None)
    assert v['status']=='partial' and v['jobs'][0]['coverage']['reasons'][0]['code']=='slurm_memory_all_node'
