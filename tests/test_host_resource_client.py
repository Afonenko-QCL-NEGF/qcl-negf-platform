from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops'))


def test_demand_exact_no_paths_flags_argv_or_client_identity():
    from host_resource_client import decode_native_demand,decode_native_ref
    doc={'schema':'qcl.host-resource-native-demand.v1','workload':{'kind':'slurm_allocation','native_id':'42'},'workload_bytes':321}
    assert decode_native_demand(doc).workload.native_id=='42'
    for key,value in [('path','/tmp/proof'),('host_id','host'),('request_id','made-up'),('qualification',True),('argv',['bad'])]:
        with pytest.raises(Exception):decode_native_demand({**doc,key:value})
    for amount in [True,0,-1,1.2]:
        with pytest.raises(Exception):decode_native_demand({**doc,'workload_bytes':amount})
    with pytest.raises(Exception):decode_native_ref({'kind':'slurm_allocation','native_id':'42','generation':'fake'})


def test_launch_gate_only_admission_no_exec_and_exit_codes():
    from host_resource_client import exit_code
    assert exit_code({'admission':'ready','phase':'RUN'},gate=True)==0
    assert exit_code({'admission':'resource_wait','phase':'HOST_GRANT'},gate=True)==75
    assert exit_code({'admission':'reconciliation_required','phase':'GROW_UNKNOWN'},gate=True)==78
    assert exit_code({'admission':'ready','phase':'GUEST_ADMIT'},gate=True)==78


def test_installed_package_isolated_imports_shared_p11_engine_and_fixed_roles(tmp_path):
    import shutil,subprocess
    root=Path(__file__).resolve().parents[1]
    files=['application_release','runtime_bindings','release_identity','release_trust','release_qualification','release_health',
        'host_resource_policy','host_resource_operations','host_resource_backends','host_resource_facts',
        'host_resource_startup','host_resource_service','host_resource_client','host_resource_projection']
    for name in files:shutil.copyfile(root/'ops'/(name+'.py'),tmp_path/(name+'.py'))
    script='import sys;sys.path.insert(0,sys.argv[1]);import host_resource_service as s;import host_resource_backends as b;import application_release as a;assert b.release_commands.command is a.command'
    result=subprocess.run([sys.executable,'-I','-c',script,str(tmp_path)],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    package=(root/'nix/host-resources.nix').read_text()
    for name in files:assert '../ops/'+name+'.py' in package
    assert 'python3 -I' in package and 'resource-client-root' in package
    # The fixed forced-SSH Python entry must remain the live sudo parent.
    # Only its finite wait leaf may spawn a child; client/routing/root APIs do
    # not acquire another arbitrary launcher or supervisor.
    import ast
    tree=ast.parse((root/'ops/host_resource_service.py').read_text())
    functions={node.name:node for node in tree.body if isinstance(node,ast.FunctionDef)}
    leaf=functions['_wait_ssh_helper'];ssh=functions['ssh_main']
    calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call)]
    spawns=[node for node in calls if (isinstance(node.func,ast.Attribute) and node.func.attr in
        {'Popen','popen','execvp','execve','spawnv','spawnve'}) or
        (isinstance(node.func,ast.Name) and node.func.id=='Popen')]
    assert len(spawns)==1 and spawns[0] in set(ast.walk(leaf))
    spawn=spawns[0]
    assert ast.unparse(spawn.func)=='subprocess.Popen' and [ast.unparse(arg) for arg in spawn.args]==['argv']
    assert {kw.arg:ast.literal_eval(kw.value) for kw in spawn.keywords}=={'shell':False,'start_new_session':True}
    parents={child:node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    current=spawn
    while current is not leaf:
        current=parents[current]
        assert not isinstance(current,(ast.For,ast.AsyncFor,ast.While,ast.comprehension))
    waits=[node for node in calls if isinstance(node.func,ast.Name) and node.func.id=='_wait_ssh_helper']
    assert len(waits)==1 and waits[0] in set(ast.walk(ssh)) and not waits[0].keywords
    assert len(waits[0].args)==1 and isinstance(waits[0].args[0],ast.List)
    fixed=waits[0].args[0].elts
    assert [ast.literal_eval(arg) for arg in fixed[:2]]==['sudo','-n']
    assert [ast.unparse(arg) for arg in fixed[2:]]==['executable','action','token']


def test_status_route_never_resolves_scheduler_or_refreshes_native_facts(monkeypatch):
    import host_resource_service as s
    import host_resource_client as c
    calls=[]
    def rpc(route,action,document,**kw):
        calls.append(action)
        return s.operation_view(c.NativeWorkloadRef('slurm_allocation','42'))
    monkeypatch.setattr(s,'trusted_rpc',rpc)
    config={'role':'controller','host_routes':{'node-a':{'target':'one'},'node-b':{'target':'one'}}}
    doc={'schema':'qcl.host-resource-native-reference.v1','workload':{'kind':'slurm_allocation','native_id':'42'}}
    assert s.route_public(config,'status',doc,{})['phase']=='NOT_INITIALIZED'
    assert calls==['status']


def test_malformed_bounded_cli_input_returns_public_json_without_traceback(monkeypatch,capsys):
    import io,json
    import host_resource_client as c
    from types import SimpleNamespace
    monkeypatch.setattr(sys,'stdin',SimpleNamespace(buffer=io.BytesIO(b'{bad')))
    assert c.main(['request','--json-stdin'])==78
    result=json.loads(capsys.readouterr().out)
    assert result['schema']=='qcl.host-resource-operation.v1' and result['workload'] is None
    assert result['admission']=='rejected' and result['failure_code']=='shape'


@pytest.mark.parametrize('role', ['authority','facts'])
def test_privileged_service_rejects_role_uid_alias_to_job_user_before_source_reads(role):
    from host_resource_service import validate_service_config
    config={'schema':'qcl.host-resource-service.v1','role':'native_host','client_uid':3000,role+'_uid':3000}
    with pytest.raises(Exception):validate_service_config(config)


def test_public_dto_exports_match_exact_schemas():
    import json
    from host_resource_client import ResourceOperationView
    from host_resource_startup import StartupReservationView
    root=Path(__file__).resolve().parents[1]/'schemas'
    for cls,name in [(ResourceOperationView,'operation'),(StartupReservationView,'startup')]:
        schema=json.loads((root/('host-resource-native-'+name+'.schema.json')).read_text())
        assert set(cls.__required_keys__)==set(schema['required'])==set(schema['properties'])


def test_unhashable_kind_and_incomplete_ready_response_are_rejected():
    from host_resource_client import decode_native_ref,validate_operation_view
    with pytest.raises(Exception):decode_native_ref({'kind':[],'native_id':'42'})
    with pytest.raises(Exception):validate_operation_view({'schema':'qcl.host-resource-operation.v1','phase':'RUN','admission':'ready'})


def test_ready_dto_requires_fresh_complete_charge_and_native_identity(tmp_path):
    from host_resource_client import validate_operation_view
    from test_host_resource_service import service
    s,d,*_=service(tmp_path);view=s.request_native(d)
    assert validate_operation_view(view)['admission']=='ready'
    for key in ['request_id','native_generation','host_id','vm_id','charged_bytes','protected_floor_bytes']:
        with pytest.raises(Exception):validate_operation_view({**view,key:None})
    with pytest.raises(Exception):validate_operation_view({**view,'native_freshness':{'status':'stale','observed_at':100}})
