from dataclasses import asdict
from pathlib import Path
import json
import os
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops'))
from test_host_resource_operations import setup,request


def test_projection_absent_never_creates_paths(tmp_path):
    from host_resource_projection import ResourceProjection
    path=tmp_path/'absent';view=ResourceProjection(path,owner_uid=os.getuid(),clock=lambda:100).read()
    assert view['status']=='not_initialized' and view['host'] is None and not path.exists()


def test_projection_nulls_cursor_bounds_no_writes_or_paths_and_pending_preserved(tmp_path):
    from host_resource_projection import ResourceProjection
    m,c,b,store,e=setup(tmp_path);c.request(request(m),e)
    state=store.load();state['receipts'][0]['native_workload']={'kind':'slurm_allocation','native_id':'42','generation':'g42'};store.save(state)
    before={str(p):(p.stat().st_mtime_ns,p.read_bytes()) for p in store.directory.rglob('*') if p.is_file()}
    projection=ResourceProjection(store.directory,policy=c.policy,owner_uid=os.getuid(),clock=lambda:100)
    view=projection.read(limit=1)
    assert view['operations'][0]['phase']=='HOST_GRANT' and view['operations'][0]['current_assigned_bytes'] is None
    assert view['vms'][0]['cpu']['online_vcpus'] is None
    assert str(tmp_path) not in json.dumps(view) and 'synthetic-agreement' not in json.dumps(view)
    assert before=={str(p):(p.stat().st_mtime_ns,p.read_bytes()) for p in store.directory.rglob('*') if p.is_file()}
    with pytest.raises(Exception):projection.read(limit=129)
    # Cursor is immutable generation, never mixed across changing state.
    state['receipts'].append({**state['receipts'][0],'request':asdict(request(m,'request-2','work-2',vm='vm-b')),'phase':'RUN'})
    state['grants'][1]['guest_bytes']=512;state['grants'][1]['state']='active';state['grants'][1]['active_floor_bytes']=449
    store.save(state);page=projection.read(limit=1)
    assert not page['complete'] and page['next_cursor']
    second=projection.read(limit=1,cursor=page['next_cursor']);assert second['complete']
    state['blocked']='private diagnostic /secret';store.save(state)
    with pytest.raises(m.ResourceError,match='stale_cursor'):projection.read(limit=1,cursor=page['next_cursor'])


def test_v2_projection_read_only_upgrade_required(tmp_path):
    from host_resource_projection import ResourceProjection
    m,c,b,store,e=setup(tmp_path);state=store.load();state['schema']='qcl.host-resource-state.v2';store.save(state)
    before=store.state_path.read_bytes()
    assert ResourceProjection(store.directory,owner_uid=os.getuid()).read()['status']=='upgrade_required'
    assert store.state_path.read_bytes()==before


def test_public_schemas_examples_and_unmapped_charged_row_never_invent_native_id(tmp_path):
    import jsonschema
    from host_resource_projection import ResourceProjection
    root=Path(__file__).resolve().parents[1]
    for example in (root/'examples').glob('host-resource-native-*.json'):
        schema=root/'schemas'/(example.stem+'.schema.json')
        jsonschema.validate(json.loads(example.read_text()),json.loads(schema.read_text()))
    m,c,b,store,e=setup(tmp_path);c.request(request(m),e)
    result=ResourceProjection(store.directory,policy=c.policy,owner_uid=os.getuid()).read()
    view=result['operations'][0]
    assert view['workload'] is None and view['admission']=='reconciliation_required'
    assert view['request_id']=='request-1' and view['charged_bytes']==512
    jsonschema.validate(result,json.loads((root/'schemas/host-resource-native-projection.schema.json').read_text()))
