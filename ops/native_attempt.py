"""One ordinary Slurm attempt owner. Operational evidence never accepts science.

Production entry points construct their own native readers. The Python constructor
seams are for SOURCE/L fixtures; passing a dictionary or an instance is no authority.
There is no retry worker, cancellation, profile bootstrap or scientific decoder.
"""
from contextlib import contextmanager
import base64
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import struct
import sys
import time
import uuid

import application_release as engine
from host_resource_backends import trusted_root_path
from host_resource_operations import ResourceError, strict_json
from release_trust import protected_directory, trusted_stat

POLICY = Path('/etc/qcl-negf/native-attempt/policy.json')
SOCKET = '/run/qcl-negf/native-attempt.sock'
FILES = {'plan': 'plan.json', 'source_graph': 'source-graph.json',
         'native_execution': 'native-execution.json', 'submit_script': '_aiidasubmit.sh'}
CLOSE_FILES = ('series_result.json', 'native-selection.json', '_scheduler-stdout.txt', '_scheduler-stderr.txt')
TECHNICAL_FILE = 'performance-source.json'
TECHNICAL_LIMIT = 1048576
ID = r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}'
SHA = r'[0-9a-f]{64}'
JOB = r'[1-9][0-9]{0,9}'
LIMIT_KEYS = {'request_bytes', 'response_bytes', 'script_bytes', 'metadata_bytes', 'memory_bytes',
              'operation_seconds', 'command_seconds', 'cleanup_seconds', 'maximum_pids',
              'maximum_calls', 'maximum_files'}
POLICY_KEYS = {'schema', 'role', 'private_root', 'spool_root', 'socket_path', 'jobs_root',
               'native_result_prefix', 'nfs_source', 'storage_identity_file', 'release_runtime',
               'client_uid', 'daemon_unit', 'server_unit_prefix', 'slurmd_unit', 'tools', 'slurm',
               'facts_service_config', 'worker_routes', 'qualification_file', 'limits'}


class Hold(RuntimeError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def need(condition, reason='shape'):
    if not condition:
        raise Hold(reason)


def exact(value, keys):
    need(type(value) is dict and set(value) == set(keys))
    return value


def matches(value, pattern):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def canonical_uuid(value):
    try:
        need(type(value) is str and str(uuid.UUID(value)) == value and uuid.UUID(value).int != 0)
    except (ValueError, AttributeError) as error:
        raise Hold('shape') from error
    return value


def path_value(value, *, absolute):
    need(type(value) is str and len(value.encode()) <= 4096 and '\x00' not in value)
    need(value.startswith('/') == absolute)
    parts = value.split('/')[1:] if absolute else value.split('/')
    need(parts and all(p not in ('', '.', '..') for p in parts))
    return value


def within(path, root):
    return path == root or path.startswith(root.rstrip('/') + '/')


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _output_string(value,limit=4096):
    need(type(value) is str and 0<len(value)<=limit and len(value.encode())<=limit and '\x00' not in value,'output_binding')
    return value


def _output_sha(value):
    need(matches(value,SHA) and value!='0'*64,'output_binding');return value


def _output_uint(value):
    need(type(value) is int and 0<value<2**64,'output_binding');return value


def _output_store_path(value):
    _output_string(value);path_value(value,absolute=True)
    need(re.fullmatch(r'/nix/store/[^/\s]+/.+',value) is not None,'output_binding');return value


def _output_identity(value):
    exact(value,{'machine_id','boot_id','kernel','dmi_uuid'})
    need(matches(value['machine_id'],r'[0-9a-f]{32}') and value['machine_id']!='0'*32,'output_binding')
    canonical_uuid(value['boot_id']);canonical_uuid(value['dmi_uuid']);_output_string(value['kernel'],256)
    return value


def _output_unit(value):
    exact(value,{'name','state','main','mount_namespace','mount_line'});name=value['name']
    need(name in ('qcl-negf-aiida.service','qcl-negf-api.service','slurmd.service'),'output_binding')
    state=exact(value['state'],{'InvocationID','ControlGroup','MainPID','ActiveState','FragmentPath','MemoryMax','RuntimeMaxUSec'})
    for item in state.values():_output_string(item)
    need(matches(state['InvocationID'],r'[0-9a-f]{32}') and state['InvocationID']!='0'*32 and
         state['ActiveState']=='active' and matches(state['MainPID'],r'[1-9][0-9]*'),'output_binding')
    _output_store_path(state['FragmentPath'])
    main=exact(value['main'],{'pid','start_ticks','uids','cgroup','executable'})
    _output_uint(main['pid']);_output_uint(main['start_ticks'])
    uid=0 if name=='slurmd.service' else 3000
    need(type(main['uids']) is list and len(main['uids'])==4 and
         all(type(v) is int and v==uid for v in main['uids']) and str(main['pid'])==state['MainPID'] and
         main['cgroup']==state['ControlGroup'],'output_binding')
    path_value(main['cgroup'],absolute=True);_output_store_path(main['executable'])
    namespace=exact(value['mount_namespace'],{'device','inode'})
    for item in namespace.values():_output_uint(item)
    _output_string(value['mount_line'],8192);need('\n' not in value['mount_line'] and '\r' not in value['mount_line'],'output_binding')
    need(len(encoded(value))<=8192,'output_bound');return value


def _output_worker(value):
    exact(value,{'node','identity','unit'});need(matches(value['node'],ID),'output_binding')
    _output_identity(value['identity']);_output_unit(value['unit'])
    need(value['unit']['name']=='slurmd.service' and len(encoded(value))<=12288,'output_binding');return value


def _runner_paths(root):
    return {key:root+'/'+path for key,path in dict(launcher='bin/qcl-negf',julia_launcher='bin/.qcl-negf-julia',
        project='share/qcl-negf/julia/Project.toml',manifest='share/qcl-negf/julia/Manifest.toml',
        runner_entry='share/qcl-negf/components/QCLNEGFRunner.jl/scripts/scientific_workflow.jl',
        runner_module='share/qcl-negf/components/QCLNEGFRunner.jl/src/QCLNEGFRunner.jl',
        cli='share/qcl-negf/components/QCLNEGFRunner.jl/src/cli.jl',
        native_lane='share/qcl-negf/components/QCLNEGFRunner.jl/src/composition/scratch_execution.jl',
        execution='share/qcl-negf/components/QCLNEGFRunner.jl/src/composition/scientific_execution.jl',
        publication='share/qcl-negf/components/QCLNEGFRunner.jl/src/infrastructure/persistence/point_artifacts.jl').items()}


def _output_runner(value):
    exact(value,{'solver_executable','runner_revision','source_graph_sha256','julia_manifest_sha256','capture_executable','files'})
    solver=_output_store_path(value['solver_executable']);capture=_output_store_path(value['capture_executable'])
    need(matches(value['runner_revision'],r'[0-9a-f]{40}') and value['runner_revision']!='0'*40,'output_binding')
    _output_sha(value['source_graph_sha256']);_output_sha(value['julia_manifest_sha256'])
    need(solver.endswith('/bin/qcl-negf') and capture.endswith('/bin/qcl-negf-results'),'output_binding')
    paths=_runner_paths(solver[:-len('/bin/qcl-negf')]);files=exact(value['files'],set(paths)|{'capture_entry','capture_cli','capture_runtime'})
    total=0;seen=set()
    for role,claim in files.items():
        exact(claim,{'path','bytes','sha256'});path=_output_store_path(claim['path']);_output_sha(claim['sha256'])
        need(type(claim['bytes']) is int and 0<=claim['bytes']<=1048576 and path not in seen,'output_binding')
        total+=claim['bytes'];seen.add(path);need(total<=2097152,'output_bound')
        if role in paths:need(path==paths[role],'output_binding')
        elif role=='capture_entry':pass  # The reader checks its actual immutable selector origin.
        else:need(path.endswith('/qcl_negf_results/'+('cli.py' if role=='capture_cli' else 'capture.py')),'output_binding')
    need(files['manifest']['sha256']==value['julia_manifest_sha256'],'output_binding');return value


def _completed_final_binding(value,routes):
    exact(value,{'runner','unit_generation_sha256','worker_generations'});_output_runner(value['runner'])
    _output_sha(value['unit_generation_sha256']);workers=exact(value['worker_generations'],routes)
    machines=set();boots=set()
    for node,worker in workers.items():
        _output_worker(worker);need(worker['node']==node and worker['identity']['machine_id'] not in machines and
            worker['identity']['boot_id'] not in boots,'output_binding')
        machines.add(worker['identity']['machine_id']);boots.add(worker['identity']['boot_id'])
    return value


def _output_relative(value,*,root=False):
    if root and value=='.':return value
    need(type(value) is str and '\\' not in value,'output_metadata');return path_value(value,absolute=False)


def _output_decimal(value,*,positive=False):
    need(matches(value,r'0|[1-9][0-9]{0,19}') and int(value)<2**64 and
         (not positive or int(value)>0),'output_metadata');return int(value)


def _output_ref(value,*,schema=None,media='application/json'):
    exact(value,{'path','bytes','sha256','schema','media_type'});_output_relative(value['path'])
    _output_decimal(value['bytes']);_output_sha(value['sha256']);_output_string(value['schema'],256)
    need(value['media_type']==media and (schema is None or value['schema']==schema),'output_metadata');return value


def _completed_metadata(launch,inputs,raws,root_inode):
    """Finite metadata subset under the qualified actual producer callpath.

    The held owner reader prepays parsing before this call. This is no standalone
    schema/creator/manifest/array proof; only the Root-qualified strong source
    gives closed/produced immutable-closure semantics to these matching bytes.
    """
    exact(inputs,{'calcjob_uuid','runner','worker_boot_id','output_root'});canonical_uuid(inputs['calcjob_uuid'])
    path_value(inputs['output_root'],absolute=True)
    canonical_uuid(inputs['worker_boot_id']);runner=_output_runner(inputs['runner'])
    names={'plan.json','source-graph.json','native-execution.json','capture-spec.json','capture-source.json',
           'series_result.json','native-selection.json'}
    need(type(raws) is dict and names<=raws.keys(),'output_metadata')
    for role in ('plan','source_graph','native_execution'):
        raw=raws[FILES[role]];need(type(raw) is bytes and len(raw)==launch['files'][role]['bytes'] and
            hashlib.sha256(raw).hexdigest()==launch['files'][role]['sha256'],'submitted_digest')
    try:docs={name:strict_json(raws[name].decode()) for name in names}
    except (ResourceError,ValueError,UnicodeError) as error:raise Hold('output_metadata') from error
    need(all(type(value) is dict for value in docs.values()),'output_metadata')
    plan=docs['plan.json'];graph=docs['source-graph.json'];native=docs['native-execution.json']
    plan_sha=launch['files']['plan']['sha256'];fingerprint=plan.get('fingerprint');_output_sha(fingerprint)
    need(plan.get('schema')=='qcl-negf-scientific-plan-v2','output_scope_unsupported')
    exact(graph,{'format','revision','components'});need(graph['format']=='qcl-negf.git-graph.v1' and
        matches(graph['revision'],r'[0-9a-f]{40}') and type(graph['components']) is list,'output_metadata')
    paths=set();runner_rows=[]
    for row in graph['components']:
        exact(row,{'path','revision','url'});_output_relative(row['path'])
        need(row['path'] not in paths and matches(row['revision'],r'[0-9a-f]{40}') and type(row['url']) is str,'output_metadata')
        paths.add(row['path'])
        if row['path']=='components/QCLNEGFRunner.jl':runner_rows.append(row)
    need(len(runner_rows)==1 and runner_rows[0]['revision']==runner['runner_revision'] and
        launch['files']['source_graph']['sha256']==runner['source_graph_sha256'],'output_source_changed')
    exact(native,{'schema','request_id','execution_id','storage','source_graph','code','input_plan','access_receipt_ref'})
    need(native['schema']=='qcl-negf.aiida-native-execution.v1' and native['request_id']==launch['request_id'] and
        native['execution_id']==launch['execution_id'],'output_metadata')
    for field,role,uuid_key in (('input_plan','plan','input_plan_uuid'),('source_graph','source_graph','source_graph_uuid')):
        need(native[field]==dict(node_uuid=launch[uuid_key],bytes=str(launch['files'][role]['bytes']),
            sha256=launch['files'][role]['sha256']),'output_metadata')
    storage=exact(native['storage'],{'namespace_id','storage_identity','relative_execution_root','computer_uuid','execution_binding_uuid',
        'retention_policy_id','retention_owner_id','hold_ref','access_binding_ref'})
    code=exact(native['code'],{'code_uuid','computer_uuid','solver_executable','release_id','build_receipt_ref'})
    need(storage['relative_execution_root']==launch['relative_execution_root'] and storage['execution_binding_uuid']==launch['native_execution_uuid'] and
        code['code_uuid']==launch['code_uuid'] and code['computer_uuid']==storage['computer_uuid'] and code['release_id']==launch['release_id'] and
        code['solver_executable']==runner['solver_executable'],'output_metadata')
    for value in (storage['computer_uuid'],storage['execution_binding_uuid'],code['code_uuid']):canonical_uuid(value)
    for field in ('namespace_id','storage_identity','retention_policy_id','retention_owner_id','hold_ref','access_binding_ref'):_output_string(storage[field],256)
    _output_string(native['access_receipt_ref'],256);_output_string(code['build_receipt_ref'],256)
    spec=exact(docs['capture-spec.json'],{'schema','selection','plan','capture_token','allocation_id','allocated_logical_cpus',
        'scratch_root','credits','native_performance'})
    need(spec['schema']=='qcl-negf.capture-spec.v3' and matches(spec['capture_token'],r'[0-9a-f]{32}') and
        spec['allocated_logical_cpus'] is None and spec['scratch_root'] is None and
        spec['selection']==dict(calcjob_uuid=inputs['calcjob_uuid'],execution_id=launch['execution_id'],attempt=launch['transport_attempt'],
            plan_fingerprint=fingerprint) and type(spec['selection']['attempt']) is int and
        spec['allocation_id']=='calcjob-process:'+inputs['calcjob_uuid']+':'+str(launch['transport_attempt']) and
        spec['native_performance']==dict(run_uuid=launch['run_uuid']) and
        spec['plan']==dict(path='plan.json',bytes=launch['files']['plan']['bytes'],sha256=plan_sha),'output_metadata')
    credit=exact(spec['credits'],{'performance_bytes','scalar_bytes','io_bytes','reserve_bytes'})
    need(all(type(value) is int for value in credit.values()) and credit['performance_bytes']==32*1024**2 and
        credit['scalar_bytes']==64*1024**2 and 16384<=credit['io_bytes']<=128*1024**2 and 0<=credit['reserve_bytes']<2**63,'output_metadata')
    locator=exact(docs['capture-source.json'],{'schema','capture_token','execution_id','plan_fingerprint','mode','actual_root','epoch','root_birth'})
    need(locator['schema']=='qcl-negf.capture-source.v3' and locator['capture_token']==spec['capture_token'] and
        locator['execution_id']==launch['execution_id'] and locator['plan_fingerprint']==fingerprint and locator['mode']=='direct' and
        type(locator['epoch']) is int and locator['epoch']==0 and locator['actual_root']==inputs['output_root'],'output_metadata')
    birth=exact(locator['root_birth'],{'boot_id','mount_namespace_device','mount_namespace_inode','producer_pid','producer_start_ticks','device','inode'})
    need(birth['boot_id']==inputs['worker_boot_id'],'output_metadata')
    for key in set(birth)-{'boot_id'}:_output_decimal(birth[key],positive=key in ('mount_namespace_inode','producer_pid','producer_start_ticks','inode'))
    need((int(birth['device']),int(birth['inode']))==tuple(root_inode),'output_metadata')
    result=docs['series_result.json'];selected=exact(docs['native-selection.json'],{'version','selected_inputs'})
    need(type(selected['version']) is int and selected['version']==1 and type(selected['selected_inputs']) is list and
        result.get('schema')=='qcl-negf-series-result-v4' and result.get('contract_set')=='qcl-negf.results.v2' and
        result.get('status') in ('completed','completed_with_warnings') and result.get('plan_fingerprint')==fingerprint and
        result.get('plan_scientific_fingerprint')==plan.get('scientific_fingerprint') and
        type(result.get('attempt_history',[])) is list and not result.get('attempt_history',[]),'output_scope_unsupported')
    need(type(plan.get('points')) is list and 0<len(plan['points'])<=256,'output_metadata')
    known={point['id']:point for point in plan['points'] if point['execution_id']==launch['execution_id']}
    need(known and len(known)==sum(p['execution_id']==launch['execution_id'] for p in plan['points']),'output_metadata')
    points=result.get('points');need(type(points) is list and len(points)==len(known)==len(selected['selected_inputs']) and
        type(result.get('expected_point_count')) is int and type(result.get('available_point_count')) is int and
        result.get('expected_point_count')==result.get('available_point_count')==len(known),'output_metadata')
    need(type(result.get('executions')) is list and len(result['executions'])==1 and result['executions'][0]['id']==launch['execution_id'] and
        set(result['executions'][0]['point_ids'])==set(known),'output_metadata')
    prefix='c1-'+inputs['calcjob_uuid'].replace('-','')+'-'+launch['native_execution_uuid'].replace('-','')+'-'
    observed=set();used=set()
    for point in points:
        point_id=point['id'];need(point_id in known and point_id not in observed and point['execution_id']==launch['execution_id'] and
            type(point['attempt']) is int and 0<point['attempt']<2**64 and point['status'] in ('completed','completed_with_warnings'),'output_metadata')
        observed.add(point_id);data=point['data'];need(data.get('checkpoint_source_attempt') is None,'output_scope_unsupported')
        source=exact(data['native_source'],{'schema','kind','artifact_root','relation','selected_state','diagnostics','observations','reason'})
        need(source['schema']=='qcl-negf.native-point-source.v1' and source['kind']=='final' and source['relation']=='current_point_attempt' and
            source['reason'] is None,'output_scope_unsupported');_output_relative(source['artifact_root'],root=True)
        state=exact(source['selected_state'],{'identity','state_id','state_sequence','manifest'})
        identity=exact(state['identity'],{'run_id','execution_id','point_id','attempt','branch_id','model_sha256','plan_sha256'})
        for field in ('run_id','branch_id'):need(matches(identity[field],ID),'output_metadata')
        need(identity['execution_id']==launch['execution_id'] and identity['point_id']==point_id and identity['attempt']==str(point['attempt']) and
            identity['plan_sha256']==plan_sha and identity['model_sha256']==known[point_id]['effective_inputs']['model_sha256'],'output_metadata')
        sequence=_output_decimal(state['state_sequence'],positive=True)
        match=re.fullmatch(re.escape(prefix)+r'([1-9][0-9]{0,19})-state-([1-9][0-9]{0,19})',state['state_id'])
        need(match is not None and int(match[1])<2**64 and int(match[2])==sequence,'output_metadata')
        _output_ref(state['manifest'],schema='qcl-negf.result-manifest.v1')
        for field in ('diagnostics','observations'):_output_ref(source[field],schema='qcl-negf-physics-analysis-v5',media='application/x-hdf5')
        matches_rows=[(index,row) for index,row in enumerate(selected['selected_inputs']) if row.get('artifact_root')==source['artifact_root'] and row.get('selected_state')==state]
        need(len(matches_rows)==1 and matches_rows[0][0] not in used,'output_metadata');index,row=matches_rows[0];used.add(index)
        exact(row,{'artifact_root','selected_state','plan','model'});_output_ref(row['plan'],schema=plan['schema']);_output_ref(row['model'],schema='qcl-negf-resolved-configuration-v3')
        need(row['plan']['bytes']==str(launch['files']['plan']['bytes']) and row['plan']['sha256']==plan_sha,'output_metadata')
    return dict(plan_fingerprint=fingerprint,selected_points=len(points),root_birth=birth,storage_identity=storage['storage_identity'])


def _output_mount_line(raw,prefix,source,readonly):
    need(type(readonly) is bool and not re.search(r'[\\\s]',prefix+source),'output_binding')
    rows=[]
    for line in raw.splitlines():
        left,separator,right=line.partition(' - ');fields=left.split();tail=right.split()
        need(separator and len(fields)>=6 and len(tail)>=3,'output_binding')
        if fields[4]==prefix if readonly else within(prefix,fields[4]):rows.append((len(fields[4]),line,fields,tail))
    need(rows,'output_binding');length=max(row[0] for row in rows);selected=[row for row in rows if row[0]==length]
    need(len(selected)==1,'output_binding');_,line,fields,tail=selected[0]
    options=set(fields[5].split(','))|set(tail[2].split(','))
    need(tail[0] in ('nfs','nfs4') and tail[1]==source and 'hard' in options and
         ('ro' if readonly else 'rw') in fields[5].split(',') and not re.search(r'[\\\s]',fields[4]),'output_binding')
    _output_string(line,8192);return line


def validate_limits(value):
    exact(value, LIMIT_KEYS)
    for key, item in value.items():
        need(type(item) in (int, float) and math.isfinite(item) and item > 0, 'policy_limits')
        if not key.endswith('_seconds'):
            need(type(item) is int, 'policy_limits')
    for key, cap in [('request_bytes', 65536), ('response_bytes', 262144),
                     ('script_bytes', 65536), ('maximum_pids', 256)]:
        need(value[key] <= cap, 'policy_limits')
    need(value['cleanup_seconds'] < value['command_seconds'] < value['operation_seconds'], 'policy_limits')
    need(value['metadata_bytes'] <= value['memory_bytes'] // 4, 'policy_limits')
    return value


class Operation:
    """One nonrefundable budget shared by socket, files, commands and journal."""
    def __init__(self, limits):
        self.limits = validate_limits(limits)
        self.started = time.monotonic()
        self.deadline = self.started + limits['operation_seconds']
        self.bytes = self.actual_bytes = self.calls = self.files = 0

    def before(self):
        need(time.monotonic() < self.deadline, 'operation_deadline')

    def reserve(self, size):
        self.before()
        need(type(size) is int and size >= 0, 'operation_bound')
        self.bytes += size
        need(self.bytes <= self.limits['metadata_bytes'], 'operation_bound')

    def file(self):
        self.before(); self.files += 1
        need(self.files <= self.limits['maximum_files'], 'operation_file_bound')

    def command(self, argv, *, env=None, run=engine.command, output_bytes=None):
        self.before(); self.calls += 1
        need(self.calls <= self.limits['maximum_calls'], 'operation_call_bound')
        cap = min(output_bytes or 65536, self.limits['response_bytes'])
        self.reserve(cap * 4)
        result = run(argv, timeout_seconds=self.limits['command_seconds'], output_bytes=cap,
                     deadline=self.deadline, cleanup_seconds=self.limits['cleanup_seconds'], env=env)
        self.before()
        return result

    def read(self, path, limit=65536):
        self.file(); raw = bytearray()
        with open(path, 'rb') as stream:
            while len(raw) <= limit:
                size = min(4096, limit + 1 - len(raw)); self.reserve(size)
                chunk = stream.read(size); self.actual_bytes += len(chunk)
                if not chunk:
                    self.before(); return bytes(raw)
                raw.extend(chunk)
        raise Hold('operation_bound')

    def stat(self, path, *, follow_symlinks=False):
        self.file(); result = os.stat(path, follow_symlinks=follow_symlinks); self.before()
        return result

    def link(self, path):
        self.reserve(4097); result = os.readlink(path); self.before()
        need(len(os.fsencode(result)) <= 4096, 'operation_bound')
        return result

    def entries(self, path, kind):
        with os.scandir(path) as iterator:
            for item in iterator:
                self.file()
                if kind != 'pid' or item.name.isdigit():
                    yield Path(item.path)


def validate_request(document):
    need(type(document) is dict and type(document.get('version')) is int and document['version'] in (1,3))
    version = document['version']
    keys = {'version', 'action', 'calcjob_uuid', 'launch', 'controls'}
    exact(document, keys | ({'technical_control'} if version == 3 else set()))
    need(document['action'] in {'submit', 'reconcile', 'start', 'close', 'status'})
    if version == 3:
        need(document['action'] == 'close')
        _close_controls(document['controls'])
        _technical_control(document['technical_control'])
    canonical_uuid(document['calcjob_uuid'])
    launch = exact(document['launch'], {'request_id', 'run_uuid', 'execution_id', 'transport_attempt',
                    'code_uuid', 'release_id', 'native_execution_uuid', 'input_plan_uuid',
                    'source_graph_uuid', 'relative_execution_root', 'remote_workdir', 'files'})
    for key in ('request_id', 'run_uuid', 'code_uuid', 'native_execution_uuid', 'input_plan_uuid', 'source_graph_uuid'):
        canonical_uuid(launch[key])
    need(matches(launch['execution_id'], ID) and matches(launch['release_id'], ID))
    need(type(launch['transport_attempt']) is int and launch['transport_attempt'] > 0)
    path_value(launch['relative_execution_root'], absolute=False)
    path_value(launch['remote_workdir'], absolute=True)
    exact(launch['files'], FILES)
    for claim in launch['files'].values():
        exact(claim, {'bytes', 'sha256'})
        need(type(claim['bytes']) is int and claim['bytes'] >= 0 and matches(claim['sha256'], SHA))
    controls = document['controls']
    if document['action'] == 'close':
        need(type(controls) is list and len(controls) <= 5)
        for claim in controls:
            exact(claim, {'path', 'bytes', 'sha256'})
            path_value(claim['path'], absolute=False)
            need(type(claim['bytes']) is int and claim['bytes'] >= 0 and matches(claim['sha256'], SHA))
        need(len({c['path'] for c in controls}) == len(controls))
    else:
        need(controls is None)
    return document


def reply(document, state, *, job=None, reason=None, receipt=None, controls=None, technical_control=None):
    version = 3 if type(document.get('version')) is int and document['version'] == 3 and document.get('action') == 'close' else 1
    result = dict(version=version, state=state, calcjob_uuid=document.get('calcjob_uuid'), receipt_ref=receipt,
                  job=job, controls=controls, reason=reason)
    if version == 3:
        result['technical_control'] = technical_control
    return result


def validate_job(job):
    exact(job, {'job_id', 'cluster', 'submit_time', 'controller_machine_id', 'controller_boot_id',
                'dispatch_id', 'generation', 'node_name', 'start_time', 'worker_machine_id', 'worker_boot_id'})
    need(matches(job['job_id'], JOB) and matches(job['cluster'], ID) and matches(job['generation'], SHA), 'job_binding')
    need(matches(job['controller_machine_id'], r'[0-9a-f]{32}'), 'job_binding')
    for key in ('controller_boot_id', 'dispatch_id'):
        canonical_uuid(job[key])
    need(type(job['submit_time']) is str and 0 < len(job['submit_time']) <= 64, 'job_binding')
    allocation = [job[key] for key in ('node_name', 'start_time', 'worker_machine_id', 'worker_boot_id')]
    need(all(value is None for value in allocation) or all(value is not None for value in allocation), 'job_binding')
    if allocation[0] is not None:
        need(matches(job['node_name'], ID) and matches(job['worker_machine_id'], r'[0-9a-f]{32}') and
             matches(job['start_time'], r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}'), 'job_binding')
        canonical_uuid(job['worker_boot_id'])
    return job


def validate_reply(document, *, historical=False):
    need(type(document) is dict and type(document.get('version')) is int and document['version'] in ((1,2,3) if historical else (1,3)), 'reply_shape')
    version = document['version']
    keys = {'version', 'state', 'calcjob_uuid', 'receipt_ref', 'job', 'controls', 'reason'}
    exact(document, keys | ({'technical_control'} if version in (2,3) else set()))
    need(type(document['state']) is str, 'reply_shape')
    need(document['state'] in ({'closed','hold','rejected'} if version in (2,3) else
                              {'bound','started','closed','hold','rejected'}), 'reply_shape')
    if version in (2,3):
        if document['state'] == 'closed':
            _technical_control(document['technical_control'])
        else:
            need(document['technical_control'] is None, 'reply_shape')
    if document['calcjob_uuid'] is not None:
        canonical_uuid(document['calcjob_uuid'])
    if document['receipt_ref'] is not None:
        need(type(document['receipt_ref']) is str and len(document['receipt_ref']) <= 256, 'reply_shape')
    if document['job'] is not None:
        validate_job(document['job'])
    if document['state'] in {'hold', 'rejected'}:
        need(matches(document['reason'], ID) and document['controls'] is None, 'reply_shape')
    else:
        need(document['job'] is not None and document['calcjob_uuid'] is not None and document['reason'] is None, 'reply_shape')
        need(document['state'] == 'closed' or document['controls'] is None, 'reply_shape')
        if document['state'] == 'started':
            need(document['job']['node_name'] is not None, 'reply_shape')
        if document['state'] == 'closed':
            need(type(document['controls']) is list and 0 < len(document['controls']) <= 5, 'reply_shape')
            for control in document['controls']:
                exact(control, {'path', 'bytes', 'sha256'}); path_value(control['path'], absolute=False)
                need(type(control['bytes']) is int and control['bytes'] >= 0 and matches(control['sha256'], SHA), 'reply_shape')
            _close_controls(document['controls'])
            need(document['receipt_ref'] == document['calcjob_uuid'] + '/close.json', 'reply_binding')
    return document


def _close_controls(controls):
    need(type(controls) is list and len(controls) == 4, 'q1_controls_unavailable')
    result = []
    for name, cap, row in zip(CLOSE_FILES, (33554432, 262144, 65536, 65536), controls):
        exact(row, {'path','bytes','sha256'})
        need(row['path'] == name and type(row['bytes']) is int and 0 <= row['bytes'] <= cap and
             matches(row['sha256'], SHA), 'q1_controls_unavailable')
        result.append(dict(row))
    return result


def _technical_control(value):
    need(type(value) is dict, 'q1_technical_unavailable')
    if value.get('status') == 'present':
        exact(value, {'status','path','bytes','sha256'})
        need(matches(value['bytes'], r'0|[1-9][0-9]{0,19}') and int(value['bytes']) <= TECHNICAL_LIMIT and
             matches(value['sha256'], SHA), 'q1_technical_unavailable')
    else:
        exact(value, {'status','path','reason'})
        need(value['status'] == 'absent' and value['reason'] == 'not_published', 'q1_technical_unavailable')
    need(value['path'] == TECHNICAL_FILE, 'q1_technical_unavailable')
    return dict(value)


def signature(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _owner_read_file(budget):
    credit=getattr(budget,'_owner_read_credit',None)
    if credit is None:return budget.file()
    budget.before();need(credit[1]>0,'owner_read_reservation');credit[1]-=1


def _owner_read_reserve(budget,size):
    credit=getattr(budget,'_owner_read_credit',None)
    if credit is None:return budget.reserve(size)
    budget.before();need(type(size) is int and 0<=size<=credit[0],'owner_read_reservation');credit[0]-=size


def read_fd(fd, limit, budget):
    _owner_read_file(budget); initial = os.fstat(fd)
    need(stat.S_ISREG(initial.st_mode) and initial.st_nlink == 1 and initial.st_size <= limit, 'file_identity')
    raw = bytearray()
    read_limit=initial.st_size if getattr(budget,'_owner_read_credit',None) is not None else limit
    while len(raw) <= read_limit:
        _owner_read_reserve(budget,min(65536, read_limit + 1 - len(raw)))
        chunk = os.read(fd, min(65536, read_limit + 1 - len(raw)))
        budget.actual_bytes += len(chunk)
        if not chunk:
            break
        raw.extend(chunk)
    budget.before()
    need(len(raw) <= limit and len(raw) == initial.st_size and signature(os.fstat(fd)) == signature(initial), 'file_changed')
    return bytes(raw), initial


def protected_read(path, budget, limit=65536):
    """Protected ancestry and same-FD + named-inode readback; no pathname reopen."""
    path = Path(path)
    with protected_directory(path.parent, budget=budget) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        primary = None
        try:
            raw, info = read_fd(fd, limit, budget)
            trusted_stat(info, directory=False)
            need(signature(info) == signature(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'file_changed')
            return raw
        except BaseException as error:
            primary = error
            raise
        finally:
            try:os.close(fd)
            except BaseException as cleanup:
                if primary is None:raise
                primary.add_note('protected source close also raised '+type(cleanup).__name__[:128])


class AttemptStore:
    """Root-local append-only records. Existing partial records are never repaired."""
    def __init__(self, root):
        self.root = Path(root)

    @contextmanager
    def directory(self, path, *, create=False):
        if create:
            try:
                path.mkdir(mode=0o700)
            except FileExistsError:
                pass
            else:
                parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077, 'journal_namespace')
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        primary=None
        try:
            need(signature(info) == signature(os.fstat(fd)), 'journal_namespace')
            yield fd
            named = path.lstat()
            need((named.st_dev, named.st_ino) == (info.st_dev, info.st_ino), 'journal_namespace')
        except BaseException as error:
            primary=error;raise
        finally:
            try:os.close(fd)
            except BaseException as cleanup:
                if primary is None:raise
                primary.add_note('journal directory FD close also raised '+type(cleanup).__name__)

    @contextmanager
    def locked(self, calcjob, budget, *, existing_only=False):
        canonical_uuid(calcjob)
        need(type(existing_only) is bool)
        with self.directory(self.root):
            locks = self.root / 'locks'
            with self.directory(locks, create=not existing_only) as parent:
                budget.file()
                flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
                if not existing_only:flags |= os.O_CREAT
                fd = os.open(calcjob, flags, 0o600, dir_fd=parent)
                primary = None
                try:
                    info = os.fstat(fd)
                    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
                         not info.st_mode & 0o077 and info.st_nlink == 1, 'journal_namespace')
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError as error:
                        raise Hold('attempt_busy') from error
                    budget.before(); yield
                except BaseException as error:
                    primary = error; raise
                finally:
                    try:os.close(fd)
                    except BaseException as cleanup:
                        if primary is None:raise
                        primary.add_note('attempt lock cleanup also raised '+type(cleanup).__name__)

    def path(self, calcjob):
        canonical_uuid(calcjob)
        return self.root / 'attempts' / calcjob

    def claim_domain(self, calcjob, domain, budget):
        path_value(domain, absolute=False)
        # A short admission lock covers only bounded metadata, never a solve.
        admission = str(uuid.uuid5(uuid.NAMESPACE_URL, 'qcl-native-output-domain-admission'))
        with self.locked(admission, budget):
            directory = self.root / 'domains'
            with self.directory(directory, create=True) as parent:
                for path in budget.entries(directory, 'domain'):
                    need(matches(path.name, SHA), 'journal_namespace')
                    fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                    try:
                        raw, info = read_fd(fd, 65536, budget)
                        need(info.st_uid == os.geteuid() and not info.st_mode & 0o077, 'journal_namespace')
                        record = exact(strict_json(raw.decode()), {'calcjob_uuid', 'domain'})
                        canonical_uuid(record['calcjob_uuid']); path_value(record['domain'], absolute=False)
                        need(hashlib.sha256(record['domain'].encode()).hexdigest() == path.name and
                             signature(info) == signature(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'journal_namespace')
                        if within(domain, record['domain']) or within(record['domain'], domain):
                            need(record == {'calcjob_uuid': calcjob, 'domain': domain}, 'output_domain_claimed')
                            return
                    finally:
                        os.close(fd)
                raw = encoded({'calcjob_uuid': calcjob, 'domain': domain}); budget.reserve(len(raw)); budget.file()
                name = hashlib.sha256(domain.encode()).hexdigest()
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
                try:
                    offset = 0
                    while offset < len(raw):
                        budget.before(); count = os.write(fd, raw[offset:]); need(count > 0, 'journal_short_write'); offset += count
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(parent)

    def read(self, calcjob, name, budget):
        path = self.path(calcjob)
        if not path.exists():
            return None
        with self.directory(path) as parent:
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            except FileNotFoundError:
                return None
            primary = None
            try:
                raw, info = read_fd(fd, 65536, budget)
                need(info.st_uid == os.geteuid() and not info.st_mode & 0o077 and
                     signature(info) == signature(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'journal_namespace')
                return strict_json(raw.decode())
            except BaseException as error:
                primary = error
                raise
            finally:
                try:os.close(fd)
                except BaseException as cleanup:
                    if primary is None:raise
                    primary.add_note('original journal close also raised '+type(cleanup).__name__[:128])

    def put(self, calcjob, name, value, budget):
        raw = encoded(value)
        need(len(raw) <= 65536, 'journal_bound')
        budget.reserve(len(raw)); budget.file()
        with self.directory(self.root / 'attempts', create=True) as attempts:
            path = self.path(calcjob)
            with self.directory(path, create=True) as parent:
                os.fsync(attempts)
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
                try:
                    offset = 0
                    while offset < len(raw):
                        budget.before(); written = os.write(fd, raw[offset:])
                        need(written > 0, 'journal_short_write'); offset += written
                    budget.before(); os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(parent)
        budget.before()


def parse_ack(output, cluster):
    need(type(output) is engine.CommandOutput, 'dispatch_ack_unqualified')
    try:
        raw = output.encode('ascii')
    except UnicodeError as error:
        raise Hold('dispatch_ack_invalid') from error
    need(type(getattr(output, 'output_bytes', None)) is int and output.output_bytes == len(raw), 'dispatch_ack_invalid')
    match = re.fullmatch('(' + JOB + r')(?:;(' + ID + r'))?\n?', str(output))
    need(match is not None and (match[2] is None or match[2] == cluster), 'dispatch_ack_invalid')
    return {'job_id': match[1], 'cluster': match[2] or cluster}


def _preclaim_diagnostic(error, retained=None):
    """Best-effort protected stderr; a sink failure cannot replace primary HOLD."""
    try:
        if retained is None:
            raw = encoded(error.record)
            retained = {'original_prefix_base64':base64.b64encode(raw[:24576]).decode('ascii'),
                        'original_bytes':len(raw),'original_sha256':hashlib.sha256(raw).hexdigest(),
                        'truncated':len(raw)>24576}
        print('native-attempt preclaim HOLD: ' + encoded(retained).decode('ascii'), file=sys.stderr)
    except BaseException:
        # The original failure still determines HOLD; there is no dispatch,
        # alternate logger, public diagnostic payload or new retry authority.
        pass


def _read_close_payload(store, calcjob_uuid, name, budget):
    """Only the two fixed close records, with exact original payload readback."""
    need(name in ('close.json','close-observation.json'), 'journal_namespace')
    with store.directory(store.path(calcjob_uuid)) as parent:
        try:
            budget.file()
            fd = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC, dir_fd=parent)
        except FileNotFoundError:
            return None
        primary=None
        try:
            raw, info = read_fd(fd,65536,budget)
            need(info.st_uid == os.geteuid() and not info.st_mode&0o077, 'journal_namespace')
            budget.reserve(len(raw)*8)
            value = strict_json(raw.decode());need(type(value) is dict and encoded(value)==raw, 'q1_close_conflict')
            if name=='close.json':
                validate_reply(value,historical=True)
                need(value['state']=='closed' and value['calcjob_uuid']==calcjob_uuid, 'q1_close_conflict')
            budget.before(); os.fsync(fd); budget.before(); os.fsync(parent)
            need(signature(info)==signature(os.fstat(fd))==signature(os.stat(name,dir_fd=parent,follow_symlinks=False)),
                 'q1_close_conflict')
            return value,raw
        except BaseException as error:
            primary=error;raise
        finally:
            try:os.close(fd)
            except BaseException as cleanup:
                if primary is None:raise
                primary.add_note('original close-record FD close also raised '+type(cleanup).__name__)


def _read_close_record(store, calcjob_uuid, budget):
    return _read_close_payload(store,calcjob_uuid,'close.json',budget)


def _close_mount_line(raw, prefix, source):
    rows = []
    for line in raw.splitlines():
        left,separator,right = line.partition(' - ');fields=left.split();tail=right.split()
        need(separator and len(fields)>=6 and len(tail)>=3, 'writer_domain_not_closed')
        if fields[4]==prefix:rows.append((line,fields,tail))
    need(len(rows)==1, 'writer_domain_not_closed')
    line,fields,tail = rows[0]
    need('ro' in fields[5].split(',') and tail[0] in ('nfs','nfs4') and tail[1]==source,
         'writer_domain_not_closed')
    return line


def _closed_native_status(observed,job):
    from host_resource_facts import parse_slurm_jobs
    need(observed['prolog_ref'] is not None and observed['epilog_ref'] is not None,'native_stop_not_observed')
    raw=observed['job']['raw'];fields=observed['job']['fields']
    pairs=re.findall(r'(?<!\S)(\w+)=([^\s]+)',raw)
    need(len(pairs)==len(dict(pairs)) and dict(pairs)==fields,'native_job_changed')
    try:rows=parse_slurm_jobs(raw,cluster=job['cluster'])
    except ResourceError as error:raise Hold('output_scope_unsupported') from error
    need(set(rows)=={job['job_id']},'native_job_changed');native=rows[job['job_id']]
    need(native['terminal'] and native['state']=='COMPLETED' and fields.get('ExitCode')=='0:0',
         'output_scope_unsupported')
    need(native['submit_time']==job['submit_time'] and native['start_time']==job['start_time'] and
         native['node']==job['node_name'] and fields.get('Comment')==job['dispatch_id'],'native_job_changed')
    return native


def _completed_worker_status(observed,job):
    from host_resource_facts import _output_native_tuple
    native=_closed_native_status(observed,job);snapshot=observed['writer_snapshot'];identity=observed['identity']['identity']
    need(snapshot['schema']=='qcl.host-resource-guest-facts.v1' and
        snapshot['identity_before']==snapshot['identity_after'] and
        all(snapshot['identity_before'].get(k)==identity[k] for k in ('machine_id','boot_id')) and
        identity['machine_id']==job['worker_machine_id'] and identity['boot_id']==job['worker_boot_id'],
        'worker_generation_changed')
    row=snapshot['jobs'].get(job['job_id']);group=snapshot['groups'].get(job['job_id'])
    need(row is not None and _output_native_tuple(row)==_output_native_tuple(native) and type(group) is dict and
        group.get('populated') is False and group.get('processes')==[],'native_stop_not_observed')
    return native


def _output_original_records(sources,calcjob,records,native,fields,context):
    """Join retained original Q1 records, without reusing resource hashes.

    This is an internal metadata guard. Its operands are read from the existing
    protected journal under its existing lock, never from the RPC request.
    """
    from host_resource_facts import _output_native_tuple
    canonical_uuid(calcjob);exact(records,{'claim.json','dispatch.json','ack.json','job.json','allocation.json'})
    need(all(type(value) is dict for value in records.values()),'partial_claim')
    claim=exact(records['claim.json'],{'launch','dispatch_id','context'});launch=claim['launch'];dispatch=claim['dispatch_id']
    canonical_uuid(dispatch)
    validate_request(dict(version=1,action='submit',calcjob_uuid=calcjob,launch=launch,controls=None))
    intent=exact(records['dispatch.json'],{'dispatch_id','snapshot','context','native'})
    snapshot=exact(intent['snapshot'],{'script_path','script_sha256'})
    ack=exact(records['ack.json'],{'job_id','cluster'});bound=validate_job(records['job.json']);job=validate_job(records['allocation.json'])
    need(claim['context']==intent['context']==context and intent['dispatch_id']==dispatch and
        snapshot==dict(script_path=str(Path(sources.policy['spool_root'])/(dispatch+'.sh')),
            script_sha256=launch['files']['submit_script']['sha256']),'native_dispatch_join_missing')
    need(all(bound[k]==job[k] for k in bound if k not in {'node_name','start_time','worker_machine_id','worker_boot_id'}) and
        job['node_name'] is not None and ack==dict(job_id=job['job_id'],cluster=job['cluster']) and
        job['dispatch_id']==dispatch and job['controller_machine_id']==context['machine_id'] and
        job['controller_boot_id']==context['boot_id'],'native_job_changed')
    tuple_now=_output_native_tuple(native)
    need(tuple_now['job_id']==job['job_id'] and tuple_now['cluster']==job['cluster'] and
        tuple_now['submit_time']==job['submit_time'] and tuple_now['start_time']==job['start_time'] and
        tuple_now['node']==job['node_name'] and fields.get('Command')==snapshot['script_path'] and
        fields.get('WorkDir')==launch['remote_workdir'] and fields.get('Comment')==dispatch,'native_job_changed')
    generation=hashlib.sha256(encoded(dict(controller=context,job_id=job['job_id'],submit_time=job['submit_time'],
        dispatch_id=dispatch,command=fields['Command'],workdir=fields['WorkDir']))).hexdigest()
    need(generation==job['generation'],'native_job_changed')
    q=sources.qualification;binding=q['worker_bindings'].get(job['worker_machine_id'])
    need(binding is not None and binding['machine_id']==job['worker_machine_id'] and binding['boot_id']==job['worker_boot_id'] and
        q['write_domain']['writer_hosts'].get(job['node_name'])==job['worker_machine_id'],'worker_generation_changed')
    original=exact(intent['native'],{'argv','script_sha256','owner'})
    owner=exact(original['owner'],{'process','unit','host','caller','actor'})
    actor=exact(owner['actor'],{'calcjob_uuid','action','launch','execution_sha256'})
    process=_caller_generation(owner['process']);unit=owner['unit'];caller=owner['caller']
    need(original['argv']==sources._argv(launch,snapshot,dispatch) and original['script_sha256']==snapshot['script_sha256'] and
        actor==dict(calcjob_uuid=calcjob,action='submit',launch=launch,execution_sha256=launch['files']['native_execution']['sha256']) and
        owner['host']==context and process['uids']==[0]*4 and process['executable']==q['unit_origins']['server']['executable'] and
        matches(process['cgroup'].rsplit('/',1)[-1],r'qcl-negf-native-attempt@[A-Za-z0-9_.:-]+\.service') and
        unit['ControlGroup']==process['cgroup'] and unit['MainPID']==str(process['pid']) and
        unit['ActiveState']=='active' and matches(unit['InvocationID'],r'[0-9a-f]{32}') and unit['InvocationID']!='0'*32,
        'native_dispatch_join_missing')
    need(type(caller) is dict and {'chain','unit','application','profile'}<=caller.keys() and
        type(caller['chain']) is list and caller['chain'] and
        type(caller['application']) is dict and 'configuration' in caller['application'],'native_dispatch_join_missing')
    return dict(launch=launch,job=job,context=context,snapshot=snapshot,caller=caller)


def _output_release_source(sources,calcjob,joined,runner):
    launch=joined['launch'];budget=sources.budget;root=Path(sources.policy['release_runtime'])
    retained=strict_json(protected_read(root/'records'/('release-'+launch['release_id']+'.json'),budget).decode())
    current=strict_json(protected_read(root/'release.json',budget).decode())
    envelope=engine.release_envelope(retained);actual=engine.release_envelope(current)
    context=engine.quantum_context(envelope)
    need(context is not None and envelope==actual and current.get('ready') is True and
        retained.get('code_uuid')==current.get('code_uuid')==launch['code_uuid'] and
        retained.get('quantum_runtime_context')==context and envelope['release_id']==launch['release_id'] and
        envelope['solver_executable']==runner['solver_executable'] and
        context['source_graph_sha256']==runner['source_graph_sha256']==launch['files']['source_graph']['sha256'] and
        context['julia_manifest_sha256']==runner['julia_manifest_sha256'] and
        context['runner_source_id']==runner['runner_revision'],'release_binding_changed')
    graph=protected_read(root/'records'/('source-graph-'+runner['source_graph_sha256']+'.json'),budget)
    need(len(graph)==launch['files']['source_graph']['bytes'] and hashlib.sha256(graph).hexdigest()==runner['source_graph_sha256'],
        'release_graph_changed')
    snapshot=joined['snapshot'];size=launch['files']['submit_script']['bytes']
    need(size<=sources.policy['limits']['script_bytes'] and snapshot['script_sha256']==launch['files']['submit_script']['sha256'],
        'snapshot_changed')
    budget.reserve(8*(size+1));raw=protected_read(snapshot['script_path'],budget,size)
    need(len(raw)==size and hashlib.sha256(raw).hexdigest()==snapshot['script_sha256'],'snapshot_changed')
    bash=joined['caller']['application']['configuration']['client']['bash_executable']
    _output_store_path(bash)
    _review_native_script(raw,launch,runner['solver_executable'],bash,sources,calcjob_uuid=calcjob)
    need(b'export QCL_NEGF_CAPTURE_SPEC=capture-spec.json QCL_NEGF_NATIVE_CAPTURE_INPUT=native-execution.json' in raw,
        'output_scope_unsupported')


class OrdinaryAttemptOwner:
    def __init__(self, policy, store, sources, budget):
        self.policy, self.store, self.sources, self.budget = policy, store, sources, budget

    def _run(self, document, action):
        job = None; receipt = None; claimed = False
        try:
            validate_request(document); need(document['action'] == action)
        except (Hold, TypeError, ValueError, KeyError):
            return reply({}, 'rejected', reason='shape')
        calcjob = document['calcjob_uuid']; launch = document['launch']
        try:
            controls = _close_controls(document['controls']) if action=='close' else None
            context = self.sources.preflight(launch, self.budget, calcjob_uuid=calcjob, action=action)
            with self.store.locked(calcjob, self.budget):
                claim = self.store.read(calcjob, 'claim.json', self.budget)
                if claim is not None:
                    claimed = True; receipt = calcjob + '/claim.json'
                    need(claim['launch'] == launch, 'launch_conflict')
                else:
                    # A directory without its complete claim is an unknown prior outcome.
                    need(not self.store.path(calcjob).exists(), 'partial_claim')
                    need(action == 'submit', 'attempt_unknown')
                    self.store.claim_domain(calcjob, launch['relative_execution_root'], self.budget)
                    claim = {'launch': launch, 'dispatch_id': str(uuid.uuid4()), 'context': context}
                    self.store.put(calcjob, 'claim.json', claim, self.budget)
                    claimed = True; receipt = calcjob + '/claim.json'
                    snapshot = self.sources.snapshot(launch, claim['dispatch_id'], self.budget)
                    intent = {'dispatch_id': claim['dispatch_id'], 'snapshot': snapshot, 'context': context,
                              'native': self.sources._intent(launch, snapshot, claim['dispatch_id'])}
                    self.store.put(calcjob, 'dispatch.json', intent, self.budget)
                    try:
                        output = self.sources.dispatch(launch, snapshot, claim['dispatch_id'], self.budget)
                        ack = parse_ack(output, self.policy.get('slurm', {}).get('cluster', 'cluster'))
                        self.store.put(calcjob, 'ack.json', ack, self.budget)
                    except (engine.CommandFailure, Hold, OSError) as error:
                        # Keep the command engine's primary record, including ambiguous cleanup.
                        failure = error.record if isinstance(error, engine.CommandFailure) else {'failure': str(error)}
                        try:
                            self.store.put(calcjob, 'failure.json', failure, self.budget)
                        except BaseException as secondary:
                            error.journal_error = repr(secondary)
                            raise error
                        raise Hold('dispatch_outcome_unknown') from error
                dispatch = self.store.read(calcjob, 'dispatch.json', self.budget)
                need(dispatch is not None, 'partial_claim')
                ack = self.store.read(calcjob, 'ack.json', self.budget)
                # Never infer a negative from scheduler absence or issue another sbatch.
                need(ack is not None, 'dispatch_outcome_unknown')
                need(claim['context'] == context, 'controller_generation_changed')
                job = self.store.read(calcjob, 'job.json', self.budget)
                if job is None:
                    job = validate_job(self.sources.bind_job(ack, launch, claim['dispatch_id'], context, self.budget))
                    self.store.put(calcjob, 'job.json', job, self.budget)
                allocation = self.store.read(calcjob, 'allocation.json', self.budget)
                if allocation is not None:
                    need(all(allocation[k] == job[k] for k in job if k not in
                             {'node_name', 'start_time', 'worker_machine_id', 'worker_boot_id'}), 'native_job_changed')
                    job = validate_job(allocation)
                if action in {'start', 'close'}:
                    observed = self.sources.worker(job, calcjob, 'start' if action == 'start' else 'close', self.budget)
                    if action == 'start':
                        need(observed['before'] is not None, 'native_start_not_observed')
                        fields = observed['job']['fields']; identity = observed['identity']['identity']
                        attached = validate_job({**job, 'node_name': fields['NodeList'], 'start_time': fields['StartTime'],
                                               'worker_machine_id': identity['machine_id'], 'worker_boot_id': identity['boot_id']})
                        if allocation is None:
                            self.store.put(calcjob, 'allocation.json', attached, self.budget)
                        else:
                            need(allocation == attached, 'worker_generation_changed')
                        job = attached
                        return reply(document, 'started', job=job, receipt=receipt)
                    need(observed['after'] is not None, 'native_stop_not_observed')
                    need(allocation is not None and observed['before'] is not None, 'native_start_not_observed')
                    return self._close(document,job,context,observed,controls)
                return reply(document, 'bound', job=job, receipt=receipt)
        except (Hold, ResourceError, OSError, ValueError, KeyError, engine.CommandFailure) as error:
            reason = error.reason if isinstance(error, Hold) else getattr(error, 'code', 'native_observation_failed')
            if isinstance(error, engine.CommandFailure):
                raw = encoded(error.record)
                retained = {'original_prefix_base64': base64.b64encode(raw[:24576]).decode('ascii'),
                            'original_bytes': len(raw), 'original_sha256': hashlib.sha256(raw).hexdigest(),
                            'truncated': len(raw) > 24576}
                if claimed:
                    try:
                        self.store.put(calcjob, 'observation-failure-' + uuid.uuid4().hex + '.json', retained, self.budget)
                    except BaseException as secondary:
                        error.journal_error = repr(secondary)
                        raise error
                else:
                    _preclaim_diagnostic(error,retained)
            elif action=='close':
                try:
                    _preclaim_diagnostic(engine.CommandFailure(dict(failure='close_observation_failed',phase='close',
                        original_type=type(error).__name__,message=str(error)[:4096])))
                except BaseException:
                    pass  # A diagnostic failure cannot replace the original HOLD.
            # Read-only retained identity remains useful after current policy or
            # native observation failed. It is explicitly not current authority.
            if job is None:
                try:
                    old_claim = self.store.read(calcjob, 'claim.json', self.budget)
                    if old_claim is not None and old_claim['launch'] == launch:
                        job = self.store.read(calcjob, 'allocation.json', self.budget) or self.store.read(calcjob, 'job.json', self.budget)
                        if job is not None:
                            validate_job(job)
                        receipt = calcjob + '/claim.json'
                except (Hold, ResourceError, OSError, ValueError, KeyError):
                    pass
            return reply(document, 'hold' if claimed or not isinstance(error, Hold) or reason != 'shape' else 'rejected',
                         job=job, reason=reason, receipt=receipt)

    def _close(self, document, job, context, observed, controls, *, facts_guard=None,facts_inputs=None):
        launch = document['launch']; calcjob = document['calcjob_uuid']; budget = self.budget
        need(isinstance(self.sources,NativeSources), 'q1_controls_unavailable')
        need(facts_guard is None or callable(facts_guard),'facts_entry_unavailable')
        previous = _read_close_record(self.store,calcjob,budget)
        retained = _read_close_payload(self.store,calcjob,'close-observation.json',budget)
        need((previous is None)==(retained is None), 'q1_close_publication_unknown')
        need(previous is None or previous[0]['version']==document['version'], 'q1_close_conflict')
        technical = document.get('technical_control')
        if facts_guard is not None:
            # The production facts factory must select this private guard after
            # its own caller/original-journal checks. Constructor seams are not
            # authority. No socket/server/daemon identity is manufactured here.
            need(previous is not None and document['version']==3 and technical is not None and
                 technical['status']=='absent','output_scope_unsupported')
            witness=retained[0]
            need(witness.get('job')==job and witness.get('launch')==launch and
                 witness.get('reply_sha256')==hashlib.sha256(previous[1]).hexdigest(),'q1_close_conflict')
            original=witness['worker_close']
            need(original['before'] is not None and original['after'] is not None,'native_stop_not_observed')
            facts_guard();_closed_native_status(observed,job)
        need(facts_inputs is None or facts_guard is not None,'facts_entry_unavailable')
        if facts_inputs is not None:
            binding=_completed_final_binding(self.sources.qualification['completed_final'],self.policy['worker_routes'])
            need(facts_inputs==dict(calcjob_uuid=calcjob,runner=binding['runner'],worker_boot_id=job['worker_boot_id'],
                 output_root=self.policy['jobs_root']+'/'+launch['relative_execution_root']),'output_binding')
            for key in ('storage_identity','native_prefix','retention_ref'):
                need(retained[0]['w1_before'][key]==retained[0]['w1_after'][key]==self.sources.qualification['write_domain'][key],
                     'writer_domain_not_closed')
            _completed_worker_status(observed,job)
        need(observed['identity']['identity']['machine_id']==job['worker_machine_id'] and
             observed['identity']['identity']['boot_id']==job['worker_boot_id'], 'worker_generation_changed')
        before = self.sources.close_writers(job,launch,observed,budget)
        options = {} if document['version'] == 1 else {'technical_control':technical}
        caller=latest=after=None
        def recheck(_readback):
            nonlocal caller,latest,after
            need(self.sources.qualify()==context, 'controller_generation_changed')
            if facts_guard is None:
                _authenticate_server(self.sources);caller=self.sources._refresh_caller('close')
            else:facts_guard()
            latest=self.sources.worker(job,calcjob,'close' if facts_guard is None else 'status',budget)
            if facts_guard is None:
                need(latest['before'] is not None and latest['after'] is not None,'native_stop_not_observed')
            else:
                if facts_inputs is None:_closed_native_status(latest,job)
                else:_completed_worker_status(latest,job)
            need(latest['identity']['identity']==observed['identity']['identity'],'worker_generation_changed')
            after=self.sources.close_writers(job,launch,latest,budget)
            for key in ('storage_identity','native_prefix','retention_ref'):
                need(before[key]==after[key],'writer_domain_not_closed')
            need([(r['unit'],r['state']) for r in before['controller_units']]==
                 [(r['unit'],r['state']) for r in after['controller_units']],'writer_domain_not_closed')
            prefix=self.policy['jobs_root']+'/'+self.policy['native_result_prefix']
            need([_close_mount_line(r['mountinfo'],prefix,self.policy['nfs_source']) for r in before['controller_units']]==
                 [_close_mount_line(r['mountinfo'],prefix,self.policy['nfs_source']) for r in after['controller_units']],
                 'writer_domain_not_closed')
            need([(r['node'],r['reply']['identity']['identity']) for r in before['workers']]==
                 [(r['node'],r['reply']['identity']['identity']) for r in after['workers']],'worker_generation_changed')
            if facts_inputs is not None:
                need(before.get('output_generation') is not None and before['output_generation']==after.get('output_generation'),
                     'output_binding')
        if facts_guard is not None:options.update(barrier=recheck,solver_logs=True)
        if facts_inputs is not None:options['native_inputs']=facts_inputs
        readback = _read_submitted_files_as_owner(self.policy,launch,budget,controls=controls,**options)
        need(readback['controls']==controls, 'q1_control_changed')
        if document['version'] == 3:
            need(readback['technical_control']==technical, 'q1_technical_changed')
            if previous is not None:
                prior = retained[0]['control_read']
                # Persisted v3 authority is the original named domain/inode,
                # not its mutable timestamps or the caller's matching hash.
                need(type(prior) is dict and type(prior.get('roots')) is list and
                     type(prior.get('files')) is list, 'q1_close_conflict')
                current_files=readback['files'] if facts_guard is None else [
                    row for row in readback['files'] if row['path'] in CLOSE_FILES]
                need(len(prior['roots'])==len(readback['roots']) and
                     len(prior['files'])==len(current_files), 'q1_close_conflict')
                for old,new in zip(prior['roots'],readback['roots']):
                    need(type(old) is dict and old.get('role')==new['role'] and old.get('path')==new['path'] and
                         type(old.get('directory')) is list and old['directory'][:2]==new['directory'][:2], 'q1_close_conflict')
                for old,new in zip(prior['files'],current_files):
                    need(type(old) is dict and old.get('path')==new['path'] and old.get('root')==new['root'], 'q1_close_conflict')
                    if facts_guard is not None:
                        need(type(old.get('signature')) is list and old['signature'][:2]==new['signature'][:2],
                             'q1_close_conflict')
        if facts_guard is None:recheck(readback)
        else:
            # The child has now closed every named FD and exited successfully.
            need(self.sources.qualify()==context,'controller_generation_changed');facts_guard()
            if facts_inputs is not None:
                need(readback['binding']['storage_identity']==self.sources.qualification['write_domain']['storage_identity'],'output_binding')
        candidate = validate_reply(reply(document,'closed',job=job,controls=controls,technical_control=technical,
                                         receipt=calcjob+'/close.json'))
        _reserve_private_record(candidate,budget)
        raw = encoded(candidate); digest = hashlib.sha256(raw).hexdigest()
        if previous is not None:
            need(previous[0]==candidate and retained[0].get('reply_sha256')==digest, 'q1_close_conflict')
            if facts_guard is not None:
                return dict(original_close=previous,original_observation=retained,control_read=readback,
                            w1_before=before,w1_after=after,current_worker=latest)
            return previous[0]
        witness = dict(reply_sha256=digest,job=job,launch=launch,worker_close=observed,
                       w1_before=before,control_read=readback,w1_after=after,caller=caller)
        _reserve_private_record(witness,budget); need(len(encoded(witness))<=65536, 'journal_bound')
        self.store.put(calcjob,'close-observation.json',witness,budget)
        witness_readback = _read_close_payload(self.store,calcjob,'close-observation.json',budget)
        need(witness_readback is not None and witness_readback[1]==encoded(witness), 'q1_close_conflict')
        self.store.put(calcjob,'close.json',candidate,budget)
        stored = _read_close_record(self.store,calcjob,budget)
        need(stored is not None and stored[1]==raw, 'q1_close_conflict')
        return stored[0]

    def submit(self, request):
        return self._run(request, 'submit')

    def reconcile(self, request):
        return self._run(request, 'reconcile')

    def observe_start(self, request):
        return self._run(request, 'start')

    def qualify_close(self, request):
        return self._run(request, 'close')

    def status(self, request):
        return self._run(request, 'status')


def _bootstrap_operation():
    return Operation(dict(request_bytes=65536, response_bytes=262144, script_bytes=65536,
                          metadata_bytes=8 * 1024 * 1024, memory_bytes=134217728,
                          operation_seconds=90, command_seconds=15, cleanup_seconds=2,
                          maximum_pids=256, maximum_calls=64, maximum_files=2048))


def _load_policy(role, budget):
    need(os.geteuid() == 0, 'root_required')
    try:
        raw = protected_read(POLICY, budget)
    except FileNotFoundError as error:
        raise Hold('native_policy_missing') from error
    policy = exact(strict_json(raw.decode()), POLICY_KEYS)
    need(policy['schema'] == 'qcl-negf.native-attempt-policy.v1' and policy['role'] == role, 'policy_role')
    need(policy['client_uid'] == 3000 and type(policy['client_uid']) is int, 'policy_owner')
    need(policy['socket_path'] == SOCKET and policy['daemon_unit'] == 'qcl-negf-aiida.service' and
         policy['server_unit_prefix'] == 'qcl-negf-native-attempt@' and policy['slurmd_unit'] == 'slurmd.service', 'policy_unit')
    exact(policy['tools'], {'systemctl', 'runuser', 'sbatch', 'scontrol', 'slurmd', 'slurmstepd', 'python'})
    exact(policy['slurm'], {'cluster', 'version', 'config_file', 'cgroup_scope'})
    need(matches(policy['slurm']['cluster'], ID), 'policy_cluster')
    for key in ('private_root', 'spool_root', 'jobs_root', 'storage_identity_file', 'release_runtime',
                'facts_service_config', 'qualification_file'):
        path_value(policy[key], absolute=True)
    path_value(policy['native_result_prefix'], absolute=False)
    for tool in policy['tools'].values():
        path_value(tool, absolute=True)
        need(tool.startswith('/nix/store/'), 'policy_tool')
    need(type(policy['worker_routes']) is dict and 1 <= len(policy['worker_routes']) <= 64, 'policy_routes')
    for name, route in policy['worker_routes'].items():
        need(matches(name, ID), 'policy_routes')
        exact(route, {'target', 'known_hosts', 'identity_file', 'helper', 'role'})
        need(route['role'] == 'facts', 'policy_routes')
    limits = validate_limits(policy['limits'])
    # Keep all bootstrap charges and the original deadline; policy can only tighten.
    need(all(limits[k] <= budget.limits[k] for k in LIMIT_KEYS), 'policy_limits')
    budget.deadline = min(budget.deadline, budget.started + limits['operation_seconds'])
    budget.limits = limits
    budget.before(); need(budget.bytes <= limits['metadata_bytes'] and budget.files <= limits['maximum_files'], 'policy_limits')
    policy['_policy_sha256'] = hashlib.sha256(raw).hexdigest()
    return policy


def load_native_attempt_policy(role):
    return _load_policy(role, _bootstrap_operation())


def _output_host(sources):
    first=sources.host()
    value=dict(machine_id=first['machine_id'],boot_id=first['boot_id'],
        kernel=sources.budget.read('/proc/sys/kernel/osrelease',256).decode().strip(),
        dmi_uuid=sources.budget.read('/sys/class/dmi/id/product_uuid',64).decode().strip().lower())
    need(first==sources.host(),'host_generation_changed');return _output_identity(value)


def _worker_output_generation(sources):
    if sources is None or sources.qualification is None or 'completed_final' not in sources.qualification:return None
    expected=_completed_final_binding(sources.qualification['completed_final'],sources.policy['worker_routes'])
    prior=getattr(sources,'_qualification_sha256',None);sources.qualify()
    need(sources.qualification.get('completed_final')==expected and
         (prior is None or prior==sources._qualification_sha256),'output_binding')
    q_sha=sources._qualification_sha256
    need(not hasattr(sources,'_output_sample_q_sha') or sources._output_sample_q_sha==q_sha,'output_binding')
    sources._output_sample_q_sha=q_sha
    runner=sources.completed_final_runner();need(runner==expected['runner'],'output_source_changed')
    identity=_output_host(sources);matches_worker=[w for w in expected['worker_generations'].values()
        if w['identity']['machine_id']==identity['machine_id']]
    need(len(matches_worker)==1,'output_binding');expected_worker=matches_worker[0]
    actual=_output_worker(dict(node=expected_worker['node'],identity=identity,
        unit=sources.output_unit_generation('slurmd.service',readonly=False)))
    need(actual==expected_worker and sources.qualification['write_domain']['writer_hosts'].get(actual['node'])==identity['machine_id'],
         'output_binding')
    sources.qualify();need(sources._qualification_sha256==q_sha and sources.qualification.get('completed_final')==expected,'output_binding')
    value=dict(worker=actual,runner=runner);sources.budget.reserve(2*len(encoded(value)))
    need(len(encoded(value))<=16384,'output_bound');return value


def _worker_output_sources():
    need(os.getuid()==os.geteuid()==0,'root_required');budget=_bootstrap_operation()
    try:policy=_load_policy('worker',budget)
    except Hold as error:
        if error.reason=='native_policy_missing':return None
        raise
    try:raw=protected_read(policy['qualification_file'],budget)
    except FileNotFoundError:return None
    q=strict_json(raw.decode());need(type(q) is dict,'output_binding')
    if 'completed_final' not in q:return None
    sources=NativeSources(policy,budget);sources.qualify();return sources


def _scheduler_output_entries(sources,store,jobs,context,runner,guard):
    from host_resource_facts import _output_native_tuple,parse_slurm_jobs
    budget=sources.budget;eligible_jobs={key:row for key,row in jobs.items() if row.get('state')=='COMPLETED' and
        row.get('terminal') is True and row.get('exit_code')=='0:0' and row.get('owner_uid')==3000}
    if not eligible_jobs:return {}
    admitted=[];associated=set();root=store.root/'attempts'
    try:
        with store.directory(root):paths=list(budget.entries(root,'attempt'))
    except FileNotFoundError:return {}
    # The existing finite metadata inventory precedes every output barrier.
    # Unknown files/directories do not expand the declared retained scope.
    for path in paths:
        canonical_uuid(path.name);calcjob=path.name
        with store.locked(calcjob,budget,existing_only=True):
            records={name:store.read(calcjob,name,budget) for name in
                ('claim.json','dispatch.json','ack.json','job.json','allocation.json')}
            ids={value.get('job_id') for name,value in records.items() if name in
                ('ack.json','job.json','allocation.json') and type(value) is dict}
            matches=ids&eligible_jobs.keys()
            if not matches:continue
            need(len(matches)==1 and ids==matches and not matches&associated,'native_job_ambiguous')
            associated.update(matches);job_id=next(iter(matches))
            need(all(type(value) is dict for value in records.values()),'partial_claim')
            closed=store.read(calcjob,'close.json',budget);witness=store.read(calcjob,'close-observation.json',budget)
            need((closed is None)==(witness is None),'q1_close_publication_unknown')
            if closed is None:continue
            validate_reply(closed,historical=True)
            if closed['version']!=3:continue
            technical=_technical_control(closed['technical_control'])
            if technical['status']=='present':continue
            need(closed['state']=='closed' and closed['calcjob_uuid']==calcjob and
                type(witness) is dict and witness.get('job')==records['allocation.json'] and
                witness.get('launch')==records['claim.json']['launch'],'q1_close_conflict')
            budget.reserve(8*len(encoded(records))+8*len(encoded(closed)))
            admitted.append((calcjob,job_id,records,closed))
            need(len(admitted)<=8,'output_bound')
    outputs={}
    for calcjob,job_id,original,closed in admitted:
        with store.locked(calcjob,budget,existing_only=True):
            records={name:store.read(calcjob,name,budget) for name in original}
            need(records==original,'native_dispatch_join_missing');guard()
            observed_job=sources.native_job(job_id);raw=observed_job['raw'];fields=observed_job['fields']
            pairs=re.findall(r'(?<!\S)(\w+)=([^\s]+)',raw)
            need(len(pairs)==len(dict(pairs)) and dict(pairs)==fields,'native_job_changed')
            parsed=parse_slurm_jobs(raw,cluster=sources.policy['slurm']['cluster'])
            need(set(parsed)=={job_id} and _output_native_tuple(parsed[job_id])==_output_native_tuple(jobs[job_id]),'native_job_changed')
            joined=_output_original_records(sources,calcjob,records,parsed[job_id],fields,context)
            launch=joined['launch'];job=joined['job'];domain=launch['relative_execution_root']
            domain_path=store.root/'domains'/hashlib.sha256(domain.encode()).hexdigest()
            need(strict_json(protected_read(domain_path,budget).decode())==dict(calcjob_uuid=calcjob,domain=domain),'output_domain_claimed')
            _output_release_source(sources,calcjob,joined,runner)
            document=dict(version=3,action='close',calcjob_uuid=calcjob,launch=launch,
                controls=_close_controls(closed['controls']),technical_control=_technical_control(closed['technical_control']))
            observed=sources.worker(job,calcjob,'status',budget)
            need(_output_native_tuple(_closed_native_status(observed,job))==_output_native_tuple(parsed[job_id]),'native_job_changed')
            inputs=dict(calcjob_uuid=calcjob,runner=runner,worker_boot_id=job['worker_boot_id'],
                output_root=sources.policy['jobs_root']+'/'+domain)
            proof=OrdinaryAttemptOwner(sources.policy,store,sources,budget)._close(document,job,context,observed,
                document['controls'],facts_guard=guard,facts_inputs=inputs)
            latest=proof['current_worker'];actual=_closed_native_status(latest,job)
            need(_output_native_tuple(actual)==_output_native_tuple(parsed[job_id]),'native_job_changed')
            generation=proof['w1_after']['output_generation'];expected=sources.qualification['completed_final']
            need(generation==proof['w1_before']['output_generation'] and
                hashlib.sha256(encoded(generation)).hexdigest()==expected['unit_generation_sha256'],'output_binding')
            worker=generation['workers'];selected=[w for w in worker if w['node']==job['node_name']]
            need(len(selected)==1 and selected[0]['identity']['machine_id']==job['worker_machine_id'] and
                selected[0]['identity']['boot_id']==job['worker_boot_id'],'worker_generation_changed')
            birth=proof['control_read']['binding']['root_birth']
            before=proof['original_observation'][0]['worker_close']['before']
            need(type(before) is dict,'native_start_not_observed')
            for row in before.get('processes',[]):
                if row.get('pid')==int(birth['producer_pid']):
                    need(row.get('start_ticks')==int(birth['producer_start_ticks']),'output_binding')
            _output_release_source(sources,calcjob,joined,runner);guard()
            q=sources.qualification;owner=dict(policy_sha256=sources.policy['_policy_sha256'],
                qualification_sha256=sources._qualification_sha256,source_graph_sha256=runner['source_graph_sha256'],
                unit_generation_sha256=expected['unit_generation_sha256'],storage_identity=q['write_domain']['storage_identity'],
                retention_ref=q['write_domain']['retention_ref'])
            controls={row['path']:row for row in document['controls']}
            value=dict(generation=parsed[job_id]['generation'],durable=True,scope='completed_final',observed_at=int(time.time()),
                controller_identity=generation['controller']['identity'],worker_identity=selected[0]['identity'],owner=owner,
                attempt=dict(calcjob_uuid=calcjob,dispatch_id=job['dispatch_id'],generation=job['generation']),
                native_tuple=_output_native_tuple(parsed[job_id]),publication=dict(
                    close_sha256=hashlib.sha256(proof['original_close'][1]).hexdigest(),
                    close_observation_sha256=hashlib.sha256(proof['original_observation'][1]).hexdigest(),
                    result_sha256=controls['series_result.json']['sha256'],selection_sha256=controls['native-selection.json']['sha256']))
            _reserve_private_record(value,budget);need(len(encoded(value))<=8192,'output_bound')
            need(value['generation'] not in outputs,'native_job_ambiguous');outputs[value['generation']]=value
    return outputs


def capture_scheduler_output_facts():
    """Existing fixed root facts route, with one inherited finite operation.

    The optional qualification is deliberately absent on old installations.
    Its absence retains the complete scheduler snapshot and grants no output
    authority. Present strong observations must all close or the packet fails.
    """
    import host_resource_service as service
    from host_resource_facts import LocalSources,capture_scheduler,_scheduler_output_observations
    need(os.getuid()==os.geteuid()==0,'root_required');budget=_bootstrap_operation()
    def configuration():
        raw=protected_read(service.CONFIG,budget,262144);budget.reserve(8*len(raw))
        return raw,service.validate_service_config(strict_json(raw.decode()))
    raw_config,config=configuration();probe=NativeSources({},budget)
    ingress=service._scheduler_facts_ingress(probe,config)
    try:policy=_load_policy('controller',budget)
    except Hold as error:
        if error.reason!='native_policy_missing':raise
        policy=None
    source=None;qraw=None;context=None;runner=None
    if policy is not None:
        need(policy['facts_service_config']==str(service.CONFIG) and policy['slurm']['config_file']==config['slurm_conf'] and
            policy['slurm']['cluster']==config['cluster'] and policy['tools']['scontrol']==config['scontrol'],'output_binding')
        try:qraw=protected_read(policy['qualification_file'],budget)
        except FileNotFoundError:pass
        if qraw is not None:
            q=strict_json(qraw.decode());need(type(q) is dict,'output_binding')
            if 'completed_final' in q:
                source=NativeSources(policy,budget);context=source.qualify()
                need(source._qualification_sha256==hashlib.sha256(qraw).hexdigest(),'output_binding')
                runner=source.completed_final_runner()
    def guard():
        fresh,_=configuration();need(fresh==raw_config,'facts_entry_changed')
        need(service._scheduler_facts_ingress(probe,config)==ingress,'facts_entry_changed')
        if source is not None:
            need(protected_read(POLICY,budget)==policy_raw,'policy_changed')
            need(protected_read(policy['qualification_file'],budget)==qraw,'output_binding')
            need(source.host()==context,'controller_generation_changed')
    policy_raw=protected_read(POLICY,budget) if source is not None else None
    if source is not None:need(hashlib.sha256(policy_raw).hexdigest()==policy['_policy_sha256'],'policy_changed')
    # Preserve the scheduler's original 256-KiB command cap and environment,
    # while every command spends this same operation/deadline.
    need(type(config['tools']) is list and 0<len(config['tools'])<=64,'policy_tool')
    for tool in config['tools']:budget.file();path_value(tool,absolute=True)
    command_runner=service.NativeCommandRunner(config['tools'],slurm_conf=config['slurm_conf'])
    local=LocalSources(config,command_runner)
    def run(argv):
        need(type(argv) in (list,tuple) and argv and argv[0] in command_runner.tools and
             all(type(arg) is str and '\x00' not in arg for arg in argv),'policy_tool')
        need(probe.origin(argv[0])==argv[0],'native_tool_changed')
        return budget.command(argv,env=command_runner.environment,output_bytes=262144)
    local.run=run
    jobs=capture_scheduler(config,local)
    outputs={} if source is None else _scheduler_output_entries(source,AttemptStore(policy['private_root']),jobs,context,runner,guard)
    guard()
    if source is not None:
        need(source.qualify()==context and source._qualification_sha256==hashlib.sha256(qraw).hexdigest() and
            source.completed_final_runner()==runner,'output_binding')
    packet=dict(schema='qcl.host-resource-scheduler-facts.v1',jobs=jobs,outputs=outputs)
    _reserve_private_record(packet,budget);need(len(encoded(packet))<=262144,'output_bound')
    # Reuse the existing closed projection validator before any reply escapes.
    _scheduler_output_observations(packet);budget.before();return packet


def _full_output_generation(sources,controller_units,workers):
    sources.budget.reserve(3*65536)
    binding=_completed_final_binding(sources.qualification['completed_final'],sources.policy['worker_routes'])
    need(type(controller_units) is list and len(controller_units)==2 and
        {row['unit'] for row in controller_units}=={'qcl-negf-aiida.service','qcl-negf-api.service'},'output_binding')
    units=[];prefix=sources.policy['jobs_root']+'/'+sources.policy['native_result_prefix']
    for row in sorted(controller_units,key=lambda value:value['unit']):
        unit=_output_unit(row['output_unit']);need(unit['name']==row['unit'],'output_binding')
        need(_output_mount_line(unit['mount_line'],prefix,sources.policy['nfs_source'],True)==unit['mount_line'],'output_binding')
        units.append(unit)
    need(type(workers) is list and len(workers)==len(sources.policy['worker_routes']) and
        {row['node'] for row in workers}==set(sources.policy['worker_routes']),'output_binding')
    actual_workers=[]
    for row in sorted(workers,key=lambda value:value['node']):
        value=row['reply']['writer_snapshot'].get('output_generation')
        exact(value,{'worker','runner'});_output_runner(value['runner']);worker=_output_worker(value['worker'])
        need(value['runner']==binding['runner'] and worker==binding['worker_generations'][row['node']] and
            worker['identity']['machine_id']==sources.qualification['write_domain']['writer_hosts'][row['node']],'output_binding')
        need(_output_mount_line(worker['unit']['mount_line'],prefix,sources.policy['nfs_source'],False)==worker['unit']['mount_line'],'output_binding')
        actual_workers.append(worker)
    generation=dict(controller=dict(identity=_output_host(sources),units=units),workers=actual_workers)
    raw=encoded(generation);need(len(raw)<=65536 and hashlib.sha256(raw).hexdigest()==binding['unit_generation_sha256'],'output_binding')
    return generation


def _caller_generation(row):
    need(engine.process_state_class(row) == 'live', 'peer_not_live')
    need(type(row['pid']) is int and type(row['start_ticks']) is int and row['start_ticks'] > 0, 'peer_credentials')
    return {key: row[key] for key in ('pid','ppid','start_ticks','uids','cgroup','executable','comm')}


def _caller_role(sources, row, argv, role, action, context):
    cfg = context['configuration']; client = cfg['client']
    if role == 'client':
        need(argv == client['argv_prefix'] + [action] and row['executable'] == sources.origin(client['argv_prefix'][0]),
             'peer_client_origin')
        return
    if role == 'shell':
        alias = '/run/current-system/sw/bin/qcl-negf-native-attempt-client'
        need(sources.origin(alias) == sources.origin(client['entrypoint']) and
             row['executable'] == sources.origin(client['bash_executable']) and
             argv == ['bash','--noprofile','--norc','-c',shlex.join([alias,action])], 'peer_shell_origin')
        return
    tail = {'worker':['daemon','worker'], 'circus':['daemon','start-circus','1','--foreground'],
            'main':['daemon','start','--foreground']}[role]
    suffix = ['-p',cfg['profile'],*tail]
    # A currently resolved mutable profile or shared canonical core script
    # cannot certify which APP this already-running Python loaded at startup.
    entrypoints = {context['app']+'/bin/verdi'}
    need(row['executable'] == sources.qualification['unit_origins'][sources.policy['daemon_unit']]['executable'],
         'application_origin')
    if len(argv) == len(suffix) + 1:
        need(argv[0] in entrypoints and sources.origin(argv[0]) == row['executable'] and argv[1:] == suffix,
             'application_origin')
    else:
        need(len(argv) == len(suffix)+2 and argv[1] in entrypoints and argv[2:] == suffix and
             sources.origin(argv[0]) == row['executable'], 'application_origin')


def _review_native_script(raw, launch, solver, bash, sources, *, calcjob_uuid):
    """One stock script subset; never execute or interpret arbitrary shell."""
    canonical_uuid(calcjob_uuid)
    lines = [line for line in raw.decode('utf-8').splitlines() if line]
    need(lines and lines[0].startswith('#!'), 'native_script')
    interpreter = lines.pop(0)[2:]
    need(interpreter in (bash,'/run/current-system/sw/bin/bash') and
         sources.origin(interpreter)==sources.origin(bash), 'native_script_interpreter')
    sources.origin('/run/current-system/sw/bin/qcl-negf-release')
    headers = {}
    while lines and lines[0].startswith('#SBATCH '):
        line = lines.pop(0)[len('#SBATCH '):]; key,sep,value = line.partition('=')
        need(key not in headers, 'native_script_directive')
        allowed = {'--no-requeue','--job-name','--get-user-env','--output','--error','--nodes',
                   '--ntasks-per-node','--cpus-per-task','--partition','--account','--qos','--time','--mem'}
        need(key in allowed, 'native_script_directive'); headers[key] = value
        if key in ('--no-requeue','--get-user-env'): need(not sep, 'native_script_directive')
        elif key=='--job-name': need(re.fullmatch(r'"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"',value), 'native_script_directive')
        elif key in ('--partition','--account','--qos'): need(matches(value,ID), 'native_script_directive')
        elif key=='--time': need(re.fullmatch(r'(?:[0-9]+-)?[0-9]{2}:[0-5][0-9]:[0-5][0-9]',value), 'native_script_directive')
        elif key=='--mem': need(re.fullmatch(r'[0-9]+',value), 'native_script_directive')
    need(headers.get('--no-requeue')=='' and '--job-name' in headers and
         headers.get('--output')=='_scheduler-stdout.txt' and headers.get('--error')=='_scheduler-stderr.txt' and
         headers.get('--nodes')==headers.get('--ntasks-per-node')=='1' and
         re.fullmatch(r'[1-9][0-9]*',headers.get('--cpus-per-task','')), 'native_script_resources')
    need(len(lines)==7 and lines[0]=='# ENVIRONMENT VARIABLES BEGIN ###' and
         lines[3]=='# ENVIRONMENT VARIABLES END ###', 'native_script')
    expected_exports = {"export JULIA_NUM_THREADS='"+headers['--cpus-per-task']+"'", "export OPENBLAS_NUM_THREADS='1'"}
    need(set(lines[1:3])==expected_exports, 'native_script_environment')
    guard = ('/run/current-system/sw/bin/qcl-negf-release guard --release-id '+shlex.quote(launch['release_id'])+
             ' --solver-executable '+shlex.quote(solver)+' || exit 78')
    capture_export = ('export QCL_NEGF_CAPTURE_SPEC=capture-spec.json '
                      'QCL_NEGF_NATIVE_CAPTURE_INPUT=native-execution.json')
    need(lines[4]==guard and lines[5] in ('unset QCL_NEGF_CAPTURE_SPEC',capture_export), 'native_script_guard')
    argv = [solver,'run-plan','plan.json',sources.policy['jobs_root']+'/'+launch['relative_execution_root'],
            '--execution-id',launch['execution_id'],'--source-graph','source-graph.json']
    # Stock Scheduler single-quotes every code argument. A free shell token or
    # extra flag never becomes authority by merely producing the same shlex words.
    literal = lambda word: "'"+word.replace("'", "'\"'\"'")+"'"
    native_argv = argv + ['--native-execution','native-execution.json','--native-calcjob-uuid',calcjob_uuid]
    expected = [' '.join(literal(word) for word in words)+"  > 'solver.stdout' 2> 'solver.stderr'"
                for words in (argv,native_argv)]
    if '--scratch-root' in lines[6]: raise Hold('native_scratch_binding_unavailable')
    # The legacy seven-argument class stays unmapped; neither branch is itself
    # proof of invocation birth or of a qualified native producer.
    need(lines[6] in (expected[1:] if lines[5]==capture_export else expected), 'native_script_argv')


def _reserve_private_record(value, budget, depth=0):
    """Prepay only the existing journal's JSON encoding, with no new codec."""
    need(depth<=16, 'private_record_bound'); budget.reserve(32)
    if type(value) is str: budget.reserve(12*len(value))
    elif type(value) is int: budget.reserve(value.bit_length()*30103//100000+2)
    elif type(value) is dict:
        for key,item in value.items():
            need(type(key) is str, 'private_record_bound')
            _reserve_private_record(key,budget,depth+1); _reserve_private_record(item,budget,depth+1)
    elif type(value) in (list,tuple):
        for item in value: _reserve_private_record(item,budget,depth+1)
    else: need(value is None or type(value) in (bool,int,float), 'private_record_bound')


def authenticate_socket_peer(connection, policy, sources, *, action):
    pid, uid, gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    need(pid > 0 and uid == gid == policy['client_uid'], 'peer_credentials')
    context = sources.actor_context(); unit = sources.unit(policy['daemon_unit'])
    need(unit['ActiveState'] == 'active' and matches(unit['InvocationID'], r'[0-9a-f]{32}') and
         int(unit['MainPID']) > 0, 'peer_unit')
    chain = []; current = pid; seen = set()
    for _ in range(16):
        need(current > 1 and current not in seen, 'peer_ancestry')
        seen.add(current); row = sources.process(current); _caller_generation(row)
        need(row['pid'] == current and row['uids'] == [uid]*4 and
             engine.daemon_scope_bound(row['cgroup'],unit['ControlGroup']), 'peer_unit')
        argv = sources.command_line(current); env = sources.selected_environment(current)
        chain.append({'process':row,'argv':argv,'environment':env})
        if current == int(unit['MainPID']): break
        current = row['ppid']
    else: raise Hold('peer_ancestry_bound')
    need(len(chain) in (4,5), 'peer_ancestry')
    roles = ['client'] + (['shell'] if len(chain)==5 else []) + ['worker','circus','main']
    for index,(entry,role) in enumerate(zip(chain,roles)):
        row = entry['process']; _caller_role(sources,row,entry['argv'],role,action,context)
        # Pinned AiiDA 2.9.2 MainPID starts with the configured base, while
        # DaemonClient.get_env propagates its actual config dir to descendants.
        cfg = context['configuration']
        need(entry['environment'] == {'AIIDA_PATH':cfg['aiida_path']+('' if role=='main' else '/.aiida'),
                                     'QCL_NEGF_NATIVE_JOBS_ROOT':cfg['jobs_root']}, 'peer_environment')
        if index+1 < len(chain):
            parent = chain[index+1]['process']
            need(row['ppid'] == parent['pid'] and parent['start_ticks'] <= row['start_ticks'], 'peer_birth_join')
        need(_caller_generation(row) == _caller_generation(sources.process(row['pid'])) and
             entry['argv'] == sources.command_line(row['pid']) and
             entry['environment'] == sources.selected_environment(row['pid']), 'peer_generation_changed')
    profile = sources.profile_view(int(unit['MainPID']),context)
    need(unit == sources.unit(policy['daemon_unit']) and context == sources.actor_context() and
         profile == sources.profile_view(int(unit['MainPID']),context), 'peer_generation_changed')
    sources._connection = connection
    return {'pid':pid,'chain':chain,'unit':unit,'application':context,'profile':profile}


def read_frame(connection, budget, limit):
    def receive(size):
        raw = bytearray()
        while len(raw) < size:
            budget.before(); connection.settimeout(max(.001, budget.deadline - time.monotonic()))
            chunk = connection.recv(size - len(raw))
            need(chunk, 'frame_truncated'); raw.extend(chunk)
        return bytes(raw)
    size = struct.unpack('!I', receive(4))[0]
    need(0 < size <= limit, 'frame_bound'); budget.reserve(size * 2)
    raw = receive(size)
    budget.before(); need(connection.recv(1) == b'', 'frame_extra')
    try:
        document = strict_json(raw.decode('utf-8'))
        need(type(document) is dict, 'frame_shape')
        return document
    except (ValueError, UnicodeError, ResourceError) as error:
        raise Hold('frame_json') from error


def write_frame(connection, document, budget, limit):
    raw = encoded(document); need(len(raw) <= limit, 'frame_bound'); budget.reserve(len(raw))
    budget.before(); connection.settimeout(max(.001, budget.deadline - time.monotonic()))
    connection.sendall(struct.pack('!I', len(raw)) + raw)


def _original_input_limit(role, policy):
    # Fixed original roles: only plan follows the existing capture plan allowance.
    return 1048576 if role == 'plan' else policy['limits']['script_bytes'] if role == 'submit_script' else 65536


def _owner_read(policy, launch, budget, *, controls=None, technical_control=None):
    """Runs ONLY after dropping credentials in production; no root NFS access."""
    need(os.getuid() == os.geteuid() == policy['client_uid'], 'owner_read_credentials')
    if controls is not None:
        return _owner_close_read(policy,launch,budget,controls,technical_control=technical_control)
    need(technical_control is None, 'q1_technical_unavailable')
    work = path_value(launch['remote_workdir'], absolute=True)
    need(within(work, policy['jobs_root']) and work != policy['jobs_root'], 'upload_namespace')
    # Walk every component using directory FDs. Symlinks, including parent aliases, fail.
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    walked = []
    try:
        for part in Path(work).parts[1:]:
            budget.file(); next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            walked.append((os.dup(parent), part, os.fstat(next_fd)))
            os.close(parent); parent = next_fd
        original = os.fstat(parent); result = {}; script = None
        for role, name in FILES.items():
            claim = launch['files'][role]
            limit = _original_input_limit(role, policy)
            need(claim['bytes'] <= limit, 'submitted_bound')
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                raw, info = read_fd(fd, limit, budget)
                need(info.st_uid == policy['client_uid'] and not info.st_mode & 0o022 and
                     signature(info) == signature(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'submitted_identity')
                observed = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
                need(observed == claim, 'submitted_digest')
                result[role] = observed
                if role == 'submit_script':
                    script = base64.b64encode(raw).decode('ascii')
            finally:
                os.close(fd)
        need(signature(original) == signature(os.fstat(parent)), 'submitted_directory_changed')
        for directory, name, info in walked:
            need(signature(info) == signature(os.stat(name, dir_fd=directory, follow_symlinks=False)), 'submitted_directory_changed')
        return {'files': result, 'script': script}
    finally:
        os.close(parent)
        for directory, _, _ in walked:
            os.close(directory)


def _owner_close_read(policy, launch, budget, controls, *, technical_control=None,
                      durable=False, solver_logs=False, barrier=None,native_inputs=None):
    need(os.getuid()==os.geteuid()==policy['client_uid'], 'owner_read_credentials')
    need(type(durable) is bool and type(solver_logs) is bool and
         (barrier is None or callable(barrier)) and (not durable or barrier is not None), 'owner_read_mode')
    controls = _close_controls(controls); rows = []; roots = []; actual = []; logs = []
    technical = None if technical_control is None else _technical_control(technical_control)
    need(not solver_logs or (technical is not None and technical['status']=='absent'), 'output_scope_unsupported')
    need(native_inputs is None or (durable and solver_logs and barrier is not None),'owner_read_mode')
    credit=getattr(budget,'_owner_read_credit',None)
    initial_bytes=budget.actual_bytes
    initial_files=budget.files if credit is None else credit[1]
    result = path_value(policy['jobs_root']+'/'+launch['relative_execution_root'],absolute=True)
    work = path_value(launch['remote_workdir'],absolute=True)
    need(within(result,policy['jobs_root']+'/'+policy['native_result_prefix']) and
         within(work,policy['jobs_root']) and not within(work,result) and not within(result,work), 'output_namespace')
    if native_inputs is not None:
        exact(native_inputs,{'calcjob_uuid','runner','worker_boot_id','output_root'})
        need(native_inputs['output_root']==result,'output_namespace')
    captured={};binding=None
    json_names={'plan.json','source-graph.json','native-execution.json','capture-spec.json','capture-source.json','series_result.json','native-selection.json'}
    held = []; files = []; directories = []; absent = []; primary = None
    def retain(fd):
        held.append(fd); return fd
    def named(parent,name,claim,limit,role):
        _owner_read_file(budget)
        fd=retain(os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent))
        raw,info=read_fd(fd,limit,budget)
        _owner_read_file(budget)
        need(info.st_uid==policy['client_uid'] and not info.st_mode&0o022 and
             signature(info)==signature(os.stat(name,dir_fd=parent,follow_symlinks=False)), 'q1_file_identity')
        observed=dict(path=name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        if claim is not None:need(observed==claim, 'q1_control_changed')
        if native_inputs is not None and name in json_names:captured[name]=raw
        rows.append(dict(path=name,root=role,signature=signature(info)))
        files.append((fd,parent,name,info,observed))
        if durable:
            _owner_read_file(budget); os.fsync(fd)
        del raw
        return observed
    def verify_names():
        # An absence observation can race a publication. Check named parent
        # generations afterwards, including the legacy single-pass Q1 path.
        for parent,name in absent:
            _owner_read_file(budget)
            try:os.stat(name,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError:pass
            else:raise Hold('q1_technical_changed')
        for fd,parent,name,info,_ in files:
            _owner_read_file(budget)
            need(signature(os.fstat(fd))==signature(info)==
                 signature(os.stat(name,dir_fd=parent,follow_symlinks=False)), 'q1_file_identity')
        for fd,parent,name,info,_ in directories:
            _owner_read_file(budget)
            need(signature(os.fstat(fd))==signature(info)==
                 signature(os.stat(name,dir_fd=parent,follow_symlinks=False)), 'q1_directory_changed')
    def metadata():
        value=dict(controls=actual,roots=roots,files=rows,
            io=dict(actual_bytes=budget.actual_bytes-initial_bytes,file_operations=budget.files-initial_files if credit is None else initial_files-credit[1]))
        if technical is not None:value['technical_control']=technical
        if solver_logs:value['logs']=logs
        if binding is not None:value['binding']=binding
        return value
    try:
        for role,path,selected in (('result',result,controls[:2]),('workdir',work,controls[2:])):
            _owner_read_file(budget); parent=retain(os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW))
            walked=[]; current=''
            for name in Path(path).parts[1:]:
                _owner_read_file(budget);child=retain(os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent))
                info=os.fstat(child)
                need(info.st_uid in (0,policy['client_uid']) and not info.st_mode&0o022, 'q1_directory_identity')
                current+='/'+name
                directories.append((child,parent,name,info,current))
                walked.append((name,info));parent=child
            directory=os.fstat(parent)
            for claim in selected:actual.append(named(parent,claim['path'],claim,claim['bytes'],role))
            if role=='result' and technical is not None:
                if technical['status']=='absent':
                    absent.append((parent,TECHNICAL_FILE))
                else:
                    observed=named(parent,TECHNICAL_FILE,None,int(technical['bytes']),role)
                    need(dict(status='present',path=TECHNICAL_FILE,bytes=str(observed['bytes']),
                         sha256=observed['sha256'])==technical, 'q1_technical_changed')
            if role=='workdir' and solver_logs:
                for name in ('solver.stdout','solver.stderr'):logs.append(named(parent,name,None,65536,role))
            if role=='workdir' and native_inputs is not None:
                for source_role,name in FILES.items():
                    claim=launch['files'][source_role]
                    cap={'plan':1048576,'source_graph':65536,'native_execution':16384,'submit_script':policy['limits']['script_bytes']}[source_role]
                    need(type(claim['bytes']) is int and 0<=claim['bytes']<=cap,'submitted_bound')
                    named(parent,name,dict(path=name,**claim),claim['bytes'],role)
                for name in ('capture-spec.json','capture-source.json'):named(parent,name,None,16384,role)
            roots.append(dict(role=role,path=path,directory=signature(directory),
                ancestors=[dict(name=name,signature=signature(info)) for name,info in walked]))
        if native_inputs is not None:
            _owner_read_reserve(budget,8*sum(len(raw) for raw in captured.values())+4096)
            binding=_completed_metadata(launch,native_inputs,captured,roots[0]['directory'][:2]);captured.clear()
        if durable:
            synced=set()
            # Only the finite opened publication ancestors inside the owned jobs
            # root; no enumeration or syncing unrelated system/NFS payloads.
            for fd,_,_,info,path in sorted(directories,key=lambda row:len(Path(row[4]).parts),reverse=True):
                key=(info.st_dev,info.st_ino)
                if within(path,policy['jobs_root']) and key not in synced:
                    _owner_read_file(budget);os.fsync(fd);synced.add(key)
        verify_names()
        if barrier is not None:
            # Production child exchanges only bounded metadata with the parent;
            # every named file/ancestor FD stays held through its post-W1 guard.
            barrier(metadata())
            verify_names()
            for fd,_,_,info,expected in files:
                _owner_read_file(budget);os.lseek(fd,0,os.SEEK_SET)
                raw,latest=read_fd(fd,expected['bytes'],budget)
                need(signature(latest)==signature(info) and len(raw)==expected['bytes'] and
                     hashlib.sha256(raw).hexdigest()==expected['sha256'], 'q1_control_changed')
                del raw
            verify_names()
        return metadata()
    except BaseException as error:
        primary=error;raise
    finally:
        cleanup=None
        for fd in reversed(held):
            try:os.close(fd)
            except BaseException as error:
                if primary is not None:primary.add_note('held output cleanup also raised '+type(error).__name__)
                elif cleanup is None:cleanup=error
                else:cleanup.add_note('held output cleanup also raised '+type(error).__name__)
        if primary is None and cleanup is not None:raise cleanup


def _held_read_forecast(policy,launch,controls,technical,solver_logs,cap,native_inputs=None):
    paths=(path_value(policy['jobs_root']+'/'+launch['relative_execution_root'],absolute=True),
           path_value(launch['remote_workdir'],absolute=True))
    depth=sum(len(Path(path).parts)-1 for path in paths)
    sizes=[row['bytes'] for row in controls]
    if technical is not None and technical['status']=='present':sizes.append(int(technical['bytes']))
    if solver_logs:sizes.extend((65536,65536))
    workspace=0
    if native_inputs is not None:
        exact(native_inputs,{'calcjob_uuid','runner','worker_boot_id','output_root'})
        canonical_uuid(native_inputs['calcjob_uuid']);canonical_uuid(native_inputs['worker_boot_id']);_output_runner(native_inputs['runner'])
        need(native_inputs['output_root']==paths[0],'output_namespace')
        for role in FILES:
            size=launch['files'][role]['bytes']
            maximum={'plan':1048576,'source_graph':65536,'native_execution':16384,'submit_script':policy['limits']['script_bytes']}[role]
            need(type(size) is int and 0<=size<=maximum,'submitted_bound');sizes.append(size)
        sizes.extend((16384,16384))
        workspace=8*(sum(row['bytes'] for row in controls[:2])+sum(launch['files'][role]['bytes'] for role in
            ('plan','source_graph','native_execution'))+2*16384)+4096
    # Two finite reads per named file, including each read_fd EOF request.
    # Unexpected repeated short reads exhaust this slice before another read.
    # Held-mode read_fd uses the admitted fstat size, not the loose leaf ceiling.
    # Each complete read + EOF fits two(size+1) slices; two passes fit four.
    # Repeated unexpected short reads still refuse before crossing prepaid credit.
    reader_bytes=4*sum(size+1 for size in sizes)+workspace
    file_operations=8*depth+16*len(sizes)+16
    # Both bounded frames, their detached JSON values and named path metadata.
    envelope=8*cap+4096*(depth+4)+8*len(encoded(controls))
    if technical is not None:envelope+=8*len(encoded(technical))
    if native_inputs is not None:envelope+=8*len(encoded(native_inputs))
    return reader_bytes,file_operations,envelope,2*sum(sizes)


def _read_held_files_as_owner(policy,launch,budget,controls,technical,solver_logs,barrier,native_inputs=None):
    """Private child handshake; the parent's W1 guard runs while owner FDs live."""
    import selectors
    cap=min(policy['limits']['response_bytes'],65536)
    reader_bytes,file_operations,envelope,actual_bound=_held_read_forecast(
        policy,launch,controls,technical,solver_logs,cap,native_inputs)
    # The same Operation owns the entire nonrefundable reservation BEFORE pipe
    # or fork. Only these two already-paid child slices can be consumed locally.
    need(not hasattr(budget,'_owner_read_credit'),'owner_read_reservation')
    budget.reserve(reader_bytes+envelope)
    for _ in range(file_operations):budget.file()
    incoming=outgoing=release_read=release_write=None;pid=None;reaped=False;selector=None;primary=None
    try:
        incoming,outgoing=os.pipe2(os.O_CLOEXEC)
        release_read,release_write=os.pipe2(os.O_CLOEXEC)
        pid=os.fork()
        if pid==0:
            initial_actual=budget.actual_bytes
            try:
                os.close(incoming);os.close(release_write)
                os.setgroups([]);os.setgid(policy['client_uid']);os.setuid(policy['client_uid'])
                budget._owner_read_credit=[reader_bytes,file_operations]
                def send(value):
                    raw=encoded(value);need(len(raw)<=cap,'owner_read_bound')
                    raw=struct.pack('!I',len(raw))+raw;offset=0
                    while offset<len(raw):
                        budget.before();count=os.write(outgoing,raw[offset:])
                        need(count>0,'owner_read_short_write');offset+=count
                def exchange(value):
                    send(value);budget.before()
                    # Parent cancellation kills only this private child. Its
                    # inherited deadline remains the owner service's deadline.
                    waiter=selectors.DefaultSelector()
                    try:
                        waiter.register(release_read,selectors.EVENT_READ)
                        while not waiter.select(min(.1,max(.001,budget.deadline-time.monotonic()))):budget.before()
                        budget.before();need(os.read(release_read,2)==b'1','owner_read_release')
                    finally:waiter.close()
                value=_owner_close_read(policy,launch,budget,controls,technical_control=technical,
                    durable=True,solver_logs=solver_logs,barrier=exchange,native_inputs=native_inputs)
                send(value)
                os.close(release_read);os.close(outgoing)
                os._exit(0)
            except BaseException as error:
                try:
                    send(dict(failure=type(error).__name__,message=str(error)[:4096],
                        reason=error.reason if isinstance(error,Hold) else 'owner_read_failed',
                        actual_bytes=budget.actual_bytes-initial_actual))
                except BaseException:pass
                os._exit(1)
        os.close(outgoing);outgoing=None;os.close(release_read);release_read=None
        selector=selectors.DefaultSelector();selector.register(incoming,selectors.EVENT_READ)
        def receive(size):
            raw=bytearray()
            while len(raw)<size:
                budget.before()
                if not selector.select(min(.1,max(.001,budget.deadline-time.monotonic()))):continue
                chunk=os.read(incoming,size-len(raw));need(chunk,'owner_read_failed')
                raw.extend(chunk);budget.actual_bytes+=len(chunk)
            return bytes(raw)
        def frame():
            size=struct.unpack('!I',receive(4))[0];need(0<size<=cap,'owner_read_bound')
            value=strict_json(receive(size).decode());need(type(value) is dict,'owner_read_bound')
            return value
        reported_actual=0
        def account(value):
            nonlocal reported_actual
            count=value.get('actual_bytes') if 'failure' in value else value['io']['actual_bytes']
            need(type(count) is int and reported_actual<=count<=actual_bound,'owner_read_bound')
            budget.actual_bytes+=count-reported_actual;reported_actual=count
        first=frame();account(first)
        if 'failure' not in first:
            barrier(first);budget.before();need(os.write(release_write,b'1')==1,'owner_read_release')
            value=frame()
        else:value=first
        os.close(release_write);release_write=None
        while True:
            budget.before()
            if selector.select(min(.1,max(.001,budget.deadline-time.monotonic()))):
                need(os.read(incoming,1)==b'','owner_read_extra');break
        while True:
            budget.before();waited,status=os.waitpid(pid,os.WNOHANG)
            if waited:reaped=True;break
            time.sleep(.005)
        account(value)
        if os.waitstatus_to_exitcode(status)!=0 or 'failure' in value:
            failure=engine.CommandFailure(value);_preclaim_diagnostic(failure)
            if native_inputs is not None:
                # Only a delivered frame from this owned private child can
                # select these fixed fatal classes. No arbitrary exception
                # import/constructor or public RPC certificate is accepted.
                # Cross-process identity is unavailable; retain class/message
                # and the original bounded frame as the primary cause.
                fatal={'MemoryError':MemoryError,'KeyboardInterrupt':KeyboardInterrupt,
                    'AssertionError':AssertionError,'RuntimeError':RuntimeError,'SystemExit':SystemExit}
                cls=fatal.get(value.get('failure'))
                if cls is not None:raise cls(value.get('message','native reader failed')) from failure
            raise Hold('owner_read_failed') from failure
        need(type(value['io']['file_operations']) is int and
             0<=value['io']['file_operations']<=file_operations,'owner_read_bound')
        return value
    except BaseException as error:
        primary=error;raise
    finally:
        cleanup=None
        for fd in (incoming,outgoing,release_read,release_write):
            if fd is None:continue
            try:os.close(fd)
            except BaseException as error:
                if cleanup is None:cleanup=error
                else:cleanup.add_note('private reader cleanup also raised '+type(error).__name__)
        if selector is not None:
            try:selector.close()
            except BaseException as error:
                if cleanup is None:cleanup=error
        if pid is not None and pid>0 and not reaped:
            try:os.kill(pid,9)
            except ProcessLookupError:pass
            except BaseException as error:
                if cleanup is None:cleanup=error
            try:os.waitpid(pid,os.WNOHANG)
            except ChildProcessError:pass
            except BaseException as error:
                if cleanup is None:cleanup=error
        if cleanup is not None:
            if primary is not None:primary.add_note('private reader cleanup also raised '+type(cleanup).__name__)
            else:raise cleanup


def _read_submitted_files_as_owner(policy, launch, budget, *, controls=None, technical_control=None,
                                  barrier=None,solver_logs=False,native_inputs=None):
    import selectors
    need(os.geteuid() == 0, 'root_required')
    # Reserve the complete bounded child envelope before forking. Charges never reset.
    cap = min(policy['limits']['response_bytes'], 131072 if controls is None else 65536)
    technical = None if technical_control is None else _technical_control(technical_control)
    need(technical is None or controls is not None, 'q1_technical_unavailable')
    need(type(solver_logs) is bool and (barrier is None or callable(barrier)), 'owner_read_mode')
    if barrier is not None:
        need(controls is not None and technical is not None and
             (not solver_logs or technical['status']=='absent'),'owner_read_mode')
        return _read_held_files_as_owner(policy,launch,budget,_close_controls(controls),technical,solver_logs,barrier,native_inputs)
    need(not solver_logs and native_inputs is None,'owner_read_mode')
    technical_bytes = int(technical['bytes']) if technical is not None and technical['status']=='present' else 0
    if controls is not None:
        controls = _close_controls(controls)
        paths = (path_value(policy['jobs_root']+'/'+launch['relative_execution_root'],absolute=True),
                 path_value(launch['remote_workdir'],absolute=True))
        depth = sum(len(Path(path).parts)-1 for path in paths)
        budget.reserve(8*(sum(row['bytes'] for row in controls)+4)+16*65536+4096*(depth+4)+8*len(encoded(controls)))
        if technical is not None:
            budget.reserve(8*(technical_bytes+1)+8*len(encoded(technical))+65536)
        for _ in range(8*depth+64+(8 if technical is not None else 0)):budget.file()
    else:
        budget.reserve(cap * 3); budget.file()
    read_end, write_end = os.pipe2(os.O_CLOEXEC)
    pid = os.fork()
    if pid == 0:
        initial_actual = budget.actual_bytes
        try:
            os.close(read_end); os.setgroups([]); os.setgid(policy['client_uid']); os.setuid(policy['client_uid'])
            options = {} if technical is None else {'technical_control':technical}
            raw = encoded(_owner_read(policy, launch, budget,controls=controls,**options)) if controls is not None else encoded(_owner_read(policy, launch, budget))
            need(len(raw) <= cap, 'owner_read_bound')
            offset = 0
            while offset < len(raw):
                budget.before(); count = os.write(write_end, raw[offset:]); need(count > 0, 'owner_read_short_write'); offset += count
            os._exit(0)
        except BaseException as error:
            if controls is not None:
                try:
                    raw = encoded(dict(failure=type(error).__name__,message=str(error)[:4096],
                                       reason=error.reason if isinstance(error,Hold) else 'owner_read_failed',
                                       actual_bytes=budget.actual_bytes-initial_actual))
                    budget.before();os.write(write_end,raw)
                except BaseException:pass
            os._exit(1)
    os.close(write_end); selector = selectors.DefaultSelector(); raw = bytearray(); reaped = False
    try:
        selector.register(read_end, selectors.EVENT_READ)
        while True:
            budget.before()
            if not selector.select(min(.1, max(.001, budget.deadline - time.monotonic()))):
                continue
            chunk = os.read(read_end, min(65536, cap + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk); need(len(raw) <= cap, 'owner_read_bound')
            if controls is not None:budget.actual_bytes += len(chunk)
        while True:
            budget.before(); waited, status = os.waitpid(pid, os.WNOHANG)
            if waited:
                reaped = True
                if controls is not None and os.waitstatus_to_exitcode(status)!=0:
                    failure = strict_json(raw.decode()) if raw else dict(failure='unknown child outcome')
                    if 'actual_bytes' in failure:
                        count=failure['actual_bytes']
                        need(type(count) is int and 0<=count<=sum(row['bytes'] for row in controls)+technical_bytes+
                             4+(1 if technical is not None else 0), 'owner_read_bound')
                        budget.actual_bytes+=count
                    primary = engine.CommandFailure(failure);_preclaim_diagnostic(primary)
                    raise Hold('owner_read_failed') from primary
                need(os.waitstatus_to_exitcode(status) == 0, 'owner_read_failed'); break
            time.sleep(.005)
        result = strict_json(raw.decode())
        if controls is not None:
            count = result['io']['actual_bytes']
            need(type(count) is int and 0<=count<=sum(row['bytes'] for row in controls)+technical_bytes, 'owner_read_bound')
            budget.actual_bytes += count
        return result
    finally:
        selector.close(); os.close(read_end)
        if not reaped:
            # Only this credential-drop metadata child, never a native job.
            try:
                os.kill(pid, 9)
            except ProcessLookupError:
                pass
            # Do not block on uninterruptible hard-NFS IO; systemd owns the cgroup.
            os.waitpid(pid, os.WNOHANG)


class NativeSources:
    """Fixed native readers. Expectations are re-observed, never accepted as proof."""
    def __init__(self, policy, budget):
        self.policy, self.budget = policy, budget
        self.qualification = None

    def run(self, argv, *, output_bytes=None):
        return self.budget.command(argv, run=engine.command, output_bytes=output_bytes,
                                   env={'PATH': '/empty', 'LANG': 'C', 'LC_ALL': 'C',
                                        'SLURM_CONF': self.policy['slurm']['config_file']})

    def origin(self, path):
        return engine.public_binary_origin(self.budget,path)['path']

    def command_line(self, pid):
        raw = self.budget.read('/proc/'+str(pid)+'/cmdline',16384)
        need(raw.endswith(b'\0'), 'peer_command_line')
        return [part.decode('utf-8') for part in raw[:-1].split(b'\0')]

    def selected_environment(self, pid):
        raw = self.budget.read('/proc/'+str(pid)+'/environ',65536); result = {}
        for entry in raw.split(b'\0'):
            key,sep,value = entry.partition(b'=')
            if key in (b'AIIDA_PATH',b'QCL_NEGF_NATIVE_JOBS_ROOT'):
                name = key.decode('ascii'); need(sep and name not in result, 'peer_environment')
                result[name] = value.decode('utf-8')
        return result  # Other environment entries, including secrets, are never retained.

    def actor_configuration(self):
        need(hasattr(self,'_server_unit'), 'server_unit')
        path = os.environ.get('QCL_NEGF_NATIVE_ACTOR_CONFIG'); path_value(path,absolute=True)
        environment = self.run([self.policy['tools']['systemctl'],'show',self._server_unit,'--property=Environment','--value'])
        selected = [entry for entry in shlex.split(environment) if entry.startswith('QCL_NEGF_NATIVE_ACTOR_CONFIG=')]
        need(selected == ['QCL_NEGF_NATIVE_ACTOR_CONFIG='+path], 'actor_configuration')
        origin = engine.public_binary_origin(self.budget,path,executable=False)['path']
        raw = engine.immutable_public_bytes(self.budget,origin,65536)
        cfg = exact(strict_json(raw.decode()), {'schema','profile','aiida_path','application_profile','jobs_root','client'})
        need(cfg['schema'] == 'qcl-negf.native-actor-launch.v1' and matches(cfg['profile'],ID) and
             cfg['aiida_path'] == '/var/lib/qcl-negf/aiida' and
             cfg['application_profile'] == '/nix/var/nix/profiles/qcl-negf-application' and
             cfg['jobs_root'] == self.policy['jobs_root'], 'actor_configuration')
        client = exact(cfg['client'], {'entrypoint','argv_prefix','bash_executable'})
        prefix = client['argv_prefix']
        need(type(prefix) is list and len(prefix)==4 and prefix[1:3]==['-I','-c'] and
             type(prefix[3]) is str and 0<len(prefix[3])<=8192, 'actor_configuration')
        for executable in (prefix[0],client['entrypoint'],client['bash_executable']):
            need(type(executable) is str and executable.startswith('/nix/store/'), 'actor_configuration')
            self.origin(executable)
        return cfg

    def actor_context(self):
        cfg = self.actor_configuration()
        raw = protected_read(Path(self.policy['release_runtime'])/'release.json',self.budget)
        app = engine.release_envelope(strict_json(raw.decode()))['application_path']
        profile = cfg['application_profile']
        origin = engine.public_binary_origin(self.budget,profile+'/bin/verdi')
        need(any(path==app and stat.S_ISDIR(info[2]) and info[3]==0 for path,info,_ in origin['chain']), 'application_profile_changed')
        need(any(path==profile and stat.S_ISLNK(info[2]) and info[3]==0 for path,info,_ in origin['chain']), 'application_profile_changed')
        for path,info,_ in origin['chain']:
            # Store admission belongs to the existing public immutable-origin
            # reader. The managed store directory may be group-writable; this
            # bridge protects the mutable profile selectors, without changing it.
            need(info[3]==0 and (path=='/nix/store' or stat.S_ISLNK(info[2]) or not info[2]&0o022),
                 'application_profile_changed')
        self.origin(app+'/bin/qcl-negf-native-actor')
        return {'configuration':cfg,'app':app,'profile_origin':origin,'release_sha256':hashlib.sha256(raw).hexdigest()}

    def profile_view(self, main_pid, context):
        cfg = context['configuration']; views = []
        for pid in (os.getpid(),main_pid):
            parent = os.open('/proc/'+str(pid)+'/root',os.O_RDONLY|os.O_DIRECTORY)
            try:
                for part in (cfg['aiida_path'].lstrip('/')+'/.aiida').split('/'):
                    self.budget.file(); child = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                    info = os.fstat(child)
                    if info.st_uid not in (0,self.policy['client_uid']) or info.st_mode&0o022:
                        os.close(child); raise Hold('profile_path')
                    os.close(parent); parent = child
                fd = os.open('config.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
                try:
                    raw,info = read_fd(fd,65536,self.budget)
                    need(info.st_uid in (0,self.policy['client_uid']) and not info.st_mode&0o022 and
                         signature(info)==signature(os.stat('config.json',dir_fd=parent,follow_symlinks=False)), 'profile_config')
                    identity = signature(info)
                finally: os.close(fd)
                for path in ('access/'+cfg['profile'],'log'):
                    directory = parent; opened = []
                    try:
                        for part in path.split('/'):
                            self.budget.file(); directory = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
                            opened.append(directory); info = os.fstat(directory)
                            need(info.st_uid==self.policy['client_uid'] and not info.st_mode&0o022, 'profile_operational_path')
                        if path=='log':
                            with os.scandir(directory) as iterator:
                                for item in iterator:
                                    self.budget.file()
                                    need(re.fullmatch(re.escape('aiida-'+cfg['profile']+'.log')+r'(?:\.(?:[1-9]|10))?',item.name),
                                         'profile_log_namespace')
                                    info = os.stat(item.name,dir_fd=directory,follow_symlinks=False)
                                    need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and
                                         info.st_uid==self.policy['client_uid'] and not info.st_mode&0o022, 'profile_log_namespace')
                    finally:
                        for directory in reversed(opened): os.close(directory)
                rows = self.budget.read('/proc/'+str(pid)+'/mountinfo',65536).decode().splitlines()
                wanted = cfg['aiida_path']+'/.aiida/config.json'
                need(any(line.split(' - ',1)[0].split()[4]==wanted and
                         'ro' in line.split(' - ',1)[0].split()[5].split(',') for line in rows), 'profile_config_not_readonly')
                need(identity == signature(os.stat('config.json',dir_fd=parent,follow_symlinks=False)), 'profile_config_changed')
                views.append({'identity':identity,'sha256':hashlib.sha256(raw).hexdigest()})
            finally: os.close(parent)
        need(views[0]==views[1], 'profile_view_changed')
        return views[0]

    def _refresh_caller(self, action):
        need(hasattr(self,'_connection'), 'peer_missing')
        fresh = authenticate_socket_peer(self._connection,self.policy,self,action=action)
        def stable(packet):
            return {'chain':[(_caller_generation(row['process']),row['argv'],row['environment']) for row in packet['chain']],
                    **{key:packet[key] for key in ('unit','application','profile')}}
        if hasattr(self,'_caller'): need(stable(self._caller)==stable(fresh), 'peer_generation_changed')
        self._caller = fresh
        return fresh

    def process(self, pid):
        row = engine.process_record(self.budget, Path('/proc') / str(pid))
        raw = self.budget.read(Path('/proc') / str(pid) / 'stat').decode()
        fields = raw[raw.rfind(')') + 2:].split()
        need(int(fields[19]) == row['start_ticks'], 'process_changed')
        def retain(value):
            if isinstance(value, bytes):
                return {'base64': base64.b64encode(value).decode('ascii')}
            if isinstance(value, dict):
                return {key: retain(item) for key, item in value.items()}
            return value
        # Keep original raw process samples in privileged journals/facts, never
        # expose them as a standalone caller-created certificate.
        need(fields[0] == row['state'], 'process_changed')
        return {**{key: row[key] for key in ('pid', 'uids', 'start_ticks', 'cgroup', 'executable', 'state', 'comm')},
                'ppid': int(fields[1]), 'observations': retain(row['observations'])}

    def host(self):
        first = {'machine_id': self.budget.read('/etc/machine-id', 64).decode().strip(),
                 'boot_id': self.budget.read('/proc/sys/kernel/random/boot_id', 64).decode().strip()}
        need(matches(first['machine_id'], r'[0-9a-f]{32}'), 'host_identity')
        canonical_uuid(first['boot_id'])
        image = engine.public_binary_origin(self.budget, '/run/current-system/nixos-version', executable=False)['path']
        first['image_id'] = str(Path(image).parent)
        return first

    def unit(self, name):
        need(matches(name, r'[A-Za-z0-9@_.:-]+\.service'), 'unit_name')
        fields = ('InvocationID', 'ControlGroup', 'MainPID', 'ActiveState', 'FragmentPath', 'MemoryMax', 'RuntimeMaxUSec')
        output = self.run([self.policy['tools']['systemctl'], 'show', name,
                           *('--property=' + key for key in fields)])
        values = dict(line.split('=', 1) for line in output.splitlines())
        need(set(values) == set(fields), 'unit_observation')
        if self.qualification is not None:
            kind = 'server' if name.startswith(self.policy['server_unit_prefix']) else name
            expected = exact(self.qualification['unit_origins'][kind], {'fragment_path', 'fragment_sha256', 'executable'})
            origin = engine.public_binary_origin(self.budget, values['FragmentPath'], executable=False)['path']
            need(origin == expected['fragment_path'] and hashlib.sha256(
                engine.immutable_public_bytes(self.budget, origin, 65536)).hexdigest() == expected['fragment_sha256'], 'unit_origin')
        return values

    def qualify(self):
        policy = self.policy
        try:
            raw = protected_read(policy['qualification_file'], self.budget)
        except FileNotFoundError as error:
            raise Hold('native_qualification_missing') from error
        q = strict_json(raw.decode())
        keys={'protocol_id','policy_sha256','controller_binding','worker_bindings','unit_origins','tool_origins',
              'write_domain','qualification_receipt_ref'}
        need(type(q) is dict and keys<=q.keys() and set(q)<=keys|{'completed_final'},'output_binding')
        if 'completed_final' in q:
            self.budget.reserve(8*len(raw));_completed_final_binding(q['completed_final'],policy['worker_routes'])
        need(q['protocol_id'] == 'p07-ordinary-slurm-v1' and q['policy_sha256'] == policy['_policy_sha256'], 'native_protocol_changed')
        host = self.host()
        binding = q['controller_binding'] if policy['role'] == 'controller' else q['worker_bindings'].get(host['machine_id'])
        need(binding == host, 'host_generation_changed')
        exact(q['tool_origins'], policy['tools'])
        for key, path in policy['tools'].items():
            origin = engine.public_binary_origin(self.budget, path)['path']
            need(origin == q['tool_origins'][key], 'native_tool_changed')
        need(self.run([policy['tools']['scontrol'], '--version']).strip() == policy['slurm']['version'], 'slurm_version_changed')
        config = protected_read(policy['slurm']['config_file'], self.budget).decode()
        cluster = re.findall(r'^ClusterName\s*=\s*([^\s#]+)', config, re.M)
        need(cluster == [policy['slurm']['cluster']], 'slurm_cluster_changed')
        # Local journals and readable script spool must never be NFS namespaces.
        for root in (policy['private_root'], policy['spool_root']):
            trusted_root_path(root, directory=True)
            need(not within(root, policy['jobs_root']) and self.mount(root)['fstype'] not in {'nfs', 'nfs4'}, 'journal_not_local')
        mount = self.mount(policy['jobs_root'])
        need(mount['fstype'] in {'nfs', 'nfs4'} and mount['source'] == policy['nfs_source'] and
             'hard' in mount['options'], 'storage_binding_changed')
        domain = q['write_domain']
        need(protected_read(policy['storage_identity_file'], self.budget).decode().strip() == domain['storage_identity'], 'storage_binding_changed')
        need(type(q['qualification_receipt_ref']) is str and 0 < len(q['qualification_receipt_ref']) <= 256, 'native_qualification_missing')
        # Receipt locator is retained context, never a boolean certificate.
        self.qualification = q
        self._qualification_sha256=hashlib.sha256(raw).hexdigest()
        unit = policy['daemon_unit'] if policy['role'] == 'controller' else policy['slurmd_unit']
        observed = self.unit(unit)
        need(observed['ActiveState'] == 'active' and matches(observed['InvocationID'], r'[0-9a-f]{32}') and
             int(observed['MainPID']) > 0, 'native_unit_changed')
        return host

    def completed_final_runner(self):
        need(self.qualification is not None and 'completed_final' in self.qualification,'output_scope_unsupported')
        binding=_completed_final_binding(self.qualification['completed_final'],self.policy['worker_routes'])
        runner=binding['runner'];inodes=set()
        self.budget.reserve(8192+16*len(runner['capture_executable'].encode()))
        capture_origin=engine.public_binary_origin(self.budget,runner['capture_executable'])
        need(capture_origin['path']==runner['files']['capture_entry']['path'],'output_source_changed')
        for role,claim in runner['files'].items():
            # Expected finite bytes, two simultaneous byte/hash workspaces and
            # bounded fixed-path origin metadata precede the public file read.
            self.budget.reserve(2*(claim['bytes']+1)+8192+16*len(claim['path'].encode()))
            first=engine.public_binary_origin(self.budget,claim['path'],executable=role in ('launcher','julia_launcher','capture_entry'))
            need(first['path']==claim['path'],'output_source_changed')
            inode=tuple(first['chain'][-1][1][:2]);need(inode not in inodes,'output_source_alias');inodes.add(inode)
            raw=engine.immutable_public_bytes(self.budget,first['path'],claim['bytes'])
            need(len(raw)==claim['bytes'] and hashlib.sha256(raw).hexdigest()==claim['sha256'],'output_source_changed')
            need(first==engine.public_binary_origin(self.budget,claim['path'],executable=role in
                 ('launcher','julia_launcher','capture_entry')),'output_source_changed')
            del raw
        need(capture_origin==engine.public_binary_origin(self.budget,runner['capture_executable']),'output_source_changed')
        return runner

    def output_unit_generation(self,name,*,readonly):
        need((name in ('qcl-negf-aiida.service','qcl-negf-api.service') and readonly is True) or
             (name=='slurmd.service' and readonly is False),'output_binding')
        self.budget.reserve(32768)
        state=self.unit(name);need(matches(state['MainPID'],r'[1-9][0-9]*'),'output_binding');pid=int(state['MainPID'])
        first=self.process(pid);need(engine.process_state_class(first)=='live','output_binding')
        expected=self.qualification['unit_origins'][name]['executable']
        need(first['executable']==expected and self.origin(expected)==expected,'output_binding')
        path='/proc/'+str(pid)+'/ns/mnt';namespace=self.budget.stat(path,follow_symlinks=True)
        raw=self.budget.read('/proc/'+str(pid)+'/mountinfo',65536).decode()
        line=_output_mount_line(raw,self.policy['jobs_root']+'/'+self.policy['native_result_prefix'],self.policy['nfs_source'],readonly)
        last_namespace=self.budget.stat(path,follow_symlinks=True);last=self.process(pid)
        keys=('pid','start_ticks','uids','cgroup','executable')
        need({k:first[k] for k in keys}=={k:last[k] for k in keys} and
             engine.process_state_class(last)=='live' and state==self.unit(name) and
             (namespace.st_dev,namespace.st_ino)==(last_namespace.st_dev,last_namespace.st_ino),'output_binding')
        return _output_unit(dict(name=name,state=state,main={k:first[k] for k in keys},
            mount_namespace=dict(device=namespace.st_dev,inode=namespace.st_ino),mount_line=line))

    def mount(self, path):
        rows = []
        for line in self.budget.read('/proc/self/mountinfo', 65536).decode().splitlines():
            left, right = line.split(' - ', 1); fields = left.split(); tail = right.split()
            mountpoint = fields[4]
            if within(path, mountpoint):
                rows.append((len(mountpoint), dict(mountpoint=mountpoint, fstype=tail[0], source=tail[1],
                                                options=set(fields[5].split(',')) | set(tail[2].split(',')))))
        need(rows, 'mount_not_observed')
        return max(rows, key=lambda row: row[0])[1]

    def _submit_admission(self, launch):
        current = strict_json(protected_read(Path(self.policy['release_runtime'])/'release.json',self.budget).decode())
        need(current.get('ready') is True and current.get('release_id')==launch['release_id'] and
             current.get('code_uuid')==launch['code_uuid'], 'native_admission_closed')
        gate = Path(self.policy['jobs_root'])/'.release-admission.json'
        # Existing G credential switch for its fixed NFS gate, no root-squash bypass.
        need(gate==engine.GATE, 'native_admission_namespace')
        with engine.admission_reader(gate):
            admission = strict_json(self.budget.read(gate,65536).decode())
        need(admission.get('open') is True and admission.get('release_id')==launch['release_id'], 'native_admission_closed')

    def _actor_read(self, kind, calcjob, launch, context):
        files = exact(launch['files'], FILES)
        counts = [(files[role]['bytes'], _original_input_limit(role, self.policy)) for role in FILES]
        need(all(type(size) is int and 0<=size<=cap for size,cap in counts), 'actor_input_bound')
        # Prepay complete raw/JSON chunk and EOF workspace for each original role
        # before the actor command; the inherited outer ledger can still refuse.
        ceiling = 30*16384 + 8*sum(min(cap+1,4096*math.ceil(size/4096)+4096) for size,cap in counts)
        self.budget.reserve(ceiling)
        cfg = context['configuration']; app = context['app']
        argv = [self.policy['tools']['runuser'],'-u','qcl-negf','--',app+'/bin/qcl-negf-native-actor',
                '--profile',cfg['profile'],kind,calcjob,'--maximum-metadata-bytes',str(ceiling)]
        output = self.budget.command(argv,run=engine.command,output_bytes=65536,
            env={'AIIDA_PATH':cfg['aiida_path'],'PATH':app+'/bin:/empty','LANG':'C','LC_ALL':'C'})
        need(type(output) is engine.CommandOutput, 'actor_output_unqualified')
        raw = output.encode('utf-8')
        need(type(getattr(output,'output_bytes',None)) is int and output.output_bytes==len(raw), 'actor_output_partial')
        return raw

    def preflight(self, launch, budget, *, calcjob_uuid, action):
        canonical_uuid(calcjob_uuid)
        need(action in {'submit','reconcile','status','start','close'} and budget is self.budget, 'actor_request')
        host = self.qualify(); policy = self.policy
        peer = self._refresh_caller(action); context = peer['application']
        root = policy['jobs_root'] + '/' + launch['relative_execution_root']
        need(within(launch['relative_execution_root'], policy['native_result_prefix']) and
             within(launch['remote_workdir'], policy['jobs_root']) and
             not within(launch['remote_workdir'], policy['jobs_root'] + '/' + policy['native_result_prefix']) and
             not within(root, launch['remote_workdir']), 'output_namespace')
        retained = strict_json(protected_read(Path(policy['release_runtime']) / 'records' /
                               ('release-' + launch['release_id'] + '.json'), budget).decode())
        envelope = engine.release_envelope(retained)
        need(retained['code_uuid'] == launch['code_uuid'] and envelope['release_id'] == launch['release_id'], 'release_binding_changed')
        graph_hash = envelope['solver_build']['source_graph_sha256']
        graph = protected_read(Path(policy['release_runtime']) / 'records' / ('source-graph-' + graph_hash + '.json'), budget)
        need(hashlib.sha256(graph).hexdigest() == graph_hash == launch['files']['source_graph']['sha256'] and
             len(graph) == launch['files']['source_graph']['bytes'], 'release_graph_changed')
        need(retained['quantum_runtime_context'] == engine.quantum_context(envelope), 'release_binding_changed')
        if action=='submit': self._submit_admission(launch)
        actual = strict_json(self._actor_read('launch',calcjob_uuid,launch,context).decode())
        need(actual==launch, 'actor_launch_changed')
        raw = self._actor_read('execution',calcjob_uuid,launch,context)
        need(len(raw)==launch['files']['native_execution']['bytes'] and
             hashlib.sha256(raw).hexdigest()==launch['files']['native_execution']['sha256'], 'actor_execution_changed')
        native = strict_json(raw.decode())  # The fixed public actor owns full scientific-schema validation.
        need(native['schema']=='qcl-negf.aiida-native-execution.v1' and native['request_id']==launch['request_id'] and
             native['execution_id']==launch['execution_id'], 'actor_execution_binding')
        for key,node in (('input_plan','input_plan_uuid'),('source_graph','source_graph_uuid')):
            role = 'plan' if key=='input_plan' else key
            need(native[key]=={'node_uuid':launch[node],'bytes':str(launch['files'][role]['bytes']),
                               'sha256':launch['files'][role]['sha256']}, 'actor_original_reference')
        code = native['code']; storage = native['storage']
        need(code['code_uuid']==launch['code_uuid'] and code['release_id']==launch['release_id'] and
             code['solver_executable']==envelope['solver_executable'] and
             code['computer_uuid']==storage['computer_uuid'] and
             storage['execution_binding_uuid']==launch['native_execution_uuid'] and
             storage['relative_execution_root']==launch['relative_execution_root'] and
             storage['storage_identity']==self.qualification['write_domain']['storage_identity'], 'actor_native_binding')
        submitted = _read_submitted_files_as_owner(policy,launch,budget)
        need(submitted['files']==launch['files'], 'submitted_digest')
        budget.reserve(launch['files']['submit_script']['bytes']*8)
        script = base64.b64decode(submitted['script'],validate=True)
        need(len(script)==launch['files']['submit_script']['bytes'] and
             hashlib.sha256(script).hexdigest()==launch['files']['submit_script']['sha256'], 'submitted_digest')
        _review_native_script(script,launch,envelope['solver_executable'],context['configuration']['client']['bash_executable'],self,
                              calcjob_uuid=calcjob_uuid)
        self._refresh_caller(action)
        self._actor = {'calcjob_uuid':calcjob_uuid,'action':action,'launch':actual,
                       'execution_sha256':hashlib.sha256(raw).hexdigest()}
        return host

    def snapshot(self, launch, dispatch, budget):
        result = _read_submitted_files_as_owner(self.policy, launch, budget)
        raw = base64.b64decode(result['script'], validate=True)
        need(result['files'] == launch['files'] and len(raw) == launch['files']['submit_script']['bytes'] and
             hashlib.sha256(raw).hexdigest() == launch['files']['submit_script']['sha256'], 'submitted_digest')
        root = Path(self.policy['spool_root'])
        with protected_directory(root, budget=budget) as parent:
            name = dispatch + '.sh'; budget.file(); budget.reserve(len(raw))
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=parent)
            try:
                offset = 0
                while offset < len(raw):
                    budget.before(); count = os.write(fd, raw[offset:]); need(count > 0, 'snapshot_short_write'); offset += count
                os.fchown(fd, 0, self.policy['client_uid']); os.fchmod(fd, 0o440); os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(parent)
        return {'script_path': str(root / name), 'script_sha256': hashlib.sha256(raw).hexdigest()}

    def _check_snapshot(self, snapshot):
        need(Path(snapshot['script_path']).parent == Path(self.policy['spool_root']), 'snapshot_namespace')
        raw = protected_read(snapshot['script_path'], self.budget, self.policy['limits']['script_bytes'])
        need(hashlib.sha256(raw).hexdigest() == snapshot['script_sha256'], 'snapshot_changed')

    def dispatch(self, launch, snapshot, dispatch, budget):
        self._check_snapshot(snapshot)
        for key in ('runuser', 'sbatch'):
            trusted_root_path(self.policy['tools'][key], executable=True)
        return self.run(self._argv(launch, snapshot, dispatch), output_bytes=4096)

    def _argv(self, launch, snapshot, dispatch):
        return [self.policy['tools']['runuser'], '-u', 'qcl-negf', '--', self.policy['tools']['sbatch'],
                '--parsable', '--no-requeue', '--chdir', launch['remote_workdir'], '--comment', dispatch,
                snapshot['script_path']]

    def _intent(self, launch, snapshot, dispatch):
        _authenticate_server(self)
        need(hasattr(self,'_actor') and self._actor['launch']==launch, 'actor_input_binding_unavailable')
        caller = self._refresh_caller(self._actor['action'])
        self._submit_admission(launch)
        process = self.process(os.getpid()); unit = self.unit(process['cgroup'].rsplit('/', 1)[-1])
        packet = {'argv': self._argv(launch,snapshot,dispatch),'script_sha256':snapshot['script_sha256'],
                  'owner': {'process':process,'unit':unit,'host':self.host(),'caller':caller,'actor':self._actor}}
        _reserve_private_record(packet,self.budget)
        need(len(encoded(packet))<=49152, 'private_record_bound')
        return packet

    def native_job(self, job_id):
        need(matches(job_id, JOB), 'job_selector')
        raw = self.run([self.policy['tools']['scontrol'], '--oneliner', 'show', 'job', job_id])
        lines = [line for line in raw.splitlines() if line.strip()]
        need(len(lines) == 1, 'native_job_ambiguous')
        fields = dict(re.findall(r'(?<!\S)(\w+)=([^\s]+)', lines[0]))
        need(fields.get('JobId') == job_id and fields.get('UserId') == 'qcl-negf(3000)' and
             matches(fields.get('SubmitTime'), r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}') and
             fields.get('Restarts') == '0' and fields.get('NumNodes') == '1' and fields.get('NumTasks') == '1' and
             fields.get('ArrayJobId', '0') == fields.get('HetJobId', '0') == '0', 'native_job_changed')
        return {'raw': str(raw), 'fields': fields}

    def bind_job(self, ack, launch, dispatch, context, budget):
        observed = self.native_job(ack['job_id']); fields = observed['fields']
        need(fields.get('WorkDir') == launch['remote_workdir'] and fields.get('Comment') == dispatch and
             fields.get('Command') == str(Path(self.policy['spool_root']) / (dispatch + '.sh')),
             'native_dispatch_join_missing')
        generation = hashlib.sha256(encoded({'controller': context, 'job_id': ack['job_id'],
                          'submit_time': fields['SubmitTime'], 'dispatch_id': dispatch,
                          'command': fields['Command'], 'workdir': fields['WorkDir']})).hexdigest()
        return dict(job_id=ack['job_id'], cluster=ack['cluster'], submit_time=fields['SubmitTime'],
                    controller_machine_id=context['machine_id'], controller_boot_id=context['boot_id'],
                    dispatch_id=dispatch, generation=generation, node_name=None, start_time=None,
                    worker_machine_id=None, worker_boot_id=None)

    def worker(self, job, calcjob, phase, budget):
        from host_resource_facts import trusted_rpc
        self._calcjob = calcjob
        native = self.native_job(job['job_id'])['fields']
        need(native['SubmitTime'] == job['submit_time'] and native.get('Comment') == job['dispatch_id'], 'native_job_changed')
        node = native.get('NodeList'); route = self.policy['worker_routes'].get(node)
        need(route is not None, 'worker_not_enrolled')
        packet = trusted_rpc(route, 'attempt-facts', dict(version=1, calcjob_uuid=calcjob,
                             dispatch_id=job['dispatch_id'], job_id=job['job_id'],
                             generation=job['generation'], phase=phase),
                             run=lambda argv, **kw: self.run(argv, output_bytes=kw.get('output_bytes')),
                             trust_snapshot_root=self._trust_root(), existing_budget=budget)
        validate_worker_reply(packet)
        actual = packet['identity']['identity']
        expected = self.qualification['worker_bindings'].get(actual['machine_id'])
        need(expected is not None and all(actual[k] == expected[k] for k in expected), 'worker_generation_changed')
        need(packet['job']['fields']['SubmitTime'] == job['submit_time'] and
             packet['job']['fields'].get('Comment') == job['dispatch_id'], 'native_job_changed')
        need(packet['prolog_ref'] is not None, 'native_prolog_not_observed')
        if phase == 'close':
            need(packet['epilog_ref'] is not None, 'native_epilog_not_observed')
        return packet

    def close_writers(self, job, launch, observed, budget):
        from host_resource_facts import trusted_rpc
        domain = self.qualification['write_domain']
        exact(domain, {'storage_identity', 'native_prefix', 'retention_ref', 'writer_hosts', 'controller_units'})
        need(domain['native_prefix'] == self.policy['native_result_prefix'] and
             set(domain['writer_hosts']) == set(self.policy['worker_routes']) and
             type(domain['retention_ref']) is str and 0 < len(domain['retention_ref']) <= 256,
             'writer_domain_not_closed')
        prefix = self.policy['jobs_root'] + '/' + domain['native_prefix']
        # Actual per-service mount namespaces, not the root helper's mount view.
        units = []
        for name in domain['controller_units']:
            need(name in {'qcl-negf-aiida.service', 'qcl-negf-api.service'}, 'writer_domain_not_closed')
            projection=self.output_unit_generation(name,readonly=True) if 'completed_final' in self.qualification else None
            unit = projection['state'] if projection is not None else self.unit(name); pid = int(unit['MainPID'])
            need(unit['ActiveState'] == 'active' and pid > 0, 'writer_domain_not_closed')
            raw = projection['mount_line']+'\n' if projection is not None else budget.read('/proc/' + str(pid) + '/mountinfo', 65536).decode()
            _close_mount_line(raw,prefix,self.policy['nfs_source'])
            need(unit == self.unit(name), 'writer_domain_not_closed')
            row=dict(unit=name,state=unit,mountinfo=raw)
            if projection is not None:row['output_unit']=projection
            units.append(row)
        need(set(domain['controller_units']) == {'qcl-negf-aiida.service', 'qcl-negf-api.service'}, 'writer_domain_not_closed')
        inventories = []; workers = []
        for node, route in self.policy['worker_routes'].items():
            packet = trusted_rpc(route, 'attempt-facts', dict(version=1, calcjob_uuid=self._calcjob,
                                 dispatch_id=job['dispatch_id'], job_id=job['job_id'],
                                 generation=job['generation'], phase='status'),
                                 run=lambda argv, **kw: self.run(argv, output_bytes=kw.get('output_bytes')),
                                 trust_snapshot_root=self._trust_root(), existing_budget=budget)
            validate_worker_reply(packet)
            identity = packet['identity']['identity']; expected = self.qualification['worker_bindings'].get(identity['machine_id'])
            need(expected is not None and all(identity[k] == expected[k] for k in expected), 'writer_domain_not_closed')
            need(identity['machine_id'] == domain['writer_hosts'][node], 'writer_domain_not_closed')
            inventories.append(packet['writer_snapshot'])
            workers.append(dict(node=node,reply=packet))
        known = self.managed_writers()
        enforce_writer_closure(launch['relative_execution_root'], inventories, known, job['generation'])
        value=dict(storage_identity=domain['storage_identity'],native_prefix=domain['native_prefix'],
                    retention_ref=domain['retention_ref'],controller_units=units,workers=workers,managed=known)
        if 'completed_final' in self.qualification:value['output_generation']=_full_output_generation(self,units,workers)
        return value

    def _trust_root(self):
        root = Path(self.policy['private_root']) / 'trust-snapshots'
        with AttemptStore(self.policy['private_root']).directory(root, create=True):
            pass
        return root

    def managed_writers(self):
        rows = []; attempts = Path(self.policy['private_root']) / 'attempts'
        store = AttemptStore(self.policy['private_root'])
        for path in self.budget.entries(attempts, 'attempt'):
            canonical_uuid(path.name)
            claim = store.read(path.name, 'claim.json', self.budget)
            job = store.read(path.name, 'job.json', self.budget)
            need(claim is not None and job is not None, 'writer_domain_not_closed')
            rows.append({'job_id': job['job_id'], 'generation': job['generation'],
                         'dispatch_id': claim['dispatch_id'], 'domain': claim['launch']['relative_execution_root'],
                         'submit_time': job['submit_time']})
        return rows


def enforce_writer_closure(target, inventories, known, closing_generation):
    """Finite admitted managed allocations, never universal process detection."""
    path_value(target, absolute=False)
    by_job = {row['job_id']: row for row in known}
    need(len(by_job) == len(known), 'writer_domain_not_closed')
    for inventory in inventories:
        # capture_guest_facts already rejects unjoined owner processes and incomplete scans.
        need(inventory['schema'] == 'qcl.host-resource-guest-facts.v1' and
             inventory['identity_before'] == inventory['identity_after'] and inventory['slurm_registered'] is True,
             'writer_domain_not_closed')
        for key, native in inventory['jobs'].items():
            row = by_job.get(key)
            need(row is not None and native['owner_uid'] == 3000 and
                 native['submit_time'] == row['submit_time'], 'writer_domain_not_closed')
            if native['terminal']:
                # Terminal state alone is insufficient for an intersecting writer.
                group = inventory['groups'][key]
                need(group.get('populated') == 0 and not group.get('processes'), 'writer_domain_not_closed')
                continue
            need(row['generation'] != closing_generation and
                 not within(row['domain'], target) and not within(target, row['domain']), 'writer_domain_not_closed')


def validate_worker_request(document):
    exact(document, {'version', 'calcjob_uuid', 'dispatch_id', 'job_id', 'generation', 'phase'})
    need(type(document['version']) is int and document['version'] == 1)
    canonical_uuid(document['calcjob_uuid']); canonical_uuid(document['dispatch_id'])
    need(matches(document['job_id'], JOB) and matches(document['generation'], SHA) and
         document['phase'] in {'start', 'close', 'status'})
    return document


def validate_worker_reply(document):
    exact(document, {'version', 'identity', 'job', 'prolog_ref', 'epilog_ref', 'before', 'after', 'writer_snapshot'})
    need(type(document['version']) is int and document['version'] == 1, 'worker_reply')
    need(document['identity']['schema'] == 'qcl.host-resource-guest-identity.v1', 'worker_reply')
    return document


def authenticate_hook(sources):
    need(os.getuid() == os.geteuid() == 0, 'hook_credentials')
    unit = sources.unit(sources.policy['slurmd_unit']); first = sources.process(os.getpid())
    need(unit['ActiveState'] == 'active' and matches(unit['InvocationID'], r'[0-9a-f]{32}') and
         int(unit['MainPID']) > 0, 'hook_unit')
    row = first; chain = []
    for _ in range(16):
        need(row['uids'] == [0] * 4 and engine.daemon_scope_bound(row['cgroup'], unit['ControlGroup']), 'hook_ancestry')
        chain.append(row)
        if row['pid'] == int(unit['MainPID']):
            need(row['executable'] == sources.policy['tools']['slurmd'], 'hook_ancestry')
            break
        need(row['ppid'] > 1 and row['ppid'] != row['pid'], 'hook_ancestry')
        row = sources.process(row['ppid'])
    else:
        raise Hold('hook_ancestry')
    need(first == sources.process(os.getpid()) and unit == sources.unit(sources.policy['slurmd_unit']), 'hook_generation_changed')
    return {'unit': unit, 'chain': chain}


def _hook_path(policy, job, dispatch, phase):
    need(matches(job, JOB) and phase in {'prolog', 'epilog'}, 'hook_selector')
    canonical_uuid(dispatch)
    return Path(policy['private_root']) / 'hooks' / (job + '-' + dispatch + '-' + phase + '.json')


def record_slurm_hook(phase):
    budget = _bootstrap_operation(); policy = _load_policy('worker', budget)
    sources = NativeSources(policy, budget); identity = sources.qualify()
    need(phase in {'prolog', 'epilog'}, 'hook_phase')
    selector = os.environ.get('SLURM_JOB_ID'); need(matches(selector, JOB), 'hook_selector')
    job = sources.native_job(selector); fields = job['fields']; dispatch = fields.get('Comment', '')
    # A foreign job is never enrolled or blocked merely by its scheduler name.
    if not matches(dispatch, r'[0-9a-f-]{36}') or fields.get('Command') != str(Path(policy['spool_root']) / (dispatch + '.sh')):
        return
    canonical_uuid(dispatch); context = authenticate_hook(sources)
    root = Path(policy['private_root']); store = AttemptStore(root)
    with store.directory(root / 'hooks', create=True) as parent:
        raw = encoded({'identity': identity, 'job': job, 'context': context, 'phase': phase})
        budget.reserve(len(raw)); budget.file()
        path = _hook_path(policy, selector, dispatch, phase)
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            offset = 0
            while offset < len(raw):
                budget.before(); count = os.write(fd, raw[offset:]); need(count > 0, 'hook_short_write'); offset += count
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)


def _worker_capture(sources, document, identity, job):
    """Reuse unchanged scientific-independent membership/whole-stop validators."""
    import slurm_job_evidence as evidence
    p = sources.policy; budget = sources.budget; host = identity['identity']
    expected = dict(job_id=document['job_id'], owner_uid=3000, slurmstepd_executable=p['tools']['slurmstepd'],
                    cgroup_scope=p['slurm']['cgroup_scope'], identity={k: host[k] for k in ('machine_id', 'boot_id')})
    store = AttemptStore(p['private_root']); key = document['calcjob_uuid']
    before = None; after = None
    with store.locked(key, budget):
        binding = {key: value for key, value in document.items() if key != 'phase'}
        prior = store.read(key, 'worker-binding.json', budget)
        if prior is None:
            store.put(key, 'worker-binding.json', binding, budget)
        else:
            need(prior == binding, 'native_job_changed')
        before = store.read(key, 'before.json', budget)
        if before is None and document['phase'] == 'start':
            text = sources.run([p['tools']['scontrol'], 'listpids', document['job_id']])
            lines = text.splitlines(); need(lines and lines[0].split()[:2] == ['PID', 'JOBID'], 'native_start_not_observed')
            rows = []
            for line in lines[1:]:
                if not line.strip():
                    continue
                parts = line.split(); need(len(parts) >= 3 and parts[0].isdigit(), 'native_start_not_observed')
                rows.append(dict(pid=int(parts[0]), job_id=parts[1], step_id=parts[2]))
                need(len(rows) <= p['limits']['maximum_pids'], 'operation_pid_bound')
            processes = []
            for row in rows:
                observed = sources.process(row['pid'])
                processes.append({**observed, 'exe': observed['executable'], 'error': None})
            current_identity = sources.host()
            raw = {'identity_before': expected['identity'], 'identity_after': {k: current_identity[k] for k in expected['identity']},
                   'listpids': {'rc': 0, 'rows': rows}, 'processes': processes}
            store.put(key, 'before-raw.json', raw, budget)
            try:
                before = evidence.classify_before(raw, expected)
            except ValueError as error:
                raise Hold('native_start_not_observed') from error
            store.put(key, 'before.json', before, budget)
        if document['phase'] == 'close':
            need(before is not None, 'native_start_not_observed')
            evidence.validate_before(before, expected); seen = []
            for old in before['processes']:
                try:
                    row = sources.process(old['pid'])
                    seen.append({**row, 'absent': False, 'error': None})
                except FileNotFoundError:
                    need(not Path('/proc/' + str(old['pid'])).exists(), 'native_stop_not_observed')
                    seen.append({'pid': old['pid'], 'absent': True, 'error': None})
            group_path = before['job_cgroup']; path = Path('/sys/fs/cgroup' + group_path)
            try:
                events = dict(line.split() for line in budget.read(path / 'cgroup.events', 4096).decode().splitlines())
                group = dict(path=group_path, absent=False, populated=int(events['populated']))
            except FileNotFoundError:
                need(not path.exists(), 'native_stop_not_observed'); group = dict(path=group_path, absent=True, populated=None)
            last = sources.host()
            raw = {'identity_before': expected['identity'], 'identity_after': {k: last[k] for k in expected['identity']},
                   'processes': seen, 'job_cgroup': group,
                   'scheduler': dict(rc=0, job_id=document['job_id'], owner_uid=3000, state=job['fields']['JobState'])}
            # Each sample has an exclusive identity; previous failed samples survive.
            store.put(key, 'after-' + uuid.uuid4().hex + '.json', raw, budget)
            try:
                after = evidence.verify_after(before, raw, expected)
            except ValueError as error:
                raise Hold('native_stop_not_observed') from error
    return before, after


def read_attempt_facts(document):
    from host_resource_facts import LocalSources, capture_guest_identity
    validate_worker_request(document)
    budget = _bootstrap_operation(); policy = _load_policy('worker', budget)
    sources = NativeSources(policy, budget); sources.qualify()
    config = strict_json(protected_read(policy['facts_service_config'], budget).decode())
    need(config['schema'] == 'qcl.host-resource-service.v1' and config['role'] == 'guest' and
         config['client_uid'] == 3000, 'facts_config')
    facts_config = config
    class SharedSources(LocalSources):
        def read(self, path, limit=65536):
            return budget.read(path, limit).decode()
        def run(self, argv):
            return sources.run(argv)
        def processes(self):
            rows = []
            for path in budget.entries('/proc', 'pid'):
                need(len(rows) < policy['limits']['maximum_pids'], 'operation_pid_bound')
                classification = engine.process_classification(budget, path)
                if engine.process_state_class(classification) == 'nonexecuting':
                    rows.append({**classification, 'executable': '[nonexecuting]'}); continue
                raw = budget.read(path / 'stat').decode(); fields = raw[raw.rfind(')') + 2:].split()
                if int(fields[6]) & 0x00200000:
                    need(classification['uids'] == [0] * 4, 'incomplete_probe')
                    rows.append({**classification, 'executable': '[kernel]'}); continue
                rows.append(sources.process(int(path.name)))
            return rows
    local = SharedSources(facts_config, None)
    identity = capture_guest_identity(facts_config, local); job = sources.native_job(document['job_id'])
    fields = job['fields']; dispatch = document['dispatch_id']
    need(fields.get('Comment') == dispatch and fields.get('Command') == str(Path(policy['spool_root']) / (dispatch + '.sh')), 'native_dispatch_join_missing')
    generation = hashlib.sha256(encoded({'controller': sources.qualification['controller_binding'],
                    'job_id': document['job_id'], 'submit_time': fields['SubmitTime'], 'dispatch_id': dispatch,
                    'command': fields['Command'], 'workdir': fields['WorkDir']})).hexdigest()
    need(document['generation'] == generation, 'native_job_changed')
    refs = {}
    for phase in ('prolog', 'epilog'):
        path = _hook_path(policy, document['job_id'], dispatch, phase)
        try:
            record = strict_json(protected_read(path, budget).decode())
            current_unit = sources.unit(policy['slurmd_unit'])
            need(record['context']['unit'] == current_unit and record['identity'] == sources.host() and
                 record['job']['fields']['SubmitTime'] == fields['SubmitTime'] and
                 record['job']['fields']['Command'] == fields['Command'] and record['phase'] == phase, 'hook_generation_changed')
            refs[phase] = str(path.relative_to(policy['private_root']))
        except FileNotFoundError:
            refs[phase] = None
    if document['phase'] != 'status':
        need(refs['prolog'] is not None, 'native_prolog_not_observed')
    if document['phase'] == 'close':
        need(refs['epilog'] is not None, 'native_epilog_not_observed')
    before, after = _worker_capture(sources, document, identity, job) if document['phase'] != 'status' else (None, None)
    return dict(version=1, identity=identity, job=job, prolog_ref=refs['prolog'], epilog_ref=refs['epilog'],
                before=before, after=after, writer_snapshot=_capture_writer_snapshot(facts_config, local, budget,output_sources=sources))


def _capture_writer_snapshot(config, local, budget, *, output_sources=None):
    """Bounded existing facts subset; every admitted UID3000 process is joined."""
    from host_resource_facts import capture_scheduler
    output_before=_worker_output_generation(output_sources)
    first = local.host(); processes = local.processes(); all_jobs = capture_scheduler(config, local)
    jobs = {key: value for key, value in all_jobs.items() if value['node'] == config['node']}
    need(all(j['owner_uid'] == 3000 for j in jobs.values()), 'writer_domain_not_closed')
    root = path_value(config['slurm_cgroup_root'], absolute=True)
    groups = {}
    for key in jobs:
        scope = root + '/job_' + key
        members = [p for p in processes if engine.daemon_scope_bound(p['cgroup'], scope)]
        try:
            events = dict(line.split() for line in budget.read('/sys/fs/cgroup' + scope + '/cgroup.events', 4096).decode().splitlines())
            need(events.get('populated') in {'0', '1'}, 'writer_domain_not_closed')
            populated = events['populated'] == '1'
        except FileNotFoundError:
            need(not Path('/sys/fs/cgroup' + scope).exists(), 'writer_domain_not_closed'); populated = False
        need(populated == bool(members), 'writer_domain_not_closed')
        groups[key] = {'populated': populated, 'processes': members}
    for process in processes:
        if 3000 not in process['uids']:
            continue
        managed = any(engine.daemon_scope_bound(process['cgroup'], root + '/job_' + job) for job in jobs)
        infrastructure = any(process['cgroup'] == row['cgroup'] and process['executable'] == row['executable']
                             for row in config['infrastructure_processes'])
        need(managed or infrastructure, 'writer_domain_not_closed')
    last = local.host()
    need(all(first[k] == last[k] for k in ('machine_id', 'boot_id', 'kernel', 'dmi_uuid')), 'writer_domain_not_closed')
    unit = engine.unit_state(lambda argv: local.run([config['systemctl'], *argv[1:]]), 'slurmd.service')
    main = next((p for p in processes if str(p['pid']) == unit['MainPID']), None)
    need(main is not None and main['uids'] == [0] * 4 and main['cgroup'] == unit['ControlGroup'] and
         main['executable'] == config['slurmd_executable'] and unit['ActiveState'] == 'active', 'writer_domain_not_closed')
    identity = {k: first[k] for k in ('machine_id', 'boot_id', 'kernel', 'dmi_uuid')}
    output_after=_worker_output_generation(output_sources)
    need(output_before==output_after,'output_binding')
    packet=dict(schema='qcl.host-resource-guest-facts.v1', identity_before=identity, identity_after=identity,
                jobs=jobs, groups=groups, slurm_registered=True)
    if output_after is not None:
        need(output_after['worker']['node']==config['node'] and output_after['worker']['identity']==identity,'output_binding')
        packet['output_generation']=output_after
    return packet


def _authenticate_server(sources):
    process = sources.process(os.getpid()); unit_name = process['cgroup'].rsplit('/', 1)[-1]
    need(unit_name.startswith(sources.policy['server_unit_prefix']) and unit_name.endswith('.service') and
         process['uids'] == [0] * 4, 'server_unit')
    unit = sources.unit(unit_name)
    need(unit['ActiveState'] == 'active' and matches(unit['InvocationID'], r'[0-9a-f]{32}') and
         unit['ControlGroup'] == process['cgroup'] and int(unit['MainPID']) == os.getpid(), 'server_unit')
    need(unit['MemoryMax'].isdigit() and int(unit['MemoryMax']) >= sources.policy['limits']['memory_bytes'] and
         int(unit['MemoryMax']) <= 134217728, 'server_limits')
    # systemctl renders RuntimeMaxUSec as a human duration; require the fixed module bound.
    need(unit['RuntimeMaxUSec'] in {'1min 30s', '90s'}, 'server_limits')
    expected = sources.qualification['unit_origins']['server']['executable']
    need(process['executable'] == expected and _caller_generation(process) == _caller_generation(sources.process(os.getpid())) and
         unit == sources.unit(unit_name), 'server_generation_changed')
    sources._server_unit = unit_name


def handle_connection(connection):
    budget = _bootstrap_operation(); document = {}; result = None; validated = False; request_invalid = False
    try:
        policy = _load_policy('controller', budget); sources = NativeSources(policy, budget)
        sources.qualify(); _authenticate_server(sources)
        document = read_frame(connection, budget, policy['limits']['request_bytes'])
        try:
            action = validate_request(document)['action']
        except (Hold, TypeError, ValueError, KeyError) as error:
            request_invalid = type(document) is dict and not (
                type(document.get('version')) is int and document['version'] == 1)
            raise Hold('shape') from error
        validated = True
        sources._caller = authenticate_socket_peer(connection,policy,sources,action=action)
        owner = OrdinaryAttemptOwner(policy, AttemptStore(policy['private_root']), sources, budget)
        result = {'submit': owner.submit, 'reconcile': owner.reconcile, 'start': owner.observe_start,
                  'close': owner.qualify_close, 'status': owner.status}[action](document)
    except (Hold, OSError, ValueError, ResourceError, KeyError, engine.CommandFailure) as error:
        reason = error.reason if isinstance(error, Hold) else getattr(error, 'code', 'native_observation_failed')
        if isinstance(error,engine.CommandFailure): _preclaim_diagnostic(error)
        # Keep the v1 pre-owner Reply7 byte semantics; only validated v3 carries
        # the close request context into a noncompleted Reply8.
        context = document if validated and document['version'] == 3 else {}
        result = reply(context, 'rejected' if request_invalid else 'hold', reason=reason)
    write_frame(connection, result, budget, budget.limits['response_bytes'])


def server_main():
    need(len(sys.argv) == 1, 'server_arguments')
    with socket.socket(fileno=os.dup(0)) as connection:
        handle_connection(connection)
    return 0


def _client_operation(context=None):
    need(len(sys.argv) == 2 and sys.argv[1] in {'submit', 'reconcile', 'start', 'close', 'status'}, 'client_arguments')
    budget = _bootstrap_operation()
    raw = sys.stdin.buffer.read(65537); need(0 < len(raw) <= 65536, 'frame_bound')
    document = validate_request(strict_json(raw.decode('utf-8')))
    need(document['action'] == sys.argv[1], 'client_action')
    # Local failure retains only validated v3 identity, never server observations.
    if context is not None and document['version'] == 3:
        context.update(version=3, action='close', calcjob_uuid=document['calcjob_uuid'])
    with protected_directory(Path(SOCKET).parent, budget=budget) as parent:
        first = os.stat(Path(SOCKET).name, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISSOCK(first.st_mode) and first.st_uid == 0 and first.st_gid == 3000 and
             stat.S_IMODE(first.st_mode) == 0o660, 'socket_namespace')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(budget.limits['operation_seconds']); connection.connect(SOCKET)
            need(signature(first) == signature(os.stat(Path(SOCKET).name, dir_fd=parent, follow_symlinks=False)), 'socket_namespace')
            _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            need(uid == 0, 'server_credentials')  # PID1 is legitimate under socket activation.
            write_frame(connection, document, budget, 65536); connection.shutdown(socket.SHUT_WR)
            result = read_frame(connection, budget, 262144)
    validate_reply(result)
    need(result['version']==document['version'], 'reply_version')
    need(result['calcjob_uuid'] in (None, document['calcjob_uuid']), 'reply_binding')
    print(encoded(result).decode())
    return 0 if result['state'] in {'bound', 'started', 'closed'} else 75


def client_main():
    context = {}
    try:
        return _client_operation(context)
    except (Hold, OSError, ValueError, ResourceError, KeyError) as error:
        reason = error.reason if isinstance(error, Hold) else getattr(error, 'code', 'transport_outcome_unknown')
        print(encoded(reply(context, 'hold', reason=reason)).decode())
        return 75


def hook_main():
    need(len(sys.argv) == 2 and sys.argv[1] in {'prolog', 'epilog'}, 'hook_arguments')
    try:
        record_slurm_hook(sys.argv[1])
    except engine.CommandFailure as error:
        # Qualification/query can fail before this global hook knows whether
        # the job is managed. Preserve bounded original context, no lifecycle.
        raw = encoded(error.record)
        diagnostic = {'reason': 'native_command_failed',
                      'original_prefix_base64': base64.b64encode(raw[:2048]).decode('ascii'),
                      'original_bytes': len(raw), 'original_sha256': hashlib.sha256(raw).hexdigest(),
                      'truncated': len(raw) > 2048}
        print('native-attempt hook HOLD: ' + encoded(diagnostic).decode(), file=sys.stderr)
    except (Hold, OSError, ValueError, ResourceError, KeyError) as error:
        # Missing hook evidence blocks subsequent managed close. Do not fail a
        # foreign Slurm job or create another job/retry owner from a global hook.
        print('native-attempt hook HOLD: ' + getattr(error, 'reason', getattr(error, 'code', 'native_observation_failed')), file=sys.stderr)
    return 0
