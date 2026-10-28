"""Demand-only public API. This gate never accepts or executes solver argv."""
from dataclasses import asdict,dataclass
import argparse
import base64
import json
import re
import sys
from typing import Literal, TypedDict
from host_resource_operations import PHASES,ResourceError,integer,require,strict_json,text

MAX_PACKET=256*1024
ACTIONS={'request','status','reconcile','finish','launch-gate'}

@dataclass(frozen=True)
class NativeWorkloadRef:
    kind: Literal['slurm_allocation','systemd_build']
    native_id: str
    def __post_init__(self):
        require(type(self.kind) is str and self.kind in {'slurm_allocation','systemd_build'},'shape','supported native kind required')
        text(self.native_id,'native_id')
        require(len(self.native_id)<=200 and re.fullmatch(r'[A-Za-z0-9_.:@-]+',self.native_id),'shape','bounded native ID required')

@dataclass(frozen=True)
class NativeDemand:
    schema: Literal['qcl.host-resource-native-demand.v1']
    workload: NativeWorkloadRef
    workload_bytes: int
    def __post_init__(self):
        require(self.schema=='qcl.host-resource-native-demand.v1' and type(self.workload) is NativeWorkloadRef,'shape','native demand required')
        integer(self.workload_bytes,'workload_bytes',1)


class NativeWorkloadView(TypedDict):
    kind: Literal['slurm_allocation','systemd_build']
    native_id: str

class NativeFreshnessView(TypedDict):
    status: Literal['fresh','stale','not_measured','inconsistent']
    observed_at: int | None

class ResourceOperationView(TypedDict):
    schema: Literal['qcl.host-resource-operation.v1']
    request_id: str | None
    workload: NativeWorkloadView | None
    native_generation: str | None
    host_id: str | None
    vm_id: str | None
    state_generation: str | None
    phase: str
    admission: Literal['ready','resource_wait','reconciliation_required','unsupported','rejected']
    failure_code: str | None
    requested_workload_bytes: int | None
    target_bytes: int | None
    charged_bytes: int | None
    current_assigned_bytes: int | None
    current_configured_bytes: int | None
    protected_floor_bytes: int | None
    cleanup: Literal['not_started','pending','confirmed','unknown']
    native_freshness: NativeFreshnessView


def decode_native_ref(document: dict) -> NativeWorkloadRef:
    require(type(document) is dict and set(document)=={'kind','native_id'},'shape','native reference only')
    return NativeWorkloadRef(**document)


def decode_native_demand(document: dict) -> NativeDemand:
    require(type(document) is dict and set(document)=={'schema','workload','workload_bytes'},'shape','demand only; no proof/path/argv')
    return NativeDemand(document['schema'],decode_native_ref(document['workload']),document['workload_bytes'])


def decode_action(action,document):
    require(action in ACTIONS,'action','public resource action required')
    if action in {'request','launch-gate'}:return decode_native_demand(document)
    require(type(document) is dict and set(document)=={'schema','workload'} and
        document['schema']=='qcl.host-resource-native-reference.v1','shape','native reference packet required')
    return decode_native_ref(document['workload'])


def validate_operation_view(view: dict) -> ResourceOperationView:
    require(type(view) is dict and set(view)==set(ResourceOperationView.__required_keys__) and
        view['schema']=='qcl.host-resource-operation.v1','shape','complete public operation DTO required')
    require(type(view['phase']) is str and view['phase'] in PHASES|{'RESOURCE_WAIT','NOT_INITIALIZED','UNSUPPORTED','REJECTED'}
        and type(view['admission']) is str and view['admission'] in
        {'ready','resource_wait','reconciliation_required','unsupported','rejected'},'shape','public phase/admission required')
    for key in ('requested_workload_bytes','target_bytes','charged_bytes','current_assigned_bytes',
                'current_configured_bytes','protected_floor_bytes'):
        require(view[key] is None or (type(view[key]) is int and view[key]>=0),'shape','nullable byte count required')
    for key in ('request_id','native_generation','host_id','vm_id','state_generation'):
        require(view[key] is None or (type(view[key]) is str and 0<len(view[key])<=MAX_PACKET),'shape','nullable identity required')
    if view['workload'] is not None:decode_native_ref(view['workload'])
    require(view['failure_code'] is None or (type(view['failure_code']) is str and
        re.fullmatch(r'[A-Za-z0-9_]{1,80}',view['failure_code'])),'shape','bounded public failure code required')
    require(type(view['cleanup']) is str and view['cleanup'] in {'not_started','pending','confirmed','unknown'},'shape','cleanup status required')
    fresh=view['native_freshness']
    require(type(fresh) is dict and set(fresh)=={'status','observed_at'} and type(fresh['status']) is str and
        fresh['status'] in {'fresh','stale','not_measured','inconsistent'} and
        (fresh['observed_at'] is None or (type(fresh['observed_at']) is int and fresh['observed_at']>=0)),
        'shape','bounded freshness required')
    if view['admission']=='ready':
        require(view['phase']=='RUN' and fresh['status']=='fresh' and view['workload'] is not None and
            all(view[key] is not None for key in ('request_id','native_generation','host_id','vm_id',
                'requested_workload_bytes','target_bytes','charged_bytes','protected_floor_bytes')) and
            view['charged_bytes']>=view['target_bytes']>=view['protected_floor_bytes']>=view['requested_workload_bytes']>0,
            'shape','ready requires fresh exact paid native admission')
    return view


def exit_code(view,*,gate=False):
    if view['admission']=='resource_wait':return 75
    if view['admission'] in {'reconciliation_required','unsupported','rejected'}:return 78
    return 0 if not gate or view['phase']=='RUN' else 78


def _invoke(action,document):
    import application_release as engine
    value=decode_action(action,document)
    payload=base64.urlsafe_b64encode(json.dumps(document,separators=(',',':')).encode()).decode()
    # Fixed executable installed by the opt-in module. Credentials/path/route do
    # not come from payload, environment or an arbitrary CLI option.
    try:
        result=engine.command(['sudo','-n','/run/current-system/sw/bin/qcl-negf-resource-client-root',action,payload],
            timeout_seconds=120,output_bytes=MAX_PACKET)
    except engine.CommandFailure:
        from host_resource_service import operation_view
        ref=value.workload if type(value) is NativeDemand else value
        return operation_view(ref,failure='transport_unknown')
    response=validate_operation_view(strict_json(result))
    return response


def request_native(demand: NativeDemand) -> ResourceOperationView:return _invoke('request',asdict(demand))
def reconcile_native(workload: NativeWorkloadRef) -> ResourceOperationView:return _invoke('reconcile',{'schema':'qcl.host-resource-native-reference.v1','workload':asdict(workload)})
def finish_native(workload: NativeWorkloadRef) -> ResourceOperationView:return _invoke('finish',{'schema':'qcl.host-resource-native-reference.v1','workload':asdict(workload)})
def read_native_status(workload: NativeWorkloadRef) -> ResourceOperationView:return _invoke('status',{'schema':'qcl.host-resource-native-reference.v1','workload':asdict(workload)})


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=sorted(ACTIONS));parser.add_argument('--json-stdin',action='store_true',required=True)
    args=parser.parse_args(argv)
    try:
        raw=sys.stdin.buffer.read(MAX_PACKET+1)
        require(len(raw)<=MAX_PACKET,'output_bound','bounded JSON input required')
        document=strict_json(raw.decode());view=_invoke(args.action,document)
    except (ResourceError,ValueError,UnicodeError) as error:
        from host_resource_service import operation_view
        view=operation_view(NativeWorkloadRef('slurm_allocation','unknown'),failure=getattr(error,'code','shape'))
        view['workload']=None
    output=json.dumps(view,separators=(',',':'));require(len(output.encode())<=MAX_PACKET,'output_bound','bounded response required')
    print(output);return exit_code(view,gate=args.action=='launch-gate')

if __name__=='__main__':sys.exit(main())
