"""Bounded read-only resource projection. No probe refresh or poll persistence."""
import base64
import json
from pathlib import Path
import time
from host_resource_operations import FileReceiptStore,HostResourceController,ResourceError,STATE_SCHEMA,require,integer
from host_resource_service import operation_view,generation
from host_resource_client import NativeWorkloadRef,MAX_PACKET


class ResourceProjection:
    def __init__(self,directory,*,policy=None,probe_path=None,owner_uid=0,clock=time.time):
        self.directory,self.policy,self.probe_path,self.owner_uid,self.clock=Path(directory),policy,probe_path,owner_uid,clock
    def read(self,*,request_id=None,cursor=None,limit=64):
        integer(limit,'limit',1);require(limit<=128,'output_bound','projection page bound')
        require(request_id is None or (type(request_id) is str and 0<len(request_id.encode())<=MAX_PACKET),
            'shape','bounded exact request ID required')
        result=dict(schema='qcl.host-resource-projection.v1',observed_at=int(self.clock()),state_generation=None,
            status='not_initialized',host=None,vms=[],operations=[],complete=True,next_cursor=None)
        try:store=FileReceiptStore.open_existing(self.directory,owner_uid=self.owner_uid)
        except FileNotFoundError:return result
        try:
            with store.locked(read_only=True):
                state=store.load()
                if state.get('schema') in {'qcl.host-resource-state.v1','qcl.host-resource-state.v2'}:
                    result.update(status='upgrade_required',state_generation=generation(state));return result
                require(state.get('schema')==STATE_SCHEMA,'state','unknown owner state')
                if self.policy:
                    class ReadOnlyBackend:quantum_bytes=1
                    state=HostResourceController(self.policy,store,ReadOnlyBackend(),self.clock)._load()
                else:require(False,'state','validated policy required for a current projection')
                gen=generation(state);result.update(status='reconciliation_required' if state['blocked'] else 'ok',state_generation=gen)
                offset=0
                if cursor is not None:
                    require(type(cursor) is str and len(cursor)<=1024,'stale_cursor','bounded opaque cursor required')
                    try:packet=json.loads(base64.b64decode(cursor,altchars=b'-_',validate=True))
                    except (ValueError,TypeError):raise ResourceError('stale_cursor','invalid cursor')
                    require(type(packet) is list and len(packet)==3 and packet[0]==gen and packet[2]==request_id,
                        'stale_cursor','state changed; restart page')
                    integer(packet[1],'offset');offset=packet[1]
                freshness=dict(status='not_measured',observed_at=None)
                if self.probe_path and Path(self.probe_path).exists():
                    # root-owned cache read only; never asks a provider to refresh.
                    from host_resource_backends import read_root_json
                    probe=read_root_json(self.probe_path);host=probe.get('host',{})
                    at=host.get('observed_at')
                    if host.get('host_boot_id')!=state['host_boot_id'] or host.get('policy_sha256')!=state['policy_sha256']:
                        freshness=dict(status='inconsistent',observed_at=at if type(at) is int else None)
                    elif type(at) is int:
                        freshness=dict(status='fresh' if 0<=self.clock()-at<=self.policy.timeouts.request_seconds else 'stale',observed_at=at)
                p=self.policy;result['host']=dict(host_id=p.host_id,physical_ram_bytes=p.physical_ram_bytes,
                    H_bytes=p.reserves.host_services_bytes+p.reserves.control_plane_bytes+p.reserves.safety_bytes,
                    F_bytes=p.reserves.foreign_max_bytes,owned_pool_bytes=p.owned_pool.capacity_bytes,
                    charged_guest_bytes=sum(g['guest_bytes'] for g in state['grants']),
                    overhead_bytes=sum(v.overhead_bytes for v in p.vms),native_freshness=freshness)
                for vm in p.vms:
                    grant=next(g for g in state['grants'] if g['vm_id']==vm.vm_id)
                    result['vms'].append(dict(vm_id=vm.vm_id,grant_state=grant['state'],charged_bytes=grant['guest_bytes'],
                        desired_bytes=state['desired'][vm.vm_id],current_assigned_bytes=None,current_configured_bytes=None,
                        protected_floor_bytes=grant['active_floor_bytes'],boot_phase=state['startups'][vm.vm_id]['phase'],
                        maintenance_required=True if state['blocked'] else None,failure_code='reconciliation_required' if state['blocked'] else None,
                        native_freshness=freshness,cpu=dict(desired_weight=vm.cpu_weight,current_weight=None,configured_vcpus=None,online_vcpus=None,online_change_supported=False)))
                rows=[r for r in state['receipts'] if request_id is None or r['request']['request_id']==request_id]
                # One exact completed lookup is allowed; never scan archive/history.
                if request_id and not rows:
                    archived=store.completed(request_id)
                    if archived:rows=[archived]
                rows.sort(key=lambda row:row['request']['request_id'])
                require(offset<=len(rows),'stale_cursor','invalid cursor position')
                for row in rows[offset:offset+limit]:
                    native=row.get('native_workload')
                    if native:
                        view=operation_view(NativeWorkloadRef(native['kind'],native['native_id']),state=state,row=row)
                    else:
                        # No invented native identity for typed/legacy owner rows.
                        view=operation_view(NativeWorkloadRef('slurm_allocation','unknown'),state=state,row=row,failure='native_generation')
                        view['workload']=None
                    if view['admission']=='ready':
                        view.update(admission='reconciliation_required',failure_code='readback_not_measured')
                    view['native_freshness']=freshness;result['operations'].append(view)
                next_offset=offset+len(result['operations']);result['complete']=next_offset>=len(rows)
                if not result['complete']:
                    result['next_cursor']=base64.urlsafe_b64encode(json.dumps([gen,next_offset,request_id],separators=(',',':')).encode()).decode()
        except FileNotFoundError:return result
        except ResourceError as error:
            if error.code in {'stale_cursor','output_bound'}:raise
            result.update(status='reconciliation_required',operations=[],vms=[],host=None)
        require(len(json.dumps(result,separators=(',',':')).encode())<=MAX_PACKET,'output_bound','projection output bound; reduce page size')
        return result


def read_resource_projection(*,request_id=None,cursor=None,limit=64):
    from host_resource_backends import read_root_json
    from host_resource_service import CONFIG
    from host_resource_policy import validate_host_resource_policy
    config=read_root_json(CONFIG);runtime=read_root_json(config['runtime'])
    policy=validate_host_resource_policy(read_root_json(runtime['policy']))
    return ResourceProjection(runtime['state_directory'],policy=policy,probe_path=runtime['evidence']).read(
        request_id=request_id,cursor=cursor,limit=limit)
