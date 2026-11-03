"""Root-observed native facts. Public demand is never an evidence document.

Only enrolled, version-qualified read protocols are accepted. Missing observations
close admission. This module never submits/cancels work or starts a guest.
"""
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import re
import time
import uuid
import xml.etree.ElementTree as ET

import application_release as command_engine
from host_resource_operations import (BackendQualification, CompletionEvidence, GuestEvidence,
    HostEvidence, ResourceError, RuntimeBinding, integer, policy_digest,
    require, strict_json, text)
from host_resource_backends import (collect_native_runtime, fingerprint, pve_memory_mib, read_root_json, read_root_qualification_report,
    trusted_root_path, MAX_OUTPUT_BYTES)
from host_resource_startup import ColdHostEvidence, ColdVMRecord

TERMINAL={'CANCELLED','COMPLETED','FAILED','TIMEOUT','OUT_OF_MEMORY','NODE_FAIL','PREEMPTED','BOOT_FAIL','DEADLINE'}
JOB_ID=re.compile(r'[1-9][0-9]{0,18}\Z')
def _output_sha256(value):
    require(type(value)is str and re.fullmatch(r'[0-9a-f]{64}',value)is not None,'qualification','actual protected SHA required')

SERVICE_CONFIG=Path('/etc/qcl-negf/host-resources/service.json')


def meminfo(raw):
    result={}
    for line in raw.splitlines():
        match=re.fullmatch(r'(MemTotal|MemAvailable):\s+([0-9]+) kB',line)
        if match:result[match[1]]=int(match[2])*1024
    require(set(result)=={'MemTotal','MemAvailable'} and 0<=result['MemAvailable']<=result['MemTotal'],
            'incomplete_probe','complete native meminfo required')
    return result


def parse_slurm_jobs(raw,*,cluster):
    """Qualified scontrol oneline v1, single node/allocation, no restart/requeue."""
    result={}
    for line in raw.splitlines():
        if not line.strip():continue
        fields=dict(re.findall(r'(?:^|\s)([A-Za-z][A-Za-z0-9_]*)=([^\s]*)',line))
        required={'JobId','UserId','JobState','NumNodes','NumTasks','NodeList','SubmitTime','StartTime','Restarts'}
        require(required<=fields.keys(),'unsupported','incomplete scontrol job protocol')
        job=fields['JobId'];require(JOB_ID.fullmatch(job) and job not in result,'unsupported','simple unique native job required')
        owner=re.fullmatch(r'[^()\s]+\(([0-9]+)\)',fields['UserId'])
        require(owner and fields['NumNodes']=='1' and fields['NumTasks']=='1' and fields['Restarts']=='0'
            and fields.get('ArrayJobId','0')=='0' and fields.get('HetJobId','0')=='0'
            and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',fields['NodeList']),
            'unsupported','only one-node one-task non-restarted allocation supported')
        limit=re.fullmatch(r'([1-9][0-9]*)([KMGT]?)',fields.get('MinMemoryNode',''))
        require(limit is not None,'unsupported','explicit per-node native memory limit required')
        # Slurm displays an unsuffixed value in MiB; never round its charge down.
        scale={'':1024**2,'K':1024,'M':1024**2,'G':1024**3,'T':1024**4}
        for name in ('SubmitTime','StartTime'):
            require(re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}',fields[name]),
                    'native_generation','allocated job generation unavailable/evicted')
        state=fields['JobState']
        exit_code=fields.get('ExitCode')
        require(exit_code is None or re.fullmatch(r'[0-9]+:[0-9]+',exit_code) is not None,'unsupported','literal native exit status required')
        generation=fingerprint([cluster,job,fields['UserId'],fields['SubmitTime'],fields['StartTime'],fields['Restarts']])
        result[job]=dict(native_id=job,kind='slurm_allocation',generation=generation,
            owner_uid=int(owner[1]),node=fields['NodeList'],state=state,terminal=state in TERMINAL,
            limit_bytes=int(limit[1])*scale[limit[2]],submit_time=fields['SubmitTime'],start_time=fields['StartTime'],
            cluster=cluster,raw_user_id=fields['UserId'],exit_code=exit_code)
    return result


def workload_identity(native):
    # Native generation is observed, never accepted from a client.
    generation=fingerprint([native.get('generation'),native.get('submit_time'),native.get('start_time')])
    return 'slurm:'+generation if native.get('kind','slurm_allocation')=='slurm_allocation' else 'build:'+generation


def _output_native_tuple(native):
    keys=('cluster','raw_user_id','owner_uid','node','submit_time','start_time','limit_bytes')
    require(type(native) is dict and all(k in native for k in (*keys,'native_id','generation','exit_code','state','terminal')),
        'cleanup','complete literal native tuple required')
    value={k:native[k] for k in keys};value.update(job_id=native['native_id'],restarts=0)
    generation=fingerprint([value[k] for k in ('cluster','job_id','raw_user_id','submit_time','start_time')]+['0'])
    require(generation==native['generation'] and native['state']=='COMPLETED' and native['terminal'] is True and
        native['exit_code']=='0:0' and type(native['owner_uid']) is int and native['owner_uid']==3000,
        'cleanup','exact successful original native allocation required')
    return value


def _scheduler_output_observations(packet):
    """Finite detached metadata projection from the existing authenticated RPC.

    The RPC reader has already bounded/decoded its original JSON and rejected
    duplicate keys. These fields convey no authority before the later guest,
    original tuple and protected owner joins.
    """
    require(type(packet) is dict and {'schema','jobs'}<=packet.keys() and
        set(packet)<={'schema','jobs','outputs'} and packet['schema']=='qcl.host-resource-scheduler-facts.v1'
        and type(packet['jobs']) is dict,'shape','closed scheduler facts packet required')
    outputs=packet.get('outputs',{})
    require(type(outputs) is dict and len(outputs)<=8,'output_bound','finite output map required')
    def fields(value,names):
        require(type(value) is dict and set(value)==set(names),'shape','closed output fields required')
    def string(value,maximum):
        require(type(value) is str and 0<len(value)<=maximum and '\x00' not in value and
            len(value.encode())<=maximum,'shape','bounded output string required')
    def sha(value):
        require(type(value) is str and re.fullmatch(r'[0-9a-f]{64}',value),'shape','output SHA required')
    def identity(value):
        fields(value,('machine_id','boot_id','kernel','dmi_uuid'))
        require(type(value['machine_id']) is str and re.fullmatch(r'[0-9a-f]{32}',value['machine_id']),
            'shape','machine identity required')
        for name in ('boot_id','dmi_uuid'):
            string(value[name],36)
            try:valid=str(uuid.UUID(value[name]))==value[name] and uuid.UUID(value[name]).int!=0
            except ValueError:valid=False
            require(valid,'shape','canonical output identity required')
        string(value['kernel'],256)
    retained=[];total=0
    for generation,value in outputs.items():
        sha(generation)
        fields(value,('generation','durable','scope','observed_at','controller_identity',
            'worker_identity','owner','attempt','native_tuple','publication'))
        require(value['generation']==generation and type(value['durable']) is bool and
            value['scope'] in ('controls','completed_final') and
            (value['scope']!='controls' or value['durable'] is False),'shape','output scope/generation differs')
        integer(value['observed_at'],'output observed_at')
        identity(value['controller_identity']);identity(value['worker_identity'])
        owner=value['owner'];fields(owner,('policy_sha256','qualification_sha256','source_graph_sha256',
            'unit_generation_sha256','storage_identity','retention_ref'))
        for key in ('policy_sha256','qualification_sha256','source_graph_sha256','unit_generation_sha256'):sha(owner[key])
        for key in ('storage_identity','retention_ref'):string(owner[key],256)
        attempt=value['attempt'];fields(attempt,('calcjob_uuid','dispatch_id','generation'));sha(attempt['generation'])
        for key in ('calcjob_uuid','dispatch_id'):
            string(attempt[key],36)
            try:valid=str(uuid.UUID(attempt[key]))==attempt[key] and uuid.UUID(attempt[key]).int!=0
            except ValueError:valid=False
            require(valid,'shape','canonical attempt identity required')
        native=value['native_tuple'];fields(native,('cluster','job_id','raw_user_id','owner_uid','node',
            'submit_time','start_time','restarts','limit_bytes'))
        for key in ('cluster','node'):
            string(native[key],128)
            require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',native[key]),'shape','simple native name required')
        require(type(native['job_id']) is str and JOB_ID.fullmatch(native['job_id']) and
            type(native['owner_uid']) is int and native['owner_uid']==3000 and
            type(native['restarts']) is int and native['restarts']==0,'native_generation','simple original allocation required')
        string(native['raw_user_id'],128)
        require(re.fullmatch(r'[^()\s]+\(3000\)',native['raw_user_id']),'native_generation','literal native owner required')
        integer(native['limit_bytes'],'native output allocation',1)
        for key in ('submit_time','start_time'):
            require(type(native[key]) is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}',native[key]),
                'native_generation','original allocation times required')
        require(generation==fingerprint([native[k] for k in
            ('cluster','job_id','raw_user_id','submit_time','start_time')]+[str(native['restarts'])]),
            'native_generation','resource generation differs from original native tuple')
        publication=value['publication'];fields(publication,('close_sha256','close_observation_sha256','result_sha256','selection_sha256'))
        for digest in publication.values():sha(digest)
        raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
        require(len(raw)<=8192,'output_bound','output observation bound')
        total+=len(raw);require(total<=65536,'output_bound','aggregate output observation bound')
        retained.append((generation,raw))
    require(len(json.dumps(packet,sort_keys=True,separators=(',',':'),allow_nan=False).encode())<=MAX_OUTPUT_BYTES,
        'output_bound','whole scheduler packet bound')
    # All entry/aggregate admissions precede detached output materialization.
    return {generation:json.loads(raw) for generation,raw in retained}


def authenticate_sudo_caller(environment,*,parent_pid,process,sudo_executables,allowed_uid):
    require(str(environment.get('SUDO_UID','')).isdigit() and int(environment['SUDO_UID'])==allowed_uid,
            'caller','enrolled sudo caller UID required')
    chain=[];pid=parent_pid
    for _ in range(8):
        item=process(pid);chain.append(item)
        if item['executable'] not in sudo_executables:break
        require(item['uids'] in ([0]*4,[allowed_uid,0,0,0],[allowed_uid]*4),
            'caller','unexpected sudo real/effective credentials')
        pid=item['ppid']
    require(len(chain)>=2 and chain[0]['executable'] in sudo_executables and
        chain[-1]['executable'] not in sudo_executables,'caller','observed sudo ancestry required')
    caller=chain[-1]
    require(caller['uids']==[allowed_uid]*4 and caller['start_ticks']>0 and caller['cgroup']!='/' and
        all(child['start_ticks']>=parent['start_ticks']>0 and child['cgroup']==parent['cgroup']
            for child,parent in zip(chain,chain[1:])),
        'caller','root-observed original owner/generation/cgroup required')
    require(all(item==process(item['pid']) for item in chain),'caller','caller ancestry changed during capture')

    return caller


def validate_inventory(rows,enrollment,foreign,*,foreign_budget,observed_qemu_pids):
    integer(foreign_budget,'foreign budget')
    fields={'native_id','maximum_bytes','kind','running','process_id','config_fingerprint'}
    require(type(rows) is list and all(type(r) is dict and fields<=r.keys() for r in rows),
            'incomplete_inventory','complete native inventory fields required')
    require(type(enrollment) is dict and all(type(r) is dict and
        {'native_id','maximum_bytes'}<=r.keys() for r in enrollment.values()),
        'incomplete_inventory','explicit enrolled native maxima required')
    require(type(foreign) is dict and all(type(r) is dict and
        {'maximum_bytes','overhead_bytes','config_fingerprint'}<=r.keys() for r in foreign.values()),
        'incomplete_inventory','explicit foreign maximum, overhead and config agreement required')
    for row in rows:
        text(row['native_id'],'native_id');text(row['config_fingerprint'],'config_fingerprint')
        integer(row['maximum_bytes'],'native maximum',1)
        require(type(row['kind']) is str and row['kind'] in {'qemu','lxc'} and type(row['running']) is bool,
                'incomplete_inventory','known native kind/power state required')
    for row in enrollment.values():
        text(row['native_id'],'enrolled native_id');integer(row['maximum_bytes'],'enrolled maximum',1)
    for native,agreed in foreign.items():
        text(native,'foreign native_id');text(agreed['config_fingerprint'],'foreign config_fingerprint')
        integer(agreed['maximum_bytes'],'agreed maximum',1)
        integer(agreed['overhead_bytes'],'agreed overhead')
    owned={r['native_id']:r for r in enrollment.values()}
    by_id={r['native_id']:r for r in rows}
    require(len(by_id)==len(rows) and len(owned)==len(enrollment),
            'incomplete_inventory','unique native/enrolled identities required')
    require(set(by_id)==set(owned)|set(foreign) and not set(owned)&set(foreign),
            'incomplete_inventory','unaccounted/missing native VM or container')
    total=0
    for native,row in by_id.items():
        if native in owned:
            require(row['maximum_bytes']==owned[native]['maximum_bytes'],'capacity_evidence','owned maximum drift')
        else:
            agreed=foreign[native]
            require(row['maximum_bytes']<=agreed['maximum_bytes'] and
                row['config_fingerprint']==agreed['config_fingerprint'],
                'capacity_evidence','foreign bound/config changed; preserve foreign resources')
            total+=agreed['maximum_bytes']+agreed['overhead_bytes']
    require(total<=foreign_budget,'capacity_evidence','foreign maximum/overhead exceeds paid F')
    require({str(r['process_id']) for r in rows if r['kind']=='qemu' and r['running']}==set(observed_qemu_pids),
            'incomplete_inventory','unmanaged QEMU or incomplete process inventory')
    return total


def classify_guest_workloads(jobs,groups,known,*,gate_executables):
    live=[]
    require(set(groups)==set(jobs),'incomplete_workloads','complete native cgroup snapshot required')
    for job_id,job in jobs.items():
        group=groups[job_id];processes=group['processes']
        require(type(group['populated']) is bool and bool(processes)==group['populated'],
                'incomplete_workloads','cgroup population/process snapshot differs')
        if job['terminal']:
            require(not group['populated'],'cleanup','terminal job still has descendants')
            continue
        require(job['state'] in {'RUNNING','CONFIGURING','COMPLETING'},'unsupported','unknown allocated job state')
        identity='slurm:'+job['generation']
        record=known.get(identity)
        if record is None:
            require(processes and all(p['uids']==[job['owner_uid']]*4 and
                p['executable'] in gate_executables and p['start_ticks']>0 for p in processes)
                and job['state']!='COMPLETING','incomplete_workloads','unexpected workload has no paid admission')
        else:
            require(record['native_id']==job_id and record['generation']==job['generation'] and
                record['phase']=='RUN' and group['populated'],'incomplete_workloads','live native owner missing/mismatched')
            live.append(identity)
    return tuple(sorted(live))


class LocalSources:
    """Real readers; tests inject an explicit synthetic source, never a production flag."""
    def __init__(self,config,runner):self.config,self.runner=config,runner
    def qualification_gate_sources(self):
        from host_resource_qualification_sources import open_guest_gate_sources
        return open_guest_gate_sources(self)
    def qualification_subset(self):
        from host_resource_qualification_sources import open_role_readonly_subset
        require(self.config['role'] in ('guest','controller'), 'qualification_role', 'fixed local facts role required')
        return open_role_readonly_subset('worker' if self.config['role']=='guest' else 'controller')
    def read(self,path,limit=65536):
        source=getattr(self,'_output_sources',None)
        if source is not None:return source.budget.read(path,limit).decode()
        with open(path,'rb') as stream:data=stream.read(limit+1)
        require(len(data)<=limit,'output_bound','native metadata exceeds bound')
        return data.decode()
    def host(self):
        return dict(boot_id=self.read('/proc/sys/kernel/random/boot_id').strip(),
            machine_id=self.read('/etc/machine-id').strip(),kernel=self.read('/proc/sys/kernel/osrelease').strip(),
            dmi_uuid=self.read('/sys/class/dmi/id/product_uuid').strip().lower(),**meminfo(self.read('/proc/meminfo')))
    def process(self,pid):
        source=getattr(self,'_output_sources',None)
        budget=source.budget if source is not None else command_engine.UpdateScan(time.monotonic()+10)
        row=command_engine.process_record(budget,Path('/proc')/str(pid))
        raw=budget.read(Path('/proc')/str(pid)/'stat').decode();fields=raw[raw.rfind(')')+2:].split()
        row['ppid']=int(fields[1])
        require(int(fields[19])==row['start_ticks'],'caller','PID birth changed')
        return {k:row[k] for k in ('pid','ppid','uids','start_ticks','cgroup','executable')}
    def processes(self):
        source=getattr(self,'_output_sources',None)
        budget=source.budget if source is not None else command_engine.UpdateScan(time.monotonic()+10);rows=[]
        for path in budget.entries('/proc','pid'):
            if source is not None:require(len(rows)<budget.limits['maximum_pids'],'output_bound','bounded native process inventory required')
            try:
                classification=command_engine.process_classification(budget,path)
                if command_engine.process_state_class(classification)=='nonexecuting':
                    rows.append({**classification,'executable':'[nonexecuting]'});continue
                raw=budget.read(path/'stat').decode();fields=raw[raw.rfind(')')+2:].split()
                if int(fields[6]) & 0x00200000:  # kernel PF_KTHREAD, read from /proc
                    require(classification['uids']==[0]*4,'incomplete_probe','unexpected kernel credentials')
                    rows.append({**classification,'executable':'[kernel]'});continue
                rows.append(command_engine.process_record(budget,path))
            except FileNotFoundError:raise ResourceError('incomplete_probe','process disappeared during complete scan')
        return rows
    def run(self,argv):
        source=getattr(self,'_output_sources',None)
        if source is None:return self.runner.run(argv,timeout_seconds=30)
        require(type(argv) in (list,tuple) and argv and argv[0] in self.runner.tools and
            argv[0] in source.policy['tools'].values(),'argv','same enrolled native tools required')
        require(source.origin(argv[0])==argv[0],'qualification','native tool origin changed')
        return source.run(argv)
    def guest_identity(self,vm_id):
        return trusted_rpc(self.config['guests'][vm_id],'guest-identity',{},run=command_engine.command)
    def guest(self,vm_id):
        route=self.config['guests'][vm_id]
        return trusted_rpc(route,'guest-facts',{},run=command_engine.command)
    def guest_calibration(self,vm_id):
        # Same authenticated fixed read route; shared protected config must opt in.
        packet=self.guest(vm_id)
        require(type(packet.get('calibration_accounting'))is dict,'qualification_observations_required','actual accounting reader not enabled')
        return packet
    def calibration_attempt(self,vm_id,calcjob_uuid,creator):
        # Existing read-only status phase validates original hook/dispatch/source;
        # it does not create before/after evidence or change a worker journal.
        return trusted_rpc(self.config['guests'][vm_id],'attempt-facts',dict(version=1,calcjob_uuid=calcjob_uuid,
            dispatch_id=creator['dispatch_id'],job_id=creator['job_id'],generation=creator['generation'],phase='status'),run=command_engine.command)
    def fixed_native(self,backend,vm_id):
        """Original read-only native config; a fixed protocol label is not proof."""
        from host_resource_backends import ProxmoxMemoryBackend,LibvirtMemoryBackend
        require(type(backend)in (ProxmoxMemoryBackend,LibvirtMemoryBackend)and backend.dynamic is False,
            'qualification','actual fixed native backend required')
        if type(backend)is ProxmoxMemoryBackend:
            return dict(backend='proxmox',configuration=strict_json(backend._run(
                ['get',backend._path(vm_id)+'/config','--current','1'])))
        return dict(backend='libvirt',configuration=backend._run(['dumpxml',backend._vm(vm_id).native_id]))
    def inventory(self,backend):
        rows=[]
        if self.config['backend_config']['backend']=='proxmox':
            root=f"/nodes/{backend.node}"
            for kind in ('qemu','lxc'):
                listing=strict_json(backend._run(['get',root+'/'+kind]))
                require(type(listing) is list,'incomplete_inventory','native listing required')
                for item in listing:
                    vmid=item['vmid'];integer(vmid,'native VMID',1)
                    cfg=strict_json(backend._run(['get',f'{root}/{kind}/{vmid}/config','--current','1']))
                    if cfg.get('template',0)==1:continue
                    if kind=='qemu':
                        uuid=re.findall(r'(?:^|,)uuid=([^,]+)(?:,|$)',cfg.get('smbios1',''))
                        require(len(uuid)==1,'incomplete_inventory','every QEMU requires actual UUID')
                        native=uuid[0]
                    else:native='lxc:'+str(vmid)
                    maximum=pve_memory_mib(cfg.get('memory'))*1024**2
                    status=strict_json(backend._run(['get',f'{root}/{kind}/{vmid}/status/current']))
                    from host_resource_backends import pve_config_fingerprint
                    stable=pve_config_fingerprint(cfg)
                    rows.append(dict(kind=kind,native_id=native,maximum_bytes=maximum,
                        running=status['status']=='running',process_id=str(status['pid']) if status['status']=='running' and kind=='qemu' else None,
                        config_fingerprint=stable))
        else:
            uuids=backend._run(['list','--all','--uuid']).split()
            for uuid in uuids:
                raw=backend._run(['dumpxml',uuid]);require('<!DOCTYPE' not in raw and '<!ENTITY' not in raw,'readback','unsafe XML')
                xml=ET.fromstring(raw);name=xml.findtext('name')
                require(type(name) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',name),
                    'unsupported','foreign domain name has no safe qualified PID locator')
                state=backend._run(['domstate',uuid]).strip()
                running=state=='running'
                require(state in {'running','shut off'},'unsupported','transitional domain state')
                from host_resource_backends import libvirt_config_fingerprint
                config_hash=libvirt_config_fingerprint(xml);pid=None
                if running:
                    path=trusted_root_path(f'/run/libvirt/qemu/{name}.pid')
                    require(path.stat().st_size<=32,'output_bound','bounded native PID locator required')
                    pid=path.read_text().strip()
                    require(pid.isdigit() and int(pid)>0,'incomplete_inventory','actual native PID required')
                rows.append(dict(kind='qemu',native_id=uuid,maximum_bytes=backend._memory(xml.find('memory')),
                    running=running,process_id=pid,config_fingerprint=config_hash))
        return rows


def trusted_rpc(route,action,payload,*,run,trust_snapshot_root=None,existing_budget=None):
    """Protected route only; existing P11 strict host-key snapshot and command engine."""
    import base64
    require(action in {'guest-facts','guest-identity','scheduler-facts','attempt-facts','request','status','reconcile','finish','launch-gate'},'action','fixed resource RPC action required')
    require(set(route)=={'target','known_hosts','identity_file','helper','role'},'trust','enrolled RPC route required')
    require(re.fullmatch(r'[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+',route['target']), 'trust','fixed SSH target required')
    if existing_budget is not None:
        from native_attempt import _reserve_private_record
        existing_budget.before()
        # Four encodings' conservative bounds cover prospective ASCII JSON,
        # UTF8 bytes, base64 bytes/string and quoted/resident argv. The existing
        # encoder forecast is >=2*JSON's worst escaped length. No request
        # materialization or trust-snapshot effect precedes this admission.
        for _ in range(4):_reserve_private_record(payload,existing_budget)
        existing_budget.reserve(32768)
        for value in route.values():
            require(type(value) is str and len(value)<=4096,'trust','bounded enrolled route required')
            existing_budget.reserve(16*len(value)+256)
    key=trusted_root_path(route['identity_file']);known=trusted_root_path(route['known_hosts'])
    require(not key.stat().st_mode&0o077,'trust','private runtime key permissions')
    if existing_budget is not None:existing_budget.before()
    if existing_budget is None:
        raw=command_engine.read_protected_file(known)
    else:
        raw=command_engine.read_protected_file(known,budget=existing_budget)
        # Bounded original trust bytes, immutable snapshot copy and finite path bookkeeping.
        existing_budget.reserve(3*len(raw)+16384)
    if trust_snapshot_root is None:
        snapshot=command_engine.freeze_ssh_trust(raw)
    else:
        # G retains the actual nofollow/root ancestry check and immutable write.
        snapshot=command_engine.freeze_ssh_trust(raw,snapshot_root=trust_snapshot_root)
    token=base64.urlsafe_b64encode(json.dumps(payload,separators=(',',':')).encode()).decode()
    require(len(token)<=MAX_OUTPUT_BYTES,'output_bound','RPC input bound')
    result=command_engine.ssh(route['target'],[route['helper'],route['role'],action,token],
        run=lambda argv:run([argv[0],'-oIdentitiesOnly=yes','-oIdentityAgent=none','-i',str(key),*argv[1:]],
            timeout_seconds=120,output_bytes=MAX_OUTPUT_BYTES),trust_snapshot=snapshot)
    if existing_budget is not None:
        # The caller's Operation.command already prepaid four response caps
        # before transport, including retained raw buffers. Only the additional
        # prospective JSON decoder graph/workspace is admitted here, from the
        # actual bounded raw string, before strict_json can allocate that graph.
        # This operational forecast is not a Python RSS measurement.
        existing_budget.before();existing_budget.reserve(64*len(result)+4096)
    packet=strict_json(result);require(type(packet) is dict,'shape','bounded RPC object required')
    return packet


class NativeFactsProvider:
    def __init__(self,policy,config,backend,runner,*,sources=None,clock=time.time):
        self.policy,self.config,self.backend,self.runner,self.clock=policy,config,backend,runner,clock
        self.sources=sources or LocalSources(config,runner)
        self.last=None;self.native={}
        self._output_epoch=self._joined_epoch=self._pending_epoch=None
        self._pending_outputs={};self._joined_outputs={};self._pending_jobs={};self._output_config=None
    def _host_inventory(self,*,retiring_vm_id=None):
        before=self.sources.host();enrolled=self.config['enrollment'];agreement=read_root_json(self.config['agreement'])
        require(before['machine_id']==self.config['host_identity']['machine_id'] and
            before['dmi_uuid']==self.config['host_identity']['dmi_uuid'] and
            before['MemTotal']==self.policy.physical_ram_bytes,'identity_mismatch','actual host identity/RAM changed')
        require(agreement['schema']=='qcl.host-resource-native-agreement.v1' and
            agreement['policy_sha256']==policy_digest(self.policy) and
            agreement['agreement_ref']==self.policy.owned_pool.agreement_ref,
            'capacity_evidence','protected current administration agreement required')
        require(set(enrolled)=={vm.vm_id for vm in self.policy.vms} and all(
            enrolled[vm.vm_id]['maximum_bytes']==vm.maximum_bytes for vm in self.policy.vms),
            'capacity_evidence','enrollment/native maxima must match policy exactly')
        rows=self.sources.inventory(getattr(self.backend,'native_backend',self.backend))
        qemu={str(p['pid']) for p in self.sources.processes() if 'qemu-system-' in Path(p['executable']).name or Path(p['executable']).name in {'kvm','qemu-kvm'}}
        if retiring_vm_id is not None:
            require(retiring_vm_id in enrolled,'ownership','exact retiring resident required')
            old=enrolled[retiring_vm_id]['native_id']
            if not any(r['native_id']==old for r in rows):enrolled={k:v for k,v in enrolled.items() if k!=retiring_vm_id}
        validate_inventory(rows,enrolled,agreement['foreign'],foreign_budget=self.policy.reserves.foreign_max_bytes,observed_qemu_pids=qemu)
        after=self.sources.host()
        require(all(before[k]==after[k] for k in ('boot_id','machine_id','kernel','dmi_uuid','MemTotal')),
            'identity_mismatch','host changed while capturing facts')
        before['MemAvailable']=min(before['MemAvailable'],after['MemAvailable'])
        return before,rows,agreement
    def cold_facts(self):
        host,rows,agreement=self._host_inventory();by_id={r['native_id']:r for r in rows}
        return ColdHostEvidence(self.policy.host_id,self.policy.owner_id,host['boot_id'],policy_digest(self.policy),int(self.clock()),
            host['MemTotal'],self.policy.reserves.foreign_max_bytes,self.policy.capacity_evidence_ref,
            self.policy.owned_pool.agreement_ref,fingerprint(agreement),host['MemAvailable']>=self.policy.reserves.safety_bytes,
            tuple(ColdVMRecord(vm.vm_id,self.config['enrollment'][vm.vm_id]['native_id'],
                by_id[self.config['enrollment'][vm.vm_id]['native_id']]['config_fingerprint'],by_id[self.config['enrollment'][vm.vm_id]['native_id']]['maximum_bytes'],
                by_id[self.config['enrollment'][vm.vm_id]['native_id']]['maximum_bytes'],'running' if by_id[self.config['enrollment'][vm.vm_id]['native_id']]['running'] else 'stopped') for vm in self.policy.vms))
    def resolve(self,ref):
        self._end_invocation();self._output_epoch=object()
        try:
            require(ref.kind=='slurm_allocation','unsupported','systemd/Nix per-build daemon join is not qualified; use paid full-VM administrative reservation')
            require(JOB_ID.fullmatch(ref.native_id),'shape','native allocation ID required')
            # Native scheduler generation must still exist. Never synthesize from job ID.
            self._output_config=self._current_output_config()
            route=self.config['scheduler_route'];packet=trusted_rpc(route,'scheduler-facts',{},run=command_engine.command)
            outputs=_scheduler_output_observations(packet)
            jobs=packet['jobs'];require(ref.native_id in jobs,'native_generation','native allocation missing/evicted')
            native=jobs[ref.native_id];require(native['owner_uid']==self.config['client_uid'],'ownership','native owner differs')
            vm=self.config['nodes'].get(native['node']);require(vm in self.config['enrollment'],'ownership','node not enrolled on this host')
            identity='slurm:'+native['generation'];self.native[identity]=native
            self._pending_outputs=outputs
            self._pending_epoch=self._output_epoch
            self._pending_jobs={value['native_tuple']['job_id']:_output_native_tuple(jobs[value['native_tuple']['job_id']])
                for value in outputs.values()}
            return native,vm,identity,'native-'+hashlib.sha256(identity.encode()).hexdigest()
        except BaseException:
            self._end_invocation();raise
    def _calibration_binding_pair(self,ctx):
        """Actual paired native/guest identity and Source, without a physical verdict."""
        from native_attempt import _output_worker,_output_runner,Hold
        from host_resource_qualification_observations import context
        try:
            started_at=self.clock();started_ns=time.monotonic_ns()
            context(ctx);host,inventory,agreement=self._host_inventory();vm=next(vm for vm in self.policy.vms if vm.vm_id==ctx['binding']['vm_id'])
            require(ctx['host_id']==self.policy.host_id and ctx['owner_id']==self.policy.owner_id and
                ctx['host_boot_id']==host['boot_id']and ctx['policy_sha256']==policy_digest(self.policy)and
                vm.minimum_bytes==ctx['native_minimum_bytes']and vm.maximum_bytes==ctx['native_maximum_bytes']and
                self.backend.quantum_bytes==ctx['quantum_bytes'],'identity_mismatch','actual host/policy/native bounds changed')
            read=self.backend.readback(vm.vm_id);runtime=collect_native_runtime(self.backend,read)
            guest=self.sources.guest(vm.vm_id)
            require(guest['schema']=='qcl.host-resource-guest-facts.v1'and guest['identity_before']==guest['identity_after']and
                type(guest['observed_at'])is int and guest['observed_at']>=0,
                'stale_evidence','stable original actual calibration guest timestamp required')
            ident=guest['identity_before'];binding=RuntimeBinding(vm.vm_id,read.native_id,read.process_id,ident['boot_id'],ident['image_id'],ident['kernel'],
                runtime.host_kernel_id,runtime.qemu_version_id,runtime.backend_version_id,self.config['readback_version'],read.config_fingerprint)
            profile=self.config['qualified_protocols'][vm.vm_id]
            require(asdict(binding)==ctx['binding']and read.running is True and read.assigned_bytes==read.configured_bytes and
                vm.minimum_bytes<=read.assigned_bytes<=ctx['paid_grant_bytes']==vm.maximum_bytes and
                ident['machine_id']==self.config['enrollment'][vm.vm_id]['machine_id']==ctx['worker_machine_id']and ident['dmi_uuid']==read.native_id.lower()and
                guest['protocol']==profile['guest_protocol']and self.sources.process(int(read.process_id))['start_ticks']==profile['qemu_birth_ticks'],
                'qualification','actual native process/guest/protocol binding differs')
            actual=guest['output_generation'];require(type(actual)is dict and set(actual)=={'worker','runner'},
                'qualification','actual calibration Source generation required')
            _output_worker(actual['worker']);_output_runner(actual['runner'])
            require(actual['worker']['identity']=={key:ident[key]for key in ('machine_id','boot_id','kernel','dmi_uuid')}and
                actual['runner']['source_graph_sha256']==ctx['source_graph_sha256'],'qualification','actual calibration Source/worker differs')
            # Preserve the original packet; no installation/qualification is implied.
            after_read=self.backend.readback(vm.vm_id)
            require(after_read==read and collect_native_runtime(self.backend,after_read)==runtime,
                'identity_mismatch','native allocation/runtime changed during paired guest capture')
            ended_ns=time.monotonic_ns();ended_at=self.clock()
            require(0<=ended_ns-started_ns<=self.policy.timeouts.request_seconds*10**9,
                'stale_evidence','bounded actual caller capture interval required')
            return read,guest,dict(host=host,inventory=inventory,agreement=agreement,guest=guest,native_before=asdict(read),native_after=asdict(after_read),
                capture_interval=dict(caller_started_at=started_at,caller_ended_at=ended_at,
                    caller_started_monotonic_ns=started_ns,caller_ended_monotonic_ns=ended_ns,
                    guest_observed_at=guest['observed_at']))
        except (OSError,KeyError,TypeError,ValueError,StopIteration,Hold)as error:
            raise ResourceError('qualification_observations_required','actual calibration observations unavailable')from error

    def _calibration_pair(self,ctx):
        """Strict physical producer; binding-only settlement never qualifies it."""
        from host_resource_qualification_observations import validate_accounting
        read,guest,original=self._calibration_binding_pair(ctx)
        try:
            require(type(guest.get('calibration_accounting'))is dict,'qualification_observations_required','actual accounting required')
            validate_accounting(guest['calibration_accounting'],ctx)
        except (ResourceError,KeyError,TypeError,ValueError)as cause:
            error=cause if isinstance(cause,ResourceError)else ResourceError('qualification_observations_required','actual accounting unavailable')
            # Raw actual capture is secondary diagnostic evidence, never a
            # successful return from this strict physical API.
            error.calibration_pair=(read,guest,original)
            if error is cause:raise
            raise error from cause
        return read,guest,original

    def calibration_observation(self,parent,permit,sequence,*,jobs=None,case_name=None):
        """Internal Root producer. Default installed ingress remains closed.

        Parent and job owners are the existing protected readers, not submitted
        JSON. Missing child/final/outer-response/closure evidence stays missing.
        This method never executes C, Slurm, a body, or a fence close.
        """
        from host_resource_qualification import check_baseline,decode_case,_exists,readback_record
        from host_resource_qualification_observations import CalibrationObservation,decode_permit,plain
        decode_permit(permit);ctx=permit['context']
        with parent.store.locked():
            plan=parent.repository.plan(parent.operation);state=parent._state();check_baseline(self.policy,parent.store,plan,state)
            pending=parent._catalog(plan,state)
            require(parent.policy==self.policy and plan['host_id']==ctx['host_id']and plan['owner_id']==ctx['owner_id']and
                plan['host_boot_id']==ctx['host_boot_id']and plan['policy_sha256']==ctx['policy_sha256']and
                plan['baseline_state_sha256']==ctx['baseline_state_sha256']and plan['source_graph_sha256']==ctx['source_graph_sha256']and
                plan['bindings'][ctx['binding']['vm_id']]==ctx['binding'],
                'qualification','actual parent/paid baseline/source differs')
            read,guest,original=self._calibration_pair(ctx);effect=None;job_rows=[]
            original.update(parent_plan=plan,pending_mutation_ids=pending)
            if case_name is not None:
                require(case_name in plan['cases'],'shape','original frozen case required')
                marker=decode_case(parent.repository.read(parent.repository.case_path(parent.operation,case_name)),parent.operation,case_name)
                original['case']=marker;mid=marker['mutation_id']
                if mid is not None:
                    owner=parent.proofs.owner_for(mid);owned=owner.effect(state,mid);witness=parent.proofs.read(mid)
                    dispatch=parent.proofs.dispatch(mid);original.update(effect=owner.record,dispatch=dispatch,witness=witness)
                    returned=witness['phase']=='RETURNED_SUCCESS';readback_sha=None
                    if returned:
                        proof=parent._proof(owner,state,owned);path=parent.repository.readback_path(parent.operation,mid)
                        if _exists(path):
                            retained=parent.repository.read(path)
                            require(retained==readback_record(owner,proof,__import__('host_resource_operations').VMReadback(**retained['readback'])),
                                'cleanup_evidence','original confirmed readback differs')
                            readback_sha=parent.repository.digest(path);original['confirmed_readback']=retained
                    effect=dict(status='returned_success'if returned else'unknown',mutation_id=mid,old_bytes=owned.old_bytes,
                        target_bytes=owned.target_bytes,before_revision=owned.before_revision,dispatches=1,witness=witness,
                        readback_sha256=readback_sha,original_evidence_sha256=parent.repository.digest(parent.repository.effect_path(parent.operation,mid)),
                        reply_status=None,failure_code=None)
            if jobs is not None:
                require(jobs.parent is parent,'qualification','child must belong to original parent')
                child=jobs.evidence();original['child_jobs']=child
                selected={calc:row for calc,row in child['permit']['jobs'].items()if row['vm_id']==ctx['binding']['vm_id']}
                require({calc:row['demand_bytes']for calc,row in selected.items()}==permit['authorized_demands']and
                    child['permit']['source_graph_sha256']==ctx['source_graph_sha256'],
                    'qualification','all original authorized child commitments must match')
                allowed=set();attempts={}
                # The existing scheduler RPC is the original completed_final reader.
                self._end_invocation();self._output_epoch=object();self._pending_epoch=self._output_epoch
                try:
                    self._output_config=self._current_output_config()
                    packet=trusted_rpc(self.config['scheduler_route'],'scheduler-facts',{},run=command_engine.command)
                    self._pending_outputs=_scheduler_output_observations(packet)
                    self._pending_jobs={out['native_tuple']['job_id']:_output_native_tuple(packet['jobs'][out['native_tuple']['job_id']])for out in self._pending_outputs.values()}
                    self._join_scheduler_outputs({ctx['binding']['vm_id']:guest},observed_now=self.clock())
                    original['scheduler']=packet
                    for calc,row in selected.items():
                        refs=child['jobs'][calc];bound=refs['bound']
                        if bound is None:continue
                        creator=bound['record']['creator'];job_id=creator['job_id'];allowed.add(job_id)
                        native=guest['jobs'].get(job_id)
                        if native is None:continue  # held/unallocated is never given a fabricated StartTime
                        status=self.sources.calibration_attempt(ctx['binding']['vm_id'],calc,creator);attempts[calc]=status
                        from native_attempt import validate_worker_reply
                        validate_worker_reply(status);fields=status['job']['fields']
                        require(parse_slurm_jobs(status['job']['raw'],cluster=creator['cluster']).get(job_id)==native and
                            fields['SubmitTime']==creator['submit_time']and fields.get('Comment')==creator['dispatch_id']and
                            fields.get('Command')==child['permit']['submit']['spool_root']+'/'+creator['dispatch_id']+'.sh'and
                            fields.get('WorkDir')==row['launch']['remote_workdir']and status['identity']['identity']==guest['identity_before'],
                            'native_generation','original held creator/prolog/current allocation differs')
                        if status['prolog_ref']is None:continue
                        group=guest['groups'][job_id];final=self._joined_outputs.get(native['generation']);closed=refs['closed']
                        phase='live'if native['state']=='RUNNING'and native['terminal']is False else'unknown'
                        if closed is not None and refs['revoked']is not None and final is not None:
                            require(closed['record']['completed_final_sha256']==fingerprint(final)and
                                closed['record']['creator']==creator,'cleanup','original genuine final/creator closure differs')
                            phase='closed'
                        job_rows.append(dict(calcjob_uuid=calc,creator_generation=creator['generation'],native=native,demand_bytes=row['demand_bytes'],
                            task_limit_bytes=group['memory_max_bytes'],state=phase,creator_sha256=bound['sha256'],
                            prolog_sha256=fingerprint(dict(path=status['prolog_ref'],status=status)),cgroup=group,cgroup_sha256=fingerprint(group),
                            completed_final=final if phase=='closed'else None,
                            absence_sha256=fingerprint(dict(group=group,status=status,closed=closed))if phase=='closed'else None,
                            revoked_sha256=refs['revoked']['sha256']if refs['revoked']is not None else None))
                    require(set(guest['jobs'])<=allowed,'ownership','native allocation outside original finite child set')
                    require(jobs.evidence()==child,'qualification','original child set changed while observing')
                    original['attempts']=attempts
                finally:self._end_invocation()
            parent._catalog(plan,state);check_baseline(self.policy,parent.store,plan,parent._state())
            return CalibrationObservation(context=ctx,sequence=sequence,readback=asdict(read),total_bytes=guest['memory']['MemTotal'],
                available_bytes=guest['memory']['MemAvailable'],slurm_memory_bytes=guest.get('slurm_memory_bytes'),
                slurm_registered=guest.get('slurm_registered'),jobs=tuple(job_rows),effect=effect,proposed_target_bytes=None,
                pressure=None,closure=None,evidence_sha256=fingerprint(original),accounting=guest['calibration_accounting'],source_records=original)

    def _current_capacity_pins(self,vm_id):
        current=read_root_json(SERVICE_CONFIG)
        require(current.get('schema')=='qcl.host-resource-service.v1'and current.get('role')=='native_host'and
            current.get('client_uid')==self.config['client_uid']and current['facts'].get('capacity_profiles')==self.config.get('capacity_profiles'),
            'qualification','current protected capacity pins changed')
        return current['facts']['capacity_profiles'][vm_id]

    def _fixed_qualification(self,protected,value,binding,guest,host_boot_id):
        """Current fixed-full proof, distinct from measured dynamic capacity."""
        from native_attempt import _output_worker,_output_runner
        started_at=self.clock();started_ns=time.monotonic_ns()
        vm=next(vm for vm in self.policy.vms if vm.vm_id==binding.vm_id)
        require(value['evidence_ref']==self.policy.active_grant.qualification_ref and
            self.config['readback_version']==binding.readback_version=='qcl.native-memory.fixed.v1',
            'qualification','exact fixed qualification/reference required')
        service=read_root_json(SERVICE_CONFIG)
        expected_raw=self._current_output_config();expected=json.loads(expected_raw).get('output_owner')
        require(type(expected)is dict and all(service['facts'].get(key)==self.config.get(key)for key in
            ('readback_version','qualified_protocols','host_identity')) and
            read_root_json(self.config['qualification'])==protected,
            'qualification','current protected fixed Source/protocol required')
        require(guest['identity_before']==guest['identity_after']and guest.get('slurm_registered')is True and
            type(guest.get('observed_at'))is int and 0<=self.clock()-guest['observed_at']<=self.policy.timeouts.request_seconds,
            'qualification','fresh stable registered fixed guest required')
        identity=guest['identity_before'];enrolled=self.config['enrollment'][vm.vm_id]
        require(identity['machine_id']==enrolled['machine_id']and identity['dmi_uuid']==binding.native_id==enrolled['native_id']and
            enrolled['maximum_bytes']==vm.maximum_bytes and identity['boot_id']==binding.guest_boot_id and
            identity['kernel']==binding.guest_kernel_id and identity['image_id']==binding.image_id,
            'qualification','actual fixed enrollment/image/kernel/boot differs')
        actual=guest['output_generation'];require(type(actual)is dict and set(actual)=={'worker','runner'},
            'qualification','actual fixed worker/Runner Source required')
        _output_worker(actual['worker']);_output_runner(actual['runner'])
        nodes=[node for node,vm_id in self.config['nodes'].items()if vm_id==vm.vm_id]
        require(len(nodes)==1 and actual['worker']==expected['worker_generations'].get(nodes[0])and
            actual['worker']['identity']=={key:identity[key]for key in ('machine_id','boot_id','kernel','dmi_uuid')}and
            actual['runner']==expected['runner'],'qualification','actual fixed Source/worker generation differs')
        profile=self.config['qualified_protocols'][vm.vm_id]
        require(guest['protocol']==profile['guest_protocol'],'qualification','actual fixed guest protocol differs')
        read=self.backend.readback(vm.vm_id);runtime=collect_native_runtime(self.backend,read)
        native_reader=getattr(self.sources,'fixed_native',None)
        require(callable(native_reader),'qualification','actual fixed native configuration reader required')
        native=native_reader(self.backend,vm.vm_id)
        require(type(native)is dict and set(native)=={'backend','configuration'},'qualification','original fixed native config required')
        if native['backend']=='proxmox':
            from host_resource_backends import pve_config_fingerprint
            cfg=native['configuration'];require(type(cfg)is dict,'qualification','actual PVE config required')
            integer(cfg.get('balloon'),'fixed PVE balloon')
            require(cfg['balloon']==0 and pve_memory_mib(cfg.get('memory'))*1024**2==vm.maximum_bytes and
                pve_config_fingerprint(cfg)==binding.config_fingerprint and cfg.get('digest')==read.revision and
                re.findall(r'(?:^|,)uuid=([^,]+)(?:,|$)',cfg.get('smbios1',''))==[binding.native_id],
                'qualification','PVE full reservation requires actual disabled balloon/config')
        else:
            from host_resource_backends import LibvirtMemoryBackend,libvirt_config_fingerprint
            raw=native['configuration'];require(native['backend']=='libvirt'and type(raw)is str and
                '<!DOCTYPE'not in raw and '<!ENTITY'not in raw,'qualification','actual fixed libvirt XML required')
            xml=ET.fromstring(raw)
            require(xml.tag=='domain'and xml.findtext('uuid')==binding.native_id and
                LibvirtMemoryBackend._memory(xml.find('currentMemory'))==LibvirtMemoryBackend._memory(xml.find('memory'))==vm.maximum_bytes and
                libvirt_config_fingerprint(xml)==binding.config_fingerprint and hashlib.sha256(raw.encode()).hexdigest()==read.revision,
                'qualification','libvirt current/configured maximum differs')
        require(read.native_id==binding.native_id and read.process_id==binding.process_id and read.config_fingerprint==binding.config_fingerprint and
            read.running is True and read.assigned_bytes==read.configured_bytes==vm.maximum_bytes and
            runtime.host_boot_id==host_boot_id and runtime.host_kernel_id==binding.host_kernel_id and
            runtime.qemu_version_id==binding.qemu_version_id and runtime.backend_version_id==binding.backend_version_id,
            'qualification','current fixed full allocation/runtime differs')
        integer(profile['qemu_birth_ticks'],'fixed QEMU birth',1)
        birth=self.sources.process(int(read.process_id))['start_ticks']
        require(type(birth)is int and birth==profile['qemu_birth_ticks'],'qualification','actual fixed QEMU birth differs')
        total=guest['memory']['MemTotal'];available=guest['memory']['MemAvailable'];scheduler=guest['slurm_memory_bytes'];reserve=enrolled['os_reserve_bytes']
        for amount in (total,available,scheduler,reserve):integer(amount,'actual fixed guest capacity')
        require(0<reserve<=vm.minimum_bytes<=total<=vm.maximum_bytes and available<=total and
            0<scheduler<=total-reserve,'qualification','fixed guest/Slurm/reserve capacity contradicts full reservation')
        require(native_reader(self.backend,vm.vm_id)==native and self.backend.readback(vm.vm_id)==read and collect_native_runtime(self.backend,read)==runtime and
            self.sources.process(int(read.process_id))['start_ticks']==birth and
            self._current_output_config()==expected_raw and read_root_json(SERVICE_CONFIG)==service and
            read_root_json(self.config['qualification'])==protected,
            'qualification','fixed original Source/native proof changed during capture')
        self._capture_timestamp(started_at,started_ns,{binding.vm_id:guest})
        return BackendQualification(**value)

    def _qualification(self,protected,binding,guest,*,host_boot_id=None):
        # The report hash/source expectation comes from protected configuration,
        # never from the row that is being authorized. No legacy positive upgrade.
        from host_resource_qualification_observations import MeasuredBackendQualification,qualification_candidate
        from host_resource_capacity import decode_capacity_qualification_v2,CapacityValidationError
        from native_attempt import _output_worker,_output_runner,Hold
        flags={'qualified_dynamic','active_floor_protection','readback_verified','slurm_registration_verified'}
        try:
            require(type(protected)is dict and set(protected)=={'schema','qualifications'} and
                protected['schema']in {'qcl.host-resource-qualification.v1','qcl.host-resource-qualification.v2'} and
                type(protected['qualifications'])is list and len(protected['qualifications'])<=64,
                'qualification','closed bounded protected qualification required')
            base=set(BackendQualification.__dataclass_fields__)
            allowed=base if protected['schema'].endswith('.v1')else base|{'capacity'}
            require(all(type(q)is dict and set(q)==allowed for q in protected['qualifications']),
                'qualification','exact private qualification fields required')
            matches=[q for q in protected['qualifications']if q['binding']==asdict(binding)]
            require(len(matches)==1,'qualification','exact actual runtime qualification required');row=matches[0]
            require(row['host_id']==self.policy.host_id and row['owner_id']==self.policy.owner_id and
                row['policy_sha256']==policy_digest(self.policy) and type(row['evidence_ref'])is str and row['evidence_ref'] and
                all(type(row[key])is bool for key in flags),'qualification','actual owner/policy/flags differ')
            value={key:row[key]for key in base};value['binding']=binding
            if not any(row[key]for key in flags):
                require('capacity'not in row or row['capacity']is None,'qualification','negative qualification cannot carry positive capacity')
                return BackendQualification(**value)
            if self.policy.active_grant.mechanism=='conservative_reservation':
                require(protected['schema']=='qcl.host-resource-qualification.v1'and row['qualified_dynamic']is False and
                    all(row[key]is True for key in flags-{'qualified_dynamic'}),
                    'qualification','fixed-only v1 qualification required; no legacy dynamic authority')
                return self._fixed_qualification(protected,value,binding,guest,host_boot_id)
            require(protected['schema'].endswith('.v2')and all(row[key]for key in flags),
                'qualification','positive qualification requires full measured v2 evidence')
            pins=self.config.get('capacity_profiles',{}).get(binding.vm_id)
            require(type(pins)is dict and set(pins)=={'source_graph_sha256','report_sha256','report_path'},
                'qualification','independent protected capacity pins required')
            require(self._current_capacity_pins(binding.vm_id)==pins,'qualification','actual independent capacity pins differ')
            for key in ('source_graph_sha256','report_sha256'):_output_sha256(pins[key])
            report=read_root_qualification_report(pins['report_path'])
            require(fingerprint(report)==pins['report_sha256']and qualification_candidate(report)==row,
                'qualification','accepted actual report or deterministic predicates differ')
            ctx=report['permit']['context'];vm=next(vm for vm in self.policy.vms if vm.vm_id==binding.vm_id)
            require(ctx['host_id']==self.policy.host_id and ctx['owner_id']==self.policy.owner_id and
                ctx['host_boot_id']==host_boot_id and ctx['policy_sha256']==policy_digest(self.policy)and
                ctx['binding']==asdict(binding)and ctx['source_graph_sha256']==pins['source_graph_sha256']and
                ctx['native_minimum_bytes']==vm.minimum_bytes and ctx['native_maximum_bytes']==vm.maximum_bytes and
                ctx['quantum_bytes']==self.backend.quantum_bytes,'qualification','actual report context differs')
            require(guest['identity_before']==guest['identity_after']and guest.get('slurm_registered')is True and
                type(guest.get('observed_at'))is int and 0<=self.clock()-guest['observed_at']<=self.policy.timeouts.request_seconds,
                'qualification','actual fresh stable guest registration required before positive qualification')
            identity=guest['identity_before'];worker_identity={key:identity[key]for key in ('machine_id','boot_id','kernel','dmi_uuid')}
            actual=guest['output_generation'];require(type(actual)is dict and set(actual)=={'worker','runner'},
                'qualification','actual worker/source generation required')
            _output_worker(actual['worker']);_output_runner(actual['runner'])
            require(actual['worker']['identity']==worker_identity and identity['machine_id']==ctx['worker_machine_id']and
                identity['boot_id']==binding.guest_boot_id and identity['kernel']==binding.guest_kernel_id and
                identity['dmi_uuid']==binding.native_id and identity['image_id']==binding.image_id and
                actual['runner']['source_graph_sha256']==pins['source_graph_sha256'],
                'qualification','fresh actual Source/worker/runtime binding differs')
            capacity=decode_capacity_qualification_v2(row['capacity'],expected_host_id=self.policy.host_id,
                expected_owner_id=self.policy.owner_id,expected_policy_sha256=policy_digest(self.policy),
                expected_binding=asdict(binding),expected_source_graph_sha256=pins['source_graph_sha256'],
                expected_report_sha256=pins['report_sha256'],expected_native_maximum_bytes=vm.maximum_bytes)
            require(capacity is not None and vm.minimum_bytes>=capacity.os_reserve_bytes+capacity.native_gap_bound_bytes and
                self.config['enrollment'][vm.vm_id]['os_reserve_bytes']==capacity.os_reserve_bytes,
                'qualification','measured R/K incompatible with actual enrollment/policy')
            # This runs on every positive qualification path, including startup/
            # binding facts, before the controller could treat it as ready.
            read=self.backend.readback(vm.vm_id);memory=guest['memory'];total=memory['MemTotal'];available=memory['MemAvailable'];scheduler=guest['slurm_memory_bytes']
            for amount in (total,available,scheduler):integer(amount,'actual guest capacity')
            require(read.native_id==binding.native_id and read.process_id==binding.process_id and read.config_fingerprint==binding.config_fingerprint and
                read.running is True and read.assigned_bytes==read.configured_bytes and
                read.assigned_bytes in {sample['assigned_bytes']for sample in report['permit']['capacity_measurement']['mapping_samples']}and
                0<total<=capacity.maximum_guest_total_bytes and available<=total and
                max(0,read.assigned_bytes-total)<=capacity.native_gap_bound_bytes and
                0<scheduler<=capacity.maximum_guest_total_bytes-capacity.os_reserve_bytes,
                'qualification','current actual native/physical/scheduler capacity contradicts measured scope')
            require(self._current_capacity_pins(binding.vm_id)==pins and read_root_qualification_report(pins['report_path'])==report,
                'qualification','accepted original profile changed during actual observation')
            return MeasuredBackendQualification(**value,capacity=capacity,supported_targets=tuple(sorted({sample['assigned_bytes']for sample in report['permit']['capacity_measurement']['mapping_samples']})))
        except (KeyError,TypeError,ValueError,StopIteration,Hold,CapacityValidationError,ET.ParseError)as error:
            raise ResourceError('qualification','missing or mismatched measured qualification')from error

    def _capture_timestamp(self,started_at,started_ns,guests):
        # Keep the oldest contributing observation; later work cannot renew it.
        now=self.clock();timeout=self.policy.timeouts.request_seconds
        require(0<=now-started_at<=timeout and 0<=time.monotonic_ns()-started_ns<=timeout*10**9,
            'stale_evidence','bounded host/guest capture interval required')
        stamps=[int(started_at)]
        for guest in guests.values():
            observed=guest.get('observed_at')
            require(type(observed)is int and 0<=now-observed<=timeout,
                'stale_evidence','every contributing guest observation must remain fresh')
            stamps.append(observed)
        return min(stamps)

    def _live_guest_workloads(self,vm_id,guest,owner_state):
        known={}
        if owner_state:
            for row in owner_state['receipts']:
                if row['request']['vm_id']==vm_id and not row['finished'] and row['phase']=='RUN':
                    identity=row['request']['workload_id'];native=self.native.get(identity)
                    if native is None:
                        native=next((j for j in guest['jobs'].values()if 'slurm:'+j['generation']==identity),None)
                    require(native is not None,'native_generation','live owner native generation evicted')
                    known[identity]=dict(native_id=native['native_id'],generation=native['generation'],phase='RUN')
        return classify_guest_workloads(guest['jobs'],guest['groups'],known,
            gate_executables=tuple(self.config['qualified_protocols'][vm_id]['gate_executables']))

    def binding_facts(self,native_vm_id,*,owner_state):
        started_at=self.clock();started_ns=time.monotonic_ns()
        host,rows,_=self._host_inventory();bindings=[];qualifications=[];guests={};live={vm.vm_id:()for vm in self.policy.vms}
        protected=read_root_json(self.config['qualification'])
        for vm in self.policy.vms:
            enrolled=self.config['enrollment'][vm.vm_id]
            row=next(r for r in rows if r['native_id']==enrolled['native_id'])
            if not row['running']:continue
            read=self.backend.readback(vm.vm_id);runtime=collect_native_runtime(self.backend,read)
            fixed_positive=(self.policy.active_grant.mechanism=='conservative_reservation'and any(
                type(q)is dict and type(q.get('binding'))is dict and q['binding'].get('vm_id')==vm.vm_id and q.get('qualified_dynamic')is False and
                all(q.get(key)is True for key in ('active_floor_protection','readback_verified','slurm_registration_verified'))
                for q in protected.get('qualifications',[])))
            full_guest=fixed_positive or protected.get('schema')=='qcl.host-resource-qualification.v2'
            guest=(self.sources.guest(vm.vm_id)if full_guest else self.sources.guest_identity(vm.vm_id));ident=guest.get('identity_before',guest.get('identity'))
            require(ident['machine_id']==enrolled['machine_id'] and ident['dmi_uuid']==read.native_id.lower(),
                'identity_mismatch','startup guest identity differs')
            binding=RuntimeBinding(vm.vm_id,read.native_id,read.process_id,ident['boot_id'],ident['image_id'],ident['kernel'],
                runtime.host_kernel_id,runtime.qemu_version_id,runtime.backend_version_id,self.config['readback_version'],read.config_fingerprint)
            qualified=self._qualification(protected,binding,guest,host_boot_id=host['boot_id'])
            if full_guest:
                guests[vm.vm_id]=guest
                live[vm.vm_id]=self._live_guest_workloads(vm.vm_id,guest,owner_state)
            bindings.append(binding);qualifications.append(qualified)
        require(any(b.native_id==native_vm_id for b in bindings),'identity_mismatch','requested native VM is not observed running')
        observed_at=self._capture_timestamp(started_at,started_ns,guests)
        return HostEvidence(self.policy.host_id,self.policy.owner_id,host['boot_id'],policy_digest(self.policy),observed_at,
            host['MemTotal'],self.policy.reserves.foreign_max_bytes,self.policy.capacity_evidence_ref,self.policy.owned_pool.agreement_ref,
            True,True,host['MemAvailable']>=self.policy.reserves.safety_bytes,fingerprint([host,rows,guests]),tuple(bindings),tuple(qualifications),live)
    def request_facts(self,demand,*,owner_state):
        self.last=None
        try:return self._capture(demand,owner_state=owner_state)
        except BaseException:
            self._end_invocation();raise
    def _end_invocation(self):
        self._output_epoch=self._joined_epoch=self._pending_epoch=None
        self._pending_outputs={};self._joined_outputs={};self._pending_jobs={};self._output_config=None;self.last=None

    def _current_output_config(self):
        from native_attempt import _output_identity,_output_runner,_completed_final_binding,_output_sha,Hold
        current=read_root_json(SERVICE_CONFIG)
        require(current.get('schema')=='qcl.host-resource-service.v1' and current.get('role')=='native_host' and
            current.get('client_uid')==self.config['client_uid'] and type(current.get('facts')) is dict,
            'qualification','current protected native-host facts configuration required')
        facts=current['facts'];keys=('scheduler_route','guests','nodes','enrollment','output_owner','capacity_profiles')
        require(all(facts.get(key)==self.config.get(key) for key in keys),'qualification','facts binding/routes changed')
        expected=facts.get('output_owner')
        if 'output_owner' in facts:
            try:
                require(type(expected) is dict and set(expected)=={'owner','controller_identity','runner','worker_generations'},
                    'qualification','closed output owner expectation required')
                # Validate the same whole R (including its optional finite fixture
                # scope) as controller and worker; never project that scope away.
                _output_identity(expected['controller_identity']);_output_runner(expected['runner'])
                owner=expected['owner'];require(type(owner) is dict and set(owner)=={'policy_sha256','qualification_sha256',
                    'source_graph_sha256','unit_generation_sha256','storage_identity','retention_ref'},'qualification','exact owner6 required')
                for key in ('policy_sha256','qualification_sha256','source_graph_sha256','unit_generation_sha256'):_output_sha(owner[key])
                for key in ('storage_identity','retention_ref'):
                    require(type(owner[key]) is str and 0<len(owner[key].encode())<=256 and '\x00' not in owner[key],
                        'qualification','bounded owner locator required')
                require(owner['source_graph_sha256']==expected['runner']['source_graph_sha256'],'qualification','owner/Runner source differs')
                _completed_final_binding(dict(runner=expected['runner'],unit_generation_sha256=owner['unit_generation_sha256'],
                    worker_generations=expected['worker_generations']),facts['nodes'])
            except Hold as error:raise ResourceError('qualification','invalid protected output owner') from error
        raw=json.dumps({key:facts.get(key) for key in keys},sort_keys=True,separators=(',',':'),allow_nan=False).encode()
        require(len(raw)<=MAX_OUTPUT_BYTES,'output_bound','bounded protected output expectation required')
        return raw

    def _join_scheduler_outputs(self,guests,*,observed_now):
        from native_attempt import _output_worker,_output_runner,Hold
        try:
            if self._output_epoch is None:
                require(not self._pending_outputs,'cleanup','no output outside invocation');return
            require(self._pending_epoch is self._output_epoch,'cleanup','stale output invocation')
            require(self._current_output_config()==self._output_config,'qualification','output owner drift')
            expected=json.loads(self._output_config)['output_owner']
            if expected is None:
                self._joined_outputs={};self._joined_epoch=self._output_epoch;return
            timeout=self.policy.timeouts.request_seconds
            for generation,output in self._pending_outputs.items():
                native=output['native_tuple'];node=native['node'];vm=self.config['nodes'].get(node)
                require(vm in guests,'cleanup','output guest not enrolled');guest=guests[vm]
                require(output['scope']=='completed_final' and output['durable'] is True and output['owner']==expected['owner'] and
                    output['controller_identity']==expected['controller_identity'],'cleanup','qualified output scope/owner differs')
                require(guest['identity_before']==guest['identity_after'],'identity_mismatch','guest identity drift')
                identity={key:guest['identity_before'][key] for key in ('machine_id','boot_id','kernel','dmi_uuid')}
                require(identity==output['worker_identity'],'identity_mismatch','output/guest identity differs')
                require(type(guest.get('output_generation')) is dict and set(guest['output_generation'])=={'worker','runner'},
                    'cleanup','fresh guest output owner tuple missing')
                actual=guest['output_generation'];_output_worker(actual['worker']);_output_runner(actual['runner'])
                require(actual['worker']==expected['worker_generations'].get(node) and actual['worker']['identity']==identity and
                    actual['runner']==expected['runner'],'cleanup','fresh worker/source generation differs')
                require(self._pending_jobs.get(native['job_id'])==native and native==_output_native_tuple(guest['jobs'][native['job_id']]) and
                    generation==guest['jobs'][native['job_id']]['generation'],'native_generation','scheduler/guest/original tuple differs')
                require(type(guest['observed_at']) is int and 0<=observed_now-output['observed_at']<=timeout and
                    0<=observed_now-guest['observed_at']<=timeout and output['observed_at']<=guest['observed_at']<=observed_now,
                    'stale_evidence','fresh ordered output and guest observations required')
            self._joined_outputs=dict(self._pending_outputs);self._joined_epoch=self._output_epoch
        except Hold as error:
            self._end_invocation();raise ResourceError('cleanup','malformed output generation') from error
        except BaseException:
            self._end_invocation();raise
    def recovery_snapshot(self,retiring_vm_id,*,owner_state):
        self._end_invocation()
        require(retiring_vm_id in owner_state['bindings'],'ownership','retiring resident required')
        evidence=self._capture(None,owner_state=owner_state,retiring_vm_id=retiring_vm_id)
        return evidence,{vm.vm_id:self.backend.readback(vm.vm_id) for vm in self.policy.vms if vm.vm_id!=retiring_vm_id}
    def _capture(self,demand,*,owner_state,retiring_vm_id=None):
        started_at=self.clock();started_ns=time.monotonic_ns()
        host,rows,agreement=self._host_inventory(retiring_vm_id=retiring_vm_id);bindings=[];qualifications=[];live={};guests={}
        protected=read_root_json(self.config['qualification'])
        for vm in self.policy.vms:
            if vm.vm_id==retiring_vm_id:continue
            read=self.backend.readback(vm.vm_id);runtime=collect_native_runtime(self.backend,read)
            if self.policy.active_grant.mechanism=='conservative_reservation':
                require(read.assigned_bytes==read.configured_bytes==vm.maximum_bytes,'readback','fixed full-maximum allocation required')
            guest=self.sources.guest(vm.vm_id);guests[vm.vm_id]=guest
            require(guest['schema']=='qcl.host-resource-guest-facts.v1' and guest['identity_before']==guest['identity_after'],
                    'identity_mismatch','fresh stable root guest identity required')
            require(type(guest['observed_at']) is int and 0<=self.clock()-guest['observed_at']<=self.policy.timeouts.request_seconds,
                'stale_evidence','fresh authenticated guest observation required')
            ident=guest['identity_before'];enroll=self.config['enrollment'][vm.vm_id]
            require(ident['machine_id']==enroll['machine_id'] and ident['dmi_uuid']==read.native_id.lower(),
                    'identity_mismatch','guest not the enrolled VM')
            binding=RuntimeBinding(vm.vm_id,read.native_id,read.process_id,ident['boot_id'],ident['image_id'],ident['kernel'],
                runtime.host_kernel_id,runtime.qemu_version_id,runtime.backend_version_id,self.config['readback_version'],read.config_fingerprint)
            qualified=self._qualification(protected,binding,guest,host_boot_id=host['boot_id'])
            qualified=replace(qualified,slurm_registration_verified=(qualified.slurm_registration_verified is True
                and guest.get('slurm_registered') is True))
            profile=self.config['qualified_protocols'][vm.vm_id]
            require(guest['protocol']==profile['guest_protocol'] and
                self.sources.process(int(read.process_id))['start_ticks']==profile['qemu_birth_ticks'],
                'qualification','native process generation/protocol changed')
            live[vm.vm_id]=self._live_guest_workloads(vm.vm_id,guest,owner_state)
            bindings.append(binding);qualifications.append(qualified)
        observed_at=self._capture_timestamp(started_at,started_ns,guests)
        evidence=HostEvidence(self.policy.host_id,self.policy.owner_id,host['boot_id'],policy_digest(self.policy),observed_at,
            host['MemTotal'],self.policy.reserves.foreign_max_bytes,self.policy.capacity_evidence_ref,self.policy.owned_pool.agreement_ref,
            True,True,host['MemAvailable']>=self.policy.reserves.safety_bytes,fingerprint([host,rows,guests]),tuple(bindings),tuple(qualifications),live)
        self._join_scheduler_outputs(guests,observed_now=self.clock())
        self.last=(evidence,guests)
        proofs=getattr(self,'native_proofs',None)
        if proofs is not None:proofs.validate_state(owner_state,evidence=evidence)
        if retiring_vm_id is None:self._persist(evidence,guests)
        self._capture_timestamp(started_at,started_ns,guests)
        return evidence
    def _persist(self,evidence,guests):
        # One bounded probe cache for status/RootNativeBoundary, not another grant ledger.
        from host_resource_operations import FileReceiptStore
        directory=trusted_root_path(self.config['state_directory'],directory=True)
        store=FileReceiptStore.open_existing(directory)
        host=asdict(replace(evidence,qualifications=()));host.pop('qualifications');host['schema']='qcl.host-resource-evidence.v1'
        packet=dict(schema='qcl.host-resource-probe.v2',host=host,guests={},completions={},cleanups={})
        data=json.dumps(packet,sort_keys=True).encode();require(len(data)<=MAX_OUTPUT_BYTES,'output_bound','probe snapshot bound')
        target=trusted_root_path(self.config['evidence']) if Path(self.config['evidence']).exists() else Path(self.config['evidence'])
        require(target.parent==directory,'trust','probe must share protected state directory')
        store._atomic(target,data)
    def _row_guest(self,request_id,owner_state):
        require(self.last is not None,'incomplete_probe','capture facts under owner lock first')
        row=next((r for r in owner_state['receipts'] if r['request']['request_id']==request_id),None)
        require(row is not None,'request_unknown','active owner request required')
        vm=row['request']['vm_id'];g=self.last[1][vm]
        native=next((j for j in g['jobs'].values() if 'slurm:'+j['generation']==row['request']['workload_id']),None)
        require(native is not None,'native_generation','exact native generation disappeared')
        return row,g,native
    def guest_admission(self,request_id,*,owner_state):
        row,g,native=self._row_guest(request_id,owner_state);req=row['request'];group=g['groups'][native['native_id']]
        require(not native['terminal'] and native['state']=='RUNNING' and g.get('slurm_registered') is True,'native_state','allocated running workload required')
        require(req['workload_bytes']>=native['limit_bytes'] and group['memory_max_bytes']==native['limit_bytes'],
                'guest_capacity','native task cgroup/allocated memory mismatch')
        from host_resource_qualification_observations import MeasuredBackendQualification,MeasuredGuestEvidence
        measured=[q for q in self.last[0].qualifications if type(q)is MeasuredBackendQualification and q.binding.vm_id==req['vm_id']]
        if measured:
            require(len(measured)==1,'qualification','one exact measured profile required');qualified=measured[0];capacity=qualified.capacity
            from host_resource_capacity import validate_guest_admission,CapacityValidationError
            vm=next(vm for vm in self.policy.vms if vm.vm_id==req['vm_id'])
            active=[r for r in owner_state['receipts']if r['request']['vm_id']==vm.vm_id and not r['finished']]
            require(len(active)<=64 and len({r['request']['workload_id']for r in active})==len(active),
                'capacity_evidence','complete unique authorized commitments required')
            limits=[]
            for receipt in active:
                original=next((j for j in g['jobs'].values()if 'slurm:'+j['generation']==receipt['request']['workload_id']),None)
                require(original is not None and original['state']=='RUNNING'and original['terminal']is False,
                    'capacity_evidence','authorized pending/unknown body lacks actual allocation')
                actual=g['groups'].get(original['native_id'])
                require(actual is not None and actual['memory_max_bytes']==original['limit_bytes'],
                    'capacity_evidence','every authorized original actual cgroup required')
                limits.append(actual['memory_max_bytes'])
            grants=[grant for grant in owner_state['grants']if grant['vm_id']==vm.vm_id]
            require(len(grants)==1,'capacity_evidence','exact actual paid grant required');read=self.backend.readback(vm.vm_id)
            require(read.native_id==qualified.binding.native_id and read.process_id==qualified.binding.process_id and
                read.config_fingerprint==qualified.binding.config_fingerprint and read.running is True and read.assigned_bytes in qualified.supported_targets,
                'qualification','actual native generation changed')
            try:
                validate_guest_admission(qualification=capacity,native_minimum_bytes=vm.minimum_bytes,
                    paid_grant_bytes=grants[0]['guest_bytes'],assigned_bytes=read.assigned_bytes,configured_bytes=read.configured_bytes,
                    total_bytes=g['memory']['MemTotal'],available_bytes=g['memory']['MemAvailable'],
                    demands=[r['request']['workload_bytes']for r in active],task_limits=limits,candidate_index=active.index(row),
                    slurm_memory_bytes=g['slurm_memory_bytes'],quantum_bytes=self.backend.quantum_bytes,limits_enforced=all(type(limit)is int and limit>0 for limit in limits),
                    expected_host_id=self.policy.host_id,expected_owner_id=self.policy.owner_id,expected_policy_sha256=policy_digest(self.policy),
                    expected_binding=asdict(qualified.binding),expected_source_graph_sha256=capacity.source_graph_sha256,
                    expected_report_sha256=capacity.report_sha256,expected_native_maximum_bytes=vm.maximum_bytes)
            except CapacityValidationError as error:raise ResourceError('guest_capacity',str(error))from error
            return MeasuredGuestEvidence(req['vm_id'],g['identity_before']['boot_id'],req['workload_id'],g['observed_at'],
                g['memory']['MemTotal'],g['memory']['MemAvailable'],capacity.os_reserve_bytes,group['memory_max_bytes'],
                g['slurm_memory_bytes'],True,tuple(self.last[0].live_workloads[req['vm_id']]),capacity,
                tuple((r['request']['workload_id'],r['request']['workload_bytes'],limit)for r,limit in zip(active,limits)))
        return GuestEvidence(req['vm_id'],g['identity_before']['boot_id'],req['workload_id'],g['observed_at'],
            g['memory']['MemTotal'],g['memory']['MemAvailable'],self.config['enrollment'][req['vm_id']]['os_reserve_bytes'],
            group['memory_max_bytes'],g['slurm_memory_bytes'],True,tuple(self.last[0].live_workloads[req['vm_id']]))
    def completion(self,request_id,*,owner_state):
        try:
            if self.last is not None:self._join_scheduler_outputs(self.last[1],observed_now=self.clock())
            row,g,native=self._row_guest(request_id,owner_state);req=row['request'];group=g['groups'][native['native_id']]
            require(native['terminal'] and not group['populated'] and not group['processes'],
                    'cleanup','actual terminal and whole native subtree absence required; gate/COMPLETING insufficient')
            output=getattr(self,'_joined_outputs',{}).get(native['generation'])
            require(getattr(self,'_output_epoch',None) is not None and
                    getattr(self,'_joined_epoch',None) is self._output_epoch and output is not None and
                    output['generation']==native['generation'] and output['scope']=='completed_final' and output['durable'] is True,
                    'cleanup','root-observed closed/fsynced output provenance missing')
            return CompletionEvidence(req['vm_id'],g['identity_before']['boot_id'],req['workload_id'],g['observed_at'],0,True,True,
                g['memory']['MemTotal'],g['memory']['MemAvailable'],tuple(self.last[0].live_workloads[req['vm_id']]))
        except BaseException:
            self._end_invocation();raise
    def cleanup(self,request_id,*,owner_state):
        proofs=getattr(self,'native_proofs',None)
        if proofs is None:return None
        require(self.last is not None,'incomplete_probe','fresh native facts required before cleanup')
        return proofs.cleanup(request_id,owner_state=owner_state,evidence=self.last[0])


def scan_job_group(path,scope,processes):
    require(scope.startswith('/') and '..' not in Path(scope).parts,'trust','canonical native job cgroup required')
    members=[{key:p[key] for key in ('pid','start_ticks','executable','uids')} for p in processes
        if p['cgroup']==scope or p['cgroup'].startswith(scope+'/')]
    if not path.exists():
        require(not members,'incomplete_workloads','absent group still has observed descendants')
        return dict(populated=False,processes=[],memory_max_bytes=None)
    raw=(path/'cgroup.events').read_text();values=dict(line.split() for line in raw.splitlines())
    require(values.get('populated') in {'0','1'},'incomplete_workloads','actual subtree population required')
    populated=values['populated']=='1';require(populated==bool(members),'incomplete_workloads','cgroup/process scan raced or incomplete')
    cap=(path/'memory.max').read_text().strip()
    require(cap.isdigit() and int(cap)>0,'unsupported','finite native task memory.max required')
    return dict(populated=populated,processes=members,memory_max_bytes=int(cap))


def capture_scheduler(config,sources):
    trusted_root_path(config['slurm_conf']);tool=trusted_root_path(config['scontrol'],executable=True)
    version=sources.run([str(tool),'--version']).strip()
    require(version==config['slurm_version'],'qualification','installed Slurm read protocol changed')
    report=sources.run([str(tool),'show','config'])
    clusters=re.findall(r'(?m)^\s*ClusterName\s*=\s*(\S+)\s*$',report)
    controllers=sorted(re.findall(r'(?m)^\s*SlurmctldHost(?:\[[0-9]+\])?\s*=\s*(\S+)\s*$',report))
    require(clusters==[config['cluster']] and controllers and controllers==sorted(config['slurmctld_hosts']),
        'identity_mismatch','actual native cluster/controller identity differs')
    raw=sources.run([str(tool),'--oneliner','show','jobs'])
    # Qualified C-locale response for the complete empty scheduler, not a job row.
    if version=='slurm 25.11.8' and raw=='No jobs in the system\n':return {}
    # Unallocated jobs do not own a guest. Parse each allocated supported node;
    # relevant incomplete/multinode records refuse instead of disappearing.
    allocated=[]
    for line in raw.splitlines():
        node=re.search(r'(?:^|\s)NodeList=([^\s]+)',line)
        if node and node[1] in {'(null)','None','None assigned'}:continue
        allocated.append(line)
    return parse_slurm_jobs('\n'.join(allocated),cluster=config['cluster'])


def capture_guest_identity(config,sources):
    before=sources.host();image=os.path.realpath('/run/current-system')
    require(image.startswith('/nix/store/'),'qualification','immutable guest image identity required')
    trusted_root_path(image,directory=True)
    after=sources.host()
    require(all(before[k]==after[k] for k in ('boot_id','machine_id','kernel','dmi_uuid','MemTotal')),
        'identity_mismatch','guest identity changed during capture')
    return dict(schema='qcl.host-resource-guest-identity.v1',identity=dict(machine_id=before['machine_id'],dmi_uuid=before['dmi_uuid'],
        boot_id=before['boot_id'],kernel=before['kernel'],image_id=image))


def _accounting_read(sources,path,limit=65536):
    raw=sources.read(str(path),limit)
    require(type(raw)is str and len(raw.encode())<=limit,'output_bound','bounded original Linux accounting read required')
    return raw


def _linux_counters(raw,*,kilobytes=False):
    result={}
    for line in raw.splitlines():
        pattern=r'([A-Za-z_][A-Za-z0-9_()]*):[ \t]+([0-9]+) kB'if kilobytes else r'([A-Za-z_][A-Za-z0-9_]*)[ \t]+([0-9]+)'
        match=re.fullmatch(pattern,line)
        if kilobytes and match is None:
            # HugePages counters are page counts, not bytes, and are not mixed in.
            require(re.fullmatch(r'HugePages_[A-Za-z_]+:[ \t]+[0-9]+',line)is not None,
                'unsupported','qualified literal meminfo protocol required');continue
        require(match is not None and match[1]not in result,'unsupported','unique literal Linux counters required')
        value=int(match[2])*(1024 if kilobytes else 1);integer(value,'Linux counter')
        result[match[1]]=value
    require(result,'incomplete_probe','explicit nonempty Linux counters required');return result


def _memory_pressure(raw):
    result={}
    for line in raw.splitlines():
        match=re.fullmatch(r'(some|full) avg10=([0-9]+\.[0-9]{2}) avg60=([0-9]+\.[0-9]{2}) avg300=([0-9]+\.[0-9]{2}) total=([0-9]+)',line)
        require(match is not None and match[1]not in result,'unsupported','qualified PSI memory protocol required')
        result[match[1]]=dict(avg10=match[2],avg60=match[3],avg300=match[4],total=int(match[5]))
        integer(result[match[1]]['total'],'PSI total')
    require(set(result)=={'some','full'},'incomplete_probe','some/full PSI observations required');return result


def capture_guest_accounting(config,sources,*,identity,jobs,groups,processes,clock=time.time):
    """Read real finite Linux accounting through the existing bounded Source.

    The conservative OS upper observation includes all non-free guest memory,
    including jobs/cache/balloon pages. It is deliberately not T-A, an exact OS
    decomposition, an inferred balloon size, or a bound on future OS peaks.
    Detailed kernel, process PSS, cgroup and pressure data remain in the packet.
    """
    try:
        require(type(jobs)is dict and type(groups)is dict and set(jobs)==set(groups)and len(jobs)<=64 and
            type(processes)is list and len(processes)<=1024,'output_bound','finite complete accounting inventory required')
        root=config['slurm_cgroup_root'];require(type(root)is str and root.startswith('/')and root!='/'and
            str(Path(root))==root and '..'not in Path(root).parts,'trust','canonical native job cgroup root required')
        memory=_linux_counters(_accounting_read(sources,'/proc/meminfo'),kilobytes=True)
        needed={'MemTotal','MemFree','MemAvailable','Buffers','Cached','SReclaimable','SUnreclaim','KernelStack','PageTables','Percpu'}
        require(needed<=memory.keys()and memory['MemFree']<=memory['MemTotal']and memory['MemAvailable']<=memory['MemTotal'],
            'incomplete_probe','complete actual OS/kernel accounting required')
        vmstat=_linux_counters(_accounting_read(sources,'/proc/vmstat'))
        require({'nr_free_pages','nr_anon_pages','nr_file_pages','balloon_inflate','balloon_deflate','balloon_migrate'}<=vmstat.keys(),
            'unsupported','actual balloon counters unavailable; do not infer balloon capacity')
        pressure=_memory_pressure(_accounting_read(sources,'/proc/pressure/memory'))
        resident=[];seen=set()
        for process in processes:
            integer(process['pid'],'resident PID',1);integer(process['start_ticks'],'resident birth',1)
            require(process['pid']not in seen,'incomplete_probe','complete unique resident process inventory required');seen.add(process['pid'])
            projection={key:process[key]for key in ('pid','start_ticks','executable','uids','cgroup')}
            if process['executable']in {'[kernel]','[nonexecuting]'}:
                resident.append({**projection,'rss_bytes':None,'pss_bytes':None});continue
            raw=_accounting_read(sources,f"/proc/{process['pid']}/smaps_rollup",16384)
            lines=raw.splitlines();require(lines and re.fullmatch(r'[0-9a-f]+-[0-9a-f]+ .*',lines[0]),
                'unsupported','actual smaps_rollup header required')
            stats=_linux_counters('\n'.join(lines[1:]),kilobytes=True)
            require({'Rss','Pss'}<=stats.keys()and stats['Pss']<=stats['Rss'],
                'incomplete_probe','actual resident RSS/PSS accounting required')
            actual=sources.process(process['pid'])
            require(all(actual[key]==process[key]for key in projection),'identity_mismatch','resident PID birth/credentials/scope changed')
            resident.append({**projection,'rss_bytes':stats['Rss'],'pss_bytes':stats['Pss']})
        job_rows={}
        for job,native in jobs.items():
            require(JOB_ID.fullmatch(job)is not None,'unsupported','literal original job ID required')
            group=groups[job];path='/sys/fs/cgroup'+root+'/job_'+job
            try:
                current=_accounting_read(sources,path+'/memory.current',128).strip()
                maximum=_accounting_read(sources,path+'/memory.max',128).strip()
                require(current.isdigit()and maximum.isdigit()and int(maximum)>0,
                    'unsupported','actual finite cgroup current/max bytes required')
                integer(int(current),'cgroup current');integer(int(maximum),'cgroup maximum',1)
                require(int(maximum)==group['memory_max_bytes']==native['limit_bytes'],
                    'guest_capacity','original allocation/cgroup limit changed')
                events=_linux_counters(_accounting_read(sources,path+'/memory.events',4096))
                require({'low','high','max','oom','oom_kill'}<=events.keys()and
                    not any(value for key,value in events.items()if key.startswith('oom')),
                    'guest_capacity','actual job experienced an OOM event')
                stats=_linux_counters(_accounting_read(sources,path+'/memory.stat',16384))
                require({'anon','file','kernel'}<=stats.keys(),'incomplete_probe','actual job resident/kernel counters required')
                job_pressure=_memory_pressure(_accounting_read(sources,path+'/memory.pressure',4096))
                require(_accounting_read(sources,path+'/memory.max',128).strip()==maximum,
                    'identity_mismatch','actual cgroup limit raced during accounting')
                job_rows[job]=dict(generation=native['generation'],cgroup=path,scope='present',memory_current_bytes=int(current),
                    memory_max_bytes=int(maximum),memory_events=events,memory_stat=stats,pressure=job_pressure)
            except FileNotFoundError:
                require(native['terminal']is True and group['populated']is False and not group['processes'],
                    'incomplete_probe','live original cgroup accounting missing')
                job_rows[job]=dict(generation=native['generation'],cgroup=path,scope='absent',memory_current_bytes=None,
                    memory_max_bytes=None,memory_events=None,memory_stat=None,pressure=None)
        after=_linux_counters(_accounting_read(sources,'/proc/meminfo'),kilobytes=True)
        require(needed<=after.keys()and memory['MemTotal']==after['MemTotal']and after['MemFree']<=after['MemTotal'],
            'identity_mismatch','guest physical accounting changed during capture')
        row=dict(schema='qcl.host-resource-guest-accounting.v1',identity=dict(identity),observed_at=int(clock()),
            scope='finite all-nonfree upper including jobs/cache/balloon; explicit future safety allowance required',
            meminfo_bytes=memory,meminfo_after_bytes=after,vmstat_counters=vmstat,pressure=pressure,processes=resident,jobs=job_rows,
            os_upper_bound_bytes=max(memory['MemTotal']-memory['MemFree'],after['MemTotal']-after['MemFree']),
            balloon_current_bytes=None)
        require(len(json.dumps(row,sort_keys=True,allow_nan=False).encode())<=MAX_OUTPUT_BYTES,
            'output_bound','bounded actual guest accounting packet required');return row
    except (OSError,KeyError,TypeError,ValueError)as error:
        raise ResourceError('incomplete_probe','actual Linux accounting unavailable or unsupported')from error


def capture_guest_facts(config,sources,*,clock=time.time,calibration=False):
    """Installed root-only guest reader; machine-local protected config only."""
    from native_attempt import _worker_output_sources,_worker_output_generation
    output_sources=_worker_output_sources()
    sources._output_sources=output_sources
    output_before=_worker_output_generation(output_sources)
    before=sources.host();processes=sources.processes();alljobs=capture_scheduler(config,sources)
    jobs={key:value for key,value in alljobs.items() if value['node']==config['node']}
    require(all(j['owner_uid']==config['client_uid'] for j in jobs.values()),'ownership','foreign job on enrolled dedicated guest')
    root=config['slurm_cgroup_root'];require(root.startswith('/') and root!='/' and '..' not in Path(root).parts,'trust','enrolled cgroup root required')
    groups={job:scan_job_group(Path('/sys/fs/cgroup'+root)/('job_'+job),root+'/job_'+job,processes) for job in jobs}
    for p in processes:
        if config['client_uid'] not in p['uids']:continue
        in_job=any(p['cgroup']==root+'/job_'+job or p['cgroup'].startswith(root+'/job_'+job+'/') for job in jobs)
        infrastructure=any(p['cgroup']==row['cgroup'] and p['executable']==row['executable'] for row in config['infrastructure_processes'])
        require(in_job or infrastructure,'incomplete_workloads','unjoined owner process outside complete native allocation inventory')
    # Owning P04/P07 staging producer is not implemented here. No directory
    # traversal/fsync of scientific files and no fabricated durable publication.
    outputs={}
    after=sources.host();require(all(before[k]==after[k] for k in ('boot_id','machine_id','kernel','dmi_uuid','MemTotal')),
        'identity_mismatch','guest changed during capture')
    before['MemAvailable']=min(before['MemAvailable'],after['MemAvailable'])
    image=os.path.realpath('/run/current-system');require(image.startswith('/nix/store/'),'qualification','immutable guest image identity required')
    trusted_root_path(image,directory=True)
    identity=dict(machine_id=before['machine_id'],dmi_uuid=before['dmi_uuid'],boot_id=before['boot_id'],kernel=before['kernel'],image_id=image)
    node=sources.run([config['scontrol'],'--oneliner','show','node',config['node']])
    real=re.findall(r'(?:^|\s)RealMemory=([0-9]+)',node)
    require(len(real)==1 and int(real[0])>0,'incomplete_probe','native Slurm node RealMemory required')
    unit=command_engine.unit_state(lambda argv:sources.run([config['systemctl'],*argv[1:]]),'slurmd.service')
    main=next((p for p in processes if str(p['pid'])==unit['MainPID']),None)
    states=re.findall(r'(?:^|\s)State=([^\s]+)',node)
    registered=(unit['LoadState']=='loaded' and unit['ActiveState']=='active' and main is not None and
        main['uids']==[0]*4 and command_engine.daemon_scope_bound(main['cgroup'],unit['ControlGroup']) and
        main['executable']==config['slurmd_executable'] and len(states)==1 and
        states[0].split('+')[0] in {'IDLE','ALLOCATED','MIXED'} and 'NOT_RESPONDING' not in states[0])
    accounting=None
    if calibration:
        try:accounting=capture_guest_accounting(config,sources,identity=identity,jobs=jobs,groups=groups,processes=processes,clock=clock)
        except ResourceError as error:accounting=dict(schema='qcl.host-resource-guest-accounting.v1',state='NOT_MEASURED',reason=error.code)
    output_after=_worker_output_generation(output_sources)
    require(output_before==output_after,'qualification','worker output generation changed during guest snapshot')
    packet=dict(schema='qcl.host-resource-guest-facts.v1',protocol=config['guest_protocol'],observed_at=int(clock()),
        identity_before=identity,identity_after=identity,jobs=jobs,groups=groups,outputs=outputs,
        memory={key:before[key] for key in ('MemTotal','MemAvailable')},slurm_memory_bytes=int(real[0])*1024**2,slurm_registered=registered)
    if output_after is not None:
        require(output_after['worker']['node']==config['node'] and output_after['worker']['identity']==
            {key:identity[key] for key in ('machine_id','boot_id','kernel','dmi_uuid')},'qualification','local worker identity differs')
        packet['output_generation']=output_after
    if calibration:packet['calibration_accounting']=accounting
    subset_reader=getattr(sources,'qualification_subset',None)
    if callable(subset_reader):
        subset=subset_reader()
        if subset is not None:
            require(type(subset)is dict and len(json.dumps(subset,sort_keys=True,allow_nan=False).encode())<=65536 and
                subset['selector']['receiver']['machine_id']==identity['machine_id'] and
                subset['selector']['receiver']['boot_id']==identity['boot_id'],
                'qualification_observations_required','fixed bounded role subset identity differs')
            packet['qualification']=subset
    require(len(json.dumps(packet,sort_keys=True,allow_nan=False).encode())<=MAX_OUTPUT_BYTES,'output_bound','whole bounded guest packet required')
    return packet
