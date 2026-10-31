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
import xml.etree.ElementTree as ET

import application_release as command_engine
from host_resource_operations import (BackendQualification, CompletionEvidence, GuestEvidence,
    HostEvidence, ResourceError, RuntimeBinding, integer, policy_digest,
    require, strict_json, text)
from host_resource_backends import (collect_native_runtime, fingerprint, pve_memory_mib, read_root_json,
    trusted_root_path, MAX_OUTPUT_BYTES)
from host_resource_startup import ColdHostEvidence, ColdVMRecord

TERMINAL={'CANCELLED','COMPLETED','FAILED','TIMEOUT','OUT_OF_MEMORY','NODE_FAIL','PREEMPTED','BOOT_FAIL','DEADLINE'}
JOB_ID=re.compile(r'[1-9][0-9]{0,18}\Z')


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
        generation=fingerprint([cluster,job,fields['UserId'],fields['SubmitTime'],fields['StartTime'],fields['Restarts']])
        result[job]=dict(native_id=job,kind='slurm_allocation',generation=generation,
            owner_uid=int(owner[1]),node=fields['NodeList'],state=state,terminal=state in TERMINAL,
            limit_bytes=int(limit[1])*scale[limit[2]],submit_time=fields['SubmitTime'],start_time=fields['StartTime'])
    return result


def workload_identity(native):
    # Native generation is observed, never accepted from a client.
    generation=fingerprint([native.get('generation'),native.get('submit_time'),native.get('start_time')])
    return 'slurm:'+generation if native.get('kind','slurm_allocation')=='slurm_allocation' else 'build:'+generation


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
    def read(self,path,limit=65536):
        with open(path,'rb') as stream:data=stream.read(limit+1)
        require(len(data)<=limit,'output_bound','native metadata exceeds bound')
        return data.decode()
    def host(self):
        return dict(boot_id=self.read('/proc/sys/kernel/random/boot_id').strip(),
            machine_id=self.read('/etc/machine-id').strip(),kernel=self.read('/proc/sys/kernel/osrelease').strip(),
            dmi_uuid=self.read('/sys/class/dmi/id/product_uuid').strip().lower(),**meminfo(self.read('/proc/meminfo')))
    def process(self,pid):
        budget=command_engine.UpdateScan(time.monotonic()+10)
        row=command_engine.process_record(budget,Path('/proc')/str(pid))
        raw=budget.read(Path('/proc')/str(pid)/'stat').decode();fields=raw[raw.rfind(')')+2:].split()
        row['ppid']=int(fields[1])
        require(int(fields[19])==row['start_ticks'],'caller','PID birth changed')
        return {k:row[k] for k in ('pid','ppid','uids','start_ticks','cgroup','executable')}
    def processes(self):
        budget=command_engine.UpdateScan(time.monotonic()+10);rows=[]
        for path in budget.entries('/proc','pid'):
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
    def run(self,argv):return self.runner.run(argv,timeout_seconds=30)
    def guest_identity(self,vm_id):
        return trusted_rpc(self.config['guests'][vm_id],'guest-identity',{},run=command_engine.command)
    def guest(self,vm_id):
        route=self.config['guests'][vm_id]
        return trusted_rpc(route,'guest-facts',{},run=command_engine.command)
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
    if existing_budget is not None:existing_budget.before()
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
    if existing_budget is not None:
        existing_budget.before()
        # Reserve before JSON/base64 allocation, not after materializing payload.
        existing_budget.reserve(4*MAX_OUTPUT_BYTES)
    token=base64.urlsafe_b64encode(json.dumps(payload,separators=(',',':')).encode()).decode()
    require(len(token)<=MAX_OUTPUT_BYTES,'output_bound','RPC input bound')
    if existing_budget is not None:
        existing_budget.before();existing_budget.reserve(3*MAX_OUTPUT_BYTES)
    result=command_engine.ssh(route['target'],[route['helper'],route['role'],action,token],
        run=lambda argv:run([argv[0],'-oIdentitiesOnly=yes','-oIdentityAgent=none','-i',str(key),*argv[1:]],
            timeout_seconds=120,output_bytes=MAX_OUTPUT_BYTES),trust_snapshot=snapshot)
    if existing_budget is not None:existing_budget.before()
    packet=strict_json(result);require(type(packet) is dict,'shape','bounded RPC object required')
    return packet


class NativeFactsProvider:
    def __init__(self,policy,config,backend,runner,*,sources=None,clock=time.time):
        self.policy,self.config,self.backend,self.runner,self.clock=policy,config,backend,runner,clock
        self.sources=sources or LocalSources(config,runner)
        self.last=None;self.native={}
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
        require(ref.kind=='slurm_allocation','unsupported','systemd/Nix per-build daemon join is not qualified; use paid full-VM administrative reservation')
        require(JOB_ID.fullmatch(ref.native_id),'shape','native allocation ID required')
        # Native scheduler generation must still exist. Never synthesize from job ID.
        route=self.config['scheduler_route'];packet=trusted_rpc(route,'scheduler-facts',{},run=command_engine.command)
        require(packet['schema']=='qcl.host-resource-scheduler-facts.v1','shape','authenticated scheduler facts required')
        jobs=packet['jobs'];require(ref.native_id in jobs,'native_generation','native allocation missing/evicted')
        native=jobs[ref.native_id];require(native['owner_uid']==self.config['client_uid'],'ownership','native owner differs')
        vm=self.config['nodes'].get(native['node']);require(vm in self.config['enrollment'],'ownership','node not enrolled on this host')
        identity='slurm:'+native['generation'];self.native[identity]=native
        return native,vm,identity,'native-'+hashlib.sha256(identity.encode()).hexdigest()
    def binding_facts(self,native_vm_id,*,owner_state):
        host,rows,_=self._host_inventory();bindings=[];qualifications=[]
        protected=read_root_json(self.config['qualification'])
        for vm in self.policy.vms:
            enrolled=self.config['enrollment'][vm.vm_id]
            row=next(r for r in rows if r['native_id']==enrolled['native_id'])
            if not row['running']:continue
            read=self.backend.readback(vm.vm_id);runtime=collect_native_runtime(self.backend,read)
            guest=self.sources.guest_identity(vm.vm_id);ident=guest['identity']
            require(ident['machine_id']==enrolled['machine_id'] and ident['dmi_uuid']==read.native_id.lower(),
                'identity_mismatch','startup guest identity differs')
            binding=RuntimeBinding(vm.vm_id,read.native_id,read.process_id,ident['boot_id'],ident['image_id'],ident['kernel'],
                runtime.host_kernel_id,runtime.qemu_version_id,runtime.backend_version_id,self.config['readback_version'],read.config_fingerprint)
            matches=[q for q in protected['qualifications'] if q['binding']==asdict(binding)]
            require(len(matches)==1,'qualification','exact startup qualification required')
            q=dict(matches[0]);q['binding']=binding;bindings.append(binding);qualifications.append(BackendQualification(**q))
        require(any(b.native_id==native_vm_id for b in bindings),'identity_mismatch','requested native VM is not observed running')
        return HostEvidence(self.policy.host_id,self.policy.owner_id,host['boot_id'],policy_digest(self.policy),int(self.clock()),
            host['MemTotal'],self.policy.reserves.foreign_max_bytes,self.policy.capacity_evidence_ref,self.policy.owned_pool.agreement_ref,
            True,True,host['MemAvailable']>=self.policy.reserves.safety_bytes,fingerprint([host,rows]),tuple(bindings),tuple(qualifications),
            {vm.vm_id:() for vm in self.policy.vms})
    def request_facts(self,demand,*,owner_state):
        return self._capture(demand,owner_state=owner_state)
    def recovery_snapshot(self,retiring_vm_id,*,owner_state):
        require(retiring_vm_id in owner_state['bindings'],'ownership','retiring resident required')
        evidence=self._capture(None,owner_state=owner_state,retiring_vm_id=retiring_vm_id)
        return evidence,{vm.vm_id:self.backend.readback(vm.vm_id) for vm in self.policy.vms if vm.vm_id!=retiring_vm_id}
    def _capture(self,demand,*,owner_state,retiring_vm_id=None):
        host,rows,agreement=self._host_inventory(retiring_vm_id=retiring_vm_id);bindings=[];qualifications=[];live={};guests={}
        protected=read_root_json(self.config['qualification'])
        require(protected['schema']=='qcl.host-resource-qualification.v1','qualification','protected exact qualification required')
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
            matching=[q for q in protected['qualifications'] if q['binding']==asdict(binding)]
            require(len(matching)==1,'qualification','observed backend/image/kernel/readback has no exact qualification')
            q=dict(matching[0]);q['binding']=binding;qualified=BackendQualification(**q)
            qualified=replace(qualified,slurm_registration_verified=(qualified.slurm_registration_verified is True
                and guest.get('slurm_registered') is True))
            profile=self.config['qualified_protocols'][vm.vm_id]
            require(guest['protocol']==profile['guest_protocol'] and
                self.sources.process(int(read.process_id))['start_ticks']==profile['qemu_birth_ticks'],
                'qualification','native process generation/protocol changed')
            known={}
            if owner_state:
                for row in owner_state['receipts']:
                    if row['request']['vm_id']==vm.vm_id and not row['finished'] and row['phase']=='RUN':
                        identity=row['request']['workload_id'];native=self.native.get(identity)
                        if native is None:
                            native=next((j for j in guest['jobs'].values() if 'slurm:'+j['generation']==identity),None)
                        require(native is not None,'native_generation','live owner native generation evicted')
                        known[identity]=dict(native_id=native['native_id'],generation=native['generation'],phase='RUN')
            live[vm.vm_id]=classify_guest_workloads(guest['jobs'],guest['groups'],known,gate_executables=tuple(profile['gate_executables']))
            bindings.append(binding);qualifications.append(qualified)
        evidence=HostEvidence(self.policy.host_id,self.policy.owner_id,host['boot_id'],policy_digest(self.policy),int(self.clock()),
            host['MemTotal'],self.policy.reserves.foreign_max_bytes,self.policy.capacity_evidence_ref,self.policy.owned_pool.agreement_ref,
            True,True,host['MemAvailable']>=self.policy.reserves.safety_bytes,fingerprint([host,rows,guests]),tuple(bindings),tuple(qualifications),live)
        self.last=(evidence,guests)
        proofs=getattr(self,'native_proofs',None)
        if proofs is not None:proofs.validate_state(owner_state,evidence=evidence)
        if retiring_vm_id is None:self._persist(evidence,guests)
        return evidence
    def _persist(self,evidence,guests):
        # One bounded probe cache for status/RootNativeBoundary, not another grant ledger.
        from host_resource_operations import FileReceiptStore
        directory=trusted_root_path(self.config['state_directory'],directory=True)
        store=FileReceiptStore.open_existing(directory)
        host=asdict(evidence);host.pop('qualifications');host['schema']='qcl.host-resource-evidence.v1'
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
        return GuestEvidence(req['vm_id'],g['identity_before']['boot_id'],req['workload_id'],g['observed_at'],
            g['memory']['MemTotal'],g['memory']['MemAvailable'],self.config['enrollment'][req['vm_id']]['os_reserve_bytes'],
            group['memory_max_bytes'],g['slurm_memory_bytes'],True,tuple(self.last[0].live_workloads[req['vm_id']]))
    def completion(self,request_id,*,owner_state):
        row,g,native=self._row_guest(request_id,owner_state);req=row['request'];group=g['groups'][native['native_id']]
        require(native['terminal'] and not group['populated'] and not group['processes'],
                'cleanup','actual terminal and whole native subtree absence required; gate/COMPLETING insufficient')
        output=g['outputs'].get(native['generation'])
        require(output is not None and output['generation']==native['generation'] and output['durable'] is True,
                'cleanup','root-observed closed/fsynced output provenance missing')
        return CompletionEvidence(req['vm_id'],g['identity_before']['boot_id'],req['workload_id'],g['observed_at'],0,True,True,
            g['memory']['MemTotal'],g['memory']['MemAvailable'],tuple(self.last[0].live_workloads[req['vm_id']]))
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


def capture_guest_facts(config,sources,*,clock=time.time):
    """Installed root-only guest reader; machine-local protected config only."""
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
        main['uids']==[0]*4 and main['cgroup']==unit['ControlGroup'] and
        main['executable']==config['slurmd_executable'] and len(states)==1 and
        states[0].split('+')[0] in {'IDLE','ALLOCATED','MIXED'} and 'NOT_RESPONDING' not in states[0])
    return dict(schema='qcl.host-resource-guest-facts.v1',protocol=config['guest_protocol'],observed_at=int(clock()),
        identity_before=identity,identity_after=identity,jobs=jobs,groups=groups,outputs=outputs,
        memory={key:before[key] for key in ('MemTotal','MemAvailable')},slurm_memory_bytes=int(real[0])*1024**2,slurm_registered=registered)
