"""Inert M2 codec/ownership fixtures. Source ticket does NOT execute this file.

Synthetic carrier bytes exercise decoding only; they grant no Linux/native,
controller, scientific or scheduler qualification.
"""
from dataclasses import asdict
import hashlib
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import MagicMock, patch

OPS=Path(__file__).parents[1]/'ops'
sys.path.insert(0,str(OPS))
import scientific_b0_provider as b0
import scientific_b0_site as site
import scientific_b0_m2 as m2


def slot(index,kind='regular',acquire='create_exclusive'):
    return dict(file_id=f'{index+1:032x}',kind=kind,root_index=None,name='file'+str(index),
        access='read_write',acquire=acquire,state='not_acquired',fd_index=None,
        expected_dev=None,expected_ino=None,expected_mode=None,initial_extent=None,
        max_extent=4096,max_opens=2,max_calls=64,create_mode=0o600,publish_mode=None,
        seals='full_before_read' if kind in ('snapshot','capture_metadata') else 'none',
        allowed_ops=['open','stat','close'],rename_targets=[])


def grant(count=2,capture=False):
    files=[slot(i) for i in range(count)]
    if capture:
        files[0]=slot(0,'snapshot','memfd_new')
        files[1]=slot(1,'capture_metadata','memfd_new')
    return dict(capsule_digest='11'*32,native_kit_digest='22'*32,worker_identity_digest='33'*32,
        operation_id='44'*16,delegate_id='55'*16,grant_sequence=7,deadline_ns=1000,
        authority_epoch='epoch-1',counter_epoch='counter-1',clock_domain='boot-1',
        bound=asdict(b0.Budget()),native_limits=dict(allocated_bytes=0,cpu_ns=0),
        kind='capture_publication' if capture else 'text',files=files)


def carrier(g,capture=False):
    n=len(g['files']); raw=bytearray(m2.counter_length(n,4096,capture,1 if capture else 0))
    struct.pack_into('<8sIIQQ',raw,0,b'QCLB0CN1',1,2,len(raw),1)
    for offset,key in ((32,'capsule_digest'),(64,'native_kit_digest'),(96,'worker_identity_digest'),
                       (224,'operation_id'),(240,'delegate_id')):
        value=bytes.fromhex(g[key]); raw[offset:offset+len(value)]=value
    for offset,key in ((128,'authority_epoch'),(160,'counter_epoch'),(192,'clock_domain')):
        raw[offset:offset+32]=hashlib.sha256(g[key].encode('utf-8')).digest()
    struct.pack_into('<Q',raw,256,g['grant_sequence']); struct.pack_into('<Q',raw,280,g['deadline_ns'])
    struct.pack_into('<Q',raw,824,n)
    for i,row in enumerate(g['files']):
        raw[832+96*i:848+96*i]=bytes.fromhex(row['file_id'])
    return raw


class CapacityAndValidity(unittest.TestCase):
    def test_closed_files_schema_and_future_null_identity(self):
        root=slot(0,'directory','inherit_fd')
        root.update(name=None,state='existing',access='directory',fd_index=3,expected_dev=5,
                    expected_ino=6,expected_mode=0o700,initial_extent=0,create_mode=None)
        child=slot(1); child['root_index']=0
        self.assertEqual(m2.validate_files([root,child]),[root,child])
        child['expected_ino']=99
        with self.assertRaises(b0.ProviderRefusal):
            m2.validate_files([root,child])
        child['expected_ino']=None; child['extra']='caller authority'
        with self.assertRaises(b0.ProviderRefusal):
            m2.validate_files([root,child])

    def test_n33_active_transfer_uses_same_fixed_stripe_and_length(self):
        g=grant(33,True); raw=carrier(g,True); initial_length=len(raw)
        transfer=bytearray(184)
        transfer[:32]=bytes.fromhex(g['capsule_digest'])
        transfer[32:48]=bytes.fromhex(g['operation_id'])
        transfer[48:64]=bytes.fromhex(g['delegate_id'])
        struct.pack_into('<QQ',transfer,64,1,1)
        transfer[80:96]=bytes.fromhex(g['files'][0]['file_id'])
        transfer[96:112]=bytes.fromhex(g['files'][1]['file_id'])
        transfer[112:128]=bytes.fromhex(g['delegate_id'])
        struct.pack_into('<QQ',transfer,128,0,1)
        transfer[168:184]=hashlib.sha256(transfer[:168]).digest()[:16]
        struct.pack_into('<Q',raw,4000,1); raw[4008:4192]=transfer
        parsed=m2.parse_counter(bytes(raw),g,4096,True)
        self.assertEqual(len(raw),initial_length)
        self.assertEqual(len(parsed['custody']),1)
        self.assertEqual(parsed['files'][0]['state'],0)

    def test_fixed_n33_lengths_and_n2_offsets(self):
        self.assertEqual(m2.counter_length(33,4096,True,1),8192)
        self.assertEqual(m2.counter_length(33,4096),4096)
        self.assertEqual(832+96*33+8+184,4192)
        self.assertEqual(832+96*2+8+184,1216)
        self.assertEqual(832+96*2+8,1032)
        for n in (2,33):
            g=grant(n,True); raw=carrier(g,True)
            self.assertEqual(m2.parse_counter(bytes(raw),g,4096,True)['custody'],[])

    def test_capture_capacity_requires_retained_exact_discriminator(self):
        g=grant(2,True); raw=carrier(g,True)
        g['files'][0]['acquire']='inherit_fd'
        with self.assertRaises(b0.ProviderRefusal):
            m2.parse_counter(bytes(raw),g,4096,True)
        with self.assertRaises(b0.ProviderRefusal):
            m2.counter_length(2,4096,True,2)

    def test_unused_capture_bytes_and_old_stripe_refuse(self):
        g=grant(2,True)
        for offset in (1032,1100,1218,len(carrier(g,True))-1):
            raw=carrier(g,True); raw[offset]=1
            with self.subTest(offset=offset),self.assertRaises(b0.ProviderRefusal):
                m2.parse_counter(bytes(raw),g,4096,True)

    def test_actual_count_cannot_increase_capacity(self):
        for capture,count in ((False,1),(True,2)):
            g=grant(2,capture); raw=carrier(g,capture)
            struct.pack_into('<Q',raw,1024,count)
            with self.assertRaises(b0.ProviderRefusal):
                m2.parse_counter(bytes(raw),g,4096,capture)

    def test_f1_valid_and_unknown_states_have_distinct_storage(self):
        g=grant(); offset=1032
        for state in range(5):
            raw=carrier(g); raw[offset]=state
            if state in (2,3):
                struct.pack_into('<QQQQ',raw,848,5,6,7,8)
            parsed=m2.parse_counter(bytes(raw),g,4096)
            self.assertEqual(parsed['files'][0]['state'],state)
        for state in (0,1,4):
            raw=carrier(g); raw[offset]=state; struct.pack_into('<Q',raw,856,6)
            with self.assertRaises(b0.ProviderRefusal):
                m2.parse_counter(bytes(raw),g,4096)

    def test_odd_torn_padding_and_extra_page_refuse(self):
        g=grant()
        variants=[]
        odd=carrier(g); struct.pack_into('<Q',odd,320,1); variants.append(odd)
        pad=carrier(g); pad[-1]=1; variants.append(pad)
        long=carrier(g)+bytes(4096); struct.pack_into('<Q',long,16,len(long)); variants.append(long)
        for raw in variants:
            with self.assertRaises(b0.ProviderRefusal):
                m2.parse_counter(bytes(raw),g,4096)

    def test_budget_and_exact_counter_identity(self):
        g=grant()
        for offset,value in ((344,1),(256,8),(280,1001)):
            raw=carrier(g); struct.pack_into('<Q',raw,offset,value)
            with self.assertRaises(b0.ProviderRefusal):
                m2.parse_counter(bytes(raw),g,4096)


class Codecs(unittest.TestCase):
    def test_epoch_exact_decoded_utf8_not_json_or_hex(self):
        for value in ('epoch-1','a'*64,'é','e\u0301'):
            self.assertEqual(m2.epoch_sha(value),hashlib.sha256(value.encode('utf-8')).digest())
            self.assertNotEqual(m2.epoch_sha(value),hashlib.sha256(site.canonical(value)).digest())
        self.assertNotEqual(m2.epoch_sha('a'*64),hashlib.sha256(bytes.fromhex('a'*64)).digest())
        self.assertNotEqual(m2.epoch_sha('é'),m2.epoch_sha('e\u0301'))
        for value in ('','x\0y',True,'\ud800'):
            with self.assertRaises(b0.ProviderRefusal):
                m2.epoch_sha(value)

    def test_identity_canonical_object_and_capsule_exact_lf(self):
        a=dict(pid=7,start_ticks=8,uid=3000,boot='b',executable=[1,2],mount_namespace=3,cgroup_namespace=4)
        reverse=dict(reversed(list(a.items())))
        self.assertEqual(site.canonical(a),site.canonical(reverse))
        self.assertNotEqual(m2.sha(site.canonical(a)),m2.sha(site.canonical(a)+b'\n'))
        self.assertNotEqual(m2.sha(b'{}'),m2.sha(b'{}\n'))
        self.assertEqual(len(bytes.fromhex('12'*16)),16)
        self.assertNotEqual(bytes.fromhex('12'*16),hashlib.sha256(b'12'*16).digest()[:16])

    def test_final_tag10_backref_only(self):
        # One final tensor with literal nothing metadata then its backreference.
        raw=b'\x04\x02\0\0\0\0\0\0\0\x06\x01\0\0\0\0\0\0\0\0\x0a\x01\0\0\0\0\0\0\0'
        self.assertEqual(len(m2.CanonicalSource3(raw,True).all()),1)
        with self.assertRaises(b0.ProviderRefusal):
            m2.CanonicalSource3(raw).all()
        with self.assertRaises(b0.ProviderRefusal):
            m2.CanonicalSource3(b'\x0a\x01\0\0\0\0\0\0\0',True).all()

    def test_path_symbol_string_and_signed_integer_are_distinct(self):
        raw=(b'\x04\x03\0\0\0\0\0\0\0'+b'\x02\x01\0\0\0\0\0\0\0x'+
             b'\x01\x01\0\0\0\0\0\0\0x'+b'\x03'+b'\xff'*8)
        result=m2.CanonicalSource3(raw).all()[0]
        self.assertEqual(m2._path_wire(result),[['symbol','x'],['string','x'],['integer',-1]])

    def test_metadata_empty_and_forged_whole_hash_refuse(self):
        for raw in (b'',b'QCLB0MD1'+bytes(120)):
            with self.assertRaises(b0.ProviderRefusal):
                m2.parse_metadata(raw,{},[dict(bytes=0)],{},[])


class OwnershipAndFreeze(unittest.TestCase):
    def test_same_ledger_e_u_p_s_exact_fit_and_plus_one(self):
        registry=object.__new__(m2.NativeRegistry)
        storage=dict(id='memory',kind='memory_snapshot',E=[1,2,1],P=[1,1,1],
            S=[1,1,1],A=[5,5,5],H=[10,10,10],protected=[0,0,0],stop_entries={'s':[1,1,1]})
        registry.leases={'l':dict(storage_id='memory',state='active',native_remaining=(2,1,2),stop_ids=[])}
        registry.objects={}; registry._memory=lambda:(10,2)
        self.assertEqual(registry._capacity(storage)[:4],((1,2,1),(2,1,2),(1,1,1),(1,1,1)))
        storage['A']=[5,4,5]
        with self.assertRaises(b0.ProviderRefusal):
            registry._capacity(storage)

    def test_existing_baseline_is_not_charged_twice(self):
        registry=object.__new__(m2.NativeRegistry)
        storage=dict(id='memory',kind='memory_snapshot',E=[5,2,1],P=[0,0,0],S=[0,0,0],
            A=[20,20,20],H=[20,20,20],protected=[0,0,0],stop_entries={})
        registry.leases={}; registry._memory=lambda:(20,2)
        registry.objects={'a':dict(storage_id='memory',accounted=(5,2,1),baseline_logical=5,retired=False)}
        self.assertEqual(registry._capacity(storage)[0][0],5)
        registry.objects['a']['accounted']=(7,2,1)
        self.assertEqual(registry._capacity(storage)[0][0],7)
        registry.objects['a']['retired']=True
        self.assertEqual(registry._capacity(storage)[0][0],5)

    def test_atomic_failure_still_freezes_local_registry(self):
        registry=object.__new__(m2.NativeRegistry)
        registry.control=MagicMock(mapping=bytearray(4096))
        registry.atomic=MagicMock(); registry.atomic.load32.side_effect=OSError('atomic unavailable')
        registry.operations={'a':dict(kind='text',state='active'),'s':dict(kind='stop',state='active')}
        registry.delegates={'d':dict(child=dict(role='normal'),state='issued')}
        with self.assertRaises(OSError):
            registry.freeze('primary')
        self.assertEqual(registry.operations['a']['state'],'frozen')
        self.assertEqual(registry.operations['s']['state'],'active')
        self.assertEqual(registry.delegates['d']['state'],'frozen')

    def test_close_unknown_retains_owner_and_no_retry(self):
        owner=site.DescriptorCustody(); owner.adopt((91,))
        with patch.object(site.os,'close',side_effect=OSError('uncertain')) as close:
            self.assertFalse(owner.close_one(91))
            with self.assertRaises(b0.ProviderRefusal):
                owner.close_one(91)
        self.assertEqual(close.call_count,1)
        self.assertEqual(owner.entries[91]['state'],'close_unknown')

    def test_source_pins_real_seals_ro_reopen_timer_and_payload_actuator(self):
        source=(OPS/'scientific_b0_m2.py').read_text()
        native=(OPS.parent/'native/b0_supervisor.c').read_text()
        supervisor=(OPS/'scientific_b0_site.py').read_text()
        for literal in ('F_SEAL_WRITE|fcntl.F_SEAL_SEAL','F_FUTURE',"'/proc/self/fd/'",'seal_attempted=True',
                        "record['state']='settling'",'self.owner.retain_resource','os.fsync(parent'):
            self.assertIn(literal,source)
        for literal in ('memory_order_acquire','memory_order_release','atomic_is_lock_free'):
            self.assertIn(literal,native)
        for literal in ('timerfd_create','TFD_TIMER_ABSTIME',"'cgroup.kill'",'payload actuator includes S'):
            self.assertIn(literal,supervisor)

    def test_terminal_settlement_cannot_be_caller_actual_tuple(self):
        registry=object.__new__(m2.NativeRegistry); registry.capsule=MagicMock(digest='11'*32)
        registry.delegates={}
        args=dict(digest='11'*32,operation_id='22'*16,delegate_id='33'*16,index=0,native_receipt=[0]*11)
        with self.assertRaises(b0.ProviderRefusal):
            registry.settle(args)

    def test_pending_does_not_contain_quiescence_or_final_success(self):
        source=(OPS/'scientific_b0_m2.py').read_text()
        self.assertIn('quiescence=None,final_result_ref=None',source)
        self.assertIn("whole_job_terminal='outer_root_slurm_observer_required'",source)
        self.assertIn("scientific_accepted=False",source)


# Fix-round1 fixtures: real methods, synthetic observations, NO native claims.
# They intentionally distinguish adapter omissions, late STOP, metadata-only
# effects and malformed installed rights. Execution remains a separate gate.
def transition_fixture():
    from types import SimpleNamespace
    registry=object.__new__(m2.NativeRegistry)
    root='aa'*32; fid='11'*16; alias='22'*16; parent='33'*16; lid='44'*16
    files=[dict(file_id=parent,kind='directory',root_index=None,max_extent=4096),
           dict(file_id=fid,kind='regular',root_index=0,max_extent=16),
           dict(file_id=alias,kind='regular',root_index=0,max_extent=16)]
    inv=dict(digest=root,logical=10,physical=10,inodes=2,slots=[])
    scope=dict(inventory=inv,parent=None,remaining=(10,10,2),materialized=(0,0,0),
               state='active',file_ids={fid,alias})
    storage=dict(id='memory',kind='memory_snapshot',E=[0,0,0],P=[0,0,0],S=[0,0,0],
        A=[100,100,100],H=[100,100,100],protected=[0,0,0],stop_entries={})
    profile=dict(commit_files=[fid],storage_id='memory')
    child=dict(role='normal',scope_digest=root)
    operation=dict(id='55'*16,descriptor=dict(delegates=[child],files=files),delegates={},capture=None,state='active')
    lease=dict(id=lid,revision='0',descriptor_digest=root,storage_id='memory',inventory=inv,
        native_remaining=(10,10,2),sequence=0,state='active',stop_ids=(),
        scopes={root:scope},observations={},profile=profile,operation=operation)
    operation['lease']=lease
    observed=dict(unknown=0,outstanding=(0,)*11,refs=0,requested=(0,)*11,
                  files=[dict(file_id=fid,state=2),dict(file_id=alias,state=2)])
    record=dict(id='66'*16,operation=operation,child=child,state='settled',sealed=True,
                observed=observed,grant=dict(files=files[1:]))
    operation['delegates'][0]=record
    obj=dict(reference='object-1',fd=91,dev=1,ino=2,extent=4,allocated=4,accounted=(0,0,0),
             baseline_logical=0,retired=False,storage_id='memory')
    parent_obj=dict(reference='parent',fd=90)
    registry.objects={'object-1':obj}; registry.leases={lid:lease}; registry.operations={operation['id']:operation}
    registry.config=dict(storage=[storage],authority_epoch='a',counter_epoch='c',clock_domain='b')
    registry.observation=1; registry.revision=0; registry.transfers={}; registry.last_verified=None
    registry.site=SimpleNamespace(primary=None); registry._fresh=MagicMock()
    registry._snapshot=MagicMock(return_value=dict(revision='1',issued_ns=1))
    registry._memory=lambda:(100,4)
    registry._observe_file=MagicMock(side_effect=lambda _lease,key,**kw:parent_obj if key==parent else obj)
    return registry,lease,scope,record,obj,fid


def resident_request(lease,scope,action,**values):
    request=dict(abi='qcl.b0.resident-transition.v1',action=action,lease_id=lease['id'],
        scope_digest=scope['inventory']['digest'],resident_sequence=lease['sequence'],
        tree=None,verified=None,delta=None,refundable=None,object_inventory_ref=None)
    request.update(values)
    return request


class ReviewRoundOne(unittest.TestCase):
    def test_observed_same_operation_stage_directory_refines_to_open_existing(self):
        from types import SimpleNamespace
        registry=object.__new__(m2.NativeRegistry); registry.owner=site.DescriptorCustody()
        root=slot(0,'directory','inherit_fd'); root.update(name=None)
        stage=slot(1,'directory','mkdir_exclusive'); stage.update(root_index=0,access='directory',allowed_ops=['mkdir','open','stat','close'])
        observed=dict(file_id=stage['file_id'],state=2,dev=5,ino=6,logical_extent=64,allocated_bytes=512)
        known=dict(dev=5,ino=6,retired=False,accounted=(64,512,1))
        prior=dict(state='settled',grant=dict(grant_sequence=0,files=[root,dict(stage)]),
            observed=dict(files=[observed],unknown=0,outstanding=(0,)*11),objects={stage['file_id']:known})
        operation=dict(id='11'*16,delegates={0:prior},lease={})
        registry.operations={operation['id']:operation}
        registry._observe_file=MagicMock(return_value=dict(fd=80))
        info=SimpleNamespace(st_mode=0o40700,st_nlink=2,st_dev=5,st_ino=6,st_size=64,st_blocks=1)
        files=[dict(root),dict(stage)]
        with patch.object(m2.os,'open',return_value=90) as opened, \
             patch.object(m2.os,'fstat',return_value=info),patch.object(m2.os,'close') as close:
            registry._refine_stage_aliases(operation,files)
        refined=files[1]
        self.assertEqual(refined['acquire'],'open_existing')
        self.assertEqual((refined['expected_dev'],refined['expected_ino'],refined['initial_extent']),(5,6,64))
        self.assertIsNone(refined['create_mode']); self.assertIsNone(refined['fd_index'])
        self.assertNotIn('mkdir',refined['allowed_ops'])
        for key in ('file_id','kind','root_index','name','max_extent','max_opens','max_calls'):
            self.assertEqual(refined[key],stage[key])
        self.assertTrue(opened.call_args.args[1]&m2.os.O_NOFOLLOW)
        close.assert_called_once_with(90)
        self.assertEqual(known['accounted'],(64,512,1))  # alias, no new E credit
        for state in (0,1,3,4):
            observed['state']=state
            with self.subTest(state=state),self.assertRaises(b0.ProviderRefusal):
                registry._refine_stage_aliases(operation,[dict(root),dict(stage)])
        observed['state']=2
        changed=dict(stage,name='foreign-stage')
        with self.assertRaises(b0.ProviderRefusal):
            registry._refine_stage_aliases(operation,[dict(root),changed])
        with self.assertRaises(b0.ProviderRefusal):
            registry._refine_stage_aliases(dict(operation),[dict(root),dict(stage)])

    def test_directory_alias_never_mints_top_root_or_unknown_actual_inode(self):
        from types import SimpleNamespace
        registry=object.__new__(m2.NativeRegistry); registry.owner=site.DescriptorCustody()
        root=slot(0,'directory','inherit_fd')
        stage=slot(1,'directory','mkdir_exclusive'); stage['root_index']=0
        observed=dict(file_id=stage['file_id'],state=2,dev=5,ino=6,logical_extent=64,allocated_bytes=512)
        prior=dict(state='settled',grant=dict(grant_sequence=0,files=[root,dict(stage)]),
            observed=dict(files=[observed],unknown=0,outstanding=(0,)*11),
            objects={stage['file_id']:dict(dev=5,ino=6,retired=False)})
        operation=dict(id='11'*16,delegates={0:prior},lease={}); registry.operations={operation['id']:operation}
        registry._observe_file=MagicMock(return_value=dict(fd=80))
        top=dict(stage,root_index=None)
        with self.assertRaises(b0.ProviderRefusal):
            registry._refine_stage_aliases(operation,[dict(root),top])
        wrong=SimpleNamespace(st_mode=0o40700,st_nlink=2,st_dev=5,st_ino=99,st_size=64,st_blocks=1)
        with patch.object(m2.os,'open',return_value=90),patch.object(m2.os,'fstat',return_value=wrong), \
             patch.object(m2.os,'close') as close,self.assertRaises(b0.ProviderRefusal):
            registry._refine_stage_aliases(operation,[dict(root),dict(stage)])
        close.assert_called_once_with(90)

    def test_readonly_open_hash_close_can_release_without_refunding_read_calls(self):
        from types import SimpleNamespace
        registry,lease,scope,record,obj,fid=transition_fixture()
        directory=SimpleNamespace(st_dev=1,st_ino=10,st_mode=0o40700,st_size=4,st_blocks=1,
            st_nlink=2,st_mtime_ns=5,st_ctime_ns=6)
        regular=SimpleNamespace(st_dev=1,st_ino=11,st_mode=0o100600,st_size=4,st_blocks=1,
            st_nlink=1,st_mtime_ns=7,st_ctime_ns=8)
        root=slot(0,'directory','inherit_fd')
        root.update(name=None,access='directory',state='existing',create_mode=None)
        child=slot(1,'regular','open_existing')
        child.update(root_index=0,access='read',state='existing',create_mode=None,
                     allowed_ops=['open','read','stat','close'])
        record['grant']['files']=[root,child]
        lease['operation']['descriptor']['files']=[root,child]
        record['baselines']={root['file_id']:m2.object_facts(directory),child['file_id']:m2.object_facts(regular)}
        record['observed']['files']=[dict(state=3,opens_actual=1,syscalls_actual=2,write_actual=0),
                                     dict(state=3,opens_actual=1,syscalls_actual=3,write_actual=0)]
        requested=(4,0,0,0,0,0,5,0,0,0,0)
        record['observed']['requested']=requested
        lease['profile']['root_indices']={root['file_id']:0}
        registry.site=SimpleNamespace(custody=SimpleNamespace(directory_fds=(90,)))
        registry.owner=site.DescriptorCustody()
        registry._observe_file=MagicMock(return_value=dict(fd=90))
        request=resident_request(lease,scope,'release',refundable=[10,10,2],
            tree=dict(descriptor=scope['inventory']['digest'],remaining=[10,10,2],children=[]))
        with patch.object(m2.os,'open',return_value=91), \
             patch.object(m2.os,'fstat',side_effect=lambda fd:directory if fd==90 else regular), \
             patch.object(m2.os,'close') as close:
            result=registry._resident_transition(record,request)
        self.assertEqual(result['outcome'],'no_mutation_proven')
        self.assertEqual(lease['native_remaining'],(0,0,0))
        self.assertEqual(record['observed']['requested'],requested)
        close.assert_called_once_with(91)

    def test_commit_before_materialize_refuses_then_exact_alias_once_survives_commit(self):
        from types import SimpleNamespace
        registry,lease,scope,record,obj,fid=transition_fixture()
        tree=lambda:dict(descriptor=scope['inventory']['digest'],remaining=list(scope['remaining']),children=[])
        commit=lambda:resident_request(lease,scope,'commit',tree=tree(),verified=dict(file_id=fid,sha256=m2.sha(b'data')))
        info=SimpleNamespace(st_dev=1,st_ino=2)
        with patch.object(m2.os,'pread',return_value=b'data'),patch.object(m2.os,'fsync'), \
             patch.object(m2.os,'fstat',return_value=info):
            with self.assertRaisesRegex(b0.ProviderRefusal,'unmaterialized'):
                registry._resident_transition(record,commit())
            self.assertEqual(lease['native_remaining'],(10,10,2))
            self.assertEqual(lease['state'],'active')
            before=registry._materialization(lease,scope)
            self.assertEqual(before['delta'],(4,4,1))  # two aliases, one object
            request=resident_request(lease,scope,'materialize',resident_sequence=1,
                delta=[4,4,1],object_inventory_ref=before['reference'])
            registry._resident_transition(record,request)
            self.assertEqual(lease['native_remaining'],(6,6,1))
            self.assertEqual(obj['accounted'],(4,4,1))
            registry._resident_transition(record,commit())
        self.assertEqual(lease['state'],'committed')
        self.assertEqual(lease['native_remaining'],(0,0,0))
        self.assertEqual(registry._capacity(registry.config['storage'][0])[0][0],4)

    def test_normal_commit_then_late_stop_lineage_and_replay_guards(self):
        registry,lease,root,normal,obj,fid=transition_fixture()
        # Normal side is already reconciled; retained STOP association is disjoint.
        obj['accounted']=(4,4,1)
        stop_digest='bb'*32
        stop_inv=dict(digest=stop_digest,logical=2,physical=2,inodes=1,slots=[])
        stop_scope=dict(inventory=stop_inv,parent=root['inventory']['digest'],remaining=(2,2,1),
            materialized=(0,0,0),state='active',file_ids=set())
        lease['scopes'][stop_digest]=stop_scope
        root['inventory']['slots']=[stop_inv]
        child=dict(role='stop',scope_digest=stop_digest)
        lease['operation']['descriptor']['delegates'].append(child)
        lease['stop_ids']=('stop1',); registry.config['storage'][0]['stop_entries']={'stop1':[2,2,1]}
        tree=dict(descriptor=root['inventory']['digest'],remaining=[10,10,2],children=[
            dict(descriptor=stop_digest,remaining=[2,2,1],children=[])])
        from types import SimpleNamespace
        with patch.object(m2.os,'pread',return_value=b'data'),patch.object(m2.os,'fsync'), \
             patch.object(m2.os,'fstat',return_value=SimpleNamespace(st_dev=1,st_ino=2)):
            registry._resident_transition(normal,resident_request(lease,root,'commit',tree=tree,
                verified=dict(file_id=fid,sha256=m2.sha(b'data'))))
        self.assertEqual(lease['native_remaining'],(2,2,1))
        registry.site.primary='late pressure'
        self.assertIs(registry._scope(lease['id'],stop_digest)[1],stop_scope)
        with self.assertRaises(b0.ProviderRefusal):
            registry._scope(lease['id'],root['inventory']['digest'])
        stop_record=dict(operation=lease['operation'],child=child,state='issued')
        observation=dict(delta=(0,0,0),objects={},reference='known-stop-empty')
        lease['observations'][stop_digest]=observation
        registry._materialization=MagicMock(return_value=observation)
        request=resident_request(lease,stop_scope,'materialize',resident_sequence=1,delta=[0,0,0],
            object_inventory_ref='known-stop-empty')
        result=registry._resident_transition(stop_record,request)
        registry._fresh.assert_called_with(normal=False)
        self.assertEqual(result['outcome'],'materialized')
        with self.assertRaises(b0.ProviderRefusal):
            registry._resident_transition(stop_record,request)
        foreign=dict(request,lease_id='99'*16)
        with self.assertRaises(b0.ProviderRefusal):
            registry._resident_transition(stop_record,foreign)
        wrong_epoch=dict(request,authority_epoch='foreign')
        with self.assertRaises(b0.ProviderRefusal):
            registry._resident_transition(stop_record,wrong_epoch)
        stop_scope['state']='committed'
        with self.assertRaises(b0.ProviderRefusal):
            registry._scope(lease['id'],stop_digest)

    def test_exact_registry_capacity_preserves_all_pending_stop_children(self):
        registry=object.__new__(m2.NativeRegistry); registry.operations={}; registry.delegates={}
        for i in range(3):
            op=dict(descriptor=dict(delegates=[dict(role='normal')]*339+[dict(role='stop')]),
                delegates={},pending_children=set(range(340)))
            registry.operations[str(i)]=op
        self.assertEqual(registry._reserved_cardinality(),1024)
        with self.assertRaises(b0.ProviderRefusal):
            registry._prebook_cardinality(1)
        # Late STOP uses the promised slot even at the exact cap.
        operation=registry.operations['0']; record=dict(id='11'*16)
        registry._register_delegate(operation,339,record)
        self.assertEqual(registry._reserved_cardinality(),1024)
        self.assertNotIn(339,operation['pending_children'])
        with self.assertRaises(b0.ProviderRefusal):
            registry._register_delegate(operation,339,record)

    def test_readonly_positive_history_and_kernel_baseline_allow_release_proof(self):
        from types import SimpleNamespace
        registry,lease,scope,record,obj,fid=transition_fixture()
        info=SimpleNamespace(st_dev=1,st_ino=2,st_mode=0o40700,st_size=4,st_blocks=1,
            st_nlink=2,st_mtime_ns=5,st_ctime_ns=6)
        root=slot(0,'directory','inherit_fd')
        root.update(name=None,access='directory',state='existing',create_mode=None)
        record['grant']['files']=[root]
        record['baselines']={root['file_id']:m2.object_facts(info)}
        record['observed']['files']=[dict(state=3,opens_actual=1,syscalls_actual=2,write_actual=0)]
        lease['profile']['root_indices']={root['file_id']:0}
        registry.site=SimpleNamespace(custody=SimpleNamespace(directory_fds=(90,)))
        with patch.object(m2.os,'fstat',return_value=info):
            self.assertTrue(registry._prove_no_mutation(lease))
            # Same zero write bytes: any admitted metadata mutation is unproved.
            for op in ('chmod','rename_from','rename_to','unlink','mkdir','temp','write'):
                root['allowed_ops']=['open','stat','close',op]
                with self.subTest(op=op),self.assertRaises(b0.ProviderRefusal):
                    registry._prove_no_mutation(lease)
            root['allowed_ops']=['open','stat','close']
            root['acquire']='create_exclusive'
            with self.assertRaises(b0.ProviderRefusal):
                registry._prove_no_mutation(lease)
            root['acquire']='inherit_fd'
            record['observed']['files'][0]['opens_actual']=0
            with self.assertRaises(b0.ProviderRefusal):
                registry._prove_no_mutation(lease)

    def test_unobserved_or_changed_metadata_cannot_release(self):
        from types import SimpleNamespace
        registry,lease,scope,record,obj,fid=transition_fixture()
        info=SimpleNamespace(st_dev=1,st_ino=2,st_mode=0o40700,st_size=4,st_blocks=1,
            st_nlink=2,st_mtime_ns=5,st_ctime_ns=6)
        row=slot(0,'directory','inherit_fd'); row.update(name=None,access='directory',create_mode=None)
        record['grant']['files']=[row]; record['baselines']={row['file_id']:m2.object_facts(info)}
        record['observed']['files']=[dict(state=3,opens_actual=1,syscalls_actual=2,write_actual=0)]
        lease['profile']['root_indices']={row['file_id']:0}
        registry.site=SimpleNamespace(custody=SimpleNamespace(directory_fds=(90,)))
        info.st_mode=0o40755
        with patch.object(m2.os,'fstat',return_value=info),self.assertRaises(b0.ProviderRefusal):
            registry._prove_no_mutation(lease)

    def test_only_retained_zero_file_root_bootstrap_can_precede_capture(self):
        registry=object.__new__(m2.NativeRegistry)
        bootstrap=dict(kind='bootstrap',role='normal',files=[],scope_digest='aa'*32,payload_binding_digest=None)
        op=dict(id='11'*16,descriptor=dict(capture_index=1,delegates=[bootstrap,dict(kind='capture_publication')]),
                lease=dict(descriptor_digest='aa'*32))
        registry.operations={op['id']:op}
        self.assertTrue(registry._before_capture_bootstrap(op,0))
        for key,value in (('kind','text'),('files',[{}]),('scope_digest','bb'*32),('role','stop'),
                          ('payload_binding_digest','cc'*32)):
            original=bootstrap[key]; bootstrap[key]=value
            self.assertFalse(registry._before_capture_bootstrap(op,0))
            bootstrap[key]=original
        with self.assertRaises(b0.ProviderRefusal):
            registry._before_capture_bootstrap(dict(op),0)


def rpc_binding():
    from types import SimpleNamespace
    binding=object.__new__(site.SiteNativeBinding)
    binding.custody=SimpleNamespace(owner=site.DescriptorCustody())
    binding.intent=dict(slot_id='slot1',attempt_id='attempt1',nonce='nonce1')
    binding._rpc_sequence=0; binding.primary=None; binding.native=None
    binding.freeze_normal=MagicMock()
    return binding


def rpc_bytes(opcode='issuer',args=None):
    return site.canonical(dict(sequence=0,opcode=opcode,slot='slot1',attempt='attempt1',nonce='nonce1',
                               args={} if args is None else args))


def ancillary_rights(fds=(90,91),pid=27):
    return [(site.socket.SOL_SOCKET,site.socket.SCM_CREDENTIALS,struct.pack('3i',pid,3000,3000)),
            (site.socket.SOL_SOCKET,site.socket.SCM_RIGHTS,struct.pack('i'*len(fds),*fds))]


def capture_rpc_fixture():
    from types import SimpleNamespace
    import stat
    binding=rpc_binding(); registry=object.__new__(m2.NativeRegistry)
    binding.native=registry; binding.capsule=SimpleNamespace(digest='11'*32)
    binding.worker=b0.ProcessIdentity(27,28,3000,'boot',(1,2),3,4)
    registry.site=binding; registry.capsule=binding.capsule; registry.owner=binding.custody.owner
    registry._fresh=MagicMock(); registry.dispatch_cost=MagicMock()
    registry._id=MagicMock(side_effect=b0.ProviderRefusal('late locator failure'))
    registry.config=dict(storage=[dict(id='memory',kind='memory_snapshot')],scalar_codes={})
    sid='a1'*16; mid='a2'*16; opid='a3'*16
    raw=bytearray(130)
    struct.pack_into('<8sII5Q',raw,0,b'QCLB0MD1',1,128,130,1,1,0,0)
    raw[56:88]=hashlib.sha256(b'\0').digest(); raw[88:120]=hashlib.sha256(b'\0').digest()
    op=dict(id=opid,descriptor=dict(digest='22'*32,shape_type_bytes=[]),capture=None,delegates={},sequence=1)
    observed=dict(files=[dict(file_id=sid,state=3,dev=1,ino=100,logical_extent=0,allocated_bytes=0),
                         dict(file_id=mid,state=3,dev=1,ino=101,logical_extent=130,allocated_bytes=512)])
    record=dict(operation=op,state='settled',observed=observed); op['delegates'][0]=record
    proof=dict(destination_child_index=1,snapshot_file_ids=[sid],metadata_file_id=mid,logical_bytes=130,allocated_bytes=512)
    registry.operations={opid:op}; registry.transfers={'token':dict(record=record,transfer=proof,state='pending')}
    args=dict(digest=binding.capsule.digest,operation_id=opid,descriptor_digest='22'*32,
        content_digest=m2.sha(b'\0'),publication_digest=m2.sha(b'\0'),
        snapshots=[dict(fd_index=0,bytes=0,shape=[0],dtype='UInt8',offset=0)],
        metadata=dict(fd_index=1,bytes=130,sha256=m2.sha(raw),format='qcl.source3.capture-metadata.v1'))
    infos={90:SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=3000,st_size=0,st_blocks=0,st_dev=1,st_ino=100),
           91:SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=3000,st_size=130,st_blocks=1,st_dev=1,st_ino=101)}
    return binding,registry,args,bytes(raw),infos


class ReceiveRightsRegression(unittest.TestCase):
    def test_bad_flags_credentials_ancillary_and_opcode_close_each_installed_right_once(self):
        cases=[(site.socket.MSG_CTRUNC,ancillary_rights(),rpc_bytes()),
               (0,ancillary_rights(pid=28),rpc_bytes()),
               (0,[ancillary_rights()[1],(site.socket.SOL_SOCKET,65535,b'bad')],rpc_bytes()),
               (0,ancillary_rights(),rpc_bytes('unknown_opcode')),
               (0,ancillary_rights(),b'{')]
        for flags,ancillary,raw in cases:
            binding=rpc_binding()
            with self.subTest(flags=flags,raw=raw),patch.object(site.os,'close') as close:
                try:
                    binding._receive_rpc(raw,ancillary,flags,27)
                except b0.ProviderRefusal:
                    pass
                self.assertEqual(sorted(call.args[0] for call in close.call_args_list),[90,91])
                self.assertEqual(binding.custody.owner.entries,{})
                self.assertEqual(binding.custody.owner.resources,{})

    def test_invalid_right_close_uncertainty_retains_only_primitive_owner_no_retry(self):
        binding=rpc_binding()
        with patch.object(site.os,'close',side_effect=OSError('close uncertain')) as close:
            with self.assertRaises(b0.ProviderRefusal):
                binding._receive_rpc(rpc_bytes(),ancillary_rights(),site.socket.MSG_CTRUNC,27)
        self.assertEqual(sorted(call.args[0] for call in close.call_args_list),[90,91])
        self.assertEqual(binding.custody.owner.entries,{})
        self.assertEqual(binding.custody.owner.state,'retained_unknown')
        primitive=next(iter(binding.custody.owner.resources.values()))
        self.assertTrue(all(row['state']=='close_unknown' for row in primitive.entries.values()))
        with patch.object(site.os,'close') as retry:
            primitive.close()
        retry.assert_not_called()

    def test_nonmember_or_extra_capture_rights_close_without_long_lived_adoption(self):
        for extra,wrong_inode in ((True,False),(False,True)):
            binding,registry,args,raw,infos=capture_rpc_fixture()
            if wrong_inode:
                infos[91].st_ino=999
            fds=(90,91,92) if extra else (90,91)
            with patch.object(m2.os,'fstat',side_effect=lambda fd:infos[fd]), \
                 patch.object(m2.fcntl,'fcntl',side_effect=lambda _fd,op:0 if op==m2.fcntl.F_GETFL else m2._SEALS), \
                 patch.object(m2.os,'pread',return_value=raw),patch.object(site.os,'close') as close:
                reply=binding._receive_rpc(rpc_bytes('verify_capture',args),ancillary_rights(fds),0,27)
            self.assertIsNotNone(reply['error'])
            self.assertEqual(sorted(call.args[0] for call in close.call_args_list),list(fds))
            self.assertEqual(registry.owner.entries,{})

    def test_only_fully_validated_registered_capture_survives_late_failure(self):
        binding,registry,args,raw,infos=capture_rpc_fixture()
        with patch.object(m2.os,'fstat',side_effect=lambda fd:infos[fd]), \
             patch.object(m2.fcntl,'fcntl',side_effect=lambda _fd,op:0 if op==m2.fcntl.F_GETFL else m2._SEALS), \
             patch.object(m2.os,'pread',return_value=raw),patch.object(site.os,'close') as close:
            reply=binding._receive_rpc(rpc_bytes('verify_capture',args),ancillary_rights(),0,27)
        self.assertEqual(reply['error'],'late locator failure')
        close.assert_not_called()
        self.assertEqual(set(registry.owner.entries),{90,91})
        self.assertTrue(all(row['state']=='owned' for row in registry.owner.entries.values()))
        self.assertEqual(next(iter(registry.transfers.values()))['state'],'registered')


class InodeLifetimeRegression(unittest.TestCase):
    def test_retired_old_inode_cannot_hide_new_tombstone_growth_before_materialize(self):
        from types import SimpleNamespace
        registry,lease,scope,record,_old_fixture,fid=transition_fixture()
        receipt_id=lease['operation']['descriptor']['files'][2]['file_id']
        parent_id=lease['operation']['descriptor']['files'][0]['file_id']
        registry.site=SimpleNamespace(primary=None,worker=SimpleNamespace(boot='boot1'),
                                      issuer=SimpleNamespace(mount_namespace=3))
        old=dict(reference='lifetime-A',generation=1,mount_id=9,dev=1,ino=2,fd=70,
            extent=4,allocated=512,accounted=(4,512,1),baseline_logical=0,retired=True,storage_id='memory')
        new=dict(reference='lifetime-B',generation=2,mount_id=9,dev=1,ino=2,fd=91,
            extent=4,allocated=512,accounted=(0,0,0),baseline_logical=0,retired=False,storage_id='memory')
        receipt=dict(reference='receipt',fd=92,dev=3,ino=4,extent=4,allocated=0,
            accounted=(4,0,1),baseline_logical=4,retired=False,storage_id='memory')
        registry.objects={'old-A':old,'receipt':receipt}
        # A belongs to a distinct old grant/slot lifetime; current B has no S
        # observation yet despite identical numeric dev/ino and ordinal1.
        prior_record=dict(id='77'*16,operation=dict(id='88'*16),grant=dict(grant_sequence=1),
                          objects={'99'*16:old},object_bindings={})
        prior_row=dict(file_id='99'*16,dev=1,ino=2,opens_actual=1)
        prior_record['object_bindings'][prior_row['file_id']]=registry._object_binding(prior_record,prior_row,old)
        row=dict(file_id=fid,state=3,dev=1,ino=2,opens_actual=1,logical_extent=4,allocated_bytes=512)
        record['observed']['files']=[row,dict(file_id=receipt_id,state=2)]
        record['objects']={}; record['object_bindings']={}; record['grant']['grant_sequence']=9
        record['grant']['files']=lease['operation']['descriptor']['files'][1:]
        scope['file_ids']={fid}; scope['remaining']=(10,1024,2)
        scope['inventory']['physical']=1024; lease['native_remaining']=(10,1024,2)
        registry.config['storage'][0]['E']=[4,0,1]
        lease['profile']['commit_files']=[receipt_id]
        registry.config['storage'][0]['A']=[2048,2048,2048]
        registry.config['storage'][0]['H']=[2048,2048,2048]
        registry._memory=lambda:(2048,512)
        def reobserve(_lease,key,allow_tombstone=False):
            if key==parent_id:
                return dict(fd=90)
            if key==receipt_id:
                return receipt
            if not allow_tombstone:
                raise b0.ProviderRefusal('terminal namespace slot requires current lifetime evidence')
            # Synthetic actual approved-path reopen: new current object, not old
            # A's numeric match. Production _observe_file supplies this binding.
            record['objects'][fid]=new
            record['object_bindings'][fid]=registry._object_binding(record,row,new)
            registry.objects['new-B']=new
            return new
        registry._observe_file=MagicMock(side_effect=reobserve)
        registry._file_native_row=MagicMock(return_value=(record,row))
        info=SimpleNamespace(st_dev=1,st_ino=2,st_size=4,st_blocks=1)
        tree=lambda:dict(descriptor=scope['inventory']['digest'],remaining=list(scope['remaining']),children=[])
        commit=lambda:resident_request(lease,scope,'commit',tree=tree(),
            verified=dict(file_id=receipt_id,sha256=m2.sha(b'data')))
        with patch.object(m2.os,'pread',return_value=b'data'),patch.object(m2.os,'fsync'), \
             patch.object(m2.os,'fstat',side_effect=lambda fd:info if fd==91 else SimpleNamespace(st_dev=3,st_ino=4)):
            with self.assertRaisesRegex(b0.ProviderRefusal,'unmaterialized'):
                registry._resident_transition(record,commit())
            self.assertEqual(lease['native_remaining'],(10,1024,2))
            self.assertEqual(new['accounted'],(0,0,0))
            self.assertIs(prior_record['objects'][prior_row['file_id']],old)
            self.assertTrue(old['retired'])
            before=registry._materialization(lease,scope)
            self.assertEqual(before['delta'],(4,512,1))
            request=resident_request(lease,scope,'materialize',resident_sequence=1,delta=[4,512,1],
                                     object_inventory_ref=before['reference'])
            registry._resident_transition(record,request)
            registry._resident_transition(record,commit())
        self.assertEqual(new['accounted'],(4,512,1))
        self.assertEqual(lease['native_remaining'],(0,0,0))
        self.assertEqual(registry._capacity(registry.config['storage'][0])[0][0],8)
        self.assertIs(registry.objects['old-A'],old)

    def test_only_exact_current_retired_slot_acquisition_can_skip(self):
        from types import SimpleNamespace
        registry,lease,scope,record,obj,fid=transition_fixture()
        registry.site=SimpleNamespace(worker=SimpleNamespace(boot='boot1'),issuer=SimpleNamespace(mount_namespace=3))
        retired=dict(reference='current-retired',generation=4,mount_id=9,dev=1,ino=2,retired=True)
        row=dict(file_id=fid,state=3,dev=1,ino=2,opens_actual=1)
        record['observed']['files']=[row]; record['grant']['files']=[dict(file_id=fid,kind='regular')]
        record['grant']['grant_sequence']=3; record['objects']={fid:retired}
        record['object_bindings']={fid:registry._object_binding(record,row,retired)}
        registry._observe_file=MagicMock(side_effect=b0.ProviderRefusal('current lifetime UNKNOWN'))
        self.assertEqual(registry._reconcile_commit(lease),())
        registry._observe_file.assert_not_called()
        for key,value in (('acquisitions',2),('record_id','77'*16),('operation_id','88'*16),
                          ('grant_sequence',4),('file_id','99'*16),('generation',5),('mount_id',10),
                          ('namespace',4),('boot','foreign'),('object_ref','different-lifetime')):
            binding=record['object_bindings'][fid]; original=binding[key]; binding[key]=value
            with self.subTest(key=key),self.assertRaisesRegex(b0.ProviderRefusal,'UNKNOWN'):
                registry._reconcile_commit(lease)
            binding[key]=original
        # Actual re-acquisition in this same grant invalidates an old binding.
        row['opens_actual']=2
        with self.assertRaisesRegex(b0.ProviderRefusal,'UNKNOWN'):
            registry._reconcile_commit(lease)


if __name__=='__main__':
    unittest.main()
