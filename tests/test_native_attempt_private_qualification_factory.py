"""Actual server/socket auth and framed ordinary owner; no native dispatch or ready stub."""
import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import struct
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops'))
from test_native_attempt import PeerSources, MemoryConnection, request, limits


def ingress(tmp_path,monkeypatch,*,factory='refuse',fault=None):
    import native_attempt as native
    events=[];budget=native.Operation(limits());peer=PeerSources();server='qcl-negf-native-attempt@fixture.service'
    policy=dict(peer.policy,private_root=str(tmp_path/'private'),limits=budget.limits,
        server_unit_prefix='qcl-negf-native-attempt@',release_runtime='/protected/release',jobs_root=str(native.engine.GATE.parent))
    class Source(PeerSources):
        def qualify(self):events.append('qualify')
        def process(self,pid):
            if pid==os.getpid():return dict(pid=pid,ppid=1,start_ticks=2,uids=[0]*4,state='S',comm='python',
                cgroup='/system.slice/'+server,executable='/nix/store/root-python')
            events.append('peer-process');return super().process(pid)
        def unit(self,name):
            if name==server:return dict(InvocationID='b'*32,MainPID=str(os.getpid()),ActiveState='active',
                ControlGroup='/system.slice/'+server,MemoryMax='134217728',RuntimeMaxUSec='90s')
            return super().unit(name)
        def preflight(self,launch,budget,*,calcjob_uuid,action):
            events.append('ordinary-preflight')
            native_sources_admission(self,launch,calcjob_uuid=calcjob_uuid,
                actor=dict(calcjob_uuid=calcjob_uuid,action='submit',launch=launch,execution_sha256=launch['files']['native_execution']['sha256']),fixture=None)
            raise AssertionError('no fixture authorizes a body')
    source=Source();source.policy=policy;source.budget=budget;source.fault=fault
    source.qualification['unit_origins']['server']=dict(executable='/nix/store/root-python')
    native_sources_admission=native.NativeSources._submit_admission
    if factory!='absent':
        def select():
            assert source._caller['pid']==456 and source._server_unit==server
            events.append('factory')
            if factory=='none':return None
            class Refusal:
                def submit_permit(self,*args,**kwargs):
                    events.append('collaborator-refused');raise native.Hold('actual_qualification_source_missing')
            return Refusal()
        source.qualification_jobs_owner=select
    document=request();wire=struct.pack('!I',len(native.encoded(document)))+native.encoded(document)
    class Connection(MemoryConnection):
        def __init__(self):super().__init__(wire);self.written=b''
        def getsockopt(self,*args):return struct.pack('3i',456,999 if fault=='uid'else 3000,3000)
        def sendall(self,raw):self.written+=raw
    connection=Connection()
    @contextmanager
    def admission(path):yield
    monkeypatch.setattr(native,'_bootstrap_operation',lambda:budget)
    monkeypatch.setattr(native,'_load_policy',lambda *args:policy)
    monkeypatch.setattr(native,'NativeSources',lambda *args:source)
    monkeypatch.setattr(native,'protected_read',lambda *args:native.encoded(dict(release_id='release-1',code_uuid=document['launch']['code_uuid'],ready=False)))
    monkeypatch.setattr(native.engine,'admission_reader',admission)
    monkeypatch.setattr(budget,'read',lambda *args:native.encoded(dict(release_id='release-1',open=False)))
    return native,source,connection,events


def result(native,connection):
    size=struct.unpack('!I',connection.written[:4])[0]
    assert len(connection.written)==size+4
    return json.loads(connection.written[4:])


def test_controller_factory_is_bound_after_real_socket_auth_before_ordinary_closed_preflight(tmp_path,monkeypatch):
    native,source,connection,events=ingress(tmp_path,monkeypatch)
    native.handle_connection(connection)
    assert result(native,connection)['reason']=='actual_qualification_source_missing'
    assert events.index('factory')>events.index('peer-process')
    assert events.index('factory')<events.index('ordinary-preflight')<events.index('collaborator-refused')
    assert not (tmp_path/'private'/'attempts').exists()


@pytest.mark.parametrize('fault',['uid','api','shell'])
def test_socket_auth_refusal_never_constructs_private_owner(tmp_path,monkeypatch,fault):
    native,source,connection,events=ingress(tmp_path,monkeypatch,fault=fault)
    native.handle_connection(connection)
    assert result(native,connection)['state']=='hold'
    assert 'factory'not in events and 'ordinary-preflight'not in events
    assert not (tmp_path/'private').exists()


@pytest.mark.parametrize('factory',['absent','none'])
def test_missing_controller_factory_keeps_original_closed_ordinary_behavior(tmp_path,monkeypatch,factory):
    native,source,connection,events=ingress(tmp_path,monkeypatch,factory=factory)
    native.handle_connection(connection)
    assert result(native,connection)['reason']=='native_admission_closed'
    assert 'collaborator-refused'not in events and not (tmp_path/'private'/'attempts').exists()
    assert ('factory'in events)==(factory=='none')
