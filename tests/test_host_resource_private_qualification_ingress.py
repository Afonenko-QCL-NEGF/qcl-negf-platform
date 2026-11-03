"""Structural Source/L assembly: real sudo/closed-gate decoders, synthetic OS facts."""
import base64
import copy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops'))
from test_host_resource_qualification_gate import gate_fixture, process


def ingress(monkeypatch, *, role='guest', factory=True, fault=None):
    import host_resource_service as service
    permit,creator,fields,hook,caller,gate_sources=gate_fixture()
    request=dict(schema='qcl.host-resource-calibration-guard-request.v1',
        release_id=permit['jobs'][next(iter(permit['jobs']))]['launch']['release_id'],
        solver_executable=permit['jobs'][next(iter(permit['jobs']))]['solver_executable'])
    token=base64.urlsafe_b64encode(json.dumps(request,separators=(',',':')).encode()).decode()
    events=[];sudo='/nix/store/sudo/bin/sudo'
    sudo_row=process(60,caller['pid'],350,sudo,0)
    rows={60:sudo_row,caller['pid']:caller}
    if fault=='manual':rows[60]=dict(sudo_row,executable='/nix/store/bash/bin/bash')
    config=dict(schema='qcl.host-resource-service.v1',role=role,client_uid=3000,sudo_executables=[sudo])
    def observed(pid):events.append(('auth-process',pid));return copy.deepcopy(rows[pid])
    class Local:
        def process(self,pid):return observed(pid)
    local=Local()
    if factory is not False:
        def source_factory():
            # Genuine sudo ancestry must have been read twice before this call.
            assert events.count(('auth-process',60))==2 and events.count(('auth-process',caller['pid']))==2
            events.append(('factory',))
            return gate_sources
        local.qualification_gate_sources=source_factory if factory is True else factory
    gate_sources.authenticated_caller=lambda:copy.deepcopy(caller)
    gate_sources.guard_context=lambda actual:dict(permit=permit,original_hook=hook,scheduler=fields)
    root=process(70,60,400,permit['client_root']['executable'],0)
    gate_sources.root_ingress=lambda:dict(process=root,
        argv=permit['client_root']['argv_prefix']+['qualification-gate',token],
        source=dict(path=permit['client_root']['source_path'],sha256=permit['client_root']['source_sha256']))
    monkeypatch.setattr(service.os,'geteuid',lambda:0)
    monkeypatch.setattr(service.os,'getppid',lambda:60)
    monkeypatch.setenv('SUDO_UID','999'if fault=='uid'else'3000')
    monkeypatch.setattr(service,'read_root_json',lambda path:copy.deepcopy(config))
    monkeypatch.setattr(service,'trusted_root_path',lambda path,**kw:Path(path))
    monkeypatch.setattr(service,'LocalSources',lambda cfg,runner:local)
    return service,token,events,creator


def test_private_guest_ingress_authenticates_before_real_closed_gate_decision(monkeypatch):
    service,token,events,creator=ingress(monkeypatch)
    result=service.root_main('client',['qualification-gate',token])
    assert result['purpose']=='calibration'and result['allowed']is True and result['generation']==creator['generation']
    assert events[-1]==('factory',) and 'ready'not in result and 'RUN'not in result
    import host_resource_client
    assert 'qualification-gate'not in host_resource_client.ACTIONS


@pytest.mark.parametrize('fault',['uid','manual'])
def test_rejected_sudo_caller_never_reaches_private_factory(monkeypatch,fault):
    service,token,events,_=ingress(monkeypatch,fault=fault)
    with pytest.raises(service.ResourceError,match='caller'):service.root_main('client',['qualification-gate',token])
    assert ('factory',)not in events


@pytest.mark.parametrize('role',['controller','native_host'])
def test_private_gate_cannot_be_routed_to_another_role(monkeypatch,role):
    service,token,events,_=ingress(monkeypatch,role=role)
    with pytest.raises(service.ResourceError,match='qualification_observations_required'):
        service.root_main('client',['qualification-gate',token])
    assert ('factory',)not in events


@pytest.mark.parametrize('factory',[False,None,42])
def test_missing_or_noncallable_actual_collector_refuses_without_public_fallback(monkeypatch,factory):
    service,token,events,_=ingress(monkeypatch,factory=factory)
    with pytest.raises(service.ResourceError,match='qualification_observations_required'):
        service.root_main('client',['qualification-gate',token])
    assert ('factory',)not in events
