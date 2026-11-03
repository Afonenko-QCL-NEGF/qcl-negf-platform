"""Controller integration of measured native/physical domains; synthetic Source/L only."""
from dataclasses import asdict, replace
from pathlib import Path
import os
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ops'))
import host_resource_operations as m
from host_resource_capacity import decode_capacity_qualification_v2
from host_resource_qualification_observations import MeasuredBackendQualification, MeasuredGuestEvidence


def measured_setup(tmp_path, *, measured=True, reserve=64, gap=32):
    policy = m.validate_host_resource_policy({
        'schema': 'qcl.host-resource-policy.v1', 'host_id': 'host', 'owner_id': 'owner',
        'physical_ram_bytes': 4096, 'capacity_evidence_ref': 'capacity',
        'reserves': dict(host_services_bytes=128, control_plane_bytes=64, safety_bytes=64,
                         foreign_max_bytes=256, evidence_ref='reserves'),
        'owned_pool': dict(capacity_bytes=3584, agreement_ref='agreement', enforceable=True,
                           foreign_growth_bounded=True, active_grants_protected=True),
        'active_grant': dict(mechanism='qualified_dynamic', qualification_ref='qualification'),
        'timeouts': dict(request_seconds=10, grow_seconds=30, shrink_seconds=30, reconcile_seconds=60),
        'vms': [dict(vm_id='vm', owner_id='owner', resident=True, minimum_bytes=128,
                     startup_bytes=256, maximum_bytes=2048, overhead_bytes=64,
                     overhead_evidence_ref='overhead', cpu_weight=100, memory_weight=100)],
    })
    binding = m.RuntimeBinding('vm', 'native', 'pid-birth', 'guest-boot', 'image', 'guest-kernel',
                               'host-kernel', 'qemu', 'backend', 'readback', 'config')
    digest = m.policy_digest(policy)
    profile = dict(schema='qcl.host-resource-capacity-qualification.v2', host_id='host',
                   owner_id='owner', policy_sha256=digest, binding=asdict(binding),
                   source_graph_sha256='b' * 64, report_sha256='c' * 64,
                   measurement=dict(state='measured', scope='synthetic explicit finite scope',
                                    evidence_sha256='d' * 64, mapping_evidence_sha256='e' * 64,
                                    observed_os_bytes=reserve - 16, safety_allowance_bytes=16,
                                    os_reserve_bytes=reserve, native_gap_bound_bytes=gap,
                                    maximum_guest_total_bytes=2016, native_maximum_bytes=2048))
    capacity = decode_capacity_qualification_v2(profile, expected_host_id='host',
        expected_owner_id='owner', expected_policy_sha256=digest, expected_binding=asdict(binding),
        expected_source_graph_sha256='b' * 64, expected_report_sha256='c' * 64,
        expected_native_maximum_bytes=2048)
    base = m.BackendQualification('host', 'owner', binding, digest, 'qualification', True, True, True, True)
    qualification = (MeasuredBackendQualification(**vars(base), capacity=capacity,
                       supported_targets=tuple(range(128, 2049, 64))) if measured else base)
    evidence = m.HostEvidence('host', 'owner', 'host-boot', digest, 100, 4096, 256,
        'capacity', 'agreement', True, True, True, 'synthetic-original', (binding,),
        (qualification,), {'vm': ()})
    store = m.FileReceiptStore(tmp_path / 'state', owner_uid=os.getuid())

    class Backend:
        quantum_bytes = 64
        row = m.VMReadback('vm', 'native', 'pid-birth', 'config', 'revision-1', 256, 256, True)

        def readback(self, vm_id):
            assert vm_id == 'vm'
            return self.row

        def resize(self, vm_id, target_bytes, before, timeout_seconds):
            self.row = replace(before, configured_bytes=target_bytes, assigned_bytes=target_bytes,
                               revision=before.revision + '-next')
            return self.row

    backend = Backend()
    controller = m.HostResourceController(policy, store, backend, clock=lambda: 100)
    controller.bootstrap((m.ResidentGrant('host', 'vm', 'owner', 256, 128, 'idle'),), evidence)
    return controller, backend, store, evidence, capacity


def admission(capacity, workload, demand, *, total, available, live=(), commitments=None):
    return MeasuredGuestEvidence('vm', 'guest-boot', workload, 100, total, available,
        capacity.os_reserve_bytes, demand, 1952, True, live, capacity,
        commitments or ((workload, demand, demand),))


def test_dynamic_bootstrap_refuses_legacy_positive_flags(tmp_path):
    with pytest.raises(m.ResourceError, match='qualification'):
        measured_setup(tmp_path, measured=False)


def test_measured_physical_total_below_native_floor_and_fixed_maximum_slurm_are_valid(tmp_path):
    c, b, store, e, capacity = measured_setup(tmp_path)
    request = m.ResourceRequest('request', 'host', 'vm', 'owner', 321, 'work')
    assert c.request(request, e).target_bytes == 512
    assert c.grow('request', e).phase == 'GUEST_ADMIT'
    # Native N=128+321=449; physical P=64+321=385; T=480 < G=512.
    assert c.admit('request', admission(capacity, 'work', 321, total=480, available=400), e).phase == 'RUN'


@pytest.mark.parametrize('reserve,gap', [(112, 32), (64, 80)])
def test_must_cover_measured_reserve_and_gap_before_bootstrap_ready(tmp_path, reserve, gap):
    with pytest.raises(m.ResourceError, match='qualification'):
        measured_setup(tmp_path, reserve=reserve, gap=gap)


@pytest.mark.parametrize('fault', ['missing-other', 'physical-shortfall', 'limit-over-demand'])
def test_second_admission_protects_every_authorized_demand(tmp_path, fault):
    c, b, store, e, capacity = measured_setup(tmp_path)
    c.request(m.ResourceRequest('r1', 'host', 'vm', 'owner', 100, 'w1'), e)
    c.grow('r1', e)
    c.admit('r1', admission(capacity, 'w1', 100, total=224, available=150), e)
    e.live_workloads['vm'] = ('w1',)
    c.request(m.ResourceRequest('r2', 'host', 'vm', 'owner', 50, 'w2'), e)
    c.grow('r2', e)
    commitments = (('w1', 100, 100), ('w2', 50, 50))
    g = admission(capacity, 'w2', 50, total=288, available=150,
                  live=('w1',), commitments=commitments)
    if fault == 'missing-other':
        g = replace(g, commitments=(commitments[1],))
    elif fault == 'physical-shortfall':
        g = replace(g, total_bytes=200)
    else:
        g = replace(g, commitments=(('w1', 100, 101), commitments[1]))
    before = store.state_path.read_bytes()
    with pytest.raises(m.ResourceError):
        c.admit('r2', g, e)
    assert store.state_path.read_bytes() == before
    assert c.admit('r2', admission(capacity, 'w2', 50, total=288, available=150,
                   live=('w1',), commitments=commitments), e).phase == 'RUN'
