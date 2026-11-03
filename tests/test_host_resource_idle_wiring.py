"""Source/L assembly; every backend and user identity is a test fixture."""
import pytest
from test_host_resource_qualification_runtime import idle


def test_installed_source_adapter_refuses_absent_runtime():
    import host_resource_native_cleanup as native
    from host_resource_operations import ResourceError
    source = object.__new__(native.NativeCleanupSources)
    with pytest.raises(ResourceError) as failure:
        source.calibration_guard({}, {}, None, 128, case_name='idle-shrink')
    assert failure.value.code == 'qualification_observations_required'


def test_adapter_uses_actual_protected_runtime_all_resident_guard(idle):
    import host_resource_native_cleanup as native
    import host_resource_qualification_runtime as runtime
    idle.stage()
    source = object.__new__(native.NativeCleanupSources)
    source.idle_qualification_runtime = runtime.open_native_runtime(idle.service)
    assert source.calibration_guard(idle.plan, idle.store.load(), idle.b.rows['vm-a'], 128, case_name='idle-shrink') is None
    assert idle.r.calls == [] and idle.store.state_path.read_bytes() == idle.raw
    idle.pairs['vm-b']['jobs'] = {'foreign-held': {}}
    with pytest.raises(idle.m.ResourceError):
        source.calibration_guard(idle.plan, idle.store.load(), idle.b.rows['vm-a'], 128, case_name='idle-shrink')
    assert idle.r.calls == []


def test_adapter_cannot_bypass_literal_target_scope(idle):
    import host_resource_native_cleanup as native
    import host_resource_qualification_runtime as runtime
    idle.stage()
    source = object.__new__(native.NativeCleanupSources)
    source.idle_qualification_runtime = runtime.open_native_runtime(idle.service)
    with pytest.raises(idle.m.ResourceError):
        source.calibration_guard(idle.plan, idle.store.load(), idle.b.rows['vm-a'], 129, case_name='idle-shrink')
    assert idle.r.calls == []


def test_open_service_reconstructs_and_attaches_same_runtime(tmp_path, monkeypatch):
    import host_resource_service as service
    import host_resource_qualification_runtime as runtime
    from test_host_resource_native_cleanup import test_factory_assembles_dynamic_proofs_without_changing_fixed_prerequisites
    original = runtime.open_native_runtime
    observed = []
    def factory(actual):
        value = original(actual)
        observed.append((actual, value))
        return value
    monkeypatch.setattr(runtime, 'open_native_runtime', factory)
    test_factory_assembles_dynamic_proofs_without_changing_fixed_prerequisites(tmp_path, monkeypatch)
    assert len(observed) == 1
    actual, value = observed[0]
    assert value is None
    assert actual.idle_qualification_runtime is value
    assert actual.provider.native_proofs.sources.idle_qualification_runtime is value
