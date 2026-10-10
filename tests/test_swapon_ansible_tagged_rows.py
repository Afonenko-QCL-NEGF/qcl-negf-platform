"""Exact declared Ansible YAML-tagged scalars through the owning filter loader."""
import json
from pathlib import Path
import pytest

RAW = "/dev/dm-0 partition 8589930496 0 -1 a798c08a-1f3f-40f6-bd9a-47a316f90fe5 \n"
EXPECTED = {"swaps": [{"name": "/dev/dm-0", "type": "partition", "size": 8589930496, "used": 0, "prio": -1}]}

@pytest.fixture
def native_filter(ansible_test_environment):
    from ansible.parsing.dataloader import DataLoader
    from ansible.plugins.loader import filter_loader
    from ansible.module_utils._internal._datatag import _AnsibleTaggedInt, _AnsibleTaggedStr
    directory = Path(__file__).resolve().parents[1]
    filter_loader.add_directory(str(directory / "ansible/filter_plugins"))
    plugin = filter_loader.get("qcl_swapon_raw")
    assert plugin is not None
    function = plugin.j2_function
    assert Path(function.__code__.co_filename).resolve() == (directory / "ops/host_swap_file_probe.py").resolve()
    return DataLoader(), function, _AnsibleTaggedInt, _AnsibleTaggedStr

def test_native_yaml_tagged_scalars_reach_real_filter(native_filter):
    loader, function, integer, string = native_filter
    data = loader.load("maximum_swap_rows: 16\nstdout: " + json.dumps(RAW) + "\n")
    assert type(data["maximum_swap_rows"]) is integer
    assert type(data["stdout"]) is string
    assert function(data["stdout"], data["maximum_swap_rows"]) == EXPECTED
    print(json.dumps({"native_tagged_boundary": True, "engine": "2.21.1", "integer_type": integer.__name__, "string_type": string.__name__, "filter_source": function.__code__.co_filename}, sort_keys=True))

def test_native_yaml_tagged_inputs_keep_rejections(native_filter):
    loader, function, integer, string = native_filter
    data = loader.load("maximum_swap_rows: 16\nstdout: " + json.dumps(RAW.replace("8589930496", "8G")) + "\nbool_bound: true\n")
    assert type(data["maximum_swap_rows"]) is integer and type(data["stdout"]) is string
    with pytest.raises(ValueError):
        function(data["stdout"], data["maximum_swap_rows"])
    with pytest.raises(ValueError):
        function(RAW, data["bool_bound"])
