"""Pure genuine util-linux rows; no swapon, Ansible, Nix or server execution."""
import importlib.util
from pathlib import Path
import pytest
P=Path(__file__).resolve().parents[1]/"ops/host_swap_file_probe.py"
s=importlib.util.spec_from_file_location("probe",P);probe=importlib.util.module_from_spec(s);s.loader.exec_module(probe)
RAW="/dev/dm-0 partition 8589930496 0 -1 a798c08a-1f3f-40f6-bd9a-47a316f90fe5 \n"
def test_real_old8_raw_empty_label():
    assert probe.normalize_swapon_raw(RAW,16)=={"swaps":[{"name":"/dev/dm-0","type":"partition","size":8589930496,"used":0,"prio":-1}]}
def test_empty_active_table():
    assert probe.normalize_swapon_raw("",16)=={"swaps":[]}
def test_file_active_with_used_and_label():
    row="/srv/final/protected-swap/swapfile file 4294963200 512 -3 33333333-3333-4333-8333-333333333333 protected\n"
    assert probe.normalize_swapon_raw(row,16)=={"swaps":[{"name":"/srv/final/protected-swap/swapfile","type":"file","size":4294963200,"used":512,"prio":-3}]}
@pytest.mark.parametrize("row",[
    "NAME TYPE SIZE USED PRIO UUID LABEL\n", "\n", "  \n",
    "relative partition 1 0 -1 a798c08a-1f3f-40f6-bd9a-47a316f90fe5 \n",
    "/dev/../dm-0 partition 1 0 -1 a798c08a-1f3f-40f6-bd9a-47a316f90fe5 \n",
    "/dev/./dm-0 partition 1 0 -1 a798c08a-1f3f-40f6-bd9a-47a316f90fe5 \n",
    "/dev/dm\\x20zero partition 1 0 -1 a798c08a-1f3f-40f6-bd9a-47a316f90fe5 \n",
    "/dev/dm-0 partition 1 0 -1 \n", "/dev/dm-0 partition 1 0 -1 invalid \n",
    "/dev/dm-0 partition 1 0 -1 00000000-0000-0000-0000-000000000000 \n",
    "/dev/dm-0 partition 1 0 -1 a798c08a-1f3f-40f6-bd9a-47a316f90fe5 bad label\n",
    "/dev/dm-0 partition 1 0 -1 a798c08a-1f3f-40f6-bd9a-47a316f90fe5 bad\\x20label\n",
    "/dev/dm-0 unknown 1 0 -1 a798c08a-1f3f-40f6-bd9a-47a316f90fe5 \n",
    "/dev/dm-0 partition 0 0 -1 a798c08a-1f3f-40f6-bd9a-47a316f90fe5 \n",
    "/dev/dm-0 partition 1 2 -1 a798c08a-1f3f-40f6-bd9a-47a316f90fe5 \n",
    "/dev/dm-0 partition 1 -1 -1 a798c08a-1f3f-40f6-bd9a-47a316f90fe5 \n",
    "/dev/dm-0 partition 1K 0 -1 a798c08a-1f3f-40f6-bd9a-47a316f90fe5 \n",
    "/dev/dm-0 partition 1 0 1.0 a798c08a-1f3f-40f6-bd9a-47a316f90fe5 \n",
    "/dev/dm-0 partition 9223372036854775808 0 -1 a798c08a-1f3f-40f6-bd9a-47a316f90fe5 \n",
    "/dev/dm-0 partition 1 0 -1 a798c08a-1f3f-40f6-bd9a-47a316f90fe5 \r\n",
])
def test_malformed_rows_refuse(row):
    with pytest.raises(ValueError):probe.normalize_swapon_raw(row,16)
def test_duplicate_names_refuse():
    with pytest.raises(ValueError):probe.normalize_swapon_raw(RAW+RAW,16)
def test_row_and_byte_bounds():
    with pytest.raises(ValueError):probe.normalize_swapon_raw(RAW,0)
    with pytest.raises(ValueError):probe.normalize_swapon_raw(RAW,True)
    with pytest.raises(ValueError):probe.normalize_swapon_raw("x"*65537,16)


def test_real_filter_exports_strict_parser():
    source=Path(__file__).resolve().parents[1]/"ansible/filter_plugins/host_swap_rows.py"
    spec=importlib.util.spec_from_file_location("swap_filter",source);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    parser=module.FilterModule().filters()["qcl_swapon_raw"]
    assert parser(RAW,16)=={"swaps":[{"name":"/dev/dm-0","type":"partition","size":8589930496,"used":0,"prio":-1}]}
    with pytest.raises(ValueError):parser(RAW.replace("8589930496","8G"),16)


def test_all_real_playbook_queries_choose_supported_exact_columns():
    import json
    import yaml
    from jinja2 import Environment,StrictUndefined
    source=Path(__file__).resolve().parents[1]/"ansible/proxmox-host-swap.yml"
    play=yaml.safe_load(source.read_text())[0]
    env=Environment(undefined=StrictUndefined);env.filters["to_json"]=json.dumps
    seen=[]
    def walk(items):
        for task in items:
            command=task.get("ansible.builtin.command",{})
            for arg in command.get("argv",[]):
                if isinstance(arg,str) and "h.tools.swapon" in arg:
                    argv=json.loads(env.from_string(arg).render(h={"tools":{"swapon":"/usr/sbin/swapon"}}))
                    assert argv==["/usr/sbin/swapon","--show=NAME,TYPE,SIZE,USED,PRIO,UUID,LABEL","--raw","--noheadings","--bytes"]
                    seen.append(argv)
            for branch in ("block","rescue","always"):
                walk(task.get(branch,[]))
    walk(play["tasks"])
    assert len(seen)==5
