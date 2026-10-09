"""Actual Ansible dispatch with a recording, non-native action boundary.

Removing a guard, changing resize args, restarting an active mount, or formatting
an existing LV must change these independently specified traces/refusals.
Native modules, connections and processes are never executed by the playbook.
"""
import json
import os
from pathlib import Path

import pytest
import yaml

BASE = Path(__file__).resolve().parents[1]
MIB = 1048576


def fixture():
    cfg = {
        "apply": True, "attempt_id": "recovery-2", "original_receipt": "failed-1",
        "host_id": "fixture-host", "boot_id": "fixture-boot",
        "admission": {"fresh": True, "exclusive": True, "receipt": "fixture-live", "expires_at_epoch": 200},
        "tools": {x: "/usr/sbin/" + x for x in ["lvs", "vgs", "pvs", "blkid", "wipefs", "dumpe2fs", "resize2fs", "blockdev"]},
        "root": {"enabled": True, "device": "/dev/test/root", "vg": "test", "lv": "root", "pv_uuid": "pv-id", "vg_uuid": "vg-id", "lv_uuid": "root-id", "fs_uuid": "root-fs", "target_mib": 128, "authorized_cap_mib": 256, "reserve_vg_mib": 16, "supported_ext4_features": ["has_journal", "extent"]},
        "stage": {"enabled": False, "vg": "test", "pool": "pool", "pool_uuid": "pool-id", "vg_uuid": "vg-id", "lv": "images", "lv_uuid": None, "fs_uuid": "stage-fs", "target_mib": 256, "authorized_cap_mib": 512, "path": "/srv/stage", "unit": "srv-stage.mount", "source": "/var/lib/vz", "preparation_data_mib": 8, "preparation_metadata_mib": 2, "protected_data_mib": 16, "protected_metadata_mib": 4, "consumers_complete": True, "namespace_complete": True, "references_complete": True, "reference_receipt": "fixture-live-refs", "volume_references": [], "lifetime": "protected-host-infrastructure"},
    }
    state = {
        "trace": [], "probes": [], "root_bytes": 64*MIB, "blocks": 16384, "block_size": 4096,
        "outside": 128*MIB, "extent": 4*MIB, "bad_probe": False,
        "root_uuid": "root-id", "fs_uuid": "root-fs", "root_type": "ext4",
        "stage_exists": False, "stage_uuid": "stage-id", "stage_fs": None,
        "stage_signature": False, "stage_active": False, "final": False,
        "alias": False, "busy": False, "metadata_percent": 10,
        "foreign": {"foreign_vm": "immutable"}, "original_receipt": "failed-1",
    }
    return cfg, state


CASES = [
    ("root-grow", ["lv-grow", "fs-grow"], False),
    ("fs-only-recovery", ["fs-grow"], False),
    ("root-complete", [], False),
    ("defaults-disabled", [], False),
    ("failed-probe", [], True),
    ("wrong-root-uuid", [], True),
    ("wrong-root-type", [], True),
    ("boolean-size", [], True),
    ("unaligned-size", [], True),
    ("outside-reserve", [], True),
    ("new-stage", ["lv-create", "format", "unit", "disable", "start", "inspect", "stop"], False),
    ("foreign-stage", [], True),
    ("signature-on-new", ["lv-create"], True),
    ("pool-metadata", [], True),
    ("stage-descendant", [], True),
    ("stage-ancestor", [], True),
    ("stage-alias", [], True),
    ("active-resume", ["inspect", "stop"], False),
    ("busy-resume", ["inspect"], True),
    ("final-handoff", [], False),
    ("resume-wrong-fs", [], True),
]


def configure(name, cfg, state):
    if name == "fs-only-recovery": state["root_bytes"] = 128*MIB
    if name == "root-complete": state.update(root_bytes=128*MIB, blocks=32768)
    if name == "defaults-disabled": return {}, state
    if name == "failed-probe": state["bad_probe"] = True
    if name == "wrong-root-uuid": state["root_uuid"] = "foreign"
    if name == "wrong-root-type": state["root_type"] = "xfs"
    if name == "boolean-size": cfg["root"]["target_mib"] = True
    if name == "unaligned-size": cfg["root"]["target_mib"] = 129
    if name == "outside-reserve": state["outside"] = 64*MIB
    if name in [x[0] for x in CASES[10:]]:
        cfg["root"]["enabled"] = False
        cfg["stage"]["enabled"] = True
    if name == "foreign-stage": state["stage_exists"] = True
    if name == "signature-on-new": state["stage_signature"] = True
    if name == "pool-metadata": state["metadata_percent"] = 99
    if name == "stage-descendant": cfg["stage"]["path"] = "/var/lib/vz/stage"
    if name == "stage-ancestor": cfg["stage"]["path"] = "/var/lib"
    if name == "stage-alias": state["alias"] = True
    if name in ("active-resume", "busy-resume", "resume-wrong-fs", "final-handoff"):
        cfg["stage"]["lv_uuid"] = "stage-id"
        state.update(stage_exists=True, stage_fs="stage-fs", stage_active=True)
    if name == "busy-resume": state["busy"] = True
    if name == "resume-wrong-fs": state["stage_fs"] = "wrong-fs"
    if name == "final-handoff": state.update(final=True, stage_active=False)
    return cfg, state


def lvs(state):
    rows = [
        {"lv_name":"root", "vg_name":"test", "lv_uuid":state["root_uuid"], "vg_uuid":"vg-id", "lv_size":str(state["root_bytes"]), "segtype":"linear", "pool_lv":"", "lv_path":"/dev/test/root", "devices":"/dev/test/pv(0)"},
        {"lv_name":"pool", "vg_name":"test", "lv_uuid":"pool-id", "vg_uuid":"vg-id", "lv_size":str(1024*MIB), "segtype":"thin-pool", "pool_lv":"", "lv_path":"/dev/test/pool", "data_percent":"10", "metadata_percent":str(state["metadata_percent"]), "lv_metadata_size":str(64*MIB), "lv_attr":"twi-a-tz--", "lv_health_status":""},
    ]
    if state["stage_exists"]:
        rows.append({"lv_name":"images", "vg_name":"test", "lv_uuid":state["stage_uuid"], "vg_uuid":"vg-id", "lv_size":str(256*MIB), "segtype":"thin", "pool_lv":"pool", "lv_path":"/dev/test/images"})
    return {"report":[{"lv": rows}]}


@pytest.mark.parametrize("name,want,refused", CASES)
def test_actual_ansible_action_contract(name, want, refused, tmp_path, monkeypatch):
    # A bad dispatch must not escape to a real command/module/SSH process.
    monkeypatch.setenv("ANSIBLE_COLLECTIONS_PATH", "/tmp/qcl-host-storage-ansible")
    monkeypatch.setenv("ANSIBLE_LOCAL_TEMP", str(tmp_path/"ansible-local"))
    from ansible import context
    from ansible.module_utils.common.collections import ImmutableDict
    from ansible.parsing.dataloader import DataLoader
    from ansible.inventory.manager import InventoryManager
    from ansible.vars.manager import VariableManager
    from ansible.executor.playbook_executor import PlaybookExecutor
    from ansible.executor.task_executor import TaskExecutor
    from ansible.plugins.action import ActionBase
    from ansible.plugins.loader import init_plugin_loader
    from ansible.plugins.connection.local import Connection
    from ansible.utils.collection_loader import AnsibleCollectionConfig
    if AnsibleCollectionConfig.collection_finder is None:
        init_plugin_loader()
    manifest = Path('/tmp/qcl-host-storage-ansible/ansible_collections/community/general/MANIFEST.json')
    assert json.loads(manifest.read_text())["collection_info"]["version"] == "13.4.0"
    cfg, state = configure(name, *fixture())
    state_path = tmp_path / "recording.json"
    state_path.write_text(json.dumps(state))
    original_handler = TaskExecutor._get_action_handler_with_module_context

    def reject_native(*args, **kwargs):
        raise AssertionError("Native action escaped recording boundary")
    monkeypatch.setattr(Connection, "exec_command", reject_native)
    monkeypatch.setattr(ActionBase, "_execute_module", reject_native)

    class FakeAction(ActionBase):
        def run(self, tmp=None, task_vars=None):
            args = self._templar.template(self._task.args)
            action = self._task.action
            s = json.loads(state_path.read_text())
            out = {"changed": False, "rc": 0, "stdout": ""}
            def trace(kind): s["trace"].append({"kind":kind, "args":dict(args)})
            if action == "ansible.builtin.command":
                argv = args["argv"]
                cmd = Path(argv[0]).name
                if cmd == "nsenter": cmd = "findmnt"
                s["probes"].append(cmd)
                if s["bad_probe"]: return {"failed":True, "rc":2, "stdout":"", "stderr":"fixture probe failed"}
                if cmd == "date": out["stdout"] = "100"
                elif cmd == "cat": out["stdout"] = "fixture-host" if "machine-id" in argv[1] else "fixture-boot"
                elif cmd == "lvs": out["stdout"] = json.dumps(lvs(s))
                elif cmd == "vgs": out["stdout"] = json.dumps({"report":[{"vg":[{"vg_name":"test", "vg_uuid":"vg-id", "vg_free":str(s["outside"]), "vg_extent_size":str(s["extent"])}]}]})
                elif cmd == "pvs": out["stdout"] = json.dumps({"report":[{"pv":[{"pv_name":"/dev/test/pv", "pv_uuid":"pv-id", "vg_uuid":"vg-id"}]}]})
                elif cmd == "findmnt":
                    rows=[{"target":"/", "source":"/dev/test/root", "uuid":s["fs_uuid"], "fstype":s["root_type"], "fsroot":"/"}]
                    if s["stage_active"]: rows.append({"target":cfg["stage"]["path"], "source":"/dev/test/images", "uuid":s["stage_fs"], "fstype":"ext4", "fsroot":"/"})
                    if s["final"]: rows.append({"target":"/var/lib/vz", "source":"/dev/test/images", "uuid":s["stage_fs"], "fstype":"ext4", "fsroot":"/"})
                    if s["alias"]: rows.append({"target":cfg["stage"]["path"], "source":"/dev/test/root", "uuid":"root-fs", "fstype":"ext4", "fsroot":"/var/lib/vz"})
                    out["stdout"] = json.dumps({"filesystems":rows})
                elif cmd == "dumpe2fs": out["stdout"] = f"Filesystem UUID: {s['fs_uuid']}\nFilesystem features: has_journal extent\nBlock count: {s['blocks']}\nBlock size: {s['block_size']}\n"
                elif cmd == "blockdev": out["stdout"] = str(s["root_bytes"])
                elif cmd == "resize2fs":
                    assert argv == ["/usr/sbin/resize2fs", "/dev/test/root", "32768"]
                    assert s["probes"][-5:] == ["lvs", "findmnt", "blockdev", "dumpe2fs", "resize2fs"]
                    trace("fs-grow"); s["blocks"] = 32768
                elif cmd == "realpath": out["stdout"] = argv[-1]
                elif cmd == "stat": out["stdout"] = "directory" if "%F" in argv else ("1:42" if argv[-1] == "/var/lib/vz" or s["alias"] else "1:43")
                elif cmd == "lsns": out["stdout"] = json.dumps({"namespaces":[{"ns":1,"pid":1},{"ns":2,"pid":2}]})
                elif cmd == "find": out["stdout"] = ""
                elif cmd == "blkid":
                    if s["stage_fs"]: out["stdout"] = f"UUID={s['stage_fs']}\nTYPE=ext4\n"
                    else: out["rc"] = 2
                elif cmd == "wipefs": out["stdout"] = json.dumps({"signatures":[{"type":"foreign"}] if s["stage_signature"] else []})
                elif cmd == "fuser": out.update(rc=0 if s["busy"] else 1, stdout="123" if s["busy"] else "")
                elif cmd == "ls": trace("inspect"); out["stdout"] = "lost+found"
                elif cmd == "systemctl": out["stdout"] = "disabled"
                elif cmd == "df": out["stdout"] = "fixture root df"
                else: raise AssertionError(f"Unexpected command {argv}")
            elif action == "community.general.lvol":
                assert args["shrink"] is False and args["force"] is False and args["resizefs"] is False
                assert args["vg"] == "test" and args["state"] == "present"
                assert args["size"] == ("128m" if args["lv"] == "root" else "256m")
                if args["lv"] != "root": assert args["thinpool"] == "pool"
                if args["lv"] == "root": trace("lv-grow"); s["root_bytes"] = 128*MIB; s["outside"] -= 64*MIB
                else: trace("lv-create"); s["stage_exists"] = True
                out["changed"] = True
            elif action == "community.general.filesystem":
                assert not s["stage_fs"] and not args["force"]
                assert args["dev"] == "/dev/test/images" and args["fstype"] == "ext4" and args["uuid"] == "stage-fs"
                trace("format"); s["stage_fs"] = "stage-fs"; out["changed"] = True
            elif action == "ansible.builtin.template":
                from ansible._internal._datatag._tags import TrustedAsTemplate
                text = self._templar.template(TrustedAsTemplate.tag((BASE/"ansible"/args["src"]).read_text()))
                assert "WantedBy" not in text and "What=UUID=stage-fs" in text
                trace("unit"); out["changed"] = True
            elif action == "ansible.builtin.systemd_service":
                assert args["name"] == "srv-stage.mount"
                assert args.get("enabled",False) is False
                assert args.get("state") != "restarted"
                if args.get("state") == "started": trace("start"); s["stage_active"] = True
                elif args.get("state") == "stopped": trace("stop"); s["stage_active"] = False
                else: trace("disable")
            else: raise AssertionError(f"Unexpected action {action}")
            state_path.write_text(json.dumps(s))
            return out

    def handler(executor, templar):
        if executor._task.action in ("ansible.builtin.assert", "ansible.builtin.set_fact", "ansible.builtin.debug"):
            return original_handler(executor, templar)
        return FakeAction(task=executor._task, connection=executor._connection, play_context=executor._play_context, loader=executor._loader, templar=__import__('ansible.template',fromlist=['Templar']).Templar._from_template_engine(templar), shared_loader_obj=executor._shared_loader_obj), None
    monkeypatch.setattr(TaskExecutor, "_get_action_handler_with_module_context", handler)
    context.CLIARGS = ImmutableDict(connection="local", forks=1, become=False, check=False, diff=False, verbosity=0, syntax=False, start_at_task=None, tags=[], skip_tags=[])
    loader = DataLoader()
    loader.set_basedir(str(BASE/"ansible"))
    inventory = InventoryManager(loader=loader, sources="proxmox_hypervisors,")
    vm = VariableManager(loader=loader, inventory=inventory)
    # RED executes an empty actual task stream: missing production actions are
    # measured as an empty trace, not a parser/tooling failure.
    source = BASE/"ansible/proxmox-storage.yml"
    pb = tmp_path/"playbook.yml"
    if source.exists():
        data = yaml.safe_load(source.read_text())
        data[0]["become"] = False
    else: data=[{"hosts":"proxmox_hypervisors", "gather_facts":False, "tasks":[]}]
    data[0]["vars"] = dict(data[0].get("vars",{}), qcl_host_storage=cfg)
    pb.write_text(yaml.safe_dump(data, sort_keys=False))
    executor = PlaybookExecutor(playbooks=[str(pb)], inventory=inventory, variable_manager=vm, loader=loader, passwords={})
    rc = executor.run()
    observed = json.loads(state_path.read_text())
    assert [x["kind"] for x in observed["trace"]] == want, f"missing/incorrect {name} action contract"
    assert (rc != 0) is refused
    assert observed["foreign"] == {"foreign_vm":"immutable"}
    assert observed["original_receipt"] == "failed-1"
    if name in ("root-grow", "fs-only-recovery", "root-complete"):
        assert observed["blocks"] == 32768 and observed["fs_uuid"] == "root-fs"
