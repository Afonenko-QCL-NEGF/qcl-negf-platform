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

pytestmark = pytest.mark.usefixtures("ansible_test_environment")

BASE = Path(__file__).resolve().parents[1]
MIB = 1048576


def fixture():
    cfg = {
        "apply": True, "attempt_id": "recovery-2", "original_receipt": "failed-1",
        "host_id": "fixture-host", "boot_id": "fixture-boot",
        "admission": {"fresh": True, "exclusive": True, "receipt": "fixture-live", "expires_at_epoch": 200},
        "tools": {x: "/usr/sbin/" + x for x in ["lvs", "vgs", "pvs", "blkid", "wipefs", "dumpe2fs", "resize2fs", "blockdev"]},
        "root": {"enabled": True, "device": "/dev/test/root", "vg": "test", "lv": "root", "pv_uuid": "pv-id", "vg_uuid": "vg-id", "lv_uuid": "root-id", "fs_uuid": "11111111-1111-4111-8111-111111111111", "target_mib": 128, "authorized_cap_mib": 256, "reserve_vg_mib": 16, "supported_ext4_features": ["has_journal", "extent"]},
        "stage": {"enabled": False, "vg": "test", "pool": "pool", "pool_uuid": "pool-id", "vg_uuid": "vg-id", "lv": "images", "lv_uuid": None, "fs_uuid": "22222222-2222-4222-8222-222222222222", "target_mib": 256, "authorized_cap_mib": 512, "path": "/srv/stage", "unit": "srv-stage.mount", "source": "/var/lib/vz", "preparation_data_mib": 8, "preparation_metadata_mib": 2, "protected_data_mib": 16, "protected_metadata_mib": 4, "consumers_complete": True, "namespace_complete": True, "references_complete": True, "reference_receipt": "fixture-live-refs", "volume_references": [], "lifetime": "protected-host-infrastructure"},
    }
    state = {
        "trace": [], "probes": [], "root_bytes": 64*MIB, "blocks": 16384, "block_size": 4096,
        "outside": 128*MIB, "extent": 4*MIB, "bad_probe": False,
        "root_uuid": "root-id", "fs_uuid": "11111111-1111-4111-8111-111111111111", "root_type": "ext4",
        "stage_exists": False, "stage_uuid": "stage-id", "stage_fs": None,
        "stage_signature": False, "stage_active": False, "final": False,
        "alias": False, "busy": False, "metadata_percent": 10,
        "data_percent":10, "segments":False, "mapper":False, "usage_changes":False,
        "unrelated_bind":False, "relevant_bind":False, "unit_state":"disabled",
        "unit_options":"rw,nodev,nosuid", "options_duplicate":False, "post_usage_field":None, "post_usage_value":None, "lazy":False, "force_unmount":False, "dropins":False, "foreign_unit":False,
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
    ("root-segments", ["lv-grow", "fs-grow"], False),
    ("root-segments-recovery", ["fs-grow"], False),
    ("new-stage-static", ["lv-create", "format", "unit", "disable", "start", "inspect", "stop"], False),
    ("static-resume", ["inspect", "stop"], False),
    ("stage-mapper-new", ["lv-create", "format", "unit", "disable", "start", "inspect", "stop"], False),
    ("stage-mapper-resume", ["inspect", "stop"], False),
    ("stage-mapper-final", [], False),
    ("pool-usage-new", ["lv-create", "format", "unit", "disable", "start", "inspect", "stop"], False),
    ("foreign-usage-root", ["lv-grow", "fs-grow"], False),
    ("unrelated-private-bind", ["inspect", "stop"], False),
    ("source-bind-alias", [], True),
    ("lazy-unit-resume", [], True),
    ("force-unit-resume", [], True),
    ("dropin-unit-resume", [], True),
    ("foreign-unit-resume", [], True),
    ("uuid-random", [], True),
    ("uuid-clear", [], True),
    ("uuid-malformed", [], True),
    ("uuid-zero", [], True),
    ("uuid-root", [], True),
    ("post-data-blank", ["lv-create", "format", "unit", "disable", "start", "inspect", "stop"], True),
    ("post-data-not-measured", ["lv-create", "format", "unit", "disable", "start", "inspect", "stop"], True),
    ("post-metadata-blank", ["lv-create", "format", "unit", "disable", "start", "inspect", "stop"], True),
    ("post-metadata-not-measured", ["lv-create", "format", "unit", "disable", "start", "inspect", "stop"], True),
    ("options-native-new", ["lv-create", "format", "unit", "disable", "start", "inspect", "stop"], False),
    ("options-native-resume", ["inspect", "stop"], False),
    ("options-ro", [], True),
    ("options-dev", [], True),
    ("options-suid", [], True),
    ("options-missing-nodev", [], True),
    ("options-missing-nosuid", [], True),
    ("options-blank", [], True),
    ("options-missing-record", [], True),
    ("options-duplicate-record", [], True),
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
    if name in [x[0] for x in CASES[10:]] and name not in ("root-segments", "root-segments-recovery", "foreign-usage-root"):
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
        state.update(stage_exists=True, stage_fs="22222222-2222-4222-8222-222222222222", stage_active=True)
    if name == "busy-resume": state["busy"] = True
    if name == "resume-wrong-fs": state["stage_fs"] = "wrong-fs"
    if name == "final-handoff": state.update(final=True, stage_active=False)
    if name in ("root-segments", "root-segments-recovery"): state["segments"] = True
    if name == "root-segments-recovery": state["root_bytes"] = 128*MIB
    if name in ("static-resume", "stage-mapper-resume", "unrelated-private-bind", "source-bind-alias", "lazy-unit-resume", "force-unit-resume", "dropin-unit-resume", "foreign-unit-resume", "stage-mapper-final"):
        cfg["stage"]["lv_uuid"] = "stage-id"
        state.update(stage_exists=True, stage_fs="22222222-2222-4222-8222-222222222222", stage_active=True)
    if name in ("new-stage-static", "static-resume"): state["unit_state"] = "static"
    if name.startswith("stage-mapper"): state["mapper"] = True
    if name == "stage-mapper-final": state.update(final=True, stage_active=False)
    if name in ("pool-usage-new", "foreign-usage-root"): state["usage_changes"] = True
    if name == "unrelated-private-bind": state["unrelated_bind"] = True
    if name == "source-bind-alias": state["relevant_bind"] = True
    if name == "lazy-unit-resume": state["lazy"] = True
    if name == "force-unit-resume": state["force_unmount"] = True
    if name == "dropin-unit-resume": state["dropins"] = True
    if name == "foreign-unit-resume": state["foreign_unit"] = True
    if name.startswith("uuid-"):
        cfg["stage"]["fs_uuid"] = {"uuid-random":"random", "uuid-clear":"clear", "uuid-malformed":"stage-fs", "uuid-zero":"00000000-0000-0000-0000-000000000000", "uuid-root":"11111111-1111-4111-8111-111111111111"}[name]
    if name.startswith("post-"):
        state["post_usage_field"] = "data_percent" if name.startswith("post-data") else "metadata_percent"
        state["post_usage_value"] = "" if name.endswith("blank") else "not_measured"
    if name.startswith("options-"):
        state["unit_options"] = "rw,nosuid,nodev,relatime,data=ordered"
        if name != "options-native-new":
            cfg["stage"]["lv_uuid"] = "stage-id"
            state.update(stage_exists=True, stage_fs="22222222-2222-4222-8222-222222222222", stage_active=True)
        if name in ("options-ro", "options-dev", "options-suid"):
            state["unit_options"] += "," + name[len("options-"):]
        if name == "options-missing-nodev": state["unit_options"] = "rw,nosuid,relatime"
        if name == "options-missing-nosuid": state["unit_options"] = "rw,nodev,relatime"
        if name == "options-blank": state["unit_options"] = ""
        if name == "options-missing-record": state["unit_options"] = None
        if name == "options-duplicate-record": state["options_duplicate"] = True
    return cfg, state


def lvs(state):
    rows = [
        {"lv_name":"root", "vg_name":"test", "lv_uuid":state["root_uuid"], "vg_uuid":"vg-id", "lv_size":str(state["root_bytes"]), "segtype":"linear", "pool_lv":"", "lv_path":"/dev/test/root", "devices":"/dev/test/pv(0)"},
        {"lv_name":"pool", "vg_name":"test", "lv_uuid":"pool-id", "vg_uuid":"vg-id", "lv_size":str(1024*MIB), "segtype":"thin-pool", "pool_lv":"", "lv_path":"/dev/test/pool", "data_percent":str(state["data_percent"]), "metadata_percent":str(state["metadata_percent"]), "lv_metadata_size":str(64*MIB), "lv_attr":"twi-a-tz--", "lv_health_status":""},
    ]
    if state["stage_exists"]:
        rows.append({"lv_name":"images", "vg_name":"test", "lv_uuid":state["stage_uuid"], "vg_uuid":"vg-id", "lv_size":str(256*MIB), "segtype":"thin", "pool_lv":"pool", "lv_path":"/dev/test/images"})
    if state["segments"]:
        rows.insert(1, dict(rows[0], devices="/dev/test/pv(16384)"))
    if state["usage_changes"]: rows.reverse()
    return {"report":[{"lv": rows}]}


@pytest.mark.parametrize("name,want,refused", CASES)
def test_actual_ansible_action_contract(name, want, refused, tmp_path, monkeypatch):
    # A bad dispatch must not escape to a real command/module/SSH process.
    monkeypatch.setenv("ANSIBLE_LOCAL_TEMP", str(tmp_path/"ansible-local"))
    from ansible import context
    from ansible.module_utils.common.collections import ImmutableDict
    from ansible.parsing.dataloader import DataLoader
    from ansible.inventory.manager import InventoryManager
    from ansible.vars.manager import VariableManager
    from ansible.executor.playbook_executor import PlaybookExecutor
    from ansible.executor.task_executor import TaskExecutor
    from ansible.plugins.action import ActionBase
    from ansible.plugins.connection.local import Connection
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
                elif cmd == "cat":
                    if argv[1].startswith("/etc/systemd/"):
                        out["stdout"] = "# Protected host infrastructure; temporary inspection only; no boot target.\n[Unit]\nDescription=Protected host image preparation stage\n[Mount]\nWhat=UUID=22222222-2222-4222-8222-222222222222\nWhere=/srv/stage\nType=ext4\nOptions=rw,nodev,nosuid\nLazyUnmount=no\nForceUnmount=no\n"
                        if s["foreign_unit"]: out["stdout"] += "# altered foreign file\n"
                    else: out["stdout"] = "fixture-host" if "machine-id" in argv[1] else "fixture-boot"
                elif cmd == "lvs":
                    if s["post_usage_field"] and any(x["kind"] == "stop" for x in s["trace"]):
                        s[s["post_usage_field"]] = s["post_usage_value"]
                    if s["usage_changes"]:
                        s["data_percent"] += 1
                        s["metadata_percent"] += 1
                    out["stdout"] = json.dumps(lvs(s))
                elif cmd == "vgs": out["stdout"] = json.dumps({"report":[{"vg":[{"vg_name":"test", "vg_uuid":"vg-id", "vg_free":str(s["outside"]), "vg_extent_size":str(s["extent"])}]}]})
                elif cmd == "pvs": out["stdout"] = json.dumps({"report":[{"pv":[{"pv_name":"/dev/test/pv", "pv_uuid":"pv-id", "vg_uuid":"vg-id"}]}]})
                elif cmd == "findmnt":
                    rows=[{"target":"/", "source":"/dev/test/root", "uuid":s["fs_uuid"], "fstype":s["root_type"], "fsroot":"/", "maj:min":"253:0"}]
                    if s["stage_active"]: rows.append({"target":cfg["stage"]["path"], "source":"/dev/mapper/test-images" if s["mapper"] else "/dev/test/images", "uuid":s["stage_fs"], "fstype":"ext4", "fsroot":"/", "maj:min":"253:1"})
                    if s["final"]: rows.append({"target":"/var/lib/vz", "source":"/dev/mapper/test-images" if s["mapper"] else "/dev/test/images", "uuid":s["stage_fs"], "fstype":"ext4", "fsroot":"/", "maj:min":"253:1"})
                    if s["alias"]: rows.append({"target":cfg["stage"]["path"], "source":"/dev/test/root", "uuid":"11111111-1111-4111-8111-111111111111", "fstype":"ext4", "fsroot":"/var/lib/vz", "maj:min":"253:0"})
                    if s["unrelated_bind"]:
                        rows.append({"target":"/tmp", "source":"/dev/test/root", "uuid":"11111111-1111-4111-8111-111111111111", "fstype":"ext4", "fsroot":"/systemd-private/foo/tmp", "maj:min":"253:0"})
                        rows.append({"target":"/container/proc", "source":"proc", "uuid":None, "fstype":"proc", "fsroot":"/123", "maj:min":"0:99"})
                    if s["relevant_bind"]: rows.append({"target":"/alias", "source":"/dev/test/root", "uuid":"11111111-1111-4111-8111-111111111111", "fstype":"ext4", "fsroot":"/var/lib/vz", "maj:min":"253:0"})
                    out["stdout"] = json.dumps({"filesystems":rows})
                elif cmd == "dumpe2fs": out["stdout"] = f"Filesystem UUID: {s['fs_uuid']}\nFilesystem features: has_journal extent\nBlock count: {s['blocks']}\nBlock size: {s['block_size']}\n"
                elif cmd == "blockdev": out["stdout"] = str(s["root_bytes"])
                elif cmd == "resize2fs":
                    assert argv == ["/usr/sbin/resize2fs", "/dev/test/root", "32768"]
                    assert s["probes"][-5:] == ["lvs", "findmnt", "blockdev", "dumpe2fs", "resize2fs"]
                    trace("fs-grow"); s["blocks"] = 32768
                elif cmd == "realpath":
                    out["stdout"] = "/dev/dm-1" if argv[-1] in ("/dev/test/images", "/dev/mapper/test-images", "/dev/disk/by-uuid/22222222-2222-4222-8222-222222222222", "/dev/dm-1") else argv[-1]
                elif cmd == "stat":
                    if "%t:%T" in argv: out["stdout"] = "fd:1"
                    elif "%U:%G:%a:%F" in argv: out["stdout"] = "root:root:644:regular file"
                    else: out["stdout"] = "directory" if "%F" in argv else ("1:42" if argv[-1] == "/var/lib/vz" or s["alias"] else "1:43")
                elif cmd == "lsns": out["stdout"] = json.dumps({"namespaces":[{"ns":1,"pid":1},{"ns":2,"pid":2}]})
                elif cmd == "find": out["stdout"] = ""
                elif cmd == "blkid":
                    if s["stage_fs"]: out["stdout"] = f"UUID={s['stage_fs']}\nTYPE=ext4\n"
                    else: out["rc"] = 2
                elif cmd == "wipefs": out["stdout"] = json.dumps({"signatures":[{"type":"foreign"}] if s["stage_signature"] else []})
                elif cmd == "fuser": out.update(rc=0 if s["busy"] else 1, stdout="123" if s["busy"] else "")
                elif cmd == "ls": trace("inspect"); out["stdout"] = "lost+found"
                elif cmd == "systemctl":
                    if argv[1] == "is-enabled": out["stdout"] = s["unit_state"]
                    else:
                        out["stdout"] = "\n".join(["What=UUID=22222222-2222-4222-8222-222222222222", "Where=/srv/stage", "Type=ext4", "Options=" + (s["unit_options"] or ""), "FragmentPath=/etc/systemd/system/srv-stage.mount", "DropInPaths=" + ("/etc/foreign.conf" if s["dropins"] else ""), "LazyUnmount=" + ("yes" if s["lazy"] else "no"), "ForceUnmount=" + ("yes" if s["force_unmount"] else "no"), "UnitFileState=" + s["unit_state"], "NeedDaemonReload=no"])
                        if s["unit_options"] is None:
                            out["stdout"] = "\n".join(x for x in out["stdout"].splitlines() if not x.startswith("Options="))
                        if s["options_duplicate"]: out["stdout"] += "\nOptions=" + s["unit_options"]
                elif cmd == "df": out["stdout"] = "fixture root df"
                else: raise AssertionError(f"Unexpected command {argv}")
            elif action == "community.general.lvol":
                assert args["shrink"] is False and args["force"] is False and args["resizefs"] is False
                assert args["vg"] == "test" and args["state"] == "present"
                assert args["size"] == ("128m" if args["lv"] == "root" else "256m")
                if args["lv"] != "root": assert args["thinpool"] == "pool"
                if args["lv"] == "root": assert args["pvs"] == ["/dev/test/pv"]
                if args["lv"] == "root": trace("lv-grow"); s["root_bytes"] = 128*MIB; s["outside"] -= 64*MIB
                else: trace("lv-create"); s["stage_exists"] = True
                out["changed"] = True
            elif action == "community.general.filesystem":
                assert not s["stage_fs"] and not args["force"]
                assert args["dev"] == "/dev/test/images" and args["fstype"] == "ext4" and args["uuid"] == "22222222-2222-4222-8222-222222222222"
                trace("format"); s["stage_fs"] = "22222222-2222-4222-8222-222222222222"; out["changed"] = True
            elif action == "ansible.builtin.template":
                from ansible._internal._datatag._tags import TrustedAsTemplate
                text = self._templar.template(TrustedAsTemplate().tag((BASE/"ansible"/args["src"]).read_text()))
                assert "WantedBy" not in text and "What=UUID=22222222-2222-4222-8222-222222222222" in text
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
    (tmp_path/"templates").symlink_to(BASE/"ansible/templates", target_is_directory=True)
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
        assert observed["blocks"] == 32768 and observed["fs_uuid"] == "11111111-1111-4111-8111-111111111111"


@pytest.mark.parametrize("foreign", ["engine_init", "engine_release", "executable", "process_executable"])
def test_declared_origins_refuse_same_version_foreign_tree(foreign):
    from conftest import _assert_declared_ansible_origins
    expected = {
        "base": "/declared/base", "launcher": "/declared/launcher",
        "engine_init": "/declared/engine/ansible/__init__.py",
        "engine_release": "/declared/engine/ansible/release.py", "engine_version": "2.21.1",
    }
    observed = {
        "python_version": (3, 14), "engine_version": "2.21.1", "no_user_site": 1,
        "executable": expected["launcher"], "process_executable": expected["base"],
        "engine_init": expected["engine_init"], "engine_release": expected["engine_release"],
    }
    assert all(_assert_declared_ansible_origins(observed, expected).values())
    observed[foreign] = "/foreign/same-version/" + foreign
    with pytest.raises(ValueError, match="Declared Ansible origin mismatch"):
        _assert_declared_ansible_origins(observed, expected)
