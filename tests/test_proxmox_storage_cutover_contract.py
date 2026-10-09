"""Cutover: real Ansible engine, fake native actions, real bounded fixture IO.

No native command/module is allowed to escape. Expectations below are separate
from production phase transitions and immutable source files are not modified.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat

import pytest
import yaml

BASE = Path(__file__).resolve().parents[1]
UUID = "22222222-2222-4222-8222-222222222222"


def helper(name):
    path = BASE / "ops" / ("host_storage_" + name + ".py")
    assert path.exists(), "missing cutover " + name + " helper"
    spec = importlib.util.spec_from_file_location("cutover_" + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def identity():
    return {"attempt_id": "fixture-cutover", "host_id": "fixture-host", "boot_id": "fixture-boot",
            "source_ref": "4" * 40, "storage_id": "fixture-dir", "storage_digest": "a" * 40,
            "source": "/fixture/source", "rollback": "/fixture/original", "stage": "/fixture/stage",
            "lv_uuid": "fixture-lv", "fs_uuid": UUID, "source_dev": 1, "source_ino": 2,
            "parent_dev": 1, "parent_ino": 3}


def receipt_dir(tmp_path):
    root = tmp_path / "receipt"
    root.mkdir(mode=0o700)
    return root / "attempt.json"


def advance(r, path, target="final_verified", intended_tree=None):
    digest = None
    for phase in ("admitted", "gate_disable_intent", "gate_disabled", "copy_started", "copy_verified",
                  "rename_intent", "source_renamed", "final_activation_intent", "final_verified",
                  "reopening_intent", "reopened", "complete"):
        result = r.transition(path, identity(), phase, {}, 65536, digest,
                              intended_tree=intended_tree if phase == "reopening_intent" else None)
        digest = result["sha256"]
        if phase == target:
            return result
    raise AssertionError(target)


@pytest.mark.parametrize("tree", ["new_final", "restored_original"])
def test_sticky_reopening_marker_and_identity(tmp_path, tree):
    r = helper("receipt")
    path = receipt_dir(tmp_path)
    if tree == "new_final":
        current = advance(r, path)
    else:
        current = advance(r, path, "copy_started")
        current = r.transition(path, identity(), "rollback_intent", {}, 65536, current["sha256"])
        current = r.transition(path, identity(), "rolled_back", {}, 65536, current["sha256"])
    marker = r.transition(path, identity(), "reopening_intent", {}, 65536,
                          current["sha256"], intended_tree=tree)
    assert marker["record"]["reopening"]["intended_tree"] == tree
    with pytest.raises(ValueError):
        r.transition(path, identity(), "rollback_intent", {}, 65536, marker["sha256"])
    wrong = dict(identity(), boot_id="other")
    with pytest.raises(ValueError):
        r.inspect(path, wrong, 65536)
    done = r.transition(path, identity(), "reopened", {}, 65536, marker["sha256"])
    assert done["record"]["reopening"] == marker["record"]["reopening"]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize("boundary", ["file-fsync", "directory-fsync", "replace"])
def test_durable_receipt_failure_stops_caller(tmp_path, monkeypatch, boundary):
    r = helper("receipt")
    path = receipt_dir(tmp_path)
    current = advance(r, path)
    fsync, replace = r.os.fsync, r.os.replace
    def sync(fd):
        directory = stat.S_ISDIR(os.fstat(fd).st_mode)
        if (boundary == "directory-fsync" and directory) or (boundary == "file-fsync" and not directory):
            raise OSError("injected " + boundary)
        return fsync(fd)
    def rep(a, b, **kwargs):
        if boundary == "replace": raise OSError("injected replace")
        return replace(a, b, **kwargs)
    monkeypatch.setattr(r.os, "fsync", sync)
    monkeypatch.setattr(r.os, "replace", rep)
    native = []
    with pytest.raises(OSError):
        r.transition(path, identity(), "reopening_intent", {}, 65536, current["sha256"], intended_tree="new_final")
        native.append("CAS")
    assert native == []
    # Directory-fsync outcome can already contain intent: never treat it as absent.
    if boundary == "directory-fsync":
        assert r.inspect(path, identity(), 65536)["record"]["reopening"]


@pytest.mark.parametrize("bad", [True, 0, -1, 1.5, "65536"])
def test_receipt_caps_are_positive_integers(tmp_path, bad):
    r = helper("receipt")
    path = receipt_dir(tmp_path)
    with pytest.raises(ValueError): r.transition(path, identity(), "admitted", {}, bad)
    assert not path.exists()


def test_receipt_corrupt_missing_mutated_or_stale_digest(tmp_path):
    r = helper("receipt")
    path = receipt_dir(tmp_path)
    current = advance(r, path, "rename_intent")
    with pytest.raises(ValueError): r.transition(path, identity(), "source_renamed", {}, 65536, "b" * 64)
    original = path.read_bytes()
    path.write_text("{}")
    with pytest.raises(ValueError): r.inspect(path, identity(), 65536)
    path.write_bytes(original)
    path.unlink()
    with pytest.raises(ValueError): r.transition(path, identity(), "source_renamed", {}, 65536, current["sha256"])
    assert not path.exists()


def limits():
    return {"entries": 128, "hash_bytes": 1048576, "logical_bytes": 1048576,
            "allocated_bytes": 1048576, "output_bytes": 262144, "seconds": 20}


def tree(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    file = root / "disk.raw"
    file.write_bytes(b"AAAA")
    os.utime(file, ns=(1234567890123, 1234567890123))
    os.link(file, root / "linked.raw")
    (root / "link").symlink_to("disk.raw")
    return root


def test_manifest_independent_bytes_ns_links_metadata_and_mode_only_acl(tmp_path):
    m = helper("manifest")
    source = tree(tmp_path)
    dest = tmp_path / "dest"
    shutil.copytree(source, dest, symlinks=True)
    (dest / "linked.raw").unlink()
    os.link(dest / "disk.raw", dest / "linked.raw")
    os.utime(dest, ns=(source.stat().st_atime_ns, source.stat().st_mtime_ns))
    a = m.snapshot(source, limits())
    b = m.snapshot(dest, limits())
    assert m.equal(a, b)
    assert a["entries"]["disk.raw"]["sha256"] == hashlib.sha256(b"AAAA").hexdigest()
    assert a["entries"]["disk.raw"]["hardlinks"] == ["disk.raw", "linked.raw"]
    assert a["entries"]["link"]["target"] == "disk.raw"
    assert a["entries"]["disk.raw"]["xattrs"] == {}
    (dest / "disk.raw").write_bytes(b"BBBB")
    os.utime(dest / "disk.raw", ns=(1234567890123, 1234567890999))
    assert not m.equal(a, m.snapshot(dest, limits()))


@pytest.mark.parametrize("problem", ["attrs-error", "external-hardlink", "fifo", "entry-cap", "hash-cap", "allocation-cap", "semantic-flags"])
def test_manifest_refuses_unknown_or_unsupported(tmp_path, monkeypatch, problem):
    m = helper("manifest")
    source = tree(tmp_path)
    cap = limits()
    if problem == "attrs-error":
        def unknown(*args, **kwargs): raise OSError("xattr not measured")
        monkeypatch.setattr(m.os, "listxattr", unknown)
    if problem == "external-hardlink": os.link(source / "disk.raw", tmp_path / "outside")
    if problem == "fifo": os.mkfifo(source / "fifo")
    if problem == "entry-cap": cap["entries"] = 1
    if problem == "hash-cap": cap["hash_bytes"] = 1
    if problem == "allocation-cap": cap["allocated_bytes"] = 1
    if problem == "semantic-flags": monkeypatch.setattr(m, "inode_flags", lambda fd: 0x10)
    with pytest.raises((ValueError, OSError)): m.snapshot(source, cap)
    assert (source / "disk.raw").read_bytes() == b"AAAA"


def test_manifest_partial_extras_sparse_and_atomic_persistence(tmp_path):
    m, r = helper("manifest"), helper("receipt")
    source = tree(tmp_path)
    # A separate sparse file, bounded logical bytes but little physical allocation.
    with (source / "sparse").open("wb") as out:
        out.seek(65535); out.write(b"Z")
    a = m.snapshot(source, limits())
    partial = tmp_path / "partial"; partial.mkdir()
    (partial / "disk.raw").write_bytes(b"BBBB")
    assert m.subset(a, m.snapshot(partial, limits()))
    (partial / "foreign").write_bytes(b"retain")
    assert not m.subset(a, m.snapshot(partial, limits()))
    assert (partial / "foreign").read_bytes() == b"retain"
    target = receipt_dir(tmp_path).parent / "manifest.json"
    result = r.persist_manifest(target, a, 262144)
    assert result["sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def run_playbook(tmp_path, monkeypatch, scenario):
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
    from ansible.template import Templar
    if AnsibleCollectionConfig.collection_finder is None: init_plugin_loader()
    assert json.loads(Path("/tmp/qcl-host-storage-ansible/ansible_collections/community/general/MANIFEST.json").read_text())["collection_info"]["version"] == "13.4.0"
    monkeypatch.setenv("ANSIBLE_LOCAL_TEMP", str(tmp_path / "ansible-local"))
    source = tree(tmp_path)
    stage = tmp_path / "stage"; stage.mkdir()
    (stage / "disk.raw").write_bytes(b"BBBB")
    os.utime(stage / "disk.raw", ns=(1234567890123, 1234567890999))
    receipt = receipt_dir(tmp_path)
    cfg = {"apply": True, "attempt_id": "fixture-cutover", "host_id": "fixture-host", "boot_id": "fixture-boot",
           "admission": {"fresh": True, "exclusive": True, "receipt": "fixture-admission", "expires_at_epoch": 200},
           "tools": {"python": "/usr/bin/python3", "rsync": "/usr/bin/rsync", "pvesm": "/usr/sbin/pvesm", "lvs": "/usr/sbin/lvs", "blkid": "/usr/sbin/blkid", "pvenode": "/usr/bin/pvenode", "pvesh": "/usr/bin/pvesh"},
           "stage": {"path": str(stage), "unit": "fixture-stage.mount", "fs_uuid": UUID, "lv_uuid": "fixture-lv", "path_dev": stage.stat().st_dev, "path_ino": stage.stat().st_ino, "lifetime": "protected-host-infrastructure"},
           "cutover": {"enabled": True, "source_ref": "4" * 40,
             "window": {"owner": "fixture-owner", "receipt": "fixture-window", "expires_at_epoch": 200,
                        "reference": {"path": "/fixture/window", "sha256": "c"*64}, "node": "fixture-node", "scope": ["file-content", "cached-workers", "direct-paths", "hooks", "vm-transitions", "automation"]},
             "preconditions": {"d04_receipt": {"path": "/fixture/d04", "sha256": "d"*64}, "r1r2_receipt": {"path": "/fixture/r1r2", "sha256": "e"*64}, "seed_receipt": {"path": "/fixture/seed", "sha256": "f"*64}, "seed_path": str(source / "disk.raw"), "seed_sha256": hashlib.sha256(b"AAAA").hexdigest(), "old_installer_unit": "fixture-old.service", "old_installer_backing": "/fixture/old.iso"},
             "storage": {"id": "fixture-dir", "type": "dir", "path": str(source), "digest": "a" * 40, "stanza": {"type": "dir", "path": str(source)}, "foreign": {"foreign-block": {"type": "lvmthin", "vgname": "fixture"}}},
             "source": {"path": str(source), "dev": source.stat().st_dev, "ino": source.stat().st_ino,
                        "parent_dev": source.parent.stat().st_dev, "parent_ino": source.parent.stat().st_ino},
             "rollback": {"path": str(tmp_path / "original")},
             "final": {"path": str(source), "unit": "fixture-source.mount", "fs_uuid": UUID, "device": "/dev/mapper/fixture-images", "rdev": 253, "options": "rw,nodev,nosuid", "allowed_defaults": ["relatime", "data=ordered"], "install_target": "local-fs.target"},
             "receipt": {"path": str(receipt), "max_bytes": 65536, "receipt_helper": str(receipt.parent / "host_storage_receipt.py"), "manifest_helper": str(receipt.parent / "host_storage_manifest.py"), "manifest_path": str(receipt.parent / "manifest.json")},
             "limits": dict(limits(), copy_bytes=1048576, aggregate_bytes=8388608, action_seconds=20),
             "capacity": {"receipt": "fixture-capacity", "pool_uuid": "fixture-pool", "data_bytes": 16777216, "metadata_bytes": 1048576, "data_reserve_bytes": 1048576, "metadata_reserve_bytes": 65536, "growth_bytes": 1048576, "metadata_growth_bytes": 65536, "image_envelope_bytes": 1048576, "lv_projection": [{"lv_uuid":"fixture-lv"}], "foreign_vm_projection": {}}}}
    if scenario == "disabled": cfg = {}
    if scenario == "bad-input": cfg["cutover"]["limits"]["copy_bytes"] = True
    state = {"trace": [], "disabled": False, "renamed": False, "stage_active": True, "final_active": False,
             "foreign": cfg.get("cutover", {}).get("storage", {}).get("foreign", {}), "digest": "a" * 40,
             "scenario": scenario, "receipt_reads": 0, "unit_declared": False, "unit_enabled": False, "offline_raw": None}
    if scenario in ("active-incomplete-resume", "complete-resume"):
        shutil.copytree(source, stage, dirs_exist_ok=True, symlinks=True)
        (stage / "linked.raw").unlink(); os.link(stage / "disk.raw", stage / "linked.raw")
        os.utime(stage, ns=(source.stat().st_atime_ns, source.stat().st_mtime_ns))
        os.rename(source, tmp_path / "original"); source.mkdir()
        state.update(renamed=True, stage_active=False, final_active=True, unit_declared=True, unit_enabled=True, offline_raw="1")
        rid = dict(identity(), source=cfg["cutover"]["source"]["path"], rollback=cfg["cutover"]["rollback"]["path"], stage=cfg["stage"]["path"], source_dev=cfg["cutover"]["source"]["dev"], source_ino=cfg["cutover"]["source"]["ino"], parent_dev=cfg["cutover"]["source"]["parent_dev"], parent_ino=cfg["cutover"]["source"]["parent_ino"])
        r = helper("receipt"); digest = None
        for phase in ("admitted","gate_disable_intent","gate_disabled","copy_started","copy_verified","rename_intent","source_renamed","final_activation_intent","final_verified","reopening_intent","reopened","complete"):
            saved = r.transition(receipt,rid,phase,{},65536,digest,intended_tree="new_final" if phase=="reopening_intent" else None)
            digest=saved["sha256"]
            if scenario=="active-incomplete-resume" and phase=="final_activation_intent": break
    state_file = tmp_path / "recording.json"; state_file.write_text(json.dumps(state))
    original = TaskExecutor._get_action_handler_with_module_context
    def escaped(*a, **kw): raise AssertionError("Native command escaped cutover recording boundary")
    monkeypatch.setattr(Connection, "exec_command", escaped)
    monkeypatch.setattr(ActionBase, "_execute_module", escaped)
    class FakeAction(ActionBase):
        def run(self, tmp=None, task_vars=None):
            args = self._templar.template(self._task.args)
            s = json.loads(state_file.read_text()); out = {"changed": False, "rc": 0, "stdout": ""}
            name = self._task.name
            def record(kind): s["trace"].append(kind)
            if self._task.action == "ansible.builtin.command":
                argv = args["argv"]
                if "host_storage_receipt.py" in " ".join(map(str, argv)):
                    r = helper("receipt")
                    request = json.loads(args.get("stdin", "{}"))
                    try:
                        if request["action"] == "inspect":
                            s["receipt_reads"] += 1
                            result = r.inspect(receipt, request["identity"], request["max_bytes"])
                        elif request["action"] == "read_manifest":
                            value, digest = r.read(request["path"], request["max_bytes"])
                            assert digest == request["sha256"]
                            result = {"manifest": value, "sha256": digest}
                        elif request["action"] == "persist_manifest":
                            result = r.persist_manifest(request["path"], request["manifest"], request["max_bytes"])
                        else:
                            phase = request["phase"]
                            fail_sync = (scenario in ("intent-fsync-failure", "intent-dir-fsync-failure") and phase == "rename_intent") or (scenario in ("completion-failure", "restore-completion-failure") and phase == "reopened")
                            original_sync = r.os.fsync
                            def injected_sync(fd):
                                is_dir = stat.S_ISDIR(os.fstat(fd).st_mode)
                                if fail_sync and (is_dir if scenario == "intent-dir-fsync-failure" else not is_dir):
                                    raise OSError("injected actual receipt fsync boundary")
                                return original_sync(fd)
                            if fail_sync: r.os.fsync = injected_sync
                            try:
                                result = r.transition(receipt, request["identity"], phase, request.get("payload", {}), request["max_bytes"], request.get("expected_sha256"), intended_tree=request.get("intended_tree"))
                            finally: r.os.fsync = original_sync
                            record("receipt:" + phase)
                        out["stdout"] = json.dumps(result)
                    except (ValueError, OSError) as exc: out.update(failed=True, rc=1, stderr=str(exc))
                elif "host_storage_manifest.py" in " ".join(map(str, argv)):
                    m = helper("manifest")
                    request = json.loads(args["stdin"])
                    try:
                        if request.get("action") in ("equal", "subset"):
                            result = {request["action"]: m.equal(request["source"], request["destination"]) if request["action"] == "equal" else m.subset(request["source"], request["partial"])}
                        else:
                            root = Path(request["root"])
                            if s["final_active"] and root == source: root = stage
                            result = m.snapshot(root, request["limits"], empty_lost_found=request.get("empty_lost_found"))
                            if request.get("role") == "final" and scenario in ("restore-original", "restore-completion-failure"):
                                result["entries"]["disk.raw"]["sha256"] = "0"*64
                        out["stdout"] = json.dumps(result)
                    except (ValueError, OSError) as exc: out.update(failed=True, rc=1, stderr=str(exc))
                    record("manifest:" + request.get("role", request.get("action")))
                elif name.startswith("CAS "):
                    assert "--digest" in argv
                    if "reopen" in name:
                        assert helper("receipt").inspect(receipt, task_vars["receipt_identity"], 65536)["record"]["reopening"]["intended_tree"] == ("restored_original" if "restored original" in name else "new_final")
                        record("CAS:reopen-original" if "restored original" in name else "CAS:reopen")
                        s["disabled"] = cfg["cutover"]["storage"]["stanza"].get("disable") in (1,"1","yes",True)
                        if scenario == "unknown-cas": out.update(failed=True, rc=1, stderr="unknown CAS outcome")
                    elif "offline" in name:
                        record("CAS:offline")
                        s["offline_raw"] = ("yes" if scenario == "native-offline-yes" else str(source) if scenario == "native-offline-path" else "1") if "--is_mountpoint" in argv else None
                    else: record("CAS:disable"); s["disabled"] = True
                    s["digest"] = chr(ord(s["digest"][0])+1)*40
                elif name == "Copy retained files once":
                    argv = argv[2:] if argv[0] == "/usr/bin/timeout" else argv
                    assert argv[1:8] == ["-aHAXS", "--numeric-ids", "--one-file-system", "--ignore-times", "--modify-window=-1", "--whole-file", "--"]
                    assert "--delete" not in argv and "--inplace" not in argv
                    record("copy")
                    if scenario == "copy-timeout":
                        out.update(failed=True, rc=124, stderr="own copy deadline")
                    shutil.copytree(source, stage, dirs_exist_ok=True, symlinks=True)
                    (stage / "linked.raw").unlink(); os.link(stage / "disk.raw", stage / "linked.raw")
                    os.utime(stage, ns=(source.stat().st_atime_ns, source.stat().st_mtime_ns))
                    if scenario == "copy-mismatch":
                        (stage / "disk.raw").write_bytes(b"CCCC")
                        os.utime(stage / "disk.raw", ns=(1234567890123,1234567890123))
                elif name == "Rename exact original once":
                    assert helper("receipt").inspect(receipt, task_vars["receipt_identity"], 65536)["record"]["phase"] == "rename_intent"
                    record("rename"); os.rename(source, tmp_path / "original"); source.mkdir(); s["renamed"] = True
                elif name == "Restore exact retained original once":
                    assert helper("receipt").inspect(receipt, task_vars["receipt_identity"], 65536)["record"]["phase"] == "rollback_intent"
                    record("restore"); source.rmdir(); os.rename(tmp_path / "original", source); s["renamed"] = False
                elif name.startswith("Observe") or name.startswith("Read") or name.startswith("Verify") or name.startswith("Sync") or name.startswith("Reconcile"):
                    # Independent native-shaped observations, not a second phase machine.
                    out["stdout"] = json.dumps({"host_id": "fixture-host", "boot_id": "fixture-boot", "now": 100,
                        "digest": s["digest"], "storage": dict(cfg["cutover"]["storage"]["stanza"], **({"disable": "1"} if s["disabled"] else {}), **({"is_mountpoint":s["offline_raw"]} if s["offline_raw"] is not None else {})),
                        "foreign": s["foreign"], "complete": True, "refs": [], "aliases": ["source-bind"] if scenario == "relevant-alias" else [], "old_loop": scenario == "old-loop",
                        "workers": [], "workers_relevant": ["cached-native-worker"] if scenario == "cached-worker" else [], "data_used_bytes": "not_measured" if scenario == "unknown-data" else 1048576, "metadata_used_bytes": 65536,
                        "healthy": True, "stage_active": s["stage_active"], "final_active": s["final_active"], "fs_uuid": "wrong" if scenario == "wrong-uuid-unit" else UUID,
                        "device": "/dev/dm-0", "rdev": 254 if scenario == "wrong-rdev-unit" else 253, "mountpoint_dev": source.stat().st_dev, "mountpoint_ino": source.stat().st_ino, "Where": "/wrong" if scenario == "wrong-where-unit" else task_vars.get("guard_path", str(source)), "Type": "xfs" if scenario == "wrong-type-unit" else "ext4", "ActiveState": "active" if (s["stage_active"] if task_vars.get("guard_stage") else s["final_active"]) else "inactive", "UnitFileState": "static" if task_vars.get("guard_stage") else "enabled" if s["unit_enabled"] else "disabled", "stage_policy": "static", "source_renamed": s["renamed"],
                        "ForceUnmount": "yes" if scenario == "force-unit" else "no", "LazyUnmount": "yes" if scenario == "lazy-unit" else "no", "DropInPaths": "foreign.conf" if scenario == "dropin-unit" else "", "NeedDaemonReload": "yes" if scenario == "reload-unit" else "no",
                        "Options": "nosuid,rw,relatime,nodev,data=ordered" + (",ro" if scenario == "ro-unit" else ",unknown-option" if scenario == "unknown-options" else ""), "fragment_exact": scenario != "unsafe-unit",
                        "seed_sha256": hashlib.sha256(b"AAAA").hexdigest(), "is_mountpoint_raw": s["offline_raw"], "mountpoint_guard": str(source) if s["offline_raw"] in ("1","yes",str(source)) else None, "storage_disabled": s["disabled"], "original_disabled": cfg["cutover"]["storage"]["stanza"].get("disable") in (1,"1","yes",True),
                        "absent": bool(task_vars.get("guard_absent", False) and not s["unit_declared"])})
                    record("observe:" + name)
                else: raise AssertionError("Unrecognized native command " + name + " " + str(argv))
            elif self._task.action == "ansible.builtin.systemd_service":
                assert args.get("state") != "restarted"
                record("systemd:" + str(args.get("state", "enable")))
                if args.get("name") == "fixture-source.mount" and "enabled" in args: s["unit_enabled"] = args["enabled"]
                if args.get("name") == "fixture-stage.mount" and args.get("state") == "stopped": s["stage_active"] = False
                if args.get("name") == "fixture-source.mount" and args.get("state") == "started": s["final_active"] = True
                if args.get("name") == "fixture-source.mount" and args.get("state") == "stopped": s["final_active"] = False
            elif self._task.action in ("ansible.builtin.template", "ansible.builtin.copy", "ansible.builtin.file"):
                record(self._task.action.split(".")[-1])
                if self._task.action == "ansible.builtin.template":
                    from ansible.utils.tags import TrustedAsTemplate
                    text = self._templar.template(TrustedAsTemplate().tag((BASE / "ansible" / args["src"]).read_text()))
                    s["unit_declared"] = True
                    assert "ForceUnmount=no" in text and "LazyUnmount=no" in text and "Before=pve-guests.service" in text
                if self._task.action == "ansible.builtin.copy" and "content" in args:
                    helper("receipt").persist_manifest(Path(args["dest"]), json.loads(args["content"]), 262144)
            else: raise AssertionError(self._task.action)
            state_file.write_text(json.dumps(s))
            return out
    def handler(executor, templar):
        if executor._task.action in ("ansible.builtin.assert", "ansible.builtin.set_fact", "ansible.builtin.debug", "ansible.builtin.fail", "ansible.builtin.include_tasks"):
            return original(executor, templar)
        return FakeAction(task=executor._task, connection=executor._connection, play_context=executor._play_context,
                          loader=executor._loader, templar=Templar._from_template_engine(templar), shared_loader_obj=executor._shared_loader_obj), None
    monkeypatch.setattr(TaskExecutor, "_get_action_handler_with_module_context", handler)
    context.CLIARGS = ImmutableDict(connection="local", forks=1, become=False, check=scenario == "check", diff=False, verbosity=0, syntax=False, start_at_task=None, tags=[], skip_tags=[])
    loader = DataLoader(); loader.set_basedir(str(BASE / "ansible"))
    inventory = InventoryManager(loader=loader, sources="proxmox_hypervisors,")
    vm = VariableManager(loader=loader, inventory=inventory)
    path = BASE / "ansible/proxmox-storage-cutover.yml"
    data = yaml.safe_load(path.read_text()) if path.exists() else [{"hosts": "proxmox_hypervisors", "gather_facts": False, "tasks": []}]
    data[0]["become"] = False
    data[0]["vars"] = dict(data[0].get("vars", {}), qcl_host_storage=cfg)
    play = tmp_path / "play.yml"; play.write_text(yaml.safe_dump(data, sort_keys=False))
    (tmp_path / "tasks").symlink_to(BASE / "ansible/tasks", target_is_directory=True)
    (tmp_path / "templates").symlink_to(BASE / "ansible/templates", target_is_directory=True)
    rc = PlaybookExecutor(playbooks=[str(play)], inventory=inventory, variable_manager=vm, loader=loader, passwords={}).run()
    return rc, json.loads(state_file.read_text()), receipt, source, stage


@pytest.mark.parametrize("scenario", ["success", "completion-failure", "unknown-cas", "disabled", "check", "bad-input", "unsafe-unit", "force-unit", "lazy-unit", "dropin-unit", "reload-unit", "ro-unit", "unknown-options", "wrong-type-unit", "wrong-where-unit", "wrong-uuid-unit", "wrong-rdev-unit", "cached-worker", "old-loop", "relevant-alias", "intent-fsync-failure", "intent-dir-fsync-failure", "copy-timeout", "copy-mismatch", "unknown-data", "native-offline-yes", "native-offline-path"])
def test_actual_cutover_yaml_and_sticky_cas_boundary(tmp_path, monkeypatch, scenario):
    rc, state, path, source, stage = run_playbook(tmp_path, monkeypatch, scenario)
    trace = state["trace"]
    if scenario not in ("success", "native-offline-yes", "native-offline-path", "completion-failure", "unknown-cas", "intent-fsync-failure", "intent-dir-fsync-failure", "copy-timeout", "copy-mismatch"):
        assert "copy" not in trace and "rename" not in trace and "CAS:reopen" not in trace
        assert (source / "disk.raw").read_bytes() == b"AAAA"
        assert ("CAS:disable" not in trace) if scenario in ("disabled", "check", "bad-input") else True
        assert (rc == 0) if scenario in ("disabled", "check") else rc != 0
        return
    if scenario in ("copy-timeout", "copy-mismatch"):
        assert rc != 0 and "copy" in trace and "rename" not in trace and "CAS:reopen" not in trace
        assert state["disabled"] and (source / "disk.raw").read_bytes() == b"AAAA"
        return
    if scenario in ("intent-fsync-failure", "intent-dir-fsync-failure"):
        assert rc != 0 and "receipt:copy_verified" in trace
        assert "rename" not in trace and "CAS:reopen" not in trace
        assert (source / "disk.raw").read_bytes() == b"AAAA" and state["disabled"]
        return
    required = ["receipt:gate_disable_intent", "CAS:disable", "receipt:gate_disabled", "receipt:copy_started", "copy", "receipt:copy_verified", "receipt:rename_intent", "rename", "receipt:source_renamed", "receipt:final_activation_intent", "systemd:started", "receipt:final_verified", "CAS:offline", "receipt:reopening_intent", "CAS:reopen"]
    position = [trace.index(x) for x in required]
    assert position == sorted(position), "missing cutover durable intent/native/observed order"
    assert state["foreign"] == {"foreign-block": {"type": "lvmthin", "vgname": "fixture"}}
    assert (source.parent / "original" / "disk.raw").read_bytes() == b"AAAA"
    assert (stage / "disk.raw").read_bytes() == b"AAAA"
    assert (stage / "disk.raw").stat().st_mtime_ns == 1234567890123
    assert not state["stage_active"] and state["final_active"] and state["unit_enabled"]
    record = helper("receipt").inspect(path, json.loads(path.read_text())["identity"], 65536)["record"]
    assert record["reopening"]["intended_tree"] == "new_final"
    if scenario in ("success", "native-offline-yes", "native-offline-path"):
        assert rc == 0 and record["phase"] == "complete"
    else:
        assert rc != 0 and state["receipt_reads"] >= 2
        assert record["phase"] in ("reopening_intent", "reconcile_required")
        after = trace[trace.index("CAS:reopen")+1:]
        assert not any(x in after for x in ("copy", "rename", "CAS:disable", "CAS:reopen", "systemd:started", "systemd:stopped"))


def test_all_embedded_native_python_and_playbook_are_parseable():
    import ast
    data = yaml.safe_load((BASE / "ansible/proxmox-storage-cutover.yml").read_text())
    guard = yaml.safe_load((BASE / "ansible/tasks/proxmox-storage-cutover-mount-guard.yml").read_text())
    def walk(value):
        if isinstance(value, dict):
            if "ansible.builtin.command" in value:
                argv = value["ansible.builtin.command"]["argv"]
                if isinstance(argv, list) and "-c" in argv:
                    ast.parse(argv[argv.index("-c")+1])
            for v in value.values(): walk(v)
        elif isinstance(value, list):
            for v in value: walk(v)
    ast.parse(data[0]["vars"]["cutover_native_probe"])
    walk(data); walk(guard)


def test_exact_empty_created_lost_found_only(tmp_path):
    m = helper("manifest")
    source = tree(tmp_path)
    directory = source / "lost+found"; directory.mkdir(mode=0o700)
    info = directory.stat()
    exact = {"dev": info.st_dev, "ino": info.st_ino, "uid": info.st_uid, "gid": info.st_gid, "mode": 0o700}
    manifest = m.snapshot(source, limits(), empty_lost_found=exact)
    assert "lost+found" not in manifest["entries"]
    (directory / "foreign").write_text("retain")
    with pytest.raises(ValueError): m.snapshot(source, limits(), empty_lost_found=exact)
    assert (directory / "foreign").read_text() == "retain"


def test_manifest_acl_xattr_bytes_are_independent_oracle(tmp_path):
    import struct
    m = helper("manifest")
    root = tree(tmp_path)
    os.setxattr(root / "disk.raw", "user.fixture", b"metadata-A")
    acl = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", tag, perm, uid) for tag, perm, uid in [(1,6,0xffffffff),(2,4,os.getuid()+1),(4,4,0xffffffff),(16,4,0xffffffff),(32,0,0xffffffff)])
    os.setxattr(root / "disk.raw", "system.posix_acl_access", acl)
    before = m.snapshot(root, limits())
    assert "system.posix_acl_access" in before["entries"]["disk.raw"]["xattrs"]
    os.setxattr(root / "disk.raw", "user.fixture", b"metadata-B")
    after = m.snapshot(root, limits())
    assert not m.equal(before, after)


@pytest.mark.parametrize("scenario", ["restore-original", "restore-completion-failure"])
def test_actual_pre_marker_restore_has_its_own_sticky_boundary(tmp_path, monkeypatch, scenario):
    rc, state, path, source, stage = run_playbook(tmp_path, monkeypatch, scenario)
    trace = state["trace"]
    assert rc != 0, "original failed attempt is never rewritten as successful cutover"
    required = ["receipt:rollback_intent", "restore", "receipt:rolled_back", "receipt:reopening_intent", "CAS:reopen-original"]
    positions = [trace.index(item) for item in required]
    assert positions == sorted(positions)
    record = json.loads(path.read_text())
    assert record["reopening"]["intended_tree"] == "restored_original"
    assert (source / "disk.raw").read_bytes() == b"AAAA"
    assert source.stat().st_ino == record["identity"]["source_ino"]
    assert not (source.parent / "original").exists() and (stage / "disk.raw").read_bytes() == b"AAAA"
    after = trace[trace.index("CAS:reopen-original")+1:]
    assert "restore" not in after and "CAS:reopen-original" not in after
    if scenario == "restore-completion-failure": assert record["phase"] == "reopening_intent"


@pytest.mark.parametrize("scenario", ["active-incomplete-resume", "complete-resume"])
def test_existing_exact_final_is_never_restarted_or_stage_aliased(tmp_path, monkeypatch, scenario):
    rc, state, path, source, stage = run_playbook(tmp_path,monkeypatch,scenario)
    assert state["final_active"] and not state["stage_active"]
    assert not any(item in state["trace"] for item in ("copy","rename","restore","CAS:disable","CAS:reopen","systemd:started","systemd:stopped","template"))
    assert (source.parent / "original" / "disk.raw").read_bytes()==b"AAAA"
    assert rc==0 if scenario=="complete-resume" else rc!=0
