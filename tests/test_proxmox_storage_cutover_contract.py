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


def fixture_pvesm_policy(argv,selected_id,current_digest):
    assert type(argv) is list and len(argv)==7 and all(type(v) is str and v for v in argv)
    assert argv[:3]==['/usr/sbin/pvesm','set',selected_id], 'wrong selected PVE command'
    pairs=list(zip(argv[3::2],argv[4::2]))
    assert len(pairs)==2 and len({key for key,_ in pairs})==2, 'duplicate PVE flag'
    flags=dict(pairs)
    assert '--digest' in flags and flags['--digest']==current_digest, 'CAS digest mismatch before native effect'
    policies=set(flags)-{'--digest'}
    assert len(policies)==1 and policies<={'--disable','--is_mountpoint','--delete'}, 'unknown PVE policy flag'
    option=next(iter(policies));value=flags[option]
    if option=='--delete':assert value in ('disable','is_mountpoint')
    elif option=='--disable':native_boolean(value)
    else:native_mountpoint(value,'/fixture/source')
    return option,value


def fixture_pvesm_effect(storage,option,value):
    updated=dict(storage)
    if option=='--delete':updated.pop(value,None)
    else:updated[option[2:]]=value
    return updated


def fixture_final_unit_bytes(source):
    # Independent frozen native policy oracle: never read production template or received bytes.
    return ("# Protected host infrastructure; original tree retained for admitted recovery.\n"
            "[Unit]\nDescription=Protected persistent Proxmox directory storage\n"
            "Before=pve-guests.service\n[Mount]\n"
            "What=/dev/disk/by-uuid/22222222-2222-4222-8222-222222222222\n"
            "Where="+str(source)+"\nType=ext4\nOptions=rw,nodev,nosuid\n"
            "LazyUnmount=no\nForceUnmount=no\n[Install]\nWantedBy=local-fs.target\n").encode('utf-8')


def fixture_declare_final_unit(args, surrogate, source):
    expected=fixture_final_unit_bytes(source)
    assert args['dest']=='/etc/systemd/system/fixture-source.mount', 'wrong final unit destination'
    assert args['content'].encode('utf-8')==expected, 'wrong complete final unit literal'
    assert int(args['mode'],8)==0o644
    def readback(path):
        st=os.lstat(path)
        assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o644
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            assert os.fstat(fd).st_ino==st.st_ino
            assert os.read(fd,len(expected)+1)==expected
            assert os.lstat(path).st_ino==st.st_ino
        finally:os.close(fd)
        return st
    if os.path.lexists(surrogate):
        before=readback(surrogate);after=readback(surrogate)
        assert (before.st_ino,before.st_mtime_ns)==(after.st_ino,after.st_mtime_ns)
    else:
        pending=surrogate.with_name(surrogate.name+'.own-new')
        fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            assert os.write(fd,expected)==len(expected);os.fchmod(fd,0o644);os.fsync(fd)
        finally:os.close(fd)
        assert not os.path.lexists(surrogate), 'unknown raced final unit'
        os.link(pending,surrogate,follow_symlinks=False)  # Atomic no-clobber publication in own fixture.
        pending.unlink()
        readback(surrogate)


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
    from ansible.template import Templar, trust_as_template
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
           "cutover": {"enabled": True, "contract_version": 3, "source_ref": "4" * 40,
             "window": {"owner": "fixture-owner", "receipt": "fixture-window", "expires_at_epoch": 200,
                        "reference": {"path": "/fixture/window", "sha256": "c"*64}, "node": "fixture-node", "scope": ["file-content", "cached-workers", "direct-paths", "hooks", "vm-transitions", "automation"]},
             "preconditions": {"d04_receipt": {"path": "/fixture/d04", "sha256": "d"*64}, "r1r2_receipt": {"path": "/fixture/r1r2", "sha256": "e"*64}, "seed_receipt": {"path": "/fixture/seed", "sha256": "f"*64}, "seed_path": str(source / "disk.raw"), "seed_bytes":4, "references_receipt":{"path":"/fixture/references","sha256":"b"*64},"excluded_old_qcl_set_sha256":"0"*64, "seed_sha256": hashlib.sha256(b"AAAA").hexdigest(), "old_installer_unit": "fixture-old.service", "old_installer_backing": "/fixture/old.iso"},
             "storage": {"id": "fixture-dir", "type": "dir", "path": str(source), "digest": "a" * 40, "stanza": {"type": "dir", "path": str(source)}, "foreign": {"foreign-block": {"type": "lvmthin", "vgname": "fixture"}}},
             "source": {"path": str(source), "dev": source.stat().st_dev, "ino": source.stat().st_ino,
                        "parent_dev": source.parent.stat().st_dev, "parent_ino": source.parent.stat().st_ino},
             "rollback": {"path": str(tmp_path / "original")},
             "final": {"path": str(source), "unit": "fixture-source.mount", "fs_uuid": UUID, "device": "/dev/mapper/fixture-images", "rdev": 253, "options": "rw,nodev,nosuid", "allowed_defaults": ["relatime", "data=ordered"], "install_target": "local-fs.target"},
             "receipt": {"path": str(receipt), "max_bytes": 65536, "receipt_helper": str(receipt.parent / "host_storage_receipt.py"), "manifest_helper": str(receipt.parent / "host_storage_manifest.py"), "manifest_path": str(receipt.parent / "manifest.json")},
             "limits": dict(limits(), copy_bytes=1048576, aggregate_bytes=794296388, action_seconds=20, attempt_seconds=900, cleanup_seconds=1, aggregate_output_bytes=23592960, aggregate_read_bytes=768606276, aggregate_write_bytes=25690112, metadata_read_bytes=8388608, request_bytes=262144, native_commands=100, reference_entries=100, reference_hash_bytes=1048576),
             "capacity": {"receipt": "fixture-capacity", "pool_uuid": "fixture-pool", "data_bytes": 16777216, "metadata_bytes": 1048576, "data_reserve_bytes": 1048576, "metadata_reserve_bytes": 65536, "growth_bytes": 1048576, "metadata_growth_bytes": 65536, "image_envelope_bytes": 1048576, "lv_projection": [{"lv_uuid":"fixture-lv"}], "foreign_vm_projection": {}}}}
    if scenario in ("complete-original-disabled","complete-missing-disable"): cfg["cutover"]["storage"]["stanza"]["disable"]="yes"
    if scenario == "disabled": cfg = {}
    if scenario == "bad-input": cfg["cutover"]["limits"]["copy_bytes"] = True
    state = {"trace": [], "disabled": False, "renamed": False, "stage_active": True, "final_active": False,
             "foreign": cfg.get("cutover", {}).get("storage", {}).get("foreign", {}), "digest": "a" * 40,
             "scenario": scenario, "receipt_reads": 0, "unit_declared": False, "unit_enabled": False, "offline_raw": None}
    if scenario in ("active-incomplete-resume", "complete-resume", "complete-reader", "complete-disable-changed", "complete-add-false", "complete-original-disabled", "complete-missing-disable", "complete-restored"):
        shutil.copytree(source, stage, dirs_exist_ok=True, symlinks=True)
        (stage / "linked.raw").unlink(); os.link(stage / "disk.raw", stage / "linked.raw")
        os.utime(stage, ns=(source.stat().st_atime_ns, source.stat().st_mtime_ns))
        os.rename(source, tmp_path / "original"); source.mkdir()
        state.update(renamed=True, stage_active=False, final_active=True, unit_declared=True, unit_enabled=True, offline_raw="1",disabled=scenario in ("complete-original-disabled","complete-missing-disable","complete-disable-changed"))
        rid = dict(identity(), source=cfg["cutover"]["source"]["path"], rollback=cfg["cutover"]["rollback"]["path"], stage=cfg["stage"]["path"], source_dev=cfg["cutover"]["source"]["dev"], source_ino=cfg["cutover"]["source"]["ino"], parent_dev=cfg["cutover"]["source"]["parent_dev"], parent_ino=cfg["cutover"]["source"]["parent_ino"])
        if scenario=="complete-restored":
            source.rmdir();os.rename(tmp_path/"original",source);state.update(renamed=False,final_active=False,offline_raw=None,unit_enabled=False)
        r = helper("receipt"); digest = None
        for phase in ("admitted","gate_disable_intent","gate_disabled","copy_started","copy_verified","rename_intent","source_renamed","final_activation_intent","final_verified",*( ("rollback_intent","rolled_back") if scenario=="complete-restored" else ()),"reopening_intent","reopened","complete"):
            saved = r.transition(receipt,rid,phase,{"original_storage":cfg["cutover"]["storage"]["stanza"]},65536,digest,intended_tree=("restored_original" if scenario=="complete-restored" else "new_final") if phase=="reopening_intent" else None)
            digest=saved["sha256"]
            if scenario=="active-incomplete-resume" and phase=="final_activation_intent": break
    if scenario in ("active-incomplete-resume", "complete-resume", "complete-reader", "complete-disable-changed", "complete-add-false", "complete-original-disabled", "complete-missing-disable", "complete-restored"):
        for name in ("receipt", "manifest"):
            dest = receipt.parent / ("host_storage_"+name+".py")
            dest.write_bytes((BASE/"ops"/dest.name).read_bytes()); dest.chmod(0o600)
    helper_before = {str(p): (p.stat().st_ino, p.stat().st_mtime_ns, hashlib.sha256(p.read_bytes()).hexdigest()) for p in receipt.parent.glob("host_storage_*.py")}
    state["helper_before"] = helper_before
    state["storage_current"]=dict(cfg.get("cutover",{}).get("storage",{}).get("stanza",{}))
    if state["offline_raw"] is not None:state["storage_current"]["is_mountpoint"]=state["offline_raw"]
    if scenario=="complete-disable-changed":state["storage_current"]["disable"]="1"
    if scenario=="complete-add-false":state["storage_current"]["disable"]="0"
    if scenario=="complete-missing-disable":state["storage_current"].pop("disable",None);state["disabled"]=False
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
            effective_action=self._task.action; outer_request=None
            if effective_action == "ansible.builtin.command" and args.get("argv",[])[-1:] == [task_vars.get("cutover_command_boundary")]:
                outer_request=json.loads(args["stdin"])
                assert outer_request["schema"]=="qcl.storage-cutover.command.v1" and set(outer_request)=={"schema","identity","slot_id","clock","bounds","operation"}
                assert set(outer_request["operation"])=={"kind","argv","stdin","mutation"}
                if outer_request["operation"]["kind"] == "clock_bootstrap":
                    import time
                    clock={"started_monotonic_ns":time.monotonic_ns(),"deadline_monotonic_ns":time.monotonic_ns()+600000000000,"expires_at_epoch":int(time.time())+600,"action_seconds":20,"cleanup_seconds":1}
                    s["trace"].append("clock-bootstrap");state_file.write_text(json.dumps(s))
                    return {"changed":False,"rc":0,"stdout":json.dumps({"clock":clock,"status":"ok"})}
                assert outer_request["schema"]=="qcl.storage-cutover.command.v1" and set(outer_request)=={"schema","identity","slot_id","clock","bounds","operation"}
                operation=outer_request["operation"];assert set(operation)=={"kind","argv","stdin","mutation"}
                assert operation["kind"] in ("probe","mount_guard","reference_check","manifest","receipt_io","native_argv","declare_file","rename_original","restore_original")
                assert operation["argv"][0] in ("/usr/bin/python3","/usr/bin/systemctl","/usr/bin/rsync","/usr/sbin/pvesm","/usr/bin/sync")
                body_sha=None
                if len(operation["argv"])>=3 and operation["argv"][1]=="-c":
                    body_sha=hashlib.sha256(operation["argv"][2].encode()).hexdigest();assert body_sha in source_body_hashes,'unrecognized source executable body before trace'
                s.setdefault("boundary_events",[]).append({"slot":outer_request["slot_id"],"kind":operation["kind"],"body_sha256":body_sha,"argv_sha256":hashlib.sha256(json.dumps(operation["argv"]).encode()).hexdigest()})
                args={"argv":operation["argv"],"stdin":operation["stdin"]}
                if operation["kind"] == "declare_file":
                    args=json.loads(operation["stdin"]);assert set(args)-{"dest","content","mode"} <= {"src","owner","group"};args={key:args[key] for key in ("dest","content","mode")};effective_action="ansible.builtin.template" if "final unit" in name else "ansible.builtin.copy"
                elif operation["argv"][0] == "/usr/bin/systemctl":
                    argv=operation["argv"];assert argv[0]=="/usr/bin/systemctl";verb=argv[1]
                    assert len(argv)==(2 if verb=="daemon-reload" else 3) and all(type(v) is str and v for v in argv)
                    args={"verb":verb,"name":argv[2] if len(argv)==3 else None};effective_action="ansible.builtin.systemd_service"
            def record(kind): s["trace"].append(kind)
            if effective_action == "ansible.builtin.command":
                argv = args["argv"]
                if operation["kind"]=="receipt_io" and argv==[cfg["tools"]["python"],cfg["cutover"]["receipt"]["receipt_helper"]]:
                    r = installed_helper("receipt", cfg)
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
                elif operation["kind"] in ("manifest","receipt_io") and argv==[cfg["tools"]["python"],cfg["cutover"]["receipt"]["manifest_helper"]]:
                    m = installed_helper("manifest", cfg)
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
                elif operation["kind"]=="reference_check":
                    reference_request=json.loads(args["stdin"]);assert set(reference_request) in ({"h","boundary","expected"},{"h","boundary","expected","retained_manifest"})
                    assert reference_request["h"]["attempt_id"]==cfg["attempt_id"]
                    record("reference:"+name);out["stdout"]=json.dumps({"complete":True})
                elif operation["kind"]=="native_argv" and argv[0]==cfg["tools"]["pvesm"]:
                    assert args["stdin"]=="", "PVE native argv does not consume JSON stdin"
                    option,value=fixture_pvesm_policy(argv,cfg["cutover"]["storage"]["id"],s["digest"])
                    s["storage_current"]=fixture_pvesm_effect(s["storage_current"],option,value)
                    s["disabled"]=native_boolean(s["storage_current"].get("disable","0"))
                    s["offline_raw"]=s["storage_current"].get("is_mountpoint")
                    if "reopen" in name:
                        assert installed_helper("receipt",cfg).inspect(receipt, json.loads(self._templar.template(trust_as_template("{{ receipt_identity | to_json }}"))), 65536)["record"]["reopening"]["intended_tree"] == ("restored_original" if "restored original" in name else "new_final")
                        record("CAS:reopen-original" if "restored original" in name else "CAS:reopen")
                        if scenario == "unknown-cas":out.update(failed=True,rc=1,stderr="unknown CAS outcome",boundary_status="native_outcome_unknown")
                    elif option=="--is_mountpoint":record("CAS:offline")
                    elif option=="--delete" and value=="is_mountpoint":record("CAS:restore-offline")
                    else:record("CAS:disable")
                    s["digest"]=chr(ord(s["digest"][0])+1)*40
                elif operation["kind"]=="native_argv" and argv[0]==cfg["tools"]["rsync"]:
                    assert args["stdin"]==""
                    assert len(argv)==10 and argv[0]==cfg["tools"]["rsync"] and argv[8:]==[str(source)+"/",str(stage)+"/"]
                    assert argv[1:8] == ["-aHAXS", "--numeric-ids", "--one-file-system", "--ignore-times", "--modify-window=-1", "--whole-file", "--"]
                    assert "--delete" not in argv and "--inplace" not in argv
                    record("retained-copy")
                    if scenario == "copy-timeout":
                        out.update(failed=True, rc=124, stderr="own copy deadline")
                    shutil.copytree(source, stage, dirs_exist_ok=True, symlinks=True)
                    (stage / "linked.raw").unlink(); os.link(stage / "disk.raw", stage / "linked.raw")
                    os.utime(stage, ns=(source.stat().st_atime_ns, source.stat().st_mtime_ns))
                    if scenario == "copy-mismatch":
                        (stage / "disk.raw").write_bytes(b"CCCC")
                        os.utime(stage / "disk.raw", ns=(1234567890123,1234567890123))
                elif operation["kind"]=="rename_original":
                    rename_request=json.loads(args["stdin"]);assert set(rename_request)=={"source","rollback","dev","ino","parent_dev","parent_ino"}
                    assert rename_request["source"]==str(source) and rename_request["rollback"]==str(tmp_path/"original")
                    assert installed_helper("receipt",cfg).inspect(receipt, json.loads(self._templar.template(trust_as_template("{{ receipt_identity | to_json }}"))), 65536)["record"]["phase"] == "rename_intent"
                    record("rename"); os.rename(source, tmp_path / "original"); source.mkdir(); s["renamed"] = True
                elif operation["kind"]=="restore_original":
                    restore_request=json.loads(args["stdin"]);assert set(restore_request)=={"source","rollback","dev","ino","parent_dev","parent_ino","mountpoint_dev","mountpoint_ino"}
                    assert restore_request["source"]==str(source) and restore_request["rollback"]==str(tmp_path/"original")
                    assert installed_helper("receipt",cfg).inspect(receipt, json.loads(self._templar.template(trust_as_template("{{ receipt_identity | to_json }}"))), 65536)["record"]["phase"] == "rollback_intent"
                    record("restore"); source.rmdir(); os.rename(tmp_path / "original", source); s["renamed"] = False
                elif operation["kind"]=="native_argv" and argv[0]=="/usr/bin/sync":
                    assert argv==["/usr/bin/sync","-f",str(stage)] and args["stdin"]=="" and operation["mutation"] is False
                    record("sync:stage");out["stdout"]=""
                elif operation["kind"] in ("probe","mount_guard"):
                    # Independent native-shaped observations, not a second phase machine.
                    observation_request = json.loads(args.get("stdin", "{}"))
                    out["stdout"] = json.dumps({"host_id": "fixture-host", "boot_id": "fixture-boot", "now": 100,
                        "digest": s["digest"], "storage": dict(s["storage_current"]),
                        "foreign": s["foreign"], "receipt_present": receipt.exists(), "helpers_verified": True, "complete": True, "refs": [{"pid":123,"target":str(source/"new-file")}] if scenario=="complete-reader" else [], "aliases": ["source-bind"] if scenario == "relevant-alias" else [], "old_loop": scenario == "old-loop",
                        "workers": [], "workers_relevant": ["legal-current-worker"] if scenario=="complete-reader" else ["cached-native-worker"] if scenario == "cached-worker" else [], "data_used_bytes": "not_measured" if scenario == "unknown-data" else 1048576, "metadata_used_bytes": 65536,
                        "healthy": True, "stage_active": s["stage_active"], "final_active": s["final_active"], "fs_uuid": "wrong" if scenario == "wrong-uuid-unit" else UUID,
                        "device": "/dev/dm-0", "rdev": 254 if scenario == "wrong-rdev-unit" else 253, "mountpoint_dev": source.stat().st_dev, "mountpoint_ino": source.stat().st_ino, "Where": "/wrong" if scenario == "wrong-where-unit" else observation_request.get("path", str(source)), "Type": "xfs" if scenario == "wrong-type-unit" else "ext4", "ActiveState": "active" if (s["stage_active"] if observation_request.get("stage", False) else s["final_active"]) else "inactive", "UnitFileState": "static" if observation_request.get("stage", False) else "enabled" if s["unit_enabled"] else "disabled", "stage_policy": "static", "source_renamed": s["renamed"],
                        "ForceUnmount": "yes" if scenario == "force-unit" else "no", "LazyUnmount": "yes" if scenario == "lazy-unit" else "no", "DropInPaths": "foreign.conf" if scenario == "dropin-unit" else "", "NeedDaemonReload": "yes" if scenario == "reload-unit" else "no",
                        "Options": "nosuid,rw,relatime,nodev,data=ordered" + (",ro" if scenario == "ro-unit" else ",unknown-option" if scenario == "unknown-options" else ""), "fragment_exact": scenario != "unsafe-unit",
                        "seed_sha256": hashlib.sha256(b"AAAA").hexdigest(), "is_mountpoint_raw": s["offline_raw"], "mountpoint_guard": "/wrong" if scenario.startswith("nb-restore") and name=="Observe native offline policy and disabled gate before reopen" else native_mountpoint(s["offline_raw"],str(source)), "storage_disabled": s["disabled"], "original_disabled": cfg["cutover"]["storage"]["stanza"].get("disable") in (1,"1","yes",True),
                        "absent": bool(observation_request.get("allow_absent",False) and not s["unit_declared"])})
                    if name == "Verify exact loaded mount policy":
                        loaded=json.loads(out["stdout"])
                        if loaded["absent"]:
                            loaded={"absent":True,"fragment_exact":loaded["fragment_exact"]}
                        else:
                            loaded={key:loaded[key] for key in ("absent","fragment_exact","fs_uuid","rdev","device","Where","Type","Options","ForceUnmount","LazyUnmount","DropInPaths","NeedDaemonReload","ActiveState","UnitFileState")}
                            loaded.update(FragmentPath="/etc/systemd/system/"+observation_request["unit"],What=cfg["cutover"]["final"]["device"])
                        out["stdout"]=json.dumps(loaded)
                    observed=json.loads(out["stdout"])
                    if outer_request and outer_request["operation"]["kind"]=="probe":
                        mode=observation_request.get("observe_only",False) or (observation_request.get("initial",False) and receipt.exists())
                        if "consumers_measured" in task_vars["cutover_native_probe"]:
                            observed.update(consumers_measured=not mode,refs=None if mode else observed["refs"])
                        if observation_request.get("final_policy_readback"):
                            observed["final_policy"]={"ActiveState":"active" if s["final_active"] else "inactive","UnitFileState":"enabled" if s["unit_enabled"] else "disabled","FragmentPath":"/etc/systemd/system/fixture-source.mount","NeedDaemonReload":"no"}
                        if name=="Reconcile actual fixed config mount units and callers read-only":
                            s["recovery_measurement"]=not mode
                            if not mode:
                                scanner=review_body("cutover_consumer_scan")["consumer_refs"]
                                holder=None;previous_cwd=os.getcwd()
                                unrelated=tmp_path/"unrelated-map";unrelated.write_bytes(b"ordinary unrelated metadata")
                                maps_patch=pytest.MonkeyPatch();independent_maps(maps_patch,unrelated)
                                try:
                                    target=source if scenario in ("nb-restore-fd","nb-restore-cwd","nb-restore-root") else tmp_path
                                    if scenario=="nb-restore-cwd":os.chdir(target)
                                    elif scenario in ("nb-restore-fd","nb-restore-root","nb-restore-unrelated"):holder=os.open(target,os.O_RDONLY|os.O_DIRECTORY)
                                    observed["refs"]=scanner([tmp_path/"original",source,stage],cfg["cutover"]["limits"]["entries"],cfg["cutover"]["limits"]["metadata_read_bytes"],5,pids=[os.getpid()])
                                    observed["consumers_measured"]=True
                                    s.setdefault("scan_evidence",[]).append({"slot":outer_request["slot_id"],"measured":True,"refs":observed["refs"],"case":scenario,"physical_root":"ordinary directory root FD; process /root remains actual unrelated /"})
                                finally:
                                    if holder is not None:os.close(holder)
                                    os.chdir(previous_cwd);maps_patch.undo()
                        out["stdout"]=json.dumps(observed)
                    record("observe:" + name)
                else: raise AssertionError("Unrecognized native command " + name + " " + str(argv))
            elif effective_action == "ansible.builtin.systemd_service":
                verb=args["verb"];assert verb in ("start","stop","enable","disable","daemon-reload")
                assert verb=="daemon-reload" or args["name"] in ("fixture-stage.mount","fixture-source.mount")
                if args["name"]=="fixture-source.mount":assert s["unit_declared"], "absent final unit reached systemd before declaration"
                record("systemd:"+{"start":"started","stop":"stopped","disable":"disable","enable":"enable","daemon-reload":"reload"}[verb])
                if args["name"]=="fixture-source.mount":
                    if verb in ("enable","disable"):s["unit_enabled"]=verb=="enable"
                    if verb in ("start","stop"):s["final_active"]=verb=="start"
                if args["name"]=="fixture-stage.mount" and verb=="stop":s["stage_active"]=False
            elif effective_action in ("ansible.builtin.template","ansible.builtin.copy"):
                assert set(args)=={"dest","content","mode"}
                content=args["content"].encode();mode=int(args["mode"],8)
                if effective_action=="ansible.builtin.template":
                    destination=tmp_path/"unit"
                    fixture_declare_final_unit(args,destination,source)
                    record("template");s["unit_declared"]=True
                else:
                    destination=Path(args["dest"]);kind="receipt" if destination.name=="host_storage_receipt.py" else "manifest"
                    assert content==(BASE/"ops"/destination.name).read_bytes() and mode==0o600
                    record("helper-declare:host_storage_"+kind)
                if destination.exists():
                    assert destination.read_bytes()==content and stat.S_IMODE(destination.stat().st_mode)==mode
                else:
                    destination.write_bytes(content);destination.chmod(mode)
                assert destination.read_bytes()==content
            else: raise AssertionError(self._task.action)
            state_file.write_text(json.dumps(s))
            if outer_request is not None:
                native=dict(out);payload={"schema":outer_request["schema"],"slot_id":outer_request["slot_id"],"identity":outer_request["identity"],"clock":outer_request["clock"],"status":native.get("boundary_status","refused" if native.get("failed") else "ok"),"returncode":native.get("rc",0),"stdout":native.get("stdout",""),"stderr":native.get("stderr",""),"observed_bytes":{"stdout":len(native.get("stdout","")),"stderr":len(native.get("stderr","")),"metadata":0},"reserved_bytes":outer_request["bounds"],"cleanup":{"pgid":None,"term_sent":False,"kill_sent":False,"reaped":True,"group_absent":True}}
                out["stdout"]=json.dumps(payload)
            return out
    def handler(executor, templar):
        if executor._task.action in ("ansible.builtin.assert", "ansible.builtin.set_fact", "ansible.builtin.debug", "ansible.builtin.fail", "ansible.builtin.include_tasks"):
            return original(executor, templar)
        return FakeAction(task=executor._task, connection=executor._connection, play_context=executor._play_context,
                          loader=executor._loader, templar=Templar._from_template_engine(templar), shared_loader_obj=executor._shared_loader_obj), None
    monkeypatch.setattr(TaskExecutor, "_get_action_handler_with_module_context", handler)
    context.CLIARGS = ImmutableDict(connection="local", forks=1, become=False, check=scenario == "check", diff=False, verbosity=0, syntax=False, start_at_task=None, tags=[], skip_tags=[])
    # Actual core caches CLI magic vars globally: reset for this independent CLI simulation.
    from ansible.utils.vars import load_options_vars
    monkeypatch.setattr(load_options_vars, "options_vars", None, raising=False)
    loader = DataLoader(); loader.set_basedir(str(BASE / "ansible"))
    inventory = InventoryManager(loader=loader, sources="proxmox_hypervisors,")
    vm = VariableManager(loader=loader, inventory=inventory)
    path = BASE / "ansible/proxmox-storage-cutover.yml"
    data = yaml.safe_load(path.read_text()) if path.exists() else [{"hosts": "proxmox_hypervisors", "gather_facts": False, "tasks": []}]
    source_bodies={key:value for key,value in data[0].get("vars",{}).items() if key.startswith("cutover_") and isinstance(value,str) and value.startswith("import ")}
    def collect_inline(tasks):
        for task in tasks:
            operation=task.get("vars",{}).get("cutover_operation",{})
            argv=operation.get("argv",[])
            if isinstance(argv,list):
                for body in argv:
                    if isinstance(body,str) and body.startswith("import "):source_bodies[hashlib.sha256(body.encode()).hexdigest()]=body
            for key in ("block","rescue","always"):
                if key in task:collect_inline(task[key])
    collect_inline(data[0]["tasks"])
    guard_source=yaml.safe_load((BASE/"ansible/tasks/proxmox-storage-cutover-mount-guard.yml").read_text())
    collect_inline(guard_source)
    source_body_hashes={hashlib.sha256(body.encode()).hexdigest() for body in source_bodies.values()}
    (tmp_path/"source-bodies.json").write_text(json.dumps(source_bodies))
    data[0]["become"] = False
    data[0]["vars"] = dict(data[0].get("vars", {}), qcl_host_storage=cfg, cutover_helper_sha256={kind:hashlib.sha256((BASE/"ops"/("host_storage_"+kind+".py")).read_bytes()).hexdigest() for kind in ("receipt","manifest")})
    def relocate_declaration(tasks):
        for task in tasks:
            declaration=task.get("vars",{}).get("cutover_declaration")
            if declaration and declaration["mode"]=="0600":
                kind="receipt" if "receipt_helper" in declaration["dest"] else "manifest"
                declaration["content"]=(BASE/"ops"/("host_storage_"+kind+".py")).read_text()
            for key in ("block","rescue","always"):
                if key in task:relocate_declaration(task[key])
    relocate_declaration(data[0]["tasks"])
    play = tmp_path / "play.yml"; play.write_text(yaml.safe_dump(data, sort_keys=False))
    (tmp_path / "tasks").symlink_to(BASE / "ansible/tasks", target_is_directory=True)
    (tmp_path / "templates").symlink_to(BASE / "ansible/templates", target_is_directory=True)
    reader=None
    if scenario=="complete-reader":
        (source/"new-file").write_bytes(b"post-reopen-new-writes");reader=os.open(source/"new-file",os.O_RDONLY)
    try:rc = PlaybookExecutor(playbooks=[str(play)], inventory=inventory, variable_manager=vm, loader=loader, passwords={}).run()
    finally:
        if reader is not None:os.close(reader)
    return rc, json.loads(state_file.read_text()), receipt, source, stage


@pytest.mark.parametrize("scenario", ["success", "completion-failure", "unknown-cas", "disabled", "check", "bad-input", "unsafe-unit", "force-unit", "lazy-unit", "dropin-unit", "reload-unit", "ro-unit", "unknown-options", "wrong-type-unit", "wrong-where-unit", "wrong-uuid-unit", "wrong-rdev-unit", "cached-worker", "old-loop", "relevant-alias", "intent-fsync-failure", "intent-dir-fsync-failure", "copy-timeout", "copy-mismatch", "unknown-data", "native-offline-yes", "native-offline-path"])
def test_actual_cutover_yaml_and_sticky_cas_boundary(tmp_path, monkeypatch, scenario):
    rc, state, path, source, stage = run_playbook(tmp_path, monkeypatch, scenario)
    trace = state["trace"]
    if scenario not in ("success", "native-offline-yes", "native-offline-path", "completion-failure", "unknown-cas", "intent-fsync-failure", "intent-dir-fsync-failure", "copy-timeout", "copy-mismatch"):
        assert "retained-copy" not in trace and "rename" not in trace and "CAS:reopen" not in trace
        assert (source / "disk.raw").read_bytes() == b"AAAA"
        assert ("CAS:disable" not in trace) if scenario in ("disabled", "check", "bad-input") else True
        assert (rc == 0) if scenario in ("disabled", "check") else rc != 0
        return
    if scenario in ("copy-timeout", "copy-mismatch"):
        assert rc != 0 and "retained-copy" in trace and "rename" not in trace and "CAS:reopen" not in trace
        assert state["disabled"] and (source / "disk.raw").read_bytes() == b"AAAA"
        return
    if scenario in ("intent-fsync-failure", "intent-dir-fsync-failure"):
        assert rc != 0 and "receipt:copy_verified" in trace
        assert "rename" not in trace and "CAS:reopen" not in trace
        assert (source / "disk.raw").read_bytes() == b"AAAA" and state["disabled"]
        return
    required = ["receipt:gate_disable_intent", "CAS:disable", "receipt:gate_disabled", "receipt:copy_started", "retained-copy", "receipt:copy_verified", "receipt:rename_intent", "rename", "receipt:source_renamed", "receipt:final_activation_intent", "systemd:started", "receipt:final_verified", "CAS:offline", "receipt:reopening_intent", "CAS:reopen"]
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
        assert not any(x in after for x in ("retained-copy", "rename", "CAS:disable", "CAS:reopen", "systemd:started", "systemd:stopped"))


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
    assert not any(item in state["trace"] for item in ("retained-copy","rename","restore","CAS:disable","CAS:reopen","systemd:started","systemd:stopped","template"))
    assert (source.parent / "original" / "disk.raw").read_bytes()==b"AAAA"
    assert rc==0 if scenario=="complete-resume" else rc!=0


@pytest.mark.parametrize("operation", ["persist_manifest", "transition"])
def test_repair_broken_symlink_record_is_never_replaced(tmp_path, operation):
    r = helper("receipt")
    path = receipt_dir(tmp_path)
    missing = path.parent / "absent.json"
    path.symlink_to(missing)
    before = path.lstat()
    with pytest.raises((ValueError,OSError)):
        if operation == "persist_manifest": r.persist_manifest(path, {"fixture":True},65536)
        else: r.transition(path,identity(),"admitted",{},65536)
    assert path.is_symlink() and path.lstat().st_ino==before.st_ino
    assert os.readlink(path)==str(missing) and not missing.exists()


@pytest.mark.parametrize("scenario", ["active-incomplete-resume", "complete-resume"])
def test_repair_existing_receipt_has_no_helper_declaration_or_write(tmp_path,monkeypatch,scenario):
    rc,state,path,source,stage=run_playbook(tmp_path,monkeypatch,scenario)
    assert not any(item.startswith("helper-declare:") for item in state["trace"])
    after={str(p):(p.stat().st_ino,p.stat().st_mtime_ns,hashlib.sha256(p.read_bytes()).hexdigest()) for p in path.parent.glob("host_storage_*.py")}
    assert after=={k:tuple(v) for k,v in state["helper_before"].items()}
    assert not any(item in state["trace"] for item in ("retained-copy","rename","restore","CAS:disable","CAS:reopen","systemd:started","systemd:stopped","template"))
    assert rc==0 if scenario=="complete-resume" else rc!=0


def test_repair_check_after_warm_noncheck_cli_has_no_native_or_helper_write(tmp_path,monkeypatch):
    warm=tmp_path/"warm";warm.mkdir()
    run_playbook(warm,monkeypatch,"disabled")
    cold=tmp_path/"check";cold.mkdir()
    rc,state,path,source,stage=run_playbook(cold,monkeypatch,"check")
    assert rc==0 and state["trace"]==[]
    assert not path.exists() and list(path.parent.glob("host_storage_*.py"))==[]
    assert (source/"disk.raw").read_bytes()==b"AAAA" and not state["renamed"]


# Review-repair regressions execute owning embedded bodies, not a parallel state machine.
def review_body(name):
    import yaml
    variables = yaml.safe_load((BASE / "ansible/proxmox-storage-cutover.yml").read_text())[0]["vars"]
    if name not in variables: raise AssertionError("missing owning review primitive: " + name)
    scope = {"__name__": "fixture"}
    exec(compile(variables[name], name, "exec"), scope)
    return scope


def review_request(argv=None, seconds=3, output=4096):
    import time
    now = time.monotonic_ns()
    return {"schema":"qcl.storage-cutover.command.v1", "identity":{"attempt_id":"fixture", "host_id":Path("/etc/machine-id").read_text().strip(), "boot_id":Path("/proc/sys/kernel/random/boot_id").read_text().strip()},
        "slot_id":"fixture-slot", "clock":{"started_monotonic_ns":now, "deadline_monotonic_ns":now+int(seconds*1e9), "expires_at_epoch":int(time.time())+60, "action_seconds":seconds, "cleanup_seconds":1},
        "bounds":{"request_bytes":1048576,"output_bytes":output,"metadata_read_bytes":8388608,"native_commands":3,"hash_read_bytes":0,"copy_read_bytes":0,"copy_write_bytes":0},
        "operation":{"kind":"native_argv", "argv":argv or ["/usr/bin/python", "-c", "print('ok')"], "stdin":"", "mutation":False}}


def test_review_final_absence_fact(tmp_path, monkeypatch):
    rc, state, *_ = run_playbook(tmp_path, monkeypatch, "review-final-absent")
    assert rc == 0 and state["unit_declared"]
    assert state["trace"].count("template") == 1
    assert "CAS:reopen" in state["trace"]


@pytest.mark.parametrize("mode", ["pipe-linger", "term-ignore", "output-cap", "expired", "gone"])
def test_review_owned_group_boundary(tmp_path, mode):
    import time, subprocess, signal
    api = review_body("cutover_command_boundary")
    witness = tmp_path / "child.pid"
    program = "print('ok')"
    if mode in ("pipe-linger", "term-ignore"):
        program = "import os,time,signal; p=os.fork(); " + ("signal.signal(signal.SIGTERM,signal.SIG_IGN); " if mode == "term-ignore" else "") + "open("+repr(str(witness))+",'w').write(str(os.getpid())) if p==0 else None; time.sleep(30) if p==0 else None"
    elif mode == "output-cap": program="print('X'*10000)"
    request = review_request(["/usr/bin/python", "-c", program], seconds=3, output=4096)
    if mode == "expired": request["clock"]["deadline_monotonic_ns"] = time.monotonic_ns()-1
    foreign = subprocess.Popen(["/usr/bin/python","-c","import time;time.sleep(30)"], start_new_session=True)
    try:
        started=time.monotonic(); result=review_boundary(request)
        assert time.monotonic()-started < 4
        assert result["cleanup"]["group_absent"] is True
        assert result["cleanup"]["reaped"] is True
        assert foreign.poll() is None
        assert result["status"] == ("ok" if mode == "gone" else "deadline" if mode in ("pipe-linger","term-ignore","expired") else "output_cap")
        if witness.exists():
            pid=int(witness.read_text()); assert not Path('/proc',str(pid)).exists() or Path('/proc',str(pid),'stat').read_text().split()[2]=='Z'
    finally:
        os.killpg(foreign.pid,signal.SIGTERM); foreign.wait(timeout=2)


def test_review_nested_cumulative_output_and_expiry(tmp_path):
    api=review_body("cutover_command_boundary")
    # Actual nested runner shares one invocation counter and the frozen deadline.
    request=review_request(output=128)
    runner=api["NestedRunner"](request)
    runner.run(["/usr/bin/python","-c","print('A'*80)"])
    with pytest.raises(ValueError,match="output"):
        runner.run(["/usr/bin/python","-c","print('B'*80)"])
    request["clock"]["deadline_monotonic_ns"]=1
    with pytest.raises(ValueError,match="deadline"):
        api["NestedRunner"](request).run(["/usr/bin/python","-c","raise AssertionError('must not start')"])


@pytest.mark.parametrize("target", ["stage-root","stage-subdir","inactive-point","deleted-original","unrelated"])
def test_review_actual_directory_consumer(tmp_path,target,monkeypatch):
    api=review_body("cutover_consumer_scan")
    original=tmp_path/'source';original.mkdir(); stage=tmp_path/'stage';stage.mkdir(); sub=stage/'sub';sub.mkdir();other=tmp_path/'other';other.mkdir()
    maps=tmp_path/'map-unrelated';maps.write_bytes(b'x');independent_maps(monkeypatch,maps)
    opened=stage if target in ('stage-root','inactive-point') else sub if target=='stage-subdir' else original if target=='deleted-original' else other
    fd=os.open(opened,os.O_RDONLY|os.O_DIRECTORY)
    if target=='deleted-original': original.rmdir()
    try:
        result=api['consumer_refs']([original,stage],100,8388608,5,pids=[os.getpid()])
        assert bool(result)==(target!='unrelated')
    finally:os.close(fd)


def test_review_reference_semantic_context(tmp_path):
    api=review_body('cutover_reference_check')
    node=tmp_path/'external';node.write_bytes(b'known')
    st=node.stat()
    graph={'schema':'qcl.storage-cutover.references.v1','accepted':True,'complete':True,'identity':{'host':'h'},'d04_receipt_sha256':'d'*64,'window_receipt_sha256':'w'*64,'retained_manifest_sha256':'m'*64,'excluded_old_qcl_set_sha256':'e'*64,
        'volume_bindings':[{'id':'dir:disk','relative':'disk','storage_id':'dir'}], 'absolute_bindings':[], 'backing_nodes':[{'id':'ext','ownership':'external','path':str(node),'format':'raw','dev':st.st_dev,'ino':st.st_ino,'size':5,'mtime_ns':st.st_mtime_ns,'sha256':hashlib.sha256(b'known').hexdigest()}], 'backing_edges':[], 'tool_evidence':[{'executable':'/usr/bin/qemu-img','source':'installed','sha256':'a'*64,'version':'fixture','argv':[],'result_artifact':'fixture'}]}
    expected={'identity':{'host':'h'},'d04_receipt_sha256':'d'*64,'window_receipt_sha256':'w'*64,'retained_manifest_sha256':'m'*64,'excluded_old_qcl_set_sha256':'e'*64}
    assert api['verify_graph'](graph,expected,str(tmp_path),10,100,lambda vol:str(tmp_path/'disk'))
    with pytest.raises(ValueError):api['verify_graph'](graph,expected,str(tmp_path),10,100,lambda vol:str(tmp_path/'wrong'))
    node.write_bytes(b'other')
    with pytest.raises(ValueError):api['verify_graph'](graph,expected,str(tmp_path),10,100,lambda vol:str(tmp_path/'disk'))
    graph['complete']=False
    with pytest.raises(ValueError):api['verify_graph'](graph,expected,str(tmp_path),10,100,lambda vol:str(tmp_path/'disk'))


def test_review_finite_slot_reservations():
    api=review_body('cutover_command_boundary')
    import yaml
    play=yaml.safe_load((BASE/'ansible/proxmox-storage-cutover.yml').read_text())[0]
    slots=play['vars']['cutover_slots']
    assert len(slots)<=90 and len(set(slots))==len(slots)
    amounts=api['reservation_totals']({'hash_bytes':7,'reference_hash_bytes':11,'copy_bytes':13,'metadata_read_bytes':17,'request_bytes':19,'output_bytes':23},5,29)
    assert amounts=={'read':6*7+17*5+3*11+4*13+90*17,'write':2*13+90*29,'output':90*23}
    seen=set()
    api['charge_slot']('a',seen,{'read':10,'write':10,'output':10},{'read':1,'write':1,'output':1})
    with pytest.raises(ValueError):api['charge_slot']('a',seen,{'read':10,'write':10,'output':10},{'read':1,'write':1,'output':1})


def review_boundary(request):
    # Subreaper belongs only to a fresh own boundary process, never pytest/controller.
    import subprocess, yaml
    code=yaml.safe_load((BASE/'ansible/proxmox-storage-cutover.yml').read_text())[0]['vars']['cutover_command_boundary']
    result=subprocess.run(['/usr/bin/python','-c',code],input=json.dumps(request),text=True,capture_output=True,timeout=5,start_new_session=True)
    assert result.stdout, result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize('scenario',['complete-reader','complete-original-disabled','complete-disable-changed','complete-add-false','complete-missing-disable','complete-restored'])
def test_review_completed_readonly_current_state(tmp_path,monkeypatch,scenario):
    rc,state,path,source,stage=run_playbook(tmp_path,monkeypatch,scenario)
    assert (rc==0)==(scenario in ('complete-reader','complete-original-disabled','complete-restored'))
    assert not any(x.startswith(('receipt:','CAS:','systemd:','helper-declare:','manifest:','reference:')) or x in ('rename','restore','retained-copy','template') for x in state['trace'])
    for filename,snapshot in state['helper_before'].items():
        file=Path(filename);assert (file.stat().st_ino,file.stat().st_mtime_ns,hashlib.sha256(file.read_bytes()).hexdigest())==tuple(snapshot)


def test_review_physical_mount_and_backing_associations(tmp_path):
    api=review_body('cutover_consumer_scan')
    assert api['mount_aliases'](['1 2 8:1 / / rw - ext4 /dev/root rw','2 1 8:2 / /stage rw - ext4 /dev/image rw'],'8:1',['/source'],'8:2',['/stage'])==[]
    assert api['mount_aliases'](['1 2 8:1 /source/sub /bind rw - ext4 /dev/root rw'],'8:1',['/source'],'8:2',['/stage'])
    assert api['mount_aliases'](['1 2 8:1 /tmp/private /tmp/x rw - ext4 /dev/root rw'],'8:1',['/source'],'8:2',['/stage'])==[]
    with pytest.raises(ValueError):api['mount_aliases'](['1 2 0:1 / /source/sub rw - overlay overlay rw'],'8:1',['/source'],'8:2',['/stage'])


def test_review_source_slot_and_category_invariant():
    import yaml, collections
    play=yaml.safe_load((BASE/'ansible/proxmox-storage-cutover.yml').read_text())[0];found=['clock-bootstrap'];kinds=[];copies=[]
    def walk(tasks):
        for task in tasks:
            op=task.get('vars',{}).get('cutover_operation')
            if op:
                found.append(task['name'].removeprefix('Bounded owning slot '));kinds.append(op['kind'])
                if any('rsync' in item for item in op['argv']):copies.append(op['argv'])
            if 'ansible.builtin.include_tasks' in task:found.append(task['vars']['guard_slot']);kinds.append('mount_guard')
            for key in ('block','rescue','always'):
                if key in task:walk(task[key])
    walk(play['tasks']);assert found==play['vars']['cutover_slots'];assert len(found)==len(set(found))<=90
    c=collections.Counter(kinds);assert c['probe']<=17 and c['mount_guard']<=12 and c['manifest']<=6 and c['reference_check']==3 and len(copies)==1
    for argv in copies:assert '--whole-file' in argv and '--delete' not in argv and '--inplace' not in argv and '/usr/bin/timeout' not in argv


def installed_helper(kind,cfg):
    path=Path(cfg['cutover']['receipt'][kind+'_helper']);expected=(BASE/'ops'/path.name).read_bytes()
    assert path.read_bytes()==expected and stat.S_IMODE(path.stat().st_mode)==0o600
    spec=importlib.util.spec_from_file_location('declared_'+kind,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def independent_maps(monkeypatch,physical,inaccessible=False):
    old_readlink,old_stat=os.readlink,os.stat
    def maps(path):return '/map_files/' in str(path) and str(path).startswith('/proc/'+str(os.getpid())+'/')
    def readlink(path,*a,**kw):
        if maps(path):
            if inaccessible:raise PermissionError('independent mapped metadata inaccessible')
            return str(physical)
        return old_readlink(path,*a,**kw)
    def statmap(path,*a,**kw):
        if maps(path):
            if inaccessible:raise PermissionError('independent mapped metadata inaccessible')
            return old_stat(physical)
        return old_stat(path,*a,**kw)
    monkeypatch.setattr(os,'readlink',readlink);monkeypatch.setattr(os,'stat',statmap)


NB_RED_IDS = [
    'test_native_recovery_stop_does_not_disable',
    'test_recovery_real_consumer_scan_precedes_stop',
    'test_whole_metadata_proc_enumeration_cap_and_deadline',
    'test_whole_reference_metadata_sum_cap',
    'test_receipt_read_multiplicity_is_prepaid',
    'test_eof_waits_for_natural_epilogue',
    'test_reference_relative_inside_manifest',
    'test_receipt_actual_dispatch_prepaid_before_mutation',
    'test_recovery_actual_source_consumer_request',
    'test_reference_actual_body_graph_and_paths_whole_cap',
    'test_final_unit_independent_literal_oracle',
]


def nb_graph(tmp_path):
    root=tmp_path/'tree';root.mkdir();(root/'disk').write_bytes(b'known')
    manifest={'schema':1,'entries':{'.':{'type':'directory'},'disk':{'type':'file'}},'summary':{}}
    graph={'schema':'qcl.storage-cutover.references.v1','accepted':True,'complete':True,'identity':{'host':'h'},'d04_receipt_sha256':'d'*64,'window_receipt_sha256':'w'*64,'retained_manifest_sha256':'m'*64,'excluded_old_qcl_set_sha256':'e'*64,'volume_bindings':[],'absolute_bindings':[{'id':'absolute','path':str(root/'disk'),'relative':'disk','type':'file','ownership':'retained'}],'backing_nodes':[],'backing_edges':[],'tool_evidence':[{'executable':'/usr/bin/qemu-img','source':'installed','sha256':'a'*64,'version':'fixture','argv':[],'result_artifact':'fixture'}]}
    expected={k:graph[k] for k in ('identity','d04_receipt_sha256','window_receipt_sha256','retained_manifest_sha256','excluded_old_qcl_set_sha256')}
    return root,manifest,graph,expected


def test_native_recovery_stop_does_not_disable(tmp_path,monkeypatch):
    rc,state,*_=run_playbook(tmp_path,monkeypatch,'nb-restore-after-enable')
    assert 'systemd:enable' in state['trace'],state['trace']
    assert 'CAS:reopen-original' in state['trace'],state['trace']
    assert state['unit_enabled'] is False,'native stop does not disable enabled final unit'
    assert 'systemd:disable' in state['trace']


def test_recovery_real_consumer_scan_precedes_stop(tmp_path,monkeypatch):
    rc,state,*_=run_playbook(tmp_path,monkeypatch,'nb-restore-after-enable')
    assert 'systemd:enable' in state['trace'],state['trace']
    assert state.get('recovery_measurement') is True,'pre-stop recovery action64 skipped consumer measurement'


def test_whole_metadata_proc_enumeration_cap_and_deadline(tmp_path,monkeypatch):
    api=review_body('cutover_command_boundary')
    if 'MetadataBudget' not in api:raise AssertionError('own cleanup/proc lacks shared bounded metadata accessor')
    if 'budget' not in api['group_members'].__code__.co_varnames:raise AssertionError('actual group enumeration does not accept shared bounded cleanup context')
    proc=tmp_path/'proc';proc.mkdir();records=16
    for index in range(records):
        node=proc/str(index+100);node.mkdir()
        fields=['S','1','77','77']+['0']*15+['123']+['0']*8
        (node/'stat').write_text(str(index+100)+' (own fixture) '+' '.join(fields)+'\n')
    calls=[]
    class FixtureProcBudget(api['MetadataBudget']):
        def names(self,path):
            assert str(path)=='/proc';calls.append(('enumerate',str(path)));return super().names(proc)
        def read(self,path,maximum):
            parts=Path(path).parts;assert parts[1]=='proc' and parts[-1]=='stat';calls.append(('read',str(path)));return super().read(proc/parts[-2]/'stat',maximum)
    budget=FixtureProcBudget(1024,__import__('time').monotonic()+1)
    with pytest.raises(ValueError,match='metadata'):api['group_members'](77,123,budget=budget)
    assert calls and any(kind=='read' for kind,_ in calls) and len([x for x in calls if x[0]=='read'])<records
    # Expire DURING the actual pass, after one complete stat record, not at entry.
    original_time=api['time'];clock={'now':0.0};deadline_calls=[]
    class DeterministicTime:
        def monotonic(self):return clock['now']
        def __getattr__(self,key):return getattr(original_time,key)
    monkeypatch.setitem(api,'time',DeterministicTime())
    class DuringPassBudget(FixtureProcBudget):
        def names(self,path):
            deadline_calls.append(('enumerate',str(path)))
            return super().names(path)
        def read(self,path,maximum):
            deadline_calls.append(('read-accessor',str(path)))
            value=super().read(path,maximum)
            clock['now']=2.0
            return value
    expiring=DuringPassBudget(8192,1.0)
    with pytest.raises(ValueError,match='deadline'):api['group_members'](77,123,budget=expiring)
    assert len([x for x in deadline_calls if x[0]=='read-accessor'])==1,deadline_calls
    assert len([x for x in deadline_calls if x[0]=='enumerate'])==1,deadline_calls
    (tmp_path/'proc-events.json').write_text(json.dumps({'cap':calls,'during_pass_deadline':deadline_calls}))


def test_whole_reference_metadata_sum_cap(tmp_path):
    api=review_body('cutover_command_boundary')
    if 'MetadataBudget' not in api:raise AssertionError('reference graph/path outputs lack one shared child allowance')
    budget=api['MetadataBudget'](300,__import__('time').monotonic()+1);budget.charge(200)
    for _ in range(3):budget.charge(25)
    with pytest.raises(ValueError,match='metadata'):budget.charge(26)


@pytest.mark.parametrize('action,factor',[('inspect',1),('transition',4),('persist_manifest',2),('read_manifest',1),('sync_manifest',3)])
def test_receipt_read_multiplicity_is_prepaid(action,factor):
    api=review_body('cutover_command_boundary')
    if 'helper_metadata_bound' not in api:raise AssertionError('receipt4B/2B/3B explicit IO not prepaid')
    request={'action':action,'max_bytes':128}
    assert api['helper_metadata_bound']('receipt',request,10,20)>=factor*128+30


def test_eof_waits_for_natural_epilogue(tmp_path):
    witness=tmp_path/'epilogue'
    code="import os,time;os.close(1);os.close(2);time.sleep(.15);open("+repr(str(witness))+",'w').write('finished')"
    result=review_boundary(review_request(['/usr/bin/python','-c',code],seconds=3))
    assert result['status']=='ok',result
    assert not result['cleanup']['term_sent'] and not result['cleanup']['kill_sent']
    assert witness.read_text()=='finished'


@pytest.mark.parametrize('case',['absolute','empty','parent','noncanonical','outside','missing','type','valid'])
def test_reference_relative_inside_manifest(tmp_path,case):
    api=review_body('cutover_reference_check');root,manifest,graph,expected=nb_graph(tmp_path)
    binding=graph['absolute_bindings'][0]
    if case=='absolute':binding.update(relative=str(root/'disk'),path=str(root/'disk'))
    elif case=='empty':binding.update(relative='',path=str(root))
    elif case=='parent':binding.update(relative='../disk',path=str(tmp_path/'disk'))
    elif case=='noncanonical':binding.update(relative='./disk',path=str(root/'./disk'))
    elif case=='outside':binding.update(path=str(tmp_path/'disk'))
    elif case=='missing':manifest['entries'].pop('disk')
    elif case=='type':manifest['entries']['disk']['type']='symlink'
    parameters=__import__('inspect').signature(api['verify_graph']).parameters
    def invoke():
        args=(graph,expected,str(root),20,100,lambda vol:str(root/'disk'))
        return api['verify_graph'](*args,retained_manifest=manifest) if 'retained_manifest' in parameters else api['verify_graph'](*args)
    if case=='valid':assert invoke()
    else:
        with pytest.raises(ValueError):invoke()


def native_boolean(value):
    # Independently specified finite fixture values observed by installed PVE parser.
    assert type(value) in (str,int,bool)
    if value in (True,1,'1','yes','true'):return True
    if value in (False,0,'0','no','false'):return False
    raise AssertionError('unresolved native boolean')


def native_mountpoint(raw,path):
    if raw is None:return None
    if raw in ('1','yes','true',True,1):return path
    if raw in ('0','no','false',False,0):return None
    assert type(raw) is str and raw.startswith('/') and os.path.normpath(raw)==raw
    return raw


def test_receipt_actual_dispatch_prepaid_before_mutation(tmp_path):
    receipt=receipt_dir(tmp_path);script=receipt.parent/'host_storage_receipt.py'
    script.write_bytes((BASE/'ops'/'host_storage_receipt.py').read_bytes());script.chmod(0o600)
    request=review_request(output=262144);request['bounds']['metadata_read_bytes']=524288
    request['operation'].update(kind='receipt_io',argv=['/usr/bin/python',str(script)],mutation=True)
    rid=dict(identity(),host_id=request['identity']['host_id'],boot_id=request['identity']['boot_id'],attempt_id=request['identity']['attempt_id'])
    request['operation']['stdin']=json.dumps({'action':'transition','path':str(receipt),'identity':rid,'phase':'admitted','payload':{},'max_bytes':65536,'expected_sha256':None})
    result=review_boundary(request)
    (tmp_path/'dispatcher-refusal.json').write_text(json.dumps(result))
    assert result['status']=='refused' and 'helper metadata' in result['stderr'],result
    assert not receipt.exists(),'upfront helper4B+input/load/readback reservation must refuse before mutation'


@pytest.mark.parametrize('case',['fd','cwd','root','unrelated'])
def test_recovery_actual_source_consumer_request(tmp_path,monkeypatch,case):
    rc,state,*_=run_playbook(tmp_path,monkeypatch,'nb-restore-'+case)
    assert 'systemd:enable' in state['trace']
    evidence=state.get('scan_evidence',[]);assert evidence and evidence[-1]['slot']=='action-64'
    assert evidence[-1]['measured'] is True
    if case=='unrelated':assert not evidence[-1]['refs'] and 'CAS:reopen-original' in state['trace']
    else:
        assert evidence[-1]['refs']
        assert 'systemd:stopped' not in state['trace'][state['trace'].index('systemd:enable')+1:]
        assert 'restore' not in state['trace'] and 'CAS:reopen-original' not in state['trace']


def test_reference_actual_body_graph_and_paths_whole_cap(tmp_path):
    import time
    root=tmp_path/'tree';root.mkdir();directory=root
    for _ in range(14):directory=directory/('d'*220);directory.mkdir()
    entries={'.':{'type':'directory'}}
    for parent in directory.parents:
        if parent==root:break
        entries[str(parent.relative_to(root))]={'type':'directory'}
    entries[str(directory.relative_to(root))]={'type':'directory'}
    graph={'schema':'qcl.storage-cutover.references.v1','accepted':True,'complete':True,'identity':{'host':'h'},'d04_receipt_sha256':'d'*64,'window_receipt_sha256':'w'*64,'retained_manifest_sha256':'m'*64,'excluded_old_qcl_set_sha256':'e'*64,'volume_bindings':[],'absolute_bindings':[],'backing_nodes':[],'backing_edges':[],'tool_evidence':[{'executable':'/usr/bin/qemu-img','source':'installed','sha256':'a'*64,'version':'fixture','argv':[],'result_artifact':'fixture'}]}
    resolution={}
    for index in range(10):
        file=directory/(('f'*180)+str(index));file.write_bytes(b'known');relative=str(file.relative_to(root));entries[relative]={'type':'file'}
        vol='dir:vol'+str(index);graph['volume_bindings'].append({'id':vol,'relative':relative,'storage_id':'dir'});resolution[vol]=str(file)
    manifest={'schema':1,'entries':entries,'summary':{}}
    expected={k:graph[k] for k in ('identity','d04_receipt_sha256','window_receipt_sha256','retained_manifest_sha256','excluded_old_qcl_set_sha256')}
    child_allowance=4194304
    graphpath=tmp_path/'graph.json'
    witness=tmp_path/'native-path-events'
    prefix=f"""import os,subprocess,sys
_original_lstat=os.lstat
class RootRecord:
 def __init__(self,value):self.value=value
 def __getattr__(self,key):return 0 if key=='st_uid' else getattr(self.value,key)
def fixture_lstat(path,*a,**kw):
 value=_original_lstat(path,*a,**kw);return RootRecord(value) if str(path)=={str(graphpath)!r} else value
os.lstat=fixture_lstat
_original_popen=subprocess.Popen
_resolutions={resolution!r}
def fixture_popen(argv,*a,**kw):
 if argv[0]=='/usr/sbin/pvesm':
  assert argv[1]=='path' and len(argv)==3
  with open({str(witness)!r},'a') as trace:trace.write(argv[2]+chr(10))
  argv=['/usr/bin/python','-c','print('+repr(_resolutions[argv[2]])+')']
 return _original_popen(argv,*a,**kw)
subprocess.Popen=fixture_popen
"""
    play=yaml.safe_load((BASE/'ansible/proxmox-storage-cutover.yml').read_text())[0]
    body=play['vars']['cutover_reference_check'];boundary=play['vars']['cutover_command_boundary']
    request=review_request(output=262144);request['bounds'].update(metadata_read_bytes=8388608,native_commands=16)
    context={'h':{'tools':{'pvesm':'/usr/sbin/pvesm'},'cutover':{'limits':{'metadata_read_bytes':8388608,'reference_entries':128,'reference_hash_bytes':1048576},'preconditions':{'references_receipt':{'path':str(graphpath),'sha256':'0'*64}},'source':{'path':str(root)}}},'boundary':boundary,'expected':expected,'retained_manifest':manifest}
    # Recompute from the FULL concrete final child stdin, including current boundary source.
    # Two path results plus 8KiB retain bounded header/accessor headroom; all ten exceed it.
    context_bytes=len(json.dumps(context).encode('utf-8'))
    path_bytes=[len((path+'\n').encode('utf-8')) for path in resolution.values()]
    headroom=sum(path_bytes[:2])+8192
    target=child_allowance-context_bytes-headroom
    base_graph_bytes=len(json.dumps(graph).encode('utf-8'))
    assert target>base_graph_bytes and all(n<child_allowance for n in path_bytes)
    graph['tool_evidence'][0]['source']='installed:'+('p'*(target-base_graph_bytes-len('installed:')+len('installed')))
    raw=json.dumps(graph).encode('utf-8');assert len(raw)==target
    graphpath.write_bytes(raw);graphpath.chmod(0o600)
    context['h']['cutover']['preconditions']['references_receipt']['sha256']=hashlib.sha256(raw).hexdigest()
    serialized=json.dumps(context)
    assert len(serialized.encode('utf-8'))==context_bytes
    assert context_bytes+len(raw)<child_allowance<context_bytes+len(raw)+sum(path_bytes)
    request['operation'].update(kind='reference_check',argv=['/usr/bin/python','-c',prefix+body],stdin=serialized)
    assert len(json.dumps(request).encode('utf-8'))<=request['bounds']['request_bytes']
    (tmp_path/'reference-cap-plan.json').write_text(json.dumps({'child_allowance':child_allowance,'full_context_bytes':context_bytes,'graph_bytes':len(raw),'path_result_bytes':path_bytes,'headroom':headroom}))
    result=review_boundary(request)
    (tmp_path/'reference-cap-result.json').write_text(json.dumps(result))
    assert result['status']=='refused' and 'metadata' in result['stderr'],result
    count=len(witness.read_text().splitlines()) if witness.exists() else 0
    assert 0<count<10,'actual graph/path shared counter must refuse before further native lookup'


@pytest.mark.parametrize('case',['valid','wrong-destination','wrong-content','existing-mismatch','existing-symlink','existing-exact'])
def test_final_unit_independent_literal_oracle(tmp_path,case):
    source=tmp_path/'source';surrogate=tmp_path/'unit'
    args={'dest':'/etc/systemd/system/fixture-source.mount','content':fixture_final_unit_bytes(source).decode('utf-8'),'mode':'0644'}
    if case=='wrong-destination':args['dest']='/etc/systemd/system/wrong.mount'
    if case=='wrong-content':args['content']=args['content'].replace('LazyUnmount=no','LazyUnmount=yes')
    if case=='existing-mismatch':surrogate.write_bytes(b'foreign unit');surrogate.chmod(0o644)
    if case=='existing-symlink':surrogate.symlink_to(tmp_path/'missing')
    if case=='existing-exact':surrogate.write_bytes(fixture_final_unit_bytes(source));surrogate.chmod(0o644)
    before=(os.lstat(surrogate).st_ino,os.lstat(surrogate).st_mtime_ns) if os.path.lexists(surrogate) else None
    if case in ('valid','existing-exact'):
        fixture_declare_final_unit(args,surrogate,source)
        assert surrogate.read_bytes()==fixture_final_unit_bytes(source)
        if before:assert before==(surrogate.stat().st_ino,surrogate.stat().st_mtime_ns)
    else:
        with pytest.raises(AssertionError):fixture_declare_final_unit(args,surrogate,source)
        if before:assert before==(os.lstat(surrogate).st_ino,os.lstat(surrogate).st_mtime_ns)
        else:assert not os.path.lexists(surrogate)


@pytest.mark.parametrize('order',['policy-first','digest-first'])
@pytest.mark.parametrize('option,value',[('--disable','1'),('--is_mountpoint','yes'),('--delete','disable'),('--delete','is_mountpoint')],ids=['disable-true','mountpoint-yes','delete-disable','delete-mountpoint'])
def test_fixture_pvesm_native_pair_order_and_readback(order,option,value):
    policy=[option,value];digest=['--digest','a'*40]
    argv=['/usr/sbin/pvesm','set','fixture-dir']+(policy+digest if order=='policy-first' else digest+policy)
    original={'type':'dir','path':'/fixture/source','disable':'no','is_mountpoint':'/fixture/source'}
    parsed=fixture_pvesm_policy(argv,'fixture-dir','a'*40)
    assert parsed==(option,value)
    changed=fixture_pvesm_effect(original,*parsed)
    assert changed['path']==original['path'] and changed['type']==original['type']
    if option=='--delete':assert value not in changed
    else:assert changed[option[2:]]==value
    assert original['disable']=='no' and original['is_mountpoint']=='/fixture/source'


@pytest.mark.parametrize('case',['duplicate-digest','duplicate-policy','unknown','wrong-digest','wrong-id','non-string','missing-pair'])
def test_fixture_pvesm_invalid_native_pairs_have_no_effect(case):
    argv=['/usr/sbin/pvesm','set','fixture-dir','--disable','1','--digest','a'*40]
    if case=='duplicate-digest':argv[3:5]=['--digest','a'*40]
    elif case=='duplicate-policy':argv[5:]=['--disable','0']
    elif case=='unknown':argv[3]='--force'
    elif case=='wrong-digest':argv[6]='b'*40
    elif case=='wrong-id':argv[2]='foreign-dir'
    elif case=='non-string':argv[4]=1
    elif case=='missing-pair':argv=argv[:-2]
    original={'type':'dir','path':'/fixture/source','disable':'no'}
    with pytest.raises(AssertionError):
        parsed=fixture_pvesm_policy(argv,'fixture-dir','a'*40)
        fixture_pvesm_effect(original,*parsed)
    assert original=={'type':'dir','path':'/fixture/source','disable':'no'}


def test_fixture_pvesm_literal_mountpoint_path_preserves_native_value():
    path='/fixture/source'
    parsed=fixture_pvesm_policy(['/usr/sbin/pvesm','set','fixture-dir','--is_mountpoint',path,'--digest','a'*40],'fixture-dir','a'*40)
    assert fixture_pvesm_effect({'type':'dir'},*parsed)=={'type':'dir','is_mountpoint':path}
