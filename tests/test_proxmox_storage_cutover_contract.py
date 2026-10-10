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


def fixture_actual_rescue_candidate(variables):
    # Evaluate only actual owning fact expressions, never a copied classifier/full play.
    from ansible.template import Templar, trust_as_template
    data=yaml.safe_load((BASE/'ansible/proxmox-storage-cutover.yml').read_text())
    found=[]
    def visit(tasks):
        for task in tasks:
            if task.get('name')=='Capture original public rescue failure before receipt reread':found.append(task)
            if task.get('name') in ('Require exact original post-observation assert shape','Select only two bound original assertion origins',
                'Select unique original raw slot register','Decode only bounded successful original raw slot',
                'Require exact own completed original envelope','Decode only own successful original comparison payload',
                'Admit only exact negative comparison evidence','Choose immutable pre-marker candidate before any recovery observation'):found.append(task)
            for key in ('block','rescue','always'):
                if key in task:visit(task[key])
    visit(data[0]['tasks']);assert len(found)==9 and len({x['name'] for x in found})==9
    scope=dict(variables)
    for task in found:
        assert 'ansible.builtin.set_fact' in task
        templar=Templar(variables=scope);conditions=task.get('when',[])
        if isinstance(conditions,str):conditions=[conditions]
        if not all(templar.template(trust_as_template('{{ '+condition+' }}')) is True for condition in conditions):continue
        scope.update({k:templar.template(trust_as_template(v)) if isinstance(v,str) else v for k,v in task['ansible.builtin.set_fact'].items()})
    return scope['pre_marker_recovery_candidate']


def fixture_probe_consumer_code(rendered_probe):
    # Select actual native nodes; no imports, native main or copied guard predicate.
    import ast
    assert type(rendered_probe) is str and len(rendered_probe.encode()) <= 262144
    tree=ast.parse(rendered_probe)
    needs=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='need']
    modes=[node for node in tree.body if isinstance(node,ast.Assign) and
           any(isinstance(target,ast.Name) and target.id=='read_only_resume' for target in node.targets)]
    guards=[node for node in tree.body if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call) and
            isinstance(node.value.func,ast.Name) and node.value.func.id=='need' and
            any(isinstance(arg,ast.Constant) and arg.value=='live original/source/stage references' for arg in node.value.args)]
    assert len(needs)==len(modes)==len(guards)==1, 'unique actual probe consumer nodes'
    need,mode,guard=needs[0],modes[0],guards[0]
    expected_need=ast.parse('def need(condition,message):\n if not condition: raise ValueError(message)').body[0]
    assert ast.dump(need,include_attributes=False)==ast.dump(expected_need,include_attributes=False), 'actual need raises ValueError only'
    assert len(mode.targets)==1 and isinstance(mode.targets[0],ast.Name) and mode.targets[0].id=='read_only_resume'
    mode_types=(ast.Assign,ast.Name,ast.Store,ast.Load,ast.BoolOp,ast.Or,ast.And,ast.Subscript,ast.Constant)
    assert all(isinstance(node,mode_types) for node in ast.walk(mode)), 'bounded native mode AST'
    assert {node.id for node in ast.walk(mode.value) if isinstance(node,ast.Name)}=={'r','receipt_present'}
    assert all(isinstance(node.value,ast.Name) and node.value.id=='r' and isinstance(node.slice,ast.Constant) and
               node.slice.value in ('observe_only','initial') for node in ast.walk(mode) if isinstance(node,ast.Subscript))
    assert all(node.value in ('observe_only','initial') for node in ast.walk(mode) if isinstance(node,ast.Constant))
    guard_types=(ast.Expr,ast.Call,ast.Name,ast.Load,ast.BoolOp,ast.Or,ast.UnaryOp,ast.Not,ast.Constant)
    assert all(isinstance(node,guard_types) for node in ast.walk(guard)), 'bounded native guard AST'
    assert {node.id for node in ast.walk(guard) if isinstance(node,ast.Name)}=={'need','read_only_resume','refs'}
    assert len(guard.value.args)==2 and not guard.value.keywords and isinstance(guard.value.args[1],ast.Constant)
    assert guard.value.args[1].value=='live original/source/stage references'
    assert sum(isinstance(node,ast.Call) for node in ast.walk(guard))==1
    return (compile(ast.Module(body=[mode],type_ignores=[]),'<actual-probe-mode>','exec'),
            compile(ast.Module(body=[need,guard],type_ignores=[]),'<actual-probe-guard>','exec'),
            hashlib.sha256(rendered_probe.encode()).hexdigest())


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
    if scenario == "success":
        # Exercise the inactive branch in the existing case; preserve the bound point and seed.
        def source_seed_identity():
            root_info = source.stat(); seed = source / "disk.raw"; seed_info = seed.stat()
            return {"source_dev": root_info.st_dev, "source_ino": root_info.st_ino,
                    "dev": seed_info.st_dev, "ino": seed_info.st_ino, "size": seed_info.st_size,
                    "mtime_ns": seed_info.st_mtime_ns, "sha256": hashlib.sha256(seed.read_bytes()).hexdigest()}
        seed_before = source_seed_identity()
        (stage / "disk.raw").unlink()
        state["stage_active"] = False
        point = stage.lstat(); seed_after = source_seed_identity()
        assert seed_after == seed_before
        assert (point.st_dev, point.st_ino) == (cfg["stage"]["path_dev"], cfg["stage"]["path_ino"])
        state["initial_stage_evidence"] = {"active": state["stage_active"], "empty": not any(stage.iterdir()),
            "type": stat.S_IFMT(point.st_mode), "dev": point.st_dev, "ino": point.st_ino,
            "bound_dev": cfg["stage"]["path_dev"], "bound_ino": cfg["stage"]["path_ino"],
            "seed_before": seed_before, "seed_after": seed_after}
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
                    if outer_request["slot_id"] == "action-16":
                        assert operation["kind"] == "native_argv" and argv == ["/usr/bin/systemctl", "start", "fixture-stage.mount"]
                        assert operation["stdin"] == "" and operation["mutation"] is True
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
                            assert result["sha256"]==s["reference_canonical_sha"]
                            s["persisted_manifest_sha"]=result["sha256"]
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
                    reference_request=json.loads(args["stdin"]);assert set(reference_request)=={"h","boundary","expected","retained_manifest"}
                    assert reference_request["h"]["attempt_id"]==cfg["attempt_id"]
                    manifest=reference_request["retained_manifest"];expected=reference_request["expected"]
                    independently_expected={"identity":{"host_id":cfg["host_id"],"boot_id":cfg["boot_id"],"attempt_id":cfg["attempt_id"],"window_owner":cfg["cutover"]["window"]["owner"],"window_expiry":cfg["cutover"]["window"]["expires_at_epoch"],"source_dev":cfg["cutover"]["source"]["dev"],"source_ino":cfg["cutover"]["source"]["ino"],"parent_dev":cfg["cutover"]["source"]["parent_dev"],"parent_ino":cfg["cutover"]["source"]["parent_ino"],"storage_id":"fixture-dir","path":str(source),"lv_uuid":"fixture-lv","fs_uuid":UUID},"d04_receipt_sha256":"d"*64,"window_receipt_sha256":"c"*64,"excluded_old_qcl_set_sha256":"0"*64}
                    if outer_request["slot_id"]=="action-21":
                        s["reference_manifest_before"]=manifest
                        canonical=json.dumps(manifest,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("utf-8")+bytes([10])
                        s["reference_canonical_sha"]=hashlib.sha256(canonical).hexdigest()
                        assert canonical[-1:]==bytes([10]) and canonical[-2:]!=b"\\n"
                    else:
                        persisted=Path(cfg["cutover"]["receipt"]["manifest_path"]).read_bytes()
                        assert hashlib.sha256(persisted).hexdigest()==s["reference_canonical_sha"]
                        assert manifest["entries"]==s["reference_manifest_before"]["entries"]
                    independently_expected["retained_manifest_sha256"]=s["reference_canonical_sha"]
                    assert expected==independently_expected,"actual rendered reference context differs from independent immutable graph oracle"
                    s.setdefault("reference_evidence",[]).append({"slot":outer_request["slot_id"],"expected":expected,"manifest_identity":manifest["identity"],"canonical_sha":s["reference_canonical_sha"]})
                    record("reference:"+name)
                    native_graph_context=dict(independently_expected)
                    if scenario=="reference-wrong-sha":native_graph_context["retained_manifest_sha256"]="f"*64
                    s["native_graph_context"]=native_graph_context
                    if native_graph_context!=expected:out.update(failed=True,rc=1,stderr="reference context retained_manifest_sha256: independent graph differs")
                    else:out["stdout"]=json.dumps({"complete":True})
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
                        "healthy": True, "stage_active": s["stage_active"], "final_active": s["final_active"], "fs_uuid": UUID,
                        "device": "/dev/dm-0", "rdev": 253, "mountpoint_dev": source.stat().st_dev, "mountpoint_ino": source.stat().st_ino, "Where": observation_request.get("path", str(source)), "Type": "ext4", "ActiveState": "active" if (s["stage_active"] if observation_request.get("stage", False) else s["final_active"]) else "inactive", "UnitFileState": "static" if observation_request.get("stage", False) else "enabled" if s["unit_enabled"] else "disabled", "stage_policy": "static", "source_renamed": s["renamed"],
                        "ForceUnmount": "no", "LazyUnmount": "no", "DropInPaths": "", "NeedDaemonReload": "no",
                        "Options": "nosuid,rw,relatime,nodev,data=ordered", "fragment_exact": True,
                        "seed_sha256": hashlib.sha256(b"AAAA").hexdigest(), "is_mountpoint_raw": s["offline_raw"], "mountpoint_guard": "/wrong" if scenario.startswith(("nb-restore","nb-disable")) and name=="Observe native offline policy and disabled gate before reopen" else native_mountpoint(s["offline_raw"],str(source)), "storage_disabled": s["disabled"], "original_disabled": cfg["cutover"]["storage"]["stanza"].get("disable") in (1,"1","yes",True),
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
                    if outer_request["slot_id"]=="guard-15":
                        valid=dict(observed)
                        if scenario in NAMED_NEGATIVE_GUARDS:
                            field=NAMED_NEGATIVE_GUARDS[scenario][1]
                            if scenario in UNIT_NEGATIVE_VALUES:observed[field]=UNIT_NEGATIVE_VALUES[scenario]
                        delta={key:[valid[key],value] for key,value in observed.items() if valid[key]!=value}
                        s["guard15_evidence"]={"slot":"guard-15","request":observation_request,"valid":valid,"observation":observed,"delta":delta}
                        out["stdout"]=json.dumps(observed)
                    if outer_request and outer_request["operation"]["kind"]=="probe":
                        mode_code,guard_code,probe_sha=fixture_probe_consumer_code(operation['argv'][2])
                        assert probe_sha==body_sha and probe_sha in source_body_hashes
                        receipt_present=os.path.lexists(receipt)
                        mode_scope={'r':observation_request,'receipt_present':receipt_present,'__builtins__':{}}
                        exec(mode_code,mode_scope);mode=mode_scope['read_only_resume']
                        if "consumers_measured" in task_vars["cutover_native_probe"]:
                            observed.update(consumers_measured=not mode,refs=None if mode else observed["refs"])
                        if observation_request.get("final_policy_readback"):
                            observed["final_policy"]={"ActiveState":"active" if s["final_active"] else "inactive","UnitFileState":"enabled" if s["unit_enabled"] else "disabled","FragmentPath":"/etc/systemd/system/fixture-source.mount","NeedDaemonReload":"no"}
                            if scenario=="nb-disable-readback-enabled":observed["final_policy"]["UnitFileState"]="enabled"
                        if name=="Reconcile actual fixed config mount units and callers read-only":
                            s["recovery_measurement"]=not mode
                            if not mode:
                                scanner_api=review_body("cutover_consumer_scan");scanner=scanner_api["consumer_refs"]
                                holder=None;previous_cwd=os.getcwd()
                                unrelated=tmp_path/"unrelated-map";unrelated.write_bytes(b"ordinary unrelated metadata")
                                maps_patch=pytest.MonkeyPatch();independent_maps(maps_patch,unrelated)
                                try:
                                    target=source if scenario in ("nb-restore-fd","nb-restore-cwd","nb-restore-root") else tmp_path
                                    if scenario=="nb-restore-cwd":os.chdir(target)
                                    elif scenario in ("nb-restore-fd","nb-restore-root","nb-restore-unrelated"):holder=os.open(target,os.O_RDONLY|os.O_DIRECTORY)
                                    observed["refs"]=scanner(scanner_api["consumer_roots"](tmp_path/"original" if s["renamed"] else source,source,stage),cfg["cutover"]["limits"]["entries"],cfg["cutover"]["limits"]["metadata_read_bytes"],5,pids=[os.getpid()])
                                    observed["consumers_measured"]=True
                                    s.setdefault("scan_evidence",[]).append({"slot":outer_request["slot_id"],"roots":[str(x) for x in scanner_api["consumer_roots"](tmp_path/"original" if s["renamed"] else source,source,stage)],"measured":True,"refs":observed["refs"],"case":scenario,"physical_root":"ordinary directory root FD; process /root remains actual unrelated /"})
                                finally:
                                    if holder is not None:os.close(holder)
                                    os.chdir(previous_cwd);maps_patch.undo()
                        if scenario.startswith("new-point-") and not mode and s["renamed"] and not s["final_active"] and outer_request["slot_id"]=="action-42":
                            api=review_body("cutover_consumer_scan");roots=api["consumer_roots"](tmp_path/"original",source,stage)
                            holder=None;previous=os.getcwd();mapping=tmp_path/"unrelated-map";mapping.write_bytes(b"ordinary map metadata")
                            maps_patch=pytest.MonkeyPatch();independent_maps(maps_patch,mapping)
                            try:
                                if scenario=="new-point-cwd":os.chdir(source)
                                else:holder=os.open(source,os.O_RDONLY|os.O_DIRECTORY)
                                observed["refs"]=api["consumer_refs"](roots,cfg["cutover"]["limits"]["entries"],cfg["cutover"]["limits"]["metadata_read_bytes"],5,pids=[os.getpid()])
                                s["point_scan_evidence"]={"slot":"action-42","roots":[str(x) for x in roots],"source_inode":source.stat().st_ino,"original_inode":(tmp_path/"original").stat().st_ino,"refs":observed["refs"]}
                            finally:
                                if holder is not None:os.close(holder)
                                os.chdir(previous);maps_patch.undo()
                        if outer_request["slot_id"]=="action-1":s["initial_observation"]=observed
                        if outer_request["slot_id"]=="action-17":
                            s["stage17_evidence"]={"slot":"action-17", **{key:observed[key] for key in ("stage_active","final_active","fs_uuid","rdev")}}
                        guard_scope={'read_only_resume':mode,'refs':observed['refs'],'__builtins__':{'ValueError':ValueError}}
                        try:
                            exec(guard_code,guard_scope)
                        except ValueError as error:
                            out.update(failed=True,rc=1,stdout='',stderr=str(error),boundary_status='refused')
                        else:
                            out["stdout"]=json.dumps(observed)
                        s.setdefault('probe_consumer_evidence',[]).append({'slot':outer_request['slot_id'],
                            'body_sha256':probe_sha,'observe_only':observation_request['observe_only'],
                            'initial':observation_request['initial'],'receipt_present':receipt_present,'mode':mode,
                            'consumers_measured':observed['consumers_measured'],
                            'refs_count':None if observed['refs'] is None else len(observed['refs']),
                            'status':'refused' if out.get('failed') else 'passed'})
                    record("observe:" + name)
                else: raise AssertionError("Unrecognized native command " + name + " " + str(argv))
            elif effective_action == "ansible.builtin.systemd_service":
                verb=args["verb"];assert verb in ("start","stop","enable","disable","daemon-reload")
                assert verb=="daemon-reload" or args["name"] in ("fixture-stage.mount","fixture-source.mount")
                if args["name"]=="fixture-source.mount":assert s["unit_declared"], "absent final unit reached systemd before declaration"
                s.setdefault("systemd_events",[]).append({"slot":outer_request["slot_id"],"verb":verb,"unit":args["name"],"trace_index":len(s["trace"])})
                record("systemd:"+{"start":"started","stop":"stopped","disable":"disable","enable":"enable","daemon-reload":"reload"}[verb])
                if args["name"]=="fixture-source.mount":
                    if verb=="disable" and scenario=="nb-disable-unknown":out.update(failed=True,rc=1,stderr="unknown own disable outcome",boundary_status="native_outcome_unknown")
                    elif verb in ("enable","disable"):s["unit_enabled"]=verb=="enable"
                    if verb in ("start","stop"):s["final_active"]=verb=="start"
                if args["name"]=="fixture-stage.mount" and verb in ("start","stop"):s["stage_active"]=verb=="start"
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
            if outer_request is not None and out.get("failed"):
                s.setdefault("native_failures",[]).append({"slot":outer_request["slot_id"],"rc":out.get("rc"),"stderr":out.get("stderr",""),"status":out.get("boundary_status","refused")})
            if outer_request is not None:
                native=dict(out);payload={"schema":outer_request["schema"],"slot_id":outer_request["slot_id"],"identity":outer_request["identity"],"clock":outer_request["clock"],"status":native.get("boundary_status","refused" if native.get("failed") else "ok"),"returncode":native.get("rc",0),"stdout":native.get("stdout",""),"stderr":native.get("stderr",""),"observed_bytes":{"stdout":len(native.get("stdout","")),"stderr":len(native.get("stderr","")),"metadata":0},"reserved_bytes":outer_request["bounds"],"cleanup":{"pgid":None,"term_sent":False,"kill_sent":False,"reaped":True,"group_absent":True}}
                if native.get('failed'):
                    s.setdefault('failed_envelopes',[]).append({key:payload[key] for key in ('slot_id','status','returncode','stdout','stderr')})
                out["stdout"]=json.dumps(payload)
            state_file.write_text(json.dumps(s))
            return out
    def handler(executor, templar):
        if executor._task.action in ("ansible.builtin.assert", "ansible.builtin.set_fact", "ansible.builtin.debug", "ansible.builtin.fail", "ansible.builtin.include_tasks"):
            action,extra=original(executor,templar)
            if executor._task.action=="ansible.builtin.assert":
                actual_run=action.run
                def observed_assert(*args,**kwargs):
                    result=actual_run(*args,**kwargs);saved=json.loads(state_file.read_text())
                    event={"task":executor._task.name,"failed":bool(result.get("failed")),"assertion":result.get("assertion"),"evaluated_to":result.get("evaluated_to"),"msg":result.get("msg")}
                    if event["failed"] and "first_assert_failure" not in saved:saved["first_assert_failure"]=event
                    if executor._task.name in ("Accept only complete safe loaded policy observation","Match initial fixed native identity and selected digest","Actual stage required before any copy"):saved.setdefault("guard_results",[]).append(event)
                    state_file.write_text(json.dumps(saved));return result
                action.run=observed_assert
            if executor._task.action=='ansible.builtin.set_fact' and executor._task.name in (
                'Capture original public rescue failure before receipt reread',
                'Choose immutable pre-marker candidate before any recovery observation'):
                actual_fact=action.run
                def observed_fact(*args,**kwargs):
                    result=actual_fact(*args,**kwargs);saved=json.loads(state_file.read_text())
                    facts=result.get('ansible_facts',{})
                    if 'cutover_original_failed_task' in facts:
                        task=facts['cutover_original_failed_task'];failure=facts['cutover_original_failed_result']
                        saved['rescue_origin']={'action':task.get('action') if isinstance(task,dict) else None,
                            'name':task.get('name') if isinstance(task,dict) else None,
                            'assertion':failure.get('assertion') if isinstance(failure,dict) else None}
                    if 'pre_marker_recovery_candidate' in facts:
                        saved.setdefault('rescue_candidates',[]).append(facts['pre_marker_recovery_candidate'])
                    state_file.write_text(json.dumps(saved));return result
                action.run=observed_fact
            return action,extra
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



UNIT_NEGATIVE_VALUES={'unsafe-unit':False,'force-unit':'yes','lazy-unit':'yes','dropin-unit':'foreign.conf','reload-unit':'yes','ro-unit':'nosuid,rw,relatime,nodev,data=ordered,ro','unknown-options':'nosuid,rw,relatime,nodev,data=ordered,unknown-option','wrong-type-unit':'xfs','wrong-where-unit':'/fixture/wrong','wrong-uuid-unit':'11111111-2222-3333-4444-555555555555','wrong-rdev-unit':254}
NAMED_NEGATIVE_GUARDS={
 'unsafe-unit':('Accept only complete safe loaded policy observation','fragment_exact',"(mount_guard.stdout | from_json).fragment_exact is sameas true"),
 'force-unit':('Accept only complete safe loaded policy observation','ForceUnmount',"(mount_guard.stdout | from_json).get('ForceUnmount', 'no') == 'no'"),
 'lazy-unit':('Accept only complete safe loaded policy observation','LazyUnmount',"(mount_guard.stdout | from_json).get('LazyUnmount', 'no') == 'no'"),
 'dropin-unit':('Accept only complete safe loaded policy observation','DropInPaths',"(mount_guard.stdout | from_json).get('DropInPaths', '') == ''"),
 'reload-unit':('Accept only complete safe loaded policy observation','NeedDaemonReload',"(mount_guard.stdout | from_json).get('NeedDaemonReload', 'no') == 'no'"),
 'ro-unit':('Accept only complete safe loaded policy observation','Options',"not (['ro','dev','suid'] | intersect((mount_guard.stdout | from_json).get('Options', 'rw,nodev,nosuid').split(',')))"),
 'unknown-options':('Accept only complete safe loaded policy observation','Options',"((mount_guard.stdout | from_json).get('Options', 'rw,nodev,nosuid').split(',') | difference(['rw','nodev','nosuid'] + c.final.allowed_defaults)) | length == 0"),
 'wrong-type-unit':('Accept only complete safe loaded policy observation','Type',"(mount_guard.stdout | from_json).get('absent', false) or (mount_guard.stdout | from_json).Type == 'ext4'"),
 'wrong-where-unit':('Accept only complete safe loaded policy observation','Where',"(mount_guard.stdout | from_json).get('absent', false) or (mount_guard.stdout | from_json).Where == guard_path"),
 'wrong-uuid-unit':('Accept only complete safe loaded policy observation','fs_uuid',"(mount_guard.stdout | from_json).get('absent', false) or (mount_guard.stdout | from_json).fs_uuid == c.final.fs_uuid"),
 'wrong-rdev-unit':('Accept only complete safe loaded policy observation','rdev',"(mount_guard.stdout | from_json).get('absent', false) or (mount_guard.stdout | from_json).rdev == c.final.rdev"),
 'cached-worker':('Match initial fixed native identity and selected digest','workers_relevant',"(admission_live.stdout | from_json).receipt_present or ((admission_live.stdout | from_json).workers_relevant | length == 0)"),
 'old-loop':('Match initial fixed native identity and selected digest','old_loop',"not (admission_live.stdout | from_json).old_loop"),
 'relevant-alias':('Match initial fixed native identity and selected digest','aliases',"(admission_live.stdout | from_json).receipt_present or ((admission_live.stdout | from_json).aliases | length == 0)"),
 'unknown-data':('Match initial fixed native identity and selected digest','data_used_bytes',"(admission_live.stdout | from_json).data_used_bytes is integer"),
}

def assert_named_negative(state,scenario,stage):
    task,field,predicate=NAMED_NEGATIVE_GUARDS[scenario]
    failure=state.get('first_assert_failure');assert failure and failure['task']==task,failure
    assert failure['evaluated_to'] is False and ' '.join(failure['assertion'].split())==' '.join(predicate.split()),failure
    if scenario in UNIT_NEGATIVE_VALUES:
        event=state['guard15_evidence'];assert event['slot']=='guard-15'
        assert event['request']['path']==str(stage) and event['request']['stage'] is True
        assert event['delta']=={field:[event['valid'][field],UNIT_NEGATIVE_VALUES[scenario]]}
        assert 'CAS:disable' in state['trace'] and 'observe:Verify exact loaded mount policy' in state['trace']
        assert not any(x['slot']=='action-16' for x in state['boundary_events'])
        assert not any(x['slot']=='action-17' for x in state['boundary_events'])
    else:
        observed=state['initial_observation'];assert observed['complete'] is True and observed['consumers_measured'] is True
        assert observed[field]=={'cached-worker':['cached-native-worker'],'old-loop':True,'relevant-alias':['source-bind'],'unknown-data':'not_measured'}[scenario]
        assert any(x['slot']=='action-1' for x in state['boundary_events'])
        assert not any(x.startswith(('helper-declare:','receipt:','CAS:')) or x in ('template','retained-copy','rename','restore') for x in state['trace'])

@pytest.mark.parametrize("scenario", ["success", "completion-failure", "unknown-cas", "disabled", "check", "bad-input", "unsafe-unit", "force-unit", "lazy-unit", "dropin-unit", "reload-unit", "ro-unit", "unknown-options", "wrong-type-unit", "wrong-where-unit", "wrong-uuid-unit", "wrong-rdev-unit", "cached-worker", "old-loop", "relevant-alias", "intent-fsync-failure", "intent-dir-fsync-failure", "copy-timeout", "copy-mismatch", "unknown-data", "native-offline-yes", "native-offline-path"])
def test_actual_cutover_yaml_and_sticky_cas_boundary(tmp_path, monkeypatch, scenario):
    rc, state, path, source, stage = run_playbook(tmp_path, monkeypatch, scenario)
    trace = state["trace"]
    if scenario not in ("success", "native-offline-yes", "native-offline-path", "completion-failure", "unknown-cas", "intent-fsync-failure", "intent-dir-fsync-failure", "copy-timeout", "copy-mismatch"):
        assert "retained-copy" not in trace and "rename" not in trace and "CAS:reopen" not in trace
        assert (source / "disk.raw").read_bytes() == b"AAAA"
        assert ("CAS:disable" not in trace) if scenario in ("disabled", "check", "bad-input") else True
        assert (rc == 0) if scenario in ("disabled", "check") else rc != 0
        if scenario in NAMED_NEGATIVE_GUARDS:assert_named_negative(state,scenario,stage)
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
    final_starts = [event for event in state["systemd_events"] if event["verb"]=="start" and event["unit"]=="fixture-source.mount"]
    assert len(final_starts)==1 and trace[final_starts[0]["trace_index"]]=="systemd:started"
    position = [final_starts[0]["trace_index"] if x=="systemd:started" else trace.index(x) for x in required]
    assert position == sorted(position), "missing cutover durable intent/native/observed order"
    if scenario == "success":
        initial = state["initial_stage_evidence"]
        assert initial["active"] is False and initial["empty"] is True and initial["type"]==stat.S_IFDIR
        assert (initial["dev"],initial["ino"])==(initial["bound_dev"],initial["bound_ino"])==(stage.stat().st_dev,stage.stat().st_ino)
        assert initial["seed_before"]==initial["seed_after"] and initial["seed_after"]["sha256"]==hashlib.sha256(b"AAAA").hexdigest()
        assert state["initial_observation"]["stage_active"] is False
        guard=state["guard15_evidence"];assert guard["delta"]=={} and guard["observation"]==guard["valid"]
        assert guard["observation"]["ActiveState"]=="inactive" and guard["observation"]["UnitFileState"]=="static"
        assert guard["request"]["path"]==str(stage) and guard["request"]["stage"] is True
        assert "first_assert_failure" not in state
        assert any(row["task"]=="Accept only complete safe loaded policy observation" and row["failed"] is False for row in state["guard_results"])
        events=state["boundary_events"];slots=[event["slot"] for event in events]
        assert slots.count("guard-15")==slots.count("action-16")==slots.count("action-17")==slots.count("action-18")==1
        assert next(event for event in events if event["slot"]=="action-16")["kind"]=="native_argv"
        assert next(event for event in events if event["slot"]=="action-17")["kind"]=="probe"
        assert slots.index("guard-15")<slots.index("action-16")<slots.index("action-17")<slots.index("action-18")
        stage_starts=[event for event in state["systemd_events"] if event["verb"]=="start" and event["unit"]=="fixture-stage.mount"]
        assert len(stage_starts)==1 and stage_starts[0]["slot"]=="action-16"
        assert stage_starts[0]["trace_index"]<trace.index("manifest:before")<trace.index("retained-copy")
        assert state["stage17_evidence"]=={"slot":"action-17","stage_active":True,"final_active":False,"fs_uuid":UUID,"rdev":253}
        assert any(row["task"]=="Actual stage required before any copy" and row["failed"] is False for row in state["guard_results"])
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
    if name == "cutover_consumer_scan":exec(compile(variables["cutover_command_boundary"], "cutover_command_boundary", "exec"), scope)
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
    original=tmp_path/'source';original.mkdir(); source=original;stage=tmp_path/'stage';stage.mkdir(); sub=stage/'sub';sub.mkdir();other=tmp_path/'other';other.mkdir()
    if target=='inactive-point':original.rename(tmp_path/'rollback');original=tmp_path/'rollback';source.mkdir();assert source.stat().st_ino!=original.stat().st_ino
    maps=tmp_path/'map-unrelated';maps.write_bytes(b'x');independent_maps(monkeypatch,maps)
    opened=source if target=='inactive-point' else stage if target=='stage-root' else sub if target=='stage-subdir' else original if target=='deleted-original' else other
    fd=os.open(opened,os.O_RDONLY|os.O_DIRECTORY)
    if target=='deleted-original': original.rmdir()
    try:
        result=api['consumer_refs'](api['consumer_roots'](original,source,stage),100,8388608,5,pids=[os.getpid()])
        assert bool(result)==(target!='unrelated')
    finally:os.close(fd)


def test_review_reference_semantic_context(tmp_path):
    api=review_body('cutover_reference_check')
    node=tmp_path/'external';node.write_bytes(b'known')
    (tmp_path/'disk').write_bytes(b'known retained bytes')
    manifest={'schema':1,'entries':{'.':{'type':'directory'},'disk':{'type':'file'}}}
    st=node.stat()
    graph={'schema':'qcl.storage-cutover.references.v1','accepted':True,'complete':True,'identity':{'host':'h'},'d04_receipt_sha256':'d'*64,'window_receipt_sha256':'w'*64,'retained_manifest_sha256':'m'*64,'excluded_old_qcl_set_sha256':'e'*64,
        'volume_bindings':[{'id':'dir:disk','relative':'disk','storage_id':'dir'}], 'absolute_bindings':[], 'backing_nodes':[{'id':'ext','ownership':'external','path':str(node),'format':'raw','dev':st.st_dev,'ino':st.st_ino,'size':5,'mtime_ns':st.st_mtime_ns,'sha256':hashlib.sha256(b'known').hexdigest()}], 'backing_edges':[], 'tool_evidence':[{'executable':'/usr/bin/qemu-img','source':'installed','sha256':'a'*64,'version':'fixture','argv':[],'result_artifact':'fixture'}]}
    expected={'identity':{'host':'h'},'d04_receipt_sha256':'d'*64,'window_receipt_sha256':'w'*64,'retained_manifest_sha256':'m'*64,'excluded_old_qcl_set_sha256':'e'*64}
    assert api['verify_graph'](graph,expected,str(tmp_path),10,100,lambda vol:str(tmp_path/'disk'),retained_manifest=manifest)
    with pytest.raises(ValueError):api['verify_graph'](graph,expected,str(tmp_path),10,100,lambda vol:str(tmp_path/'wrong'),retained_manifest=manifest)
    node.write_bytes(b'other')
    with pytest.raises(ValueError):api['verify_graph'](graph,expected,str(tmp_path),10,100,lambda vol:str(tmp_path/'disk'),retained_manifest=manifest)
    graph['complete']=False
    with pytest.raises(ValueError):api['verify_graph'](graph,expected,str(tmp_path),10,100,lambda vol:str(tmp_path/'disk'),retained_manifest=manifest)


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


def review_boundary(request,prefix=""):
    # Subreaper belongs only to a fresh own boundary process, never pytest/controller.
    import subprocess, yaml
    code=yaml.safe_load((BASE/'ansible/proxmox-storage-cutover.yml').read_text())[0]['vars']['cutover_command_boundary']
    result=subprocess.run(['/usr/bin/python','-c',prefix+code],input=json.dumps(request),text=True,capture_output=True,timeout=5,start_new_session=True)
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
    walk(play['tasks']);assert found==play['vars']['cutover_slots'];assert len(found)==len(set(found))==84
    c=collections.Counter(kinds);assert c['probe']<=17 and c['mount_guard']<=12 and c['manifest']<=6 and c['reference_check']==3 and len(copies)==1 and c['native_argv']==14
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
    closed=tmp_path/'closed';witness=tmp_path/'epilogue';wait=tmp_path/'wait-entry'
    code="import os,time;marker=os.open("+repr(str(closed))+",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(1);os.close(2);os.write(marker,b'both closed');os.close(marker);time.sleep(.15);open("+repr(str(witness))+",'x').write('finished')"
    request=review_request(['/usr/bin/env','/usr/bin/python','-c',code],seconds=3)
    assert request['operation']['argv'][1]!='-c' and len(request['operation']['argv'])==4
    prefix="import subprocess,json,os\n_real_popen=subprocess.Popen\ndef witnessed_popen(*a,**kw):\n p=_real_popen(*a,**kw);actual_wait=p.wait\n def observed_wait(*args,**kwargs):\n  if not os.path.exists("+repr(str(wait))+"):\n   with open("+repr(str(wait))+",'x') as log:json.dump({'leader_alive':p.poll() is None,'stdout_closed':not os.path.lexists('/proc/'+str(p.pid)+'/fd/1'),'stderr_closed':not os.path.lexists('/proc/'+str(p.pid)+'/fd/2'),'epilogue_exists':os.path.exists("+repr(str(witness))+"),'telemetry_passed':bool(kw.get('pass_fds'))},log)\n  return actual_wait(*args,**kwargs)\n p.wait=observed_wait;return p\nsubprocess.Popen=witnessed_popen\n"
    import time
    started=time.monotonic();result=review_boundary(request,prefix=prefix);elapsed=time.monotonic()-started
    assert .1<=elapsed<4
    assert result['status']=='ok' and result['returncode']==0 and result['cleanup']['reaped'] and result['cleanup']['group_absent'],result
    assert not result['cleanup']['term_sent'] and not result['cleanup']['kill_sent']
    assert closed.read_text()=='both closed' and witness.read_text()=='finished'
    assert json.loads(wait.read_text())=={'leader_alive':True,'stdout_closed':True,'stderr_closed':True,'epilogue_exists':False,'telemetry_passed':False}


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
    import time,subprocess
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
    request['operation'].update(kind='reference_check',argv=['/usr/bin/python','-c',prefix+body],stdin=json.dumps(context))
    load_api=review_body('cutover_command_boundary')
    prepaid_context=load_api['child_metadata_load_bound'](request)
    target=child_allowance-prepaid_context-headroom
    base_graph_bytes=len(json.dumps(graph).encode('utf-8'))
    assert target>base_graph_bytes and all(n<child_allowance for n in path_bytes)
    graph['tool_evidence'][0]['source']='installed:'+('p'*(target-base_graph_bytes-len('installed:')+len('installed')))
    raw=json.dumps(graph).encode('utf-8');assert len(raw)==target
    graphpath.write_bytes(raw);graphpath.chmod(0o600)
    context['h']['cutover']['preconditions']['references_receipt']['sha256']=hashlib.sha256(raw).hexdigest()
    serialized=json.dumps(context)
    assert len(serialized.encode('utf-8'))==context_bytes
    assert prepaid_context+len(raw)<child_allowance<prepaid_context+len(raw)+sum(path_bytes)
    request['operation'].update(kind='reference_check',argv=['/usr/bin/python','-c',prefix+body],stdin=serialized)
    assert len(json.dumps(request).encode('utf-8'))<=request['bounds']['request_bytes']
    (tmp_path/'reference-cap-plan.json').write_text(json.dumps({'child_allowance':child_allowance,'full_context_bytes':context_bytes,'source_defined_prepaid_context_bytes':prepaid_context,'graph_bytes':len(raw),'path_result_bytes':path_bytes,'headroom':headroom}))
    # Only dispatch/accessor execution spends the real runtime clock.
    now=time.monotonic_ns()
    request['clock'].update(started_monotonic_ns=now,deadline_monotonic_ns=now+3000000000,expires_at_epoch=int(time.time())+60)
    assert load_api['child_metadata_load_bound'](request)==prepaid_context,'refreshed clock changed prepaid load; replan required'
    assert len(json.dumps(request).encode('utf-8'))<=request['bounds']['request_bytes']
    dispatched=subprocess.run(['/usr/bin/python','-c',boundary],input=json.dumps(request),text=True,capture_output=True,timeout=5,start_new_session=True)
    assert dispatched.stdout,dispatched.stderr
    result=json.loads(dispatched.stdout)
    (tmp_path/'reference-cap-result.json').write_text(json.dumps(result))
    assert result['status']=='refused' and 'metadata' in result['stderr'] and 'metadata deadline' not in result['stderr'],result
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


@pytest.mark.parametrize('scenario',['nb-disable-unknown','nb-disable-readback-enabled'])
def test_native_recovery_disable_unknown_or_bad_readback_blocks_reopening(tmp_path,monkeypatch,scenario):
    rc,state,receipt,source,stage=run_playbook(tmp_path,monkeypatch,scenario)
    assert rc!=0
    trace=state['trace'];assert 'systemd:enable' in trace and 'systemd:disable' in trace,trace
    assert 'restore' not in trace and 'CAS:reopen-original' not in trace and 'receipt:complete' not in trace
    assert state['renamed'] and (tmp_path/'original'/'disk.raw').read_bytes()==b'AAAA'
    assert json.loads(receipt.read_text())['reopening'] is None


@pytest.mark.parametrize('case',['relevant','unrelated','inaccessible'])
def test_real_directory_refs_with_independent_maps_boundary(tmp_path,monkeypatch,case):
    api=review_body('cutover_consumer_scan');root=tmp_path/'tree';root.mkdir()
    retained=root/'mapped';retained.write_bytes(b'actual retained inode')
    other=tmp_path/'unrelated';other.write_bytes(b'ordinary external inode')
    independent_maps(monkeypatch,retained if case=='relevant' else other,inaccessible=case=='inaccessible')
    # Only map_files stat/link metadata is adapted; real FD/cwd/root walk remains.
    if case=='inaccessible':
        with pytest.raises(PermissionError):api['consumer_refs']([root],100,8388608,5,pids=[os.getpid()])
    else:
        refs=api['consumer_refs']([root],100,8388608,5,pids=[os.getpid()])
        assert bool(refs)==(case=='relevant')
        if case=='relevant':assert any(row.get('ino')==retained.stat().st_ino and row['target']==str(retained) for row in refs)


@pytest.mark.parametrize('case',['valid','wrong-association','cycle'])
def test_retained_backing_edges_inside_manifest(tmp_path,case):
    api=review_body('cutover_reference_check');root,manifest,graph,expected=nb_graph(tmp_path)
    (root/'upper').write_bytes(b'finite fixture qcow metadata')
    manifest['entries']['upper']={'type':'file'}
    graph['absolute_bindings']=[]
    graph['backing_nodes']=[{'id':'base','ownership':'retained','relative':'disk','format':'qcow2'},{'id':'upper','ownership':'retained','relative':'upper','format':'qcow2'}]
    graph['backing_edges']=[{'id':'edge','from':'upper','to':'base','association':'disk'}]
    if case=='wrong-association':graph['backing_edges'][0]['association']='../disk'
    if case=='cycle':graph['backing_edges'].append({'id':'reverse','from':'base','to':'upper','association':'upper'})
    def invoke():return api['verify_graph'](graph,expected,str(root),20,100,lambda vol:(_ for _ in ()).throw(AssertionError('no volume lookup expected')),retained_manifest=manifest)
    if case=='valid':assert invoke()
    else:
        with pytest.raises(ValueError):invoke()


@pytest.mark.parametrize('case',['unsafe-unit','force-unit','lazy-unit','dropin-unit','reload-unit','ro-unit','unknown-options','wrong-type-unit','wrong-where-unit','wrong-uuid-unit','wrong-rdev-unit','cached-worker','old-loop','relevant-alias','unknown-data'])
def test_named_negative_independent_positive_controls(tmp_path,monkeypatch,case):
    rc,state,path,source,stage=run_playbook(tmp_path,monkeypatch,'control:'+case)
    assert rc==0 and 'CAS:reopen' in state['trace']
    assert 'first_assert_failure' not in state
    task,field,_=NAMED_NEGATIVE_GUARDS[case]
    assert any(row['task']==task and row['failed'] is False for row in state['guard_results'])
    if case in UNIT_NEGATIVE_VALUES:
        observed=state['guard15_evidence'];assert observed['delta']=={} and observed['observation']==observed['valid']
        assert observed['request']['path']==str(stage) and observed['request']['stage'] is True
        assert state['initial_observation']['stage_active'] is True and observed['observation']['ActiveState']=='active'
        events=state['boundary_events'];slots=[row['slot'] for row in events]
        assert 'action-16' not in slots
        assert slots.count('guard-15')==slots.count('action-17')==slots.count('action-18')==1
        assert next(row for row in events if row['slot']=='action-17')['kind']=='probe'
        assert slots.index('guard-15')<slots.index('action-17')<slots.index('action-18')
        assert state['stage17_evidence']=={'slot':'action-17','stage_active':True,'final_active':False,'fs_uuid':UUID,'rdev':253}
        assert any(row['task']=='Actual stage required before any copy' and row['failed'] is False for row in state['guard_results'])
    else:
        assert state['initial_observation'][field]=={'cached-worker':[],'old-loop':False,'relevant-alias':[],'unknown-data':1048576}[case]


def test_actual_reference_graph_wrong_sha_control(tmp_path,monkeypatch):
    rc,state,path,source,stage=run_playbook(tmp_path,monkeypatch,'reference-wrong-sha')
    assert rc!=0 and state['reference_evidence'][0]['slot']=='action-21'
    assert state['reference_evidence'][0]['expected']['retained_manifest_sha256']==state['reference_canonical_sha']
    assert state['native_graph_context']['retained_manifest_sha256']=='f'*64 and state['reference_canonical_sha']!='f'*64
    assert state['native_failures'][0]=={'slot':'action-21','rc':1,'stderr':'reference context retained_manifest_sha256: independent graph differs','status':'refused'}
    assert not any(row in state['trace'] for row in ('retained-copy','rename','CAS:reopen'))


@pytest.mark.parametrize('case',['fd','cwd','root'])
def test_actual_postrename_new_point_consumer_scope(tmp_path,monkeypatch,case):
    rc,state,path,source,stage=run_playbook(tmp_path,monkeypatch,'new-point-'+case)
    assert rc!=0 and 'rename' in state['trace']
    event=state['point_scan_evidence'];assert event['slot']=='action-42'
    assert event['roots']==[str(tmp_path/'original'),str(source),str(stage)]
    assert event['source_inode']!=event['original_inode'] and event['refs']
    assert any(row['ino']==event['source_inode'] and row['target']==str(source) for row in event['refs'])
    assert 'systemd:stopped' not in state['trace'] and 'restore' not in state['trace'] and 'CAS:reopen' not in state['trace'] and 'CAS:reopen-original' not in state['trace']
    cause='live original/source/stage references'
    assert state['native_failures'][0]=={'slot':'action-42','rc':1,'stderr':cause,'status':'refused'}
    assert state['failed_envelopes'][0]=={'slot_id':'action-42','status':'refused','returncode':1,'stdout':'','stderr':cause}
    probes=state['probe_consumer_evidence'];failed=next(row for row in probes if row['slot']=='action-42')
    assert failed['observe_only'] is False and failed['initial'] is False and failed['mode'] is False
    assert failed['receipt_present'] is True and failed['consumers_measured'] is True
    assert failed['refs_count']==len(event['refs']) and failed['status']=='refused'
    boundary=next(row for row in state['boundary_events'] if row['slot']=='action-42')
    assert boundary['kind']=='probe' and boundary['body_sha256']==failed['body_sha256']
    assert not any(row['status']=='refused' for row in probes[:probes.index(failed)])
    assert path.exists() and 'reopening_intent' not in state['trace'] and 'complete' not in state['trace']
    assert not state['final_active']
    suffix=state['trace'][state['trace'].index('rename')+1:]
    assert not any(row in suffix for row in ('systemd:stopped','systemd:started','restore','CAS:reopen','CAS:reopen-original',
                                           'receipt:final_activation_intent','receipt:rollback_intent','receipt:rolled_back','receipt:reopening_intent','receipt:reopened','receipt:complete'))
    rescue=[row for row in probes if row['slot']=='action-64']
    assert rescue and all(row['observe_only'] is True and row['mode'] is True and
                          row['consumers_measured'] is False and row['refs_count'] is None for row in rescue)
    assert state['rescue_origin']['action']=='ansible.builtin.command'
    assert state['rescue_candidates']==[False,False]
    # Fixed literal matrix via actual owning Jinja facts; no extra engine/native calls.
    from ansible.errors import AnsibleError
    import copy
    host={'host_id':'own-host','boot_id':'own-boot','attempt_id':'own-attempt'}
    clock={'deadline':123}
    base={'h':host,'c':{'storage':{'path':'/own/source'},'limits':{'output_bytes':65536}},'cutover_clock':clock,
          'fresh_cutover_branch':True,'fresh_attempt_started':True,
          'receipt_current':{'record':{'phase':'final_verified','reopening':None}},'used_cutover_slots':['action-51','action-56']}
    for slot,name,assertion,payload in (
        ('action-51','Final mounted retained manifest verified before reopening','(comparison.stdout | from_json).equal is sameas true',{'equal':False}),
        ('action-56','Offline readback before durable reopening','(live.stdout | from_json).mountpoint_guard == c.storage.path',{'mountpoint_guard':'/wrong','storage_disabled':True,'final_active':True})):
        envelope={'schema':'qcl.storage-cutover.command.v1','slot_id':slot,'identity':host,'clock':clock,'status':'ok','returncode':0,
                  'cleanup':{'reaped':True,'group_absent':True,'term_sent':False,'kill_sent':False},'stdout':json.dumps(payload)}
        v=dict(base,ansible_failed_task={'action':'ansible.builtin.assert','name':name},
               ansible_failed_result={'failed':True,'evaluated_to':False,'assertion':assertion})
        v['boundary_'+slot.replace('-','_')]={'rc':0,'stdout':json.dumps(envelope)}
        assert fixture_actual_rescue_candidate(v) is True
        negatives=[]
        for status in ('refused','deadline','output_cap','metadata_unknown','cleanup_unknown','native_outcome_unknown','arbitrary',None):
            e=copy.deepcopy(envelope);e['status']=status;negatives.append(('envelope',e))
        for key,value in (('slot_id','action-42'),('identity',dict(host,host_id='foreign')),('identity',dict(host,boot_id='foreign')),
                          ('identity',dict(host,attempt_id='foreign')),('clock',{'deadline':124}),('returncode',True),('returncode',1),('cleanup',None)):
            e=copy.deepcopy(envelope);e[key]=value;negatives.append(('envelope',e))
        for key,value in (('term_sent',True),('kill_sent',True),('reaped',False),('group_absent',False)):
            e=copy.deepcopy(envelope);e['cleanup'][key]=value;negatives.append(('envelope',e))
        for e in ({},None,{'status':'ok'}):negatives.append(('envelope',e))
        for raw in ('invalid JSON',''):negatives.append(('raw',{'rc':0,'stdout':raw}))
        for raw in (None,{}, {'rc':True,'stdout':json.dumps(envelope)}, {'rc':1,'stdout':json.dumps(envelope)}):negatives.append(('raw',raw))
        for payload_bad in (None,{}, {'equal':None}, {'equal':'false'}, {'mountpoint_guard':'/wrong','storage_disabled':'true','final_active':True}):
            e=copy.deepcopy(envelope);e['stdout']=json.dumps(payload_bad);negatives.append(('envelope',e))
        for kind,value in (('task',None),('task',{'action':'ansible.builtin.command','name':name}),('task',{'action':'ansible.builtin.assert','name':'other'}),
                           ('failure',None),('failure',{'failed':True,'evaluated_to':False,'assertion':'other'}),
                           ('phase','complete'),('phase','copy_started'),('marker',{'intended_tree':'new_final'}),('slots',[])):
            negatives.append((kind,value))
        for kind,value in negatives:
            n=copy.deepcopy(v);register='boundary_'+slot.replace('-','_')
            if kind=='envelope':n[register]['stdout']=json.dumps(value)
            elif kind=='raw':n[register]=value
            elif kind=='task':n['ansible_failed_task']=value
            elif kind=='failure':n['ansible_failed_result']=value
            elif kind=='phase':n['receipt_current']['record']['phase']=value
            elif kind=='marker':n['receipt_current']['record']['reopening']=value
            elif kind=='slots':n['used_cutover_slots']=value
            try:actual=fixture_actual_rescue_candidate(n)
            except AnsibleError:continue # Supported branch parse refusal before candidate/mutation is allowed.
            assert actual is False,(slot,kind,value)
    rendered=yaml.safe_load((BASE/'ansible/proxmox-storage-cutover.yml').read_text())[0]['vars']['cutover_native_probe']
    mode_code,guard_code,body_sha=fixture_probe_consumer_code(rendered)
    assert body_sha==failed['body_sha256']
    # Fixed independent inputs/expectations: five pure clauses in each existing ID.
    literal_refs=[{'target':'/independent/source','ino':123}]
    for flags,present,refs,expected_mode,refused in (
        ({'observe_only':False,'initial':False},False,[],False,False),
        ({'observe_only':False,'initial':False},True,literal_refs,False,True),
        ({'observe_only':True,'initial':False},False,literal_refs,True,False),
        ({'observe_only':False,'initial':True},True,literal_refs,True,False),
        ({'observe_only':False,'initial':True},False,literal_refs,False,True)):
        scope={'r':flags,'receipt_present':present,'__builtins__':{}}
        exec(mode_code,scope);assert scope['read_only_resume'] is expected_mode
        guard_scope={'read_only_resume':scope['read_only_resume'],'refs':refs,'__builtins__':{'ValueError':ValueError}}
        if refused:
            with pytest.raises(ValueError,match='^live original/source/stage references$'):exec(guard_code,guard_scope)
        else:exec(guard_code,guard_scope)


@pytest.mark.parametrize('case',['new-point-bind','unrelated-bind'])
def test_actual_postrename_namespace_roots(tmp_path,case):
    api=review_body('cutover_consumer_scan');source=tmp_path/'source';source.mkdir();rollback=tmp_path/'original';source.rename(rollback);source.mkdir();stage=tmp_path/'stage';stage.mkdir()
    roots=api['consumer_roots'](rollback,source,stage);assert roots==[rollback,source,stage] and source.stat().st_ino!=rollback.stat().st_ino
    device=str(os.major(source.stat().st_dev))+':'+str(os.minor(source.stat().st_dev))
    physical=str(source) if case=='new-point-bind' else str(tmp_path/'unrelated')
    rows=['1 0 '+device+' / / rw - ext4 /dev/root rw','2 1 '+device+' '+physical+' /fixture-bind rw - ext4 /dev/root rw']
    aliases=api['mount_aliases'](rows,device,[str(x) for x in roots],'253:0',[str(stage),str(source)])
    assert bool(aliases)==(case=='new-point-bind')


def extracted_wrapper_classes(budget):
    import ast,io,time
    api=review_body('cutover_command_boundary');tree=ast.parse(api['CHILD_WRAPPER'])
    nodes=[node for node in tree.body if isinstance(node,ast.ClassDef) and node.name in ('Entries','Entry','MetadataFile','Input')]
    scope={'budget':budget,'io':io,'os':os,'stat':stat,'need':api['need'],'input_size':200}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-owning-wrapper-classes>','exec'),scope)
    return scope


@pytest.mark.parametrize('maximum',[4096,256])
@pytest.mark.parametrize('mode',['near-cap','expired','positive'])
def test_actual_owner_pipe_preaccess(tmp_path,monkeypatch,maximum,mode):
    import time
    api=review_body('cutover_command_boundary');limit=maximum+1;budget=api['MetadataBudget'](limit,time.monotonic()+1)
    calls=[];raw=os.read
    read,write=os.pipe();os.write(write,b'p'*min(maximum,200));os.close(write)
    def observed(fd,n):calls.append((fd,n));return raw(fd,n)
    monkeypatch.setattr(os,'read',observed)
    if mode=='near-cap':budget.used=limit-1
    if mode=='expired':budget.deadline=time.monotonic()-1
    try:
        if mode=='positive':
            assert api['metadata_pipe_read'](budget,read,maximum)==b'p'*min(maximum,200)
            assert calls==[(read,maximum)] and budget.used==1+min(maximum,200)
        else:
            with pytest.raises(ValueError,match='metadata'):api['metadata_pipe_read'](budget,read,maximum)
            assert calls==[] and budget.used<=limit
    finally:os.close(read)


@pytest.mark.parametrize('mode',['near-cap','expired','positive','unknown-native'])
def test_actual_name_enumeration_preaccess(tmp_path,mode):
    import time
    api=review_body('cutover_command_boundary');budget=api['MetadataBudget'](8192,time.monotonic()+1);calls=[]
    class Item:name='n'*200
    class Iterator:
        def __init__(self):self.sent=False
        def __next__(self):
            calls.append('next')
            if self.sent:raise StopIteration
            self.sent=True;return Item()
        def close(self):calls.append('close')
    def pathconf(path,key):calls.append('pathconf');assert key=='PC_NAME_MAX';return -1 if mode=='unknown-native' else 255
    def scandir(path):
        calls.append('scandir')
        if mode=='near-cap':budget.used=budget.limit-1
        if mode=='expired':budget.deadline=time.monotonic()-1
        return Iterator()
    budget.raw=dict(budget.raw,pathconf=pathconf,scandir=scandir)
    if mode=='positive':assert budget.names(tmp_path)==['n'*200] and calls==['pathconf','scandir','next','next','close']
    else:
        with pytest.raises(ValueError,match='metadata|filename'):budget.names(tmp_path)
        assert 'next' not in calls and budget.used<=budget.limit
        if mode=='unknown-native':assert 'scandir' not in calls


@pytest.mark.parametrize('mode',['near-cap','expired','positive'])
def test_actual_buffered_second_read_preaccess(tmp_path,mode):
    import io,time
    api=review_body('cutover_command_boundary');scope=extracted_wrapper_classes(None)
    file=tmp_path/'record';file.write_bytes(b'b'*200);calls=[]
    class Witness(io.BytesIO):
        def read(self,n=-1):calls.append(n);return super().read(n)
    budget=api['MetadataBudget'](8192,time.monotonic()+1);scope['budget']=budget
    reader=scope['MetadataFile'](file,'rb');reader.data=Witness(b'b'*200)
    if mode=='near-cap':budget.used=budget.limit-1
    if mode=='expired':budget.deadline=time.monotonic()-1
    if mode=='positive':
        budget.used=budget.limit-21;before=budget.used;assert reader.read(20)==b'b'*20 and calls==[20] and budget.used==before+21==budget.limit and reader.remaining==180
    else:
        with pytest.raises(ValueError,match='metadata'):reader.read(200)
        assert calls==[] and budget.used<=budget.limit
    reader.data.close()


@pytest.mark.parametrize('mode',['near-cap','expired','positive'])
def test_actual_text_input_utf8_bytes_charge(mode):
    import io,time
    api=review_body('cutover_command_boundary');scope=extracted_wrapper_classes(None);calls=[]
    payload='яя';scope['input_size']=len(payload.encode())
    class Witness(io.BytesIO):
        def read(self,n=-1):calls.append(n);return super().read(n)
    handle=Witness(payload.encode())
    budget=api['MetadataBudget'](6,time.monotonic()+1);scope['budget']=budget
    reader=scope['Input'](handle)
    if mode=='near-cap':budget.used=budget.limit-1
    if mode=='expired':budget.deadline=time.monotonic()-1
    if mode=='positive':assert reader.read()==payload and calls==[5] and budget.used==5 and reader.remaining==0
    else:
        with pytest.raises(ValueError,match='metadata'):reader.read()
        assert calls==[] and budget.used<=budget.limit


@pytest.mark.parametrize('mode',['near-cap','expired','positive'])
def test_actual_child_entry_preaccess(tmp_path,mode):
    import time
    api=review_body('cutover_command_boundary');scope=extracted_wrapper_classes(None);calls=[]
    class Item:name='n'*200;path=str(tmp_path/'file')
    class Iterator:
        def __next__(self):calls.append('next');return Item()
        def close(self):calls.append('close')
    def pathconf(path,key):calls.append('pathconf');assert key=='PC_NAME_MAX';return 255
    def scandir(path):
        calls.append('scandir')
        if mode=='near-cap':budget.used=budget.limit-1
        if mode=='expired':budget.deadline=time.monotonic()-1
        return Iterator()
    budget=api['MetadataBudget'](8192,time.monotonic()+1);scope['budget']=budget
    budget.raw=dict(budget.raw,pathconf=pathconf,scandir=scandir);entries=scope['Entries'](tmp_path)
    if mode=='positive':
        before=budget.used;item=next(entries);assert item.name=='n'*200 and calls==['pathconf','scandir','next'] and budget.used==before+201
    else:
        with pytest.raises(ValueError,match='metadata'):next(entries)
        assert 'next' not in calls and budget.used<=budget.limit
    entries.close()


@pytest.mark.parametrize('value',[-1,0,4097,True])
def test_native_name_maximum_unknown_refuses_before_iterator(tmp_path,value):
    import time
    api=review_body('cutover_command_boundary');budget=api['MetadataBudget'](8192,time.monotonic()+1);calls=[]
    def query(path,key):calls.append('pathconf');assert key=='PC_NAME_MAX';return value
    def iterator(path):calls.append('scandir');raise AssertionError('unsupported maximum cannot reach enumeration')
    budget.raw=dict(budget.raw,pathconf=query,scandir=iterator)
    with pytest.raises(ValueError,match='filename'):budget.names(tmp_path)
    assert calls==['pathconf'] and budget.used<=budget.limit
