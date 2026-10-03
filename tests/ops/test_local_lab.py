"""Host admission and ownership checks; these tests never launch a VM."""
import importlib.util
import base64
import json
from pathlib import Path
import subprocess

import pytest

spec = importlib.util.spec_from_file_location("local_lab", Path(__file__).parents[2] / "ops/local_lab.py")
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


def config():
    return {"namespace": "qcl-lab", "network_cidr": "192.168.231.0/24",
            "resources": lab.DEFAULT_RESOURCES, "pool_path": "/var/tmp/qcl-negf-qcl-lab",
            "host_reserve_mib": 1024, "host_reserved_cpus": 1,
            "disk_reserve_bytes": 2 * 1024**3, "image_bytes": 1024**3}


def snapshot():
    return {"kvm_rw": True, "memory_available_mib": 12 * 1024, "logical_cpus": 16,
            "disk_free_bytes": 10 * 1024**3, "running": {}}


def test_address_and_mac_contract():
    machines = lab.machines(config())
    assert machines["control"]["ip"] == "192.168.231.10"
    assert machines["worker-2"]["ip"] == "192.168.231.22"
    assert machines["worker-1"]["mac"].endswith(":00:15")
    assert len({m["mac"] for m in machines.values()}) == 4


@pytest.mark.parametrize("field,value,match", [
    ("kvm_rw", False, "KVM"), ("memory_available_mib", 8000, "RAM"),
    ("logical_cpus", 7, "CPU"), ("disk_free_bytes", 2 * 1024**3, "disk"),
])
def test_measured_host_admission_refuses_shortfall(field, value, match):
    measured = snapshot()
    measured[field] = value
    with pytest.raises(ValueError, match=match):
        lab.admit(config(), measured, set())


def test_running_owned_memory_is_not_charged_twice_but_foreign_cpu_is_counted():
    measured = snapshot()
    measured["running"] = {"qcl-lab-" + role: dict(resources)
                           for role, resources in lab.DEFAULT_RESOURCES.items()}
    measured["memory_available_mib"] = 2048
    assert lab.admit(config(), measured, set(measured["running"]))["additional_guest_memory_mib"] == 0
    measured["running"]["foreign"] = {"memory_mib": 1024, "vcpus": 10}
    with pytest.raises(ValueError, match="CPU"):
        lab.admit(config(), measured, set(measured["running"]) - {"foreign"})


def test_only_exact_state_resource_ids_allow_partial_apply_recovery():
    actual = {"domains": {"qcl-lab-control": "uuid-a"}, "networks": {}, "pools": {}}
    tracked = {"domains": {"qcl-lab-control": "uuid-a"}, "networks": {}, "pools": {}, "volumes": {}}
    assert lab.verify_ownership(config(), actual, tracked) == {"qcl-lab-control"}
    for state in ({}, {**tracked, "domains": {"qcl-lab-control": "uuid-b"}}):
        with pytest.raises(ValueError, match="foreign"):
            lab.verify_ownership(config(), actual, state)


def test_foreign_pool_path_collision_is_refused_even_with_different_name():
    actual = {"domains": {}, "networks": {}, "pools": {
        "production": {"uuid": "foreign", "path": config()["pool_path"]}}}
    with pytest.raises(ValueError, match="pool path"):
        lab.verify_ownership(config(), actual, {})


def test_network_overlap_ignores_only_proven_owned_bridge():
    with pytest.raises(ValueError, match="overlap"):
        lab.check_overlaps(config()["network_cidr"], [{"cidr": "192.168.231.0/25", "owner": "foreign"}], set())
    lab.check_overlaps(config()["network_cidr"], [{"cidr": "192.168.231.0/24", "owner": "uuid-a"}], {"uuid-a"})
    with pytest.raises(ValueError, match="overlap"):
        lab.check_overlaps(config()["network_cidr"], [{"cidr": "192.168.0.0/16", "owner": "uuid-a"}], {"uuid-a"})


def test_tfstate_is_authority_for_each_domain_and_network_uuid(tmp_path):
    state = tmp_path / "terraform.tfstate"
    state.write_text(json.dumps({"resources": [{"type": "libvirt_domain", "instances": [
        {"attributes": {"name": "qcl-lab-control", "id": 1, "uuid": "uuid-a"}}]},
        {"type": "libvirt_network", "instances": [{"attributes": {"name": "qcl-lab-network", "id": "uuid-n"}}]}]}))
    tracked = lab.read_state(state)
    assert tracked["domains"] == {"qcl-lab-control": "uuid-a"}
    assert tracked["networks"] == {"qcl-lab-network": "uuid-n"}


def test_tainted_partial_domain_state_uses_persistent_uuid_not_numeric_runtime_id(tmp_path):
    state = tmp_path / "terraform.tfstate"
    uuid = "493b2d7b-8140-41b7-9610-42a2b2695fee"
    actual = {"domains": {"qcl-lab-control": uuid}, "networks": {}, "pools": {}}
    for runtime_id in (1, 999, None):
        state.write_text(json.dumps({"resources": [{"type": "libvirt_domain", "instances": [
            {"status": "tainted", "attributes": {"name": "qcl-lab-control", "id": runtime_id, "uuid": uuid}}]}]}))
        assert lab.verify_ownership(config(), actual, lab.read_state(state)) == {"qcl-lab-control"}
    actual["domains"]["qcl-lab-control"] = "80a93f19-da34-4feb-a402-bfd4f1ee8ad9"
    with pytest.raises(ValueError, match="foreign"):
        lab.verify_ownership(config(), actual, lab.read_state(state))


def test_numeric_domain_id_cannot_establish_ownership_without_uuid(tmp_path):
    state = tmp_path / "terraform.tfstate"
    state.write_text(json.dumps({"resources": [{"type": "libvirt_domain", "instances": [
        {"attributes": {"name": "qcl-lab-control", "id": 1}}]}]}))
    assert "qcl-lab-control" not in lab.read_state(state)["domains"]


def test_module_sync_preserves_existing_private_state_and_keys(tmp_path):
    destination = tmp_path / "tofu"
    destination.mkdir()
    state = destination / "terraform.tfstate"
    state.write_bytes(b"existing partial state")
    keys = tmp_path / "private"
    keys.mkdir()
    (keys / "munge.key").write_bytes(b"preserve private key")
    lab.sync_module(destination)
    assert state.read_bytes() == b"existing partial state"
    assert (keys / "munge.key").read_bytes() == b"preserve private key"
    assert (destination / "main.tf").read_bytes() == (lab.ROOT / "tofu/local-lab/main.tf").read_bytes()


def test_existing_private_keys_are_preserved_and_never_enter_provider_vars(tmp_path):
    private = tmp_path / "private"
    private.mkdir()
    (private / "id_ed25519").write_bytes(b"existing private bytes")
    (private / "id_ed25519.pub").write_text("ssh-ed25519 AAAATEST lab\n")
    (private / "munge.key").write_bytes(b"x" * 1024)
    runner = lab.Commands(tmp_path, timeout=5)
    before = {p.name: p.read_bytes() for p in private.iterdir()}
    lab.ensure_keys(private, runner)
    assert {p.name: p.read_bytes() for p in private.iterdir()} == before
    cfg = config() | {"libvirt_uri": "qemu:///system", "image": "/nix/store/example/image.qcow2", "image_sha256": "a" * 64}
    values = lab.provider_vars(cfg, private)
    encoded = json.dumps(values)
    assert "existing private bytes" not in encoded and "x" * 1024 not in encoded
    assert "munge" not in encoded and "id_ed25519" not in encoded
    assert values["ssh_public_key"] == "ssh-ed25519 AAAATEST lab"


def test_commands_pass_literal_argv_and_finite_timeout_without_shell(tmp_path, monkeypatch):
    calls = []
    def execute(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0)
    monkeypatch.setattr(lab.subprocess, "run", execute)
    runner = lab.Commands(tmp_path, timeout=13)
    runner.run(["printf", "$(touch /tmp/must-not-exist); `false`"])
    argv, kwargs = calls[0]
    assert argv[1] == "$(touch /tmp/must-not-exist); `false`"
    assert kwargs["shell"] is False and kwargs["timeout"] == 13


def test_private_directory_rejects_git_tracked_destination(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, "is_ignored", lambda path: False)
    with pytest.raises(ValueError, match="ignored"):
        lab.private_directory(tmp_path / "runtime")


def test_provider_never_receives_ownership_true_until_actual_preflight(tmp_path):
    private = tmp_path / "private"
    private.mkdir()
    (private / "id_ed25519.pub").write_text("ssh-ed25519 AAAATEST lab\n")
    values = lab.provider_vars(config() | {"libvirt_uri": "qemu:///system",
        "image": "/nix/store/test/image.qcow2", "image_sha256": "a" * 64}, private)
    assert values["ownership_verified"] is False


@pytest.mark.parametrize("field,value", [("vcpus", True), ("memory_mib", 1), ("vcpus", 0)])
def test_invalid_resource_budget_is_refused(field, value):
    cfg = config()
    cfg["resources"] = {role: dict(values) for role, values in lab.DEFAULT_RESOURCES.items()}
    cfg["resources"]["worker-1"][field] = value
    with pytest.raises(ValueError, match="RAM/CPU"):
        lab.admit(cfg, snapshot(), set())


def test_inventory_enrolls_once_then_uses_strict_hosts_and_local_python(tmp_path, monkeypatch):
    cfg = config() | {"systems": {role: "/nix/store/system-" + role for role in lab.ROLES}, "libvirt_uri": "qemu:///system"}
    expected = lab.machines(cfg)
    actual = {"domains": {m["domain"]: "uuid-" + role for role, m in expected.items()}, "networks": {}, "pools": {}}
    monkeypatch.setattr(lab, "load_config", lambda directory: cfg)
    monkeypatch.setattr(lab, "read_state", lambda path: actual | {"volumes": {}})
    monkeypatch.setattr(lab, "actual_inventory", lambda *args: (actual, {}, []))
    monkeypatch.setattr(lab, "source_identity", lambda: {"commit": "test"})
    (tmp_path / "private").mkdir()
    calls = []
    class Runner:
        def run(self, argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, json.dumps({"inventory": {"value": expected}}), "")
    result = lab.inventory(tmp_path, Runner(), enroll=True)
    assert result["all"]["children"]["orchestrator"]["hosts"]["localhost"]["ansible_python_interpreter"] == lab.sys.executable
    assert all("StrictHostKeyChecking=accept-new" in command for command in calls if command[0] == "ssh")
    calls.clear()
    lab.inventory(tmp_path, Runner(), enroll=True)
    assert all("StrictHostKeyChecking=yes" in command for command in calls if command[0] == "ssh")


@pytest.fixture
def trust_inventory(tmp_path, monkeypatch):
    cfg = config() | {"systems": {role: "/nix/store/system-" + role for role in lab.ROLES},
                      "libvirt_uri": "qemu:///system"}
    expected = lab.machines(cfg)
    actual = {"domains": {m["domain"]: "uuid-" + role for role, m in expected.items()},
              "networks": {}, "pools": {}}
    monkeypatch.setattr(lab, "load_config", lambda directory: cfg)
    monkeypatch.setattr(lab, "read_state", lambda path: actual | {"volumes": {}})
    monkeypatch.setattr(lab, "actual_inventory", lambda *args: (actual, {}, []))
    monkeypatch.setattr(lab, "source_identity", lambda: {"commit": "test"})
    (tmp_path / "private").mkdir()
    calls = []
    class Runner:
        def run(self, argv, **kwargs):
            calls.append([str(a) for a in argv])
            return subprocess.CompletedProcess(argv, 0, json.dumps({"inventory": {"value": expected}}), "")
    return Runner(), calls, actual


def test_public_nix_key_is_optional_inventory_input_only(tmp_path, trust_inventory):
    runner, calls, actual = trust_inventory
    public = tmp_path / "private/nix-cache-public.key"
    value = "qcl-test-1:" + base64.b64encode(bytes(range(32))).decode()
    public.write_text(value + "\n")
    result = lab.inventory(tmp_path, runner, enroll=True)
    assert result["all"]["vars"]["qcl_lab_nix_public_key_file"] == str(public)
    assert value not in json.dumps(result)
    assert "trusted-users" not in json.dumps(result)


@pytest.mark.parametrize("value", [
    "qcl-test-1:" + base64.b64encode(bytes(range(64))).decode(),
    "bad name:" + base64.b64encode(bytes(range(32))).decode(),
    "qcl-test-1:" + base64.b64encode(bytes(range(32))).decode() + "\nrequire-sigs = false",
    "qcl-test-1:" + base64.b64encode(bytes(range(31))).decode(),
    "qcl-test-1:" + base64.b64encode(bytes(range(32))).decode()[:-2] + "9=",
])
def test_inventory_refuses_private_or_invalid_nix_key_before_ssh(tmp_path, trust_inventory, value):
    runner, calls, actual = trust_inventory
    (tmp_path / "private/nix-cache-public.key").write_text(value + "\n")
    with pytest.raises(ValueError, match="public"):
        lab.inventory(tmp_path, runner, enroll=True)
    assert not any(command[0] == "ssh" for command in calls)


def test_trust_uses_guarded_enrollment_then_only_the_tagged_playbook(tmp_path, trust_inventory):
    runner, calls, actual = trust_inventory
    public = tmp_path / "private/nix-cache-public.key"
    public.write_text("qcl-test-1:" + base64.b64encode(bytes(range(32))).decode() + "\n")
    result = lab.trust(tmp_path, runner, 17)
    assert result["signed_import"] == "not_measured" and result["role_activation"] == "not_performed"
    assert calls[-1] == ["ansible-playbook", "-i", str(tmp_path / "private/inventory.json"),
                         str(lab.ROOT / "ansible/local-lab.yml"), "--tags", "nix-trust"]
    assert len([call for call in calls if call[0] == "ssh"]) == 4
    calls.clear()
    lab.trust(tmp_path, runner, 17)
    assert all("StrictHostKeyChecking=yes" in call for call in calls if call[0] == "ssh")


def test_trust_refuses_uuid_collision_before_ssh_or_playbook(tmp_path, trust_inventory, monkeypatch):
    runner, calls, actual = trust_inventory
    (tmp_path / "private/nix-cache-public.key").write_text(
        "qcl-test-1:" + base64.b64encode(bytes(range(32))).decode() + "\n")
    monkeypatch.setattr(lab, "read_state", lambda path: {"domains": {}, "networks": {}, "pools": {}})
    with pytest.raises(ValueError, match="foreign"):
        lab.trust(tmp_path, runner, 17)
    assert not any(call[0] in ("ssh", "ansible-playbook") for call in calls)


def test_trust_requires_declared_public_key_before_inventory(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, "inventory", lambda *a, **kw: pytest.fail("inventory before public key"))
    with pytest.raises(ValueError, match="public"):
        lab.trust(tmp_path, None, 17)


def test_inventory_rejects_indirect_public_key_file(tmp_path, trust_inventory):
    runner, calls, actual = trust_inventory
    target = tmp_path / "valid-public.key"
    target.write_text("qcl-test-1:" + base64.b64encode(bytes(range(32))).decode() + "\n")
    (tmp_path / "private/nix-cache-public.key").symlink_to(target)
    with pytest.raises(ValueError, match="regular Nix public"):
        lab.inventory(tmp_path, runner, enroll=True)


def test_apply_refuses_destructive_plan_before_provider_mutation(tmp_path, monkeypatch):
    cfg = config() | {"libvirt_uri": "qemu:///system", "image": "immutable", "image_sha256": "a" * 64}
    monkeypatch.setattr(lab, "load_config", lambda directory: cfg)
    monkeypatch.setattr(lab, "preflight", lambda *args: {"status": "pass"})
    monkeypatch.setattr(lab, "provider_vars", lambda *args: {"ownership_verified": False})
    calls = []
    class Runner:
        def run(self, argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, json.dumps({"resource_changes": [{"change": {"actions": ["delete", "create"]}}]}), "")
    with pytest.raises(ValueError, match="destructive"):
        lab.apply(tmp_path, Runner(), 5)
    assert not any("apply" in argv for argv in calls)
    assert json.loads((tmp_path / "tofu/lab.auto.tfvars.json").read_text())["ownership_verified"] is True


def test_guest_probe_rejects_root_backed_durable_mount_and_missing_uuid():
    cfg = config() | {"systems": {role: "closure" for role in lab.ROLES}}
    result = {"hostname": "storage", "system": "closure", "uid": 3000, "cgroup_v2": True,
        "resolution": {name: m["ip"] for name, m in lab.machines(cfg).items()}, "durable_device": 2,
        "exports": "/srv/qcl-negf/jobs root_squash", "mounts": {
            "/": {"device": 1}, "/srv/qcl-negf": {"device": 2, "findmnt": {"fstype": "ext4", "uuid": "uuid-d"}}}}
    lab.verify_guest(cfg, "storage", result)
    result["mounts"]["/srv/qcl-negf"]["findmnt"]["uuid"] = None
    with pytest.raises(ValueError, match="measured UUID"):
        lab.verify_guest(cfg, "storage", result)
    result["mounts"]["/srv/qcl-negf"]["device"] = 1
    with pytest.raises(ValueError, match="root filesystem"):
        lab.verify_guest(cfg, "storage", result)


def test_seed_is_public_only_and_repeat_generation_keeps_existing_iso(tmp_path, monkeypatch):
    private = tmp_path / "private"
    private.mkdir()
    (private / "id_ed25519.pub").write_text("ssh-ed25519 AAAATEST lab\n")
    (private / "id_ed25519").write_text("SSH PRIVATE MATERIAL")
    (private / "munge.key").write_text("MUNGE PRIVATE MATERIAL")
    monkeypatch.setattr(lab.shutil, "which", lambda name: "/usr/bin/" + name)
    calls = []
    class Runner:
        def run(self, argv, **kwargs):
            calls.append(argv)
            Path(argv[2]).write_bytes(b"fake public ISO")
    lab.create_seeds(config(), private, Runner())
    assert len(calls) == 4
    for path in (private / "seeds").rglob("*"):
        if path.is_file():
            assert b"PRIVATE MATERIAL" not in path.read_bytes()
    before = {path: path.read_bytes() for path in (private / "seeds").rglob("*") if path.is_file()}
    lab.create_seeds(config(), private, Runner())
    assert len(calls) == 4 and all(path.read_bytes() == content for path, content in before.items())


def test_untracked_pool_file_is_refused_before_init_or_apply(tmp_path, monkeypatch):
    image = tmp_path / "image.qcow2"
    image.write_bytes(b"immutable image fixture")
    pool = tmp_path / "pool"
    pool.mkdir()
    (pool / "foreign.qcow2").write_text("preserve foreign data")
    cfg = config() | {"image": str(image), "image_sha256": lab.sha256(image), "pool_path": str(pool)}
    monkeypatch.setattr(lab, "actual_inventory", lambda *args: ({"domains": {}, "pools": {}, "networks": {}}, {}, []))
    with pytest.raises(ValueError, match="untracked/foreign"):
        lab.preflight(tmp_path, cfg, None)
    assert (pool / "foreign.qcow2").read_text() == "preserve foreign data"


def test_command_failure_records_status_and_cannot_be_pass(tmp_path):
    runner = lab.Commands(tmp_path, timeout=5)
    with pytest.raises(RuntimeError, match="status=7"):
        runner.run([lab.sys.executable, "-c", "raise SystemExit(7)"])
    event = json.loads((tmp_path / "commands.jsonl").read_text())
    assert event["returncode"] == 7 and "pass" not in event.values()


def test_volume_table_preserves_path_spaces_and_accepts_empty_pool():
    assert lab.parse_volume_table(" Name   Path\n----------------\n owned.qcow2   /pool with spaces/owned.qcow2\n") == [
        ("owned.qcow2", "/pool with spaces/owned.qcow2")]
    assert lab.parse_volume_table("Name Path\n---------\n") == []


@pytest.mark.parametrize("row", ["foreign volume   /pool/foreign", "foreign  name   /pool/foreign",
    "owned.qcow2   -", "unparseable", "owned.qcow2   /pool/owned\nowned.qcow2   /pool/other"])
def test_volume_table_refuses_unknown_or_ambiguous_rows(row):
    with pytest.raises(ValueError, match="volume table"):
        lab.parse_volume_table("Name Path\n---------\n" + row)


@pytest.mark.parametrize("foreign", [False, True])
def test_volume_ownership_uses_supported_cli_and_checks_each_key_and_path(foreign):
    calls = []
    class Runner:
        def run(self, argv, **kwargs):
            calls.append(argv)
            assert "--name" not in argv
            operation = argv[3]
            text = {"vol-list": " Name  Path\n-------------\n owned.qcow2   /pool with spaces/owned.qcow2\n" +
                    (" foreign.qcow2   /pool/foreign.qcow2\n" if foreign else ""),
                    "vol-key": "key-owned", "vol-path": "/pool with spaces/owned.qcow2"}[operation]
            return subprocess.CompletedProcess(argv, 0, text, "")
    cfg = config() | {"libvirt_uri": "qemu:///system"}
    if foreign:
        with pytest.raises(ValueError, match="foreign"):
            lab.verify_pool_volumes(cfg, Runner(), "qcl-lab-pool", {"owned.qcow2": "key-owned"})
    else:
        lab.verify_pool_volumes(cfg, Runner(), "qcl-lab-pool", {"owned.qcow2": "key-owned"})
    assert calls[0][-2:] == ["vol-list", "qcl-lab-pool"]


def test_volume_table_cannot_disguise_foreign_spaced_name_as_owned_name():
    class Runner:
        def run(self, argv, **kwargs):
            text = {"vol-list": "Name Path\n---------\nowned.qcow2  /fake name   /real/foreign\n",
                    "vol-key": "owned-key", "vol-path": "/real/owned"}[argv[3]]
            return subprocess.CompletedProcess(argv, 0, text, "")
    with pytest.raises(ValueError, match="volume path"):
        lab.verify_pool_volumes(config() | {"libvirt_uri": "qemu:///system"}, Runner(), "pool", {"owned.qcow2": "owned-key"})
