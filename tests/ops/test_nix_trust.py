"""Exercise the actual tagged Ansible block on temp files, never a VM/root config."""
import base64
import json
import os
from pathlib import Path
import subprocess


def test_public_trust_block_is_idempotent_and_preserves_existing_config(tmp_path):
    source = (Path(__file__).parents[2] / "ansible/local-lab.yml").read_text()
    start = "    - name: Configure optional public Nix cache trust\n"
    assert start in source, "playbook lacks the optional pre-import public trust block"
    block = start + source.split(start, 1)[1].split("    - name: Confirm role closure", 1)[0]
    assert source.index(start) < source.index("    - name: Confirm role closure")
    assert "tags: [nix-trust]" in block
    assert "owner: root" in block and "group: root" in block
    assert "require-sigs" not in block and "trusted-users" not in block
    target = tmp_path / "nix"
    target.mkdir()
    config = target / "nix.conf"
    original = "require-sigs = true\ntrusted-users = root\n# preserve caller settings\n"
    config.write_text(original)
    public = tmp_path / "public.key"
    key = "qcl-test-1:" + base64.b64encode(bytes(range(224, 256))).decode()
    public.write_text(key + "\n")
    # Production fixed root paths/owners are checked above; translate only for
    # local module execution as the test UID. No guest or host trust is changed.
    block = block.replace("/root/.config/nix", str(target))
    block = block.replace("owner: root", f"owner: '{os.getuid()}'")
    block = block.replace("group: root", f"group: '{os.getgid()}'")
    play = tmp_path / "play.yml"
    play.write_text("- hosts: localhost\n  connection: local\n  gather_facts: false\n"
                    f"  vars:\n    qcl_lab_nix_public_key_file: '{public}'\n  tasks:\n" + block)
    env = dict(os.environ, ANSIBLE_LOCAL_TEMP=str(tmp_path / "ansible-local"),
               ANSIBLE_REMOTE_TEMP=str(tmp_path / "ansible-remote"))
    command = ["ansible-playbook", "-i", "localhost,", str(play), "--tags", "nix-trust"]
    first = subprocess.run(command, capture_output=True, text=True, env=env, timeout=60)
    assert first.returncode == 0, first.stdout + first.stderr
    expected = (original + "# BEGIN qcl-local-lab trusted cache key\n"
                f"extra-trusted-public-keys = {key}\n"
                "# END qcl-local-lab trusted cache key\n")
    assert config.read_text() == expected
    assert target.stat().st_mode & 0o777 == 0o700
    assert config.stat().st_mode & 0o777 == 0o600
    second = subprocess.run(command, capture_output=True, text=True, env=env, timeout=60)
    assert second.returncode == 0, second.stdout + second.stderr
    assert "changed=0" in second.stdout
    assert config.read_text() == expected


def test_tag_selection_never_activates_role_or_provisions_secrets(tmp_path):
    playbook = Path(__file__).parents[2] / "ansible/local-lab.yml"
    hosts = {role: {"ansible_connection": "local", "qcl_lab_role": role,
                    "qcl_lab_system": "/nix/store/" + "a" * 32 + "-nixos-system-" + role}
             for role in ("control", "storage", "worker-1", "worker-2")}
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps({"all": {"vars": {"qcl_lab_namespace": "qcl-test",
        "ansible_user": "root"}, "children": {"local_lab": {"hosts": hosts}}}}))
    env = dict(os.environ, ANSIBLE_LOCAL_TEMP=str(tmp_path / "ansible-local"))
    result = subprocess.run(["ansible-playbook", "-i", str(inventory), str(playbook),
                             "--list-tasks", "--tags", "nix-trust"],
                            capture_output=True, text=True, env=env, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Retain other Nix settings" in result.stdout
    for forbidden in ["Confirm role closure", "Deliver the shared Munge", "Deliver optional controller API",
                      "Activate the role", "Select the exact boot closure", "Restart authentication"]:
        assert forbidden not in result.stdout


def test_ansible_block_refuses_private_signing_key_without_config_write(tmp_path):
    source = (Path(__file__).parents[2] / "ansible/local-lab.yml").read_text()
    start = "    - name: Configure optional public Nix cache trust\n"
    block = start + source.split(start, 1)[1].split("    - name: Confirm role closure", 1)[0]
    target = tmp_path / "must-not-be-created"
    block = block.replace("/root/.config/nix", str(target))
    public = tmp_path / "actually-private.key"
    value = "qcl-test-1:" + base64.b64encode(bytes(range(64))).decode()
    public.write_text(value + "\n")
    play = tmp_path / "play.yml"
    play.write_text("- hosts: localhost\n  connection: local\n  gather_facts: false\n"
                    f"  vars:\n    qcl_lab_nix_public_key_file: '{public}'\n  tasks:\n" + block)
    env = dict(os.environ, ANSIBLE_LOCAL_TEMP=str(tmp_path / "ansible-local"),
               ANSIBLE_REMOTE_TEMP=str(tmp_path / "ansible-remote"))
    result = subprocess.run(["ansible-playbook", "-i", "localhost,", str(play), "--tags", "nix-trust"],
                            capture_output=True, text=True, env=env, timeout=60)
    assert result.returncode != 0
    assert not target.exists()
    assert value not in result.stdout + result.stderr
