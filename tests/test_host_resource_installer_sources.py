"""PVE installer must ship the same source closure as the Nix helpers."""
from collections import Counter
from pathlib import Path
import re

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_pve_installer_copies_exact_declared_nix_resource_sources():
    nix = (ROOT / 'nix/host-resources.nix').read_text()
    expected = re.findall(r'cp\s+\$\{\.\./ops/([A-Za-z0-9_]+)\.py\}\s+"\$out/ops/\1\.py"', nix)
    assert expected and len(expected) == len(set(expected)), 'Nix source declaration missing or duplicated'
    plays = yaml.safe_load((ROOT / 'ansible/host-resources.yml').read_text())
    tasks = [task for play in plays for task in play['tasks']
             if task.get('name') == 'Install frozen command engine and resource source']
    assert len(tasks) == 1, 'one concrete installer copy task required'
    task = tasks[0]
    assert task['ansible.builtin.copy']['src'] == '../ops/{{ item }}.py'
    assert task['ansible.builtin.copy']['dest'] == '/usr/local/lib/qcl-negf-host-resources/{{ item }}.py'
    actual = task['loop']
    assert isinstance(actual, list) and len(actual) == len(set(actual)), 'concrete unique installer source list required'
    assert Counter(actual) == Counter(expected), (
        f'missing={sorted(set(expected) - set(actual))}; extra={sorted(set(actual) - set(expected))}'
    )
