"""Qualification modules must be present in both real source packages."""
from pathlib import Path
import re

import yaml

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    'host_resource_capacity',
    'host_resource_qualification',
    'host_resource_qualification_gate',
    'host_resource_qualification_observations',
    'host_resource_qualification_runtime',
}


def test_qualification_sources_are_in_both_installer_packages():
    nix = (ROOT / 'nix/host-resources.nix').read_text()
    nix_sources = set(re.findall(r'cp\s+\$\{\.\./ops/([A-Za-z0-9_]+)\.py\}\s+"\$out/ops/\1\.py"', nix))
    plays = yaml.safe_load((ROOT / 'ansible/host-resources.yml').read_text())
    task = next(task for play in plays for task in play['tasks']
                if task.get('name') == 'Install frozen command engine and resource source')
    assert REQUIRED <= nix_sources
    assert REQUIRED <= set(task['loop'])
