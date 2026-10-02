"""Read-only ownership guard used by the Proxmox host playbook."""
from pathlib import Path
import re
import sys


def validate_owner(content, expected):
    if "# Managed by qcl-negf-platform/ansible/proxmox-host.yml; vmbr0 remains external." not in content.splitlines():
        raise ValueError("Existing drop-in is not the QCL-owned bridge declaration")
    auto = set(re.findall(r"^auto (\S+)$", content, re.MULTILINE))
    interfaces = set(re.findall(r"^iface (\S+) inet static$", content, re.MULTILINE))
    if auto != set(expected) or interfaces != set(expected):
        raise ValueError("Installed bridge names are immutable; review bridge migration separately")


if __name__ == "__main__":
    expected = sys.argv[1:]
    path = Path("/etc/network/interfaces.d/qcl-negf")
    if path.exists():
        validate_owner(path.read_text(), expected)
    elif any(Path("/sys/class/net", name).exists() for name in expected):
        raise SystemExit("Existing bridge needs explicit ownership review")
