import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "network_ownership", Path(__file__).parents[1] / "ops" / "network_ownership.py"
)
ownership = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ownership)

CONTENT = """# Managed by qcl-negf-platform/ansible/proxmox-host.yml; vmbr0 remains external.
auto vmbrqcl
iface vmbrqcl inet static
auto vmbr710ci
iface vmbr710ci inet static
"""


class OwnershipTests(unittest.TestCase):
    def test_current_pair_remains_owned(self):
        ownership.validate_owner(CONTENT, ["vmbrqcl", "vmbr710ci"])

    def test_stale_drop_in_cannot_adopt_another_existing_bridge(self):
        with self.assertRaisesRegex(ValueError, "immutable"):
            ownership.validate_owner(CONTENT, ["vmbrqcl", "vmbr1"])

    def test_extra_interface_or_unmarked_drop_in_fails_closed(self):
        for content in (CONTENT + "auto vmbr0\n", CONTENT.replace("# Managed", "# Previously managed")):
            with self.assertRaises(ValueError):
                ownership.validate_owner(content, ["vmbrqcl", "vmbr710ci"])
