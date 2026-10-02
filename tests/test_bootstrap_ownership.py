import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "bootstrap_ownership", Path(__file__).parents[1] / "ops" / "bootstrap_ownership.py"
)
ownership = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ownership)

CONFIG = """name: qcl-bootstrap
tags: bootstrap;qcl-negf
virtio0: local-lvm:vm-709-disk-0,backup=0,serial=qcl-bootstrap-root,size=128G
"""


class BootstrapOwnershipTests(unittest.TestCase):
    def test_exact_owned_vm_accepts_missing_or_owned_arguments(self):
        ownership.validate_bootstrap(CONFIG, "official args")
        ownership.validate_bootstrap(CONFIG + "args: official args\n", "official args")

    def test_lookalike_tags_serial_or_protected_vm_are_rejected(self):
        for config in (CONFIG.replace("bootstrap;qcl-negf", "bootstrap-other;qcl-negf"),
                       CONFIG.replace("serial=qcl-bootstrap-root,", "serial=qcl-bootstrap-root-other,"),
                       CONFIG + "protection: 1\n"):
            with self.assertRaisesRegex(ValueError, "Only"):
                ownership.validate_bootstrap(config, "official args")

    def test_different_qemu_arguments_are_never_removed_or_overwritten(self):
        with self.assertRaisesRegex(ValueError, "another owner"):
            ownership.validate_bootstrap(CONFIG + "args: custom args\n", "official args")
