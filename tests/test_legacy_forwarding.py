import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "legacy_forwarding", Path(__file__).parents[1] / "ops" / "legacy_forwarding.py"
)
forwarding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(forwarding)


class LegacyForwardingTests(unittest.TestCase):
    def test_rules_only_admit_exact_outbound_subnets_and_established_returns(self):
        rules = forwarding.commands("vmbr0", "vmbrqcl", "192.0.2.0/24", "vmbr710ci", "198.51.100.0/24")
        self.assertEqual(len(rules), 4)
        for rule in rules:
            self.assertEqual(rule[:2], ["-A", "QCL-NEGF"])
            if "-s" in rule:
                self.assertEqual(rule[rule.index("-o") + 1], "vmbr0")
            else:
                self.assertEqual(rule[rule.index("-i") + 1], "vmbr0")
                self.assertEqual(rule[rule.index("--ctstate") + 1], "ESTABLISHED,RELATED")

    def test_overlapping_subnets_and_bridge_argument_injection_are_rejected(self):
        for args in (("vmbr0", "vmbrqcl", "192.0.2.0/24", "vmbr710ci", "192.0.2.0/25"),
                     ("vmbr0;bad", "vmbrqcl", "192.0.2.0/24", "vmbr710ci", "198.51.100.0/24")):
            with self.assertRaises(ValueError):
                forwarding.commands(*args)

    def test_apply_changes_only_owned_chain_and_own_forward_jump(self):
        calls = []
        def run(args, **_kwargs):
            calls.append(args[3:])
            return type("Result", (), {"returncode": 1 if args[3] in ("-S", "-C") else 0})()
        with patch.object(forwarding.subprocess, "run", run):
            forwarding.apply(forwarding.commands("vmbr0", "vmbrqcl", "192.0.2.0/24", "vmbr710ci", "198.51.100.0/24"))
        self.assertEqual(calls[-1], ["-I", "FORWARD", "1", "-j", "QCL-NEGF"])
        self.assertEqual([call for call in calls if call[0] == "-F"], [["-F", "QCL-NEGF"]])
        self.assertFalse(any(call[0] in ("-P", "-X") or "DOCKER" in " ".join(call) for call in calls))
