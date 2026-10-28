"""Source contracts only: pure validation and actual Ansible template rendering.

No playbook/native action, nft process, connection, network or VM is executed.
The small packet oracle covers only the two known postrouting rule forms.
"""

import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys

import pytest
import yaml


BASE = Path(__file__).resolve().parents[1]
BASELINE = """# destroy is idempotent on nft >= 1.0.9. Replace only these tables atomically;
# never flush the host ruleset or change existing Proxmox firewall tables.
destroy table inet qcl_negf
destroy table ip qcl_negf_nat
table inet qcl_negf {
    set ci_denied {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { 198.51.100.0/24, 192.0.2.0/24 }
    }
    chain forward {
        type filter hook forward priority -10; policy accept;
        iifname "vmbr710ci" meta nfproto ipv6 drop
        iifname "vmbr710ci" ip saddr != 203.0.113.0/24 drop
        iifname "vmbr710ci" ip daddr { 192.0.2.53 } meta l4proto { tcp, udp } th dport 53 accept
        iifname "vmbr710ci" ip daddr @ci_denied drop
        iifname "vmbrqcl" oifname "vmbr710ci" drop
    }
    chain input {
        type filter hook input priority -10; policy accept;
        ct state established,related accept
        iifname "vmbr710ci" drop
    }
}
table ip qcl_negf_nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr { 198.51.100.0/24, 203.0.113.0/24 } oifname "vmbr0" masquerade
    }
}
"""
EXEMPTION = (
    '        ip saddr 198.51.100.0/24 ip daddr { 192.0.2.14 } oifname "vmbr0" return\n'
)


def play():
    return yaml.safe_load((BASE / "ansible/proxmox-host.yml").read_text())[0]


def settings(**updates):
    value = dict(play()["vars"])
    value.update(
        qcl_cluster_cidr="198.51.100.0/24",
        qcl_ci_cidr="203.0.113.0/24",
        qcl_cluster_gateway_cidr="198.51.100.1/24",
        qcl_ci_gateway_cidr="203.0.113.1/24",
        qcl_ci_denied_cidrs=["192.0.2.0/24"],
        qcl_ci_dns_servers=["192.0.2.53"],
        ansible_facts={"os_family": "Debian"},
        ansible_check_mode=True,
    )
    value.update(updates)
    return value


def validate_script(addresses, **updates):
    """Execute the actual pure validator, with literal argv in its native order."""
    task = next(
        t
        for t in play()["tasks"]
        if t["name"] == "Validate IPv4 CIDRs and non-overlapping isolated subnets"
    )
    argv = task["ansible.builtin.command"]["argv"]
    assert argv[:2] == ["python3", "-c"]
    values = settings(**updates)
    return subprocess.run(
        [
            sys.executable,
            "-c",
            argv[2],
            values["qcl_cluster_cidr"],
            values["qcl_ci_cidr"],
            values["qcl_cluster_gateway_cidr"],
            values["qcl_ci_gateway_cidr"],
            " ".join(values["qcl_ci_denied_cidrs"]),
            " ".join(values["qcl_ci_dns_servers"]),
            json.dumps(addresses),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )


@pytest.fixture
def templar(ansible_test_environment):
    from ansible.parsing.dataloader import DataLoader
    from ansible.template import Templar
    from ansible._internal._datatag._tags import TrustedAsTemplate

    def create(values):
        return Templar(loader=DataLoader(), variables=values), TrustedAsTemplate()

    return create


def render(templar, **updates):
    engine, trust = templar(settings(**updates))
    return engine.template(
        trust.tag((BASE / "ansible/templates/proxmox-firewall.j2").read_text())
    )


def test_missing_and_empty_list_preserve_entire_old_render(templar):
    assert play()["vars"]["qcl_external_worker_ipv4_addresses"] == []
    assert render(templar) == BASELINE
    assert render(templar, qcl_external_worker_ipv4_addresses=[]) == BASELINE


@pytest.mark.parametrize(
    "addresses", [[], ["192.0.2.14"], ["192.0.2.14", "192.0.2.15"]]
)
def test_pure_validator_accepts_exact_external_hosts(addresses):
    result = validate_script(addresses)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "addresses",
    [
        None,
        True,
        "192.0.2.14",
        {},
        [False],
        [14],
        [None],
        [""],
        ["192.0.2.14/32"],
        ["192.0.2.0/24"],
        ["192.0.2.014"],
        [" 192.0.2.14"],
        ["192.0.2.14\n"],
        ["192.0.2.14; accept"],
        ["::1"],
        ["2001:db8::1"],
        ["198.51.100.9"],
        ["203.0.113.9"],
        ["0.0.0.0"],
        ["127.0.0.1"],
        ["169.254.1.1"],
        ["224.0.0.1"],
        ["255.255.255.255"],
        ["192.0.2.14", "192.0.2.14"],
    ],
)
def test_actual_pure_validator_rejects_unsafe_or_nonexternal_identity(addresses):
    result = validate_script(addresses)
    assert result.returncode != 0, (
        f"Accepted unsafe external-worker input: {addresses!r}"
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"qcl_ci_cidr": "198.51.100.0/24"},
        {"qcl_cluster_cidr": "198.51.100.9/24"},
        {"qcl_cluster_gateway_cidr": "192.0.2.1/24"},
        {"qcl_ci_dns_servers": ["198.51.100.9"]},
    ],
)
def test_existing_subnet_and_dns_guards_are_still_executed(updates):
    assert validate_script([], **updates).returncode != 0


@pytest.mark.parametrize(
    "value,want",
    [
        ([], True),
        (["192.0.2.14"], True),
        (None, False),
        (True, False),
        ("192.0.2.14", False),
        ({}, False),
    ],
)
def test_actual_ansible_type_guard_precedes_first_command(templar, value, want):
    engine, trust = templar(settings(qcl_external_worker_ipv4_addresses=value))
    guards = []
    for task in play()["tasks"]:
        if "ansible.builtin.command" in task:
            break
        guards.extend(task.get("ansible.builtin.assert", {}).get("that", []))
    assert guards, "Missing production validation before commands"
    outcome = all(engine.evaluate_conditional(trust.tag(g)) for g in guards)
    assert outcome == want


def test_actual_argv_passes_json_list_to_the_validator(templar):
    engine, trust = templar(settings(qcl_external_worker_ipv4_addresses=["192.0.2.14"]))
    task = next(
        t
        for t in play()["tasks"]
        if t["name"] == "Validate IPv4 CIDRs and non-overlapping isolated subnets"
    )
    argv = [
        engine.template(trust.tag(x)) for x in task["ansible.builtin.command"]["argv"]
    ]
    assert len(argv) == 10
    assert json.loads(argv[-1]) == ["192.0.2.14"]
    assert (
        subprocess.run(
            [sys.executable, *argv[1:]], capture_output=True, timeout=10
        ).returncode
        == 0
    )


def postrouting_decision(text, source, destination, egress):
    """Restricted first-match oracle, refusing unknown rule/action grammar."""
    fragment = text.split("table ip qcl_negf_nat {\n", 1)[1]
    rules = [s.strip() for s in fragment.splitlines() if s.strip().startswith("ip ")]
    for rule in rules:
        exempt = re.fullmatch(
            r'ip saddr (\S+) ip daddr \{ ([^}]+) \} oifname "([^"]+)" return', rule
        )
        masq = re.fullmatch(
            r'ip saddr \{ ([^}]+) \} oifname "([^"]+)" masquerade', rule
        )
        assert exempt or masq, "Unexpected postrouting grammar: " + rule
        if exempt:
            network, hosts, interface = exempt.groups()
            if (
                ipaddress.ip_address(source) in ipaddress.ip_network(network)
                and destination in hosts.split(", ")
                and egress == interface
            ):
                return "return"
        else:
            networks, interface = masq.groups()
            if egress == interface and any(
                ipaddress.ip_address(source) in ipaddress.ip_network(n)
                for n in networks.split(", ")
            ):
                return "masquerade"
    return "unchanged"


@pytest.mark.parametrize(
    "source,destination,egress,want",
    [
        ("198.51.100.12", "192.0.2.14", "vmbr0", "return"),
        ("198.51.100.12", "192.0.2.15", "vmbr0", "masquerade"),
        ("203.0.113.12", "192.0.2.14", "vmbr0", "masquerade"),
        ("203.0.113.12", "192.0.2.15", "vmbr0", "masquerade"),
        ("192.0.2.99", "192.0.2.14", "vmbr0", "unchanged"),
        ("198.51.100.12", "192.0.2.14", "vmbrOTHER", "unchanged"),
    ],
)
def test_ordered_rule_matches_only_cluster_to_selected_host(
    templar, source, destination, egress, want
):
    text = render(templar, qcl_external_worker_ipv4_addresses=["192.0.2.14"])
    assert EXEMPTION in text
    assert text.index(EXEMPTION) < text.index("masquerade\n")
    assert postrouting_decision(text, source, destination, egress) == want


def test_multiple_workers_do_not_change_filter_or_other_nat_rules(templar):
    text = render(
        templar, qcl_external_worker_ipv4_addresses=["192.0.2.14", "192.0.2.15"]
    )
    rule = '        ip saddr 198.51.100.0/24 ip daddr { 192.0.2.14, 192.0.2.15 } oifname "vmbr0" return\n'
    assert text.replace(rule, "", 1) == BASELINE
    assert (
        postrouting_decision(text, "198.51.100.12", "192.0.2.15", "vmbr0") == "return"
    )
    assert (
        postrouting_decision(text, "203.0.113.12", "192.0.2.15", "vmbr0")
        == "masquerade"
    )
