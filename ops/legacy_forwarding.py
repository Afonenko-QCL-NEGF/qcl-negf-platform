#!/usr/bin/env python3
"""QCL-owned compatibility chain for an existing iptables-legacy FORWARD drop.

nftables QCL denies run at priority -10 before this priority-0 legacy table.
Never changes a policy, Docker/Proxmox chains or their rules.
"""
import ipaddress
import re
import shutil
import subprocess
import sys

CHAIN = "QCL-NEGF"


def commands(management, cluster_bridge, cluster_cidr, ci_bridge, ci_cidr):
    bridges = [management, cluster_bridge, ci_bridge]
    if len(set(bridges)) != 3 or any(not re.fullmatch(r"vmbr[a-zA-Z0-9_]{0,6}", name) for name in bridges):
        raise ValueError("Select three distinct bridge names")
    cluster, ci = [ipaddress.ip_network(value, strict=True) for value in [cluster_cidr, ci_cidr]]
    if cluster.version != 4 or ci.version != 4 or cluster.overlaps(ci):
        raise ValueError("Select distinct IPv4 guest subnets")
    rules = []
    for bridge, cidr in [(cluster_bridge, cluster_cidr), (ci_bridge, ci_cidr)]:
        rules.append(["-A", CHAIN, "-i", bridge, "-s", cidr, "-o", management, "-j", "ACCEPT"])
        rules.append(["-A", CHAIN, "-i", management, "-o", bridge, "-d", cidr,
                      "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    return rules


def apply(rules):
    def run(args, check=True):
        return subprocess.run(["iptables-legacy", "-w", "10", *args], check=check,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if run(["-S", CHAIN], check=False).returncode:
        run(["-N", CHAIN])
    # Only the owned chain is flushed. Reposition only our own unqualified jump.
    # nftables still denies CI/private traffic during these restrictive updates.
    run(["-F", CHAIN])
    for rule in rules:
        run(rule)
    while run(["-C", "FORWARD", "-j", CHAIN], check=False).returncode == 0:
        run(["-D", "FORWARD", "-j", CHAIN])
    run(["-I", "FORWARD", "1", "-j", CHAIN])


def disable():
    if not shutil.which("iptables-legacy"):
        return
    def run(args, check=True):
        return subprocess.run(["iptables-legacy", "-w", "10", *args], check=check,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    while run(["-C", "FORWARD", "-j", CHAIN], check=False).returncode == 0:
        run(["-D", "FORWARD", "-j", CHAIN])
    if run(["-S", CHAIN], check=False).returncode == 0:
        run(["-F", CHAIN])
        run(["-X", CHAIN])


if __name__ == "__main__":
    if sys.argv[1:] == ["--disable"]:
        disable()
        raise SystemExit(0)
    if len(sys.argv) != 6:
        raise SystemExit("Expected management bridge, cluster bridge/CIDR and CI bridge/CIDR")
    apply(commands(*sys.argv[1:]))
