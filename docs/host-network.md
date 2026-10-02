# Existing Proxmox host policy

`ansible/proxmox-host.yml` owns the two QCL guest bridges and the `qcl_negf` /
`qcl_negf_nat` nftables tables. OpenTofu consumes the resulting bridge names; do
not give a second tool ownership of these resources. The management bridge
`vmbr0`, existing VM definitions and Proxmox firewall tables remain externally
managed. No scientific package is installed on the host.

Copy `ansible/proxmox-site.yml.example` and a `proxmox_hypervisors` inventory into
a private site repository. Supply two disjoint IPv4 guest subnets, their gateway
CIDRs, and every reachable management, production and private LAN in
`qcl_ci_denied_cidrs`. List any DNS servers inside denied LANs explicitly in
`qcl_ci_dns_servers`: this grants only TCP/UDP port 53 to those exact IPv4
addresses and rejects DNS exceptions inside the scientific cluster subnet.
CI has no access to host services or scientific guests; host-initiated
SSH return traffic is allowed. New IPv6 forwarding from CI is denied. The host
routes and masquerades IPv4 guest traffic through `vmbr0`. This is an additional
restrictive policy: it cannot override a drop in existing Proxmox firewall
tables, which must permit the intended outbound forwarding.

```sh
ansible-playbook -i /absolute/private-site/inventory.ini \
  ansible/proxmox-host.yml -e @/absolute/private-site/proxmox-site.yml --check --diff
```

Review the complete diff, existing firewall and any staged network edits before
the administrative apply. `ifreload -a` applies the current host network
configuration; preserve console access during that operation. The playbook
requires `/etc/network/interfaces` to source `interfaces.d`, existing `vmbr0`,
Proxmox `qm`, and nftables >= 1.0.9. It refuses to adopt already present QCL
bridge names without the managed `/etc/network/interfaces.d/qcl-negf` drop-in.
Existing bridges require an explicit ownership review first.

Set `qcl_apply_host_policy: true` in the private vars only for the reviewed
apply, then repeat the command without `--check`. The dedicated systemd service
persists the two nftables tables across host restarts. Each reload atomically
replaces only those tables; it does not flush the host ruleset. The playbook
does not change the host default gateway or the `vmbr0` declaration.

After apply, verify SSH from the host to CI, outbound DNS/HTTPS from both guest
subnets, refusal of CI connections to the cluster and denied LANs, and isolation
after a host policy reload. Expression/template validation cannot establish
reachability or isolation on the target host. If Proxmox firewall maintenance
removes externally managed tables, restart `qcl-negf-network.service` and repeat
these checks before permitting CI jobs.

For an explicitly selected existing Pnetlab VM, set `qcl_pnetlab_vm_id` to its
ID. Only its RAM ceiling (`qcl_pnetlab_memory_mib`) and balloon floor
(`qcl_pnetlab_balloon_mib`) are managed. The playbook uses exact configuration
lines and reports pending changes. It does not create, import, destroy, stop or
restart that VM. Plan a separately authorized graceful restart if Proxmox marks
these settings pending; verify the actual running limit afterward. Leave the
ID null when another owner already applied that policy.

Keep host inventory, actual addresses, API credentials and OpenTofu state
private. The public examples use documentation address ranges.

References: [Proxmox network configuration](https://pve.proxmox.com/pve-docs/pve-admin-guide.html#sysadmin_network_configuration),
[nftables manual](https://netfilter.org/projects/nftables/manpage.html),
[bpg Proxmox bridge schema](https://github.com/bpg/terraform-provider-proxmox/blob/v0.114.0/docs/resources/network_linux_bridge.md).
