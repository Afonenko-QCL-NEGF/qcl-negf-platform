output "inventory" {
  value = { for name, machine in libvirt_domain.machine : name => {
    domain         = machine.name
    ip             = local.addresses[name]
    mac            = local.macs[name]
    role           = name
    memory_mib     = var.resources[name].memory_mib
    vcpus          = var.resources[name].vcpus
    durable_serial = local.machines[name].serial
    root_path      = libvirt_volume.root[name].path
    durable_path   = libvirt_volume.durable[name].path
  } }
}
output "nocloud" {
  description = "Public bootstrap payload; caller writes metadata/user-data to ISO label cidata before apply."
  value = { for name, m in local.machines : name => {
    meta_data = yamlencode({ "instance-id" = "${var.namespace}-${name}", "local-hostname" = name })
    user_data = join("\n", ["#cloud-config", yamlencode({ users = [{ name = "root", "ssh_authorized_keys" = [var.ssh_public_key], "lock_passwd" = true }], "disable_root" = false, "ssh_pwauth" = false })])
  } }
}
output "resource_names" {
  value = {
    network = libvirt_network.lab.name
    pool    = libvirt_pool.lab.name
    domains = [for m in libvirt_domain.machine : m.name]
  }
}
