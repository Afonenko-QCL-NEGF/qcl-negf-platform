locals {
  machines = {
    control  = { suffix = 10, serial = "qcl-state" }
    storage  = { suffix = 11, serial = "qcl-data" }
    worker-1 = { suffix = 21, serial = "qcl-scratch" }
    worker-2 = { suffix = 22, serial = "qcl-scratch" }
  }
  addresses = { for name, m in local.machines : name => cidrhost(var.network_cidr, m.suffix) }
  # Namespace-derived MAC prefix prevents collisions between independent labs.
  macs = { for name, m in local.machines : name => format("52:54:%s:%s:00:%02x", substr(sha256(var.namespace), 0, 2), substr(sha256(var.namespace), 2, 2), m.suffix) }
}
resource "terraform_data" "admission" {
  input = var.namespace
  lifecycle {
    precondition {
      condition     = var.ownership_verified
      error_message = "Refusing resource adoption: run the actual libvirt/state ownership preflight first."
    }
    precondition {
      condition     = filesha256(var.bootstrap_image) == var.bootstrap_sha256
      error_message = "Bootstrap image SHA256 differs from the selected immutable build."
    }
  }
}
resource "libvirt_network" "lab" {
  name      = "${var.namespace}-network"
  autostart = false
  forward   = { mode = "nat" }
  domain    = { name = "${var.namespace}.internal", local_only = "yes" }
  dns       = { host = [for name, ip in local.addresses : { ip = ip, hostnames = [{ hostname = name }] }] }
  ips = [{ address = cidrhost(var.network_cidr, 1), prefix = 24, dhcp = {
    ranges = [{ start = cidrhost(var.network_cidr, 100), end = cidrhost(var.network_cidr, 200) }]
    hosts  = [for name, ip in local.addresses : { ip = ip, mac = local.macs[name], name = name }]
  } }]
  depends_on = [terraform_data.admission]
}
resource "libvirt_pool" "lab" {
  name       = "${var.namespace}-pool"
  type       = "dir"
  target     = { path = var.pool_path }
  depends_on = [terraform_data.admission]
  lifecycle { prevent_destroy = true }
}
resource "libvirt_volume" "base" {
  name   = "${var.namespace}-bootstrap-${substr(var.bootstrap_sha256, 0, 16)}.qcow2"
  pool   = libvirt_pool.lab.name
  target = { format = { type = "qcow2" } }
  create = { content = { url = abspath(var.bootstrap_image) } }
  lifecycle { prevent_destroy = true }
}
resource "libvirt_volume" "root" {
  for_each      = local.machines
  name          = "${var.namespace}-${each.key}-root.qcow2"
  pool          = libvirt_pool.lab.name
  capacity      = var.root_capacity_gib * 1024 * 1024 * 1024
  allocation    = 0
  target        = { format = { type = "qcow2" } }
  backing_store = { path = libvirt_volume.base.path, format = { type = "qcow2" } }
}
resource "libvirt_volume" "durable" {
  for_each   = local.machines
  name       = "${var.namespace}-${each.key}-${each.value.serial}.qcow2"
  pool       = libvirt_pool.lab.name
  capacity   = var.durable_capacity_gib * 1024 * 1024 * 1024
  allocation = 0
  target     = { format = { type = "qcow2" } }
  lifecycle { prevent_destroy = true }
}
resource "libvirt_volume" "seed" {
  for_each = local.machines
  name     = "${var.namespace}-${each.key}-cidata.iso"
  pool     = libvirt_pool.lab.name
  target   = { format = { type = "raw" } }
  create   = { content = { url = abspath(var.seed_images[each.key]) } }
}
resource "libvirt_domain" "machine" {
  for_each    = local.machines
  name        = "${var.namespace}-${each.key}"
  type        = "kvm"
  running     = true
  autostart   = false
  memory      = var.resources[each.key].memory_mib
  memory_unit = "MiB"
  vcpu        = var.resources[each.key].vcpus
  cpu         = { mode = "host-passthrough" }
  os          = { type = "hvm", type_arch = "x86_64", type_machine = "pc", boot_devices = [{ dev = "hd" }] }
  devices = {
    disks = [
      { device = "disk", driver = { name = "qemu", type = "qcow2" }, source = { file = { file = libvirt_volume.root[each.key].path } }, target = { dev = "vda", bus = "virtio" }, serial = "qcl-root" },
      { device = "disk", driver = { name = "qemu", type = "qcow2" }, source = { file = { file = libvirt_volume.durable[each.key].path } }, target = { dev = "vdb", bus = "virtio" }, serial = each.value.serial },
      { device = "cdrom", driver = { name = "qemu", type = "raw" }, source = { file = { file = libvirt_volume.seed[each.key].path } }, target = { dev = "hda", bus = "ide" }, read_only = true }
    ]
    interfaces = [{ model = { type = "virtio" }, mac = { address = local.macs[each.key] }, source = { network = { network = libvirt_network.lab.name } } }]
    serials    = [{ source = { pty = { path = "" } }, target = { port = 0 } }]
    consoles   = [{ source = { pty = { path = "" } }, target = { type = "serial", port = 0 } }]
  }
}
