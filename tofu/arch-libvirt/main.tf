resource "terraform_data" "admission" {
  input = "arch-worker"
  lifecycle {
    precondition {
      condition     = var.ownership_verified
      error_message = "Require a reviewed ownership/state inventory for the exact domain, pool, bridge and disks before apply."
    }
    precondition {
      condition     = var.capacity_verified
      error_message = "Require fresh private host capacity/reserves and reviewed admission for the planned storage or resident operation before apply."
    }
    precondition {
      condition     = filesha256(var.image_path) == var.image_sha256
      error_message = "The local root image does not match its reviewed SHA-256."
    }
    precondition {
      condition = length(var.additional_routes) == 0 || try(
        can(cidrnetmask(var.address)) && tonumber(split("/", var.address)[1]) <= 30 &&
        alltrue([for route in var.additional_routes :
          cidrhost("${route.via}/${split("/", var.address)[1]}", 0) == cidrhost(var.address, 0) &&
          route.via != cidrhost("${split("/", var.address)[0]}/32", 0) &&
          route.via != cidrhost(var.address, 0) && route.via != cidrhost(var.address, -1)
        ]), false
      )
      error_message = "Additional routes need an IPv4 guest subnet with prefix at most 30 and directly reachable next hops distinct from guest, network and broadcast addresses."
    }
  }
}
resource "libvirt_pool" "qcl" {
  name       = "qcl-negf"
  type       = "dir"
  target     = { path = var.pool_path }
  depends_on = [terraform_data.admission]
  lifecycle { prevent_destroy = true }
}
resource "libvirt_volume" "base" {
  name   = "qcl-negf-root-${substr(var.image_sha256, 0, 16)}.qcow2"
  pool   = libvirt_pool.qcl.name
  target = { format = { type = "qcow2" } }
  create = { content = { url = abspath(var.image_path) } }
}
resource "libvirt_volume" "root" {
  name          = "arch-worker-root-${substr(var.image_sha256, 0, 16)}.qcow2"
  pool          = libvirt_pool.qcl.name
  capacity      = var.root_gib * 1024 * 1024 * 1024
  allocation    = 0
  target        = { format = { type = "qcow2" } }
  backing_store = { path = libvirt_volume.base.path, format = { type = "qcow2" } }
}
resource "libvirt_volume" "scratch" {
  name       = "arch-worker-scratch.qcow2"
  pool       = libvirt_pool.qcl.name
  capacity   = var.scratch_gib * 1024 * 1024 * 1024
  allocation = 0
  target     = { format = { type = "qcow2" } }
  lifecycle { prevent_destroy = true }
}
resource "libvirt_cloudinit_disk" "seed" {
  name      = "arch-worker-seed"
  user_data = "#cloud-config\n${yamlencode({ hostname = "arch-worker", ssh_pwauth = false, ssh_authorized_keys = var.ssh_public_keys })}"
  meta_data = yamlencode({ "instance-id" = "arch-worker-${substr(var.image_sha256, 0, 16)}", "local-hostname" = "arch-worker" })
  network_config = yamlencode({ version = 2, ethernets = { cluster0 = {
    match       = { macaddress = lower(var.mac) }
    "set-name"  = "cluster0"
    addresses   = [var.address]
    routes      = concat([{ to = "default", via = var.gateway }], var.additional_routes)
    nameservers = { addresses = var.dns_servers }
  } } })
}
resource "libvirt_volume" "seed" {
  name   = "arch-worker-seed-${libvirt_cloudinit_disk.seed.id}.iso"
  pool   = libvirt_pool.qcl.name
  target = { format = { type = "iso" } }
  create = { content = { url = libvirt_cloudinit_disk.seed.path } }
}
resource "libvirt_domain" "worker" {
  name                = "arch-worker"
  type                = "kvm"
  running             = var.start_worker
  autostart           = var.autostart_worker
  memory              = var.memory_mib
  memory_unit         = "MiB"
  current_memory      = var.resident_memory.startup_mib
  current_memory_unit = "MiB"
  vcpu                = var.vcpus
  cpu                 = { mode = "host-passthrough" }
  os                  = { type = "hvm", type_arch = "x86_64", type_machine = "q35", boot_devices = [{ dev = "hd" }] }
  devices = {
    # Driver/device support alone does not qualify online memory mutation.
    mem_balloon = { model = "virtio", auto_deflate = "off" }
    disks = [
      { device = "disk", driver = { name = "qemu", type = "qcow2" }, source = { file = { file = libvirt_volume.root.path } }, target = { dev = "vda", bus = "virtio" }, serial = "qcl-root" },
      { device = "disk", driver = { name = "qemu", type = "qcow2", discard = "unmap" }, source = { file = { file = libvirt_volume.scratch.path } }, target = { dev = "vdb", bus = "virtio" }, serial = "qcl-scratch" },
      { device = "cdrom", source = { file = { file = libvirt_volume.seed.path } }, target = { dev = "sda", bus = "sata" }, read_only = true }
    ]
    interfaces = [{ model = { type = "virtio" }, mac = { address = var.mac }, source = { bridge = { bridge = var.bridge } } }]
    # Libvirt allocates PTY source paths; only the guest target is declarative.
    serials  = [{ target = { port = 0 } }]
    consoles = [{ target = { type = "serial", port = 0 } }]
    # Libvirt owns the guest-agent socket mode/path, including inactive XML normalization.
    channels = [{ source = { unix = {} }, target = { virt_io = { name = "org.qemu.guest_agent.0" } } }]
  }
}
