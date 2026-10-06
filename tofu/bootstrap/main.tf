# Temporary installer/builder. Its configuration does not depend on the solver
# or on a previously built application image. Keep its state in the private site.
locals {
  build_profile    = jsondecode(file("${path.module}/../../ops/build-profiles.json"))[var.build_profile]
  build_vcpus      = var.build_profile == "production-build" ? coalesce(var.production_build_vcpus, 1) : local.build_profile.vcpus
  build_memory_mib = var.build_profile == "production-build" ? coalesce(var.production_build_memory_mib, 1) : local.build_profile.memory_mib
}
resource "proxmox_virtual_environment_file" "installer" {
  node_name    = var.node
  datastore_id = var.iso_datastore
  content_type = "iso"
  source_file {
    path      = var.iso_path
    file_name = "qcl-bootstrap-${substr(var.iso_sha256, 0, 16)}.iso"
    checksum  = var.iso_sha256
  }
  lifecycle {
    precondition {
      condition     = filesha256(var.iso_path) == var.iso_sha256
      error_message = "Official installer bytes differ from the pinned SHA-256."
    }
  }
}
resource "proxmox_virtual_environment_vm" "builder" {
  node_name           = var.node
  vm_id               = var.vm_id
  name                = "qcl-bootstrap"
  tags                = ["qcl-negf", "bootstrap"]
  bios                = "seabios"
  machine             = "q35"
  on_boot             = false
  started             = true
  stop_on_destroy     = true
  reboot_after_update = true
  boot_order          = var.installer_boot ? ["ide2", "virtio0"] : ["virtio0", "ide2"]
  agent {
    enabled = true
    wait_for_ip { disabled = true }
  }
  cpu {
    cores = local.build_vcpus
    type  = "host"
  }
  memory {
    dedicated = local.build_memory_mib
    floating  = 0
  }
  disk {
    datastore_id = var.root_datastore
    interface    = "virtio0"
    size         = 128
    serial       = "qcl-bootstrap-root"
    backup       = false
  }
  # The pinned provider defaults an absent block to a physical CD-ROM on ide3.
  # q35 supports ide0/ide2 and a headless host has no physical media device.
  cdrom {
    file_id   = var.installer_boot ? proxmox_virtual_environment_file.installer.id : "none"
    interface = "ide2"
  }
  network_device {
    bridge      = var.ci_bridge
    mac_address = var.mac
    model       = "virtio"
  }
  serial_device {}
  vga { type = "serial0" }
  operating_system { type = "l26" }
  # Proxmox restricts arbitrary QEMU args to the root host user. The paired
  # bootstrap-media playbook owns only these temporary installer arguments.
  lifecycle {
    ignore_changes = [kvm_arguments]
    precondition {
      condition = var.build_profile == "production-build" ? try(
        var.production_build_vcpus <= var.host_logical_cpus &&
        var.production_build_memory_mib > local.build_profile.guest_reserve_mib,
        false
      ) : var.production_build_vcpus == null && var.production_build_memory_mib == null
      error_message = "Temporary production-build requires explicit CPU/RAM and measured host CPU count; guest CPUs cannot exceed the host. Fixed profiles reject resource overrides."
    }
  }
}
