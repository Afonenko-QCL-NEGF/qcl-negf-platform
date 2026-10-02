# Temporary installer/builder. Its configuration does not depend on the solver
# or on a previously built application image. Keep its state in the private site.
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
  node_name       = var.node
  vm_id           = var.vm_id
  name            = "qcl-bootstrap"
  tags            = ["qcl-negf", "bootstrap"]
  bios            = "seabios"
  machine         = "q35"
  on_boot         = false
  started         = true
  stop_on_destroy = true
  boot_order      = ["ide2", "virtio0"]
  agent {
    enabled = true
    wait_for_ip { disabled = true }
  }
  cpu {
    cores = 4
    type  = "host"
  }
  memory {
    dedicated = 8192
    floating  = 0
  }
  disk {
    datastore_id = var.root_datastore
    interface    = "virtio0"
    size         = 128
    serial       = "qcl-bootstrap-root"
    backup       = false
  }
  cdrom {
    file_id   = proxmox_virtual_environment_file.installer.id
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
}
