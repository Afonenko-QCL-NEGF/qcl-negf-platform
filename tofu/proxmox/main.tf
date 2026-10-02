locals {
  persistent   = { for name, vm in var.vms : name => vm if contains(["storage", "control"], name) }
  replaceable  = { for name, vm in var.vms : name => vm if contains(["compute", "ci"], name) }
  local_images = { for name, vm in var.vms : name => vm if vm.image_file_id == null }
  root_images  = { for name, vm in var.vms : name => vm.image_file_id != null ? vm.image_file_id : proxmox_virtual_environment_file.root_image[name].id }
}
resource "proxmox_virtual_environment_file" "root_image" {
  for_each     = local.local_images
  node_name    = var.node
  datastore_id = var.image_datastore
  content_type = "import"
  source_file {
    path      = each.value.image_path
    file_name = "qcl-negf-${each.key}-${substr(each.value.image_sha256, 0, 16)}.qcow2"
    checksum  = each.value.image_sha256
  }
  lifecycle {
    precondition {
      condition     = filesha256(each.value.image_path) == each.value.image_sha256
      error_message = "QCOW2 image content does not match the reviewed SHA-256."
    }
  }
}
resource "proxmox_virtual_environment_file" "user_data" {
  for_each     = var.vms
  node_name    = var.node
  datastore_id = var.snippet_datastore
  content_type = "snippets"
  source_raw {
    file_name = "${var.resource_prefix}-${each.key}-user-data.yaml"
    data      = "#cloud-config\n${yamlencode({ hostname = each.key, ssh_pwauth = false, ssh_authorized_keys = var.ssh_public_keys })}"
  }
}
resource "proxmox_virtual_environment_file" "network_data" {
  for_each     = var.vms
  node_name    = var.node
  datastore_id = var.snippet_datastore
  content_type = "snippets"
  source_raw {
    file_name = "${var.resource_prefix}-${each.key}-network.yaml"
    data = yamlencode({ version = 2, ethernets = { cluster0 = {
      match       = { macaddress = lower(each.value.mac) }
      "set-name"  = "cluster0"
      addresses   = [each.value.address]
      routes      = [{ to = "default", via = each.value.gateway }]
      nameservers = { addresses = var.dns_servers }
    } } })
  }
}
resource "proxmox_virtual_environment_vm" "persistent" {
  for_each                             = local.persistent
  name                                 = each.key
  node_name                            = var.node
  vm_id                                = each.value.vm_id
  tags                                 = ["qcl-negf", each.key]
  bios                                 = "seabios"
  machine                              = "q35"
  on_boot                              = true
  protection                           = true
  delete_unreferenced_disks_on_destroy = false
  agent { enabled = true }
  cpu {
    cores = each.value.vcpus
    type  = "host"
  }
  memory {
    dedicated = each.value.memory_mib
    floating  = 0
  }
  disk {
    datastore_id = var.root_datastore
    import_from  = local.root_images[each.key]
    interface    = "virtio0"
    size         = each.value.root_gib
    serial       = "qcl-root"
    backup       = false
  }
  disk {
    datastore_id = var.data_datastore
    interface    = "virtio1"
    size         = each.key == "storage" ? var.main_data_gib : var.controller_state_gib
    serial       = each.key == "storage" ? "qcl-data" : "qcl-state"
    backup       = true
  }
  network_device {
    bridge      = var.cluster_bridge
    mac_address = each.value.mac
    model       = "virtio"
  }
  initialization {
    datastore_id         = var.root_datastore
    user_data_file_id    = proxmox_virtual_environment_file.user_data[each.key].id
    network_data_file_id = proxmox_virtual_environment_file.network_data[each.key].id
  }
  serial_device {}
  operating_system { type = "l26" }
  lifecycle { prevent_destroy = true }
}
resource "proxmox_virtual_environment_vm" "replaceable" {
  for_each        = local.replaceable
  name            = each.key
  node_name       = var.node
  vm_id           = each.value.vm_id
  tags            = ["qcl-negf", each.key]
  bios            = "seabios"
  machine         = "q35"
  on_boot         = true
  stop_on_destroy = true
  agent { enabled = true }
  cpu {
    cores = each.value.vcpus
    type  = "host"
  }
  memory {
    dedicated = each.value.memory_mib
    floating  = 0
  }
  disk {
    datastore_id = var.root_datastore
    import_from  = local.root_images[each.key]
    interface    = "virtio0"
    size         = each.value.root_gib
    serial       = "qcl-root"
  }
  dynamic "disk" {
    for_each = each.key == "compute" ? [1] : []
    content {
      datastore_id = var.data_datastore
      interface    = "virtio1"
      size         = var.compute_scratch_gib
      serial       = "qcl-scratch"
      backup       = false
    }
  }
  network_device {
    bridge      = each.key == "ci" ? var.ci_bridge : var.cluster_bridge
    mac_address = each.value.mac
    model       = "virtio"
  }
  initialization {
    datastore_id         = var.root_datastore
    user_data_file_id    = proxmox_virtual_environment_file.user_data[each.key].id
    network_data_file_id = proxmox_virtual_environment_file.network_data[each.key].id
  }
  serial_device {}
  operating_system { type = "l26" }
}
