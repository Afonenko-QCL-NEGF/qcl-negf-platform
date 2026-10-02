mock_provider "proxmox" {
  mock_resource "proxmox_virtual_environment_file" {
    defaults = { id = "local:snippets/qcl-negf-synthetic.yaml" }
  }
}

variables {
  endpoint            = "https://127.0.0.1:8006/"
  node                = "test"
  image_datastore     = "local"
  snippet_datastore   = "local"
  root_datastore      = "local-lvm"
  data_datastore      = "local-lvm"
  cluster_bridge      = "vmbr-test"
  ci_bridge           = "vmbr-test-ci"
  dns_servers         = ["192.0.2.1"]
  ssh_public_keys     = ["ssh-ed25519 SYNTHETIC-TEST-PUBLIC-KEY"]
  main_data_gib       = 16
  compute_scratch_gib = 16
  vms = {
    for name, number in { storage = 721, control = 722, compute = 723, ci = 720 } : name => {
      vm_id                       = number
      vcpus                       = 1
      memory_mib                  = 1024
      root_gib                    = 32
      mac                         = "52:54:00:72:${number - 700}:01"
      address                     = "192.0.2.${number - 700}/24"
      gateway                     = "192.0.2.1"
      image_file_id               = "local:import/qcl-negf-${name}-0000000000000000000000000000000000000000000000000000000000000000.qcow2"
      image_sha256                = "0000000000000000000000000000000000000000000000000000000000000000"
    }
  }
}

run "headless_q35_roles_never_request_physical_cdrom" {
  command = plan
  assert {
    condition = alltrue(concat(
      [for vm in values(proxmox_virtual_environment_vm.persistent) :
      try(vm.cdrom[0].file_id == "none" && vm.cdrom[0].interface == "ide0" && vm.boot_order == tolist(["virtio0"]), false)],
      [for vm in values(proxmox_virtual_environment_vm.replaceable) :
      try(vm.cdrom[0].file_id == "none" && vm.cdrom[0].interface == "ide0" && vm.boot_order == tolist(["virtio0"]), false)]
    ))
    error_message = "Every headless q35 role must declare an empty CD-ROM on ide0, leaving ide2 for cloud-init."
  }
}
