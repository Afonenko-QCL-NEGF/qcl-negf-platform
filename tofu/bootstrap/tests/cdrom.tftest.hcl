# This text file is never uploaded: all provider operations are mocked.
mock_provider "proxmox" {
  mock_resource "proxmox_virtual_environment_file" {
    defaults = { id = "local:iso/qcl-synthetic.iso" }
  }
}
variables {
  endpoint       = "https://127.0.0.1:8006/"
  node           = "test"
  iso_datastore  = "local"
  root_datastore = "local-lvm"
  ci_bridge      = "vmbr-test-ci"
  vm_id          = 709
  mac            = "52:54:00:71:09:01"
  iso_path       = "tests/installer-fixture.txt"
  iso_sha256     = filesha256("tests/installer-fixture.txt")
}
run "official_installer_is_first_on_q35_supported_ide2" {
  command = plan
  assert {
    condition     = proxmox_virtual_environment_vm.builder.cdrom[0].file_id == "local:iso/qcl-synthetic.iso" && proxmox_virtual_environment_vm.builder.cdrom[0].interface == "ide2" && proxmox_virtual_environment_vm.builder.boot_order == tolist(["ide2", "virtio0"])
    error_message = "Installer boot must use only the declared ISO and a q35-supported IDE interface."
  }
}
run "disk_boot_keeps_explicit_empty_cdrom" {
  command = plan
  variables { installer_boot = false }
  assert {
    condition     = proxmox_virtual_environment_vm.builder.cdrom[0].file_id == "none" && proxmox_virtual_environment_vm.builder.cdrom[0].interface == "ide2" && proxmox_virtual_environment_vm.builder.boot_order == tolist(["virtio0", "ide2"])
    error_message = "Disk boot must keep the CD-ROM empty and avoid physical ide3 defaults."
  }
}
