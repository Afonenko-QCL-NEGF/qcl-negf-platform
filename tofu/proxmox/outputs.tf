output "hosts" {
  value = { for name, vm in var.vms : name => { address = split("/", vm.address)[0], vm_id = vm.vm_id } }
}
output "persistent_vm_ids" {
  value       = { for name, vm in proxmox_virtual_environment_vm.persistent : name => vm.vm_id }
  description = "Protected VM identities; retain their data disks during deliberate OS reinstallation."
}
