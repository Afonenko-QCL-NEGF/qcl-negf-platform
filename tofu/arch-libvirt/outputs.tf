output "worker" {
  value = { hostname = "arch-worker", address = split("/", var.address)[0], domain_uuid = libvirt_domain.worker.uuid, vcpus = var.vcpus, memory_mib = var.memory_mib }
}
output "scratch_volume" {
  value       = libvirt_volume.scratch.path
  description = "Protected local scratch volume survives root-image/domain replacement."
}
