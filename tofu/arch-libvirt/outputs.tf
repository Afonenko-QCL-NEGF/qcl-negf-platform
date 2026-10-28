output "worker" {
  value = { hostname = "arch-worker", address = split("/", var.address)[0], domain_uuid = libvirt_domain.worker.uuid, vcpus = var.vcpus, memory_mib = var.memory_mib }
}
output "memory_capability" {
  value = {
    mode              = "conservative_reservation"
    resident_memory   = var.resident_memory
    dynamic_supported = false
    reason            = "native_active_grant_not_qualified"
  }
  description = "Declared profile capability only. Actual host grant/readback and guest readiness require native qualification."
}
output "scratch_volume" {
  value       = libvirt_volume.scratch.path
  description = "Protected local scratch volume survives root-image/domain replacement."
}
