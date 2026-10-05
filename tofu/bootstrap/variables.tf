variable "endpoint" {
  type = string
  validation {
    condition     = startswith(var.endpoint, "https://")
    error_message = "Use an HTTPS Proxmox endpoint with trusted TLS."
  }
}
variable "node" { type = string }
variable "iso_datastore" { type = string }
variable "root_datastore" { type = string }
variable "ci_bridge" { type = string }
variable "build_profile" {
  type        = string
  default     = "standard"
  description = "Select after host admission; resource changes reboot the idle builder."
  validation {
    condition     = contains(["standard", "burst", "local-debug", "production-build"], var.build_profile)
    error_message = "Use standard, burst, local-debug or temporary production-build."
  }
}
variable "production_build_vcpus" {
  type        = number
  default     = null
  description = "Explicit production-build CPU choice from fresh actual host admission; no exclusive CPU pinning."
  validation {
    condition     = var.production_build_vcpus == null ? true : var.production_build_vcpus >= 1 && floor(var.production_build_vcpus) == var.production_build_vcpus
    error_message = "production_build_vcpus must be a positive integer."
  }
}
variable "production_build_memory_mib" {
  type        = number
  default     = null
  description = "Explicit production-build guest RAM from fresh maximum-allocation and anonymous resident-memory admission."
  validation {
    condition     = var.production_build_memory_mib == null ? true : var.production_build_memory_mib > 2048 && floor(var.production_build_memory_mib) == var.production_build_memory_mib
    error_message = "production_build_memory_mib must leave more than 2 GiB for the shared build slice and guest OS."
  }
}
variable "host_logical_cpus" {
  type        = number
  default     = null
  description = "Fresh measured host logical CPU count, required for temporary production-build admission."
  validation {
    condition     = var.host_logical_cpus == null ? true : var.host_logical_cpus >= 1 && floor(var.host_logical_cpus) == var.host_logical_cpus
    error_message = "host_logical_cpus must be a positive integer."
  }
}
variable "installer_boot" {
  type        = bool
  default     = true
  description = "Boot the official installer; set false after installation to boot the root disk and leave the ide2 CD-ROM empty."
}
variable "vm_id" {
  type = number
  validation {
    condition     = var.vm_id >= 100 && floor(var.vm_id) == var.vm_id
    error_message = "Select an unused integer Proxmox VM ID."
  }
}
variable "mac" { type = string }
variable "iso_path" { type = string }
variable "iso_sha256" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.iso_sha256))
    error_message = "Pin the official installer SHA-256."
  }
}
