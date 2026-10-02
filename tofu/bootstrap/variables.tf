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
