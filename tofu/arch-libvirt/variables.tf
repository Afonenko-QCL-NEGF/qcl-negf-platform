variable "uri" {
  type        = string
  description = "Existing Arch libvirt system connection, normally qemu+ssh://operator@arch-host/system using SSH agent."
}
variable "bridge" {
  type        = string
  description = "Existing LAN bridge on Arch; must reach storage and control without NAT."
}
variable "pool_path" {
  type        = string
  default     = "/var/lib/libvirt/qcl-negf"
  description = "Arch directory on the selected local storage filesystem."
}
variable "image_path" { type = string }
variable "image_sha256" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.image_sha256))
    error_message = "Supply the reviewed QCOW2 SHA-256."
  }
}
variable "root_gib" {
  type    = number
  default = 32
}
variable "scratch_gib" {
  type        = number
  default     = 512
  description = "Separate local scratch disk; combined root+scratch is bounded below the 800 GB host budget."
  validation {
    condition     = var.scratch_gib >= 32 && var.scratch_gib + var.root_gib <= 700
    error_message = "Use at least 32 GiB scratch and no more than 700 GiB root+scratch, leaving host/image overhead within 800 GB."
  }
}
variable "memory_mib" {
  type    = number
  default = 30720
  validation {
    condition     = var.memory_mib >= 4096 && var.memory_mib <= 30720
    error_message = "Maximum guest RAM is 30 GiB on the nominal 32 GiB host, leaving 2 GiB before hypervisor overhead."
  }
}
variable "vcpus" {
  type    = number
  default = 12
  validation {
    condition     = var.vcpus >= 1 && var.vcpus <= 12
    error_message = "Use at most 12 guest vCPUs on this 12-logical-CPU host."
  }
}
variable "mac" { type = string }
variable "address" {
  type = string
  validation {
    condition     = can(cidrhost(var.address, 0))
    error_message = "Supply the guest's actual LAN IPv4 CIDR."
  }
}
variable "gateway" { type = string }
variable "dns_servers" { type = list(string) }
variable "ssh_public_keys" {
  type = list(string)
  validation {
    condition     = length(var.ssh_public_keys) > 0 && alltrue([for key in var.ssh_public_keys : startswith(key, "ssh-")])
    error_message = "Supply administrative SSH public keys."
  }
}
