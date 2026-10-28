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
  type        = number
  description = "Explicit reviewed root capacity in GiB, fitting the selected image virtual size."
  validation {
    condition     = var.root_gib > 0 && floor(var.root_gib) == var.root_gib
    error_message = "Root capacity must be an explicit positive integer GiB."
  }
}
variable "scratch_gib" {
  type        = number
  description = "Explicit separately owned scratch capacity in GiB from fresh storage inventory."
  validation {
    condition     = var.scratch_gib > 0 && floor(var.scratch_gib) == var.scratch_gib
    error_message = "Scratch capacity must be an explicit positive integer GiB."
  }
}
variable "memory_mib" {
  type        = number
  description = "Explicit fixed guest RAM in MiB; not a measurement or physical host reservation."
  validation {
    condition     = var.memory_mib > 0 && floor(var.memory_mib) == var.memory_mib
    error_message = "Memory must be an explicit positive integer MiB."
  }
}
variable "vcpus" {
  type        = number
  description = "Explicit guest logical CPU count from fresh private host admission."
  validation {
    condition     = var.vcpus >= 1 && floor(var.vcpus) == var.vcpus
    error_message = "vCPUs must be an explicit positive integer."
  }
}
variable "resident_memory" {
  type        = object({ minimum_mib = number, startup_mib = number, maximum_mib = number })
  description = "Private resident policy projection. This profile supports conservative reservation only; native dynamic grants are not qualified."
  validation {
    condition     = var.resident_memory.minimum_mib == var.memory_mib && var.resident_memory.startup_mib == var.memory_mib && var.resident_memory.maximum_mib == var.memory_mib
    error_message = "Unqualified dynamic mode: minimum/startup/maximum must equal memory_mib for conservative reservation."
  }
}
variable "ownership_verified" {
  type        = bool
  default     = false
  description = "Operator acknowledgement of the reviewed exact ownership/state inventory, not native evidence."
}
variable "capacity_verified" {
  type        = bool
  default     = false
  description = "Operator acknowledgement of fresh capacity/reserves and external resident grant admission, not native evidence."
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
