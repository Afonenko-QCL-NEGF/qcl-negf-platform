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
  description = "Operator acknowledgement of fresh capacity/reserves for this operation. Stopped definition prepares storage; power/autostart additionally require an external resident grant and protected hook. Not native evidence."
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
variable "additional_routes" {
  type        = list(object({ to = string, via = string }))
  default     = []
  description = "Specific IPv4 NoCloud routes after the unchanged default. Next hops must be directly reachable on the guest subnet."
  validation {
    condition = alltrue([for route in var.additional_routes : try(
      can(cidrnetmask(route.to)) &&
      tonumber(split("/", route.to)[1]) >= 1 &&
      route.to == "${cidrhost(route.to, 0)}/${tonumber(split("/", route.to)[1])}" &&
      route.via == cidrhost("${route.via}/32", 0) &&
      can(cidrnetmask("${route.via}/32")), false
    )]) && length(distinct([for route in var.additional_routes : route.to])) == length(var.additional_routes)
    error_message = "Additional routes require unique canonical IPv4 CIDRs with prefix 1..32 and canonical bare IPv4 next hops; default routes are not allowed."
  }
}
variable "dns_servers" { type = list(string) }
variable "ssh_public_keys" {
  type = list(string)
  validation {
    condition     = length(var.ssh_public_keys) > 0 && alltrue([for key in var.ssh_public_keys : startswith(key, "ssh-")])
    error_message = "Supply administrative SSH public keys."
  }
}
variable "start_worker" {
  type        = bool
  default     = true
  description = "Desired current power state, not a grant. Set false for initial definition; require actual cold reservation and the protected start hook before true."
  validation {
    condition     = var.start_worker != null
    error_message = "Current power intent must be an explicit boolean, not null."
  }
}
variable "autostart_worker" {
  type        = bool
  default     = true
  description = "Desired host-boot autostart, not a grant. Keep false until the exact owned domain has a protected start permit/hook."
  validation {
    condition     = var.autostart_worker != null
    error_message = "Host autostart intent must be an explicit boolean, not null."
  }
}
