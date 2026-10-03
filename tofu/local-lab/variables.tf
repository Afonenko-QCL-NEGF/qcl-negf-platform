variable "libvirt_uri" {
  type    = string
  default = "qemu:///system"
}
variable "namespace" {
  type = string
  validation {
    condition     = can(regex("^qcl-[a-z0-9][a-z0-9-]{1,30}$", var.namespace))
    error_message = "Use a dedicated qcl- namespace."
  }
}
variable "pool_path" {
  type = string
  validation {
    condition     = startswith(var.pool_path, "/") && !contains(["/", "/tmp", "/var/lib/libvirt/images"], var.pool_path)
    error_message = "Supply a dedicated absolute directory reachable and writable by the libvirt daemon."
  }
}
variable "ownership_verified" {
  type        = bool
  default     = false
  description = "Caller verified actual libvirt names and pool directory against this exact private state; foreign collision must abort."
}
variable "bootstrap_image" { type = string }
variable "bootstrap_sha256" { type = string }
variable "ssh_public_key" {
  type = string
  validation {
    condition     = can(regex("^ssh-(ed25519|rsa) [A-Za-z0-9+/=]+", var.ssh_public_key)) && !strcontains(var.ssh_public_key, "PRIVATE KEY")
    error_message = "Supply only one SSH public key; never private bytes."
  }
}
variable "seed_images" {
  type        = map(string)
  description = "Caller materializes the nocloud output as ISO cidata; contains public SSH key only."
  validation {
    condition     = toset(keys(var.seed_images)) == toset(["control", "storage", "worker-1", "worker-2"])
    error_message = "One public-only NoCloud seed ISO is required per machine."
  }
}
variable "network_cidr" {
  type    = string
  default = "192.168.231.0/24"
  validation {
    condition     = can(cidrhost(var.network_cidr, 254)) && can(regex("/24$", var.network_cidr))
    error_message = "Supply a non-overlapping private IPv4 /24."
  }
}
variable "resources" {
  type = map(object({ memory_mib = number, vcpus = number }))
  default = {
    control  = { memory_mib = 2048, vcpus = 2 }
    storage  = { memory_mib = 768, vcpus = 1 }
    worker-1 = { memory_mib = 2304, vcpus = 2 }
    worker-2 = { memory_mib = 2304, vcpus = 2 }
  }
  validation {
    condition     = toset(keys(var.resources)) == toset(["control", "storage", "worker-1", "worker-2"]) && alltrue([for r in values(var.resources) : r.memory_mib >= 512 && r.vcpus >= 1 && floor(r.vcpus) == r.vcpus])
    error_message = "Measured budgets must cover exactly the four roles with positive CPUs and RAM."
  }
}
variable "root_capacity_gib" {
  type    = number
  default = 24
}
variable "durable_capacity_gib" {
  type    = number
  default = 8
}
