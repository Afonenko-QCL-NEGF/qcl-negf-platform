variable "endpoint" {
  type        = string
  description = "HTTPS Proxmox API endpoint with trusted TLS certificate."
  validation {
    condition     = startswith(var.endpoint, "https://")
    error_message = "Use an HTTPS API endpoint."
  }
}
variable "node" {
  type        = string
  description = "Existing Proxmox node name."
}
variable "image_datastore" {
  type        = string
  description = "Existing datastore permitting import content."
}
variable "snippet_datastore" {
  type        = string
  description = "Existing datastore permitting snippets content."
}
variable "resource_prefix" {
  type        = string
  default     = "qcl-negf"
  description = "Stable namespace for cloud-init snippet files; choose a distinct prefix for each deployment sharing a snippet datastore."
  validation {
    condition     = length(var.resource_prefix) <= 48 && can(regex("^[a-z][a-z0-9]*(-[a-z0-9]+)*$", var.resource_prefix))
    error_message = "resource_prefix must be a lowercase ASCII slug starting with a letter, with at most 48 characters and single hyphen separators."
  }
}
variable "root_datastore" {
  type        = string
  description = "Datastore for replaceable VM root disks and cloud-init disks."
}
variable "data_datastore" {
  type        = string
  description = "Datastore for separately backed-up data/state/scratch disks."
}
variable "cluster_bridge" {
  type        = string
  description = "Existing private LAN or VLAN bridge on Proxmox."
}
variable "ci_bridge" {
  type        = string
  description = "Existing isolated CI network bridge with outbound GitHub access."
}
variable "build_profile" {
  type        = string
  default     = null
  nullable    = true
  description = "Optional standard/burst CI profile from the shared build table; null preserves custom site resources. Select only after fresh host/queue admission."
  validation {
    condition     = var.build_profile == null ? true : contains(["standard", "burst"], var.build_profile)
    error_message = "build_profile must be null, standard or burst."
  }
}
variable "dns_servers" {
  type        = list(string)
  description = "Site DNS server addresses."
}
variable "ssh_public_keys" {
  type        = list(string)
  description = "Administrative public SSH keys seeded once; no private key material."
  validation {
    condition     = length(var.ssh_public_keys) > 0 && alltrue([for key in var.ssh_public_keys : startswith(key, "ssh-")])
    error_message = "Supply at least one SSH public key."
  }
}
variable "vms" {
  type = map(object({
    vm_id         = number
    vcpus         = number
    memory_mib    = number
    root_gib      = number
    mac           = string
    address       = string
    gateway       = string
    started       = optional(bool, true)
    on_boot       = optional(bool, true)
    image_path    = optional(string)
    image_file_id = optional(string)
    image_sha256  = string
  }))
  description = "Exactly storage, control, compute and ci, with real site addresses and measured resource budgets."
  validation {
    condition     = toset(keys(var.vms)) == toset(["storage", "control", "compute", "ci"])
    error_message = "Define all four VM roles and no additional names."
  }
  validation {
    condition     = alltrue([for vm in values(var.vms) : vm.vcpus >= 1 && vm.memory_mib >= 1024 && vm.root_gib >= 16 && can(cidrhost(vm.address, 0)) && can(regex("^[0-9a-f]{64}$", vm.image_sha256))])
    error_message = "VMs need positive resources, an IPv4 CIDR and a SHA-256 pinned QCOW2 image."
  }
  validation {
    condition     = alltrue([for vm in values(var.vms) : (vm.image_path != null) != (vm.image_file_id != null)])
    error_message = "Choose exactly one image source: an operator-local image_path or a verified existing image_file_id."
  }
  validation {
    condition     = alltrue([for name, vm in var.vms : vm.image_file_id == null ? true : vm.image_file_id == "${var.image_datastore}:import/qcl-negf-${name}-${vm.image_sha256}.qcow2"])
    error_message = "Existing images must be staged in image_datastore with the full reviewed SHA-256 filename."
  }
  validation {
    condition     = sum(concat([0], [for vm in values(var.vms) : vm.memory_mib if vm.started || vm.on_boot])) <= var.host_memory_mib - var.host_reserve_mib
    error_message = "VMs started now or on host boot exceed the physical host memory budget after its reserve."
  }
  validation {
    condition     = sum(concat([0], [for vm in values(var.vms) : vm.vcpus if vm.started || vm.on_boot])) <= var.host_logical_cpus - var.host_reserved_cpus
    error_message = "VMs started now or on host boot exceed the non-overcommitted logical CPU budget."
  }
  validation {
    condition = var.build_profile == null ? true : try(
      var.vms["ci"].vcpus == local.build_profiles[var.build_profile].vcpus &&
      var.vms["ci"].memory_mib == local.build_profiles[var.build_profile].memory_mib,
      !contains(["standard", "burst"], var.build_profile)
    )
    error_message = "CI CPU/RAM must exactly match the selected shared build profile and the NixOS builder profile."
  }
  validation {
    condition     = var.build_profile == "burst" ? (!var.vms["compute"].started && !var.vms["compute"].on_boot) : true
    error_message = "Burst requires compute.started=false and compute.on_boot=false; restore standard before starting compute."
  }

}
variable "main_data_gib" {
  type        = number
  description = "Capacity of the persistent primary NFS data disk."
}
variable "controller_state_gib" {
  type        = number
  default     = 64
  description = "Separate PostgreSQL, AiiDA repository and Slurm state disk."
}
variable "compute_scratch_gib" {
  type        = number
  description = "Worker-local scratch capacity; main data remains on NFS."
}

variable "host_memory_mib" {
  type        = number
  default     = 65536
  description = "Physical Proxmox host budget; replace with measured usable RAM when different."
}
variable "host_reserve_mib" {
  type        = number
  default     = 8192
  description = "RAM reserved outside QCL-NEGF VMs, including hypervisor and other guests."
}
variable "host_logical_cpus" {
  type        = number
  default     = 32
  description = "Measured logical CPU count, not physical core count."
}
variable "host_reserved_cpus" {
  type    = number
  default = 2
}
