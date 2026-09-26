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
    vm_id        = number
    vcpus        = number
    memory_mib   = number
    root_gib     = number
    mac          = string
    address      = string
    gateway      = string
    image_path   = string
    image_sha256 = string
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
    condition     = sum([for vm in values(var.vms) : vm.memory_mib]) <= var.host_memory_mib - var.host_reserve_mib
    error_message = "VM memory exceeds the physical host budget after its reserve."
  }
  validation {
    condition     = sum([for vm in values(var.vms) : vm.vcpus]) <= var.host_logical_cpus - var.host_reserved_cpus
    error_message = "VM vCPUs exceed the non-overcommitted logical CPU budget."
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
