terraform {
  required_version = ">= 1.10, < 2.0"
  backend "local" {}
  required_providers {
    proxmox = { source = "bpg/proxmox", version = "= 0.114.0" }
  }
}
provider "proxmox" {
  endpoint = var.endpoint
  insecure = false
  # PROXMOX_VE_API_TOKEN is supplied by the operator's secret manager.
  # Snippet uploads use the operator's existing SSH agent, never a private key in state.
  ssh { agent = true }
}
