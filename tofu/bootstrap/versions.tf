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
  ssh {
    agent    = true
    username = "root"
  }
}
