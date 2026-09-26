terraform {
  required_version = ">= 1.10, < 2.0"
  required_providers {
    libvirt = { source = "dmacvicar/libvirt", version = "= 0.9.9" }
  }
}
provider "libvirt" { uri = var.uri }
