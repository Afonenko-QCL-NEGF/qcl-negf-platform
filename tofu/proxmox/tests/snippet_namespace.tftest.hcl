# Provider mocking evaluates the actual resource arguments without contacting
# Proxmox, uploading snippets or importing images.
mock_provider "proxmox" {
  mock_resource "proxmox_virtual_environment_file" {
    defaults = { id = "local:snippets/qcl-negf-synthetic.yaml" }
  }
}

variables {
  endpoint            = "https://127.0.0.1:8006/"
  node                = "test"
  image_datastore     = "local"
  snippet_datastore   = "local"
  root_datastore      = "local-lvm"
  data_datastore      = "local-lvm"
  cluster_bridge      = "vmbr-test"
  ci_bridge           = "vmbr-test-ci"
  dns_servers         = ["192.0.2.1"]
  ssh_public_keys     = ["ssh-ed25519 SYNTHETIC-TEST-PUBLIC-KEY"]
  main_data_gib       = 16
  compute_scratch_gib = 16
  vms = {
    for name, number in { storage = 721, control = 722, compute = 723, ci = 720 } : name => {
      vm_id                       = number
      vcpus                       = 1
      memory_mib                  = 1024
      root_gib                    = 32
      mac                         = "52:54:00:72:${number - 700}:01"
      address                     = "192.0.2.${number - 700}/24"
      gateway                     = "192.0.2.1"
      image_file_id               = "local:import/qcl-negf-${name}-0000000000000000000000000000000000000000000000000000000000000000.qcow2"
      image_sha256                = "0000000000000000000000000000000000000000000000000000000000000000"
    }
  }
}

run "default_keeps_existing_snippet_names" {
  command = plan
  assert {
    condition = alltrue([
      for name in keys(var.vms) :
      proxmox_virtual_environment_file.user_data[name].source_raw[0].file_name == "qcl-negf-${name}-user-data.yaml" &&
      proxmox_virtual_environment_file.network_data[name].source_raw[0].file_name == "qcl-negf-${name}-network.yaml"
    ])
    error_message = "The default namespace must preserve every production cloud-init file name."
  }
}

run "rehearsal_has_disjoint_snippet_paths_in_same_datastore" {
  command = plan
  variables { resource_prefix = "qcl-negf-rehearsal" }
  assert {
    condition = alltrue([
      for name in keys(var.vms) :
      proxmox_virtual_environment_file.user_data[name].source_raw[0].file_name == "qcl-negf-rehearsal-${name}-user-data.yaml" &&
      proxmox_virtual_environment_file.network_data[name].source_raw[0].file_name == "qcl-negf-rehearsal-${name}-network.yaml" &&
      proxmox_virtual_environment_file.user_data[name].source_raw[0].file_name != "qcl-negf-${name}-user-data.yaml" &&
      proxmox_virtual_environment_file.network_data[name].source_raw[0].file_name != "qcl-negf-${name}-network.yaml"
    ])
    error_message = "Both rehearsal snippet resources must have paths disjoint from the default inventory on the same datastore."
  }
  assert {
    condition = alltrue([
      for name in keys(var.vms) :
      proxmox_virtual_environment_file.user_data[name].datastore_id == var.snippet_datastore &&
      proxmox_virtual_environment_file.network_data[name].datastore_id == var.snippet_datastore
    ])
    error_message = "The namespace must isolate file names without requiring a separate datastore."
  }
}

run "reject_path_components" {
  command = plan
  variables { resource_prefix = "../qcl-negf" }
  expect_failures = [var.resource_prefix]
}

run "reject_non_ascii" {
  command = plan
  variables { resource_prefix = "qcl-тест" }
  expect_failures = [var.resource_prefix]
}

run "reject_oversized_prefix" {
  command = plan
  variables { resource_prefix = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
  expect_failures = [var.resource_prefix]
}
