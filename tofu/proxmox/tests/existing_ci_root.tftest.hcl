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

# Fixtures use documentation addresses and are not observations of VM710.
run "default_preserves_image_roots" {
  command = plan
  assert {
    condition     = !var.vms["ci"].adopt_existing_root && contains(keys(local.root_images), "ci") && proxmox_virtual_environment_vm.replaceable["ci"].disk[0].serial == "qcl-root"
    error_message = "Default CI remains image-backed; adoption must be explicit."
  }
}
run "adopted_ci_uses_observed_root_without_import" {
  command = plan
  variables {
    vms = { for name, number in { storage = 721, control = 722, compute = 723, ci = 720 } : name => {
      vm_id               = number
      vcpus               = 1
      memory_mib          = 1024
      root_gib            = name == "ci" ? 128 : 32
      mac                 = "52:54:00:72:${number - 700}:01"
      address             = "192.0.2.${number - 700}/24"
      gateway             = "192.0.2.1"
      adopt_existing_root = name == "ci"
      existing_root       = name == "ci" ? { datastore_id = "local-lvm", size_gib = 128, serial = "fixture-ci-root" } : null
      image_file_id       = name == "ci" ? null : "local:import/qcl-negf-${name}-0000000000000000000000000000000000000000000000000000000000000000.qcow2"
      image_sha256        = name == "ci" ? null : "0000000000000000000000000000000000000000000000000000000000000000"
    } }
  }
  assert {
    condition     = !contains(keys(local.local_images), "ci") && !contains(keys(local.root_images), "ci") && !contains(keys(proxmox_virtual_environment_file.root_image), "ci")
    error_message = "Adopted CI must not upload or select an image root."
  }
  assert {
    condition     = proxmox_virtual_environment_vm.replaceable["ci"].disk[0].datastore_id == "local-lvm" && proxmox_virtual_environment_vm.replaceable["ci"].disk[0].size == 128 && proxmox_virtual_environment_vm.replaceable["ci"].disk[0].serial == "fixture-ci-root" && try(proxmox_virtual_environment_vm.replaceable["ci"].disk[0].import_from == null || proxmox_virtual_environment_vm.replaceable["ci"].disk[0].import_from == "", false)
    error_message = "The declared existing disk tuple must survive with no import source."
  }
  assert {
    condition     = contains(keys(local.root_images), "compute") && proxmox_virtual_environment_vm.replaceable["compute"].disk[0].serial == "qcl-root" && proxmox_virtual_environment_vm.persistent["storage"].protection
    error_message = "Other role image/persistence behavior must remain unchanged."
  }
}
run "reject_non_ci_adoption" {
  command = plan
  variables {
    vms = { for name, number in { storage = 721, control = 722, compute = 723, ci = 720 } : name => {
      vm_id               = number
      vcpus               = 1
      memory_mib          = 1024
      root_gib            = name == "compute" ? 128 : 32
      mac                 = "52:54:00:72:${number - 700}:01"
      address             = "192.0.2.${number - 700}/24"
      gateway             = "192.0.2.1"
      adopt_existing_root = name == "compute"
      existing_root       = name == "compute" ? { datastore_id = "local-lvm", size_gib = 128, serial = "fixture-ci-root" } : null
      image_file_id       = name == "compute" ? null : "local:import/qcl-negf-${name}-0000000000000000000000000000000000000000000000000000000000000000.qcow2"
      image_sha256        = name == "compute" ? null : "0000000000000000000000000000000000000000000000000000000000000000"
    } }
  }
  expect_failures = [var.vms]
}
run "reject_adoption_with_image_source" {
  command = plan
  variables {
    vms = { for name, number in { storage = 721, control = 722, compute = 723, ci = 720 } : name => {
      vm_id               = number
      vcpus               = 1
      memory_mib          = 1024
      root_gib            = name == "ci" ? 128 : 32
      mac                 = "52:54:00:72:${number - 700}:01"
      address             = "192.0.2.${number - 700}/24"
      gateway             = "192.0.2.1"
      adopt_existing_root = name == "ci"
      existing_root       = name == "ci" ? { datastore_id = "local-lvm", size_gib = 128, serial = "fixture-ci-root" } : null
      image_file_id       = name == "ci" ? null : "local:import/qcl-negf-${name}-0000000000000000000000000000000000000000000000000000000000000000.qcow2"
      image_sha256        = name == "ci" ? "1111111111111111111111111111111111111111111111111111111111111111" : "0000000000000000000000000000000000000000000000000000000000000000"
    } }
  }
  expect_failures = [var.vms]
}
run "reject_descriptor_size_mismatch" {
  command = plan
  variables {
    vms = { for name, number in { storage = 721, control = 722, compute = 723, ci = 720 } : name => {
      vm_id               = number
      vcpus               = 1
      memory_mib          = 1024
      root_gib            = name == "ci" ? 128 : 32
      mac                 = "52:54:00:72:${number - 700}:01"
      address             = "192.0.2.${number - 700}/24"
      gateway             = "192.0.2.1"
      adopt_existing_root = name == "ci"
      existing_root       = name == "ci" ? { datastore_id = "local-lvm", size_gib = 64, serial = "fixture-ci-root" } : null
      image_file_id       = name == "ci" ? null : "local:import/qcl-negf-${name}-0000000000000000000000000000000000000000000000000000000000000000.qcow2"
      image_sha256        = name == "ci" ? null : "0000000000000000000000000000000000000000000000000000000000000000"
    } }
  }
  expect_failures = [var.vms]
}

# Exactly21 valid serial characters isolate the provider-compatible20-character bound.
run "reject_descriptor_serial_21" {
  command = plan
  variables {
    vms = { for name, number in { storage = 721, control = 722, compute = 723, ci = 720 } : name => {
      vm_id               = number
      vcpus               = 1
      memory_mib          = 1024
      root_gib            = name == "ci" ? 128 : 32
      mac                 = "52:54:00:72:${number - 700}:01"
      address             = "192.0.2.${number - 700}/24"
      gateway             = "192.0.2.1"
      adopt_existing_root = name == "ci"
      existing_root       = name == "ci" ? { datastore_id = "local-lvm", size_gib = 128, serial = "123456789012345678901" } : null
      image_file_id       = name == "ci" ? null : "local:import/qcl-negf-${name}-0000000000000000000000000000000000000000000000000000000000000000.qcow2"
      image_sha256        = name == "ci" ? null : "0000000000000000000000000000000000000000000000000000000000000000"
    } }
  }
  expect_failures = [var.vms]
}
