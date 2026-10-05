# Actual resource arguments under the pinned mock provider, without an API call.
mock_provider "proxmox" {
  mock_resource "proxmox_virtual_environment_file" {
    defaults = { id = "local:snippets/synthetic.yaml" }
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

run "null_profile_preserves_existing_inventory" {
  command = plan
  assert {
    condition     = proxmox_virtual_environment_vm.replaceable["ci"].cpu[0].cores == 1 && proxmox_virtual_environment_vm.replaceable["ci"].memory[0].dedicated == 1024
    error_message = "No selected profile must preserve the inventory's custom CI resources."
  }
  assert {
    condition = alltrue(concat(
      [for vm in values(proxmox_virtual_environment_vm.persistent) : vm.started && vm.on_boot],
      [for vm in values(proxmox_virtual_environment_vm.replaceable) : vm.started && vm.on_boot]
    ))
    error_message = "Default startup and host reboot behavior must remain unchanged."
  }
}

run "standard_matches_shared_profile" {
  command = plan
  variables {
    build_profile = "standard"
    vms = { for name, number in { storage = 721, control = 722, compute = 723, ci = 720 } : name => {
      vm_id         = number
      vcpus         = name == "ci" ? 4 : 1
      memory_mib    = name == "ci" ? 8192 : 1024
      started       = true
      on_boot       = true
      root_gib      = 32
      mac           = "52:54:00:72:${number - 700}:01"
      address       = "192.0.2.${number - 700}/24"
      gateway       = "192.0.2.1"
      image_file_id = "local:import/qcl-negf-${name}-0000000000000000000000000000000000000000000000000000000000000000.qcow2"
      image_sha256  = "0000000000000000000000000000000000000000000000000000000000000000"
    } }
  }
  assert {
    condition     = proxmox_virtual_environment_vm.replaceable["ci"].cpu[0].cores == 4 && proxmox_virtual_environment_vm.replaceable["ci"].memory[0].dedicated == 8192 && proxmox_virtual_environment_vm.replaceable["compute"].started
    error_message = "Standard CI must be 4 CPU/8 GiB and permit the declared compute startup."
  }
}

run "burst_budgets_only_declared_active_guests" {
  command = plan
  variables {
    build_profile     = "burst"
    host_memory_mib   = 40960
    host_logical_cpus = 16
    vms = { for name, number in { storage = 721, control = 722, compute = 723, ci = 720 } : name => {
      vm_id         = number
      vcpus         = contains(["ci", "compute"], name) ? 12 : 1
      memory_mib    = name == "ci" ? 24576 : (name == "compute" ? 28672 : 1024)
      started       = name != "compute"
      on_boot       = name != "compute"
      root_gib      = 32
      mac           = "52:54:00:72:${number - 700}:01"
      address       = "192.0.2.${number - 700}/24"
      gateway       = "192.0.2.1"
      image_file_id = "local:import/qcl-negf-${name}-0000000000000000000000000000000000000000000000000000000000000000.qcow2"
      image_sha256  = "0000000000000000000000000000000000000000000000000000000000000000"
    } }
  }
  assert {
    condition     = proxmox_virtual_environment_vm.replaceable["ci"].cpu[0].cores == 12 && proxmox_virtual_environment_vm.replaceable["ci"].memory[0].dedicated == 24576 && !proxmox_virtual_environment_vm.replaceable["compute"].started && !proxmox_virtual_environment_vm.replaceable["compute"].on_boot
    error_message = "Burst must be 12 CPU/24 GiB with compute stopped across host reboot."
  }
  assert {
    condition     = proxmox_virtual_environment_vm.replaceable["compute"].vm_id == 723 && proxmox_virtual_environment_vm.replaceable["compute"].memory[0].dedicated == 28672
    error_message = "Stopping compute must preserve its declared identity and resources."
  }
}

run "reject_burst_with_compute_running" {
  command = plan
  variables {
    build_profile = "burst"
    vms = { for name, number in { storage = 721, control = 722, compute = 723, ci = 720 } : name => {
      vm_id         = number
      vcpus         = name == "ci" ? 12 : 1
      memory_mib    = name == "ci" ? 24576 : 1024
      started       = true
      on_boot       = true
      root_gib      = 32
      mac           = "52:54:00:72:${number - 700}:01"
      address       = "192.0.2.${number - 700}/24"
      gateway       = "192.0.2.1"
      image_file_id = "local:import/qcl-negf-${name}-0000000000000000000000000000000000000000000000000000000000000000.qcow2"
      image_sha256  = "0000000000000000000000000000000000000000000000000000000000000000"
    } }
  }
  expect_failures = [var.vms]
}

run "reject_burst_with_compute_autostart" {
  command = plan
  variables {
    build_profile = "burst"
    vms = { for name, number in { storage = 721, control = 722, compute = 723, ci = 720 } : name => {
      vm_id         = number
      vcpus         = name == "ci" ? 12 : 1
      memory_mib    = name == "ci" ? 24576 : 1024
      started       = name != "compute"
      on_boot       = true
      root_gib      = 32
      mac           = "52:54:00:72:${number - 700}:01"
      address       = "192.0.2.${number - 700}/24"
      gateway       = "192.0.2.1"
      image_file_id = "local:import/qcl-negf-${name}-0000000000000000000000000000000000000000000000000000000000000000.qcow2"
      image_sha256  = "0000000000000000000000000000000000000000000000000000000000000000"
    } }
  }
  expect_failures = [var.vms]
}

run "reject_profile_resource_mismatch" {
  command = plan
  variables { build_profile = "standard" }
  expect_failures = [var.vms]
}

run "reject_active_memory_over_budget" {
  command = plan
  variables {
    build_profile   = "burst"
    host_memory_mib = 24576
    vms = { for name, number in { storage = 721, control = 722, compute = 723, ci = 720 } : name => {
      vm_id         = number
      vcpus         = name == "ci" ? 12 : 1
      memory_mib    = name == "ci" ? 24576 : 1024
      started       = name != "compute"
      on_boot       = name != "compute"
      root_gib      = 32
      mac           = "52:54:00:72:${number - 700}:01"
      address       = "192.0.2.${number - 700}/24"
      gateway       = "192.0.2.1"
      image_file_id = "local:import/qcl-negf-${name}-0000000000000000000000000000000000000000000000000000000000000000.qcow2"
      image_sha256  = "0000000000000000000000000000000000000000000000000000000000000000"
    } }
  }
  expect_failures = [var.vms]
}

run "reject_unknown_profile" {
  command = plan
  variables { build_profile = "automatic" }
  expect_failures = [var.build_profile]
}

run "reject_temporary_production_build_in_final_site" {
  command = plan
  variables { build_profile = "production-build" }
  expect_failures = [var.build_profile]
}

run "reject_debug_profile_in_final_site" {
  command = plan
  variables { build_profile = "local-debug" }
  expect_failures = [var.build_profile]
}

run "all_roles_stopped_need_no_active_guest_budget" {
  command = plan
  variables {
    host_memory_mib   = 8192
    host_logical_cpus = 2
    vms = { for name, number in { storage = 721, control = 722, compute = 723, ci = 720 } : name => {
      vm_id         = number
      vcpus         = 1
      memory_mib    = 1024
      started       = false
      on_boot       = false
      root_gib      = 32
      mac           = "52:54:00:72:${number - 700}:01"
      address       = "192.0.2.${number - 700}/24"
      gateway       = "192.0.2.1"
      image_file_id = "local:import/qcl-negf-${name}-0000000000000000000000000000000000000000000000000000000000000000.qcow2"
      image_sha256  = "0000000000000000000000000000000000000000000000000000000000000000"
    } }
  }
  assert {
    condition = alltrue(concat(
      [for vm in values(proxmox_virtual_environment_vm.persistent) : !vm.started && !vm.on_boot],
      [for vm in values(proxmox_virtual_environment_vm.replaceable) : !vm.started && !vm.on_boot]
    ))
    error_message = "The empty active guest set must have a zero budget without losing resources."
  }
}

run "reject_active_cpu_over_budget_without_memory_pressure" {
  command = plan
  variables {
    build_profile     = "burst"
    host_logical_cpus = 12
    vms = { for name, number in { storage = 721, control = 722, compute = 723, ci = 720 } : name => {
      vm_id         = number
      vcpus         = name == "ci" ? 12 : 1
      memory_mib    = name == "ci" ? 24576 : 1024
      started       = name != "compute"
      on_boot       = name != "compute"
      root_gib      = 32
      mac           = "52:54:00:72:${number - 700}:01"
      address       = "192.0.2.${number - 700}/24"
      gateway       = "192.0.2.1"
      image_file_id = "local:import/qcl-negf-${name}-0000000000000000000000000000000000000000000000000000000000000000.qcow2"
      image_sha256  = "0000000000000000000000000000000000000000000000000000000000000000"
    } }
  }
  expect_failures = [var.vms]
}
