# Mock provider evaluates real resource arguments without a Proxmox API call.
mock_provider "proxmox" {
  mock_resource "proxmox_virtual_environment_file" {
    defaults = { id = "local:iso/qcl-synthetic.iso" }
  }
}
variables {
  endpoint       = "https://127.0.0.1:8006/"
  node           = "test"
  iso_datastore  = "local"
  root_datastore = "local-lvm"
  ci_bridge      = "vmbr-test-ci"
  vm_id          = 709
  mac            = "52:54:00:71:09:01"
  iso_path       = "tests/installer-fixture.txt"
  iso_sha256     = filesha256("tests/installer-fixture.txt")
}
run "local_debug_keeps_small_guest" {
  command = plan
  variables { build_profile = "local-debug" }
  assert {
    condition     = proxmox_virtual_environment_vm.builder.cpu[0].cores == 4 && proxmox_virtual_environment_vm.builder.memory[0].dedicated == 8192
    error_message = "Local debugging must preserve the small 4 CPU/8 GiB guest."
  }
}
run "production_uses_explicit_actual_host_choice" {
  command = plan
  variables {
    build_profile               = "production-build"
    production_build_vcpus      = 24
    production_build_memory_mib = 40960
    host_logical_cpus           = 24
  }
  assert {
    condition     = proxmox_virtual_environment_vm.builder.cpu[0].cores == 24 && proxmox_virtual_environment_vm.builder.memory[0].dedicated == 40960 && !proxmox_virtual_environment_vm.builder.on_boot
    error_message = "Temporary bootstrap must use declared resources and keep on_boot false."
  }
}
run "production_requires_resource_evidence" {
  command = plan
  variables { build_profile = "production-build" }
  expect_failures = [proxmox_virtual_environment_vm.builder]
}
run "production_guest_cannot_exceed_host_cpu_count" {
  command = plan
  variables {
    build_profile               = "production-build"
    production_build_vcpus      = 25
    production_build_memory_mib = 40960
    host_logical_cpus           = 24
  }
  expect_failures = [proxmox_virtual_environment_vm.builder]
}
run "fixed_profile_cannot_receive_dynamic_overrides" {
  command = plan
  variables {
    build_profile               = "standard"
    production_build_vcpus      = 24
    production_build_memory_mib = 40960
  }
  expect_failures = [proxmox_virtual_environment_vm.builder]
}
