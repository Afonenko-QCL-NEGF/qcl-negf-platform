mock_provider "libvirt" {}
variables {
  namespace          = "qcl-test"
  pool_path          = "/tmp/qcl-test-pool"
  bootstrap_image    = "tests/image-fixture.txt"
  bootstrap_sha256   = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  ssh_public_key     = "ssh-ed25519 AAAATEST public-only"
  seed_images        = { control = "tests/image-fixture.txt", storage = "tests/image-fixture.txt", worker-1 = "tests/image-fixture.txt", worker-2 = "tests/image-fixture.txt" }
  ownership_verified = true
}
run "four_roles_and_separate_disks" {
  command = plan
  assert {
    condition     = length(libvirt_domain.machine) == 4 && sum([for m in libvirt_domain.machine : m.memory]) == 7424
    error_message = "The infrastructure profile must fit the measured small host and keep four roles."
  }
  assert {
    condition     = libvirt_domain.machine["storage"].devices.disks[1].serial == "qcl-data" && libvirt_domain.machine["control"].devices.disks[1].serial == "qcl-state" && libvirt_domain.machine["worker-1"].devices.disks[1].serial == "qcl-scratch"
    error_message = "Durable disks must be distinct from replaceable roots and retain stable IDs."
  }
  assert {
    condition     = alltrue([for v in libvirt_volume.root : v.allocation == 0]) && alltrue([for v in libvirt_volume.durable : v.allocation == 0])
    error_message = "Logical root and data capacities must use sparse allocation."
  }
  assert {
    condition     = alltrue([for m in libvirt_domain.machine : startswith(m.name, "qcl-test-") && m.type == "kvm"])
    error_message = "Only namespaced KVM domains belong to this lab."
  }
  assert {
    condition     = alltrue([for m in libvirt_domain.machine : m.devices.serials[0].source == null && m.devices.consoles[0].source == null])
    error_message = "Host-allocated PTY sources must not be pinned to empty paths."
  }
}
run "reject_unverified_ownership" {
  command = plan
  variables { ownership_verified = false }
  expect_failures = [terraform_data.admission]
}
run "reject_bad_image_hash" {
  command = plan
  variables { bootstrap_sha256 = "0000000000000000000000000000000000000000000000000000000000000000" }
  expect_failures = [terraform_data.admission]
}

run "reject_missing_worker_budget" {
  command = plan
  variables {
    resources = { control = { memory_mib = 2048, vcpus = 2 } }
  }
  expect_failures = [var.resources]
}
