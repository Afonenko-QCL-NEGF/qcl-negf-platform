mock_provider "libvirt" {}
variables {
  uri                = "qemu:///system"
  bridge             = "br-synthetic"
  pool_path          = "/tmp/qcl-synthetic-pool"
  image_path         = "tests/image-fixture.txt"
  image_sha256       = "aeae83a278489bdd7fb987ad931f71e562743d6d6a548c51e96e5ddbd49f0e09"
  root_gib           = 32
  scratch_gib        = 32
  memory_mib         = 4096
  vcpus              = 2
  resident_memory    = { minimum_mib = 4096, startup_mib = 4096, maximum_mib = 4096 }
  ownership_verified = true
  capacity_verified  = true
  mac                = "52:54:00:00:00:0e"
  address            = "192.0.2.14/24"
  gateway            = "192.0.2.1"
  dns_servers        = ["192.0.2.1"]
  ssh_public_keys    = ["ssh-ed25519 AAAATEST synthetic-only"]
}

run "reject_numeric_self_next_hop_for_aliased_guest" {
  command = plan
  variables {
    address           = "192.0.2.014/24"
    additional_routes = [{ to = "198.51.100.0/24", via = "192.0.2.14" }]
  }
  expect_failures = [terraform_data.admission]
}

run "aliased_guest_with_distinct_next_hop" {
  command = plan
  variables {
    address           = "192.0.2.014/24"
    additional_routes = [{ to = "198.51.100.0/24", via = "192.0.2.201" }]
  }
  assert {
    condition     = jsonencode(yamldecode(libvirt_cloudinit_disk.seed.network_config).ethernets.cluster0.routes) == jsonencode([{ to = "default", via = "192.0.2.1" }, { to = "198.51.100.0/24", via = "192.0.2.201" }])
    error_message = "Numeric guest normalization must only reject an actual self next hop."
  }
}

run "legacy_empty_routes_keep_guest_spelling" {
  command = plan
  variables { address = "192.0.2.014/24" }
  assert {
    condition     = yamldecode(libvirt_cloudinit_disk.seed.network_config).ethernets.cluster0.addresses[0] == "192.0.2.014/24" && length(yamldecode(libvirt_cloudinit_disk.seed.network_config).ethernets.cluster0.routes) == 1
    error_message = "Empty additional routes must retain the existing seed behavior."
  }
}

run "conservative_resident_guest_and_devices" {
  command = plan
  assert {
    condition     = libvirt_domain.worker.memory == 4096 && libvirt_domain.worker.current_memory == 4096 && libvirt_domain.worker.memory_unit == "MiB" && libvirt_domain.worker.current_memory_unit == "MiB"
    error_message = "Conservative mode must reserve the same full RAM at startup and maximum."
  }
  assert {
    condition     = libvirt_domain.worker.devices.mem_balloon.model == "virtio" && libvirt_domain.worker.devices.mem_balloon.auto_deflate == "off"
    error_message = "Balloon capability must be explicit without automatic growth."
  }
  assert {
    condition     = libvirt_domain.worker.running && libvirt_domain.worker.autostart && libvirt_domain.worker.os.boot_devices[0].dev == "hd" && libvirt_domain.worker.os.type_arch == "x86_64"
    error_message = "A production resident guest must retain the BIOS disk boot contract."
  }
  assert {
    condition     = libvirt_domain.worker.devices.disks[0].serial == "qcl-root" && libvirt_domain.worker.devices.disks[1].serial == "qcl-scratch" && libvirt_domain.worker.devices.disks[2].target.bus == "sata"
    error_message = "Root, persistent scratch and NoCloud seed must have distinct devices."
  }
  assert {
    condition     = libvirt_domain.worker.devices.interfaces[0].source.bridge.bridge == "br-synthetic" && libvirt_domain.worker.devices.channels[0].target.virt_io.name == "org.qemu.guest_agent.0"
    error_message = "Use the assigned existing bridge and the native guest-agent channel."
  }
  assert {
    condition     = yamldecode(libvirt_cloudinit_disk.seed.network_config).ethernets.cluster0.match.macaddress == "52:54:00:00:00:0e" && yamldecode(libvirt_cloudinit_disk.seed.network_config).ethernets.cluster0["set-name"] == "cluster0" && yamldecode(libvirt_cloudinit_disk.seed.network_config).ethernets.cluster0.addresses[0] == "192.0.2.14/24"
    error_message = "The seed must bind static cluster networking to the assigned MAC and interface name."
  }
  assert {
    condition     = output.memory_capability.dynamic_supported == false && output.memory_capability.reason == "native_active_grant_not_qualified"
    error_message = "Source metadata must not claim dynamic memory qualification."
  }
}

run "reject_unknown_ownership" {
  command = plan
  variables { ownership_verified = false }
  expect_failures = [terraform_data.admission]
}
run "reject_unverified_capacity" {
  command = plan
  variables { capacity_verified = false }
  expect_failures = [terraform_data.admission]
}
run "reject_wrong_image" {
  command = plan
  variables { image_sha256 = "0000000000000000000000000000000000000000000000000000000000000000" }
  expect_failures = [terraform_data.admission]
}
run "reject_unqualified_balloon_range" {
  command = plan
  variables { resident_memory = { minimum_mib = 1024, startup_mib = 4096, maximum_mib = 8192 } }
  expect_failures = [var.resident_memory]
}
run "reject_memory_alias_mismatch" {
  command = plan
  variables { memory_mib = 8192 }
  expect_failures = [var.resident_memory]
}
run "reject_fractional_cpu" {
  command = plan
  variables { vcpus = 1.5 }
  expect_failures = [var.vcpus]
}

run "ordinary_default_with_specific_cluster_routes" {
  command = plan
  variables {
    additional_routes = [
      { to = "198.51.100.0/24", via = "192.0.2.201" },
      { to = "203.0.113.9/32", via = "192.0.2.202" }
    ]
  }
  assert {
    condition = jsonencode(yamldecode(libvirt_cloudinit_disk.seed.network_config).ethernets.cluster0.routes) == jsonencode([
      { to = "default", via = "192.0.2.1" },
      { to = "198.51.100.0/24", via = "192.0.2.201" },
      { to = "203.0.113.9/32", via = "192.0.2.202" }
    ])
    error_message = "Specific cluster routes must follow the unchanged ordinary default with their assigned next hops."
  }
}

run "empty_extra_routes_preserves_full_seed" {
  command = plan
  assert {
    condition = libvirt_cloudinit_disk.seed.network_config == yamlencode({
      version = 2
      ethernets = { cluster0 = {
        match       = { macaddress = "52:54:00:00:00:0e" }
        "set-name"  = "cluster0"
        addresses   = ["192.0.2.14/24"]
        routes      = [{ to = "default", via = "192.0.2.1" }]
        nameservers = { addresses = ["192.0.2.1"] }
      } }
    })
    error_message = "Omitting additional_routes must preserve the complete old network seed."
  }
}

run "reject_route_default" {
  command = plan
  variables { additional_routes = [{ to = "default", via = "192.0.2.201" }] }
  expect_failures = [var.additional_routes]
}

run "reject_route_zero" {
  command = plan
  variables { additional_routes = [{ to = "0.0.0.0/0", via = "192.0.2.201" }] }
  expect_failures = [var.additional_routes]
}

run "reject_route_ipv6" {
  command = plan
  variables { additional_routes = [{ to = "2001:db8::/64", via = "192.0.2.201" }] }
  expect_failures = [var.additional_routes]
}

run "reject_route_bad_prefix" {
  command = plan
  variables { additional_routes = [{ to = "198.51.100.0/33", via = "192.0.2.201" }] }
  expect_failures = [var.additional_routes]
}

run "reject_route_host_bits" {
  command = plan
  variables { additional_routes = [{ to = "198.51.100.9/24", via = "192.0.2.201" }] }
  expect_failures = [var.additional_routes]
}

run "reject_route_noncanonical_prefix" {
  command = plan
  variables { additional_routes = [{ to = "198.51.100.0/024", via = "192.0.2.201" }] }
  expect_failures = [var.additional_routes]
}

run "reject_route_whitespace" {
  command = plan
  variables { additional_routes = [{ to = "198.51.100.0/24 ", via = "192.0.2.201" }] }
  expect_failures = [var.additional_routes]
}

run "reject_route_bad_via" {
  command = plan
  variables { additional_routes = [{ to = "198.51.100.0/24", via = "192.0.2.999" }] }
  expect_failures = [var.additional_routes]
}

run "reject_route_ipv6_via" {
  command = plan
  variables { additional_routes = [{ to = "198.51.100.0/24", via = "2001:db8::1" }] }
  expect_failures = [var.additional_routes]
}

run "reject_route_cidr_via" {
  command = plan
  variables { additional_routes = [{ to = "198.51.100.0/24", via = "192.0.2.201/32" }] }
  expect_failures = [var.additional_routes]
}

run "reject_duplicate_route_destinations" {
  command = plan
  variables {
    additional_routes = [{ to = "198.51.100.0/24", via = "192.0.2.201" }, { to = "198.51.100.0/24", via = "192.0.2.202" }]
  }
  expect_failures = [var.additional_routes]
}

run "reject_route_off_link_next_hop" {
  command = plan
  variables { additional_routes = [{ to = "198.51.100.0/24", via = "203.0.113.1" }] }
  expect_failures = [terraform_data.admission]
}

run "reject_route_self_next_hop" {
  command = plan
  variables { additional_routes = [{ to = "198.51.100.0/24", via = "192.0.2.14" }] }
  expect_failures = [terraform_data.admission]
}

run "reject_route_network_next_hop" {
  command = plan
  variables { additional_routes = [{ to = "198.51.100.0/24", via = "192.0.2.0" }] }
  expect_failures = [terraform_data.admission]
}

run "reject_route_broadcast_next_hop" {
  command = plan
  variables { additional_routes = [{ to = "198.51.100.0/24", via = "192.0.2.255" }] }
  expect_failures = [terraform_data.admission]
}

run "reject_extra_route_ipv6_guest" {
  command = plan
  variables {
    address           = "2001:db8::14/64"
    additional_routes = [{ to = "198.51.100.0/24", via = "192.0.2.201" }]
  }
  expect_failures = [terraform_data.admission]
}

run "reject_extra_route_point_to_point_guest" {
  command = plan
  variables {
    address           = "192.0.2.14/31"
    additional_routes = [{ to = "198.51.100.0/24", via = "192.0.2.201" }]
  }
  expect_failures = [terraform_data.admission]
}

run "reject_extra_route_host_only_guest" {
  command = plan
  variables {
    address           = "192.0.2.14/32"
    additional_routes = [{ to = "198.51.100.0/24", via = "192.0.2.201" }]
  }
  expect_failures = [terraform_data.admission]
}
