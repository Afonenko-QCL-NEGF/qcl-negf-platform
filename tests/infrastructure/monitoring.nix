{ nixpkgs }:
let
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  make = enabled: (import (nixpkgs + "/nixos/lib/eval-config.nix") {
    system = "x86_64-linux";
    modules = [ ../../modules {
      system.stateVersion = "26.05";
      # Closed synthetic boot metadata; this is evaluation, never a disk provision.
      boot.loader.grub.enable = false;
      fileSystems."/" = { device = "/dev/disk/by-label/synthetic-root"; fsType = "ext4"; };
      qclNegf.privateInterface = "cluster0";
      qclNegf.monitoring = {
        nodeExporter = enabled; collector.enable = enabled;
        observation = { enable = enabled; sampler.enable = enabled; };
      };
    } ];
  }).config;
  enabled = make true;
  disabled = make false;
in
assert builtins.all (x: x.assertion) enabled.assertions;
assert !disabled.services.vector.enable;
assert !disabled.services.prometheus.exporters.node.enable;
assert !(builtins.hasAttr "qcl-negf-monitor-sample" disabled.systemd.services);
assert enabled.systemd.services.qcl-negf-monitor-sample.serviceConfig.Type == "oneshot";
assert enabled.systemd.services.qcl-negf-monitor-sample.serviceConfig.RuntimeDirectoryPreserve == "yes";
assert enabled.systemd.services.qcl-negf-monitor-sample.requiredBy == [];
assert enabled.systemd.services.qcl-negf-monitor-sample.before == [];
assert enabled.systemd.services.qcl-negf-monitor-sample.partOf == [];
assert enabled.systemd.services.vector.serviceConfig.ExecCondition != [];
assert !enabled.systemd.services.vector.serviceConfig.DynamicUser;
assert enabled.systemd.services.vector.serviceConfig.User == "qcl-monitoring";
assert !enabled.services.vector.journaldAccess;
assert enabled.services.vector.settings.data_dir == "/var/lib/qcl-negf-monitoring-vector";
assert enabled.services.vector.settings.sources.scientific.path == "/events";
assert enabled.services.vector.settings.sources.scientific.framing.newline_delimited.max_length == 16384;
assert enabled.services.vector.settings.sinks.telemetry.buffer.type == "memory";
assert enabled.services.vector.settings.sinks.telemetry.buffer.max_events == 256;
assert enabled.services.vector.settings.sinks.telemetry.buffer.when_full == "drop_newest";
assert !enabled.services.vector.settings.sinks.telemetry.acknowledgements.enabled;
{
  collector = enabled.services.vector.settings;
  memory = enabled.systemd.services.vector.serviceConfig.MemoryMax;
  sampler = { inherit (enabled.systemd.services.qcl-negf-monitor-sample.serviceConfig) Type RuntimeDirectory RuntimeDirectoryPreserve MemoryMax CPUQuota; };
  collectorCapacityGate = enabled.systemd.services.vector.serviceConfig.ExecCondition;
  samplerTimer = enabled.systemd.timers.qcl-negf-monitor-sample.timerConfig;
  assertionFailures = builtins.map (x: x.message) (builtins.filter (x: !x.assertion) enabled.assertions);
  ports = enabled.networking.firewall.interfaces.cluster0.allowedTCPPorts;
}
