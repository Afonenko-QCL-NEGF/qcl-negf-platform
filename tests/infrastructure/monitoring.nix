{ nixpkgs }:
let
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  make = enabled: (import (nixpkgs + "/nixos/lib/eval-config.nix") {
    system = "x86_64-linux";
    modules = [ ../../modules {
      system.stateVersion = "26.05";
      qclNegf.privateInterface = "cluster0";
      qclNegf.monitoring = { nodeExporter = enabled; collector.enable = enabled; };
    } ];
  }).config;
  enabled = make true;
  disabled = make false;
in
assert !disabled.services.vector.enable;
assert !disabled.services.prometheus.exporters.node.enable;
assert enabled.services.vector.settings.sources.scientific.path == "/events";
assert enabled.services.vector.settings.sources.scientific.framing.newline_delimited.max_length == 16384;
assert enabled.services.vector.settings.sinks.telemetry.buffer.type == "memory";
assert enabled.services.vector.settings.sinks.telemetry.buffer.max_events == 256;
assert enabled.services.vector.settings.sinks.telemetry.buffer.when_full == "drop_newest";
assert !enabled.services.vector.settings.sinks.telemetry.acknowledgements.enabled;
{
  collector = enabled.services.vector.settings;
  memory = enabled.systemd.services.vector.serviceConfig.MemoryMax;
  ports = enabled.networking.firewall.interfaces.cluster0.allowedTCPPorts;
}
