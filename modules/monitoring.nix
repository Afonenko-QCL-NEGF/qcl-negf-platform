{ config, lib, pkgs, ... }:
let
  cfg = config.qclNegf.monitoring;
  python = pkgs.python314.withPackages (p: [ p.pyarrow ]);
  exporter = pkgs.writeShellApplication {
    name = "qcl-negf-telemetry-export";
    runtimeInputs = [ python ];
    text = ''exec python3 ${../ops/telemetry_export.py} "$@"'';
  };
in {
  options.qclNegf.monitoring = {
    nodeExporter = lib.mkEnableOption "standard Prometheus node exporter on the private interface";
    collector = {
      enable = lib.mkEnableOption "best-effort Vector HTTP JSON collector on a permanent node";
      address = lib.mkOption { type = lib.types.str; default = "127.0.0.1"; description = "Trusted-LAN listen address; disabled by default."; };
      port = lib.mkOption { type = lib.types.port; default = 8081; };
      retentionDays = lib.mkOption { type = lib.types.ints.positive; default = 7; };
    };
  };
  config = lib.mkMerge [
    (lib.mkIf cfg.nodeExporter {
      services.prometheus.exporters.node = { enable = true; openFirewall = false; };
      networking.firewall.interfaces.${config.qclNegf.privateInterface}.allowedTCPPorts = [ 9100 ];
    })
    (lib.mkIf cfg.collector.enable {
      environment.systemPackages = [ exporter ];
      services.vector = {
        enable = true;
        settings = {
          data_dir = "/var/lib/vector";
          sources.scientific = {
            type = "http_server";
            address = "${cfg.collector.address}:${toString cfg.collector.port}";
            path = "/events"; strict_path = true;
            decoding.codec = "json";
            framing = { method = "newline_delimited"; newline_delimited.max_length = 16384; };
          };
          sinks.telemetry = {
            type = "file"; inputs = [ "scientific" ];
            path = "/var/lib/vector/qcl-telemetry/events-%Y-%m-%d.ndjson";
            encoding.codec = "json";
            buffer = { type = "memory"; max_events = 256; when_full = "drop_newest"; };
            acknowledgements.enabled = false;
          };
        };
      };
      systemd.services.vector.serviceConfig = { MemoryMax = "512M"; CPUQuota = "100%"; };
      systemd.tmpfiles.rules = [ "e /var/lib/vector/qcl-telemetry - - - ${toString cfg.collector.retentionDays}d" ];
      networking.firewall.interfaces.${config.qclNegf.privateInterface}.allowedTCPPorts = [ cfg.collector.port ];
    })
  ];
}
