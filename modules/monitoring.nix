{ config, lib, pkgs, ... }:
let
  cfg = config.qclNegf.monitoring;
  monitor = import ../nix/monitoring.nix { inherit pkgs; };
  allocationMount = if cfg.collector.allocationMount == null then "/var/lib/qcl-negf-monitoring-unqualified" else cfg.collector.allocationMount;
  python = pkgs.python314.withPackages (p: [ p.pyarrow ]);
  exporter = pkgs.writeShellApplication {
    name = "qcl-negf-telemetry-export";
    runtimeInputs = [ python ];
    text = ''exec python3 ${../ops/telemetry_export.py} "$@"'';
  };
in {
  options.qclNegf.monitoring = {
    nodeExporter = lib.mkEnableOption "standard Prometheus node exporter on the private interface";
    observation = {
      enable = lib.mkEnableOption "bounded read-only P31 observation helpers";
      readerUser = lib.mkOption { type = lib.types.str; default = "qcl-monitor-reader"; description = "Existing dedicated local non-root reader; UID must match the protected config."; };
      observerUser = lib.mkOption { type = lib.types.str; default = "qcl-monitor-observer"; description = "Existing dedicated SSH identity; distinct from reader and grant roles."; };
      sampler = {
        enable = lib.mkEnableOption "best-effort root sampler on an existing enrolled host/guest";
        intervalSeconds = lib.mkOption { type = lib.types.ints.positive; default = 30; };
      };
      storageMaintenance = lib.mkEnableOption "bounded retention of qualified QCL-only telemetry files";
    };
    collector = {
      enable = lib.mkEnableOption "best-effort Vector HTTP JSON collector on a permanent node";
      allocationMount = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; description = "Optional already prepared QCL-only bounded mount; never created/provisioned by this module. Unknown proof keeps persistence disabled."; };
      address = lib.mkOption { type = lib.types.str; default = "127.0.0.1"; description = "Trusted-LAN listen address; disabled by default."; };
      port = lib.mkOption { type = lib.types.port; default = 8081; };
      retentionDays = lib.mkOption { type = lib.types.ints.positive; default = 7; description = "Compatibility setting; protected monitoring storage.retention_seconds governs P31 maintenance."; };
    };
  };
  config = lib.mkMerge [
    (lib.mkIf cfg.nodeExporter {
      services.prometheus.exporters.node = { enable = true; openFirewall = false; };
      networking.firewall.interfaces.${config.qclNegf.privateInterface}.allowedTCPPorts = [ 9100 ];
    })
    (lib.mkIf cfg.observation.enable {
      assertions = [
        { assertion = cfg.observation.readerUser != "root" && cfg.observation.observerUser != "root" && cfg.observation.readerUser != cfg.observation.observerUser;
          message = "P31 reader and observer must be distinct existing non-root identities."; }
      ];
      environment.systemPackages = [ monitor ];
      # No user/key/config is synthesized; the private site owns actual identities.
      security.sudo.extraRules = [
        { users = [ cfg.observation.readerUser ]; commands = [ { command = "${monitor}/bin/qcl-negf-monitor-read *"; options = [ "NOPASSWD" ]; } { command = "${monitor}/bin/qcl-negf-monitor-context *"; options = [ "NOPASSWD" ]; } ]; }
        { users = [ cfg.observation.observerUser ]; commands = [ { command = "${monitor}/bin/qcl-negf-monitor-observer *"; options = [ "NOPASSWD" ]; } ]; }
      ];
    })
    (lib.mkIf (cfg.observation.enable && cfg.observation.sampler.enable) {
      systemd.services.qcl-negf-monitor-sample = {
        description = "Bounded QCL observation sample; independent of solver admission";
        serviceConfig = {
          Type = "oneshot"; User = "root"; UMask = "0077";
          RuntimeDirectory = "qcl-negf-monitoring"; RuntimeDirectoryMode = "0700";
          RuntimeDirectoryPreserve = "yes";
          ExecStart = "${monitor}/bin/qcl-negf-monitor-sample";
          TimeoutStartSec = 310; MemoryMax = "128M"; CPUQuota = "25%";
          ProtectSystem = "strict"; ProtectHome = true; PrivateTmp = true;
          ReadWritePaths = [ "/run/qcl-negf-monitoring" ];
          NoNewPrivileges = true; StandardOutput = "null"; StandardError = "null";
        };
      };
      systemd.timers.qcl-negf-monitor-sample = {
        wantedBy = [ "timers.target" ];
        timerConfig = { OnBootSec = "30s"; OnUnitInactiveSec = "${toString cfg.observation.sampler.intervalSeconds}s"; };
      };
    })
    (lib.mkIf (cfg.observation.enable && cfg.observation.storageMaintenance) {
      systemd.services.qcl-negf-monitor-storage = {
        description = "Maintain only qualified QCL-owned telemetry scope";
        serviceConfig = { Type = "oneshot"; User = "root"; UMask = "0077";
          ExecStart = "${monitor}/bin/qcl-negf-monitor-storage";
          TimeoutStartSec = 30; MemoryMax = "128M"; CPUQuota = "25%";
          ProtectHome = true; PrivateTmp = true; NoNewPrivileges = true;
          StandardOutput = "null"; StandardError = "null";
        };
      };
      systemd.timers.qcl-negf-monitor-storage = {
        wantedBy = [ "timers.target" ]; timerConfig = { OnBootSec = "5m"; OnUnitInactiveSec = "1h"; };
      };
    })
    (lib.mkIf cfg.collector.enable {
      environment.systemPackages = [ exporter ];
      assertions = [ {
        assertion = builtins.attrNames config.services.vector.settings.sources == [ "scientific" ]
          && builtins.attrNames config.services.vector.settings.sinks == [ "telemetry" ]
          && !config.services.vector.journaldAccess;
        message = "QCL collector owns this Vector instance only; existing unrelated pipelines require a separate binding.";
      } ];
      users.groups.qcl-monitoring = {};
      users.users.qcl-monitoring = { isSystemUser = true; group = "qcl-monitoring"; };
      services.vector = {
        enable = true;
        settings = {
          data_dir = "${allocationMount}/state";
          sources.scientific = {
            type = "http_server";
            address = "${cfg.collector.address}:${toString cfg.collector.port}";
            path = "/events"; strict_path = true;
            decoding.codec = "json";
            framing = { method = "newline_delimited"; newline_delimited.max_length = 16384; };
          };
          sinks.telemetry = {
            type = "file"; inputs = [ "scientific" ];
            path = "${allocationMount}/data/events-%Y-%m-%d.ndjson";
            encoding.codec = "json";
            buffer = { type = "memory"; max_events = 256; when_full = "drop_newest"; };
            acknowledgements.enabled = false;
          };
        };
      };
      # An unqualified/full scope skips persistence, with no solver dependency.
      # The hard backing maximum is authoritative; age is not a capacity proof.
      systemd.services.vector.serviceConfig = {
        MemoryMax = "512M"; CPUQuota = "100%";
        DynamicUser = lib.mkForce false; User = "qcl-monitoring"; Group = "qcl-monitoring";
        # All durable collector output/state is inside the prepared hard boundary.
        StateDirectory = lib.mkForce ""; LogsDirectory = lib.mkForce "";
        CacheDirectory = lib.mkForce ""; RuntimeDirectory = lib.mkForce "";
        ProtectSystem = lib.mkForce "strict"; ProtectHome = lib.mkForce true;
        PrivateDevices = lib.mkForce true; PrivateTmp = lib.mkForce false;
        NoNewPrivileges = lib.mkForce true; CapabilityBoundingSet = lib.mkForce [];
        RootDirectory = lib.mkForce ""; RootImage = lib.mkForce "";
        BindPaths = lib.mkForce []; BindReadOnlyPaths = lib.mkForce [];
        TemporaryFileSystem = lib.mkForce [];
        ReadWritePaths = lib.mkForce [ "${allocationMount}/data" "${allocationMount}/state" ];
        StandardOutput = lib.mkForce "null"; StandardError = lib.mkForce "null";
        ExecCondition = [ "+${monitor}/bin/qcl-negf-monitor-storage-check" ];
      };
      # No tmpfiles/mount/format: a missing allocation remains an explicit native gate.
      networking.firewall.interfaces.${config.qclNegf.privateInterface}.allowedTCPPorts = [ cfg.collector.port ];
    })
  ];
}
