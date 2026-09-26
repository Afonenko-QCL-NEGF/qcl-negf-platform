{ config, lib, pkgs, ... }:
let cfg = config.qclNegf.application;
in {
  options.qclNegf.application = {
    enable = lib.mkEnableOption "AiiDA scientific control service";
    package = lib.mkOption { type = lib.types.package; description = "Immutable Python environment containing verdi, aiida-qcl-negf and qcl-negf-api."; };
    profile = lib.mkOption { type = lib.types.str; default = "qcl-negf"; description = "AiiDA profile name."; };
    api = {
      enable = lib.mkEnableOption "Scientific HTTP API";
      tokenFile = lib.mkOption { type = lib.types.str; default = "/run/secrets/qcl-negf-api-token"; description = "Runtime bearer token file outside the Nix store."; };
      allowedCodes = lib.mkOption { type = lib.types.listOf lib.types.str; default = []; description = "AiiDA Code UUIDs admitted by the API."; };
      maxCores = lib.mkOption { type = lib.types.ints.positive; default = 4; description = "Maximum CPUs per API submission; align with the selected partition."; };
      maxMemoryKiB = lib.mkOption { type = lib.types.ints.positive; default = 7168000; description = "Maximum RAM KiB per API submission; align with Slurm RealMemory."; };
      defaultMemoryKiB = lib.mkOption { type = lib.types.ints.positive; default = 4194304; description = "Default RAM KiB per API submission."; };
      port = lib.mkOption { type = lib.types.port; default = 8080; description = "Loopback API port for an authenticated TLS proxy."; };
    };
  };
  config = lib.mkIf cfg.enable {
    qclNegf.enable = true;
    assertions = [{ assertion = config.qclNegf.cluster.submit || config.qclNegf.cluster.controller; message = "AiiDA requires the local Slurm submission configuration."; }];
    services.postgresql = {
      enable = true; package = pkgs.postgresql_17;
      ensureDatabases = [ "qcl-negf" ];
      ensureUsers = [{ name = "qcl-negf"; ensureDBOwnership = true; }];
      enableTCPIP = false;
      authentication = lib.mkForce ''
        local all postgres peer
        local qcl-negf qcl-negf peer
      '';
    };
    environment.systemPackages = [ cfg.package ];
    systemd.tmpfiles.rules = [ "d /var/lib/qcl-negf/aiida 0700 qcl-negf qcl-negf -" ];
    systemd.services.qcl-negf-aiida = {
      description = "AiiDA workflow daemon";
      wantedBy = [ "multi-user.target" ];
      requires = [ "postgresql.service" ];
      wants = [ "network-online.target" ];
      after = [ "postgresql.service" "network-online.target" ];
      unitConfig.ConditionPathExists = "/var/lib/qcl-negf/aiida/config.json";
      environment = {
        AIIDA_PATH = "/var/lib/qcl-negf/aiida";
        SLURM_CONF = "${config.services.slurm.etcSlurm}/slurm.conf";
      };
      path = [ pkgs.openssh pkgs.slurm ];
      serviceConfig = {
        User = "qcl-negf"; Group = "qcl-negf";
        WorkingDirectory = "/var/lib/qcl-negf";
        ExecStart = "${cfg.package}/bin/verdi -p ${cfg.profile} daemon start --foreground";
        Restart = "on-failure"; RestartSec = 5;
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ "/var/lib/qcl-negf" "/srv/qcl-negf" ];
      };
    };
    systemd.services.qcl-negf-api = lib.mkIf cfg.api.enable {
      description = "QCL-NEGF scientific API";
      wantedBy = [ "multi-user.target" ];
      after = [ "qcl-negf-aiida.service" ];
      unitConfig.ConditionPathExists = "/var/lib/qcl-negf/aiida/config.json";
      environment = {
        AIIDA_PATH = "/var/lib/qcl-negf/aiida";
        SLURM_CONF = "${config.services.slurm.etcSlurm}/slurm.conf";
        QCL_NEGF_AIIDA_PROFILE = cfg.profile;
        QCL_NEGF_SCRATCH_ROOT = "/scratch/qcl-negf";
        QCL_NEGF_API_TOKEN_FILE = "%d/api-token";
        QCL_NEGF_ALLOWED_CODES = lib.concatStringsSep "," cfg.api.allowedCodes;
        QCL_NEGF_MAX_CORES_PER_PROCESS = toString cfg.api.maxCores;
        QCL_NEGF_MAX_MEMORY_KB = toString cfg.api.maxMemoryKiB;
        QCL_NEGF_DEFAULT_MEMORY_KB = toString cfg.api.defaultMemoryKiB;
      };
      serviceConfig = {
        User = "qcl-negf"; Group = "qcl-negf";
        WorkingDirectory = "/var/lib/qcl-negf";
        LoadCredential = "api-token:${cfg.api.tokenFile}";
        ExecStart = "${cfg.package}/bin/qcl-negf-api --host 127.0.0.1 --port ${toString cfg.api.port}";
        Restart = "on-failure";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ "/var/lib/qcl-negf" ];
      };
    };
  };
}
