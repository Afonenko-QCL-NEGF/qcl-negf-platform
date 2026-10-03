{ config, lib, pkgs, ... }:
let cfg = config.qclNegf.application;
    applicationProfile = "/nix/var/nix/profiles/qcl-negf-application";
    bootstrapUnits = lib.optional cfg.bootstrap.enable "qcl-negf-bootstrap.service";
    operations = pkgs.runCommand "qcl-negf-bootstrap-operations" {} ''
      mkdir -p "$out/ops"
      cp ${../ops/bootstrap.ts} "$out/ops/bootstrap.ts"
      cp ${../ops/plan.ts} "$out/ops/plan.ts"
      cp ${../ops/register_aiida.py} "$out/ops/register_aiida.py"
      cp ${../ops/application_release.py} "$out/ops/application_release.py"
    '';
    apiStart = pkgs.writeShellScript "qcl-negf-api-start" ''
      set -eu
      ${lib.optionalString (cfg.api.allowedCodesFile != null) ''
        export QCL_NEGF_ALLOWED_CODES="$(cat ${lib.escapeShellArg cfg.api.allowedCodesFile})"
        test -n "$QCL_NEGF_ALLOWED_CODES"
      ''}
      exec ${applicationProfile}/bin/qcl-negf-api --host 127.0.0.1 --port ${toString cfg.api.port}
    '';
in {
  options.qclNegf.application = {
    enable = lib.mkEnableOption "AiiDA scientific control service";
    package = lib.mkOption { type = lib.types.package; description = "Immutable Python environment containing verdi, aiida-qcl-negf and qcl-negf-api."; };
    profile = lib.mkOption { type = lib.types.str; default = "qcl-negf"; description = "AiiDA profile name."; };
    bootstrap = {
      enable = lib.mkEnableOption "repeatable local AiiDA profile, Computer and InstalledCode reconciliation";
      email = lib.mkOption { type = lib.types.str; default = ""; description = "Service user email stored in AiiDA; supplied by the private site."; };
      codeLabel = lib.mkOption { type = lib.types.str; default = "qcl-negf"; description = "Stable Code label; choose a new label for a different immutable solver executable."; };
    };
    api = {
      enable = lib.mkEnableOption "Scientific HTTP API";
      tokenFile = lib.mkOption { type = lib.types.str; default = "/run/secrets/qcl-negf-api-token"; description = "Runtime bearer token file outside the Nix store."; };
      allowedCodes = lib.mkOption { type = lib.types.listOf lib.types.str; default = []; description = "AiiDA Code UUIDs admitted by the API."; };
      allowedCodesFile = lib.mkOption { type = lib.types.nullOr lib.types.str; default = if cfg.bootstrap.enable || config.qclNegf.release.enable then "/var/lib/qcl-negf/aiida/code-uuid" else null; description = "Runtime comma-separated UUID allowlist; when set this is authoritative instead of allowedCodes."; };
      exportDiskBytes = lib.mkOption { type = lib.types.ints.positive; default = 107374182400; description = "Aggregate temporary export disk admission budget in bytes; align with controller free disk."; };
      exportTtlSeconds = lib.mkOption { type = lib.types.ints.positive; default = 86400; description = "Retention in seconds of downloadable export archives."; };
      maxCores = lib.mkOption { type = lib.types.ints.positive; default = 4; description = "Maximum CPUs per API submission; align with the selected partition."; };
      maxMemoryKiB = lib.mkOption { type = lib.types.ints.positive; default = 7168000; description = "Maximum RAM KiB per API submission; align with Slurm RealMemory."; };
      defaultMemoryKiB = lib.mkOption { type = lib.types.ints.positive; default = 4194304; description = "Default RAM KiB per API submission."; };
      port = lib.mkOption { type = lib.types.port; default = 8080; description = "Loopback API port for an authenticated TLS proxy."; };
    };
  };
  config = lib.mkIf cfg.enable {
    qclNegf.enable = true;
    assertions = [
      { assertion = config.qclNegf.cluster.submit || config.qclNegf.cluster.controller; message = "AiiDA requires the local Slurm submission configuration."; }
      { assertion = !cfg.bootstrap.enable || (cfg.profile == "qcl-negf" && cfg.bootstrap.email != "" && config.qclNegf.cluster.solverPackage != null); message = "Automatic bootstrap requires profile qcl-negf, a service email and the immutable cluster solver package."; }
      { assertion = !cfg.api.enable || (lib.hasPrefix "/" cfg.api.tokenFile && !(lib.hasPrefix "/nix/store/" cfg.api.tokenFile)); message = "API token requires a runtime absolute path outside the store."; }
      { assertion = cfg.api.allowedCodesFile == null || (lib.hasPrefix "/" cfg.api.allowedCodesFile && !(lib.hasPrefix "/nix/store/" cfg.api.allowedCodesFile)); message = "API Code allowlist file must be a runtime absolute path outside the store."; }
    ];
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
    systemd.services.qcl-negf-bootstrap = lib.mkIf cfg.bootstrap.enable {
      description = "Reconcile the declared AiiDA profile and immutable installed Code";
      wantedBy = [ "multi-user.target" ];
      requires = [ "postgresql.service" "qcl-negf-application-profile.service" ];
      after = [ "postgresql.service" "qcl-negf-application-profile.service" ];
      before = [ "qcl-negf-aiida.service" "qcl-negf-api.service" ];
      unitConfig.RequiresMountsFor = "/var/lib/qcl-negf";
      path = [ pkgs.deno pkgs.openssh pkgs.slurm ];
      environment.AIIDA_PATH = "/var/lib/qcl-negf/aiida";
      serviceConfig = {
        Type = "oneshot"; RemainAfterExit = true;
        User = "qcl-negf"; Group = "qcl-negf";
        WorkingDirectory = "/var/lib/qcl-negf";
        NoNewPrivileges = true; ProtectSystem = "strict";
        ReadWritePaths = [ "/var/lib/qcl-negf" ];
      };
      script = ''
        export PATH=${applicationProfile}/bin:$PATH
        identity="$(${pkgs.python314}/bin/python3 ${operations}/ops/application_release.py bootstrap-identity \
          --solver-executable ${config.qclNegf.cluster.solverPackage}/bin/qcl-negf \
          --initial-label ${lib.escapeShellArg cfg.bootstrap.codeLabel})"
        solver="''${identity%%$'\n'*}"
        label="''${identity#*$'\n'}"
        deno run --allow-read --allow-sys=uid --allow-run=verdi \
          ${operations}/ops/bootstrap.ts ${lib.escapeShellArg cfg.bootstrap.email} \
          "$solver" --label "$label" --apply
      '';
    };
    systemd.services.qcl-negf-aiida = {
      description = "AiiDA workflow daemon";
      wantedBy = [ "multi-user.target" ];
      requires = [ "postgresql.service" "munged.service" "qcl-negf-application-profile.service" ] ++ lib.optional config.qclNegf.cluster.controller "slurmctld.service" ++ bootstrapUnits ++ config.qclNegf.runtimeSecretUnits;
      partOf = bootstrapUnits;
      wants = [ "network-online.target" ];
      after = [ "postgresql.service" "network-online.target" "munged.service" "qcl-negf-application-profile.service" ] ++ lib.optional config.qclNegf.cluster.controller "slurmctld.service" ++ bootstrapUnits ++ config.qclNegf.runtimeSecretUnits;
      unitConfig.RequiresMountsFor = [ "/var/lib/qcl-negf" config.qclNegf.cluster.jobDirectory ];
      unitConfig.ConditionPathExists = "/var/lib/qcl-negf/aiida/.aiida/config.json";
      environment = {
        AIIDA_PATH = "/var/lib/qcl-negf/aiida";
        SLURM_CONF = "${config.services.slurm.etcSlurm}/slurm.conf";
      };
      path = [ pkgs.openssh pkgs.slurm ];
      serviceConfig = {
        User = "qcl-negf"; Group = "qcl-negf";
        WorkingDirectory = "/var/lib/qcl-negf";
        EnvironmentFile = "-/var/lib/qcl-negf/runtime/service.env";
        ExecStart = "${applicationProfile}/bin/verdi -p ${cfg.profile} daemon start --foreground";
        Restart = "on-failure"; RestartSec = 5;
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ "/var/lib/qcl-negf" "/srv/qcl-negf" ];
      };
    };
    systemd.services.qcl-negf-api = lib.mkIf cfg.api.enable {
      description = "QCL-NEGF scientific API";
      wantedBy = [ "multi-user.target" ];
      requires = [ "qcl-negf-aiida.service" "qcl-negf-application-profile.service" ] ++ bootstrapUnits ++ config.qclNegf.runtimeSecretUnits;
      partOf = bootstrapUnits;
      after = [ "qcl-negf-aiida.service" "qcl-negf-application-profile.service" ] ++ bootstrapUnits ++ config.qclNegf.runtimeSecretUnits;
      unitConfig.RequiresMountsFor = [ "/var/lib/qcl-negf" cfg.api.tokenFile ];
      unitConfig.ConditionPathExists = "/var/lib/qcl-negf/aiida/.aiida/config.json";
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
        QCL_NEGF_EXPORT_DISK_BYTES = toString cfg.api.exportDiskBytes;
        QCL_NEGF_EXPORT_TTL_SECONDS = toString cfg.api.exportTtlSeconds;
      };
      serviceConfig = {
        User = "qcl-negf"; Group = "qcl-negf";
        WorkingDirectory = "/var/lib/qcl-negf";
        LoadCredential = "api-token:${cfg.api.tokenFile}";
        EnvironmentFile = "-/var/lib/qcl-negf/runtime/service.env";
        ExecStart = apiStart;
        Restart = "on-failure";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ "/var/lib/qcl-negf" ];
      };
    };
  };
}
