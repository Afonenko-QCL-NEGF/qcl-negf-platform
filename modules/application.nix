{ config, lib, pkgs, ... }:
let cfg = config.qclNegf.application;
    native = cfg.nativeAttempts or { enable = false; };
    nativePackage = import ../nix/native-attempt.nix { inherit pkgs; };
    monitoringPackage = import ../nix/monitoring.nix { inherit pkgs; };
    nativePrefix = "${config.qclNegf.cluster.jobDirectory}/${native.resultPrefix or "native"}";
    configurator = cfg.api.configurator;
    configuratorEnabled = configurator.enable;
    savedResults = cfg.api.savedResults or { enable = false; };
    savedEnabled = savedResults.enable;
    savedRoot = config.qclNegf.cluster.jobDirectory;
    savedAlias = "/run/qcl-negf-saved";
    savedMount = config.fileSystems.${savedRoot} or {};
    finiteIdentity = value: value != null &&
      builtins.match "[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}" value != null;
    runtimePath = value: value != null &&
      builtins.match "/[A-Za-z0-9_./-]+" value != null &&
      !(lib.hasPrefix "/nix/store/" value) &&
      lib.all (part: part != "" && part != "." && part != "..")
        (lib.tail (lib.splitString "/" value));
    savedBound = savedEnabled && cfg.api.enable &&
      savedResults.namespaceId != null &&
      builtins.match "[A-Za-z0-9][A-Za-z0-9._-]{0,127}" savedResults.namespaceId != null &&
      finiteIdentity savedResults.storageIdentity &&
      runtimePath savedResults.storageIdentityFile && runtimePath savedRoot &&
      finiteIdentity savedResults.retentionPolicyId && finiteIdentity savedResults.retentionOwnerId &&
      finiteIdentity savedResults.holdRef && finiteIdentity savedResults.accessBindingRef &&
      savedResults.allowedComputerUuids != [] && builtins.length savedResults.allowedComputerUuids <= 64 &&
      lib.unique savedResults.allowedComputerUuids == savedResults.allowedComputerUuids &&
      lib.all (value: builtins.match "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" value != null)
        savedResults.allowedComputerUuids &&
      (savedMount.fsType or null) == "nfs4" &&
      (savedMount.device or null) == "${config.qclNegf.cluster.storageHost}:/srv/qcl-negf/jobs" &&
      lib.elem "hard" (savedMount.options or []);
    savedBinding = pkgs.writeText "qcl-negf-saved-results-binding.json" (builtins.toJSON {
      namespace_id = savedResults.namespaceId;
      storage_identity = savedResults.storageIdentity;
      root = savedAlias;
      allowed_computer_uuids = savedResults.allowedComputerUuids;
      retention_policy_id = savedResults.retentionPolicyId;
      retention_owner_id = savedResults.retentionOwnerId;
      hold_ref = savedResults.holdRef;
      access_binding_ref = savedResults.accessBindingRef;
    });
    apiSlice = config.systemd.services.qcl-negf-api.serviceConfig.Slice or "system.slice";
    sliceParts = lib.splitString "-" (lib.removeSuffix ".slice" apiSlice);
    slicePath = if apiSlice == "-.slice" then "" else
      lib.concatStringsSep "/" (lib.imap0 (index: _:
        lib.concatStringsSep "-" (lib.take (index + 1) sliceParts) + ".slice") sliceParts);
    configuratorCgroupRoot = "/sys/fs/cgroup/" +
      lib.optionalString (slicePath != "") (slicePath + "/") + "qcl-negf-api.service";
    applicationProfile = "/nix/var/nix/profiles/qcl-negf-application";
    aiidaRoot = "/var/lib/qcl-negf/aiida";
    profileConfig = "${aiidaRoot}/.aiida/config.json";
    profileAccess = "${aiidaRoot}/.aiida/access/${cfg.profile}";
    profileLog = "${aiidaRoot}/.aiida/log";
    nativeActorConfiguration = pkgs.writeText "qcl-negf-native-actor-launch.json" (builtins.toJSON {
      schema = "qcl-negf.native-actor-launch.v1";
      profile = cfg.profile;
      aiida_path = aiidaRoot;
      application_profile = applicationProfile;
      jobs_root = config.qclNegf.cluster.jobDirectory;
      client = nativePackage.clientLaunch;
    });
    exportSpoolDirectory = "/var/lib/qcl-negf/exports";
    bootstrapUnits = lib.optional cfg.bootstrap.enable "qcl-negf-bootstrap.service";
    operations = pkgs.runCommand "qcl-negf-bootstrap-operations" {} ''
      mkdir -p "$out/ops"
      cp ${../ops/bootstrap.ts} "$out/ops/bootstrap.ts"
      cp ${../ops/bootstrap_profile.py} "$out/ops/bootstrap_profile.py"
      cp ${../ops/plan.ts} "$out/ops/plan.ts"
      cp ${../ops/register_aiida.py} "$out/ops/register_aiida.py"
      cp ${../ops/application_release.py} "$out/ops/application_release.py"
      cp ${../ops/release_identity.py} "$out/ops/release_identity.py"
      cp ${../ops/release_trust.py} "$out/ops/release_trust.py"
      cp ${../ops/release_qualification.py} "$out/ops/release_qualification.py"
      cp ${../ops/release_health.py} "$out/ops/release_health.py"
      cp ${../ops/runtime_bindings.py} "$out/ops/runtime_bindings.py"
    '';
    launchConfiguration = pkgs.writeText "qcl-negf-application-launch.json" (builtins.toJSON {
      schema = "qcl-negf-application-launch-v1";
      allowed_codes_file = cfg.api.allowedCodesFile;
      configurator = if configuratorEnabled then { cgroup_root = configuratorCgroupRoot; } else null;
      cluster_cache = if config.qclNegf.monitoring.observation.portalCache.enable then {
        executable = monitoringPackage.portalCacheClient;
      } else null;
      saved_results = if savedBound then {
        binding_file = toString savedBinding;
        root = savedRoot;
        alias = savedAlias;
        nfs_source = savedMount.device;
        storage_identity_file = savedResults.storageIdentityFile;
      } else null;
    });
    apiStart = pkgs.writeShellScript "qcl-negf-api-start" ''
      set -eu
      exec ${pkgs.python314}/bin/python3 ${operations}/ops/runtime_bindings.py \
        --config ${launchConfiguration} --port ${toString cfg.api.port}
    '';
    daemonStart = pkgs.writeShellScript "qcl-negf-aiida-start" (if native.enable then ''
      set -eu
      native_application="$(${pkgs.coreutils}/bin/readlink -e ${applicationProfile})"
      case "$native_application" in
        /nix/store/*) ;;
        *) exit 78 ;;
      esac
      export PATH="$native_application/bin:$PATH"
      exec "$native_application/bin/verdi" -p ${lib.escapeShellArg cfg.profile} daemon start --foreground
    '' else ''
      export PATH=${applicationProfile}/bin:$PATH
      exec ${applicationProfile}/bin/verdi -p ${lib.escapeShellArg cfg.profile} daemon start --foreground
    '');
in {
  options.qclNegf.application = {
    enable = lib.mkEnableOption "AiiDA scientific control service";
    package = lib.mkOption { type = lib.types.package; description = "Immutable Python environment containing verdi, aiida-qcl-negf and qcl-negf-api."; };
    profile = lib.mkOption { type = lib.types.str; default = "qcl-negf"; description = "AiiDA profile name."; };
    nativeAttempts = {
      enable = lib.mkEnableOption "ordinary native attempt socket owner (requires separate native qualification)";
      policyFile = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; description = "Private controller policy runtime path; no credentials or qualification in the store."; };
      resultPrefix = lib.mkOption { type = lib.types.str; default = "native"; description = "New owned canonical result subdomain under jobs; uploads stay outside it."; };
    };
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
      savedResults = {
        enable = lib.mkEnableOption "registered retained NFS results through a read-only API alias";
        namespaceId = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; description = "Finite site namespace ID; never reuse it for another storage identity."; };
        storageIdentity = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; description = "Measured site storage/export identity, not a hostname guess."; };
        storageIdentityFile = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; description = "Root-owned readable runtime file with the admitted storage identity; site maintains its binding to the actual NFS export."; };
        allowedComputerUuids = lib.mkOption { type = lib.types.listOf lib.types.str; default = []; description = "Explicit AiiDA Computer UUID allowlist; each source must match one exact Computer."; };
        retentionPolicyId = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; description = "Site policy for indefinite retention until explicit owner disposition."; };
        retentionOwnerId = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; description = "Named site retention owner."; };
        holdRef = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; description = "Site namespace hold evidence reference; not per-attempt proof of quiescence or closure."; };
        accessBindingRef = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; description = "Private site admission receipt reference for storage, numeric identity and read access."; };
      };
      configurator = {
        enable = lib.mkEnableOption "bounded source-bound Runner catalog/preview in the existing API unit";
      };
      tls = {
        enable = lib.mkEnableOption "loopback-only TLS API proxy with runtime credentials";
        port = lib.mkOption { type = lib.types.port; default = 443; description = "Loopback TLS proxy port."; };
        serverName = lib.mkOption { type = lib.types.str; default = "localhost"; description = "TLS virtual host name; certificate identity is a private site choice."; };
        certificateFile = lib.mkOption { type = lib.types.str; default = "/run/secrets/qcl-negf-tls.crt"; description = "Runtime certificate file outside the Nix store."; };
        keyFile = lib.mkOption { type = lib.types.str; default = "/run/secrets/qcl-negf-tls.key"; description = "Runtime private key file outside the Nix store."; };
      };
    };
  };
  config = lib.mkIf cfg.enable {
    qclNegf.enable = true;
    assertions = [
      { assertion = !native.enable || (cfg.api.enable && native.policyFile == "/etc/qcl-negf/native-attempt/policy.json" && builtins.match "[A-Za-z0-9][A-Za-z0-9._-]{0,127}" native.resultPrefix != null); message = "Native attempts require the existing API, the protected fixed runtime policy and one new owned result prefix."; }
      { assertion = !native.enable || (builtins.match "[A-Za-z0-9][A-Za-z0-9._-]{0,127}" cfg.profile != null && runtimePath config.qclNegf.cluster.jobDirectory); message = "Native actor selection requires a portable existing profile and normalized jobs root."; }
      { assertion = !savedEnabled || savedBound; message = "Saved results require an enabled API, explicit finite namespace/storage/retention/access binding, canonical runtime identity path, Computer UUIDs and the existing hard NFSv4 jobs mount."; }
      { assertion = !configuratorEnabled || cfg.api.enable; message = "Configurator requires the existing API; solver and Research bindings come from its protected active release descriptor."; }
      { assertion = !configuratorEnabled || lib.versionAtLeast config.systemd.package.version "254"; message = "Configurator DelegateSubgroup requires systemd >= 254."; }
      { assertion = !configuratorEnabled || (builtins.match "[A-Za-z0-9_.:-]+[.]slice" apiSlice != null); message = "Configurator requires an ordinary explicitly bound systemd slice name."; }
      { assertion = config.qclNegf.cluster.submit || config.qclNegf.cluster.controller; message = "AiiDA requires the local Slurm submission configuration."; }
      { assertion = !cfg.bootstrap.enable || (cfg.profile == "qcl-negf" && cfg.bootstrap.email != "" && config.qclNegf.cluster.solverPackage != null); message = "Automatic bootstrap requires profile qcl-negf, a service email and the immutable cluster solver package."; }
      { assertion = !cfg.api.enable || (lib.hasPrefix "/" cfg.api.tokenFile && !(lib.hasPrefix "/nix/store/" cfg.api.tokenFile)); message = "API token requires a runtime absolute path outside the store."; }
      { assertion = cfg.api.allowedCodesFile == null || (lib.hasPrefix "/" cfg.api.allowedCodesFile && !(lib.hasPrefix "/nix/store/" cfg.api.allowedCodesFile)); message = "API Code allowlist file must be a runtime absolute path outside the store."; }
      { assertion = !cfg.api.tls.enable || (cfg.api.enable && cfg.api.tls.port != cfg.api.port && builtins.all (path: lib.hasPrefix "/" path && !(lib.hasPrefix "/nix/store/" path)) [ cfg.api.tls.certificateFile cfg.api.tls.keyFile ]); message = "TLS requires an enabled API, a separate port and runtime certificate/key paths outside the store."; }
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
    environment.systemPackages = [ cfg.package ] ++ lib.optional native.enable nativePackage;
    systemd.tmpfiles.rules = [ "d /var/lib/qcl-negf/aiida 0700 qcl-negf qcl-negf -" ] ++ lib.optionals cfg.api.enable [
      "d ${exportSpoolDirectory} 0700 qcl-negf qcl-negf -"
      "d /var/lib/qcl-negf/runtime-failures 0700 qcl-negf qcl-negf 7d"
    ] ++ lib.optionals native.enable [
      "d /run/qcl-negf 0755 root root -"
      "d /var/lib/qcl-negf-native-attempt 0700 root root -"
      "d /var/lib/qcl-negf-native-spool 0750 root qcl-negf -"
      "d /etc/qcl-negf/native-attempt 0700 root root -"
    ];
    systemd.sockets.qcl-negf-native-attempt = lib.mkIf native.enable {
      description = "One authenticated native attempt operation per connection";
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenStream = "/run/qcl-negf/native-attempt.sock";
        SocketUser = "root"; SocketGroup = "qcl-negf"; SocketMode = "0660";
        DirectoryMode = "0755"; Accept = true; MaxConnections = 8;
      };
    };
    systemd.services."qcl-negf-native-attempt@" = lib.mkIf native.enable {
      description = "Bounded root ordinary attempt owner";
      unitConfig.RequiresMountsFor = [ "/var/lib/qcl-negf-native-attempt" "/var/lib/qcl-negf-native-spool" config.qclNegf.cluster.jobDirectory native.policyFile profileConfig profileAccess profileLog ];
      unitConfig.ConditionPathExists = [ native.policyFile profileConfig profileAccess profileLog ];
      environment.QCL_NEGF_NATIVE_ACTOR_CONFIG = toString nativeActorConfiguration;
      serviceConfig = {
        User = "root"; Group = "root"; StandardInput = "socket"; StandardOutput = "socket"; StandardError = "journal";
        ExecStart = "${nativePackage}/bin/qcl-negf-native-attempt-serve";
        Restart = "no"; KillMode = "control-group"; RuntimeMaxSec = 90; TimeoutStopSec = 5;
        MemoryMax = 134217728; TasksMax = 16; UMask = "0077";
        ProtectSystem = "strict"; ProtectHome = true; PrivateTmp = true;
        ReadWritePaths = [ "/var/lib/qcl-negf-native-attempt" "/var/lib/qcl-negf-native-spool" profileAccess profileLog ];
        ReadOnlyPaths = [ profileConfig ];
      };
    };
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
        deno run --allow-read --allow-sys=uid --allow-run=verdi,${applicationProfile}/bin/python \
          ${operations}/ops/bootstrap.ts ${lib.escapeShellArg cfg.bootstrap.email} \
          "$solver" --label "$label" --apply
      '';
    };
    services.nginx = lib.mkIf cfg.api.tls.enable {
      enable = true;
      virtualHosts."qcl-negf-api" = {
        serverName = cfg.api.tls.serverName;
        onlySSL = true;
        listen = [{ addr = "127.0.0.1"; port = cfg.api.tls.port; ssl = true; }];
        sslCertificate = "/run/credentials/nginx.service/qcl-api-cert";
        sslCertificateKey = "/run/credentials/nginx.service/qcl-api-key";
        locations."/" = {
          proxyPass = "http://127.0.0.1:${toString cfg.api.port}";
          extraConfig = ''
            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_buffering off;
            proxy_request_buffering off;
            proxy_max_temp_file_size 0;
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
          '';
        };
      };
    };
    systemd.services.nginx = lib.mkIf cfg.api.tls.enable {
      requires = config.qclNegf.runtimeSecretUnits;
      after = config.qclNegf.runtimeSecretUnits;
      serviceConfig.LoadCredential = [
        "qcl-api-cert:${cfg.api.tls.certificateFile}"
        "qcl-api-key:${cfg.api.tls.keyFile}"
      ];
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
      } // lib.optionalAttrs native.enable {
        QCL_NEGF_NATIVE_JOBS_ROOT = config.qclNegf.cluster.jobDirectory;
      };
      path = [ pkgs.bash pkgs.openssh pkgs.slurm ] ++ lib.optional native.enable nativePackage;
      serviceConfig = {
        User = "qcl-negf"; Group = "qcl-negf";
        WorkingDirectory = "/var/lib/qcl-negf";
        EnvironmentFile = "-/var/lib/qcl-negf-admin/runtime/service.env";
        ExecStart = daemonStart;
        Restart = "on-failure"; RestartSec = 5;
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ "/var/lib/qcl-negf" "/srv/qcl-negf" ];
      } // lib.optionalAttrs native.enable {
        ReadOnlyPaths = [ nativePrefix profileConfig ];
      };
    };
    systemd.services.qcl-negf-api = lib.mkIf cfg.api.enable {
      description = "QCL-NEGF scientific API";
      path = [ pkgs.util-linux ];
      wantedBy = [ "multi-user.target" ];
      requires = [ "qcl-negf-aiida.service" "qcl-negf-application-profile.service" ] ++ bootstrapUnits ++ config.qclNegf.runtimeSecretUnits;
      partOf = bootstrapUnits;
      after = [ "qcl-negf-aiida.service" "qcl-negf-application-profile.service" ] ++ bootstrapUnits ++ config.qclNegf.runtimeSecretUnits;
      unitConfig.RequiresMountsFor = [ "/var/lib/qcl-negf" cfg.api.tokenFile ] ++
        lib.optionals savedBound [ savedRoot savedResults.storageIdentityFile ];
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
        TMPDIR = exportSpoolDirectory;
      };
      serviceConfig = {
        User = "qcl-negf"; Group = "qcl-negf";
        WorkingDirectory = "/var/lib/qcl-negf";
        LoadCredential = "api-token:${cfg.api.tokenFile}";
        EnvironmentFile = "-/var/lib/qcl-negf-admin/runtime/service.env";
        ExecStart = apiStart;
        Restart = "on-failure";
        NoNewPrivileges = true;
        # Hold the memory-admission namespace assumptions across child spawn.
        # Ordinary fork/exec remains available; no new namespace or setns.
        RestrictNamespaces = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ "/var/lib/qcl-negf" ];
      } // lib.optionalAttrs native.enable {
        ReadOnlyPaths = [ nativePrefix profileConfig ];
      } // lib.optionalAttrs savedBound {
        BindReadOnlyPaths = [ "${savedRoot}:${savedAlias}" ];
        ReadOnlyPaths = [ savedRoot savedResults.storageIdentityFile ] ++ lib.optionals native.enable [ nativePrefix profileConfig ];
      } // lib.optionalAttrs configuratorEnabled {
        Delegate = "cpu memory pids";
        DelegateSubgroup = "api";
        KillMode = "control-group";
      };
    };
  };
}
