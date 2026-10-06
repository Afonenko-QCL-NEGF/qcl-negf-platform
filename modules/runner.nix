{ config, lib, pkgs, ... }:
let cfg = config.qclNegf.runner;
    repositories = [ "qcl-negf" ];
    runnerUser = repo: "github-runner-${repo}";
    routingEnabled = cfg.routing.hostsFile != null && cfg.routing.nsswitchFile != null;
    routingFiles = [ cfg.routing.hostsFile cfg.routing.nsswitchFile ];
    runtimeFile = path: path == null || (
      builtins.match "/[^[:space:]:%]*" path != null
      && path != "/"
      && path != "/nix/store"
      && !(lib.hasPrefix "/nix/store/" path)
      && builtins.all (part: !(builtins.elem part [ "" "." ".." ]))
        (builtins.tail (lib.splitString "/" path))
    );
in {
  imports = map (name: lib.mkRemovedOptionModule [ "qclNegf" "runner" name ]
    "Use qclNegf.builder.profile; Nix daemon and runner jobs share its one aggregate resource slice.")
    [ "cpuQuota" "memoryMax" "maxJobs" "buildCores" ];
  options.qclNegf.runner = {
    enable = lib.mkEnableOption "Local GitHub Actions runners";
    repositories = lib.mkOption { type = lib.types.listOf (lib.types.enum repositories); default = repositories; description = "Repositories registered on this dedicated CI host."; };
    tokenDirectory = lib.mkOption { type = lib.types.str; default = "/run/secrets/github-runners"; description = "Directory of short-lived per-repository registration tokens outside the store; PATs stay on the administrative controller."; };
    secretUnits = lib.mkOption { type = lib.types.listOf lib.types.str; default = config.qclNegf.runtimeSecretUnits; description = "Runtime secret provisioning units required before runner registration."; };
    routing = {
      hostsFile = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; description = "Site-provisioned absolute runtime hosts file, bound read-only only in runner units; requires nsswitchFile."; };
      nsswitchFile = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; description = "Site-provisioned absolute runtime NSS configuration, bound read-only only in runner units; requires hostsFile."; };
      units = lib.mkOption { type = lib.types.listOf lib.types.str; default = []; description = "Runtime file provisioning units required and ordered before runner startup when routing is enabled."; };
    };
  };
  config = lib.mkIf cfg.enable {
    qclNegf.enable = true;
    qclNegf.builder.enable = lib.mkDefault true;
    # CI executes checksum-pinned upstream Julia and Python manylinux artifacts.
    # Keep foreign ELF compatibility confined to the dedicated build VM.
    programs.nix-ld.enable = true;
    assertions = [
      { assertion = !(config.qclNegf.cluster.controller || config.qclNegf.cluster.worker || config.qclNegf.cluster.submit || config.qclNegf.application.enable || config.qclNegf.storage.enable); message = "CI must be on a dedicated VM, isolated from scientific credentials, mounts and workloads."; }
      { assertion = lib.hasPrefix "/" cfg.tokenDirectory && !(lib.hasPrefix "/nix/store/" cfg.tokenDirectory); message = "Runner tokens require a runtime absolute directory outside the store."; }
      { assertion = config.qclNegf.builder.enable; message = "GitHub jobs must share the dedicated builder resource profile."; }
      { assertion = (cfg.routing.hostsFile == null) == (cfg.routing.nsswitchFile == null); message = "Runner routing requires both hostsFile and nsswitchFile, or neither."; }
      { assertion = builtins.all runtimeFile routingFiles; message = "Runner routing files must be canonical absolute runtime paths outside the Nix store, without whitespace, bind-path separators or systemd specifiers."; }
    ];
    users.groups = lib.listToAttrs (map (repo: lib.nameValuePair (runnerUser repo) {}) cfg.repositories);
    users.users = lib.listToAttrs (map (repo: lib.nameValuePair (runnerUser repo) {
      isSystemUser = true;
      group = runnerUser repo;
      home = "/var/lib/github-runner/${repo}";
      createHome = false;
    }) cfg.repositories);
    systemd.tmpfiles.rules = lib.concatMap (repo: [
      "d /var/lib/qcl-negf-ci 0750 root ${runnerUser repo} -"
      "d /var/lib/qcl-negf-ci/releases 0770 root ${runnerUser repo} -"
      "d /var/lib/qcl-negf-ci/work 0750 root ${runnerUser repo} -"
      "d /var/lib/qcl-negf-ci/work/${repo} 0700 ${runnerUser repo} ${runnerUser repo} -"
    ]) cfg.repositories;
    services.github-runners = lib.listToAttrs (map (repo: lib.nameValuePair repo {
      enable = true;
      url = "https://github.com/Afonenko-QCL-NEGF/${repo}";
      name = repo;
      tokenFile = "${cfg.tokenDirectory}/${repo}";
      tokenType = "registration";
      ephemeral = false;
      user = runnerUser repo;
      group = runnerUser repo;
      workDir = "/var/lib/qcl-negf-ci/work/${repo}";
      replace = true;
      extraLabels = [ "qcl-negf-ci" "nixos" ];
      serviceOverrides = {
        Slice = config.qclNegf.builder.sliceName;
        DynamicUser = false;
        SupplementaryGroups = [];
        ReadWritePaths = [ "/var/lib/qcl-negf-ci/releases" ];
        InaccessiblePaths = [
          "-/var/lib/qcl-negf-releases"
          "-/var/lib/qcl-negf-artifacts"
          "-/var/lib/qcl-site-secrets"
          "-/var/lib/qcl-ci-registration"
        ] ++ lib.optional routingEnabled "-/run/nscd";
      } // lib.optionalAttrs routingEnabled {
        BindReadOnlyPaths = [ "${cfg.routing.hostsFile}:/etc/hosts" "${cfg.routing.nsswitchFile}:/etc/nsswitch.conf" ];
      };
      extraPackages = with pkgs; [ git nix deno uv python314 nodejs_24 gcc gnumake opentofu ansible ];
      extraEnvironment = {
        NIX_CONFIG = "experimental-features = nix-command flakes";
        # systemd services do not source the login-session environment.
        NIX_LD = config.environment.sessionVariables.NIX_LD;
        NIX_LD_LIBRARY_PATH = config.environment.sessionVariables.NIX_LD_LIBRARY_PATH;
        # Nix Python bypasses nix-ld, but imported manylinux extension modules
        # still need these standard non-vendored runtime libraries.
        LD_LIBRARY_PATH = lib.makeLibraryPath [ pkgs.stdenv.cc.cc pkgs.zlib ];
      };
    }) cfg.repositories);
    systemd.services = lib.listToAttrs (map (repo: lib.nameValuePair "github-runner-${repo}" {
      requires = cfg.secretUnits ++ lib.optionals routingEnabled cfg.routing.units;
      after = cfg.secretUnits ++ lib.optionals routingEnabled cfg.routing.units;
      unitConfig.RequiresMountsFor = if routingEnabled then [ cfg.tokenDirectory ] ++ routingFiles else cfg.tokenDirectory;
    }) cfg.repositories);
  };
}
