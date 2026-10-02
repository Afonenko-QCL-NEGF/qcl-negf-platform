{ config, lib, pkgs, ... }:
let cfg = config.qclNegf.runner;
    repositories = [ "qcl-negf" ];
    runnerUser = repo: "github-runner-${repo}";
in {
  imports = map (name: lib.mkRemovedOptionModule [ "qclNegf" "runner" name ]
    "Use qclNegf.builder.profile; Nix daemon and runner jobs share its one aggregate resource slice.")
    [ "cpuQuota" "memoryMax" "maxJobs" "buildCores" ];
  options.qclNegf.runner = {
    enable = lib.mkEnableOption "Local GitHub Actions runners";
    repositories = lib.mkOption { type = lib.types.listOf (lib.types.enum repositories); default = repositories; description = "Repositories registered on this dedicated CI host."; };
    tokenDirectory = lib.mkOption { type = lib.types.str; default = "/run/secrets/github-runners"; description = "Directory of short-lived per-repository registration tokens outside the store; PATs stay on the administrative controller."; };
    secretUnits = lib.mkOption { type = lib.types.listOf lib.types.str; default = config.qclNegf.runtimeSecretUnits; description = "Runtime secret provisioning units required before runner registration."; };
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
        ];
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
      requires = cfg.secretUnits;
      after = cfg.secretUnits;
      unitConfig.RequiresMountsFor = cfg.tokenDirectory;
    }) cfg.repositories);
  };
}
