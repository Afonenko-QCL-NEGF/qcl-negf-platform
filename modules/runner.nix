{ config, lib, pkgs, ... }:
let cfg = config.qclNegf.runner;
    repositories = [ "qcl-negf" ];
in {
  options.qclNegf.runner = {
    enable = lib.mkEnableOption "Local GitHub Actions runners";
    repositories = lib.mkOption { type = lib.types.listOf (lib.types.enum repositories); default = repositories; description = "Repositories registered on this dedicated CI host."; };
    tokenDirectory = lib.mkOption { type = lib.types.str; default = "/run/secrets/github-runners"; description = "Directory of per-repository access tokens outside the store."; };
    cpuQuota = lib.mkOption { type = lib.types.str; default = "200%"; description = "Aggregate CPU ceiling for all repository runner services."; };
    memoryMax = lib.mkOption { type = lib.types.str; default = "8G"; description = "Aggregate memory ceiling for all repository runner services."; };
    maxJobs = lib.mkOption { type = lib.types.ints.positive; default = 2; description = "Maximum parallel Nix builds on the CI host."; };
    buildCores = lib.mkOption { type = lib.types.ints.positive; default = 4; description = "Nix build cores per derivation; applies to daemon builds as well as runner jobs."; };
    secretUnits = lib.mkOption { type = lib.types.listOf lib.types.str; default = config.qclNegf.runtimeSecretUnits; description = "Runtime secret provisioning units required before runner registration."; };
  };
  config = lib.mkIf cfg.enable {
    qclNegf.enable = true;
    # CI executes checksum-pinned upstream Julia and Python manylinux artifacts.
    # Keep foreign ELF compatibility confined to the dedicated build VM.
    programs.nix-ld.enable = true;
    assertions = [
      { assertion = !(config.qclNegf.cluster.controller || config.qclNegf.cluster.worker || config.qclNegf.cluster.submit || config.qclNegf.application.enable || config.qclNegf.storage.enable); message = "CI must be on a dedicated VM, isolated from scientific credentials, mounts and workloads."; }
      { assertion = lib.hasPrefix "/" cfg.tokenDirectory && !(lib.hasPrefix "/nix/store/" cfg.tokenDirectory); message = "Runner tokens require a runtime absolute directory outside the store."; }
    ];
    users.groups.qcl-negf-build = {};
    systemd.tmpfiles.rules = [ "d /var/lib/qcl-negf-releases 2770 root qcl-negf-build -" ];
    nix.settings.max-jobs = cfg.maxJobs;
    nix.settings.cores = cfg.buildCores;
    systemd.slices.qcl-negf-ci.sliceConfig = { CPUQuota = cfg.cpuQuota; MemoryMax = cfg.memoryMax; TasksMax = 4096; };
    services.github-runners = lib.listToAttrs (map (repo: lib.nameValuePair repo {
      enable = true;
      url = "https://github.com/Afonenko-QCL-NEGF/${repo}";
      name = repo;
      tokenFile = "${cfg.tokenDirectory}/${repo}";
      tokenType = "access";
      ephemeral = true;
      replace = true;
      extraLabels = [ "qcl-negf-ci" "nixos" ];
      serviceOverrides = {
        Slice = "qcl-negf-ci.slice";
        SupplementaryGroups = [ "qcl-negf-build" ];
        ReadWritePaths = [ "/var/lib/qcl-negf-releases" ];
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
