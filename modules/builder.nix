{ config, lib, ... }:
let
  cfg = config.qclNegf.builder;
  profiles = builtins.fromJSON (builtins.readFile ../ops/build-profiles.json);
  profile = profiles.${cfg.profile};
in {
  options.qclNegf.builder = {
    enable = lib.mkEnableOption "bounded administrative builds on a dedicated CI VM";
    profile = lib.mkOption {
      type = lib.types.enum (builtins.attrNames profiles);
      default = "standard";
      description = "Reviewed VM resource profile; host admission and VM resizing are separate deployment operations.";
    };
    sliceName = lib.mkOption {
      type = lib.types.str;
      default = "qcl-build.slice";
      readOnly = true;
      description = "Shared resource parent for Nix daemon, administrative builds and CI jobs.";
    };
  };
  config = lib.mkIf cfg.enable {
    qclNegf.enable = true;
    assertions = [{
      assertion = !(config.qclNegf.cluster.controller || config.qclNegf.cluster.worker
        || config.qclNegf.cluster.submit || config.qclNegf.application.enable
        || config.qclNegf.storage.enable);
      message = "Administrative builds require a dedicated CI VM without scientific services.";
    }];
    nix.settings = { max-jobs = profile.max_jobs; cores = profile.build_cores; };
    systemd.services.nix-daemon.serviceConfig.Slice = cfg.sliceName;
    systemd.slices.qcl-build.sliceConfig = {
      CPUQuota = profile.cpu_quota;
      MemoryMax = profile.memory_max;
      MemorySwapMax = profile.memory_swap_max;
      TasksMax = 4096;
    };
  };
}
