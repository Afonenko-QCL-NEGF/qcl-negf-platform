{ config, lib, ... }:
let
  cfg = config.qclNegf.builder;
  profiles = builtins.fromJSON (builtins.readFile ../ops/build-profiles.json);
  selected = profiles.${cfg.profile};
  dynamic = selected.dynamic or false;
  vcpus = if cfg.resources == null then 0 else cfg.resources.vcpus;
  memoryMiB = if cfg.resources == null then 0 else cfg.resources.memoryMiB;
  profile = if dynamic then selected // {
    cpu_quota = "${toString (vcpus * 100)}%";
    memory_max = "${toString (lib.max 0 (memoryMiB - selected.guest_reserve_mib))}M";
    build_cores = vcpus;
  } else selected;
in {
  options.qclNegf.builder = {
    enable = lib.mkEnableOption "bounded administrative builds on a dedicated CI VM";
    profile = lib.mkOption {
      type = lib.types.enum (builtins.attrNames profiles);
      default = "standard";
      description = "Reviewed VM resource profile; host admission and VM resizing are separate deployment operations.";
    };
    resources = lib.mkOption {
      type = lib.types.nullOr (lib.types.submodule {
        options = {
          vcpus = lib.mkOption { type = lib.types.ints.positive; };
          memoryMiB = lib.mkOption { type = lib.types.ints.positive; };
        };
      });
      default = null;
      description = "Explicit temporary production-build guest CPU/RAM, identical to the admitted bootstrap VM resources; other profiles use the shared fixed table.";
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
    } {
      assertion = !dynamic || (cfg.resources != null && memoryMiB > selected.guest_reserve_mib);
      message = "production-build requires explicit guest CPU/RAM with at least 2 GiB reserved for the guest OS.";
    } {
      assertion = dynamic || cfg.resources == null;
      message = "Explicit builder resources belong only to production-build; fixed profiles retain their shared budgets.";
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
