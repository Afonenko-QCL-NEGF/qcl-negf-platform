# Render the real launch scripts without creating Nix store artifacts or a VM.
# Only writeShellScript's file creation is replaced; module launch behavior is real.
{ nixpkgs }:
let
  lib = import (nixpkgs + "/lib");
  make = enabled: import ../../modules/application.nix {
    inherit lib;
    pkgs = {
      writeShellScript = name: text: text;
      bash = "bash";
      openssh = "openssh";
      slurm = "slurm";
      coreutils = "/synthetic-coreutils";
    };
    config = {
      qclNegf.cluster.solverPackage = "/nix/store/synthetic-solver";
      qclNegf.application = {
        enable = true;
        profile = "qcl-negf";
        package = {
          outPath = "/nix/store/synthetic-application";
          configuratorCatalogRoot = "/nix/store/synthetic-research";
        };
        api = {
          enable = true; port = 8080; allowedCodesFile = null;
          configurator = {
            enable = enabled;
            catalogRoot = "/nix/store/synthetic-research";
            catalogSourceId = "synthetic-source";
          };
        };
      };
      systemd.services.qcl-negf-api.serviceConfig.Slice = "system.slice";
    };
  };
  module = make false;
  enabledModule = make true;
in {
  daemon = module.config.content.systemd.services.qcl-negf-aiida.serviceConfig.ExecStart;
  daemonPath = module.config.content.systemd.services.qcl-negf-aiida.path;
  api = module.config.content.systemd.services.qcl-negf-api.content.serviceConfig.ExecStart;
  configuratorApi = enabledModule.config.content.systemd.services.qcl-negf-api.content.serviceConfig.ExecStart;
}
