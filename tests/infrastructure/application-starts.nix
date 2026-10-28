# Render the real launch scripts without creating Nix store artifacts or a VM.
# Only writeShellScript's file creation is replaced; module launch behavior is real.
{ nixpkgs }:
let
  lib = import (nixpkgs + "/lib");
  make = enabled: slice: import ../../modules/application.nix {
    inherit lib;
    pkgs = {
      writeShellScript = name: text: text;
      writeText = name: text: lib.escapeShellArg text;
      runCommand = name: attrs: script: "/synthetic-operations";
      python314 = "/synthetic-python";
      util-linux = "util-linux";
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
        };
        api = {
          enable = true; port = 8080; allowedCodesFile = null;
          configurator = {
            enable = enabled;
          };
        };
      };
      systemd.services.qcl-negf-api.serviceConfig.Slice = slice;
    };
  };
  module = make false "system.slice";
  enabledModule = make true "system.slice";
  nestedModule = make true "research-api.slice";
in {
  daemon = module.config.content.systemd.services.qcl-negf-aiida.serviceConfig.ExecStart;
  daemonPath = module.config.content.systemd.services.qcl-negf-aiida.path;
  api = module.config.content.systemd.services.qcl-negf-api.content.serviceConfig.ExecStart;
  apiPath = module.config.content.systemd.services.qcl-negf-api.content.path or [];
  configuratorApi = enabledModule.config.content.systemd.services.qcl-negf-api.content.serviceConfig.ExecStart;
  nestedApi = nestedModule.config.content.systemd.services.qcl-negf-api.content.serviceConfig.ExecStart;
}
