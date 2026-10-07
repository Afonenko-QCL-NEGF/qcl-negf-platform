# Render the real launch scripts without creating Nix store artifacts or a VM.
# Only writeShellScript's file creation is replaced; module launch behavior is real.
{ nixpkgs }:
let
  lib = import (nixpkgs + "/lib");
  module = import ../../modules/application.nix {
    inherit lib;
    pkgs = {
      writeShellScript = name: text: text;
      bash = "bash";
      openssh = "openssh";
      slurm = "slurm";
    };
    config.qclNegf.application = {
      enable = true;
      profile = "qcl-negf";
      api = { enable = true; port = 8080; allowedCodesFile = null; };
    };
  };
in {
  daemon = module.config.content.systemd.services.qcl-negf-aiida.serviceConfig.ExecStart;
  daemonPath = module.config.content.systemd.services.qcl-negf-aiida.path;
  api = module.config.content.systemd.services.qcl-negf-api.content.serviceConfig.ExecStart;
}
