{ config, lib, pkgs, ... }:
let cfg = config.qclNegf.stateArchive;
    tool = pkgs.writeShellApplication {
      name = "qcl-negf-state-archive";
      runtimeInputs = [ pkgs.python3 pkgs.postgresql_17 pkgs.systemd pkgs.slurm pkgs.util-linux pkgs.coreutils ];
      text = ''
        exec python3 ${../ops/state_archive.py} \
          --slurm-directory ${lib.escapeShellArg config.services.slurm.stateSaveLocation} \
          --secret-reference ${lib.escapeShellArg config.qclNegf.cluster.mungeKeyFile} \
          ${lib.optionalString config.qclNegf.application.api.enable "--secret-reference ${lib.escapeShellArg config.qclNegf.application.api.tokenFile}"} \
          "$@"
      '';
    };
in {
  options.qclNegf.stateArchive.enable = lib.mkEnableOption "manual coordinated controller-state archive and empty-state restoration";
  config = lib.mkIf cfg.enable {
    assertions = [{ assertion = config.qclNegf.application.enable && config.qclNegf.application.profile == "qcl-negf" && config.qclNegf.stateDisk.enable; message = "Controller-state archival requires the qcl-negf application profile and its separate persistent state disk."; }];
    environment.systemPackages = [ tool ];
  };
}
