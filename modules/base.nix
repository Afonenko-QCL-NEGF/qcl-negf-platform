{ config, lib, pkgs, ... }:
let cfg = config.qclNegf;
in {
  options.qclNegf = {
    enable = lib.mkEnableOption "QCL-NEGF host defaults";
    privateInterface = lib.mkOption { type = lib.types.str; description = "Interface on the private cluster network."; };
    uid = lib.mkOption { type = lib.types.int; default = 3000; description = "Identical service UID on all cluster nodes."; };
    authorizedKeys = lib.mkOption { type = lib.types.listOf lib.types.str; default = []; description = "SSH public keys for the scientific service account."; };
    runtimeSecretUnits = lib.mkOption { type = lib.types.listOf lib.types.str; default = []; description = "Private site units that provision runtime secrets before consuming services start."; };
  };
  config = lib.mkIf cfg.enable {
    nix.settings.experimental-features = [ "nix-command" "flakes" ];
    nix.settings.sandbox = true;
    nix.settings.auto-optimise-store = true;
    users.groups.qcl-negf.gid = cfg.uid;
    users.users.qcl-negf = {
      uid = cfg.uid; group = "qcl-negf"; isSystemUser = true;
      home = "/var/lib/qcl-negf"; createHome = true;
      shell = pkgs.bashInteractive;
      openssh.authorizedKeys.keys = cfg.authorizedKeys;
    };
    services.openssh.enable = true;
    services.openssh.settings = { PasswordAuthentication = false; KbdInteractiveAuthentication = false; };
    services.timesyncd.enable = lib.mkDefault true;
    environment.systemPackages = with pkgs; [ git deno nix-output-monitor ];
    systemd.tmpfiles.rules = [ "d /srv/qcl-negf 0750 qcl-negf qcl-negf -" ];
  };
}
