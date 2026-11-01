# Opt-in: importing the ordinary platform module never enables this authority.
{ config, lib, pkgs, ... }:
let
  cfg = config.qclNegf.hostResources;
  package = import ../nix/host-resources.nix { inherit pkgs; };
  command = role: "${package}/bin/qcl-negf-resource-${role}";
in {
  options.qclNegf.hostResources = {
    enable = lib.mkEnableOption "native resource demand/facts helpers (private preparation required)";
    clientUser = lib.mkOption { type = lib.types.str; default = "qcl-negf"; };
    authorityUser = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; };
    factsUser = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; };
    authorityKeysFile = lib.mkOption { type = lib.types.str; default = "/etc/ssh/qcl-negf-resource/authority.authorized_keys"; };
    factsKeysFile = lib.mkOption { type = lib.types.str; default = "/etc/ssh/qcl-negf-resource/facts.authorized_keys"; };
  };
  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ package ];
    systemd.tmpfiles.rules = [
      "d /etc/qcl-negf/host-resources 0700 root root -"
      "d /var/lib/qcl-negf/host-resources 0700 root root -"
      "d /etc/ssh/qcl-negf-resource 0755 root root -"
    ];
    security.sudo.extraRules = [ {
      users = [ cfg.clientUser ];
      commands = [ { command = command "client-root"; options = [ "NOPASSWD" ]; } ];
    } ] ++ lib.optional (cfg.authorityUser != null) {
      users = [ cfg.authorityUser ];
      commands = [ { command = command "authority"; options = [ "NOPASSWD" ]; } ];
    } ++ lib.optional (cfg.factsUser != null) {
      users = [ cfg.factsUser ];
      commands = [ { command = command "facts"; options = [ "NOPASSWD" ]; } ];
    };
    services.openssh.settings.PermitUserEnvironment = false;
    services.openssh.extraConfig = lib.concatStringsSep "\n" (map (role:
      let user = if role == "authority" then cfg.authorityUser else cfg.factsUser;
          keys = if role == "authority" then cfg.authorityKeysFile else cfg.factsKeysFile;
      in lib.optionalString (user != null) ''
        Match User ${if user == null then "unused" else user}
          AuthenticationMethods publickey
          AuthorizedKeysFile ${keys}
          ForceCommand ${command "ssh-${role}"}
          PasswordAuthentication no
          KbdInteractiveAuthentication no
          AllowTcpForwarding no
          X11Forwarding no
          PermitTTY no
          PermitTunnel no
        Match all
      '') [ "authority" "facts" ]);
    # No daemon, autostart, qualification, slurmd resume, or launch wiring. These
    # helpers are invoked synchronously after private runtime config preparation.
    assertions = [ {
      assertion = (cfg.authorityUser == null || (cfg.authorityUser != cfg.clientUser && cfg.authorityUser != cfg.factsUser))
        && (cfg.factsUser == null || cfg.factsUser != cfg.clientUser);
      message = "Resource authority/facts/client accounts must be separate.";
    } {
      assertion = builtins.all (user: user == null || (user != "root" && builtins.match "[a-z_][a-z0-9_-]*" user != null)) [ cfg.clientUser cfg.authorityUser cfg.factsUser ];
      message = "Resource transport identities require distinct non-root native account names.";
    } {
      assertion = builtins.all (path: lib.hasPrefix "/" path && !(lib.hasPrefix "/nix/store/" path)
        && builtins.match "/[A-Za-z0-9_./-]+" path != null && !(lib.hasInfix "/../" path)) [ cfg.authorityKeysFile cfg.factsKeysFile ];
      message = "Resource transport public keys are protected runtime files outside the store.";
    } ];
  };
}
