{ config, lib, ... }:
let cfg = config.qclNegf.cache;
in {
  options.qclNegf.cache = {
    enable = lib.mkEnableOption "Signed Nix binary cache";
    address = lib.mkOption { type = lib.types.str; default = "127.0.0.1"; description = "Bind address; expose through a private-network TLS proxy."; };
    port = lib.mkOption { type = lib.types.port; default = 5000; description = "Binary cache port."; };
    signingKeyFile = lib.mkOption { type = lib.types.str; default = "/run/secrets/nix-cache-key"; description = "Runtime signing key path; keep off job runners."; };
  };
  config = lib.mkIf cfg.enable {
    qclNegf.enable = true;
    assertions = [{ assertion = lib.hasPrefix "/" cfg.signingKeyFile && !(lib.hasPrefix "/nix/store/" cfg.signingKeyFile); message = "Cache signing key must be a runtime absolute path outside the store."; }];
    services.nix-serve = {
      enable = true; bindAddress = cfg.address; port = cfg.port;
      secretKeyFile = cfg.signingKeyFile;
    };
    systemd.services.nix-serve = {
      requires = config.qclNegf.runtimeSecretUnits;
      after = config.qclNegf.runtimeSecretUnits;
      unitConfig.RequiresMountsFor = cfg.signingKeyFile;
    };
  };
}
