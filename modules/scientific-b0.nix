# Explicit source candidate only; never enabled by cluster/runner defaults.
{ config, lib, ... }:
let
  cfg = config.qclNegf.scientificB0;
  runtimePath = path: builtins.match "/[^[:space:]]+" path != null
    && !(lib.hasPrefix "/nix/store/" path)
    && builtins.all (part: !(builtins.elem part [ "" "." ".." ]))
      (builtins.tail (lib.splitString "/" path));
in {
  options.qclNegf.scientificB0 = {
    enable = lib.mkEnableOption "reviewed fixed B0 privileged wrapper candidate";
    helperPackage = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = null;
      description = "Exact mkB0Helper output after separate native/HIGH/OPS qualification.";
    };
    admissionConfig = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Root provisioned runtime admission locator; no private data enters the store. M1 entry still refuses missing descriptor producer/B1/native attachment.";
    };
  };
  config = lib.mkIf cfg.enable {
    assertions = [
      { assertion = cfg.helperPackage != null; message = "B0 requires exact reviewed helper package."; }
      { assertion = cfg.admissionConfig != null && runtimePath cfg.admissionConfig;
        message = "B0 needs a canonical runtime admission path outside the Nix store."; }
      { assertion = !config.qclNegf.runner.enable;
        message = "Privileged scientific B0 wrapper must not be installed on CI builder."; }
    ];
    security.wrappers.qcl-b0-trampoline = {
      source = "${cfg.helperPackage}/bin/qcl-b0-trampoline";
      owner = "root";
      group = "root";
      permissions = "u+rx,g+x,o+x";
      setuid = true;
      setgid = false;
    };
  };
}
