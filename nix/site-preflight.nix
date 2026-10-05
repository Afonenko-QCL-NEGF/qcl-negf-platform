# Unary function: `nix eval --file ... --apply 'f: f "/absolute/private-site"'`.
# Evaluate ALL role toplevels before the first expensive image/application build.
siteDir:
let
  site = builtins.getFlake siteDir;
  roles = [ "storage" "control" "compute" "ci" ];
  paths = builtins.listToAttrs (map (name: {
    inherit name;
    value = site.nixosConfigurations.${name}.config.system.build.toplevel.drvPath;
  }) roles);
  control = site.nixosConfigurations.control.config;
  context = builtins.getContext control.systemd.services.nginx.serviceConfig.ExecStart;
  targets = map (drv: assert context.${drv}.outputs == [ "out" ]; "${drv}^out")
    (builtins.filter (drv: builtins.match ".*-nginx[.]conf[.]drv" drv != null)
      (builtins.attrNames context));
  result = {
    roles = paths;
    nginx = {
      enabled = control.services.nginx.enable;
      validated = control.services.nginx.validateConfigFile;
      inherit targets;
    };
  };
in builtins.deepSeq result result
