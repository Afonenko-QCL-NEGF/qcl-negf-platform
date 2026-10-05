# Real locked NixOS module configuration, no image build or daemon start.
{ nixpkgs, platform }:
let
  lib = nixpkgs.lib;
  host = name: (lib.nixosSystem {
    system = "x86_64-linux";
    modules = [ platform.nixosModules.default platform.nixosModules.image
      ../../examples/private-site/production.nix.example
      { networking.hostName = name; qclNegf.privateInterface = "cluster0"; }
    ];
  }).config;
  network = name: let
    config = host name;
    text = config.systemd.network.units."40-cluster0.network".text;
  in
    assert config.networking.defaultGateway.interface == "cluster0";
    assert lib.hasInfix "Name=cluster0" text;
    assert lib.hasInfix "Gateway=" text;
    assert !config.services.cloud-init.network.enable;
    assert builtins.all (a: a.assertion) config.assertions;
    true;
  control = host "control";
  context = builtins.getContext control.systemd.services.nginx.serviceConfig.ExecStart;
  targets = builtins.filter (drv: builtins.match ".*-nginx[.]conf[.]drv" drv != null) (builtins.attrNames context);
in
assert builtins.all network [ "storage" "control" "compute" "ci" ];
assert control.services.nginx.validateConfigFile;
assert control.services.nginx.recommendedProxySettings;
assert builtins.length targets == 1;
assert context.${builtins.head targets}.outputs == [ "out" ];
assert !(lib.hasInfix "$http_host" control.services.nginx.virtualHosts."control.example.org".locations."/".extraConfig);
assert control.services.nginx.virtualHosts."control.example.org".forceSSL;
assert control.services.nginx.virtualHosts."control.example.org".locations."/".proxyPass == "http://127.0.0.1:8080";
true
