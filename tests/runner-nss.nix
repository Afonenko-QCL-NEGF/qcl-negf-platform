{ nixpkgs }:
let
  lib = import (builtins.toPath nixpkgs + "/lib");
  evaluate = routing: import (builtins.toPath nixpkgs + "/nixos/lib/eval-config.nix") {
    system = "x86_64-linux";
    modules = [ ../modules ../modules/image.nix {
      qclNegf.privateInterface = "cluster0";
      qclNegf.runner = { enable = true; inherit routing; };
    } ];
  };
  disabled = (evaluate {}).config;
  enabled = (evaluate {
    hostsFile = "/run/site-runner-routing/hosts";
    nsswitchFile = "/run/site-runner-routing/nsswitch.conf";
    units = [ "site-runner-routing.service" ];
  }).config;
  oldService = disabled.systemd.services.github-runner-qcl-negf;
  service = enabled.systemd.services.github-runner-qcl-negf;
  valid = c: builtins.all (a: a.assertion) c.assertions;
  invalid = routing: !(valid (evaluate routing).config);
in
assert valid disabled;
assert valid enabled;
assert !(builtins.elem "-/run/nscd" oldService.serviceConfig.InaccessiblePaths);
assert (oldService.serviceConfig.BindReadOnlyPaths or []) == [];
assert oldService.unitConfig.RequiresMountsFor == "/run/secrets/github-runners";
assert builtins.elem "/run/site-runner-routing/hosts:/etc/hosts" service.serviceConfig.BindReadOnlyPaths;
assert builtins.elem "/run/site-runner-routing/nsswitch.conf:/etc/nsswitch.conf" service.serviceConfig.BindReadOnlyPaths;
assert builtins.elem "-/run/nscd" service.serviceConfig.InaccessiblePaths;
assert builtins.all (v: builtins.elem v service.serviceConfig.InaccessiblePaths) oldService.serviceConfig.InaccessiblePaths;
assert builtins.elem "site-runner-routing.service" service.requires;
assert builtins.elem "site-runner-routing.service" service.after;
assert builtins.elem "/run/site-runner-routing/hosts" service.unitConfig.RequiresMountsFor;
assert builtins.elem "/run/site-runner-routing/nsswitch.conf" service.unitConfig.RequiresMountsFor;
assert service.serviceConfig.DynamicUser == oldService.serviceConfig.DynamicUser;
assert service.serviceConfig.Slice == oldService.serviceConfig.Slice;
assert service.serviceConfig.ReadWritePaths == oldService.serviceConfig.ReadWritePaths;
assert service.serviceConfig.SupplementaryGroups == [];
assert invalid { hostsFile = "/run/site/hosts"; };
assert invalid { nsswitchFile = "/run/site/nsswitch.conf"; };
assert invalid { hostsFile = "relative/hosts"; nsswitchFile = "/run/site/nsswitch.conf"; };
assert invalid { hostsFile = "/nix/store/hosts"; nsswitchFile = "/run/site/nsswitch.conf"; };
assert invalid { hostsFile = "/run/site/../hosts"; nsswitchFile = "/run/site/nsswitch.conf"; };
assert invalid { hostsFile = "/run/site/hosts:alias"; nsswitchFile = "/run/site/nsswitch.conf"; };
assert invalid { hostsFile = "/run/site/%n"; nsswitchFile = "/run/site/nsswitch.conf"; };
{
  disabledUnchanged = true;
  enabledNamespaceRouting = true;
  missingPairRejected = true;
  ambiguousOrStorePathsRejected = true;
}
