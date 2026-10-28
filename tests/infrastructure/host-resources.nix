# Source evaluation only: no build, installation, unit start or native backend.
{ nixpkgs }:
let
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  eval = enabled: extra: import (nixpkgs + "/nixos/lib/eval-config.nix") {
    system = "x86_64-linux";
    modules = [ ../../modules/host-resources.nix {
      system.stateVersion = "26.05";
      qclNegf.hostResources.enable = enabled;
    } extra ];
  };
  off = (eval false {}).config;
  on = (eval true {}).config;
  roles = (eval true {
    qclNegf.hostResources.authorityUser = "qcl-resource-authority";
    qclNegf.hostResources.factsUser = "qcl-resource-facts";
  }).config;
  package = import ../../nix/host-resources.nix { inherit pkgs; };
  outputs = (import ../../flake.nix).outputs {
    self = {}; nixpkgs = { lib = pkgs.lib; legacyPackages.x86_64-linux = pkgs; };
    pyproject-nix = {}; uv2nix = {}; pyproject-build-systems = {};
  };
  rules = builtins.filter (rule: rule.users == [ "qcl-negf" ]) on.security.sudo.extraRules;
in assert builtins.isFunction outputs.nixosModules.hostResources;
assert outputs.packages.x86_64-linux.hostResources.name == "qcl-negf-host-resources";
assert off.environment.systemPackages != on.environment.systemPackages;
assert builtins.length rules == 1;
assert (builtins.head rules).users == [ "qcl-negf" ];
assert builtins.length (builtins.head rules).commands == 1;
assert pkgs.lib.hasSuffix "/bin/qcl-negf-resource-client-root" (builtins.head (builtins.head rules).commands).command;
assert !(builtins.hasAttr "qcl-resource" on.systemd.services);
assert on.qclNegf.hostResources.authorityUser == null;
assert on.qclNegf.hostResources.factsUser == null;
assert pkgs.lib.hasInfix (builtins.unsafeDiscardStringContext "ForceCommand ${package}/bin/qcl-negf-resource-ssh-authority") roles.services.openssh.extraConfig;
assert pkgs.lib.hasInfix (builtins.unsafeDiscardStringContext "ForceCommand ${package}/bin/qcl-negf-resource-ssh-facts") roles.services.openssh.extraConfig;
assert !(pkgs.lib.hasInfix (builtins.unsafeDiscardStringContext "ForceCommand ${package}/bin/qcl-negf-resource-client-root") roles.services.openssh.extraConfig);
assert builtins.length (builtins.filter (rule: builtins.elem "qcl-resource-authority" rule.users) roles.security.sudo.extraRules) == 1;
assert package.passthru.source != null;
true
