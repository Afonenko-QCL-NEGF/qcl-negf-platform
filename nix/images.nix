# The caller supplies the actual private site's already evaluated host configurations.
# Root images may be replaced independently of data/scratch disks attached by OpenTofu.
{ nixpkgs, configurations }:
nixpkgs.lib.mapAttrs (name: host:
  import (nixpkgs + "/nixos/lib/make-disk-image.nix") {
    inherit (host) pkgs config;
    lib = nixpkgs.lib;
    format = "qcow2";
    partitionTableType = "legacy";
    diskSize = "auto";
    additionalSpace = "2048M";
    copyChannel = false;
    name = "qcl-negf-${name}-root";
  }
) configurations
