# Opt-in production Linux/libvirt guest profile. Site values and runtime secret
# provisioning belong to a private site; this module contains no credential bytes.
{ config, lib, pkgs, ... }: {
  imports = [ ./default.nix ./image.nix ];
  qclNegf = {
    privateInterface = lib.mkDefault "cluster0";
    cluster = {
      worker = lib.mkDefault true;
      scratchDevice = lib.mkDefault "/dev/disk/by-id/virtio-qcl-scratch";
      initializeBlankScratch = lib.mkDefault false;
    };
  };
  assertions = [
    { assertion = pkgs.stdenv.hostPlatform.system == "x86_64-linux";
      message = "Linux/libvirt worker profile currently supports x86_64-linux only."; }
    { assertion = config.qclNegf.cluster.worker && !(config.qclNegf.cluster.controller
        || config.qclNegf.cluster.submit || config.qclNegf.storage.enable || config.qclNegf.runner.enable);
      message = "Linux worker profile must not enable controller, submit, storage or CI roles."; }
    { assertion = config.qclNegf.release.enable;
      message = "Linux worker profile requires the ordinary release admission guard."; }
    { assertion = config.qclNegf.runtimeSecretUnits != [];
      message = "Linux worker profile requires explicit runtime secret provisioning units."; }
  ];
  # image.nix imports the locked Nixpkgs QEMU guest profile, including
  # virtio_balloon. Provisioning the device/driver is not dynamic qualification.
}
