# Common replaceable root image. No site credentials or application data are baked in.
{ lib, modulesPath, ... }: {
  imports = [ (modulesPath + "/profiles/qemu-guest.nix") ];
  boot.loader.grub = { enable = true; device = "/dev/vda"; };
  boot.kernelParams = [ "console=ttyS0,115200n8" ];
  fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; autoResize = true; };
  services.qemuGuest.enable = true;
  services.cloud-init = {
    enable = true;
    network.enable = true;
    settings = {
      datasource_list = [ "NoCloud" "ConfigDrive" ];
      users = [ "root" ];
      disable_root = false;
      ssh_pwauth = false;
      growpart = { mode = "auto"; devices = [ "/" ]; ignore_growroot_disabled = true; };
      resize_rootfs = true;
    };
  };
  services.openssh = {
    enable = true;
    settings = { PasswordAuthentication = false; KbdInteractiveAuthentication = false; PermitRootLogin = "prohibit-password"; };
  };
  networking.useDHCP = lib.mkDefault false;
  networking.dhcpcd.enable = false;
  system.stateVersion = "26.05";
}
