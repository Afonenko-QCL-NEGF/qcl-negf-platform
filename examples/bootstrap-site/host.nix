{ lib, pkgs, modulesPath, ... }: {
  imports = [ (modulesPath + "/profiles/qemu-guest.nix") ];
  networking.hostName = "ci";
  qclNegf = {
    enable = true;
    privateInterface = "ens18";
    runner.enable = lib.mkDefault false;
    builder = { enable = true; profile = lib.mkDefault "standard"; };
  };
  # Build capability does not depend on GitHub registration or production secrets.
  programs.nix-ld.enable = true;
  environment.systemPackages = with pkgs; [
    git deno uv python314 nodejs_24 gcc gnumake opentofu ansible
  ];
  services.qemuGuest.enable = true;
  services.openssh.settings.PermitRootLogin = "prohibit-password";
  system.stateVersion = "26.05";
}
