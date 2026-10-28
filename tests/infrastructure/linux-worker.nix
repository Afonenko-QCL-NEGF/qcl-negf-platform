# Synthetic module evaluation only: no build, boot, secret bytes or host API.
{ nixpkgs, variant ? "valid" }:
let
  lib = import (nixpkgs + "/lib");
  host = import (nixpkgs + "/nixos/lib/eval-config.nix") {
    system = if variant == "wrong-architecture" then "aarch64-linux" else "x86_64-linux";
    modules = [ ../../modules/linux-worker.nix (if variant == "example" then ({ pkgs, ... }: {
      imports = [ (import ../../examples/linux-worker/worker.nix.example {
        application = pkgs.hello; solver = pkgs.hello;
      }) ];
    }) else ({ pkgs, ... }: {
      networking.hostName = "arch-worker";
      qclNegf = {
        runtimeSecretUnits = if variant == "missing-secret-unit" then [] else [ "site-munge.service" ];
        cluster = {
          controller = variant == "controller";
          submit = variant == "submit";
          nodes = [ "arch-worker CPUs=2 RealMemory=3072 State=DRAIN" ];
          partitions = [ "compute Nodes=arch-worker Default=YES State=UP" ];
          solverPackage = pkgs.hello;
        };
        release = {
          applicationPackage = pkgs.hello;
          enable = variant != "disabled-release";
        };
      };
    })) ];
  };
  c = host.config;
in {
  failures = map (a: a.message) (builtins.filter (a: !a.assertion) c.assertions);
  architecture = host.pkgs.stdenv.hostPlatform.system;
  worker = c.qclNegf.cluster.worker;
  controller = c.qclNegf.cluster.controller;
  submit = c.qclNegf.cluster.submit;
  privateInterface = c.qclNegf.privateInterface;
  scratch = c.fileSystems."/scratch";
  root = c.fileSystems."/".device;
  nfs = c.fileSystems."/srv/qcl-negf/jobs".device;
  boot = { inherit (c.boot.initrd) kernelModules availableKernelModules; inherit (c.boot.loader.grub) device; };
  cloudInit = c.services.cloud-init.settings;
  cloudInitNetwork = c.services.cloud-init.network.enable;
  guestAgent = c.services.qemuGuest.enable;
  munge = { path = c.services.munge.password; requires = c.systemd.services.munged.requires; };
  guard = c.systemd.services.slurmd.serviceConfig.ExecStartPre or null;
  firewall = c.networking.firewall.interfaces.cluster0;
  ports = c.qclNegf.cluster.srunPortRange;
  sshPassword = c.services.openssh.settings.PasswordAuthentication;
}
