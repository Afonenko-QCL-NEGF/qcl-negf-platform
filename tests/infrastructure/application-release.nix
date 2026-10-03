# Evaluate the actual merged services and Slurm gates, without a VM or a build.
{ nixpkgs }:
let
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  lib = pkgs.lib;
  make = role: import (nixpkgs + "/nixos/lib/eval-config.nix") {
    system = "x86_64-linux";
    modules = [ ../../modules ({ ... }: {
      system.stateVersion = "26.05";
      qclNegf.cluster = {
        controller = role == "controller";
        submit = role == "controller";
        worker = role == "worker";
        solverPackage = pkgs.hello;
        scratchDevice = if role == "worker" then "/dev/disk/by-id/virtio-qcl-scratch" else null;
        nodes = [ "worker CPUs=1 RealMemory=1024 State=UNKNOWN" ];
        partitions = [ "compute Nodes=worker Default=YES State=UP" ];
      };
      qclNegf.application = {
        enable = role == "controller";
        package = pkgs.hello;
        api.enable = role == "controller";
      };
      qclNegf.release.applicationPackage = pkgs.hello;
    }) ];
  };
  controller = (make "controller").config;
  worker = (make "worker").config;
in
assert controller.qclNegf.release.enable;
assert worker.qclNegf.release.enable;
assert lib.hasPrefix "/nix/var/nix/profiles/qcl-negf-application/bin/verdi " controller.systemd.services.qcl-negf-aiida.serviceConfig.ExecStart;
assert controller.systemd.services.qcl-negf-aiida.serviceConfig.EnvironmentFile == "-/var/lib/qcl-negf/runtime/service.env";
assert lib.hasInfix "qcl-negf-release node-check" worker.systemd.services.slurmd.serviceConfig.ExecStartPre;
assert lib.hasInfix "ReturnToService=0" worker.services.slurm.extraConfig;
assert lib.hasInfix "JobRequeue=0" worker.services.slurm.extraConfig;
assert lib.elem "qcl-negf-application-profile.service" controller.systemd.services.qcl-negf-aiida.requires;
{
  controllerStart = controller.systemd.services.qcl-negf-aiida.serviceConfig.ExecStart;
  workerGate = worker.systemd.services.slurmd.serviceConfig.ExecStartPre;
  profileInit = controller.systemd.services.qcl-negf-application-profile.unitConfig.ConditionPathExists;
}
