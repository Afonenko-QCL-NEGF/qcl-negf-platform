# Evaluate real pinned NixOS units without building or starting any daemon.
{ nixpkgs, platform }:
let
  lib = nixpkgs.lib;
  mk = role: lib.nixosSystem {
    system = "x86_64-linux";
    modules = [ platform.nixosModules.default ({ pkgs, ... }: {
      system.stateVersion = "26.05";
      qclNegf.runtimeSecretUnits = [ "site-runtime-secrets.service" ];
      qclNegf.cluster = {
        controller = role == "controller";
        worker = role == "worker";
        submit = role == "submit";
        nodes = [ "worker CPUs=1 RealMemory=1024 State=UNKNOWN" ];
        partitions = [ "compute Nodes=worker Default=YES State=UP" ];
        scratchDevice = if role == "worker" then "/dev/disk/by-id/virtio-qcl-scratch" else null;
        mungeKeyFile = "/run/secrets/test-munge.key";
      };
      # Only the merged service configuration is evaluated. No application
      # package, solver, PostgreSQL, Munge or Slurm process is built or run.
      qclNegf.application = {
        enable = role != "worker";
        package = pkgs.hello;
      };
      systemd.services.site-runtime-secrets.serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.coreutils}/bin/true";
      };
    }) ];
  };
  roles = [ "controller" "worker" "submit" ];
  checked = map (role: let
    config = (mk role).config;
    units = config.systemd.services;
    daemon = units.munged;
    consumer = if role == "worker" then units.slurmd else units.qcl-negf-aiida;
  in
    assert config.services.munge.enable;
    assert !(units ? munge);
    assert lib.hasInfix "/bin/munged " daemon.serviceConfig.ExecStart;
    assert lib.hasInfix "/run/secrets/test-munge.key" daemon.serviceConfig.ExecStart;
    assert lib.elem "site-runtime-secrets.service" daemon.requires;
    assert lib.elem "site-runtime-secrets.service" daemon.after;
    assert daemon.unitConfig.RequiresMountsFor == "/run/secrets/test-munge.key";
    assert lib.elem "munged.service" consumer.requires;
    assert lib.elem "munged.service" consumer.after;
    { inherit role; daemon = "munged.service"; }
  ) roles;
in builtins.deepSeq checked { inherit checked; }
