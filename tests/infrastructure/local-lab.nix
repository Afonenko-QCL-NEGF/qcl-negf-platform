# Real module evaluation: no VM build or daemon start.
{ nixpkgs, platform }:
let
  lab = import ../../nix/local-lab.nix {
    inherit nixpkgs platform;
    site = {
      hosts = { "192.168.231.10" = [ "control" ]; "192.168.231.11" = [ "storage" ]; "192.168.231.21" = [ "worker-1" ]; "192.168.231.22" = [ "worker-2" ]; };
      nodes = [ "worker-[1-2] CPUs=2 RealMemory=2048 State=UNKNOWN" ];
      partitions = [ "compute Nodes=worker-[1-2] Default=YES State=UP" ];
      sshPublicKey = "ssh-ed25519 AAAATEST public-only";
      initializeBlankDisks = true;
    };
  };
  applicationLab = import ../../nix/local-lab.nix {
    inherit nixpkgs platform;
    site = {
      hosts = {};
      nodes = [ "worker-[1-2] CPUs=2 RealMemory=2048 State=UNKNOWN" ];
      partitions = [ "compute Nodes=worker-[1-2] Default=YES State=UP" ];
      sshPublicKey = "ssh-ed25519 AAAATEST public-only";
      application = lab.configurations.control.pkgs.hello;
      solver = lab.configurations.control.pkgs.hello;
      serviceEmail = "lab@example.invalid";
    };
  };
  appControl = applicationLab.configurations.control.config;
  appWorker = applicationLab.configurations.worker-1.config;
  control = lab.configurations.control.config;
  storage = lab.configurations.storage.config;
  worker = lab.configurations.worker-1.config;
  assertions = config: builtins.all (a: a.assertion) config.assertions;
in
assert builtins.attrNames lab.configurations == [ "control" "storage" "worker-1" "worker-2" ];
assert builtins.all (c: assertions c.config) (builtins.attrValues lab.configurations);
assert control.qclNegf.cluster.controller;
assert control.qclNegf.stateDisk.enable;
assert !control.qclNegf.application.enable;
assert storage.qclNegf.storage.enable && !storage.qclNegf.cluster.controller;
assert storage.fileSystems."/srv/qcl-negf".device == "/dev/disk/by-id/virtio-qcl-data";
assert worker.fileSystems."/scratch".device == "/dev/disk/by-id/virtio-qcl-scratch";
assert worker.users.users.qcl-negf.uid == 3000;
assert worker.qclNegf.privateInterface == "eth0";
assert worker.systemd.services.munged.requires == [ "qcl-lab-runtime-secrets.service" ];
assert builtins.length lab.bootstrap.config.system.extraDependencies == 4;
assert !lab.bootstrap.config.qclNegf.cluster.worker;
assert appControl.qclNegf.application.api.enable;
assert appControl.qclNegf.application.api.maxMemoryKiB == 1792 * 1024;
assert appControl.qclNegf.application.api.defaultMemoryKiB == 1024 * 1024;
assert appControl.qclNegf.release.enable && appWorker.qclNegf.release.enable;
assert builtins.match ".*node-check.*" appWorker.systemd.services.slurmd.serviceConfig.ExecStartPre != null;
assert lab.bootstrap.config.services.openssh.settings.PermitRootLogin == "prohibit-password";
true
