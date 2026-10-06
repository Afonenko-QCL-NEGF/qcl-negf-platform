# Caller supplies public configuration only; secret bytes never enter evaluation.
{ nixpkgs, platform, site, system ? "x86_64-linux" }:
let
  lib = nixpkgs.lib;
  application = site.application or null;
  solver = site.solver or null;
  shared = { pkgs, ... }: {
    imports = [ (platform.outPath + "/modules/image.nix") ];
    # One virtio NIC; disable predictable renaming in bootstrap and every role.
    boot.kernelParams = [ "net.ifnames=0" ];
    networking.interfaces.eth0.useDHCP = true;
    networking.hosts = site.hosts;
    users.users.root.openssh.authorizedKeys.keys = [ site.sshPublicKey ];
    environment.systemPackages = [ pkgs.python3 pkgs.util-linux pkgs.nfs-utils ];
    nix.settings.experimental-features = [ "nix-command" "flakes" ];
  };
  cluster = { config, pkgs, ... }: {
    qclNegf = {
      privateInterface = "eth0";
      authorizedKeys = [ site.sshPublicKey ];
      runtimeSecretUnits = [ "qcl-lab-runtime-secrets.service" ];
      cluster = { inherit (site) nodes partitions; solverPackage = solver; };
      release.applicationPackage = application;
    };
    systemd.services.qcl-lab-runtime-secrets = {
      description = "Load private persistent lab Munge key into runtime storage";
      requiredBy = [ "munged.service" ];
      before = [ "munged.service" ];
      serviceConfig = { Type = "oneshot"; RemainAfterExit = true; };
      script = ''
        set -eu
        test -s /var/lib/qcl-lab-secrets/munge.key
        install -d -m 0755 /run/secrets
        install -o munge -g munge -m 0400 /var/lib/qcl-lab-secrets/munge.key /run/secrets/munge.key
        ${lib.optionalString (application != null && config.qclNegf.cluster.controller && config.qclNegf.application.api.enable) ''
          test -s /var/lib/qcl-lab-secrets/api-token
          install -d -m 0755 ${lib.escapeShellArg (builtins.dirOf config.qclNegf.application.api.tokenFile)}
          install -o root -g root -m 0400 /var/lib/qcl-lab-secrets/api-token ${lib.escapeShellArg config.qclNegf.application.api.tokenFile}
        ''}
      '';
    };
  };
  make = name: extra: lib.nixosSystem {
    inherit system;
    modules = [ platform.nixosModules.default shared { networking.hostName = name; } ] ++ extra;
  };
  initialize = site.initializeBlankDisks or false;
  configurations = {
    storage = make "storage" [{
      qclNegf.privateInterface = "eth0";
      qclNegf.storage = { enable = true; clients = builtins.attrNames site.hosts; initializeBlankDisk = initialize; };
    }];
    control = make "control" ([ cluster {
      qclNegf.cluster = { controller = true; submit = true; };
      qclNegf.stateDisk = { enable = true; initializeBlankDisk = initialize; };
    } ] ++ lib.optional (application != null) {
      qclNegf.application = {
        enable = true; package = application;
        api = {
          enable = true;
          maxCores = 2;
          maxMemoryKiB = 1792 * 1024;
          defaultMemoryKiB = 1024 * 1024;
          exportDiskBytes = 512 * 1024 * 1024;
        } // (site.api or {});
        bootstrap = { enable = true; email = site.serviceEmail; codeLabel = site.codeLabel or "qcl-local-lab"; };
      };
    });
    worker-1 = makeWorker "worker-1";
    worker-2 = makeWorker "worker-2";
  };
  # Optional application stage uses the owning application and release modules.
  # The ordinary release guard remains enabled when both packages are supplied.
  makeWorker = name: make name [ cluster {
    qclNegf.cluster = { worker = true; scratchDevice = "/dev/disk/by-id/virtio-qcl-scratch"; initializeBlankScratch = initialize; };
  } ];
  bootstrap = lib.nixosSystem {
    inherit system;
    modules = [ platform.nixosModules.default shared {
      networking.hostName = "qcl-lab-bootstrap";
      qclNegf.privateInterface = "eth0";
      system.extraDependencies = map (host: host.config.system.build.toplevel) (builtins.attrValues configurations);
    } ];
  };
in
assert (application == null) == (solver == null);
{
  inherit configurations bootstrap;
  systems = lib.mapAttrs (_: host: host.config.system.build.toplevel) configurations;
  image = import (nixpkgs.outPath + "/nixos/lib/make-disk-image.nix") {
    inherit (bootstrap) pkgs config;
    inherit lib;
    format = "qcow2";
    partitionTableType = "legacy";
    diskSize = "auto";
    additionalSpace = "512M";
    copyChannel = false;
    name = "qcl-local-lab-bootstrap";
  };
}
