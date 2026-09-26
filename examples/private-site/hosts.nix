# Import this function from the private site flake, passing measured inventory and
# application/solver derivations exported by the pinned qcl-negf root repository.
{ nixpkgs, platform, site, application, solver }:
let
  shared = {
    qclNegf.privateInterface = "cluster0";
    qclNegf.cluster = {
      controllerHost = "control";
      storageHost = "storage";
      inherit (site.slurm) nodes partitions;
      solverPackage = solver;
    };
    networking.hosts = site.hosts;
  };
  make = name: modules: nixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [ platform.nixosModules.default (platform.outPath + "/modules/image.nix") shared
      { networking.hostName = name; } ] ++ modules;
  };
in {
  storage = make "storage" [{ qclNegf.storage = {
    enable = true; clients = site.storageClients;
    initializeBlankDisk = site.initializeBlankDisks;
  }; }];
  control = make "control" [{
    qclNegf.cluster = { controller = true; submit = true; };
    qclNegf.stateDisk = { enable = true; initializeBlankDisk = site.initializeBlankDisks; };
    qclNegf.application = { enable = true; package = application; api.enable = true; };
  }];
  compute = make "compute" [{ qclNegf.cluster = {
    worker = true; scratchDevice = "/dev/disk/by-id/virtio-qcl-scratch";
    initializeBlankScratch = site.initializeBlankDisks;
  }; }];
  arch-worker = make "arch-worker" [{ qclNegf.cluster = {
    worker = true; scratchDevice = "/dev/disk/by-id/virtio-qcl-scratch";
    initializeBlankScratch = site.initializeBlankDisks;
  }; }];
  ci = make "ci" [{ qclNegf.runner.enable = true; }];
}
