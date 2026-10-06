# Pure Nix evaluation checks for deployment boundaries; no hypervisor access.
{ nixpkgs, platform }:
let
  mk = extra: nixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [ platform.nixosModules.default platform.nixosModules.image
      { qclNegf.privateInterface = "cluster0"; }
    ] ++ extra;
  };
  storage = mk [{ qclNegf.storage = { enable = true; clients = [ "control" "worker" ]; }; }];
  worker = mk [{ qclNegf.cluster = {
    worker = true; storageHost = "storage";
    nodes = [ "worker CPUs=12 RealMemory=28672 State=UNKNOWN" ];
    partitions = [ "compute Nodes=worker Default=YES State=UP" ];
    scratchDevice = "/dev/disk/by-id/virtio-qcl-scratch";
  }; }];
  ci = mk [{ qclNegf.runner.enable = true; }];
  ciSubmit = mk [{
    qclNegf.runner.enable = true;
    qclNegf.cluster = {
      submit = true;
      nodes = [ "worker CPUs=1 RealMemory=1024 State=UNKNOWN" ];
      partitions = [ "compute Nodes=worker Default=YES State=UP" ];
    };
  }];
  ciStorage = mk [{
    qclNegf.runner.enable = true;
    qclNegf.storage = { enable = true; clients = [ "192.0.2.11" ]; };
  }];
  rejected = host: !(builtins.tryEval host.config.system.build.toplevel.drvPath).success;
in assert storage.config.fileSystems."/srv/qcl-negf".autoFormat == false;
   assert !storage.config.services.slurm.server.enable;
   assert worker.config.fileSystems."/srv/qcl-negf/jobs".device == "storage:/srv/qcl-negf/jobs";
   assert worker.config.fileSystems."/scratch".autoFormat == false;
   assert !worker.config.services.nfs.server.enable;
   assert ci.config.qclNegf.runner.repositories == [ "qcl-negf" ];
   assert !ci.config.services.nfs.server.enable;
   assert !(ci.config.fileSystems ? "/srv/qcl-negf/jobs");
   assert rejected ciSubmit;
   assert rejected ciStorage;
   {
     storage = storage.config.system.build.toplevel.drvPath;
     worker = worker.config.system.build.toplevel.drvPath;
     ci = ci.config.system.build.toplevel.drvPath;
   }
