{ pkgs, module }:
pkgs.testers.runNixOSTest {
  name = "qcl-negf-slurm-dedicated-storage";
  nodes = let
    shared = { lib, ... }: {
      imports = [ module ];
      qclNegf.privateInterface = "eth1";
      qclNegf.cluster = {
        controllerHost = "control"; storageHost = "storage";
        nodes = [ "worker CPUs=2 RealMemory=900 State=UNKNOWN" ];
        partitions = [ "compute Nodes=worker Default=YES MaxTime=00:10:00 State=UP" ];
      };
      virtualisation = { cores = 2; memorySize = 1536; };
      # Isolated test VMs only: a public test key, never deployment credentials.
      systemd.tmpfiles.rules = [
        "d /run/secrets 0755 root root -"
        "f /run/secrets/munge.key 0400 munge munge - ${lib.concatStrings (lib.replicate 16 "test-key-")}"
      ];
    };
  in {
    storage = { ... }: {
      imports = [ module ];
      qclNegf.privateInterface = "eth1";
      qclNegf.storage = { enable = true; clients = [ "control" "worker" ]; initializeBlankDisk = true; };
      virtualisation = {
        memorySize = 1024;
        emptyDiskImages = [{ size = 256; driveConfig.deviceExtraOpts.serial = "qcl-data"; }];
      };
    };
    control = { ... }: { imports = [ shared ]; qclNegf.cluster = { controller = true; submit = true; }; };
    worker = { ... }: {
      imports = [ shared ];
      qclNegf.cluster = { worker = true; scratchDevice = "/dev/disk/by-id/virtio-qcl-scratch"; initializeBlankScratch = true; };
      virtualisation.emptyDiskImages = [{ size = 256; driveConfig.deviceExtraOpts.serial = "qcl-scratch"; }];
    };
  };
  testScript = ''
    start_all()
    storage.wait_for_unit("nfs-server.service")
    control.wait_for_unit("slurmctld.service")
    worker.wait_for_unit("slurmd.service")
    control.wait_until_succeeds("sinfo -h -o %T | grep -Fx idle")
    control.succeed("su -s /bin/sh qcl-negf -c 'cd /srv/qcl-negf/jobs && sbatch --wait --output=smoke.txt --wrap=hostname'")
    control.succeed("su -s /bin/sh qcl-negf -c 'grep -Fx worker /srv/qcl-negf/jobs/smoke.txt'")
    storage.succeed("test $(stat -c %u /srv/qcl-negf/jobs/smoke.txt) = 3000")
    worker.succeed("su -s /bin/sh qcl-negf -c 'touch /scratch/qcl-negf/local-only'")
    control.fail("test -e /srv/qcl-negf/jobs/local-only")
    storage.succeed("findmnt -n -o SOURCE /srv/qcl-negf | grep -v '/dev/vda'")
    worker.succeed("test -f /sys/fs/cgroup/cgroup.controllers")
    # Data lives outside the controller: reboot it, then read the completed job.
    control.shutdown()
    control.start()
    control.wait_for_unit("slurmctld.service")
    control.succeed("su -s /bin/sh qcl-negf -c 'grep -Fx worker /srv/qcl-negf/jobs/smoke.txt'")
  '';
}
