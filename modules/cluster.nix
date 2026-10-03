{ config, lib, pkgs, ... }:
let cfg = config.qclNegf.cluster;
    active = cfg.controller || cfg.worker || cfg.submit;
in {
  options.qclNegf.cluster = {
    controller = lib.mkEnableOption "Slurm controller";
    worker = lib.mkEnableOption "Slurm compute daemon";
    submit = lib.mkEnableOption "Slurm submission tools";
    controllerHost = lib.mkOption { type = lib.types.str; default = "control"; description = "Resolvable short hostname of Slurm controller."; };
    nodes = lib.mkOption { type = lib.types.listOf lib.types.str; default = []; description = "Slurm NodeName lines, including measured CPU and RAM limits."; };
    partitions = lib.mkOption { type = lib.types.listOf lib.types.str; default = []; description = "Slurm PartitionName lines."; };
    srunPortRange = lib.mkOption {
      type = lib.types.submodule {
        options = {
          from = lib.mkOption { type = lib.types.port; };
          to = lib.mkOption { type = lib.types.port; };
        };
      };
      default = { from = 60001; to = 60128; };
      description = "Bounded TCP callback listeners for srun on the private cluster interface. Use the same range on every role; allow at least five ports and size for concurrent steps (four ports per srun up to 48 hosts, one extra with --pty).";
    };
    mungeKeyFile = lib.mkOption { type = lib.types.str; default = "/run/secrets/munge.key"; description = "Runtime path to identical Munge key, owned by munge, mode0400; never a Nix path literal."; };
    jobDirectory = lib.mkOption { type = lib.types.str; default = "/srv/qcl-negf/jobs"; description = "Shared Slurm working directory; identical absolute path on all nodes."; };
    storageHost = lib.mkOption { type = lib.types.str; default = "storage"; description = "Dedicated primary NFS server reachable on the cluster network."; };
    scratchDevice = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; description = "Stable ID of the worker-local scratch disk; separate from OS and shared storage."; };
    initializeBlankScratch = lib.mkOption { type = lib.types.bool; default = false; description = "Explicit first-install formatting permission for a blank scratch disk."; };
    solverPackage = lib.mkOption { type = lib.types.nullOr lib.types.package; default = null; description = "Solver package installed identically on submit and compute hosts."; };
  };
  config = lib.mkMerge [
    (lib.mkIf active {
      qclNegf.enable = true;
      assertions = [
        { assertion = cfg.nodes != []; message = "Supply measured Slurm node resources."; }
        { assertion = cfg.partitions != []; message = "Declare a Slurm partition."; }
        { assertion = lib.hasPrefix "/" cfg.mungeKeyFile && !(lib.hasPrefix "/nix/store/" cfg.mungeKeyFile); message = "Munge secret must be a runtime absolute path outside the store."; }
        { assertion = cfg.srunPortRange.from >= 1024 && cfg.srunPortRange.to - cfg.srunPortRange.from >= 4; message = "srun requires at least five unprivileged callback ports in ascending order."; }
        { assertion = cfg.srunPortRange.to < 6817 || cfg.srunPortRange.from > 6818; message = "srun callback ports must not overlap Slurm daemon ports 6817/6818."; }
      ];
      services.munge.password = cfg.mungeKeyFile;
      systemd.services.munged = {
        requires = config.qclNegf.runtimeSecretUnits;
        after = config.qclNegf.runtimeSecretUnits;
        unitConfig.RequiresMountsFor = cfg.mungeKeyFile;
      };
      services.slurm = {
        server.enable = cfg.controller;
        client.enable = cfg.worker;
        enableStools = cfg.submit;
        clusterName = "qcl-negf";
        controlMachine = cfg.controllerHost;
        nodeName = cfg.nodes;
        partitionName = cfg.partitions;
        procTrackType = "proctrack/cgroup";
        extraConfig = ''
          AuthType=auth/munge
          SlurmctldPort=6817
          SlurmdPort=6818
          SrunPortRange=${toString cfg.srunPortRange.from}-${toString cfg.srunPortRange.to}
          SelectType=select/cons_tres
          SelectTypeParameters=CR_Core_Memory
          SchedulerType=sched/backfill
          TaskPlugin=task/cgroup,task/affinity
          ReturnToService=0
          JobRequeue=0
          JobAcctGatherType=jobacct_gather/cgroup
          JobAcctGatherFrequency=30
          DefMemPerCPU=1024
          SlurmdSpoolDir=/var/spool/slurmd
        '';
        extraCgroupConfig = ''
          CgroupPlugin=cgroup/v2
          ConstrainCores=yes
          ConstrainRAMSpace=yes
          ConstrainSwapSpace=yes
        '';
      };
      environment.variables = {
        OPENBLAS_NUM_THREADS = "1"; OMP_NUM_THREADS = "1"; MKL_NUM_THREADS = "1";
      };
      environment.systemPackages = lib.optional (cfg.solverPackage != null) cfg.solverPackage;
      # slurmstepd connects back to srun, including steps started inside a batch
      # allocation on a worker. No public/global or ephemeral-range opening.
      networking.firewall.interfaces.${config.qclNegf.privateInterface} = {
        allowedTCPPorts = lib.optional cfg.controller 6817 ++ lib.optional cfg.worker 6818;
        allowedTCPPortRanges = [ cfg.srunPortRange ];
      };
    })
    (lib.mkIf active {
      fileSystems.${cfg.jobDirectory} = {
        device = "${cfg.storageHost}:/srv/qcl-negf/jobs";
        fsType = "nfs4";
        options = [ "hard" "_netdev" "x-systemd.automount" ];
      };
    })
    (lib.mkIf cfg.worker {
      assertions = [
        { assertion = cfg.scratchDevice != null; message = "Compute workers require an explicit local scratch disk."; }
        { assertion = cfg.scratchDevice != null && (lib.hasPrefix "/dev/disk/by-id/" cfg.scratchDevice || lib.hasPrefix "/dev/disk/by-uuid/" cfg.scratchDevice); message = "Scratch requires a stable non-root disk identifier."; }
      ];
      fileSystems."/scratch" = { device = cfg.scratchDevice; fsType = "ext4"; autoFormat = cfg.initializeBlankScratch; options = [ "noatime" ]; };
      systemd.services.qcl-negf-scratch-directories = {
        requiredBy = [ "slurmd.service" ]; before = [ "slurmd.service" ];
        unitConfig.RequiresMountsFor = "/scratch";
        serviceConfig = { Type = "oneshot"; RemainAfterExit = true; };
        script = ''
          if [ "$(stat -c %d /scratch)" = "$(stat -c %d /)" ]; then
            echo "Refusing to run scientific scratch on the root filesystem" >&2
            exit 1
          fi
          install -d -o qcl-negf -g qcl-negf -m 0700 /scratch/qcl-negf
        '';
      };
      systemd.services.slurmd = {
        requires = [ "munged.service" ];
        after = [ "munged.service" ];
        unitConfig.RequiresMountsFor = [ cfg.jobDirectory "/scratch" ];
      };
    })
  ];
}
