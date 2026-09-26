{ config, lib, ... }:
let cfg = config.qclNegf.storage;
in {
  options.qclNegf.storage = {
    enable = lib.mkEnableOption "dedicated persistent NFS storage VM";
    device = lib.mkOption { type = lib.types.str; default = "/dev/disk/by-id/virtio-qcl-data"; description = "Stable ID of the separate persistent data disk."; };
    initializeBlankDisk = lib.mkOption { type = lib.types.bool; default = false; description = "Explicit first-install permission to format a disk without any blkid filesystem signature."; };
    clients = lib.mkOption { type = lib.types.listOf lib.types.str; default = []; description = "Explicit client IPs or private CIDRs allowed to mount NFS."; };
  };
  config = lib.mkIf cfg.enable {
    qclNegf.enable = true;
    assertions = [
      { assertion = cfg.clients != []; message = "Declare the private NFS client allowlist."; }
      { assertion = lib.hasPrefix "/dev/disk/by-id/" cfg.device || lib.hasPrefix "/dev/disk/by-uuid/" cfg.device; message = "Storage must use a persistent disk identifier, not the replaceable root device."; }
      { assertion = !(config.qclNegf.cluster.controller || config.qclNegf.cluster.worker || config.qclNegf.runner.enable); message = "The storage VM has a separate lifecycle from controller, worker and CI."; }
    ];
    fileSystems."/srv/qcl-negf" = {
      device = cfg.device; fsType = "ext4";
      autoFormat = cfg.initializeBlankDisk;
      options = [ "noatime" ];
    };
    services.nfs.server = {
      enable = true;
      exports = "/srv/qcl-negf/jobs " + lib.concatMapStringsSep " " (host: "${host}(rw,sync,no_subtree_check,root_squash)") cfg.clients;
    };
    services.nfs.settings.nfsd.vers3 = false;
    networking.firewall.interfaces.${config.qclNegf.privateInterface}.allowedTCPPorts = [ 2049 ];
    systemd.services.nfs-server.unitConfig.RequiresMountsFor = "/srv/qcl-negf";
    systemd.services.qcl-negf-storage-directories = {
      requiredBy = [ "nfs-server.service" ];
      before = [ "nfs-server.service" ];
      unitConfig.RequiresMountsFor = "/srv/qcl-negf";
      serviceConfig = { Type = "oneshot"; RemainAfterExit = true; };
      script = ''
        if [ "$(stat -c %d /srv/qcl-negf)" = "$(stat -c %d /)" ]; then
          echo "Refusing to export scientific data from the root filesystem" >&2
          exit 1
        fi
        install -d -o qcl-negf -g qcl-negf -m 0750 /srv/qcl-negf/jobs
      '';
    };
  };
}
