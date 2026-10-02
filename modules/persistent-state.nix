{ config, lib, ... }:
let cfg = config.qclNegf.stateDisk;
in {
  options.qclNegf.stateDisk = {
    enable = lib.mkEnableOption "separate persistent controller state disk";
    device = lib.mkOption { type = lib.types.str; default = "/dev/disk/by-id/virtio-qcl-state"; description = "Stable controller state disk ID."; };
    initializeBlankDisk = lib.mkOption { type = lib.types.bool; default = false; description = "Explicit initial formatting permission for an unformatted state disk."; };
  };
  config = lib.mkIf cfg.enable {
    assertions = [
      { assertion = config.qclNegf.cluster.controller; message = "Controller state disk belongs on the controller VM."; }
      { assertion = lib.hasPrefix "/dev/disk/by-id/" cfg.device || lib.hasPrefix "/dev/disk/by-uuid/" cfg.device; message = "Controller state requires a stable non-root disk identifier."; }
    ];
    fileSystems."/var/lib/qcl-negf-state" = { device = cfg.device; fsType = "ext4"; autoFormat = cfg.initializeBlankDisk; options = [ "noatime" ]; };
    fileSystems."/var/lib/qcl-negf" = { device = "/var/lib/qcl-negf-state/aiida"; fsType = "none"; options = [ "bind" "x-systemd.requires-mounts-for=/var/lib/qcl-negf-state" ]; };
    services.postgresql.dataDir = "/var/lib/qcl-negf-state/postgresql/${config.services.postgresql.package.psqlSchema}";
    services.slurm.stateSaveLocation = "/var/lib/qcl-negf-state/slurm";
    systemd.tmpfiles.rules = [ "d /var/lib/qcl-negf-state/aiida 0750 qcl-negf qcl-negf -" ];
    systemd.services.qcl-negf-state-directories = {
      requiredBy = [ "var-lib-qcl\\x2dnegf.mount" "slurmctld.service" ] ++ lib.optional config.services.postgresql.enable "postgresql.service";
      before = [ "var-lib-qcl\\x2dnegf.mount" ];
      unitConfig = { RequiresMountsFor = "/var/lib/qcl-negf-state"; DefaultDependencies = false; };
      serviceConfig = { Type = "oneshot"; RemainAfterExit = true; };
      script = ''
        if [ "$(stat -c %d /var/lib/qcl-negf-state)" = "$(stat -c %d /)" ]; then
          echo "Refusing to keep controller state on the root filesystem" >&2
          exit 1
        fi
        install -d -o qcl-negf -g qcl-negf -m 0750 /var/lib/qcl-negf-state/aiida
      '';
    };
    systemd.services.postgresql.unitConfig.RequiresMountsFor = "/var/lib/qcl-negf-state";
    systemd.services.slurmctld.unitConfig.RequiresMountsFor = "/var/lib/qcl-negf-state";
    systemd.services.qcl-negf-aiida.unitConfig.RequiresMountsFor = [ "/var/lib/qcl-negf" ];
    systemd.services.qcl-negf-api.unitConfig.RequiresMountsFor = [ "/var/lib/qcl-negf" ];
  };
}
