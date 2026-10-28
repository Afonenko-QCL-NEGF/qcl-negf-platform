{ config, lib, pkgs, ... }:
let
  cfg = config.qclNegf.release;
  cluster = config.qclNegf.cluster;
  profile = "/nix/var/nix/profiles/qcl-negf-application";
  operations = pkgs.runCommand "qcl-negf-release-operations" {} ''
    mkdir -p "$out/ops"
    cp ${../ops/application_release.py} "$out/ops/application_release.py"
    cp ${../ops/delivery_requests.py} "$out/ops/delivery_requests.py"
    cp ${../ops/delivery_service.py} "$out/ops/delivery_service.py"
    cp ${../ops/release_identity.py} "$out/ops/release_identity.py"
    cp ${../ops/release_trust.py} "$out/ops/release_trust.py"
    cp ${../ops/release_qualification.py} "$out/ops/release_qualification.py"
    cp ${../ops/release_health.py} "$out/ops/release_health.py"
    cp ${../ops/worker_lifecycle.py} "$out/ops/worker_lifecycle.py"
    cp ${../ops/aiida_update_check.py} "$out/ops/aiida_update_check.py"
    cp ${../ops/register_aiida.py} "$out/ops/register_aiida.py"
  '';
  releaseCommand = pkgs.writeShellApplication {
    name = "qcl-negf-release";
    runtimeInputs = [ pkgs.nix pkgs.systemd pkgs.slurm pkgs.openssh pkgs.util-linux pkgs.coreutils pkgs.python314 ];
    text = ''
      export SLURM_CONF=${config.services.slurm.etcSlurm}/slurm.conf
      exec python3 ${operations}/ops/application_release.py "$@"
    '';
  };
  deliveryCommand = pkgs.writeShellApplication {
    name = "qcl-negf-delivery-service";
    runtimeInputs = [ pkgs.nix pkgs.systemd pkgs.slurm pkgs.openssh pkgs.util-linux pkgs.coreutils pkgs.python314 ];
    text = ''
      export SLURM_CONF=${config.services.slurm.etcSlurm}/slurm.conf
      exec python3 ${operations}/ops/delivery_service.py "$@"
    '';
  };
  lifecycleCommand = pkgs.writeShellApplication {
    name = "qcl-negf-worker-lifecycle";
    runtimeInputs = [ pkgs.nix pkgs.systemd pkgs.slurm pkgs.openssh pkgs.util-linux pkgs.python314 ];
    text = ''
      export SLURM_CONF=${config.services.slurm.etcSlurm}/slurm.conf
      exec python3 ${operations}/ops/worker_lifecycle.py "$@"
    '';
  };
in {
  options.qclNegf.release = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = cfg.applicationPackage != null && cluster.solverPackage != null && (cluster.controller || cluster.worker);
      description = "Application-only activation and closed release admission after one-time image preparation.";
    };
    applicationPackage = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = if config.qclNegf.application.enable then config.qclNegf.application.package else null;
      description = "Initial application closure; pass the same closure to all Linux workers, including Hyper-V guests.";
    };
  };
  config = lib.mkMerge [
    (lib.mkIf (cfg.applicationPackage != null) {
      # A GC-rooted application profile is provisioned once. Reboots retain the
      # selected release; routine CD never runs nixos-rebuild or changes the OS.
      systemd.services.qcl-negf-application-profile = {
        description = "Initialize the stable application profile only when absent";
        requiredBy = lib.optionals config.qclNegf.application.enable [ "qcl-negf-bootstrap.service" "qcl-negf-aiida.service" "qcl-negf-api.service" ];
        before = [ "qcl-negf-bootstrap.service" "qcl-negf-aiida.service" "qcl-negf-api.service" "slurmd.service" ];
        unitConfig.ConditionPathExists = "!${profile}";
        serviceConfig = { Type = "oneshot"; RemainAfterExit = true; };
        script = ''
          ${pkgs.nix}/bin/nix-env --profile ${profile} --set ${cfg.applicationPackage}
        '';
      };
    })
    (lib.mkIf cfg.enable {
      assertions = [
        { assertion = cfg.applicationPackage != null && cluster.solverPackage != null; message = "Release activation requires initial application and immutable solver closures."; }
        { assertion = cluster.controller || cluster.worker; message = "Release activation belongs on controller and Linux worker roles."; }
        { assertion = !(cluster.controller && cluster.worker); message = "Enrolled node identity requires distinct controller and worker machines."; }
      ];
      environment.systemPackages = [ releaseCommand lifecycleCommand ];
      environment.etc."qcl-negf/release-config.json".text = builtins.toJSON {
        email = config.qclNegf.application.bootstrap.email;
        allowed_codes_file = config.qclNegf.application.api.allowedCodesFile;
        role = if cluster.controller then "controller" else "worker";
        nfs_source = "${cluster.storageHost}:/srv/qcl-negf/jobs";
        slurm_conf = "${config.services.slurm.etcSlurm}/slurm.conf";
      };
      systemd.tmpfiles.rules = [
        "d /var/lib/qcl-negf-admin 0755 root root -"
        "d /var/lib/qcl-negf-admin/runtime 0755 root root -"
        "d /var/lib/qcl-negf-admin/trust-snapshots 0700 root root -"
      ];
      # A native unit owns the complete maintenance operation. The units stopped
      # by that engine are intentionally neither Requires nor PartOf here.
      systemd.services."qcl-negf-delivery@" = lib.mkIf cluster.controller {
        description = "Controller-owned explicit maintenance request %i";
        requires = [ "qcl-negf-delivery-boot-reconcile.service" "qcl-negf-application-profile.service" ];
        after = [ "qcl-negf-delivery-boot-reconcile.service" "qcl-negf-application-profile.service" "network-online.target" ];
        unitConfig = {
          RequiresMountsFor = [ "/var/lib/qcl-negf-admin/runtime" "/var/lib/qcl-negf" cluster.jobDirectory ];
          OnFailure = [ "qcl-negf-delivery-reconcile.service" ];
        };
        serviceConfig = {
          Type = "exec";
          User = "root";
          UMask = "0077";
          Restart = "no";
          KillMode = "control-group";
          # The request's existing monotonic engine/command deadlines own its
          # duration. systemd must not shorten them or mint a new retry budget.
          TimeoutStartSec = "infinity";
          TimeoutStopSec = "infinity";
          ExecStart = "${deliveryCommand}/bin/qcl-negf-delivery-service run --request-id %i";
        };
      };
      systemd.services.qcl-negf-delivery-boot-reconcile = lib.mkIf cluster.controller {
        description = "Classify interrupted delivery requests before new dispatch";
        wantedBy = [ "multi-user.target" ];
        after = [ "systemd-tmpfiles-setup.service" ];
        unitConfig.RequiresMountsFor = [ "/var/lib/qcl-negf-admin/runtime" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          User = "root";
          UMask = "0077";
          TimeoutStartSec = "infinity";
          ExecStart = "${deliveryCommand}/bin/qcl-negf-delivery-service reconcile";
        };
      };
      systemd.services.qcl-negf-delivery-reconcile = lib.mkIf cluster.controller {
        description = "Classify delivery service failure without replay";
        after = [ "systemd-tmpfiles-setup.service" ];
        unitConfig.RequiresMountsFor = [ "/var/lib/qcl-negf-admin/runtime" ];
        serviceConfig = {
          Type = "oneshot";
          User = "root";
          UMask = "0077";
          TimeoutStartSec = "infinity";
          ExecStart = "${deliveryCommand}/bin/qcl-negf-delivery-service reconcile";
        };
      };
      systemd.services.slurmd = lib.mkIf cluster.worker {
        requires = [ "qcl-negf-application-profile.service" ];
        after = [ "qcl-negf-application-profile.service" ];
        serviceConfig.ExecStartPre = "${releaseCommand}/bin/qcl-negf-release node-check";
        environment.SLURM_CONF = "${config.services.slurm.etcSlurm}/slurm.conf";
      };
    })
  ];
}
