# Evaluate the actual merged services and Slurm gates, without a VM or a build.
{ nixpkgs }:
let
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  lib = pkgs.lib;
  make = role: import (nixpkgs + "/nixos/lib/eval-config.nix") {
    system = "x86_64-linux";
    modules = [ ../../modules ({ ... }: {
      system.stateVersion = "26.05";
      qclNegf.cluster = {
        controller = role == "controller";
        submit = role == "controller";
        worker = role == "worker";
        solverPackage = pkgs.hello;
        scratchDevice = if role == "worker" then "/dev/disk/by-id/virtio-qcl-scratch" else null;
        nodes = [ "worker CPUs=1 RealMemory=1024 State=UNKNOWN" ];
        partitions = [ "compute Nodes=worker Default=YES State=UP" ];
      };
      qclNegf.application = {
        enable = role == "controller";
        package = pkgs.hello;
        api.enable = role == "controller";
        api.tls = {
          enable = role == "controller";
          certificateFile = "/run/secrets/test-api.crt";
          keyFile = "/run/secrets/test-api.key";
        };
      };
      qclNegf.release.applicationPackage = pkgs.hello;
      qclNegf.stateDisk.enable = role == "controller";
      # A version override must flow into the state-directory provisioner.
      services.postgresql.package = lib.mkForce pkgs.postgresql_18;
      # Render upstream's actual configuration as a string, without a build.
      services.nginx.enableReload = role == "controller";
      services.nginx.validateConfigFile = false;
    }) ];
  };
  controller = (make "controller").config;
  worker = (make "worker").config;
  nginxText = controller.environment.etc."nginx/nginx.conf".source.text;
  listeners = lib.filter (line: builtins.match "[[:space:]]*listen[[:space:]].*" line != null) (lib.splitString "\n" nginxText);
in
assert controller.qclNegf.release.enable;
assert worker.qclNegf.release.enable;
assert lib.hasPrefix "/nix/var/nix/profiles/qcl-negf-application/bin/verdi " controller.systemd.services.qcl-negf-aiida.serviceConfig.ExecStart;
assert controller.systemd.services.qcl-negf-aiida.serviceConfig.EnvironmentFile == "-/var/lib/qcl-negf/runtime/service.env";
assert lib.hasInfix "qcl-negf-release node-check" worker.systemd.services.slurmd.serviceConfig.ExecStartPre;
assert lib.hasInfix "ReturnToService=0" worker.services.slurm.extraConfig;
assert lib.hasInfix "JobRequeue=0" worker.services.slurm.extraConfig;
assert lib.elem "qcl-negf-application-profile.service" controller.systemd.services.qcl-negf-aiida.requires;
assert controller.systemd.services.qcl-negf-aiida.unitConfig.ConditionPathExists == "/var/lib/qcl-negf/aiida/.aiida/config.json";
assert controller.systemd.services.qcl-negf-api.unitConfig.ConditionPathExists == "/var/lib/qcl-negf/aiida/.aiida/config.json";
assert controller.systemd.services.qcl-negf-aiida.environment.AIIDA_PATH == "/var/lib/qcl-negf/aiida";
assert controller.systemd.services.qcl-negf-api.environment.AIIDA_PATH == "/var/lib/qcl-negf/aiida";
assert controller.qclNegf.application.api.allowedCodesFile == "/var/lib/qcl-negf/aiida/code-uuid";
assert controller.services.nginx.virtualHosts."qcl-negf-api".onlySSL;
assert controller.services.nginx.virtualHosts."qcl-negf-api".listen == [{ addr = "127.0.0.1"; port = 443; ssl = true; proxyProtocol = false; extraParameters = []; }];
assert controller.services.nginx.virtualHosts."qcl-negf-api".sslCertificate == "/run/credentials/nginx.service/qcl-api-cert";
assert lib.elem "qcl-api-key:/run/secrets/test-api.key" controller.systemd.services.nginx.serviceConfig.LoadCredential;
assert controller.services.nginx.virtualHosts."qcl-negf-api".locations."/".proxyPass == "http://127.0.0.1:8080";
assert builtins.length listeners == 1;
assert lib.hasInfix "127.0.0.1:443 ssl" (builtins.head listeners);
assert lib.hasInfix "ssl_certificate_key /run/credentials/nginx.service/qcl-api-key;" nginxText;
assert lib.elem "postgresql.service" controller.systemd.services.qcl-negf-state-directories.before;
assert lib.elem "slurmctld.service" controller.systemd.services.qcl-negf-state-directories.before;
assert controller.services.postgresql.dataDir == "/var/lib/qcl-negf-state/postgresql/18";
assert lib.hasInfix "install -d -o postgres -g postgres -m 0700 /var/lib/qcl-negf-state/postgresql/18" controller.systemd.services.qcl-negf-state-directories.script;
assert !controller.fileSystems."/var/lib/qcl-negf-state".autoFormat;
assert controller.systemd.services.qcl-negf-api.environment.TMPDIR == "/var/lib/qcl-negf/exports";
assert lib.elem "d /var/lib/qcl-negf/exports 0700 qcl-negf qcl-negf -" controller.systemd.tmpfiles.rules;
assert lib.elem "/var/lib/qcl-negf" controller.systemd.services.qcl-negf-api.serviceConfig.ReadWritePaths;
{
  controllerStart = controller.systemd.services.qcl-negf-aiida.serviceConfig.ExecStart;
  workerGate = worker.systemd.services.slurmd.serviceConfig.ExecStartPre;
  profileInit = controller.systemd.services.qcl-negf-application-profile.unitConfig.ConditionPathExists;
}
