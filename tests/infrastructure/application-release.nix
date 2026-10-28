# Evaluate the actual merged services and Slurm gates, without a VM or a build.
{ nixpkgs }:
let
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  lib = pkgs.lib;
  make = role: extra: import (nixpkgs + "/nixos/lib/eval-config.nix") {
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
    }) extra ];
  };
  controller = (make "controller" {}).config;
  configurator = extra: (make "controller" {
    imports = [ { qclNegf.application.api.configurator.enable = lib.mkDefault true; } extra ];
  }).config;
  configured = configurator {};
  missingApi = configurator {
    qclNegf.application.api.enable = lib.mkForce false;
  };
  # Runtime metadata, rather than image-era package passthru, owns these bindings.
  missingBundle = configurator {
    qclNegf.application.package = lib.mkForce pkgs.hello;
  };
  missingSolver = configurator {
    qclNegf.cluster.solverPackage = lib.mkForce null;
  };
  nested = configurator {
    systemd.services.qcl-negf-api.serviceConfig.Slice = "research-api.slice";
  };
  configuratorFailures = cfg:
    let
      failedAssertions = builtins.filter (entry: !entry.assertion) cfg.assertions;
    in builtins.filter (entry: lib.hasPrefix "Configurator" entry.message) failedAssertions;
  api = configured.systemd.services.qcl-negf-api;
  disabledApi = controller.systemd.services.qcl-negf-api;
  worker = (make "worker" {}).config;
  nginxText = controller.environment.etc."nginx/nginx.conf".source.text;
  listeners = lib.filter (line: builtins.match "[[:space:]]*listen[[:space:]].*" line != null) (lib.splitString "\n" nginxText);
in
# A successful assertion may have an error-only diagnostic that must stay lazy.
assert map (entry: entry.message) (configuratorFailures {
  assertions = [
    { assertion = true; message = throw "successful diagnostic was forced"; }
    { assertion = false; message = "Configurator sentinel"; }
    { assertion = false; message = "Unrelated sentinel"; }
  ];
}) == [ "Configurator sentinel" ];
assert !controller.qclNegf.application.api.configurator.enable;
assert !(disabledApi.environment ? QCL_NEGF_CONFIGURATOR_EXECUTABLE);
assert !(disabledApi.serviceConfig ? DelegateSubgroup);
assert configuratorFailures configured == [];
assert configuratorFailures missingApi != [];
assert configuratorFailures missingBundle == [];
assert configuratorFailures missingSolver == [];
assert !(api.environment ? QCL_NEGF_CONFIGURATOR_EXECUTABLE);
assert !(api.environment ? QCL_NEGF_CONFIGURATOR_CATALOG_ROOT);
assert !(api.environment ? QCL_NEGF_CONFIGURATOR_CATALOG_SOURCE_ID);
assert !(api.environment ? QCL_NEGF_CONFIGURATOR_CGROUP_ROOT);
assert nested.systemd.services.qcl-negf-api.serviceConfig.DelegateSubgroup == "api";
assert api.serviceConfig.Delegate == "cpu memory pids";
assert api.serviceConfig.DelegateSubgroup == "api";
assert api.serviceConfig.KillMode == "control-group";
assert api.serviceConfig.User == "qcl-negf";
assert api.serviceConfig.NoNewPrivileges;
# Namespace admission is held by the existing unit, including the non-configurator API.
assert api.serviceConfig.RestrictNamespaces;
assert disabledApi.serviceConfig.RestrictNamespaces;
assert api.serviceConfig.ProtectSystem == "strict";
assert api.serviceConfig.ReadWritePaths == disabledApi.serviceConfig.ReadWritePaths;
assert builtins.attrNames configured.systemd.services == builtins.attrNames controller.systemd.services;
assert controller.qclNegf.release.enable;
assert worker.qclNegf.release.enable;
assert lib.hasPrefix "/nix/store/" controller.systemd.services.qcl-negf-aiida.serviceConfig.ExecStart;
assert lib.hasSuffix "-qcl-negf-aiida-start" controller.systemd.services.qcl-negf-aiida.serviceConfig.ExecStart;
assert controller.systemd.services.qcl-negf-aiida.serviceConfig.EnvironmentFile == "-/var/lib/qcl-negf-admin/runtime/service.env";
assert controller.systemd.services.qcl-negf-api.serviceConfig.EnvironmentFile == "-/var/lib/qcl-negf-admin/runtime/service.env";
assert lib.all (role: lib.all (rule: lib.elem rule role.systemd.tmpfiles.rules) [
  "d /var/lib/qcl-negf-admin 0755 root root -"
  "d /var/lib/qcl-negf-admin/runtime 0755 root root -"
  "d /var/lib/qcl-negf-admin/trust-snapshots 0700 root root -"
]) [ controller worker ];
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
