# Source-specific module controls: no NixOS evaluation, builds or live mounts.
{ nixpkgs }:
let
  lib = import (nixpkgs + "/lib");
  settings = {
    enable = true;
    namespaceId = "retained-test";
    storageIdentity = "storage-test-identity";
    storageIdentityFile = "/run/site/saved-storage-identity";
    allowedComputerUuids = [ "11111111-1111-4111-8111-111111111111" ];
    retentionPolicyId = "indefinite-owner-disposition";
    retentionOwnerId = "test-owner";
    holdRef = "test-hold";
    accessBindingRef = "test-access-receipt";
  };
  makeWithMount = mount: overrides: import ../../modules/application.nix {
    inherit lib;
    pkgs = {
      writeShellScript = name: text: text;
      writeText = name: text: if name == "qcl-negf-application-launch.json"
        then lib.escapeShellArg text else "/synthetic-binding.json";
      runCommand = name: attrs: script: "/synthetic-operations";
      python314 = "/synthetic-python";
      coreutils = "/synthetic-coreutils";
      util-linux = "/synthetic-util-linux";
    };
    config = {
      qclNegf.cluster = {
        solverPackage = "/nix/store/synthetic-solver";
        jobDirectory = "/srv/qcl-negf/jobs";
        storageHost = "storage";
        submit = true; controller = true;
      };
      qclNegf.application = {
        enable = true; profile = "qcl-negf";
        package.outPath = "/nix/store/synthetic-application";
        bootstrap.enable = false;
        api = {
          enable = true; port = 8080; allowedCodesFile = null;
          tokenFile = "/run/secrets/api-token";
          tls.enable = false;
          configurator.enable = false;
          savedResults = settings // overrides;
        };
      };
      fileSystems."/srv/qcl-negf/jobs" = mount;
    };
  };
  mount = {
    device = "storage:/srv/qcl-negf/jobs";
    fsType = "nfs4";
    options = [ "hard" "_netdev" "x-systemd.automount" ];
  };
  make = makeWithMount mount;
  module = make {};
  api = module.config.content.systemd.services.qcl-negf-api.content;
  disabled = (make { enable = false; }).config.content.systemd.services.qcl-negf-api.content;
  failures = value: builtins.filter (entry: lib.hasPrefix "Saved results" entry.message)
    (builtins.filter (entry: !entry.assertion) value.config.content.assertions);
in
assert failures module == [];
assert failures (makeWithMount {} {}) != [];
assert failures (makeWithMount (mount // { fsType = "ext4"; }) {}) != [];
assert failures (makeWithMount (mount // { device = "foreign:/export"; }) {}) != [];
assert failures (makeWithMount (mount // { options = [ "soft" ]; }) {}) != [];
assert failures (make { namespaceId = null; }) != [];
assert failures (make { namespaceId = "../foreign"; }) != [];
assert failures (make { storageIdentity = null; }) != [];
assert failures (make { storageIdentityFile = null; }) != [];
assert failures (make { storageIdentityFile = "/run/../foreign"; }) != [];
assert failures (make { allowedComputerUuids = []; }) != [];
assert failures (make { allowedComputerUuids = settings.allowedComputerUuids ++ settings.allowedComputerUuids; }) != [];
assert failures (make { allowedComputerUuids = [ "not-a-uuid" ]; }) != [];
assert failures (make { holdRef = null; }) != [];
assert failures (make { accessBindingRef = null; }) != [];
assert failures (make { retentionPolicyId = null; }) != [];
assert failures (make { retentionOwnerId = null; }) != [];
assert api.unitConfig.RequiresMountsFor == [ "/var/lib/qcl-negf" "/run/secrets/api-token" "/srv/qcl-negf/jobs" "/run/site/saved-storage-identity" ];
assert api.serviceConfig.BindReadOnlyPaths == [ "/srv/qcl-negf/jobs:/run/qcl-negf-saved" ];
assert api.serviceConfig.ReadOnlyPaths == [ "/srv/qcl-negf/jobs" "/run/site/saved-storage-identity" ];
assert api.serviceConfig.ReadWritePaths == [ "/var/lib/qcl-negf" ];
assert !(disabled.environment ? QCL_NEGF_SAVED_RESULTS_BINDING_FILE);
assert !(disabled.serviceConfig ? BindReadOnlyPaths);
assert disabled.unitConfig.RequiresMountsFor == [ "/var/lib/qcl-negf" "/run/secrets/api-token" ];
{
  enabled = api.serviceConfig.ExecStart;
  disabled = disabled.serviceConfig.ExecStart;
}
