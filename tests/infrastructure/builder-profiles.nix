{ nixpkgs }:
let
  evaluate = profile: extra: import (builtins.toPath nixpkgs + "/nixos/lib/eval-config.nix") {
    system = "x86_64-linux";
    modules = [ ../../modules ../../modules/image.nix {
      qclNegf.privateInterface = "cluster0";
      qclNegf.builder = { enable = true; inherit profile; };
    } ] ++ extra;
  };
  standard = (evaluate "standard" []).config;
  burst = (evaluate "burst" []).config;
  localDebug = (evaluate "local-debug" []).config;
  production = (evaluate "production-build" [{
    qclNegf.builder.resources = { vcpus = 24; memoryMiB = 40960; };
  }]).config;
  productionMissing = (evaluate "production-build" []).config;
  scientific = (evaluate "burst" [{
    qclNegf.storage = { enable = true; clients = [ "192.0.2.11" ]; };
  }]).config;
  failed = c: builtins.filter (a: !a.assertion) c.assertions;
in
assert standard.nix.settings.max-jobs == 1;
assert standard.nix.settings.cores == 4;
assert burst.nix.settings.max-jobs == 1;
assert burst.nix.settings.cores == 12;
assert standard.systemd.services.nix-daemon.serviceConfig.Slice == "qcl-build.slice";
assert burst.systemd.services.nix-daemon.serviceConfig.Slice == "qcl-build.slice";
assert standard.systemd.slices.qcl-build.sliceConfig.CPUQuota == "400%";
assert burst.systemd.slices.qcl-build.sliceConfig.CPUQuota == "1200%";
assert standard.systemd.slices.qcl-build.sliceConfig.MemoryMax == "7G";
assert burst.systemd.slices.qcl-build.sliceConfig.MemoryMax == "22G";
assert burst.systemd.slices.qcl-build.sliceConfig.MemorySwapMax == 0;
assert localDebug.nix.settings.cores == 4;
assert localDebug.systemd.slices.qcl-build.sliceConfig.MemoryMax == "7G";
assert production.nix.settings.cores == 24;
assert production.nix.settings.max-jobs == 1;
assert production.systemd.slices.qcl-build.sliceConfig.CPUQuota == "2400%";
assert production.systemd.slices.qcl-build.sliceConfig.MemoryMax == "38912M";
assert production.systemd.slices.qcl-build.sliceConfig.MemorySwapMax == 0;
assert builtins.any (a: a.message == "production-build requires explicit guest CPU/RAM with at least 2 GiB reserved for the guest OS.") (failed productionMissing);
assert builtins.any (a: a.message == "Administrative builds require a dedicated CI VM without scientific services.") (failed scientific);
{
  standard = { cores = standard.nix.settings.cores; memory = standard.systemd.slices.qcl-build.sliceConfig.MemoryMax; };
  burst = { cores = burst.nix.settings.cores; memory = burst.systemd.slices.qcl-build.sliceConfig.MemoryMax; };
  productionBuild = { cores = production.nix.settings.cores; memory = production.systemd.slices.qcl-build.sliceConfig.MemoryMax; };
  scientificMixtureRejected = true;
}
