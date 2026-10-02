{ nixpkgs }:
let
  evaluate = profile: import (builtins.toPath nixpkgs + "/nixos/lib/eval-config.nix") {
    system = "x86_64-linux";
    modules = [ ../../modules ../../modules/image.nix {
      qclNegf.privateInterface = "cluster0";
      # Runner must enable the builder itself rather than duplicate its settings.
      qclNegf.builder = { inherit profile; };
      qclNegf.runner.enable = true;
    } ];
  };
  check = profile: cores: quota: memory:
    let
      c = (evaluate profile).config;
      runner = c.services.github-runners.qcl-negf;
      service = c.systemd.services.github-runner-qcl-negf.serviceConfig;
      user = c.users.users.github-runner-qcl-negf;
    in
    assert c.nix.settings.max-jobs == 1;
    assert c.nix.settings.cores == cores;
    assert c.systemd.services.nix-daemon.serviceConfig.Slice == "qcl-build.slice";
    assert service.Slice == "qcl-build.slice";
    assert c.systemd.slices.qcl-build.sliceConfig.CPUQuota == quota;
    assert c.systemd.slices.qcl-build.sliceConfig.MemoryMax == memory;
    assert c.systemd.slices.qcl-build.sliceConfig.MemorySwapMax == 0;
    assert !(builtins.hasAttr "qcl-negf-ci" c.systemd.slices);
    assert runner.tokenType == "registration";
    assert !runner.ephemeral;
    assert runner.user == "github-runner-qcl-negf";
    assert runner.group == "github-runner-qcl-negf";
    assert service.DynamicUser == false;
    assert user.group == "github-runner-qcl-negf";
    assert user.isSystemUser;
    assert !(builtins.elem "wheel" user.extraGroups);
    assert !(builtins.elem "qcl-negf-build" user.extraGroups);
    assert !(builtins.elem runner.user c.nix.settings.trusted-users);
    assert service.SupplementaryGroups == [];
    assert service.ReadWritePaths == [ "/var/lib/qcl-negf-ci/releases" ];
    assert builtins.elem "-/var/lib/qcl-negf-releases" service.InaccessiblePaths;
    assert builtins.elem "-/var/lib/qcl-negf-artifacts" service.InaccessiblePaths;
    assert runner.workDir == "/var/lib/qcl-negf-ci/work/qcl-negf";
    assert builtins.all (a: a.assertion) c.assertions;
    { inherit cores quota memory; user = runner.user; sharedSlice = service.Slice; };
in {
  standard = check "standard" 4 "400%" "7G";
  burst = check "burst" 12 "1200%" "22G";
}
