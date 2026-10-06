# Real NixOS module evaluation: callback listeners and private firewall agree.
# Removing SrunPortRange or opening it on a public/global firewall must fail.
{ nixpkgs, platform }:
let
  lib = nixpkgs.lib;
  mk = role: extra: (lib.nixosSystem {
    system = "x86_64-linux";
    modules = [ platform.nixosModules.default platform.nixosModules.image {
      qclNegf.privateInterface = "cluster0";
      qclNegf.cluster = {
        ${role} = true;
        nodes = [ "worker CPUs=2 RealMemory=1024 State=UNKNOWN" ];
        partitions = [ "compute Nodes=worker Default=YES State=UP" ];
        scratchDevice = "/dev/disk/by-id/virtio-qcl-scratch";
      };
    } extra ];
  }).config;
  controller = mk "controller" {};
  worker = mk "worker" {};
  submit = mk "submit" {};
  changed = mk "submit" { qclNegf.cluster.srunPortRange = { from = 61001; to = 61016; }; };
  inactive = (lib.nixosSystem {
    system = "x86_64-linux";
    modules = [ platform.nixosModules.default platform.nixosModules.image {
      qclNegf.privateInterface = "cluster0";
    } ];
  }).config;
  ranges = c: c.networking.firewall.interfaces.cluster0.allowedTCPPortRanges or [];
  noPublicCallbacks = c:
    c.networking.firewall.allowedTCPPortRanges == []
    && !(c.networking.firewall.interfaces ? public0)
    && builtins.all (interface: interface == "lo") c.networking.firewall.trustedInterfaces;
  rejected = extra: !(builtins.tryEval (mk "submit" extra).system.build.toplevel.drvPath).success;
in
assert lib.hasInfix "SrunPortRange=60001-60128" controller.services.slurm.extraConfig;
assert builtins.all (c:
  lib.hasInfix "SrunPortRange=60001-60128" c.services.slurm.extraConfig
  && ranges c == [{ from = 60001; to = 60128; }]
  && noPublicCallbacks c
) [ controller worker submit ];
assert controller.networking.firewall.interfaces.cluster0.allowedTCPPorts == [ 6817 ];
assert worker.networking.firewall.interfaces.cluster0.allowedTCPPorts == [ 6818 ];
assert submit.networking.firewall.interfaces.cluster0.allowedTCPPorts == [];
assert lib.hasInfix "SrunPortRange=61001-61016" changed.services.slurm.extraConfig;
assert ranges changed == [{ from = 61001; to = 61016; }] && noPublicCallbacks changed;
assert inactive.networking.firewall.allowedTCPPortRanges == [];
assert !(inactive.networking.firewall.interfaces ? cluster0);
assert rejected { qclNegf.cluster.srunPortRange = { from = 61016; to = 61001; }; };
assert rejected { qclNegf.cluster.srunPortRange = { from = 61001; to = 61004; }; };
assert rejected { qclNegf.cluster.srunPortRange = { from = 6817; to = 6824; }; };
assert rejected { qclNegf.cluster.srunPortRange = { from = 1023; to = 1030; }; };
true
