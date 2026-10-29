# SOURCE evaluator oracle. Root separately owns Nix evaluation/native activation.
{ nixpkgs }:
let
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  make = native: role: extra: (import (nixpkgs + "/nixos/lib/eval-config.nix") {
    system = "x86_64-linux";
    modules = [ ../../modules ({ ... }: {
      system.stateVersion = "26.05";
      qclNegf.cluster = {
        controller = role == "controller"; submit = role == "controller"; worker = role == "worker";
        nodes = [ "worker CPUs=1 RealMemory=1024 State=UNKNOWN" ];
        partitions = [ "compute Nodes=worker Default=YES State=UP" ];
        scratchDevice = if role == "worker" then "/dev/disk/by-id/virtio-qcl-scratch" else null;
        nativeAttempts = { enable = native && role == "worker"; policyFile = "/etc/qcl-negf/native-attempt/policy.json"; };
      };
      qclNegf.application = {
        enable = role == "controller"; package = pkgs.hello; api.enable = role == "controller";
        nativeAttempts = { enable = native && role == "controller"; policyFile = "/etc/qcl-negf/native-attempt/policy.json"; };
      };
    }) extra ];
  }).config;
  off = make false "controller" {};
  on = make true "controller" {};
  worker = make true "worker" {};
  foreignHooks = make true "worker" {
    services.slurm.extraConfig = pkgs.lib.mkForce ''
      Prolog=/foreign/prolog
      Epilog=/foreign/epilog
    '';
  };
  socket = on.systemd.sockets.qcl-negf-native-attempt.socketConfig;
  server = on.systemd.services."qcl-negf-native-attempt@".serviceConfig;
in
assert !(off.systemd.sockets ? qcl-negf-native-attempt);
assert on.systemd.services.qcl-negf-aiida.serviceConfig.NoNewPrivileges;
assert on.systemd.services.qcl-negf-api.serviceConfig.NoNewPrivileges;
assert socket.Accept && socket.SocketMode == "0660" && socket.SocketUser == "root";
assert server.User == "root" && server.Restart == "no" && server.KillMode == "control-group";
assert server.MemoryMax == 134217728 && server.RuntimeMaxSec == 90;
assert builtins.elem "/srv/qcl-negf/jobs/native" on.systemd.services.qcl-negf-aiida.serviceConfig.ReadOnlyPaths;
assert builtins.elem "/srv/qcl-negf/jobs/native" on.systemd.services.qcl-negf-api.serviceConfig.ReadOnlyPaths;
assert pkgs.lib.hasInfix "Prolog=" worker.services.slurm.extraConfig;
assert pkgs.lib.hasInfix "Epilog=" worker.services.slurm.extraConfig;
assert builtins.any (entry: !entry.assertion && entry.message == "Native hooks cannot overwrite or chain foreign Prolog/Epilog settings.") foreignHooks.assertions;
true
