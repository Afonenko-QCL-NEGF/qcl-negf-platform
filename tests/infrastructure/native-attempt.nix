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
  launch = (import ../../nix/native-attempt.nix { inherit pkgs; }).clientLaunch;
  profileConfig = "/var/lib/qcl-negf/aiida/.aiida/config.json";
  profileAccess = "/var/lib/qcl-negf/aiida/.aiida/access/qcl-negf";
  profileLog = "/var/lib/qcl-negf/aiida/.aiida/log";
  originalDaemonStart = pkgs.writeShellScript "qcl-negf-aiida-start" ''
    export PATH=/nix/var/nix/profiles/qcl-negf-application/bin:$PATH
    exec /nix/var/nix/profiles/qcl-negf-application/bin/verdi -p qcl-negf daemon start --foreground
  '';
in
assert !(off.systemd.sockets ? qcl-negf-native-attempt);
assert toString off.systemd.services.qcl-negf-aiida.serviceConfig.ExecStart == toString originalDaemonStart;
assert on.systemd.services.qcl-negf-aiida.serviceConfig.NoNewPrivileges;
assert on.systemd.services.qcl-negf-api.serviceConfig.NoNewPrivileges;
assert socket.Accept && socket.SocketMode == "0660" && socket.SocketUser == "root";
assert server.User == "root" && server.Restart == "no" && server.KillMode == "control-group";
assert server.MemoryMax == 134217728 && server.RuntimeMaxSec == 90;
assert !(off.systemd.services.qcl-negf-aiida.environment ? QCL_NEGF_NATIVE_JOBS_ROOT);
assert on.systemd.services.qcl-negf-aiida.environment.QCL_NEGF_NATIVE_JOBS_ROOT == "/srv/qcl-negf/jobs";
assert pkgs.lib.hasPrefix "/nix/store/" on.systemd.services."qcl-negf-native-attempt@".environment.QCL_NEGF_NATIVE_ACTOR_CONFIG;
assert server.StandardError == "journal";
assert server.ReadWritePaths == [ "/var/lib/qcl-negf-native-attempt" "/var/lib/qcl-negf-native-spool" profileAccess profileLog ];
assert server.ReadOnlyPaths == [ profileConfig ];
assert builtins.elem profileConfig on.systemd.services.qcl-negf-aiida.serviceConfig.ReadOnlyPaths;
assert builtins.elem profileConfig on.systemd.services.qcl-negf-api.serviceConfig.ReadOnlyPaths;
assert builtins.elemAt launch.argv_prefix 1 == "-I" && builtins.elemAt launch.argv_prefix 2 == "-c";
assert pkgs.lib.hasInfix "m.client_main()" (builtins.elemAt launch.argv_prefix 3);
assert builtins.elem "/srv/qcl-negf/jobs/native" on.systemd.services.qcl-negf-aiida.serviceConfig.ReadOnlyPaths;
assert builtins.elem "/srv/qcl-negf/jobs/native" on.systemd.services.qcl-negf-api.serviceConfig.ReadOnlyPaths;
assert pkgs.lib.hasInfix "Prolog=" worker.services.slurm.extraConfig;
assert pkgs.lib.hasInfix "Epilog=" worker.services.slurm.extraConfig;
assert builtins.any (entry: !entry.assertion && entry.message == "Native hooks cannot overwrite or chain foreign Prolog/Epilog settings.") foreignHooks.assertions;
true
