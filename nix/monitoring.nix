# Immutable P31 source. Private enrollment, keys and cache stay outside the store.
{ pkgs }:
let
  resources = import ./host-resources.nix { inherit pkgs; };
  python = pkgs.python314.withPackages (p: [ p.jsonschema p.referencing ]);
  source = pkgs.runCommand "qcl-negf-monitoring-source" {} ''
    mkdir -p "$out/ops" "$out/schemas"
    cp ${../ops/cluster_projection.py} "$out/ops/cluster_projection.py"
    cp ${../ops/slurm_context.py} "$out/ops/slurm_context.py"
    cp ${../ops/native_monitoring.py} "$out/ops/native_monitoring.py"
    cp ${../ops/monitoring_runtime.py} "$out/ops/monitoring_runtime.py"
    cp ${../schemas/cluster-projection.schema.json} "$out/schemas/cluster-projection.schema.json"
    cp ${../schemas/monitoring-config.schema.json} "$out/schemas/monitoring-config.schema.json"
    cp ${../schemas/host-resource-native-projection.schema.json} "$out/schemas/host-resource-native-projection.schema.json"
  '';
  entry = name: expression: pkgs.writeShellApplication {
    inherit name;
    runtimeInputs = [ python pkgs.openssh pkgs.sudo ];
    text = ''exec ${python}/bin/python3 -I -B -c ${pkgs.lib.escapeShellArg "import sys; sys.path[:0] = ['${source}/ops', '${resources.source}/ops']; import monitoring_runtime as m; ${expression}"} "$@"'';
  };
  read = entry "qcl-negf-monitor-read" "sys.exit(m.main('read'))";
  context = entry "qcl-negf-monitor-context" "sys.exit(m.main('context'))";
  observer = entry "qcl-negf-monitor-observer" "sys.exit(m.main('observer'))";
  forced = entry "qcl-negf-monitor-ssh-observer" "m.ssh_main()";
  # Marker accepts no sampler action. sshd's forced helper is the real ingress.
  rpc = entry "qcl-negf-monitor-rpc" "raise SystemExit('forced SSH observer required')";
  sample = entry "qcl-negf-monitor-sample" "sys.exit(m.main('sample'))";
  storage = entry "qcl-negf-monitor-storage" "sys.exit(m.main('maintain'))";
  storageCheck = entry "qcl-negf-monitor-storage-check" "sys.exit(m.main('storage-check'))";
  client = entry "qcl-negf-cluster-status" "m.client_main()";
in pkgs.symlinkJoin {
  name = "qcl-negf-monitoring";
  paths = [ read context observer forced rpc sample storage storageCheck client ];
  passthru = { inherit source; };
}
