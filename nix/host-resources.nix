# Source package only; private enrollment, keys, policy and qualification stay runtime files.
{ pkgs }:
let
  source = pkgs.runCommand "qcl-negf-resource-source" {} ''
    mkdir -p "$out/ops"
    cp ${../ops/application_release.py} "$out/ops/application_release.py"
    cp ${../ops/release_identity.py} "$out/ops/release_identity.py"
    cp ${../ops/release_trust.py} "$out/ops/release_trust.py"
    cp ${../ops/release_qualification.py} "$out/ops/release_qualification.py"
    cp ${../ops/release_health.py} "$out/ops/release_health.py"
    cp ${../ops/runtime_bindings.py} "$out/ops/runtime_bindings.py"
    cp ${../ops/host_resource_policy.py} "$out/ops/host_resource_policy.py"
    cp ${../ops/host_resource_operations.py} "$out/ops/host_resource_operations.py"
    cp ${../ops/host_resource_backends.py} "$out/ops/host_resource_backends.py"
    cp ${../ops/host_resource_facts.py} "$out/ops/host_resource_facts.py"
    cp ${../ops/host_resource_startup.py} "$out/ops/host_resource_startup.py"
    cp ${../ops/host_resource_service.py} "$out/ops/host_resource_service.py"
    cp ${../ops/host_resource_client.py} "$out/ops/host_resource_client.py"
    cp ${../ops/host_resource_projection.py} "$out/ops/host_resource_projection.py"
  '';
  entry = name: expression: pkgs.writeShellApplication {
    inherit name;
    runtimeInputs = [ pkgs.python314 pkgs.openssh pkgs.sudo pkgs.systemd ];
    text = ''
      exec python3 -I -c ${pkgs.lib.escapeShellArg "import sys; sys.path.insert(0, '${source}/ops'); ${expression}"} "$@"
    '';
  };
  client = entry "qcl-negf-resource" "import host_resource_client as m; sys.exit(m.main())";
  # Explicit role executables: sudo on one never grants the other actions.
  clientRoot = entry "qcl-negf-resource-client-root" "import host_resource_service as m; sys.exit(m.main('client'))";
  authority = entry "qcl-negf-resource-authority" "import host_resource_service as m; sys.exit(m.main('authority'))";
  facts = entry "qcl-negf-resource-facts" "import host_resource_service as m; sys.exit(m.main('facts'))";
  worker = entry "qcl-negf-resource-worker" "import host_resource_service as m; sys.exit(m.main('worker'))";
  admin = entry "qcl-negf-resource-admin" "import host_resource_startup as m; sys.exit(m.admin_main())";
  hook = entry "qcl-negf-resource-start-hook" "import host_resource_startup as m; sys.exit(m.hook_main())";
  sshClient = entry "qcl-negf-resource-ssh-client" "import host_resource_service as m; m.ssh_main('client')";
  sshAuthority = entry "qcl-negf-resource-ssh-authority" "import host_resource_service as m; m.ssh_main('authority')";
  sshFacts = entry "qcl-negf-resource-ssh-facts" "import host_resource_service as m; m.ssh_main('facts')";
  projection = entry "qcl-negf-resource-projection" "import json; import host_resource_projection as m; print(json.dumps(m.read_resource_projection()))";
in pkgs.symlinkJoin {
  name = "qcl-negf-host-resources";
  paths = [ client clientRoot authority facts worker admin hook projection sshClient sshAuthority sshFacts ];
  passthru = { inherit source; };
}
