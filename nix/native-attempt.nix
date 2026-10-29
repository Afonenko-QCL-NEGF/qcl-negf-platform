# Fixed entrypoints only. Policy, enrollment, qualification and credentials are runtime files.
{ pkgs }:
let
  resources = import ./host-resources.nix { inherit pkgs; };
  entry = name: expression: pkgs.writeShellApplication {
    inherit name;
    runtimeInputs = [ pkgs.python314 ];
    text = ''
      exec ${pkgs.python314}/bin/python3 -I -c ${pkgs.lib.escapeShellArg "import sys; sys.path.insert(0, '${resources.source}/ops'); import native_attempt as m; sys.exit(m.${expression}())"} "$@"
    '';
  };
in pkgs.symlinkJoin {
  name = "qcl-negf-native-attempt";
  paths = [
    (entry "qcl-negf-native-attempt-client" "client_main")
    (entry "qcl-negf-native-attempt-serve" "server_main")
    (entry "qcl-negf-native-attempt-hook" "hook_main")
  ];
}
