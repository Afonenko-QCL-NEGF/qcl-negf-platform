# Fixed entrypoints only. Policy, enrollment, qualification and credentials are runtime files.
{ pkgs }:
let
  resources = import ./host-resources.nix { inherit pkgs; };
  sourceExpression = operation:
    "import sys; sys.path.insert(0, '${resources.source}/ops'); import native_attempt as m; sys.exit(m.${operation}())";
  entry = name: expression: pkgs.writeShellApplication {
    inherit name;
    runtimeInputs = [ pkgs.python314 ];
    text = ''
      exec ${pkgs.python314}/bin/python3 -I -c ${pkgs.lib.escapeShellArg expression} "$@"
    '';
  };
  clientExpression = sourceExpression "client_main";
  client = entry "qcl-negf-native-attempt-client" clientExpression;
in pkgs.symlinkJoin {
  name = "qcl-negf-native-attempt";
  paths = [
    client
    (entry "qcl-negf-native-attempt-serve" (sourceExpression "server_main"))
    (entry "qcl-negf-native-attempt-hook" (sourceExpression "hook_main"))
  ];
  passthru.clientLaunch = {
    entrypoint = "${client}/bin/qcl-negf-native-attempt-client";
    argv_prefix = [ "${pkgs.python314}/bin/python3" "-I" "-c" clientExpression ];
    bash_executable = "${pkgs.bash}/bin/bash";
  };
}
