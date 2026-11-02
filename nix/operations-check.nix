# Root injects its locked includeTests App environment; Platform never imports Root.
{ pkgs, platformSource, scope, applicationTestEnvironment ? null }:
assert builtins.elem scope [ "ops" "full" ];
assert scope != "full" || applicationTestEnvironment != null;
let
  testEnvironment = import ./operations-test-environment.nix { inherit pkgs; };
  exports = pkgs.lib.concatStringsSep "\n" (pkgs.lib.mapAttrsToList
    (name: value: "export ${name}=${pkgs.lib.escapeShellArg value}") testEnvironment.environment);
  runner = pkgs.writeShellApplication {
    name = "qcl-negf-platform-check";
    runtimeInputs = [ pkgs.deno pkgs.nix pkgs.coreutils testEnvironment.python ];
    text = ''
      if [ "$#" -gt 1 ]; then
        echo "usage: qcl-negf-platform-check [NEW_ABSOLUTE_REPORT_DIRECTORY]" >&2
        exit 1
      fi
      if [ "$(id -u)" = 0 ]; then
        echo "Platform fixtures require a nonroot runner" >&2
        exit 1
      fi
      qclCheckWork=$(mktemp -d)
      trap 'rm -rf -- "$qclCheckWork"' EXIT
      cp -r ${platformSource}/. "$qclCheckWork/source"
      chmod -R u+w "$qclCheckWork/source"
      cd "$qclCheckWork/source"
      ${exports}
      export PATH=${testEnvironment.python}/bin:"$PATH"
      export QCL_PLATFORM_OPERATIONS_PYTHON=${testEnvironment.python.interpreter}
      ${pkgs.lib.optionalString (scope == "full") ''
        export QCL_PLATFORM_APPLICATION_PYTHON=${applicationTestEnvironment}/bin/python3
      ''}
      if [ "$#" -eq 1 ]; then
        export QCL_PLATFORM_CHECK_OUTPUT="$1"
      else
        unset QCL_PLATFORM_CHECK_OUTPUT
      fi
      export QCL_TEST_NIXPKGS=${pkgs.path}
      export DENO_DIR="$qclCheckWork/deno"
      deno task ${if scope == "full" then "check" else "check:ops"}
    '';
  };
in {
  inherit runner;
  check = pkgs.runCommand "qcl-negf-platform-${scope}-check" {} ''
    ${runner}/bin/qcl-negf-platform-check "$out"
  '';
}
