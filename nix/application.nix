# One dependency graph: native workspace metadata and its generated uv.lock.
{ pkgs, workspaceRoot, uv2nix, pyproject-nix, pyproject-build-systems, includeTests ? false }:
let
  inherit (pkgs) lib;
  workspace = uv2nix.lib.workspace.loadWorkspace { inherit workspaceRoot; };
  project = (builtins.fromTOML (builtins.readFile (workspaceRoot + "/pyproject.toml"))).project;
  members = [ "qcl-negf-contracts" "qcl-negf-results" "aiida-qcl-negf" "qcl-negf-api" ];
  frontend = import (workspaceRoot + "/components/qcl-negf-portal/nix/frontend.nix") { inherit pkgs; };
  sourceBuilds = final: prev: lib.genAttrs members (name:
    prev.${name}.overrideAttrs (old: {
      nativeBuildInputs = (old.nativeBuildInputs or [])
        ++ final.resolveBuildSystem { hatchling = []; };
      postPatch = (old.postPatch or "") + lib.optionalString (name == "qcl-negf-api") ''
        mkdir -p src/qcl_negf_api/static
        cp -r ${frontend}/. src/qcl_negf_api/static/
      '';
    })
  );
  pythonSet = (pkgs.callPackage pyproject-nix.build.packages { python = pkgs.python314; }).overrideScope
    (lib.composeManyExtensions [
      pyproject-build-systems.overlays.wheel
      (workspace.mkPyprojectOverlay { sourcePreference = "wheel"; })
      sourceBuilds
    ]);
  environment = pythonSet.mkVirtualEnv "qcl-negf-application-${project.version}"
    (if includeTests then workspace.deps.all else workspace.deps.default);
in
assert lib.hasPrefix "3.14." pkgs.python314.version;
environment.overrideAttrs (old: {
  postInstall = (old.postInstall or "") + ''
    "$out/bin/python" - <<'PY'
    from importlib.metadata import distribution
    import aiida_qcl_negf, qcl_negf_api, qcl_negf_contracts, qcl_negf_results
    from aiida.plugins import CalculationFactory, ParserFactory, WorkflowFactory
    for name in ("qcl-negf-contracts", "aiida-qcl-negf", "qcl-negf-api", "qcl-negf-results"):
        assert distribution(name).version == ${builtins.toJSON project.version}, name
    CalculationFactory("qcl_negf.execution")
    ParserFactory("qcl_negf.execution")
    WorkflowFactory("qcl_negf.plan")
    PY
  '';
})
