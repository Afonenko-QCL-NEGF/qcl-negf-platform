# One dependency graph: native workspace metadata and its generated uv.lock.
{ pkgs, workspaceRoot, uv2nix, pyproject-nix, pyproject-build-systems, includeTests ? false }:
let
  inherit (pkgs) lib;
  workspace = uv2nix.lib.workspace.loadWorkspace { inherit workspaceRoot; };
  project = (builtins.fromTOML (builtins.readFile (workspaceRoot + "/pyproject.toml"))).project;
  memberDirectories = {
    qcl-negf-contracts = "qcl-negf-contracts";
    qcl-negf-results = "qcl-negf-results";
    aiida-qcl-negf = "qcl-negf-aiida";
    qcl-negf-api = "qcl-negf-portal";
  };
  members = builtins.attrNames memberDirectories;
  # loadWorkspace accepts a contextual store string, so retain that contract.
  # cleanSourceWith produces a new filtered store input without discarding context.
  ownedSource = root: names: lib.cleanSourceWith {
    src = root;
    filter = path: type: let
      relative = lib.removePrefix (toString root + "/") (toString path);
      top = builtins.head (lib.splitString "/" relative);
    in (toString path == toString root || builtins.elem top names)
      && !(top == "frontend" && builtins.elem (baseNameOf path) [ "node_modules" "dist" ])
      && lib.cleanSourceFilter path type;
  };
  memberSource = name: ownedSource
    (workspaceRoot + "/components/${memberDirectories.${name}}")
    ([ "pyproject.toml" "README.md" "LICENSE" "src" ]
      ++ lib.optionals (name == "qcl-negf-api") [ "hatch_build.py" "frontend" ]);
  catalogSource = ownedSource (workspaceRoot + "/components/qcl-negf-research")
    [ "config" "literature" "docs" "README.md" "LICENSE" ];
  compatibilityCheck = builtins.path {
    path = ../ops/application_compatibility.py;
    name = "qcl-application-compatibility.py";
  };
  frontend = import (workspaceRoot + "/components/qcl-negf-portal/nix/frontend.nix") { inherit pkgs; };
  sourceBuilds = final: prev: lib.genAttrs members (name:
    prev.${name}.overrideAttrs (old: {
      src = memberSource name;
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
  # Share the locked PythonSet while selecting only the Results CLI and its
  # dependencies. Passthru is lazy: solver capture never requires the API,
  # AiiDA or frontend application output.
  captureRuntime = pythonSet.mkVirtualEnv "qcl-negf-capture-${project.version}"
    { "qcl-negf-results" = []; };
  environment = pythonSet.mkVirtualEnv "qcl-negf-application-${project.version}"
    (if includeTests then workspace.deps.all else workspace.deps.default);
in
assert lib.hasPrefix "3.14." pkgs.python314.version;
environment.overrideAttrs (old: {
  passthru = (old.passthru or {}) // {
    inherit captureRuntime;
  };
  postInstall = (old.postInstall or "") + ''
    mkdir -p "$out/share/qcl-negf"
    cat > "$out/share/qcl-negf/runtime.json" <<'JSON'
    ${builtins.toJSON {
      schema = "qcl-negf-application-runtime-v1";
      configurator.catalog_root = "${catalogSource}";
    }}
    JSON
    # AiiDA imports initialize configuration directories even without a profile.
    # Keep the integrity check's mutable state in the build sandbox.
    AIIDA_PATH="$TMPDIR/qcl-negf-application-check" "$out/bin/python" - <<'PY'
    import runpy
    import aiida_qcl_negf, qcl_negf_api, qcl_negf_contracts, qcl_negf_results
    from aiida.plugins import CalculationFactory, ParserFactory, WorkflowFactory
    runpy.run_path("${compatibilityCheck}", run_name="__main__")
    CalculationFactory("qcl_negf.execution")
    ParserFactory("qcl_negf.execution")
    WorkflowFactory("qcl_negf.plan")
    PY
  '';
})
