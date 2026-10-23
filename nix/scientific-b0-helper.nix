# Source-only candidate. Building does not install a wrapper or grant authority.
{ pkgs, solverPackage, controllerPackage, nativeKit }:
pkgs.stdenv.mkDerivation (finalAttrs: {
  pname = "qcl-negf-scientific-b0-helper";
  version = "0.1.0-m1";
  dontUnpack = true;
  strictDeps = true;
  buildPhase = ''
    runHook preBuild
    mkdir -p lib bin
    cp ${../ops/scientific_b0_provider.py} lib/scientific_b0_provider.py
    cp ${../ops/scientific_b0_site.py} lib/scientific_b0_site.py
    cp ${../ops/slurm_job_evidence.py} lib/slurm_job_evidence.py
    cat > lib/entry.py <<'PY'
import sys
sys.path.insert(0, '${placeholder "out"}/lib/qcl-b0')
from scientific_b0_site import main, ProviderRefusal
try:
    main()
except ProviderRefusal:
    raise SystemExit(126)
PY
    $CC -std=c11 -O2 -Wall -Wextra -Werror -fstack-protector-strong \
      -D_FORTIFY_SOURCE=3 -Wl,-z,relro,-z,now \
      '-DQCL_B0_PYTHON="${pkgs.python314}/bin/python3"' \
      '-DQCL_B0_ENTRY="${placeholder "out"}/lib/qcl-b0/entry.py"' \
      ${../native/b0_trampoline.c} -o bin/qcl-b0-trampoline
    runHook postBuild
  '';
  installPhase = ''
    runHook preInstall
    mkdir -p "$out/bin" "$out/lib/qcl-b0" "$out/share/qcl-b0"
    install -m0555 bin/qcl-b0-trampoline "$out/bin/"
    install -m0444 lib/*.py "$out/lib/qcl-b0/"
    cat > "$out/share/qcl-b0/closure.json" <<'JSON'
${builtins.toJSON {
  schema = "qcl-b0-helper-closure.v1";
  python = "${pkgs.python314}/bin/python3";
  solver = toString solverPackage;
  controller = toString controllerPackage;
  nativeKit = toString nativeKit;
  platformProvider = builtins.hashFile "sha256" ../ops/scientific_b0_provider.py;
  platformSite = builtins.hashFile "sha256" ../ops/scientific_b0_site.py;
  jobEvidence = builtins.hashFile "sha256" ../ops/slurm_job_evidence.py;
  trampoline = builtins.hashFile "sha256" ../native/b0_trampoline.c;
  activation = "blocked_root_descriptor_producer_controller_native_attach";
}}
JSON
    runHook postInstall
  '';
  # There is no installCheck/native qualification in this source ticket.
  doCheck = false;
  meta.platforms = [ "x86_64-linux" "aarch64-linux" ];
})
