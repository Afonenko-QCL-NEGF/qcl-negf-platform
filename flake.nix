{
  description = "QCL-NEGF NixOS modules, local CI and typed operations";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/f5c082a40f7571c266e74e80ae2e68aadd8a9fc7";
  inputs.pyproject-nix = {
    url = "github:pyproject-nix/pyproject.nix/6a8a7881d75b6f98967e7b8069f4ead331384301";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.uv2nix = {
    url = "github:pyproject-nix/uv2nix/a24323e9e6ecbbf305c238845ff6c612d50467c0";
    inputs.pyproject-nix.follows = "pyproject-nix";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  inputs.pyproject-build-systems = {
    url = "github:pyproject-nix/build-system-pkgs/32156c9d9777eba86b09ad0e3299e6cd6e3fa46f";
    inputs.pyproject-nix.follows = "pyproject-nix";
    inputs.uv2nix.follows = "uv2nix";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  outputs = { self, nixpkgs, pyproject-nix, uv2nix, pyproject-build-systems }: let
    systems = [ "x86_64-linux" "aarch64-linux" ];
    forAll = nixpkgs.lib.genAttrs systems;
  in {
    nixosModules.default = import ./modules;
    nixosModules.image = import ./modules/image.nix;
    lib.mkPythonEnvironment = { system, workspaceRoot, includeTests ? false }:
      import ./nix/application.nix {
        pkgs = nixpkgs.legacyPackages.${system};
        inherit workspaceRoot includeTests uv2nix pyproject-nix pyproject-build-systems;
      };
    lib.mkApplication = { system, workspaceRoot }:
      self.lib.mkPythonEnvironment { inherit system workspaceRoot; };
    lib.mkImages = { configurations }:
      import ./nix/images.nix { inherit nixpkgs configurations; };
    devShells = forAll (system: let pkgs = nixpkgs.legacyPackages.${system}; in {
      default = pkgs.mkShell {
        packages = with pkgs; [ deno git nix nixos-rebuild uv python314 nodejs_24 opentofu ansible ];
      };
    });
    checks = forAll (system: let pkgs = nixpkgs.legacyPackages.${system}; in {
      infrastructure = let
        checked = import ./tests/infrastructure/invariants.nix { inherit nixpkgs; platform = self; };
      in builtins.deepSeq checked (pkgs.runCommand "qcl-negf-infrastructure-check" {} "touch $out");
      slurm-vm = import ./tests/slurm-vm.nix { inherit pkgs; module = self.nixosModules.default; };
      operations = pkgs.runCommand "qcl-negf-operations-check" { nativeBuildInputs = [ pkgs.deno pkgs.python314 ]; } ''
        cp -r ${./.} source
        chmod -R u+w source
        cd source
        export DENO_DIR="$TMPDIR/deno"
        deno task check
        touch "$out"
      '';
    });
  };
}
