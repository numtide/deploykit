{
  description = "Execute commands remotely and locally in parallel for a group of hosts with
python";

  inputs = {
    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    (flake-parts.lib.evalFlakeModule { inherit inputs; } {
      imports = [
        inputs.treefmt-nix.flakeModule
      ];
      systems = [
        "aarch64-linux"
        "x86_64-linux"
        "riscv64-linux"

        "x86_64-darwin"
        "aarch64-darwin"
      ];
      perSystem =
        { self'
        , pkgs
        , lib
        , ...
        }:
        {
          packages.deploykit = pkgs.python3.pkgs.callPackage ./nix/default.nix { };
          packages.default = self'.packages.deploykit;
          devShells.default = pkgs.callPackage ./nix/shell.nix { };
          treefmt = ./treefmt.nix;

          checks =
            let
              packages = lib.mapAttrs' (n: lib.nameValuePair "package-${n}") self'.packages;
              devShells = lib.mapAttrs' (n: lib.nameValuePair "devShell-${n}") self'.devShells;
            in
            packages // devShells;
        };
    }).config.flake;
}
