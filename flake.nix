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

  outputs = { self, flake-parts, nixpkgs, treefmt-nix, ... }:
    let
      platforms = nixpkgs.lib.intersectLists nixpkgs.lib.systems.flakeExposed nixpkgs.legacyPackages.x86_64-linux.openssh.meta.platforms;
      substractBrokenPlatforms = nixpkgs.lib.subtractLists [
        "mipsel-linux"
        "armv5tel-linux"
      ];
    in
    flake-parts.lib.mkFlake { inherit self; } {
      imports = [
        treefmt-nix.flakeModule
      ];
      systems = substractBrokenPlatforms platforms;
      perSystem = { self', pkgs, ... }: {
        packages.deploykit = pkgs.python3.pkgs.callPackage ./nix/default.nix { };
        packages.default = self'.packages.deploykit;
        devShells.default = pkgs.callPackage ./nix/shell.nix { };
        treefmt = import ./treefmt.nix;
      };
    };
}
