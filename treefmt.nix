{ ... }:
{
  projectRootFile = "flake.lock";

  programs.black.enable = true;
  programs.nixpkgs-fmt.enable = true;
}
