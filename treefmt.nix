{
  projectRootFile = "flake.lock";

  programs.nixpkgs-fmt.enable = true;
  programs.ruff.format = true;
  programs.ruff.check = true;
}
