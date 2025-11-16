{ pkgs, config, ... }:
{
  projectRootFile = "flake.lock";

  programs.nixpkgs-fmt.enable = true;
  programs.ruff.format = true;
  programs.ruff.check = true;
  programs.mypy.enable = true;
  programs.mypy.directories = {
    "." = {
      extraPythonPackages = with pkgs.python3.pkgs; [
        pytest
      ];
    };
  };
}
