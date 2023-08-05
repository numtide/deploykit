{ lib, pkgs, ... }:
{
  projectRootFile = "flake.lock";

  programs.nixpkgs-fmt.enable = true;
  settings.formatter = {
    python = {
      command = "sh";
      options = [
        "-eucx"
        ''
          ${lib.getExe pkgs.ruff} --fix "$@"
          ${lib.getExe pkgs.black} "$@"
        ''
        "--" # this argument is ignored by bash
      ];
      includes = [ "*.py" ];
    };

  };
}
