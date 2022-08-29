{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  nativeBuildInputs = [
    pkgs.bashInteractive
    pkgs.openssh
    pkgs.mypy
    pkgs.python3.pkgs.flake8
    pkgs.python3.pkgs.black
    pkgs.python3.pkgs.pytest
    pkgs.python3.pkgs.setuptools
  ];
}
