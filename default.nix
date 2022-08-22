with import <nixpkgs> {};
mkShell {
  nativeBuildInputs = [
    bashInteractive
    openssh
    mypy
    python3.pkgs.flake8
    python3.pkgs.black
    python3.pkgs.pytest
  ];
}
