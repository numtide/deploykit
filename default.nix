with import <nixpkgs> {};
mkShell {
  checkInputs = [
    openssh
    mypy
    python3.pkgs.flake8
  ];
  nativeBuildInputs = [
    bashInteractive
  ];
}
