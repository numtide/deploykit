with import <nixpkgs> {};
mkShell {
  buildInputs = [
    python3.pkgs.flake8
    mypy
  ];
  nativeBuildInputs = [
    bashInteractive
  ];
}
