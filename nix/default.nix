{ python
, buildPythonPackage
, mypy
, black
, flake8
, pytest
, glibcLocales
, pytestCheckHook
}:

buildPythonPackage rec {
  name = "deploykit";
  src = ./..;

  checkInputs = [
    mypy
    black
    flake8
    glibcLocales
    pytestCheckHook
  ];

  postCheck = ''
    echo -e "\x1b[32m## run black\x1b[0m"
    LC_ALL=en_US.utf-8 black --check .
    echo -e "\x1b[32m## run flake8\x1b[0m"
    flake8 .
    echo -e "\x1b[32m## run mypy\x1b[0m"
    mypy --strict nixpkgs_review
  '';
}
