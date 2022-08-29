{ python
, buildPythonPackage
, mypy
, black
, setuptools
, flake8
, pytest
, glibcLocales
, pytestCheckHook
, openssh
, bash
, lib
}:

buildPythonPackage rec {
  name = "deploykit";
  src = ./..;

  buildInputs = [
    setuptools
  ];

  checkInputs = [
    mypy
    black
    flake8
    glibcLocales
    pytestCheckHook
    openssh
    bash
  ];

  #preCheck = ''echo "sleep ...."; sleep 99999'';

  # don't swallow stdout/stderr
  pytestFlagsArray = [ "-s" ];

  postCheck = ''
    echo -e "\x1b[32m## run black\x1b[0m"
    LC_ALL=en_US.utf-8 black --check .
    echo -e "\x1b[32m## run flake8\x1b[0m"
    flake8 .
    echo -e "\x1b[32m## run mypy\x1b[0m"
    MYPYPATH=$(pwd):$(pwd)/tests mypy --strict --namespace-packages --explicit-package-bases .
  '';
  meta = with lib; {
    description = "Execute commands remote via ssh and locally in parallel with python";
    homepage = "https://github.com/numtide/deploykit";
    license = licenses.mit;
    maintainers = with maintainers; [ mic92 ];
    platforms = platforms.unix;
  };
}
