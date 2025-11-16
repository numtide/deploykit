{ buildPythonPackage
, hatchling
, glibcLocales
, pytestCheckHook
, openssh
, bash
, lib
, stdenv
}:

buildPythonPackage {
  name = "deploykit";
  src = ./..;

  pyproject = true;

  build-system = [
    hatchling
  ];

  nativeCheckInputs = [ openssh bash glibcLocales pytestCheckHook ];

  disabledTests = lib.optionals stdenv.isDarwin [ "test_ssh" ];

  # don't swallow stdout/stderr
  pytestFlagsArray = [ "-s" ];
  meta = with lib; {
    description = "Execute commands remote via ssh and locally in parallel with python";
    homepage = "https://github.com/numtide/deploykit";
    license = licenses.mit;
    maintainers = with maintainers; [ mic92 ];
    platforms = platforms.unix;
  };
}
