# Development

You will need python3 and openssh installed at a minimum.
Optionally the following python tools are required:

- flake8
- black
- pytest
- mypy

Clone the project:

```console
$ git clone git@github.com:numtide/deploykit.git
```

To run test, you need to install [pytest](https://pytest.org):

```console
$ pytest ./tests
```

The project also is fully typechecked with [mypy](http://www.mypy-lang.org/).
You can run the typechecking like this

```console
$ MYPYPATH=$(pwd):$(pwd)/tests mypy --strict --namespace-packages --explicit-package-bases .
```

Furthermore all code is formated with black:

```console
$ black .
```

and linted with flake8:

```console
$ flake8 .
```
