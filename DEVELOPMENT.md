# Development

You will need python3 and openssh installed at a minimum.

## Setup

### Using Nix (Recommended)

The easiest way to get started is using Nix:

```console
$ git clone git@github.com:numtide/deploykit.git
$ cd deploykit
$ nix develop
```

This will provide all necessary dependencies including pytest, mypy, and ruff.

### Without Nix

Clone the project and install in development mode:

```console
$ git clone git@github.com:numtide/deploykit.git
$ cd deploykit
$ python3 -m venv .venv
$ source .venv/bin/activate
$ pip install -e '.[dev]'
```

This will install deploykit in editable mode along with all development dependencies.

## Running Tests

To run tests, you need [pytest](https://pytest.org):

```console
$ pytest ./tests
```

## Code Quality

The project uses modern Python tooling:

- **Type checking** with [mypy](http://www.mypy-lang.org/)
- **Formatting** with [ruff](https://docs.astral.sh/ruff/)
- **Linting** with [ruff](https://docs.astral.sh/ruff/)

### Using treefmt (Recommended)

Run all formatters and linters at once (if you have nix installed)

```console
$ nix fmt
```

### Manual Usage

Type checking:

```console
$ mypy deploykit tests
```

Formatting:

```console
$ ruff format .
```

Linting:

```console
$ ruff check --fix .
```

## Logging

We use python3s `logging` library. 
DeployHost-related logging starting with `[hostname]` is handled by a logger called `deploykit.command`, other logging is handled by the `deploykit.main` logger.
