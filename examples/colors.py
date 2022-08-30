#!/usr/bin/env python3

from deploykit import parse_hosts
import sys
from typing import Callable

# Instead of defining your own print functions here you could also use the
# logging library of your choice.

HAS_TTY = sys.stderr.isatty()


def color_text(code: int) -> Callable[[str], str]:
    def wrapper(text: str) -> str:
        if HAS_TTY:
            return f"\x1b[{code}m{text}\x1b[0m"
        else:
            return text

    return wrapper


warn = color_text(31)
info = color_text(32)


def print_info(text: str) -> None:
    print(info(text))


def print_warn(text: str) -> None:
    print(warn(text))


def main() -> None:
    group = parse_hosts("localhost", out_logger=print_info, err_logger=print_warn)
    # This will to print to stdout and will thus be green.
    group.run_local("echo 'Print to stdout'")
    # This will to print to stderr and will thus be red.
    group.run_local("echo 'Print to stderr' 1>&2")


if __name__ == "__main__":
    main()
