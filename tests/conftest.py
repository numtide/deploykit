import contextlib
import os
import shutil
import signal
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from sys import platform
from tempfile import TemporaryDirectory
from typing import IO, Any

import pytest

# ============================================================================
# Root paths
# ============================================================================

TEST_ROOT = Path(__file__).parent.resolve()
PROJECT_ROOT = TEST_ROOT.parent


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Root directory of the project."""
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def test_root() -> Path:
    """Root directory of the tests."""
    return TEST_ROOT


# ============================================================================
# Command fixture
# ============================================================================

_FILE = None | int | IO[Any]


class Command:
    def __init__(self) -> None:
        self.processes: list[subprocess.Popen[str]] = []

    def run(
        self,
        command: list[str],
        extra_env: dict[str, str] | None = None,
        stdin: _FILE = None,
        stdout: _FILE = None,
        stderr: _FILE = None,
    ) -> subprocess.Popen[str]:
        if extra_env is None:
            extra_env = {}
        env = os.environ.copy()
        env.update(extra_env)
        # We start a new session here so that we can than more reliably kill all childs as well
        p = subprocess.Popen(
            command,
            env=env,
            start_new_session=True,
            stdout=stdout,
            stderr=stderr,
            stdin=stdin,
            text=True,
        )
        self.processes.append(p)
        return p

    def terminate(self) -> None:
        # Stop in reverse order in case there are dependencies.
        # We just kill all processes as quickly as possible because we don't
        # care about corrupted state and want to make tests fasts.
        for p in reversed(self.processes):
            with contextlib.suppress(OSError):
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)


@pytest.fixture
def command() -> Iterator[Command]:
    """Starts a background command. The process is automatically terminated in the end.
    >>> p = command.run(["some", "daemon"])
    >>> print(p.pid)
    """
    c = Command()
    try:
        yield c
    finally:
        c.terminate()


# ============================================================================
# Ports fixture
# ============================================================================


class Ports:
    def allocate(self) -> socket.socket:
        """
        Allocate a single free port by binding to port 0.

        Returns a bound socket. The caller is responsible for closing the socket
        when done. Use sock.getsockname()[1] to get the allocated port number.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        return sock


@pytest.fixture
def ports() -> Ports:
    return Ports()


# ============================================================================
# SSHD fixture
# ============================================================================


class Sshd:
    def __init__(self, port: int, proc: subprocess.Popen[str], key: str) -> None:
        self.port = port
        self.proc = proc
        self.key = key


class SshdConfig:
    def __init__(self, path: str, key: str, preload_lib: str | None) -> None:
        self.path = path
        self.key = key
        self.preload_lib = preload_lib


@pytest.fixture(scope="session")
def sshd_config(project_root: Path, test_root: Path) -> Iterator[SshdConfig]:
    # FIXME, if any parent of `project_root` is world-writable than sshd will refuse it.
    with TemporaryDirectory(dir=project_root) as _dir:
        tmp_dir = Path(_dir)
        host_key = tmp_dir / "host_ssh_host_ed25519_key"
        subprocess.run(
            [
                "ssh-keygen",
                "-t",
                "ed25519",
                "-f",
                host_key,
                "-N",
                "",
            ],
            check=True,
        )

        sshd_config = tmp_dir / "sshd_config"
        sshd_config.write_text(
            f"""
        HostKey {host_key}
        LogLevel DEBUG3
        # In the nix build sandbox we don't get any meaningful PATH after login
        SetEnv PATH={os.environ.get("PATH", "")}
        MaxStartups 64:30:256
        AuthorizedKeysFile {host_key}.pub
        """,
        )

        lib_path = None
        if platform == "linux":
            # This enforces a login shell by overriding the login shell of `getpwnam(3)`
            lib_path = str(tmp_dir / "libgetpwnam-preload.so")
            subprocess.run(
                [
                    os.environ.get("CC", "cc"),
                    "-shared",
                    "-o",
                    lib_path,
                    str(test_root / "getpwnam-preload.c"),
                ],
                check=True,
            )

        yield SshdConfig(str(sshd_config), str(host_key), lib_path)


@pytest.fixture
def sshd(sshd_config: SshdConfig, command: Command, ports: Ports) -> Iterator[Sshd]:
    sock = ports.allocate()
    port = sock.getsockname()[1]
    sock.close()  # Release the port so sshd can bind to it
    sshd = shutil.which("sshd")
    assert sshd is not None, "no sshd binary found"
    env = {}
    if sshd_config.preload_lib is not None:
        bash = shutil.which("bash")
        assert bash is not None
        env = {"LD_PRELOAD": str(sshd_config.preload_lib), "LOGIN_SHELL": bash}
    proc = command.run(
        [sshd, "-f", sshd_config.path, "-D", "-p", str(port)],
        extra_env=env,
    )

    while True:
        if (
            subprocess.run(
                [
                    "ssh",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-i",
                    sshd_config.key,
                    "localhost",
                    "-p",
                    str(port),
                    "true",
                ],
                check=False,
            ).returncode
            == 0
        ):
            yield Sshd(port, proc, sshd_config.key)
            return
        else:
            rc = proc.poll()
            if rc is not None:
                msg = f"sshd processes was terminated with {rc}"
                raise RuntimeError(msg)
            time.sleep(0.1)
