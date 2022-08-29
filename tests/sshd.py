import pytest
import shutil
import subprocess
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Iterator

from ports import Ports, check_port
from command import Command


class Sshd:
    def __init__(self, port: int, proc: subprocess.Popen, key: str) -> None:
        self.port = port
        self.proc = proc
        self.key = key


class SshdConfig:
    def __init__(self, path: str, key: str) -> None:
        self.path = path
        self.key = key


@pytest.fixture(scope="session")
def sshd_config(project_root: Path) -> Iterator[SshdConfig]:
    # FIXME, if any parent of `project_root` is world-writable than sshd will refuse it.
    with TemporaryDirectory(dir=project_root) as _dir:
        dir = Path(_dir)
        host_key = dir / "host_ssh_host_ed25519_key"
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

        sshd_config = dir / "sshd_config"
        sshd_config.write_text(
            f"""
        HostKey {host_key}
        LogLevel DEBUG3
        AuthorizedKeysFile {host_key}.pub
        """
        )
        yield SshdConfig(str(sshd_config), str(host_key))


@pytest.fixture
def sshd(sshd_config: SshdConfig, command: Command, ports: Ports) -> Iterator[Sshd]:
    port = ports.allocate(1)
    sshd = shutil.which("sshd")
    assert sshd is not None, "no sshd binary found"
    proc = command.run([sshd, "-f", sshd_config.path, "-D", "-p", str(port)])

    while True:
        if check_port(port):
            yield Sshd(port, proc, sshd_config.key)
            return
        else:
            rc = proc.poll()
            if rc is not None:
                raise Exception(f"sshd processes was terminated with {rc}")
            time.sleep(0.1)
