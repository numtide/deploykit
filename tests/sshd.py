import pytest
import shutil
import subprocess
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import Iterator

from ports import Ports
from command import Command


class Sshd:
    def __init__(self, port: int, proc: subprocess.Popen) -> None:
        self.port = port
        self.proc = proc


@pytest.fixture
def sshd(command: Command, ports: Ports) -> Iterator[Sshd]:
    """ """
    with TemporaryDirectory() as _dir:
        dir = Path(_dir)
        host_key = dir / "host_ssh_host_ed25519_key"
        proc = command.run(
            [
                "ssh-keygen",
                "-t",
                "ed25519",
                "-f",
                host_key,
                "-N",
                "",
            ]
        )
        proc.wait()
        sshd_config = dir / "sshd_config"
        sshd_config.write_text(f"HostKey {host_key}")

        port = ports.allocate(1)
        sshd = shutil.which("sshd")
        proc = command.run(
            [sshd, "-f", str(sshd_config), "-D", "-d", "-p", str(port), "-6"],
            stderr=subprocess.PIPE,
        )
        assert proc.stderr is not None
        for line in proc.stderr:
            if "Server listening on ::" in line:
                yield Sshd(port, proc)
            print(line, end="")
        raise RuntimeError("Could not start sshd")
