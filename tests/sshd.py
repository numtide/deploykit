import pytest
import shutil
import subprocess
from tempfile import NamedTemporaryFile
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
    with NamedTemporaryFile(mode="w") as f:
        f.write("HostKey /tmp/id_ed25519")
        f.flush()
        port = ports.allocate(1)
        sshd = shutil.which("sshd")
        proc = command.run(
            [sshd, "-f", f.name, "-D", "-d", "-p", str(port), "-6"],
            stdout=subprocess.PIPE,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            if "Server listening on ::" in line:
                yield Sshd(port, proc)
        raise RuntimeError("Could not start sshd")
