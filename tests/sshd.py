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


@pytest.fixture
def sshd(command: Command, ports: Ports, project_root: Path) -> Iterator[Sshd]:
    """ """
    # FIXME, if any parent of `project_root` is world-writable than sshd will refuse it.
    with TemporaryDirectory(dir=project_root) as _dir:
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
        sshd_config.write_text(
            f"""
        HostKey {host_key}
        AuthorizedKeysFile {host_key}.pub
        """
        )

        port = ports.allocate(1)
        sshd = shutil.which("sshd")
        proc = command.run([sshd, "-f", str(sshd_config), "-D", "-p", str(port), "-6"])

        while True:
            if check_port(port):
                yield Sshd(port, proc, str(host_key))
                return
            else:
                rc = proc.poll()
                if rc is not None:
                    raise Exception(f"sshd processes was terminated with {rc}")
                time.sleep(0.1)
