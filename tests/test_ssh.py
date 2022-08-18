import subprocess
from deploykit import parse_hosts, run, HostKeyCheck
from sshd import Sshd


def test_run(sshd: Sshd) -> None:
    port = sshd.port
    g = parse_hosts(f"joerg@localhost:{port}", host_key_check=HostKeyCheck.NONE, key=sshd.key)
    proc = g.run("echo hello", stdout=subprocess.PIPE)
    assert proc[0].result.stdout == "hello\n"
