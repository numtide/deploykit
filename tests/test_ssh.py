from deploykit import parse_hosts, run, HostKeyCheck
from sshd import Sshd


def test_run(sshd: Sshd) -> None:
    port = sshd.port
    g = parse_hosts(f"joerg@localhost:{port}", host_key_check=HostKeyCheck.NONE, key=sshd.key)
    breakpoint()
    g.run("echo hello")
