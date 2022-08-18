from sshd import Sshd
from deploykit import parse_hosts, run, DeployHost
import subprocess


def test_run() -> None:
    p = run("echo hello")
    assert p.stdout is None


def test_run_failure() -> None:
    p = run("exit 1", check=False)
    assert p.returncode == 1

    try:
        p = run("exit 1")
    except subprocess.CalledProcessError:
        return
    assert False, "Command should have raised an error"


def test_run_non_shell():
    p = run(["echo", "$hello"], stdout=subprocess.PIPE)
    assert p.stdout == "$hello\n"


def test_run_local():
    hosts = parse_hosts("some_host")
    hosts.run_local("echo hello")


def test_run_function():
    def some_func(h):
        p = h.run_local("echo hello", stdout=subprocess.PIPE)
        return p.stdout == "hello\n"

    hosts = parse_hosts("some_host")
    res = hosts.run_function(some_func)
    assert res[0][1] == True
