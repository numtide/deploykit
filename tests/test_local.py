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


def test_run_environment() -> None:
    p1 = run("echo $env_var", stdout=subprocess.PIPE, extra_env=dict(env_var="true"))
    assert p1.stdout == "true\n"

    hosts = parse_hosts("some_host")
    p2 = hosts.run_local(
        "echo $env_var", extra_env=dict(env_var="true"), stdout=subprocess.PIPE
    )
    assert p2[0][1].stdout == "true\n"


def test_run_non_shell() -> None:
    p = run(["echo", "$hello"], stdout=subprocess.PIPE)
    assert p.stdout == "$hello\n"


def test_run_local() -> None:
    hosts = parse_hosts("some_host")
    hosts.run_local("echo hello")


def test_run_function() -> None:
    def some_func(h: DeployHost) -> bool:
        p = h.run_local("echo hello", stdout=subprocess.PIPE)
        return p.stdout == "hello\n"

    hosts = parse_hosts("some_host")
    res = hosts.run_function(some_func)
    assert res[0][1] == True
