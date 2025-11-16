from __future__ import annotations

import os
import pwd
import subprocess
from typing import TYPE_CHECKING

import pytest

from deploykit import DeployGroup, DeployHost, HostKeyCheck, parse_hosts

if TYPE_CHECKING:
    from conftest import Sshd


def deploy_group(sshd: Sshd) -> DeployGroup:
    login = pwd.getpwuid(os.getuid()).pw_name
    return parse_hosts(
        f"{login}@127.0.0.1:{sshd.port}",
        host_key_check=HostKeyCheck.NONE,
        key=sshd.key,
    )


def test_run(sshd: Sshd) -> None:
    g = deploy_group(sshd)
    proc = g.run("echo hello", stdout=subprocess.PIPE)
    assert proc[0].result.stdout == "hello\n"


def test_run_environment(sshd: Sshd) -> None:
    g = deploy_group(sshd)
    p1 = g.run("echo $env_var", stdout=subprocess.PIPE, extra_env={"env_var": "true"})
    assert p1[0].result.stdout == "true\n"
    p2 = g.run(["env"], stdout=subprocess.PIPE, extra_env={"env_var": "true"})
    assert "env_var=true" in p2[0].result.stdout


def test_run_no_shell(sshd: Sshd) -> None:
    g = deploy_group(sshd)
    proc = g.run(["echo", "$hello"], stdout=subprocess.PIPE)
    assert proc[0].result.stdout == "$hello\n"


def test_run_function(sshd: Sshd) -> None:
    def some_func(h: DeployHost) -> bool:
        p = h.run("echo hello", stdout=subprocess.PIPE)
        return p.stdout == "hello\n"

    g = deploy_group(sshd)
    res = g.run_function(some_func)
    assert res[0].result


def test_timeout(sshd: Sshd) -> None:
    g = deploy_group(sshd)
    with pytest.raises(RuntimeError):
        g.run("sleep 10", timeout=0.01)


def test_run_exception(sshd: Sshd) -> None:
    g = deploy_group(sshd)

    r = g.run("exit 1", check=False)
    assert r[0].result.returncode == 1

    with pytest.raises(RuntimeError):
        g.run("exit 1")


def test_run_function_exception(sshd: Sshd) -> None:
    def some_func(h: DeployHost) -> subprocess.CompletedProcess[str]:
        return h.run_local("exit 1")

    g = deploy_group(sshd)

    with pytest.raises(RuntimeError):
        g.run_function(some_func)
