import fcntl
import os
import select
import subprocess
from contextlib import ExitStack, contextmanager
from enum import Enum
from shlex import quote
from threading import Thread
from pathlib import Path
import shlex
from typing import (
    IO,
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
    Text,
    Tuple,
    Union,
    TypeVar,
)


@contextmanager
def _pipe() -> Iterator[Tuple[IO[str], IO[str]]]:
    (pipe_r, pipe_w) = os.pipe()
    read_end = os.fdopen(pipe_r, "r")
    write_end = os.fdopen(pipe_w, "w")

    try:
        fl = fcntl.fcntl(read_end, fcntl.F_GETFL)
        fcntl.fcntl(read_end, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        yield (read_end, write_end)
    finally:
        read_end.close()
        write_end.close()


FILE = Union[None, int]


class HostKeyCheck(Enum):
    # Strictly check ssh host keys, prompt for unknown ones
    STRICT = 0
    # Trust on ssh keys on first use
    TOFU = 1
    # Do not check ssh host keys
    NONE = 2


class DeployHost:
    def __init__(
        self,
        host: str,
        user: str = "root",
        port: int = 22,
        forward_agent: bool = False,
        command_prefix: Optional[str] = None,
        host_key_check: HostKeyCheck = HostKeyCheck.STRICT,
        meta: Dict[str, Any] = {},
    ) -> None:
        """
        Creates a DeployHost
        @host the hostname to connect to via ssh
        @port the port to connect to via ssh
        @forward_agent: wheter to forward ssh agent
        @command_prefix: string to prefix each line of the command output with, defaults to host
        @host_key_check: wether to check ssh host keys
        @meta: meta attributes associated with the host. Those can be accessed in custom functions passed to `run_function`
        """
        self.host = host
        self.user = user
        self.port = port
        if command_prefix:
            self.command_prefix = command_prefix
        else:
            self.command_prefix = host
        self.forward_agent = forward_agent
        self.host_key_check = host_key_check
        self.meta = meta

    def _prefix_output(
        self, print_fd: IO[str], stdout: Optional[IO[str]], stderr: Optional[IO[str]]
    ) -> Tuple[str, str]:
        rlist = [print_fd]
        if stdout is not None:
            rlist.append(stdout)

        if stderr is not None:
            rlist.append(stderr)

        print_buf = ""
        stdout_buf = ""
        stderr_buf = ""

        while len(rlist) != 0:
            r, _, _ = select.select(rlist, [], [])

            if print_fd in r:
                read = os.read(print_fd.fileno(), 4096)
                if len(read) == 0:
                    rlist.remove(print_fd)
                print_buf += read.decode("utf-8")
                if read == "" or "\n" in print_buf:
                    lines = print_buf.rstrip("\n").split("\n")
                    for line in lines:
                        print(f"[{self.command_prefix}] {line}")
                    print_buf = ""

            def handle_fd(fd: Optional[IO[Any]]) -> str:
                if fd and fd in r:
                    read = os.read(fd.fileno(), 4096)
                    if len(read) == 0:
                        rlist.remove(fd)
                    else:
                        return read.decode("utf-8")
                return ""

            stdout_buf += handle_fd(stdout)
            stderr_buf += handle_fd(stderr)
        return stdout_buf, stderr_buf

    def _run(
        self,
        cmd: List[str],
        shell: bool,
        stdout: FILE = None,
        stderr: FILE = None,
        extra_env: Dict[str, str] = {},
        cwd: Union[None, str, Path] = None,
    ) -> subprocess.CompletedProcess[Text]:
        with ExitStack() as stack:
            if stdout is None or stderr is None:
                read_fd, write_fd = stack.enter_context(_pipe())

            if stdout is None:
                stdout_read = None
                stdout_write = write_fd
            elif stdout == subprocess.PIPE:
                stdout_read, stdout_write = stack.enter_context(_pipe())

            if stderr is None:
                stderr_read = None
                stderr_write = write_fd
            elif stderr == subprocess.PIPE:
                stderr_read, stderr_write = stack.enter_context(_pipe())

            with subprocess.Popen(
                cmd,
                text=True,
                shell=shell,
                stdout=stdout_write,
                stderr=stderr_write,
                cwd=cwd,
            ) as p:
                write_fd.close()
                if stdout == subprocess.PIPE:
                    stdout_write.close()
                if stderr == subprocess.PIPE:
                    stderr_write.close()
                stdout_data, stderr_data = self._prefix_output(
                    read_fd, stdout_read, stderr_read
                )
                ret = p.wait()
                return subprocess.CompletedProcess(
                    cmd, ret, stdout=stdout_data, stderr=stderr_data
                )
        raise RuntimeError("unreachable")

    def run_local(
        self,
        cmd: str,
        stdout: FILE = None,
        stderr: FILE = None,
        extra_env: Dict[str, str] = {},
        cwd: Union[None, str, Path] = None,
    ) -> subprocess.CompletedProcess:
        """
        Command to run locally for the host

        @cmd the commmand to run
        @stdout if not None stdout of the command will be redirected to this file i.e. stdout=subprocss.PIPE
        @stderr if not None stderr of the command will be redirected to this file i.e. stderr=subprocess.PIPE
        @extra_env: environment variables to override whe running the command
        @cwd: current working directory to run the process in

        @return subprocess.CompletedProcess result of the command
        """
        print(f"[{self.command_prefix}] {cmd}")
        return self._run(
            [cmd],
            shell=True,
            stdout=stdout,
            stderr=stderr,
            extra_env=extra_env,
            cwd=cwd,
        )

    def run(
        self,
        cmd: str,
        stdout: FILE = None,
        stderr: FILE = None,
        become_root: bool = False,
        extra_env: Dict[str, str] = {},
        cwd: Union[None, str, Path] = None,
    ) -> subprocess.CompletedProcess:
        """
        Command to run on the host via ssh

        @cmd the commmand to run
        @stdout if not None stdout of the command will be redirected to this file i.e. stdout=subprocss.PIPE
        @stderr if not None stderr of the command will be redirected to this file i.e. stderr=subprocess.PIPE
        @become_root if the ssh_user is not root than sudo is prepended
        @extra_env: environment variables to override whe running the command
        @cwd: current working directory to run the process in

        @return subprocess.CompletedProcess result of the ssh command
        """
        sudo = ""
        if become_root and self.user != "root":
            sudo = "sudo"
        vars = []
        for k, v in extra_env.items():
            vars.append(f"export {shlex.quote(k)}={shlex.quote(v)};")
        if vars:
            cmd = f"{' '.join(vars)} {cmd}"
        print(f"[{self.command_prefix}] {cmd}")
        ssh_opts = ["-A"] if self.forward_agent else []

        if self.host_key_check != HostKeyCheck.STRICT:
            ssh_opts.extend(["-o", "StrictHostKeyChecking=no"])
        if self.host_key_check == HostKeyCheck.NONE:
            ssh_opts.extend(["-o", "UserKnownHostsFile=/dev/null"])

        ssh_cmd = (
            ["ssh", f"{self.user}@{self.host}", "-p", str(self.port)]
            + ssh_opts
            + ["--", f"{sudo} bash -c {quote(cmd)}"]
        )
        return self._run(ssh_cmd, shell=False, stdout=stdout, stderr=stderr, cwd=cwd)


DeployResults = List[Tuple[DeployHost, subprocess.CompletedProcess[Text]]]

T = TypeVar("T")


def worker(
    func: Callable[[DeployHost], T],
    host: DeployHost,
    results: List[Tuple[DeployHost, Union[T, Exception]]],
    idx: int,
) -> None:
    try:
        results[idx] = (host, func(host))
    except Exception as e:
        results[idx] = (host, e)


class DeployGroup:
    def __init__(self, hosts: List[DeployHost]) -> None:
        self.hosts = hosts

    def _run_local(
        self,
        cmd: str,
        host: DeployHost,
        results: DeployResults,
        stdout: FILE = None,
        stderr: FILE = None,
        extra_env: Dict[str, str] = {},
        cwd: Union[None, str, Path] = None,
    ) -> None:
        results.append(
            (
                host,
                host.run_local(
                    cmd, stdout=stdout, stderr=stderr, extra_env=extra_env, cwd=cwd
                ),
            )
        )

    def _run_remote(
        self,
        cmd: str,
        host: DeployHost,
        results: DeployResults,
        stdout: FILE = None,
        stderr: FILE = None,
        extra_env: Dict[str, str] = {},
        cwd: Union[None, str, Path] = None,
    ) -> None:
        results.append(
            (
                host,
                host.run(
                    cmd, stdout=stdout, stderr=stderr, extra_env=extra_env, cwd=cwd
                ),
            )
        )

    def _run(
        self,
        cmd: str,
        local: bool = False,
        stdout: FILE = None,
        stderr: FILE = None,
        extra_env: Dict[str, str] = {},
        cwd: Union[None, str, Path] = None,
    ) -> DeployResults:
        results: DeployResults = []
        threads = []
        for host in self.hosts:
            fn = self._run_local if local else self._run_remote
            thread = Thread(
                target=fn,
                kwargs=dict(
                    results=results,
                    cmd=cmd,
                    host=host,
                    stdout=stdout,
                    stderr=stderr,
                    extra_env=extra_env,
                    cwd=cwd,
                ),
            )
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        return results

    def run(
        self,
        cmd: str,
        stdout: FILE = None,
        stderr: FILE = None,
        extra_env: Dict[str, str] = {},
        cwd: Union[None, str, Path] = None,
    ) -> DeployResults:
        """
        Command to run on the remote host via ssh
        @stdout if not None stdout of the command will be redirected to this file i.e. stdout=subprocss.PIPE
        @stderr if not None stderr of the command will be redirected to this file i.e. stderr=subprocess.PIPE
        @cwd: current working directory to run the process in

        @return a lists of tuples containing DeployNode and the result of the command for this DeployNode
        """
        return self._run(
            cmd, stdout=stdout, stderr=stderr, extra_env=extra_env, cwd=cwd
        )

    def run_local(
        self,
        cmd: str,
        stdout: FILE = None,
        stderr: FILE = None,
        extra_env: Dict[str, str] = {},
        cwd: Union[None, str, Path] = None,
    ) -> DeployResults:
        """
        Command to run locally for each host in the group in parallel
        @cmd the commmand to run
        @stdout if not None stdout of the command will be redirected to this file i.e. stdout=subprocss.PIPE
        @stderr if not None stderr of the command will be redirected to this file i.e. stderr=subprocess.PIPE
        @cwd: current working directory to run the process in
        @extra_env: environment variables to override whe running the command

        @return a lists of tuples containing DeployNode and the result of the command for this DeployNode
        """
        return self._run(
            cmd, local=True, stdout=stdout, stderr=stderr, extra_env=extra_env, cwd=cwd
        )

    def run_function(
        self, func: Callable[[DeployHost], T]
    ) -> List[Tuple[DeployHost, Union[T, Exception]]]:
        """
        Function to run for each host in the group in parallel

        @func the function to call
        """
        threads = []
        results: List[Tuple[DeployHost, Union[T, Exception]]] = [
            (h, Exception(f"No result set for thread {i}"))
            for (i, h) in enumerate(self.hosts)
        ]
        for i, host in enumerate(self.hosts):
            thread = Thread(
                target=worker,
                args=(func, host, results, i),
            )
            threads.append(thread)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()
        return results


def parse_hosts(
    hosts: str,
    host_key_check: HostKeyCheck = HostKeyCheck.STRICT,
    forward_agent: bool = False,
    domain_suffix: str = "",
    default_user: str = "root",
) -> DeployGroup:
    """
    Parse comma seperated string of hosts

    @hosts: A comma seperated list of hostnames with optional username (defaulting to root) i.e. admin@node1.example.com,admin@node2.example.com
    @host_key_check: wether to check ssh host keys
    @forward_agent: wether to forward the ssh agent
    @domain_suffix: a string to append to each hostname, i.e. hosts=admin@node0, domain_suffix=example.com -> admin@node0.example.com
    @default_user: user to choose if no ssh user is specified with the hostname

    @return A deploy group containing all hosts specified in hosts
    """
    deploy_hosts = []
    for h in hosts.split(","):
        parts = h.split("@")
        if len(parts) > 1:
            user = parts[0]
            hostname = parts[1]
        else:
            user = default_user
            hostname = parts[0]
        deploy_hosts.append(
            DeployHost(
                hostname + domain_suffix,
                user=user,
                host_key_check=host_key_check,
                forward_agent=forward_agent,
            )
        )
    return DeployGroup(deploy_hosts)
