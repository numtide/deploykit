import fcntl
import os
import select
import subprocess
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta
from enum import Enum
from shlex import quote
from threading import Thread
from pathlib import Path
import shlex
from typing import (
    IO,
    overload,
    Literal,
    Generic,
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
    Tuple,
    Union,
    TypeVar,
)


# Seconds until a warning is printed when _run produces no output. This is used
# to warn when ssh connections fail to be established.
NO_OUTPUT_WARNING = 10


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
        key: Optional[str] = None,
        forward_agent: bool = False,
        command_prefix: Optional[str] = None,
        out_logger: Callable[[Any], Any] = print,
        err_logger: Callable[[Any], Any] = print,
        host_key_check: HostKeyCheck = HostKeyCheck.STRICT,
        meta: Dict[str, Any] = {},
    ) -> None:
        """
        Creates a DeployHost
        @host the hostname to connect to via ssh
        @port the port to connect to via ssh
        @forward_agent: wheter to forward ssh agent
        @command_prefix: string to prefix each line of the command output with, defaults to host
        @out_logger: logging function (taking at least one string as parameter) to print a commands `stdout` with
        @err_logger: logging function (taking at least one string as parameter) to print a commands `stderr` with
        @host_key_check: wether to check ssh host keys
        @meta: meta attributes associated with the host. Those can be accessed in custom functions passed to `run_function`
        """
        self.host = host
        self.user = user
        self.port = port
        self.key = key
        if command_prefix:
            self.command_prefix = command_prefix
        else:
            self.command_prefix = host
        self.out_logger = out_logger
        self.err_logger = err_logger
        self.forward_agent = forward_agent
        self.host_key_check = host_key_check
        self.meta = meta

    def _prefix_output(
        self,
        cmd: List[str],
        print_std_fd: Optional[IO[str]],
        print_err_fd: Optional[IO[str]],
        stdout: Optional[IO[str]],
        stderr: Optional[IO[str]],
    ) -> Tuple[str, str]:
        start = datetime.now()
        rlist = []
        if print_std_fd is not None:
            rlist.append(print_std_fd)
        if print_err_fd is not None:
            rlist.append(print_err_fd)
        if stdout is not None:
            rlist.append(stdout)

        if stderr is not None:
            rlist.append(stderr)

        print_std_buf = ""
        print_err_buf = ""
        stdout_buf = ""
        stderr_buf = ""
        had_output = False
        timeout = NO_OUTPUT_WARNING

        while len(rlist) != 0:
            r, _, _ = select.select(rlist, [], [], timeout)

            def print_from(print_fd: IO[str], print_buf: str, is_err: bool = False) -> str:
                read = os.read(print_fd.fileno(), 4096)
                if len(read) == 0:
                    rlist.remove(print_fd)
                else:
                    had_output = True
                print_buf += read.decode("utf-8")
                if read == b"" or "\n" in print_buf:
                    lines = print_buf.rstrip("\n").split("\n")
                    for line in lines:
                        if not is_err:
                            self.out_logger(f"[{self.command_prefix}] {line}")
                        else:
                            self.err_logger(f"[{self.command_prefix} ERR] {line}")
                    print_buf = ""
                return print_buf

            if print_std_fd in r and print_std_fd is not None:
                print_std_buf = print_from(print_std_fd, print_std_buf, is_err=False)
            if print_err_fd in r and print_err_fd is not None:
                print_err_buf = print_from(print_err_fd, print_err_buf, is_err=True)

            if datetime.now() - start >= timedelta(seconds=NO_OUTPUT_WARNING) and not had_output and timeout != 0:
                self.err_logger(f"[{self.command_prefix}][Command has not printed within {timeout}s. Is ssh timing out?] {cmd}")
                timeout = 0

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
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        with ExitStack() as stack:
            read_std_fd, write_std_fd = (None, None)
            read_err_fd, write_err_fd = (None, None)

            if stdout is None or stderr is None:
                read_std_fd, write_std_fd = stack.enter_context(_pipe())
                read_err_fd, write_err_fd = stack.enter_context(_pipe())

            if stdout is None:
                stdout_read = None
                stdout_write = write_std_fd
            elif stdout == subprocess.PIPE:
                stdout_read, stdout_write = stack.enter_context(_pipe())
            else:
                raise Exception(f"unsupported value for stdout parameter: {stdout}")

            if stderr is None:
                stderr_read = None
                stderr_write = write_err_fd
            elif stderr == subprocess.PIPE:
                stderr_read, stderr_write = stack.enter_context(_pipe())
            else:
                raise Exception(f"unsupported value for stderr parameter: {stderr}")

            env = os.environ.copy()
            env.update(extra_env)

            with subprocess.Popen(
                cmd,
                text=True,
                shell=shell,
                stdout=stdout_write,
                stderr=stderr_write,
                env=env,
                cwd=cwd,
            ) as p:
                if write_std_fd is not None:
                    write_std_fd.close()
                if write_err_fd is not None:
                    write_err_fd.close()
                if stdout == subprocess.PIPE:
                    assert stdout_write is not None
                    stdout_write.close()
                if stderr == subprocess.PIPE:
                    assert stderr_write is not None
                    stderr_write.close()
                stdout_data, stderr_data = self._prefix_output(
                    cmd, read_std_fd, read_err_fd, stdout_read, stderr_read
                )
                ret = p.wait()
                if check and ret != 0:
                    raise subprocess.CalledProcessError(
                        ret, cmd=cmd, output=stdout_data, stderr=stderr_data
                    )
                return subprocess.CompletedProcess(
                    cmd, ret, stdout=stdout_data, stderr=stderr_data
                )
        raise RuntimeError("unreachable")

    def run_local(
        self,
        cmd: Union[str, List[str]],
        stdout: FILE = None,
        stderr: FILE = None,
        extra_env: Dict[str, str] = {},
        cwd: Union[None, str, Path] = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        """
        Command to run locally for the host

        @cmd the commmand to run
        @stdout if not None stdout of the command will be redirected to this file i.e. stdout=subprocss.PIPE
        @stderr if not None stderr of the command will be redirected to this file i.e. stderr=subprocess.PIPE
        @extra_env environment variables to override whe running the command
        @cwd current working directory to run the process in

        @return subprocess.CompletedProcess result of the command
        """
        shell = False
        if isinstance(cmd, str):
            cmd = [cmd]
            shell = True
        print(f"[{self.command_prefix}] {' '.join(cmd)}")
        return self._run(
            cmd,
            shell=shell,
            stdout=stdout,
            stderr=stderr,
            extra_env=extra_env,
            cwd=cwd,
            check=check,
        )

    def run(
        self,
        cmd: Union[str, List[str]],
        stdout: FILE = None,
        stderr: FILE = None,
        become_root: bool = False,
        extra_env: Dict[str, str] = {},
        cwd: Union[None, str, Path] = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        """
        Command to run on the host via ssh

        @cmd the commmand to run
        @stdout if not None stdout of the command will be redirected to this file i.e. stdout=subprocss.PIPE
        @stderr if not None stderr of the command will be redirected to this file i.e. stderr=subprocess.PIPE
        @become_root if the ssh_user is not root than sudo is prepended
        @extra_env environment variables to override whe running the command
        @cwd current working directory to run the process in

        @return subprocess.CompletedProcess result of the ssh command
        """
        sudo = ""
        if become_root and self.user != "root":
            sudo = "sudo -- "
        vars = []
        for k, v in extra_env.items():
            vars.append(f"{shlex.quote(k)}={shlex.quote(v)}")

        print(f"[{self.command_prefix}] ", end="")
        export_cmd = ""
        if vars:
            export_cmd = f"export {' '.join(vars)}; "
            print(export_cmd, end="")
        if isinstance(cmd, list):
            print(" ".join(cmd))
        else:
            print(cmd)

        ssh_opts = ["-A"] if self.forward_agent else []

        if self.key:
            ssh_opts.extend(["-i", self.key])

        if self.host_key_check != HostKeyCheck.STRICT:
            ssh_opts.extend(["-o", "StrictHostKeyChecking=no"])
        if self.host_key_check == HostKeyCheck.NONE:
            ssh_opts.extend(["-o", "UserKnownHostsFile=/dev/null"])

        bash_cmd = export_cmd
        bash_args = []
        if isinstance(cmd, list):
            bash_cmd += 'exec "$@"'
            bash_args += cmd
        else:
            bash_cmd += cmd
        # FIXME we assume bash to be present here? Should be documented...
        ssh_cmd = (
            ["ssh", f"{self.user}@{self.host}", "-p", str(self.port)]
            + ssh_opts
            + [
                "--",
                f"{sudo}bash -c {quote(bash_cmd)} -- {' '.join(map(quote, bash_args))}",
            ]
        )
        return self._run(
            ssh_cmd, shell=False, stdout=stdout, stderr=stderr, cwd=cwd, check=check
        )


T = TypeVar("T")


class HostResult(Generic[T]):
    def __init__(self, host: DeployHost, result: Union[T, Exception]) -> None:
        self.host = host
        self._result = result

    @property
    def error(self) -> Optional[Exception]:
        """
        Returns an error if the command failed
        """
        if isinstance(self._result, Exception):
            return self._result
        return None

    @property
    def result(self) -> T:
        """
        Unwrap the result
        """
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


DeployResults = List[HostResult[subprocess.CompletedProcess[str]]]


def _worker(
    func: Callable[[DeployHost], T],
    host: DeployHost,
    results: List[HostResult[T]],
    idx: int,
) -> None:
    try:
        results[idx] = HostResult(host, func(host))
    except Exception as e:
        results[idx] = HostResult(host, e)


class DeployGroup:
    def __init__(self, hosts: List[DeployHost]) -> None:
        self.hosts = hosts

    def _run_local(
        self,
        cmd: Union[str, List[str]],
        host: DeployHost,
        results: DeployResults,
        stdout: FILE = None,
        stderr: FILE = None,
        extra_env: Dict[str, str] = {},
        cwd: Union[None, str, Path] = None,
        check: bool = True,
    ) -> None:
        try:
            proc = host.run_local(
                cmd,
                stdout=stdout,
                stderr=stderr,
                extra_env=extra_env,
                cwd=cwd,
                check=check,
            )
            results.append(HostResult(host, proc))
        except Exception as e:
            results.append(HostResult(host, e))

    def _run_remote(
        self,
        cmd: Union[str, List[str]],
        host: DeployHost,
        results: DeployResults,
        stdout: FILE = None,
        stderr: FILE = None,
        extra_env: Dict[str, str] = {},
        cwd: Union[None, str, Path] = None,
        check: bool = True,
    ) -> None:
        try:
            proc = host.run(
                cmd,
                stdout=stdout,
                stderr=stderr,
                extra_env=extra_env,
                cwd=cwd,
                check=check,
            )
            results.append(HostResult(host, proc))
        except Exception as e:
            results.append(HostResult(host, e))

    def _reraise_errors(self, results: List[HostResult[Any]]) -> None:
        for result in results:
            if result.error:
                raise result.error

    def _run(
        self,
        cmd: Union[str, List[str]],
        local: bool = False,
        stdout: FILE = None,
        stderr: FILE = None,
        extra_env: Dict[str, str] = {},
        cwd: Union[None, str, Path] = None,
        check: bool = True,
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
                    check=check,
                ),
            )
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        if check:
            self._reraise_errors(results)

        return results

    def run(
        self,
        cmd: Union[str, List[str]],
        stdout: FILE = None,
        stderr: FILE = None,
        extra_env: Dict[str, str] = {},
        cwd: Union[None, str, Path] = None,
        check: bool = True,
    ) -> DeployResults:
        """
        Command to run on the remote host via ssh
        @stdout if not None stdout of the command will be redirected to this file i.e. stdout=subprocss.PIPE
        @stderr if not None stderr of the command will be redirected to this file i.e. stderr=subprocess.PIPE
        @cwd current working directory to run the process in

        @return a lists of tuples containing DeployNode and the result of the command for this DeployNode
        """
        return self._run(
            cmd, stdout=stdout, stderr=stderr, extra_env=extra_env, cwd=cwd, check=check
        )

    def run_local(
        self,
        cmd: Union[str, List[str]],
        stdout: FILE = None,
        stderr: FILE = None,
        extra_env: Dict[str, str] = {},
        cwd: Union[None, str, Path] = None,
        check: bool = True,
    ) -> DeployResults:
        """
        Command to run locally for each host in the group in parallel
        @cmd the commmand to run
        @stdout if not None stdout of the command will be redirected to this file i.e. stdout=subprocss.PIPE
        @stderr if not None stderr of the command will be redirected to this file i.e. stderr=subprocess.PIPE
        @cwd current working directory to run the process in
        @extra_env environment variables to override whe running the command

        @return a lists of tuples containing DeployNode and the result of the command for this DeployNode
        """
        return self._run(
            cmd,
            local=True,
            stdout=stdout,
            stderr=stderr,
            extra_env=extra_env,
            cwd=cwd,
            check=check,
        )

    def run_function(
        self, func: Callable[[DeployHost], T], check: bool = True
    ) -> List[HostResult[T]]:
        """
        Function to run for each host in the group in parallel

        @func the function to call
        """
        threads = []
        results: List[HostResult[T]] = [
            HostResult(h, Exception(f"No result set for thread {i}"))
            for (i, h) in enumerate(self.hosts)
        ]
        for i, host in enumerate(self.hosts):
            thread = Thread(
                target=_worker,
                args=(func, host, results, i),
            )
            threads.append(thread)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()
        if check:
            self._reraise_errors(results)
        return results


@overload
def run(
    cmd: Union[List[str], str],
    text: Literal[True] = ...,
    stdout: FILE = ...,
    stderr: FILE = ...,
    extra_env: Dict[str, str] = ...,
    cwd: Union[None, str, Path] = ...,
    check: bool = ...,
) -> subprocess.CompletedProcess[str]:
    ...


@overload
def run(
    cmd: Union[List[str], str],
    text: Literal[False],
    stdout: FILE = ...,
    stderr: FILE = ...,
    extra_env: Dict[str, str] = ...,
    cwd: Union[None, str, Path] = ...,
    check: bool = ...,
) -> subprocess.CompletedProcess[bytes]:
    ...


def run(
    cmd: Union[List[str], str],
    text: bool = True,
    stdout: FILE = None,
    stderr: FILE = None,
    extra_env: Dict[str, str] = {},
    cwd: Union[None, str, Path] = None,
    check: bool = True,
) -> subprocess.CompletedProcess[Any]:
    """
    Run command locally

    @cmd if this parameter is a string the command is interpreted as a shell command,
         otherwise if it is a list, than the first list element is the command
         and the remaining list elements are passed as arguments to the
         command.
    @text when true, file objects for stdout and stderr are opened in text mode.
    @stdout if not None stdout of the command will be redirected to this file i.e. stdout=subprocss.PIPE
    @stderr if not None stderr of the command will be redirected to this file i.e. stderr=subprocess.PIPE
    @extra_env environment variables to override whe running the command
    @cwd current working directory to run the process in
    @check If check is true, and the process exits with a non-zero exit code, a
           CalledProcessError exception will be raised. Attributes of that exception
           hold the arguments, the exit code, and stdout and stderr if they were
           captured.
    """
    if isinstance(cmd, list):
        print(" ".join(cmd))
    else:
        print(cmd)
    env = os.environ.copy()
    env.update(extra_env)

    return subprocess.run(
        cmd,
        stdout=stdout,
        stderr=stderr,
        env=env,
        cwd=cwd,
        check=check,
        shell=not isinstance(cmd, list),
        text=text,
    )


def parse_hosts(
    hosts: str,
    host_key_check: HostKeyCheck = HostKeyCheck.STRICT,
    key: Optional[str] = None,
    forward_agent: bool = False,
    domain_suffix: str = "",
    default_user: str = "root",
    out_logger: Callable[[Any], Any] = print,
    err_logger: Callable[[Any], Any] = print,
) -> DeployGroup:
    """
    Parse comma seperated string of hosts

    @hosts A comma seperated list of hostnames with optional username (defaulting to root) i.e. admin@node1.example.com,admin@node2.example.com
    @host_key_check wether to check ssh host keys
    @forward_agent wether to forward the ssh agent
    @domain_suffix a string to append to each hostname, i.e. hosts=admin@node0, domain_suffix=example.com -> admin@node0.example.com
    @out_logger: logging function (taking at least one string as parameter) to print a commands `stdout` with
    @err_logger: logging function (taking at least one string as parameter) to print a commands `stderr` with
    @default_user user to choose if no ssh user is specified with the hostname

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
        maybe_port = hostname.split(":")
        port = 22
        if len(maybe_port) > 1:
            hostname = maybe_port[0]
            port = int(maybe_port[1])
        deploy_hosts.append(
            DeployHost(
                hostname + domain_suffix,
                user=user,
                port=port,
                key=key,
                host_key_check=host_key_check,
                forward_agent=forward_agent,
                out_logger=out_logger,
                err_logger=err_logger,
            )
        )
    return DeployGroup(deploy_hosts)
