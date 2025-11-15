

"""Execute commands remotely via ssh and locally in parallel with python."""

import fcntl
import logging
import math
import os
import select
import shlex
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from enum import Enum
from pathlib import Path
from shlex import quote
from threading import Thread
from typing import (
    IO,
    Any,
    Literal,
    TypeVar,
    overload,
)

# https://no-color.org
DISABLE_COLOR = not sys.stderr.isatty() or os.environ.get("NO_COLOR", "") != ""


def ansi_color(color: int) -> str:
    """Return ANSI color escape sequence for the given color code."""
    return f"\x1b[{color}m"


class CommandFormatter(logging.Formatter):
    """Print errors in red and warnings in yellow."""

    def __init__(self) -> None:
        """Initialize formatter with color-coded output."""
        super().__init__(
            "%(prefix_color)s[%(command_prefix)s]%(color_reset)s %(color)s%(message)s%(color_reset)s",
        )
        self.hostnames: list[str] = []
        self.hostname_color_offset = 1  # first host shouldn't get agressive red

    def formatMessage(self, record: logging.LogRecord) -> str:  # noqa: N802
        """Format log message with ANSI color codes based on log level."""
        colorcode = 0
        if record.levelno == logging.ERROR:
            colorcode = 31  # red
        if record.levelno == logging.WARNING:
            colorcode = 33  # yellow

        color, prefix_color, color_reset = "", "", ""
        if not DISABLE_COLOR:
            command_prefix = getattr(record, "command_prefix", "")
            color = ansi_color(colorcode)
            prefix_color = ansi_color(self.hostname_colorcode(command_prefix))
            color_reset = "\x1b[0m"

        record.color = color
        record.prefix_color = prefix_color
        record.color_reset = color_reset

        return super().formatMessage(record)

    def hostname_colorcode(self, hostname: str) -> int:
        """Get ANSI color code for hostname based on its index."""
        try:
            index = self.hostnames.index(hostname)
        except ValueError:
            self.hostnames += [hostname]
            index = self.hostnames.index(hostname)
        return 31 + (index + self.hostname_color_offset) % 7


def setup_loggers() -> tuple[logging.Logger, logging.Logger]:
    """Set up and return two loggers: one for main messages and one for command output.

    If we use the default logger here (logging.error etc) or a logger called
    "deploykit", then cmdlog messages are also posted on the default logger.
    To avoid this message duplication, we set up a main and command logger
    and use a "deploykit" main logger.
    """
    kitlog = logging.getLogger("deploykit.main")
    kitlog.setLevel(logging.INFO)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter())

    kitlog.addHandler(ch)

    # use specific logger for command outputs
    cmdlog = logging.getLogger("deploykit.command")
    cmdlog.setLevel(logging.INFO)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(CommandFormatter())

    cmdlog.addHandler(ch)
    return (kitlog, cmdlog)


# loggers for: general deploykit, command output
kitlog, cmdlog = setup_loggers()

info = kitlog.info
warn = kitlog.warning
error = kitlog.error


@contextmanager
def _pipe() -> Iterator[tuple[IO[str], IO[str]]]:
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


FILE = None | int

# Seconds until a message is printed when _run produces no output.
NO_OUTPUT_TIMEOUT = 20


class HostKeyCheck(Enum):
    """SSH host key verification modes."""

    # Strictly check ssh host keys, prompt for unknown ones
    STRICT = 0
    # Trust on ssh keys on first use
    TOFU = 1
    # Do not check ssh host keys
    NONE = 2


class DeployHost:
    

    """Represents a host to deploy to via SSH or locally."""

    def __init__(
        self,
        host: str,
        user: str | None = None,
        port: int | None = None,
        key: str | None = None,
        forward_agent: bool = False,
        command_prefix: str | None = None,
        host_key_check: HostKeyCheck = HostKeyCheck.STRICT,
        meta: dict[str, Any] | None = None,
        verbose_ssh: bool = False,
        extra_ssh_opts: list[str] | None = None,
    ) -> None:
        """Create a DeployHost instance.

        Args:
            host: The hostname to connect to via ssh
            user: The user to connect as
            port: The port to connect to via ssh
            key: Path to SSH private key file
            forward_agent: Whether to forward ssh agent
            command_prefix: String to prefix each line of the command output with, defaults to host
            host_key_check: Whether to check ssh host keys
            meta: Meta attributes associated with the host. Those can be accessed in custom functions passed to `run_function`
            verbose_ssh: Enables verbose logging on ssh connections
            extra_ssh_opts: Additional SSH options to use while connecting

        """
        if extra_ssh_opts is None:
            extra_ssh_opts = []
        if meta is None:
            meta = {}
        self.host = host
        self.user = user
        self.port = port
        self.key = key
        if command_prefix:
            self.command_prefix = command_prefix
        else:
            self.command_prefix = host
        self.forward_agent = forward_agent
        self.host_key_check = host_key_check
        self.meta = meta
        self.verbose_ssh = verbose_ssh
        self.extra_ssh_opts = extra_ssh_opts

    def _log_output_lines(self, lines: list[str], is_err: bool) -> None:
        """Log output lines with appropriate log level."""
        for line in lines:
            if is_err:
                cmdlog.error(line, extra={"command_prefix": self.command_prefix})
            else:
                cmdlog.info(line, extra={"command_prefix": self.command_prefix})

    def _read_and_log_fd(
        self,
        print_fd: IO[str],
        print_buf: str,
        rlist: list[IO[str]],
        is_err: bool,
    ) -> tuple[float, str]:
        """Read from file descriptor and log complete lines."""
        read = os.read(print_fd.fileno(), 4096)
        if len(read) == 0:
            rlist.remove(print_fd)
        print_buf += read.decode("utf-8")

        if (read == b"" and len(print_buf) != 0) or "\n" in print_buf:
            lines = print_buf.rstrip("\n").split("\n")
            self._log_output_lines(lines, is_err)
            print_buf = ""

        return (time.time(), print_buf)

    def _read_fd_to_buffer(
        self,
        fd: IO[Any] | None,
        ready_fds: list[IO[Any]],
        rlist: list[IO[str]],
    ) -> str:
        """Read from file descriptor into buffer without logging."""
        if fd and fd in ready_fds:
            read = os.read(fd.fileno(), 4096)
            if len(read) == 0:
                rlist.remove(fd)
            else:
                return read.decode("utf-8")
        return ""

    def _prefix_output(
        self,
        displayed_cmd: str,
        print_std_fd: IO[str] | None,
        print_err_fd: IO[str] | None,
        stdout: IO[str] | None,
        stderr: IO[str] | None,
        timeout: float = math.inf,
    ) -> tuple[str, str]:
        rlist = [
            fd for fd in [print_std_fd, print_err_fd, stdout, stderr] if fd is not None
        ]

        print_std_buf = ""
        print_err_buf = ""
        stdout_buf = ""
        stderr_buf = ""

        start = time.time()
        last_output = time.time()

        while rlist:
            ready_fds, _, _ = select.select(
                rlist,
                [],
                [],
                min(timeout, NO_OUTPUT_TIMEOUT),
            )

            if print_std_fd in ready_fds and print_std_fd is not None:
                last_output, print_std_buf = self._read_and_log_fd(
                    print_std_fd,
                    print_std_buf,
                    rlist,
                    is_err=False,
                )

            if print_err_fd in ready_fds and print_err_fd is not None:
                last_output, print_err_buf = self._read_and_log_fd(
                    print_err_fd,
                    print_err_buf,
                    rlist,
                    is_err=True,
                )

            now = time.time()
            if now - last_output > NO_OUTPUT_TIMEOUT:
                elapsed = now - start
                elapsed_msg = time.strftime("%H:%M:%S", time.gmtime(elapsed))
                cmdlog.warn(
                    f"still waiting for '{displayed_cmd}' to finish... ({elapsed_msg} elapsed)",
                    extra={"command_prefix": self.command_prefix},
                )

            stdout_buf += self._read_fd_to_buffer(stdout, ready_fds, rlist)
            stderr_buf += self._read_fd_to_buffer(stderr, ready_fds, rlist)

            if now - last_output >= timeout:
                break

        return stdout_buf, stderr_buf

    def _setup_output_pipe(
        self,
        stack: ExitStack,
        requested: FILE,
        write_default: IO[str] | None,
    ) -> tuple[IO[str] | None, IO[str] | None]:
        """Set up output pipe based on requested FILE parameter."""
        if requested is None:
            return (None, write_default)
        if requested == subprocess.PIPE:
            return stack.enter_context(_pipe())
        msg = f"unsupported value for output parameter: {requested}"
        raise ValueError(msg)

    def _close_write_pipes(
        self,
        write_std_fd: IO[str] | None,
        write_err_fd: IO[str] | None,
        stdout: FILE,
        stderr: FILE,
        stdout_write: IO[str] | None,
        stderr_write: IO[str] | None,
    ) -> None:
        """Close write ends of pipes after process starts."""
        if write_std_fd is not None:
            write_std_fd.close()
        if write_err_fd is not None:
            write_err_fd.close()
        if stdout == subprocess.PIPE and stdout_write is not None:
            stdout_write.close()
        if stderr == subprocess.PIPE and stderr_write is not None:
            stderr_write.close()

    def _run(
        self,
        cmd: list[str],
        displayed_cmd: str,
        shell: bool,
        stdout: FILE = None,
        stderr: FILE = None,
        extra_env: dict[str, str] | None = None,
        cwd: None | str | Path = None,
        check: bool = True,
        timeout: float = math.inf,
    ) -> subprocess.CompletedProcess[str]:
        if extra_env is None:
            extra_env = {}
        with ExitStack() as stack:
            read_std_fd, write_std_fd = (None, None)
            read_err_fd, write_err_fd = (None, None)

            if stdout is None or stderr is None:
                read_std_fd, write_std_fd = stack.enter_context(_pipe())
                read_err_fd, write_err_fd = stack.enter_context(_pipe())

            stdout_read, stdout_write = self._setup_output_pipe(
                stack,
                stdout,
                write_std_fd,
            )
            stderr_read, stderr_write = self._setup_output_pipe(
                stack,
                stderr,
                write_err_fd,
            )

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
                self._close_write_pipes(
                    write_std_fd,
                    write_err_fd,
                    stdout,
                    stderr,
                    stdout_write,
                    stderr_write,
                )

                start = time.time()
                stdout_data, stderr_data = self._prefix_output(
                    displayed_cmd,
                    read_std_fd,
                    read_err_fd,
                    stdout_read,
                    stderr_read,
                    timeout,
                )
                try:
                    ret = p.wait(timeout=max(0, timeout - (time.time() - start)))
                except subprocess.TimeoutExpired:
                    p.kill()
                    raise
                if ret != 0 and check:
                    raise subprocess.CalledProcessError(
                        ret,
                        cmd=cmd,
                        output=stdout_data,
                        stderr=stderr_data,
                    )
                if ret != 0:
                    cmdlog.warning(
                        f"[Command failed: {ret}] {displayed_cmd}",
                        extra={"command_prefix": self.command_prefix},
                    )
                return subprocess.CompletedProcess(
                    cmd,
                    ret,
                    stdout=stdout_data,
                    stderr=stderr_data,
                )

    def run_local(
        self,
        cmd: str | list[str],
        stdout: FILE = None,
        stderr: FILE = None,
        extra_env: dict[str, str] | None = None,
        cwd: None | str | Path = None,
        check: bool = True,
        timeout: float = math.inf,
    ) -> subprocess.CompletedProcess[str]:
        """Command to run locally for the host.

        @cmd the commmand to run
        @stdout if not None stdout of the command will be redirected to this file i.e. stdout=subprocss.PIPE
        @stderr if not None stderr of the command will be redirected to this file i.e. stderr=subprocess.PIPE
        @extra_env environment variables to override whe running the command
        @cwd current working directory to run the process in
        @timeout: Timeout in seconds for the command to complete

        @return subprocess.CompletedProcess result of the command
        """
        if extra_env is None:
            extra_env = {}
        shell = False
        if isinstance(cmd, str):
            cmd = [cmd]
            shell = True
        displayed_cmd = shlex.join(cmd)
        cmdlog.info(
            f"$ {displayed_cmd}",
            extra={"command_prefix": self.command_prefix},
        )
        return self._run(
            cmd,
            displayed_cmd,
            shell=shell,
            stdout=stdout,
            stderr=stderr,
            extra_env=extra_env,
            cwd=cwd,
            check=check,
            timeout=timeout,
        )

    def _build_export_cmd(self, extra_env: dict[str, str]) -> str:
        """Build export command for environment variables."""
        if not extra_env:
            return ""
        env_vars = [f"{shlex.quote(k)}={shlex.quote(v)}" for k, v in extra_env.items()]
        return f"export {shlex.join(env_vars)}; "

    def _build_displayed_cmd(self, cmd: str | list[str], export_cmd: str) -> str:
        """Build command string for display in logs."""
        displayed_cmd = export_cmd
        if isinstance(cmd, list):
            displayed_cmd += shlex.join(cmd)
        else:
            displayed_cmd += cmd
        return displayed_cmd

    def _build_ssh_opts(self, verbose_ssh: bool) -> list[str]:
        """Build SSH options list."""
        ssh_opts = ["-A"] if self.forward_agent else []
        if self.port:
            ssh_opts.extend(["-p", str(self.port)])
        if self.key:
            ssh_opts.extend(["-i", self.key])
        if self.host_key_check != HostKeyCheck.STRICT:
            ssh_opts.extend(["-o", "StrictHostKeyChecking=no"])
        if self.host_key_check == HostKeyCheck.NONE:
            ssh_opts.extend(["-o", "UserKnownHostsFile=/dev/null"])
        if verbose_ssh or self.verbose_ssh:
            ssh_opts.extend(["-v"])
        return ssh_opts

    def run(
        self,
        cmd: str | list[str],
        stdout: FILE = None,
        stderr: FILE = None,
        become_root: bool = False,
        extra_env: dict[str, str] | None = None,
        cwd: None | str | Path = None,
        check: bool = True,
        verbose_ssh: bool = False,
        timeout: float = math.inf,
    ) -> subprocess.CompletedProcess[str]:
        """Command to run on the host via ssh.

        @cmd the commmand to run
        @stdout if not None stdout of the command will be redirected to this file i.e. stdout=subprocss.PIPE
        @stderr if not None stderr of the command will be redirected to this file i.e. stderr=subprocess.PIPE
        @become_root if the ssh_user is not root than sudo is prepended
        @extra_env environment variables to override whe running the command
        @cwd current working directory to run the process in
        @verbose_ssh: Enables verbose logging on ssh connections
        @timeout: Timeout in seconds for the command to complete

        @return subprocess.CompletedProcess result of the ssh command
        """
        if extra_env is None:
            extra_env = {}

        sudo = "sudo -- " if become_root and self.user != "root" else ""
        export_cmd = self._build_export_cmd(extra_env)
        displayed_cmd = self._build_displayed_cmd(cmd, export_cmd)

        cmdlog.info(f"$ {displayed_cmd}", extra={"command_prefix": self.command_prefix})

        ssh_target = f"{self.user}@{self.host}" if self.user is not None else self.host
        ssh_opts = self._build_ssh_opts(verbose_ssh)

        bash_cmd = export_cmd
        bash_args = []
        if isinstance(cmd, list):
            bash_cmd += 'exec "$@"'
            bash_args = cmd
        else:
            bash_cmd += cmd

        ssh_cmd = [
            "ssh",
            ssh_target,
            *ssh_opts,
            *self.extra_ssh_opts,
            "--",
            f"{sudo}bash -c {quote(bash_cmd)} -- {shlex.join(bash_args)}",
        ]
        return self._run(
            ssh_cmd,
            displayed_cmd,
            shell=False,
            stdout=stdout,
            stderr=stderr,
            cwd=cwd,
            check=check,
            timeout=timeout,
        )


T = TypeVar("T")


class HostResult[T]:
    """Result of running a command on a host, wrapping either a successful result or an exception."""

    def __init__(self, host: DeployHost, result: T | Exception) -> None:
        """Initialize HostResult with host and result/exception."""
        self.host = host
        self._result = result

    @property
    def error(self) -> Exception | None:
        """Returns an error if the command failed."""
        if isinstance(self._result, Exception):
            return self._result
        return None

    @property
    def result(self) -> T:
        """Unwrap the result."""
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


DeployResults = list[HostResult[subprocess.CompletedProcess[str]]]


def _worker(
    func: Callable[[DeployHost], T],
    host: DeployHost,
    results: list[HostResult[T]],
    idx: int,
) -> None:
    try:
        results[idx] = HostResult(host, func(host))
    except Exception as e:  # noqa: BLE001
        kitlog.exception(e)
        results[idx] = HostResult(host, e)


class DeployGroup:
    """Group of deployment hosts for executing commands in parallel."""

    def __init__(self, hosts: list[DeployHost]) -> None:
        """Initialize DeployGroup with a list of hosts."""
        self.hosts = hosts

    def _run_local(
        self,
        cmd: str | list[str],
        host: DeployHost,
        results: DeployResults,
        stdout: FILE = None,
        stderr: FILE = None,
        extra_env: dict[str, str] | None = None,
        cwd: None | str | Path = None,
        check: bool = True,
        verbose_ssh: bool = False,  # noqa: ARG002
        timeout: float = math.inf,
    ) -> None:
        if extra_env is None:
            extra_env = {}
        try:
            proc = host.run_local(
                cmd,
                stdout=stdout,
                stderr=stderr,
                extra_env=extra_env,
                cwd=cwd,
                check=check,
                timeout=timeout,
            )
            results.append(HostResult(host, proc))
        except Exception as e:  # noqa: BLE001
            kitlog.exception(e)
            results.append(HostResult(host, e))

    def _run_remote(
        self,
        cmd: str | list[str],
        host: DeployHost,
        results: DeployResults,
        stdout: FILE = None,
        stderr: FILE = None,
        extra_env: dict[str, str] | None = None,
        cwd: None | str | Path = None,
        check: bool = True,
        verbose_ssh: bool = False,
        timeout: float = math.inf,
    ) -> None:
        if extra_env is None:
            extra_env = {}
        try:
            proc = host.run(
                cmd,
                stdout=stdout,
                stderr=stderr,
                extra_env=extra_env,
                cwd=cwd,
                check=check,
                verbose_ssh=verbose_ssh,
                timeout=timeout,
            )
            results.append(HostResult(host, proc))
        except Exception as e:  # noqa: BLE001
            kitlog.exception(e)
            results.append(HostResult(host, e))

    def _reraise_errors(self, results: list[HostResult[Any]]) -> None:
        errors = 0
        for result in results:
            e = result.error
            if e:
                cmdlog.error(
                    f"failed with: {e}",
                    extra={"command_prefix": result.host.command_prefix},
                )
                errors += 1
        if errors > 0:
            msg = f"{errors} hosts failed with an error. Check the logs above"
            raise RuntimeError(
                msg,
            )

    def _run(
        self,
        cmd: str | list[str],
        local: bool = False,
        stdout: FILE = None,
        stderr: FILE = None,
        extra_env: dict[str, str] | None = None,
        cwd: None | str | Path = None,
        check: bool = True,
        verbose_ssh: bool = False,
        timeout: float = math.inf,
    ) -> DeployResults:
        if extra_env is None:
            extra_env = {}
        results: DeployResults = []
        threads = []
        for host in self.hosts:
            fn = self._run_local if local else self._run_remote
            thread = Thread(
                target=fn,
                kwargs={
                    "results": results,
                    "cmd": cmd,
                    "host": host,
                    "stdout": stdout,
                    "stderr": stderr,
                    "extra_env": extra_env,
                    "cwd": cwd,
                    "check": check,
                    "verbose_ssh": verbose_ssh,
                    "timeout": timeout,
                },
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
        cmd: str | list[str],
        stdout: FILE = None,
        stderr: FILE = None,
        extra_env: dict[str, str] | None = None,
        cwd: None | str | Path = None,
        check: bool = True,
        verbose_ssh: bool = False,
        timeout: float = math.inf,
    ) -> DeployResults:
        """Command to run on the remote host via ssh.

        @stdout if not None stdout of the command will be redirected to this file i.e. stdout=subprocss.PIPE
        @stderr if not None stderr of the command will be redirected to this file i.e. stderr=subprocess.PIPE
        @cwd current working directory to run the process in
        @verbose_ssh: Enables verbose logging on ssh connections
        @timeout: Timeout in seconds for the command to complete.

        @return a lists of tuples containing DeployNode and the result of the command for this DeployNode
        """
        if extra_env is None:
            extra_env = {}
        return self._run(
            cmd,
            stdout=stdout,
            stderr=stderr,
            extra_env=extra_env,
            cwd=cwd,
            check=check,
            verbose_ssh=verbose_ssh,
            timeout=timeout,
        )

    def run_local(
        self,
        cmd: str | list[str],
        stdout: FILE = None,
        stderr: FILE = None,
        extra_env: dict[str, str] | None = None,
        cwd: None | str | Path = None,
        check: bool = True,
        timeout: float = math.inf,
    ) -> DeployResults:
        """Command to run locally for each host in the group in parallel.

        @cmd the commmand to run
        @stdout if not None stdout of the command will be redirected to this file i.e. stdout=subprocss.PIPE
        @stderr if not None stderr of the command will be redirected to this file i.e. stderr=subprocess.PIPE
        @cwd current working directory to run the process in
        @extra_env environment variables to override whe running the command
        @timeout: Timeout in seconds for the command to complete.

        @return a lists of tuples containing DeployNode and the result of the command for this DeployNode
        """
        if extra_env is None:
            extra_env = {}
        return self._run(
            cmd,
            local=True,
            stdout=stdout,
            stderr=stderr,
            extra_env=extra_env,
            cwd=cwd,
            check=check,
            timeout=timeout,
        )

    def run_function(
        self,
        func: Callable[[DeployHost], T],
        check: bool = True,
    ) -> list[HostResult[T]]:
        """Run function for each host in the group in parallel.

        @func the function to call
        """
        threads = []
        results: list[HostResult[T]] = [
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

    def filter(self, pred: Callable[[DeployHost], bool]) -> "DeployGroup":
        """Return a new DeployGroup with the results filtered by the predicate."""
        return DeployGroup(list(filter(pred, self.hosts)))


@overload
def run(
    cmd: list[str] | str,
    text: Literal[True] = ...,
    stdout: FILE = ...,
    stderr: FILE = ...,
    extra_env: dict[str, str] = ...,
    cwd: None | str | Path = ...,
    check: bool = ...,
) -> subprocess.CompletedProcess[str]: ...


@overload
def run(
    cmd: list[str] | str,
    text: Literal[False],
    stdout: FILE = ...,
    stderr: FILE = ...,
    extra_env: dict[str, str] = ...,
    cwd: None | str | Path = ...,
    check: bool = ...,
) -> subprocess.CompletedProcess[bytes]: ...


def run(
    cmd: list[str] | str,
    text: bool = True,
    stdout: FILE = None,
    stderr: FILE = None,
    extra_env: dict[str, str] | None = None,
    cwd: None | str | Path = None,
    check: bool = True,
) -> subprocess.CompletedProcess[Any]:
    """Run command locally.

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
    if extra_env is None:
        extra_env = {}
    if isinstance(cmd, list):
        info("$ " + " ".join(cmd))
    else:
        info(f"$ {cmd}")
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
    key: str | None = None,
    forward_agent: bool = False,
    domain_suffix: str = "",
    default_user: str | None = None,
) -> DeployGroup:
    """Parse comma seperated string of hosts.

    @hosts A comma seperated list of hostnames with optional username (defaulting to root) i.e. admin@node1.example.com,admin@node2.example.com
    @host_key_check wether to check ssh host keys
    @forward_agent wether to forward the ssh agent
    @domain_suffix a string to append to each hostname, i.e. hosts=admin@node0, domain_suffix=example.com -> admin@node0.example.com
    @default_user user to choose if no ssh user is specified with the hostname

    @return A deploy group containing all hosts specified in hosts
    """
    deploy_hosts = []
    for h in hosts.split(","):
        parts = h.split("@")
        if len(parts) > 1:
            user: str | None = parts[0]
            hostname = parts[1]
        else:
            user = default_user
            hostname = parts[0]
        maybe_port = hostname.split(":")
        port = None
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
            ),
        )
    return DeployGroup(deploy_hosts)
