"""Aramid is a perfect base for a fabric you can rely on.

The module provides a simple API for executing commands on remote hosts and
copying files to remote hosts over SSH. It uses the standard system SSH tools so
it doesn't suffer from issues that custom implementations of the SSH protocol
have.

:example:

>>> import aramid
>>> ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]
>>> hosts = [aramid.Host(host_name=ip) for ip in ips]
>>> results = aramid.execute(hosts, 'echo "Successfully logged in to %s"', ips)
>>> [(results[h].retcode, results[h].stdout) for h in hosts]
[(0, 'Successfully logged in to 1.1.1.1'),
 (0, 'Successfully logged in to 2.2.2.2'),
 (0, 'Successfully logged in to 3.3.3.3'),
 (0, 'Successfully logged in to 4.4.4.4')]
>>> results = aramid.execute(hosts, 'yum update')
>>> failed = [h.host_name for h in hosts if any(result.retcode != 0 for result in results[h])]
>>> if any(failed):
...     print("Failed to update hosts: %s" % failed)

"""

from enum import Enum
from collections import namedtuple
import subprocess
import time

DEFAULT_SSH_ARGS = [
    "-oLogLevel=ERROR",
    "-oUserKnownHostsFile=/dev/null",
    "-oStrictHostKeyChecking=no",
    "-oBatchMode=yes",
    "-oHostKeyAlgorithms=+ssh-rsa",
    "-oPubkeyAcceptedKeyTypes=+ssh-rsa",
]
"""Default arguments to use with all SSH commands (incl. 'scp' and 'rsync')"""

PRINT_OUT_FN = print
"""Function to print commands and outputs from them"""

# just a named constant
_DEFAULT_SSH_PORT = 22


class AramidError(Exception):
    """Base exception class for the aramid module"""

    pass


class ExecutionError(AramidError):
    """Error when executing commands on remote hosts"""

    pass


class PutError(AramidError):
    """Error when copying files to remote hosts"""

    pass


class _TaskError(AramidError):
    pass


class PutMethod(Enum):
    """Method of copying files to remote hosts over SSH"""

    SCP = 1
    RSYNC = 2

    @classmethod
    def from_str(cls, method_str):
        if method_str.lower() == "scp":
            return cls.SCP
        elif method_str.lower() == "rsync":
            return cls.RSYNC
        else:
            raise ValueError("Invalid or unsupported method '%s' given" % method_str)


def _get_put_method_args(method, host, src, dst):
    port_args = []
    if method == PutMethod.SCP:
        if host.port != _DEFAULT_SSH_PORT:
            port_args += ["-P", str(host.port)]
        return (
            ["scp", "-r"] + DEFAULT_SSH_ARGS + port_args + [src, host.login + ":" + dst]
        )
    elif method == PutMethod.RSYNC:
        if host.port != _DEFAULT_SSH_PORT:
            port_args += ["-p", str(host.port)]
        return [
            "rsync",
            "-a",
            "-e",
            "ssh " + " ".join(DEFAULT_SSH_ARGS + port_args + host.extra_ssh_args),
        ] + [src, host.login + ":" + dst]
    else:
        raise ValueError("Invalid or unsupported method '%s' given" % method)


ExecutionResult = namedtuple(
    "ExecutionResult", ["action", "retcode", "stdout", "stderr"]
)


class _Task:
    def __init__(self, host, proc, action=None, retries=0):  # TODO: timeout=60
        self.host = host
        self.proc = proc
        self.action = action
        self._max_retries = retries
        self._retries = retries
        self.stdout = ""
        self.stderr = ""
        self.done = False

    def communicate(self, timeout=1, ignore_failed=False):
        start = time.time()
        try:
            out, err = self.proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            return False
        except Exception as e:
            raise _TaskError("Failed to communicate with the process") from e
        else:
            if self.proc.returncode == 255:  # SSH error
                if self._retries > 0:
                    # wait for the rest of timeout (if any) and restart the process
                    time.sleep(max(timeout - (time.time() - start), 0))
                    self.proc = subprocess.Popen(
                        self.proc.args,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        universal_newlines=True,
                    )
                    self._retries -= 1
                    return False
                else:
                    if ignore_failed:
                        self.done = True
                        return False
                    # else
                    if self._max_retries > 0:
                        raise _TaskError(
                            "SSH failed on '%s' (%d attempts)"
                            % (self.host.host_name, self._max_retries)
                        )
                    else:
                        raise _TaskError("SSH failed on '%s'" % self.host.host_name)
            else:
                self.done = True
                self.stdout += out
                self.stderr += err
                return True

    def print_output(
        self, max_host_name_length, echo_action=False, out_flag="", err_flag="err"
    ):
        out_flag_str = ""
        err_flag_str = ""
        if out_flag:
            out_flag_str = " (%s)" % out_flag
        if err_flag:
            err_flag_str = " (%s)" % err_flag

        if echo_action and self.action is not None:
            for action_line in self.action.splitlines():
                host_name = self.host.host_name_port.ljust(max_host_name_length)
                PRINT_OUT_FN("[{0}]:+ {1}".format(host_name, action_line))

        for line in self.stdout.splitlines():
            host_name = self.host.host_name_port.ljust(max_host_name_length)
            PRINT_OUT_FN("[{0}{1}]: {2}".format(host_name, out_flag_str, line))

        for line in self.stderr.splitlines():
            host_name = self.host.host_name_port.ljust(max_host_name_length)
            PRINT_OUT_FN("[{0}{1}]: {2}".format(host_name, err_flag_str, line))

    def get_result(self):
        return ExecutionResult(
            self.action, self.proc.returncode, self.stdout, self.stderr
        )


class Host:
    """A remote host to execute commands on or copy files to"""

    def __init__(self, host_name, user="root", extra_ssh_args=None):
        """
        :param str host_name: host name or IP of the host
        :param str user: user name to use to login to the host
        :param extra_ssh_args: extra SSH arguments to use when opening an SSH
                               connection to the host

        """
        if ":" in host_name:
            host_name, port = host_name.split(":")
            self.host_name = host_name
            self.port = int(port)
        else:
            self.host_name = host_name
            self.port = _DEFAULT_SSH_PORT
        self.user = user
        self.extra_ssh_args = extra_ssh_args or []

        self.tasks = []
        """A helper attribute which may change in the future"""

    @property
    def login(self):
        """user@host_name for the host"""
        return self.user + "@" + self.host_name

    @property
    def host_name_port(self):
        """ "host_name:port" or just "host_name" if using standard port"""
        port_spec = (":%d" % self.port) if self.port != _DEFAULT_SSH_PORT else ""
        return self.host_name + port_spec

    def __str__(self):
        return "Host(host_name='{0.host_name}', user='{0.user}', extra_ssh_args='{0.extra_ssh_args}')".format(
            self
        )


def _hosts_to_host_specs(hosts):
    host_specs = []
    for host in hosts:
        if isinstance(host, str):
            host_specs.append(Host(host))
        else:
            host_specs.append(host)
    return host_specs


def _wait_for_tasks(hosts, tasks, ignore_failed, echo, echo_action, out_flag=""):
    while not all(task.done for task in tasks):
        for task in (t for t in tasks if not t.done):
            # TODO: add logging here
            try:
                task.communicate(ignore_failed=ignore_failed)
            except _TaskError as e:
                raise ExecutionError(e) from e

    if echo and any(tasks):
        n = max(len(task.host.host_name) for task in tasks)
        for task in tasks:
            task.print_output(n, echo_action=echo_action, out_flag=out_flag)

    ret = dict()
    for host in hosts:
        ret[host] = []
        host.tasks = []
    for task in tasks:
        ret[task.host].append(task.get_result())
    return ret


def execute(
    hosts,
    command,
    command_args=None,
    retries=0,
    ignore_failed=False,
    echo=True,
    echo_cmd=False,
):  # TODO: parallel=False
    """Execute command on remote hosts (in parallel)

    :param hosts: an iterable of hosts
    :type hosts: an iterable of :class:`Host` instances or strings (IPs/host names)
    :param str command: command to execute on hosts
    :param command_args: an iterable of replacement items for commands if
                         :param:`command` contains one or more '%' string
                         replacement sequences
    :param int retries: number of SSH connection retries (for each host)
    :param bool ignore_failed: whether to ignore SSH connection failures and just
                               leave retcode == 255 or raise exception in case
                               of SSH connection failure
    :param bool echo: whether to echo the output (STDOUT first followed by
                      STDERR) of the given commands
    :param bool echo_cmd: whether to echo the commands run on the hosts
    :return: results of commands executed on the given hosts
    :rtype: dict(:class:`Host` -> list(:class:`ExecutionResult`))

    .. note::
       If string replacement in :param:`command` is used, :param:`command_args`
       has to be of the same length as :param:`hosts`.

    """
    if command_args is None:
        commands = len(hosts) * [command]
    else:
        commands = [(command % cmd_args) for cmd_args in command_args]

    tasks = []
    hosts = _hosts_to_host_specs(hosts)
    for i, host in enumerate(hosts):
        port_args = []
        if host.port != _DEFAULT_SSH_PORT:
            port_args += ["-p", str(host.port)]
        proc = subprocess.Popen(
            ["ssh", host.login]
            + DEFAULT_SSH_ARGS
            + port_args
            + host.extra_ssh_args
            + [commands[i]],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        task = _Task(host, proc, commands[i], retries=retries)
        host.tasks.append(task)
        tasks.append(task)

    return _wait_for_tasks(hosts, tasks, ignore_failed, echo, echo_cmd)


def execute_commands(
    hosts,
    data,
    get_command_fn,
    retries=0,
    ignore_failed=False,
    echo=True,
    echo_cmd=True,
):  # TODO: parallel=False
    """A more flexible version of the :func:`execute` function

    For each host in :param:`hosts` the function :param:`get_command_fn` is
    called with :param:`data` to get the command to execute on the host.

    :type get_command_fn: (:class:`Host`, :param:`data`) -> str
    :type data: anything

    .. seealso:: :func:`execute`

    :example:

    >>> import aramid
    >>> from collections import defaultdict
    >>> ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]
    >>> hosts = [aramid.Host(host_name=ip) for ip in ips]
    >>> dns = defaultdict(lambda: '8.8.8.8')  # defaultdict is a friend
    >>> dns['1.1.1.1'] = '9.9.9.9'  # overriding for one host
    >>> results = aramid.execute_commands(hosts, dns,
    ...                                   lambda host, data: "set-dns-resolver %s" % data[host.host_ip])

    """
    tasks = []
    hosts = _hosts_to_host_specs(hosts)
    for host in hosts:
        command = get_command_fn(host, data)
        if command:
            port_args = []
            if host.port != _DEFAULT_SSH_PORT:
                port_args += ["-p", str(host.port)]
            proc = subprocess.Popen(
                ["ssh", host.login]
                + DEFAULT_SSH_ARGS
                + port_args
                + host.extra_ssh_args
                + [command],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            )
            task = _Task(host, proc, command, retries=retries)
            host.tasks.append(task)
            tasks.append(task)

    return _wait_for_tasks(hosts, tasks, ignore_failed, echo, echo_cmd)


def put(
    hosts, src, dst=None, method=PutMethod.SCP, ignore_failed=False, echo=True
):  # TODO: parallel=False
    """Copy files to remote hosts

    :param hosts: an iterable of hosts
    :type hosts: an iterable of :class:`Host` instances or strings (IPs/host names)
    :param str src: local file or directory to copy
    :param str dst: destination path to copy the file or folder to (if `None`,
                    defaults to :param:`src`)
    :param method: method of copying files to remote hosts over SSH
    :type method: :class:`PutMethod` or str
    :param bool ignore_failed: whether to ignore SSH connection failures and just
                               leave retcode == 255 or raise exception in case
                               of SSH connection failure
    :param bool echo: whether to report 'src -> dst' and STDOUT followed by
                      STDERR for each host/transfer

    .. note::
       If `PutMethod.RSYNC` is used, the :param:`src` and :param:`dst` are
       sensitive to trailing `/`.

    :example:

    >>> import aramid
    >>> ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]
    >>> hosts = [aramid.Host(host_name=ip) for ip in ips]
    >>> results = aramid.put(hosts, "/etc/hosts", ignore_failed=True)
    >>> failed = [h.host_name for h in hosts if any(result.retcode != 0 for result in results[h])]
    >>> if any(failed):
    ...     print("Failed to copy /etc/hosts to hosts %s" % failed)

    """
    dst = dst or src  # `dst` defaults to `src`
    if isinstance(method, str):
        method = PutMethod.from_str(method)

    tasks = []
    hosts = _hosts_to_host_specs(hosts)
    for host in hosts:
        proc = subprocess.Popen(
            _get_put_method_args(method, host, src, dst),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        task = _Task(host, proc, action="{0} -> {1}".format(src, dst))
        host.tasks.append(task)
        tasks.append(task)

    return _wait_for_tasks(hosts, tasks, ignore_failed, echo, echo, out_flag="out")


def put_to_hosts(
    hosts, data, get_src_dst_fn, method=PutMethod.SCP, ignore_failed=False, echo=True
):
    """A more flexible version of the :func:`put` function

    For each host in :param:`hosts` the function :param:`get_src_dst_fn` is
    called with :param:`data` to get the source and destination paths for the
    host.

    :type get_src_dst_fn: (:class:`Host`, :param:`data`) -> (str, str)
    :type data: anything

    .. seealso:: :func:`put`
    .. seealso:: :func:`execute_commands`

    """
    if isinstance(method, str):
        method = PutMethod.from_str(method)

    tasks = []
    hosts = _hosts_to_host_specs(hosts)
    for host in hosts:
        src_dst = get_src_dst_fn(host, data)
        if src_dst is not None:
            src, dst = src_dst
            dst = dst or src  # `dst` defaults to `src`
            proc = subprocess.Popen(
                _get_put_method_args(method, host, src, dst),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            )
            task = _Task(host, proc, action="{0} -> {1}".format(src, dst))
            host.tasks.append(task)
            tasks.append(task)

    return _wait_for_tasks(hosts, tasks, ignore_failed, echo, echo, out_flag="out")
