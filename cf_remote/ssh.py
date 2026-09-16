import os
import pwd
import shlex
import shutil
import signal
import socket
import subprocess
from typing import Union
from urllib.parse import urlparse

from cf_remote import aramid
from cf_remote import log
from cf_remote import paths
from cf_remote.utils import whoami, read_json, CFRUserError
from cf_remote.aramid import ExecutionResult
from cf_remote.paths import SSH_CONFIG_FPATH, SSH_CONFIGS_JSON_FPATH, CLOUD_STATE_FPATH

_PREFLIGHT_TIMEOUT = 5  # seconds
_PREFLIGHT_MAX_RETRIES = 5


class UnreachableHostError(aramid.AramidError):
    pass


def _check_reachable(
    host, port, timeout=_PREFLIGHT_TIMEOUT, max_retries=_PREFLIGHT_MAX_RETRIES
):
    tries = 0
    err = ""
    while tries < max_retries:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return
        except OSError as e:  # timeout/no-route-to-host
            tries += 1
            err = e
            pass

    raise UnreachableHostError(
        "Host '%s' is unreachable on port %s: %s" % (host, port, err)
    )


DEFAULT_SWITCH_USER_COMMAND = "sudo -n bash -c"
"""Command used to run commands as another (privileged) user

'-n' because there is never a terminal to prompt on: the SSH connections are
made with 'BatchMode=yes' and without a pty, so a 'sudo' that decides to ask
for a password has nowhere to ask. Saying so up front makes that failure
immediate and worded the same way everywhere, instead of leaving each 'sudo'
to complain about the missing terminal in its own words.
"""

DEFAULT_SWITCH_USER_COMMAND_WITH_PASSWORD = "sudo -S -p '' bash -c"
"""Same, but reading the password from standard input instead of a terminal

No '-n' here: it means never prompt, which is exactly what '-S' is asking to
do, and the two together refuse the password rather than read it.
"""

SWITCH_USER_LOCALE = "LC_ALL=C"
"""Locale the command switching user runs in

'_switch_user_hint()' tells "this wanted a password" apart from any other
failure by what the command said, and 'sudo' says it in the caller's language,
which 'ssh' carries over. Pinning it is what makes those wordings arrive.
"""


def read_switch_user_password(path):
    """Read the password for switching user from the first line of a file

    Refuses to read a file others can read, the same way ssh refuses to use a
    private key with too generous permissions.
    """
    path = os.path.expanduser(path)
    if not os.path.isfile(path):
        raise CFRUserError("Password file '%s' does not exist" % path)

    if os.name == "posix" and (os.stat(path).st_mode & 0o077):
        raise CFRUserError(
            "Password file '%s' is readable by others, run"
            " 'chmod 600 %s' before using it" % (path, path)
        )

    try:
        with open(path, "r") as f:
            line = f.readline()
    except OSError as e:
        raise CFRUserError("Cannot read password file '%s': %s" % (path, e))

    # Only the newline the editor added, a password may well end in a space
    return line.rstrip("\r\n")


class SwitchUser:
    """How to run commands as another (privileged) user on the remote hosts

    Built once from the command line options and passed to the connections it
    applies to. Nothing here changes after that, so the settings of a run
    cannot be read before they are complete, and a test can make one of these
    without having to put anything back afterwards.
    """

    def __init__(self, command=None, password=None):
        """
        :param str command: command to run commands as another user with, the
                            command to run is appended as a single quoted
                            argument. `None` picks a default depending on
                            whether there is a password to send.
        :param str password: password to send to :param:`command`, or `None`
                             when there is none to send.
        """
        self._command = command
        self._password = password

    @property
    def password(self):
        return self._password

    @property
    def is_command_given(self):
        """Whether the command is one we were given rather than one we picked"""
        return self._command is not None

    @property
    def command(self):
        if self._command is not None:
            return self._command
        if self._password is not None:
            return DEFAULT_SWITCH_USER_COMMAND_WITH_PASSWORD
        return DEFAULT_SWITCH_USER_COMMAND

    def wrap(self, cmd):
        """Wrap 'cmd' so that it runs as another (privileged) user

        'cmd' is quoted rather than wrapped in quotes: a command containing a
        quote of its own would otherwise end the wrapping early and the remote
        shell would run something else, or nothing at all.

        The locale is pinned, see :data:`SWITCH_USER_LOCALE`. 'sudo' keeps
        'LC_ALL', so 'cmd' runs in it too.
        """
        return "%s %s %s" % (SWITCH_USER_LOCALE, self.command, shlex.quote(cmd))

    def needs_password_on(self, connection):
        """Check whether switching user on this host requires a password

        Only interesting when we actually have a password to send. Sending it
        when it isn't needed would leave it on the standard input of the
        command we are running instead.

        'sudo -n' answers this without ever attempting to authenticate. Asking
        by letting an attempt fail instead would count towards the failed
        attempts that pam_faillock locks accounts out over, once per host and
        run.
        """
        if not connection.needs_sudo:
            return False

        if self._password is None:
            return False

        if self.is_command_given:
            # A command we didn't pick has no 'sudo -n' to ask with, so run it
            # with nothing on standard input: one that wants a password fails
            # right away rather than taking ours. Assuming it wants one instead
            # would hand the password to whatever runs when it doesn't.
            return (
                connection.run(self.wrap("true"), hide=True, stdin_input="").retcode
                != 0
            )

        return connection.run("sudo -n true", hide=True).retcode != 0


class LocalConnection:
    is_local = True
    ssh_user = None
    ssh_host = "localhost"

    def __init__(self, switch_user=None):
        self.ssh_user = pwd.getpwuid(os.getuid()).pw_name
        self.switch_user = switch_user or SwitchUser()
        self.needs_sudo = self.run("echo $UID", hide=True).stdout.strip() != "0"
        self.switch_user_needs_password = self.switch_user.needs_password_on(self)

    def run(self, command, hide=False, stdin_input=None):
        # to maintain Python 3.5/3.6 compatability the following are used:
        # stdout=PIPE, stderr=STDOUT instead of capture_output=True
        # universal_newlines=True instead of text=True
        result = subprocess.run(
            command,
            input=stdin_input,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            universal_newlines=True,
            cwd=os.environ["HOME"],
        )
        r = ExecutionResult(command, result.returncode, result.stdout, result.stderr)
        return r

    def put(self, src, hide=False):
        dst = os.path.join(os.environ["HOME"], os.path.basename(src))
        src = os.path.abspath(src)
        if src != dst:
            if not hide:
                print("Local copy: '%s' -> '%s'" % (src, dst))
            shutil.copy(src, dst)


class Connection:
    def __init__(
        self,
        host,
        user,
        connect_kwargs=None,
        port=aramid._DEFAULT_SSH_PORT,
        switch_user=None,
    ):
        log.debug(
            "Initializing Connection: host '%s' user '%s' port '%s'"
            % (host, user, port)
        )

        self.ssh_host = host
        self.ssh_port = port
        self.ssh_user = user
        self.switch_user = switch_user or SwitchUser()
        self._connect_kwargs = connect_kwargs
        self._ssh_control_master = None

        # Fail fast, before starting the Control Master or entering run()'s retry loop.
        log.debug("Checking that '%s:%s' is reachable" % (host, port))
        _check_reachable(host, port)

        # Create an SSH Control Master process (man:ssh_config(5)) so that
        # commands run on this host can reuse the same SSH connection.
        self._control_path = os.path.join(paths.cf_remote_dir(), "%C")
        control_master_args = [
            "ssh",
            "-M",
            "-N",
            "-p %s" % self.ssh_port,
            "-oControlPath=%s" % self._control_path,
        ]
        control_master_args.extend(aramid.DEFAULT_SSH_ARGS)
        control_master_args.append("%s@%s" % (self.ssh_user, self.ssh_host))

        log.debug(
            "Attempting to open SSH Control Master process with command: %s"
            % " ".join(control_master_args)
        )
        self._ssh_control_master = subprocess.Popen(
            control_master_args, stderr=subprocess.DEVNULL  # stdout=subprocess.DEVNULL,
        )

        self.needs_sudo = self.run("echo $UID", hide=True).stdout.strip() != "0"
        self.switch_user_needs_password = self.switch_user.needs_password_on(self)
        log.debug("Connection initialized")

    def __del__(self):
        # If we have an SSH Control Master running, signal it to terminate.
        if (
            self._ssh_control_master is not None
            and self._ssh_control_master.poll() is None
        ):
            self._ssh_control_master.send_signal(signal.SIGTERM)

    def run(self, command, hide=False, stdin_input=None):
        extra_ssh_args = []
        if self._connect_kwargs and "key_filename" in self._connect_kwargs:
            extra_ssh_args.extend(["-i", self._connect_kwargs["key_filename"]])

        # If the Control Master process is running (poll() returns None), let's
        # reuse its connection.
        if (
            self._ssh_control_master is not None
            and self._ssh_control_master.poll() is None
        ):
            log.debug("Control Master is running, using it")
            extra_ssh_args.extend(["-oControlPath=%s" % self._control_path])

        ahost = aramid.Host(self.ssh_host, self.ssh_user, self.ssh_port, extra_ssh_args)
        results = aramid.execute(
            [ahost], command, echo=(not hide), stdin_input=stdin_input
        )
        return results[ahost][0]

    def put(self, src, hide=False):
        dst = os.path.basename(src)
        ahost = aramid.Host(self.ssh_host, self.ssh_user, self.ssh_port)
        results = aramid.put([ahost], src, dst=dst, echo=(not hide))
        return results[ahost][0].retcode

    def __enter__(self, *args, **kwargs):
        return self

    def __exit__(self, *args, **kwargs):
        pass


def _build_ssh_config():
    configs = read_json(SSH_CONFIGS_JSON_FPATH)

    os.makedirs(os.path.dirname(SSH_CONFIG_FPATH), exist_ok=True)
    with open(SSH_CONFIG_FPATH, "w") as f:
        if configs is not None:
            for config in configs.values():
                f.write(config)


def host_is_vagrant(host):

    config = read_json(CLOUD_STATE_FPATH)

    if config is None:
        return False

    for group in config.values():
        for curr_host in group.keys():
            if curr_host == host and group["meta"]["provider"] == "vagrant":
                return True

    return False


def get_state_from_host(host):

    config = read_json(CLOUD_STATE_FPATH)
    if config is None:
        return False

    for group in config.values():
        for curr_host, data in group.items():
            if curr_host == host:
                return data


def connect(host, users=None, switch_user=None):
    log.debug("Connecting to '%s'" % host)
    log.debug("users= '%s'" % users)

    parts = urlparse("ssh://%s" % host)
    host = parts.hostname
    if not users and parts.username:
        users = [parts.username]
    port = parts.port or aramid._DEFAULT_SSH_PORT

    if host_is_vagrant(host):
        users = ["vagrant"]

    if not users:
        users = [
            "Administrator",
            "admin",
            "ubuntu",
            "ec2-user",
            "centos",
            "vagrant",
            "root",
        ]
        # Similar to ssh, try own username first,
        # some systems will lock us out if we have too many failed attempts.
        if whoami() not in users:
            users = [whoami()] + users
    for user in users:
        try:
            log.debug("Attempting ssh: %s@%s:%s" % (user, host, port))
            connect_kwargs = {}
            key = os.getenv("CF_REMOTE_SSH_KEY")
            if key:
                connect_kwargs["key_filename"] = os.path.expanduser(key)
            c = Connection(
                host=host,
                user=user,
                port=port,
                connect_kwargs=connect_kwargs,
                switch_user=switch_user,
            )
            c.ssh_user = user
            c.ssh_host = host
            c.ssh_port = port
            c.run("whoami", hide=True)
            return c
        except UnreachableHostError as e:
            # Host is down, trying other usernames won't help. Must raise
            # rather than sys.exit(): install() calls connect() inside a
            # multiprocessing.dummy.Pool worker thread, where a SystemExit
            # is silently swallowed and pool.map() hangs forever instead.
            raise CFRUserError(str(e)) from e
        except aramid.ExecutionError:
            continue
    raise CFRUserError("Could not ssh into '%s'" % host)


# Decorator to make a function automatically connect
# Requires that first positional argument is host
# and connection should be a keyword argument with default None
# Uses a context manager (with) to ensure connections are closed
#
# A 'switch_user' keyword argument, like 'users', is read here to make the
# connection with. A connection we are given already carries the one it was
# made with, so it is only of interest when we make one ourselves.
def auto_connect(func):
    log.debug("Building config file")
    _build_ssh_config()

    def connect_wrapper(host, *args, **kwargs):
        switch_user = kwargs.get("switch_user")
        if not kwargs.get("connection"):
            if host == "localhost":
                kwargs["connection"] = LocalConnection(switch_user=switch_user)
                return func(host, *args, **kwargs)
            with connect(
                host, users=kwargs.get("users"), switch_user=switch_user
            ) as connection:
                assert connection
                kwargs["connection"] = connection
                return func(host, *args, **kwargs)
        return func(host, *args, **kwargs)

    return connect_wrapper


def scp(file, remote, connection=None, rename=None, hide=False, switch_user=None):
    if not connection:
        with connect(remote, switch_user=switch_user) as connection:
            scp(file, remote, connection, rename, hide=hide)
    else:
        if not hide:
            print("Copying: '%s' to '%s'" % (file, remote))
        connection.put(file, hide=hide)
        if rename:
            file = os.path.basename(file)
            if file == rename:
                return 0
            if not hide:
                print("Renaming '%s' -> '%s' on '%s'" % (file, rename, remote))
            ssh_cmd(connection, "mv %s %s" % (file, rename))
    return 0


def ssh_cmd(connection, cmd, errors=False, needs_pty=True) -> Union[str, None]:
    assert connection

    if needs_pty:
        cmd = "script -qec %s /dev/null" % shlex.quote(cmd)

    result = connection.run(cmd, hide=True)
    if result.retcode == 0:
        output = result.stdout.replace("\r\n", "\n").strip("\n")
        log.debug("'%s' -> '%s'" % (cmd, output))
        return output
    else:
        msg = "Non-sudo command unexpectedly exited: '%s' [%d]" % (cmd, result.retcode)
        if errors:
            print(result.stdout if result.stdout is not None else "")
            print(result.stderr if result.stderr is not None else "")
            log.error(msg)
        else:
            log.debug(result.stdout if result.stdout is not None else "")
            log.debug(result.stderr if result.stderr is not None else "")
            log.debug(msg)
        return None


def _switch_user_hint(connection, result):
    """Explain a switch user failure caused by the password, if that's what it is"""
    output = (result.stdout or "") + (result.stderr or "")
    output = output.lower()

    if "try again" in output or "incorrect password" in output:
        return "Password for switching user was rejected on '%s'" % connection.ssh_host

    # C locale wordings, which SWITCH_USER_LOCALE is what guarantees. The
    # default command says "a password is required" (both wordings sudo has
    # used), the other two are what a command given with
    # --switch-user-command says when it wants to ask on a terminal
    needs_password = (
        "a password is required" in output
        or "a terminal is required" in output
        or "no tty present" in output
    )
    if needs_password:
        if connection.switch_user.password is None:
            return (
                "Switching user requires a password on '%s',"
                " rerun with --ask-pass to be prompted for it" % connection.ssh_host
            )
        return (
            "Switching user asked for a password on '%s' after reporting that"
            " it didn't need one, so none was sent" % connection.ssh_host
        )

    return None


def ssh_sudo(connection, cmd, errors=False, needs_pty=False):
    assert connection

    stdin_input = None
    if connection.needs_sudo:
        cmd = connection.switch_user.wrap(cmd)
        password = connection.switch_user.password
        if connection.switch_user_needs_password and password is not None:
            stdin_input = password + "\n"

    if needs_pty:
        cmd = "script -qec %s /dev/null" % shlex.quote(cmd)

    result = connection.run(cmd, hide=True, stdin_input=stdin_input)

    if result.retcode == 0:
        output = result.stdout.strip("\n")
        log.debug("'%s' -> '%s'" % (cmd, output))
        return output
    else:
        msg = "Sudo command unexpectedly exited: '%s' [%d]" % (cmd, result.retcode)
        hint = _switch_user_hint(connection, result)
        if hint:
            log.error(hint)
        if errors:
            print(result.stdout if result.stdout is not None else "")
            print(result.stderr if result.stderr is not None else "")
            log.error(msg)
        else:
            log.debug(result.stdout if result.stdout is not None else "")
            log.debug(result.stderr if result.stderr is not None else "")
            log.debug(msg)
        return None
