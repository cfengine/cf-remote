import os
import sys
import pwd
import shutil
import signal
import subprocess
from urllib.parse import urlparse

from cf_remote import aramid
from cf_remote import log
from cf_remote import paths
from cf_remote.utils import whoami, read_json
from cf_remote.aramid import ExecutionResult
from cf_remote.paths import SSH_CONFIG_FPATH, SSH_CONFIGS_JSON_FPATH, CLOUD_STATE_FPATH


class LocalConnection:
    is_local = True
    ssh_user = None
    ssh_host = "localhost"

    def __init__(self):
        self.ssh_user = pwd.getpwuid(os.getuid()).pw_name
        self.needs_sudo = self.run("echo $UID", hide=True).stdout.strip() != "0"

    def run(self, command, hide=False):
        # to maintain Python 3.5/3.6 compatability the following are used:
        # stdout=PIPE, stderr=STDOUT instead of capture_output=True
        # universal_newlines=True instead of text=True
        result = subprocess.run(
            command,
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
    def __init__(self, host, user, connect_kwargs=None, port=aramid._DEFAULT_SSH_PORT):
        log.debug(
            "Initializing Connection: host '%s' user '%s' port '%s'"
            % (host, user, port)
        )

        self.ssh_host = host
        self.ssh_port = port
        self.ssh_user = user
        self._connect_kwargs = connect_kwargs

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
        log.debug("Connection initialized")

    def __del__(self):
        # If we have an SSH Control Master running, signal it to terminate.
        if (
            self._ssh_control_master is not None
            and self._ssh_control_master.poll() is None
        ):
            self._ssh_control_master.send_signal(signal.SIGTERM)

    def run(self, command, hide=False):
        extra_ssh_args = []
        if self._connect_kwargs and "key_filename" in self._connect_kwargs:
            extra_ssh_args.extend(["-i", self._connect_kwargs["key_filename"]])

        # If the Control Master process is running (poll() returns None), let's
        # reuse its connection.
        if self._ssh_control_master.poll() is None:
            log.debug("Control Master is running, using it")
            extra_ssh_args.extend(["-oControlPath=%s" % self._control_path])

        ahost = aramid.Host(self.ssh_host, self.ssh_user, self.ssh_port, extra_ssh_args)
        results = aramid.execute([ahost], command, echo=(not hide))
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


def connect(host, users=None):
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
                host=host, user=user, port=port, connect_kwargs=connect_kwargs
            )
            c.ssh_user = user
            c.ssh_host = host
            c.ssh_port = port
            c.run("whoami", hide=True)
            return c
        except aramid.ExecutionError:
            continue
    sys.exit("Could not ssh into '%s'" % host)


# Decorator to make a function automatically connect
# Requires that first positional argument is host
# and connection should be a keyword argument with default None
# Uses a context manager (with) to ensure connections are closed
def auto_connect(func):
    log.debug("Building config file")
    _build_ssh_config()

    def connect_wrapper(host, *args, **kwargs):
        if not kwargs.get("connection"):
            if host == "localhost":
                kwargs["connection"] = LocalConnection()
                return func(host, *args, **kwargs)
            with connect(host, users=kwargs.get("users")) as connection:
                assert connection
                kwargs["connection"] = connection
                return func(host, *args, **kwargs)
        return func(host, *args, **kwargs)

    return connect_wrapper


def scp(file, remote, connection=None, rename=None, hide=False):
    if not connection:
        with connect(remote) as connection:
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


def ssh_cmd(connection, cmd, errors=False, needs_pty=True):
    assert connection

    if needs_pty:
        cmd = 'script -qec "%s" /dev/null' % cmd

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


def ssh_sudo(connection, cmd, errors=False, needs_pty=False):
    assert connection

    if connection.needs_sudo:
        cmd = "sudo bash -c '%s'" % cmd

    if needs_pty:
        cmd = 'script -qec "%s" /dev/null' % cmd

    result = connection.run(cmd, hide=True)

    if result.retcode == 0:
        output = result.stdout.strip("\n")
        log.debug("'%s' -> '%s'" % (cmd, output))
        return output
    else:
        msg = "Sudo command unexpectedly exited: '%s' [%d]" % (cmd, result.retcode)
        if errors:
            print(result.stdout if result.stdout is not None else "")
            print(result.stderr if result.stderr is not None else "")
            log.error(msg)
        else:
            log.debug(result.stdout if result.stdout is not None else "")
            log.debug(result.stderr if result.stderr is not None else "")
            log.debug(msg)
        return None
