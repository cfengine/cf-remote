import os
import sys
import pwd
import shutil
import subprocess

from cf_remote import aramid
from cf_remote import log
from cf_remote.utils import whoami


class LocalConnection:
    is_local = True
    ssh_user = None
    ssh_host = "localhost"

    def __init__(self):
        self.ssh_user = pwd.getpwuid(os.getuid()).pw_name

    def run(self, command, hide=False):
        return subprocess.run(command, capture_output=True, shell=True, text=True)

    def put(self, src):
        src = os.path.abspath(src)
        dst = os.path.basename(src)
        if src != dst:
            shutil.copy(src, dst)


class Connection:
    def __init__(self, host, user, connect_kwargs=None):
        self.ssh_host = host
        self.ssh_user = user
        self._connect_kwargs = connect_kwargs

    def run(self, command, hide=False):
        extra_ssh_args = []
        if "key_filename" in self._connect_kwargs:
            extra_ssh_args.extend(["-i", self._connect_kwargs["key_filename"]])

        ahost = aramid.Host(self.ssh_host, self.ssh_user, extra_ssh_args)
        results = aramid.execute([ahost], command, echo=(not hide))
        return results[ahost][0]

    def put(self, src):
        dst = os.path.basename(src)
        ahost = aramid.Host(self.ssh_host, self.ssh_user)
        results = aramid.put([ahost], src, dst)
        return results[ahost][0].retcode

    def __enter__(self, *args, **kwargs):
        return self

    def __exit__(self, *args, **kwargs):
        pass


def connect(host, users=None):
    log.debug(f"Connecting to '{host}'")
    log.debug(f"users= '{users}'")
    if "@" in host:
        parts = host.split("@")
        assert len(parts) == 2
        host = parts[1]
        if not users:
            users = [parts[0]]
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
            log.debug(f"Attempting ssh: {user}@{host}")
            connect_kwargs = {}
            key = os.getenv("CF_REMOTE_SSH_KEY")
            if key:
                connect_kwargs["key_filename"] = os.path.expanduser(key)
            c = Connection(host=host, user=user, connect_kwargs=connect_kwargs)
            c.ssh_user = user
            c.ssh_host = host
            c.run("whoami", hide=True)
            return c
        except aramid.ExecutionError:
            continue
    sys.exit(f"Could not ssh into '{host}'")


# Decorator to make a function automatically connect
# Requires that first positional argument is host
# and connection should be a keyword argument with default None
# Uses a context manager (with) to ensure connections are closed
def auto_connect(func):
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


def scp(file, remote, connection=None, rename=None):
    if not connection:
        with connect(remote) as connection:
            scp(file, remote, connection, rename)
    else:
        print(f"Copying: '{file}' to '{remote}'")
        connection.put(file)
        if rename:
            file = os.path.basename(file)
            if file == rename:
                return 0
            print(f"Renaming '{file}' -> '{rename}' on '{remote}'")
            ssh_cmd(connection, f"mv {file} {rename}")
    return 0


def ssh_cmd(connection, cmd, errors=False):
    assert connection

    log.debug(f"Running over SSH: '{cmd}'")
    result = connection.run(cmd, hide=True)
    if result.retcode == 0:
        output = result.stdout.replace("\r\n", "\n").strip("\n")
        log.debug(f"'{cmd}' -> '{output}'")
        return output
    else:
        msg = f"Non-sudo command unexpectedly exited: '{cmd}' [{result.retcode}]"
        if errors:
            print(result.stdout + result.stderr)
            log.error(msg)
        else:
            log.debug(result.stdout + result.stderr)
            log.debug(msg)
        return None


def ssh_sudo(connection, cmd, errors=False):
    assert connection

    log.debug(f"Running(sudo) over SSH: '{cmd}'")
    escaped = cmd.replace('"', r"\"")
    sudo_cmd = f'sudo bash -c "{escaped}"'
    result = connection.run(sudo_cmd, hide=True)
    if result.retcode == 0:
        output = result.stdout.strip("\n")
        log.debug(f"'{cmd}' -> '{output}'")
        return output
    else:
        msg = f"Sudo command unexpectedly exited: '{cmd}' [{result.retcode}]"
        if errors:
            print(result.stdout + result.stderr)
            log.error(msg)
        else:
            log.debug(result.stdout + result.stderr)
            log.debug(msg)
        return None
