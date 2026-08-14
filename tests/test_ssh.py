import shlex

import pytest

from cf_remote import ssh
from cf_remote.aramid import ExecutionResult
from cf_remote.ssh import auto_connect, ssh_cmd
from cf_remote.utils import CFRUserError

# for debugging, uncomment the following two lines
# from cf_remote import log
# log.set_level("debug")


@auto_connect
def whoami(host, *, users=None, connection=None):
    ssh_cmd(connection, "whoami")


@auto_connect
def nope(host, *, users=None, connection=None):
    ssh_cmd(connection, "nope")


def test_ssh_localhost():
    whoami("localhost")


def test_failed_command():
    nope("localhost")


@pytest.fixture(autouse=True)
def reset_switch_user():
    """Keep the switch user settings from leaking between tests"""
    yield
    ssh.set_switch_user_command(None)
    ssh.set_switch_user_password(None)


def test_switch_user_default():
    assert ssh.switch_user("cf-agent -K") == "sudo bash -c 'cf-agent -K'"


def test_switch_user_with_password():
    # With a password to send, sudo has to read it from standard input
    ssh.set_switch_user_password("hunter2")
    assert ssh.switch_user("cf-agent -K") == "sudo -S -p '' bash -c 'cf-agent -K'"


def test_switch_user_command_overrides_default():
    ssh.set_switch_user_command("doas -n /bin/sh -c")
    assert ssh.switch_user("cf-agent -K") == "doas -n /bin/sh -c 'cf-agent -K'"

    # ... also when a password is given, then it's up to the user to make the
    # command read it from standard input
    ssh.set_switch_user_password("hunter2")
    assert ssh.switch_user("cf-agent -K") == "doas -n /bin/sh -c 'cf-agent -K'"


def test_switch_user_survives_quotes_in_the_command():
    # A command carrying quotes of its own must not end the wrapping early.
    # Splitting it back the way a shell would proves it arrives in one piece.
    for cmd in ("echo it's fine", 'echo "double"', "echo 'mixed \"quotes\"'"):
        assert shlex.split(ssh.switch_user(cmd))[-1] == cmd


def _password_file(tmp_path, content, mode=0o600):
    path = tmp_path / "password"
    path.write_text(content)
    path.chmod(mode)
    return str(path)


def test_password_file_drops_the_trailing_newline(tmp_path):
    path = _password_file(tmp_path, "hunter2\n")
    assert ssh.read_switch_user_password(path) == "hunter2"


def test_password_file_keeps_the_rest_of_the_line(tmp_path):
    # A password may well end in a space, only the editor's newline goes
    path = _password_file(tmp_path, "hunter2 \r\nignored second line\n")
    assert ssh.read_switch_user_password(path) == "hunter2 "


def test_password_file_readable_by_others_is_refused(tmp_path):
    path = _password_file(tmp_path, "hunter2\n", mode=0o644)
    with pytest.raises(CFRUserError, match="readable by others"):
        ssh.read_switch_user_password(path)


def test_missing_password_file_is_refused(tmp_path):
    with pytest.raises(CFRUserError, match="does not exist"):
        ssh.read_switch_user_password(str(tmp_path / "nope"))


class FakeConnection:
    ssh_host = "somehost"
    needs_sudo = True
    switch_user_needs_password = False

    def __init__(self, retcode=0):
        self.retcode = retcode
        self.commands = []

    def run(self, command, hide=False, stdin_input=None):
        self.commands.append((command, stdin_input))
        return ExecutionResult(command, self.retcode, "", "")


def test_no_password_means_no_asking():
    connection = FakeConnection()
    assert ssh._switch_user_needs_password(connection) is False
    assert connection.commands == []


def test_root_is_never_asked():
    # Nothing to switch to, so no round trip and nothing to send
    ssh.set_switch_user_password("hunter2")
    connection = FakeConnection()
    connection.needs_sudo = False

    assert ssh._switch_user_needs_password(connection) is False
    assert connection.commands == []


def test_asking_never_attempts_authentication():
    # A failed attempt is what pam_faillock counts, so this must not make one
    ssh.set_switch_user_password("hunter2")

    connection = FakeConnection(retcode=1)
    assert ssh._switch_user_needs_password(connection) is True
    assert connection.commands == [("sudo -n true", None)]

    connection = FakeConnection(retcode=0)
    assert ssh._switch_user_needs_password(connection) is False
    assert connection.commands == [("sudo -n true", None)]


def test_password_goes_on_standard_input():
    ssh.set_switch_user_password("hunter2")
    connection = FakeConnection()
    connection.switch_user_needs_password = True

    ssh.ssh_sudo(connection, "id -un")
    assert connection.commands == [("sudo -S -p '' bash -c 'id -un'", "hunter2\n")]


def test_password_is_withheld_where_it_isnt_needed():
    # Otherwise it ends up on the standard input of the command instead
    ssh.set_switch_user_password("hunter2")
    connection = FakeConnection()
    connection.switch_user_needs_password = False

    ssh.ssh_sudo(connection, "id -un")
    assert connection.commands == [("sudo -S -p '' bash -c 'id -un'", None)]


def test_own_switch_user_command_is_asked_with_empty_input():
    # Assuming it wants a password would hand the password to whatever runs
    # when it doesn't, so ask, with nothing it could mistake for one
    ssh.set_switch_user_password("hunter2")
    ssh.set_switch_user_command("doas /bin/sh -c")

    connection = FakeConnection(retcode=0)
    assert ssh._switch_user_needs_password(connection) is False
    assert connection.commands == [("doas /bin/sh -c true", "")]

    connection = FakeConnection(retcode=1)
    assert ssh._switch_user_needs_password(connection) is True


def _failure(stderr):
    return ExecutionResult("some command", 1, "", stderr)


def test_switch_user_hint_suggests_ask_pass():
    result = _failure("sudo: a terminal is required to read the password")
    hint = ssh._switch_user_hint(FakeConnection(), result)
    assert hint is not None
    assert "--ask-pass" in hint
    assert "somehost" in hint


def test_switch_user_hint_reports_rejected_password():
    ssh.set_switch_user_password("hunter2")
    result = _failure("Sorry, try again.\nsudo: 1 incorrect password attempt")
    hint = ssh._switch_user_hint(FakeConnection(), result)
    assert hint is not None
    assert "rejected" in hint


def test_switch_user_hint_reports_password_that_was_never_sent():
    # Asking said no password was needed, but the command disagreed
    ssh.set_switch_user_password("hunter2")
    result = _failure("sudo: a password is required")
    hint = ssh._switch_user_hint(FakeConnection(), result)
    assert hint is not None
    assert "none was sent" in hint


def test_switch_user_hint_ignores_unrelated_failures():
    result = _failure("dpkg: error processing archive")
    assert ssh._switch_user_hint(FakeConnection(), result) is None
