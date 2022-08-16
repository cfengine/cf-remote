from cf_remote.ssh import auto_connect, ssh_cmd

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
