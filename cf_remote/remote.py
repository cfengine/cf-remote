#!/usr/bin/env python3
import sys
import re
from os.path import basename
from collections import OrderedDict

from cf_remote.utils import (
    os_release,
    column_print,
    pretty,
    user_error,
    parse_systeminfo,
    parse_version,
)
from cf_remote.ssh import ssh_sudo, ssh_cmd, scp, auto_connect
from cf_remote import log
from cf_remote.web import download_package
from cf_remote.packages import Releases, Artifact, filter_artifacts

import cf_remote.demo as demo_lib


def powershell(cmd):
    assert '"' not in cmd  # TODO: How to escape in cmd / powershell
    # Note: Have to use double quotes, because single quotes are different
    #       in cmd
    return r'powershell.exe -Command "{}"'.format(cmd)


def os_name_pretty(data):
    id = None
    redhat_release = data.get("redhat_release")
    os_release = data.get("os_release")
    if redhat_release:
        id = redhat_release.split(" ")[0]
    elif os_release:
        id = os_release["ID"]

    if id:
        if id.lower() == "red" or id.lower() == "rhel":
            return "RHEL"
        if id.lower() == "centos":
            return "CentOS"
        if id.lower() == "sles" or id.lower() == "suse" or id.lower() == "opensuse":
            return "SUSE"
        return id.capitalize()

    systeminfo = data.get("systeminfo")
    if systeminfo:
        return "Windows"

    uname = data.get("uname")
    if uname:
        return uname

    return "Unknown"


def os_version_major(data):
    redhat_release = data.get("redhat_release")
    if redhat_release:
        match = re.search(r"[1-9][0-9]*", redhat_release)
        if match:
            return match.group(0)

    os_release = data.get("os_release")
    if os_release and "VERSION_ID" in os_release:
        return os_release["VERSION_ID"].split(".")[0]

    systeminfo = data.get("systeminfo")
    if systeminfo and "OS Name" in systeminfo:
        match = re.search(r"[1-9][0-9]*", systeminfo["OS Name"])
        if match:
            return match.group(0)

    return None


def print_info(data):
    output = OrderedDict()
    print()
    print(data["ssh"])

    os_name = os_name_pretty(data)
    os_version = os_version_major(data)
    output["OS"] = os_name + (" " + os_version if os_version else "")

    if "arch" in data:
        output["Architecture"] = data["arch"]

    agent_version = data["agent_version"]
    if agent_version:
        output["CFEngine"] = agent_version
    else:
        output["CFEngine"] = "Not installed"

    output["Policy server"] = data.get("policy_server")

    binaries = []
    if "bin" in data:
        for key in data["bin"]:
            binaries.append(key)
    if binaries:
        output["Binaries"] = ", ".join(binaries)

    column_print(output)
    print()


def transfer_file(host, file, users=None, connection=None):
    assert not users or len(users) == 1
    if users:
        host = users[0] + "@" + host
    return scp(file=file, remote=host, connection=connection)


@auto_connect
def run_command(host, command, *, users=None, connection=None, sudo=False):
    if sudo:
        return ssh_sudo(connection, command, errors=True)
    return ssh_cmd(connection, command, errors=True)


def get_package_tags(os_release=None, redhat_release=None):
    tags = []
    if os_release is not None:
        distro = os_release["ID"]
        major = os_release["VERSION_ID"].split(".")[0]
        platform_tag = distro + major

        # Add tags with version number first, to filter by them first:
        tags.append(platform_tag)  # Example: ubuntu16
        if distro == "centos" or distro == "rhel":
            tags.append("el" + major)

        # Then add more generic tags (lower priority):
        tags.append(distro)  # Example: ubuntu
        if distro == "centos":
            tags.append("rhel")

        if distro == "centos" or distro == "rhel":
            tags.append("el")
    elif redhat_release is not None:
        # Examples:
        # CentOS release 6.10 (Final)
        # Red Hat Enterprise Linux release 8.0 (Ootpa)
        before, after = redhat_release.split(" release ")
        distro = "rhel"
        if before.lower().startswith("centos"):
            distro = "centos"
        major = after.split(".")[0]
        tags.append(distro + major)
        tags.append("el" + major)
        if "rhel" not in tags:
            tags.append("rhel" + major)

        tags.append(distro)
        if "rhel" not in tags:
            tags.append("rhel")
        tags.append("el")

    return tags


@auto_connect
def get_info(host, *, users=None, connection=None):
    log.debug("Getting info about '{}'".format(host))

    user, host = connection.ssh_user, connection.ssh_host
    data = OrderedDict()
    data["ssh_user"] = user
    data["ssh_host"] = host
    data["ssh"] = "{}@{}".format(user, host)
    data["whoami"] = ssh_cmd(connection, "whoami")
    systeminfo = ssh_cmd(connection, "systeminfo")
    if systeminfo:
        data["os"] = "windows"
        data["systeminfo"] = parse_systeminfo(systeminfo)
        data["package_tags"] = ["x86_64", "msi"]
        data["arch"] = "x86_64"
        agent = r"& 'C:\Program Files\Cfengine\bin\cf-agent.exe'"
        data["agent"] = agent
        version_cmd = powershell("{} -V".format(agent))
        data["agent_version"] = parse_version(ssh_cmd(connection, version_cmd))
    else:
        data["os"] = "unix"
        data["uname"] = ssh_cmd(connection, "uname")
        data["arch"] = ssh_cmd(connection, "uname -m")
        data["os_release"] = os_release(ssh_cmd(connection, "cat /etc/os-release"))

        os_release_data = data.get("os_release")
        redhat_release_data = None
        if not os_release_data:
            redhat_release_data = ssh_cmd(connection, "cat /etc/redhat-release")
            data["redhat_release"] = redhat_release_data

        data["package_tags"] = get_package_tags(os_release_data, redhat_release_data)

        data["agent_location"] = ssh_cmd(connection, "which cf-agent")
        data["policy_server"] = ssh_cmd(
            connection, "cat /var/cfengine/policy_server.dat"
        )

        agent = r"/var/cfengine/bin/cf-agent"
        data["agent"] = agent
        data["agent_version"] = parse_version(
            ssh_cmd(connection, "{} --version".format(agent))
        )

        data["bin"] = {}
        for bin in ["dpkg", "rpm", "yum", "apt", "pkg"]:
            path = ssh_cmd(connection, "which {}".format(bin))
            if path:
                data["bin"][bin] = path

    log.debug("JSON data from host info: \n" + pretty(data))
    return data


@auto_connect
def install_package(host, pkg, data, *, connection=None):

    print("Installing: '{}' on '{}'".format(pkg, host))
    if ".deb" in pkg:
        output = ssh_sudo(connection, "dpkg -i {}".format(pkg), True)
    elif ".msi" in pkg:
        # Windows is crazy, be careful if you decide to change this;
        # This needs to work in both powershell and cmd, and in
        # Windows 2012 Server, 2016, and so on...
        # sleep is powershell specific,
        # timeout doesn't work over ssh.
        output = ssh_cmd(connection, powershell(r".\{} ; sleep 10".format(pkg)), True)
    else:
        output = ssh_sudo(connection, "yum -y install {}".format(pkg), True)
    if output is None:
        log.error("Installation failed on '{}'".format(host))

    return output is not None


@auto_connect
def uninstall_cfengine(host, data, *, connection=None):
    print("Uninstalling CFEngine on '{}'".format(host))

    if "dpkg" in data["bin"]:
        run_command(
            host,
            "dpkg --remove cfengine-community || true",
            connection=connection,
            sudo=True,
        )
        run_command(
            host,
            "dpkg --remove cfengine-nova || true",
            connection=connection,
            sudo=True,
        )
        run_command(
            host,
            "dpkg --remove cfengine-nova-hub || true",
            connection=connection,
            sudo=True,
        )
    elif "rpm" in data["bin"]:
        run_command(
            host,
            "rpm --erase cfengine-community || true",
            connection=connection,
            sudo=True,
        )
        run_command(
            host, "rpm --erase cfengine-nova || true", connection=connection, sudo=True
        )
        run_command(
            host,
            "rpm --erase cfengine-nova-hub || true",
            connection=connection,
            sudo=True,
        )
    else:
        user_error("I don't know how to uninstall there!")

    run_command(host, "pkill -U cfapache || true", connection=connection, sudo=True)
    run_command(
        host, "rm -rf /var/cfengine /opt/cfengine", connection=connection, sudo=True
    )


@auto_connect
def bootstrap_host(host_data, policy_server, *, connection=None, trust_server=True):
    host = host_data["ssh_host"]
    agent = host_data["agent"]
    print("Bootstrapping: '{}' -> '{}'".format(host, policy_server))
    command = "{} --bootstrap {}".format(agent, policy_server)
    if not trust_server:
        command += " --trust-server=no"
    if host_data["os"] == "windows":
        output = ssh_cmd(connection, powershell(command))
    else:
        output = ssh_sudo(connection, command)

    if output is None:
        sys.exit("Bootstrap failed on '{}'".format(host))
    if output and "completed successfully" in output:
        print("Bootstrap successful: '{}' -> '{}'".format(host, policy_server))
        return True
    else:
        log.error("Something went wrong while bootstrapping")
        return False


def _package_from_list(tags, extension, packages):
    artifacts = [Artifact(None, p) for p in packages]
    artifact = filter_artifacts(artifacts, tags, extension)[-1]
    return artifact.url


def _package_from_releases(tags, extension, version, edition, remote_download):
    log.debug("Looking for a package from releases based on host tags: {}".format(tags))
    releases = Releases(edition)
    release = releases.default
    if version:
        release = releases.pick_version(version)

    release.init_download()

    if not release.artifacts:
        log.error(
            "The {} {} release is empty, visit tracker.mender.io to file a bug report".format(
                version, edition
            )
        )
        return None

    artifacts = release.find(tags, extension)
    if not artifacts:
        log.error(
            "Could not find an appropriate package for host, please use --{}-package".format(
                "hub" if "hub" in tags else "client"
            )
        )
        return None
    artifact = artifacts[-1]
    if remote_download:
        return artifact.url
    else:
        return download_package(artifact.url)


def get_package_from_host_info(
    package_tags,
    pkg_binary,
    arch,
    version=None,
    hub=False,
    edition="enterprise",
    packages=None,
    remote_download=False,
):
    tags = []
    if edition == "enterprise":
        tags.append("hub" if hub else "agent")

    tags.append("64" if arch in ("x86_64", "amd64", "aarch64") else arch)
    if arch == "aarch64":
        tags.append("arm64")
    if arch in ("i386", "i486", "i586", "i686"):
        tags.append("32")
    if arch in ("x86_64", "amd64"):
        tags.append(arch)

    extension = None
    if package_tags is not None and "msi" in package_tags:
        extension = ".msi"
    elif "dpkg" in pkg_binary:
        extension = ".deb"
    elif "rpm" in pkg_binary:
        extension = ".rpm"

    if package_tags is not None:
        tags.extend(tag for tag in package_tags if tag != "msi")

    if packages is None:  # No command line argument given
        package = _package_from_releases(
            tags, extension, version, edition, remote_download
        )
    else:
        package = _package_from_list(tags, extension, packages)

    return package


@auto_connect
def install_host(
    host,
    *,
    hub=False,
    packages=None,
    bootstrap=None,
    version=None,
    demo=False,
    call_collect=False,
    connection=None,
    edition=None,
    show_info=True,
    remote_download=False,
    trust_keys=None
):

    data = get_info(host, connection=connection)
    if show_info:
        print_info(data)

    package = None
    if packages and type(packages) is str:
        package = packages
    elif packages and len(packages) == 1:
        package = packages[0]

    if not package:
        package = get_package_from_host_info(
            data.get("package_tags"),
            data.get("bin"),
            data.get("arch"),
            version,
            hub,
            edition,
            packages,
            remote_download,
        )

    if not package:
        log.error("Installation failed - no package found!")
        return 1

    if remote_download:
        print("Downloading '%s' on '%s' using curl" % (package, host))
        r = ssh_cmd(
            cmd="curl --fail -O {}".format(package), connection=connection, errors=True
        )
        if r is None:
            return 1
        package = basename(package)
    elif not getattr(connection, "is_local", False):
        scp(package, host, connection=connection)
        package = basename(package)

    success = install_package(host, package, data, connection=connection)
    if not success:
        # errors already logged
        return 1

    data = get_info(host, connection=connection)
    if data["agent_version"] and len(data["agent_version"]) > 0:
        print(
            "CFEngine {} was successfully installed on '{}'".format(
                data["agent_version"], host
            )
        )
    else:
        log.error("Installation failed!")
        return 1

    if trust_keys:
        for key in trust_keys:
            scp(key, host, connection=connection)
            run_command(
                host,
                "mv %s /var/cfengine/ppkeys/" % basename(key),
                connection=connection,
                sudo=True,
            )

    if bootstrap:
        ret = bootstrap_host(
            data,
            policy_server=bootstrap,
            connection=connection,
            trust_server=(not trust_keys),
        )
        if not ret:
            return 1
    if demo:
        if hub:
            demo_lib.install_def_json(
                host, connection=connection, call_collect=call_collect
            )
            demo_lib.agent_run(data, connection=connection)
            demo_lib.disable_password_dialog(host)
        demo_lib.agent_run(data, connection=connection)
    return 0


class HostInstaller:
    def __init__(self, *args, **kwargs):
        self._args = args
        self._kwargs = kwargs
        self._errors = None

    def run(self):
        self._errors = install_host(*self._args, **self._kwargs)

    @property
    def errors(self):
        return self._errors


@auto_connect
def uninstall_host(host, *, connection=None):
    data = get_info(host, connection=connection)
    print_info(data)

    if not data["agent_version"]:
        log.warning(
            "CFEngine does not seem to be installed on '{}' - attempting uninstall anyway".format(
                host
            )
        )

    uninstall_cfengine(host, data, connection=connection)
    data = get_info(host, connection=connection)

    if (not data) or data["agent_version"]:
        log.error("Failed to uninstall CFEngine on '{}'".format(host))
        return 1

    print_info(data)

    print("Uninstallation successful on '{}'".format(host))
    return 0


@auto_connect
def deploy_masterfiles(host, tarball, *, connection=None):
    data = get_info(host, connection=connection)
    print("\nDeploying to:")
    print_info(data)
    if not data["agent_version"]:
        log.error("Cannot deploy masterfiles on %s - CFEngine not installed" % host)
        return 1

    if not getattr(connection, "is_local", False):
        scp(tarball, host, connection=connection, rename="masterfiles.tgz")
        tarball = "masterfiles.tgz"
    ssh_cmd(connection, "tar -xzf %s" % tarball)
    commands = [
        "rm -rf /var/cfengine/masterfiles.delete",
        "mv /var/cfengine/masterfiles /var/cfengine/masterfiles.delete",
        "mv masterfiles /var/cfengine/masterfiles",
        "rm -rf /var/cfengine/masterfiles.delete",
        "cf-agent -Kf update.cf",
        "cf-agent -K",
    ]
    combined = " && ".join(commands)
    print("Running: '%s'" % combined)
    ssh_sudo(connection, combined)
    print("Policy set successfully deployed to '%s' 🚀" % host)
    return 0
