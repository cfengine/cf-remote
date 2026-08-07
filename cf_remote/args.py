import argparse
import os
import sys

from cf_remote.utils import cache


def add_info_args(sp: argparse.ArgumentParser) -> None:
    sp.add_argument(
        "--hosts", "-H", help="Which hosts to get info for", type=str, required=True
    )


def add_install_args(sp: argparse.ArgumentParser) -> None:
    sp.add_argument(
        "--edition",
        "-E",
        choices=["community", "enterprise"],
        help="Enterprise or community packages",
        type=str,
    )
    sp.add_argument(
        "--package", help="Local path to package or URL to download", type=str
    )
    sp.add_argument(
        "--hub-package",
        help="Local path to package or URL to download for --hub",
        type=str,
    )
    sp.add_argument(
        "--client-package",
        help="Local path to package or URL to download for --clients",
        type=str,
    )
    sp.add_argument("--bootstrap", "-B", help="cf-agent --bootstrap argument", type=str)
    sp.add_argument("--clients", "-c", help="Where to install client package", type=str)
    sp.add_argument("--hub", help="Where to install hub package", type=str)
    sp.add_argument(
        "--demo",
        help="Use defaults to make demos smoother (NOT secure)",
        action="store_true",
    )
    sp.add_argument(
        "--call-collect",
        help="Enable call collect in --demo def.json",
        action="store_true",
    )
    sp.add_argument(
        "--remote-download",
        help="Package will be downloaded directly to the target machine",
        action="store_true",
    )
    sp.add_argument(
        "--trust-keys",
        help="Comma-separated list of paths to keys hosts should trust"
        + " (implies '--trust-server no' when boostraping)",
        type=str,
    )
    sp.add_argument(
        "--insecure",
        help="Ignore mismatching checksums when downloading urls",
        action="store_true",
    )


def add_uninstall_args(sp: argparse.ArgumentParser) -> None:
    sp.add_argument("--purge", help="Complete uninstallation", action="store_true")
    sp.add_argument("--clients", "-c", help="Where to uninstall", type=str)
    sp.add_argument("--hub", help="Where to uninstall", type=str)
    sp.add_argument("--hosts", "-H", help="Where to uninstall", type=str)


def add_packages_args(sp: argparse.ArgumentParser) -> None:
    sp.add_argument(
        "--edition",
        "-E",
        choices=["community", "enterprise"],
        help="Enterprise or community packages",
        type=str,
    )
    sp.add_argument("tags", metavar="TAG", nargs="*")


def add_list_args(sp: argparse.ArgumentParser) -> None:
    sp.add_argument(
        "--edition",
        "-E",
        choices=["community", "enterprise"],
        help="Enterprise or community packages",
        type=str,
    )
    sp.add_argument("tags", metavar="TAG", nargs="*")
    sp.add_argument(
        "--allow-expired", help="Also lists expired packages", action="store_true"
    )


def add_download_args(sp: argparse.ArgumentParser) -> None:
    sp.add_argument(
        "--edition",
        "-E",
        choices=["community", "enterprise"],
        help="Enterprise or community packages",
        type=str,
    )
    sp.add_argument("tags", metavar="TAG", nargs="*")
    sp.add_argument("--output-dir", "-o", help="Where to download", type=str)
    sp.add_argument(
        "--insecure",
        help="Ignore mismatching checksums when downloading urls",
        action="store_true",
    )
    sp.add_argument(
        "--allow-expired", help="Allow expired packages", action="store_true"
    )


def add_run_args(sp: argparse.ArgumentParser) -> None:
    sp.add_argument(
        "--hosts",
        "-H",
        help="Which hosts to run the command on",
        type=str,
        required=True,
    )
    sp.add_argument(
        "--raw", help="Print only output of command itself", action="store_true"
    )
    sp.add_argument(
        "remote_command",
        help="Command to execute on remote host (including args)",
        type=str,
        nargs=1,
    )


def add_save_args(sp: argparse.ArgumentParser) -> None:
    sp.add_argument(
        "--role",
        help="Role of the hosts",
        choices=["hub", "hubs", "client", "clients"],
        required=True,
    )
    sp.add_argument(
        "--name",
        help="Name of the group of hosts (can be used in other commands)",
        required=True,
    )
    sp.add_argument(
        "--hosts",
        "-H",
        help="SSH usernames and IPs for SSH and CFEngine in the form of user@ip",
        required=True,
    )


def add_sudo_args(sp: argparse.ArgumentParser) -> None:
    sp.add_argument(
        "--hosts",
        "-H",
        help="Which hosts to run the command on",
        type=str,
        required=True,
    )
    sp.add_argument(
        "--raw", help="Print only output of command itself", action="store_true"
    )
    sp.add_argument(
        "remote_command",
        help="Command to execute on remote host (including args)",
        type=str,
        nargs=1,
    )


def add_scp_args(sp: argparse.ArgumentParser) -> None:
    sp.add_argument(
        "--hosts", "-H", help="Which hosts to copy the file to", type=str, required=True
    )
    sp.add_argument("args", help="Arguments", type=str, nargs="*")


def add_spawn_args(sp: argparse.ArgumentParser) -> None:
    sp.add_argument(
        "--list-platforms", help="List supported platforms", action="store_true"
    )
    sp.add_argument(
        "--list-boxes", help="List installed vagrant boxes", action="store_true"
    )
    sp.add_argument(
        "--init-config",
        help="Initialize configuration file for spawn functionality",
        action="store_true",
    )
    sp.add_argument("--platform", help="Platform or vagrant box to use", type=str)
    sp.add_argument("--count", default=1, help="How many hosts to spawn", type=int)
    sp.add_argument(
        "--role", help="Role of the hosts", choices=["hub", "hubs", "client", "clients"]
    )
    sp.add_argument(
        "--name", help="Name of the group of hosts (can be used in other commands)"
    )
    sp.add_argument(
        "--append",
        help="Append the new VMs to a pre-existing group",
        action="store_true",
    )
    sp.add_argument(
        "--provider",
        help="VM provider",
        type=str,
        default="aws",
        choices=["aws", "gcp", "vagrant"],
    )
    sp.add_argument("--cpus", help="Number of CPUs of the vagrant instances", type=int)
    sp.add_argument(
        "--sync-folder",
        help="Root folder of synchronized folders of vagrant instance",
        type=str,
    )
    sp.add_argument(
        "--provision",
        help="full path to provision shell script for Vagrant VM",
        type=str,
    )
    sp.add_argument("--size", help="Size/type of the instances", type=str)
    sp.add_argument(
        "--network", help="network/subnet to assign the VMs to (GCP only)", type=str
    )
    sp.add_argument(
        "--no-public-ip",
        help="No public IP needed (GCP only; WARNING: The VMs will only be accessible"
        + " from some other VM in the same cloud/network!)",
        action="store_true",
    )
    # TODO: --region (optional)


def add_show_args(sp: argparse.ArgumentParser) -> None:
    sp.add_argument(
        "--ansible-inventory",
        help="Print Ansible inventory with spawned hosts",
        action="store_true",
    )


def add_destroy_args(sp: argparse.ArgumentParser) -> None:
    sp.add_argument(
        "--all", help="Destroy all hosts spawned in the clouds", action="store_true"
    )
    sp.add_argument("name", help="Name of the group of hosts to destroy", nargs="?")


def add_deploy_args(sp: argparse.ArgumentParser) -> None:
    sp.add_argument("--hub", help="Hub(s) to deploy to", type=str)
    sp.add_argument(
        "masterfiles",
        help="Policy-set location (tarball URL or local path to tarball / directory)",
        type=str,
        nargs="?",
    )


def add_agent_args(sp: argparse.ArgumentParser) -> None:
    sp.add_argument(
        "--hosts",
        "-H",
        help="Which hosts to run cf-agent from",
        type=str,
        required=True,
    )
    sp.add_argument("--bootstrap", "-B", help="Which hub to bootstrap to", type=str)


def add_connect_args(sp: argparse.ArgumentParser) -> None:
    sp.add_argument(
        "--hosts", "-H", help="Host to open the shell on", type=str, required=True
    )


@cache
def get_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Spooky CFEngine at a distance",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    ap.add_argument(
        "--log-level",
        help="Specify level of logging: NONE, DEBUG, INFO, WARNING, ERROR, or CRITICAL",
        type=str,
        default="WARNING",
    )
    ap.add_argument(
        "--version",
        "-V",
        help="Print or specify version",
        nargs="?",
        type=str,
        const=True,
    )

    command_help_hint = (
        "Commands (use %s COMMAND --help to get more info)"
        % os.path.basename(sys.argv[0])
    )
    subp = ap.add_subparsers(dest="command", title=command_help_hint)

    add_info_args(subp.add_parser("info", help="Get info about the given hosts"))
    add_install_args(
        subp.add_parser("install", help="Install CFEngine on the given hosts")
    )
    add_uninstall_args(
        subp.add_parser("uninstall", help="Uninstall CFEngine on the given hosts")
    )
    add_packages_args(
        subp.add_parser("packages", help="Get info about available packages")
    )
    add_list_args(
        subp.add_parser("list", help="List CFEngine packages available for download")
    )
    add_download_args(subp.add_parser("download", help="Download CFEngine packages"))
    add_run_args(
        subp.add_parser(
            "run", help="Run the command given as arguments on the given hosts"
        )
    )
    add_save_args(
        subp.add_parser(
            "save", help="Save host(s) with a group name to use in other commands"
        )
    )
    add_sudo_args(
        subp.add_parser(
            "sudo",
            help="Run the command given as arguments on the given hosts with 'sudo'",
        )
    )
    add_scp_args(subp.add_parser("scp", help="Copy the given file to the given hosts"))
    add_spawn_args(subp.add_parser("spawn", help="Spawn hosts in the clouds"))
    add_show_args(
        subp.add_parser("show", help="Show hosts spawned by or added to cf-remote")
    )
    add_destroy_args(
        subp.add_parser("destroy", help="Destroy hosts spawned in the clouds")
    )
    add_deploy_args(
        subp.add_parser("deploy", help="Deploy policy-set (masterfiles) to hub")
    )
    add_agent_args(subp.add_parser("agent", help="Run cf-agent"))
    add_connect_args(subp.add_parser("connect", help="Opens interactive ssh shell"))

    return ap
