import os
import sys
import re
import socket

from cf_remote import log
from cf_remote import version
from cf_remote import commands, paths
from cf_remote.args import get_arg_parser
from cf_remote.utils import (
    CFRExitError,
    CFRProgrammerError,
    CFRUserError,
    exit_success,
    expand_list_from_file,
    is_file_string,
    migrate_config_paths,
)
from cf_remote.utils import strip_user, read_json
from cf_remote.packages import Releases
from cf_remote.spawn import Providers
from cf_remote.validate import (
    validate_edition_args,
    validate_install_args,
    validate_uninstall_args,
    validate_spawn_args,
    validate_destroy_args,
    validate_deploy_args,
)


def print_version_info():
    print("cf-remote version %s" % version.string())
    print("Available CFEngine versions:")
    releases = Releases()
    print(releases)


def get_args():
    ap = get_arg_parser()
    args = ap.parse_args()
    return args


def run_command_with_args(command, args) -> int:
    if command == "info":
        return commands.info(args.hosts, None)
    elif command == "install":
        if args.trust_keys:
            trust_keys = args.trust_keys.split(",")
        else:
            trust_keys = None

        return commands.install(
            args.hub,
            args.clients,
            package=args.package,
            bootstrap=args.bootstrap,
            hub_package=args.hub_package,
            client_package=args.client_package,
            version=args.version,
            demo=args.demo,
            call_collect=args.call_collect,
            edition=args.edition,
            remote_download=args.remote_download,
            trust_keys=trust_keys,
            insecure=args.insecure,
        )
    elif command == "uninstall":
        all_hosts = (args.hosts or []) + (args.hub or []) + (args.clients or [])
        return commands.uninstall(all_hosts, purge=args.purge)
    elif command == "packages":
        log.warning(
            "packages command is deprecated, please use the new command: download"
        )
        return commands.download(
            tags=args.tags,
            version=args.version,
            edition=args.edition,
        )
    elif command == "list":
        return commands.list_command(
            tags=args.tags,
            version=args.version,
            edition=args.edition,
            allow_expired=args.allow_expired,
        )
    elif command == "download":
        return commands.download(
            tags=args.tags,
            version=args.version,
            edition=args.edition,
            output_dir=args.output_dir,
            insecure=args.insecure,
            allow_expired=args.allow_expired,
        )
    elif command == "run":
        return commands.run(hosts=args.hosts, raw=args.raw, command=args.remote_command)
    elif command == "save":
        return commands.save(hosts=args.hosts, role=args.role, name=args.name)
    elif command == "sudo":
        return commands.sudo(
            hosts=args.hosts, raw=args.raw, command=args.remote_command
        )
    elif command == "scp":
        return commands.scp(hosts=args.hosts, files=args.args)
    elif command == "spawn":
        if args.list_platforms:
            return commands.list_platforms()
        if args.list_boxes:
            return commands.list_boxes()
        if args.init_config:
            return commands.init_cloud_config()
        if args.name and "," in args.name:
            raise CFRExitError("Group --name may not contain commas")
        if args.role.endswith("s"):
            # role should be singular
            args.role = args.role[:-1]
        if args.provider == "gcp":
            provider = Providers.GCP
        elif args.provider == "aws":
            provider = Providers.AWS
            if args.network:
                raise CFRExitError("--network not supported for AWS")
            if args.no_public_ip:
                raise CFRExitError("--no-public-ip not supported for AWS")
        else:
            assert args.provider == "vagrant"
            provider = Providers.VAGRANT

        if provider != Providers.VAGRANT:
            if args.cpus:
                raise CFRExitError("--cpus not supported for {}".format(args.provider))
            if args.sync_folder:
                raise CFRExitError(
                    "--sync-folder not supported for {}".format(args.provider)
                )
            if args.provision:
                raise CFRExitError(
                    "--provision not supported for {}".format(args.provider)
                )

        if args.network and (args.network.count("/") != 1):
            raise CFRExitError(
                "Invalid network specified, needs to be in the network/subnet format"
            )

        return commands.spawn(
            args.platform,
            args.count,
            args.role,
            args.name,
            provider=provider,
            size=args.size,
            network=args.network,
            public_ip=not args.no_public_ip,
            extend_group=args.append,
            vagrant_cpus=args.cpus,
            vagrant_sync_folder=args.sync_folder,
            vagrant_provision=args.provision,
        )
    elif command == "show":
        return commands.show(args.ansible_inventory)
    elif command == "destroy":
        group_name = args.name if args.name else None
        return commands.destroy(group_name)
    elif command == "deploy":
        return commands.deploy(args.hub, args.masterfiles)
    elif command == "agent":
        return commands.agent(args.hosts, args.bootstrap)
    elif command == "connect":
        return commands.connect_cmd(args.hosts)
    else:
        raise CFRExitError("Unknown command: '{}'".format(command))


def validate_command(command, args):
    if command in ["install", "packages", "list", "download"]:
        validate_edition_args(args)

    if command == "uninstall":
        validate_uninstall_args(args)

    if command == "install":
        validate_install_args(args)

    if command in ["sudo", "run"]:
        if len(args.remote_command) != 1:
            raise CFRExitError(
                "cf-remote sudo/run requires exactly 1 command (use quotes)"
            )
        args.remote_command = args.remote_command[0]

    if command == "spawn":
        validate_spawn_args(args)

    if command == "destroy":
        validate_destroy_args(args)

    if command == "deploy":
        validate_deploy_args(args)


def is_in_cloud_state(name):
    if not os.path.exists(paths.CLOUD_STATE_FPATH):
        return False
    # else
    state = read_json(paths.CLOUD_STATE_FPATH)
    assert state is not None, "Failed reading from '{}'".format(paths.CLOUD_STATE_FPATH)
    if name in state:
        return True
    if ("@" + name) in state:
        return True

    # search for a host in any of the groups
    for group in [key for key in state.keys() if key.startswith("@")]:
        if name in state[group]:
            return True

    return False


def get_cloud_hosts(name, bootstrap_ips=False):
    if not os.path.exists(paths.CLOUD_STATE_FPATH):
        return []

    state = read_json(paths.CLOUD_STATE_FPATH)
    if not state:
        return []
    group_name = None
    hosts = []
    if name.startswith("@") and name in state:
        # @some_group given and exists
        group_name = name
    elif ("@" + name) in state:
        # group_name given and @group_name exists
        group_name = "@" + name

    if group_name is not None:
        for name, info in state[group_name].items():
            if name == "meta":
                continue
            log.debug("found name '{}' in state, info='{}'".format(name, info))
            hosts.append((name, info))
    else:
        if name in state:
            # host_name given and exists at the top level
            hosts.append((name, state[name]))
        else:
            for group_name in [key for key in state.keys() if key.startswith("@")]:
                if name in state[group_name]:
                    hosts.append((name, state[group_name][name]))

    ret = []
    for name, host in hosts:
        if bootstrap_ips and "private_ips" in host:
            key = "private_ips"
        else:
            key = "public_ips"

        if "vmdir" in host:
            ret.append(name)
            continue

        ips = host.get(key, [])
        if len(ips) > 0:
            if host.get("user"):
                ret.append("{}@{}".format(host.get("user"), ips[0]))
            else:
                ret.append(ips[0])
        else:
            ret.append(None)

    return ret


def dns_lookup(name):
    try:
        return bool(socket.getaddrinfo(name, 22))
    except socket.gaierror as e:
        raise CFRUserError("DNS lookup failed for '{}': {}".format(name, e))


def resolve_hosts(string, single=False, bootstrap_ips=False):
    log.debug("resolving hosts from '{}'".format(string))
    if is_file_string(string):
        names = expand_list_from_file(string)
    else:
        names = string.split(",")

    ret = []

    for name in names:
        if is_in_cloud_state(name):
            hosts = get_cloud_hosts(name, bootstrap_ips)
            ret.extend(hosts)
            log.debug("found in cloud, adding '{}'".format(hosts))
        elif name.startswith("@"):
            raise CFRUserError("'{}' does not exist.".format(name))
        elif re.search(r"[@:.]", name) or dns_lookup(name):
            ret.append(name)
        else:
            raise CFRUserError("'{}' does not exist.".format(name))

    if single:
        if len(ret) != 1:
            raise CFRExitError(
                "'{}' must contain exactly 1 hostname or IP".format(string)
            )
        return ret[0]
    else:
        return ret


def validate_args(args):
    if args.version is True:  # --version with no second argument
        print_version_info()
        exit_success()

    if args.version and args.command not in ["install", "packages", "list", "download"]:
        raise CFRExitError(
            "Cannot specify version number in '{}' command".format(args.command)
        )

    if "hosts" in args and args.hosts:
        log.debug("validate_args, hosts in args, args.hosts='{}'".format(args.hosts))
        args.hosts = resolve_hosts(args.hosts)
    if "clients" in args and args.clients:
        args.clients = resolve_hosts(args.clients)
    if "bootstrap" in args and args.bootstrap:
        args.bootstrap = [
            strip_user(host_info)
            for host_info in resolve_hosts(args.bootstrap, bootstrap_ips=True)
        ]
    if "hub" in args and args.hub:
        args.hub = resolve_hosts(args.hub)

    if not args.command:
        get_arg_parser().print_help()
        raise CFRExitError("Invalid or missing command")
    args.command = args.command.strip()
    validate_command(args.command, args)


def _main() -> int:
    args = get_args()
    if args.log_level:
        log.set_level(args.log_level)
    validate_args(args)

    exit_code = run_command_with_args(args.command, args)
    assert type(exit_code) is int
    return exit_code


def main() -> int:
    """Entry point

    The only thing we want to do here is call _main() and handle exceptions (errors).
    """
    migrate_config_paths()

    if os.getenv("CFBACKTRACE") == "1":
        r = _main()
        assert type(r) is int
        return r
    try:
        r = _main()
        assert type(r) is int
        return r
    except CFRUserError as e:
        print("\nError: " + str(e))
    except CFRExitError as e:
        print("\nError: " + str(e))
    except (AssertionError, CFRProgrammerError, Exception) as e:
        print("\nError: " + str(e))
        print(
            "This is an unexpected error indicating a bug, please create a ticket at:"
        )
        print("https://northerntech.atlassian.net/")
        print("(Rerun with CFBACKTRACE=1 in front of your command to show backtraces)")

    # TODO: Handle other exceptions
    return 1


if __name__ == "__main__":
    sys.exit(main())
