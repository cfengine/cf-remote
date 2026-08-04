import os

from cf_remote.utils import CFRExitError, is_package_url


def validate_edition_args(args) -> None:
    if args.edition:
        args.edition = args.edition.lower()
        if args.edition == "core":
            args.edition = "community"
        if args.edition not in ["enterprise", "community"]:
            raise CFRExitError("--edition must be either community or enterprise")
    else:
        args.edition = "enterprise"


def validate_install_args(args) -> None:
    if args.call_collect and not args.demo:
        raise CFRExitError("--call-collect must be used with --demo")
    if not args.clients and not args.hub:
        raise CFRExitError("Specify hosts using --hub and --clients")
    if args.hub and args.clients and args.package:
        raise CFRExitError(
            "Use --hub-package / --client-package instead to distinguish between hosts"
        )
    if args.package and (args.hub_package or args.client_package):
        raise CFRExitError(
            "--package cannot be used in combination with --hub-package / --client-package"
        )
    if args.package and not is_package_url(args.package):
        if not os.path.exists(os.path.expanduser(args.package)):
            raise CFRExitError("Package/directory '%s' does not exist" % args.package)
    if args.hub_package and not is_package_url(args.hub_package):
        if not os.path.isfile(args.hub_package):
            raise CFRExitError("Hub package '%s' does not exist" % args.hub_package)
    if args.client_package and not is_package_url(args.client_package):
        if not os.path.isfile(args.client_package):
            raise CFRExitError(
                "Client package '%s' does not exist" % args.client_package
            )


def validate_uninstall_args(args) -> None:
    if not (args.hosts or args.hub or args.clients):
        raise CFRExitError("Use --hosts, --hub or --clients to specify remote hosts")


def validate_spawn_args(args) -> None:
    if args.list_platforms or args.init_config or args.list_boxes:
        # The above options don't require any other options/arguments (TODO:
        # --provider), but otherwise all have to be given
        return
    if not args.platform:
        raise CFRExitError("--platform needs to be specified")
    if not args.count:
        raise CFRExitError("--count needs to be specified")
    if not args.role:
        raise CFRExitError("--role needs to be specified")
    if not args.name:
        raise CFRExitError("--name needs to be specified")


def validate_destroy_args(args) -> None:
    if not args.all and not args.name:
        raise CFRExitError("One of --all or NAME required for destroy")


def validate_deploy_args(args) -> None:
    if not args.masterfiles:
        return
    masterfiles = args.masterfiles
    if masterfiles.startswith(("http://", "https://")):
        if not masterfiles.endswith((".tgz", ".tar.gz")):
            raise CFRExitError(
                "masterfiles URL must be to a gzipped tarball (.tgz or .tar.gz)"
            )
    elif not os.path.exists(masterfiles):
        raise CFRExitError("'%s' does not exist" % masterfiles)
