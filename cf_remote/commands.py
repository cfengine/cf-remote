import os
import sys
import time
from multiprocessing.dummy import Pool

from cf_remote.remote import (
    get_info,
    print_info,
    HostInstaller,
    uninstall_host,
    run_command,
    transfer_file,
    deploy_masterfiles,
)
from cf_remote.packages import Releases
from cf_remote.web import download_package
from cf_remote.paths import (
    cf_remote_dir,
    CLOUD_CONFIG_FPATH,
    CLOUD_STATE_FPATH,
    cf_remote_packages_dir,
)
from cf_remote.utils import (
    save_file,
    strip_user,
    read_json,
    write_json,
    whoami,
    get_package_name,
)
from cf_remote.utils import user_error, is_package_url, print_progress_dot
from cf_remote.spawn import VM, VMRequest, Providers, AWSCredentials, GCPCredentials
from cf_remote.spawn import spawn_vms, destroy_vms, dump_vms_info, get_cloud_driver
from cf_remote import log
from cf_remote import cloud_data


def info(hosts, users=None):
    assert hosts
    log.debug("hosts='{}'".format(hosts))
    errors = 0
    for host in hosts:
        data = get_info(host, users=users)
        if data:
            print_info(data)
        else:
            errors += 1
    return errors


def run(hosts, command, users=None, sudo=False, raw=False):
    assert hosts
    errors = 0
    for host in hosts:
        lines = run_command(host=host, command=command, users=users, sudo=sudo)
        if lines is None:
            log.error("Command: '{}'\nFailed on host: '{}'".format(command, host))
            errors += 1
            continue
        host_colon = (host + ":").ljust(16)
        if lines == "":
            if not raw:
                print("{} '{}'".format(host_colon, command))
            continue
        cmd = command
        lines = lines.replace("\r", "")
        for line in lines.split("\n"):
            if raw:
                print(line)
            elif cmd:
                print("{} '{}' -> '{}'".format(host_colon, cmd, line))
                fill = " " * (len(cmd) + 7)
                cmd = None
            else:
                print("{}{}'{}'".format(host_colon, fill, line))
    return errors


def sudo(hosts, command, users=None, raw=False):
    return run(hosts, command, users, sudo=True, raw=raw)


def scp(hosts, files, users=None):
    errors = 0
    for host in hosts:
        for file in files:
            errors += transfer_file(host, file, users)
    return errors


def _download_urls(urls):
    """Download packages from URLs, replace URLs with filenames

    Return a new list of packages where URLs are replaced with paths
    to packages which have been downloaded. Other values, like None
    and paths to local packages are preserved.
    """
    urls_dir = cf_remote_packages_dir("url_specified")

    downloaded_urls = []
    downloaded_paths = []
    paths = []
    for package_url in urls:
        # Skip anything that is not a package url:
        if package_url is None or not is_package_url(package_url):
            paths.append(package_url)
            continue

        if not os.path.isdir(urls_dir):
            os.mkdir(urls_dir)

        # separate name from url and construct path for downloaded file
        url, name = package_url, get_package_name(package_url)
        path = os.path.join(urls_dir, name)

        # replace url with local path to package in list which will be returned
        paths.append(path)

        if path in downloaded_paths and url not in downloaded_urls:
            user_error("2 packages with the same name '%s' from different URLs" % name)

        download_package(url, path)
        downloaded_urls.append(url)
        downloaded_paths.append(path)

    return paths


def _verify_package_urls(urls):
    verified_urls = []
    for package_url in urls:
        if package_url is None:
            verified_urls.append(None)
            continue

        # Throw an error if not valid URL
        if is_package_url(package_url):
            verified_urls.append(package_url)
        else:
            user_error("Wrong package URL: {}".format(package_url))

    return verified_urls


def _maybe_packages_in_folder(package):
    if not (package and type(package) is str):
        return package
    folder = os.path.abspath(os.path.expanduser(package))
    if os.path.isdir(folder):
        return [os.path.join(folder, f) for f in os.listdir(folder)]
    return package


def install(
    hubs,
    clients,
    *,
    bootstrap=None,
    package=None,
    hub_package=None,
    client_package=None,
    version=None,
    demo=False,
    call_collect=False,
    edition=None,
    remote_download=False,
    trust_keys=None
):
    assert hubs or clients
    assert not (hubs and clients and package)
    assert (trust_keys is None) or hasattr(trust_keys, "__iter__")
    # These assertions are checked/ensured in main.py

    # If there are URLs in any of the package strings and remote_download is FALSE, download and replace with path:
    packages = (package, hub_package, client_package)
    if remote_download:
        package, hub_package, client_package = _verify_package_urls(packages)
    else:
        package, hub_package, client_package = _download_urls(packages)

    # If any of these are folders, transform them to lists of the files inside those folders:
    package = _maybe_packages_in_folder(package)
    hub_package = _maybe_packages_in_folder(hub_package)
    client_package = _maybe_packages_in_folder(client_package)

    # If --hub-package or --client-pacakge are not specified, use --package argument:
    if not hub_package:
        hub_package = package
    if not client_package:
        client_package = package

    if bootstrap:
        if type(bootstrap) is str:
            bootstrap = [bootstrap]
        save_file(
            os.path.join(cf_remote_dir(), "policy_server.dat"),
            "\n".join(bootstrap + [""]),
        )

    hub_jobs = []
    if hubs:
        show_host_info = len(hubs) == 1
        if type(hubs) is str:
            hubs = [hubs]
        for index, hub in enumerate(hubs):
            log.debug("Installing {} hub package on '{}'".format(edition, hub))
            hub_jobs.append(
                HostInstaller(
                    hub,
                    hub=True,
                    packages=hub_package,
                    bootstrap=bootstrap[index % len(bootstrap)] if bootstrap else None,
                    version=version,
                    demo=demo,
                    call_collect=call_collect,
                    edition=edition,
                    show_info=show_host_info,
                    remote_download=remote_download,
                    trust_keys=trust_keys,
                )
            )

    errors = 0
    if hub_jobs:
        with Pool(len(hub_jobs)) as hubs_install_pool:
            hubs_install_pool.map(lambda job: job.run(), hub_jobs)
        errors = sum(job.errors for job in hub_jobs)

    if errors > 0:
        s = "s" if errors > 1 else ""
        log.error(
            "%s error%s encountered while installing hub packages, aborting..."
            % (errors, s)
        )
        return errors

    client_jobs = []
    show_host_info = clients and (len(clients) == 1)
    for index, host in enumerate(clients or []):
        log.debug("Installing {} client package on '{}'".format(edition, host))
        client_jobs.append(
            HostInstaller(
                host,
                hub=False,
                packages=client_package,
                bootstrap=bootstrap[index % len(bootstrap)] if bootstrap else None,
                version=version,
                demo=demo,
                edition=edition,
                show_info=show_host_info,
                remote_download=remote_download,
                trust_keys=trust_keys,
            )
        )

    if client_jobs:
        with Pool(len(client_jobs)) as clients_install_pool:
            clients_install_pool.map(lambda job: job.run(), client_jobs)
        errors += sum(job.errors for job in client_jobs)

    if demo and hubs:
        for hub in hubs:
            print(
                "Your demo hub is ready: https://{}/ (Username: admin, Password: password)".format(
                    strip_user(hub)
                )
            )

    if errors > 0:
        s = "s" if errors > 1 else ""
        log.error(
            "%s error%s encountered while installing client packages" % (errors, s)
        )

    return errors


def _iterate_over_packages(tags=None, version=None, edition=None, download=False):
    releases = Releases(edition)
    print("Available releases: {}".format(releases))

    release = releases.default
    if version:
        release = releases.pick_version(version)
    print("Using {}:".format(release))
    log.debug("Looking for a release based on host tags: {}".format(tags))
    artifacts = release.find(tags)

    if len(artifacts) == 0:
        print("No suitable packages found")
    else:
        for artifact in artifacts:
            if download:
                download_package(artifact.url)
            else:
                print(artifact.url)
    return 0


# named list_command to not conflict with list()
def list_command(tags=None, version=None, edition=None):
    return _iterate_over_packages(tags, version, edition, False)


def download(tags=None, version=None, edition=None):
    return _iterate_over_packages(tags, version, edition, True)


def _get_aws_creds_from_env():
    if "AWS_ACCESS_KEY_ID" in os.environ and "AWS_SECRET_ACCESS_KEY" in os.environ:
        return AWSCredentials(
            os.environ["AWS_ACCESS_KEY_ID"],
            os.environ["AWS_SECRET_ACCESS_KEY"],
            os.environ.get("AWS_SESSION_TOKEN", ""),
        )
    return None


def spawn(
    platform,
    count,
    role,
    group_name,
    provider=Providers.AWS,
    region=None,
    size=None,
    network=None,
    public_ip=True,
    extend_group=False,
):

    if os.path.exists(CLOUD_CONFIG_FPATH):
        creds_data = read_json(CLOUD_CONFIG_FPATH)
    else:
        print("Cloud configuration not found at %s" % CLOUD_CONFIG_FPATH)
        return 1

    if os.path.exists(CLOUD_STATE_FPATH):
        vms_info = read_json(CLOUD_STATE_FPATH)
    else:
        vms_info = dict()

    group_key = "@%s" % group_name
    group_exists = group_key in vms_info
    if not extend_group and group_exists:
        print("Group '%s' already exists!" % group_key)
        return 1

    creds = None
    sec_groups = None
    key_pair = None
    if provider == Providers.AWS:
        try:
            creds = _get_aws_creds_from_env() or AWSCredentials(
                creds_data["aws"]["key"],
                creds_data["aws"]["secret"],
                creds_data["aws"].get("token", ""),
            )
            sec_groups = creds_data["aws"]["security_groups"]
            key_pair = creds_data["aws"]["key_pair"]
        except KeyError:
            print("Incomplete AWS credential info")  # TODO: report missing keys
            return 1

        region = region or creds_data["aws"].get("region", "eu-west-1")
    elif provider == Providers.GCP:
        try:
            creds = GCPCredentials(
                creds_data["gcp"]["project_id"],
                creds_data["gcp"]["service_account_id"],
                creds_data["gcp"]["key_path"],
            )
        except KeyError:
            print("Incomplete GCP credential info")  # TODO: report missing keys
            return 1

        region = region or creds_data["gcp"].get("region", "europe-west1-b")

    # TODO: Do we have to complicate this instead of just assuming existing VMs
    # were created by this code and thus follow the naming pattern from this
    # code?
    if group_exists:
        range_start = len([key for key in vms_info[group_key].keys() if key != "meta"])
    else:
        range_start = 0

    requests = []
    for i in range(range_start, range_start + count):
        vm_name = whoami()[0:2] + group_name + "-" + platform + role + str(i)
        requests.append(
            VMRequest(platform=platform, name=vm_name, size=size, public_ip=public_ip)
        )
    print("Spawning VMs...", end="")
    sys.stdout.flush()
    vms = spawn_vms(
        requests,
        creds,
        region,
        key_pair,
        security_groups=sec_groups,
        provider=provider,
        network=network,
        role=role,
        spawned_cb=print_progress_dot,
    )
    print("DONE")

    if public_ip and (not all(vm.public_ips for vm in vms)):
        print("Waiting for VMs to get IP addresses...", end="")
        sys.stdout.flush()  # STDOUT is line-buffered
        while not all(vm.public_ips for vm in vms):
            time.sleep(1)
            print_progress_dot()
        print("DONE")

    if group_exists:
        vms_info[group_key].update(dump_vms_info(vms))
    else:
        vms_info[group_key] = dump_vms_info(vms)

    write_json(CLOUD_STATE_FPATH, vms_info)
    print("Details about the spawned VMs can be found in %s" % CLOUD_STATE_FPATH)

    return 0


def _is_saved_group(vms_info, group_name):
    group = vms_info[group_name]
    return group.get("meta", {}).get("saved") == True


def _delete_saved_group(vms_info, group_name):
    print("Deleting saved group '{}' without terminating VMs:".format(group_name))
    for name, vm in vms_info[group_name].items():
        if name == "meta":
            continue
        print(
            "  {}: {}@{} ({})".format(name, vm["user"], vm["public_ips"][0], vm["role"])
        )
    del vms_info[group_name]


def destroy(group_name=None):
    if os.path.exists(CLOUD_CONFIG_FPATH):
        creds_data = read_json(CLOUD_CONFIG_FPATH)
    else:
        creds_data = None

    aws_creds = _get_aws_creds_from_env()
    if not aws_creds and creds_data:
        try:
            aws_creds = AWSCredentials(
                creds_data["aws"]["key"],
                creds_data["aws"]["secret"],
                creds_data["aws"].get("token", ""),
            )
        except KeyError:
            # missing/incomplete AWS credentials, may not be needed, though
            pass

    gcp_creds = None
    if creds_data:
        try:
            gcp_creds = GCPCredentials(
                creds_data["gcp"]["project_id"],
                creds_data["gcp"]["service_account_id"],
                creds_data["gcp"]["key_path"],
            )
        except KeyError:
            # missing/incomplete GCP credentials, may not be needed, though
            pass

    if not os.path.exists(CLOUD_STATE_FPATH):
        print("No saved cloud state info")
        return 1

    vms_info = read_json(CLOUD_STATE_FPATH)

    to_destroy = []
    if group_name:
        if not group_name.startswith("@"):
            group_name = "@" + group_name
        if group_name not in vms_info:
            print("Group '%s' not found" % group_name)
            return 1

        if _is_saved_group(vms_info, group_name):
            _delete_saved_group(vms_info, group_name)
            write_json(CLOUD_STATE_FPATH, vms_info)
            return 0

        print("Destroying hosts in the '%s' group" % group_name)

        region = vms_info[group_name]["meta"]["region"]
        provider = vms_info[group_name]["meta"]["provider"]
        if provider == "aws":
            if aws_creds is None:
                user_error("Missing/incomplete AWS credentials")
                return 1
            driver = get_cloud_driver(Providers.AWS, aws_creds, region)
        if provider == "gcp":
            if gcp_creds is None:
                user_error("Missing/incomplete GCP credentials")
                return 1
            driver = get_cloud_driver(Providers.GCP, gcp_creds, region)

        nodes = driver.list_nodes()
        for name, vm_info in vms_info[group_name].items():
            if name == "meta":
                continue
            vm_uuid = vm_info["uuid"]
            vm = VM.get_by_uuid(vm_uuid, nodes=nodes)
            if vm is not None:
                to_destroy.append(vm)
            else:
                print("VM '%s' not found in the clouds" % vm_uuid)
        del vms_info[group_name]
    else:
        print("Destroying all hosts")
        for group_name in [key for key in vms_info.keys() if key.startswith("@")]:
            if _is_saved_group(vms_info, group_name):
                _delete_saved_group(vms_info, group_name)
                continue

            region = vms_info[group_name]["meta"]["region"]
            provider = vms_info[group_name]["meta"]["provider"]
            if provider == "aws":
                if aws_creds is None:
                    user_error("Missing/incomplete AWS credentials")
                    return 1
                driver = get_cloud_driver(Providers.AWS, aws_creds, region)
            if provider == "gcp":
                if gcp_creds is None:
                    user_error("Missing/incomplete GCP credentials")
                    return 1
                driver = get_cloud_driver(Providers.GCP, gcp_creds, region)

            nodes = driver.list_nodes()
            for name, vm_info in vms_info[group_name].items():
                if name == "meta":
                    continue
                vm_uuid = vm_info["uuid"]
                vm = VM.get_by_uuid(vm_uuid, nodes=nodes)
                if vm is not None:
                    to_destroy.append(vm)
                else:
                    print("VM '%s' not found in the clouds" % vm_uuid)
            del vms_info[group_name]

    destroy_vms(to_destroy)
    write_json(CLOUD_STATE_FPATH, vms_info)
    return 0


def list_platforms():
    print("Available platforms:")
    for key in sorted(cloud_data.aws_platforms.keys()):
        print(key)
    return 0


def init_cloud_config():
    if os.path.exists(CLOUD_CONFIG_FPATH):
        print("File %s already exists" % CLOUD_CONFIG_FPATH)
        return 1
    empty_config = {
        "aws": {
            "key": "TBD",
            "secret": "TBD",
            "key_pair": "TBD",
            "security_groups": ["TBD"],
            "region": "OPTIONAL (DEFAULT: eu-west-1)",
        },
        "gcp": {
            "project_id": "TBD",
            "service_account_id": "TBD",
            "key_path": "TBD",
            "region": "OPTIONAL (DEFAULT: europe-west1-b)",
        },
    }
    write_json(CLOUD_CONFIG_FPATH, empty_config)
    print(
        "Config file %s created, please complete the configuration in it."
        % CLOUD_CONFIG_FPATH
    )
    return 0


def save(name, hosts, role):
    state = read_json(CLOUD_STATE_FPATH)
    if not state:
        state = {}
    if "@" + name in state:
        print("Group '{}' already exists".format(name))
        return 1
    group = {"meta": {"saved": True}}
    for index, host in enumerate(hosts):
        split = host.split("@")
        if len(split) != 2:
            print(
                "Host '{}' not accepted, must be given as user@ip-address".format(host)
            )
            return 1
        user, ip = host.split("@")
        instance = {
            "public_ips": [ip],
            "user": user,
            "role": role,
        }
        group[name + "-" + str(index + 1)] = instance
    state["@" + name] = group
    write_json(CLOUD_STATE_FPATH, state)
    return 0


def _ansible_inventory():
    if not os.path.exists(CLOUD_STATE_FPATH):
        print("No saved cloud state info")
        return 1

    vms_info = read_json(CLOUD_STATE_FPATH)
    all_lines = []
    hub_lines = []
    client_lines = []
    for group_name in vms_info:
        print("[%s]" % group_name.strip("@"))
        for vm in (name for name in vms_info[group_name] if name != "meta"):
            host_line = (
                '%s ansible_host=%s ansible_user=%s ansible_ssh_extra_args="-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"'
                % (
                    vm,
                    vms_info[group_name][vm]["public_ips"][0],
                    vms_info[group_name][vm]["user"],
                )
            )
            print(host_line)
            all_lines.append(host_line)
            if vms_info[group_name][vm]["role"] == "hub":
                hub_lines.append(host_line)
            if vms_info[group_name][vm]["role"] == "client":
                client_lines.append(host_line)
        print()

    if len(all_lines) > 0:
        print("[all]")
        for line in all_lines:
            print(line)
        print()

    if len(hub_lines) > 1:
        print("[hubs]")
        for line in hub_lines:
            print(line)
        print()
    elif len(hub_lines) == 1:
        print("[hub]")
        print(hub_lines[0])
        print()

    if len(client_lines) > 0:
        print("[clients]")
        for line in client_lines:
            print(line)
        print()

    return 0


def _flatten(items):
    flattened = []
    for item in items:
        if isinstance(item, (list, tuple)):
            flattened.extend(_flatten(item))
        else:
            flattened.append(str(item))
    return flattened


def _print_indented_and_wrapped(strings, indent, wrap):
    strings = _flatten(strings)
    lines = []
    line = ""
    for index, string in enumerate(strings):
        if index < len(strings) - 1:
            string += ", "

        if line == "":
            line = " " * indent + string
            continue

        if len(line + string) >= wrap:
            lines.append(line)
            line = " " * indent + string
            continue

        line += string
    if line != "":
        lines.append(line)
    for line in lines:
        print(line)


def show(ansible_inventory):
    if ansible_inventory:
        return _ansible_inventory()
    if not os.path.exists(CLOUD_STATE_FPATH):
        print("No saved cloud state info")
        return 1

    vms_info = read_json(CLOUD_STATE_FPATH)
    if not vms_info:
        print("No hosts found")
        return 0
    hosts = 0
    groups = len(vms_info)
    for group_name in vms_info:
        extra = ""
        group = vms_info[group_name]
        if "meta" in group:
            meta = group["meta"]
            del group["meta"]
            if "region" in meta and "provider" in meta:
                extra = " in {}, {}".format(meta["region"], meta["provider"])
        print(
            "{}: ({} host{}{})".format(
                group_name, len(group), "s" if len(group) > 1 else "", extra
            )
        )
        hosts += len(group)
        for name, vm in group.items():
            role = vm["role"]
            keywords = [v for k, v in vm.items() if k not in ("user", "role")]
            keywords = [role, name] + keywords
            identifier = "{}@{}".format(vm["user"], vm["public_ips"][0])
            print("  " + identifier)
            _print_indented_and_wrapped(keywords, 4, 80)
        print("\n")
    print(
        "Total: {} host{} in {} group{}".format(
            hosts, "s" if hosts > 1 else "", groups, "s" if groups > 1 else ""
        )
    )
    return 0


def uninstall(hosts):
    errors = 0
    for host in hosts:
        errors += uninstall_host(host)
    return errors


def deploy_tarball(hubs, tarball):
    assert os.path.isfile(tarball)

    if not tarball.endswith((".tgz", ".tar.gz")):
        log.error(
            "The masterfiles directory must be in a gzipped tarball (.tgz or .tar.gz)"
        )
        return 1

    errors = 0
    for hub in hubs:
        errors += deploy_masterfiles(hub, tarball)
    return errors


def _get_hubs():
    if not os.path.exists(CLOUD_STATE_FPATH):
        return None
    groups = read_json(CLOUD_STATE_FPATH)
    if not groups:
        return None
    hubs = []
    for name, group in groups.items():
        for name, vm in group.items():
            if name == "meta":
                continue
            if vm["role"] == "hub":
                identifier = "{}@{}".format(vm["user"], vm["public_ips"][0])
                hubs.append(identifier)
    return hubs


def deploy(hubs, masterfiles):
    if not hubs:
        hubs = _get_hubs()
        if hubs:
            print("Found saved/spawned hubs: " + ", ".join(hubs))

    if not hubs:
        user_error(
            "No hub to deploy to (Specify with --hub or use spawn/save commands to add to cf-remote)"
        )

    if (
        not masterfiles
        and os.path.isfile("cfbs.json")
        and os.path.isfile("out/masterfiles.tgz")
    ):
        masterfiles = "out/masterfiles.tgz"
        print("Found cfbs policy set: '{}'".format(masterfiles))
    elif masterfiles.startswith(("http://", "https://")):
        urls = [masterfiles]
        paths = _download_urls(urls)
        assert len(paths) == 1
        masterfiles = paths[0]
        log.debug("Deploying downloaded: %s" % masterfiles)
    else:
        masterfiles = os.path.abspath(os.path.expanduser(masterfiles))
        log.debug("Deploy path expanded to: %s" % masterfiles)

    masterfiles = masterfiles.rstrip("/")

    if os.path.isfile(masterfiles):
        return deploy_tarball(hubs, masterfiles)

    if masterfiles.endswith((".tgz", ".tar.gz")):
        if not os.path.exists(masterfiles):
            log.error("'{}' does not exist".format(masterfiles))
            return 1
        else:
            assert not os.path.isfile(masterfiles)
            log.error("'{}' is not a file".format(masterfiles))
            return 1

    if not os.path.isdir(masterfiles):
        log.error("'%s' must be a directory" % masterfiles)
        return 1

    directory = masterfiles

    if not directory.endswith("/masterfiles"):
        log.error("The masterfiles directory to deploy must be called 'masterfiles'")
        return 1

    if os.path.isfile("%s/autogen.sh" % directory):
        os.system("bash -c 'cd %s && ./autogen.sh 1>/dev/null 2>&1'" % directory)
        if not os.path.isfile("%s/promises.cf" % directory):
            log.error(
                "The autogen.sh script did not produce promises.cf in '%s'" % directory
            )
            return 1
    elif os.path.isfile("%s/configure" % directory):
        os.system("bash -c 'cd %s && ./configure 1>/dev/null 2>&1'" % directory)
        if not os.path.isfile("%s/promises.cf" % directory):
            log.error(
                "The configure script did not produce promises.cf in '%s'" % directory
            )
            return 1
    else:
        log.debug(
            "No autogen.sh / configure found, assuming ready to install directory"
        )
        if not os.path.isfile("%s/promises.cf" % directory):
            log.error("No promises.cf in '%s'" % directory)
            return 1

    assert not cf_remote_dir().endswith("/")
    tarball = cf_remote_dir() + "/masterfiles.tgz"
    above = directory[0 : -len("/masterfiles")]
    os.system("rm -rf %s" % tarball)
    os.system("tar -czf %s -C %s masterfiles" % (tarball, above))
    return deploy_tarball(hubs, tarball)
