import os
import fcntl
import re
import urllib.request
import json
import tempfile
from collections import OrderedDict
from cf_remote.utils import (
    is_different_checksum,
    file_has_different_checksum,
    user_error,
    write_json,
    mkdir,
    parse_json,
    copy_file,
    delete_file,
)
from cf_remote import log
from cf_remote.paths import cf_remote_dir, cf_remote_packages_dir
from cf_remote.utils import ChecksumError

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def get_json(url):
    with urllib.request.urlopen(url) as r:
        assert r.status >= 200 and r.status < 300
        data = json.loads(r.read().decode(), object_pairs_hook=OrderedDict)

    filename = os.path.basename(url)
    dir = cf_remote_dir("json")
    path = os.path.join(dir, filename)
    log.debug("Saving '{}' to '{}'".format(url, path))
    write_json(path, data)

    return data


def download_package(url, path=None, checksum=None, insecure=False):
    if not insecure and not checksum:
        log.warning(f"Checksum not provided for download of package {url}. ")

    if checksum and not SHA256_RE.match(checksum):
        if not insecure:
            raise ChecksumError(
                "Invalid checksum or unsupported checksum algorithm: '%s'" % checksum
            )
        log.warning(
            f"Invalid checksum or unsupported checksum algorithm for file {url}: {checksum}. Continuing due to insecure flag"
        )

    filename = os.path.basename(url)

    if not path:
        directory = cf_remote_packages_dir()
        mkdir(directory)
        path = os.path.join(directory, filename)

    tempfolder = os.path.join(tempfile.gettempdir(), "cf-remote")
    mkdir(tempfolder)
    # Wait for other process if lockfile is taken. Otherwise lock it
    lockfile = os.path.join(tempfolder, f"{filename}.lock")
    with open(lockfile, "w") as lf:
        # Exclusive file lock. Automatically unlocked on end of or return from open
        fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
        # Check if file already exists
        if os.path.exists(path):
            # File already exist, check the hash
            print("Package '{}' already downloaded".format(path))
            if checksum and file_has_different_checksum(path, checksum):
                if insecure:
                    log.warning(
                        "Pre-existing file {path} did not have expected checksum {checksum}. Continuing due to insecure flag"
                    )
                    return path
                delete_file(path)
                log.warning(
                    "Pre-existing file did not match existing checksum. File is now deleted."
                )
            else:
                # Checksum was correct, skip download
                return path

        # File does not exist, download it
        print("Downloading package: '{}'".format(path))
        tempfilename, header = urllib.request.urlretrieve(url)
        # File downloaded to temp file. Check checksum
        if checksum and file_has_different_checksum(tempfilename, checksum):
            if not insecure:
                urllib.request.urlcleanup()
                raise ChecksumError(
                    "Downloaded file '{}' does not match expected checksum '{}'.".format(
                        filename, checksum
                    )
                )
            else:
                log.warning(
                    f"Downloaded file {url} did not have expected checksum {checksum}. Continuing due to insecure flag"
                )

        # Copy over the tempfile and remove it
        copy_file(tempfilename, path)
        urllib.request.urlcleanup()

    return path
