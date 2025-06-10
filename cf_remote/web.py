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


def download_package(url, path=None, checksum=None):

    if checksum and not SHA256_RE.match(checksum):
        raise ChecksumError(
            "Invalid checksum or unsupported checksum algorithm: '%s'" % checksum
        )

    filename = os.path.basename(url)

    if not path:
        directory = cf_remote_packages_dir()
        mkdir(directory)
        path = os.path.join(directory, filename)

    tempfolder = os.path.join(tempfile.gettempdir(), "cf-engine")
    mkdir(tempfolder)
    # Check if other process is handeling this - lockfile
    lockfile = os.path.join(tempfolder, f"{filename}.lock")
    with open(lockfile, "w") as lf:
        fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
        # Check if file already exists, if so check the hash if ok - return
        if os.path.exists(path):
            # File already exist, check the hash
            print("Package '{}' already downloaded".format(path))
            if file_has_different_checksum(path, checksum):              
                delete_file(path)
                log.warning("Pre-existing file did not match existing checksum. File is now deleted.")
            else:
                # Checksum was correct, skip download
                return path

        # File does not exist, download it
        print("Downloading package: '{}'".format(path))
        tempfilename, header = urllib.request.urlretrieve(url)
        if file_has_different_checksum(tempfilename, checksum):
            urllib.request.urlcleanup()
            raise ChecksumError(
                "Downloaded file '{}' does not match expected checksum '{}'.".format(
                    filename, checksum
                )
            )

        # Copy over the tempfile and remove it
        copy_file(tempfilename, path)
        urllib.request.urlcleanup()
        # Unlock the lockfile
        fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
    
    return path
