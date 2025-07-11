import os
import fcntl
import re
import urllib.request
import json
from collections import OrderedDict
from cf_remote.utils import (
    is_different_checksum,
    write_json,
    mkdir,
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

    if not path:
        filename = os.path.basename(url)
        directory = cf_remote_packages_dir()
        mkdir(directory)
        path = os.path.join(directory, filename)

    # Use "ab" to prevent truncation of the file in case it is already being
    # downloaded by a different thread.
    with open(path, "ab+") as f:
        # Get an exclusive lock. If the file size is != 0 then it's already
        # downloaded, otherwise we download.
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        st = os.stat(path)
        if st.st_size != 0:
            print("Package '{}' already downloaded".format(path))

            f.seek(0)
            content = f.read()
            if checksum and is_different_checksum(checksum, content):
                raise ChecksumError(
                    "Downloaded file '{}' does not match expected checksum '{}'. Please delete the file.".format(
                        filename, checksum
                    )
                )

        else:
            print("Downloading package: '{}'".format(path))

            answer = urllib.request.urlopen(url).read()
            if checksum and is_different_checksum(checksum, answer):
                raise ChecksumError(
                    "Downloaded file '{}' does not match expected checksum '{}'. Please delete the file.".format(
                        filename, checksum
                    )
                )

            f.write(answer)
            f.flush()

        fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    return path
