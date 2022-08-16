import os
import fcntl
import urllib.request
import requests
from cf_remote.utils import write_json, mkdir, parse_json
from cf_remote import log
from cf_remote.paths import cf_remote_dir, cf_remote_packages_dir


def get_json(url):
    r = requests.get(url)
    assert r.status_code >= 200 and r.status_code < 300
    data = parse_json(r.text)

    filename = os.path.basename(url)
    dir = cf_remote_dir("json")
    path = os.path.join(dir, filename)
    log.debug("Saving '{}' to '{}'".format(url, path))
    write_json(path, data)

    return data


def download_package(url, path=None):
    if not path:
        filename = os.path.basename(url)
        directory = cf_remote_packages_dir()
        mkdir(directory)
        path = os.path.join(directory, filename)

    # Use "ab" to prevent truncation of the file in case it is already being
    # downloaded by a different thread.
    with open(path, "ab") as f:
        # Get an exclusive lock. If the file size is != 0 then it's already
        # downloaded, otherwise we download.
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        st = os.stat(path)
        if st.st_size != 0:
            log.debug("Package '{}' already downloaded".format(path))
        else:
            print("Downloading package: '{}'".format(path))
            f.write(urllib.request.urlopen(url).read())
            f.flush()
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    return path
