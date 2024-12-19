import os
from cf_remote.utils import user_error


def path_append(dir, subdir):
    dir = os.path.abspath(os.path.expanduser(dir))
    return dir if not subdir else os.path.join(dir, subdir)


def cfengine_dir(subdir=None):
    override_dir = os.getenv("CF_REMOTE_DIR")

    if override_dir:
        override_dir = os.path.normpath(override_dir)
        parent = os.path.dirname(override_dir)

        if not os.path.exists(parent):
            user_error(
                "'{}' doesn't exist. Make sure this path is correct and exists.".format(
                    parent
                )
            )

        return path_append(override_dir, subdir)

    return path_append("~/.cfengine/", subdir)


def cf_remote_dir(subdir=None):
    return path_append(cfengine_dir("cf-remote"), subdir)


def cf_remote_file(fname=None):
    return path_append(cfengine_dir("cf-remote"), fname)


def cf_remote_packages_dir(subdir=None):
    return path_append(cf_remote_dir("packages"), subdir)


CLOUD_CONFIG_FNAME = "cloud_config.json"
CLOUD_CONFIG_FPATH = cf_remote_file(CLOUD_CONFIG_FNAME)
CLOUD_STATE_FNAME = "cloud_state.json"
CLOUD_STATE_FPATH = cf_remote_file(CLOUD_STATE_FNAME)
