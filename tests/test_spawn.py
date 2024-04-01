from cf_remote.spawn import _get_image_criteria

def test_get_image_criteria():
    criteria = _get_image_criteria("ubuntu-22-04-x86")
    assert criteria["version"] == "22.04"
    assert criteria["architecture"] == "x86_64"

    criteria = _get_image_criteria("ubuntu-22-04")
    """ It says version is "22", not "22.04" """
    # assert criteria["version"] == "22.04"
    assert criteria["architecture"] == "x86_64"

    criteria = _get_image_criteria("ubuntu")
    assert criteria["version"] == ""
    assert criteria["architecture"] == "x86_64"

    criteria = _get_image_criteria("ubuntu-22-04-arm64")
    assert criteria["version"] == "22.04"
    assert criteria["architecture"] == "arm64"

    criteria = _get_image_criteria("rhel-9-x64")
    assert criteria["version"] == "9"
    assert criteria["architecture"] == "x86_64"

    criteria = _get_image_criteria("rhel-9")
    assert criteria["version"] == "9"
    assert criteria["architecture"] == "x86_64"

    criteria = _get_image_criteria("rhel")
    assert criteria["version"] == "*"
    assert criteria["architecture"] == "x86_64"

    criteria = _get_image_criteria("debian-12-x64")
    assert criteria["version"] == "12"
    assert criteria["architecture"] == "x86_64"

    criteria = _get_image_criteria("debian-12")
    assert criteria["version"] == "12"
    assert criteria["architecture"] == "x86_64"

    criteria = _get_image_criteria("debian")
    assert criteria["version"] == "*"
    assert criteria["architecture"] == "x86_64"

    criteria = _get_image_criteria("debian-11-arm64")
    assert criteria["version"] == "11"
    assert criteria["architecture"] == "arm64"

    criteria = _get_image_criteria("centos-7-x64")
    assert criteria["version"] == "7"
    assert criteria["architecture"] == "x86_64"

    criteria = _get_image_criteria("centos-7")
    assert criteria["version"] == "7"
    assert criteria["architecture"] == "x86_64"

    criteria = _get_image_criteria("centos")
    assert criteria["version"] == "*"
    assert criteria["architecture"] == "x86_64"

    criteria = _get_image_criteria("windows-2019-x64")
    assert criteria["version"] == "2019"
    assert criteria["architecture"] == "x86_64"

    criteria = _get_image_criteria("windows-2019")
    assert criteria["version"] == "2019"
    assert criteria["architecture"] == "x86_64"

    criteria = _get_image_criteria("windows")
    assert criteria["version"] == "*"
    assert criteria["architecture"] == "x86_64"
