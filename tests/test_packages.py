import json
from collections import OrderedDict

from cf_remote.packages import Release
from cf_remote import log

# log.set_level("debug")


def test_release():
    with open("tests/master-releases.json") as file:
        data = file.read()
    json_data = json.loads(data, object_pairs_hook=OrderedDict)
    data = {
        "URL": "test-release-url",
        "version": "master",
        "lts_branch": "test-lts-branch",
        "data": json_data,
    }
    release = Release(data)
    release.init_download()
    found = release.find(["arm64", "ubuntu", "20"])
    assert (
        found[0].filename
        == "cfengine-nova-hub_3.21.0a.138df3742~21749.ubuntu22_arm64.deb"
    )
    assert "hub" in found[0].tags
    assert (
        found[1].filename == "cfengine-nova_3.21.0a.138df3742~21749.ubuntu22_arm64.deb"
    )
    assert "hub" not in found[1].tags

    found = release.find(["aarch64", "ubuntu22"])
    assert (
        found[0].filename
        == "cfengine-nova-hub_3.21.0a.138df3742~21749.ubuntu22_arm64.deb"
    )
    assert "hub" in found[0].tags
    assert (
        found[1].filename == "cfengine-nova_3.21.0a.138df3742~21749.ubuntu22_arm64.deb"
    )
    assert "hub" not in found[1].tags
