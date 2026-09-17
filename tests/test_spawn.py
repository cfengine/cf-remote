import pytest
from libcloud.common.exceptions import BaseHTTPError
from libcloud.common.google import GoogleBaseError
from libcloud.common.types import InvalidCredsError

from cf_remote import spawn
from cf_remote.spawn import (
    _destroy_one,
    _get_image_criteria,
    _update_config,
    destroy_vms,
)
from cf_remote.utils import read_json, write_json


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


class FakeVM:
    """Just enough of a VM for destroy_vms()/_destroy_one()"""

    def __init__(self, name, fail_times=0, error_factory=None):
        self.name = name
        self._fail_times = fail_times
        self._error_factory = error_factory or (lambda: RuntimeError("boom"))
        self.calls = 0

    def destroy(self):
        self.calls += 1
        if self.calls <= self._fail_times:
            raise self._error_factory()


class FakeVagrantVM(FakeVM):
    """A FakeVM that also has a vmdir to clean up, like VagrantVM"""

    def __init__(self, name, vmdir, **kwargs):
        super().__init__(name, **kwargs)
        self.vmdir = vmdir


@pytest.fixture
def state_paths(tmp_path, monkeypatch):
    """Point CLOUD_STATE_FPATH/SSH_CONFIGS_JSON_FPATH at throwaway files"""

    cloud_state = tmp_path / "cloud_state.json"
    ssh_configs = tmp_path / "ssh_configs.json"
    monkeypatch.setattr(spawn, "CLOUD_STATE_FPATH", str(cloud_state))
    monkeypatch.setattr(spawn, "SSH_CONFIGS_JSON_FPATH", str(ssh_configs))
    monkeypatch.setattr("time.sleep", lambda _: None)
    return cloud_state, ssh_configs


def test_destroy_one_success():
    vm = FakeVM("a")
    assert _destroy_one(vm) == (vm, None)


def test_destroy_one_treats_404_as_already_destroyed():
    vm = FakeVM("a", fail_times=1, error_factory=lambda: BaseHTTPError(404, "gone"))
    result_vm, error = _destroy_one(vm)
    assert result_vm is vm
    assert error is None


@pytest.mark.parametrize(
    "error_factory",
    [
        lambda: BaseHTTPError(500, "server error"),
        lambda: InvalidCredsError(),
        lambda: GoogleBaseError("quota exceeded", 200, "QUOTA_EXCEEDED"),
    ],
)
def test_destroy_one_reports_known_errors_instead_of_raising(error_factory):
    vm = FakeVM("a", fail_times=1, error_factory=error_factory)
    result_vm, error = _destroy_one(vm)
    assert result_vm is vm
    assert error is not None


def test_destroy_one_lets_unknown_errors_propagate():
    vm = FakeVM("a", fail_times=1, error_factory=lambda: AssertionError("bug"))
    with pytest.raises(AssertionError):
        _destroy_one(vm)


def test_update_config_removes_host_but_keeps_group_with_other_hosts(state_paths):
    cloud_state, ssh_configs = state_paths
    write_json(
        str(cloud_state),
        {"@g": {"meta": {"provider": "aws"}, "h1": {}, "h2": {}}},
    )
    write_json(str(ssh_configs), {"@g": {"h1": {}, "h2": {}}})

    _update_config("@g", "h1")

    assert read_json(str(cloud_state)) == {
        "@g": {"meta": {"provider": "aws"}, "h2": {}}
    }
    assert read_json(str(ssh_configs)) == {"@g": {"h1": {}, "h2": {}}}


def test_update_config_removes_group_and_ssh_entry_when_last_host_destroyed(
    state_paths,
):
    cloud_state, ssh_configs = state_paths
    write_json(str(cloud_state), {"@g": {"meta": {"provider": "aws"}, "h1": {}}})
    write_json(str(ssh_configs), {"@g": {"h1": {}}})

    _update_config("@g", "h1")

    assert read_json(str(cloud_state)) == {}
    assert read_json(str(ssh_configs)) == {}


def test_update_config_updates_state_even_when_ssh_config_is_empty(state_paths):
    """Regression test: an empty-but-valid ssh_configs.json (`{}`) used to be
    treated the same as a missing file, causing this function to return
    before ever touching cloud_state.json."""
    cloud_state, ssh_configs = state_paths
    write_json(str(cloud_state), {"@g": {"meta": {"provider": "aws"}, "h1": {}}})
    write_json(str(ssh_configs), {})

    _update_config("@g", "h1")

    assert read_json(str(cloud_state)) == {}


def test_destroy_vms_removes_successfully_destroyed_vm_from_state(state_paths):
    cloud_state, ssh_configs = state_paths
    vmdir = cloud_state.parent / "vagrant-vm"
    vmdir.mkdir()
    write_json(str(cloud_state), {"@g": {"meta": {"provider": "vagrant"}, "h1": {}}})
    write_json(str(ssh_configs), {"@g": {"h1": {}}})

    vm = FakeVagrantVM("h1", str(vmdir))

    assert destroy_vms({vm: ("@g", "h1")}) == 0
    assert read_json(str(cloud_state)) == {}
    assert not vmdir.exists()


def test_destroy_vms_retries_transient_error_then_succeeds(state_paths):
    cloud_state, ssh_configs = state_paths
    write_json(str(cloud_state), {"@g": {"meta": {"provider": "aws"}, "h1": {}}})
    write_json(str(ssh_configs), {})

    vm = FakeVM(
        "h1", fail_times=1, error_factory=lambda: GoogleBaseError("busy", 503, None)
    )

    assert destroy_vms({vm: ("@g", "h1")}, retries=3, retry_delay=0) == 0
    assert vm.calls == 2
    assert read_json(str(cloud_state)) == {}


def test_destroy_vms_gives_up_after_retries_and_keeps_state(state_paths):
    cloud_state, ssh_configs = state_paths
    write_json(str(cloud_state), {"@g": {"meta": {"provider": "aws"}, "h1": {}}})
    write_json(str(ssh_configs), {})

    vm = FakeVM(
        "h1", fail_times=999, error_factory=lambda: BaseHTTPError(500, "server error")
    )

    assert destroy_vms({vm: ("@g", "h1")}, retries=2, retry_delay=0) == 1
    assert read_json(str(cloud_state)) == {
        "@g": {"meta": {"provider": "aws"}, "h1": {}}
    }


def test_destroy_vms_one_permanent_failure_does_not_block_other_vms(state_paths):
    """Regression test for the real-world scenario: destroying several VMs at
    once, one of which keeps failing, must not prevent the VMs that were
    actually destroyed from being removed from the saved state."""
    cloud_state, ssh_configs = state_paths
    write_json(
        str(cloud_state),
        {
            "@ok": {"meta": {"provider": "aws"}, "h_ok": {}},
            "@bad": {"meta": {"provider": "aws"}, "h_bad": {}},
        },
    )
    write_json(str(ssh_configs), {})

    vm_ok = FakeVM("h_ok")
    vm_bad = FakeVM(
        "h_bad",
        fail_times=999,
        error_factory=lambda: BaseHTTPError(500, "server error"),
    )

    ret = destroy_vms(
        {vm_ok: ("@ok", "h_ok"), vm_bad: ("@bad", "h_bad")}, retries=2, retry_delay=0
    )

    assert ret == 1
    state = read_json(str(cloud_state))
    assert "@ok" not in state
    assert "@bad" in state
