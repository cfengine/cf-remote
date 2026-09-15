import pytest

from cf_remote import commands
from cf_remote.remote import print_info

HUB_1 = "admin@34.243.147.219"
HUB_2 = "admin@34.243.147.220"
CLIENT_1 = "admin@34.243.147.221"

DATA_BY_HOST = {
    HUB_1: {"ssh": HUB_1, "role": "hub", "agent_version": None},
    HUB_2: {"ssh": HUB_2, "role": "hub", "agent_version": None},
    CLIENT_1: {"ssh": CLIENT_1, "role": "client", "agent_version": None},
}

# Literal JSON string to guarantee the insertion order for python 3.5
CLOUD_STATE_JSON = """
{
  "@mygroup": {
    "meta": {"provider": "aws", "region": "eu-west-1"},
    "mygroup-1": {"user": "admin", "role": "hub", "public_ips": ["34.243.147.219"]},
    "mygroup-2": {"user": "admin", "role": "hub", "public_ips": ["34.243.147.220"]},
    "mygroup-3": {"user": "admin", "role": "client", "public_ips": ["34.243.147.221"]}
  }
}
"""


@pytest.fixture
def cloud_state(tmp_path, monkeypatch):
    state_path = tmp_path / "cloud_state.json"
    state_path.write_text(CLOUD_STATE_JSON)
    monkeypatch.setattr(commands, "CLOUD_STATE_FPATH", str(state_path))
    return state_path


@pytest.fixture(autouse=True)
def fake_get_info(monkeypatch):
    monkeypatch.setattr(
        commands, "get_info", lambda host, users=None: DATA_BY_HOST[host]
    )


def render(hosts, capsys):
    """Render the exact output cf-remote would print for these hosts."""
    for host in hosts:
        print_info(DATA_BY_HOST[host])
    return capsys.readouterr().out


def test_info_without_hosts_shows_all_hubs(cloud_state, capsys):
    expected = render([HUB_1, HUB_2], capsys)

    errors = commands.info(None)
    actual = capsys.readouterr().out

    assert errors == 0
    assert actual == expected


def test_info_with_all_shows_every_host(cloud_state, capsys):
    expected = render([HUB_1, HUB_2, CLIENT_1], capsys)

    errors = commands.info(None, all=True)
    actual = capsys.readouterr().out

    assert errors == 0
    assert actual == expected
