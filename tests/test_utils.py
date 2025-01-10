from cf_remote.utils import has_unescaped_character, parse_envfile


def test_parse_envfile():
    data = parse_envfile('NTD_TEST="test"')
    assert "NTD_TEST" in data
    assert data["NTD_TEST"] == "test"

    data = parse_envfile('NTD_TEST="\\"helloworld\\""')
    assert data["NTD_TEST"] == '"helloworld"'

    data = parse_envfile('NTD_TEST=""helloworld""')
    assert data is None

    data = parse_envfile('NTD_TEST="\n"')
    assert data is None

    data = parse_envfile('NTD_TEST="\\nhello"')
    assert data["NTD_TEST"] == "\nhello"

    # 2 lines:
    data = parse_envfile('NTD_TEST="test"\nNTD_HELLO="hello"')
    assert len(data) == 2
    assert data["NTD_TEST"] == "test"
    assert data["NTD_HELLO"] == "hello"
    # Empty value is allowed:
    data = parse_envfile('NTD_EMPTY=""')
    assert data["NTD_EMPTY"] == ""
    # Empty key is not allowed:
    assert parse_envfile('="value"') is None
    # Lowercase key not allowed:
    assert parse_envfile('NTD_key="value"') is None
    # Various cases of things which are not allowed:
    assert parse_envfile("") is None
    assert parse_envfile("=") is None
    assert parse_envfile('""=""') is None
    assert parse_envfile('=""') is None
    assert parse_envfile('""=') is None
    assert parse_envfile(" ") is None
    assert parse_envfile('NTD_TEST="NTD_TEST_TWO="test"\\nhello"') is None


def test_has_unescaped_character():
    assert not has_unescaped_character(r"test", '"')
    assert not has_unescaped_character(r"\"test\"", '"')
    assert has_unescaped_character(r'hello"world', '"')
    assert has_unescaped_character(r'hello\""world', '"')
