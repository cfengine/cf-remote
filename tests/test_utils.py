import os
import shutil
from multiprocessing import Pool
from cf_remote.utils import has_unescaped_character, parse_envfile, copy_file


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


def copy_file_with_args(args):
    src, dest = args
    copy_file(src, dest)


def test_copy_file():

    src_dir = "/tmp/cf-remote-test-src/"
    dest_dir = "/tmp/cf-remote-test-dest/"
    os.makedirs(src_dir, exist_ok=True)
    os.makedirs(dest_dir, exist_ok=True)

    src_file = "myfile.txt"
    dest_file = "copy.txt"

    src = os.path.join(src_dir, src_file)
    dest = os.path.join(dest_dir, dest_file)

    with open(src, "w") as f:
        f.write("This is a test file for atomic copy.")

    num_processes = 10

    with Pool(num_processes) as copy_pool:
        copy_pool.map(copy_file_with_args, [(src, dest) for _ in range(num_processes)])

    content = None
    try:
        with open(dest, "r") as f:
            content = f.read()
    except:
        assert False

    assert content
    assert content == "This is a test file for atomic copy."
    assert os.listdir(dest_dir) == [dest_file]

    shutil.rmtree(src_dir)
    shutil.rmtree(dest_dir)
