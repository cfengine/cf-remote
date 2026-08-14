import argparse

from cf_remote.args import add_switch_user_args, get_arg_parser


def test_switch_user_args_are_added_to_every_parser():
    # Memoizing this would key on parsers that look alike, so a second one
    # would quietly get none of these and reading them would raise
    for _ in range(2):
        ap = argparse.ArgumentParser(description="Spooky CFEngine at a distance")
        add_switch_user_args(ap)
        args = ap.parse_args([])
        assert args.ask_pass is False
        assert args.password_file is None
        assert args.switch_user_command is None


def test_switch_user_options_reach_the_real_parser():
    args = get_arg_parser().parse_args(["info", "-H", "somehost"])
    assert args.ask_pass is False
    assert args.password_file is None
    assert args.switch_user_command is None


def test_password_sources_are_mutually_exclusive(capsys):
    ap = get_arg_parser()
    try:
        ap.parse_args(["--ask-pass", "--password-file", "/tmp/x", "info", "-H", "h"])
    except SystemExit:
        pass
    assert "not allowed with argument" in capsys.readouterr().err
