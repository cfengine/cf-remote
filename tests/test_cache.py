from cf_remote.utils import cache

_calls = 0


@cache
def _add_x_y(x=0, y=0):
    global _calls
    _calls += 1
    return x + y


def test_cache():
    global _calls
    assert _calls == 0

    assert _add_x_y(2, 3) == 5
    assert _calls == 1
    assert _add_x_y(2, 3) == 5
    assert _calls == 1

    # cache decorator doesn't convert between args and kwargs,
    # so this will be one more call:
    assert _add_x_y(x=2, y=3) == 5
    assert _calls == 2
    assert _add_x_y(x=2, y=3) == 5
    assert _calls == 2

    # Keys are sorted, no new call:
    assert _add_x_y(y=3, x=2) == 5
    assert _calls == 2
    assert _add_x_y(y=3, x=2) == 5
    assert _calls == 2

    # If we pass string 2 instead of int, function should be called and
    # will raise TypeError:
    try:
        _add_x_y("2", 3)
        assert False
    except TypeError:
        assert True
    assert _calls == 3
