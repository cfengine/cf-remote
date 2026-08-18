from cf_remote import aramid

# A process that writes more than a pipe buffer holds before it reads anything,
# so it stops reading while there is still output to collect. Writing to
# 'proc.stdin' ourselves is what deadlocks on that, which is why the input goes
# to 'communicate()' instead.
_TALKS_BEFORE_LISTENING = ["sh", "-c", "yes ohnoes | head -c 200000; cat"]

# Slow enough that collecting the output takes more than one call
_SLOW_TO_ANSWER = ["sh", "-c", "sleep 0.5; cat"]


def _run(args, stdin_input=None, timeout=0.01):
    """Run 'args' the way :func:`aramid.execute` runs a command on a host

    :return: the result and how many times collecting it timed out
    """
    proc = aramid._popen(args, stdin_input=stdin_input)
    task = aramid._Task(
        aramid.Host("somehost"), proc, " ".join(args), stdin_input=stdin_input
    )
    timeouts = 0
    while not task.communicate(timeout=timeout):
        timeouts += 1
    return task.get_result(), timeouts


def test_input_arrives_and_no_output_is_lost():
    result, _ = _run(_TALKS_BEFORE_LISTENING, stdin_input="hunter2\n")

    assert result.retcode == 0
    assert len(result.stdout) == 200000 + len("hunter2\n")
    assert result.stdout.endswith("hunter2\n")


def test_input_is_only_handed_over_once():
    # 'communicate()' keeps writing what the first call gave it and raises if a
    # later one gives it the same input again, and timing out is normal here
    result, timeouts = _run(_SLOW_TO_ANSWER, stdin_input="hunter2\n")

    assert timeouts > 0, "the command answered too quickly to test anything"
    assert result.retcode == 0
    assert result.stdout == "hunter2\n"


def test_empty_input_closes_standard_input():
    # An empty string is not the same as None: the command gets a pipe that is
    # closed with nothing in it, so it sees EOF instead of blocking on the
    # terminal cf-remote was started from
    result, _ = _run(["sh", "-c", "cat"], stdin_input="")

    assert result.retcode == 0
    assert result.stdout == ""


def test_output_and_exit_code_come_back_without_input():
    result, _ = _run(["sh", "-c", "echo hello; exit 3"])

    assert result.retcode == 3
    assert result.stdout == "hello\n"
