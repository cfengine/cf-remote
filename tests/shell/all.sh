#!/usr/bin/env bash
echo "Warning: These shell based tests use the cf-remote you have installed"
echo "         If you haven't already, run: pip install ."
set -e

_passed=0
_failed=0
_skipped=0
_total=0
_failures=""
_suite_start=$(date +%s)

run_test() {
    local test_script="$1"
    local test_name
    test_name=$(basename "$test_script" .sh)
    _total=$((_total + 1))

    local start end elapsed
    start=$(date +%s)

    local output
    local exit_code=0
    output=$(bash "$test_script" 2>&1) || exit_code=$?

    end=$(date +%s)
    elapsed=$((end - start))

    if [ $exit_code -eq 0 ]; then
        if echo "$output" | grep -q "^--- SKIP:"; then
            _skipped=$((_skipped + 1))
            echo "--- SKIP: $test_name (${elapsed}s)"
        else
            _passed=$((_passed + 1))
            echo "--- PASS: $test_name (${elapsed}s)"
        fi
    else
        _failed=$((_failed + 1))
        _failures="${_failures}  ${test_name}\n"
        echo "--- FAIL: $test_name (${elapsed}s)"
        echo "$output"
        echo "---"
    fi
}

run_test tests/shell/001_migrate_dirs.sh

# Summary
_suite_end=$(date +%s)
_suite_elapsed=$((_suite_end - _suite_start))
echo ""
echo "=============================="
echo "Test Results: $_passed passed, $_failed failed, $_skipped skipped (total: $_total, ${_suite_elapsed}s)"
if [ $_failed -gt 0 ]; then
    echo ""
    echo "Failed tests:"
    echo -e "$_failures"
    exit 1
fi
echo "=============================="
echo "All cf-remote shell tests completed successfully!"
