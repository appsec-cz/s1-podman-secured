#!/bin/bash
#
# Shared assertions and reporting for the test suite.
#
# Every test file sources this, declares its tests as functions named test_*,
# and calls run_tests at the end. Output is one line per assertion so a failing
# run says what broke without re-running anything by hand.

# shellcheck disable=SC2034
_TESTS_PASSED=0
_TESTS_FAILED=0
_TESTS_SKIPPED=0
_CURRENT_TEST=""
_FAILURES=()

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
DIM='\033[2m'
NC='\033[0m'

# --- reporting ---------------------------------------------------------------

t_section() {
    printf '\n%b── %s ──%b\n' "$BLUE" "$1" "$NC"
}

t_pass() {
    _TESTS_PASSED=$((_TESTS_PASSED + 1))
    printf '  %bok%b   %s\n' "$GREEN" "$NC" "$1"
}

t_fail() {
    _TESTS_FAILED=$((_TESTS_FAILED + 1))
    _FAILURES+=("${_CURRENT_TEST}: $1")
    printf '  %bFAIL%b %s\n' "$RED" "$NC" "$1"
    [ -n "${2:-}" ] && printf '       %b%s%b\n' "$DIM" "$2" "$NC"
    return 0
}

t_skip() {
    _TESTS_SKIPPED=$((_TESTS_SKIPPED + 1))
    printf '  %bskip%b %s %b(%s)%b\n' "$YELLOW" "$NC" "$1" "$DIM" "${2:-no reason given}" "$NC"
}

t_info() {
    printf '       %b%s%b\n' "$DIM" "$1" "$NC"
}

# --- assertions --------------------------------------------------------------
# Each takes a human readable description last, so failures read like sentences.

assert_eq() {
    local expected="$1" actual="$2" desc="$3"
    if [ "$expected" = "$actual" ]; then
        t_pass "$desc"
    else
        t_fail "$desc" "expected '$expected', got '$actual'"
    fi
}

assert_ne() {
    local unexpected="$1" actual="$2" desc="$3"
    if [ "$unexpected" != "$actual" ]; then
        t_pass "$desc"
    else
        t_fail "$desc" "expected anything but '$unexpected'"
    fi
}

assert_contains() {
    local haystack="$1" needle="$2" desc="$3"
    if printf '%s' "$haystack" | grep -qF -- "$needle"; then
        t_pass "$desc"
    else
        t_fail "$desc" "'$needle' not found in: $(printf '%s' "$haystack" | head -c 200)"
    fi
}

assert_not_contains() {
    local haystack="$1" needle="$2" desc="$3"
    if printf '%s' "$haystack" | grep -qF -- "$needle"; then
        t_fail "$desc" "'$needle' unexpectedly present"
    else
        t_pass "$desc"
    fi
}

assert_matches() {
    local value="$1" regex="$2" desc="$3"
    if printf '%s' "$value" | grep -qE -- "$regex"; then
        t_pass "$desc"
    else
        t_fail "$desc" "'$value' does not match /$regex/"
    fi
}

assert_ok() {
    local desc="$1"; shift
    local out rc
    out=$("$@" 2>&1); rc=$?
    if [ $rc -eq 0 ]; then
        t_pass "$desc"
    else
        t_fail "$desc" "exit $rc: $(printf '%s' "$out" | head -c 200)"
    fi
}

assert_fails() {
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then
        t_fail "$desc" "command unexpectedly succeeded"
    else
        t_pass "$desc"
    fi
}

assert_file_exists() {
    if [ -f "$1" ]; then t_pass "$2"; else t_fail "$2" "no such file: $1"; fi
}

# --- runner ------------------------------------------------------------------

run_tests() {
    local filter="${TEST_FILTER:-}"
    local fn
    for fn in $(declare -F | awk '{print $3}' | grep '^test_' | sort); do
        if [ -n "$filter" ] && [[ "$fn" != *"$filter"* ]]; then
            continue
        fi
        _CURRENT_TEST="$fn"
        t_section "${fn#test_}"
        "$fn"
    done
    t_summary
}

t_summary() {
    printf '\n'
    if [ "$_TESTS_FAILED" -eq 0 ]; then
        printf '%b%d passed%b' "$GREEN" "$_TESTS_PASSED" "$NC"
    else
        printf '%b%d failed%b, %d passed' "$RED" "$_TESTS_FAILED" "$NC" "$_TESTS_PASSED"
    fi
    [ "$_TESTS_SKIPPED" -gt 0 ] && printf ', %b%d skipped%b' "$YELLOW" "$_TESTS_SKIPPED" "$NC"
    printf '\n'

    if [ "$_TESTS_FAILED" -gt 0 ]; then
        printf '\nFailures:\n'
        printf '  - %s\n' "${_FAILURES[@]}"
        return 1
    fi
    return 0
}
