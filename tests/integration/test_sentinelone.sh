#!/bin/bash
#
# Layer 4c - SentinelOne. The reason this image exists.
#
# The agent being installed is checkable; whether it attributes container context
# to podman workloads is not, from here - that needs a registered agent and the
# console. What this file does is make sure the pieces the image is responsible
# for are in place, and report the agent's own view of itself.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"
# shellcheck source=../lib/machine.sh
source "$HERE/../lib/machine.sh"

MACHINE=$(guest_machine) || exit 1
printf 'Testing guest: %s\n' "$MACHINE"

agent_present() {
    # The agent tree is root only, so the check has to run as root - without sudo
    # this reports "no agent" on a machine that has one.
    guest 'sudo test -x /opt/sentinelone/bin/sentinelctl && echo yes || echo no' 2>/dev/null | tr -d '\r'
}

test_agent_installed() {
    if [ "$(agent_present)" != "yes" ]; then
        t_skip "SentinelOne agent is installed" "no agent in this image (built with INSTALL_SENTINELONE=0?)"
        return
    fi
    t_pass "SentinelOne agent is installed"

    local state
    state=$(guest 'systemctl is-active sentinelone' 2>/dev/null | tr -d '\r')
    assert_eq "active" "$state" "the agent service is running"
}

test_agent_reports_healthy() {
    [ "$(agent_present)" = "yes" ] || { t_skip "agent status" "no agent"; return; }

    local status
    status=$(guest 'sudo /opt/sentinelone/bin/sentinelctl control status 2>/dev/null | head -20' 2>/dev/null)
    assert_contains "$status" "Enabled" "the agent reports itself enabled"
    t_info "$(printf '%s' "$status" | grep -iE 'agent state|disk|self' | head -2 | tr '\n' ' ')"
}

test_agent_registration() {
    [ "$(agent_present)" = "yes" ] || { t_skip "agent registration" "no agent"; return; }

    local mgmt
    mgmt=$(guest 'sudo /opt/sentinelone/bin/sentinelctl management status 2>/dev/null' 2>/dev/null)
    if printf '%s' "$mgmt" | grep -qiE 'Connectivity\s+On'; then
        t_pass "the agent is registered and connected"
    else
        # Not a failure of the image: the token is deployed separately.
        t_skip "the agent is registered and connected" \
            "unregistered - container visibility cannot be evaluated until a token is set"
        t_info "$(printf '%s' "$mgmt" | grep -iE 'connectivity|customer id' | head -2 | tr '\n' ' ')"
    fi
}

test_hostname_identifies_the_machine() {
    # The deploy script names the VM after the Mac so it is findable in the console.
    local hostname
    hostname=$(guest 'hostname' 2>/dev/null | tr -d '\r')
    assert_matches "$hostname" '.+' "the machine has a hostname ($hostname)"
    if printf '%s' "$hostname" | grep -q -- '-podman$'; then
        t_pass "the hostname carries the -podman suffix for the console"
    else
        t_skip "the hostname carries the -podman suffix" "hostname is '$hostname' - deploy.sh sets this"
    fi
}

test_agent_sees_container_activity() {
    # Not proof of container attribution, but it does show the agent's sensors
    # are looking at container storage and container processes at all.
    [ "$(agent_present)" = "yes" ] || { t_skip "agent observes containers" "no agent"; return; }

    local marker="s1probe$$"
    guest "podman run --rm --name $marker docker.io/library/alpine:latest echo probe" >/dev/null 2>&1
    sleep 5

    local seen
    seen=$(guest 'sudo grep -aic "containers/storage" /opt/sentinelone/log/providers.log 2>/dev/null || echo 0' 2>/dev/null | tr -d '\r ')
    if [ "${seen:-0}" -gt 0 ]; then
        t_pass "the agent's provider log mentions container storage ($seen lines)"
    else
        t_skip "the agent's provider log mentions container storage" \
            "nothing logged - expected while the agent is unregistered"
    fi
}

run_tests
