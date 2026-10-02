#!/bin/bash
#
# Layer 1 - static checks of the repository. No VM, no image, runs in a second.
#
# Most of these guard a bug that actually shipped. When one of them fails, read
# the assertion text: it says which past failure is coming back.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=../lib/common.sh
source "$HERE/../lib/common.sh"

test_shell_syntax() {
    local f
    while IFS= read -r f; do
        if bash -n "$f" 2>/dev/null; then
            t_pass "$(basename "$f") parses"
        else
            t_fail "$(basename "$f") parses" "$(bash -n "$f" 2>&1 | head -2)"
        fi
    done < <(find "$ROOT" -name '*.sh' -not -path '*/tests/podman-system/vendor/*' -not -path '*/.git/*' | sort)
}

test_python_syntax() {
    local f
    while IFS= read -r f; do
        if python3 -m py_compile "$f" 2>/dev/null; then
            t_pass "$(basename "$f") compiles"
        else
            t_fail "$(basename "$f") compiles" "$(python3 -m py_compile "$f" 2>&1 | head -2)"
        fi
    done < <(find "$ROOT/resources" -name '*.py' | sort)
}

test_build_required_files() {
    # build.sh refuses to start without these; make sure the list matches reality.
    local f missing=0
    while IFS= read -r f; do
        f="${f//\$RESOURCES_DIR/$ROOT/resources}"
        f="${f//\"/}"
        if [ ! -f "$f" ]; then
            t_fail "resource exists: $f" "referenced by build.sh REQUIRED_FILES"
            missing=1
        fi
    done < <(sed -n '/^REQUIRED_FILES=(/,/^)/p' "$ROOT/build.sh" | grep -oE '"\$RESOURCES_DIR/[^"]+"')
    [ "$missing" -eq 0 ] && t_pass "every file in build.sh REQUIRED_FILES exists"
}

test_config_files_parse() {
    local f
    for f in containers.conf storage.conf; do
        if python3 -c "
import sys, tomllib
with open('$ROOT/resources/configs/$f','rb') as fh:
    tomllib.load(fh)
" 2>/dev/null; then
            t_pass "$f is valid TOML"
        else
            t_fail "$f is valid TOML" "$(python3 -c "
import tomllib
with open('$ROOT/resources/configs/$f','rb') as fh: tomllib.load(fh)" 2>&1 | tail -1)"
        fi
    done
}

test_systemd_units() {
    local f content
    for f in "$ROOT"/resources/services/*.service; do
        content=$(cat "$f")
        assert_contains "$content" "[Unit]" "$(basename "$f") has [Unit]"
        assert_contains "$content" "[Service]" "$(basename "$f") has [Service]"
        # every ExecStart must point at a script the image actually installs
        local exec_path
        exec_path=$(grep -oE 'ExecStart=[^ ]+' "$f" | head -1 | cut -d= -f2)
        case "$exec_path" in
            /usr/local/bin/*|/usr/local/sbin/*)
                if grep -q "$(basename "$exec_path")" "$ROOT/resources/install.sh"; then
                    t_pass "$(basename "$f") ExecStart is installed by install.sh"
                else
                    t_fail "$(basename "$f") ExecStart is installed by install.sh" "$exec_path is never installed"
                fi
                ;;
        esac
    done
}

test_storage_driver_is_btrfs() {
    # Regression: the image silently ran on overlay because storage.conf was shadowed.
    # btrfs must come first, and overlay must be there as a fallback - pinning the
    # driver breaks every store that is not on btrfs, /tmp being tmpfs.
    # Directives only - the comments explain what not to do and would match.
    local conf
    conf=$(grep -vE '^[[:space:]]*#' "$ROOT/resources/configs/storage.conf")
    assert_contains "$conf" 'driver_priority = ["btrfs", "overlay"]' \
        "storage.conf prefers btrfs and falls back to overlay"
    assert_not_contains "$conf" 'driver = "btrfs"' \
        "storage.conf does not pin the driver"

    # Pinning these to the rootful paths broke every rootless command on podman
    # 5.8, which honours them where 5.4 silently substituted the user's own.
    assert_not_contains "$conf" "graphroot" "storage.conf does not hardcode graphroot"
    assert_not_contains "$conf" "runroot" "storage.conf does not hardcode runroot"
}

test_configs_survive_podman6_mount() {
    # Regression: podman 6 mounts the host config over /etc/containers, which hid
    # storage.conf and containers.conf. Both must also go to /usr/share/containers.
    local install="$ROOT/resources/install.sh"
    assert_contains "$(cat "$install")" "/usr/share/containers/storage.conf" \
        "install.sh writes storage.conf where the host mount cannot shadow it"
    assert_contains "$(cat "$install")" "/usr/share/containers/containers.conf" \
        "install.sh writes containers.conf where the host mount cannot shadow it"
}

test_etc_containers_mount_is_skipped() {
    # Regression: this mount hid the podman-machine marker, so no published port
    # was ever forwarded to the host.
    assert_contains "$(cat "$ROOT/resources/scripts/ignition-provider.py")" \
        "'etc-containers.mount'" "ignition provider skips etc-containers.mount"
}

test_journal_access_for_podman_logs() {
    # Regression: podman logs was silently empty, which broke kind.
    assert_contains "$(cat "$ROOT/resources/scripts/post-ignition-setup.sh")" \
        "systemd-journal" "post-ignition-setup grants journal access to the user"
}

test_post_ignition_setup_cannot_deadlock_itself() {
    # This shipped and left every new machine hanging at "Starting machine" with
    # an empty serial log: the unit was ordered Before=ssh.service while the
    # script waited on "systemctl reload ssh.service". systemd will not run the
    # job until the unit finishes, and the unit will not finish until the job
    # runs. Only the first boot was affected - on later boots the config file
    # already exists and the reload is skipped - which is exactly what made it
    # slip through.
    local unit script
    unit=$(cat "$ROOT/resources/services/post-ignition-setup.service")
    script=$(cat "$ROOT/resources/scripts/post-ignition-setup.sh")

    # Directives only - the unit explains this trap in a comment that names it.
    local ordering
    ordering=$(printf '%s\n' "$unit" | grep -E '^Before=ssh(d)?\.service' || true)
    if [ -z "$ordering" ]; then
        t_pass "post-ignition-setup is not ordered before the service it reloads"
    else
        t_fail "post-ignition-setup is not ordered before the service it reloads" "$ordering"
    fi

    # Anything it asks systemd for has to be fire and forget, whatever the
    # ordering happens to be.
    local blocking
    blocking=$(printf '%s\n' "$script" | grep -E '^\s*systemctl (reload|restart|start|stop) ' | grep -v -- '--no-block' || true)
    if [ -z "$blocking" ]; then
        t_pass "every systemctl job it queues is --no-block"
    else
        t_fail "every systemctl job it queues is --no-block" "$blocking"
    fi
}

test_journal_access_lands_before_the_user_manager() {
    # Regression: the group was granted, but logind had already started the user's
    # systemd manager, which keeps the groups it started with - so podman's API
    # service read nothing from the journal until the machine was restarted.
    local unit
    unit=$(cat "$ROOT/resources/services/post-ignition-setup.service")
    assert_contains "$unit" "Before=systemd-user-sessions.service" \
        "post-ignition-setup runs before user sessions are permitted"
    assert_contains "$(cat "$ROOT/resources/scripts/post-ignition-setup.sh")" \
        'systemctl restart "user@$USER_UID.service"' \
        "post-ignition-setup restarts a user manager that started too early"
}

test_diagnostics_cover_the_failures_that_shipped() {
    # A generic "dump everything" buries the specific silent failures this image
    # has had, so each of them is asked about by name.
    local diag
    diag=$(cat "$ROOT/resources/scripts/machine-diagnostics.sh")
    assert_contains "$diag" "systemd-journal" "diagnostics check journal access for rootless podman"
    assert_contains "$diag" "user@\${uid}.service" "and check the manager podman inherits its groups from"
    assert_contains "$diag" "findmnt -no SOURCE,FSTYPE /etc/containers" "diagnostics check for a shadowed /etc/containers"
    assert_contains "$diag" "podman-machine" "diagnostics check the machine marker that drives port forwarding"
    assert_contains "$diag" "GraphDriverName" "diagnostics check the effective storage driver"
    assert_contains "$diag" "binfmt_misc" "diagnostics check which x86_64 handler is registered"
    assert_contains "$diag" "podman-machine-ready-signal" "diagnostics report whether the host was told we are ready"
}

test_diagnostics_are_off_the_critical_path() {
    # podman machine start blocks on the ready signal, so the collection must
    # happen after it or every start pays for it.
    local ready before_signal
    ready=$(cat "$ROOT/resources/scripts/podman-machine-ready.sh")
    assert_contains "$ready" "podman-machine-diagnostics" "the ready reporter runs the diagnostics"
    before_signal=$(printf '%s' "$ready" | sed -nE '1,/^send_ready( |$)/p')
    assert_not_contains "$before_signal" "/usr/local/bin/podman-machine-diagnostics" \
        "but only after the ready signal has gone out"
    assert_contains "$ready" "/run/podman-machine-ready-signal" \
        "and the ready signal outcome is recorded for them"
}

test_diagnostics_are_installed_by_install_sh() {
    assert_contains "$(cat "$ROOT/resources/install.sh")" \
        "machine-diagnostics.sh" "install.sh installs the diagnostics script"
}

test_health_uses_the_channel_that_survives() {
    # A vsock endpoint is not available: podman gives the VM one vsock device,
    # port 1025, and the unix socket behind it exists only while machine start
    # waits for the ready signal. The serial console is what is left, and
    # /dev/console is tty0 here - not the port vfkit captures.
    local health
    health=$(cat "$ROOT/resources/scripts/machine-health.sh")
    assert_contains "$health" "/dev/hvc0" "the health report goes to the captured serial port"
    assert_not_contains "$health" 'CONSOLE:-/dev/console' "and not to /dev/console, which reaches nobody"

    # The Groups line in /proc/PID/status is tab separated; splitting on spaces
    # alone leaves "Groups:<tab>999" glued and reports every machine as blind.
    assert_contains "$health" "awk '/^Groups:/ {\$1=\"\"; print}'" \
        "the journal check strips the label before splitting"
}

test_health_does_not_grow_the_host_log_forever() {
    local health
    health=$(cat "$ROOT/resources/scripts/machine-health.sh")
    assert_contains "$health" "HEARTBEAT_SECONDS" "an idle machine only reports on a heartbeat"
    assert_contains "$health" "up=[0-9]*s//" \
        "uptime is excluded from the comparison, or nothing ever looks unchanged"
}

test_health_is_installed_and_scheduled() {
    local install
    install=$(cat "$ROOT/resources/install.sh")
    assert_contains "$install" "machine-health.sh" "install.sh installs the health reporter"
    assert_contains "$install" "systemctl enable podman-machine-health.timer" \
        "and enables the timer that keeps it reporting"
}

test_ansible_is_in_the_image() {
    # systemd-analyze on the generated unit says it plainly when it is not:
    # "Command ansible-playbook is not executable". Installing it on demand at
    # first boot would make a playbook depend on reaching a Debian mirror.
    assert_contains "$(cat "$ROOT/build.sh")" "ansible-core" \
        "the image carries ansible-core for --playbook"
}

test_import_native_ca_lands_somewhere_debian_reads() {
    # "podman machine init --import-native-ca" is how a machine works behind TLS
    # inspection, and it is hard-coded for Fedora: it copies the host CAs into
    # /etc/pki/ca-trust/source/anchors and runs "sudo update-ca-trust". Neither
    # exists on Debian, so without a stand-in the flag imports nothing.
    local shim install
    shim=$(cat "$ROOT/resources/scripts/update-ca-trust.sh")
    install=$(cat "$ROOT/resources/install.sh")

    assert_contains "$install" "/usr/local/sbin/update-ca-trust" \
        "the Fedora command name exists on a path sudo searches"
    assert_contains "$install" "mkdir -p /etc/pki/ca-trust/source/anchors" \
        "and the folder podman copies into exists before it does"
    assert_contains "$shim" "/usr/sbin/update-ca-certificates" \
        "the shim ends in Debian's own trust update"

    # update-ca-certificates only reads *.crt, and podman writes
    # host-ca-certs.pem - the extension has to change on the way across.
    assert_contains "$shim" '.crt' "anchors are renamed to the extension Debian reads"

    # openssl rehash skips a file holding more than one certificate, so a
    # concatenated bundle would land in ca-certificates.crt and never get a hash
    # link - trust by CAfile, refusal by CApath.
    assert_contains "$shim" "BEGIN CERTIFICATE" \
        "the bundle is split so each certificate gets its own hash link"
}

test_podman_socket_fallback() {
    # Without this socket nothing on the Mac can reach the machine at all, so a
    # config that failed to enable it is a total failure - worth a net even
    # though Podman Desktop always sends it.
    local script
    script=$(cat "$ROOT/resources/scripts/post-ignition-setup.sh")
    assert_contains "$script" 'ln -sf "$PODMAN_SOCKET_UNIT" "$SYSTEM_WANTS/podman.socket"' \
        "the fallback enables podman.socket by writing the wants symlink"

    # "systemctl --user" cannot work here: the script runs as root, where --user
    # has no user manager to talk to, and the unit is ordered before user
    # sessions so the manager may not exist yet. Waiting on a job from inside
    # this unit is also how it deadlocked against sshd once.
    local user_calls
    user_calls=$(printf '%s\n' "$script" | grep -vE '^\s*#' | grep -F 'systemctl --user' || true)
    if [ -z "$user_calls" ]; then
        t_pass "and never by asking a user manager that may not be running"
    else
        t_fail "and never by asking a user manager that may not be running" "$user_calls"
    fi

    # Ignition may enable it in either location; creating a second link would be
    # harmless but claiming Ignition had not done it would be a lie in the log.
    assert_contains "$script" '[ -e "$SYSTEM_WANTS/podman.socket" ] || [ -e "$USER_WANTS/podman.socket" ]' \
        "both places Ignition may have enabled it are checked first"
}

test_policy_json_fallback() {
    # Regression: with /etc/containers shadowed, no image could be pulled at all.
    assert_contains "$(cat "$ROOT/resources/scripts/post-ignition-setup.sh")" \
        "policy.json" "post-ignition-setup installs a policy.json fallback"
}

test_package_list() {
    local build="$ROOT/build.sh"
    local packages
    packages=$(sed -n '/^PACKAGES=/,/"$/p' "$build")

    local pkg
    for pkg in podman crun btrfs-progs netavark aardvark-dns passt uidmap nftables; do
        assert_contains "$packages" "$pkg" "package list contains $pkg"
    done

    assert_not_contains "$packages" "docker.io" "package list has no Docker Engine"
    assert_not_contains "$packages" "containerd" "package list has no containerd"

    # The list is the contract between build.sh and install.sh.
    assert_contains "$(cat "$build")" "package-list.txt" "build.sh ships the package list into the image"
    assert_contains "$(cat "$ROOT/resources/install.sh")" "package-list.txt" \
        "install.sh verifies against the shipped package list"
}

test_missing_sentinelone_fails_the_build() {
    # The agent is the point of the image; a build that quietly omits it produces
    # something that passes every other check and does nothing useful.
    assert_contains "$(cat "$ROOT/build.sh")" "but no SentinelAgent*.deb in" \
        "build.sh fails when the agent is requested but absent"
}

test_container_stack_from_unstable() {
    # Stable's podman never moves and backports carries no container packages at
    # all, so the stack comes from unstable - pinned, so nothing else follows it.
    local install
    install=$(cat "$ROOT/resources/install.sh")
    assert_contains "$install" "sid main" "install.sh adds unstable as a source"
    assert_contains "$install" "Pin-Priority: 100" "unstable is pinned below stable"
    assert_contains "$install" 'apt-get install -y -t sid $CONTAINER_STACK' \
        "only the container stack is taken from unstable"
}

test_kernel_comes_from_backports() {
    local install
    install=$(cat "$ROOT/resources/install.sh")
    assert_contains "$install" "trixie-backports" "install.sh pulls a kernel from backports"
    assert_contains "$install" "apt-get purge" "install.sh purges the superseded kernel"
    assert_contains "$install" 'linux-image-$DEB_ARCH' "the kernel package is architecture independent"
}

test_rosetta_is_enabled_at_init() {
    # Rosetta is decided at init time; podman leaves it off by default, so x86_64
    # containers would silently fall back to qemu emulation.
    local deploy
    deploy=$(cat "$ROOT/deploy.sh")
    assert_contains "$deploy" "rosetta = true" "deploy.sh turns Rosetta on"
    assert_contains "$deploy" "containers.conf" "deploy.sh writes the setting where podman re-reads it on every start"

    # And the guest keeps qemu as the fallback when Rosetta is not there.
    assert_contains "$(cat "$ROOT/resources/scripts/rosetta-activate.sh")" "QEMU fallback" \
        "the guest falls back to qemu when Rosetta is unavailable"
}

test_bootloader_verification_present() {
    # Regression: the build reported success while producing an image whose GRUB
    # still searched for the old ext4 UUID.
    local build
    build=$(cat "$ROOT/build.sh")
    assert_contains "$build" "Boot configuration updated and verified" \
        "build.sh verifies the bootloader after conversion"
    assert_contains "$build" "still references the old ext4 UUID" \
        "build.sh fails when a boot config keeps the old UUID"

    # Installing a kernel regenerates grub.cfg, so verifying once before the
    # package installation is not enough any more.
    local calls
    calls=$(printf '%s' "$build" | grep -c '^verify_boot_config ')
    assert_eq "2" "$calls" "the bootloader is verified both after conversion and after customization"
}

test_image_carries_no_machine_identity() {
    # A host key or machine-id created by the build is shared by every machine
    # deployed from the image. The build must not create them, and must strip
    # anything that put them back.
    local install
    install=$(cat "$ROOT/resources/install.sh")

    assert_not_contains "$(grep -vE '^[[:space:]]*#' "$ROOT/resources/install.sh")" "ssh-keygen -A" \
        "the build does not generate host keys"
    assert_contains "$install" "rm -f /etc/ssh/ssh_host_*" \
        "the build removes any host keys before finishing"
    assert_contains "$install" ": > /etc/machine-id" \
        "the build clears the machine-id"

    # ...and something has to create them on the machine, without depending on
    # systemd's first-boot detection.
    local dropin="$ROOT/resources/configs/ssh-hostkeys.conf"
    assert_file_exists "$dropin" "the ssh host key drop-in exists"
    assert_contains "$(cat "$dropin")" "ssh-keygen -A" "the drop-in generates host keys"
    assert_matches "$(cat "$dropin")" 'ExecStartPre=$' "the drop-in resets sshd's own ExecStartPre"
    assert_contains "$install" "10-hostkeys.conf" "install.sh installs the drop-in"
}

test_sshd_does_not_lock_out_the_host() {
    # Every host client arrives from gvproxy's one address. sshd listening before
    # logins were permitted earned that address a penalty at boot, and
    # MaxStartups dropped parallel calls: "podman machine ssh" exited 255, silent.
    local install order conf
    install=$(cat "$ROOT/resources/install.sh")
    order="$ROOT/resources/configs/ssh-after-user-sessions.conf"
    conf=$(grep -vE '^[[:space:]]*#' "$ROOT/resources/configs/podman-machine.conf")

    assert_file_exists "$order" "the ssh ordering drop-in exists"
    assert_matches "$(cat "$order")" '^After=systemd-user-sessions\.service$' \
        "sshd starts only after user sessions are permitted"
    assert_contains "$install" "ssh.service.d/20-after-user-sessions.conf" \
        "install.sh installs the ordering drop-in"
    # The deadlock from 4c3d9ad must not come back the other way round.
    assert_not_contains "$(grep -vE '^[[:space:]]*#' "$ROOT/resources/services/post-ignition-setup.service")" \
        "Before=ssh.service" "post-ignition-setup is still not ordered before ssh"

    assert_matches "$conf" '^PerSourcePenaltyExemptList 192\.168\.127\.1$' \
        "gvproxy's address is exempt from per-source penalties"
    assert_matches "$conf" '^MaxStartups [0-9]{3,}:' "MaxStartups is raised above ten"
}

test_clock_recovers_from_host_sleep() {
    # A sleeping Mac stops the guest clock; Debian's "makestep 1 3" then only
    # slews, and the guest stayed most of a day behind for days.
    local dropin="$ROOT/resources/configs/chrony-podman-machine.conf"
    assert_file_exists "$dropin" "the chrony drop-in exists"
    assert_matches "$(cat "$dropin")" '^makestep [0-9.]+ -1$' "chrony may step the clock at any time"
    assert_contains "$(cat "$ROOT/resources/install.sh")" "/etc/chrony/conf.d/podman-machine.conf" \
        "install.sh installs the chrony drop-in"
}

test_health_reports_ssh() {
    local health
    health=$(cat "$ROOT/resources/scripts/machine-health.sh")
    assert_contains "$health" "field ssh" "the health line reports sshd"
    assert_contains "$health" "Maxstartups" "and counts connections sshd dropped"
}

test_restart_always_survives_a_machine_restart() {
    # Debian does not apply presets to user units, so podman-restart.service sat
    # disabled and --restart=always containers stayed down after every restart.
    local install
    install=$(grep -vE '^[[:space:]]*#' "$ROOT/resources/install.sh")
    assert_contains "$install" "systemctl --global enable podman-restart.service" \
        "podman-restart is enabled for rootless containers"
    assert_matches "$install" '^systemctl enable podman-restart\.service$' \
        "and for rootful ones"
}

test_base_image_is_never_used_unverified() {
    # An unreachable SHA512SUMS, or one without a line for the image, used to
    # mean "skip the check". The cached image was never checked at all.
    local build tmp out
    build=$(cat "$ROOT/build.sh")
    assert_contains "$build" "refusing an unverified base image" \
        "a missing SHA512SUMS stops the build"
    assert_contains "$build" 'verify_base_image "$BASE_IMAGE"' "the cached image is verified too"
    assert_contains "$build" '"$BASE_IMAGE.part"' "a download only becomes the cache once verified"

    # The functions themselves, against a real file and a real checksum list.
    tmp=$(mktemp -d)
    printf 'image bytes' > "$tmp/img"
    out=$( (
        set +e
        eval "$(awk '/^expected_checksum\(\) \{/,/^}/' "$ROOT/build.sh")"
        eval "$(awk '/^verify_base_image\(\) \{/,/^}/' "$ROOT/build.sh")"
        IMAGE_FILE_NAME=debian-13-generic-arm64.qcow2
        CHECKSUM_FILE="$tmp/sums"
        sum=$(sha512sum "$tmp/img" | awk '{print $1}')
        printf '%s  debian-13-generic-arm64.qcow2.json\n%s  debian-13-generic-arm64.qcow2\n' 0000 "$sum" > "$CHECKSUM_FILE"
        verify_base_image "$tmp/img" >/dev/null && echo match-ok
        printf '%s  debian-13-generic-arm64.qcow2\n' 0000 > "$CHECKSUM_FILE"
        verify_base_image "$tmp/img" >/dev/null || echo mismatch-refused
        printf '%s  debian-13-generic-amd64.qcow2\n' "$sum" > "$CHECKSUM_FILE"
        verify_base_image "$tmp/img" >/dev/null || echo missing-line-refused
    ) 2>&1)
    rm -rf "$tmp"
    assert_contains "$out" "match-ok" "a matching checksum passes"
    assert_contains "$out" "mismatch-refused" "a different checksum is refused"
    assert_contains "$out" "missing-line-refused" "no line for the image is refused, not skipped"
}

test_agent_token_does_not_linger_in_the_cache() {
    local build
    build=$(cat "$ROOT/build.sh")
    assert_not_contains "$build" '> "$CACHE_DIR/sentinelone-token"' \
        "the token is not written to a fixed file in the cache"
    assert_contains "$build" 'umask 077 && mktemp' "it goes into a private temporary file"
    assert_contains "$build" "trap 'rm -f \"\$TOKEN_FILE\"' EXIT" "which is removed however the build ends"
}

test_ready_signal_failure_fails_the_unit() {
    # Restart=on-failure only retries what fails; the script used to end on a
    # successful logger call whatever happened to the signal.
    assert_contains "$(cat "$ROOT/resources/scripts/podman-machine-ready.sh")" "send_ready || exit 1" \
        "a ready signal that never went out fails the unit"
    assert_contains "$(cat "$ROOT/resources/services/podman-machine-ready.service")" "Restart=on-failure" \
        "and the unit retries it"
}

test_health_detects_a_dead_podman() {
    # Without pipefail the status was wc's, so "unresponsive" never appeared,
    # and a hung podman hung the timer with it.
    local health
    health=$(grep -vE '^[[:space:]]*#' "$ROOT/resources/scripts/machine-health.sh")
    assert_not_contains "$health" "podman ps -q 2>/dev/null | wc" \
        "podman's exit status is not lost in a pipeline"
    assert_contains "$health" 'timeout "$PODMAN_TIMEOUT"' "podman calls are bounded"
}

test_ready_waits_for_a_real_address() {
    # "inet " alone matched 127.0.0.1, so the network wait passed at once.
    assert_contains "$(cat "$ROOT/resources/scripts/podman-machine-ready.sh")" \
        'ip -4 addr show scope global | grep -q "inet "' "the network wait ignores loopback"
}

test_build_host_dependencies_are_complete() {
    # build.sh runs btrfs-convert; install-deps did not install it.
    assert_contains "$(cat "$ROOT/Makefile")" "btrfs-progs" "make install-deps installs btrfs-progs"
    assert_contains "$(cat "$ROOT/docs/build.md")" "btrfs-progs" "and the build docs list it"
}

test_partition_hint_is_anchored() {
    # "hd0,gpt1" is also the start of "hd0,gpt15". The expression from build.sh,
    # run on what grub-mkconfig writes.
    local expr out
    expr=$(grep -o -e '-e "s/(hd0.*g"' "$ROOT/build.sh")
    assert_ne "" "$expr" "build.sh rewrites partition hints with an anchored expression"
    out=$(ROOT_PARTNUM=2; printf '%s\n' "set root='hd0,gpt1'" \
        "--hint-efi=hd0,gpt1 --hint-baremetal=ahci0,gpt1 UUID" "set root='hd0,gpt15'" \
        | eval "sed -E $expr")
    assert_contains "$out" "set root='hd0,gpt2'" "gpt1 becomes the root partition"
    assert_contains "$out" "--hint-efi=hd0,gpt2 --hint-baremetal=ahci0,gpt2 UUID" "in every hint"
    assert_contains "$out" "set root='hd0,gpt15'" "and gpt15 is left alone"
}

test_ssh_takes_keys_only() {
    local conf
    conf=$(grep -vE '^[[:space:]]*#' "$ROOT/resources/configs/podman-machine.conf")
    assert_matches "$conf" '^PasswordAuthentication no$' "password logins are off"
    assert_matches "$conf" '^KbdInteractiveAuthentication no$' "keyboard-interactive too"
}

test_no_sysctl_that_never_applies() {
    # net.bridge.* only exists with br_netfilter loaded, which nothing loads.
    assert_not_contains "$(cat "$ROOT/resources/configs/99-podman.conf")" "net.bridge." \
        "no bridge netfilter settings that could never take effect"
}

test_documentation_links_resolve() {
    # Docs rot quietly; a link to a file that was renamed is worse than no link.
    local doc target missing=0
    while IFS= read -r doc; do
        while IFS= read -r target; do
            case "$target" in
                http*|"#"*) continue ;;
            esac
            target="${target%%#*}"
            [ -n "$target" ] || continue
            if [ ! -e "$(dirname "$doc")/$target" ]; then
                t_fail "link resolves: $target" "referenced from $(basename "$doc")"
                missing=1
            fi
        done < <(grep -oE '\]\([^)]+\)' "$doc" | sed -E 's/^\]\(//; s/\)$//')
    done < <(find "$ROOT/docs" "$ROOT" -maxdepth 1 -name '*.md' 2>/dev/null; find "$ROOT/docs" -name '*.md' 2>/dev/null)
    [ "$missing" -eq 0 ] && t_pass "every relative link in the documentation resolves"
}

run_tests
