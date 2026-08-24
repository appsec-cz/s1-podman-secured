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
    assert_contains "$deploy" "rosetta = true" "deploy.sh turns Rosetta on for the machine"
    assert_contains "$deploy" "CONTAINERS_CONF=" "deploy.sh passes the config to podman machine init"

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

run_tests
