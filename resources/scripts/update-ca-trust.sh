#!/bin/bash
#
# Debian stand-in for the Fedora command podman reaches for.
#
# "podman machine init --import-native-ca" exists to make a machine work behind
# TLS inspection: it reads the host's trusted CAs, copies them into the guest and
# updates the trust store. Both halves are hard-coded for Fedora CoreOS -
# podman writes to /etc/pki/ca-trust/source/anchors and then runs
# "sudo update-ca-trust". Neither exists on Debian, so on this image the flag
# fails outright or, worse, appears to work and imports nothing.
#
# Two details decide whether this actually takes effect:
#   - update-ca-certificates only reads files named *.crt, and podman writes
#     host-ca-certs.pem, so the extension has to change on the way across
#   - that file holds every CA the host trusts concatenated, and it has to be
#     split. Debian does cat a multi-certificate file into the bundle, so trust
#     by CAfile would work either way - but it symlinks and hashes each anchor
#     into /etc/ssl/certs, and "openssl rehash" skips any file holding more than
#     one certificate. Left whole, the CAs land in ca-certificates.crt and never
#     get a hash link, so anything verifying by CApath still refuses them.
#
# Anchors this script has installed before are removed first, so dropping a
# certificate on the host really does drop the trust here.
set -u

ANCHORS=/etc/pki/ca-trust/source/anchors
LOCAL_ANCHORS=/usr/local/share/ca-certificates
PREFIX=podman-anchor-

if [ ! -d "$ANCHORS" ]; then
    echo "update-ca-trust: no $ANCHORS, nothing to import"
    exec /usr/sbin/update-ca-certificates
fi

mkdir -p "$LOCAL_ANCHORS"
find "$LOCAL_ANCHORS" -maxdepth 1 -type f -name "${PREFIX}*.crt" -delete 2>/dev/null

imported=0
for anchor in "$ANCHORS"/*; do
    [ -f "$anchor" ] || continue
    base=$(basename "$anchor")
    stem="$LOCAL_ANCHORS/${PREFIX}${base%.*}"
    count=$(awk -v stem="$stem" '
        /-----BEGIN CERTIFICATE-----/ { n++; out = sprintf("%s-%03d.crt", stem, n) }
        n > 0 { print > out }
        /-----END CERTIFICATE-----/   { close(out) }
        END { print n + 0 }
    ' "$anchor" 2>/dev/null)
    chmod 644 "$stem"-*.crt 2>/dev/null
    imported=$((imported + ${count:-0}))
done
echo "update-ca-trust: took $imported certificate(s) from $ANCHORS"

exec /usr/sbin/update-ca-certificates
