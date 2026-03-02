#!/usr/bin/env bash
# create-signing-key.sh — Generate a GPG signing key for wazuh-archiver
#
# The PRIVATE key stays on this machine (used to sign each archive).
# The PUBLIC key is shared with the compliance team (used to verify signatures).
#
# Run as root: sudo bash create-signing-key.sh

set -euo pipefail

GPG_HOMEDIR="/etc/wazuh-archiver/signing/gnupg"
CONF="/etc/wazuh-archiver/archiver.conf"

# ---------------------------------------------------------------------------
# Generate key
# ---------------------------------------------------------------------------
cat > /tmp/wazuh-signing-keygen.conf << 'EOF'
%no-protection
Key-Type: EdDSA
Key-Curve: Ed25519
Key-Usage: sign
Name-Real: Wazuh Archiver Signing
Name-Email: wazuh-archiver-signing@wazuh-node1
Expire-Date: 0
%commit
EOF

gpg --homedir "${GPG_HOMEDIR}" --batch --gen-key /tmp/wazuh-signing-keygen.conf
rm -f /tmp/wazuh-signing-keygen.conf
chown -R wazuh-archiver:wazuh-archiver "${GPG_HOMEDIR}"

# ---------------------------------------------------------------------------
# Get fingerprint
# ---------------------------------------------------------------------------
FINGERPRINT=$(gpg --homedir "${GPG_HOMEDIR}" \
    --list-secret-keys --with-colons 2>/dev/null \
    | awk -F: '/^sec/{print $5}' | tail -1)

echo ""
echo "Signing key created: ${FINGERPRINT}"

# ---------------------------------------------------------------------------
# Update archiver.conf
# ---------------------------------------------------------------------------
if [ -f "${CONF}" ]; then
    sed -i "s/^signing_key_id =.*/signing_key_id = ${FINGERPRINT}/" "${CONF}"
    sed -i "s/^signing = .*/signing = true/" "${CONF}"
    echo "archiver.conf updated: signing = true, signing_key_id = ${FINGERPRINT}"
fi

# ---------------------------------------------------------------------------
# Export public key
# ---------------------------------------------------------------------------
PUB_KEY="/etc/wazuh-archiver/signing/MOVE_TO_SAFE/pubkey.asc"
gpg --homedir "${GPG_HOMEDIR}" --export --armor "${FINGERPRINT}" > "${PUB_KEY}"
chmod 644 "${PUB_KEY}"
echo "Public key exported: ${PUB_KEY}"
echo "  → Share this with the compliance team for signature verification"

echo ""
echo ""
echo "  Move the public key to the compliance team:"
echo "    ${PUB_KEY}"
