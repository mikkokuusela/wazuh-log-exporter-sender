#!/usr/bin/env bash
# create-encryption-key.sh — Generate a GPG encryption key pair for wazuh-archiver
#
# The PUBLIC key stays on this machine (used to encrypt each archive).
# The PRIVATE key must be exported and stored securely — it is the only
# way to decrypt the archived files.
#
# Run as root: sudo bash create-encryption-key.sh

set -euo pipefail

GPG_HOMEDIR="/etc/wazuh-archiver/encryption/gnupg"
CONF="/etc/wazuh-archiver/archiver.conf"

# ---------------------------------------------------------------------------
# Generate key pair (Ed25519 primary + Curve25519 encryption subkey)
# ---------------------------------------------------------------------------
cat > /tmp/wazuh-enc-keygen.conf << 'EOF'
%no-protection
Key-Type: EdDSA
Key-Curve: Ed25519
Key-Usage: cert
Subkey-Type: ECDH
Subkey-Curve: Curve25519
Subkey-Usage: encrypt
Name-Real: Wazuh Archiver Encryption
Name-Email: wazuh-archiver-enc@wazuh-node1
Expire-Date: 2y
%commit
EOF

gpg --homedir "${GPG_HOMEDIR}" --batch --gen-key /tmp/wazuh-enc-keygen.conf
rm -f /tmp/wazuh-enc-keygen.conf
chown -R wazuh-archiver:wazuh-archiver "${GPG_HOMEDIR}"

# ---------------------------------------------------------------------------
# Get fingerprint
# ---------------------------------------------------------------------------
FINGERPRINT=$(gpg --homedir "${GPG_HOMEDIR}" \
    --list-keys --with-colons "wazuh-archiver-enc@wazuh-node1" 2>/dev/null \
    | awk -F: '/^pub/{print $5}' | tail -1)

echo ""
echo "Encryption key pair created: ${FINGERPRINT}"

# ---------------------------------------------------------------------------
# Update archiver.conf
# ---------------------------------------------------------------------------
if [ -f "${CONF}" ]; then
    sed -i "s/^encryption_recipient =.*/encryption_recipient = ${FINGERPRINT}/" "${CONF}"
    sed -i "s/^encryption = .*/encryption = true/" "${CONF}"
    echo "archiver.conf updated: encryption = true, encryption_recipient = ${FINGERPRINT}"
fi

# ---------------------------------------------------------------------------
# Export public key (stays on this machine — used for encryption)
# ---------------------------------------------------------------------------
PUB_KEY="/etc/wazuh-archiver/encryption/pubkey.asc"
gpg --homedir "${GPG_HOMEDIR}" --export --armor "${FINGERPRINT}" > "${PUB_KEY}"
chmod 644 "${PUB_KEY}"
echo "Public key exported: ${PUB_KEY}"

# ---------------------------------------------------------------------------
# Export private key (must be moved to secure storage — required for decryption)
# ---------------------------------------------------------------------------
PRIV_KEY="/etc/wazuh-archiver/encryption/MOVE_TO_SAFE/private-key.asc"
gpg --homedir "${GPG_HOMEDIR}" --export-secret-keys --armor "${FINGERPRINT}" > "${PRIV_KEY}"
chmod 400 "${PRIV_KEY}"
echo "Private key exported: ${PRIV_KEY}"

echo ""
echo "=========================================================="
echo "  IMPORTANT — move the private key to secure storage NOW"
echo "=========================================================="
echo ""
echo "  The private key is the ONLY way to decrypt archived files."
echo "  Store it in a physically secured location (safe, HSM, or"
echo "  offline escrow) and delete it from this machine:"
echo ""
echo "    # Copy to secure location, then:"
echo "    shred -u ${PRIV_KEY}"
echo ""
echo "  To decrypt an archive on the receiving end:"
echo "    gpg --import private-key.asc"
echo "    gpg --decrypt ossec-archive-20-14.json.gz.gpg > ossec-archive-20-14.json.gz"
