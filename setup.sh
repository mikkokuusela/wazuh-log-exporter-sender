#!/usr/bin/env bash
# setup.sh — Install wazuh-archiver on the Wazuh host
#
# Run as root: sudo bash setup.sh
#
# What this does:
#   1. Creates a dedicated system user (wazuh-archiver)
#   2. Installs the Python script and dependencies
#   3. Creates required directories with correct permissions
#   4. Copies example config (edit before enabling the service)
#   5. Installs and enables the systemd service + timer
#
# After running setup.sh, you still need to:
#   a) Edit /etc/wazuh-archiver/archiver.conf
#   b) Set up the SSH key pair for SFTP (see below)
#   c) Optionally generate a GPG signing/encryption key (see below)
#   d) Add ossec-conf-snippet.xml settings to ossec.conf
#   e) systemctl start wazuh-archiver.timer

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_USER="wazuh-archiver"
INSTALL_DIR="/usr/local/lib/wazuh-archiver"
BIN_LINK="/usr/local/bin/wazuh-archiver"
CONFIG_DIR="/etc/wazuh-archiver"
STATE_DIR="/var/lib/wazuh-archiver"
LOG_DIR="/var/log/wazuh-archiver"
TEMP_DIR="/tmp/wazuh-archiver"

# ---------------------------------------------------------------------------
echo "==> Creating system user: ${SERVICE_USER}"
# ---------------------------------------------------------------------------
if ! id "${SERVICE_USER}" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
    echo "    Created user ${SERVICE_USER}"
else
    echo "    User ${SERVICE_USER} already exists"
fi

# ---------------------------------------------------------------------------
echo "==> Checking runtime dependencies"
# ---------------------------------------------------------------------------
for bin in python3 sftp gpg; do
    if command -v "$bin" &>/dev/null; then
        echo "    $bin: OK ($(command -v "$bin"))"
    else
        case "$bin" in
            python3) echo "    ERROR: python3 not found — install python3" ;;
            sftp)    echo "    ERROR: sftp not found — install openssh-client" ;;
            gpg)     echo "    WARNING: gpg not found — required only if signing/encryption is enabled" ;;
        esac
    fi
done

# ---------------------------------------------------------------------------
echo "==> Installing script"
# ---------------------------------------------------------------------------
install -d "${INSTALL_DIR}"
install -m 755 "${SCRIPT_DIR}/archiver.py" "${INSTALL_DIR}/archiver.py"

# Create a simple wrapper so the script is callable as 'wazuh-archiver'
cat > "${BIN_LINK}" << 'EOF'
#!/usr/bin/env bash
exec python3 /usr/local/lib/wazuh-archiver/archiver.py "$@"
EOF
chmod 755 "${BIN_LINK}"
echo "    Script installed: ${BIN_LINK}"

# ---------------------------------------------------------------------------
echo "==> Creating directories"
# ---------------------------------------------------------------------------
install -d -m 750 -o root          -g "${SERVICE_USER}" "${CONFIG_DIR}"
install -d -m 700 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${CONFIG_DIR}/gnupg"
install -d -m 750 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${STATE_DIR}"
install -d -m 750 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${LOG_DIR}"
install -d -m 750 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${TEMP_DIR}"
echo "    Directories created"

# ---------------------------------------------------------------------------
echo "==> Installing configuration template"
# ---------------------------------------------------------------------------
if [ ! -f "${CONFIG_DIR}/archiver.conf" ]; then
    install -m 640 -o root -g "${SERVICE_USER}" \
        "${SCRIPT_DIR}/archiver.conf.example" "${CONFIG_DIR}/archiver.conf"
    echo "    Config written to ${CONFIG_DIR}/archiver.conf — EDIT BEFORE ENABLING"
else
    echo "    Config already exists, not overwriting: ${CONFIG_DIR}/archiver.conf"
fi

# ---------------------------------------------------------------------------
echo "==> Installing systemd units"
# ---------------------------------------------------------------------------
install -m 644 "${SCRIPT_DIR}/systemd/wazuh-archiver.service" \
    /etc/systemd/system/wazuh-archiver.service
install -m 644 "${SCRIPT_DIR}/systemd/wazuh-archiver.timer" \
    /etc/systemd/system/wazuh-archiver.timer
systemctl daemon-reload
echo "    Systemd units installed (NOT yet enabled)"

# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "  Installation complete — next steps:"
echo "============================================================"
echo ""
echo "1) Edit the config file:"
echo "     nano ${CONFIG_DIR}/archiver.conf"
echo ""
echo "2) Generate an SSH key pair for SFTP authentication:"
echo "     ssh-keygen -t ed25519 -f ${CONFIG_DIR}/sftp_key -N \"\""
echo "     chown root:${SERVICE_USER} ${CONFIG_DIR}/sftp_key"
echo "     chmod 440 ${CONFIG_DIR}/sftp_key"
echo "     # Copy the public key to the SFTP server:"
echo "     cat ${CONFIG_DIR}/sftp_key.pub"
echo ""
echo "3) Record the SFTP server's host key (strict verification):"
echo "     ssh-keyscan -H sftp.example.com >> ${CONFIG_DIR}/known_hosts"
echo "     chown root:${SERVICE_USER} ${CONFIG_DIR}/known_hosts"
echo "     chmod 640 ${CONFIG_DIR}/known_hosts"
echo ""
echo "4) (Optional) Generate a GPG signing key:"
echo "     cat > ${CONFIG_DIR}/gpg-keygen.conf << 'GPGEOF'"
echo "     %no-protection"
echo "     Key-Type: EdDSA"
echo "     Key-Curve: Ed25519"
echo "     Key-Usage: sign"
echo "     Name-Real: Wazuh Archiver Node1"
echo "     Name-Email: wazuh-archiver@your-org.fi"
echo "     Expire-Date: 2y"
echo "     %commit"
echo "     GPGEOF"
echo "     gpg --homedir ${CONFIG_DIR}/gnupg --batch --gen-key ${CONFIG_DIR}/gpg-keygen.conf"
echo "     # Back up the private key to a physical safe/HSM!"
echo "     gpg --homedir ${CONFIG_DIR}/gnupg --export-secret-keys --armor > /path/to/safe/signing-key.asc"
echo "     chown -R ${SERVICE_USER}:${SERVICE_USER} ${CONFIG_DIR}/gnupg"
echo ""
echo "5) Apply ossec.conf changes (see ossec-conf-snippet.xml):"
echo "     Edit /var/ossec/etc/ossec.conf inside the Wazuh container"
echo "     Add: <logall_json>yes</logall_json>"
echo "          <rotate_interval>1h</rotate_interval>"
echo "     Restart wazuh-manager"
echo ""
echo "6) Test with dry-run:"
echo "     sudo -u ${SERVICE_USER} ${BIN_LINK} --dry-run"
echo ""
echo "7) Enable the timer:"
echo "     systemctl enable --now wazuh-archiver.timer"
echo "     systemctl list-timers wazuh-archiver.timer"
echo ""
