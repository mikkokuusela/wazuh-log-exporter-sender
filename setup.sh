#!/usr/bin/env bash
# setup.sh — Install wazuh-archiver on the Wazuh host
#
# Supports: Debian/Ubuntu, Rocky Linux 8/9, RHEL 8/9, AlmaLinux 8/9
# Run as root: sudo bash setup.sh
#
# Steps performed:
#   1.  Detect OS family
#   2.  Find Python 3.8+
#   3.  Check runtime dependencies
#   4.  Create system user
#   5.  Install script and wrapper binary
#   6.  Create directories with correct permissions
#   7.  Install configuration template
#   8.  Grant read access to Docker log volume (POSIX ACL)
#   9.  Configure SELinux (RHEL/Rocky only)
#   10. Install systemd units
#
# After running setup.sh you still need to:
#   a) Edit /etc/wazuh-archiver/archiver.conf
#   b) Set up the SSH key pair for SFTP (instructions printed at the end)
#   c) Optionally generate a GPG signing/encryption key (see below)
#   d) Add ossec-conf-snippet.xml settings to ossec.conf
#   e) systemctl enable --now wazuh-archiver.timer

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_USER="wazuh-archiver"
DOCKER_LOG_VOL="/var/lib/docker/volumes/single-node_wazuh_logs/_data"
INSTALL_DIR="/usr/local/lib/wazuh-archiver"
BIN_LINK="/usr/local/bin/wazuh-archiver"
CONFIG_DIR="/etc/wazuh-archiver"
STATE_DIR="/var/lib/wazuh-archiver"
LOG_DIR="/var/log/wazuh-archiver"
TEMP_DIR="/tmp/wazuh-archiver"

# ---------------------------------------------------------------------------
echo "==> Detecting OS"
# ---------------------------------------------------------------------------
OS_FAMILY="unknown"
OS_NAME="unknown"
if [ -f /etc/os-release ]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    OS_NAME="${PRETTY_NAME:-unknown}"
    case "${ID:-}" in
        ubuntu|debian|linuxmint|pop)
            OS_FAMILY="debian" ;;
        rhel|centos|rocky|almalinux|fedora)
            OS_FAMILY="rhel" ;;
    esac
fi
echo "    ${OS_NAME} (family: ${OS_FAMILY})"

# Package names differ between OS families
case "${OS_FAMILY}" in
    debian)
        PKG_MANAGER="apt-get install -y"
        PKG_PYTHON="python3"
        PKG_SFTP="openssh-client"
        PKG_GPG="gnupg"
        PKG_ACL="acl"
        PKG_SELINUX=""          # not applicable
        ;;
    rhel)
        PKG_MANAGER="dnf install -y"
        PKG_PYTHON="python39"   # Rocky 8 default python3 is 3.6; require 3.9 explicitly
        PKG_SFTP="openssh-clients"
        PKG_GPG="gnupg2"
        PKG_ACL="acl"
        PKG_SELINUX="policycoreutils-python-utils"  # provides semanage + audit2allow
        ;;
    *)
        PKG_MANAGER=""
        PKG_PYTHON="python3"
        PKG_SFTP="openssh-client"
        PKG_GPG="gnupg"
        PKG_ACL="acl"
        PKG_SELINUX=""
        ;;
esac

# ---------------------------------------------------------------------------
echo "==> Finding Python 3.8+"
# ---------------------------------------------------------------------------
# Rocky 8 ships Python 3.6 as 'python3'; we need 3.8 minimum.
# Try specific version binaries first, fall back to generic python3.
PYTHON_BIN=""
for candidate in python3.12 python3.11 python3.10 python3.9 python3.8 python3; do
    if command -v "${candidate}" &>/dev/null; then
        if "${candidate}" -c \
            'import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)' 2>/dev/null; then
            PYTHON_BIN="$(command -v "${candidate}")"
            break
        fi
    fi
done

if [ -z "${PYTHON_BIN}" ]; then
    echo "    ERROR: Python 3.8+ not found."
    echo ""
    case "${OS_FAMILY}" in
        rhel)
            echo "    Install with:"
            echo "      dnf install -y ${PKG_PYTHON}"
            echo "    Then re-run setup.sh"
            ;;
        debian)
            echo "    Install with:"
            echo "      apt-get install -y ${PKG_PYTHON}"
            echo "    Then re-run setup.sh"
            ;;
        *)
            echo "    Install Python 3.8 or newer and re-run setup.sh"
            ;;
    esac
    exit 1
fi

PYTHON_VER="$(${PYTHON_BIN} -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')"
echo "    Using: ${PYTHON_BIN} (${PYTHON_VER})"

# ---------------------------------------------------------------------------
echo "==> Checking runtime dependencies"
# ---------------------------------------------------------------------------
MISSING_HARD=0
MISSING_SOFT=0

check_bin() {
    local bin="$1"
    local pkg="$2"
    local required="$3"   # "required" or "optional"
    if command -v "${bin}" &>/dev/null; then
        echo "    ${bin}: OK ($(command -v "${bin}"))"
    else
        if [ "${required}" = "required" ]; then
            echo "    ${bin}: MISSING — install package: ${pkg}"
            MISSING_HARD=$((MISSING_HARD + 1))
        else
            echo "    ${bin}: not found (optional — needed only if signing/encryption enabled)"
            echo "            install with: ${PKG_MANAGER} ${pkg}"
            MISSING_SOFT=$((MISSING_SOFT + 1))
        fi
    fi
}

check_bin sftp  "${PKG_SFTP}"  required
check_bin gpg   "${PKG_GPG}"   optional
check_bin setfacl "${PKG_ACL}" required

if [ "${MISSING_HARD}" -gt 0 ]; then
    echo ""
    echo "    ERROR: ${MISSING_HARD} required dependency/dependencies missing. Aborting."
    exit 1
fi

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
echo "==> Installing script"
# ---------------------------------------------------------------------------
install -d "${INSTALL_DIR}"
install -m 755 "${SCRIPT_DIR}/archiver.py" "${INSTALL_DIR}/archiver.py"

# Wrapper uses the Python binary found above (important on Rocky 8 where
# 'python3' might be 3.6 but we need the 3.9 binary we detected earlier).
cat > "${BIN_LINK}" << EOF
#!/usr/bin/env bash
exec ${PYTHON_BIN} /usr/local/lib/wazuh-archiver/archiver.py "\$@"
EOF
chmod 755 "${BIN_LINK}"
echo "    Installed: ${BIN_LINK} (interpreter: ${PYTHON_BIN})"

# ---------------------------------------------------------------------------
echo "==> Creating directories"
# ---------------------------------------------------------------------------
install -d -m 750 -o root              -g "${SERVICE_USER}" "${CONFIG_DIR}"
# signing key directories
install -d -m 750 -o root              -g "${SERVICE_USER}" "${CONFIG_DIR}/signing"
install -d -m 700 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${CONFIG_DIR}/signing/gnupg"
install -d -m 750 -o root              -g "${SERVICE_USER}" "${CONFIG_DIR}/signing/MOVE_TO_SAFE"
# encryption key directories
install -d -m 750 -o root              -g "${SERVICE_USER}" "${CONFIG_DIR}/encryption"
install -d -m 700 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${CONFIG_DIR}/encryption/gnupg"
install -d -m 750 -o root              -g "${SERVICE_USER}" "${CONFIG_DIR}/encryption/MOVE_TO_SAFE"
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
    echo "    Written: ${CONFIG_DIR}/archiver.conf — EDIT BEFORE ENABLING"
else
    echo "    Exists (not overwritten): ${CONFIG_DIR}/archiver.conf"
fi

# ---------------------------------------------------------------------------
echo "==> Granting read access to Docker log volume (POSIX ACL)"
# ---------------------------------------------------------------------------
# setfacl gives wazuh-archiver read-only access without changing ownership.
# The -d (default) flag makes the ACL inherit to new files created inside
# the directory — important because Wazuh creates new .json.gz files every hour.
if [ -d "${DOCKER_LOG_VOL}" ]; then
    # Grant traversal (execute) on every parent directory up to the volume.
    # /var/lib/docker/volumes is typically mode 700 — without x permission
    # here the service user cannot reach _data even if _data itself is ACL'd.
    for parent_dir in \
        /var/lib/docker \
        /var/lib/docker/volumes \
        "$(dirname "${DOCKER_LOG_VOL}")"; do
        if [ -d "${parent_dir}" ]; then
            setfacl -m "u:${SERVICE_USER}:x" "${parent_dir}"
            echo "    ACL set: ${SERVICE_USER} → x  on ${parent_dir}"
        fi
    done

    # Grant read + execute on the data directory itself (recursive).
    # The -d (default) flag propagates the ACL to files created in future
    # by Wazuh log rotation.
    setfacl -R -m  "u:${SERVICE_USER}:rX" "${DOCKER_LOG_VOL}"
    setfacl -R -d -m "u:${SERVICE_USER}:rX" "${DOCKER_LOG_VOL}"
    echo "    ACL set: ${SERVICE_USER} → rX on ${DOCKER_LOG_VOL}"
else
    echo "    WARNING: ${DOCKER_LOG_VOL} not found — is Wazuh running?"
    echo "    Run these commands once Wazuh has started:"
    echo "      setfacl -m u:${SERVICE_USER}:x /var/lib/docker"
    echo "      setfacl -m u:${SERVICE_USER}:x /var/lib/docker/volumes"
    echo "      setfacl -m u:${SERVICE_USER}:x $(dirname "${DOCKER_LOG_VOL}")"
    echo "      setfacl -R -m  u:${SERVICE_USER}:rX ${DOCKER_LOG_VOL}"
    echo "      setfacl -R -d -m u:${SERVICE_USER}:rX ${DOCKER_LOG_VOL}"
fi

# ---------------------------------------------------------------------------
# SELinux configuration (RHEL / Rocky Linux only)
# ---------------------------------------------------------------------------
# On Rocky 8 SELinux is Enforcing by default. Files written by the Wazuh
# Docker container carry the label 'svirt_sandbox_file_t'. A systemd service
# running as a regular user cannot read that label without an explicit policy.
#
# Strategy:
#   1. Use 'semanage fcontext' to declare the Docker volume as 'var_log_t'
#      (standard host log type that system services are allowed to read).
#      'restorecon' applies the label to existing files immediately.
#   2. Default ACLs (set above) make new files inherit the POSIX permissions.
#   3. New files created by the container will initially have the container
#      label, but systemd-tmpfiles / restorecon picks up the fcontext policy
#      on the next run.  If denials still appear, the audit2allow helper
#      below generates a minimal policy module for the remaining denials.
# ---------------------------------------------------------------------------
configure_selinux() {
    echo "==> Configuring SELinux"

    local se_state
    se_state="$(getenforce)"
    echo "    SELinux status: ${se_state}"

    if [ "${se_state}" = "Disabled" ]; then
        echo "    SELinux is disabled — nothing to do"
        return
    fi

    # Ensure semanage and audit2allow are available
    if ! command -v semanage &>/dev/null; then
        echo "    Installing ${PKG_SELINUX}..."
        dnf install -y -q "${PKG_SELINUX}"
    fi
    echo "    semanage: OK ($(command -v semanage))"

    # Set the persistent file context for the Docker log volume.
    # 'semanage fcontext -a' adds a new rule; -m modifies an existing one.
    # We try -a first and fall back to -m if the rule already exists.
    local fcontext_pattern="${DOCKER_LOG_VOL}(/.*)?"
    if semanage fcontext -a -t var_log_t "${fcontext_pattern}" 2>/dev/null; then
        echo "    fcontext rule added: ${fcontext_pattern} → var_log_t"
    else
        semanage fcontext -m -t var_log_t "${fcontext_pattern}"
        echo "    fcontext rule updated: ${fcontext_pattern} → var_log_t"
    fi

    # Apply the label to files that already exist in the volume
    if [ -d "${DOCKER_LOG_VOL}" ]; then
        restorecon -Rv "${DOCKER_LOG_VOL}" | grep -c 'Relabeled' \
            | xargs -I{} echo "    restorecon: {} file(s) relabeled"
    else
        echo "    Volume not yet present — run 'restorecon -Rv ${DOCKER_LOG_VOL}'"
        echo "    after Wazuh starts for the first time."
    fi

    echo ""
    echo "    NOTE: Files the Wazuh container creates AFTER setup will initially"
    echo "    carry the container label (svirt_sandbox_file_t). If the archiver"
    echo "    fails to read new log files, run the audit2allow helper:"
    echo ""
    echo "      # 1. Attempt a dry-run so denials are logged:"
    echo "      sudo -u ${SERVICE_USER} ${BIN_LINK} --dry-run --config ${CONFIG_DIR}/archiver.conf"
    echo ""
    echo "      # 2. Generate and install a minimal SELinux policy module:"
    echo "      ausearch -m avc -c python3 --raw | audit2allow -M wazuh-archiver"
    echo "      semodule -i wazuh-archiver.pp"
    echo ""
    echo "      # 3. Verify:"
    echo "      semodule -l | grep wazuh"
}

if [ "${OS_FAMILY}" = "rhel" ]; then
    configure_selinux
fi

# ---------------------------------------------------------------------------
echo "==> Generating GPG keys"
# ---------------------------------------------------------------------------
if command -v gpg &>/dev/null; then
    # Signing key — skip if a signing key already exists
    if gpg --homedir "${CONFIG_DIR}/signing/gnupg" --list-secret-keys 2>/dev/null \
            | grep -q "^sec"; then
        echo "    Signing key already exists — skipping"
    else
        echo "    Generating signing key..."
        bash "${SCRIPT_DIR}/create-signing-key.sh"
    fi

    # Encryption key — skip if an encryption key already exists
    if gpg --homedir "${CONFIG_DIR}/encryption/gnupg" --list-keys 2>/dev/null \
            | grep -q "wazuh-archiver-enc"; then
        echo "    Encryption key already exists — skipping"
    else
        echo "    Generating encryption key pair..."
        bash "${SCRIPT_DIR}/create-encryption-key.sh"
    fi
else
    echo "    WARNING: gpg not found — skipping key generation"
    echo "             Install gpg and run manually:"
    echo "               bash ${SCRIPT_DIR}/create-signing-key.sh"
    echo "               bash ${SCRIPT_DIR}/create-encryption-key.sh"
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
echo "     cat ${CONFIG_DIR}/sftp_key.pub   # copy this to the SFTP server"
echo ""
echo "3) Record the SFTP server's host key:"
echo "     ssh-keyscan -H sftp.example.com >> ${CONFIG_DIR}/known_hosts"
echo "     chown root:${SERVICE_USER} ${CONFIG_DIR}/known_hosts"
echo "     chmod 640 ${CONFIG_DIR}/known_hosts"
echo ""
echo "4) GPG keys were generated automatically during setup."
echo "   Key directories:"
echo "     ${CONFIG_DIR}/signing/gnupg/           — signing key (stays on this machine)"
echo "     ${CONFIG_DIR}/signing/MOVE_TO_SAFE/    — signing public key → share with compliance team"
echo "     ${CONFIG_DIR}/encryption/gnupg/        — encryption key (stays on this machine)"
echo "     ${CONFIG_DIR}/encryption/MOVE_TO_SAFE/ — encryption private key → move to secure offline storage"
echo "   To regenerate keys manually:"
echo "     bash ${SCRIPT_DIR}/create-signing-key.sh"
echo "     bash ${SCRIPT_DIR}/create-encryption-key.sh"
echo ""
echo "5) Apply Wazuh ossec.conf changes (see ossec-conf-snippet.xml):"
echo "     docker exec -it single-node-wazuh.manager-1 vi /var/ossec/etc/ossec.conf"
echo "     # Add: <logall_json>yes</logall_json>"
echo "     #      <rotate_interval>1h</rotate_interval>"
echo "     docker compose restart wazuh.manager"
echo ""
echo "6) Test with dry-run:"
echo "     sudo -u ${SERVICE_USER} ${BIN_LINK} --dry-run --config ${CONFIG_DIR}/archiver.conf"
echo ""
echo "7) Enable the timer:"
echo "     systemctl enable --now wazuh-archiver.timer"
echo "     systemctl list-timers wazuh-archiver.timer"
echo ""
