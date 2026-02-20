# wazuh-log-exporter-sender

Compliance log archival tool for Wazuh single-node deployments.

Collects Wazuh's hourly-rotated log files, optionally signs and/or encrypts
them with GPG, and transfers them to an SFTP server with a full audit trail.
Designed to satisfy common security compliance requirements around log
integrity, non-repudiation, and confidentiality (ISO 27001, NIS2, NIST
SP 800-92, and similar frameworks).

**Zero external Python dependencies** — runs on stdlib + OpenSSH + GPG.
Suitable for air-gapped environments where pip is unavailable.

Supported platforms: Debian/Ubuntu, Rocky Linux 8/9, RHEL 8/9, AlmaLinux 8/9.

---

## Table of contents

- [Architecture](#architecture)
- [Repository layout](#repository-layout)
- [Requirements](#requirements)
- [Installation](#installation)
- [Wazuh configuration](#wazuh-configuration)
- [Configuration file](#configuration-file)
- [GPG key management](#gpg-key-management)
- [SFTP connection](#sftp-connection)
- [Systemd scheduling](#systemd-scheduling)
- [Testing](#testing)
- [Files written to the SFTP store](#files-written-to-the-sftp-store)
- [Compliance coverage](#compliance-coverage)
- [Troubleshooting](#troubleshooting)

---

## Architecture

```
Wazuh (Docker, single-node)
│
│  /var/lib/docker/volumes/single-node_wazuh_logs/_data/
│    archives/YYYY/Mon/ossec-archive-DD-HH.json.gz
│    alerts/YYYY/Mon/ossec-alerts-DD-HH.json.gz
│
│  [systemd timer — every hour at :05]
│
│  archiver.py
│    1. Find unprocessed .json.gz files
│    2. Calculate SHA-256
│    3. GPG detached signature (.sig)   ← optional
│    4. GPG encryption (.gpg)           ← optional
│    5. SFTP transfer (sftp -b batch)
│    6. Update state.json
│    7. Write audit record
│
SFTP server
  /archive/wazuh/
    ossec-archive-20-14.json.gz
    ossec-archive-20-14.json.gz.sha256
    ossec-archive-20-14.json.gz.sig    ← if signing = true
    ossec-archive-20-14.json.gz.gpg    ← if encryption = true
```

---

## Repository layout

```
wazuh-log-exporter-sender/
├── archiver.py                  # Main script
├── archiver.conf.example        # Configuration template
├── requirements.txt             # No external deps (documentation only)
├── ossec-conf-snippet.xml       # Required ossec.conf additions
├── setup.sh                     # Installation script
└── systemd/
    ├── wazuh-archiver.service   # Systemd service unit
    └── wazuh-archiver.timer     # Systemd timer (hourly)
```

---

## Requirements

| Component | Version | Debian/Ubuntu package | Rocky/RHEL package |
|-----------|---------|----------------------|-------------------|
| Python 3 | 3.8+ | `python3` | `python39` |
| OpenSSH client | any | `openssh-client` | `openssh-clients` |
| GnuPG | 2.x | `gnupg` | `gnupg2` |

GPG is only required when `signing = true` or `encryption = true`.

```bash
python3 --version
sftp -V
gpg --version
```

---

## Installation

### 1. Clone the repository

```bash
git clone git@github.com:mikkokuusela/wazuh-log-exporter-sender.git
cd wazuh-log-exporter-sender
```

### 2. Run the install script as root

```bash
sudo bash setup.sh
```

The script will:
- Detect your OS family (Debian/Ubuntu or Rocky/RHEL)
- Find a Python 3.8+ binary and hard-code it into the wrapper
- Check runtime dependencies with OS-correct package names
- Create system user `wazuh-archiver`
- Install the script to `/usr/local/bin/wazuh-archiver`
- Create all required directories with correct permissions
- Grant read access to the Wazuh Docker volume via POSIX ACL
- Configure SELinux (Rocky/RHEL only — see [SELinux](#selinux-rockyrhel))
- Install the systemd service and timer units

### 3. Edit the configuration

```bash
sudo nano /etc/wazuh-archiver/archiver.conf
```

Required fields:
- `[wazuh] log_dirs` — host-side path(s) to the Wazuh log directories
- `[sftp] host`, `username`, `ssh_key_path`, `remote_dir`

### 4. Configure the SFTP connection

```bash
# Generate a dedicated SSH key pair
sudo ssh-keygen -t ed25519 -f /etc/wazuh-archiver/sftp_key -N ""
sudo chown root:wazuh-archiver /etc/wazuh-archiver/sftp_key
sudo chmod 440 /etc/wazuh-archiver/sftp_key

# Copy the public key to the SFTP server's authorized_keys
cat /etc/wazuh-archiver/sftp_key.pub

# Record the SFTP server's host key for strict verification
sudo ssh-keyscan -H sftp.example.com | sudo tee /etc/wazuh-archiver/known_hosts
sudo chown root:wazuh-archiver /etc/wazuh-archiver/known_hosts
sudo chmod 640 /etc/wazuh-archiver/known_hosts
```

### 5. Configure Wazuh

See [Wazuh configuration](#wazuh-configuration).

### 6. Test with dry-run

```bash
sudo -u wazuh-archiver wazuh-archiver --dry-run --config /etc/wazuh-archiver/archiver.conf
```

### 7. Enable the timer

```bash
sudo systemctl enable --now wazuh-archiver.timer
sudo systemctl list-timers wazuh-archiver.timer
```

---

## Wazuh configuration

Add the following to `ossec.conf` (full snippet also in `ossec-conf-snippet.xml`):

```xml
<global>
  <!-- Write all events in JSON format to archives.json -->
  <logall_json>yes</logall_json>

  <!-- Rotate logs every hour (default is once per day) -->
  <rotate_interval>1h</rotate_interval>
</global>
```

**Docker deployment:**

```bash
# Edit ossec.conf inside the running container
docker exec -it single-node-wazuh.manager-1 \
  sh -c "vi /var/ossec/etc/ossec.conf"

# Restart the manager
docker compose restart wazuh.manager
```

**Optional — bind mount instead of named volume:**

Replacing the named Docker volume with a bind mount gives a predictable
host-side path and simplifies the ACL setup:

```yaml
services:
  wazuh.manager:
    volumes:
      - /opt/wazuh/logs:/var/ossec/logs
      - /opt/wazuh/etc:/var/ossec/etc
```

Logs are then accessible on the host at `/opt/wazuh/logs/archives/`.

---

## Configuration file

Full annotated template: `archiver.conf.example`

```ini
[wazuh]
log_dirs  = /var/lib/docker/volumes/single-node_wazuh_logs/_data/archives,
            /var/lib/docker/volumes/single-node_wazuh_logs/_data/alerts
node_name = wazuh-node1

[sftp]
host             = sftp.example.com
port             = 22
username         = wazuh-archiver
ssh_key_path     = /etc/wazuh-archiver/sftp_key
remote_dir       = /archive/wazuh
known_hosts_file = /etc/wazuh-archiver/known_hosts

[gpg]
signing              = false
signing_key_id       =
encryption           = false
encryption_recipient =
gpg_binary           = /usr/bin/gpg
gpg_homedir          = /etc/wazuh-archiver/gnupg

[archiver]
state_file = /var/lib/wazuh-archiver/state.json
audit_log  = /var/log/wazuh-archiver/audit.log
temp_dir   = /tmp/wazuh-archiver
```

---

## GPG key management

### Signing key

```bash
# Create a batch key-generation config
cat > /etc/wazuh-archiver/gpg-keygen.conf << 'EOF'
%no-protection
Key-Type: EdDSA
Key-Curve: Ed25519
Key-Usage: sign
Name-Real: Wazuh Archiver Node1
Name-Email: wazuh-archiver@your-org.example
Expire-Date: 2y
%commit
EOF

# Generate the key
gpg --homedir /etc/wazuh-archiver/gnupg \
    --batch --gen-key /etc/wazuh-archiver/gpg-keygen.conf

# Verify
gpg --homedir /etc/wazuh-archiver/gnupg --list-secret-keys

# Set permissions
chown -R wazuh-archiver:wazuh-archiver /etc/wazuh-archiver/gnupg
chmod 700 /etc/wazuh-archiver/gnupg
```

**Important — key backup:** Export the private key to a physically secured
location (safe, HSM, or offline escrow) immediately after generation:

```bash
gpg --homedir /etc/wazuh-archiver/gnupg \
    --export-secret-keys --armor > /secure/location/wazuh-signing-key.asc
```

### Encryption key

```bash
# Import the recipient's public key
gpg --homedir /etc/wazuh-archiver/gnupg \
    --import recipient-pubkey.asc

# Set encryption_recipient in archiver.conf to the fingerprint or email
```

### Verifying archives (recipient side)

```bash
# Import the Wazuh node's public key
gpg --import wazuh-node1-pubkey.asc

# Verify the signature
gpg --verify ossec-archive-20-14.json.gz.sig ossec-archive-20-14.json.gz

# Verify the checksum
sha256sum -c ossec-archive-20-14.json.gz.sha256
```

---

## SFTP connection

The tool uses the system `sftp(1)` binary in batch mode — no external Python
libraries. This makes it work on any host with OpenSSH installed, including
servers in air-gapped networks.

**Host key verification behaviour:**

| Situation | Behaviour |
|-----------|-----------|
| `known_hosts_file` configured | `StrictHostKeyChecking=yes` — strict, recommended |
| No `known_hosts_file` | `StrictHostKeyChecking=accept-new` — records on first contact, rejects changes |

**Transfer integrity:** SSH provides HMAC-SHA2 transport-layer integrity.
The `.sha256` sidecar file provides content-level integrity that the
compliance team can verify independently at any time with `sha256sum -c`.

---

## Systemd scheduling

```
:00  Wazuh rotates logs → ossec-archive-DD-HH.json.gz
:05  wazuh-archiver.timer fires archiver.py
:05+ Files transferred to SFTP server
```

```bash
# Check timer and service status
systemctl status wazuh-archiver.timer
systemctl status wazuh-archiver.service

# Next scheduled run
systemctl list-timers wazuh-archiver.timer

# Live service output
journalctl -u wazuh-archiver.service -f

# Audit log
tail -f /var/log/wazuh-archiver/audit.log
```

**Manual trigger:**

```bash
sudo systemctl start wazuh-archiver.service
```

---

## Testing

```bash
# List discovered files without uploading or updating state
sudo -u wazuh-archiver wazuh-archiver \
    --dry-run --config /etc/wazuh-archiver/archiver.conf

# Normal run
sudo -u wazuh-archiver wazuh-archiver \
    --config /etc/wazuh-archiver/archiver.conf

# Test with an alternate config
sudo -u wazuh-archiver wazuh-archiver --config /tmp/test.conf --dry-run
```

---

## Files written to the SFTP store

Each hourly rotation produces the following files:

```
/archive/wazuh/
  ossec-archive-20-14.json.gz          always   — compressed log data
  ossec-archive-20-14.json.gz.sha256   always   — SHA-256 integrity manifest
  ossec-archive-20-14.json.gz.sig      optional — GPG detached signature
  ossec-archive-20-14.json.gz.gpg      optional — GPG-encrypted copy
```

The `.sha256` format is compatible with `sha256sum -c`:

```
a3f2c1...  ossec-archive-20-14.json.gz
```

---

## Compliance coverage

| Requirement | Mechanism |
|-------------|-----------|
| **Integrity** | SHA-256 manifest for every transferred file |
| **Non-repudiation** | GPG detached signature — signer identity verifiable |
| **Confidentiality in transit** | SFTP over SSH (HMAC-SHA2 transport) |
| **Confidentiality at rest** | GPG encryption with recipient's public key (optional) |
| **Log immutability at source** | Wazuh writes and rotates; archiver accesses read-only |
| **Audit trail** | Structured JSON `AUDIT_RECORD` written per run |
| **Key management** | Signing key on host; private key backed up offline |

---

## Troubleshooting

### "No new files found"

- Is `logall_json=yes` set in `ossec.conf`?
- Is `rotate_interval=1h` set?
- Are the `log_dirs` paths correct for your deployment (host paths, not
  container-internal paths)?
- Check processed file list: `cat /var/lib/wazuh-archiver/state.json`

### "sftp failed"

- Test connectivity manually:
  `sftp -i /etc/wazuh-archiver/sftp_key -P 22 user@host`
- Is `known_hosts` populated?
  `ssh-keyscan -H sftp.example.com >> /etc/wazuh-archiver/known_hosts`
- Check key permissions: `stat /etc/wazuh-archiver/sftp_key`
  (must be 440 or 400)

### "GPG command failed"

- List keys: `gpg --homedir /etc/wazuh-archiver/gnupg --list-keys`
- Check gnupg directory ownership:
  `stat /etc/wazuh-archiver/gnupg` (must be owned by `wazuh-archiver`)

### SELinux (Rocky/RHEL)

If the service cannot read the Docker volume despite correct ACLs:

```bash
# Check for AVC denials
ausearch -m avc -c python3 -ts recent

# Generate and install a minimal policy module for any remaining denials
ausearch -m avc -c python3 --raw | audit2allow -M wazuh-archiver
semodule -i wazuh-archiver.pp

# Re-apply file context labels to the volume
restorecon -Rv /var/lib/docker/volumes/single-node_wazuh_logs/_data
```

### Reading the audit log

```bash
# Pretty-print all AUDIT_RECORD entries
grep AUDIT_RECORD /var/log/wazuh-archiver/audit.log \
  | sed 's/.*AUDIT_RECORD //' \
  | python3 -m json.tool
```
