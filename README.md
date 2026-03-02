# wazuh-archiver

Compliance log archival tool for Wazuh single-node deployments.

Collects Wazuh's rotated log files, optionally signs and/or encrypts
them with GPG, and transfers them to a remote store with a full audit trail.
Supports SFTP, WebDAV HTTPS, FTP, and FTPS — individually or in combination.
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
- [WebDAV connection (HTTPS)](#webdav-connection-https)
- [FTP connection](#ftp-connection)
- [FTPS connection (explicit TLS)](#ftps-connection-explicit-tls)
- [Systemd scheduling](#systemd-scheduling)
- [Testing](#testing)
- [Monitoring with Zabbix](#monitoring-with-zabbix)
- [Files written to the remote store](#files-written-to-the-remote-store)
- [Compliance coverage](#compliance-coverage)
- [Troubleshooting](#troubleshooting)

---

## Architecture

```
Wazuh (Docker, single-node)
│
│  /var/lib/docker/volumes/single-node_wazuh_logs/_data/
│    archives/YYYY/Mon/ossec-archive-DD.json.gz   (compressed rotated)
│    archives/YYYY/Mon/ossec-archive-DD.json      (uncompressed rotated)
│    alerts/YYYY/Mon/ossec-alerts-DD.json.gz
│    alerts/YYYY/Mon/ossec-alerts-DD.json
│    api/YYYY/Mon/*.log.gz
│    wazuh/YYYY/Mon/*.log.gz
│
│  [systemd timer — every 10 minutes at :30s]
│
│  archiver.py
│    1. Find unprocessed files (*.json.gz, *.json, *.log.gz)
│       — skip root-level active files (archives.json, alerts.log …)
│       — skip uncompressed files newer than min_age_minutes (65 min)
│    2. Calculate SHA-256
│    3. GPG detached signature (.sig)   ← optional
│    4. GPG encryption (.gpg)           ← optional
│    5. Transfer: SFTP / WebDAV HTTPS / FTP / FTPS (configurable)
│    6. Update state.json
│    7. Write audit record
│
SFTP / WebDAV / FTP / FTPS server
  /archive/wazuh/
    2026/Feb/
      ossec-archive-20.json.gz          ← omitted if upload_plaintext = false
      ossec-archive-20.json.gz.sha256
      ossec-archive-20.json.gz.sig    ← if signing = true
      ossec-archive-20.json.gz.gpg    ← if encryption = true
    2026/Mar/
      ossec-archive-20.json.gz
      ...
```

---

## Repository layout

```
wazuh-log-exporter-sender/
├── archiver.py                  # Main script
├── archiver.conf.example        # Configuration template
├── requirements.txt             # No external deps (documentation only)
├── ossec-conf-snippet.xml       # Required ossec.conf additions
├── setup.sh                     # Installation script (auto-generates GPG keys)
├── create-signing-key.sh        # GPG signing key generation
├── create-encryption-key.sh     # GPG encryption key pair generation
├── gpg-keygen.conf              # GPG batch key generation template
└── systemd/
    ├── wazuh-archiver.service   # Systemd service unit
    └── wazuh-archiver.timer     # Systemd timer (every 10 minutes)
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
- **Auto-generate GPG signing and encryption keys**
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
            /var/lib/docker/volumes/single-node_wazuh_logs/_data/alerts,
            /var/lib/docker/volumes/single-node_wazuh_logs/_data/api,
            /var/lib/docker/volumes/single-node_wazuh_logs/_data/wazuh
node_name = wazuh-node1

# File patterns to collect (matched recursively in each log_dir)
file_patterns = *.json.gz, *.json, *.log.gz

# Minimum age in minutes for uncompressed files before archiving.
# Prevents capturing files Wazuh is still actively writing to.
# Set slightly above rotate_interval (e.g. 65 for rotate_interval=1h).
min_age_minutes = 65

[sftp]
host             = sftp.example.com
port             = 22
username         = wazuh-archiver
ssh_key_path     = /etc/wazuh-archiver/sftp_key
remote_dir       = /archive/wazuh
known_hosts_file = /etc/wazuh-archiver/known_hosts

[gpg]
signing              = true
signing_key_id       =                                   # auto-populated by setup.sh
encryption           = true
encryption_recipient =                                   # auto-populated by setup.sh
upload_plaintext     = true                              # set false to send only .gpg
gpg_binary           = /usr/bin/gpg
signing_homedir      = /etc/wazuh-archiver/signing/gnupg
encryption_homedir   = /etc/wazuh-archiver/encryption/gnupg

[transfer]
mode = sftp          # sftp | webdav | ftp | ftps | comma-separated combination

[archiver]
state_file = /var/lib/wazuh-archiver/state.json
audit_log  = /var/log/wazuh-archiver/audit.log
temp_dir   = /tmp/wazuh-archiver
```

---

## GPG key management

Both keys are generated automatically by `setup.sh`. The directory structure
under `/etc/wazuh-archiver/` is:

```
/etc/wazuh-archiver/
├── signing/
│   ├── gnupg/              — signing keyring (stays on this machine)
│   └── MOVE_TO_SAFE/
│       └── pubkey.asc      — public key → share with compliance team
│
├── encryption/
│   ├── gnupg/              — encryption keyring (stays on this machine)
│   ├── pubkey.asc          — public key reference copy
│   └── MOVE_TO_SAFE/
│       └── private-key.asc — private key → move to secure offline storage
```

### Signing key

- **Private key**: stays in `signing/gnupg/` — used by the archiver to sign every file
- **Public key** (`signing/MOVE_TO_SAFE/pubkey.asc`): share with the compliance
  team so they can verify signatures independently

```bash
# Verify a signature on the receiving end
gpg --import pubkey.asc
gpg --verify ossec-archive-20.json.gz.sig ossec-archive-20.json.gz
```

### Encryption key pair

- **Public key**: stays in `encryption/gnupg/` — used by the archiver to encrypt
- **Private key** (`encryption/MOVE_TO_SAFE/private-key.asc`): the **only** way
  to decrypt archived files. Move to a physically secured location (safe, HSM, or
  offline escrow) and delete from this machine immediately:

```bash
# After copying to secure location:
shred -u /etc/wazuh-archiver/encryption/MOVE_TO_SAFE/private-key.asc

# To decrypt an archive on the receiving end:
gpg --import private-key.asc
gpg --decrypt ossec-archive-20.json.gz.gpg > ossec-archive-20.json.gz
```

### Regenerating keys manually

```bash
sudo bash create-signing-key.sh
sudo bash create-encryption-key.sh
```

### Verifying archives (recipient side)

```bash
# Import the Wazuh node's public signing key
gpg --import pubkey.asc

# Verify the signature
gpg --verify ossec-archive-20.json.gz.sig ossec-archive-20.json.gz

# Verify the checksum
sha256sum -c ossec-archive-20.json.gz.sha256
```

---

## SFTP connection

The tool uses the system `sftp(1)` binary in batch mode — no external Python
libraries. This makes it work on any host with OpenSSH installed, including
servers in air-gapped networks.

**Host key verification behaviour:**

| Situation | Behaviour |
|-----------|-----------|
| `known_hosts_file` configured | `StrictHostKeyChecking=yes` — strict, recommended for production |
| No `known_hosts_file` | `StrictHostKeyChecking=accept-new` — records on first contact, rejects changes thereafter |

When `known_hosts_file` is not configured, the host key is stored automatically
to `/var/lib/wazuh-archiver/known_hosts` on first connection. This avoids
relying on `~/.ssh/known_hosts` which is inaccessible when the systemd service
runs with `ProtectHome=true`.

**Recommended — configure `known_hosts_file` explicitly:**

```bash
# Record the SFTP server's host key (replace sftp.example.com with your host)
sudo ssh-keyscan -H sftp.example.com | sudo tee /etc/wazuh-archiver/known_hosts
sudo chown root:wazuh-archiver /etc/wazuh-archiver/known_hosts
sudo chmod 640 /etc/wazuh-archiver/known_hosts
```

Then set in `archiver.conf`:

```ini
known_hosts_file = /etc/wazuh-archiver/known_hosts
```

This enables strict host key verification (`StrictHostKeyChecking=yes`) which
protects against MITM attacks. Without it, the first connection is accepted
automatically without any confirmation.

**Transfer integrity:** SSH provides HMAC-SHA2 transport-layer integrity.
The `.sha256` sidecar file provides content-level integrity that the
compliance team can verify independently at any time with `sha256sum -c`.

---

## WebDAV connection (HTTPS)

In addition to SFTP, the archiver supports uploading to a WebDAV server over
HTTPS.  This is the native protocol for Synology DSM (port **5001**) and
QNAP QTS (port **5006**) NAS devices.

**Zero additional dependencies** — uses Python's stdlib `urllib.request` and
`ssl` modules.  No external packages are required.

### Transfer mode

Set `mode` in the new `[transfer]` config section:

```ini
[transfer]
mode = sftp          # default — existing behaviour unchanged
# mode = webdav      # WebDAV only
# mode = sftp,webdav # upload to both simultaneously (redundancy)
```

### 1. Create the password file

The WebDAV password is stored in a dedicated file (not inline in the config)
so it never appears in `ps` output or log files:

```bash
printf '%s' 'your-webdav-password' | sudo tee /etc/wazuh-archiver/webdav_password > /dev/null
sudo chown root:wazuh-archiver /etc/wazuh-archiver/webdav_password
sudo chmod 440 /etc/wazuh-archiver/webdav_password
```

### 2. Obtain the TLS certificate (Synology / QNAP)

Synology DSM and QNAP QTS ship with self-signed certificates by default.
Export the root CA certificate so the archiver can verify the connection:

**Synology DSM:**
```
Control Panel → Security → Certificate → (select certificate) → Export certificate
```
Extract `root.pem` from the downloaded archive, then:

```bash
sudo cp root.pem /etc/wazuh-archiver/webdav_ca.pem
sudo chown root:wazuh-archiver /etc/wazuh-archiver/webdav_ca.pem
sudo chmod 640 /etc/wazuh-archiver/webdav_ca.pem
```

**QNAP QTS:**
Download from `https://<nas-ip>:8080/cgi-bin/filemanager/utilRequest.cgi?func=get_cacert`
or export via Control Panel → Certificate & Private Key.

**Test the certificate:**
```bash
curl -v --cacert /etc/wazuh-archiver/webdav_ca.pem \
     https://nas.example.com:5001/
```

### 3. Configure `archiver.conf`

```ini
[transfer]
mode = webdav

[webdav]
url           = https://nas.example.com:5001
remote_dir    = /archive/wazuh
username      = wazuh-archiver
password_file = /etc/wazuh-archiver/webdav_password
ca_cert       = /etc/wazuh-archiver/webdav_ca.pem
```

### 4. Test the WebDAV connection manually

```bash
# Create directory
curl -v -u wazuh-archiver:password \
     --cacert /etc/wazuh-archiver/webdav_ca.pem \
     -X MKCOL https://nas.example.com:5001/archive/wazuh/

# Upload a test file
curl -v -u wazuh-archiver:password \
     --cacert /etc/wazuh-archiver/webdav_ca.pem \
     -T /tmp/test.txt \
     https://nas.example.com:5001/archive/wazuh/test.txt
```

### Host key verification behaviour (WebDAV)

WebDAV over HTTPS relies on TLS for both encryption and server authentication:

| `ca_cert` value | Behaviour |
|-----------------|-----------|
| `/path/to/ca.pem` | Verify against custom CA bundle — recommended for self-signed NAS certs |
| `true` | Verify against system CA store — for publicly trusted certificates |
| `false` | **Disable verification — never use in production** |

---

## FTP connection

Plain FTP transfers files using a username and password.  Implemented with
Python's built-in `ftplib` module — no external packages required.

> **Security note:** FTP transmits credentials and file content in cleartext.
> Use only on closed internal networks or legacy systems where FTPS is
> unavailable.  The `.sha256` manifest still provides content-level integrity
> verifiable by the recipient at any time with `sha256sum -c`.

### Configure `archiver.conf`

```ini
[transfer]
mode = ftp

[ftp]
host          = ftp.example.com
port          = 21
username      = wazuh-archiver
password_file = /etc/wazuh-archiver/ftp_password
remote_dir    = /archive/wazuh
passive_mode  = true
```

### Create the password file

```bash
printf '%s' 'your-ftp-password' | sudo tee /etc/wazuh-archiver/ftp_password > /dev/null
sudo chown root:wazuh-archiver /etc/wazuh-archiver/ftp_password
sudo chmod 440 /etc/wazuh-archiver/ftp_password
```

### Test the connection manually

```bash
python3 -c "
import ftplib
ftp = ftplib.FTP()
ftp.connect('ftp.example.com', 21, timeout=10)
ftp.login('wazuh-archiver', open('/etc/wazuh-archiver/ftp_password').read().strip())
print('PWD:', ftp.pwd())
ftp.quit()
"
```

---

## FTPS connection (explicit TLS)

FTPS explicit (AUTH TLS) connects to port 21 and negotiates TLS after the
initial handshake.  Both the control channel (credentials) and the data
channel (file content) are protected by TLS.  Implemented with Python's
built-in `ftplib.FTP_TLS` — no external packages required.

**Connection flow:**
```
1. TCP connect to port 21
2. login()  — server negotiates AUTH TLS → control channel encrypted
3. prot_p() — PROT P command → data channel encrypted
4. set_pasv() — passive data connections (PASV)
5. storbinary() — upload files
```

### Configure `archiver.conf`

```ini
[transfer]
mode = ftps

[ftps]
host          = ftps.example.com
port          = 21
username      = wazuh-archiver
password_file = /etc/wazuh-archiver/ftps_password
remote_dir    = /archive/wazuh
ca_cert       = true        # or /path/to/ca.pem for self-signed certs
passive_mode  = true
```

### Create the password file

```bash
printf '%s' 'your-ftps-password' | sudo tee /etc/wazuh-archiver/ftps_password > /dev/null
sudo chown root:wazuh-archiver /etc/wazuh-archiver/ftps_password
sudo chmod 440 /etc/wazuh-archiver/ftps_password
```

### Test the connection manually

```bash
python3 -c "
import ftplib, ssl
ctx = ssl.create_default_context()
# For self-signed: ctx.load_verify_locations('/etc/wazuh-archiver/ftps_ca.pem')
ftp = ftplib.FTP_TLS(context=ctx)
ftp.connect('ftps.example.com', 21, timeout=10)
ftp.login('wazuh-archiver', open('/etc/wazuh-archiver/ftps_password').read().strip())
ftp.prot_p()
print('PWD:', ftp.pwd())
ftp.quit()
"
```

| `ca_cert` value | Behaviour |
|-----------------|-----------|
| `true` | Verify against system CA store (public certificates) |
| `/path/to/ca.pem` | Verify against custom CA bundle (self-signed) |
| `false` | **Disable verification — never use in production** |

---

## Systemd scheduling

The timer runs every 10 minutes at :30 seconds past each interval
(`:00:30`, `:10:30`, `:20:30`, `:30:30`, `:40:30`, `:50:30`).
Most runs will find no new files; the state file prevents re-uploading.

```
:00  Wazuh rotates logs
:00:30  wazuh-archiver.timer fires archiver.py
:00:30+ Files transferred to SFTP server
```

Adjust `OnCalendar` in `systemd/wazuh-archiver.timer` to match your
`rotate_interval` setting in `ossec.conf`:

| rotate_interval | OnCalendar |
|-----------------|------------|
| 10m | `*-*-* *:0/10:30` |
| 15m | `*-*-* *:0/15:30` |
| 30m | `*-*-* *:0/30:30` |
| 1h  | `*-*-* *:00:30`   |

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

## Monitoring with Zabbix

The archiver writes a structured `AUDIT_RECORD` JSON line to the audit log for
every processed file.  Zabbix can monitor this log in real time and alert
immediately when a transfer fails.

### What is monitored

Every successful or failed file transfer produces one line in
`/var/log/wazuh-archiver/audit.log` of the form:

```
2026-02-22T10:10:54-0500 [INFO] AUDIT_RECORD {"timestamp": "...", "node": "wazuh-node1", "source_file": "...", "status": "failed", "error": "..."}
2026-02-22T10:12:01-0500 [INFO] AUDIT_RECORD {"timestamp": "...", "node": "wazuh-node1", "source_file": "...", "status": "success", ...}
```

The Zabbix item watches for lines containing `"status": "failed"` and triggers
an alert as soon as one appears.

### Step 1 — Grant Zabbix agent read access

The Zabbix agent runs as the `zabbix` user and needs read access to the audit
log and its directory.  Use POSIX ACL so that the existing `wazuh-archiver`
group permissions are not disturbed:

```bash
# Directory: execute permission so the agent can list files (needed for logrt)
setfacl -m u:zabbix:x /var/log/wazuh-archiver

# Current log file
setfacl -m u:zabbix:r /var/log/wazuh-archiver/audit.log

# Default ACL — automatically applied to rotated files (audit.log.1, .2, …)
setfacl -d -m u:zabbix:r /var/log/wazuh-archiver
```

Verify:

```bash
getfacl /var/log/wazuh-archiver/audit.log
```

### Step 2 — Configure the Zabbix item

Create a new item on the host in the Zabbix frontend:

| Field | Value |
|-------|-------|
| **Name** | `wazuh-archiver: failed transfer` |
| **Type** | `Zabbix agent (active)` |
| **Key** | `logrt[/var/log/wazuh-archiver/audit.log,"\"status\": \"failed\"",UTF-8,skip]` |
| **Type of information** | `Log` |
| **Update interval** | `1m` |

> **Why `logrt` and not `log`?**  The audit log uses rotating file names
> (`audit.log` → `audit.log.1` → `audit.log.2` …).  `logrt` follows rotations
> automatically; `log` does not.

> **Why `active` agent?**  Log monitoring in Zabbix requires an active agent —
> passive checks cannot tail log files.  Ensure `ServerActive` is configured
> in `/etc/zabbix/zabbix_agentd.conf`.

### Step 3 — Configure the trigger

Create a trigger linked to the item above:

| Field | Value |
|-------|-------|
| **Name** | `wazuh-archiver: transfer failed on {HOST.NAME}` |
| **Severity** | `High` |
| **Expression** | `length(last(/HOST/logrt[...]))>0` |

The trigger fires as soon as the item matches any line — i.e. the moment a
failed `AUDIT_RECORD` appears in the log.  It recovers automatically once no
new failures are detected.

### What the alert tells you

The matched log line contains the full JSON audit record, including:

- `source_file` — which log file failed to transfer
- `error` — the exact error message (e.g. sftp exit code, GPG error)
- `node` — the Wazuh node name
- `timestamp` — when the failure occurred

This is sufficient to diagnose the problem without logging into the server.

---

## Files written to the remote store

The remote directory structure mirrors Wazuh's source layout (`YYYY/Mon/`),
so files from different months never overwrite each other regardless of
filename.

Each processed file produces the following sidecar files:

```
/archive/wazuh/
  2026/Feb/
    ossec-archive-20.json.gz          upload_plaintext=true (default) — compressed log data
    ossec-archive-20.json.gz.sha256   always   — SHA-256 integrity manifest
    ossec-archive-20.json.gz.sig      optional — GPG detached signature (signing=true)
    ossec-archive-20.json.gz.gpg      optional — GPG-encrypted copy (encryption=true)
  2026/Mar/
    ossec-archive-20.json.gz
    ...
```

Set `upload_plaintext = false` (requires `encryption = true`) to upload only the
encrypted `.gpg` file instead of the plaintext archive.  The `.sha256` manifest is
always uploaded — it digests the original plaintext so integrity can be verified
after decryption with `sha256sum -c`.

The same pattern applies to `.json` and `.log.gz` files.

The `.sha256` format is compatible with `sha256sum -c`:

```
a3f2c1...  ossec-archive-20.json.gz
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
| **Key management** | Signing key on host; encryption private key stored offline |

---

## Troubleshooting

### "No new files found"

- Is `logall_json=yes` set in `ossec.conf`?
- Is `rotate_interval` set?
- Are the `log_dirs` paths correct for your deployment (host paths, not
  container-internal paths)?
- Are uncompressed `.json` files younger than `min_age_minutes`? Check with:
  `ls -la /var/lib/docker/volumes/single-node_wazuh_logs/_data/archives/$(date +%Y/%b)/`
- Check processed file list: `cat /var/lib/wazuh-archiver/state.json`

### "sftp failed"

- Test connectivity manually:
  `sftp -i /etc/wazuh-archiver/sftp_key -P 22 user@host`
- Is `known_hosts` populated?
  `ssh-keyscan -H sftp.example.com >> /etc/wazuh-archiver/known_hosts`
- Check key permissions: `stat /etc/wazuh-archiver/sftp_key`
  (must be 440 or 400)

### "GPG command failed"

- List signing keys:
  `gpg --homedir /etc/wazuh-archiver/signing/gnupg --list-secret-keys`
- List encryption keys:
  `gpg --homedir /etc/wazuh-archiver/encryption/gnupg --list-keys`
- Check directory ownership (must be owned by `wazuh-archiver`, chmod 700):
  `stat /etc/wazuh-archiver/signing/gnupg`
  `stat /etc/wazuh-archiver/encryption/gnupg`
- After updating systemd service, reload:
  `systemctl daemon-reload`

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
