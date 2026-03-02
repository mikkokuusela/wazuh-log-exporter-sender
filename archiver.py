#!/usr/bin/env python3
"""
wazuh-archiver — Compliance log archival for Wazuh (KATAKRI 2020 / NIST)

Collects rotated Wazuh archive files (.json.gz), optionally signs them with
a GPG detached signature and/or encrypts them, then uploads everything to
an SFTP server via the system sftp(1) binary with a full audit trail.

Zero external dependencies — requires only Python 3 stdlib + OpenSSH + gpg,
all of which are present on any standard Linux server.  Suitable for
air-gapped environments where pip is unavailable.

Intended to run via systemd timer once per hour, 5 minutes after the top of
the hour so that Wazuh has time to finish log rotation at :00.

Usage:
    python3 archiver.py [--config /path/to/archiver.conf] [--dry-run]
"""

import argparse
import base64
import configparser
import ftplib
import hashlib
import json
import logging
import logging.handlers
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

VERSION = "1.3.1"
DEFAULT_CONFIG = "/etc/wazuh-archiver/archiver.conf"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def load_config(path: str) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    if not cfg.read(path):
        raise FileNotFoundError(f"Config file not found: {path}")
    return cfg


# ---------------------------------------------------------------------------
# Logging / Audit trail
# ---------------------------------------------------------------------------


def setup_logger(audit_log_path: str) -> logging.Logger:
    logger = logging.getLogger("wazuh-archiver")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    os.makedirs(os.path.dirname(audit_log_path), exist_ok=True)
    fh = logging.handlers.RotatingFileHandler(
        audit_log_path, maxBytes=50 * 1024 * 1024, backupCount=12
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------


def load_state(state_file: str) -> dict:
    if os.path.isfile(state_file):
        try:
            with open(state_file) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            # Corrupted state: start fresh rather than crash
            logging.getLogger("wazuh-archiver").warning(
                f"State file unreadable ({e}), starting fresh"
            )
    return {"processed_files": [], "version": VERSION}


def save_state(state_file: str, state: dict) -> None:
    """Atomic write: write to .tmp then rename to avoid corruption on crash."""
    os.makedirs(os.path.dirname(state_file), exist_ok=True)
    tmp = state_file + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, state_file)


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------


def find_new_log_files(
    log_dirs: list,
    state: dict,
    file_patterns: list,
    min_age_seconds: int,
) -> list:
    """
    Return rotated log files not yet processed.

    Searches recursively inside each configured directory for all configured
    file patterns. Files at the root level of a log directory (e.g.
    archives.json, alerts.log) are always skipped — they are the
    currently-active files Wazuh is still writing to.

    For uncompressed files (no .gz suffix), min_age_seconds is enforced so
    that files Wazuh is actively rotating are not captured mid-write.
    Compressed (.gz) files are always safe to archive immediately.
    """
    processed = set(state.get("processed_files", []))
    new_files = []
    now = datetime.now(timezone.utc).timestamp()

    for log_dir in log_dirs:
        p = Path(log_dir)
        try:
            if not p.exists():
                logging.getLogger("wazuh-archiver").warning(
                    f"Log directory not found, skipping: {log_dir}"
                )
                continue
        except PermissionError:
            # Path.exists() propagates PermissionError in Python 3.12+
            logging.getLogger("wazuh-archiver").error(
                f"Permission denied: {log_dir}\n"
                f"  Fix with: setfacl -m u:{os.getlogin() if hasattr(os, 'getlogin') else 'wazuh-archiver'}:x "
                f"<each parent dir up to {log_dir}>\n"
                f"  Then:     setfacl -R -m u:wazuh-archiver:rX {log_dir}"
            )
            continue

        try:
            # Collect candidates across all patterns; use a set to avoid
            # processing the same file twice if patterns overlap.
            candidates: set = set()
            for pattern in file_patterns:
                for f in p.rglob(pattern):
                    # Skip root-level active files (archives.json, alerts.log, …)
                    if f.parent == p:
                        continue
                    candidates.add(f)

            for f in sorted(candidates):
                path_str = str(f)

                if path_str in processed:
                    continue

                # For uncompressed files, enforce minimum age so we don't
                # capture files Wazuh is still actively writing to.
                if not path_str.endswith(".gz") and min_age_seconds > 0:
                    try:
                        age = now - f.stat().st_mtime
                        if age < min_age_seconds:
                            logging.getLogger("wazuh-archiver").debug(
                                f"Skipping (too recent, {int(age)}s < {min_age_seconds}s): {path_str}"
                            )
                            continue
                    except OSError:
                        continue

                new_files.append((path_str, log_dir))

        except PermissionError as e:
            logging.getLogger("wazuh-archiver").error(
                f"Permission denied while scanning {log_dir}: {e}"
            )

    return sorted(new_files)


# ---------------------------------------------------------------------------
# Integrity
# ---------------------------------------------------------------------------


def sha256sum(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_sha256_file(file_path: str, digest: str) -> str:
    """Write a sha256sum-compatible manifest (.sha256) alongside the file."""
    manifest = file_path + ".sha256"
    with open(manifest, "w") as f:
        # sha256sum-compatible format: "<hash>  <filename>"
        f.write(f"{digest}  {os.path.basename(file_path)}\n")
    return manifest


# ---------------------------------------------------------------------------
# GPG operations
# ---------------------------------------------------------------------------


def _gpg_run(args: list, logger: logging.Logger) -> None:
    """Run a GPG command; raise RuntimeError on failure."""
    result = subprocess.run(args, capture_output=True, text=True)
    if result.stderr:
        logger.debug(f"GPG stderr: {result.stderr.strip()}")
    if result.returncode != 0:
        raise RuntimeError(
            f"GPG command failed (exit {result.returncode}): {result.stderr.strip()}"
        )


def gpg_sign(
    file_path: str,
    key_id: str,
    gpg_binary: str,
    gpg_homedir: str,
    logger: logging.Logger,
) -> str:
    """Create a detached armored signature (.sig). Returns path to .sig file."""
    sig = file_path + ".sig"
    _gpg_run(
        [
            gpg_binary,
            "--homedir", gpg_homedir,
            "--batch", "--no-tty", "--yes",
            "--detach-sign", "--armor",
            "--local-user", key_id,
            "--output", sig,
            file_path,
        ],
        logger,
    )
    logger.info(f"  Signed  -> {os.path.basename(sig)}")
    return sig


def gpg_encrypt(
    file_path: str,
    recipient: str,
    gpg_binary: str,
    gpg_homedir: str,
    logger: logging.Logger,
) -> str:
    """Encrypt file to recipient's public key (.gpg). Returns path to .gpg file."""
    enc = file_path + ".gpg"
    _gpg_run(
        [
            gpg_binary,
            "--homedir", gpg_homedir,
            "--batch", "--no-tty", "--yes",
            "--encrypt",
            "--recipient", recipient,
            "--output", enc,
            file_path,
        ],
        logger,
    )
    logger.info(f"  Encrypted -> {os.path.basename(enc)}")
    return enc


# ---------------------------------------------------------------------------
# SFTP transfer  (stdlib-only: delegates to system sftp(1) and ssh(1))
# ---------------------------------------------------------------------------


def _ssh_opts(key_path: str, port: int, known_hosts: Optional[str]) -> list:
    """
    Build the common SSH/SFTP CLI option list used by every subprocess call.

    StrictHostKeyChecking=yes + an explicit UserKnownHostsFile is the
    production-safe default.  Without a known_hosts file we fall back to
    'accept-new' (records the key on first contact, rejects changes
    thereafter) rather than 'no' (which would accept MITM substitutions).

    UserKnownHostsFile is always set explicitly to avoid SSH falling back
    to ~/.ssh/known_hosts, which is inaccessible when the systemd service
    runs with ProtectHome=true.
    """
    opts = [
        "-i", key_path,
        "-o", "BatchMode=yes",          # never prompt for a password
        "-o", "ConnectTimeout=30",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
    ]
    if known_hosts and os.path.isfile(known_hosts):
        opts += [
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={known_hosts}",
        ]
    else:
        opts += [
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UserKnownHostsFile=/var/lib/wazuh-archiver/known_hosts",
        ]
    return opts


def _sftp_batch_mkdir(remote_dir: str) -> list:
    """
    Return sftp batch-mode lines that create the full remote directory tree.

    The leading '-' on each mkdir suppresses the error when the directory
    already exists, so subsequent runs are idempotent.
    """
    parts = remote_dir.strip("/").split("/")
    lines = []
    path = ""
    for part in parts:
        path = f"{path}/{part}"
        lines.append(f"-mkdir {path}")
    return lines


def sftp_upload_files(
    host: str,
    port: int,
    username: str,
    key_path: str,
    known_hosts: Optional[str],
    remote_dir: str,
    files: list,   # list of (local_path, remote_filename) tuples
    logger: logging.Logger,
) -> list:
    """
    Upload files using the system sftp(1) binary in batch mode.

    A single SFTP session handles all files in one connection:
      • mkdir lines create the remote directory tree (idempotent)
      • put lines upload each file

    Transfer integrity is guaranteed by the SSH transport layer (HMAC-SHA2).
    Content integrity for the compliance team is provided by the .sha256
    manifest file uploaded alongside each archive — verifiable at any time
    with: sha256sum -c <file>.sha256
    """
    ssh_opts = _ssh_opts(key_path, port, known_hosts)

    # Build the batch script
    batch_lines = _sftp_batch_mkdir(remote_dir)
    for local_path, remote_name in files:
        remote_path = f"{remote_dir}/{remote_name}"
        # Double-quote paths so sftp handles spaces correctly
        batch_lines.append(f'put "{local_path}" "{remote_path}"')
    batch_content = "\n".join(batch_lines) + "\n"

    logger.debug(f"SFTP batch script:\n{batch_content}")

    # Write batch file to a temp file (avoids shell quoting on the command line)
    batch_fd, batch_path = tempfile.mkstemp(suffix=".sftp", prefix="wazuh-arch-")
    try:
        with os.fdopen(batch_fd, "w") as f:
            f.write(batch_content)

        cmd = (
            ["sftp"]
            + ssh_opts
            + ["-P", str(port), "-b", batch_path, f"{username}@{host}"]
        )
        logger.debug(f"Running: {' '.join(cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stderr:
            logger.debug(f"sftp stderr: {result.stderr.strip()}")
        if result.returncode != 0:
            raise IOError(
                f"sftp failed (exit {result.returncode}): {result.stderr.strip()}"
            )
    finally:
        os.unlink(batch_path)

    # Record results — local sizes are the ground truth;
    # SSH transport guarantees byte-identical delivery.
    results = []
    for local_path, remote_name in files:
        size = os.path.getsize(local_path)
        logger.info(f"  Transferred: {remote_name} ({size:,} bytes)")
        results.append(
            {
                "remote_name": remote_name,
                "remote_path": f"{remote_dir}/{remote_name}",
                "size_bytes": size,
                "verified": True,   # SSH HMAC transport-layer integrity
            }
        )
    return results


# ---------------------------------------------------------------------------
# WebDAV transfer  (stdlib-only: urllib.request + ssl)
# ---------------------------------------------------------------------------


def _build_ssl_context(ca_cert: str) -> ssl.SSLContext:
    """
    Build an SSLContext for HTTPS/FTPS connections.

    ca_cert values:
      "true"       — verify against the system's trusted CA store (default)
      "/path/…"    — verify against a custom CA bundle (.pem), e.g. for
                     self-signed certificates on Synology/QNAP NAS devices
      "false"      — disable verification entirely (NOT recommended in prod)
    """
    if ca_cert.lower() == "false":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    ctx = ssl.create_default_context()
    if ca_cert.lower() != "true":
        ctx.load_verify_locations(cafile=ca_cert)
    return ctx


def _webdav_basic_auth(username: str, password: str) -> str:
    """Return a Basic Authorization header value."""
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"


def _webdav_mkcol(
    url: str,
    headers: dict,
    ssl_ctx: ssl.SSLContext,
    logger: logging.Logger,
) -> None:
    """
    Create a remote directory via WebDAV MKCOL.

    Idempotent: HTTP 405 (Method Not Allowed) and 409 (Conflict) indicate
    the directory already exists and are treated as success.  Synology DSM
    returns 405 for an existing collection; QNAP returns 405 or 409.
    """
    req = urllib.request.Request(url, method="MKCOL", headers=headers)
    try:
        with urllib.request.urlopen(req, context=ssl_ctx):
            logger.debug(f"WebDAV MKCOL created: {url}")
    except urllib.error.HTTPError as exc:
        if exc.code in (405, 409, 301, 302):
            logger.debug(f"WebDAV MKCOL {exc.code} (already exists): {url}")
        else:
            raise IOError(
                f"WebDAV MKCOL failed (HTTP {exc.code}) for {url}: {exc.reason}"
            ) from exc


def webdav_upload_files(
    url_base: str,
    remote_dir: str,
    username: str,
    password: str,
    ca_cert: str,
    files: list,   # list of (local_path, remote_filename) tuples
    logger: logging.Logger,
) -> list:
    """
    Upload files to a WebDAV server over HTTPS using HTTP Basic Auth.

    Uses only Python stdlib (urllib.request + ssl).  Suitable for
    Synology DSM (port 5001) and QNAP QTS (port 5006) NAS devices.

    Directory structure is created via MKCOL (idempotent).
    Each file is uploaded with a PUT request.

    Transfer integrity is provided by TLS (HTTPS); content integrity is
    provided by the .sha256 manifest uploaded alongside each archive.
    """
    ssl_ctx = _build_ssl_context(ca_cert)
    auth_header = _webdav_basic_auth(username, password)
    headers = {"Authorization": auth_header}

    # Create remote directory tree (idempotent MKCOL for each path segment)
    parts = remote_dir.strip("/").split("/")
    path = ""
    for part in parts:
        path = f"{path}/{part}"
        _webdav_mkcol(f"{url_base.rstrip('/')}{path}", headers, ssl_ctx, logger)

    # Upload files via PUT
    results = []
    for local_path, remote_name in files:
        remote_url = f"{url_base.rstrip('/')}{remote_dir.rstrip('/')}/{remote_name}"
        file_size = os.path.getsize(local_path)

        with open(local_path, "rb") as f:
            data = f.read()

        put_headers = {
            **headers,
            "Content-Type": "application/octet-stream",
            "Content-Length": str(file_size),
        }
        req = urllib.request.Request(
            remote_url, data=data, method="PUT", headers=put_headers
        )
        try:
            with urllib.request.urlopen(req, context=ssl_ctx) as resp:
                if resp.status not in (200, 201, 204):
                    raise IOError(
                        f"WebDAV PUT returned unexpected status {resp.status}"
                    )
        except urllib.error.HTTPError as exc:
            raise IOError(
                f"WebDAV PUT failed (HTTP {exc.code}) for {remote_url}: {exc.reason}"
            ) from exc

        logger.info(f"  Transferred (WebDAV): {remote_name} ({file_size:,} bytes)")
        results.append(
            {
                "remote_name": remote_name,
                "remote_path": f"{remote_dir}/{remote_name}",
                "size_bytes": file_size,
                "verified": True,   # TLS transport-layer integrity
            }
        )
    return results


# ---------------------------------------------------------------------------
# FTP / FTPS transfer  (stdlib-only: ftplib)
# ---------------------------------------------------------------------------


def _ftp_mkdir_recursive(
    ftp: ftplib.FTP,
    remote_dir: str,
    logger: logging.Logger,
) -> None:
    """
    Create the full remote directory tree via FTP MKD commands.

    Idempotent: a 550 error reply (directory already exists) is silently
    ignored.  Other permission errors are raised as IOError.
    """
    parts = remote_dir.strip("/").split("/")
    path = ""
    for part in parts:
        path = f"{path}/{part}"
        try:
            ftp.mkd(path)
            logger.debug(f"FTP MKD created: {path}")
        except ftplib.error_perm as exc:
            # 550 = "Failed to create directory" — usually means it already exists
            if str(exc)[:3] == "550":
                logger.debug(f"FTP MKD 550 (exists): {path}")
            else:
                raise IOError(f"FTP MKD failed for {path}: {exc}") from exc


def ftp_upload_files(
    host: str,
    port: int,
    username: str,
    password: str,
    remote_dir: str,
    files: list,    # list of (local_path, remote_filename) tuples
    passive: bool,
    logger: logging.Logger,
) -> list:
    """
    Upload files via plain FTP using ftplib.FTP (Python stdlib).

    Uses passive mode (PASV) by default — required by most firewalls.

    Note: FTP transmits credentials and file data in cleartext.
    The .sha256 manifest still provides content-level integrity
    verifiable by the recipient at any time.
    """
    with ftplib.FTP() as ftp:
        ftp.connect(host, port, timeout=30)
        ftp.login(username, password)
        ftp.set_pasv(passive)
        _ftp_mkdir_recursive(ftp, remote_dir, logger)
        results = []
        for local_path, remote_name in files:
            remote_path = f"{remote_dir.rstrip('/')}/{remote_name}"
            file_size = os.path.getsize(local_path)
            with open(local_path, "rb") as f:
                ftp.storbinary(f"STOR {remote_path}", f)
            logger.info(f"  Transferred (FTP): {remote_name} ({file_size:,} bytes)")
            results.append(
                {
                    "remote_name": remote_name,
                    "remote_path": f"{remote_dir}/{remote_name}",
                    "size_bytes": file_size,
                    "verified": False,  # FTP has no transport-layer integrity
                }
            )
    return results


def ftps_upload_files(
    host: str,
    port: int,
    username: str,
    password: str,
    ca_cert: str,
    remote_dir: str,
    files: list,    # list of (local_path, remote_filename) tuples
    passive: bool,
    logger: logging.Logger,
) -> list:
    """
    Upload files via explicit FTPS (AUTH TLS on port 21) using ftplib.FTP_TLS.

    Connection flow:
      1. Plain TCP connect to port 21
      2. login() — server sends AUTH TLS challenge, control channel upgraded to TLS
      3. prot_p() — data channel upgraded to TLS (PROT P command)
      4. set_pasv() — passive data connections (PASV)
      5. storbinary() — upload files

    Both the control channel (credentials) and data channel (file content)
    are protected by TLS.  Transfer integrity is guaranteed by TLS (HMAC).
    Content integrity for the compliance team is provided by the .sha256 manifest.
    """
    ssl_ctx = _build_ssl_context(ca_cert)
    with ftplib.FTP_TLS(context=ssl_ctx) as ftp:
        ftp.connect(host, port, timeout=30)
        ftp.login(username, password)
        ftp.prot_p()          # upgrade data channel to TLS (PROT P)
        ftp.set_pasv(passive)
        _ftp_mkdir_recursive(ftp, remote_dir, logger)
        results = []
        for local_path, remote_name in files:
            remote_path = f"{remote_dir.rstrip('/')}/{remote_name}"
            file_size = os.path.getsize(local_path)
            with open(local_path, "rb") as f:
                ftp.storbinary(f"STOR {remote_path}", f)
            logger.info(f"  Transferred (FTPS): {remote_name} ({file_size:,} bytes)")
            results.append(
                {
                    "remote_name": remote_name,
                    "remote_path": f"{remote_dir}/{remote_name}",
                    "size_bytes": file_size,
                    "verified": True,   # TLS transport-layer integrity
                }
            )
    return results


# ---------------------------------------------------------------------------
# Core: process one log file end-to-end
# ---------------------------------------------------------------------------


def _effective_dir(base: str, subdir: str) -> str:
    """Return base/subdir when subdir is non-empty, otherwise just base."""
    return f"{base}/{subdir}" if subdir else base


def process_file(
    source_path: str,
    log_dir: str,
    config: configparser.ConfigParser,
    work_dir: str,
    logger: logging.Logger,
) -> dict:
    """
    Process a single rotated log file:
      1. Calculate SHA-256
      2. Write .sha256 manifest
      3. GPG sign (optional)
      4. GPG encrypt (optional)
      5. Upload via configured transport(s): sftp, webdav, or both
      6. Return audit record

    The original file is never modified.
    When gpg.upload_plaintext = false (requires encryption = true), only the
    encrypted .gpg file is uploaded alongside the .sha256 manifest and optional
    .sig signature.  The .sha256 digest is always of the original plaintext so
    the recipient can verify integrity after decryption.
    Returns a dict with status='success' or status='failed'.
    """
    node = config.get("wazuh", "node_name", fallback="wazuh-node1")

    # Transfer mode: sftp, webdav, or comma-separated combination.
    # Defaults to "sftp" for backwards compatibility.
    transfer_mode_raw = config.get("transfer", "mode", fallback="sftp").strip()
    transfer_modes = {m.strip().lower() for m in transfer_mode_raw.split(",") if m.strip()}
    if not transfer_modes:
        transfer_modes = {"sftp"}

    gpg_bin = config.get("gpg", "gpg_binary", fallback="/usr/bin/gpg")
    # Legacy single gpg_homedir — used as fallback if separate homedirs are not set
    _legacy_home = config.get("gpg", "gpg_homedir", fallback="").strip()
    if _legacy_home:
        logger.warning(
            "gpg.gpg_homedir is deprecated — use gpg.signing_homedir and gpg.encryption_homedir"
        )
    signing_home = config.get(
        "gpg", "signing_homedir",
        fallback=_legacy_home or "/etc/wazuh-archiver/signing/gnupg",
    ).strip()
    encryption_home = config.get(
        "gpg", "encryption_homedir",
        fallback=_legacy_home or "/etc/wazuh-archiver/encryption/gnupg",
    ).strip()
    signing = config.getboolean("gpg", "signing", fallback=False)
    signing_key = config.get("gpg", "signing_key_id", fallback="").strip()
    encryption = config.getboolean("gpg", "encryption", fallback=False)
    enc_recipient = config.get("gpg", "encryption_recipient", fallback="").strip()
    upload_plaintext = config.getboolean("gpg", "upload_plaintext", fallback=True)

    if not upload_plaintext and not encryption:
        raise ValueError(
            "gpg.upload_plaintext = false requires gpg.encryption = true"
        )

    if "sftp" in transfer_modes:
        sftp_host = config.get("sftp", "host")
        sftp_port = config.getint("sftp", "port", fallback=22)
        sftp_user = config.get("sftp", "username")
        sftp_key = config.get("sftp", "ssh_key_path")
        sftp_known_hosts = config.get("sftp", "known_hosts_file", fallback="").strip() or None
        sftp_remote = config.get("sftp", "remote_dir")

    if "webdav" in transfer_modes:
        webdav_url = config.get("webdav", "url").rstrip("/")
        webdav_remote = config.get("webdav", "remote_dir")
        webdav_user = config.get("webdav", "username")
        webdav_pwfile = config.get("webdav", "password_file")
        webdav_ca = config.get("webdav", "ca_cert", fallback="true").strip()
        with open(webdav_pwfile) as _f:
            webdav_password = _f.read().strip()

    if "ftp" in transfer_modes:
        ftp_host    = config.get("ftp", "host")
        ftp_port    = config.getint("ftp", "port", fallback=21)
        ftp_user    = config.get("ftp", "username")
        ftp_pwfile  = config.get("ftp", "password_file")
        ftp_remote  = config.get("ftp", "remote_dir")
        ftp_passive = config.getboolean("ftp", "passive_mode", fallback=True)
        with open(ftp_pwfile) as _f:
            ftp_password = _f.read().strip()

    if "ftps" in transfer_modes:
        ftps_host    = config.get("ftps", "host")
        ftps_port    = config.getint("ftps", "port", fallback=21)
        ftps_user    = config.get("ftps", "username")
        ftps_pwfile  = config.get("ftps", "password_file")
        ftps_remote  = config.get("ftps", "remote_dir")
        ftps_ca      = config.get("ftps", "ca_cert", fallback="true").strip()
        ftps_passive = config.getboolean("ftps", "passive_mode", fallback=True)
        with open(ftps_pwfile) as _f:
            ftps_password = _f.read().strip()

    t0 = datetime.now(timezone.utc)
    rel_path   = os.path.relpath(source_path, log_dir)   # e.g. "2026/Feb/ossec-archive-22.json"
    rel_subdir = os.path.dirname(rel_path)                # e.g. "2026/Feb"
    fname      = os.path.basename(rel_path)               # e.g. "ossec-archive-22.json"

    # Isolated working directory — cleaned up even on failure
    wd = tempfile.mkdtemp(dir=work_dir, prefix="arch-")
    try:
        # Copy original into working dir (never modify the source)
        local = os.path.join(wd, fname)
        shutil.copy2(source_path, local)

        # 1. SHA-256 of the original compressed file
        digest = sha256sum(source_path)
        logger.info(f"  SHA256: {digest}")
        sha_file = write_sha256_file(local, digest)

        # Build the upload manifest.
        # The .sha256 is always included — it is a digest of the original
        # plaintext so the recipient can verify integrity after decryption.
        # The plaintext archive is included unless upload_plaintext = false
        # (only valid when encryption is also enabled).
        files = []
        if upload_plaintext:
            files.append((local, fname))
        files.append((sha_file, fname + ".sha256"))

        # 2. GPG signing
        if signing:
            if not signing_key:
                raise ValueError(
                    "gpg.signing = true but gpg.signing_key_id is not set"
                )
            sig = gpg_sign(local, signing_key, gpg_bin, signing_home, logger)
            files.append((sig, fname + ".sig"))

        # 3. GPG encryption
        if encryption:
            if not enc_recipient:
                raise ValueError(
                    "gpg.encryption = true but gpg.encryption_recipient is not set"
                )
            enc = gpg_encrypt(local, enc_recipient, gpg_bin, encryption_home, logger)
            files.append((enc, fname + ".gpg"))

        # 4. Upload via configured transport(s)
        upload_results = []
        if "sftp" in transfer_modes:
            upload_results += sftp_upload_files(
                host=sftp_host,
                port=sftp_port,
                username=sftp_user,
                key_path=sftp_key,
                known_hosts=sftp_known_hosts,
                remote_dir=_effective_dir(sftp_remote, rel_subdir),
                files=files,
                logger=logger,
            )
        if "webdav" in transfer_modes:
            upload_results += webdav_upload_files(
                url_base=webdav_url,
                remote_dir=_effective_dir(webdav_remote, rel_subdir),
                username=webdav_user,
                password=webdav_password,
                ca_cert=webdav_ca,
                files=files,
                logger=logger,
            )
        if "ftp" in transfer_modes:
            upload_results += ftp_upload_files(
                host=ftp_host,
                port=ftp_port,
                username=ftp_user,
                password=ftp_password,
                remote_dir=_effective_dir(ftp_remote, rel_subdir),
                files=files,
                passive=ftp_passive,
                logger=logger,
            )
        if "ftps" in transfer_modes:
            upload_results += ftps_upload_files(
                host=ftps_host,
                port=ftps_port,
                username=ftps_user,
                password=ftps_password,
                ca_cert=ftps_ca,
                remote_dir=_effective_dir(ftps_remote, rel_subdir),
                files=files,
                passive=ftps_passive,
                logger=logger,
            )

        t1 = datetime.now(timezone.utc)
        return {
            "timestamp": t1.isoformat(),
            "node": node,
            "source_file": source_path,
            "filename": fname,
            "sha256": digest,
            "size_bytes": os.path.getsize(source_path),
            "signed": signing,
            "encrypted": encryption,
            "transport": sorted(transfer_modes),
            "sftp_host":  sftp_host  if "sftp"  in transfer_modes else None,
            "webdav_url": webdav_url if "webdav" in transfer_modes else None,
            "ftp_host":   ftp_host   if "ftp"   in transfer_modes else None,
            "ftps_host":  ftps_host  if "ftps"  in transfer_modes else None,
            "remote_dir": _effective_dir(
                sftp_remote  if "sftp"  in transfer_modes else
                webdav_remote if "webdav" in transfer_modes else
                ftp_remote   if "ftp"   in transfer_modes else
                ftps_remote,
                rel_subdir,
            ),
            "files_uploaded": [r["remote_name"] for r in upload_results],
            "duration_seconds": round((t1 - t0).total_seconds(), 2),
            "status": "success",
        }

    except Exception as exc:
        logger.error(f"  FAILED processing {fname}: {exc}")
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "node": node,
            "source_file": source_path,
            "filename": fname,
            "status": "failed",
            "error": str(exc),
        }
    finally:
        shutil.rmtree(wd, ignore_errors=True)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Wazuh compliance log archiver (KATAKRI 2020 / NIST)"
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG,
        help=f"Path to config file (default: {DEFAULT_CONFIG})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Discover new files and log them, but do not upload or update state",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"wazuh-archiver {VERSION}",
    )
    # Show help when invoked with no arguments — prevents accidental runs
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    audit_log = config.get(
        "archiver", "audit_log", fallback="/var/log/wazuh-archiver/audit.log"
    )
    logger = setup_logger(audit_log)
    logger.info(f"wazuh-archiver {VERSION} starting  dry_run={args.dry_run}")

    state_file = config.get(
        "archiver", "state_file", fallback="/var/lib/wazuh-archiver/state.json"
    )
    state = load_state(state_file)

    log_dirs_raw = config.get(
        "wazuh", "log_dirs", fallback="/opt/wazuh/logs/archives"
    )
    log_dirs = [d.strip() for d in log_dirs_raw.split(",") if d.strip()]

    file_patterns_raw = config.get(
        "wazuh", "file_patterns", fallback="*.json.gz, *.json, *.log.gz"
    )
    file_patterns = [p.strip() for p in file_patterns_raw.split(",") if p.strip()]

    min_age_minutes = config.getint("wazuh", "min_age_minutes", fallback=65)
    min_age_seconds = min_age_minutes * 60

    new_files = find_new_log_files(log_dirs, state, file_patterns, min_age_seconds)

    if not new_files:
        logger.info("No new files found — exiting")
        return

    logger.info(f"Found {len(new_files)} new file(s) to process")

    work_dir = config.get("archiver", "temp_dir", fallback="/tmp/wazuh-archiver")
    os.makedirs(work_dir, exist_ok=True)

    ok = fail = 0

    for path, log_dir in new_files:
        logger.info(f"Processing: {path}")

        if args.dry_run:
            logger.info("  [dry-run] skipping upload")
            continue

        rec = process_file(path, log_dir, config, work_dir, logger)

        # Write structured audit record to the audit log
        logger.info(f"AUDIT_RECORD {json.dumps(rec)}")

        if rec["status"] == "success":
            state["processed_files"].append(path)
            save_state(state_file, state)
            ok += 1
        else:
            fail += 1

    logger.info(f"Done — success={ok}  failed={fail}")

    if fail:
        sys.exit(1)


if __name__ == "__main__":
    main()
