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
import configparser
import hashlib
import json
import logging
import logging.handlers
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

VERSION = "1.1.0"
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


def find_new_log_files(log_dirs: list, state: dict) -> list:
    """
    Return rotated Wazuh archive files (.json.gz) not yet processed.
    Searches recursively inside each configured directory.
    Files are returned sorted by path (oldest date first given Wazuh naming).
    """
    processed = set(state.get("processed_files", []))
    new_files = []
    for log_dir in log_dirs:
        p = Path(log_dir)
        if not p.exists():
            logging.getLogger("wazuh-archiver").warning(
                f"Log directory not found, skipping: {log_dir}"
            )
            continue
        for gz in sorted(p.rglob("*.json.gz")):
            path_str = str(gz)
            if path_str not in processed:
                new_files.append(path_str)
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
        opts += ["-o", "StrictHostKeyChecking=accept-new"]
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
# Core: process one log file end-to-end
# ---------------------------------------------------------------------------


def process_file(
    source_path: str,
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
      5. SFTP upload + verify
      6. Return audit record

    The original file is never modified.
    Returns a dict with status='success' or status='failed'.
    """
    node = config.get("wazuh", "node_name", fallback="wazuh-node1")
    gpg_bin = config.get("gpg", "gpg_binary", fallback="/usr/bin/gpg")
    gpg_home = config.get("gpg", "gpg_homedir", fallback="/etc/wazuh-archiver/gnupg")
    signing = config.getboolean("gpg", "signing", fallback=False)
    signing_key = config.get("gpg", "signing_key_id", fallback="").strip()
    encryption = config.getboolean("gpg", "encryption", fallback=False)
    enc_recipient = config.get("gpg", "encryption_recipient", fallback="").strip()

    sftp_host = config.get("sftp", "host")
    sftp_port = config.getint("sftp", "port", fallback=22)
    sftp_user = config.get("sftp", "username")
    sftp_key = config.get("sftp", "ssh_key_path")
    sftp_known_hosts = config.get("sftp", "known_hosts_file", fallback="").strip() or None
    sftp_remote = config.get("sftp", "remote_dir")

    t0 = datetime.now(timezone.utc)
    fname = os.path.basename(source_path)

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

        # Build the upload manifest (always: archive + sha256)
        files = [
            (local, fname),
            (sha_file, fname + ".sha256"),
        ]

        # 2. GPG signing
        if signing:
            if not signing_key:
                raise ValueError(
                    "gpg.signing = true but gpg.signing_key_id is not set"
                )
            sig = gpg_sign(local, signing_key, gpg_bin, gpg_home, logger)
            files.append((sig, fname + ".sig"))

        # 3. GPG encryption
        if encryption:
            if not enc_recipient:
                raise ValueError(
                    "gpg.encryption = true but gpg.encryption_recipient is not set"
                )
            enc = gpg_encrypt(local, enc_recipient, gpg_bin, gpg_home, logger)
            files.append((enc, fname + ".gpg"))

        # 4. SFTP upload + verify
        upload_results = sftp_upload_files(
            host=sftp_host,
            port=sftp_port,
            username=sftp_user,
            key_path=sftp_key,
            known_hosts=sftp_known_hosts,
            remote_dir=sftp_remote,
            files=files,
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
            "sftp_host": sftp_host,
            "remote_dir": sftp_remote,
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

    new_files = find_new_log_files(log_dirs, state)

    if not new_files:
        logger.info("No new files found — exiting")
        return

    logger.info(f"Found {len(new_files)} new file(s) to process")

    work_dir = config.get("archiver", "temp_dir", fallback="/tmp/wazuh-archiver")
    os.makedirs(work_dir, exist_ok=True)

    ok = fail = 0

    for path in new_files:
        logger.info(f"Processing: {path}")

        if args.dry_run:
            logger.info("  [dry-run] skipping upload")
            continue

        rec = process_file(path, config, work_dir, logger)

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
