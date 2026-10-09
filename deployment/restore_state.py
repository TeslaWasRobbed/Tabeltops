#!/usr/bin/env python3
"""Safely restore a tabletop SQLite backup after the application is stopped."""

from __future__ import annotations

import argparse
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

try:
    from deployment.backup_state import DEFAULT_BACKUP_DIR, DEFAULT_STATE_DB, sqlite_integrity
except ModuleNotFoundError:  # Allow direct execution as deployment/restore_state.py.
    from backup_state import DEFAULT_BACKUP_DIR, DEFAULT_STATE_DB, sqlite_integrity


def copy_database(source: Path, destination: Path) -> None:
    source_db = sqlite3.connect(f"file:{source.as_posix()}?mode=ro", uri=True)
    destination_db = sqlite3.connect(destination)
    try:
        source_db.backup(destination_db)
    finally:
        destination_db.close(); source_db.close()


def restore_state(backup: Path, target: Path, backup_dir: Path, *, now=None) -> Path | None:
    backup = backup.resolve(); target = target.resolve(); backup_dir = backup_dir.resolve()
    if not backup.is_file():
        raise FileNotFoundError(f"Backup does not exist: {backup}")
    if sqlite_integrity(backup) != "ok":
        raise RuntimeError("Selected backup failed its integrity check.")
    sidecars = [Path(str(target) + suffix) for suffix in ("-wal", "-shm", "-journal")]
    if any(path.exists() for path in sidecars):
        raise RuntimeError("SQLite sidecar files are present. Stop tabletop-siem cleanly before restoring.")

    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    rollback = None
    if target.is_file():
        rollback = backup_dir / f"tabletop-pre-restore-{timestamp}.db"
        copy_database(target, rollback)
        rollback.chmod(0o600)
        if sqlite_integrity(rollback) != "ok":
            rollback.unlink(missing_ok=True)
            raise RuntimeError("Could not create a valid pre-restore rollback backup.")

    temporary = target.with_name(f".{target.name}.restore-{timestamp}.tmp")
    temporary.unlink(missing_ok=True)
    try:
        copy_database(backup, temporary)
        temporary.chmod(0o600)
        if sqlite_integrity(temporary) != "ok":
            raise RuntimeError("Restored temporary database failed its integrity check.")
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    return rollback


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backup", type=Path)
    parser.add_argument("--target", type=Path, default=Path(os.getenv("TABLETOP_STATE_DB", DEFAULT_STATE_DB)))
    parser.add_argument("--backup-dir", type=Path, default=Path(os.getenv("TABLETOP_BACKUP_DIR", DEFAULT_BACKUP_DIR)))
    args = parser.parse_args(argv)
    rollback = restore_state(args.backup, args.target, args.backup_dir)
    print(f"State restored and verified from: {args.backup.resolve()}")
    if rollback:
        print(f"Pre-restore rollback backup: {rollback}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
