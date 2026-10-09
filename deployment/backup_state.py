#!/usr/bin/env python3
"""Create an integrity-checked online backup of the tabletop SQLite state."""

from __future__ import annotations

import argparse
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_STATE_DB = Path(__file__).resolve().parents[1] / "webapp" / "data" / "tabletop.db"
DEFAULT_BACKUP_DIR = Path("/home/ubuntu/tabletop-backups")


def sqlite_integrity(path: Path) -> str:
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        return str(connection.execute("PRAGMA integrity_check").fetchone()[0])
    finally:
        connection.close()


def create_backup(source: Path, backup_dir: Path, *, now=None, retain: int = 96) -> Path:
    source = source.resolve(); backup_dir = backup_dir.resolve()
    if not source.is_file():
        raise FileNotFoundError(f"State database does not exist: {source}")
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    destination = backup_dir / f"tabletop-state-{timestamp}.db"
    if destination.exists():
        raise FileExistsError(f"Backup already exists: {destination}")

    source_db = sqlite3.connect(f"file:{source.as_posix()}?mode=ro", uri=True)
    destination_db = sqlite3.connect(destination)
    try:
        source_db.backup(destination_db)
    finally:
        destination_db.close(); source_db.close()
    destination.chmod(0o600)
    integrity = sqlite_integrity(destination)
    if integrity != "ok":
        destination.unlink(missing_ok=True)
        raise RuntimeError(f"Backup integrity check failed: {integrity}")

    automatic = sorted(backup_dir.glob("tabletop-state-*.db"), key=lambda item: item.stat().st_mtime, reverse=True)
    for expired in automatic[max(1, retain):]:
        expired.unlink()
    return destination


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(os.getenv("TABLETOP_STATE_DB", DEFAULT_STATE_DB)))
    parser.add_argument("--backup-dir", type=Path, default=Path(os.getenv("TABLETOP_BACKUP_DIR", DEFAULT_BACKUP_DIR)))
    parser.add_argument("--retain", type=int, default=int(os.getenv("TABLETOP_BACKUP_RETAIN", "96")))
    args = parser.parse_args(argv)
    destination = create_backup(args.source, args.backup_dir, retain=args.retain)
    print(f"Backup created and verified: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
