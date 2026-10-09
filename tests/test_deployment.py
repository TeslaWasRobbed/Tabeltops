import json
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from deployment.backup_state import create_backup, sqlite_integrity
from deployment.health_check import check_health
from deployment.restore_state import restore_state
from deployment.smoke_test import load_env_file


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


class HealthCheckTests(unittest.TestCase):
    def test_healthy_application_passes(self):
        payload = {"application": "ok", "kusto": "connected", "database": "TabletopSIEM", "scenario_available": True}
        result = check_health(opener=lambda request, timeout: FakeResponse(payload))
        self.assertEqual(result["database"], "TabletopSIEM")

    def test_disconnected_kusto_fails(self):
        payload = {"application": "ok", "kusto": "unavailable", "scenario_available": True}
        with self.assertRaisesRegex(RuntimeError, "Kusto is not connected"):
            check_health(opener=lambda request, timeout: FakeResponse(payload))


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).parent / "backup_fixture"
        self.backups = self.root / "backups"
        self.root.mkdir(exist_ok=True); self.backups.mkdir(exist_ok=True)
        self.source = self.root / "state.db"
        db = sqlite3.connect(self.source)
        db.execute("CREATE TABLE exercise_state(value TEXT)")
        db.execute("INSERT INTO exercise_state VALUES('clean')")
        db.commit(); db.close()

    def tearDown(self):
        for path in self.backups.glob("*.db"):
            path.unlink()
        for path in self.root.glob("*.db"):
            path.unlink()
        self.backups.rmdir(); self.root.rmdir()

    def test_backup_retention_and_restore_with_rollback(self):
        start = datetime(2026, 10, 9, 10, 0, tzinfo=timezone.utc)
        snapshots = [create_backup(self.source, self.backups, now=start + timedelta(minutes=15 * index), retain=2) for index in range(3)]
        self.assertFalse(snapshots[0].exists())
        self.assertEqual(len(list(self.backups.glob("tabletop-state-*.db"))), 2)
        self.assertEqual(sqlite_integrity(snapshots[-1]), "ok")

        db = sqlite3.connect(self.source)
        db.execute("UPDATE exercise_state SET value='changed'")
        db.commit(); db.close()
        rollback = restore_state(snapshots[-1], self.source, self.backups, now=start + timedelta(hours=1))
        restored = sqlite3.connect(self.source)
        self.assertEqual(restored.execute("SELECT value FROM exercise_state").fetchone()[0], "clean")
        restored.close()
        self.assertIsNotNone(rollback)
        self.assertEqual(sqlite_integrity(rollback), "ok")


class SmokeTestTests(unittest.TestCase):
    def test_environment_file_parser_ignores_comments_and_quotes_values(self):
        path = Path(__file__).parent / "smoke.env"
        path.write_text("# comment\nTABLETOP_ALPHA_CODE='alpha secret'\nTABLETOP_BRAVO_CODE=bravo-secret\n", encoding="utf-8")
        try:
            values = load_env_file(path)
            self.assertEqual(values["TABLETOP_ALPHA_CODE"], "alpha secret")
            self.assertEqual(values["TABLETOP_BRAVO_CODE"], "bravo-secret")
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
