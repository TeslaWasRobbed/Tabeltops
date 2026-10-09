import json
import csv
import sqlite3
import unittest
from pathlib import Path
from unittest.mock import patch

from scenario.build_exercise_data import build_rows, load_schemas, write_build
from webapp.ingestion import sync_due, table_command


class DataBuildTests(unittest.TestCase):
    def setUp(self):
        self.output = Path(__file__).parent / "generated_fixture"

    def tearDown(self):
        if self.output.exists():
            for path in sorted(self.output.rglob("*"), reverse=True):
                if path.is_file(): path.unlink()
                elif path.is_dir(): path.rmdir()
            self.output.rmdir()

    def test_all_approved_schemas_are_loaded(self):
        schemas = load_schemas()
        self.assertEqual(len(schemas), 22)
        self.assertIn("CloudAppEvents", schemas)
        self.assertIn("CiscoASA_CL", schemas)

    def test_build_contains_history_and_timed_batches(self):
        manifest = write_build(self.output)
        self.assertGreaterEqual(sum(item["rows"] for item in manifest["batches"]), 750)
        self.assertTrue(any(item["offset_seconds"] < 0 for item in manifest["batches"]))
        self.assertTrue(any(item["offset_seconds"] == 25 * 60 for item in manifest["batches"]))
        self.assertTrue(any(item["table"] == "ThreatIntelligenceIndicator" for item in manifest["batches"]))
        self.assertTrue(all(len(item["sha256"]) == 64 for item in manifest["batches"]))

    def test_records_never_use_columns_outside_schema(self):
        schemas = load_schemas()
        rows = build_rows(schemas)
        for (_, table), items in rows.items():
            expected = [column["name"] for column in schemas[table]]
            for item in items:
                self.assertEqual(list(item), expected)

    def test_every_roster_identity_has_queryable_role_data(self):
        schemas = load_schemas()
        rows = build_rows(schemas)
        identity_rows = rows[(-1, "IdentityInfo")]
        with (Path(__file__).parents[1] / "scenario" / "SCENARIO_ROSTER.csv").open(encoding="utf-8-sig", newline="") as handle:
            roster = list(csv.DictReader(handle))

        self.assertEqual({row["AccountUPN"] for row in identity_rows}, {user["UserPrincipalName"] for user in roster})
        self.assertTrue(all(row["AssignedRoles"] != "" for row in identity_rows))
        louise = next(row for row in identity_rows if row["AccountUPN"] == "louise.lonn@creditsafe.com")
        self.assertEqual(json.loads(louise["AssignedRoles"]), ["eDiscovery Manager", "Security Reader"])

    def test_kusto_history_contains_believable_closed_incident_queue(self):
        rows = build_rows(load_schemas())
        incidents = rows[(-1, "SecurityIncident")]
        self.assertGreaterEqual(len(incidents), 30)

        relevant = {"1841", "1854", "1868", "1889", "1932"}
        chronological = sorted(incidents, key=lambda item: item["TimeGenerated"], reverse=True)
        positions = [index for index, item in enumerate(chronological) if item["IncidentNumber"] in relevant]
        self.assertEqual(len(positions), len(relevant))
        self.assertGreater(max(positions) - min(positions), len(relevant) - 1)

    def test_endpoint_history_is_timestamped_and_distributed_across_users(self):
        rows = build_rows(load_schemas())
        network = rows[(-1, "DeviceNetworkEvents")]
        processes = rows[(-1, "DeviceProcessEvents")]
        files = rows[(-1, "DeviceFileEvents")]

        self.assertGreaterEqual(len(network), 2000)
        self.assertGreaterEqual(len({row["DeviceName"] for row in network}), 100)
        self.assertGreaterEqual(len({row["DeviceName"] for row in processes}), 100)
        self.assertGreaterEqual(len({row["DeviceName"] for row in files}), 100)
        self.assertTrue(all(row["TimeGenerated"] and row["Timestamp"] for row in network + processes + files))

    def test_historical_batches_are_written_in_time_order(self):
        write_build(self.output)
        path = self.output / "historical" / "DeviceNetworkEvents.csv"
        schema = load_schemas()["DeviceNetworkEvents"]
        columns = [column["name"] for column in schema]
        time_index = columns.index("TimeGenerated")
        with path.open(encoding="utf-8", newline="") as handle:
            timestamps = [row[time_index] for row in csv.reader(handle)]
        self.assertEqual(timestamps, sorted(timestamps))


class IngestionTests(unittest.TestCase):
    def setUp(self):
        self.manifest = Path(__file__).parent / "test_manifest.json"
        self.database = Path(__file__).parent / "test_ingestion.db"
        self.manifest.write_text(json.dumps({"batches": [
            {"id": "future", "offset_seconds": 600, "table": "AuditLogs", "rows": 1, "path": "scheduled/t00600/AuditLogs.csv"},
            {"id": "due", "offset_seconds": 300, "table": "AuditLogs", "rows": 2, "path": "scheduled/t00300/AuditLogs.csv"}
        ]}), encoding="utf-8")

    def tearDown(self):
        self.manifest.unlink(missing_ok=True)
        self.database.unlink(missing_ok=True)

    @patch("webapp.ingestion.ingest_batch")
    def test_due_batches_are_ingested_exactly_once(self, ingest_batch):
        db = sqlite3.connect(self.database)
        try:
            self.assertEqual(sync_due(db, 300, self.manifest, "/kustodata/tabletop"), 2)
            self.assertEqual(sync_due(db, 300, self.manifest, "/kustodata/tabletop"), 0)
            self.assertEqual(ingest_batch.call_count, 1)
        finally:
            db.close()

    def test_table_command_preserves_schema_types(self):
        command = table_command("Example", [{"name": "Timestamp", "type": "datetime"}, {"name": "Details", "type": "dynamic"}])
        self.assertIn("Timestamp:datetime", command)
        self.assertIn("Details:dynamic", command)


if __name__ == "__main__":
    unittest.main()
