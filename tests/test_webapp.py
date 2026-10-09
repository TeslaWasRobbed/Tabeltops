import unittest
import io
import json
import sqlite3
import zipfile
from pathlib import Path
from unittest.mock import patch

from webapp.app import HISTORICAL_INCIDENTS, app, create_app


class WebAppTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.client.post("/login", data={"role": "alpha", "code": "alpha-training"})

    def test_workspace_renders_kusto_query_client(self):
        response = self.client.get("/alpha")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Connected to TabletopSIEM", response.data)
        self.assertIn(b"/api/kql/query", response.data)
        self.assertIn(b"TestEvents", response.data)
        self.assertIn(b"Investigation context", response.data)
        self.assertIn(b"Related FreshService records", response.data)
        self.assertNotIn(b"Next alert", response.data)
        self.assertNotIn(b'id="next-alert"', response.data)

    def test_access_codes_protect_workspaces_and_apis(self):
        anonymous = app.test_client()
        self.assertEqual(anonymous.get("/").status_code, 200)
        self.assertEqual(anonymous.get("/alpha").status_code, 200)
        self.assertEqual(anonymous.post("/api/kql/query", json={"query": "IdentityInfo | take 1"}).status_code, 403)
        self.assertEqual(anonymous.post("/login", data={"role": "facilitator", "code": "wrong"}).status_code, 401)

        facilitator = app.test_client()
        facilitator.post("/login", data={"role": "facilitator", "code": "facilitator-training"})
        self.assertEqual(facilitator.get("/facilitator").status_code, 200)
        self.assertEqual(facilitator.get("/api/incidents").status_code, 403)

    @patch("webapp.app.call_kusto")
    def test_query_results_are_normalized(self, call_kusto):
        call_kusto.return_value = {
            "Tables": [
                {
                    "Columns": [
                        {"ColumnName": "Timestamp"},
                        {"ColumnName": "ActionType"},
                        {"ColumnName": "Context"},
                    ],
                    "Rows": [
                        [
                            "2026-05-28T09:00:05Z",
                            "ProcessCreated",
                            {"source": "test"},
                        ]
                    ],
                }
            ]
        }

        response = self.client.post(
            "/api/kql/query", json={"query": "TestEvents | take 1"}
        )
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["columns"], ["Timestamp", "ActionType", "Context"])
        self.assertEqual(payload["row_count"], 1)
        self.assertEqual(payload["rows"][0]["Context"], {"source": "test"})

    def test_empty_query_is_rejected(self):
        response = self.client.post("/api/kql/query", json={"query": ""})
        self.assertEqual(response.status_code, 400)

    def test_management_command_is_rejected(self):
        response = self.client.post(
            "/api/kql/query", json={"query": ".show tables"}
        )
        self.assertEqual(response.status_code, 400)

    def test_freshservice_records_are_searchable_read_only_evidence(self):
        response = self.client.get("/api/freshservice/records")
        payload = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(payload["records"]), 14)
        self.assertIn("INC-48217", {item["id"] for item in payload["records"]})
        self.assertIn("CHG-76822", {item["id"] for item in payload["records"]})

        detail = self.client.get("/api/freshservice/records/INC-48217").get_json()["record"]
        self.assertEqual(detail["assigned_to"], "Anita Job")
        self.assertEqual(detail["related_records"], ["SR-48226", "Sentinel INC-1841"])
        self.assertTrue(any(entry["kind"] == "Resolution" for entry in detail["timeline"]))
        self.assertEqual(self.client.patch("/api/freshservice/records/INC-48217", json={}).status_code, 405)

class ExerciseWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.db_path = Path(__file__).parent / "test_state.db"
        self.db_path.unlink(missing_ok=True)
        self.test_app = create_app({
            "TESTING": True,
            "STATE_DB": str(self.db_path),
            "SECRET_KEY": "test-secret",
            "ACCESS_CODES": {"alpha": "alpha-code", "bravo": "bravo-code", "facilitator": "fac-code"},
        })
        self.client = self.test_app.test_client()
        self.bravo = self.test_app.test_client()
        self.facilitator = self.test_app.test_client()
        self.client.post("/login", data={"role": "alpha", "code": "alpha-code"})
        self.bravo.post("/login", data={"role": "bravo", "code": "bravo-code"})
        self.facilitator.post("/login", data={"role": "facilitator", "code": "fac-code"})

    def tearDown(self):
        self.db_path.unlink(missing_ok=True)

    def fast_forward(self, seconds):
        db = sqlite3.connect(self.db_path)
        try:
            db.execute(
                "UPDATE exercise_state SET status='paused', started_at=NULL, accumulated_seconds=? WHERE singleton=1",
                (seconds,),
            )
            db.commit()
        finally:
            db.close()

    def test_historical_incidents_are_available_before_start(self):
        payload = self.client.get("/api/incidents").get_json()

        self.assertEqual(payload["exercise"]["status"], "not_started")
        self.assertNotIn("next_alert_in_seconds", payload["exercise"])
        self.assertEqual(len(payload["incidents"]), len(HISTORICAL_INCIDENTS))
        self.assertGreaterEqual(len(payload["incidents"]), 30)
        self.assertTrue(all(item["historical"] for item in payload["incidents"]))
        relevant = {"INC-1841", "INC-1854", "INC-1868", "INC-1889", "INC-1932"}
        positions = [index for index, item in enumerate(payload["incidents"]) if item["id"] in relevant]
        self.assertGreater(max(positions) - min(positions), len(relevant) - 1)

    def test_start_then_timed_release_hides_future_alerts(self):
        response = self.facilitator.post("/api/facilitator/exercise/start", json={})
        self.assertEqual(response.status_code, 200)

        self.fast_forward(5 * 60)
        payload = self.client.get("/api/incidents").get_json()
        day_alerts = [item for item in payload["incidents"] if not item["historical"]]

        self.assertEqual([item["id"] for item in day_alerts], ["INC-2001"])
        self.assertEqual(payload["exercise"]["released_alerts"], 1)

    def test_incident_requires_active_before_closed_and_saves_notes(self):
        self.fast_forward(5 * 60)

        premature = self.client.patch(
            "/api/incidents/INC-2001",
            json={"status": "Closed", "classification": "Undetermined", "closure_notes": "Needs review"},
        )
        self.assertEqual(premature.status_code, 400)

        active = self.client.patch(
            "/api/incidents/INC-2001",
            json={"status": "Active", "actor": "Alpha Team", "owner": "Alpha Team"},
        )
        self.assertEqual(active.status_code, 200)

        missing_notes = self.client.patch(
            "/api/incidents/INC-2001",
            json={"status": "Closed", "classification": "Undetermined"},
        )
        self.assertEqual(missing_notes.status_code, 400)

        closed = self.client.patch(
            "/api/incidents/INC-2001",
            json={"status": "Closed", "classification": "Undetermined", "closure_notes": "Evidence remains inconclusive."},
        )
        self.assertEqual(closed.status_code, 200)
        self.assertEqual(closed.get_json()["incident"]["closure_notes"], "Evidence remains inconclusive.")

        review = self.facilitator.get("/api/facilitator/review").get_json()
        self.assertEqual(len(review["activity"]), 2)

    def test_reset_requires_confirmation_and_clears_day_state(self):
        self.facilitator.post("/api/facilitator/exercise/start", json={})
        denied = self.facilitator.post("/api/facilitator/exercise/reset", json={})
        self.assertEqual(denied.status_code, 400)

        reset = self.facilitator.post("/api/facilitator/exercise/reset", json={"confirmation": "RESET"})
        self.assertEqual(reset.status_code, 200)
        self.assertEqual(reset.get_json()["status"], "not_started")

    def test_pause_and_resume_preserve_elapsed_time(self):
        self.facilitator.post("/api/facilitator/exercise/start", json={})
        paused = self.facilitator.post("/api/facilitator/exercise/pause", json={})
        self.assertEqual(paused.status_code, 200)
        self.assertEqual(paused.get_json()["status"], "paused")

        resumed = self.facilitator.post("/api/facilitator/exercise/resume", json={})
        self.assertEqual(resumed.status_code, 200)
        self.assertEqual(resumed.get_json()["status"], "running")

    def test_team_state_is_isolated_and_facilitator_controls_are_protected(self):
        denied = self.client.post("/api/facilitator/exercise/start", json={})
        self.assertEqual(denied.status_code, 403)

        self.facilitator.post("/api/facilitator/exercise/start", json={})
        self.fast_forward(5 * 60)
        changed = self.client.patch(
            "/api/incidents/INC-2001",
            json={"status": "Active", "actor": "Team Alpha", "owner": "Team Alpha"},
        )
        self.assertEqual(changed.status_code, 200)

        bravo_incidents = self.bravo.get("/api/incidents").get_json()["incidents"]
        bravo_alert = next(item for item in bravo_incidents if item["id"] == "INC-2001")
        self.assertEqual(bravo_alert["status"], "New")

        review = self.facilitator.get("/api/facilitator/review").get_json()
        alpha_alert = next(item for item in review["teams"]["alpha"]["incidents"] if item["id"] == "INC-2001")
        bravo_alert = next(item for item in review["teams"]["bravo"]["incidents"] if item["id"] == "INC-2001")
        self.assertEqual(alpha_alert["status"], "Active")
        self.assertEqual(bravo_alert["status"], "New")

    def test_bookmarks_are_team_isolated_exported_and_cleared_by_reset(self):
        self.fast_forward(5 * 60)
        created = self.client.post("/api/bookmarks", json={
            "title": "MFA removal matches Service Desk request",
            "notes": "The target and timestamp correlate with the approved lost-phone ticket.",
            "query": "AuditLogs | where OperationName contains 'authentication phone'",
            "incident_id": "INC-2001",
            "evidence": {"row_count": 1, "columns": ["OperationName"], "rows": [{"OperationName": "Delete user authentication phone method"}]},
        })
        self.assertEqual(created.status_code, 201)
        self.assertEqual(len(self.client.get("/api/bookmarks").get_json()["bookmarks"]), 1)
        self.assertEqual(self.bravo.get("/api/bookmarks").get_json()["bookmarks"], [])

        exported = self.facilitator.get("/api/facilitator/export")
        self.assertEqual(exported.status_code, 200)
        self.assertEqual(exported.mimetype, "application/zip")
        with zipfile.ZipFile(io.BytesIO(exported.data)) as archive:
            self.assertEqual(set(archive.namelist()), {"Team_Alpha_Report.html", "Team_Bravo_Report.html", "Facilitator_Observations.html", "Incident_Decisions.csv", "Raw_Exercise_Data.json"})
            alpha_report = archive.read("Team_Alpha_Report.html").decode("utf-8")
            self.assertIn("MFA removal matches Service Desk request", alpha_report)
            self.assertIn("INC-2001", alpha_report)

        self.facilitator.post("/api/facilitator/exercise/reset", json={"confirmation": "RESET"})
        self.assertEqual(self.client.get("/api/bookmarks").get_json()["bookmarks"], [])
        self.assertEqual(self.facilitator.get("/api/facilitator/review").get_json()["activity"], [])

    def test_journal_is_team_isolated_exported_and_cleared_by_reset(self):
        self.fast_forward(5 * 60)
        invalid = self.client.post("/api/journal", json={"category": "Answer", "content": "Unsupported category"})
        self.assertEqual(invalid.status_code, 400)

        created = self.client.post("/api/journal", json={
            "category": "Hypothesis",
            "content": "The MFA change may be connected to an approved support request.",
            "incident_id": "INC-2001",
        })
        self.assertEqual(created.status_code, 201)
        entries = self.client.get("/api/journal").get_json()["entries"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["category"], "Hypothesis")
        self.assertEqual(self.bravo.get("/api/journal").get_json()["entries"], [])

        exported = self.facilitator.get("/api/facilitator/export")
        with zipfile.ZipFile(io.BytesIO(exported.data)) as archive:
            alpha_report = archive.read("Team_Alpha_Report.html").decode("utf-8")
            bravo_report = archive.read("Team_Bravo_Report.html").decode("utf-8")
            raw = json.loads(archive.read("Raw_Exercise_Data.json"))
            self.assertIn("Investigation journal", alpha_report)
            self.assertIn("The MFA change may be connected", alpha_report)
            self.assertNotIn("The MFA change may be connected", bravo_report)
            self.assertEqual(len(raw["teams"]["alpha"]["journal"]), 1)
            self.assertEqual(raw["teams"]["bravo"]["journal"], [])

        self.facilitator.post("/api/facilitator/exercise/reset", json={"confirmation": "RESET"})
        self.assertEqual(self.client.get("/api/journal").get_json()["entries"], [])
        self.assertEqual(self.facilitator.get("/api/facilitator/review").get_json()["activity"], [])

    def test_facilitator_observations_are_private_exported_and_cleared_by_reset(self):
        self.fast_forward(5 * 60)
        denied = self.client.post("/api/facilitator/observations", json={
            "category": "Observation", "content": "Participants must not create this note."
        })
        self.assertEqual(denied.status_code, 403)

        created = self.facilitator.post("/api/facilitator/observations", json={
            "category": "Coaching point",
            "team_id": "alpha",
            "incident_id": "INC-2001",
            "content": "Team prioritised the alert before assigning an incident owner.",
        })
        self.assertEqual(created.status_code, 201)
        review = self.facilitator.get("/api/facilitator/review").get_json()
        self.assertEqual(len(review["observations"]), 1)
        self.assertEqual(review["observations"][0]["team_id"], "alpha")
        self.assertEqual(self.client.get("/api/facilitator/review").status_code, 403)

        exported = self.facilitator.get("/api/facilitator/export")
        with zipfile.ZipFile(io.BytesIO(exported.data)) as archive:
            observations = archive.read("Facilitator_Observations.html").decode("utf-8")
            raw = json.loads(archive.read("Raw_Exercise_Data.json"))
            self.assertIn("Team prioritised the alert", observations)
            self.assertEqual(len(raw["facilitator_observations"]), 1)

        self.facilitator.post("/api/facilitator/exercise/reset", json={"confirmation": "RESET"})
        self.assertEqual(self.facilitator.get("/api/facilitator/review").get_json()["observations"], [])

    @patch("webapp.app.call_kusto")
    def test_query_and_freshservice_steps_are_visible_to_facilitator(self, call_kusto):
        call_kusto.return_value = {"Tables": [{"Columns": [{"ColumnName": "AccountUPN"}], "Rows": [["louise.lonn@creditsafe.com"]]}]}
        self.client.post("/api/kql/query", json={"query": "IdentityInfo | take 1"})
        self.client.get("/api/freshservice/records/INC-48217")

        actions = [item["action"] for item in self.facilitator.get("/api/facilitator/review").get_json()["activity"]]
        self.assertIn("KQL query", actions)
        self.assertIn("FreshService record opened", actions)


if __name__ == "__main__":
    unittest.main()
