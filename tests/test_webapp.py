import unittest
import sqlite3
from pathlib import Path
from unittest.mock import patch

from webapp.app import HISTORICAL_INCIDENTS, app, create_app


class WebAppTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_workspace_renders_kusto_query_client(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Connected to TabletopSIEM", response.data)
        self.assertIn(b"/api/kql/query", response.data)
        self.assertIn(b"TestEvents", response.data)

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

class ExerciseWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.db_path = Path(__file__).parent / "test_state.db"
        self.db_path.unlink(missing_ok=True)
        self.test_app = create_app({"TESTING": True, "STATE_DB": str(self.db_path)})
        self.client = self.test_app.test_client()

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
        self.assertEqual(len(payload["incidents"]), len(HISTORICAL_INCIDENTS))
        self.assertGreaterEqual(len(payload["incidents"]), 30)
        self.assertTrue(all(item["historical"] for item in payload["incidents"]))
        relevant = {"INC-1841", "INC-1854", "INC-1868", "INC-1889", "INC-1932"}
        positions = [index for index, item in enumerate(payload["incidents"]) if item["id"] in relevant]
        self.assertGreater(max(positions) - min(positions), len(relevant) - 1)

    def test_start_then_timed_release_hides_future_alerts(self):
        response = self.client.post("/api/facilitator/exercise/start", json={})
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

        review = self.client.get("/api/facilitator/review").get_json()
        self.assertEqual(len(review["activity"]), 2)

    def test_reset_requires_confirmation_and_clears_day_state(self):
        self.client.post("/api/facilitator/exercise/start", json={})
        denied = self.client.post("/api/facilitator/exercise/reset", json={})
        self.assertEqual(denied.status_code, 400)

        reset = self.client.post("/api/facilitator/exercise/reset", json={"confirmation": "RESET"})
        self.assertEqual(reset.status_code, 200)
        self.assertEqual(reset.get_json()["status"], "not_started")

    def test_pause_and_resume_preserve_elapsed_time(self):
        self.client.post("/api/facilitator/exercise/start", json={})
        paused = self.client.post("/api/facilitator/exercise/pause", json={})
        self.assertEqual(paused.status_code, 200)
        self.assertEqual(paused.get_json()["status"], "paused")

        resumed = self.client.post("/api/facilitator/exercise/resume", json={})
        self.assertEqual(resumed.status_code, 200)
        self.assertEqual(resumed.get_json()["status"], "running")


if __name__ == "__main__":
    unittest.main()
