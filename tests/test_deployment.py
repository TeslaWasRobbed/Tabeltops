import json
import unittest

from deployment.health_check import check_health


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


if __name__ == "__main__":
    unittest.main()
