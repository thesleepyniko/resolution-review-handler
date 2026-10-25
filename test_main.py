import hashlib
import hmac
import json
import time
import unittest
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

import main


class ShipRelayTests(unittest.TestCase):
    def setUp(self):
        self.settings = patch.multiple(
            main,
            AIRTABLE_SECRET="airtable-test-token",
            ARI_SIGNING_SECRET="ari-test-secret",
            ARI_WEBHOOK_URL="https://ari.example/api/ingest/program",
        )
        self.settings.start()
        self.addCleanup(self.settings.stop)
        self.enterContext(
            patch.object(
                httpx.HTTPTransport,
                "handle_request",
                side_effect=AssertionError("Real HTTP requests are disabled in relay tests"),
            )
        )
        self.client = TestClient(main.app, raise_server_exceptions=False)
        self.addCleanup(self.client.close)
        self.headers = {"airtable-token": "airtable-test-token"}
        self.payload = {
            "external_id": "project-17",
            "maker_email": "maker@example.com",
            "maker_name": "Zoë",
            "maker_slack_id": "U0123ABCD",
            "title": "A café timer",
            "description": "Tracks work & breaks.",
            "repo_url": "https://github.com/example/timer",
            "demo_url": "https://example.com/demo",
            "thumbnail_url": "https://example.com/thumbnail.png",
            "hackatime_projects": ["timer"],
        }

    def ari_response(self, status, body):
        return httpx.Response(
            status,
            json=body,
            request=httpx.Request("POST", main.ARI_WEBHOOK_URL),
        )

    def test_signed_submission_preserves_accepted_ship_id(self):
        upstream = self.ari_response(202, {"id": "AR-4821"})
        started = int(time.time())
        with patch.object(main.httpx, "post", return_value=upstream) as post:
            response = self.client.post(
                "/ari-ship-relay", json=self.payload, headers=self.headers
            )

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json(), {"id": "AR-4821"})
        self.assertEqual(post.call_args.args, (main.ARI_WEBHOOK_URL,))
        forwarded = post.call_args.kwargs
        self.assertEqual(forwarded["headers"]["Content-Type"], "application/json")
        timestamp = forwarded["headers"]["X-Ari-Timestamp"]
        self.assertTrue(timestamp.isascii() and timestamp.isdecimal())
        self.assertGreaterEqual(int(timestamp), started)
        self.assertLessEqual(int(timestamp), int(time.time()))
        raw = forwarded["content"]
        expected_signature = hmac.new(
            b"ari-test-secret", timestamp.encode() + b"." + raw, hashlib.sha256
        ).hexdigest()
        self.assertEqual(forwarded["headers"]["X-Ari-Signature"], expected_signature)
        self.assertEqual(
            json.loads(raw),
            {
                "external_id": "project-17",
                "maker": {
                    "email": "maker@example.com",
                    "name": "Zoë",
                    "slack_id": "U0123ABCD",
                },
                "title": "A café timer",
                "description": "Tracks work & breaks.",
                "repo_url": "https://github.com/example/timer",
                "demo_url": "https://example.com/demo",
                "thumbnail_url": "https://example.com/thumbnail.png",
                "hackatime_projects": ["timer"],
                "evidence": ["commits", "elapsed"],
            },
        )

    def test_duplicate_and_actionable_rejections_preserve_ari_response(self):
        for status, body in [
            (200, {"status": "duplicate", "id": "AR-4821"}),
            (409, {"error": "already_queued", "id": "AR-4821"}),
            (422, {"error": "invalid_payload", "field": "demo_url"}),
        ]:
            with self.subTest(status=status):
                upstream = self.ari_response(status, body)
                with patch.object(main.httpx, "post", return_value=upstream) as post:
                    response = self.client.post(
                        "/ari-ship-relay", json=self.payload, headers=self.headers
                    )
                self.assertEqual(response.status_code, status)
                self.assertEqual(response.json(), body)
                self.assertEqual(post.call_count, 1)

    def test_upstream_failures_remain_gateway_errors(self):
        failures = [
            {"return_value": self.ari_response(401, {"error": "bad_signature"})},
            {"return_value": self.ari_response(404, {"error": "unknown_program"})},
            {"return_value": self.ari_response(503, {"error": "unavailable"})},
            {"side_effect": httpx.ReadTimeout("Ari timed out")},
        ]
        for failure in failures:
            with self.subTest(failure=failure):
                with patch.object(main.httpx, "post", **failure):
                    with self.assertLogs("uvicorn.error", level="ERROR"):
                        response = self.client.post(
                            "/ari-ship-relay", json=self.payload, headers=self.headers
                        )
                self.assertEqual(response.status_code, 502)
                self.assertEqual(
                    response.json(), {"detail": "failed to forward submission to Ari"}
                )

    def test_authentication_precedes_payload_validation(self):
        for token in [None, "wrong-token"]:
            with self.subTest(token=token):
                headers = {} if token is None else {"airtable-token": token}
                with patch.object(main.httpx, "post") as post:
                    response = self.client.post(
                        "/ari-ship-relay", content=b"not-json", headers=headers
                    )
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.json(), {"detail": "Unauthorized"})
                post.assert_not_called()

    def test_hours_and_evidence_boundaries(self):
        for hours, projects, expected_status in [
            (1000, None, 202),
            (0.25, ["  ", ""], 202),
            (0, [" timer ", ""], 202),
            (1000.01, [], 422),
            (-0.01, ["timer"], 422),
            ("Infinity", [], 422),
            (None, None, 422),
            (0, ["  "], 422),
        ]:
            with self.subTest(hours=hours, projects=projects):
                payload = self.payload | {
                    "maker_program_hours": hours,
                    "hackatime_projects": projects,
                }
                upstream = self.ari_response(202, {"id": "AR-4821"})
                with patch.object(main.httpx, "post", return_value=upstream) as post:
                    response = self.client.post(
                        "/ari-ship-relay", json=payload, headers=self.headers
                    )
                self.assertEqual(response.status_code, expected_status)
                if expected_status == 422:
                    post.assert_not_called()
                else:
                    sent = json.loads(post.call_args.kwargs["content"])
                    self.assertEqual(sent["maker"]["program_hours"], hours)
                    self.assertEqual(
                        sent["hackatime_projects"], ["timer"] if projects and hours == 0 else []
                    )


if __name__ == "__main__":
    unittest.main()
