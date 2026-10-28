"""Vercel WSGI and first-run setup tests using a fake Redis REST backend."""
from __future__ import annotations
import copy
import io
import json
import os
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as panel


class VercelDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.old_is_vercel = panel.IS_VERCEL
        self.old_store_ref = panel.STORE
        self.old_store_value = copy.deepcopy(panel.STORE)
        self.old_kv = panel._kv_command
        self.old_storage_check = panel.storage_is_configured
        self.old_setup_token = os.environ.get("ALI_VPN_SETUP_TOKEN")
        os.environ["ALI_VPN_SETUP_TOKEN"] = "test-private-setup-token-long-123456"
        self.redis = {}
        panel.IS_VERCEL = True
        panel.STORE = panel.default_data()
        panel.STORE["auth"] = {}
        panel.storage_is_configured = lambda: True

        def fake_kv(command):
            name = command[0].upper()
            if name == "GET":
                return self.redis.get(str(command[1]))
            if name == "SET":
                key = str(command[1])
                options = [str(item).upper() for item in command[3:]]
                if "NX" in options and key in self.redis:
                    return None
                self.redis[key] = str(command[2])
                return "OK"
            if name == "DEL":
                existed = str(command[1]) in self.redis
                self.redis.pop(str(command[1]), None)
                return 1 if existed else 0
            if name == "INCR":
                key = str(command[1])
                self.redis[key] = str(int(self.redis.get(key, "0")) + 1)
                return int(self.redis[key])
            if name == "EXPIRE":
                return 1 if str(command[1]) in self.redis else 0
            return None

        panel._kv_command = fake_kv

    def tearDown(self):
        self.old_store_ref.clear()
        self.old_store_ref.update(self.old_store_value)
        panel.STORE = self.old_store_ref
        panel.IS_VERCEL = self.old_is_vercel
        panel._kv_command = self.old_kv
        panel.storage_is_configured = self.old_storage_check
        if self.old_setup_token is None:
            os.environ.pop("ALI_VPN_SETUP_TOKEN", None)
        else:
            os.environ["ALI_VPN_SETUP_TOKEN"] = self.old_setup_token

    def request(self, path="/", method="GET", body=None, cookie=None, origin=None):
        raw = json.dumps(body).encode("utf-8") if body is not None else b""
        env = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "QUERY_STRING": "",
            "CONTENT_LENGTH": str(len(raw)),
            "CONTENT_TYPE": "application/json",
            "wsgi.input": io.BytesIO(raw),
            "wsgi.url_scheme": "https",
            "SERVER_NAME": "panel-test.vercel.app",
            "SERVER_PORT": "443",
            "HTTP_HOST": "panel-test.vercel.app",
            "REMOTE_ADDR": "127.0.0.1",
        }
        if cookie:
            env["HTTP_COOKIE"] = cookie
        if origin:
            env["HTTP_ORIGIN"] = origin
        captured = {}

        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = headers

        body_bytes = b"".join(panel.app(env, start_response))
        return captured, body_bytes

    def test_wsgi_root_and_auth_check_are_served(self):
        response, body = self.request("/")
        self.assertEqual(response["status"], "200 OK")
        self.assertIn(b'id="setupForm"', body)
        response, body = self.request("/api/auth/check")
        value = json.loads(body)
        self.assertEqual(response["status"], "200 OK")
        self.assertTrue(value["setup_required"])
        self.assertTrue(value["storage_configured"])

    def test_first_run_sets_password_and_persists_secure_session(self):
        response, body = self.request("/api/setup", "POST", {
            "password": "example-test-password-long",
            "confirm_password": "example-test-password-long",
            "setup_token": "test-private-setup-token-long-123456",
        }, origin="https://panel-test.vercel.app")
        value = json.loads(body)
        self.assertEqual(response["status"], "200 OK", value)
        self.assertTrue(value["ok"])
        cookie = next(v for k, v in response["headers"] if k.lower() == "set-cookie")
        self.assertIn("Secure", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        cookie_pair = cookie.split(";", 1)[0]
        response, body = self.request("/api/auth/check", cookie=cookie_pair)
        self.assertEqual(response["status"], "200 OK")
        self.assertTrue(json.loads(body)["authenticated"])
        state = json.loads(self.redis[f"{panel.KV_KEY_PREFIX}:state"])
        self.assertEqual(state["apis"]["direct"]["api_key"], "")
        self.assertEqual(state["apis"]["tunnel"]["api_key"], "")
        self.assertEqual(state["owners"], {"direct": {}, "tunnel": {}})
        self.assertEqual(state["logs"], [])

    def test_setup_rejects_short_or_mismatched_passwords(self):
        response, body = self.request("/api/setup", "POST", {
            "password": "short",
            "confirm_password": "different",
            "setup_token": "test-private-setup-token-long-123456",
        }, origin="https://panel-test.vercel.app")
        self.assertEqual(response["status"], "400 Bad Request")
        self.assertFalse(json.loads(body)["ok"])
        self.assertEqual(panel.STORE["auth"], {})

    def test_invalid_setup_token_is_rejected(self):
        response, body = self.request("/api/setup", "POST", {
            "password": "example-test-password-long",
            "confirm_password": "example-test-password-long",
            "setup_token": "wrong-token",
        }, origin="https://panel-test.vercel.app")
        self.assertEqual(response["status"], "403 Forbidden")
        self.assertFalse(json.loads(body)["ok"])
        self.assertEqual(panel.STORE["auth"], {})
        self.assertTrue(panel._remote_login_blocked("127.0.0.1") is False)

    def test_auth_check_disables_setup_without_server_token(self):
        os.environ.pop("ALI_VPN_SETUP_TOKEN", None)
        response, body = self.request("/api/auth/check")
        value = json.loads(body)
        self.assertEqual(response["status"], "200 OK")
        self.assertTrue(value["setup_required"])
        self.assertFalse(value["setup_allowed"])
        self.assertIn("ALI_VPN_SETUP_TOKEN", value["setup_message"])

    def test_missing_storage_blocks_setup_with_actionable_message(self):
        panel.storage_is_configured = lambda: False
        response, body = self.request("/api/auth/check")
        value = json.loads(body)
        self.assertEqual(response["status"], "200 OK")
        self.assertFalse(value["storage_configured"])
        self.assertIn("Upstash Redis", value["setup_message"])

    def test_warm_instance_refreshes_auth_from_shared_kv(self):
        # Seed the shared record as if another serverless instance completed setup.
        data = panel.default_data()
        salt, digest = panel.hash_password("valid-test-password-123")
        data["auth"] = {"salt": salt, "hash": digest, "updated_at": "2026-10-28T00:00:00+00:00"}
        self.redis[panel._state_key()] = json.dumps(data)
        panel.STORE = panel.default_data()
        panel.STORE["auth"] = {}
        response, body = self.request("/api/auth/check")
        value = json.loads(body)
        self.assertEqual(response["status"], "200 OK")
        self.assertFalse(value["setup_required"])

    def test_setup_lock_prevents_a_second_concurrent_first_run(self):
        self.redis[f"{panel.KV_KEY_PREFIX}:setup-lock"] = "another-instance"
        response, body = self.request("/api/setup", "POST", {
            "password": "example-test-password-long",
            "confirm_password": "example-test-password-long",
            "setup_token": "test-private-setup-token-long-123456",
        }, origin="https://panel-test.vercel.app")
        self.assertEqual(response["status"], "409 Conflict")
        self.assertFalse(json.loads(body)["ok"])
        self.assertEqual(panel.STORE["auth"], {})

    def test_login_rate_limit_is_shared_through_kv(self):
        ip = "203.0.113.42"
        for _ in range(8):
            panel._remote_record_failed_login(ip)
        self.assertTrue(panel._remote_login_blocked(ip))
        panel._remote_clear_failed_logins(ip)
        self.assertFalse(panel._remote_login_blocked(ip))


if __name__ == "__main__":
    unittest.main()
