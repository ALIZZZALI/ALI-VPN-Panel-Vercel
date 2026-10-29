"""Focused regression tests for findings from the deep review.
All API responses are mocked; no real service is created, changed, or deleted.
"""
from __future__ import annotations
import copy
import importlib
import json
import sys
import tempfile
import urllib.request
from pathlib import Path
from unittest.mock import patch
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
panel = importlib.import_module("app")
REAL_API_REQUEST = panel.api_request


class FakeResponse:
    status = 200
    def __init__(self, value):
        self.raw = json.dumps(value).encode("utf-8")
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self): return self.raw


class FakeOpener:
    def __init__(self, value): self.value = value
    def open(self, req, timeout=60): return FakeResponse(self.value)


class ReviewRegressionTests(unittest.TestCase):
    def test_aliases_are_canonicalized_before_route_allowlist(self):
        self.assertEqual(panel.canonical_method("change-link"), "change_link")
        self.assertEqual(panel.canonical_method("changeLink"), "change_link")
        self.assertEqual(panel.canonical_method("set-status"), "reverse_mode")
        self.assertEqual(panel.canonical_method("addVolume"), "upg_size")

    def test_empty_legacy_list_does_not_hide_nonempty_services(self):
        rows, total = panel.service_list_from({"ok": True, "result": {
            "list": [], "services": [{"username": "ABC123456", "status": "active"}], "total": 1
        }})
        self.assertEqual([r["username"] for r in rows], ["ABC123456"])
        self.assertEqual(total, 1)

    def test_lowercase_username_still_finds_saved_owner(self):
        with panel.LOCK:
            previous = copy.deepcopy(panel.STORE.get("owners", {}))
            panel.STORE.setdefault("owners", {}).setdefault("direct", {})["ABC123456"] = "Owner Regression"
        try:
            self.assertEqual(panel.owner_for("direct", "abc123456"), "Owner Regression")
            rows = panel.attach_owners("direct", [{"username": "abc123456"}])
            self.assertEqual(rows[0]["owner"], "Owner Regression")
        finally:
            with panel.LOCK:
                panel.STORE["owners"] = previous

    def test_filter_search_fetches_later_pages_not_only_first_page(self):
        records = [{"username": f"USR{i:06d}", "status": "active", "gig": 20} for i in range(500)]
        records.append({"username": "TARGET123", "status": "active", "gig": 20})
        calls = []
        def fake(mode, method, params=None, http_method=None, *, record=True, **kwargs):
            self.assertEqual(method, "clients")
            params = params or {}
            calls.append(dict(params))
            offset = int(params.get("offset", 0))
            limit = int(params.get("limit", len(records)))
            page = records[offset:offset + limit]
            return {"ok": True, "error": "", "http_code": 200,
                    "result": {"list": page, "count": len(page), "total": len(records)}}
        with patch.object(panel, "api_request", side_effect=fake):
            result = panel.get_clients("direct", limit=25, offset=0, search="TARGET123")
        self.assertTrue(result["ok"], result)
        self.assertEqual([x["username"] for x in result["items"]], ["TARGET123"])
        self.assertEqual(result["total"], 1)
        self.assertIn({"limit": 500, "offset": 500}, calls)

    def test_old_api_empty_fallback_returns_empty_success(self):
        responses = [
            {"ok": False, "error": "limit parameter not supported", "http_code": 403, "result": []},
            {"ok": False, "error": "no service", "http_code": 404, "result": []},
        ]
        def fake(*args, **kwargs): return responses.pop(0)
        with patch.object(panel, "api_request", side_effect=fake):
            result = panel.get_clients("direct", limit=25, search="something")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["items"], [])
        self.assertEqual(result["total"], 0)

    def test_add_log_storage_failure_is_best_effort(self):
        with panel.LOCK:
            previous_logs = copy.deepcopy(panel.STORE.get("logs", []))
        try:
            with patch.object(panel, "_write_store", side_effect=OSError("disk full")):
                saved = panel.add_log({"mode": "direct", "method": "test", "ok": True})
            self.assertFalse(saved)
            with panel.LOCK:
                self.assertEqual(panel.STORE.get("logs", []), previous_logs)
        finally:
            with panel.LOCK:
                panel.STORE["logs"] = previous_logs

    def test_successful_api_response_survives_history_write_failure(self):
        with panel.LOCK:
            old_key = panel.STORE["apis"]["direct"].get("api_key", "")
            panel.STORE["apis"]["direct"]["api_key"] = "test-key"
        try:
            success = {"ok": True, "error": "", "result": {"price": 123}, "http_code": 200}
            with patch.object(panel, "api_request", REAL_API_REQUEST), \
                 patch("app.urllib.request.build_opener", return_value=FakeOpener(success)), \
                 patch.object(panel, "_write_store", side_effect=OSError("disk full")):
                result = panel.api_request("direct", "price", {"gig": 1, "day": 1}, "GET")
            self.assertTrue(result["ok"])
            self.assertEqual(result["result"]["price"], 123)
        finally:
            with panel.LOCK:
                panel.STORE["apis"]["direct"]["api_key"] = old_key

    def test_corrupt_current_file_does_not_overwrite_healthy_backup(self):
        with tempfile.TemporaryDirectory(prefix="ali-vpn-store-regression-") as tmp:
            d = Path(tmp)
            data_file = d / "panel-data.json"
            backup_file = d / "panel-data.json.bak"
            data_file.write_text('{not-json', encoding="utf-8")
            healthy = '{"healthy": true}'
            backup_file.write_text(healthy, encoding="utf-8")
            with patch.object(panel, "DATA_DIR", d), patch.object(panel, "DATA_FILE", data_file):
                panel._write_store({"replacement": True})
            self.assertEqual(backup_file.read_text(encoding="utf-8"), healthy)
            self.assertEqual(json.loads(data_file.read_text(encoding="utf-8")), {"replacement": True})

    def test_load_store_repairs_non_dict_auth(self):
        with tempfile.TemporaryDirectory(prefix="ali-vpn-auth-regression-") as tmp:
            d = Path(tmp)
            data_file = d / "panel-data.json"
            payload = panel.default_data()
            payload["auth"] = None
            data_file.write_text(json.dumps(payload), encoding="utf-8")
            with patch.object(panel, "DATA_DIR", d), patch.object(panel, "DATA_FILE", data_file):
                fixed, generated_password = panel.load_store()
            self.assertIsInstance(fixed.get("auth"), dict)
            self.assertTrue(fixed["auth"].get("salt"))
            self.assertTrue(fixed["auth"].get("hash"))
            self.assertTrue(generated_password)

    def test_upstream_network_errors_use_gateway_status_codes(self):
        self.assertEqual(panel.http_status_for_exception(RuntimeError("خطای اتصال به API: Connection refused")), 502)
        self.assertEqual(panel.http_status_for_exception(RuntimeError("زمان انتظار اتصال به API تمام شد.")), 504)
        self.assertEqual(panel.http_status_for_exception(ValueError("ورودی نامعتبر")), 400)
        self.assertEqual(panel.http_status_for_exception(RuntimeError("خطای ذخیرهٔ فایل")), 502 if "api" in "خطای ذخیرهٔ فایل".casefold() else 400)

    def test_clear_logs_route_only_removes_selected_account(self):
        import http.cookiejar
        import threading
        import time
        with panel.LOCK:
            old_store = copy.deepcopy(panel.STORE)
            salt, digest = panel.hash_password("clear-logs-test-password")
            panel.STORE["auth"] = {"salt": salt, "hash": digest, "updated_at": panel.now_iso()}
            panel.STORE["logs"] = [
                {"mode": "direct", "method": "direct-event", "ok": True, "at": panel.now_iso()},
                {"mode": "tunnel", "method": "tunnel-event", "ok": True, "at": panel.now_iso()},
            ]
            panel._write_store(panel.STORE)
        server = panel.ThreadingHTTPServer(("127.0.0.1", 0), panel.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        base = f"http://127.0.0.1:{server.server_address[1]}"
        def request_json(path, data=None):
            raw = None if data is None else json.dumps(data).encode("utf-8")
            req = urllib.request.Request(base + path, data=raw,
                headers={"Content-Type": "application/json"} if raw is not None else {},
                method="POST" if raw is not None else "GET")
            with opener.open(req, timeout=5) as response:
                return json.loads(response.read().decode("utf-8")), response.status
        try:
            login, status = request_json("/api/login", {"password": "clear-logs-test-password"})
            self.assertEqual(status, 200)
            self.assertTrue(login["ok"])
            cleared, status = request_json("/api/logs/clear", {"mode": "direct"})
            self.assertEqual(status, 200)
            self.assertTrue(cleared["ok"])
            logs, _ = request_json("/api/logs?mode=all")
            self.assertEqual([x["mode"] for x in logs["logs"]], ["tunnel"])
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=3)
            with panel.LOCK:
                panel.STORE.clear(); panel.STORE.update(old_store)
                panel._write_store(panel.STORE)

    def test_sensitive_operations_reject_get_requests(self):
        with panel.LOCK:
            old_key = panel.STORE["apis"]["direct"].get("api_key", "")
            panel.STORE["apis"]["direct"]["api_key"] = "test-key"
        try:
            with patch.object(panel, "api_request", REAL_API_REQUEST):
                with self.assertRaisesRegex(ValueError, "فقط باید با POST"):
                    panel.api_request("direct", "create", {"test": 1}, "GET", record=False)
        finally:
            with panel.LOCK:
                panel.STORE["apis"]["direct"]["api_key"] = old_key


if __name__ == "__main__":
    unittest.main(verbosity=2)
