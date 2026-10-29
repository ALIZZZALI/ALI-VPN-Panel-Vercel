"""Regression tests for full two-account backup and restore; uses only fake API responses."""
from __future__ import annotations
import copy
import importlib
import json
import os
import sys
import tempfile
import unittest
import time
import threading
import urllib.request
import http.cookiejar
from unittest.mock import patch
from pathlib import Path

TEMP_DATA = tempfile.TemporaryDirectory(prefix="ali-vpn-test-data-")
os.environ["ALI_VPN_PANEL_DATA_DIR"] = TEMP_DATA.name
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
panel = importlib.import_module("app")

DIRECT_USER = "D1A2B3C4D"
TUNNEL_USER = "T1A2B3C4D"
ORIGINAL_API_REQUEST = panel.api_request


def fake_api_request(mode, method, params=None, http_method=None, *, record=True):
    params = params or {}
    key = DIRECT_USER if mode == "direct" else TUNNEL_USER
    if method == "me":
        return {"ok": True, "error": "", "result": {"user_id": 101 if mode == "direct" else 202,
            "balance": 123456, "currency": "toman", "prices": {"per_gb": 1000, "per_day": 200},
            "limits": {"min_gig": 0.5, "max_gig": 1000}, "services": {"total": 1, "active": 1}}, "http_code": 200}
    if method == "status":
        return {"ok": True, "error": "", "result": {"system": "connected", "ping": 0.01}, "http_code": 200}
    if method == "get_hosts":
        return {"ok": True, "error": "", "result": {"VLESS": [{"id": 1, "remark": "Test host", "address": "host.example", "port": 443}]}, "http_code": 200}
    if method == "clients":
        item = {"username": key, "status": "active", "owner": "", "gig": 20, "day": 30,
                "data_limit_gb": 20, "used_traffic_gb": 1, "expire_jalali": "1405/09/01",
                "sub_link": f"https://sub.example/{mode}/{key}", "source": "cache"}
        limit = int(params.get("limit", 10**6)); offset = int(params.get("offset", 0))
        items = [item][offset:offset + limit]
        return {"ok": True, "error": "", "result": {"count": len(items), "total": 1, "list": items}, "http_code": 200}
    if method == "info":
        username = params.get("username", key)
        return {"ok": True, "error": "", "result": {"username": username, "status": "active", "source": "panel",
            "test": False, "unlimited": False, "sub_link": f"https://sub.example/{mode}/{username}",
            "links": [f"vless://uuid@{mode}.example:443#Test"], "expire": 1900000000,
            "expire_jalali": "1405/09/01", "days_left": 10, "data_limit": 21474836480,
            "used_traffic": 1073741824, "remaining_traffic": 20401094656,
            "data_limit_gb": 20, "used_traffic_gb": 1, "remaining_traffic_gb": 19,
            "created_at": 1800000000}, "http_code": 200}
    if method == "find":
        return {"ok": False, "error": "service not found!", "result": [], "http_code": 404}
    raise AssertionError(f"Unexpected method: {mode} {method}")


class FullBackupTests(unittest.TestCase):
    def setUp(self):
        with panel.LOCK:
            panel.STORE["apis"] = {
                "direct": {"api_key": "test-direct-key", "api_url": panel.API_URLS["direct"]},
                "tunnel": {"api_key": "test-tunnel-key", "api_url": panel.API_URLS["tunnel"]},
            }
            panel.STORE["owners"] = {"direct": {DIRECT_USER: "مالک مستقیم"}, "tunnel": {TUNNEL_USER: "مالک تانل"}}
            panel.STORE["preferences"] = {"theme": "violet", "last_mode": "tunnel", "last_view": "settings", "service_page_size": 50}
            panel.STORE["logs"] = [{"mode": "direct", "kind": "operation", "method": "create", "username": DIRECT_USER, "ok": True, "at": "2026-10-28T12:00:00+03:30"}]
            panel.STORE["auth"] = {"salt": "0" * 32, "hash": "1" * 64, "updated_at": "2026-10-28T12:00:00+03:30"}
            panel._write_store(panel.STORE)
        panel.LAST_RESPONSES.update({"direct": {"ok": True, "result": {"test_marker": "direct-last"}}, "tunnel": {"ok": True, "result": {"test_marker": "tunnel-last"}}})
        panel.api_request = fake_api_request
        with panel.BACKUP_JOB_LOCK:
            panel.BACKUP_JOBS.clear()

    def make_backup(self, include_secrets=True, include_details=True):
        job_id = "test-job"
        with panel.BACKUP_JOB_LOCK:
            panel.BACKUP_JOBS[job_id] = {"status": "running", "stage": "test", "total_services": 0, "completed_services": 0}
        panel._run_backup_job(job_id, {"include_secrets": include_secrets, "include_service_details": include_details})
        job = panel.BACKUP_JOBS[job_id]
        self.assertEqual(job["status"], "complete", job.get("error"))
        return json.loads(job["result"].decode("utf-8"))

    def test_full_backup_captures_both_accounts_services_and_owners(self):
        backup = self.make_backup()
        self.assertEqual(backup["format"], "ALI-VPN-FULL-BACKUP-v2")
        self.assertIn("direct", backup["accounts"])
        self.assertIn("tunnel", backup["accounts"])
        direct = backup["accounts"]["direct"]["services"][0]
        tunnel = backup["accounts"]["tunnel"]["services"][0]
        self.assertEqual(direct["username"], DIRECT_USER)
        self.assertEqual(direct["owner"], "مالک مستقیم")
        self.assertEqual(direct["details"]["status"], "active")
        self.assertIn("links", direct["details"])
        self.assertEqual(tunnel["owner"], "مالک تانل")
        self.assertEqual(backup["settings"]["apis"]["direct"]["api_key"], "test-direct-key")
        self.assertEqual(backup["settings"]["apis"]["tunnel"]["api_key"], "test-tunnel-key")
        self.assertEqual(backup["settings"]["preferences"]["theme"], "violet")
        self.assertIn("auth", backup["settings"])
        self.assertEqual(backup["last_responses"]["direct"]["result"]["test_marker"], "direct-last")
        self.assertEqual(panel.LAST_RESPONSES["direct"]["result"]["test_marker"], "direct-last", "background backup must not overwrite API inspector state")

    def test_restore_restores_both_accounts_and_theme(self):
        backup = self.make_backup()
        with panel.LOCK:
            panel.STORE["apis"]["direct"]["api_key"] = "changed"
            panel.STORE["apis"]["tunnel"]["api_key"] = "changed"
            panel.STORE["owners"] = {"direct": {}, "tunnel": {}}
            panel.STORE["preferences"]["theme"] = "amber"
        result = panel.restore_full_backup(backup)
        self.assertEqual(result["owners"], 2)
        self.assertEqual(panel.STORE["apis"]["direct"]["api_key"], "test-direct-key")
        self.assertEqual(panel.STORE["apis"]["tunnel"]["api_key"], "test-tunnel-key")
        self.assertEqual(panel.STORE["owners"]["direct"][DIRECT_USER], "مالک مستقیم")
        self.assertEqual(panel.STORE["owners"]["tunnel"][TUNNEL_USER], "مالک تانل")
        self.assertEqual(panel.STORE["preferences"]["theme"], "violet")
        self.assertEqual(panel.LAST_RESPONSES["direct"]["result"]["test_marker"], "direct-last")
        self.assertEqual(panel.LAST_RESPONSES["tunnel"]["result"]["test_marker"], "tunnel-last")

    def test_backup_without_secrets_keeps_current_keys_on_restore(self):
        backup = self.make_backup(include_secrets=False, include_details=False)
        self.assertNotIn("auth", backup["settings"])
        self.assertNotIn("api_key", backup["settings"]["apis"]["direct"])
        with panel.LOCK:
            panel.STORE["apis"]["direct"]["api_key"] = "keep-direct"
            panel.STORE["apis"]["tunnel"]["api_key"] = "keep-tunnel"
        result = panel.restore_full_backup(backup)
        self.assertFalse(result["includes_secrets"])
        self.assertEqual(panel.STORE["apis"]["direct"]["api_key"], "keep-direct")
        self.assertEqual(panel.STORE["apis"]["tunnel"]["api_key"], "keep-tunnel")

    def test_invalid_backup_does_not_partially_mutate_store(self):
        backup = self.make_backup()
        backup["settings"]["apis"]["direct"]["api_url"] = "https://evil.example/api/"
        before = copy.deepcopy(panel.STORE)
        with self.assertRaises(ValueError):
            panel.restore_full_backup(backup)
        self.assertEqual(panel.STORE, before)


    def test_backup_without_details_reports_progress_as_completed(self):
        backup = self.make_backup(include_secrets=False, include_details=False)
        job = panel.BACKUP_JOBS["test-job"]
        self.assertEqual(job["status"], "complete")
        self.assertEqual(job["total_services"], 2)
        self.assertEqual(job["completed_services"], 2)
        self.assertFalse(backup["included"]["full_service_details"])
        self.assertEqual(len(backup["accounts"]["direct"]["services"]), 1)
        self.assertEqual(len(backup["accounts"]["tunnel"]["services"]), 1)

    def test_read_only_backup_api_calls_do_not_replace_last_response(self):
        class FakeResponse:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self): return b'{"ok":true,"error":"","result":{"balance":777},"http_code":200}'
        before = copy.deepcopy(panel.LAST_RESPONSES["direct"])
        panel.api_request = ORIGINAL_API_REQUEST
        try:
            class FakeOpener:
                def open(self, req, timeout=60): return FakeResponse()
            with patch("app.urllib.request.build_opener", return_value=FakeOpener()):
                res = panel.api_request("direct", "me", {}, "GET", record=False)
            self.assertTrue(res["ok"])
            self.assertEqual(panel.LAST_RESPONSES["direct"], before)
        finally:
            panel.api_request = fake_api_request

    def test_http_backup_endpoint_downloads_a_single_combined_backup(self):
        with panel.LOCK:
            salt, digest = panel.hash_password("route-test-password")
            panel.STORE["auth"] = {"salt": salt, "hash": digest, "updated_at": "2026-10-28T12:00:00+03:30"}
            panel._write_store(panel.STORE)
        server = panel.ThreadingHTTPServer(("127.0.0.1", 0), panel.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        base = f"http://127.0.0.1:{server.server_address[1]}"
        def request_json(path, data=None):
            raw = None if data is None else json.dumps(data).encode("utf-8")
            req = urllib.request.Request(base + path, data=raw, headers={"Content-Type": "application/json"} if raw is not None else {}, method="POST" if raw is not None else "GET")
            with opener.open(req, timeout=5) as response:
                return response.read(), response.status
        try:
            raw, status = request_json("/api/login", {"password": "route-test-password"})
            self.assertEqual(status, 200)
            self.assertTrue(json.loads(raw)["ok"])
            raw, status = request_json("/api/data/export/start", {"include_secrets": False, "include_service_details": True})
            self.assertEqual(status, 202)
            job_id = json.loads(raw)["job_id"]
            job = None
            for _ in range(200):
                raw, _ = request_json(f"/api/data/export/status?id={job_id}")
                job = json.loads(raw)
                if job.get("status") in ("complete", "failed"):
                    break
                time.sleep(0.02)
            self.assertEqual(job.get("status"), "complete", job)
            raw, status = request_json(f"/api/data/export/download?id={job_id}")
            self.assertEqual(status, 200)
            backup = json.loads(raw)
            self.assertEqual(backup["format"], "ALI-VPN-FULL-BACKUP-v2")
            self.assertEqual(set(backup["accounts"]), {"direct", "tunnel"})
            self.assertEqual(backup["accounts"]["direct"]["services"][0]["owner"], "مالک مستقیم")
            self.assertEqual(backup["accounts"]["tunnel"]["services"][0]["owner"], "مالک تانل")
            self.assertNotIn("api_key", backup["settings"]["apis"]["direct"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


    def test_second_backup_job_is_rejected_while_one_is_running(self):
        with panel.BACKUP_JOB_LOCK:
            panel.BACKUP_JOBS.clear()
            panel.BACKUP_JOBS["still-running"] = {"status": "running", "created_at": time.time()}
        with self.assertRaisesRegex(RuntimeError, "پشتیبان‌گیری دیگر در حال اجراست"):
            panel.start_backup_job({"include_secrets": False, "include_service_details": False})
        with panel.BACKUP_JOB_LOCK:
            panel.BACKUP_JOBS.clear()

    def test_malformed_full_backup_schema_is_rejected_without_mutation(self):
        backup = self.make_backup()
        backup["settings"].pop("owners", None)
        before = copy.deepcopy(panel.STORE)
        with self.assertRaisesRegex(ValueError, "owners"):
            panel.restore_full_backup(backup)
        self.assertEqual(panel.STORE, before)

    def test_imported_logs_are_bounded_and_allowlisted(self):
        backup = self.make_backup()
        backup["settings"]["logs"] = [{"mode": "not-a-mode", "method": "M" * 1000,
            "error": "E" * 2000, "password": "must-not-be-stored", "http_code": 99999,
            "ms": 10**20, "charged": float("inf"), "ok": "yes", "at": "T" * 100}]
        panel.restore_full_backup(backup)
        row = panel.STORE["logs"][0]
        self.assertEqual(row["mode"], "all")
        self.assertEqual(len(row["method"]), 80)
        self.assertEqual(len(row["error"]), 500)
        self.assertNotIn("password", row)
        self.assertEqual(row["http_code"], 599)
        self.assertEqual(row["ms"], 60000)
        self.assertNotIn("charged", row)
        self.assertNotIn("ok", row)
        self.assertEqual(len(row["at"]), 40)

    def test_metadata_owner_backup_compatibility_parser(self):
        result = panel._safe_owner_map({"direct": {DIRECT_USER.lower(): "Name"}, "tunnel": {TUNNEL_USER: "Other"}})
        self.assertEqual(result["direct"][DIRECT_USER], "Name")
        self.assertEqual(result["tunnel"][TUNNEL_USER], "Other")


if __name__ == "__main__":
    unittest.main(verbosity=2)
