#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ALI VPN Panel — local, responsive management UI for Iranisystem API v1.
No third-party Python packages are required.
"""
from __future__ import annotations
import argparse, base64, hashlib, hmac, io, json, os, secrets, shutil, socket, sys, threading, time, urllib.error, urllib.parse, urllib.request, copy, uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from email.message import Message
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
DATA_DIR = Path(os.environ.get("ALI_VPN_PANEL_DATA_DIR", str(APP_DIR / "ALI_VPN_PANEL_DATA"))).expanduser().resolve()
DATA_FILE = DATA_DIR / "panel-data.json"
IS_VERCEL = os.environ.get("VERCEL", "").strip().lower() in {"1", "true", "yes"} or bool(os.environ.get("VERCEL_ENV"))
KV_KEY_PREFIX = (os.environ.get("ALI_VPN_KV_PREFIX", "ali-vpn-panel").strip().strip(":") or "ali-vpn-panel")


def kv_config() -> tuple[str, str]:
    url = (os.environ.get("KV_REST_API_URL") or os.environ.get("UPSTASH_REDIS_REST_URL") or "").strip().rstrip("/")
    token = (os.environ.get("KV_REST_API_TOKEN") or os.environ.get("UPSTASH_REDIS_REST_TOKEN") or "").strip()
    return url, token


def storage_is_configured() -> bool:
    if not IS_VERCEL:
        return True
    url, token = kv_config()
    parsed = urllib.parse.urlsplit(url)
    return bool(url and token and parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment)


def _kv_command(command: list[Any]) -> Any:
    """Issue a private Upstash Redis REST command without logging credentials."""
    url, token = kv_config()
    parsed = urllib.parse.urlsplit(url)
    if not (url and token and parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment):
        raise RuntimeError("ذخیره‌ساز پایدار تنظیم نشده است؛ اتصال Upstash Redis را از بخش Storage در Vercel به پروژه اضافه کن و دوباره Deploy بگیر.")
    req = urllib.request.Request(
        url,
        data=json.dumps(command, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if not isinstance(payload, dict) or "error" in payload:
            raise RuntimeError("ذخیره‌ساز KV درخواست را نپذیرفت؛ اعتبار اتصال Storage را در Vercel بررسی کن.")
        return payload.get("result")
    except urllib.error.HTTPError as exc:
        # Deliberately do not include request headers, URL query values, or tokens.
        raise RuntimeError(f"خطای ذخیره‌ساز KV (HTTP {exc.code})؛ متغیرهای Storage را در Vercel بررسی کن.") from None
    except urllib.error.URLError:
        raise RuntimeError("اتصال به ذخیره‌ساز KV برقرار نشد؛ وضعیت سرویس و متغیرهای Storage را بررسی کن.") from None
    except (TimeoutError, OSError):
        raise RuntimeError("پاسخ ذخیره‌ساز KV دریافت نشد؛ دوباره تلاش کن.") from None
    except (ValueError, UnicodeError):
        raise RuntimeError("پاسخ ذخیره‌ساز KV معتبر نیست.") from None


def _state_key() -> str:
    return f"{KV_KEY_PREFIX}:state"


def _session_key(sid: str) -> str:
    return f"{KV_KEY_PREFIX}:session:{sid}"


def _backup_key(job_id: str) -> str:
    return f"{KV_KEY_PREFIX}:backup:{job_id}"


def _login_attempt_key(ip: str) -> str:
    # Keep raw IP addresses out of Redis keys.
    digest = hashlib.sha256(str(ip or "unknown").encode("utf-8")).hexdigest()[:32]
    return f"{KV_KEY_PREFIX}:login-attempts:{digest}"


def _remote_login_blocked(ip: str) -> bool:
    count = _kv_command(["GET", _login_attempt_key(ip)])
    try:
        return int(count or 0) >= 8
    except (TypeError, ValueError):
        return False


def _remote_record_failed_login(ip: str) -> None:
    key = _login_attempt_key(ip)
    count = int(_kv_command(["INCR", key]) or 0)
    if count == 1:
        _kv_command(["EXPIRE", key, 300])


def _remote_clear_failed_logins(ip: str) -> None:
    _kv_command(["DEL", _login_attempt_key(ip)])


def _create_session(sid: str, expires_at: float) -> None:
    if IS_VERCEL:
        session_version = str(STORE.get("session_version", ""))
        _kv_command(["SET", _session_key(sid), session_version, "EX", 36000])
    else:
        SESSIONS[sid] = expires_at


def _revoke_session(sid: str | None) -> None:
    if not sid:
        return
    if IS_VERCEL:
        _kv_command(["DEL", _session_key(sid)])
    else:
        SESSIONS.pop(sid, None)

API_URLS = {
    "direct": "https://iranisystem.com/bot/api/v1/",
    "tunnel": "https://iranisystem.com/newbot/api/v1/",
}
MODE_LABELS = {"direct": "مستقیم", "tunnel": "تانل"}
METHOD_ALIASES = {
    "account": "me", "balance": "me", "quote": "price",
    "hosts": "get_hosts", "locations": "get_hosts",
    "buy": "create", "service": "info", "list": "clients", "services": "clients",
    "add_time": "upg_time", "upgrade_time": "upg_time", "extend": "upg_time",
    "add_volume": "upg_size", "add_traffic": "upg_size", "upgrade_size": "upg_size",
    "revoke_sub": "change_link", "new_link": "change_link",
    "mode_reverse": "reverse_mode", "toggle_status": "reverse_mode", "set_status": "reverse_mode",
    "changelink": "change_link", "setstatus": "reverse_mode", "modereverse": "reverse_mode",
    "addtime": "upg_time", "upgrade_time": "upg_time", "upgradetime": "upg_time",
    "addvolume": "upg_size", "addtraffic": "upg_size", "upgradesize": "upg_size",
    "delete": "delsv", "remove": "delsv",
}
GET_METHODS = {"me", "status", "get_hosts", "clients", "info", "price"}
ALLOWED_METHODS = GET_METHODS | {"create", "renew", "upg_time", "upg_size", "change_link", "reverse_mode", "delsv"} | set(METHOD_ALIASES)
MAX_LOGS = 350
SENSITIVE_METHODS = {"create", "renew", "upg_time", "upg_size", "change_link", "reverse_mode", "delsv"}
MAX_FULL_CLIENTS = 10000
PBKDF2_ROUNDS = 240_000
LOCK = threading.RLock()
SESSIONS: dict[str, float] = {}
LOGIN_ATTEMPTS: dict[str, list[float]] = {}
LAST_RESPONSES: dict[str, dict[str, Any] | None] = {"direct": None, "tunnel": None}
BACKUP_JOBS: dict[str, dict[str, Any]] = {}
BACKUP_JOB_LOCK = threading.RLock()
BACKUP_MAX_SERVICES = 10000
BACKUP_WORKERS = 3
BACKUP_MAX_ACTIVE_JOBS = 1
THEMES = {"obsidian", "violet", "ocean", "emerald", "amber"}


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, digest_hex: str) -> bool:
    try:
        _, candidate = hash_password(password, bytes.fromhex(salt_hex))
        return hmac.compare_digest(candidate, digest_hex)
    except Exception:
        return False


def default_data() -> dict[str, Any]:
    return {
        "version": 1,
        "session_version": uuid.uuid4().hex,
        "auth": {},
        "apis": {
            "direct": {"api_key": "", "api_url": API_URLS["direct"]},
            "tunnel": {"api_key": "", "api_url": API_URLS["tunnel"]},
        },
        "owners": {"direct": {}, "tunnel": {}},
        "preferences": {"theme": "obsidian", "last_mode": "direct", "last_view": "dashboard", "service_page_size": 25},
        "created_at": now_iso(),
        "logs": [],
    }


def _write_store(data: dict[str, Any]) -> None:
    """Persist settings atomically locally or in Upstash Redis on Vercel."""
    encoded = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    if IS_VERCEL:
        if not storage_is_configured():
            raise RuntimeError("ذخیره‌ساز پایدار تنظیم نشده است؛ اتصال Upstash Redis را به پروژهٔ Vercel اضافه کن.")
        _kv_command(["SET", _state_key(), encoded])
        return
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    temp = DATA_DIR / f".{DATA_FILE.name}.{uuid.uuid4().hex}.tmp"
    try:
        temp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        if DATA_FILE.exists():
            try:
                current = json.loads(DATA_FILE.read_text(encoding="utf-8"))
                if isinstance(current, dict):
                    backup = DATA_FILE.with_suffix(".json.bak")
                    backup_tmp = DATA_DIR / f".{backup.name}.{uuid.uuid4().hex}.tmp"
                    try:
                        shutil.copy2(DATA_FILE, backup_tmp)
                        os.replace(backup_tmp, backup)
                        if os.name != "nt":
                            try: os.chmod(backup, 0o600)
                            except OSError: pass
                    finally:
                        try: backup_tmp.unlink(missing_ok=True)
                        except OSError: pass
            except Exception:
                pass
        os.replace(temp, DATA_FILE)
        if os.name != "nt":
            try: os.chmod(DATA_FILE, 0o600)
            except OSError: pass
    finally:
        try: temp.unlink(missing_ok=True)
        except OSError: pass


def load_store() -> tuple[dict[str, Any], str | None]:
    """Load saved state. Vercel starts uninitialized until Redis is linked."""
    if IS_VERCEL:
        if not storage_is_configured():
            blank = default_data()
            blank["auth"] = {}
            return blank, None
        remote = _kv_command(["GET", _state_key()])
        if remote is None:
            data = default_data()
            data["auth"] = {}
            fresh = True
        else:
            try:
                data = json.loads(remote) if isinstance(remote, str) else remote
                if not isinstance(data, dict):
                    raise ValueError("root must be a JSON object")
            except Exception as exc:
                raise RuntimeError("دادهٔ ذخیره‌شدهٔ پنل در KV معتبر نیست؛ پیش از ادامه، مقدار ذخیره‌شده را بررسی کن.") from exc
            fresh = False
    else:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        fresh = not DATA_FILE.exists()
        try:
            data = json.loads(DATA_FILE.read_text(encoding="utf-8")) if not fresh else default_data()
            if not isinstance(data, dict):
                raise ValueError("root must be a JSON object")
        except Exception as read_error:
            bad = DATA_DIR / f"panel-data.corrupt-{int(time.time())}-{secrets.token_hex(3)}.json"
            try:
                if DATA_FILE.exists():
                    bad.write_bytes(DATA_FILE.read_bytes())
                    DATA_FILE.unlink(missing_ok=True)
            except Exception as preserve_error:
                raise RuntimeError(f"فایل داده خراب است و نتوانستم نسخهٔ آن را برای بازیابی نگه دارم: {type(preserve_error).__name__}") from read_error
            data = default_data()
            fresh = True

    base = default_data()
    base.update(data)
    if not isinstance(base.get("apis"), dict):
        base["apis"] = {}
    if not isinstance(base.get("owners"), dict):
        base["owners"] = {}
    if not isinstance(base.get("logs"), list):
        base["logs"] = []
    if not isinstance(base.get("preferences"), dict):
        base["preferences"] = {"theme": "obsidian", "last_mode": "direct", "last_view": "dashboard", "service_page_size": 25}
    prefs = base["preferences"]
    if prefs.get("theme") not in THEMES:
        prefs["theme"] = "obsidian"
    if prefs.get("last_mode") not in API_URLS:
        prefs["last_mode"] = "direct"
    if prefs.get("last_view") not in {"dashboard", "services", "create", "locations", "apilab", "logs", "settings"}:
        prefs["last_view"] = "dashboard"
    try:
        prefs["service_page_size"] = max(10, min(100, int(prefs.get("service_page_size", 25))))
    except (TypeError, ValueError):
        prefs["service_page_size"] = 25
    for mode in API_URLS:
        if not isinstance(base["apis"].get(mode), dict):
            base["apis"][mode] = {"api_key": "", "api_url": API_URLS[mode]}
        base["apis"][mode].setdefault("api_key", "")
        try:
            base["apis"][mode]["api_url"] = validate_api_url(mode, str(base["apis"][mode].get("api_url") or API_URLS[mode]))
        except Exception:
            base["apis"][mode]["api_url"] = API_URLS[mode]
        if not isinstance(base["owners"].get(mode), dict):
            base["owners"][mode] = {}
    if not isinstance(base.get("auth"), dict):
        base["auth"] = {}
    generated_password = None
    auth = base["auth"]
    if not auth.get("salt") or not auth.get("hash"):
        if IS_VERCEL:
            # First admin password is created interactively in the browser; no seeded password.
            base["auth"] = {}
        else:
            generated_password = secrets.token_urlsafe(13)
            salt, digest = hash_password(generated_password)
            base["auth"] = {"salt": salt, "hash": digest, "updated_at": now_iso()}
    # Vercel reads the shared state at request time; do not rewrite a healthy
    # remote record on every refresh. Only seed Redis when it was empty.
    if storage_is_configured() and (not IS_VERCEL or fresh):
        _write_store(base)
    return base, generated_password


# Avoid external storage I/O while importing a serverless function. The Vercel
# entry point reloads the shared state before handling each request.
if IS_VERCEL:
    STORE, INITIAL_PASSWORD = default_data(), None
    STORE["auth"] = {}
else:
    STORE, INITIAL_PASSWORD = load_store()


def save_store() -> None:
    with LOCK:
        _write_store(STORE)


def valid_mode(mode: str) -> str:
    if mode not in API_URLS:
        raise ValueError("حالت API نامعتبر است؛ مستقیم یا تانل را انتخاب کنید.")
    return mode


def validate_api_url(mode: str, value: str) -> str:
    """Allow HTTPS URLs only on iranisystem.com ending in /api/v1/ (no query/userinfo)."""
    mode = valid_mode(mode)
    value = (value or "").strip()
    parsed = urllib.parse.urlsplit(value)
    required_suffix = "/bot/api/v1/" if mode == "direct" else "/newbot/api/v1/"
    if (parsed.scheme.lower() != "https" or parsed.hostname != "iranisystem.com"
            or parsed.username or parsed.password or parsed.port is not None
            or parsed.query or parsed.fragment or parsed.path != required_suffix):
        raise ValueError(f"آدرس API این حساب باید دقیقاً روی دامنه iranisystem.com و مسیر {required_suffix} باشد.")
    if any(c.isspace() for c in value):
        raise ValueError("آدرس API شامل فاصلهٔ نامعتبر است.")
    return urllib.parse.urlunsplit(("https", "iranisystem.com", parsed.path, "", ""))


def api_url_for(mode: str) -> str:
    mode = valid_mode(mode)
    with LOCK:
        entry = STORE.get("apis", {}).get(mode, {})
        value = str(entry.get("api_url") or API_URLS[mode]) if isinstance(entry, dict) else API_URLS[mode]
    # Do not silently fall back to a different endpoint if live state is invalid.
    return validate_api_url(mode, value)

def canonical_method(method: str) -> str:
    normalized = str(method or "").strip().lower().replace("-", "_")
    camel_aliases = {
        "changelink": "change_link", "modereverse": "reverse_mode", "setstatus": "reverse_mode",
        "addtime": "upg_time", "upgradetime": "upg_time", "addvolume": "upg_size",
        "addtraffic": "upg_size", "upgradesize": "upg_size",
    }
    return METHOD_ALIASES.get(normalized, camel_aliases.get(normalized.replace("_", ""), normalized))

def response_payload(raw: bytes, status: int) -> dict[str, Any]:
    text = raw.decode("utf-8", errors="replace")
    try:
        value = json.loads(text)
        if isinstance(value, dict):
            value.setdefault("http_code", status)
            return value
        return {"ok": False, "error": "پاسخ API یک شیء JSON نیست.", "result": value, "http_code": status}
    except Exception:
        return {"ok": False, "error": f"پاسخ JSON معتبر نیست (HTTP {status}).", "raw": text[:4000], "result": [], "http_code": status}


def api_request(mode: str, method: str, params: dict[str, Any] | None = None,
                http_method: str | None = None, *, record: bool = True,
                api_key_override: str | None = None, api_url_override: str | None = None) -> dict[str, Any]:
    mode = valid_mode(mode)
    requested_method = str(method or "").strip().lower().replace("-", "_")
    method = canonical_method(requested_method)
    if requested_method not in ALLOWED_METHODS and method not in ALLOWED_METHODS:
        raise ValueError("این متد در پنل مجاز نیست.")
    with LOCK:
        stored_key = str(STORE.get("apis", {}).get(mode, {}).get("api_key", "")).strip()
    key = stored_key if api_key_override is None else str(api_key_override).strip()
    if not key:
        raise RuntimeError(f"برای API «{MODE_LABELS[mode]}» هنوز کلید وارد نشده است.")
    params = params or {}
    http_method = (http_method or ("GET" if method in GET_METHODS else "POST")).upper()
    if http_method not in {"GET", "POST"}:
        raise ValueError("فقط GET و POST مجاز هستند.")
    if method in SENSITIVE_METHODS and http_method != "POST":
        raise ValueError("عملیات تغییردهنده یا مالی فقط باید با POST ارسال شود.")
    base_url = validate_api_url(mode, api_url_override) if api_url_override is not None else api_url_for(mode)
    url = base_url + method
    headers = {"Authorization": f"Bearer {key}", "Accept": "application/json", "User-Agent": "ALI-VPN-Panel/1.1"}
    body = None
    if http_method == "GET" and params:
        url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    elif http_method == "POST":
        body = json.dumps(params, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    req = urllib.request.Request(url, data=body, headers=headers, method=http_method)
    start = time.monotonic()

    def log_failure(message: str, status_code: int = 0) -> None:
        if not record:
            return
        elapsed = round((time.monotonic() - start) * 1000)
        entry = {"mode": mode, "kind": "operation" if method in SENSITIVE_METHODS else "api",
                 "method": method, "http_code": status_code, "ok": False,
                 "error": str(message)[:220], "username": str(params.get("username", ""))[:32],
                 "ms": elapsed, "at": now_iso(), "outcome_unknown": status_code == 0 and method in SENSITIVE_METHODS}
        add_log(entry)

    try:
        # Refuse redirects so Authorization cannot be sent to a different host.
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        opener = urllib.request.build_opener(_NoRedirect)
        with opener.open(req, timeout=60) as resp:
            raw, status = resp.read(), int(resp.status)
    except urllib.error.HTTPError as exc:
        if 300 <= int(exc.code) < 400:
            message = "سرور API درخواست را به نشانی دیگری هدایت کرد؛ برای جلوگیری از انتقال کلید، هدایت خودکار متوقف شد."
            log_failure(message, int(exc.code))
            raise RuntimeError(message) from exc
        raw, status = exc.read(), int(exc.code)
    except urllib.error.URLError as exc:
        message = f"خطای اتصال به API: {exc.reason}"
        if method in SENSITIVE_METHODS:
            message += " نتیجهٔ عملیات تغییردهنده ممکن است نامشخص باشد؛ قبل از تکرار، سرویس را بررسی کن."
        log_failure(message)
        raise RuntimeError(message) from exc
    except TimeoutError as exc:
        message = "زمان انتظار اتصال به API تمام شد."
        if method in SENSITIVE_METHODS:
            message += " نتیجهٔ عملیات نامشخص است؛ قبل از تکرار، فهرست یا جزئیات سرویس را بررسی کن."
        log_failure(message)
        raise RuntimeError(message) from exc
    except Exception as exc:
        message = f"خطای ارتباطی: {type(exc).__name__}"
        if method in SENSITIVE_METHODS:
            message += " نتیجهٔ عملیات ممکن است نامشخص باشد؛ قبل از تکرار وضعیت سرویس را بررسی کن."
        log_failure(message)
        raise RuntimeError(message) from exc
    result = response_payload(raw, status)
    if record:
        with LOCK:
            LAST_RESPONSES[mode] = copy.deepcopy(result)
    elapsed = round((time.monotonic() - start) * 1000)
    root = result.get("result") if isinstance(result.get("result"), dict) else {}
    username = str(params.get("username", ""))[:32]
    if method == "create":
        service = root.get("service") if isinstance(root.get("service"), dict) else root
        username = str(service.get("username") or root.get("username") or username)[:32]
    entry = {"mode": mode,
             "kind": "operation" if method in SENSITIVE_METHODS else "api",
             "method": method,
             "http_code": result.get("http_code", status),
             "ok": result.get("ok") is True,
             "error": str(result.get("error", ""))[:220],
             "username": username, "ms": elapsed, "at": now_iso()}
    if method in {"create", "renew", "upg_time", "upg_size"} and result.get("ok") is True:
        amount = root.get("charged", root.get("price"))
        if amount is not None:
            entry["charged"] = amount
    elif method == "delsv" and result.get("ok") is True and result.get("return_price") is not None:
        entry["refund"] = result.get("return_price")
        entry["applied"] = True
    if record:
        # Logging is best-effort: a disk error must never turn a successful remote
        # purchase/renewal into a false failure that encourages duplicate payment.
        add_log(entry)
    return result

def add_log(entry: dict[str, Any]) -> bool:
    """Persist a bounded audit row; fail closed for the log only, not for the API result."""
    with LOCK:
        logs = STORE.setdefault("logs", [])
        previous = list(logs)
        logs.insert(0, entry)
        del logs[MAX_LOGS:]
        try:
            _write_store(STORE)
            return True
        except Exception as exc:
            STORE["logs"] = previous
            # Do not propagate a storage error into the already completed API operation.
            try: print(f"[ALI VPN PANEL] Failed to persist operation log: {type(exc).__name__}", file=sys.stderr)
            except Exception: pass
            return False

def service_list_from(response: dict[str, Any]) -> tuple[list[dict[str, Any]], int | None]:
    root = response.get("result") if isinstance(response, dict) else None
    if isinstance(root, dict):
        items = None
        # Prefer the first non-empty supported collection; an empty legacy alias must not
        # hide a populated collection later in the response.
        for key in ("list", "clients", "items", "services"):
            candidate = root.get(key)
            if isinstance(candidate, list):
                if items is None:
                    items = candidate
                if candidate:
                    items = candidate
                    break
        if items is not None:
            total_raw = root.get("total", root.get("count"))
            total = None
            try:
                n = float(total_raw)
                if n >= 0 and n.is_integer(): total = int(n)
            except (TypeError, ValueError, OverflowError):
                pass
            return [x for x in items if isinstance(x, dict) and x.get("username")], total
        if "total" in root and str(root.get("total")) in {"0", "0.0"}:
            return [], 0
    if isinstance(root, list):
        return [x for x in root if isinstance(x, dict) and x.get("username")], len(root)
    return [], None

def owner_for(mode: str, username: str) -> str:
    with LOCK:
        return str(STORE["owners"][mode].get(str(username).strip().upper(), "")).strip()


def attach_owners(mode: str, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for item in items:
        user = str(item.get("username", ""))
        if user:
            item["owner"] = owner_for(mode, user) or item.get("owner") or ""
    return items


def get_clients(mode: str, limit: int = 50, offset: int = 0, search: str = "", status: str = "all", service_type: str = "all", sort_by: str = "api", sort_dir: str = "asc") -> dict[str, Any]:
    limit = max(1, min(500, int(limit)))
    offset = max(0, int(offset))
    search = search.strip().casefold()
    status = status.strip().lower() or "all"
    service_type = service_type.strip().lower() or "all"
    sort_by = sort_by.strip().lower() or "api"
    sort_dir = "desc" if sort_dir.strip().lower() == "desc" else "asc"
    if status not in {"all", "active", "disabled", "limited", "expired", "on_hold"}: status = "all"
    if service_type not in {"all", "test", "normal", "unlimited", "volume"}: service_type = "all"
    if sort_by not in {"api", "username", "status", "usage", "gig", "expire", "days_left"}: sort_by = "api"

    needs_full_list = bool(search or status != "all" or service_type != "all" or sort_by != "api" or sort_dir == "desc")

    def fetch_all() -> tuple[list[dict[str, Any]] | None, int | None, dict[str, Any], str | None]:
        page_size = 500
        first = api_request(mode, "clients", {"limit": page_size, "offset": 0}, "GET", record=False)
        if first.get("ok") is not True:
            # Compatibility fallback for older API deployments that do not accept pagination.
            fallback = api_request(mode, "clients", {}, "GET", record=False)
            if fallback.get("ok") is True:
                rows, total_hint = service_list_from(fallback)
                return rows, (total_hint if total_hint is not None else len(rows)), fallback, None
            if str(fallback.get("error", "")).lower() == "no service":
                return [], 0, fallback, None
            return None, None, fallback, str(fallback.get("error") or first.get("error") or "دریافت کامل فهرست سرویس‌ها ناموفق بود.")

        rows, total_hint = service_list_from(first)
        collected = list(rows)
        if total_hint is not None and total_hint > MAX_FULL_CLIENTS:
            return None, total_hint, first, f"تعداد سرویس‌ها ({total_hint}) از سقف پردازش یکجای پنل ({MAX_FULL_CLIENTS}) بیشتر است؛ برای جلوگیری از بارگذاری ناقص، جست‌وجوی سراسری اجرا نشد."
        if not rows and total_hint in (0, None):
            return [], 0, first, None
        last = first
        while True:
            if total_hint is not None and len(collected) >= total_hint: break
            if total_hint is None and len(rows) < page_size: break
            if len(collected) >= MAX_FULL_CLIENTS:
                return None, total_hint, last, f"پردازش فهرست به سقف {MAX_FULL_CLIENTS} سرویس رسید؛ هیچ نتیجهٔ ناقصی نمایش داده نشد."
            page = api_request(mode, "clients", {"limit": page_size, "offset": len(collected)}, "GET", record=False)
            if page.get("ok") is not True:
                # If pagination fails midway, never silently filter only the first page.
                fallback = api_request(mode, "clients", {}, "GET", record=False)
                if fallback.get("ok") is True:
                    fallback_rows, fallback_total = service_list_from(fallback)
                    return fallback_rows, (fallback_total if fallback_total is not None else len(fallback_rows)), fallback, None
                return None, total_hint, page, str(page.get("error") or "ادامه صفحه‌بندی سرویس‌ها ناموفق بود.")
            rows, page_total = service_list_from(page)
            if not rows: break
            collected.extend(rows)
            last = page
            if total_hint is None and page_total is not None: total_hint = page_total
            if total_hint is not None and len(collected) >= total_hint: break
            if total_hint is None and len(rows) < page_size: break
        return collected, (total_hint if total_hint is not None else len(collected)), last, None

    if needs_full_list:
        all_items, total_hint, primary, fetch_error = fetch_all()
        if all_items is None:
            return {"ok": False, "items": [], "total": 0, "offset": offset, "limit": limit, "raw": primary, "error": fetch_error or "دریافت سرویس‌ها ناموفق بود."}
        all_items = attach_owners(mode, all_items)
        if search:
            all_items = [x for x in all_items if search in str(x.get("username", "")).casefold() or search in str(x.get("owner", "")).casefold()]
        if status != "all":
            all_items = [x for x in all_items if str(x.get("status", "unknown")).lower() == status]
        def is_test(x: dict[str, Any]) -> bool:
            value = x.get("test")
            return value is True or str(value).lower() in {"1", "true", "yes"}
        def is_unlimited(x: dict[str, Any]) -> bool:
            if x.get("unlimited") is True: return True
            for key in ("gig", "data_limit", "data_limit_gb", "package_size"):
                value = x.get(key)
                if value is not None and value != "":
                    try:
                        if float(value) == 0: return True
                    except (TypeError, ValueError, OverflowError): pass
            return False
        if service_type == "test": all_items = [x for x in all_items if is_test(x)]
        elif service_type == "normal": all_items = [x for x in all_items if not is_test(x)]
        elif service_type == "unlimited": all_items = [x for x in all_items if is_unlimited(x)]
        elif service_type == "volume": all_items = [x for x in all_items if not is_unlimited(x)]

        def number(value: Any, default: float = 0.0) -> float:
            try:
                if value is None or value == "": return default
                n = float(value)
                return n if n == n and abs(n) != float("inf") else default
            except (TypeError, ValueError, OverflowError): return default
        if sort_by != "api":
            def sort_key(x: dict[str, Any]):
                if sort_by == "username": return str(x.get("username", "")).casefold()
                if sort_by == "status": return str(x.get("status", "")).casefold()
                if sort_by == "gig": return number(x.get("data_limit_gb", x.get("gig", 0)))
                if sort_by == "usage": return number(x.get("used_traffic_gb", x.get("usage_converted", x.get("usage", 0))))
                if sort_by == "days_left": return number(x.get("days_left"), float("inf"))
                if sort_by == "expire": return number(x.get("expire", x.get("expiration_time", 0)))
                return str(x.get("username", "")).casefold()
            all_items.sort(key=sort_key, reverse=sort_dir == "desc")
        elif sort_dir == "desc":
            all_items.reverse()
        total = len(all_items)
        return {"ok": True, "items": all_items[offset:offset + limit], "total": total,
                "offset": offset, "limit": limit, "raw": primary, "complete_list_processed": True}

    primary = api_request(mode, "clients", {"limit": limit, "offset": offset}, "GET")
    items, total = service_list_from(primary)
    if primary.get("ok") is True:
        return {"ok": True, "items": attach_owners(mode, items), "total": total if total is not None else len(items),
                "offset": offset, "limit": limit, "raw": primary}
    # Compatibility fallback, including an empty account response.
    if primary.get("http_code") in (400, 403, 404) or str(primary.get("error", "")).lower() == "no service":
        fallback = api_request(mode, "clients", {}, "GET", record=False)
        if fallback.get("ok") is True:
            rows, fallback_total = service_list_from(fallback)
            total_n = fallback_total if fallback_total is not None else len(rows)
            return {"ok": True, "items": attach_owners(mode, rows[offset:offset + limit]), "total": total_n,
                    "offset": offset, "limit": limit, "raw": fallback, "compatibility_fallback": True}
        if str(fallback.get("error", "")).lower() == "no service":
            return {"ok": True, "items": [], "total": 0, "offset": offset, "limit": limit, "raw": fallback, "compatibility_fallback": True}
    if str(primary.get("error", "")).lower() == "no service":
        return {"ok": True, "items": [], "total": 0, "offset": offset, "limit": limit, "raw": primary}
    return {"ok": False, "items": [], "total": 0, "offset": offset, "limit": limit, "raw": primary,
            "error": primary.get("error", "دریافت سرویس‌ها ناموفق بود.")}

def get_service(mode: str, username: str) -> dict[str, Any]:
    username = username.strip().upper()
    if not username:
        raise ValueError("شناسهٔ سرویس را وارد کنید.")
    current = api_request(mode, "info", {"username": username}, "GET")
    if current.get("ok") is True:
        root = current.get("result")
        service = root.get("service") if isinstance(root, dict) and isinstance(root.get("service"), dict) else root
        if isinstance(service, dict) and (service.get("username") or len(service) > 1):
            service.setdefault("username", username)
            service["owner"] = owner_for(mode, username)
            return {"ok": True, "service": service, "raw": current, "legacy": False}
    # Legacy compatibility: find contains online_info/latest_info and may also contain service.
    try:
        legacy = api_request(mode, "find", {"username": username}, "POST")
        if legacy.get("ok") is True:
            root = legacy.get("result") if isinstance(legacy.get("result"), dict) else {}
            service = root.get("service") if isinstance(root.get("service"), dict) else {}
            latest = root.get("latest_info") if isinstance(root.get("latest_info"), dict) else {}
            online = root.get("online_info") if isinstance(root.get("online_info"), dict) else {}
            merged = {**latest, **service}
            merged.setdefault("username", username)
            merged.setdefault("status", online.get("status", "unknown"))
            if merged.get("used_traffic") is None and online.get("usage") is not None:
                merged["used_traffic"] = online.get("usage")
            # Leave used_traffic_gb absent when unavailable so the UI can convert
            # the legacy byte field rather than rendering a misleading dash.
            merged.setdefault("links", online.get("tak_links", []))
            merged.setdefault("expire_jalali", latest.get("expire_date"))
            merged["owner"] = owner_for(mode, username)
            return {"ok": True, "service": merged, "raw": legacy, "legacy": True}
    except Exception:
        pass
    return {"ok": False, "service": None, "raw": current, "error": current.get("error", "اطلاعات سرویس دریافت نشد.")}



def _backup_progress(job_id: str, **updates: Any) -> None:
    with BACKUP_JOB_LOCK:
        job = BACKUP_JOBS.get(job_id)
        if job is not None:
            job.update(updates)
            job["updated_at"] = time.time()


def _safe_owner_map(value: Any) -> dict[str, dict[str, str]]:
    result = {mode: {} for mode in API_URLS}
    if not isinstance(value, dict):
        return result
    for mode in API_URLS:
        block = value.get(mode, {})
        if not isinstance(block, dict):
            continue
        for username, owner in block.items():
            if isinstance(username, str) and isinstance(owner, str) and username.strip() and owner.strip():
                result[mode][username.strip().upper()[:80]] = owner.strip()[:120]
    return result


def _safe_logs(value: Any) -> list[dict[str, Any]]:
    """Keep only known, bounded operation-log fields from local data or imports."""
    if not isinstance(value, list):
        return []
    result: list[dict[str, Any]] = []
    allowed_modes = set(API_URLS) | {"all"}
    for row in value[:MAX_LOGS]:
        if not isinstance(row, dict):
            continue
        clean: dict[str, Any] = {}
        mode = str(row.get("mode", "all"))
        clean["mode"] = mode if mode in allowed_modes else "all"
        for field, max_len in (("kind", 40), ("method", 80), ("error", 500), ("username", 80), ("at", 40)):
            field_value = row.get(field)
            if isinstance(field_value, str):
                clean[field] = field_value[:max_len]
        for field in ("ok",):
            if isinstance(row.get(field), bool):
                clean[field] = row[field]
        for field in ("http_code", "ms"):
            val = row.get(field)
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                try:
                    numeric = float(val)
                    if numeric == numeric and abs(numeric) != float("inf"):
                        clean[field] = max(0, min(60000 if field == "ms" else 599, int(numeric)))
                except (TypeError, ValueError, OverflowError):
                    pass
        for field in ("charged", "refund"):
            val = row.get(field)
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                try:
                    numeric = float(val)
                    if numeric == numeric and abs(numeric) != float("inf") and abs(numeric) <= 10**15:
                        clean[field] = int(val) if isinstance(val, int) else numeric
                except (TypeError, ValueError, OverflowError):
                    pass
        result.append(clean)
    return result


def _compact_api_response(value: Any, max_bytes: int = 1024 * 1024) -> dict[str, Any] | None:
    """Retain useful raw response data without duplicating very large service arrays."""
    if not isinstance(value, dict):
        return None
    try:
        raw = json.dumps(value, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError):
        return {"ok": False, "error": "پاسخ ذخیره‌شده قابل تبدیل به JSON نیست.", "http_code": 0, "result": []}
    if len(raw) <= max_bytes:
        return copy.deepcopy(value)
    root = value.get("result")
    if isinstance(root, dict):
        meta = {k: copy.deepcopy(v) for k, v in root.items() if not isinstance(v, list)}
    elif isinstance(root, list):
        meta = {"count": len(root)}
    else:
        meta = {}
    meta["omitted_large_payload"] = True
    meta["note"] = "پاسخ خام بزرگ بود؛ فهرست‌ها و جزئیات سرویس‌ها جداگانه در بخش accounts این پشتیبان ذخیره شده‌اند."
    return {"ok": value.get("ok") is True, "error": str(value.get("error") or "")[:500],
            "http_code": value.get("http_code"), "result": meta, "truncated_for_backup": True}


def _compact_clients_response(value: Any) -> dict[str, Any] | None:
    """The complete client rows are already captured as service summaries; avoid saving them twice."""
    compact = _compact_api_response(value, max_bytes=0)
    if not isinstance(value, dict):
        return compact
    original_root = value.get("result")
    if isinstance(original_root, dict):
        root = {k: copy.deepcopy(v) for k, v in original_root.items()
                if not (k in {"list", "clients", "items"} and isinstance(v, list))
                and not (k == "services" and isinstance(v, list))}
        rows, reported = service_list_from(value)
        root.setdefault("count", len(rows))
        root.setdefault("total", reported if reported is not None else len(rows))
        root["service_rows_saved_separately"] = True
        return {"ok": value.get("ok") is True, "error": str(value.get("error") or "")[:500],
                "http_code": value.get("http_code"), "result": root, "compacted": True}
    rows, reported = service_list_from(value)
    return {"ok": value.get("ok") is True, "error": str(value.get("error") or "")[:500],
            "http_code": value.get("http_code"),
            "result": {"count": len(rows), "total": reported if reported is not None else len(rows),
                       "service_rows_saved_separately": True}, "compacted": True}


def _backup_one_service(mode: str, item: dict[str, Any]) -> dict[str, Any]:
    username = str(item.get("username", "")).strip().upper()
    owner = owner_for(mode, username) or str(item.get("owner", ""))[:120]
    summary = copy.deepcopy(item)
    summary["username"] = username
    summary["owner"] = owner
    detail = None
    detail_response = None
    detail_error = ""
    if username:
        try:
            detail_response = api_request(mode, "info", {"username": username}, "GET", record=False)
            if detail_response.get("ok") is True:
                root = detail_response.get("result")
                detail = root.get("service") if isinstance(root, dict) and isinstance(root.get("service"), dict) else root
            else:
                detail_error = str(detail_response.get("error") or "دریافت جزئیات زنده ناموفق بود.")
                # Try the documented legacy method only as a read-only compatibility fallback.
                legacy = api_request(mode, "find", {"username": username}, "POST", record=False)
                if legacy.get("ok") is True:
                    root = legacy.get("result") if isinstance(legacy.get("result"), dict) else {}
                    service = root.get("service") if isinstance(root.get("service"), dict) else {}
                    latest = root.get("latest_info") if isinstance(root.get("latest_info"), dict) else {}
                    online = root.get("online_info") if isinstance(root.get("online_info"), dict) else {}
                    detail = {**latest, **online, **service}
                    detail.setdefault("username", username)
                    detail_response = legacy
                    detail_error = ""
        except Exception as exc:
            detail_error = str(exc)[:300]
    if not isinstance(detail, dict):
        detail = None
    elif detail is not None:
        detail = copy.deepcopy(detail)
        detail.setdefault("username", username)
        detail["owner"] = owner
    return {
        "username": username,
        "owner": owner,
        "summary": summary,
        "details": detail,
        "detail_complete": isinstance(detail, dict),
        "detail_error": detail_error[:300],
        "detail_response": _compact_api_response(detail_response),
    }


def _collect_api_backup(mode: str, job_id: str, include_details: bool) -> dict[str, Any]:
    mode = valid_mode(mode)
    with LOCK:
        api_config = copy.deepcopy(STORE.get("apis", {}).get(mode, {}))
    configured = bool(str(api_config.get("api_key", "")).strip())
    snapshot: dict[str, Any] = {
        "mode": mode,
        "label": MODE_LABELS[mode],
        "api_url": api_url_for(mode),
        "configured": configured,
        "captured_at": now_iso(),
        "account_response": None,
        "status_response": None,
        "hosts_response": None,
        "clients_response": None,
        "service_count_reported": 0,
        "service_count_captured": 0,
        "services": [],
        "errors": [],
        "details_requested": bool(include_details),
        "details_complete": False,
    }
    if not configured:
        snapshot["errors"].append("برای این حساب کلید API ذخیره نشده است؛ اطلاعات زنده دریافت نشد.")
        _backup_progress(job_id, stage=f"حساب {MODE_LABELS[mode]} کلید ندارد؛ مرحله بعدی", current_mode=mode)
        return snapshot

    _backup_progress(job_id, stage=f"دریافت اطلاعات حساب {MODE_LABELS[mode]}", current_mode=mode)
    try:
        snapshot["account_response"] = api_request(mode, "me", {}, "GET", record=False)
        if not snapshot["account_response"].get("ok"):
            snapshot["errors"].append("me: " + str(snapshot["account_response"].get("error") or "پاسخ موفق نبود")[:300])
    except Exception as exc:
        snapshot["errors"].append("me: " + str(exc)[:300])
    try:
        snapshot["status_response"] = api_request(mode, "status", {}, "GET", record=False)
        if not snapshot["status_response"].get("ok"):
            snapshot["errors"].append("status: " + str(snapshot["status_response"].get("error") or "پاسخ موفق نبود")[:300])
    except Exception as exc:
        snapshot["errors"].append("status: " + str(exc)[:300])
    try:
        snapshot["hosts_response"] = api_request(mode, "get_hosts", {}, "GET", record=False)
        if not snapshot["hosts_response"].get("ok"):
            snapshot["errors"].append("get_hosts: " + str(snapshot["hosts_response"].get("error") or "پاسخ موفق نبود")[:300])
    except Exception as exc:
        snapshot["errors"].append("get_hosts: " + str(exc)[:300])

    try:
        first = api_request(mode, "clients", {}, "GET", record=False)
        snapshot["clients_response"] = _compact_clients_response(first)
    except Exception as exc:
        snapshot["errors"].append("clients: " + str(exc)[:300])
        return snapshot

    if not isinstance(first, dict) or first.get("ok") is not True:
        error = str((first or {}).get("error", "")) if isinstance(first, dict) else "پاسخ نامعتبر"
        if error.lower() == "no service":
            raw_items, reported = [], 0
        else:
            snapshot["errors"].append("clients: " + (error or "دریافت فهرست سرویس‌ها ناموفق بود")[:300])
            return snapshot
    else:
        raw_items, reported = service_list_from(first)
    seen: set[str] = set()
    all_items: list[dict[str, Any]] = []
    for item in raw_items:
        username = str(item.get("username", "")).strip().upper()
        if username and username not in seen:
            seen.add(username)
            all_items.append(item)
    reported = int(reported or len(all_items))
    snapshot["service_count_reported"] = reported

    # The API documents no-argument clients as returning all entries. If it returns a partial page,
    # continue using limit/offset so older deployments do not silently lose services in the backup.
    while len(all_items) < reported and len(all_items) < BACKUP_MAX_SERVICES:
        offset = len(all_items)
        page_limit = min(500, BACKUP_MAX_SERVICES - offset)
        try:
            page = api_request(mode, "clients", {"limit": page_limit, "offset": offset}, "GET", record=False)
        except Exception as exc:
            snapshot["errors"].append("clients pagination: " + str(exc)[:300])
            break
        if not isinstance(page, dict) or page.get("ok") is not True:
            err = str(page.get("error", "")) if isinstance(page, dict) else "پاسخ نامعتبر"
            snapshot["errors"].append("clients pagination: " + (err or "صفحه بعدی دریافت نشد")[:300])
            break
        page_items, page_total = service_list_from(page)
        added = 0
        for item in page_items:
            username = str(item.get("username", "")).strip().upper()
            if username and username not in seen:
                seen.add(username)
                all_items.append(item)
                added += 1
        if page_total and page_total > reported:
            reported = page_total
            snapshot["service_count_reported"] = reported
        if added == 0:
            break
    if reported > BACKUP_MAX_SERVICES:
        snapshot["errors"].append(f"تعداد سرویس‌ها از سقف پشتیبان این نسخه ({BACKUP_MAX_SERVICES}) بیشتر است؛ خروجی به سقف محدود شد.")
        all_items = all_items[:BACKUP_MAX_SERVICES]

    _backup_progress(job_id, stage=f"فهرست {MODE_LABELS[mode]} دریافت شد", current_mode=mode,
                     total_services=int((BACKUP_JOBS.get(job_id) or {}).get("total_services", 0)) + len(all_items),
                     completed_services=int((BACKUP_JOBS.get(job_id) or {}).get("completed_services", 0)))
    if not include_details and all_items:
        with BACKUP_JOB_LOCK:
            job = BACKUP_JOBS.get(job_id, {})
            next_done = int(job.get("completed_services", 0)) + len(all_items)
            next_total = int(job.get("total_services", 0))
        _backup_progress(job_id, stage=f"خلاصهٔ {len(all_items)} سرویس {MODE_LABELS[mode]} آماده شد",
                         completed_services=next_done, total_services=next_total)
    if include_details and all_items:
        mode_results: list[dict[str, Any]] = []
        total_combined = int((BACKUP_JOBS.get(job_id) or {}).get("total_services", 0))
        completed_combined = int((BACKUP_JOBS.get(job_id) or {}).get("completed_services", 0))
        _backup_progress(job_id, stage=f"دریافت جزئیات {len(all_items)} سرویس {MODE_LABELS[mode]}", total_services=total_combined, completed_services=completed_combined)
        with ThreadPoolExecutor(max_workers=BACKUP_WORKERS) as pool:
            futures = {pool.submit(_backup_one_service, mode, item): item for item in all_items}
            for future in as_completed(futures):
                item = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    username = str(item.get("username", "")).strip().upper()
                    result = {"username": username, "owner": owner_for(mode, username), "summary": item,
                              "details": None, "detail_complete": False, "detail_error": str(exc)[:300], "detail_response": None}
                mode_results.append(result)
                with BACKUP_JOB_LOCK:
                    job = BACKUP_JOBS.get(job_id, {})
                    job["completed_services"] = int(job.get("completed_services", 0)) + 1
                    job["stage"] = f"جزئیات {MODE_LABELS[mode]}: {job['completed_services']} از {job.get('total_services', 0)}"
                    job["updated_at"] = time.time()
        # API list order is retained despite asynchronous detail requests.
        order = {str(x.get("username", "")).upper(): i for i, x in enumerate(all_items)}
        mode_results.sort(key=lambda x: order.get(str(x.get("username", "")).upper(), 10**9))
        snapshot["services"] = mode_results
        snapshot["details_complete"] = all(x.get("detail_complete") for x in mode_results)
        incomplete = sum(1 for x in mode_results if not x.get("detail_complete"))
        if incomplete:
            snapshot["errors"].append(f"جزئیات زندهٔ {incomplete} سرویس دریافت نشد؛ اطلاعات فهرست و علت خطا در پشتیبان باقی مانده است.")
    else:
        snapshot["services"] = [
            {"username": str(x.get("username", "")).strip().upper(), "owner": owner_for(mode, str(x.get("username", "")).strip().upper()) or str(x.get("owner", "")),
             "summary": {**copy.deepcopy(x), "owner": owner_for(mode, str(x.get("username", "")).strip().upper()) or str(x.get("owner", ""))},
             "details": None, "detail_complete": False, "detail_error": "جزئیات عمیق سرویس در این نوع پشتیبان درخواست نشده است.", "detail_response": None}
            for x in all_items
        ]
    snapshot["service_count_captured"] = len(snapshot["services"])
    if reported > len(all_items):
        snapshot["errors"].append(f"فهرست ناقص است: {len(all_items)} از {reported} سرویس دریافت شد.")
    return snapshot


def _run_backup_job(job_id: str, options: dict[str, Any]) -> None:
    try:
        include_secrets = bool(options.get("include_secrets", True))
        include_details = bool(options.get("include_service_details", True))
        with LOCK:
            local = json.loads(json.dumps(STORE, ensure_ascii=False))
            last_responses_snapshot = copy.deepcopy(LAST_RESPONSES)
        _backup_progress(job_id, stage="آماده‌سازی پشتیبان مشترک مستقیم و تانل", total_services=0, completed_services=0, current_mode="all")
        accounts: dict[str, Any] = {}
        for mode in API_URLS:
            accounts[mode] = _collect_api_backup(mode, job_id, include_details)
        # Include all owner metadata, including owners seen in returned service snapshots.
        owners = _safe_owner_map(local.get("owners", {}))
        for mode in API_URLS:
            for service in accounts[mode].get("services", []):
                username, owner = service.get("username"), service.get("owner")
                if username and owner and username not in owners[mode]:
                    owners[mode][username] = owner
        api_settings: dict[str, Any] = {}
        for mode in API_URLS:
            entry = local.get("apis", {}).get(mode, {}) if isinstance(local.get("apis"), dict) else {}
            item = {"api_url": api_url_for(mode), "configured": bool(str(entry.get("api_key", "")).strip())}
            if include_secrets:
                item["api_key"] = str(entry.get("api_key", ""))
            api_settings[mode] = item
        settings: dict[str, Any] = {
            "apis": api_settings,
            "owners": owners,
            "logs": _safe_logs(local.get("logs", [])),
            "preferences": copy.deepcopy(local.get("preferences", {})),
        }
        if include_secrets:
            settings["auth"] = copy.deepcopy(local.get("auth", {}))
        backup = {
            "format": "ALI-VPN-FULL-BACKUP-v2",
            "schema_version": 2,
            "app": {"name": "ALI VPN PANEL", "version": "1.1.0"},
            "exported_at": now_iso(),
            "included": {
                "direct": True, "tunnel": True, "service_summaries": True,
                "full_service_details": include_details,
                "api_keys": include_secrets,
                "panel_login_hash": include_secrets,
                "panel_preferences": True, "owner_metadata": True, "operation_logs": True,
            },
            "settings": settings,
            "accounts": accounts,
            "last_responses": {mode: _compact_api_response(response) for mode, response in last_responses_snapshot.items()},
            "restore_notes": [
                "یک فایل واحد شامل هر دو حساب مستقیم و تانل است.",
                "جزئیات سرویس‌ها و لینک‌ها اسنپ‌شات مرجع هستند؛ سرویس‌های واقعی در سمت سرور API قرار دارند و با واردکردن فایل ساخته یا حذف نمی‌شوند.",
                "اگر این پشتیبان شامل کلید API باشد، فایل محرمانه است.",
            ],
        }
        raw = json.dumps(backup, ensure_ascii=False, indent=2).encode("utf-8")
        with BACKUP_JOB_LOCK:
            job = BACKUP_JOBS.get(job_id)
            if job is not None:
                job.update({"status": "complete", "stage": "پشتیبان آمادهٔ دانلود است", "progress": 100,
                            "completed_at": time.time(), "result": raw, "file_name": f"ALI-VPN-FULL-BACKUP-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"})
    except Exception as exc:
        _backup_progress(job_id, status="failed", stage="ساخت پشتیبان ناموفق بود", error=str(exc)[:1000], completed_at=time.time())


def start_backup_job(options: dict[str, Any]) -> str:
    now = time.time()
    with BACKUP_JOB_LOCK:
        for old_id, job in list(BACKUP_JOBS.items()):
            finished = job.get("completed_at")
            if finished and now - float(finished) > 3600:
                BACKUP_JOBS.pop(old_id, None)
        active = sum(1 for job in BACKUP_JOBS.values() if job.get("status") == "running")
        if active >= BACKUP_MAX_ACTIVE_JOBS:
            raise RuntimeError("یک پشتیبان‌گیری دیگر در حال اجراست؛ پس از پایان آن دوباره تلاش کن.")
        job_id = uuid.uuid4().hex
        BACKUP_JOBS[job_id] = {"status": "running", "stage": "در صف آماده‌سازی", "progress": 0,
                               "total_services": 0, "completed_services": 0, "current_mode": "all",
                               "created_at": now, "updated_at": now}
    if IS_VERCEL:
        # Detached threads are not reliable in serverless functions; run within the request.
        _run_backup_job(job_id, dict(options))
        _persist_backup_job(job_id)
    else:
        threading.Thread(target=_run_backup_job, args=(job_id, dict(options)), daemon=True, name=f"backup-{job_id[:8]}").start()
    return job_id



def _persist_backup_job(job_id: str) -> None:
    if not IS_VERCEL:
        return
    with BACKUP_JOB_LOCK:
        job = BACKUP_JOBS.get(job_id)
        if not job:
            return
        result = job.get("result")
        result_b64 = base64.b64encode(result).decode("ascii") if isinstance(result, bytes) else None
        if isinstance(result, bytes) and len(result) > 4 * 1024 * 1024:
            job.update({"status": "failed", "stage": "فایل پشتیبان از سقف نسخهٔ Vercel بزرگ‌تر است",
                        "error": "حجم پشتیبان بیشتر از ۴ مگابایت است؛ این نسخه برای ذخیرهٔ موقت دانلود، فایل‌های بزرگ را در KV نگه نمی‌دارد.",
                        "result": None})
            result_b64 = None
        saved = {k: v for k, v in job.items() if k != "result"}
        if result_b64 is not None:
            saved["result_b64"] = result_b64
        encoded = json.dumps(saved, ensure_ascii=False, separators=(",", ":"))
    _kv_command(["SET", _backup_key(job_id), encoded, "EX", 3600])


def _get_backup_job(job_id: str) -> dict[str, Any] | None:
    if IS_VERCEL:
        saved = _kv_command(["GET", _backup_key(job_id)])
        if not isinstance(saved, str):
            return None
        try:
            job = json.loads(saved)
            if not isinstance(job, dict):
                return None
            result_b64 = job.pop("result_b64", None)
            job["result"] = base64.b64decode(result_b64, validate=True) if isinstance(result_b64, str) else None
            with BACKUP_JOB_LOCK:
                BACKUP_JOBS[job_id] = job
            return job
        except Exception:
            return None
    with BACKUP_JOB_LOCK:
        return BACKUP_JOBS.get(job_id)

def restore_full_backup(value: dict[str, Any]) -> dict[str, Any]:
    if value.get("format") != "ALI-VPN-FULL-BACKUP-v2" or not isinstance(value.get("settings"), dict):
        raise ValueError("قالب پشتیبان کامل ALI VPN معتبر نیست.")
    settings = value["settings"]
    # A restore is a security boundary: revoke old Vercel sessions even if an old
    # password hash is re-imported from a backup.
    required_dicts = ("apis", "owners", "preferences")
    for key in required_dicts:
        if not isinstance(settings.get(key), dict):
            raise ValueError(f"بخش {key} در فایل پشتیبان وجود ندارد یا معتبر نیست.")
    if not isinstance(settings.get("logs"), list):
        raise ValueError("فهرست گزارش‌های محلی در فایل پشتیبان معتبر نیست.")
    for mode in API_URLS:
        if not isinstance(settings["apis"].get(mode), dict):
            raise ValueError(f"تنظیمات حساب {MODE_LABELS[mode]} در فایل پشتیبان ناقص است.")
        if not isinstance(settings["owners"].get(mode), dict):
            raise ValueError(f"فهرست مالکان حساب {MODE_LABELS[mode]} در فایل پشتیبان ناقص است.")
    if not isinstance(value.get("accounts"), dict):
        raise ValueError("اسنپ‌شات حساب‌های مستقیم و تانل در فایل پشتیبان وجود ندارد.")
    for mode in API_URLS:
        account = value["accounts"].get(mode)
        if not isinstance(account, dict) or not isinstance(account.get("services"), list):
            raise ValueError(f"اسنپ‌شات سرویس‌های حساب {MODE_LABELS[mode]} در فایل پشتیبان معتبر نیست.")
    included = value.get("included") if isinstance(value.get("included"), dict) else {}
    include_secrets = included.get("api_keys") is True
    new_owners = _safe_owner_map(settings.get("owners", {}))
    # Service snapshots also carry owner names, so recover them if the owner map is missing an entry.
    accounts = value.get("accounts") if isinstance(value.get("accounts"), dict) else {}
    for mode in API_URLS:
        block = accounts.get(mode) if isinstance(accounts.get(mode), dict) else {}
        services = block.get("services") if isinstance(block.get("services"), list) else []
        for service in services:
            if not isinstance(service, dict):
                continue
            username = str(service.get("username", "")).strip().upper()[:80]
            owner = str(service.get("owner", "")).strip()[:120]
            if username and owner and username not in new_owners[mode]:
                new_owners[mode][username] = owner

    # Validate every field before mutating STORE; a malformed import must not partially restore settings.
    api_settings = settings.get("apis") if isinstance(settings.get("apis"), dict) else {}
    with LOCK:
        current_apis = copy.deepcopy(STORE.get("apis", {}))
    new_apis: dict[str, dict[str, str]] = {}
    for mode in API_URLS:
        current = copy.deepcopy(current_apis.get(mode, {}))
        incoming = api_settings.get(mode, {}) if isinstance(api_settings.get(mode, {}), dict) else {}
        if "api_url" in incoming:
            current["api_url"] = validate_api_url(mode, str(incoming.get("api_url") or API_URLS[mode]))
        if include_secrets:
            if "api_key" not in incoming:
                raise ValueError(f"پشتیبان کامل اعلام کرده کلیدها را دارد، اما کلید بخش {MODE_LABELS[mode]} موجود نیست.")
            key = str(incoming.get("api_key") or "").strip()
            if incoming.get("configured") is True and not key:
                raise ValueError(f"پشتیبان اعلام کرده API بخش {MODE_LABELS[mode]} تنظیم شده، اما کلید آن خالی است.")
            if len(key) > 512 or any(ord(ch) > 127 or ch.isspace() for ch in key):
                raise ValueError(f"کلید API بخش {MODE_LABELS[mode]} در فایل معتبر نیست.")
            current["api_key"] = key
        current.setdefault("api_key", "")
        new_apis[mode] = current

    prefs = settings.get("preferences") if isinstance(settings.get("preferences"), dict) else {}
    theme = prefs.get("theme", "obsidian")
    if theme not in THEMES:
        theme = "obsidian"
    mode_pref = prefs.get("last_mode", "direct")
    if mode_pref not in API_URLS:
        mode_pref = "direct"
    view_pref = prefs.get("last_view", "dashboard")
    if view_pref not in {"dashboard", "services", "create", "locations", "apilab", "logs", "settings"}:
        view_pref = "dashboard"
    try:
        page_size = max(10, min(100, int(prefs.get("service_page_size", 25))))
    except (TypeError, ValueError):
        page_size = 25
    new_preferences = {"theme": theme, "last_mode": mode_pref, "last_view": view_pref, "service_page_size": page_size}

    safe_logs = _safe_logs(settings.get("logs", []))

    incoming_last_responses = value.get("last_responses", {})
    if not isinstance(incoming_last_responses, dict):
        raise ValueError("ساختار پاسخ‌های آخر در فایل پشتیبان معتبر نیست.")
    new_last_responses: dict[str, dict[str, Any] | None] = {"direct": None, "tunnel": None}
    for mode in API_URLS:
        response = incoming_last_responses.get(mode)
        if response is None:
            new_last_responses[mode] = None
        elif isinstance(response, dict):
            try:
                response_size = len(json.dumps(response, ensure_ascii=False).encode("utf-8"))
            except (TypeError, ValueError):
                raise ValueError(f"پاسخ ذخیره‌شدهٔ حساب {MODE_LABELS[mode]} قابل پردازش نیست.")
            if response_size > 2 * 1024 * 1024:
                # Last API responses are an inspector convenience; a huge list response
                # is already represented in the account snapshot and is not needed to restore operation.
                new_last_responses[mode] = None
            else:
                new_last_responses[mode] = copy.deepcopy(response)
        else:
            raise ValueError(f"ساختار پاسخ ذخیره‌شدهٔ حساب {MODE_LABELS[mode]} معتبر نیست.")

    new_auth = None
    auth = settings.get("auth")
    if include_secrets:
        if not isinstance(auth, dict):
            raise ValueError("تنظیمات ورود در پشتیبان کامل وجود ندارد.")
        salt, digest = str(auth.get("salt", "")), str(auth.get("hash", ""))
        if len(salt) != 32 or len(digest) != 64:
            raise ValueError("ساختار رمز هش‌شدهٔ ورود در پشتیبان معتبر نیست.")
        try:
            bytes.fromhex(salt); bytes.fromhex(digest)
        except ValueError as exc:
            raise ValueError("هش رمز ورود در پشتیبان معتبر نیست.") from exc
        new_auth = {"salt": salt, "hash": digest, "updated_at": str(auth.get("updated_at") or now_iso())}

    with LOCK:
        STORE["apis"] = new_apis
        STORE["owners"] = new_owners
        STORE["logs"] = safe_logs
        STORE["preferences"] = new_preferences
        if new_auth is not None:
            STORE["auth"] = new_auth
        STORE["session_version"] = uuid.uuid4().hex
        _write_store(STORE)
        LAST_RESPONSES.update(new_last_responses)
    return {"owners": sum(len(v) for v in new_owners.values()), "logs": len(safe_logs), "includes_secrets": include_secrets,
            "last_responses_restored": sum(1 for v in new_last_responses.values() if v is not None)}

def local_ip_addresses() -> list[str]:
    found: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET, socket.SOCK_STREAM):
            ip = info[4][0]
            if not ip.startswith("127.") and not ip.startswith("169.254."):
                found.add(ip)
    except Exception:
        pass
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("192.0.2.1", 80))
        ip = sock.getsockname()[0]
        sock.close()
        if not ip.startswith("127."):
            found.add(ip)
    except Exception:
        pass
    return sorted(found)


def http_status_for_exception(exc: Exception) -> int:
    """Keep client input errors distinct from upstream and internal failures."""
    message = str(exc).casefold()
    if isinstance(exc, (TimeoutError, socket.timeout)) or "زمان انتظار" in message or "timeout" in message or "timed out" in message:
        return 504
    if isinstance(exc, urllib.error.URLError) or any(token in message for token in ("خطای اتصال به api", "خطای ارتباطی", "هدایت خودکار متوقف شد")):
        return 502
    if isinstance(exc, (ValueError, TypeError, json.JSONDecodeError)):
        return 400
    if isinstance(exc, RuntimeError):
        # RuntimeError is also used for missing local configuration and validation.
        if "هنوز کلید وارد نشده" in message or "مجاز نیست" in message or "معتبر نیست" in message:
            return 400
        if "خطای اتصال به api" in message or "خطای ارتباطی" in message:
            return 502
        return 502 if "api" in message else 400
    return 500


def parse_json_body(handler: BaseHTTPRequestHandler, max_bytes: int = 1_000_000) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0") or 0)
    if length < 0:
        raise ValueError("طول بدنهٔ درخواست معتبر نیست.")
    if length > max_bytes:
        raise ValueError(f"درخواست بزرگ‌تر از حد مجاز است ({max_bytes // (1024 * 1024)} مگابایت).")
    raw = handler.rfile.read(length) if length else b"{}"
    try:
        value = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError("JSON درخواست معتبر نیست.") from exc
    if not isinstance(value, dict):
        raise ValueError("بدنهٔ درخواست باید یک شیء JSON باشد.")
    return value


class Handler(BaseHTTPRequestHandler):
    server_version = "ALIVPNPanel/1.0"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        # Bound slow/incomplete client connections so one socket cannot stay open forever.
        self.connection.settimeout(15)

    def log_message(self, fmt: str, *args: Any) -> None:
        # Keep routine requests out of console; never log secrets.
        return

    def send_json(self, value: Any, status: int = 200, headers: dict[str, str] | None = None) -> None:
        raw = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def send_html(self) -> None:
        path = STATIC_DIR / "index.html"
        if not path.exists():
            self.send_error(500, "static/index.html is missing")
            return
        raw = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(raw)

    def client_ip(self) -> str:
        return self.client_address[0] if self.client_address else "unknown"

    def current_session(self) -> str | None:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            morsel = cookie.get("ali_vpn_session")
            sid = morsel.value if morsel else None
        except Exception:
            sid = None
        if sid:
            if IS_VERCEL:
                try:
                    version = _kv_command(["GET", _session_key(sid)])
                    current_version = str(STORE.get("session_version", ""))
                    return sid if version is not None and str(version) == current_version and current_version else None
                except Exception:
                    return None
            with LOCK:
                expires = SESSIONS.get(sid, 0)
                if expires > time.time():
                    SESSIONS[sid] = time.time() + 10 * 60 * 60
                    return sid
                SESSIONS.pop(sid, None)
        return None

    def require_auth(self) -> bool:
        if self.current_session():
            return True
        self.send_json({"ok": False, "error": "نشست واردشده معتبر نیست؛ دوباره وارد شوید.", "auth_required": True}, 401)
        return False

    def check_same_origin(self) -> bool:
        origin = self.headers.get("Origin")
        referer = self.headers.get("Referer")
        req_host = self.headers.get("Host", "").strip().lower()
        try:
            host_parts = urllib.parse.urlsplit("//" + req_host)
            hostname = (host_parts.hostname or "").lower()
            allowed = {"localhost", "127.0.0.1", "::1", socket.gethostname().lower()}
            try: allowed.update(ip.lower() for ip in local_ip_addresses())
            except Exception: pass
            if IS_VERCEL and hostname:
                # Vercel validates routing hosts; the Origin/Referer must still exactly match Host below.
                allowed.add(hostname)
            if hostname not in allowed:
                return False
            if host_parts.port is not None and host_parts.port != self.server.server_port:
                return False
            # Browsers include Origin for JSON POSTs; command-line/local clients may not.
            # When Origin is absent, the local Host allowlist still prevents arbitrary Host
            # values and authentication remains required for every private route.
            if not origin and not referer:
                return True
            candidate = urllib.parse.urlparse(origin or referer or "")
            return bool(candidate.scheme in {"http", "https"} and candidate.netloc.lower() == req_host)
        except Exception:
            return False

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        if path in ("/", "/index.html"):
            self.send_html(); return
        if path == "/favicon.ico":
            self.send_response(204); self.end_headers(); return
        if path == "/api/auth/check":
            if IS_VERCEL and not storage_is_configured():
                self.send_json({"ok": True, "authenticated": False, "setup_required": False,
                                "storage_configured": False,
                                "setup_message": "برای نگه‌داری امن تنظیمات، ابتدا در Vercel از Storage یک Upstash Redis به پروژه متصل کن و دوباره Deploy بگیر."}); return
            try:
                setup_required = not bool(STORE.get("auth", {}).get("salt") and STORE.get("auth", {}).get("hash"))
                setup_token_ready = len(os.environ.get("ALI_VPN_SETUP_TOKEN", "").strip()) >= 32 if IS_VERCEL else True
                self.send_json({"ok": True, "authenticated": bool(self.current_session()),
                                "setup_required": setup_required, "setup_allowed": setup_token_ready,
                                "setup_message": ("برای جلوگیری از تصاحب اولیهٔ پنل، متغیر ALI_VPN_SETUP_TOKEN را در Vercel تنظیم کن و دوباره Deploy بگیر." if setup_required and not setup_token_ready else ""),
                                "storage_configured": storage_is_configured(), "name": "مدیر پنل"})
            except Exception as exc:
                self.send_json({"ok": False, "authenticated": False, "storage_configured": storage_is_configured(),
                                "error": str(exc), "setup_message": str(exc)}, 503)
            return
        if not path.startswith("/api/"):
            self.send_json({"ok": False, "error": "مسیر پیدا نشد."}, 404); return
        if not self.require_auth(): return
        try:
            if path == "/api/config":
                mode = valid_mode((query.get("mode") or ["direct"])[0])
                with LOCK:
                    key = str(STORE["apis"][mode].get("api_key", ""))
                self.send_json({"ok": True, "mode": mode, "api_url": api_url_for(mode), "default_api_url": API_URLS[mode], "configured": bool(key), "masked_key": ((("•" * (len(key) - 4)) + key[-4:]) if len(key) > 8 else ("•" * len(key))) if key else "", "configured_modes": {m: bool(STORE["apis"][m].get("api_key")) for m in API_URLS}, "panel_ips": [] if IS_VERCEL else local_ip_addresses(), "port": self.server.server_port}); return
            if path == "/api/preferences":
                with LOCK:
                    prefs = copy.deepcopy(STORE.get("preferences", {}))
                self.send_json({"ok": True, "preferences": prefs}); return
            if path == "/api/data/export/status":
                job_id = (query.get("id") or [""])[0]
                job = _get_backup_job(job_id)
                if job is None:
                    self.send_json({"ok": False, "error": "وظیفهٔ پشتیبان پیدا نشد یا منقضی شده است."}, 404); return
                view = {k: job.get(k) for k in ("status", "stage", "progress", "total_services", "completed_services", "current_mode", "error")}
                if job.get("status") == "complete": view["ready_to_download"] = True
                self.send_json({"ok": True, **view}); return
            if path == "/api/data/export/download":
                job_id = (query.get("id") or [""])[0]
                job = _get_backup_job(job_id)
                if not job or job.get("status") != "complete" or not isinstance(job.get("result"), bytes):
                    self.send_json({"ok": False, "error": (job or {}).get("error") or "فایل پشتیبان هنوز آماده نیست."}, 409); return
                raw = job["result"]
                file_name = job.get("file_name", "ALI-VPN-FULL-BACKUP.json")
                self.send_response(200); self.send_header("Content-Type", "application/json; charset=utf-8"); self.send_header("Content-Disposition", f'attachment; filename="{file_name}"'); self.send_header("Content-Length", str(len(raw))); self.send_header("Cache-Control", "no-store"); self.send_header("X-Content-Type-Options", "nosniff"); self.end_headers(); self.wfile.write(raw)
                with BACKUP_JOB_LOCK: BACKUP_JOBS.pop(job_id, None)
                if IS_VERCEL:
                    _kv_command(["DEL", _backup_key(job_id)])
                return
            if path == "/api/dashboard":
                mode = valid_mode((query.get("mode") or ["direct"])[0])
                me_result = api_request(mode, "me", {}, "GET")
                account = me_result.get("result") if isinstance(me_result.get("result"), dict) else {}
                status_result = None
                if me_result.get("ok") is not True:
                    status_result = api_request(mode, "status", {}, "GET")
                    account = status_result.get("result") if isinstance(status_result.get("result"), dict) else {}
                totals = account.get("services") if isinstance(account.get("services"), dict) else {}
                if not totals and isinstance(account, dict):
                    totals = {"total": account.get("count_services"), "active": account.get("count_active_services")}
                self.send_json({"ok": me_result.get("ok") is True or bool(status_result and status_result.get("ok") is True), "mode": mode, "account": account, "services": totals, "response": me_result if me_result.get("ok") is True else status_result or me_result, "me_response": me_result}); return
            if path == "/api/services":
                mode = valid_mode((query.get("mode") or ["direct"])[0])
                limit = int((query.get("limit") or ["50"])[0]); offset = int((query.get("offset") or ["0"])[0])
                search = (query.get("q") or [""])[0]
                status_filter = (query.get("status") or ["all"])[0]
                service_type = (query.get("type") or ["all"])[0]
                sort_by = (query.get("sort") or ["api"])[0]
                sort_dir = (query.get("order") or ["asc"])[0]
                self.send_json(get_clients(mode, limit, offset, search, status_filter, service_type, sort_by, sort_dir)); return
            if path == "/api/service/detail":
                mode = valid_mode((query.get("mode") or ["direct"])[0])
                username = (query.get("username") or [""])[0]
                self.send_json(get_service(mode, username)); return
            if path == "/api/locations":
                mode = valid_mode((query.get("mode") or ["direct"])[0])
                res = api_request(mode, "get_hosts", {}, "GET")
                self.send_json({"ok": res.get("ok") is True, "result": res.get("result", {}), "raw": res, "error": res.get("error", "")}); return
            if path == "/api/logs":
                mode = (query.get("mode") or ["all"])[0]
                with LOCK:
                    logs = list(STORE.get("logs", []))
                if mode in API_URLS:
                    logs = [x for x in logs if x.get("mode") == mode]
                self.send_json({"ok": True, "logs": logs[:200]}); return
            if path == "/api/last-response":
                mode = valid_mode((query.get("mode") or ["direct"])[0])
                self.send_json({"ok": True, "response": LAST_RESPONSES.get(mode)}); return
            if path == "/api/phone-info":
                self.send_json({"ok": True, "ips": [] if IS_VERCEL else local_ip_addresses(), "port": self.server.server_port, "hosted": IS_VERCEL}); return
            if path == "/api/data/export":
                with LOCK:
                    export = {"format": "ALI-VPN-LOCAL-METADATA-v1", "exported_at": now_iso(), "owners": STORE.get("owners", {})}
                raw = json.dumps(export, ensure_ascii=False, indent=2).encode("utf-8")
                self.send_response(200); self.send_header("Content-Type", "application/json; charset=utf-8"); self.send_header("Content-Disposition", 'attachment; filename="ali-vpn-metadata-legacy.json"'); self.send_header("Content-Length", str(len(raw))); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(raw); return
            self.send_json({"ok": False, "error": "مسیر API پیدا نشد."}, 404)
        except Exception as exc:
            self.send_json({"ok": False, "error": str(exc)}, http_status_for_exception(exc))

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/api/login":
            self.handle_login(); return
        if path == "/api/setup":
            self.handle_setup(); return
        if not path.startswith("/api/"):
            self.send_json({"ok": False, "error": "مسیر پیدا نشد."}, 404); return
        if not self.check_same_origin():
            self.send_json({"ok": False, "error": "درخواست با مبدأ غیرمجاز رد شد."}, 403); return
        if path != "/api/logout" and not self.require_auth(): return
        try:
            body = parse_json_body(self, max_bytes=100 * 1024 * 1024 if path == "/api/data/import" else 1_000_000)
            if path == "/api/logout":
                sid = self.current_session()
                if sid:
                    try: _revoke_session(sid)
                    except Exception as exc:
                        self.send_json({"ok": False, "error": str(exc)}, 503); return
                cookie = SimpleCookie(); cookie["ali_vpn_session"] = ""; cookie["ali_vpn_session"]["path"] = "/"; cookie["ali_vpn_session"]["max-age"] = 0; cookie["ali_vpn_session"]["httponly"] = True; cookie["ali_vpn_session"]["samesite"] = "Strict"
                if IS_VERCEL or getattr(self, "is_secure", False): cookie["ali_vpn_session"]["secure"] = True
                self.send_json({"ok": True}, headers={"Set-Cookie": cookie.output(header="").strip()}); return
            if path == "/api/logs/clear":
                mode_to_clear = str(body.get("mode", "all"))
                if mode_to_clear not in {"all", "direct", "tunnel"}:
                    raise ValueError("بخش انتخاب‌شده برای پاک‌کردن گزارش‌ها معتبر نیست.")
                with LOCK:
                    previous_logs = copy.deepcopy(STORE.get("logs", []))
                    if mode_to_clear == "all":
                        STORE["logs"] = []
                    else:
                        STORE["logs"] = [row for row in previous_logs if not (isinstance(row, dict) and row.get("mode") == mode_to_clear)]
                    try:
                        _write_store(STORE)
                    except Exception:
                        STORE["logs"] = previous_logs
                        raise
                    remaining = len(STORE["logs"])
                self.send_json({"ok": True, "message": "گزارش‌های انتخاب‌شده پاک شدند.", "remaining": remaining})
                return
            if path == "/api/config/test":
                mode = valid_mode(str(body.get("mode", "direct")))
                try:
                    url = validate_api_url(mode, str(body.get("api_url", "")))
                    typed_key = str(body.get("api_key") or "").strip()
                    if typed_key:
                        try: typed_key.encode("ascii")
                        except UnicodeEncodeError: raise ValueError("کلید API باید فقط شامل کاراکترهای ASCII باشد.")
                        if len(typed_key) > 512: raise ValueError("کلید API بیش از حد طولانی است.")
                        key = typed_key
                    else:
                        with LOCK: key = str(STORE["apis"][mode].get("api_key", "")).strip()
                    result = api_request(mode, "me", {}, "GET", record=False,
                                         api_key_override=key, api_url_override=url)
                    ok = result.get("ok") is True
                    self.send_json({"ok": ok, "mode": mode, "response": result,
                                    "message": "اتصال با مقادیر فعلی فرم موفق بود." if ok else "اتصال با مقادیر فعلی فرم ناموفق بود."})
                except Exception as exc:
                    self.send_json({"ok": False, "mode": mode, "error": str(exc)}, http_status_for_exception(exc))
                return
            if path == "/api/config":
                mode = valid_mode(str(body.get("mode", "direct")))
                with LOCK:
                    if "api_url" in body:
                        STORE["apis"][mode]["api_url"] = validate_api_url(mode, str(body.get("api_url", "")))
                    if body.get("clear_key") is True:
                        STORE["apis"][mode]["api_key"] = ""
                    elif str(body.get("api_key", "")).strip():
                        key = "".join(str(body["api_key"]).replace("\u200b", "").replace("\ufeff", "").split())
                        try: key.encode("ascii")
                        except UnicodeEncodeError: raise ValueError("کلید API باید فقط شامل کاراکترهای ASCII باشد.")
                        if len(key) > 512: raise ValueError("کلید API بیش از حد طولانی است.")
                        STORE["apis"][mode]["api_key"] = key
                    _write_store(STORE)
                add_log({"mode": mode, "kind": "settings", "method": "save_api_settings", "ok": True, "at": now_iso()})
                self.send_json({"ok": True, "message": "تنظیمات حساب ذخیره شد."}); return
            if path == "/api/preferences":
                prefs = body.get("preferences") if isinstance(body.get("preferences"), dict) else body
                updates: dict[str, Any] = {}
                if "theme" in prefs:
                    theme = str(prefs.get("theme", ""))
                    if theme not in THEMES: raise ValueError("تم انتخاب‌شده معتبر نیست.")
                    updates["theme"] = theme
                if "last_mode" in prefs:
                    mode_pref = str(prefs.get("last_mode", ""))
                    if mode_pref not in API_URLS: raise ValueError("بخش انتخاب‌شده معتبر نیست.")
                    updates["last_mode"] = mode_pref
                if "last_view" in prefs:
                    view_pref = str(prefs.get("last_view", ""))
                    if view_pref not in {"dashboard", "services", "create", "locations", "apilab", "logs", "settings"}: raise ValueError("صفحهٔ انتخاب‌شده معتبر نیست.")
                    updates["last_view"] = view_pref
                if "service_page_size" in prefs:
                    try: updates["service_page_size"] = max(10, min(100, int(prefs.get("service_page_size"))))
                    except (TypeError, ValueError): raise ValueError("اندازهٔ صفحه معتبر نیست.")
                with LOCK:
                    STORE.setdefault("preferences", {}).update(updates)
                    _write_store(STORE)
                    saved = copy.deepcopy(STORE["preferences"])
                self.send_json({"ok": True, "preferences": saved}); return
            if path == "/api/data/export/start":
                options = {"include_secrets": body.get("include_secrets", True) is True,
                           "include_service_details": body.get("include_service_details", True) is True}
                job_id = start_backup_job(options)
                self.send_json({"ok": True, "job_id": job_id, "message": "ساخت پشتیبان کامل برای هر دو حساب شروع شد."}, 202); return
            if path == "/api/account/password":
                old = str(body.get("old_password", "")); new = str(body.get("new_password", ""))
                with LOCK: auth = dict(STORE.get("auth", {}))
                if not verify_password(old, auth.get("salt", ""), auth.get("hash", "")):
                    self.send_json({"ok": False, "error": "رمز فعلی درست نیست."}, 403); return
                if len(new) < 12:
                    self.send_json({"ok": False, "error": "رمز جدید باید حداقل ۱۲ کاراکتر داشته باشد."}, 400); return
                salt, digest = hash_password(new)
                cookie = SimpleCookie()
                try: cookie.load(self.headers.get("Cookie", "")); current_sid = cookie.get("ali_vpn_session").value if cookie.get("ali_vpn_session") else None
                except Exception: current_sid = None
                with LOCK:
                    STORE["auth"] = {"salt": salt, "hash": digest, "updated_at": now_iso()}
                    STORE["session_version"] = uuid.uuid4().hex
                    _write_store(STORE)
                    if IS_VERCEL and current_sid:
                        _kv_command(["SET", _session_key(current_sid), STORE["session_version"], "EX", 36000])
                    for sid in list(SESSIONS):
                        if sid != current_sid:
                            SESSIONS.pop(sid, None)
                add_log({"mode": "all", "kind": "security", "method": "change_password", "ok": True, "at": now_iso()})
                self.send_json({"ok": True, "message": "رمز پنل عوض شد؛ سایر نشست‌های قبلی باطل شدند."}); return
            if path == "/api/owner":
                mode = valid_mode(str(body.get("mode", "direct")))
                username = str(body.get("username", "")).strip().upper()
                owner = str(body.get("owner", "")).strip()
                if not username or len(username) > 80: raise ValueError("شناسه سرویس معتبر نیست.")
                with LOCK:
                    if owner: STORE["owners"][mode][username] = owner[:120]
                    else: STORE["owners"][mode].pop(username, None)
                    _write_store(STORE)
                add_log({"mode": mode, "kind": "local", "method": "set_owner", "username": username, "ok": True, "at": now_iso()})
                self.send_json({"ok": True, "owner": owner}); return
            if path == "/api/call":
                mode = valid_mode(str(body.get("mode", "direct")))
                requested_method = str(body.get("method", "")).strip().lower()
                method = canonical_method(requested_method)
                if requested_method not in ALLOWED_METHODS and method not in ALLOWED_METHODS:
                    raise ValueError("متد API مجاز نیست.")
                params = body.get("params") or {}
                if not isinstance(params, dict): raise ValueError("پارامترها باید یک شیء باشند.")
                http_method = str(body.get("http_method") or ("GET" if method in GET_METHODS else "POST")).upper()
                if method in SENSITIVE_METHODS:
                    if body.get("confirm_sensitive") is not True:
                        self.send_json({"ok": False, "error": "این متد می‌تواند سرویس یا موجودی را تغییر دهد؛ پس از تأیید صریح از ابزار API دوباره اجرا کن.", "confirmation_required": True}, 409); return
                    if http_method != "POST":
                        raise ValueError("متدهای پولی و تغییردهنده فقط با POST اجرا می‌شوند.")
                res = api_request(mode, method, params, http_method)
                self.send_json({"ok": res.get("ok") is True, "response": res}); return
            if path == "/api/service/action":
                self.handle_service_action(body); return
            if path == "/api/data/import":
                value = body.get("data")
                if not isinstance(value, dict):
                    raise ValueError("فایل پشتیبان یک شیء JSON معتبر نیست.")
                if value.get("format") == "ALI-VPN-LOCAL-METADATA-v1" and isinstance(value.get("owners"), dict):
                    sanitized = _safe_owner_map(value.get("owners"))
                    with LOCK:
                        for mode in API_URLS: STORE["owners"][mode].update(sanitized[mode])
                        _write_store(STORE)
                    self.send_json({"ok": True, "message": "نام مالک‌های مستقیم و تانل وارد شد؛ سایر تنظیمات تغییر نکردند."}); return
                if value.get("format") == "ALI-VPN-FULL-BACKUP-v2":
                    restored = restore_full_backup(value)
                    msg = f"پشتیبان هر دو حساب بازگردانی شد؛ {restored['owners']} نام مالک و {restored['logs']} گزارش محلی بازیابی شد."
                    if restored["includes_secrets"]:
                        msg += " تنظیمات API و اطلاعات هش‌شدهٔ ورود نیز بازیابی شدند."
                    else:
                        msg += " چون کلیدها در فایل نبودند، کلیدهای فعلی حفظ شدند."
                    msg += " سرویس‌های واقعی از API خوانده می‌شوند؛ بخش accounts در فایل، اسنپ‌شات مرجع سرویس‌هاست و از روی فایل سرویس جدیدی ساخته یا حذف نمی‌شود."
                    self.send_json({"ok": True, "message": msg, "restored": restored}); return
                raise ValueError("قالب فایل شناخته‌شده نیست؛ از پشتیبان ALI-VPN-FULL-BACKUP-v2 یا پشتیبان قدیمی نام مالکان استفاده کن.")
            self.send_json({"ok": False, "error": "مسیر API پیدا نشد."}, 404)
        except Exception as exc:
            self.send_json({"ok": False, "error": str(exc)}, http_status_for_exception(exc))


    def handle_setup(self) -> None:
        if not self.check_same_origin():
            self.send_json({"ok": False, "error": "درخواست با مبدأ غیرمجاز رد شد."}, 403); return
        if IS_VERCEL and not storage_is_configured():
            self.send_json({"ok": False, "error": "ابتدا یک Upstash Redis از بخش Storage به پروژهٔ Vercel متصل کن و دوباره Deploy بگیر."}, 503); return
        expected_setup_token = os.environ.get("ALI_VPN_SETUP_TOKEN", "").strip() if IS_VERCEL else ""
        if IS_VERCEL and len(expected_setup_token) < 32:
            self.send_json({"ok": False, "error": "متغیر ALI_VPN_SETUP_TOKEN باید در تنظیمات Vercel یک مقدار تصادفی حداقل ۳۲ کاراکتری داشته باشد؛ آن را تنظیم و Deploy مجدد کن."}, 503); return
        if IS_VERCEL:
            try:
                if _remote_login_blocked(self.client_ip()):
                    self.send_json({"ok": False, "error": "تلاش‌های ناموفق زیاد است؛ پنج دقیقه دیگر دوباره امتحان کن."}, 429); return
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, 503); return
        with LOCK:
            if STORE.get("auth", {}).get("salt") and STORE.get("auth", {}).get("hash"):
                self.send_json({"ok": False, "error": "مدیر قبلاً راه‌اندازی شده است؛ از فرم ورود استفاده کن."}, 409); return
        try:
            body = parse_json_body(self)
            password = str(body.get("password", ""))
            confirm = str(body.get("confirm_password", ""))
            supplied_setup_token = str(body.get("setup_token", ""))
        except Exception as exc:
            self.send_json({"ok": False, "error": str(exc)}, 400); return
        if IS_VERCEL and not hmac.compare_digest(supplied_setup_token, expected_setup_token):
            try: _remote_record_failed_login(self.client_ip())
            except Exception: pass
            self.send_json({"ok": False, "error": "توکن راه‌اندازی معتبر نیست."}, 403); return
        if IS_VERCEL:
            try:
                _remote_clear_failed_logins(self.client_ip())
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, 503); return
        if len(password) < 12:
            self.send_json({"ok": False, "error": "رمز مدیر باید دست‌کم ۱۲ کاراکتر داشته باشد."}, 400); return
        if password != confirm:
            self.send_json({"ok": False, "error": "تکرار رمز با رمز واردشده یکسان نیست."}, 400); return
        if IS_VERCEL:
            # SET NX is an atomic one-time guard across serverless instances.
            # The short TTL lets setup recover if a function dies mid-flight.
            try:
                lock_key = f"{KV_KEY_PREFIX}:setup-lock"
                lock_value = secrets.token_urlsafe(24)
                claimed = _kv_command(["SET", lock_key, lock_value, "NX", "EX", 90])
                if claimed != "OK":
                    self.send_json({"ok": False, "error": "راه‌اندازی اولیه هم‌اکنون در حال انجام است؛ صفحه را تازه‌سازی کن و دوباره بررسی کن."}, 409); return
                latest_store, _ = load_store()
                with LOCK:
                    STORE.clear()
                    STORE.update(latest_store)
                    if STORE.get("auth", {}).get("salt") and STORE.get("auth", {}).get("hash"):
                        self.send_json({"ok": False, "error": "مدیر قبلاً راه‌اندازی شده است؛ از فرم ورود استفاده کن."}, 409); return
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, 503); return
        salt, digest = hash_password(password)
        with LOCK:
            if STORE.get("auth", {}).get("salt") and STORE.get("auth", {}).get("hash"):
                self.send_json({"ok": False, "error": "مدیر قبلاً راه‌اندازی شده است؛ از فرم ورود استفاده کن."}, 409); return
            previous_auth = copy.deepcopy(STORE.get("auth", {}))
            STORE["auth"] = {"salt": salt, "hash": digest, "updated_at": now_iso()}
            try:
                _write_store(STORE)
            except Exception as exc:
                STORE["auth"] = previous_auth
                self.send_json({"ok": False, "error": str(exc)}, 503); return
            sid = secrets.token_urlsafe(32)
            try:
                _create_session(sid, time.time() + 10 * 60 * 60)
            except Exception:
                # The admin password is already persisted. The user can sign in after refreshing.
                self.send_json({"ok": False, "error": "رمز مدیر ذخیره شد اما ساخت نشست ناموفق بود؛ صفحه را تازه‌سازی کن و با همان رمز وارد شو."}, 503); return
        cookie = SimpleCookie(); cookie["ali_vpn_session"] = sid; cookie["ali_vpn_session"]["path"] = "/"; cookie["ali_vpn_session"]["httponly"] = True; cookie["ali_vpn_session"]["samesite"] = "Strict"; cookie["ali_vpn_session"]["max-age"] = 36000
        if IS_VERCEL or getattr(self, "is_secure", False): cookie["ali_vpn_session"]["secure"] = True
        self.send_json({"ok": True, "message": "رمز مدیر ساخته شد؛ اکنون می‌توانی کلیدهای API را خودت وارد کنی."}, headers={"Set-Cookie": cookie.output(header="").strip()})

    def handle_login(self) -> None:
        if not self.check_same_origin():
            self.send_json({"ok": False, "error": "درخواست با مبدأ غیرمجاز رد شد."}, 403); return
        ip = self.client_ip(); now = time.time()
        if IS_VERCEL:
            try:
                blocked = _remote_login_blocked(ip)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, 503); return
        else:
            with LOCK:
                # Bound in-memory tracking and make the check/update atomic.
                for old_ip in list(LOGIN_ATTEMPTS):
                    LOGIN_ATTEMPTS[old_ip] = [x for x in LOGIN_ATTEMPTS[old_ip] if now - x < 300]
                    if not LOGIN_ATTEMPTS[old_ip]: LOGIN_ATTEMPTS.pop(old_ip, None)
                attempts = [x for x in LOGIN_ATTEMPTS.get(ip, []) if now - x < 300]
                LOGIN_ATTEMPTS[ip] = attempts
                blocked = len(attempts) >= 8
        if blocked:
            self.send_json({"ok": False, "error": "تلاش‌های ورود زیاد است؛ پنج دقیقه دیگر دوباره امتحان کنید."}, 429); return
        try:
            body = parse_json_body(self)
            password = str(body.get("password", ""))
        except Exception:
            password = ""
        with LOCK: auth = dict(STORE.get("auth", {}))
        if not auth.get("salt") or not auth.get("hash"):
            self.send_json({"ok": False, "error": "هنوز رمز مدیر ساخته نشده است؛ صفحه را تازه‌سازی کن و راه‌اندازی اولیه را انجام بده."}, 409); return
        if not verify_password(password, auth.get("salt", ""), auth.get("hash", "")):
            try:
                if IS_VERCEL:
                    _remote_record_failed_login(ip)
                else:
                    with LOCK: LOGIN_ATTEMPTS.setdefault(ip, []).append(now)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, 503); return
            try: add_log({"mode": "all", "kind": "security", "method": "login_failed", "ok": False, "error": "رمز پنل اشتباه است.", "at": now_iso()})
            except Exception: pass
            self.send_json({"ok": False, "error": "رمز پنل اشتباه است."}, 401); return
        with LOCK:
            LOGIN_ATTEMPTS.pop(ip, None)
        if IS_VERCEL:
            try: _remote_clear_failed_logins(ip)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, 503); return
        with LOCK:
            now_session = time.time()
            for old_sid in list(SESSIONS):
                if SESSIONS[old_sid] <= now_session: SESSIONS.pop(old_sid, None)
            sid = secrets.token_urlsafe(32)
            try:
                _create_session(sid, now_session + 10 * 60 * 60)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, 503); return
        cookie = SimpleCookie(); cookie["ali_vpn_session"] = sid; cookie["ali_vpn_session"]["path"] = "/"; cookie["ali_vpn_session"]["httponly"] = True; cookie["ali_vpn_session"]["samesite"] = "Strict"; cookie["ali_vpn_session"]["max-age"] = 36000
        if IS_VERCEL or getattr(self, "is_secure", False): cookie["ali_vpn_session"]["secure"] = True
        self.send_json({"ok": True, "message": "ورود موفق بود."}, headers={"Set-Cookie": cookie.output(header="").strip()})

    def handle_service_action(self, body: dict[str, Any]) -> None:
        mode = valid_mode(str(body.get("mode", "direct")))
        action = str(body.get("action", ""))
        if action in SENSITIVE_METHODS and body.get("confirmed") is not True:
            self.send_json({"ok": False, "error": "برای عملیات مالی یا تغییردهنده باید تأیید صریح ارسال شود."}, 409)
            return
        username = str(body.get("username", "")).strip().upper()
        owner = str(body.get("owner", "")).strip()[:120]
        params: dict[str, Any] = {}
        method = ""
        if action == "create":
            method = "create"
            raw_test = body.get("test", 0)
            if str(raw_test).lower() not in {"0", "1", "false", "true"}:
                raise ValueError("پارامتر test باید ۰ یا ۱ باشد.")
            test = 1 if str(raw_test).lower() in {"1", "true"} else 0
            params = {"test": test}
            if not test:
                try: gig = float(body.get("gig")); day = float(body.get("day"))
                except (TypeError, ValueError): raise ValueError("حجم و مدت باید عدد معتبر باشند.")
                if not (gig == gig and abs(gig) != float("inf") and 0 <= gig <= 10000): raise ValueError("حجم باید بین صفر تا ۱۰۰۰۰ گیگابایت باشد؛ صفر فقط برای سرویس نامحدود است.")
                if not (day == day and abs(day) != float("inf") and 1 <= day <= 3650 and day.is_integer()): raise ValueError("مدت باید عدد صحیح بین ۱ تا ۳۶۵۰ روز باشد.")
                params.update({"gig": gig, "day": int(day)})
        else:
            if not username or not re.fullmatch(r"[A-Z0-9]{9}", username):
                raise ValueError("شناسه سرویس باید ۹ کاراکتر انگلیسی/عددی باشد.")
            if action == "renew":
                method = "renew"
                try: gig = float(body.get("gig")); day = float(body.get("day"))
                except (TypeError, ValueError): raise ValueError("حجم و مدت تمدید باید عدد معتبر باشند.")
                if not (gig == gig and abs(gig) != float("inf") and 0 <= gig <= 10000): raise ValueError("حجم تمدید معتبر نیست؛ صفر فقط برای نامحدود است.")
                if not (day == day and abs(day) != float("inf") and 1 <= day <= 3650 and day.is_integer()): raise ValueError("مدت تمدید باید عدد صحیح بین ۱ تا ۳۶۵۰ روز باشد.")
                params = {"username": username, "gig": gig, "day": int(day)}
            elif action == "upg_time":
                method = "upg_time"
                try: day = float(body.get("day"))
                except (TypeError, ValueError): raise ValueError("تعداد روز باید عدد معتبر باشد.")
                if not (day == day and abs(day) != float("inf") and 1 <= day <= 3650 and day.is_integer()): raise ValueError("افزایش زمان باید عدد صحیح بین ۱ تا ۳۶۵۰ روز باشد.")
                params = {"username": username, "day": int(day)}
            elif action == "upg_size":
                method = "upg_size"
                try: gig = float(body.get("gig"))
                except (TypeError, ValueError): raise ValueError("حجم اضافه باید عدد معتبر باشد.")
                if not (gig == gig and abs(gig) != float("inf") and 1 <= gig <= 10000): raise ValueError("حجم اضافه باید بین ۱ تا ۱۰۰۰۰ گیگابایت باشد.")
                params = {"username": username, "gig": gig}
            elif action == "change_link":
                method = "change_link"; params = {"username": username}
            elif action == "reverse_mode":
                status = str(body.get("status", "disabled")).strip().lower()
                if status not in {"active", "disabled"}: raise ValueError("وضعیت نهایی فقط می‌تواند active یا disabled باشد.")
                method = "reverse_mode"; params = {"username": username, "status": status}
            elif action == "delsv":
                method = "delsv"; params = {"username": username}
            else:
                raise ValueError("عملیات ناشناخته است.")

        # Always send state-changing and monetary operations as POST.
        res = api_request(mode, method, params, "POST")
        local_warning = None
        applied = res.get("ok") is True
        if res.get("ok") is True and action == "delsv":
            # Docs: repeated delete of an absent service can still return ok=true,
            # but it omits return_price. Keep owner metadata unless deletion is explicit.
            applied = isinstance(res, dict) and "return_price" in res
        if res.get("ok") is True and action == "create":
            root = res.get("result") if isinstance(res.get("result"), dict) else {}
            service = root.get("service") if isinstance(root.get("service"), dict) else root
            made_username = str(service.get("username") or root.get("username") or "").strip().upper()
            if made_username:
                username = made_username
                if owner:
                    with LOCK:
                        old_owner = STORE["owners"][mode].get(username)
                        STORE["owners"][mode][username] = owner
                        try: _write_store(STORE)
                        except Exception as exc:
                            if old_owner is None: STORE["owners"][mode].pop(username, None)
                            else: STORE["owners"][mode][username] = old_owner
                            local_warning = "سرویس در API ساخته شد، اما ذخیرهٔ نام مالک روی رایانه ناموفق بود. مالک را از جزئیات سرویس دوباره ثبت کن."
        elif res.get("ok") is True and action == "delsv" and applied:
            with LOCK:
                old_owner = STORE["owners"][mode].pop(username, None)
                try: _write_store(STORE)
                except Exception:
                    if old_owner is not None: STORE["owners"][mode][username] = old_owner
                    local_warning = "حذف سرویس در API تأیید شد، اما پاک‌سازی نام مالک در دادهٔ محلی ذخیره نشد."
        if res.get("ok") is True and action == "delsv" and not applied:
            local_warning = "API پاسخ موفق داده، اما حذف واقعی را تأیید نکرد و مبلغ برگشتی هم ارائه نشده است؛ نام مالک محلی حفظ شد."

        detail = None
        if res.get("ok") is True and action not in ("delsv",):
            detail_username = username
            if action == "create":
                root = res.get("result") if isinstance(res.get("result"), dict) else {}
                svc = root.get("service") if isinstance(root.get("service"), dict) else root
                detail_username = str(svc.get("username") or root.get("username") or username)
            if detail_username:
                try: detail = get_service(mode, detail_username)
                except Exception: detail = None
        self.send_json({"ok": res.get("ok") is True, "response": res, "detail": detail,
                        "action": action, "username": username, "applied": applied,
                        "local_warning": local_warning})


class _WSGIRequest:
    """Minimal WSGI request facade; avoids a framework dependency on Vercel."""
    def __init__(self, environ: dict[str, Any]):
        self.environ = environ
        self.method = str(environ.get("REQUEST_METHOD", "GET")).upper()
        self.path = str(environ.get("PATH_INFO", "/") or "/")
        self.query_string = str(environ.get("QUERY_STRING", "")).encode("latin-1", "replace")
        self.remote_addr = str(environ.get("REMOTE_ADDR", "") or "unknown")
        self.headers = Message()
        for key, value in environ.items():
            if key.startswith("HTTP_"):
                self.headers[key[5:].replace("_", "-").title()] = str(value)
        if environ.get("CONTENT_TYPE"):
            self.headers["Content-Type"] = str(environ["CONTENT_TYPE"])
        if environ.get("CONTENT_LENGTH"):
            self.headers["Content-Length"] = str(environ["CONTENT_LENGTH"])
        if not self.headers.get("Host"):
            host = str(environ.get("SERVER_NAME", ""))
            port = str(environ.get("SERVER_PORT", ""))
            if host:
                self.headers["Host"] = f"{host}:{port}" if port and port not in {"80", "443"} else host
        self.is_secure = str(environ.get("wsgi.url_scheme", "http")).lower() == "https" or self.headers.get("X-Forwarded-Proto", "").lower() == "https"
        self._body: bytes | None = None

    def get_data(self, cache: bool = True) -> bytes:
        if self._body is None:
            stream = self.environ.get("wsgi.input")
            try:
                length = int(self.environ.get("CONTENT_LENGTH") or 0)
            except (TypeError, ValueError):
                length = 0
            self._body = stream.read(max(0, min(length, 100 * 1024 * 1024))) if stream and length > 0 else b""
        return self._body


class _VercelHandler(Handler):
    """Run the same validated HTTP route methods through a WSGI request."""
    def __init__(self, wsgi_request: _WSGIRequest):
        self._response_status = 200
        self._response_headers: list[tuple[str, str]] = []
        self.wfile = io.BytesIO()
        self.headers = wsgi_request.headers
        self.rfile = io.BytesIO(wsgi_request.get_data(cache=True))
        self.client_address = (wsgi_request.remote_addr or "unknown", 0)
        host = self.headers.get("Host", "")
        try:
            host_parts = urllib.parse.urlsplit("//" + host)
            default_port = 443 if wsgi_request.is_secure else 80
            port = host_parts.port or default_port
        except Exception:
            port = 443 if wsgi_request.is_secure else 80
        self.server = SimpleNamespace(server_port=port)
        self.path = wsgi_request.path
        if wsgi_request.query_string:
            self.path += "?" + wsgi_request.query_string.decode("latin-1")
        self.command = wsgi_request.method
        self.is_secure = wsgi_request.is_secure

    def send_response(self, code: int, message: str | None = None) -> None:
        self._response_status = int(code)

    def send_header(self, keyword: str, value: Any) -> None:
        self._response_headers.append((str(keyword), str(value)))

    def end_headers(self) -> None:
        return

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        self.send_json({"ok": False, "error": message or "درخواست قابل پردازش نیست."}, int(code))


def app(environ: dict[str, Any], start_response: Any) -> list[bytes]:
    """Vercel WSGI entry point. Existing local HTTP server remains unchanged."""
    global STORE
    try:
        # Warm serverless instances can outlive other requests. Refresh shared
        # settings from Redis so auth changes and API keys are not instance-local.
        if IS_VERCEL and storage_is_configured():
            latest_store, _ = load_store()
            with LOCK:
                STORE.clear()
                STORE.update(latest_store)
        wsgi_request = _WSGIRequest(environ)
        handler = _VercelHandler(wsgi_request)
        method = wsgi_request.method
        if method in {"GET", "HEAD"}:
            handler.do_GET()
        elif method == "POST":
            handler.do_POST()
        else:
            handler.send_json({"ok": False, "error": "این متد HTTP پشتیبانی نمی‌شود."}, 405)
        body = b"" if method == "HEAD" else handler.wfile.getvalue()
        status_code = handler._response_status
        try:
            phrase = HTTPStatus(status_code).phrase
        except ValueError:
            phrase = "Unknown"
        headers = [(key, value) for key, value in handler._response_headers]
        if not any(k.lower() == "content-type" for k, _ in headers) and body:
            headers.append(("Content-Type", "application/octet-stream"))
        start_response(f"{status_code} {phrase}", headers)
        return [body]
    except Exception as exc:
        status_code = http_status_for_exception(exc)
        message = str(exc)[:500] if isinstance(exc, (ValueError, RuntimeError)) else "خطای داخلی پنل رخ داد."
        raw = json.dumps({"ok": False, "error": message}, ensure_ascii=False).encode("utf-8")
        try:
            phrase = HTTPStatus(status_code).phrase
        except ValueError:
            phrase = "Unknown"
        start_response(f"{status_code} {phrase}", [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Length", str(len(raw))),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
        ])
        return [raw]

def main() -> None:
    parser = argparse.ArgumentParser(description="ALI VPN Panel local web UI")
    parser.add_argument("--host", default="127.0.0.1", help="bind address; use 0.0.0.0 only when phone access on a trusted LAN is needed")
    parser.add_argument("--port", type=int, default=8765, help="HTTP port")
    args = parser.parse_args()
    if INITIAL_PASSWORD:
        print("\n" + "=" * 65)
        print("ALI VPN PANEL — FIRST RUN")
        print("رمز اولیهٔ ورود به پنل (همین حالا نگهش دار؛ فقط بار اول نمایش داده می‌شود):")
        print(f"  {INITIAL_PASSWORD}")
        print("بعد از ورود از بخش تنظیمات، رمز را تغییر بده.")
        print("=" * 65 + "\n")
    try:
        server = ThreadingHTTPServer((args.host, args.port), Handler)
    except OSError as exc:
        print(f"خطا در راه‌اندازی سرور: {exc}")
        print("اگر پورت اشغال است، با --port 8766 اجرا کن.")
        sys.exit(1)
    server.daemon_threads = True
    print(f"پنل روی این رایانه: http://127.0.0.1:{args.port}")
    if args.host in ("0.0.0.0", "::"):
        for ip in local_ip_addresses():
            print(f"دسترسی در شبکهٔ محلی: http://{ip}:{args.port}")
        print("امنیت: فقط در شبکهٔ قابل اعتماد استفاده کن؛ پورت را روی اینترنت عمومی فوروارد نکن.")
    print("برای بستن پنل، Ctrl+C را بزن.")
    try:
        server.serve_forever(poll_interval=0.4)
    except KeyboardInterrupt:
        print("\nدر حال بستن پنل...")
    finally:
        server.server_close()

if __name__ == "__main__":
    main()
