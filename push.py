"""Powiadomienia push (Firebase Cloud Messaging, HTTP v1) — działają także, gdy apka jest
zamknięta. Moduł nie importuje main.py (patrz portal.py); dostaje get_db() przez init().

Konfiguracja (zmienne środowiskowe na serwerze, Railway → Variables):
  DEPRESS_SENSE_FCM_SERVICE_ACCOUNT       — CAŁA zawartość pliku JSON klucza konta usługi Firebase
  (albo) DEPRESS_SENSE_FCM_SERVICE_ACCOUNT_FILE — ścieżka do tego pliku
Bez tego push jest wyłączony (nic się nie wysyła, serwer działa normalnie — apki dalej mają
odpytywanie co 30 s jako zapas).

Prywatność: w wiadomości push lecą WYŁĄCZNIE typ zdarzenia i identyfikatory techniczne
(np. entry_id). Żadnych imion, wyników ani treści — tekst powiadomienia budują same apki.
"""
import json
import os
import threading
import time
import urllib.error
import urllib.request

_get_db = None
_cred = None
_cred_lock = threading.Lock()
_SCOPE = "https://www.googleapis.com/auth/firebase.messaging"
ROLES = ("pacjent", "specjalista", "opiekun")


def init(get_db_fn):
    global _get_db
    _get_db = get_db_fn
    conn = _get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS push_tokens (
            token TEXT PRIMARY KEY,
            role TEXT NOT NULL,
            user_id TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_push_tokens_user ON push_tokens(role, user_id);
        CREATE TABLE IF NOT EXISTS push_sent (
            dedupe_key TEXT PRIMARY KEY,
            sent_at TEXT NOT NULL
        );
        """
    )
    conn.commit()
    conn.close()


def _service_account_info():
    raw = os.environ.get("DEPRESS_SENSE_FCM_SERVICE_ACCOUNT")
    if raw:
        return json.loads(raw)
    path = os.environ.get("DEPRESS_SENSE_FCM_SERVICE_ACCOUNT_FILE")
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return None


def configured() -> bool:
    try:
        info = _service_account_info()
        return bool(info and info.get("project_id") and info.get("private_key"))
    except Exception:
        return False


def _access_token(info) -> str:
    """Token OAuth2 dla FCM (cache w obiekcie poświadczeń, odświeżany automatycznie)."""
    global _cred
    from google.oauth2 import service_account
    from google.auth.transport.requests import Request as GRequest
    with _cred_lock:
        if _cred is None:
            _cred = service_account.Credentials.from_service_account_info(info, scopes=[_SCOPE])
        if not _cred.valid:
            _cred.refresh(GRequest())
        return _cred.token


def _http_post(url: str, headers: dict, body: bytes):
    """Wydzielone, żeby dało się podmienić w testach. Zwraca (status, tekst)."""
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


# ---------------------------------------------------------------- tokeny
def register_token(role: str, user_id: str, token: str):
    if role not in ROLES or not user_id or not token:
        raise ValueError("bad push registration")
    conn = _get_db()
    conn.execute(
        "INSERT INTO push_tokens (token, role, user_id, updated_at) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(token) DO UPDATE SET role = excluded.role, user_id = excluded.user_id, updated_at = excluded.updated_at",
        (token, role, user_id, time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())),
    )
    conn.commit()
    conn.close()


def unregister_token(token: str):
    conn = _get_db()
    conn.execute("DELETE FROM push_tokens WHERE token = ?", (token,))
    conn.commit()
    conn.close()


def token_counts() -> dict:
    conn = _get_db()
    rows = conn.execute("SELECT role, COUNT(*) AS n FROM push_tokens GROUP BY role").fetchall()
    conn.close()
    return {r["role"]: r["n"] for r in rows}


def _tokens_for(role: str, user_id):
    conn = _get_db()
    if user_id is None:
        rows = conn.execute("SELECT token FROM push_tokens WHERE role = ?", (role,)).fetchall()
    else:
        rows = conn.execute("SELECT token FROM push_tokens WHERE role = ? AND user_id = ?", (role, user_id)).fetchall()
    conn.close()
    return [r["token"] for r in rows]


# ---------------------------------------------------------------- wysyłka
def _send_one(info, token: str, data: dict):
    url = f"https://fcm.googleapis.com/v1/projects/{info['project_id']}/messages:send"
    body = json.dumps({
        "message": {
            "token": token,
            "data": {k: str(v) for k, v in data.items()},
            # data-only + wysoki priorytet: apka sama buduje powiadomienie i budzi się nawet w Doze
            "android": {"priority": "HIGH", "ttl": "86400s"},
        }
    }).encode("utf-8")
    status, text = _http_post(
        url, {"Authorization": "Bearer " + _access_token(info), "Content-Type": "application/json"}, body
    )
    if status in (404, 410) or (status == 400 and "UNREGISTERED" in text) or "UNREGISTERED" in text:
        unregister_token(token)  # token martwy (apka odinstalowana / wyczyszczona)
    elif status >= 300:
        print(f"[push] FCM {status}: {text[:200]}")
    return status


def _deliver(role: str, user_id, data: dict, dedupe_key):
    try:
        info = _service_account_info()
        if not info:
            return
        if dedupe_key:
            conn = _get_db()
            cur = conn.execute(
                "INSERT OR IGNORE INTO push_sent (dedupe_key, sent_at) VALUES (?, ?)",
                (dedupe_key, time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())),
            )
            conn.commit()
            fresh = cur.rowcount > 0
            conn.close()
            if not fresh:
                return
        for token in _tokens_for(role, user_id):
            _send_one(info, token, data)
    except Exception as e:  # push nigdy nie może wywrócić żądania, które go wywołało
        print(f"[push] błąd wysyłki: {e}")


def notify(role: str, user_id, data: dict, dedupe_key=None):
    """Wysyła w tle (osobny wątek) — wywołujący nie czeka na Google. user_id=None → wszyscy
    z daną rolą. Gdy push nie jest skonfigurowany, kończy się po cichu."""
    if _get_db is None or not configured():
        return
    threading.Thread(target=_deliver, args=(role, user_id, data, dedupe_key), daemon=True).start()
