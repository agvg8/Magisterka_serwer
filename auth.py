"""Uwierzytelnianie endpointów używanych przez apki mobilne (Faza 12).

Zasada: każde żądanie do /patients/*, /specialists/*, /caregivers/*, /push/* niesie
`Authorization: Bearer <sekret>` i serwer sprawdza, KTO pyta i czy WOLNO mu dotknąć danego
pacjenta — zanim w ogóle uruchomi się właściwy endpoint (middleware = jedno miejsce, trudno coś
pominąć; kontrolę pokrycia robi test `check_coverage`).

Trzy typy podmiotów:
  specjalista — token sesji z logowania (tabela `sessions`, w bazie przechowywany tylko hash);
                wygasa po SESSION_IDLE_DAYS dni bez użycia; unieważniany przy wylogowaniu /
                resecie hasła / usunięciu konta. Wolno mu: tylko własnych pacjentów.
  pacjent     — sekret urządzenia (losowy, generowany przez apkę; tabela `device_credentials`,
                hash). Pierwsze użycie "zajmuje" tożsamość (trust-on-first-use), każde kolejne
                musi pasować. Wolno mu: tylko własne dane (id pacjenta = X-Device-Id).
  opiekun     — jak pacjent (sekret urządzenia), + wiersz w `caregivers` łączący go z pacjentem.

Tryb przejściowy: DEPRESS_SENSE_AUTH_ENFORCE=0 → nic nie jest odrzucane (tylko log), żeby można
było wdrożyć serwer przed zaktualizowaniem apek. Domyślnie wymuszane.
"""
import hashlib
import hmac
import os
import re
import secrets
import time
from dataclasses import dataclass
from typing import Optional

from fastapi import Request
from fastapi.responses import JSONResponse

SESSION_IDLE_SECONDS = 14 * 24 * 3600
ENFORCE = os.environ.get("DEPRESS_SENSE_AUTH_ENFORCE", "1") != "0"
MIN_TOKEN_LEN = 32

_get_db = None


def init(get_db_fn):
    global _get_db
    _get_db = get_db_fn
    conn = _get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            specialist_id TEXT NOT NULL,
            created_at REAL NOT NULL,
            last_used REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_spec ON sessions(specialist_id);
        CREATE TABLE IF NOT EXISTS device_credentials (
            role TEXT NOT NULL,
            subject TEXT NOT NULL,
            secret_hash TEXT NOT NULL,
            created_at REAL NOT NULL,
            PRIMARY KEY (role, subject)
        );
        """
    )
    conn.commit()
    conn.close()


def _h(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass
class Principal:
    role: str      # "specjalista" | "pacjent" | "opiekun"
    subject: str   # id specjalisty / id pacjenta / id urządzenia opiekuna


# ------------------------------------------------------------------ sesje specjalistów
def create_session(specialist_id: str) -> str:
    token = secrets.token_urlsafe(32)
    now = time.time()
    conn = _get_db()
    conn.execute("INSERT INTO sessions (token_hash, specialist_id, created_at, last_used) VALUES (?, ?, ?, ?)",
                 (_h(token), specialist_id, now, now))
    # porządki: wygasłe sesje
    conn.execute("DELETE FROM sessions WHERE last_used < ?", (now - SESSION_IDLE_SECONDS,))
    conn.commit()
    conn.close()
    return token


def delete_session(token: str):
    conn = _get_db()
    conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_h(token),))
    conn.commit()
    conn.close()


def delete_sessions_for(specialist_id: str):
    conn = _get_db()
    conn.execute("DELETE FROM sessions WHERE specialist_id = ?", (specialist_id,))
    conn.commit()
    conn.close()


# ------------------------------------------------------------------ ustalanie podmiotu
def resolve_principal(request: Request) -> Optional[Principal]:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        return None
    token = header[7:].strip()
    if len(token) < MIN_TOKEN_LEN:
        return None
    th = _h(token)
    conn = _get_db()
    try:
        row = conn.execute("SELECT specialist_id, last_used FROM sessions WHERE token_hash = ?", (th,)).fetchone()
        now = time.time()
        if row:
            if now - row["last_used"] > SESSION_IDLE_SECONDS:
                conn.execute("DELETE FROM sessions WHERE token_hash = ?", (th,))
                conn.commit()
                return None
            if now - row["last_used"] > 60:  # odświeżaj najwyżej raz na minutę
                conn.execute("UPDATE sessions SET last_used = ? WHERE token_hash = ?", (now, th))
                conn.commit()
            return Principal("specjalista", row["specialist_id"])

        role = request.headers.get("x-device-role", "")
        subject = request.headers.get("x-device-id", "").strip()
        if role in ("pacjent", "opiekun") and subject:
            cred = conn.execute("SELECT secret_hash FROM device_credentials WHERE role = ? AND subject = ?",
                                (role, subject)).fetchone()
            if cred:
                return Principal(role, subject) if hmac.compare_digest(cred["secret_hash"], th) else None
            # pierwsze użycie tego urządzenia — zajmujemy tożsamość (trust-on-first-use)
            conn.execute("INSERT OR IGNORE INTO device_credentials (role, subject, secret_hash, created_at) VALUES (?, ?, ?, ?)",
                         (role, subject, th, now))
            conn.commit()
            return Principal(role, subject)
    finally:
        conn.close()
    return None


# ------------------------------------------------------------------ reguły dostępu
# (metoda, wzorzec ścieżki, kto)   kto: litery P=pacjent(własne dane), S=specjalista pacjenta,
# C=opiekun powiązany z pacjentem, "sid"=specjalista o id z ścieżki, "sid+own"=sid i jego pacjent,
# "any"=każdy uwierzytelniony, "S*"=dowolny specjalista (np. wylogowanie)
_PID = r"/patients/(?P<pid>[^/]+)"
_SID = r"/specialists/(?P<sid>[^/]+)"
RULES = [
    ("POST", r"/patients/register", "Preg"),
    ("POST", _PID + r"/data", "P"),
    ("GET", _PID + r"/data", "PSC"),
    ("GET", _PID + r"/status", "P"),
    ("POST", _PID + r"/status/[^/]+/ack", "P"),
    ("POST", _PID + r"/self-assessment", "P"),
    ("GET", _PID + r"/self-assessments", "PS"),
    ("POST", _PID + r"/phq9", "P"),
    ("GET", _PID + r"/phq9", "PS"),
    ("POST", _PID + r"/phq9/[^/]+/review", "S"),
    ("GET", _PID + r"/safety-status", "SC"),
    ("POST", _PID + r"/madrs", "S"),
    ("GET", _PID + r"/madrs", "S"),
    ("GET", _PID + r"/trends", "S"),
    ("GET", _PID + r"/change-detection", "S"),
    ("GET", _PID + r"/caregivers/count", "PSC"),
    ("POST", _PID + r"/contact", "S"),
    ("POST", _PID + r"/contact-specialist", "C"),
    ("POST", r"/caregivers/add", "Creg"),
    ("GET", _SID + r"/safety-alerts", "sid"),
    ("GET", _SID + r"/change-alerts", "sid"),
    ("GET", _SID + r"/patients", "sid"),
    ("POST", _SID + r"/patients", "sid"),
    ("GET", _SID + r"/unassigned-patients", "sid"),
    ("PATCH", _SID + r"/patients/(?P<pid>[^/]+)", "sid+own"),
    ("POST", _SID + r"/patients/(?P<pid>[^/]+)/clear-flag", "sid+own"),
    ("POST", r"/specialists/logout", "S*"),
    ("POST", r"/push/register", "any"),
    ("POST", r"/push/unregister", "any"),
]
_COMPILED = [(m, re.compile("^" + p + "$"), who) for m, p, who in RULES]

# ścieżki mobilne, które NIE wymagają tokenu (logowanie ma własną kontrolę hasła)
PUBLIC = {("POST", "/specialists/login"), ("POST", "/specialists/change-password"), ("GET", "/health")}
MOBILE_PREFIXES = ("/patients", "/specialists", "/caregivers", "/push")


def _specialist_owns(conn, spec_id, pid) -> bool:
    r = conn.execute("SELECT 1 FROM patients WHERE id = ? AND specialist_id = ?", (pid, spec_id)).fetchone()
    return r is not None


def _caregiver_linked(conn, device_id, pid) -> bool:
    r = conn.execute("SELECT 1 FROM caregivers WHERE patient_id = ? AND caregiver_device_id = ?", (pid, device_id)).fetchone()
    return r is not None


def authorize(p: Principal, who: str, groups: dict, query) -> bool:
    pid, sid = groups.get("pid"), groups.get("sid")
    if who == "any":
        return True
    if who == "S*":
        return p.role == "specjalista"
    if who == "Preg":
        return p.role == "pacjent"   # zgodność id z nagłówkiem sprawdza sam endpoint
    if who == "Creg":
        return p.role == "opiekun"
    if who in ("sid", "sid+own"):
        if p.role != "specjalista" or p.subject != sid:
            return False
        if who == "sid+own":
            conn = _get_db()
            try:
                return _specialist_owns(conn, p.subject, pid)
            finally:
                conn.close()
        return True
    # litery P / S / C względem pacjenta z ścieżki
    if "P" in who and p.role == "pacjent" and p.subject == pid:
        return True
    conn = _get_db()
    try:
        if "S" in who and p.role == "specjalista":
            qs = query.get("specialist_id")
            if qs and qs != p.subject:
                return False  # np. review: nie można podpisać się cudzym id
            return _specialist_owns(conn, p.subject, pid)
        if "C" in who and p.role == "opiekun":
            return _caregiver_linked(conn, p.subject, pid)
    finally:
        conn.close()
    return False


def match_rule(method: str, path: str):
    for m, rx, who in _COMPILED:
        if m == method:
            mo = rx.match(path)
            if mo:
                return who, mo.groupdict()
    return None


async def auth_middleware(request: Request, call_next):
    path, method = request.url.path.rstrip("/") or "/", request.method
    if method == "OPTIONS" or (method, path) in PUBLIC or not path.startswith(MOBILE_PREFIXES):
        return await call_next(request)
    hit = match_rule(method, path)
    if hit is None:
        # nie ma reguły: ścieżki chronione inaczej (admin-dependency) przechodzą dalej;
        # pokrycie sprawdza check_coverage()
        return await call_next(request)
    who, groups = hit
    principal = resolve_principal(request)
    request.state.principal = principal
    if principal is None:
        if ENFORCE:
            return JSONResponse({"detail": "Wymagane uwierzytelnienie"}, status_code=401)
        print(f"[auth] (tryb przejściowy) brak/nieprawidłowy token: {method} {path}")
    elif not authorize(principal, who, groups, request.query_params):
        if ENFORCE:
            return JSONResponse({"detail": "Brak dostępu do tego zasobu"}, status_code=403)
        print(f"[auth] (tryb przejściowy) brak uprawnień: {principal.role} {method} {path}")
    return await call_next(request)


def check_coverage(app) -> list:
    """Lista tras mobilnych bez reguły, bez publicznego wyjątku i bez zależności (np. admin).
    Powinna być pusta — wywoływane w teście i przy starcie (ostrzeżenie w logu)."""
    gaps = []
    for r in app.routes:
        path = getattr(r, "path", "")
        if not path.startswith(MOBILE_PREFIXES):
            continue
        for method in getattr(r, "methods", set()) or set():
            if method in ("HEAD", "OPTIONS"):
                continue
            # podstaw przykładowe wartości za {parametry}
            concrete = re.sub(r"\{[^}]+\}", "x", path)
            if (method, concrete) in PUBLIC or match_rule(method, concrete):
                continue
            if getattr(r, "dependencies", None):  # np. require_admin
                continue
            gaps.append((method, path))
    return gaps
