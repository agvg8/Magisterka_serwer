"""
ChaD-Sence — lokalny serwer testowy
====================================
Prosty serwer FastAPI + SQLite, który symuluje backend dla trzech aplikacji:
- Pacjent (wysyła dane behawioralne, odbiera info o kontakcie)
- Specjalista (loguje się, zarządza pacjentami, widzi dane)
- Opiekun (dołącza do pacjenta, inicjuje kontakt ze specjalistą)

Uruchomienie (patrz README.md):
    pip install -r requirements.txt
    uvicorn main:app --host 0.0.0.0 --port 8000
"""

import asyncio
import os
import socket
import sqlite3
import time
import uuid
import webbrowser
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

# Ścieżkę do pliku bazy można nadpisać zmienną środowiskową CHAD_SENCE_DB_PATH —
# przy wdrożeniu na serwerze zewnętrznym (np. Railway) wskazujemy nią ścieżkę
# na trwałym wolumenie (np. "/data/chad_sence.db"), żeby dane przeżyły restart
# kontenera. Lokalnie (bez tej zmiennej) zachowanie jest identyczne jak dotychczas.
DB_PATH = os.environ.get("CHAD_SENCE_DB_PATH", "chad_sence.db")
_db_dir = os.path.dirname(DB_PATH)
if _db_dir:
    os.makedirs(_db_dir, exist_ok=True)

# Gdy serwer działa na zewnętrznym hoście (nie w lokalnej sieci WiFi), adres IP
# wykryty lokalnie nie ma sensu pokazywać w banerze — trzeba podać prawdziwy,
# publiczny adres (np. https://chadsence-production.up.railway.app) tą zmienną.
# Jej obecność jest też sygnałem "jesteśmy w chmurze", więc przy okazji wyłącza
# próbę otwarcia przeglądarki przy starcie (i tak by się nie udała bez GUI).
PUBLIC_URL = os.environ.get("CHAD_SENCE_PUBLIC_URL")

app = FastAPI(title="ChaD-Sence Local Server")

# Bufor logów żądań trzymany tylko w pamięci (nie w bazie) — to podgląd na żywo,
# nie trwały log. Po restarcie serwera zawartość się czyści, co jest tu w porządku.
LOG_BUFFER = deque(maxlen=300)

# Co ile sekund przeliczamy statystyki pacjentów w tle, niezależnie od tego, czy
# ktoś akurat patrzy na panel specjalisty (patrz sekcja "STATYSTYKI" niżej).
BACKGROUND_STATS_INTERVAL_SECONDS = 300  # 5 minut


# ---------------------------------------------------------------------------
# Baza danych (SQLite, plik lokalny — zero konfiguracji)
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS patients (
            id TEXT PRIMARY KEY,
            name TEXT,
            caregiver_slots INTEGER NOT NULL DEFAULT 0,
            specialist_id TEXT,
            last_sync TEXT,
            flag INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS specialists (
            id TEXT PRIMARY KEY,
            password TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS caregivers (
            patient_id TEXT NOT NULL,
            caregiver_device_id TEXT NOT NULL,
            UNIQUE(patient_id, caregiver_device_id)
        );

        CREATE TABLE IF NOT EXISTS behavior_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            phone_activity REAL DEFAULT 0,
            app_usage REAL DEFAULT 0,
            movement REAL DEFAULT 0,
            room_activity REAL DEFAULT 0,
            unlocks REAL DEFAULT 0,
            calls INTEGER DEFAULT 0,
            sms INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id TEXT NOT NULL,
            direction TEXT NOT NULL,  -- 'to_patient' albo 'to_specialist'
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            role TEXT,
            model TEXT,
            mac_address TEXT,
            ip_address TEXT,
            last_endpoint TEXT,
            first_seen TEXT,
            last_seen TEXT
        );

        CREATE TABLE IF NOT EXISTS patient_stats_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id TEXT NOT NULL,
            computed_at TEXT NOT NULL,
            phone_activity_avg REAL,
            app_usage_avg REAL,
            movement_avg REAL,
            room_activity_avg REAL,
            unlocks_avg REAL,
            calls_avg REAL,
            sms_avg REAL,
            phone_activity_pct REAL,
            app_usage_pct REAL,
            movement_pct REAL,
            room_activity_pct REAL,
            unlocks_pct REAL,
            calls_pct REAL,
            sms_pct REAL
        );
        """
    )
    # Domyślne konto specjalisty do testów, żeby nie trzeba było nic rejestrować ręcznie
    cur.execute(
        "INSERT OR IGNORE INTO specialists (id, password) VALUES (?, ?)",
        ("spec001", "test1234"),
    )
    conn.commit()
    conn.close()


init_db()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Adres IP komputera w sieci lokalnej — pokazywany na górze strony logów,
# żeby nie trzeba było go szukać ręcznie przez ipconfig/ifconfig.
# ---------------------------------------------------------------------------

_cached_local_ip: Optional[str] = None


def get_local_ip() -> str:
    """Nie wysyła żadnych danych — otwarcie gniazda UDP do 8.8.8.8 tylko zmusza
    system operacyjny do wybrania, którym interfejsem sieciowym by wysłał pakiet,
    co ujawnia lokalny adres IP tego interfejsu. Działa nawet bez internetu."""
    global _cached_local_ip
    if _cached_local_ip:
        return _cached_local_ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        _cached_local_ip = s.getsockname()[0]
    except Exception:
        _cached_local_ip = "127.0.0.1"
    finally:
        s.close()
    return _cached_local_ip


# ---------------------------------------------------------------------------
# Śledzenie podpiętych urządzeń (dashboard w czasie rzeczywistym)
# ---------------------------------------------------------------------------
#
# Każda z 3 apek dokłada do swoich zapytań nagłówki:
#   X-Device-Id    - stały identyfikator instalacji (UUID wygenerowany lokalnie)
#   X-Device-Role  - "pacjent" / "specjalista" / "opiekun"
#   X-Device-Model - model telefonu (Build.MODEL), tylko do czytelności na liście
#   X-Device-Mac   - best-effort, PRAWIE ZAWSZE "niedostępny" (patrz niżej)
#
# WAŻNE o adresie MAC: od Androida 6.0 system celowo zwraca stałą, fałszywą
# wartość "02:00:00:00:00:00" zamiast prawdziwego MAC WiFi (ochrona prywatności),
# a od Androida 10 karta sieciowa dodatkowo losuje inny MAC dla każdej sieci.
# Żadna zwykła aplikacja (bez roota) nie ma sposobu, żeby to obejść — to nie jest
# błąd w tym kodzie, tylko świadome ograniczenie systemu Android. Dlatego jako
# realny identyfikator urządzenia w sieci używamy adresu IP (widzianego bezpośrednio
# przez serwer z połączenia TCP — to jest zawsze prawdziwe) oraz Device ID.

def track_device(request: Request):
    device_id = request.headers.get("X-Device-Id")
    if not device_id:
        return  # zwykłe zapytanie bez nagłówków (np. przeglądarka na /dashboard) — nic do zapisania

    role = request.headers.get("X-Device-Role", "?")
    model = request.headers.get("X-Device-Model", "?")
    mac = request.headers.get("X-Device-Mac") or "niedostępny (ograniczenie systemu Android)"
    ip = request.client.host if request.client else "?"
    ts = now_iso()

    conn = get_db()
    conn.execute(
        """INSERT INTO devices (device_id, role, model, mac_address, ip_address, last_endpoint, first_seen, last_seen)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(device_id) DO UPDATE SET
               role = excluded.role,
               model = excluded.model,
               mac_address = excluded.mac_address,
               ip_address = excluded.ip_address,
               last_endpoint = excluded.last_endpoint,
               last_seen = excluded.last_seen""",
        (device_id, role, model, mac, ip, f"{request.method} {request.url.path}", ts, ts),
    )
    conn.commit()
    conn.close()


@app.middleware("http")
async def device_tracking_middleware(request: Request, call_next):
    try:
        track_device(request)
    except Exception:
        pass  # śledzenie urządzeń nigdy nie może wywrócić prawdziwego zapytania
    return await call_next(request)


@app.middleware("http")
async def access_log_middleware(request: Request, call_next):
    """Zapisuje KAŻDE zapytanie do bufora w pamięci — to jest właśnie "strona z logami":
    prosty, czytelny dziennik tego, co dzieje się na serwerze w czasie rzeczywistym,
    bez potrzeby zaglądania w surowy output terminala."""
    start = time.perf_counter()
    status_code: Optional[int] = None
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        duration_ms = int((time.perf_counter() - start) * 1000)
        LOG_BUFFER.appendleft({
            "time": now_iso(),
            "method": request.method,
            "path": request.url.path,
            "status": status_code,
            "ip": request.client.host if request.client else "?",
            "duration_ms": duration_ms,
        })


# ---------------------------------------------------------------------------
# Modele (Pydantic) — muszą odpowiadać data class w Kotlinie
# ---------------------------------------------------------------------------

class RegisterPatientRequest(BaseModel):
    patient_id: str


class BehaviorDataRequest(BaseModel):
    phone_activity: float = 0
    app_usage: float = 0
    movement: float = 0
    room_activity: float = 0
    unlocks: float = 0
    calls: int = 0
    sms: int = 0


class LoginRequest(BaseModel):
    specialist_id: str
    password: str


class AddPatientRequest(BaseModel):
    patient_id: str


class UpdatePatientRequest(BaseModel):
    name: Optional[str] = None
    caregiver_slots: Optional[int] = None


class CaregiverAddRequest(BaseModel):
    patient_id: str
    caregiver_device_id: str


# ---------------------------------------------------------------------------
# PACJENT
# ---------------------------------------------------------------------------

@app.post("/patients/register")
def register_patient(req: RegisterPatientRequest):
    conn = get_db()
    conn.execute(
        "INSERT OR IGNORE INTO patients (id, name, last_sync) VALUES (?, ?, ?)",
        (req.patient_id, f"Pacjent {req.patient_id[:6]}", now_iso()),
    )
    conn.commit()
    conn.close()
    return {"status": "ok", "patient_id": req.patient_id}


@app.post("/patients/{patient_id}/data")
def send_behavior_data(patient_id: str, data: BehaviorDataRequest):
    conn = get_db()
    row = conn.execute("SELECT id FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Nieznany pacjent — najpierw wywołaj /patients/register")
    conn.execute(
        """INSERT INTO behavior_data
           (patient_id, timestamp, phone_activity, app_usage, movement, room_activity, unlocks, calls, sms)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            patient_id, now_iso(), data.phone_activity, data.app_usage,
            data.movement, data.room_activity, data.unlocks, data.calls, data.sms,
        ),
    )
    conn.execute("UPDATE patients SET last_sync = ? WHERE id = ?", (now_iso(), patient_id))
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.get("/patients/{patient_id}/status")
def patient_status(patient_id: str):
    """Pacjent odpytuje: czy specjalista zainicjował kontakt (do pokazania powiadomienia)."""
    conn = get_db()
    row = conn.execute(
        "SELECT id, created_at FROM messages WHERE patient_id = ? AND direction = 'to_patient' AND status = 'pending' ORDER BY id DESC LIMIT 1",
        (patient_id,),
    ).fetchone()
    patient = conn.execute("SELECT last_sync FROM patients WHERE id = ?", (patient_id,)).fetchone()
    conn.close()
    if not patient:
        raise HTTPException(404, "Nieznany pacjent")
    if row:
        return {"pending_contact": True, "message_id": row["id"], "created_at": row["created_at"]}
    return {"pending_contact": False}


@app.post("/patients/{patient_id}/status/{message_id}/ack")
def ack_message(patient_id: str, message_id: int):
    """Pacjent potwierdza odebranie powiadomienia (żeby nie pokazywać go w kółko)."""
    conn = get_db()
    conn.execute("UPDATE messages SET status = 'seen' WHERE id = ? AND patient_id = ?", (message_id, patient_id))
    conn.commit()
    conn.close()
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# STATYSTYKI — średnia z ostatnich 24h, przeliczana co najwyżej raz na godzinę
# ---------------------------------------------------------------------------
#
# Pacjent wysyła pojedyncze "pakiety" danych co 15 minut (SyncWorker w apce Pacjenta).
# Zamiast pokazywać specjaliście surowy ostatni odczyt (który mógł być przypadkowym
# wychyleniem), co godzinę liczymy średnią z ostatnich 24h i porównujemy ją z poprzednio
# policzoną średnią — różnica w % to właśnie strzałka "wzrost/spadek" widoczna w panelu
# specjalisty (dokładnie tak, jak na oryginalnych makietach z prezentacji).

STATS_METRICS = ["phone_activity", "app_usage", "movement", "room_activity", "unlocks", "calls", "sms"]
SNAPSHOT_MAX_AGE = timedelta(hours=1)


def compute_patient_snapshot(patient_id: str) -> Optional[dict]:
    """Liczy nową migawkę: średnią z ostatnich 24h dla każdej metryki oraz % zmiany
    względem POPRZEDNIEJ migawki (czyli sprzed ~godziny). Zwraca None, jeśli pacjent
    nie przysłał jeszcze żadnych danych w ogóle (nie ma sensu liczyć pustej migawki)."""
    conn = get_db()

    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="seconds")
    row = conn.execute(
        f"""SELECT {', '.join(f'AVG({m}) as {m}' for m in STATS_METRICS)}, COUNT(*) as n
            FROM behavior_data WHERE patient_id = ? AND timestamp >= ?""",
        (patient_id, cutoff),
    ).fetchone()

    if row is None or row["n"] == 0:
        conn.close()
        return None

    previous = conn.execute(
        "SELECT * FROM patient_stats_snapshots WHERE patient_id = ? ORDER BY id DESC LIMIT 1",
        (patient_id,),
    ).fetchone()

    averages = {m: row[m] for m in STATS_METRICS}
    percents = {}
    for m in STATS_METRICS:
        prev_avg = previous[f"{m}_avg"] if previous else None
        cur_avg = averages[m]
        if prev_avg is None or cur_avg is None:
            percents[m] = None
        elif prev_avg == 0:
            percents[m] = None if cur_avg == 0 else 100.0  # wzrost z zera — % nie ma matematycznego sensu
        else:
            percents[m] = round(((cur_avg - prev_avg) / prev_avg) * 100.0, 1)

    computed_at = now_iso()
    conn.execute(
        f"""INSERT INTO patient_stats_snapshots
            (patient_id, computed_at, {', '.join(f'{m}_avg' for m in STATS_METRICS)},
             {', '.join(f'{m}_pct' for m in STATS_METRICS)})
            VALUES (?, ?, {', '.join('?' for _ in STATS_METRICS)}, {', '.join('?' for _ in STATS_METRICS)})""",
        (patient_id, computed_at, *(averages[m] for m in STATS_METRICS), *(percents[m] for m in STATS_METRICS)),
    )
    conn.commit()
    conn.close()

    return {"computed_at": computed_at, "averages": averages, "percents": percents}


def ensure_fresh_snapshot(patient_id: str) -> Optional[dict]:
    """Zwraca najświeższą migawkę statystyk dla pacjenta, licząc nową tylko wtedy,
    gdy poprzednia ma więcej niż godzinę (albo nie ma żadnej jeszcze)."""
    conn = get_db()
    latest = conn.execute(
        "SELECT * FROM patient_stats_snapshots WHERE patient_id = ? ORDER BY id DESC LIMIT 1",
        (patient_id,),
    ).fetchone()
    conn.close()

    needs_refresh = True
    if latest:
        try:
            computed_at = datetime.fromisoformat(latest["computed_at"])
            needs_refresh = (datetime.now(timezone.utc) - computed_at) >= SNAPSHOT_MAX_AGE
        except Exception:
            needs_refresh = True

    if needs_refresh:
        fresh = compute_patient_snapshot(patient_id)
        if fresh is not None:
            return fresh
        # brak jakichkolwiek danych do policzenia — zwracamy starą migawkę, jeśli istnieje
        if latest is None:
            return None

    return {
        "computed_at": latest["computed_at"],
        "averages": {m: latest[f"{m}_avg"] for m in STATS_METRICS},
        "percents": {m: latest[f"{m}_pct"] for m in STATS_METRICS},
    }


async def _background_stats_refresher():
    """Odświeża statystyki WSZYSTKICH pacjentów co kilka minut w tle — dzięki temu
    "co godzinę jest na nowo przeliczana średnia" dzieje się naprawdę co godzinę,
    a nie tylko w chwili, gdy akurat specjalista otworzy panel."""
    while True:
        try:
            conn = get_db()
            patient_ids = [r["id"] for r in conn.execute("SELECT id FROM patients").fetchall()]
            conn.close()
            for pid in patient_ids:
                ensure_fresh_snapshot(pid)
        except Exception:
            pass
        await asyncio.sleep(BACKGROUND_STATS_INTERVAL_SECONDS)


def _maybe_open_dashboard_in_browser():
    """Otwiera stronę logów w domyślnej przeglądarce przy starcie serwera.
    Wyłączyć można zmienną środowiskową CHAD_SENCE_NO_BROWSER=1 (np. przy
    wielokrotnym restartowaniu serwera podczas pracy, żeby nie mnożyć zakładek).
    Na serwerze zewnętrznym (CHAD_SENCE_PUBLIC_URL ustawione) i tak nie ma GUI,
    więc pomijamy to automatycznie bez potrzeby osobnej flagi."""
    if os.environ.get("CHAD_SENCE_NO_BROWSER") or PUBLIC_URL:
        return
    port = os.environ.get("PORT", "8000")
    url = f"http://{get_local_ip()}:{port}/dashboard"
    try:
        webbrowser.open(url)
    except Exception:
        pass  # środowisko bez przeglądarki (np. serwer bez GUI) — nic się nie dzieje, serwer działa dalej


@app.on_event("startup")
async def on_startup():
    _maybe_open_dashboard_in_browser()
    asyncio.create_task(_background_stats_refresher())


# ---------------------------------------------------------------------------
# DANE WSPÓLNE (specjalista + opiekun czytają to samo)
# ---------------------------------------------------------------------------

@app.get("/patients/{patient_id}/data")
def get_latest_data(patient_id: str):
    conn = get_db()
    patient = conn.execute("SELECT * FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if not patient:
        conn.close()
        raise HTTPException(404, "Nieznany pacjent")
    row = conn.execute(
        "SELECT * FROM behavior_data WHERE patient_id = ? ORDER BY id DESC LIMIT 1",
        (patient_id,),
    ).fetchone()
    conn.close()

    snapshot = ensure_fresh_snapshot(patient_id)
    averages = snapshot["averages"] if snapshot else {m: None for m in STATS_METRICS}
    percents = snapshot["percents"] if snapshot else {m: None for m in STATS_METRICS}
    stats_computed_at = snapshot["computed_at"] if snapshot else None

    base = {
        "patient_id": patient_id, "name": patient["name"], "last_sync": patient["last_sync"],
        "stats_computed_at": stats_computed_at,
    }
    if not row:
        # brak danych jeszcze przesłanych przez pacjenta — zwracamy zera dla ostatniego odczytu
        base.update({m: 0 for m in STATS_METRICS})
    else:
        base.update({m: row[m] for m in STATS_METRICS})

    for m in STATS_METRICS:
        base[f"{m}_avg"] = averages.get(m)
        base[f"{m}_pct"] = percents.get(m)

    return base


# ---------------------------------------------------------------------------
# SPECJALISTA
# ---------------------------------------------------------------------------

@app.post("/specialists/login")
def specialist_login(req: LoginRequest):
    conn = get_db()
    row = conn.execute(
        "SELECT id FROM specialists WHERE id = ? AND password = ?",
        (req.specialist_id, req.password),
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(401, "Błędny login lub hasło")
    return {"status": "ok", "specialist_id": req.specialist_id}


@app.get("/specialists/{specialist_id}/patients")
def list_patients(specialist_id: str):
    conn = get_db()
    rows = conn.execute(
        "SELECT id, name, flag, last_sync FROM patients WHERE specialist_id = ?",
        (specialist_id,),
    ).fetchall()
    conn.close()
    return [{"id": r["id"], "name": r["name"], "flag": bool(r["flag"]), "last_sync": r["last_sync"]} for r in rows]


@app.post("/specialists/{specialist_id}/patients")
def add_patient(specialist_id: str, req: AddPatientRequest):
    conn = get_db()
    row = conn.execute("SELECT id FROM patients WHERE id = ?", (req.patient_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Pacjent o takim ID jeszcze nie zarejestrował się w systemie (nie uruchomił apki)")
    conn.execute(
        "UPDATE patients SET specialist_id = ? WHERE id = ?",
        (specialist_id, req.patient_id),
    )
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.patch("/specialists/{specialist_id}/patients/{patient_id}")
def update_patient(specialist_id: str, patient_id: str, req: UpdatePatientRequest):
    conn = get_db()
    if req.name is not None:
        conn.execute("UPDATE patients SET name = ? WHERE id = ?", (req.name, patient_id))
    if req.caregiver_slots is not None:
        conn.execute("UPDATE patients SET caregiver_slots = ? WHERE id = ?", (req.caregiver_slots, patient_id))
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.get("/patients/{patient_id}/caregivers/count")
def caregiver_count(patient_id: str):
    conn = get_db()
    row = conn.execute("SELECT COUNT(*) c FROM caregivers WHERE patient_id = ?", (patient_id,)).fetchone()
    slots = conn.execute("SELECT caregiver_slots FROM patients WHERE id = ?", (patient_id,)).fetchone()
    conn.close()
    return {"current": row["c"], "slots": slots["caregiver_slots"] if slots else 0}


@app.post("/patients/{patient_id}/contact")
def specialist_contact_patient(patient_id: str):
    """Specjalista inicjuje kontakt z pacjentem (po lokalnym potwierdzeniu w apce)."""
    conn = get_db()
    row = conn.execute("SELECT id FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Nieznany pacjent")
    conn.execute(
        "INSERT INTO messages (patient_id, direction, status, created_at) VALUES (?, 'to_patient', 'pending', ?)",
        (patient_id, now_iso()),
    )
    conn.commit()
    conn.close()
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# OPIEKUN
# ---------------------------------------------------------------------------

@app.post("/caregivers/add")
def caregiver_add_patient(req: CaregiverAddRequest):
    conn = get_db()
    patient = conn.execute("SELECT caregiver_slots FROM patients WHERE id = ?", (req.patient_id,)).fetchone()
    if not patient:
        conn.close()
        raise HTTPException(404, "Nie znaleziono pacjenta o takim ID")
    if patient["caregiver_slots"] <= 0:
        conn.close()
        raise HTTPException(403, "Specjalista nie zezwolił jeszcze na dodanie opiekunów dla tego pacjenta")
    current = conn.execute(
        "SELECT COUNT(*) c FROM caregivers WHERE patient_id = ?", (req.patient_id,)
    ).fetchone()["c"]
    if current >= patient["caregiver_slots"]:
        conn.close()
        raise HTTPException(403, "Limit opiekunów dla tego pacjenta został już osiągnięty")
    conn.execute(
        "INSERT OR IGNORE INTO caregivers (patient_id, caregiver_device_id) VALUES (?, ?)",
        (req.patient_id, req.caregiver_device_id),
    )
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.post("/patients/{patient_id}/contact-specialist")
def caregiver_contact_specialist(patient_id: str):
    """Opiekun inicjuje kontakt ze specjalistą -> pacjent dostaje '!' na liście specjalisty."""
    conn = get_db()
    row = conn.execute("SELECT id FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Nieznany pacjent")
    conn.execute("UPDATE patients SET flag = 1 WHERE id = ?", (patient_id,))
    conn.execute(
        "INSERT INTO messages (patient_id, direction, status, created_at) VALUES (?, 'to_specialist', 'pending', ?)",
        (patient_id, now_iso()),
    )
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.post("/specialists/{specialist_id}/patients/{patient_id}/clear-flag")
def clear_flag(specialist_id: str, patient_id: str):
    conn = get_db()
    conn.execute("UPDATE patients SET flag = 0 WHERE id = ?", (patient_id,))
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.get("/health")
def health():
    return {"status": "ok", "time": now_iso()}


# ---------------------------------------------------------------------------
# DASHBOARD — podgląd podpiętych urządzeń w czasie rzeczywistym
# ---------------------------------------------------------------------------

@app.get("/api/devices")
def api_devices():
    """Lista wszystkich urządzeń, które kiedykolwiek odezwały się do serwera,
    posortowana od najświeżej aktywności. Używane przez /dashboard (polling co 2s)."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
    conn.close()

    now = datetime.now(timezone.utc)
    result = []
    for r in rows:
        try:
            last_seen_dt = datetime.fromisoformat(r["last_seen"])
            seconds_ago = int((now - last_seen_dt).total_seconds())
        except Exception:
            seconds_ago = None
        result.append({
            "device_id": r["device_id"],
            "role": r["role"],
            "model": r["model"],
            "mac_address": r["mac_address"],
            "ip_address": r["ip_address"],
            "last_endpoint": r["last_endpoint"],
            "first_seen": r["first_seen"],
            "last_seen": r["last_seen"],
            "seconds_ago": seconds_ago,
            "online": seconds_ago is not None and seconds_ago < 60,
        })
    return result


@app.get("/api/logs")
def api_logs():
    """Ostatnie 300 zapytań do serwera, najnowsze pierwsze. Używane przez /dashboard."""
    return list(LOG_BUFFER)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    if PUBLIC_URL:
        # Serwer zewnętrzny — pokazujemy prawdziwy publiczny adres, a nie lokalny IP
        # kontenera (który i tak byłby bezużyteczny dla kogokolwiek spoza hosta).
        server_url = PUBLIC_URL.rstrip("/")
    else:
        ip = get_local_ip()
        server_info = request.scope.get("server")
        port = server_info[1] if server_info and server_info[1] else os.environ.get("PORT", "8000")
        server_url = f"http://{ip}:{port}"

    return f"""
<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="utf-8">
<title>ChaD-Sence — serwer</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 24px;
         background: #f4f5f7; color: #1a1a1a; }}
  h1 {{ font-size: 18px; margin: 0 0 4px; }}
  h2 {{ font-size: 15px; margin: 0 0 4px; }}
  .banner {{ background: #1a1a2e; color: white; padding: 16px 20px; border-radius: 10px;
             margin-bottom: 24px; }}
  .banner .ip {{ font-family: ui-monospace, monospace; font-size: 22px; font-weight: 700;
                 color: #7dd3fc; letter-spacing: 0.5px; }}
  .banner .label {{ font-size: 12px; color: #aaa; text-transform: uppercase; letter-spacing: 0.5px; }}
  section {{ margin-bottom: 28px; }}
  .sub {{ color: #666; font-size: 13px; margin-bottom: 12px; }}
  table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px;
          overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  th, td {{ text-align: left; padding: 8px 14px; font-size: 13px; border-bottom: 1px solid #eee; }}
  th {{ background: #fafafa; color: #555; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
  tr:last-child td {{ border-bottom: none; }}
  .role {{ display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; }}
  .role-pacjent {{ background: #e3f2fd; color: #1565c0; }}
  .role-specjalista {{ background: #f3e5f5; color: #6a1b9a; }}
  .role-opiekun {{ background: #e8f5e9; color: #2e7d32; }}
  .dot {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }}
  .dot-online {{ background: #2e7d32; }}
  .dot-offline {{ background: #bbb; }}
  .mono {{ font-family: ui-monospace, monospace; font-size: 12px; color: #444; }}
  .empty {{ padding: 40px; text-align: center; color: #888; background: white; border-radius: 8px; }}
  .muted {{ color: #999; }}
  .status-ok {{ color: #2e7d32; font-weight: 600; }}
  .status-err {{ color: #c62828; font-weight: 600; }}
  .logs-table {{ max-height: 420px; overflow-y: auto; display: block; }}
</style>
</head>
<body>

  <div class="banner">
    <div class="label">Serwer ChaD-Sence działa pod adresem</div>
    <div class="ip">{server_url}</div>
    <div class="label" style="margin-top: 6px;">Ten adres wpisz w każdej z 3 apek (Pacjent / Specjalista / Opiekun) — bez "http://"</div>
  </div>

  <section>
    <h2>Logi żądań (na żywo)</h2>
    <div class="sub">Każde zapytanie trafiające do serwera. Odświeża się co 2 sekundy.</div>
    <div id="logs">Ładowanie...</div>
  </section>

  <section>
    <h2>Podpięte urządzenia</h2>
    <div class="sub">"Online" = kontakt w ciągu ostatnich 60 sekund.</div>
    <div id="devices">Ładowanie...</div>
  </section>

<script>
function escapeHtml(s) {{
  return (s === null || s === undefined ? "" : String(s)).replace(/[&<>"']/g, c => ({{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}}[c]));
}}
function fmtAgo(sec) {{
  if (sec === null || sec === undefined) return "—";
  if (sec < 5) return "przed chwilą";
  if (sec < 60) return sec + " s temu";
  if (sec < 3600) return Math.floor(sec / 60) + " min temu";
  return Math.floor(sec / 3600) + " godz. temu";
}}
function fmtTime(iso) {{
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleTimeString("pl-PL");
}}

async function refreshLogs() {{
  const el = document.getElementById("logs");
  let logs;
  try {{
    const resp = await fetch("/api/logs");
    logs = await resp.json();
  }} catch (e) {{
    el.innerHTML = '<div class="empty">Błąd połączenia z serwerem.</div>';
    return;
  }}
  if (logs.length === 0) {{
    el.innerHTML = '<div class="empty">Jeszcze żadnych zapytań.</div>';
    return;
  }}
  let html = '<div class="logs-table"><table><thead><tr>' +
    '<th>Godzina</th><th>Metoda</th><th>Ścieżka</th><th>Status</th><th>Adres IP</th><th>Czas</th>' +
    '</tr></thead><tbody>';
  for (const l of logs) {{
    const statusClass = l.status && l.status < 400 ? "status-ok" : "status-err";
    html += '<tr>' +
      '<td class="mono">' + fmtTime(l.time) + '</td>' +
      '<td class="mono">' + escapeHtml(l.method) + '</td>' +
      '<td class="mono">' + escapeHtml(l.path) + '</td>' +
      '<td class="mono ' + statusClass + '">' + escapeHtml(l.status ?? "błąd") + '</td>' +
      '<td class="mono muted">' + escapeHtml(l.ip) + '</td>' +
      '<td class="mono muted">' + l.duration_ms + ' ms</td>' +
      '</tr>';
  }}
  html += '</tbody></table></div>';
  el.innerHTML = html;
}}

async function refreshDevices() {{
  const el = document.getElementById("devices");
  let devices;
  try {{
    const resp = await fetch("/api/devices");
    devices = await resp.json();
  }} catch (e) {{
    el.innerHTML = '<div class="empty">Błąd połączenia z serwerem.</div>';
    return;
  }}
  if (devices.length === 0) {{
    el.innerHTML = '<div class="empty">Żadne urządzenie jeszcze się nie odezwało.<br>Uruchom apkę Pacjent, Specjalista albo Opiekun.</div>';
    return;
  }}
  let html = '<table><thead><tr>' +
    '<th></th><th>Rola</th><th>Device ID</th><th>Model</th><th>Adres IP</th>' +
    '<th>MAC</th><th>Ostatni kontakt</th><th>Ostatnia akcja</th>' +
    '</tr></thead><tbody>';
  for (const d of devices) {{
    html += '<tr>' +
      '<td><span class="dot ' + (d.online ? "dot-online" : "dot-offline") + '"></span></td>' +
      '<td><span class="role role-' + escapeHtml(d.role) + '">' + escapeHtml(d.role) + '</span></td>' +
      '<td class="mono">' + escapeHtml(d.device_id.slice(0, 8)) + '…</td>' +
      '<td>' + escapeHtml(d.model) + '</td>' +
      '<td class="mono">' + escapeHtml(d.ip_address) + '</td>' +
      '<td class="mono muted">' + escapeHtml(d.mac_address) + '</td>' +
      '<td>' + fmtAgo(d.seconds_ago) + '</td>' +
      '<td class="mono muted">' + escapeHtml(d.last_endpoint) + '</td>' +
      '</tr>';
  }}
  html += '</tbody></table>';
  el.innerHTML = html;
}}

function refreshAll() {{ refreshLogs(); refreshDevices(); }}
refreshAll();
setInterval(refreshAll, 2000);
</script>
</body>
</html>
"""
