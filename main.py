"""
DEPRESS-SENSE — lokalny serwer testowy
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
import hashlib
import hmac
import json
import os
import secrets
import socket
import sqlite3
import time
import uuid
import webbrowser
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field

# Ścieżkę do pliku bazy można nadpisać zmienną środowiskową DEPRESS_SENSE_DB_PATH —
# przy wdrożeniu na serwerze zewnętrznym (np. Railway) wskazujemy nią ścieżkę
# na trwałym wolumenie (np. "/data/depress_sense.db"), żeby dane przeżyły restart
# kontenera. Lokalnie (bez tej zmiennej) zachowanie jest identyczne jak dotychczas.
#
# UWAGA PRZY REBRANDINGU (ChaD-Sence -> DEPRESS-SENSE): jeśli na Railway są już
# ustawione STARE zmienne (CHAD_SENCE_DB_PATH / CHAD_SENCE_PUBLIC_URL), czytamy je
# nadal jako fallback — inaczej serwer po redeployu cicho zgubiłby ścieżkę do
# trwałego wolumenu (DB_PATH wróciłby do domyślnej, czyli do pustej bazy w
# efemerycznym systemie plików kontenera = pozorna "utrata" wszystkich danych).
# Docelowo warto w Railway podmienić nazwy zmiennych na nowe (DEPRESS_SENSE_*),
# ale do tego czasu stare nazwy nadal działają.
DB_PATH = os.environ.get("DEPRESS_SENSE_DB_PATH") or os.environ.get("CHAD_SENCE_DB_PATH", "depress_sense.db")
_db_dir = os.path.dirname(DB_PATH)
if _db_dir:
    os.makedirs(_db_dir, exist_ok=True)

# Gdy serwer działa na zewnętrznym hoście (nie w lokalnej sieci WiFi), adres IP
# wykryty lokalnie nie ma sensu pokazywać w banerze — trzeba podać prawdziwy,
# publiczny adres (np. https://depresssense-production.up.railway.app) tą zmienną.
# Jej obecność jest też sygnałem "jesteśmy w chmurze", więc przy okazji wyłącza
# próbę otwarcia przeglądarki przy starcie (i tak by się nie udała bez GUI).
PUBLIC_URL = os.environ.get("DEPRESS_SENSE_PUBLIC_URL") or os.environ.get("CHAD_SENCE_PUBLIC_URL")

app = FastAPI(title="DEPRESS-SENSE Local Server")

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


# ---------------------------------------------------------------------------
# Bezpieczeństwo: hasła, logowanie administratora, ograniczenie prób logowania
# ---------------------------------------------------------------------------

_PBKDF2_ITERATIONS = 200_000
_PASSWORD_PREFIX = "pbkdf2_sha256$"
MIN_PASSWORD_LENGTH = 8


def hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256 z losową solą (sama biblioteka standardowa — bez nowej
    zależności w requirements.txt). Format: pbkdf2_sha256$iteracje$sól$hash."""
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return f"{_PASSWORD_PREFIX}{_PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(stored: str, password: str) -> bool:
    """Porównuje hasło z zapisanym hashem. Wiersze sprzed wprowadzenia hashowania
    (hasło jawnym tekstem, bez prefiksu) też są akceptowane — i przy pierwszym
    udanym logowaniu zostają automatycznie przepisane na hash (patrz specialist_login),
    więc istniejące konta na Railway nie przestają działać po aktualizacji."""
    if stored.startswith(_PASSWORD_PREFIX):
        try:
            _, iters, salt_hex, hash_hex = stored.split("$")
            dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iters))
        except Exception:
            return False
        return hmac.compare_digest(dk.hex(), hash_hex)
    return hmac.compare_digest(stored.encode("utf-8"), password.encode("utf-8"))


def is_hashed(stored: str) -> bool:
    return stored.startswith(_PASSWORD_PREFIX)


# Logowanie administratora (panel /admin, /dashboard i endpointy administracyjne):
# HTTP Basic, login z DEPRESS_SENSE_ADMIN_USER (domyślnie "admin"), hasło z
# DEPRESS_SENSE_ADMIN_PASSWORD. Bez tej zmiennej: lokalnie (brak PUBLIC_URL) panel
# działa otwarcie jak dotąd; na serwerze zewnętrznym jest ZABLOKOWANY, dopóki
# hasło nie zostanie ustawione — lepiej zablokować panel niż zostawić go otwartego
# dla każdego, kto zna adres serwera.
ADMIN_USER = os.environ.get("DEPRESS_SENSE_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("DEPRESS_SENSE_ADMIN_PASSWORD")
_admin_basic = HTTPBasic(auto_error=False)


def _is_local_direct_request(request: Request) -> bool:
    """True tylko dla żądania prosto z tego samego komputera (loopback), BEZ pośrednika.
    Na Railway ruch przychodzi przez proxy (adres klienta ≠ loopback, są nagłówki
    X-Forwarded-*), więc tam to nigdy nie jest prawdą."""
    host = request.client.host if request.client else ""
    proxied = "x-forwarded-for" in request.headers or "x-forwarded-proto" in request.headers
    return host in ("127.0.0.1", "::1", "localhost") and not proxied


def require_admin(request: Request, credentials: Optional[HTTPBasicCredentials] = Depends(_admin_basic)):
    if not ADMIN_PASSWORD:
        # Bez hasła panel jest otwarty WYŁĄCZNIE dla żądań z tego samego komputera
        # (lokalne uruchomienie "Run" w IDE). Każde inne — w tym serwer na Railway,
        # także gdy nie ustawiono DEPRESS_SENSE_PUBLIC_URL — jest odrzucane.
        # (Wcześniej brak PUBLIC_URL traktowano jak "lokalnie" i panel był otwarty
        # dla całego internetu.)
        if _is_local_direct_request(request):
            return
        raise HTTPException(
            503,
            "Panel administratora jest wyłączony: ustaw zmienną środowiskową "
            "DEPRESS_SENSE_ADMIN_PASSWORD na serwerze (Railway → Variables) i zrestartuj usługę.",
        )
    ok = (
        credentials is not None
        and secrets.compare_digest(credentials.username.encode("utf-8"), ADMIN_USER.encode("utf-8"))
        and secrets.compare_digest(credentials.password.encode("utf-8"), ADMIN_PASSWORD.encode("utf-8"))
    )
    if not ok:
        raise HTTPException(
            401, "Wymagane logowanie administratora",
            headers={"WWW-Authenticate": 'Basic realm="DEPRESS-SENSE admin", charset="UTF-8"'},
        )


# Ograniczenie prób zgadywania hasła specjalisty: po 5 nieudanych próbach w ciągu
# 5 minut dla danego loginu kolejne są odrzucane (429). Licznik w pamięci procesu —
# wystarcza na prototyp z jedną instancją serwera.
_LOGIN_FAILS: dict = {}
LOGIN_MAX_FAILS = 5
LOGIN_WINDOW_SECONDS = 300


def _login_key(specialist_id: str) -> str:
    return specialist_id.strip().lower()


def _check_login_throttle(key: str):
    now = time.time()
    fails = [t for t in _LOGIN_FAILS.get(key, []) if now - t < LOGIN_WINDOW_SECONDS]
    _LOGIN_FAILS[key] = fails
    if len(fails) >= LOGIN_MAX_FAILS:
        raise HTTPException(429, "Zbyt wiele nieudanych prób logowania. Spróbuj ponownie za kilka minut.")


def _register_login_failure(key: str):
    _LOGIN_FAILS.setdefault(key, []).append(time.time())


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
            flag INTEGER NOT NULL DEFAULT 0,
            last_action_at TEXT,
            -- 'pending' = pacjent zarejestrował się w apce, ale żaden specjalista jeszcze
            -- go nie przypisał do siebie (kwestia podpisania zgód/umów i odpowiedzialności) —
            -- w tym stanie pacjent NIE MOŻE wysyłać danych (patrz send_behavior_data niżej).
            -- 'active' = przypisany, może korzystać z aplikacji normalnie.
            status TEXT NOT NULL DEFAULT 'pending'
        );

        CREATE TABLE IF NOT EXISTS specialists (
            id TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            -- Konto założone przez panel admina (zakładka "Specjaliści") dostaje tu 1 —
            -- przy pierwszym logowaniu apka Specjalisty MUSI wymusić zmianę hasła, zanim
            -- pozwoli przejść dalej (patrz /specialists/login i /specialists/change-password).
            must_change_password INTEGER NOT NULL DEFAULT 1
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
            -- Mobilność z GPS — NULL (nie 0!) oznacza "pacjent nie dał zgody na lokalizację
            -- w tym momencie", odróżnione celowo od "zmierzono 0% ruchu". Osobna kolumna od
            -- 'movement' (żyroskop), bo to dwa różne obszary z dokumentu wymagań
            -- ("Aktywność ruchowa" vs "Mobilność").
            mobility REAL,
            room_activity REAL DEFAULT 0,
            unlocks REAL DEFAULT 0,
            calls INTEGER DEFAULT 0,
            sms INTEGER DEFAULT 0,
            screen_time_minutes REAL DEFAULT 0,
            -- Faza 9: czas (minuty) w oknie synchronizacji spędzony w aplikacjach danej
            -- KATEGORII SYSTEMOWEJ Androida (ApplicationInfo.category, API 26+) — NIE
            -- identyfikujemy konkretnych aplikacji, tylko ich deklarowaną kategorię, co
            -- jest zgodne z zasadą "bez analizy treści". category_other_minutes to
            -- wszystko poza "społeczne"/"produktywność" (gry, multimedia, mapy, a przede
            -- wszystkim aplikacje, które NIE zadeklarowały żadnej kategorii — w praktyce
            -- większość, bo deklaracja jest opcjonalna po stronie twórcy aplikacji;
            -- to ograniczenie samego API Androida, patrz DataCollector.kt).
            category_social_minutes REAL DEFAULT 0,
            category_productivity_minutes REAL DEFAULT 0,
            category_other_minutes REAL DEFAULT 0,
            -- Faza 9: wzbogacenie metadanych komunikacyjnych o ŁĄCZNY CZAS TRWANIA
            -- połączeń w oknie (minuty) — wciąż metadane (długość), nie treść rozmowy.
            call_duration_minutes REAL DEFAULT 0
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
            screen_time_minutes_avg REAL,
            mobility_avg REAL,
            category_social_minutes_avg REAL,
            category_productivity_minutes_avg REAL,
            category_other_minutes_avg REAL,
            call_duration_minutes_avg REAL,
            phone_activity_pct REAL,
            app_usage_pct REAL,
            movement_pct REAL,
            room_activity_pct REAL,
            unlocks_pct REAL,
            calls_pct REAL,
            sms_pct REAL,
            screen_time_minutes_pct REAL,
            mobility_pct REAL,
            category_social_minutes_pct REAL,
            category_productivity_minutes_pct REAL,
            category_other_minutes_pct REAL,
            call_duration_minutes_pct REAL
        );

        CREATE TABLE IF NOT EXISTS patient_circadian_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id TEXT NOT NULL,
            computed_at TEXT NOT NULL,
            hourly_profile TEXT NOT NULL,
            deviation_pct REAL,
            shifted INTEGER
        );

        -- Faza 3: krótka samoocena wypełniana przez pacjenta kilka razy w tygodniu
        -- (nastrój/energia/sen/anhedonia, skala 0-10, WYŻSZA wartość = lepiej —
        -- celowo jednolita skala dla wszystkich 4 pytań, patrz SelfAssessmentScreen.kt
        -- w apce Pacjenta po stronie Kotlin). To NIE jest kwestionariusz kliniczny
        -- (PHQ-9/MADRS to osobne, przyszłe fazy) — to szybki, nieformalny check-in.
        CREATE TABLE IF NOT EXISTS self_assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            mood INTEGER NOT NULL,
            energy INTEGER NOT NULL,
            sleep_quality INTEGER NOT NULL,
            anhedonia INTEGER NOT NULL
        );

        -- Faza 4: PHQ-9, kwestionariusz przesiewowy nasilenia objawów depresyjnych,
        -- wypełniany RAZ W TYGODNIU. 9 pytań, każde skalowane 0-3 (0=wcale,
        -- 3=niemal każdego dnia) — standardowa skala PHQ-9, NIE jest to to samo co
        -- samoocena (self_assessments, Faza 3), która jest nieformalnym check-inem.
        -- item9 dotyczy myśli o śmierci/samouszkodzeniu — jego wynik > 0 uruchamia
        -- MODUŁ BEZPIECZEŃSTWA (Faza 5, patrz 06_PROCEDURA_BEZPIECZENSTWA.docx):
        -- (1) komunikat bezpieczeństwa w apce, (2) numer 112, (3) oznaczenie wyniku
        -- do weryfikacji przez upoważnionego lekarza (safety_reviewed poniżej).
        -- Aplikacja CELOWO nie interpretuje samodzielnie stopnia ryzyka — tylko flaguje.
        CREATE TABLE IF NOT EXISTS phq9_responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            item1 INTEGER NOT NULL,
            item2 INTEGER NOT NULL,
            item3 INTEGER NOT NULL,
            item4 INTEGER NOT NULL,
            item5 INTEGER NOT NULL,
            item6 INTEGER NOT NULL,
            item7 INTEGER NOT NULL,
            item8 INTEGER NOT NULL,
            item9 INTEGER NOT NULL,
            total_score INTEGER NOT NULL,
            severity TEXT NOT NULL,
            safety_flag INTEGER NOT NULL DEFAULT 0,
            safety_reviewed INTEGER NOT NULL DEFAULT 0,
            safety_reviewed_at TEXT,
            safety_reviewed_by TEXT
        );

        -- Faza 6: MADRS (Montgomery-Åsberg Depression Rating Scale) — ocena KLINICZNA,
        -- wprowadzana przez specjalistę/lekarza (NIE wypełniana samodzielnie przez
        -- pacjenta), w punktach T0 i ok. 4/8/12 tygodniu terapii. 10 pytań, każde
        -- skalowane 0-6 (standardowa skala MADRS). item10 dotyczy myśli samobójczych —
        -- tak jak w PHQ-9 (item9), wynik > 0 jest flagowany (safety_flag), ale TUTAJ
        -- specjalista jest już obecny w momencie wprowadzania wyniku, więc nie ma
        -- osobnego ekranu "komunikatu bezpieczeństwa" jak w apce Pacjenta — flaga
        -- służy dokumentacji/audytowi oraz przyszłym wykresom trendu (Faza 7).
        CREATE TABLE IF NOT EXISTS madrs_assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id TEXT NOT NULL,
            specialist_id TEXT,
            timestamp TEXT NOT NULL,
            occasion TEXT,
            item1 INTEGER NOT NULL,
            item2 INTEGER NOT NULL,
            item3 INTEGER NOT NULL,
            item4 INTEGER NOT NULL,
            item5 INTEGER NOT NULL,
            item6 INTEGER NOT NULL,
            item7 INTEGER NOT NULL,
            item8 INTEGER NOT NULL,
            item9 INTEGER NOT NULL,
            item10 INTEGER NOT NULL,
            total_score INTEGER NOT NULL,
            severity TEXT NOT NULL,
            safety_flag INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    # Domyślne konto specjalisty do testów, żeby nie trzeba było nic rejestrować ręcznie —
    # must_change_password=0, bo to konto deweloperskie, a nie realne konto badacza.
    # Na serwerze zewnętrznym (PUBLIC_URL) konto z publicznie znanym hasłem NIE jest już
    # tworzone domyślnie — chyba że jawnie ustawiono DEPRESS_SENSE_SEED_TEST_ACCOUNT=1.
    if not (PUBLIC_URL or os.environ.get("RAILWAY_ENVIRONMENT") or os.environ.get("RAILWAY_PROJECT_ID")) \
            or os.environ.get("DEPRESS_SENSE_SEED_TEST_ACCOUNT") == "1":
        cur.execute(
            "INSERT OR IGNORE INTO specialists (id, password, must_change_password) VALUES (?, ?, 0)",
            ("spec001", hash_password("test1234")),
        )
    conn.commit()
    conn.close()
    _migrate_existing_columns()


def _migrate_existing_columns():
    """CREATE TABLE IF NOT EXISTS nie dodaje nowych kolumn do tabel, które już
    istnieją (np. baza utworzona przed dodaniem tej funkcji — zwłaszcza na
    serwerze wdrożonym na trwałym wolumenie, gdzie plik bazy przeżywa redeploy).
    Dlatego sprawdzamy brakujące kolumny ręcznie i dopisujemy je przez ALTER TABLE,
    zamiast kasować/odtwarzać tabelę — to jest właśnie ta "architektura append-only":
    nawet aktualizacja kodu serwera nie rusza już zapisanych danych."""
    conn = get_db()
    migrations = {
        "patients": [("last_action_at", "TEXT"), ("status", "TEXT NOT NULL DEFAULT 'pending'")],
        "specialists": [("must_change_password", "INTEGER NOT NULL DEFAULT 1")],
        "behavior_data": [
            ("screen_time_minutes", "REAL DEFAULT 0"),
            ("mobility", "REAL"),
            ("category_social_minutes", "REAL DEFAULT 0"),
            ("category_productivity_minutes", "REAL DEFAULT 0"),
            ("category_other_minutes", "REAL DEFAULT 0"),
            ("call_duration_minutes", "REAL DEFAULT 0"),
        ],
        "patient_stats_snapshots": [
            ("screen_time_minutes_avg", "REAL"),
            ("screen_time_minutes_pct", "REAL"),
            ("mobility_avg", "REAL"),
            ("mobility_pct", "REAL"),
            ("category_social_minutes_avg", "REAL"),
            ("category_social_minutes_pct", "REAL"),
            ("category_productivity_minutes_avg", "REAL"),
            ("category_productivity_minutes_pct", "REAL"),
            ("category_other_minutes_avg", "REAL"),
            ("category_other_minutes_pct", "REAL"),
            ("call_duration_minutes_avg", "REAL"),
            ("call_duration_minutes_pct", "REAL"),
        ],
    }
    for table, columns in migrations.items():
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        for col_name, col_type in columns:
            if col_name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}")
    conn.commit()
    # Pacjenci sprzed tej zmiany: ci, których specjalista już przypisał (specialist_id
    # ustawione), traktujemy jako 'active' z mocy wstecznej — to nie są nowi, nieprzypisani
    # uczestnicy, więc nie ma sensu nagle blokować im wysyłania danych.
    conn.execute(
        "UPDATE patients SET status = 'active' WHERE specialist_id IS NOT NULL AND status = 'pending'"
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
    # None = pacjent nie dał (jeszcze) zgody na lokalizację — odróżnione celowo od 0.0
    # ("zmierzono, stoi w miejscu"). Patrz DataCollector.kt (mobilityPercent) w apce Pacjenta.
    mobility: Optional[float] = None
    room_activity: float = 0
    unlocks: float = 0
    calls: int = 0
    sms: int = 0
    # Realny czas korzystania z telefonu w oknie synchronizacji (minuty), a nie %
    # jak phone_activity — patrz DataCollector.kt w apce Pacjenta.
    screen_time_minutes: float = 0
    # Faza 9: czas (minuty) w kategoriach aplikacji Androida — bez identyfikacji
    # konkretnej aplikacji, tylko systemowa kategoria (ApplicationInfo.category).
    category_social_minutes: float = 0
    category_productivity_minutes: float = 0
    category_other_minutes: float = 0
    # Faza 9: wzbogacenie metadanych komunikacyjnych — łączny czas trwania połączeń
    # w oknie (minuty), wciąż metadana, nie treść rozmowy.
    call_duration_minutes: float = 0


class SelfAssessmentRequest(BaseModel):
    # Skala 0-10, WYŻSZA wartość = lepiej, jednolicie dla wszystkich 4 pytań
    # (celowo, żeby UI w apce Pacjenta nie musiał tłumaczyć różnych kierunków skali —
    # patrz komentarz przy SelfAssessmentScreen.kt). To NIE jest PHQ-9/MADRS.
    mood: int = Field(ge=0, le=10)
    energy: int = Field(ge=0, le=10)
    sleep_quality: int = Field(ge=0, le=10)
    anhedonia: int = Field(ge=0, le=10)


class Phq9Request(BaseModel):
    # Standardowa skala PHQ-9: każde pytanie 0-3 (0=wcale, 1=kilka dni,
    # 2=więcej niż połowa dni, 3=niemal każdego dnia). item9 = myśli o śmierci/
    # samouszkodzeniu — patrz komentarz przy tabeli phq9_responses w init_db().
    item1: int = Field(ge=0, le=3)
    item2: int = Field(ge=0, le=3)
    item3: int = Field(ge=0, le=3)
    item4: int = Field(ge=0, le=3)
    item5: int = Field(ge=0, le=3)
    item6: int = Field(ge=0, le=3)
    item7: int = Field(ge=0, le=3)
    item8: int = Field(ge=0, le=3)
    item9: int = Field(ge=0, le=3)


class MadrsRequest(BaseModel):
    # Standardowa skala MADRS: 10 pytań, każde 0-6 (patrz komentarz przy tabeli
    # madrs_assessments w init_db()). item10 = myśli samobójcze.
    item1: int = Field(ge=0, le=6)
    item2: int = Field(ge=0, le=6)
    item3: int = Field(ge=0, le=6)
    item4: int = Field(ge=0, le=6)
    item5: int = Field(ge=0, le=6)
    item6: int = Field(ge=0, le=6)
    item7: int = Field(ge=0, le=6)
    item8: int = Field(ge=0, le=6)
    item9: int = Field(ge=0, le=6)
    item10: int = Field(ge=0, le=6)
    # Etykieta punktu pomiaru wg protokołu (np. "T0", "Tydzień 4") — dowolny tekst,
    # wpisywany przez specjalistę; serwer niczego z niej nie wylicza automatycznie.
    occasion: Optional[str] = None
    specialist_id: Optional[str] = None


class LoginRequest(BaseModel):
    specialist_id: str
    password: str


class RegisterSpecialistRequest(BaseModel):
    specialist_id: str
    password: str


class ChangePasswordRequest(BaseModel):
    specialist_id: str
    old_password: str
    new_password: str


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
    row = conn.execute("SELECT id, status FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Nieznany pacjent — najpierw wywołaj /patients/register")
    if row["status"] != "active":
        conn.close()
        raise HTTPException(
            403,
            "Pacjent nie został jeszcze przypisany do specjalisty — dane nie są jeszcze zbierane.",
        )
    conn.execute(
        """INSERT INTO behavior_data
           (patient_id, timestamp, phone_activity, app_usage, movement, mobility, room_activity, unlocks, calls, sms,
            screen_time_minutes, category_social_minutes, category_productivity_minutes, category_other_minutes,
            call_duration_minutes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            patient_id, now_iso(), data.phone_activity, data.app_usage,
            data.movement, data.mobility, data.room_activity, data.unlocks, data.calls, data.sms,
            data.screen_time_minutes, data.category_social_minutes, data.category_productivity_minutes,
            data.category_other_minutes, data.call_duration_minutes,
        ),
    )
    conn.execute("UPDATE patients SET last_sync = ? WHERE id = ?", (now_iso(), patient_id))
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.get("/patients/{patient_id}/status")
def patient_status(patient_id: str):
    """Pacjent odpytuje: czy specjalista zainicjował kontakt (do pokazania powiadomienia)
    oraz czy konto jest już aktywne (account_status) — dopóki 'pending', apka Pacjenta
    nie uruchamia zbierania/wysyłania danych (patrz procedura przypisania pacjenta)."""
    conn = get_db()
    row = conn.execute(
        "SELECT id, created_at FROM messages WHERE patient_id = ? AND direction = 'to_patient' AND status = 'pending' ORDER BY id DESC LIMIT 1",
        (patient_id,),
    ).fetchone()
    patient = conn.execute("SELECT last_sync, status FROM patients WHERE id = ?", (patient_id,)).fetchone()
    # "Dzisiaj" liczone jako doba UTC (prosty, jednoznaczny podział na serwerze) —
    # wystarczające dla "czy pokazać dziś przypomnienie o samoocenie", nie wymaga
    # znajomości strefy czasowej pacjenta.
    today_start = datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00")
    done_today_row = conn.execute(
        "SELECT 1 FROM self_assessments WHERE patient_id = ? AND timestamp >= ? LIMIT 1",
        (patient_id, today_start),
    ).fetchone()
    conn.close()
    if not patient:
        raise HTTPException(404, "Nieznany pacjent")
    phq9 = phq9_summary(patient_id)
    result = {
        "account_status": patient["status"],
        "self_assessment_done_today": done_today_row is not None,
        "phq9_due": phq9["phq9_due"],
    }
    if row:
        result.update({"pending_contact": True, "message_id": row["id"], "created_at": row["created_at"]})
    else:
        result["pending_contact"] = False
    return result


@app.post("/patients/{patient_id}/status/{message_id}/ack")
def ack_message(patient_id: str, message_id: int):
    """Pacjent potwierdza odebranie powiadomienia (żeby nie pokazywać go w kółko)."""
    conn = get_db()
    conn.execute("UPDATE messages SET status = 'seen' WHERE id = ? AND patient_id = ?", (message_id, patient_id))
    conn.commit()
    conn.close()
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# FAZA 3 — SAMOOCENA KRÓTKA (nastrój/energia/sen/anhedonia, 0-10, kilka razy w tygodniu)
# ---------------------------------------------------------------------------
#
# To NIE jest kwestionariusz kliniczny — PHQ-9 i MADRS to osobne, przyszłe fazy
# (Faza 4 i Faza 6), z OSOBNYMI tabelami/endpointami. Samoocena jest celowo prosta:
# 4 liczby 0-10 raz (lub kilka razy) dziennie, bez żadnej automatycznej interpretacji
# klinicznej tutaj — surowe wartości trafiają do panelu specjalisty jako trend.

def self_assessment_summary(patient_id: str) -> dict:
    """Najnowszy wpis samooceny + liczba DNI z co najmniej jednym wpisem w ostatnich
    7 dniach (prosty wskaźnik regularności wypełniania, nie wymagamy codziennie —
    dokument wymagań mówi 'kilka razy w tygodniu', nie 'codziennie')."""
    conn = get_db()
    latest = conn.execute(
        "SELECT timestamp, mood, energy, sleep_quality, anhedonia FROM self_assessments "
        "WHERE patient_id = ? ORDER BY id DESC LIMIT 1",
        (patient_id,),
    ).fetchone()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat(timespec="seconds")
    rows = conn.execute(
        "SELECT timestamp FROM self_assessments WHERE patient_id = ? AND timestamp >= ?",
        (patient_id, cutoff),
    ).fetchall()
    conn.close()
    distinct_days = {r["timestamp"][:10] for r in rows}  # "YYYY-MM-DD" z ISO timestampu (UTC)
    result = {"self_assessment_count_7d": len(distinct_days)}
    if latest:
        result["self_assessment"] = {
            "timestamp": latest["timestamp"],
            "mood": latest["mood"],
            "energy": latest["energy"],
            "sleep_quality": latest["sleep_quality"],
            "anhedonia": latest["anhedonia"],
        }
    else:
        result["self_assessment"] = None
    return result


@app.post("/patients/{patient_id}/self-assessment")
def submit_self_assessment(patient_id: str, req: SelfAssessmentRequest):
    conn = get_db()
    row = conn.execute("SELECT id, status FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Nieznany pacjent — najpierw wywołaj /patients/register")
    if row["status"] != "active":
        conn.close()
        raise HTTPException(
            403,
            "Pacjent nie został jeszcze przypisany do specjalisty — dane nie są jeszcze zbierane.",
        )
    conn.execute(
        """INSERT INTO self_assessments (patient_id, timestamp, mood, energy, sleep_quality, anhedonia)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (patient_id, now_iso(), req.mood, req.energy, req.sleep_quality, req.anhedonia),
    )
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.get("/patients/{patient_id}/self-assessments")
def list_self_assessments(patient_id: str, limit: int = 30):
    """Historia samooceny (od najnowszej) — do przyszłych wykresów trendu
    (Faza 7, panel badacza) i ewentualnego widoku historii w apce Pacjenta."""
    conn = get_db()
    patient = conn.execute("SELECT id FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if not patient:
        conn.close()
        raise HTTPException(404, "Nieznany pacjent")
    rows = conn.execute(
        "SELECT timestamp, mood, energy, sleep_quality, anhedonia FROM self_assessments "
        "WHERE patient_id = ? ORDER BY id DESC LIMIT ?",
        (patient_id, max(1, min(limit, 365))),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# FAZA 4 — PHQ-9 (raz w tygodniu) + rdzeń MODUŁU BEZPIECZEŃSTWA (Faza 5)
# ---------------------------------------------------------------------------
#
# item9 (myśli o śmierci/samouszkodzeniu) > 0 uruchamia procedurę z
# 06_PROCEDURA_BEZPIECZENSTWA_DEPRESS-SENSE.docx: (1) komunikat bezpieczeństwa
# w apce Pacjenta zaraz po wysłaniu, (2) numer 112, (3) oznaczenie wyniku jako
# wymagającego weryfikacji przez upoważnionego lekarza — stąd safety_flag/
# safety_reviewed poniżej. Serwer NIE interpretuje samodzielnie stopnia ryzyka
# (zgodnie z procedurą, pkt 4: "Aplikacja nie interpretuje samodzielnie stopnia
# ryzyka i nie zmienia leczenia") — tylko flaguje i udostępnia specjaliście.

PHQ9_SEVERITY_BANDS = [
    (4, "minimalne"),
    (9, "łagodne"),
    (14, "umiarkowane"),
    (19, "umiarkowanie ciężkie"),
    (27, "ciężkie"),
]


def phq9_severity(total_score: int) -> str:
    for max_score, label in PHQ9_SEVERITY_BANDS:
        if total_score <= max_score:
            return label
    return "ciężkie"


@app.post("/patients/{patient_id}/phq9")
def submit_phq9(patient_id: str, req: Phq9Request):
    conn = get_db()
    row = conn.execute("SELECT id, status FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Nieznany pacjent — najpierw wywołaj /patients/register")
    if row["status"] != "active":
        conn.close()
        raise HTTPException(
            403,
            "Pacjent nie został jeszcze przypisany do specjalisty — dane nie są jeszcze zbierane.",
        )
    items = [req.item1, req.item2, req.item3, req.item4, req.item5, req.item6, req.item7, req.item8, req.item9]
    total_score = sum(items)
    severity = phq9_severity(total_score)
    safety_flag = req.item9 > 0
    ts = now_iso()
    conn.execute(
        """INSERT INTO phq9_responses
           (patient_id, timestamp, item1, item2, item3, item4, item5, item6, item7, item8, item9,
            total_score, severity, safety_flag, safety_reviewed)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
        (patient_id, ts, *items, total_score, severity, int(safety_flag)),
    )
    conn.commit()
    conn.close()
    # safety_flag w odpowiedzi steruje tym, czy apka Pacjenta natychmiast pokaże
    # komunikat bezpieczeństwa + numer 112 (patrz SafetyMessageScreen.kt) — bez
    # czekania na żadną interpretację serwera, zgodnie z procedurą bezpieczeństwa.
    return {
        "status": "ok",
        "timestamp": ts,
        "total_score": total_score,
        "severity": severity,
        "safety_flag": safety_flag,
    }


@app.get("/patients/{patient_id}/phq9")
def list_phq9(patient_id: str, limit: int = 30):
    """Historia PHQ-9 (od najnowszej) — do przyszłych wykresów trendu (Faza 7)."""
    conn = get_db()
    patient = conn.execute("SELECT id FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if not patient:
        conn.close()
        raise HTTPException(404, "Nieznany pacjent")
    rows = conn.execute(
        "SELECT id, timestamp, total_score, severity, safety_flag, safety_reviewed FROM phq9_responses "
        "WHERE patient_id = ? ORDER BY id DESC LIMIT ?",
        (patient_id, max(1, min(limit, 365))),
    ).fetchall()
    conn.close()
    return [
        {**dict(r), "safety_flag": bool(r["safety_flag"]), "safety_reviewed": bool(r["safety_reviewed"])}
        for r in rows
    ]


def phq9_summary(patient_id: str) -> dict:
    """Najnowszy wynik PHQ-9 + czy minął już tydzień od ostatniego (phq9_due) —
    do przypomnienia w apce Pacjenta i karty w panelu specjalisty."""
    conn = get_db()
    latest = conn.execute(
        "SELECT id, timestamp, total_score, severity, safety_flag, safety_reviewed FROM phq9_responses "
        "WHERE patient_id = ? ORDER BY id DESC LIMIT 1",
        (patient_id,),
    ).fetchone()
    conn.close()
    if not latest:
        return {"last_phq9": None, "phq9_due": True}
    due = True
    try:
        last_ts = datetime.fromisoformat(latest["timestamp"])
        due = (datetime.now(timezone.utc) - last_ts) >= timedelta(days=7)
    except Exception:
        due = True
    return {
        "last_phq9": {
            "id": latest["id"],
            "timestamp": latest["timestamp"],
            "total_score": latest["total_score"],
            "severity": latest["severity"],
            "safety_flag": bool(latest["safety_flag"]),
            "safety_reviewed": bool(latest["safety_reviewed"]),
        },
        "phq9_due": due,
    }


@app.post("/patients/{patient_id}/phq9/{entry_id}/review")
def review_phq9_safety_flag(patient_id: str, entry_id: int, specialist_id: str = ""):
    """Specjalista/lekarz potwierdza, że dokonał oceny klinicznej po flagowanym
    wyniku (procedura bezpieczeństwa, pkt 5-6: ocena + odnotowanie w dokumentacji).
    To NIE jest interpretacja ryzyka przez aplikację — tylko odhaczenie, że
    upoważniona osoba już to przejrzała."""
    conn = get_db()
    row = conn.execute(
        "SELECT id FROM phq9_responses WHERE id = ? AND patient_id = ?", (entry_id, patient_id)
    ).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Nie znaleziono tego wyniku PHQ-9 dla tego pacjenta")
    conn.execute(
        "UPDATE phq9_responses SET safety_reviewed = 1, safety_reviewed_at = ?, safety_reviewed_by = ? WHERE id = ?",
        (now_iso(), specialist_id or None, entry_id),
    )
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.get("/specialists/{specialist_id}/safety-alerts")
def list_safety_alerts(specialist_id: str):
    """Lista NIEZWERYFIKOWANYCH flag bezpieczeństwa wśród pacjentów TEGO specjalisty —
    szybki widok "kto wymaga oceny klinicznej teraz", zamiast przeglądania po kolei
    każdego pacjenta (patrz procedura bezpieczeństwa, pkt 5: "ocena w możliwie
    najkrótszym czasie")."""
    conn = get_db()
    rows = conn.execute(
        """SELECT p.id as patient_id, p.name as patient_name, r.id as entry_id,
                  r.timestamp, r.total_score, r.severity
           FROM phq9_responses r
           JOIN patients p ON p.id = r.patient_id
           WHERE p.specialist_id = ? AND r.safety_flag = 1 AND r.safety_reviewed = 0
           ORDER BY r.id DESC""",
        (specialist_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/patients/{patient_id}/safety-status")
def get_safety_status(patient_id: str):
    """Faza 5 — eskalacja do opiekuna: czy jest AKTYWNA (jeszcze niezweryfikowana
    przez specjalistę) flaga bezpieczeństwa PHQ-9 dla tego pacjenta. Celowo NIE
    ujawnia opiekunowi surowego wyniku/odpowiedzi (to dane kliniczne widoczne tylko
    w apce Specjalisty) — tylko samą flagę + odkąd, żeby opiekun wiedział, że sprawa
    wymaga uwagi, bez przekazywania mu danych klinicznych, do których nie jest
    uprawniony. To wciąż NIE jest interpretacja ryzyka przez aplikację."""
    conn = get_db()
    patient = conn.execute("SELECT id FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if not patient:
        conn.close()
        raise HTTPException(404, "Nieznany pacjent")
    row = conn.execute(
        "SELECT timestamp FROM phq9_responses WHERE patient_id = ? AND safety_flag = 1 AND safety_reviewed = 0 "
        "ORDER BY id DESC LIMIT 1",
        (patient_id,),
    ).fetchone()
    conn.close()
    return {"safety_flag_active": row is not None, "since": row["timestamp"] if row else None}


# ---------------------------------------------------------------------------
# FAZA 6 — MADRS (ocena kliniczna wprowadzana przez specjalistę, T0/4/8/12 tyg.)
# ---------------------------------------------------------------------------
#
# W przeciwieństwie do samooceny (Faza 3) i PHQ-9 (Faza 4), które wypełnia PACJENT
# w swojej apce, MADRS wprowadza SPECJALISTA/lekarz w apce Specjalisty — podczas
# wizyty/rozmowy klinicznej. Dlatego gating jest taki sam (pacjent musi być
# 'active'), ale nie ma tu żadnego ekranu po stronie apki Pacjenta.

MADRS_SEVERITY_BANDS = [
    (6, "brak depresji"),
    (19, "łagodna"),
    (34, "umiarkowana"),
    (60, "ciężka"),
]


def madrs_severity(total_score: int) -> str:
    for max_score, label in MADRS_SEVERITY_BANDS:
        if total_score <= max_score:
            return label
    return "ciężka"


@app.post("/patients/{patient_id}/madrs")
def submit_madrs(patient_id: str, req: MadrsRequest):
    conn = get_db()
    row = conn.execute("SELECT id, status FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Nieznany pacjent — najpierw wywołaj /patients/register")
    if row["status"] != "active":
        conn.close()
        raise HTTPException(
            403,
            "Pacjent nie został jeszcze przypisany do specjalisty — oceny klinicznej nie można jeszcze wprowadzić.",
        )
    items = [
        req.item1, req.item2, req.item3, req.item4, req.item5,
        req.item6, req.item7, req.item8, req.item9, req.item10,
    ]
    total_score = sum(items)
    severity = madrs_severity(total_score)
    safety_flag = req.item10 > 0
    ts = now_iso()
    conn.execute(
        """INSERT INTO madrs_assessments
           (patient_id, specialist_id, timestamp, occasion, item1, item2, item3, item4, item5,
            item6, item7, item8, item9, item10, total_score, severity, safety_flag)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (patient_id, req.specialist_id, ts, req.occasion, *items, total_score, severity, int(safety_flag)),
    )
    conn.commit()
    conn.close()
    return {
        "status": "ok",
        "timestamp": ts,
        "total_score": total_score,
        "severity": severity,
        "safety_flag": safety_flag,
    }


@app.get("/patients/{patient_id}/madrs")
def list_madrs(patient_id: str, limit: int = 30):
    """Historia MADRS (od najnowszej) — do przyszłych wykresów trendu nałożonych
    na dane cyfrowe (Faza 7, panel badacza)."""
    conn = get_db()
    patient = conn.execute("SELECT id FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if not patient:
        conn.close()
        raise HTTPException(404, "Nieznany pacjent")
    rows = conn.execute(
        "SELECT id, specialist_id, timestamp, occasion, total_score, severity, safety_flag FROM madrs_assessments "
        "WHERE patient_id = ? ORDER BY id DESC LIMIT ?",
        (patient_id, max(1, min(limit, 365))),
    ).fetchall()
    conn.close()
    return [{**dict(r), "safety_flag": bool(r["safety_flag"])} for r in rows]


def madrs_summary(patient_id: str) -> dict:
    """Najnowszy wynik MADRS — do karty w panelu specjalisty. Brak koncepcji
    'due' jak w PHQ-9, bo terminy T0/4/8/12 tydz. ustala specjalista wg protokołu,
    nie prosty cykl czasowy."""
    conn = get_db()
    latest = conn.execute(
        "SELECT id, specialist_id, timestamp, occasion, total_score, severity, safety_flag FROM madrs_assessments "
        "WHERE patient_id = ? ORDER BY id DESC LIMIT 1",
        (patient_id,),
    ).fetchone()
    conn.close()
    if not latest:
        return {"last_madrs": None}
    return {
        "last_madrs": {**dict(latest), "safety_flag": bool(latest["safety_flag"])},
    }


# ---------------------------------------------------------------------------
# FAZA 7 — PANEL BADACZA: wykresy trendów dla apki Specjalisty
# ---------------------------------------------------------------------------
#
# Jeden endpoint zwraca WSZYSTKIE serie potrzebne do wykresów naraz (dane
# behawioralne dzień-po-dniu + samoocena + PHQ-9 + MADRS), żeby apka Specjalisty
# nie musiała robić 4 osobnych zapytań i ręcznie składać wspólną osi dni.
# Dni bez żadnych danych behawioralnych/samooceny dostają `null` w odpowiednich
# tablicach (NIE 0!) — apka rysuje to jako przerwę w linii wykresu, a nie
# fałszywe "zero", zgodnie z tą samą zasadą co `mobility` w Fazie 1.

def _trend_day_range(days: int) -> list:
    """Lista dni (YYYY-MM-DD, doba UTC) od najstarszego do dzisiejszego, włącznie —
    wspólna oś X dla wszystkich serii wykresu, nawet jeśli część dni nie ma danych."""
    today = datetime.now(timezone.utc).date()
    return [(today - timedelta(days=offset)).isoformat() for offset in range(days - 1, -1, -1)]


@app.get("/patients/{patient_id}/trends")
def get_patient_trends(patient_id: str, days: int = 30):
    conn = get_db()
    patient = conn.execute("SELECT id FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if not patient:
        conn.close()
        raise HTTPException(404, "Nieznany pacjent")

    days = max(7, min(days, 90))
    day_list = _trend_day_range(days)
    cutoff = day_list[0] + "T00:00:00"

    # --- dane behawioralne, zagregowane dzień-po-dniu (SQL AVG ignoruje NULLe) ---
    behavior_rows = conn.execute(
        """SELECT substr(timestamp, 1, 10) as day,
                  AVG(movement) as movement_avg,
                  AVG(mobility) as mobility_avg,
                  AVG(room_activity) as room_activity_avg,
                  AVG(screen_time_minutes) as screen_time_minutes_avg,
                  SUM(calls) as calls_sum,
                  SUM(sms) as sms_sum
           FROM behavior_data
           WHERE patient_id = ? AND timestamp >= ?
           GROUP BY day""",
        (patient_id, cutoff),
    ).fetchall()
    behavior_by_day = {r["day"]: r for r in behavior_rows}

    # --- samoocena, zagregowana dzień-po-dniu (jeśli pacjent wypełnił kilka razy w ten sam dzień) ---
    sa_rows = conn.execute(
        """SELECT substr(timestamp, 1, 10) as day,
                  AVG(mood) as mood_avg, AVG(energy) as energy_avg,
                  AVG(sleep_quality) as sleep_quality_avg, AVG(anhedonia) as anhedonia_avg
           FROM self_assessments
           WHERE patient_id = ? AND timestamp >= ?
           GROUP BY day""",
        (patient_id, cutoff),
    ).fetchall()
    sa_by_day = {r["day"]: r for r in sa_rows}

    def col(rows_by_day: dict, day: str, field: str):
        row = rows_by_day.get(day)
        return row[field] if row is not None else None

    movement_avg, mobility_avg, room_activity_avg, screen_time_minutes_avg = [], [], [], []
    communication_count = []
    mood_avg, energy_avg, sleep_quality_avg, anhedonia_avg = [], [], [], []
    for day in day_list:
        movement_avg.append(col(behavior_by_day, day, "movement_avg"))
        mobility_avg.append(col(behavior_by_day, day, "mobility_avg"))
        room_activity_avg.append(col(behavior_by_day, day, "room_activity_avg"))
        screen_time_minutes_avg.append(col(behavior_by_day, day, "screen_time_minutes_avg"))
        row = behavior_by_day.get(day)
        communication_count.append(
            None if row is None else (row["calls_sum"] or 0) + (row["sms_sum"] or 0)
        )
        mood_avg.append(col(sa_by_day, day, "mood_avg"))
        energy_avg.append(col(sa_by_day, day, "energy_avg"))
        sleep_quality_avg.append(col(sa_by_day, day, "sleep_quality_avg"))
        anhedonia_avg.append(col(sa_by_day, day, "anhedonia_avg"))

    # --- PHQ-9 i MADRS: rzadkie, nieregularne wpisy (raz w tygodniu / na wizytę) —
    # zwracane jako osobna lista {date, total_score, ...}, a NIE jako tablica
    # wyrównana do day_list, bo próba "przypisania" do konkretnego dnia w tablicy
    # zgubiłaby dokładny znacznik czasu bez żadnej korzyści dla wykresu.
    phq9_rows = conn.execute(
        "SELECT timestamp, total_score, severity FROM phq9_responses "
        "WHERE patient_id = ? AND timestamp >= ? ORDER BY id",
        (patient_id, cutoff),
    ).fetchall()
    madrs_rows = conn.execute(
        "SELECT timestamp, total_score, severity, occasion FROM madrs_assessments "
        "WHERE patient_id = ? AND timestamp >= ? ORDER BY id",
        (patient_id, cutoff),
    ).fetchall()
    conn.close()

    return {
        "days": day_list,
        "movement_avg": movement_avg,
        "mobility_avg": mobility_avg,
        "room_activity_avg": room_activity_avg,
        "screen_time_minutes_avg": screen_time_minutes_avg,
        "communication_count": communication_count,
        "self_assessment_mood": mood_avg,
        "self_assessment_energy": energy_avg,
        "self_assessment_sleep_quality": sleep_quality_avg,
        "self_assessment_anhedonia": anhedonia_avg,
        "phq9": [
            {"date": r["timestamp"][:10], "total_score": r["total_score"], "severity": r["severity"]}
            for r in phq9_rows
        ],
        "madrs": [
            {
                "date": r["timestamp"][:10],
                "total_score": r["total_score"],
                "severity": r["severity"],
                "occasion": r["occasion"],
            }
            for r in madrs_rows
        ],
    }


# ---------------------------------------------------------------------------
# FAZA 8 — MODEL WYKRYWANIA ZMIAN (per pacjent, samokalibrujący się)
# ---------------------------------------------------------------------------
#
# Zamiast jednego globalnego progu "co jest normalne" dla wszystkich pacjentów
# (różne style życia, różne wyjściowe wartości metryk), każdy pacjent jest
# porównywany TYLKO Z WŁASNĄ historią: liczymy średnią i odchylenie standardowe
# każdej metryki z okresu "bazowego" (np. dni -30..-4), a bieżące dni (-3..0)
# wyrażamy jako znormalizowany wynik odchylenia (uproszczona wersja Mahalanobisa —
# standaryzowana odległość euklidesowa po metrykach, bez odwracania macierzy
# kowariancji, żeby nie wymagać numpy/scipy, których NIE ma w requirements.txt
# wdrożonego serwera). To jest właśnie "samokalibracja": próg w jednostkach
# odchylenia standardowego jest ten sam dla każdego pacjenta, ale baza odniesienia
# (średnia/std) jest przeliczana indywidualnie z historii TEGO pacjenta.
# Reguła TRWAŁOŚCI: flaga "wykryta zmiana" zapala się tylko, gdy ostatnie
# CHANGE_PERSISTENCE_DAYS dni pod rząd przekraczają próg — jeden odstający dzień
# (np. jeden nietypowy wieczór) nie uruchamia alertu.
# Osobna, niezależna reguła "pacjent zniknął": wiek `last_sync` > DISAPPEARED_HOURS.

CHANGE_THRESHOLD_Z = 1.5
CHANGE_PERSISTENCE_DAYS = 3
CHANGE_MIN_BASELINE_DAYS = 5
DISAPPEARED_HOURS = 48
CHANGE_METRIC_NAMES = [
    "movement_avg", "mobility_avg", "room_activity_avg",
    "screen_time_minutes_avg", "communication_count",
]


def _metric_daily_values(patient_id: str, day_list: list) -> dict:
    """Te same agregacje dzień-po-dniu co w /trends (Faza 7) — ta sama definicja
    metryk w obu miejscach, żeby liczby na wykresie i w modelu wykrywania zmian
    się zgadzały. `None` = brak danych tego dnia (nie 0)."""
    conn = get_db()
    cutoff = day_list[0] + "T00:00:00"
    rows = conn.execute(
        """SELECT substr(timestamp, 1, 10) as day,
                  AVG(movement) as movement_avg,
                  AVG(mobility) as mobility_avg,
                  AVG(room_activity) as room_activity_avg,
                  AVG(screen_time_minutes) as screen_time_minutes_avg,
                  SUM(calls) as calls_sum, SUM(sms) as sms_sum
           FROM behavior_data
           WHERE patient_id = ? AND timestamp >= ?
           GROUP BY day""",
        (patient_id, cutoff),
    ).fetchall()
    conn.close()
    by_day = {r["day"]: r for r in rows}
    metrics = {name: [] for name in CHANGE_METRIC_NAMES}
    for day in day_list:
        row = by_day.get(day)
        metrics["movement_avg"].append(row["movement_avg"] if row else None)
        metrics["mobility_avg"].append(row["mobility_avg"] if row else None)
        metrics["room_activity_avg"].append(row["room_activity_avg"] if row else None)
        metrics["screen_time_minutes_avg"].append(row["screen_time_minutes_avg"] if row else None)
        metrics["communication_count"].append(
            None if row is None else (row["calls_sum"] or 0) + (row["sms_sum"] or 0)
        )
    return metrics


def _mean_std(values: list):
    """Średnia i odchylenie standardowe (populacyjne) z nie-None wartości, albo
    (None, None), gdy brak jakichkolwiek danych — bez numpy, czysty Python."""
    known = [v for v in values if v is not None]
    if not known:
        return None, None
    mean = sum(known) / len(known)
    if len(known) < 2:
        return mean, 0.0
    variance = sum((v - mean) ** 2 for v in known) / len(known)
    return mean, variance ** 0.5


def _compute_change_detection(patient_id: str, lookback_days: int = 30, recent_days: int = 3) -> Optional[dict]:
    """Zwraca None, jeśli pacjent nie istnieje. Używane zarówno przez endpoint
    pojedynczego pacjenta, jak i listing alertów dla specjalisty."""
    conn = get_db()
    patient = conn.execute("SELECT id, last_sync FROM patients WHERE id = ?", (patient_id,)).fetchone()
    conn.close()
    if not patient:
        return None

    lookback_days = max(10, min(lookback_days, 180))
    recent_days = max(1, min(recent_days, 7))
    day_list = _trend_day_range(lookback_days)
    metrics = _metric_daily_values(patient_id, day_list)

    baseline_cutoff = len(day_list) - recent_days  # dni PRZED tym indeksem = baza odniesienia
    baseline_stats = {
        name: _mean_std(values[:baseline_cutoff]) for name, values in metrics.items()
    }
    baseline_days_with_data = len({
        day_list[i] for i in range(baseline_cutoff)
        if any(metrics[name][i] is not None for name in CHANGE_METRIC_NAMES)
    })
    insufficient_data = baseline_days_with_data < CHANGE_MIN_BASELINE_DAYS

    day_scores = []
    for i, day in enumerate(day_list):
        z_values = []
        for name in CHANGE_METRIC_NAMES:
            v = metrics[name][i]
            mean, std = baseline_stats[name]
            if v is None or mean is None or std is None or std < 1e-6:
                continue
            z_values.append(abs((v - mean) / std))
        score = round(sum(z_values) / len(z_values), 2) if z_values else None
        day_scores.append({"date": day, "score": score})

    flagged = False
    flagged_since = None
    if not insufficient_data:
        recent_scores = day_scores[-CHANGE_PERSISTENCE_DAYS:]
        if len(recent_scores) == CHANGE_PERSISTENCE_DAYS and all(
            d["score"] is not None and d["score"] > CHANGE_THRESHOLD_Z for d in recent_scores
        ):
            flagged = True
            flagged_since = recent_scores[0]["date"]

    hours_since_last_sync = None
    disappeared = False
    if patient["last_sync"]:
        try:
            last_sync_dt = datetime.fromisoformat(patient["last_sync"])
            hours_since_last_sync = round(
                (datetime.now(timezone.utc) - last_sync_dt).total_seconds() / 3600, 1
            )
            disappeared = hours_since_last_sync > DISAPPEARED_HOURS
        except Exception:
            disappeared = False
    else:
        # Pacjent aktywowany, ale jeszcze nigdy nic nie wysłał — w praktyce nie powinno
        # się zdarzyć (register_patient ustawia last_sync od razu), ale dla bezpieczeństwa
        # traktujemy to tak samo jak "zniknięcie".
        disappeared = True

    return {
        "days": day_scores,
        "threshold": CHANGE_THRESHOLD_Z,
        "persistence_days": CHANGE_PERSISTENCE_DAYS,
        "baseline_days_used": baseline_days_with_data,
        "insufficient_data": insufficient_data,
        "flagged": flagged,
        "flagged_since": flagged_since,
        "last_sync": patient["last_sync"],
        "hours_since_last_sync": hours_since_last_sync,
        "disappeared": disappeared,
    }


@app.get("/patients/{patient_id}/change-detection")
def get_change_detection(patient_id: str, lookback_days: int = 30, recent_days: int = 3):
    result = _compute_change_detection(patient_id, lookback_days, recent_days)
    if result is None:
        raise HTTPException(404, "Nieznany pacjent")
    return result


@app.get("/specialists/{specialist_id}/change-alerts")
def list_change_alerts(specialist_id: str):
    """Pacjenci TEGO specjalisty z wykrytą TRWAŁĄ zmianą zachowania (≥3 kolejne dni
    odchylenia od WŁASNEGO wzorca) albo zaginięciem kontaktu (> 48h bez synchronizacji) —
    szybki przegląd "kto wymaga uwagi" w panelu badacza, analogicznie do alertów
    bezpieczeństwa PHQ-9 (Faza 4/5), ale to NIE jest moduł bezpieczeństwa — to monitoring
    jakości danych/zachowania, bez implikacji klinicznych."""
    conn = get_db()
    patients = conn.execute(
        "SELECT id, name FROM patients WHERE specialist_id = ?", (specialist_id,)
    ).fetchall()
    conn.close()
    alerts = []
    for p in patients:
        result = _compute_change_detection(p["id"])
        if result and (result["flagged"] or result["disappeared"]):
            alerts.append({
                "patient_id": p["id"],
                "patient_name": p["name"],
                "flagged": result["flagged"],
                "flagged_since": result["flagged_since"],
                "disappeared": result["disappeared"],
                "hours_since_last_sync": result["hours_since_last_sync"],
            })
    return alerts


# ---------------------------------------------------------------------------
# STATYSTYKI — średnia z ostatnich 24h, przeliczana co najwyżej raz na godzinę
# ---------------------------------------------------------------------------
#
# Pacjent wysyła pojedyncze "pakiety" danych co 15 minut (SyncWorker w apce Pacjenta).
# Zamiast pokazywać specjaliście surowy ostatni odczyt (który mógł być przypadkowym
# wychyleniem), co godzinę liczymy średnią z ostatnich 24h i porównujemy ją z poprzednio
# policzoną średnią — różnica w % to właśnie strzałka "wzrost/spadek" widoczna w panelu
# specjalisty (dokładnie tak, jak na oryginalnych makietach z prezentacji).

STATS_METRICS = [
    "phone_activity", "app_usage", "movement", "room_activity",
    "unlocks", "calls", "sms", "screen_time_minutes",
    # mobility: GPS może być null (brak zgody) — AVG() w SQL ignoruje NULLe, więc
    # jeśli pacjent nigdy nie dał zgody, averages["mobility"] wyjdzie po prostu None,
    # a nie błędne "0.0" (patrz specjalny fallback w get_latest_data niżej).
    "mobility",
    # Faza 9: czas w kategoriach aplikacji (bez identyfikacji konkretnej aplikacji) +
    # wzbogacone metadane komunikacyjne (czas trwania połączeń). Te cztery metryki
    # korzystają z tego samego, generycznego mechanizmu średnich/pct co wszystkie
    # powyższe — nic więcej nie trzeba dopisywać poza tą listą.
    "category_social_minutes", "category_productivity_minutes", "category_other_minutes",
    "call_duration_minutes",
]
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
                ensure_fresh_circadian(pid)
        except Exception:
            pass
        await asyncio.sleep(BACKGROUND_STATS_INTERVAL_SECONDS)


# ---------------------------------------------------------------------------
# RYTM DOBOWY — profil aktywności wg godziny doby, przeliczany najwyżej raz na
# dobę, z 15% tolerancją zmiany między kolejnymi dniami
# ---------------------------------------------------------------------------
#
# Pomysł: liczymy, jak wygląda "typowy dzień" pacjenta — średnią aktywność
# telefonu osobno dla każdej z 24 godzin doby, na podstawie ostatnich 24h
# danych (bucketing po godzinie zegarowej, nie po dacie kalendarzowej, więc
# działa od razu, a nie dopiero od północy). Porównujemy ten świeży profil do
# poprzedniego (sprzed ~doby) — jeśli uśredniona zmiana między godzinami
# przekracza 15%, oznaczamy to jako "zmianę rytmu dobowego" (np. przesunięcie
# pory aktywności, co bywa objawem klinicznie istotnym w monitoringu
# behawioralnym). 15% to świadomie przyjęty próg tolerancji — dzień w dzień
# rytm naturalnie trochę "pływa", więc mniejsze wahania nie powinny alarmować.

CIRCADIAN_MAX_AGE = timedelta(hours=24)
CIRCADIAN_TOLERANCE_PCT = 15.0


def compute_circadian_snapshot(patient_id: str) -> Optional[dict]:
    """Liczy nowy profil aktywności wg godziny doby (24 kubełki) z ostatnich 24h
    i porównuje go do poprzedniego profilu. Zwraca None, jeśli brak jakichkolwiek
    danych w tym oknie (nic do policzenia)."""
    conn = get_db()
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="seconds")
    rows = conn.execute(
        """SELECT CAST(strftime('%H', timestamp) AS INTEGER) AS hr,
                  AVG(phone_activity) AS avg_val, COUNT(*) AS n
           FROM behavior_data WHERE patient_id = ? AND timestamp >= ?
           GROUP BY hr""",
        (patient_id, cutoff),
    ).fetchall()

    if not rows or sum(r["n"] for r in rows) == 0:
        conn.close()
        return None

    profile = [None] * 24  # profile[h] = średnia phone_activity dla godziny h (0-23), None = brak danych
    for r in rows:
        profile[r["hr"]] = r["avg_val"]

    previous = conn.execute(
        "SELECT * FROM patient_circadian_snapshots WHERE patient_id = ? ORDER BY id DESC LIMIT 1",
        (patient_id,),
    ).fetchone()

    deviation_pct: Optional[float] = None
    shifted: Optional[bool] = None
    if previous:
        try:
            prev_profile = json.loads(previous["hourly_profile"])
        except Exception:
            prev_profile = [None] * 24
        diffs = []
        for cur_val, prev_val in zip(profile, prev_profile):
            if cur_val is None or prev_val is None:
                continue  # godzina bez danych w jednym z dwóch dni — pomijamy, nie zerujemy
            if prev_val == 0:
                diffs.append(0.0 if cur_val == 0 else 100.0)
            else:
                diffs.append(abs(cur_val - prev_val) / prev_val * 100.0)
        if diffs:
            deviation_pct = round(sum(diffs) / len(diffs), 1)
            shifted = deviation_pct > CIRCADIAN_TOLERANCE_PCT

    computed_at = now_iso()
    conn.execute(
        """INSERT INTO patient_circadian_snapshots
           (patient_id, computed_at, hourly_profile, deviation_pct, shifted)
           VALUES (?, ?, ?, ?, ?)""",
        (patient_id, computed_at, json.dumps(profile), deviation_pct,
         None if shifted is None else int(shifted)),
    )
    conn.commit()
    conn.close()

    return {"computed_at": computed_at, "deviation_pct": deviation_pct, "shifted": shifted}


def ensure_fresh_circadian(patient_id: str) -> Optional[dict]:
    """Jak ensure_fresh_snapshot, ale próg świeżości to 24h zamiast 1h —
    rytm dobowy z sensu rzeczy nie ma co przeliczać częściej niż raz na dzień."""
    conn = get_db()
    latest = conn.execute(
        "SELECT * FROM patient_circadian_snapshots WHERE patient_id = ? ORDER BY id DESC LIMIT 1",
        (patient_id,),
    ).fetchone()
    conn.close()

    needs_refresh = True
    if latest:
        try:
            computed_at = datetime.fromisoformat(latest["computed_at"])
            needs_refresh = (datetime.now(timezone.utc) - computed_at) >= CIRCADIAN_MAX_AGE
        except Exception:
            needs_refresh = True

    if needs_refresh:
        fresh = compute_circadian_snapshot(patient_id)
        if fresh is not None:
            return fresh
        if latest is None:
            return None

    return {
        "computed_at": latest["computed_at"],
        "deviation_pct": latest["deviation_pct"],
        "shifted": None if latest["shifted"] is None else bool(latest["shifted"]),
    }


def _maybe_open_dashboard_in_browser():
    """Otwiera stronę logów w domyślnej przeglądarce przy starcie serwera.
    Wyłączyć można zmienną środowiskową DEPRESS_SENSE_NO_BROWSER=1 (np. przy
    wielokrotnym restartowaniu serwera podczas pracy, żeby nie mnożyć zakładek).
    Na serwerze zewnętrznym (DEPRESS_SENSE_PUBLIC_URL ustawione) i tak nie ma GUI,
    więc pomijamy to automatycznie bez potrzeby osobnej flagi."""
    if os.environ.get("DEPRESS_SENSE_NO_BROWSER") or os.environ.get("CHAD_SENCE_NO_BROWSER") or PUBLIC_URL:
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

    circadian = ensure_fresh_circadian(patient_id)
    self_assessment = self_assessment_summary(patient_id)
    phq9 = phq9_summary(patient_id)
    madrs = madrs_summary(patient_id)

    base = {
        "patient_id": patient_id, "name": patient["name"], "last_sync": patient["last_sync"],
        "last_action_at": patient["last_action_at"],
        "stats_computed_at": stats_computed_at,
        "circadian_computed_at": circadian["computed_at"] if circadian else None,
        "circadian_deviation_pct": circadian["deviation_pct"] if circadian else None,
        "circadian_shifted": circadian["shifted"] if circadian else None,
        "self_assessment": self_assessment["self_assessment"],
        "self_assessment_count_7d": self_assessment["self_assessment_count_7d"],
        "last_phq9": phq9["last_phq9"],
        "phq9_due": phq9["phq9_due"],
        "last_madrs": madrs["last_madrs"],
    }
    if not row:
        # Brak danych jeszcze przesłanych przez pacjenta — zwracamy zera dla ostatniego odczytu.
        # Wyjątek: "mobility" to pole celowo nullable (brak zgody GPS != zmierzone zero ruchu),
        # więc dla niego fallback to None, a nie 0 — inaczej byśmy udawali pomiar, którego nie było.
        base.update({m: (None if m == "mobility" else 0) for m in STATS_METRICS})
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
    """Porównanie ID jest celowo NIEczułe na wielkość liter (LOWER(id) = LOWER(?)) —
    np. telefon z klawiaturą, która capitalizuje pierwszą literę, albo ktoś, kto po
    prostu inaczej zapamiętał wielkość liter w ID, i tak się zaloguje. Hasło zostaje
    porównywane dokładnie (z wielkością liter) — to jest normalne dla haseł."""
    key = _login_key(req.specialist_id)
    _check_login_throttle(key)
    conn = get_db()
    row = conn.execute(
        "SELECT id, password, must_change_password FROM specialists WHERE LOWER(id) = LOWER(?)",
        (req.specialist_id.strip(),),
    ).fetchone()
    if not row or not verify_password(row["password"], req.password):
        conn.close()
        _register_login_failure(key)
        raise HTTPException(401, "Błędny login lub hasło")
    _LOGIN_FAILS.pop(key, None)
    if not is_hashed(row["password"]):
        # Konto sprzed wprowadzenia hashowania — przepisujemy hasło na hash.
        conn.execute("UPDATE specialists SET password = ? WHERE id = ?", (hash_password(req.password), row["id"]))
        conn.commit()
    conn.close()
    # Zwracamy ID tak, jak jest zapisane w bazie (kanoniczna wielkość liter) — ważne,
    # bo apka zapamiętuje to ID i używa go dalej (lista pacjentów itd.), więc musi się
    # zgadzać dokładnie z tym, co ma specialist_id w tabeli patients.
    return {
        "status": "ok",
        "specialist_id": row["id"],
        "must_change_password": bool(row["must_change_password"]),
    }


@app.post("/specialists/change-password")
def change_password(req: ChangePasswordRequest):
    """Wymuszona zmiana hasła przy pierwszym logowaniu (i dostępna też później).
    Wymaga podania starego hasła — to nie jest reset, tylko zwykła zmiana przez
    zalogowanego już (must_change_password=1) użytkownika."""
    key = _login_key(req.specialist_id)
    _check_login_throttle(key)
    conn = get_db()
    row = conn.execute(
        "SELECT id, password FROM specialists WHERE LOWER(id) = LOWER(?)",
        (req.specialist_id.strip(),),
    ).fetchone()
    if not row or not verify_password(row["password"], req.old_password):
        conn.close()
        _register_login_failure(key)
        raise HTTPException(401, "Błędne obecne hasło")
    if not req.new_password or len(req.new_password) < MIN_PASSWORD_LENGTH:
        conn.close()
        raise HTTPException(400, f"Nowe hasło jest za krótkie (minimum {MIN_PASSWORD_LENGTH} znaków)")
    conn.execute(
        "UPDATE specialists SET password = ?, must_change_password = 0 WHERE id = ?",
        (hash_password(req.new_password), row["id"]),
    )
    conn.commit()
    conn.close()
    return {"status": "ok", "specialist_id": row["id"]}


@app.post("/specialists/register", dependencies=[Depends(require_admin)])
def register_specialist(req: RegisterSpecialistRequest):
    """Dodaje nowe konto specjalisty. Używane przez panel użytkowników /admin;
    wymaga zalogowania administratora (patrz require_admin)."""
    specialist_id = req.specialist_id.strip()
    if not specialist_id or not req.password:
        raise HTTPException(400, "ID i hasło nie mogą być puste")
    if len(req.password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(400, f"Hasło jest za krótkie (minimum {MIN_PASSWORD_LENGTH} znaków)")
    conn = get_db()
    # Sprawdzamy duplikat też bez rozróżniania wielkości liter — inaczej dałoby się
    # przez przypadek stworzyć "spec001" i "Spec001" jako dwa różne konta, co tylko
    # pogłębiłoby zamieszanie z wielkością liter przy logowaniu.
    existing = conn.execute("SELECT id FROM specialists WHERE LOWER(id) = LOWER(?)", (specialist_id,)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(409, f"Specjalista z tym ID już istnieje (jako \"{existing['id']}\")")
    conn.execute(
        "INSERT INTO specialists (id, password) VALUES (?, ?)",
        (specialist_id, hash_password(req.password)),
    )
    conn.commit()
    conn.close()
    return {"status": "ok", "specialist_id": specialist_id}


@app.get("/specialists", dependencies=[Depends(require_admin)])
def list_specialists():
    """Lista kont specjalistów (bez haseł) — do panelu użytkowników /admin."""
    conn = get_db()
    rows = conn.execute(
        """SELECT s.id, s.password, s.must_change_password,
                  (SELECT COUNT(*) FROM patients p WHERE p.specialist_id = s.id) AS patient_count
           FROM specialists s ORDER BY s.id"""
    ).fetchall()
    conn.close()
    return [
        {
            "id": r["id"],
            "must_change_password": bool(r["must_change_password"]),
            "patient_count": r["patient_count"],
            # Ostrzeżenie w panelu: konto testowe z domyślnym, publicznie znanym hasłem.
            "default_credentials": r["id"] == "spec001" and verify_password(r["password"], "test1234"),
        }
        for r in rows
    ]


@app.delete("/specialists/{specialist_id}", dependencies=[Depends(require_admin)])
def delete_specialist(specialist_id: str):
    """Usuwa konto specjalisty (panel admina na /dashboard). Pacjentów, którzy byli
    do niego przypisani, cofamy do stanu 'pending' (specialist_id = NULL) zamiast
    zostawiać martwe odwołanie — ktoś inny musi ich świadomie przejąć, zgodnie z
    tą samą zasadą co przy pierwszym przypisaniu."""
    conn = get_db()
    row = conn.execute("SELECT id FROM specialists WHERE LOWER(id) = LOWER(?)", (specialist_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Nie znaleziono specjalisty o takim ID")
    conn.execute(
        "UPDATE patients SET specialist_id = NULL, status = 'pending' WHERE specialist_id = ?",
        (row["id"],),
    )
    conn.execute("DELETE FROM specialists WHERE id = ?", (row["id"],))
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.post("/specialists/{specialist_id}/force-password-change", dependencies=[Depends(require_admin)])
def force_password_change(specialist_id: str):
    """Admin wymusza zmianę hasła przy NASTĘPNYM logowaniu tego specjalisty
    (np. podejrzenie przejęcia konta, odejście osoby z zespołu itp.) — niezależnie
    od tego, czy to konto miało to już kiedyś za sobą."""
    conn = get_db()
    row = conn.execute("SELECT id FROM specialists WHERE LOWER(id) = LOWER(?)", (specialist_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Nie znaleziono specjalisty o takim ID")
    conn.execute("UPDATE specialists SET must_change_password = 1 WHERE id = ?", (row["id"],))
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.get("/admin/patients", dependencies=[Depends(require_admin)])
def admin_list_patients():
    """Pełny przegląd pacjentów do panelu admina na /dashboard — w odróżnieniu od
    /specialists/{id}/patients (które widzi tylko SWOICH pacjentów), to widzi
    WSZYSTKICH, łącznie z 'pending' (jeszcze nieprzypisanymi) — potrzebne, żeby
    dozorować, czy ktoś w ogóle zajął się nowo zarejestrowanym uczestnikiem."""
    conn = get_db()
    rows = conn.execute(
        """SELECT p.id, p.name, p.status, p.specialist_id, p.last_sync,
                  (SELECT COUNT(*) FROM caregivers c WHERE c.patient_id = p.id) AS caregiver_count
           FROM patients p ORDER BY p.status ASC, p.last_sync DESC"""
    ).fetchall()
    conn.close()
    return [
        {
            "id": r["id"], "name": r["name"], "status": r["status"],
            "specialist_id": r["specialist_id"], "last_sync": r["last_sync"],
            "caregiver_count": r["caregiver_count"],
        }
        for r in rows
    ]


@app.delete("/admin/patients/{patient_id}", dependencies=[Depends(require_admin)])
def admin_delete_patient(patient_id: str):
    """Kasuje pacjenta ORAZ wszystkie powiązane dane (opiekunowie, wiadomości, dane
    behawioralne, migawki statystyk/rytmu dobowego) — celowe odstępstwo od zasady
    "architektura append-only" wspomnianej przy innych tabelach: to jest narzędzie
    porządkowe admina (np. usunięcie konta testowego), a nie coś, co dzieje się
    w normalnym przepływie badania."""
    conn = get_db()
    row = conn.execute("SELECT id FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Nie znaleziono pacjenta o takim ID")
    for table in (
        "caregivers", "messages", "behavior_data",
        "patient_stats_snapshots", "patient_circadian_snapshots",
        # Dane kliniczne — wcześniej pomijane, więc "usunięcie pacjenta" zostawiało
        # w bazie jego samooceny, PHQ-9 i oceny MADRS (osierocone rekordy).
        "self_assessments", "phq9_responses", "madrs_assessments",
    ):
        conn.execute(f"DELETE FROM {table} WHERE patient_id = ?", (patient_id,))
    conn.execute("DELETE FROM patients WHERE id = ?", (patient_id,))
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.delete("/admin/patients/{patient_id}/caregivers/{caregiver_device_id}", dependencies=[Depends(require_admin)])
def admin_remove_caregiver(patient_id: str, caregiver_device_id: str):
    """Usuwa jedno powiązanie opiekun-pacjent (np. opiekun zgubił telefon, zmiana
    osoby sprawującej opiekę itp.) — zwalnia jedno miejsce z puli caregiver_slots."""
    conn = get_db()
    conn.execute(
        "DELETE FROM caregivers WHERE patient_id = ? AND caregiver_device_id = ?",
        (patient_id, caregiver_device_id),
    )
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.get("/admin/patients/{patient_id}/caregivers", dependencies=[Depends(require_admin)])
def admin_list_caregivers(patient_id: str):
    """Lista device_id opiekunów podpiętych pod danego pacjenta — do rozwijanego
    widoku w panelu admina (przycisk 'usuń' przy każdym)."""
    conn = get_db()
    rows = conn.execute(
        "SELECT caregiver_device_id FROM caregivers WHERE patient_id = ?", (patient_id,)
    ).fetchall()
    conn.close()
    return [{"caregiver_device_id": r["caregiver_device_id"]} for r in rows]


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
    """Specjalista przypisuje pacjenta do siebie. To jest jednocześnie moment AKTYWACJI
    konta pacjenta (status 'pending' -> 'active') — przed tym pacjent nie może wysyłać
    danych (patrz send_behavior_data), bo kwestie zgód/umowy i odpowiedzialności za
    tego uczestnika nie są jeszcze formalnie ustalone."""
    conn = get_db()
    row = conn.execute("SELECT id FROM patients WHERE id = ?", (req.patient_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Pacjent o takim ID jeszcze nie zarejestrował się w systemie (nie uruchomił apki)")
    conn.execute(
        "UPDATE patients SET specialist_id = ?, status = 'active' WHERE id = ?",
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
    """Specjalista klika wykrzyknik przy pacjencie i wybiera 'Podjęto działania' —
    zdejmujemy flagę ORAZ zapisujemy, kiedy to się stało (last_action_at), żeby
    można było to pokazać w szczegółach pacjenta."""
    conn = get_db()
    conn.execute(
        "UPDATE patients SET flag = 0, last_action_at = ? WHERE id = ?",
        (now_iso(), patient_id),
    )
    conn.commit()
    conn.close()
    return {"status": "ok"}


@app.get("/health")
def health():
    return {"status": "ok", "time": now_iso()}


# ---------------------------------------------------------------------------
# DASHBOARD — podgląd podpiętych urządzeń w czasie rzeczywistym
# ---------------------------------------------------------------------------

@app.get("/api/devices", dependencies=[Depends(require_admin)])
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


@app.get("/api/logs", dependencies=[Depends(require_admin)])
def api_logs():
    """Ostatnie 300 zapytań do serwera, najnowsze pierwsze. Używane przez /dashboard."""
    return list(LOG_BUFFER)


# ---------------------------------------------------------------------------
# PANELE WWW — dwie osobne strony (obie za logowaniem administratora):
#   /dashboard — monitoring serwera: adres, logi żądań na żywo, podpięte urządzenia
#   /admin     — zarządzanie użytkownikami: dodawanie i operacje na specjalistach,
#                pacjentach (przypisanie/odpięcie/usunięcie) i ich opiekunach
# ---------------------------------------------------------------------------

class ResetPasswordRequest(BaseModel):
    new_password: str


class AssignPatientRequest(BaseModel):
    specialist_id: str


@app.post("/admin/specialists/{specialist_id}/reset-password", dependencies=[Depends(require_admin)])
def admin_reset_specialist_password(specialist_id: str, req: ResetPasswordRequest):
    """Administrator ustawia nowe hasło specjaliście (np. zapomniał hasła) — z
    wymuszeniem zmiany przy najbliższym logowaniu, więc admin nie zna hasła na stałe."""
    if len(req.new_password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(400, f"Hasło jest za krótkie (minimum {MIN_PASSWORD_LENGTH} znaków)")
    conn = get_db()
    row = conn.execute("SELECT id FROM specialists WHERE LOWER(id) = LOWER(?)", (specialist_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Nie znaleziono specjalisty o takim ID")
    conn.execute(
        "UPDATE specialists SET password = ?, must_change_password = 1 WHERE id = ?",
        (hash_password(req.new_password), row["id"]),
    )
    conn.commit()
    conn.close()
    _LOGIN_FAILS.pop(_login_key(row["id"]), None)
    return {"status": "ok"}


@app.post("/admin/patients/{patient_id}/assign", dependencies=[Depends(require_admin)])
def admin_assign_patient(patient_id: str, req: AssignPatientRequest):
    """Przypisuje pacjenta do wskazanego specjalisty (albo zmienia przypisanie) i
    aktywuje jego konto — to samo, co robi specjalista w apce, tylko z panelu."""
    conn = get_db()
    patient = conn.execute("SELECT id FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if not patient:
        conn.close()
        raise HTTPException(404, "Nie znaleziono pacjenta o takim ID")
    spec = conn.execute("SELECT id FROM specialists WHERE LOWER(id) = LOWER(?)", (req.specialist_id.strip(),)).fetchone()
    if not spec:
        conn.close()
        raise HTTPException(404, "Nie znaleziono specjalisty o takim ID")
    conn.execute("UPDATE patients SET specialist_id = ?, status = 'active' WHERE id = ?", (spec["id"], patient_id))
    conn.commit()
    conn.close()
    return {"status": "ok", "specialist_id": spec["id"]}


@app.post("/admin/patients/{patient_id}/unassign", dependencies=[Depends(require_admin)])
def admin_unassign_patient(patient_id: str):
    """Odpina pacjenta od specjalisty i cofa go do stanu 'pending' (apka pacjenta
    przestaje wysyłać dane, dopóki ktoś go znów nie przypisze)."""
    conn = get_db()
    patient = conn.execute("SELECT id FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if not patient:
        conn.close()
        raise HTTPException(404, "Nie znaleziono pacjenta o takim ID")
    conn.execute("UPDATE patients SET specialist_id = NULL, status = 'pending' WHERE id = ?", (patient_id,))
    conn.commit()
    conn.close()
    return {"status": "ok"}


_PANEL_CSS = r"""
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 0;
         background: #f4f5f7; color: #1a1a1a; }
  .nav { background: #0a5a62; padding: 0 24px; display: flex; align-items: center; gap: 4px; }
  .nav .brand { color: #7dd3fc; font-weight: 700; font-size: 14px; margin-right: 20px; padding: 14px 0; }
  .nav a { color: #ccc; text-decoration: none; font-size: 13px; padding: 14px 14px; border-bottom: 3px solid transparent; }
  .nav a:hover { color: white; }
  .nav a.active { color: white; border-bottom-color: #7dd3fc; }
  .page { padding: 24px; max-width: 1200px; margin: 0 auto; }
  h2 { font-size: 15px; margin: 0 0 4px; }
  .banner { background: #0a5a62; color: white; padding: 16px 20px; border-radius: 10px; margin-bottom: 24px; }
  .banner .ip { font-family: ui-monospace, monospace; font-size: 22px; font-weight: 700; color: #7dd3fc; letter-spacing: 0.5px; }
  .banner .label { font-size: 12px; color: #aaa; text-transform: uppercase; letter-spacing: 0.5px; }
  section { margin-bottom: 28px; }
  .sub { color: #666; font-size: 13px; margin-bottom: 12px; }
  table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px;
          overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  th, td { text-align: left; padding: 8px 14px; font-size: 13px; border-bottom: 1px solid #eee; vertical-align: middle; }
  th { background: #fafafa; color: #555; font-weight: 600; text-transform: uppercase; font-size: 11px; }
  tr:last-child td { border-bottom: none; }
  .role { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; }
  .role-pacjent { background: #e3f2fd; color: #1565c0; }
  .role-specjalista { background: #f3e5f5; color: #6a1b9a; }
  .role-opiekun { background: #e8f5e9; color: #2e7d32; }
  .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
  .dot-online { background: #2e7d32; }
  .dot-offline { background: #bbb; }
  .mono { font-family: ui-monospace, monospace; font-size: 12px; color: #444; }
  .empty { padding: 40px; text-align: center; color: #888; background: white; border-radius: 8px; }
  .muted { color: #999; }
  .status-ok { color: #2e7d32; font-weight: 600; }
  .status-err { color: #c62828; font-weight: 600; }
  .logs-table { max-height: 520px; overflow-y: auto; display: block; }
  .panel { background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); padding: 16px 20px; }
  .panel input, .toolbar input, .toolbar select, td select { padding: 7px 10px; font-size: 13px; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; }
  .form-row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
  .form-row input { flex: 1; min-width: 160px; }
  button { background: #0a5a62; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 13px; cursor: pointer; }
  button:hover { background: #2a2a4a; }
  button.secondary { background: #eee; color: #333; }
  button.secondary:hover { background: #ddd; }
  .form-msg { font-size: 12px; margin-top: 8px; min-height: 16px; }
  .form-msg.ok { color: #2e7d32; }
  .form-msg.err { color: #c62828; }
  .status-chip { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; }
  .status-pending { background: #fff3e0; color: #e65100; }
  .status-active { background: #e8f5e9; color: #2e7d32; }
  .btn-sm { background: #eee; color: #333; border: none; padding: 4px 10px; border-radius: 6px; font-size: 11px; cursor: pointer; margin-right: 4px; }
  .btn-sm:hover { background: #ddd; }
  .btn-danger { background: #ffebee; color: #c62828; }
  .btn-danger:hover { background: #ffcdd2; }
  .btn-warn { background: #fff3e0; color: #e65100; }
  .btn-warn:hover { background: #ffe0b2; }
  .tabs { display: flex; gap: 8px; margin-bottom: 20px; }
  .tab { background: white; color: #333; border: 1px solid #ddd; padding: 8px 18px; border-radius: 20px; font-size: 13px; cursor: pointer; }
  .tab.active { background: #0a5a62; color: white; border-color: #0a5a62; }
  .toolbar { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-bottom: 12px; }
  .toolbar input { min-width: 240px; }
  .stats { display: flex; gap: 12px; margin-bottom: 14px; flex-wrap: wrap; }
  .stat { background: white; border-radius: 8px; padding: 10px 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); font-size: 12px; color: #666; }
  .stat b { display: block; font-size: 20px; color: #1a1a1a; }
  .warn-banner { background: #fff3e0; color: #8a4b00; border: 1px solid #ffcc80; border-radius: 8px; padding: 10px 14px; font-size: 13px; margin-bottom: 14px; }
  .sub-row td { background: #fafafa; }
  .copy { cursor: pointer; }
  .copy:hover { text-decoration: underline; }
"""

_COMMON_JS = r"""
function escapeHtml(s) {
  return (s === null || s === undefined ? "" : String(s)).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
function fmtAgo(sec) {
  if (sec === null || sec === undefined) return "—";
  if (sec < 5) return "przed chwilą";
  if (sec < 60) return sec + " s temu";
  if (sec < 3600) return Math.floor(sec / 60) + " min temu";
  return Math.floor(sec / 3600) + " godz. temu";
}
function fmtTime(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleTimeString("pl-PL");
}
function fmtDateTime(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("pl-PL");
}
"""


def _render_panel_page(title: str, active: str, body: str, script: str, server_url: str) -> str:
    nav = (
        '<div class="nav"><span class="brand">DEPRESS-SENSE</span>'
        f'<a href="/dashboard" class="{"active" if active == "dashboard" else ""}">Monitoring serwera</a>'
        f'<a href="/admin" class="{"active" if active == "admin" else ""}">Użytkownicy</a></div>'
    )
    return (
        '<!DOCTYPE html><html lang="pl"><head><meta charset="utf-8">'
        f"<title>{title}</title>"
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<style>{_PANEL_CSS}</style></head><body>{nav}"
        f'<div class="page">{body}</div><script>{_COMMON_JS}{script}</script></body></html>'
    ).replace("__SERVER_URL__", escape_html(server_url))


def escape_html(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _public_server_url(request: Request) -> str:
    if PUBLIC_URL:
        # Serwer zewnętrzny — pokazujemy prawdziwy publiczny adres, a nie lokalny IP
        # kontenera (który i tak byłby bezużyteczny dla kogokolwiek spoza hosta).
        return PUBLIC_URL.rstrip("/")
    ip = get_local_ip()
    server_info = request.scope.get("server")
    port = server_info[1] if server_info and server_info[1] else os.environ.get("PORT", "8000")
    return f"http://{ip}:{port}"


_DASHBOARD_BODY = r"""
  <div class="banner">
    <div class="label">Serwer DEPRESS-SENSE działa pod adresem</div>
    <div class="ip">__SERVER_URL__</div>
    <div class="label" style="margin-top: 6px;">Adres jest zaszyty na stałe w kodzie wszystkich 3 apek — nie trzeba go nigdzie wpisywać.
      Zarządzanie kontami: zakładka „Użytkownicy”.</div>
  </div>
  <section>
    <h2>Logi żądań (na żywo)</h2>
    <div class="sub">Każde zapytanie trafiające do serwera. Odświeża się co 2 sekundy.</div>
    <div id="logs">Ładowanie...</div>
  </section>
  <section>
    <h2>Podpięte urządzenia</h2>
    <div class="sub">„Online” = kontakt w ciągu ostatnich 60 sekund.</div>
    <div id="devices">Ładowanie...</div>
  </section>
"""

_DASHBOARD_JS = r"""
async function refreshLogs() {
  const el = document.getElementById("logs");
  let logs;
  try { logs = await (await fetch("/api/logs")).json(); }
  catch (e) { el.innerHTML = '<div class="empty">Błąd połączenia z serwerem.</div>'; return; }
  if (!Array.isArray(logs)) { el.innerHTML = '<div class="empty">' + escapeHtml(logs.detail || "Brak dostępu.") + '</div>'; return; }
  if (logs.length === 0) { el.innerHTML = '<div class="empty">Jeszcze żadnych zapytań.</div>'; return; }
  let html = '<div class="logs-table"><table><thead><tr><th>Godzina</th><th>Metoda</th><th>Ścieżka</th><th>Status</th><th>Adres IP</th><th>Czas</th></tr></thead><tbody>';
  for (const l of logs) {
    const statusClass = l.status && l.status < 400 ? "status-ok" : "status-err";
    html += '<tr><td class="mono">' + fmtTime(l.time) + '</td><td class="mono">' + escapeHtml(l.method) +
      '</td><td class="mono">' + escapeHtml(l.path) + '</td><td class="mono ' + statusClass + '">' + escapeHtml(l.status ?? "błąd") +
      '</td><td class="mono muted">' + escapeHtml(l.ip) + '</td><td class="mono muted">' + l.duration_ms + ' ms</td></tr>';
  }
  el.innerHTML = html + '</tbody></table></div>';
}
async function refreshDevices() {
  const el = document.getElementById("devices");
  let devices;
  try { devices = await (await fetch("/api/devices")).json(); }
  catch (e) { el.innerHTML = '<div class="empty">Błąd połączenia z serwerem.</div>'; return; }
  if (!Array.isArray(devices)) { el.innerHTML = '<div class="empty">' + escapeHtml(devices.detail || "Brak dostępu.") + '</div>'; return; }
  if (devices.length === 0) { el.innerHTML = '<div class="empty">Żadne urządzenie jeszcze się nie odezwało.<br>Uruchom apkę Pacjent, Specjalista albo Opiekun.</div>'; return; }
  let html = '<table><thead><tr><th></th><th>Rola</th><th>Device ID</th><th>Model</th><th>Adres IP</th><th>MAC</th><th>Ostatni kontakt</th><th>Ostatnia akcja</th></tr></thead><tbody>';
  for (const d of devices) {
    html += '<tr><td><span class="dot ' + (d.online ? "dot-online" : "dot-offline") + '"></span></td>' +
      '<td><span class="role role-' + escapeHtml(d.role) + '">' + escapeHtml(d.role) + '</span></td>' +
      '<td class="mono">' + escapeHtml(d.device_id.slice(0, 8)) + '…</td><td>' + escapeHtml(d.model) + '</td>' +
      '<td class="mono">' + escapeHtml(d.ip_address) + '</td><td class="mono muted">' + escapeHtml(d.mac_address) + '</td>' +
      '<td>' + fmtAgo(d.seconds_ago) + '</td><td class="mono muted">' + escapeHtml(d.last_endpoint) + '</td></tr>';
  }
  el.innerHTML = html + '</tbody></table>';
}
function refreshAll() { refreshLogs(); refreshDevices(); }
refreshAll();
setInterval(refreshAll, 2000);
"""

_ADMIN_BODY = r"""
  <div class="tabs">
    <button class="tab active" data-tab="specialists">Specjaliści</button>
    <button class="tab" data-tab="patients">Pacjenci i opiekunowie</button>
  </div>

  <div id="tab-specialists">
    <section>
      <h2>Dodaj specjalistę</h2>
      <div class="sub">ID + hasło startowe do logowania w apce Specjalisty (min. 8 znaków). Nowe konto wymusza zmianę hasła przy pierwszym logowaniu.</div>
      <div class="panel">
        <div class="form-row">
          <input id="spec-id" type="text" placeholder="ID specjalisty (np. jkowalski)" autocomplete="off">
          <input id="spec-password" type="text" placeholder="Hasło startowe (min. 8 znaków)" autocomplete="off">
          <button class="secondary" id="gen-password" type="button">Generuj hasło</button>
          <button id="add-specialist" type="button">Dodaj specjalistę</button>
        </div>
        <div id="spec-msg" class="form-msg"></div>
      </div>
    </section>
    <section>
      <h2>Konta specjalistów</h2>
      <div id="specialists-warning"></div>
      <div id="specialists-list">Ładowanie...</div>
    </section>
  </div>

  <div id="tab-patients" style="display:none">
    <section>
      <h2>Pacjenci</h2>
      <div class="sub">Wszyscy zarejestrowani uczestnicy. „Oczekuje” = jeszcze nieprzypisany do żadnego specjalisty — apka pacjenta nie wysyła wtedy danych.
        Wybierz specjalistę z listy, aby przypisać (i aktywować) pacjenta; „— brak —” odpina go.</div>
      <div class="stats" id="patient-stats"></div>
      <div class="toolbar">
        <input id="patient-search" type="search" placeholder="Szukaj po ID, nazwie lub specjaliście…">
        <select id="patient-filter">
          <option value="all">Wszyscy</option>
          <option value="pending">Tylko oczekujący</option>
          <option value="active">Tylko aktywni</option>
        </select>
        <button class="secondary" id="patients-refresh" type="button">Odśwież</button>
      </div>
      <div id="admin-patients">Ładowanie...</div>
    </section>
  </div>
"""

_ADMIN_JS = r"""
let specialists = [];
let patients = [];
const openCaregivers = new Set();

async function call(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  try {
    const resp = await fetch(path, opts);
    let data = null;
    try { data = await resp.json(); } catch (e) {}
    return { ok: resp.ok, status: resp.status, data };
  } catch (e) {
    return { ok: false, status: 0, data: { detail: "Brak połączenia z serwerem." } };
  }
}
function errText(r) { return (r.data && r.data.detail) || ("Błąd (kod " + r.status + ")."); }

// --- zakładki
document.querySelectorAll(".tab").forEach(btn => btn.addEventListener("click", () => showTab(btn.dataset.tab)));
function showTab(name) {
  document.querySelectorAll(".tab").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
  document.getElementById("tab-specialists").style.display = name === "specialists" ? "" : "none";
  document.getElementById("tab-patients").style.display = name === "patients" ? "" : "none";
  if (location.hash !== "#" + name) history.replaceState(null, "", "#" + name);
}

// --- specjaliści
async function refreshSpecialists() {
  const el = document.getElementById("specialists-list");
  const r = await call("GET", "/specialists");
  if (!r.ok) { el.innerHTML = '<div class="empty">' + escapeHtml(errText(r)) + '</div>'; return; }
  specialists = r.data;
  document.getElementById("specialists-warning").innerHTML = specialists.some(s => s.default_credentials)
    ? '<div class="warn-banner">⚠ Konto testowe <b>spec001</b> nadal ma domyślne, publicznie znane hasło. Zresetuj je albo usuń to konto, zanim serwer zacznie obsługiwać realnych uczestników.</div>' : "";
  if (specialists.length === 0) { el.innerHTML = '<div class="empty">Żadnego konta specjalisty.</div>'; renderPatients(); return; }
  let html = '<table><thead><tr><th>ID</th><th>Pacjenci</th><th>Hasło</th><th>Akcje</th></tr></thead><tbody>';
  for (const s of specialists) {
    html += '<tr><td class="mono">' + escapeHtml(s.id) + '</td><td>' + s.patient_count + '</td><td>' +
      (s.must_change_password ? '<span class="status-chip status-pending">wymagana zmiana</span>' : '<span class="status-chip status-active">ustawione</span>') +
      '</td><td>' +
      '<button class="btn-sm" data-action="reset-pw" data-id="' + escapeHtml(s.id) + '">Ustaw nowe hasło</button>' +
      '<button class="btn-sm btn-warn" data-action="force-pw" data-id="' + escapeHtml(s.id) + '">Wymuś zmianę hasła</button>' +
      '<button class="btn-sm btn-danger" data-action="delete-spec" data-id="' + escapeHtml(s.id) + '">Usuń</button></td></tr>';
  }
  el.innerHTML = html + '</tbody></table>';
  renderPatients();
}

function randomPassword() {
  const chars = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = new Uint32Array(14);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => chars[b % chars.length]).join("");
}
document.getElementById("gen-password").addEventListener("click", () => { document.getElementById("spec-password").value = randomPassword(); });
document.getElementById("add-specialist").addEventListener("click", async () => {
  const idEl = document.getElementById("spec-id"), pwEl = document.getElementById("spec-password"), msgEl = document.getElementById("spec-msg");
  const id = idEl.value.trim(), password = pwEl.value;
  msgEl.className = "form-msg";
  if (!id || !password) { msgEl.textContent = "Podaj ID i hasło."; msgEl.className = "form-msg err"; return; }
  const r = await call("POST", "/specialists/register", { specialist_id: id, password });
  if (r.ok) {
    msgEl.textContent = 'Dodano konto „' + id + '”. Hasło startowe: ' + password + ' (przekaż je specjaliście — przy pierwszym logowaniu będzie musiał je zmienić).';
    msgEl.className = "form-msg ok";
    idEl.value = ""; pwEl.value = "";
    refreshSpecialists();
  } else { msgEl.textContent = errText(r); msgEl.className = "form-msg err"; }
});

// --- pacjenci
async function refreshPatients() {
  const el = document.getElementById("admin-patients");
  const r = await call("GET", "/admin/patients");
  if (!r.ok) { el.innerHTML = '<div class="empty">' + escapeHtml(errText(r)) + '</div>'; return; }
  patients = r.data;
  renderPatients();
}

function renderPatients() {
  const el = document.getElementById("admin-patients");
  const active = patients.filter(p => p.status === "active").length;
  document.getElementById("patient-stats").innerHTML =
    '<div class="stat"><b>' + patients.length + '</b>wszyscy</div>' +
    '<div class="stat"><b>' + active + '</b>aktywni</div>' +
    '<div class="stat"><b>' + (patients.length - active) + '</b>oczekujący</div>' +
    '<div class="stat"><b>' + patients.reduce((a, p) => a + p.caregiver_count, 0) + '</b>opiekunów łącznie</div>';
  const q = document.getElementById("patient-search").value.trim().toLowerCase();
  const filter = document.getElementById("patient-filter").value;
  const rows = patients.filter(p =>
    (filter === "all" || p.status === filter) &&
    (!q || [p.id, p.name, p.specialist_id].some(v => (v || "").toLowerCase().includes(q))));
  if (patients.length === 0) { el.innerHTML = '<div class="empty">Żaden pacjent jeszcze się nie zarejestrował.</div>'; return; }
  if (rows.length === 0) { el.innerHTML = '<div class="empty">Brak pacjentów spełniających filtr.</div>'; return; }
  let html = '<table><thead><tr><th>ID pacjenta</th><th>Nazwa</th><th>Status</th><th>Specjalista</th><th>Ostatnia sync.</th><th>Opiekunowie</th><th>Akcje</th></tr></thead><tbody>';
  for (const p of rows) {
    const options = ['<option value="">— brak —</option>'].concat(specialists.map(s =>
      '<option value="' + escapeHtml(s.id) + '"' + (s.id === p.specialist_id ? " selected" : "") + '>' + escapeHtml(s.id) + '</option>')).join("");
    html += '<tr><td class="mono copy" title="Kliknij, aby skopiować" data-action="copy" data-id="' + escapeHtml(p.id) + '">' + escapeHtml(p.id.slice(0, 13)) + '…</td>' +
      '<td>' + escapeHtml(p.name || "—") + '</td>' +
      '<td>' + (p.status === "active" ? '<span class="status-chip status-active">aktywny</span>' : '<span class="status-chip status-pending">oczekuje</span>') + '</td>' +
      '<td><select data-assign="' + escapeHtml(p.id) + '">' + options + '</select></td>' +
      '<td>' + fmtDateTime(p.last_sync) + '</td>' +
      '<td>' + p.caregiver_count + (p.caregiver_count > 0 ? ' <button class="btn-sm" data-action="toggle-cg" data-id="' + escapeHtml(p.id) + '">' + (openCaregivers.has(p.id) ? "ukryj" : "zarządzaj") + '</button>' : '') + '</td>' +
      '<td><button class="btn-sm btn-danger" data-action="delete-patient" data-id="' + escapeHtml(p.id) + '">Usuń pacjenta</button></td></tr>';
    if (openCaregivers.has(p.id)) html += '<tr class="sub-row"><td colspan="7" id="cg-' + escapeHtml(p.id) + '">Ładowanie opiekunów…</td></tr>';
  }
  el.innerHTML = html + '</tbody></table>';
  for (const id of openCaregivers) loadCaregivers(id);
}

async function loadCaregivers(patientId) {
  const cell = document.getElementById("cg-" + patientId);
  if (!cell) return;
  const r = await call("GET", "/admin/patients/" + encodeURIComponent(patientId) + "/caregivers");
  if (!r.ok) { cell.textContent = errText(r); return; }
  if (r.data.length === 0) { cell.textContent = "Ten pacjent nie ma opiekunów."; return; }
  cell.innerHTML = 'Opiekunowie (device ID): ' + r.data.map(c =>
    '<span class="mono">' + escapeHtml(c.caregiver_device_id) + '</span> <button class="btn-sm btn-danger" data-action="remove-cg" data-id="' + escapeHtml(patientId) +
    '" data-cg="' + escapeHtml(c.caregiver_device_id) + '">Odłącz</button>').join(" &nbsp; ");
}

document.getElementById("patient-search").addEventListener("input", renderPatients);
document.getElementById("patient-filter").addEventListener("change", renderPatients);
document.getElementById("patients-refresh").addEventListener("click", refreshPatients);

document.addEventListener("change", async (ev) => {
  const sel = ev.target.closest("select[data-assign]");
  if (!sel) return;
  const patientId = sel.dataset.assign;
  const r = sel.value
    ? await call("POST", "/admin/patients/" + encodeURIComponent(patientId) + "/assign", { specialist_id: sel.value })
    : await call("POST", "/admin/patients/" + encodeURIComponent(patientId) + "/unassign");
  if (!r.ok) alert(errText(r));
  await refreshPatients();
  refreshSpecialists();
});

// --- akcje przyciskowe (delegacja zdarzeń)
document.addEventListener("click", async (ev) => {
  const btn = ev.target.closest("[data-action]");
  if (!btn) return;
  const id = btn.dataset.id;
  switch (btn.dataset.action) {
    case "copy":
      try { await navigator.clipboard.writeText(id); btn.textContent = "skopiowano ✓"; setTimeout(renderPatients, 900); } catch (e) { prompt("ID pacjenta:", id); }
      break;
    case "force-pw":
      if (!confirm('Wymusić zmianę hasła dla „' + id + '” przy następnym logowaniu?')) return;
      { const r = await call("POST", "/specialists/" + encodeURIComponent(id) + "/force-password-change"); if (!r.ok) alert(errText(r)); }
      refreshSpecialists(); break;
    case "reset-pw": {
      const suggestion = randomPassword();
      const pw = prompt('Nowe hasło dla „' + id + '” (min. 8 znaków; przy logowaniu zostanie wymuszona jego zmiana):', suggestion);
      if (!pw) return;
      const r = await call("POST", "/admin/specialists/" + encodeURIComponent(id) + "/reset-password", { new_password: pw });
      alert(r.ok ? 'Hasło ustawione. Przekaż je specjaliście: ' + pw : errText(r));
      refreshSpecialists(); break;
    }
    case "delete-spec":
      if (!confirm('Usunąć konto specjalisty „' + id + '”? Jego pacjenci wrócą do stanu „oczekuje”.')) return;
      { const r = await call("DELETE", "/specialists/" + encodeURIComponent(id)); if (!r.ok) alert(errText(r)); }
      await refreshPatients(); refreshSpecialists(); break;
    case "delete-patient":
      if (!confirm('Usunąć pacjenta ' + id + ' i WSZYSTKIE jego dane (pomiary, samooceny, PHQ-9, MADRS, opiekunowie)? Operacja jest nieodwracalna.')) return;
      { const r = await call("DELETE", "/admin/patients/" + encodeURIComponent(id)); if (!r.ok) alert(errText(r)); }
      openCaregivers.delete(id);
      await refreshPatients(); refreshSpecialists(); break;
    case "toggle-cg":
      if (openCaregivers.has(id)) openCaregivers.delete(id); else openCaregivers.add(id);
      renderPatients(); break;
    case "remove-cg":
      if (!confirm('Odłączyć tego opiekuna od pacjenta?')) return;
      { const r = await call("DELETE", "/admin/patients/" + encodeURIComponent(id) + "/caregivers/" + encodeURIComponent(btn.dataset.cg)); if (!r.ok) alert(errText(r)); }
      await refreshPatients(); break;
  }
});

showTab(location.hash === "#patients" ? "patients" : "specialists");
refreshSpecialists().then(refreshPatients);
// Odświeżanie w tle co 15 s — pomijane, gdy admin akurat wybiera coś z listy/pisze w polu.
setInterval(() => {
  const a = document.activeElement;
  if (a && (a.tagName === "SELECT" || a.tagName === "INPUT")) return;
  refreshPatients(); refreshSpecialists();
}, 15000);
"""


@app.get("/dashboard", response_class=HTMLResponse, dependencies=[Depends(require_admin)])
def dashboard(request: Request):
    """Monitoring serwera na żywo (adres, logi żądań, urządzenia). Zarządzanie
    użytkownikami jest teraz osobno, na /admin."""
    return _render_panel_page(
        "DEPRESS-SENSE — monitoring", "dashboard", _DASHBOARD_BODY, _DASHBOARD_JS, _public_server_url(request),
    )


@app.get("/admin", response_class=HTMLResponse, dependencies=[Depends(require_admin)])
def admin_panel(request: Request):
    """Osobny panel do dodawania użytkowników i operacji na nich (specjaliści,
    pacjenci, opiekunowie)."""
    return _render_panel_page(
        "DEPRESS-SENSE — użytkownicy", "admin", _ADMIN_BODY, _ADMIN_JS, _public_server_url(request),
    )


# ---------------------------------------------------------------------------
# Portal WWW specjalisty (/specjalista) — patrz portal.py
# ---------------------------------------------------------------------------
import portal  # noqa: E402

portal.setup(app, globals())


# ---------------------------------------------------------------------------
# Uruchomienie bezpośrednio (`python main.py`, np. przyciskiem "Run" w IDE).
# Do tej pory plik nie miał tego bloku, więc odpalenie w ten sposób (bez
# wpisywania komendy `uvicorn main:app ...` w terminalu) po prostu definiowało
# `app` i kończyło proces (exit code 0) bez wystartowania serwera — wyglądało
# to tak, jakby serwer "działał", ale w rzeczywistości nic nie nasłuchiwało.
# Udokumentowana komenda `uvicorn main:app --host 0.0.0.0 --port 8000`
# (README.md, komenda startowa na Railway) działa tak jak dotychczas —
# ten blok tylko dodaje DRUGĄ, równoważną drogę startu, przydatną lokalnie.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8000")),
    )
