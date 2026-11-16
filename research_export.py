"""Eksport badawczy z pseudonimizacją (RODO art. 4 pkt 5 — pseudonimizacja, nie anonimizacja).

Dwa oddzielne pliki, które NIE powinny być przechowywane razem:
  1) paczka danych (ZIP z CSV)  — bez imion, ID pacjentów, ID specjalistów i dat kalendarzowych,
  2) plik klucza (CSV)          — kod uczestnika ↔ prawdziwe ID/nazwa; tylko dla administratora badania.

Kod uczestnika = HMAC-SHA256(klucz, patient_id): stały (ten sam pacjent = ten sam kod we
wszystkich eksportach), nieodwracalny bez klucza. Klucz jest w zmiennej środowiskowej
DEPRESS_SENSE_PSEUDONYM_KEY (poza bazą danych!). Bez niej eksport jest wyłączony (503).

Co robimy z danymi:
  * patient_id → kod "P-XXXXXXXXXX", specialist_id (ocena MADRS) → "S-XXXXXX",
  * imię/nazwa pacjenta, opiekunowie, urządzenia, IP — nie wchodzą do eksportu,
  * znaczniki czasu → numer dnia od pierwszego wpisu uczestnika (day_index) + godzina doby
    tylko dla pomiarów behawioralnych (potrzebna do analizy rytmu dobowego),
  * pole tekstowe `occasion` (MADRS) pomijane — wolny tekst może zawierać dane osobowe.
"""
import csv
import hashlib
import hmac
import io
import os
import zipfile
from datetime import datetime

from fastapi import HTTPException
from fastapi.responses import Response

MIN_KEY_LEN = 16


def _key() -> bytes:
    k = os.environ.get("DEPRESS_SENSE_PSEUDONYM_KEY", "")
    if len(k) < MIN_KEY_LEN:
        raise HTTPException(
            503,
            "Eksport wyłączony: ustaw zmienną DEPRESS_SENSE_PSEUDONYM_KEY (min. 16 znaków, losowa) "
            "na serwerze — klucz przechowuj poza bazą danych.",
        )
    return k.encode("utf-8")


def code(prefix: str, value: str, length: int) -> str:
    digest = hmac.new(_key(), f"{prefix}:{value}".encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{prefix}-{digest[:length].upper()}"


def _date(ts: str):
    return datetime.fromisoformat(ts).date()


def _csv(header, rows) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(header)
    w.writerows(rows)
    return buf.getvalue()


README = """DEPRESS-SENSE — eksport badawczy (pseudonimizowany)

UWAGA PRAWNA: dane są PSEUDONIMIZOWANE, nie zanonimizowane. Pozostają danymi osobowymi (dane o zdrowiu,
RODO art. 9) dopóki istnieje plik klucza lub klucz HMAC. Nie przechowuj tej paczki razem z plikiem klucza.

participant  — kod uczestnika (P-...), ten sam we wszystkich plikach i eksportach
rater        — kod oceniającego specjalisty (S-...), tylko MADRS
day_index    — numer dnia od pierwszego wpisu danego uczestnika (0 = pierwszy dzień)
hour         — godzina doby 0-23 (UTC), tylko behavior.csv
Puste pole   — brak pomiaru (np. mobility bez zgody GPS), NIE zero.

behavior.csv         pomiary behawioralne (metadane telefonu; bez treści i bez współrzędnych)
self_assessment.csv  samoocena 0-10 (wyżej = lepiej)
phq9.csv             PHQ-9, pozycje 0-3, suma 0-27, flaga bezpieczeństwa
madrs.csv            MADRS (ocena kliniczna), pozycje 0-6, suma 0-60; bez pola tekstowego "occasion"
"""


def build_zip(get_db) -> bytes:
    _key()  # wczesne sprawdzenie konfiguracji
    conn = get_db()
    pats = [r["id"] for r in conn.execute("SELECT id FROM patients WHERE status = 'active'").fetchall()]
    first = {}
    for pid in pats:
        ts = conn.execute(
            """SELECT MIN(t) AS t FROM (
                 SELECT MIN(timestamp) AS t FROM behavior_data WHERE patient_id = ?
                 UNION ALL SELECT MIN(timestamp) FROM self_assessments WHERE patient_id = ?
                 UNION ALL SELECT MIN(timestamp) FROM phq9_responses WHERE patient_id = ?
                 UNION ALL SELECT MIN(timestamp) FROM madrs_assessments WHERE patient_id = ?)""",
            (pid, pid, pid, pid),
        ).fetchone()["t"]
        if ts:
            first[pid] = _date(ts)

    def day_idx(pid, ts):
        return (_date(ts) - first[pid]).days

    files = {}

    bcols = ["phone_activity", "app_usage", "movement", "mobility", "room_activity", "unlocks", "calls", "sms",
             "screen_time_minutes", "category_social_minutes", "category_productivity_minutes",
             "category_other_minutes", "call_duration_minutes"]
    rows = []
    for pid in first:
        for r in conn.execute(f"SELECT timestamp, {', '.join(bcols)} FROM behavior_data WHERE patient_id = ? ORDER BY timestamp", (pid,)):
            rows.append([code("P", pid, 10), day_idx(pid, r["timestamp"]), datetime.fromisoformat(r["timestamp"]).hour]
                        + ["" if r[c] is None else r[c] for c in bcols])
    files["behavior.csv"] = _csv(["participant", "day_index", "hour"] + bcols, rows)

    rows = []
    for pid in first:
        for r in conn.execute("SELECT timestamp, mood, energy, sleep_quality, anhedonia FROM self_assessments WHERE patient_id = ? ORDER BY timestamp", (pid,)):
            rows.append([code("P", pid, 10), day_idx(pid, r["timestamp"]), r["mood"], r["energy"], r["sleep_quality"], r["anhedonia"]])
    files["self_assessment.csv"] = _csv(["participant", "day_index", "mood", "energy", "sleep_quality", "anhedonia"], rows)

    items9 = [f"item{i}" for i in range(1, 10)]
    rows = []
    for pid in first:
        for r in conn.execute(f"SELECT timestamp, {', '.join(items9)}, total_score, severity, safety_flag, safety_reviewed FROM phq9_responses WHERE patient_id = ? ORDER BY timestamp", (pid,)):
            rows.append([code("P", pid, 10), day_idx(pid, r["timestamp"])] + [r[c] for c in items9]
                        + [r["total_score"], r["severity"], r["safety_flag"], r["safety_reviewed"]])
    files["phq9.csv"] = _csv(["participant", "day_index"] + items9 + ["total_score", "severity", "safety_flag", "safety_reviewed"], rows)

    items10 = [f"item{i}" for i in range(1, 11)]
    rows = []
    for pid in first:
        for r in conn.execute(f"SELECT timestamp, specialist_id, {', '.join(items10)}, total_score, severity, safety_flag FROM madrs_assessments WHERE patient_id = ? ORDER BY timestamp", (pid,)):
            rows.append([code("P", pid, 10), code("S", r["specialist_id"] or "", 6) if r["specialist_id"] else "", day_idx(pid, r["timestamp"])]
                        + [r[c] for c in items10] + [r["total_score"], r["severity"], r["safety_flag"]])
    files["madrs.csv"] = _csv(["participant", "rater", "day_index"] + items10 + ["total_score", "severity", "safety_flag"], rows)
    conn.close()

    files["README.txt"] = README
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in files.items():
            z.writestr(name, content)
    return buf.getvalue()


def build_key_csv(get_db) -> str:
    _key()
    conn = get_db()
    rows = []
    for r in conn.execute("SELECT id, name, specialist_id FROM patients ORDER BY id"):
        ts = conn.execute(
            """SELECT MIN(t) AS t FROM (
                 SELECT MIN(timestamp) AS t FROM behavior_data WHERE patient_id = ?
                 UNION ALL SELECT MIN(timestamp) FROM self_assessments WHERE patient_id = ?
                 UNION ALL SELECT MIN(timestamp) FROM phq9_responses WHERE patient_id = ?
                 UNION ALL SELECT MIN(timestamp) FROM madrs_assessments WHERE patient_id = ?)""",
            (r["id"], r["id"], r["id"], r["id"]),
        ).fetchone()["t"]
        rows.append([code("P", r["id"], 10), r["id"], r["name"] or "", r["specialist_id"] or "",
                     code("S", r["specialist_id"], 6) if r["specialist_id"] else "",
                     str(_date(ts)) if ts else ""])
    conn.close()
    return _csv(["participant", "patient_id", "patient_name", "specialist_id", "rater_code", "day_index_0_date"], rows)


def setup(app, get_db, require_admin):
    from fastapi import Depends

    @app.get("/admin/export/research.zip", dependencies=[Depends(require_admin)])
    def export_research():
        data = build_zip(get_db)
        return Response(data, media_type="application/zip", headers={
            "Content-Disposition": 'attachment; filename="depress-sense-research-pseudonymized.zip"',
            "Cache-Control": "no-store"})

    @app.get("/admin/export/key.csv", dependencies=[Depends(require_admin)])
    def export_key():
        return Response(build_key_csv(get_db), media_type="text/csv; charset=utf-8", headers={
            "Content-Disposition": 'attachment; filename="depress-sense-KEY-do-not-share.csv"',
            "Cache-Control": "no-store"})
