"""
DEPRESS-SENSE — portal WWW specjalisty (backend).

Strona dla specjalisty w przeglądarce: to samo, co w apce Specjalisty (lista pacjentów,
szczegóły, alerty, MADRS, kontakt), plus wykresy zbiorcze i dla każdego pacjenta.
Frontend: static/portal.html (jeden plik, bez frameworka), wykresy: static/chart.umd.js
(Chart.js, serwowany z tego samego serwera — bez zależności od zewnętrznego CDN).

W odróżnieniu od endpointów używanych przez apki mobilne (patrz Faza 12 w planie),
TEN moduł od początku wymaga zalogowania: sesja w ciasteczku HttpOnly + SameSite=Strict,
a każde zapytanie o pacjenta sprawdza, że pacjent należy do zalogowanego specjalisty.

Moduł jest podpinany z main.py przez portal.setup(app, namespace) — nie importuje
main.py (uniknięcie podwójnego wykonania pliku przy `python main.py`).
"""

import os
import secrets
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

SESSION_COOKIE = "ds_session"
SESSION_TTL_SECONDS = 8 * 3600
_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

# token -> {"specialist_id", "must_change", "expires"} — w pamięci procesu (restart serwera
# wylogowuje; dla prototypu z jedną instancją to wystarcza).
_SESSIONS: dict = {}


class PortalLogin(BaseModel):
    specialist_id: str
    password: str


class PortalChangePassword(BaseModel):
    old_password: str
    new_password: str


class PortalAddPatient(BaseModel):
    patient_id: str


class PortalRename(BaseModel):
    name: Optional[str] = None
    caregiver_slots: Optional[int] = None


def setup(app, ns: dict):
    """ns — słownik z funkcjami/klasami z main.py (get_db, verify_password, ...)."""
    get_db = ns["get_db"]
    verify_password = ns["verify_password"]
    hash_password = ns["hash_password"]
    is_hashed = ns["is_hashed"]
    login_key = ns["_login_key"]
    check_throttle = ns["_check_login_throttle"]
    register_failure = ns["_register_login_failure"]
    login_fails = ns["_LOGIN_FAILS"]
    min_password = ns["MIN_PASSWORD_LENGTH"]
    now_iso = ns["now_iso"]
    get_latest_data = ns["get_latest_data"]
    get_patient_trends = ns["get_patient_trends"]
    compute_change = ns["_compute_change_detection"]
    phq9_summary = ns["phq9_summary"]
    madrs_summary = ns["madrs_summary"]
    self_assessment_summary = ns["self_assessment_summary"]
    list_phq9 = ns["list_phq9"]
    list_madrs = ns["list_madrs"]
    review_phq9 = ns["review_phq9_safety_flag"]
    submit_madrs = ns["submit_madrs"]
    MadrsRequest = ns["MadrsRequest"]
    contact_patient = ns["specialist_contact_patient"]

    router = APIRouter(prefix="/portal/api")

    # ------------------------------------------------------------------ sesja
    def _is_https(request: Request) -> bool:
        return request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "") == "https"

    def _session_from_request(request: Request) -> Optional[dict]:
        token = request.cookies.get(SESSION_COOKIE)
        sess = _SESSIONS.get(token) if token else None
        if not sess:
            return None
        if sess["expires"] < time.time():
            _SESSIONS.pop(token, None)
            return None
        return sess

    def _guard_csrf(request: Request):
        # Dodatkowa ochrona obok SameSite=Strict: zapytania zmieniające stan muszą mieć
        # nagłówek, którego nie da się dodać formularzem z obcej strony.
        if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get("x-portal") != "1":
            raise HTTPException(403, "Brak nagłówka X-Portal")

    def session_any(request: Request) -> dict:
        _guard_csrf(request)
        sess = _session_from_request(request)
        if not sess:
            raise HTTPException(401, "Zaloguj się")
        return sess

    def session_ready(sess: dict = Depends(session_any)) -> dict:
        if sess["must_change"]:
            raise HTTPException(403, "Najpierw zmień hasło startowe")
        return sess

    def own_patient(sess: dict, patient_id: str):
        conn = get_db()
        row = conn.execute(
            "SELECT id, name, status FROM patients WHERE id = ? AND specialist_id = ?",
            (patient_id, sess["specialist_id"]),
        ).fetchone()
        conn.close()
        if not row:
            # 404 zamiast 403 — nie zdradzamy, czy taki pacjent istnieje u kogoś innego.
            raise HTTPException(404, "Nie znaleziono pacjenta")
        return row

    # ------------------------------------------------------------------ logowanie
    @router.post("/login")
    def login(req: PortalLogin, request: Request, response: Response):
        _guard_csrf(request)
        key = login_key(req.specialist_id)
        check_throttle(key)
        conn = get_db()
        row = conn.execute(
            "SELECT id, password, must_change_password FROM specialists WHERE LOWER(id) = LOWER(?)",
            (req.specialist_id.strip(),),
        ).fetchone()
        if not row or not verify_password(row["password"], req.password):
            conn.close()
            register_failure(key)
            raise HTTPException(401, "Błędny login lub hasło")
        login_fails.pop(key, None)
        if not is_hashed(row["password"]):
            conn.execute("UPDATE specialists SET password = ? WHERE id = ?", (hash_password(req.password), row["id"]))
            conn.commit()
        conn.close()
        token = secrets.token_urlsafe(32)
        _SESSIONS[token] = {
            "specialist_id": row["id"],
            "must_change": bool(row["must_change_password"]),
            "expires": time.time() + SESSION_TTL_SECONDS,
        }
        response.set_cookie(
            SESSION_COOKIE, token, max_age=SESSION_TTL_SECONDS, httponly=True,
            samesite="strict", secure=_is_https(request), path="/",
        )
        return {"specialist_id": row["id"], "must_change_password": bool(row["must_change_password"])}

    @router.post("/logout")
    def logout(request: Request, response: Response):
        _guard_csrf(request)
        token = request.cookies.get(SESSION_COOKIE)
        if token:
            _SESSIONS.pop(token, None)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return {"status": "ok"}

    @router.get("/me")
    def me(request: Request):
        sess = _session_from_request(request)
        if not sess:
            raise HTTPException(401, "Zaloguj się")
        return {"specialist_id": sess["specialist_id"], "must_change_password": sess["must_change"]}

    @router.post("/change-password")
    def change_password(req: PortalChangePassword, request: Request, sess: dict = Depends(session_any)):
        key = login_key(sess["specialist_id"])
        check_throttle(key)
        conn = get_db()
        row = conn.execute("SELECT id, password FROM specialists WHERE id = ?", (sess["specialist_id"],)).fetchone()
        if not row or not verify_password(row["password"], req.old_password):
            conn.close()
            register_failure(key)
            raise HTTPException(401, "Błędne obecne hasło")
        if len(req.new_password) < min_password:
            conn.close()
            raise HTTPException(400, f"Nowe hasło jest za krótkie (minimum {min_password} znaków)")
        conn.execute(
            "UPDATE specialists SET password = ?, must_change_password = 0 WHERE id = ?",
            (hash_password(req.new_password), row["id"]),
        )
        conn.commit()
        conn.close()
        sess["must_change"] = False
        return {"status": "ok"}

    # ------------------------------------------------------------------ przegląd
    def _patient_card(r) -> dict:
        pid = r["id"]
        ss = self_assessment_summary(pid)
        ph = phq9_summary(pid)
        md = madrs_summary(pid)
        cd = compute_change(pid) or {}
        conn = get_db()
        alert = conn.execute(
            "SELECT id, timestamp FROM phq9_responses WHERE patient_id = ? AND safety_flag = 1 AND safety_reviewed = 0 "
            "ORDER BY id DESC LIMIT 1",
            (pid,),
        ).fetchone()
        conn.close()
        return {
            "id": pid,
            "name": r["name"],
            "status": r["status"],
            "flag": bool(r["flag"]),
            "last_sync": r["last_sync"],
            "self_assessment_count_7d": ss["self_assessment_count_7d"],
            "last_phq9": ph["last_phq9"],
            "phq9_due": ph["phq9_due"],
            "last_madrs": md["last_madrs"],
            "safety_alert": {"entry_id": alert["id"], "since": alert["timestamp"]} if alert else None,
            "change_flagged": bool(cd.get("flagged")),
            "change_since": cd.get("flagged_since"),
            "disappeared": bool(cd.get("disappeared")),
            "hours_since_last_sync": cd.get("hours_since_last_sync"),
            "insufficient_data": bool(cd.get("insufficient_data", True)),
        }

    @router.get("/overview")
    def overview(sess: dict = Depends(session_ready)):
        conn = get_db()
        rows = conn.execute(
            "SELECT id, name, status, flag, last_sync FROM patients WHERE specialist_id = ?",
            (sess["specialist_id"],),
        ).fetchall()
        conn.close()
        cards = [_patient_card(r) for r in rows]
        cards.sort(key=lambda c: (
            0 if c["safety_alert"] else 1,
            0 if (c["change_flagged"] or c["disappeared"]) else 1,
            (c["name"] or c["id"]).lower(),
        ))
        severity_counts: dict = {}
        phq_scores, madrs_scores = [], []
        for c in cards:
            ph = c["last_phq9"]
            label = ph["severity"] if ph else "brak wyniku"
            severity_counts[label] = severity_counts.get(label, 0) + 1
            if ph:
                phq_scores.append(ph["total_score"])
            if c["last_madrs"]:
                madrs_scores.append(c["last_madrs"]["total_score"])
        n = len(cards)
        regular = sum(1 for c in cards if c["self_assessment_count_7d"] >= 3)
        return {
            "specialist_id": sess["specialist_id"],
            "patients": cards,
            "summary": {
                "total": n,
                "safety_alerts": sum(1 for c in cards if c["safety_alert"]),
                "change_alerts": sum(1 for c in cards if c["change_flagged"]),
                "disappeared": sum(1 for c in cards if c["disappeared"]),
                "phq9_due": sum(1 for c in cards if c["phq9_due"]),
                "avg_phq9": round(sum(phq_scores) / len(phq_scores), 1) if phq_scores else None,
                "avg_madrs": round(sum(madrs_scores) / len(madrs_scores), 1) if madrs_scores else None,
                "self_assessment_regular_pct": round(100 * regular / n) if n else None,
                "phq9_severity": severity_counts,
            },
        }

    @router.get("/group-trends")
    def group_trends(days: int = 30, sess: dict = Depends(session_ready)):
        """Średnie po wszystkich pacjentach danego specjalisty, dzień po dniu (dni bez
        danych = null), plus punkty PHQ-9 każdego pacjenta osobno."""
        days = max(7, min(days, 90))
        conn = get_db()
        rows = conn.execute(
            "SELECT id, name FROM patients WHERE specialist_id = ? AND status = 'active'",
            (sess["specialist_id"],),
        ).fetchall()
        conn.close()
        keys = [
            "movement_avg", "mobility_avg", "room_activity_avg", "screen_time_minutes_avg",
            "communication_count", "self_assessment_mood", "self_assessment_energy",
            "self_assessment_sleep_quality", "self_assessment_anhedonia",
        ]
        sums = {k: None for k in keys}
        counts = {k: None for k in keys}
        labels = None
        reporting = None
        phq_by_patient = {}
        for r in rows:
            t = get_patient_trends(r["id"], days)
            if labels is None:
                labels = t["days"]
                sums = {k: [0.0] * len(labels) for k in keys}
                counts = {k: [0] * len(labels) for k in keys}
                reporting = [0] * len(labels)
            for k in keys:
                for i, v in enumerate(t[k]):
                    if v is not None:
                        sums[k][i] += v
                        counts[k][i] += 1
            for i, v in enumerate(t["movement_avg"]):
                if v is not None:
                    reporting[i] += 1
            display = r["name"] or r["id"][:8]
            if t["phq9"]:
                phq_by_patient[display] = t["phq9"]
        if labels is None:
            return {"days": [], "series": {}, "reporting": [], "phq9_by_patient": {}, "patients": 0}
        series = {
            k: [round(sums[k][i] / counts[k][i], 2) if counts[k][i] else None for i in range(len(labels))]
            for k in keys
        }
        return {
            "days": labels, "series": series, "reporting": reporting,
            "phq9_by_patient": phq_by_patient, "patients": len(rows),
        }

    # ------------------------------------------------------------------ pacjent
    @router.get("/patients/{patient_id}")
    def patient_detail(patient_id: str, sess: dict = Depends(session_ready)):
        own_patient(sess, patient_id)
        data = get_latest_data(patient_id)
        conn = get_db()
        p = conn.execute(
            "SELECT status, flag, caregiver_slots FROM patients WHERE id = ?", (patient_id,)
        ).fetchone()
        cg = conn.execute("SELECT COUNT(*) c FROM caregivers WHERE patient_id = ?", (patient_id,)).fetchone()["c"]
        alert = conn.execute(
            "SELECT id, timestamp FROM phq9_responses WHERE patient_id = ? AND safety_flag = 1 AND safety_reviewed = 0 "
            "ORDER BY id DESC LIMIT 1",
            (patient_id,),
        ).fetchone()
        conn.close()
        return {
            "data": data,
            "change": compute_change(patient_id),
            "status": p["status"],
            "flag": bool(p["flag"]),
            "caregivers": {"current": cg, "slots": p["caregiver_slots"]},
            "safety_alert": {"entry_id": alert["id"], "since": alert["timestamp"]} if alert else None,
            "phq9_history": list_phq9(patient_id, 30),
            "madrs_history": list_madrs(patient_id, 30),
        }

    @router.get("/patients/{patient_id}/trends")
    def patient_trends(patient_id: str, days: int = 30, sess: dict = Depends(session_ready)):
        own_patient(sess, patient_id)
        return get_patient_trends(patient_id, days)

    @router.post("/patients")
    def add_patient(req: PortalAddPatient, sess: dict = Depends(session_ready)):
        pid = req.patient_id.strip()
        conn = get_db()
        row = conn.execute("SELECT id, specialist_id FROM patients WHERE id = ?", (pid,)).fetchone()
        if not row:
            conn.close()
            raise HTTPException(404, "Pacjent o takim ID jeszcze nie zarejestrował się w systemie (nie uruchomił apki)")
        if row["specialist_id"] and row["specialist_id"] != sess["specialist_id"]:
            conn.close()
            raise HTTPException(409, "Ten pacjent jest już przypisany do innego specjalisty")
        conn.execute(
            "UPDATE patients SET specialist_id = ?, status = 'active' WHERE id = ?",
            (sess["specialist_id"], pid),
        )
        conn.commit()
        conn.close()
        return {"status": "ok"}

    @router.patch("/patients/{patient_id}")
    def update_patient(patient_id: str, req: PortalRename, sess: dict = Depends(session_ready)):
        own_patient(sess, patient_id)
        conn = get_db()
        if req.name is not None:
            conn.execute("UPDATE patients SET name = ? WHERE id = ?", (req.name.strip()[:120], patient_id))
        if req.caregiver_slots is not None:
            conn.execute(
                "UPDATE patients SET caregiver_slots = ? WHERE id = ?", (max(0, min(req.caregiver_slots, 10)), patient_id)
            )
        conn.commit()
        conn.close()
        return {"status": "ok"}

    @router.post("/patients/{patient_id}/clear-flag")
    def clear_flag(patient_id: str, sess: dict = Depends(session_ready)):
        own_patient(sess, patient_id)
        conn = get_db()
        conn.execute("UPDATE patients SET flag = 0, last_action_at = ? WHERE id = ?", (now_iso(), patient_id))
        conn.commit()
        conn.close()
        return {"status": "ok"}

    @router.post("/patients/{patient_id}/contact")
    def contact(patient_id: str, sess: dict = Depends(session_ready)):
        own_patient(sess, patient_id)
        return contact_patient(patient_id)

    @router.post("/patients/{patient_id}/phq9/{entry_id}/review")
    def review(patient_id: str, entry_id: int, sess: dict = Depends(session_ready)):
        own_patient(sess, patient_id)
        return review_phq9(patient_id, entry_id, sess["specialist_id"])

    @router.post("/patients/{patient_id}/madrs")
    def add_madrs(patient_id: str, req: MadrsRequest, sess: dict = Depends(session_ready)):
        own_patient(sess, patient_id)
        req.specialist_id = sess["specialist_id"]
        return submit_madrs(patient_id, req)

    app.include_router(router)

    # ------------------------------------------------------------------ strony
    @app.get("/specjalista", response_class=HTMLResponse)
    def portal_page():
        path = os.path.join(_STATIC_DIR, "portal.html")
        with open(path, encoding="utf-8") as f:
            return HTMLResponse(f.read(), headers={"Cache-Control": "no-store"})

    @app.get("/portal/static/chart.umd.js")
    def chart_js():
        return FileResponse(
            os.path.join(_STATIC_DIR, "chart.umd.js"),
            media_type="application/javascript",
            headers={"Cache-Control": "public, max-age=86400"},
        )
