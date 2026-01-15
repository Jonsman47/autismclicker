import json
import os
import shutil
import threading
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, os.environ.get("DB_PATH", "db.json"))

lock = threading.Lock()


def _empty_db():
    return {
        "users": {},
        "settings": {
            "bg": None,
            "logo": None,
            "update": "",
            "shop": None,
            "season": {"id": None, "started_at": None},
            "season_history": [],
        },
        "reviews": [],
        "review_reports": [],
    }


def load_db():
    if not os.path.exists(DB_PATH):
        return _empty_db()
    try:
        with open(DB_PATH, "r", encoding="utf-8") as f:
            db = json.load(f)
    except Exception:
        bak = DB_PATH + ".bak"
        if os.path.exists(bak):
            try:
                with open(bak, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        bad = DB_PATH + ".bad"
        try:
            os.replace(DB_PATH, bad)
        except Exception:
            pass
        return _empty_db()

    db.setdefault("settings", {})
    db.setdefault("users", {})
    db.setdefault("reviews", [])
    db.setdefault("review_reports", [])
    settings = db["settings"]
    settings.setdefault("bg", None)
    settings.setdefault("logo", None)
    settings.setdefault("update", "")
    settings.setdefault("shop", None)
    settings.setdefault("season", {"id": None, "started_at": None})
    settings.setdefault("season_history", [])
    return db


def save_db(db):
    tmp = DB_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    bak = DB_PATH + ".bak"
    if os.path.exists(DB_PATH):
        try:
            shutil.copy2(DB_PATH, bak)
        except Exception:
            pass
    os.replace(tmp, DB_PATH)


def update_season(settings, users):
    now = time.localtime()
    current_id = f"{now.tm_year}-{now.tm_mon:02d}"
    season = settings.setdefault("season", {"id": None, "started_at": None})
    if season.get("id") == current_id:
        return
    previous_id = season.get("id")
    if previous_id:
        season_entry = {
            "id": previous_id,
            "ended_at": int(time.time()),
            "top_count": [],
            "top_cps": [],
        }
        rows = []
        for name, doc in (users or {}).items():
            prog = (doc or {}).get("progress") or {}
            rows.append({
                "user": name,
                "count": float(prog.get("season_count") or 0.0),
                "cps": float(prog.get("season_cps") or 0.0),
            })
        season_entry["top_count"] = sorted(rows, key=lambda r: r["count"], reverse=True)[:50]
        season_entry["top_cps"] = sorted(rows, key=lambda r: r["cps"], reverse=True)[:50]
        settings.setdefault("season_history", []).append(season_entry)

    season["id"] = current_id
    season["started_at"] = int(time.time())
    for doc in (users or {}).values():
        prog = (doc or {}).get("progress") or {}
        prog["season_count"] = float(prog.get("count") or 0.0)
        prog["season_cps"] = float(prog.get("cps") or 0.0)
        doc["progress"] = prog


def tick_bots(db, rate_per_hour=0.001):
    now = time.time()
    changed = False
    for _, doc in (db.get("users") or {}).items():
        if not doc.get("bot"):
            continue
        last = float(doc.get("bot_tick") or now)
        dt_h = max(0.0, (now - last) / 3600.0)
        if dt_h <= 0:
            continue

        prog = doc.get("progress") or {}
        cur = float(prog.get("count") or 0.0)
        if cur > 0.0:
            prog["count"] = cur * ((1.0 + rate_per_hour) ** dt_h)
            doc["progress"] = prog
            changed = True

        doc["bot_tick"] = now

    if changed:
        save_db(db)
