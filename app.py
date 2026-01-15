import os
import random
import secrets
import time
from functools import wraps

from flask import Flask, jsonify, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from achievements import ALL_ACH_BONUS, BASE_ACH_MULT, build_achievement_maps, scan_achievements, achievement_multiplier
from db import DB_PATH, lock, load_db, save_db, tick_bots, update_season
from game_logic import (
    ACHIEVEMENT_BOOSTS,
    MAX_CUSTOM_UNITS,
    PRESTIGE_TREE,
    PRESTIGE_UPGRADES,
    SHOP_TIERS,
    apply_offline_progress,
    asc_mult,
    daily_reward,
    daily_reward_amount,
    default_shop,
    empty_prestige,
    empty_progress,
    get_shop_catalog,
    normalize_progress,
    prestige_cost,
    prestige_tree_bonus,
    quest_progress,
    quest_reward_amount,
    assign_quests,
    refund_rate,
    shop_discount,
    start_boost,
    validate_progress_payload,
    compute_cps,
    compute_click_power,
    crit_chance,
)

app = Flask(__name__)


def _get_secret_key():
    path = os.environ.get("SECRET_FILE", "secret.key")
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    if os.path.exists(path):
        return open(path, "rb").read()
    key = secrets.token_hex(32).encode()
    with open(path, "wb") as f:
        f.write(key)
    return key


app.secret_key = _get_secret_key()
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_upload_root = os.environ.get("UPLOAD_DIR", "uploads")
if os.path.isabs(_upload_root):
    UPLOAD_DIR = _upload_root
else:
    UPLOAD_DIR = os.path.join(BASE_DIR, _upload_root)
ALLOWED_EXT = {"png", "jpg", "jpeg", "webp", "gif", "svg"}
ADMIN_USERNAME = "jonsman47"

os.makedirs(UPLOAD_DIR, exist_ok=True)

RATE_LIMITS = {
    "save_progress": (30, 60),
    "reviews": (10, 60),
    "review_report": (10, 300),
}
_rate_state = {}


def is_authed():
    return bool(session.get("user"))


def is_admin():
    return session.get("user", "").lower() == ADMIN_USERNAME


def get_theme_mode():
    return session.get("theme", "meme")


def set_theme_mode(mode: str):
    session["theme"] = "clean" if mode == "clean" else "meme"


def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(16)
        session["csrf_token"] = token
    return token


def require_csrf():
    token = session.get("csrf_token")
    if not token:
        return False
    submitted = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token") or request.args.get("csrf_token")
    return submitted == token


def rate_limit(key: str):
    limit, window = RATE_LIMITS.get(key, (0, 0))
    if limit <= 0:
        return True
    now = time.time()
    addr = request.headers.get("X-Forwarded-For", request.remote_addr) or "anon"
    bucket = _rate_state.setdefault((addr, key), [])
    bucket[:] = [t for t in bucket if now - t < window]
    if len(bucket) >= limit:
        return False
    bucket.append(now)
    return True


def csrf_protected(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            if not require_csrf():
                return jsonify({"ok": False, "err": "csrf"}), 400
        return fn(*args, **kwargs)

    return wrapper


def load_catalog(db):
    return get_shop_catalog((db.get("settings") or {}).get("shop"))


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not is_admin():
            return "Forbidden", 403
        return fn(*args, **kwargs)

    return wrapper


def _save_upload(file_storage):
    if not file_storage:
        return None, "no_file"
    filename = file_storage.filename or ""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXT:
        return None, "bad_ext"
    safe = secure_filename(os.path.splitext(filename)[0])
    uniq = f"{int(time.time())}_{secrets.token_hex(6)}.{ext}"
    path = os.path.join(UPLOAD_DIR, f"{safe}_{uniq}")
    file_storage.save(path)
    return path, None


@app.get("/uploads/<path:filename>")
def serve_upload(filename):
    return send_from_directory(UPLOAD_DIR, filename, conditional=True)


@app.get("/")
def home():
    with lock:
        db = load_db()
        tick_bots(db)
        update_season(db.get("settings"), db.get("users"))
        save_db(db)
    settings = db.get("settings", {})
    return render_template(
        "home.html",
        user=session.get("user"),
        is_admin=is_admin(),
        update_text=settings.get("update", ""),
        csrf_token=csrf_token(),
    )


@app.get("/register")
def register_form():
    return render_template("register.html", csrf_token=csrf_token())


@app.post("/register")
@csrf_protected
def register_post():
    u = (request.form.get("u") or "").strip()
    p = request.form.get("p") or ""
    if not u or not p:
        return "Invalid", 400
    with lock:
        db = load_db()
        if u in db["users"]:
            return "Username taken", 400
        db["users"][u] = {
            "pw": generate_password_hash(p),
            "progress": empty_progress(),
            "prestige": empty_prestige(),
        }
        save_db(db)
    session["user"] = u
    return redirect("/")


@app.get("/login")
def login_form():
    return render_template("login.html", csrf_token=csrf_token())


@app.post("/login")
@csrf_protected
def login_post():
    u = (request.form.get("u") or "").strip()
    p = request.form.get("p") or ""
    with lock:
        db = load_db()
        doc = db["users"].get(u)
    if not doc or not check_password_hash(doc["pw"], p):
        return "Wrong creds", 401
    session["user"] = u
    return redirect("/")


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.get("/clicker")
def clicker():
    with lock:
        db = load_db()
        tick_bots(db)
        update_season(db.get("settings"), db.get("users"))
        save_db(db)
    return render_template(
        "clicker.html",
        csrf_token=csrf_token(),
        theme_mode=get_theme_mode(),
        is_admin=is_admin(),
    )


@app.get("/profile")
def profile_page():
    return render_template("profile.html", csrf_token=csrf_token())


@app.get("/leaderboard")
def leaderboard_page():
    return render_template("leaderboard.html", csrf_token=csrf_token(), theme_mode=get_theme_mode())


@app.get("/disclaimer")
def disclaimer():
    return render_template("disclaimer.html")


@app.get("/admin")
@admin_required
def admin_panel():
    with lock:
        db = load_db()
        users = sorted(db["users"].keys())
        st = db.get("settings", {})
        reports = list(reversed(db.get("review_reports", [])))[:200]
    return render_template(
        "admin.html",
        users=users,
        settings=st,
        csrf_token=csrf_token(),
        reports=reports,
    )


@app.get("/api/me")
def api_me():
    return jsonify({"ok": True, "user": session.get("user"), "is_admin": is_admin()})


@app.post("/api/theme")
@csrf_protected
def api_set_theme():
    data = request.get_json(silent=True) or {}
    mode = (data.get("mode") or "meme").lower()
    set_theme_mode(mode)
    return jsonify({"ok": True, "mode": get_theme_mode()})


@app.get("/api/settings")
def api_settings():
    with lock:
        db = load_db()
        st = db.get("settings", {})
    def full(url):
        return url_for("serve_upload", filename=os.path.basename(url), _external=False) if url else None
    return jsonify({
        "ok": True,
        "settings": {
            "bg": full(st.get("bg")),
            "logo": full(st.get("logo")),
            "update": st.get("update", ""),
        },
    })


@app.get("/api/shop")
def api_shop():
    with lock:
        db = load_db()
        catalog = load_catalog(db)
    return jsonify({"ok": True, "shop": catalog, "tiers": SHOP_TIERS, "max_custom": MAX_CUSTOM_UNITS})


@app.post("/api/save_progress")
@csrf_protected
def api_save_progress():
    if not is_authed():
        return jsonify({"ok": False, "err": "not_auth"}), 401
    if not rate_limit("save_progress"):
        return jsonify({"ok": False, "err": "rate"}), 429

    data = request.get_json(silent=True) or {}

    with lock:
        db = load_db()
        u = session.get("user")
        if not u or u not in db.get("users", {}):
            return jsonify({"ok": False, "err": "user_missing"}), 400
        doc = db["users"][u]
        doc.setdefault("prestige", empty_prestige())
        doc["progress"] = normalize_progress(doc.get("progress"))
        catalog = load_catalog(db)

        ok, err, cleaned = validate_progress_payload(data, catalog)
        if not ok:
            return jsonify({"ok": False, "err": err}), 400

        doc["progress"].update({
            "count": max(0.0, cleaned["count"]),
            "inventory": cleaned["inventory"],
            "custom_units": cleaned["custom_units"],
            "saved_at": int(time.time()),
        })

        ach_defs, ach_mult_map = build_achievement_maps([c["key"] for c in catalog if c.get("tier") in ("early", "core")])
        ach_state = scan_achievements(doc, [c["key"] for c in catalog if c.get("tier") in ("early", "core")], ach_mult_map)
        doc["progress"]["ach_all"] = ach_state["has_all"]
        ach_mult = achievement_multiplier(doc.get("ach") or [], ach_mult_map)

        server_cps = compute_cps(doc["progress"], doc.get("prestige"), catalog, ach_mult, ALL_ACH_BONUS)
        diff = abs(server_cps - cleaned["cps"])
        if server_cps > 0 and diff / server_cps > 0.05:
            return jsonify({"ok": False, "err": "cps_mismatch", "server": server_cps}), 400

        doc["progress"]["cps"] = server_cps
        doc["progress"]["season_count"] = doc["progress"].get("count", 0.0)
        doc["progress"]["season_cps"] = server_cps
        save_db(db)

    return jsonify({"ok": True, "cps": server_cps})


@app.get("/api/load_progress")
def api_load_progress():
    if not is_authed():
        return jsonify({"ok": False, "err": "not_auth"}), 401

    with lock:
        db = load_db()
        u = session.get("user")
        if not u or u not in db.get("users", {}):
            return jsonify({"ok": True, "progress": empty_progress()})
        doc = db["users"][u]
        doc.setdefault("prestige", empty_prestige())
        doc["progress"] = normalize_progress(doc.get("progress"))
        catalog = load_catalog(db)
        core_keys = [c["key"] for c in catalog if c.get("tier") in ("early", "core")]
        ach_defs, ach_mult_map = build_achievement_maps(core_keys)
        ach_state = scan_achievements(doc, core_keys, ach_mult_map)
        doc["progress"]["ach_all"] = ach_state["has_all"]
        ach_mult = achievement_multiplier(doc.get("ach") or [], ach_mult_map)
        doc["progress"]["cps"] = compute_cps(doc["progress"], doc.get("prestige"), catalog, ach_mult, ALL_ACH_BONUS)

        awarded_dt, full_dt = apply_offline_progress(doc["progress"], doc.get("prestige"))
        offline_award = 0.0
        if awarded_dt > 0:
            offline_award = doc["progress"]["cps"] * awarded_dt
            doc["progress"]["count"] += offline_award

        quest_state = assign_quests(doc["progress"], catalog)
        save_db(db)

    return jsonify({
        "ok": True,
        "progress": doc["progress"],
        "prestige": doc.get("prestige"),
        "achievements": {
            "defs": ach_defs,
            "unlocked": doc.get("ach", []),
            "count": ach_state["count"],
            "total": ach_state["total"],
            "mult": ach_mult,
            "all": ach_state["has_all"],
            "all_bonus": ALL_ACH_BONUS,
            "boosts": ACHIEVEMENT_BOOSTS,
            "spent": (doc.get("prestige") or {}).get("ach_spend", {}),
        },
        "offline": {"awarded": awarded_dt, "elapsed": full_dt, "amount": offline_award},
        "quests": quest_state,
    })


@app.get("/api/achievements")
def api_get_achievements():
    if not is_authed():
        return jsonify({"ok": False, "err": "not_auth"}), 401
    with lock:
        db = load_db()
        u = session.get("user")
        user = (db.get("users") or {}).get(u) or {}
        user.setdefault("progress", empty_progress())
        catalog = load_catalog(db)
        core_keys = [c["key"] for c in catalog if c.get("tier") in ("early", "core")]
        ach_defs, ach_mult_map = build_achievement_maps(core_keys)
        state = scan_achievements(user, core_keys, ach_mult_map)
        mult = achievement_multiplier(user.get("ach") or [], ach_mult_map)
        save_db(db)
    return jsonify({
        "ok": True,
        "defs": ach_defs,
        "unlocked": user.get("ach", []),
        "count": state["count"],
        "total": state["total"],
        "mult": mult,
        "all": state["has_all"],
        "all_bonus": ALL_ACH_BONUS,
        "boosts": ACHIEVEMENT_BOOSTS,
        "spent": (user.get("prestige") or {}).get("ach_spend", {}),
    })


@app.post("/api/achievements/spend")
@csrf_protected
def api_spend_achievements():
    if not is_authed():
        return jsonify({"ok": False, "err": "not_auth"}), 401
    data = request.get_json(silent=True) or {}
    key = str(data.get("key") or "")
    with lock:
        db = load_db()
        u = session.get("user")
        doc = (db.get("users") or {}).get(u)
        if not doc:
            return jsonify({"ok": False, "err": "user_missing"}), 400
        doc.setdefault("prestige", empty_prestige())
        spent = doc["prestige"].setdefault("ach_spend", {})
        ach_count = len(doc.get("ach") or [])
        spent_total = sum(int(v or 0) for v in spent.values())
        available = max(0, ach_count - spent_total)
        boost = next((b for b in ACHIEVEMENT_BOOSTS if b["key"] == key), None)
        if not boost:
            return jsonify({"ok": False, "err": "bad_key"}), 400
        current = int(spent.get(key) or 0)
        if current >= boost["max"]:
            return jsonify({"ok": False, "err": "maxed"}), 400
        if available < boost["cost"]:
            return jsonify({"ok": False, "err": "no_points"}), 400
        spent[key] = current + 1
        save_db(db)
    return jsonify({"ok": True, "spent": spent})


@app.post("/api/daily_reward")
@csrf_protected
def api_daily_reward():
    if not is_authed():
        return jsonify({"ok": False, "err": "not_auth"}), 401
    with lock:
        db = load_db()
        u = session.get("user")
        doc = (db.get("users") or {}).get(u)
        if not doc:
            return jsonify({"ok": False, "err": "user_missing"}), 400
        doc.setdefault("prestige", empty_prestige())
        doc["progress"] = normalize_progress(doc.get("progress"))
        available, daily = daily_reward(doc["progress"], doc.get("prestige"))
        if not available:
            return jsonify({"ok": False, "err": "too_soon", "daily": daily}), 400
        reward = daily_reward_amount(doc["progress"].get("cps", 0.0), doc.get("prestige"), daily.get("streak") or 1)
        doc["progress"]["count"] += reward
        save_db(db)
    return jsonify({"ok": True, "reward": reward, "daily": daily})


@app.get("/api/quests")
def api_quests():
    if not is_authed():
        return jsonify({"ok": False, "err": "not_auth"}), 401
    with lock:
        db = load_db()
        u = session.get("user")
        doc = (db.get("users") or {}).get(u)
        if not doc:
            return jsonify({"ok": False, "err": "user_missing"}), 400
        catalog = load_catalog(db)
        doc["progress"] = normalize_progress(doc.get("progress"))
        quest_state = assign_quests(doc["progress"], catalog)
        save_db(db)

    quests = []
    for q in quest_state.get("list", []):
        progress, target = quest_progress(doc["progress"], doc.get("prestige") or {}, q)
        quests.append({
            **q,
            "progress": progress,
            "target": target,
            "claimed": q.get("key") in (quest_state.get("claims") or []),
        })
    return jsonify({"ok": True, "quests": quests, "assigned": quest_state.get("assigned")})


@app.post("/api/quests/claim")
@csrf_protected
def api_claim_quest():
    if not is_authed():
        return jsonify({"ok": False, "err": "not_auth"}), 401
    data = request.get_json(silent=True) or {}
    key = data.get("key")
    with lock:
        db = load_db()
        u = session.get("user")
        doc = (db.get("users") or {}).get(u)
        if not doc:
            return jsonify({"ok": False, "err": "user_missing"}), 400
        catalog = load_catalog(db)
        doc["progress"] = normalize_progress(doc.get("progress"))
        quest_state = assign_quests(doc["progress"], catalog)
        claims = quest_state.setdefault("claims", [])
        quest = next((q for q in quest_state.get("list", []) if q.get("key") == key), None)
        if not quest:
            return jsonify({"ok": False, "err": "bad_key"}), 400
        if key in claims:
            return jsonify({"ok": False, "err": "claimed"}), 400
        progress, target = quest_progress(doc["progress"], doc.get("prestige") or {}, quest)
        if progress < target:
            return jsonify({"ok": False, "err": "incomplete"}), 400
        reward = quest_reward_amount(float(quest.get("reward") or 0), doc.get("prestige") or {})
        doc["progress"]["count"] += reward
        claims.append(key)
        save_db(db)
    return jsonify({"ok": True, "reward": reward, "claims": claims})


@app.post("/api/boost")
@csrf_protected
def api_roll_boost():
    if not is_authed():
        return jsonify({"ok": False, "err": "not_auth"}), 401
    with lock:
        db = load_db()
        u = session.get("user")
        doc = (db.get("users") or {}).get(u)
        if not doc:
            return jsonify({"ok": False, "err": "user_missing"}), 400
        doc["progress"] = normalize_progress(doc.get("progress"))
        boost = doc["progress"].setdefault("boost", {"mult": 1.0, "until": None, "last_roll": None})
        now = time.time()
        last_roll = boost.get("last_roll")
        if last_roll and now - float(last_roll) < 180:
            return jsonify({"ok": True, "boost": boost, "rolled": False})
        boost["last_roll"] = now
        if random.random() < 0.15:
            boost["mult"] = random.choice([1.25, 1.5, 2.0])
            boost["until"] = now + random.choice([120, 180, 300])
        save_db(db)
    return jsonify({"ok": True, "boost": boost, "rolled": True})


@app.get("/api/prestige")
def api_get_prestige():
    if not is_authed():
        return jsonify({"ok": False, "err": "not_auth"}), 401
    with lock:
        db = load_db()
        u = session.get("user")
        if not u or u not in db["users"]:
            return jsonify({"ok": False, "err": "user_missing"}), 400
        p = db["users"][u].get("prestige") or empty_prestige()
    return jsonify({"ok": True, "prestige": p, "upgrades": PRESTIGE_UPGRADES, "tree": PRESTIGE_TREE})


@app.post("/api/buy_prestige_upgrade")
@csrf_protected
def api_buy_prestige_upgrade():
    if not is_authed():
        return jsonify({"ok": False, "err": "not_auth"}), 401
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip()
    if not key:
        return jsonify({"ok": False, "err": "missing_key"}), 400

    with lock:
        db = load_db()
        u = session.get("user")
        if not u or u not in db["users"]:
            return jsonify({"ok": False, "err": "user_missing"}), 400
        doc = db["users"][u]
        prest = doc.get("prestige") or empty_prestige()
        up = prest.get("up") or {}

        defn = next((d for d in PRESTIGE_UPGRADES if d["key"] == key), None)
        if not defn:
            return jsonify({"ok": False, "err": "bad_key"}), 400

        cur = int(up.get(key, 0))
        if cur >= defn["max"]:
            return jsonify({"ok": False, "err": "maxed"}), 400

        cost = prestige_cost(key, cur + 1)
        if prest.get("tryz", 0) < cost:
            return jsonify({"ok": False, "err": "no_funds", "need": cost}), 400

        prest["tryz"] -= cost
        up[key] = cur + 1
        prest["up"] = up
        doc["prestige"] = prest
        save_db(db)

    return jsonify({"ok": True, "prestige": prest, "cost": cost, "level": up[key]})


@app.post("/api/buy_prestige_tree")
@csrf_protected
def api_buy_prestige_tree():
    if not is_authed():
        return jsonify({"ok": False, "err": "not_auth"}), 401
    data = request.get_json(silent=True) or {}
    key = str(data.get("key") or "")
    with lock:
        db = load_db()
        u = session.get("user")
        doc = (db.get("users") or {}).get(u)
        if not doc:
            return jsonify({"ok": False, "err": "user_missing"}), 400
        doc.setdefault("prestige", empty_prestige())
        prest = doc["prestige"]
        tree = prest.setdefault("tree", [])
        node = next((n for n in PRESTIGE_TREE if n["key"] == key), None)
        if not node:
            return jsonify({"ok": False, "err": "bad_key"}), 400
        if key in tree:
            return jsonify({"ok": False, "err": "owned"}), 400
        if any(req not in tree for req in node.get("requires", [])):
            return jsonify({"ok": False, "err": "locked"}), 400
        cost = int(node.get("cost") or 0)
        if prest.get("tryz", 0) < cost:
            return jsonify({"ok": False, "err": "no_funds"}), 400
        prest["tryz"] -= cost
        tree.append(key)
        prest["tree"] = tree
        save_db(db)
    return jsonify({"ok": True, "prestige": prest})


@app.post("/api/sell_prestige_upgrade")
@csrf_protected
def api_sell_prestige_upgrade():
    if not is_authed():
        return jsonify({"ok": False, "err": "not_auth"}), 401

    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip()
    if not key:
        return jsonify({"ok": False, "err": "missing_key"}), 400

    with lock:
        db = load_db()
        u = session.get("user")
        if not u or u not in db["users"]:
            return jsonify({"ok": False, "err": "user_missing"}), 400

        doc = db["users"][u]
        prest = doc.get("prestige") or empty_prestige()
        up = prest.get("up") or {}

        defn = next((d for d in PRESTIGE_UPGRADES if d["key"] == key), None)
        if not defn:
            return jsonify({"ok": False, "err": "bad_key"}), 400

        cur = int(up.get(key, 0))
        if cur <= 0:
            return jsonify({"ok": False, "err": "no_level"}), 400

        total_spent = sum(prestige_cost(key, i) for i in range(1, cur + 1))
        refund = int(total_spent * 0.50)

        prest["tryz"] = int(prest.get("tryz", 0)) + refund
        up[key] = cur - 1
        prest["up"] = up
        doc["prestige"] = prest
        save_db(db)

    return jsonify({"ok": True, "prestige": prest, "refund": refund, "level": up[key]})


@app.post("/api/ascend")
@csrf_protected
def api_ascend():
    if not is_authed():
        return jsonify({"ok": False, "err": "not_auth"}), 401
    with lock:
        db = load_db()
        u = session.get("user")
        if not u or u not in db["users"]:
            return jsonify({"ok": False, "err": "user_missing"}), 400

        doc = db["users"][u]
        doc["progress"] = normalize_progress(doc.get("progress"))
        cps_now = float(doc["progress"].get("cps") or 0.0)
        prest = doc.get("prestige") or empty_prestige()
        award = int((cps_now / 1_000_000) * asc_mult(prest))
        if award <= 0:
            return jsonify({"ok": False, "err": "too_low", "need": 1_000_000}), 400

        prest["tryz"] = int(prest.get("tryz", 0)) + award
        prest["asc"] = int(prest.get("asc", 0)) + 1
        doc["prestige"] = prest

        fresh = empty_progress()
        fresh["saved_at"] = int(time.time())
        fresh["count"] = start_boost(prest)
        doc["progress"] = fresh
        save_db(db)

    return jsonify({"ok": True, "award": award, "prestige": prest, "progress": fresh})


@app.post("/api/click")
@csrf_protected
def api_click():
    if not is_authed():
        return jsonify({"ok": False, "err": "not_auth"}), 401
    data = request.get_json(silent=True) or {}
    clicks = int(data.get("clicks") or 1)
    clicks = max(1, min(clicks, 25))
    with lock:
        db = load_db()
        u = session.get("user")
        doc = (db.get("users") or {}).get(u)
        if not doc:
            return jsonify({"ok": False, "err": "user_missing"}), 400
        doc["progress"] = normalize_progress(doc.get("progress"))
        doc.setdefault("prestige", empty_prestige())
        catalog = load_catalog(db)
        core_keys = [c["key"] for c in catalog if c.get("tier") in ("early", "core")]
        ach_defs, ach_mult_map = build_achievement_maps(core_keys)
        scan_achievements(doc, core_keys, ach_mult_map)
        ach_mult = achievement_multiplier(doc.get("ach") or [], ach_mult_map)
        doc["progress"]["cps"] = compute_cps(doc["progress"], doc.get("prestige"), catalog, ach_mult, ALL_ACH_BONUS)
        power = compute_click_power(doc["progress"]["cps"], doc.get("prestige"))
        crit = crit_chance(doc.get("prestige"))
        total_gain = 0.0
        for _ in range(clicks):
            gain = power
            if random.random() < crit:
                gain *= 3
            total_gain += gain
        doc["progress"]["count"] += total_gain
        save_db(db)
    return jsonify({"ok": True, "gain": total_gain})


@app.get("/api/leaderboard")
def api_leaderboard():
    with lock:
        db = load_db()
        update_season(db.get("settings"), db.get("users"))
        users = db.get("users", {}) or {}
        rows = []
        season_rows = []
        for name, doc in users.items():
            prog = (doc or {}).get("progress") or {}
            rows.append({"user": str(name), "count": float(prog.get("count") or 0), "cps": float(prog.get("cps") or 0)})
            season_rows.append({"user": str(name), "count": float(prog.get("season_count") or 0), "cps": float(prog.get("season_cps") or 0)})
        top_count = sorted(rows, key=lambda x: x["count"], reverse=True)[:50]
        top_cps = sorted(rows, key=lambda x: x["cps"], reverse=True)[:50]
        top_season_count = sorted(season_rows, key=lambda x: x["count"], reverse=True)[:50]
        top_season_cps = sorted(season_rows, key=lambda x: x["cps"], reverse=True)[:50]
        season = (db.get("settings") or {}).get("season") or {}
        history = (db.get("settings") or {}).get("season_history") or []
        save_db(db)
    return jsonify({
        "ok": True,
        "top_count": top_count,
        "top_cps": top_cps,
        "season": season,
        "season_top_count": top_season_count,
        "season_top_cps": top_season_cps,
        "season_history": history[-3:],
    })


@app.get("/api/profile")
def api_profile():
    target = (request.args.get("u") or "").strip()
    with lock:
        db = load_db()
        if not target:
            target = session.get("user")
        users = db.get("users", {}) or {}
        if not target or target not in users:
            return jsonify({"ok": False, "err": "not_found"}), 404
        doc = users[target]
        doc.setdefault("progress", empty_progress())
        doc.setdefault("prestige", empty_prestige())
        catalog = load_catalog(db)
        core_keys = [c["key"] for c in catalog if c.get("tier") in ("early", "core")]
        ach_defs, ach_mult_map = build_achievement_maps(core_keys)
        state = scan_achievements(doc, core_keys, ach_mult_map)
        ach_map = {d["id"]: d for d in ach_defs}
        ach_list = [{
            "id": aid,
            "name": ach_map.get(aid, {"name": aid}).get("name"),
            "group": ach_map.get(aid, {}).get("group", ""),
            "category": ach_map.get(aid, {}).get("category", ""),
            "mult": float(ach_map.get(aid, {}).get("mult", BASE_ACH_MULT)),
        } for aid in (doc.get("ach") or [])[:200]]

        inventory = doc["progress"].get("inventory") or {}
        top_units = sorted(inventory.items(), key=lambda x: x[1], reverse=True)[:5]
        top_units = [{
            "key": k,
            "lvl": v,
            "name": next((c.get("name") for c in catalog if c.get("key") == k), k),
        } for k, v in top_units]

        profile = doc.get("profile") or {}
        prof = {
            "exists": isinstance(profile, dict),
            "user": target,
            "bio": profile.get("bio", "")[:280] if isinstance(profile, dict) else "",
            "count": float(doc["progress"].get("count") or 0.0),
            "cps": float(doc["progress"].get("cps") or 0.0),
            "tryz": int(doc["prestige"].get("tryz") or 0),
            "asc": int(doc["prestige"].get("asc") or 0),
            "ach_count": state["count"],
            "ach_total": state["total"],
            "ach_mult": achievement_multiplier(doc.get("ach") or [], ach_mult_map),
            "ach": ach_list,
            "top_units": top_units,
            "prestige_tree": doc["prestige"].get("tree", []),
        }
        save_db(db)
        return jsonify({"ok": True, "profile": prof, "self": (session.get("user") == target)})


@app.post("/api/profile_create")
@csrf_protected
def api_profile_create():
    if not is_authed():
        return jsonify({"ok": False, "err": "not_auth"}), 401
    with lock:
        db = load_db()
        u = session.get("user")
        users = db.get("users", {}) or {}
        if not u or u not in users:
            return jsonify({"ok": False, "err": "user_missing"}), 400
        doc = users[u]
        if not isinstance(doc.get("profile"), dict):
            doc["profile"] = {"bio": ""}
            save_db(db)
            return jsonify({"ok": True, "created": True})
        return jsonify({"ok": True, "created": False})


@app.post("/api/profile_settings")
@csrf_protected
def api_profile_settings():
    if not is_authed():
        return jsonify({"ok": False, "err": "not_auth"}), 401
    data = request.get_json(silent=True) or {}
    bio = str(data.get("bio") or "").strip()[:280]
    with lock:
        db = load_db()
        u = session.get("user")
        users = db.get("users", {}) or {}
        if not u or u not in users:
            return jsonify({"ok": False, "err": "user_missing"}), 400
        doc = users[u]
        if not isinstance(doc.get("profile"), dict):
            return jsonify({"ok": False, "err": "no_profile"}), 400
        doc["profile"]["bio"] = bio
        save_db(db)
    return jsonify({"ok": True, "bio": bio})


@app.get("/api/reviews")
def api_reviews_list():
    with lock:
        db = load_db()
        items = list(reversed(db.get("reviews", [])))[:100]
    return jsonify({"ok": True, "reviews": items})


@app.get("/api/reviews/summary")
def api_reviews_summary():
    with lock:
        db = load_db()
        arr = db.get("reviews", [])
        n = len(arr)
        s = sum(x.get("stars", 0) for x in arr)
    avg = (s / n) if n else 0.0
    return jsonify({"ok": True, "count": n, "sum": s, "avg": round(avg, 2)})


def _sanitize_review(r):
    u = str(r.get("u") or "").strip()[:40]
    stars = int(r.get("stars") or 0)
    stars = max(1, min(5, stars))
    text = str(r.get("text") or "").strip()[:800]
    return {"u": u or "Anonymous", "stars": stars, "text": text, "ts": int(time.time())}


@app.post("/api/reviews")
@csrf_protected
def api_reviews_add():
    if not rate_limit("reviews"):
        return jsonify({"ok": False, "err": "rate"}), 429
    data = request.get_json(silent=True) or {}
    try:
        stars = int(data.get("stars", 0))
    except Exception:
        stars = 0
    text = (data.get("text") or "").strip()
    if stars < 1 or stars > 5:
        return jsonify({"ok": False, "err": "stars_1_5"}), 400
    if not text:
        return jsonify({"ok": False, "err": "empty_text"}), 400

    with lock:
        db = load_db()
        u = session.get("user") or "Guest"
        doc = _sanitize_review({"u": u, "stars": stars, "text": text})
        db.setdefault("reviews", []).append(doc)
        db["reviews"] = db["reviews"][-1000:]
        save_db(db)
    return jsonify({"ok": True, "review": doc})


@app.post("/api/reviews/report")
@csrf_protected
def api_reviews_report():
    if not rate_limit("review_report"):
        return jsonify({"ok": False, "err": "rate"}), 429
    data = request.get_json(silent=True) or {}
    ts = int(data.get("ts") or 0)
    reason = str(data.get("reason") or "").strip()[:300]
    if not ts:
        return jsonify({"ok": False, "err": "bad_ts"}), 400
    with lock:
        db = load_db()
        db.setdefault("review_reports", []).append({
            "ts": ts,
            "reason": reason,
            "by": session.get("user") or "Guest",
            "at": int(time.time()),
        })
        db["review_reports"] = db["review_reports"][-500:]
        save_db(db)
    return jsonify({"ok": True})


@app.get("/api/update")
def api_get_update():
    with lock:
        db = load_db()
        txt = (db.get("settings", {}) or {}).get("update", "") or ""
    return jsonify({"ok": True, "update": txt})


@app.post("/admin/set_update")
@admin_required
@csrf_protected
def admin_set_update():
    txt = (request.form.get("update") or "").strip()[:5000]
    with lock:
        db = load_db()
        db.setdefault("settings", {}).setdefault("update", "")
        db["settings"]["update"] = txt
        save_db(db)
    return redirect("/admin")


@app.post("/admin/reset_pw")
@admin_required
@csrf_protected
def admin_reset_pw():
    u = request.form.get("u", "")
    p = request.form.get("p", "")
    if not u or not p:
        return "Bad", 400
    with lock:
        db = load_db()
        if u not in db["users"]:
            return "No user", 404
        db["users"][u]["pw"] = generate_password_hash(p)
        save_db(db)
    return redirect("/admin")


@app.post("/admin/add")
@admin_required
@csrf_protected
def admin_add():
    u = request.form.get("u", "")
    n = request.form.get("n", "0")
    try:
        n = float(n)
    except Exception:
        n = 0
    with lock:
        db = load_db()
        doc = db["users"].get(u)
        if not doc:
            return redirect("/admin")
        doc.setdefault("progress", empty_progress())
        doc["progress"]["count"] = float(doc["progress"].get("count", 0)) + n
        save_db(db)
    return redirect("/admin")


@app.post("/admin/sub")
@admin_required
@csrf_protected
def admin_sub():
    u = request.form.get("u", "")
    n = request.form.get("n", "0")
    try:
        n = float(n)
    except Exception:
        n = 0
    with lock:
        db = load_db()
        doc = db["users"].get(u)
        if not doc:
            return redirect("/admin")
        doc.setdefault("progress", empty_progress())
        doc["progress"]["count"] = float(doc["progress"].get("count", 0)) - n
        save_db(db)
    return redirect("/admin")


@app.post("/admin/delete")
@admin_required
@csrf_protected
def admin_delete():
    u = request.form.get("u", "")
    with lock:
        db = load_db()
        if u in db["users"]:
            del db["users"][u]
            save_db(db)
    return redirect("/admin")


@app.post("/admin/upload")
@admin_required
@csrf_protected
def admin_upload():
    t = request.args.get("type", "")
    if t not in {"bg", "logo"}:
        return "Bad type", 400
    f = request.files.get("file")
    path, err = _save_upload(f)
    if err:
        return f"Upload error: {err}", 400
    with lock:
        db = load_db()
        db.setdefault("settings", {"bg": None, "logo": None})
        db["settings"][t] = path
        save_db(db)
    return redirect("/admin")


@app.get("/admin/clear_asset")
@admin_required
def admin_clear_asset():
    t = request.args.get("type", "")
    if t not in {"bg", "logo"}:
        return "Bad type", 400
    with lock:
        db = load_db()
        db.setdefault("settings", {"bg": None, "logo": None})
        db["settings"][t] = None
        save_db(db)
    return redirect("/admin")


BOT_NAMES = [
    "jaime les fucks",
    "NEGRO",
    "67",
    "couilles",
    "bitesenplastic",
    "Paulitodu64",
    "autiste tom",
    "seus",
    "Z3r0x",
    "ValouTV",
    "ta mere la pute",
    "lingam lugigig",
    "MC_Dojo",
    "NoScopeNico",
    "LeFromagedesnoirs",
    "snap: hector227",
    "AnanasSurPizza",
    "LeRatDuMetro",
    "BZH_Bot",
    "autsitemax",
    "niq ta mere alex",
    "le numero de tel de adrian: 06 52 03 45 03",
    "envoye c jeux a ma crush",
    "negro tout noir",
    "putes d'alex",
    "ChipsSaveurSel",
]

FAKE_REVIEW_LINES_FR = [
    "jai 30t autiste par second, comme dans ma cave",
    "guez",
    "Meilleur jeux de tout les temps, STP ajouter plus de trucs j'ai presque finis le jeu.",
    "Des bugs mais ça passe.",
    "Toute notre classe joue a ca en cours mdr, jai poste un tiktok, il a 12k vues",
    "caca prout gnt !",
    "J’ai reset par erreur… pls help :)",
    "Le prestige est satisfaisant.",
    "trop mal fait aprends a coder stp",
    "FAIT PLUS DE MISE A JOUER JE SUIS ADDICTE TA MERE LA PUTE MICHAEL",
]

FAKE_REVIEW_LINES_EN = [
    "Surprisingly ass ",
    "ass game, funny tho.",
    "I love niggers!",
    "YT: editxs_shorts",
    "Came from Jonsmans discord profile, im fearless on dc",
    "Where did u fall off jonsman",
    "playing this in class, peak.",
    "Mid",
]


def _rand_username():
    return random.choice(BOT_NAMES) + (str(random.randint(1, 999)) if random.random() < 0.4 else "")


def _fake_progress():
    cps = max(0.0, round(random.expovariate(1 / 2_000_000) * 1_000_000_000_000_000_000_000_000_000, 2))
    count = max(cps * random.uniform(50, 300), random.uniform(1e3, 1e56))
    return {
        "v": 5,
        "count": float(count),
        "cps": float(cps),
        "inventory": {},
        "custom_units": [],
        "saved_at": int(time.time()),
    }


def _fake_review(user):
    stars = random.choices([5, 4, 3, 2, 1], weights=[45, 25, 15, 10, 5], k=1)[0]
    text = random.choice(FAKE_REVIEW_LINES_FR + FAKE_REVIEW_LINES_EN)
    if random.random() < 0.25:
        text += " ⭐"
    return {"u": user[:40] or "Anonymous", "stars": int(stars), "text": text[:800], "ts": int(time.time())}


def seed_bots(n=25, overwrite_existing=False, max_total=200):
    with lock:
        db = load_db()
        users = db.setdefault("users", {})
        created = 0
        if len(users) >= max_total:
            return 0

        for _ in range(n):
            name = _rand_username()
            if (name in users) and not overwrite_existing:
                continue
            users[name] = {
                "pw": generate_password_hash(secrets.token_hex(8)),
                "progress": _fake_progress(),
                "prestige": empty_prestige(),
                "bot": True,
                "bot_tick": int(time.time()),
            }

            created += 1
            if len(users) >= max_total:
                break

        save_db(db)
        return created


def seed_fake_reviews(m=40):
    with lock:
        db = load_db()
        users = list((db.get("users") or {}).keys())
        if not users:
            users = [_rand_username() for _ in range(10)]

        db.setdefault("reviews", [])
        for _ in range(m):
            author = random.choice(users) if random.random() < 0.7 else _rand_username()
            db["reviews"].append(_fake_review(author))

        db["reviews"] = db["reviews"][-1000:]
        save_db(db)
        return m


@app.post("/admin/seed_bots")
@admin_required
@csrf_protected
def admin_seed_bots():
    try:
        n = int(request.form.get("n", "25"))
        overwrite = request.form.get("overwrite") == "1"
    except Exception:
        n = 25
        overwrite = False
    made = seed_bots(n=n, overwrite_existing=overwrite)
    return jsonify({"ok": True, "created": made})


@app.post("/admin/seed_reviews")
@admin_required
@csrf_protected
def admin_seed_reviews():
    try:
        m = int(request.form.get("m", "40"))
    except Exception:
        m = 40
    made = seed_fake_reviews(m=m)
    return jsonify({"ok": True, "created": made})


@app.post("/admin/delete_review")
@admin_required
@csrf_protected
def admin_delete_review():
    try:
        ts = int(request.form.get("ts", "0"))
    except Exception:
        return "Bad timestamp", 400

    with lock:
        db = load_db()
        reviews = db.get("reviews", [])
        before = len(reviews)
        reviews = [r for r in reviews if int(r.get("ts", 0)) != ts]
        db["reviews"] = reviews[-1000:]
        save_db(db)
        after = len(reviews)

    return jsonify({"ok": True, "deleted": before - after})


@app.post("/api/update_shop")
@admin_required
@csrf_protected
def api_update_shop():
    data = request.get_json(silent=True) or {}
    if "shop" not in data:
        return jsonify({"ok": False, "err": "Missing shop data"}), 400
    with lock:
        db = load_db()
        db.setdefault("settings", {})["shop"] = data["shop"]
        save_db(db)
    return jsonify({"ok": True})


@app.get("/api/load_shop")
def api_load_shop():
    with lock:
        db = load_db()
        shop = (db.get("settings", {}) or {}).get("shop") or []
    return jsonify({"ok": True, "shop": shop})


@app.get("/<path:_>")
def any_route(_):
    return redirect("/")


if __name__ == "__main__":
    with lock:
        db = load_db()
        users = db.setdefault("users", {})
        if not users:
            for _ in range(15):
                name = _rand_username()
                users[name] = {
                    "pw": generate_password_hash(secrets.token_hex(8)),
                    "progress": _fake_progress(),
                    "prestige": empty_prestige(),
                    "bot": True,
                    "bot_tick": int(time.time()),
                }
        save_db(db)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
