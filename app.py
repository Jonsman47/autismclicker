# app.py — full stack clicker (auth, admin, uploads, shop, sell, leaderboard) — NO UPGRADES
from flask import Flask, request, redirect, session, jsonify, send_from_directory, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os, json, threading, secrets, time, shutil

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
# optional, but nice defaults for browser cookies
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,   # set True if your in https only:
)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, os.environ.get("DB_PATH", "db.json"))
_upload_root = os.environ.get("UPLOAD_DIR", "uploads")
if os.path.isabs(_upload_root):
    UPLOAD_DIR = _upload_root
else:
    UPLOAD_DIR = os.path.join(BASE_DIR, _upload_root)
os.makedirs(UPLOAD_DIR, exist_ok=True)

lock = threading.Lock()
ADMIN_USERNAME = "Jonsman47".lower()
ALLOWED_EXT = {"png","jpg","jpeg","webp","gif","svg"}

# ---------- tiny JSON "DB" ----------
def _empty_db():
    return {
        "users": {},
        "settings": {"bg": None, "logo": None, "update": ""},  # + update note
        "reviews": []  # [{u, stars, text, ts}]
    }


def load_db():
    if not os.path.exists(DB_PATH):
        return _empty_db()
    try:
        with open(DB_PATH, "r", encoding="utf-8") as f:
            db = json.load(f)
    except Exception:
        # keep the bad file for inspection instead of silently wiping it
        bak = DB_PATH + ".bak"
        if os.path.exists(bak):
            try:
                with open(bak, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        bad = DB_PATH + ".bad"
        try: os.replace(DB_PATH, bad)
        except Exception: pass
        return _empty_db()

    db.setdefault("settings", {"bg": None, "logo": None})
    db.setdefault("users", {})
    db.setdefault("reviews", [])
    db.setdefault("settings", {}).setdefault("update", "")
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
    os.replace(tmp, DB_PATH)  # atomic on POSIX

def _tick_bots(db, rate_per_hour=0.001):
    """
    +0.10%/h composés sur progress['count'] pour les comptes marqués bot.
    Nécessite doc['bot']=True et doc['bot_tick']=timestamp.
    """
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



def is_authed(): return bool(session.get("user"))
def is_admin():  return session.get("user","").lower() == ADMIN_USERNAME

# ---------- i18n ----------
LANGS = ["en","fr"]
STR = {
  "en":{
    "title_home":"Autists Counter",
    "goto_clicker":"→ Go to Autists Clicker",
    "account":"Account",
    "logged_in_as":"Logged in as",
    "not_logged_in":"Not logged in",
    "register":"Register",
    "login":"Login",
    "logout":"Logout",
    "lang":"Language",
    "change_en":"Change to English",
    "change_fr":"Passer en français",
    "home":"Home",
    "profile":"Profile",
    "leaderboard":"Leaderboard",
    "respect":"Respect",
    "username":"Username",
    "password":"Password",
    "save":"Save",
    "home_update_heading":"Public Update Note",
    "home_update_placeholder":"Update 1.2.1:\nBug fixes ...\nAdded Features:",
    "calc":"Calculator",
    "num_a":"Number A",
    "num_b":"Number B (ignored for Square)",
    "op":"Operation",
    "add":"Addition (+)",
    "sub":"Subtraction (−)",
    "mul":"Multiplication (×)",
    "div":"Division (÷)",
    "sqr":"Square (A²)",
    "compute":"Compute",
    "total":"Total autists",
    "tip":"Tip: for A², B is ignored.",
    "admin":"Admin Panel",
    "users":"Users",
    "actions":"Actions",    
    "reset_pw":"Reset password",
    "new_pw":"New password",
    "add_aut":"Add autists",
    "sub_aut":"Remove autists",
    "delete":"Delete user",
    "assets":"Game Assets",
    "bg":"Background image",
    "logo":"Game logo",
    "upload":"Upload",
    "clear":"Clear",
  },
  "fr":{
    "title_home":"Compteur d’autistes",
    "goto_clicker":"→ Aller au jeu Autists Clicker",
    "account":"Compte",
    "logged_in_as":"Connecté en tant que",
    "not_logged_in":"Non connecté",
    "register":"Créer un compte",
    "login":"Se connecter",
    "logout":"Se déconnecter",
    "lang":"Langue",
    "change_en":"Change in English",
    "change_fr":"Changer en Français",
    "home":"Accueil",
    "profile":"Profil",
    "leaderboard":"Classement",
    "respect":"Respect",
    "username":"Nom d’utilisateur",
    "password":"Mot de passe",
    "save":"Enregistrer",
    "home_update_heading":"Note de mise à jour publique",
    "home_update_placeholder":"Mise à jour 1.2.1:\nCorrections de bugs ...\nNouvelles fonctionnalités :",
    "calc":"Calculatrice",
    "num_a":"Nombre A",
    "num_b":"Nombre B (inutile pour Carré)",
    "op":"Opération",
    "add":"Addition (+)",
    "sub":"Soustraction (−)",
    "mul":"Multiplication (×)",
    "div":"Division (÷)",
    "sqr":"Carré (A²)",
    "compute":"Calculer",
    "total":"Total d’autistes",
    "tip":"Astuce : pour A², B est ignoré.",
    "admin":"Panneau Admin",
    "users":"Comptes",
    "actions":"Actions",
    "reset_pw":"Réinitialiser mot de passe",
    "new_pw":"Nouveau mot de passe",
    "add_aut":"Ajouter des autistes",
    "sub_aut":"Enlever des autistes",
    "delete":"Supprimer le compte",
    "assets":"Assets du jeu",
    "bg":"Image de fond",
    "logo":"Logo du jeu",
    "upload":"Uploader",
    "clear":"Retirer",
  }
}

def get_lang():
    lang = session.get("lang") or request.args.get("lang") or "en"
    if lang not in LANGS:
        lang = "en"
    session["lang"] = lang
    return lang

def T(key, lang=None):
    lang = lang or get_lang()
    pack = STR.get(lang)
    if not pack:
        pack = STR["en"]
    return pack.get(key, STR["en"].get(key, key))

def compact(n):
    try:
        n = float(n)
    except:
        return str(n)
    # short scale jusqu’à 1e33
    # short scale up to 1e75 (then fallback to scientific)
    scales = [
        (1e75, "qavg"),  # quattuorvigintillion
        (1e72, "tvg"),   # tresvigintillion
        (1e69, "dvg"),   # duovigintillion
        (1e66, "uvg"),   # unvigintillion
        (1e63, "vg"),    # vigintillion
        (1e60, "nd"),    # novemdecillion
        (1e57, "od"),    # octodecillion
        (1e54, "spd"),   # septendecillion
        (1e51, "sxd"),   # sexdecillion
        (1e48, "qid"),   # quindecillion
        (1e45, "qad"),   # quattuordecillion
        (1e42, "td"),    # tredecillion
        (1e39, "dd"),    # duodecillion
        (1e36, "ud"),    # undecillion
        (1e33, "de"),    # decillion
        (1e30, "no"),    # nonillion
        (1e27, "oc"),    # octillion
        (1e24, "sp"),    # septillion
        (1e21, "sx"),    # sextillion
        (1e18, "qi"),    # quintillion
        (1e15, "qa"),    # quadrillion
        (1e12, "t"),     # trillion
        (1e9,  "b"),     # billion
        (1e6,  "m"),     # million
        (1e3,  "k"),     # thousand
    ]

    for div, suf in scales:
        if abs(n) >= div:
            val = n / div
            # keep up to 2 decimals but remove useless zeros and dot
            s = f"{val:.2f}".rstrip("0").rstrip(".")
            return f"{s}{suf}"

    # scientific fallback for ultra-large values
    if abs(n) >= 1e6:
        s = f"{n:.2e}".replace("e+0", "e").replace("e+", "e")
        return s

    try:
        s = str(int(n)) if float(n).is_integer() else str(round(n, 2))
    except:
        s = str(n)
    return s


# ---------- Auth ----------
@app.get("/register")
def register_form():
    return f"""<!doctype html><meta charset="utf-8"><title>{T('register')}</title>
    <style>
      :root {{
        --bg:#07070a; --panel:#0e0e14; --border:#2b2b38; --txt:#e7e7f5;
        --violet:#7c3aed; --violet2:#a78bfa; --red:#ef4444; --muted:#a3a3b2;
      }}
      *{{box-sizing:border-box}} body{{font-family:Inter,Arial;margin:0;background:radial-gradient(1200px 600px at 20% -10%, rgba(124,58,237,.25), transparent 60%), #000;color:var(--txt)}}
      .wrap{{max-width:960px;margin:48px auto;padding:0 16px}}
      .card{{background:linear-gradient(180deg,#0e0e14,#0b0b10);border:1px solid var(--border);border-radius:20px;padding:22px;box-shadow:0 0 40px rgba(124,58,237,.08)}}
      .btn, input, button{{border-radius:12px;border:1px solid var(--border);padding:12px 14px;background:#12121a;color:var(--txt)}}
      .btn.violet, button{{background:linear-gradient(90deg,#7c3aed,#ef4444);border-color:#7c3aed}}
      a.btn{{text-decoration:none;display:inline-block}}
    </style>
    <div class="wrap">
      <div class="card">
        <h2 style="margin-top:0">{T('register')}</h2>
        <form method="post" style="display:grid;gap:12px">
          <label>{T('username')}<br><input name="u" required></label>
          <label>{T('password')}<br><input name="p" type="password" required></label>
          <button class="btn violet">{T('register')}</button>
        </form>
        <p style="margin-top:12px"><a class="btn" href="/">{'← ' + T('home')}</a></p>
      </div>
    </div>"""

@app.post("/register")
def register_post():
    u = (request.form.get("u") or "").strip()
    p = request.form.get("p") or ""
    if not u or not p: return "Invalid", 400
    with lock:
        db = load_db()
        if u in db["users"]: return "Username taken", 400
        db["users"][u] = {
            "pw": generate_password_hash(p),
            "progress": None,
            "prestige": _empty_prestige()
        }
        save_db(db)
    session["user"] = u
    return redirect("/")

@app.get("/login")
def login_form():
    return f"""<!doctype html><meta charset="utf-8"><title>{T('login')}</title>
    <style>
      :root {{ --bg:#07070a; --panel:#0e0e14; --border:#2b2b38; --txt:#e7e7f5; --violet:#7c3aed; --red:#ef4444; }}
      *{{box-sizing:border-box}} body{{font-family:Inter,Arial;margin:0;background:linear-gradient(160deg,rgba(239,68,68,.12),transparent 40%), #000;color:var(--txt)}}
      .wrap{{max-width:960px;margin:48px auto;padding:0 16px}}
      .card{{background:linear-gradient(180deg,#0e0e14,#0b0b10);border:1px solid var(--border);border-radius:20px;padding:22px;box-shadow:0 0 40px rgba(239,68,68,.08)}}
      .btn, input, button{{border-radius:12px;border:1px solid var(--border);padding:12px 14px;background:#12121a;color:var(--txt)}}
      button{{background:linear-gradient(90deg,#ef4444,#7c3aed);border-color:#7c3aed}}
      a.btn{{text-decoration:none;display:inline-block}}
    </style>
    <div class="wrap">
      <div class="card">
        <h2 style="margin-top:0">{T('login')}</h2>
        <form method="post" style="display:grid;gap:12px">
          <label>{T('username')}<br><input name="u" required></label>
          <label>{T('password')}<br><input name="p" type="password" required></label>
          <button>{T('login')}</button>
        </form>
        <p style="margin-top:12px"><a class="btn" href="/">{'← ' + T('home')}</a></p>
      </div>
    </div>"""

@app.post("/login")
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

@app.get("/lang")
def set_lang():
    lang = request.args.get("to", "en")
    if lang not in LANGS:
        lang = "en"
    session["lang"] = lang
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"ok": True, "lang": lang})
    return redirect(request.referrer or "/")

# ---------- Home ----------
@app.route("/", methods=["GET","POST"])
def home():
    get_lang()
    import html
    with lock:
        _db = load_db()
        _tick_bots(_db)  # tick bots à chaque visite de /
    update_txt = (_db.get("settings", {}) or {}).get("update", "")
    a_str = request.form.get("a","")
    b_str = request.form.get("b","")
    op = request.form.get("op","add")
    res = ""

    def parse(x):
        try: return float(x)
        except: return None

    if request.method=="POST":
        a = parse(a_str); b = parse(b_str)
        try:
            if op=="add": res = "" if a is None or b is None else a + b
            elif op=="sub": res = "" if a is None or b is None else a - b
            elif op=="mul": res = "" if a is None or b is None else a * b
            elif op=="div":
                if a is None or b is None: res = ""
                elif b==0: res = "Err: /0"
                else: res = a/b
            elif op=="sqr": res = "" if a is None else a*a
        except Exception as e:
            res = f"Err: {e}"

    user = session.get("user")
    admin_link = f'<a class="btn solid warn" href="/admin">{T("admin")}</a>' if is_admin() else ""
    admin_html = f"<span style='margin-left:8px'></span>{admin_link}" if admin_link else ""
    if user:
        user_html = (
            f"{T('logged_in_as')}: <b>{html.escape(str(user))}</b> "
            f"<a class=\"btn\" href=\"/logout\">{T('logout')}</a>"
        )
    else:
        user_html = (
            f"{T('not_logged_in')} | "
            f"<a class=\"btn\" href=\"/register\">{T('register')}</a> "
            f"<a class=\"btn\" href=\"/login\">{T('login')}</a>"
        )
    res_fmt = compact(res) if isinstance(res, (int, float)) or (isinstance(res, str) and res.replace(".", "", 1).isdigit()) else res
    res_html = html.escape(str(res_fmt))
    update_html = html.escape(update_txt)

    return f"""<!doctype html><meta charset="utf-8"><title>{T('title_home')}</title>
    <style>
      :root {{
        --bg:#020204; --panel:#0b0b12; --panel2:#0f0f18; --muted:#a3a3b2; --border:#232334;
        --ink:#e7e7f5; --violet:#7c3aed; --violet2:#a78bfa; --red:#ef4444; --rose:#fb7185;
      }}
      *{{box-sizing:border-box}} body{{font-family:Inter,Arial;background:
        radial-gradient(1000px 400px at 80% -10%, rgba(239,68,68,.22), transparent 60%),
        radial-gradient(1000px 600px at -20% 10%, rgba(124,58,237,.28), transparent 65%),
        #000; color:var(--ink); margin:0; padding:28px}}
      .container{{max-width:1080px;margin:0 auto}}
      .panel{{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--border);border-radius:20px;padding:20px;box-shadow:0 0 60px rgba(124,58,237,.08)}}
      .btn{{display:inline-flex;align-items:center;gap:8px;padding:10px 14px;border-radius:12px;border:1px solid var(--border);background:#12121a;color:var(--ink);text-decoration:none;cursor:pointer}}
      .btn.solid{{background:linear-gradient(90deg,#7c3aed,#ef4444);border-color:#7c3aed}}
      .btn.warn{{background:#fb7185;border-color:#fb7185;color:#140a0a}}
      .row{{display:flex;gap:10px;flex-wrap:wrap;align-items:center}}
      /* toolbar layout (desktop + mobile) */
.toolbar{{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap}}
.toolbar-left,.toolbar-right{{display:flex;gap:10px;align-items:center;flex-wrap:wrap}}
@media (max-width:700px){{
  .toolbar{{flex-direction:column;align-items:stretch}}
  .toolbar-right{{justify-content:flex-start}}
}}
      input,select,button{{border-radius:12px;border:1px solid var(--border);padding:12px;background:#13131c;color:var(--ink)}}
      button.solid{{background:linear-gradient(90deg,#7c3aed,#ef4444);border-color:#7c3aed;cursor:pointer}}
      label b{{display:block;margin-bottom:6px;color:#d9d9ff}}
      .pill{{padding:6px 10px;border:1px solid var(--border);border-radius:999px;background:#10101a;color:#cfcfe8}}
    </style>
    <div class="container">
          <div class="card">
    <h2 style="margin-top:0">{T('home_update_heading')}</h2>
    <form method="post" action="/admin/set_update" class="grid" style="grid-template-columns:1fr">
  <textarea name="update" rows="8" placeholder="{T('home_update_placeholder')}"
    style="width:100%;border-radius:12px;border:1px solid var(--border);padding:12px;background:#11131a;color:#e5e7eb">{update_html}</textarea>
  <div class="row" style="margin-top:8px;justify-content:flex-end">
    <button class="btn solid" type="submit">{T('save')}</button>
  </div>
</form>
  </div>
      <div class="toolbar">
  <div class="toolbar-left">
    <a class="btn solid" href="/clicker">🎮 {T('goto_clicker')}</a>
    <a class="btn" href="/leaderboard">🏆 {T('leaderboard')}</a>
    <a class="btn" href="/disclaimer">ℹ️ {T('respect')}</a>
  </div>

  <div class="toolbar-right">
    <a class="btn" href="/lang?to=en">{T('change_en')}</a>
    <a class="btn" href="/lang?to=fr">{T('change_fr')}</a>
    {admin_html}
  </div>
</div>


      <div class="panel" style="text-align:center">
        <h1 style="margin:8px 0; letter-spacing:.5px">{T('title_home')}</h1>
        <div style="margin:8px 0">
          <span>{user_html}</span>
        </div>
      </div>

      <div class="panel" style="margin-top:18px">
        <h2 style="text-align:center">{T('calc')}</h2>
        <form method="post" style="display:grid;gap:12px;grid-template-columns:1fr 1fr 1fr 1fr">
          <label style="grid-column:span 2"><b>{T('num_a')}</b>
            <input type="number" step="any" name="a" value="{a_str}">
          </label>
          <label style="grid-column:span 2"><b>{T('num_b')}</b>
            <input type="number" step="any" name="b" value="{b_str}">
          </label>
          <label style="grid-column:span 3"><b>{T('op')}</b>
            <select name="op">
              <option value="add" {'selected' if op=='add' else ''}>{T('add')}</option>
              <option value="sub" {'selected' if op=='sub' else ''}>{T('sub')}</option>
              <option value="mul" {'selected' if op=='mul' else ''}>{T('mul')}</option>
              <option value="div" {'selected' if op=='div' else ''}>{T('div')}</option>
              <option value="sqr" {'selected' if op=='sqr' else ''}>{T('sqr')}</option>
            </select>
          </label>
          <button class="solid" type="submit" style="font-size:18px">{T('compute')}</button>
        </form>
        <p style="margin-top:10px;font-size:20px"><b>{T('total')}:</b> {res_html}</p>
        <p class="pill">{T('tip')}</p>
      </div>
    </div>"""

# ---------- API: save/load + settings ----------


def _sanitize_shop(items):
    safe = []
    if not isinstance(items, list):
        return safe
    for it in items[:2000]:
        if not isinstance(it, dict):
            continue
        key  = str(it.get("key")  or "")[:128] or f"unit-{len(safe)}"
        name = str(it.get("name") or "Unit")[:128]
        try:
            base = float(it.get("base") or 10.0)
        except:
            base = 10.0
        try:
            inc = float(it.get("inc") or 0.0)
        except:
            inc = 0.0
        try:
            lvl = int(it.get("lvl") or 0)
        except:
            lvl = 0
        safe.append({
            "key":  key,
            "name": name,
            "base": max(0.0, base),
            "inc":  max(0.0, inc),
            "lvl":  max(0, lvl),
        })
    return safe

@app.get("/api/prestige")
def api_get_prestige():
    if not is_authed():
        return jsonify({"ok": False, "err": "not_auth"}), 401
    with lock:
        db = load_db()
        u = session.get("user")
        if not u or u not in db["users"]:
            return jsonify({"ok": False, "err": "user_missing"}), 400
        p = db["users"][u].get("prestige") or _empty_prestige()
    return jsonify({"ok": True, "prestige": p, "upgrades": PRESTIGE_UPGRADES})

@app.post("/api/ascend")
def api_ascend():
    if not is_authed():
        return jsonify({"ok": False, "err": "not_auth"}), 401
    with lock:
        db = load_db()
        u = session.get("user")
        if not u or u not in db["users"]:
            return jsonify({"ok": False, "err": "user_missing"}), 400

        doc = db["users"][u]
        prog = (doc.get("progress") or _empty_progress())
        cps_now = float(prog.get("cps") or 0.0)

        prest = doc.get("prestige") or _empty_prestige()
        asc_lvl = int((prest.get("up") or {}).get("asc_mult", 0))
        mult = 1.0 + 0.10 * asc_lvl
        award = int((cps_now / 1_000_000) * mult)
  # 1 tryz / 1,000,000 a/s
        if award <= 0:
            return jsonify({"ok": False, "err": "too_low", "need": 1_000_000}), 400

        # grant currency + increment asc count
        prest = doc.get("prestige") or _empty_prestige()
        prest["tryz"] = int(prest.get("tryz", 0)) + award
        prest["asc"]  = int(prest.get("asc", 0)) + 1
        doc["prestige"] = prest

        # reset progress to clean slate (server-controlled)
        fresh = _empty_progress()
        fresh["saved_at"] = int(time.time())
        doc["progress"] = fresh

        save_db(db)

    return jsonify({"ok": True, "award": award, "prestige": prest, "progress": fresh})

@app.post("/api/buy_prestige_upgrade")
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
        prest = doc.get("prestige") or _empty_prestige()
        up = prest.get("up") or {}

        defn = next((d for d in PRESTIGE_UPGRADES if d["key"] == key), None)
        if not defn:
            return jsonify({"ok": False, "err": "bad_key"}), 400

        cur = int(up.get(key, 0))
        if cur >= defn["max"]:
            return jsonify({"ok": False, "err": "maxed"}), 400

        cost = _prestige_cost(key, cur + 1)
        if prest.get("tryz", 0) < cost:
            return jsonify({"ok": False, "err": "no_funds", "need": cost}), 400

        prest["tryz"] -= cost
        up[key] = cur + 1
        prest["up"] = up
        doc["prestige"] = prest
        save_db(db)

    return jsonify({"ok": True, "prestige": prest, "cost": cost, "level": up[key]})

@app.post("/api/sell_prestige_upgrade")
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
        prest = doc.get("prestige") or _empty_prestige()
        up = prest.get("up") or {}

        defn = next((d for d in PRESTIGE_UPGRADES if d["key"] == key), None)
        if not defn:
            return jsonify({"ok": False, "err": "bad_key"}), 400

        cur = int(up.get(key, 0))
        if cur <= 0:
            return jsonify({"ok": False, "err": "no_level"}), 400

        total_spent = sum(_prestige_cost(key, i) for i in range(1, cur + 1))
        refund = int(total_spent * 0.50)

        prest["tryz"] = int(prest.get("tryz", 0)) + refund
        up[key] = cur - 1
        prest["up"] = up
        doc["prestige"] = prest
        save_db(db)

    return jsonify({"ok": True, "prestige": prest, "refund": refund, "level": up[key]})


def _empty_progress():
    return {
        "v": 1,
        "count": 0.0,
        "cps": 0.0,
        "shop": [],
        "saved_at": None,
    }

def _empty_prestige():
    return {
        "tryz": 0,            # prestige currency
        "asc": 0,             # number of ascensions
        "up": {}              # upgrades: {key: lvl}
    }

# server-side canonical prestige upgrades (validate + pricing)
PRESTIGE_UPGRADES = [
    {"key": "cps_mult",     "name": "Passive a/s x1.10/level",  "base": 1_000_000_000, "max": 50},     # 1B
    {"key": "click_mult",   "name": "Click power x1.25/level",  "base": 10_000_000_000, "max": 20},    # 10B
    {"key": "start_boost",  "name": "Start +10k/level",         "base": 50_000_000_000, "max": 10},    # 50B
    {"key": "asc_mult",     "name": "Ascend yield +10%/level",  "base": 100_000_000_000, "max": 50},   # 100B
    {"key": "shop_discount", "name": "Shop prices -2%/level",   "base": 500_000_000_000, "max": 50},   # 500B
    {"key": "flat_cps",     "name": "+100 a/s per level",       "base": 1_000_000_000_000, "max": 200},# 1T
    {"key": "refund_plus",  "name": "Sell refund +5%/level",    "base": 10_000_000_000_000, "max": 9}, # 10T
    {"key": "lucky_clicks", "name": "Crit click +5%/lvl (x3)",  "base": 1_000_000_000_000_000, "max": 15}, # 1Qa
]

# ---------- Achievements (server authority) ----------
# Base: +0.25% a/s per achievement (multiplicative: 1.0025 ** n)
# Some "extreme" achievements grant large bonuses (+10% / +25% / +50%)
# +1000 a/s flat bonus if ALL are unlocked

BASE_ACH_MULT = 1.0025  # 0.25% per achievement (multiplicative)


# Milestones
CPS_TARGETS   = [1,2,5,10,20,50,100,200,500,1_000,2_000,5_000,10_000,20_000,50_000,100_000,200_000,500_000,1_000_000,2_000_000]
COUNT_TARGETS = [1_000,10_000,100_000,1_000_000,10_000_000,100_000_000,1_000_000_000,10_000_000_000,100_000_000_000,
                 1_000_000_000_000,10_000_000_000_000,100_000_000_000_000,1_000_000_000_000_000,10_000_000_000_000_000,
                 100_000_000_000_000_000,1_000_000_000_000_000_000,10_000_000_000_000_000_000,100_000_000_000_000_000_000,
                 1_000_000_000_000_000_000_000,10_000_000_000_000_000_000_000]
ASC_TARGETS   = [1,5,10,25,50]
BUY_THRESHOLDS = [10,25,50,100]  # per core unit
# Extreme long-term achievements (months+ grind)
EXTREME_CPS = [
    (1_000_000_000_000_000_000_000_000,           "ultra_cps_1t",   "Insane a/s: 1T",    1.10),  # +10%
    (1_000_000_000_000_000_000_000_000_000,       "ultra_cps_1qa",  "Insane a/s: 1Qa",   1.25),  # +25%
    (1_000_000_000_000_000_000_000_000_000_000,   "ultra_cps_1qi",  "Beyond a/s: 1Qi",   1.50),  # +50%
]
EXTREME_COUNT = [
    (10**30, "ultra_count_1e30", "Bank 1e39", 1.10),  # +10%
    (10**33, "ultra_count_1e33", "Bank 1e43", 1.25),  # +25%
    (10**36, "ultra_count_1e36", "Bank 1e56", 1.50),  # +50%
]
EXTREME_ASC = [
    (100, "ultra_asc_100", "Ascend ×100", 1.10),  # +10%
    (250, "ultra_asc_250", "Ascend ×250", 1.25),  # +25%
    (500, "ultra_asc_500", "Ascend ×500", 1.50),  # +50%
]


# Core unit keys (match client shop)
CORE_UNITS = {
  "rock":"Petit caillou Autiste","wood":"Autiste en bois","pen":"Stylo Autiste",
  "remi":"Remi - Autiste","jonsman":"Jonsman - Autiste","hector":"Hector - Autiste","valentin":"Valentin - Autiste",
  "johan":"Johan - Autiste","viki":"Viki - Autiste","paul":"Paul - Autiste","samere":"Sa Mère - Autiste",
  "shoes":"Chaussures Autistes","factory":"Usine Autiste","farm":"Ferme Autiste","tower":"Tour Autiste",
  "lab":"Laboratoire Autiste","server":"Serveur Autiste","mine":"Mine Autiste","bunker":"Bunker Autiste",
  "fusion":"Autiste Fusion Reactor","qportal":"Quantum Portail Autiste","aiswarm":"AI Swarm Autiste","planet":"Planet Factory Autiste",
  "bhc":"Black Hole Autiste Collider","multi":"Multiverse Franchise Autiste","timemachine":"Time Machine Autiste",
  "galactic":"Galactic Autiste Conglomerate","dimemp":"Dimensional Autiste Empire",
  "sock":"Chaussettes Autistes","iphone":"Autiste iPhone 34","tesla":"Autiste Tesla Cybertruck","pcgamer":"Autiste PC Gamer",
  "mcdo":"Autiste McDo Factory","rocket":"Autiste SpaceX Rocket","crypto":"Autiste Crypto Mine","nuclear":"Autiste Nuclear Plant",
  "mars":"Autiste Mars Colony","black":"Autiste Black Market",
  "dyson":"Autiste Dyson Sphere","empiregal":"Empire Autiste Galactique","universe":"Autiste Univers Portable",
  "simul":"Simulation Autiste Infinie","god":"Autiste Dieu Ancien","omniverse":"Autiste Omnivers","source":"Autiste Source du Tout",
}
CORE_KEYS = list(CORE_UNITS.keys())  # 45 units → 45 * 4 = 180 buy achievements

# Build static definition list (≈225)
def build_achievement_defs():
    defs = []
    # base achievements: each grants BASE_ACH_MULT
    for v in CPS_TARGETS:
        defs.append({"id": f"cps_{v}", "group":"cps", "name": f"Hit {v} a/s",
                     "desc": f"Reach ≥ {v} autists/s", "mult": BASE_ACH_MULT})
    for v in COUNT_TARGETS:
        defs.append({"id": f"count_{v}", "group":"count", "name": f"Bank {v}",
                     "desc": f"Total autists ≥ {v}", "mult": BASE_ACH_MULT})
    for v in ASC_TARGETS:
        defs.append({"id": f"asc_{v}", "group":"asc", "name": f"Ascend ×{v}",
                     "desc": f"Perform {v} ascensions", "mult": BASE_ACH_MULT})
    for key in CORE_KEYS:
        nm = CORE_UNITS.get(key, key)
        for n in BUY_THRESHOLDS:
            defs.append({"id": f"buy_{key}_{n}", "group":"buy",
                         "name": f"{nm} ×{n}", "desc": f"Own {n} of {nm}",
                         "mult": BASE_ACH_MULT})

    # extreme achievements: large multipliers
    for v, aid, nm, mult in EXTREME_CPS:
        defs.append({"id": aid, "group": "cps", "name": nm,
                     "desc": f"Reach ≥ {v} autists/s", "mult": float(mult)})
    for v, aid, nm, mult in EXTREME_COUNT:
        defs.append({"id": aid, "group": "count", "name": nm,
                     "desc": f"Total autists ≥ {v}", "mult": float(mult)})
    for v, aid, nm, mult in EXTREME_ASC:
        defs.append({"id": aid, "group": "asc", "name": nm,
                     "desc": f"Perform {v} ascensions", "mult": float(mult)})

    return defs


ACH_DEFS = build_achievement_defs()
ACH_MULT_BY_ID = {d["id"]: float(d.get("mult", BASE_ACH_MULT)) for d in ACH_DEFS}
ACH_TOTAL = len(ACH_DEFS)
ALL_ACH_BONUS = 1000  # +1000 a/s flat if all unlocked


def _ach_product(ach_ids):
    """Return total multiplicative bonus from the list of unlocked achievement IDs."""
    m = 1.0
    for aid in ach_ids or []:
        m *= ACH_MULT_BY_ID.get(aid, BASE_ACH_MULT)
    return m

def _scan_achievements(doc):
    """
    Evaluate achievements for a user doc (modifies doc['ach']).
    Returns (new_count, total_defs, has_all).
    """
    prog = (doc or {}).get("progress") or {}
    cps   = float(prog.get("cps") or 0.0)
    total = float(prog.get("count") or 0.0)
    shop  = prog.get("shop") or []
    asc   = int(((doc or {}).get("prestige") or {}).get("asc") or 0)

    have = set((doc or {}).get("ach") or [])

    # base milestones
    for v in CPS_TARGETS:
        if cps >= v: have.add(f"cps_{v}")
    for v in COUNT_TARGETS:
        if total >= v: have.add(f"count_{v}")
    for v in ASC_TARGETS:
        if asc >= v: have.add(f"asc_{v}")

    # extreme milestones
    for v, aid, _, _ in EXTREME_CPS:
        if cps >= v: have.add(aid)
    for v, aid, _, _ in EXTREME_COUNT:
        if total >= v: have.add(aid)
    for v, aid, _, _ in EXTREME_ASC:
        if asc >= v: have.add(aid)

    # per-unit buys (core only)
    qty = { (it.get("key") or ""): int(it.get("lvl") or 0) for it in shop }
    for key in CORE_KEYS:
        lv = int(qty.get(key, 0))
        for n in BUY_THRESHOLDS:
            if lv >= n: have.add(f"buy_{key}_{n}")

    doc["ach"] = sorted(have)
    has_all = len(doc["ach"]) >= ACH_TOTAL
    return len(doc["ach"]), ACH_TOTAL, has_all


@app.get("/api/achievements")
def api_get_achievements():
    if not is_authed():
        return jsonify({"ok": False, "err": "not_auth"}), 401
    with lock:
        db = load_db()
        u = session.get("user")
        user = (db.get("users") or {}).get(u) or {}
        n, tot, all_ok = _scan_achievements(user)  # update in-memory
        save_db(db)
        unlocked = user.get("ach", [])
        mult = _ach_product(unlocked)
        save_db(db)
        return jsonify({
            "ok": True,
            "defs": ACH_DEFS,
            "unlocked": unlocked,
            "count": n, "total": tot,
            "mult": mult,
            "all": all_ok, "all_bonus": ALL_ACH_BONUS
        })


# ---------- Profiles (explicit create) ----------
def _profile_from_doc(username, doc):
    # DO NOT auto-create here; just read doc safely
    prog  = (doc or {}).get("progress") or _empty_progress()
    prest = (doc or {}).get("prestige") or _empty_prestige()
    has_profile = isinstance((doc or {}).get("profile"), dict)

    # keep achievements up to date
    _scan_achievements(doc)
    ach_ids = doc.get("ach") or []
    ach_map = {d["id"]: d for d in ACH_DEFS}
    ach_list = [{
        "id": aid,
        "name": ach_map.get(aid, {"name": aid}).get("name"),
        "group": ach_map.get(aid, {}).get("group", ""),
        "mult": float(ach_map.get(aid, {}).get("mult", BASE_ACH_MULT)),
    } for aid in ach_ids[:200]]

    return {
        "exists": has_profile,
        "user": username,
        "bio": (doc.get("profile", {}) or {}).get("bio", "")[:280] if has_profile else "",
        "count": float(prog.get("count") or 0.0),
        "cps": float(prog.get("cps") or 0.0),
        "tryz": int(prest.get("tryz") or 0),
        "asc": int(prest.get("asc") or 0),
        "ach_count": len(ach_ids),
        "ach_total": ACH_TOTAL,
        "ach_mult": _ach_product(ach_ids),
        "ach": ach_list,
    }

@app.get("/api/profile")
def api_profile():
    # ?u=Name  → show that user's profile
    # empty    → show current user (must be authed)
    target = (request.args.get("u") or "").strip()
    with lock:
        db = load_db()
        if not target:
            target = session.get("user")
        users = db.get("users", {}) or {}
        if not target or target not in users:
            return jsonify({"ok": False, "err": "not_found"}), 404
        doc = users[target]
        prof = _profile_from_doc(target, doc)
        save_db(db)  # achievements might have been updated
        return jsonify({"ok": True, "profile": prof, "self": (session.get("user") == target)})

@app.post("/api/profile_create")
def api_profile_create():
    # Create profile for current authed user from their existing account
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
        else:
            return jsonify({"ok": True, "created": False})  # already exists

@app.post("/api/profile_settings")
def api_profile_settings():
    # Update bio (requires an existing profile)
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

@app.get("/profile")
def profile_page():
    # Search + view + create-if-missing + settings (only when profile exists)
    return """
<!doctype html><meta charset="utf-8"><title>Profile</title>
<style>
  :root{ --bg:#000; --panel:#0b0b12; --panel2:#0f0f18; --border:#232334; --ink:#e7e7f5; --muted:#9aa0a6; }
  *{box-sizing:border-box} body{font-family:Inter,Arial;background:
    radial-gradient(900px 400px at 0% -10%, rgba(124,58,237,.25), transparent 60%),
    radial-gradient(900px 500px at 120% 10%, rgba(239,68,68,.18), transparent 65%),
    #000; color:var(--ink); margin:0; padding:24px}
  .wrap{max-width:980px;margin:0 auto}
  .card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--border);border-radius:16px;padding:16px;margin-bottom:16px;box-shadow:0 0 40px rgba(124,58,237,.08)}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  input,button,textarea{border-radius:10px;border:1px solid var(--border);padding:10px;background:#15172b;color:#eee}
  .btn{display:inline-block;padding:10px 14px;border:1px solid var(--border);border-radius:12px;background:#141625;color:#e5e7eb;text-decoration:none;cursor:pointer}
  .btn.solid{background:linear-gradient(90deg,#7c3aed,#ef4444);border-color:#7c3aed}
  .pill{padding:6px 10px;border:1px solid var(--border);border-radius:999px;background:#10101a;color:#cfcfe8}
  .grid{display:grid;gap:10px}
  .stats{display:grid;gap:10px;grid-template-columns:repeat(2,1fr)}
  @media (min-width:900px){ .stats{grid-template-columns:repeat(4,1fr)} }
  .stat{background:#0f1020;border:1px solid #2b2d4a;border-radius:14px;padding:12px;text-align:center}
  .stat .v{font-size:20px;font-weight:700}
  .ach{border:1px solid #2b2d4a;border-radius:12px;padding:10px;background:#121322;display:flex;justify-content:space-between;gap:8px}
</style>

<div class="wrap">
  <div class="card">
    <div class="row" style="justify-content:space-between">
      <div class="row">
        <a class="btn" href="/">← Home</a>
        <a class="btn" href="/clicker">🎮 Clicker</a>
        <a class="btn" href="/leaderboard">🏆 Leaderboard</a>
      </div>
      <div class="row">
        <input id="q" placeholder="Search username…" style="min-width:220px">
        <button id="go" class="btn solid">Open Profile</button>
      </div>
    </div>
  </div>

  <!-- Profile card (stats always visible, even if profile not created) -->
  <div id="card_profile" class="card">
    <div class="row" style="justify-content:space-between;align-items:flex-start">
      <div>
        <h1 id="p_user" style="margin:.2rem 0">—</h1>
        <div id="p_bio" class="pill" style="margin-top:6px;max-width:700px">—</div>
      </div>
      <a class="btn" href="/profile">👤 My profile</a>
    </div>

    <div class="stats" style="margin-top:12px">
      <div class="stat"><div class="k">Autists</div><div class="v" id="p_count">0</div></div>
      <div class="stat"><div class="k">a/s</div><div class="v" id="p_cps">0</div></div>
      <div class="stat"><div class="k">Tryzomiques</div><div class="v" id="p_tryz">0</div></div>
      <div class="stat"><div class="k">Ascensions</div><div class="v" id="p_asc">0</div></div>
    </div>

    <div class="card" style="margin-top:12px">
      <div class="row" style="justify-content:space-between;align-items:center">
        <h3 style="margin:.2rem 0">Achievements</h3>
        <div id="p_ach_sum" class="pill">—</div>
      </div>
      <div id="p_ach_list" class="grid" style="grid-template-columns:1fr;gap:8px;margin-top:8px"></div>
    </div>
  </div>

  <!-- Create profile CTA (only shows if self & not exists) -->
  <div id="card_create" class="card" style="display:none">
    <h2 style="margin:.2rem 0">Create your profile</h2>
    <p class="pill">This will use your existing account. You can add a short bio after.</p>
    <div class="row">
      <button id="btn_create_profile" class="btn solid">Create Profile</button>
      <span id="create_msg" class="pill">—</span>
    </div>
  </div>

  <!-- Profile settings (only when profile exists & viewing self) -->
  <div id="card_settings" class="card" style="display:none">
    <h2 style="margin:.2rem 0">Profile Settings</h2>
    <div class="grid" style="grid-template-columns:1fr auto;align-items:start">
      <textarea id="bio" rows="3" placeholder="Short bio (public, 280 chars max)"></textarea>
      <button id="save_bio" class="btn solid">Save</button>
    </div>
    <div id="save_msg" class="pill" style="margin-top:8px">Write something and click Save.</div>
  </div>
</div>

<script>
function fmt(n){
  n = Number(n)||0;
  const scales = [
    [1e75,'qavg'],[1e72,'tvg'],[1e69,'dvg'],[1e66,'uvg'],[1e63,'vg'],
    [1e60,'nd'],[1e57,'od'],[1e54,'spd'],[1e51,'sxd'],[1e48,'qid'],
    [1e45,'qad'],[1e42,'td'],[1e39,'dd'],[1e36,'ud'],[1e33,'de'],
    [1e30,'no'],[1e27,'oc'],[1e24,'sp'],[1e21,'sx'],[1e18,'qi'],
    [1e15,'qa'],[1e12,'t'],[1e9,'b'],[1e6,'m'],[1e3,'k']
  ];
  for (const [div,suf] of scales){
    if (Math.abs(n) >= div){
      const val = (n/div).toFixed(2).replace(/\.00$/,'').replace(/(\.\d*[1-9])0$/,'$1');
      return val + suf;
    }
  }
  if (Math.abs(n) >= 1e6) return n.toExponential(2).replace("+","");
  return String(Math.trunc(n));
}

function param(n){ return new URLSearchParams(location.search).get(n)||''; }

function renderProfile(p, isSelf){
  document.getElementById('p_user').textContent = p.user || '—';
  document.getElementById('p_bio').textContent  = (p.exists && (p.bio||'').trim()) ? p.bio : (p.exists ? '—' : 'No profile yet.');

  document.getElementById('p_count').textContent= fmt(p.count||0);
  document.getElementById('p_cps').textContent  = fmt(p.cps||0);
  document.getElementById('p_tryz').textContent = fmt(p.tryz||0);
  document.getElementById('p_asc').textContent  = fmt(p.asc||0);

  const mult = Number(p.ach_mult||1);
  const sum  = `Unlocked ${p.ach_count||0}/${p.ach_total||0} — Mult x${mult.toFixed(2)}`;
  document.getElementById('p_ach_sum').textContent = sum;

  const wrap = document.getElementById('p_ach_list');
  wrap.innerHTML = '';
  (p.ach||[]).slice(0,12).forEach(a=>{
    const el = document.createElement('div');
    el.className = 'ach';
    el.innerHTML = `
      <div>
        <div style="font-weight:700">${(a.name||a.id)}</div>
        <div style="opacity:.75">${(a.group||'').toUpperCase()}</div>
      </div>
      <div class="pill">✓ +${(((Number(a.mult||1)-1)*100).toFixed(2))}%</div>
    `;
    wrap.appendChild(el);
  });

  const showCreate = isSelf && !p.exists;
  document.getElementById('card_create').style.display   = showCreate ? 'block' : 'none';
  document.getElementById('card_settings').style.display = (isSelf && p.exists) ? 'block' : 'none';
  if(isSelf && p.exists){
    document.getElementById('bio').value = p.bio || '';
  }
}

async function loadProfile(name){
  let url = '/api/profile' + (name ? ('?u=' + encodeURIComponent(name)) : '');
  try{
    const r = await fetch(url, {cache:'no-store'});
    const j = await r.json();
    if(j && j.ok){
      renderProfile(j.profile, j.self);
    }else{
      document.getElementById('p_user').textContent = 'Not found';
      document.getElementById('p_bio').textContent = '—';
    }
  }catch(e){}
}

function goSearch(){
  const q = (document.getElementById('q').value||'').trim();
  if(!q) return;
  location.href = '/profile?u=' + encodeURIComponent(q);
}

document.getElementById('go').onclick = goSearch;
document.getElementById('q').addEventListener('keydown', (e)=>{ if(e.key==='Enter'){ goSearch(); } });

document.getElementById('btn_create_profile').onclick = async ()=>{
  try{
    const r = await fetch('/api/profile_create', {method:'POST'});
    const j = await r.json().catch(()=>({}));
    document.getElementById('create_msg').textContent = (j && j.ok) ? (j.created ? 'Created ✓' : 'Already exists') : (j.err || 'Error');
    if(j && j.ok){ loadProfile(''); }
  }catch(e){
    document.getElementById('create_msg').textContent = 'Network error';
  }
};

document.getElementById('save_bio').onclick = async ()=>{
  const bio = (document.getElementById('bio').value||'').trim();
  try{
    const r = await fetch('/api/profile_settings', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({bio})
    });
    const j = await r.json().catch(()=>({}));
    document.getElementById('save_msg').textContent = (j && j.ok) ? 'Saved ✓' : (j.err || 'Error');
    if(j && j.ok){ loadProfile(''); }
  }catch(e){
    document.getElementById('save_msg').textContent = 'Network error';
  }
};

// boot
const target = param('u');
if(target){ document.getElementById('q').value = target; }
loadProfile(target);
</script>
"""



def _prestige_cost(key, lvl_next):
    # lvl_next starts at 1 for first buy
    for u in PRESTIGE_UPGRADES:
        if u["key"] == key:
            return int(u["base"] * lvl_next)  # simple linear scale
    return 999999999

@app.post("/api/save_progress")
def api_save_progress():
    if not is_authed():
        return jsonify({"ok": False, "err": "not_auth"}), 401

    data = request.get_json(silent=True) or {}

    try:
        count = float(data.get("count") or 0.0)
    except:
        count = 0.0
    try:
        cps = float(data.get("cps") or 0.0)
    except:
        cps = 0.0

    shop = _sanitize_shop(data.get("shop") or [])

    if not isinstance(shop, list):
        return jsonify({"ok": False, "err": "bad_payload"}), 400

    with lock:
        db = load_db()
        u = session.get("user")
        if not u or u not in db.get("users", {}):
            return jsonify({"ok": False, "err": "user_missing"}), 400

        db["users"][u]["progress"] = {
            "v": int(data.get("v") or data.get("version") or 1),
            "count": max(0.0, count),
            "cps": max(0.0, cps),
            "shop": shop,
            "saved_at": int(time.time()),
        }

        # Update achievements based on the newly saved state
        doc = db["users"][u]
        _scan_achievements(doc)

        save_db(db)

    return jsonify({"ok": True})




@app.get("/api/load_progress")
def api_load_progress():
    if not is_authed():
        return jsonify({"ok": False, "err": "not_auth"}), 401

    with lock:
        db = load_db()
        u = session.get("user")
        if u and u in db.get("users", {}):
            # ensure prestige exists for existing accounts
            db["users"][u].setdefault("prestige", _empty_prestige())
            save_db(db)

        base = _empty_progress()
        if not u or u not in db.get("users", {}):
            return jsonify({"ok": True, "progress": base})

        prog = db["users"][u].get("progress") or base
        prog = {
            "v": int(prog.get("v") or 1),
            "count": float(prog.get("count") or 0.0),
            "cps": float(prog.get("cps") or 0.0),
            "shop": _sanitize_shop(prog.get("shop") or []),
            "saved_at": prog.get("saved_at"),
        }
        # Backfill achievements for older accounts on load
        user_doc = db["users"].get(u, {})
        changed_count, _, _ = _scan_achievements(user_doc)
        save_db(db)
    return jsonify({"ok": True, "progress": prog})


@app.post("/api/update_shop")
def api_update_shop():
    if not is_admin():  # Only allow admins to update the shop
        return jsonify({"ok": False, "err": "Forbidden"}), 403

    data = request.get_json(silent=True) or {}

    if "shop" not in data:
        return jsonify({"ok": False, "err": "Missing shop data"}), 400

    # Save the updated shop data in the database
    with lock:
        db = load_db()
        db["settings"]["shop"] = data["shop"]
        save_db(db)

    return jsonify({"ok": True})

@app.get("/api/load_shop")
def api_load_shop():
    with lock:
        db = load_db()
        shop = (db.get("settings", {}) or {}).get("shop") or []
    return jsonify({"ok": True, "shop": shop})


@app.get("/api/settings")
def api_settings():
    with lock:
        db = load_db()
        st = db.get("settings", {})
    def full(url):
        return url_for("serve_upload", filename=os.path.basename(url), _external=False) if url else None
    return jsonify({"ok": True, "settings": {"bg": full(st.get("bg")), "logo": full(st.get("logo"))}})

# ---------- Reviews ----------
def _sanitize_review(r):
    # ensure structure and clamp values
    u = str(r.get("u") or "").strip()[:40]
    stars = int(r.get("stars") or 0)
    stars = max(1, min(5, stars))
    text = str(r.get("text") or "").strip()[:800]
    return {"u": u or "Anonymous", "stars": stars, "text": text, "ts": int(time.time())}

@app.get("/api/reviews")
def api_reviews_list():
    with lock:
        db = load_db()
        items = list(reversed(db.get("reviews", [])))[:100]  # newest first, cap 100
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

@app.post("/api/reviews")
def api_reviews_add():
    data = request.get_json(silent=True) or {}
    # Require at least a comment or stars
    try:
        stars = int(data.get("stars", 0))
    except:
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
        # Keep only last 1000 reviews
        db.setdefault("reviews", []).append(doc)
        db["reviews"] = db["reviews"][-1000:]
        save_db(db)
    return jsonify({"ok": True, "review": doc})

# ---------- Public Update Note ----------
@app.get("/api/update")
def api_get_update():
    with lock:
        db = load_db()
        txt = (db.get("settings", {}) or {}).get("update", "") or ""
    return jsonify({"ok": True, "update": txt})

@app.post("/admin/set_update")
def admin_set_update():
    if not is_admin():
        return "Forbidden", 403
    txt = (request.form.get("update") or "").strip()[:5000]
    with lock:
        db = load_db()
        db.setdefault("settings", {}).setdefault("update", "")
        db["settings"]["update"] = txt
        save_db(db)
    return redirect("/admin")


# ---------- Uploads ----------
@app.get("/uploads/<path:filename>")
def serve_upload(filename):
    return send_from_directory(UPLOAD_DIR, filename, conditional=True)

def _save_upload(file_storage):
    if not file_storage: return None, "no_file"
    filename = file_storage.filename or ""
    ext = filename.rsplit(".",1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXT: return None, "bad_ext"
    safe = secure_filename(os.path.splitext(filename)[0])
    uniq = f"{int(time.time())}_{secrets.token_hex(6)}.{ext}"
    path = os.path.join(UPLOAD_DIR, f"{safe}_{uniq}")
    file_storage.save(path)
    return path, None

# ---------- Admin ----------
@app.get("/admin")
def admin_panel():
    if not is_admin(): return "Forbidden", 403
    with lock:
        db = load_db()
        users = sorted(db["users"].keys())
        st = db.get("settings", {"bg":None, "logo":None})
    rows=[]
    for u in users:
        rows.append(f"""
        <tr>
          <td>{u}</td>
          <td style="display:flex;gap:6px;flex-wrap:wrap">
            <form method="post" action="/admin/reset_pw" class="act">
              <input type="hidden" name="u" value="{u}">
              <input name="p" placeholder="{T('new_pw')}" required>
              <button class="btn ok">{T('reset_pw')}</button>
            </form>
            <form method="post" action="/admin/add" class="act">
              <input type="hidden" name="u" value="{u}">
              <input name="n" type="number" step="1" placeholder="+N">
              <button class="btn warn">{T('add_aut')}</button>
            </form>
            <form method="post" action="/admin/sub" class="act">
              <input type="hidden" name="u" value="{u}">
              <input name="n" type="number" step="1" placeholder="-N">
              <button class="btn">{T('sub_aut')}</button>
            </form>
            <form method="post" action="/admin/delete" onsubmit="return confirm('Delete {u}?')" class="act">
              <input type="hidden" name="u" value="{u}">
              <button class="btn danger">{T('delete')}</button>
            </form>
          </td>
        </tr>""")
    table = "\n".join(rows) or "<tr><td colspan=2>Empty</td></tr>"
    bg_preview = f'<img src="/uploads/{os.path.basename(st["bg"])}" style="max-height:80px;border-radius:8px">' if st.get("bg") else "<i>None</i>"
    logo_preview = f'<img src="/uploads/{os.path.basename(st["logo"])}" style="max-height:80px;border-radius:8px">' if st.get("logo") else "<i>None</i>"
    return f"""<!doctype html><meta charset="utf-8"><title>{T('admin')}</title>
    <style>
      :root {{ --panel:#0b0b12; --border:#232334; --ink:#e7e7f5; --violet:#7c3aed; --red:#ef4444 }}
      *{{box-sizing:border-box}} body{{font-family:Inter,Arial;background:#000;color:var(--ink);margin:0;padding:24px}}
      .container{{max-width:1100px;margin:0 auto}}
      .card{{background:linear-gradient(180deg,#0b0b12,#0f0f18);border:1px solid var(--border);border-radius:16px;padding:18px;margin-bottom:18px}}
      table{{width:100%;border-collapse:collapse}}
      th,td{{border-bottom:1px solid var(--border);padding:10px;text-align:left}}
      input,button{{border-radius:10px;border:1px solid var(--border);padding:8px;background:#11131a;color:#e5e7eb}}
      .btn{{background:#141625;border-color:#2a2a3a;cursor:pointer;color:#e5e7eb;padding:8px 12px;border-radius:10px;text-decoration:none;display:inline-block}}
      .btn.ok{{background:linear-gradient(90deg,#7c3aed,#a78bfa)}}
      .btn.warn{{background:#ef4444;border-color:#ef4444}}
      .btn.danger{{background:#7c1d1d;border-color:#ef4444}}
      .act{{display:inline-flex;gap:6px;align-items:center;margin:4px 0}}
      .grid{{display:grid;gap:12px;grid-template-columns:1fr 1fr}}
      .row{{display:flex;align-items:center;gap:12px;flex-wrap:wrap}}
      .pill{{padding:6px 10px;border:1px solid #2a2a2a;border-radius:999px;background:#10101a}}

      /* toolbar layout (desktop + mobile) */
      .toolbar{{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap}}
      .toolbar-left,.toolbar-right{{display:flex;gap:10px;align-items:center;flex-wrap:wrap}}
      @media (max-width:700px){{
        .toolbar{{flex-direction:column;align-items:stretch}}
        .toolbar-right{{justify-content:flex-start}}
      }}
    </style>
    <div class="container">

      <div class="card">
        <div class="toolbar">
          <div class="toolbar-left">
            <h1 style="margin:4px 0">{T('admin')}</h1>
          </div>
          <div class="toolbar-right">
            <a class="btn" href="/">← {T('home')}</a>
            <a class="btn" href="/disclaimer">ℹ️ {T('respect')}</a>
            <a class="btn" href="/leaderboard">🏆 {T('leaderboard')}</a>
          </div>
        </div>
      </div>

      <div class="card">
        <h2 style="margin-top:0">{T('assets')}</h2>
        <div class="grid">
          <form class="card" method="post" action="/admin/upload?type=bg" enctype="multipart/form-data">
            <h3 style="margin-top:0">{T('bg')}</h3>
            <div class="row">
              <input type="file" name="file" accept=".png,.jpg,.jpeg,.webp,.gif,.svg">
              <button class="btn ok">{T('upload')}</button>
              <a class="btn warn" href="/admin/clear_asset?type=bg">{T('clear')}</a>
              <span class="pill">Current: {bg_preview}</span>
            </div>
          </form>
          <form class="card" method="post" action="/admin/upload?type=logo" enctype="multipart/form-data">
            <h3 style="margin-top:0">{T('logo')}</h3>
            <div class="row">
              <input type="file" name="file" accept=".png,.jpg,.jpeg,.webp,.gif,.svg">
              <button class="btn ok">{T('upload')}</button>
              <a class="btn warn" href="/admin/clear_asset?type=logo">{T('clear')}</a>
              <span class="pill">Current: {logo_preview}</span>
            </div>
          </form>
        </div>
        <p style="color:#9aa0a6;margin-top:8px">PNG/JPG/WEBP/GIF/SVG. Applied in-game on next load (persists on restart).</p>
      </div>

      <div class="card">
        <h2 style="margin:0 0 8px 0">Bot Seeder</h2>
        <form method="post" action="/admin/seed_bots" class="act" style="display:flex;gap:8px;flex-wrap:wrap">
          <input name="n" type="number" min="1" step="1" value="25" placeholder="How many bots?">
          <label><input type="checkbox" name="overwrite" value="1"> Overwrite existing</label>
          <button class="btn ok">Create Bots</button>
        </form>

        <h3 style="margin:12px 0 8px 0">Fake Reviews</h3>
        <form method="post" action="/admin/seed_reviews" class="act" style="display:flex;gap:8px;flex-wrap:wrap">
          <input name="m" type="number" min="1" step="1" value="40" placeholder="How many reviews?">
          <button class="btn">Create Reviews</button>
        </form>
        <p class="pill" style="margin-top:8px">Bots will appear on the leaderboard; reviews are public.</p>
      </div>

      <div class="card">
        <h2 style="margin:0 0 8px 0">{T('users')}</h2>
        <table>
          <thead><tr><th>{T('users')}</th><th>{T('actions')}</th></tr></thead>
          <tbody>{table}</tbody>
        </table>

        <div class="card">
          <h2 style="margin-top:0">Gérer les commentaires</h2>
          <form onsubmit="deleteReview(event)" class="act" style="display:flex;gap:8px;flex-wrap:wrap">
            <input name="ts" id="rev_ts" placeholder="Timestamp du commentaire" required>
            <button class="btn warn">Supprimer le commentaire</button>
          </form>
          <p class="pill" id="rev_del_msg">Entre le timestamp exact (fourni dans /api/reviews ou DB)</p>
        </div>

        <script>
        async function deleteReview(e){{   // f-string escaping
          e.preventDefault();
          const ts = document.getElementById("rev_ts").value;
          const res = await fetch("/admin/delete_review", {{
            method: "POST",
            headers: {{"Content-Type": "application/x-www-form-urlencoded"}},
            body: "ts=" + encodeURIComponent(ts)
          }});
          const j = await res.json().catch(()=>({{}}));
          document.getElementById("rev_del_msg").textContent = j.ok ? "Supprimé ✓" : "Erreur";
        }}
        </script>

      </div>
    </div>"""


def _adjust_user_count(username, delta):
    with lock:
        db = load_db()
        doc = db["users"].get(username)
        if not doc: return False
        prog = doc.get("progress") or {"count":0,"cps":0,"shop":[]}
        prog["count"] = float(prog.get("count",0)) + float(delta)
        doc["progress"] = prog
        save_db(db)
    return True

@app.post("/admin/reset_pw")
def admin_reset_pw():
    if not is_admin(): return "Forbidden", 403
    u = request.form.get("u",""); p = request.form.get("p","")
    if not u or not p: return "Bad", 400
    with lock:
        db = load_db()
        if u not in db["users"]: return "No user", 404
        db["users"][u]["pw"] = generate_password_hash(p)
        save_db(db)
    return redirect("/admin")

@app.post("/admin/add")
def admin_add():
    if not is_admin(): return "Forbidden", 403
    u = request.form.get("u",""); n = request.form.get("n","0")
    try: n = float(n)
    except: n = 0
    _adjust_user_count(u, n)
    return redirect("/admin")

@app.post("/admin/sub")
def admin_sub():
    if not is_admin(): return "Forbidden", 403
    u = request.form.get("u",""); n = request.form.get("n","0")
    try: n = float(n)
    except: n = 0
    _adjust_user_count(u, -n)
    return redirect("/admin")

@app.post("/admin/delete")
def admin_delete():
    if not is_admin(): return "Forbidden", 403
    u = request.form.get("u","")
    with lock:
        db = load_db()
        if u in db["users"]:
            del db["users"][u]
            save_db(db)
    return redirect("/admin")

@app.post("/admin/upload")
def admin_upload():
    if not is_admin(): return "Forbidden", 403
    t = request.args.get("type","")
    if t not in {"bg","logo"}: return "Bad type", 400
    f = request.files.get("file")
    path, err = _save_upload(f)
    if err: return f"Upload error: {err}", 400
    with lock:
        db = load_db()
        db.setdefault("settings", {"bg":None,"logo":None})
        db["settings"][t] = path
        save_db(db)
    return redirect("/admin")

@app.get("/admin/clear_asset")
def admin_clear_asset():
    if not is_admin(): return "Forbidden", 403
    t = request.args.get("type","")
    if t not in {"bg","logo"}: return "Bad type", 400
    with lock:
        db = load_db()
        db.setdefault("settings", {"bg":None,"logo":None})
        db["settings"][t] = None
        save_db(db)
    return redirect("/admin")

# ---------- Fake bots & reviews (admin-only seeders) ----------

import random

BOT_NAMES = [
    "jaime les fucks", "NEGRO", "67", "couilles", "bitesenplastic", "Paulitodu64",
    "autiste tom", "seus", "Z3r0x", "ValouTV", "ta mere la pute",
    "lingam lugigig", "MC_Dojo", "NoScopeNico", "LeFromagedesnoirs", "snap: hector227",
    "AnanasSurPizza", "LeRatDuMetro", "BZH_Bot", "autsitemax", "niq ta mere alex",
    "le numero de tel de adrian: 06 52 03 45 03", "envoye c jeux a ma crush", "negro tout noir", "putes d'alex", "ChipsSaveurSel",
]

FAKE_REVIEW_LINES_FR = [
    "jai 30t autiste par second, comme dans ma cave", "guez", "Meilleur jeux de tout les temps, STP ajouter plus de trucs j'ai presque finis le jeu.",
    "Des bugs mais ça passe.", "Toute notre classe joue a ca en cours mdr, jai poste un tiktok, il a 12k vues", "caca prout gnt !",
    "J’ai reset par erreur… pls help :)", "Le prestige est satisfaisant.",
    "trop mal fait aprends a coder stp", "FAIT PLUS DE MISE A JOUER JE SUIS ADDICTE TA MERE LA PUTE MICHAEL",
]

FAKE_REVIEW_LINES_EN = [
    "Surprisingly ass ", "ass game, funny tho.", "I love niggers!",
    "YT: editxs_shorts" , "Came from Jonsmans discord profile, im fearless on dc", "Where did u fall off jonsman",
    "playing this in class, peak.", "Mid",
]

def _rand_username():
    return random.choice(BOT_NAMES) + (str(random.randint(1, 999)) if random.random() < 0.4 else "")

def _fake_progress():
    # Roughly log-normal-ish spread so a few are huge, most are small:
    cps = max(0.0, round(random.expovariate(1/2_000_000) * 1_000_000_000_000_000_000 , 2))  # avg ~2M cps
    count = max(cps * random.uniform(50, 300), random.uniform(1e3, 1e48))
    return {
        "v": 5,
        "count": float(count),
        "cps": float(cps),
        "shop": [],
        "saved_at": int(time.time()),
    }

def _fake_review(user):
    stars = random.choices([5,4,3,2,1], weights=[45,25,15,10,5], k=1)[0]
    text = random.choice(FAKE_REVIEW_LINES_FR + FAKE_REVIEW_LINES_EN)
    # small chance to append an emoji or extra bit
    if random.random() < 0.25:
        text += " ⭐"
    return {"u": user[:40] or "Anonymous", "stars": int(stars), "text": text[:800], "ts": int(time.time())}

def seed_bots(n=25, overwrite_existing=False, max_total=200):
    """
    Create up to n bot users with fake progress.
    - overwrite_existing=False: skip names that already exist
    - max_total: safety cap on total users
    """
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
    "prestige": _empty_prestige(),
    "bot": True,
    "bot_tick": int(time.time()),
}

            created += 1
            if len(users) >= max_total:
                break

        save_db(db)
        return created

def seed_fake_reviews(m=40):
    """
    Append m fake reviews from random names (new or existing).
    Keeps last 1000 reviews overall (same behavior as /api/reviews).
    """
    with lock:
        db = load_db()
        users = list((db.get("users") or {}).keys())
        if not users:
            users = [ _rand_username() for _ in range(10) ]  # fallback names

        db.setdefault("reviews", [])
        for _ in range(m):
            author = random.choice(users) if random.random() < 0.7 else _rand_username()
            db["reviews"].append(_fake_review(author))

        db["reviews"] = db["reviews"][-1000:]
        save_db(db)
        return m



# Admin-only HTTP triggers
@app.post("/admin/seed_bots")
def admin_seed_bots():
    if not is_admin():
        return "Forbidden", 403
    try:
        n = int(request.form.get("n", "25"))
        overwrite = request.form.get("overwrite") == "1"
    except:
        n = 25; overwrite = False
    made = seed_bots(n=n, overwrite_existing=overwrite)
    return jsonify({"ok": True, "created": made})

@app.post("/admin/seed_reviews")
def admin_seed_reviews():
    if not is_admin():
        return "Forbidden", 403
    try:
        m = int(request.form.get("m", "40"))
    except:
        m = 40
    made = seed_fake_reviews(m=m)
    return jsonify({"ok": True, "created": made})

# ---------- Admin: Delete reviews ----------
@app.post("/admin/delete_review")
def admin_delete_review():
    if not is_admin():
        return "Forbidden", 403

    try:
        ts = int(request.form.get("ts", "0"))  # timestamp unique du commentaire
    except:
        return "Bad timestamp", 400

    with lock:
        db = load_db()
        reviews = db.get("reviews", [])
        before = len(reviews)
        reviews = [r for r in reviews if int(r.get("ts", 0)) != ts]
        db["reviews"] = reviews[-1000:]  # garder max 1000
        save_db(db)
        after = len(reviews)

    return jsonify({"ok": True, "deleted": before - after})


@app.get("/api/me")
def api_me():
    return jsonify({
        "ok": True,
        "user": session.get("user"),
        "is_admin": is_admin()
    })



# ---------- Clicker ----------
@app.get("/clicker")
def clicker():
    lang = get_lang()
    with lock:
        db = load_db()
        _tick_bots(db)

    # OPEN the one-and-only triple-quoted string
    html = """<!doctype html><meta charset="utf-8"><title>Autists Clicker</title>
<style>
  :root{
    --bg:#000; --panel:#0b0b12; --panel2:#0f0f18; --muted:#b6b6c6; --border:#232334;
    --btn:#141625; --btnTxt:#e7e7f5; --violet:#7c3aed; --violet2:#a78bfa; --good:#22c55e; --red:#ef4444;
  }
  *{box-sizing:border-box} body{font-family:Inter,Arial;background:
     radial-gradient(800px 400px at 10% -10%, rgba(124,58,237,.25), transparent 60%),
     radial-gradient(900px 500px at 110% 20%, rgba(239,68,68,.18), transparent 65%),
     #000;color:#eee;margin:0;padding:18px}
  .wrap{max-width:1000px;margin:0 auto;background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--border);padding:16px;border-radius:22px;box-shadow:0 0 60px rgba(124,58,237,.08)}
  .row{display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap}
  /* toolbar layout (desktop + mobile) */
  .toolbar{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap}
  .toolbar-left,.toolbar-right{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
  @media (max-width:700px){
    .toolbar{flex-direction:column;align-items:stretch}
    .toolbar-right{justify-content:flex-start}
  }

  .btn{display:inline-flex;align-items:center;gap:8px;padding:10px 14px;border-radius:12px;border:1px solid var(--border);background:var(--btn);color:var(--btnTxt);text-decoration:none;cursor:pointer;transition:transform .05s ease}
  .btn:active{transform:scale(.98)}
  .btn.orange{background:linear-gradient(90deg,#7c3aed,#ef4444);border-color:#7c3aed}
  .btn.blue{background:#27284a;border-color:#2d2f58}
  .btn.green{background:#1f3b28;border-color:#2c5a39}
  .btn.red{background:#3a1f1f;border-color:#4a2a2a}
  .pill{padding:6px 10px;border:1px solid var(--border);border-radius:999px;color:#cfcfe8;background:#11121c}
  #click{font-size:34px;padding:22px 42px;border-radius:16px;box-shadow:0 0 0 0 rgba(124,58,237,.6); position:relative; overflow:hidden}
  #shop .card{display:flex;justify-content:space-between;align-items:center;border:1px solid #31314a;padding:14px;border-radius:14px;background:#121322}
  #topbar img#logo{max-height:42px;border-radius:10px;display:none}
  input,button{border-radius:10px;border:1px solid var(--border);padding:10px;background:#15172b;color:#eee}
  .statgrid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:10px 0}
  .stat{background:#0f1020;border:1px solid #2b2d4a;border-radius:14px;padding:10px;text-align:center}
  .stat .v{font-size:20px;font-weight:700}
  .shimmer{background:linear-gradient(90deg,rgba(124,58,237,.15),rgba(239,68,68,.15));filter:blur(30px);position:absolute;inset:-30px;z-index:-1}
/* Achievements modal */
#ach_backdrop{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;z-index:999}
#ach_modal{position:fixed;left:50%;top:50%;transform:translate(-50%,-50%);width:min(920px,90vw);max-height:80vh;overflow:auto;
  background:#0f1020;border:1px solid #2b2d4a;border-radius:16px;padding:16px;display:none;z-index:1000}
#ach_list{display:grid;grid-template-columns:1fr;gap:8px}
@media (min-width:800px){ #ach_list{grid-template-columns:1fr 1fr} }
.ach{border:1px solid #2b2d4a;border-radius:12px;padding:10px;background:#121322;display:flex;justify-content:space-between;gap:8px}
.ach.ok{border-color:#2f9657;background:#142016}
</style>

<div id="topbar" class="toolbar">
  <div class="toolbar-left" style="gap:8px">
    <button class="btn" onclick="setLang('fr')">Français</button>
    <button class="btn" onclick="setLang('en')">English</button>
    <a class="btn" id="nav_leaderboard" href="/leaderboard">🏆 Leaderboard</a>
    <a class="btn" id="nav_profile" href="/profile">👤 Profile</a>
    <img id="logo" alt="logo">
  </div>
  <div class="toolbar-right">
    <a class="btn" id="nav_home" href="/">← Home</a>
    <a class="btn blue" id="nav_login" href="/login">Login</a>
    <a class="btn blue" id="nav_register" href="/register">Register</a>
    <a class="btn red" href="/logout">Logout</a>
  </div>
</div>

<!-- >>> PASTE THE REST OF YOUR PAGE HERE, UNCHANGED
     This includes the section in your screenshot:
     - <!-- Public Update box -->
     - <!-- Rating summary -->
     - statgrid, click button, save/load buttons
     - prestige, shop, reviews
     - achievements modal
     - console
     - ALL the big <script> blocks
     and keep going until the very last closing </script> of the page. <<< -->

</script>
"""  # CLOSE the string ONLY once, here, after the final </script>

    # Post-process language/labels safely (not an f-string)
    html = html.replace('let LANG="fr";', f'let LANG="{lang}";')
    html = html.replace('setLang("fr");', f'setLang("{lang}");')
    html = html.replace(
        'function setLang(l){ LANG = LANGS[l]?l:"fr"; applyLang(); update(); }',
        """function setLang(l){
  if(!LANGS[l]){return;}
  const same = LANG === l;
  LANG = l;
  applyLang();
  update();
  if(same){ return; }
  fetch(`/lang?to=${l}`, {headers: {'X-Requested-With': 'XMLHttpRequest'}}).catch(()=>{});
}"""
    )
    html = html.replace(
        '  document.getElementById("lbl_shop").textContent = t("shop");\n  document.getElementById("c_msg").textContent = "";\n  const clickBtn=document.getElementById("click");\n  if(clickBtn) clickBtn.firstChild.nodeValue = t("click");\n  document.getElementById("cps_click").textContent = formatNum(cpsClick);\n  document.getElementById("rev_send").onclick = postReview;\n}',
        """  document.getElementById("lbl_shop").textContent = t("shop");
  document.getElementById("c_msg").textContent = "";
  const clickBtn=document.getElementById("click");
  if(clickBtn) clickBtn.firstChild.nodeValue = t("click");
  document.getElementById("cps_click").textContent = formatNum(cpsClick);
  document.getElementById("rev_send").onclick = postReview;
  const navLeader = document.getElementById("nav_leaderboard");
  if(navLeader) navLeader.textContent = `🏆 ${t("leaderboard")}`;
  const navProfile = document.getElementById("nav_profile");
  if(navProfile) navProfile.textContent = `👤 ${t("profile")}`;
  const navHome = document.getElementById("nav_home");
  if(navHome) navHome.textContent = `← ${t("home")}`;
  const navLogin = document.getElementById("nav_login");
  if(navLogin) navLogin.textContent = t("login");
  const navRegister = document.getElementById("nav_register");
  if(navRegister) navRegister.textContent = t("register");
}"""
    )

    return html



    html += r'''
  <h1 id="title" style="text-align:center;margin:10px 0;letter-spacing:.5px;text-shadow:0 0 18px rgba(124,58,237,.35)">Autists Clicker</h1>

    <!-- Public Update box -->
  <div id="update_box" class="stat" style="text-align:left;margin:10px 0">
    <div style="font-weight:700;margin-bottom:6px">Latest Update</div>
    <div id="update_text" style="white-space:pre-wrap;color:#cfd2ff">Loading…</div>
  </div>

  <!-- Rating summary -->
  <div class="stat" style="display:flex;justify-content:center;gap:10px;align-items:center">
    <div id="rating_summary" style="font-size:18px">⭐ 0.00 — 0 reviews</div>
  </div>


  <div class="statgrid">
    <div class="stat"><div class="k">Autists</div><div class="v" id="count">0</div></div>
    <div class="stat"><div class="k">a/s</div><div class="v" id="cps">0</div></div>
    <div class="stat"><div class="k">CPS (clicks/s)</div><div class="v" id="cps_click">0</div></div>
  </div>

  <div style="text-align:center">
    <button id="click" class="btn orange">+1<div class="shimmer"></div></button>
  </div>

  <div class="row" style="margin:12px 0;justify-content:center">
    <button id="btn_save"  class="btn green">Upload</button>
    <button id="btn_load"  class="btn blue">Load</button>
    <button id="btn_sync_shop" class="btn blue">Sync Shop</button>
    <span id="sync_msg" class="pill">…</span>
  </div>
  <div class="row" style="justify-content:center;margin:8px 0">
  <button id="btn_ach" class="btn blue">🏅 Achievements</button>
  <span id="ach_summary" class="pill">—</span>
</div>


    <div id="prestige" style="margin:12px 0;padding:12px;border:1px solid #2b2d4a;border-radius:14px;background:#0f1020">
    <div class="row" style="justify-content:space-between;gap:8px;align-items:center">
      <div>
        <b>Prestige — Tryzomiques:</b> <span id="tryz_bal">0</span>
        <span class="pill" style="margin-left:8px">If Ascend now: +<span id="tryz_est">0</span></span>
      </div>
      <button id="btn_ascend" class="btn red">Ascend (reset, keep upgrades)</button>
    </div>
    <div style="margin-top:12px">
      <h3 style="margin:6px 0">Prestige Upgrades</h3>
      <div id="prestige_shop" style="display:grid;gap:10px"></div>
    </div>
  </div>

  <h2 id="lbl_shop" style="text-align:center;margin-top:8px">Shop</h2>
  <div id="shop" style="display:grid;gap:12px;grid-template-columns:1fr;"></div>
  
  <div id="reviews" style="margin-top:16px;border:1px solid #2b2d4a;border-radius:14px;background:#0f1020;padding:12px">
    <h3 style="margin:6px 0">Reviews</h3>

    <!-- Submit -->
    <div style="display:grid;gap:8px;grid-template-columns:120px 1fr auto;align-items:start">
      <select id="rev_stars" style="padding:10px;border-radius:10px;border:1px solid #2b2d4a;background:#15172b;color:#eee">
        <option value="5">5 ★</option>
        <option value="4">4 ★</option>
        <option value="3">3 ★</option>
        <option value="2">2 ★</option>
        <option value="1">1 ★</option>
      </select>
      <textarea id="rev_text" rows="3" placeholder="Write a short review (public)" style="width:100%;padding:10px;border-radius:10px;border:1px solid #2b2d4a;background:#15172b;color:#eee"></textarea>
      <button id="rev_send" class="btn orange">Post</button>
    </div>
    <div id="rev_msg" class="pill" style="margin-top:6px">Be nice 🙂</div>

    <!-- List -->
    <div id="rev_list" style="display:grid;gap:10px;margin-top:12px"></div>
  </div>

  <div id="ach_backdrop"></div>
<div id="ach_modal">
  <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:8px">
    <h2 style="margin:0">Achievements</h2>
    <button id="ach_close" class="btn">Close</button>
  </div>
  <div id="ach_head" class="pill" style="margin-bottom:8px">Loading…</div>
  <div id="ach_list"></div>
</div>

  
  <div id="custom" style="margin-top:16px;border:1px dashed #34345a;padding:12px;border-radius:12px;background:#11121f">
    <h3 id="lbl_create" style="text-align:center">Create custom Autist (cost: 1000)</h3>
    <div style="display:grid;gap:8px;grid-template-columns:1fr 1fr auto">
      <input id="c_name" placeholder="Name">
      <input id="c_cost" type="number" min="10" step="10" placeholder="Base cost">
      <button id="c_make" class="btn">Create (1000)</button>
    </div>
    <p id="c_msg" style="color:#bcbce8;margin-top:6px"></p>
  </div>
</div>

<!-- Console (bottom of page) -->
<div id="console" class="card" style="margin-top:16px;border:1px solid #2b2d4a;border-radius:14px;background:#0f1020;padding:12px">
  <div style="display:flex;align-items:center;justify-content:space-between">
    <h3 style="margin:6px 0">Console</h3>
    <span class="pill">type: <b>help</b></span>
  </div>

  <div id="con_out" style="height:180px;overflow:auto;background:#0e1022;border:1px solid #2b2d4a;border-radius:10px;padding:8px;font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;white-space:pre-wrap"></div>

  <form id="con_form" style="display:flex;gap:8px;margin-top:8px" onsubmit="return false">
    <input id="con_in" placeholder="help" autocomplete="off" style="flex:1;padding:10px;border-radius:10px;border:1px solid #2b2d4a;background:#15172b;color:#eee">
    <button id="con_run" class="btn orange" type="button">Run</button>
    <button id="con_clear" class="btn" type="button">Clear</button>
  </form>
</div>



<script>
'''

// ===== i18n (client EN/FR) =====
const LANGS = {
  fr:{shop:"Boutique",count:"Autistes",cps:"a/s",click:"+1 Autiste",create:"Créer un Autiste custom (coût: 1000)",level:"Niveau",cost:"Coût",buy:"Acheter",sell:"Vendre",upload:"Uploader vers mon compte",load:"Charger depuis mon compte",reset:"Reset local",leaderboard:"Classement",profile:"Profil",home:"Accueil",login:"Connexion",register:"Inscription",not_enough:"Pas assez d’autistes (1000 requis).",invalid:"Nom + coût valide (≥ 10) requis.",created:(u)=>`Créé: ${u.name} — base ${formatNum(u.base)}, ~${formatNum(u.inc)}/s (aléatoire).`},
  en:{shop:"Shop",count:"Autists",cps:"a/s",click:"+1 Autist",create:"Create custom Autist (cost: 1000)",level:"Level",cost:"Cost",buy:"Buy",sell:"Sell",upload:"Upload to my account",load:"Load from my account",reset:"Reset local",leaderboard:"Leaderboard",profile:"Profile",home:"Home",login:"Login",register:"Register",not_enough:"Not enough autists (1000 required).",invalid:"Valid name + base cost (≥ 10) required.",created:(u)=>`Created: ${u.name} — base ${formatNum(u.base)}, ~${formatNum(u.inc)}/s (random).`}
};
let LANG="fr";
function setLang(l){ LANG = LANGS[l]?l:"fr"; applyLang(); update(); }
function t(k,...a){ const L=LANGS[LANG]||LANGS.fr; const v=L[k]; return (typeof v==="function")?v(...a):v; }
function applyLang(){
  document.getElementById("lbl_shop").textContent = t("shop");
  document.getElementById("c_msg").textContent = "";
  const clickBtn=document.getElementById("click");
  if(clickBtn) clickBtn.firstChild.nodeValue = t("click");
  document.getElementById("cps_click").textContent = formatNum(cpsClick);
  document.getElementById("rev_send").onclick = postReview;
}

function starRow(n){ return "★".repeat(n) + "☆".repeat(5-n); }

async function refreshAchievements(){
  try{
    const r = await fetch("/api/achievements",{cache:"no-store"});
    if(r.status===401) return; // not logged
    const j = await r.json();
    if(!j.ok) return;

    ACH.unlocked = new Set(j.unlocked||[]);
    ACH.count    = Number(j.count||0);
    ACH.total    = Number(j.total||0);
    ACH.mult     = Number(j.mult||1);
    ACH.all      = !!j.all;
    ACH.allBonus = Number(j.all_bonus||1000);

    // small summary
    const pct = ((ACH.count/Math.max(1,ACH.total))*100).toFixed(1);
    document.getElementById("ach_summary").textContent =
      `Unlocked: ${ACH.count}/${ACH.total} — +${((ACH.mult-1)*100).toFixed(1)}% a/s` +
      (ACH.all?` — All unlocked! +${ACH.allBonus}/s`:``);

    // reapply math
    recalc(); update();
  }catch(e){}
}

function openAch(){
  document.getElementById("ach_backdrop").style.display="block";
  document.getElementById("ach_modal").style.display="block";
  renderAchievementsModal();
}
function closeAch(){
  document.getElementById("ach_backdrop").style.display="none";
  document.getElementById("ach_modal").style.display="none";
}

function renderAchievementsModal(){
  const head = document.getElementById("ach_head");
  head.textContent = `Unlocked ${ACH.count}/${ACH.total} — Multiplier x${(ACH.mult||1).toFixed(2)}${ACH.all?` — +${ACH.allBonus}/s bonus`:``}`;

  const wrap = document.getElementById("ach_list");
  wrap.innerHTML = "";
  // Request defs on demand (they're also in the API we called)
  // But we cached them in the previous call:
  fetch("/api/achievements",{cache:"no-store"})
    .then(r=>r.json())
    .then(j=>{
      if(!j || !j.ok) return;
      const defs = j.defs||[];
      const have = new Set(j.unlocked||[]);
      defs.forEach(d=>{
        const ok = have.has(d.id);
        const row = document.createElement("div");
        row.className = "ach" + (ok ? " ok" : "");
        row.innerHTML = `
          <div>
            <div style="font-weight:700">${d.name}</div>
            <div style="opacity:.8">${d.desc}</div>
            <div style="opacity:.6;font-size:.9rem">${d.group.toUpperCase()}</div>
          </div>
          <div class="pill">${ok ? ("✓ +" + (((Number(d.mult||1)-1)*100).toFixed(2)) + "%") : "Locked"}</div>
        `;
        wrap.appendChild(row);
      });
    })
    .catch(()=>{});
}


async function loadUpdateBox(){
  try{
    const r = await fetch("/api/update", {cache:"no-store"});
    const j = await r.json();
    if(j.ok){
      document.getElementById("update_text").textContent = j.update || "—";
    }
  }catch(e){}
}

async function loadReviewSummary(){
  try{
    const r = await fetch("/api/reviews/summary",{cache:"no-store"});
    const j = await r.json();
    if(j.ok){
      const el = document.getElementById("rating_summary");
      el.textContent = `⭐ ${Number(j.avg||0).toFixed(2)} — ${j.count||0} reviews`;
    }
  }catch(e){}
}

function renderReviews(list){
  const wrap = document.getElementById("rev_list");
  wrap.innerHTML = "";
  if(!list || !list.length){
    wrap.innerHTML = `<div class="pill" style="justify-self:start">No reviews yet.</div>`;
    return;
  }
  list.forEach(r=>{
    const card = document.createElement("div");
    card.className = "card";
    card.style = "padding:10px;border-radius:12px;background:#121322;border:1px solid #31314a";
    const when = new Date((r.ts||0)*1000).toLocaleString();
    const stars = Number(r.stars)||0;

    card.innerHTML = `
      <div style="display:flex;justify-content:space-between;gap:8px;align-items:center">
        <div style="font-weight:700">${(r.u||"Anonymous")}</div>
        <div style="display:flex;gap:8px;align-items:center">
          <div class="pill">${"★".repeat(stars) + "☆".repeat(5-stars)}</div>
          ${ME.is_admin ? `<button class="btn red" data-del="${r.ts}">Supprimer</button>` : ``}
        </div>
      </div>
      <div style="margin-top:6px;white-space:pre-wrap">${(r.text||"").replace(/[<>&]/g, s => ({ "<":"&lt;", ">":"&gt;", "&":"&amp;" }[s]))}</div>
      <div style="opacity:.7;margin-top:6px;font-size:.85rem">${when} — <span class="pill">ts: ${r.ts}</span></div>
    `;

    if (ME.is_admin){
      const btn = card.querySelector(`[data-del="${r.ts}"]`);
      btn.onclick = async ()=>{
        try{
          const res = await fetch("/admin/delete_review", {
            method: "POST",
            headers: {"Content-Type": "application/x-www-form-urlencoded"},
            body: "ts=" + encodeURIComponent(r.ts)
          });
          const j = await res.json().catch(()=>({}));
          if(j && j.ok){
            card.remove();            // retire visuellement
            loadReviewSummary();      // maj moyenne & compteur
          }else{
            alert("Suppression impossible");
          }
        }catch(e){
          alert("Erreur réseau");
        }
      };
    }

    wrap.appendChild(card);
  });
}


async function loadReviews(){
  try{
    const r = await fetch("/api/reviews",{cache:"no-store"});
    const j = await r.json();
    if(j.ok){ renderReviews(j.reviews||[]); }
  }catch(e){}
}

async function postReview(){
  const stars = Number(document.getElementById("rev_stars").value);
  const text  = (document.getElementById("rev_text").value||"").trim();
  const msg   = document.getElementById("rev_msg");
  if(!text){ msg.textContent = "Please write something."; return; }
  try{
    const r = await fetch("/api/reviews",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body: JSON.stringify({stars, text})
    });
    const j = await r.json();
    if(j.ok){
      document.getElementById("rev_text").value = "";
      msg.textContent = "Thanks for the review!";
      await loadReviewSummary();
      await loadReviews();
    }else{
      msg.textContent = j.err || "Error";
    }
  }catch(e){
    msg.textContent = "Network error";
  }
}


// ===== SHOP DATA =====
const mk = (name, key, base, inc) => ({ key, name, base, inc, lvl: 0 });

const earlyUnits = [
  mk("Petit caillou Autiste", "rock", 10, 1),
  mk("Autiste en bois", "wood", 50, 3),
  mk("Stylo Autiste", "pen", 200, 5),
];

const coreUnits = [
  mk("Remi - Autiste", "remi", 1_000, 15),
  mk("Jonsman - Autiste", "jonsman", 10_000, 150),
  mk("Hector - Autiste", "hector", 30_000, 500),
  mk("Valentin - Autiste", "valentin", 75_000, 1_000),
  mk("Johan - Autiste", "johan", 120_000, 2_000),
  mk("Viki - Autiste", "viki", 180_000, 3_000),
  mk("Paul - Autiste", "paul", 240_000, 4_500),
  mk("Sa Mère - Autiste", "samere", 320_000, 6_000),
];

const midUnits = [
  mk("Chaussures Autistes", "shoes", 500_000, 12_000),
  mk("Usine Autiste", "factory", 1_000_000, 30_000),
  mk("Ferme Autiste", "farm", 2_500_000, 80_000),
  mk("Tour Autiste", "tower", 5_000_000, 150_000),
  mk("Laboratoire Autiste", "lab", 10_000_000, 400_000),
  mk("Serveur Autiste", "server", 20_000_000, 900_000),
  mk("Mine Autiste", "mine", 50_000_000, 2_000_000),
  mk("Bunker Autiste", "bunker", 100_000_000, 5_000_000),
];

const gigaUnits = [
  mk("Autiste Fusion Reactor", "fusion", 500_000_000, 30_000_000),
  mk("Quantum Portail Autiste", "qportal", 2_000_000_000, 150_000_000),
  mk("AI Swarm Autiste", "aiswarm", 10_000_000_000, 1_000_000_000),
  mk("Planet Factory Autiste", "planet", 50_000_000_000, 5_000_000_000),
  mk("Black Hole Autiste Collider", "bhc", 200_000_000_000, 15_000_000_000),
  mk("Multiverse Franchise Autiste", "multi", 1_000_000_000_000, 100_000_000_000),
  mk("Time Machine Autiste", "timemachine", 5_000_000_000_000, 500_000_000_000),
  mk("Galactic Autiste Conglomerate", "galactic", 20_000_000_000_000, 2_000_000_000_000),
  mk("Dimensional Autiste Empire", "dimemp", 100_000_000_000_000, 15_000_000_000_000),
];

const randomUnits = [
  mk("Chaussettes Autistes", "sock", 750_000, 25_000),
  mk("Autiste iPhone 34", "iphone", 5_000_000, 200_000),
  mk("Autiste Tesla Cybertruck", "tesla", 20_000_000, 800_000),
  mk("Autiste PC Gamer", "pcgamer", 75_000_000, 3_000_000),
  mk("Autiste McDo Factory", "mcdo", 200_000_000, 12_000_000),
  mk("Autiste SpaceX Rocket", "rocket", 1_000_000_000, 100_000_000),
  mk("Autiste Crypto Mine", "crypto", 5_000_000_000, 500_000_000),
  mk("Autiste Nuclear Plant", "nuclear", 20_000_000_000, 2_000_000_000),
  mk("Autiste Mars Colony", "mars", 100_000_000_000, 10_000_000_000),
  mk("Autiste Black Market", "black", 500_000_000_000, 50_000_000_000),
];

const megaUnits = [
  mk("Autiste Dyson Sphere", "dyson", 1e15, 5e11),
  mk("Empire Autiste Galactique", "empiregal", 1e16, 1e14),
  mk("Autiste Univers Portable", "universe", 1e18, 2e16),
  mk("Simulation Autiste Infinie", "simul", 1e20, 1e18),
  mk("Autiste Dieu Ancien", "god", 1e24, 1e19),
  mk("Autiste Omnivers", "omniverse", 1e28, 1e22),
  mk("Autiste Source du Tout", "source", 1e33, 1e26),
];
const mythicUnits = [
  mk("Autiste Quantum Foam",         "qfoam",        1e36, 1e30),
  mk("Autiste Neutrino Forge",       "neutrino",     5e36, 2e30),
  mk("Autiste Gluon Foundry",        "gluon",        1e37, 5e30),
  mk("Autiste Planck Reactor",       "planck",       5e37, 1e31),
  mk("Autiste Tachyon Drive",        "tachyon",      1e38, 2e31),
  mk("Autiste Singularity Core",     "singularity",  5e38, 5e31),
  mk("Autiste Entanglement Array",   "entangle",     1e39, 1e32),
  mk("Autiste Higgs Farm",           "higgs",        5e39, 2e32),
  mk("Autiste Wormhole Lattice",     "wormhole",     1e40, 5e32),
  mk("Autiste Dyson Cloud",          "dysoncloud",   5e40, 1e33),
  mk("Autiste Matryoshka Brain",     "matbrain",     1e41, 2e33),
  mk("Autiste Chrono Forge",         "chronoforge",  5e41, 5e33),
  mk("Autiste Probability Engine",   "probability",  1e42, 1e34),
  mk("Autiste Antimatter Sun",       "antimatter",   5e42, 2e34),
  mk("Autiste Quantum Computer",     "qcomputer",    1e43, 5e34),
  mk("Autiste Dark Energy Tap",      "darkenergy",   5e43, 1e35),
  mk("Autiste Perfect Vacuum",       "vacuum",       1e44, 2e35),
  mk("Autiste Brane Weave",          "branes",       5e44, 5e35),
  mk("Autiste Multiversal Hub",      "multihub",     1e45, 1e36),
  mk("Autiste Primordial Forge",     "primordial",   5e45, 2e36),
  mk("Autiste Ω Engine",             "omega",        1e46, 5e36),
  mk("Autiste Alpha-Omega Ring",     "alphaomega",   5e46, 1e37),
  mk("Autiste Akashic Archive",      "akashic",      1e47, 2e37),
  mk("Autiste Oracle Mesh",          "oracle",       5e47, 5e37),
  mk("Autiste Creation Foundry",     "creation",     1e48, 1e38),
];

const ultraUnits = [
  mk("Autiste Quantum Matryoshka",      "matryoshka",   1e36, 1e27),
  mk("Autiste Brane Weaving Loom",      "branloom",     3e36, 3e27),
  mk("Autiste Vacuum Forge",            "vacuumforge",  1e37, 1e28),
  mk("Autiste Dark Energy Turbine",     "darkenergy",   3e37, 3e28),
  mk("Autiste Cosmic Filament",         "filament",     1e38, 1e29),
  mk("Autiste Hypercluster",            "hypercluster", 3e38, 4e29),
  mk("Autiste Inflation Engine",        "inflation",    1e39, 1e30),
  mk("Autiste False Vacuum Drill",      "fvacuum",      3e39, 3e30),
  mk("Autiste Entropy Reverser",        "entropy",      1e40, 1e31),
  mk("Autiste Causal Lattice",          "lattice",      3e40, 3e31),
  mk("Autiste Axion Farm",              "axion",        1e42, 1e32),
  mk("Autiste Tachyon Accelerator",     "tachyon",      1e43, 3e32),
  mk("Autiste Warp Foundry",            "warp",         1e45, 1e33),
  mk("Autiste Multiversal Loom",        "multiloom",    3e45, 3e33),
  mk("Autiste Chrono Smithy",           "chrono",       1e48, 1e34),
  mk("Autiste Probability Mine",        "probmine",     3e48, 3e34),
  mk("Autiste Ontology Engine",         "ontology",     1e51, 1e35),
  mk("Autiste Kardashev Hub",           "karda",        1e54, 1e36),
  mk("Autiste Omega Foundry",           "omegafoundry", 1e57, 1e37),
  mk("Autiste Reality Printer",         "rprinter",     1e60, 1e38),
  mk("Autiste Prime Universe Seeder",   "primes",       1e63, 1e39),
  mk("Autiste Meta-Godworks",           "metagod",      1e66, 1e40),
  mk("Autiste Omni-Anvil",              "omnianvil",    1e69, 1e41),
  mk("Autiste Eternity Mill",           "eternity",     1e72, 1e42),
  mk("Autiste Origin Forge",            "originforge",  1e75, 1e43),
];


const DEFAULT_SHOP = [
  ...earlyUnits, 
  ...coreUnits, 
  ...midUnits, 
  ...randomUnits, 
  ...gigaUnits, 
  ...megaUnits,
  ...ultraUnits
];


// Load the shop data from the server
async function loadShopData() {
    try {
        const response = await fetch("/api/load_shop");
        const data = await response.json();

        if (data.ok && data.shop) {
            // Update the local shop with the new data
            shop = data.shop;
            renderShop();  // Re-render the shop with updated data
        }
    } catch (error) {
        console.error("Error fetching shop data:", error);
    }
}



// ===== STATE & SAVE =====
let count = 0, cps = 0;
// Prestige (server-authoritative)
let prestige = { tryz: 0, asc: 0, up: {} };
let prestigeDefs = []; // from server

// Achievements (client cache)
let ACH = { unlocked:new Set(), mult:1.0, total:0, count:0, all:false, allBonus:1000 };
function achievementsMult(){ return ACH.mult || 1.0; }


function prestigeGet(key){ return Number((prestige.up||{})[key]||0); }
function prestigeMultCps(){
  const lvl = prestigeGet("cps_mult");
  return Math.pow(1.10, lvl); // +10% per lvl
}
function prestigeMultClick(){
  const lvl = prestigeGet("click_mult");
  return Math.pow(1.25, lvl); // +25% per lvl
}
function prestigeStartBoost(){
  const lvl = prestigeGet("start_boost");
  return 10000 * lvl;
}
function updateTryzEst(){
  const est = Math.floor(((cps||0) / 1_000_000) * ascMult());
  document.getElementById("tryz_est").textContent = est;
}
function ascMult(){ return 1 + 0.10 * prestigeGet("asc_mult"); }
function shopDiscount(){ return Math.min(0.02 * prestigeGet("shop_discount"), 0.50); } // max 50%
function flatCps(){ return 100 * prestigeGet("flat_cps"); }
function refundRate(){ return Math.min(0.50 + 0.05 * prestigeGet("refund_plus"), 0.95); } // base 50%
function critChance(){ return Math.min(0.05 * prestigeGet("lucky_clicks"), 0.75); } // max 75%
function critMult(){ return 3; }
function pct(n){ return Math.round(n) + "%"; }

const PRESTIGE_TEXT = {
  cps_mult: (lvl)=> {
    const now  = Math.pow(1.10, lvl);
    const next = Math.pow(1.10, lvl+1);
    return `Passive a/s: x${now.toFixed(2)} ➜ x${next.toFixed(2)} (+10%/lvl)`;
  },
  click_mult: (lvl)=> {
    const now  = Math.pow(1.25, lvl);
    const next = Math.pow(1.25, lvl+1);
    return `Click power: x${now.toFixed(2)} ➜ x${next.toFixed(2)} (+25%/lvl)`;
  },
  start_boost: (lvl)=> {
    const now  = 10000*lvl;
    const next = 10000*(lvl+1);
    return `Start bonus: +${formatNum(now)} ➜ +${formatNum(next)} (+10k/lvl)`;
  },
  asc_mult: (lvl)=> {
    const now  = 10*lvl;
    const next = 10*(lvl+1);
    return `Ascend yield: +${now}% ➜ +${next}% (+10%/lvl)`;
  },
  shop_discount: (lvl)=> {
    const now  = Math.min(2*lvl,50);
    const next = Math.min(2*(lvl+1),50);
    return `Shop prices: -${now}% ➜ -${next}% (cap 50%)`;
  },
  flat_cps: (lvl)=> {
    const now  = 100*lvl;
    const next = 100*(lvl+1);
    return `Flat a/s: +${formatNum(now)} ➜ +${formatNum(next)} (+100/lvl)`;
  },
  refund_plus: (lvl)=> {
    const now  = Math.min(50 + 5*lvl, 95);
    const next = Math.min(50 + 5*(lvl+1), 95);
    return `Sell refund: ${now}% ➜ ${next}% (cap 95%)`;
  },
  lucky_clicks: (lvl)=> {
    const now  = Math.min(5*lvl, 75);
    const next = Math.min(5*(lvl+1), 75);
    return `Crit chance: ${now}% ➜ ${next}% (x3 crits)`;
  },
};


let shop = JSON.parse(JSON.stringify(DEFAULT_SHOP));

// Clicks-per-second meter
let clickTimes = [];
let cpsClick = 0;
const CPS_WINDOW_MS = 2000;

// ===== UTILS =====
function addCustom(name, base){
  const unit = { key:`custom_${Date.now()}`, name, base:Number(base), inc:rndInc(base), lvl:0 };
  shop.push(unit);
  count -= 1000;
  recalc(); saveLocal();
  return unit;
}

function formatNum(n){
  n = Number(n)||0;
    const scales = [
    [1e75,"qavg"], [1e72,"tvg"], [1e69,"dvg"], [1e66,"uvg"], [1e63,"vg"],
    [1e60,"nd"],   [1e57,"od"],  [1e54,"spd"], [1e51,"sxd"], [1e48,"qid"],
    [1e45,"qad"],  [1e42,"td"],  [1e39,"dd"],  [1e36,"ud"],  [1e33,"de"],
    [1e30,"no"],   [1e27,"oc"],  [1e24,"sp"],  [1e21,"sx"],  [1e18,"qi"],
    [1e15,"qa"],   [1e12,"t"],   [1e9,"b"],    [1e6,"m"],    [1e3,"k"],
  ];
  for (const [div,suf] of scales){
    if (Math.abs(n) >= div){
      const val = (n/div).toFixed(2).replace(/\\.00$/,'').replace(/(\\.\\d*[1-9])0$/,'$1');
      return `${val}${suf}`;
    }
  }
  return String(Math.trunc(n));
}
function costOf(i){
  const raw = Math.floor(i.base * Math.pow(1.15, i.lvl));
  const disc = shopDiscount();
  return Math.max(1, Math.floor(raw * (1 - disc)));
}
function effectiveInc(it){ return it.inc; }
function recalc(){
  const base = shop.reduce((s,x)=> s + effectiveInc(x)*(Number(x.lvl)||0), 0);
  let next = Math.max(0, base * prestigeMultCps() + flatCps());
  next = next * achievementsMult();
  if (ACH.all) next += (ACH.allBonus||0);     // +1000 a/s if ALL achievements
  cps = next;
}
function rndInc(base){
  if(!base || base<=0) return 1;
  let min = Math.floor(Math.sqrt(base));
  let max = Math.floor(Math.sqrt(base)*75);
  if(min<1) min=1;
  const val = min + Math.random()*(max-min);
  return Math.round(val);
}
function clickPower(){
  const base = Math.max(1, Math.floor(1 + (cps/1000)*25));
  return Math.floor(base * prestigeMultClick());
}
function updateClickButton(){
  const btn = document.getElementById("click");
  if (btn) btn.childNodes[0].nodeValue = "+" + formatNum(clickPower());
}

// Clicks per second (client-side)
function pushClick(){
  const now = Date.now();
  clickTimes.push(now);
  clickTimes = clickTimes.filter(t=> now - t <= CPS_WINDOW_MS);
  cpsClick = clickTimes.length / (CPS_WINDOW_MS/1000);
  document.getElementById("cps_click").textContent = cpsClick.toFixed(2);
}

// ===== SAVE =====
function saveLocal(){
  try{ localStorage.setItem("autistes_clicker", JSON.stringify({v:5,count,cps,shop})); }catch(e){}
}
function loadLocal(){
  const raw = localStorage.getItem("autistes_clicker");
  if(!raw) return;
  try{
    const d = JSON.parse(raw);
    count = Number(d.count)||0;
    cps   = Number(d.cps)||0;
    if(Array.isArray(d.shop)){
      shop = d.shop.map(it=>({
        key: it.key||("unit-"+Date.now()),
        name: it.name||"Unit",
        base: Number(it.base)||10,
        inc:  Number(it.inc)||1,
        lvl:  Number(it.lvl)||0
      }));
    }
  }catch(e){}
}

// ===== RENDER =====
function render(){
  const el=document.getElementById("shop");
  el.innerHTML="";
  shop.forEach((it,i)=>{
    const price=costOf(it), canBuy=count>=price;
    const canSell = it.lvl>0;
    const row=document.createElement("div");
    row.className="card";
    const btnStyle = canBuy ? "btn orange" : "btn";
    const sellStyle= canSell ? "btn red" : "btn";
    const refundPct = refundRate();
    const refund = formatNum(Math.floor(price * refundPct));

    
    row.innerHTML=`
      <div style="text-align:left">
        <div style="font-size:18px;"><b>${it.name}</b> (+${formatNum(effectiveInc(it))}/s per lvl)</div>
        <div>Level: ${formatNum(it.lvl)} — Cost: ${formatNum(price)}</div>
      </div>
      <div style="display:flex; gap:6px">
        <button data-i="${i}" class="${btnStyle}">Buy (+${formatNum(effectiveInc(it))}/s)</button>
        <button data-sell="${i}" class="${sellStyle}" ${canSell?"":"disabled"}>
          Sell (-1) → +${refund}
        </button>
      </div>
    `;

    row.querySelector("[data-i]").onclick=()=>{
      if(count>=price){
        count-=price; it.lvl++; recalc(); update(); render(); saveLocal(); updateClickButton();
      }
    };
    const sbtn = row.querySelector("[data-sell]");
    if(canSell){ sbtn.onclick=()=>{ sellItem(i); }; }
    el.appendChild(row);
  });
}

// Sell 1 level → 50% of current price
function sellItem(i){
  const it = shop[i];
  if(!it || it.lvl<=0) return;
  const price = costOf(it);
  const refund = Math.floor(price * refundRate());
  it.lvl -= 1;
  count  += refund;
  recalc(); render(); saveLocal(); updateClickButton();
}

// ===== UI =====
function update(){
  document.getElementById("count").textContent = formatNum(count);
  document.getElementById("cps").textContent   = formatNum(cps);
    document.getElementById("tryz_bal").textContent = formatNum(prestige.tryz||0);
  updateTryzEst();
  render();
  updateClickButton();
}
document.getElementById("click").onclick = () => {
  let add = clickPower();
  if (Math.random() < critChance()) add = Math.floor(add * critMult());
  count += add;
  pushClick();
  update();
  saveLocal();
};


document.getElementById("c_make").onclick=()=>{
  const name=(document.getElementById("c_name").value||"").trim();
  const base=Number(document.getElementById("c_cost").value);
  const msg=document.getElementById("c_msg");
  if(count<1000){ msg.textContent=t("not_enough"); return; }
  if(!name || !isFinite(base) || base<10){ msg.textContent=t("invalid"); return; }
  const u=addCustom(name,base); update(); msg.textContent=t("created",u); document.getElementById("c_name").value=""; document.getElementById("c_cost").value="";
};

// ===== Server sync =====
async function saveServer(){
  const payload = { v:5, count, cps, shop };
  try{
    const r = await fetch("/api/save_progress",{
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      credentials:"same-origin",
      body: JSON.stringify(payload)
    });
    if (r.status === 401){
      document.getElementById("sync_msg").textContent = "Login first";
      return;
    }
    const j = await r.json().catch(()=>({}));
    document.getElementById("sync_msg").textContent = j.ok ? "✓" : "x";
    if (j && j.ok){ refreshAchievements(); }
  }catch(e){
    document.getElementById("sync_msg").textContent = "network x";
  }
}

async function loadServer(){
  try{
    const r = await fetch("/api/load_progress",{ credentials:"same-origin" });
    if (r.status === 401){
      document.getElementById("sync_msg").textContent = "Login first";
      return;
    }
    const j = await r.json().catch(()=>({}));
    if (j.ok && j.progress){
      const p = j.progress;
      count = Number(p.count)||0; cps = Number(p.cps)||0;
      if (Array.isArray(p.shop)) shop = p.shop;
      update(); saveLocal();
      document.getElementById("sync_msg").textContent = "✓";
    } else {
      document.getElementById("sync_msg").textContent = "x";
    }
  }catch(e){
    document.getElementById("sync_msg").textContent = "network x";
  }
}


async function awaitPrestige(){
  try{
    const r = await fetch("/api/prestige",{cache:"no-store"});
    const j = await r.json();
    if(j.ok){
      prestige = j.prestige || prestige;
      prestigeDefs = j.upgrades || [];
      renderPrestigeShop();
    }
  }catch(e){}
}

function renderPrestigeShop(){
  const wrap = document.getElementById("prestige_shop");
  wrap.innerHTML = "";

  prestigeDefs.forEach(def=>{
    const lvl  = prestigeGet(def.key);
    const next = lvl + 1;
    const cost = def.base * next;
    const can  = (prestige.tryz||0) >= cost && lvl < def.max;
    const desc = (PRESTIGE_TEXT[def.key]?.(lvl)) || def.name;

    const row = document.createElement("div");
    row.className = "card";
    row.style = "display:flex;justify-content:space-between;align-items:center;border:1px solid #31314a;padding:12px;border-radius:12px;background:#121322;gap:8px";

    row.innerHTML = `
      <div style="max-width:70%">
        <div style="font-weight:700">${def.name}</div>
        <div style="opacity:.8;font-size:.95rem;margin-top:2px">${desc}</div>
        <div style="opacity:.7;font-size:.9rem;margin-top:2px">Level: ${lvl}/${def.max}</div>
      </div>
      <div style="display:flex;align-items:center;gap:8px">
        <div class="pill">Cost: ${formatNum(cost)}</div>
        <button class="btn ${can?'orange':''}" data-up="${def.key}" ${can?'':'disabled'}>${can?'Buy':'Need ' + formatNum(cost)}</button>
      </div>
    `;

    row.querySelector("[data-up]").onclick = async ()=>{
      try{
        const r = await fetch("/api/buy_prestige_upgrade",{
          method:"POST",headers:{"Content-Type":"application/json"},
          body:JSON.stringify({key:def.key})
        });
        const j = await r.json();
        if(j.ok){
          prestige = j.prestige;
          recalc(); update(); renderPrestigeShop(); saveLocal();
        }
      }catch(e){}
    };
  // Add Sell (50%) button if level > 0
if (lvl > 0) {
  const sellBtn = document.createElement("button");
  sellBtn.className = "btn red";
  sellBtn.textContent = "Sell (50%)";
  sellBtn.onclick = async () => {
    try {
      const r = await fetch("/api/sell_prestige_upgrade", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({key: def.key})
      });
      const j = await r.json();
      if (j.ok) {
        prestige = j.prestige || prestige;
        recalc(); update(); renderPrestigeShop(); saveLocal();
      } else {
        alert(j.err || "Sell failed");
      }
    } catch (e) {
      alert("Sell error");
    }
  };
  // place it next to the buy button (right side)
  const controls = row.lastElementChild; // right-side controls
  controls.appendChild(sellBtn);
}
    wrap.appendChild(row);
  });
}



document.getElementById("btn_ascend").onclick = async ()=>{
  const est = Math.floor(((cps||0)/1_000_000) * ascMult());
  if(!confirm(`Ascend now? You will reset to 0 and gain +${est} tryzomiques.`)) return;
  try{
    const r = await fetch("/api/ascend",{method:"POST"});
    const j = await r.json();
    if(j.ok){
      // wipe local, apply fresh save from server, then reload prestige
      localStorage.removeItem("autistes_clicker");
      count = 0; cps = 0; shop = JSON.parse(JSON.stringify(DEFAULT_SHOP));
      prestige = j.prestige || prestige;
      // server already saved a fresh progress; also pull it
      await loadServer();
      await awaitPrestige();
      // apply start boost to brand new run
      count += prestigeStartBoost();
      recalc(); render(); update(); saveLocal();
      document.getElementById("sync_msg").textContent = `Ascended +${j.award}`;
    } else {
      alert(j.err || "Ascend failed");
    }
  }catch(e){ alert("Ascend error"); }
};
document.getElementById("btn_save").onclick=saveServer;
document.getElementById("btn_ach").onclick = openAch;
document.getElementById("ach_close").onclick = closeAch;
document.getElementById("ach_backdrop").onclick = closeAch;
document.getElementById("btn_load").onclick=loadServer;

// Sync shop without reset
function syncShopWithDefaults(){
  const curMap = new Map(shop.map(it=>[it.key,it]));
  DEFAULT_SHOP.forEach(def=>{
    const cur=curMap.get(def.key);
    if(cur){ cur.name=def.name; cur.base=def.base; cur.inc=def.inc; }
    else { shop.push({...def, lvl:0}); }
  });
  recalc(); render(); update(); saveLocal();
}
document.getElementById("btn_sync_shop").onclick=()=>{ syncShopWithDefaults(); document.getElementById("sync_msg").textContent="Shop sync ✓"; };

// Settings bg/logo
async function applySettings(){
  try{
    const r=await fetch("/api/settings"); const j=await r.json();
    if(j.ok){
      if(j.settings.bg){ document.body.style.backgroundImage = `url('${j.settings.bg}')`; document.body.style.backgroundSize="cover"; document.body.style.backgroundAttachment="fixed"; }
      const logoEl=document.getElementById("logo");
      if(j.settings.logo){ logoEl.src=j.settings.logo; logoEl.style.display="block"; }
    }
  }catch(e){}
}

let ME = { is_admin: false, user: null };

function setAuthUI(){
  const saveBtn = document.getElementById("btn_save");
  const loadBtn = document.getElementById("btn_load");
  const msg = document.getElementById("sync_msg");
  if (ME.user){
    saveBtn.disabled = false; loadBtn.disabled = false;
  }else{
    saveBtn.disabled = true; loadBtn.disabled = true;
    msg.textContent = "Login to sync";
  }
}


async function loadMe(){
  try{
    const r = await fetch("/api/me", {cache:"no-store"});
    const j = await r.json();
    if(j && j.ok){
      ME = { is_admin: !!j.is_admin, user: j.user || null };
    }
  }catch(e){}
}


// Boot
setLang("fr");
applyLang();
applySettings();
loadLocal();
refreshAchievements();
recalc();
render();
loadUpdateBox();
loadReviewSummary();
loadMe().then(()=>{ setAuthUI(); return loadReviews(); });  // auth-gated UI
awaitPrestige().then(()=>{
  // apply start boost only if fresh (local count==0 and no shop levels)
  const anyLvl = shop.some(s=> (s.lvl||0) > 0);
  if (count === 0 && !anyLvl) {
    count += prestigeStartBoost();
  }
  update();
});
setInterval(()=>{
  count += cps;
  updateTryzEst();
  update();
  saveLocal();
},1000);
</script>


<script>
// ===== Mini Console =====
(function(){
  const out = document.getElementById('con_out');
  const form = document.getElementById('con_form');
  const input = document.getElementById('con_in');
  const btnRun = document.getElementById('con_run');
  const btnClear = document.getElementById('con_clear');

  if(!out || !input){ return; } // if the block wasn't inserted, bail

  const H = { list: [], idx: -1 };

  function conPrint(msg){
    const line = document.createElement('div');
    line.textContent = String(msg);
    out.appendChild(line);
    out.scrollTop = out.scrollHeight;
  }
  function conPrintKV(k, v){
    const line = document.createElement('div');
    line.innerHTML = `<span style="opacity:.8">${k}:</span> <b>${v}</b>`;
    out.appendChild(line);
    out.scrollTop = out.scrollHeight;
  }
  function splitArgs(s){
    // supports quoted segments: buy "Planet Factory Autiste" 3
    const m = s.match(/"([^"]*)"|'([^']*)'|\S+/g) || [];
    return m.map(x => x.replace(/^['"]|['"]$/g,''));
  }
  function findUnit(keyOrName){
    if(!keyOrName) return null;
    const q = keyOrName.toLowerCase();
    // try by key
    let it = shop.find(u => (u.key||'').toLowerCase() === q);
    if(it) return it;
    // fallback: name contains
    it = shop.find(u => (u.name||'').toLowerCase().includes(q));
    return it || null;
  }

  async function runCmd(line){
    if(!line.trim()) return;
    conPrint(`> ${line}`);
    H.list.push(line);
    H.idx = H.list.length;

    const [cmd, ...args] = splitArgs(line.trim());
    const c = (cmd||'').toLowerCase();

    if(!commands[c]){
      conPrint("Unknown command. Type 'help'.");
      return;
    }
    try{
      await commands[c](args);
    }catch(e){
      conPrint('Error: ' + (e?.message || e));
    }
  }

  const commands = {
    help(){
      conPrint("Available commands:");
      conPrint("  help                          — show this help");
      conPrint("  stats                         — show key stats");
      conPrint("  list [n]                      — list first n shop items (default 10)");
      conPrint("  info <key|name>               — show details for a unit");
      conPrint("  buy <key|name> [n]            — buy n levels (default 1)");
      conPrint("  sell <key|name> [n]           — sell n levels (default 1)");
      conPrint("  add <n>                       — add n autists locally");
      conPrint("  setlang <fr|en>               — switch UI language");
      conPrint("  save | load                   — sync with your account");
      conPrint("  syncshop                      — refresh shop defs (names/costs)");
      conPrint("  prestige                      — show prestige & ascend estimate");
      conPrint("  ascend                        — click the Ascend button");
      conPrint("  clear                         — clear console output");
    },

    stats(){
      conPrintKV('Count', formatNum(count));
      conPrintKV('a/s', formatNum(cps));
      conPrintKV('Clicks/s (local)', (cpsClick||0).toFixed(2));
      conPrintKV('Prestige — tryz', formatNum((prestige.tryz||0)));
      conPrintKV('Prestige — asc', String(prestige.asc||0));
    },

    list(args){
      const n = Math.max(1, Math.min(100, parseInt(args[0]||'10',10)));
      shop.slice(0,n).forEach(it=>{
        conPrint(`${it.key.padEnd(14,' ')}  ${it.name} — lvl ${it.lvl} — cost ${formatNum(costOf(it))} — +${formatNum(effectiveInc(it))}/s/lvl`);
      });
    },

    info(args){
      const it = findUnit(args.join(' '));
      if(!it){ conPrint('Unit not found'); return; }
      conPrintKV('Key', it.key);
      conPrintKV('Name', it.name);
      conPrintKV('Level', formatNum(it.lvl));
      conPrintKV('Base cost', formatNum(it.base));
      conPrintKV('Income/level', formatNum(effectiveInc(it)));
      conPrintKV('Buy cost now', formatNum(costOf(it)));
    },

    buy(args){
      const it = findUnit(args[0]);
      if(!it){ conPrint('Unit not found'); return; }
      let n = Math.max(1, parseInt(args[1]||'1',10));
      let bought = 0;
      while(n-- > 0){
        const price = costOf(it);
        if(count >= price){
          count -= price;
          it.lvl++;
          bought++;
        }else break;
      }
      recalc(); update(); saveLocal(); updateClickButton();
      conPrint(`Bought ${bought} × ${it.name}.`);
    },

    sell(args){
      const it = findUnit(args[0]);
      if(!it){ conPrint('Unit not found'); return; }
      let n = Math.max(1, parseInt(args[1]||'1',10));
      let sold = 0;
      while(n-- > 0 && it.lvl > 0){
        const price = costOf(it);
        const refund = Math.floor(price * refundRate());
        it.lvl -= 1;
        count  += refund;
        sold++;
      }
      recalc(); render(); saveLocal(); updateClickButton();
      conPrint(`Sold ${sold} × ${it.name}.`);
    },

    add(args){
      const n = Number(args[0]||0);
      if(!isFinite(n)){ conPrint('Usage: add <number>'); return; }
      count += n;
      recalc(); update(); saveLocal(); updateClickButton();
      conPrint(`Added ${formatNum(n)}.`);
    },

    setlang(args){
      const l = (args[0]||'').toLowerCase();
      if(l!=='fr' && l!=='en'){ conPrint("Usage: setlang fr|en"); return; }
      setLang(l); update(); conPrint(`Language set to ${l}.`);
    },

    async save(){ await saveServer(); conPrint('Save requested.'); },
    async load(){ await loadServer(); conPrint('Load requested.'); },

    syncshop(){ syncShopWithDefaults(); conPrint('Shop synced with defaults.'); },

    prestige(){
      const est = Math.floor(((cps||0)/1_000_000) * (1 + 0.10 * (prestigeGet('asc_mult'))));
      conPrintKV('Tryz now', formatNum(prestige.tryz||0));
      conPrintKV('Ascends', String(prestige.asc||0));
      conPrintKV('If ascend now', `+${formatNum(est)} tryz`);
    },

    ascend(){
      const btn = document.getElementById('btn_ascend');
      if(btn){ btn.click(); conPrint('Ascend dialog shown.'); }
    },

    clear(){ out.innerHTML=''; }
  };

  // Wire UI
  function run(){
    const line = input.value || '';
    input.value = '';
    runCmd(line);
  }
  btnRun?.addEventListener('click', run);
  form?.addEventListener('submit', run);
  btnClear?.addEventListener('click', ()=>commands.clear());

  input.addEventListener('keydown', (e)=>{
    if(e.key === 'ArrowUp'){
      if(H.idx > 0){ H.idx--; input.value = H.list[H.idx] || ''; e.preventDefault(); }
    }else if(e.key === 'ArrowDown'){
      if(H.idx < H.list.length){ H.idx++; input.value = H.list[H.idx] || ''; e.preventDefault(); }
    }else if(e.key === 'Enter'){
      // handled by form
    }
  });

  conPrint('Console ready. Type "help".');
})();
</script>

    """

@app.get("/api/leaderboard")
def api_leaderboard():
    with lock:
        db = load_db()
        _tick_bots(db)  # make sure _tick_bots is defined at module scope, not inside save_db()
        users = db.get("users", {}) or {}
        rows = []
        for name, doc in users.items():
            prog = (doc or {}).get("progress") or {}
            try:
                c = float(prog.get("count", 0) or 0)
            except:
                c = 0.0
            try:
                s = float(prog.get("cps", 0) or 0)
            except:
                s = 0.0
            rows.append({"user": str(name), "count": c, "cps": s})

        top_count = sorted(rows, key=lambda x: x["count"], reverse=True)[:50]
        top_cps   = sorted(rows, key=lambda x: x["cps"],   reverse=True)[:50]

    return jsonify({"ok": True, "top_count": top_count, "top_cps": top_cps})


@app.get("/leaderboard")
def leaderboard_page():
    return r"""<!doctype html><meta charset="utf-8"><title>Leaderboard</title>
    <style>
      :root { --bg:#000; --panel:#0b0b12; --panel2:#0f0f18; --border:#232334; --ink:#e7e7f5; }
      *{box-sizing:border-box} body{font-family:Inter,Arial;background:
        radial-gradient(900px 400px at 0% -10%, rgba(124,58,237,.25), transparent 60%),
        radial-gradient(900px 500px at 120% 10%, rgba(239,68,68,.18), transparent 65%),
        #000; color:var(--ink); margin:0; padding:24px}
      .wrap{max-width:980px;margin:0 auto}
      .card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--border);border-radius:16px;padding:16px;margin-bottom:16px;box-shadow:0 0 40px rgba(124,58,237,.08)}
      table{width:100%;border-collapse:collapse}
      th,td{border-bottom:1px solid var(--border);padding:10px}
      th:last-child, td:last-child{text-align:right}
      a.btn{display:inline-block;padding:8px 12px;border:1px solid var(--border);border-radius:10px;color:#ddd;text-decoration:none;background:#141625}
      .grid{display:grid;gap:16px;grid-template-columns:1fr;}
      @media (min-width:900px){ .grid{grid-template-columns:1fr 1fr} }
      .muted{color:#9aa0a6}
      .toolbar{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
      .toolbar-left,.toolbar-right{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
    </style>

    <div class="wrap">

      <div class="card">
        <div class="toolbar">
          <div class="toolbar-left">
            <h1 style="margin:0">Leaderboard</h1>
          </div>
          <div class="toolbar-right">
            <span id="updated" class="muted">—</span>
            <a class="btn" href="/">← Home</a>
          </div>
        </div>
      </div>

      <div class="grid">
        <div class="card">
          <h2 style="margin:0 0 8px 0">Most Autists (current)</h2>
          <table id="tbl_count"><thead><tr><th>#</th><th>User</th><th>Autists</th></tr></thead><tbody></tbody></table>
        </div>
        <div class="card">
          <h2 style="margin:0 0 8px 0">Most Autists / sec (current)</h2>
          <table id="tbl_cps"><thead><tr><th>#</th><th>User</th><th>a/s</th></tr></thead><tbody></tbody></table>
        </div>
      </div>

      <div class="card muted">Auto-updates every 60s.</div>
    </div>

    <script>
    function fmt(n){
      n = Number(n)||0;
      const scales = [
        [1e75,'qavg'],[1e72,'tvg'],[1e69,'dvg'],[1e66,'uvg'],[1e63,'vg'],
        [1e60,'nd'],[1e57,'od'],[1e54,'spd'],[1e51,'sxd'],[1e48,'qid'],
        [1e45,'qad'],[1e42,'td'],[1e39,'dd'],[1e36,'ud'],[1e33,'de'],
        [1e30,'no'],[1e27,'oc'],[1e24,'sp'],[1e21,'sx'],[1e18,'qi'],
        [1e15,'qa'],[1e12,'t'],[1e9,'b'],[1e6,'m'],[1e3,'k']
      ];
      for (const [div,suf] of scales){
        if (Math.abs(n) >= div){
          const val = (n/div).toFixed(2).replace(/\.00$/,'').replace(/(\.\d*[1-9])0$/,'$1');
          return val + suf;
        }
      }
      if (Math.abs(n) >= 1e6) return n.toExponential(2).replace("+","");
      return String(Math.trunc(n));
    }

    function renderTable(tbody, rows, key){
      tbody.innerHTML = '';
      if(!rows || !rows.length){
        tbody.innerHTML = '<tr><td colspan="3" class="muted">Empty</td></tr>';
        return;
      }

      rows.forEach((r,i)=>{
        const tr = document.createElement('tr');
        let name = r.user;
        let badge = '';

        if (name && name.toLowerCase() === 'jonsman47') {
          name = `<span style="color:#b24ef5;font-weight:700">${name}</span>`;
          badge = ` <span style="font-size:0.75rem;background:#b24ef5;color:#fff;padding:2px 6px;border-radius:6px;margin-left:6px;">CREATOR</span>`;
        }

        tr.innerHTML = `
          <td>${i+1}</td>
          <td>${name}${badge}</td>
          <td>${fmt(r[key])}</td>
        `;
        tbody.appendChild(tr);
      });
    }

    async function loadLB(){
      try{
        const r = await fetch('/api/leaderboard',{cache:'no-store'});
        const j = await r.json();
        if(j && j.ok){
          renderTable(document.querySelector('#tbl_count tbody'), j.top_count, 'count');
          renderTable(document.querySelector('#tbl_cps tbody'),   j.top_cps,   'cps');
          document.getElementById('updated').textContent = 'Updated: ' + new Date().toLocaleTimeString();
        }
      }catch(e){ console.error(e); }
    }

    loadLB();
    setInterval(loadLB, 60000);
    </script>
    """


# ---------- catch-all ----------
# ---------- Respect / Inclusion (FR + EN) ----------
@app.get("/disclaimer")
def disclaimer():
    return """
<!doctype html><meta charset="utf-8"><title>Respect & Inclusion</title>
<style>
  :root { --bg:#000; --panel:#0b0b12; --panel2:#0f0f18; --border:#232334; --ink:#e7e7f5; }
  *{box-sizing:border-box} body{font-family:Inter,Arial;background:
    radial-gradient(900px 400px at 0% -10%, rgba(124,58,237,.25), transparent 60%),
    radial-gradient(900px 500px at 120% 10%, rgba(239,68,68,.18), transparent 65%),
    #000; color:var(--ink); margin:0; padding:24px}
  .wrap{max-width:900px;margin:0 auto}
  .card{background:linear-gradient(180deg,var(--panel),var(--panel2));border:1px solid var(--border);border-radius:16px;padding:16px;margin-bottom:16px;box-shadow:0 0 40px rgba(124,58,237,.08)}
  a.btn{display:inline-block;padding:8px 12px;border:1px solid var(--border);border-radius:10px;color:#ddd;text-decoration:none;background:#141625}
  .muted{color:#9aa0a6}
</style>

<div class="card">
  <div class="toolbar">
    <div class="toolbar-left">
      <h1 style="margin:0">Respect & Inclusion</h1>
    </div>
    <div class="toolbar-right">
      <a class="btn" href="/">← Home</a>
      <a class="btn" href="/clicker">🎮 Clicker</a>
      <a class="btn" href="/leaderboard">🏆 Leaderboard</a>
    </div>
  </div>
</div>


  <div class="card">
    <h2 style="margin:.2rem 0">FR — Note de respect</h2>
    <p>
      Ce jeu ne se moque d’aucun groupe de personnes. Il n’a pas pour but
      d’insulter, de stigmatiser ou de dénigrer les personnes autistes ou
      toute personne en situation de handicap. Le ton est parodique/arcade.
      Si un contenu vous met mal à l’aise, dites-le nous et nous l’ajusterons.
    </p>
  </div>

  <div class="card">
    <h2 style="margin:.2rem 0">EN — Respect note</h2>
    <p>
      This game does not mock any group of people. It is not intended to insult,
      stigmatize, or demean autistic people or anyone with disabilities.
      The tone is parody/arcade. If something feels off, please tell us and
      we’ll adjust.
    </p>
  </div>

  <div class="card muted">
    Merci / Thank you for playing ♥
  </div>
</div>
"""


@app.get("/<path:_>")
def any_route(_):
    return redirect("/")


if __name__ == "__main__":
    with lock:
        db = load_db()
        users = db.setdefault("users", {})
        if not users:  # premier démarrage -> seed pour voir quelque chose sur le LB
            for _ in range(15):
                name = _rand_username()
                users[name] = {
                    "pw": generate_password_hash(secrets.token_hex(8)),
                    "progress": _fake_progress(),
                    "prestige": _empty_prestige(),
                    "bot": True,
                    "bot_tick": int(time.time()),
                }
        save_db(db)
    # démarre le serveur si tu lances `python app.py`
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
