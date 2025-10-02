# app.py — full stack clicker (auth, admin, uploads, shop, sell, leaderboard) — NO UPGRADES
from flask import Flask, request, redirect, session, jsonify, send_from_directory, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os, json, threading, secrets, time

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(16))

DB_PATH = "db.json"
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

lock = threading.Lock()
ADMIN_USERNAME = "Jonsman47".lower()
ALLOWED_EXT = {"png","jpg","jpeg","webp","gif","svg"}

# ---------- tiny JSON "DB" ----------
def _empty_db():
    return {"users": {}, "settings": {"bg": None, "logo": None}}

def load_db():
    if not os.path.exists(DB_PATH):
        return _empty_db()
    try:
        with open(DB_PATH, "r", encoding="utf-8") as f:
            db = json.load(f)
            db.setdefault("settings", {"bg": None, "logo": None})
            db.setdefault("users", {})
            return db
    except:
        return _empty_db()

def save_db(db):
    with open(DB_PATH, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)

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
    lang = session.get("lang") or request.args.get("lang") or "fr"
    if lang not in LANGS: lang = "fr"
    session["lang"] = lang
    return lang

def T(key): return STR.get(get_lang(), STR["en"]).get(key, key)

def compact(n):
    try:
        n = float(n)
    except:
        return str(n)
    # short scale jusqu’à 1e33
    scales = [
        (1e33, "de"),  # decillion
        (1e30, "no"),  # nonillion
        (1e27, "oc"),  # octillion
        (1e24, "sp"),  # septillion
        (1e21, "sx"),  # sextillion
        (1e18, "qi"),  # quintillion
        (1e15, "qa"),  # quadrillion
        (1e12, "t"),   # trillion
        (1e9,  "b"),   # billion
        (1e6,  "m"),   # million
        (1e3,  "k"),   # thousand
    ]
    for div, suf in scales:
        if abs(n) >= div:
            val = round(n/div, 2)
            s = f"{val:.2f}".rstrip("0").rstrip(".")
            return f"{s}{suf}"
    try:
        return str(int(n))
    except:
        return str(n)

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
        <h2 style="margin-top:0">Register</h2>
        <form method="post" style="display:grid;gap:12px">
          <label>Username<br><input name="u" required></label>
          <label>Password<br><input name="p" type="password" required></label>
          <button class="btn violet">{T('register')}</button>
        </form>
        <p style="margin-top:12px"><a class="btn" href="/">{'← Home'}</a></p>
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
        db["users"][u] = {"pw": generate_password_hash(p), "progress": None}
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
        <h2 style="margin-top:0">Login</h2>
        <form method="post" style="display:grid;gap:12px">
          <label>Username<br><input name="u" required></label>
          <label>Password<br><input name="p" type="password" required></label>
          <button>Login</button>
        </form>
        <p style="margin-top:12px"><a class="btn" href="/">{'← Home'}</a></p>
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
    lang = request.args.get("to","fr")
    if lang not in LANGS: lang = "fr"
    session["lang"] = lang
    return redirect(request.referrer or "/")

# ---------- Home ----------
@app.route("/", methods=["GET","POST"])
def home():
    get_lang()
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
    res_fmt = compact(res) if isinstance(res,(int,float)) or (isinstance(res,str) and res.replace(".","",1).isdigit()) else res

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
      input,select,button{{border-radius:12px;border:1px solid var(--border);padding:12px;background:#13131c;color:var(--ink)}}
      button.solid{{background:linear-gradient(90deg,#7c3aed,#ef4444);border-color:#7c3aed;cursor:pointer}}
      label b{{display:block;margin-bottom:6px;color:#d9d9ff}}
      .pill{{padding:6px 10px;border:1px solid var(--border);border-radius:999px;background:#10101a;color:#cfcfe8}}
    </style>
    <div class="container">
      <div class="row" style="justify-content:space-between;margin-bottom:16px">
        <div class="row">
          <a class="btn solid" href="/clicker">🎮 {T('goto_clicker')}</a>
          <a class="btn" href="/leaderboard">🏆 Leaderboard</a>
        </div>
        <div class="row">
          <a class="btn" href="/lang?to=en">{T('change_en')}</a>
          <a class="btn" href="/lang?to=fr">{T('change_fr')}</a>
          {"<span style='margin-left:8px'></span>"+admin_link if admin_link else ""}
        </div>
      </div>

      <div class="panel" style="text-align:center">
        <h1 style="margin:8px 0; letter-spacing:.5px">{T('title_home')}</h1>
        <div style="margin:8px 0">
          <span>{(T('logged_in_as')+': <b>'+str(user)+'</b> <a class=\"btn\" href=\"/logout\">'+T('logout')+'</a>') if user else T('not_logged_in')}</span>
          {' | <a class="btn" href="/register">'+T('register')+'</a> <a class="btn" href="/login">'+T('login')+'</a>' if not user else ''}
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
        <p style="margin-top:10px;font-size:20px"><b>{T('total')}:</b> {res_fmt}</p>
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

def _empty_progress():
    return {
        "v": 1,
        "count": 0.0,
        "cps": 0.0,
        "shop": [],
        "saved_at": None,
    }

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
        save_db(db)

    return jsonify({"ok": True})

@app.get("/api/load_progress")
def api_load_progress():
    if not is_authed():
        return jsonify({"ok": False, "err": "not_auth"}), 401

    with lock:
        db = load_db()
        u = session.get("user")
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

    return jsonify({"ok": True, "progress": prog})

@app.get("/api/settings")
def api_settings():
    with lock:
        db = load_db()
        st = db.get("settings", {})
    def full(url):
        return url_for("serve_upload", filename=os.path.basename(url), _external=False) if url else None
    return jsonify({"ok": True, "settings": {"bg": full(st.get("bg")), "logo": full(st.get("logo"))}})

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
    </style>
    <div class="container">
      <div class="card" style="display:flex;justify-content:space-between;align-items:center">
        <h1 style="margin:4px 0">{T('admin')}</h1>
        <div class="row">
          <a class="btn" href="/">← Home</a>
          <a class="btn" href="/leaderboard">🏆 Leaderboard</a>
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
        <h2 style="margin:0 0 8px 0">{T('users')}</h2>
        <table>
          <thead><tr><th>{T('users')}</th><th>{T('actions')}</th></tr></thead>
          <tbody>{table}</tbody>
        </table>
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

# ---------- Clicker ----------
@app.get("/clicker")
def clicker():
    return """
<!doctype html><meta charset="utf-8"><title>Autists Clicker</title>
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
</style>
<div class="wrap" id="root">
  <div class="row" id="topbar">
    <div class="row" style="gap:8px">
      <button class="btn" onclick="setLang('fr')">Français</button>
      <button class="btn" onclick="setLang('en')">English</button>
      <a class="btn" href="/leaderboard">🏆 Leaderboard</a>
      <img id="logo" alt="logo">
    </div>
    <div class="row">
      <a class="btn" href="/">← Home</a>
      <a class="btn blue" href="/login">Login</a>
      <a class="btn blue" href="/register">Register</a>
      <a class="btn red" href="/logout">Logout</a>
    </div>
  </div>

  <h1 id="title" style="text-align:center;margin:10px 0;letter-spacing:.5px;text-shadow:0 0 18px rgba(124,58,237,.35)">Autists Clicker</h1>

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
    <button id="btn_reset" class="btn">Reset local</button>
    <button id="btn_sync_shop" class="btn blue">Sync Shop</button>
    <span id="sync_msg" class="pill">…</span>
  </div>

  <h2 id="lbl_shop" style="text-align:center;margin-top:8px">Shop</h2>
  <div id="shop" style="display:grid;gap:12px;grid-template-columns:1fr;"></div>

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

<script>
// ===== i18n (client EN/FR) =====
const LANGS = {
  fr:{shop:"Boutique",count:"Autistes",cps:"a/s",click:"+1 Autiste",create:"Créer un Autiste custom (coût: 1000)",level:"Niveau",cost:"Coût",buy:"Acheter",sell:"Vendre",upload:"Uploader vers mon compte",load:"Charger depuis mon compte",reset:"Reset local",not_enough:"Pas assez d’autistes (1000 requis).",invalid:"Nom + coût valide (≥ 10) requis.",created:(u)=>`Créé: ${u.name} — base ${formatNum(u.base)}, ~${formatNum(u.inc)}/s (aléatoire).`},
  en:{shop:"Shop",count:"Autists",cps:"a/s",click:"+1 Autist",create:"Create custom Autist (cost: 1000)",level:"Level",cost:"Cost",buy:"Buy",sell:"Sell",upload:"Upload to my account",load:"Load from my account",reset:"Reset local",not_enough:"Not enough autists (1000 required).",invalid:"Valid name + base cost (≥ 10) required.",created:(u)=>`Created: ${u.name} — base ${formatNum(u.base)}, ~${formatNum(u.inc)}/s (random).`}
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
}

// ===== SHOP DATA =====
const mk = (name, key, base, inc) => ({ key, name, base, inc, lvl:0 });
const earlyUnits = [
  mk("Petit caillou Autiste","rock",10,1),
  mk("Autiste en bois","wood",50,3),
  mk("Stylo Autiste","pen",200,5),
];
const coreUnits = [
  mk("Remi - Autiste","remi",1_000,10),
  mk("Jonsman - Autiste","jonsman",10_000,120),
  mk("Hector - Autiste","hector",30_000,350),
  mk("Valentin - Autiste","valentin",75_000,900),
  mk("Johan - Autiste","johan",120_000,1_800),
  mk("Viki - Autiste","viki",180_000,2_700),
  mk("Paul - Autiste","paul",240_000,3_600),
  mk("Sa Mère - Autiste","samere",320_000,5_000),
];
const midUnits = [
  mk("Chaussures Autistes","shoes",500_000,12_000),
  mk("Usine Autiste","factory",1_000_000,30_000),
  mk("Ferme Autiste","farm",2_500_000,80_000),
  mk("Tour Autiste","tower",5_000_000,150_000),
  mk("Laboratoire Autiste","lab",10_000_000,400_000),
  mk("Serveur Autiste","server",20_000_000,900_000),
  mk("Mine Autiste","mine",50_000_000,2_000_000),
  mk("Bunker Autiste","bunker",100_000_000,5_000_000),
];
const gigaUnits = [
  mk("Autiste Fusion Reactor","fusion",500_000_000,20_000_000),
  mk("Quantum Portail Autiste","qportal",2_000_000_000,90_000_000),
  mk("AI Swarm Autiste","aiswarm",10_000_000_000,500_000_000),
  mk("Planet Factory Autiste","planet",50_000_000_000,2_000_000_000),
  mk("Black Hole Autiste Collider","bhc",200_000_000_000,8_000_000_000),
  mk("Multiverse Franchise Autiste","multi",1_000_000_000_000,40_000_000_000),
  mk("Time Machine Autiste","timemachine",5_000_000_000_000,200_000_000_000),
  mk("Galactic Autiste Conglomerate","galactic",20_000_000_000_000,800_000_000_000),
  mk("Dimensional Autiste Empire","dimemp",100_000_000_000_000,3_500_000_000_000),
];
const randomUnits = [
  mk("Chaussettes Autistes","sock",750_000,20_000),
  mk("Autiste iPhone 34","iphone",5_000_000,150_000),
  mk("Autiste Tesla Cybertruck","tesla",20_000_000,600_000),
  mk("Autiste PC Gamer","pcgamer",75_000_000,2_500_000),
  mk("Autiste McDo Factory","mcdo",200_000_000,9_000_000),
  mk("Autiste SpaceX Rocket","rocket",1_000_000_000,50_000_000),
  mk("Autiste Crypto Mine","crypto",5_000_000_000,200_000_000),
  mk("Autiste Nuclear Plant","nuclear",20_000_000_000,800_000_000),
  mk("Autiste Mars Colony","mars",100_000_000_000,4_000_000_000),
  mk("Autiste Black Market","black",500_000_000_000,20_000_000_000),
];
const megaUnits = [
  mk("Autiste Dyson Sphere","dyson",1e15,5e10),
  mk("Empire Autiste Galactique","empiregal",1e16,1e9),
  mk("Autiste Univers Portable","universe",1e18,1e12),
  mk("Simulation Autiste Infinie","simul",1e20,5e12),
  mk("Autiste Dieu Ancien","god",1e24,1e15),
  mk("Autiste Omnivers","omniverse",1e28,1e18),
  mk("Autiste Source du Tout","source",1e33,1e21),
];
const DEFAULT_SHOP = [...earlyUnits, ...coreUnits, ...midUnits, ...randomUnits, ...gigaUnits, ...megaUnits];

// ===== STATE & SAVE =====
let count = 0, cps = 0;
let shop = JSON.parse(JSON.stringify(DEFAULT_SHOP));

// Clicks-per-second meter
let clickTimes = [];
let cpsClick = 0;
const CPS_WINDOW_MS = 2000;

// ===== UTILS =====
function formatNum(n){
  n = Number(n)||0;
  const scales = [
    [1e33,"de"], [1e30,"no"], [1e27,"oc"], [1e24,"sp"], [1e21,"sx"],
    [1e18,"qi"], [1e15,"qa"], [1e12,"t"],  [1e9,"b"],   [1e6,"m"], [1e3,"k"]
  ];
  for (const [div,suf] of scales){
    if (Math.abs(n) >= div){
      const val = (n/div).toFixed(2).replace(/\\.00$/,'').replace(/(\\.\\d*[1-9])0$/,'$1');
      return `${val}${suf}`;
    }
  }
  return String(Math.trunc(n));
}
function costOf(i){ return Math.floor(i.base*Math.pow(1.15,i.lvl)); }
function effectiveInc(it){ return it.inc; }
function recalc(){ cps = shop.reduce((s,x)=> s + effectiveInc(x)*(Number(x.lvl)||0), 0); }
function rndInc(base){
  if(!base || base<=0) return 1;
  let min = Math.floor(Math.sqrt(base));
  let max = Math.floor(Math.sqrt(base)*75);
  if(min<1) min=1;
  const val = min + Math.random()*(max-min);
  return Math.round(val);
}
function clickPower(){ return Math.max(1, Math.floor(1 + (cps/1000)*25)); }
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
    const refund = formatNum(Math.floor(price*0.5));

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
  const refund = Math.floor(price*0.5);
  it.lvl -= 1;
  count  += refund;
  recalc(); render(); saveLocal(); updateClickButton();
}

// ===== UI =====
function update(){
  document.getElementById("count").textContent = formatNum(count);
  document.getElementById("cps").textContent   = formatNum(cps);
  render();
  updateClickButton();
}
document.getElementById("click").onclick = () => {
  count += clickPower();
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
  const payload={ v:5, count, cps, shop };
  const r=await fetch("/api/save_progress",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
  const j=await r.json().catch(()=>({}));
  document.getElementById("sync_msg").textContent=j.ok?"✓":"x";
}
async function loadServer(){
  const r=await fetch("/api/load_progress"); const j=await r.json().catch(()=>({}));
  if(j.ok && j.progress){
    const p=j.progress;
    count=Number(p.count)||0; cps=Number(p.cps)||0;
    if(Array.isArray(p.shop)) shop=p.shop;
    update(); saveLocal(); document.getElementById("sync_msg").textContent="✓";
  } else { document.getElementById("sync_msg").textContent="x"; }
}
document.getElementById("btn_save").onclick=saveServer;
document.getElementById("btn_load").onclick=loadServer;
document.getElementById("btn_reset").onclick=()=>{ localStorage.removeItem("autistes_clicker"); count=0; shop=JSON.parse(JSON.stringify(DEFAULT_SHOP)); recalc(); update(); };

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

// Boot
setLang("fr");
applyLang();
applySettings();
loadLocal(); recalc(); render(); update();
setInterval(()=>{ count+=cps; update(); saveLocal(); },1000);
</script>
"""

# ---------- Leaderboard (current count & a/s, refresh via client every 60s) ----------
def _collect_leaderboards_simple():
    with lock:
        db = load_db()
        rows = []
        for u, doc in (db.get("users") or {}).items():
            prog = (doc or {}).get("progress") or {}
            rows.append({
                "user": u,
                "count": float(prog.get("count") or 0.0),
                "cps":   float(prog.get("cps")   or 0.0),
            })
    top_count = sorted(rows, key=lambda r: r["count"], reverse=True)[:50]
    top_cps   = sorted(rows, key=lambda r: r["cps"],   reverse=True)[:50]
    return top_count, top_cps

@app.get("/api/leaderboard")
def api_leaderboard():
    top_count, top_cps = _collect_leaderboards_simple()
    return jsonify({"ok": True, "top_count": top_count, "top_cps": top_cps})

@app.get("/leaderboard")
def leaderboard_page():
    page = """<!doctype html><meta charset="utf-8"><title>Leaderboard</title>
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
      .grid{display:grid;gap:16px;grid-template-columns:1fr; }
      @media (min-width:900px){ .grid{grid-template-columns:1fr 1fr} }
      .muted{color:#9aa0a6}
    </style>
    <div class="wrap">
      <div class="card" style="display:flex;justify-content:space-between;align-items:center">
        <h1 style="margin:0">Leaderboard</h1>
        <div style="display:flex;gap:8px;align-items:center">
          <span id="updated" class="muted">—</span>
          <a class="btn" href="/">← Home</a>
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
          [1e33,'de'],[1e30,'no'],[1e27,'oc'],[1e24,'sp'],[1e21,'sx'],
          [1e18,'qi'],[1e15,'qa'],[1e12,'t'],[1e9,'b'],[1e6,'m'],[1e3,'k']
        ];
        for (const [div,suf] of scales){
          if (Math.abs(n) >= div){
            const val = (n/div).toFixed(2).replace(/\\.00$/,'').replace(/(\\.\\d*[1-9])0$/,'$1');
            return val + suf;
          }
        }
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
          tr.innerHTML = '<td>'+(i+1)+'</td><td>'+r.user+'</td><td>'+fmt(r[key])+'</td>';
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
        }catch(e){}
      }
      loadLB();
      setInterval(loadLB, 60000);
    </script>
    """
    return page

# ---------- catch-all ----------
@app.get("/<path:_>")
def any_route(_):
    return redirect("/")

if __name__ == "__main__":
    with lock:
        db = load_db()
        db.setdefault("settings", {"bg":None,"logo":None})
        save_db(db)
    app.run(host="0.0.0.0", port=5001, debug=True)
