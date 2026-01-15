from __future__ import annotations

import math
import random
import time
from typing import Dict, List, Tuple

from achievements import achievement_multiplier

MAX_COUNT = 1e120
MAX_CPS = 1e90
MAX_LEVEL = 1_000_000
MAX_CUSTOM_UNITS = 25

SHOP_TIERS = [
    "early",
    "core",
    "mid",
    "random",
    "giga",
    "mega",
    "ultra",
]


PRESTIGE_UPGRADES = [
    {"key": "cps_mult", "name": "Passive a/s x1.10/level", "base": 1_000_000_000, "max": 50},
    {"key": "click_mult", "name": "Click power x1.25/level", "base": 10_000_000_000, "max": 20},
    {"key": "start_boost", "name": "Start +10k/level", "base": 50_000_000_000, "max": 10},
    {"key": "asc_mult", "name": "Ascend yield +10%/level", "base": 100_000_000_000, "max": 50},
    {"key": "shop_discount", "name": "Shop prices -2%/level", "base": 500_000_000_000, "max": 50},
    {"key": "flat_cps", "name": "+100 a/s per level", "base": 1_000_000_000_000, "max": 200},
    {"key": "refund_plus", "name": "Sell refund +5%/level", "base": 10_000_000_000_000, "max": 9},
    {"key": "lucky_clicks", "name": "Crit click +5%/lvl (x3)", "base": 1_000_000_000_000_000, "max": 15},
]

PRESTIGE_TREE = [
    {
        "key": "offline_boost",
        "name": "Offline Cap +4h",
        "cost": 50,
        "requires": [],
        "desc": "Increase offline progress cap by 4 hours.",
        "bonus": {"offline_hours": 4},
    },
    {
        "key": "daily_boost",
        "name": "Daily Chest +25%",
        "cost": 80,
        "requires": [],
        "desc": "Increase daily reward value by 25%.",
        "bonus": {"daily_mult": 0.25},
    },
    {
        "key": "quest_boost",
        "name": "Quest Rewards +20%",
        "cost": 100,
        "requires": [],
        "desc": "Increase quest rewards by 20%.",
        "bonus": {"quest_mult": 0.20},
    },
    {
        "key": "automation_slot",
        "name": "Automation Slot",
        "cost": 200,
        "requires": ["quest_boost"],
        "desc": "Unlock automation controls.",
        "bonus": {"automation": True},
    },
    {
        "key": "research_tree",
        "name": "Research Tree",
        "cost": 400,
        "requires": ["automation_slot"],
        "desc": "Unlock research bonuses.",
        "bonus": {"research": True},
    },
]

ACHIEVEMENT_BOOSTS = [
    {"key": "minor_cps", "name": "+1% CPS (per level)", "max": 50, "cost": 1},
    {"key": "minor_click", "name": "+1% Click Power (per level)", "max": 50, "cost": 1},
    {"key": "cosmetic_glow", "name": "Cosmetic: Glow Effect", "max": 1, "cost": 10},
]


def _mk(name, key, base, inc, tier, clean_name):
    return {
        "key": key,
        "name": name,
        "clean_name": clean_name,
        "base": base,
        "inc": inc,
        "tier": tier,
    }


def default_shop() -> List[Dict]:
    early = [
        _mk("Petit caillou Autiste", "rock", 10, 1, "early", "Pebble Worker"),
        _mk("Autiste en bois", "wood", 50, 3, "early", "Wooden Worker"),
        _mk("Stylo Autiste", "pen", 200, 5, "early", "Pen Operator"),
    ]
    core = [
        _mk("Remi - Autiste", "remi", 1_000, 15, "core", "Remi - Worker"),
        _mk("Jonsman - Autiste", "jonsman", 10_000, 150, "core", "Jonsman - Worker"),
        _mk("Hector - Autiste", "hector", 30_000, 500, "core", "Hector - Worker"),
        _mk("Valentin - Autiste", "valentin", 75_000, 1_000, "core", "Valentin - Worker"),
        _mk("Johan - Autiste", "johan", 120_000, 2_000, "core", "Johan - Worker"),
        _mk("Viki - Autiste", "viki", 180_000, 3_000, "core", "Viki - Worker"),
        _mk("Paul - Autiste", "paul", 240_000, 4_500, "core", "Paul - Worker"),
        _mk("Sa Mère - Autiste", "samere", 320_000, 6_000, "core", "Mom - Worker"),
    ]
    mid = [
        _mk("Chaussures Autistes", "shoes", 500_000, 12_000, "mid", "Shoe Workshop"),
        _mk("Usine Autiste", "factory", 1_000_000, 30_000, "mid", "Factory"),
        _mk("Ferme Autiste", "farm", 2_500_000, 80_000, "mid", "Farm"),
        _mk("Tour Autiste", "tower", 5_000_000, 150_000, "mid", "Tower"),
        _mk("Laboratoire Autiste", "lab", 10_000_000, 400_000, "mid", "Lab"),
        _mk("Serveur Autiste", "server", 20_000_000, 900_000, "mid", "Server"),
        _mk("Mine Autiste", "mine", 50_000_000, 2_000_000, "mid", "Mine"),
        _mk("Bunker Autiste", "bunker", 100_000_000, 5_000_000, "mid", "Bunker"),
    ]
    random_units = [
        _mk("Chaussettes Autistes", "sock", 750_000, 25_000, "random", "Socks"),
        _mk("Autiste iPhone 34", "iphone", 5_000_000, 200_000, "random", "Phone Lab"),
        _mk("Autiste Tesla Cybertruck", "tesla", 20_000_000, 800_000, "random", "EV Workshop"),
        _mk("Autiste PC Gamer", "pcgamer", 75_000_000, 3_000_000, "random", "Gaming Rig"),
        _mk("Autiste McDo Factory", "mcdo", 200_000_000, 12_000_000, "random", "Fast-Food Plant"),
        _mk("Autiste SpaceX Rocket", "rocket", 1_000_000_000, 100_000_000, "random", "Rocket Lab"),
        _mk("Autiste Crypto Mine", "crypto", 5_000_000_000, 500_000_000, "random", "Crypto Mine"),
        _mk("Autiste Nuclear Plant", "nuclear", 20_000_000_000, 2_000_000_000, "random", "Nuclear Plant"),
        _mk("Autiste Mars Colony", "mars", 100_000_000_000, 10_000_000_000, "random", "Mars Colony"),
        _mk("Autiste Black Market", "black", 500_000_000_000, 50_000_000_000, "random", "Black Market"),
    ]
    giga = [
        _mk("Autiste Fusion Reactor", "fusion", 500_000_000, 30_000_000, "giga", "Fusion Reactor"),
        _mk("Quantum Portail Autiste", "qportal", 2_000_000_000, 150_000_000, "giga", "Quantum Portal"),
        _mk("AI Swarm Autiste", "aiswarm", 10_000_000_000, 1_000_000_000, "giga", "AI Swarm"),
        _mk("Planet Factory Autiste", "planet", 50_000_000_000, 5_000_000_000, "giga", "Planet Factory"),
        _mk("Black Hole Autiste Collider", "bhc", 200_000_000_000, 15_000_000_000, "giga", "Black Hole Collider"),
        _mk("Multiverse Franchise Autiste", "multi", 1_000_000_000_000, 100_000_000_000, "giga", "Multiverse Franchise"),
        _mk("Time Machine Autiste", "timemachine", 5_000_000_000_000, 500_000_000_000, "giga", "Time Machine"),
        _mk("Galactic Autiste Conglomerate", "galactic", 20_000_000_000_000, 2_000_000_000_000, "giga", "Galactic Conglomerate"),
        _mk("Dimensional Autiste Empire", "dimemp", 100_000_000_000_000, 15_000_000_000_000, "giga", "Dimensional Empire"),
    ]
    mega = [
        _mk("Autiste Dyson Sphere", "dyson", 1e15, 5e11, "mega", "Dyson Sphere"),
        _mk("Empire Autiste Galactique", "empiregal", 1e16, 1e14, "mega", "Galactic Empire"),
        _mk("Autiste Univers Portable", "universe", 1e18, 2e16, "mega", "Pocket Universe"),
        _mk("Simulation Autiste Infinie", "simul", 1e20, 1e18, "mega", "Infinite Simulation"),
        _mk("Autiste Dieu Ancien", "god", 1e24, 1e19, "mega", "Ancient Deity"),
        _mk("Autiste Omnivers", "omniverse", 1e28, 1e22, "mega", "Omniverse"),
        _mk("Autiste Source du Tout", "source", 1e33, 1e26, "mega", "Source of All"),
    ]
    ultra = [
        _mk("Autiste Quantum Matryoshka", "matryoshka", 1e36, 1e27, "ultra", "Quantum Matryoshka"),
        _mk("Autiste Brane Weaving Loom", "branloom", 3e36, 3e27, "ultra", "Brane Loom"),
        _mk("Autiste Vacuum Forge", "vacuumforge", 1e37, 1e28, "ultra", "Vacuum Forge"),
        _mk("Autiste Dark Energy Turbine", "darkenergy", 3e37, 3e28, "ultra", "Dark Energy Turbine"),
        _mk("Autiste Cosmic Filament", "filament", 1e38, 1e29, "ultra", "Cosmic Filament"),
        _mk("Autiste Hypercluster", "hypercluster", 3e38, 4e29, "ultra", "Hypercluster"),
        _mk("Autiste Inflation Engine", "inflation", 1e39, 1e30, "ultra", "Inflation Engine"),
        _mk("Autiste False Vacuum Drill", "fvacuum", 3e39, 3e30, "ultra", "False Vacuum Drill"),
        _mk("Autiste Entropy Reverser", "entropy", 1e40, 1e31, "ultra", "Entropy Reverser"),
        _mk("Autiste Causal Lattice", "lattice", 3e40, 3e31, "ultra", "Causal Lattice"),
        _mk("Autiste Axion Farm", "axion", 1e42, 1e32, "ultra", "Axion Farm"),
        _mk("Autiste Tachyon Accelerator", "tachyon", 1e43, 3e32, "ultra", "Tachyon Accelerator"),
        _mk("Autiste Warp Foundry", "warp", 1e45, 1e33, "ultra", "Warp Foundry"),
        _mk("Autiste Multiversal Loom", "multiloom", 3e45, 3e33, "ultra", "Multiversal Loom"),
        _mk("Autiste Chrono Smithy", "chrono", 1e48, 1e34, "ultra", "Chrono Smithy"),
        _mk("Autiste Probability Mine", "probmine", 3e48, 3e34, "ultra", "Probability Mine"),
        _mk("Autiste Ontology Engine", "ontology", 1e51, 1e35, "ultra", "Ontology Engine"),
        _mk("Autiste Kardashev Hub", "karda", 1e54, 1e36, "ultra", "Kardashev Hub"),
        _mk("Autiste Omega Foundry", "omegafoundry", 1e57, 1e37, "ultra", "Omega Foundry"),
        _mk("Autiste Reality Printer", "rprinter", 1e60, 1e38, "ultra", "Reality Printer"),
        _mk("Autiste Prime Universe Seeder", "primes", 1e63, 1e39, "ultra", "Prime Seeder"),
        _mk("Autiste Meta-Godworks", "metagod", 1e66, 1e40, "ultra", "Meta-Godworks"),
        _mk("Autiste Omni-Anvil", "omnianvil", 1e69, 1e41, "ultra", "Omni-Anvil"),
        _mk("Autiste Eternity Mill", "eternity", 1e72, 1e42, "ultra", "Eternity Mill"),
        _mk("Autiste Origin Forge", "originforge", 1e75, 1e43, "ultra", "Origin Forge"),
    ]
    return [*early, *core, *mid, *random_units, *giga, *mega, *ultra]


def get_shop_catalog(settings_shop: List[Dict] | None) -> List[Dict]:
    if not settings_shop:
        return default_shop()
    catalog = []
    for item in settings_shop:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "")[:128]
        if not key:
            continue
        try:
            base = float(item.get("base") or 0)
        except Exception:
            base = 0.0
        try:
            inc = float(item.get("inc") or 0)
        except Exception:
            inc = 0.0
        name = str(item.get("name") or key)[:128]
        clean_name = str(item.get("clean_name") or name)[:128]
        tier = str(item.get("tier") or "custom")
        catalog.append({
            "key": key,
            "name": name,
            "clean_name": clean_name,
            "base": max(0.0, base),
            "inc": max(0.0, inc),
            "tier": tier,
        })
    return catalog


def empty_progress() -> Dict:
    return {
        "v": 2,
        "count": 0.0,
        "cps": 0.0,
        "inventory": {},
        "custom_units": [],
        "saved_at": None,
        "last_ts": None,
        "last_award_ts": None,
        "daily": {"last_ts": None, "streak": 0},
        "quests": {"assigned": None, "claims": []},
        "boost": {"mult": 1.0, "until": None, "last_roll": None},
        "automation": {"auto_click": False, "auto_buy": False, "targets": {}},
        "season_count": 0.0,
        "season_cps": 0.0,
    }


def empty_prestige() -> Dict:
    return {
        "tryz": 0,
        "asc": 0,
        "up": {},
        "tree": [],
        "ach_spend": {},
    }


def prestige_cost(key: str, lvl_next: int) -> int:
    for u in PRESTIGE_UPGRADES:
        if u["key"] == key:
            return int(u["base"] * lvl_next)
    return 999999999


def custom_unit_inc(base: float) -> float:
    if base <= 0:
        return 1.0
    return max(1.0, round(math.sqrt(base) * 8))


def normalize_progress(prog: Dict) -> Dict:
    if not prog:
        return empty_progress()
    if "inventory" in prog:
        return prog
    inventory: Dict[str, int] = {}
    custom_units: List[Dict] = []
    for item in prog.get("shop", []) or []:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "")
        try:
            lvl = int(item.get("lvl") or 0)
        except Exception:
            lvl = 0
        lvl = max(0, min(lvl, MAX_LEVEL))
        if key.startswith("custom_"):
            custom_units.append({
                "key": key,
                "name": str(item.get("name") or "Custom")[:64],
                "base": float(item.get("base") or 10),
                "inc": float(item.get("inc") or 1),
            })
        else:
            inventory[key] = lvl
    new_prog = empty_progress()
    new_prog.update({
        "count": float(prog.get("count") or 0.0),
        "cps": float(prog.get("cps") or 0.0),
        "inventory": inventory,
        "custom_units": custom_units,
        "saved_at": prog.get("saved_at"),
    })
    return new_prog


def event_multiplier() -> float:
    now = time.localtime()
    if now.tm_wday in (5, 6):
        return 1.5
    return 1.0


def boost_multiplier(progress: Dict) -> float:
    boost = (progress or {}).get("boost") or {}
    until = boost.get("until")
    mult = float(boost.get("mult") or 1.0)
    if until and time.time() > float(until):
        boost["mult"] = 1.0
        boost["until"] = None
    return float(boost.get("mult") or 1.0)


def prestige_tree_bonus(tree_keys: List[str]) -> Dict:
    bonus = {"offline_hours": 0, "daily_mult": 0.0, "quest_mult": 0.0, "automation": False, "research": False}
    owned = set(tree_keys or [])
    for node in PRESTIGE_TREE:
        if node["key"] in owned:
            for key, val in node.get("bonus", {}).items():
                if isinstance(val, bool):
                    bonus[key] = bonus.get(key) or val
                elif isinstance(val, (int, float)):
                    bonus[key] = bonus.get(key, 0) + val
    return bonus


def achievement_boosts(prestige: Dict) -> Dict:
    spend = (prestige or {}).get("ach_spend") or {}
    cps_lvl = int(spend.get("minor_cps") or 0)
    click_lvl = int(spend.get("minor_click") or 0)
    glow = bool(spend.get("cosmetic_glow"))
    return {"cps_mult": 1 + 0.01 * cps_lvl, "click_mult": 1 + 0.01 * click_lvl, "glow": glow}


def compute_cps(progress: Dict, prestige: Dict, catalog: List[Dict], ach_mult: float, ach_all_bonus: int) -> float:
    inventory = progress.get("inventory") or {}
    base = 0.0
    catalog_map = {c["key"]: c for c in catalog}
    for key, lvl in inventory.items():
        item = catalog_map.get(key)
        if not item:
            continue
        base += float(item.get("inc") or 0.0) * int(lvl)
    for unit in progress.get("custom_units") or []:
        lvl = int(inventory.get(unit.get("key"), 0))
        base += float(unit.get("inc") or 0.0) * lvl

    up = (prestige or {}).get("up") or {}
    cps_mult = math.pow(1.10, int(up.get("cps_mult", 0)))
    flat = 100 * int(up.get("flat_cps", 0))

    tree_bonus = prestige_tree_bonus(prestige.get("tree") or [])
    boost = boost_multiplier(progress)
    event_mult = event_multiplier()
    ach_boost = achievement_boosts(prestige)

    total = max(0.0, base * cps_mult + flat)
    total *= ach_mult
    total *= event_mult
    total *= boost
    total *= ach_boost["cps_mult"]
    if ach_mult > 0 and progress.get("ach_all"):
        total += ach_all_bonus
    return total


def compute_click_power(cps: float, prestige: Dict) -> int:
    up = (prestige or {}).get("up") or {}
    click_lvl = int(up.get("click_mult") or 0)
    base = max(1, math.floor(1 + (cps / 1000) * 25))
    ach_boost = achievement_boosts(prestige)
    return int(base * (math.pow(1.25, click_lvl)) * ach_boost["click_mult"])


def shop_discount(prestige: Dict) -> float:
    up = (prestige or {}).get("up") or {}
    return min(0.02 * int(up.get("shop_discount") or 0), 0.50)


def refund_rate(prestige: Dict) -> float:
    up = (prestige or {}).get("up") or {}
    return min(0.50 + 0.05 * int(up.get("refund_plus") or 0), 0.95)


def crit_chance(prestige: Dict) -> float:
    up = (prestige or {}).get("up") or {}
    return min(0.05 * int(up.get("lucky_clicks") or 0), 0.75)


def asc_mult(prestige: Dict) -> float:
    up = (prestige or {}).get("up") or {}
    return 1.0 + 0.10 * int(up.get("asc_mult") or 0)


def start_boost(prestige: Dict) -> float:
    up = (prestige or {}).get("up") or {}
    return 10000 * int(up.get("start_boost") or 0)


def apply_offline_progress(progress: Dict, prestige: Dict) -> Tuple[float, float]:
    now = time.time()
    last_ts = progress.get("last_ts") or progress.get("saved_at") or now
    if not last_ts:
        progress["last_ts"] = now
        return 0.0, 0.0
    dt = max(0.0, now - float(last_ts))
    if dt <= 1:
        progress["last_ts"] = now
        return 0.0, dt
    tree_bonus = prestige_tree_bonus(prestige.get("tree") or [])
    base_cap_hours = 8
    cap_hours = base_cap_hours + tree_bonus.get("offline_hours", 0)
    max_dt = cap_hours * 3600
    awarded_dt = min(dt, max_dt)
    progress["last_ts"] = now
    progress["last_award_ts"] = now
    return awarded_dt, dt


def daily_reward(progress: Dict, prestige: Dict) -> Tuple[bool, Dict]:
    now = time.time()
    daily = progress.get("daily") or {"last_ts": None, "streak": 0}
    last_ts = daily.get("last_ts")
    if last_ts and now - float(last_ts) < 20 * 3600:
        return False, daily
    streak = int(daily.get("streak") or 0)
    if last_ts and now - float(last_ts) > 48 * 3600:
        streak = 0
    streak += 1
    daily["last_ts"] = now
    daily["streak"] = streak
    progress["daily"] = daily
    return True, daily


def daily_reward_amount(cps: float, prestige: Dict, streak: int) -> float:
    base = max(500.0, cps * 60)
    tree_bonus = prestige_tree_bonus(prestige.get("tree") or [])
    mult = 1.0 + tree_bonus.get("daily_mult", 0.0)
    streak_mult = 1.0 + min(streak, 7) * 0.05
    return base * mult * streak_mult


def quest_definitions(catalog: List[Dict]) -> List[Dict]:
    core = [item for item in catalog if item.get("tier") in ("early", "core")]
    return [
        {"key": "reach_cps", "name": "Reach a/s", "target": 1_000, "reward": 2000},
        {"key": "reach_count", "name": "Bank total", "target": 100_000, "reward": 5000},
        {"key": "buy_unit", "name": "Buy units", "target": 10, "reward": 1500, "unit": (core[0]["key"] if core else "rock")},
        {"key": "ascend", "name": "Ascend once", "target": 1, "reward": 5000},
    ]


def assign_quests(progress: Dict, catalog: List[Dict]) -> Dict:
    now = time.localtime()
    quest_state = progress.get("quests") or {"assigned": None, "claims": []}
    current_id = f"{now.tm_year}-{now.tm_yday}"
    if quest_state.get("assigned") == current_id:
        return quest_state
    defs = quest_definitions(catalog)
    random.shuffle(defs)
    quest_state = {
        "assigned": current_id,
        "list": defs[:3],
        "claims": [],
    }
    progress["quests"] = quest_state
    return quest_state


def quest_progress(progress: Dict, prestige: Dict, quest: Dict) -> Tuple[float, float]:
    key = quest.get("key")
    if key == "reach_cps":
        return float(progress.get("cps") or 0.0), float(quest.get("target") or 0)
    if key == "reach_count":
        return float(progress.get("count") or 0.0), float(quest.get("target") or 0)
    if key == "buy_unit":
        inv = progress.get("inventory") or {}
        return float(inv.get(quest.get("unit"), 0)), float(quest.get("target") or 0)
    if key == "ascend":
        return float(prestige.get("asc") or 0), float(quest.get("target") or 0)
    return 0.0, float(quest.get("target") or 0)


def quest_reward_amount(base: float, prestige: Dict) -> float:
    tree_bonus = prestige_tree_bonus(prestige.get("tree") or [])
    return base * (1.0 + tree_bonus.get("quest_mult", 0.0))


def validate_progress_payload(payload: Dict, catalog: List[Dict]) -> Tuple[bool, str, Dict]:
    if not isinstance(payload, dict):
        return False, "bad_payload", {}
    try:
        count = float(payload.get("count") or 0.0)
    except Exception:
        count = 0.0
    try:
        cps = float(payload.get("cps") or 0.0)
    except Exception:
        cps = 0.0

    if not math.isfinite(count) or not math.isfinite(cps):
        return False, "nan", {}
    if count < 0 or cps < 0 or count > MAX_COUNT or cps > MAX_CPS:
        return False, "range", {}

    inventory = payload.get("inventory") or {}
    if not isinstance(inventory, dict):
        return False, "bad_inventory", {}

    catalog_keys = {c["key"]: c for c in catalog}
    clean_inventory = {}
    for key, lvl in inventory.items():
        if not isinstance(key, str):
            continue
        if not isinstance(lvl, (int, float)):
            continue
        lvl_int = int(lvl)
        if lvl_int < 0 or lvl_int > MAX_LEVEL:
            return False, "bad_level", {}
        if key not in catalog_keys and not key.startswith("custom_"):
            return False, "bad_key", {}
        clean_inventory[key] = lvl_int

    custom_units = payload.get("custom_units") or []
    if not isinstance(custom_units, list):
        return False, "bad_custom", {}
    clean_custom = []
    for unit in custom_units[:MAX_CUSTOM_UNITS]:
        if not isinstance(unit, dict):
            continue
        name = str(unit.get("name") or "Custom")[:64]
        key = str(unit.get("key") or f"custom_{random.randint(1, 999999)}")[:64]
        try:
            base = float(unit.get("base") or 10)
        except Exception:
            base = 10.0
        base = max(10.0, min(base, 1e18))
        inc = custom_unit_inc(base)
        clean_custom.append({"key": key, "name": name, "base": base, "inc": inc})
        if key not in clean_inventory:
            clean_inventory[key] = 0

    return True, "", {"count": count, "cps": cps, "inventory": clean_inventory, "custom_units": clean_custom}
