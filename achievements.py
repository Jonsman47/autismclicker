from __future__ import annotations

from typing import Dict, List, Tuple

BASE_ACH_MULT = 1.0025

CPS_TARGETS = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1_000, 2_000, 5_000, 10_000, 20_000, 50_000, 100_000, 200_000, 500_000, 1_000_000, 2_000_000]
COUNT_TARGETS = [
    1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000, 1_000_000_000,
    10_000_000_000, 100_000_000_000, 1_000_000_000_000, 10_000_000_000_000,
    100_000_000_000_000, 1_000_000_000_000_000, 10_000_000_000_000_000,
    100_000_000_000_000_000, 1_000_000_000_000_000_000, 10_000_000_000_000_000_000,
    100_000_000_000_000_000_000, 1_000_000_000_000_000_000_000,
    10_000_000_000_000_000_000_000,
]
ASC_TARGETS = [1, 5, 10, 25, 50]
BUY_THRESHOLDS = [10, 25, 50, 100]

EXTREME_CPS = [
    (1_000_000_000_000_000_000_000_000, "ultra_cps_1t", "Insane a/s: 1T", 1.10),
    (1_000_000_000_000_000_000_000_000_000, "ultra_cps_1qa", "Insane a/s: 1Qa", 1.25),
    (1_000_000_000_000_000_000_000_000_000_000, "ultra_cps_1qi", "Beyond a/s: 1Qi", 1.50),
]
EXTREME_COUNT = [
    (10**30, "ultra_count_1e30", "Bank 1e30", 1.10),
    (10**33, "ultra_count_1e33", "Bank 1e33", 1.25),
    (10**36, "ultra_count_1e36", "Bank 1e36", 1.50),
]
EXTREME_ASC = [
    (100, "ultra_asc_100", "Ascend ×100", 1.10),
    (250, "ultra_asc_250", "Ascend ×250", 1.25),
    (500, "ultra_asc_500", "Ascend ×500", 1.50),
]

ALL_ACH_BONUS = 1000


def build_achievement_defs(core_keys: List[str]) -> List[Dict]:
    defs: List[Dict] = []
    for v in CPS_TARGETS:
        defs.append({
            "id": f"cps_{v}",
            "group": "cps",
            "name": f"Hit {v} a/s",
            "desc": f"Reach ≥ {v} autists/s",
            "mult": BASE_ACH_MULT,
            "category": "Milestones",
        })
    for v in COUNT_TARGETS:
        defs.append({
            "id": f"count_{v}",
            "group": "count",
            "name": f"Bank {v}",
            "desc": f"Total autists ≥ {v}",
            "mult": BASE_ACH_MULT,
            "category": "Milestones",
        })
    for v in ASC_TARGETS:
        defs.append({
            "id": f"asc_{v}",
            "group": "asc",
            "name": f"Ascend ×{v}",
            "desc": f"Perform {v} ascensions",
            "mult": BASE_ACH_MULT,
            "category": "Prestige",
        })
    for key in core_keys:
        for n in BUY_THRESHOLDS:
            defs.append({
                "id": f"buy_{key}_{n}",
                "group": "buy",
                "name": f"{key} ×{n}",
                "desc": f"Own {n} of {key}",
                "mult": BASE_ACH_MULT,
                "category": "Collection",
            })

    for v, aid, nm, mult in EXTREME_CPS:
        defs.append({
            "id": aid,
            "group": "cps",
            "name": nm,
            "desc": f"Reach ≥ {v} autists/s",
            "mult": float(mult),
            "category": "Extreme",
        })
    for v, aid, nm, mult in EXTREME_COUNT:
        defs.append({
            "id": aid,
            "group": "count",
            "name": nm,
            "desc": f"Total autists ≥ {v}",
            "mult": float(mult),
            "category": "Extreme",
        })
    for v, aid, nm, mult in EXTREME_ASC:
        defs.append({
            "id": aid,
            "group": "asc",
            "name": nm,
            "desc": f"Perform {v} ascensions",
            "mult": float(mult),
            "category": "Extreme",
        })

    return defs


def build_achievement_maps(core_keys: List[str]) -> Tuple[List[Dict], Dict[str, float]]:
    defs = build_achievement_defs(core_keys)
    mult_map = {d["id"]: float(d.get("mult", BASE_ACH_MULT)) for d in defs}
    return defs, mult_map


def achievement_multiplier(ach_ids: List[str], mult_map: Dict[str, float]) -> float:
    m = 1.0
    for aid in ach_ids or []:
        m *= mult_map.get(aid, BASE_ACH_MULT)
    return m


def scan_achievements(doc: Dict, catalog_keys: List[str], mult_map: Dict[str, float]) -> Dict:
    prog = (doc or {}).get("progress") or {}
    cps = float(prog.get("cps") or 0.0)
    total = float(prog.get("count") or 0.0)
    asc = int(((doc or {}).get("prestige") or {}).get("asc") or 0)
    inventory = prog.get("inventory") or {}

    have = set((doc or {}).get("ach") or [])

    for v in CPS_TARGETS:
        if cps >= v:
            have.add(f"cps_{v}")
    for v in COUNT_TARGETS:
        if total >= v:
            have.add(f"count_{v}")
    for v in ASC_TARGETS:
        if asc >= v:
            have.add(f"asc_{v}")

    for v, aid, _, _ in EXTREME_CPS:
        if cps >= v:
            have.add(aid)
    for v, aid, _, _ in EXTREME_COUNT:
        if total >= v:
            have.add(aid)
    for v, aid, _, _ in EXTREME_ASC:
        if asc >= v:
            have.add(aid)

    for key in catalog_keys:
        lv = int(inventory.get(key, 0))
        for n in BUY_THRESHOLDS:
            if lv >= n:
                have.add(f"buy_{key}_{n}")

    doc["ach"] = sorted(have)
    total_defs = len(mult_map)
    has_all = len(doc["ach"]) >= total_defs
    return {
        "count": len(doc["ach"]),
        "total": total_defs,
        "has_all": has_all,
    }
