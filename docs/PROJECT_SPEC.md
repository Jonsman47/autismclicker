# Autists Clicker Project Specification

This document captures the current state of the game, technical structure, gameplay systems, pain points, and a proposed upgrade roadmap. It is intended to be a single source of truth for future development and refactors.

## 1) What the game is right now (high-level)

Autists Clicker is a browser clicker/idle game served by a single Flask app (`app.py`) that contains:

- Auth (register/login/logout)
- The clicker game page (HTML/CSS/JS embedded inside Python)
- Server save/load of progress
- Shop system with many units (lots of tiers)
- Prestige system (Tryzomiques currency + upgrades + ascensions)
- Achievements system (server-authoritative, huge list)
- Public leaderboard (top by total + by CPS)
- User profiles (bio + stats + achievements preview)
- Reviews system (public ratings/comments)
- Admin panel stuff (user edits, uploads, shop sync, bots/reviews seeding, update note)

**Gameplay loop**

- Click button to increase “count”
- Buy units that generate passive “cps” (autists per second)
- Create custom units by paying a fixed cost
- Save/load either locally and/or server-side
- Ascend to reset progress and gain prestige currency
- Buy prestige upgrades to scale faster
- Unlock achievements that multiply CPS
- Compare with others on leaderboard + profiles

## 2) Current tech structure (what Codex is dealing with)

### Backend

- Flask app with sessions cookie auth.
- Database is a JSON file (`db.json`) with a file lock + atomic writes.
- Uploads stored under `uploads/` and served by `/uploads/<filename>`.
- Admin is hardcoded username: `ADMIN_USERNAME = "Jonsman47".lower()`.
- Bot tick system updates bot accounts over time.

**“DB” shape (important)**

```
{
  users: { username: doc },
  settings: { bg, logo, update, shop? },
  reviews: []
}
```

Each user doc includes:

- `pw` (hashed)
- `progress` (count/cps/shop list/etc)
- `prestige` (tryz, asc, upgrades)
- `ach` list of achievement IDs
- optional `profile` { bio }
- optional bot fields: `bot`, `bot_tick`

### Frontend

Not a separate project: the HTML/CSS/JS for pages is embedded in Python return strings.

The clicker page JS defines:

- Shop items (`DEFAULT_SHOP`) with many tiers and insane scaling
- Local save state (count/cps/shop)
- Server sync via `/api/save_progress` and `/api/load_progress`
- Achievements modal that calls `/api/achievements`
- Prestige panel calling `/api/prestige`, `/api/ascend`, `/api/buy_prestige_upgrade`, `/api/sell_prestige_upgrade`
- Reviews UI calling `/api/reviews` + `/api/reviews/summary`
- “Sync Shop” that fetches `/api/load_shop` (admin can overwrite with `/api/update_shop`)

## 3) Current gameplay systems (detailed)

### A) Clicking + CPS

- Base click gives +1 (then multiplied by prestige click multiplier + crit system).
- CPS is computed from owned shop units + prestige cps multiplier + flat cps upgrade + achievements multiplier.
- There’s also a “CPS (clicks/s)” meter tracking click frequency over last ~2 seconds.

### B) Shop / Units

Shop items are objects like:

- `key`, `name`, `base cost`, `inc` production per sec, `lvl` owned

Tiers include early/core/mid/random/giga/mega/ultra etc, going up to like 1e75 base costs.

**Buying**

- Cost scales per level (client-side logic)
- You can also sell (refund affected by `prestige refund_plus`)
- There’s a shop discount prestige upgrade (max 50% off)

**Custom units**

Pay a fixed cost (1000) to add a custom unit with:

- custom name
- base cost you choose
- `inc` is “random-ish” derived from base
- stored in your shop list

### C) Prestige (Ascension)

Prestige currency: Tryzomiques

“Ascend” resets progression but gives Tryz based on CPS:

```
estimate shown: floor((cps / 1_000_000) * ascMult())
```

Prestige upgrades are server-canonical (validated server-side):

- `cps_mult`: passive multiplier (x1.10 per level, up to 50)
- `click_mult`: click multiplier (x1.25 per level, up to 20)
- `start_boost`: start with +10k per level (up to 10)
- `asc_mult`: more tryz from ascension (+10% per level up to 50)
- `shop_discount`: -2% per level up to 50%
- `flat_cps`: +100 cps per level up to 200
- `refund_plus`: sell refund +5% per level up to 95% total
- `lucky_clicks`: crit chance +5% per level, crit is x3

### D) Achievements (server authority, huge)

Achievements are computed server-side by scanning:

- CPS milestones (list)
- Total count milestones (list)
- Ascension count milestones
- Per-unit ownership milestones (10/25/50/100 for each core unit key)
- “Extreme” achievements give bigger multipliers (+10/+25/+50%)

Base achievement bonus: multiplicative `1.0025 ** n`

If **ALL** achievements unlocked: +1000 flat CPS bonus

### E) Profiles

`/profile` page:

- Search usernames
- View stats: count, cps, tryz, asc, achievements
- Create a profile (only sets `profile: { bio:"" }`) then edit bio up to 280 chars
- Achievements preview list included

### F) Leaderboard

`/leaderboard` page fetches `/api/leaderboard`

Shows two leaderboards:

- top by total count
- top by cps

### G) Reviews

`/api/reviews` stores entries with `{u, stars, text, ts}`

Public summary endpoint shows average rating + count

Admin can seed fake reviews and delete a review by timestamp

### H) Admin powers

- Seed bots, seed reviews
- Set “Latest Update” note (but note: on `/` there’s an update form visible in the HTML — this should be locked down)
- Reset passwords, add/sub currency, delete user
- Upload assets: background + logo (served from uploads)
- Update shop data server-side

## 4) Big problems / pain points (what to fix)

### Gameplay / design

- Balance is chaotic: costs and production jump like crazy; early/mid pacing might feel either too fast or dead slow depending on choices.
- No structured progression besides “buy next unit”.
- No goals/quests/events to keep it sticky.
- No offline progress system (true idle).
- Custom unit system can break balance (players can create busted stuff).
- Achievements are huge but UI is basic; no “new achievement unlocked” dopamine.

### UX

- Shop can become massive; no search/filter/sort.
- No bulk buy (x10/x100/max) or “buy until next milestone”.
- No clearer breakdown of CPS sources.
- Mobile UX is okay but could be much better.

### Security / cheating

- A lot of game logic is client-side. A user can modify JS in devtools and upload insane saves.
- Need server validation / anti-cheat for uploaded progress (at least sanity checks).
- Admin update form appearing on home page looks like a mistake; admin actions should require admin auth + CSRF protection.
- JSON DB file is fragile for concurrency and scaling.

### Codebase maintainability

- `app.py` is a mega-monolith mixing backend + huge HTML + massive JS lists.
- No templates, no static bundling, no tests.
- venv included in repo zip (shouldn’t ship like that).

### Content / naming risk

- The theme uses “Autists” as the primary currency/unit naming. Even with a disclaimer page, it’s still likely to get flagged or to make people uncomfortable.
- If the goal is to keep the meme vibe, you still want a “safe mode” rename/theme toggle so the game can be shared publicly without drama.

## 5) Upgrade plan (features that would actually make it a better game)

Below is a concrete roadmap, in priority order.

### Phase 1: Make it fair + harder to cheat (must-have)

- Server-authoritative progress validation
- On `/api/save_progress`, validate:
  - count/cps non-negative, finite, within max ranges
  - shop items keys must exist in server shop list OR be allowed custom keys with strict limits
  - level increments must be plausible (no 10^9 levels)
- Add a server-side recompute:
  - server calculates CPS from shop levels + prestige + achievements
  - server rejects uploaded CPS if it doesn’t match within tolerance
- Add CSRF protection for all POST forms (admin + profile settings + auth forms if needed)
- Lock admin-only UI (update note editor, shop editor, seed buttons)
- Add rate limits on save/review endpoints

### Phase 2: Make progression addictive (core game design)

- Offline progress
  - Store `last_seen_ts` in server progress
  - On load, grant earnings for time away with caps (e.g. max 8h/24h unless upgrade)
- Daily rewards + streak
  - Daily login chest scaling with ascensions
- Quests system
  - Rotating goals: “buy 10 of X”, “reach Y cps”, “ascend once”, etc.
  - Rewards: currency boosts, temporary multipliers, cosmetics
- Timed events
  - Weekend event: +50% cps
  - Random “boost drops” every few minutes

### Phase 3: Shop UX that doesn’t suck

- Shop controls:
  - Search bar (by name/key)
  - Filters by tier (early/core/mid/giga/mega/ultra/custom)
  - Sort by cost / ROI / owned / production
- Bulk buy:
  - x1 / x10 / x100 / MAX
- Better unit cards:
  - Show: owned, next cost, current production, total production from that unit
  - Show ROI (seconds to pay back)

### Phase 4: Prestige depth (so it’s not just “reset for number”)

- Add prestige milestones that unlock mechanics:
  - Ascension 1: offline progress
  - Ascension 5: automation slot
  - Ascension 10: “research tree”
- Add a prestige skill tree (branching, not linear upgrades only)
- Add automation (late game)
  - Auto-buy specific units up to target levels
  - Auto-click limited by energy system

### Phase 5: Achievements feel rewarding

- Achievement popups:
  - Toast on unlock + sound toggle
- Achievement categories + progress bars
- “Achievement points” to spend on cosmetics or minor boosts
- Keep server authority but cache smartly

### Phase 6: Profiles + community

- Better profile:
  - Show top owned units, build style, prestige tree snapshot
- Leaderboard seasons:
  - Monthly reset leaderboard with seasonal badges
- Reporting/moderation for reviews

### Phase 7: Make it safe to share publicly (theme toggle)

- Add Theme Mode:
  - “Meme mode” (current names)
  - “Clean mode” (rename currency/units to neutral like “Clicks”, “Workers”, “Bots”, “Energy”, etc.)
- Store user preference in profile/session
- Make leaderboard show names neutral in clean mode

## 6) Concrete implementation checklist (what Codex should do in code)

### Refactor structure (minimum to stay sane)

Split into:

- `app.py` (routes only)
- `db.py` (load/save, locking)
- `game_logic.py` (recompute cps, validate saves, pricing)
- `achievements.py` (defs + scanning)
- `templates/` (Jinja) for pages
- `static/` for JS/CSS, move the giant clicker JS out of Python strings

### Server-side “truth” engine

- Create canonical “shop catalog” on server (from settings or default list).
- Store user inventory as `{key: lvl}` rather than full list duplication.
- On save:
  - server merges inventory with catalog + custom definitions
  - server recomputes:
    - base cps from units
    - applies prestige multipliers
    - applies achievements multipliers
  - server stores final cps + count
- On click:
  - (optional) create `/api/click` to record clicks server-side if you want real anti-cheat

### Offline progress

Add fields:

- `progress.last_ts`
- `progress.last_award_ts`

On load:

- award = cps * dt (cap dt)
- update count and last_ts

### Shop UX + bulk buy

- Update frontend JS:
  - add buy modes, search/filter/sort
  - add ROI compute
- Update backend:
  - optional endpoint for “buy” actions server-side if going full authoritative

### Admin fixes

- Remove the update-note editor from `/` for non-admin
- Add CSRF token validation to all admin POSTs
- Add auth checks to any endpoint that can mutate global settings

## 7) Acceptance tests (how to know it’s done)

- If someone edits JS and tries to upload a save with impossible CPS, server rejects it.
- Offline progress works: leave for 10 minutes, come back, count increases appropriately.
- Bulk buy works and feels smooth.
- Shop is searchable and not a scroll nightmare.
- Achievements pop and feel rewarding.
- Clean mode exists and the game can be shown to people without getting instantly flagged.
