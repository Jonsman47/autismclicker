const csrfToken = window.APP_CONFIG?.csrfToken || "";
const isAdmin = window.APP_CONFIG?.isAdmin || false;
let themeMode = window.APP_CONFIG?.themeMode || "meme";

const THEME_TEXT = {
  meme: {
    count: "Autists",
    cps: "a/s",
    click: "+1",
    create: "Create custom Autist (cost: 1000)",
    unit: "Autist",
  },
  clean: {
    count: "Clicks",
    cps: "c/s",
    click: "+1",
    create: "Create custom Unit (cost: 1000)",
    unit: "Unit",
  }
};

let catalog = [];
let catalogMap = {};
let inventory = {};
let customUnits = [];
let count = 0;
let cps = 0;
let prestige = { tryz: 0, asc: 0, up: {}, tree: [], ach_spend: {} };
let prestigeDefs = [];
let prestigeTree = [];
let achievements = { unlocked: new Set(), defs: [], count: 0, total: 0, mult: 1, all: false, allBonus: 1000 };
let quests = [];
let boost = { mult: 1.0, until: null };
let buyMode = 1;
let soundEnabled = localStorage.getItem("ach_sound") !== "off";
let automation = { auto_click: false, auto_buy: false, targets: {} };
let energy = { current: 0, max: 0 };
let daily = { last_ts: null, streak: 0 };

const CPS_WINDOW_MS = 2000;
let clickTimes = [];
let cpsClick = 0;

function fmt(n){
  n = Number(n)||0;
  const scales = [
    [1e75,"qavg"],[1e72,"tvg"],[1e69,"dvg"],[1e66,"uvg"],[1e63,"vg"],
    [1e60,"nd"],[1e57,"od"],[1e54,"spd"],[1e51,"sxd"],[1e48,"qid"],
    [1e45,"qad"],[1e42,"td"],[1e39,"dd"],[1e36,"ud"],[1e33,"de"],
    [1e30,"no"],[1e27,"oc"],[1e24,"sp"],[1e21,"sx"],[1e18,"qi"],
    [1e15,"qa"],[1e12,"t"],[1e9,"b"],[1e6,"m"],[1e3,"k"],
  ];
  for (const [div,suf] of scales){
    if (Math.abs(n) >= div){
      const val = (n/div).toFixed(2).replace(/\.00$/,'').replace(/(\.\d*[1-9])0$/,'$1');
      return `${val}${suf}`;
    }
  }
  return String(Math.trunc(n));
}

function toast(msg){
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.classList.add("show");
  setTimeout(()=> el.classList.remove("show"), 2200);
}

function playBeep(){
  try{
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = "sine";
    osc.frequency.value = 640;
    gain.gain.value = 0.05;
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    setTimeout(()=>{ osc.stop(); ctx.close(); }, 160);
  }catch(e){}
}

function themeName(item){
  return themeMode === "clean" ? (item.clean_name || item.name) : item.name;
}

function applyTheme(){
  const text = THEME_TEXT[themeMode] || THEME_TEXT.meme;
  document.body.dataset.theme = themeMode;
  document.getElementById("label_count").textContent = text.count;
  document.getElementById("label_cps").textContent = text.cps;
  document.getElementById("click").childNodes[0].nodeValue = `${text.click} ${text.unit}`;
  document.getElementById("lbl_create").textContent = text.create;
  document.getElementById("title").textContent = themeMode === "clean" ? "Clicker" : "Autists Clicker";
}

function pushClick(){
  const now = Date.now();
  clickTimes.push(now);
  clickTimes = clickTimes.filter(t=> now - t <= CPS_WINDOW_MS);
  cpsClick = clickTimes.length / (CPS_WINDOW_MS/1000);
  document.getElementById("cps_click").textContent = cpsClick.toFixed(2);
}

function prestigeGet(key){ return Number((prestige.up||{})[key]||0); }
function prestigeMultCps(){ return Math.pow(1.10, prestigeGet("cps_mult")); }
function prestigeMultClick(){ return Math.pow(1.25, prestigeGet("click_mult")); }
function shopDiscount(){ return Math.min(0.02 * prestigeGet("shop_discount"), 0.50); }
function flatCps(){ return 100 * prestigeGet("flat_cps"); }
function refundRate(){ return Math.min(0.50 + 0.05 * prestigeGet("refund_plus"), 0.95); }
function critChance(){ return Math.min(0.05 * prestigeGet("lucky_clicks"), 0.75); }
function ascMult(){ return 1 + 0.10 * prestigeGet("asc_mult"); }

function achBoost(key){
  const spent = prestige.ach_spend || {};
  if(key === "minor_cps") return 1 + 0.01 * (spent.minor_cps || 0);
  if(key === "minor_click") return 1 + 0.01 * (spent.minor_click || 0);
  return 1;
}

function costOf(item, lvl){
  const level = lvl ?? (inventory[item.key] || 0);
  const raw = Math.floor(item.base * Math.pow(1.15, level));
  return Math.max(1, Math.floor(raw * (1 - shopDiscount())));
}

function costForLevels(item, levels){
  let total = 0;
  let start = inventory[item.key] || 0;
  for (let i = 0; i < levels; i++){
    total += costOf(item, start + i);
  }
  return total;
}

function maxAffordable(item){
  let lvl = 0;
  let spent = 0;
  let start = inventory[item.key] || 0;
  while (lvl < 1000){
    const price = costOf(item, start + lvl);
    if (spent + price > count) break;
    spent += price;
    lvl += 1;
  }
  return lvl;
}

function unitInc(item){ return item.inc || 0; }

function recalc(){
  let base = 0;
  for (const item of catalog){
    base += unitInc(item) * (inventory[item.key] || 0);
  }
  for (const unit of customUnits){
    base += (unit.inc || 0) * (inventory[unit.key] || 0);
  }
  let next = Math.max(0, base * prestigeMultCps() + flatCps());
  next *= achievements.mult || 1;
  next *= achBoost("minor_cps");
  if (achievements.all){ next += achievements.allBonus || 0; }
  cps = next;
}

function clickPower(){
  const base = Math.max(1, Math.floor(1 + (cps/1000)*25));
  return Math.floor(base * prestigeMultClick() * achBoost("minor_click"));
}

function updateClickButton(){
  const btn = document.getElementById("click");
  if (btn) btn.childNodes[0].nodeValue = `+${fmt(clickPower())}`;
}

function update(){
  document.getElementById("count").textContent = fmt(count);
  document.getElementById("cps").textContent   = fmt(cps);
  document.getElementById("tryz_bal").textContent = fmt(prestige.tryz||0);
  document.getElementById("tryz_est").textContent = Math.floor(((cps||0)/1_000_000) * ascMult());
  updateClickButton();
}

function updateDailyStatus(){
  const status = document.getElementById("daily_status");
  if (!daily.last_ts){
    status.textContent = `Streak: ${daily.streak || 0} — Ready to claim.`;
    return;
  }
  const now = Date.now();
  const since = (now - daily.last_ts * 1000) / 3600000;
  if (since >= 20){
    status.textContent = `Streak: ${daily.streak || 0} — Ready to claim.`;
  } else {
    const wait = Math.max(0, Math.ceil(20 - since));
    status.textContent = `Streak: ${daily.streak || 0} — Available in ~${wait}h.`;
  }
}

function renderShop(){
  const search = (document.getElementById("shop_search").value || "").toLowerCase();
  const filter = document.getElementById("shop_filter").value;
  const sort = document.getElementById("shop_sort").value;

  let items = catalog.filter(item=>{
    const name = themeName(item).toLowerCase();
    const match = name.includes(search) || item.key.toLowerCase().includes(search);
    const tierOk = filter === "all" || item.tier === filter;
    return match && tierOk;
  });

  items.sort((a,b)=>{
    if (sort === "owned") return (inventory[b.key]||0) - (inventory[a.key]||0);
    if (sort === "prod") return (unitInc(b)) - (unitInc(a));
    if (sort === "roi"){
      const roiA = costOf(a) / Math.max(1, unitInc(a));
      const roiB = costOf(b) / Math.max(1, unitInc(b));
      return roiA - roiB;
    }
    return costOf(a) - costOf(b);
  });

  const el = document.getElementById("shop");
  el.innerHTML = "";
  items.forEach(item=>{
    const price = costOf(item);
    const owned = inventory[item.key] || 0;
    const totalProd = unitInc(item) * owned;
    const roi = price / Math.max(1, unitInc(item));
    const canBuy = count >= price;
    const refund = Math.floor(price * refundRate());

    const card = document.createElement("div");
    card.className = "shop-card";
    card.innerHTML = `
      <div>
        <div style="font-size:18px;font-weight:700">${themeName(item)}</div>
        <div class="shop-meta">Owned: ${fmt(owned)} | Next cost: ${fmt(price)} | +${fmt(unitInc(item))}/s | Total: ${fmt(totalProd)}/s</div>
        <div class="shop-meta">ROI: ${fmt(roi)}s | Tier: ${item.tier}</div>
      </div>
      <div class="shop-actions">
        <button data-buy="${item.key}" class="btn ${canBuy ? 'orange' : ''}">Buy</button>
        <button data-sell="${item.key}" class="btn red" ${owned > 0 ? '' : 'disabled'}>Sell</button>
        <span class="pill">+${fmt(refund)}</span>
      </div>
    `;
    card.querySelector("[data-buy]").onclick = ()=> buyUnit(item.key);
    const sellBtn = card.querySelector("[data-sell]");
    if (owned > 0){
      sellBtn.onclick = ()=> sellUnit(item.key, 1);
    }
    el.appendChild(card);
  });
}

function buyUnit(key){
  const item = catalogMap[key] || customUnits.find(u=>u.key === key);
  if (!item) return;
  let qty = buyMode === "max" ? maxAffordable(item) : buyMode;
  if (!qty || qty < 1) return;
  const cost = costForLevels(item, qty);
  if (count < cost) return;
  count -= cost;
  inventory[item.key] = (inventory[item.key] || 0) + qty;
  recalc();
  renderShop();
  update();
}

function sellUnit(key, qty){
  const item = catalogMap[key] || customUnits.find(u=>u.key === key);
  if (!item) return;
  const owned = inventory[key] || 0;
  if (owned <= 0) return;
  const toSell = Math.min(owned, qty || 1);
  for (let i = 0; i < toSell; i++){
    const price = costOf(item);
    const refund = Math.floor(price * refundRate());
    count += refund;
    inventory[key] = (inventory[key] || 0) - 1;
  }
  recalc();
  renderShop();
  update();
}

function renderPrestigeShop(){
  const wrap = document.getElementById("prestige_shop");
  wrap.innerHTML = "";
  prestigeDefs.forEach(def=>{
    const lvl = prestigeGet(def.key);
    const next = lvl + 1;
    const cost = def.base * next;
    const can = (prestige.tryz||0) >= cost && lvl < def.max;

    const row = document.createElement("div");
    row.className = "card";
    row.innerHTML = `
      <div>
        <div style="font-weight:700">${def.name}</div>
        <div class="shop-meta">Level: ${lvl}/${def.max}</div>
      </div>
      <div class="row">
        <div class="pill">Cost: ${fmt(cost)}</div>
        <button class="btn ${can ? 'orange' : ''}" ${can?'':'disabled'} data-up="${def.key}">${can ? 'Buy' : 'Need ' + fmt(cost)}</button>
        <button class="btn red" data-sell="${def.key}" ${lvl>0?'':'disabled'}>Sell</button>
      </div>
    `;
    row.querySelector("[data-up]").onclick = ()=> buyPrestige(def.key);
    row.querySelector("[data-sell]").onclick = ()=> sellPrestige(def.key);
    wrap.appendChild(row);
  });
}

function renderPrestigeTree(){
  const wrap = document.getElementById("prestige_tree");
  wrap.innerHTML = "";
  prestigeTree.forEach(node=>{
    const owned = (prestige.tree || []).includes(node.key);
    const locked = (node.requires || []).some(req => !(prestige.tree || []).includes(req));
    const can = !owned && !locked && (prestige.tryz || 0) >= node.cost;
    const row = document.createElement("div");
    row.className = "card";
    row.innerHTML = `
      <div>
        <div style="font-weight:700">${node.name}</div>
        <div class="shop-meta">${node.desc}</div>
      </div>
      <div class="row">
        <span class="pill">Cost: ${fmt(node.cost)}</span>
        <button class="btn ${can ? 'orange' : ''}" data-node="${node.key}" ${can ? '' : 'disabled'}>${owned ? 'Owned' : locked ? 'Locked' : 'Buy'}</button>
      </div>
    `;
    row.querySelector("[data-node]").onclick = ()=> buyPrestigeTree(node.key);
    wrap.appendChild(row);
  });
}

async function buyPrestige(key){
  const r = await fetch("/api/buy_prestige_upgrade", {
    method:"POST",
    headers:{"Content-Type":"application/json","X-CSRF-Token": csrfToken},
    body: JSON.stringify({key})
  });
  const j = await r.json();
  if(j.ok){
    prestige = j.prestige;
    recalc(); update(); renderPrestigeShop();
  }
}

async function sellPrestige(key){
  const r = await fetch("/api/sell_prestige_upgrade", {
    method:"POST",
    headers:{"Content-Type":"application/json","X-CSRF-Token": csrfToken},
    body: JSON.stringify({key})
  });
  const j = await r.json();
  if(j.ok){
    prestige = j.prestige;
    recalc(); update(); renderPrestigeShop();
  }
}

async function buyPrestigeTree(key){
  const r = await fetch("/api/buy_prestige_tree", {
    method:"POST",
    headers:{"Content-Type":"application/json","X-CSRF-Token": csrfToken},
    body: JSON.stringify({key})
  });
  const j = await r.json();
  if(j.ok){
    prestige = j.prestige;
    renderPrestigeTree();
    renderAutomation();
  }
}

function renderAutomation(){
  const unlocked = (prestige.asc || 0) >= 5 || (prestige.tree || []).includes("automation_slot");
  const card = document.getElementById("automation");
  card.style.display = unlocked ? "block" : "none";
  if(!unlocked) return;

  document.getElementById("auto_click").checked = automation.auto_click || false;
  document.getElementById("auto_buy").checked = automation.auto_buy || false;
  document.getElementById("energy_state").textContent = `Energy: ${energy.current}/${energy.max}`;

  const targetWrap = document.getElementById("auto_targets");
  targetWrap.innerHTML = "";
  catalog.filter(item=> item.tier === "early" || item.tier === "core").slice(0,6).forEach(item=>{
    const row = document.createElement("div");
    row.className = "row";
    row.innerHTML = `
      <div>${themeName(item)}</div>
      <input data-target="${item.key}" type="number" min="0" value="${automation.targets[item.key] || 0}">
    `;
    row.querySelector("[data-target]").addEventListener("change", (e)=>{
      automation.targets[item.key] = Number(e.target.value || 0);
    });
    targetWrap.appendChild(row);
  });
}

function tickAutomation(){
  const unlocked = (prestige.asc || 0) >= 5 || (prestige.tree || []).includes("automation_slot");
  if(!unlocked) return;
  energy.max = 10 + (prestige.asc || 0);
  energy.current = Math.min(energy.max, energy.current + 1);

  if (automation.auto_click && energy.current >= 1){
    energy.current -= 1;
    count += clickPower();
  }

  if (automation.auto_buy){
    for (const [key, target] of Object.entries(automation.targets || {})){
      if ((inventory[key] || 0) < target){
        buyUnit(key);
      }
    }
  }
  document.getElementById("energy_state").textContent = `Energy: ${energy.current}/${energy.max}`;
}

function renderAchievements(){
  const head = document.getElementById("ach_head");
  head.textContent = `Unlocked ${achievements.count}/${achievements.total} — Mult x${(achievements.mult||1).toFixed(2)}${achievements.all?` — +${achievements.allBonus}/s bonus`:``}`;

  const progressWrap = document.getElementById("ach_progress");
  progressWrap.innerHTML = "";
  const grouped = {};
  achievements.defs.forEach(def=>{
    const cat = def.category || def.group || "Other";
    grouped[cat] = grouped[cat] || { total: 0, unlocked: 0 };
    grouped[cat].total += 1;
    if (achievements.unlocked.has(def.id)) grouped[cat].unlocked += 1;
  });
  Object.entries(grouped).forEach(([cat, data])=>{
    const row = document.createElement("div");
    row.className = "ach-progress";
    const pct = data.total ? (data.unlocked / data.total) * 100 : 0;
    row.innerHTML = `
      <div style="min-width:120px">${cat}</div>
      <div class="ach-bar"><span style="width:${pct}%"></span></div>
      <div class="pill">${data.unlocked}/${data.total}</div>
    `;
    progressWrap.appendChild(row);
  });

  const wrap = document.getElementById("ach_list");
  wrap.innerHTML = "";
  achievements.defs.forEach(def=>{
    const ok = achievements.unlocked.has(def.id);
    const row = document.createElement("div");
    row.className = "ach" + (ok ? " ok" : "");
    row.innerHTML = `
      <div>
        <div style="font-weight:700">${def.name}</div>
        <div style="opacity:.8">${def.desc}</div>
        <div style="opacity:.6;font-size:.9rem">${(def.category || def.group || '').toUpperCase()}</div>
      </div>
      <div class="pill">${ok ? ("✓ +" + (((Number(def.mult||1)-1)*100).toFixed(2)) + "%") : "Locked"}</div>
    `;
    wrap.appendChild(row);
  });

  const spend = prestige.ach_spend || {};
  const spentTotal = Object.values(spend).reduce((s,v)=> s + Number(v||0), 0);
  const available = Math.max(0, achievements.count - spentTotal);
  document.getElementById("ach_points").textContent = `Available points: ${available}`;

  const shop = document.getElementById("ach_shop");
  shop.innerHTML = "";
  (achievements.boosts || []).forEach(boost=>{
    const lvl = spend[boost.key] || 0;
    const can = available >= boost.cost && lvl < boost.max;
    const row = document.createElement("div");
    row.className = "ach";
    row.innerHTML = `
      <div>
        <div style="font-weight:700">${boost.name}</div>
        <div class="shop-meta">Level: ${lvl}/${boost.max}</div>
      </div>
      <button class="btn ${can ? 'orange' : ''}" data-boost="${boost.key}" ${can ? '' : 'disabled'}>Spend ${boost.cost}</button>
    `;
    row.querySelector("[data-boost]").onclick = ()=> spendAchievement(boost.key);
    shop.appendChild(row);
  });
}

function bindAchievementSound(){
  const toggle = document.getElementById("ach_sound");
  if (!toggle) return;
  toggle.checked = soundEnabled;
  toggle.addEventListener("change", () => {
    soundEnabled = toggle.checked;
    localStorage.setItem("ach_sound", soundEnabled ? "on" : "off");
  });
}

async function spendAchievement(key){
  const r = await fetch("/api/achievements/spend", {
    method:"POST",
    headers:{"Content-Type":"application/json","X-CSRF-Token": csrfToken},
    body: JSON.stringify({key})
  });
  const j = await r.json();
  if(j.ok){
    prestige.ach_spend = j.spent;
    renderAchievements();
  }
}

function openAch(){
  document.getElementById("ach_backdrop").style.display="block";
  document.getElementById("ach_modal").style.display="block";
  renderAchievements();
}
function closeAch(){
  document.getElementById("ach_backdrop").style.display="none";
  document.getElementById("ach_modal").style.display="none";
}

function updateQuests(){
  const wrap = document.getElementById("quest_list");
  wrap.innerHTML = "";
  quests.forEach(q=>{
    const pct = q.target ? Math.min(100, (q.progress / q.target) * 100) : 0;
    const card = document.createElement("div");
    card.className = "quest-card";
    card.innerHTML = `
      <div>
        <div style="font-weight:700">${q.name}</div>
        <div class="shop-meta">${fmt(q.progress)}/${fmt(q.target)}</div>
        <div class="ach-bar"><span style="width:${pct}%"></span></div>
      </div>
      <button class="btn ${q.progress >= q.target && !q.claimed ? 'orange' : ''}" ${q.claimed ? 'disabled' : ''} data-quest="${q.key}">${q.claimed ? 'Claimed' : 'Claim'}</button>
    `;
    card.querySelector("[data-quest]").onclick = ()=> claimQuest(q.key);
    wrap.appendChild(card);
  });
}

async function claimQuest(key){
  const r = await fetch("/api/quests/claim", {
    method:"POST",
    headers:{"Content-Type":"application/json", "X-CSRF-Token": csrfToken},
    body: JSON.stringify({key})
  });
  const j = await r.json();
  if(j.ok){
    toast(`Quest reward +${fmt(j.reward)}`);
    await loadQuests();
    await loadProgress();
  }
}

async function loadQuests(){
  const r = await fetch("/api/quests", {cache:"no-store"});
  const j = await r.json();
  if(j.ok){
    quests = j.quests || [];
    updateQuests();
  }
}

async function loadUpdateBox(){
  const r = await fetch("/api/update", {cache:"no-store"});
  const j = await r.json();
  if(j.ok){
    document.getElementById("update_text").textContent = j.update || "—";
  }
}

async function loadReviewSummary(){
  const r = await fetch("/api/reviews/summary", {cache:"no-store"});
  const j = await r.json();
  if(j.ok){
    document.getElementById("rating_summary").textContent = `⭐ ${Number(j.avg||0).toFixed(2)} — ${j.count||0} reviews`;
  }
}

function renderReviews(list){
  const wrap = document.getElementById("rev_list");
  wrap.innerHTML = "";
  if(!list || !list.length){
    wrap.innerHTML = `<div class="pill">No reviews yet.</div>`;
    return;
  }
  list.forEach(r=>{
    const card = document.createElement("div");
    card.className = "card";
    const when = new Date((r.ts||0)*1000).toLocaleString();
    const stars = Number(r.stars)||0;
    card.innerHTML = `
      <div class="row space">
        <div style="font-weight:700">${(r.u||"Anonymous")}</div>
        <div class="row">
          <div class="pill">${"★".repeat(stars) + "☆".repeat(5-stars)}</div>
          <button class="btn" data-report="${r.ts}">Report</button>
          ${isAdmin ? `<button class="btn red" data-del="${r.ts}">Delete</button>` : ``}
        </div>
      </div>
      <div style="margin-top:6px;white-space:pre-wrap">${(r.text||"").replace(/[<>&]/g, s => ({ "<":"&lt;", ">":"&gt;", "&":"&amp;" }[s]))}</div>
      <div style="opacity:.7;margin-top:6px;font-size:.85rem">${when}</div>
    `;

    card.querySelector(`[data-report="${r.ts}"]`).onclick = async ()=>{
      const reason = prompt("Report reason (optional):") || "";
      const res = await fetch("/api/reviews/report", {
        method:"POST",
        headers:{"Content-Type":"application/json", "X-CSRF-Token": csrfToken},
        body: JSON.stringify({ts: r.ts, reason})
      });
      const j = await res.json().catch(()=>({}));
      if(j.ok){ toast("Report sent."); }
    };

    if (isAdmin){
      card.querySelector(`[data-del="${r.ts}"]`).onclick = async ()=>{
        const res = await fetch("/admin/delete_review", {
          method: "POST",
          headers: {"Content-Type": "application/x-www-form-urlencoded", "X-CSRF-Token": csrfToken},
          body: "ts=" + encodeURIComponent(r.ts) + "&csrf_token=" + encodeURIComponent(csrfToken)
        });
        const j = await res.json().catch(()=>({}));
        if(j.ok){ card.remove(); loadReviewSummary(); }
      };
    }
    wrap.appendChild(card);
  });
}

async function loadReviews(){
  const r = await fetch("/api/reviews", {cache:"no-store"});
  const j = await r.json();
  if(j.ok){ renderReviews(j.reviews||[]); }
}

async function postReview(){
  const stars = Number(document.getElementById("rev_stars").value);
  const text = (document.getElementById("rev_text").value||"").trim();
  const msg = document.getElementById("rev_msg");
  if(!text){ msg.textContent = "Please write something."; return; }
  const r = await fetch("/api/reviews", {
    method:"POST",
    headers:{"Content-Type":"application/json", "X-CSRF-Token": csrfToken},
    body: JSON.stringify({stars, text})
  });
  const j = await r.json();
  if(j.ok){
    document.getElementById("rev_text").value = "";
    msg.textContent = "Thanks for the review!";
    await loadReviewSummary();
    await loadReviews();
  } else {
    msg.textContent = j.err || "Error";
  }
}

async function saveServer(){
  const payload = { v:5, count, cps, inventory, custom_units: customUnits };
  const r = await fetch("/api/save_progress", {
    method:"POST",
    headers:{"Content-Type":"application/json", "X-CSRF-Token": csrfToken},
    credentials:"same-origin",
    body: JSON.stringify(payload)
  });
  if (r.status === 401){
    document.getElementById("sync_msg").textContent = "Login first";
    return;
  }
  const j = await r.json().catch(()=>({}));
  document.getElementById("sync_msg").textContent = j.ok ? "✓" : (j.err || "x");
}

async function loadProgress(){
  const r = await fetch("/api/load_progress", { credentials:"same-origin" });
  if (r.status === 401){
    document.getElementById("sync_msg").textContent = "Login first";
    return;
  }
  const j = await r.json().catch(()=>({}));
  if (j.ok){
    const p = j.progress || {};
    count = Number(p.count)||0;
    cps = Number(p.cps)||0;
    inventory = p.inventory || {};
    customUnits = p.custom_units || [];
    daily = p.daily || daily;
    prestige = j.prestige || prestige;
    achievements.defs = (j.achievements || {}).defs || [];
    achievements.boosts = (j.achievements || {}).boosts || [];
    const newUnlocked = new Set((j.achievements || {}).unlocked || []);
    const diff = [...newUnlocked].filter(x => !achievements.unlocked.has(x));
    achievements.unlocked = newUnlocked;
    achievements.count = (j.achievements || {}).count || 0;
    achievements.total = (j.achievements || {}).total || 0;
    achievements.mult = (j.achievements || {}).mult || 1;
    achievements.all = (j.achievements || {}).all || false;
    achievements.allBonus = (j.achievements || {}).all_bonus || 1000;
    prestige.ach_spend = (j.achievements || {}).spent || prestige.ach_spend || {};
    quests = j.quests?.list ? j.quests.list : quests;

    if (diff.length){
      diff.slice(0,3).forEach(id=>{
        toast(`Achievement unlocked: ${id}`);
        if (soundEnabled){ playBeep(); }
      });
    }
    if (j.offline && j.offline.amount > 0){
      toast(`Offline progress +${fmt(j.offline.amount)}`);
    }
    recalc();
    renderShop();
    renderPrestigeShop();
    renderPrestigeTree();
    renderAutomation();
    update();
    updateDailyStatus();
  }
}

async function loadPrestige(){
  const r = await fetch("/api/prestige", {cache:"no-store"});
  const j = await r.json();
  if(j.ok){
    prestige = j.prestige || prestige;
    prestigeDefs = j.upgrades || [];
    prestigeTree = j.tree || [];
    renderPrestigeShop();
    renderPrestigeTree();
    renderAutomation();
  }
}

async function loadShop(){
  const r = await fetch("/api/shop", {cache:"no-store"});
  const j = await r.json();
  if(j.ok){
    catalog = j.shop || [];
    catalogMap = Object.fromEntries(catalog.map(item=>[item.key, item]));
    const filter = document.getElementById("shop_filter");
    filter.innerHTML = "";
    const optAll = document.createElement("option");
    optAll.value = "all";
    optAll.textContent = "All tiers";
    filter.appendChild(optAll);
    (j.tiers || []).forEach(tier=>{
      const opt = document.createElement("option");
      opt.value = tier;
      opt.textContent = tier;
      filter.appendChild(opt);
    });
    renderShop();
  }
}

async function syncShopWithDefaults(){
  const r = await fetch("/api/shop", {cache:"no-store"});
  const j = await r.json();
  if(j.ok){
    catalog = j.shop || [];
    catalogMap = Object.fromEntries(catalog.map(item=>[item.key, item]));
    renderShop();
    document.getElementById("sync_msg").textContent = "Shop sync ✓";
  }
}

function addCustom(name, base){
  const unit = { key:`custom_${Date.now()}`, name, base:Number(base), inc:Math.max(1, Math.round(Math.sqrt(base) * 8)) };
  customUnits.push(unit);
  inventory[unit.key] = 0;
  count -= 1000;
  recalc();
  renderShop();
  update();
  return unit;
}

async function claimDaily(){
  const r = await fetch("/api/daily_reward", {
    method:"POST",
    headers:{"Content-Type":"application/json", "X-CSRF-Token": csrfToken}
  });
  const j = await r.json();
  if(j.ok){
    toast(`Daily reward +${fmt(j.reward)}`);
    daily = j.daily || daily;
    updateDailyStatus();
    await loadProgress();
  } else {
    document.getElementById("daily_status").textContent = j.err || "Too soon";
  }
}

function updateEventBanner(){
  const now = new Date();
  const weekend = now.getDay() === 0 || now.getDay() === 6;
  document.getElementById("event_banner").textContent = weekend ? "Weekend Event: +50% CPS" : "No event active.";
}

async function rollBoost(){
  const r = await fetch("/api/boost", {
    method:"POST",
    headers:{"Content-Type":"application/json", "X-CSRF-Token": csrfToken},
    body: JSON.stringify({})
  });
  const j = await r.json();
  if(j.ok && j.boost){
    boost = j.boost;
    if (boost.mult && boost.mult > 1 && boost.until){
      document.getElementById("boost_banner").textContent = `Boost active: x${boost.mult} until ${new Date(boost.until*1000).toLocaleTimeString()}`;
    } else {
      document.getElementById("boost_banner").textContent = "No boosts active.";
    }
  }
}

async function toggleTheme(){
  themeMode = themeMode === "clean" ? "meme" : "clean";
  await fetch("/api/theme", {
    method:"POST",
    headers:{"Content-Type":"application/json", "X-CSRF-Token": csrfToken},
    body: JSON.stringify({mode: themeMode})
  });
  applyTheme();
  renderShop();
}

function renderBuyModeButtons(){
  document.querySelectorAll("[data-buy]").forEach(btn=>{
    btn.classList.toggle("orange", btn.dataset.buy === String(buyMode));
  });
}

function bindEvents(){
  document.getElementById("click").onclick = async () => {
    let add = clickPower();
    if (Math.random() < critChance()) add = Math.floor(add * 3);
    count += add;
    pushClick();
    update();
  };
  document.getElementById("btn_save").onclick = saveServer;
  document.getElementById("btn_load").onclick = loadProgress;
  document.getElementById("btn_sync_shop").onclick = syncShopWithDefaults;
  document.getElementById("btn_ach").onclick = openAch;
  document.getElementById("ach_close").onclick = closeAch;
  document.getElementById("ach_backdrop").onclick = closeAch;
  document.getElementById("rev_send").onclick = postReview;
  document.getElementById("btn_daily").onclick = claimDaily;
  document.getElementById("theme_toggle").onclick = toggleTheme;

  document.getElementById("shop_search").addEventListener("input", renderShop);
  document.getElementById("shop_filter").addEventListener("change", renderShop);
  document.getElementById("shop_sort").addEventListener("change", renderShop);

  document.querySelectorAll(".buy-modes button").forEach(btn=>{
    btn.onclick = ()=>{
      buyMode = btn.dataset.buy === "max" ? "max" : Number(btn.dataset.buy || 1);
      renderBuyModeButtons();
    };
  });

  document.getElementById("c_make").onclick = ()=>{
    const name = (document.getElementById("c_name").value || "").trim();
    const base = Number(document.getElementById("c_cost").value);
    const msg = document.getElementById("c_msg");
    if (count < 1000){ msg.textContent = "Not enough currency."; return; }
    if (!name || !isFinite(base) || base < 10){ msg.textContent = "Name + cost required."; return; }
    const unit = addCustom(name, base);
    msg.textContent = `Created: ${unit.name} — base ${fmt(unit.base)}, +${fmt(unit.inc)}/s`;
    document.getElementById("c_name").value = "";
    document.getElementById("c_cost").value = "";
  };

  document.getElementById("auto_click").addEventListener("change", (e)=>{
    automation.auto_click = e.target.checked;
  });
  document.getElementById("auto_buy").addEventListener("change", (e)=>{
    automation.auto_buy = e.target.checked;
  });
}

async function applySettings(){
  const r = await fetch("/api/settings");
  const j = await r.json();
  if(j.ok){
    if(j.settings.bg){
      document.body.style.backgroundImage = `url('${j.settings.bg}')`;
      document.body.style.backgroundSize = "cover";
      document.body.style.backgroundAttachment = "fixed";
    }
    const logoEl = document.getElementById("logo");
    if(j.settings.logo){
      logoEl.src = j.settings.logo;
      logoEl.style.display = "block";
    }
  }
}

applyTheme();
renderBuyModeButtons();
bindEvents();
bindAchievementSound();
applySettings();
loadShop().then(()=> renderShop());
loadProgress().then(()=>{
  update();
  renderShop();
  renderPrestigeShop();
  renderPrestigeTree();
  renderAutomation();
});
loadPrestige();
loadUpdateBox();
loadReviewSummary();
loadReviews();
loadQuests();
updateEventBanner();
rollBoost();
setInterval(()=>{
  count += cps;
  update();
  tickAutomation();
},1000);
setInterval(rollBoost, 180000);
