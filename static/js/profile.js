const csrfToken = window.APP_CONFIG?.csrfToken || "";

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
        <div style="opacity:.75">${(a.category||a.group||'').toUpperCase()}</div>
      </div>
      <div class="pill">✓ +${(((Number(a.mult||1)-1)*100).toFixed(2))}%</div>
    `;
    wrap.appendChild(el);
  });

  const units = document.getElementById('p_units');
  units.innerHTML = '';
  (p.top_units||[]).forEach(unit=>{
    const el = document.createElement('div');
    el.className = 'ach';
    el.innerHTML = `<div>${unit.name}</div><div class="pill">lvl ${fmt(unit.lvl)}</div>`;
    units.appendChild(el);
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
    const r = await fetch('/api/profile_create', {method:'POST', headers: {"X-CSRF-Token": csrfToken}});
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
      method:'POST', headers:{'Content-Type':'application/json', "X-CSRF-Token": csrfToken},
      body: JSON.stringify({bio})
    });
    const j = await r.json().catch(()=>({}));
    document.getElementById('save_msg').textContent = (j && j.ok) ? 'Saved ✓' : (j.err || 'Error');
    if(j && j.ok){ loadProfile(''); }
  }catch(e){
    document.getElementById('save_msg').textContent = 'Network error';
  }
};

const target = param('u');
if(target){ document.getElementById('q').value = target; }
loadProfile(target);
