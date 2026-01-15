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
    if (i === 0){ badge += ' <span class="pill">🥇</span>'; }
    if (i === 1){ badge += ' <span class="pill">🥈</span>'; }
    if (i === 2){ badge += ' <span class="pill">🥉</span>'; }
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
      renderTable(document.querySelector('#tbl_season_count tbody'), j.season_top_count, 'count');
      renderTable(document.querySelector('#tbl_season_cps tbody'), j.season_top_cps, 'cps');
      document.getElementById('updated').textContent = 'Updated: ' + new Date().toLocaleTimeString();
    }
  }catch(e){ console.error(e); }
}

loadLB();
setInterval(loadLB, 60000);

const theme = document.body.dataset.theme || "meme";
if (theme === "clean"){
  document.getElementById("lbl_count").textContent = "Most Clicks (current)";
  document.getElementById("lbl_cps").textContent = "Most Clicks / sec (current)";
  document.getElementById("lbl_season_count").textContent = "Season — Most Clicks";
  document.getElementById("lbl_season_cps").textContent = "Season — Most c/s";
}
