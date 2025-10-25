async function api(path, opts){ const r=await fetch(path, opts); return await r.json(); }
const statusEl = document.getElementById('statusText');
const procBody = document.getElementById('procBody');
function fmtBytes(n){ let s=Number(n||0); for(const u of ["B","KB","MB","GB","TB"]){ if(s<1024) return `${s.toFixed(1)}${u}`; s/=1024;} return `${s.toFixed(1)}PB`; }
function vtTag(v){ if(!v) return "UNK"; const m=Number(v.malicious||0), s=Number(v.suspicious||0), u=Number(v.undetected||0), h=Number(v.harmless||0); if(m>0) return `M=${m}`; if(s>0) return `S=${s}`; if(h+u>0) return "OK"; return "UNK"; }

async function refreshStatus(){
  const s = await api('/api/health');
  statusEl.textContent = s.running ? 'Monitor running' : 'Ready';
}

async function refreshProcesses(){
  const js = await api('/api/processes');
  const rows = js.rows || [];
  procBody.innerHTML = "";

  // 500 MB у байтах
  const MEM_WARN_BYTES = 500 * 1024 * 1024;

  for (const r of rows){
    const vt = vtTag(r.vt || {});
    const tr = document.createElement('tr');

    // tooltip з причиною UNK (якщо є)
    const reason = r.vt_reason ? ` title="${r.vt_reason}"` : '';

    tr.innerHTML = `<td>${vt.startsWith('M=')||vt.startsWith('S=')?'!':''}</td>
      <td>${(r.name||'').slice(0,60)}</td>
      <td class="mono">${r.pid}</td>
      <td>${(r.cpu||0).toFixed(1)}</td>
      <td>${fmtBytes(r.rss||0)}</td>
      <td${reason}><span class="tag">${vt}</span></td>
      <td class="mono">${(r.exe||'').slice(0,120)}</td>`;

    // ✅ підсвітка (всередині циклу!)
    const rss = Number(r.rss || 0);
    if (rss > MEM_WARN_BYTES) tr.classList.add('danger');
    if (vt.startsWith('M='))  tr.classList.add('danger');
    else if (vt.startsWith('S=')) tr.classList.add('warn');

    procBody.appendChild(tr);
  }
}


document.getElementById('startSimple').onclick = async ()=>{
  await api('/api/start', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ include_vt:false, poll:5 })});
  refreshStatus(); refreshProcesses();
};
document.getElementById('startVT').onclick = async ()=>{
  await api('/api/start', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ include_vt:true, poll:15, vt_upload_unknown:false })});
  refreshStatus(); refreshProcesses();
};
document.getElementById('stopMon').onclick = async ()=>{ await api('/api/stop', {method:'POST'}); refreshStatus(); };
document.getElementById('snapshot').onclick = async ()=>{
  const res = await fetch('/api/snapshot', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({limit:100})
  });
  const j = await res.json();
  if(j.ok) alert(`✅ Snapshot complete.\n${j.count} processes checked.\nPolicy actions applied.`);
  else alert('❌ Snapshot failed: ' + (j.msg || 'unknown error'));
  refreshProcesses();
};

document.getElementById('refreshProc').onclick = refreshProcesses;

async function loadQuarantine(){ 
  const q = await api('/api/quarantine_list'); 
  const ul = document.getElementById('qList'); ul.innerHTML='';
  (q.files||[]).forEach(f=>{
    const size = f.size < 1024 ? `${f.size} B` : `${Math.round(f.size/1024)} KB`;
    const li = document.createElement('li');
    li.textContent = `${f.name} — ${size} — ${new Date(f.mtime*1000).toLocaleString()}`;
    ul.appendChild(li);
  });
}

document.getElementById('refreshQ').onclick = loadQuarantine;
document.getElementById('dryScan').onclick = async ()=>{ const r=await api('/api/scan_suspect_names', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({dryRun:true})}); alert(`Знайдено: ${r.found.length}\n\n`+r.found.join('\n')); };
document.getElementById('hardScan').onclick = async ()=>{ const r=await api('/api/scan_suspect_names', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({dryRun:false})}); alert(`Карантиновано: ${r.quarantined.length}`); loadQuarantine(); };

(async ()=>{
  await loadPolicy();              // <- підтягнемо memory_warning_mb з /api/policy_info
  refreshStatus();
  refreshProcesses();
  loadQuarantine();
})();


document.getElementById('exportSnap').onclick = async ()=>{
  const r = await fetch('/api/snapshot_export', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ csv: 'logs/process_snapshot.csv', jsonl: 'logs/process_snapshot.jsonl' })
  });
  const j = await r.json();
  alert(j.ok ? `Saved ${j.count} rows to logs/` : (j.msg || 'Export failed'));
};
// автооновлення кожні 5 секунд, якщо монітор запущено
setInterval(async ()=>{
  try{
    const s = await api('/api/health');
    statusEl.textContent = s.running ? 'Monitor running' : 'Ready';
    if (s.running) await refreshProcesses();
  }catch(e){}
}, 5000);
