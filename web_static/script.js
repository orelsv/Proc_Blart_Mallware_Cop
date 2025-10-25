async function api(path, opts) {
  const res = await fetch(path, opts);
  return await res.json();
}

async function refreshStatus() {
  const s = await api('/api/status');
  const el = document.getElementById('statusText');
  el.textContent = s.running ? `Running (PID ${s.pid})` : 'Stopped';
}

document.getElementById('startBtn').addEventListener('click', async () => {
  const res = await api('/api/start', { method: 'POST' });
  alert(JSON.stringify(res));
  refreshStatus();
});

document.getElementById('stopBtn').addEventListener('click', async () => {
  const res = await api('/api/stop', { method: 'POST' });
  alert(JSON.stringify(res));
  refreshStatus();
});

document.getElementById('scanBtn').addEventListener('click', async () => {
  const res = await api('/api/scan_once', { method: 'POST' });
  const stdout = res.stdout || res.msg || JSON.stringify(res);
  alert(stdout.slice(0, 2000));
  refreshLogs();
});

document.getElementById('refreshQ').addEventListener('click', async () => {
  const res = await api('/api/quarantine_list');
  const ul = document.getElementById('qList');
  ul.innerHTML = '';
  if (res.ok) {
    res.files.forEach(f => {
      const li = document.createElement('li');
      li.textContent = `${f.name} — ${Math.round(f.size/1024)} KB — ${new Date(f.mtime*1000).toLocaleString()}`;
      ul.appendChild(li);
    });
  } else {
    ul.textContent = res.msg || 'No data';
  }
});

async function refreshLogs() {
  const res = await api('/api/tail_log');
  const pre = document.getElementById('logPre');
  if (res.ok) pre.textContent = res.tail;
  else pre.textContent = res.msg || 'No log found';
}

document.getElementById('refreshLog').addEventListener('click', refreshLogs);

// refresh status on load
refreshStatus();
refreshLogs();

document.getElementById('scanPathBtn').addEventListener('click', async () => {
  const path = document.getElementById('scanPath').value.trim();
  if (!path) {
    alert('Вкажи повний шлях до файлу');
    return;
  }
  const res = await fetch('/api/scan_path', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ path })
  });
  const j = await res.json();
  document.getElementById('scanPathOut').textContent = JSON.stringify(j, null, 2);

  // якщо був карантин — одразу оновимо перелік і лог
  if (j.ok && j.action === 'quarantine') {
    document.getElementById('refreshQ').click();
    document.getElementById('refreshLog').click();
  }
});
