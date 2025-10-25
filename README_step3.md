
# Step 3 – Response Policy (Proc Blart: Mallware Cop)

This adds **automatic reactions** to your existing monitor:
- **Name match** (e.g., `virus.exe`) → terminate + quarantine.
- **VirusTotal detects > 3** → suspend → memory dump → quarantine.
- **Memory > 500 MB** → log a warning.

Everything is driven by an editable **`policy.yaml`** so you can tweak behavior without touching code.

---

## Files

- `monitor_with_policy.py` — policy-aware wrapper that uses your `proc_monitor_vt_api.py` (already in your project).
- `response_actions.py` — helper actions (suspend/resume/terminate/dump/quarantine/log).
- `policy.yaml` — rules & thresholds.
- `response_actions.log.jsonl` — JSON-lines log auto-created with every action taken.

Place these **next to** `proc_monitor_vt_api.py` in your project folder.

> ⚠️ **Windows notes**
> - For memory dumps you need **Sysinternals `procdump`**. Recommended path:
>   `C:\Tools\Sysinternals\procdump64.exe` (add the folder to `PATH` or set `procdump_path` in `policy.yaml`).  
> - Run PowerShell/Terminal **as Administrator** for best results (suspend/terminate/quarantine may need elevated rights).

---

## Install dependencies

```powershell
# In your venv
python -m pip install psutil vt-py pyyaml
```

If `vt-py` is already installed (you verified `import vt`), you only need `psutil` and `pyyaml`.

Set your VT key (optional if you embedded it already):
```powershell
setx VT_API_KEY "YOUR_VT_API_KEY"
$env:VT_API_KEY="YOUR_VT_API_KEY"   # for current session
```

---

## Configure policy

Open `policy.yaml` and adjust:
- `memory_warning_mb`: threshold in MB
- `vt_suspicious_threshold`: react if **malicious + suspicious > threshold**
- `kill_names`: exact process names to block
- `procdump_dir`, `quarantine_dir`, `procdump_path`
- `actions` per trigger

Example already matches the task:

```yaml
kill_names: ["virus.exe"]
actions:
  on_name_match: ["terminate", "quarantine"]
  on_vt_detected: ["suspend", "dump", "quarantine"]
  on_high_memory: ["log_warning"]
```

---

## How to run

**One-shot** (print snapshot, apply actions, exit):
```powershell
python monitor_with_policy.py --print --limit 50
```

**Continuous** (loop forever; applies actions every poll):
```powershell
python monitor_with_policy.py --poll 10 --limit 50
```

**Also upload unknown executables to VT** (optional; mind the size & system files):
```powershell
python monitor_with_policy.py --poll 10 --vt-upload-unknown --vt-upload-wait 60
```

> If you want the **API** from your base module, you can run:
> ```powershell
> python monitor_with_policy.py --api --port 5001
> ```
> (API mode serves data only; it doesn’t apply policy actions via endpoints.)

---

## Where do results go?

- Console shows the table with VT tags (reused from your base script).
- Every action is appended to **`response_actions.log.jsonl`**, e.g.:
```json
{"ts_utc":"2025-10-24T13:55:00Z","pid":1234,"exe":"C:\\evil\\virus.exe","action":"terminate","reason":"name_match","result":"ok"}
{"ts_utc":"2025-10-24T13:55:02Z","pid":1234,"exe":"C:\\evil\\virus.exe","action":"quarantine","reason":"name_match","quarantine_path":"C:\\Quarantine\\20251024-135502__virus.exe","result":"ok"}
{"ts_utc":"2025-10-24T13:59:10Z","pid":2222,"exe":"C:\\Users\\...\\app.exe","action":"dump","reason":"vt_detects=5","dump_path":"C:\\Tools\\dumps\\pid2222_20251024-135910.dmp","result":"ok"}
{"ts_utc":"2025-10-24T14:02:33Z","pid":3333,"exe":"C:\\Windows\\System32\\msedgewebview2.exe","action":"log_warning","reason":"memory>700MB","result":"ok"}
```

---

## Troubleshooting

- **PowerShell line breaks**: In PS you must use backtick ``` ` ``` to continue lines. The caret `^` is for CMD.  
- **"Access Denied"**: Start the shell as **Administrator**.
- **procdump not found**: Download Sysinternals Suite → extract → set `procdump_path` or add the folder to `PATH`.
- **Quarantine fails**: If the process still holds the file, the script suspends before quarantine; if needed, it will terminate. You may need admin rights.
- **vt-py installed but import fails**: Ensure you run inside the same **venv** where you installed it: `(.venv) PS> python -c "import vt; print(vt.__version__)"
```

