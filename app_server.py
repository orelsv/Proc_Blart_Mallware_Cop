#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import sys
import hashlib
import time
from pathlib import Path
from typing import Optional

from flask import Flask, jsonify, request, send_from_directory, Response

# Project modules
import proc_monitor_vt_api as base
import response_actions as ra

APP_DIR = Path(__file__).resolve().parent
LOG_PATH = Path("response_actions.log.jsonl")

app = Flask(__name__, static_folder=None)

# --- NEW: simple monitor state ---
from threading import Thread, Event, Lock

_last_rows = []
_mon_thread = None
_mon_stop = Event()
_mon_lock = Lock()
_mon_running = False

def _collect_snapshot(include_vt: bool = False, upload_unknown: bool = False, poll: float = 10.0, limit: int = 50):
    """
    Бекграунд-цикл збору снапшотів. include_vt=False -> простий монітор без VT.
    """
    global _last_rows, _mon_running
    vt_checker = None
    try:
        if include_vt and getattr(base, "vt", None) is not None and getattr(base, "VT_API_KEY", None):
            vt_checker = base.VTChecker(base.VT_API_KEY)
    except Exception:
        vt_checker = None

    _mon_running = True
    try:
        while not _mon_stop.is_set():
            rows = base.collect_process_snapshot(
                vt_checker=vt_checker if include_vt else None,
                include_paths=True,
                upload_unknown=upload_unknown,
                upload_wait=30,
                upload_max_bytes=32*1024*1024,
                upload_allow_system=False,
            )
            with _mon_lock:
                _last_rows = rows
            _mon_stop.wait(timeout=poll)
    finally:
        _mon_running = False
        try:
            if vt_checker:
                vt_checker.close()
        except Exception:
            pass


# --------------------------
# Helpers
# --------------------------

def sha256_file(path: Path, max_bytes: Optional[int] = None) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        if max_bytes:
            remaining = max_bytes
            while remaining > 0:
                chunk = f.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                h.update(chunk)
                remaining -= len(chunk)
        else:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
    return h.hexdigest()


def vt_check_or_upload(vt_checker, file_path: Path,
                       sha256: str,
                       upload_unknown: bool,
                       wait_seconds: int,
                       max_mb: int) -> dict:
    if vt_checker is None:
        return {"status": "unknown", "row": {"note": "vt-disabled"}}
    try:
        row = vt_checker.lookup_sha256(sha256)
        if row and row.get("status"):
            return {"status": row["status"], "row": row}
        if not upload_unknown:
            return {"status": "unknown", "row": {"note": "not_found"}}
        size_mb = file_path.stat().st_size / (1024 * 1024)
        if size_mb > max_mb:
            return {"status": "unknown", "row": {"note": f"too_large:{size_mb:.1f}MB"}}
        up_id = vt_checker.upload_file(str(file_path))
        t0 = time.time()
        last = None
        while time.time() - t0 < wait_seconds:
            time.sleep(5)
            last = vt_checker.lookup_upload(up_id)
            s = (last or {}).get("status")
            if s in ("malicious", "suspicious", "clean"):
                return {"status": s, "row": last}
        return {"status": "unknown", "row": last or {"note": "not_ready"}}
    except Exception as e:
        return {"status": "unknown", "row": {"error": str(e)}}


# --------------------------
# UI ROUTES (robust find)
# --------------------------

def find_ui_file(name: str) -> Optional[Path]:
    """Try to find a UI file either in project root or in ui/ subfolder."""
    candidates = [APP_DIR / name, APP_DIR / "ui" / name]
    for c in candidates:
        if c.exists():
            return c
    return None


@app.route("/")
def index():
    idx = find_ui_file("index.html")
    if idx is None:
        msg = f"<h1>index.html not found</h1><p>Looked in:<br>{APP_DIR}\\index.html<br>{APP_DIR}\\ui\\index.html</p>"
        return Response(msg, status=500, mimetype="text/html")
    return send_from_directory(idx.parent, idx.name)


@app.route("/ui/<path:filename>")
def ui_files(filename):
    # Serve from root or /ui
    p = find_ui_file(filename)
    if p is None:
        return ("Not Found", 404)
    return send_from_directory(p.parent, p.name)


# --------------------------
# API ROUTES
# --------------------------

@app.route("/api/status")
def status():
    return jsonify({
        "ok": True,
        "vt_key_present": bool(getattr(base, "VT_API_KEY", None)),
    })


@app.route("/api/tail_log")
def tail_log():
    if not LOG_PATH.exists():
        return jsonify({"ok": True, "tail": ""})
    data = LOG_PATH.read_text(encoding="utf-8", errors="ignore")
    return jsonify({"ok": True, "tail": data[-2000:]})

@app.route("/api/health")
def health_api():
    return jsonify({"ok": True, "running": _mon_running, "time": time.time()})

@app.route("/api/processes")
def processes_api():
    limit = int(request.args.get("limit", "50"))
    with _mon_lock:
        rows = list(_last_rows)
    return jsonify({"timestamp": time.time(), "count": len(rows), "rows": rows[:limit]})

@app.route("/api/snapshot", methods=["POST"])
def snapshot_api():
    """
    Робить знімок процесів + застосовує policy.yaml.
    """
    limit = int((request.json or {}).get("limit", 50))
    rows = base.collect_process_snapshot(vt_checker=None, include_paths=True)

    # Застосовуємо політику (kill/quarantine/log_warning)
    try:
        import subprocess, sys
        cmd = [sys.executable, "monitor_with_policy.py", "--policy", "policy.yaml"]
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    except Exception as e:
        print(f"[snapshot_api] policy run failed: {e}")

    with _mon_lock:
        _last_rows[:] = rows

    # Записуємо у лог для історії
    try:
        base.write_json_log(rows, "logs/monitor.jsonl")
        base.write_csv_log(rows, "logs/monitor.csv")
    except Exception:
        pass

    return jsonify({"ok": True, "count": len(rows), "rows": rows[:limit]})


@app.route("/api/start", methods=["POST"])
def start_api():
    """
    Start monitor thread.
    Body: { poll: 10, vt_upload_unknown: false, include_vt: false }
    """
    global _mon_thread, _mon_stop
    if _mon_running:
        return jsonify({"ok": False, "msg": "already running"})
    b = request.get_json(silent=True) or {}
    poll = float(b.get("poll", 10.0))
    include_vt = bool(b.get("include_vt", False))  # простий монітор за замовчуванням
    upload_unknown = bool(b.get("vt_upload_unknown", False))
    _mon_stop.clear()
    _mon_thread = Thread(target=_collect_snapshot, kwargs={
        "include_vt": include_vt,
        "upload_unknown": upload_unknown,
        "poll": poll,
        "limit": 0
    }, daemon=True)
    _mon_thread.start()
    time.sleep(0.2)
    return jsonify({"ok": True, "running": True, "mode": "with_vt" if include_vt else "simple"})

@app.route("/api/stop", methods=["POST"])
def stop_api():
    global _mon_thread
    if not _mon_running:
        return jsonify({"ok": True, "running": False})
    _mon_stop.set()
    try:
        if _mon_thread:
            _mon_thread.join(timeout=2.0)
    except Exception:
        pass
    return jsonify({"ok": True, "running": False})



@app.route("/api/scan_once", methods=["POST"])
def scan_once():
    import subprocess
    cmd = [
        sys.executable, "monitor_with_policy.py",
        "--print",
        "--limit", "200",
        "--vt-upload-unknown",
        "--vt-upload-wait", "60",
        "--vt-upload-allow-system",
        "--policy", "policy.yaml"
    ]
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             shell=False, timeout=180)
        out = res.stdout.decode(errors="ignore")
        return jsonify({"ok": True, "stdout": out})
    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "msg": "Scan timed out"}), 500
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 500


@app.route("/api/scan_path", methods=["POST"])
def scan_path():
    try:
        body = request.get_json(force=True, silent=False) or {}
        raw_path = (body.get("path") or "").strip()
        if not raw_path:
            return jsonify({"ok": False, "msg": "Missing 'path'"}), 400

        f = Path(raw_path)
        if not f.exists() or not f.is_file():
            return jsonify({"ok": False, "msg": "File not found"}), 400

        upload_unknown = bool(body.get("uploadUnknown", True))
        wait_sec = int(body.get("waitSec", 60))
        max_mb = int(body.get("maxMb", 50))

        vt_checker = None
        if getattr(base, "vt", None) is not None and getattr(base, "VT_API_KEY", None):
            try:
                vt_checker = base.VTChecker(base.VT_API_KEY)
            except Exception:
                vt_checker = None

        file_sha = sha256_file(f)

        vt_res = vt_check_or_upload(
            vt_checker=vt_checker,
            file_path=f,
            sha256=file_sha,
            upload_unknown=upload_unknown,
            wait_seconds=wait_sec,
            max_mb=max_mb
        )

        status = vt_res["status"]
        row = vt_res["row"]

        action = "log_only"
        if status == "malicious":
            action = "quarantine_kill"
        elif status == "suspicious":
            action = "isolate"

        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "exe": str(f),
            "pid": None,
            "name": f.name,
            "size": f.stat().st_size,
            "sha256": file_sha,
            "vt_status": status,
            "action": action,
            "result": "preview_only",
            "vt_row": row,
        }
        try:
            LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with LOG_PATH.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass

        return jsonify({"ok": True, "vt_status": status, "sha256": file_sha, "vt_row": row, "action": action})

    except Exception as e:
        return jsonify({"ok": False, "msg": f"scan_path failed: {e}"}), 500


SUSPECT_NAMES = {"virus", "eicar", "malware", "trojan", "worm", "backdoor"}
SUSPECT_EXTS  = {".exe",".com",".scr",".pif",".vbs",".js",".jse",".bat",".cmd",".ps1",".dll"}

def _is_system_path(p: Path) -> bool:
    low = str(p).lower()
    return low.startswith("c:\\windows") or low.startswith("c:\\program files") or low.startswith("c:\\program files (x86)")

def _iter_scan_roots():
    # юзерські місця + публічні завантаження; додавай свої шляхи за бажанням
    home = Path.home()
    candidates = [
        home / "Downloads",
        home / "Desktop",
        home / "Documents",
        Path(r"C:\Users\Public\Downloads"),
    ]
    for c in candidates:
        if c.exists():
            yield c

@app.route("/api/scan_suspect_names", methods=["POST"])
def scan_suspect_names():
    """
    Знаходить підозрілі файли за назвою/розширенням і відправляє в карантин.
    Body: { dryRun: false, quarantineDir: "C:\\Quarantine" }
    """
    body = request.get_json(silent=True) or {}
    dry = bool(body.get("dryRun", False))
    qdir = body.get("quarantineDir") or str(APP_DIR / "Quarantine")
    Path(qdir).mkdir(parents=True, exist_ok=True)

    matches = []
    for root in _iter_scan_roots():
        for p in root.rglob("*"):
            try:
                if not p.is_file(): 
                    continue
                if _is_system_path(p):
                    continue
                name = p.name.lower()
                ext = p.suffix.lower()
                # збіг по імені або по розширенню у поєднанні з ключовими словами
                name_hit = any(k in name for k in SUSPECT_NAMES)
                ext_hit = ext in SUSPECT_EXTS
                if name_hit or (ext_hit and any(k in name for k in SUSPECT_NAMES)):
                    matches.append(str(p))
            except Exception:
                continue

    quarantined = []
    failed = []
    if not dry:
        for m in matches:
            dst = ra.quarantine_file(m, qdir)
            if dst:
                quarantined.append({"src": m, "dst": dst})
            else:
                failed.append(m)

    # лог в кінець JSONL
    try:
        with LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "action": "scan_suspect_names",
                "dry": dry,
                "found": len(matches),
                "quarantined": len(quarantined),
                "failed": len(failed),
            }) + "\n")
    except Exception:
        pass

    return jsonify({
        "ok": True,
        "dryRun": dry,
        "found": matches,
        "quarantined": quarantined,
        "failed": failed
    })

@app.route("/api/quarantine_list")
def quarantine_list():
    qdir = request.args.get("dir") or str(APP_DIR / "Quarantine")
    p = Path(qdir)
    if not p.exists():
        return jsonify({"ok": True, "files": []})
    files = []
    for f in p.iterdir():
        if f.is_file():
            st = f.stat()
            files.append({"name": f.name, "size": st.st_size, "mtime": st.st_mtime})
    return jsonify({"ok": True, "files": files})

@app.route("/api/snapshot_export", methods=["POST"])
def snapshot_export():
    b = request.get_json(silent=True) or {}
    csv_path = b.get("csv") or None
    jsonl_path = b.get("jsonl") or None
    with _mon_lock:
        rows = list(_last_rows)
    if not rows:
        return jsonify({"ok": False, "msg": "No snapshot in memory yet"}), 400
    if not (csv_path or jsonl_path):
        return jsonify({"ok": False, "msg": "Provide 'csv' and/or 'jsonl' paths"}), 400

    try:
        if csv_path:
            base.write_csv_log(rows, csv_path)
        if jsonl_path:
            base.write_json_log(rows, jsonl_path)
        return jsonify({"ok": True, "count": len(rows), "csv": csv_path, "jsonl": jsonl_path})
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 500


# --------------------------
# RUN
# --------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
