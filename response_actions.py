
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
response_actions.py
-------------------
Cross‑platform response actions for suspicious processes.

Requires: psutil (pip install psutil)
Optional: procdump.exe on Windows for memory dump
"""

import os
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

import psutil


def ensure_dir(p: str):
    Path(p).mkdir(parents=True, exist_ok=True)


def safe_basename(p: Optional[str]) -> str:
    if not p:
        return "unknown"
    b = os.path.basename(p)
    return b or "unknown"


def timestamp() -> str:
    return datetime.utcnow().strftime("%Y%m%d-%H%M%S")


def suspend_process(pid: int) -> bool:
    """Suspend a process by PID (Windows & Linux supported by psutil)."""
    try:
        p = psutil.Process(pid)
        p.suspend()
        return True
    except Exception:
        return False


def resume_process(pid: int) -> bool:
    try:
        p = psutil.Process(pid)
        p.resume()
        return True
    except Exception:
        return False


def terminate_process(pid: int, timeout: float = 5.0) -> bool:
    """Terminate (graceful) then kill if needed."""
    try:
        p = psutil.Process(pid)
        p.terminate()
        try:
            p.wait(timeout=timeout)
            return True
        except psutil.TimeoutExpired:
            p.kill()
            p.wait(timeout=timeout)
            return True
    except Exception:
        return False


def dump_memory_with_procdump(pid: int, out_dir: str, procdump_path: Optional[str] = None) -> Optional[str]:
    """
    Create a full-memory dump with Sysinternals procdump.
    Returns the path to the dump file or None on failure.
    """
    ensure_dir(out_dir)
    exe = shutil.which(procdump_path) if procdump_path else (shutil.which("procdump.exe") or shutil.which("procdump64.exe"))
    if not exe:
        # Try common locations
        candidates = [
            r"C:\Tools\Sysinternals\procdump64.exe",
            r"C:\Tools\Sysinternals\procdump.exe",
            r"C:\Windows\System32\procdump64.exe",
            r"C:\Windows\System32\procdump.exe",
        ]
        for c in candidates:
            if os.path.isfile(c):
                exe = c
                break
    if not exe:
        return None

    dump_name = f"pid{pid}_{timestamp()}.dmp"
    dump_path = os.path.join(out_dir, dump_name)

    # procdump flags:
    #  -ma     : full memory dump
    #  -accepteula : auto-accept EULA
    #  -64     : force 64-bit (safe to include; ignored if not applicable)
    cmd = [exe, "-accepteula", "-ma", str(pid), dump_path]
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if cp.returncode == 0 and os.path.exists(dump_path):
            return dump_path
        else:
            return None
    except Exception:
        return None


def quarantine_file(src_path: str, quarantine_dir: str) -> Optional[str]:
    """
    Move a file into a quarantine folder with a timestamped name.
    Returns the destination path or None on failure.
    """
    if not src_path or not os.path.isfile(src_path):
        return None
    ensure_dir(quarantine_dir)
    base = safe_basename(src_path)
    dest = os.path.join(quarantine_dir, f"{timestamp()}__{base}")
    try:
        # Attempt to make file writable (helps if read-only)
        try:
            os.chmod(src_path, 0o644)
        except Exception:
            pass
        shutil.move(src_path, dest)
        return dest
    except Exception:
        return None


def write_action_log(log_path: str, record: Dict[str, Any]):
    """Append a JSON line with the action we took."""
    ensure_dir(os.path.dirname(os.path.abspath(log_path)))
    record = dict(record)
    record["ts_utc"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json_dumps_safe(record))
        f.write("\n")


def json_dumps_safe(obj: Dict[str, Any]) -> str:
    try:
        import json
        return json.dumps(obj, ensure_ascii=False, default=str)
    except Exception:
        return str(obj)
