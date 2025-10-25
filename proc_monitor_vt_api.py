#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
proc_monitor_vt_api.py
---------------------------------
Process Monitor + VirusTotal Integration + optional Flask REST API + JSON/CSV logging

Features:
- Lists running processes with CPU%, memory (RSS), and executable path.
- Calculates SHA-256 of each executable.
- Queries VirusTotal (vt-py) for last_analysis_stats.
- Optionally uploads unknown executables (--vt-upload-unknown) and waits for results.
- Console output highlights Suspicious (yellow) / Malicious (red).
- Prints clear VT state: OK, S=x, M=x, or UNK[:reason].
- JSON and CSV logging for snapshots (single-shot, continuous console, and API background).
- Optional Flask API for automation (/health, /processes, /processes/<pid>).

Dependencies:
    pip install psutil vt-py Flask
"""

import os
import sys
import time
import json
import csv
import hashlib
import threading
import argparse
from datetime import datetime
from functools import lru_cache
from typing import Dict, Optional, Any, List

# ------------------ External Libraries ------------------
try:
    import psutil
except Exception:
    print("Missing dependency 'psutil'. Install with: pip install psutil")
    raise

try:
    import vt  # official VirusTotal API client
except Exception:
    vt = None

try:
    from flask import Flask, jsonify, request
except Exception:
    Flask = None

# ------------------ Configuration ------------------
# WARNING: Embedded key for training only. Prefer environment variable VT_API_KEY in real usage.
VT_API_KEY_EMBEDDED = "4c41cd2a58c758b5090f330c23556fe006ded4c054d39899a7ebe87d85465ae0"
VT_API_KEY = os.environ.get("VT_API_KEY", VT_API_KEY_EMBEDDED)

POLL_INTERVAL = 5.0  # seconds for background monitor
VT_CACHE_MAXSIZE = 4096


# ------------------ Helper Functions ------------------
def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> Optional[str]:
    """Safely compute SHA-256 of a file in chunks (returns hex or None on failure)."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, IsADirectoryError):
        return None
    except Exception:
        return None


def fmt_bytes(n: int) -> str:
    """Convert bytes to a human-readable string."""
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0:
            return f"{size:3.1f}{unit}"
        size /= 1024.0
    return f"{size:.1f}PB"


def is_system_path(path: str) -> bool:
    """Return True if the file is inside typical Windows system folders."""
    p = (path or "").lower().replace("/", "\\")
    return (
        p.startswith("c:\\windows\\")
        or p.startswith("c:\\program files\\")
        or p.startswith("c:\\program files (x86)\\")
    )


# ------------------ Logging Helpers ------------------
def ensure_parent_dir(path: str):
    """Create parent directory for path if it doesn't exist."""
    if not path:
        return
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


def vt_state_tag(vt_stats: Optional[dict], vt_reason: Optional[str]) -> str:
    """
    Produce a compact VT state string for display/logging:
    - 'M=x' if malicious>0
    - 'S=x' if suspicious>0
    - 'OK'  if harmless+undetected>0
    - 'UNK[:reason]' otherwise
    """
    if isinstance(vt_stats, dict):
        m = int(vt_stats.get("malicious", 0))
        s = int(vt_stats.get("suspicious", 0))
        u = int(vt_stats.get("undetected", 0))
        h = int(vt_stats.get("harmless", 0))
        if m > 0:
            return f"M={m}"
        if s > 0:
            return f"S={s}"
        if (h + u) > 0:
            return "OK"
    return f"UNK{(':'+vt_reason) if vt_reason else ''}"


def write_json_log(rows: List[Dict[str, Any]], path: str):
    """
    Append one JSON object per snapshot (JSON Lines).
    {
      "timestamp": "2025-10-24T12:34:56Z",
      "count": N,
      "rows": [ {process obj}, ... ]
    }
    """
    if not path:
        return
    ensure_parent_dir(path)
    payload = {
        "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "count": len(rows),
        "rows": rows,
    }
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False))
        f.write("\n")


def write_csv_log(rows: List[Dict[str, Any]], path: str):
    """
    Append CSV rows: one row per process in the snapshot.
    Columns:
      timestamp, name, pid, cpu, rss, exe, sha256,
      vt_malicious, vt_suspicious, vt_undetected, vt_harmless,
      vt_state, vt_reason
    """
    if not path:
        return
    ensure_parent_dir(path)
    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    fieldnames = [
        "timestamp", "name", "pid", "cpu", "rss", "exe", "sha256",
        "vt_malicious", "vt_suspicious", "vt_undetected", "vt_harmless",
        "vt_state", "vt_reason",
    ]
    file_exists = os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:
            w.writeheader()
        for r in rows:
            vt_stats = r.get("vt") if isinstance(r.get("vt"), dict) else {}
            w.writerow({
                "timestamp": ts,
                "name": r.get("name"),
                "pid": r.get("pid"),
                "cpu": r.get("cpu"),
                "rss": r.get("rss"),
                "exe": r.get("exe"),
                "sha256": r.get("sha256"),
                "vt_malicious": vt_stats.get("malicious", None),
                "vt_suspicious": vt_stats.get("suspicious", None),
                "vt_undetected": vt_stats.get("undetected", None),
                "vt_harmless": vt_stats.get("harmless", None),
                "vt_state": vt_state_tag(vt_stats, r.get("vt_reason")),
                "vt_reason": r.get("vt_reason"),
            })


# ------------------ VirusTotal Wrapper ------------------
class VTChecker:
    """Encapsulates VirusTotal API calls (lookup + upload/scan)."""

    def __init__(self, api_key: str):
        if vt is None:
            raise RuntimeError("vt-py not installed. Run: pip install vt-py")
        if not api_key:
            raise RuntimeError("No VirusTotal API key provided.")
        self.client = vt.Client(api_key)

    def close(self):
        """Close HTTP connection."""
        try:
            self.client.close()
        except Exception:
            pass

    @lru_cache(maxsize=VT_CACHE_MAXSIZE)
    def get_stats_by_sha256(self, sha256: str) -> Optional[Dict[str, int]]:
        """
        Query VirusTotal for file analysis by hash.
        Returns dict with counts or None if not found/error.
        """
        try:
            obj = self.client.get_object(f"/files/{sha256}")
            stats = None
            if isinstance(obj, dict):
                stats = obj.get("last_analysis_stats") or (obj.get("attributes") or {}).get("last_analysis_stats")
            else:
                attrs = getattr(obj, "attributes", None)
                if attrs:
                    stats = getattr(attrs, "last_analysis_stats", None) or attrs.get("last_analysis_stats")
                else:
                    stats = getattr(obj, "last_analysis_stats", None)
            if not stats:
                return None
            return {
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "undetected": int(stats.get("undetected", 0)),
                "harmless": int(stats.get("harmless", 0)),
            }
        except vt.error.APIError:
            # NotFound / rate-limit / other API-level issue
            return None
        except Exception:
            return None

    def scan_and_wait(self, filepath: str, wait_seconds: int = 30) -> Optional[Dict[str, int]]:
        """
        Upload a file to VT and wait (up to wait_seconds) for the analysis to complete.
        Returns the resulting stats dict or None.
        """
        try:
            import time as _t
            with open(filepath, "rb") as f:
                analysis = self.client.scan_file(f)
            analysis_id = None
            if isinstance(analysis, dict):
                analysis_id = analysis.get("id") or analysis.get("data", {}).get("id")
            else:
                analysis_id = getattr(analysis, "id", None)
            if not analysis_id:
                return None

            deadline = _t.time() + max(5, int(wait_seconds))
            while _t.time() < deadline:
                a = self.client.get_object(f"/analyses/{analysis_id}")
                status = None
                if isinstance(a, dict):
                    status = a.get("status") or (a.get("attributes") or {}).get("status")
                else:
                    status = getattr(a, "status", None)
                    if status is None:
                        attrs = getattr(a, "attributes", None)
                        if attrs:
                            status = attrs.get("status")
                if status == "completed":
                    sha = sha256_file(filepath)
                    if not sha:
                        return None
                    return self.get_stats_by_sha256(sha)
                _t.sleep(2.0)
            return None
        except vt.error.APIError:
            return None
        except Exception:
            return None


# ------------------ Process Snapshot Collector ------------------
def collect_process_snapshot(
    vt_checker: Optional[VTChecker] = None,
    include_paths: bool = True,
    upload_unknown: bool = False,
    upload_wait: int = 30,
    upload_max_bytes: int = 32 * 1024 * 1024,
    upload_allow_system: bool = False,
) -> List[Dict[str, Any]]:
    """
    Collect info about running processes:
    name, pid, cpu, rss, exe, sha256, vt, vt_reason.
    """
    rows: List[Dict[str, Any]] = []
    for p in psutil.process_iter(attrs=["pid", "name", "exe", "cpu_percent", "memory_info"]):
        info = p.info
        pid = info.get("pid")
        name = info.get("name") or ""
        exe = info.get("exe") or ""
        cpu = float(info.get("cpu_percent") or 0.0)
        rss = int(getattr(info.get("memory_info"), "rss", 0) if info.get("memory_info") else 0)

        entry: Dict[str, Any] = {
            "name": name,
            "pid": pid,
            "cpu": cpu,
            "rss": rss,
            "exe": exe if include_paths else "",
            "sha256": None,
            "vt": None,
            "vt_reason": None,
        }

        if exe and vt_checker:
            sha = sha256_file(exe)
            entry["sha256"] = sha
            stats = None
            if not sha:
                entry["vt_reason"] = "NO_HASH"
            else:
                stats = vt_checker.get_stats_by_sha256(sha)
                # If VT has no record and upload is allowed, try uploading (with safeguards)
                if stats is None and upload_unknown:
                    try:
                        if os.path.isfile(exe):
                            if upload_allow_system or not is_system_path(exe):
                                size = os.path.getsize(exe)
                                if size <= upload_max_bytes:
                                    stats = vt_checker.scan_and_wait(exe, wait_seconds=upload_wait)
                                else:
                                    entry["vt_reason"] = "SIZE_LIMIT"
                            else:
                                entry["vt_reason"] = "SYSTEM_PATH"
                        else:
                            entry["vt_reason"] = "NOFILE"
                    except PermissionError:
                        entry["vt_reason"] = "PERM_DENIED"
                    except Exception:
                        entry["vt_reason"] = "ERROR"
            entry["vt"] = stats
        else:
            if not exe:
                entry["vt_reason"] = "NO_EXE"

        rows.append(entry)

    rows.sort(key=lambda x: x.get("rss", 0), reverse=True)
    return rows


# ------------------ Console Output ------------------
def print_snapshot(rows: List[Dict[str, Any]], limit: int = 30):
    """Nicely print the process list with VT results and reason tags."""
    print("=" * 100)
    print(f"Snapshot at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    header = f"{'!':1} {'NAME':30} {'PID':>6} {'CPU%':>6} {'RSS':>10} {'VT':>12} {'EXE':40}"
    print(header)
    print("-" * 100)

    for r in rows[:limit]:
        vt_stats = r.get("vt")
        vt_tag = vt_state_tag(vt_stats, r.get("vt_reason"))
        alert = False
        warn = False

        if isinstance(vt_stats, dict):
            if int(vt_stats.get("malicious", 0)) > 0:
                alert = True
            elif int(vt_stats.get("suspicious", 0)) > 0:
                warn = True

        prefix = "!" if (alert or warn) else " "
        name = (r.get("name") or "")[:30].ljust(30)
        pid = str(r.get("pid")).rjust(6)
        cpu = f"{r.get('cpu', 0):6.1f}"
        rss = fmt_bytes(r.get("rss", 0)).rjust(10)
        exe = (r.get("exe") or "")[:40].ljust(40)
        line = f"{prefix} {name} {pid} {cpu} {rss} {vt_tag:>12} {exe}"

        if alert:
            print("\033[91m" + line + "\033[0m")  # red
        elif warn:
            print("\033[93m" + line + "\033[0m")  # yellow
        else:
            print(line)

    print("=" * 100)


# ------------------ Background Monitor for API ------------------
class MonitorThread(threading.Thread):
    """Background thread that keeps updating the latest process snapshot (and logs if configured)."""

    def __init__(
        self,
        vt_checker: Optional[VTChecker],
        poll_interval: float,
        upload_unknown: bool,
        upload_wait: int,
        upload_max_bytes: int,
        upload_allow_system: bool,
        log_json_path: Optional[str] = None,
        log_csv_path: Optional[str] = None,
    ):
        super().__init__(daemon=True)
        self.vt_checker = vt_checker
        self.poll_interval = poll_interval
        self.upload_unknown = upload_unknown
        self.upload_wait = upload_wait
        self.upload_max_bytes = upload_max_bytes
        self.upload_allow_system = upload_allow_system
        self.log_json_path = log_json_path
        self.log_csv_path = log_csv_path
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._snapshot: List[Dict[str, Any]] = []

    def run(self):
        while not self._stop.is_set():
            rows = collect_process_snapshot(
                self.vt_checker,
                include_paths=True,
                upload_unknown=self.upload_unknown,
                upload_wait=self.upload_wait,
                upload_max_bytes=self.upload_max_bytes,
                upload_allow_system=self.upload_allow_system,
            )
            # Persist new snapshot
            with self._lock:
                self._snapshot = rows
            # Background logging
            if self.log_json_path:
                write_json_log(rows, self.log_json_path)
            if self.log_csv_path:
                write_csv_log(rows, self.log_csv_path)
            time.sleep(self.poll_interval)

    def stop(self):
        self._stop.set()

    def get_snapshot(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._snapshot)


# ------------------ Flask REST API ------------------
def create_app(monitor_thread: Optional[MonitorThread] = None) -> Any:
    if Flask is None:
        raise RuntimeError("Flask not installed. Run: pip install Flask")
    app = Flask(__name__)

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "time": time.time()})

    @app.route("/processes", methods=["GET"])
    def processes():
        limit = int(request.args.get("limit", "50"))
        include_vt = request.args.get("include_vt", "1").lower() not in ("0", "false")
        if monitor_thread:
            rows = monitor_thread.get_snapshot()
        else:
            vt_checker = VT_API_KEY and VTChecker(VT_API_KEY)
            rows = collect_process_snapshot(vt_checker, include_paths=True)
            if vt_checker:
                vt_checker.close()
        if not include_vt:
            for r in rows:
                r.pop("vt", None)
                r.pop("sha256", None)
        return jsonify({"timestamp": time.time(), "count": len(rows), "rows": rows[:limit]})

    @app.route("/processes/<int:pid>", methods=["GET"])
    def process_by_pid(pid: int):
        try:
            p = psutil.Process(pid)
            exe = p.exe() if p else ""
            sha = sha256_file(exe) if exe else None
            vt_data = None
            if sha and VT_API_KEY:
                vt_checker = VTChecker(VT_API_KEY)
                vt_data = vt_checker.get_stats_by_sha256(sha)
                vt_checker.close()
            return jsonify({
                "pid": pid, "name": p.name(), "exe": exe,
                "sha256": sha, "vt": vt_data
            })
        except psutil.NoSuchProcess:
            return jsonify({"error": "no such process"}), 404
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return app


# ------------------ Main Entry ------------------
def main():
    parser = argparse.ArgumentParser(description="Process monitor with VirusTotal integration, upload, and logging.")
    parser.add_argument("--api", action="store_true", help="Run Flask API mode")
    parser.add_argument("--host", default="0.0.0.0", help="API host (default 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000, help="API port (default 5000)")
    parser.add_argument("--poll", type=float, default=POLL_INTERVAL, help="Polling interval (seconds)")
    parser.add_argument("--print", action="store_true", help="Print one-time snapshot and exit")
    parser.add_argument("--limit", type=int, default=30, help="Console row limit")

    # Upload options
    parser.add_argument("--vt-upload-unknown", action="store_true",
                        help="Upload unknown executables to VT and wait for analysis.")
    parser.add_argument("--vt-upload-wait", type=int, default=30,
                        help="Max seconds to wait for analysis to complete.")
    parser.add_argument("--vt-upload-max-mb", type=int, default=32,
                        help="Max file size (MB) for upload (public VT limit ~32MB).")
    parser.add_argument("--vt-upload-allow-system", action="store_true",
                        help="Allow uploading files from system directories (use with caution).")

    # Logging options
    parser.add_argument("--log-json", type=str, default=None,
                        help="Path to JSON log file. Appends one JSON object per snapshot (JSON Lines).")
    parser.add_argument("--log-csv", type=str, default=None,
                        help="Path to CSV log file. Appends rows per process per snapshot.")
    parser.add_argument("--log-append", action="store_true",
                        help="Append to existing log files (default behavior).")

    args = parser.parse_args()

    # --- Single snapshot mode ---
    if args.print:
        vt_checker = VT_API_KEY and VTChecker(VT_API_KEY)
        try:
            rows = collect_process_snapshot(
                vt_checker,
                include_paths=True,
                upload_unknown=args.vt_upload_unknown,
                upload_wait=args.vt_upload_wait,
                upload_max_bytes=args.vt_upload_max_mb * 1024 * 1024,
                upload_allow_system=args.vt_upload_allow_system,
            )
        finally:
            if vt_checker:
                vt_checker.close()

        # Logging (single-shot)
        if args.log_json:
            write_json_log(rows, args.log_json)
        if args.log_csv:
            write_csv_log(rows, args.log_csv)

        print_snapshot(rows, limit=args.limit)
        return

    # --- Flask API mode ---
    if args.api:
        vt_checker = VT_API_KEY and VTChecker(VT_API_KEY)
        monitor = MonitorThread(
            vt_checker=vt_checker,
            poll_interval=args.poll,
            upload_unknown=args.vt_upload_unknown,
            upload_wait=args.vt_upload_wait,
            upload_max_bytes=args.vt_upload_max_mb * 1024 * 1024,
            upload_allow_system=args.vt_upload_allow_system,
            log_json_path=args.log_json,
            log_csv_path=args.log_csv,
        )
        monitor.start()
        app = create_app(monitor)
        print(f"API running at http://{args.host}:{args.port}")
        try:
            app.run(host=args.host, port=args.port)
        finally:
            monitor.stop()
            if vt_checker:
                vt_checker.close()
        return

    # --- Continuous console monitor mode ---
    vt_checker = VT_API_KEY and VTChecker(VT_API_KEY)
    try:
        while True:
            try:
                rows = collect_process_snapshot(
                    vt_checker,
                    include_paths=True,
                    upload_unknown=args.vt_upload_unknown,
                    upload_wait=args.vt_upload_wait,
                    upload_max_bytes=args.vt_upload_max_mb * 1024 * 1024,
                    upload_allow_system=args.vt_upload_allow_system,
                )

                # Logging (continuous)
                if args.log_json:
                    write_json_log(rows, args.log_json)
                if args.log_csv:
                    write_csv_log(rows, args.log_csv)

                print_snapshot(rows, limit=args.limit)
            except Exception as e:
                print(f"[monitor] error: {e}", file=sys.stderr)
            time.sleep(args.poll)
    except KeyboardInterrupt:
        print("Exiting monitor.")
    finally:
        if vt_checker:
            vt_checker.close()


if __name__ == "__main__":
    main()
