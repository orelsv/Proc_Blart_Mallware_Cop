#!/usr/bin/env python3
"""
Proc Blart: Mallware Cop — Step 1: Real-Time Process Monitor
Shows: Process Name, PID, CPU%, Memory (RSS), optional exe path (toggle).
Windows-friendly, minimal deps (psutil only).
"""

import argparse
import datetime as dt
import os
import sys
import time
from typing import List, Dict, Any

import psutil


def fmt_bytes(n: int) -> str:
    """Human-readable bytes (e.g., 123.4 MB)."""
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(n)
    i = 0
    while size >= 1024 and i < len(units) - 1:
        size /= 1024.0
        i += 1
    return f"{size:.1f} {units[i]}"


def collect_process_snapshot(include_path: bool = False) -> List[Dict[str, Any]]:
    """
    Safely collect process info: name, pid, cpu%, rss, (optional exe path).
    Handles AccessDenied/NoSuchProcess without crashing.
    """
    procs = []
    for p in psutil.process_iter(attrs=["pid", "name"]):
        try:
            # cpu_percent(None) uses last interval; first call seeds, second returns value.
            cpu = p.cpu_percent(interval=None)
            mem = p.memory_info().rss
            item = {
                "name": p.info.get("name") or "",
                "pid": p.info["pid"],
                "cpu": cpu,
                "rss": mem,
            }
            if include_path:
                try:
                    item["exe"] = p.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    item["exe"] = ""
            procs.append(item)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return procs


def print_table(rows: List[Dict[str, Any]], include_path: bool, limit: int) -> None:
    """Simple, portable table rendering."""
    # Sort by CPU desc, then RSS desc
    rows = sorted(rows, key=lambda r: (r["cpu"], r["rss"]), reverse=True)
    if limit > 0:
        rows = rows[:limit]

    # Column widths
    name_w = 27
    pid_w = 7
    cpu_w = 6
    rss_w = 12

    header = f"{'NAME':{name_w}} {'PID':>{pid_w}} {'CPU%':>{cpu_w}} {'RSS':>{rss_w}}"
    if include_path:
        header += "  EXE"
    print(header)
    print("-" * len(header))

    for r in rows:
        name = (r["name"] or "")[:name_w]
        pid = str(r["pid"]).rjust(pid_w)
        cpu = f"{r['cpu']:.1f}".rjust(cpu_w)
        rss = fmt_bytes(r["rss"]).rjust(rss_w)
        line = f"{name:{name_w}} {pid} {cpu} {rss}"
        if include_path:
            line += f"  {r.get('exe','')}"
        print(line)


def main():
    parser = argparse.ArgumentParser(
        description="Real-Time Process Monitor (psutil-based)."
    )
    parser.add_argument(
        "-i", "--interval", type=float, default=1.0,
        help="Refresh interval in seconds (default: 1.0)"
    )
    parser.add_argument(
        "-n", "--top", type=int, default=25,
        help="Show top N processes by CPU (default: 25; 0=show all)"
    )
    parser.add_argument(
        "--paths", action="store_true",
        help="Include executable path column (may require admin for some processes)"
    )
    parser.add_argument(
        "--sort", choices=["cpu", "mem"], default="cpu",
        help="Primary sort key: cpu or mem (default: cpu)"
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Print a single snapshot and exit"
    )
    args = parser.parse_args()

    # Seed CPU percentages (first read often returns 0.0)
    for p in psutil.process_iter():
        try:
            p.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    try:
        while True:
            rows = collect_process_snapshot(include_path=args.paths)

            # If sort by memory requested, override cpu sort
            if args.sort == "mem":
                rows = sorted(rows, key=lambda r: r["rss"], reverse=True)

            # Clear screen (portable-ish)
            if not args.once:
                os.system("cls" if os.name == "nt" else "clear")

            now = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{now}] Processes: {len(rows)}  (interval={args.interval}s, sort={args.sort})")
            print_table(rows, include_path=args.paths, limit=args.top)

            if args.once:
                break

            # Sleep, but also tick CPU measurement
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\nExiting…")


if __name__ == "__main__":
    # Better default encoding on Windows consoles
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        except Exception:
            pass
    sys.exit(main())
