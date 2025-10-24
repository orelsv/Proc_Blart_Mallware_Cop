#!/usr/bin/env python3
"""
Proc Blart: Mallware Cop — Step 1: Real-Time Process Monitor (CSV + Alerts)
Shows: Name, PID, CPU%, RSS, optional exe path.
Adds: CSV logging, threshold alerts with highlighting.
Deps: psutil
"""

import argparse
import csv
import datetime as dt
import os
import sys
import time
from typing import List, Dict, Any

import psutil


def fmt_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(n)
    i = 0
    while size >= 1024 and i < len(units) - 1:
        size /= 1024.0
        i += 1
    return f"{size:.1f} {units[i]}"


def collect_process_snapshot(include_path: bool = False) -> List[Dict[str, Any]]:
    procs = []
    for p in psutil.process_iter(attrs=["pid", "name"]):
        try:
            cpu = p.cpu_percent(interval=None)
            mem = p.memory_info().rss
            item = {
                "name": p.info.get("name") or "",
                "pid": p.info["pid"],
                "cpu": float(cpu),
                "rss": int(mem),
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


def csv_writer(path: str, include_path: bool):
    """
    Returns (writer_func, ensure_header) closures to append rows and create header once.
    """
    header = ["timestamp", "name", "pid", "cpu", "rss"]
    if include_path:
        header.append("exe")

    def ensure_header():
        need_header = not os.path.exists(path) or os.path.getsize(path) == 0
        if need_header:
            with open(path, "a", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(header)

    def write_rows(ts: str, rows: List[Dict[str, Any]]):
        with open(path, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            for r in rows:
                base = [ts, r["name"], r["pid"], f"{r['cpu']:.3f}", r["rss"]]
                if include_path:
                    base.append(r.get("exe", ""))
                w.writerow(base)

    return write_rows, ensure_header


def supports_color(no_color_flag: bool) -> bool:
    if no_color_flag:
        return False
    if os.name == "nt":
        # On modern Windows 10+ terminals, ANSI is usually fine.
        return True
    return sys.stdout.isatty()


# ANSI colors (safe to no-op if disabled)
COL_RESET = "\033[0m"
COL_ALERT = "\033[1;31m"   # bright red
COL_WARN  = "\033[1;33m"   # bright yellow


def print_table(rows: List[Dict[str, Any]],
                include_path: bool,
                limit: int,
                color_on: bool,
                cpu_thr: float,
                mem_thr_mb: float) -> None:
    # Sort by CPU desc, then RSS desc
    rows = sorted(rows, key=lambda r: (r["cpu"], r["rss"]), reverse=True)
    if limit > 0:
        rows = rows[:limit]

    name_w = 27
    pid_w = 7
    cpu_w = 6
    rss_w = 12

    header = f"{'!':1} {'NAME':{name_w}} {'PID':>{pid_w}} {'CPU%':>{cpu_w}} {'RSS':>{rss_w}}"
    if include_path:
        header += "  EXE"
    print(header)
    print("-" * len(header))

    for r in rows:
        alert = False
        warn = False

        if cpu_thr is not None and r["cpu"] >= cpu_thr:
            alert = True
        if mem_thr_mb is not None and (r["rss"] / (1024 * 1024)) >= mem_thr_mb:
            # If already alert by CPU, keep as alert; otherwise mark as warn (yellow)
            warn = not alert

        prefix = "!" if (alert or warn) else " "
        name = (r["name"] or "")[:name_w]
        pid = str(r["pid"]).rjust(pid_w)
        cpu = f"{r['cpu']:.1f}".rjust(cpu_w)
        rss = fmt_bytes(r["rss"]).rjust(rss_w)
        line = f"{prefix} {name:{name_w}} {pid} {cpu} {rss}"

        if include_path:
            line += f"  {r.get('exe','')}"

        if color_on and (alert or warn):
            col = COL_ALERT if alert else COL_WARN
            print(col + line + COL_RESET)
        else:
            print(line)


def main():
    parser = argparse.ArgumentParser(
        description="Real-Time Process Monitor (psutil) with CSV logging & alerts."
    )
    parser.add_argument("-i", "--interval", type=float, default=1.0,
                        help="Refresh interval in seconds (default: 1.0)")
    parser.add_argument("-n", "--top", type=int, default=25,
                        help="Show top N processes by CPU (default: 25; 0=show all)")
    parser.add_argument("--paths", action="store_true",
                        help="Include executable path column")
    parser.add_argument("--sort", choices=["cpu", "mem"], default="cpu",
                        help="Primary sort key for CSV only (screen is CPU-first)")
    parser.add_argument("--once", action="store_true",
                        help="Print a single snapshot and exit")
    parser.add_argument("--csv", type=str, default=None,
                        help="Append snapshots to CSV file at given PATH")
    parser.add_argument("--cpu-threshold", type=float, default=None,
                        help="Highlight processes with CPU%% >= THRESHOLD")
    parser.add_argument("--mem-threshold", type=float, default=None,
                        help="Highlight processes with RSS (MB) >= THRESHOLD")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colors in output")

    args = parser.parse_args()

    # Seed CPU percentages
    for p in psutil.process_iter():
        try:
            p.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    csv_write = None
    csv_header = None
    if args.csv:
        csv_write, csv_header = csv_writer(args.csv, include_path=args.paths)
        csv_header()

    color_on = supports_color(args.no_color)

    try:
        while True:
            rows = collect_process_snapshot(include_path=args.paths)

            # Optional sort override for CSV (screen remains CPU-first)
            rows_for_screen = sorted(rows, key=lambda r: (r["cpu"], r["rss"]), reverse=True)
            if args.top > 0:
                rows_for_screen = rows_for_screen[:args.top]

            # Clear screen for live view
            if not args.once:
                os.system("cls" if os.name == "nt" else "clear")

            now = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{now}] Processes: {len(rows)}  (interval={args.interval}s)")
            print_table(
                rows_for_screen,
                include_path=args.paths,
                limit=0,  # already sliced above
                color_on=color_on,
                cpu_thr=args.cpu_threshold,
                mem_thr_mb=args.mem_threshold
            )

            # CSV logging (full list, not just top N)
            if csv_write:
                # Allow user to choose CSV sort
                if args.sort == "mem":
                    csv_rows = sorted(rows, key=lambda r: r["rss"], reverse=True)
                else:
                    csv_rows = sorted(rows, key=lambda r: r["cpu"], reverse=True)
                csv_write(now, csv_rows)

            if args.once:
                break

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\nExiting…")


if __name__ == "__main__":
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        except Exception:
            pass
    sys.exit(main())
