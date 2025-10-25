#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Policy-driven reactions:
# - name == virus.exe -> terminate + quarantine
# - VT (malicious + suspicious) > threshold -> suspend -> dump -> quarantine
# - RSS > memory_warning_mb -> write warning to response_actions.log.jsonl

import argparse, os, sys, time, json, hashlib
from pathlib import Path

import psutil  # pip install psutil

import proc_monitor_vt_api as base   # VT wrapper, hashing, etc.
import response_actions as ra        # actions: suspend/terminate/dump/quarantine/log

# ---------- defaults (overridden by policy.yaml) ----------
DEFAULTS = {
    "kill_names": ["virus.exe"],
    "vt_detect_threshold": 3,           # malicious + suspicious > 3
    "memory_warning_mb": 500,           # warn if RSS > 500 MB
    "procdump_dir": "dumps",
    "quarantine_dir": "Quarantine",
    "procdump_path": None               # e.g. C:\\Tools\\Sysinternals\\procdump64.exe
}

LOG_PATH = "response_actions.log.jsonl"

def load_policy(path: str | None):
    if not path or not Path(path).exists():
        return dict(DEFAULTS)
    try:
        import yaml  # pip install pyyaml
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        pol = dict(DEFAULTS)
        pol.update(data)
        return pol
    except Exception:
        return dict(DEFAULTS)

def write_action(kind: str, **kwargs):
    rec = dict(kwargs)
    rec["action"] = kind
    ra.write_action_log(LOG_PATH, rec)   # already appends JSONL with ts_utc. :contentReference[oaicite:6]{index=6}

def sha256_file(p: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1024*1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def vt_counts(stats: dict | None) -> tuple[int,int]:
    if not isinstance(stats, dict):
        return (0,0)
    m = int(stats.get("malicious", 0))
    s = int(stats.get("suspicious", 0))
    return (m, s)

def act_terminate_quarantine(pid: int, exe: str, qdir: str):
    ra.terminate_process(pid)
    dst = ra.quarantine_file(exe, qdir)
    write_action("terminate", pid=pid, exe=exe, reason="name_match", result="ok" if dst is not None else "moved_without_log")
    write_action("quarantine", pid=pid, exe=exe, quarantine_path=dst, reason="name_or_vt")

def act_suspend_dump_quarantine(pid: int, exe: str, pdir: str, qdir: str, procdump_path: str | None):
    ra.suspend_process(pid)
    dmp = ra.dump_memory_with_procdump(pid, pdir, procdump_path=procdump_path)  # may be None if procdump not found
    dst = ra.quarantine_file(exe, qdir)
    write_action("suspend", pid=pid, exe=exe, reason="vt_threshold")
    write_action("dump", pid=pid, exe=exe, dump_path=dmp, reason="vt_threshold", result="ok" if dmp else "failed_or_missing_procdump")
    write_action("quarantine", pid=pid, exe=exe, quarantine_path=dst, reason="vt_threshold")

def run_once(args):
    pol = load_policy(args.policy)

    # optional VT
    vt_checker = None
    if getattr(base, "vt", None) is not None and getattr(base, "VT_API_KEY", None):
        try:
            vt_checker = base.VTChecker(base.VT_API_KEY)  # provides get_stats_by_sha256(). :contentReference[oaicite:7]{index=7}
        except Exception:
            vt_checker = None

    kill_names = {n.lower() for n in pol["kill_names"]}
    vt_thr = int(pol["vt_detect_threshold"])
    mem_warn = int(pol["memory_warning_mb"]) * 1024 * 1024
    pdir = pol["procdump_dir"]
    qdir = pol["quarantine_dir"]
    procdump_path = pol.get("procdump_path")

    Path(pdir).mkdir(parents=True, exist_ok=True)
    Path(qdir).mkdir(parents=True, exist_ok=True)

    # iterate processes
    for p in psutil.process_iter(attrs=["pid","name","exe","memory_info"]):
        pid = p.info["pid"]
        name = (p.info.get("name") or "").lower()
        exe  = p.info.get("exe") or ""

        # 1) high memory warning
        rss = int(getattr(p.info.get("memory_info"), "rss", 0) or 0)
        if rss > mem_warn:
            write_action("log_warning", pid=pid, exe=exe, name=name, reason=f"memory>{mem_warn}B", rss=rss)

        # 2) name-based kill + quarantine
        if name in kill_names and exe:
            act_terminate_quarantine(pid, exe, qdir)
            continue  # already handled

        # 3) VT threshold reaction
        if not exe or not vt_checker:
            continue
        sha = sha256_file(exe)
        if not sha:
            continue
        stats = vt_checker.get_stats_by_sha256(sha)     # returns last_analysis_stats dict. :contentReference[oaicite:8]{index=8}
        m, s = vt_counts(stats)
        if (m + s) > vt_thr:
            act_suspend_dump_quarantine(pid, exe, pdir, qdir, procdump_path)

    if vt_checker:
        vt_checker.close()

def main():
    ap = argparse.ArgumentParser(description="Apply response policy to running processes.")
    ap.add_argument("--policy", default="policy.yaml")
    ap.add_argument("--print", action="store_true", help="(kept for compatibility; actions still apply)")
    ap.add_argument("--limit", type=int, default=0, help="(unused, kept for compatibility)")
    ap.add_argument("--vt-upload-unknown", action="store_true", help="(unused here; policy uses lookups only)")
    ap.add_argument("--vt-upload-wait", type=int, default=60)
    args = ap.parse_args()
    run_once(args)

if __name__ == "__main__":
    main()
