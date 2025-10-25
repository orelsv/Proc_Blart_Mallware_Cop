#!/usr/bin/env python3
# vt_debug.py — compute sha256 of an exe or get by PID and query VT API (HTTP)
# Usage:
#  python vt_debug.py --pid 4616
#  python vt_debug.py --file "C:\Users\...\Downloads\test_charmap.exe"

import argparse
import hashlib
import os
import sys
import json

try:
    import requests
except Exception:
    print("Missing dependency: pip install requests")
    sys.exit(2)

def sha256_of_path(path, read_bytes=None):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        if read_bytes:
            h.update(f.read(read_bytes))
        else:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    return h.hexdigest()

def get_exe_from_pid(pid):
    try:
        import psutil
    except Exception:
        raise RuntimeError("psutil not installed. pip install psutil")
    p = psutil.Process(pid)
    return p.exe()

def query_vt(sha256, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": api_key}
    try:
        r = requests.get(url, headers=headers, timeout=20)
    except requests.exceptions.RequestException as e:
        return {"ok": False, "error": f"network error: {e}"}
    out = {"ok": True, "status_code": r.status_code, "text_snippet": None, "json": None}
    try:
        out["text_snippet"] = r.text[:200]
    except Exception:
        pass
    # Try to parse JSON if available
    try:
        out["json"] = r.json()
    except Exception:
        out["json"] = None
    return out

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--pid", type=int, help="PID to inspect")
    p.add_argument("--file", help="Path to exe file")
    p.add_argument("--bytes", type=int, default=1024*1024, help="Read this many bytes for quick hash (default 1MB). Use 0 for full file")
    args = p.parse_args()

    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        print("VT_API_KEY is not set in this environment. Set it and rerun.")
        sys.exit(3)

    if not args.pid and not args.file:
        p.print_help()
        sys.exit(1)

    try:
        if args.pid:
            exe = get_exe_from_pid(args.pid)
        else:
            exe = args.file
        print("Target executable:", exe)
        if args.bytes == 0:
            sha = sha256_of_path(exe, read_bytes=None)
        else:
            # For a robust check we compute full file by default; smaller read is faster but may not match VT's full-hash
            sha = sha256_of_path(exe, read_bytes=None)
        print("SHA256:", sha)
    except Exception as e:
        print("Error reading file / pid:", e)
        sys.exit(4)

    print("Querying VirusTotal API...")
    res = query_vt(sha, api_key)
    if not res.get("ok"):
        print("Request failed:", res.get("error"))
        sys.exit(5)

    sc = res.get("status_code")
    print("HTTP status:", sc)
    if sc == 200:
        print("VT returned a report (200). Summary keys:")
        js = res.get("json") or {}
        # Print small, useful parts
        summary = {}
        data = js.get("data")
        if data and isinstance(data, dict):
            attrs = data.get("attributes", {})
            last_analysis = attrs.get("last_analysis_stats", {})
            summary["last_analysis_stats"] = last_analysis
            summary["meaningful_names"] = {
                "type_description": attrs.get("type_description"),
                "times_submitted": attrs.get("times_submitted"),
            }
        else:
            summary = js
        print(json.dumps(summary, indent=2))
    elif sc == 404:
        print("404 Not Found — VT does not have info about this file (not submitted).")
        print("You can submit the file if you choose (careful with private files).")
    elif sc == 401:
        print("401 Unauthorized — API key invalid or missing.")
    elif sc == 403:
        print("403 Forbidden — API key lacks permission or is rate-limited.")
    elif sc == 429:
        print("429 Too Many Requests — rate limit exceeded. Try later.")
    else:
        print("Response snippet:", res.get("text_snippet"))
        if res.get("json"):
            print("Response JSON (first 300 chars):", json.dumps(res.get("json"))[:300])

if __name__ == "__main__":
    main()
