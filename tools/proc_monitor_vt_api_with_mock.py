#!/usr/bin/env python3
"""
proc_monitor_vt_api_with_mock.py — запуск оригінального proc_monitor_vt_api.py
з підтримкою --mock-vt-dir без конфліктів аргументів.
"""

import sys, json, runpy
from pathlib import Path

def read_mock_vt(mock_dir, sha256):
    from pathlib import Path
    md = Path(mock_dir)
    if not md.exists():
        return None
    for p in md.glob(f"{sha256}*.json"):
        try:
            return json.load(open(p, "r", encoding="utf-8"))
        except Exception:
            continue
    return None

def get_vt_result(sha256, mock_vt_dir=None, vt_client=None):
    if mock_vt_dir:
        res = read_mock_vt(mock_vt_dir, sha256)
        if res:
            return res
    if vt_client:
        try:
            if hasattr(vt_client, "get_analysis"):
                return vt_client.get_analysis(sha256=sha256)
            if hasattr(vt_client, "file"):
                f = vt_client.file(sha256)
                if hasattr(f, "analysis"): return f.analysis()
                if hasattr(f, "get_analysis"): return f.get_analysis()
        except Exception as e:
            print("[mock-wrapper] VT call failed:", e)
    return None

def main():
    # знаходимо оригінальний файл
    orig = Path(__file__).with_name("proc_monitor_vt_api.py")
    if not orig.exists():
        print(f"[mock-wrapper] Не знайдено {orig}")
        sys.exit(1)

    # шукаємо опцію --mock-vt-dir
    mock_dir = None
    args = []
    skip_next = False
    for i, a in enumerate(sys.argv[1:]):
        if skip_next:
            skip_next = False
            continue
        if a == "--mock-vt-dir":
            if i + 2 <= len(sys.argv):
                mock_dir = sys.argv[i + 2]
                skip_next = True
            continue
        args.append(a)

    # видаляємо можливе подвійне "--"
    if len(args) > 0 and args[0] == "--":
        args = args[1:]

    # замінюємо sys.argv на аргументи для оригінального скрипта
    sys.argv = [str(orig)] + args

    init_globals = {
        "__name__": "__main__",
        "get_vt_result": lambda sha: get_vt_result(sha, mock_vt_dir=mock_dir),
        "MOCK_VT_DIR": mock_dir,
    }

    runpy.run_path(str(orig), run_name="__main__", init_globals=init_globals)

if __name__ == "__main__":
    main()
