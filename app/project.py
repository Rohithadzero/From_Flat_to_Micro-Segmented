"""Read/write project data for the dashboard: configs, result CSVs, metrics."""

from __future__ import annotations

import csv
import difflib
import importlib.util
import io
import json
import re
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent          # CN Project/
CFG = ROOT / "configs"
RES = ROOT / "results"
TOOLS = ROOT / "tools"
SAVES = ROOT / "Cisco packet saves"

DESIGNS = {
    "D0": {"dir": "D0-flat", "name": "D0 Flat", "summary": "One VLAN, every host reaches every host (baseline)."},
    "D1": {"dir": "D1-vlan", "name": "D1 VLAN-only", "summary": "Role VLANs, inter-VLAN routing on the core with no filtering."},
    "D2": {"dir": "D2-zone-acl", "name": "D2 Zone ACLs", "summary": "Coarse SVI ACLs: IoT to server zone only, guests to Internet only."},
    "D3": {"dir": "D3-microseg", "name": "D3 Micro-segmentation",
           "summary": "VLAN per device class, least-privilege host+port ACLs, ASA in front of servers, L2 hardening, SSH-only mgmt."},
}

CSV_FILES = {
    "attack-matrix": "attack-matrix.csv",
    "attack-surface": "attack-surface.csv",
    "functional": "functional.csv",
    "config-complexity": "config-complexity.csv",
    "static-analysis": "static-analysis.csv",
    "static-surface": "static-surface.csv",
    "static-functional": "static-functional.csv",
}

_csv_lock = threading.Lock()


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = mod          # dataclasses need the module registered
    if str(path.parent) not in sys.path:
        sys.path.insert(0, str(path.parent))
    spec.loader.exec_module(mod)
    return mod


# ------------------------------------------------------------------ configs
def list_configs(design: str) -> dict[str, str]:
    d = CFG / DESIGNS[design]["dir"]
    return {f.stem: f.read_text(encoding="utf-8") for f in sorted(d.glob("*.txt"))}


def config_diff(a: str, b: str, device: str) -> dict:
    fa = CFG / DESIGNS[a]["dir"] / f"{device}.txt"
    fb = CFG / DESIGNS[b]["dir"] / f"{device}.txt"
    la = fa.read_text(encoding="utf-8").splitlines() if fa.exists() else []
    lb = fb.read_text(encoding="utf-8").splitlines() if fb.exists() else []
    strip = lambda ls: [x for x in ls if x.strip() and not x.strip().startswith("!")]  # noqa: E731
    diff = list(difflib.unified_diff(strip(la), strip(lb), f"{a}/{device}", f"{b}/{device}", lineterm="", n=1))
    added = sum(1 for x in diff if x.startswith("+") and not x.startswith("+++"))
    removed = sum(1 for x in diff if x.startswith("-") and not x.startswith("---"))
    return {"device": device, "a": a, "b": b, "diff": diff, "added": added, "removed": removed,
            "exists": {"a": fa.exists(), "b": fb.exists()}}


def complexity() -> list[dict]:
    cs = _load_module("config_stats", TOOLS / "config_stats.py")
    rows = []
    for design in cs.DESIGNS:
        files = sorted((CFG / design).glob("*.txt"))
        lines = aces = 0
        found = set()
        per_device = {}
        for f in files:
            cmds = list(cs.real_commands(f.read_text(encoding="utf-8")))
            n_aces = sum(1 for c in cmds if cs.ACE_RE.search(c))
            per_device[f.stem] = {"lines": len(cmds), "aces": n_aces}
            lines += len(cmds)
            aces += n_aces
            for name, pat in cs.FEATURES.items():
                if any(re.search(pat, c.strip()) for c in cmds):
                    found.add(name)
        rows.append({"design": design.split("-")[0], "devices": len(files), "config_lines": lines,
                     "aces": aces, "features": [n for n in cs.FEATURES if n in found], "per_device": per_device})
    return rows


# ---------------------------------------------------------------------- csv
def read_csv(key: str) -> list[dict]:
    p = RES / CSV_FILES[key]
    if not p.exists():
        return []
    with p.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def write_rows(key: str, rows: list[dict]) -> None:
    p = RES / CSV_FILES[key]
    if not rows:
        return
    with _csv_lock:
        tmp = p.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        tmp.replace(p)


def record_observation(key: str, match: dict[str, str], updates: dict[str, str]) -> int:
    """Set columns on every row whose fields equal ``match``. Returns rows changed."""
    with _csv_lock:
        rows = read_csv(key)
    n = 0
    for r in rows:
        if all(str(r.get(k, "")) == str(v) for k, v in match.items()):
            for k, v in updates.items():
                if k in r:
                    r[k] = v
            n += 1
    if n:
        write_rows(key, rows)
    return n


EXTRA_CSV = {  # written by the live runner (literature-driven additions, see research/GAP-ANALYSIS.md)
    "overhead": ["design", "trial", "flow", "metric", "value", "unit", "notes"],
    "extended-attacks": ["test_id", "test_name", "design", "location", "trial", "expected", "observed",
                         "time_to_detect_s", "time_to_contain_s", "collateral_ok", "notes"],
    "detection": ["design", "location", "trial", "test_id", "deny_hits_delta", "detected", "notes"],
    "probes": ["design", "probe", "result", "notes"],
}
CSV_FILES.update({k: f"{k}.csv" for k in EXTRA_CSV})


def append_row(key: str, row: dict) -> None:
    """Append one row to a runner-owned CSV, replacing a row with the same identity."""
    cols = EXTRA_CSV[key]
    ident = [c for c in ("test_id", "design", "location", "trial", "flow", "metric", "probe") if c in cols]
    with _csv_lock:
        rows = read_csv(key)
        rows = [r for r in rows if any(str(r.get(c, "")) != str(row.get(c, "")) for c in ident)]
        rows.append({c: str(row.get(c, "")) for c in cols})
    write_rows(key, rows)


OBS_HOSTS = RES / "observed-hosts.json"


def append_observed_hosts(entry: dict) -> None:
    with _csv_lock:
        data = json.loads(OBS_HOSTS.read_text(encoding="utf-8")) if OBS_HOSTS.exists() else []
        data = [d for d in data if not (d["design"] == entry["design"] and d["location"] == entry["location"]
                                        and d["trial"] == entry["trial"])] + [entry]
        OBS_HOSTS.write_text(json.dumps(data, indent=1), encoding="utf-8")


def observed_hosts() -> list[dict]:
    return json.loads(OBS_HOSTS.read_text(encoding="utf-8")) if OBS_HOSTS.exists() else []


def summary() -> dict:
    am = read_csv("attack-matrix")
    surf = read_csv("attack-surface")
    fn = read_csv("functional")
    filled = lambda rows, col: sum(1 for r in rows if str(r.get(col, "")).strip())  # noqa: E731
    return {
        "attack_matrix": {"rows": len(am), "observed": filled(am, "observed")},
        "attack_surface": {"rows": len(surf), "observed": filled(surf, "observed_hosts_of_23")},
        "functional": {"rows": len(fn), "observed": filled(fn, "observed")},
        "static_analysis": (RES / "static-analysis.json").exists(),
        "pkt_files": {p.stem: p.stat().st_mtime for p in sorted(SAVES.glob("D*.pkt"))},
    }


def majority(rows: list[dict], col: str) -> dict[str, dict[str, str]]:
    from collections import Counter, defaultdict
    cells: dict[tuple, list] = defaultdict(list)
    for r in rows:
        v = str(r.get(col, "")).strip().upper()
        if v:
            cells[(r["test_id"], r["design"])].append(v)
    out: dict[str, dict[str, str]] = {}
    for (tid, d), vs in cells.items():
        out.setdefault(tid, {})[d] = Counter(vs).most_common(1)[0][0]
    return out


def results_bundle() -> dict:
    am = read_csv("attack-matrix")
    names = {r["test_id"]: r["test_name"] for r in am}
    static = read_csv("static-analysis")
    static_m = {}
    if static:
        key = "predicted" if "predicted" in static[0] else ("outcome" if "outcome" in static[0] else None)
        if key:
            static_m = majority([dict(r, test_id=r.get("test_id", r.get("attack", ""))) for r in static], key)
    return {
        "attack_names": names,
        "matrix": {"expected": majority(am, "expected"), "observed": majority(am, "observed"), "static": static_m},
        "surface": read_csv("attack-surface"),
        "static_surface": read_csv("static-surface"),
        "functional": read_csv("functional"),
        "static_functional": read_csv("static-functional"),
        "complexity": complexity(),
        "observed_hosts": observed_hosts(),
        "extended": read_csv("extended-attacks"),
        "overhead": read_csv("overhead"),
        "detection": read_csv("detection"),
        "probes": read_csv("probes"),
        "summary": summary(),
    }


# ------------------------------------------------------------ analyzer/tests
def analyzer() -> dict:
    j = RES / "static-analysis.json"
    pa = TOOLS / "policy_analyzer.py"
    if pa.exists():
        try:
            mod = _load_module("policy_analyzer", pa)
            if hasattr(mod, "analyze_all"):
                return {"available": True, "source": "live", "data": mod.analyze_all()}
        except Exception as exc:  # noqa: BLE001
            if j.exists():
                return {"available": True, "source": "cached", "warning": str(exc),
                        "data": json.loads(j.read_text(encoding="utf-8"))}
            return {"available": False, "error": f"policy_analyzer failed: {exc}"}
    if j.exists():
        return {"available": True, "source": "cached", "data": json.loads(j.read_text(encoding="utf-8"))}
    return {"available": False, "error": "tools/policy_analyzer.py not built yet"}


def run_pytest() -> dict:
    tests = ROOT / "tests"
    if not tests.exists():
        return {"ok": False, "output": "tests/ folder not created yet"}
    import shutil
    py = shutil.which("python") or sys.executable   # system Python has pytest
    proc = subprocess.run([py, "-m", "pytest", "-q", "--no-header", "-p", "no:cacheprovider", str(tests)],
                          cwd=str(ROOT), capture_output=True, text=True, timeout=600)
    out = proc.stdout + proc.stderr
    m = re.search(r"(\d+) passed", out)
    f = re.search(r"(\d+) failed", out)
    return {"ok": proc.returncode == 0, "passed": int(m.group(1)) if m else 0,
            "failed": int(f.group(1)) if f else 0, "output": out[-6000:], "python": py}
