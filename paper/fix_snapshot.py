"""Pre-fix vs post-fix snapshot for the analyser-found misconfigurations (tests/FINDINGS.md).

For D2 and D3 it assembles the pre-fix configuration set (the current files,
with configs/archive/pre-fix/<Dn>-<DEVICE>.txt substituted) in a temporary
directory. It then runs tools/policy_analyzer.py (read-only; single-design
mode never writes to results/) on both the pre-fix and the current (post-fix)
configurations, and counts configuration cost with the same rule as
tools/config_stats.py.

Writes paper/data/fix-impact.csv (one row per design x version). The table
generator turns it into tables/fix_impact.tex. Nothing outside paper/ is written.

Usage:  python paper/fix_snapshot.py
"""
import csv
import re
import shutil
import sys
import tempfile
from pathlib import Path

PAPER = Path(__file__).resolve().parent
ROOT = PAPER.parent
CFG = ROOT / "configs"
ARCH = CFG / "archive" / "pre-fix"
OUT = PAPER / "data" / "fix-impact.csv"
DIRS = {"D2": "D2-zone-acl", "D3": "D3-microseg"}
WRAPPERS = {"enable", "configure terminal", "end", "write memory"}
ACE_RE = re.compile(r"^\s*(permit|deny)\s|^access-list \d+ (permit|deny)\s|^access-list \S+ extended (permit|deny)\s")
LOCS = ["L1", "L2", "L3"]


def cost(folder: Path):
    lines = aces = 0
    for f in sorted(folder.glob("*.txt")):
        for ln in f.read_text(encoding="utf-8").splitlines():
            s = ln.strip()
            if not s or s.startswith("!") or s in WRAPPERS:
                continue
            lines += 1
            aces += bool(ACE_RE.search(ln))
    return lines, aces


def unused_srv_ports_up(folder: Path) -> int:
    """SW-SRV ports with no device attached that are not shut down (finding F-4)."""
    p = folder / "SW-SRV.txt"
    if not p.exists():
        return 0
    text = p.read_text(encoding="utf-8")
    parked = 0
    for m in re.finditer(r"^interface range ([^\n]+)\n((?: [^\n]*\n)+)", text, re.M):
        if re.search(r"^\s*shutdown\s*$", m.group(2), re.M):
            for part in m.group(1).split(","):
                r = re.search(r"(\d+)/(\d+)\s*-\s*(\d+)", part)
                parked += (int(r.group(3)) - int(r.group(2)) + 1) if r else 1
    return max(0, 21 - parked)          # Fa0/5-24 + Gi0/2 = 21 unused ports on SW-SRV


def expected_matrix():
    exp = {}
    with (ROOT / "results" / "attack-matrix.csv").open(encoding="utf-8-sig", newline="") as fh:
        for r in csv.DictReader(fh):
            exp[(r["design"], r["location"], r["test_id"])] = r["expected"].strip().upper()[:1]
    return exp


def summarise(pa, design, folder, version, exp):
    res = pa.analyze(design, folder)
    lines, aces = cost(folder)
    row = {"design": design, "version": version, "config_lines": lines, "aces": aces}
    hosts, svcs, exfil, a4 = [], [], False, []
    for loc in LOCS:
        L = res["locations"][loc]
        hosts.append(L["surface"]["hosts_reachable_of_23"])
        svcs.append(L["surface"]["services_reachable_of_10"])
        a4.append(L["attacks"]["A4"]["predicted"])
        for ch in L.get("residual_channels", []):
            if "Internet" in ch["channel"] and ch.get("forward_delivered"):
                exfil = True
    # H-1: guest -> EDGE-RTR WAN address (outside 10/8) management session
    m = pa.load_design(design, folder)
    g = pa.mgmt_probe(m, ("host", "Guest-Phone"), pa.ip2i("198.51.100.2"))
    row["guest_edge_mgmt"] = "yes" if g["ok"] else "no"
    dis = sum(1 for a in res["attacks"]
              if exp.get((design, a["location"], a["test_id"])) not in (None, a["predicted"]))
    row.update(a4="/".join(a4), hosts_mean=round(sum(hosts) / len(hosts), 2),
               services_mean=round(sum(svcs) / len(svcs), 2),
               udp67_internet="yes" if exfil else "no",
               unused_srv_ports_up=unused_srv_ports_up(folder),
               analyzer_disagreements=dis,
               functional_pass=sum(1 for v in res["functional"].values() if v["predicted"] == "PASS"),
               functional_total=len(res["functional"]))
    return row


def main():
    if not ARCH.exists():
        print("fix_snapshot: configs/archive/pre-fix not found; nothing to do")
        return 0
    sys.path.insert(0, str(ROOT / "tools"))
    import policy_analyzer as pa       # project code, read-only use
    exp = expected_matrix()
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        for d, sub in DIRS.items():
            pre = Path(tmp) / d
            shutil.copytree(CFG / sub, pre)
            subs = sorted(ARCH.glob(f"{d}-*.txt"))
            for f in subs:
                shutil.copy(f, pre / (f.name[len(d) + 1:]))
            if not subs:
                continue
            rows.append(summarise(pa, d, pre, "pre-fix", exp))
            rows.append(summarise(pa, d, CFG / sub, "post-fix", exp))
    OUT.parent.mkdir(exist_ok=True)
    with OUT.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    for r in rows:
        print("  ", r)
    print(f"fix_snapshot: wrote {OUT.relative_to(PAPER)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
