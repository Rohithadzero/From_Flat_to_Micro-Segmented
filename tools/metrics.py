"""Derived security metrics borrowed from the literature (see research/GAP-ANALYSIS.md).

  ASR   attack-surface reduction, 1 - reachable/total            (Odule et al. 2026)
  BR_w  criticality-weighted blast radius, sum(w reachable)/sum(w) (Odule 2026 blast radius,
        weighted by asset criticality - weights below are OUR assumption, state them in the paper)
  ABR   attack block rate = blocked attempts / all attempts       (Mughaid et al. 2026)
  PCR   policy-compliance rate = (blocked unauthorised + passed authorised) / all checks (Mughaid 2026)
  DET   detection coverage = attack windows with a deny-counter increase / windows
  Fisher's exact test (two-sided) on blocked vs not-blocked attempts between adjacent designs.

Uses observed values when present; otherwise falls back to the expected values and marks the
row source=expected so it can never be mistaken for a measurement.

Usage: python tools/metrics.py            -> results/metrics.csv + Markdown table
"""
from __future__ import annotations

import csv
import json
from math import comb
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "results"
DESIGNS = ["D0", "D1", "D2", "D3"]

WEIGHT = {  # asset criticality (1 low .. 5 critical) - our assumption
    "EHR-SRV": 5, "DNS-DHCP-SRV": 3, "IOT-REG-SRV": 3, "SYSLOG-NTP-SRV": 2,
    "CORE-MLS": 4, "EDGE-RTR": 4, "SW-WARD-A": 4, "SW-WARD-B": 4, "SW-ADMIN": 4, "NetAdmin-PC": 4,
    "Monitor-A1": 4, "Monitor-B1": 4, "Pump-A1": 5, "Pump-B1": 5,
    "Nurse-PC-A": 2, "Nurse-PC-B": 2, "Reception-PC": 2,
    "Smart-Door": 3, "Fire-Monitor": 3, "HVAC-Fan": 2, "Webcam": 2, "Guest-Phone": 1, "Guest-Tablet": 1,
}
SERVERS = ["EHR-SRV", "DNS-DHCP-SRV", "IOT-REG-SRV", "SYSLOG-NTP-SRV"]
MED = ["Monitor-A1", "Monitor-B1", "Pump-A1", "Pump-B1"]
BLDG = ["Smart-Door", "Fire-Monitor", "HVAC-Fan", "Webcam"]


def expected_hosts(d: str, loc: str) -> list[str]:
    l3 = loc.startswith("L3")
    if d in ("D0", "D1"):
        return list(WEIGHT)
    if d == "D2":
        return SERVERS + (BLDG if l3 else MED)
    return BLDG if l3 else ["Monitor-A1", "Monitor-B1"]


def read(name: str) -> list[dict]:
    p = RES / name
    if not p.exists():
        return []
    with p.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def fisher_two_sided(a: int, b: int, c: int, d: int) -> float:
    """2x2 table [[a, b], [c, d]]; exact two-sided p (sum of tables as or less likely)."""
    r1, c1, n = a + b, a + c, a + b + c + d

    def p(x):
        return comb(c1, x) * comb(n - c1, r1 - x) / comb(n, r1)

    p0 = p(a)
    lo, hi = max(0, r1 + c1 - n), min(r1, c1)
    return min(1.0, sum(p(x) for x in range(lo, hi + 1) if p(x) <= p0 * (1 + 1e-9)))


def main() -> None:
    am = read("attack-matrix.csv")
    obs_any = any(r["observed"].strip() for r in am)
    col = "observed" if obs_any else "expected"
    hosts_obs = json.loads((RES / "observed-hosts.json").read_text(encoding="utf-8")) \
        if (RES / "observed-hosts.json").exists() else []
    det = read("detection.csv")
    fn = read("functional.csv")
    locs = ["L1-WardA-MedIoT", "L2-WardB-MedIoT", "L3-BuildingIoT"]
    total_w = sum(WEIGHT.values())
    rows, counts = [], {}
    for d in DESIGNS:
        att = [r for r in am if r["design"] == d and r[col].strip()]
        blocked = sum(1 for r in att if r[col].strip().upper() == "B")
        counts[d] = (blocked, len(att) - blocked)
        reach_sets = []
        for loc in locs:
            o = [h for h in hosts_obs if h["design"] == d and h["location"] == loc]
            reach_sets.append([x.split(" (")[0] for x in o[-1]["hosts"]] if (o and obs_any) else expected_hosts(d, loc))
        asr = sum(1 - len(s) / 23 for s in reach_sets) / len(reach_sets)
        brw = sum(sum(WEIGHT.get(h, 1) for h in s) / total_w for s in reach_sets) / len(reach_sets)
        f_col = "observed" if any(r["observed"].strip() for r in fn if r["design"] == d) else "expected"
        f_rows = [r for r in fn if r["design"] == d and r[f_col].strip()]
        passed = sum(1 for r in f_rows if r[f_col].strip().upper() == "PASS")
        pcr = (blocked + passed) / (len(att) + len(f_rows)) if (att or f_rows) else float("nan")
        dd = [r for r in det if r["design"] == d]
        detc = sum(1 for r in dd if r["detected"] == "yes") / len(dd) if dd else None
        rows.append({"design": d, "source": col, "attempts": len(att), "blocked": blocked,
                     "ABR": round(blocked / len(att), 3) if att else "", "ASR": round(asr, 3),
                     "blast_radius_weighted": round(brw, 3), "PCR": round(pcr, 3),
                     "detection_coverage": round(detc, 3) if detc is not None else "",
                     "functional_source": f_col})
    for prev, cur in zip(DESIGNS, DESIGNS[1:]):
        (a, b), (c, e) = counts[prev], counts[cur]
        p = fisher_two_sided(a, b, c, e) if (a + b and c + e) else float("nan")
        next(r for r in rows if r["design"] == cur)[f"fisher_p_vs_{prev}"] = f"{p:.3g}"
    keys = list(dict.fromkeys(k for r in rows for k in r))
    with (RES / "metrics.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)
    print(f"source of attack outcomes: {col}" + ("" if obs_any else "  (EXPECTED - not measured)"))
    print("| " + " | ".join(keys) + " |")
    print("|" + "---|" * len(keys))
    for r in rows:
        print("| " + " | ".join(str(r.get(k, "")) for k in keys) + " |")
    print(f"\nWritten: {RES / 'metrics.csv'}")


if __name__ == "__main__":
    main()
