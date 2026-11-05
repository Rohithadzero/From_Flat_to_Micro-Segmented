"""Create blank test-log spreadsheets (CSV) with the EXPECTED outcome of
every test already filled in. While running the tests in Packet Tracer,
type what you actually saw into the `observed` column.

  results/attack-matrix.csv   7 attacks x 4 designs x location x 3 trials
  results/attack-surface.csv  reachable hosts/services from the test node
  results/functional.csv      9 legitimate-traffic checks x 4 designs

Codes: S = attack succeeded, B = blocked, P = partial (see README),
       PASS / FAIL for functional tests.
Run once:  python tools/make_test_logs.py   (it will NOT overwrite files
that already exist, so your observations are safe).
"""
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "results"
DESIGNS = ["D0", "D1", "D2", "D3"]
TRIALS = [1, 2, 3]
LOCS = ["L1-WardA-MedIoT", "L2-WardB-MedIoT", "L3-BuildingIoT"]

ATTACKS = [
    # id, name, locations, expected D0..D3
    ("A1", "Reconnaissance ping sweep", LOCS, "S S P P"),
    ("A2", "Unauthorised EHR access (HTTP)", LOCS, "S S S B"),
    ("A3", "IoT server login / cross-class device", LOCS, "S S S P"),
    ("A4", "Telnet/SSH to switch or router", LOCS, "S S B B"),
    ("A5", "Rogue DHCP server", ["SW-WARD-A Fa0/5"], "S S S B"),
    ("A6", "Unauthorised device on IoT port", ["SW-WARD-A Fa0/2"], "S S S B"),
    ("A7", "Guest Wi-Fi -> EHR pivot", ["Guest-Phone"], "S S B B"),
]

# Expected reachability from the compromised node (design analysis).
# 23 target hosts, 10 target services - see README section 7.
SURFACE = {
    "D0": {"L1": (23, 10), "L2": (23, 10), "L3": (23, 10)},
    "D1": {"L1": (23, 10), "L2": (23, 10), "L3": (23, 10)},
    "D2": {"L1": (8, 4), "L2": (8, 4), "L3": (8, 4)},
    "D3": {"L1": (2, 1), "L2": (2, 1), "L3": (4, 1)},
}

FUNCTIONAL = [
    ("F1", "Staff PC opens http://ehr.hospital.local (DNS + HTTP)"),
    ("F2", "Staff PC pings EHR-SRV"),
    ("F3", "All 8 IoT devices listed on IOT-REG-SRV dashboard"),
    ("F4", "DHCP gives every client an address in the right subnet"),
    ("F5", "Guest phone opens http://web.isp.test (Internet)"),
    ("F6", "Staff PC reaches Internet; NAT translation visible on EDGE-RTR"),
    ("F7", "NetAdmin-PC manages switches (Telnet D0-D2, SSH D3)"),
    ("F8", "IoT rule fires: smoke detected -> HVAC fan on"),
    ("F9", "SYSLOG-NTP-SRV receives log messages"),
]


def write(path, header, rows):
    if path.exists():
        print(f"skip (already exists): {path.name}")
        return
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)
    print(f"created: {path.name} ({len(rows)} rows)")


def main():
    RES.mkdir(exist_ok=True)
    rows = []
    for aid, name, locs, exp in ATTACKS:
        exp = dict(zip(DESIGNS, exp.split()))
        for d in DESIGNS:
            for loc in locs:
                for t in TRIALS:
                    rows.append([aid, name, d, loc, t, exp[d], "", ""])
    write(RES / "attack-matrix.csv",
          ["test_id", "test_name", "design", "location", "trial",
           "expected", "observed", "notes"], rows)

    rows = []
    for d in DESIGNS:
        for loc in LOCS:
            h, s = SURFACE[d][loc[:2]]
            for t in TRIALS:
                rows.append([d, loc, t, h, "", s, "", ""])
    write(RES / "attack-surface.csv",
          ["design", "location", "trial", "expected_hosts_of_23",
           "observed_hosts_of_23", "expected_services_of_10",
           "observed_services_of_10", "notes"], rows)

    rows = [[fid, name, d, "PASS", "", ""] for d in DESIGNS for fid, name in FUNCTIONAL]
    write(RES / "functional.csv",
          ["test_id", "test_name", "design", "expected", "observed", "notes"], rows)


if __name__ == "__main__":
    main()
