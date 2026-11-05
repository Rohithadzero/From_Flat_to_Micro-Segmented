"""Measure the configuration complexity of each design (D0-D3).

Reads every configs/<design>/*.txt file and counts, per design:
  * config_lines  - real commands (blank lines, '!' comments and the
                    enable / configure terminal / end / write memory
                    wrappers are not counted)
  * aces          - access-control entries (permit/deny lines in any ACL)
  * features      - how many distinct security features are switched on

Writes results/config-complexity.csv and prints a Markdown table.
Usage:  python tools/config_stats.py
"""
import csv
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DESIGNS = ["D0-flat", "D1-vlan", "D2-zone-acl", "D3-microseg"]
WRAPPERS = {"enable", "configure terminal", "end", "write memory"}

# feature name -> regex that proves the feature is configured
FEATURES = {
    "VLAN segmentation":          r"^vlan (?!1$)\d+",
    "Inter-VLAN ACLs":            r"ip access-group \S+ in",
    "Stateful firewall (ASA)":    r"^\s*nameif ",
    "Port security":              r"switchport port-security$",
    "DHCP snooping":              r"^ip dhcp snooping$",
    "SSH-only management":        r"transport input ssh",
    "VTY source restriction":     r"access-class \d+ in",
    "BPDU Guard / PortFast":      r"spanning-tree bpduguard enable",
    "Native-VLAN hardening":      r"switchport trunk native vlan",
    "Trunk allowed-VLAN pruning": r"switchport trunk allowed vlan",
    "Unused ports disabled":      r"name BLACKHOLE",
    "Password encryption":        r"service password-encryption",
}

ACE_RE = re.compile(
    r"^\s*(permit|deny)\s"                      # inside a named ACL
    r"|^access-list \d+ (permit|deny)\s"        # numbered IOS ACL
    r"|^access-list \S+ extended (permit|deny)\s"  # ASA ACL
)


def real_commands(text):
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("!") or s in WRAPPERS:
            continue
        yield line


def main():
    rows = []
    for design in DESIGNS:
        files = sorted((ROOT / "configs" / design).glob("*.txt"))
        lines = aces = 0
        found = set()
        for f in files:
            cmds = list(real_commands(f.read_text(encoding="utf-8")))
            lines += len(cmds)
            aces += sum(1 for c in cmds if ACE_RE.search(c))
            for name, pat in FEATURES.items():
                if any(re.search(pat, c.strip()) for c in cmds):
                    found.add(name)
        rows.append({
            "design": design.split("-")[0],
            "devices_configured": len(files),
            "config_lines": lines,
            "aces": aces,
            "security_features": len(found),
            "feature_list": "; ".join(n for n in FEATURES if n in found),
        })

    out = ROOT / "results" / "config-complexity.csv"
    out.parent.mkdir(exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)

    print("| Design | Devices | Config lines | ACEs | Security features |")
    print("|---|---|---|---|---|")
    for r in rows:
        print(f"| {r['design']} | {r['devices_configured']} | {r['config_lines']} "
              f"| {r['aces']} | {r['security_features']} |")
    print(f"\nWritten: {out}")


if __name__ == "__main__":
    main()
