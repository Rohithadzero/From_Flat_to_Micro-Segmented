"""Draw the logical topology of the final design (D3) for the report.
Output: report/figures/topology.png
Replace it with a Packet Tracer screenshot if your evaluator prefers
(keep this one as the 'logical diagram').
Usage: python tools/draw_topology.py
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "report" / "figures" / "topology.png"

INK, INK2, LINE, SURFACE = "#0b0b0b", "#52514e", "#898781", "#ffffff"
ZONE = {  # fill, edge
    "net":   ("#e8eef7", "#2a78d6"),
    "fw":    ("#fde8e8", "#d03b3b"),
    "srv":   ("#e6f4ea", "#008300"),
    "staff": ("#e8f0fb", "#2a78d6"),
    "mon":   ("#fdeee6", "#eb6834"),
    "inf":   ("#fbe9f0", "#d55181"),
    "bldg":  ("#fff4d6", "#c98500"),
    "guest": ("#efedfb", "#6250d6"),
    "mgmt":  ("#eeeeec", "#52514e"),
    "ext":   ("#f4f4f2", "#898781"),
}

plt.rcParams.update({"font.family": ["Segoe UI", "DejaVu Sans", "sans-serif"]})
fig, ax = plt.subplots(figsize=(16, 10.5))
ax.set_xlim(-3, 162); ax.set_ylim(0, 105); ax.axis("off")
fig.patch.set_facecolor(SURFACE)


def box(x, y, w, h, title, sub="", zone="net", fs=9.5):
    fc, ec = ZONE[zone]
    ax.add_patch(FancyBboxPatch((x - w / 2, y - h / 2), w, h,
                                boxstyle="round,pad=0.25,rounding_size=1.2",
                                fc=fc, ec=ec, lw=1.6, zorder=3))
    ax.text(x, y + (1.2 if sub else 0), title, ha="center", va="center",
            fontsize=fs, weight="bold", color=INK, zorder=4)
    if sub:
        ax.text(x, y - 1.9, sub, ha="center", va="center", fontsize=7.6,
                color=INK2, zorder=4)


def link(p, q, label="", style="-", lw=1.4, color=LINE, lpos=0.5, dy=0.0, dx=0.0):
    ax.plot([p[0], q[0]], [p[1], q[1]], style, color=color, lw=lw, zorder=1)
    if label:
        mx = p[0] + (q[0] - p[0]) * lpos + dx
        my = p[1] + (q[1] - p[1]) * lpos + dy
        ax.text(mx, my, label, fontsize=7, color=INK2, ha="center", va="center",
                bbox=dict(fc=SURFACE, ec="none", pad=0.6), zorder=2)


# ---- WAN / Internet ----
box(14, 96, 22, 7, "INTERNET-WEB", "203.0.113.10", "ext")
box(14, 82, 20, 7, "ISP-RTR (2911)", "G0/0 198.51.100.1/30", "ext")
box(50, 82, 26, 7.5, "EDGE-RTR (Cisco 2911)", "PAT  |  OSPF  |  default route", "net")
link((14, 92.5), (14, 85.5), "203.0.113.0/24")
link((24, 82), (37, 82), "198.51.100.0/30", lpos=0.5, dy=1.8)

# ---- Core ----
box(50, 64, 32, 8, "CORE-MLS (Catalyst 3560)", "Inter-VLAN routing (SVIs) | ACLs | DHCP relay | OSPF", "net")
link((50, 78.2), (50, 68), "10.10.255.0/30  (OSPF area 0)", dx=0)

# ---- Firewall + servers ----
box(93, 64, 24, 8, "ASA-SRV (ASA 5506-X)", "outside sec 0  |  inside sec 100", "fw")
link((66, 64), (81, 64), "10.10.254.0/30", dy=1.8)
box(120, 64, 18, 7, "SW-SRV (2960)", "server switch", "srv")
link((105, 64), (111, 64), "", )
ax.text(108, 67.5, "VLAN 20\n10.10.20.0/24", fontsize=7, color=INK2, ha="center")
servers = [("EHR-SRV", ".10  HTTP/HTTPS"), ("DNS-DHCP-SRV", ".11  DNS, DHCP"),
           ("IOT-REG-SRV", ".12  IoT registration"), ("SYSLOG-NTP-SRV", ".13  Syslog, NTP")]
for i, (n, s) in enumerate(servers):
    y = 76 - i * 8
    box(149, y, 21, 6.2, n, s, "srv", fs=8.5)
    link((129, 64), (138.5, y))
ax.text(118, 55, "Clinical-server zone\n(behind the firewall in D3)", ha="center",
        fontsize=8, color="#008300", style="italic")

# ---- Access switches ----
acc = [(22, "SW-WARD-A (2960)", "mgmt 10.10.99.11"), (62, "SW-WARD-B (2960)", "mgmt 10.10.99.12"),
       (110, "SW-ADMIN (2960)", "mgmt 10.10.99.13")]
for x, n, s in acc:
    box(x, 44, 24, 7, n, s, "net")
    link((50, 60), (x, 47.5), "802.1Q trunk", lpos=0.62)

# ---- End devices ----
def dev(x, y, name, sub, zone, sw_x):
    box(x, y, 17, 7, name, sub, zone, fs=8.2)
    link((sw_x, 40.5), (x, y + 3.5), color="#b9b8b0", lw=1.1)


dev(8, 27, "Nurse-PC-A", "VLAN 10 Staff", "staff", 22)
dev(26, 27, "Monitor-A1", "VLAN 31 Monitors", "mon", 22)
dev(8, 15, "Pump-A1", "VLAN 32 Infusion", "inf", 22)
dev(26, 15, "IOT-COMPROMISED", "test node, VLAN 31", "mon", 22)

dev(52, 27, "Nurse-PC-B", "VLAN 10 Staff", "staff", 62)
dev(70, 27, "Monitor-B1", "VLAN 31 Monitors", "mon", 62)
dev(61, 15, "Pump-B1", "VLAN 32 Infusion", "inf", 62)

dev(88, 27, "Reception-PC", "VLAN 10 Staff", "staff", 110)
dev(106, 27, "NetAdmin-PC", "VLAN 99 Mgmt", "mgmt", 110)
dev(124, 27, "Building IoT x4", "VLAN 40: door, fire,\nfan, webcam", "bldg", 110)
dev(142, 27, "Guest-AP", "VLAN 50 Guest", "guest", 110)
box(142, 13, 22, 7, "Guest-Phone / Tablet", "WPA2 SSID HOSP-GUEST", "guest", fs=8.2)
ax.plot([142, 142], [23.5, 16.5], ":", color="#6250d6", lw=1.6)

# ---- Legend ----
items = [("staff", "VLAN 10 Staff 10.10.10.0/24"), ("srv", "VLAN 20 Servers 10.10.20.0/24"),
         ("mon", "VLAN 31 Patient monitors 10.10.31.0/24"),
         ("inf", "VLAN 32 Infusion pumps 10.10.32.0/24"),
         ("bldg", "VLAN 40 Building IoT 10.10.40.0/24"), ("guest", "VLAN 50 Guest Wi-Fi 10.10.50.0/24"),
         ("mgmt", "VLAN 99 Management 10.10.99.0/24"), ("fw", "Firewall (added in D3)")]
lx, ly = 42, 102
for i, (z, t) in enumerate(items):
    cx = lx + (i % 2) * 44
    cy = ly - (i // 2) * 3.6
    fc, ec = ZONE[z]
    ax.add_patch(FancyBboxPatch((cx, cy - 1.1), 3, 2.2, boxstyle="round,pad=0.1",
                                fc=fc, ec=ec, lw=1.3))
    ax.text(cx + 4.2, cy, t, va="center", fontsize=8, color=INK)

ax.text(1, 3.5, "Logical topology of the final design D3. In D1/D2 the ASA is absent "
        "and SW-SRV connects straight to CORE-MLS (VLAN 20); medical IoT is one VLAN 30. "
        "In D0 every device is in VLAN 1 (10.10.0.0/17).",
        fontsize=8.5, color=INK2)

fig.tight_layout()
OUT.parent.mkdir(parents=True, exist_ok=True)
fig.savefig(OUT, dpi=180, facecolor=SURFACE)
print("written", OUT)
