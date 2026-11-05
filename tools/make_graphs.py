"""Draw the result graphs for the report and the paper.

  report/figures/complexity.png      config lines + ACEs per design (from configs)
  report/figures/attack-heatmap.png  attack x design outcome matrix
  report/figures/attack-surface.png  % hosts / services reachable from the test node
  report/figures/tradeoff.png        complexity vs number of attacks fully blocked

Default: uses the `observed` columns of results/*.csv (fill them in while
testing). With --expected it plots the design-analysis predictions instead
and stamps every chart "EXPECTED - not measured" so it is never mistaken
for measured data.

Usage:  python tools/config_stats.py        (once, for complexity numbers)
        python tools/make_graphs.py            (after testing)
        python tools/make_graphs.py --expected (preview)
"""
import argparse
import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "results"
FIG = ROOT / "report" / "figures"
DESIGNS = ["D0", "D1", "D2", "D3"]
NAMES = {"D0": "D0 Flat", "D1": "D1 VLAN-only", "D2": "D2 Zone ACL", "D3": "D3 Micro-seg"}

# palette (validated reference instance, light mode)
INK, INK2, MUTED = "#0b0b0b", "#52514e", "#898781"
GRID, AXIS, SURFACE = "#e1e0d9", "#c3c2b7", "#fcfcfb"
BLUE, ORANGE = "#2a78d6", "#eb6834"
STATUS = {"S": "#d03b3b", "P": "#fab219", "B": "#0ca30c"}
STATUS_TEXT = {"S": "#ffffff", "P": "#0b0b0b", "B": "#ffffff"}
STATUS_LABEL = {"S": "Succeeded", "P": "Partial", "B": "Blocked"}

plt.rcParams.update({
    "font.family": ["Segoe UI", "DejaVu Sans", "sans-serif"],
    "font.size": 10, "text.color": INK, "axes.labelcolor": INK2,
    "axes.edgecolor": AXIS, "xtick.color": INK2, "ytick.color": INK2,
    "axes.spines.top": False, "axes.spines.right": False,
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.dpi": 200,
})


def read(name):
    with (RES / name).open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def stamp(fig, expected):
    if expected:
        fig.text(0.99, 0.01, "EXPECTED (design analysis) - not measured",
                 ha="right", va="bottom", fontsize=8, color="#d03b3b", style="italic")


def style_axis(ax):
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.tick_params(length=0)


def complexity():
    rows = read("config-complexity.csv")
    fig, axes = plt.subplots(1, 2, figsize=(8, 3.2))
    for ax, key, title in [(axes[0], "config_lines", "Configuration lines"),
                           (axes[1], "aces", "Access-control entries (ACEs)")]:
        vals = [int(r[key]) for r in rows]
        bars = ax.bar([NAMES[r["design"]] for r in rows], vals, color=BLUE, width=0.55)
        ax.bar_label(bars, padding=3, color=INK, fontsize=9)
        ax.set_title(title, loc="left", fontsize=11, color=INK)
        ax.set_ylim(0, max(vals) * 1.18)
        style_axis(ax)
        ax.tick_params(axis="x", labelsize=8.5)
    fig.suptitle("Configuration complexity per design (counted from the config files)",
                 x=0.01, ha="left", fontsize=11, color=INK2)
    fig.tight_layout()
    fig.savefig(FIG / "complexity.png")
    plt.close(fig)


def outcome_matrix(col):
    cells = defaultdict(list)
    names = {}
    for r in read("attack-matrix.csv"):
        v = r[col].strip().upper()
        if v:
            cells[(r["test_id"], r["design"])].append(v)
        names[r["test_id"]] = r["test_name"]
    # majority vote over locations and trials
    return {k: Counter(v).most_common(1)[0][0] for k, v in cells.items()}, names


def heatmap(col, expected):
    m, names = outcome_matrix(col)
    ids = sorted(names)
    fig, ax = plt.subplots(figsize=(8, 4.2))
    for i, aid in enumerate(ids):
        for j, d in enumerate(DESIGNS):
            v = m.get((aid, d), "")
            ax.add_patch(plt.Rectangle((j + 0.03, i + 0.05), 0.94, 0.9,
                                       color=STATUS.get(v, "#f0efec"), linewidth=0))
            ax.text(j + 0.5, i + 0.5, STATUS_LABEL.get(v, "-"), ha="center", va="center",
                    fontsize=9, color=STATUS_TEXT.get(v, INK2), weight="bold")
    ax.set_xlim(0, 4); ax.set_ylim(len(ids), 0)
    ax.set_xticks([j + 0.5 for j in range(4)], [NAMES[d] for d in DESIGNS])
    ax.set_yticks([i + 0.5 for i in range(len(ids))], [f"{a}  {names[a]}" for a in ids])
    ax.xaxis.tick_top()
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0)
    ax.set_title("Attack outcome by design (majority over locations x trials)",
                 loc="left", fontsize=11, pad=28)
    stamp(fig, expected)
    fig.tight_layout()
    fig.savefig(FIG / "attack-heatmap.png")
    plt.close(fig)
    return m


def surface(expected):
    hk = "expected_hosts_of_23" if expected else "observed_hosts_of_23"
    sk = "expected_services_of_10" if expected else "observed_services_of_10"
    h, s = defaultdict(list), defaultdict(list)
    for r in read("attack-surface.csv"):
        if r[hk].strip():
            h[r["design"]].append(float(r[hk]) / 23 * 100)
        if r[sk].strip():
            s[r["design"]].append(float(r[sk]) / 10 * 100)
    mean = lambda xs: sum(xs) / len(xs) if xs else 0  # noqa: E731
    fig, ax = plt.subplots(figsize=(8, 3.4))
    x = range(len(DESIGNS))
    w = 0.36
    b1 = ax.bar([i - w / 2 - 0.01 for i in x], [mean(h[d]) for d in DESIGNS], w,
                color=BLUE, label="Hosts reachable (of 23)")
    b2 = ax.bar([i + w / 2 + 0.01 for i in x], [mean(s[d]) for d in DESIGNS], w,
                color=ORANGE, label="Services reachable (of 10)")
    for b in (b1, b2):
        ax.bar_label(b, fmt="%.0f%%", padding=3, fontsize=9, color=INK)
    ax.set_xticks(list(x), [NAMES[d] for d in DESIGNS])
    ax.set_ylim(0, 115)
    ax.set_ylabel("% reachable from compromised node")
    ax.legend(frameon=False, loc="upper right", fontsize=9)
    ax.set_title("Attack surface: mean over 3 locations x 3 trials", loc="left", fontsize=11)
    style_axis(ax)
    stamp(fig, expected)
    fig.tight_layout()
    fig.savefig(FIG / "attack-surface.png")
    plt.close(fig)


def tradeoff(m, expected):
    rows = {r["design"]: int(r["config_lines"]) for r in read("config-complexity.csv")}
    blocked = {d: sum(1 for (a, dd), v in m.items() if dd == d and v == "B") for d in DESIGNS}
    fig, ax = plt.subplots(figsize=(6.5, 3.6))
    xs = [rows[d] for d in DESIGNS]
    ys = [blocked[d] for d in DESIGNS]
    ax.plot(xs, ys, color=BLUE, linewidth=2, zorder=1)
    ax.scatter(xs, ys, s=70, color=BLUE, edgecolors=SURFACE, linewidths=2, zorder=2)
    for d, xv, yv in zip(DESIGNS, xs, ys):
        ax.annotate(NAMES[d], (xv, yv), xytext=(6, 8), textcoords="offset points",
                    fontsize=9, color=INK)
    ax.set_xlabel("Total configuration lines")
    ax.set_ylabel("Attacks fully blocked (of 7)")
    ax.set_ylim(-0.5, 7.5)
    ax.set_xlim(min(xs) * 0.8, max(xs) * 1.2)
    ax.set_title("Security gained vs configuration effort", loc="left", fontsize=11)
    style_axis(ax)
    stamp(fig, expected)
    fig.tight_layout()
    fig.savefig(FIG / "tradeoff.png")
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--expected", action="store_true",
                    help="plot design-analysis predictions (stamped as not measured)")
    args = ap.parse_args()
    FIG.mkdir(parents=True, exist_ok=True)
    complexity()
    col = "expected" if args.expected else "observed"
    if not args.expected:
        missing = [r for r in read("attack-matrix.csv") if not r["observed"].strip()]
        if missing:
            print(f"{len(missing)} attack rows have no 'observed' value yet. Fill them in "
                  "results/attack-matrix.csv, or run with --expected for a preview.")
            sys.exit(1)
    m = heatmap(col, args.expected)
    surface(args.expected)
    tradeoff(m, args.expected)
    print("Figures written to", FIG)


if __name__ == "__main__":
    main()
