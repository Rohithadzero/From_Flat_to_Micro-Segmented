"""Redraw the result figures for the paper into paper/figures/ (nothing outside paper/ is written).

Reuses the plotting functions of tools/make_graphs.py (same style), with its
output folder redirected to paper/figures. Observed values are used only when
every attack row has one; otherwise the expected values are plotted and every
chart carries the "EXPECTED (design analysis) - not measured" stamp.
topology.png is copied from report/figures by build.ps1 (it is not data-driven).

Usage:  python paper/make_figures.py
"""
import sys
from pathlib import Path

PAPER = Path(__file__).resolve().parent
ROOT = PAPER.parent


def main():
    sys.path.insert(0, str(ROOT / "tools"))
    import make_graphs as mg              # project code; FIG is redirected before any call
    mg.FIG = PAPER / "figures"
    mg.FIG.mkdir(exist_ok=True)
    rows = mg.read("attack-matrix.csv")
    measured = bool(rows) and all(r["observed"].strip() for r in rows)
    col, expected = ("observed", False) if measured else ("expected", True)
    mg.complexity()
    m = mg.heatmap(col, expected)
    mg.surface(expected)
    mg.tradeoff(m, expected)
    print(f"make_figures: wrote complexity/attack-heatmap/attack-surface/tradeoff to paper/figures "
          f"({'observed' if measured else 'EXPECTED, stamped'})")


if __name__ == "__main__":
    main()
