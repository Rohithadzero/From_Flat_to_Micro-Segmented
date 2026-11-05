"""Merge research/papers/refs.bib into paper/refs.bib (re-runnable).

paper/refs.bib keeps its hand-verified standards/vendor section at the top.
Everything between the BEGIN/END markers below is regenerated from
research/papers/refs.bib on each run, so new verified papers flow in
automatically. Entries whose key already exists in the top section are
skipped.

Sanitising (so pdflatex + BibTeX on Overleaf do not fail):
  * unescaped & in non-URL fields  -> \\&
  * typographic dashes/quotes      -> TeX ligatures
  * characters outside what LaTeX's utf8 + T1 setup supports -> ASCII
Every change is reported.

Usage:  python paper/merge_refs.py
"""
import re
import sys
from pathlib import Path

PAPER = Path(__file__).resolve().parent
SRC = PAPER.parent / "research" / "papers" / "refs.bib"
DST = PAPER / "refs.bib"
BEGIN = "% ==== BEGIN merged from research/papers/refs.bib (auto, do not edit here) ===="
END = "% ==== END merged from research/papers/refs.bib ===="

REPLACE = {
    "–": "--", "—": "---", "‘": "`", "’": "'", "“": "``", "”": "''",
    " ": "~", "‐": "-", "‑": "-", "−": "-",
    "ẗ": "t",      # t with diaeresis (transliteration), unsupported by utf8.def
    "ʻ": "'",      # modifier letter turned comma (ayn)
    "ʼ": "'",
    "ʾ": "'", "ʿ": "'",
}
# Latin-1 + Latin Extended-A are handled by inputenc utf8 with T1 fontenc.
SAFE = lambda ch: ord(ch) < 0x17F


def split_entries(text):
    """Yield (key, entry_text) for each @type{key, ...} with brace matching."""
    i = 0
    while True:
        m = re.compile(r"@(\w+)\s*\{\s*([^,\s]+)\s*,").search(text, i)
        if not m:
            return
        depth, j = 0, text.index("{", m.start())
        while j < len(text):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        yield m.group(2), m.group(1).lower(), text[m.start():j + 1]
        i = j + 1


def sanitise(key, entry, report):
    # HTML entities leaked from publisher metadata
    for ent, ch in (("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'), ("&#39;", "'")):
        if ent in entry:
            report.append(f"{key}: HTML entity {ent} decoded")
            entry = entry.replace(ent, ch)

    # month=July / month=Aug -> BibTeX month macro (jul, aug)
    def fix_month(m):
        mon = m.group(1)[:3].lower()
        if mon in ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"):
            if m.group(1) != mon:
                report.append(f"{key}: month={m.group(1)} -> {mon}")
            return f"month={mon}"
        return m.group(0)
    entry = re.sub(r"\bmonth\s*=\s*([A-Za-z]+)\b", fix_month, entry)

    # escape & outside url/doi fields
    def fix_field(m):
        name, val = m.group(1), m.group(2)
        if name.lower() in ("url", "doi"):
            return m.group(0)
        new = re.sub(r"(?<!\\)&", r"\\&", val)
        if new != val:
            report.append(f"{key}: escaped & in {name}")
        return f"{name}={{{new}}}"
    entry = re.sub(r"(\b[A-Za-z]+)\s*=\s*\{((?:[^{}]|\{[^{}]*\})*)\}", fix_field, entry)
    for a, b in REPLACE.items():
        if a in entry:
            report.append(f"{key}: U+{ord(a):04X} -> {b!r}")
            entry = entry.replace(a, b)
    bad = sorted({c for c in entry if not SAFE(c)})
    for c in bad:
        report.append(f"{key}: unsupported U+{ord(c):04X} {c!r} -> '?' (fix by hand)")
        entry = entry.replace(c, "?")
    return entry


def main():
    dst = DST.read_text(encoding="utf-8")
    if BEGIN in dst:
        dst = dst[:dst.index(BEGIN)].rstrip() + "\n"
    if not SRC.exists():
        DST.write_text(dst, encoding="utf-8")
        print("merge_refs: research/papers/refs.bib not found; kept the standards section only")
        return
    own = {k for k, _, _ in split_entries(dst)}
    src = SRC.read_text(encoding="utf-8-sig")
    report, blocks, skipped = [], [], []
    for key, typ, entry in split_entries(src):
        if key in own:
            skipped.append(key)
            continue
        if typ == "inbook" and "booktitle" in entry and "chapter" not in entry and "pages" not in entry:
            report.append(f"{key}: @inbook without chapter/pages (IEEEtran may warn)")
        blocks.append(sanitise(key, entry, report))
        own.add(key)
    merged = (dst.rstrip() + "\n\n" + BEGIN + "\n% Source: research/papers/refs.bib; summaries in research/papers/INDEX.md\n\n"
              + "\n\n".join(blocks) + "\n\n" + END + "\n")
    DST.write_text(merged, encoding="utf-8")
    print(f"merge_refs: merged {len(blocks)} entries"
          + (f", skipped {len(skipped)} duplicate keys ({', '.join(skipped)})" if skipped else ""))
    for r in report:
        print("  ", r)


if __name__ == "__main__":
    sys.exit(main())
