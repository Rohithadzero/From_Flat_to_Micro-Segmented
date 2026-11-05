"""Static sanity check of the LaTeX project (no TeX installation needed).

Checks, for main.tex and every file it \\input's (recursively):
  * balanced braces { } (escaped \\{ \\} ignored; verbatim skipped)
  * balanced \\begin{env} / \\end{env}
  * balanced \\ifmeasured / \\ifhavestatic / \\if... against \\fi
  * every \\input / \\include target exists
  * every \\cite key exists in refs.bib
  * every \\includegraphics file exists (graphicspath figures/)
  * every \\ref / \\label pair resolves, no duplicate labels
  * every macro used is either defined in the project or in a known-standard list
Also lists TODO(authors) / TODO(cite) markers.

Usage:  python paper/check_tex.py      (exit code 1 on any error)
"""
import re
import sys
from pathlib import Path

PAPER = Path(__file__).resolve().parent

STANDARD = set("""
documentclass usepackage graphicspath newcommand renewcommand providecommand DeclareRobustCommand newif begin end
input include title author and IEEEauthorblockN IEEEauthorblockA textit textbf texttt textsf emph
maketitle section subsection subsubsection label ref cite caption centering includegraphics
textwidth columnwidth footnotesize scriptsize small normalsize setlength tabcolsep toprule midrule
bottomrule cmidrule multicolumn par vspace medskip smallskip noindent fbox fboxsep fboxrule parbox
dimexpr item rightarrow times pm dagger ddagger checkmark ensuremath colorbox makebox balance
bibliographystyle bibliography IEEEoverridecommandlockouts IEEEkeywords abstract fi else textsuperscript textsubscript
textless textgreater textbackslash ldots e i g hline url href ifmeasured ifhavestatic star ifextratables extratablestrue extratablesfalse
havestatictrue havestaticfalse measuredtrue measuredfalse IEEEPARstart thanks appendices noindent mathrm text
""".split())

errors, warnings, todos = [], [], []


def strip_comments(text):
    out = []
    for ln in text.splitlines():
        m = re.search(r"(?<!\\)%", ln)
        out.append(ln[:m.start()] if m else ln)
    return "\n".join(out)


def drop_verbatim(text):
    return re.sub(r"\\begin\{verbatim\}.*?\\end\{verbatim\}", r"\\begin{verbatim}\\end{verbatim}", text, flags=re.S)


def collect(path, seen):
    if path in seen:
        return
    seen.append(path)
    raw = path.read_text(encoding="utf-8")
    for i, ln in enumerate(raw.splitlines(), 1):
        if "TODO(" in ln:
            todos.append(f"{path.relative_to(PAPER)}:{i}: {ln.strip()}")
        # prose accidentally swallowed by a comment (e.g. after an edit)
        cm = re.search(r"(?<!\\)%(.*)$", ln)
        if cm and re.search(r"\\(cite|cfg|ref|emph|textbf)\{", cm.group(1)):
            warnings.append(f"{path.relative_to(PAPER)}:{i}: LaTeX command inside a comment; "
                            "is this prose that should be visible?")
    body = drop_verbatim(strip_comments(raw))
    for m in re.finditer(r"\\(?:input|include)\{([^}]+)\}", body):
        tgt = PAPER / m.group(1)
        if tgt.suffix != ".tex":
            tgt = tgt.with_suffix(".tex")
        if not tgt.exists():
            errors.append(f"{path.name}: \\input target missing: {m.group(1)}")
        else:
            collect(tgt, seen)


def main():
    files = []
    collect(PAPER / "main.tex", files)
    bib = (PAPER / "refs.bib").read_text(encoding="utf-8")
    keys = set(re.findall(r"@\w+\s*\{\s*([^,\s]+)\s*,", bib))
    dup_keys = [k for k in keys if len(re.findall(r"@\w+\s*\{\s*" + re.escape(k) + r"\s*,", bib)) > 1]
    for k in dup_keys:
        errors.append(f"refs.bib: duplicate key {k}")

    labels, refs, defined, used = {}, [], set(), {}
    cites = set()
    nums = (PAPER / "tables" / "numbers.tex")
    false_flags = re.findall(r"\\have([a-z]+)false", nums.read_text(encoding="utf-8")) if nums.exists() else []
    for f in files:
        rel = f.relative_to(PAPER)
        text = drop_verbatim(strip_comments(f.read_text(encoding="utf-8")))
        # braces
        depth = 0
        for ch_i, ch in enumerate(re.sub(r"\\[{}%$&#_]", "", text)):
            depth += ch == "{"
            depth -= ch == "}"
            if depth < 0:
                errors.append(f"{rel}: unmatched '}}'")
                break
        if depth > 0:
            errors.append(f"{rel}: {depth} unclosed '{{'")
        # environments
        stack = []
        for m in re.finditer(r"\\(begin|end)\{([^}]+)\}", text):
            kind, env = m.groups()
            if kind == "begin":
                stack.append(env)
            elif not stack or stack[-1] != env:
                errors.append(f"{rel}: \\end{{{env}}} does not match {stack[-1] if stack else 'nothing'}")
                break
            else:
                stack.pop()
        if stack:
            errors.append(f"{rel}: unclosed environments {stack}")
        # conditionals
        n_if = len(re.findall(r"(?<!\\newif)\\if(?:measured|have[a-z]+|extratables|x|num|dim)\b", text))
        n_fi = len(re.findall(r"\\fi\b", text))
        if n_if != n_fi:
            errors.append(f"{rel}: {n_if} \\if... vs {n_fi} \\fi")
        # drop \ifhaveX ... \fi branches whose switch numbers.tex sets false (TeX skips them)
        for flag in false_flags:
            text = re.sub(r"(?<!\\newif)\\ifhave" + flag + r"\b(?:(?!\\fi\b).)*?\\fi\b", "", text, flags=re.S)
        # cites
        for m in re.finditer(r"\\cite\{([^}]+)\}", text):
            for k in m.group(1).split(","):
                cites.add(k.strip())
                if k.strip() not in keys:
                    errors.append(f"{rel}: \\cite key not in refs.bib: {k.strip()}")
        # figures
        for m in re.finditer(r"\\includegraphics(?:\[[^\]]*\])?\{([^}]+)\}", text):
            if not ((PAPER / "figures" / m.group(1)).exists() or (PAPER / m.group(1)).exists()):
                errors.append(f"{rel}: figure missing: {m.group(1)}")
        for m in re.finditer(r"\\label\{([^}]+)\}", text):
            if m.group(1) in labels:
                errors.append(f"{rel}: duplicate label {m.group(1)} (also in {labels[m.group(1)]})")
            labels[m.group(1)] = rel
        refs += [(rel, m.group(1)) for m in re.finditer(r"\\ref\{([^}]+)\}", text)]
        for m in re.finditer(r"\\(?:newcommand|renewcommand|providecommand|DeclareRobustCommand)\{?\\([A-Za-z]+)", text):
            defined.add(m.group(1))
        for m in re.finditer(r"\\newif\\if([A-Za-z]+)", text):
            defined.update({"if" + m.group(1), m.group(1) + "true", m.group(1) + "false"})
        for m in re.finditer(r"\\([A-Za-z]+)", text):
            used.setdefault(m.group(1), rel)
        for bm in re.finditer(r"(?<![\\A-Za-z])'\{[A-Za-z]\}", text):
            errors.append(f"{rel}: accent without backslash near '{text[bm.start():bm.start() + 12]}'")
        if re.search(r"[^\x00-\x7f]", text):
            warnings.append(f"{rel}: contains non-ASCII characters")
    for rel, r in refs:
        if r not in labels:
            errors.append(f"{rel}: \\ref to undefined label {r}")
    unknown = sorted(m for m in used if m not in defined and m not in STANDARD)
    for m in unknown:
        warnings.append(f"macro \\{m} (first used in {used[m]}) is not defined in the project; "
                        "check it is provided by a loaded package")
    uncited = sorted(keys - cites)
    # bibliography: entry brace balance, required fields, raw '&' outside url/doi
    for m in re.finditer(r"@(\w+)\s*\{\s*([^,\s]+)\s*,", bib):
        start, depth, j = m.start(), 0, bib.index("{", m.start())
        while j < len(bib):
            depth += bib[j] == "{"
            depth -= bib[j] == "}"
            if depth == 0:
                break
            j += 1
        if depth != 0:
            errors.append(f"refs.bib: entry {m.group(2)} has unbalanced braces")
            continue
        entry = bib[start:j + 1]
        if m.group(2) in cites:
            needed = ("title",) if m.group(1).lower() in ("misc", "manual", "online") else ("title", "year")
            for fld in needed:
                if not re.search(rf"\b{fld}\s*=", entry, re.I):
                    errors.append(f"refs.bib: cited entry {m.group(2)} has no {fld}")
            if not re.search(r"\b(author|organization|key)\s*=", entry, re.I):
                warnings.append(f"refs.bib: cited entry {m.group(2)} has no author/organization/key")
        no_url = re.sub(r"\b(url|doi)\s*=\s*\{[^}]*\}", "", entry, flags=re.I)
        if re.search(r"(?<!\\)&", no_url):
            errors.append(f"refs.bib: entry {m.group(2)} has an unescaped '&'")

    print(f"check_tex: {len(files)} .tex files, {len(keys)} bib entries, {len(cites)} cited, "
          f"{len(labels)} labels, {len(refs)} refs")
    for e in errors:
        print("  ERROR  ", e)
    for w in warnings:
        print("  warn   ", w)
    if uncited:
        print("  note    bib entries not cited (IEEEtran lists only cited ones):", ", ".join(uncited))
    print(f"  {len(todos)} TODO markers (run with --todos to list)")
    if "--todos" in sys.argv:
        for t in todos:
            print("   ", t)
    print("check_tex:", "FAILED" if errors else "OK")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
