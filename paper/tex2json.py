"""tex2json.py -- convert the paper's LaTeX source into a JSON document model.

    python paper/tex2json.py            -> paper/build/paper.json

build_docx.js turns that JSON into paper.docx (IEEE two-column layout), so the
Word version is generated from the same source, switches and numbers as the
PDF and never has to be edited by hand.

This is not a general LaTeX converter. It understands the subset this paper
uses (sections, \\if switches from tables/numbers.tex, zero-argument number
macros, booktabs tables, verbatim, figures, itemize/enumerate, \\cite, \\ref)
and fails loudly (exit 1) on anything else, so nothing is silently dropped.
Numbering follows IEEEtran: sections I, II, ...; subsections III-A; tables
I, II, ...; figures 1, 2, ...; references numbered in order of first citation.
"""
import json
import re
import struct
import sys
import unicodedata
from pathlib import Path

PAPER = Path(__file__).resolve().parent
OUT = PAPER / 'build' / 'paper.json'


class TexError(Exception):
    pass


# ---------------------------------------------------------------- source loading
def strip_comments(text):
    """Remove % comments with TeX semantics: a comment also eats the line end
    and the next line's leading blanks. Verbatim environments are kept as is."""
    out, in_verb, join = [], False, False
    for ln in text.splitlines():
        if in_verb:
            out.append(ln + '\n')
            if r'\end{verbatim}' in ln:
                in_verb = False
            continue
        if join:
            ln = ln.lstrip()
        join = False
        cut = None
        i = 0
        while i < len(ln):
            if ln[i] == '\\':
                i += 2
                continue
            if ln[i] == '%':
                cut = i
                break
            i += 1
        if cut is not None:
            out.append(ln[:cut])
            join = True
        else:
            out.append(ln.rstrip() + '\n')
        if r'\begin{verbatim}' in ln and r'\end{verbatim}' not in ln and cut is None:
            in_verb = True
    return ''.join(out)


def load(path, depth=0):
    if depth > 10:
        raise TexError(f'\\input nesting too deep at {path}')
    text = strip_comments(path.read_text(encoding='utf-8'))

    def repl(m):
        name = m.group(1).strip()
        p = PAPER / (name if name.endswith('.tex') else name + '.tex')
        if not p.exists():
            raise TexError(f'\\input{{{name}}}: {p} not found')
        return load(p, depth + 1)
    return re.sub(r'\\input\{([^}]+)\}', repl, text)


# ---------------------------------------------------------------- low-level readers
def read_group(s, i):
    """s[i] == '{'  ->  (content, index after the closing brace)."""
    if i >= len(s) or s[i] != '{':
        raise TexError(f'expected {{ at: {s[i:i + 40]!r}')
    depth, j = 0, i
    while j < len(s):
        c = s[j]
        if c == '\\':
            j += 2
            continue
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return s[i + 1:j], j + 1
        j += 1
    raise TexError(f'unbalanced braces from: {s[i:i + 60]!r}')


def read_optional(s, i):
    """Optional [..] argument at s[i] (after blanks) -> (content or None, index)."""
    j = skip_ws(s, i)
    if j < len(s) and s[j] == '[':
        depth, k = 0, j
        while k < len(s):
            if s[k] == '{':
                depth += 1
            elif s[k] == '}':
                depth -= 1
            elif s[k] == ']' and depth == 0:
                return s[j + 1:k], k + 1
            k += 1
        raise TexError(f'unclosed [ from: {s[j:j + 40]!r}')
    return None, i


def skip_ws(s, i):
    while i < len(s) and s[i] in ' \t\n':
        i += 1
    return i


def read_arg(s, i):
    """Mandatory argument: a {group} or a single token."""
    i = skip_ws(s, i)
    if i >= len(s):
        raise TexError('missing argument at end of input')
    if s[i] == '{':
        return read_group(s, i)
    if s[i] == '\\':
        m = re.match(r'\\([A-Za-z]+|.)', s[i:])
        return m.group(0), i + len(m.group(0))
    return s[i], i + 1


def split_top(s, sep):
    """Split at depth-0 occurrences of sep ('&' or '\\\\'), ignoring escaped ones."""
    parts, depth, cur, i = [], 0, [], 0
    while i < len(s):
        c = s[i]
        if c == '\\':
            if sep == '\\\\' and s.startswith('\\\\', i) and depth == 0:
                parts.append(''.join(cur))
                cur = []
                i += 2
                continue
            cur.append(s[i:i + 2])
            i += 2
            continue
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
        if c == sep and depth == 0:
            parts.append(''.join(cur))
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    parts.append(''.join(cur))
    return parts


def env_body(s, i, env):
    """i is just after \\begin{env}; return (body, index after \\end{env})."""
    if env == 'verbatim':
        k = s.find(r'\end{verbatim}', i)
        if k < 0:
            raise TexError('unclosed verbatim')
        return s[i:k], k + len(r'\end{verbatim}')
    pat = re.compile(r'\\(begin|end)\{' + re.escape(env) + r'\}')
    depth = 1
    for m in pat.finditer(s, i):
        depth += 1 if m.group(1) == 'begin' else -1
        if depth == 0:
            return s[i:m.start()], m.end()
    raise TexError(f'unclosed environment {env}')


# ---------------------------------------------------------------- macros and switches
def collect_macros(text):
    macros = {}
    for m in re.finditer(r'\\(?:providecommand|renewcommand|newcommand)\{\\([A-Za-z]+)\}\{', text):
        val, _ = read_group(text, m.end() - 1)
        macros[m.group(1)] = val        # later definitions win, as in TeX
    return macros


def collect_switches(text):
    names = set(re.findall(r'\\newif\\if([A-Za-z]+)', text))
    state = {n: False for n in names}
    for m in re.finditer(r'\\([A-Za-z]+?)(true|false)(?![A-Za-z])', text):
        if m.group(1) in names:
            state[m.group(1)] = m.group(2) == 'true'
    return state


def resolve_ifs(body, switches):
    if not switches:
        return body
    pat = re.compile(r'\\if(' + '|'.join(sorted(switches, key=len, reverse=True)) +
                     r')(?![A-Za-z])[ \t]*\n?|\\else(?![A-Za-z])[ \t]*\n?|\\fi(?![A-Za-z])[ \t]*\n?')
    out, stack, pos = [], [], 0      # stack of (cond, in_else)

    def active():
        return all((c if not e else not c) for c, e in stack)
    for m in pat.finditer(body):
        if active():
            out.append(body[pos:m.start()])
        tok = m.group(0)
        if tok.startswith('\\if'):
            stack.append((switches[m.group(1)], False))
        elif tok.startswith('\\else'):
            if not stack:
                raise TexError('\\else without \\if')
            c, _ = stack.pop()
            stack.append((c, True))
        else:
            if not stack:
                raise TexError('\\fi without \\if')
            stack.pop()
        pos = m.end()
    if stack:
        raise TexError('unterminated \\if')
    out.append(body[pos:])
    return ''.join(out)


# ---------------------------------------------------------------- block parser
SIZES = {'tiny': 5, 'scriptsize': 7, 'footnotesize': 8, 'small': 9, 'normalsize': 10}
IGNORED_BLOCK = {'medskip', 'smallskip', 'bigskip', 'balance', 'centering', 'vfill', 'clearpage', 'newpage'}


def parse_blocks(s):
    blocks, buf = [], []
    state = {'noindent': False}

    def flush():
        text = ''.join(buf).strip()
        buf.clear()
        if text:
            blocks.append({'type': 'para', 'raw': text, 'noindent': state['noindent']})
        state['noindent'] = False

    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == '\n':
            m = re.match(r'\n[ \t]*\n\s*', s[i:])
            if m:
                flush()
                i += len(m.group(0))
                continue
            buf.append(c)
            i += 1
            continue
        if c == '{':
            g, j = read_group(s, i)
            buf.append('{' + g + '}')
            i = j
            continue
        if c == '$':
            k = i + 1
            while k < n and not (s[k] == '$' and s[k - 1] != '\\'):
                k += 1
            buf.append(s[i:k + 1])
            i = k + 1
            continue
        if c != '\\':
            buf.append(c)
            i += 1
            continue
        m = re.match(r'\\([A-Za-z]+)(\*?)', s[i:])
        if not m:
            buf.append(s[i:i + 2])
            i += 2
            continue
        name, star, j = m.group(1), m.group(2), i + len(m.group(0))
        if name in ('section', 'subsection', 'subsubsection'):
            flush()
            title, j = read_arg(s, j)
            level = {'section': 1, 'subsection': 2, 'subsubsection': 3}[name]
            blocks.append({'type': 'heading', 'level': level, 'raw': title, 'numbered': not star})
            i = j
        elif name == 'label':
            key, j = read_arg(s, j)
            blocks.append({'type': 'label', 'key': key.strip()})
            i = skip_ws(s, j) if not buf else j
        elif name == 'noindent':
            if not ''.join(buf).strip():
                state['noindent'] = True
            i = j
        elif name == 'par':
            flush()
            i = j
        elif name in IGNORED_BLOCK:
            i = j
        elif name == 'maketitle':
            flush()
            blocks.append({'type': 'maketitle'})
            i = j
        elif name == 'appendices':
            flush()
            blocks.append({'type': 'appendices'})
            i = j
        elif name in ('bibliographystyle', 'title', 'author'):
            _, i = read_arg(s, j)       # title/author are read separately in build()
        elif name == 'bibliography':
            flush()
            _, i = read_arg(s, j)
            blocks.append({'type': 'bibliography'})
        elif name == 'fbox':
            flush()
            inner, i = read_arg(s, j)
            inner = inner.strip()
            size = 10
            pm = re.match(r'\\parbox(\[[^\]]*\])?\{', inner)
            if pm:
                _, k = read_group(inner, pm.end() - 1)
                inner, _ = read_group(inner, k)
            sm = re.match(r'\s*\\(tiny|scriptsize|footnotesize|small|normalsize)(?![A-Za-z])', inner)
            if sm:
                size = SIZES[sm.group(1)]
                inner = inner[sm.end():]
            blocks.append({'type': 'box', 'raw': inner.strip(), 'size': size})
        elif name == 'begin':
            env, j = read_arg(s, j)
            env = env.strip()
            if env in ('table', 'table*', 'figure', 'figure*'):
                flush()
                _, j = read_optional(s, j)
                body, i = env_body(s, j, env)
                blocks.append(parse_float(body, env))
            elif env in ('itemize', 'enumerate'):
                flush()
                body, i = env_body(s, j, env)
                blocks.append(parse_list(body, env))
            elif env in ('abstract', 'IEEEkeywords'):
                flush()
                body, i = env_body(s, j, env)
                blocks.append({'type': env.lower(), 'raw': body.strip()})
            elif env == 'verbatim':
                flush()
                body, i = env_body(s, j, env)
                blocks.append({'type': 'verbatim', 'lines': body.strip('\n').split('\n'), 'size': 8})
            else:
                raise TexError(f'unsupported environment in body: {env}')
        else:
            buf.append(m.group(0))
            i = j
    flush()
    return blocks


def parse_list(body, env):
    parts = re.split(r'\\item(?![A-Za-z])', body)
    if parts[0].strip():
        raise TexError(f'text before first \\item in {env}: {parts[0][:40]!r}')
    items = []
    for p in parts[1:]:
        label, k = read_optional(p, 0)
        items.append({'label': label, 'raw': p[k:].strip()})
    return {'type': 'list', 'kind': 'enum' if env == 'enumerate' else 'item', 'items': items}


def find_cmd(s, name):
    return re.search(r'\\' + name + r'(?![A-Za-z])', s)


def parse_colspec(spec):
    cols, i = [], 0
    while i < len(spec):
        c = spec[i]
        if c in '@!><':
            _, i = read_group(spec, i + 1)
            continue
        if c in ' |':
            i += 1
            continue
        if c in 'lcr':
            cols.append({'align': {'l': 'left', 'c': 'center', 'r': 'right'}[c], 'frac': None})
            i += 1
        elif c == 'p':
            w, i = read_group(spec, i + 1)
            fm = re.match(r'\s*([\d.]*)\s*\\(columnwidth|textwidth|linewidth)', w)
            if not fm:
                raise TexError(f'unsupported p{{}} width: {w}')
            cols.append({'align': 'left', 'frac': float(fm.group(1) or 1)})
        else:
            raise TexError(f'unsupported column spec char {c!r} in {spec!r}')
    return cols


RULE = re.compile(r'\s*\\(toprule|midrule|bottomrule|hline|cmidrule)(?![A-Za-z])(\([^)]*\))?')


def parse_tabular(spec, body):
    cols = parse_colspec(spec)
    rows, carry_rules, carry_partial = [], [], []
    for seg in split_top(body, '\\\\'):
        rules, partial = list(carry_rules), list(carry_partial)
        carry_rules, carry_partial = [], []
        while True:
            m = RULE.match(seg)
            if not m:
                break
            seg = seg[m.end():]
            if m.group(1) == 'cmidrule':
                rng, k = read_group(seg, skip_ws(seg, 0))
                seg = seg[k:]
                a, b = (int(x) for x in rng.split('-'))
                partial.append([a - 1, b - 1])
            else:
                rules.append(m.group(1))
        if not seg.strip():
            if rows and ('bottomrule' in rules):
                rows[-1]['ruleBelow'] = 'thick'
            else:                       # rule line before the next row
                carry_rules, carry_partial = rules, partial
            continue
        cells = []
        for cell in split_top(seg, '&'):
            cell = cell.strip()
            mc = re.match(r'\\multicolumn\{(\d+)\}', cell)
            if mc:
                spec_c, k = read_group(cell, mc.end())
                content, k = read_group(cell, k)
                al = parse_colspec(spec_c)
                cells.append({'raw': content, 'span': int(mc.group(1)),
                              'align': al[0]['align'] if al else 'left'})
            else:
                cells.append({'raw': cell, 'span': 1, 'align': None})
        ncells = sum(c['span'] for c in cells)
        if ncells != len(cols):
            raise TexError(f'row has {ncells} cells, spec has {len(cols)}: {cells[0]["raw"][:30]!r}')
        rows.append({'cells': cells, 'rules': rules, 'partial': partial})
    first_mid = next((k for k, r in enumerate(rows) if 'midrule' in r['rules']), None)
    for k, r in enumerate(rows):
        r['header'] = first_mid is not None and k < first_mid
        if 'toprule' in r['rules'] or ('hline' in r['rules'] and k == 0):
            r['ruleAbove'] = 'thick'
        elif 'midrule' in r['rules'] or 'hline' in r['rules']:
            r['ruleAbove'] = 'thin'
        else:
            r['ruleAbove'] = None
        r.pop('rules')
    return cols, rows


def parse_float(body, env):
    kind = 'table' if env.startswith('table') else 'figure'
    blk = {'type': kind, 'wide': env.endswith('*')}
    m = find_cmd(body, 'caption')
    if not m:
        raise TexError(f'{env} without \\caption')
    blk['caption'], _ = read_group(body, skip_ws(body, m.end()))
    m = find_cmd(body, 'label')
    blk['label'] = read_group(body, skip_ws(body, m.end()))[0].strip() if m else None
    sm = re.search(r'\\(tiny|scriptsize|footnotesize|small|normalsize)(?![A-Za-z])', body)
    blk['size'] = SIZES[sm.group(1)] if sm else 10
    if kind == 'figure':
        m = re.search(r'\\includegraphics(\[[^\]]*\])?\{([^}]+)\}', body)
        if not m:
            raise TexError('figure without \\includegraphics')
        opt = (m.group(1) or '')[1:-1]
        wm = re.search(r'width\s*=\s*([\d.]*)\s*\\(columnwidth|textwidth|linewidth)', opt)
        blk['frac'] = float(wm.group(1) or 1) if wm else 1.0
        blk['base'] = 'text' if wm and wm.group(2) == 'textwidth' else 'column'
        f = PAPER / 'figures' / m.group(2)
        if not f.exists():
            raise TexError(f'figure file missing: {f}')
        blk['file'] = str(f)
        blk['px'] = png_size(f)
        return blk
    tm = re.search(r'\\begin\{tabular\}', body)
    vm = re.search(r'\\begin\{verbatim\}', body)
    blk['note'] = None
    if tm:
        spec, k = read_group(body, tm.end())
        tbody, k2 = env_body(body, k, 'tabular')
        blk['cols'], blk['rows'] = parse_tabular(spec, tbody)
        rest = body[k2:]
        pm = re.search(r'\\parbox(\[[^\]]*\])?\{', rest)
        if pm:
            _, k = read_group(rest, pm.end() - 1)
            note, _ = read_group(rest, k)
            note = re.sub(r'^\s*\\(tiny|scriptsize|footnotesize|small|normalsize)(?![A-Za-z])', '', note)
            blk['note'] = note.strip()
    elif vm:
        vbody, _ = env_body(body, vm.end(), 'verbatim')
        blk['verbatim'] = vbody.strip('\n').split('\n')
    else:
        raise TexError(f'table without tabular or verbatim: {blk["caption"][:40]!r}')
    return blk


def png_size(path):
    with open(path, 'rb') as fh:
        head = fh.read(24)
    if head[:8] != b'\x89PNG\r\n\x1a\n':
        raise TexError(f'not a PNG: {path}')
    w, h = struct.unpack('>II', head[16:24])
    return [w, h]


# ---------------------------------------------------------------- inline parser
ACCENTS = {"'": '\u0301', '`': '\u0300', '"': '\u0308', '^': '\u0302', '~': '\u0303', '=': '\u0304',
           '.': '\u0307', 'c': '\u0327', 'v': '\u030C', 'u': '\u0306', 'H': '\u030B'}
SYMBOLS = {'cmark': '\u2713', 'checkmark': '\u2713', 'xmark': '\u00D7', 'times': '\u00D7',
           'rightarrow': '\u2192', 'to': '\u2192', 'leftarrow': '\u2190', 'pm': '\u00B1',
           'ldots': '\u2026', 'dots': '\u2026', 'cdot': '\u00B7', 'approx': '\u2248',
           'le': '\u2264', 'leq': '\u2264', 'ge': '\u2265', 'geq': '\u2265', 'textless': '<',
           'textgreater': '>', 'textbackslash': '\\', 'dagger': '\u2020', 'ddagger': '\u2021',
           'S': '\u00A7', 'quad': '\u2003', 'qquad': '\u2003\u2003', 'i': '\u0131', 'ss': '\u00DF',
           'textendash': '\u2013', 'textemdash': '\u2014', 'alpha': '\u03B1', 'beta': '\u03B2',
           'mu': '\u03BC', 'Delta': '\u0394', 'infty': '\u221E', 'neq': '\u2260'}
IGNORED_INLINE = {'noindent', 'par', 'centering', 'tiny', 'scriptsize', 'footnotesize', 'small',
                  'normalsize', 'medskip', 'smallskip', 'bigskip', 'hfill', 'null', 'relax',
                  'protect', 'balance', 'displaystyle'}
# xcolor mixes from main.tex: red!30, yellow!45, green!25 over white
OUTCOME = {'oS': ('S', 'FFB3B3'), 'oP': ('P', 'FFFF8C'), 'oB': ('B', 'BFFFBF')}
STYLE_KEYS = ('b', 'i', 'm', 'sc', 'sub', 'sup', 'fill', 'url')


class Inline:
    def __init__(self, macros, switches, labels, citenum):
        self.macros, self.switches, self.labels, self.citenum = macros, switches, labels, citenum
        self.depth = 0

    def runs(self, s, st=None):
        out = []
        self._parse(s, dict(st or {}), out, math=False)
        return merge(out)

    @staticmethod
    def _emit(out, text, st):
        if text:
            out.append(dict({k: v for k, v in st.items() if v and k != 'upright'}, t=text))

    def _parse(self, s, st, out, math):
        self.depth += 1
        if self.depth > 50:
            raise TexError('macro expansion too deep (recursive macro?)')
        try:
            self._parse_inner(s, st, out, math)
        finally:
            self.depth -= 1

    def _parse_inner(self, s, st, out, math):
        i, n = 0, len(s)
        prev = False                    # math: previous token was an operand
        while i < n:
            c = s[i]
            if c == '\\':
                m = re.match(r'\\([A-Za-z]+)', s[i:])
                if m:
                    j = i + len(m.group(0))
                    if not math:
                        j = skip_ws(s, j)   # TeX drops blanks after a control word
                    i = self._command(m.group(1), s, j, st, out, math)
                    prev = True
                    continue
                sym = s[i + 1] if i + 1 < n else ''
                i += 2
                if sym in ' \n\t':
                    self._emit(out, ' ', st)
                elif sym == ',':
                    self._emit(out, '\u2009', st)
                elif sym in ';:':
                    self._emit(out, ' ', st)
                elif sym in '!-/@':
                    pass
                elif sym in '%&_#${}':
                    self._emit(out, sym, st)
                elif sym == '\\':
                    _, i = read_optional(s, i)
                    out.append({'br': True})
                    i = skip_ws(s, i)
                elif sym in ACCENTS:
                    base, i = read_arg(s, i)
                    self._emit(out, self._accent(sym, base), st)
                else:
                    raise TexError(f'unknown control symbol \\{sym}')
                continue
            if c == '{':
                g, i = read_group(s, i)
                self._parse(g, dict(st), out, math)
                continue
            if c == '}':
                raise TexError(f'unbalanced }} in: {s[:60]!r}')
            if c == '$':
                if math:
                    raise TexError('nested $')
                k = i + 1
                while k < n and not (s[k] == '$' and s[k - 1] != '\\'):
                    k += 1
                if k >= n:
                    raise TexError(f'unclosed $ in: {s[i:i + 40]!r}')
                self._parse(s[i + 1:k], dict(st), out, math=True)
                i = k + 1
                continue
            if c == '~':
                self._emit(out, '\u00A0', st)
                i += 1
                continue
            if math:
                i, prev = self._math_char(s, i, st, out, prev)
                continue
            if c in ' \t\n':
                self._emit(out, ' ', st)
                i = skip_ws(s, i)
                continue
            if c == '-':
                k = i
                while k < n and s[k] == '-' and k - i < 3:
                    k += 1
                self._emit(out, {1: '-', 2: '\u2013', 3: '\u2014'}[k - i], st)
                i = k
                continue
            if c in '`\'':
                dbl = s.startswith(c * 2, i)
                self._emit(out, ('\u201C' if dbl else '\u2018') if c == '`' else ('\u201D' if dbl else '\u2019'), st)
                i += 2 if dbl else 1
                continue
            if c in '&#^_':
                raise TexError(f'unexpected {c!r} in text: {s[max(0, i - 30):i + 30]!r}')
            self._emit(out, c, st)
            i += 1

    def _math_char(self, s, i, st, out, prev):
        c = s[i]
        if c in ' \t\n':
            return i + 1, prev
        if c in '_^':
            arg, j = read_arg(s, i + 1)
            sub = dict(st)
            sub['sub' if c == '_' else 'sup'] = True
            self._parse(arg, sub, out, math=True)
            return j, True
        if c.isalpha():
            it = dict(st)
            if not st.get('upright'):
                it['i'] = True
            self._emit(out, c, it)
            return i + 1, True
        if c in '=<>':
            self._emit(out, f' {c} ', st)
            return i + 1, False
        if c in '+-':
            sign = '\u2212' if c == '-' else '+'
            self._emit(out, f' {sign} ' if prev else sign, st)
            return i + 1, False
        self._emit(out, c, st)
        return i + 1, True

    @staticmethod
    def _accent(acc, base):
        base = base.strip('{}')
        if base == '\\i':
            base = 'i'
        return unicodedata.normalize('NFC', base + ACCENTS[acc])

    def _command(self, name, s, j, st, out, math):
        def sub(**kw):
            d = dict(st)
            d.update(kw)
            return d
        if name == 'textbf':
            a, j = read_arg(s, j)
            self._parse(a, sub(b=True), out, math=False)
        elif name in ('textit', 'textsl'):
            a, j = read_arg(s, j)
            self._parse(a, sub(i=True), out, math=False)
        elif name == 'emph':
            a, j = read_arg(s, j)
            self._parse(a, sub(i=not st.get('i')), out, math=False)
        elif name in ('texttt', 'cfg'):
            a, j = read_arg(s, j)
            self._parse(a, sub(m=True), out, math=False)
        elif name == 'url':
            a, j = read_arg(s, j)
            self._emit(out, re.sub(r'\\([_%&#$])', r'\1', a), sub(url=True))
        elif name in ('textsuperscript', 'textsubscript'):
            a, j = read_arg(s, j)
            self._parse(a, sub(**{'sup' if name == 'textsuperscript' else 'sub': True}), out, math=False)
        elif name == 'textsc':
            a, j = read_arg(s, j)
            self._parse(a, sub(sc=True), out, math=False)
        elif name in ('textrm', 'textsf', 'textnormal', 'text', 'mbox', 'fbox', 'textup'):
            a, j = read_arg(s, j)
            self._parse(a, sub(upright=True), out, math=False)
        elif name == 'mathrm':
            a, j = read_arg(s, j)
            self._parse(a, sub(upright=True), out, math=True)
        elif name == 'makebox':
            _, j = read_optional(s, j)
            _, j = read_optional(s, j)
            a, j = read_arg(s, j)
            self._parse(a, dict(st), out, math)
        elif name == 'ensuremath':
            a, j = read_arg(s, j)
            self._parse(a, dict(st), out, math=True)
        elif name == 'cite':
            _, j = read_optional(s, j)
            a, j = read_arg(s, j)
            self._emit(out, self.cite_text(a), {k: v for k, v in st.items() if k in ('b', 'i')})
        elif name in ('ref', 'eqref'):
            a, j = read_arg(s, j)
            key = a.strip()
            if key not in self.labels:
                raise TexError(f'\\ref{{{key}}}: undefined label')
            self._emit(out, self.labels[key], {k: v for k, v in st.items() if k in ('b', 'i', 'sc')})
        elif name == 'label':
            _, j = read_arg(s, j)
        elif name in OUTCOME:
            letter, fill = OUTCOME[name]
            self._emit(out, '\u2002' + letter + '\u2002', sub(b=True, fill=fill))
        elif name in SYMBOLS:
            self._emit(out, SYMBOLS[name], {k: v for k, v in st.items() if k not in ('upright', 'i')})
        elif name in IGNORED_INLINE:
            pass
        elif name in ('vspace', 'hspace'):
            if j < len(s) and s[j] == '*':
                j += 1
            _, j = read_arg(s, j)
        elif name == 'setlength':
            _, j = read_arg(s, j)
            _, j = read_arg(s, j)
        elif name == 'parbox':
            _, j = read_optional(s, j)
            _, j = read_arg(s, j)
            a, j = read_arg(s, j)
            self._parse(a, dict(st), out, math)
        elif name == 'expnote':
            if not self.switches.get('measured'):
                self._parse('\\ \\statusNote', dict(st), out, math=False)
        elif name in ('c', 'v', 'u', 'H'):
            base, j = read_arg(s, j)
            self._emit(out, self._accent(name, base), st)
        elif name in self.macros:
            self._parse(self.macros[name], dict(st), out, math)
        else:
            raise TexError(f'unknown macro \\{name} near: {s[max(0, j - 40):j + 20]!r}')
        return j

    def cite_text(self, keys):
        nums = []
        for k in keys.split(','):
            k = k.strip()
            if k not in self.citenum:
                raise TexError(f'\\cite{{{k}}}: key not in refs.bib')
            nums.append(self.citenum[k])
        nums = sorted(set(nums))
        groups, start, prev = [], nums[0], nums[0]
        for x in nums[1:] + [None]:
            if x is not None and x == prev + 1:
                prev = x
                continue
            if start == prev:
                groups.append(f'[{start}]')
            elif prev == start + 1:
                groups.append(f'[{start}], [{prev}]')
            else:
                groups.append(f'[{start}]\u2013[{prev}]')     # cite package: compressed range
            if x is not None:
                start = prev = x
        return ', '.join(groups)


def merge(runs):
    out = []
    for r in runs:
        if out and not r.get('br') and not out[-1].get('br') and \
                all(out[-1].get(k) == r.get(k) for k in STYLE_KEYS):
            out[-1]['t'] += r['t']
        else:
            out.append(r)
    for r in out:
        if 't' in r and not r.get('fill'):
            r['t'] = re.sub(r' {2,}', ' ', r['t'])
    return out


def strip_runs(runs):
    """Trim blanks at both ends of a run list."""
    def blank(r):
        return not r.get('br') and not r.get('fill') and r.get('t', '').strip() == ''
    while runs and blank(runs[0]):
        runs.pop(0)
    while runs and blank(runs[-1]):
        runs.pop()
    if runs and 't' in runs[0] and not runs[0].get('fill'):
        runs[0]['t'] = runs[0]['t'].lstrip()
    if runs and 't' in runs[-1] and not runs[-1].get('fill'):
        runs[-1]['t'] = runs[-1]['t'].rstrip()
    return runs


def plain(runs):
    return ''.join(r.get('t', ' ') for r in runs)


# ---------------------------------------------------------------- bibliography
MONTHS = {'jan': 'Jan.', 'feb': 'Feb.', 'mar': 'Mar.', 'apr': 'Apr.', 'may': 'May', 'jun': 'Jun.',
          'jul': 'Jul.', 'aug': 'Aug.', 'sep': 'Sep.', 'oct': 'Oct.', 'nov': 'Nov.', 'dec': 'Dec.'}


def parse_bib(text):
    entries = {}
    for m in re.finditer(r'^@(\w+)\s*\{\s*([^,\s]+)\s*,', text, re.M):
        typ = m.group(1).lower()
        if typ in ('comment', 'string', 'preamble'):
            continue
        key, i, fields = m.group(2), m.end(), {}
        while True:
            i = skip_ws(text, i)
            if i < len(text) and text[i] == ',':
                i += 1
                continue
            if i >= len(text) or text[i] == '}':
                break
            fm = re.match(r'([A-Za-z_-]+)\s*=\s*', text[i:])
            if not fm:
                raise TexError(f'bib {key}: cannot parse field at {text[i:i + 30]!r}')
            name = fm.group(1).lower()
            i += fm.end()
            if text[i] == '{':
                val, i = read_group(text, i)
            elif text[i] == '"':
                k = text.index('"', i + 1)
                val, i = text[i + 1:k], k + 1
            else:
                vm = re.match(r'[A-Za-z0-9.+-]+', text[i:])
                if not vm:
                    raise TexError(f'bib {key}: bad value for {name}')
                val, i = vm.group(0), i + vm.end()
            fields[name] = ' '.join(val.split())
        entries[key] = {**fields, '_type': typ}   # a 'type' field (techreport) must not clobber the entry type
    return entries


def split_names(s):
    parts, depth, cur, i = [], 0, '', 0
    while i < len(s):
        if s[i] == '{':
            depth += 1
        elif s[i] == '}':
            depth -= 1
        m = re.match(r'\s+and\s+', s[i:]) if depth == 0 else None
        if m:
            parts.append(cur)
            cur = ''
            i += m.end()
            continue
        cur += s[i]
        i += 1
    parts.append(cur)
    return [p.strip() for p in parts if p.strip()]


def format_name(n):
    """'Last, First' or 'First von Last' -> 'F. von Last' (IEEEtran style)."""
    if n.startswith('{') and n.endswith('}'):
        return n                                   # corporate author, kept literally
    if ',' in n:
        last, first = (x.strip() for x in n.split(',', 1))
    else:
        toks = n.split()
        if len(toks) == 1:
            return n
        k = len(toks) - 1
        while k > 1 and toks[k - 1][:1].islower():
            k -= 1
        first, last = ' '.join(toks[:k]), ' '.join(toks[k:])
    inits = []
    for tok in re.split(r'\s+|(?<=\.)(?=\w)', first):
        sub = [t for t in tok.split('-') if t]
        if sub:
            inits.append('-'.join(t[0] + '.' for t in sub))
    return (' '.join(inits) + ' ' + last).strip()


def format_authors(field):
    names = [format_name(n) for n in split_names(field)]
    if len(names) > 10:
        return names[0] + ' \\textit{et~al.}'
    if len(names) == 1:
        return names[0]
    if len(names) == 2:
        return names[0] + ' and ' + names[1]
    return ', '.join(names[:-1]) + ', and ' + names[-1]


def format_ref(e):
    """IEEEtran-style reference as a LaTeX string (rendered by the inline parser)."""
    who = e.get('author') or e.get('organization') or ''
    month = MONTHS.get(e.get('month', '').strip('{}').lower()[:3], e.get('month', ''))
    date = ' '.join(x for x in (month, e.get('year', '')) if x)
    pages = e.get('pages', '').replace('--', '-')
    pp = (f"pp.~{pages.replace('-', '--')}" if '-' in pages else f'p.~{pages}') if pages else ''
    typ, title = e['_type'], e.get('title', '').strip()
    head = format_authors(who) + ', ' if who else ''
    if typ == 'manual':
        parts = [head + f'\\textit{{{title}}}', date]
    else:
        q = f"``{title}''" if title[-1:] in '?!' else f"``{title},''"
        head += q
        if typ == 'article':
            parts = [head + ' \\textit{' + e.get('journal', '') + '}',
                     f"vol.~{e['volume']}" if e.get('volume') else '',
                     f"no.~{e['number']}" if e.get('number') else '', pp, date]
        elif typ in ('inproceedings', 'incollection', 'inbook', 'conference'):
            parts = [head + ' in \\textit{' + e.get('booktitle', '') + '}', e.get('publisher', ''), date, pp]
        elif typ == 'techreport':
            parts = [head + ' ' + e.get('institution', ''), e.get('address', ''),
                     ' '.join(x for x in (e.get('type', 'Tech. Rep.'), e.get('number', '')) if x), date]
        else:   # misc and anything else
            parts = [head + ' ' + (e.get('howpublished') or e.get('publisher', '')), date]
    s = ', '.join(x.strip() for x in parts if x and x.strip()) + '.'
    s = s.replace("'', ", "'' ").replace(",.", ".")
    if e.get('note'):
        s += ' ' + e['note'].rstrip('.') + '.'
    if e.get('url'):
        s += ' [Online]. Available: \\url{' + e['url'] + '}'
    elif e.get('doi'):
        s += ' doi: \\url{' + e['doi'] + '}'
    return s


# ---------------------------------------------------------------- numbering and assembly
def roman(n):
    out = ''
    for v, r in [(10, 'X'), (9, 'IX'), (5, 'V'), (4, 'IV'), (1, 'I')]:
        while n >= v:
            out += r
            n -= v
    return out


def walk_raw(blocks):
    """Every raw LaTeX string of the body in document order (gives citation order)."""
    for b in blocks:
        t = b['type']
        if t in ('para', 'heading', 'abstract', 'ieeekeywords', 'box'):
            yield b['raw']
        elif t == 'list':
            for it in b['items']:
                yield it['raw']
        elif t in ('table', 'figure'):
            yield b['caption']
            for r in b.get('rows', []):
                for c in r['cells']:
                    yield c['raw']
            if b.get('note'):
                yield b['note']


def colstats(cols, rows, to_plain):
    """Per column: longest cell text and longest unbreakable word (in characters),
    plus the fixed width fraction of p{} columns. build_docx.js turns these into
    DXA widths for the actual font size."""
    want, word = [1] * len(cols), [1] * len(cols)
    for r in rows:
        k = 0
        for c in r['cells']:
            if c['span'] == 1:
                txt = to_plain(c['raw']).strip()
                want[k] = max(want[k], len(txt))
                # Word may break at blanks and after a hyphen, en dash or slash
                word[k] = max([word[k]] + [len(w) for w in re.split(r'[\s\u00A0]+|(?<=[-\u2013/])', txt)])
            k += c['span']
    return [{'align': c['align'], 'frac': c['frac'], 'want': w, 'word': wd}
            for c, w, wd in zip(cols, want, word)]


def build():
    main_tex = load(PAPER / 'main.tex')
    if '\\begin{document}' not in main_tex:
        raise TexError('main.tex has no \\begin{document}')
    pre, rest = main_tex.split('\\begin{document}', 1)
    body = rest.split('\\end{document}', 1)[0]
    macros = collect_macros(main_tex)
    switches = collect_switches(main_tex)
    body = resolve_ifs(body, switches)

    tm, am = re.search(r'\\title\{', main_tex), re.search(r'\\author\{', main_tex)
    if not tm or not am:
        raise TexError('main.tex needs \\title{} and \\author{}')
    title_raw = read_group(main_tex, tm.end() - 1)[0]
    auth_raw = read_group(main_tex, am.end() - 1)[0]

    blocks = parse_blocks(body)

    # pass 1: numbering and labels (IEEEtran: I, II / III-A / TABLE I / Fig. 1 / Appendix A)
    labels, sec, sub, tab, fig, appendix, last = {}, 0, 0, 0, 0, False, None
    for b in blocks:
        t = b['type']
        if t == 'appendices':
            appendix, sec = True, 0
        elif t == 'heading' and b['numbered']:
            if b['level'] == 1:
                sec, sub = sec + 1, 0
                b['num'] = chr(64 + sec) if appendix else roman(sec)
                b['appendix'] = appendix
                last = b['num']
            else:
                sub += 1
                b['num'] = chr(64 + sub)
                last = f'{chr(64 + sec) if appendix else roman(sec)}-{b["num"]}'
        elif t in ('table', 'figure'):
            if t == 'table':
                tab += 1
                b['num'] = roman(tab)
            else:
                fig += 1
                b['num'] = str(fig)
            last = b['num']
            if b['label']:
                labels[b['label']] = last
        elif t == 'label':
            if last is None:
                raise TexError(f'\\label{{{b["key"]}}} before any numbered item')
            labels[b['key']] = last

    bib = parse_bib((PAPER / 'refs.bib').read_text(encoding='utf-8'))
    order = []
    for raw in walk_raw(blocks):
        for m in re.finditer(r'\\cite(?:\[[^\]]*\])?\{([^}]*)\}', raw):
            for k in m.group(1).split(','):
                k = k.strip()
                if k not in bib:
                    raise TexError(f'\\cite{{{k}}}: key not in refs.bib')
                if k not in order:
                    order.append(k)
    citenum = {k: n + 1 for n, k in enumerate(order)}

    il = Inline(macros, switches, labels, citenum)

    def R(raw):
        return strip_runs(il.runs(raw))

    def P(raw):
        return plain(il.runs(raw))

    doc = {
        'generator': 'paper/tex2json.py',
        'switches': switches,
        'status': P('\\statusNote') if 'statusNote' in macros else '',
        'title': R(title_raw),
        'authors': [],
        'abstract': None, 'keywords': None,
        'blocks': [],
        'references': [],
    }
    for part in re.split(r'\\and(?![A-Za-z])', auth_raw):
        nm = re.search(r'\\IEEEauthorblockN\{', part)
        am = re.search(r'\\IEEEauthorblockA\{', part)
        doc['authors'].append({
            'name': R(read_group(part, nm.end() - 1)[0]) if nm else [],
            'affil': R(read_group(part, am.end() - 1)[0]) if am else [],
            # the author block in main.tex is still the template (TODO(authors))
            'placeholder': bool(re.search(r'example\.(edu|com|org)|Author Name|Guide Name|Author (One|Two)|Faculty Co-Author', part)),
        })

    out = doc['blocks']
    for b in blocks:
        t = b['type']
        if t == 'abstract':
            doc['abstract'] = R(b['raw'])
        elif t == 'ieeekeywords':
            doc['keywords'] = R(b['raw'])
        elif t == 'heading':
            out.append({'type': 'heading', 'level': b['level'], 'num': b.get('num'),
                        'appendix': b.get('appendix', False), 'runs': R(b['raw'])})
        elif t == 'para':
            out.append({'type': 'para', 'noindent': b['noindent'], 'runs': R(b['raw'])})
        elif t == 'box':
            out.append({'type': 'box', 'size': b['size'], 'runs': R(b['raw'])})
        elif t == 'list':
            out.append({'type': 'list', 'kind': b['kind'],
                        'items': [{'label': R(it['label']) if it['label'] is not None else None,
                                   'runs': R(it['raw'])} for it in b['items']]})
        elif t == 'verbatim':
            out.append(b)
        elif t == 'figure':
            out.append({'type': 'figure', 'num': b['num'], 'wide': b['wide'], 'file': b['file'],
                        'px': b['px'], 'frac': b['frac'], 'base': b['base'], 'caption': R(b['caption'])})
        elif t == 'table':
            tb = {'type': 'table', 'num': b['num'], 'wide': b['wide'], 'size': b['size'],
                  'caption': R(b['caption']), 'note': R(b['note']) if b.get('note') else None}
            if 'verbatim' in b:
                tb['verbatim'] = b['verbatim']
            else:
                tb['cols'] = colstats(b['cols'], b['rows'], P)
                tb['rows'] = [{'header': r['header'], 'ruleAbove': r['ruleAbove'],
                               'ruleBelow': r.get('ruleBelow'), 'partial': r['partial'],
                               'cells': [{'span': c['span'], 'align': c['align'], 'runs': R(c['raw'])}
                                         for c in r['cells']]} for r in b['rows']]
            out.append(tb)
        elif t == 'bibliography':
            out.append({'type': 'references'})
        # label / maketitle / appendices markers carry no content of their own
    if doc['abstract'] is None:
        raise TexError('no abstract found')

    for k in order:
        doc['references'].append({'num': citenum[k], 'key': k, 'runs': R(format_ref(bib[k]))})
    return doc, {'blocks': len(out), 'tables': tab, 'figures': fig, 'refs': len(order), 'labels': len(labels)}


def main():
    try:
        doc, stats = build()
    except TexError as e:
        print(f'tex2json: ERROR: {e}', file=sys.stderr)
        return 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding='utf-8')
    print('tex2json: wrote {} ({blocks} blocks, {tables} tables, {figures} figures, '
          '{refs} references, {labels} labels)'.format(OUT.relative_to(PAPER.parent), **stats))
    return 0


if __name__ == '__main__':
    sys.exit(main())
