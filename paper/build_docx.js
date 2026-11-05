// build_docx.js -- paper/build/paper.json (from tex2json.py) -> paper/paper.docx
//
//   python paper/tex2json.py && node paper/build_docx.js     (build.ps1 runs both)
//
// IEEE conference layout: US Letter, two 3.5" columns, Times New Roman 10 pt,
// roman-numbered small-caps section heads, "TABLE I" captions above tables,
// "Fig. 1." captions below figures, booktabs-style rules, 8 pt references.
// The document is generated: edit the LaTeX source and rebuild, never the .docx.
"use strict";
const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, ImageRun, Table, TableRow, TableCell,
  AlignmentType, HeadingLevel, WidthType, ShadingType, BorderStyle, SectionType,
  TableLayoutType, VerticalAlign, LevelFormat, ExternalHyperlink,
} = require("docx");

const PAPER = __dirname;
const SRC = path.join(PAPER, "build", "paper.json");
const OUT = path.join(PAPER, "paper.docx");

const FONT = "Times New Roman";
const MONO = "Courier New";
const PAGE = { width: 12240, height: 15840 };                      // US Letter (DXA)
const MARGIN = { top: 1080, bottom: 1440, left: 900, right: 900 };  // IEEE conference template
const TEXT_W = PAGE.width - MARGIN.left - MARGIN.right;            // 10440 = 7.25"
const GAP = 360;                                                    // 0.25" between columns
const COL_W = (TEXT_W - GAP) / 2;                                   // 5040 = 3.5"
const PX_PER_DXA = 96 / 1440;

const doc = JSON.parse(fs.readFileSync(SRC, "utf8"));

// ---------------------------------------------------------------- runs
// JSON run: {t, b, i, m, sc, sub, sup, fill, url} or {br: true}
function textRuns(runs, base = {}) {
  const out = [];
  for (const r of runs || []) {
    if (r.br) { out.push(new TextRun({ break: 1, font: FONT, size: base.size })); continue; }
    const o = {
      text: r.t, font: r.m || r.url ? MONO : FONT, size: base.size,
      bold: !!(r.b || base.bold), italics: !!(r.i || base.italics),
      smallCaps: !!(r.sc || base.smallCaps),
      subScript: !!r.sub, superScript: !!r.sup,
    };
    // placeholders (template author block) are shaded yellow; docx 9.5.1 writes
    // <w:highlightCs> out of schema order, so shading is used instead of highlight
    if (base.mark) o.shading = { type: ShadingType.CLEAR, fill: "FFFF00", color: "auto" };
    if (r.fill) o.shading = { type: ShadingType.CLEAR, fill: r.fill, color: "auto" };
    if ((r.m || r.url) && base.size) o.size = Math.max(12, base.size - 2);   // mono looks larger
    if (r.url) {
      out.push(new ExternalHyperlink({ link: r.t, children: [new TextRun(o)] }));
    } else {
      out.push(new TextRun(o));
    }
  }
  return out;
}

// split a run list at {br} markers (author blocks)
function lines(runs) {
  const out = [[]];
  for (const r of runs || []) (r.br ? out.push([]) : out[out.length - 1].push(r));
  return out.filter((l) => l.length);
}

const plain = (runs) => (runs || []).map((r) => r.t || "").join("");

// ---------------------------------------------------------------- paragraphs
const body = (runs, o = {}) => new Paragraph({
  alignment: AlignmentType.JUSTIFIED,
  indent: o.noindent ? undefined : { firstLine: 202 },             // ~1 em at 10 pt
  spacing: { after: 0, line: 240 },
  children: textRuns(runs, { size: 20 }),
});

function heading(b) {
  const level = b.level === 1 ? HeadingLevel.HEADING_1 : HeadingLevel.HEADING_2;
  let label = "";
  if (b.level === 1) label = b.appendix ? `Appendix ${b.num}: ` : (b.num ? `${b.num}. ` : "");
  else label = b.num ? `${b.num}. ` : "";
  return new Paragraph({
    heading: level,
    children: [new TextRun({ text: label }), ...textRuns(b.runs, {})],
  });
}

function caption(prefix, runs, o = {}) {
  return new Paragraph({
    alignment: o.align ?? AlignmentType.CENTER,
    keepNext: !!o.keepNext,
    spacing: { before: o.before ?? 0, after: o.after ?? 0, line: 220 },
    children: [new TextRun({ text: prefix, font: FONT, size: 16, smallCaps: !!o.sc }),
      ...textRuns(runs, { size: 16, smallCaps: !!o.sc })],
  });
}

// ---------------------------------------------------------------- tables
const NONE = { style: BorderStyle.NONE, size: 0, color: "FFFFFF" };
const rule = (w) => ({ style: BorderStyle.SINGLE, size: w, color: "000000" });
const RULE_W = { thick: 8, thin: 4 };
const ALIGN = { left: AlignmentType.LEFT, center: AlignmentType.CENTER, right: AlignmentType.RIGHT,
  justify: AlignmentType.LEFT };

// Column widths in DXA summing exactly to W. Every column first gets room for
// its longest unbreakable word; the rest goes to the columns whose text would
// still wrap, in proportion to how much more they need. p{} columns keep their
// LaTeX share of the width (but never less than their longest word).
const PAD = 100 + 20;                         // left+right cell margins + slack
function columnWidths(cols, W, pt) {
  const cw = pt * 0.5 * 20;                  // average Times glyph ~0.5 em, in DXA
  const min = cols.map((c) => c.word * cw + PAD);
  const want = cols.map((c, k) => (c.frac ? Math.max(min[k], c.frac * W) : Math.max(min[k], c.want * cw + PAD)));
  const fixed = cols.map((c) => !!c.frac);
  let w;
  const sumWant = want.reduce((a, b) => a + b, 0);
  if (sumWant <= W) {
    // everything fits on one line: share the leftover by need
    w = want.map((x) => x + (W - sumWant) * x / sumWant);
  } else {
    const base = cols.map((c, k) => (fixed[k] ? want[k] : min[k]));
    const left = W - base.reduce((a, b) => a + b, 0);
    if (left >= 0) {
      const need = cols.map((c, k) => (fixed[k] ? 0 : want[k] - min[k]));
      const tot = need.reduce((a, b) => a + b, 0) || 1;
      w = base.map((x, k) => x + left * need[k] / tot);
    } else {
      // not even the longest words fit: scale down (text will break inside words)
      const s = W / base.reduce((a, b) => a + b, 0);
      w = base.map((x) => x * s);
    }
  }
  w = w.map((x) => Math.round(x));
  w[w.length - 1] += W - w.reduce((a, b) => a + b, 0);
  return w;
}

function tableBlock(t) {
  const W = t.wide ? TEXT_W : COL_W;
  const size = (t.size || 8) * 2;
  const out = [
    caption("", [{ t: `Table ${t.num}` }], { sc: true, keepNext: true, before: 160 }),
    caption("", t.caption, { sc: false, keepNext: true, after: 80 }),
  ];
  if (t.verbatim) {
    t.verbatim.forEach((ln, k) => out.push(new Paragraph({
      keepNext: k < t.verbatim.length - 1, keepLines: true,
      spacing: { after: 0, line: 200 },
      border: k === 0 ? { top: rule(8) } : (k === t.verbatim.length - 1 ? { bottom: rule(8) } : undefined),
      children: [new TextRun({ text: ln || " ", font: MONO, size: Math.max(12, size - 2) })],
    })));
    out.push(spacer());
    return out;
  }
  const widths = columnWidths(t.cols, W, t.size || 8);
  const nrows = t.rows.length;
  const rows = t.rows.map((r, ri) => {
    let col = 0;
    const cells = r.cells.map((c) => {
      const start = col;
      col += c.span;
      const w = widths.slice(start, start + c.span).reduce((a, b) => a + b, 0);
      const inPartial = (r.partial || []).some(([a, b]) => start >= a && start + c.span - 1 <= b);
      const top = r.ruleAbove ? rule(RULE_W[r.ruleAbove]) : (inPartial ? rule(4) : NONE);
      const bottom = ri === nrows - 1 ? rule(8) : NONE;              // \bottomrule
      const align = c.align || t.cols[start].align;
      return new TableCell({
        width: { size: w, type: WidthType.DXA },
        columnSpan: c.span > 1 ? c.span : undefined,
        borders: { top, left: NONE, bottom, right: NONE },
        margins: { top: 15, bottom: 15, left: 50, right: 50 },
        verticalAlign: VerticalAlign.CENTER,
        children: [new Paragraph({
          alignment: ALIGN[align] ?? AlignmentType.LEFT,
          spacing: { after: 0, line: 220 },
          children: textRuns(c.runs, { size }),
        })],
      });
    });
    return new TableRow({ tableHeader: !!r.header, cantSplit: true, children: cells });
  });
  out.push(new Table({
    width: { size: W, type: WidthType.DXA },
    columnWidths: widths,
    layout: TableLayoutType.FIXED,
    alignment: AlignmentType.CENTER,
    borders: { top: NONE, bottom: NONE, left: NONE, right: NONE, insideHorizontal: NONE, insideVertical: NONE },
    rows,
  }));
  if (t.note) {
    out.push(new Paragraph({
      alignment: AlignmentType.JUSTIFIED, spacing: { before: 40, after: 0, line: 200 },
      children: textRuns(t.note, { size: 14 }),
    }));
  }
  out.push(spacer());
  return out;
}

const spacer = (after = 120) => new Paragraph({ spacing: { after, line: 120 }, children: [] });

// ---------------------------------------------------------------- figures
function figureBlock(f) {
  const base = f.base === "text" ? TEXT_W : COL_W;
  const avail = f.wide ? TEXT_W : COL_W;
  const wDxa = Math.min(avail, f.frac * base);
  const width = Math.round(wDxa * PX_PER_DXA);
  const height = Math.round(width * f.px[1] / f.px[0]);
  return [
    new Paragraph({
      alignment: AlignmentType.CENTER, keepNext: true, spacing: { before: 120, after: 60 },
      children: [new ImageRun({ type: "png", data: fs.readFileSync(f.file),
        transformation: { width, height },
        altText: { title: `Fig. ${f.num}`, description: plain(f.caption), name: `fig${f.num}` } })],
    }),
    caption(`Fig. ${f.num}. `, f.caption, { align: AlignmentType.JUSTIFIED, after: 160 }),
  ];
}

// ---------------------------------------------------------------- lists, box, references
function listBlock(l) {
  return l.items.map((it, k) => {
    if (!it.label && l.kind === "item") {        // plain bullet: Word numbering, not a literal glyph
      return new Paragraph({
        numbering: { reference: "bullets", level: 0 }, alignment: AlignmentType.JUSTIFIED,
        spacing: { after: 0, line: 240 }, children: textRuns(it.runs, { size: 20 }),
      });
    }
    const label = it.label ? textRuns(it.label, { size: 20 }) :
      [new TextRun({ text: `${k + 1})`, font: FONT, size: 20 })];     // IEEEtran enumerate: 1)
    return new Paragraph({
      alignment: AlignmentType.JUSTIFIED,
      indent: { left: 504, hanging: 360 },
      spacing: { after: 0, line: 240 },
      children: [...label, new TextRun({ text: "\t", size: 20 }), ...textRuns(it.runs, { size: 20 })],
    });
  });
}

// \fbox{\parbox{...}} -> one-cell bordered table (docx 9.5.1 writes paragraph
// borders as top/bottom/left/right, which fails the OOXML schema order)
function boxBlock(b) {
  const bd = rule(4);
  return [new Table({
    width: { size: COL_W, type: WidthType.DXA }, columnWidths: [COL_W], layout: TableLayoutType.FIXED,
    rows: [new TableRow({ cantSplit: true, children: [new TableCell({
      width: { size: COL_W, type: WidthType.DXA },
      borders: { top: bd, left: bd, bottom: bd, right: bd },
      margins: { top: 40, bottom: 40, left: 80, right: 80 },
      children: [new Paragraph({ alignment: AlignmentType.JUSTIFIED, spacing: { after: 0, line: 220 },
        children: textRuns(b.runs, { size: (b.size || 8) * 2 }) })],
    })] })],
  }), spacer()];
}

function referencesBlock() {
  const out = [new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun("References")] })];
  for (const r of doc.references) {
    out.push(new Paragraph({
      alignment: AlignmentType.LEFT,
      indent: { left: 360, hanging: 360 },
      spacing: { after: 30, line: 200 },
      children: [new TextRun({ text: `[${r.num}]\t`, font: FONT, size: 16 }), ...textRuns(r.runs, { size: 16 })],
    }));
  }
  return out;
}

// ---------------------------------------------------------------- front matter
function frontMatter() {
  const out = [new Paragraph({
    alignment: AlignmentType.CENTER, spacing: { after: 240, line: 240 },
    children: textRuns(doc.title, { size: 48 }),
  })];
  const n = doc.authors.length || 1;
  const w = Math.floor(TEXT_W / n);
  const widths = doc.authors.map((_, k) => (k === n - 1 ? TEXT_W - w * (n - 1) : w));
  const cells = doc.authors.map((a, k) => new TableCell({
    width: { size: widths[k], type: WidthType.DXA },
    borders: { top: NONE, bottom: NONE, left: NONE, right: NONE },
    margins: { top: 0, bottom: 0, left: 60, right: 60 },
    children: [
      new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 20 },
        children: textRuns(a.name, { size: 22, mark: a.placeholder }) }),
      ...lines(a.affil).map((ln) => new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 0 },
        children: textRuns(ln, { size: 20, mark: a.placeholder }) })),
    ],
  }));
  out.push(new Table({
    width: { size: TEXT_W, type: WidthType.DXA }, columnWidths: widths, layout: TableLayoutType.FIXED,
    borders: { top: NONE, bottom: NONE, left: NONE, right: NONE, insideHorizontal: NONE, insideVertical: NONE },
    rows: [new TableRow({ children: cells })],
  }));
  out.push(spacer(240));
  return out;
}

function abstractBlocks() {
  const out = [new Paragraph({
    alignment: AlignmentType.JUSTIFIED, spacing: { after: 120, line: 220 },
    children: [new TextRun({ text: "Abstract—", font: FONT, size: 18, bold: true, italics: true }),
      ...textRuns(doc.abstract, { size: 18, bold: true })],
  })];
  if (doc.keywords) {
    out.push(new Paragraph({
      alignment: AlignmentType.JUSTIFIED, spacing: { after: 160, line: 220 },
      children: [new TextRun({ text: "Index Terms—", font: FONT, size: 18, bold: true, italics: true }),
        ...textRuns(doc.keywords, { size: 18, bold: true })],
    }));
  }
  return out;
}

// ---------------------------------------------------------------- sections
// Word cannot float a full-width figure across two columns, so a wide float gets
// its own one-column continuous section between two-column sections.
const props = (columns) => ({
  type: SectionType.CONTINUOUS,
  page: { size: PAGE, margin: MARGIN },
  column: columns === 2 ? { count: 2, space: GAP, equalWidth: true } : { count: 1 },
});

const sections = [{ properties: { ...props(1), type: SectionType.NEXT_PAGE }, children: frontMatter() }];
let cur = { properties: props(2), children: abstractBlocks() };
for (const b of doc.blocks) {
  let kids;
  switch (b.type) {
    case "heading": kids = [heading(b)]; break;
    case "para": kids = [body(b.runs, b)]; break;
    case "list": kids = listBlock(b); break;
    case "box": kids = boxBlock(b); break;
    case "table": kids = tableBlock(b); break;
    case "figure": kids = figureBlock(b); break;
    case "verbatim": kids = b.lines.map((ln) => new Paragraph({ spacing: { after: 0 },
      children: [new TextRun({ text: ln || " ", font: MONO, size: 16 })] })); break;
    case "references": kids = referencesBlock(); break;
    default: throw new Error(`unknown block type ${b.type}`);
  }
  if (b.wide) {
    sections.push(cur);
    sections.push({ properties: props(1), children: kids });
    cur = { properties: props(2), children: [] };
  } else {
    cur.children.push(...kids);
  }
}
sections.push(cur);

const heading1 = {
  run: { font: FONT, size: 20, smallCaps: true, bold: false, italics: false, color: "000000" },
  paragraph: { alignment: AlignmentType.CENTER, spacing: { before: 200, after: 80 }, keepNext: true, keepLines: true },
};
const heading2 = {
  run: { font: FONT, size: 20, italics: true, bold: false, color: "000000" },
  paragraph: { alignment: AlignmentType.LEFT, spacing: { before: 120, after: 60 }, keepNext: true, keepLines: true },
};

const document = new Document({
  creator: "tex2json.py + build_docx.js",
  title: plain(doc.title),
  description: "Generated from the LaTeX source in paper/ - edit the .tex files and rebuild, not this file. " +
    (doc.switches && !doc.switches.measured ? `Data status: ${doc.status}` : ""),
  styles: {
    default: {
      document: { run: { font: FONT, size: 20 }, paragraph: { spacing: { after: 0 } } },
      heading1: { ...heading1, paragraph: { ...heading1.paragraph, alignment: AlignmentType.CENTER } },
      heading2,
    },
  },
  numbering: { config: [{ reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•",
    alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 504, hanging: 360 } } } }] }] },
  sections,
});

Packer.toBuffer(document).then((buf) => {
  fs.writeFileSync(OUT, buf);
  const t = doc.blocks.filter((b) => b.type === "table").length;
  const f = doc.blocks.filter((b) => b.type === "figure").length;
  console.log(`build_docx: wrote ${path.relative(path.dirname(PAPER), OUT)} ` +
    `(${sections.length} sections, ${t} tables, ${f} figures, ${doc.references.length} references)`);
}).catch((e) => { console.error("build_docx: " + e.stack); process.exit(1); });
