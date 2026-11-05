/* Ward Containment Lab - dashboard logic (vanilla JS, talks to the ptlab backend). */
"use strict";

const DESIGNS = ["D0", "D1", "D2", "D3"];
const LOCS = ["L1-WardA-MedIoT", "L2-WardB-MedIoT", "L3-BuildingIoT"];
const LOC_LABEL = { "L1-WardA-MedIoT": "Ward A monitor jack", "L2-WardB-MedIoT": "Ward B monitor jack",
  "L3-BuildingIoT": "Building IoT jack" };
const ZONES = [
  { id: "staff", name: "Staff", color: "var(--z-staff)", hosts: ["Nurse-PC-A", "Nurse-PC-B", "Reception-PC"] },
  { id: "mgmt", name: "Management", color: "var(--z-mgmt)", hosts: ["NetAdmin-PC"] },
  { id: "srv", name: "Clinical servers", color: "var(--z-srv)", hosts: ["EHR-SRV", "DNS-DHCP-SRV", "IOT-REG-SRV", "SYSLOG-NTP-SRV"] },
  { id: "med", name: "Medical IoT", color: "var(--z-mon)", hosts: ["Monitor-A1", "Monitor-B1", "Pump-A1", "Pump-B1"] },
  { id: "bldg", name: "Building IoT", color: "var(--z-bldg)", hosts: ["Smart-Door", "Fire-Monitor", "HVAC-Fan", "Webcam"] },
  { id: "guest", name: "Guest Wi-Fi", color: "var(--z-guest)", hosts: ["Guest-Phone", "Guest-Tablet"] },
  { id: "net", name: "Network devices", color: "var(--z-net)", hosts: ["CORE-MLS", "EDGE-RTR", "SW-WARD-A", "SW-WARD-B", "SW-ADMIN"] },
];
const VLAN = {
  D0: { staff: "VLAN 1", mgmt: "VLAN 1", srv: "VLAN 1", med: "VLAN 1", bldg: "VLAN 1", guest: "VLAN 1", net: "" },
  D1: { staff: "VLAN 10", mgmt: "VLAN 99", srv: "VLAN 20", med: "VLAN 30", bldg: "VLAN 40", guest: "VLAN 50", net: "" },
};
VLAN.D2 = VLAN.D1;
VLAN.D3 = { ...VLAN.D1, srv: "behind ASA", med: "VLAN 31 / 32" };
const ALL = ZONES.flatMap(z => z.hosts);

// Expected reachability from the design analysis (README section 7).
function expectedHosts(d, loc) {
  const l3 = loc.startsWith("L3");
  if (d === "D0" || d === "D1") return ALL;
  if (d === "D2") return [...ZONES[2].hosts, ...(l3 ? ZONES[4].hosts : ZONES[3].hosts)];
  return l3 ? ZONES[4].hosts : ["Monitor-A1", "Monitor-B1"];
}

const state = { design: "D3", loc: LOCS[0], source: "expected", data: null, project: null, analysis: null };
const $ = s => document.querySelector(s);
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v; else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v); else n.setAttribute(k, v);
  }
  kids.flat().forEach(k => k != null && n.append(k));
  return n;
};
async function api(path, opts = {}) {
  const r = await fetch(path, { headers: { "content-type": "application/json" }, ...opts });
  return r.json();
}
const post = (path, body) => api(path, { method: "POST", body: JSON.stringify(body || {}) });

/* ---------------------------------------------------------------- tabs */
document.querySelectorAll(".tabs button").forEach(b => b.addEventListener("click", () => {
  document.querySelectorAll(".tabs button").forEach(x => x.setAttribute("aria-selected", x === b));
  document.querySelectorAll(".tab").forEach(t => { t.hidden = t.id !== "tab-" + b.dataset.tab; });
  if (b.dataset.tab === "configs") loadConfig();
}));

/* ------------------------------------------------------------ corridor */
function buildCorridor() {
  const c = $("#corridor");
  c.replaceChildren(...DESIGNS.map(d => {
    const p = state.project?.designs?.[d] || {};
    return el("button", { role: "radio", "aria-checked": d === state.design, onclick: () => { state.design = d; render(); } },
      el("span", { class: "d", text: d }), el("span", { class: "n", text: (p.name || d).replace(/^D\d\s/, "") }),
      el("span", { class: "t", text: lineCount(d) ? `${lineCount(d)} config lines` : "" }));
  }));
}
const lineCount = d => state.data?.complexity?.find(r => r.design === d)?.config_lines;

/* ----------------------------------------------------------------- map */
function parseList(s) { return String(s || "").split(/[;,|]/).map(x => x.trim()).filter(Boolean); }
function norm(n) { return n.replace(/\s*\(.*\)$/, "").trim(); }

function hostsFor(source, d, loc) {
  if (source === "expected") return { list: expectedHosts(d, loc), known: true };
  if (source === "static") {
    const row = (state.data?.static_surface || []).find(r => r.design === d && r.location === loc);
    if (!row) return { list: [], known: false, why: "Policy analyzer has not produced results yet." };
    return { list: parseList(row.host_list).map(norm), known: true };
  }
  const obs = (state.data?.observed_hosts || []).filter(r => r.design === d && r.location === loc)
    .sort((a, b) => b.trial - a.trial);
  if (!obs.length) return { list: [], known: false, why: "No Packet Tracer run recorded for this design and location yet." };
  return { list: obs[0].hosts.map(norm), known: true, trial: obs[0].trial, evidence: obs[0].evidence };
}

function renderMap() {
  const { design: d, loc, source } = state;
  const h = hostsFor(source, d, loc);
  const reach = new Set(h.list);
  const nodeZone = loc.startsWith("L3") ? "bldg" : "med";
  $("#map").replaceChildren(...ZONES.map(z => el("div", { class: "zone", style: `--zc:${z.color}` },
    el("h3", {}, z.name, el("small", { text: VLAN[d][z.id] || "" })),
    ...(z.id === nodeZone ? [el("div", { class: "host self", text: "IOT-COMPROMISED (test node)" })] : []),
    ...z.hosts.map(n => el("div", { class: "host" + (!h.known ? " unknown" : reach.has(n) ? " reach" : ""),
      text: n === "CORE-MLS" ? "CORE-MLS (own gateway)" : n,
      title: !h.known ? "not measured" : reach.has(n) ? "answers the compromised device" : "contained" })))));
  const m = matrixFor(source);
  const blocked = Object.values(m).filter(r => r[d] === "B").length;
  const measured = Object.values(m).filter(r => r[d]).length;
  $("#r-hosts").textContent = h.known ? reach.size : "-";
  $("#r-blocked").textContent = measured ? blocked : "-";
  $("#r-lines").textContent = lineCount(d) ?? "-";
  $("#design-summary").textContent = state.project?.designs?.[d]?.summary || "";
  const note = source === "expected" ? "Expected values from the design analysis, not measurements."
    : !h.known ? h.why : source === "observed" ? `Observed in Packet Tracer, trial ${h.trial}. Evidence: ${h.evidence}`
    : "Computed by tools/policy_analyzer.py from the configuration files.";
  $("#map-note").textContent = note;
}
function matrixFor(source) { return state.data?.matrix?.[source] || {}; }

/* ------------------------------------------------------------- results */
function renderResults() {
  const D = state.data;
  if (!D) return;
  const names = D.attack_names;
  const ids = Object.keys(names).sort();
  const titles = { expected: "Design analysis (expected)", static: "Policy analyzer (computed)", observed: "Packet Tracer (observed)" };
  $("#matrices").replaceChildren(...["expected", "static", "observed"].map(src => {
    const m = D.matrix[src] || {};
    const g = el("div", { class: "grid", role: "table", "aria-label": titles[src] },
      el("div", { class: "h", text: "" }), ...DESIGNS.map(d => el("div", { class: "h", text: d })));
    ids.forEach(a => {
      g.append(el("div", { class: "rl", text: `${a} ${names[a]}` }));
      DESIGNS.forEach(d => { const v = m[a]?.[d]; g.append(el("div", { class: "cell " + (v || "N"), text: v || "-" })); });
    });
    return el("div", { class: "matrix" }, el("h3", { text: titles[src] }), g);
  }));

  // attack surface: mean % hosts per design for each source
  const mean = xs => xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null;
  const surf = src => DESIGNS.map(d => {
    let rows;
    if (src === "static") rows = (D.static_surface || []).filter(r => r.design === d).map(r => +r.hosts_reachable_of_23);
    else rows = (D.surface || []).filter(r => r.design === d && String(r[src + "_hosts_of_23"]).trim() !== "")
      .map(r => +r[src + "_hosts_of_23"]);
    const v = mean(rows.filter(x => !Number.isNaN(x)));
    return v == null ? null : v / 23 * 100;
  });
  const series = [["expected", "ghost"], ["static", "alt"], ["observed", ""]].map(([s, c]) => [s, c, surf(s)]);
  $("#surface").replaceChildren(...DESIGNS.map((d, i) => el("div", { class: "barrow" },
    el("span", { text: state.project?.designs?.[d]?.name || d }),
    el("div", { class: "track" }, ...series.map(([s, c, vals]) => vals[i] == null
      ? el("div", { class: "b ghost", style: "width:auto;opacity:.5", text: `${s}: not measured` })
      : el("div", { class: "b " + c, style: `width:${Math.max(vals[i], 4)}%`, text: `${s} ${vals[i].toFixed(0)}%` }))))));

  // functional
  const fn = D.functional || [];
  const tests = [...new Set(fn.map(r => r.test_id))];
  const t = el("table", {}, el("thead", {}, el("tr", {}, el("th", { text: "Check" }),
    ...DESIGNS.map(d => el("th", { class: "c", text: d })))));
  const tb = el("tbody");
  tests.forEach(id => {
    const r0 = fn.find(r => r.test_id === id);
    tb.append(el("tr", {}, el("td", { text: `${id} ${r0.test_name}` }), ...DESIGNS.map(d => {
      const r = fn.find(x => x.test_id === id && x.design === d) || {};
      const v = (r.observed || "").trim();
      return el("td", { class: "c", title: r.notes || "" }, v ? el("span", { class: "tag " + v, text: v })
        : el("span", { class: "sub", text: `expect ${r.expected || "-"}` }));
    })));
  });
  t.append(tb);
  $("#functional").replaceChildren(t);

  const cx = D.complexity || [];
  const maxL = Math.max(...cx.map(r => r.config_lines)), maxA = Math.max(...cx.map(r => r.aces));
  $("#complexity").replaceChildren(...cx.map(r => el("div", { class: "barrow" },
    el("span", { text: state.project?.designs?.[r.design]?.name || r.design }),
    el("div", { class: "track" },
      el("div", { class: "b", style: `width:${r.config_lines / maxL * 100}%`, text: `${r.config_lines} lines` }),
      el("div", { class: "b alt", style: `width:${Math.max(r.aces / maxA * 100, 4)}%`, text: `${r.aces} ACL entries` }),
      el("div", { class: "sub", style: "margin:0", text: r.features.length ? `${r.features.length} security features: ${r.features.join(", ")}` : "No security features" })))));
  const s = D.summary;
  $("#progress").textContent = `Observed so far: attack matrix ${s.attack_matrix.observed}/${s.attack_matrix.rows} rows, ` +
    `attack surface ${s.attack_surface.observed}/${s.attack_surface.rows}, functional ${s.functional.observed}/${s.functional.rows}.`;
}

/* ------------------------------------------------------------- configs */
let cfgCache = {};
async function loadConfig() {
  const d = $("#cfg-design").value;
  cfgCache[d] = cfgCache[d] || await api(`/api/configs/${d}`);
  const devSel = $("#cfg-device");
  const cur = devSel.value;
  devSel.replaceChildren(...Object.keys(cfgCache[d]).map(n => el("option", { text: n })));
  if (cur && cfgCache[d][cur]) devSel.value = cur;
  const dev = devSel.value;
  const view = $("#cfg-view");
  const idx = DESIGNS.indexOf(d);
  if ($("#cfg-diff").checked && idx > 0) {
    const r = await api(`/api/diff?a=${DESIGNS[idx - 1]}&b=${d}&device=${encodeURIComponent(dev)}`);
    view.replaceChildren(...(r.diff.length ? r.diff : ["No changes."]).map(l =>
      el("span", { class: l.startsWith("+") ? "add" : l.startsWith("-") ? "del" : "cm", text: l + "\n" })));
  } else {
    view.replaceChildren(...cfgCache[d][dev].split("\n").map(l =>
      el("span", { class: l.trim().startsWith("!") ? "cm" : "", text: l + "\n" })));
  }
}
["#cfg-design", "#cfg-device", "#cfg-diff"].forEach(s => $(s).addEventListener("change", loadConfig));

/* ---------------------------------------------------------------- live */
function chips(target, items, checked, name) {
  $(target).replaceChildren(...items.map(([v, label]) => el("label", {},
    Object.assign(el("input", { type: "checkbox", value: v, name }), { checked: checked.includes(v) }), label)));
}
const picked = name => [...document.querySelectorAll(`input[name=${name}]:checked`)].map(i => i.value);

$("#run-form").addEventListener("submit", async e => {
  e.preventDefault();
  const r = await post("/api/live/run", { designs: picked("rd"), tests: picked("rt"), locations: picked("rl"),
    trials: +$("#run-trials").value, open_file: $("#run-open").checked, prepare: $("#run-prep").checked,
    save: $("#run-save").checked });
  $("#log").textContent = r.ok ? "Run started." : (r.error || JSON.stringify(r));
  pollJob();
});
$("#prep-only").addEventListener("click", async () => {
  const r = await post("/api/live/prepare", { designs: picked("rd"), open_file: $("#run-open").checked, save: $("#run-save").checked });
  $("#log").textContent = r.ok ? "Checklist started." : (r.error || JSON.stringify(r));
  pollJob();
});
$("#stop-run").addEventListener("click", () => post("/api/live/stop"));

$("#quick").addEventListener("submit", async e => {
  e.preventDefault();
  const kind = $("#q-kind").value, dev = $("#q-dev").value.trim(), cmd = $("#q-cmd").value.trim();
  const args = { deviceName: dev };
  if (kind === "pcCommand" || kind === "iosExec") args.command = cmd;
  if (kind === "httpGet") args.url = cmd;
  $("#q-out").textContent = "Running...";
  const r = await post(`/api/pt/tool/${kind}`, args);
  const out = r.result?.output ?? r.result?.content;
  $("#q-out").textContent = r.success ? (out != null ? out : JSON.stringify(r.result, null, 1)) : `Failed: ${r.error}`;
});

let jobTimer = null;
async function pollJob() {
  clearTimeout(jobTimer);
  const j = await api("/api/live/status");
  const pill = $("#job-pill");
  if (j.state === "running") { pill.className = "pill run"; pill.textContent = `Running: ${j.label} (${j.observations} cells)`; }
  else if (j.state === "idle") { pill.className = "pill quiet"; pill.textContent = "No test running"; }
  else { pill.className = "pill quiet"; pill.textContent = `Last run ${j.state}: ${j.observations} cells written`; }
  if (j.log?.length) { const L = $("#log"); L.textContent = j.log.join("\n"); L.scrollTop = L.scrollHeight; }
  if (j.state === "running") jobTimer = setTimeout(pollJob, 2000);
  else if (j.state === "done" || j.state === "stopped") refreshData();
}

async function pollPT() {
  try {
    const s = await api("/api/pt/status");
    const p = $("#pt-pill");
    p.className = "pill " + (s.connected ? "on" : "off");
    p.textContent = s.connected ? "Packet Tracer connected" : "Packet Tracer offline";
    $("#calls").replaceChildren(...s.history.slice(0, 25).map(h =>
      el("li", { text: `${new Date(h.t * 1000).toLocaleTimeString()} ${h.tool} ${h.ms} ms` })));
    if (s.job === "running" && !jobTimer) pollJob();
  } catch { $("#pt-pill").className = "pill off"; $("#pt-pill").textContent = "Server unreachable"; }
  setTimeout(pollPT, 4000);
}

/* -------------------------------------------------------------- checks */
$("#pytest").addEventListener("click", async () => {
  $("#pytest-out").textContent = "Running...";
  const r = await post("/api/tests/pytest");
  $("#pytest-out").textContent = (r.passed != null ? `${r.passed} passed, ${r.failed} failed\n\n` : "") + r.output;
});
$("#manual").addEventListener("submit", async e => {
  e.preventDefault();
  const csv = $("#m-csv").value;
  const match = { test_id: $("#m-test").value.trim(), design: $("#m-design").value };
  if (csv === "attack-matrix") { match.location = $("#m-loc").value.trim(); match.trial = $("#m-trial").value.trim(); }
  const r = await post("/api/observe", { csv, match, updates: { observed: $("#m-val").value, notes: $("#m-note").value } });
  $("#m-res").textContent = r.error ? r.error : r.changed ? `Saved to ${r.changed} row(s).` : "No row matched. Check test, design, location and trial.";
  refreshData();
});

/* ---------------------------------------------------------------- init */
function render() { buildCorridor(); renderMap(); renderResults(); }
async function refreshData() { state.data = await api("/api/results"); render(); }

async function init() {
  state.project = await api("/api/project");
  $("#map-loc").replaceChildren(...LOCS.map(l => el("option", { value: l, text: LOC_LABEL[l] })));
  $("#map-loc").addEventListener("change", e => { state.loc = e.target.value; renderMap(); });
  $("#map-source").addEventListener("change", e => { state.source = e.target.value; renderMap(); });
  ["#cfg-design", "#m-design"].forEach(s => $(s).replaceChildren(...DESIGNS.map(d => el("option", { text: d }))));
  $("#cfg-design").value = "D3";
  chips("#run-designs", DESIGNS.map(d => [d, d]), ["D3"], "rd");
  chips("#run-tests", ["A1", "A2", "A3", "A4", "A5", "A6", "A7"].map(a => [a, a]).concat([
    ["F", "F1-F9"], ["A8", "A8 rogue switch"], ["Q1", "Q1 auto-quarantine"], ["O1", "O1 overhead"],
    ["PE", "Protected-port probe"]]),
    ["A1", "A2", "A3", "A4", "A5", "A6", "A7", "F", "A8", "Q1", "O1"], "rt");
  chips("#run-locs", LOCS.map(l => [l, LOC_LABEL[l]]), LOCS, "rl");
  await refreshData();
  pollPT();
  pollJob();
}
init();
