// Builds report/CN_MiniProject_Report.docx in the RV University
// CS2403 mini-project template layout.
//   npm install docx      (once)
//   node tools/build_report.js
// Text in yellow highlight = placeholders to fill in (names, USNs,
// screenshots, observed results).
const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, ImageRun, Table, TableRow, TableCell,
  AlignmentType, HeadingLevel, WidthType, ShadingType, BorderStyle, PageBreak,
  Footer, PageNumber, LevelFormat, VerticalAlign, TableLayoutType,
} = require("docx");

const ROOT = path.resolve(__dirname, "..");
const FIG = (f) => path.join(ROOT, "report", "figures", f);
const CFG = (d, f) => fs.readFileSync(path.join(ROOT, "configs", d, f), "utf8");
const csv = (f) => {
  const [h, ...rows] = fs.readFileSync(path.join(ROOT, "results", f), "utf8").trim().split(/\r?\n/);
  const keys = h.split(",");
  return rows.map((r) => Object.fromEntries(r.split(",").map((v, i) => [keys[i], v])));
};

const TITLE = "From Flat to Micro-Segmented: A Simulation-Based Evaluation of " +
  "Lateral-Movement Containment for Compromised IoMT Devices in a Smart-Hospital Network";
const SERIF = "Times New Roman";
const HEAD_COLOR = "1F4E5F";
const W = 9026; // A4 width minus 1" margins, in DXA

// ---------- helpers ----------
const run = (t, o = {}) => new TextRun({ text: t, font: SERIF, size: 24, ...o });
const ph = (t) => run(t, { highlight: "yellow" });
function P(content, o = {}) {
  const children = (Array.isArray(content) ? content : [content]).map((c) =>
    typeof c === "string" ? run(c) : c);
  return new Paragraph({ children, spacing: { after: 160, line: 300 },
    alignment: o.align ?? AlignmentType.JUSTIFIED, ...o });
}
const C = (t, o = {}) => P(t, { align: AlignmentType.CENTER, ...o });
const H1 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun(t)],
  spacing: { before: 240, after: 200 } });
const H2 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(t)],
  spacing: { before: 220, after: 120 } });
const H3 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_3, children: [new TextRun(t)],
  spacing: { before: 160, after: 80 } });
const bullet = (content) => new Paragraph({
  numbering: { reference: "bullets", level: 0 }, spacing: { after: 80, line: 280 },
  children: (Array.isArray(content) ? content : [content]).map((c) => typeof c === "string" ? run(c) : c),
});
const pageBreak = () => new Paragraph({ children: [new PageBreak()] });

function img(file, w, h) {
  return new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 80 },
    children: [new ImageRun({ type: "png", data: fs.readFileSync(FIG(file)),
      transformation: { width: w, height: h } })] });
}
const caption = (t) => new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 240 },
  children: [run(t, { italics: true, size: 20 })] });

const border = { style: BorderStyle.SINGLE, size: 4, color: "A6A6A6" };
const borders = { top: border, bottom: border, left: border, right: border };
function table(headers, rows, widths, o = {}) {
  const fs_ = o.size ?? 19;
  const cell = (text, i, head) => new TableCell({
    borders, width: { size: widths[i], type: WidthType.DXA },
    margins: { top: 50, bottom: 50, left: 90, right: 90 },
    verticalAlign: VerticalAlign.CENTER,
    shading: head ? { fill: "DCE6EE", type: ShadingType.CLEAR, color: "auto" } :
      (o.shade && o.shade(text, i)) ? { fill: o.shade(text, i), type: ShadingType.CLEAR, color: "auto" } : undefined,
    children: [new Paragraph({ spacing: { after: 0 },
      alignment: (o.center && i >= (o.centerFrom ?? 1)) ? AlignmentType.CENTER : AlignmentType.LEFT,
      children: [typeof text === "string" || typeof text === "number"
        ? run(String(text), { size: fs_, bold: head, highlight: (!head && String(text).startsWith("[")) ? "yellow" : undefined })
        : text] })],
  });
  return new Table({
    width: { size: widths.reduce((a, b) => a + b, 0), type: WidthType.DXA },
    columnWidths: widths, layout: TableLayoutType.FIXED,
    rows: [new TableRow({ tableHeader: true, children: headers.map((h, i) => cell(h, i, true)) }),
      ...rows.map((r) => new TableRow({ cantSplit: true, children: r.map((c, i) => cell(c, i, false)) }))],
  });
}
const tableCaption = (t) => new Paragraph({ spacing: { before: 120, after: 80 },
  children: [run(t, { bold: true, size: 20 })] });
const gap = () => new Paragraph({ spacing: { after: 120 }, children: [] });

function code(text) {
  return text.replace(/\r/g, "").split("\n").map((line, i, arr) => new Paragraph({
    spacing: { after: 0, line: 228 },
    shading: { fill: "F3F3F1", type: ShadingType.CLEAR, color: "auto" },
    border: i === 0 ? { top: { style: BorderStyle.SINGLE, size: 4, color: "BFBFBF", space: 2 } } :
      i === arr.length - 1 ? { bottom: { style: BorderStyle.SINGLE, size: 4, color: "BFBFBF", space: 2 } } : undefined,
    children: [new TextRun({ text: line || " ", font: "Consolas", size: 16,
      color: line.trim().startsWith("!") ? "2E7D32" : "1A1A1A" })],
  }));
}

function shot(n, title, how) {
  return [
    new Table({ width: { size: W, type: WidthType.DXA }, columnWidths: [W], rows: [new TableRow({
      height: { value: 2600, rule: "atLeast" },
      children: [new TableCell({ width: { size: W, type: WidthType.DXA }, verticalAlign: VerticalAlign.CENTER,
        borders: { top: { style: BorderStyle.DASHED, size: 6, color: "7F7F7F" }, bottom: { style: BorderStyle.DASHED, size: 6, color: "7F7F7F" },
          left: { style: BorderStyle.DASHED, size: 6, color: "7F7F7F" }, right: { style: BorderStyle.DASHED, size: 6, color: "7F7F7F" } },
        children: [
          new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 80 },
            children: [ph(`[Paste screenshot ${n} here]`)] }),
          new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 0 },
            children: [run("How to capture: " + how, { size: 18, italics: true, color: "595959" })] }),
        ] })] })] }),
    caption(`Figure ${n}: ${title}`),
  ];
}

// ---------- data ----------
const complexity = csv("config-complexity.csv");

// ---------- cover + certificate ----------
const logo = () => img("rvu_logo.png", 230, 125);
const cover = [
  gap(), logo(), gap(), gap(),
  C(run("CS2403 COMPUTER NETWORKS", { bold: true, size: 32 })),
  gap(),
  C(run("Mini Project Report", { bold: true, size: 30 })),
  gap(), gap(),
  C(run(TITLE, { italics: true, size: 36 }), { spacing: { after: 400, line: 360 } }),
  gap(),
  C(run("Submitted", { size: 22 }), { spacing: { after: 60 } }),
  C(run("By", { size: 22 })),
  C([ph("Student Name 1"), run(" ("), ph("USN"), run(")")].map((r) => r), { spacing: { after: 80 } }),
  C([ph("Student Name 2"), run(" ("), ph("USN"), run(")")], { spacing: { after: 80 } }),
  C([ph("Student Name 3 (optional)"), run(" ("), ph("USN"), run(")")], { spacing: { after: 300 } }),
  C(run("Under the guidance of:", { size: 24 })),
  C([run("Dr./Prof. ", { italics: true, size: 26 }), ph("Faculty Name")], { spacing: { after: 300 } }),
  C(run("School of Computer Science and Engineering", { bold: true, size: 30 }), { spacing: { after: 80 } }),
  C(run("RV University, Bangalore", { bold: true, size: 24 })),
];

const certificate = [
  gap(), logo(), gap(),
  C(run("School of Computer Science and Engineering", { bold: true, size: 32 })),
  gap(), gap(),
  C(run("CERTIFICATE", { size: 28, underline: {} }), { spacing: { after: 480 } }),
  P([run("Certified that the CS2403 Computer Networks Mini Project work titled "),
    run(`“${TITLE}”`, { italics: true }),
    run(" is carried out by "), ph("Student Name 1 (USN), Student Name 2 (USN), Student Name 3 (USN)"),
    run(", who are bonafide students of the School of Computer Science and Engineering, RV University, " +
      "Bengaluru, during the year 2025–26. It is certified that all corrections/ suggestions from all the " +
      "continuous internal evaluations have been incorporated into the project and in this report.")],
  { spacing: { line: 400, after: 200 } }),
  gap(), gap(), gap(), gap(), gap(),
  new Paragraph({ children: [run("Dr./ Prof. ________________")], spacing: { after: 200 } }),
  new Table({ width: { size: W, type: WidthType.DXA }, columnWidths: [W / 2, W / 2],
    borders: { top: { style: BorderStyle.NONE }, bottom: { style: BorderStyle.NONE }, left: { style: BorderStyle.NONE },
      right: { style: BorderStyle.NONE }, insideHorizontal: { style: BorderStyle.NONE }, insideVertical: { style: BorderStyle.NONE } },
    rows: [new TableRow({ children: [
      new TableCell({ width: { size: W / 2, type: WidthType.DXA }, borders: {}, children: [new Paragraph({ children: [run("Faculty Guide")] })] }),
      new TableCell({ width: { size: W / 2, type: WidthType.DXA }, borders: {}, children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [run("Program Director")] })] }),
    ] })] }),
];

// ---------- 1. Problem statement ----------
const s1 = [
  H1("1  Problem statement"),
  P("Hospitals now connect large numbers of medical Internet-of-Things (IoMT) devices, such as patient " +
    "monitors and infusion pumps, to the same network as staff computers, clinical servers and building " +
    "systems. These devices often run old, unpatchable firmware, so one of them can be taken over. In a " +
    "flat network the attacker can then move sideways (lateral movement) to the electronic health record " +
    "(EHR) server, to other medical devices and to the switches and routers themselves. This project builds " +
    "a smart-hospital network in Cisco Packet Tracer and measures how well four levels of network " +
    "segmentation contain a compromised medical IoT device. The four levels are a flat network (D0), " +
    "VLANs only (D1), VLANs with zone ACLs (D2) and full micro-segmentation with a stateful firewall and " +
    "Layer-2 hardening (D3). Each design is tested with the same seven attacks and nine legitimate-traffic " +
    "checks. We then compare the attack surface left open, whether clinical functions still work, and " +
    "the configuration effort each level costs."),
];

// ---------- 2. Introduction ----------
const s2 = [
  H1("2. Introduction"),
  P("A modern “smart hospital” depends on its network: nurses read patient records from the EHR, bedside " +
    "monitors stream vital signs, infusion pumps receive drug libraries, and doors, fire detectors, " +
    "ventilation and CCTV are all networked. Healthcare is one of the sectors most often hit by " +
    "ransomware, and attackers usually get in through the weakest device, then move sideways towards " +
    "valuable data. Medical IoT devices are a common weak device. They run embedded operating systems " +
    "that often cannot be patched or run security software, so the network itself has to contain them. " +
    "Network segmentation, and its finest-grained form micro-segmentation, is the control recommended by " +
    "the Zero Trust model (NIST SP 800-207). The question for a network designer is how much segmentation " +
    "is enough, and what it costs."),
  P("Our network models a small hospital campus with a collapsed-core design. A Cisco 2911 edge router " +
    "connects the hospital to a simulated ISP using PAT and exchanges routes with the core over OSPF. A " +
    "Catalyst 3560 multilayer switch is the core and routes between VLANs. Three Catalyst 2960 access " +
    "switches serve Ward A, Ward B and the admin block. A server switch holds four servers: the EHR web " +
    "server, the DNS/DHCP server, the IoT registration server and a Syslog/NTP server. End devices include " +
    "staff PCs, a network-admin PC, eight IoT devices (four standing in for medical devices, four for " +
    "building devices) and a WPA2 guest Wi-Fi network with a phone and a tablet. In the final design an " +
    "ASA 5506-X firewall guards the server zone. A laptop placed in a medical-IoT VLAN acts as the " +
    "“compromised device”, because Packet Tracer IoT devices cannot generate attack traffic."),
  P("The same physical network is saved as four Packet Tracer files, and only the security policy " +
    "changes between them. D0 is a single flat VLAN. D1 separates devices into role-based VLANs but routes " +
    "freely between them. D2 adds coarse zone ACLs on the core switch. D3 applies least-privilege " +
    "micro-segmentation: each device class gets its own VLAN and may reach only the exact server and port " +
    "it needs. D3 also adds a stateful firewall, port security, DHCP snooping, BPDU Guard, hardened trunks " +
    "and SSH-only management. Keeping everything else fixed makes the comparison a controlled experiment. " +
    "It answers three research questions: (RQ1) how much does each level shrink the attack surface; " +
    "(RQ2) does tighter segmentation break legitimate clinical and IoT traffic; and (RQ3) what does each " +
    "level cost in configuration complexity?"),
  P("Several Layer-2 and Layer-3 technologies are used. VLANs (IEEE 802.1Q) split one switched network " +
    "into separate broadcast domains, and 802.1Q trunks carry several VLANs over one link using a 4-byte " +
    "tag. Inter-VLAN routing is done by Switched Virtual Interfaces (SVIs) on the multilayer switch, " +
    "which act as each VLAN’s default gateway. OSPF, a link-state routing protocol, exchanges routes " +
    "between the core and the edge router, and the edge router injects a default route. Floating static routes (administrative distance 250) on both the core and the edge act as a backup that is used only if OSPF fails. DHCP (RFC 2131) " +
    "hands out addresses from a central server. The core switch relays the DHCP broadcasts to that server " +
    "with ip helper-address, which also tells the server which pool to use. DNS resolves names such as " +
    "ehr.hospital.local. PAT (NAT overload, RFC 3022) lets all private 10.10.x.x hosts share one " +
    "public address. Extended ACLs filter traffic by source, destination, protocol and port. The ASA is a " +
    "stateful firewall: it allows traffic from a higher to a lower security level, blocks the reverse " +
    "unless an ACL permits it, and tracks connections so that replies get back in."),
  P("At the access edge, port security limits each switch port to its learned (sticky) MAC address and " +
    "shuts the port if another device is plugged in. DHCP snooping lets only the trusted uplink send DHCP " +
    "offers, which defeats rogue DHCP servers. PortFast with BPDU Guard protects the Spanning Tree " +
    "Protocol, and an unused native VLAN, allowed-VLAN lists and disabled DTP reduce VLAN-hopping risk. " +
    "Management uses SSH version 2 with local accounts and VTY access-class filters instead of plaintext " +
    "Telnet, and every network device sends logs to a Syslog server and takes its time from NTP so " +
    "events can be correlated. Our contribution is a reproducible, openly documented Packet Tracer " +
    "testbed. It measures how lateral movement is contained at each level of segmentation, and it " +
    "reports both the security gained and the configuration cost."),
];

// ---------- 3. Network diagram ----------
const s3 = [
  H1("3  Network Diagram"),
  img("topology.png", 600, 394),
  caption("Figure 1: Logical topology of the final micro-segmented design (D3), colour-coded by VLAN/zone"),
  P([run("Note: ", { bold: true }), ph("Also paste the Packet Tracer workspace screenshot (Logical view) of D3 below this figure.")]),
  tableCaption("Table 3.1: VLAN and IP addressing plan"),
  table(["VLAN", "Name", "Subnet", "Gateway", "Used in", "Members"], [
    ["1", "Flat (D0)", "10.10.0.0/17", "10.10.0.1 (core SVI 1)", "D0", "Every device"],
    ["10", "STAFF", "10.10.10.0/24", "10.10.10.1", "D1–D3", "Nurse PCs, reception PC"],
    ["20", "SERVERS", "10.10.20.0/24", ".1 core SVI (D1–D2) / ASA inside (D3)", "D1–D3", "EHR, DNS/DHCP, IoT reg., Syslog/NTP"],
    ["30", "MED-IOT", "10.10.30.0/24", "10.10.30.1", "D1–D2", "All medical IoT"],
    ["31", "MED-MONITORS", "10.10.31.0/24", "10.10.31.1", "D3", "Patient monitors"],
    ["32", "MED-INFUSION", "10.10.32.0/24", "10.10.32.1", "D3", "Infusion pumps"],
    ["40", "BLDG-IOT", "10.10.40.0/24", "10.10.40.1", "D1–D3", "Door, fire monitor, fan, webcam"],
    ["50", "GUEST", "10.10.50.0/24", "10.10.50.1", "D1–D3", "Guest Wi-Fi clients"],
    ["99", "MGMT", "10.10.99.0/24", "10.10.99.1", "D1–D3", "Switch management, NetAdmin-PC"],
    ["998 / 999", "NATIVE / BLACKHOLE", "–", "–", "D3", "Unused native VLAN / parked ports"],
    ["–", "Core–Edge link", "10.10.255.0/30", "–", "All", "OSPF area 0"],
    ["–", "Core–ASA link", "10.10.254.0/30", "–", "D3", "Routed transit to firewall"],
    ["–", "WAN / Internet", "198.51.100.0/30, 203.0.113.0/24", "–", "All", "ISP link, public web server"],
  ], [900, 1500, 1500, 2026, 800, 2300]),
  gap(),
  tableCaption("Table 3.2: Devices and physical connections"),
  table(["Device (PT model)", "Port", "Connects to", "Cable"], [
    ["ISP-RTR (2911)", "G0/0 / G0/1", "EDGE-RTR G0/0 / INTERNET-WEB", "Copper cross-over"],
    ["EDGE-RTR (2911)", "G0/1", "CORE-MLS G0/1 (routed port)", "Copper straight"],
    ["CORE-MLS (3560-24PS)", "Fa0/1, 2, 3", "SW-WARD-A, SW-WARD-B, SW-ADMIN (G0/1), 802.1Q trunks", "Copper cross-over"],
    ["CORE-MLS", "G0/2", "SW-SRV G0/1 (D0–D2) / ASA-SRV G1/1 (D3)", "Cross-over / straight"],
    ["ASA-SRV (5506-X), D3 only", "G1/2", "SW-SRV G0/1", "Copper straight"],
    ["SW-SRV (2960)", "Fa0/1–4", "EHR-SRV, DNS-DHCP-SRV, IOT-REG-SRV, SYSLOG-NTP-SRV", "Copper straight"],
    ["SW-WARD-A / B (2960)", "Fa0/1–5", "Nurse PC, monitor, pump, test-node port, staff wall jack", "Copper straight"],
    ["SW-ADMIN (2960)", "Fa0/1–8", "Reception PC, NetAdmin PC, 4 building IoT, test-node port, Guest-AP", "Copper straight"],
    ["Guest-AP (AccessPoint-PT)", "Wireless", "Guest-Phone, Guest-Tablet (WPA2-PSK)", "Wireless"],
  ], [2400, 1300, 3726, 1600]),
  gap(),
  tableCaption("Table 3.3: The four designs compared (only the security policy changes)"),
  table(["Design", "Segmentation", "Filtering", "Extra controls"], [
    ["D0 Flat", "One VLAN, one /17 subnet", "None", "Telnet with shared password"],
    ["D1 VLAN-only", "6 role VLANs + 802.1Q trunks", "None (free inter-VLAN routing)", "Telnet"],
    ["D2 Zone ACLs", "Same as D1", "Coarse zone ACLs on SVIs (IoT → server zone only; guests → Internet only)", "Telnet"],
    ["D3 Micro-seg", "8 VLANs, IoT split per device class", "Least-privilege ACLs (host + port) + ASA stateful firewall",
      "Port security, DHCP snooping, BPDU Guard, trunk hardening, SSH-only mgmt, unused ports shut"],
  ], [1500, 2300, 2726, 2500]),
];

// ---------- 4. Configuration ----------
const d3 = "D3-microseg";
const s4 = [
  H1("4. Configuration setup"),
  P("This section gives the configuration of every device in the final design (D3). End devices are set " +
    "up through the Packet Tracer GUI. Network devices are configured from the CLI; the commands below can " +
    "be pasted directly into each device’s CLI tab. Lines starting with “!” are comments that explain the " +
    "purpose of each block. The full configuration files for all four designs are in the project’s " +
    "configs/ folder, and Section 4.10 lists what differs in D0–D2. In our build, every router, switch and " +
    "firewall configuration was pushed into Packet Tracer 9.0.1 from these same files, so the report and the " +
    ".pkt files match line for line."),
  H2("4.1 PCs and laptops"),
  table(["Device", "Switch / port", "VLAN (D3)", "IP configuration"], [
    ["Nurse-PC-A", "SW-WARD-A Fa0/1", "10 STAFF", "DHCP → 10.10.10.100+, GW 10.10.10.1, DNS 10.10.20.11"],
    ["Nurse-PC-B", "SW-WARD-B Fa0/1", "10 STAFF", "DHCP (same pool)"],
    ["Reception-PC", "SW-ADMIN Fa0/1", "10 STAFF", "DHCP (same pool)"],
    ["NetAdmin-PC", "SW-ADMIN Fa0/2", "99 MGMT", "Static 10.10.99.50/24, GW 10.10.99.1, DNS 10.10.20.11"],
    ["IOT-COMPROMISED (Laptop)", "SW-WARD-A Fa0/4 (also Ward-B Fa0/4, Admin Fa0/7)", "31 / 40", "DHCP: simulates a hijacked medical device"],
    ["ROGUE-LAPTOP", "SW-WARD-A Fa0/2 (attack A6 only)", "31", "DHCP: unauthorised device"],
    ["Guest-Phone, Guest-Tablet", "Wireless via Guest-AP", "50 GUEST", "SSID HOSP-GUEST, WPA2-PSK, DHCP"],
  ], [1900, 2500, 1100, 3526]),
  H2("4.2 Servers"),
  table(["Server", "IP / mask / gateway", "Services enabled"], [
    ["EHR-SRV", "10.10.20.10 /24, GW 10.10.20.1", "HTTP, HTTPS (index.html: “Hospital EHR – Patient Records (CONFIDENTIAL)”)"],
    ["DNS-DHCP-SRV", "10.10.20.11 /24, GW 10.10.20.1", "DNS: ehr.hospital.local→.10, iot.hospital.local→.12, web.isp.test→203.0.113.10; DHCP pools (Table 4.2)"],
    ["IOT-REG-SRV", "10.10.20.12 /24, GW 10.10.20.1", "IoT registration server (account iotadmin)"],
    ["SYSLOG-NTP-SRV", "10.10.20.13 /24, GW 10.10.20.1", "Syslog, NTP"],
    ["INTERNET-WEB", "203.0.113.10 /24, GW 203.0.113.1", "HTTP (“Public Internet web server”)"],
    ["ROGUE-DHCP (attack A5 only)", "10.10.10.66 /24", "DHCP pool handing out gateway/DNS 10.10.10.66 (man-in-the-middle)"],
  ], [1900, 2600, 4526]),
  tableCaption("Table 4.2: DHCP pools on DNS-DHCP-SRV (D3); the relay agent’s giaddr selects the pool"),
  table(["Pool", "Default gateway", "DNS", "Start IP", "Mask", "Max users"], [
    ["serverPool", "10.10.20.1", "10.10.20.11", "10.10.20.200", "255.255.255.0", "20"],
    ["STAFF", "10.10.10.1", "10.10.20.11", "10.10.10.100", "255.255.255.0", "100"],
    ["MED-MONITORS", "10.10.31.1", "10.10.20.11", "10.10.31.100", "255.255.255.0", "100"],
    ["MED-INFUSION", "10.10.32.1", "10.10.20.11", "10.10.32.100", "255.255.255.0", "100"],
    ["BLDG-IOT", "10.10.40.1", "10.10.20.11", "10.10.40.100", "255.255.255.0", "100"],
    ["GUEST", "10.10.50.1", "10.10.20.11", "10.10.50.100", "255.255.255.0", "100"],
  ], [1700, 1500, 1400, 1500, 1726, 1200]),
  H2("4.3 IoT devices"),
  table(["Device", "Represents", "Port", "VLAN (D3)", "Settings"], [
    ["Monitor-A1, Monitor-B1", "Patient vital-signs monitor", "Ward-A/B Fa0/2", "31", "Wired NIC (PT-IOT-NM-1CFE), DHCP, IoT server 10.10.20.12"],
    ["Pump-A1, Pump-B1", "Infusion pump", "Ward-A/B Fa0/3", "32", "Same as above"],
    ["Smart-Door", "Access-controlled door", "Admin Fa0/3", "40", "Same as above"],
    ["Fire-Monitor", "Smoke / fire detector", "Admin Fa0/4", "40", "Same; rule: smoke → HVAC-Fan high"],
    ["HVAC-Fan", "Ventilation", "Admin Fa0/5", "40", "Same as above"],
    ["Webcam", "CCTV camera", "Admin Fa0/6", "40", "Same as above"],
  ], [1800, 1900, 1400, 900, 3026]),
  H2("4.4 Wireless access point"),
  P("Guest-AP (AccessPoint-PT): Port 0 is cabled to SW-ADMIN Fa0/8 (VLAN 50). Port 1 uses SSID HOSP-GUEST " +
    "with WPA2-PSK authentication and the passphrase GuestWiFi@2026. Wireless clients get addresses from " +
    "the GUEST DHCP pool through the core’s DHCP relay."),
  H2("4.5 ISP-RTR (Cisco 2911)"), ...code(CFG(d3, "ISP-RTR.txt")),
  H2("4.6 EDGE-RTR (Cisco 2911)"), ...code(CFG(d3, "EDGE-RTR.txt")),
  H2("4.7 CORE-MLS (Cisco Catalyst 3560-24PS)"), ...code(CFG(d3, "CORE-MLS.txt")),
  H2("4.8 ASA-SRV (Cisco ASA 5506-X)"), ...code(CFG(d3, "ASA-SRV.txt")),
  H2("4.9 Access and server switches (Cisco 2960-24TT)"),
  H3("SW-WARD-A"), ...code(CFG(d3, "SW-WARD-A.txt")),
  H3("SW-WARD-B"),
  P("Same as SW-WARD-A with these changes: hostname SW-WARD-B, enable secret WardB@2026, port descriptions " +
    "naming Nurse-PC-B, Monitor-B1 and Pump-B1, uplink to CORE-MLS Fa0/2, and management IP " +
    "10.10.99.12/24. The full file is configs/D3-microseg/SW-WARD-B.txt."),
  H3("SW-ADMIN"), ...code(CFG(d3, "SW-ADMIN.txt")),
  H3("SW-SRV"), ...code(CFG(d3, "SW-SRV.txt")),
  H2("4.10 Baseline designs D0, D1 and D2: what is different"),
  P("ISP-RTR and SW-SRV are identical in all designs. EDGE-RTR keeps the same routing and NAT but uses " +
    "Telnet with a shared password instead of SSH. Key differences:"),
  bullet([run("D0 Flat: ", { bold: true }), run("there are no VLANs. The core has a single SVI (VLAN 1, 10.10.0.1/17), every host uses a /17 mask (255.255.128.0, chosen so it cannot overlap the 10.10.255.0/30 core–edge link), and one DHCP pool serves everyone.")]),
  bullet([run("D1 VLAN-only: ", { bold: true }), run("VLANs 10/20/30/40/50/99, trunks to the access switches, an SVI and ip helper-address per VLAN, no ACLs, and SW-SRV in access VLAN 20 on the core.")]),
  bullet([run("D2 Zone ACLs: ", { bold: true }), run("D1 plus three coarse ACLs on the core SVIs:")]),
  ...code(CFG("D2-zone-acl", "CORE-MLS.txt").split("\n").filter((l, i, a) => {
    const s = a.indexOf("ip access-list extended MEDIOT-IN"); const e = a.findIndex((x) => x.startsWith("interface Vlan10"));
    return i >= s && i < e;
  }).join("\n").trim()),
];

// ---------- 5. Results ----------
const exp = { S: "Succeeded", B: "Blocked", P: "Partial" };
const shadeOutcome = (t) => t === "Blocked" ? "D9EAD3" : t === "Succeeded" ? "F4CCCC" : t === "Partial" ? "FFF2CC" : undefined;
const s5 = [
  H1("5. Results"),
  H2("5.1 Test method"),
  P("Every design was put through the same test plan. A laptop (IOT-COMPROMISED) plays a hijacked medical " +
    "device and is placed at three locations: Ward A medical IoT, Ward B medical IoT and building IoT. " +
    "Each attack is repeated three times at each location, and the outcome is confirmed in Packet " +
    "Tracer’s Simulation mode, where the PDU details show the exact ACL or firewall rule that dropped a " +
    "packet. Nine functional tests check that legitimate traffic still works. All observations are logged " +
    "in results/attack-matrix.csv, attack-surface.csv and functional.csv, and the graphs are generated " +
    "from these files."),
  table(["ID", "Attack scenario", "How it is performed"], [
    ["A1", "Reconnaissance sweep", "From IOT-COMPROMISED, ping all 23 target hosts and gateways; count replies"],
    ["A2", "Unauthorised data access", "Browser on IOT-COMPROMISED → http://10.10.20.10 (EHR)"],
    ["A3", "Device / IoT-server hijack", "Browse to the IoT server login (10.10.20.12) and ping a device of another class (e.g. a pump)"],
    ["A4", "Infrastructure takeover", "telnet / ssh to 10.10.99.11–13, the core gateway and EDGE-RTR"],
    ["A5", "Rogue DHCP server", "Connect ROGUE-DHCP to SW-WARD-A Fa0/5; renew Nurse-PC-A’s lease"],
    ["A6", "Unauthorised device / MAC spoof", "Unplug Monitor-A1, plug ROGUE-LAPTOP into SW-WARD-A Fa0/2"],
    ["A7", "Guest → clinical pivot", "Guest-Phone browser → http://10.10.20.10"],
  ], [600, 2500, 5926]),
  H2("5.2 Proof of communication (screenshots)"),
  ...shot(2, "Nurse-PC-A successfully pings EHR-SRV and opens http://ehr.hospital.local (D3)",
    "Nurse-PC-A → Desktop → Command Prompt → ping 10.10.20.10; then Web Browser → ehr.hospital.local."),
  ...shot(3, "All IoT devices registered on the IoT server dashboard",
    "Any staff PC → Web Browser → 10.10.20.12 → log in as iotadmin."),
  ...shot(4, "Internet access through PAT: output of show ip nat translations on EDGE-RTR",
    "Guest-Phone opens http://web.isp.test, then run the command on EDGE-RTR."),
  ...shot(5, "D3: IoT → EHR request dropped by ACL MONITORS-IN (Simulation mode, PDU details)",
    "Simulation mode, filter HTTP/TCP, browse to 10.10.20.10 from IOT-COMPROMISED, click the red X PDU at CORE-MLS."),
  ...shot(6, "D3: port security shuts SW-WARD-A Fa0/2 when ROGUE-LAPTOP is connected",
    "After attack A6 run show port-security interface fa0/2 and show interfaces status err-disabled."),
  ...shot(7, "D3: DHCP snooping drops the rogue server’s offers; Nurse-PC-A keeps a legitimate lease",
    "Run show ip dhcp snooping on SW-WARD-A and ipconfig on Nurse-PC-A."),
  ...shot(8, "D3: ACL hit counters on CORE-MLS and ASA-SRV after the attack runs",
    "show access-lists on CORE-MLS; show access-list OUTSIDE-IN on ASA-SRV."),
  ...shot(9, "D0/D1 contrast: the same IoT → EHR request succeeds in the flat network",
    "Open the D0 file and repeat the browser test from IOT-COMPROMISED."),
  H2("5.3 Functional preservation (legitimate traffic)"),
  P([run("Expected result for every design is PASS. Fill the observed column from results/functional.csv. "),
    ph("[Update after testing]")]),
  table(["ID", "Legitimate flow", "D0", "D1", "D2", "D3"],
    [["F1", "Staff PC opens EHR web page by name (DNS + HTTP)"], ["F2", "Staff PC pings EHR-SRV"],
      ["F3", "All 8 IoT devices registered on IoT server"], ["F4", "DHCP: every client gets an address in its own subnet"],
      ["F5", "Guest phone reaches Internet web server"], ["F6", "Staff reaches Internet; NAT entries on EDGE-RTR"],
      ["F7", "NetAdmin manages switches (Telnet D0–D2, SSH D3)"], ["F8", "IoT rule fires (smoke → HVAC fan)"],
      ["F9", "Syslog server receives device logs"]].map((r) => [...r, "[  ]", "[  ]", "[  ]", "[  ]"]),
    [600, 4826, 900, 900, 900, 900], { center: true, centerFrom: 2 }),
  H2("5.4 Attack success matrix"),
  P([run("Table 5.2 gives the outcome predicted by analysing each design’s configuration. Every cell must be " +
    "confirmed in Packet Tracer and recorded in results/attack-matrix.csv; then re-run "),
  run("python tools/make_graphs.py", { font: "Consolas", size: 20 }),
  run(" to redraw Figure 10 from the observed data. "), ph("[Replace “expected” with observed after testing]")]),
  tableCaption("Table 5.2: Expected attack outcome per design, and the control responsible in D3"),
  table(["Attack", "D0", "D1", "D2", "D3", "D3 control that stops it"], [
    ["A1 Recon sweep", "S", "S", "P", "P", "SVI ACLs drop all ICMP; only same-class peers (same VLAN) still answer"],
    ["A2 EHR access", "S", "S", "S", "B", "MONITORS-IN + ASA OUTSIDE-IN permit EHR only from staff"],
    ["A3 IoT server / device hijack", "S", "S", "S", "P", "Cross-class device blocked; IoT server port 80 stays open by necessity"],
    ["A4 Telnet/SSH to infra", "S", "S", "B", "B", "SVI ACLs, VTY access-class 10, SSH-only"],
    ["A5 Rogue DHCP", "S", "S", "S", "B", "DHCP snooping (untrusted access ports)"],
    ["A6 Unauthorised device", "S", "S", "S", "B", "Port security sticky MAC, violation shutdown"],
    ["A7 Guest → EHR", "S", "S", "B", "B", "GUEST-IN denies 10.0.0.0/8; ASA has no guest → EHR rule"],
  ].map((r) => r.map((c, i) => (i >= 1 && i <= 4) ? exp[c] : c)),
  [2000, 950, 950, 950, 950, 3226], { center: false, shade: (t) => shadeOutcome(t), size: 18 }),
  P([run("S = attack succeeded, P = partial (limited reach), B = blocked.", { size: 20, italics: true })]),
  img("attack-heatmap.png", 600, 315),
  caption("Figure 10: Attack outcome matrix (currently the expected values; regenerate from observed data)"),
  H2("5.5 Attack surface (RQ1)"),
  P("The attack surface is the share of 23 target hosts (staff PCs, servers, IoT devices, guest clients " +
    "and network devices) that answer a ping from the compromised node, together with the share of 10 " +
    "target services (EHR HTTP/HTTPS, IoT server web page, DNS, the Internet web server as an " +
    "exfiltration path, and Telnet/SSH on five network devices) " +
    "that accept a connection."),
  table(["Design", "Hosts reachable (of 23)", "Services reachable (of 10)", "Why"], [
    ["D0", "23 (100%)", "10 (100%)", "One broadcast domain, no filtering"],
    ["D1", "23 (100%)", "10 (100%)", "VLANs are routed freely by the core SVIs"],
    ["D2", "8 (35%)", "4 (40%)", "IoT may reach the whole server zone; management, other VLANs and Internet denied"],
    ["D3", "2–4 (9–17%)", "1 (10%)", "Only same-class peers in the same VLAN; only IoT-server TCP 80"],
  ], [900, 2000, 2200, 3926], { center: false }),
  P([ph("[Expected values from design analysis; replace with the observed means]")]),
  img("attack-surface.png", 600, 255),
  caption("Figure 11: Attack surface reachable from the compromised node"),
  H2("5.6 Configuration complexity (RQ3)"),
  P("These numbers are counted directly from the configuration files by tools/config_stats.py. They are " +
    "exact for the configurations in Section 4."),
  table(["Design", "Devices configured", "Config lines", "ACEs", "Security features"],
    complexity.map((r) => [r.design, r.devices_configured, r.config_lines, r.aces, r.security_features]),
    [1500, 1900, 1900, 1800, 1926], { center: true }),
  img("complexity.png", 600, 240),
  caption("Figure 12: Configuration lines and access-control entries per design"),
  img("tradeoff.png", 470, 260),
  caption("Figure 13: Security gained versus configuration effort (expected attack outcomes)"),
  H2("5.7 Overhead on legitimate traffic (RQ2)"),
  table(["Flow", "D0", "D1", "D2", "D3"], [
    ["Nurse-PC → EHR: Layer-3 devices in path", "0 (same subnet)", "1 (core)", "1 (core)", "2 (core + ASA)"],
    ["Nurse-PC → EHR: policy checks", "0", "0", "0", "2 (STAFF-IN, OUTSIDE-IN)"],
    ["Monitor → IoT server: policy checks", "0", "0", "1 (MEDIOT-IN)", "2 (MONITORS-IN, OUTSIDE-IN)"],
  ], [3226, 1450, 1450, 1450, 1450], { center: true }),
  P([run("Verify with tracert from Nurse-PC-A and by counting events in Simulation mode. By default the ASA " +
    "does not decrement TTL, so it does not appear in tracert output even though it is in the path. "),
  ph("[Add observed event counts]")]),
  H2("5.8 Discussion"),
  bullet([run("VLANs alone give no containment. ", { bold: true }), run("D1 needs 85 more configuration lines than D0, but the expected attack surface stays at 100%, because the core routes freely between VLANs. VLANs separate broadcast domains; they are not a security boundary unless filtering is added.")]),
  bullet([run("Coarse zone ACLs are the cheapest large gain. ", { bold: true }), run("D2 adds only 10 ACEs and is expected to block management takeover (A4) and the guest pivot (A7). It still lets a compromised IoT device reach the EHR, because it permits the whole server zone.")]),
  bullet([run("Least privilege closes data access, but costs effort. ", { bold: true }), run("D3 roughly triples the configuration size of D0 (559 lines, 47 ACEs). It is expected to block five of seven attacks fully and leave two partial.")]),
  bullet([run("Residual risk is structural. ", { bold: true }), run("Devices in the same VLAN still reach each other at Layer 2, and the IoT server must stay reachable. Private VLANs, 802.1X/NAC or per-device SDN policies would be needed to close these gaps.")]),
  bullet([run("Minimum viable segmentation. ", { bold: true }), run("For small hospitals, D2-style zone ACLs, plus a least-privilege rule protecting the EHR and Layer-2 hardening on IoT ports, give most of D3’s protection for a fraction of its configuration effort. ")
    , ph("[Confirm against the observed results]")]),
  bullet([run("Limitations. ", { bold: true }), run("Packet Tracer is a simulator: there are no real exploits, timing is approximate, and a laptop stands in for a compromised IoT device. Packet Tracer’s implementation of some features (e.g. ASA inspection) is simplified.")]),
];

// ---------- 6. Conclusion ----------
const s6 = [
  H1("6. Conclusion"),
  P("We designed and simulated a smart-hospital network in Cisco Packet Tracer and evaluated four levels of " +
    "segmentation, from a flat LAN to full micro-segmentation, against the same set of lateral-movement " +
    "attacks launched from a compromised medical IoT device. The network combines 802.1Q VLANs, " +
    "inter-VLAN routing on a multilayer switch, OSPF, DHCP relay, DNS, PAT, extended ACLs, a stateful ASA " +
    "firewall, port security, DHCP snooping, BPDU Guard, SSH-only management, Syslog/NTP and WPA2 guest " +
    "Wi-Fi. By changing only the security policy between designs, we could measure the attack surface, " +
    "functional impact and configuration cost of each level. The analysis shows that VLANs by themselves " +
    "do not contain an attacker, that coarse zone ACLs remove the biggest risks cheaply, and that " +
    "least-privilege micro-segmentation keeps a compromised device away from patient records while " +
    "clinical services keep working. This gives hospital IT teams a practical, evidence-based path to " +
    "protect patient data and safety-critical devices. Future work includes private VLANs or per-port " +
    "ACLs to stop same-VLAN movement, 802.1X with RADIUS-based network access control for device identity, " +
    "and controller-based (SDN) segmentation that isolates a device automatically when an intrusion " +
    "detection system flags it."),
  H1("References"),
  ...[
    "S. Rose, O. Borchert, S. Mitchell and S. Connelly, “Zero Trust Architecture,” NIST Special Publication 800-207, 2020.",
    "IEEE Std 802.1Q, “IEEE Standard for Local and Metropolitan Area Networks—Bridges and Bridged Networks.”",
    "R. Droms, “Dynamic Host Configuration Protocol,” RFC 2131, IETF, 1997.",
    "M. Patrick, “DHCP Relay Agent Information Option,” RFC 3046, IETF, 2001.",
    "J. Moy, “OSPF Version 2,” RFC 2328, IETF, 1998.",
    "P. Srisuresh and K. Egevang, “Traditional IP Network Address Translator (Traditional NAT),” RFC 3022, IETF, 2001.",
    "Y. Rekhter et al., “Address Allocation for Private Internets,” RFC 1918, IETF, 1996.",
    "T. Ylonen and C. Lonvick, “The Secure Shell (SSH) Transport Layer Protocol,” RFC 4253, IETF, 2006.",
    "R. Gerhards, “The Syslog Protocol,” RFC 5424, IETF, 2009.",
    "D. Mills, J. Martin, J. Burbank and W. Kasch, “Network Time Protocol Version 4,” RFC 5905, IETF, 2010.",
  ].map((t, i) => new Paragraph({ spacing: { after: 100 }, indent: { left: 500, hanging: 500 },
    children: [run(`[${i + 1}]  ${t}`, { size: 22 })] })),
];

// ---------- document ----------
const footer = new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER,
  children: [new TextRun({ children: [PageNumber.CURRENT], font: SERIF, size: 20 })] })] });
const page = { size: { width: 11906, height: 16838 }, margin: { top: 1440, bottom: 1440, left: 1440, right: 1440 } };

const doc = new Document({
  creator: "CN Mini Project Team", title: TITLE,
  styles: {
    default: { document: { run: { font: SERIF, size: 24 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: SERIF, size: 32, bold: true, color: HEAD_COLOR }, paragraph: { outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: SERIF, size: 26, bold: true, color: HEAD_COLOR }, paragraph: { outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: SERIF, size: 24, bold: true, italics: true, color: "404040" }, paragraph: { outlineLevel: 2 } },
    ],
  },
  numbering: { config: [{ reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•",
    alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 300 } } } }] }] },
  sections: [
    { properties: { page }, children: cover },
    { properties: { page }, children: certificate },
    { properties: { page: { ...page, pageNumbers: { start: 1 } } }, footers: { default: footer },
      children: [...s1, pageBreak(), ...s2, pageBreak(), ...s3, pageBreak(), ...s4, pageBreak(), ...s5, pageBreak(), ...s6] },
  ],
});

const out = path.join(ROOT, "report", "CN_MiniProject_Report.docx");
Packer.toBuffer(doc).then((b) => { fs.writeFileSync(out, b); console.log("written", out); });
