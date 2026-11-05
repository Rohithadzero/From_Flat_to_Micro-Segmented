# Gap analysis: our project vs the 2020–2026 literature

Inputs: the 48 papers in `research/papers/` (papers.csv, INDEX.md, SUMMARY.md) and the
22 open-access PDFs. Eight were read in full: Sifawa 2026, Odule 2026, Avila Pesantez 2022,
Raval 2026, Djuanda 2024, Alhajahmad 2025 and the method/results sections of Mughaid 2026
and Dube 2026. The other 14 were read at abstract + conclusion level. Link-only papers
(26) were not read beyond the abstract.

## 1. Where we stand

| Dimension | Closest papers | Us |
|---|---|---|
| Simulator + reproducible CLI | Sifawa (PT, no configs published), Odule (GNS3, configs + attack script), Avila Pesantez (EVE-NG, Huawei CLI) | PT 9, every config published, 4 design files, push plans, gateway |
| Design ladder (controlled variable) | Sifawa: 2 states (before/after ACL); Odule: 2 (flat/segmented) | **4 states** (flat → VLAN → zone ACL → micro-seg), only policy changes |
| Domain | Avila Pesantez, Mughaid, Jassim: hospital but no compromised-device study; Sifawa/Odule: enterprise/SME | Hospital, compromised **medical IoT** device as the attacker |
| Attack coverage | Sifawa: 3 ping scenarios; Odule: SSH brute force, RDP, SMB; Avila Pesantez: L2 (MITM, CAM, ARP, STP, DHCP starvation, VLAN hopping) | 7 attacks across L2/L3/L4/mgmt plane, 3 attacker locations × 3 trials |
| Functional preservation | Sifawa: 3 authorised paths | 9 functional tests (DNS, HTTP, DHCP, NAT, SSH mgmt, IoT rule, syslog) |
| Cost of security | Odule: $ and hours; Dube: practitioner failure survey | Measured config lines / ACEs / features (189→559 lines, 1→47 ACEs) |
| Independent oracle | none (no formal reachability verification in any simulation paper found) | static policy analyzer cross-checked against PT runs (testing agent) |

What the literature already says that we must **not** claim as new:
- "VLANs alone don't isolate once inter-VLAN routing is on" — Sifawa 2026 states this explicitly.
  We extend it (four-level ladder, IoMT attacker, quantified surface), we do not discover it.
- "Micro-segmentation cuts reachable nodes by ~90%" — Odule 2026 (24→2 nodes).

## 2. What we lack (from the literature), and what we do about it

| # | Gap (who does it) | Feasible in PT? | Action |
|---|---|---|---|
| G1 | **Overhead on legitimate traffic**: ΔRTT, throughput (Odule +0.6 ms / 94%; Mughaid ΔRTT, ITU-T G.114 thresholds). Our own plan.md promised hop count + overhead (RQ3) but nothing measured it. | Yes: ping RTT, tracert hop count | **Added** test `O1` to the live runner → `results/overhead.csv` (staff→EHR, monitor→IoT server, staff→Internet; RTT avg/max over N pings, hop count). Throughput is not measurable in PT; stated as a limitation. |
| G2 | **Visibility / detection** of attack attempts (Odule: 5%→98% visibility; deny-log counts) | Yes: ACL hit counters on CORE-MLS + ASA, syslog entries | **Added** per-attack evidence capture: `show access-lists` / ASA `show access-list` snapshots before/after each attack; "detected" = a deny counter moved. Reported as **detection coverage** per design. |
| G3 | **Blast radius / ASR / block-rate metrics** (Odule ASR formula, blast radius; Mughaid attack-block rate and policy-compliance rate) | Yes, computed from our data | **Added** `tools/metrics.py`: ASR = 1 − reachable/total, criticality-weighted blast radius (EHR and infra weighted higher), attack block rate (ABR), policy-compliance rate = (blocked unauthorised + allowed authorised) / all checks. |
| G4 | **Statistical treatment** (Wintolo 2023 ANOVA; none of the simulation papers use repeated runs + CI) | Partly: PT is deterministic | `tools/metrics.py` reports per-design counts with Fisher's exact test between adjacent designs on blocked/not-blocked attempts, and states that PT outcomes are deterministic (variance 0 across trials). |
| G5 | **Threat-model mapping** (only a survey maps to ATT&CK; Grammatikis uses CVSS + attack-defence trees) | Yes (documentation) | **Added** ATT&CK mapping table (below) + per-attack severity weight used by the weighted blast radius. |
| G6 | **More L2 attacks**: VLAN hopping / switch spoofing, STP root takeover (Avila Pesantez, Alhajahmad) | Rogue switch: yes. Double-tagging, ARP spoofing, DHCP starvation: no (PT end devices cannot craft frames) | **Added** attack `A8 rogue switch / switch spoofing`: a 2960 plugged into a ward access port tries to negotiate a trunk (DTP desirable) and send BPDUs. D0 ports are dynamic-auto; D1/D2 are `mode access`; D3 adds BPDU Guard. ARP/double-tag/starvation listed as limitations. |
| G7 | **Dynamic quarantine / automated response** (Raval 2026 health-tag quarantine; Hussain QUARANTINE decision) | Yes, through our gateway | **Added** `Q1 automated containment`: the gateway watches deny counters on the compromised device's SVI ACL, finds its access port from the DHCP-snooping binding table, moves the port to black-hole VLAN 999, and records time-to-contain and whether other devices kept working. This turns the network from a static filter into a detect-and-respond loop — not done in any PT/GNS3 paper we found. |
| G8 | **Same-VLAN residual risk** (our own D3 limitation; Alvarez 2023 on private VLANs) | PT 2960 has no full PVLAN; `switchport protected` (PVLAN-edge) may exist | **Probe** in PT (`switchport protected` on IoT ports). If accepted, offer a D3+ variant and re-run A1/A3 to see whether monitor↔monitor traffic stops. If rejected, keep it as stated future work. |
| G9 | Real attack tooling (Nmap, Metasploit, Yersinia, OpenVAS) | No | Limitation: PT has no exploit tools; our attacks are protocol-level emulations. Say so explicitly. |
| G10 | 802.1X / NAC, device profiling | PT supports basic 802.1X + RADIUS, but setup is GUI-heavy | Future work (also not implemented in any simulation paper found). |
| G11 | Standards mapping (ISO 27032 in Avila Pesantez; NIST SP 800-207) | Documentation | Map D3 controls to NIST SP 800-207 tenets in the discussion. |
| G12 | Practitioner reality: why segmentation projects fail (Dube 2026, n=400) | — | Use it to motivate RQ3 (complexity cost) and the "minimum viable segmentation" recommendation. |

## 3. ATT&CK mapping (nearest technique)

| Attack | ATT&CK | Note |
|---|---|---|
| A1 recon ping sweep | T1018 Remote System Discovery; T1046 Network Service Discovery | sweep + service probe |
| A2 EHR access | T1213 Data from Information Repositories | EHR web app |
| A3 IoT server / cross-class device | T1021 Remote Services | IoT dashboard, other device class |
| A4 Telnet/SSH to infrastructure | T1021.004 Remote Services: SSH (and Telnet) | management plane |
| A5 rogue DHCP | T1557.003 Adversary-in-the-Middle: DHCP Spoofing | verified on attack.mitre.org |
| A6 rogue device on IoT port | T1200 Hardware Additions | verified on attack.mitre.org |
| A7 guest → clinical pivot | T1213 (target) via guest Wi-Fi foothold | |
| A8 rogue switch (new) | T1200 Hardware Additions; T1599 Network Boundary Bridging (nearest) | T1599 verified on attack.mitre.org |
| Q1 response | (defence) | NIST SP 800-207: dynamic policy |

## 4. Novelty statement (defensible)

"To the best of our knowledge, in the literature we reviewed (48 papers, 2020–2026), no study
combines (i) a hospital/IoMT topology with a compromised medical device as the attacker, (ii) a
four-level policy-only design ladder, (iii) a stateful firewall plus Layer-2 hardening, (iv) a
multi-attack suite with functional-preservation tests, (v) a measured configuration-cost metric,
(vi) an independent static reachability analyzer cross-validated against the simulator, and
(vii) an automated detect-and-quarantine loop driven through the simulator's scripting API."

Before submission: read Hari 2026 and MEDIotWALL in full (link-only), and run a Google Scholar
/ IEEE Xplore query for "Packet Tracer" AND (IoMT OR medical).
