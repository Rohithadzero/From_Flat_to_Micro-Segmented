# SUMMARY: Literature positioning for "From Flat to Micro-Segmented" (2020-2026)

Scope and honesty note. 48 papers are catalogued (see INDEX.md, papers.csv, refs.bib). Discovery was done mainly through the OpenAlex API (relevance search, many topic queries), then each record was checked via OpenAlex metadata and DOI content negotiation. Google Scholar, IEEE Xplore and ACM DL were not queried directly, so the search is broad but not exhaustive. 22 PDFs were downloaded from legal OA sources; 26 are link-only because MDPI, Hindawi, Springer, ACM, ScienceDirect and Europe PMC returned 403 to a script (no bypass was attempted). Entries for link-only papers rely on abstracts; weaker claims are marked "not verified" in the CSV.

## (a) Ten most similar papers, ranked

1. P06 Sifawa et al. 2026, Network-Level Zero Trust Controls Using Cisco Packet Tracer (Sifawa2026ImplementationEvaluation). Same tool, VLAN segments, extended ACLs, default-deny, least privilege, before/after design, lateral-movement framing. Finds VLAN-only is insufficient once inter-VLAN routing is on, matching our D1. Enterprise, not hospital; only 6 ping scenarios.
2. P08 Odule et al. 2026, Micro-Segmentation Framework for Zero-Trust Lite (GNS3) (Odule2026SimulationValidation). Flat baseline vs segmented network with a "Patient Zero" attacker doing recon and lateral movement. Reports reachable nodes (24 to 2), lateral moves, time-to-compromise, blast radius, latency (+0.6 ms), throughput (94%). Not hospital/IoMT; uses pfSense/Zeek/ODL.
3. P07 Hari et al. 2026, Three-tier microsegmentation under ZTA (Hari2026ThreeTier). Evaluated on data from a super-speciality hospital and a campus; exposure metric ENICE (-99%) and attack paths (-99.7%). Algorithmic/eBPF framework, not a reproducible CLI build (PDF not accessed).
4. P47 Avila Pesantez et al. 2022, Cybersecurity policies for switching devices in hospital data centers (AvilaPesantez2022HospitalSwitchPolicies). Hospital L2 hardening (port security, DHCP snooping, BPDU protection, VLAN hopping, ARP) in EVE-NG; 10 attack scenarios, 98% of vulnerabilities mitigated, CLI shown. Huawei, no device-class segmentation.
5. P14 Mughaid et al. 2026, Secure and adaptive IoT network architecture for smart hospitals (Mughaid2026SecureAdaptive). Hospital network in Packet Tracer with ACLs, latency/throughput load tests and penetration testing. QoS-centred, no design ladder.
6. P15 Alvarez et al. 2023, SDN vs ACL against private-VLAN attacks (Alvarez2023PerformanceAnalysis). Segmentation plus attack plus ACL mitigation, with CPU, memory, delay, loss and power overhead metrics.
7. P11 Raval 2026, Dynamic microsegmentation for a multi-robot IoT network (Raval2026ImplementationDynamic). Lab demo of isolating an infected IoT asset by health tags without disturbing others.
8. P05 Gosalvez-White et al. 2025, MEDIotWALL (GosalvezWhite2025Mediotwall). IoMT-specific firewall with generated per-device rules and regulation awareness (abstract only).
9. P12 Jassim 2024, Smart Hospital Network Enterprise Design via Packet Tracer (Jassim2024SmartHospital). Same tool and domain, but a design paper; no security evaluation found in the abstract.
10. P01 Tyler and Viana 2021, Trust No One? Healthcare zero-trust transition (Tyler2021TrustNo). Healthcare motivation: flat internal trust, unmanageable medical devices, legacy systems. Conceptual only.

Honorable mentions: P19 Djuanda 2024 (VLAN + ACL case study), P44 Alhajahmad 2025 (Packet Tracer DHCP snooping + port security with CLI), P46 Alotaibi 2025 (hybrid ZT for legacy healthcare), P36 Wintolo 2023 (ANOVA on rogue-DHCP impact).

## (b) Features, metrics and methods in the literature that our project lacks

| Missing item | Papers that do it (from what we saw) |
|---|---|
| Latency / throughput / overhead of the security controls | P08 (+0.6 ms, 94% throughput), P14, P15 (CPU, memory, delay, loss, power), P07 (130 ms at 1000 users), P37 |
| Blast radius, time-to-compromise, count of successful lateral moves | P08 |
| Exposure and attack-path counts (formalised attack surface) | P07 (ENICE, attack paths), P41, P45 (attack graphs) |
| Statistical testing of differences | P36 (ANOVA, p = 0.004) |
| Real attack tooling (Nmap, Metasploit, Kali, Yersinia, Dsniff, OpenVAS) | P08, P19, P47, P35 |
| Layer-2 attack coverage: VLAN double-tagging, ARP spoofing, STP/BPDU, DHCP starvation, trusted-port abuse | P47, P35, P44, P16 |
| Private VLANs | P15 |
| SDN / programmable enforcement as comparison | P15, P13, P22 |
| Traffic visibility / monitoring (Zeek, IDS, anomaly detection) | P08 (visibility 5% to 98%), P30, P31, P32 |
| Dynamic or health-tag-driven quarantine, continuous or device-profile access control | P11, P22, P02, P28, P03 |
| Regulatory or standards mapping (ISO 27032, NIST SP 800-207 migration, HIPAA-aware rules) | P47, P24-P26, P05 |
| Cost metric | P08 |
| Operational-failure evidence for segmentation (practitioner survey) | P10 |
| MITRE ATT&CK mapping | Only P34 (survey of lateral-movement detection, ATT&CK-based). No simulation paper in our set maps its attacks to ATT&CK. |
| 802.1X / NAC | Not implemented in any simulated paper found; only conceptual in P28, P03. |
| Dynamic ARP inspection | ARP defence discussed in P47; not confirmed as a configured control in the Packet Tracer papers. |
| CVSS scoring | None of the 48 papers was verified to use CVSS. |
| Formal ACL reachability verification (Batfish-style) | None found. P45 uses model checking for a device-level attack graph, the nearest formal method. |
| Repeated runs / confidence intervals | Not seen in any simulation paper (P36 is the only one with a significance test). |

Cheapest high-value additions: (1) a blast-radius and hosts-reachable-per-hop metric (P08), (2) an overhead measurement (ping RTT through the ASA/ACL path vs D0; P08, P14), (3) an ATT&CK technique column in the attack-success matrix (P34 for the lateral-movement tactic), (4) VLAN double-tagging and ARP/DAI tests (P47), (5) a limitations note about missing 802.1X and no formal verification.

## (c) Research gap (only as supported by what we found)

Within the 48 papers retrieved:
- Packet Tracer / GNS3 segmentation studies exist for generic enterprise or SME networks (P06, P08, P19, P44), none for hospitals or medical IoT.
- Hospital network design or hardening papers (P12, P14, P47) do not compare segmentation levels and do not model a compromised medical device.
- Healthcare zero-trust papers (P01, P02, P03, P04, P37, P46) are conceptual or identity/crypto-centred, not a reproducible network build.
- One hospital-dataset microsegmentation framework (P07) is algorithmic rather than a CLI-level design.

We did not find, in this search, a single paper combining: an IoMT/hospital topology; a controlled ladder of four designs (flat, VLAN-only, coarse ACL, device-class micro-segmentation) where only policy changes; a stateful firewall plus Layer-2 hardening in the top design; a multi-attack suite launched from a compromised medical device; functional-preservation tests; and a configuration-complexity metric. That combination is where our contribution sits. Phrase it as "to the best of our knowledge, in the literature we reviewed", because the search was not exhaustive (no direct Scholar/IEEE/ACM queries) and several relevant PDFs were read only at abstract level.

## (d) Novelty threats

- P06 (Sifawa 2026) is the closest threat. Same simulator, same VLAN-vs-ACL contrast, same VLAN-only conclusion. Distinguish by hospital/IoMT domain, four-level ladder, 7-attack suite, ASA and L2 hardening, and the complexity metric. Cite it explicitly and say our results extend the finding rather than claiming the VLAN-only insight as new.
- P08 (Odule 2026) threatens method novelty (flat vs segmented, Patient Zero, quantified reachability, overhead). Distinguish by healthcare context, device-class micro-segmentation, Cisco CLI reproducibility, functional-preservation tests and L2 attack coverage. Adopt its blast-radius, time and overhead metrics to stay comparable.
- P07 (Hari 2026) threatens the "hospital + microsegmentation + exposure metric" claim at framework level. Ours is a configuration-level, reproducible simulation, which that paper does not appear to provide (PDF not retrieved; confirm before submission).
- P47 and P14 do not threaten the core claim but overlap with the hospital and L2-hardening parts; cite them.
- P11 (Raval 2026) and P05 (MEDIotWALL 2025) overlap with the IoT/IoMT isolation idea but use different mechanisms.

Next step before submission: read P07 and P05 in full in a browser (link-only), and run a Google Scholar / IEEE Xplore query for "Packet Tracer" AND (IoMT OR medical) to close the search gap.