# INDEX: Literature (2020-2026) related to the smart-hospital micro-segmentation project

All entries verified by publisher/DOI/arXiv/OpenAlex metadata. 'Link only' = no legal OA PDF could be fetched automatically (publisher bot-blocks or paywalled); open the URL in a browser. Summaries for link-only papers are abstract-based.


## A. Closest: simulated/emulated VLAN-ACL segmentation and lateral-movement containment

### P06 [High] IMPLEMENTATION AND EVALUATION OF NETWORK-LEVEL ZERO TRUST CONTROLS FOR ENTERPRISE NETWORK SECURITY USING CISCO PACKET TRACER
- Ismail Mahmoud Sifawa et al., Science World Journal, 2026. Key `Sifawa2026ImplementationEvaluation`. No DOI | https://scienceworldjournal.org/article/view/24917
- PDF: `research/papers/pdf/2026_Sifawa_ImplementationEvaluationNetwork.pdf`
- Summary: Enterprise network (Finance/HR/IT/Guest/Server VLANs) in Packet Tracer; extended ACLs and default-deny. Concludes VLAN segmentation alone does not isolate once inter-VLAN routing is enabled. Simulation/tool: Packet Tracer; configs shown: partial.
- Similarity (High): Same tool; VLAN segments + extended ACLs + default-deny + least-privilege against lateral movement; before/after design; shows VLAN-only is insufficient once inter-VLAN routing is on (same finding as our D1).
- Metrics: 6 connectivity scenarios (3 authorized stay up, 3 restricted blocked), ICMP via PT; before/after tables
- What we can borrow: Before/after allowed-vs-blocked scenario table format; the 'VLAN alone is insufficient' claim as a citable precedent for D1 vs D2/D3. Novelty threat: closest PT paper (see SUMMARY).

### P08 [High] Simulation-Based Validation of a Low-Cost Open-Source Micro-Segmentation Framework for Zero-Trust Lite Implementation in SMEs: Efficacy, Overhead, and Practical Considerations
- Tola John Odule et al., Nigerian Journal of Physics, 2026. Key `Odule2026SimulationValidation`. DOI 10.62292/njp.v35i3.2026.566 | https://doi.org/10.62292/njp.v35i3.2026.566
- PDF: `research/papers/pdf/2026_Odule_SimulationValidationLow.pdf`
- Summary: GNS3 + VMware 24-node SME network, flat vs micro-segmented (pfSense, Zeek, OpenDaylight, default-deny ACLs); Patient Zero attacker with Nmap/Metasploit. Simulation/tool: GNS3; configs shown: partial.
- Similarity (High): Flat baseline vs segmented design with a 'Patient Zero' compromised node doing recon and lateral movement; quantifies reachable nodes and blast radius. Conceptually the same experiment as ours.
- Metrics: Reachable nodes 24->2 (-91.7%); lateral moves -94.4% (18->1); time-to-compromise 14 -> >185 min; blast radius -92%; latency +0.6 ms; throughput 94% of baseline; traffic visibility 5%->98%; cost
- What we can borrow: Blast-radius and time-to-compromise metrics; latency/throughput overhead measurement; 'Patient Zero' framing; visibility metric. Novelty threat for the method (see SUMMARY).

### P15 [Medium] Performance Analysis of Software-Defined Networks to Mitigate Private VLAN Attacks
- David Álvarez et al., Sensors, 2023. Key `Alvarez2023PerformanceAnalysis`. DOI 10.3390/s23041747 | https://doi.org/10.3390/s23041747
- PDF: link only
- Summary: Emulates a corporate PVLAN scenario, executes a PVLAN attack and compares ACL vs SDN mitigation performance. Simulation/tool: emulation (SDN); configs shown: no.
- Similarity (Medium): Compares ACL-based vs SDN mitigation of a VLAN-layer (PVLAN) attack with performance metrics; layered segmentation + defence-in-depth.
- Metrics: CPU use, memory use, communication delay, packet loss, power consumption
- What we can borrow: Overhead metrics (CPU, delay, loss) and private-VLAN as an extra isolation tool for same-class devices.

### P19 [Medium] Network Security Strategy with VLANs and Access Control Lists: Case Studies and Implementation
- Dhafa Nugraha Djuanda, Information Technology and Systems, 2024. Key `Djuanda2024NetworkSecurity`. DOI 10.58777/its.v2i1.305 | https://doi.org/10.58777/its.v2i1.305
- PDF: `research/papers/pdf/2024_Djuanda_NetworkSecurityStrategy.pdf`
- Summary: Designs and implements VLAN and ACL network security at a financial branch office. Simulation/tool: Packet Tracer (tools) / real-site design; configs shown: partial.
- Similarity (Medium): VLAN + ACL security design at an organisation with testing via Kali/Wireshark.
- Metrics: Throughput, latency, security tests (details in paper)
- What we can borrow: Example VLAN numbering/ACL narrative; testing with Kali.

### P48 [Medium] Buenas prácticas de seguridad para redes empresariales: Implementación de VLANs, ACLs y Router-on-a-Stick
- Joselyn Katiuska Franco Avila et al., Dialnet (Universidad de la Rioja), 2026. Key `AvilaPesantez2026HospitalSwitchPolicies`. No DOI | https://dialnet.unirioja.es/servlet/oaiart?codigo=10763167
- PDF: link only
- Summary: Best-practice implementation of VLAN segmentation, ACLs and router-on-a-stick for isolating sensitive zones. Simulation/tool: none; configs shown: partial.
- Similarity (Medium): VLANs + ACLs + router-on-a-stick best practices for enterprise networks, least privilege.
- Metrics: Not verified
- What we can borrow: Router-on-a-stick vs SVI discussion for D1.


## B. Hospital and smart-hospital network design, hardening and healthcare segmentation

### P07 [High] A three-tier microsegmentation framework for enterprise networks under Zero Trust Architecture
- Hari NN et al., Alexandria Engineering Journal, 2026. Key `Hari2026ThreeTier`. DOI 10.1016/j.aej.2026.03.014 | https://doi.org/10.1016/j.aej.2026.03.014
- PDF: link only
- Summary: Three-tier microsegmentation (network ZTOG plane with DNOS algorithm, ZFLOW system-level, eBPF endpoint agents) evaluated on hospital and campus datasets. Simulation/tool: real hospital dataset; configs shown: no.
- Similarity (High): Microsegmentation evaluated with data from a super-speciality hospital; exposure metric (ENICE) is analogous to our attack-surface %.
- Metrics: ENICE (internal connectivity exposure) -99%+; attack paths -99.7%; resilience +60-90%; ~130 ms end-to-end latency at 1000 users
- What we can borrow: Exposure-reduction and attack-path-count metrics; scalability/latency study; claim that fragmented policies across layers enable lateral movement.

### P14 [High] Secure and Adaptive IoT Network Architecture for Smart Hospitals with Load Balancing in Diabetic Care Systems
- Ala’ S Mughaid et al., International Journal of Advances in Soft Computing and its Applications, 2026. Key `Mughaid2026SecureAdaptive`. DOI 10.15849/ijasca.v18i1.21 | https://doi.org/10.15849/ijasca.v18i1.21
- PDF: `research/papers/pdf/2026_Mughaid_SecureAdaptiveIot.pdf`
- Summary: Smart-hospital IoT architecture (cloud, hospital network, home network, balanced load) simulated in Packet Tracer; evaluated with latency/throughput and pen-testing. Simulation/tool: Packet Tracer; configs shown: partial.
- Similarity (High): Packet Tracer smart-hospital IoT network with ACLs and penetration testing; closest hospital+PT paper with a security evaluation.
- Metrics: Latency and throughput under traffic load; penetration testing; scalability/reliability simulation
- What we can borrow: Latency/throughput load tests to quantify overhead of our ACL/ASA path; layered smart-hospital zone naming.

### P47 [High] Cybersecurity Policies for Network Switching Devices in Hospital Data Centers: A Case Study
- Diego Fernando Ávila Pesantez et al., ESPOCH Congresses The Ecuadorian Journal of S T E A M, 2022. Key `AvilaPesantez2022HospitalSwitchPolicies`. DOI 10.18502/espoch.v2i2.11413 | https://doi.org/10.18502/espoch.v2i2.11413
- PDF: `research/papers/pdf/2022_AvilaPesantez_HospitalSwitchPolicies.pdf`
- Summary: Real hospital data-center network (22 VLANs) analysed; EVE-NG scenario with Huawei switches (VLAN 10/20/25/40) attacked with Yersinia/Dsniff, then hardened with port security, DHCP snooping, BPDU protection. CLI snippets printed. Simulation/tool: EVE-NG (Huawei); configs shown: yes.
- Similarity (High): Hospital network hardening against Layer-2 attacks (ARP spoofing, DHCP starvation, STP, VLAN hopping/double-tagging) with port security, DHCP snooping, BPDU protection - same control family as our D3.
- Metrics: 98% of vulnerabilities mitigated; 10 attack scenarios; OpenVAS and Yersinia scans; ISO 27032 policy phases
- What we can borrow: L2 attack list and before/after vulnerability count method (OpenVAS/Yersinia); ISO 27032 style policy mapping; DAI/ARP checks to add.

### P12 [Medium] Smart Hospital Network Enterprise Design for Medicine City Hospital via Packet Tracer
- Mohammed Jassim, Anbar journal for engineering sciences/Mağallaẗ al-anbār li-l-ʻulūm al-handasiyyaẗ, 2024. Key `Jassim2024SmartHospital`. DOI 10.37649/aengs.2024.144601.1065 | https://doi.org/10.37649/aengs.2024.144601.1065
- PDF: link only
- Summary: Discusses designing an intelligent hospital management network in Cisco Packet Tracer, requirements and cost/maintenance benefits. Simulation/tool: Packet Tracer; configs shown: partial.
- Similarity (Medium): Packet Tracer smart-hospital enterprise design (Iraq).
- Metrics: Not verified (abstract describes requirements and benefits only)
- What we can borrow: Hospital zone list (wards, labs, admin) as topology inspiration; cite as existing PT hospital design lacking security evaluation.

### P13 [Medium] Adaptive Traffic Segregation and Simulation in Software-Defined Healthcare Networks
- Bhargavi Dalal et al., Atlantis highlights in engineering/Atlantis Highlights in Engineering, 2026. Key `Dalal2026AdaptiveTraffic`. DOI 10.2991/978-94-6239-727-9_9 | https://doi.org/10.2991/978-94-6239-727-9_9
- PDF: `research/papers/pdf/2026_Dalal_AdaptiveTrafficSegregation.pdf`
- Summary: Studies patient-related traffic in SDN healthcare environments, comparing traffic-classification approaches and anomaly detection. Simulation/tool: none (review-style; cites Mininet/ONOS studies); configs shown: no.
- Similarity (Medium): SDN-based segregation and analysis of patient traffic in healthcare networks.
- Metrics: Qualitative; flow- vs packet-based analysis comparison
- What we can borrow: SDN as an alternative enforcement point to cite in future work; traffic classes for clinical flows.

### P43 [Low] A unified IoT architectural model for smart hospitals: enhancing interoperability, security, and efficiency through clinical information systems (CIS)
- Fatemeh Yadegari et al., Journal Of Big Data, 2025. Key `Yadegari2025UnifiedIot`. DOI 10.1186/s40537-025-01197-4 | https://doi.org/10.1186/s40537-025-01197-4
- PDF: `research/papers/pdf/2025_Yadegari_UnifiedIotArchitectural.pdf`
- Summary: Unified IoT architecture model for smart hospitals centred on the Clinical Information System. Simulation/tool: none; configs shown: no.
- Similarity (Low): Smart-hospital IoT architecture with security discussion.
- Metrics: Architecture comparison (interoperability, efficiency)
- What we can borrow: Reference architecture to justify our zone layout.


## C. Zero trust and security for healthcare / IoMT (conceptual and system papers)

### P01 [Medium] Trust No One? A Framework for Assisting Healthcare Organisations in Transitioning to a Zero-Trust Network Architecture
- Dan Tyler et al., Applied Sciences, 2021. Key `Tyler2021TrustNo`. DOI 10.3390/app11167499 | https://doi.org/10.3390/app11167499
- PDF: link only
- Summary: Argues healthcare perimeter-only security leaves a soft interior and proposes a transition framework to zero trust. Simulation/tool: none; configs shown: no.
- Similarity (Medium): Framework for healthcare organisations moving from perimeter to zero-trust network architecture; notes unmanageable medical devices and legacy systems as barriers.
- Metrics: None (framework)
- What we can borrow: Core citation for motivation (flat internal trust, unmanageable devices); framework steps to map to D0-D3.

### P04 [Medium] Research on Medical Security System Based on Zero Trust
- Zhiqiang Wang et al., Sensors, 2023. Key `Wang2023ResearchMedical`. DOI 10.3390/s23073774 | https://doi.org/10.3390/s23073774
- PDF: link only
- Summary: Zero-trust medical security system with RBAC plus behaviour risk scoring to protect devices and data. Simulation/tool: simulation (unspecified); configs shown: no.
- Similarity (Medium): Zero-trust medical security system with dynamic access control; feasibility via simulation.
- Metrics: Feasibility simulation; behaviour risk/trust value
- What we can borrow: Risk-score based policy as future work.

### P05 [Medium] MEDIotWALL: Securing Smart Healthcare Environments Through IoT Firewalls
- Irene Gosálvez-White et al., Sensors, 2025. Key `GosalvezWhite2025Mediotwall`. DOI 10.3390/s25196235 | https://doi.org/10.3390/s25196235
- PDF: link only
- Summary: MEDIotWALL: two-tier healthcare IoT firewall combining distributed traffic monitoring and AI-driven rule generation with human supervision. Simulation/tool: prototype/testbed (not verified); configs shown: partial.
- Similarity (Medium): IoMT-specific firewall architecture with rule generation, regulation-aware; same goal of least-privilege flow rules for medical devices.
- Metrics: Cost-efficiency and effectiveness (details not verified)
- What we can borrow: Idea of deriving per-device allow-lists from observed traffic; regulation (HIPAA/GDPR) mapping of ACEs.

### P22 [Medium] Modeling, Detecting, and Mitigating Threats Against Industrial Healthcare Systems: A Combined Software Defined Networking and Reinforcement Learning Approach
- Panagiotis I. Radoglou Grammatikis et al., IEEE Transactions on Industrial Informatics, 2021. Key `Grammatikis2021ModelingDetecting`. DOI 10.1109/tii.2021.3093905 | https://doi.org/10.1109/tii.2021.3093905
- PDF: `research/papers/pdf/2021_Grammatikis_ModelingDetectingMitigating.pdf`
- Summary: Combines SDN and reinforcement learning to model, detect and mitigate attacks against IEC 60870-5-104 industrial healthcare systems. Simulation/tool: real testbed (SDN); configs shown: no.
- Similarity (Medium): SDN-based detect-and-mitigate pipeline for healthcare protocol attacks, with automatic flow-rule mitigation.
- Metrics: Detection and mitigation effectiveness (see paper)
- What we can borrow: Automated reactive isolation as a future-work contrast to static ACLs.

### P46 [Medium] Hybrid Approach to Secure Legacy Healthcare Systems: Integrating Zero Trust and Traditional Security Models
- Bashayer Alotaibi et al., International Journal of Engineering Trends and Technology, 2025. Key `Alotaibi2025HybridZeroTrustLegacy`. DOI 10.14445/22315381/ijett-v73i5p103 | https://doi.org/10.14445/22315381/ijett-v73i5p103
- PDF: `research/papers/pdf/2025_Alotaibi_HybridZeroTrustLegacy.pdf`
- Summary: Proposes combining Zero Trust and traditional security for legacy healthcare IT, with micro-segmentation as a core mechanism. Simulation/tool: none (conceptual; EVE-NG mentioned); configs shown: no.
- Similarity (Medium): Hybrid zero-trust plus perimeter for legacy healthcare systems (Windows XP/7); micro-segmentation as a component.
- Metrics: Qualitative; framework
- What we can borrow: Motivation for unpatchable legacy devices; NIST ZTA alignment text.

### P02 [Low] A Security Awareness and Protection System for 5G Smart Healthcare Based on Zero-Trust Architecture
- Baozhan Chen et al., IEEE Internet of Things Journal, 2020. Key `Chen2020SecurityAwareness`. DOI 10.1109/jiot.2020.3041042 | https://doi.org/10.1109/jiot.2020.3041042
- PDF: `research/papers/pdf/2020_Chen_SecurityAwarenessProtection.pdf`
- Summary: Security awareness and protection platform built on ZTA for 5G smart medical platforms with continuous authentication and behaviour analysis. Simulation/tool: real testbed; configs shown: no.
- Similarity (Low): Zero-trust security system for 5G smart healthcare with fine-grained access control.
- Metrics: Industrial-grade test; access-control and situational-awareness functions
- What we can borrow: Subject/object/behaviour/environment decision model as a future dynamic-policy extension.

### P03 [Low] Enabling Zero Trust Security in IoMT Edge Network
- Maha Ali Allouzi et al., arXiv (Cornell University), 2024. Key `Allouzi2024EnablingZero`. DOI 10.48550/arxiv.2402.10389 | https://doi.org/10.48550/arxiv.2402.10389
- PDF: `research/papers/pdf/2024_Allouzi_EnablingZeroTrust.pdf`
- Summary: Soter: trust-negotiation-based zero-trust access control for IoMT using identity, device health and location. Simulation/tool: prototype; configs shown: no.
- Similarity (Low): Zero-trust authentication for IoMT edge (Soter).
- Metrics: Trust negotiation, access decisions (details not verified)
- What we can borrow: Device-health-conditioned access as a NAC/802.1X extension.

### P37 [Low] Post-quantum cognitive zero trust architecture for healthcare IoT devices
- Hashim Hussain et al., PLoS ONE, 2026. Key `Hussain2026PostQuantum`. DOI 10.1371/journal.pone.0348600 | https://doi.org/10.1371/journal.pone.0348600
- PDF: `research/papers/pdf/2026_Hussain_PostQuantumCognitive.pdf`
- Summary: Cognitive ZTA for resource-constrained healthcare IoT with post-quantum protection. Simulation/tool: simulation; configs shown: no.
- Similarity (Low): Zero-trust for healthcare IoT with post-quantum crypto.
- Metrics: Latency overhead, security under classical/quantum attacks
- What we can borrow: Latency-overhead reporting style.

### P40 [Low] Solutions for Mitigating Cybersecurity Risks Caused by Legacy Software in Medical Devices: A Scoping Review
- Tom Tervoort et al., IEEE Access, 2020. Key `Tervoort2020SolutionsMitigating`. DOI 10.1109/access.2020.2984376 | https://doi.org/10.1109/access.2020.2984376
- PDF: `research/papers/pdf/2020_Tervoort_SolutionsMitigatingCybersecurity.pdf`
- Summary: Scoping review of solutions that mitigate risk from unpatchable legacy software on medical devices. Simulation/tool: none; configs shown: no.
- Similarity (Low): Scoping review of mitigations for legacy software in medical devices.
- Metrics: Review categories
- What we can borrow: Justification that unpatchable devices need compensating controls.

### P41 [Low] Using attack graphs to defend healthcare systems from cyberattacks: a longitudinal empirical study
- Hüseyin Ünözkan et al., Network Modeling Analysis in Health Informatics and Bioinformatics, 2022. Key `Unozkan2022AttackGraphs`. DOI 10.1007/s13721-022-00391-1 | https://doi.org/10.1007/s13721-022-00391-1
- PDF: link only
- Summary: Uses attack graphs to defend healthcare systems from cyberattacks. Simulation/tool: none; configs shown: no.
- Similarity (Low): Attack graphs for healthcare cyber defence (longitudinal study).
- Metrics: Attack-graph based vulnerability analysis
- What we can borrow: Attack-graph/reachability formalism for a formal reachability comparison.

### P45 [Low] Attack Graph Modeling for Implantable Pacemaker
- Mariam Ibrahim et al., Biosensors, 2020. Key `Ibrahim2020AttackGraph`. DOI 10.3390/bios10020014 | https://doi.org/10.3390/bios10020014
- PDF: link only
- Summary: Models a pacemaker remote monitoring system in AADL and generates attack graphs by model checking. Simulation/tool: formal model (AADL, JKind); configs shown: no.
- Similarity (Low): Attack-graph and model-checking for pacemaker remote monitoring.
- Metrics: Model-checked attack graph
- What we can borrow: Formal verification as a possible reachability check.


## D. Micro-segmentation for IoT/IIoT and segmentation practice

### P10 [Medium] Why Network Segmentation Projects Fail
- Rohit Dube, arXiv (Cornell University), 2026. Key `Dube2026WhyNetwork`. DOI 10.48550/arxiv.2604.08632 | https://doi.org/10.48550/arxiv.2604.08632
- PDF: `research/papers/pdf/2026_Dube_WhyNetworkSegmentation.pdf`
- Summary: Survey-based explanation of segmentation project failures using a two-part failure framework. Simulation/tool: survey (n=400); configs shown: no.
- Similarity (Medium): Empirical evidence why segmentation projects fail; relevant to config complexity/operability argument.
- Metrics: Survey of 400 practitioners, latent-class analysis
- What we can borrow: Supports our config-complexity metric (lines, ACEs) as a proxy for operability.

### P11 [Medium] Implementation of Dynamic Microsegmentation for a Multi-Robot Network
- Vishwam Raval et al., arXiv (Cornell University), 2026. Key `Raval2026ImplementationDynamic`. DOI 10.48550/arxiv.2610.30102 | https://doi.org/10.48550/arxiv.2610.30102
- PDF: `research/papers/pdf/2026_Raval_ImplementationDynamicMicrosegmentation.pdf`
- Summary: Dynamic microsegmentation by asset functional and health tags on a multi-robot IoT network. Simulation/tool: real testbed (Raspberry Pi robots, commercial tool); configs shown: no.
- Similarity (Medium): Lab demonstration that tag-based dynamic microsegmentation isolates an infected IoT asset automatically without disrupting others.
- Metrics: Isolation delay, operation continuity
- What we can borrow: Health-tag-driven quarantine as an extension of our static policy.

### P09 [Low] An Explainable Federated Framework for Zero Trust Micro-Segmentation in IIoT Networks
- Muhammad Liman Gambo et al., arXiv (Cornell University), 2026. Key `Gambo2026ExplainableFederated`. DOI 10.48550/arxiv.2603.24754 | https://doi.org/10.48550/arxiv.2603.24754
- PDF: `research/papers/pdf/2026_Gambo_ExplainableFederatedFramework.pdf`
- Summary: Federated explainable ML framework to derive micro-segments for IIoT networks. Simulation/tool: dataset-ML; configs shown: no.
- Similarity (Low): Micro-segmentation for IIoT using federated explainable ML.
- Metrics: Segmentation accuracy, explainability
- What we can borrow: Dynamic/ML segmentation as future work.

### P23 [Low] Flexible zero trust architecture for the cybersecurity of industrial IoT infrastructures
- Claudio Zanasi et al., Ad Hoc Networks, 2024. Key `Zanasi2024FlexibleZero`. DOI 10.1016/j.adhoc.2024.103414 | https://doi.org/10.1016/j.adhoc.2024.103414
- PDF: link only
- Summary: Zero trust architecture adapted to heterogeneous IIoT infrastructure. Simulation/tool: not verified; configs shown: no.
- Similarity (Low): Flexible zero-trust for IIoT.
- Metrics: Architecture evaluation (abstract-level)
- What we can borrow: Cite for IoT ZT adaptation.

### P28 [Low] A novel zero-trust network access control scheme based on the security profile of devices and users
- Pedro García‐Teodoro et al., Computer Networks, 2022. Key `Garciateodoro2022NovelZero`. DOI 10.1016/j.comnet.2022.109068 | https://doi.org/10.1016/j.comnet.2022.109068
- PDF: link only
- Summary: NAC scheme driven by device and user security profile. Simulation/tool: not verified; configs shown: no.
- Similarity (Low): Zero-trust network access control based on device/user security profile.
- Metrics: Not verified
- What we can borrow: Device-profile based admission as NAC extension.


## E. Layer-2 attack and mitigation studies (DHCP, port security, misconfiguration)

### P16 [Medium] Network security misconfigurations in Spanish organisations: An empirical study
- David Álvarez et al., Computer Networks, 2026. Key `Alvarez2026NetworkSecurity`. DOI 10.1016/j.comnet.2026.112631 | https://doi.org/10.1016/j.comnet.2026.112631
- PDF: link only
- Summary: Assesses link-layer, network-layer and higher-layer vulnerabilities across 61 Spanish organisations. Simulation/tool: real organisations; configs shown: no.
- Similarity (Medium): Empirical Layer 2/3 misconfiguration assessment of 61 organisations; lateral movement exposure.
- Metrics: Share of organisations vulnerable (>93%)
- What we can borrow: Checklist of L2/L3 misconfigurations to include in attack suite.

### P18 [Medium] Analysis of Different Types of Network Attacks on the GNS3 Platform
- Resul Daş et al., Sakarya University Journal of Computer and Information Sciences, 2020. Key `Das2020AnalysisDifferent`. DOI 10.35377/saucis.03.03.721364 | https://doi.org/10.35377/saucis.03.03.721364
- PDF: `research/papers/pdf/2020_Das_AnalysisDifferentTypes.pdf`
- Summary: Models common network attacks in GNS3 and analyses security. Simulation/tool: GNS3; configs shown: partial.
- Similarity (Medium): Attack modelling (DDoS, SQLi, XSS) on GNS3 with firewall and routers.
- Metrics: Attack effects on servers (see paper)
- What we can borrow: Emulation-based attack methodology.

### P35 [Medium] DESIGNING A SECURE NETWORK SOLUTION AGAINST DHCP ATTACKS
- Salim A. Mohammed Ali et al., Iraqi Journal of Information & Communications Technology, 2021. Key `Ali2021DesigningSecure`. DOI 10.31987/ijict.1.1.175 | https://doi.org/10.31987/ijict.1.1.175
- PDF: `research/papers/pdf/2021_Ali_DesigningSecureNetwork.pdf`
- Summary: Designs a network solution against DHCP attacks in GNS3 with real OS images. Simulation/tool: GNS3 + VMware; configs shown: partial.
- Similarity (Medium): Implements DHCP attacks (starvation, rogue server) and tests three countermeasures.
- Metrics: Attack success before/after countermeasure
- What we can borrow: Rogue-DHCP attack procedure and countermeasure testing.

### P36 [Medium] Descriptive Analysis and ANOVA Test with File Sending on Computer Networks Attacked with Rogue's Dynamic Host Configuration Protocol (DHCP)
- Hero Wintolo et al., Jurnal Ilmiah Teknik Elektro Komputer dan Informatika, 2023. Key `Wintolo2023DescriptiveAnalysis`. DOI 10.26555/jiteki.v9i2.26167 | https://doi.org/10.26555/jiteki.v9i2.26167
- PDF: link only
- Summary: Compares file-transfer time in normal, rogue-DHCP-attacked and mitigated networks using ANOVA. Simulation/tool: not verified; configs shown: no.
- Similarity (Medium): Rogue DHCP attack and DHCP snooping mitigation with a statistical test.
- Metrics: ANOVA on file transfer time (p = 0.004)
- What we can borrow: ANOVA/descriptive statistics for performance comparisons.

### P44 [Medium] Improving Switch Security Against MITM Attacks Using DHCP Snooping and Port Security
- Bashar Alhajahmad, Uluslararası Yönetim Bilişim Sistemleri ve Bilgisayar Bilimleri Dergisi, 2025. Key `Alhajahmad2025ImprovingSwitch`. DOI 10.33461/uybisbbd.1766477 | https://doi.org/10.33461/uybisbbd.1766477
- PDF: `research/papers/pdf/2025_Alhajahmad_ImprovingSwitchSecurity.pdf`
- Summary: Combines DHCP snooping and port security on L2 switches to defeat DHCP spoofing. Simulation/tool: Packet Tracer; configs shown: yes.
- Similarity (Medium): DHCP snooping + port security configuration in simulation against DHCP spoofing, including trusted-port abuse.
- Metrics: Attack blocked or not; stability
- What we can borrow: Port-security + DHCP snooping interaction (trusted-port abuse) test.


## F. Surveys, datasets, IDS and background

### P17 [Low] Hybrid IoT Cyber Range
- Karl Edvard Balto et al., Sensors, 2023. Key `Balto2023HybridIot`. DOI 10.3390/s23063071 | https://doi.org/10.3390/s23063071
- PDF: link only
- Summary: Hybrid emulation/hardware IoT cyber range. Simulation/tool: real testbed + emulation; configs shown: no.
- Similarity (Low): IoT cyber range.
- Metrics: None
- What we can borrow: Cyber-range as future validation platform.

### P20 [Low] Improve Security in Smart Cities Based on IoT, Solve Cyber Electronic Attacks with Technology by using Packet Tracer
- Raed Ahmed Alhamarneh, International Journal of Network Security & Its Applications, 2021. Key `Alhamarneh2021ImproveSecurity`. DOI 10.5121/ijnsa.2021.13605 | https://doi.org/10.5121/ijnsa.2021.13605
- PDF: `research/papers/pdf/2021_Alhamarneh_ImproveSecuritySmart.pdf`
- Summary: Simulates smart-city IoT with security measures in Packet Tracer. Simulation/tool: Packet Tracer; configs shown: partial.
- Similarity (Low): Packet Tracer IoT smart-city security simulation.
- Metrics: Connectivity ping results
- What we can borrow: PT IoT device registration example.

### P21 [Low] Safe and Secure Smart Home using Cisco Packet Tracer
- Shivansh Walia et al., arXiv (Cornell University), 2023. Key `Walia2023SafeSecure`. DOI 10.48550/arxiv.2304.11827 | https://doi.org/10.48550/arxiv.2304.11827
- PDF: `research/papers/pdf/2023_Walia_SafeSecureSmart.pdf`
- Summary: Smart home design in Packet Tracer. Simulation/tool: Packet Tracer; configs shown: partial.
- Similarity (Low): Packet Tracer smart-home IoT.
- Metrics: Functional tests
- What we can borrow: PT IoT usage.

### P24 [Low] Zero Trust Architecture (ZTA): A Comprehensive Survey
- Naeem Syed et al., IEEE Access, 2022. Key `Syed2022ZeroTrust`. DOI 10.1109/access.2022.3174679 | https://doi.org/10.1109/access.2022.3174679
- PDF: link only
- Summary: Survey of zero trust. Simulation/tool: none; configs shown: no.
- Similarity (Low): ZTA survey.
- Metrics: None
- What we can borrow: NIST 800-207 citation.

### P25 [Low] Migrating to Zero Trust Architecture: Reviews and Challenges
- Songpon Teerakanok et al., Security and Communication Networks, 2021. Key `Teerakanok2021MigratingZero`. DOI 10.1155/2021/9947347 | https://doi.org/10.1155/2021/9947347
- PDF: link only
- Summary: Reviews ZTA migration per NIST SP 800-207. Simulation/tool: none; configs shown: no.
- Similarity (Low): Migration to ZTA review based on SP 800-207.
- Metrics: None
- What we can borrow: Migration steps.

### P26 [Low] A Comprehensive Framework for Migrating to Zero Trust Architecture
- Pacharee Phiayura et al., IEEE Access, 2023. Key `Phiayura2023ComprehensiveFramework`. DOI 10.1109/access.2023.3248622 | https://doi.org/10.1109/access.2023.3248622
- PDF: link only
- Summary: Comprehensive ZTA migration framework. Simulation/tool: none; configs shown: no.
- Similarity (Low): ZTA migration framework.
- Metrics: None
- What we can borrow: Migration framework.

### P27 [Low] Verify and trust: A multidimensional survey of zero-trust security in the age of IoT
- Muhammad Ajmal Azad et al., Internet of Things, 2024. Key `Azad2024VerifyTrust`. DOI 10.1016/j.iot.2024.101227 | https://doi.org/10.1016/j.iot.2024.101227
- PDF: link only
- Summary: Multidimensional survey of zero trust in IoT. Simulation/tool: none; configs shown: no.
- Similarity (Low): ZT for IoT survey.
- Metrics: None
- What we can borrow: IoT ZT taxonomy.

### P29 [Low] CICIoMT2024: A benchmark dataset for multi-protocol security assessment in IoMT
- Sajjad Dadkhah et al., Internet of Things, 2024. Key `Dadkhah2024CiciomtBenchmark`. DOI 10.1016/j.iot.2024.101351 | https://doi.org/10.1016/j.iot.2024.101351
- PDF: link only
- Summary: Benchmark dataset for multi-protocol IoMT security. Simulation/tool: dataset; configs shown: no.
- Similarity (Low): IoMT attack dataset (CICIoMT2024).
- Metrics: Dataset of IoMT attacks
- What we can borrow: IoMT protocol mix for realistic traffic.

### P30 [Low] An Anomaly-Based Intrusion Detection System for Internet of Medical Things Networks
- Georgios Zachos et al., Electronics, 2021. Key `Zachos2021AnomalyIntrusion`. DOI 10.3390/electronics10212562 | https://doi.org/10.3390/electronics10212562
- PDF: link only
- Summary: Anomaly-based IDS for IoMT. Simulation/tool: dataset-ML; configs shown: no.
- Similarity (Low): Anomaly IDS for IoMT.
- Metrics: Detection accuracy
- What we can borrow: IDS as additional layer.

### P31 [Low] An Intrusion Detection System for Internet of Medical Things
- Geethapriya Thamilarasu et al., IEEE Access, 2020. Key `Thamilarasu2020IntrusionDetection`. DOI 10.1109/access.2020.3026260 | https://doi.org/10.1109/access.2020.3026260
- PDF: `research/papers/pdf/2020_Thamilarasu_IntrusionDetectionSystem.pdf`
- Summary: IDS for IoMT evaluated by simulation. Simulation/tool: simulation; configs shown: no.
- Similarity (Low): IDS for IoMT.
- Metrics: Detection accuracy, resource usage
- What we can borrow: IDS layer.

### P32 [Low] Efficient Anomaly Detection for Smart Hospital IoT Systems
- Abdel Mlak Said et al., Sensors, 2021. Key `Said2021EfficientAnomaly`. DOI 10.3390/s21041026 | https://doi.org/10.3390/s21041026
- PDF: link only
- Summary: Anomaly detection in smart hospital IoT. Simulation/tool: dataset-ML; configs shown: no.
- Similarity (Low): Smart hospital IoT anomaly detection.
- Metrics: Detection metrics
- What we can borrow: Smart hospital IoT scenario.

### P33 [Low] Security Analysis for Smart Healthcare Systems
- Mariam Ibrahim et al., Sensors, 2024. Key `Ibrahim2024SecurityAnalysis`. DOI 10.3390/s24113375 | https://doi.org/10.3390/s24113375
- PDF: link only
- Summary: Security analysis for smart healthcare systems. Simulation/tool: none; configs shown: no.
- Similarity (Low): Security analysis of smart healthcare.
- Metrics: Threat taxonomy
- What we can borrow: Threat list.

### P34 [Low] Detecting lateral movement: A systematic survey
- Christos Smiliotopoulos et al., Heliyon, 2024. Key `Smiliotopoulos2024DetectingLateral`. DOI 10.1016/j.heliyon.2024.e26317 | https://doi.org/10.1016/j.heliyon.2024.e26317
- PDF: link only
- Summary: Systematic survey of lateral movement detection. Simulation/tool: none; configs shown: no.
- Similarity (Low): Survey of lateral-movement detection mapped to ATT&CK.
- Metrics: None
- What we can borrow: ATT&CK lateral movement tactic mapping.

### P38 [Low] Security and Privacy Management in Internet of Medical Things (IoMT): A Synthesis
- Rachida Hireche et al., Journal of Cybersecurity and Privacy, 2022. Key `Hireche2022SecurityPrivacy`. DOI 10.3390/jcp2030033 | https://doi.org/10.3390/jcp2030033
- PDF: link only
- Summary: Security and privacy management synthesis for IoMT. Simulation/tool: none; configs shown: no.
- Similarity (Low): IoMT security survey.
- Metrics: None
- What we can borrow: Threat background.

### P39 [Low] A Comprehensive Review of the State-of-the-Art on Security and Privacy Issues in Healthcare
- Antonio López Martínez et al., ACM Computing Surveys, 2022. Key `Martinez2022ComprehensiveReview`. DOI 10.1145/3571156 | https://doi.org/10.1145/3571156
- PDF: link only
- Summary: Review of healthcare cybersecurity. Simulation/tool: none; configs shown: no.
- Similarity (Low): Healthcare security survey.
- Metrics: None
- What we can borrow: Background.

### P42 [Low] A Survey: To Govern, Protect, and Detect Security Principles on Internet of Medical Things (IoMT)
- Taqwa Ahmed Alhaj et al., IEEE Access, 2022. Key `Alhaj2022SurveyGovern`. DOI 10.1109/access.2022.3225038 | https://doi.org/10.1109/access.2022.3225038
- PDF: link only
- Summary: Survey of IoMT security principles. Simulation/tool: none; configs shown: no.
- Similarity (Low): IoMT security survey.
- Metrics: None
- What we can borrow: Background.
