# Plan: Containing compromised medical IoT devices with network segmentation in a smart-hospital network (Packet Tracer)

## Context
The task is a Computer Networks project: build a network in Cisco Packet Tracer and simulate it. The result should be good enough for a research paper, and the topic should not be one that is already covered all over the internet.

Common topics I checked:
- **Saturated:** The RIP/OSPF/EIGRP comparison has many existing papers built in Packet Tracer.
- **Common:** Generic VLAN or security labs and HSRP/STP campus labs are tutorial material.
- **Little coverage:** Searches found no Packet Tracer study on segmenting a hospital's medical IoT (IoMT) devices to contain a compromised device. Existing work on IoMT micro-segmentation uses vendor white papers or ML on datasets such as UNSW-NB15 and IoTID20, not a reproducible network simulation. That gap is this paper's contribution.

**Proposed title:** *"From Flat to Micro-Segmented: A Simulation-Based Evaluation of Lateral-Movement Containment for Compromised IoMT Devices in a Smart-Hospital Network"*

**Research questions**
1. How much does each level of segmentation shrink the attack surface reachable from a compromised medical IoT device?
2. Does tighter segmentation break legitimate clinical and IoT functions?
3. What does each level cost in configuration complexity and in overhead on legitimate traffic?

## Approach: 4 designs × the same attack set
Build one hospital network and save it as 4 `.pkt` files. Only the security policy changes between files (the controlled variable).

| Design | Description |
|---|---|
| **D0 Flat** | One VLAN, everything can reach everything (baseline) |
| **D1 VLAN-only** | Devices split by role into VLANs, inter-VLAN routing with no filtering. Shows that VLANs alone do not stop lateral movement |
| **D2 Zone ACLs** | D1 plus coarse extended ACLs on the core switch's SVIs (IoT zone ↔ server zone only) |
| **D3 Micro-segmentation** | One VLAN per device class, least-privilege ACLs (only the required port to the required server), an ASA 5506-X in front of the clinical-server zone, port security, DHCP snooping, SSH-only management VLAN |

### Topology (Packet Tracer 8.x)
- **Edge:** ISR 4331 router, with NAT and a static default route to a simulated "Internet/ISP" router and server.
- **Core:** 3650 multilayer switch for inter-VLAN routing, with ACLs on the SVIs.
- **Server zone:** Behind an ASA 5506-X in D3. Holds the EHR web server (HTTP/HTTPS), the IoT Registration Server, DHCP/DNS and a Syslog server.
- **Access:** 3 × 2960 switches for Ward A, Ward B and Admin/Building, plus a wireless access point / home gateway for wireless IoT and guests.
- **End devices:** Staff PCs and laptops. The medical IoT devices are PT IoT devices standing in for patient monitors and infusion pumps, built from sensors and an SBC. Building IoT devices are a smart door, fire monitor, fan/HVAC and webcam. Guest devices are a smartphone and a tablet.
- **"Compromised" node:** A laptop placed in the medical-IoT VLAN, because PT IoT devices cannot run attack traffic. Repeat the experiments with it in 3 locations: Ward A, Ward B and building IoT.

### Addressing / VLAN plan (10.10.VLAN.0/24)
| VLAN | Name | Subnet | Gateway |
|---|---|---|---|
| 10 | Staff | 10.10.10.0/24 | .1 |
| 20 | Clinical servers | 10.10.20.0/24 | .1 (ASA inside in D3) |
| 30 | Medical IoT (D3 splits it into 31 Monitors, 32 Infusion) | 10.10.30.0/24 | .1 |
| 40 | Building IoT | 10.10.40.0/24 | .1 |
| 50 | Guest Wi-Fi | 10.10.50.0/24 | .1 |
| 99 | Management | 10.10.99.0/24 | .1 |

### Attack / test scenarios (run against every design)
1. **Reconnaissance sweep:** Ping every host and gateway from the compromised node.
2. **Unauthorized data access:** Open the EHR server over HTTP from the IoT node.
3. **Device hijack:** Log in to the IoT Registration Server or control another IoT device.
4. **Infrastructure takeover:** Telnet or SSH to a switch or router management IP.
5. **Rogue DHCP server** plugged into an access port.
6. **Unauthorized device / MAC spoof** on a ward port (port security).
7. **Guest → clinical pivot:** From a guest device to the EHR server.

### Metrics (for tables and graphs in the paper)
- **Attack surface:** % of hosts and services reachable from the compromised node.
- **Attack success matrix:** 7 attacks × 4 designs, each marked success or blocked.
- **Functional preservation:** % of legitimate flows still working, such as monitors reporting to the registration server, staff reaching the EHR, IoT automation rules firing, and DHCP leases.
- **Configuration complexity:** Number of ACEs, total config lines, and number of security features per design.
- **Overhead on legitimate traffic:** Hop count and Simulation-mode event count for a fixed staff→EHR and monitor→server flow.
- Run each test 3 times and from 3 node locations, then report means.

### Deliverables
- 4 `.pkt` files (D0–D3).
- A test log spreadsheet (attack × design × trial).
- Results graphs (bar chart of attack surface, heatmap of the attack-success matrix, graph of complexity vs security).
- The paper, structured as: Abstract → Introduction (IoMT threats, rising healthcare ransomware) → Related Work (micro-segmentation, zero trust, earlier PT studies) → Methodology (topology, designs, attacks, metrics) → Results → Discussion (security vs complexity trade-off, a recommended "minimum viable segmentation") → Limitations (PT is an emulator: no real exploits, approximate timing, a laptop stands in for compromised IoT) → Conclusion and future work (SDN/controller-based dynamic segmentation, NAC with 802.1X/RADIUS).

## Build order
1. Build the shared physical topology and IoT devices, and register the IoT devices to the registration server. Save as D0, flat.
2. Add the VLANs, trunks and SVIs. Save as D1.
3. Add the zone ACLs. Save as D2.
4. Split the IoT VLANs and add the ASA, least-privilege ACLs, port security, DHCP snooping and SSH. Save as D3.
5. Run the test matrix on each file, record the results, then make the graphs and write the paper.

## Verification
- In every design, legitimate flows must work: staff PC → EHR web page loads, IoT devices appear on the registration server dashboard, DHCP leases are handed out, and the Internet is reachable through NAT.
- In D3, attacks 1–7 must be blocked, confirmed in Simulation mode with the ACL or ASA drop shown in the PDU details. Use those screenshots as figures.
- Packet Tracer's Check Results / Activity Wizard is optional for validating the configs.
