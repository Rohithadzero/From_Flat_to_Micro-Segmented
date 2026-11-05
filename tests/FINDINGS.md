# Findings from the static policy analyzer (Phase 1, offline)

Source: `tools/policy_analyzer.py` traced over `configs/`. Nothing in `configs/` was changed.
Each finding still needs live confirmation in Packet Tracer (see the assumptions at the end).

## F-1 Config bug, High (D2): compromised IoT can take over CORE-MLS
- `configs/D2-zone-acl/CORE-MLS.txt` lines 58 and 64 permit IoT -> 10.10.20.0/24. That range contains
  the core's own Vlan20 address 10.10.20.1 (lines 79-81).
- The VTY (lines 121-124) accepts Telnet with password `cisco` and has no `access-class`.
- Effect: A4 is P (not B); attack surface 9 hosts / 5 services (not 8 / 4); README §4 "IoT can't reach
  switches" is false for D2. The README A4 procedure misses it (it only tests 10.10.99.11, the own
  gateway and 10.10.255.1).
- Proposed fix: `deny ip any host 10.10.20.1` before lines 58 and 64 (mutation test: gives 8/4 and
  A4 = B, F1-F9 still pass). Add `telnet 10.10.20.1` to the A4 procedure.
- Paper angle: a coarse zone ACL that names a subnet silently includes the router's own interface
  in that subnet, so the "server zone" permit also opens the management plane.

## F-2 Inconsistent expectation, Medium (D2, A3 at L3)
- README A3 target from L3 is Pump-A1. From VLAN 40 in D2 that ping is dropped by BLDGIOT-IN
  (CORE-MLS.txt:65), so A3 at D2-L3 is P, not the expected S. Using a building device as the target
  instead would make D3-L3 S, contradicting D3's expected P.
- Proposal: use Pump-A1 from every location and change the D2-L3 expectation to P.

## F-3 Medium (D2, D3): UDP/67 permitted to any destination
- `permit udp any any eq 67` (D3 CORE-MLS lines 91, 103, 110, 117, 124; D2 lines 57, 63, 69) lets
  UDP/67 leave to the Internet through PAT: a one-way exfiltration channel that survives D3, and a
  path to flood the real DHCP server.
- Proposed fix: `permit udp any host 255.255.255.255 eq 67` + `permit udp any host 10.10.20.11 eq 67`
  (mutation test: F1-F9 still pass).

## F-4 Low (D3): SW-SRV not hardened
- Unused SW-SRV ports (Fa0/5-24, Gi0/2) are up in VLAN 1 on the firewall's trusted inside. A strict
  xfail test documents this.

## F-5 Low (D3): stateless echo-reply permits
- A compromised device can send unsolicited ICMP echo-replies into the management VLAN (MONITORS-IN #3).

## F-6 Info (D2)
- NetAdmin-PC cannot ping IoT or guest devices; replies are dropped at CORE-MLS.txt:59, :65, :71.
  Not covered by F1-F9. D3 fixes it.

## Assumptions the live run must confirm
1. PT applies inbound SVI ACLs to packets addressed to the switch itself.
2. PT IoT devices answer pings.
3. IoT registration uses TCP 80.
4. The rogue DHCP server wins the race against the real server (A5).
5. Port security has learned Monitor-A1's MAC before A6.

---

# ECC network-config-reviewer pass (after F-1/F-3/F-4 fixes)

Review procedure: ECC `network-config-reviewer` agent + `network-config-validation`, `cisco-ios-patterns`,
`hipaa-compliance` skills (ECC 2.2.3). Status: FIXED = applied in `configs/`, otherwise documented
residual risk / future work. PT support marked where unverified.

| ID | Sev | Design | Finding | Status |
|---|---|---|---|---|
| H-1 | High | D2 | GUEST-IN denies only 10/8, so a guest can Telnet EDGE-RTR's WAN 198.51.100.2 (VTY password `cisco`, no access-class), then the core. Same class as F-1: a router's own address outside the range the ACL names. | **FIXED**: `deny ip any 198.51.100.0 0.0.0.3` before the deny-10/8 line (`D2 CORE-MLS`, `fixes-D2.txt`); tests `test_d2_guest_cannot_telnet_edge_wan_after_h1_fix` + regression. A7 procedure should add `telnet 198.51.100.2`. D3 is not affected (VTY access-class 10 + SSH only). |
| H-2 | High (design) | D3 | IOT-REG-SRV shares the ASA inside segment with the EHR; it is the one server every IoT class may reach, so exploiting it lands one hop from the EHR and Syslog. | Residual risk. Fix = ASA DMZ interface (`nameif iot-dmz`, sec-level 50) for .12; PT 5506-X third interface unverified. |
| M-1 | Med | D3 | EHR also on TCP 80 and IoT registration HTTP only: cleartext health data (HIPAA §164.312(e)). | Recommendation: EHR 443 only; PT IoT registration over HTTPS likely unsupported (limitation). |
| M-2 | Med | D3 | No syslog/NTP/timestamps on access switches; no `log` on deny ACEs; ASA no logging, so port-security/BPDU-guard events never reach syslog. | Recommendation; ptlab uses `show access-lists` counters as detection evidence instead (detection.csv, Q1). |
| M-3 | Med | D3 | No DAI / IP Source Guard: ARP-spoofing the VLAN 31 gateway is possible inside the VLAN. | Residual risk (extends the same-VLAN limitation); PT 9 DAI support unverified. |
| L-1..L-6 | Low | D3 | SW-SRV `enable secret cisco` + console `cisco`; NAT ACL lets IoT use PAT (second layer for F-3); EDGE `vty 0 4` only; no DHCP-snooping rate limit / pinned STP root; ASA UDP/67 from all 10.10/16 and VLAN 99 `ip any`; no OSPF MD5 / anti-spoof on EDGE G0/0. | Hardening recommendations (all PT-supported). |
| Info | - | all | Fix files delete-and-recreate ACLs that are applied (fine in the lab; on real IOS, insert by sequence number). `violation shutdown` on life-critical ports turns a MAC spoof into a clinical outage; consider `restrict` + syslog. 1024-bit RSA (use 2048 on real gear). |  |

Strengths the reviewer confirmed:
- exact host+port least privilege at the core, re-enforced statefully by the ASA, with correct wildcard vs subnet masks;
- zero Internet/management reach for the IoT classes;
- VLAN 20 removed from the core so the connected route cannot bypass the firewall;
- hardened trunks, parked ports, SSHv2 + local users, `passive-interface default`, DHCP snooping with option 82 off;
- no undefined ACL references.
