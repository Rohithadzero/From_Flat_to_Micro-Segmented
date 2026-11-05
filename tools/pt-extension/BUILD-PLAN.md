# Live build plan (cisco-pt-mcp)

Claude builds the network in Packet Tracer 9.0.1 through the `cisco-pt-mcp` bridge.
Order: build D0 → save → transform to D1 → save → D2 → save → D3 → save.
(Saving and a few GUI-only settings are done by a person. See the checklist at the end.)

## Canvas placement (logical workspace)
| Device | Model | x | y |
|---|---|---|---|
| INTERNET-WEB | Server-PT | 100 | 60 |
| ISP-RTR | 2911 | 100 | 180 |
| EDGE-RTR | 2911 | 380 | 180 |
| CORE-MLS | 3560-24PS | 380 | 320 |
| ASA-SRV (D3 only) | 5506-X | 640 | 320 |
| SW-SRV | 2960-24TT | 880 | 320 |
| EHR-SRV / DNS-DHCP-SRV / IOT-REG-SRV / SYSLOG-NTP-SRV | Server-PT | 1100 | 180 / 270 / 360 / 450 |
| SW-WARD-A / SW-WARD-B / SW-ADMIN | 2960-24TT | 160 / 520 / 900 | 480 |
| Nurse-PC-A, Monitor-A1, Pump-A1, IOT-COMPROMISED | PC-PT, Temperature Monitor, Appliance, Laptop-PT | 40 / 120 / 200 / 280 | 640 |
| Nurse-PC-B, Monitor-B1, Pump-B1 | PC-PT, Temperature Monitor, Appliance | 440 / 520 / 600 | 640 |
| Reception-PC, NetAdmin-PC, Smart-Door, Fire-Monitor, HVAC-Fan, Webcam, Guest-AP | PC-PT, PC-PT, Door, Smoke Detector, Fan, Webcam, AccessPoint-PT | 740…1220 (step 80) | 640 |
| Guest-Phone, Guest-Tablet | SMARTPHONE-PT, TabletPC-PT | 1180 / 1260 | 780 |
| ROGUE-DHCP, ROGUE-LAPTOP (unlinked test tools) | Server-PT, Laptop-PT | 40 / 120 | 780 |

## Links
| A | Port | B | Port | Type |
|---|---|---|---|---|
| ISP-RTR | GigabitEthernet0/1 | INTERNET-WEB | FastEthernet0 | cross |
| ISP-RTR | GigabitEthernet0/0 | EDGE-RTR | GigabitEthernet0/0 | cross |
| EDGE-RTR | GigabitEthernet0/1 | CORE-MLS | GigabitEthernet0/1 | straight |
| CORE-MLS | FastEthernet0/1,2,3 | SW-WARD-A / SW-WARD-B / SW-ADMIN | GigabitEthernet0/1 | cross |
| CORE-MLS | GigabitEthernet0/2 | SW-SRV | GigabitEthernet0/1 | cross (D3: CORE→ASA G1/1 straight, ASA G1/2→SW-SRV G0/1 straight) |
| SW-SRV | FastEthernet0/1–4 | the four servers | FastEthernet0 | straight |
| SW-WARD-A/B | Fa0/1, Fa0/2, Fa0/3, (A only) Fa0/4 | Nurse PC, monitor, pump, IOT-COMPROMISED | FastEthernet0 | straight |
| SW-ADMIN | Fa0/1–Fa0/6, Fa0/8 | Reception, NetAdmin, door, fire, fan, webcam, Guest-AP (Port 0) | | straight |

## Configs
CLI from `configs/<design>/*.txt` (via configureIosDevice). Static IPs via configurePcIp:
servers .10–.13 (mask /17 (255.255.128.0) + gw 10.10.0.1 in D0, /24 + gw 10.10.20.1 in D1–D3), NetAdmin-PC 10.10.99.50,
INTERNET-WEB 203.0.113.10/24 gw 203.0.113.1, ROGUE-DHCP 10.10.10.66. Everything else DHCP.

## Person-only checklist (no tool exists for these)
1. DNS-DHCP-SRV → Services → DHCP pools + DNS records (configs/END-DEVICES.md §1).
2. EHR-SRV / INTERNET-WEB → HTTP on, edit index.html. IOT-REG-SRV → IoT on. SYSLOG-NTP-SRV → Syslog + NTP on.
3. IoT devices → IoT Server = 10.10.20.12 (after creating the iotadmin account).
4. (Optional) Guest-AP + phone/tablet → SSID HOSP-GUEST, WPA2-PSK.
5. File → Save As → D0.pkt / D1.pkt / D2.pkt / D3.pkt in `Cisco packet saves/` (always Save As, never Ctrl+S, or the previous design is overwritten).

Push order per design is in `push-plan/<design>.json` (made by `make_push_plan.py`; each chunk ends at a `(no) shutdown` because PT swallows the next line).
