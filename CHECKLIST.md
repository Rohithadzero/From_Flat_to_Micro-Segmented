# Build checklist: what you do and check at each design

Claude pushes all router and switch configs live through the MCP (quirk-safe chunks are in
`tools/pt-extension/push-plan/`). You do the GUI-only steps, run the checks, and save each file
into the `Cisco packet saves/` folder (always **Save As**, never Ctrl+S). Tell Claude **"D1"**, **"D2"** or **"D3"** to start the next push.

---

## D0: Flat (already configured)

### 1. Network checks
| #   | Where                        | Command / action        | Pass if                                                     |
| --- | ---------------------------- | ----------------------- | ----------------------------------------------------------- |
| 1   | CORE-MLS CLI                 | `show ip ospf neighbor` | `1.1.1.1` … `FULL`                                          |
| 2   | CORE-MLS CLI                 | `show ip route`         | a `0.0.0.0/0` route (`O*E2` via OSPF, or `S*` = the backup) |
| 3   | NetAdmin-PC → Command Prompt | `ping 10.10.20.10`      | replies                                                     |
| 4   | NetAdmin-PC → Command Prompt | `ping 203.0.113.10`     | replies (first may time out during ARP)                     |

**If check 4 fails, send Claude a screenshot of checks 1 and 2.**

### 2. GUI tasks (no MCP tool exists for these)
1. **Servers → Services** (exact values in `configs/END-DEVICES.md`):
   - DNS-DHCP-SRV: DHCP **On**, with `serverPool` = gateway 10.10.0.1, DNS 10.10.20.11, start 10.10.1.1, **mask 255.255.128.0**, max 250.
     DNS **On**, with A records `ehr.hospital.local`→10.10.20.10, `iot.hospital.local`→10.10.20.12, `web.isp.test`→203.0.113.10.
   - EHR-SRV: HTTP and HTTPS **On**. Edit index.html to "Hospital EHR – Patient Records (CONFIDENTIAL)".
   - INTERNET-WEB: HTTP **On**. Edit index.html to "Public Internet web server".
   - IOT-REG-SRV: IoT **On**. SYSLOG-NTP-SRV: Syslog **On**, NTP **On**.
2. **IoT and Wi-Fi devices.** Drag these onto the canvas; Claude can then rename, place and cable them:
   - 2× Temperature Monitor, 2× Appliance (any on/off actuator), 1× Door, 1× Smoke Detector, 1× Ceiling Fan, 1× Webcam
   - In each IoT device: **Advanced → I/O Config → Network Adapter = PT-IOT-NM-1CFE** (wired)
   - 1× AccessPoint-PT, 1× Smartphone-PT, 1× TabletPC-PT
   - Then tell Claude **"IoT placed"**.
3. **After Claude has cabled them:**
   - Set every IoT device to DHCP, then **Config → IoT Server → Remote Server 10.10.20.12** (create user `iotadmin`/`Iot@2026` first from a PC browser at `http://10.10.20.12`).
   - Guest-AP **Port 0** cable → SW-ADMIN Fa0/8 (the MCP can't cable "Port 0"). Optional: SSID `HOSP-GUEST`, WPA2-PSK `GuestWiFi@2026` on the AP, phone and tablet.

### 3. Functional checks
| # | Check | Pass if |
|---|---|---|
| F1 | Nurse-PC-A → Web Browser → `ehr.hospital.local` | EHR page loads |
| F3 | Browser → `10.10.20.12` → login | IoT devices listed |
| F4 | Nurse-PC-A → Desktop → IP Configuration → DHCP | gets `10.10.1.x / 255.255.128.0` |
| F6 | EDGE-RTR CLI → `show ip nat translations` after F1/F5 | entries listed |

### 4. Save
**File → Save As → `Cisco packet saves/D0.pkt`.** ✅ done Then tell Claude **"D1"**.

---

## D1: VLAN-only
**Claude pushes:** transition (clears Vlan1), plus VLANs, trunks and SVIs on CORE and the 3 access switches (22 chunks). Servers and NetAdmin-PC are moved to /24 masks.

**You do:**
1. DNS-DHCP-SRV: change `serverPool` to gw 10.10.20.1 / start 10.10.20.200 / mask 255.255.255.0 / max 20, and **add pools** STAFF, MED-IOT, BLDG-IOT, GUEST (table in END-DEVICES.md).
2. Renew DHCP on every client (IP Configuration: Static → DHCP).

**Check:**
| Where | Command | Pass if |
|---|---|---|
| CORE-MLS | `show vlan brief` | VLANs 10, 20, 30, 40, 50, 99 |
| CORE-MLS | `show interfaces trunk` | Fa0/1, Fa0/2, Fa0/3 trunking |
| Nurse-PC-A | `ipconfig` | 10.10.10.x |
| IOT-COMPROMISED | `ipconfig`, then `ping 10.10.20.10` | 10.10.30.x, replies (**VLANs alone don't block**) |
| NetAdmin-PC | `ping 203.0.113.10` | replies |

**Save:** `Cisco packet saves/D1.pkt` ✅ done. Then tell Claude **"D2"**.

---

## D2: Zone ACLs
**Claude pushes:** three ACLs on CORE-MLS (8 chunks). Nothing for you to set up.

**Check:**
| Where | Command | Pass if |
|---|---|---|
| CORE-MLS | `show access-lists` | MEDIOT-IN, BLDGIOT-IN, GUEST-IN |
| IOT-COMPROMISED | `telnet 10.10.99.11` | **fails** (blocked) |
| IOT-COMPROMISED | browser `http://10.10.20.10` | **loads** (coarse ACL still allows it) |
| Nurse-PC-A | browser `ehr.hospital.local` | loads |

**Save:** `Cisco packet saves/D2.pkt` ✅ done. Then continue to D3.

---

## D3: Micro-segmentation
**You first:** drag one **ASA 5506-X** onto the canvas, then tell Claude **"D3"**.

**Claude pushes:** renames and re-cables the ASA (CORE G0/2 → ASA G1/1, ASA G1/2 → SW-SRV G0/1), runs the transition (removes VLAN 20/30 SVIs and the old ACLs), then pushes D3 to EDGE, CORE, ASA and the 3 access switches (45 chunks).
If the ASA config fails through the MCP, paste `configs/D3-microseg/ASA-SRV.txt` into the ASA CLI by hand.

**You do:** in the DHCP server, replace pool MED-IOT with **MED-MONITORS (10.10.31.x)** and **MED-INFUSION (10.10.32.x)**, then renew DHCP on all clients.

**Check:**
| Where | Command | Pass if |
|---|---|---|
| Nurse-PC-A | browser `ehr.hospital.local` | loads (allowed) |
| IOT-COMPROMISED | browser `http://10.10.20.10` | **fails** (blocked) |
| IOT-COMPROMISED | `telnet 10.10.99.11` | **fails** |
| NetAdmin-PC | `ssh -l netadmin 10.10.99.11` | login works (password `Adm1n@2026`) |
| CORE-MLS | `show access-lists` | hit counters increase |
| ASA-SRV | `show access-list OUTSIDE-IN` | hit counters |
| SW-WARD-A | `show port-security`, `show ip dhcp snooping` | enabled |

**Save:** `Cisco packet saves/D3.pkt` ✅ done.

---

## After all four
Run the attack tests (README §7), fill in `results/*.csv`, take the report screenshots, then ask Claude to regenerate the graphs and the report.

---

## Automated path (ptlab gateway): replaces most GUI steps above
1. `powershell -File app\run.ps1`, then install the patched PT module once (`tools/pt-extension/PATCH-PLUGIN.md`).
2. Dashboard http://127.0.0.1:7532/ → **Live lab** → *Apply checklist only* (tick *Save the .pkt*). For each design the runner:
   - pushes the analyzer fixes (`configs/transitions/fixes-D2.txt`, `fixes-D3.txt`);
   - sets server IPs, HTTP/HTTPS pages, DNS records, DHCP pools, IoT/Syslog/NTP services;
   - renews every DHCP lease;
   - saves the file, with a backup in `Cisco packet saves/backup/`.
3. Still manual (no script API): IoT device → IoT Server registration + the smoke→fan rule; Guest-AP SSID/WPA2 on the phone and tablet.
4. **Start test run** writes the observed values (A1–A8, Q1, O1, F1/F2/F4–F7/F9). Record F3/F8 under **Checks → Record a manual observation**.
5. Check the runner offline at any time with `python -m app.dryrun D3` (fake PT, sandboxed results).
