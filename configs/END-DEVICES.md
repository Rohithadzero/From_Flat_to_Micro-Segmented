# End-device settings (PCs, servers, IoT, Wi-Fi)

These devices have no CLI. They are set up in Packet Tracer's GUI tabs (**Desktop → IP Configuration**, **Services**, **Config**).
Where a value changes between designs, the table gives one column per design.

## 1. Servers (all on SW-SRV)

| Device | SW-SRV port | IP address | Mask D0 / D1–D3 | Gateway D0 / D1–D3 | DNS |
|---|---|---|---|---|---|
| EHR-SRV | Fa0/1 | 10.10.20.10 | 255.255.128.0 / 255.255.255.0 | 10.10.0.1 / 10.10.20.1 | 10.10.20.11 |
| DNS-DHCP-SRV | Fa0/2 | 10.10.20.11 | same | same | 10.10.20.11 |
| IOT-REG-SRV | Fa0/3 | 10.10.20.12 | same | same | 10.10.20.11 |
| SYSLOG-NTP-SRV | Fa0/4 | 10.10.20.13 | same | same | 10.10.20.11 |
| INTERNET-WEB (on ISP side) | ISP-RTR G0/1 | 203.0.113.10 | 255.255.255.0 | 203.0.113.1 | (leave blank) |

In **D1–D3** the gateway 10.10.20.1 is the core SVI 20 in D1/D2 and the **ASA inside interface** in D3, so the servers keep the same settings.

### Services to turn on (Services tab). Turn every other service off.
- **EHR-SRV**: HTTP **On** and HTTPS **On**. Edit `index.html` so the page reads *"Hospital EHR – Patient Records (CONFIDENTIAL)"*. Seeing this page proves an EHR access worked.
- **DNS-DHCP-SRV**: DNS **On**, with these A records:
  - `ehr.hospital.local` → 10.10.20.10
  - `iot.hospital.local` → 10.10.20.12
  - `web.isp.test` → 203.0.113.10

  DHCP **On**, with the pools below.
- **IOT-REG-SRV**: IoT **On**. From Nurse-PC-A open a browser at `http://10.10.20.12`, click *Sign up now*, and create the user **iotadmin / Iot@2026**.
- **SYSLOG-NTP-SRV**: SYSLOG **On** and NTP **On**. Logs from the routers and the core switch appear on this server.
- **INTERNET-WEB**: HTTP **On**. Edit `index.html` to read *"Public Internet web server"*.

### DHCP pools on DNS-DHCP-SRV
Packet Tracer won't let you delete `serverPool`, so edit it instead. The server chooses the pool from the relay agent's gateway address (`giaddr`, set by `ip helper-address`).

**D0 (flat): one pool only**

| Pool | Default gateway | DNS | Start IP | Mask | Max users |
|---|---|---|---|---|---|
| serverPool | 10.10.0.1 | 10.10.20.11 | 10.10.1.1 | 255.255.128.0 | 250 |

**D1 and D2**

| Pool | Default gateway | DNS | Start IP | Mask | Max users |
|---|---|---|---|---|---|
| serverPool | 10.10.20.1 | 10.10.20.11 | 10.10.20.200 | 255.255.255.0 | 20 |
| STAFF | 10.10.10.1 | 10.10.20.11 | 10.10.10.100 | 255.255.255.0 | 100 |
| MED-IOT | 10.10.30.1 | 10.10.20.11 | 10.10.30.100 | 255.255.255.0 | 100 |
| BLDG-IOT | 10.10.40.1 | 10.10.20.11 | 10.10.40.100 | 255.255.255.0 | 100 |
| GUEST | 10.10.50.1 | 10.10.20.11 | 10.10.50.100 | 255.255.255.0 | 100 |

**D3**: the same pools as D1/D2, with `MED-IOT` replaced by two pools:

| Pool | Default gateway | DNS | Start IP | Mask | Max users |
|---|---|---|---|---|---|
| MED-MONITORS | 10.10.31.1 | 10.10.20.11 | 10.10.31.100 | 255.255.255.0 | 100 |
| MED-INFUSION | 10.10.32.1 | 10.10.20.11 | 10.10.32.100 | 255.255.255.0 | 100 |

## 2. Staff and admin PCs

| Device | Switch / port | Addressing |
|---|---|---|
| Nurse-PC-A | SW-WARD-A Fa0/1 | DHCP |
| Nurse-PC-B | SW-WARD-B Fa0/1 | DHCP |
| Reception-PC | SW-ADMIN Fa0/1 | DHCP |
| NetAdmin-PC | SW-ADMIN Fa0/2 | **Static.** D0: 10.10.99.50 / 255.255.128.0, gateway 10.10.0.1. D1–D3: 10.10.99.50 / 255.255.255.0, gateway 10.10.99.1. DNS 10.10.20.11 |

## 3. IoT devices (wired)

Packet Tracer has no medical devices, so ordinary PT smart devices are renamed and stand in for them. In each device go to **Advanced → I/O Config → Network Adapter** and pick **PT-IOT-NM-1CFE** (wired FastEthernet). Then cable it to the switch port.

| Device name | Stands in for | PT device to use (any IoT "thing" works) | Switch / port |
|---|---|---|---|
| Monitor-A1 | Patient vital-signs monitor | Home → Temperature Monitor | SW-WARD-A Fa0/2 |
| Pump-A1 | Infusion pump | Home → Appliance / any on-off actuator | SW-WARD-A Fa0/3 |
| Monitor-B1 | Patient vital-signs monitor | Home → Temperature Monitor | SW-WARD-B Fa0/2 |
| Pump-B1 | Infusion pump | Home → Appliance / any on-off actuator | SW-WARD-B Fa0/3 |
| Smart-Door | Access-controlled door | Home → Door | SW-ADMIN Fa0/3 |
| Fire-Monitor | Smoke/fire detector | Home → Smoke Detector | SW-ADMIN Fa0/4 |
| HVAC-Fan | Ventilation | Home → Ceiling Fan | SW-ADMIN Fa0/5 |
| Webcam | CCTV | Home → Webcam | SW-ADMIN Fa0/6 |

On every IoT device:
1. **Config → FastEthernet0**: set IP to **DHCP**.
2. **Config → Settings → IoT Server**: choose **Remote Server**, set Server Address **10.10.20.12**, user **iotadmin**, password **Iot@2026**, then click **Connect**.
3. On any staff PC, browse to `http://10.10.20.12` and log in. All 8 devices should be listed.
4. Under **Conditions**, add one automation rule: *If Fire-Monitor (smoke) is On, then set HVAC-Fan to High.* Test F8 checks that this rule fires.

> If a device registers in D0–D2 but **not** in D3, open Simulation mode, filter on the IoT device, and check which TCP port its registration traffic uses. The ACLs allow TCP 80. If PT uses another port, add that port to `MONITORS-IN`, `INFUSION-IN` and `BLDGIOT-IN` on CORE-MLS, and to `OUTSIDE-IN` on ASA-SRV.

## 4. Guest Wi-Fi

| Device | Settings |
|---|---|
| Guest-AP (AccessPoint-PT) | Cable Port 0 to SW-ADMIN Fa0/8. **Config → Port 1**: SSID `HOSP-GUEST`, **WPA2-PSK**, passphrase `GuestWiFi@2026` |
| Guest-Phone (Smartphone-PT) | **Config → Wireless0**: SSID `HOSP-GUEST`, WPA2-PSK, same passphrase. IP: DHCP |
| Guest-Tablet (TabletPC-PT) | Same as Guest-Phone |

## 5. Test-only devices (attack tools)

| Device | Purpose | Settings |
|---|---|---|
| IOT-COMPROMISED (Laptop-PT) | A medical IoT device an attacker has taken over (PT IoT devices cannot generate attack traffic). | IP: DHCP. **Location 1** = SW-WARD-A Fa0/4; to test locations 2 and 3, move the cable to SW-WARD-B Fa0/4 or SW-ADMIN Fa0/7 |
| ROGUE-DHCP (Server-PT) | Rogue DHCP server for attack A5. | Static IP 10.10.10.66 / 255.255.255.0 (in D0 use 10.10.66.66 / 255.255.128.0). DHCP **On**: edit serverPool to gateway **10.10.10.66** (the attacker becomes the gateway, enabling man-in-the-middle), DNS 10.10.10.66, start 10.10.10.200. Connect it to SW-WARD-A Fa0/5 **only while running A5** |
| ROGUE-LAPTOP (Laptop-PT) | Unauthorised device for attack A6. | IP: DHCP. During A6, unplug Monitor-A1 from SW-WARD-A Fa0/2 and plug this laptop in |
