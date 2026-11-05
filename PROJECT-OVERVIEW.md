# Project Overview: Smart-Hospital Network Segmentation

A plain-language summary of what this project is about, how many networks it has, why the problem needs a network to solve it, and what we are trying to prove.

> **Title:** *From Flat to Micro-Segmented: A Simulation-Based Evaluation of Lateral-Movement Containment for Compromised IoMT Devices in a Smart-Hospital Network*

---

## 1. What is this project about?

This is a **Computer Networks mini-project about hospital network security**. We build one hospital network in Cisco Packet Tracer and test how well different designs stop a hacker.

### The problem, in simple words

Hospitals now connect many smart medical devices to their network, such as patient heart monitors and drip (infusion) pumps. These are called **IoMT** (Internet of Medical Things) devices. They often run old software that can't be updated, so they are easy to hack.

In most hospitals, everything is on **one big open network**:
- the patient monitors and infusion pumps,
- the nurses' PCs,
- the server holding patient records (EHR),
- the guest Wi-Fi,
- the switches and routers.

So if a hacker takes over one cheap monitor, they can jump from it to the patient records, the other medical devices and the network equipment. This jumping is called **lateral movement**.

**The project's question:** *how do we split up the network so one hacked device can't reach everything else?*

### The core idea (and a common misunderstanding)

The idea is **not** "only flat networks are vulnerable." Our point is that **how much** you segment matters. Each step adds protection, and each step also adds cost.

| Design | What it adds | Can the hacked IoT device reach the EHR (patient records)? | Lesson |
|---|---|---|---|
| **D0 Flat** | Nothing | ✅ yes | Everything can reach everything |
| **D1 VLANs** | Separate VLANs | ✅ **still yes** | VLANs alone aren't security. The core switch routes between them freely |
| **D2 Zone ACLs** | Coarse rules ("IoT may reach the server zone") | ✅ **still yes** | Coarse rules leave the EHR exposed because it sits in the allowed zone |
| **D3 Micro-seg** | Least privilege (exact host + port), firewall, Layer-2 protections | ❌ **no** | Only fine-grained rules actually contain the device |

**Key findings:**
1. **D1 is the surprise.** Many people assume VLANs give security. Our test shows they don't on their own.
2. **D2 shows that partial security gives false confidence.** It blocks some attacks, but not the one that matters most.
3. **D3 works but isn't perfect.** Two devices in the same VLAN can still talk to each other, and the IoT server must stay reachable. That is our residual risk and our future work (private VLANs, 802.1X).
4. **Security has a cost.** D3 needs about 3× the config lines of D0 (189 → 571) and 52× the ACL rules.

**One-line answer for the viva:**
> "We show that segmenting a hospital network into VLANs is not enough on its own. Only least-privilege micro-segmentation contains a compromised medical IoT device, and we measure what that extra security costs in configuration complexity."

---

## 2. How many networks are there?

There are **four versions of the same hospital network**, each saved as its own `.pkt` file. The devices and cables stay the same in all four. Only the security rules change, which keeps it a fair experiment.

| Version | What it is | Separate network segments inside |
|---|---|---|
| **D0 Flat** | One open network, everyone can reach everyone (the "before" picture) | 1 |
| **D1 VLANs** | Devices split into groups (staff, servers, medical IoT, building IoT, guests, management), but the groups can still talk freely | 6 |
| **D2 Zone ACLs** | D1 plus basic rules, e.g. "IoT may only talk to the server zone" and "guests only get Internet" | 6 |
| **D3 Micro-segmentation** | Each device type gets its own segment (monitors and pumps are separated) and may reach only the one server and port it needs. Adds an ASA firewall and switch-port protections | 7 (6 VLANs + the server segment behind the firewall) |

Every version also has a few small links that connect the parts:
- core switch ↔ edge router (`10.10.255.0/30`)
- edge router ↔ ISP (`198.51.100.0/30`)
- core switch ↔ firewall (`10.10.254.0/30`, D3 only)
- a pretend "Internet" with a public web server

### Physical layout

```
Internet (web server)
      |
   ISP router
      |
   Edge router
      |
   Core switch
      |
  +---------+---------+---------+--------------+
  |         |         |         |              |
Ward A    Ward B    Admin    Server room    (ASA firewall in D3,
switch    switch    switch     switch        between core and
                                             server room)
```

### Network segments (VLANs) used in D1–D3

| VLAN | Name | Who lives there |
|---|---|---|
| 10 | STAFF | Nurse PCs, reception |
| 20 | SERVERS | EHR, DNS/DHCP, IoT registration, Syslog/NTP |
| 30 | MED-IOT | All medical IoT (D1–D2) |
| 31 | MED-MONITORS | Patient monitors (D3) |
| 32 | MED-INFUSION | Infusion pumps (D3) |
| 40 | BLDG-IOT | Smart door, fire monitor, fan, webcam |
| 50 | GUEST | Guest Wi-Fi |
| 99 | MGMT | Switch management, NetAdmin PC |

---

## 3. Why do we need a network to solve this?

1. **The problem only exists because of the network.** A hacked monitor sitting alone can't hurt anyone. It's dangerous because it's connected to everything else. Lateral movement is entirely a network problem.
2. **The fix also lives in the network.** You can't patch the monitor, so the protection has to be built into the switches, routers and firewall: VLANs, ACL rules, the firewall, port security and SSH-only management. The network itself becomes the security guard.
3. **The hospital still needs it to work.** Monitors must still send readings, nurses must still open patient records, and devices must still get IP addresses. Building it as a network lets us check that the security doesn't break normal hospital work.
4. **We can measure it.** In Packet Tracer we run the same 7 attacks on all four versions and count how many succeed and how much of the network the attacker can still reach.

### The 7 attacks (run from a "hacked IoT device", a laptop)

1. Reconnaissance sweep: ping every host and gateway
2. Unauthorized data access: open the EHR server from the IoT device
3. Device hijack: log in to the IoT server or control another IoT device
4. Infrastructure takeover: Telnet/SSH into a switch or router
5. Rogue DHCP server plugged into an access port
6. Unauthorized device / MAC spoof on a ward port
7. Guest → clinical pivot: from guest Wi-Fi to the EHR server

---

## 4. What are we trying to prove?

We're trying to prove that **putting devices into separate groups (VLANs) is not enough to protect a hospital network. Real protection needs strict rules on top, and stronger rules cost more setup work.**

We break that into three claims, one for each research question.

### Claim 1: More segmentation means a hacker can reach less (RQ1)

If one medical device is hacked, how much of the network can the attacker still reach?

- **D0 Flat:** almost everything.
- **D1 VLANs:** still almost everything. This is the surprising part we want to show. Many people assume VLANs give security, but the core switch routes freely between them, so they only organise the network.
- **D2 Zone ACLs:** much less.
- **D3 Micro-segmentation:** only the one server and port the device actually needs.

### Claim 2: Security doesn't have to break the hospital (RQ2)

Even in the strictest design (D3), normal work should still run:

- monitors send readings,
- nurses open patient records,
- devices get IP addresses,
- the Internet works.

The point is that strong security and a working hospital can exist together.

### Claim 3: Security has a cost (RQ3)

Each step up needs more configuration. The counts below are measured from the config files:

| | D0 | D1 | D2 | D3 |
|---|---|---|---|---|
| Config lines | 189 | 274 | 302 | 571 |
| ACL entries | 1 | 1 | 17 | 52 |

So we can tell a hospital which level gives the best protection for the effort. The cheap jump is D1 → D2, which gives a lot of security for very little extra config. D3 gives the most security but about 3 times the config of D0.

### The honest limit we also show

Even D3 can't stop two devices **in the same VLAN** (two monitors, for example) from talking to each other. Rules on the core switch only see traffic that moves between VLANs. Being upfront about this makes the project stronger, and it leads to the future work (private VLANs, 802.1X/NAC, SDN).

### Why this matters

Earlier studies on this topic use vendor white papers or machine learning on datasets. We couldn't find a network simulation that anyone can rebuild and test. This project gives one: a measured, step-by-step case that **the network itself can contain a hacked medical device**, even though the device can't be patched.

---

## 5. The expected answer

- **VLANs alone (D1) don't stop anything.** They organise the network but don't protect it.
- **Simple rules (D2)** are cheap and block a lot.
- **Full micro-segmentation (D3)** is expected to block 5 of the 7 attacks completely and 2 only partly, but takes about 3 times as many config lines (571 vs 189).
- **D3 still has a gap:** devices in the same segment (two monitors, for example) can still reach each other. Fixing that (private VLANs, 802.1X/NAC, SDN) is future work.

| | D0 Flat | D1 VLAN-only | D2 Zone ACLs | D3 Micro-seg |
|---|---|---|---|---|
| Can IoT reach EHR? | yes | yes | yes | **no** |
| Can IoT reach switches? | yes | yes | no | no |
| Can guests reach EHR? | yes | yes | no | no |
| Config lines (measured) | 189 | 274 | 302 | 571 |
| ACL entries (measured) | 1 | 1 | 17 | 52 |

> **Note:** the attack results are still predictions from the design. Replace them with what we actually observe in Packet Tracer before the report is submitted. Only the config-line and ACL counts are already measured.
