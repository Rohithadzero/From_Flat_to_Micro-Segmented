"""Generate tools/live_test_plan.json: the ordered Packet Tracer procedure (cisco-pt-mcp tools)
for A1-A7 / F1-F9, with the static analyzer's prediction for every single step.

Why generated: the MCP can only send ICMP Simple PDUs between *named* devices
(sendPdu), so every TCP/UDP test needs a proxy or a human. For each TCP/UDP
test we ask the analyzer whether an ICMP echo between the same endpoints is
decided by the *same* rule (same device, ACL and ACE, same verdict). Only then
is the ICMP PDU accepted as proxy evidence ("proxy_valid": true); otherwise
the step is marked manual. This keeps the live evidence honest.

Usage: python tools/make_live_plan.py   (writes tools/live_test_plan.json)
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import policy_analyzer as pa  # noqa: E402
from policy_analyzer import ip2i  # noqa: E402

OUT = Path(__file__).resolve().parent / "live_test_plan.json"

TARGET_DEVICE = {  # A1 target label -> PT device name for sendPdu
    "CORE-MLS (gateway)": "CORE-MLS", "EDGE-RTR": "EDGE-RTR", "SW-WARD-A": "SW-WARD-A",
    "SW-WARD-B": "SW-WARD-B", "SW-ADMIN": "SW-ADMIN"}
COUNTER_CMDS = {
    "D0": {}, "D1": {},
    "D2": {"CORE-MLS": ["do show access-lists"]},
    "D3": {"CORE-MLS": ["do show access-lists"], "ASA-SRV": ["show access-list OUTSIDE-IN"]},
}
RUNNING_DEVICES = {"D0": ["CORE-MLS", "EDGE-RTR", "SW-WARD-A", "SW-WARD-B", "SW-ADMIN"],
                   "D3": ["CORE-MLS", "EDGE-RTR", "ASA-SRV", "SW-WARD-A", "SW-WARD-B", "SW-ADMIN"]}
RUNNING_DEVICES["D1"] = RUNNING_DEVICES["D2"] = RUNNING_DEVICES["D0"]


def decisive(p):
    """(device, acl, seq, verdict) of the rule that decided a probe, or the L2/unfiltered marker."""
    hops = (p.get("fwd") or {}).get("hops", []) + ((p.get("rev") or {}).get("hops", []))
    if not p["ok"]:
        d = p.get("decisive") or {}
        if d.get("acl"):
            return (d["at"], d["acl"], d.get("seq"), "deny", d.get("ref"))
        return (d.get("at"), d.get("action"), None, "deny", p["reason"][:80])
    acls = [h for h in hops if h.get("acl") and h.get("result") == "permit"]
    if any(h.get("action") == "L2_SAME_SEGMENT" for h in hops):
        return ("L2", "same-VLAN", None, "permit", None)
    if not acls:
        return ("-", "unfiltered", None, "permit", None)
    return tuple(["+".join(f"{h['at']}:{h['acl']}#{h['seq']}" for h in acls), "acl-chain", None, "permit", None])


def proxy(m, src, ip, proto, port):
    real = pa.probe(m, src, ip, proto, port)
    icmp = pa.probe(m, src, ip, "icmp")
    dr, di = decisive(real), decisive(icmp)
    same = dr[:4] == di[:4]
    return {
        "real_flow": f"{proto}/{port}", "real_predicted": "reachable" if real["ok"] else "blocked",
        "real_reason": pa.short_reason(real),
        "icmp_predicted": "accepted" if icmp["ok"] else "dropped", "icmp_reason": pa.short_reason(icmp),
        "proxy_valid": bool(same and real["ok"] == icmp["ok"]),
        "proxy_note": ("ICMP is decided by the same rule as the real flow -> PDU outcome is valid evidence "
                       "for the ACL/firewall stage (not for the application/VTY stage)") if same and real["ok"] == icmp["ok"]
        else "ICMP and the real flow are decided by DIFFERENT rules -> PDU is NOT evidence; manual step required",
    }


def plan_location(design, loc):
    m, atk = pa.with_attacker(design, loc)
    src = ("host", atk.name)
    label, sw, port = pa.LOCATIONS[loc]
    steps = []
    steps.append({"step": "move_test_node", "tools": [
        {"tool": "getDeviceInfo", "args": {"deviceName": "IOT-COMPROMISED"}, "why": "find current link + NIC name"},
        {"tool": "removeLink", "args": {"links": [{"device": "IOT-COMPROMISED", "port": "FastEthernet0"}]},
         "skip_if": "already cabled to " + f"{sw} {port}"},
        {"tool": "addLink", "args": {"device1Name": "IOT-COMPROMISED", "device1Interface": "FastEthernet0",
                                      "device2Name": sw, "device2Interface": port.replace("Fa", "FastEthernet"),
                                      "linkType": "straight"}},
        {"tool": "setSimulationMode", "args": {"toSimMode": False}, "why": "let STP/DHCP converge in realtime"},
        {"tool": "configurePcIp", "args": {"deviceName": "IOT-COMPROMISED", "dhcpEnabled": True}},
        {"tool": "getDeviceInfo", "args": {"deviceName": "IOT-COMPROMISED"},
         "record": "leased IP / mask / gateway -> notes", "expected": {
             "ip_in": pa.i2ip(atk.ip & atk.mask) + f"/{pa.prefixlen(atk.mask)}" if atk.ip else None,
             "gateway": pa.i2ip(atk.gw) if atk.gw else None, "pool": atk.lease.get("pool") if atk.lease else None}},
    ]})
    la = pa.analyse_location(design, loc)
    sweep = []
    for h in la["hosts"]:
        dev = TARGET_DEVICE.get(h["target"], h["target"])
        sweep.append({"target": h["target"], "sendPdu": {"sourceDevice": "IOT-COMPROMISED", "destinationDevice": dev},
                      "expected": "accepted" if h["reachable_at_listed"] or (h["reachable"] and dev not in TARGET_DEVICE.values())
                      else "dropped",
                      "expected_any_address": "accepted" if h["reachable"] else "dropped",
                      "listed_ip": h["listed_ip"], "reason": h["reason"],
                      "note": "PT chooses the destination IP of a named router/switch - record the IP shown in "
                              "getPduResults" if dev in TARGET_DEVICE.values() else ""})
    proxies = {}
    for tid, ip, proto, port, dst_dev in [("A2", "10.10.20.10", "tcp", 80, "EHR-SRV"),
                                          ("A3-iot-http", "10.10.20.12", "tcp", 80, "IOT-REG-SRV"),
                                          ("A4-switch", "10.10.99.11", "tcp", 23, "SW-WARD-A"),
                                          ("A4-edge", "10.10.255.1", "tcp", 23, "EDGE-RTR"),
                                          ("A4-gateway", pa.i2ip(atk.gw), "tcp", 23, "CORE-MLS"),
                                          ("S-dns", "10.10.20.11", "udp", 53, "DNS-DHCP-SRV"),
                                          ("S-internet", "203.0.113.10", "tcp", 80, "INTERNET-WEB")]:
        pr = proxy(m, src, ip2i(ip), proto, port)
        pr["sendPdu"] = {"sourceDevice": "IOT-COMPROMISED", "destinationDevice": dst_dev}
        proxies[tid] = pr
    if design == "D2":
        pr = proxy(m, src, ip2i("10.10.20.1"), "tcp", 23)
        pr["sendPdu"] = None
        pr["manual"] = "Finding F-1: on IOT-COMPROMISED Command Prompt run 'ping 10.10.20.1' and 'telnet 10.10.20.1' " \
                       "(password cisco). sendPdu cannot target a specific IP of CORE-MLS."
        proxies["A4-core-via-10.10.20.1"] = pr
    return {"location": label, "attacker_expected_ip": pa.i2ip(atk.ip) if atk.ip else None,
            "setup": steps, "trial_procedure": [
                {"tool": "setSimulationMode", "args": {"toSimMode": True}},
                {"tool": "configureIosDevice", "for_each": COUNTER_CMDS[design], "record": "ACL counters BEFORE"},
                "for each PDU below: stepSimulation reset -> sendPdu -> stepSimulation forward (steps 30, repeat until "
                "no PDU in_transit, max 5x) -> getPduResults types=['ICMP'] -> record accepted/dropped + last hop",
                {"tool": "configureIosDevice", "for_each": COUNTER_CMDS[design], "record": "ACL counters AFTER"}],
            "A1_sweep": sweep, "icmp_proxies": proxies,
            "predicted": {k: v["predicted"] for k, v in la["attacks"].items()},
            "predicted_surface": la["surface"]}


def plan_design(design):
    a5, a6, a7 = pa.analyse_a5(design), pa.analyse_a6(design), pa.analyse_a7(design)
    m = pa.load_design(design)
    f = pa.analyse_functional(design)
    guest_proxy = proxy(m, ("host", "Guest-Phone"), ip2i("10.10.20.10"), "tcp", 80)
    guest_proxy["sendPdu"] = {"sourceDevice": "Guest-Phone", "destinationDevice": "EHR-SRV"}
    return {
        "design": design,
        "preflight": [
            {"tool": "getNetwork", "check": "IOT-COMPROMISED cabled to SW-WARD-A Fa0/4 (L1); ASA present only in D3"},
            {"tool": "configureIosDevice", "for_each_device": RUNNING_DEVICES[design],
             "commands": "do terminal length 0\ndo show running-config",
             "save_to": f"results/raw/{design}/running/<DEVICE>.txt",
             "then": f"python tools/policy_analyzer.py --design {design} --config-dir results/raw/{design}/running "
                     "--no-write  -> config drift check: any verdict that differs from the file-based analysis "
                     "means the live device does not run configs/ (record it)"},
            {"tool": "configureIosDevice", "deviceName": "CORE-MLS",
             "commands": "do show ip route\ndo show vlan brief\ndo show interfaces trunk\ndo show ip ospf neighbor",
             "save_to": f"results/raw/{design}/core-state.json"},
        ],
        "locations": {loc: plan_location(design, loc) for loc in pa.LOCATIONS},
        "A5": {"predicted": a5["predicted"], "reason": a5["reason"], "needs_human": [
            "ROGUE-DHCP Services->DHCP: On, pool gateway 10.10.10.66 / DNS 10.10.10.66 / start 10.10.10.200 "
            "(D0: 10.10.66.x) - GUI only"],
            "tools": [
                {"tool": "addLink", "args": {"device1Name": "ROGUE-DHCP", "device1Interface": "FastEthernet0",
                                              "device2Name": "SW-WARD-A", "device2Interface": "FastEthernet0/5",
                                              "linkType": "straight"}},
                {"tool": "configurePcIp", "args": {"deviceName": "Nurse-PC-A", "dhcpEnabled": False,
                                                    "ipaddress": "0.0.0.0", "subnetMask": "255.0.0.0"},
                 "why": "toggle off DHCP, then on, to force DISCOVER"},
                {"tool": "configurePcIp", "args": {"deviceName": "Nurse-PC-A", "dhcpEnabled": True}},
                {"tool": "getDeviceInfo", "args": {"deviceName": "Nurse-PC-A"},
                 "observe": "S if gateway == 10.10.10.66 (D0: 10.10.66.66), B if gateway == legit"},
                {"tool": "configureIosDevice", "deviceName": "SW-WARD-A",
                 "commands": "do show ip dhcp snooping\ndo show ip dhcp snooping binding", "only": "D3"},
                {"tool": "removeLink", "args": {"links": [{"device": "ROGUE-DHCP", "port": "FastEthernet0"}]},
                 "restore": True},
                {"tool": "configurePcIp", "args": {"deviceName": "Nurse-PC-A", "dhcpEnabled": True},
                 "restore": True, "why": "renew from the legitimate server"}]},
        "A6": {"predicted": a6["predicted"], "reason": a6["reason"], "tools": [
            {"tool": "configureIosDevice", "deviceName": "SW-WARD-A",
             "commands": "do show port-security interface fa0/2", "only": "D3",
             "precondition": "Sticky MAC of Monitor-A1 learned (generate traffic from Monitor-A1 first: "
                             "sendPdu Monitor-A1 -> IOT-REG-SRV is dropped in D3 but still teaches the MAC)"},
            {"tool": "removeLink", "args": {"links": [{"device": "Monitor-A1", "port": "FastEthernet0"}]}},
            {"tool": "addLink", "args": {"device1Name": "ROGUE-LAPTOP", "device1Interface": "FastEthernet0",
                                          "device2Name": "SW-WARD-A", "device2Interface": "FastEthernet0/2",
                                          "linkType": "straight"}},
            {"tool": "configurePcIp", "args": {"deviceName": "ROGUE-LAPTOP", "dhcpEnabled": True}},
            {"tool": "sendPdu", "args": {"sourceDevice": "ROGUE-LAPTOP", "destinationDevice": "Pump-A1"}},
            {"tool": "getDeviceInfo", "args": {"deviceName": "ROGUE-LAPTOP"}, "observe": "lease?"},
            {"tool": "configureIosDevice", "deviceName": "SW-WARD-A",
             "commands": "do show port-security interface fa0/2\ndo show interfaces status err-disabled",
             "observe": "D3: Security Violation Count >= 1, port err-disabled -> B"},
            {"restore": True, "tool": "removeLink", "args": {"links": [{"device": "ROGUE-LAPTOP", "port": "FastEthernet0"}]}},
            {"restore": True, "tool": "addLink", "args": {"device1Name": "Monitor-A1", "device1Interface": "FastEthernet0",
                                                           "device2Name": "SW-WARD-A", "device2Interface": "FastEthernet0/2",
                                                           "linkType": "straight"}},
            {"restore": True, "only": "D3", "tool": "configureIosDevice", "deviceName": "SW-WARD-A",
             "commands": "interface FastEthernet0/2\nshutdown\nno shutdown",
             "why": "recover err-disabled port (sticky MAC of Monitor-A1 is kept)"}]},
        "A7": {"predicted": a7["predicted"], "reason": a7["reason"], "icmp_proxy": guest_proxy,
               "precondition": "Guest-Phone associated to Guest-AP and holding a lease (getDeviceInfo Guest-Phone)"},
        "functional": {
            "F2": {"mcp": True, "sendPdu": {"sourceDevice": "Nurse-PC-A", "destinationDevice": "EHR-SRV"},
                   "predicted": f["F2"]["predicted"]},
            "F4": {"mcp": True, "procedure": "configurePcIp dhcpEnabled=true on each DHCP client, then getDeviceInfo; "
                                             "compare with predicted leases (subnet, gateway)",
                   "predicted": f["F4"]["predicted"], "predicted_leases": f["F4"]["leases"]},
            "F6": {"mcp": "partial", "procedure": "sendPdu Nurse-PC-A -> INTERNET-WEB, then configureIosDevice EDGE-RTR "
                                                  "'do show ip nat translations' (ICMP entry proves PAT; HTTP part manual)",
                   "predicted": f["F6"]["predicted"]},
            "F9": {"mcp": "partial", "procedure": "configureIosDevice CORE-MLS/EDGE-RTR 'do show logging' -> "
                                                  "'Logging to 10.10.20.13' + messages logged count; server-side view manual",
                   "predicted": f["F9"]["predicted"]},
            **{k: {"mcp": False, "manual": v, "predicted": f[k]["predicted"]} for k, v in {
                "F1": "Nurse-PC-A Desktop > Web Browser > http://ehr.hospital.local - page title visible",
                "F3": "Nurse-PC-A browser http://10.10.20.12, login iotadmin/Iot@2026, count devices listed (8)",
                "F5": "Guest-Phone browser http://web.isp.test",
                "F7": "NetAdmin-PC Command Prompt: telnet 10.10.99.11 (D0-D2) / ssh -l netadmin 10.10.99.11 (D3)",
                "F8": "Alt-click Fire-Monitor (smoke) -> HVAC-Fan turns on"}.items()}},
        "restore": [{"tool": "removeLink", "args": {"links": [{"device": "IOT-COMPROMISED", "port": "FastEthernet0"}]}},
                    {"tool": "addLink", "args": {"device1Name": "IOT-COMPROMISED", "device1Interface": "FastEthernet0",
                                                  "device2Name": "SW-WARD-A", "device2Interface": "FastEthernet0/4",
                                                  "linkType": "straight"}},
                    {"tool": "setSimulationMode", "args": {"toSimMode": False}},
                    "never File>Save; never removeDevice/addDevice"],
    }


RUNNER = [
    "0. Receive 'PT_READY <design>'. Confirm the open .pkt is that design: getNetwork (ASA-SRV present only in D3; "
    "IOT-COMPROMISED on SW-WARD-A Fa0/4). Save getNetwork JSON to results/raw/<design>/network.json.",
    "1. Preflight (designs.<d>.preflight): verify configureIosDevice returns show output ('do show access-lists' on "
    "CORE-MLS). Capture running-configs into results/raw/<d>/running/, then run the analyzer on them (drift check).",
    "2. For L in L1, L2, L3: run designs.<d>.locations.<L>.setup (move cable, DHCP renew, record lease vs expected).",
    "3. For trial 1..3 at L: snapshot ACL counters; for each of the 23 A1_sweep targets: stepSimulation reset -> "
    "sendPdu -> stepSimulation forward (30, repeat while in_transit, max 5x) -> getPduResults(types=['ICMP']); "
    "record accepted/dropped + the IP PT used. Then the icmp_proxies PDUs. Snapshot ACL counters again; the "
    "counter delta per ACE attributes every drop/permit to a config line. Save all tool outputs to "
    "results/raw/<d>/<L>/trial<k>.json.",
    "4. A5, A6 (once per trial, location-independent): run designs.<d>.A5/A6 tools incl. the restore steps.",
    "5. A7: Guest-Phone -> EHR-SRV ICMP proxy (valid in all designs: same deciding rule as HTTP).",
    "6. Functional: F2/F4 fully by MCP; F6/F9 partially; F1/F3/F5/F7/F8 manual (list them for the human).",
    "7. Restore: IOT-COMPROMISED back to SW-WARD-A Fa0/4, realtime mode. Never save the .pkt.",
    "8. Write observed cells only for measured items (see observed_value_rules); leave others blank with the reason "
    "in notes. Compare observed vs results/static-analysis.csv vs expected; append to tests/CROSS-VALIDATION.md.",
]
METHODS = {
    "A1 (23-host ICMP sweep)": "MCP direct: sendPdu per target device; 3 trials x 3 locations",
    "A2 EHR HTTP": "MCP ICMP proxy (valid: same deciding rule in all designs) + manual browser for the S cases",
    "A3 IoT-server HTTP": "manual browser in D3 (proxy INVALID: TCP80 permitted, ICMP denied); proxy valid D0-D2",
    "A3 cross-class ping": "MCP direct: sendPdu IOT-COMPROMISED -> Pump-A1",
    "A4 Telnet/SSH": "MCP ICMP proxy proves the ACL stage only; VTY stage (transport, access-class, login) needs a "
                     "human telnet/ssh from IOT-COMPROMISED. D2: also telnet 10.10.20.1 (finding F-1).",
    "A5 rogue DHCP": "MCP relink + DHCP renew + getDeviceInfo gateway; rogue DHCP service setup is GUI (human)",
    "A6 rogue device": "MCP relink + DHCP + 'do show port-security interface fa0/2'",
    "A7 guest pivot": "MCP ICMP proxy Guest-Phone -> EHR-SRV (valid); manual browser optional",
    "Services (10)": "manual for TCP/UDP; ICMP proxies recorded in notes only, never as service counts",
    "F2, F4": "MCP direct", "F6, F9": "MCP partial (NAT table / show logging)", "F1, F3, F5, F7, F8": "manual GUI",
}
LIMITATIONS = [
    "The MCP bridge generates only ICMP Simple PDUs between named devices; application-layer tests (HTTP, "
    "Telnet, SSH, DNS) and GUI services cannot be driven programmatically and were performed manually or not at all.",
    "An ICMP PDU is used as evidence for a TCP/UDP verdict only when the static analyzer shows that both are "
    "decided by the same ACL entry (84/87 checks); it never evidences the application or VTY stage.",
    "sendPdu cannot choose the destination IP of a multi-homed device, so address-specific bypasses (F-1: "
    "10.10.20.1) need a manual ping/telnet.",
    "configureIosDevice ends with 'write memory' (device NVRAM, not the .pkt); only read-only 'do show' commands "
    "were sent, except the err-disable recovery of SW-WARD-A Fa0/2 after A6.",
    "Packet Tracer is a simulator: ACL, ASA and port-security behaviour follow PT's implementation of IOS/ASA, "
    "which is a subset of real devices.",
]


def main():
    plan = {
        "generated_by": "tools/make_live_plan.py (from tools/policy_analyzer.py predictions)",
        "mcp_tools_used": ["getNetwork", "getDeviceInfo", "configurePcIp", "configureIosDevice", "sendPdu",
                           "stepSimulation", "getPduResults", "getSimulationStatus", "setSimulationMode",
                           "removeLink", "addLink", "getCommandLog"],
        "mcp_limits": [
            "sendPdu sends ICMP echo only, between NAMED devices: no TCP/UDP, no choice of destination IP",
            "no tool drives a PC's Web Browser, Telnet/SSH client, nslookup, or a server/IoT GUI",
            "configureIosDevice runs from global config and ends with 'write memory': use only 'do show ...' "
            "(read-only); it re-saves the device's own running-config to NVRAM (not the .pkt file)",
            "whether configureIosDevice returns show output must be verified in preflight; if not, ACL hit "
            "counters must be read by a human",
            "PDU drop location: getPduResults gives status only; attribution uses ACL hit-counter deltas",
        ],
        "observed_value_rules": [
            "write an observed cell only from a tool output or human observation saved under results/raw/<design>/",
            "A1/surface host counts: count accepted ICMP PDUs among the 23 targets",
            "service counts: only cells measured (manual HTTP/Telnet/SSH/DNS); leave blank otherwise",
            "an ICMP proxy may be used for a TCP/UDP verdict only where proxy_valid is true, and the note must "
            "say 'ICMP proxy'",
        ],
        "runner_procedure": RUNNER,
        "measurement_methods": METHODS,
        "limitations_for_paper": LIMITATIONS,
        "designs": {d: plan_design(d) for d in pa.DESIGNS},
    }
    OUT.write_text(json.dumps(plan, indent=1, default=str), encoding="utf-8")
    n_valid = sum(1 for d in plan["designs"].values() for l in d["locations"].values()
                  for p in l["icmp_proxies"].values() if p["proxy_valid"])
    n_all = sum(1 for d in plan["designs"].values() for l in d["locations"].values() for p in l["icmp_proxies"].values())
    print(f"written {OUT} - ICMP proxy valid for {n_valid}/{n_all} TCP/UDP checks")
    for d, dp in plan["designs"].items():
        for loc, lp in dp["locations"].items():
            print(d, loc, {k: ("ok" if v["proxy_valid"] else "MANUAL") for k, v in lp["icmp_proxies"].items()})
        print(d, "A7", "ok" if dp["A7"]["icmp_proxy"]["proxy_valid"] else "MANUAL")


if __name__ == "__main__":
    main()
