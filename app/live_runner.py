"""Automated Packet Tracer test runner (GUI-checklist prep + attacks A1-A7 + functional F1-F9).

Everything here drives the *running* Packet Tracer through the gateway tools.
Observed values are written to results/*.csv only from what PT actually
returned, and every observation keeps its raw evidence under results/raw/.
Tests that cannot be automated (IoT dashboard listing, IoT automation rule)
are reported as "manual" and left blank.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import json
import re
import shutil
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from . import project
from .pt_tools import PTTools

ROOT = project.ROOT
RAW = project.RES / "raw"

NODE = "IOT-COMPROMISED"
LOCATIONS = {
    "L1-WardA-MedIoT": ("SW-WARD-A", "FastEthernet0/4"),
    "L2-WardB-MedIoT": ("SW-WARD-B", "FastEthernet0/4"),
    "L3-BuildingIoT": ("SW-ADMIN", "FastEthernet0/7"),
}
SERVERS = {"EHR-SRV": "10.10.20.10", "DNS-DHCP-SRV": "10.10.20.11", "IOT-REG-SRV": "10.10.20.12",
           "SYSLOG-NTP-SRV": "10.10.20.13"}
DHCP_HOSTS = {  # device -> (class, port)
    "Nurse-PC-A": ("staff", "FastEthernet0"), "Nurse-PC-B": ("staff", "FastEthernet0"),
    "Reception-PC": ("staff", "FastEthernet0"),
    "Monitor-A1": ("monitor", "FastEthernet0"), "Monitor-B1": ("monitor", "FastEthernet0"),
    "Pump-A1": ("pump", "FastEthernet0"), "Pump-B1": ("pump", "FastEthernet0"),
    "Smart-Door": ("bldg", "FastEthernet0"), "Fire-Monitor": ("bldg", "FastEthernet0"),
    "HVAC-Fan": ("bldg", "FastEthernet0"), "Webcam": ("bldg", "FastEthernet0"),
    "Guest-Phone": ("guest", "Wireless0"), "Guest-Tablet": ("guest", "Wireless0"),
}
SUBNET = {
    "D0": {c: "10.10.0.0/17" for c in ("staff", "monitor", "pump", "bldg", "guest", "mgmt", "server")},
    "D1": {"staff": "10.10.10.0/24", "monitor": "10.10.30.0/24", "pump": "10.10.30.0/24", "bldg": "10.10.40.0/24",
           "guest": "10.10.50.0/24", "mgmt": "10.10.99.0/24", "server": "10.10.20.0/24"},
}
SUBNET["D2"] = dict(SUBNET["D1"])
SUBNET["D3"] = dict(SUBNET["D1"], monitor="10.10.31.0/24", pump="10.10.32.0/24")
NODE_CLASS = {"L1-WardA-MedIoT": "monitor", "L2-WardB-MedIoT": "monitor", "L3-BuildingIoT": "bldg"}
NET_DEVICES = {"EDGE-RTR": "10.10.255.1", "SW-WARD-A": "10.10.99.11", "SW-WARD-B": "10.10.99.12",
               "SW-ADMIN": "10.10.99.13"}

POOLS = {
    "D0": [("serverPool", "10.10.0.1", "10.10.1.1", "255.255.128.0", 250)],
    "D1": [("serverPool", "10.10.20.1", "10.10.20.200", "255.255.255.0", 20),
           ("STAFF", "10.10.10.1", "10.10.10.100", "255.255.255.0", 100),
           ("MED-IOT", "10.10.30.1", "10.10.30.100", "255.255.255.0", 100),
           ("BLDG-IOT", "10.10.40.1", "10.10.40.100", "255.255.255.0", 100),
           ("GUEST", "10.10.50.1", "10.10.50.100", "255.255.255.0", 100)],
}
POOLS["D2"] = POOLS["D1"]
POOLS["D3"] = [p for p in POOLS["D1"] if p[0] != "MED-IOT"] + [
    ("MED-MONITORS", "10.10.31.1", "10.10.31.100", "255.255.255.0", 100),
    ("MED-INFUSION", "10.10.32.1", "10.10.32.100", "255.255.255.0", 100)]
DNS_RECORDS = [("ehr.hospital.local", "10.10.20.10"), ("iot.hospital.local", "10.10.20.12"),
               ("web.isp.test", "203.0.113.10")]
EHR_PAGE = "<html><body><h1>Hospital EHR - Patient Records (CONFIDENTIAL)</h1><p>marker:{nonce}</p></body></html>"
WEB_PAGE = "<html><body><h1>Public Internet web server</h1></body></html>"

LOGIN_RE = re.compile(r"Password:|Username:|User Access Verification|\[OK\]|Open", re.I)
REPLY_RE = r"Reply from {ip}\b"


def own_gateway(design: str, loc: str) -> str:
    if design == "D0":
        return "10.10.0.1"
    if loc.startswith("L3"):
        return "10.10.40.1"
    return "10.10.31.1" if design == "D3" else "10.10.30.1"


class LiveRunner:
    def __init__(self, tools: PTTools) -> None:
        self.t = tools
        self.job: dict[str, Any] = {"state": "idle"}
        self._task: asyncio.Task | None = None
        self._stop = False

    # ------------------------------------------------------------ job plumbing
    def status(self) -> dict:
        j = dict(self.job)
        j["log"] = j.get("log", [])[-400:]
        return j

    def start(self, coro_factory: Callable[[], Any], label: str) -> dict:
        if self._task and not self._task.done():
            return {"ok": False, "error": "a job is already running", "job": self.status()}
        self._stop = False
        self.job = {"id": uuid.uuid4().hex[:8], "label": label, "state": "running", "started": time.time(),
                    "log": [], "observations": 0}

        async def wrap():
            try:
                await coro_factory()
                self.job["state"] = "stopped" if self._stop else "done"
            except Exception as exc:  # noqa: BLE001
                self.job["state"] = "error"
                self.log(f"ERROR: {exc}")
            self.job["finished"] = time.time()

        self._task = asyncio.create_task(wrap())
        return {"ok": True, "job": self.status()}

    def stop(self) -> None:
        self._stop = True

    def log(self, msg: str) -> None:
        self.job.setdefault("log", []).append(f"{dt.datetime.now():%H:%M:%S} {msg}")

    def _check(self) -> None:
        if self._stop:
            raise RuntimeError("stopped by user")

    async def call(self, _tool: str, /, **args) -> dict:
        # positional-only: tools have their own `name` argument (addDnsRecord)
        self._check()
        res = await self.t.call(_tool, args)
        if not res.get("success", False):
            self.log(f"  {_tool} failed: {res.get('error')}")
        return res

    def evidence(self, design: str, tag: str, data: Any) -> str:
        d = RAW / design
        d.mkdir(parents=True, exist_ok=True)
        p = d / f"{dt.datetime.now():%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:4]}-{tag}.json"
        p.write_text(json.dumps(data, indent=1, default=str), encoding="utf-8")
        try:
            return str(p.relative_to(ROOT)).replace("\\", "/")
        except ValueError:          # evidence dir outside the project (dry-run sandbox)
            return str(p)

    # --------------------------------------------------------------- PT files
    async def open_design(self, design: str) -> None:
        path = str((project.SAVES / f"{design}.pkt").resolve())
        self.log(f"opening {path}")
        code = f"var r = ipc.appWindow().fileOpen({json.dumps(path)}); return String(r);"
        res = await self.call("ptEval", code=code)
        self.log(f"  fileOpen -> {res.get('result')}")
        await asyncio.sleep(8)  # devices boot
        await self.call("setSimulationMode", toSimMode=False)

    async def save_design(self, design: str) -> str:
        src = project.SAVES / f"{design}.pkt"
        bdir = project.SAVES / "backup"
        bdir.mkdir(exist_ok=True)
        bak = bdir / f"{design}-{dt.datetime.now():%Y%m%d-%H%M%S}.pkt"
        shutil.copy2(src, bak)
        code = f"ipc.appWindow().fileSaveAsNoPrompt({json.dumps(str(src.resolve()))}, true); return true;"
        await self.call("ptEval", code=code)
        self.log(f"saved {src.name} (backup {bak.name})")
        return str(bak)

    # ----------------------------------------------------- GUI checklist (prep)
    async def prepare(self, design: str) -> dict:
        """Apply the CHECKLIST.md GUI-only settings for one design."""
        report: dict[str, Any] = {"design": design, "steps": []}

        def step(name, res):
            ok = bool(res.get("success"))
            report["steps"].append({"step": name, "ok": ok, "detail": res.get("result", res.get("error"))})
            self.log(f"  [{'ok' if ok else 'FAIL'}] {name}")

        fixes = project.CFG / "transitions" / f"fixes-{design}.txt"
        if fixes.exists():  # analyzer findings F-1/F-3/F-4 (tests/FINDINGS.md) onto the saved .pkt
            self.log(f"prepare {design}: push {fixes.name}")
            dev, buf = None, []
            for ln in fixes.read_text(encoding="utf-8").splitlines() + ["!@END"]:
                if ln.startswith("!@"):
                    if dev and buf:
                        step(f"fixes -> {dev}", await self.call("configureIosDevice", deviceName=dev,
                                                                 commands="\n".join(buf)))
                    dev, buf = ln[2:].strip(), []
                elif ln.strip() and not ln.startswith("!"):
                    buf.append(ln)
        mask = "255.255.128.0" if design == "D0" else "255.255.255.0"
        gw = "10.10.0.1" if design == "D0" else "10.10.20.1"
        self.log(f"prepare {design}: server addressing")
        for srv, ip in SERVERS.items():
            step(f"{srv} static {ip}", await self.call("configurePcIp", deviceName=srv, dhcpEnabled=False,
                                                       ipaddress=ip, subnetMask=mask, defaultGateway=gw,
                                                       dnsServer="10.10.20.11"))
        step("INTERNET-WEB static", await self.call("configurePcIp", deviceName="INTERNET-WEB", dhcpEnabled=False,
                                                    ipaddress="203.0.113.10", subnetMask="255.255.255.0",
                                                    defaultGateway="203.0.113.1"))
        na_gw = "10.10.0.1" if design == "D0" else "10.10.99.1"
        step("NetAdmin-PC static", await self.call("configurePcIp", deviceName="NetAdmin-PC", dhcpEnabled=False,
                                                   ipaddress="10.10.99.50", subnetMask=mask, defaultGateway=na_gw,
                                                   dnsServer="10.10.20.11"))
        self.log("services")
        step("EHR page+HTTPS", await self.call("setHttpPage", deviceName="EHR-SRV",
                                               content=EHR_PAGE.format(nonce="baseline")))
        step("INTERNET-WEB page", await self.call("setHttpPage", deviceName="INTERNET-WEB", content=WEB_PAGE,
                                                  https=False))
        for srv, svc, on in [("IOT-REG-SRV", "iot", True), ("SYSLOG-NTP-SRV", "syslog", True),
                             ("SYSLOG-NTP-SRV", "ntp", True), ("DNS-DHCP-SRV", "http", False),
                             ("DNS-DHCP-SRV", "https", False), ("SYSLOG-NTP-SRV", "http", False),
                             ("SYSLOG-NTP-SRV", "https", False)]:
            step(f"{srv} {svc}={'on' if on else 'off'}", await self.call("setServerService", deviceName=srv,
                                                                       service=svc, enabled=on))
        for name, ip in DNS_RECORDS:
            step(f"DNS A {name}", await self.call("addDnsRecord", deviceName="DNS-DHCP-SRV", name=name, ip=ip))
        self.log("DHCP pools")
        want = {p[0] for p in POOLS[design]}
        cur = await self.call("listDhcpPools", deviceName="DNS-DHCP-SRV")
        for p in (cur.get("result") or {}).get("pools", []):
            if p.get("name") and p["name"] not in want and p["name"] != "serverPool":
                step(f"remove pool {p['name']}", await self.call("removeDhcpPool", deviceName="DNS-DHCP-SRV",
                                                                  poolName=p["name"]))
        for name, pgw, start, pmask, mx in POOLS[design]:
            step(f"pool {name}", await self.call("setDhcpPool", deviceName="DNS-DHCP-SRV", poolName=name,
                                                 gateway=pgw, dns="10.10.20.11", startIp=start, mask=pmask,
                                                 maxUsers=mx))
        step("DHCP on", await self.call("setServerService", deviceName="DNS-DHCP-SRV", service="dhcp", enabled=True))
        await asyncio.sleep(2)
        self.log("renew DHCP on clients")
        leases = {}
        for dev, (_cls, port) in list(DHCP_HOSTS.items()) + [(NODE, ("node", "FastEthernet0"))]:
            r = await self.call("renewDhcp", deviceName=dev, port=port, wait=10)
            leases[dev] = (r.get("result") or {}) if r.get("success") else {"error": r.get("error")}
            step(f"lease {dev} -> {leases[dev].get('ip')}", r)
        report["leases"] = leases
        report["evidence"] = self.evidence(design, "prepare", report)
        return report

    # ------------------------------------------------------------- primitives
    async def ping(self, src: str, ip: str, count: int = 3) -> dict:
        r = await self.call("pcCommand", deviceName=src, command=f"ping -n {count} {ip}", wait=12 + 6 * count)
        out = (r.get("result") or {}).get("output", "")
        return {"ip": ip, "reply": bool(re.search(REPLY_RE.format(ip=re.escape(ip)), out)), "output": out}

    async def login_probe(self, src: str, cmd: str) -> dict:
        r = await self.call("pcCommand", deviceName=src, command=cmd, wait=35, settle=8)
        out = (r.get("result") or {}).get("output", "")
        reached = bool(LOGIN_RE.search(out))
        if reached:  # leave the session: three empty/bad answers close it
            await self.call("pcSession", deviceName=src, lines=["x", "x", "x", ""], wait=6)
        return {"cmd": cmd, "login_prompt": reached, "output": out}

    async def http(self, src: str, url: str, marker: str | None = None, https: bool = False) -> dict:
        r = await self.call("httpGet", deviceName=src, url=url, wait=25, https=https)
        res = r.get("result") or {}
        content = res.get("content", "") or ""
        ok = bool(res.get("changed")) and (marker is None or marker in content)
        return {"url": url, "ok": ok, "changed": res.get("changed"), "snippet": content[:300],
                "error": r.get("error")}

    async def nonce_ehr(self) -> str:
        nonce = uuid.uuid4().hex[:10]
        await self.call("setHttpPage", deviceName="EHR-SRV", content=EHR_PAGE.format(nonce=nonce))
        return nonce

    async def move_node(self, loc: str) -> dict:
        sw, port = LOCATIONS[loc]
        await self.call("removeLink", links=[{"device": NODE, "port": "FastEthernet0"}])
        await asyncio.sleep(1)
        await self.call("addLink", device1Name=NODE, device1Interface="FastEthernet0", device2Name=sw,
                        device2Interface=port, linkType="straight")
        await asyncio.sleep(4)
        r = await self.call("renewDhcp", deviceName=NODE, wait=15)
        self.log(f"  node at {loc} ({sw} {port}) ip={(r.get('result') or {}).get('ip')}")
        return r.get("result") or {}

    async def discover_targets(self, design: str, loc: str) -> list[tuple[str, str]]:
        targets = []
        for dev, (_c, port) in DHCP_HOSTS.items():
            r = await self.call("getHostIp", deviceName=dev, port=port)
            ip = (r.get("result") or {}).get("ip")
            targets.append((dev, ip if ip and ip != "0.0.0.0" else ""))
        targets += [("NetAdmin-PC", "10.10.99.50")] + list(SERVERS.items())
        targets += [("CORE-MLS (own gateway)", own_gateway(design, loc))] + list(NET_DEVICES.items())
        return targets  # 13 + 1 + 4 + 1 + 4 = 23

    # ------------------------------------------------------------------ tests
    async def a1_a4(self, design: str, loc: str, trial: int) -> dict:
        """A1 recon, A2 EHR, A3 IoT hijack, A4 infra takeover + attack surface."""
        targets = await self.discover_targets(design, loc)
        node_ip = ((await self.call("getHostIp", deviceName=NODE)).get("result") or {}).get("ip")
        snaps = [("start", await self.deny_hits(design))]
        hosts = []
        for name, ip in targets:
            if not ip:
                hosts.append({"name": name, "ip": "", "reply": None, "note": "no address"})
                continue
            if ip == node_ip:
                continue
            p = await self.ping(NODE, ip, count=2)
            hosts.append({"name": name, **{k: p[k] for k in ("ip", "reply")}})
            self.log(f"    ping {name} {ip}: {'reply' if p['reply'] else 'no reply'}")
        reachable_hosts = sum(1 for h in hosts if h["reply"])
        snaps.append(("A1", await self.deny_hits(design)))

        nonce = await self.nonce_ehr()
        svc = {}
        svc["EHR HTTP"] = await self.http(NODE, "http://10.10.20.10", marker=nonce)
        svc["EHR HTTPS"] = await self.http(NODE, "https://10.10.20.10", marker=nonce, https=True)
        snaps.append(("A2", await self.deny_hits(design)))
        svc["IoT HTTP"] = await self.http(NODE, "http://10.10.20.12")
        dns = await self.call("pcCommand", deviceName=NODE, command="nslookup ehr.hospital.local", wait=20)
        dns_out = (dns.get("result") or {}).get("output", "")
        svc["DNS"] = {"ok": "10.10.20.10" in dns_out, "output": dns_out}
        svc["Internet web"] = await self.http(NODE, "http://203.0.113.10", marker="Public Internet")
        mg_cmd = "ssh -l netadmin {ip}" if design == "D3" else "telnet {ip}"
        infra = {}
        for name, ip in [("CORE-MLS", own_gateway(design, loc))] + list(NET_DEVICES.items()):
            pr = await self.login_probe(NODE, mg_cmd.format(ip=ip))
            if design == "D3" and not pr["login_prompt"]:   # attacker also tries telnet in D3
                pt = await self.login_probe(NODE, f"telnet {ip}")
                pr = {**pr, "telnet": pt, "login_prompt": pt["login_prompt"]}
            infra[name] = pr
            svc[f"mgmt {name}"] = {"ok": pr["login_prompt"]}
            self.log(f"    mgmt {name} {ip}: {'LOGIN PROMPT' if pr['login_prompt'] else 'blocked'}")
        reachable_svcs = sum(1 for v in svc.values() if v.get("ok"))
        snaps.append(("A4", await self.deny_hits(design)))
        for (_, prev), (tid, cur) in zip(snaps, snaps[1:]):
            if tid == "A4":
                prev = snaps[2][1]  # A4 window starts after the A2 snapshot (A3/DNS/web in between)
            delta = cur["total"] - prev["total"]
            project.append_row("detection", {"design": design, "location": loc, "trial": trial, "test_id": tid,
                                             "deny_hits_delta": delta, "detected": "yes" if delta > 0 else "no",
                                             "notes": f"core {prev['core']}->{cur['core']}, asa {prev['asa']}->{cur['asa']}"})

        # A3: IoT server page + ping another device class
        other = "Pump-A1"  # F-2: same cross-class target from every location
        other_ip = dict(targets).get(other, "")
        cross = next((h for h in hosts if h["name"] == other), None)
        a3_parts = [svc["IoT HTTP"]["ok"], bool(cross and cross["reply"])]
        a3 = "S" if all(a3_parts) else ("P" if any(a3_parts) else "B")
        servers_hit = sum(1 for h in hosts if h["name"] in SERVERS and h["reply"])
        a1 = "S" if reachable_hosts >= len([h for h in hosts if h["ip"]]) else ("B" if reachable_hosts == 0 else "P")
        out = {
            "A1": (a1, f"{reachable_hosts}/{len(hosts)} hosts replied; servers {servers_hit}/4"),
            "A2": ("S" if svc["EHR HTTP"]["ok"] or svc["EHR HTTPS"]["ok"] else "B",
                   f"EHR http={svc['EHR HTTP']['ok']} https={svc['EHR HTTPS']['ok']} (nonce page)"),
            "A3": (a3, f"IoT server page={a3_parts[0]}; ping {other} {other_ip}={a3_parts[1]}"),
            "A4": ("S" if any(v["login_prompt"] for v in infra.values()) else "B",
                   "login prompt on " + (",".join(k for k, v in infra.items() if v["login_prompt"]) or "none")),
        }
        ev = self.evidence(design, f"{loc}-t{trial}-A1-A4", {"hosts": hosts, "services": svc, "infra": infra,
                                                              "node_ip": node_ip, "outcomes": out})
        return {"outcomes": out, "hosts": reachable_hosts, "services": reachable_svcs, "evidence": ev,
                "host_list": [h["name"] for h in hosts if h["reply"]]}

    async def nurse_gateway(self) -> str:
        r = await self.call("pcCommand", deviceName="Nurse-PC-A", command="ipconfig", wait=10, settle=3)
        out = (r.get("result") or {}).get("output", "")
        m = re.findall(r"Default Gateway[ .]*:\s*([0-9.]+)", out)
        return m[-1] if m else ""

    async def a5(self, design: str, trial: int) -> tuple[str, str, str]:
        rogue_ip = "10.10.66.66" if design == "D0" else "10.10.10.66"
        mask = "255.255.128.0" if design == "D0" else "255.255.255.0"
        await self.call("configurePcIp", deviceName="ROGUE-DHCP", dhcpEnabled=False, ipaddress=rogue_ip,
                        subnetMask=mask, defaultGateway=rogue_ip)
        await self.call("setDhcpPool", deviceName="ROGUE-DHCP", poolName="serverPool", gateway=rogue_ip,
                        dns=rogue_ip, startIp="10.10.10.200" if design != "D0" else "10.10.66.100",
                        mask=mask, maxUsers=20)
        await self.call("setServerService", deviceName="ROGUE-DHCP", service="dhcp", enabled=True)
        await self.call("addLink", device1Name="ROGUE-DHCP", device1Interface="FastEthernet0",
                        device2Name="SW-WARD-A", device2Interface="FastEthernet0/5", linkType="straight")
        await asyncio.sleep(5)
        await self.call("configurePcIp", deviceName="Nurse-PC-A", dhcpEnabled=False, ipaddress="10.10.10.250",
                        subnetMask="255.255.255.0")
        lease = await self.call("renewDhcp", deviceName="Nurse-PC-A", wait=12)
        gw = await self.nurse_gateway()
        snoop = await self.call("iosExec", deviceName="SW-WARD-A", command="show ip dhcp snooping")
        await self.call("removeLink", links=[{"device": "ROGUE-DHCP", "port": "FastEthernet0"}])
        await asyncio.sleep(2)
        await self.call("renewDhcp", deviceName="Nurse-PC-A", wait=12)
        outcome = "S" if gw == rogue_ip else ("B" if gw else "")
        ev = self.evidence(design, f"t{trial}-A5", {"lease": lease, "gateway_after": gw, "rogue": rogue_ip,
                                                    "snooping": snoop})
        return outcome, f"Nurse-PC-A gateway after renew = {gw or 'unknown'} (rogue {rogue_ip})", ev

    async def a6(self, design: str, trial: int) -> tuple[str, str, str]:
        await self.call("removeLink", links=[{"device": "Monitor-A1", "port": "FastEthernet0"}])
        await asyncio.sleep(1)
        await self.call("addLink", device1Name="ROGUE-LAPTOP", device1Interface="FastEthernet0",
                        device2Name="SW-WARD-A", device2Interface="FastEthernet0/2", linkType="straight")
        await asyncio.sleep(5)
        lease = await self.call("renewDhcp", deviceName="ROGUE-LAPTOP", wait=12)
        ip = (lease.get("result") or {}).get("ip") or ""
        gw = own_gateway(design, "L1")
        p = await self.ping("ROGUE-LAPTOP", gw, count=2)
        ps = await self.call("iosExec", deviceName="SW-WARD-A", command="show port-security interface fa0/2")
        ps_out = (ps.get("result") or {}).get("output", "")
        errdis = bool(re.search(r"Secure-shutdown|err-?disabled", ps_out, re.I))
        # restore
        await self.call("removeLink", links=[{"device": "ROGUE-LAPTOP", "port": "FastEthernet0"}])
        await asyncio.sleep(1)
        await self.call("addLink", device1Name="Monitor-A1", device1Interface="FastEthernet0",
                        device2Name="SW-WARD-A", device2Interface="FastEthernet0/2", linkType="straight")
        if errdis:
            await self.call("configureIosDevice", deviceName="SW-WARD-A",
                            commands="interface FastEthernet0/2\n shutdown\n no shutdown")
        outcome = "S" if p["reply"] else "B"
        ev = self.evidence(design, f"t{trial}-A6", {"lease_ip": ip, "ping_gateway": p, "port_security": ps_out,
                                                    "err_disabled": errdis})
        return outcome, f"rogue laptop ip={ip or 'none'} ping gw={p['reply']} port err-disabled={errdis}", ev

    async def a7(self, design: str, trial: int) -> tuple[str, str, str]:
        nonce = await self.nonce_ehr()
        h = await self.http("Guest-Phone", "http://10.10.20.10", marker=nonce)
        ip = ((await self.call("getHostIp", deviceName="Guest-Phone", port="Wireless0")).get("result") or {}).get("ip")
        if not ip or ip == "0.0.0.0":
            ev = self.evidence(design, f"t{trial}-A7", {"guest_ip": ip, "http": h})
            return "", "Guest-Phone has no IP (Wi-Fi not associated) - not run", ev
        # H-1 path (ECC review): guest -> EDGE-RTR WAN address -> Telnet/SSH
        edge = await self.login_probe("Guest-Phone", ("ssh -l netadmin " if design == "D3" else "telnet ") + "198.51.100.2")
        ev = self.evidence(design, f"t{trial}-A7", {"guest_ip": ip, "http": h, "edge_wan_mgmt": edge})
        if h["ok"] and edge["login_prompt"]:
            v = "S"
        elif h["ok"] or edge["login_prompt"]:
            v = "P"
        else:
            v = "B"
        return v, (f"guest {ip} EHR page {'loaded' if h['ok'] else 'not loaded'}; "
                   f"EDGE WAN 198.51.100.2 login prompt={edge['login_prompt']}"), ev

    async def functional(self, design: str) -> list[tuple[str, str, str]]:
        res = []
        nonce = await self.nonce_ehr()
        f1 = await self.http("Nurse-PC-A", "http://ehr.hospital.local", marker=nonce)
        res.append(("F1", "PASS" if f1["ok"] else "FAIL", f"EHR by name loaded={f1['ok']}"))
        f2 = await self.ping("Nurse-PC-A", "10.10.20.10")
        res.append(("F2", "PASS" if f2["reply"] else "FAIL", "ping EHR " + ("replied" if f2["reply"] else "no reply")))
        res.append(("F3", "", "manual: IoT dashboard device list has no script API"))
        bad = []
        for dev, (cls, port) in DHCP_HOSTS.items():
            ip = ((await self.call("getHostIp", deviceName=dev, port=port)).get("result") or {}).get("ip") or ""
            try:
                ok = ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(SUBNET[design][cls])
            except ValueError:
                ok = False
            if not ok:
                bad.append(f"{dev}={ip or 'none'}")
        res.append(("F4", "PASS" if not bad else "FAIL",
                    "all clients in correct subnet" if not bad else "wrong/none: " + ", ".join(bad)))
        f5 = await self.http("Guest-Phone", "http://web.isp.test", marker="Public Internet")
        res.append(("F5", "PASS" if f5["ok"] else "FAIL", f"guest Internet page loaded={f5['ok']}"))
        f6a = await self.http("Nurse-PC-A", "http://203.0.113.10", marker="Public Internet")
        nat = await self.call("iosExec", deviceName="EDGE-RTR", command="show ip nat translations")
        nat_out = (nat.get("result") or {}).get("output", "")
        f6 = f6a["ok"] and "198.51.100.2" in nat_out
        res.append(("F6", "PASS" if f6 else "FAIL", f"page={f6a['ok']} nat-entry={'198.51.100.2' in nat_out}"))
        if design == "D3":
            lines = ["ssh -l netadmin 10.10.99.11", "Adm1n@2026", "exit"]
        else:
            lines = ["telnet 10.10.99.11", "cisco", "exit"]
        s = await self.call("pcSession", deviceName="NetAdmin-PC", lines=lines, wait=25)
        txt = " ".join(x.get("output", "") for x in (s.get("result") or []))
        f7 = bool(re.search(r"SW-WARD-A[>#]", txt))
        res.append(("F7", "PASS" if f7 else "FAIL", f"{lines[0]} -> prompt seen={f7}"))
        res.append(("F8", "", "manual: IoT automation rule (smoke -> fan) has no script API"))
        sl = await self.call("ptEval", code=(
            "var d = ipc.network().getDevice('SYSLOG-NTP-SRV'); var p = null;"
            "try { p = d.getProcess('SyslogServer'); } catch (e) {}"
            "if (!p) { return -1; } var a = p.getAllEntries(); return a ? a.length : 0;"))
        n = sl.get("result")
        res.append(("F9", "PASS" if isinstance(n, int) and n > 0 else ("FAIL" if n == 0 else ""),
                    f"syslog entries={n}"))
        self.evidence(design, "functional", {"results": res, "nat": nat_out, "mgmt": txt[-2000:]})
        return res

    # ------------------------------------- literature-driven additions (GAP-ANALYSIS.md)
    async def deny_hits(self, design: str) -> dict:
        """Sum of deny-ACE match counters on CORE-MLS (and ASA in D3). G2 visibility."""
        out = {"core": 0, "asa": 0, "raw": {}}
        r = await self.call("iosExec", deviceName="CORE-MLS", command="show access-lists")
        txt = (r.get("result") or {}).get("output", "")
        out["raw"]["core"] = txt[-3000:]
        out["core"] = sum(int(m) for m in re.findall(r"\bdeny\b[^\n]*?\((\d+) match", txt))
        if design == "D3":
            r = await self.call("iosExec", deviceName="ASA-SRV", command="show access-list OUTSIDE-IN")
            txt = (r.get("result") or {}).get("output", "")
            out["raw"]["asa"] = txt[-3000:]
            out["asa"] = sum(int(m) for m in re.findall(r"\bdeny\b[^\n]*?hitcnt=(\d+)", txt))
        out["total"] = out["core"] + out["asa"]
        return out

    async def overhead(self, design: str, trial: int) -> None:
        """G1: RTT and hop count for legitimate flows (plan.md RQ3 overhead metric)."""
        flows = [("staff->EHR", "Nurse-PC-A", "10.10.20.10"), ("staff->Internet", "Nurse-PC-A", "203.0.113.10"),
                 ("admin->SW-WARD-A", "NetAdmin-PC", "10.10.99.11")]
        for flow, src, ip in flows:
            r = await self.call("pcCommand", deviceName=src, command=f"ping -n 10 {ip}", wait=60, settle=6)
            out = (r.get("result") or {}).get("output", "")
            times = [int(t) for t in re.findall(r"time[=<](\d+)ms", out)]
            avg = re.search(r"Average = (\d+)ms", out)
            t = await self.call("pcCommand", deviceName=src, command=f"tracert {ip}", wait=60, settle=8)
            tout = (t.get("result") or {}).get("output", "")
            hops = len(re.findall(r"^\s*\d+\s+.*?(\d+\.\d+\.\d+\.\d+)\s*$", tout, re.M))
            stamp = f"auto {dt.date.today():%Y-%m-%d}; {len(times)}/10 replies"
            project.append_row("overhead", {"design": design, "trial": trial, "flow": flow, "metric": "rtt_avg",
                                            "value": avg.group(1) if avg else "", "unit": "ms", "notes": stamp})
            project.append_row("overhead", {"design": design, "trial": trial, "flow": flow, "metric": "rtt_max",
                                            "value": max(times) if times else "", "unit": "ms", "notes": stamp})
            project.append_row("overhead", {"design": design, "trial": trial, "flow": flow, "metric": "hops",
                                            "value": hops or "", "unit": "hops", "notes": tout.strip()[-200:]})
            self.log(f"    overhead {flow}: avg={avg.group(1) if avg else '?'}ms hops={hops}")
        t0 = time.time()
        nonce = await self.nonce_ehr()
        h = await self.http("Nurse-PC-A", "http://10.10.20.10", marker=nonce)
        project.append_row("overhead", {"design": design, "trial": trial, "flow": "staff->EHR web",
                                        "metric": "http_load", "value": round(time.time() - t0, 1) if h["ok"] else "",
                                        "unit": "s (wall clock, 1 s polling)", "notes": f"loaded={h['ok']}"})

    async def a8(self, design: str, trial: int) -> tuple[str, str, str]:
        """G6: rogue switch on a staff wall jack tries DTP trunk negotiation (switch spoofing)."""
        port = "FastEthernet0/5"
        await self.call("removeDevice", deviceNames=["ROGUE-SW"])
        await self.call("addDevice", deviceName="ROGUE-SW", deviceModel="2960-24TT", x=600, y=780)
        await asyncio.sleep(3)
        await self.call("configureIosDevice", deviceName="ROGUE-SW",
                        commands="interface GigabitEthernet0/1\n switchport mode dynamic desirable")
        await self.call("addLink", device1Name="ROGUE-SW", device1Interface="GigabitEthernet0/1",
                        device2Name="SW-WARD-B", device2Interface=port, linkType="cross")
        await asyncio.sleep(40)  # STP listening/learning + DTP
        tr = await self.call("iosExec", deviceName="SW-WARD-B", command="show interfaces trunk")
        tr_out = (tr.get("result") or {}).get("output", "")
        st = await self.call("iosExec", deviceName="SW-WARD-B", command="show interfaces status err-disabled")
        st_out = (st.get("result") or {}).get("output", "")
        trunked = bool(re.search(r"Fa0/5\s+\S+\s+(on|desirable|auto)?\s*\S*\s*trunking", tr_out, re.I)) or \
            bool(re.search(r"Fa0/5[^\n]*trunking", tr_out))
        errdis = "Fa0/5" in st_out
        await self.call("removeLink", links=[{"device": "ROGUE-SW", "port": "GigabitEthernet0/1"}])
        await self.call("removeDevice", deviceNames=["ROGUE-SW"])
        if errdis:
            await self.call("configureIosDevice", deviceName="SW-WARD-B",
                            commands=f"interface {port}\n shutdown\n no shutdown")
        outcome = "S" if trunked else "B"
        ev = self.evidence(design, f"t{trial}-A8", {"trunk": tr_out, "errdisabled": st_out})
        return outcome, f"trunk formed on Fa0/5={trunked}; port err-disabled={errdis}", ev

    async def q1(self, design: str, trial: int) -> dict:
        """G7: detect the compromised node from ACL deny counters and quarantine its port."""
        loc = "L1-WardA-MedIoT"
        sw, port = LOCATIONS[loc]
        acl = {"D2": "MEDIOT-IN", "D3": "MONITORS-IN"}.get(design)
        row = {"test_id": "Q1", "test_name": "Automated detect-and-quarantine", "design": design,
               "location": loc, "trial": trial, "expected": "B" if acl else "S"}
        if not acl:
            row.update(observed="S", notes="no SVI ACL on the node's VLAN -> no deny telemetry -> nothing to trigger on")
            project.append_row("extended-attacks", row)
            return row
        await self.move_node(loc)
        node = (await self.call("getHostIp", deviceName=NODE)).get("result") or {}

        async def denies() -> int:
            r = await self.call("iosExec", deviceName="CORE-MLS", command=f"show access-lists {acl}")
            return sum(int(m) for m in re.findall(r"\bdeny\b[^\n]*?\((\d+) match", (r.get("result") or {}).get("output", "")))

        base = await denies()
        t0 = time.time()
        attack = asyncio.create_task(self.call("pcCommand", deviceName=NODE, command="ping -n 20 10.10.99.11",
                                               wait=90, settle=10))
        t_detect = None
        while time.time() - t0 < 80:
            await asyncio.sleep(2)
            if await denies() - base >= 3:
                t_detect = time.time()
                break
        t_contain, found_port = None, None
        if t_detect:
            mac = (node.get("mac") or "").lower()
            mt = await self.call("iosExec", deviceName=sw, command="show mac address-table")
            for line in (mt.get("result") or {}).get("output", "").splitlines():
                if mac and mac in line.lower():
                    m = re.search(r"(Fa\d+/\d+|Gi\d+/\d+)", line)
                    found_port = m.group(1) if m else None
            target = found_port or port.replace("FastEthernet", "Fa")
            await self.call("configureIosDevice", deviceName=sw,
                            commands=f"interface {target}\n switchport access vlan 999")
            t_contain = time.time()
        await attack
        after = await self.ping(NODE, own_gateway(design, loc), count=2)
        collateral = await self.ping("Nurse-PC-A", "10.10.20.10", count=2)
        await self.call("configureIosDevice", deviceName=sw,
                        commands=f"interface {port}\n switchport access vlan {31 if design == 'D3' else 30}")
        contained = t_contain is not None and not after["reply"]
        row.update(observed="B" if contained else "S",
                   time_to_detect_s=round(t_detect - t0, 1) if t_detect else "",
                   time_to_contain_s=round(t_contain - t0, 1) if t_contain else "",
                   collateral_ok=str(collateral["reply"]),
                   notes=f"deny counter {acl}; port from MAC table={found_port}; node isolated={not after['reply']}; "
                         + self.evidence(design, f"t{trial}-Q1", {"node": node, "after": after, "collateral": collateral}))
        project.append_row("extended-attacks", row)
        self.log(f"    Q1: detect={row['time_to_detect_s']}s contain={row['time_to_contain_s']}s "
                 f"isolated={not after['reply']} collateral_ok={collateral['reply']}")
        return row

    async def probe_protected(self, design: str) -> None:
        """G8: does PT's 2960 accept `switchport protected` (PVLAN edge) for the same-VLAN gap?"""
        await self.call("configureIosDevice", deviceName="SW-WARD-B", commands="interface FastEthernet0/6\n switchport protected")
        r = await self.call("iosExec", deviceName="SW-WARD-B", command="show running-config interface FastEthernet0/6")
        out = (r.get("result") or {}).get("output", "")
        ok = "switchport protected" in out
        await self.call("configureIosDevice", deviceName="SW-WARD-B", commands="interface FastEthernet0/6\n no switchport protected")
        project.append_row("probes", {"design": design, "probe": "switchport protected", "result": "supported" if ok else "rejected",
                                      "notes": out.strip()[-300:]})
        self.log(f"    probe switchport protected: {'supported' if ok else 'rejected'}")

    # ------------------------------------------------------------- orchestration
    async def run_design(self, design: str, *, open_file: bool, prep: bool, save: bool,
                         tests: list[str], locations: list[str], trials: int) -> None:
        self.job["design"] = design
        if open_file:
            await self.open_design(design)
        await self.call("setSimulationMode", toSimMode=False)
        if prep:
            await self.prepare(design)
            if save:
                await self.save_design(design)
        stamp = f"auto {dt.date.today():%Y-%m-%d}"
        if any(t in tests for t in ("A1", "A2", "A3", "A4")):
            for loc in locations:
                await self.move_node(loc)
                for trial in range(1, trials + 1):
                    self.log(f"{design} {loc} trial {trial}: A1-A4")
                    r = await self.a1_a4(design, loc, trial)
                    for tid, (v, why) in r["outcomes"].items():
                        if tid in tests:
                            self.job["observations"] += project.record_observation(
                                "attack-matrix", {"test_id": tid, "design": design, "location": loc,
                                                  "trial": str(trial)},
                                {"observed": v, "notes": f"{stamp}; {why}; {r['evidence']}"})
                    if "A1" in tests:
                        project.append_observed_hosts({"design": design, "location": loc, "trial": trial,
                                                       "hosts": r["host_list"], "evidence": r["evidence"]})
                        project.record_observation(
                            "attack-surface", {"design": design, "location": loc, "trial": str(trial)},
                            {"observed_hosts_of_23": str(r["hosts"]), "observed_services_of_10": str(r["services"]),
                             "notes": f"{stamp}; {r['evidence']}"})
            await self.move_node("L1-WardA-MedIoT")
        for tid, fn, loc in [("A5", self.a5, "SW-WARD-A Fa0/5"), ("A6", self.a6, "SW-WARD-A Fa0/2"),
                             ("A7", self.a7, "Guest-Phone")]:
            if tid not in tests:
                continue
            for trial in range(1, trials + 1):
                self.log(f"{design} {tid} trial {trial}")
                v, why, ev = await fn(design, trial)
                self.log(f"    -> {v or 'not run'}: {why}")
                if v:
                    self.job["observations"] += project.record_observation(
                        "attack-matrix", {"test_id": tid, "design": design, "location": loc, "trial": str(trial)},
                        {"observed": v, "notes": f"{stamp}; {why}; {ev}"})
        if "A8" in tests:
            for trial in range(1, trials + 1):
                self.log(f"{design} A8 rogue switch trial {trial}")
                v, why, ev = await self.a8(design, trial)
                self.log(f"    -> {v}: {why}")
                project.append_row("extended-attacks", {
                    "test_id": "A8", "test_name": "Rogue switch / DTP switch spoofing", "design": design,
                    "location": "SW-WARD-B Fa0/5", "trial": trial, "expected": "S" if design == "D0" else "B",
                    "observed": v, "notes": f"{stamp}; {why}; {ev}"})
        if "Q1" in tests:
            for trial in range(1, trials + 1):
                self.log(f"{design} Q1 detect-and-quarantine trial {trial}")
                await self.q1(design, trial)
            await self.move_node("L1-WardA-MedIoT")
        if "O1" in tests:
            for trial in range(1, trials + 1):
                self.log(f"{design} O1 overhead trial {trial}")
                await self.overhead(design, trial)
        if "PE" in tests:
            await self.probe_protected(design)
        if "F" in tests:
            self.log(f"{design} functional F1-F9")
            for fid, v, why in await self.functional(design):
                self.log(f"    {fid}: {v or 'manual'} ({why})")
                if v:
                    self.job["observations"] += project.record_observation(
                        "functional", {"test_id": fid, "design": design}, {"observed": v, "notes": f"{stamp}; {why}"})
        # restore baseline EHR page so the saved file is clean
        await self.call("setHttpPage", deviceName="EHR-SRV", content=EHR_PAGE.format(nonce="baseline"))
