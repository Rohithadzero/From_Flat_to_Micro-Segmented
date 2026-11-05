"""Static reachability / policy verifier for the four hospital designs (D0-D3).

An independent oracle: it reads ONLY the device configs in configs/<design>/
plus the end-device facts in configs/END-DEVICES.md (encoded below as data),
builds a model of the network (Layer-2 bridge domains, routing tables, ACLs,
ASA policy, VTY access rules, DHCP relay/snooping, port security) and then
predicts, for every test of README section 7, whether it succeeds.

Nothing here is hand-typed outcome data: every verdict is computed by walking
a packet hop by hop through the parsed configuration. The result of each
decision carries the config file + line of the rule that decided it.

Model (what is and is not simulated)
  * L2: bridge domains are computed from switchport modes, access VLANs,
    trunk allowed lists / native VLANs / DTP mode and the physical links.
    Two hosts in the same bridge domain talk directly: SVI ACLs never see
    that traffic (the residual-risk finding of the paper).
  * L3: connected + static routes, ASA routes, a small OSPF emulation
    (adjacency, network statements, passive interfaces, default-information
    originate, redistribute static), longest-prefix match, AD.
  * IOS ACLs: named/numbered, standard/extended, wildcard masks, host/any,
    eq/neq/lt/gt/range, ICMP types, first match, implicit deny. Inbound ACLs
    also filter traffic addressed to the router itself; router-originated
    traffic is not filtered by outbound ACLs (IOS behaviour).
  * ASA: access-group per interface, subnet masks, security levels,
    stateful return traffic (connection table), `inspect icmp`.
  * NAT/PAT on EDGE-RTR (inside/outside + source list).
  * Device management: VTY transport input, access-class, login method,
    SSH prerequisites.
  * DHCP: relay (helper + giaddr pool choice), DHCP snooping trust,
    representative leases (pool start + index) for DHCP clients.
Not simulated: timing, ARP/STP convergence, PT application quirks (e.g. the
actual TCP port PT IoT devices use for registration; we assume TCP 80 as the
configs do), MAC-flooding, VTP.

API
  analyze(design) -> dict          one design ("D0".."D3")
  analyze_all()   -> dict          all four + disagreements vs expected
  load_design(design, config_dir=None) -> Model   (parsed model, for tests)

CLI
  python tools/policy_analyzer.py                 analyse all, write results/static-*.{csv,json}
  python tools/policy_analyzer.py --design D3     print one design
  python tools/policy_analyzer.py --json          print JSON to stdout
  python tools/policy_analyzer.py --design D3 --config-dir results/raw/D3/running
        analyse configs captured from the live devices (show running-config)
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIGS = ROOT / "configs"
RESULTS = ROOT / "results"
DESIGNS = ["D0", "D1", "D2", "D3"]
DESIGN_DIRS = {"D0": "D0-flat", "D1": "D1-vlan", "D2": "D2-zone-acl", "D3": "D3-microseg"}
ALL_ONES = 0xFFFFFFFF
EPHEMERAL = 49152


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------
def ip2i(s: str) -> int:
    return int(ipaddress.IPv4Address(s))


def i2ip(i: int) -> str:
    return str(ipaddress.IPv4Address(i))


def is_dotted(s: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", s or ""))


def mask_is_contiguous(mask: int) -> bool:
    """True for a real subnet mask (1...10...0)."""
    inv = (~mask) & ALL_ONES
    return (inv & (inv + 1)) == 0


def prefixlen(mask: int) -> int:
    return bin(mask).count("1")


def net_of(ip: int, mask: int) -> int:
    return ip & mask


PORT_NAMES = {
    "www": 80, "http": 80, "https": 443, "telnet": 23, "ssh": 22, "domain": 53,
    "bootps": 67, "bootpc": 68, "tftp": 69, "ntp": 123, "syslog": 514,
    "snmp": 161, "smtp": 25, "ftp": 21, "pop3": 110, "isakmp": 500,
}
ICMP_TYPES = {
    "echo-reply": 0, "unreachable": 3, "source-quench": 4, "redirect": 5,
    "echo": 8, "time-exceeded": 11, "parameter-problem": 12,
}
PROTO_NUM = {"ip": None, "tcp": 6, "udp": 17, "icmp": 1, "ospf": 89, "gre": 47, "esp": 50}


def port_value(tok: str) -> int:
    if tok.isdigit():
        return int(tok)
    if tok.lower() not in PORT_NAMES:
        raise ValueError(f"unknown port name '{tok}' - add it to PORT_NAMES")
    return PORT_NAMES[tok.lower()]


def norm_if(name: str) -> str:
    """'FastEthernet0/1' / 'fa0/1' / 'Gig0/1' -> 'Fa0/1', 'Gi0/1'; 'Vlan10'."""
    n = name.strip()
    m = re.fullmatch(r"(?i)(fastethernet|fa|f|gigabitethernet|gig|gi|g|vlan|ethernet|eth|e)\s*([\d/.]+)", n)
    if not m:
        return n
    t = m.group(1).lower()
    if t.startswith("f"):
        p = "Fa"
    elif t.startswith("g"):
        p = "Gi"
    elif t.startswith("v"):
        p = "Vlan"
    else:
        p = "Eth"
    return p + m.group(2)


def parse_vlan_list(s: str) -> set[int]:
    out: set[int] = set()
    for part in s.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-")
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(part))
    return out


def expand_if_range(spec: str) -> list[str]:
    """'FastEthernet0/9 - 24, GigabitEthernet0/2' -> ['Fa0/9'..'Fa0/24','Gi0/2']"""
    out = []
    for seg in spec.split(","):
        seg = seg.strip()
        m = re.fullmatch(r"([A-Za-z]+)\s*(\d+)/(\d+)\s*(?:-\s*(\d+))?", seg)
        if not m:
            out.append(norm_if(seg))
            continue
        typ, slot, a, b = m.group(1), m.group(2), int(m.group(3)), m.group(4)
        b = int(b) if b else a
        for i in range(a, b + 1):
            out.append(norm_if(f"{typ}{slot}/{i}"))
    return out


# ----------------------------------------------------------------------------
# ACLs
# ----------------------------------------------------------------------------
@dataclass(frozen=True)
class Packet:
    proto: str            # 'icmp' | 'tcp' | 'udp'
    src: int
    dst: int
    sport: int = 0
    dport: int = 0
    icmp_type: int | None = None
    reply: bool = False

    def reversed(self) -> "Packet":
        it = self.icmp_type
        if self.proto == "icmp" and it == 8:
            it = 0
        return Packet(self.proto, self.dst, self.src, self.dport, self.sport, it, True)

    def __str__(self) -> str:
        if self.proto == "icmp":
            t = {8: "echo", 0: "echo-reply"}.get(self.icmp_type, str(self.icmp_type))
            return f"icmp {i2ip(self.src)} -> {i2ip(self.dst)} {t}"
        return f"{self.proto} {i2ip(self.src)}:{self.sport} -> {i2ip(self.dst)}:{self.dport}"


@dataclass
class ACE:
    action: str
    proto: str
    src: int
    src_wc: int
    dst: int = 0
    dst_wc: int = ALL_ONES
    src_port: tuple | None = None
    dst_port: tuple | None = None
    icmp_type: int | None = None
    established: bool = False
    text: str = ""
    file: str = ""
    line: int = 0
    seq: int = 0
    standard: bool = False
    mask_tokens: tuple = ()   # raw mask strings (ASA lint)

    @staticmethod
    def _addr_ok(ip: int, addr: int, wc: int) -> bool:
        keep = (~wc) & ALL_ONES
        return (ip & keep) == (addr & keep)

    @staticmethod
    def _port_ok(p: int, spec: tuple | None) -> bool:
        if spec is None:
            return True
        op = spec[0]
        if op == "eq":
            return p == spec[1]
        if op == "neq":
            return p != spec[1]
        if op == "lt":
            return p < spec[1]
        if op == "gt":
            return p > spec[1]
        if op == "range":
            return spec[1] <= p <= spec[2]
        raise ValueError(op)

    def matches(self, pkt: Packet) -> bool:
        if not self._addr_ok(pkt.src, self.src, self.src_wc):
            return False
        if self.standard:
            return True
        if self.proto != "ip" and self.proto != pkt.proto:
            return False
        if not self._addr_ok(pkt.dst, self.dst, self.dst_wc):
            return False
        if self.proto in ("tcp", "udp"):
            if not (self._port_ok(pkt.sport, self.src_port) and self._port_ok(pkt.dport, self.dst_port)):
                return False
            if self.established and not pkt.reply:
                return False
        if self.proto == "icmp" and self.icmp_type is not None:
            if pkt.icmp_type != self.icmp_type:
                return False
        return True

    def ref(self) -> str:
        return f"{self.file}:{self.line}"


@dataclass
class ACL:
    name: str
    kind: str          # 'standard' | 'extended' | 'asa'
    file: str = ""
    line: int = 0
    aces: list = field(default_factory=list)

    def evaluate(self, pkt: Packet):
        """First match wins; returns (action, ace) - ace None = implicit deny."""
        for ace in self.aces:
            if ace.matches(pkt):
                return ace.action, ace
        return "deny", None


def _parse_addr(tok: list[str], i: int, asa: bool, standard: bool = False):
    """Returns (addr, wildcard, next_index, raw_mask)."""
    t = tok[i].lower()
    if t in ("any", "any4"):
        return 0, ALL_ONES, i + 1, None
    if t == "host":
        return ip2i(tok[i + 1]), 0, i + 2, None
    addr = ip2i(tok[i])
    if i + 1 < len(tok) and is_dotted(tok[i + 1]):
        m = ip2i(tok[i + 1])
        wc = ((~m) & ALL_ONES) if asa else m
        return addr, wc, i + 2, tok[i + 1]
    if standard or asa:
        return addr, 0, i + 1, None
    raise ValueError(f"address without mask: {tok}")


def _parse_port(tok: list[str], i: int):
    if i < len(tok) and tok[i].lower() in ("eq", "neq", "lt", "gt"):
        return (tok[i].lower(), port_value(tok[i + 1])), i + 2
    if i < len(tok) and tok[i].lower() == "range":
        return ("range", port_value(tok[i + 1]), port_value(tok[i + 2])), i + 3
    return None, i


def parse_ace(body: str, kind: str, file: str = "", line: int = 0, seq: int = 0) -> ACE | None:
    """body = 'permit tcp 10.0.0.0 0.0.0.255 host 1.2.3.4 eq 80' (no ACL name)."""
    tok = body.split()
    if tok and tok[0].isdigit():          # sequence number in named ACL
        seq = int(tok[0])
        tok = tok[1:]
    if not tok or tok[0] not in ("permit", "deny"):
        return None
    action = tok[0]
    asa = kind == "asa"
    if kind == "standard":
        addr, wc, _, _ = _parse_addr(tok, 1, asa=False, standard=True)
        return ACE(action, "ip", addr, wc, standard=True, text=body.strip(), file=file, line=line, seq=seq)
    proto = tok[1].lower()
    if proto not in PROTO_NUM:
        proto = {"6": "tcp", "17": "udp", "1": "icmp"}.get(proto, proto)
    i = 2
    s, swc, i, smask = _parse_addr(tok, i, asa)
    sport = None
    if proto in ("tcp", "udp"):
        sport, i = _parse_port(tok, i)
    d, dwc, i, dmask = _parse_addr(tok, i, asa)
    dport = None
    icmp_t = None
    est = False
    if proto in ("tcp", "udp"):
        dport, i = _parse_port(tok, i)
    rest = [t.lower() for t in tok[i:]]
    if proto == "icmp" and rest and rest[0] not in ("log",):
        icmp_t = int(rest[0]) if rest[0].isdigit() else ICMP_TYPES[rest[0]]
    if "established" in rest:
        est = True
    return ACE(action, proto, s, swc, d, dwc, sport, dport, icmp_t, est, body.strip(), file, line, seq,
               mask_tokens=tuple(m for m in (smask, dmask) if m))


# ----------------------------------------------------------------------------
# Device model + parser
# ----------------------------------------------------------------------------
@dataclass
class Iface:
    name: str
    device: str
    ip: int | None = None
    mask: int | None = None
    shutdown: bool | None = None
    switchport: bool = True
    mode: str | None = None          # 'access' | 'trunk' | None (dynamic auto)
    access_vlan: int = 1
    native_vlan: int = 1
    allowed: set | None = None
    nonegotiate: bool = False
    encapsulation: str | None = None
    acl_in: str | None = None
    acl_out: str | None = None
    helpers: list = field(default_factory=list)
    ps_enabled: bool = False
    ps_max: int = 1
    ps_sticky: bool = False
    ps_violation: str = "shutdown"
    snoop_trust: bool = False
    nat: str | None = None
    nameif: str | None = None
    security_level: int | None = None
    portfast: bool = False
    bpduguard: bool = False
    description: str = ""
    lines: dict = field(default_factory=dict)   # attribute -> config line no

    @property
    def is_svi(self) -> bool:
        return self.name.startswith("Vlan")

    @property
    def vlan_id(self) -> int | None:
        return int(self.name[4:]) if self.is_svi else None

    def up(self, default_shut: bool) -> bool:
        return not (self.shutdown if self.shutdown is not None else default_shut)


@dataclass
class Device:
    name: str
    kind: str                       # 'router' | 'mls' | 'l2' | 'asa'
    file: str = ""
    hostname: str = ""
    ifaces: dict = field(default_factory=dict)
    acls: dict = field(default_factory=dict)
    static_routes: list = field(default_factory=list)   # (net, mask, nh|ifname, ad, line)
    ip_routing: bool = False
    default_gateway: int | None = None
    vlans: dict = field(default_factory=dict)
    snooping: bool = False
    snooping_vlans: set = field(default_factory=set)
    snoop_option82: bool = True
    vty: dict = field(default_factory=dict)
    console: dict = field(default_factory=dict)
    users: dict = field(default_factory=dict)
    domain_name: str | None = None
    crypto_key: bool = False
    ssh_version: int | None = None
    ospf: dict | None = None
    nat_rules: list = field(default_factory=list)
    logging_hosts: list = field(default_factory=list)
    ntp_servers: list = field(default_factory=list)
    access_groups: dict = field(default_factory=dict)  # ASA nameif -> (acl, line)
    inspect: set = field(default_factory=set)
    enable_secret: str | None = None
    password_encryption: bool = False
    lines: list = field(default_factory=list)          # raw (lineno, text)

    def iface(self, name: str) -> Iface:
        n = norm_if(name)
        if n not in self.ifaces:
            self.ifaces[n] = Iface(n, self.name, switchport=(self.kind in ("mls", "l2") and not n.startswith("Vlan")))
        return self.ifaces[n]

    def default_shut(self, ifc: Iface) -> bool:
        if self.kind in ("router", "asa"):
            return True
        return False

    def up_ifaces(self):
        for ifc in self.ifaces.values():
            if ifc.up(self.default_shut(ifc)) and ifc.ip is not None:
                if ifc.is_svi and ifc.vlan_id != 1 and ifc.vlan_id not in self.vlans:
                    continue      # SVI for a VLAN that does not exist stays down
                if self.kind == "asa" and not ifc.nameif:
                    continue
                yield ifc

    def own_ips(self) -> dict:
        return {ifc.ip: ifc for ifc in self.up_ifaces()}

    def nameif_iface(self, nameif: str) -> Iface | None:
        for ifc in self.ifaces.values():
            if ifc.nameif == nameif:
                return ifc
        return None


DEVICE_KIND = {"CORE-MLS": "mls", "EDGE-RTR": "router", "ISP-RTR": "router", "ASA-SRV": "asa",
               "SW-WARD-A": "l2", "SW-WARD-B": "l2", "SW-ADMIN": "l2", "SW-SRV": "l2"}
DEFAULT_PORTS = {
    "mls": [f"Fa0/{i}" for i in range(1, 25)] + ["Gi0/1", "Gi0/2"],
    "l2": [f"Fa0/{i}" for i in range(1, 25)] + ["Gi0/1", "Gi0/2"],
    "router": ["Gi0/0", "Gi0/1", "Gi0/2"],
    "asa": [f"Gi1/{i}" for i in range(1, 9)],
}


def parse_config(text: str, name: str, file: str = "") -> Device:
    kind = DEVICE_KIND.get(name, "router")
    dev = Device(name, kind, file=file, hostname=name)
    for p in DEFAULT_PORTS[kind]:
        dev.iface(p)
    ctx = None          # ('if', [ifaces]) | ('acl', ACL) | ('line', key) | ('ospf',) | ('vlan', id) | ('other',)
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        s = line.strip()
        if not s or s.startswith("!"):
            continue
        dev.lines.append((lineno, s))
        indented = line[:1] in (" ", "\t")
        if not indented:
            ctx = None
            ctx = _global_cmd(dev, s, lineno, file) or None
        else:
            if ctx is None:
                continue
            _sub_cmd(dev, ctx, s, lineno, file)
    return dev


def _global_cmd(dev: Device, s: str, ln: int, file: str):
    t = s.split()
    low = s.lower()
    if t[0] == "hostname":
        dev.hostname = t[1]
    elif low == "ip routing":
        dev.ip_routing = True
    elif low.startswith("enable secret") or low.startswith("enable password"):
        dev.enable_secret = t[-1]
    elif low == "service password-encryption":
        dev.password_encryption = True
    elif low.startswith("ip domain-name"):
        dev.domain_name = t[-1]
    elif t[0] == "username":
        dev.users[t[1]] = {"privilege": int(t[t.index("privilege") + 1]) if "privilege" in t else 1, "line": ln}
    elif low.startswith("crypto key generate rsa"):
        dev.crypto_key = True
    elif low.startswith("ip ssh version"):
        dev.ssh_version = int(t[-1])
    elif t[0] == "vlan" and len(t) == 2 and t[1].isdigit():
        dev.vlans[int(t[1])] = ""
        return ("vlan", int(t[1]))
    elif low.startswith("no vlan "):
        for v in parse_vlan_list(t[2]):
            dev.vlans.pop(v, None)
    elif low.startswith("interface range "):
        ifs = [dev.iface(n) for n in expand_if_range(s[len("interface range "):])]
        for i in ifs:
            i.lines.setdefault("block", ln)
        return ("if", ifs)
    elif t[0] == "interface":
        ifc = dev.iface(" ".join(t[1:]))
        ifc.lines.setdefault("block", ln)
        if dev.kind == "mls" and ifc.is_svi:
            ifc.switchport = False
        return ("if", [ifc])
    elif low.startswith("no interface "):
        dev.ifaces.pop(norm_if(" ".join(t[2:])), None)
    elif low.startswith("ip access-list "):
        kind = t[2].lower()
        acl = ACL(t[3], kind, file, ln)
        dev.acls[t[3]] = acl            # (re)definition; files are complete configs
        return ("acl", acl)
    elif low.startswith("no ip access-list "):
        dev.acls.pop(t[-1], None)
    elif t[0] == "access-list":
        aname = t[1]
        if len(t) > 2 and t[2] == "remark":
            return None
        if dev.kind == "asa":
            if t[2] == "extended":
                acl = dev.acls.setdefault(aname, ACL(aname, "asa", file, ln))
                ace = parse_ace(" ".join(t[3:]), "asa", file, ln, len(acl.aces) + 1)
                if ace:
                    acl.aces.append(ace)
            return None
        num = int(aname)
        kind = "standard" if (1 <= num <= 99 or 1300 <= num <= 1999) else "extended"
        acl = dev.acls.setdefault(aname, ACL(aname, kind, file, ln))
        ace = parse_ace(" ".join(t[2:]), kind, file, ln, len(acl.aces) + 1)
        if ace:
            acl.aces.append(ace)
    elif t[0] == "access-group" and dev.kind == "asa":
        # access-group NAME in interface NAMEIF
        dev.access_groups[t[-1]] = (t[1], t[2], ln)
    elif t[0] == "route" and dev.kind == "asa":
        # route NAMEIF net mask nh [metric]
        dev.static_routes.append((ip2i(t[2]), ip2i(t[3]), ip2i(t[4]), 1, ln, t[1]))
    elif low.startswith("ip route "):
        net, mask = ip2i(t[2]), ip2i(t[3])
        nh = t[4]
        ad = int(t[5]) if len(t) > 5 and t[5].isdigit() else 1
        dev.static_routes.append((net, mask, ip2i(nh) if is_dotted(nh) else norm_if(nh), ad, ln, None))
    elif low.startswith("ip default-gateway"):
        dev.default_gateway = ip2i(t[-1])
    elif low.startswith("router ospf"):
        dev.ospf = {"pid": t[2], "router_id": None, "networks": [], "passive_default": False,
                    "passive": set(), "nonpassive": set(), "default_originate": False,
                    "redistribute_static": False, "line": ln}
        return ("ospf",)
    elif low.startswith("ip nat inside source list"):
        dev.nat_rules.append({"acl": t[5], "iface": norm_if(t[7]) if t[6] == "interface" else None,
                              "overload": "overload" in t, "line": ln})
    elif t[0] == "ntp" and t[1] == "server":
        dev.ntp_servers.append(ip2i(t[2]))
    elif t[0] == "logging":
        h = t[2] if t[1] == "host" else t[1]
        if is_dotted(h):
            dev.logging_hosts.append(ip2i(h))
    elif low == "ip dhcp snooping":
        dev.snooping = True
    elif low.startswith("ip dhcp snooping vlan"):
        dev.snooping_vlans |= parse_vlan_list(t[4])
    elif low == "no ip dhcp snooping information option":
        dev.snoop_option82 = False
    elif t[0] == "line":
        # a session lands on the lowest free line, so only 'line vty 0 ...' (and console 0) count
        first = len(t) > 2 and t[2] == "0"
        key = ("vty" if t[1] == "vty" else "console" if t[1] == "console" else t[1]) if first else "other"
        if key == "other":
            return ("line", "other")
        store = dev.vty if key == "vty" else dev.console
        store.setdefault("blocks", []).append(" ".join(t[1:]))
        store.setdefault("line", ln)
        return ("line", key)
    elif t[0] in ("class-map", "policy-map"):
        return ("policy",)
    return None


def _sub_cmd(dev: Device, ctx, s: str, ln: int, file: str):
    t = s.split()
    low = s.lower()
    kind = ctx[0]
    if kind == "vlan":
        if t[0] == "name":
            dev.vlans[ctx[1]] = t[1]
        return
    if kind == "acl":
        acl: ACL = ctx[1]
        if t[0] == "remark":
            return
        ace = parse_ace(s, acl.kind, file, ln, len(acl.aces) + 1)
        if ace:
            acl.aces.append(ace)
        return
    if kind == "ospf":
        o = dev.ospf
        if t[0] == "router-id":
            o["router_id"] = t[1]
        elif t[0] == "network":
            o["networks"].append((ip2i(t[1]), ip2i(t[2]), t[4]))
        elif low == "passive-interface default":
            o["passive_default"] = True
        elif t[0] == "passive-interface":
            o["passive"].add(norm_if(t[1]))
        elif low.startswith("no passive-interface"):
            o["nonpassive"].add(norm_if(t[2]))
            o["passive"].discard(norm_if(t[2]))
        elif low.startswith("default-information originate"):
            o["default_originate"] = True
        elif low.startswith("redistribute static"):
            o["redistribute_static"] = True
        return
    if kind == "line":
        if ctx[1] == "other":
            return
        store = dev.vty if ctx[1] == "vty" else dev.console
        if t[0] == "password":
            store["password"] = t[-1]
        elif low == "login":
            store["login"] = "password"
        elif low == "login local":
            store["login"] = "local"
        elif low == "no login":
            store["login"] = "none"
        elif low.startswith("transport input"):
            store["transport"] = set(t[2:])
            store["transport_line"] = ln
        elif t[0] == "access-class":
            store["access_class"] = t[1]
            store["access_class_line"] = ln
        return
    if kind == "policy":
        if t[0] == "inspect":
            dev.inspect.add(t[1])
        return
    if kind != "if":
        return
    for ifc in ctx[1]:
        if t[0] == "description":
            ifc.description = s[len("description "):]
        elif t[0] == "ip" and len(t) >= 4 and t[1] == "address" and is_dotted(t[2]):
            ifc.ip, ifc.mask = ip2i(t[2]), ip2i(t[3])
            ifc.lines["ip"] = ln
        elif low == "no ip address":
            ifc.ip = ifc.mask = None
        elif low == "shutdown":
            ifc.shutdown = True
            ifc.lines["shutdown"] = ln
        elif low == "no shutdown":
            ifc.shutdown = False
        elif low == "no switchport":
            ifc.switchport = False
            ifc.lines["no_switchport"] = ln
        elif low.startswith("switchport mode "):
            ifc.mode = t[2]
            ifc.lines["mode"] = ln
        elif low.startswith("switchport access vlan"):
            ifc.access_vlan = int(t[3])
            ifc.lines["access_vlan"] = ln
        elif low.startswith("switchport trunk native vlan"):
            ifc.native_vlan = int(t[4])
            ifc.lines["native"] = ln
        elif low.startswith("switchport trunk allowed vlan"):
            ifc.allowed = parse_vlan_list(t[4])
            ifc.lines["allowed"] = ln
        elif low.startswith("switchport trunk encapsulation"):
            ifc.encapsulation = t[3]
        elif low == "switchport nonegotiate":
            ifc.nonegotiate = True
            ifc.lines["nonegotiate"] = ln
        elif low == "switchport port-security":
            ifc.ps_enabled = True
            ifc.lines["ps"] = ln
        elif low.startswith("switchport port-security maximum"):
            ifc.ps_max = int(t[3])
            ifc.lines["ps_max"] = ln
        elif low.startswith("switchport port-security mac-address sticky"):
            ifc.ps_sticky = True
            ifc.lines["ps_sticky"] = ln
        elif low.startswith("switchport port-security violation"):
            ifc.ps_violation = t[3]
            ifc.lines["ps_violation"] = ln
        elif low == "spanning-tree portfast":
            ifc.portfast = True
        elif low == "spanning-tree bpduguard enable":
            ifc.bpduguard = True
        elif low == "ip dhcp snooping trust":
            ifc.snoop_trust = True
            ifc.lines["snoop_trust"] = ln
        elif t[0] == "ip" and t[1] == "access-group":
            if t[3] == "in":
                ifc.acl_in = t[2]
                ifc.lines["acl_in"] = ln
            else:
                ifc.acl_out = t[2]
                ifc.lines["acl_out"] = ln
        elif t[0] == "ip" and t[1] == "helper-address":
            ifc.helpers.append(ip2i(t[2]))
            ifc.lines["helper"] = ln
        elif t[0] == "ip" and t[1] == "nat":
            ifc.nat = t[2]
        elif t[0] == "nameif":
            ifc.nameif = t[1]
            ifc.switchport = False
        elif t[0] == "security-level":
            ifc.security_level = int(t[1])


# ----------------------------------------------------------------------------
# End devices, topology, DHCP pools (from configs/END-DEVICES.md, BUILD-PLAN.md)
# ----------------------------------------------------------------------------
# name, class, switch, port, addressing ('dhcp' or static key)
HOSTS = [
    ("Nurse-PC-A", "staff", "SW-WARD-A", "Fa0/1", "dhcp"),
    ("Nurse-PC-B", "staff", "SW-WARD-B", "Fa0/1", "dhcp"),
    ("Reception-PC", "staff", "SW-ADMIN", "Fa0/1", "dhcp"),
    ("NetAdmin-PC", "staff", "SW-ADMIN", "Fa0/2", "netadmin"),
    ("EHR-SRV", "server", "SW-SRV", "Fa0/1", "srv:10.10.20.10"),
    ("DNS-DHCP-SRV", "server", "SW-SRV", "Fa0/2", "srv:10.10.20.11"),
    ("IOT-REG-SRV", "server", "SW-SRV", "Fa0/3", "srv:10.10.20.12"),
    ("SYSLOG-NTP-SRV", "server", "SW-SRV", "Fa0/4", "srv:10.10.20.13"),
    ("Monitor-A1", "monitor", "SW-WARD-A", "Fa0/2", "dhcp"),
    ("Pump-A1", "pump", "SW-WARD-A", "Fa0/3", "dhcp"),
    ("Monitor-B1", "monitor", "SW-WARD-B", "Fa0/2", "dhcp"),
    ("Pump-B1", "pump", "SW-WARD-B", "Fa0/3", "dhcp"),
    ("Smart-Door", "bldg", "SW-ADMIN", "Fa0/3", "dhcp"),
    ("Fire-Monitor", "bldg", "SW-ADMIN", "Fa0/4", "dhcp"),
    ("HVAC-Fan", "bldg", "SW-ADMIN", "Fa0/5", "dhcp"),
    ("Webcam", "bldg", "SW-ADMIN", "Fa0/6", "dhcp"),
    ("Guest-Phone", "guest", "SW-ADMIN", "Fa0/8", "dhcp"),    # wireless, bridged by Guest-AP
    ("Guest-Tablet", "guest", "SW-ADMIN", "Fa0/8", "dhcp"),
    ("INTERNET-WEB", "internet", "ISP-RTR", "Gi0/1", "inet"),
]
LOCATIONS = {
    "L1": ("L1-WardA-MedIoT", "SW-WARD-A", "Fa0/4"),
    "L2": ("L2-WardB-MedIoT", "SW-WARD-B", "Fa0/4"),
    "L3": ("L3-BuildingIoT", "SW-ADMIN", "Fa0/7"),
}
SERVICES_LISTENING = {
    "EHR-SRV": {("tcp", 80), ("tcp", 443)},
    "DNS-DHCP-SRV": {("udp", 53), ("udp", 67)},
    "IOT-REG-SRV": {("tcp", 80)},
    "SYSLOG-NTP-SRV": {("udp", 514), ("udp", 123)},
    "INTERNET-WEB": {("tcp", 80)},
    "ROGUE-DHCP": {("udp", 67)},
}
INFRA = ["CORE-MLS", "EDGE-RTR", "SW-WARD-A", "SW-WARD-B", "SW-ADMIN"]
INFRA_LISTED_ADDR = {"EDGE-RTR": "10.10.255.1", "SW-WARD-A": "10.10.99.11",
                     "SW-WARD-B": "10.10.99.12", "SW-ADMIN": "10.10.99.13"}   # CORE = own gateway

# DHCP pools on DNS-DHCP-SRV: (name, gateway, start, mask)
POOLS = {
    "D0": [("serverPool", "10.10.0.1", "10.10.1.1", "255.255.128.0")],
    "D1": [("serverPool", "10.10.20.1", "10.10.20.200", "255.255.255.0"),
           ("STAFF", "10.10.10.1", "10.10.10.100", "255.255.255.0"),
           ("MED-IOT", "10.10.30.1", "10.10.30.100", "255.255.255.0"),
           ("BLDG-IOT", "10.10.40.1", "10.10.40.100", "255.255.255.0"),
           ("GUEST", "10.10.50.1", "10.10.50.100", "255.255.255.0")],
}
POOLS["D2"] = list(POOLS["D1"])
POOLS["D3"] = [p for p in POOLS["D1"] if p[0] != "MED-IOT"] + [
    ("MED-MONITORS", "10.10.31.1", "10.10.31.100", "255.255.255.0"),
    ("MED-INFUSION", "10.10.32.1", "10.10.32.100", "255.255.255.0")]
DHCP_SERVER = "DNS-DHCP-SRV"

# subnet each device class SHOULD land in (README section 3) - used by F4
INTENDED_SUBNET = {
    "D0": {c: "10.10.0.0/17" for c in ("staff", "monitor", "pump", "bldg", "guest")},
    "D1": {"staff": "10.10.10.0/24", "monitor": "10.10.30.0/24", "pump": "10.10.30.0/24",
           "bldg": "10.10.40.0/24", "guest": "10.10.50.0/24"},
}
INTENDED_SUBNET["D2"] = INTENDED_SUBNET["D1"]
INTENDED_SUBNET["D3"] = dict(INTENDED_SUBNET["D1"], monitor="10.10.31.0/24", pump="10.10.32.0/24")


def links_for(design: str):
    links = [
        (("ISP-RTR", "Gi0/0"), ("EDGE-RTR", "Gi0/0")),
        (("EDGE-RTR", "Gi0/1"), ("CORE-MLS", "Gi0/1")),
        (("CORE-MLS", "Fa0/1"), ("SW-WARD-A", "Gi0/1")),
        (("CORE-MLS", "Fa0/2"), ("SW-WARD-B", "Gi0/1")),
        (("CORE-MLS", "Fa0/3"), ("SW-ADMIN", "Gi0/1")),
    ]
    if design == "D3":
        links += [(("CORE-MLS", "Gi0/2"), ("ASA-SRV", "Gi1/1")),
                  (("ASA-SRV", "Gi1/2"), ("SW-SRV", "Gi0/1"))]
    else:
        links += [(("CORE-MLS", "Gi0/2"), ("SW-SRV", "Gi0/1"))]
    return links


@dataclass
class Host:
    name: str
    cls: str
    switch: str
    port: str
    addressing: str
    ip: int | None = None
    mask: int | None = None
    gw: int | None = None
    bd: int | None = None
    lease: dict | None = None
    services: set = field(default_factory=set)


def static_addr(design: str, h: Host):
    flat = design == "D0"
    if h.addressing.startswith("srv:"):
        return ip2i(h.addressing[4:]), ip2i("255.255.128.0" if flat else "255.255.255.0"), \
            ip2i("10.10.0.1" if flat else "10.10.20.1")
    if h.addressing == "netadmin":
        return ip2i("10.10.99.50"), ip2i("255.255.128.0" if flat else "255.255.255.0"), \
            ip2i("10.10.0.1" if flat else "10.10.99.1")
    if h.addressing == "inet":
        return ip2i("203.0.113.10"), ip2i("255.255.255.0"), ip2i("203.0.113.1")
    if h.addressing == "rogue-dhcp":
        return (ip2i("10.10.66.66"), ip2i("255.255.128.0"), None) if flat else \
            (ip2i("10.10.10.66"), ip2i("255.255.255.0"), None)
    return None


# ----------------------------------------------------------------------------
# Network model: L2 bridge domains + routing
# ----------------------------------------------------------------------------
class UF:
    def __init__(self):
        self.p = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        self.p[self.find(a)] = self.find(b)


@dataclass
class Route:
    net: int
    mask: int
    iface: str
    nh: int | None
    ad: int
    src: str
    line: int = 0


class Model:
    def __init__(self, design: str, devices: dict, extra_hosts: list | None = None, config_dir: Path | None = None):
        self.design = design
        self.devices: dict[str, Device] = devices
        self.config_dir = config_dir
        self.warnings: list[str] = []
        self.hosts: dict[str, Host] = {}
        for spec in HOSTS + (extra_hosts or []):
            h = Host(*spec)
            h.services = set(SERVICES_LISTENING.get(h.name, set()))
            self.hosts[h.name] = h
        self.links = links_for(design)
        self._build_l2()
        self._address_static()
        self._build_routes()
        self._address_dhcp()

    # ---------- L2 ----------
    def _vlan_exists(self, dev: Device, v: int) -> bool:
        return v == 1 or v in dev.vlans

    def _port_vlan_untagged(self, dev: Device, ifc: Iface) -> int:
        return ifc.native_vlan if ifc.mode == "trunk" else ifc.access_vlan

    def _build_l2(self):
        uf = UF()
        self.uf = uf
        for dev in self.devices.values():
            for ifc in dev.up_ifaces():
                node = ("l3", dev.name, ifc.name)
                uf.find(node)
                if ifc.is_svi and dev.kind in ("mls", "l2"):
                    uf.union(node, ("sw", dev.name, ifc.vlan_id))
        attached = set()
        for (da, pa), (db, pb) in self.links:
            if da not in self.devices or db not in self.devices:
                continue
            self._join(self.devices[da], self.devices[da].iface(pa), self.devices[db], self.devices[db].iface(pb))
        for h in self.hosts.values():
            dev = self.devices.get(h.switch)
            if dev is None:
                continue
            ifc = dev.iface(h.port)
            if not ifc.up(dev.default_shut(ifc)):
                self.warnings.append(f"{h.name}: {h.switch} {h.port} is shut down")
                continue
            if not ifc.switchport:
                uf.union(("host", h.name), ("l3", dev.name, ifc.name))
                attached.add(("host", h.name))
                continue
            v = self._port_vlan_untagged(dev, ifc)
            if not self._vlan_exists(dev, v):
                self.warnings.append(f"{h.name}: VLAN {v} on {h.switch} {h.port} not in VLAN database")
                continue
            uf.union(("host", h.name), ("sw", dev.name, v))
            attached.add(("host", h.name))
        for h in self.hosts.values():
            h.bd = uf.find(("host", h.name)) if ("host", h.name) in attached else None

    def _l3_end(self, dev: Device, ifc: Iface):
        return (dev.kind in ("router", "asa")) or (not ifc.switchport)

    def _join(self, da: Device, ia: Iface, db: Device, ib: Iface):
        uf = self.uf
        if not ia.up(da.default_shut(ia)) or not ib.up(db.default_shut(ib)):
            return
        la, lb = self._l3_end(da, ia), self._l3_end(db, ib)
        if la and lb:
            uf.union(("l3", da.name, ia.name), ("l3", db.name, ib.name))
            return
        if la or lb:
            (dl, il), (ds, is_) = ((da, ia), (db, ib)) if la else ((db, ib), (da, ia))
            v = self._port_vlan_untagged(ds, is_)
            if self._vlan_exists(ds, v):
                uf.union(("l3", dl.name, il.name), ("sw", ds.name, v))
            return
        # switchport <-> switchport
        def trunking(x: Iface, y: Iface):
            if x.mode == "trunk" and y.mode == "trunk":
                return True
            if x.mode == "trunk" and y.mode is None and not x.nonegotiate:
                return True
            if y.mode == "trunk" and x.mode is None and not y.nonegotiate:
                return True
            return False
        if trunking(ia, ib):
            alla = ia.allowed if ia.allowed is not None else set(range(1, 4095))
            allb = ib.allowed if ib.allowed is not None else set(range(1, 4095))
            na, nb = ia.native_vlan, ib.native_vlan
            if na != nb:
                self.warnings.append(f"native VLAN mismatch {da.name} {ia.name} ({na}) <-> {db.name} {ib.name} ({nb})")
            if na in alla and nb in allb and self._vlan_exists(da, na) and self._vlan_exists(db, nb):
                uf.union(("sw", da.name, na), ("sw", db.name, nb))
            for v in alla & allb:
                if v in (na, nb):
                    continue
                if self._vlan_exists(da, v) and self._vlan_exists(db, v):
                    uf.union(("sw", da.name, v), ("sw", db.name, v))
        else:
            va, vb = self._port_vlan_untagged(da, ia), self._port_vlan_untagged(db, ib)
            if (ia.mode == "trunk") != (ib.mode == "trunk"):
                self.warnings.append(f"trunk/access mismatch {da.name} {ia.name} <-> {db.name} {ib.name}")
            if self._vlan_exists(da, va) and self._vlan_exists(db, vb):
                uf.union(("sw", da.name, va), ("sw", db.name, vb))

    def bd_of_l3(self, dev: str, ifname: str):
        return self.uf.find(("l3", dev, ifname))

    def bd_members(self, bd):
        hosts = [h for h in self.hosts.values() if h.bd == bd]
        l3 = []
        for dev in self.devices.values():
            for ifc in dev.up_ifaces():
                if self.uf.find(("l3", dev.name, ifc.name)) == bd:
                    l3.append((dev, ifc))
        return hosts, l3

    # ---------- addressing ----------
    def _address_static(self):
        for h in self.hosts.values():
            sa = static_addr(self.design, h)
            if sa:
                h.ip, h.mask, h.gw = sa
                h.lease = {"type": "static"}

    def _address_dhcp(self):
        counters: dict[str, int] = {}
        for h in self.hosts.values():
            if h.addressing != "dhcp":
                continue
            res = self.dhcp_lease(h)
            h.lease = res
            if res.get("ok"):
                k = res["pool"]
                pool = next(p for p in POOLS[self.design] if p[0] == k)
                idx = counters.get(k, 0)
                counters[k] = idx + 1
                h.ip = ip2i(pool[2]) + idx
                h.mask = ip2i(pool[3])
                h.gw = ip2i(pool[1])
                res["ip"] = i2ip(h.ip)

    def _pool_for(self, giaddr: int):
        for p in POOLS[self.design]:
            m = ip2i(p[3])
            if net_of(giaddr, m) == net_of(ip2i(p[1]), m):
                return p
        return None

    def dhcp_lease(self, h: Host) -> dict:
        """Can host h obtain a lease from the legitimate DHCP server?"""
        if h.bd is None:
            return {"ok": False, "reason": "NO_L2: host port down or VLAN missing"}
        srv = self.hosts[DHCP_SERVER]
        steps = []
        # DHCP snooping on the client's access switch
        sw = self.devices.get(h.switch)
        port_vlan = self._port_vlan_untagged(sw, sw.iface(h.port)) if sw else None
        if sw and sw.snooping and port_vlan in sw.snooping_vlans:
            uplinks = [p for (a, b) in self.links for (d, p) in (a, b) if d == sw.name]
            trusted = [p for p in uplinks if sw.iface(p).snoop_trust]
            if not trusted:
                return {"ok": False, "reason": f"SNOOPING_DROP: {sw.name} snoops VLAN {port_vlan} but no uplink is trusted"}
            steps.append(f"snooping trust on {sw.name} {trusted[0]} ({sw.file}:{sw.iface(trusted[0]).lines.get('snoop_trust')})")
            if sw.snoop_option82:
                steps.append(f"WARN option-82 inserted by {sw.name}; relay may drop (giaddr 0)")
        if srv.bd == h.bd:
            pool = self._pool_for(srv.ip)
            if not pool:
                return {"ok": False, "reason": "NO_POOL for server subnet"}
            return {"ok": True, "pool": pool[0], "via": "local server (same L2 segment)", "steps": steps}
        hosts, l3 = self.bd_members(h.bd)
        relays = [(d, i) for d, i in l3 if i.helpers]
        if not relays:
            return {"ok": False, "reason": "NO_RELAY: no ip helper-address on this segment's gateway"}
        dev, ifc = relays[0]
        giaddr = ifc.ip
        disc = Packet("udp", 0, ALL_ONES, 68, 67)
        if dev.kind != "asa" and ifc.acl_in:
            act, ace = dev.acls[ifc.acl_in].evaluate(disc) if ifc.acl_in in dev.acls else ("permit", None)
            if act != "permit":
                return {"ok": False, "reason": f"ACL_DENY DISCOVER at {dev.name} {ifc.name} in {ifc.acl_in} "
                                               f"{_ace_ref(ace, dev, ifc.acl_in)}"}
            steps.append(f"DISCOVER permitted {dev.name} {ifc.name} in {ifc.acl_in}#{ace.seq} ({ace.ref()})")
        helper = ifc.helpers[0]
        relay_pkt = Packet("udp", giaddr, helper, 67, 67)
        fwd = self.trace(("dev", dev.name, giaddr), relay_pkt)
        if not fwd.ok:
            return {"ok": False, "reason": "RELAY_BLOCKED " + fwd.reason}
        st = fwd.state
        back = self.trace(("host", DHCP_SERVER), relay_pkt.reversed(), st)
        if not back.ok:
            return {"ok": False, "reason": "RELAY_REPLY_BLOCKED " + back.reason}
        pool = self._pool_for(giaddr)
        if not pool:
            return {"ok": False, "reason": f"NO_POOL for giaddr {i2ip(giaddr)}"}
        steps.append(f"relay {dev.name} {ifc.name} giaddr {i2ip(giaddr)} -> {i2ip(helper)}")
        return {"ok": True, "pool": pool[0], "via": f"relay {dev.name} {ifc.name}", "steps": steps}

    # ---------- routing ----------
    def _build_routes(self):
        self.rt: dict[str, list[Route]] = {}
        for dev in self.devices.values():
            rts = []
            for ifc in dev.up_ifaces():
                rts.append(Route(net_of(ifc.ip, ifc.mask), ifc.mask, ifc.name, None, 0, "connected", ifc.lines.get("ip", 0)))
            if dev.kind == "l2" and not dev.ip_routing and dev.default_gateway:
                for ifc in dev.up_ifaces():
                    if net_of(dev.default_gateway, ifc.mask) == net_of(ifc.ip, ifc.mask):
                        rts.append(Route(0, 0, ifc.name, dev.default_gateway, 1, "default-gateway"))
            self.rt[dev.name] = rts
        for dev in self.devices.values():
            for sr in dev.static_routes:
                net, mask, nh, ad, ln, nameif = sr
                if nameif:   # ASA
                    ifc = dev.nameif_iface(nameif)
                    if ifc:
                        self.rt[dev.name].append(Route(net, mask, ifc.name, nh, ad, "static", ln))
                    continue
                if isinstance(nh, int):
                    c = self._lookup(dev.name, nh, connected_only=True)
                    if c:
                        self.rt[dev.name].append(Route(net, mask, c.iface, nh, ad, "static", ln))
                else:
                    self.rt[dev.name].append(Route(net, mask, nh, None, ad, "static", ln))
        self._ospf()

    def _ospf_ifaces(self, dev: Device):
        o = dev.ospf
        out = []
        for ifc in dev.up_ifaces():
            for addr, wc, area in o["networks"]:
                keep = (~wc) & ALL_ONES
                if ifc.ip & keep == addr & keep:
                    passive = (o["passive_default"] and ifc.name not in o["nonpassive"]) or ifc.name in o["passive"]
                    out.append((ifc, passive))
                    break
        return out

    def _ospf(self):
        rtrs = [d for d in self.devices.values() if d.ospf]
        for a in rtrs:
            for b in rtrs:
                if a is b:
                    continue
                act_a = [(i, p) for i, p in self._ospf_ifaces(a) if not p]
                act_b = [(i, p) for i, p in self._ospf_ifaces(b) if not p]
                adj = None
                for ia, _ in act_a:
                    for ib, _ in act_b:
                        if self.bd_of_l3(a.name, ia.name) == self.bd_of_l3(b.name, ib.name):
                            adj = (ia, ib)
                if not adj:
                    continue
                ia, ib = adj        # a learns from b via ia, next hop ib.ip
                for ifc, _ in self._ospf_ifaces(b):
                    self.rt[a.name].append(Route(net_of(ifc.ip, ifc.mask), ifc.mask, ia.name, ib.ip, 110, "ospf"))
                if b.ospf["redistribute_static"]:
                    for r in self.rt[b.name]:
                        if r.src == "static" and r.mask != 0:
                            self.rt[a.name].append(Route(r.net, r.mask, ia.name, ib.ip, 110, "ospf-E2"))
                if b.ospf["default_originate"] and any(r.mask == 0 and r.src == "static" for r in self.rt[b.name]):
                    self.rt[a.name].append(Route(0, 0, ia.name, ib.ip, 110, "ospf-E2-default"))

    def _lookup(self, dev: str, dst: int, connected_only=False) -> Route | None:
        best = None
        for r in self.rt.get(dev, []):
            if connected_only and r.src != "connected":
                continue
            if dst & r.mask == r.net:
                if best is None or prefixlen(r.mask) > prefixlen(best.mask) or \
                        (r.mask == best.mask and r.ad < best.ad):
                    best = r
        return best

    def route_table(self, dev: str) -> list[str]:
        out = []
        for r in sorted(self.rt.get(dev, []), key=lambda r: (-prefixlen(r.mask), r.ad)):
            out.append(f"{r.src:16s} {i2ip(r.net)}/{prefixlen(r.mask)} via {i2ip(r.nh) if r.nh else 'connected'} "
                       f"{r.iface} AD {r.ad}")
        return out

    # ---------- packet walk ----------
    def trace(self, start, pkt: Packet, state: "State | None" = None) -> "Trace":
        return Walker(self, state or State()).run(start, pkt)


def _ace_ref(ace, dev: Device, aclname: str) -> str:
    if ace is None:
        acl = dev.acls.get(aclname)
        return f"implicit-deny (end of {aclname}, {acl.file}:{acl.aces[-1].line if acl and acl.aces else acl.line if acl else '?'})"
    return f"#{ace.seq} '{ace.text}' ({ace.ref()})"


@dataclass
class State:
    nat: dict = field(default_factory=dict)           # translated src -> original src
    asa_conns: set = field(default_factory=set)


@dataclass
class Trace:
    ok: bool
    reason: str
    hops: list
    state: State
    delivered: tuple | None = None
    final_pkt: Packet | None = None
    decisive: dict | None = None

    def to_dict(self):
        return {"ok": self.ok, "reason": self.reason, "hops": self.hops,
                "delivered": list(self.delivered) if self.delivered else None,
                "decisive": self.decisive}


class Walker:
    def __init__(self, m: Model, state: State):
        self.m, self.state, self.hops = m, state, []
        self.decisive = None

    def note(self, **kw):
        self.hops.append(kw)
        return kw

    def fail(self, reason, pkt, decisive=None):
        return Trace(False, reason, self.hops, self.state, None, pkt, decisive or self.decisive)

    def run(self, start, pkt: Packet) -> Trace:
        m = self.m
        if start[0] == "host":
            h = m.hosts[start[1]]
            if h.bd is None or h.ip is None:
                return self.fail(f"NO_ADDRESS {h.name} has no L2/L3 connectivity", pkt)
            self.note(at=h.name, action="send", pkt=str(pkt))
            if pkt.dst & h.mask == h.ip & h.mask:
                return self.deliver_in_bd(h.bd, pkt, l2_from=h.name)
            hosts, l3 = m.bd_members(h.bd)
            gw = [(d, i) for d, i in l3 if i.ip == h.gw]
            if not gw:
                return self.fail(f"NO_GATEWAY {h.name} gateway {i2ip(h.gw) if h.gw else None} not on its segment", pkt)
            return self.arrive(gw[0][0], gw[0][1], pkt)
        # device-originated
        dev = m.devices[start[1]]
        r = m._lookup(dev.name, pkt.dst)
        if not r:
            return self.fail(f"NO_ROUTE on {dev.name} to {i2ip(pkt.dst)}", pkt)
        egress = dev.ifaces[r.iface]
        if pkt.src == 0:
            pkt = Packet(pkt.proto, egress.ip, pkt.dst, pkt.sport, pkt.dport, pkt.icmp_type, pkt.reply)
        self.note(at=dev.name, action="originate", egress=egress.name, route=r.src, pkt=str(pkt))
        return self.leave(dev, None, egress, r, pkt)

    def deliver_in_bd(self, bd, pkt: Packet, l2_from=None) -> Trace:
        m = self.m
        hosts, l3 = m.bd_members(bd)
        for h in hosts:
            if h.ip == pkt.dst:
                if l2_from:
                    self.decisive = self.note(at=h.name, action="L2_SAME_SEGMENT",
                                              detail=f"{l2_from} -> {h.name} switched at L2; no SVI/ACL on path")
                return self.host_accept(h, pkt)
        for d, i in l3:
            if i.ip == pkt.dst:
                return self.arrive(d, i, pkt)
        return self.fail(f"ARP_FAIL no endpoint {i2ip(pkt.dst)} on segment", pkt)

    def host_accept(self, h: Host, pkt: Packet) -> Trace:
        if pkt.proto == "icmp" and pkt.icmp_type in (8, 0):
            ok = True
        elif pkt.reply:
            ok = True
        else:
            ok = (pkt.proto, pkt.dport) in h.services
        if not ok:
            return self.fail(f"PORT_CLOSED {h.name} does not listen on {pkt.proto}/{pkt.dport}", pkt)
        self.note(at=h.name, action="accept", pkt=str(pkt))
        return Trace(True, f"DELIVERED to {h.name}", self.hops, self.state, ("host", h.name), pkt, self.decisive)

    def acl_check(self, dev: Device, ifc: Iface, direction: str, aclname: str, pkt: Packet):
        acl = dev.acls.get(aclname)
        if acl is None:
            # IOS: an access-group naming a missing ACL permits everything
            self.note(at=dev.name, iface=ifc.name, dir=direction, acl=aclname, result="permit", detail="ACL undefined -> permit all")
            return True
        act, ace = acl.evaluate(pkt)
        rec = self.note(at=dev.name, iface=ifc.name, dir=direction, acl=aclname, result=act,
                        seq=ace.seq if ace else None, ace=ace.text if ace else "implicit deny ip any any",
                        ref=ace.ref() if ace else f"{acl.file}:end-of-{aclname}")
        if act != "permit":
            self.decisive = rec
            return False
        if self.decisive is None or self.decisive.get("action") != "L2_SAME_SEGMENT":
            self.decisive = rec
        return True

    def arrive(self, dev: Device, ifc: Iface, pkt: Packet) -> Trace:
        m = self.m
        if len(self.hops) > 40:
            return self.fail("LOOP", pkt)
        # NAT un-translate on outside interface
        if dev.kind == "router" and ifc.nat == "outside" and pkt.dst in self.state.nat:
            orig = self.state.nat[pkt.dst]
            self.note(at=dev.name, iface=ifc.name, action="NAT_UNTRANSLATE", detail=f"{i2ip(pkt.dst)} -> {i2ip(orig)}")
            pkt = Packet(pkt.proto, pkt.src, orig, pkt.sport, pkt.dport, pkt.icmp_type, pkt.reply)
        if dev.kind != "asa" and ifc.acl_in:
            if not self.acl_check(dev, ifc, "in", ifc.acl_in, pkt):
                return self.fail(f"ACL_DENY {dev.name} {ifc.name} in {ifc.acl_in}#{self.decisive.get('seq') or 'implicit'} "
                                 f"'{self.decisive.get('ace')}' ({self.decisive.get('ref')})", pkt)
        own = dev.own_ips()
        if pkt.dst in own:
            return self.self_accept(dev, ifc, own[pkt.dst], pkt)
        if dev.kind == "l2" or (dev.kind == "mls" and not dev.ip_routing):
            return self.fail(f"NO_ROUTING {dev.name} is not a router", pkt)
        r = m._lookup(dev.name, pkt.dst)
        if not r:
            return self.fail(f"NO_ROUTE on {dev.name} to {i2ip(pkt.dst)}", pkt)
        egress = dev.ifaces[r.iface]
        if dev.kind == "asa":
            ok, why = self.asa_policy(dev, ifc, egress, pkt)
            if not ok:
                return self.fail(why, pkt)
        return self.leave(dev, ifc, egress, r, pkt)

    def asa_policy(self, dev: Device, ing: Iface, eg: Iface, pkt: Packet):
        key_rev = (pkt.proto, pkt.dst, pkt.src, pkt.dport, pkt.sport)
        stateful_icmp = "icmp" in dev.inspect
        if key_rev in self.state.asa_conns and (pkt.proto != "icmp" or stateful_icmp):
            self.note(at=dev.name, iface=ing.name, action="ASA_STATEFUL_RETURN",
                      detail="return traffic of a permitted connection" + (" (inspect icmp)" if pkt.proto == "icmp" else ""))
            return True, ""
        ag = dev.access_groups.get(ing.nameif)
        if ag:
            aclname = ag[0]
            if not self.acl_check(dev, ing, "in", aclname, pkt):
                return False, (f"ASA_ACL_DENY {dev.name} {ing.nameif} {aclname}#{self.decisive.get('seq') or 'implicit'} "
                               f"'{self.decisive.get('ace')}' ({self.decisive.get('ref')})")
        else:
            if (ing.security_level or 0) <= (eg.security_level or 0):
                rec = self.note(at=dev.name, iface=ing.name, action="ASA_SECLEVEL_DENY",
                                detail=f"{ing.nameif}({ing.security_level}) -> {eg.nameif}({eg.security_level}) without ACL")
                self.decisive = rec
                return False, f"ASA_SECLEVEL_DENY {ing.nameif}({ing.security_level})->{eg.nameif}({eg.security_level})"
            self.note(at=dev.name, iface=ing.name, action="ASA_SECLEVEL_PERMIT",
                      detail=f"{ing.nameif}({ing.security_level}) -> {eg.nameif}({eg.security_level})")
        self.state.asa_conns.add((pkt.proto, pkt.src, pkt.dst, pkt.sport, pkt.dport))
        return True, ""

    def leave(self, dev: Device, ing: Iface | None, eg: Iface, r: Route, pkt: Packet) -> Trace:
        m = self.m
        if dev.kind != "asa" and eg.acl_out and ing is not None:
            if not self.acl_check(dev, eg, "out", eg.acl_out, pkt):
                return self.fail(f"ACL_DENY {dev.name} {eg.name} out {eg.acl_out}", pkt)
        if dev.kind == "router" and ing is not None and ing.nat == "inside" and eg.nat == "outside":
            for rule in dev.nat_rules:
                acl = dev.acls.get(rule["acl"])
                if acl and acl.evaluate(pkt)[0] == "permit" and rule["iface"] == eg.name:
                    self.state.nat[eg.ip] = pkt.src
                    self.note(at=dev.name, iface=eg.name, action="NAT_PAT",
                              detail=f"{i2ip(pkt.src)} -> {i2ip(eg.ip)} (list {rule['acl']}, {dev.file}:{rule['line']})")
                    pkt = Packet(pkt.proto, eg.ip, pkt.dst, pkt.sport, pkt.dport, pkt.icmp_type, pkt.reply)
                    break
        self.note(at=dev.name, action="route", egress=eg.name, route=f"{r.src} {i2ip(r.net)}/{prefixlen(r.mask)}")
        bd = m.bd_of_l3(dev.name, eg.name)
        if r.nh is None:
            return self.deliver_in_bd(bd, pkt)
        hosts, l3 = m.bd_members(bd)
        for d, i in l3:
            if i.ip == r.nh:
                return self.arrive(d, i, pkt)
        return self.fail(f"NEXTHOP_UNREACHABLE {i2ip(r.nh)} from {dev.name}", pkt)

    def self_accept(self, dev: Device, ing: Iface, target: Iface, pkt: Packet) -> Trace:
        def ok(detail):
            self.note(at=dev.name, iface=target.name, action="accept", detail=detail)
            return Trace(True, f"DELIVERED to {dev.name} {target.name}: {detail}", self.hops, self.state,
                         ("dev", dev.name), pkt, self.decisive)
        if pkt.reply:
            return ok("reply to device-originated traffic")
        if pkt.proto == "icmp" and pkt.icmp_type == 8:
            if dev.kind == "asa" and target is not ing:
                return self.fail(f"ASA_NO_FAR_IFACE_ICMP {dev.name} does not answer pings to {target.nameif} from {ing.nameif}", pkt)
            return ok("ICMP echo answered")
        if pkt.proto == "udp" and pkt.dport == 67 and target.helpers:
            return ok("DHCP relay agent")
        if pkt.proto == "tcp" and pkt.dport in (22, 23) and dev.kind != "asa":
            good, why, rec = vty_check(dev, pkt)
            if not good:
                self.decisive = self.note(at=dev.name, action="VTY_REFUSE", detail=why, **rec)
                return self.fail(f"VTY_REFUSE {dev.name}: {why}", pkt)
            self.decisive = self.note(at=dev.name, action="VTY_ACCEPT", detail=why, **rec)
            return ok(why)
        return self.fail(f"PORT_CLOSED {dev.name} {pkt.proto}/{pkt.dport}", pkt)


def vty_check(dev: Device, pkt: Packet):
    """Would `dev` accept a telnet (23) / ssh (22) session from pkt.src?"""
    v = dev.vty
    svc = "telnet" if pkt.dport == 23 else "ssh"
    rec = {"ref": f"{dev.file}:{v.get('line', '?')}"}
    if not v:
        return False, "no line vty configured (login, no password)", rec
    transport = v.get("transport")
    if transport is None:
        transport = {"telnet", "ssh"}
    if svc not in transport and "all" not in transport:
        rec["ref"] = f"{dev.file}:{v.get('transport_line')}"
        return False, f"transport input {' '.join(sorted(transport))} rejects {svc}", rec
    if v.get("access_class"):
        acl = dev.acls.get(v["access_class"])
        if acl:
            act, ace = acl.evaluate(Packet("tcp", pkt.src, pkt.dst, pkt.sport, pkt.dport))
            if act != "permit":
                rec["ref"] = f"{dev.file}:{v.get('access_class_line')}"
                return False, f"access-class {acl.name} denies {i2ip(pkt.src)} " \
                              f"({'implicit deny' if ace is None else ace.text})", rec
    login = v.get("login")
    if login == "local":
        if not dev.users:
            return False, "login local but no username", rec
        cred = f"local user {'/'.join(dev.users)}"
    elif login == "password":
        if not v.get("password"):
            return False, "login without password (Password required, but none set)", rec
        cred = f"shared line password '{v['password']}'"
    elif login == "none":
        cred = "no login required"
    else:
        return False, "no login configured on vty (IOS default: login, no password)", rec
    if svc == "ssh":
        # 'crypto key generate' is not shown by show running-config; 'ip ssh version' is
        if not ((dev.crypto_key or dev.ssh_version) and dev.domain_name):
            return False, "ssh not enabled (no RSA key / domain-name)", rec
    return True, f"{svc} accepted ({cred})", rec


# ----------------------------------------------------------------------------
# loading
# ----------------------------------------------------------------------------
def load_design(design: str, config_dir: Path | None = None, extra_hosts=None) -> Model:
    d = Path(config_dir) if config_dir else CONFIGS / DESIGN_DIRS[design]
    devices = {}
    for f in sorted(d.glob("*.txt")):
        name = f.stem
        rel = f.relative_to(ROOT).as_posix() if ROOT in f.resolve().parents else f.name
        devices[name] = parse_config(f.read_text(encoding="utf-8"), name, rel)
    return Model(design, devices, extra_hosts, d)


# ----------------------------------------------------------------------------
# probes and test evaluation
# ----------------------------------------------------------------------------
def probe(m: Model, src, dst_ip: int, proto: str, port: int = 0, one_way=False) -> dict:
    """Round-trip reachability (request + reply) from src (('host',name)|('dev',name,None))."""
    if src[0] == "host":
        h = m.hosts[src[1]]
        if h.ip is None:
            return {"ok": False, "reason": f"NO_ADDRESS {h.name}: {h.lease.get('reason') if h.lease else ''}",
                    "fwd": None, "rev": None}
        sip = h.ip
    else:
        sip = 0
    if proto == "icmp":
        pkt = Packet("icmp", sip, dst_ip, icmp_type=8)
    else:
        pkt = Packet(proto, sip, dst_ip, EPHEMERAL, port)
    fwd = m.trace(src, pkt)
    if not fwd.ok or one_way:
        return {"ok": fwd.ok, "reason": fwd.reason, "fwd": fwd.to_dict(), "rev": None,
                "decisive": fwd.decisive, "nat": bool(fwd.state.nat)}
    rp = fwd.final_pkt.reversed()
    rev = m.trace(fwd.delivered if fwd.delivered[0] == "host" else ("dev", fwd.delivered[1]), rp, fwd.state)
    ok = rev.ok and (rev.delivered == tuple(src[:2]) if src[0] == "host" else rev.delivered[0] == "dev")
    reason = fwd.reason if ok else "REPLY_BLOCKED " + rev.reason
    return {"ok": ok, "reason": reason, "fwd": fwd.to_dict(), "rev": rev.to_dict(),
            "decisive": rev.decisive if not ok else fwd.decisive, "nat": bool(fwd.state.nat)}


def short_reason(p: dict) -> str:
    """Machine-readable reason: every control that permitted the flow, or the one that blocked it."""
    if not p["ok"]:
        return p["reason"]
    hops = (p.get("fwd") or {}).get("hops", []) + ((p.get("rev") or {}).get("hops", []))
    return path_controls(hops)


def path_controls(hops: list) -> str:
    parts = []
    for h in hops:
        if h.get("action") == "L2_SAME_SEGMENT":
            parts.append("L2_SAME_VLAN (switched, no SVI/ACL on path)")
        elif h.get("acl") and h.get("result") == "permit":
            parts.append(f"PERMIT {h['at']} {h.get('iface', '')} {h['dir']} {h['acl']}#{h.get('seq')} "
                         f"'{h.get('ace')}' ({h.get('ref')})")
        elif h.get("action") in ("VTY_ACCEPT", "ASA_STATEFUL_RETURN", "NAT_PAT", "ASA_SECLEVEL_PERMIT"):
            parts.append(f"{h['action']} {h['at']}: {h.get('detail')}")
    uniq = list(dict.fromkeys(parts))
    return " | ".join(uniq) if uniq else "UNFILTERED routed path (no ACL on path)"


def tag(reason: str) -> str:
    """Compact control tag: 'L2', 'MEDIOT-IN#2+OUTSIDE-IN#4', 'unfiltered'."""
    if reason.startswith("L2_SAME_VLAN"):
        return "L2-same-VLAN"
    acls = re.findall(r"(?:in|out) (\S+#\d+) ", reason)
    return "+".join(dict.fromkeys(acls)) if acls else "unfiltered"


def target_list(m: Model, attacker: Host):
    """The 23 A1 targets: (label, [ip candidates], listed_ip)."""
    t = []
    for name in ["Nurse-PC-A", "Nurse-PC-B", "Reception-PC", "NetAdmin-PC",
                 "EHR-SRV", "DNS-DHCP-SRV", "IOT-REG-SRV", "SYSLOG-NTP-SRV",
                 "Monitor-A1", "Pump-A1", "Monitor-B1", "Pump-B1",
                 "Smart-Door", "Fire-Monitor", "HVAC-Fan", "Webcam",
                 "Guest-Phone", "Guest-Tablet"]:
        h = m.hosts[name]
        t.append((name, [h.ip] if h.ip else [], h.ip))
    for dev in INFRA:
        ips = sorted(m.devices[dev].own_ips().keys()) if dev in m.devices else []
        if dev == "CORE-MLS":
            listed = attacker.gw
            label = "CORE-MLS (gateway)"
        else:
            listed = ip2i(INFRA_LISTED_ADDR[dev])
            label = dev
        t.append((label, ips, listed if listed in ips else None))
    return t


def mgmt_probe(m: Model, src, ip: int):
    tel = probe(m, src, ip, "tcp", 23)
    ssh = probe(m, src, ip, "tcp", 22)
    best = tel if tel["ok"] else ssh if ssh["ok"] else tel
    return {"ok": tel["ok"] or ssh["ok"], "telnet": tel["ok"], "ssh": ssh["ok"], "reason": short_reason(best)}


def classify(n_ok: int, n_total: int) -> str:
    if n_ok == 0:
        return "B"
    if n_ok == n_total:
        return "S"
    return "P"


def with_attacker(design: str, loc: str, config_dir=None) -> tuple[Model, Host]:
    label, sw, port = LOCATIONS[loc]
    m = load_design(design, config_dir, extra_hosts=[("IOT-COMPROMISED", "attacker", sw, port, "dhcp")])
    return m, m.hosts["IOT-COMPROMISED"]


def analyse_location(design: str, loc: str, config_dir=None) -> dict:
    m, atk = with_attacker(design, loc, config_dir)
    src = ("host", atk.name)
    out = {"location": LOCATIONS[loc][0], "attacker": {"ip": i2ip(atk.ip) if atk.ip else None,
                                                        "gateway": i2ip(atk.gw) if atk.gw else None,
                                                        "lease": atk.lease}}
    # ---- A1 recon: 23 hosts, ICMP round trip ----
    hosts = []
    for label, ips, listed in target_list(m, atk):
        per_ip = {i2ip(ip): probe(m, src, ip, "icmp") for ip in ips}
        any_ok = [k for k, v in per_ip.items() if v["ok"]]
        lst = per_ip.get(i2ip(listed)) if listed else None
        rep = per_ip[any_ok[0]] if any_ok else (lst or (next(iter(per_ip.values())) if per_ip else
                                                         {"ok": False, "reason": "NO_ADDRESS", "decisive": None}))
        hosts.append({"target": label, "ips": list(per_ip), "listed_ip": i2ip(listed) if listed else None,
                      "reachable": bool(any_ok), "reachable_ips": any_ok,
                      "reachable_at_listed": bool(lst and lst["ok"]), "reason": short_reason(rep)})
    out["hosts"] = hosts
    # ---- services (10) ----
    svc = []
    for label, ip, proto, port in [("EHR HTTP", "10.10.20.10", "tcp", 80), ("EHR HTTPS", "10.10.20.10", "tcp", 443),
                                   ("IoT-server HTTP", "10.10.20.12", "tcp", 80), ("DNS", "10.10.20.11", "udp", 53),
                                   ("Internet web", "203.0.113.10", "tcp", 80)]:
        p = probe(m, src, ip2i(ip), proto, port)
        svc.append({"service": label, "target": f"{ip} {proto}/{port}", "reachable": p["ok"],
                    "reachable_at_listed": p["ok"], "reason": short_reason(p), "nat": p.get("nat")})
    for label, ips, listed in target_list(m, atk)[18:]:
        dev = label.split()[0]
        res = {i2ip(ip): mgmt_probe(m, src, ip) for ip in ips}
        okk = [k for k, v in res.items() if v["ok"]]
        lst = res.get(i2ip(listed)) if listed else None
        rep = res[okk[0]] if okk else (lst or next(iter(res.values())))
        svc.append({"service": f"{dev} Telnet/SSH", "target": ",".join(res), "reachable": bool(okk),
                    "reachable_ips": okk, "reachable_at_listed": bool(lst and lst["ok"]),
                    "listed_ip": i2ip(listed) if listed else None, "reason": rep["reason"]})
    out["services"] = svc
    # ---- residual channels (not part of the 10) ----
    resid = []
    for label, ip, proto, port in [("UDP/67 to Internet (exfil via DHCP permit)", "203.0.113.10", "udp", 67),
                                   ("UDP/67 to DHCP server (starvation)", "10.10.20.11", "udp", 67)]:
        p = probe(m, src, ip2i(ip), proto, port, one_way=True)
        delivered = p["ok"] or p["reason"].startswith("PORT_CLOSED")
        resid.append({"channel": label, "forward_delivered": delivered,
                      "reason": (path_controls(p["fwd"]["hops"]) + " -> " + p["reason"]) if delivered else p["reason"]})
    netadmin = m.hosts["NetAdmin-PC"].ip
    pk = Packet("icmp", atk.ip or 0, netadmin, icmp_type=0)
    tr = m.trace(src, pk)
    resid.append({"channel": "unsolicited ICMP echo-reply to NetAdmin-PC (stateless ACL)",
                  "forward_delivered": tr.ok, "reason": (path_controls(tr.hops) + " -> " if tr.ok else "") + tr.reason})
    out["residual_channels"] = resid
    # ---- attacks A1-A4 ----
    n_h = sum(1 for h in hosts if h["reachable"])
    n_h_listed = sum(1 for h in hosts if h["reachable_at_listed"])
    a = {}
    a["A1"] = {"predicted": classify(n_h, 23), "predicted_readme_procedure": classify(n_h_listed, 23),
               "reason": f"{n_h}/23 hosts answer ICMP echo round-trip "
                         f"({n_h_listed}/23 at the README-listed addresses); reachable: "
                         + "; ".join(f"{h['target']}@{','.join(h['reachable_ips'])}[{tag(h['reason'])}]"
                                     for h in hosts if h["reachable"])}
    ehr = svc[0]
    a["A2"] = {"predicted": "S" if ehr["reachable"] else "B", "predicted_readme_procedure": "S" if ehr["reachable"] else "B",
               "reason": ehr["reason"]}
    iot = svc[2]
    pump = next(h for h in hosts if h["target"] == "Pump-A1")
    n3 = int(iot["reachable"]) + int(pump["reachable"])
    a["A3"] = {"predicted": classify(n3, 2), "predicted_readme_procedure": classify(n3, 2),
               "reason": f"IoT-server HTTP {'OK' if iot['reachable'] else 'BLOCKED'} [{iot['reason']}]; "
                         f"ping Pump-A1 {'OK' if pump['reachable'] else 'BLOCKED'} [{pump['reason']}]"}
    infra = svc[5:]
    n4 = sum(1 for s in infra if s["reachable"])
    # README procedure: telnet/ssh 10.10.99.11, own gateway, 10.10.255.1
    listed = [s for s in infra if s["service"].split()[0] in ("CORE-MLS", "SW-WARD-A", "EDGE-RTR")]
    n4l = sum(1 for s in listed if s["reachable_at_listed"])
    bypass = [f"{s['service'].split()[0]} via {','.join(s['reachable_ips'])}" for s in infra
              if s["reachable"] and not s["reachable_at_listed"]]
    a["A4"] = {"predicted": classify(n4, 5), "predicted_readme_procedure": classify(n4l, 3),
               "reason": f"{n4}/5 infra devices accept a mgmt session from any of their addresses; "
                         f"{n4l}/3 at README targets; "
                         + ("BYPASS: " + "; ".join(bypass) + "; " if bypass else "")
                         + "; ".join(f"{s['service']}: {s['reason']}" for s in infra)}
    out["attacks"] = a
    out["surface"] = {"hosts_reachable_of_23": n_h, "hosts_at_listed_addr_of_23": n_h_listed,
                      "services_reachable_of_10": sum(1 for s in svc if s["reachable"]),
                      "services_at_listed_addr_of_10": sum(1 for s in svc if s["reachable_at_listed"]),
                      "host_list": [h["target"] for h in hosts if h["reachable"]],
                      "service_list": [s["service"] for s in svc if s["reachable"]]}
    return out


def analyse_a5(design: str, config_dir=None) -> dict:
    m = load_design(design, config_dir, extra_hosts=[("ROGUE-DHCP", "rogue", "SW-WARD-A", "Fa0/5", "rogue-dhcp")])
    sw = m.devices["SW-WARD-A"]
    port = sw.iface("Fa0/5")
    victim = m.hosts["Nurse-PC-A"]
    rogue = m.hosts["ROGUE-DHCP"]
    if rogue.bd is None:
        return {"predicted": "B", "reason": f"ROGUE_PORT_DOWN SW-WARD-A Fa0/5 ({sw.file})"}
    if rogue.bd != victim.bd:
        return {"predicted": "B", "reason": "DIFFERENT_BROADCAST_DOMAIN rogue offers cannot reach Nurse-PC-A"}
    vlan = m._port_vlan_untagged(sw, port)
    if port.ps_enabled and port.ps_max < 1:
        return {"predicted": "B", "reason": "PORT_SECURITY max 0"}
    if sw.snooping and vlan in sw.snooping_vlans and not port.snoop_trust:
        ln = next((l for l, s in sw.lines if s.startswith("ip dhcp snooping vlan")), "?")
        return {"predicted": "B",
                "reason": f"DHCP_SNOOPING SW-WARD-A snoops VLAN {vlan} ({sw.file}:{ln}); Fa0/5 untrusted -> "
                          f"rogue OFFER/ACK dropped; port-security max {port.ps_max if port.ps_enabled else 'off'} admits the rogue MAC"}
    why = "no 'ip dhcp snooping'" if not sw.snooping else f"VLAN {vlan} not snooped" if vlan not in sw.snooping_vlans else "Fa0/5 trusted"
    return {"predicted": "S",
            "reason": f"NO_L2_CONTROL SW-WARD-A: {why}; rogue on Fa0/5 shares VLAN {vlan} with Nurse-PC-A -> rogue OFFER "
                      f"(gw 10.10.10.66) reaches the victim (wins the race: it is one switch hop away vs. a relayed server)"}


def analyse_a6(design: str, config_dir=None) -> dict:
    m = load_design(design, config_dir)
    sw = m.devices["SW-WARD-A"]
    p = sw.iface("Fa0/2")
    if p.ps_enabled:
        learned = 1  # Monitor-A1's MAC (sticky or dynamic) - precondition of the test
        if p.ps_max <= learned:
            act = {"shutdown": "port err-disabled", "restrict": "frames dropped + logged",
                   "protect": "frames dropped silently"}[p.ps_violation]
            return {"predicted": "B",
                    "reason": f"PORT_SECURITY SW-WARD-A Fa0/2 max {p.ps_max}"
                              f"{' sticky' if p.ps_sticky else ''} violation {p.ps_violation} "
                              f"({sw.file}:{p.lines.get('ps')}-{p.lines.get('ps_violation')}) -> {act} "
                              f"(precondition: Monitor-A1 MAC learned first)"}
        return {"predicted": "S", "reason": f"PORT_SECURITY max {p.ps_max} > 1 legit MAC: rogue admitted"}
    # no port security: rogue laptop replaces Monitor-A1 and gets a lease in that VLAN
    m2 = load_design(design, config_dir, extra_hosts=[("ROGUE-LAPTOP", "rogue", "SW-WARD-A", "Fa0/2", "dhcp")])
    r = m2.hosts["ROGUE-LAPTOP"]
    pr = probe(m2, ("host", r.name), m2.hosts["Pump-A1"].ip, "icmp") if r.ip else {"ok": False}
    return {"predicted": "S" if r.ip else "B",
            "reason": f"NO_PORT_SECURITY on SW-WARD-A Fa0/2 -> laptop admitted, DHCP lease "
                      f"{i2ip(r.ip) if r.ip else 'none'} (pool {r.lease.get('pool') if r.lease else '-'}), "
                      f"ping Pump-A1 {'OK' if pr['ok'] else 'fails'}"}


def analyse_a7(design: str, config_dir=None) -> dict:
    m = load_design(design, config_dir)
    p = probe(m, ("host", "Guest-Phone"), ip2i("10.10.20.10"), "tcp", 80)
    return {"predicted": "S" if p["ok"] else "B", "reason": short_reason(p),
            "guest_ip": i2ip(m.hosts["Guest-Phone"].ip) if m.hosts["Guest-Phone"].ip else None}


def analyse_functional(design: str, config_dir=None) -> dict:
    m = load_design(design, config_dir)
    F = {}

    def P(src, ip, proto, port=0, one_way=False):
        return probe(m, ("host", src) if isinstance(src, str) else src, ip2i(ip), proto, port, one_way)

    def res(checks):
        ok = all(c[1]["ok"] for c in checks)
        bad = [f"{c[0]}: {c[1]['reason']}" for c in checks if not c[1]["ok"]]
        return {"predicted": "PASS" if ok else "FAIL",
                "reason": "; ".join(bad) if bad else "; ".join(f"{c[0]}: {short_reason(c[1])}" for c in checks)}

    F["F1"] = res([("DNS", P("Nurse-PC-A", "10.10.20.11", "udp", 53)), ("HTTP", P("Nurse-PC-A", "10.10.20.10", "tcp", 80))])
    F["F2"] = res([("ping", P("Nurse-PC-A", "10.10.20.10", "icmp"))])
    checks = [("staff->IoT dashboard", P("Nurse-PC-A", "10.10.20.12", "tcp", 80))]
    for d in ["Monitor-A1", "Pump-A1", "Monitor-B1", "Pump-B1", "Smart-Door", "Fire-Monitor", "HVAC-Fan", "Webcam"]:
        checks.append((f"{d} registration tcp/80", P(d, "10.10.20.12", "tcp", 80)))
    F["F3"] = res(checks)
    bad = []
    for h in m.hosts.values():
        if h.addressing != "dhcp":
            continue
        if not h.lease or not h.lease.get("ok"):
            bad.append(f"{h.name}: {h.lease.get('reason') if h.lease else 'no lease'}")
            continue
        want = ipaddress.ip_network(INTENDED_SUBNET[design][h.cls])
        if ipaddress.ip_address(i2ip(h.ip)) not in want:
            bad.append(f"{h.name}: got {i2ip(h.ip)} not in intended {want}")
    leases = ", ".join(f"{h.name}={i2ip(h.ip)}({h.lease['pool']})" for h in m.hosts.values()
                       if h.addressing == "dhcp" and h.ip)
    F["F4"] = {"predicted": "FAIL" if bad else "PASS", "reason": "; ".join(bad) if bad else "all leases OK: " + leases}
    F["F5"] = res([("DNS", P("Guest-Phone", "10.10.20.11", "udp", 53)), ("HTTP", P("Guest-Phone", "203.0.113.10", "tcp", 80))])
    f6 = P("Nurse-PC-A", "203.0.113.10", "tcp", 80)
    F["F6"] = res([("HTTP", f6), ("NAT", {"ok": f6.get("nat", False), "reason": "PAT translation on EDGE-RTR"
                                                                           if f6.get("nat") else "NO_NAT"})])
    port = 22 if design == "D3" else 23
    F["F7"] = res([(f"{'ssh' if port == 22 else 'telnet'} 10.10.99.11", P("NetAdmin-PC", "10.10.99.11", "tcp", port))])
    F["F8"] = res([("Fire-Monitor reg", P("Fire-Monitor", "10.10.20.12", "tcp", 80)),
                   ("HVAC-Fan reg", P("HVAC-Fan", "10.10.20.12", "tcp", 80))])
    checks = []
    for d in ["CORE-MLS", "EDGE-RTR"]:
        dev = m.devices[d]
        if ip2i("10.10.20.13") not in dev.logging_hosts:
            checks.append((f"{d} logging", {"ok": False, "reason": "no 'logging host 10.10.20.13'"}))
        else:
            checks.append((f"{d} syslog", P(("dev", d, None), "10.10.20.13", "udp", 514, one_way=True)))
    F["F9"] = res(checks)
    F["F4"]["leases"] = {h.name: (i2ip(h.ip) if h.ip else None) for h in m.hosts.values() if h.addressing == "dhcp"}
    return F


# ----------------------------------------------------------------------------
# expected values + comparison
# ----------------------------------------------------------------------------
def read_expected():
    exp = {"attack": {}, "surface": {}, "functional": {}}
    try:
        with (RESULTS / "attack-matrix.csv").open(encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                exp["attack"][(r["design"], r["location"], r["test_id"])] = r["expected"]
        with (RESULTS / "attack-surface.csv").open(encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                exp["surface"][(r["design"], r["location"])] = (int(r["expected_hosts_of_23"]), int(r["expected_services_of_10"]))
        with (RESULTS / "functional.csv").open(encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                exp["functional"][(r["design"], r["test_id"])] = r["expected"]
    except FileNotFoundError:
        pass
    return exp


def analyze(design: str, config_dir=None) -> dict:
    design = design.upper()
    m = load_design(design, config_dir)
    out = {"design": design, "config_dir": str(m.config_dir), "warnings": list(m.warnings),
           "hosts": {h.name: {"class": h.cls, "switch": h.switch, "port": h.port,
                              "ip": i2ip(h.ip) if h.ip else None,
                              "gateway": i2ip(h.gw) if h.gw else None,
                              "addressing": "dhcp (representative lease)" if h.addressing == "dhcp" else "static",
                              "pool": h.lease.get("pool") if h.lease else None}
                     for h in m.hosts.values()},
           "routes": {d: m.route_table(d) for d in m.devices},
           "locations": {}, "attacks": [], "functional": {}}
    for loc in LOCATIONS:
        la = analyse_location(design, loc, config_dir)
        out["locations"][loc] = la
        for tid, v in la["attacks"].items():
            out["attacks"].append({"design": design, "location": la["location"], "test_id": tid, **v})
    for tid, fn, loc in [("A5", analyse_a5, "SW-WARD-A Fa0/5"), ("A6", analyse_a6, "SW-WARD-A Fa0/2"),
                         ("A7", analyse_a7, "Guest-Phone")]:
        v = fn(design, config_dir)
        out["attacks"].append({"design": design, "location": loc, "test_id": tid,
                               "predicted_readme_procedure": v["predicted"], **v})
    out["functional"] = analyse_functional(design, config_dir)
    out["attacks"].sort(key=lambda r: (r["test_id"], r["location"]))
    return out


def compare(res: dict, exp: dict) -> list[dict]:
    dis = []
    d = res["design"]
    for a in res["attacks"]:
        e = exp["attack"].get((d, a["location"], a["test_id"]))
        if e is None:
            continue
        if a["predicted"] != e or a["predicted_readme_procedure"] != e:
            dis.append({"design": d, "location": a["location"], "test": a["test_id"], "expected": e,
                        "analyzer": a["predicted"], "analyzer_readme_procedure": a["predicted_readme_procedure"],
                        "reason": a["reason"]})
    for loc, la in res["locations"].items():
        e = exp["surface"].get((d, la["location"]))
        s = la["surface"]
        if e and (e[0] != s["hosts_reachable_of_23"] or e[1] != s["services_reachable_of_10"]
                  or e[0] != s["hosts_at_listed_addr_of_23"] or e[1] != s["services_at_listed_addr_of_10"]):
            dis.append({"design": d, "location": la["location"], "test": "surface",
                        "expected": f"{e[0]} hosts / {e[1]} services",
                        "analyzer": f"{s['hosts_reachable_of_23']} hosts / {s['services_reachable_of_10']} services",
                        "analyzer_readme_procedure": f"{s['hosts_at_listed_addr_of_23']} / {s['services_at_listed_addr_of_10']}",
                        "reason": "hosts: " + ", ".join(s["host_list"]) + " | services: " + ", ".join(s["service_list"])})
    for tid, v in res["functional"].items():
        e = exp["functional"].get((d, tid))
        if e and e != v["predicted"]:
            dis.append({"design": d, "location": "-", "test": tid, "expected": e, "analyzer": v["predicted"],
                        "analyzer_readme_procedure": v["predicted"], "reason": v["reason"]})
    return dis


def analyze_all(config_dirs: dict | None = None) -> dict:
    exp = read_expected()
    out = {"tool": "policy_analyzer.py", "designs": {}, "disagreements": []}
    for d in DESIGNS:
        r = analyze(d, (config_dirs or {}).get(d))
        out["designs"][d] = r
        out["disagreements"] += compare(r, exp)
    return out


# ----------------------------------------------------------------------------
# output
# ----------------------------------------------------------------------------
def write_outputs(all_res: dict, outdir: Path = RESULTS):
    outdir.mkdir(exist_ok=True)
    exp = read_expected()
    with (outdir / "static-analysis.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["design", "location", "test_id", "predicted", "reason", "predicted_readme_procedure", "expected"])
        for d, r in all_res["designs"].items():
            for a in r["attacks"]:
                w.writerow([d, a["location"], a["test_id"], a["predicted"], a["reason"],
                            a["predicted_readme_procedure"], exp["attack"].get((d, a["location"], a["test_id"]), "")])
    with (outdir / "static-surface.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["design", "location", "hosts_reachable_of_23", "services_reachable_of_10", "host_list",
                    "service_list", "hosts_at_listed_addr_of_23", "services_at_listed_addr_of_10", "attacker_ip"])
        for d, r in all_res["designs"].items():
            for loc, la in r["locations"].items():
                s = la["surface"]
                w.writerow([d, la["location"], s["hosts_reachable_of_23"], s["services_reachable_of_10"],
                            "; ".join(s["host_list"]), "; ".join(s["service_list"]),
                            s["hosts_at_listed_addr_of_23"], s["services_at_listed_addr_of_10"], la["attacker"]["ip"]])
    with (outdir / "static-functional.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["design", "test_id", "predicted", "reason", "expected"])
        for d, r in all_res["designs"].items():
            for tid, v in r["functional"].items():
                w.writerow([d, tid, v["predicted"], v["reason"], exp["functional"].get((d, tid), "")])
    with (outdir / "static-analysis.json").open("w", encoding="utf-8") as fh:
        json.dump(all_res, fh, indent=1, default=str)


def print_summary(r: dict, file=None):
    file = file or sys.stdout
    d = r["design"]
    print(f"\n== {d} ==", file=file)
    for w in r["warnings"]:
        print(f"  warning: {w}", file=file)
    print("  attack  location              pred  (README-proc)", file=file)
    for a in r["attacks"]:
        print(f"  {a['test_id']:6s}  {a['location']:20s}  {a['predicted']:4s}  ({a['predicted_readme_procedure']})", file=file)
    for loc, la in r["locations"].items():
        s = la["surface"]
        print(f"  surface {la['location']:18s} attacker {la['attacker']['ip']}: hosts {s['hosts_reachable_of_23']}/23 "
              f"(listed {s['hosts_at_listed_addr_of_23']}), services {s['services_reachable_of_10']}/10 "
              f"(listed {s['services_at_listed_addr_of_10']})", file=file)
    print("  functional: " + " ".join(f"{k}={v['predicted']}" for k, v in r["functional"].items()), file=file)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--design", choices=DESIGNS)
    ap.add_argument("--json", action="store_true", help="print JSON to stdout")
    ap.add_argument("--config-dir", help="analyse configs from this folder (e.g. captured running-configs)")
    ap.add_argument("--no-write", action="store_true", help="do not write results/static-*")
    args = ap.parse_args(argv)
    if args.design:
        r = analyze(args.design, Path(args.config_dir) if args.config_dir else None)
        if args.json:
            json.dump(r, sys.stdout, indent=1, default=str)
        else:
            print_summary(r)
            dis = compare(r, read_expected())
            if dis:
                print(f"\n  {len(dis)} disagreement(s) with expected values:")
                for x in dis:
                    print(f"   - {x['design']} {x['location']} {x['test']}: expected {x['expected']}, "
                          f"analyzer {x['analyzer']} (README procedure {x['analyzer_readme_procedure']})")
        return 0
    res = analyze_all()
    if not args.no_write:
        write_outputs(res)
    if args.json:
        json.dump(res, sys.stdout, indent=1, default=str)
        return 0
    for d in DESIGNS:
        print_summary(res["designs"][d])
    print(f"\n{len(res['disagreements'])} disagreement(s) between analyzer and expected values:")
    for x in res["disagreements"]:
        print(f" - {x['design']} {x['location']} {x['test']}: expected {x['expected']}, analyzer {x['analyzer']} "
              f"(README procedure {x['analyzer_readme_procedure']})")
    if not args.no_write:
        print(f"\nWritten: results/static-analysis.csv, static-surface.csv, static-functional.csv, static-analysis.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
