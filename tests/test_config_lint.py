"""Config lint: hardening rules the designs claim to follow, checked against the config files."""
import ipaddress

import pytest

import policy_analyzer as pa
from policy_analyzer import i2ip, ip2i

DESIGNS = pa.DESIGNS
ACCESS = ["SW-WARD-A", "SW-WARD-B", "SW-ADMIN"]
MGMT_DEVICES = ["CORE-MLS", "EDGE-RTR"] + ACCESS


def client_svis(dev):
    """SVIs that relay DHCP = gateways of client VLANs."""
    return [i for i in dev.ifaces.values() if i.is_svi and i.ip and i.helpers]


def used_ports(design, dev_name):
    used = {p for h in pa.HOSTS if h[2] == dev_name for p in [h[3]]}
    used |= {port for _, sw, port in pa.LOCATIONS.values() if sw == dev_name}
    if dev_name == "SW-WARD-A":
        used.add("Fa0/5")                    # staff jack / rogue-DHCP test port
    if dev_name == "SW-WARD-B":
        used.add("Fa0/5")                    # staff jack
    for a, b in pa.links_for(design):
        for d, p in (a, b):
            if d == dev_name:
                used.add(p)
    return used


# ---------------- every design ----------------
@pytest.mark.parametrize("design", DESIGNS)
def test_model_builds_without_warnings(models, design):
    assert models[design].warnings == []


@pytest.mark.parametrize("design", DESIGNS)
def test_every_access_group_and_access_class_references_a_defined_acl(models, design):
    for dev in models[design].devices.values():
        for i in dev.ifaces.values():
            for a in (i.acl_in, i.acl_out):
                if a:
                    assert a in dev.acls, f"{dev.name} {i.name} uses undefined ACL {a}"
        if dev.vty.get("access_class"):
            assert dev.vty["access_class"] in dev.acls
        for nameif, (aclname, _, _) in dev.access_groups.items():
            assert aclname in dev.acls and dev.nameif_iface(nameif)


@pytest.mark.parametrize("design", DESIGNS)
def test_no_overlapping_subnets(models, design):
    """Distinct L3 segments must not overlap; the same subnet may appear only on one segment."""
    m = models[design]
    segs = {}
    for dev in m.devices.values():
        for i in dev.up_ifaces():
            net = ipaddress.ip_network(f"{i2ip(i.ip)}/{pa.prefixlen(i.mask)}", strict=False)
            bd = m.bd_of_l3(dev.name, i.name)
            segs.setdefault(net, set()).add(bd)
    for net, bds in segs.items():
        assert len(bds) == 1, f"{design}: {net} configured on {len(bds)} different segments"
    nets = list(segs)
    for a in nets:
        for b in nets:
            if a != b:
                assert not a.overlaps(b), f"{design}: {a} overlaps {b}"


@pytest.mark.parametrize("design", DESIGNS)
def test_helper_address_on_every_client_svi(models, design):
    """Every DHCP client's segment either holds the DHCP server or has a relay to 10.10.20.11."""
    m = models[design]
    srv = m.hosts[pa.DHCP_SERVER]
    for h in m.hosts.values():
        if h.addressing != "dhcp":
            continue
        if h.bd == srv.bd:
            continue
        _, l3 = m.bd_members(h.bd)
        gws = [i for d, i in l3 if d.kind == "mls"]
        assert gws, f"{h.name}: no SVI on its segment"
        assert all(ip2i("10.10.20.11") in i.helpers for i in gws), \
            f"{design} {h.name}: gateway {gws[0].name} lacks ip helper-address 10.10.20.11"


@pytest.mark.parametrize("design", ["D2", "D3"])
def test_svi_acls_start_with_dhcp_permit(models, design):
    core = models[design].devices["CORE-MLS"]
    for i in client_svis(core):
        if not i.acl_in:
            continue
        first = core.acls[i.acl_in].aces[0]
        assert first.text == "permit udp any host 255.255.255.255 eq 67", f"{i.name} {i.acl_in} starts with '{first.text}'"
        second = core.acls[i.acl_in].aces[1]
        assert second.text == "permit udp any host 10.10.20.11 eq 67", f"{i.name} {i.acl_in} 2nd '{second.text}'"


@pytest.mark.parametrize("design", ["D2", "D3"])
def test_applied_acls_end_in_deny_or_internet_pattern(models, design):
    """Last ACE is 'deny ip any any', or the pair 'deny ip any 10/8' + 'permit ip <own subnet> any'."""
    m = models[design]
    for dev in m.devices.values():
        applied = {i.acl_in for i in dev.ifaces.values() if i.acl_in} | {a for a, _, _ in dev.access_groups.values()}
        for name in applied:
            aces = dev.acls[name].aces
            last = aces[-1]
            if last.action == "deny" and last.src_wc == pa.ALL_ONES and last.dst_wc == pa.ALL_ONES and last.proto == "ip":
                continue
            prev = aces[-2]
            ok = (prev.action == "deny" and prev.dst == ip2i("10.0.0.0") and prev.dst_wc == ip2i("0.255.255.255")
                  and last.action == "permit" and last.dst_wc == pa.ALL_ONES and last.src_wc == ip2i("0.0.0.255"))
            iface = next(i for i in dev.ifaces.values() if i.acl_in == name)
            assert ok, f"{dev.name} {name} ends with '{last.text}'"
            assert last.src == iface.ip & iface.mask, f"{name}: internet permit is not limited to its own subnet"


# ---------------- D3 hardening ----------------
def test_d3_every_user_svi_has_inbound_acl(models):
    core = models["D3"].devices["CORE-MLS"]
    svis = client_svis(core)
    assert {i.name for i in svis} == {"Vlan10", "Vlan31", "Vlan32", "Vlan40", "Vlan50"}
    for i in svis:
        assert i.acl_in and i.acl_in in core.acls, f"{i.name} has no inbound ACL"


def trunk_ports(m):
    out = []
    for (da, pa_), (db, pb) in m.links:
        for d, p in ((da, pa_), (db, pb)):
            dev = m.devices[d]
            i = dev.iface(p)
            if dev.kind in ("mls", "l2") and i.switchport and i.mode == "trunk":
                out.append((dev, i))
    return out


def test_d3_trunks_hardened(models):
    m = models["D3"]
    trunks = trunk_ports(m)
    assert len(trunks) == 6          # 3 core ends + 3 access uplinks
    for dev, i in trunks:
        where = f"{dev.name} {i.name}"
        assert i.native_vlan == 998, f"{where} native {i.native_vlan}"
        assert i.nonegotiate, f"{where} DTP not disabled"
        assert i.allowed is not None, f"{where} allows all VLANs"
        assert 1 not in i.allowed and 999 not in i.allowed and 998 not in i.allowed
        assert i.allowed <= set(dev.vlans), f"{where} allows VLANs missing from the VLAN database"


@pytest.mark.parametrize("dev_name", ["CORE-MLS"] + ACCESS)
def test_d3_unused_ports_parked_and_shut(models, dev_name):
    dev = models["D3"].devices[dev_name]
    used = used_ports("D3", dev_name)
    for name, i in dev.ifaces.items():
        if i.is_svi or name in used:
            continue
        assert i.access_vlan == 999 and i.shutdown, f"{dev_name} {name} unused but vlan {i.access_vlan}, shutdown={i.shutdown}"


# FINDING F-4 fixed in configs/D3-microseg/SW-SRV.txt
def test_d3_sw_srv_unused_ports_parked(models):
    dev = models["D3"].devices["SW-SRV"]
    used = used_ports("D3", "SW-SRV")
    for name, i in dev.ifaces.items():
        if not i.is_svi and name not in used:
            assert i.access_vlan == 999 and i.shutdown, name


@pytest.mark.parametrize("dev_name", ACCESS)
def test_d3_access_ports_have_port_security_and_bpduguard(models, dev_name):
    dev = models["D3"].devices[dev_name]
    for name in used_ports("D3", dev_name):
        i = dev.iface(name)
        if not i.switchport or i.mode == "trunk":
            continue
        assert i.ps_enabled, f"{dev_name} {name} lacks port-security"
        assert i.bpduguard and i.portfast, f"{dev_name} {name} lacks portfast/bpduguard"


@pytest.mark.parametrize("dev_name", ACCESS)
def test_d3_dhcp_snooping_trusts_only_uplink(models, dev_name):
    dev = models["D3"].devices[dev_name]
    assert dev.snooping and not dev.snoop_option82
    trusted = [n for n, i in dev.ifaces.items() if i.snoop_trust]
    assert trusted == ["Gi0/1"]
    client_vlans = {dev.iface(p).access_vlan for p in used_ports("D3", dev_name)
                    if dev.iface(p).mode != "trunk"} - {99}
    assert client_vlans <= dev.snooping_vlans, f"VLANs {client_vlans - dev.snooping_vlans} not snooped"


@pytest.mark.parametrize("dev_name", MGMT_DEVICES)
def test_d3_vty_ssh_only_with_access_class(models, dev_name):
    dev = models["D3"].devices[dev_name]
    v = dev.vty
    assert v.get("transport") == {"ssh"}, f"{dev_name} transport {v.get('transport')}"
    assert v.get("login") == "local" and "netadmin" in dev.users
    assert dev.domain_name and dev.crypto_key and dev.ssh_version == 2
    acl = dev.acls[v["access_class"]]
    assert [a.text for a in acl.aces] == ["permit 10.10.99.0 0.0.0.255"]


@pytest.mark.parametrize("design", ["D0", "D1", "D2"])
def test_d0_d2_vty_is_telnet_with_shared_password(models, design):
    """Documents the deliberately weak baseline (it is what A4 exploits)."""
    for dev_name in MGMT_DEVICES:
        v = models[design].devices[dev_name].vty
        assert v.get("transport") == {"telnet"} and v.get("login") == "password" and not v.get("access_class")


def test_d3_asa_acl_uses_subnet_masks_not_wildcards(models):
    asa = models["D3"].devices["ASA-SRV"]
    acl = asa.acls["OUTSIDE-IN"]
    assert len(acl.aces) == 16
    for ace in acl.aces:
        for tok in ace.mask_tokens:
            assert pa.mask_is_contiguous(ip2i(tok)) and tok.startswith("255."), f"'{ace.text}' uses {tok}"


def test_d3_asa_interfaces_and_policy(models):
    asa = models["D3"].devices["ASA-SRV"]
    out, ins = asa.nameif_iface("outside"), asa.nameif_iface("inside")
    assert out.security_level == 0 and ins.security_level == 100
    assert asa.access_groups["outside"][0] == "OUTSIDE-IN"
    assert "icmp" in asa.inspect


def test_d3_servers_route_only_through_asa(models):
    """No VLAN 20 SVI on the core in D3, so server traffic cannot bypass the firewall."""
    m = models["D3"]
    core = m.devices["CORE-MLS"]
    assert "Vlan20" not in core.ifaces
    r = m._lookup("CORE-MLS", ip2i("10.10.20.10"))
    assert r.nh == ip2i("10.10.254.2") and r.src == "static"
