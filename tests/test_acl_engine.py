"""Unit tests of the analyzer's ACL / parsing engine on small hand-built inputs."""
import pytest

import policy_analyzer as pa
from policy_analyzer import ACL, Packet, ip2i, parse_ace, parse_config


def acl(kind, *lines):
    a = ACL("T", kind)
    for i, l in enumerate(lines, 1):
        a.aces.append(parse_ace(l, kind, "t", i, i))
    return a


def pkt(proto, src, dst, dport=0, sport=49152, icmp=None):
    return Packet(proto, ip2i(src), ip2i(dst), sport, dport, icmp)


# ---------------- first match / implicit deny ----------------
def test_first_match_wins_permit_before_deny():
    a = acl("extended", "permit tcp any host 10.10.20.10 eq 80", "deny ip any any")
    act, ace = a.evaluate(pkt("tcp", "10.10.30.5", "10.10.20.10", 80))
    assert act == "permit" and ace.seq == 1


def test_first_match_wins_deny_before_permit():
    a = acl("extended", "deny ip any any", "permit tcp any host 10.10.20.10 eq 80")
    act, ace = a.evaluate(pkt("tcp", "10.10.30.5", "10.10.20.10", 80))
    assert act == "deny" and ace.seq == 1


def test_implicit_deny_when_nothing_matches():
    a = acl("extended", "permit tcp any host 10.10.20.12 eq 80")
    act, ace = a.evaluate(pkt("tcp", "10.10.31.5", "10.10.20.10", 80))
    assert act == "deny" and ace is None


def test_empty_acl_is_implicit_deny():
    assert ACL("E", "extended").evaluate(pkt("icmp", "1.1.1.1", "2.2.2.2", icmp=8))[0] == "deny"


# ---------------- wildcard matching ----------------
@pytest.mark.parametrize("src,ok", [("10.10.30.0", True), ("10.10.30.77", True), ("10.10.30.255", True),
                                    ("10.10.31.1", False), ("10.11.30.1", False)])
def test_wildcard_24(src, ok):
    a = acl("extended", "permit ip 10.10.30.0 0.0.0.255 any")
    assert (a.evaluate(pkt("udp", src, "8.8.8.8", 53))[0] == "permit") is ok


def test_wildcard_slash30():
    a = acl("extended", "permit ip 10.10.255.0 0.0.0.3 any")
    assert a.evaluate(pkt("udp", "10.10.255.3", "1.1.1.1", 1))[0] == "permit"
    assert a.evaluate(pkt("udp", "10.10.255.4", "1.1.1.1", 1))[0] == "deny"


def test_noncontiguous_wildcard():
    # 0.0.255.0 = "any third octet, fourth octet must be .5"
    a = acl("extended", "permit ip 10.10.0.5 0.0.255.0 any")
    assert a.evaluate(pkt("tcp", "10.10.77.5", "1.1.1.1", 80))[0] == "permit"
    assert a.evaluate(pkt("tcp", "10.10.77.6", "1.1.1.1", 80))[0] == "deny"


def test_host_and_any_keywords():
    a = acl("extended", "permit tcp host 10.10.10.5 any eq 22")
    assert a.evaluate(pkt("tcp", "10.10.10.5", "10.10.99.1", 22))[0] == "permit"
    assert a.evaluate(pkt("tcp", "10.10.10.6", "10.10.99.1", 22))[0] == "deny"


def test_class_a_deny_then_internet_permit_pattern():
    a = acl("extended", "permit udp any any eq 67", "deny ip any 10.0.0.0 0.255.255.255",
            "permit ip 10.10.50.0 0.0.0.255 any")
    assert a.evaluate(pkt("tcp", "10.10.50.9", "203.0.113.10", 80))[0] == "permit"
    assert a.evaluate(pkt("tcp", "10.10.50.9", "10.10.20.10", 80))[0] == "deny"
    assert a.evaluate(pkt("udp", "0.0.0.0", "255.255.255.255", 67, sport=68))[0] == "permit"


# ---------------- protocols, ports, ICMP types ----------------
def test_echo_vs_echo_reply():
    a = acl("extended", "permit icmp 10.10.31.0 0.0.0.255 10.10.99.0 0.0.0.255 echo-reply")
    assert a.evaluate(pkt("icmp", "10.10.31.5", "10.10.99.50", icmp=0))[0] == "permit"
    assert a.evaluate(pkt("icmp", "10.10.31.5", "10.10.99.50", icmp=8))[0] == "deny"


def test_icmp_without_type_matches_all_types():
    a = acl("extended", "permit icmp any any")
    assert a.evaluate(pkt("icmp", "1.1.1.1", "2.2.2.2", icmp=8))[0] == "permit"
    assert a.evaluate(pkt("icmp", "1.1.1.1", "2.2.2.2", icmp=0))[0] == "permit"


def test_tcp_ace_does_not_match_udp_and_ip_matches_everything():
    a = acl("extended", "permit tcp any any eq 53")
    assert a.evaluate(pkt("udp", "1.1.1.1", "2.2.2.2", 53))[0] == "deny"
    b = acl("extended", "permit ip any any")
    for p in ("tcp", "udp"):
        assert b.evaluate(pkt(p, "1.1.1.1", "2.2.2.2", 9))[0] == "permit"


@pytest.mark.parametrize("ace,port,ok", [
    ("permit tcp any any eq www", 80, True), ("permit udp any any eq bootps", 67, True),
    ("permit tcp any any range 20 23", 23, True), ("permit tcp any any range 20 23", 24, False),
    ("permit tcp any any gt 1023", 1024, True), ("permit tcp any any lt 1024", 1024, False),
    ("permit tcp any any neq 23", 22, True), ("permit tcp any any neq 23", 23, False)])
def test_port_operators(ace, port, ok):
    proto = "udp" if "udp" in ace else "tcp"
    assert (acl("extended", ace).evaluate(pkt(proto, "1.1.1.1", "2.2.2.2", port))[0] == "permit") is ok


def test_source_port_operator():
    a = acl("extended", "permit udp any eq 67 any eq 67")
    assert a.evaluate(pkt("udp", "1.1.1.1", "2.2.2.2", 67, sport=67))[0] == "permit"
    assert a.evaluate(pkt("udp", "1.1.1.1", "2.2.2.2", 67, sport=68))[0] == "deny"


def test_sequence_numbers_in_named_acl():
    ace = parse_ace("20 permit tcp any any eq 443", "extended")
    assert ace.seq == 20 and ace.dst_port == ("eq", 443)


def test_unknown_port_name_is_an_error_not_a_silent_match():
    with pytest.raises(ValueError):
        parse_ace("permit tcp any any eq notaport", "extended")


# ---------------- standard ACLs ----------------
def test_standard_acl_matches_source_only():
    a = acl("standard", "permit 10.10.99.0 0.0.0.255")
    assert a.evaluate(pkt("tcp", "10.10.99.50", "10.10.99.11", 22))[0] == "permit"
    assert a.evaluate(pkt("tcp", "10.10.31.5", "10.10.99.11", 22))[0] == "deny"


def test_standard_acl_bare_address_is_host():
    a = acl("standard", "permit 10.10.99.50")
    assert a.evaluate(pkt("tcp", "10.10.99.50", "1.1.1.1", 22))[0] == "permit"
    assert a.evaluate(pkt("tcp", "10.10.99.51", "1.1.1.1", 22))[0] == "deny"


# ---------------- ASA: subnet masks ----------------
def test_asa_subnet_mask_converted_to_wildcard():
    a = acl("asa", "permit tcp 10.10.31.0 255.255.255.0 host 10.10.20.12 eq 80")
    assert a.evaluate(pkt("tcp", "10.10.31.200", "10.10.20.12", 80))[0] == "permit"
    assert a.evaluate(pkt("tcp", "10.10.32.1", "10.10.20.12", 80))[0] == "deny"
    assert a.aces[0].mask_tokens == ("255.255.255.0",)


def test_asa_slash16_and_slash30():
    a = acl("asa", "permit udp 10.10.0.0 255.255.0.0 host 10.10.20.11 eq 67",
            "permit udp 10.10.254.0 255.255.255.252 host 10.10.20.13 eq 514")
    assert a.evaluate(pkt("udp", "10.10.40.1", "10.10.20.11", 67))[0] == "permit"
    assert a.evaluate(pkt("udp", "10.10.254.1", "10.10.20.13", 514))[0] == "permit"
    assert a.evaluate(pkt("udp", "10.10.254.5", "10.10.20.13", 514))[0] == "deny"


def test_mask_is_contiguous():
    assert pa.mask_is_contiguous(ip2i("255.255.255.252"))
    assert not pa.mask_is_contiguous(ip2i("0.0.0.255"))


# ---------------- config parsing ----------------
CFG = """hostname R1
ip access-list extended IN-T
 remark test
 permit udp any any eq 67
 deny ip any any
access-list 10 remark mgmt
access-list 10 permit 10.10.99.0 0.0.0.255
interface range FastEthernet0/9 - 11, GigabitEthernet0/2
 switchport mode access
 switchport access vlan 999
 shutdown
interface Vlan31
 ip address 10.10.31.1 255.255.255.0
 ip helper-address 10.10.20.11
 ip access-group IN-T in
 no shutdown
line vty 0 15
 access-class 10 in
 login local
 transport input ssh
line vty 16 20
 transport input telnet
"""


def test_parse_small_config():
    d = parse_config(CFG, "CORE-MLS", "x")
    assert [a.text for a in d.acls["IN-T"].aces] == ["permit udp any any eq 67", "deny ip any any"]
    assert d.acls["10"].kind == "standard" and len(d.acls["10"].aces) == 1
    for n in ("Fa0/9", "Fa0/10", "Fa0/11", "Gi0/2"):
        assert d.ifaces[n].access_vlan == 999 and d.ifaces[n].shutdown
    assert d.ifaces["Fa0/12"].shutdown is None
    v = d.ifaces["Vlan31"]
    assert v.acl_in == "IN-T" and v.helpers == [ip2i("10.10.20.11")] and not v.switchport
    assert d.vty["transport"] == {"ssh"} and d.vty["access_class"] == "10"   # vty 16 20 ignored


def test_norm_if_and_ranges():
    assert pa.norm_if("FastEthernet0/1") == "Fa0/1"
    assert pa.norm_if("GigabitEthernet1/2") == "Gi1/2"
    assert pa.norm_if("vlan 10") == "Vlan10"
    assert pa.expand_if_range("FastEthernet0/1 - 3") == ["Fa0/1", "Fa0/2", "Fa0/3"]
    assert pa.parse_vlan_list("10,31-32,99") == {10, 31, 32, 99}


def test_vty_check_access_class_and_transport():
    d = parse_config(CFG.replace("hostname R1", "hostname R1\nusername netadmin privilege 15 secret x\n"
                                                "ip domain-name h.local\ncrypto key generate rsa general-keys modulus 1024"),
                     "CORE-MLS", "x")
    ok, why, _ = pa.vty_check(d, pkt("tcp", "10.10.99.50", "10.10.31.1", 22))
    assert ok, why
    ok, why, _ = pa.vty_check(d, pkt("tcp", "10.10.31.5", "10.10.31.1", 22))
    assert not ok and "access-class" in why
    ok, why, _ = pa.vty_check(d, pkt("tcp", "10.10.99.50", "10.10.31.1", 23))
    assert not ok and "transport" in why


def test_vty_login_without_password_refuses():
    d = parse_config("line vty 0 4\n login\n transport input telnet\n", "EDGE-RTR")
    ok, why, _ = pa.vty_check(d, pkt("tcp", "1.1.1.1", "2.2.2.2", 23))
    assert not ok and "none set" in why


def test_packet_reverse_turns_echo_into_echo_reply():
    p = pkt("icmp", "1.1.1.1", "2.2.2.2", icmp=8).reversed()
    assert p.icmp_type == 0 and p.src == ip2i("2.2.2.2") and p.reply
