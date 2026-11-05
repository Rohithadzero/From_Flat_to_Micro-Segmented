"""Design-level assertions: what the paper claims, checked against the analyzer's computed predictions."""
import pytest

import policy_analyzer as pa
from conftest import attack
from policy_analyzer import ip2i

LOCS = ["L1", "L2", "L3"]


def res(all_results, d):
    return all_results["designs"][d]


def surface(all_results, d, loc):
    return res(all_results, d)["locations"][loc]["surface"]


# ---------------- headline claims ----------------
def test_d0_flat_everything_reachable(all_results):
    for loc in LOCS:
        s = surface(all_results, "D0", loc)
        assert (s["hosts_reachable_of_23"], s["services_reachable_of_10"]) == (23, 10)
    assert all(a["predicted"] == "S" for a in res(all_results, "D0")["attacks"])


def test_d1_vlans_alone_do_not_block_a2(all_results):
    for row in attack(res(all_results, "D1"), "A2"):
        assert row["predicted"] == "S", row
        assert "UNFILTERED" in row["reason"]


def test_d1_vlans_alone_contain_nothing(all_results):
    assert all(a["predicted"] == "S" for a in res(all_results, "D1")["attacks"])
    for loc in LOCS:
        assert surface(all_results, "D1", loc)["hosts_reachable_of_23"] == 23


@pytest.mark.parametrize("test_id", ["A2", "A4", "A5", "A6", "A7"])
def test_d3_blocks(all_results, test_id):
    for row in attack(res(all_results, "D3"), test_id):
        assert row["predicted"] == "B", row
        assert row["predicted_readme_procedure"] == "B", row


def test_d3_a2_blocked_by_monitors_acl_line(all_results):
    row = attack(res(all_results, "D3"), "A2", "L1")[0]
    assert "MONITORS-IN" in row["reason"] and "CORE-MLS.txt:110" in row["reason"]  # final deny (line moved +4 by the F-3 fix)


def test_d3_partial_attacks_are_a1_and_a3(all_results):
    part = {a["test_id"] for a in res(all_results, "D3")["attacks"] if a["predicted"] == "P"}
    assert part == {"A1", "A3"}


def test_d3_blocks_five_of_seven_attack_types(all_results):
    by_type = {}
    for a in res(all_results, "D3")["attacks"]:
        by_type.setdefault(a["test_id"], set()).add(a["predicted"])
    assert sum(1 for v in by_type.values() if v == {"B"}) == 5


# ---------------- residual risk: same-VLAN traffic is never filtered ----------------
@pytest.mark.parametrize("loc,peers", [("L1", {"Monitor-A1", "Monitor-B1"}), ("L2", {"Monitor-A1", "Monitor-B1"}),
                                       ("L3", {"Smart-Door", "Fire-Monitor", "HVAC-Fan", "Webcam"})])
def test_d3_same_vlan_reachability_survives(all_results, loc, peers):
    la = res(all_results, "D3")["locations"][loc]
    reach = {h["target"]: h for h in la["hosts"] if h["reachable"]}
    assert set(reach) == peers
    for h in reach.values():
        assert h["reason"].startswith("L2_SAME_VLAN")


def test_d3_monitor_vlan_spans_both_wards(all_results):
    """VLAN 31 is trunked to both ward switches, so Ward-A's attacker reaches Ward-B's monitor at L2."""
    la = res(all_results, "D3")["locations"]["L1"]
    mb1 = next(h for h in la["hosts"] if h["target"] == "Monitor-B1")
    assert mb1["reachable"] and mb1["reason"].startswith("L2_SAME_VLAN")


def test_d3_attacker_cannot_ping_its_own_gateway(all_results):
    """Inbound SVI ACLs also filter traffic addressed to the switch itself."""
    la = res(all_results, "D3")["locations"]["L1"]
    gw = next(h for h in la["hosts"] if h["target"].startswith("CORE-MLS"))
    assert not gw["reachable"] and "MONITORS-IN" in gw["reason"]


def test_d3_only_iot_server_http_remains(all_results):
    for loc in LOCS:
        s = surface(all_results, "D3", loc)
        assert s["service_list"] == ["IoT-server HTTP"]


def test_surface_never_grows_with_more_policy(all_results):
    for loc in LOCS:
        h = [surface(all_results, d, loc)["hosts_reachable_of_23"] for d in pa.DESIGNS]
        s = [surface(all_results, d, loc)["services_reachable_of_10"] for d in pa.DESIGNS]
        assert h == sorted(h, reverse=True) and s == sorted(s, reverse=True), (loc, h, s)


# ---------------- D2 ----------------
def test_d2_iot_still_reaches_ehr(all_results):
    for row in attack(res(all_results, "D2"), "A2"):
        assert row["predicted"] == "S" and ("MEDIOT-IN#4" in row["reason"] or "BLDGIOT-IN#4" in row["reason"])  # zone permit after F-1/F-3 lines


def test_d2_guest_blocked(all_results):
    assert attack(res(all_results, "D2"), "A7")[0]["predicted"] == "B"


def test_d2_core_vty_closed_after_f1_fix(all_results):
    """FINDING F-1 is fixed in configs/: IoT can no longer reach the core's own SVI 10.10.20.1."""
    for loc in LOCS:
        la = res(all_results, "D2")["locations"][loc]
        core = next(s for s in la["services"] if s["service"].startswith("CORE-MLS"))
        assert not core["reachable"], core
        assert la["attacks"]["A4"]["predicted"] == "B"


def test_d2_f1_regression_bug_reappears_without_fix(mutated):
    """Regression guard: removing the F-1 deny line re-opens Telnet to 10.10.20.1 (the original bug)."""
    bug = [(" remark F-1 fix: the server zone contains the core's own SVI 10.10.20.1 (Telnet VTY)\n"
            " deny ip any host 10.10.20.1\n", "")]
    r = mutated("D2", {"CORE-MLS": bug})
    for loc in LOCS:
        la = r["locations"][loc]
        core = next(s for s in la["services"] if s["service"].startswith("CORE-MLS"))
        assert core["reachable"] and core["reachable_ips"] == ["10.10.20.1"]
        assert la["attacks"]["A4"]["predicted"] == "P"


# ---------------- functional (least privilege must not break the hospital) ----------------
@pytest.mark.parametrize("design", pa.DESIGNS)
def test_all_functional_tests_pass(all_results, design):
    f = res(all_results, design)["functional"]
    assert set(f) == {f"F{i}" for i in range(1, 10)}
    bad = {k: v["reason"] for k, v in f.items() if v["predicted"] != "PASS"}
    assert not bad


def test_d3_dhcp_leases_in_split_medical_vlans(all_results):
    leases = res(all_results, "D3")["functional"]["F4"]["leases"]
    assert leases["Monitor-A1"].startswith("10.10.31.") and leases["Pump-A1"].startswith("10.10.32.")


def test_d3_staff_ehr_passes_both_policy_layers(all_results):
    r = res(all_results, "D3")["functional"]["F1"]["reason"]
    assert "STAFF-IN#3" in r and "OUTSIDE-IN#1" in r


# ---------------- mutation tests: verdicts follow the controls, not a lookup table ----------------
def test_defence_in_depth_asa_alone_blocks_ehr(mutated):
    r = mutated("D3", {"CORE-MLS": [(" ip access-group MONITORS-IN in\n", "")]})
    row = attack(r, "A2", "L1")[0]
    assert row["predicted"] == "B" and "ASA_ACL_DENY" in row["reason"] and "OUTSIDE-IN" in row["reason"]


def test_defence_in_depth_core_alone_blocks_ehr(mutated):
    # Make the ASA permit everything (removing the access-group instead would also block the
    # DHCP relay by security level, so the attacker would never get an address).
    r = mutated("D3", {"ASA-SRV": [("access-list OUTSIDE-IN extended deny ip any any",
                                    "access-list OUTSIDE-IN extended permit ip any any")]})
    row = attack(r, "A2", "L1")[0]
    assert r["locations"]["L1"]["attacker"]["ip"]
    assert row["predicted"] == "B" and "MONITORS-IN" in row["reason"]


def test_asa_without_acl_denies_by_security_level(mutated):
    r = mutated("D3", {"ASA-SRV": [("access-group OUTSIDE-IN in interface outside\n", "")]})
    f1 = r["functional"]["F1"]
    assert f1["predicted"] == "FAIL" and "ASA_SECLEVEL_DENY" in f1["reason"]


def test_removing_dhcp_snooping_enables_rogue_dhcp(mutated):
    r = mutated("D3", {"SW-WARD-A": [("ip dhcp snooping vlan 10,31,32\n", "ip dhcp snooping vlan 31,32\n")]})
    assert attack(r, "A5")[0]["predicted"] == "S"


def test_removing_port_security_enables_rogue_device(mutated):
    block = (" description Monitor-A1 (patient monitor)\n switchport mode access\n switchport access vlan 31\n"
             " switchport port-security\n")
    r = mutated("D3", {"SW-WARD-A": [(block, block.replace(" switchport port-security\n", ""))]})
    a6 = attack(r, "A6")[0]
    assert a6["predicted"] == "S" and "10.10.31." in a6["reason"]


def test_untrusted_uplink_breaks_dhcp(mutated):
    r = mutated("D3", {"SW-WARD-A": [(" switchport nonegotiate\n ip dhcp snooping trust\n", " switchport nonegotiate\n")]})
    f4 = r["functional"]["F4"]
    assert f4["predicted"] == "FAIL" and "SNOOPING_DROP" in f4["reason"]


def test_wrong_native_vlan_is_reported(mutated):
    r = mutated("D3", {"SW-WARD-B": [(" switchport trunk native vlan 998\n", " switchport trunk native vlan 1\n")]})
    assert any("native VLAN mismatch" in w for w in r["warnings"])


def test_d2_matches_expected_values_after_fix(all_results):
    """With F-1 fixed, D2 matches the README's expected 8 hosts / 4 services / A4=B, F1-F9 intact."""
    r = res(all_results, "D2")
    for loc in LOCS:
        s_ = r["locations"][loc]["surface"]
        assert (s_["hosts_reachable_of_23"], s_["services_reachable_of_10"]) == (8, 4)
    assert all(v["predicted"] == "PASS" for v in r["functional"].values())


def test_udp67_exfil_closed_and_dhcp_still_works_in_d3(all_results):
    """FINDING F-3 fixed: DHCP permits are broadcast + real server only; no UDP/67 path to the Internet."""
    r = res(all_results, "D3")
    assert all(v["predicted"] == "PASS" for v in r["functional"].values())
    for loc in LOCS:
        ch = next(c for c in r["locations"][loc]["residual_channels"] if c["channel"].startswith("UDP/67 to Internet"))
        assert not ch["forward_delivered"], ch
        assert r["locations"][loc]["surface"]["services_reachable_of_10"] == 1


def test_f3_regression_broad_dhcp_permit_reopens_exfil(mutated):
    """Regression guard: the original 'permit udp any any eq 67' re-opens UDP/67 to the Internet via PAT."""
    bug = [(" permit udp any host 255.255.255.255 eq 67\n permit udp any host 10.10.20.11 eq 67\n",
            " permit udp any any eq 67\n")]
    la = mutated("D3", {"CORE-MLS": bug})["locations"]["L1"]
    ch = next(c for c in la["residual_channels"] if c["channel"].startswith("UDP/67 to Internet"))
    assert ch["forward_delivered"] and "MONITORS-IN#1" in ch["reason"] and "NAT_PAT" in ch["reason"]


# ---------------- API / outputs ----------------
def test_api_shapes(all_results):
    assert set(all_results["designs"]) == set(pa.DESIGNS)
    for d in pa.DESIGNS:
        r = all_results["designs"][d]
        assert len(r["attacks"]) == 4 * 3 + 3
        assert all(a["predicted"] in "SPB" and a["reason"] for a in r["attacks"])


def test_analyze_is_deterministic():
    a, b = pa.analyze("D3"), pa.analyze("D3")
    assert a["attacks"] == b["attacks"] and a["functional"] == b["functional"]


def test_cli_single_design_runs(capsys):
    assert pa.main(["--design", "D3", "--no-write"]) == 0
    assert "== D3 ==" in capsys.readouterr().out


# ---------------- live-plan proxy logic ----------------
def test_icmp_proxy_validity_is_rule_based():
    import make_live_plan as mlp
    m, atk = pa.with_attacker("D3", "L1")
    src = ("host", atk.name)
    # EHR: ICMP and HTTP are both dropped by MONITORS-IN 'deny ip any any' -> valid proxy
    assert mlp.proxy(m, src, ip2i("10.10.20.10"), "tcp", 80)["proxy_valid"]
    # IoT server: HTTP permitted by MONITORS-IN#2, ICMP denied by #4 -> NOT a valid proxy
    p = mlp.proxy(m, src, ip2i("10.10.20.12"), "tcp", 80)
    assert not p["proxy_valid"] and p["real_predicted"] == "reachable" and p["icmp_predicted"] == "dropped"


# ---------------- ECC review finding H-1 (D2 guest -> EDGE-RTR WAN Telnet) ----------------
def _guest_to_edge_telnet(config_dir=None):
    m = pa.load_design("D2", config_dir)
    return pa.probe(m, ("host", "Guest-Phone"), pa.ip2i("198.51.100.2"), "tcp", 23)


def test_d2_guest_cannot_telnet_edge_wan_after_h1_fix():
    r = _guest_to_edge_telnet()
    assert not r["ok"], r


def test_d2_h1_regression_guest_reaches_edge_without_fix(tmp_path):
    import shutil
    dst = tmp_path / "D2"
    shutil.copytree(pa.CONFIGS / pa.DESIGN_DIRS["D2"], dst)
    f = dst / "CORE-MLS.txt"
    f.write_text(f.read_text(encoding="utf-8").replace(" deny ip any 198.51.100.0 0.0.0.3\n", ""), encoding="utf-8")
    assert _guest_to_edge_telnet(dst)["ok"]
