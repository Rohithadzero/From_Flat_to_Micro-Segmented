# Phase 1 report: static analyzer + test suite (offline)

## Analyzer verdicts vs expected (from `results/static-analysis.csv`)

| Design | A1 | A2 | A3 | A4 | A5 | A6 | A7 | Hosts /23 (L1,L2,L3) | Services /10 | F1-F9 |
|---|---|---|---|---|---|---|---|---|---|---|
| D0 | S | S | S | S | S | S | S | 23,23,23 | 10 | 9/9 PASS |
| D1 | S | S | S | S | S | S | S | 23,23,23 | 10 | 9/9 PASS |
| D2 | P | S | S,S,**P** | **P** (README procedure gives B) | S | S | B | **9** (8 at README addresses) | **5** (4) | 9/9 PASS |
| D3 | P | B | P | B | B | B | B | 2,2,4 | 1 (IoT-server HTTP) | 9/9 PASS |

- D3 fully blocks 5 of 7 attack types; A1/A3 stay partial only through same-VLAN traffic
  (Monitor-A1 and Monitor-B1 share VLAN 31 across both wards; the 4 building-IoT devices at L3).
- Defence in depth holds both ways (mutation tests): core ACL removed -> ASA alone blocks the EHR;
  ASA permit-all -> core ACL alone blocks it.
- All 7 disagreements with the hand-written expectations are in D2; see `FINDINGS.md` (F-1, F-2).

## pytest
`python -m pytest tests -q` -> 121 passed, 1 xfailed (F-4, deliberate).
- ACL engine: first match, implicit deny, wildcards (incl. non-contiguous), host/any, echo vs
  echo-reply, port operators, standard ACLs, ASA subnet masks, VTY checks.
- Config lint: SVI ACLs, DHCP permit first, trunk hardening, parked ports, SSH-only VTY + access-class,
  no overlapping subnets, helper-address, ASA masks, undefined-ACL references, port security +
  BPDU guard, snooping trust, ASA always in the server path.
- Design assertions: D0-D3 claims and the D3 same-VLAN residual risk.
- Mutation tests: removing snooping, port security, uplink trust or an ACL layer flips the verdict;
  the proposed fixes work.

## Live measurement
The stock MCP can only send ICMP between named devices. The ptlab gateway (`app/`, patched PT module)
adds PC command output (ping/telnet/ssh/nslookup/tracert), a browser client, IOS `show` capture,
server services, DHCP pools and DNS records, so `app/live_runner.py` can run A1-A8, Q1, O1 and
F1/F2/F4-F7/F9 directly. F3 and F8 stay manual. The analyzer's ICMP-proxy plan in
`tools/live_test_plan.json` remains the fallback if only the stock module is available.
