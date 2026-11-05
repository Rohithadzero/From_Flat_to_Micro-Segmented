# ptlab: gateway, test runner and dashboard

One local server (`http://127.0.0.1:7532/`, loopback only) that:

1. **Bridges Packet Tracer.** The patched PT module connects to it over Socket.IO, using the same wire
   protocol as cisco-pt-mcp.
2. **Exposes every PT tool over REST.** That is the 18 stock tools plus 16 new ones built on `ptEval`:
   server services, DHCP pools, DNS records, web pages, PC command prompt (ping/telnet/ssh/
   nslookup/tracert), IOS `show` capture, browser (HttpClient), DHCP renew, device list.
3. **Runs the experiment** (`live_runner.py`). For each design it:
   - opens `Cisco packet saves/Dn.pkt`;
   - applies the CHECKLIST GUI steps;
   - runs A1–A8, Q1, O1 and F1–F9 from 3 locations × N trials;
   - writes **observed** values to `results/*.csv`, with raw evidence JSON under `results/raw/`.
4. **Serves the dashboard.** It has these tabs:
   - Containment map: expected, analyzer and observed views;
   - Results;
   - Configurations, with a diff against the previous design;
   - Live lab: run and stop tests, quick commands;
   - Checks: pytest, plus manual entry for F3/F8.
5. **Feeds an MCP proxy** (`mcp_proxy.py`, 36 tools). Claude Code, the dashboard and the runner then all
   share one PT connection.

## Run

```powershell
powershell -File app\run.ps1           # starts the server; open http://127.0.0.1:7532/
```
Install the patched PT module once: `tools/pt-extension/PATCH-PLUGIN.md`.

Register the MCP proxy for Claude Code (optional; restart Claude Code afterwards):
```powershell
claude mcp add hospital-pt --scope user -e PYTHONPATH="C:\01ZEPHYRUS\RV\Computer Networks\CN Project" -- "$env:APPDATA\uv\tools\cisco-pt-mcp\Scripts\python.exe" -m app.mcp_proxy
```

## REST

| Method | Path | Body / query |
|---|---|---|
| GET | `/api/pt/status` | PT connected?, recent calls |
| POST | `/api/pt/tool/{name}` | tool arguments as JSON |
| GET | `/api/results` | expected / static / observed matrices, surface, functional, complexity, extended tests |
| GET | `/api/configs/{D0..D3}`, `/api/diff?a=D2&b=D3&device=CORE-MLS` | |
| GET | `/api/analysis` | static policy analyzer (`tools/policy_analyzer.py`) |
| POST | `/api/tests/pytest` | runs `tests/` |
| POST | `/api/live/run` | `{designs, tests, locations, trials, open_file, prepare, save}` |
| POST | `/api/live/prepare` | GUI checklist only |
| GET/POST | `/api/live/status`, `/api/live/stop` | |
| POST | `/api/observe` | manual observation (`csv`, `match`, `updates`), stamped "manual" |

## Tests added from the literature review (research/GAP-ANALYSIS.md)

| ID | What | Output |
|---|---|---|
| A8 | rogue switch on a staff jack tries DTP trunking (switch spoofing) | `results/extended-attacks.csv` |
| Q1 | detect the node from ACL deny counters, then move its port to VLAN 999; time-to-detect/contain, collateral | `results/extended-attacks.csv` |
| O1 | RTT avg/max (10 pings), tracert hops, EHR page load for legitimate flows | `results/overhead.csv` |
| (A1–A4) | deny-counter deltas per attack window, i.e. detection coverage | `results/detection.csv` |
| PE | does PT accept `switchport protected` (PVLAN edge)? | `results/probes.csv` |

`python tools/metrics.py` gives ASR, weighted blast radius, attack block rate, policy-compliance rate,
detection coverage and Fisher's exact test between adjacent designs. The output goes to `results/metrics.csv`.

## Self-test without Packet Tracer
```powershell
& "$env:APPDATA\uv\tools\cisco-pt-mcp\Scripts\python.exe" -m app.selftest   # fake plugin, 7 checks
```
