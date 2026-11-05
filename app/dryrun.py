"""Dry-run the live test runner end to end WITHOUT Packet Tracer.

* A fake bridge answers every tool call with plausible, canned output.
* A virtual clock makes all sleeps instant.
* results/ is redirected to a temporary sandbox, so the real CSVs are never touched.

It exercises every code path (prepare, A1-A8, Q1, O1, PE, F1-F9, CSV writers, evidence files)
and reports any exception. The values it produces are FAKE and are thrown away.

Usage: <venv python> -m app.dryrun [D3] [--keep]
"""
from __future__ import annotations

import asyncio
import json
import shutil
import sys
import tempfile
import time as _time
import traceback
from pathlib import Path

from . import live_runner, project
from .pt_tools import PTTools


class Clock:
    def __init__(self) -> None:
        self.t = 1_000_000.0

    def time(self) -> float:
        return self.t

    async def sleep(self, d: float = 0) -> None:
        self.t += max(d, 0.05)
        await _real_sleep(0)


_real_sleep = asyncio.sleep
CLOCK = Clock()


class FakeBridge:
    """Canned PT answers keyed on the JS snippet shape."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.deny = 0

    async def call(self, tool: str, args: dict) -> dict:
        self.calls.append(tool)
        if tool != "ptEval":
            return {"success": True, "result": {"deviceCount": 0, "devices": [], "connections": []}}
        c = args["code"]
        if "return before;" in c:
            return {"success": True, "result": 0}
        if "line.getOutput()" in c and "substring(from)" in c:
            self.deny += 1
            text = ("Reply from 10.10.20.10: bytes=32 time<1ms TTL=127\n"
                    "Ping statistics for 10.10.20.10:\n Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),\n"
                    "Approximate round trip times in milli-seconds:\n Minimum = 0ms, Maximum = 1ms, Average = 0ms\n"
                    "Default Gateway......: 10.10.10.1\n"
                    f" 10 deny ip any any ({self.deny} matches)\n Password: \nC:\\>")
            return {"success": True, "result": {"len": len(text), "text": text, "prompt": "C:\\>"}}
        if "getIpAddress()" in c:
            return {"success": True, "result": {"ip": "10.10.31.102", "mask": "255.255.255.0",
                                                "mac": "0001.4242.0001", "dhcp": True, "gateway": None}}
        if "getLastPageContent" in c and "go(" in c:
            return {"success": True, "result": {"process": "HttpClient", "before": "", "accepted": True}}
        if "getLastPageContent" in c:
            return {"success": True, "result": "<h1>Public Internet web server</h1> marker:x"}
        if "pools()" in c:
            return {"success": True, "result": {"enabled": True, "pools": [{"name": "serverPool"}, {"name": "MED-IOT"}]}}
        if "getAllEntries" in c:
            return {"success": True, "result": 3}
        return {"success": True, "result": {"ok": True}}


async def main(design: str, keep: bool) -> int:
    sandbox = Path(tempfile.mkdtemp(prefix="ptlab-dryrun-"))
    shutil.copytree(project.RES, sandbox / "results", ignore=shutil.ignore_patterns("raw"))
    real_res = project.RES
    project.RES = sandbox / "results"
    project.OBS_HOSTS = project.RES / "observed-hosts.json"
    live_runner.RAW = project.RES / "raw"
    asyncio.sleep = CLOCK.sleep          # type: ignore[assignment]
    _time.time = CLOCK.time              # type: ignore[assignment]
    bridge = FakeBridge()
    runner = live_runner.LiveRunner(PTTools(bridge))  # type: ignore[arg-type]
    runner.job = {"log": [], "observations": 0}
    tests = ["A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "Q1", "O1", "PE", "F"]
    ok = True
    try:
        await runner.run_design(design, open_file=True, prep=True, save=False, tests=tests,
                                locations=list(live_runner.LOCATIONS)[:1], trials=1)
    except Exception:  # noqa: BLE001
        ok = False
        traceback.print_exc()
    finally:
        project.RES = real_res
    written = {p.name: sum(1 for _ in p.open(encoding="utf-8")) - 1
               for p in (sandbox / "results").glob("*.csv")}
    print(json.dumps({"design": design, "ok": ok, "tool_calls": len(bridge.calls),
                      "observations_written_in_sandbox": runner.job.get("observations"),
                      "csv_rows_in_sandbox": written,
                      "evidence_files": len(list((sandbox / "results" / "raw").rglob("*.json"))),
                      "log_tail": runner.job["log"][-6:]}, indent=1))
    if not keep:
        shutil.rmtree(sandbox, ignore_errors=True)
    else:
        print("sandbox kept at", sandbox)
    return 0 if ok else 1


if __name__ == "__main__":
    d = next((a for a in sys.argv[1:] if a.startswith("D")), "D3")
    sys.exit(asyncio.run(main(d, "--keep" in sys.argv)))
