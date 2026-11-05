"""ptlab: one local server for the smart-hospital segmentation project.

  * Socket.IO bridge for the (patched) Packet Tracer plugin   ws://127.0.0.1:7532
  * REST gateway to every PT tool                             /api/pt/...
  * Dashboard backend (configs, results, analyzer, tests)      /api/...
  * Dashboard frontend                                         http://127.0.0.1:7532/

Run:  app\\run.ps1     (uses the Python 3.12 venv that ships with cisco-pt-mcp)
Loopback only.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import time
from pathlib import Path

from aiohttp import web

from . import project
from .bridge import PTBridge
from .live_runner import LOCATIONS, LiveRunner
from .pt_tools import COMPOSITE_SCHEMAS, LEGACY_TOOLS, PTTools

log = logging.getLogger("ptlab")
STATIC = Path(__file__).resolve().parent / "static"
HOST = "127.0.0.1"


def ok(data, status=200):
    return web.json_response(data, status=status, dumps=lambda o: json.dumps(o, default=str))


def build_app() -> web.Application:
    app = web.Application(client_max_size=4 * 1024 * 1024)
    bridge = PTBridge(app)
    tools = PTTools(bridge)
    runner = LiveRunner(tools)
    app["bridge"], app["tools"], app["runner"] = bridge, tools, runner
    r = app.router

    # ------------------------------------------------------------ PT gateway
    async def pt_status(_):
        return ok({"connected": bridge.is_connected, "since": bridge.connected_since,
                   "history": list(bridge.history)[:40], "job": runner.status()["state"]})

    async def pt_tools_list(_):
        return ok({"legacy": LEGACY_TOOLS, "composite": COMPOSITE_SCHEMAS})

    async def pt_tool(req):
        name = req.match_info["name"]
        try:
            args = await req.json() if req.can_read_body else {}
        except json.JSONDecodeError:
            return ok({"success": False, "error": "body must be JSON"}, 400)
        return ok(await tools.call(name, args or {}))

    r.add_get("/api/pt/status", pt_status)
    r.add_get("/api/pt/tools", pt_tools_list)
    r.add_post("/api/pt/tool/{name}", pt_tool)

    # ------------------------------------------------------------- project
    async def proj(_):
        return ok({"designs": project.DESIGNS, "locations": list(LOCATIONS), "summary": project.summary()})

    async def configs(req):
        d = req.match_info["design"]
        if d not in project.DESIGNS:
            return ok({"error": "unknown design"}, 404)
        return ok(project.list_configs(d))

    async def diff(req):
        q = req.query
        return ok(project.config_diff(q.get("a", "D2"), q.get("b", "D3"), q.get("device", "CORE-MLS")))

    async def results(_):
        return ok(project.results_bundle())

    async def csv_get(req):
        key = req.match_info["key"]
        if key not in project.CSV_FILES:
            return ok({"error": "unknown csv"}, 404)
        return ok(project.read_csv(key))

    async def observe(req):
        """Manual entry for tests that PT scripting cannot run (marked 'manual')."""
        body = await req.json()
        key = body.get("csv")
        if key not in ("attack-matrix", "attack-surface", "functional"):
            return ok({"error": "csv must be attack-matrix, attack-surface or functional"}, 400)
        updates = {k: str(v) for k, v in (body.get("updates") or {}).items()}
        allowed = {"observed", "notes", "observed_hosts_of_23", "observed_services_of_10"}
        if not updates or set(updates) - allowed:
            return ok({"error": f"updates may only touch {sorted(allowed)}"}, 400)
        updates.setdefault("notes", "")
        updates["notes"] = f"manual {time.strftime('%Y-%m-%d')}; " + updates["notes"]
        n = project.record_observation(key, body.get("match") or {}, updates)
        return ok({"changed": n})

    async def analysis(_):
        return ok(await asyncio.to_thread(project.analyzer))

    async def pytest_run(_):
        return ok(await asyncio.to_thread(project.run_pytest))

    r.add_get("/api/project", proj)
    r.add_get("/api/configs/{design}", configs)
    r.add_get("/api/diff", diff)
    r.add_get("/api/results", results)
    r.add_get("/api/csv/{key}", csv_get)
    r.add_post("/api/observe", observe)
    r.add_get("/api/analysis", analysis)
    r.add_post("/api/tests/pytest", pytest_run)

    # ---------------------------------------------------------------- live
    async def live_status(_):
        return ok(runner.status())

    async def live_run(req):
        b = await req.json()
        designs = b.get("designs") or [b.get("design", "D3")]
        if any(d not in project.DESIGNS for d in designs):
            return ok({"error": "unknown design"}, 400)
        tests = b.get("tests") or ["A1", "A2", "A3", "A4", "A5", "A6", "A7", "F", "A8", "Q1", "O1"]
        locs = b.get("locations") or list(LOCATIONS)
        trials = max(1, min(int(b.get("trials", 3)), 5))

        async def job():
            for d in designs:
                await runner.run_design(d, open_file=bool(b.get("open_file", True)), prep=bool(b.get("prepare", True)),
                                        save=bool(b.get("save", False)), tests=tests, locations=locs, trials=trials)

        return ok(runner.start(job, f"run {','.join(designs)} {','.join(tests)} x{trials}"))

    async def live_prepare(req):
        b = await req.json()
        designs = b.get("designs") or [b.get("design", "D0")]

        async def job():
            for d in designs:
                if b.get("open_file", True):
                    await runner.open_design(d)
                await runner.prepare(d)
                if b.get("save", False):
                    await runner.save_design(d)

        return ok(runner.start(job, f"prepare {','.join(designs)}"))

    async def live_stop(_):
        runner.stop()
        return ok({"stopping": True})

    r.add_get("/api/live/status", live_status)
    r.add_post("/api/live/run", live_run)
    r.add_post("/api/live/prepare", live_prepare)
    r.add_post("/api/live/stop", live_stop)

    # ------------------------------------------------------------ frontend
    async def index(_):
        return web.FileResponse(STATIC / "index.html")

    r.add_get("/", index)
    r.add_static("/static/", STATIC)
    r.add_static("/figures/", project.ROOT / "report" / "figures")
    return app


async def main_async(port: int) -> None:
    app = build_app()
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, HOST, port).start()
    log.info("ptlab on http://%s:%d  (PT plugin -> ws://%s:%d)", HOST, port, HOST, port)
    print(f"ptlab running: http://{HOST}:{port}/", flush=True)
    await asyncio.Event().wait()


def main() -> None:
    ap = argparse.ArgumentParser(prog="ptlab")
    ap.add_argument("--port", type=int, default=7532)
    ap.add_argument("--log-level", default="INFO")
    a = ap.parse_args()
    logging.basicConfig(level=a.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        asyncio.run(main_async(a.port))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
