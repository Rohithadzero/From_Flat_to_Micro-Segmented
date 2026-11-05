"""MCP (stdio) front for the ptlab gateway.

Claude Code / any MCP client talks to this process; every tool call is
forwarded to the running ptlab server (http://127.0.0.1:7532/api/pt/tool/...),
so the MCP client, the dashboard and the automated test runner all share one
Packet Tracer connection.

Register (after starting app/run.ps1):
  claude mcp add hospital-pt --scope user -- <venv python> -m app.mcp_proxy
  (run from the CN Project folder, or set PYTHONPATH to it)
"""

from __future__ import annotations

import asyncio
import json
import os

import httpx
import mcp.types as T
from mcp.server import Server
from mcp.server.stdio import stdio_server

try:  # legacy schemas ship with cisco-pt-mcp, which this venv already has
    from mcp_server.tools import TOOLS as LEGACY
except Exception:  # noqa: BLE001
    LEGACY = []

from .pt_tools import COMPOSITE_SCHEMAS

BASE = os.environ.get("PTLAB_URL", "http://127.0.0.1:7532")

EXTRA = [
    {"name": "liveRun", "description": "Start the automated test runner on the ptlab server (opens the design .pkt, "
     "applies the GUI checklist, runs attacks/functional tests, writes observed CSV values). Returns job status.",
     "inputSchema": {"type": "object", "properties": {
         "designs": {"type": "array", "items": {"type": "string"}}, "tests": {"type": "array", "items": {"type": "string"}},
         "locations": {"type": "array", "items": {"type": "string"}}, "trials": {"type": "integer"},
         "open_file": {"type": "boolean"}, "prepare": {"type": "boolean"}, "save": {"type": "boolean"}}}},
    {"name": "liveStatus", "description": "Status and log of the running/finished test job.",
     "inputSchema": {"type": "object", "properties": {}}},
]


def descriptors() -> list[T.Tool]:
    out = [T.Tool(name=t["name"], description=t["description"], inputSchema=t["inputSchema"]) for t in LEGACY]
    for name, s in COMPOSITE_SCHEMAS.items():
        out.append(T.Tool(name=name, description=s["description"],
                          inputSchema={"type": "object", "properties": s["properties"], "required": s["required"]}))
    out += [T.Tool(**t) for t in EXTRA]
    return out


def build() -> Server:
    app: Server = Server("hospital-pt")
    tools = descriptors()

    @app.list_tools()
    async def _list() -> list[T.Tool]:
        return tools

    @app.call_tool()
    async def _call(name: str, arguments: dict) -> list[T.TextContent]:
        async with httpx.AsyncClient(timeout=600) as c:
            try:
                if name == "liveRun":
                    r = await c.post(f"{BASE}/api/live/run", json=arguments or {})
                elif name == "liveStatus":
                    r = await c.get(f"{BASE}/api/live/status")
                else:
                    r = await c.post(f"{BASE}/api/pt/tool/{name}", json=arguments or {})
                data = r.json()
            except httpx.HTTPError as exc:
                data = {"success": False, "error": f"ptlab server not reachable at {BASE}: {exc}. Start app\\run.ps1"}
        return [T.TextContent(type="text", text=json.dumps(data, indent=1, default=str))]

    return app


async def run() -> None:
    app = build()
    async with stdio_server() as (r, w):
        await app.run(r, w, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(run())
