# Install the patched Packet Tracer module (one-time, about 5 minutes)

The stock cisco-pt-mcp module (`cisco-pt-mcp.pts`) only exposes 18 fixed functions, so it cannot
set DHCP pools, DNS records or server services, read a PC's command-prompt output, or capture IOS
`show` output. The patched module adds **one** generic function, `ptEval`, and points the bridge at the
ptlab server (port 7532). Every new tool in `app/pt_tools.py` is built on that function, so this
rebuild is needed only once.

Source of the patch: `tools/pt-extension/plugin-src/` (upstream source from
github.com/muhammadbalawal/cisco-pt-mcp, MIT). Only two files differ from upstream:

| File | Change |
|---|---|
| `userfunctions.js` | appends `ptEval = function (code) {...}` (last 13 lines) |
| `interface/interface.js` | `MCP_URL` → `http://127.0.0.1:7532`, and `ptEval: ["code"]` added to `TOOL_ARGS` |

## Steps

1. Start the server first: `powershell -File app\run.ps1` (from the `CN Project` folder). Leave it open.
2. Open Packet Tracer 9.0.1.
3. **Extensions → Scripting → Configure PT Script Modules…** Select the existing `cisco-pt-mcp`
   module and open it for editing. Depending on the PT build, the button is labelled *Edit*, or
   double-clicking the module opens the *Scripting Interface*.
4. In the Scripting Interface:
   - Script Engine → file `userfunctions.js`: replace its whole content with
     `tools/pt-extension/plugin-src/userfunctions.js`.
   - Web Views → `interface.js` (under `interface/`): replace its whole content with
     `tools/pt-extension/plugin-src/interface/interface.js`.
   - Click **Save**. PT writes the module back to its `.pts` file. If PT asks for a file name, use
     `tools/pt-extension/cisco-pt-mcp-ptlab.pts`.
5. Restart Packet Tracer, then click **Extensions → Packet Tracer MCP**. The bridge window should
   show `connected`, and the dashboard (http://127.0.0.1:7532/) header should say
   *Packet Tracer connected*.

If the module cannot be edited (for example, it is locked), use **New** in the same dialog. Add the
seven files from `plugin-src/` (`main.js`, `window.js`, `runcode.js`, `userfunctions.js`,
`devices.js`, `links.js`, `modules.js`) as Script Engine files, and `interface/index.html`,
`interface/interface.js` and the stock `socket.io.min.js` as web-view files. Then save it as a new
`.pts`.

## Quick check after connecting

```powershell
curl.exe -s -X POST http://127.0.0.1:7532/api/pt/tool/probeProcesses -H "content-type: application/json" -d '{\"deviceName\":\"DNS-DHCP-SRV\"}'
```

It should list which service processes exist on the server (DnsServer, HttpServer, DHCP).

## Going back to the stock module

Re-add the original `tools/pt-extension/cisco-pt-mcp.pts`. The stock `cisco-pt-mcp` MCP server keeps
working on port 7531.
