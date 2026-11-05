# Start the ptlab server (PT bridge + REST gateway + dashboard) on http://127.0.0.1:7532/
# Uses the Python 3.12 venv installed with cisco-pt-mcp (has aiohttp, python-socketio, mcp, httpx).
$py = Join-Path $env:APPDATA "uv\tools\cisco-pt-mcp\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }
Set-Location (Split-Path -Parent $PSScriptRoot)   # CN Project
& $py -m app @args
