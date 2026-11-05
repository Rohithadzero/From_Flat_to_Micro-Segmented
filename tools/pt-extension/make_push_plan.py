"""Build quirk-safe push plans for the cisco-pt-mcp live build.

Packet Tracer drops the CLI line that follows `no shutdown` (the link-state
console message swallows it). So each config is cut into chunks that END
at any (no) shutdown or RSA-key line; every chunk is one configureIosDevice
call.

Output: tools/pt-extension/push-plan/<step>.json  ->  [{device, commands}]
Usage:  python tools/pt-extension/make_push_plan.py
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CFG = ROOT / "configs"
OUT = Path(__file__).resolve().parent / "push-plan"
SKIP = {"enable", "configure terminal", "end", "write memory"}
TRIGGER = re.compile(r"^(no )?shutdown$|^crypto key generate")
MAX_LINES = 30

STEPS = {
    "D0": [(f"D0-flat/{d}.txt", d) for d in
           ("ISP-RTR", "EDGE-RTR", "CORE-MLS", "SW-WARD-A", "SW-WARD-B", "SW-ADMIN", "SW-SRV")],
    # step: list of (source file, device) in push order
    "D1": [("transitions/D0-to-D1.txt", None)]
          + [(f"D1-vlan/{d}.txt", d) for d in ("CORE-MLS", "SW-WARD-A", "SW-WARD-B", "SW-ADMIN")],
    "D2": [("D2-zone-acl/CORE-MLS.txt", "CORE-MLS")],
    "D3": [("transitions/D2-to-D3.txt", None)]
          + [(f"D3-microseg/{d}.txt", d) for d in
             ("EDGE-RTR", "CORE-MLS", "ASA-SRV", "SW-WARD-A", "SW-WARD-B", "SW-ADMIN")],
}


def blocks(lines):
    """Group a top-level command with its indented sub-commands."""
    cur = []
    for ln in lines:
        if not ln.startswith(" ") and cur:
            yield cur
            cur = []
        cur.append(ln)
    if cur:
        yield cur


def chunk(device, text):
    lines = [l.rstrip() for l in text.splitlines()
             if l.strip() and not l.strip().startswith("!") and l.strip() not in SKIP]
    out, cur = [], []
    for b in blocks(lines):
        if cur and len(cur) + len(b) > MAX_LINES:
            out.append(cur)
            cur = []
        cur.extend(b)
        if any(TRIGGER.match(l.strip()) for l in b):
            out.append(cur)
            cur = []
    if cur:
        out.append(cur)
    return [{"device": device, "commands": "\n".join(c)} for c in out]


def split_transition(text):
    """Transition files mark device sections with '!@DEVICE'."""
    parts, dev, buf = [], None, []
    for ln in text.splitlines():
        if ln.startswith("!@"):
            if dev and buf:
                parts.append((dev, "\n".join(buf)))
            dev, buf = ln[2:].strip(), []
        elif dev:
            buf.append(ln)
    if dev and buf:
        parts.append((dev, "\n".join(buf)))
    return parts


def main():
    OUT.mkdir(exist_ok=True)
    for step, items in STEPS.items():
        plan = []
        for rel, device in items:
            text = (CFG / rel).read_text(encoding="utf-8")
            if device is None:
                for dev, body in split_transition(text):
                    plan += chunk(dev, body)
            else:
                plan += chunk(device, text)
        (OUT / f"{step}.json").write_text(json.dumps(plan, indent=1), encoding="utf-8")
        per = {}
        for p in plan:
            per[p["device"]] = per.get(p["device"], 0) + 1
        print(step, len(plan), "pushes", per)


if __name__ == "__main__":
    main()
