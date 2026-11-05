"""Print a config file as plain IOS commands (no comments, no enable/conf t/end/wr)."""
import sys
SKIP = {"enable", "configure terminal", "end", "write memory"}
for line in open(sys.argv[1], encoding="utf-8").read().splitlines():
    s = line.strip()
    if not s or s.startswith("!") or s in SKIP:
        continue
    print(line.rstrip())
