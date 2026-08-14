"""Regenerate the register board + header counts from the item tables.
Single source of truth = the tables. Run after editing any item row."""
import re, pathlib, subprocess
from collections import Counter, defaultdict

P = pathlib.Path('docs/CHANGE-REGISTER.md')
s = P.read_text()

rows = re.findall(r'^\| ([A-Z]{2,4}-\d+) \| ([^|]+?) \| (.+?) \|\s*$', s, re.M)
sev, title = {}, {}
for rid, sv, body in rows:
    sev[rid] = ('fixed' if 'Fixed' in sv else 'crit' if 'Critical' in sv
                else 'high' if 'High' in sv else 'med')
    m = re.match(r'\*\*(.+?)\*\*', body)
    t = (m.group(1) if m else body).rstrip('. ')
    title[rid] = re.sub(r'`([^`]*)`', r'\1', t)[:78]

# Which items have an executable acceptance check, by id, from the test file.
checks = set()
for m in re.finditer(r'def test_([a-z]+)_(\d+)_', pathlib.Path('tests/acceptance/test_register.py').read_text()):
    checks.add(f"{m.group(1).upper()}-{m.group(2)}")

# Lane assignment. Blocked = waiting on another ITEM (not a decision).
BLOCKED = {"GFA-1":"GFA-5 rollout","POS-1":"INS-2 rollout","SEC-4":"ARC-6 rollout",
           "STO-3":"STO-7 rollout","GFA-6":"GFA-5 rollout","GFA-7":"ML-4 (ATT&CK mapping)",
           "GFA-8":"GFA-5 rollout","INS-6":"INS-2 rollout","SKL-3":"SKL-1 contract",
           "ING-3":"ING-8 fix","ARC-1":"ING-8 fix"}
SPRINT = ["ING-8"]
c = Counter(sev.values())
openids = [r for r in sev if sev[r] != 'fixed']
lanes = {
 "Sprint 3": [r for r in openids if r in SPRINT],
 "Ready":    sorted([r for r in openids if r not in SPRINT and r not in BLOCKED],
                    key=lambda r: ({'crit':0,'high':1,'med':2}[sev[r]], r)),
 "Blocked":  sorted([r for r in openids if r in BLOCKED],
                    key=lambda r: ({'crit':0,'high':1,'med':2}[sev[r]], r)),
 "Verified": sorted([r for r in sev if sev[r] == 'fixed']),
}
NOTE = {
 "Sprint 3":"One item. It blocks two others and is the only failing acceptance check — a second session is on it.",
 "Ready":"Scoped and unblocked. Each needs an acceptance check written before it is safe to delegate.",
 "Blocked":"Waiting on another item, not on a decision.",
 "Verified":"Check passes and the diff was reviewed.",
}
E = {"crit":"🔴","high":"🟠","med":"🟡","fixed":"✅"}
out = ["## Board\n",
 f"Generated from the item tables by `scripts/regen_board.py` — it cannot drift from them. "
 f"{len(checks)} items carry an executable acceptance check (`make check`).\n"]
for lane, ids in lanes.items():
    out += [f"### {lane} · {len(ids)}\n", f"_{NOTE[lane]}_\n"]
    for r in ids:
        w = f" — _waits on {BLOCKED[r]}_" if r in BLOCKED else ""
        chk = " ·  ✓check" if r in checks else ""
        out.append(f"- {E[sev[r]]} **{r}** {title[r]}{chk}{w}")
    out.append("")
board = "\n".join(out) + "\n---\n"

s = re.sub(r'^## Board\n.*?^---\n', board, s, flags=re.M | re.S, count=1)
s = re.sub(r'\*\*\d+ items — .*?\*\*',
           f"**{len(rows)} items — {c['crit']} critical · {c['high']} high · {c['med']} medium · {c['fixed']} fixed**",
           s, count=1)
s = re.sub(r'^\w+ items have executable acceptance checks.*$',
           f"{len(checks)} items have executable acceptance checks in `tests/acceptance/test_register.py`. Run them with `make check`. They are *expected to fail* until the item is fixed — a failure there is an open register item, not broken code.",
           s, flags=re.M, count=1)
P.write_text(s)
print(f"{len(rows)} items | {dict(c)} | checks: {len(checks)}")
for k, v in lanes.items(): print(f"  {k:9} {len(v)}")
