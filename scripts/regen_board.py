"""Regenerate the register board + header counts from the item tables.
Single source of truth = the tables. Run after editing any item row."""
import re, pathlib, subprocess
from collections import Counter, defaultdict

P = pathlib.Path('docs/CHANGE-REGISTER.md')
s = P.read_text()

rows = re.findall(r'^\| ([A-Z]{2,4}-\d+) \| ([^|]+?) \| (.+?) \|\s*$', s, re.M)
sev, title = {}, {}
for rid, sv, body in rows:
    # "Reversed" is a closed state, not outstanding work: the item was resolved
    # by withdrawing an earlier fix whose premise no longer held, the reasoning
    # is on the card, and an acceptance check defends the replacement. Without
    # this it would sit in Ready forever, reading as something nobody started.
    sev[rid] = ('fixed' if ('Fixed' in sv or 'Reversed' in sv)
                else 'crit' if 'Critical' in sv
                else 'high' if 'High' in sv else 'med')
    m = re.match(r'\*\*(.+?)\*\*', body)
    t = (m.group(1) if m else body).rstrip('. ')
    title[rid] = re.sub(r'`([^`]*)`', r'\1', t)[:78]

# Which items have an executable acceptance check, by id, from the test file.
checks = set()
for m in re.finditer(r'def test_([a-z]+)_(\d+)_', pathlib.Path('tests/acceptance/test_register.py').read_text()):
    checks.add(f"{m.group(1).upper()}-{m.group(2)}")

# Lane assignment.
#
# BLOCKS maps item -> the item it waits on, by ID rather than by prose, so a
# blocker that gets fixed automatically releases whatever was waiting on it.
# The previous hardcoded list went stale the moment GFA-5, INS-2 and ML-4
# landed and left six items showing as blocked when they were free.
BLOCKS = {"GFA-1": "GFA-5", "SEC-4": "ARC-6", "STO-3": "STO-7",
          "GFA-6": "GFA-5", "GFA-7": "ML-4", "GFA-8": "GFA-5",
          "SKL-3": "SKL-1", "ING-3": "ING-8", "ARC-1": "ING-8",
          # POS-1 is not parked by choice — it cannot close without the demo
          # path, which is. Recording it as blocked rather than deferred keeps
          # the distinction between "we chose to wait" and "we are waiting".
          "POS-1": "INS-1",
          # ML-1 and ML-2 are one problem. Retraining while the behavioural
          # features are still discarded would just re-fit Wazuh's own rule_id,
          # which is the leak ML-1 describes.
          "ML-1": "ML-2"}

# Explicitly parked. Not blocked and not forgotten — deprioritised on purpose,
# with the reason recorded so "last" does not quietly become "never".
DEFERRED = {
    "ING-8": "owned by a separate session",
    "ML-2":  "needs a deliberate training-data decision; a rushed pass would "
             "just rebuild ML-1's leak",
    "INS-1": "demo path parked on request",
    "INS-4": "demo path parked on request",
    "INS-5": "demo path parked on request",
    "INS-6": "demo path parked on request",
}
SPRINT: list[str] = []
c = Counter(sev.values())
openids = [r for r in sev if sev[r] != 'fixed']
rank = {'crit': 0, 'high': 1, 'med': 2}

def blocked_by(r):
    """The unmet blocker for r, or None once that blocker is fixed/absent."""
    b = BLOCKS.get(r)
    if not b or sev.get(b) == 'fixed':
        return None
    return b

BLOCKED = {r: blocked_by(r) for r in openids if blocked_by(r)}
lanes = {
 "Deferred": sorted([r for r in openids if r in DEFERRED], key=lambda r: (rank[sev[r]], r)),
 "Ready":    sorted([r for r in openids if r not in DEFERRED and r not in BLOCKED],
                    key=lambda r: (rank[sev[r]], r)),
 "Blocked":  sorted([r for r in openids if r not in DEFERRED and r in BLOCKED],
                    key=lambda r: (rank[sev[r]], r)),
 "Verified": sorted([r for r in sev if sev[r] == 'fixed']),
}
NOTE = {
 "Deferred":"Parked deliberately, last in priority. The reason is recorded on each card so this does not decay into 'never'.",
 "Ready":"Scoped and unblocked. Each needs an acceptance check written before it is safe to delegate.",
 "Blocked":"Waiting on another item. Blockers resolve by ID, so a card leaves this lane the moment its blocker is fixed.",
 "Verified":"Check passes and the diff was reviewed.",
}
E = {"crit":"🔴","high":"🟠","med":"🟡","fixed":"✅"}
out = ["## Board\n",
 f"Generated from the item tables by `scripts/regen_board.py` — it cannot drift from them. "
 f"{len(checks)} items carry an executable acceptance check (`make check`).\n"]
for lane, ids in lanes.items():
    out += [f"### {lane} · {len(ids)}\n", f"_{NOTE[lane]}_\n"]
    for r in ids:
        if r in DEFERRED and sev[r] != 'fixed':
            w = f" — _deferred: {DEFERRED[r]}_"
        elif r in BLOCKED:
            b = BLOCKED[r]
            tag = f"{b} (deferred)" if b in DEFERRED else b
            w = f" — _waits on {tag}_"  
        else:
            w = ""
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
