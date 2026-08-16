"""Build core/attack_map.json — rule -> MITRE ATT&CK (register item ML-4).

Scope is deliberate: only rules whose groups intersect `_FORWARD_GROUPS` in
wazuh/integrations/custom-lureguard.py. A rule outside those groups never
reaches this product, so mapping it would claim coverage that does not exist.

Two provenances, kept distinct because their confidence differs:
  wazuh     — read from the running manager's own <mitre> blocks
  lureguard — assigned by hand for local_rules.xml, which has no <mitre> data

Usage:  python3 scripts/build_attack_map.py
Needs the wazuh-manager container running.
"""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys
from collections import Counter

REPO = pathlib.Path(__file__).resolve().parents[1]
OUT = REPO / "core" / "attack_map.json"

# Custom rules carry no <mitre> block; these are our assignments.
CUSTOM = {
    "100001": (["T1110"], 8, ["cowrie", "authentication_failed", "lureguard_custom"],
               "Cowrie: failed login on honeypot"),
    "100002": (["T1078"], 10, ["cowrie", "authentication_success", "lureguard_custom"],
               "Cowrie: successful login to honeypot"),
    "100003": (["T1059"], 12, ["cowrie", "lureguard_custom"],
               "Cowrie: command executed in honeypot"),
    "100010": (["T1190", "T1083"], 10, ["web", "web-attack", "sql_injection", "lureguard_custom"],
               "LureGuard: SQLi or path traversal probe"),
    "100011": (["T1059.007"], 8, ["web", "web-attack", "xss", "lureguard_custom"],
               "LureGuard: XSS probe in web request"),
    "100012": (["T1595.002"], 7, ["web", "scanner", "web-attack", "lureguard_custom"],
               "LureGuard: web scanner signature"),
    # ML-5 post-compromise rules. Each is mapped to the tactic the *observed
    # signal* belongs to, not every tactic ATT&CK lists for the technique —
    # a cron file appearing is persistence here, whatever else T1053 can be.
    "100020": (["T1098.004"], 12, ["syscheck", "lureguard_custom"],
               "LureGuard: SSH authorized_keys changed"),
    "100021": (["T1053.003"], 12, ["syscheck", "lureguard_custom"],
               "LureGuard: cron entry added or changed"),
    "100022": (["T1543.002"], 12, ["syscheck", "lureguard_custom"],
               "LureGuard: systemd unit added or changed"),
    "100023": (["T1548.003"], 12, ["syscheck", "lureguard_custom"],
               "LureGuard: sudoers changed"),
    "100024": (["T1548.003"], 10, ["lureguard_custom"],
               "LureGuard: sudo shell escape to root"),
    "100030": (["T1082", "T1033"], 12, ["cowrie", "lureguard_custom"],
               "LureGuard: discovery commands in honeypot session"),
    "100031": (["T1105"], 13, ["cowrie", "lureguard_custom"],
               "LureGuard: payload download in honeypot session"),
    "100032": (["T1070.003"], 12, ["cowrie", "lureguard_custom"],
               "LureGuard: history or log tampering in honeypot session"),
}

TACTIC = {
    "T1110": "credential-access", "T1212": "credential-access", "T1555": "credential-access",
    "T1078": "initial-access", "T1133": "initial-access", "T1190": "initial-access",
    "T1195": "initial-access", "T1566": "initial-access",
    "T1059": "execution", "T1203": "execution", "T1072": "execution", "T1053": "execution",
    # Sub-technique overrides win over the base id (see tactic_for): a cron job
    # planted by an intruder is persistence, even though T1053 defaults to execution.
    "T1053.003": "persistence",
    "T1595": "reconnaissance", "T1592": "reconnaissance", "T1590": "reconnaissance",
    "T1046": "discovery", "T1083": "discovery", "T1018": "discovery", "T1082": "discovery",
    "T1057": "discovery", "T1518": "discovery", "T1033": "discovery", "T1016": "discovery",
    "T1497": "defense-evasion", "T1014": "defense-evasion", "T1070": "defense-evasion",
    "T1112": "defense-evasion", "T1562": "defense-evasion", "T1222": "defense-evasion",
    "T1027": "defense-evasion", "T1036": "defense-evasion", "T1553": "defense-evasion",
    "T1068": "privilege-escalation", "T1055": "privilege-escalation", "T1548": "privilege-escalation",
    "T1543": "persistence", "T1136": "persistence", "T1505": "persistence",
    "T1098": "persistence", "T1547": "persistence", "T1546": "persistence",
    "T1021": "lateral-movement", "T1210": "lateral-movement", "T1563": "lateral-movement",
    "T1550": "lateral-movement", "T1570": "lateral-movement",
    "T1499": "impact", "T1498": "impact", "T1486": "impact", "T1489": "impact",
    "T1531": "impact", "T1485": "impact", "T1529": "impact", "T1561": "impact", "T1565": "impact",
    "T1005": "collection", "T1119": "collection", "T1114": "collection", "T1056": "collection",
    "T1041": "exfiltration", "T1048": "exfiltration",
    "T1071": "command-and-control", "T1571": "command-and-control", "T1105": "command-and-control",
    "T1219": "command-and-control", "T1090": "command-and-control", "T1102": "command-and-control",
    "T1588": "resource-development", "T1583": "resource-development", "T1587": "resource-development",
}


def forward_groups() -> set[str]:
    src = (REPO / "wazuh/integrations/custom-lureguard.py").read_text()
    block = re.search(r"_FORWARD_GROUPS = frozenset\((.*?)\)", src, re.S)
    return set(re.findall(r'"([a-z_\-0-9]+)"', block.group(1)))


def wazuh_rules_xml() -> str:
    r = subprocess.run(
        ["docker", "exec", "wazuh-manager", "sh", "-c",
         "cd /var/ossec/ruleset/rules && cat *.xml"],
        capture_output=True, text=True, errors="replace")
    if r.returncode != 0 or not r.stdout.strip():
        sys.exit("wazuh-manager not reachable — start the stack, or this would "
                 "silently produce an empty map.")
    return r.stdout


def tactic_for(tech: str) -> str | None:
    return TACTIC.get(tech) or TACTIC.get(tech.split(".")[0])


def main() -> None:
    fwd = forward_groups()
    raw = wazuh_rules_xml()
    rules: dict[str, dict] = {}
    no_mitre = 0

    for gm in re.finditer(r'<group\s+name="([^"]+)"\s*>(.*?)</group>\s*(?=<group|\Z)', raw, re.S):
        outer = {g.strip() for g in gm.group(1).split(",") if g.strip()}
        for rm in re.finditer(r'<rule\s+id="(\d+)"[^>]*level="(\d+)"[^>]*>(.*?)</rule>',
                              gm.group(2), re.S):
            rid, level, body = rm.group(1), int(rm.group(2)), rm.group(3)
            inner: set[str] = set()
            for g in re.findall(r"<group>([^<]*)</group>", body):
                inner |= {x.strip() for x in g.split(",") if x.strip()}
            groups = outer | inner
            if not (groups & fwd):
                continue
            tech = re.findall(r"<id>\s*(T\d{4}(?:\.\d{3})?)\s*</id>", body)
            if not tech:
                no_mitre += 1
                continue
            d = re.search(r"<description>(.*?)</description>", body, re.S)
            rules[rid] = {
                "techniques": sorted(set(tech)), "level": level,
                "groups": sorted(groups & fwd),
                "description": re.sub(r"\s+", " ", d.group(1)).strip()[:110] if d else "",
                "source": "wazuh",
            }

    for rid, (tech, lvl, groups, desc) in CUSTOM.items():
        rules[rid] = {"techniques": tech, "level": lvl, "groups": groups,
                      "description": desc, "source": "lureguard"}

    unmapped: set[str] = set()
    for v in rules.values():
        v["attack"] = []
        for t in v.pop("techniques"):
            tac = tactic_for(t)
            if not tac:
                unmapped.add(t)
            v["attack"].append({"technique": t, "tactic": tac or "unmapped"})

    OUT.write_text(json.dumps({
        "_meta": {
            "purpose": "Rule -> MITRE ATT&CK for rules this product actually ingests (ML-4).",
            "scope": "Only rules whose groups intersect _FORWARD_GROUPS; a rule outside "
                     "those never reaches LureGuard, so mapping it would overstate coverage.",
            "source_wazuh": "the running manager's own <mitre> blocks",
            "source_lureguard": "hand-assigned for local_rules.xml (no <mitre> data) — lower confidence",
            "regenerate": "python3 scripts/build_attack_map.py",
            "rules_in_scope_without_mitre": no_mitre,
        },
        "rules": rules,
    }, indent=2, sort_keys=True) + "\n")

    src = Counter(v["source"] for v in rules.values())
    tac = Counter(a["tactic"] for v in rules.values() for a in v["attack"])
    print(f"mapped {len(rules)} rules {dict(src)} -> {OUT.relative_to(REPO)}")
    print(f"in scope but carrying no ATT&CK metadata: {no_mitre}")
    if unmapped:
        print(f"techniques with no tactic in TACTIC: {sorted(unmapped)}")
    print("tactics:", ", ".join(f"{k}={v}" for k, v in tac.most_common()))


if __name__ == "__main__":
    main()
