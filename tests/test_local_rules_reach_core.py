"""Every rule we write must be able to fire, be delivered, and be counted.

Three things have to line up for a custom Wazuh rule to mean anything here:

  1. its groups intersect `_FORWARD_GROUPS` in the integratord script, or
     integratord drops the alert and the detection silently never fires;
  2. it is in core/attack_map.json, or the GFA-7 coverage dashboard cannot
     see it and the technique reads as dark when it is not;
  3. the demo dataset exercises it, or `make demo` shows a blind spot the
     product does not actually have.

Each is invisible when broken — the rule looks fine in the XML. That is the
defect class ML-5 exists to close, so it gets a test rather than a convention.
"""
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RULES = REPO / "wazuh" / "local_rules.xml"


def _local_rules() -> dict[int, set[str]]:
    """rule id -> groups, including the file's outer <group name="...">."""
    xml = RULES.read_text(encoding="utf-8")
    outer = set(re.search(r'<group name="([^"]+)"', xml).group(1).split(",")) - {""}
    rules = {}
    for rid, body in re.findall(r'<rule id="(\d+)"[^>]*>(.*?)</rule>', xml, re.S):
        inner = {g.strip() for tag in re.findall(r"<group>([^<]*)</group>", body)
                 for g in tag.split(",") if g.strip()}
        rules[int(rid)] = outer | inner
    return rules


def _forward_groups() -> set[str]:
    src = (REPO / "wazuh/integrations/custom-lureguard.py").read_text(encoding="utf-8")
    block = re.search(r"_FORWARD_GROUPS = frozenset\((.*?)\)", src, re.S).group(1)
    return set(re.findall(r'"([a-z_\-0-9]+)"', block))


def test_every_local_rule_is_forwarded_to_core():
    forward = _forward_groups()
    orphans = {rid: sorted(g) for rid, g in _local_rules().items() if not (g & forward)}
    assert not orphans, (
        f"rules {sorted(orphans)} are in no forwarded group — integratord will "
        f"drop them and the detection never reaches LureGuard. Add a group from "
        f"_FORWARD_GROUPS to the rule, or the rule's group to _FORWARD_GROUPS "
        f"(and to <integration><group> in wazuh/ossec.conf). Got: {orphans}"
    )


def test_every_local_rule_is_mapped_to_attack():
    mapped = json.loads((REPO / "core/attack_map.json").read_text(encoding="utf-8"))["rules"]
    missing = sorted(rid for rid in _local_rules() if str(rid) not in mapped)
    assert not missing, (
        f"rules {missing} carry no ATT&CK mapping, so the coverage dashboard "
        f"counts their techniques as dark. Add them to CUSTOM in "
        f"scripts/build_attack_map.py and re-run it."
    )


def test_demo_dataset_exercises_every_local_rule():
    import sys

    sys.path[:0] = [str(REPO / "core"), str(REPO)]
    from demo_seed import generate_events

    seeded = {int(r["wazuh_rule_id"]) for r in generate_events(500)}
    missing = sorted(rid for rid in _local_rules() if rid not in seeded)
    assert not missing, (
        f"rules {missing} never appear in the demo dataset, so `make demo` shows "
        f"their techniques as never observed. Add a scenario to core/demo_seed.py."
    )
