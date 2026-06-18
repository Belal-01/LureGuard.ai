# Auto-triage (event-triggered)

Read `skills/triage.md` and `skills/_shared.md`.

An automated Wazuh alert fired at level >= AUTO_TRIAGE_LEVEL. Triage the triggering event:

1. `open_investigation(subject="Auto-triage <src_ip>", trigger="wazuh_event", detection_source="wazuh")`
2. `get_soc_health()`
3. `get_ip_context(src_ip)` — mandatory
4. `get_attack_summary(src_ip)`
5. `get_event_timeline(src_ip, window_hours=24)`
6. `record_finding` with verdict, MITRE, priority
7. `close_investigation` with kill_chain_summary
8. If true_positive P1/P2: `recommend_block_ip` + `notify_telegram`
