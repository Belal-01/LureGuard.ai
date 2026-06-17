# Mode: incident-report — Write formal incident report

## Purpose

Produce a standards-structured incident report (hybrid NIST / PICERL / MITRE) saved to `reports/` and Postgres. Must be **self-contained** for Telegram/management (key metrics + narrative) — see report-vs-dashboard rules in `_shared.md`.

## Workflow

1. Ensure investigation is open (`open_investigation` with `detection_source`, `asset_criticality`, `severity`)
2. Gather evidence using tools — do not invent
3. For each conclusion:
   - `record_finding(finding, citation, mitre_technique=, mitre_tactic=, severity=, ioc_type=, ioc_value=)`
   - `add_timeline_event(description, ts_event, phase=, source=)` for key events
4. Enrich external indicators (IP, URL, domain, hash) before recording IOC findings
5. `get_investigation_artifacts` — verify structured rows before drafting
6. Draft report using template in `_shared.md`; self-score rubric (target ≥14/16)
7. `close_investigation(verdict, confidence, summary, mttd_seconds=, kill_chain_summary=)`
8. `save_report(title="...", markdown="...")` — auto PNG charts in Visual summary; optional `generate_report_chart` for extras
9. If user wants delivery: `send_report_to_telegram(file_path="reports/....md")` or `save_report(..., send_telegram=true)` — **always PDF**
10. If user asks for a PDF file on disk: `save_report(..., as_pdf=true)` or `convert_report_to_pdf`

## Output format

Full markdown per `_shared.md` template. Every evidence bullet must map to a `record_finding` evidence ID (E01, E02…).

## Quality bar

- Executive summary: causal narrative in 30 seconds
- **Key metrics snapshot:** alert/event counts, affected host count, CVE exposure on affected host if relevant — reader must not need Grafana
- Timeline: UTC from `get_event_timeline` / `add_timeline_event`
- MITRE: technique + tactic + evidence ID + confidence
- IOCs: defanged via `defang_ioc` or tool output
- Recommended actions: advisory, prioritized, with owner/SLA
- Dashboards section: optional deep-link for operators; not a substitute for metrics in the body
