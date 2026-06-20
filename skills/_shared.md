# LureGuard — Shared analyst playbook

Load this file with every investigation mode.

## Report vs Grafana (mandatory)

Reports are often sent to **management or Telegram** — readers will **not** open Grafana or attach dashboard screenshots. The report must be **self-contained**: include the numbers that matter, plus analyst interpretation.

| Audience | What they need in the report |
|----------|------------------------------|
| Management / Telegram | Headline metrics, top risks, verdict, actions — readable without Grafana |
| Operator / analyst | Same report + optional Grafana deep-link for drill-down |

**Include in every report (when relevant):**
- **Key metrics snapshot** — summarized counts from tools: alert volume (24h), open investigations, fleet health (active/disconnected), CVE headline (critical/high counts + top 3–5 actionable CVEs), exposure headline
- **Analyst narrative** — causality, verdict reasoning, kill-chain, MITRE with evidence IDs, impact, prioritized actions, detection gaps

**Do NOT paste full Grafana tables:**
- Every agent row (fleet inventory dump)
- Every CVE row (use top prioritized actionable CVEs; posture skill caps at 10)
- Raw event volume tables with no interpretation

Grafana is for **live drill-down**; the report carries the **executive snapshot + story**. Always add a **Dashboards** line with `http://localhost:3000` for operators who want more — but never use that link as a substitute for key numbers in the body.

## Container / web-app CVE scope (know the limits)

LureGuard posture today covers **six pillars** on enrolled hosts: OS package CVEs (OSV + EPSS + EOL boost), port exposure, detection coverage, **SCA/CIS compliance**, **local user inventory**, and **container runtime + image CVEs**.

LureGuard CVE scanning uses **Wazuh syscollector packages on the enrolled host** (OS packages via OSV.dev) — e.g. `docker.io`, `containerd`, `nginx`, `openssl` on the **VM/node**.

**EOL OS:** `get_posture_snapshot` includes `eol_os: true` when the OS is past standard support — boost critical CVE priority and recommend upgrade.

**Not scanned automatically today (gaps):**
- npm/Next.js dependencies **inside** a Docker image — use `get_agent_container_posture` or `get_posture_snapshot` (containers pillar); queue `trigger_posture_scan` if cache is empty
- `privileged: true`, `--cap-add`, or `/var/run/docker.sock` mounts (no dedicated check yet)
- Container-escape blast radius scoring (app RCE → container root → host root)

**ML scope honesty:** the shipped classifier scores **SSH auth events only** (honeypot redirect). LLM/MCP tools handle triage, investigation, and reporting for all other channels.

**What you can still report for a Dockerized Next.js app (from cache, no auto-scan):**
- Host/node CVEs: dockerd, kernel, exposed ports (`get_agent_exposure`)
- Web attack events if ingested (`analyze_web_attack`, `investigate-web.md`)
- **Call out the gap** in reports when image scan was not run: "Container image dependencies not inventoried — run `trigger_posture_scan` for Trivy/npm CVEs; if container runs as root + privileged, host compromise risk is elevated."

**Fresh CVE index:** only when user explicitly asks → `skills/refresh-posture.md` (`trigger_posture_scan`). Routine posture uses cache.

| Grafana dashboard | Typical snapshot to pull into report |
|-------------------|--------------------------------------|
| LureGuard SOC Overview | alert count 24h, top 3 source IPs, notable channels |
| LureGuard Security Posture | critical/high CVE counts, top actionable CVEs, risky ports headline |
| LureGuard Fleet and Hosts | N active / N disconnected / N never_connected |
| LureGuard Agent Activity | open investigations, verdict mix, top MITRE technique |

## Triage matrix (Tier-1 replacement)

| Alert confidence | Asset criticality | Action | SLA |
|------------------|-------------------|--------|-----|
| High | Critical | Escalate human P1 | 15 min |
| High | High | Investigate priority | 30 min |
| High | Medium/Low | Standard queue | 1–4 h |
| Medium | Critical/High | Investigate | 30 min–2 h |
| Medium | Low | Watch / batch close | 8 h |
| Low | Any | Close with note | 24 h |

**Verdicts:** `true_positive` | `false_positive` | `undetermined`  
**Confidence:** `confirmed` | `high` | `medium` | `low`  
**Severity:** P1 (breach) → P4 (informational)

## Asset criticality (default rules)

| Signal | Criticality |
|--------|-------------|
| K8s control plane, domain controller, payment/DB | critical |
| Production web/app server (apache/nginx), enrolled agent with alerts | high |
| Worker node, dev VM | medium |
| Honeypot (cowrie), lab, disconnected host | low |

Set via `set_host_criticality(agent_id, ...)` or `open_investigation(asset_criticality=...)` and refine with `get_agent_detail`.

**Priority:** check `list_enrolled_hosts` → `criticality` column before applying keyword heuristics below.

## Post-investigation containment (advisory)

After `close_investigation` with verdict `true_positive` and severity P1/P2:

1. `recommend_block_ip(ip, reason, investigation_id)` — writes pending blocklist entry
2. Human runs `confirm_block_ip(block_id)` — applies iptables DROP on **hosts with evidence** for that IP (last 48h)
3. If scope is unclear, `confirm_block_ip` returns `needs_scope` — pass `agent_id='007'` or `fleet_wide=true` with notes explaining why
4. Optionally `notify_telegram` with summary + `confirm_block_ip(block_id='...')` for the operator

**Whitelist (trusted SSH sources — ML skips alert/redirect):**

1. `recommend_whitelist_ip(ip, reason, investigation_id)` — writes pending whitelist entry
2. Human runs `confirm_whitelist_ip(whitelist_id)` — activates entry; Core picks up on next tick (~2s)
3. `list_whitelist(pending_only=true)` / `remove_whitelist_ip(whitelist_id=…)` as needed (remove is human-gated like confirm)

For blocks, also `notify_telegram` with summary + `confirm_block_ip(block_id='...')` for the human operator.
**Never** call `confirm_block_ip`, `confirm_whitelist_ip`, or `remove_whitelist_ip` autonomously — human must confirm in chat first.

## NIST IR lifecycle (advisory — human executes containment)

| Phase | PICERL | Agent role |
|-------|--------|------------|
| Detection & Analysis | Identification | Pull events, enrich IOCs, timeline, MITRE |
| Containment | Containment | Recommend only; never block/isolate |
| Eradication | Eradication | Document in report |
| Recovery | Recovery | Document in report |
| Post-incident | Lessons Learned | Detection gaps + `save_report` |

## MITRE ATT&CK

Map only when evidence supports it. Use `record_finding(..., mitre_technique="T1110", mitre_tactic="Credential Access")`. For technique hints before mapping, call `rag_lookup("brute force ssh")` — keyword retrieval over local MITRE hints + skills (not a vector DB).

Common mappings:
- SSH brute force → T1110.001
- Web exploit / scanner → T1190
- Valid account abuse → T1078
- Recon scan UA → T1595

If unsure: note "possible T1110" with `confidence=low`.

## Confidence rubric

| Level | When to use |
|-------|-------------|
| confirmed | Multiple independent tools agree; direct artifact |
| high | Strong single-source evidence + context |
| medium | Pattern match or partial enrichment |
| low | Thin data, single event, no enrichment |

## Incident report template (hybrid NIST / PICERL / ISO 27035)

```markdown
# Incident Report: [TITLE]

**Classification:** INTERNAL  
**Investigation ID:** [from open_investigation]  
**Detection source:** wazuh | human | scheduled  
**Asset criticality:** critical | high | medium | low  
**Severity:** P1–P4  
**Verdict:** true_positive | false_positive | undetermined  
**Confidence:** confirmed | high | medium | low  
**MTTD:** [seconds or human-readable, from first event to investigation open]  
**Report date (UTC):** [now]  
**PICERL phase at close:** Lessons Learned

## Executive summary
[2–3 plain-language sentences for a developer or manager — what happened, impact, current status]

## Key metrics snapshot
[Self-contained numbers from tools — reader must not need Grafana to understand scale/risk]
- Alerts (24h): [N] — source: get_recent_alerts / get_soc_health
- Fleet: [N] active, [N] disconnected, [N] never_connected — source: list_agents
- CVEs (if relevant): [N] critical, [N] high; top: CVE-XXXX on [host] — source: get_fleet_vulnerability_summary
- Open investigations: [N] — source: Agent Activity / investigations

## Visual summary
[`save_report` auto-appends PNG charts here when data exists — do not use HTML charts. Optional: `generate_report_chart` / `generate_report_chart_preset` for extra images before save.]

## Dashboards (optional drill-down for operators)
- SOC Overview, Posture, Fleet, Agent Activity → http://localhost:3000

## Kill-chain timeline
| Time (UTC) | Phase | Event | Evidence ID | Source |
|------------|-------|-------|-------------|--------|
| | identification | | E01 | get_event_timeline |

Populate via `add_timeline_event` during investigation; mirror here at report time.

## Evidence (citations required)
| ID | Finding | Citation |
|----|---------|----------|
| E01 | [finding] | [tool + key fields] |

Every row must map to `record_finding` in this session.

## MITRE ATT&CK
| Technique | Tactic | Evidence | Confidence |
|-----------|--------|----------|------------|
| T1110.001 | Credential Access | E01 | high |

## Impact assessment
- **Affected hosts:**
- **Data at risk:**
- **Business impact:** [downtime, exposure scope]
- **Why this asset matters:** [criticality reasoning]

## IOC table
| Type | Value (defanged) | Reputation | Source |
|------|------------------|------------|--------|
| ip | 203[.]0[.]113[.]99 | malicious (VT: N) | check_ip_virustotal |

Use `defang_ioc` before publishing. Omit section if no IOCs checked.

## Recommended actions (human executes)
| Priority | Action | Owner | SLA |
|----------|--------|-------|-----|
| P2 | Review firewall for 203.0.113.99 | operator | 24h |

## Escalation
- **Escalate to Tier II/III if:** [conditions]
- **Current status:** advisory only — no containment executed by agent

## Detection gaps & lessons learned
- [What rules/thresholds missed or delayed detection]
- [What to tune in Wazuh / Grafana]

## NIST close-out
- **Containment:** [recommended, not executed]
- **Eradication:** [recommended]
- **Recovery:** [recommended]
```

## Report quality rubric (self-score before save_report)

Score each 0–2 (0=missing, 1=partial, 2=complete). Target **≥14/16** for incident reports.

| # | Criterion |
|---|-----------|
| 1 | Header block complete (ID, detection source, severity, verdict, confidence, MTTD) |
| 2 | Executive summary is causal; key metrics snapshot present for standalone readers |
| 3 | Timeline has UTC timestamps from tools |
| 4 | Every finding has evidence ID ↔ citation |
| 5 | MITRE mapped with confidence |
| 6 | Impact explains asset criticality |
| 7 | IOCs defanged + reputation cited |
| 8 | Recommended actions prioritized with owner/SLA |

## Tools reference

| Need | Tool |
|------|------|
| Recent alerts | `get_recent_alerts` |
| Ingestion health | `get_soc_health` |
| IP history | `get_alerts_for_ip`, `get_event_timeline`, `get_attack_summary` |
| Filter search | `search_events` |
| IP context (mandatory) | `get_ip_context` |
| IP reputation (legacy) | `check_ip_reputation`, `check_ip_virustotal` |
| URL/domain reputation | `check_url_virustotal`, `check_domain_virustotal`, `check_url_urlhaus` |
| Web attack classify | `analyze_web_attack` |
| Hash check | `check_hash` |
| Defang IOC | `defang_ioc` |
| Host inventory | `get_agent_detail`, `list_agents` |
| Posture snapshot | `get_posture_snapshot` (6 pillars: CVE, exposure, detection, SCA, users, containers) |
| SCA / CIS | `get_agent_sca_summary`, `get_fleet_sca_summary` |
| User inventory | `get_agent_users` |
| Rescan posture | `trigger_posture_scan` (`force=true` when user asks refresh) |
| Structured artifacts | `get_investigation_artifacts` |
| Timeline row | `add_timeline_event` |
| Audit trail | `record_finding`, `close_investigation` |
| Custom chart PNG | `generate_report_chart`, `generate_report_chart_preset` |
| Report file | `save_report` (auto PNG charts; `as_pdf=true` when user asks; `send_telegram=true` sends **PDF**) |
| Report to Telegram | `send_report_to_telegram` — **always PDF**; pass `.md` path; never skip PDF for Telegram |
| Local PDF file | `convert_report_to_pdf` or `save_report(..., as_pdf=true)` — when user asks for a PDF on disk |
| Notify (text) | `notify_telegram` |
| Block IP (advisory) | `recommend_block_ip`, `confirm_block_ip`, `list_blocklist` |
| Whitelist IP (SSH ML) | `recommend_whitelist_ip`, `confirm_whitelist_ip`, `list_whitelist`, `remove_whitelist_ip` |
| Asset criticality | `set_host_criticality` |
| Container CVEs | `get_agent_container_posture`, `get_posture_snapshot` (containers pillar) |
| TLS check | `check_tls` |
