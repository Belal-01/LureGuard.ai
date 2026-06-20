# LureGuard — Product Status & Engineering Checklist

**Last updated:** 2026-06-18  
**Purpose:** End-to-end map of what LureGuard is, what it can do, what's built, and what's left — for you (and anyone joining) to see **where we are** and **where we're going**.

**Legend**

| Symbol | Meaning |
|--------|---------|
| ✅ | Done and verified (or code complete + tested in dev) |
| 🟡 | Partial — exists but not proven end-to-end or quality bar not met |
| ⬜ | Not started / not working |
| 🚫 | Explicitly out of scope or cancelled |
| 🔴 | **Blocker** — gates Tier I replacement |

**Overall Tier I analyst replacement:** ~**45% code complete** · **E2E proof pending** (see §0 below)

---

## 0. Verification status (what actually proves it works)

**Legend for this section:** ✅ proven in this environment · 🟡 code + unit tests only · ⬜ not tested yet

| Layer | Status | How to verify |
|-------|--------|---------------|
| Unit / integration tests | ✅ | `make test` → **101 passed** (includes `tests/test_investigation_quality.py`) |
| DB migration `h8i9j0k1l2m3` | 🟡 | `make migrate` then `\d events` shows `wazuh_rule_description`, `geo_country`; `\d blocklist` exists |
| Alert ingestion | ✅ | `get_soc_health()` → `events_24h > 0`, `last_event_at` recent |
| Rich timeline / attack summary | 🟡 | `.venv/bin/python -c "from lureguard_mcp.db import get_event_timeline; ..."` returns geo, duration, phases |
| `get_ip_context` compound enrichment | 🟡 | Returns `internal` for RFC1918; needs VT/AbuseIPDB keys for external IPs |
| ML score in timeline | 🟡 | Only SSH `auth_failed`/`auth_success` rows; requires `decisions.event_id` populated on **new** events after deploy |
| `recommend_block_ip` / `confirm_block_ip` | ⬜ | Not run on lab hosts together — needs explicit human test before trusting iptables |
| `alert_watcher` auto-triage | ⬜ | Starts with MCP server; needs level ≥ 12 event + `opencode` in PATH + Telegram configured |
| Web/docker log coverage | 🟡 | `ossec.conf` groups aligned with `_FORWARD_GROUPS`; custom web rules `100010-100012`; investigate-web uses `channel=docker` — agent restart + lab E2E still pending |
| Container posture (Trivy) | 🟡 | `container_posture.py` + `get_agent_container_posture`; lab proof on agent 007 (3187 CVE rows) |
| `check_tls` / firewall in exposure | ⬜ | Tool exists; not smoke-tested against a live HTTPS endpoint |
| opencode triage → saved report | ⬜ | **Gate B1** — run together before calling Tier I done |
| Grafana new panels | 🟡 | Investigation Console dashboard (`investigation-console.json`) with vars + timeline_events; need reload + populated data |

**What we have not done together yet:** a full investigate → `recommend_block_ip` → human `confirm_block_ip` run, a saved triage report citing `get_ip_context`, or an auto-triage fire from a real level-12 alert.

**Recommended joint test script** (run after `make migrate`):

```bash
make test
make migrate && make doctor

# Ingestion + SLA
.venv/bin/python -c "from lureguard_mcp.db import get_soc_health_db; import json; print(json.dumps(get_soc_health_db(), indent=2))"

# Rich timeline (pick an IP from get_recent_alerts)
.venv/bin/python -c "
from lureguard_mcp.db import get_attack_summary, get_event_timeline
ip = '127.0.0.1'  # replace with src_ip from alerts
import json
print(json.dumps(get_attack_summary(ip), indent=2))
print(json.dumps(get_event_timeline(ip), indent=2)[:2000])
"

# Full agent workflow (you + opencode)
opencode run "Read skills/triage.md and triage alerts from the last 2 hours"
opencode run "Read skills/investigate-host.md and investigate <src_ip>"
```

## Tier 1 investigation quality (2026-06-18 — code landed, E2E pending)

New capabilities added in the investigation quality roadmap. All are **implemented in code**; see §0 for proof status.

| Feature | MCP / code | Skill / config |
|---------|------------|----------------|
| Richer events | `wazuh_rule_description`, geo on `events`; `decisions.event_id` → `ml_score` in queries | — |
| Mandatory enrichment | `get_ip_context` | `skills/triage.md`, `skills/investigate-host.md` |
| Attack narrative | `get_event_timeline`, `get_attack_summary` | `skills/investigate-host.md` |
| IP block path | `recommend_block_ip`, `confirm_block_ip`, `list_blocklist` | `skills/_shared.md` containment section |
| Always-on triage | `lureguard_mcp/alert_watcher.py` | `AUTO_TRIAGE_LEVEL=12`, `.opencode/command/auto-triage.md` |
| Generic log coverage | integratord + `collector.py` web/docker channels | `wazuh/agent-ossec.conf` docker stdout + nginx/apache |
| Container CVEs | `get_agent_container_posture`, `trigger_posture_scan` | `skills/security-posture.md` |
| Asset criticality | `set_host_criticality`, `hosts.criticality` | `onboard_host_tool(..., criticality=)` |
| SLA metrics | `get_soc_health` → `sla.avg_mttd_seconds`, MTTR, FPR | Grafana SOC Overview SLA row |
| TLS + firewall | `check_tls`, `get_agent_exposure` → `firewall_rules` | — |

**New Postgres objects:** `blocklist`, `container_cve_findings`, `watched_events`; columns on `events`, `decisions`, `hosts`.

**Migration:** `migrations/versions/h8i9j0k1l2m3_investigation_quality.py`

---

- [x] **One-liner:** Plug-and-play AI security analyst — `docker compose up -d`, talk in plain language via opencode.
- [x] **Wazuh invisible:** Embedded SIEM engine; user never configures Wazuh directly.
- [x] **Trust posture:** Tier-2 brains, Tier-1 hands — investigate deeply, **recommend only**, human executes containment.
- [x] **Grounding contract:** No conclusion without tool output; every MCP call logged to Postgres.
- [x] **Target user:** Developer who runs servers, not a Tier-3 SOC analyst.
- [x] **Runtime:** opencode + BYO-LLM (not bundled in compose).
- [ ] **Tier III sign-off:** A senior analyst trusts output without re-doing the work.

---

## 2. User use cases → status

What a developer asks for, and whether the product delivers today.

| # | Use case (plain language) | Skill / command | Status | Notes |
|---|---------------------------|-----------------|--------|-------|
| U1 | "Triage alerts from the last hour" | `skills/triage.md` · `/triage` | 🟡 | Skill + MCP + `get_ip_context`; needs proven report on live traffic |
| U2 | "Investigate IP / host / brute force" | `skills/investigate-host.md` · `/investigate` | 🟡 | Rich timeline + attack summary + block recommend path |
| U3 | "Sweep this hash/domain across fleet" | `skills/ioc-sweep.md` | 🟡 | VT/AbuseIPDB MCP tools exist; no sample output |
| U4 | "Write an incident report" | `skills/incident-report.md` · `/report` | 🟡 | `save_report` works; old samples weak on citations |
| U5 | "Protect / onboard this VM" | `skills/onboard-host.md` · `/onboard` | ✅ | Agents 007, 008, 011 enrolled on K8s lab |
| U6 | "What happened today? / shift handover" | `skills/daily-summary.md` | 🟡 | Skill updated; old report didn't prove ingestion |
| U7 | "Security posture / CVEs / open ports" | `skills/security-posture.md` · `/posture` | 🟡 | Pipeline fixed; **regenerate report** post-fix |
| U8 | "Send report to Telegram" | `save_report(..., send_telegram=true)` | ✅ | Sends `.md` only by default |
| U9 | "Auto-investigate when Wazuh fires" | `alert_watcher.py` · level ≥ 12 | 🟡 | Code complete; not E2E proven with opencode |
| U10 | "Block this IP" | `recommend_block_ip` / `confirm_block_ip` | 🟡 | Human-confirmed iptables; not tested on lab hosts together |

---

## 3. End-to-end flows

### 3.1 Flagship demo (onboard → attack → investigate → report)

| Step | What happens | Status | Subtasks |
|------|--------------|--------|----------|
| 1 | User: "protect 192.168.x.x" | ✅ | `onboard_host_tool` · SSH enroll · Wazuh agent active |
| 2 | Attacker hits SSH / honeypot | 🟡 | Cowrie + Wazuh rules exist; lab attack not scripted in docs |
| 3 | Wazuh alert → Core → Postgres | ✅ | Integratord configured; `events_24h > 0` in lab |
| 4 | Agent auto-triage (event trigger) | 🟡 | `alert_watcher.py` at level ≥ 12 |
| 5 | User: "investigate …" via opencode | 🟡 | MCP + skills ready; blocked on step 3 |
| 6 | Enrich IP (AbuseIPDB / VT) | ✅ | MCP tools; keys optional in `.env` |
| 7 | Decoy confirms malicious | 🟡 | Cowrie logs → Wazuh; `check_decoy_contact` not in MCP yet |
| 8 | Grounded report + Telegram | 🟡 | `save_report` + Telegram work; report **quality** not Tier III grade |
| 9 | Grafana shows investigation trail | 🟡 | `agent-activity` dashboard; needs populated investigations |

### 3.2 Daily SOC operator loop

| Step | Status | Subtasks |
|------|--------|----------|
| Check ingestion health | 🟡 | `get_soc_health` ✅ · includes SLA block; triage report not saved yet |
| Pull recent alerts | 🟡 | `get_recent_alerts` ✅ · needs data |
| Triage clusters (TP/FP/P1–P4) | ⬜ | No proven triage report in `reports/` |
| Shift handover summary | 🟡 | `daily-summary` skill ✅ · old sample invalid |
| Escalate P1/P2 to human | 🟡 | Skill rules ✅ · no live examples |

### 3.3 Security posture / patch hygiene loop

| Step | Status | Subtasks |
|------|--------|----------|
| Read cached posture (instant) | ✅ | `get_posture_snapshot` · 6 pillars from Postgres |
| Background refresh (6h) | ✅ | `scan_scheduler` · `trigger_posture_scan` |
| CVE scan (OSV + syscollector) | ✅ | `vuln_scanner.py` · per-agent |
| CVE triage (noise filter) | ✅ | `cve_triage.py` · KEV · patched-version · service-aware |
| Exposure (ports + bind scope) | ✅ | `exposure_scanner.py` · risky vs total listening |
| Detection coverage | ✅ | FIM/rootcheck · rules_firing_count · events_last_at |
| Analyst-quality report | ⬜ | Regenerate after fix; max 10 actionable CVEs |
| Grafana posture dashboard | ✅ | `cve-posture.json` |

---

## 4. Platform layers (engineering checklist)

### 4.1 Appliance & infrastructure (Epic E1)

| Item | Status | Details |
|------|--------|---------|
| `docker compose up -d` stack | ✅ | postgres, core, wazuh-manager, cowrie×2, grafana |
| Postgres on :5433 | ✅ | Events, investigations, posture caches, hosts |
| Wazuh manager 4.14 | ✅ | API :55000 · agents :1514/:1515 |
| Cowrie honeypots (dev + db) | ✅ | :2222 / :2223 · logs into Wazuh |
| Grafana :3000 | ✅ | Provisioned datasources + 4 dashboards |
| `.env` secrets model | ✅ | Telegram, VT, AbuseIPDB, Wazuh API, SSH onboard |
| `make doctor` health checks | ✅ | Docker, Postgres, Wazuh API, MCP import |
| `make migrate` Alembic | ✅ | Through `h8i9j0k1l2m3_investigation_quality` |
| One-liner curl installer | 🚫 | Removed; use Quick start in README |
| README appliance story | 🟡 | Exists; Tier I gate not documented until this file |

### 4.2 Alert ingestion (Epic E1 + **Tier I Gate A** ✅)

| Item | Status | Details |
|------|--------|---------|
| Wazuh integratord hook | 🟡 | `custom-lureguard.py` → `POST /wazuh/event` |
| Core `/wazuh/event` endpoint | ✅ | `core/api/wazuh_endpoint.py` |
| Group filter (sshd, syscheck, rootcheck, cowrie) | ✅ | `wazuh/ossec.conf` + integration script |
| Collector normalization | ✅ | `core/modules/collector.py` · tested |
| Persist to `events` table | ✅ | Code ✅ · lab has events |
| `wazuh_rule_description` + geo on events | ✅ | Migration h8i9j0k1l2m3 |
| `decisions.event_id` → ML score in timeline | ✅ | SSH auth events only |
| Syslog / apache / nginx / docker groups forwarded | ✅ | integratord + agent-ossec.conf |
| Windows events forwarded | ⬜ | No Windows agent in lab |
| Ingestion lag ≤ 5s (SRS) | ⬜ | Not measured |
| Verify: test SSH fail → row in `events` | ✅ | `get_soc_health()` events_24h > 0 |

### 4.3 Core decision pipeline (legacy ML path — parallel to agentic layer)

| Item | Status | Details |
|------|--------|---------|
| SSH ML classifier (allow/alert/redirect) | ✅ | `decision_policy.py` · model in `ml/models/` |
| DNAT redirect to Cowrie | ✅ | `enforcer.py` · NET_ADMIN on core |
| Whitelist cache | ✅ | Postgres + runtime refresh |
| Telegram on alert/redirect | 🟡 | `alerting.py` · depends on events flowing |
| Non-SSH alerts (FIM, rootcheck, cowrie) | 🟡 | Telegram path exists; ingest volume unknown |
| Prometheus `/metrics` | 🟡 | Endpoint exists; not wired in compose |
| Triage ML ranking for agent (E7) | ⬜ | ML scores SSH; not exposed as MCP "rank alerts" |

### 4.4 LureGuard MCP server (Epic E2)

| Item | Status | Details |
|------|--------|---------|
| FastMCP stdio server | ✅ | `lureguard_mcp/server.py` |
| `@audited` → `agent_actions` log | ✅ | Every tool call logged |
| opencode.json integration | ✅ | 180s timeout |
| **Alerts & search** | | |
| └ `get_recent_alerts` | ✅ | |
| └ `get_alerts_for_ip` | ✅ | |
| └ `get_event_timeline` | 🟡 | Rich shape; E2E narrative not saved yet |
| └ `get_attack_summary` | 🟡 | Unit-tested helpers |
| └ `get_ip_context` | 🟡 | Mandatory in skills; external IP needs API keys |
| └ `recommend_block_ip` / `confirm_block_ip` / `list_blocklist` | 🟡 | Not iptables-tested on lab |
| └ `set_host_criticality` | 🟡 | DB + MCP; use during onboard |
| └ `get_agent_container_posture` | 🟡 | Trivy + runtime inventory; lab data on 007 |
| └ `check_tls` | 🟡 | Not smoke-tested |
| └ `search_events` | ✅ | |
| └ `get_soc_health` | ✅ | Ingestion proof for daily summary |
| **Fleet & Wazuh** | | |
| └ `list_agents` | ✅ | |
| └ `get_agent_detail` | ✅ | packages, processes, ports sample |
| └ `get_rules_summary` | ✅ | |
| └ `get_manager_status` | ✅ | |
| └ `restart_agent` | ✅ | Advisory |
| **Posture** | | |
| └ `scan_agent_vulnerabilities` | ✅ | OSV batch (slow) |
| └ `get_agent_vulnerabilities` | ✅ | Actionable-only default |
| └ `get_fleet_vulnerability_summary` | ✅ | |
| └ `get_agent_exposure` / fleet | 🟡 | Includes `firewall_rules` via SSH; not verified |
| └ `get_agent_detection_coverage` / fleet | ✅ | |
| └ `get_posture_snapshot` | ✅ | Instant 6-pillar read |
| └ `get_fleet_posture_summary` | ✅ | |
| └ `trigger_posture_scan` | ✅ | Background job |
| └ `get_posture_scan_status` | ✅ | |
| **Intel** | | |
| └ `check_ip_reputation` (AbuseIPDB) | ✅ | Graceful if no key |
| └ `check_ip_virustotal` | ✅ | |
| └ `check_hash` (VT) | ✅ | |
| **Investigation lifecycle** | | |
| └ `open_investigation` | ✅ | |
| └ `record_finding` | ✅ | |
| └ `close_investigation` | ✅ | |
| **Output** | | |
| └ `save_report` | ✅ | Optional Telegram |
| └ `send_report_to_telegram` | ✅ | `.md` default |
| └ `convert_report_to_pdf` | ✅ | WeasyPrint/xhtml2pdf via `make venv` |
| └ `notify_telegram` | ✅ | Text summary |
| **Onboarding** | | |
| └ `onboard_host_tool` | ✅ | SSH + Wazuh API |
| └ `list_enrolled_hosts` | ✅ | |
| **Not in MCP yet** | | |
| └ `check_decoy_contact` (E6) | ⬜ | |
| └ `enrich` caching layer | ⬜ | Rate-limit cache |
| └ Event-triggered agent invoke | 🟡 | `alert_watcher.py` — not E2E proven |

### 4.5 Agent skills & constitution (Epic E5)

| Skill | Status | Quality bar in skill |
|-------|--------|----------------------|
| `AGENTS.md` | ✅ | Trust rules, mode routing, MCP summary |
| `skills/_shared.md` | ✅ | Triage matrix, IR template, tool ref |
| `skills/triage.md` | 🟡 | Defined · **no proven report** |
| `skills/investigate-host.md` | 🟡 | Defined · no sample |
| `skills/ioc-sweep.md` | 🟡 | Defined |
| `skills/incident-report.md` | 🟡 | Template · citations required |
| `skills/onboard-host.md` | ✅ | MCP-only enforced |
| `skills/daily-summary.md` | 🟡 | Updated with `get_soc_health` |
| `skills/security-posture.md` | 🟡 | Max 10 CVEs, no IOC section, bind_scope |
| `skills/opencode-mcp.md` | ✅ | MCP contract for opencode |
| `.opencode/command/*` | ✅ | triage, investigate, onboard, posture, report, **auto-triage** |
| Headless `opencode run` | 🟡 | Documented · not CI-gated |

### 4.6 Grounding & audit (Epic E4)

| Item | Status | Details |
|------|--------|---------|
| `investigations` table | ✅ | open/close lifecycle |
| `agent_actions` table | ✅ | tool name, args, duration |
| `reports` table | ✅ | saved markdown paths |
| `record_finding` citations | 🟡 | Tool exists; reports often skip it |
| Grafana investigation trail | 🟡 | `agent-activity.json` · needs data |
| "No claim without citation" in output | ⬜ | Not enforced automatically |

### 4.7 Onboarding (Epic E3)

| Item | Status | Details |
|------|--------|---------|
| Plain-language → SSH enroll | ✅ | `onboard_host_tool` |
| Wazuh agent install + start | ✅ | Linux |
| Verify agent active in manager | ✅ | 007, 008, 011 on lab K8s VMs |
| Verify telemetry in Postgres | 🟡 | Ingestion ✅; agent-attributed events sparse in lab |
| Windows onboard (E10) | ⬜ | Not tested |
| Stale agent cleanup (002–010) | ⬜ | Fleet noise in summaries |

### 4.8 Posture pipeline (agentic — beyond classic Wazuh vuln module)

| Item | Status | Details |
|------|--------|---------|
| `cve_findings` + OSV.dev | ✅ | No Wazuh Indexer required |
| CVE triage (actionable filter) | ✅ | KEV, patched-version, metadata pkgs |
| `exposure_findings` + syscollector ports | ✅ | bind_scope, K8s ports |
| `detection_coverage` cache | ✅ | rules_firing_count, events_last_at |
| APScheduler 6h background scan | ✅ | Starts with MCP `main()` |
| Host sync from Wazuh → `hosts` | ✅ | Core tick every 60s |
| SCA + user inventory | ✅ | `sca_scanner.py`, `user_scanner.py`, EPSS in CVE triage |
| Container image CVE (Trivy) | 🟡 | `container_posture.py` — inventory + CVE cache on lab agent 007 |
| Wazuh native vuln-detection + indexer | 🚫 | Indexer not in compose; we use OSV |

### 4.9 Threat intel (Epic E9)

| Item | Status | Details |
|------|--------|---------|
| AbuseIPDB IP reputation | ✅ | MCP |
| VirusTotal IP + hash | ✅ | MCP |
| CISA KEV in CVE triage | ✅ | `cve_triage.py` fetch |
| Cache / rate-limit | ⬜ | |
| Cited in triage reports | ⬜ | Blocked on U1 |

### 4.10 Honeypot / deception (Epic E6)

| Item | Status | Details |
|------|--------|---------|
| Cowrie dev-server + db-server | ✅ | Docker |
| Wazuh local_rules for Cowrie | ✅ | `lureguard_custom` group |
| Logs → Wazuh → integratord | 🟡 | Ingestion ✅; docker/web groups need agent config push |
| DNAT redirect high-score SSH | ✅ | Core enforcer |
| `check_decoy_contact` MCP tool | ⬜ | |
| Decoy panel in Grafana | ⬜ | |

### 4.11 Grafana / SIEM face (Epic E8)

| Dashboard | Status | Panels |
|-----------|--------|--------|
| `lureguard-overview` | 🟡 | Events + **SLA row** (MTTD/MTTR/FPR/pending blocks) |
| `agent-activity` | 🟡 | Investigations + **attack timeline panel** |
| `fleet-hosts` | ✅ | Enrolled hosts |
| `cve-posture` | ✅ | CVE + exposure + detection |
| Wazuh full parity (A–H in old spec) | ⬜ | Many panels not built |
| Agent verdict vs Wazuh level | ⬜ | Differentiator panel |
| Deep-link from Telegram | ⬜ | |

### 4.12 Reports & delivery

| Item | Status | Details |
|------|--------|---------|
| `reports/*.md` on disk | 🟡 | 2 samples — **pre-fix, invalid** |
| Report quality (Tier III bar) | ⬜ | See §6 |
| Telegram `.md` upload | ✅ | |
| PDF via WeasyPrint | ✅ | `make venv`; Telegram sends PDF by default |
| Notion / external PM sync | 🟡 | Product Backlog updated 2026-06-13 |

### 4.13 Tests & CI

| Item | Status | Details |
|------|--------|---------|
| Unit tests (collector, policy, ML, investigation) | ✅ | `tests/` · **101 passed** locally |
| Integration test (live Core) | 🟡 | Marker in pytest |
| MCP smoke test in CI | ⬜ | |
| End-to-end playbook doc | ⬜ | Tier I Gate E |

---

## 5. Postgres data model

| Table | Purpose | Populated? |
|-------|---------|------------|
| `events` | Wazuh alerts (SIEM ground truth) | ✅ |
| `decisions` | ML allow/alert/redirect + `event_id` FK | 🟡 |
| `blocklist` | Pending/executed IP blocks | 🟡 empty until used |
| `container_cve_findings` | Trivy image scan cache | 🟡 empty until scanned |
| `watched_events` | Auto-triage dedup | 🟡 |
| `sca_findings` / `user_findings` | Posture pillars 4–5 | ✅ |
| `investigations` | Agent investigation sessions | 🟡 When opencode runs |
| `agent_actions` | MCP audit log | ✅ |
| `reports` | Saved report metadata | 🟡 |
| `hosts` | Enrolled fleet | ✅ |
| `cve_findings` | Posture CVE cache | ✅ (007/008/011 scanned) |
| `exposure_findings` | Port exposure cache | ✅ |
| `detection_coverage` | FIM/rootcheck/alert metrics | ✅ |
| `whitelist` | IP allowlist | 🟡 |
| `sessions` / `summaries` / `alerts` | Legacy Telegram/LLM paths | 🟡 |

---

## 6. Tier I replacement gate (definition of "done")

All must pass before claiming **Tier I analyst replaced**:

- [x] 🔴 **A. Ingestion proven** — `get_soc_health()` shows recent `last_event_at` + `events_24h > 0`
- [ ] **B1. Triage report** on real alerts — clustered, TP/FP, P1–P4, tool citations
- [ ] **B2. Daily summary** — leads with ingestion health; skeptical silence
- [ ] **B3. Investigation sample** — timeline + evidence + handoff quality
- [ ] **C. Posture report regenerated** — post-fix pipeline; ≤10 actionable CVEs
- [ ] **D. Tier III spot-check** — approves 2–3 findings without re-querying Wazuh
- [ ] **E. E2E test playbook** — documented + optional headless run
- [ ] **F. Stale agent cleanup** — lab fleet not polluted with 002–010

Tracked in Notion: [Product Backlog → Tier I Gate cards](https://www.notion.so/Product-Backlog-36bd7cdfb78280349cabe398755220ef)

---

## 7. Epics map (E1–E11)

| Epic | Name | Status | Notes |
|------|------|--------|-------|
| E1 | Appliance (compose, Wazuh hidden) | 🟡 In progress | Ingestion proven; E2E investigation pending |
| E2 | MCP server | 🟡 In progress | 40+ tools; new investigation tools need E2E proof |
| E3 | Onboarding flow | ✅ Dev done | Telemetry verify pending |
| E4 | Grounding + audit | 🟡 In progress | Tables live; report discipline weak |
| E5 | Skills + NIST IR | 🟡 In progress | All skills written; proof missing |
| E6 | Honeypot ground-truth | 🟡 Partial | Cowrie live; no MCP decoy check |
| E7 | Triage ML | 🟡 Partial | SSH ML in Core; not agent-facing rank |
| E8 | SIEM dashboard + agent layer | 🟡 In progress | 4 dashboards; parity incomplete |
| E9 | Threat intel enrichment | ✅ Dev done | Prove in triage |
| E10 | Windows demo host | ⬜ Backlog | |
| E11 | Demo script + docs + landing | ⬜ Backlog | Flagship demo not scripted |

---

## 8. Where we're going (priority order)

1. **Joint E2E proof** — triage + investigate reports saved to `reports/` (Gates B1–B3)
2. **Test block path** — `recommend_block_ip` → human `confirm_block_ip` on lab host
3. **Push agent config** — docker stdout + web logs on `.131`
4. **Auto-triage smoke** — level ≥ 12 event → watcher → opencode
5. **Container posture E2E** — `trigger_posture_scan` on agent with Docker; confirm Grafana Containers panel
6. **Tier III review** (Gate D)
7. **Flagship demo script** (E11)

---

## 9. Explicitly out of scope (don't block MVP)

- [x] **Autonomous** containment (agent never calls `confirm_block_ip` alone)
- [ ] **Human-confirmed** block via `recommend_block_ip` → `confirm_block_ip` (implemented, not E2E tested)
- [x] Bundled LLM in Docker (BYO-LLM via opencode)
- [x] Wazuh Indexer / OpenSearch stack (we use Postgres + OSV)
- [x] PDF reports via pip (WeasyPrint / xhtml2pdf fallback)
- [x] PentAGI-style autonomous red team
- [x] Multi-tenant / enterprise SSO
- [x] Prometheus in compose (optional later)

---

## 10. Lab environment snapshot (2026-06-18)

| Resource | Value |
|----------|-------|
| Active agents | 007 (cp-131), 008 (vm3-134), 011 (k8s-133) |
| Agent IPs | 192.168.28.131, .134, .133 |
| Posture cache | Fresh for 007/008/011 (6 pillars: CVE, exposure, detection, SCA, users, containers) |
| Events in Postgres | **8+** in 24h window (ingestion proven) |
| Closed investigations (24h) | 6 (SLA metrics populated — review FPR sanity) |
| New MCP tools (uncommitted) | See § Tier 1 investigation quality |

---

## 11. Quick commands (verify state yourself)

```bash
docker compose up -d
make migrate && make doctor

# Ingestion health
.venv/bin/python -c "from lureguard_mcp.db import get_soc_health_db; print(get_soc_health_db())"

# Posture snapshot
.venv/bin/python -c "from lureguard_mcp.posture_snapshot import get_posture_snapshot; import json; print(json.dumps(get_posture_snapshot('007'), indent=2)[:1500])"

# Rich timeline + attack summary
.venv/bin/python -c "
from lureguard_mcp.db import get_attack_summary, get_event_timeline
import json
ip = '127.0.0.1'
print(json.dumps(get_attack_summary(ip), indent=2))
"

# IP context (set VIRUSTOTAL_API_KEY / ABUSEIPDB_API_KEY for external IPs)
.venv/bin/python -c "from lureguard_mcp.enrichment import get_ip_context; print(get_ip_context('8.8.8.8'))"

# Blocklist (pending entries)
.venv/bin/python -c "from lureguard_mcp.blocklist import list_blocklist; print(list_blocklist())"
```

---

*Keep this file updated when a gate closes or a use case moves from 🟡 → ✅.*
