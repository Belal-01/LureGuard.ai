# MCP tools reference

All tools are defined in `lureguard_mcp/server.py`, exposed via FastMCP stdio, and logged to `agent_actions` when decorated with `@audited`.

Return format: JSON strings via `mcp_json()` unless noted as `compact_json` (Wazuh fleet tools).

---

## Alerts and search

| Tool | Parameters | Purpose |
|------|------------|---------|
| `get_recent_alerts` | `limit`, `min_level`, `channel` | Recent rows from Postgres `events` |
| `get_alerts_for_ip` | `ip`, `limit` | Events for one source IP |
| `get_event_timeline` | `ip`, `window_hours` | Chronological narrative + geo + ML score on SSH rows |
| `get_attack_summary` | `ip`, `window_hours` | Duration, phases, top rules, channels |
| `search_events` | `query`, `channel`, `min_level`, `limit`, `hours` | Text/rule search on `events` |
| `correlate_alerts` | `window_hours`, `min_level` | Cluster by `src_ip` with kill-chain lite |

---

## Enrichment and intel

| Tool | Parameters | Purpose |
|------|------------|---------|
| `get_ip_context` | `ip` | Geo + AbuseIPDB + VirusTotal + combined verdict (preferred over single checks) |
| `check_ip_reputation` | `ip` | AbuseIPDB only |
| `check_ip_virustotal` | `ip` | VirusTotal IP |
| `check_hash` | `file_hash` | VirusTotal hash |
| `check_url_virustotal` | `url` | VirusTotal URL |
| `check_domain_virustotal` | `domain` | VirusTotal domain |
| `check_url_urlhaus` | `url` | URLhaus |
| `check_tls` | `host`, `port` | TLS certificate / cipher summary |
| `analyze_web_attack` | `event_payload` | Parse web attack fields from event JSON |
| `defang_ioc` | `value`, `ioc_type` | Defang IP/URL/hash for reports |
| `rag_lookup` | `query`, `limit` | Keyword search over local MITRE hints + skills markdown |

Requires `.env` keys for external intel where noted.

---

## Fleet and Wazuh API

| Tool | Parameters | Purpose |
|------|------------|---------|
| `list_agents` | `status` | Wazuh agent list |
| `get_agent_detail` | `agent_id` | Agent metadata + syscollector summary |
| `get_rules_summary` | `limit` | Top firing rules (from recent events) |
| `get_manager_status` | — | Manager health |
| `restart_agent` | `agent_id` | Wazuh API agent restart (**advisory — confirm with human**) |
| `list_enrolled_hosts` | — | Postgres `hosts` table |

---

## Posture (read cache)

| Tool | Parameters | Purpose |
|------|------------|---------|
| `get_posture_snapshot` | `agent_id` | Six-pillar instant read from Postgres cache |
| `get_fleet_posture_summary` | — | Fleet rollup |
| `get_agent_vulnerabilities` | `agent_id`, `severity`, `include_noise` | Host OS CVE rows (`cve_findings`) |
| `get_fleet_vulnerability_summary` | — | Fleet CVE counts |
| `get_agent_exposure` | `agent_id`, `risk_level` | Open ports / exposure rows |
| `get_fleet_exposure_summary` | — | Fleet exposure rollup |
| `get_agent_detection_coverage` | `agent_id` | FIM/rootcheck/alerts coverage |
| `get_fleet_detection_coverage` | — | Fleet detection rollup |
| `get_agent_sca_summary` | `agent_id` | CIS/SCA pass-fail summary |
| `get_fleet_sca_summary` | — | Fleet SCA rollup |
| `get_agent_users` | `agent_id`, `risk_level` | Local user risk findings |
| `get_agent_container_posture` | `agent_id`, `image_ref`, `limit` | Container inventory + Trivy CVE rows |

---

## Posture (scan / refresh)

| Tool | Parameters | Purpose |
|------|------------|---------|
| `scan_agent_vulnerabilities` | `agent_id` | Force OSV scan for one agent (writes `cve_findings`) |
| `trigger_posture_scan` | `agent_id`, `force` | Background job — all six pillars (empty `agent_id` = fleet) |
| `get_posture_scan_status` | `job_id` | Job progress from `posture_scan_jobs` |

Routine posture reads use cache; user-triggered refresh → `skills/refresh-posture.md`.

---

## Containment

| Tool | Parameters | Purpose |
|------|------------|---------|
| `recommend_block_ip` | `ip`, `reason`, `investigation_id` | Insert pending blocklist row |
| `confirm_block_ip` | `block_id`, `notes` | Human-gated iptables DROP on fleet |
| `list_blocklist` | `pending_only` | List blocklist entries |
| `recommend_whitelist_ip` | `ip`, `reason`, `investigation_id` | Insert pending whitelist row |
| `confirm_whitelist_ip` | `whitelist_id`, `notes` | Human-gated whitelist (Core ML cache) |
| `list_whitelist` | `pending_only` | List whitelist entries |
| `remove_whitelist_ip` | `whitelist_id` or `ip` | Remove whitelist row |

Default: agent **cannot** call `confirm_*` unless env gates enabled.

---

## Investigation lifecycle

| Tool | Parameters | Purpose |
|------|------------|---------|
| `open_investigation` | `title`, `trigger`, `asset_criticality`, … | Start investigation; sets MCP context |
| `record_finding` | `title`, `detail`, `verdict`, `confidence`, `severity`, … | Append finding (must cite tool evidence) |
| `add_timeline_event` | `label`, `detail`, `occurred_at` | Analyst timeline beat |
| `get_investigation_artifacts` | `investigation_id` | Findings, IOCs, timeline, actions |
| `close_investigation` | `verdict`, `confidence`, `summary`, … | Close with TP/FP/undetermined |

**Required:** `open_investigation` before triage/investigate work; `close_investigation` when done.

---

## Reports and charts

| Tool | Parameters | Purpose |
|------|------------|---------|
| `generate_report_chart` | `title`, `chart_type`, `labels_json`, `values_json`, … | Custom PNG → `reports/assets/` |
| `generate_report_chart_preset` | `preset`, `hours`, `agent_id`, … | Presets: `events_by_channel`, `alert_level_distribution`, `cve_by_severity`, `investigation_timeline` |
| `save_report` | `title`, `markdown`, `send_telegram`, `as_pdf` | Save `.md` + auto charts; Telegram sends PDF |
| `convert_report_to_pdf` | `file_path` | WeasyPrint/xhtml2pdf conversion |
| `send_report_to_telegram` | `file_path`, `caption` | PDF to Telegram |
| `notify_telegram` | `message` | Short text ping |

---

## Onboarding and assets

| Tool | Parameters | Purpose |
|------|------------|---------|
| `onboard_host_tool` | `ip`, `ssh_user`, `ssh_password`, `agent_name`, `criticality` | **Only** supported enroll path (SSH + Wazuh API) |
| `set_host_criticality` | `agent_id`, `criticality` | Update `hosts.criticality` |

---

## SOC metrics

| Tool | Parameters | Purpose |
|------|------------|---------|
| `get_soc_health` | — | Ingestion stats, SLA (MTTD/MTTR/FPR), pending blocks, fleet counts |

---

## System update

| Tool | Purpose |
|------|---------|
| `check_system_update` | JSON: up-to-date / update-available / offline / dismissed |
| `apply_system_update` | Apply system-layer git checkout from upstream |
| `dismiss_system_update` | Suppress update prompt |
| `rollback_system_update` | Restore from `backup-pre-update-*` branch |

---

## Tools that do **not** exist

Do not reference or implement workarounds for removed/planned tools:

- `scan_container_image` / `get_container_vulnerabilities` (removed — use `get_agent_container_posture` + `trigger_posture_scan`)
- `check_decoy_contact` (not in MCP)
