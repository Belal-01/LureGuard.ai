# Mode: investigate-web — Web server incident (apache/nginx)

## Purpose

Investigate web-facing attacks on apache/nginx or containerized web servers: classify attack type, enrich URLs/domains, map MITRE, produce Tier-2-lite findings.

## When to use

- User mentions apache, nginx, web server, container, HTTP attack, SQLi, XSS, path traversal
- Events on web-related channels or `raw_ref` contains HTTP paths, user-agents, query strings

## Workflow

1. `open_investigation(subject="Web investigation: <host or IP>", trigger="human", detection_source="wazuh", asset_criticality="high")`
2. `search_events(ip=..., channel=..., min_level=3)` — pull web-related events
3. For each suspicious event (or cluster):
   - `analyze_web_attack(event_payload)` — pass `raw_ref` JSON or event fields
   - Extract URLs/domains from payload; `check_url_virustotal`, `check_domain_virustotal`, `check_url_urlhaus`
   - `defang_ioc` before recording in findings
4. `get_event_timeline(ip, window_hours=48)` — build attack sequence
5. `add_timeline_event` per phase: probe → exploit attempt → (if any) success indicator
6. `list_agents` → `get_agent_detail` — confirm web process (apache2/nginx) and exposed ports via `get_agent_exposure` (cached; no scan unless user asks)
7. **Only if user asks about CVEs/posture on this host:** `get_agent_vulnerabilities(agent_id)` from cache, or `refresh-posture.md` if they want a live rescan. npm/Next.js inside container images are **not** in syscollector — state this gap for Dockerized apps
8. `record_finding` with MITRE (typically T1190 Exploit Public-Facing Application, T1059 for RCE attempts)
9. `get_investigation_artifacts` before close
10. `close_investigation` with kill_chain_summary describing attack progression (include container blast-radius note if docker + privileged/root)
11. If user asked for report → `skills/incident-report.md`

## MITRE quick reference (web)

| Attack signal | Technique | Tactic |
|---------------|-----------|--------|
| SQLi in query string | T1190 | Initial Access |
| XSS payload | T1189 | Initial Access |
| LFI / path traversal | T1190 | Initial Access |
| Scanner UA (sqlmap, nikto) | T1595.002 | Reconnaissance |
| RCE in params | T1190 + T1059 | Initial Access / Execution |

## Recommended actions (advisory only)

- Review WAF / mod_security rules for matched patterns
- Block source IP at firewall (human executes)
- Patch CVEs on exposed web stack — cite **cached** `get_agent_vulnerabilities` if user asked; else offer rescan via `refresh-posture.md`
- Restrict bind scope if port exposed on all interfaces (`get_agent_exposure`)

Never block IPs or restart services without explicit human approval.

## Output format

```markdown
## Web Investigation: [host/IP]

**Attack type:** sqli | xss | lfi | rce | probe | scanner  
**Verdict:** TP | FP | undetermined  
**Confidence:** [level]

### Timeline
| Time (UTC) | Event | MITRE | Evidence |

### Enrichment
| IOC | Type | VT/URLhaus | Defanged |

### Host context
[apache/nginx version, exposed port, criticality, dockerd/containerd CVEs from posture scan]

### Container / app stack (if Docker)
- Image app deps (Next.js/npm): **not auto-scanned** — recommend image scan
- If container runs as root or privileged: **elevated host escape risk** — cite exposure + state in impact

### Recommended actions
[Prioritized, human executes]
```
