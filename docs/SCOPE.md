# Supported Platforms and Scope

## Current support: Linux only

LureGuard **runs only on Linux** and expects **Linux hosts** to monitor.

### What works
- Wazuh agents on any Linux distribution (`apt` onboarding tested; others available)
- SSH authentication detection and triage
- Host posture scanning (CVEs via OSV, open ports, SCA, users, container CVEs)
- Alert enrichment (IP geo, Virustotal, AbuseIPDB)
- PDF report generation
- Grafana dashboards

### What does not work
- **Windows agents:** not supported
- **Active Directory / Kerberos detection:** not supported
- **Windows-specific attack detection:** not supported

## Why: The deliberate scope decision (ML-6)

### Windows support looks cheap
Wazuh's agent does support Windows, which makes adding it seem straightforward. It is not.

**Onboarding divergence:** The current path is `SSH + apt install`. Windows requires either:
- WinRM/PowerShell remoting (a separate authentication/transport layer), or
- Manual MSI installation (no automation).

Both paths must be built and tested separately.

**Detection difference:** AD attack detection is a different discipline entirely:
- **Unix/Linux:** SSH auth events (failed/successful login attempts, source IP, username), syslog parsing, process auditing
- **Windows/AD:** Event ID 4624 (success), 4625 (failure), Sysmon integration, PowerShell logging, LSASS access, Kerberos ticket-granting service queries

The two domains share almost no rules or features.

### The classifier is Linux-shaped
The current ML model—while useful only for SSH events today—has hardcoded features:
- `is_sshd`: is this from the SSH daemon?
- `decoder_sshd`: does the message parser identify it as SSH?

Adding Windows without retraining on Windows data would add features that never fire, polluting inference.

### Coverage is narrow even on Linux
`docs/CHANGE-REGISTER.md` ML-5 measured real coverage: **8 of 42 ATT&CK techniques observed**, and **8 of 13 tactics are completely dark**—persistence, privilege-escalation, execution, discovery, command-and-control, collection, reconnaissance and resource-development have zero observations. Every post-compromise technique is unseen.

Doubling the surface to Windows before even one platform passes a senior-analyst review is a scaling mistake. Breadth without depth produces a false sense of coverage while adding maintenance burden and operational complexity.

### The decision
**Windows support is deferred until:**
1. Linux detection and triage pass a senior security analyst's review, or
2. The product's users specifically request it with a clear use case.

This is not a temporary limitation we expect to lift soon. It is a deliberate scope boundary. If your fleet is Windows-first, this is not the right product.
