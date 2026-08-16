# Architecture decisions

Decisions the owner has already made in discussion, written down so a contributor
(or the owner in three months) can act on them without re-deriving the reasoning.
Each entry is context, decision, consequences accepted — including the downside,
when there is one. A decision record that lists only upsides is marketing, not
a record.

These close register items `ARC-3`, `ARC-4`, `ARC-5`, `ARC-6`, `POS-3`, `POS-4`,
`POS-7` and `STO-7` in [`CHANGE-REGISTER.md`](CHANGE-REGISTER.md).

---

## ADR-1 · Shape A is the product; Shape B is a configuration of it

**Closes:** `ARC-3` (and the tension named in `ARC-2`).

**Context.** The register described "two products built as one": a single-VPS
self-protect tool and a multi-host fleet SIEM, with no stated line between them.
`ARC-2` names the sharper version — a fleet-aggregation SIEM watching one host
is a contradiction, not a feature.

**Decision.** Shape A — one VPS, self-protect — is the product, and it is what
the market wants. Shape B — a fleet — is a *configuration* of Shape A, not a
second build: same analyst layer (opencode, MCP, skills, Grafana), different
collection (one Wazuh manager vs. several enrolled agents). The owner's own lab
runs Shape B; the product being sold runs Shape A. That tension is real and is
stated here rather than papered over.

**Consequences accepted.** Every feature is scoped and demoed against Shape A
first. Shape B stays possible because the analyst layer never assumes a single
host, but it is not built, tested, or marketed as a separate product — it is
what happens when Shape A's collector is pointed at a Wazuh manager with more
than one agent enrolled.

---

## ADR-2 · The analyst/collector seam is deliberate

**Closes:** `ARC-4`.

**Context.** The seam between "always-on collection" and "interactive analysis"
already existed in the code — MCP runs on the host, not inside Docker compose —
but it was accidental. Nothing documented it as a boundary, so nothing enforced
it either.

**Decision.** The seam is now a named architectural line. **Collector** (Wazuh,
Postgres, Core) is always-on and belongs on a server. **Analyst** (opencode,
MCP, skills) is interactive and belongs on the laptop. MCP running on the host
rather than in Docker was the right call made for the wrong reason; it is now
the right call made on purpose.

**Consequences accepted.** Two small installers instead of one large one, and
a network boundary between them (see `ADR-4`) that has to be documented and
secured rather than assumed away. Any future feature has to declare which side
of the seam it lives on.

---

## ADR-3 · No SIEM manager on the laptop

**Closes:** `ARC-5`.

**Context.** A tempting shape: run the whole manager on the analyst's laptop,
lid open or closed, and skip a second box entirely.

**Decision.** Ruled out. Agents connect *outbound* to the manager, so a NAT'd,
sleeping, or Wi-Fi-roaming laptop is unreachable — there is no stable inbound
address to receive from. The agent-side buffer that would seem to cover the gap
is a finite anti-flood queue, not a durable spool; it is sized to smooth bursts,
not to hold hours of alerts while a laptop is closed. Attacks do not wait for
the lid to open.

**Consequences accepted.** The manager has to live somewhere always-reachable —
the target VPS itself (`ADR-4`) or, in Shape B, a dedicated box. This forecloses
the simplest possible install (single laptop, nothing else) as a real option.

---

## ADR-4 · Topology: collector on the target, analyst on the laptop, tunneled

**Closes:** `ARC-6`.

**Context.** Given `ADR-2` (seam) and `ADR-3` (no manager on the laptop), Shape A
still needs a concrete topology, not just a division of responsibilities.

**Decision.** The collector runs on the same VPS it protects. The analyst
connects from the laptop over Tailscale or an SSH tunnel. No second box.

**Consequences accepted — plainly, not hidden.** This puts the SIEM on the
monitored host: if the host is fully compromised before detection, the SIEM
data and the attacker are on the same machine. That is a real weakness, and it
is the same trade-off CrowdSec makes at this price point — footprint over
isolation. A separate, always-on monitoring box is the Shape B answer for
anyone who needs that isolation; Shape A does not pretend to provide it.

---

## ADR-5 · Compete in the analyst layer, not against Wazuh or Splunk

**Closes:** `POS-3`.

**Context.** The register had this positioned between Splunk and Wazuh, which
is the wrong category — this product ships no agent, no detection content, and
no scale story. It is downstream of Wazuh, not a replacement for it.

**Decision.** Compete in the analyst layer instead: Security Copilot,
Elastic/Splunk AI Assistants, Dropzone. The axis is auditable, self-hostable,
BYO-LLM — not "we detect more" or "we scale further," since neither is true.
For a single-VPS buyer specifically, the real competitor is CrowdSec; there the
axis is investigation depth, never footprint, because CrowdSec wins on
footprint by design.

**Consequences accepted.** This concedes there is no proprietary agent and no
proprietary detection content — the product is a thin, auditable layer on top
of someone else's collection. Marketing copy that implies otherwise would be
`POS-6`'s mistake again.

---

## ADR-6 · One user, two roles: operator and validator

**Closes:** `POS-4`.

**Context.** "Who is this for" had two candidate answers — a software engineer
with no SOC background, and a Tier 3 analyst — that read like two audiences
needing two products.

**Decision.** They are one requirement, not two audiences. The software
engineer is the *user*: zero SOC skill required to operate it. The Tier 3
analyst is the *validator*: the engineer is only right to trust the output once
a senior analyst would approve it. Both roles converge on the same bar — output
that survives senior scrutiny and needs no SOC skill to consume.

**Consequences accepted.** Every output-facing feature is held to the stricter
of the two bars at once: readable by someone with no security background,
defensible to someone who audits security tools for a living. Optimizing for
only one (dumbing down for the engineer, or jargon for the analyst) fails the
requirement even if it looks like it serves one audience well.

---

## ADR-7 · Distribution: not yet

**Closes:** `POS-7`.

**Context.** Strategy is knowable — audience concentrates in r/selfhosted,
r/homelab, r/netsec, HN, and awesome-* lists — but the outcome of pushing there
now is not, because the product has no artefact yet that converts in that
niche.

**Decision.** Not yet. Gate distribution on two things existing first: a demo
path (`INS-1`/`INS-2`-adjacent), and one honest "here is what it caught in 24
hours" write-up. The converting artefact in this niche is proof-of-catch, not a
feature list — this product already produces that as a report, it just has not
been pointed at a real 24-hour window yet. Footprint (single VPS, no agent) is
itself a distribution feature once there is proof to attach it to.

**Consequences accepted.** No launch push, no submission to awesome-* lists,
no HN post until the proof-of-catch write-up exists. Being first is traded for
not burning the one credible shot at these audiences on an unfinished story.

---

## ADR-8 · Events stay in Postgres; no OpenSearch

**Closes:** `STO-7`.

**Context.** OpenSearch would fix retention, compression, partitioning and
search in one move — all real gaps (`STO-1`, `STO-2`, `STO-6`, `STO-8`) — and it
would fix none of `ING-1`…`ING-7`, which are upstream pipeline defects, not
storage defects. Wazuh Indexer *is* OpenSearch and is already in the compose
file's dependency graph but not deployed — the option was live, not
hypothetical.

**Decision.** Keep events in Postgres, partitioned by month, retention enforced
by `DROP PARTITION`. Raw payload is not duplicated — it stays in Wazuh,
referenced via `raw_ref`. No OpenSearch.

**Consequences accepted.** Two disqualifying reasons, stated rather than
implied: OpenSearch is JVM-based (2–4 GB heap, which is why Wazuh's own
quickstart asks for 8 GiB) and ends the small-VPS target this product is built
for; and it has no joins and no ACID, which would kill `GFA-5`'s
verdict-vs-Wazuh-level join and the audit trail that is the product's whole
differentiator. Full-text search across raw log bodies — the one thing
OpenSearch would have given for free — stays a gap this decision does not
solve; `STO-6`'s TOAST compression is the partial answer for now.
