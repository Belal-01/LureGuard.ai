# Mode: incident-report — Write formal incident report

## Purpose

Produce a developer-readable incident report with ATT&CK tags, saved to `reports/` and Postgres.

## Workflow

1. Ensure an investigation is open (or `open_investigation` first)
2. Gather evidence using tools from `_shared.md` (do not invent)
3. Draft report using template in `_shared.md`
4. `save_report(title="...", markdown="...", send_telegram=true)` — saves and uploads **.md** to Telegram
5. `close_investigation` if not already closed

Alternatively: `save_report` then `send_report_to_telegram(file_path=...)` using the returned path.

**PDF (opt-in only):** Do **not** convert or send PDF unless the user explicitly asks (e.g. "send as PDF"). Then: `convert_report_to_pdf(file_path=...)` or `send_report_to_telegram(..., as_pdf=true)`. Requires `pandoc` on the host.

Optional: `notify_telegram` with a one-line executive summary (text only, not the full report).

## Output format

Full markdown per `_shared.md` template. Every evidence bullet must map to a prior tool call.

## Quality bar

- Executive summary understandable by a developer in 30 seconds
- Timeline has UTC timestamps from `get_event_timeline`
- Recommended actions are advisory ("you should…"), never executed by agent
