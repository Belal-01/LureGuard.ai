"""Lightweight MITRE ATT&CK + skills keyword retrieval (no vector DB)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from lureguard_mcp.config import REPO_ROOT

_SKILLS_DIR = REPO_ROOT / "skills"
_MITRE_KEYWORDS = {
    "T1110": ["brute", "password", "auth_failed", "ssh"],
    "T1190": ["web", "sqli", "xss", "exploit", "http"],
    "T1059": ["shell", "powershell", "bash", "cmd"],
    "T1078": ["valid account", "auth_success", "login"],
    "T1083": ["file", "syscheck", "fim"],
    "T1018": ["lateral", "remote", "smb", "psexec"],
    "T1046": ["scan", "nmap", "port"],
    "T1566": ["phish", "email"],
}


def _load_skill_snippets(max_files: int = 5, max_chars: int = 400) -> list[dict[str, str]]:
    snippets: list[dict[str, str]] = []
    if not _SKILLS_DIR.exists():
        return snippets
    for path in sorted(_SKILLS_DIR.glob("*.md"))[:max_files]:
        text = path.read_text(encoding="utf-8")
        snippets.append({"skill": path.name, "excerpt": text[:max_chars]})
    return snippets


def rag_lookup(query: str, *, limit: int = 5) -> dict[str, Any]:
    q = query.lower()
    technique_hits: list[dict[str, str]] = []
    for technique, keywords in _MITRE_KEYWORDS.items():
        if any(kw in q for kw in keywords):
            technique_hits.append({"technique": technique, "matched_keywords": keywords})

    skill_hits: list[dict[str, str]] = []
    for snippet in _load_skill_snippets():
        if any(token in snippet["excerpt"].lower() for token in re.findall(r"[a-z]{4,}", q)):
            skill_hits.append(snippet)

    return {
        "query": query,
        "technique_hits": technique_hits[:limit],
        "skill_hits": skill_hits[:limit],
        "note": "Keyword retrieval over local skills; not a full vector RAG index.",
    }


def rag_lookup_json(query: str, *, limit: int = 5) -> str:
    return json.dumps(rag_lookup(query, limit=limit), indent=2)
