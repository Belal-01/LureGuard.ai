#!/usr/bin/env python3
"""Safe auto-updater for LureGuard — system layer only.

Usage:
  python update-system.py check      # Check if update available
  python update-system.py apply      # Apply update (after user confirms)
  python update-system.py rollback   # Rollback last update
  python update-system.py dismiss    # Dismiss update check

See DATA_CONTRACT.md for system/user layer definitions.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent

CANONICAL_REPO = "https://github.com/Belal-01/LureGuard.ai.git"
RAW_VERSION_URL = "https://raw.githubusercontent.com/Belal-01/LureGuard.ai/main/VERSION"
RELEASES_API = "https://api.github.com/repos/Belal-01/LureGuard.ai/releases/latest"

SYSTEM_PATHS = [
    "AGENTS.md",
    "skills/",
    "lureguard_mcp/",
    "core/",
    "connectors/",
    "wazuh/",
    "grafana/provisioning/",
    "opencode.json",
    ".opencode/",
    "migrations/",
    "config/core.yaml",
    "Makefile",
    "docker-compose.yml",
    "pyproject.toml",
    ".env.example",
    "README.md",
    "PRODUCT-STATUS.md",
    "docs/",
    "tests/",
    "ml/",
    "cowrie/",
    "VERSION",
    "DATA_CONTRACT.md",
    "update-system.py",
    ".claude/skills/",
    ".agents/skills/",
    "LICENSE",
]

USER_PATHS = [
    ".env",
    "secrets/",
    "reports/",
]

SEMVER_RE = re.compile(r"^v?(\d+\.\d+\.\d+)$", re.I)


def parse_version_file(raw: str) -> str:
    return raw.strip().split()[0] if raw.strip() else ""


def local_version() -> str:
    v_path = ROOT / "VERSION"
    return parse_version_file(v_path.read_text(encoding="utf-8")) if v_path.exists() else "0.0.0"


def compare_versions(a: str, b: str) -> int:
    pa = [int(x) for x in a.split(".")]
    pb = [int(x) for x in b.split(".")]
    for i in range(3):
        ai, bi = pa[i] if i < len(pa) else 0, pb[i] if i < len(pb) else 0
        if ai < bi:
            return -1
        if ai > bi:
            return 1
    return 0


def git(*args: str) -> str:
    return subprocess.check_output(
        ["git", *args],
        cwd=ROOT,
        text=True,
        timeout=60,
    ).strip()


def git_status_entries() -> list[tuple[str, str]]:
    status = git("status", "--porcelain")
    if not status:
        return []
    return [(line[:2], line[3:]) for line in status.splitlines() if line]


def revert_paths(paths: list[str]) -> None:
    if paths:
        git("checkout", "--", *paths)


def add_paths(paths: list[str]) -> None:
    if paths:
        git("add", "--", *paths)


def _fetch_text(url: str, *, headers: dict[str, str] | None = None) -> str | None:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def check() -> None:
    dismiss = ROOT / ".update-dismissed"
    if dismiss.exists():
        print(json.dumps({"status": "dismissed"}))
        return

    local = local_version()
    remote = ""
    release_version = ""
    changelog = ""

    version_raw = _fetch_text(RAW_VERSION_URL)
    if version_raw:
        match = SEMVER_RE.match(parse_version_file(version_raw))
        if match:
            remote = match.group(1)

    release_raw = _fetch_text(
        RELEASES_API,
        headers={
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "lureguard-update-checker",
        },
    )
    if release_raw:
        try:
            release = json.loads(release_raw)
            changelog = (release.get("body") or "")[:500]
            tag = str(release.get("tag_name") or "").strip()
            match = SEMVER_RE.match(tag)
            if match:
                release_version = match.group(1)
        except json.JSONDecodeError:
            pass

    if not remote and not release_version:
        both_failed = version_raw is None and release_raw is None
        status = "offline" if both_failed else "no-remote-version"
        print(json.dumps({"status": status, "local": local}))
        return

    if not remote:
        remote = release_version
    elif release_version and compare_versions(release_version, remote) > 0:
        remote = release_version

    if compare_versions(local, remote) >= 0:
        print(json.dumps({"status": "up-to-date", "local": local, "remote": remote}))
        return

    print(
        json.dumps(
            {
                "status": "update-available",
                "local": local,
                "remote": remote,
                "changelog": changelog,
            }
        )
    )


def apply() -> None:
    local = local_version()
    initial_status = {path for _, path in git_status_entries()}
    lock_file = ROOT / ".update-lock"

    if lock_file.exists():
        print("Update already in progress (.update-lock exists). Delete manually if stuck.", file=sys.stderr)
        sys.exit(1)

    lock_file.write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")
    updated: list[str] = []

    try:
        backup_branch = f"backup-pre-update-{local}"
        try:
            git("branch", backup_branch)
            print(f"Backup branch created: {backup_branch}")
        except subprocess.CalledProcessError:
            print(f"Backup branch already exists ({backup_branch}), continuing...")

        print("Fetching latest from upstream...")
        git("fetch", CANONICAL_REPO, "main")

        print("Updating system files...")
        for path in SYSTEM_PATHS:
            try:
                git("checkout", "FETCH_HEAD", "--", path)
                updated.append(path)
            except subprocess.CalledProcessError:
                pass

        violated: set[str] = set()
        for _, file in git_status_entries():
            if file in initial_status:
                continue
            if file in SYSTEM_PATHS:
                continue
            for user_path in USER_PATHS:
                if file.startswith(user_path):
                    print(f"SAFETY VIOLATION: User file was modified: {file}", file=sys.stderr)
                    violated.add(file)

        if violated:
            print("Aborting: user files were touched. Rolling back...", file=sys.stderr)
            revert_paths([*updated, *sorted(violated)])
            raise RuntimeError("Update aborted: user files were touched.")

        try:
            subprocess.run(
                ["make", "venv"],
                cwd=ROOT,
                check=False,
                timeout=300,
            )
        except (subprocess.TimeoutExpired, OSError):
            print("make venv skipped (may need manual run)")

        remote = local_version()
        try:
            paths_to_stage = list(updated)
            dismiss = ROOT / ".update-dismissed"
            if dismiss.exists():
                dismiss.unlink()
                paths_to_stage.append(".update-dismissed")
            add_paths(paths_to_stage)
            git("commit", "-m", f"chore: auto-update system files to v{remote}")
        except subprocess.CalledProcessError:
            pass

        print(f"\nUpdate complete: v{local} → v{remote}")
        print(f"Updated {len(updated)} system paths.")
        print("Run: make migrate && docker compose up -d")
        print(f"Rollback available: python update-system.py rollback")
    finally:
        lock_file.unlink(missing_ok=True)


def rollback() -> None:
    try:
        branches = git(
            "for-each-ref",
            "--sort=-committerdate",
            "--format=%(refname:short)",
            "refs/heads/backup-pre-update-*",
        )
        branch_list = [b.strip() for b in branches.splitlines() if b.strip()]
        if not branch_list:
            print("No backup branches found. Nothing to rollback.", file=sys.stderr)
            sys.exit(1)

        latest = branch_list[0]
        print(f"Rolling back to: {latest}")
        restored: list[str] = []
        for path in SYSTEM_PATHS:
            try:
                git("checkout", latest, "--", path)
                restored.append(path)
            except subprocess.CalledProcessError:
                pass

        if restored:
            add_paths(restored)
            try:
                git("commit", "-m", f"chore: rollback system files from {latest}")
            except subprocess.CalledProcessError:
                pass

        print(f"Rollback complete. Restored {len(restored)} path(s) from {latest}.")
        print("Your data (.env, secrets, reports) was not affected.")
    except subprocess.CalledProcessError as exc:
        print(f"Rollback failed: {exc}", file=sys.stderr)
        sys.exit(1)


def dismiss() -> None:
    (ROOT / ".update-dismissed").write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")
    print('Update check dismissed. Run "python update-system.py check" or say "check for updates" to re-enable.')


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    try:
        if cmd == "check":
            check()
        elif cmd == "apply":
            apply()
        elif cmd == "rollback":
            rollback()
        elif cmd == "dismiss":
            dismiss()
        else:
            print("Usage: python update-system.py [check|apply|rollback|dismiss]")
            sys.exit(1)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
