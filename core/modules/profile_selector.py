"""
Profile Selector — pure function, no I/O.
select_profile(username, p) → "dev-server" | "db-server"

Tested with 20+ cases in tests/test_profile_selector.py
"""

_DB_USERS = {"postgres", "mysql", "mongo", "mssql", "oracle", "redis", "mariadb", "mongodb"}
_DEV_USERS = {"deploy", "node", "jenkins", "git", "www-data", "docker",
              "ubuntu", "ec2-user", "app", "dev", "ansible", "github-actions"}


def select_profile(username: str, p: float) -> str:
    """
    Choose which Cowrie profile to redirect the attacker to.

    Args:
        username: the last username the attacker tried
        p:        classifier probability (0..1)

    Returns:
        "dev-server" or "db-server"
    """
    u = (username or "").lower().strip()

    if u in _DB_USERS:
        return "db-server"
    if u in _DEV_USERS:
        return "dev-server"

    # Tie-break: high confidence → dev-server (richer bait)
    return "dev-server" if p >= 0.85 else "db-server"
