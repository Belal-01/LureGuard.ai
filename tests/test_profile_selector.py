"""
20+ unit tests for profile_selector.py — Pure Function.
No I/O, no DB, no network.
"""
import pytest
from modules.profile_selector import select_profile


# ── DB usernames → db-server ──────────────────────────────
@pytest.mark.parametrize("username", [
    "postgres", "mysql", "mongo", "mssql",
    "oracle", "redis", "mariadb", "mongodb",
    "POSTGRES",  # case insensitive
])
def test_db_usernames_go_to_db_server(username):
    assert select_profile(username, 0.9) == "db-server"


# ── Dev usernames → dev-server ────────────────────────────
@pytest.mark.parametrize("username", [
    "deploy", "node", "jenkins", "git",
    "www-data", "docker", "ubuntu", "ec2-user",
    "app", "dev", "ansible",
])
def test_dev_usernames_go_to_dev_server(username):
    assert select_profile(username, 0.9) == "dev-server"


# ── Tie-break by probability ──────────────────────────────
def test_unknown_user_high_p_goes_to_dev():
    assert select_profile("hacker", 0.90) == "dev-server"
    assert select_profile("hacker", 0.85) == "dev-server"


def test_unknown_user_low_p_goes_to_db():
    assert select_profile("hacker", 0.84) == "db-server"
    assert select_profile("hacker", 0.50) == "db-server"
    assert select_profile("hacker", 0.00) == "db-server"


# ── Edge cases ────────────────────────────────────────────
def test_empty_username_low_p():
    assert select_profile("", 0.5) == "db-server"


def test_empty_username_high_p():
    assert select_profile("", 0.9) == "dev-server"


def test_none_username():
    # should not raise
    result = select_profile(None, 0.9)  # type: ignore
    assert result in ("dev-server", "db-server")


def test_whitespace_username():
    assert select_profile("  root  ", 0.9) in ("dev-server", "db-server")
