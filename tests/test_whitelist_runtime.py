"""Tests for DB-backed whitelist in-memory cache."""
from runtime import whitelist as wl


def test_refresh_and_match():
    wl.reset_whitelist_cache()
    wl.refresh_cache(["192.168.1.108", "10.0.0.1"])
    assert wl.is_whitelisted("192.168.1.108")
    assert not wl.is_whitelisted("203.0.113.1")


def test_normalizes_ip_strings():
    wl.reset_whitelist_cache()
    wl.refresh_cache(["192.168.1.108 "])
    assert wl.is_whitelisted("192.168.1.108")


def test_invalid_ip_not_whitelisted():
    wl.reset_whitelist_cache()
    wl.refresh_cache(["10.0.0.1"])
    assert not wl.is_whitelisted("not-an-ip")
