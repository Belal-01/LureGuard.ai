"""Core API security: ingest token, admin token, thresholds."""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials


def test_verify_ingest_token_rejects_missing(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("INGEST_TOKEN", "secret-ingest")
    monkeypatch.setenv("INGEST_ALLOW_UNAUTHENTICATED", "false")

    from api.ingest_auth import verify_ingest_token

    with pytest.raises(HTTPException) as exc:
        verify_ingest_token(x_lureguard_token=None)
    assert exc.value.status_code == 401


def test_verify_ingest_token_accepts_match(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("INGEST_TOKEN", "secret-ingest")
    monkeypatch.setenv("INGEST_ALLOW_UNAUTHENTICATED", "false")

    from api.ingest_auth import verify_ingest_token

    verify_ingest_token(x_lureguard_token="secret-ingest")


def test_verify_ingest_token_allows_when_unconfigured(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("INGEST_TOKEN", raising=False)
    monkeypatch.setenv("INGEST_ALLOW_UNAUTHENTICATED", "true")

    from api.ingest_auth import verify_ingest_token

    verify_ingest_token(x_lureguard_token=None)


def test_admin_verify_token_fail_closed(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("ADMIN_TOKEN", raising=False)

    from api.admin_api import _verify_token

    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="anything")
    with pytest.raises(HTTPException) as exc:
        _verify_token(creds)
    assert exc.value.status_code == 503


def test_admin_verify_token_accepts_match(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ADMIN_TOKEN", "admin-secret")

    from api.admin_api import _verify_token

    _verify_token(HTTPAuthorizationCredentials(scheme="Bearer", credentials="admin-secret"))


def test_update_thresholds_rejects_invalid_range(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ADMIN_TOKEN", "admin-secret")

    from api.admin_api import update_thresholds

    with pytest.raises(HTTPException) as exc:
        update_thresholds(t1=0.9, t2=0.5, _=None)
    assert exc.value.status_code == 422
