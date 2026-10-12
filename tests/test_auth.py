"""Unit tests for passwords, tokens and the tenant rule (no database needed)."""
import base64
import json
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import HTTPException

from app import auth
from app.auth import Claims, check_login, create_token, decode_token, hash_password, resolve_tenant, verify_password
from app.config import settings

VIEWER_A = Claims(sub="viewerA", role="viewer", tenant="demoA")
ADMIN = Claims(sub="admin", role="admin", tenant="demoA")


def test_password_hash_roundtrip_and_salted():
    h1, h2 = hash_password("s3cret"), hash_password("s3cret")
    assert h1 != h2  # random salt per hash
    assert verify_password("s3cret", h1) and not verify_password("wrong", h1)
    assert "s3cret" not in h1


def test_check_login_unknown_user_is_false():
    assert check_login("anything", None) is False


def test_token_roundtrip():
    assert decode_token(create_token(VIEWER_A)) == VIEWER_A


def test_expired_token_rejected():
    old = create_token(VIEWER_A, now=datetime.now(timezone.utc) - timedelta(minutes=settings.jwt_expire_minutes + 1))
    with pytest.raises(HTTPException) as e:
        decode_token(old)
    assert e.value.status_code == 401


def test_token_signed_with_other_secret_rejected():
    forged = jwt.encode({"sub": "x", "role": "admin", "tenant": "demoB",
                         "exp": datetime.now(timezone.utc) + timedelta(hours=1)}, "x" * 32, algorithm="HS256")
    with pytest.raises(HTTPException):
        decode_token(forged)


def test_tampered_payload_rejected():
    h, p, s = create_token(VIEWER_A).split(".")
    claims = json.loads(base64.urlsafe_b64decode(p + "=="))
    claims |= {"tenant": "demoB", "role": "admin"}
    p2 = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    with pytest.raises(HTTPException):
        decode_token(f"{h}.{p2}.{s}")


def test_alg_none_rejected():
    b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")  # noqa: E731
    token = b({"alg": "none", "typ": "JWT"}) + "." + b({"sub": "x", "role": "admin", "tenant": "demoB", "exp": 9999999999}) + "."
    with pytest.raises(HTTPException):
        decode_token(token)


def test_token_missing_tenant_claim_rejected():
    t = jwt.encode({"sub": "x", "role": "viewer", "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
                   settings.jwt_secret, algorithm="HS256")
    with pytest.raises(HTTPException):
        decode_token(t)


# --- the tenant rule ---------------------------------------------------------

def test_viewer_gets_own_tenant_by_default():
    assert resolve_tenant(VIEWER_A, None) == "demoA"
    assert resolve_tenant(VIEWER_A, "demoA") == "demoA"


def test_viewer_cannot_switch_tenant():
    with pytest.raises(HTTPException) as e:
        resolve_tenant(VIEWER_A, "demoB")
    assert e.value.status_code == 403


def test_admin_can_switch_tenant():
    assert resolve_tenant(ADMIN, None) == "demoA"
    assert resolve_tenant(ADMIN, "demoB") == "demoB"


@pytest.mark.parametrize("secret", ["", "short", "change-me-to-a-long-random-string"])
def test_weak_jwt_secret_refused_at_startup(monkeypatch, secret):
    monkeypatch.setattr(settings, "jwt_secret", secret)
    with pytest.raises(RuntimeError):
        auth.check_jwt_secret()
