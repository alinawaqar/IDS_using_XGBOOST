"""
Single-user authentication for the IDS dashboard/API.

Design:
- The password is no longer required to be pre-set via an env var before
  the server can start. Instead, its bcrypt hash lives in a small local
  file (IDS_PASSWORD_FILE, default data/password.hash). If that file
  doesn't exist yet, the API is in "needs setup" mode: the frontend shows
  a one-time "create your password" screen instead of a login screen.
  Once a password is set, /auth/setup permanently refuses to run again --
  it can never be used to silently reset an existing password.
- Backward compatibility: if you already have IDS_PASSWORD_HASH set as an
  env var (from before this change), it's honored automatically and
  "needs setup" is treated as already satisfied -- nothing breaks for an
  existing deployment that configured it that way.
- On successful login, the server issues a signed, time-limited token
  (itsdangerous) and sets it as an httpOnly cookie. The browser sends it
  back automatically on every request; your React code never touches it.
- live_ids.py talks to /predict-csv from the same machine, not from a
  browser, so it can't hold a browser cookie. It authenticates instead with
  a separate long-lived shared secret (IDS_INTERNAL_KEY) sent as a header.
  This keeps "a human is logged into the dashboard" and "my own capture
  script is allowed to post flow data" as two different, independently
  revocable checks.
- SESSION_SECRET signs the cookie so it can't be forged or edited. Losing
  this secret (or rotating it) invalidates all issued sessions -- that's a
  feature, not a bug, if you ever suspect compromise. This one still must
  be set via env var, since unlike the password it's never user-facing.
"""

import os
import time
from dotenv import load_dotenv

load_dotenv()
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from passlib.context import CryptContext
from fastapi import Request, Response, HTTPException, Depends

# ------------------------------------------------------------------
# Config
# ------------------------------------------------------------------

SESSION_SECRET = os.environ.get("IDS_SESSION_SECRET")
INTERNAL_KEY = os.environ.get("IDS_INTERNAL_KEY")
SESSION_TTL_SECONDS = int(os.environ.get("IDS_SESSION_TTL", str(12 * 3600)))  # 12h default
COOKIE_NAME = "ids_session"
# Only send the cookie over HTTPS once you're actually running behind TLS.
# Keep this True in production; set IDS_COOKIE_SECURE=false only for local
# HTTP testing.
COOKIE_SECURE = os.environ.get("IDS_COOKIE_SECURE", "true").lower() != "false"

# Where the password hash is stored once someone completes setup.
PASSWORD_FILE = os.environ.get("IDS_PASSWORD_FILE", os.path.join("data", "password.hash"))

# Legacy path: an env var set before this change still works, and counts
# as "setup already done" so existing deployments aren't disrupted.
_LEGACY_ENV_HASH = os.environ.get("IDS_PASSWORD_HASH")

if not SESSION_SECRET:
    raise RuntimeError(
        "IDS_SESSION_SECRET must be set. Generate one with: "
        "python -c \"import secrets; print(secrets.token_hex(32))\""
    )

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
_serializer = URLSafeTimedSerializer(SESSION_SECRET, salt="ids-session")


def _read_stored_hash():
    """Returns the current password hash, from the legacy env var if set,
    otherwise from the password file, otherwise None if no password has
    ever been configured."""
    if _LEGACY_ENV_HASH:
        return _LEGACY_ENV_HASH
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    return None


def needs_setup() -> bool:
    return _read_stored_hash() is None


def set_password(plaintext: str):
    """Writes the password hash for the first time. Refuses to run if a
    password already exists (env var or file) -- setup is one-time only,
    by design, so it can never be used to silently reset someone's
    password later. Use a proper change-password flow for that instead."""
    if not needs_setup():
        raise HTTPException(status_code=403, detail="A password is already configured.")
    os.makedirs(os.path.dirname(PASSWORD_FILE) or ".", exist_ok=True)
    hashed = _pwd_ctx.hash(plaintext)
    with open(PASSWORD_FILE, "w", encoding="utf-8") as f:
        f.write(hashed)


# ------------------------------------------------------------------
# Very small brute-force guard: 5 bad attempts -> 60s lockout, per process.
# Fine for a single-user box; put this behind a real rate limiter (e.g.
# nginx/Caddy limit_req, or slowapi) if you ever expose login beyond your LAN.
# ------------------------------------------------------------------

_failed_attempts: dict[str, list[float]] = {}
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 60


def _check_lockout(client_ip: str):
    now = time.time()
    attempts = [t for t in _failed_attempts.get(client_ip, []) if now - t < LOCKOUT_SECONDS]
    _failed_attempts[client_ip] = attempts
    if len(attempts) >= MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try again shortly.")


def _record_failure(client_ip: str):
    _failed_attempts.setdefault(client_ip, []).append(time.time())


def verify_password(plaintext: str) -> bool:
    stored = _read_stored_hash()
    if stored is None:
        return False
    return _pwd_ctx.verify(plaintext, stored)


def issue_session_cookie(response: Response):
    token = _serializer.dumps({"authenticated": True})
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",  # same-origin only -- this is also your CSRF defense
    )


def clear_session_cookie(response: Response):
    response.delete_cookie(COOKIE_NAME)


def _valid_session_cookie(request: Request) -> bool:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return False
    try:
        _serializer.loads(token, max_age=SESSION_TTL_SECONDS)
        return True
    except (BadSignature, SignatureExpired):
        return False


def require_user(request: Request):
    """Dependency for browser-facing routes: dashboard, evidence, live controls."""
    if not _valid_session_cookie(request):
        raise HTTPException(status_code=401, detail="Not authenticated.")


def require_user_or_internal(request: Request):
    """
    Dependency for /predict-csv, which is called both by a logged-in human
    (manual CSV upload from the dashboard) and by live_ids.py running as a
    local background process (no browser session to hold a cookie).
    """
    if _valid_session_cookie(request):
        return
    supplied_key = request.headers.get("x-internal-key")
    if INTERNAL_KEY and supplied_key and supplied_key == INTERNAL_KEY:
        return
    raise HTTPException(status_code=401, detail="Not authenticated.")