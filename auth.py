"""Authentication for NextTrace Web.

This file is part of a modified version of NextTrace Web. NextTrace Web is
licensed under the GNU General Public License v3.0 (see LICENSE); this file is
an addition made by this fork and is distributed under the same terms.
Upstream: https://github.com/nxtrace/nexttraceweb

Multiple username/password accounts, stored either in a JSON file or inline in
an environment variable. Passwords are never stored in plaintext: each account
record holds a PBKDF2-SHA256 hash produced by ``werkzeug.security``.

Account sources, in priority order:

1. ``NTWA_USERS_FILE`` — path to a JSON file (see ``docs`` in the README).
2. ``NTWA_USERS`` — inline JSON, convenient for container env vars.

Both share one shape::

    {"alice": "<pbkdf2-hash>", "bob": "<pbkdf2-hash>"}

Generate hashes with ``python auth.py hash`` (see ``__main__`` below) so the
plaintext never has to be written down anywhere.

When no account source is configured the app falls back to locked mode: every
protected route is refused. This is deliberate — silently allowing anonymous
access because of a typo in an env var name would be a far worse failure.
"""

import hmac
import json
import logging
import os
import secrets
import time
from hashlib import sha256
from typing import Dict, Optional, Tuple

from flask import current_app, jsonify, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

SESSION_KEY = "ntwa_user"
LOGIN_ATTEMPT_WINDOW_SECONDS = 900.0
DEFAULT_MAX_LOGIN_ATTEMPTS = 10
DEFAULT_MIN_LOGIN_INTERVAL_SECONDS = 0.5

_HASH_PREFIXES = ("pbkdf2:", "scrypt:")


class AuthConfigError(RuntimeError):
    """Raised when the configured account source cannot be used at all."""


def _parse_users_payload(raw: str, source: str) -> Dict[str, str]:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AuthConfigError(f"{source} is not valid JSON: {exc}") from exc

    if not isinstance(parsed, dict):
        raise AuthConfigError(f"{source} must be a JSON object of username -> password hash")

    users: Dict[str, str] = {}
    for raw_name, raw_hash in parsed.items():
        name = str(raw_name).strip()
        if not name:
            logging.warning("Ignoring an account with an empty username from %s", source)
            continue
        if not isinstance(raw_hash, str) or not raw_hash:
            logging.warning("Ignoring account %r from %s: hash is missing", name, source)
            continue
        if not raw_hash.startswith(_HASH_PREFIXES):
            # Refuse plaintext outright rather than accepting a weak secret.
            raise AuthConfigError(
                f"Account {name!r} in {source} does not look like a hash "
                f"(expected a '{_HASH_PREFIXES[0]}' or '{_HASH_PREFIXES[1]}' prefix). "
                "Run `python auth.py hash` and store the output instead of a plaintext password."
            )
        users[name] = raw_hash
    return users


def load_users() -> Dict[str, str]:
    """Read the account table from the configured source.

    Returns an empty dict when nothing is configured, which the caller treats
    as locked mode.
    """
    path = os.environ.get("NTWA_USERS_FILE", "").strip()
    if path:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return _parse_users_payload(handle.read(), f"NTWA_USERS_FILE ({path})")
        except OSError as exc:
            raise AuthConfigError(f"cannot read NTWA_USERS_FILE at {path}: {exc}") from exc

    inline = os.environ.get("NTWA_USERS", "").strip()
    if inline:
        return _parse_users_payload(inline, "NTWA_USERS")

    return {}


def load_required() -> bool:
    """Whether authentication is configured at all."""
    return bool(load_users())


def hash_password(password: str, method: str = "pbkdf2:sha256:600000") -> str:
    return generate_password_hash(password, method=method)


def is_login_required() -> bool:
    """Whether the current deployment has authentication switched on."""
    return bool(current_app.config.get("NTWA_USERS"))


def verify_credentials(username: str, password: str) -> bool:
    """Constant-time-ish credential check against the configured account table.

    Always performs a hash comparison, even for unknown users, so that response
    timing does not reveal whether a username exists.
    """
    users: Dict[str, str] = current_app.config.get("NTWA_USERS") or {}
    stored = users.get(username)

    if stored is None:
        # Burn a comparable amount of work so the failure path looks the same.
        check_password_hash(
            "pbkdf2:sha256:600000$" + ("0" * 16) + "$" + ("0" * 64),
            password,
        )
        return False

    try:
        return check_password_hash(stored, password)
    except ValueError:
        logging.warning("Malformed password hash for account %r", username)
        return False


def current_username() -> Optional[str]:
    value = session.get(SESSION_KEY)
    return value if isinstance(value, str) and value else None


def login_user(username: str) -> None:
    session.clear()
    session[SESSION_KEY] = username
    session.permanent = False


def logout_user() -> None:
    session.clear()


def safe_redirect_target(raw: Optional[str]) -> Optional[str]:
    """Validate a ``next`` parameter, rejecting anything off-site.

    Only same-origin absolute paths are accepted. Protocol-relative URLs
    (``//evil.example``) and absolute URLs are dropped, so the login page
    cannot be turned into an open redirect.
    """
    if not raw:
        return None
    candidate = raw.strip()
    if not candidate.startswith("/"):
        return None
    if candidate.startswith("//") or candidate.startswith("/\\"):
        return None
    # A backslash anywhere lets some clients re-interpret the path as a host.
    if "\\" in candidate:
        return None
    return candidate


def _client_key() -> str:
    return request.remote_addr or "unknown"


def _attempt_store() -> Dict[str, list]:
    return current_app.config.setdefault("NTWA_LOGIN_ATTEMPTS", {})


def throttle_login() -> Optional[float]:
    """Enforce a minimum interval and a cap per client address.

    Returns the number of seconds to wait when the caller should be refused,
    or None when the attempt may proceed.
    """
    now = time.monotonic()
    min_interval = current_app.config.get("NTWA_MIN_LOGIN_INTERVAL_SECONDS", DEFAULT_MIN_LOGIN_INTERVAL_SECONDS)
    max_attempts = current_app.config.get("NTWA_MAX_LOGIN_ATTEMPTS", DEFAULT_MAX_LOGIN_ATTEMPTS)
    key = _client_key()
    store = _attempt_store()

    timestamps = [t for t in store.get(key, []) if now - t < LOGIN_ATTEMPT_WINDOW_SECONDS]

    if timestamps and min_interval > 0:
        remaining = min_interval - (now - timestamps[-1])
        if remaining > 0:
            store[key] = timestamps
            return remaining

    if max_attempts > 0 and len(timestamps) >= max_attempts:
        retry_after = LOGIN_ATTEMPT_WINDOW_SECONDS - (now - timestamps[0])
        store[key] = timestamps
        return max(0.0, retry_after)

    timestamps.append(now)
    store[key] = timestamps
    return None


def clear_login_attempts() -> None:
    _attempt_store().pop(_client_key(), None)


def wants_json() -> bool:
    """Whether the caller is an API/Socket.IO client rather than a browser.

    Only an *explicit* preference for JSON qualifies. A bare ``Accept: */*``
    (which is what curl and many HTTP clients send) must fall through to the
    redirect path, otherwise a human typing the URL into a browser could be
    handed a raw 401 body instead of the login form.
    """
    if request.path.startswith("/api/") or request.path.startswith("/socket.io/"):
        return True

    accept = request.accept_mimetypes
    json_quality = accept["application/json"]
    html_quality = accept["text/html"]

    # An explicit JSON preference that beats HTML, with no HTML at all behind it.
    return json_quality > 0 and json_quality > html_quality and html_quality == 0


def unauthorized_response():
    """Redirect browsers to the login page; hand API clients a 401."""
    if wants_json():
        return jsonify({"status": "error", "code": "unauthorized"}), 401

    target = request.full_path if request.query_string else request.path
    target = safe_redirect_target(target) or "/"
    return redirect(url_for("login", next=target))


def locked_out_response():
    """Refusal shown when no account source is configured.

    503 rather than 401: this is a server-side misconfiguration, not a
    credential problem, and no password would fix it.
    """
    message = (
        "Authentication is not configured on this server. "
        "Set NTWA_USERS or NTWA_USERS_FILE and restart."
    )
    if wants_json():
        return jsonify({"status": "error", "code": "auth_not_configured", "message": message}), 503
    return message, 503, {"Content-Type": "text/plain; charset=utf-8"}


def require_auth_guard():
    """``before_request`` hook. Returns a response to short-circuit, else None.

    Fails closed: when no account source is configured the app refuses every
    protected route rather than silently serving anonymous traffic. An
    unconfigured deployment is a misconfiguration, and treating it as "open"
    would turn a typo in an env var name into an unprotected traceroute box.
    """
    path = request.path

    # The login page and its assets must stay reachable, otherwise a
    # logged-out visitor could never get back in. Read the prefix from the app
    # instead of hardcoding /static/, so changing static_url_path cannot
    # silently lock the stylesheet out of the login page.
    static_prefix = (current_app.static_url_path or "/static").rstrip("/") + "/"
    if path in ("/login", "/favicon.ico") or path.startswith(static_prefix):
        return None

    if current_username() is not None:
        return None

    if not is_login_required():
        logging.error(
            "Refusing %s: authentication is not configured. "
            "Set NTWA_USERS or NTWA_USERS_FILE to enable the app.",
            path,
        )
        return locked_out_response()

    # Opt-in escape hatch for uptime probes. Off by default, so enabling
    # authentication never silently leaves an endpoint open.
    if path == "/healthz" and current_app.config.get("NTWA_HEALTHZ_PUBLIC"):
        return None

    return unauthorized_response()


def _fingerprint(value: str) -> str:
    return sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def generate_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def constant_time_equals(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)


def _cli_hash(argv: list) -> int:
    import getpass

    if len(argv) >= 1 and argv[0] not in ("-", "--stdin"):
        password = argv[0]
    else:
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm:  ")
        if password != confirm:
            print("Passwords do not match.")
            return 1

    if not password:
        print("Refusing to hash an empty password.")
        return 1

    print(hash_password(password))
    return 0


def _cli_check(argv: list) -> int:
    """Verify a password against a stored hash, for debugging lockouts."""
    if len(argv) != 2:
        print("usage: python auth.py check <hash> <password>")
        return 2
    stored, password = argv
    print("match" if check_password_hash(stored, password) else "no match")
    return 0


def _cli_users(argv: list) -> int:
    """Print the configured account names and hashes (no plaintext ever)."""
    try:
        users = load_users()
    except AuthConfigError as exc:
        print(f"error: {exc}")
        return 1

    if not users:
        print("No accounts configured (locked mode: all protected routes refused).")
        return 0

    width = max(len(name) for name in users)
    for name, stored in sorted(users.items()):
        print(f"{name.ljust(width)}  {stored[:28]}…  fp={_fingerprint(stored)}")
    return 0


def main(argv: Optional[list] = None) -> int:
    import sys

    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(__doc__)
        print("Commands:")
        print("  hash [password]   Hash a password (prompts when omitted)")
        print("  check <h> <pw>    Verify a password against a hash")
        print("  users             List configured accounts")
        return 0

    command, rest = args[0], args[1:]
    handlers = {"hash": _cli_hash, "check": _cli_check, "users": _cli_users}

    handler = handlers.get(command)
    if handler is None:
        print(f"unknown command: {command}")
        return 2
    return handler(rest)


if __name__ == "__main__":
    raise SystemExit(main())
