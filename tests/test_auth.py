"""Tests for the login gate: routing, session handling, and bypass resistance.

Run with:  python -m unittest tests.test_auth -v
"""

import importlib
import json
import os
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

GOOD_PASSWORD = "correct-horse-battery-staple"
BAD_PASSWORD = "wrong-password"

# The account table is derived from GOOD_PASSWORD so the two can never drift.
ACCOUNTS = {"alice": GOOD_PASSWORD, "bob": "bob-secret"}


def build_users_env():
    import auth as auth_module

    return json.dumps(
        {name: auth_module.hash_password(pw) for name, pw in ACCOUNTS.items()}
    )


class AuthTestCase(unittest.TestCase):
    """Boots the app fresh per test with a known account table."""

    users_json = None

    @classmethod
    def setUpClass(cls):
        cls.users_json = build_users_env()

    def setUp(self):
        self.env = mock.patch.dict(
            os.environ,
            {
                "NTWA_USERS": self.users_json,
                "NTWA_MAX_LOGIN_ATTEMPTS": "0",
                "NTWA_MIN_LOGIN_INTERVAL_SECONDS": "0",
            },
            clear=False,
        )
        self.env.start()

        for name in ("app", "auth", "login_i18n"):
            if name in sys.modules:
                del sys.modules[name]

        self.app_module = importlib.import_module("app")
        self.app_module.app.config.update(TESTING=True)
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.env.stop()

    def login(self, username="alice", password=GOOD_PASSWORD, follow=False):
        return self.client.post(
            "/login",
            data={"username": username, "password": password},
            follow_redirects=follow,
        )

    # ---------- unauthenticated access ----------

    def test_root_redirects_to_login(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_login_redirect_preserves_destination(self):
        response = self.client.get("/api/devices")
        self.assertEqual(response.status_code, 401)
        body = response.get_json()
        self.assertEqual(body["code"], "unauthorized")

    def test_html_request_does_not_get_json(self):
        response = self.client.get("/")
        self.assertNotIn("application/json", response.headers.get("Content-Type", ""))

    # ---------- login flow ----------

    def test_login_page_renders(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'name="username"', response.data)
        self.assertIn(b'name="password"', response.data)

    def test_login_page_stylesheet_is_actually_served(self):
        """The login page must not render unstyled.

        The static folder is ``assets`` and nginx proxies ``/assets/...``, so the
        default ``/static`` URL prefix would 404 every stylesheet while still
        producing a 200 login page. Assert the rendered href resolves.
        """
        page = self.client.get("/login")
        self.assertEqual(page.status_code, 200)

        match = re.search(rb'href="([^"]*login\.css)"', page.data)
        self.assertIsNotNone(match, "login page does not reference login.css")

        href = match.group(1).decode()
        asset = self.client.get(href)
        self.assertEqual(asset.status_code, 200, f"{href} is not served")
        self.assertGreater(len(asset.data), 0)

    def test_static_assets_are_not_blocked_by_auth(self):
        """A logged-out visitor must still be able to load the login stylesheet."""
        response = self.client.get("/assets/css/login.css")
        self.assertEqual(response.status_code, 200)

    def test_valid_credentials_grant_access(self):
        response = self.login()
        self.assertEqual(response.status_code, 302)

        after = self.client.get("/")
        self.assertEqual(after.status_code, 200)
        self.assertIn(b"NextTrace", after.data)

    def test_invalid_password_is_rejected(self):
        response = self.client.post(
            "/login", data={"username": "alice", "password": BAD_PASSWORD}
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"login.error.invalid", response.data)

        self.assertEqual(self.client.get("/").status_code, 302)

    def test_unknown_user_is_rejected(self):
        response = self.client.post(
            "/login", data={"username": "nobody", "password": GOOD_PASSWORD}
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"login.error.invalid", response.data)

    def test_missing_fields_reported(self):
        response = self.client.post("/login", data={"username": "alice", "password": ""})
        self.assertIn(b"login.error.missing", response.data)

    def test_session_survives_across_requests(self):
        self.login()
        for path in ("/", "/api/devices"):
            with self.subTest(path=path):
                self.assertNotEqual(self.client.get(path).status_code, 302)

    def test_logout_revokes_access(self):
        self.login()
        self.assertEqual(self.client.get("/").status_code, 200)

        self.client.get("/logout")
        self.assertEqual(self.client.get("/").status_code, 302)

    def test_logged_in_visiting_login_is_redirected(self):
        self.login()
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("/login", response.headers["Location"])

    # ---------- redirect safety ----------

    def test_next_parameter_is_honoured_for_safe_paths(self):
        response = self.client.post(
            "/login",
            data={"username": "alice", "password": GOOD_PASSWORD, "next": "/api/devices"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/api/devices"))

    def test_protocol_relative_next_is_rejected(self):
        for hostile in ("//evil.example", "https://evil.example", "//evil.example/path"):
            with self.subTest(next=hostile):
                response = self.client.post(
                    "/login",
                    data={"username": "alice", "password": GOOD_PASSWORD, "next": hostile},
                )
                location = response.headers["Location"]
                self.assertNotIn("evil.example", location)

    def test_backslash_next_is_rejected(self):
        response = self.client.post(
            "/login",
            data={"username": "alice", "password": GOOD_PASSWORD, "next": "/\\evil.example"},
        )
        self.assertNotIn("evil.example", response.headers["Location"])

    # ---------- brute force ----------

    def test_login_throttling_kicks_in(self):
        self.app_module.app.config["NTWA_MAX_LOGIN_ATTEMPTS"] = 3
        self.app_module.app.config["NTWA_MIN_LOGIN_INTERVAL_SECONDS"] = 0

        statuses = []
        for _ in range(5):
            response = self.client.post(
                "/login", data={"username": "alice", "password": BAD_PASSWORD}
            )
            statuses.append(response.status_code)

        self.assertIn(429, statuses)

    def test_successful_login_clears_attempt_counter(self):
        # A failed attempt first, so there is something to clear.
        self.client.post("/login", data={"username": "alice", "password": BAD_PASSWORD})
        store_before = self.app_module.app.config["NTWA_LOGIN_ATTEMPTS"]
        self.assertTrue(store_before, "a failed attempt should be recorded")

        self.login()
        store_after = self.app_module.app.config["NTWA_LOGIN_ATTEMPTS"]
        self.assertEqual(store_after, {}, "a successful login must reset the counter")


class AuthModuleTestCase(unittest.TestCase):
    """Unit-level checks that do not need a booted app."""

    @classmethod
    def setUpClass(cls):
        if "auth" in sys.modules:
            del sys.modules["auth"]
        cls.auth = importlib.import_module("auth")

    def test_hash_roundtrip(self):
        stored = self.auth.hash_password("hunter2")
        self.assertTrue(stored.startswith("pbkdf2:"))
        from werkzeug.security import check_password_hash

        self.assertTrue(check_password_hash(stored, "hunter2"))
        self.assertFalse(check_password_hash(stored, "hunter3"))

    def test_plaintext_accounts_are_refused(self):
        with self.assertRaises(self.auth.AuthConfigError):
            self.auth._parse_users_payload('{"alice": "plaintext"}', "test")

    def test_empty_username_is_skipped(self):
        stored = self.auth.hash_password("x")
        payload = json.dumps({"": stored, "  ": stored, "ok": stored})
        users = self.auth._parse_users_payload(payload, "test")
        self.assertEqual(list(users), ["ok"])

    def test_malformed_json_is_refused(self):
        with self.assertRaises(self.auth.AuthConfigError):
            self.auth._parse_users_payload("{not json", "test")

    def test_non_object_json_is_refused(self):
        with self.assertRaises(self.auth.AuthConfigError):
            self.auth._parse_users_payload('["a", "b"]', "test")

    def test_safe_redirect_target(self):
        cases = {
            "/dashboard": "/dashboard",
            "/a/b?c=d": "/a/b?c=d",
            "//evil.example": None,
            "https://evil.example": None,
            "/\\evil.example": None,
            "/a\\b": None,
            "": None,
            None: None,
            "  ": None,
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(self.auth.safe_redirect_target(raw), expected)


class LoginI18nTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if "login_i18n" in sys.modules:
            del sys.modules["login_i18n"]
        cls.i18n = importlib.import_module("login_i18n")

    def test_explicit_cookie_wins(self):
        self.assertEqual(
            self.i18n.resolve_locale("zh", "en-US,en;q=0.9"),
            "zh",
        )

    def test_accept_language_used_when_cookie_absent(self):
        self.assertEqual(
            self.i18n.resolve_locale(None, "zh-CN,zh;q=0.9,en;q=0.8"),
            "zh",
        )

    def test_quality_values_respected(self):
        self.assertEqual(
            self.i18n.resolve_locale(None, "en;q=0.3,zh;q=0.9"),
            "zh",
        )

    def test_wildcard_does_not_override_later_specific_tag(self):
        self.assertEqual(self.i18n.resolve_locale(None, "*"), "en")

    def test_defaults_to_english(self):
        self.assertEqual(self.i18n.resolve_locale(None, None), "en")
        self.assertEqual(self.i18n.resolve_locale("auto", ""), "en")

    def test_unsupported_locale_falls_back(self):
        self.assertEqual(self.i18n.resolve_locale("de", None), "en")

    def test_translator_covers_every_key_in_both_locales(self):
        keys = set(self.i18n.DICTIONARIES["en"])
        self.assertEqual(keys, set(self.i18n.DICTIONARIES["zh"]))
        self.assertIn("login.error.invalid", keys)
        self.assertIn("login.error.throttled", keys)

    def test_unknown_key_returns_key_itself(self):
        t = self.i18n.make_translator("en")
        self.assertEqual(t("nope.not.here"), "nope.not.here")

    def test_both_locales_translate_login_submit(self):
        self.assertEqual(self.i18n.make_translator("en")("login.submit"), "Sign in")
        self.assertEqual(self.i18n.make_translator("zh")("login.submit"), "登录")


class SocketAuthTestCase(unittest.TestCase):
    """The socket must not be reachable without a session."""

    @classmethod
    def setUpClass(cls):
        cls.users_json = build_users_env()

    def setUp(self):
        self.env = mock.patch.dict(
            os.environ, {"NTWA_USERS": self.users_json}, clear=False
        )
        self.env.start()
        for name in ("app", "auth", "login_i18n"):
            if name in sys.modules:
                del sys.modules[name]
        self.app_module = importlib.import_module("app")
        self.app_module.app.config.update(TESTING=True)

    def tearDown(self):
        self.env.stop()

    def test_socket_connect_without_session_is_refused(self):
        client = self.app_module.socketio.test_client(self.app_module.app)
        self.assertFalse(client.is_connected(), "anonymous socket must be refused")

    def test_socket_connect_with_session_succeeds(self):
        flask_client = self.app_module.app.test_client()
        flask_client.post(
            "/login", data={"username": "alice", "password": GOOD_PASSWORD}
        )
        # Reuse the authenticated session cookie for the socket handshake.
        cookie = flask_client.get_cookie("session")
        self.assertIsNotNone(cookie, "login should have set a session cookie")

        client = self.app_module.socketio.test_client(
            self.app_module.app,
            flask_test_client=flask_client,
        )
        self.assertTrue(client.is_connected(), "authenticated socket should connect")


class LockedModeTestCase(unittest.TestCase):
    """With no accounts configured the app must refuse, not open up."""

    def setUp(self):
        self.clean_env = mock.patch.dict(os.environ, {}, clear=False)
        self.clean_env.start()
        for key in ("NTWA_USERS", "NTWA_USERS_FILE"):
            os.environ.pop(key, None)

        for name in ("app", "auth", "login_i18n"):
            if name in sys.modules:
                del sys.modules[name]
        self.app_module = importlib.import_module("app")
        self.app_module.app.config.update(TESTING=True)
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        self.clean_env.stop()

    def test_all_protected_routes_refused(self):
        # 503 (not 401): an unconfigured server is misconfigured, and no
        # credential would get you in.
        self.assertEqual(self.client.get("/").status_code, 503)
        self.assertEqual(self.client.get("/api/devices").status_code, 503)

    def test_refusal_explains_the_misconfiguration(self):
        response = self.client.get("/api/devices")
        body = response.get_json()
        self.assertEqual(body["code"], "auth_not_configured")
        self.assertIn("NTWA_USERS", body["message"])

    def test_healthz_protected_by_default(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 503)

    def test_healthz_can_be_opened_explicitly(self):
        self.app_module.app.config["NTWA_USERS"] = {"alice": "pbkdf2:sha256:600000$x$" + "0" * 64}
        self.app_module.app.config["NTWA_HEALTHZ_PUBLIC"] = True
        response = self.client.get("/healthz")
        self.assertIn(response.status_code, (200, 503))
        # Still refused for the anonymous user on any *other* route.
        self.assertEqual(self.client.get("/").status_code, 302)

    def test_login_page_refuses_when_locked(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 503)

    def test_anonymous_access_denied_on_socket(self):
        client = self.app_module.socketio.test_client(self.app_module.app)
        self.assertFalse(client.is_connected())


if __name__ == "__main__":
    unittest.main(verbosity=2)
