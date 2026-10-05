"""Server-side translation for the login page.

This file is part of a modified version of NextTrace Web. NextTrace Web is
licensed under the GNU General Public License v3.0 (see LICENSE); this file is
an addition made by this fork and is distributed under the same terms.
Upstream: https://github.com/nxtrace/nexttraceweb

The main UI is translated in the browser by ``assets/js/i18n.js``. The login
page cannot use that: it renders before any script runs, and showing an
untranslated flash of English to a Chinese user would be sloppy. So the same
preference resolution is reimplemented here, reading the same
``localStorage.uiLanguage`` key via a cookie that the main page keeps in sync.

Resolution order matches the client exactly:

1. An explicit ``en`` / ``zh`` preference.
2. The browser's ``Accept-Language`` header.
3. English.
"""

from typing import Callable, Dict, Optional

DEFAULT_LOCALE = "en"
SUPPORTED_LOCALES = ("en", "zh")

# Keep in sync with the "auto" option in templates/index.html.
LOCALE_COOKIE = "ntwa_language"

DICTIONARIES: Dict[str, Dict[str, str]] = {
    "en": {
        "login.title": "Sign in",
        "login.eyebrow": "restricted access",
        "login.heading": "NextTrace Web",
        "login.subtitle": "Sign in to run traceroutes from this server.",
        "login.username": "Username",
        "login.password": "Password",
        "login.submit": "Sign in",
        "login.footnote": "Sessions are signed with the server's secret key.",
        "login.retryIn": "Retry in",
        "login.error.invalid": "Incorrect username or password.",
        "login.error.missing": "Enter both a username and a password.",
        "login.error.throttled": "Too many sign-in attempts. Please wait before trying again.",
    },
    "zh": {
        "login.title": "登录",
        "login.eyebrow": "受限访问",
        "login.heading": "NextTrace Web",
        "login.subtitle": "登录后即可从这台服务器发起路由追踪。",
        "login.username": "用户名",
        "login.password": "密码",
        "login.submit": "登录",
        "login.footnote": "会话使用服务端密钥签名。",
        "login.retryIn": "请等待",
        "login.error.invalid": "用户名或密码不正确。",
        "login.error.missing": "请输入用户名和密码。",
        "login.error.throttled": "登录尝试过于频繁，请稍后再试。",
    },
}


def normalize_locale(value: Optional[str]) -> Optional[str]:
    """Map a raw preference onto a supported locale, or None when unusable."""
    if not value:
        return None
    candidate = value.strip().lower()
    if not candidate or candidate == "auto":
        return None
    if candidate in SUPPORTED_LOCALES:
        return candidate
    # Accept full tags such as zh-CN, en-US, zh-Hans.
    primary = candidate.split("-", 1)[0]
    return primary if primary in SUPPORTED_LOCALES else None


def parse_accept_language(header: Optional[str]) -> Optional[str]:
    """Pick the best supported locale from an Accept-Language header."""
    if not header:
        return None

    ranked = []
    for index, entry in enumerate(header.split(",")):
        part = entry.strip()
        if not part:
            continue
        tag, _, raw_quality = part.partition(";")
        quality = 1.0
        raw_quality = raw_quality.strip()
        if raw_quality.startswith("q="):
            try:
                quality = float(raw_quality[2:])
            except ValueError:
                quality = 0.0
        # A wildcard tells us nothing about intent; keep it last.
        if tag.strip() == "*":
            quality = -1.0
        ranked.append((quality, -index, tag.strip().lower()))

    ranked.sort(reverse=True)
    for _quality, _order, tag in ranked:
        locale = normalize_locale(tag)
        if locale is not None:
            return locale
    return None


def resolve_locale(cookie_value: Optional[str], accept_language: Optional[str]) -> str:
    return (
        normalize_locale(cookie_value)
        or parse_accept_language(accept_language)
        or DEFAULT_LOCALE
    )


def make_translator(locale: str) -> Callable[[str], str]:
    """Return a ``t(key)`` function that falls back to English, then the key."""
    primary = DICTIONARIES.get(locale, {})
    fallback = DICTIONARIES[DEFAULT_LOCALE]

    def translate(key: str) -> str:
        return primary.get(key) or fallback.get(key) or key

    return translate
