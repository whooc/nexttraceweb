<div align="center">

<img src="https://github.com/nxtrace/NTrace-core/raw/main/assets/logo.png" height="200px" alt="NextTrace Logo"/>

# NEXTTRACE WEB

A lightweight web API server for NextTrace — run visual traceroutes from your browser.

<div align="center">

[![Docker Pulls](https://img.shields.io/docker/pulls/tsosc/nexttraceweb)](https://hub.docker.com/r/tsosc/nexttraceweb)
[![License](https://img.shields.io/github/license/nxtrace/nexttraceweb)](LICENSE)

[中文](README.zh-CN.md) | **English**

</div>

</div>

---

<img width="1440" alt="NextTrace Web Interface" src="https://github.com/tsosunchia/nexttracewebapi/assets/59512455/798554e2-190e-4425-9527-3a11708dafd8">

<p align="center">
  <img width="443" alt="IP Selection Dialog" src="https://github.com/tsosunchia/nexttracewebapi/assets/59512455/1eb4b6ce-3ed9-4728-be85-fbdabc5803bd">
  <img width="721" alt="Traceroute Results" src="https://github.com/tsosunchia/nexttracewebapi/assets/59512455/a0563bfc-37a8-417a-89bf-3ab87ef44d6d">
</p>

---

## Overview

NextTrace Web is a spin-off of the [NextTrace](https://github.com/nxtrace/NTrace-core) project. It provides a simple web frontend and API server so you can run traceroutes and visualize results — including hop, IP, ASN, geolocation, domain, packet loss, and latency stats — entirely from your browser.

> **Reverse proxy note:** This project uses WebSocket as its communication protocol. If you configure a reverse proxy, please refer to the Nginx config included in this repository. The provided Docker image already has Nginx reverse proxy built in.

*Inspired by [PING.PE](https://ping.pe) — thanks for years of keeping that service alive and giving the community such a great reference.*

---

## Interface Theme

This fork restyles the frontend with a neutral dark theme. Only the presentation layer changed: `assets/css/m.css` and the heatmap color ramps in `assets/js/mtr-agg.js`. No DOM ids, i18n keys, English/Chinese copy, or table markup were touched, so the upstream test suite still passes unmodified.

| | Upstream | This fork |
|---|---|---|
| Page background | `#030704` (dark green) | `#0e1117` (neutral dark blue-grey) |
| Accent | `#4fdd73` (fluorescent green) | `#4d9ef7` (blue) |
| Table header | green gradient bar | flat `#1a2230` |
| Latency heatmap | pure red channel ramp | teal → amber → brick ramp |
| Card treatment | translucent + blur + heavy shadow | solid surface + hairline border |

The heatmap ramps are sampled continuously rather than clamped per-channel, so the gradient stays smooth across the whole latency range. Numeric columns are right-aligned with tabular figures, and a fixed light foreground color is applied to those cells so the inline background stays legible at every step of the ramp.

---

## How To Use

### Docker (Recommended)

```bash
docker pull tsosc/nexttraceweb
docker run --network host -d --privileged --name ntwa tsosc/nexttraceweb 127.0.0.1:30080
# Visit http://127.0.0.1:30080
```

Expose the service to the Internet through your own reverse proxy or gateway.

**This fork ships a built-in login page and refuses to serve anything until you configure at least one account.** See [Authentication](#authentication) below — the container will otherwise return `503 auth_not_configured` for every route.

### Custom Address & Port

Pass an address/port argument to `docker run` to override the default:

```bash
# Bind to localhost only
docker run --network host -d --privileged --name ntwa tsosc/nexttraceweb 127.0.0.1:30080

# Listen on all IPs, port 80
docker run --network host -d --privileged --name ntwa tsosc/nexttraceweb 80

# Listen on IPv6 loopback
docker run --network host -d --privileged --name ntwa tsosc/nexttraceweb [::1]:30080
```

## Interface Language

The UI ships English and Simplified Chinese. The selector in the page header defaults to **Auto**, which follows the browser's `Accept-Language` preference; pick `English` or `中文` to pin one. The choice is stored in `localStorage` under `uiLanguage`.

The separate **Geo Data Language** option inside the settings drawer is unrelated — it is passed straight to `nexttrace` and controls the language of geolocation data, not the interface.

## Sub-path Deployment

All assets, the `/api/devices` endpoint, and the Socket.IO path are resolved relative to the page's own directory, so the app can be mounted under a sub-path. The outer proxy must **strip the prefix** (note the trailing slash on both `location` and `proxy_pass`) and redirect the prefix without a trailing slash:

```nginx
# In the http block. $connection_upgrade is not a built-in variable:
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

# In the server block. https://example.com/tools/nexttrace/ maps to the container root:
location = /tools/nexttrace {
    return 301 /tools/nexttrace/$is_args$args;
}

location /tools/nexttrace/ {
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_pass http://127.0.0.1:30080/;
}
```

Both trailing slashes matter. Drop the one on `proxy_pass` and the backend receives `/tools/nexttrace/...`, for which it has no route. The 301 covers visitors who leave the trailing slash out of the address bar: the browser resolves relative references against the parent directory, so the assets would be fetched from `/tools/assets/...` and the page would render unstyled.

## Runtime Notes

- Health endpoint: `GET /healthz`
- The container now exits when `gunicorn` or `nginx` dies, so supervisors can restart it instead of leaving a half-dead process tree behind.
- `nexttrace_error` is now a structured payload with `code` and `message`, plus `retry_after_seconds` on rate-limit and capacity rejections.

## Security Defaults

- **Configure at least one account** (`NTWA_USERS` / `NTWA_USERS_FILE`). Until then the app is locked and serves `503`. See [Authentication](#authentication).
- Configure `NTWA_SECRET_KEY` in production. If omitted, the app generates a temporary random key and logs a warning.
- Recommended: set `NTWA_TRUSTED_HOSTS=trace.example.com` behind a reverse proxy.
- Set `NTWA_SESSION_COOKIE_SECURE=true` only when the outer proxy serves HTTPS.
- Abuse controls:
  - `NTWA_MIN_START_INTERVAL_SECONDS`
  - `NTWA_MAX_ACTIVE_TRACES`
  - `NTWA_TRACE_IDLE_TIMEOUT_SECONDS`
  - `NTWA_TRACE_MAX_DURATION_SECONDS`

## Authentication

This fork adds a built-in login page. Every route is protected by default — the page itself, `/api/devices`, `/healthz`, static assets only excepted, and the Socket.IO handshake (which re-checks the session independently, because the HTTP `before_request` hook does not cover Engine.IO upgrades).

> **Fail-closed by design.** With no accounts configured, the app refuses every protected route with `503` and an `auth_not_configured` body rather than quietly serving anonymous traffic. If you upgrade and see 503s, you have not configured an account yet — that is the intended state, not a bug.

### 1. Generate password hashes

Passwords are stored as PBKDF2-SHA256 hashes; the app refuses to start with a plaintext value in the account map. Use the bundled CLI so the plaintext is never written down:

```bash
# Local checkout
python auth.py hash 'your-password'

# Inside the container
docker exec <container> python /app/auth.py hash 'your-password'
```

Other subcommands: `python auth.py check <user>` (prompts for a password and verifies it), `python auth.py users` (lists configured accounts).

### 2. Provide the accounts

Two sources, checked in this order:

**`NTWA_USERS_FILE`** — path to a JSON file (mounted secret, better for bare-metal):

```json
{
  "alice": "pbkdf2:sha256:600000$03hLeQFFx28Rdv1G$462656e5...",
  "bob": "pbkdf2:sha256:600000$Qn7Kd2mLx91Tsv4B$9b3f1a7c..."
}
```

**`NTWA_USERS`** — the same JSON inline, convenient for container env vars:

```bash
docker run --network host -d --privileged --name ntwa \
  -e NTWA_SECRET_KEY="$(openssl rand -hex 32)" \
  -e NTWA_USERS="{\"alice\":\"pbkdf2:sha256:600000\$03hLeQ...\"}" \
  tsosc/nexttraceweb 127.0.0.1:30080
```

Generate accounts straight into your shell environment:

```bash
export NTWA_USERS="{\"alice\":\"$(python auth.py hash 'your-password')\"}"
```

Treat the account map as a secret. Do not commit it; `docker/` and `.env` files are gitignored for this reason.

### 3. Related settings

| Variable | Default | Purpose |
|---|---|---|
| `NTWA_SECRET_KEY` | random per process | Session signing key. **Set it in production** — otherwise every restart invalidates all sessions and multiple workers cannot share sessions. |
| `NTWA_SESSION_LIFETIME_SECONDS` | `43200` (12h) | How long a login stays valid. |
| `NTWA_MAX_LOGIN_ATTEMPTS` | `10` | Failed attempts per IP per window before lockout. |
| `NTWA_MIN_LOGIN_INTERVAL_SECONDS` | `0.5` | Minimum delay between attempts. |
| `NTWA_HEALTHZ_PUBLIC` | `false` | Set `true` to leave `/healthz` reachable without logging in — needed if your orchestrator cannot authenticate its probes. |
| `NTWA_SESSION_COOKIE_SECURE` | `false` | Set `true` only when the outer proxy terminates HTTPS. |

`/logout` (GET or POST) clears the session and returns you to the login page.

### Login page language

The login page resolves its language server-side, before any JavaScript runs: the `ntwa_language` cookie first, then the browser's `Accept-Language`, then English. Signing in sets the cookie so the page language follows the UI on subsequent visits. This is a separate mechanism from the in-app language selector, which is client-side.

## External Auth Example

The built-in login page is optional to use *alongside* an outer gate. Minimal Nginx example with Basic Auth in front of the container — note that in this configuration the container still requires its own account, so you get two layers:

```nginx
server {
    listen 443 ssl http2;
    server_name trace.example.com;

    auth_basic "restricted";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_pass http://127.0.0.1:30080;
    }
}
```
