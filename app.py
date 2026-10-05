import os
import sys

REQUESTED_SOCKETIO_ASYNC_MODE = os.environ.get("NTWA_SOCKETIO_ASYNC_MODE", "gevent")
SOCKETIO_ASYNC_MODE = REQUESTED_SOCKETIO_ASYNC_MODE

if SOCKETIO_ASYNC_MODE == "gevent":
    from gevent import monkey

    monkey.patch_all()

try:
    import distutils  # noqa: F401
except ModuleNotFoundError:
    import setuptools._distutils as _distutils

    sys.modules.setdefault("distutils", _distutils)
    sys.modules.setdefault("distutils.version", _distutils.version)

import ipaddress
import json
import logging
import re
import secrets
import shutil
import socket as socket_module
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple
from urllib.parse import urlparse

from flask import Flask, jsonify, make_response, redirect, render_template, request
from flask_socketio import SocketIO

import auth
import login_i18n
from nexttrace_mtr import INVALID_PARAM_PATTERN, build_mtr_raw_command, build_process_env, parse_mtr_raw_line


TRACE_OPTION_PATTERN = r"^\d+\.\s+(.+)$"
DEVICE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,126}$"
HOSTNAME_PATTERN = r"^(?=.{1,255}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.(?!-)[A-Za-z0-9-]{1,63})*$"
DATA_PROVIDER_ALLOWLIST = {
    "Ip2region",
    "ip2region",
    "IP.SB",
    "ip.sb",
    "IPInfo",
    "ipinfo",
    "IPInsight",
    "ipinsight",
    "IPAPI.com",
    "ip-api.com",
    "IPInfoLocal",
    "ipinfolocal",
    "chunzhen",
    "LeoMoeAPI",
    "leomoeapi",
    "disable-geoip",
}
OPTION_EMIT_DELAY_SECONDS = 0.1
PROCESS_STOP_TIMEOUT_SECONDS = 1.0


def configure_logging():
    log_level = os.environ.get("NTWA_LOG_LEVEL", "INFO").upper()
    if log_level not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}:
        log_level = "INFO"
    logging.basicConfig(level=log_level, format="%(asctime)s %(levelname)s %(message)s")


configure_logging()


def env_float(name: str, default: float) -> float:
    raw_value = os.environ.get(name)
    if raw_value is None or raw_value == "":
        return default
    try:
        return float(raw_value)
    except ValueError:
        logging.warning("Invalid float in %s=%r, falling back to %s", name, raw_value, default)
        return default


def env_int(name: str, default: int) -> int:
    raw_value = os.environ.get(name)
    if raw_value is None or raw_value == "":
        return default
    try:
        return int(raw_value)
    except ValueError:
        logging.warning("Invalid integer in %s=%r, falling back to %s", name, raw_value, default)
        return default


def env_bool(name: str, default: bool) -> bool:
    raw_value = os.environ.get(name)
    if raw_value is None or raw_value == "":
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


def parse_trusted_hosts(raw_value: Optional[str]) -> Tuple[str, ...]:
    if not raw_value:
        return ()
    hosts = []
    for host in raw_value.split(","):
        normalized = host.strip().lower()
        if normalized:
            hosts.append(normalized)
    return tuple(dict.fromkeys(hosts))


def load_secret_key() -> str:
    configured = os.environ.get("NTWA_SECRET_KEY")
    if configured:
        return configured
    generated = secrets.token_hex(32)
    logging.warning("NTWA_SECRET_KEY is unset; generated an ephemeral secret key for this process")
    return generated


def host_without_port(host_header: str) -> str:
    host = (host_header or "").strip().lower()
    if host.startswith("[") and "]" in host:
        return host[1 : host.index("]")]
    if ":" in host and host.count(":") == 1:
        return host.rsplit(":", 1)[0]
    return host


def is_trusted_host(host_header: str) -> bool:
    trusted_hosts = app.config["NTWA_TRUSTED_HOSTS"]
    if not trusted_hosts:
        return True
    host = host_without_port(host_header)
    return host in trusted_hosts


@dataclass(frozen=True)
class PayloadError(Exception):
    code: str
    message: str
    retry_after_seconds: Optional[float] = None


class TraceTask:
    def __init__(self, sid: str, params: Iterable[str], nexttrace_path: str):
        self.sid = sid
        self.params = list(params)
        self.nexttrace_path = nexttrace_path
        self.process = None
        self.thread = None
        self.created_at = time.monotonic()
        self.last_output_at = self.created_at
        self._stop_event = threading.Event()
        self._complete_lock = threading.Lock()
        self._complete_emitted = False
        self._stop_lock = threading.Lock()
        self._pending_options = []
        self._option_timer = None
        self._last_stderr_line = ""
        self._stdout_hints = []
        self._saw_output_record = False

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True, name=f"trace-{self.sid}")
        self.thread.start()

    def emit_error(self, code: str, message: str, retry_after_seconds: Optional[float] = None):
        emit_nexttrace_error(self.sid, code, message, retry_after_seconds)

    def emit_complete(self):
        with self._complete_lock:
            if self._complete_emitted:
                return
            self._complete_emitted = True
        cleanup_client_state(self.sid, task=self)
        socketio.emit("nexttrace_complete", room=self.sid)

    def request_stop(self):
        with self._stop_lock:
            self._stop_event.set()
            self._cancel_option_timer()
            process = self.process

        if process is None:
            return

        try:
            terminate = getattr(process, "terminate", None)
            wait = getattr(process, "wait", None)
            if callable(terminate):
                terminate()
            if callable(wait):
                wait(timeout=PROCESS_STOP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            logging.warning("Force killing nexttrace process for sid=%s", self.sid)
            kill = getattr(process, "kill", None)
            if callable(kill):
                kill()
        except OSError as exc:
            logging.debug("Stopping process for sid=%s failed: %s", self.sid, exc)
        finally:
            self._close_pipe(getattr(process, "stdout", None))
            self._close_pipe(getattr(process, "stderr", None))
            self._close_pipe(getattr(process, "stdin", None))

    def process_input(self, data: str):
        process = self.process
        if not process or not process.stdin:
            raise PayloadError("trace_not_running", "当前没有可交互的 trace 任务")
        try:
            process.stdin.write(data)
            process.stdin.flush()
        except OSError as exc:
            raise PayloadError("trace_not_running", f"任务已结束，无法继续输入: {exc}") from exc

    def run(self):
        command = build_mtr_raw_command(self.nexttrace_path, self.params)
        logging.info("Starting nexttrace sid=%s command=%s", self.sid, command)
        try:
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                text=True,
                bufsize=1,
                env=build_process_env(os.environ),
            )
        except OSError as exc:
            logging.error("Failed to start nexttrace sid=%s: %s", self.sid, exc)
            self.emit_error("start_failed", "启动 nexttrace 失败，请检查服务器配置")
            self.emit_complete()
            return

        stderr_thread = threading.Thread(target=self._consume_stderr, daemon=True, name=f"trace-stderr-{self.sid}")
        stderr_thread.start()
        watchdog_thread = threading.Thread(target=self._watchdog_loop, daemon=True, name=f"trace-watchdog-{self.sid}")
        watchdog_thread.start()

        try:
            while not self._stop_event.is_set():
                try:
                    line = self.process.stdout.readline()
                except ValueError:
                    break
                if line == "":
                    break

                self.last_output_at = time.monotonic()
                option = parse_trace_option(line)
                if option:
                    self._pending_options.append(option)
                    self._schedule_option_emit()
                    continue

                record = parse_mtr_raw_line(line)
                if record is not None:
                    self._saw_output_record = True
                    self.socket_emit("mtr_raw", record)
                    continue

                stripped = line.strip()
                if stripped:
                    self._remember_stdout_hint(stripped)
                    logging.debug("Ignored nexttrace stdout sid=%s line=%s", self.sid, stripped)
        finally:
            self._cancel_option_timer()
            return_code = None
            if self.process is not None:
                try:
                    return_code = self.process.wait(timeout=PROCESS_STOP_TIMEOUT_SECONDS)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    return_code = self.process.wait(timeout=PROCESS_STOP_TIMEOUT_SECONDS)
            if return_code not in (None, 0) and not self._stop_event.is_set():
                message = self._last_stderr_line or f"nexttrace exited with code {return_code}"
                self.emit_error("nexttrace_exit_nonzero", message)
            elif (
                return_code == 0
                and not self._stop_event.is_set()
                and not self._saw_output_record
                and self._looks_like_cli_usage_failure()
            ):
                self.emit_error("nexttrace_invalid_args", self._stdout_hints[-1])
            self.emit_complete()

    def socket_emit(self, event: str, payload: Any):
        socketio.emit(event, payload, room=self.sid)

    def _watchdog_loop(self):
        idle_timeout = app.config["NTWA_TRACE_IDLE_TIMEOUT_SECONDS"]
        max_duration = app.config["NTWA_TRACE_MAX_DURATION_SECONDS"]
        while not self._stop_event.wait(1):
            now = time.monotonic()
            if max_duration > 0 and now - self.created_at > max_duration:
                self.emit_error("trace_max_duration_reached", "任务达到最大运行时长，已停止")
                self.request_stop()
                return
            if idle_timeout > 0 and now - self.last_output_at > idle_timeout:
                self.emit_error("trace_idle_timeout", "任务长时间无输出，已停止")
                self.request_stop()
                return

    def _consume_stderr(self):
        if not self.process or not self.process.stderr:
            return
        while True:
            try:
                line = self.process.stderr.readline()
            except ValueError:
                break
            if line == "":
                break
            stripped = line.strip()
            if stripped:
                self._last_stderr_line = stripped
                logging.warning("nexttrace stderr sid=%s %s", self.sid, stripped)

    def _schedule_option_emit(self):
        self._cancel_option_timer()
        timer = threading.Timer(OPTION_EMIT_DELAY_SECONDS, self._emit_pending_options)
        timer.daemon = True
        self._option_timer = timer
        timer.start()

    def _emit_pending_options(self):
        if self._stop_event.is_set():
            return
        options = list(self._pending_options)
        self._pending_options.clear()
        if options:
            self.socket_emit("nexttrace_options", options)

    def _cancel_option_timer(self):
        if self._option_timer is not None:
            self._option_timer.cancel()
            self._option_timer = None

    def _remember_stdout_hint(self, line: str):
        self._stdout_hints.append(line)
        if len(self._stdout_hints) > 8:
            self._stdout_hints = self._stdout_hints[-8:]

    def _looks_like_cli_usage_failure(self) -> bool:
        if not self._stdout_hints:
            return False
        for line in self._stdout_hints:
            if line.startswith("unknown arguments "):
                return True
            if line.startswith("usage: "):
                return True
        return False

    @staticmethod
    def _close_pipe(pipe):
        if pipe is None:
            return
        try:
            pipe.close()
        except Exception:
            pass


# static_url_path must match the real folder name: the templates reference
# assets/... relatively (see templates/index.html) and nginx.conf proxies
# /assets/... through to this app, so serving them under the default /static/
# prefix would 404 the stylesheets.
app = Flask(__name__, static_folder="assets", static_url_path="/assets")
app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=env_bool("NTWA_SESSION_COOKIE_SECURE", False),
    PERMANENT_SESSION_LIFETIME=max(1, env_int("NTWA_SESSION_LIFETIME_SECONDS", 43200)),
    NTWA_NEXTTRACE_PATH=os.environ.get("NTWA_NEXTTRACE_PATH", "/usr/local/bin/nexttrace"),
    NTWA_TRUSTED_HOSTS=parse_trusted_hosts(os.environ.get("NTWA_TRUSTED_HOSTS")),
    NTWA_TRACE_IDLE_TIMEOUT_SECONDS=max(0.0, env_float("NTWA_TRACE_IDLE_TIMEOUT_SECONDS", 120.0)),
    NTWA_TRACE_MAX_DURATION_SECONDS=max(0.0, env_float("NTWA_TRACE_MAX_DURATION_SECONDS", 0.0)),
    NTWA_MAX_ACTIVE_TRACES=max(1, env_int("NTWA_MAX_ACTIVE_TRACES", 64)),
    NTWA_MIN_START_INTERVAL_SECONDS=max(0.0, env_float("NTWA_MIN_START_INTERVAL_SECONDS", 1.0)),
    NTWA_MIN_LOGIN_INTERVAL_SECONDS=max(0.0, env_float("NTWA_MIN_LOGIN_INTERVAL_SECONDS", 0.5)),
    NTWA_MAX_LOGIN_ATTEMPTS=max(0, env_int("NTWA_MAX_LOGIN_ATTEMPTS", 10)),
    NTWA_HEALTHZ_PUBLIC=env_bool("NTWA_HEALTHZ_PUBLIC", False),
    NTWA_LOGIN_ATTEMPTS={},
)


def load_auth_users() -> dict:
    """Resolve the account table once at boot.

    Failing hard here is intentional: a misconfigured account source must not
    degrade into "no authentication".
    """
    try:
        users = auth.load_users()
    except auth.AuthConfigError as exc:
        logging.error("Authentication configuration is invalid: %s", exc)
        raise SystemExit(2) from exc

    if users:
        logging.info(
            "Authentication enabled for %d account(s): %s",
            len(users),
            ", ".join(sorted(users)),
        )
    else:
        logging.warning(
            "Authentication is NOT configured (no NTWA_USERS / NTWA_USERS_FILE). "
            "All protected routes will be refused. Set an account source to enable the app."
        )
    return users


app.config["NTWA_USERS"] = load_auth_users()
socketio = SocketIO(
    app,
    async_mode=SOCKETIO_ASYNC_MODE,
    logger=False,
    engineio_logger=False,
)

clients = {}
client_last_start = {}
clients_lock = threading.RLock()


def emit_nexttrace_error(sid: str, code: str, message: str, retry_after_seconds: Optional[float] = None):
    payload = {"code": code, "message": message}
    if retry_after_seconds is not None:
        payload["retry_after_seconds"] = retry_after_seconds
    socketio.emit("nexttrace_error", payload, room=sid)


def cleanup_client_state(sid: str, task: Optional[TraceTask] = None):
    with clients_lock:
        current_task = clients.get(sid)
        if task is None or current_task is task:
            clients.pop(sid, None)


def get_task(sid: str) -> Optional[TraceTask]:
    with clients_lock:
        return clients.get(sid)


def parse_json_object(raw_data: Any, field_name: str) -> Dict[str, Any]:
    if raw_data is None or raw_data == "":
        return {}
    if isinstance(raw_data, dict):
        return raw_data
    if isinstance(raw_data, str):
        try:
            parsed = json.loads(raw_data)
        except json.JSONDecodeError as exc:
            raise PayloadError("invalid_payload", f"{field_name} 不是合法的 JSON") from exc
        if isinstance(parsed, dict):
            return parsed
    raise PayloadError("invalid_payload", f"{field_name} 必须是对象")


def normalize_target(raw_target: Any) -> str:
    if raw_target is None:
        raise PayloadError("invalid_target", "缺少目标地址")
    target = str(raw_target).strip()
    if not target:
        raise PayloadError("invalid_target", "缺少目标地址")

    if "://" in target:
        parsed = urlparse(target)
        target = parsed.hostname or ""
    elif target.startswith("[") and "]" in target:
        target = target[1 : target.index("]")]
    elif target.count(":") == 1:
        host_part, port_part = target.rsplit(":", 1)
        if port_part.isdigit():
            target = host_part

    if INVALID_PARAM_PATTERN.search(target):
        raise PayloadError("invalid_target", "目标地址包含非法字符")
    if len(target) > 255:
        raise PayloadError("invalid_target", "目标地址过长")

    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    if not re.match(HOSTNAME_PATTERN, target):
        raise PayloadError("invalid_target", "目标地址格式不合法")
    return target


def parse_client_payload(data: Any) -> Tuple[str, Dict[str, Any]]:
    payload = parse_json_object(data, "payload")
    if "ip" not in payload:
        raise PayloadError("invalid_payload", "payload 缺少 ip 字段")
    target = normalize_target(payload.get("ip"))
    extra = parse_json_object(payload.get("extra"), "extra")
    return target, extra


def parse_positive_int(value: Any, name: str, minimum: int, maximum: int) -> Optional[int]:
    if value in (None, ""):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise PayloadError("invalid_payload", f"{name} 不是合法整数") from exc
    if not minimum <= parsed <= maximum:
        raise PayloadError("invalid_payload", f"{name} 超出允许范围")
    return parsed


def parse_positive_float(value: Any, name: str, minimum: float, maximum: float) -> Optional[float]:
    if value in (None, ""):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise PayloadError("invalid_payload", f"{name} 不是合法数字") from exc
    if not minimum <= parsed <= maximum:
        raise PayloadError("invalid_payload", f"{name} 超出允许范围")
    return parsed


def build_trace_params(target: str, extra: Dict[str, Any]) -> list:
    params = [target]

    ip_version = extra.get("ipVersion")
    if ip_version == "ipv4":
        params.append("--ipv4")
    elif ip_version == "ipv6":
        params.append("--ipv6")

    protocol = extra.get("protocol")
    if protocol == "tcp":
        params.append("--tcp")
    elif protocol == "udp":
        params.append("--udp")

    language = extra.get("language")
    if language == "en":
        params.extend(["--language", "en"])

    interval_seconds = parse_positive_float(extra.get("intervalSeconds"), "intervalSeconds", 0.005, 60.0)
    if interval_seconds is not None:
        params.extend(["--ttl-time", str(int(interval_seconds * 1000))])

    packet_size = parse_positive_int(extra.get("packetSize"), "packetSize", 0, 1500)
    if packet_size is not None:
        params.extend(["--psize", str(packet_size)])

    max_hop = parse_positive_int(extra.get("maxHop"), "maxHop", 1, 255)
    if max_hop is not None:
        params.extend(["--max-hops", str(max_hop)])

    min_hop = parse_positive_int(extra.get("minHop"), "minHop", 1, 255)
    if min_hop is not None:
        params.extend(["--first", str(min_hop)])

    port = parse_positive_int(extra.get("port"), "port", 1, 65535)
    if port is not None:
        params.extend(["--port", str(port)])

    device = extra.get("device")
    if device not in (None, ""):
        device = str(device).strip()
        if len(device) > 127 or not re.match(DEVICE_PATTERN, device):
            raise PayloadError("invalid_payload", "device 不合法")
        params.extend(["--dev", device])

    data_provider = extra.get("dataProvider")
    if data_provider not in (None, ""):
        data_provider = str(data_provider).strip()
        if data_provider not in DATA_PROVIDER_ALLOWLIST:
            raise PayloadError("invalid_payload", "dataProvider 不合法")
        params.extend(["--data-provider", data_provider])

    return params


def parse_trace_option(line: str) -> Optional[str]:
    match = re.match(TRACE_OPTION_PATTERN, line.strip())
    if not match:
        return None
    return match.group(1).strip()


def enforce_start_limits(sid: str):
    now = time.monotonic()
    min_interval = app.config["NTWA_MIN_START_INTERVAL_SECONDS"]
    max_active = app.config["NTWA_MAX_ACTIVE_TRACES"]
    with clients_lock:
        last_start = client_last_start.get(sid)
        if last_start is not None and min_interval > 0:
            remaining = min_interval - (now - last_start)
            if remaining > 0:
                raise PayloadError(
                    "trace_rate_limited",
                    "操作过于频繁，请稍后再试",
                    retry_after_seconds=round(remaining, 3),
                )
        existing_task = clients.get(sid)
        active_count = len(clients) - (1 if existing_task else 0)
        if active_count >= max_active:
            raise PayloadError(
                "trace_capacity_exceeded",
                "当前并发任务已达上限，请稍后再试",
                retry_after_seconds=1.0,
            )
        client_last_start[sid] = now


def stop_nexttrace_for_sid(sid: str):
    task = get_task(sid)
    if task is not None:
        task.request_stop()


def list_available_devices() -> list[str]:
    try:
        discovered = socket_module.if_nameindex()
    except OSError:
        logging.warning("Failed to enumerate local interfaces", exc_info=True)
        return []

    devices = []
    seen = set()
    for _index, raw_name in discovered:
        name = str(raw_name).strip()
        if not name or not re.match(DEVICE_PATTERN, name):
            continue
        if name in seen:
            continue
        seen.add(name)
        devices.append(name)
    return devices


@app.before_request
def validate_request_host():
    if not is_trusted_host(request.host):
        return jsonify({"status": "error", "code": "untrusted_host"}), 400
    return None


@app.before_request
def enforce_authentication():
    """Gate every route behind a session login when accounts are configured."""
    return auth.require_auth_guard()


@app.route("/login", methods=["GET", "POST"])
def login():
    # Without accounts there is no way to ever satisfy this page, so say so
    # plainly instead of bouncing the visitor between two routes.
    if not auth.is_login_required():
        return auth.locked_out_response()

    if auth.current_username() is not None:
        return redirect(auth.safe_redirect_target(request.args.get("next")) or "/")

    locale = login_i18n.resolve_locale(
        request.cookies.get(login_i18n.LOCALE_COOKIE),
        request.accept_languages.to_header() if request.accept_languages else None,
    )
    translate = login_i18n.make_translator(locale)

    error_key = None
    username_value = ""
    retry_after = 0
    next_target = auth.safe_redirect_target(request.values.get("next"))

    if request.method == "POST":
        username_value = str(request.form.get("username", "")).strip()
        password = request.form.get("password", "")

        wait = auth.throttle_login()
        if wait is not None:
            error_key = "login.error.throttled"
            retry_after = max(1, int(wait) + 1)
        elif not username_value or not password:
            error_key = "login.error.missing"
        elif auth.verify_credentials(username_value, password):
            auth.clear_login_attempts()
            auth.login_user(username_value)
            logging.info("Login succeeded user=%s ip=%s", username_value, request.remote_addr)
            return redirect(next_target or "/")
        else:
            error_key = "login.error.invalid"
            logging.warning("Login failed user=%r ip=%s", username_value, request.remote_addr)

    response = make_response(
        render_template(
            "login.html",
            t=translate,
            locale=locale,
            error_key=error_key,
            username=username_value,
            next_target=next_target,
            retry_after=retry_after,
        )
    )
    # Remember the resolved locale so the main UI's language selector can honour
    # the same choice, and so repeat visits skip the header sniffing.
    response.set_cookie(
        login_i18n.LOCALE_COOKIE,
        locale,
        max_age=31536000,
        httponly=False,
        samesite="Lax",
        secure=app.config["SESSION_COOKIE_SECURE"],
    )
    if error_key == "login.error.throttled":
        response.status_code = 429
        response.headers["Retry-After"] = str(retry_after)
    return response


@app.route("/logout", methods=["GET", "POST"])
def logout():
    username = auth.current_username()
    auth.logout_user()
    if username:
        logging.info("Logout user=%s", username)
    return redirect("/login")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/healthz")
def healthz():
    nexttrace_path = app.config["NTWA_NEXTTRACE_PATH"]
    binary_exists = Path(nexttrace_path).exists() or shutil.which(nexttrace_path)
    status_code = 200 if binary_exists else 503
    with clients_lock:
        active_traces = len(clients)
    return (
        jsonify(
            {
                "status": "ok" if binary_exists else "degraded",
                "nexttrace_path": nexttrace_path,
                "nexttrace_available": bool(binary_exists),
                "active_traces": active_traces,
            }
        ),
        status_code,
    )


@app.route("/api/devices")
def api_devices():
    devices = list_available_devices()
    return jsonify({"devices": devices, "count": len(devices)})


@socketio.on("connect")
def handle_connect():
    if not is_trusted_host(request.host):
        logging.warning("Rejected websocket from untrusted host=%s", request.host)
        return False
    # The HTTP gate does not cover Engine.IO upgrades, so re-check the session
    # here. Without this a client could skip the login page and talk to the
    # socket directly. Fails closed: an unconfigured server refuses sockets too.
    if not auth.is_login_required():
        logging.error("Rejected websocket: authentication is not configured")
        return False
    if auth.current_username() is None:
        logging.warning("Rejected websocket from unauthenticated client ip=%s", request.remote_addr)
        return False
    logging.info("Client connected sid=%s user=%s", request.sid, auth.current_username())
    return None


@socketio.on("disconnect")
def handle_disconnect(*_args):
    logging.info("Client disconnected sid=%s", request.sid)
    stop_nexttrace_for_sid(request.sid)
    with clients_lock:
        client_last_start.pop(request.sid, None)


@socketio.on("start_nexttrace")
def start_nexttrace(data):
    sid = request.sid
    try:
        target, extra = parse_client_payload(data)
        params = build_trace_params(target, extra)
        enforce_start_limits(sid)
    except PayloadError as exc:
        emit_nexttrace_error(sid, exc.code, exc.message, exc.retry_after_seconds)
        return

    existing_task = get_task(sid)
    if existing_task is not None:
        existing_task.request_stop()

    task = TraceTask(sid, params, app.config["NTWA_NEXTTRACE_PATH"])
    with clients_lock:
        clients[sid] = task
    task.start()


@socketio.on("stop_nexttrace")
def stop_nexttrace():
    stop_nexttrace_for_sid(request.sid)


@socketio.on("nexttrace_options_choice")
def nexttrace_options_choice(data):
    sid = request.sid
    try:
        payload = parse_json_object(data, "payload")
        choice = parse_positive_int(payload.get("choice"), "choice", 1, 9999)
        if choice is None:
            raise PayloadError("invalid_payload", "缺少 choice 字段")
        task = get_task(sid)
        if task is None:
            raise PayloadError("trace_not_running", "当前没有可交互的 trace 任务")
        task.process_input(f"{choice}\n")
    except PayloadError as exc:
        emit_nexttrace_error(sid, exc.code, exc.message, exc.retry_after_seconds)


if __name__ == "__main__":
    socketio.run(app, host="127.0.0.1", port=35000)
