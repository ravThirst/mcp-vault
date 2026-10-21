"""The MCP Vault agent: holds the unlocked vault and serves the web UI.

Listens on 127.0.0.1 only. Two kinds of callers:

* the browser UI (/api/*): needs a session cookie obtained by entering the
  master password, plus an X-MCPVault header on writes (blocks CSRF), and a
  matching Host header (blocks DNS rebinding);
* launchers (/internal/*): need the random token in agent.json, which is
  readable only by the current user.
"""

import hmac
import http.server
import json
import logging
import os
import re
import secrets
import socket
import subprocess
import threading
import time
import urllib.parse

from . import __version__, adapters, clients, importer, model, paths, probe, winutil
from .store import Vault, VaultLocked, WrongPassword, atomic_write

log = logging.getLogger("mcpvault")

MIN_PASSWORD = 8


class ApiError(Exception):
    def __init__(self, status: int, message: str, **extra):
        super().__init__(message)
        self.status, self.message, self.extra = status, message, extra


class Agent:
    def __init__(self):
        self.vault = Vault()
        self.lock = threading.RLock()
        self.token = secrets.token_urlsafe(32)
        self.sessions: set[str] = set()
        self.last_activity = time.time()
        self.unlocked_at = 0.0
        self.prompt_active = False
        self.cancelled_at = 0.0
        self.host_status: dict[str, dict] = {}
        self.server_status: dict[str, dict] = {}
        self.running: dict[int, dict] = {}
        self.server: http.server.ThreadingHTTPServer | None = None

    # -- lock state ----------------------------------------------------------

    def touch(self) -> None:
        self.last_activity = time.time()

    def unlock(self, password: str) -> None:
        with self.lock:
            if not self.vault.unlocked:
                self.vault.unlock(password)
                self.unlocked_at = time.time()
                log.info("vault unlocked")
            elif not self.vault.verify(password):
                raise WrongPassword("wrong master password")
            self.touch()

    def lock_vault(self, reason: str) -> None:
        with self.lock:
            if self.vault.unlocked:
                log.info("vault locked (%s)", reason)
            self.vault.lock()
            self.sessions.clear()

    def auto_lock_loop(self) -> None:
        while True:
            time.sleep(20)
            with self.lock:
                if not self.vault.unlocked:
                    continue
                minutes = int(self.vault.data["settings"].get("auto_lock_minutes") or 0)
                if minutes > 0 and time.time() - self.last_activity > minutes * 60:
                    self.lock_vault(f"idle for {minutes} min")

    def request_unlock(self) -> None:
        if os.environ.get("MCPVAULT_NO_PROMPT"):
            return
        with self.lock:
            if self.vault.unlocked or self.prompt_active or not self.vault.exists():
                return
            self.prompt_active = True
        threading.Thread(target=self._prompt_loop, daemon=True).start()

    def _prompt_loop(self) -> None:
        message = ""
        try:
            for _ in range(5):
                if self.vault.unlocked:
                    return
                env = dict(os.environ, PYTHONIOENCODING="utf-8")
                proc = subprocess.run([paths.python_windowed(), paths.ENTRY, "prompt", message],
                                      capture_output=True, env=env, timeout=900)
                if self.vault.unlocked:
                    return
                if proc.returncode != 0:
                    self.cancelled_at = time.time()
                    return
                try:
                    self.unlock(proc.stdout.decode("utf-8").rstrip("\r\n"))
                    return
                except WrongPassword:
                    message = "Wrong password, try again."
            self.cancelled_at = time.time()
        except Exception:  # noqa: BLE001
            log.exception("unlock prompt failed")
            self.cancelled_at = time.time()
        finally:
            self.prompt_active = False

    # -- helpers -------------------------------------------------------------

    def data(self) -> dict:
        try:
            return self.vault.require()
        except VaultLocked:
            raise ApiError(423, "The vault is locked") from None

    def hosts_by_id(self) -> dict:
        return {h["id"]: h for h in self.data()["hosts"]}

    def find_server(self, sid: str) -> dict:
        for s in self.data()["servers"]:
            if s["id"] == sid:
                return s
        raise ApiError(404, f"No server named {sid!r}")

    def find_host(self, hid: str) -> dict:
        for h in self.data()["hosts"]:
            if h["id"] == hid:
                return h
        raise ApiError(404, "Host not found")

    def running_counts(self) -> dict:
        counts: dict[str, int] = {}
        for pid, info in list(self.running.items()):
            if not winutil.pid_alive(pid):
                self.running.pop(pid, None)
                continue
            counts[info["server"]] = counts.get(info["server"], 0) + 1
        return counts

    def snapshot(self) -> dict:
        d = self.data()
        used_by: dict[str, list[str]] = {}
        for s in d["servers"]:
            for hid in s["hosts"]:
                used_by.setdefault(hid, []).append(s["id"])
        hosts = [{**model.mask_host(h), "used_by": used_by.get(h["id"], [])} for h in d["hosts"]]
        return {
            "hosts": hosts,
            "servers": [model.mask_server(s) for s in d["servers"]],
            "settings": d["settings"],
            "status": {"hosts": self.host_status, "servers": self.server_status},
            "running": self.running_counts(),
            "meta": {
                "templates": adapters.TEMPLATES,
                "kinds": model.HOST_KINDS,
                "clients": {k: {"label": v["label"], "path": v["path"]} for k, v in clients.CLIENTS.items()},
                "python": paths.python_console(),
                "entry": paths.ENTRY,
                "vault_file": paths.VAULT_FILE,
                "log_dir": paths.LOG_DIR,
                "autostart": os.path.exists(winutil.startup_shortcut_path()),
                "version": __version__,
            },
        }

    # -- API handlers ---------------------------------------------------------

    def api_state(self, _body, _q) -> dict:
        return {"exists": self.vault.exists(), "unlocked": self.vault.unlocked, "version": __version__}

    def api_create(self, body, _q, handler) -> dict:
        pw = str(body.get("password") or "")
        if len(pw) < MIN_PASSWORD:
            raise ApiError(400, f"Use at least {MIN_PASSWORD} characters")
        with self.lock:
            if self.vault.exists():
                raise ApiError(409, "A vault already exists")
            self.vault.create(pw)
            self.unlocked_at = time.time()
            self.touch()
        handler.new_session()
        return {"ok": True}

    def api_login(self, body, _q, handler) -> dict:
        if not self.vault.exists():
            raise ApiError(404, "No vault exists yet")
        try:
            self.unlock(str(body.get("password") or ""))
        except WrongPassword:
            time.sleep(1.0)
            raise ApiError(403, "Wrong master password") from None
        handler.new_session()
        return {"ok": True}

    def api_lock(self, _body, _q) -> dict:
        self.lock_vault("locked from the UI")
        return {"ok": True}

    def api_data(self, _body, _q) -> dict:
        return self.snapshot()

    def api_reveal(self, _body, q) -> dict:
        kind, item_id, field = q.get("kind", ""), q.get("id", ""), q.get("field", "")
        if kind == "host":
            if field not in model.HOST_SECRETS:
                raise ApiError(400, "Unknown field")
            return {"value": self.find_host(item_id).get(field, "")}
        if kind == "server":
            return {"value": self.find_server(item_id).get("secret_env", {}).get(field, "")}
        raise ApiError(400, "Unknown kind")

    def api_save_host(self, body, _q) -> dict:
        with self.lock:
            d = self.data()
            existing = next((h for h in d["hosts"] if h["id"] == body.get("id")), None)
            try:
                host = model.clean_host(body, existing)
            except model.ValidationError as exc:
                raise ApiError(400, str(exc)) from None
            if any(h["name"].lower() == host["name"].lower() and h["id"] != host["id"] for h in d["hosts"]):
                raise ApiError(400, f"A host named {host['name']!r} already exists")
            if existing:
                used = [s for s in d["servers"] if host["id"] in s["hosts"]]
                for s in used:
                    if host["kind"] not in adapters.TEMPLATES[s["template"]]["kinds"]:
                        raise ApiError(400, f"Server {s['id']!r} cannot use a {model.HOST_KINDS[host['kind']]} host")
                d["hosts"][d["hosts"].index(existing)] = host
            else:
                d["hosts"].append(host)
            self.vault.save()
            self.host_status.pop(host["id"], None)
        return {"ok": True, "id": host["id"]}

    def api_delete_host(self, body, _q, hid) -> dict:
        """Delete a host. If servers use it, `cascade` unlinks it from them and deletes
        the ones that cannot run without it; without `cascade` the impact is returned
        (409) so the caller can show it and confirm."""
        with self.lock:
            d = self.data()
            host = self.find_host(hid)
            impact = model.host_removal_impact(d["servers"], hid)
            if impact and not body.get("cascade"):
                raise ApiError(409, f"Host {host['name']!r} is in use: {model.describe_impact(impact)}", impact=impact)
            for item in impact:
                server = self.find_server(item["server"])
                if item["action"] == "delete":
                    d["servers"].remove(server)
                    self.server_status.pop(server["id"], None)
                else:
                    server["hosts"] = [h for h in server["hosts"] if h != hid]
            d["hosts"].remove(host)
            self.host_status.pop(hid, None)
            self.vault.save()
        deleted = [i["server"] for i in impact if i["action"] == "delete"]
        return {"ok": True, "deleted_servers": deleted,
                "detached_from": [i["server"] for i in impact if i["action"] == "detach"]}

    def api_save_server(self, body, _q) -> dict:
        with self.lock:
            d = self.data()
            original = body.get("original_id")
            existing = next((s for s in d["servers"] if s["id"] == original), None) if original else None
            try:
                server = model.clean_server(body, existing, self.hosts_by_id())
            except model.ValidationError as exc:
                raise ApiError(400, str(exc)) from None
            if any(s["id"] == server["id"] and s is not existing for s in d["servers"]):
                raise ApiError(400, f"A server named {server['id']!r} already exists")
            if existing:
                d["servers"][d["servers"].index(existing)] = server
            else:
                d["servers"].append(server)
            self.vault.save()
            self.server_status.pop(server["id"], None)
        return {"ok": True, "id": server["id"]}

    def api_delete_server(self, _body, _q, sid) -> dict:
        with self.lock:
            d = self.data()
            d["servers"].remove(self.find_server(sid))
            self.vault.save()
        return {"ok": True}

    def api_test_host(self, _body, _q, hid) -> dict:
        host = dict(self.find_host(hid))
        result = probe.test_host(host)
        self.host_status[hid] = result
        return result

    def api_test_server(self, _body, _q, sid) -> dict:
        server = self.find_server(sid)
        try:
            spec, secrets_ = adapters.resolve(server, self.hosts_by_id())
        except adapters.ResolveError as exc:
            raise ApiError(400, str(exc)) from None
        result = probe.test_server(spec, secrets_)
        self.server_status[sid] = result
        return result

    def api_logs(self, _body, q, sid) -> dict:
        if not model.ID_RE.match(sid):
            raise ApiError(400, "Invalid server name")
        path = os.path.join(paths.LOG_DIR, f"{sid}.log")
        if not os.path.exists(path):
            return {"text": "", "path": path}
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 200_000))
            text = fh.read().decode("utf-8", errors="replace")
        lines = text.splitlines()[-int(q.get("lines", "400")):]
        return {"text": "\n".join(lines), "path": path}

    def api_settings(self, body, _q) -> dict:
        with self.lock:
            d = self.data()
            try:
                minutes = int(body.get("auto_lock_minutes", d["settings"].get("auto_lock_minutes", 480)))
            except (TypeError, ValueError):
                raise ApiError(400, "Auto-lock must be a number of minutes") from None
            d["settings"]["auto_lock_minutes"] = max(0, min(minutes, 60 * 24 * 30))
            self.vault.save()
        return {"ok": True}

    def api_password(self, body, _q) -> dict:
        new = str(body.get("new") or "")
        if len(new) < MIN_PASSWORD:
            raise ApiError(400, f"Use at least {MIN_PASSWORD} characters")
        with self.lock:
            self.data()
            try:
                self.vault.change_password(str(body.get("old") or ""), new)
            except WrongPassword:
                raise ApiError(403, "The current password is wrong") from None
        return {"ok": True}

    def api_autostart(self, body, _q) -> dict:
        self.data()
        path = winutil.startup_shortcut_path()
        if body.get("enabled"):
            winutil.create_shortcut(path, paths.python_windowed(), f'"{paths.ENTRY}" agent', paths.APP_DIR,
                                    "MCP Vault agent (starts locked)")
        elif os.path.exists(path):
            os.remove(path)
        return {"enabled": os.path.exists(path)}

    def api_clients_plan(self, _body, _q) -> dict:
        return {"clients": clients.plan(self.data()["servers"])}

    def api_clients_apply(self, body, _q) -> dict:
        with self.lock:
            servers = self.data()["servers"]
            results = clients.apply(self.vault, servers, list(body.get("clients") or []))
        return {"results": results}

    def api_backups(self, _body, _q) -> dict:
        self.data()
        return {"backups": clients.list_backups()}

    def api_restore(self, body, _q) -> dict:
        with self.lock:
            self.data()
            try:
                return clients.restore(self.vault, str(body.get("name") or ""))
            except (OSError, ValueError) as exc:
                raise ApiError(400, str(exc)) from None

    def api_import_scan(self, _body, _q) -> dict:
        return importer.mask(importer.scan(self.data()))

    def api_import_apply(self, body, _q) -> dict:
        with self.lock:
            d = self.data()
            try:
                summary = importer.apply(d, list(body.get("ids") or []))
            except (model.ValidationError, ValueError) as exc:
                raise ApiError(400, f"Import failed: {exc}") from None
            self.vault.save()
        return summary

    # -- command-line management (no secret values) --------------------------

    def manage_save_host(self, body, q) -> dict:
        if any(body.get(f) for f in model.HOST_SECRETS):
            raise ApiError(400, "Passwords can only be entered in the MCP Vault window")
        clean = {k: v for k, v in body.items() if k not in model.HOST_SECRETS}  # absent = keep current
        return self.api_save_host(clean, q)

    def manage_save_server(self, body, q) -> dict:
        with self.lock:
            original = body.get("original_id")
            existing = next((s for s in self.data()["servers"] if s["id"] == original), None) if original else None
            old = (existing or {}).get("secret_env", {})
            declared = {}
            for key, value in (body.get("secret_env") or {}).items():
                if value not in (None, True, False):
                    raise ApiError(400, "Secret values can only be entered in the MCP Vault window")
                declared[key] = None if key in old else ""  # keep the stored value, or declare an empty one
            return self.api_save_server({**body, "secret_env": declared}, q)

    # -- internal (launcher) handlers ---------------------------------------

    def internal_resolve(self, body) -> tuple[int, dict]:
        sid = str(body.get("server") or "")
        with self.lock:
            if not self.vault.exists():
                return 404, {"error": "no vault has been created yet; run `vault.py ui`"}
            if not self.vault.unlocked:
                return 423, {"locked": True, "prompt_active": self.prompt_active, "cancelled_at": self.cancelled_at}
            self.touch()
            server = next((s for s in self.vault.data["servers"] if s["id"] == sid), None)
            if server is None:
                return 404, {"error": f"the vault has no server named {sid!r}"}
            if not server.get("enabled", True):
                return 403, {"error": f"server {sid!r} is disabled in MCP Vault"}
            try:
                spec, secrets_ = adapters.resolve(server, {h["id"]: h for h in self.vault.data["hosts"]})
            except adapters.ResolveError as exc:
                return 400, {"error": str(exc)}
        return 200, {"spec": spec, "secrets": secrets_}

    def internal_event(self, body) -> tuple[int, dict]:
        pid = int(body.get("pid") or 0)
        if body.get("event") == "started" and pid:
            self.running[pid] = {"server": str(body.get("server")), "started": time.time()}
        else:
            self.running.pop(pid, None)
        return 200, {"ok": True}


ROUTES = [
    ("GET", r"/api/state", "api_state", False),
    ("POST", r"/api/create", "api_create", False),
    ("POST", r"/api/login", "api_login", False),
    ("POST", r"/api/lock", "api_lock", True),
    ("GET", r"/api/data", "api_data", True),
    ("GET", r"/api/reveal", "api_reveal", True),
    ("POST", r"/api/hosts", "api_save_host", True),
    ("DELETE", r"/api/hosts/([\w-]+)", "api_delete_host", True),
    ("POST", r"/api/hosts/([\w-]+)/test", "api_test_host", True),
    ("POST", r"/api/servers", "api_save_server", True),
    ("DELETE", r"/api/servers/([\w-]+)", "api_delete_server", True),
    ("POST", r"/api/servers/([\w-]+)/test", "api_test_server", True),
    ("GET", r"/api/servers/([\w-]+)/logs", "api_logs", True),
    ("POST", r"/api/settings", "api_settings", True),
    ("POST", r"/api/password", "api_password", True),
    ("POST", r"/api/autostart", "api_autostart", True),
    ("GET", r"/api/clients", "api_clients_plan", True),
    ("POST", r"/api/clients/apply", "api_clients_apply", True),
    ("GET", r"/api/backups", "api_backups", True),
    ("POST", r"/api/backups/restore", "api_restore", True),
    ("GET", r"/api/import", "api_import_scan", True),
    ("POST", r"/api/import", "api_import_apply", True),
]
_COMPILED = [(m, re.compile(p + r"$"), name, auth) for m, p, name, auth in ROUTES]

# Management routes for the command line (vault.py list/host/server/test/apply).
# They use the launcher token rather than a UI session and never carry secret
# values in either direction: entries can be created and edited, but passwords
# and secret variables are only ever typed into the UI.
MANAGE_ROUTES = [
    ("GET", r"/internal/manage/snapshot", "api_data"),
    ("POST", r"/internal/manage/hosts", "manage_save_host"),
    ("DELETE", r"/internal/manage/hosts/([\w-]+)", "api_delete_host"),
    ("POST", r"/internal/manage/hosts/([\w-]+)/test", "api_test_host"),
    ("POST", r"/internal/manage/servers", "manage_save_server"),
    ("DELETE", r"/internal/manage/servers/([\w-]+)", "api_delete_server"),
    ("POST", r"/internal/manage/servers/([\w-]+)/test", "api_test_server"),
    ("GET", r"/internal/manage/clients", "api_clients_plan"),
    ("POST", r"/internal/manage/clients/apply", "api_clients_apply"),
]
_MANAGE_COMPILED = [(m, re.compile(p + r"$"), name) for m, p, name in MANAGE_ROUTES]
_NEEDS_HANDLER = {"api_create", "api_login"}


def make_handler(agent: Agent):
    allowed_hosts = {f"127.0.0.1:{paths.PORT}", f"localhost:{paths.PORT}"}
    allowed_origins = {f"http://{h}" for h in allowed_hosts}

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "mcp-vault"
        protocol_version = "HTTP/1.1"
        _cookie_out: str | None = None

        def log_message(self, fmt, *args):  # keep request lines out of the log
            pass

        # -- plumbing ---------------------------------------------------------

        def _send(self, status: int, payload, content_type="application/json", extra_headers=None):
            body = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            if self._cookie_out:
                self.send_header("Set-Cookie", self._cookie_out)
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if length > 2_000_000:
                raise ApiError(413, "Request too large")
            raw = self.rfile.read(length) if length else b""
            if not raw:
                return {}
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                raise ApiError(400, "Invalid JSON") from None
            return obj if isinstance(obj, dict) else {}

        def _session(self) -> str | None:
            for part in (self.headers.get("Cookie") or "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == "mcpvault_sid":
                    return v
            return None

        def new_session(self) -> None:
            sid = secrets.token_urlsafe(32)
            agent.sessions.add(sid)
            self._cookie_out = f"mcpvault_sid={sid}; HttpOnly; SameSite=Strict; Path=/"

        def _authed(self) -> bool:
            sid = self._session()
            return bool(sid) and any(hmac.compare_digest(sid, s) for s in list(agent.sessions))

        # -- dispatch -----------------------------------------------------------

        def _handle(self, method: str):
            if self.headers.get("Host") not in allowed_hosts:
                return self._send(421, {"error": "Invalid Host header"})
            url = urllib.parse.urlsplit(self.path)
            path = url.path
            query = {k: v[-1] for k, v in urllib.parse.parse_qs(url.query).items()}
            try:
                if path.startswith("/internal/"):
                    return self._internal(method, path)
                if path.startswith("/api/"):
                    return self._api(method, path, query)
                if method == "GET" and path in ("/", "/index.html"):
                    with open(os.path.join(paths.STATIC_DIR, "index.html"), "rb") as fh:
                        return self._send(200, fh.read(), "text/html; charset=utf-8", {
                            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                                                       "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                                                       "connect-src 'self'; frame-ancestors 'none'"})
                return self._send(404, {"error": "Not found"})
            except ApiError as exc:
                return self._send(exc.status, {"error": exc.message, **exc.extra})
            except Exception:  # noqa: BLE001
                log.exception("request failed: %s %s", method, path)
                return self._send(500, {"error": "Internal error; see agent.log"})

        def _api(self, method: str, path: str, query: dict):
            if method != "GET":
                origin = self.headers.get("Origin")
                if self.headers.get("X-MCPVault") != "1" or (origin and origin not in allowed_origins):
                    raise ApiError(403, "Cross-site request blocked")
            for m, rx, name, auth in _COMPILED:
                match = rx.match(path)
                if m != method or not match:
                    continue
                if auth:
                    if not agent.vault.unlocked:
                        raise ApiError(401, "The vault is locked", locked=True)
                    if not self._authed():
                        raise ApiError(401, "Please sign in")
                    agent.touch()
                body = self._body() if method != "GET" else {}
                fn = getattr(agent, name)
                if name in _NEEDS_HANDLER:
                    return self._send(200, fn(body, query, self))
                return self._send(200, fn(body, query, *match.groups()))
            raise ApiError(404, "Not found")

        def _internal(self, method: str, path: str):
            if not hmac.compare_digest(self.headers.get("X-Agent-Token") or "", agent.token):
                return self._send(403, {"error": "bad agent token"})
            if path == "/internal/ping":
                return self._send(200, {"ok": True, "unlocked": agent.vault.unlocked})
            body = self._body()
            if path == "/internal/resolve" and method == "POST":
                return self._send(*agent.internal_resolve(body))
            if path == "/internal/request-unlock" and method == "POST":
                agent.request_unlock()
                return self._send(200, {"ok": True})
            if path == "/internal/event" and method == "POST":
                return self._send(*agent.internal_event(body))
            if path == "/internal/shutdown" and method == "POST":
                self._send(200, {"ok": True})
                threading.Thread(target=agent.server.shutdown, daemon=True).start()
                return None
            for m, rx, name in _MANAGE_COMPILED:
                match = rx.match(path)
                if m == method and match:
                    agent.touch()
                    return self._send(200, getattr(agent, name)(body, {}, *match.groups()))
            return self._send(404, {"error": "Not found"})

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

        def do_DELETE(self):
            self._handle("DELETE")

    return Handler


class ExclusiveHTTPServer(http.server.ThreadingHTTPServer):
    """An HTTP server that owns its port outright.

    The stdlib server sets SO_REUSEADDR, which on Windows lets any number of
    processes bind the same port at once. MCP clients start every server in
    parallel, so several agents would come up side by side, each with its own
    token. Exclusive binding makes the first agent win and the others exit.
    """

    allow_reuse_address = False
    daemon_threads = True

    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def serve() -> int:
    paths.ensure_dirs()
    logging.basicConfig(filename=paths.AGENT_LOG, level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", encoding="utf-8")
    agent = Agent()
    try:
        server = ExclusiveHTTPServer(("127.0.0.1", paths.PORT), make_handler(agent))
    except OSError:
        # Another agent already owns the port; that is the normal outcome of a start race.
        log.info("another agent is already listening on 127.0.0.1:%s; exiting (pid %s)", paths.PORT, os.getpid())
        return 3
    agent.server = server
    atomic_write(paths.AGENT_FILE, json.dumps({"port": paths.PORT, "token": agent.token, "pid": os.getpid()}).encode())
    try:
        os.remove(paths.SPAWN_LOCK)  # launchers waiting on the spawn claim can connect now
    except OSError:
        pass
    threading.Thread(target=agent.auto_lock_loop, daemon=True).start()
    log.info("agent %s listening on 127.0.0.1:%s (pid %s)", __version__, paths.PORT, os.getpid())
    try:
        server.serve_forever()
    finally:
        agent.lock_vault("agent stopped")
        try:
            with open(paths.AGENT_FILE, encoding="utf-8") as fh:
                if json.load(fh).get("pid") == os.getpid():
                    os.remove(paths.AGENT_FILE)
        except (OSError, ValueError):
            pass
        log.info("agent stopped")
    return 0
