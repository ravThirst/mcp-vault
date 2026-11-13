"""`vault.py run <server>`: persistent MCP stdio supervisor started by clients.

Unlocked vault, active server: asks the agent for the server's launch spec and
runs the real server with the decrypted settings in its environment, relaying
the MCP stream line by line (stdout carries nothing else) and keeping a copy of
the server's handshake and tool list (see toolcache).

Standby (locked vault, disabled server, or all hosts disabled): answers the
client's startup questions (initialize, tools/list) from that saved copy
without starting a child process (an empty tool list if there is no copy yet).
The real server starts on demand: on the first tool call (showing the unlock
prompt if locked) or automatically once the vault is unlocked / a host is
enabled; the handshake is replayed to it and the client is notified via
notifications/tools/list_changed if the tools differ. MCPVAULT_EAGER=1 restores
asking for the password at startup.

Live updates: while running, the launcher tracks the vault's revision counter.
When a host or server setting changes in MCP Vault, the launcher waits for any
in-flight tool call to finish, swaps in a fresh child process with the new
environment (replaying initialize behind the scenes), or stops the child back
into standby if its hosts were disabled — so client apps (Antigravity, Codex,
Claude, Kimi Work) never need to be restarted for host changes.

stderr is copied to a per-server log with secrets redacted.
"""

import copy
import datetime as _dt
import http.client
import json
import os
import queue
import subprocess
import sys
import threading
import time

from . import adapters, paths, toolcache, winutil

UNLOCK_TIMEOUT = float(os.environ.get("MCPVAULT_UNLOCK_TIMEOUT", "180"))
SPAWN_CLAIM_TTL = 20
EAGER = bool(os.environ.get("MCPVAULT_EAGER"))
POLL_SEC = float(os.environ.get("MCPVAULT_POLL_SEC", "2"))

# Ids of the requests the launcher itself sends to a server it starts or reloads on demand.
INIT_ID = "mcp-vault-init"
TOOLS_ID = "mcp-vault-tools"
# List requests a server without those features is asked anyway by some clients.
EMPTY_LISTS = {"resources/list": "resources", "resources/templates/list": "resourceTemplates", "prompts/list": "prompts"}
# The only requests worth starting / unlocking a server for: they need the real server.
# Anything else a client sends while in standby (e.g. server/discover) is answered
# "method not found", as a server without that feature would.
NEEDS_SERVER = {"tools/call", "resources/read", "prompts/get", "completion/complete"}

DEFAULT_INIT = {
    "jsonrpc": "2.0",
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "mcp-vault", "version": "1"},
    },
}


class LauncherError(Exception):
    pass


class LockedError(LauncherError):
    pass


class AgentClient:
    def __init__(self):
        self.port = paths.PORT
        self.token = ""
        self._mtime = 0.0

    def _load(self, force: bool = False) -> bool:
        try:
            mtime = os.path.getmtime(paths.AGENT_FILE)
            if not force and self.token and mtime == self._mtime:
                return True
            with open(paths.AGENT_FILE, encoding="utf-8") as fh:
                info = json.load(fh)
            self.port, self.token, self._mtime = int(info["port"]), info["token"], mtime
            return True
        except (OSError, ValueError, KeyError):
            return False

    def _request(self, method: str, path: str, body: dict | None, timeout: float) -> tuple[int, dict]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            payload = json.dumps(body or {}).encode("utf-8")
            conn.request(method, path, body=payload, headers={
                "Content-Type": "application/json", "X-Agent-Token": self.token, "Host": f"127.0.0.1:{self.port}"})
            resp = conn.getresponse()
            data = resp.read()
            try:
                return resp.status, json.loads(data or b"{}")
            except json.JSONDecodeError:
                return resp.status, {"error": data[:200].decode("utf-8", "replace")}
        finally:
            conn.close()

    def call(self, method: str, path: str, body: dict | None = None, timeout: float = 15) -> tuple[int, dict]:
        self._load()
        try:
            status, resp = self._request(method, path, body, timeout)
            if status != 403 or not self._load(force=True):
                return status, resp
            return self._request(method, path, body, timeout)
        except OSError:
            if not self._load(force=True):
                raise
            return self._request(method, path, body, timeout)

    def state(self) -> dict | None:
        """Return /internal/ping info if the agent is running, without starting it."""
        if not self._load():
            return None
        try:
            status, body = self.call("GET", "/internal/ping", timeout=2)
            return body if status == 200 else None
        except OSError:
            return None

    def ping(self) -> bool:
        return self.state() is not None

    def unlocked(self) -> bool:
        st = self.state()
        return bool(st and st.get("unlocked"))

    @staticmethod
    def _claim_spawn() -> bool:
        """Let exactly one of several launchers started together spawn the agent.

        The claim is a lock file the new agent deletes once it is listening; a
        claim older than SPAWN_CLAIM_TTL is treated as a failed start.
        """
        paths.ensure_dirs()
        try:
            if time.time() - os.path.getmtime(paths.SPAWN_LOCK) > SPAWN_CLAIM_TTL:
                os.remove(paths.SPAWN_LOCK)
        except OSError:
            pass
        try:
            os.close(os.open(paths.SPAWN_LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
            return True
        except OSError:
            return False

    def ensure_running(self) -> None:
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            if self.ping():
                return
            if self._claim_spawn():
                winutil.spawn_detached([paths.python_windowed(), paths.ENTRY, "agent"], paths.APP_DIR)
            time.sleep(0.3)
        detail = ""
        try:
            with open(paths.AGENT_LOG, encoding="utf-8", errors="replace") as fh:
                last = [ln.strip() for ln in fh.readlines()[-20:] if " ERROR " in ln or " WARNING " in ln]
            if last:
                detail = f": {last[-1].split(' ', 3)[-1]}"
        except OSError:
            pass
        raise LauncherError(f"could not start the MCP Vault agent{detail} (see {paths.AGENT_LOG}; "
                            "\"Stop MCP Vault\" from the Start menu clears a stuck agent)")


def obtain(server_id: str) -> tuple[int, dict]:
    """Resolve `server_id`, prompting to unlock if the vault is locked."""
    client = AgentClient()
    client.ensure_running()
    requested_at = None
    deadline = time.time() + UNLOCK_TIMEOUT
    while True:
        status, body = client.call("POST", "/internal/resolve", {"server": server_id})
        if status != 423:
            return status, body
        if requested_at is None:
            requested_at = time.time()
            client.call("POST", "/internal/request-unlock", {"server": server_id})
        elif body.get("cancelled_at", 0) >= requested_at:
            raise LockedError("the vault is locked and the unlock prompt was cancelled")
        if time.time() > deadline:
            raise LockedError("timed out waiting for the vault to be unlocked")
        time.sleep(0.5)


class ServerLog:
    MAX_BYTES = 1_000_000

    def __init__(self, server_id: str, secrets: list[str]):
        paths.ensure_dirs()
        self.path = os.path.join(paths.LOG_DIR, f"{server_id}.log")
        if os.path.exists(self.path) and os.path.getsize(self.path) > self.MAX_BYTES:
            os.replace(self.path, self.path + ".1")
        self.secrets = [s.encode("utf-8") for s in secrets]
        self.lock = threading.Lock()
        self.fh = open(self.path, "ab")

    def write(self, line: bytes) -> None:
        for s in self.secrets:
            line = line.replace(s, b"******")
        stamp = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S ").encode()
        with self.lock:
            if self.fh is None:
                return
            self.fh.write(stamp + line.rstrip(b"\r\n") + b"\n")
            self.fh.flush()

    def note(self, text: str) -> None:
        self.write(f"[mcp-vault] {text}".encode("utf-8"))

    def close(self) -> None:
        with self.lock:
            if self.fh is not None:
                self.fh.close()
                self.fh = None


def _log_note(server_id: str, text: str, secrets: list[str] | None = None) -> None:
    log = ServerLog(server_id, secrets or [])
    try:
        log.note(text)
    finally:
        log.close()


def _fail(message: str, server_id: str | None = None) -> int:
    sys.stderr.write(f"mcp-vault: {message}\n")
    sys.stderr.flush()
    if server_id:
        try:
            _log_note(server_id, message)
        except OSError:
            pass
    return 1


class ClientOut:
    """Newline-delimited JSON-RPC to the MCP client, one writer at a time."""

    def __init__(self):
        self._out = sys.stdout.buffer
        self._lock = threading.Lock()

    def raw(self, line: bytes) -> None:
        with self._lock:
            self._out.write(line if line.endswith(b"\n") else line + b"\n")
            self._out.flush()

    def send(self, msg: dict) -> None:
        self.raw(json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _parse(line: bytes):
    try:
        return json.loads(line)
    except ValueError:
        return None


def _error_reply(msg: dict, text: str) -> dict:
    """A tool call fails as a tool result the model can read; anything else as a JSON-RPC error."""
    if msg.get("method") == "tools/call":
        return {"jsonrpc": "2.0", "id": msg["id"], "result": {"content": [{"type": "text", "text": text}], "isError": True}}
    return {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32603, "message": text}}


def _locked_reply(msg: dict, reason: str) -> dict:
    return _error_reply(msg, f"MCP Vault is locked, so this server could not start ({reason}). "
                             "Unlock MCP Vault (Start menu > MCP Vault, or the password window) and call the tool again.")


class Child:
    """One running generation of the underlying MCP server process."""

    def __init__(self, session: "Session", spec: dict, secrets: list[str], activated: bool):
        problem = adapters.missing_command(spec["command"])
        if problem:
            raise LauncherError(problem)
        env = dict(os.environ)
        env.update(spec["env"])
        try:
            proc = subprocess.Popen([spec["command"], *spec["args"]], cwd=spec["cwd"] or None, env=env,
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as exc:
            raise LauncherError(adapters.redact(f"cannot start {spec['command']}: {exc}", secrets)) from None

        self.session = session
        self.proc = proc
        self.pid = proc.pid
        self.activated = activated
        self.log = ServerLog(session.server_id, secrets)
        try:
            self.job = winutil.kill_with_parent(proc)
        except OSError:
            self.job = None

        self._stdin_lock = threading.Lock()
        self._state_lock = threading.Condition()
        self.alive = True
        self.stopping = False
        self.in_flight: dict = {}
        self.watched: dict = {}
        self.captured: dict = {}
        self.init_done = threading.Event()

        self.log.note(f"started pid {self.pid}" + (" (on demand)" if activated else ""))
        self.notify("started")

        self._stderr_thread = threading.Thread(target=self._stderr_loop, daemon=True)
        self._stdout_thread = threading.Thread(target=self._stdout_loop, daemon=True)
        self._stderr_thread.start()
        self._stdout_thread.start()

    def notify(self, event: str) -> None:
        try:
            self.session.agent.call("POST", "/internal/event",
                                    {"event": event, "server": self.session.server_id, "pid": self.pid}, timeout=3)
        except OSError:
            pass

    def is_alive(self) -> bool:
        with self._state_lock:
            return self.alive

    def has_in_flight(self) -> bool:
        with self._state_lock:
            return bool(self.alive and self.in_flight)

    def wait_idle(self, timeout: float = 30.0) -> bool:
        deadline = time.monotonic() + timeout
        with self._state_lock:
            while self.alive and self.in_flight:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._state_lock.wait(remaining)
            return True

    def send_line(self, line: bytes) -> bool:
        try:
            with self._stdin_lock:
                self.proc.stdin.write(line if line.endswith(b"\n") else line + b"\n")
                self.proc.stdin.flush()
            return True
        except (OSError, ValueError):
            return False

    def send_msg(self, msg: dict) -> bool:
        return self.send_line(json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

    def activate(self, init_msg: dict) -> None:
        """Replay the client's MCP handshake to a child started or reloaded on demand."""
        if not self.send_msg({**init_msg, "id": INIT_ID}):
            raise LauncherError(f"server {self.session.server_id!r} exited during startup (see {self.log.path})")
        if not self.init_done.wait(60):
            self.log.note("the server did not answer the replayed initialize within 60 s")
        if not self.is_alive():
            raise LauncherError(f"server {self.session.server_id!r} exited during startup (see {self.log.path})")
        self.send_msg({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.send_msg({"jsonrpc": "2.0", "id": TOOLS_ID, "method": "tools/list", "params": {}})

    def forward(self, line: bytes, msg: dict | None) -> None:
        """Send a client JSON-RPC line to the child, tracking client requests until answered."""
        mid = msg.get("id") if isinstance(msg, dict) else None
        method = msg.get("method") if isinstance(msg, dict) else None
        is_request = isinstance(method, str) and mid is not None
        if is_request:
            with self._state_lock:
                self.in_flight[mid] = msg
                if method == "initialize":
                    self.watched[mid] = "initialize"
                elif method == "tools/list" and not (msg.get("params") or {}).get("cursor"):
                    self.watched[mid] = "tools"
        if not self.send_line(line) and is_request:
            with self._state_lock:
                orphaned = self.in_flight.pop(mid, None)
                self.watched.pop(mid, None)
                if not self.in_flight:
                    self._state_lock.notify_all()
            if orphaned is not None:
                self.session.out.send(_error_reply(
                    orphaned, f"MCP server {self.session.server_id!r} closed its input stream "
                              f"(see {self.log.path}). Call the tool again to restart it."))

    def stop(self, reason: str = "") -> None:
        with self._state_lock:
            self.stopping = True
        if reason:
            self.log.note(reason)
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                pass
        winutil.close_job(self.job)
        self.job = None
        self._stdout_thread.join(timeout=3.0)
        self._stderr_thread.join(timeout=2.0)

    def _stdout_loop(self) -> None:
        for line in self.proc.stdout:
            msg = _parse(line)
            mid = msg.get("id") if isinstance(msg, dict) else None
            is_response = isinstance(msg, dict) and mid is not None and "method" not in msg and (
                "result" in msg or "error" in msg)

            if mid == INIT_ID and is_response:
                if isinstance(msg.get("result"), dict):
                    self.captured["initialize"] = msg["result"]
                self.init_done.set()
                continue
            if mid == TOOLS_ID and is_response:
                tools = (msg.get("result") or {}).get("tools")
                if isinstance(tools, list):
                    self.captured["tools"] = tools
                    self.session.update_tools(self.captured.get("initialize"), tools, notify_client=True)
                continue

            watched_kind = None
            if is_response:
                with self._state_lock:
                    self.in_flight.pop(mid, None)
                    watched_kind = self.watched.pop(mid, None)
                    if not self.in_flight:
                        self._state_lock.notify_all()

            if watched_kind == "initialize" and isinstance(msg.get("result"), dict):
                raw_init = copy.deepcopy(msg["result"])
                self.captured["initialize"] = raw_init
                self.session.set_init_result(raw_init)
                caps = msg["result"].setdefault("capabilities", {})
                tools_cap = caps.get("tools") if isinstance(caps.get("tools"), dict) else {}
                caps["tools"] = {**tools_cap, "listChanged": True}
                try:
                    self.session.out.send(msg)
                except (OSError, ValueError):
                    break
                continue

            if watched_kind == "tools" and isinstance(msg.get("result"), dict):
                tools = msg["result"].get("tools")
                if isinstance(tools, list) and not msg["result"].get("nextCursor"):
                    self.captured["tools"] = tools
                    self.session.update_tools(self.captured.get("initialize"), tools, notify_client=False)

            try:
                self.session.out.raw(line)
            except (OSError, ValueError):
                break

        self.init_done.set()
        code = self.proc.wait()
        self._stderr_thread.join(timeout=2.0)
        with self._state_lock:
            self.alive = False
            stopping = self.stopping
            orphaned = list(self.in_flight.values())
            self.in_flight.clear()
            self.watched.clear()
            self._state_lock.notify_all()
        self.log.note(f"exited with code {code}" + (" (reloaded)" if stopping else ""))
        self.log.close()
        winutil.close_job(self.job)
        self.job = None
        self.notify("exited")
        if not stopping:
            for req in orphaned:
                try:
                    self.session.out.send(_error_reply(
                        req, f"MCP server {self.session.server_id!r} exited unexpectedly with code {code} "
                             f"(see {self.log.path}). Call the tool again to restart it."))
                except (OSError, ValueError):
                    break

    def _stderr_loop(self) -> None:
        err = sys.stderr.buffer
        for line in self.proc.stderr:
            try:
                err.write(line)
                err.flush()
            except (OSError, ValueError):
                pass
            self.log.write(line)


class Session:
    """Supervises one MCP stdio session across standby, on-demand starts and hot-reloads."""

    def __init__(self, server_id: str, agent: AgentClient, agent_pid: int | None):
        self.server_id = server_id
        self.agent = agent
        self.agent_pid = agent_pid
        self.out = ClientOut()

        cached = toolcache.load(server_id)
        self._tools_lock = threading.Lock()
        self.init_result: dict | None = copy.deepcopy(cached["initialize"]) if cached else None
        self.client_tools: list = list(cached["tools"]) if cached else []
        self._had_cache = cached is not None

        self.init_msg: dict | None = None
        self.child: Child | None = None
        self.spec: dict | None = None
        self.secrets: list[str] = []
        self.revision: int | None = None
        self.standby_reason: str | None = None

    def set_init_result(self, init_result: dict) -> None:
        with self._tools_lock:
            self.init_result = copy.deepcopy(init_result)

    def update_tools(self, init_result: dict | None, tools: list, notify_client: bool) -> None:
        changed = False
        with self._tools_lock:
            if init_result is not None:
                self.init_result = copy.deepcopy(init_result)
            saved_init = self.init_result
            if tools != self.client_tools:
                self.client_tools = copy.deepcopy(tools)
                changed = True
        if saved_init is not None:
            try:
                toolcache.save(self.server_id, saved_init, tools)
            except OSError:
                pass
        if notify_client and changed:
            try:
                self.out.send({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
            except (OSError, ValueError):
                pass

    def start_child(self, spec: dict, secrets: list[str], revision: int | None, activate: bool) -> None:
        child = Child(self, spec, secrets, activated=activate)
        if activate:
            try:
                child.activate(self.init_msg or DEFAULT_INIT)
            except LauncherError:
                child.stop()
                raise
        self.child = child
        self.spec = spec
        self.secrets = secrets
        self.revision = revision
        self.standby_reason = None

    def enter_standby(self, reason: str | None, revision: int | None, locked: bool) -> None:
        self.standby_reason = reason
        self.revision = revision
        saved = "from the saved tool list" if self._had_cache else "with an empty tool list (none saved yet)"
        if locked:
            _log_note(self.server_id, f"vault locked: answering startup {saved}; "
                                      "the server starts on the first tool call or when the vault is unlocked")
        else:
            _log_note(self.server_id, f"standby ({reason}): answering startup {saved}; "
                                      "the server starts automatically when enabled")

    def reconcile(self, for_request: bool = False) -> None:
        """Sync the running child with the vault's current state."""
        if self.child is not None and not self.child.is_alive():
            self.child = None
            self.spec = None
            self.secrets = []

        ping = self.agent.state()
        if ping is None:
            if not for_request or self.child is not None:
                return  # agent was stopped: keep running servers alive and leave standby quiet
            self.agent.ensure_running()
            ping = self.agent.state()
            if ping is None:
                raise LauncherError("cannot reach the MCP Vault agent")

        if ping.get("pid") and ping.get("pid") != self.agent_pid:
            self.agent_pid = ping["pid"]
            if self.child is not None:
                self.child.notify("started")

        if not ping.get("unlocked"):
            if self.child is not None:
                return  # running servers keep working when the vault locks
            if not for_request:
                self.standby_reason = None
                return
            _log_note(self.server_id, "tool call needs the server: asking to unlock the vault")
            status, body = obtain(self.server_id)
        else:
            need_resolve = (ping.get("revision") != self.revision) or (for_request and self.child is None)
            if not need_resolve:
                return
            if not for_request and self.child is None and self.init_msg is None:
                return  # wait until the client has completed initialize before background-starting
            if not for_request and self.child is not None and self.child.has_in_flight():
                return  # let the running tool call finish; the next poll swaps cleanly
            try:
                status, body = self.agent.call("POST", "/internal/resolve", {"server": self.server_id})
            except OSError as exc:
                if for_request and self.child is None:
                    raise LauncherError(f"cannot reach the MCP Vault agent: {exc}") from None
                return
            if status == 423:
                if self.child is not None or not for_request:
                    return
                status, body = obtain(self.server_id)

        rev = body.get("revision")
        if status == 200:
            spec, secrets = body["spec"], body["secrets"]
            if self.child is not None and spec == self.spec and secrets == self.secrets:
                self.revision = rev
                self.standby_reason = None
                return
            if self.child is not None:
                self.child.wait_idle(timeout=60.0)
                self.child.stop("reloading server: settings changed in MCP Vault")
                self.child = None
                self.spec = None
                self.secrets = []
            try:
                self.start_child(spec, secrets, rev, activate=self.init_msg is not None or for_request)
            except LauncherError as exc:
                self.revision = rev
                self.standby_reason = str(exc)
                _log_note(self.server_id, f"could not start server: {exc}")
                if for_request:
                    raise
            return

        reason = body.get("error") or f"agent answered HTTP {status}"
        if self.child is not None:
            self.child.wait_idle(timeout=30.0)
            self.child.stop(f"stopping server: {reason}")
            self.child = None
            self.spec = None
            self.secrets = []
        self.revision = rev
        self.standby_reason = reason
        if for_request:
            raise LauncherError(reason)

    def _answer_standby_initialize(self, msg: dict) -> None:
        with self._tools_lock:
            saved_init = copy.deepcopy(self.init_result)
        if saved_init:
            result = saved_init
        else:
            note = self.standby_reason or "MCP Vault is locked; this server's tools appear once it is unlocked."
            result = {
                "protocolVersion": (msg.get("params") or {}).get("protocolVersion", "2025-06-18"),
                "serverInfo": {"name": self.server_id, "version": "0"},
                "instructions": note,
            }
        caps = result.setdefault("capabilities", {})
        tools_cap = caps.get("tools") if isinstance(caps.get("tools"), dict) else {}
        caps["tools"] = {**tools_cap, "listChanged": True}
        self.out.send({"jsonrpc": "2.0", "id": msg["id"], "result": result})

    def handle_client_line(self, line: bytes) -> None:
        if self.child is not None and not self.child.is_alive():
            self.child = None
            self.spec = None
            self.secrets = []

        msg = _parse(line)
        if not isinstance(msg, dict):
            if self.child is not None:
                self.child.send_line(line)
            return

        method, mid = msg.get("method"), msg.get("id")
        if method == "initialize" and mid is not None:
            self.init_msg = msg

        if mid is not None and method in NEEDS_SERVER:
            try:
                self.reconcile(for_request=True)
            except LockedError as exc:
                self.out.send(_locked_reply(msg, str(exc)))
                return
            except LauncherError as exc:
                self.out.send(_error_reply(msg, str(exc)))
                return

        if self.child is not None and self.child.is_alive():
            if method == "initialize" and mid is not None and self.child.activated:
                self._answer_standby_initialize(msg)
                return
            self.child.forward(line, msg)
            return

        if mid is None:
            return
        if method == "initialize":
            self._answer_standby_initialize(msg)
        elif method == "ping":
            self.out.send({"jsonrpc": "2.0", "id": mid, "result": {}})
        elif method == "tools/list":
            with self._tools_lock:
                if not self.client_tools:
                    cached = toolcache.load(self.server_id)
                    if cached:
                        self.init_result = copy.deepcopy(cached["initialize"])
                        self.client_tools = list(cached["tools"])
                tools = list(self.client_tools)
            self.out.send({"jsonrpc": "2.0", "id": mid, "result": {"tools": tools}})
        elif method in EMPTY_LISTS:
            self.out.send({"jsonrpc": "2.0", "id": mid, "result": {EMPTY_LISTS[method]: []}})
        else:
            self.out.send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"Method not found: {method}"}})

    def serve(self) -> int:
        lines: queue.Queue = queue.Queue()

        def reader() -> None:
            for raw in sys.stdin.buffer:
                lines.put(raw)
            lines.put(None)

        threading.Thread(target=reader, daemon=True).start()

        try:
            while True:
                try:
                    line = lines.get(timeout=POLL_SEC)
                except queue.Empty:
                    try:
                        self.reconcile(for_request=False)
                    except LauncherError:
                        pass
                    continue
                if line is None:
                    return 0
                self.handle_client_line(line)
        except KeyboardInterrupt:
            return 0
        finally:
            if self.child is not None:
                self.child.stop()
                self.child = None


def run(server_id: str) -> int:
    client = AgentClient()
    try:
        client.ensure_running()
        ping = client.state()
        status, body = client.call("POST", "/internal/resolve", {"server": server_id})
    except LauncherError as exc:
        return _fail(str(exc))
    except OSError as exc:
        return _fail(f"cannot reach the MCP Vault agent: {exc}")

    session = Session(server_id, client, agent_pid=(ping or {}).get("pid"))

    if status == 423 and EAGER:
        try:
            status, body = obtain(server_id)
        except LauncherError as exc:
            return _fail(str(exc), server_id)
        except OSError as exc:
            return _fail(f"cannot reach the MCP Vault agent: {exc}", server_id)

    if status == 200:
        try:
            session.start_child(body["spec"], body["secrets"], body.get("revision"), activate=False)
        except LauncherError as exc:
            return _fail(str(exc), server_id)
        return session.serve()

    if status == 423:
        session.enter_standby(None, body.get("revision"), locked=True)
        return session.serve()

    if body.get("standby"):
        session.enter_standby(body.get("error") or "server is inactive", body.get("revision"), locked=False)
        return session.serve()

    return _fail(body.get("error") or f"agent answered HTTP {status}", server_id)
