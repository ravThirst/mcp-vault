"""`vault.py run <server>`: what MCP clients actually start.

Unlocked vault: asks the agent for the server's launch spec and runs the real
server with the decrypted settings in its environment, relaying the MCP stream
line by line (stdout carries nothing else) and keeping a copy of the server's
handshake and tool list (see toolcache).

Locked vault: never asks at startup. The client's startup questions
(initialize, tools/list) are answered from that copy without credentials (an
empty tool list if there is no copy yet). The real server starts on demand:
on the first tool call, which shows the unlock prompt, or as soon as the vault
is unlocked some other way (another server's tool call, the MCP Vault window);
the handshake is replayed to it and the client is told if the tools differ.
MCPVAULT_EAGER=1 restores asking at startup.

stderr is copied to a per-server log with secrets redacted.
"""

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
SPAWN_CLAIM_TTL = 10
EAGER = bool(os.environ.get("MCPVAULT_EAGER"))
UNLOCK_POLL_SEC = 3  # how often a waiting server checks whether the vault was unlocked elsewhere

# Ids of the requests the launcher itself sends to a server it starts on demand.
INIT_ID = "mcp-vault-init"
TOOLS_ID = "mcp-vault-tools"
# List requests a server without those features is asked anyway by some clients.
EMPTY_LISTS = {"resources/list": "resources", "resources/templates/list": "resourceTemplates", "prompts/list": "prompts"}
# The only requests worth an unlock prompt while locked: they need the real server.
# Anything else a client sends at startup (e.g. server/discover) is answered
# "method not found", as a server without that feature would.
NEEDS_SERVER = {"tools/call", "resources/read", "prompts/get", "completion/complete"}


class LauncherError(Exception):
    pass


class AgentClient:
    def __init__(self):
        self.port = paths.PORT
        self.token = ""

    def _load(self) -> bool:
        try:
            with open(paths.AGENT_FILE, encoding="utf-8") as fh:
                info = json.load(fh)
            self.port, self.token = int(info["port"]), info["token"]
            return True
        except (OSError, ValueError, KeyError):
            return False

    def call(self, method: str, path: str, body: dict | None = None, timeout: float = 15) -> tuple[int, dict]:
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

    def ping(self) -> bool:
        if not self._load():
            return False
        try:
            status, _ = self.call("GET", "/internal/ping", timeout=3)
            return status == 200
        except OSError:
            return False

    def unlocked(self) -> bool:
        if not self._load():
            return False
        try:
            status, body = self.call("GET", "/internal/ping", timeout=3)
            return status == 200 and bool(body.get("unlocked"))
        except OSError:
            return False

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
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if self.ping():
                return
            if self._claim_spawn():
                winutil.spawn_detached([paths.python_windowed(), paths.ENTRY, "agent"], paths.APP_DIR)
            time.sleep(0.3)
        raise LauncherError(f"could not start the MCP Vault agent (see {paths.AGENT_LOG})")


def obtain(server_id: str) -> tuple[dict, list[str]]:
    client = AgentClient()
    client.ensure_running()
    requested_at = None
    deadline = time.time() + UNLOCK_TIMEOUT
    while True:
        status, body = client.call("POST", "/internal/resolve", {"server": server_id})
        if status == 200:
            return body["spec"], body["secrets"]
        if status != 423:
            raise LauncherError(body.get("error") or f"agent answered HTTP {status}")
        if requested_at is None:
            requested_at = time.time()
            client.call("POST", "/internal/request-unlock", {"server": server_id})
        elif body.get("cancelled_at", 0) >= requested_at:
            raise LauncherError("the vault is locked and the unlock prompt was cancelled")
        if time.time() > deadline:
            raise LauncherError("timed out waiting for the vault to be unlocked")
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
            self.fh.write(stamp + line.rstrip(b"\r\n") + b"\n")
            self.fh.flush()

    def note(self, text: str) -> None:
        self.write(f"[mcp-vault] {text}".encode("utf-8"))


def _fail(message: str, log: ServerLog | None = None) -> int:
    sys.stderr.write(f"mcp-vault: {message}\n")
    sys.stderr.flush()
    if log:
        log.note(message)
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


def run(server_id: str) -> int:
    try:
        client = AgentClient()
        client.ensure_running()
        status, body = client.call("POST", "/internal/resolve", {"server": server_id})
    except LauncherError as exc:
        return _fail(str(exc))
    except OSError as exc:
        return _fail(f"cannot reach the MCP Vault agent: {exc}")

    if status == 200:
        return _serve(server_id, body["spec"], body["secrets"], ClientOut())
    if status != 423:
        return _fail(body.get("error") or f"agent answered HTTP {status}")
    if not EAGER:
        return _serve_locked(server_id, toolcache.load(server_id))
    try:
        spec, secrets = obtain(server_id)
    except LauncherError as exc:
        return _fail(str(exc))
    except OSError as exc:
        return _fail(f"cannot reach the MCP Vault agent: {exc}")
    return _serve(server_id, spec, secrets, ClientOut())


def _error_reply(msg: dict, text: str) -> dict:
    """A tool call fails as a tool result the model can read; anything else as a JSON-RPC error."""
    if msg.get("method") == "tools/call":
        return {"jsonrpc": "2.0", "id": msg["id"], "result": {"content": [{"type": "text", "text": text}], "isError": True}}
    return {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32603, "message": text}}


def _locked_reply(msg: dict, reason: str) -> dict:
    return _error_reply(msg, f"MCP Vault is locked, so this server could not start ({reason}). "
                             "Unlock MCP Vault (Start menu > MCP Vault, or the password window) and call the tool again.")


def _serve_locked(server_id: str, cached: dict | None) -> int:
    """Answer the handshake without credentials until the real server is needed.

    `cached` is the saved handshake, or None: then the client gets an empty tool
    list, filled in (via tools/list_changed) once the server can start.
    """
    out = ClientOut()
    log = ServerLog(server_id, [])
    log.note("vault locked: answering startup " + ("from the saved tool list" if cached else "with an empty tool list (none saved yet)")
             + "; the server starts on the first tool call or when the vault is unlocked")
    tools = cached["tools"] if cached else []

    # stdin is read on a thread so the loop can also notice an unlock that happens elsewhere.
    lines: queue.Queue = queue.Queue()

    def reader() -> None:
        for raw in sys.stdin.buffer:
            lines.put(raw)
        lines.put(None)

    threading.Thread(target=reader, daemon=True).start()

    def remaining_lines():
        """What the real server reads once it runs: everything the client sends from then on."""
        while (item := lines.get()) is not None:
            yield item

    agent = AgentClient()
    init_msg = None
    poll = True  # stops after a failed background start, so a broken server is not retried every few seconds
    while True:
        try:
            line = lines.get(timeout=UNLOCK_POLL_SEC)
        except queue.Empty:
            if init_msg is not None and poll and agent.unlocked():
                try:
                    spec, secrets = obtain(server_id)
                except (LauncherError, OSError) as exc:
                    log.note(f"vault unlocked, but the server could not start: {exc}")
                    poll = False
                    continue
                log.note("vault unlocked elsewhere: starting the server")
                return _serve(server_id, spec, secrets, out, source=remaining_lines(),
                              activation={"init": init_msg, "trigger": None, "cached_tools": tools})
            continue
        if line is None:
            log.note("client closed the connection; the server was not needed")
            return 0
        msg = _parse(line)
        if not isinstance(msg, dict):
            continue
        method, mid = msg.get("method"), msg.get("id")
        if mid is None:
            continue  # notifications (initialized, cancelled, ...) need no answer while nothing runs
        if method == "initialize":
            init_msg = msg
            if cached:
                result = json.loads(json.dumps(cached["initialize"]))
            else:
                result = {"protocolVersion": (msg.get("params") or {}).get("protocolVersion", "2025-06-18"),
                          "serverInfo": {"name": server_id, "version": "0"},
                          "instructions": "MCP Vault is locked; this server's tools appear once it is unlocked."}
            caps = result.setdefault("capabilities", {})
            tools_cap = caps.get("tools") if isinstance(caps.get("tools"), dict) else {}
            caps["tools"] = {**tools_cap, "listChanged": True}  # lets us announce the real list later
            out.send({"jsonrpc": "2.0", "id": mid, "result": result})
        elif method == "ping":
            out.send({"jsonrpc": "2.0", "id": mid, "result": {}})
        elif method == "tools/list":
            out.send({"jsonrpc": "2.0", "id": mid, "result": {"tools": tools}})
        elif method in EMPTY_LISTS:
            out.send({"jsonrpc": "2.0", "id": mid, "result": {EMPTY_LISTS[method]: []}})
        elif method not in NEEDS_SERVER:
            out.send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"Method not found: {method}"}})
        else:
            log.note(f"{method} needs the server: asking to unlock the vault")
            try:
                spec, secrets = obtain(server_id)
            except (LauncherError, OSError) as exc:
                log.note(f"not started: {exc}")
                out.send(_locked_reply(msg, str(exc)))
                continue
            if init_msg is None:
                init_msg = {"jsonrpc": "2.0", "method": "initialize", "params": {
                    "protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "mcp-vault", "version": "1"}}}
            return _serve(server_id, spec, secrets, out, source=remaining_lines(),
                          activation={"init": init_msg, "trigger": line, "cached_tools": tools})


def _serve(server_id: str, spec: dict, secrets: list[str], out: ClientOut,
           activation: dict | None = None, source=None) -> int:
    """Run the real server and relay the MCP stream.

    With `activation` (started on demand from the locked state), the client's
    handshake is replayed to the server first, the server's tool list is
    checked against the copy the client was given, and the request that
    triggered the start (if any) is passed on. `source` yields the client's
    lines when stdin is already being read elsewhere.
    """
    log = ServerLog(server_id, secrets)
    problem = adapters.missing_command(spec["command"])
    if problem:
        if activation and activation["trigger"]:  # the client is waiting for an answer to the request that started us
            msg = _parse(activation["trigger"])
            if isinstance(msg, dict) and msg.get("id") is not None:
                out.send(_error_reply(msg, f"MCP Vault could not start this server: {problem}"))
        return _fail(problem, log)
    env = dict(os.environ)
    env.update(spec["env"])
    try:
        proc = subprocess.Popen([spec["command"], *spec["args"]], cwd=spec["cwd"] or None, env=env,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        problem = adapters.redact(f"cannot start {spec['command']}: {exc}", secrets)
        if activation and activation["trigger"]:
            msg = _parse(activation["trigger"])
            if isinstance(msg, dict) and msg.get("id") is not None:
                out.send(_error_reply(msg, f"MCP Vault could not start this server: {problem}"))
        return _fail(problem, log)
    try:
        winutil.kill_with_parent(proc)
    except OSError:
        pass
    log.note(f"started pid {proc.pid}" + (" (on demand)" if activation else ""))

    client = AgentClient()
    client._load()

    def notify(event: str) -> None:
        try:
            client.call("POST", "/internal/event", {"event": event, "server": server_id, "pid": proc.pid}, timeout=3)
        except OSError:
            pass

    notify("started")

    # Requests whose answers refresh the saved handshake: id -> "initialize" | "tools".
    watched: dict = {}
    captured: dict = {}
    init_done = threading.Event()
    child_lock = threading.Lock()

    def to_child(line: bytes) -> bool:
        try:
            with child_lock:
                proc.stdin.write(line if line.endswith(b"\n") else line + b"\n")
                proc.stdin.flush()
            return True
        except (OSError, ValueError):
            return False

    def to_child_msg(msg: dict) -> bool:
        return to_child(json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

    def watch(line: bytes) -> None:
        msg = _parse(line)
        if not isinstance(msg, dict) or msg.get("id") is None:
            return
        if msg.get("method") == "initialize":
            watched[msg["id"]] = "initialize"
        elif msg.get("method") == "tools/list" and not (msg.get("params") or {}).get("cursor"):
            watched[msg["id"]] = "tools"

    def remember() -> None:
        if "initialize" in captured and "tools" in captured:
            try:
                toolcache.save(server_id, captured["initialize"], captured["tools"])
            except OSError:
                pass

    def client_to_server() -> None:
        try:
            if activation:
                to_child_msg({**activation["init"], "id": INIT_ID})
                if not init_done.wait(60):
                    log.note("the server did not answer the replayed initialize within 60 s")
                to_child_msg({"jsonrpc": "2.0", "method": "notifications/initialized"})
                to_child_msg({"jsonrpc": "2.0", "id": TOOLS_ID, "method": "tools/list", "params": {}})
                if activation["trigger"]:
                    watch(activation["trigger"])
                    to_child(activation["trigger"])
            for line in (source if source is not None else sys.stdin.buffer):
                watch(line)
                if not to_child(line):
                    break
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    def server_to_client() -> None:
        for line in proc.stdout:
            msg = _parse(line)
            mid = msg.get("id") if isinstance(msg, dict) else None
            if mid == INIT_ID and activation:
                captured["initialize"] = msg.get("result") or {}
                init_done.set()
                continue
            if mid == TOOLS_ID and activation:
                tools = (msg.get("result") or {}).get("tools")
                if isinstance(tools, list):
                    captured["tools"] = tools
                    remember()
                    if tools != activation["cached_tools"]:
                        out.send({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
                continue
            if mid is not None and mid in watched and isinstance(msg.get("result"), dict):
                kind = watched.pop(mid)
                if kind == "initialize":
                    captured["initialize"] = msg["result"]
                elif isinstance(msg["result"].get("tools"), list) and not msg["result"].get("nextCursor"):
                    captured["tools"] = msg["result"]["tools"]
                    remember()
            try:
                out.raw(line)
            except (OSError, ValueError):
                break
        init_done.set()

    def stderr_pump() -> None:
        err = sys.stderr.buffer
        for line in proc.stderr:
            try:
                err.write(line)
                err.flush()
            except (OSError, ValueError):
                pass
            log.write(line)

    threading.Thread(target=client_to_server, daemon=True).start()
    relay = threading.Thread(target=server_to_client, daemon=True)
    relay.start()
    pump = threading.Thread(target=stderr_pump, daemon=True)
    pump.start()
    try:
        code = proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        code = proc.wait()
    relay.join(timeout=2)
    pump.join(timeout=2)
    log.note(f"exited with code {code}")
    notify("exited")
    return code
