"""`vault.py run <server>`: what MCP clients actually start.

Asks the agent for the server's launch spec (starting the agent and showing
the unlock prompt if needed), then runs the real server with the decrypted
settings in its environment. stdin/stdout are inherited untouched so the MCP
stream flows straight through; stderr is copied to a per-server log with
secrets redacted. Nothing is ever written to stdout here.
"""

import datetime as _dt
import http.client
import json
import os
import subprocess
import sys
import threading
import time

from . import adapters, paths, winutil

UNLOCK_TIMEOUT = float(os.environ.get("MCPVAULT_UNLOCK_TIMEOUT", "180"))
SPAWN_CLAIM_TTL = 10


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


def run(server_id: str) -> int:
    try:
        spec, secrets = obtain(server_id)
    except LauncherError as exc:
        return _fail(str(exc))
    except OSError as exc:
        return _fail(f"cannot reach the MCP Vault agent: {exc}")

    log = ServerLog(server_id, secrets)
    problem = adapters.missing_command(spec["command"])
    if problem:
        return _fail(problem, log)
    env = dict(os.environ)
    env.update(spec["env"])
    try:
        proc = subprocess.Popen([spec["command"], *spec["args"]], cwd=spec["cwd"] or None, env=env, stderr=subprocess.PIPE)
    except OSError as exc:
        return _fail(adapters.redact(f"cannot start {spec['command']}: {exc}", secrets), log)
    try:
        winutil.kill_with_parent(proc)
    except OSError:
        pass
    log.note(f"started pid {proc.pid}")

    client = AgentClient()
    client._load()

    def notify(event: str) -> None:
        try:
            client.call("POST", "/internal/event", {"event": event, "server": server_id, "pid": proc.pid}, timeout=3)
        except OSError:
            pass

    notify("started")

    def pump() -> None:
        out = sys.stderr.buffer
        for line in proc.stderr:
            try:
                out.write(line)
                out.flush()
            except (OSError, ValueError):
                pass
            log.write(line)

    t = threading.Thread(target=pump, daemon=True)
    t.start()
    try:
        code = proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        code = proc.wait()
    t.join(timeout=2)
    log.note(f"exited with code {code}")
    notify("exited")
    return code
