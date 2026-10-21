"""Configuration, host inventory and connections for the example MCP server.

Hosts are read from, in order of precedence:

  EXAMPLE_MCP_HOSTS        inline JSON: {"hosts": [...]} or [...]
  EXAMPLE_MCP_HOSTS_FILE   path to a JSON file in the same format

MCP Vault fills EXAMPLE_MCP_HOSTS (server template "inventory"), so in normal use
no file with passwords exists. Each host object (SERVER-SPEC shape):

  {"name": "web1", "host": "10.0.0.5", "port": 22, "username": "admin",
   "password": "...", "key_file": "", "sudo_password": "", "readonly": false,
   "description": "", "kind": "linux"}

Connections are opened lazily on the first tool call, so the server starts (and
answers `initialize`) even when a host is down.

To adapt: rename ENV_PREFIX, then replace Connection._connect / Connection.run
with the target's own client (HTTP API, RouterOS API, database driver, ...).
Keep the inventory and the error handling: they are what makes every server
behave the same way.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field

ENV_PREFIX = "EXAMPLE"  # -> EXAMPLE_MCP_HOSTS, EXAMPLE_MCP_HOSTS_FILE, EXAMPLE_MCP_READONLY
MAX_OUTPUT_CHARS = 60_000


class ConfigError(RuntimeError):
    """The inventory is missing or an entry is unusable. Messages never contain secrets."""


def env(name: str, default: str = "") -> str:
    return os.environ.get(f"{ENV_PREFIX}_{name}", default).strip()


def env_bool(name: str) -> bool:
    return env(name).lower() in ("1", "true", "yes", "on")


def truncate(text: str) -> str:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    return text[:MAX_OUTPUT_CHARS] + f"\n... [truncated {len(text) - MAX_OUTPUT_CHARS} more characters]"


# --------------------------------------------------------------------------
# Inventory
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class HostConfig:
    name: str
    host: str
    username: str = ""
    port: int = 22
    password: str = field(default="", repr=False)
    key_file: str = ""
    sudo_password: str = field(default="", repr=False)
    readonly: bool = False
    description: str = ""
    kind: str = ""

    @classmethod
    def from_dict(cls, raw: object, index: int) -> "HostConfig":
        if not isinstance(raw, dict):
            raise ConfigError(f"host entry #{index} is not an object")
        host = str(raw.get("host", "")).strip()
        name = str(raw.get("name", "") or host).strip()
        if not host:
            raise ConfigError(f"host entry #{index} ({name or '?'}) has no 'host'")
        try:
            port = int(raw.get("port", 22) or 22)
        except (TypeError, ValueError):
            raise ConfigError(f"host '{name}' has an invalid port") from None
        password = str(raw.get("password", "") or "")
        return cls(
            name=name,
            host=host,
            username=str(raw.get("username", "") or "").strip(),
            port=port,
            password=password,
            key_file=os.path.expanduser(str(raw.get("key_file", "") or "").strip()),
            sudo_password=str(raw.get("sudo_password", "") or password),
            readonly=bool(raw.get("readonly", False)),
            description=str(raw.get("description", "") or ""),
            kind=str(raw.get("kind", "") or ""),
        )


class Inventory:
    """Loads host definitions and hands out one cached connection per host."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hosts: dict[str, HostConfig] = {}
        self._source = ""
        self._mtime: float | None = None
        self._conns: dict[str, Connection] = {}

    def _load(self) -> None:
        inline = env("MCP_HOSTS")
        if inline:
            if self._source != "env":
                self._apply(self._parse(inline, f"{ENV_PREFIX}_MCP_HOSTS"), "env")
            return
        path = os.path.expanduser(env("MCP_HOSTS_FILE"))
        if not path:
            raise ConfigError(
                f"no hosts configured: set {ENV_PREFIX}_MCP_HOSTS (MCP Vault does this when the server "
                f"uses the 'inventory' template) or {ENV_PREFIX}_MCP_HOSTS_FILE"
            )
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            raise ConfigError(f"host file {path} does not exist") from None
        if self._source == path and self._mtime == mtime:
            return
        with open(path, encoding="utf-8-sig") as fh:
            self._apply(self._parse(fh.read(), path), path)
        self._mtime = mtime

    @staticmethod
    def _parse(text: str, where: str) -> list:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            # Position only: the text contains passwords.
            raise ConfigError(f"{where} is not valid JSON (line {exc.lineno}, column {exc.colno})") from None
        if isinstance(data, dict):
            data = data.get("hosts", [])
        if not isinstance(data, list):
            raise ConfigError(f'{where} must be a list of hosts or {{"hosts": [...]}}')
        return data

    def _apply(self, data: list, source: str) -> None:
        hosts: dict[str, HostConfig] = {}
        for i, raw in enumerate(data):
            cfg = HostConfig.from_dict(raw, i)
            key = cfg.name.lower()
            if key in hosts:
                raise ConfigError(f"duplicate host name '{cfg.name}'")
            hosts[key] = cfg
        for key, conn in list(self._conns.items()):
            if hosts.get(key) != conn.cfg:  # settings changed or host removed
                conn.close()
                del self._conns[key]
        self._hosts, self._source = hosts, source

    def hosts(self) -> list[HostConfig]:
        with self._lock:
            self._load()
            return list(self._hosts.values())

    def resolve(self, name: str = "") -> HostConfig:
        """Find a host by name (or address). Errors list the valid names so the caller can retry."""
        with self._lock:
            self._load()
            if not self._hosts:
                raise ConfigError("the host inventory is empty")
            names = ", ".join(h.name for h in self._hosts.values())
            wanted = (name or "").strip().lower()
            if not wanted:
                if len(self._hosts) == 1:
                    return next(iter(self._hosts.values()))
                raise ConfigError(f"several hosts are configured - pass host=<name>. Valid: {names}")
            cfg = self._hosts.get(wanted)
            if cfg is None:
                matches = [h for h in self._hosts.values() if h.host.lower() == wanted]
                if len(matches) == 1:
                    return matches[0]
                raise ConfigError(f"unknown host '{name}'. Valid: {names}")
            return cfg

    def connection(self, name: str = "") -> "Connection":
        cfg = self.resolve(name)
        with self._lock:
            conn = self._conns.get(cfg.name.lower())
            if conn is None:
                conn = self._conns[cfg.name.lower()] = Connection(cfg)
            return conn


# --------------------------------------------------------------------------
# Connection: SSH by default; replace for other targets
# --------------------------------------------------------------------------


@dataclass
class Result:
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def render(self) -> str:
        parts = [truncate(self.stdout.rstrip())] if self.stdout.strip() else []
        if self.stderr.strip():
            parts.append("--- stderr ---\n" + truncate(self.stderr.rstrip()))
        parts.append("--- TIMED OUT ---" if self.timed_out else f"--- exit code: {self.exit_code} ---")
        return "\n".join(parts)


@dataclass(eq=False)
class Connection:
    cfg: HostConfig
    _client: object = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def describe(self) -> str:
        return f"{self.cfg.username}@{self.cfg.host}:{self.cfg.port}"

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:  # noqa: BLE001
                pass
            self._client = None

    def _connect(self):
        import paramiko

        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.cfg.host, port=self.cfg.port, username=self.cfg.username,
            password=self.cfg.password or None, key_filename=self.cfg.key_file or None,
            look_for_keys=not self.cfg.password and not self.cfg.key_file, allow_agent=True,
            timeout=15, banner_timeout=20, auth_timeout=20,
        )
        transport = client.get_transport()
        if transport is not None:
            transport.set_keepalive(30)
        return client

    def client(self):
        """The live client, reconnecting if the previous connection dropped."""
        with self._lock:
            t = self._client.get_transport() if self._client is not None else None
            if t is None or not t.is_active():
                self.close()
                self._client = self._connect()
            return self._client

    def run(self, command: str, timeout_sec: int = 60) -> Result:
        _, stdout, stderr = self.client().exec_command(command, timeout=timeout_sec)
        chan = stdout.channel
        deadline = time.monotonic() + timeout_sec
        while not chan.exit_status_ready():
            if time.monotonic() > deadline:
                chan.close()
                return Result(stdout.read().decode("utf-8", "replace"), "", -1, timed_out=True)
            time.sleep(0.05)
        return Result(stdout.read().decode("utf-8", "replace"), stderr.read().decode("utf-8", "replace"),
                      chan.recv_exit_status())
