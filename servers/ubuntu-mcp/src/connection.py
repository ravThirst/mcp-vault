"""SSH transport and host inventory for the Ubuntu remote-admin MCP server.

Hosts are read from a JSON inventory, in order of precedence:

  UBUNTU_MCP_HOSTS        inline JSON (list of host objects)
  UBUNTU_MCP_HOSTS_FILE   path to a JSON file
  <server dir>/hosts.json default file

Each host object:

  {"name": "web1", "host": "10.0.0.5", "port": 22, "username": "root",
   "password": "...", "key_file": "", "sudo_password": "", "readonly": false}

The file is re-read when it changes, so hosts can be added without restarting
Claude. Connections are opened lazily and reused; a dropped connection is
re-established on the next call.
"""

from __future__ import annotations

import base64
import json
import os
import shlex
import socket
import threading
import time
from dataclasses import dataclass, field

from mcp.server.mcpserver.exceptions import ToolError

MAX_OUTPUT_CHARS = 60_000

SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_HOSTS_FILE = os.path.join(SERVER_DIR, "hosts.json")


class ConfigError(ToolError):
    """Raised when the inventory is missing or a host entry is unusable.

    A ToolError, so the MCP SDK shows the message to the model (it hides the
    text of any other exception)."""


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def env_bool(name: str, default: bool = False) -> bool:
    raw = _env(name)
    if not raw:
        return default
    return raw.lower() in ("1", "true", "yes", "on")


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------


@dataclass
class Result:
    """Outcome of one remote command."""

    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def render(self) -> str:
        parts = []
        if self.stdout.strip():
            parts.append(_truncate(self.stdout.rstrip()))
        if self.stderr.strip():
            parts.append("--- stderr ---\n" + _truncate(self.stderr.rstrip()))
        if not parts:
            parts.append("(no output)")
        if self.timed_out:
            parts.append("--- TIMED OUT (command may still be running remotely) ---")
        else:
            parts.append(f"--- exit code: {self.exit_code} ---")
        return "\n".join(parts)


def _truncate(text: str) -> str:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    dropped = len(text) - MAX_OUTPUT_CHARS
    return text[:MAX_OUTPUT_CHARS] + f"\n... [truncated {dropped} more characters]"


# --------------------------------------------------------------------------
# Inventory
# --------------------------------------------------------------------------


@dataclass
class HostConfig:
    name: str
    host: str
    username: str
    port: int = 22
    password: str = ""
    key_file: str = ""
    sudo_password: str = ""
    readonly: bool = False
    description: str = ""

    @classmethod
    def from_dict(cls, raw: dict, index: int) -> "HostConfig":
        if not isinstance(raw, dict):
            raise ConfigError(f"host entry #{index} is not an object")
        host = str(raw.get("host", "")).strip()
        username = str(raw.get("username", "")).strip()
        name = str(raw.get("name", "") or host).strip()
        if not host:
            raise ConfigError(f"host entry #{index} ({name or '?'}) has no 'host'")
        if not username:
            raise ConfigError(f"host '{name}' has no 'username'")
        key_file = os.path.expanduser(str(raw.get("key_file", "") or "").strip())
        password = str(raw.get("password", "") or "")
        return cls(
            name=name,
            host=host,
            username=username,
            port=int(raw.get("port", 22) or 22),
            password=password,
            key_file=key_file,
            sudo_password=str(raw.get("sudo_password", "") or password),
            readonly=bool(raw.get("readonly", False)),
            description=str(raw.get("description", "") or ""),
        )


class Inventory:
    """Loads host definitions and hands out one cached connection per host."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hosts: dict[str, HostConfig] = {}
        self._source = ""
        self._mtime: float | None = None
        self._conns: dict[str, SSHConnection] = {}

    # -- loading ------------------------------------------------------------

    def _load(self) -> None:
        inline = _env("UBUNTU_MCP_HOSTS")
        if inline:
            if self._source == "env":
                return
            data = self._parse(inline, "UBUNTU_MCP_HOSTS")
            self._apply(data, "env")
            return

        path = os.path.expanduser(_env("UBUNTU_MCP_HOSTS_FILE") or DEFAULT_HOSTS_FILE)
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            raise ConfigError(
                f"no host inventory: {path} does not exist. Create it (see hosts.example.json) "
                "or set UBUNTU_MCP_HOSTS."
            ) from None
        if self._source == path and self._mtime == mtime:
            return
        with open(path, encoding="utf-8-sig") as fh:
            data = self._parse(fh.read(), path)
        self._apply(data, path)
        self._mtime = mtime

    @staticmethod
    def _parse(text: str, where: str) -> list:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"{where} is not valid JSON: {exc}") from None
        if isinstance(data, dict):
            data = data.get("hosts", [])
        if not isinstance(data, list):
            raise ConfigError(f"{where} must be a list of hosts or {{\"hosts\": [...]}}")
        return data

    def _apply(self, data: list, source: str) -> None:
        hosts: dict[str, HostConfig] = {}
        for i, raw in enumerate(data):
            cfg = HostConfig.from_dict(raw, i)
            key = cfg.name.lower()
            if key in hosts:
                raise ConfigError(f"duplicate host name '{cfg.name}'")
            hosts[key] = cfg
        # Drop connections whose settings changed or disappeared.
        for key, conn in list(self._conns.items()):
            if hosts.get(key) != conn.cfg:
                conn.close()
                del self._conns[key]
        self._hosts = hosts
        self._source = source

    # -- lookup -------------------------------------------------------------

    def hosts(self) -> list[HostConfig]:
        with self._lock:
            self._load()
            return list(self._hosts.values())

    def resolve(self, name: str) -> HostConfig:
        with self._lock:
            self._load()
            if not self._hosts:
                raise ConfigError("the host inventory is empty")
            names = ", ".join(h.name for h in self._hosts.values())
            if not name:
                if len(self._hosts) == 1:
                    return next(iter(self._hosts.values()))
                raise ConfigError(f"several hosts are configured - pass host=<name>. Valid: {names}")
            cfg = self._hosts.get(name.strip().lower())
            if cfg is None:
                # Allow addressing by IP/hostname as well as by name.
                matches = [h for h in self._hosts.values() if h.host.lower() == name.strip().lower()]
                if len(matches) == 1:
                    return matches[0]
                raise ConfigError(f"unknown host '{name}'. Valid: {names}")
            return cfg

    def connection(self, name: str) -> "SSHConnection":
        cfg = self.resolve(name)
        with self._lock:
            key = cfg.name.lower()
            conn = self._conns.get(key)
            if conn is None:
                conn = SSHConnection(cfg)
                self._conns[key] = conn
            return conn


# --------------------------------------------------------------------------
# SSH
# --------------------------------------------------------------------------


def wrap_script(script: str, working_dir: str = "") -> str:
    """Build a bash invocation that runs `script` verbatim.

    The script travels base64-encoded so multi-line bodies, quotes and `$` need
    no escaping, and a UTF-8 locale is forced so tool output is predictable.
    """
    body = script
    if working_dir:
        body = f"cd -- {shlex.quote(working_dir)} || exit 1\n{script}"
    encoded = base64.b64encode(body.encode("utf-8")).decode("ascii")
    return f"bash -c \"$(printf %s {encoded} | base64 -d)\""


@dataclass(eq=False)
class SSHConnection:
    cfg: HostConfig
    _client: object = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def describe(self) -> str:
        return f"ssh {self.cfg.username}@{self.cfg.host}:{self.cfg.port}"

    @property
    def is_root(self) -> bool:
        return self.cfg.username == "root"

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:  # noqa: BLE001
                pass
            self._client = None

    def _connect(self):
        import paramiko

        cfg = self.cfg
        if not cfg.password and not cfg.key_file:
            look_for_keys = True
        else:
            look_for_keys = bool(cfg.key_file)
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=cfg.host,
            port=cfg.port,
            username=cfg.username,
            password=cfg.password or None,
            key_filename=cfg.key_file or None,
            look_for_keys=look_for_keys,
            allow_agent=True,
            timeout=20,
            banner_timeout=30,
            auth_timeout=30,
        )
        transport = client.get_transport()
        if transport is not None:
            transport.set_keepalive(30)
        return client

    def client(self):
        with self._lock:
            t = self._client.get_transport() if self._client is not None else None
            if t is None or not t.is_active():
                self.close()
                self._client = self._connect()
            return self._client

    def exec(self, command: str, timeout_sec: int = 120, stdin_data: str = "") -> Result:
        """Run a raw command line, reading stdout and stderr concurrently."""
        client = self.client()
        transport = client.get_transport()
        chan = transport.open_session(timeout=20)
        chan.settimeout(1.0)
        chan.exec_command(command)
        if stdin_data:
            chan.sendall(stdin_data.encode("utf-8"))
        chan.shutdown_write()

        out, err = bytearray(), bytearray()
        deadline = time.monotonic() + max(1, timeout_sec)
        timed_out = False
        try:
            while True:
                progressed = False
                while chan.recv_ready():
                    out += chan.recv(65536)
                    progressed = True
                while chan.recv_stderr_ready():
                    err += chan.recv_stderr(65536)
                    progressed = True
                if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                    break
                if time.monotonic() > deadline:
                    timed_out = True
                    break
                if not progressed:
                    time.sleep(0.05)
            code = chan.recv_exit_status() if not timed_out else -1
        except socket.timeout:
            timed_out, code = True, -1
        finally:
            chan.close()
        return Result(
            out.decode("utf-8", errors="replace"),
            err.decode("utf-8", errors="replace"),
            code,
            timed_out,
        )

    def run(self, script: str, timeout_sec: int = 120, sudo: bool = False, working_dir: str = "") -> Result:
        """Run a bash script, optionally under sudo."""
        line = wrap_script(script, working_dir)
        stdin_data = ""
        if sudo and not self.is_root:
            # -S reads the password from stdin; -p '' keeps the prompt out of stderr.
            line = f"sudo -S -p '' -- {line}"
            stdin_data = self.cfg.sudo_password + "\n" if self.cfg.sudo_password else ""
        env = "LC_ALL=C.UTF-8 LANG=C.UTF-8 SYSTEMD_PAGER= PAGER=cat DEBIAN_FRONTEND=noninteractive"
        return self.exec(f"env {env} {line}", timeout_sec, stdin_data)

    # -- files --------------------------------------------------------------

    def upload(self, local_path: str, remote_path: str) -> str:
        size = os.path.getsize(local_path)
        sftp = self.client().open_sftp()
        try:
            sftp.put(local_path, remote_path)
        finally:
            sftp.close()
        return f"Uploaded {size} bytes to {self.cfg.name}:{remote_path}"

    def download(self, remote_path: str, local_path: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(local_path)) or ".", exist_ok=True)
        sftp = self.client().open_sftp()
        try:
            sftp.get(remote_path, local_path)
        finally:
            sftp.close()
        return f"Downloaded {self.cfg.name}:{remote_path} to {local_path} ({os.path.getsize(local_path)} bytes)"
