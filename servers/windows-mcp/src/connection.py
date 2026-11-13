"""Host inventory and transports for the Windows remote-admin MCP server.

Hosts are read from, in order of precedence:

  WINDOWS_MCP_HOSTS        inline JSON: {"hosts": [...]} or [...]   (MCP Vault fills this)
  WINDOWS_MCP_HOSTS_FILE   path to a JSON file in the same format
  WINDOWS_HOST, ...        the original single-host variables (still supported)

Each host object:

  {"name": "office-pc", "host": "10.0.0.5", "port": 22, "username": "admin",
   "password": "...", "key_file": "", "protocol": "ssh", "use_ssl": false,
   "readonly": false, "description": ""}

Three transports, chosen per host with "protocol" (default WINDOWS_MCP_TRANSPORT,
else winrm):

  winrm  PowerShell Remoting over WS-Man. Needs WinRM enabled on the target
         (`Enable-PSRemoting -Force`). Port 5985 (http) or 5986 (https).
  ssh    OpenSSH Server on the target. Port 22. Also gives SFTP for file
         transfer, which is much faster than the WinRM base64-chunk fallback.
  agent  agent/winmcp-agent.ps1 running on the target, for machines where WinRM
         and SSH are unavailable. Port 5990. "password" holds the agent key and
         no username is needed. Requests are encrypted and signed with that key.

Connections are opened lazily, on the first tool call for that host, and reused.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field

from mcp.server.mcpserver.exceptions import ToolError

MAX_OUTPUT_CHARS = 60_000

# Outer Out-String width. Anything the tools format as a table is already
# rendered to text before this, so this only governs how long a raw line may be
# before PowerShell folds it - log lines need plenty of room.
OUT_WIDTH = 8192


def wrap_ps(script: str) -> str:
    """Wrap a PowerShell script so its output comes back as UTF-8 on one stream.

    Windows PowerShell encodes redirected output using the console code page,
    which mangles every non-ASCII character on a localized server (event log
    levels, service display names, paths). Rather than guess the code page, the
    script's output is captured, converted to UTF-8 bytes and written straight
    to the standard output handle, bypassing console encoding entirely.

    The script itself travels as base64 so multi-line bodies and embedded quotes
    need no escaping, and errors are folded into the output as readable text
    instead of vanishing.
    """
    encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
    return (
        "$ProgressPreference='SilentlyContinue';"
        "$ErrorActionPreference='Continue';"
        "try{[Console]::OutputEncoding=[Text.Encoding]::UTF8}catch{};"
        "$__code=0;$global:LASTEXITCODE=0;"
        f"$__src=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}'));"
        "try{"
        "$__sb=[ScriptBlock]::Create($__src);"
        f"$__out=(& $__sb 2>&1|Out-String -Width {OUT_WIDTH})"
        "}catch{"
        "$__out='ERROR: '+$_.Exception.Message+[Environment]::NewLine+$_.ScriptStackTrace;"
        "$__code=1};"
        "if($LASTEXITCODE -and $LASTEXITCODE -ne 0){$__code=$LASTEXITCODE};"
        "$__b=[Text.Encoding]::UTF8.GetBytes($__out);"
        "$__s=[Console]::OpenStandardOutput();"
        "$__s.Write($__b,0,$__b.Length);$__s.Flush();"
        "exit $__code"
    )


def wrap_cmd(command: str) -> str:
    """Run a cmd.exe command through the PowerShell wrapper.

    Going via PowerShell keeps one encoding path for both kinds of command:
    `chcp 65001` makes cmd emit UTF-8 and the wrapper carries it back intact.
    The command is passed to cmd as a single argument so its own quoting
    survives untouched.
    """
    return (
        "$__c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"
        + base64.b64encode(command.encode("utf-8")).decode("ascii")
        + "'));"
        '& cmd.exe /c "chcp 65001>nul & $__c"'
    )


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name)
    if not raw:
        return default
    return raw.lower() in ("1", "true", "yes", "on")


class ConfigError(ToolError):
    """The host inventory is missing or an entry is unusable. Messages never contain secrets.

    A ToolError, so the MCP SDK shows the message to the model (it hides the
    text of any other exception)."""


# --------------------------------------------------------------------------
# Inventory
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class HostConfig:
    name: str
    host: str
    username: str
    password: str = field(default="", repr=False)
    key_file: str = ""
    protocol: str = "winrm"
    port: int = 0  # 0 = the protocol's default port
    use_ssl: bool = False
    readonly: bool = False
    description: str = ""

    @property
    def effective_port(self) -> int:
        if self.port:
            return self.port
        if self.protocol == "ssh":
            return 22
        if self.protocol == "agent":
            return AGENT_PORT
        return 5986 if self.use_ssl else 5985

    @classmethod
    def from_dict(cls, raw: object, index: int) -> "HostConfig":
        if not isinstance(raw, dict):
            raise ConfigError(f"host entry #{index} is not an object")
        host = str(raw.get("host", "")).strip()
        name = str(raw.get("name", "") or host).strip()
        if not host:
            raise ConfigError(f"host entry #{index} ({name or '?'}) has no 'host'")
        protocol = str(raw.get("protocol", "") or _env("WINDOWS_MCP_TRANSPORT", "winrm")).strip().lower()
        if protocol not in ("winrm", "ssh", "agent"):
            raise ConfigError(f"host '{name}': unknown protocol {protocol!r} (expected 'winrm', 'ssh' or 'agent')")
        username = str(raw.get("username", "") or "").strip()
        if not username and protocol != "agent":
            raise ConfigError(f"host '{name}' has no 'username'")
        password = str(raw.get("password", "") or "")
        key_file = os.path.expanduser(str(raw.get("key_file", "") or "").strip())
        if protocol == "winrm" and not password:
            raise ConfigError(f"host '{name}': a password is required for winrm")
        if protocol == "agent" and not password:
            raise ConfigError(f"host '{name}': the agent key is required (put it in the password field)")
        if protocol == "ssh" and not password and not key_file:
            raise ConfigError(f"host '{name}': set a password or key_file for ssh")
        try:
            port = int(raw.get("port", 0) or 0)
        except (TypeError, ValueError):
            raise ConfigError(f"host '{name}' has an invalid port") from None
        return cls(
            name=name, host=host, username=username, password=password, key_file=key_file,
            protocol=protocol, port=port, use_ssl=bool(raw.get("use_ssl", False)),
            readonly=bool(raw.get("readonly", False)), description=str(raw.get("description", "") or ""),
        )


def _legacy_hosts() -> list[dict] | None:
    """The original single-host configuration (WINDOWS_HOST etc.), as an inventory."""
    host = _env("WINDOWS_HOST")
    if not host:
        return None
    protocol = _env("WINDOWS_MCP_TRANSPORT", "winrm").lower()
    port = _env("WINDOWS_SSH_PORT") if protocol == "ssh" else _env("WINDOWS_WINRM_PORT")
    return [{
        "name": _env("WINDOWS_HOST_NAME") or host, "host": host, "username": _env("WINDOWS_USERNAME"),
        "password": _env("WINDOWS_PASSWORD"), "key_file": _env("WINDOWS_SSH_KEY"), "protocol": protocol,
        "port": port or 0, "use_ssl": _env_bool("WINDOWS_USE_SSL", False),
    }]


class Inventory:
    """Loads host definitions and hands out one cached transport per host."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hosts: dict[str, HostConfig] = {}
        self._source = ""
        self._mtime: float | None = None
        self._conns: dict[str, Transport] = {}

    def _load(self) -> None:
        inline = _env("WINDOWS_MCP_HOSTS")
        if inline:
            if self._source != "env":
                self._apply(self._parse(inline, "WINDOWS_MCP_HOSTS"), "env")
            return
        path = os.path.expanduser(_env("WINDOWS_MCP_HOSTS_FILE"))
        if path:
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                raise ConfigError(f"host file {path} does not exist") from None
            if self._source != path or self._mtime != mtime:
                with open(path, encoding="utf-8-sig") as fh:
                    self._apply(self._parse(fh.read(), path), path)
                self._mtime = mtime
            return
        legacy = _legacy_hosts()
        if legacy is None:
            raise ConfigError(
                "no hosts configured: set WINDOWS_MCP_HOSTS (MCP Vault does this), "
                "WINDOWS_MCP_HOSTS_FILE, or the single-host WINDOWS_HOST variables"
            )
        if self._source != "legacy":
            self._apply(legacy, "legacy")

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
        for key in list(self._conns):
            if key not in hosts or self._conns[key].cfg != hosts[key]:
                del self._conns[key]  # settings changed or host removed
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

    def connection(self, name: str = "") -> "Transport":
        """The transport for a host, connecting on first use."""
        cfg = self.resolve(name)
        key = cfg.name.lower()
        with self._lock:
            conn = self._conns.get(key)
        if conn is None:
            # Built outside the lock: an unreachable host can take ~30 s to fail
            # and must not hold up calls to the other hosts.
            conn = build_transport(cfg)
            with self._lock:
                conn = self._conns.setdefault(key, conn)
        return conn


@dataclass
class Result:
    """Outcome of one remote command."""

    stdout: str
    stderr: str
    exit_code: int

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    def render(self) -> str:
        parts = []
        if self.stdout.strip():
            parts.append(_truncate(self.stdout.rstrip()))
        if self.stderr.strip():
            parts.append("--- stderr ---\n" + _truncate(self.stderr.rstrip()))
        if not parts:
            parts.append("(no output)")
        parts.append(f"--- exit code: {self.exit_code} ---")
        return "\n".join(parts)


def _truncate(text: str) -> str:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    dropped = len(text) - MAX_OUTPUT_CHARS
    return text[:MAX_OUTPUT_CHARS] + f"\n... [truncated {dropped} more characters]"


def _decode(raw) -> str:
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return raw or ""


def ps_quote(value: str) -> str:
    """Quote a value for a PowerShell single-quoted string literal."""
    return "'" + str(value).replace("'", "''") + "'"


class Transport:
    """Common interface both transports implement."""

    name = "base"
    cfg: HostConfig

    def describe(self) -> str:
        raise NotImplementedError

    def run_ps(self, script: str, timeout_sec: int) -> Result:
        raise NotImplementedError

    def run_cmd(self, command: str, timeout_sec: int) -> Result:
        raise NotImplementedError

    def upload(self, local_path: str, remote_path: str) -> str:
        raise NotImplementedError

    def download(self, remote_path: str, local_path: str) -> str:
        raise NotImplementedError


class WinRMTransport(Transport):
    name = "winrm"

    def __init__(self, cfg: HostConfig):
        import winrm  # imported lazily so an SSH-only install still starts

        self.cfg = cfg
        self.host = cfg.host
        self.port = cfg.effective_port
        self.use_ssl = cfg.use_ssl
        # Auth scheme, certificate check and timeouts stay server-wide settings.
        self.auth = _env("WINDOWS_WINRM_AUTH", "ntlm").lower()
        verify = _env_bool("WINDOWS_SSL_VERIFY", False)

        scheme = "https" if self.use_ssl else "http"
        endpoint = f"{scheme}://{self.host}:{self.port}/wsman"

        self._session = winrm.Session(
            endpoint,
            auth=(cfg.username, cfg.password),
            transport=self.auth,
            server_cert_validation="validate" if verify else "ignore",
            read_timeout_sec=int(_env("WINDOWS_READ_TIMEOUT", "180")),
            operation_timeout_sec=int(_env("WINDOWS_OPERATION_TIMEOUT", "170")),
        )

    def describe(self) -> str:
        scheme = "https" if self.use_ssl else "http"
        return f"winrm {scheme}://{self.host}:{self.port} (auth={self.auth})"

    def run_ps(self, script: str, timeout_sec: int) -> Result:
        # pywinrm fixes its timeouts at session construction, so timeout_sec is
        # bounded by WINDOWS_READ_TIMEOUT rather than applied per call.
        r = self._session.run_ps(wrap_ps(script))
        return Result(_decode(r.std_out), _decode(r.std_err), r.status_code)

    def run_cmd(self, command: str, timeout_sec: int) -> Result:
        return self.run_ps(wrap_cmd(command), timeout_sec)

    def upload(self, local_path: str, remote_path: str) -> str:
        with open(local_path, "rb") as fh:
            data = fh.read()
        encoded = base64.b64encode(data).decode("ascii")
        target = ps_quote(remote_path)
        staging = ps_quote(remote_path + ".b64")

        init = self.run_ps(
            f"$p={target};"
            "$d=Split-Path -Parent $p;"
            "if($d -and -not (Test-Path $d)){New-Item -ItemType Directory -Force -Path $d|Out-Null};"
            f"if(Test-Path {staging}){{Remove-Item -Force {staging}}}",
            60,
        )
        if not init.ok:
            raise RuntimeError(f"could not prepare remote path: {init.stderr or init.stdout}")

        # WS-Man caps the size of each request, so the payload goes up in chunks
        # appended to a staging .b64 file and is decoded once on the far side.
        chunk = 6000
        for i in range(0, len(encoded), chunk):
            piece = encoded[i : i + chunk]
            res = self.run_ps(
                f"Add-Content -Path {staging} -Value '{piece}' -NoNewline -Encoding ascii", 120
            )
            if not res.ok:
                raise RuntimeError(f"chunk upload failed at offset {i}: {res.stderr}")

        finish = self.run_ps(
            f"$b=[Convert]::FromBase64String((Get-Content -Raw {staging}));"
            f"[IO.File]::WriteAllBytes({target},$b);"
            f"Remove-Item -Force {staging};"
            f"(Get-Item {target}).Length",
            180,
        )
        if not finish.ok:
            raise RuntimeError(f"remote decode failed: {finish.stderr or finish.stdout}")
        return f"Uploaded {len(data)} bytes to {remote_path} (remote size: {finish.stdout.strip()})"

    def download(self, remote_path: str, local_path: str) -> str:
        res = self.run_ps(
            f"[Convert]::ToBase64String([IO.File]::ReadAllBytes({ps_quote(remote_path)}))", 180
        )
        if not res.ok:
            raise RuntimeError(f"remote read failed: {res.stderr or res.stdout}")
        data = base64.b64decode("".join(res.stdout.split()))
        os.makedirs(os.path.dirname(os.path.abspath(local_path)) or ".", exist_ok=True)
        with open(local_path, "wb") as fh:
            fh.write(data)
        return f"Downloaded {len(data)} bytes from {remote_path} to {local_path}"


class SSHTransport(Transport):
    name = "ssh"

    # Seconds between SSH keepalives. Without them an idle session can be dropped
    # silently by a NAT or firewall, and the next command fails on a dead socket.
    KEEPALIVE_SEC = 30

    def __init__(self, cfg: HostConfig):
        import paramiko

        self._paramiko = paramiko
        self.cfg = cfg
        self.host = cfg.host
        self.port = cfg.effective_port
        self.username = cfg.username
        self._password = cfg.password
        self._key_path = cfg.key_file
        self._client = None
        self._connect()

    def _connect(self) -> None:
        """(Re)open the SSH session, discarding any previous one."""
        if self._client is not None:
            try:
                self._client.close()
            except Exception:  # noqa: BLE001 - the old session is already broken
                pass

        client = self._paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(self._paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            password=self._password or None,
            key_filename=self._key_path or None,
            look_for_keys=bool(self._key_path) or not self._password,
            allow_agent=True,
            timeout=30,
        )
        client.get_transport().set_keepalive(self.KEEPALIVE_SEC)
        self._client = client

    def _live(self):
        """The client, reconnected first if the session has died.

        The session used to be opened once and kept for the life of the server,
        so after the host rebooted - or the network dropped - every call failed
        until the MCP server itself was restarted.
        """
        transport = self._client.get_transport() if self._client else None
        if transport is None or not transport.is_active():
            self._connect()
        return self._client

    def _with_retry(self, open_fn):
        """Open a channel or SFTP session, reconnecting once if the session is dead.

        Only the *opening* is retried: nothing has run on the host yet, so doing it
        again cannot run a command twice. A failure after the command started is
        surfaced as-is.
        """
        try:
            return open_fn(self._live())
        except (self._paramiko.SSHException, EOFError, OSError):
            self._connect()
            return open_fn(self._client)

    def describe(self) -> str:
        return f"ssh {self.username}@{self.host}:{self.port}"

    def _exec(self, command: str, timeout_sec: int) -> Result:
        _, stdout, stderr = self._with_retry(lambda client: client.exec_command(command, timeout=timeout_sec))
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        return Result(out, err, stdout.channel.recv_exit_status())

    def run_ps(self, script: str, timeout_sec: int) -> Result:
        encoded = base64.b64encode(wrap_ps(script).encode("utf-16-le")).decode("ascii")
        return self._exec(
            f"powershell -NoProfile -NonInteractive -EncodedCommand {encoded}", timeout_sec
        )

    def run_cmd(self, command: str, timeout_sec: int) -> Result:
        # Routed through PowerShell so the encoding path matches run_ps and the
        # caller does not depend on which shell OpenSSH was configured with.
        return self.run_ps(wrap_cmd(command), timeout_sec)

    def upload(self, local_path: str, remote_path: str) -> str:
        size = os.path.getsize(local_path)
        sftp = self._with_retry(lambda client: client.open_sftp())
        try:
            sftp.put(local_path, remote_path)
        finally:
            sftp.close()
        return f"Uploaded {size} bytes to {remote_path}"

    def download(self, remote_path: str, local_path: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(local_path)) or ".", exist_ok=True)
        sftp = self._with_retry(lambda client: client.open_sftp())
        try:
            sftp.get(remote_path, local_path)
        finally:
            sftp.close()
        return f"Downloaded {remote_path} to {local_path} ({os.path.getsize(local_path)} bytes)"


AGENT_PORT = 5990


class AgentTransport(Transport):
    """HTTP to agent/winmcp-agent.ps1 on the target.

    Each request body is AES-256-CBC encrypted and HMAC-SHA256 signed with keys
    derived from the shared agent key, and carries a timestamp and a fresh nonce
    that the agent checks against replays. The reply is signed over that same
    nonce, so it cannot be swapped for another. The key never crosses the wire.
    """

    name = "agent"

    def __init__(self, cfg: HostConfig):
        import requests  # already a dependency of pywinrm

        self.cfg = cfg
        self.url = f"http://{cfg.host}:{cfg.effective_port}/rpc"
        secret = cfg.password.strip().encode("utf-8")
        self._enc_key = hmac.new(secret, b"winmcp-agent enc v1", hashlib.sha256).digest()
        self._mac_key = hmac.new(secret, b"winmcp-agent mac v1", hashlib.sha256).digest()
        self._requests = requests
        self._http = requests.Session()
        # Seconds to add to our clock so timestamps match the target's (learned on first skew refusal).
        self._clock_offset = 0

    def describe(self) -> str:
        skew = f", target clock {self._clock_offset:+d} s" if self._clock_offset else ""
        return f"agent {self.url} (encrypted{skew})"

    def _mac(self, text: str) -> bytes:
        return hmac.new(self._mac_key, text.encode("utf-8"), hashlib.sha256).digest()

    @staticmethod
    def _agent_time(resp) -> int | None:
        """The agent's clock from a clock-skew refusal, or None for any other response."""
        try:
            value = resp.json().get("agent_time")
        except (ValueError, AttributeError):
            return None
        return int(value) if isinstance(value, (int, float)) else None

    def _call(self, request: dict, timeout_sec: int) -> dict:
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        padder = padding.PKCS7(128).padder()
        plain = padder.update(json.dumps(request).encode("utf-8")) + padder.finalize()
        iv_raw = os.urandom(16)
        enc = Cipher(algorithms.AES(self._enc_key), modes.CBC(iv_raw)).encryptor()
        ct = base64.b64encode(enc.update(plain) + enc.finalize()).decode("ascii")
        iv = base64.b64encode(iv_raw).decode("ascii")

        wait = timeout_sec + 30  # the agent enforces timeout_sec itself; this is the backstop
        for attempt in (1, 2):
            ts = int(time.time()) + self._clock_offset
            nonce = secrets.token_hex(16)
            mac = base64.b64encode(self._mac(f"req|{ts}|{nonce}|{iv}|{ct}")).decode("ascii")
            body = {"v": 1, "ts": ts, "nonce": nonce, "iv": iv, "ct": ct, "mac": mac}
            try:
                resp = self._http.post(self.url, json=body, timeout=(15, wait))
            except self._requests.ConnectionError as exc:
                raise RuntimeError(
                    f"cannot reach the agent at {self.url} - is it running and is the port open? ({type(exc).__name__})"
                ) from None
            except self._requests.Timeout:
                raise RuntimeError(f"the agent at {self.url} did not answer within {wait} s") from None
            agent_time = self._agent_time(resp) if resp.status_code == 401 else None
            if attempt == 1 and agent_time is not None:
                # The target's clock is off (old servers drift). Sign with its time instead;
                # it only reports its time after our signature checked out, and the nonce
                # still stops replays, so this weakens nothing.
                self._clock_offset = agent_time - int(time.time())
                continue
            break
        if resp.status_code != 200:
            try:
                detail = resp.json().get("error", "")
            except ValueError:
                detail = resp.text[:200]
            raise RuntimeError(f"agent refused the request (HTTP {resp.status_code}): {detail}")

        data = resp.json()
        expected = self._mac(f"resp|{nonce}|{data.get('iv', '')}|{data.get('ct', '')}")
        try:
            given = base64.b64decode(data.get("mac", ""))
        except ValueError:
            given = b""
        if not hmac.compare_digest(expected, given):
            raise RuntimeError("the agent's reply failed signature verification")
        dec = Cipher(algorithms.AES(self._enc_key), modes.CBC(base64.b64decode(data["iv"]))).decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        raw = dec.update(base64.b64decode(data["ct"])) + dec.finalize()
        reply = json.loads(unpadder.update(raw) + unpadder.finalize())
        if "error" in reply:
            raise RuntimeError(f"agent error: {reply['error']}")
        return reply

    def run_ps(self, script: str, timeout_sec: int) -> Result:
        r = self._call({"op": "ps", "script": wrap_ps(script), "timeout": int(timeout_sec)}, int(timeout_sec))
        return Result(r.get("stdout") or "", r.get("stderr") or "", int(r.get("exit_code", 1)))

    def run_cmd(self, command: str, timeout_sec: int) -> Result:
        return self.run_ps(wrap_cmd(command), timeout_sec)

    def upload(self, local_path: str, remote_path: str) -> str:
        with open(local_path, "rb") as fh:
            data = fh.read()
        r = self._call({"op": "upload", "path": remote_path, "data": base64.b64encode(data).decode("ascii")}, 300)
        return f"Uploaded {len(data)} bytes to {remote_path} (remote size: {r.get('size')})"

    def download(self, remote_path: str, local_path: str) -> str:
        r = self._call({"op": "download", "path": remote_path}, 300)
        data = base64.b64decode(r["data"])
        os.makedirs(os.path.dirname(os.path.abspath(local_path)) or ".", exist_ok=True)
        with open(local_path, "wb") as fh:
            fh.write(data)
        return f"Downloaded {len(data)} bytes from {remote_path} to {local_path}"


def build_transport(cfg: HostConfig) -> Transport:
    """Construct (and, for SSH, connect) the transport for one host."""
    if cfg.protocol == "ssh":
        return SSHTransport(cfg)
    if cfg.protocol == "agent":
        return AgentTransport(cfg)
    return WinRMTransport(cfg)
