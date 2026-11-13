"""Connection tests for hosts and an MCP handshake test for servers."""

import json
import os
import queue
import socket
import subprocess
import threading
import time

from . import adapters, paths

PROTOCOL_VERSION = "2025-06-18"
_MULTI_HOST_TEMPLATES = {"windows-mcp", "ubuntu-mcp", "mikrotik-mcp", "inventory"}


def _tcp(address: str, port: int, timeout: float = 5.0) -> dict:
    start = time.monotonic()
    try:
        with socket.create_connection((address, port), timeout=timeout):
            pass
        return {"ok": True, "ms": round((time.monotonic() - start) * 1000)}
    except OSError as exc:
        return {"ok": False, "error": exc.strerror or str(exc)}


def _ssh(h: dict) -> dict:
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    start = time.monotonic()
    try:
        client.connect(
            hostname=h["address"], port=h["port"], username=h["username"],
            password=h["password"] if h["auth"] == "password" else None,
            key_filename=os.path.expanduser(h["key_path"]) if h["auth"] == "key" else None,
            look_for_keys=False, allow_agent=False, timeout=10, banner_timeout=15, auth_timeout=15,
        )
        return {"ok": True, "ms": round((time.monotonic() - start) * 1000)}
    except paramiko.AuthenticationException:
        return {"ok": False, "error": "authentication failed (wrong username, password or key)"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": adapters.redact(str(exc) or type(exc).__name__, [h.get("password", "")])}
    finally:
        client.close()


def _winmcp_agent(h: dict) -> dict:
    import base64
    import hashlib
    import hmac
    import secrets
    import urllib.error
    import urllib.request
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    secret = h.get("password", "").strip().encode("utf-8")
    enc_key = hmac.new(secret, b"winmcp-agent enc v1", hashlib.sha256).digest()
    mac_key = hmac.new(secret, b"winmcp-agent mac v1", hashlib.sha256).digest()
    url = f"http://{h['address']}:{h['port']}/rpc"

    padder = padding.PKCS7(128).padder()
    plain = padder.update(json.dumps({"op": "ping"}).encode("utf-8")) + padder.finalize()
    iv_raw = os.urandom(16)
    enc = Cipher(algorithms.AES(enc_key), modes.CBC(iv_raw)).encryptor()
    ct = base64.b64encode(enc.update(plain) + enc.finalize()).decode("ascii")
    iv = base64.b64encode(iv_raw).decode("ascii")

    start = time.monotonic()
    offset = 0
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for attempt in (1, 2):
        ts = int(time.time()) + offset
        nonce = secrets.token_hex(16)
        mac = base64.b64encode(hmac.new(mac_key, f"req|{ts}|{nonce}|{iv}|{ct}".encode("utf-8"), hashlib.sha256).digest()).decode("ascii")
        req_body = json.dumps({"v": 1, "ts": ts, "nonce": nonce, "iv": iv, "ct": ct, "mac": mac}).encode("utf-8")
        req = urllib.request.Request(url, data=req_body, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with opener.open(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            break
        except urllib.error.HTTPError as exc:
            raw_err = exc.read().decode("utf-8", errors="replace")
            try:
                err_json = json.loads(raw_err)
            except ValueError:
                err_json = {}
            if attempt == 1 and exc.code == 401 and isinstance(err_json.get("agent_time"), (int, float)):
                offset = int(err_json["agent_time"]) - int(time.time())
                continue
            return {"ok": False, "error": err_json.get("error") or f"HTTP {exc.code}"}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": adapters.redact(str(exc) or type(exc).__name__, [h.get("password", "")])}

    expected = hmac.new(mac_key, f"resp|{nonce}|{data.get('iv', '')}|{data.get('ct', '')}".encode("utf-8"), hashlib.sha256).digest()
    try:
        given = base64.b64decode(data.get("mac", ""))
        if not hmac.compare_digest(expected, given):
            return {"ok": False, "error": "reply failed signature verification"}
        dec = Cipher(algorithms.AES(enc_key), modes.CBC(base64.b64decode(data["iv"]))).decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        reply = json.loads(unpadder.update(dec.update(base64.b64decode(data["ct"])) + dec.finalize()) + unpadder.finalize())
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"invalid encrypted reply ({type(exc).__name__})"}
    if "error" in reply:
        return {"ok": False, "error": str(reply["error"])}
    return {"ok": True, "ms": round((time.monotonic() - start) * 1000),
            "computer": reply.get("computer", ""), "agent": reply.get("agent", "")}


def test_host(h: dict) -> dict:
    result = {"time": time.strftime("%H:%M:%S"), "tcp": _tcp(h["address"], h["port"])}
    if not result["tcp"]["ok"]:
        result["ok"] = False
        result["summary"] = f"Port {h['port']} unreachable: {result['tcp']['error']}"
        return result
    if h["protocol"] == "ssh":
        if not h.get("username"):
            result["ok"] = False
            result["summary"] = f"Port {h['port']} reachable ({result['tcp']['ms']} ms), but no username is set"
            return result
        result["auth"] = _ssh(h)
        result["ok"] = result["auth"]["ok"]
        result["summary"] = (f"SSH login OK ({result['auth']['ms']} ms)" if result["ok"]
                             else f"SSH: {result['auth']['error']}")
    elif h["protocol"] == "agent" and h.get("password"):
        result["auth"] = _winmcp_agent(h)
        result["ok"] = result["auth"]["ok"]
        if result["ok"]:
            who = " ".join(x for x in (result["auth"].get("computer"), f"v{result['auth']['agent']}" if result["auth"].get("agent") else "") if x)
            result["summary"] = f"WinMCP agent OK{': ' + who if who else ''} ({result['auth']['ms']} ms)"
        else:
            result["summary"] = f"WinMCP agent: {result['auth']['error']}"
    elif h["protocol"] == "agent":
        result["ok"] = False
        result["summary"] = f"Port {h['port']} reachable ({result['tcp']['ms']} ms), but no agent key is set yet"
    elif not h.get("username") or not h.get("password"):
        missing = "username" if not h.get("username") else "password"
        result["ok"] = False
        result["summary"] = f"Port {h['port']} reachable ({result['tcp']['ms']} ms), but no {missing} is set yet"
    else:
        result["ok"] = True
        result["summary"] = f"Port {h['port']} reachable ({result['tcp']['ms']} ms); call win_test_connection to verify WinRM credentials"
    return result


def _server_warnings(init: dict, tools: list, server: dict | None, hosts: list[dict] | None) -> list[str]:
    if not server:
        return []
    warnings: list[str] = []
    template = server.get("template", "")
    active_hosts = [h for h in (hosts or []) if isinstance(h, dict) and h.get("enabled", True)]
    tool_names = {t.get("name", "") for t in tools if isinstance(t, dict)}
    instructions_text = str(init.get("instructions") or "").lower()
    tool_descs = " ".join(str(t.get("description") or "") for t in tools if isinstance(t, dict)).lower()
    combined_text = f"{instructions_text} {tool_descs}"

    if template == "windows-mcp":
        bundled = os.path.join(paths.APP_DIR, "servers", "windows-mcp", "src", "server.py")
        agent_hosts = [h.get("name") or h.get("address", "host") for h in active_hosts if h.get("protocol") == "agent"]
        if agent_hosts and ("win_list_hosts" not in tool_names or "agent" not in combined_text):
            warnings.append(
                f"Host {', '.join(repr(n) for n in agent_hosts)} uses protocol 'agent', but this server "
                f"({len(tools)} tools) does not support WinMCP agent transport — point it at bundled {bundled}"
            )
        ssh_hosts = [h.get("name") or h.get("address", "host") for h in active_hosts if h.get("protocol") == "ssh"]
        if ssh_hosts and "win_list_hosts" not in tool_names and "winrm" in combined_text and "ssh" not in combined_text:
            warnings.append(
                f"Host {', '.join(repr(n) for n in ssh_hosts)} uses protocol 'ssh', but this server "
                f"({len(tools)} tools) appears to be WinRM-only — point it at bundled {bundled}"
            )

    if template in _MULTI_HOST_TEMPLATES and len(active_hosts) > 1 and tools:
        has_host_arg = any(
            isinstance(t, dict)
            and any(k in ((t.get("inputSchema") or t.get("input_schema") or {}).get("properties") or {})
                    for k in ("host", "device"))
            for t in tools
        )
        if not has_host_arg:
            warnings.append(
                f"{len(active_hosts)} hosts are attached, but none of this server's {len(tools)} tools "
                "accept a 'host' or 'device' argument (multi-host inventory is ignored)"
            )
    return warnings


def test_server(
    spec: dict,
    secrets: list[str],
    timeout: float = 45.0,
    server: dict | None = None,
    hosts: list[dict] | None = None,
) -> dict:
    """Start the server, run initialize + tools/list over stdio, then stop it."""
    env = dict(os.environ)
    env.update(spec["env"])
    start = time.monotonic()
    result = {"time": time.strftime("%H:%M:%S"), "ok": False}
    problem = adapters.missing_command(spec["command"])
    if problem:
        result["summary"] = f"Cannot start: {problem}"
        return result
    try:
        proc = subprocess.Popen(
            [spec["command"], *spec["args"]], cwd=spec["cwd"] or None, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=0x08000000,
        )
    except OSError as exc:
        result["summary"] = f"Cannot start: {exc}"
        return result

    lines: queue.Queue = queue.Queue()
    stderr_chunks: list[bytes] = []
    noise: list[str] = []

    def read_out():
        for raw in proc.stdout:
            lines.put(raw)
        lines.put(None)

    def read_err():
        for raw in proc.stderr:
            stderr_chunks.append(raw)
            if len(stderr_chunks) > 400:
                del stderr_chunks[:100]

    threading.Thread(target=read_out, daemon=True).start()
    threading.Thread(target=read_err, daemon=True).start()

    def send(msg: dict) -> None:
        proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
        proc.stdin.flush()

    def wait_for(msg_id: int) -> dict:
        deadline = start + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"no response within {int(timeout)} s")
            try:
                raw = lines.get(timeout=remaining)
            except queue.Empty:
                continue
            if raw is None:
                raise EOFError(f"server exited (code {proc.poll()})")
            text = raw.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            try:
                msg = json.loads(text)
            except json.JSONDecodeError:
                noise.append(text[:200])
                continue
            if msg.get("id") == msg_id:
                if "error" in msg:
                    raise RuntimeError(msg["error"].get("message", "error"))
                return msg["result"]

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": "mcp-vault", "version": "0.1"}}})
        init = wait_for(1)
        result["startup_ms"] = round((time.monotonic() - start) * 1000)
        result["server_info"] = init.get("serverInfo", {})
        result["protocol"] = init.get("protocolVersion")
        result["has_instructions"] = bool(init.get("instructions"))
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools, cursor, n = [], None, 2
        while True:
            send({"jsonrpc": "2.0", "id": n, "method": "tools/list", "params": {"cursor": cursor} if cursor else {}})
            page = wait_for(n)
            tools += page.get("tools", [])
            cursor = page.get("nextCursor")
            n += 1
            if not cursor or n > 20:
                break
        result["tools"] = [t.get("name") for t in tools]
        result["annotated"] = sum(1 for t in tools if t.get("annotations"))
        result["handshake"] = {"initialize": init, "tools": tools}  # the agent saves it, then drops it
        result["ok"] = True
        info = result["server_info"]
        ident = " ".join(str(x) for x in (info.get("name"), info.get("version")) if x)
        result["summary"] = f"{len(tools)} tools, started in {result['startup_ms']} ms" + (f" ({ident})" if ident else "")
        warnings = [adapters.redact(w, secrets) for w in _server_warnings(init, tools, server, hosts)]
        if warnings:
            result["warnings"] = warnings
            result["summary"] += f" — WARNING: {'; '.join(warnings)}"
    except Exception as exc:  # noqa: BLE001
        result["summary"] = adapters.redact(f"Handshake failed: {exc}", secrets)
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    if noise:
        result["stdout_noise"] = [adapters.redact(x, secrets) for x in noise[:5]]
    tail = b"".join(stderr_chunks).decode("utf-8", errors="replace")[-4000:]
    result["stderr"] = adapters.redact(tail, secrets)
    return result
