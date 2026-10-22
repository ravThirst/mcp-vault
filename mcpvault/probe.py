"""Connection tests for hosts and an MCP handshake test for servers."""

import json
import os
import queue
import socket
import subprocess
import threading
import time

from . import adapters

PROTOCOL_VERSION = "2025-06-18"


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


def test_host(h: dict) -> dict:
    result = {"time": time.strftime("%H:%M:%S"), "tcp": _tcp(h["address"], h["port"])}
    if not result["tcp"]["ok"]:
        result["ok"] = False
        result["summary"] = f"Port {h['port']} unreachable: {result['tcp']['error']}"
        return result
    if h["protocol"] == "ssh" and h["username"]:
        result["auth"] = _ssh(h)
        result["ok"] = result["auth"]["ok"]
        result["summary"] = (f"SSH login OK ({result['auth']['ms']} ms)" if result["ok"]
                             else f"SSH: {result['auth']['error']}")
    else:
        result["ok"] = True
        result["summary"] = f"Port {h['port']} reachable ({result['tcp']['ms']} ms); WinRM login is checked by the server test"
    return result


def test_server(spec: dict, secrets: list[str], timeout: float = 45.0) -> dict:
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
