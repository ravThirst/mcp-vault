"""MCP client config files (Claude Code, Claude Desktop, Kimi Work, Codex, Antigravity).

The vault writes one launcher entry per server into each selected client:

    "windows": {"type": "stdio", "command": "<venv python>", "args": ["<vault.py>", "run", "windows"], "env": {}}

An entry counts as vault-managed when its args point at this app's vault.py
with "run"; everything else in the file is left untouched.

Kimi Work loads MCP servers from plugins: the vault maintains a `mcp-vault`
plugin whose `kimi.plugin.json` manifest holds the launcher entries, and
registers that plugin in `plugins/installed.json` on apply.

Codex stores settings in TOML (`~/.codex/config.toml`) under `[mcp_servers.<id>]`;
apply updates only vault-managed and selected server tables, leaving every other
setting and comment intact.
"""

import datetime as _dt
import json
import os
import re

from . import paths
from .store import atomic_write

CLIENTS = {
    "claude-code": {
        "label": "Claude Code",
        "path": os.environ.get("MCPVAULT_CLAUDE_CODE_CONFIG") or os.path.join(os.path.expanduser("~"), ".claude.json"),
        "typed": True,
        "reload": "Start a new Claude Code session, or run /mcp to reconnect.",
    },
    "claude-desktop": {
        "label": "Claude Desktop",
        "path": os.environ.get("MCPVAULT_CLAUDE_DESKTOP_CONFIG")
        or os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "Claude", "claude_desktop_config.json"),
        "typed": False,
        "reload": "Quit Claude Desktop from the tray and start it again.",
    },
    "kimi": {
        "label": "Kimi Work",
        "path": paths.KIMI_MANIFEST,
        "typed": False,
        "reload": "Restart Kimi Work, or toggle the mcp-vault plugin off and on in its settings.",
    },
    "codex": {
        "label": "Codex",
        "path": paths.CODEX_CONFIG,
        "typed": False,
        "reload": "Restart Codex (only needed when adding or removing servers; host changes apply automatically).",
    },
    "antigravity": {
        "label": "Antigravity",
        "path": paths.ANTIGRAVITY_CONFIG,
        "typed": False,
        "reload": "Reload Antigravity (only needed when adding or removing servers; host changes apply automatically).",
    },
}


def _norm(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))


def launcher_entry(server_id: str, typed: bool, client_id: str = "") -> dict:
    if client_id == "codex":
        return {
            "command": paths.python_console(),
            "args": [paths.ENTRY, "run", server_id],
            "startup_timeout_sec": 60,
            "tool_timeout_sec": 240,
            "enabled": True,
        }
    entry = {"command": paths.python_console(), "args": [paths.ENTRY, "run", server_id], "env": {}}
    return {"type": "stdio", **entry} if typed else entry


def is_managed(entry: dict) -> bool:
    if not isinstance(entry, dict):
        return False
    args = [a for a in (entry.get("args") or []) if isinstance(a, str)]
    for i, arg in enumerate(args):
        norm = _norm(arg)
        if norm == _norm(paths.ENTRY) and "run" in args:
            return True
        if os.path.basename(norm) == "vault.py" and i + 2 < len(args) and args[i + 1] == "run" and bool(args[i + 2].strip()):
            return True
    return False


# -- Codex TOML helpers -------------------------------------------------------

_TABLE_RE = re.compile(r"^\s*(\[\[?)([^\[\]]+)(\]\]?)\s*(?:#.*)?$")
_KEYVAL_RE = re.compile(r"^\s*([A-Za-z0-9_-]+|\"(?:\\.|[^\"])*\"|'[^']*')\s*=\s*(.+?)\s*$")


def _loads_toml(raw: str) -> dict:
    try:
        import tomllib

        return tomllib.loads(raw)
    except ModuleNotFoundError:
        return _loads_toml_fallback(raw)


def _strip_toml_comment(line: str) -> str:
    quote: str | None = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote is None:
            if ch == "#":
                return line[:i]
            if ch in ('"', "'"):
                quote = ch
        else:
            if quote == '"' and ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        i += 1
    return line


def _split_toml_top(text: str, sep: str) -> list[str]:
    parts: list[str] = []
    cur: list[str] = []
    quote: str | None = None
    depth = 0
    i = 0
    while i < len(text):
        ch = text[i]
        if quote is None:
            if ch in ('"', "'"):
                quote = ch
            elif ch in "{[":
                depth += 1
            elif ch in "}]" and depth > 0:
                depth -= 1
            elif ch == sep and depth == 0:
                parts.append("".join(cur))
                cur = []
                i += 1
                continue
        else:
            if quote == '"' and ch == "\\":
                cur.append(text[i:i + 2])
                i += 2
                continue
            if ch == quote:
                quote = None
        cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return parts


def _unquote_toml_key(raw_key: str) -> str:
    k = raw_key.strip()
    if k.startswith('"') and k.endswith('"') and len(k) >= 2:
        return json.loads(k)
    if k.startswith("'") and k.endswith("'") and len(k) >= 2:
        return k[1:-1]
    return k


def _parse_toml_inline_table(body: str) -> dict:
    out: dict = {}
    for item in _split_toml_top(body, ","):
        piece = item.strip()
        if not piece:
            continue
        kv = _split_toml_top(piece, "=")
        if len(kv) < 2:
            continue
        raw_key = kv[0].strip()
        raw_val = "=".join(kv[1:]).strip()
        keys = [_unquote_toml_key(part) for part in _split_toml_top(raw_key, ".")]
        target = out
        for sub in keys[:-1]:
            nxt = target.get(sub)
            if not isinstance(nxt, dict):
                nxt = {}
                target[sub] = nxt
            target = nxt
        target[keys[-1]] = _parse_toml_scalar(raw_val)
    return out


def _loads_toml_fallback(raw: str) -> dict:
    """Minimal fallback for Python 3.10 (reads [mcp_servers.<id>] sections)."""
    servers: dict[str, dict] = {}
    cur: tuple[str, str | None] | None = None
    for raw_line in raw.splitlines():
        line = _strip_toml_comment(raw_line).strip()
        if not line:
            continue
        m = _TABLE_RE.match(line)
        if m and m.group(1) == "[":
            cur = _mcp_server_header(m.group(2).strip())
            if cur and cur[1] is None:
                servers.setdefault(cur[0], {})
            continue
        if not cur:
            continue
        km = _KEYVAL_RE.match(line)
        if not km:
            continue
        k = _unquote_toml_key(km.group(1))
        v = km.group(2).strip()
        val = _parse_toml_scalar(v)
        srv = servers.setdefault(cur[0], {})
        if cur[1] == "env":
            srv.setdefault("env", {})[k] = val
        elif cur[1] is None:
            srv[k] = val
    return {"mcp_servers": servers}


def _parse_toml_scalar(v: str):
    v = v.strip()
    if v in ("true", "false"):
        return v == "true"
    if v.startswith("{") and v.endswith("}"):
        return _parse_toml_inline_table(v[1:-1])
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        if not inner:
            return []
        return [_parse_toml_scalar(p) for p in _split_toml_top(inner, ",") if p.strip()]
    if v.startswith("'") and v.endswith("'") and len(v) >= 2:
        return v[1:-1]
    try:
        return json.loads(v)
    except ValueError:
        if v.startswith('"') and v.endswith('"') and len(v) >= 2:
            return v[1:-1]
        return v


def _mcp_server_header(header: str) -> tuple[str, str | None] | None:
    """If `header` is `mcp_servers.<name>[.<sub>]`, return `(name, sub)`."""
    if not header.startswith("mcp_servers."):
        return None
    rest = header[len("mcp_servers."):].strip()
    if not rest:
        return None
    if rest[0] in ('"', "'"):
        q = rest[0]
        end = rest.find(q, 1)
        while end > 0 and q == '"' and rest[end - 1] == "\\":
            end = rest.find(q, end + 1)
        if end < 0:
            return None
        name = json.loads(rest[:end + 1]) if q == '"' else rest[1:end]
        tail = rest[end + 1:].strip()
        sub = tail[1:].strip() if tail.startswith(".") else None
        return name, sub
    name, _, sub = rest.partition(".")
    return name.strip(), (sub.strip() or None)


def _update_multiline_quote(line: str, quote: str | None) -> str | None:
    i = 0
    while i < len(line):
        if quote is None:
            if line[i] == "#":
                break
            if line.startswith('"""', i) or line.startswith("'''", i):
                quote = line[i:i + 3]
                i += 3
                continue
            if line[i] in ('"', "'"):
                q = line[i]
                i += 1
                while i < len(line):
                    if q == '"' and line[i] == "\\":
                        i += 2
                        continue
                    if line[i] == q:
                        i += 1
                        break
                    i += 1
                continue
        else:
            if quote == '"""' and line[i] == "\\":
                i += 2
                continue
            if line.startswith(quote, i):
                quote = None
                i += 3
                continue
        i += 1
    return quote


def _write_codex(raw: str | None, current: dict, desired: dict) -> str:
    touched = {n for n, e in current.items() if isinstance(e, dict) and is_managed(e)} | set(desired)
    kept: list[str] = []
    skip = False
    quote: str | None = None
    for line in (raw or "").splitlines(keepends=True):
        if quote is None:
            m = _TABLE_RE.match(line)
            if m:
                parsed = _mcp_server_header(m.group(2).strip()) if m.group(1) == "[" else None
                skip = bool(parsed and parsed[0] in touched)
        quote = _update_multiline_quote(line, quote)
        if not skip:
            kept.append(line)

    blocks = []
    for name, entry in desired.items():
        key = name if re.match(r"^[A-Za-z0-9_-]+$", name) else json.dumps(name, ensure_ascii=False)
        args_toml = ", ".join(json.dumps(a, ensure_ascii=False) for a in entry["args"])
        blocks.append(
            f"[mcp_servers.{key}]\n"
            f"command = {json.dumps(entry['command'], ensure_ascii=False)}\n"
            f"args = [{args_toml}]\n"
            f"startup_timeout_sec = {entry['startup_timeout_sec']}\n"
            f"tool_timeout_sec = {entry['tool_timeout_sec']}\n"
            f"enabled = {'true' if entry['enabled'] else 'false'}"
        )
    parts = [p for p in ["".join(kept).rstrip(), *blocks] if p]
    out = ("\n\n".join(parts) + "\n") if parts else ""
    _loads_toml(out)  # verify valid TOML before touching disk
    return out


# -- Kimi Work plugin ---------------------------------------------------------

def kimi_available() -> bool:
    """True when a Kimi Work installation (plugins or daimon folder) is present on this machine."""
    return (
        os.path.isdir(os.path.join(paths.KIMI_HOME, "plugins"))
        or os.path.isdir(os.path.dirname(paths.KIMI_SKILLS_DIR))
        or os.path.isdir(paths.KIMI_SKILLS_DIR)
    )


def installed_clients() -> list[str]:
    """Client IDs whose application folder or config file exists on this machine."""
    home = os.path.expanduser("~")
    found: list[str] = []
    if os.path.isdir(os.path.join(home, ".claude")) or os.path.isfile(CLIENTS["claude-code"]["path"]):
        found.append("claude-code")
    desktop_cfg = CLIENTS["claude-desktop"]["path"]
    if os.path.isdir(os.path.dirname(desktop_cfg)) or os.path.isfile(desktop_cfg):
        found.append("claude-desktop")
    if kimi_available():
        found.append("kimi")
    if os.path.isdir(paths.CODEX_HOME) or os.path.isfile(paths.CODEX_CONFIG):
        found.append("codex")
    if (
        os.path.isdir(paths.ANTIGRAVITY_HOME)
        or os.path.isdir(os.path.join(home, ".gemini", "antigravity"))
        or os.path.isfile(paths.ANTIGRAVITY_CONFIG)
    ):
        found.append("antigravity")
    return found


def _kimi_scaffold() -> dict:
    from . import __version__

    return {
        "$schema": "https://kimi.com/schemas/kimi.plugin.schema.json",
        "name": paths.KIMI_PLUGIN_ID,
        "version": __version__,
        "description": "MCP servers launched through MCP Vault; hosts and credentials stay in the encrypted vault.",
        "author": "MCP Vault",
        "license": "MIT",
        "interface": {"displayName": "MCP Vault", "hostKind": "local", "platforms": ["windows"]},
        "mcpServers": {},
    }


def _kimi_register() -> None:
    """Add or refresh the mcp-vault entry in Kimi Work's plugins/installed.json."""
    os.makedirs(os.path.dirname(paths.KIMI_INSTALLED), exist_ok=True)
    data = {"version": 1, "plugins": []}
    if os.path.exists(paths.KIMI_INSTALLED):
        with open(paths.KIMI_INSTALLED, "r", encoding="utf-8-sig") as fh:
            raw = fh.read()
        if raw.strip():
            loaded = json.loads(raw)
            if isinstance(loaded, dict) and isinstance(loaded.get("plugins"), list):
                data = loaded
    now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    for entry in data["plugins"]:
        if isinstance(entry, dict) and entry.get("id") == paths.KIMI_PLUGIN_ID:
            entry["root"] = paths.KIMI_PLUGIN_DIR
            entry["updatedAt"] = now
            break
    else:
        data["plugins"].append({
            "id": paths.KIMI_PLUGIN_ID,
            "root": paths.KIMI_PLUGIN_DIR,
            "source": "local-path",
            "enabled": True,
            "installedAt": now,
            "updatedAt": now,
            "originalSource": paths.APP_DIR,
        })
    atomic_write(paths.KIMI_INSTALLED, (json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))


def read_config(client_id: str) -> tuple[dict, str | None]:
    """Return (parsed config, raw text or None if the file does not exist)."""
    path = CLIENTS[client_id]["path"]
    if not os.path.exists(path):
        return {}, None
    with open(path, "r", encoding="utf-8-sig") as fh:
        raw = fh.read()
    if not raw.strip():
        return {}, raw
    if client_id == "codex":
        obj = _loads_toml(raw)
        servers = {k: v for k, v in (obj.get("mcp_servers") or {}).items() if isinstance(v, dict)}
        return {"mcpServers": servers}, raw
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError(f"{path} does not contain a JSON object")
    return obj, raw


def _desired(servers: list[dict], client_id: str) -> dict:
    typed = CLIENTS[client_id]["typed"]
    return {s["id"]: launcher_entry(s["id"], typed, client_id)
            for s in servers if s.get("enabled", True) and client_id in s.get("clients", [])}


def plan(servers: list[dict]) -> list[dict]:
    result = []
    for cid, info in CLIENTS.items():
        item = {"client": cid, "label": info["label"], "path": info["path"], "reload": info["reload"],
                "exists": os.path.exists(info["path"]), "changes": [], "unmanaged": [], "error": None}
        if cid == "kimi" and not kimi_available():
            item["error"] = (f"Kimi Work plugins folder not found ({os.path.join(paths.KIMI_HOME, 'plugins')}). "
                             "Set MCPVAULT_KIMI_HOME to the kimi-code home if it lives elsewhere.")
            result.append(item)
            continue
        try:
            cfg, _ = read_config(cid)
        except (OSError, ValueError) as exc:
            item["error"] = f"Cannot read config: {exc}"
            result.append(item)
            continue
        current = cfg.get("mcpServers") or {}
        desired = _desired(servers, cid)
        for name, entry in desired.items():
            if name not in current:
                item["changes"].append({"name": name, "action": "add"})
            elif not is_managed(current[name]):
                item["changes"].append({"name": name, "action": "replace",
                                        "note": "inline settings removed, launched through the vault"})
            elif current[name] != entry:
                item["changes"].append({"name": name, "action": "update"})
            else:
                item["changes"].append({"name": name, "action": "keep"})
        for name, entry in current.items():
            if name in desired:
                continue
            if is_managed(entry):
                item["changes"].append({"name": name, "action": "remove"})
            else:
                item["unmanaged"].append(name)
        result.append(item)
    return result


def apply(vault, servers: list[dict], client_ids: list[str]) -> list[dict]:
    results = []
    for cid in client_ids:
        if cid not in CLIENTS:
            continue
        info = CLIENTS[cid]
        if cid == "kimi" and not kimi_available():
            results.append({"client": cid, "ok": False,
                            "error": f"Kimi Work plugins folder not found ({os.path.join(paths.KIMI_HOME, 'plugins')})"})
            continue
        try:
            cfg, raw = read_config(cid)
            if raw is not None:
                backup(vault, cid, raw)
            desired = _desired(servers, cid)
            if cid == "codex":
                out_text = _write_codex(raw, cfg.get("mcpServers") or {}, desired)
                atomic_write(info["path"], out_text.encode("utf-8"))
                results.append({"client": cid, "ok": True, "reload": info["reload"]})
                continue
            if cid == "kimi":
                base = _kimi_scaffold()
                base.update({k: v for k, v in cfg.items() if k != "mcpServers"})
                base["mcpServers"] = cfg.get("mcpServers") or {}
                cfg = base
                os.makedirs(paths.KIMI_PLUGIN_DIR, exist_ok=True)
            current = dict(cfg.get("mcpServers") or {})
            for name in [n for n, e in current.items() if is_managed(e) and n not in desired]:
                del current[name]
            current.update(desired)
            cfg["mcpServers"] = current
            atomic_write(info["path"], (json.dumps(cfg, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
            if cid == "kimi":
                _kimi_register()
            results.append({"client": cid, "ok": True, "reload": info["reload"]})
        except Exception as exc:  # noqa: BLE001 - reported to the UI
            results.append({"client": cid, "ok": False, "error": str(exc)})
    return results


# -- encrypted backups ------------------------------------------------------

_BACKUP_RE = re.compile(r"^(\d{8}-\d{6}-\d{6})_([a-z-]+)\.enc$")


def backup(vault, client_id: str, raw: str) -> str:
    paths.ensure_dirs()
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    name = f"{stamp}_{client_id}.enc"
    payload = json.dumps({"client": client_id, "path": CLIENTS[client_id]["path"], "content": raw}).encode("utf-8")
    atomic_write(os.path.join(paths.BACKUP_DIR, name), vault.seal_blob(payload, "backup"))
    _prune(client_id, keep=30)
    return name


def _prune(client_id: str, keep: int) -> None:
    mine = sorted(n for n in os.listdir(paths.BACKUP_DIR) if (m := _BACKUP_RE.match(n)) and m.group(2) == client_id)
    for n in mine[:-keep]:
        try:
            os.remove(os.path.join(paths.BACKUP_DIR, n))
        except OSError:
            pass


def list_backups() -> list[dict]:
    if not os.path.isdir(paths.BACKUP_DIR):
        return []
    out = []
    for n in sorted(os.listdir(paths.BACKUP_DIR), reverse=True):
        m = _BACKUP_RE.match(n)
        if not m or m.group(2) not in CLIENTS:
            continue
        when = _dt.datetime.strptime(m.group(1), "%Y%m%d-%H%M%S-%f")
        out.append({"name": n, "client": m.group(2), "label": CLIENTS[m.group(2)]["label"],
                    "time": when.strftime("%Y-%m-%d %H:%M:%S")})
    return out


def restore(vault, name: str) -> dict:
    m = _BACKUP_RE.match(name)
    if not m:
        raise ValueError("invalid backup name")
    with open(os.path.join(paths.BACKUP_DIR, name), "rb") as fh:
        payload = json.loads(vault.open_blob(fh.read(), "backup").decode("utf-8"))
    cid = payload["client"]
    _, raw = read_config(cid)
    if raw is not None:
        backup(vault, cid, raw)
    atomic_write(CLIENTS[cid]["path"], payload["content"].encode("utf-8"))
    return {"client": cid, "reload": CLIENTS[cid]["reload"]}
