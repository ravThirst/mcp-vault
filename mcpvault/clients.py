"""MCP client config files (Claude Code, Claude Desktop, Kimi Work).

The vault writes one launcher entry per server into each selected client:

    "windows": {"type": "stdio", "command": "<venv python>", "args": ["<vault.py>", "run", "windows"], "env": {}}

An entry counts as vault-managed when its args point at this app's vault.py
with "run"; everything else in the file is left untouched.

Kimi Work loads MCP servers from plugins: the vault maintains a `mcp-vault`
plugin whose `kimi.plugin.json` manifest holds the launcher entries, and
registers that plugin in `plugins/installed.json` on apply.
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
}


def _norm(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))


def launcher_entry(server_id: str, typed: bool) -> dict:
    entry = {"command": paths.python_console(), "args": [paths.ENTRY, "run", server_id], "env": {}}
    return {"type": "stdio", **entry} if typed else entry


def is_managed(entry: dict) -> bool:
    args = entry.get("args") or []
    return any(isinstance(a, str) and _norm(a) == _norm(paths.ENTRY) for a in args) and "run" in args


# -- Kimi Work plugin ---------------------------------------------------------

def kimi_available() -> bool:
    """True when a Kimi Work plugins folder is present on this machine."""
    return os.path.isdir(os.path.join(paths.KIMI_HOME, "plugins"))


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
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError(f"{path} does not contain a JSON object")
    return obj, raw


def _desired(servers: list[dict], client_id: str) -> dict:
    typed = CLIENTS[client_id]["typed"]
    return {s["id"]: launcher_entry(s["id"], typed) for s in servers if s.get("enabled", True) and client_id in s.get("clients", [])}


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
            if cid == "kimi":
                base = _kimi_scaffold()
                base.update({k: v for k, v in cfg.items() if k != "mcpServers"})
                base["mcpServers"] = cfg.get("mcpServers") or {}
                cfg = base
                os.makedirs(paths.KIMI_PLUGIN_DIR, exist_ok=True)
            current = dict(cfg.get("mcpServers") or {})
            desired = _desired(servers, cid)
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
