"""MCP client config files (Claude Code, Claude Desktop).

The vault writes one launcher entry per server into each selected client:

    "windows": {"type": "stdio", "command": "<venv python>", "args": ["<vault.py>", "run", "windows"], "env": {}}

An entry counts as vault-managed when its args point at this app's vault.py
with "run"; everything else in the file is left untouched.
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
}


def _norm(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))


def launcher_entry(server_id: str, typed: bool) -> dict:
    entry = {"command": paths.python_console(), "args": [paths.ENTRY, "run", server_id], "env": {}}
    return {"type": "stdio", **entry} if typed else entry


def is_managed(entry: dict) -> bool:
    args = entry.get("args") or []
    return any(isinstance(a, str) and _norm(a) == _norm(paths.ENTRY) for a in args) and "run" in args


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
        try:
            cfg, raw = read_config(cid)
            if raw is not None:
                backup(vault, cid, raw)
            current = dict(cfg.get("mcpServers") or {})
            desired = _desired(servers, cid)
            for name in [n for n, e in current.items() if is_managed(e) and n not in desired]:
                del current[name]
            current.update(desired)
            cfg["mcpServers"] = current
            atomic_write(info["path"], (json.dumps(cfg, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
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
