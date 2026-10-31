"""Import existing MCP server entries (and their plaintext credentials) into the vault."""

import json
import os
import re

from . import clients, model

SECRET_NAME = re.compile(r"(?i)(pass|secret|token|apikey|api_key|_key$|credential|auth|cookie)")

_WINDOWS_KEYS = ("WINDOWS_HOST", "WINDOWS_USERNAME", "WINDOWS_PASSWORD", "WINDOWS_MCP_TRANSPORT",
                 "WINDOWS_SSH_PORT", "WINDOWS_WINRM_PORT", "WINDOWS_USE_SSL", "WINDOWS_SSH_KEY",
                 "WINDOWS_MCP_READONLY")
_MIKROTIK_KEYS = ("MIKROTIK_HOST", "MIKROTIK_USERNAME", "MIKROTIK_PASSWORD", "MIKROTIK_PORT",
                  "MIKROTIK_KEY_FILENAME", "MIKROTIK_INVENTORY", "MIKROTIK_INVENTORY_FILE")
_UBUNTU_KEYS = ("UBUNTU_MCP_HOSTS", "UBUNTU_MCP_HOSTS_FILE")


def _truthy(v) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _windows(name: str, env: dict) -> tuple[list[dict], list[str]]:
    protocol = (env.get("WINDOWS_MCP_TRANSPORT") or "winrm").lower()
    use_ssl = _truthy(env.get("WINDOWS_USE_SSL", ""))
    port = env.get("WINDOWS_SSH_PORT") if protocol == "ssh" else env.get("WINDOWS_WINRM_PORT")
    key = env.get("WINDOWS_SSH_KEY", "")
    host = {
        "name": name, "kind": "windows", "address": env.get("WINDOWS_HOST", ""), "port": port or "",
        "protocol": protocol, "use_ssl": use_ssl, "username": env.get("WINDOWS_USERNAME", ""),
        "auth": "key" if key and protocol == "ssh" else "password", "key_path": key,
        "password": env.get("WINDOWS_PASSWORD", ""), "readonly": _truthy(env.get("WINDOWS_MCP_READONLY", "")),
    }
    return [host], []


def _mikrotik(name: str, env: dict) -> tuple[list[dict], list[str]]:
    warnings = []
    items = None
    if env.get("MIKROTIK_INVENTORY"):
        try:
            items = json.loads(env["MIKROTIK_INVENTORY"])
        except json.JSONDecodeError:
            warnings.append("MIKROTIK_INVENTORY is YAML, not JSON; add its devices by hand")
            items = []
    elif env.get("MIKROTIK_INVENTORY_FILE"):
        path = os.path.expanduser(env["MIKROTIK_INVENTORY_FILE"])
        try:
            with open(path, encoding="utf-8") as fh:
                items = json.load(fh)
            warnings.append(f"{path} still holds plaintext credentials; delete it once the vault works")
        except (OSError, json.JSONDecodeError):
            warnings.append(f"Could not read {path} as JSON; add its devices by hand")
            items = []
    if items is None:
        items = [{"title": name, "host": env.get("MIKROTIK_HOST", "127.0.0.1"),
                  "port": env.get("MIKROTIK_PORT", 22), "username": env.get("MIKROTIK_USERNAME", "admin"),
                  "password": env.get("MIKROTIK_PASSWORD", ""), "key_filename": env.get("MIKROTIK_KEY_FILENAME")}]
    if isinstance(items, dict):
        items = items.get("inventory", [items])
    hosts = []
    for it in items:
        key = it.get("key_filename") or ""
        hosts.append({"name": it.get("title") or name, "kind": "mikrotik", "address": it.get("host", ""),
                      "port": it.get("port", 22), "username": it.get("username", "admin"),
                      "auth": "key" if key else "password", "key_path": key, "password": it.get("password", "")})
    return hosts, warnings


def _ubuntu(name: str, env: dict, command: str, args: list) -> tuple[list[dict], list[str]]:
    warnings = []
    data = None
    if env.get("UBUNTU_MCP_HOSTS"):
        data = json.loads(env["UBUNTU_MCP_HOSTS"])
    else:
        path = env.get("UBUNTU_MCP_HOSTS_FILE")
        if not path:
            script = next((a for a in args if str(a).lower().endswith(".py")), "")
            path = os.path.join(os.path.dirname(os.path.dirname(script)), "hosts.json") if script else ""
        path = os.path.expanduser(path)
        try:
            with open(path, encoding="utf-8-sig") as fh:
                data = json.load(fh)
            warnings.append(f"{path} still holds plaintext passwords; delete it once the vault works")
        except (OSError, json.JSONDecodeError):
            warnings.append(f"Could not read the host inventory {path or '(unknown)'}; add hosts by hand")
            data = []
    if isinstance(data, dict):
        data = data.get("hosts", [])
    hosts = []
    for it in data:
        key = it.get("key_file") or ""
        pw = it.get("password", "")
        sudo = it.get("sudo_password", "")
        hosts.append({"name": it.get("name") or it.get("host", name), "kind": "linux", "address": it.get("host", ""),
                      "port": it.get("port", 22), "username": it.get("username", ""),
                      "auth": "key" if key and not pw else "password", "key_path": key, "password": pw,
                      "sudo_password": "" if sudo == pw else sudo, "readonly": bool(it.get("readonly")),
                      "description": it.get("description", "")})
    return hosts, warnings


def _analyse(name: str, entry: dict) -> dict:
    command = str(entry.get("command", ""))
    args = [str(a) for a in entry.get("args") or []]
    env = {str(k): str(v) for k, v in (entry.get("env") or {}).items()}
    prop = {"id": name, "template": "generic", "command": command, "args": args, "cwd": entry.get("cwd", ""),
            "hosts": [], "env": {}, "secret_env": {}, "warnings": [], "supported": True}

    if entry.get("url") or entry.get("type") in ("http", "sse"):
        prop["supported"] = False
        prop["warnings"].append("Remote (URL) servers are not managed by the vault yet")
        return prop

    haystack = " ".join([command, *args]).lower()
    consumed: tuple = ()
    if "WINDOWS_HOST" in env:
        prop["template"], consumed = "windows-mcp", _WINDOWS_KEYS
        prop["hosts"], w = _windows(name, env)
    elif any(k in env for k in _MIKROTIK_KEYS) or "mikrotik" in haystack:
        prop["template"], consumed = "mikrotik-mcp", _MIKROTIK_KEYS
        prop["hosts"], w = _mikrotik(name, env)
    elif any(k in env for k in _UBUNTU_KEYS) or "ubuntu-mcp" in haystack:
        prop["template"], consumed = "ubuntu-mcp", _UBUNTU_KEYS
        prop["hosts"], w = _ubuntu(name, env, command, args)
    else:
        w = []
    prop["warnings"] += w

    for k, v in env.items():
        if k in consumed:
            continue
        (prop["secret_env"] if SECRET_NAME.search(k) else prop["env"])[k] = v
    return prop


def scan(data: dict) -> dict:
    """Find importable entries in every client config. Result contains secrets."""
    found: dict[str, dict] = {}
    notes = []
    for cid, info in clients.CLIENTS.items():
        try:
            cfg, raw = clients.read_config(cid)
        except (OSError, ValueError) as exc:
            notes.append(f"{info['label']}: cannot read {info['path']} ({exc})")
            continue
        if raw is None:
            continue
        for name, entry in (cfg.get("mcpServers") or {}).items():
            if isinstance(entry, dict) and not clients.is_managed(entry):
                found.setdefault(name, {})[cid] = entry

    existing_ids = {s["id"] for s in data["servers"]}
    proposals = []
    for name, entries in found.items():
        primary = entries.get("claude-code") or next(iter(entries.values()))
        prop = _analyse(name, primary)
        prop["clients"] = list(entries)
        if len({json.dumps(e, sort_keys=True) for e in entries.values()}) > 1:
            prop["warnings"].append(f"Configured differently across apps ({', '.join(sorted(entries))}); "
                                    "the first listed version is used")
        prop["exists"] = name in existing_ids
        proposals.append(prop)
    return {"proposals": proposals, "notes": notes}


def mask(result: dict) -> dict:
    out = {"notes": result["notes"], "proposals": []}
    for p in result["proposals"]:
        q = dict(p)
        q["secret_env"] = {k: bool(v) for k, v in p["secret_env"].items()}
        q["hosts"] = [{**{k: v for k, v in h.items() if k not in model.HOST_SECRETS},
                       "has_password": bool(h.get("password"))} for h in p["hosts"]]
        out["proposals"].append(q)
    return out


def apply(data: dict, ids: list[str]) -> dict:
    """Import the selected proposals into `data` (mutates it). Returns a summary."""
    result = scan(data)
    hosts_by_id = {h["id"]: h for h in data["hosts"]}
    imported, skipped = [], []
    for prop in result["proposals"]:
        if prop["id"] not in ids:
            continue
        if prop["exists"] or not prop["supported"]:
            skipped.append(prop["id"])
            continue
        host_ids = []
        for raw in prop["hosts"]:
            h = model.clean_host(raw, None)
            same = next((x for x in data["hosts"] if (x["kind"], x["address"].lower(), x["port"], x["username"])
                         == (h["kind"], h["address"].lower(), h["port"], h["username"])), None)
            if same:
                host_ids.append(same["id"])
                continue
            base, n = h["name"], 2
            names = {x["name"].lower() for x in data["hosts"]}
            while h["name"].lower() in names:
                h["name"] = f"{base} {n}"
                n += 1
            data["hosts"].append(h)
            hosts_by_id[h["id"]] = h
            host_ids.append(h["id"])
        server = model.clean_server({**prop, "hosts": host_ids, "enabled": True}, None, hosts_by_id)
        data["servers"].append(server)
        imported.append(server["id"])
    return {"imported": imported, "skipped": skipped}
