"""Server templates: how vault hosts turn into each MCP server's own config.

Each template knows which host kinds it accepts and produces the environment
variables that server already understands, so the servers need no changes.
"""

import json

TEMPLATES = {
    "windows-mcp": {
        "label": "windows-mcp",
        "description": "One Windows machine over SSH or WinRM (WINDOWS_* variables).",
        "kinds": ["windows"],
        "min_hosts": 1,
        "max_hosts": 1,
    },
    "ubuntu-mcp": {
        "label": "ubuntu-mcp",
        "description": "One or more Linux hosts over SSH (UBUNTU_MCP_HOSTS).",
        "kinds": ["linux"],
        "min_hosts": 1,
        "max_hosts": None,
    },
    "mikrotik-mcp": {
        "label": "mikrotik-mcp",
        "description": "One or more RouterOS devices over SSH (MIKROTIK_INVENTORY).",
        "kinds": ["mikrotik"],
        "min_hosts": 1,
        "max_hosts": None,
    },
    "inventory": {
        "label": "Standard inventory",
        "description": "Any server built to SERVER-SPEC: its hosts arrive as inline JSON in the variable named below.",
        "kinds": ["windows", "linux", "mikrotik", "other"],
        "min_hosts": 1,
        "max_hosts": None,
        "options": ["inventory_env"],
    },
    "generic": {
        "label": "Generic",
        "description": "Any MCP server; configured with environment variables only.",
        "kinds": [],
        "min_hosts": 0,
        "max_hosts": 0,
    },
}


class ResolveError(Exception):
    pass


def _windows(hosts: list[dict], _server: dict) -> dict:
    h = hosts[0]
    env = {
        "WINDOWS_HOST": h["address"],
        "WINDOWS_USERNAME": h["username"],
        "WINDOWS_MCP_TRANSPORT": h["protocol"],
    }
    if h["protocol"] == "ssh":
        env["WINDOWS_SSH_PORT"] = str(h["port"])
        if h["auth"] == "key":
            env["WINDOWS_SSH_KEY"] = h["key_path"]
        else:
            env["WINDOWS_PASSWORD"] = h["password"]
    else:
        env["WINDOWS_WINRM_PORT"] = str(h["port"])
        env["WINDOWS_PASSWORD"] = h["password"]
        if h.get("use_ssl"):
            env["WINDOWS_USE_SSL"] = "true"
    if h.get("readonly"):
        env["WINDOWS_MCP_READONLY"] = "true"
    return env


def standard_hosts(hosts: list[dict]) -> list[dict]:
    """Host objects in the SERVER-SPEC inventory shape (also what ubuntu-mcp reads)."""
    items = []
    for h in hosts:
        item = {"name": h["name"], "host": h["address"], "port": h["port"], "username": h["username"]}
        if h["auth"] == "key":
            item["key_file"] = h["key_path"]
        else:
            item["password"] = h["password"]
        if h.get("sudo_password"):
            item["sudo_password"] = h["sudo_password"]
        if h.get("readonly"):
            item["readonly"] = True
        if h.get("description"):
            item["description"] = h["description"]
        items.append(item)
    return items


def _ubuntu(hosts: list[dict], _server: dict) -> dict:
    return {"UBUNTU_MCP_HOSTS": json.dumps({"hosts": standard_hosts(hosts)}, ensure_ascii=False)}


def _inventory(hosts: list[dict], server: dict) -> dict:
    items = standard_hosts(hosts)
    for item, h in zip(items, hosts):
        item["kind"] = h["kind"]
        if h["kind"] == "windows":
            item["protocol"] = h["protocol"]
            if h.get("use_ssl"):
                item["use_ssl"] = True
    return {server["inventory_env"]: json.dumps({"hosts": items}, ensure_ascii=False)}


def _mikrotik(hosts: list[dict], _server: dict) -> dict:
    items = []
    for h in hosts:
        item = {"title": h["name"], "host": h["address"], "port": h["port"], "username": h["username"]}
        if h["auth"] == "key":
            item["key_filename"] = h["key_path"]
        else:
            item["password"] = h["password"]
        items.append(item)
    return {"MIKROTIK_INVENTORY": json.dumps(items, ensure_ascii=False)}


_BUILDERS = {"windows-mcp": _windows, "ubuntu-mcp": _ubuntu, "mikrotik-mcp": _mikrotik, "inventory": _inventory}


def resolve(server: dict, hosts_by_id: dict) -> tuple[dict, list[str]]:
    """Build the launch spec for a server.

    Returns ({command, args, cwd, env}, secrets) where `secrets` lists every
    sensitive value so callers can redact it from logs and error messages.
    """
    template = TEMPLATES.get(server["template"])
    if template is None:
        raise ResolveError(f"unknown template {server['template']!r}")
    hosts = []
    for hid in server.get("hosts", []):
        h = hosts_by_id.get(hid)
        if h is None:
            raise ResolveError(f"server {server['id']!r} refers to a host that no longer exists")
        hosts.append(h)
    if len(hosts) < template["min_hosts"]:
        raise ResolveError(f"server {server['id']!r} needs at least {template['min_hosts']} host(s)")

    env: dict[str, str] = {}
    builder = _BUILDERS.get(server["template"])
    if builder:
        env.update(builder(hosts, server))
    env.update(server.get("env", {}))
    env.update(server.get("secret_env", {}))

    secrets = [v for v in server.get("secret_env", {}).values() if v]
    for h in hosts:
        secrets += [h.get("password", ""), h.get("sudo_password", "")]
    secrets = sorted({s for s in secrets if s and len(s) >= 3}, key=len, reverse=True)

    spec = {
        "command": server["command"],
        "args": list(server.get("args", [])),
        "cwd": server.get("cwd", ""),
        "env": env,
    }
    return spec, secrets


def missing_command(command: str) -> str | None:
    """Explain why `command` cannot be started, or None if it looks runnable."""
    import os
    import shutil

    if os.path.isabs(command) or os.sep in command or "/" in command:
        return None if os.path.exists(command) else f"command not found: {command}"
    return None if shutil.which(command) else f"command {command!r} is not on PATH"


def redact(text: str, secrets: list[str]) -> str:
    for s in secrets:
        text = text.replace(s, "******")
    return text
