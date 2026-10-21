"""Validation and masking of the vault's hosts and servers."""

import copy
import re
import secrets as _secrets

from . import adapters
from .clients import CLIENTS

ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

HOST_KINDS = {
    "windows": "Windows",
    "linux": "Linux",
    "mikrotik": "MikroTik",
    "other": "Other",
}
HOST_SECRETS = ("password", "sudo_password")


class ValidationError(ValueError):
    pass


def new_id() -> str:
    return _secrets.token_hex(6)


def default_port(kind: str, protocol: str, use_ssl: bool) -> int:
    if kind == "windows" and protocol == "winrm":
        return 5986 if use_ssl else 5985
    return 22


def _text(p: dict, key: str) -> str:
    value = p.get(key)
    return "" if value is None else str(value).strip()


def clean_host(p: dict, existing: dict | None) -> dict:
    name = _text(p, "name")
    if not name:
        raise ValidationError("Host name is required")
    kind = _text(p, "kind") or "other"
    if kind not in HOST_KINDS:
        raise ValidationError(f"Unknown host kind {kind!r}")
    address = _text(p, "address")
    if not address:
        raise ValidationError("Address is required")

    protocol = _text(p, "protocol") or "ssh"
    if kind != "windows":
        protocol = "ssh"
    if protocol not in ("ssh", "winrm"):
        raise ValidationError("Protocol must be ssh or winrm")
    use_ssl = bool(p.get("use_ssl")) and protocol == "winrm"

    raw_port = _text(p, "port")
    try:
        port = int(raw_port) if raw_port else default_port(kind, protocol, use_ssl)
    except ValueError:
        raise ValidationError("Port must be a number") from None
    if not 0 < port < 65536:
        raise ValidationError("Port must be between 1 and 65535")

    auth = _text(p, "auth") or "password"
    if protocol == "winrm":
        auth = "password"
    if auth not in ("password", "key"):
        raise ValidationError("Authentication must be password or key")
    key_path = _text(p, "key_path")
    if auth == "key" and not key_path:
        raise ValidationError("A private key path is required for key authentication")

    host = {
        "id": existing["id"] if existing else new_id(),
        "name": name,
        "kind": kind,
        "address": address,
        "port": port,
        "protocol": protocol,
        "use_ssl": use_ssl,
        "username": _text(p, "username"),
        "auth": auth,
        "key_path": key_path,
        "readonly": bool(p.get("readonly")),
        "description": _text(p, "description"),
    }
    for field in HOST_SECRETS:
        value = p.get(field)
        host[field] = (existing or {}).get(field, "") if value is None else str(value)
    if kind != "linux":
        host["sudo_password"] = ""
    return host


def clean_server(p: dict, existing: dict | None, hosts_by_id: dict) -> dict:
    sid = _text(p, "id")
    if not ID_RE.match(sid):
        raise ValidationError(
            "Server name must start with a letter or digit and contain only letters, digits, '-' and '_' "
            "(it becomes part of tool names, e.g. mcp__name__tool)"
        )
    template = _text(p, "template") or "generic"
    tpl = adapters.TEMPLATES.get(template)
    if tpl is None:
        raise ValidationError(f"Unknown template {template!r}")
    command = _text(p, "command")
    if not command:
        raise ValidationError("Command is required")
    args = [str(a) for a in (p.get("args") or []) if str(a) != ""]

    env = {}
    for key, value in (p.get("env") or {}).items():
        key = str(key).strip()
        if not ENV_RE.match(key):
            raise ValidationError(f"Invalid environment variable name {key!r}")
        env[key] = "" if value is None else str(value)

    old_secret = (existing or {}).get("secret_env", {})
    secret_env = {}
    for key, value in (p.get("secret_env") or {}).items():
        key = str(key).strip()
        if not ENV_RE.match(key):
            raise ValidationError(f"Invalid environment variable name {key!r}")
        if value is None:
            if key not in old_secret:
                raise ValidationError(f"Enter a value for secret {key}")
            secret_env[key] = old_secret[key]
        else:
            secret_env[key] = str(value)
    both = set(env) & set(secret_env)
    if both:
        raise ValidationError(f"{', '.join(sorted(both))} is defined twice")

    host_ids = []
    for hid in p.get("hosts") or []:
        h = hosts_by_id.get(hid)
        if h is None:
            raise ValidationError("A selected host no longer exists")
        if h["kind"] not in tpl["kinds"]:
            raise ValidationError(f"{tpl['label']} cannot use {HOST_KINDS[h['kind']]} host {h['name']!r}")
        if hid not in host_ids:
            host_ids.append(hid)
    if len(host_ids) < tpl["min_hosts"]:
        raise ValidationError(f"{tpl['label']} needs at least {tpl['min_hosts']} host")
    if tpl["max_hosts"] is not None and len(host_ids) > tpl["max_hosts"]:
        if tpl["max_hosts"] == 0:
            raise ValidationError(f"{tpl['label']} servers do not take hosts")
        raise ValidationError(f"{tpl['label']} takes at most {tpl['max_hosts']} host (add another server for more)")

    inventory_env = ""
    if "inventory_env" in tpl.get("options", []):
        inventory_env = _text(p, "inventory_env")
        if not ENV_RE.match(inventory_env):
            raise ValidationError("Name the environment variable that receives the host inventory, e.g. PROXMOX_MCP_HOSTS")
        if inventory_env in env or inventory_env in secret_env:
            raise ValidationError(f"{inventory_env} is filled from the hosts; remove it from the environment variables")

    return {
        "id": sid,
        "description": _text(p, "description"),
        "template": template,
        "inventory_env": inventory_env,
        "command": command,
        "args": args,
        "cwd": _text(p, "cwd"),
        "env": env,
        "secret_env": secret_env,
        "hosts": host_ids,
        "clients": [c for c in (p.get("clients") or []) if c in CLIENTS],
        "enabled": bool(p.get("enabled", True)),
    }


def mask_host(h: dict) -> dict:
    out = copy.deepcopy(h)
    out["secrets_set"] = {f: bool(h.get(f)) for f in HOST_SECRETS}
    for f in HOST_SECRETS:
        out[f] = ""
    return out


def mask_server(s: dict) -> dict:
    out = copy.deepcopy(s)
    out["secret_env"] = {k: bool(v) for k, v in s.get("secret_env", {}).items()}
    return out
