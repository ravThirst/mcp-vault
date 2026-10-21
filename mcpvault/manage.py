"""Management commands: inspect and edit the vault without touching secret values.

Meant for scripts and for Claude. Everything goes through the running agent
(so the vault must be unlocked), and nothing here can read or write a
password or secret variable; those are entered in the MCP Vault window.

Exit codes: 0 ok, 1 error, 2 usage, 4 agent not running or vault locked.
"""

import argparse
import json
import os
import sys

from . import adapters, model, paths
from .launcher import AgentClient

UI_HINT = "Open MCP Vault from the Start menu (or run \"MCP Vault.bat\")"


class CliError(Exception):
    def __init__(self, message: str, code: int = 1):
        super().__init__(message)
        self.code = code


# -- agent access ------------------------------------------------------------

def _client() -> AgentClient:
    c = AgentClient()
    if not c.ping():
        raise CliError(f"The MCP Vault agent is not running. {UI_HINT} and unlock it, then retry.", 4)
    return c


def _call(c: AgentClient, method: str, path: str, body: dict | None = None, timeout: float = 90) -> dict:
    status, data = c.call(method, path, body, timeout=timeout)
    if status in (401, 423):
        raise CliError(f"The vault is locked. {UI_HINT}, enter the master password, then retry.", 4)
    if status >= 400:
        raise CliError(data.get("error") or f"agent answered HTTP {status}")
    return data


def _snapshot(c: AgentClient) -> dict:
    return _call(c, "GET", "/internal/manage/snapshot")


def _find_host(snap: dict, ref: str) -> dict:
    for h in snap["hosts"]:
        if h["id"] == ref or h["name"].lower() == ref.lower():
            return h
    raise CliError(f"No host named {ref!r}. Hosts: {', '.join(h['name'] for h in snap['hosts']) or 'none'}")


def _find_server(snap: dict, ref: str) -> dict:
    for s in snap["servers"]:
        if s["id"] == ref:
            return s
    raise CliError(f"No server named {ref!r}. Servers: {', '.join(s['id'] for s in snap['servers']) or 'none'}")


def _out(args, data, text: str) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False) if args.json else text)


# -- read commands -----------------------------------------------------------

def cmd_list(args) -> int:
    snap = _snapshot(_client())
    hosts = {h["id"]: h for h in snap["hosts"]}
    lines = ["SERVERS"]
    for s in snap["servers"]:
        st = snap["status"]["servers"].get(s["id"])
        run = snap["running"].get(s["id"], 0)
        lines.append(
            f"  {s['id']:<16} {s['template']:<13} {'enabled ' if s['enabled'] else 'DISABLED'}"
            f"  hosts: {', '.join(hosts[h]['name'] for h in s['hosts'] if h in hosts) or '-'}"
            f"  apps: {', '.join(s['clients']) or '-'}"
            + (f"  running: {run}" if run else "")
            + (f"\n  {'':<16} last test {st['time']}: {st['summary']}" if st else ""))
    lines.append("HOSTS")
    for h in snap["hosts"]:
        kind = h["kind"] + (f"/{h['protocol']}" if h["kind"] == "windows" else "")
        auth = "key" if h["auth"] == "key" else ("password set" if h["secrets_set"]["password"] else "NO PASSWORD")
        st = snap["status"]["hosts"].get(h["id"])
        lines.append(f"  {h['name']:<16} {kind:<13} {h['username']}@{h['address']}:{h['port']}  {auth}"
                     f"  used by: {', '.join(h['used_by']) or '-'}" + (f"  [{st['summary']}]" if st else ""))
    _out(args, {"servers": snap["servers"], "hosts": snap["hosts"], "running": snap["running"],
                "status": snap["status"]}, "\n".join(lines))
    return 0


def cmd_show(args) -> int:
    snap = _snapshot(_client())
    item = _find_host(snap, args.name) if args.kind == "host" else _find_server(snap, args.name)
    print(json.dumps(item, indent=2, ensure_ascii=False))
    return 0


def cmd_templates(args) -> int:
    lines = []
    for key, t in adapters.TEMPLATES.items():
        kinds = ", ".join(t["kinds"]) or "no hosts"
        count = "exactly 1" if t["max_hosts"] == 1 else ("none" if t["max_hosts"] == 0 else f"{t['min_hosts']}+")
        lines.append(f"  {key:<14} hosts: {count} ({kinds})\n  {'':<14} {t['description']}")
    _out(args, adapters.TEMPLATES, "TEMPLATES\n" + "\n".join(lines))
    return 0


def cmd_logs(args) -> int:
    if not model.ID_RE.match(args.server):
        raise CliError("invalid server name")
    path = os.path.join(paths.LOG_DIR, f"{args.server}.log")
    if not os.path.exists(path):
        print(f"(no log yet: {path} is created when an app starts the server)")
        return 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.read().splitlines()
    print("\n".join(lines[-args.lines:]))
    return 0


# -- hosts ---------------------------------------------------------------------

_HOST_FIELDS = {"kind": "kind", "address": "address", "port": "port", "user": "username", "protocol": "protocol",
                "auth": "auth", "key_path": "key_path", "description": "description"}


def cmd_host(args) -> int:
    c = _client()
    snap = _snapshot(c)
    if args.action == "remove":
        h = _find_host(snap, args.name)
        if h["used_by"]:
            raise CliError(f"Host {h['name']!r} is used by {', '.join(h['used_by'])}; "
                           "remove it from those servers first (server edit <id> --remove-host).")
        if not args.yes:
            raise CliError(f"Removing host {h['name']!r} deletes its stored credentials. Re-run with --yes to confirm.", 2)
        _call(c, "DELETE", f"/internal/manage/hosts/{h['id']}")
        print(f"Removed host {h['name']}.")
        return 0

    if args.action == "add":
        if any(h["name"].lower() == args.name.lower() for h in snap["hosts"]):
            raise CliError(f"A host named {args.name!r} already exists; use `host edit`.")
        if not args.kind or not args.address:
            raise CliError("host add needs --kind and --address", 2)
        payload = {"name": args.name}
    else:
        h = _find_host(snap, args.name)
        payload = {k: v for k, v in h.items() if k not in ("secrets_set", "used_by", *model.HOST_SECRETS)}
        if args.rename:
            payload["name"] = args.rename
    for opt, field in _HOST_FIELDS.items():
        value = getattr(args, opt)
        if value is not None:
            payload[field] = value
    if args.ssl is not None:
        payload["use_ssl"] = args.ssl
    if args.readonly is not None:
        payload["readonly"] = args.readonly

    result = _call(c, "POST", "/internal/manage/hosts", payload)
    saved = _find_host(_snapshot(c), result["id"])
    print(f"Saved host {saved['name']}: {saved['kind']} {saved['username']}@{saved['address']}:{saved['port']} ({saved['auth']}).")
    if saved["auth"] == "password" and not saved["secrets_set"]["password"]:
        print(f"Next: enter its password in MCP Vault -> Hosts -> {saved['name']} -> Edit.")
    if saved["used_by"]:
        print(f"Servers using it ({', '.join(saved['used_by'])}) pick up the change the next time they start.")
    return 0


# -- servers ---------------------------------------------------------------------

def _parse_env(pairs: list[str]) -> dict:
    env = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep:
            raise CliError(f"--env expects NAME=value, got {pair!r}", 2)
        env[key.strip()] = value
    return env


def cmd_server(args) -> int:
    c = _client()
    snap = _snapshot(c)
    if args.action == "remove":
        s = _find_server(snap, args.id)
        if not args.yes:
            raise CliError(f"Removing server {s['id']!r} deletes its settings and secrets. Re-run with --yes to confirm.", 2)
        _call(c, "DELETE", f"/internal/manage/servers/{s['id']}")
        print(f"Removed server {s['id']}. Run `vault.py apply` to remove it from the apps.")
        return 0

    if args.action == "add":
        if any(s["id"] == args.id for s in snap["servers"]):
            raise CliError(f"A server named {args.id!r} already exists; use `server edit`.")
        if not args.command:
            raise CliError("server add needs --command", 2)
        payload = {"id": args.id, "template": args.template or "generic", "args": [], "env": {}, "secret_env": {},
                   "hosts": [], "clients": list(clients_default()), "enabled": True}
        before = None
    else:
        before = _find_server(snap, args.id)
        payload = dict(before, original_id=before["id"])
        payload["secret_env"] = {k: None for k in before["secret_env"]}
        if args.rename:
            payload["id"] = args.rename

    for opt in ("template", "command", "cwd", "description", "inventory_env"):
        value = getattr(args, opt)
        if value is not None:
            payload[opt] = value
    if args.clear_args:
        payload["args"] = []
    if args.arg:
        payload["args"] = list(args.arg)

    if args.host is not None:
        payload["hosts"] = [_find_host(snap, n)["id"] for n in args.host]
    for n in args.add_host or []:
        hid = _find_host(snap, n)["id"]
        if hid not in payload["hosts"]:
            payload["hosts"].append(hid)
    for n in args.remove_host or []:
        hid = _find_host(snap, n)["id"]
        payload["hosts"] = [h for h in payload["hosts"] if h != hid]

    env = dict(payload.get("env", {}))
    env.update(_parse_env(args.env or []))
    for key in args.unset_env or []:
        env.pop(key, None)
    payload["env"] = env
    secrets = dict(payload["secret_env"])
    for key in args.secret or []:
        if key in env:
            raise CliError(f"{key} is a plain variable; remove it with --unset-env first, then declare it as secret", 2)
        secrets.setdefault(key, None)
    for key in args.drop_secret or []:
        secrets.pop(key, None)
    payload["secret_env"] = secrets

    if args.app is not None:
        payload["clients"] = list(args.app)
    if args.enable is not None:
        payload["enabled"] = args.enable

    result = _call(c, "POST", "/internal/manage/servers", payload)
    after = _find_server(_snapshot(c), result["id"])
    print(f"Saved server {after['id']} ({after['template']}), apps: {', '.join(after['clients']) or 'none'}, "
          f"{'enabled' if after['enabled'] else 'disabled'}.")
    unset = [k for k, v in after["secret_env"].items() if not v]
    if unset:
        print(f"Next: enter the value of {', '.join(unset)} in MCP Vault -> Servers -> {after['id']} -> Edit.")
    affects_apps = before is None or any(before.get(k) != after.get(k) for k in ("id", "clients", "enabled"))
    if affects_apps:
        print("Then run `vault.py apply` so the apps start it through the vault.")
    else:
        print("Apps pick up the change the next time they start the server (reconnect it, e.g. /mcp in Claude Code).")
    return 0


def clients_default() -> list[str]:
    from .clients import CLIENTS

    return list(CLIENTS)


# -- tests / apply ------------------------------------------------------------------

def cmd_test(args) -> int:
    c = _client()
    snap = _snapshot(c)
    if args.kind == "host":
        h = _find_host(snap, args.name)
        r = _call(c, "POST", f"/internal/manage/hosts/{h['id']}/test")
        _out(args, r, f"{h['name']}: {'OK' if r['ok'] else 'FAILED'} - {r['summary']}")
        return 0 if r["ok"] else 1
    s = _find_server(snap, args.name)
    r = _call(c, "POST", f"/internal/manage/servers/{s['id']}/test", timeout=120)
    lines = [f"{s['id']}: {'OK' if r['ok'] else 'FAILED'} - {r['summary']}"]
    if r.get("tools") is not None:
        lines.append(f"  tools ({len(r['tools'])}): {', '.join(r['tools'])}")
        lines.append(f"  annotated: {r['annotated']}/{len(r['tools'])}   instructions: {'yes' if r.get('has_instructions') else 'no'}"
                     f"   protocol: {r.get('protocol')}")
    if r.get("stdout_noise"):
        lines.append(f"  WARNING non-JSON output on stdout: {r['stdout_noise']}")
    if r.get("stderr") and (args.verbose or not r["ok"]):
        lines.append("  stderr (secrets masked):\n    " + r["stderr"].strip().replace("\n", "\n    "))
    _out(args, r, "\n".join(lines))
    return 0 if r["ok"] else 1


def cmd_apply(args) -> int:
    c = _client()
    plan = _call(c, "GET", "/internal/manage/clients")["clients"]
    targets = args.app or [p["client"] for p in plan]
    lines = []
    pending = []
    for p in plan:
        if p["client"] not in targets:
            continue
        changes = [x for x in p["changes"] if x["action"] != "keep"]
        if p.get("error"):
            lines.append(f"{p['label']}: {p['error']}")
            continue
        lines.append(f"{p['label']} ({p['path']}): " + ("up to date" if not changes else
                     ", ".join(f"{x['action']} {x['name']}" for x in changes)))
        if p["unmanaged"]:
            lines.append(f"  not managed by the vault, left alone: {', '.join(p['unmanaged'])}")
        if changes:
            pending.append(p["client"])
    if args.dry_run or not pending:
        _out(args, plan, "\n".join(lines) + ("\n(dry run, nothing written)" if args.dry_run and pending else ""))
        return 0
    results = _call(c, "POST", "/internal/manage/clients/apply", {"clients": pending})["results"]
    for r in results:
        lines.append(f"  -> {r['client']}: " + (f"written. {r['reload']}" if r["ok"] else f"FAILED: {r['error']}"))
    _out(args, results, "\n".join(lines))
    return 0 if all(r["ok"] for r in results) else 1


# -- parser ----------------------------------------------------------------------------

def _bool_pair(p, name: str, dest: str, on_help: str, off_help: str, off_name: str | None = None) -> None:
    g = p.add_mutually_exclusive_group()
    g.add_argument(f"--{name}", dest=dest, action="store_true", default=None, help=on_help)
    g.add_argument(f"--{off_name or 'no-' + name}", dest=dest, action="store_false", help=off_help)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="vault.py", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list", help="servers and hosts (no secrets)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("show", help="one server or host as JSON (no secrets)")
    p.add_argument("kind", choices=["server", "host"])
    p.add_argument("name")
    p.set_defaults(fn=cmd_show, json=True)

    p = sub.add_parser("templates", help="server templates and the hosts they take")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_templates)

    p = sub.add_parser("logs", help="tail a server's log (secrets already masked)")
    p.add_argument("server")
    p.add_argument("-n", "--lines", type=int, default=60)
    p.set_defaults(fn=cmd_logs)

    p = sub.add_parser("host", help="add, edit or remove a host (passwords: use the UI)")
    p.add_argument("action", choices=["add", "edit", "remove"])
    p.add_argument("name")
    p.add_argument("--kind", choices=list(model.HOST_KINDS))
    p.add_argument("--address")
    p.add_argument("--port")
    p.add_argument("--user")
    p.add_argument("--protocol", choices=["ssh", "winrm"])
    _bool_pair(p, "ssl", "ssl", "WinRM over HTTPS", "WinRM over HTTP")
    p.add_argument("--auth", choices=["password", "key"])
    p.add_argument("--key-path", dest="key_path")
    _bool_pair(p, "readonly", "readonly", "server refuses writes on this host", "allow writes")
    p.add_argument("--description")
    p.add_argument("--rename")
    p.add_argument("--yes", action="store_true", help="confirm remove")
    p.set_defaults(fn=cmd_host)

    p = sub.add_parser("server", help="add, edit or remove a server (secret values: use the UI)")
    p.add_argument("action", choices=["add", "edit", "remove"])
    p.add_argument("id")
    p.add_argument("--template", choices=list(adapters.TEMPLATES))
    p.add_argument("--command")
    p.add_argument("--arg", action="append", help="argument (repeat; replaces all arguments)")
    p.add_argument("--clear-args", action="store_true")
    p.add_argument("--cwd")
    p.add_argument("--description")
    p.add_argument("--inventory-env", dest="inventory_env", help="variable for the host inventory (template 'inventory')")
    p.add_argument("--host", action="append", help="host name (repeat; replaces the host list)")
    p.add_argument("--add-host", action="append")
    p.add_argument("--remove-host", action="append")
    p.add_argument("--env", action="append", help="NAME=value plain variable (repeat)")
    p.add_argument("--unset-env", action="append")
    p.add_argument("--secret", action="append", help="declare a secret variable; its value is entered in the UI")
    p.add_argument("--drop-secret", action="append")
    p.add_argument("--app", action="append", choices=clients_default(), help="install into this app (repeat; replaces)")
    _bool_pair(p, "enable", "enable", "enable the server", "disable the server", off_name="disable")
    p.add_argument("--rename")
    p.add_argument("--yes", action="store_true", help="confirm remove")
    p.set_defaults(fn=cmd_server)

    p = sub.add_parser("test", help="test a host (TCP + SSH login) or a server (MCP handshake)")
    p.add_argument("kind", choices=["server", "host"])
    p.add_argument("name")
    p.add_argument("-v", "--verbose", action="store_true", help="always show stderr")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_test)

    p = sub.add_parser("apply", help="write launcher entries into the apps' MCP configs")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--app", action="append", choices=clients_default())
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_apply)
    return ap


COMMANDS = {"list", "show", "templates", "logs", "host", "server", "test", "apply"}


def main(argv: list[str]) -> int:
    if sys.stdout is not None:
        sys.stdout.reconfigure(encoding="utf-8")
    args = build_parser().parse_args(argv)
    args.json = getattr(args, "json", False)
    try:
        return args.fn(args)
    except CliError as exc:
        print(f"mcp-vault: {exc}", file=sys.stderr)
        return exc.code
    except OSError as exc:
        print(f"mcp-vault: cannot reach the agent: {exc}", file=sys.stderr)
        return 4
