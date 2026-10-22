---
name: mcp-vault
description: Operate and troubleshoot MCP Vault, the local Windows app that keeps MCP server hosts and credentials in an encrypted vault and launches every MCP server through `vault.py run <server>`. Use this whenever the user wants to add, register, rename, move or remove an MCP server or a host (PC, router, VPS, NAS) that an MCP server talks to; change which host or credentials a server uses; update Claude Code / Claude Desktop MCP config; or asks why an MCP server fails, times out ("connection timed out after 30000ms", "Connection closed"), shows no tools or reports a config error. Also use it for anything about the vault itself: unlocking, the master password, the agent, logs, backups, sharing the app. Use it even if the user never says "vault": in this setup every MCP server goes through it.
---

# MCP Vault

MCP Vault replaces the plaintext `env` blocks in MCP client configs with one
encrypted vault. Each MCP client entry is just `python vault.py run <server>`;
the launcher asks a background agent for that server's settings and starts the
real server with them. Understanding that chain is what makes troubleshooting fast:

```
Claude Code / Desktop ─starts─> vault.py run <server> ─asks─> agent 127.0.0.1:47821 (holds the unlocked vault)
                                      │                               │ (locked → one password pop-up)
                                      └─starts real server <──────────┘ env built from the server's hosts + variables
```

| What | Where |
| --- | --- |
| App (code, `.venv`, `MCP Vault.bat`, `SERVER-SPEC.md`) | `~\.mcp-servers\mcp-vault` (a shared copy may live elsewhere; see below) |
| Vault (AES-GCM, master password) | `%APPDATA%\mcp-vault\vault.json` |
| Agent log / per-server logs (secrets masked) | `%APPDATA%\mcp-vault\agent.log`, `%APPDATA%\mcp-vault\logs\<server>.log` |
| Encrypted backups of app configs | `%APPDATA%\mcp-vault\backups\` |
| Client configs it writes | `~\.claude.json` (Claude Code), `%APPDATA%\Claude\claude_desktop_config.json` (Claude Desktop) |

If the app is not at the default path, read any vault-managed entry in
`~\.claude.json`: its `command` is the vault's python and its first arg is `vault.py`.

## Ground rules: secrets never pass through you

The whole point of the vault is that credentials live in one encrypted place and
nowhere else, including this conversation. So:

- Never ask for the master password or a host/API password in chat, and do not
  accept one if offered; say where to enter it instead. Passwords and secret
  variables are typed in the MCP Vault window (Start menu → **MCP Vault**).
- Use only the commands below. Do not call the agent's `/internal/resolve`
  endpoint, read `agent.json`'s token for your own requests, decrypt the vault
  or print a server's resolved environment: those return live credentials.
- `vault.py apply` rewrites the user's MCP client config files (an encrypted
  backup is made first). Show the `--dry-run` result and get a yes first.
  Removing a host or server needs `--yes`; confirm with the user before passing it.
- The user's MCP servers can reach real machines. Testing a server only runs the
  MCP handshake and lists tools; it calls no tools. Testing a host attempts one
  SSH login. Both are safe to run without asking.

## Running the CLI

PowerShell (define once per command line):

```powershell
$V = "$HOME\.mcp-servers\mcp-vault"; & "$V\.venv\Scripts\python.exe" "$V\vault.py" list
```

| Command | Purpose |
| --- | --- |
| `status` | Is the agent running, is the vault unlocked |
| `list [--json]` | All servers and hosts: template, hosts, apps, enabled, running count, last test |
| `show server <id>` / `show host <name>` | One entry as JSON (secret values appear only as set/unset flags) |
| `templates` | Server templates and which host kinds they take |
| `host add <name> --kind windows\|linux\|mikrotik\|other --address A [--port N] [--user U] [--protocol ssh\|winrm] [--auth password\|key] [--key-path P] [--readonly] [--description D]` | New host; password is then entered in the UI |
| `host edit <name> [same options] [--rename NEW] [--enable\|--disable]` | Change only the given fields. A disabled host keeps its credentials but is not given to servers; a server whose hosts are all disabled won't start |
| `host remove <name> [--yes]` | Without `--yes`: shows the effect. With it: deletes the host and its credentials, unlinks it from servers that keep other hosts, and deletes servers left with none (then `apply`) |
| `server add <id> --command EXE [--arg A]... [--template T] [--host NAME]... [--inventory-env VAR] [--env K=V]... [--secret K]... [--app claude-code\|claude-desktop]... [--cwd D] [--description D]` | New server. `--secret K` declares a secret variable; its value goes in the UI |
| `server edit <id> [--add-host H] [--remove-host H] [--host H]... [--env K=V] [--unset-env K] [--secret K] [--drop-secret K] [--enable\|--disable] [--rename NEW] ...` | Change only the given fields (`--arg`/`--host`/`--app` replace the whole list) |
| `server remove <id> --yes` | Delete server entry and its secrets |
| `test server <id> [-v]` | Start it, MCP handshake + tools/list: tool count, annotations, instructions, stderr |
| `test host <name>` | TCP reachability + SSH login (WinRM: reachability only) |
| `apply [--dry-run] [--app X]` | Write/remove launcher entries in the apps' MCP configs |
| `logs <server> [-n 100]` | Tail the server's stderr log |
| `ui` | Open the MCP Vault window (starts the agent) |

Exit code 4 means the agent is not running or the vault is locked: ask the user
to open **MCP Vault** from the Start menu and unlock it, then retry. Do not
try to work around it.

### Templates

- `windows-mcp`: one or more Windows hosts (SSH or WinRM) → `WINDOWS_MCP_HOSTS`; tools take `host` (windows-mcp 2.0+; with a single host the old `WINDOWS_*` variables are set too).
- `ubuntu-mcp`: Linux hosts → `UBUNTU_MCP_HOSTS`.
- `mikrotik-mcp`: MikroTik devices → `MIKROTIK_INVENTORY`.
- `inventory`: any server built to `SERVER-SPEC.md`; hosts go as inline JSON into the
  variable named by `--inventory-env` (e.g. `PROXMOX_MCP_HOSTS`). New servers should use this.
- `generic`: no hosts; plain `--env` variables plus `--secret` variables.

## Common tasks

**Add a server for an existing program**
1. `templates`, then `list` to reuse existing hosts.
2. `host add …` for any new machine; tell the user to enter its password in the UI (MCP Vault → Hosts → Edit).
3. `server add <id> --template … --command <python or exe> --arg <script> --host <name>`, plus `--secret` for API tokens.
   The id becomes part of tool names (`mcp__<id>__tool`), so keep it short: letters, digits, `-`, `_`.
4. After the user has entered the values: `test server <id>`; it must report OK.
5. `apply --dry-run`, show it, then `apply` after a yes.
6. Tell the user to reconnect: `/mcp` in Claude Code or a new session, or restart Claude Desktop.

**Change a password, token or key**: UI only (Hosts → Edit, or Servers → Edit
for secret variables). No `apply` needed; the server picks it up when it next
starts, so reconnect it.

**Point a server at another machine**: `server edit <id> --host <name>` (or
`--add-host`/`--remove-host` for multi-host servers), `test server <id>`, reconnect.

**What needs `apply`?** Only adding, removing, renaming, enabling/disabling a
server, or changing which apps it is installed into. Everything else (hosts,
passwords, arguments, variables) is read at server start.

## Troubleshooting

Work from the outside in: agent → server process → remote host.

1. **`status`**. Not running or locked explains a whole class of failures. A locked
   vault does not block startup: launchers answer from saved tool lists
   (`%APPDATA%\mcp-vault\toolcache`) and the first tool call shows the password
   window. A tool result "MCP Vault is locked, so this server could not start"
   means that window was cancelled or timed out; ask the user to unlock, then retry
   the call. A server with no tools at all while locked has no saved list yet:
   it fills in once the vault is unlocked (or run `test server <id>` while unlocked).
2. **`list`**. Is the server present and enabled, installed into the right app, with the right hosts?
   If the client still shows an old entry or no entry, run `apply --dry-run`: a pending change means apply was never run.
3. **`test server <id>`** separates the cases:
   - `Cannot start: command not found` → the runtime is missing or moved (e.g. Node.js
     uninstalled). Fix the install or `server edit <id> --command <new path>`.
   - `Handshake failed: server exited` / timeout → read the stderr shown (or `logs <id>`).
     Typical: missing Python package in the server's `.venv`, a config error, a crash on import.
   - `WARNING non-JSON output on stdout` → the server prints to stdout, which corrupts
     the MCP stream; it must log to stderr.
   - OK here but broken in Claude → the client is still running an old process or
     config: `apply --dry-run`, then reconnect.
4. **Errors from inside a working server** ("WINDOWS_HOST is not set", "no hosts configured",
   "unknown host") mean the server got the wrong or empty settings: `show server <id>`
   to check template and hosts; empty secrets show as `false`. "cannot start: its host(s) …
   are disabled" means the user disabled them on purpose; ask before `host edit <name> --enable`.
5. **`test host <name>`** for remote failures: "Port … unreachable" means the
   machine is off, on another network or firewalled (nothing the vault can fix);
   "authentication failed" means wrong username/password/key, fixed in the UI.
6. Still unclear: read `%APPDATA%\mcp-vault\agent.log` (agent start/lock/unlock events)
   and `logs <id>` (each start, exit code and stderr of that server).

## Sharing the app

`Make share zip.bat` in the app folder builds `mcp-vault-<version>.zip` from
source files only: no vault, logs, backups or `.venv`. The recipient extracts
it, double-clicks `MCP Vault.bat` (installs Python deps, offers a Start-menu
shortcut) and creates their own vault. `vault.py install-skills` installs these
skills for them.
