---
name: mcp-vault
description: Operate and troubleshoot MCP Vault, the local Windows app that keeps MCP server hosts and credentials in an encrypted vault and launches every MCP server through `vault.py run <server>`. Use this whenever the user asks whether a named server, host, PC, VM, router or NAS is accessible, online or reachable (e.g. "check if meridian server in mcp vault is accessible"); wants to add, register, rename, move, enable/disable or remove an MCP server or host; change which host or credentials a server uses; update Claude Code / Claude Desktop / Kimi Work / Codex / Antigravity MCP config; or asks why an MCP server fails, times out ("connection timed out after 30000ms", "Connection closed"), shows no tools or reports a config error. Also use it for anything about the vault itself: unlocking, the master password, the agent, logs, backups, sharing the app. Use it even if the user never says "vault": in this setup every MCP server goes through it.
---

# MCP Vault

MCP Vault replaces plaintext `env` blocks in MCP client configs with one
encrypted vault. Each MCP client entry is just `python vault.py run <server>`;
the launcher asks a background agent for that server's settings and starts the
real server with them. Understanding that chain makes troubleshooting instant:

```
Claude / Codex / Antigravity / Kimi Work ─starts─> vault.py run <server> ─asks─> agent 127.0.0.1:47821 (unlocked vault)
                                                         │                               │ (locked → password pop-up)
                                                         └─starts real server <──────────┘ env built from hosts + secrets
```

| What | Where |
| --- | --- |
| App install path breadcrumb (plain path, no secrets) | `%APPDATA%\mcp-vault\app_dir.txt` |
| App (`vault.py`, `.venv`, `MCP Vault.bat`, `SERVER-SPEC.md`, `agent\`, bundled `servers\`) | `~\.mcp-servers\mcp-vault` by default (or the path in `app_dir.txt`) |
| Bundled multi-host MCP servers (run on `<APP_DIR>\.venv\Scripts\python.exe`) | `<APP_DIR>\servers\windows-mcp\src\server.py` (21 tools: SSH, WinRM, WinMCP `agent`), `<APP_DIR>\servers\ubuntu-mcp\src\server.py` (22 tools: SSH) |
| Vault (AES-GCM, master password — **never read**) | `%APPDATA%\mcp-vault\vault.json` |
| Agent token file (**never read**) | `%APPDATA%\mcp-vault\agent.json` |
| Agent log / per-server logs (secrets masked) | `%APPDATA%\mcp-vault\agent.log`, `%APPDATA%\mcp-vault\logs\<server>.log` |
| Encrypted backups of app configs | `%APPDATA%\mcp-vault\backups\` |
| Client configs it writes | `~\.claude.json` (Claude Code), `%APPDATA%\Claude\claude_desktop_config.json` (Claude Desktop), `%APPDATA%\kimi-desktop\daimon-share\daimon\runtime\kimi-code\home\plugins\managed\mcp-vault\kimi.plugin.json` (Kimi Work; also registers in `plugins\installed.json`), `~\.codex\config.toml` (Codex), `~\.gemini\config\mcp_config.json` (Antigravity) |

### Locating `vault.py` (zero-secret discovery)

Resolve the app folder `$V` deterministically without ever reading `agent.json` or `vault.json`:
1. `%APPDATA%\mcp-vault\app_dir.txt` (written automatically when the agent starts or skills are installed).
2. Default install path `~\.mcp-servers\mcp-vault` (or the stamped install path below).
3. Start Menu shortcut `%APPDATA%\Microsoft\Windows\Start Menu\Programs\MCP Vault.lnk` (its `WorkingDirectory` is `$V`, even before any client config is applied).
4. Any launcher entry (`args` containing `vault.py` and `run`) in `~\.codex\config.toml`, `~\.gemini\config\mcp_config.json`, `~\.claude.json`, `%APPDATA%\Claude\claude_desktop_config.json`, or Kimi Work's `kimi.plugin.json`.

```powershell
$V = if (Test-Path "$env:APPDATA\mcp-vault\app_dir.txt") {
    (Get-Content "$env:APPDATA\mcp-vault\app_dir.txt" -Raw).Trim()
} elseif (Test-Path "$HOME\.mcp-servers\mcp-vault\vault.py") {
    "$HOME\.mcp-servers\mcp-vault"
} elseif (Test-Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\MCP Vault.lnk") {
    (New-Object -ComObject WScript.Shell).CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\MCP Vault.lnk").WorkingDirectory
}
```

## Fast path: Checking if a server/host `<name>` is accessible (<2s)

1. **Terminology ("server" = host):** When a user asks *"check if `<name>` server [in mcp vault] is accessible"* (e.g. `"meridian"`), `<name>` is almost always a **host** inside a multi-host MCP server (`windows`, `windows-server`, `ubuntu`, `mikrotik`), **not** a top-level MCP server ID.
2. **Step 1 — If MCP tools are active in this session:** Call `win_test_connection(host="<name>")` or `ubuntu_test_connection(host="<name>")` right away (call `win_list_hosts` / `ubuntu_list_hosts` / `<prefix>_list_hosts` first if unsure which server owns `<name>`).
3. **Step 2 — CLI (if the MCP server isn't applied to this client yet, is in standby, or fails):** Run `vault.py list` and `vault.py test host <name>` in **one** command:
   ```powershell
   $V = if (Test-Path "$env:APPDATA\mcp-vault\app_dir.txt") { (Get-Content "$env:APPDATA\mcp-vault\app_dir.txt" -Raw).Trim() } else { "$HOME\.mcp-servers\mcp-vault" }
   & "$V\.venv\Scripts\python.exe" "$V\vault.py" list; & "$V\.venv\Scripts\python.exe" "$V\vault.py" test host <name>
   ```
   - `vault.py test host <name>` natively performs **TCP reachability + SSH login OR an encrypted WinMCP `agent` ping** (verifying the stored `agent.key` and returning remote `ComputerName` + WinMCP agent version + latency in ms, without exposing secrets).
   - **NEVER** attempt WinRM against a `windows/agent` host (port `5990`), and **NEVER** write custom scripts or reverse-engineer `winmcp-agent` AES/HMAC crypto — `vault.py test host <name>` and `win_test_connection(host="<name>")` already do it.

## Ground rules: secrets never pass through you

The whole point of the vault is that credentials live in one encrypted place and
nowhere else, including this conversation. So:

- Never ask for the master password, SSH/WinRM password, API token or WinMCP agent
  key in chat, and do not accept one if offered; say where to enter it instead.
  Passwords, agent keys and secret variables are typed in the MCP Vault window
  (Start menu → **MCP Vault**).
- Use only the commands below. Do not call `/internal/resolve`, read `agent.json`
  or `vault.json`, decrypt the vault, print a server's resolved environment, or
  write custom scripts to speak the `winmcp-agent` protocol directly.
- `vault.py apply` rewrites the user's MCP client config files (an encrypted
  backup is made first) and refreshes installed agent skills. Show `--dry-run`
  and get a yes first. Removing a host or server needs `--yes`; confirm first.
- Testing a server runs only the MCP handshake, lists tools and checks protocol
  compatibility; it calls no tools. Testing a host attempts TCP reachability plus
  one SSH login or one encrypted WinMCP `agent` ping (WinRM: TCP reachability only).
  Both are safe to run without asking.

## Running the CLI

PowerShell (define once per command line):

```powershell
$V = if (Test-Path "$env:APPDATA\mcp-vault\app_dir.txt") { (Get-Content "$env:APPDATA\mcp-vault\app_dir.txt" -Raw).Trim() } else { "$HOME\.mcp-servers\mcp-vault" }
& "$V\.venv\Scripts\python.exe" "$V\vault.py" list
```

| Command | Purpose |
| --- | --- |
| `status` | Is the agent running, is the vault unlocked |
| `list [--json]` | All servers and hosts: template, hosts, apps, enabled, running count, last test |
| `show server <id>` / `show host <name>` | One entry as JSON (secret values appear only as set/unset flags; cross-hints if `<name>` is a host vs server) |
| `templates` | Server templates and which host kinds they take |
| `host add <name> --kind windows\|linux\|mikrotik\|other --address A [--port N] [--user U] [--protocol ssh\|winrm\|agent] [--auth password\|key] [--key-path P] [--readonly] [--description D]` | New host; password / agent key is then entered in the UI |
| `host edit <name> [same options] [--rename NEW] [--enable\|--disable]` | Change only the given fields. A disabled host keeps its credentials; if all of a server's hosts are disabled, the launcher stays in standby (answering from cached tools) and starts automatically once a host is enabled |
| `host remove <name> [--yes]` | Without `--yes`: shows the effect. With it: deletes the host and its credentials, unlinks it from servers that keep other hosts, and deletes servers left with none (then `apply`) |
| `server add <id> [--template T] [--command EXE] [--arg A]... [--host NAME]... [--inventory-env VAR] [--env K=V]... [--secret K]... [--app claude-code\|claude-desktop\|kimi\|codex\|antigravity]... [--cwd D] [--description D]` | New server. Omit `--command` with `--template windows-mcp\|ubuntu-mcp` to auto-fill the bundled server in `servers\`. `--secret K` declares a secret variable entered in the UI |
| `server edit <id> [--add-host H] [--remove-host H] [--host H]... [--env K=V] [--unset-env K] [--secret K] [--drop-secret K] [--enable\|--disable] [--rename NEW] ...` | Change only the given fields (`--arg`/`--host`/`--app` replace the whole list) |
| `server remove <id> --yes` | Delete server entry and its secrets |
| `test server <id> [-v]` | Start it, MCP handshake + tools/list + compatibility warnings (e.g. `agent` host attached to a legacy WinRM-only binary), annotations, instructions, stderr |
| `test host <name>` | TCP reachability + SSH login or WinMCP `agent` encrypted ping (WinRM: reachability only) |
| `apply [--dry-run] [--app X]` | Write/remove launcher entries in the apps' MCP configs (and refresh installed skills) |
| `logs <server> [-n 100]` | Tail the server's redacted stderr log |
| `ui` | Open the MCP Vault window (starts the agent) |

Exit code 4 means the agent is not running or the vault is locked: ask the user
to open **MCP Vault** from the Start menu and unlock it, then retry. Do not
try to work around it (no browser/UI automation, no reading `agent.json` yourself).
If the message says the agent **cannot be reached from here** (something listens on
port 47821 but the token file is missing or belongs to another agent; the user sees
the UI working), wait 3 s and retry once: agents from 0.4.4 restore the file
themselves. If it persists, run `vault.py stop --force` (tell the user the vault will
lock), then `vault.py ui`, ask the user to unlock, and retry.

### Templates & bundled servers

- `windows-mcp` (**bundled** at `<APP_DIR>\servers\windows-mcp\src\server.py`, 21 tools): one or more Windows hosts over SSH, WinRM, or the portable WinMCP `agent` (default port `5990`) → `WINDOWS_MCP_HOSTS`; every tool takes optional `host` (`win_list_hosts`, `win_test_connection`, `win_run_powershell`, etc.). Single SSH/WinRM hosts also populate legacy `WINDOWS_*` vars (`agent` hosts never populate `WINDOWS_WINRM_PORT` or `WINDOWS_PASSWORD`). For `agent` hosts, start the portable agent on the target Windows machine with `irm https://raw.githubusercontent.com/ravThirst/mcp-vault/main/agent/launch.ps1 | iex` (or copy `agent\` from the MCP Vault folder) and paste the printed key as the host's **Agent key** in the UI.
- `ubuntu-mcp` (**bundled** at `<APP_DIR>\servers\ubuntu-mcp\src\server.py`, 22 tools): one or more Linux hosts over SSH → `UBUNTU_MCP_HOSTS` (`ubuntu_list_hosts`, `ubuntu_test_connection`, `ubuntu_run`, etc.).
- `mikrotik-mcp`: MikroTik RouterOS devices over SSH → `MIKROTIK_INVENTORY`.
- `inventory`: any server built to `SERVER-SPEC.md`; hosts go as inline JSON into the
  variable named by `--inventory-env` (e.g. `PROXMOX_MCP_HOSTS`). New custom servers should use this.
- `generic`: no hosts; plain `--env` variables plus `--secret` variables.

## Common tasks

**Add a server**
1. `templates`, then `list` to reuse existing hosts.
2. `host add …` for any new machine; tell the user to enter its password or agent key in the UI (MCP Vault → Hosts → Edit).
3. For Windows or Linux hosts, use the bundled server by omitting `--command`:
   `server add windows --template windows-mcp --host <name>` (or `--template ubuntu-mcp`).
   For third-party/custom programs, pass `--command <python or exe> --arg <script>`, plus `--secret` for API tokens.
   Keep `<id>` short (letters, digits, `-`, `_`; becomes `mcp__<id>__tool`).
4. After the user enters credentials: `test host <name>` and `test server <id>` must report OK with no warnings.
5. `apply --dry-run`, show it, then `apply` after a yes.
6. Tell the user to reload their client (only needed when adding/removing/renaming a server ID): `/mcp` in Claude Code, restart Claude Desktop / Codex, reload Antigravity, or restart Kimi Work.

**Change a password, agent key or token**: UI only (Hosts → Edit, or Servers → Edit).
No `apply` or client restart needed; running launchers detect the vault revision
change and hot-reload the child server automatically.

**Switch a Windows/Linux server to the bundled server** (e.g. it runs an old or
third-party package such as the 6-tool `win-mcp-server`): `server edit <id> --use-bundled`
(template `windows-mcp` or `ubuntu-mcp`), then `test server <id>`. Hosts, apps and
variables stay; running apps reload it automatically. In the UI: the server card's
**Use bundled** button. `templates` prints the bundled paths and versions.

**Point a server at another machine / enable or disable a host**: `server edit <id> --host <name>` (or
`--add-host`/`--remove-host`, or `host edit <name> --enable|--disable`), `test server <id>`.
Running client apps (Antigravity, Codex, Claude, Kimi) pick up the change automatically with no restart.

**What needs `apply`?** Only adding, removing, renaming, enabling/disabling a
server entry in client configs, or changing which apps it is installed into.
Everything else (hosts, enabling/disabling hosts, passwords, agent keys, arguments,
variables) hot-reloads automatically on running launchers.

## Troubleshooting

Work from the outside in: agent → server process → remote host.

1. **`status`**. Not running or locked explains a whole class of failures. Launchers
   answer startup while locked from `%APPDATA%\mcp-vault\toolcache` and show the
   password window on the first tool call. "MCP Vault is locked, so this server could
   not start" means that window was cancelled or timed out; ask the user to unlock
   and retry.
   "could not start the MCP Vault agent" with `agent.log` repeating "another agent is
   already listening" means a stuck agent (often from an older version or another
   install folder) holds port 47821. Since 0.4.1 a new agent ends such a process
   itself; otherwise run `vault.py stop --force` (Start menu → **Stop MCP Vault**) and
   retry. "used by another program" in `agent.log` means a non-MCP-Vault process owns
   the port: tell the user its PID/command line from the log; do not kill it.
2. **`list`**. Check that the server is enabled, lists the current client under `apps`,
   and has the expected hosts enabled. If the client lacks the server, run
   `apply --dry-run`: a pending change means `apply` was never run.
3. **`test server <id>`** separates server-process issues:
   - `WARNING: ... does not support WinMCP agent` or multi-host warning → the server
     entry points at an older/third-party WinRM-only package (e.g. 6-tool `win-mcp-server`)
     instead of the bundled 21-tool `servers\windows-mcp\src\server.py`. Update its
     command/args to `"$V\.venv\Scripts\python.exe"` and `"$V\servers\windows-mcp\src\server.py"`.
   - `Cannot start: command not found` → runtime moved or missing; fix with `server edit <id> --command ...`.
   - `Handshake failed: server exited` / timeout → read stderr shown (or `logs <id>`).
   - `WARNING non-JSON output on stdout` → server prints to stdout, corrupting JSON-RPC.
4. **Errors from inside a working server** ("WINDOWS_HOST is not set", "no hosts configured",
   "unknown host"): run `show server <id>` to check template, attached hosts, and `false`
   secret flags. "cannot start: its host(s) … are disabled" means hosts were intentionally
   disabled; ask before `host edit <name> --enable`.
5. **`test host <name>`** for remote reachability & auth:
   - `Port … unreachable` → target is off, on another network/VPN, or firewalled (for WinMCP agent, ensure `winmcp-agent.ps1` is running and `-AllowFrom` includes this PC).
   - `WinMCP agent OK: <COMPUTER> v1.1.0` → agent transport and key are verified; any failure is in the MCP server configuration, not the host.
   - `WinMCP agent: bad signature` / `no agent key is set yet` → paste the target's `agent.key` (`winmcp-agent.ps1 -ShowKey`) into MCP Vault → Hosts → Edit → Agent key.
   - `SSH: authentication failed` → fix username/password/key in the UI.
6. Still unclear: read `%APPDATA%\mcp-vault\agent.log` and `logs <id>`.

## Sharing the app

`Make share zip.bat` in the app folder builds `mcp-vault-<version>.zip` from
source files only (including `agent\` and bundled `servers\`, with no vault,
`hosts.json`, logs, backups or `.venv`). The recipient extracts it, double-clicks
`MCP Vault.bat` (installs Python deps, offers Start-menu shortcuts and skills)
and creates their own vault. `vault.py install-skills --force` installs or refreshes
these skills across Claude Code, Kimi Work, Codex and Antigravity.
