# MCP Vault

**One encrypted place for every MCP server's hosts and credentials, on Windows.**

MCP client configs (`~/.claude.json`, `claude_desktop_config.json`,
`~/.codex/config.toml`, `~/.gemini/config/mcp_config.json`, Kimi Work's plugin
manifests) usually hold server passwords and API tokens in plain text, and every
server invents its own way to configure hosts. MCP Vault moves all of that into
one AES-256-GCM vault behind a master password, gives you a local web UI to edit
it, and writes launcher entries into the client configs that contain no secrets
at all.

```
Claude / Codex / Antigravity / Kimi ──starts──> vault.py run windows ──asks──> agent (127.0.0.1, holds unlocked key)
                                                        │                           │ (locked → one password pop-up)
                                                        └──starts real server <─────┘ env: WINDOWS_MCP_HOSTS, ...
```

- Hosts, passwords, agent keys and secret variables in one encrypted file; secrets masked in all logs
- Live updates without restarting your AI app: adding, editing, enabling or disabling hosts reloads affected MCP servers behind the scenes; servers whose hosts are disabled stay registered in standby and wake automatically when enabled
- Web UI on 127.0.0.1: servers, hosts, connection and MCP handshake + compatibility tests, logs, encrypted config backups
- Works with Claude Code, Claude Desktop, Kimi Work, Codex and Antigravity; imports your existing MCP entries, then rewrites them without secrets
- Ships **bundled multi-host MCP servers** in `servers/` (`windows-mcp` with 21 tools over SSH, WinRM or the portable WinMCP Agent; `ubuntu-mcp` with 22 tools over SSH) and works with third-party servers unchanged (`mikrotik-mcp`, any `SERVER-SPEC` or env-var server)
- A command line and two skills (installed for Claude Code, Kimi Work, Codex and Antigravity), so AI agents can inspect, test and manage servers without ever seeing a password
- [SERVER-SPEC.md](SERVER-SPEC.md): a standard for building MCP servers that all behave the same way

**Requirements:** Windows 10/11, Python 3.10+ (offered automatically if missing),
and any of Claude Code, Claude Desktop, Codex, Antigravity or Kimi Work.

## Install and start

**One line** (PowerShell, no admin needed). Run the same line again to update:

```powershell
irm https://raw.githubusercontent.com/ravThirst/mcp-vault/main/install.ps1 | iex
```

It downloads the code into `~\.mcp-servers\mcp-vault` (set `$env:MCPVAULT_DIR`
first for another folder, `$env:MCPVAULT_REF = 'v0.4.0'` for a specific
version), then runs the setup below. Updates replace only the app code (`mcpvault`,
`skills`, `servers`, `agent`); `.venv` and your vault are kept, and installed AI
client skills are refreshed automatically. As with any `irm | iex`, you can read
[install.ps1](install.ps1) first.

**Or manually:** **Code → Download ZIP** on GitHub and extract it anywhere, or
`git clone`. Then double-click **`MCP Vault.bat`**, or use the Start-menu
shortcut it offers to create (the shortcut runs the same file). The first run,
or `"MCP Vault.bat" setup`:

* finds Python 3.10+ (`py -3`, `python`, `python3`), and offers to install
  Python 3.12 with winget if there is none;
* creates `.venv` in the app folder and installs `requirements.txt` (including
  the dependencies for the bundled `windows-mcp` and `ubuntu-mcp` servers);
* rebuilds `.venv` if it is broken (e.g. the folder was copied from another PC);
* offers Start-menu shortcuts (**MCP Vault** and **Stop MCP Vault**) and the two
  skills for every supported client found (Claude Code, Kimi Work, Codex, Antigravity).

Later starts skip all of that and open the UI in your browser.

Files downloaded from the internet carry a "mark of the web", so Windows
SmartScreen may warn about `MCP Vault.bat`: choose *More info → Run anyway*, or
right-click the downloaded ZIP → Properties → *Unblock* before extracting.

**Sharing:** run `Make share zip.bat`. It packs an allowlist of source files
(including `agent/` and `servers/`) into `mcp-vault-<version>.zip`. Vaults,
backups and logs live in `%APPDATA%\mcp-vault` and are never included, and
neither is `.venv`. The recipient extracts the zip anywhere and double-clicks
`MCP Vault.bat`.

## Use

1. **Create** the vault with a master password (it cannot be recovered).
2. **Import** (or **+ Add server**): Import picks up servers already in
   `~/.claude.json`, Claude Desktop's config, `~/.codex/config.toml`,
   `~/.gemini/config/mcp_config.json` and Kimi Work's plugin manifest (including
   hosts in `ubuntu-mcp/hosts.json`). Or add a new `windows-mcp` / `ubuntu-mcp`
   server directly — the bundled server command and script path are filled in
   automatically.
3. **Test** each server (MCP handshake + tool list + protocol compatibility) and
   host (TCP + SSH login or encrypted WinMCP agent ping).
4. **Apply to apps**: replaces plaintext entries with vault launcher entries in
   your selected clients (Claude Code, Claude Desktop, Codex, Antigravity, Kimi
   Work) and refreshes installed agent skills. For Kimi Work it writes a
   `mcp-vault` plugin (`kimi.plugin.json`) and registers it in
   `plugins/installed.json`. Old config files are backed up, encrypted, and can
   be restored from the same tab.
5. Delete leftover plaintext files the importer warns about (e.g. `hosts.json`).

## Command line

`.venv\Scripts\python.exe vault.py <command>` (`<command> --help` for options).
Management commands work through the running, unlocked agent and never read or
write secret values: passwords, agent keys and secret variables are entered in
the window.

| Command | |
| --- | --- |
| `status`, `stop [--force]`, `ui` | agent state / stop it (`--force` also ends unresponsive agents; this is what `Stop MCP Vault.bat` runs) / open the window |
| `list [--json]`, `show server\|host <name>`, `templates` | inspect (secrets only as set/unset; cross-hints if `<name>` is a host vs server) |
| `host add\|edit\|remove <name> ...` | hosts (`remove` needs `--yes`) |
| `server add\|edit\|remove <id> ...` | servers (omit `--command` with `--template windows-mcp\|ubuntu-mcp` to use the bundled server; `--secret NAME` declares a secret entered in the UI) |
| `test server <id>`, `test host <name>` | MCP handshake + tool list + warnings / TCP + SSH login or encrypted WinMCP agent ping |
| `apply [--dry-run]` | write launcher entries into the apps' configs and refresh installed skills |
| `logs <server> [-n N]` | tail a server's log |
| `install-shortcut`, `install-skills [--force]`, `package [dir]` | Start-menu entries, agent skills (Claude Code / Kimi Work / Codex / Antigravity), share zip |

Exit codes: 0 ok, 1 error, 2 usage, 4 agent not running or vault locked.

## Agent skills

`skills/` holds two skills; `vault.py install-skills` (and **Apply to apps**)
copies them to every supported client found on the machine (`~/.claude/skills`
for Claude Code, `%APPDATA%\kimi-desktop\daimon-share\daimon\skills` for Kimi
Work, `~/.codex/skills` for Codex, `~/.gemini/config/skills` for Antigravity):

* **mcp-vault**: the agent locates the vault via `%APPDATA%\mcp-vault\app_dir.txt`,
  checks host connectivity in one step, and operates or troubleshoots the vault
  with the CLI above without ever handling passwords itself.
* **mcp-server-builder**: the agent builds new MCP servers to
  [SERVER-SPEC.md](SERVER-SPEC.md) from a tested template and registers them
  with the `inventory` template.

## Bundled MCP servers (`servers/`)

MCP Vault ships two full multi-host remote-administration MCP servers built to
[SERVER-SPEC.md](SERVER-SPEC.md), ready to run on MCP Vault's own
`.venv\Scripts\python.exe` with no separate environment setup:

* **`servers/windows-mcp`** (`src/server.py`, **21 `win_*` tools**): administers
  one or more remote Windows machines over **SSH** (port 22, SFTP file transfer),
  **WinRM** (ports 5985/5986), or the portable **WinMCP Agent** (port 5990,
  AES-256-CBC + HMAC-SHA256 encrypted RPC). Includes `win_list_hosts`,
  `win_test_connection`, PowerShell & `cmd.exe` execution, directory/file
  read/write/upload/download/search, services, processes, event logs, scheduled
  tasks, installed software, system/disk/network inspection, read-only mode,
  destructive command guards, and confirmed reboot.
* **`servers/ubuntu-mcp`** (`src/server.py`, **22 `ubuntu_*` tools**): administers
  one or more Ubuntu / Linux machines over **SSH** (`ubuntu_list_hosts`,
  `ubuntu_test_connection`, bash execution with optional `sudo`, SFTP file
  operations, `systemd` services, `journalctl`, processes, `apt` packages,
  networking, disks, `ufw` firewall, Docker, read-only mode, and confirmed reboot).

Selecting `windows-mcp` or `ubuntu-mcp` when adding a server in the UI (or
running `vault.py server add <id> --template windows-mcp --host <host>`)
automatically fills in `.venv\Scripts\python.exe` and the bundled `src\server.py`.

## Locking

Opening a client while the vault is locked asks for nothing. Each server's
launcher answers the client's startup questions (handshake, tool list) from a saved
copy of that server's tool list. The copy holds only tool names and
descriptions, never credentials (`%APPDATA%\mcp-vault\toolcache`). The real
server starts only when it is needed:

* the **first tool call** shows the password window; after unlocking, the call
  goes through (if you cancel, the call returns "MCP Vault is locked…" and the
  next call asks again);
* unlocking **any other way** (another server's tool call, the MCP Vault
  window) starts the remaining waiting servers in the background, with no
  further prompts.

The copy is refreshed every time a server runs and by **Test** in the UI. A
server without one yet starts with an empty tool list that fills in once the
vault is unlocked. If a server's tools changed, the client is told to reload them.
`MCPVAULT_EAGER=1` brings back asking at startup.

The vault auto-locks after the idle time set in Settings; servers already
running keep working.

## Templates

| Template | Hosts | What the server receives |
| --- | --- | --- |
| windows-mcp | 1+ Windows hosts (SSH, WinRM or WinMCP agent) | `WINDOWS_MCP_HOSTS` (inline JSON inventory for bundled `servers/windows-mcp`); for a single SSH/WinRM host, also legacy `WINDOWS_HOST`, `WINDOWS_PASSWORD`, … (`agent` hosts omit legacy WinRM vars) |
| ubuntu-mcp | 1+ Linux hosts | `UBUNTU_MCP_HOSTS` (inline JSON inventory for bundled `servers/ubuntu-mcp`) |
| mikrotik-mcp | 1+ MikroTik devices | `MIKROTIK_INVENTORY` (inline JSON inventory) |
| inventory | 1+ hosts of any kind | inline JSON host list in the variable you name (any server built to SERVER-SPEC) |
| generic | none | only the env vars you define (mark tokens as secret) |

New servers built to SERVER-SPEC use *inventory* and need no code here; a
server with its own config format needs a builder in `mcpvault/adapters.py`,
or *generic* with secret env vars.

## Windows remote agent (`agent/`)

For Windows machines where WinRM and OpenSSH Server are unavailable (Windows 10/11
or Windows Server 2016+), `agent/` ships the portable PowerShell 5.1 **WinMCP
agent** (`winmcp-agent.ps1`, `Start WinMCP Agent.bat`, `Stop WinMCP Agent.bat`,
`launch.ps1`). Every request and reply is encrypted (AES-256-CBC) and signed
(HMAC-SHA256) with a shared key that never crosses the wire.

**One-line launch on the target Windows machine** (PowerShell, asks for UAC
elevation if needed):

```powershell
irm https://raw.githubusercontent.com/ravThirst/mcp-vault/main/agent/launch.ps1 | iex
```

It saves the agent scripts to `C:\WinMCP`, generates `agent.key` on first run
(printing it so you can paste it into MCP Vault under **Hosts → Protocol: Agent
→ Agent key**), and starts the agent hidden in the background on TCP `5990` with
a temporary firewall rule (nothing installed; runs until stopped, logoff or
reboot). Run the same command again to update or restart.

Optional settings before running:

```powershell
$env:WINMCP_ALLOW_FROM = '192.168.0.10'  # allowed IPs/subnets, comma-separated (default Any)
$env:WINMCP_PORT       = '34212'         # custom TCP port (default 5990)
$env:WINMCP_INSTALL    = '1'             # install as a SYSTEM scheduled task at every boot
$env:WINMCP_DIR        = 'C:\WinMCP'     # folder for scripts, key and log
$env:WINMCP_SHOW_KEY   = '1'             # print an existing key again
irm https://raw.githubusercontent.com/ravThirst/mcp-vault/main/agent/launch.ps1 | iex
```

**Offline / manual:** copy the [`agent/`](agent) folder to the target machine
(for example `C:\WinMCP`) and double-click **`Start WinMCP Agent.bat`** (or pass
allowed addresses: `"Start WinMCP Agent.bat" 192.168.0.10`), or manage it from
PowerShell:

```powershell
.\winmcp-agent.ps1 -Background -AllowFrom 192.168.0.10  # hidden, temporary firewall rule
.\winmcp-agent.ps1 -Install -AllowFrom 192.168.0.10     # SYSTEM scheduled task at boot
.\winmcp-agent.ps1 -Status                              # check process, task and port
.\winmcp-agent.ps1 -ShowKey                             # print the shared key again
.\winmcp-agent.ps1 -NewKey                              # rotate the key (then restart)
.\winmcp-agent.ps1 -Stop                                # stop agent and close temp firewall rule
.\winmcp-agent.ps1 -Uninstall                           # remove scheduled task and permanent rule
```

## Security model

* `%APPDATA%\mcp-vault\vault.json`: AES-256-GCM. A random data key is wrapped
  with a key derived from the master password (scrypt, N=2^17). Hosts, names
  and addresses are encrypted too. `vault.json.prev` is the previous generation.
* `%APPDATA%\mcp-vault\app_dir.txt`: stores only the plain MCP Vault install
  directory so CLI tools and AI skills can locate `vault.py` without touching
  `agent.json` or `vault.json`.
* The agent listens on 127.0.0.1 only. The UI needs the master password for a
  session cookie (HttpOnly, SameSite=Strict); writes also need a custom header,
  and the Host header is checked, which blocks CSRF and DNS rebinding.
* Launchers authenticate with a random token in `%APPDATA%\mcp-vault\agent.json`.
  Like ssh-agent, **while the vault is unlocked any program running as you can
  ask the agent for a server's credentials**. Auto-lock limits that window; the
  master password protects the file at rest and on backups.
* Secrets are redacted from server logs (`%APPDATA%\mcp-vault\logs`) and test output.
* Back up `vault.json`. Without the password it is useless, to you as well.

## Layout

`vault.py` entry point · `mcpvault/agent.py` HTTP server + API · `launcher.py`
`run` command · `store.py` / `crypto.py` vault file · `adapters.py` templates ·
`clients.py` client configs + backups · `importer.py` · `probe.py` tests ·
`manage.py` CLI · `static/index.html` UI · `servers/windows-mcp` &
`servers/ubuntu-mcp` bundled MCP servers · `agent/` portable Windows remote
agent · `skills/` AI client skills. See also [SERVER-SPEC.md](SERVER-SPEC.md).
