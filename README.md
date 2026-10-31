# MCP Vault

**One encrypted place for every MCP server's hosts and credentials, on Windows.**

MCP client configs (`~/.claude.json`, `claude_desktop_config.json`, Kimi Work's
plugin manifests) usually hold server passwords and API tokens in plain text,
and every server invents its own way to configure hosts. MCP Vault moves all of
that into one AES-256-GCM vault
behind a master password, gives you a local web UI to edit it, and writes
launcher entries into the client configs that contain no secrets at all.

```
Claude / Kimi Work ──starts──> vault.py run windows ──asks──> agent (127.0.0.1, holds unlocked key)
                                        │                           │ (locked → one password pop-up)
                                        └──starts real server <─────┘ env: WINDOWS_HOST, WINDOWS_PASSWORD, ...
```

- Hosts, passwords, keys and secret variables in one encrypted file; secrets masked in all logs
- Web UI on 127.0.0.1: servers, hosts, connection and MCP handshake tests, logs, encrypted config backups
- Works with Claude Code, Claude Desktop and Kimi Work; imports your existing MCP entries, then rewrites them without secrets
- Works with existing servers unchanged (templates for windows-mcp, ubuntu-mcp, mikrotik-mcp, any env-var server)
- A command line and two skills (Claude Code and Kimi Work), so the agent can manage servers without ever seeing a password
- [SERVER-SPEC.md](SERVER-SPEC.md): a standard for building MCP servers that all behave the same way

**Requirements:** Windows 10/11, Python 3.10+ (offered automatically if missing),
Claude Code, Claude Desktop and/or Kimi Work.

## Install and start

**One line** (PowerShell, no admin needed). Run the same line again to update:

```powershell
irm https://raw.githubusercontent.com/ravThirst/mcp-vault/main/install.ps1 | iex
```

It downloads the code into `~\.mcp-servers\mcp-vault` (set `$env:MCPVAULT_DIR`
first for another folder, `$env:MCPVAULT_REF = 'v0.2.0'` for a specific
version), then runs the setup below. Updates replace only the app code; `.venv`
and your vault are kept. As with any `irm | iex`, you can read
[install.ps1](install.ps1) first.

**Or manually:** **Code → Download ZIP** on GitHub and extract it anywhere, or
`git clone`. Then double-click **`MCP Vault.bat`**, or use the Start-menu
shortcut it offers to create (the shortcut runs the same file). The first run,
or `"MCP Vault.bat" setup`:

* finds Python 3.10+ (`py -3`, `python`, `python3`), and offers to install
  Python 3.12 with winget if there is none;
* creates `.venv` in the app folder and installs `requirements.txt`;
* rebuilds `.venv` if it is broken (e.g. the folder was copied from another PC);
* offers Start-menu shortcuts (**MCP Vault** and **Stop MCP Vault**) and the two
  skills for every supported client found (Claude Code, Kimi Work).

Later starts skip all of that and open the UI in your browser.

Files downloaded from the internet carry a "mark of the web", so Windows
SmartScreen may warn about `MCP Vault.bat`: choose *More info → Run anyway*, or
right-click the downloaded ZIP → Properties → *Unblock* before extracting.

**Sharing:** run `Make share zip.bat`. It packs an allowlist of source files
into `mcp-vault-<version>.zip`. Vaults, backups and logs live in
`%APPDATA%\mcp-vault` and are never included, and neither is `.venv`. The
recipient extracts the zip anywhere and double-clicks `MCP Vault.bat`.

## Use

1. **Create** the vault with a master password (it cannot be recovered).
2. **Import**: picks up the servers already in `~/.claude.json`, Claude
   Desktop's config and the vault's Kimi Work plugin manifest, including the
   hosts in `ubuntu-mcp/hosts.json`.
3. **Test** each server (MCP handshake + tool list) and host (TCP + SSH login).
4. **Apply to apps**: replaces the plaintext entries with launcher entries. For
   Kimi Work it writes a `mcp-vault` plugin (`kimi.plugin.json` with one
   launcher entry per server) and registers it in `plugins/installed.json`;
   restart Kimi Work afterwards. The old files are backed up, encrypted, and
   can be restored from the same tab.
5. Delete leftover plaintext files the importer warns about (e.g. `hosts.json`).

## Command line

`.venv\Scripts\python.exe vault.py <command>` (`<command> --help` for options).
Management commands work through the running, unlocked agent and never read or
write secret values: passwords and secret variables are entered in the window.

| Command | |
| --- | --- |
| `status`, `stop [--force]`, `ui` | agent state / stop it (`--force` also ends unresponsive agents; this is what `Stop MCP Vault.bat` runs) / open the window |
| `list [--json]`, `show server\|host <name>`, `templates` | inspect (secrets only as set/unset) |
| `host add\|edit\|remove <name> ...` | hosts (`remove` needs `--yes`) |
| `server add\|edit\|remove <id> ...` | servers; `--secret NAME` declares a secret whose value goes in the UI |
| `test server <id>`, `test host <name>` | MCP handshake + tool list / TCP + SSH login |
| `apply [--dry-run]` | write launcher entries into the apps' configs |
| `logs <server> [-n N]` | tail a server's log |
| `install-shortcut`, `install-skills [--force]`, `package [dir]` | Start-menu entries, agent skills (Claude Code / Kimi Work), share zip |

Exit codes: 0 ok, 1 error, 2 usage, 4 agent not running or vault locked.

## Agent skills

`skills/` holds two skills; `vault.py install-skills` copies them to every
supported client found on the machine (`~/.claude/skills` for Claude Code,
`%APPDATA%\kimi-desktop\daimon-share\daimon\skills` for Kimi Work):

* **mcp-vault**: the agent operates and troubleshoots the vault with the CLI
  above, and never handles passwords itself.
* **mcp-server-builder**: the agent builds new MCP servers to
  [SERVER-SPEC.md](SERVER-SPEC.md) from a tested template and registers them
  with the `inventory` template.

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
| windows-mcp | 1+ Windows hosts (SSH or WinRM) | `WINDOWS_MCP_HOSTS` (inline JSON inventory); with one host also the original `WINDOWS_HOST`, `WINDOWS_PASSWORD`, … for windows-mcp before 2.0 |
| ubuntu-mcp | 1+ Linux hosts | `UBUNTU_MCP_HOSTS` (inline JSON inventory) |
| mikrotik-mcp | 1+ MikroTik devices | `MIKROTIK_INVENTORY` (inline JSON inventory) |
| inventory | 1+ hosts of any kind | inline JSON host list in the variable you name (any server built to SERVER-SPEC) |
| generic | none | only the env vars you define (mark tokens as secret) |

New servers built to SERVER-SPEC use *inventory* and need no code here; a
server with its own config format needs a builder in `mcpvault/adapters.py`,
or *generic* with secret env vars.

## Security model

* `%APPDATA%\mcp-vault\vault.json`: AES-256-GCM. A random data key is wrapped
  with a key derived from the master password (scrypt, N=2^17). Hosts, names
  and addresses are encrypted too. `vault.json.prev` is the previous generation.
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
`static/index.html` UI. See also [SERVER-SPEC.md](SERVER-SPEC.md).
