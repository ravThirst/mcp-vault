---
name: mcp-server-builder
description: Build a new MCP server, or bring an existing one up to standard, following the house SERVER-SPEC, then register it in MCP Vault so its hosts and credentials live in the encrypted vault. Use this whenever the user wants to create, write or scaffold an MCP server or MCP tools for some system (a device, router, hypervisor, NAS, API, app, database, service), wrap a CLI or REST API as MCP tools, add tools to one of their servers in ~/.mcp-servers, or make a server "follow the spec / standard". Also use it for "let Claude control X" or "I want an MCP for X", even when MCP isn't named, as long as the result is a new tool server.
---

# MCP server builder

Goal: every server the user owns behaves the same way. Same layout, same
configuration (hosts from the vault, nothing in plaintext), same safety switches,
same first tools to call when debugging. Then any server can be managed, tested
and troubleshot with one routine (the `mcp-vault` skill), and a new one costs an
hour instead of a day.

The rules come from `SERVER-SPEC.md` in the MCP Vault folder
(`~\.mcp-servers\mcp-vault\SERVER-SPEC.md`); read it if anything below is unclear.
This skill's `template/` folder is the reference implementation; servers the
user already built to the spec (look in `~\.mcp-servers`) are good examples of
their own style.

## 1. Pin down the server before writing code

Ask only what you cannot infer:
- **Target and transport**: SSH, an HTTP/REST API, a vendor API (RouterOS, Proxmox,
  vSphere…), a local program or files?
- **Hosts**: one machine or several? For each: address, port, username, and whether
  auth is a password, a key file or an API token. Don't ask for the secret
  values: they will be typed into the MCP Vault window.
- **Scope**: which read tools, which write tools, and anything destructive? Start
  read-heavy; write tools are added on purpose, not by default.
- **Name and prefix**: a short name (`proxmox`) gives the folder `proxmox-mcp`,
  tool prefix `proxmox_`, env prefix `PROXMOX`.

## 2. Scaffold from the template

The template in this skill's `template/` folder is a complete, working server
(SSH-based) that already meets the spec. Copy, then rename:

```
~\.mcp-servers\<name>-mcp\
  src\server.py        <- template\server.py      (tools only)
  src\connection.py    <- template\connection.py  (inventory, config, transport)
  requirements.txt     <- template\requirements.txt (+ the target's client library)
  README.md            <- template\README.md      (config table, tools, safety)
  server.json          <- template\server.json    (declared env vars, isSecret on credentials)
```

Rename `example` / `EXAMPLE` everywhere: server name, `ENV_PREFIX`, tool names,
README, server.json. For non-SSH targets, keep `Inventory` and replace
`Connection._connect` / `Connection.run` with the target's client (for a REST API:
a `requests.Session` with the token from `cfg.password` and the base URL from
`cfg.host`/`cfg.port`). API tokens travel in the host's `password` field, so they
stay in the vault's encrypted host record.

Create the environment:

```powershell
cd "$HOME\.mcp-servers\<name>-mcp"; python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The template targets MCP Python SDK 2.x (`from mcp.server.mcpserver import MCPServer`,
`@mcp.tool(annotations=ToolAnnotations(read_only_hint=...))`). If the installed SDK
differs, check with `python -c "import inspect, mcp.server.mcpserver as m; print(inspect.signature(m.MCPServer.tool))"`
instead of guessing.

## 3. Rules the code must follow, and why

| Rule | Why |
| --- | --- |
| All settings from env vars `<PREFIX>_*`; hosts as inline JSON in `<PREFIX>_MCP_HOSTS` (file fallback `<PREFIX>_MCP_HOSTS_FILE`), standard host fields | The vault's `inventory` template fills exactly this, with no plaintext anywhere |
| Never put credentials in command-line args, tool results, logs or exception text | Args show in process lists; tool results land in chat transcripts |
| Connect lazily on first tool call; answer `initialize` fast | Clients give a server ~30 s to start; a down host must not break startup |
| Nothing but JSON-RPC on stdout (no `print`); logs to stderr | Stray stdout corrupts the MCP stream; stderr goes to the vault's masked log |
| Every tool takes optional `host`; unknown/missing host errors list the valid names | The model can correct itself in one step |
| Expected failures (bad config, unknown host, refusals, unreachable host) are returned as text or raised as `mcp.server.mcpserver.exceptions.ToolError`, never as plain exceptions | SDK 2.x treats any other exception as a crash and shows the model only "Error executing tool", hiding the message it needs |
| `<prefix>_list_hosts` and `<prefix>_test_connection` exist | Same first debugging step on every server |
| Every tool has annotations: `READ`, `WRITE` or `DESTRUCTIVE` from the template | Clients decide what needs confirmation from these hints |
| `<PREFIX>_MCP_READONLY=true` and per-host `readonly` refuse write tools | One switch to make a server safe to explore with |
| Destructive tools require an explicit confirmation argument (e.g. `confirm=<host name>`); catastrophic commands are blocklisted | Nothing irreversible happens from a misread request |
| `instructions` says what the server does, the first tool to call and its limits | Shown to the model at connect time |
| Tool names `prefix_verb_noun`, docstrings say what and when | Names are the model's main hint, so keep them consistent across servers |

## 4. Verify locally

```powershell
.venv\Scripts\python.exe -c "import sys; sys.path.insert(0, 'src'); import server"
```

An import error here would otherwise surface as a cryptic "connection closed" in Claude.

## 5. Register in MCP Vault and test

Use the `mcp-vault` skill's CLI (`$V = "$HOME\.mcp-servers\mcp-vault"`; `& "$V\.venv\Scripts\python.exe" "$V\vault.py" ...`):

```powershell
vault.py list                                    # reuse existing hosts where possible
vault.py host add <host> --kind linux --address 10.0.0.5 --user admin   # per new machine
vault.py server add <name> --template inventory --inventory-env <PREFIX>_MCP_HOSTS `
    --command "$HOME\.mcp-servers\<name>-mcp\.venv\Scripts\python.exe" `
    --arg "$HOME\.mcp-servers\<name>-mcp\src\server.py" --host <host> --description "..."
```

Then:
1. Tell the user to enter passwords or tokens for new hosts in **MCP Vault → Hosts → Edit**
   (never in chat).
2. `vault.py test server <name>` must say OK, with **annotated N/N**,
   **instructions: yes**, and no stdout warning. Fix and re-test until it does.
3. `vault.py apply --dry-run`, show the user, `vault.py apply` after a yes.
4. Ask the user to reconnect (`/mcp` in Claude Code, or a new session), then call
   `<prefix>_test_connection` yourself as the end-to-end check.

## Bringing an existing server up to spec

Run `vault.py test server <name>` first. It reports annotations, instructions and
stdout noise. Then go through the rules table: usually it needs annotations, a
`_test_connection` tool, a read-only switch and, for multi-host servers, the
inline inventory variable. Keep backwards compatibility (old env vars still
work) unless the user says otherwise, then switch the vault entry to the
`inventory` template and re-test.

## Done means

- [ ] Folder layout as above, `.venv` installed, import check passes
- [ ] README config table matches the env vars; server.json declares them (`isSecret` on credentials)
- [ ] Registered in the vault with no secrets in any file; user entered them in the UI
- [ ] `vault.py test server` OK, all tools annotated, instructions present, no stdout noise
- [ ] Applied, reconnected, `<prefix>_test_connection` succeeds from Claude
