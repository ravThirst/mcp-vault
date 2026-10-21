# Requirements for MCP servers managed by MCP Vault

What every server (own or third-party) should meet so it can be managed,
tested and secured the same way. "Test" in MCP Vault checks the items marked ✓.

## 1. Configuration
- All settings come from environment variables; no hidden config files.
- Credentials are never passed as command-line arguments (they show in process lists).
- Servers that talk to machines accept an **inline JSON inventory** in
  `<PREFIX>_MCP_HOSTS` (file fallback `<PREFIX>_MCP_HOSTS_FILE`), so no plaintext
  file is needed. Host objects use the same field names: `name`, `host`, `port`,
  `username`, `password` or `key_file`, `sudo_password`, `readonly`, `description`
  (MCP Vault also adds `kind`, plus `protocol` for Windows hosts). API tokens go in
  `password`. MCP Vault's `inventory` template fills this variable, so a new
  server needs no vault code.
- Tools that target a host take a `host`/`device` argument; unknown names return an
  error that lists the valid ones.
- Ship a `server.json` (official MCP Registry format) that declares every env var,
  with `isSecret` on credentials.

## 2. Lifecycle
- ✓ Answers `initialize` within 2 s; connects to remote hosts lazily, on the first tool call.
- ✓ Reports `serverInfo.name` and `serverInfo.version`.
- ✓ Writes nothing but JSON-RPC to stdout; logs go to stderr.
- Never logs credentials, including in validation errors.
- Exits cleanly when stdin closes.
- Has a connection-test tool (`*_test_connection` / `*_ping`) for debugging.

## 3. Tools
- Names follow `prefix_verb_noun` (`win_service_control`, `fl_set_tempo`).
- Every tool has an input schema; tools that return data also declare an output schema.
- ✓ Every tool declares annotations: `readOnlyHint`, `destructiveHint`,
  `idempotentHint`. Clients use them to decide what needs confirmation.
- ✓ Provides `instructions` describing requirements and limits.

## 4. Safety
- A read-only switch (`*_READONLY=true`) that refuses every write tool.
- Destructive operations need an explicit confirmation argument or support
  dry-run / rollback (as fl-studio's `set_dry_run` and mikrotik's safe mode do).
- Hard-blocks operations that should never run unattended (disk wipes, account deletion).
