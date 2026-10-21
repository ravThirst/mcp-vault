# example-mcp

MCP server for administering example hosts. Built to SERVER-SPEC (MCP Vault).

## Configuration

Normally managed by MCP Vault (template **inventory**, inventory variable
`EXAMPLE_MCP_HOSTS`): add the hosts in the vault and the server receives them
at start. All settings are environment variables:

| Variable | Required | Meaning |
| --- | --- | --- |
| `EXAMPLE_MCP_HOSTS` | yes* | Inline JSON host list: `{"hosts": [{"name", "host", "port", "username", "password" or "key_file", "sudo_password", "readonly", "description"}]}` |
| `EXAMPLE_MCP_HOSTS_FILE` | yes* | Path to a file in the same format (*one of the two; inline wins) |
| `EXAMPLE_MCP_READONLY` | no | `true` refuses every write tool |

## Tools

| Tool | Kind | Notes |
| --- | --- | --- |
| `example_list_hosts` | read | names to pass as `host` |
| `example_test_connection` | read | run first when debugging |
| `example_status` | read | |
| `example_run` | write | blocklist applies; refused when read-only |
| `example_reboot` | destructive | needs `confirm=<host name>` |

## Safety

- Read-only mode (global or per host) refuses write tools.
- Blocked outright: recursive delete of `/`, filesystem formats, raw disk writes.
- Credentials never appear in tool results or logs.

## Development

```powershell
python -m venv .venv; .venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -c "import sys; sys.path.insert(0, 'src'); import server"
```
