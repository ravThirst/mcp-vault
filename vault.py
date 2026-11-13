"""MCP Vault entry point.

    vault.py ui                     open the web UI (starts the agent if needed)
    vault.py status                 show whether the agent is running and unlocked
    vault.py stop [--force]         stop the agent
    vault.py list [--json]          list all servers and hosts (no secrets)
    vault.py show server|host <id>  inspect one server or host as JSON (no secrets)
    vault.py templates [--json]     list server templates and their host kinds
    vault.py host add|edit|remove   manage hosts (passwords/keys stay in the UI)
    vault.py server add|edit|remove manage servers (auto-fills bundled windows-mcp/ubuntu-mcp)
    vault.py test server <id>       MCP handshake + tools/list + compatibility warnings
    vault.py test host <name>       TCP + SSH login or encrypted WinMCP agent ping
    vault.py apply [--dry-run]      write launcher entries into AI client configs
    vault.py logs <server> [-n N]   tail a server's redacted stderr log
    vault.py run <server>           launch a vault-managed MCP server (used by MCP clients)
    vault.py agent                  run the agent in the foreground
    vault.py install-skills         install mcp-vault skills into detected AI clients
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcpvault.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
