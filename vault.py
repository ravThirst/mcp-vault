"""MCP Vault entry point.

    vault.py ui            open the web UI (starts the agent if needed)
    vault.py agent         run the agent in the foreground
    vault.py run <server>  launch a vault-managed MCP server (used by MCP clients)
    vault.py status        show whether the agent is running and unlocked
    vault.py stop          stop the agent
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcpvault.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
