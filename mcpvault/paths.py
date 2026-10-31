"""Filesystem locations used by MCP Vault."""

import os
import sys

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENTRY = os.path.join(APP_DIR, "vault.py")
LAUNCHER_BAT = os.path.join(APP_DIR, "MCP Vault.bat")
STOP_BAT = os.path.join(APP_DIR, "Stop MCP Vault.bat")
STATIC_DIR = os.path.join(APP_DIR, "mcpvault", "static")

DATA_DIR = os.environ.get("MCPVAULT_HOME") or os.path.join(
    os.environ.get("APPDATA") or os.path.expanduser("~"), "mcp-vault"
)
VAULT_FILE = os.path.join(DATA_DIR, "vault.json")
AGENT_FILE = os.path.join(DATA_DIR, "agent.json")
AGENT_LOG = os.path.join(DATA_DIR, "agent.log")
SPAWN_LOCK = os.path.join(DATA_DIR, "agent.spawn")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
LOG_DIR = os.path.join(DATA_DIR, "logs")

PORT = int(os.environ.get("MCPVAULT_PORT", "47821"))

# Kimi Work (kimi-code runtime): plugins register MCP servers through a
# kimi.plugin.json manifest in plugins/managed/<id>/ plus an entry in
# plugins/installed.json. Skills live in the daimon skills folder.
KIMI_HOME = os.environ.get("MCPVAULT_KIMI_HOME") or os.path.join(
    os.environ.get("APPDATA") or os.path.expanduser("~"),
    "kimi-desktop", "daimon-share", "daimon", "runtime", "kimi-code", "home")
KIMI_SKILLS_DIR = os.environ.get("MCPVAULT_KIMI_SKILLS") or os.path.join(
    os.environ.get("APPDATA") or os.path.expanduser("~"),
    "kimi-desktop", "daimon-share", "daimon", "skills")
KIMI_PLUGIN_ID = "mcp-vault"
KIMI_PLUGIN_DIR = os.path.join(KIMI_HOME, "plugins", "managed", KIMI_PLUGIN_ID)
KIMI_MANIFEST = os.path.join(KIMI_PLUGIN_DIR, "kimi.plugin.json")
KIMI_INSTALLED = os.path.join(KIMI_HOME, "plugins", "installed.json")

_VENV_SCRIPTS = os.path.join(APP_DIR, ".venv", "Scripts")


def python_console() -> str:
    """The interpreter MCP clients should start (console subsystem, stdio pipes)."""
    exe = os.path.join(_VENV_SCRIPTS, "python.exe")
    return exe if os.path.exists(exe) else sys.executable


def python_windowed() -> str:
    """The interpreter for background processes (no console window)."""
    exe = os.path.join(_VENV_SCRIPTS, "pythonw.exe")
    if os.path.exists(exe):
        return exe
    alt = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    return alt if os.path.exists(alt) else sys.executable


def ensure_dirs() -> None:
    for d in (DATA_DIR, BACKUP_DIR, LOG_DIR):
        os.makedirs(d, exist_ok=True)
