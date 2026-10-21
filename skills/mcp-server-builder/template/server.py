"""Example MCP server built to SERVER-SPEC (template; rename `example` everywhere).

Every tool takes an optional `host` argument naming the target, as listed by
example_list_hosts; it may be omitted when only one host is configured.
"""

from __future__ import annotations

import functools
import re

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from connection import ENV_PREFIX, ConfigError, Inventory, env_bool

__version__ = "0.1.0"

mcp = MCPServer(
    "example",
    version=__version__,
    instructions=(
        "Administers example hosts. Call example_list_hosts to see the hosts and "
        "example_test_connection when anything fails. Write tools are refused when the "
        f"server or host is read-only ({ENV_PREFIX}_MCP_READONLY or the host's readonly flag)."
    ),
)

# Annotations tell clients what needs confirmation. Every tool gets one of these.
READ = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=True)
WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True)
DESTRUCTIVE = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=True)

inventory = Inventory()
READ_ONLY = env_bool("MCP_READONLY")

# Operations refused even outside read-only mode; run them by hand on the box.
BLOCKED = [
    (r"\brm\s+(-[a-z]*\s+)*-[a-z]*r[a-z]*\s+(-[a-z-]+\s+)*(/|/\*)(\s|$)", "recursive delete of /"),
    (r"\bmkfs(\.\w+)?\b", "filesystem format"),
    (r"\bdd\b[^|;&]*\bof=/dev/", "raw write to a disk device"),
]


def _guard(command: str) -> None:
    lowered = " ".join(command.lower().split())
    for pattern, label in BLOCKED:
        if re.search(pattern, lowered):
            raise RuntimeError(f"Refused: this looks like {label}. Run it directly on the host if you really mean it.")


def _require_write(host: str, action: str) -> None:
    if READ_ONLY:
        raise RuntimeError(f"Refused: {action} is a write operation and {ENV_PREFIX}_MCP_READONLY is enabled.")
    cfg = inventory.resolve(host)
    if cfg.readonly:
        raise RuntimeError(f"Refused: {action} is a write operation and host '{cfg.name}' is read-only.")


def _errors(fn):
    """Turn configuration and connection problems into readable tool results."""
    @functools.wraps(fn)  # keeps the signature the SDK turns into the input schema
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ConfigError as exc:
            return f"Configuration error: {exc}"
        except RuntimeError as exc:
            return str(exc)
        except Exception as exc:  # noqa: BLE001 - surfaced for diagnosis
            return f"Failed: {type(exc).__name__}: {exc}"
    return wrapper


# --------------------------------------------------------------------------
# Inventory / connection (every server has these two)
# --------------------------------------------------------------------------


@mcp.tool(annotations=READ)
@_errors
def example_list_hosts() -> str:
    """List the configured hosts (names to pass as `host` to other tools)."""
    hosts = inventory.hosts()
    if not hosts:
        return "No hosts configured."
    lines = []
    for h in hosts:
        flags = ["readonly"] if (h.readonly or READ_ONLY) else []
        flags.append("key" if h.key_file else "password" if h.password else "default keys")
        desc = f" - {h.description}" if h.description else ""
        lines.append(f"{h.name}: {h.username}@{h.host}:{h.port} [{', '.join(flags)}]{desc}")
    return "\n".join(lines)


@mcp.tool(annotations=READ)
@_errors
def example_test_connection(host: str = "") -> str:
    """Verify the connection to a host and report who we are.

    Run this first when something is not working: it separates "cannot reach
    the host" from "the command failed".
    """
    conn = inventory.connection(host)
    try:
        conn.client()
    except Exception as exc:  # noqa: BLE001
        return f"Connection to {conn.describe()} failed: {type(exc).__name__}: {exc}"
    return f"Host: {conn.cfg.name} via {conn.describe()}\n" + conn.run("hostname; id; uname -a").render()


# --------------------------------------------------------------------------
# Domain tools: replace with the real ones
# --------------------------------------------------------------------------


@mcp.tool(annotations=READ)
@_errors
def example_status(host: str = "") -> str:
    """Uptime, load and disk usage of a host."""
    return inventory.connection(host).run("uptime; df -h /").render()


@mcp.tool(annotations=WRITE)
@_errors
def example_run(command: str, host: str = "", timeout_sec: int = 60) -> str:
    """Run a shell command on a host. Refused in read-only mode."""
    _require_write(host, "example_run")
    _guard(command)
    return inventory.connection(host).run(command, timeout_sec).render()


@mcp.tool(annotations=DESTRUCTIVE)
@_errors
def example_reboot(confirm: str, host: str = "") -> str:
    """Reboot a host. `confirm` must equal the host's name, so it cannot happen by accident."""
    cfg = inventory.resolve(host)
    if confirm != cfg.name:
        return f"Refused: pass confirm='{cfg.name}' to reboot {cfg.name}."
    _require_write(host, "example_reboot")
    return inventory.connection(host).run("sudo -n reboot || reboot", 15).render()


if __name__ == "__main__":
    mcp.run()  # stdio; never print() to stdout, it would corrupt the MCP stream
