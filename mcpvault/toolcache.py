"""Each server's saved MCP handshake: its `initialize` result and tool list.

While the vault is locked, the launcher answers a client's startup questions
(initialize, tools/list) from this copy, so opening Claude does not ask for the
master password; the real server starts on the first tool call. The copy holds
only what a server advertises to every client (names, descriptions, schemas),
never credentials. It is refreshed on every normal run and by the UI's Test.
"""

import json
import os

from . import paths
from .store import atomic_write

CACHE_DIR = os.path.join(paths.DATA_DIR, "toolcache")


def _path(server_id: str) -> str | None:
    from .model import ID_RE

    return os.path.join(CACHE_DIR, f"{server_id}.json") if ID_RE.match(server_id) else None


def load(server_id: str) -> dict | None:
    path = _path(server_id)
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if isinstance(data.get("initialize"), dict) and isinstance(data.get("tools"), list):
        return data
    return None


def save(server_id: str, initialize: dict, tools: list) -> bool:
    """Store the handshake; returns True if it differed from the saved one."""
    path = _path(server_id)
    if not path:
        return False
    data = {"initialize": initialize, "tools": tools}
    old = load(server_id)
    if old and old.get("initialize") == initialize and old.get("tools") == tools:
        return False
    os.makedirs(CACHE_DIR, exist_ok=True)
    atomic_write(path, json.dumps(data, ensure_ascii=False, indent=1).encode("utf-8"))
    return True


def remove(server_id: str) -> None:
    path = _path(server_id)
    if path:
        try:
            os.remove(path)
        except OSError:
            pass
