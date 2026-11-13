"""MCP server for administering remote Ubuntu machines over SSH.

Exposes shell execution plus targeted tools for the things you actually do on
an Ubuntu box: files, systemd services, the journal, processes, packages,
networking, disks, firewall and Docker.

Several hosts can be configured (see README.md); every tool takes an optional
`host` argument naming the target, as listed by ubuntu_list_hosts. It may be
omitted when only one host is configured. Connections are opened lazily, so the
server registers cleanly even when a host is unreachable.
"""

from __future__ import annotations

import re
import shlex

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from mcp.types import ToolAnnotations

from connection import ConfigError, Inventory, SSHConnection, env_bool

__version__ = "1.1.0"

mcp = MCPServer(
    "ubuntu",
    version=__version__,
    instructions=(
        "Administers Ubuntu/Linux hosts over SSH. Call ubuntu_list_hosts to see the configured hosts "
        "(pass one as `host` when there are several) and ubuntu_test_connection when anything fails. "
        "Write tools are refused when UBUNTU_MCP_READONLY is set or the host is marked readonly. "
        "Wiping disks, deleting / and similar are blocked outright; ubuntu_reboot needs an explicit "
        "host and confirm=true."
    ),
)

# Annotations tell clients which tools need confirmation. Tools that mix reads and
# writes (packages, services) are annotated for the strongest thing they can do.
READ = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=True)
WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True)
DESTRUCTIVE = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=True)

inventory = Inventory()

GLOBAL_READ_ONLY = env_bool("UBUNTU_MCP_READONLY")

# Patterns that would take the server down or destroy data wholesale. These are
# refused even outside read-only mode; run them from a real session instead.
BLOCKED = [
    (r"\brm\s+(-[a-z]*\s+)*-[a-z]*r[a-z]*\s+(-[a-z-]+\s+)*(/|/\*|--no-preserve-root)(\s|$)", "recursive delete of /"),
    (r"--no-preserve-root", "rm --no-preserve-root"),
    (r"\bmkfs(\.\w+)?\b", "filesystem format"),
    (r"\bdd\b[^|;&]*\bof=/dev/(sd|vd|xvd|nvme|hd|mmcblk)", "raw write to a disk device"),
    (r">\s*/dev/(sd|vd|xvd|nvme|hd|mmcblk)\w*", "raw write to a disk device"),
    (r"\bwipefs\b", "filesystem signature wipe"),
    (r"\b(shred|blkdiscard)\b[^|;&]*/dev/", "disk wipe"),
    (r":\(\)\s*\{\s*:\|:&\s*\};:", "fork bomb"),
    (r"\bchmod\s+(-[a-z]+\s+)*-R\s+[0-7]{3,4}\s+/(\s|$)", "recursive chmod of /"),
    (r"\bchown\s+(-[a-z]+\s+)*-R\s+\S+\s+/(\s|$)", "recursive chown of /"),
    (r"\buserdel\b[^|;&]*\broot\b", "root account deletion"),
]


def conn(host: str) -> SSHConnection:
    return inventory.connection(host)


def _remote(host: str, method: str, *args, **kwargs):
    """Call a connection method, reporting failures to the model as readable tool errors.

    The SDK shows the model only ToolError messages; any other exception is
    treated as a crash and reaches it as a bare "Error executing tool".
    """
    c = conn(host)
    try:
        return getattr(c, method)(*args, **kwargs)
    except ToolError:
        raise
    except Exception as exc:  # noqa: BLE001 - connection and remote failures
        raise ToolError(f"host '{c.cfg.name}': {type(exc).__name__}: {exc}") from exc


def _guard(script: str) -> None:
    lowered = " ".join(script.lower().split())
    for pattern, label in BLOCKED:
        if re.search(pattern, lowered):
            raise ToolError(
                f"Refused: this looks like {label}. The MCP server blocks it outright - "
                "run it directly on the server if you really intend to."
            )


def _require_write(host: str, action: str) -> None:
    if GLOBAL_READ_ONLY:
        raise ToolError(
            f"Refused: {action} is a write operation and UBUNTU_MCP_READONLY is enabled."
        )
    cfg = inventory.resolve(host)
    if cfg.readonly:
        raise ToolError(
            f"Refused: {action} is a write operation and host '{cfg.name}' is marked readonly "
            "in the inventory."
        )


def _sh(host: str, script: str, timeout_sec: int = 120, sudo: bool = False, working_dir: str = "") -> str:
    return _remote(host, "run", script, timeout_sec, sudo=sudo, working_dir=working_dir).render()


def _can_sudo(host: str) -> bool:
    """Whether read-only tools should elevate: root, or a sudo password is known."""
    cfg = inventory.resolve(host)
    return cfg.username == "root" or bool(cfg.sudo_password)


q = shlex.quote


# --------------------------------------------------------------------------
# Inventory / connection
# --------------------------------------------------------------------------


@mcp.tool(annotations=READ)
def ubuntu_list_hosts() -> str:
    """List the configured Ubuntu hosts (names to pass as `host` to other tools)."""
    try:
        hosts = inventory.hosts()
    except ConfigError as exc:
        return f"Configuration error: {exc}"
    if not hosts:
        return "No hosts configured."
    lines = []
    for h in hosts:
        flags = []
        if h.readonly or GLOBAL_READ_ONLY:
            flags.append("readonly")
        flags.append("key" if h.key_file else "password" if h.password else "agent/default keys")
        desc = f" - {h.description}" if h.description else ""
        lines.append(f"{h.name}: {h.username}@{h.host}:{h.port} [{', '.join(flags)}]{desc}")
    return "\n".join(lines)


@mcp.tool(annotations=READ)
def ubuntu_test_connection(host: str = "") -> str:
    """Verify the SSH connection to a host and report identity, OS and sudo access.

    Run this first when something is not working - it separates "cannot reach
    the host" from "the command failed".
    """
    try:
        c = conn(host)
        c.client()
    except ConfigError as exc:
        return f"Configuration error: {exc}"
    except Exception as exc:  # noqa: BLE001 - surfaced verbatim for diagnosis
        return f"Connection failed: {type(exc).__name__}: {exc}"

    res = c.run(
        'echo "Hostname: $(hostname -f 2>/dev/null || hostname)"\n'
        'echo "User: $(id -un) ($(id))"\n'
        '. /etc/os-release 2>/dev/null; echo "OS: ${PRETTY_NAME:-unknown}"\n'
        'echo "Kernel: $(uname -r)"\n'
        'echo "Uptime: $(uptime -p 2>/dev/null)"',
        30,
    )
    sudo = c.run("id -un", 30, sudo=True)
    sudo_line = (
        "Sudo: yes (root)" if c.is_root
        else "Sudo: OK" if sudo.ok and sudo.stdout.strip() == "root"
        else f"Sudo: FAILED - {(sudo.stderr or sudo.stdout).strip()[:200]}"
    )
    mode = " [READ-ONLY MODE]" if (GLOBAL_READ_ONLY or c.cfg.readonly) else ""
    return f"Host: {c.cfg.name} via {c.describe()}{mode}\n\n{res.render()}\n{sudo_line}"


# --------------------------------------------------------------------------
# Command execution
# --------------------------------------------------------------------------


@mcp.tool(annotations=DESTRUCTIVE)
def ubuntu_run(command: str, host: str = "", sudo: bool = False, timeout_sec: int = 120, working_dir: str = "") -> str:
    """Run a bash script on a remote Ubuntu host and return its output.

    This is the general-purpose escape hatch: use it for anything the more
    specific tools do not cover. Multi-line scripts are fine.

    Args:
        command: Bash to execute.
        host: Target host name (see ubuntu_list_hosts); optional with one host.
        sudo: Run the whole script as root via sudo.
        timeout_sec: Give up after this many seconds (default 120).
        working_dir: Optional directory to run from.
    """
    _guard(command)
    if GLOBAL_READ_ONLY or inventory.resolve(host).readonly:
        # Read-only hosts still allow ad-hoc commands without sudo, since most
        # diagnostics need them; privilege escalation is what gets blocked.
        if sudo:
            _require_write(host, "sudo")
    return _sh(host, command, timeout_sec, sudo=sudo, working_dir=working_dir)


# --------------------------------------------------------------------------
# System information
# --------------------------------------------------------------------------


@mcp.tool(annotations=READ)
def ubuntu_system_info(host: str = "") -> str:
    """Report OS, kernel, CPU, memory, load, uptime and virtualization for a host."""
    return _sh(
        host,
        '. /etc/os-release; echo "OS:        $PRETTY_NAME"\n'
        'echo "Hostname:  $(hostname -f 2>/dev/null || hostname)"\n'
        'echo "Kernel:    $(uname -srm)"\n'
        'echo "Virt:      $(systemd-detect-virt 2>/dev/null || echo unknown)"\n'
        'echo "Uptime:    $(uptime -p)  (since $(uptime -s))"\n'
        'echo "Load:      $(cut -d" " -f1-3 /proc/loadavg)"\n'
        'echo "CPU:       $(nproc) x $(grep -m1 "model name" /proc/cpuinfo | cut -d: -f2 | sed "s/^ *//")"\n'
        'echo "Timezone:  $(timedatectl show -p Timezone --value 2>/dev/null)"\n'
        'echo; free -h\n'
        'echo; echo "Reboot required: $( [ -f /var/run/reboot-required ] && echo YES || echo no )"',
        60,
    )


@mcp.tool(annotations=READ)
def ubuntu_disk_usage(host: str = "", path: str = "", depth: int = 1) -> str:
    """Show filesystem usage; with `path`, also the largest subdirectories under it.

    Args:
        path: Optional directory to break down with `du` (e.g. /var).
        depth: du depth when `path` is given (default 1).
    """
    script = "df -hT -x tmpfs -x devtmpfs -x squashfs -x overlay\necho; lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS 2>/dev/null || lsblk"
    if path:
        script += f"\necho; echo '== largest under {path} =='; du -xh --max-depth={int(depth)} -- {q(path)} 2>/dev/null | sort -rh | head -30"
    return _sh(host, script, 180, sudo=bool(path) and _can_sudo(host))


@mcp.tool(annotations=READ)
def ubuntu_network_info(host: str = "", include_listening_ports: bool = True) -> str:
    """Show interfaces, addresses, routes, DNS and (optionally) listening ports."""
    script = (
        "ip -br addr\necho; ip route\necho; echo '== DNS =='; "
        "(resolvectl dns 2>/dev/null || grep nameserver /etc/resolv.conf)"
    )
    if include_listening_ports:
        script += "\necho; echo '== listening =='; ss -tulpnH | sort -k5"
    return _sh(host, script, 60, sudo=include_listening_ports and _can_sudo(host))


# --------------------------------------------------------------------------
# Files
# --------------------------------------------------------------------------


@mcp.tool(annotations=READ)
def ubuntu_list_dir(path: str, host: str = "", show_hidden: bool = True, sudo: bool = False) -> str:
    """List a directory with permissions, owner, size and modification time."""
    flags = "-lah" if show_hidden else "-lh"
    return _sh(host, f"ls {flags} --time-style=long-iso -- {q(path)}", 60, sudo=sudo)


@mcp.tool(annotations=READ)
def ubuntu_read_file(path: str, host: str = "", max_lines: int = 500, tail: bool = False, sudo: bool = False) -> str:
    """Read a text file (the first or last `max_lines` lines).

    Args:
        tail: Read from the end instead - useful for logs.
        sudo: Read as root (e.g. /etc/shadow-protected configs, /var/log/*).
    """
    tool = "tail" if tail else "head"
    return _sh(host, f"{tool} -n {int(max_lines)} -- {q(path)}", 60, sudo=sudo)


@mcp.tool(annotations=WRITE)
def ubuntu_write_file(path: str, content: str, host: str = "", append: bool = False, sudo: bool = False, backup: bool = True) -> str:
    """Write (or append) text to a file on the host.

    Args:
        append: Append instead of overwriting.
        sudo: Write as root (needed for most files under /etc).
        backup: When overwriting an existing file, copy it to <path>.bak first.
    """
    _require_write(host, "writing a file")
    import base64

    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    p = q(path)
    redirect = ">>" if append else ">"
    script = f"mkdir -p -- \"$(dirname -- {p})\"\n"
    if backup and not append:
        script += f"[ -f {p} ] && cp -a -- {p} {q(path + '.bak')} && echo 'Backup: {path}.bak'\n"
    script += f"printf %s {encoded} | base64 -d {redirect} {p} && echo \"Wrote $(stat -c %s -- {p}) bytes to {path}\""
    return _sh(host, script, 60, sudo=sudo)


@mcp.tool(annotations=WRITE)
def ubuntu_upload_file(local_path: str, remote_path: str, host: str = "") -> str:
    """Copy a local file to the host over SFTP (as the SSH user)."""
    _require_write(host, "uploading a file")
    return _remote(host, "upload", local_path, remote_path)


@mcp.tool(annotations=WRITE)
def ubuntu_download_file(remote_path: str, local_path: str, host: str = "") -> str:
    """Copy a file from the host to this machine over SFTP (as the SSH user)."""
    return _remote(host, "download", remote_path, local_path)


@mcp.tool(annotations=READ)
def ubuntu_search_files(
    path: str,
    host: str = "",
    name_pattern: str = "",
    content_pattern: str = "",
    max_results: int = 200,
    sudo: bool = False,
) -> str:
    """Find files by name glob and/or grep their contents.

    Args:
        path: Directory to search.
        name_pattern: Filename glob, e.g. '*.conf'.
        content_pattern: Extended regex to match inside files (grep -E).
    """
    n = int(max_results)
    if content_pattern:
        include = f"--include={q(name_pattern)} " if name_pattern else ""
        script = f"grep -rIEn {include}-- {q(content_pattern)} {q(path)} 2>/dev/null | head -n {n}"
    else:
        name = f"-name {q(name_pattern)} " if name_pattern else ""
        script = f"find {q(path)} -xdev {name}2>/dev/null | head -n {n}"
    return _sh(host, script, 180, sudo=sudo)


# --------------------------------------------------------------------------
# systemd services and logs
# --------------------------------------------------------------------------


@mcp.tool(annotations=READ)
def ubuntu_services(host: str = "", name_filter: str = "", state: str = "") -> str:
    """List systemd services.

    Args:
        name_filter: Substring to match in the unit name.
        state: Optional filter: running, failed, exited, inactive, enabled, disabled.
    """
    state = state.strip().lower()
    if state in ("enabled", "disabled"):
        script = f"systemctl list-unit-files --type=service --no-legend --state={state}"
    else:
        st = f"--state={q(state)} " if state else "--all "
        script = f"systemctl list-units --type=service --no-legend {st}"
    if name_filter:
        script += f" | grep -i -- {q(name_filter)}"
    return _sh(host, script, 60)


@mcp.tool(annotations=WRITE)
def ubuntu_service_control(name: str, action: str, host: str = "") -> str:
    """Control a systemd service.

    Args:
        name: Unit name, e.g. nginx or nginx.service.
        action: status, start, stop, restart, reload, enable, disable,
            enable-now, disable-now, is-active, daemon-reload.
    """
    action = action.strip().lower()
    unit = q(name)
    if action in ("status", "is-active", "is-enabled"):
        return _sh(host, f"systemctl {action} --no-pager -l {unit}", 60)
    _require_write(host, f"service {action}")
    if action == "daemon-reload":
        cmd = "systemctl daemon-reload"
    elif action in ("start", "stop", "restart", "reload", "enable", "disable"):
        cmd = f"systemctl {action} {unit}"
    elif action == "enable-now":
        cmd = f"systemctl enable --now {unit}"
    elif action == "disable-now":
        cmd = f"systemctl disable --now {unit}"
    else:
        return f"Unknown action '{action}'."
    return _sh(host, f"{cmd}; rc=$?; systemctl status --no-pager -n 5 {unit} 2>/dev/null; exit $rc", 120, sudo=True)


@mcp.tool(annotations=READ)
def ubuntu_journal(
    host: str = "",
    unit: str = "",
    lines: int = 100,
    since: str = "",
    priority: str = "",
    grep: str = "",
    kernel: bool = False,
) -> str:
    """Read the systemd journal.

    Args:
        unit: Limit to one unit, e.g. nginx.service.
        lines: Number of most recent lines (default 100).
        since: e.g. '1 hour ago', 'today', '2026-09-28 10:00'.
        priority: Max priority: emerg, alert, crit, err, warning, notice, info, debug.
        grep: Regex filter on the message.
        kernel: Kernel messages only (like dmesg).
    """
    args = [f"-n {int(lines)}", "--no-pager", "-o short-iso"]
    if unit:
        args.append(f"-u {q(unit)}")
    if since:
        args.append(f"--since {q(since)}")
    if priority:
        args.append(f"-p {q(priority)}")
    if grep:
        args.append(f"-g {q(grep)}")
    if kernel:
        args.append("-k")
    return _sh(host, "journalctl " + " ".join(args), 120, sudo=_can_sudo(host))


# --------------------------------------------------------------------------
# Processes
# --------------------------------------------------------------------------


@mcp.tool(annotations=READ)
def ubuntu_processes(host: str = "", name_filter: str = "", sort_by: str = "cpu", top: int = 30) -> str:
    """List processes sorted by cpu or mem.

    Args:
        name_filter: Substring to match in the command line.
        sort_by: 'cpu' or 'mem'.
        top: Number of rows (default 30).
    """
    key = "-%mem" if sort_by.lower().startswith("mem") else "-%cpu"
    script = f"ps -eo pid,ppid,user,%cpu,%mem,rss,etime,stat,args --sort={key} --cols 300"
    if name_filter:
        script += f" | awk -v f={q(name_filter.lower())} 'NR==1 || index(tolower($0), f)' | grep -v 'awk -v f='"
    script += f" | head -n {int(top) + 1}"
    return _sh(host, script, 60)


@mcp.tool(annotations=DESTRUCTIVE)
def ubuntu_kill_process(pid: int, host: str = "", signal: str = "TERM") -> str:
    """Send a signal (default TERM) to a process by PID."""
    _require_write(host, "killing a process")
    if int(pid) <= 1:
        return "Refused: will not signal PID 0 or 1."
    return _sh(host, f"ps -o pid,user,args -p {int(pid)}; kill -s {q(signal)} {int(pid)} && echo 'Sent SIG{signal}'", 30, sudo=True)


# --------------------------------------------------------------------------
# Packages
# --------------------------------------------------------------------------


@mcp.tool(annotations=DESTRUCTIVE)
def ubuntu_packages(action: str, host: str = "", names: str = "", timeout_sec: int = 900) -> str:
    """Query or manage apt packages.

    Args:
        action: installed (optionally filtered by `names`), search, show,
            upgradable, update, install, remove, purge, upgrade, autoremove.
        names: Space-separated package names or search term.
    """
    action = action.strip().lower()
    pkgs = " ".join(q(n) for n in names.split())
    if action == "installed":
        script = "dpkg-query -W -f='${Package}\\t${Version}\\t${Status}\\n' | grep 'install ok installed' | cut -f1,2"
        if names:
            script += f" | grep -iE -- {q('|'.join(names.split()))}"
        return _sh(host, script, 60)
    if action == "search":
        return _sh(host, f"apt-cache search -- {q(names)} | head -n 100", 60)
    if action == "show":
        return _sh(host, f"apt-cache policy {pkgs}; echo; apt-cache show --no-all-versions {pkgs}", 60)
    if action == "upgradable":
        return _sh(host, "apt list --upgradable 2>/dev/null", 60)

    _require_write(host, f"apt {action}")
    apt = "apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
    if action == "update":
        cmd = "apt-get update -q"
    elif action in ("install", "remove", "purge"):
        if not pkgs:
            return "Pass `names` for this action."
        cmd = f"{apt} {action} {pkgs}"
    elif action == "upgrade":
        cmd = f"apt-get update -q && {apt} upgrade"
    elif action == "autoremove":
        cmd = f"{apt} autoremove"
    else:
        return f"Unknown action '{action}'."
    return _sh(host, cmd, int(timeout_sec), sudo=True)


# --------------------------------------------------------------------------
# Firewall, Docker, users
# --------------------------------------------------------------------------


@mcp.tool(annotations=READ)
def ubuntu_firewall_status(host: str = "") -> str:
    """Show UFW status and rules (falls back to nftables/iptables if UFW is absent)."""
    return _sh(
        host,
        "if command -v ufw >/dev/null; then ufw status verbose; echo; ufw status numbered; "
        "else echo 'ufw not installed'; fi\n"
        "echo; echo '== nftables =='; nft list ruleset 2>/dev/null | head -150 || iptables -S",
        60,
        sudo=True,
    )


@mcp.tool(annotations=READ)
def ubuntu_docker(host: str = "", show_all: bool = True, include_images: bool = False) -> str:
    """Show Docker containers (and optionally images, compose projects)."""
    a = "-a " if show_all else ""
    script = (
        "command -v docker >/dev/null || { echo 'docker not installed'; exit 0; }\n"
        f"docker ps {a}--format 'table {{{{.Names}}}}\\t{{{{.Image}}}}\\t{{{{.Status}}}}\\t{{{{.Ports}}}}'\n"
        "echo; docker compose ls 2>/dev/null"
    )
    if include_images:
        script += "\necho; docker images --format 'table {{.Repository}}:{{.Tag}}\\t{{.Size}}\\t{{.CreatedSince}}'"
    return _sh(host, script, 60, sudo=_can_sudo(host))


@mcp.tool(annotations=READ)
def ubuntu_logins(host: str = "", failed: bool = False, lines: int = 30) -> str:
    """Show who is logged in and recent (or failed) logins."""
    if failed:
        script = f"lastb -n {int(lines)} -w 2>/dev/null || journalctl -u ssh -n 200 --no-pager | grep -i 'failed\\|invalid' | tail -n {int(lines)}"
    else:
        script = f"w; echo; last -n {int(lines)} -w"
    return _sh(host, script, 60, sudo=failed)


@mcp.tool(annotations=DESTRUCTIVE)
def ubuntu_reboot(host: str, confirm: bool = False, delay_minutes: int = 0) -> str:
    """Reboot a host. `host` is required and `confirm` must be true.

    Args:
        delay_minutes: Schedule the reboot this many minutes ahead (0 = now).
    """
    _require_write(host, "reboot")
    if not confirm:
        return "Refused: pass confirm=true to reboot."
    when = f"+{int(delay_minutes)}" if delay_minutes > 0 else "now"
    # Detach so the SSH session ends cleanly before the machine goes down.
    return _sh(host, f"nohup shutdown -r {when} >/dev/null 2>&1 & echo 'Reboot scheduled ({when})'", 30, sudo=True)


if __name__ == "__main__":
    mcp.run()
