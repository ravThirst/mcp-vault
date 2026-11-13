"""MCP server for administering remote Windows machines.

Exposes PowerShell execution plus targeted tools for the things you actually do
on a Windows box: files, services, processes, event logs, scheduled tasks,
networking and disks.

Several hosts can be configured (see README.md); every tool takes an optional
`host` argument naming the target, as listed by win_list_hosts. It may be
omitted when only one host is configured. Connections are opened lazily, per
host, so the server registers cleanly when a host is unreachable; failures then
surface as tool errors you can read.
"""

from __future__ import annotations

import os
import re

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from connection import ConfigError, Inventory, Transport, ps_quote

__version__ = "2.1.0"

mcp = MCPServer(
    "windows",
    version=__version__,
    instructions=(
        "Administers remote Windows machines over WinRM, SSH or the portable WinMCP agent. Call win_list_hosts to see the "
        "configured hosts (pass one as `host` when there are several) and win_test_connection "
        "when anything fails. Write tools are refused when WINDOWS_MCP_READONLY is set or the "
        "host is marked readonly. Disk formats, drive-root deletes and similar are blocked outright; "
        "win_restart_host needs the exact computer name as confirmation."
    ),
)

# Annotations tell clients which tools need confirmation.
READ = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=True)
WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True)
DESTRUCTIVE = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=True)

inventory = Inventory()

READ_ONLY = os.environ.get("WINDOWS_MCP_READONLY", "").strip().lower() in ("1", "true", "yes", "on")

# Patterns that would take the server down or destroy data wholesale. These are
# refused even outside read-only mode; run them from a real session instead.
BLOCKED = [
    (r"\bformat-volume\b", "disk format"),
    (r"\bformat\s+[a-z]:", "disk format"),
    (r"\bremove-item\b[^|]*\b[a-z]:\\\s*(-recurse|$)", "recursive delete of a drive root"),
    (r"\bremove-item\b[^|]*(-recurse)[^|]*\b(c:\\windows|c:\\program files)", "delete of a system directory"),
    (r"\brd\s+/s\b.*\b[a-z]:\\?\s*$", "recursive delete of a drive root"),
    (r"\bdel\s+/[sqf]*\s+[a-z]:\\\*", "wildcard delete of a drive root"),
    (r"\bclear-disk\b", "disk wipe"),
    (r"\bdiskpart\b.*\bclean\b", "diskpart clean"),
    (r"\bcipher\s+/w", "free-space wipe"),
    (r"\bvssadmin\b.*\bdelete\s+shadows", "shadow copy deletion"),
    (r"\bbcdedit\b.*\bdelete", "boot configuration deletion"),
    (r"\bremove-localuser\b|\bnet\s+user\b.*\/delete", "local account deletion"),
]


def conn(host: str = "") -> Transport:
    """Return the transport for a host, connecting on first use."""
    try:
        return inventory.connection(host)
    except ToolError:
        raise  # configuration problems (ConfigError) already read well
    except Exception as exc:  # noqa: BLE001 - e.g. SSH host unreachable
        raise ToolError(f"cannot connect to host '{host or 'default'}': {type(exc).__name__}: {exc}") from exc


def _guard(script: str) -> None:
    lowered = " ".join(script.lower().split())
    for pattern, label in BLOCKED:
        if re.search(pattern, lowered):
            raise ToolError(
                f"Refused: this looks like {label}. The MCP server blocks it outright - "
                "run it directly on the server if you really intend to."
            )


def _require_write(host: str, action: str) -> None:
    if READ_ONLY:
        raise ToolError(
            f"Refused: {action} is a write operation and WINDOWS_MCP_READONLY is enabled. "
            "Unset WINDOWS_MCP_READONLY in the MCP server config to allow changes."
        )
    cfg = inventory.resolve(host)
    if cfg.readonly:
        raise ToolError(
            f"Refused: {action} is a write operation and host '{cfg.name}' is marked readonly."
        )


def _remote(host: str, method: str, *args):
    """Call a transport method, reporting failures to the model as readable tool errors.

    The SDK shows the model only ToolError messages; any other exception is
    treated as a crash and reaches it as a bare "Error executing tool".
    """
    transport = conn(host)
    try:
        return getattr(transport, method)(*args)
    except ToolError:
        raise
    except Exception as exc:  # noqa: BLE001 - connection and remote failures
        raise ToolError(f"host '{transport.cfg.name}': {type(exc).__name__}: {exc}") from exc


def _ps(host: str, script: str, timeout_sec: int = 120) -> str:
    return _remote(host, "run_ps", script, timeout_sec).render()


# --------------------------------------------------------------------------
# Hosts / connection
# --------------------------------------------------------------------------


@mcp.tool(annotations=READ)
def win_list_hosts() -> str:
    """List the configured remote Windows hosts/servers (names to pass as `host` to other tools)."""
    try:
        hosts = inventory.hosts()
    except ConfigError as exc:
        return f"Configuration error: {exc}"
    lines = []
    for h in hosts:
        flags = [h.protocol + ("/https" if h.protocol == "winrm" and h.use_ssl else "")]
        if h.readonly or READ_ONLY:
            flags.append("readonly")
        if h.protocol != "agent":
            flags.append("key" if h.key_file else "password")
        desc = f" - {h.description}" if h.description else ""
        user = f"{h.username}@" if h.username else ""
        lines.append(f"{h.name}: {user}{h.host}:{h.effective_port} [{', '.join(flags)}]{desc}")
    return "\n".join(lines) or "No hosts configured."


@mcp.tool(annotations=READ)
def win_test_connection(host: str = "") -> str:
    """Verify the SSH, WinRM or encrypted WinMCP agent connection to the remote Windows host and report who we are.

    Run this first when something is not working - it separates "cannot reach
    the host" from "the command failed".
    """
    try:
        transport = inventory.connection(host)
    except ConfigError as exc:
        return f"Configuration error: {exc}"
    except Exception as exc:  # noqa: BLE001 - surfaced verbatim for diagnosis
        return f"Connection failed: {type(exc).__name__}: {exc}"

    try:
        # WinRM connects only here (SSH already did above), so its failures surface here too.
        res = transport.run_ps(
            "$o=[ordered]@{"
            "ComputerName=$env:COMPUTERNAME;"
            "User=[Security.Principal.WindowsIdentity]::GetCurrent().Name;"
            "IsAdmin=(New-Object Security.Principal.WindowsPrincipal("
            "[Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole("
            "[Security.Principal.WindowsBuiltInRole]::Administrator);"
            "OS=(Get-CimInstance Win32_OperatingSystem).Caption;"
            "PSVersion=$PSVersionTable.PSVersion.ToString();"
            "Uptime=((Get-Date)-(Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToString('d\\.hh\\:mm\\:ss')"
            "};$o.GetEnumerator()|ForEach-Object{\"$($_.Key): $($_.Value)\"}",
            60,
        )
    except Exception as exc:  # noqa: BLE001 - surfaced verbatim for diagnosis
        return f"Connection failed ({transport.describe()}): {type(exc).__name__}: {exc}"
    mode = " [READ-ONLY MODE]" if READ_ONLY or transport.cfg.readonly else ""
    return f"Host: {transport.cfg.name}\nTransport: {transport.describe()}{mode}\n\n{res.render()}"


# --------------------------------------------------------------------------
# Command execution
# --------------------------------------------------------------------------


@mcp.tool(annotations=DESTRUCTIVE)
def win_run_powershell(script: str, timeout_sec: int = 120, working_dir: str = "", host: str = "") -> str:
    """Run a PowerShell script on the remote Windows host and return its output.

    This is the general-purpose escape hatch: use it for anything the more
    specific tools do not cover. Prefer the specific tools when one fits, since
    they format their output for reading.

    Args:
        script: PowerShell to execute. Multi-line is fine.
        timeout_sec: Give up after this many seconds (default 120).
        working_dir: Optional directory to run from.
    """
    _guard(script)
    body = script
    if working_dir:
        body = f"Set-Location -LiteralPath {ps_quote(working_dir)};\n{script}"
    return _ps(host, body, timeout_sec)


@mcp.tool(annotations=DESTRUCTIVE)
def win_run_cmd(command: str, timeout_sec: int = 120, host: str = "") -> str:
    """Run a classic cmd.exe command on the remote Windows host.

    Use this for legacy tools that misbehave under PowerShell (some .bat files,
    `sc`, `reg`, older CLIs). For anything else prefer win_run_powershell.
    """
    _guard(command)
    return _remote(host, "run_cmd", command, timeout_sec).render()


# --------------------------------------------------------------------------
# System information
# --------------------------------------------------------------------------


@mcp.tool(annotations=READ)
def win_system_info(host: str = "") -> str:
    """Report OS, hardware, memory, CPU and domain details for the remote host."""
    return _ps(host,
        "$os=Get-CimInstance Win32_OperatingSystem;"
        "$cs=Get-CimInstance Win32_ComputerSystem;"
        "$cpu=Get-CimInstance Win32_Processor|Select-Object -First 1;"
        "$o=[ordered]@{"
        "ComputerName=$cs.Name;Domain=$cs.Domain;Manufacturer=$cs.Manufacturer;Model=$cs.Model;"
        "OS=$os.Caption;Version=$os.Version;Build=$os.BuildNumber;Architecture=$os.OSArchitecture;"
        "InstallDate=$os.InstallDate;LastBoot=$os.LastBootUpTime;"
        "CPU=$cpu.Name;Cores=$cpu.NumberOfCores;LogicalProcessors=$cs.NumberOfLogicalProcessors;"
        "TotalRAM_GB=[math]::Round($cs.TotalPhysicalMemory/1GB,2);"
        "FreeRAM_GB=[math]::Round($os.FreePhysicalMemory/1MB,2);"
        "TimeZone=(Get-TimeZone).DisplayName"
        "};$o.GetEnumerator()|ForEach-Object{'{0,-22} {1}' -f $_.Key,$_.Value}",
        90,
    )


@mcp.tool(annotations=READ)
def win_disk_usage(host: str = "") -> str:
    """List drives on the remote host with size, free space and percent used."""
    return _ps(host,
        "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3'|ForEach-Object{"
        "[PSCustomObject]@{"
        "Drive=$_.DeviceID;Label=$_.VolumeName;"
        "SizeGB=[math]::Round($_.Size/1GB,1);"
        "FreeGB=[math]::Round($_.FreeSpace/1GB,1);"
        "UsedPct=if($_.Size){[math]::Round(100*($_.Size-$_.FreeSpace)/$_.Size,1)}else{0}"
        "}}|Format-Table -AutoSize|Out-String -Width 200",
        60,
    )


@mcp.tool(annotations=READ)
def win_network_info(include_listening_ports: bool = True, host: str = "") -> str:
    """Show IP configuration, and optionally which processes hold listening ports."""
    script = (
        "'=== IP addresses ===';"
        "Get-NetIPAddress -AddressFamily IPv4|Where-Object{$_.IPAddress -ne '127.0.0.1'}|"
        "Select-Object InterfaceAlias,IPAddress,PrefixLength|Format-Table -AutoSize|Out-String -Width 200;"
        "'=== Default gateways ===';"
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0'|Select-Object InterfaceAlias,NextHop,RouteMetric|"
        "Format-Table -AutoSize|Out-String -Width 200;"
        "'=== DNS servers ===';"
        "Get-DnsClientServerAddress -AddressFamily IPv4|Where-Object{$_.ServerAddresses}|"
        "Select-Object InterfaceAlias,@{n='Servers';e={$_.ServerAddresses -join ', '}}|"
        "Format-Table -AutoSize|Out-String -Width 200;"
    )
    if include_listening_ports:
        script += (
            "'=== Listening TCP ports ===';"
            "Get-NetTCPConnection -State Listen|Sort-Object LocalPort|ForEach-Object{"
            "$p=Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue;"
            "[PSCustomObject]@{LocalAddress=$_.LocalAddress;Port=$_.LocalPort;PID=$_.OwningProcess;"
            "Process=$(if($p){$p.ProcessName}else{'?'})}}|"
            "Format-Table -AutoSize|Out-String -Width 200;"
        )
    return _ps(host, script, 120)


# --------------------------------------------------------------------------
# Files
# --------------------------------------------------------------------------


@mcp.tool(annotations=READ)
def win_list_dir(path: str, pattern: str = "*", recurse: bool = False, max_items: int = 300, host: str = "") -> str:
    """List the contents of a directory on the remote host.

    Args:
        path: Directory to list, e.g. 'C:\\inetpub\\wwwroot'.
        pattern: Optional filename filter such as '*.log'.
        recurse: Descend into subdirectories.
        max_items: Cap on the number of entries returned.
    """
    rec = "-Recurse " if recurse else ""
    return _ps(host,
        f"Get-ChildItem -LiteralPath {ps_quote(path)} -Filter {ps_quote(pattern)} {rec}"
        "-Force -ErrorAction SilentlyContinue|"
        f"Select-Object -First {int(max_items)} @{{n='Mode';e={{$_.Mode}}}},"
        "@{n='Size';e={if($_.PSIsContainer){''}else{$_.Length}}},"
        "@{n='Modified';e={$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm')}},"
        "@{n='Name';e={$_.FullName}}|"
        "Format-Table -AutoSize|Out-String -Width 250",
        120,
    )


@mcp.tool(annotations=READ)
def win_read_file(path: str, max_lines: int = 500, tail: bool = False, host: str = "") -> str:
    """Read a text file from the remote host.

    Args:
        path: Full path to the file.
        max_lines: Maximum number of lines to return.
        tail: Return the LAST max_lines instead of the first - use this for logs.
    """
    selector = f"-Tail {int(max_lines)}" if tail else f"-TotalCount {int(max_lines)}"
    return _ps(host,
        f"Get-Content -LiteralPath {ps_quote(path)} {selector} -ErrorAction Stop", 120
    )


@mcp.tool(annotations=WRITE)
def win_write_file(path: str, content: str, append: bool = False, host: str = "") -> str:
    """Write text to a file on the remote host, creating parent directories as needed.

    Args:
        path: Full destination path.
        content: Text to write.
        append: Append instead of overwriting.
    """
    _require_write(host, "win_write_file")
    import base64 as _b64

    encoded = _b64.b64encode(content.encode("utf-8")).decode("ascii")
    mode = "Append" if append else "Create"
    return _ps(host,
        f"$p={ps_quote(path)};"
        "$d=Split-Path -Parent $p;"
        "if($d -and -not (Test-Path $d)){New-Item -ItemType Directory -Force -Path $d|Out-Null};"
        f"$t=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}'));"
        + (
            "[IO.File]::AppendAllText($p,$t,[Text.Encoding]::UTF8);"
            if mode == "Append"
            else "[IO.File]::WriteAllText($p,$t,(New-Object Text.UTF8Encoding $false));"
        )
        + "\"Wrote $((Get-Item $p).Length) bytes to $p\"",
        120,
    )


@mcp.tool(annotations=WRITE)
def win_upload_file(local_path: str, remote_path: str, host: str = "") -> str:
    """Copy a file from this machine to the remote Windows host.

    Over SSH this uses SFTP; over the WinMCP agent (`agent` protocol) it sends an
    encrypted RPC upload. Over WinRM the file is chunked through PowerShell,
    which works but is slow above a few megabytes.
    """
    _require_write(host, "win_upload_file")
    if not os.path.isfile(local_path):
        raise ToolError(f"local file not found: {local_path}")
    return _remote(host, "upload", local_path, remote_path)


@mcp.tool(annotations=WRITE)
def win_download_file(remote_path: str, local_path: str, host: str = "") -> str:
    """Copy a file from the remote Windows host to this machine."""
    return _remote(host, "download", remote_path, local_path)


@mcp.tool(annotations=READ)
def win_search_files(
    path: str, pattern: str, content_match: str = "", max_results: int = 100, host: str = ""
) -> str:
    """Find files by name, and optionally by the text they contain.

    Args:
        path: Directory to search under.
        pattern: Filename pattern, e.g. '*.config'.
        content_match: If set, only return files containing this text, with the
            matching lines.
        max_results: Cap on results.
    """
    if content_match:
        return _ps(host,
            f"Get-ChildItem -LiteralPath {ps_quote(path)} -Filter {ps_quote(pattern)} "
            "-Recurse -File -Force -ErrorAction SilentlyContinue|"
            f"Select-String -Pattern {ps_quote(content_match)} -SimpleMatch -ErrorAction SilentlyContinue|"
            f"Select-Object -First {int(max_results)} Path,LineNumber,Line|"
            "ForEach-Object{'{0}:{1}: {2}' -f $_.Path,$_.LineNumber,$_.Line.Trim()}",
            240,
        )
    return _ps(host,
        f"Get-ChildItem -LiteralPath {ps_quote(path)} -Filter {ps_quote(pattern)} "
        "-Recurse -File -Force -ErrorAction SilentlyContinue|"
        f"Select-Object -First {int(max_results)} -ExpandProperty FullName",
        240,
    )


# --------------------------------------------------------------------------
# Services
# --------------------------------------------------------------------------


@mcp.tool(annotations=READ)
def win_services(name_filter: str = "", status: str = "", host: str = "") -> str:
    """List Windows services with their status, start mode and account.

    Args:
        name_filter: Substring match against the service or display name.
        status: Optionally 'Running' or 'Stopped'.
    """
    where = []
    if name_filter:
        q = ps_quote(f"*{name_filter}*")
        where.append(f"($_.Name -like {q} -or $_.DisplayName -like {q})")
    if status:
        where.append(f"$_.State -eq {ps_quote(status)}")
    clause = f"|Where-Object{{{' -and '.join(where)}}}" if where else ""
    return _ps(host,
        f"Get-CimInstance Win32_Service{clause}|"
        "Select-Object Name,DisplayName,State,StartMode,StartName|"
        "Sort-Object Name|Format-Table -AutoSize|Out-String -Width 250",
        120,
    )


@mcp.tool(annotations=WRITE)
def win_service_control(name: str, action: str, host: str = "") -> str:
    """Start, stop or restart a Windows service, then report its new state.

    Args:
        name: Service name (not the display name).
        action: 'start', 'stop' or 'restart'.
    """
    _require_write(host, "win_service_control")
    verb = action.strip().lower()
    cmdlet = {"start": "Start-Service", "stop": "Stop-Service", "restart": "Restart-Service"}.get(verb)
    if not cmdlet:
        raise ToolError(f"unknown action {action!r} (expected start, stop or restart)")
    q = ps_quote(name)
    force = " -Force" if verb in ("stop", "restart") else ""
    return _ps(host,
        f"{cmdlet} -Name {q}{force} -ErrorAction Stop;"
        "Start-Sleep -Seconds 2;"
        f"Get-Service -Name {q}|Select-Object Name,DisplayName,Status|Format-List|Out-String",
        180,
    )


# --------------------------------------------------------------------------
# Processes
# --------------------------------------------------------------------------


@mcp.tool(annotations=READ)
def win_processes(name_filter: str = "", sort_by: str = "cpu", top: int = 30, host: str = "") -> str:
    """List running processes on the remote host.

    Args:
        name_filter: Substring match against the process name.
        sort_by: 'cpu', 'memory' or 'name'.
        top: How many to return.
    """
    clause = (
        f"|Where-Object{{$_.ProcessName -like {ps_quote('*' + name_filter + '*')}}}"
        if name_filter
        else ""
    )
    sort = {
        "cpu": "CPU -Descending",
        "memory": "WS -Descending",
        "name": "ProcessName",
    }.get(sort_by.lower(), "CPU -Descending")
    return _ps(host,
        f"Get-Process{clause}|Sort-Object {sort}|Select-Object -First {int(top)} "
        "Id,ProcessName,@{n='CPU_s';e={[math]::Round($_.CPU,1)}},"
        "@{n='RAM_MB';e={[math]::Round($_.WS/1MB,1)}},"
        "@{n='Started';e={try{$_.StartTime.ToString('yyyy-MM-dd HH:mm')}catch{'?'}}}|"
        "Format-Table -AutoSize|Out-String -Width 200",
        120,
    )


@mcp.tool(annotations=DESTRUCTIVE)
def win_stop_process(name_or_pid: str, force: bool = True, host: str = "") -> str:
    """Stop a process on the remote host by name or PID.

    Args:
        name_or_pid: Process name (stops every match) or a numeric PID.
        force: Kill without asking the process to close gracefully.
    """
    _require_write(host, "win_stop_process")
    target = name_or_pid.strip()
    selector = f"-Id {int(target)}" if target.isdigit() else f"-Name {ps_quote(target)}"
    f = " -Force" if force else ""
    return _ps(host,
        f"$procs=Get-Process {selector} -ErrorAction Stop;"
        "$procs|ForEach-Object{\"Stopping $($_.ProcessName) (PID $($_.Id))\"};"
        f"Stop-Process {selector}{f} -ErrorAction Stop;"
        "'Done.'",
        120,
    )


# --------------------------------------------------------------------------
# Event log, tasks, software
# --------------------------------------------------------------------------


@mcp.tool(annotations=READ)
def win_event_log(
    log_name: str = "System",
    level: str = "",
    since_hours: int = 24,
    count: int = 50,
    provider: str = "",
    search: str = "",
    host: str = "",
) -> str:
    """Read the Windows event log on the remote host.

    Args:
        log_name: 'System', 'Application', 'Security', or any other log name.
        level: Optionally 'Critical', 'Error', 'Warning' or 'Information'.
        since_hours: Only events from the last N hours.
        count: Maximum events to return.
        provider: Optional source/provider name filter.
        search: Optional substring that must appear in the message.
    """
    levels = {"critical": 1, "error": 2, "warning": 3, "information": 4}
    filters = [f"LogName={ps_quote(log_name)}", f"StartTime=(Get-Date).AddHours(-{int(since_hours)})"]
    if level:
        num = levels.get(level.strip().lower())
        if num is None:
            raise ToolError(f"unknown level {level!r}")
        filters.append(f"Level={num}")
    if provider:
        filters.append(f"ProviderName={ps_quote(provider)}")
    hashtable = "@{" + ";".join(filters) + "}"
    search_clause = (
        f"|Where-Object{{$_.Message -like {ps_quote('*' + search + '*')}}}" if search else ""
    )
    return _ps(host,
        f"Get-WinEvent -FilterHashtable {hashtable} -MaxEvents {int(count) * 3} "
        f"-ErrorAction SilentlyContinue{search_clause}|"
        f"Select-Object -First {int(count)}|ForEach-Object{{"
        "'[{0:yyyy-MM-dd HH:mm:ss}] {1} {2} (id {3})' -f "
        "$_.TimeCreated,$_.LevelDisplayName,$_.ProviderName,$_.Id;"
        "'    '+(($_.Message -split \"`r?`n\")[0..3] -join ' ').Trim()}",
        180,
    )


@mcp.tool(annotations=READ)
def win_scheduled_tasks(name_filter: str = "", only_enabled: bool = False, host: str = "") -> str:
    """List scheduled tasks on the remote host with their state and last result."""
    clause = (
        f"|Where-Object{{$_.TaskName -like {ps_quote('*' + name_filter + '*')}}}"
        if name_filter
        else ""
    )
    enabled = "|Where-Object{$_.State -ne 'Disabled'}" if only_enabled else ""
    return _ps(host,
        f"Get-ScheduledTask{clause}{enabled}|ForEach-Object{{"
        "$i=$_|Get-ScheduledTaskInfo -ErrorAction SilentlyContinue;"
        "[PSCustomObject]@{Path=$_.TaskPath;Name=$_.TaskName;State=$_.State;"
        "LastRun=$i.LastRunTime;LastResult=$i.LastTaskResult;NextRun=$i.NextRunTime}}|"
        "Format-Table -AutoSize|Out-String -Width 250",
        180,
    )


@mcp.tool(annotations=READ)
def win_installed_software(name_filter: str = "", host: str = "") -> str:
    """List installed software on the remote host, read from the uninstall registry keys."""
    clause = (
        f"|Where-Object{{$_.DisplayName -like {ps_quote('*' + name_filter + '*')}}}"
        if name_filter
        else "|Where-Object{$_.DisplayName}"
    )
    return _ps(host,
        "Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' "
        f"-ErrorAction SilentlyContinue{clause}|"
        "Select-Object DisplayName,DisplayVersion,Publisher,InstallDate|"
        "Sort-Object DisplayName|Format-Table -AutoSize|Out-String -Width 250",
        180,
    )


@mcp.tool(annotations=DESTRUCTIVE)
def win_restart_host(confirm_computer_name: str, host: str = "") -> str:
    """Reboot the remote Windows host. Requires the exact computer name as confirmation.

    Call win_test_connection for the same host first to read its ComputerName,
    then pass it here. This drops the connection; reconnect after the host comes back.
    """
    _require_write(host, "win_restart_host")
    return _ps(host,
        f"if($env:COMPUTERNAME -ne {ps_quote(confirm_computer_name)}){{"
        f"throw \"Refused: confirmation {ps_quote(confirm_computer_name)} does not match \"+$env:COMPUTERNAME}};"
        "Restart-Computer -Force;'Restart issued.'",
        60,
    )


if __name__ == "__main__":
    mcp.run()
