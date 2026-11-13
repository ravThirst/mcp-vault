"""Windows process helpers: job objects, liveness checks, detached spawning, shortcuts."""

import ctypes
import os
import subprocess
import threading
from ctypes import wintypes as wt

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)

_k32.CreateJobObjectW.restype = wt.HANDLE
_k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wt.LPCWSTR]
_k32.SetInformationJobObject.restype = wt.BOOL
_k32.SetInformationJobObject.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD]
_k32.AssignProcessToJobObject.restype = wt.BOOL
_k32.AssignProcessToJobObject.argtypes = [wt.HANDLE, wt.HANDLE]
_k32.OpenProcess.restype = wt.HANDLE
_k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
_k32.GetExitCodeProcess.restype = wt.BOOL
_k32.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
_k32.CloseHandle.argtypes = [wt.HANDLE]


class _BasicLimit(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wt.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wt.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wt.DWORD),
        ("SchedulingClass", wt.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint64) for n in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _ExtendedLimit(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimit),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


_JobObjectExtendedLimitInformation = 9
_KILL_ON_JOB_CLOSE = 0x2000
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_STILL_ACTIVE = 259

DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_BREAKAWAY_FROM_JOB = 0x01000000

_jobs = []  # keep job handles alive for the life of this process
_jobs_lock = threading.Lock()


def kill_with_parent(proc: subprocess.Popen):
    """Put `proc` in a job that is killed when this process exits for any reason."""
    job = _k32.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    info = _ExtendedLimit()
    info.BasicLimitInformation.LimitFlags = _KILL_ON_JOB_CLOSE
    if not _k32.SetInformationJobObject(job, _JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)):
        _k32.CloseHandle(job)
        raise ctypes.WinError(ctypes.get_last_error())
    if not _k32.AssignProcessToJobObject(job, wt.HANDLE(int(proc._handle))):
        _k32.CloseHandle(job)
        raise ctypes.WinError(ctypes.get_last_error())
    with _jobs_lock:
        _jobs.append(job)
    return job


def close_job(job) -> None:
    """Close a job created by kill_with_parent, ending any remaining processes in it."""
    if not job:
        return
    with _jobs_lock:
        try:
            _jobs.remove(job)
        except ValueError:
            return
    _k32.CloseHandle(job)


def pid_alive(pid: int) -> bool:
    h = _k32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return False
    try:
        code = wt.DWORD()
        return bool(_k32.GetExitCodeProcess(h, ctypes.byref(code))) and code.value == _STILL_ACTIVE
    finally:
        _k32.CloseHandle(h)


def spawn_detached(argv: list[str], cwd: str) -> None:
    """Start a background process that outlives the caller.

    MCP clients run servers inside kill-on-close job objects, so a plain child
    would die with the first server that started it. Break away from the job
    if allowed; otherwise let WMI create the process outside our job tree.
    """
    flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB
    try:
        subprocess.Popen(argv, cwd=cwd, creationflags=flags, close_fds=True,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return
    except OSError:
        pass
    env = dict(os.environ, MCPVAULT_CMDLINE=subprocess.list2cmdline(argv), MCPVAULT_CWD=cwd)
    subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
         "$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments "
         "@{CommandLine=$env:MCPVAULT_CMDLINE; CurrentDirectory=$env:MCPVAULT_CWD}; exit $r.ReturnValue"],
        env=env, check=True, capture_output=True, creationflags=0x08000000,
    )


def agent_pids(entry: str) -> list[int]:
    """PIDs of agent processes started from this app's vault.py (venv shims included)."""
    env = dict(os.environ, MCPVAULT_ENTRY=entry)
    out = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
         "Get-CimInstance Win32_Process -Filter \"Name like 'python%'\" | "
         "Where-Object { $_.CommandLine -and $_.CommandLine.ToLower().Contains($env:MCPVAULT_ENTRY.ToLower()) "
         "-and $_.CommandLine -match '\\sagent\\s*$' } | ForEach-Object { $_.ProcessId }"],
        env=env, capture_output=True, text=True, creationflags=0x08000000,
    ).stdout
    return [int(x) for x in out.split() if x.strip().isdigit() and int(x) != os.getpid()]


def port_owner(port: int) -> int | None:
    """PID of the process listening on 127.0.0.1/0.0.0.0:`port` (TCP), or None."""
    try:
        raw = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True,
                             creationflags=0x08000000, timeout=10).stdout or b""
    except (OSError, subprocess.SubprocessError):
        return None
    out = raw.decode("oem", errors="replace")  # netstat prints in the console code page
    for line in out.splitlines():
        parts = line.split()
        # TCP  127.0.0.1:47821  0.0.0.0:0  LISTENING  1234  (state is localized on some systems)
        if len(parts) >= 5 and parts[0].upper() == "TCP" and parts[1].rsplit(":", 1)[-1] == str(port) \
                and parts[2].endswith(":0") and parts[-1].isdigit():
            return int(parts[-1])
    return None


def process_cmdline(pid: int) -> str:
    """Command line of `pid` ('' if it cannot be read)."""
    import base64

    script = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
              f"(Get-CimInstance Win32_Process -Filter 'ProcessId={int(pid)}').CommandLine")
    try:
        raw = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand",
             base64.b64encode(script.encode("utf-16-le")).decode("ascii")],
            capture_output=True, creationflags=0x08000000, timeout=20,
        ).stdout or b""
        return raw.decode("utf-8", errors="replace").strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def is_vault_agent_cmdline(cmdline: str) -> bool:
    """True for `python[w] ...\\vault.py agent` from any MCP Vault folder."""
    import re

    return bool(re.search(r"vault\.py\"?\s+agent\s*$", cmdline.strip(), re.IGNORECASE))


def process_user() -> str:
    """Windows account this process runs as (from its token, not the environment)."""
    buf = ctypes.create_unicode_buffer(257)
    size = wt.DWORD(257)
    try:
        if ctypes.WinDLL("advapi32").GetUserNameW(buf, ctypes.byref(size)):
            return buf.value
    except OSError:
        pass
    return ""


def foreign_user() -> str | None:
    """The account name when this process runs as a different Windows user than the
    profile it works for, e.g. Codex's sandbox accounts (CodexSandboxOnline/Offline),
    which run shell commands with the real user's environment. None when normal."""
    me = process_user()
    if not me:
        return None
    owner = os.environ.get("USERNAME", "")
    if me.lower().startswith("codexsandbox") or (owner and me.lower() != owner.lower()):
        return me
    return None


def foreign_user_message(user: str) -> str:
    owner = os.environ.get("USERNAME") or "your account"
    return (f"this command runs as Windows user '{user}' (Codex's sandbox runs shell commands as separate "
            f"accounts), not as '{owner}', so it cannot start, stop or reliably reach MCP Vault's agent. "
            "Use the server's MCP tools instead (e.g. win_test_connection / ubuntu_test_connection), or run "
            "the vault.py command outside the sandbox (request escalated permissions); if MCP Vault is not "
            "running, ask the user to open it from the Start menu")


def stop_menu_shortcut_path() -> str:
    return os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs", "Stop MCP Vault.lnk")


STOP_ICON = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "shell32.dll") + ",27"


def startup_shortcut_path() -> str:
    return os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "MCP Vault Agent.lnk")


def start_menu_shortcut_path() -> str:
    return os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs", "MCP Vault.lnk")


LOCK_ICON = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "shell32.dll") + ",47"


def create_shortcut(path: str, target: str, arguments: str, workdir: str, description: str, icon: str = LOCK_ICON) -> None:
    env = dict(os.environ, SC_PATH=path, SC_TARGET=target, SC_ARGS=arguments, SC_DIR=workdir, SC_DESC=description, SC_ICON=icon)
    subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
         "$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:SC_PATH); "
         "$s.TargetPath = $env:SC_TARGET; $s.Arguments = $env:SC_ARGS; "
         "$s.WorkingDirectory = $env:SC_DIR; $s.Description = $env:SC_DESC; $s.IconLocation = $env:SC_ICON; $s.Save()"],
        env=env, check=True, capture_output=True, creationflags=0x08000000,
    )
