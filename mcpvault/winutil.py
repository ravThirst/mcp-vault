"""Windows process helpers: job objects, liveness checks, detached spawning, shortcuts."""

import ctypes
import os
import subprocess
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


def kill_with_parent(proc: subprocess.Popen) -> None:
    """Put `proc` in a job that is killed when this process exits for any reason."""
    job = _k32.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    info = _ExtendedLimit()
    info.BasicLimitInformation.LimitFlags = _KILL_ON_JOB_CLOSE
    if not _k32.SetInformationJobObject(job, _JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)):
        raise ctypes.WinError(ctypes.get_last_error())
    if not _k32.AssignProcessToJobObject(job, wt.HANDLE(int(proc._handle))):
        raise ctypes.WinError(ctypes.get_last_error())
    _jobs.append(job)


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
