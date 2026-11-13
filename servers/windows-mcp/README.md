# windows-mcp

MCP server for administering **remote Windows machines** from Claude, Codex,
Antigravity, or Kimi Work. Connects over WinRM (PowerShell Remoting), SSH, or
the portable WinMCP agent (`..\..\agent\winmcp-agent.ps1`, for machines where
neither works) and exposes 21 tools covering commands, files, services,
processes, event logs, scheduled tasks, networking and disks.

One server handles any number of hosts. Every tool takes an optional `host`
argument (a name from `win_list_hosts`); it may be left out when only one host
is configured. Built to MCP Vault's SERVER-SPEC.

## Configuration

Normally managed by **MCP Vault** (template `windows-mcp`): add the Windows
hosts in the vault, tick them on the `windows` server, and the server receives
them at start, with no passwords in any config file.

### Hosts

| Variable | Meaning |
| --- | --- |
| `WINDOWS_MCP_HOSTS` | Inline JSON host list (what MCP Vault sets) |
| `WINDOWS_MCP_HOSTS_FILE` | Path to a JSON file in the same format |
| `WINDOWS_HOST`, `WINDOWS_USERNAME`, `WINDOWS_PASSWORD`, `WINDOWS_SSH_PORT` / `WINDOWS_WINRM_PORT`, `WINDOWS_SSH_KEY`, `WINDOWS_USE_SSL` | The original single-host settings; still work when neither of the above is set (`WINDOWS_HOST_NAME` names that host, default its address) |

Inline wins over the file, the file over the single-host variables. Host format:

```json
{"hosts": [
  {"name": "office-pc", "host": "192.168.0.30", "username": "admin", "password": "...",
   "protocol": "ssh", "port": 22},
  {"name": "lab-pc", "host": "192.168.0.34", "username": "User", "password": "...",
   "protocol": "winrm", "use_ssl": true, "readonly": true, "description": "test machine"},
  {"name": "srv2016", "host": "192.168.0.40", "password": "<agent key>", "protocol": "agent"}
]}
```

`protocol` is `winrm`, `ssh` or `agent` (default `WINDOWS_MCP_TRANSPORT`, else `winrm`);
`port` defaults to 22 / 5985 / 5986 (HTTPS) / 5990 (agent); SSH may use `key_file` instead of
`password`; an agent host needs no `username`, and its `password` is the agent key;
`readonly: true` refuses write tools on that host.

### Server-wide settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `WINDOWS_MCP_READONLY` | off | `true` blocks every write tool on every host |
| `WINDOWS_MCP_TRANSPORT` | `winrm` | Protocol for hosts that don't set one |
| `WINDOWS_SSL_VERIFY` | `false` | WinRM: validate the server certificate |
| `WINDOWS_WINRM_AUTH` | `ntlm` | WinRM: `ntlm`, `basic`, `kerberos`, `certificate` |
| `WINDOWS_READ_TIMEOUT` | 180 | WinRM socket read timeout, seconds |
| `WINDOWS_OPERATION_TIMEOUT` | 170 | WS-Man operation timeout; keep below read timeout |

### Which transport?

**WinRM** is the default and needs nothing installed on the target beyond what
ships with Windows — just enable it. **SSH** needs the OpenSSH Server feature,
but gives real SFTP, so file transfer is much faster. The **agent** is for
machines where neither is possible (Windows Server 2016 has no built-in OpenSSH,
or WinRM is locked down by policy): one PowerShell script, nothing installed.

## Preparing the remote server

WinRM, in an elevated PowerShell **on the remote machine**:

```powershell
Enable-PSRemoting -Force
# Only needed when connecting by IP or across a workgroup (no domain trust):
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force
Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*' | Enable-NetFirewallRule
```

For HTTPS instead of plaintext HTTP, bind a certificate and set
`WINDOWS_USE_SSL=true`:

```powershell
$c = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My
New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $c.Thumbprint -Force
New-NetFirewallRule -DisplayName 'WinRM HTTPS' -Direction Inbound -LocalPort 5986 -Protocol TCP -Action Allow
```

NTLM authentication encrypts the payload even over HTTP, but HTTPS is better if
the traffic leaves a trusted network.

### SSH

In an **elevated** PowerShell on the remote Windows machine:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd
Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Enable-NetFirewallRule
```

To use key authentication, generate the pair **on this workstation** and copy
only the `.pub` file to the server:

```bash
ssh-keygen -t ed25519 -f "$HOME/.ssh/winmcp" -C "winmcp"
```

Then configure the key path in MCP Vault (or set `WINDOWS_SSH_KEY` to the private key path).

Two Windows-specific gotchas worth knowing when configuring key auth on Windows:

* For accounts in the Administrators group, sshd reads
  `C:\ProgramData\ssh\administrators_authorized_keys`, **not** the user's
  `~/.ssh/authorized_keys`. Putting the key in the obvious place silently fails.
* That file must have inheritance disabled and grant only SYSTEM and
  Administrators (`S-1-5-18` and `S-1-5-32-544`), or sshd ignores it.

### WinMCP agent

`..\..\agent\winmcp-agent.ps1` (shipped in the top-level `agent\` folder of MCP Vault)
is a single PowerShell 5.1 script (Windows Server 2016 and later, Windows 10 and
later). On the target Windows machine, either launch it directly with one line:

```powershell
irm https://raw.githubusercontent.com/ravThirst/mcp-vault/main/agent/launch.ps1 | iex
```

or copy MCP Vault's `..\..\agent\` folder to the server (for example as `C:\WinMCP`).

**Without installing anything:** double-click `Start WinMCP Agent.bat` (edit
`ALLOW_FROM` in it first, or pass the address: `"Start WinMCP Agent.bat" 192.168.0.10`).
It asks for administrator rights, prints the key on the first run, and starts
the agent hidden in the background. The firewall is opened only while it runs.
It keeps running until `Stop WinMCP Agent.bat`, logoff or reboot.

The same from PowerShell (it asks for elevation itself when needed):

```powershell
.\winmcp-agent.ps1 -AllowFrom 192.168.0.10              # foreground, Ctrl+C stops it
.\winmcp-agent.ps1 -Background -AllowFrom 192.168.0.10  # hidden, no install
.\winmcp-agent.ps1 -Status                              # running? listening?
.\winmcp-agent.ps1 -Stop                                # stop it (also the installed task)

# Permanent: a SYSTEM scheduled task at every boot with a lasting firewall rule
.\winmcp-agent.ps1 -Install -AllowFrom 192.168.0.10
.\winmcp-agent.ps1 -Uninstall   # remove the task and firewall rule

.\winmcp-agent.ps1 -ShowKey     # print the key again
.\winmcp-agent.ps1 -NewKey      # replace the key (then restart the agent)
```

`-AllowFrom` takes addresses or subnets, comma-separated; the default is `Any`.
If the background agent fails to start, the launcher prints the reason from
`agent.log`.

In MCP Vault add a Windows host with protocol **WinMCP agent**, port 5990, and
paste the key as its password. The key file (`agent.key`) is readable only by
SYSTEM and Administrators; `agent.log` records each request (client, operation,
duration, exit code), never the script text.

How it works: the agent listens with `HttpListener` on one port and runs each
script in a fresh `powershell.exe`, fed over stdin, with the requested timeout
(the process tree is killed when it expires). Every request is AES-256-CBC
encrypted and HMAC-SHA256 signed with keys derived from the shared key, and
carries a timestamp (±5 minutes, so keep both clocks in sync) and a one-time
nonce; replies are signed over the request's nonce. The key never crosses the
wire, so plain HTTP is safe from eavesdropping, but anyone holding the key runs
code as SYSTEM: scope the firewall with `-AllowFrom` or reach the port through a
VPN. Up to 4 requests run at once (`-MaxConcurrent`).

## Tools

**Hosts** — `win_list_hosts` (names to pass as `host`), `win_test_connection` (run this first when debugging).

Every tool carries MCP annotations (read-only / write / destructive); `win_run_powershell`, `win_run_cmd`,
`win_stop_process` and `win_restart_host` are marked destructive.

**Commands** — `win_run_powershell`, `win_run_cmd`.

**System** — `win_system_info`, `win_disk_usage`, `win_network_info`.

**Files** — `win_list_dir`, `win_read_file`, `win_write_file`, `win_upload_file`,
`win_download_file`, `win_search_files`.

**Services** — `win_services`, `win_service_control`.

**Processes** — `win_processes`, `win_stop_process`.

**Diagnostics** — `win_event_log`, `win_scheduled_tasks`,
`win_installed_software`.

**Host** — `win_restart_host` (requires the exact computer name as confirmation).

## Safety

Two independent layers:

1. **Blocked outright**, in every mode: disk formatting, recursive deletion of
   drive roots or system directories, `diskpart clean`, shadow-copy deletion,
   `bcdedit /delete`, free-space wiping and local-account deletion. These are
   refused rather than confirmed — run them in a real session on the box.
2. **Read-only mode** (`WINDOWS_MCP_READONLY=true` for all hosts, or `readonly: true` on one
   host) additionally refuses every write tool: file writes, uploads, service control, process termination and
   restart. Note that it does *not* parse arbitrary scripts passed to
   `win_run_powershell`, so it is a guard rail, not a sandbox.

With MCP Vault, credentials live only in its encrypted vault; with the plain
variables they sit in plaintext in `~/.claude.json`. Either way, give the account the least
privilege that does the job, and prefer a dedicated admin account over a shared
one.

## Notes on output handling

Windows PowerShell encodes redirected output using the console code page, which
corrupts every non-ASCII character on a localized server. This server captures
each script's output, converts it to UTF-8 and writes it straight to the
standard output handle, bypassing console encoding. Scripts travel to the far
side as base64, so multi-line bodies and embedded quotes need no escaping.
Output is truncated at 60,000 characters.

## Development

```bash
..\..\.venv\Scripts\python.exe -c "import sys; sys.path.insert(0,'src'); import server"
```

`src/connection.py` holds the three transports (`winrm`, `ssh`, `agent`); `src/server.py` holds the 21 tools.
