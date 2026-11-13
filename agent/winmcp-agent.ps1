<#
.SYNOPSIS
    Portable agent that lets windows-mcp administer this machine without WinRM or SSH.

.DESCRIPTION
    A single PowerShell 5.1 script, nothing to install: copy it to the server and run it
    in an elevated PowerShell. It listens on one TCP port (default 5990) and runs the
    PowerShell scripts and file transfers that windows-mcp sends it.

    Every request and response is encrypted (AES-256-CBC) and authenticated
    (HMAC-SHA256) with a shared key, carries a timestamp and a one-time nonce, and is
    refused if any of those do not check out. The key itself never crosses the wire,
    so plain HTTP is safe to use; still keep the port closed to everything but the
    machine that runs windows-mcp (-AllowFrom), or reach it through a VPN.

    The key lives in agent.key next to this script, readable by SYSTEM and
    Administrators only. Paste it into MCP Vault as the host's password.

    Run without -Install, nothing is left behind: the firewall is opened only while the
    agent runs. Started from a normal (not elevated) window, the script asks for UAC
    elevation and continues in a new window.

.EXAMPLE
    .\winmcp-agent.ps1
    Run in the foreground (Ctrl+C stops it). Creates the key on first run and prints it.

.EXAMPLE
    .\winmcp-agent.ps1 -Background -AllowFrom 192.168.0.10
    Run hidden in the background, no install. Runs until -Stop, logoff or reboot.

.EXAMPLE
    .\winmcp-agent.ps1 -Status
    Show whether the agent is running and listening. -Stop stops it.

.EXAMPLE
    .\winmcp-agent.ps1 -Install -AllowFrom 192.168.0.10
    Run as a scheduled task under SYSTEM at every boot, firewall open to one address.

.EXAMPLE
    .\winmcp-agent.ps1 -Uninstall
    Remove the scheduled task and firewall rule. The script and key stay where they are.
#>
param(
    [int]$Port = 5990,
    [switch]$Install,
    [string[]]$AllowFrom = @('Any'),
    [switch]$Uninstall,
    [switch]$ShowKey,
    [switch]$NewKey,
    [switch]$Background,
    [switch]$Stop,
    [switch]$Status,
    [int]$MaxConcurrent = 4
)

$ErrorActionPreference = 'Stop'
$ScriptArgs = $PSBoundParameters
$AgentVersion = '1.1.0'
$TaskName = 'WinMCP Agent'
$RuleName = 'WinMCP Agent'
$TempRuleName = 'WinMCP Agent (temporary)'
$Root = $PSScriptRoot
$KeyPath = Join-Path $Root 'agent.key'
$LogPath = Join-Path $Root 'agent.log'
$PidPath = Join-Path $Root 'agent.pid'
$PowerShellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
# "-AllowFrom a,b" arrives as one string when the script is started with -File.
$AllowFrom = @($AllowFrom | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

function Write-Log([string]$Message) {
    $line = '{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $Message
    Write-Host $line
    try { Add-Content -Path $LogPath -Value $line -Encoding UTF8 } catch { }
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Protect-Path([string]$Path) {
    # SYSTEM and Administrators only, by SID so it works on localized Windows.
    & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $Path" }
}

function New-AgentKey {
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $key = -join ($bytes | ForEach-Object { $_.ToString('x2') })
    [IO.File]::WriteAllText($KeyPath, $key, (New-Object Text.UTF8Encoding $false))
    Protect-Path $KeyPath
    $key
}

function Show-Key([string]$Key) {
    Write-Host ''
    Write-Host 'Agent key (paste into MCP Vault as this host''s password, then keep it secret):' -ForegroundColor Yellow
    Write-Host "    $Key" -ForegroundColor Cyan
    Write-Host ''
}

function Get-AgentProcess {
    # The agent started from this folder, found by the PID it records while running.
    if (-not (Test-Path $PidPath)) { return $null }
    $id = 0
    if (-not [int]::TryParse([IO.File]::ReadAllText($PidPath).Trim(), [ref]$id)) { return $null }
    $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$id" -ErrorAction SilentlyContinue
    if ($proc -and $proc.CommandLine -like "*$(Split-Path -Leaf $PSCommandPath)*") { return $proc }
    $null
}

function Test-Listening {
    [bool](Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
}

function Get-ForwardedArgs {
    $list = @()
    foreach ($p in $ScriptArgs.GetEnumerator()) {
        if ($p.Value -is [switch]) { if ($p.Value) { $list += "-$($p.Key)" } }
        elseif ($p.Key -eq 'AllowFrom') { $list += '-AllowFrom', ($AllowFrom -join ',') }
        else { $list += "-$($p.Key)", "$($p.Value)" }
    }
    $list
}

if (-not (Test-Admin)) {
    # Ask for elevation and carry on in a new window that stays open, so the key and any
    # error stay readable (this is what happens when a launcher .bat is double-clicked).
    Write-Host 'Administrator rights are needed; asking for elevation...'
    $relaunch = @('-NoLogo', '-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"") + (Get-ForwardedArgs)
    Start-Process $PowerShellExe -Verb RunAs -ArgumentList $relaunch
    return
}

if ($Status) {
    $proc = Get-AgentProcess
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($proc) { Write-Host "Agent running (PID $($proc.ProcessId))." -ForegroundColor Green } else { Write-Host 'No agent process from this folder is running.' }
    if ($task) { Write-Host "Scheduled task '$TaskName' is installed (state: $($task.State))." }
    if (Test-Listening) { Write-Host "Port $Port is listening." -ForegroundColor Green } else { Write-Host "Port $Port is not listening." -ForegroundColor Yellow }
    return
}

if ($Stop) {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task -and $task.State -eq 'Running') {
        Stop-ScheduledTask -TaskName $TaskName
        Write-Host "Stopped the scheduled task '$TaskName' (it starts again at boot; -Uninstall removes it)."
    }
    $proc = Get-AgentProcess
    if ($proc) {
        Stop-Process -Id $proc.ProcessId -Force
        Write-Host "Stopped the agent (PID $($proc.ProcessId))."
    } elseif (-not ($task -and $task.State -eq 'Running')) {
        Write-Host 'The agent is not running.'
    }
    # A killed agent cannot clean up after itself.
    Get-NetFirewallRule -DisplayName $TempRuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Remove-Item $PidPath -ErrorAction SilentlyContinue
    return
}

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Write-Host "Removed scheduled task and firewall rule '$TaskName'. Files in $Root were left in place."
    return
}

if ($NewKey -or -not (Test-Path $KeyPath)) {
    Show-Key (New-AgentKey)
    if ($NewKey) { Write-Host 'Restart the agent to use the new key.'; return }
} elseif ($ShowKey) {
    Show-Key ([IO.File]::ReadAllText($KeyPath).Trim())
    return
}

if ($Install) {
    Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Protocol TCP -LocalPort $Port `
        -RemoteAddress $AllowFrom -Action Allow -Profile Any | Out-Null
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $action = New-ScheduledTaskAction -Execute $ps `
        -Argument "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Port $Port -MaxConcurrent $MaxConcurrent"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 `
        -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
        -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName
    Start-Sleep -Seconds 3
    $listening = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
    Write-Host "Installed '$TaskName' (runs as SYSTEM at boot), firewall open on TCP $Port from: $($AllowFrom -join ', ')"
    if ($listening) { Write-Host "Agent is listening on port $Port." -ForegroundColor Green }
    else { Write-Host "Port $Port is not listening yet; check $LogPath." -ForegroundColor Yellow }
    Write-Host "Show the key again with: .\$(Split-Path -Leaf $PSCommandPath) -ShowKey"
    return
}

if ($Background) {
    $proc = Get-AgentProcess
    if ($proc) { Write-Host "The agent is already running (PID $($proc.ProcessId)). Stop it with -Stop."; return }
    if (Test-Listening) { throw "Port $Port is already in use (the installed task? check with -Status)." }
    $run = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" " +
           "-Port $Port -MaxConcurrent $MaxConcurrent -AllowFrom $($AllowFrom -join ',')"
    $logLines = 0
    if (Test-Path $LogPath) { $logLines = @(Get-Content $LogPath).Count }
    $child = Start-Process $PowerShellExe -ArgumentList $run -WindowStyle Hidden -PassThru
    for ($i = 0; $i -lt 20 -and -not (Test-Listening) -and -not $child.HasExited; $i++) { Start-Sleep -Milliseconds 500 }
    Start-Sleep -Seconds 1  # a start-up failure right after binding the port still shows as an exit
    if ((Test-Listening) -and -not $child.HasExited) {
        Write-Host "Agent running in the background (PID $($child.Id)) on port $Port, firewall open from: $($AllowFrom -join ', ')" -ForegroundColor Green
        Write-Host 'It runs until -Stop, logoff or reboot. Nothing was installed.'
    } else {
        Write-Host 'The agent did not start. Its log says:' -ForegroundColor Yellow
        if (Test-Path $LogPath) { Get-Content $LogPath | Select-Object -Skip $logLines | ForEach-Object { Write-Host "    $_" } }
    }
    return
}

# --------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------

$secret = [Text.Encoding]::UTF8.GetBytes([IO.File]::ReadAllText($KeyPath).Trim())
$kdf = [Security.Cryptography.HMACSHA256]::new($secret)
$State = [hashtable]::Synchronized(@{
    EncKey  = $kdf.ComputeHash([Text.Encoding]::UTF8.GetBytes('winmcp-agent enc v1'))
    MacKey  = $kdf.ComputeHash([Text.Encoding]::UTF8.GetBytes('winmcp-agent mac v1'))
    Nonces  = [hashtable]::Synchronized(@{})
    LogPath = $LogPath
    Version = $AgentVersion
})
$kdf.Dispose()

# Runs in a runspace per request. Everything it needs comes from $State.
$Handler = {
    param($Context, $State)

    Add-Type -AssemblyName System.Web.Extensions
    $json = New-Object Web.Script.Serialization.JavaScriptSerializer
    $json.MaxJsonLength = [int]::MaxValue
    $utf8 = New-Object Text.UTF8Encoding $false
    $MaxSkewSec = 300

    function Log([string]$Message) {
        $line = '{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $Message
        [Console]::WriteLine($line)
        try { [IO.File]::AppendAllText($State.LogPath, $line + "`r`n", $utf8) } catch { }
    }

    function Get-Mac([string]$Text) {
        $h = [Security.Cryptography.HMACSHA256]::new($State.MacKey)
        try { , $h.ComputeHash($utf8.GetBytes($Text)) } finally { $h.Dispose() }
    }

    function Test-Same([byte[]]$A, [byte[]]$B) {
        if ($null -eq $A -or $null -eq $B -or $A.Length -ne $B.Length) { return $false }
        $diff = 0
        for ($i = 0; $i -lt $A.Length; $i++) { $diff = $diff -bor ($A[$i] -bxor $B[$i]) }
        $diff -eq 0
    }

    function New-Aes {
        $aes = [Security.Cryptography.Aes]::Create()
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $State.EncKey
        $aes
    }

    function Send([int]$Status, [string]$Body) {
        $bytes = $utf8.GetBytes($Body)
        $Context.Response.StatusCode = $Status
        $Context.Response.ContentType = 'application/json'
        $Context.Response.ContentLength64 = $bytes.Length
        $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
        $Context.Response.Close()
    }

    function Send-Sealed([string]$Nonce, $Reply) {
        $aes = New-Aes
        try {
            $aes.GenerateIV()
            $plain = $utf8.GetBytes($json.Serialize($Reply))
            $enc = $aes.CreateEncryptor()
            $ct = [Convert]::ToBase64String($enc.TransformFinalBlock($plain, 0, $plain.Length))
            $iv = [Convert]::ToBase64String($aes.IV)
        } finally { $aes.Dispose() }
        $mac = [Convert]::ToBase64String((Get-Mac "resp|$Nonce|$iv|$ct"))
        Send 200 ($json.Serialize(@{ v = 1; iv = $iv; ct = $ct; mac = $mac }))
    }

    function Invoke-Script([string]$Script, [int]$TimeoutSec) {
        # The script travels on stdin as base64 so neither the command-line length limit
        # nor the console code page can touch it. Anything that is not base64 (the BOM the
        # stdin writer may prepend, line breaks) is stripped before decoding.
        $boot = '$ProgressPreference=''SilentlyContinue'';' +
                '$__b=[Console]::In.ReadToEnd() -replace ''[^A-Za-z0-9+/=]'','''';' +
                '$__s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($__b));' +
                '. ([ScriptBlock]::Create($__s))'
        $psi = New-Object Diagnostics.ProcessStartInfo
        $psi.FileName = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $psi.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -OutputFormat Text -EncodedCommand ' +
                         [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($boot))
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.StandardOutputEncoding = $utf8
        $psi.StandardErrorEncoding = $utf8
        $proc = [Diagnostics.Process]::Start($psi)
        try {
            $out = $proc.StandardOutput.ReadToEndAsync()
            $err = $proc.StandardError.ReadToEndAsync()
            $proc.StandardInput.Write([Convert]::ToBase64String($utf8.GetBytes($Script)))
            $proc.StandardInput.Close()
            if (-not $proc.WaitForExit([Math]::Max(1, $TimeoutSec) * 1000)) {
                & taskkill.exe /T /F /PID $proc.Id 2>&1 | Out-Null
                $proc.WaitForExit(5000) | Out-Null
                return @{ stdout = ''; stderr = "Timed out after $TimeoutSec s; the process tree was killed."; exit_code = 124 }
            }
            $proc.WaitForExit()  # flushes the async readers
            @{ stdout = $out.Result; stderr = $err.Result; exit_code = $proc.ExitCode }
        } finally { $proc.Dispose() }
    }

    $client = $Context.Request.RemoteEndPoint.Address.ToString()
    $nonce = ''
    $op = '?'
    $started = Get-Date
    try {
        if ($Context.Request.HttpMethod -ne 'POST' -or $Context.Request.Url.AbsolutePath -ne '/rpc') {
            Send 404 '{"error":"not found"}'; return
        }
        $reader = New-Object IO.StreamReader($Context.Request.InputStream, $utf8)
        $env_ = $json.DeserializeObject($reader.ReadToEnd())
        $reader.Dispose()

        $ts = [long]$env_['ts']; $nonce = [string]$env_['nonce']
        $iv = [string]$env_['iv']; $ct = [string]$env_['ct']
        $given = $null
        try { $given = [Convert]::FromBase64String([string]$env_['mac']) } catch { }
        if (-not (Test-Same $given (Get-Mac "req|$ts|$nonce|$iv|$ct"))) {
            Log "$client rejected: bad signature (wrong key?)"
            Send 401 '{"error":"bad signature: the key does not match this agent"}'; return
        }
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        if ([Math]::Abs($now - $ts) -gt $MaxSkewSec) {
            Log "$client rejected: clock skew $($now - $ts) s"
            Send 401 ($json.Serialize(@{ error = "clock skew: request time differs from agent time by $($now - $ts) s (max $MaxSkewSec)"; agent_time = $now })); return
        }
        $nonces = $State.Nonces
        $seen = $false
        [Threading.Monitor]::Enter($nonces.SyncRoot)
        try {
            if ($nonces.ContainsKey($nonce)) { $seen = $true }
            else {
                $nonces[$nonce] = $now
                if ($nonces.Count -gt 5000) {
                    foreach ($k in @($nonces.Keys)) { if ($now - $nonces[$k] -gt 2 * $MaxSkewSec) { $nonces.Remove($k) } }
                }
            }
        } finally { [Threading.Monitor]::Exit($nonces.SyncRoot) }
        if ($seen) {
            Log "$client rejected: replayed nonce"
            Send 401 '{"error":"replayed request"}'; return
        }

        $aes = New-Aes
        try {
            $aes.IV = [Convert]::FromBase64String($iv)
            $cipher = [Convert]::FromBase64String($ct)
            $dec = $aes.CreateDecryptor()
            $req = $json.DeserializeObject($utf8.GetString($dec.TransformFinalBlock($cipher, 0, $cipher.Length)))
        } finally { $aes.Dispose() }

        $op = [string]$req['op']
        switch ($op) {
            'ping' {
                $reply = @{
                    computer = $env:COMPUTERNAME
                    user     = [Security.Principal.WindowsIdentity]::GetCurrent().Name
                    agent    = $State.Version
                    time     = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                }
            }
            'ps' {
                $timeout = 180
                if ($req.ContainsKey('timeout')) { $timeout = [int]$req['timeout'] }
                $reply = Invoke-Script ([string]$req['script']) $timeout
            }
            'upload' {
                $path = [string]$req['path']
                $dir = Split-Path -Parent $path
                if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
                $bytes = [Convert]::FromBase64String([string]$req['data'])
                [IO.File]::WriteAllBytes($path, $bytes)
                $reply = @{ size = $bytes.Length }
            }
            'download' {
                $bytes = [IO.File]::ReadAllBytes([string]$req['path'])
                $reply = @{ data = [Convert]::ToBase64String($bytes); size = $bytes.Length }
            }
            default { $reply = @{ error = "unknown op '$op'" } }
        }
        Send-Sealed $nonce $reply
        $ms = [int]((Get-Date) - $started).TotalMilliseconds
        $code = ''
        if ($reply.ContainsKey('exit_code')) { $code = " exit=$($reply['exit_code'])" }
        Log "$client $op ok ${ms}ms$code"
    } catch {
        $msg = $_.Exception.Message
        Log "$client $op failed: $msg"
        try {
            if ($nonce) { Send-Sealed $nonce @{ error = $msg } }
            else { Send 400 ($json.Serialize(@{ error = 'bad request' })) }
        } catch { }
    }
}

if (Test-Listening) { throw "Port $Port is already in use (another agent? check with -Status)." }
$listener = New-Object Net.HttpListener
$listener.Prefixes.Add("http://+:$Port/")
$pool = $null
$tempRule = $false
try {
    # Without -Install there is no permanent rule for this port, so open one for as long as we run.
    $installedRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue |
        Get-NetFirewallPortFilter | Where-Object { @($_.LocalPort) -contains "$Port" }
    if (-not $installedRule) {
        Get-NetFirewallRule -DisplayName $TempRuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        $tempRule = $true
        New-NetFirewallRule -DisplayName $TempRuleName -Direction Inbound -Protocol TCP -LocalPort $Port `
            -RemoteAddress $AllowFrom -Action Allow -Profile Any | Out-Null
        Write-Log "Firewall opened on TCP $Port from $($AllowFrom -join ', ') until the agent stops"
    }

    $listener.Start()
    $pool = [RunspaceFactory]::CreateRunspacePool(1, $MaxConcurrent)
    $pool.Open()
    $jobs = New-Object Collections.ArrayList
    [IO.File]::WriteAllText($PidPath, "$PID")
    Write-Log "WinMCP agent $AgentVersion listening on port $Port as $([Security.Principal.WindowsIdentity]::GetCurrent().Name) (PID $PID; Ctrl+C stops)"

    $pending = $listener.GetContextAsync()
    while ($listener.IsListening) {
        # Wait in short slices so Ctrl+C is honoured and finished jobs get cleaned up.
        if ($pending.Wait(1000)) {
            $ps = [PowerShell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript($Handler).AddArgument($pending.Result).AddArgument($State)
            [void]$jobs.Add(@{ PS = $ps; Handle = $ps.BeginInvoke() })
            $pending = $listener.GetContextAsync()
        }
        foreach ($job in @($jobs)) {
            if ($job.Handle.IsCompleted) {
                try { $job.PS.EndInvoke($job.Handle) | Out-Null } catch { Write-Log "handler error: $($_.Exception.Message)" }
                $job.PS.Dispose()
                $jobs.Remove($job)
            }
        }
    }
} catch {
    # A background agent has no window, so the log is the only place this can be seen.
    Write-Log "FATAL: $($_.Exception.Message)"
    throw
} finally {
    if ($listener.IsListening) { $listener.Stop() }
    $listener.Close()
    if ($pool) { $pool.Close() }
    if ($tempRule) { Get-NetFirewallRule -DisplayName $TempRuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule }
    if (Test-Path $PidPath) {
        if ([IO.File]::ReadAllText($PidPath).Trim() -eq "$PID") { Remove-Item $PidPath -ErrorAction SilentlyContinue }
    }
    Write-Log 'WinMCP agent stopped'
}
