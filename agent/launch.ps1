# WinMCP remote agent downloader and launcher (Windows PowerShell 5.1+ / PowerShell 7).
#
# Run on the target Windows machine (asks for UAC elevation when needed):
#
#   irm https://raw.githubusercontent.com/ravThirst/mcp-vault/main/agent/launch.ps1 | iex
#
# Saves the agent scripts to C:\WinMCP, generates the shared key on first run
# (printing it to paste into MCP Vault), and starts the agent hidden in the
# background on TCP 5990 with a temporary firewall rule (nothing installed; runs
# until Stop, logoff or reboot). Run the same line again to update or restart.
#
# Optional settings, set in PowerShell before running:
#   $env:WINMCP_ALLOW_FROM = '192.168.0.10'  # allowed IPs/subnets (default Any)
#   $env:WINMCP_PORT       = '5990'          # TCP port to listen on (default 5990)
#   $env:WINMCP_INSTALL    = '1'             # install as a SYSTEM task at every boot
#   $env:WINMCP_DIR        = 'C:\WinMCP'     # folder for scripts, key and log
#   $env:WINMCP_SHOW_KEY   = '1'             # print an existing key again
#   $env:WINMCP_REF        = 'main'          # git branch or tag to fetch from

& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'  # the progress bar makes downloads very slow on PowerShell 5.1
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    function Say($text, $color = 'Gray') { Write-Host "  $text" -ForegroundColor $color }
    function Test-Admin {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    Write-Host ''
    Say 'WinMCP Agent launcher' 'Cyan'
    Say '====================='
    if ($env:OS -ne 'Windows_NT') { Say 'The WinMCP agent runs on Windows only.' 'Red'; return }

    $repo = 'ravThirst/mcp-vault'
    $ref = if ($env:WINMCP_REF) { $env:WINMCP_REF.Trim() } else { 'main' }
    $dir = if ($env:WINMCP_DIR) { $env:WINMCP_DIR.Trim() } else { 'C:\WinMCP' }

    $portExplicit = [bool]($env:WINMCP_PORT -and $env:WINMCP_PORT.Trim())
    $port = 5990
    if ($portExplicit) {
        if (-not [int]::TryParse($env:WINMCP_PORT.Trim(), [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
            Say "Invalid WINMCP_PORT '$env:WINMCP_PORT' (expected 1..65535)." 'Red'
            return
        }
    }

    $allowExplicit = [bool]($env:WINMCP_ALLOW_FROM -and $env:WINMCP_ALLOW_FROM.Trim())
    $allowFrom = if ($allowExplicit) { ($env:WINMCP_ALLOW_FROM -replace '"', '').Trim() } else { 'Any' }

    $installMode = 'auto'
    if ($env:WINMCP_INSTALL -and $env:WINMCP_INSTALL.Trim()) {
        $rawInstall = $env:WINMCP_INSTALL.Trim().ToLowerInvariant()
        if ($rawInstall -in @('1', 'true', 'yes', 'on')) { $installMode = 'install' }
        elseif ($rawInstall -in @('0', 'false', 'no', 'off')) { $installMode = 'background' }
        else { Say "Invalid WINMCP_INSTALL '$env:WINMCP_INSTALL' (expected 1 or 0)." 'Red'; return }
    }

    $showKey = [bool]($env:WINMCP_SHOW_KEY -and ($env:WINMCP_SHOW_KEY.Trim().ToLowerInvariant() -in @('1', 'true', 'yes', 'on')))
    $dryRun = [bool]($env:WINMCP_DRY_RUN -and ($env:WINMCP_DRY_RUN.Trim().ToLowerInvariant() -in @('1', 'true', 'yes', 'on')))

    $files = @('winmcp-agent.ps1', 'Start WinMCP Agent.bat', 'Stop WinMCP Agent.bat')
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('winmcp-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null

    $handedOff = $false
    try {
        if ($env:WINMCP_SOURCE_DIR) {
            foreach ($f in $files) {
                Copy-Item -LiteralPath (Join-Path $env:WINMCP_SOURCE_DIR $f) -Destination (Join-Path $tmp $f) -Force
            }
        } else {
            Say "Downloading agent scripts from $repo ($ref) ..."
            $base = "https://raw.githubusercontent.com/$repo/$ref/agent"
            foreach ($f in $files) {
                $uri = "$base/$([Uri]::EscapeDataString($f))"
                Invoke-WebRequest -Uri $uri -OutFile (Join-Path $tmp $f) -UseBasicParsing
            }
        }

        $downloaded = [IO.File]::ReadAllText((Join-Path $tmp 'winmcp-agent.ps1'), [Text.Encoding]::UTF8)
        if ($downloaded -notmatch '\$TaskName\s*=\s*''WinMCP Agent''') {
            throw 'the downloaded file does not look like winmcp-agent.ps1'
        }

        # Stage settings + post-download runner in $tmp so UAC elevation (which drops
        # custom environment variables) still receives every setting intact.
        $cfg = @{
            dir           = $dir
            port          = $port
            portExplicit  = $portExplicit
            allowFrom     = $allowFrom
            allowExplicit = $allowExplicit
            installMode   = $installMode
            showKey       = $showKey
            dryRun        = $dryRun
        }
        $utf8NoBom = New-Object Text.UTF8Encoding $false
        [IO.File]::WriteAllText((Join-Path $tmp '_config.json'), ($cfg | ConvertTo-Json -Compress), $utf8NoBom)

        $finishBody = @'
$ErrorActionPreference = 'Stop'
$stage = $PSScriptRoot
Set-Location $env:SystemRoot
function Say($text, $color = 'Gray') { Write-Host "  $text" -ForegroundColor $color }

try {
    $cfg = Get-Content -Raw -LiteralPath (Join-Path $stage '_config.json') -Encoding UTF8 | ConvertFrom-Json
    $dir = [string]$cfg.dir
    $port = [int]$cfg.port
    $allowFrom = [string]$cfg.allowFrom

    $existingBat = Join-Path $dir 'Start WinMCP Agent.bat'
    if (Test-Path -LiteralPath $existingBat) {
        $oldBat = Get-Content -Raw -LiteralPath $existingBat -ErrorAction SilentlyContinue
        if (-not $cfg.portExplicit -and $oldBat -match '(?m)^set "PORT=(\d+)"') {
            $port = [int]$Matches[1]
        }
        if (-not $cfg.allowExplicit -and $oldBat -match '(?m)^set "ALLOW_FROM=(?!%ALLOW_FROM:)([^"\r\n]+)"') {
            $allowFrom = $Matches[1].Trim()
        }
    }

    $stagedBat = Join-Path $stage 'Start WinMCP Agent.bat'
    $batText = [IO.File]::ReadAllText($stagedBat, [Text.Encoding]::UTF8)
    $batText = $batText -replace '(?m)^set "PORT=[^\r\n]*"', "set `"PORT=$port`""
    $batText = $batText -replace '(?m)^set "ALLOW_FROM=(?!%ALLOW_FROM:)[^\r\n]*"', "set `"ALLOW_FROM=$allowFrom`""
    $batText = $batText -replace '\r?\n', "`r`n"
    [IO.File]::WriteAllText($stagedBat, $batText, (New-Object Text.UTF8Encoding $false))

    $stagedStopBat = Join-Path $stage 'Stop WinMCP Agent.bat'
    $stopText = [IO.File]::ReadAllText($stagedStopBat, [Text.Encoding]::UTF8) -replace '\r?\n', "`r`n"
    [IO.File]::WriteAllText($stagedStopBat, $stopText, (New-Object Text.UTF8Encoding $false))

    if (-not $cfg.dryRun) {
        $existingAgent = Join-Path $dir 'winmcp-agent.ps1'
        $existingTask = Get-ScheduledTask -TaskName 'WinMCP Agent' -ErrorAction SilentlyContinue
        $wasRunning = (Test-Path -LiteralPath (Join-Path $dir 'agent.pid')) -or ($existingTask -and $existingTask.State -eq 'Running')
        if ((Test-Path -LiteralPath $existingAgent) -and $wasRunning) {
            Say 'Stopping running WinMCP agent ...'
            try { & $existingAgent -Stop | Out-Null } catch { }
            for ($i = 0; $i -lt 15; $i++) {
                if (-not (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue)) { break }
                Start-Sleep -Milliseconds 300
            }
        }
    }

    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    foreach ($f in @('winmcp-agent.ps1', 'Start WinMCP Agent.bat', 'Stop WinMCP Agent.bat')) {
        $dst = Join-Path $dir $f
        Copy-Item -LiteralPath (Join-Path $stage $f) -Destination $dst -Force
        Unblock-File -LiteralPath $dst -ErrorAction SilentlyContinue
    }

    if ($cfg.dryRun) {
        Say "Dry run complete: staged scripts into $dir (port $port, allow $allowFrom, mode $($cfg.installMode))." 'Green'
        return
    }

    $agent = Join-Path $dir 'winmcp-agent.ps1'
    $keyExisted = Test-Path -LiteralPath (Join-Path $dir 'agent.key')
    $existingTask = Get-ScheduledTask -TaskName 'WinMCP Agent' -ErrorAction SilentlyContinue
    $install = switch ([string]$cfg.installMode) {
        'install'    { $true }
        'background' { $false }
        default      { [bool]$existingTask }
    }

    if (-not $install -and $existingTask -and [string]$cfg.installMode -eq 'background') {
        & $agent -Uninstall
    }

    if ($install) {
        & $agent -Install -Port $port -AllowFrom $allowFrom
    } else {
        & $agent -Background -Port $port -AllowFrom $allowFrom
    }

    if ($keyExisted -and $cfg.showKey) {
        & $agent -ShowKey
    }

    Write-Host ''
    Say "Files saved in $dir" 'Green'
    if ($keyExisted -and -not $cfg.showKey) {
        Say "Show key:   powershell -ep Bypass -File `"$agent`" -ShowKey"
    }
    Say "Status:     powershell -ep Bypass -File `"$agent`" -Status -Port $port"
    Say "Stop agent: `"$(Join-Path $dir 'Stop WinMCP Agent.bat')`""
    Write-Host ''
} catch {
    Write-Host ''
    Say "Launch failed: $($_.Exception.Message)" 'Red'
    exit 1
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}
'@
        $finish = Join-Path $tmp '_finish.ps1'
        [IO.File]::WriteAllText($finish, $finishBody, $utf8NoBom)

        $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if ((Test-Admin) -or $dryRun) {
            # Run via powershell.exe -ExecutionPolicy Bypass so a default Windows 10/11
            # 'Restricted' execution policy never blocks _finish.ps1 or winmcp-agent.ps1.
            $handedOff = $true
            & $psExe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $finish
            $global:LASTEXITCODE = 0
        } else {
            Say 'Administrator rights are needed; asking for elevation (UAC) ...' 'Yellow'
            Start-Process -FilePath $psExe -Verb RunAs -ArgumentList @(
                '-NoLogo', '-NoProfile', '-NoExit', '-ExecutionPolicy', 'Bypass', '-File', "`"$finish`""
            ) | Out-Null
            $handedOff = $true
            Say 'Continued in the elevated PowerShell window.' 'Green'
            Write-Host ''
        }
    } catch {
        Say "Launch failed: $($_.Exception.Message)" 'Red'
    } finally {
        if (-not $handedOff) {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
