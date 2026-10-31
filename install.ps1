# MCP Vault installer and updater (Windows PowerShell 5.1+ / PowerShell 7).
#
#   irm https://raw.githubusercontent.com/ravThirst/mcp-vault/main/install.ps1 | iex
#
# Run the same line again to update. Optional settings, set before running:
#   $env:MCPVAULT_DIR = 'D:\Tools\mcp-vault'   # install folder (default ~\.mcp-servers\mcp-vault)
#   $env:MCPVAULT_REF = 'v0.2.0'               # branch or tag to install (default main)
#
# It only downloads the app's code from GitHub, then runs "MCP Vault.bat" setup.
# Your vault, logs and backups live in %APPDATA%\mcp-vault and are never touched.

& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'  # the progress bar makes downloads very slow on PowerShell 5.1
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $repo = 'ravThirst/mcp-vault'
    $ref = 'main'
    if ($env:MCPVAULT_REF) { $ref = $env:MCPVAULT_REF }
    $dir = Join-Path $HOME '.mcp-servers\mcp-vault'
    if ($env:MCPVAULT_DIR) { $dir = $env:MCPVAULT_DIR }

    function Say($text, $color = 'Gray') { Write-Host "  $text" -ForegroundColor $color }

    Write-Host ''
    Say 'MCP Vault installer' 'Cyan'
    Say '==================='
    if ($env:OS -ne 'Windows_NT') { Say 'MCP Vault runs on Windows only.' 'Red'; return }

    if (Test-Path (Join-Path $dir '.git')) {
        Say "$dir is a git checkout; update it with 'git pull' instead." 'Yellow'
        return
    }
    $updating = Test-Path (Join-Path $dir 'vault.py')
    if ($updating) { Say "Updating the existing install in $dir" } else { Say "Installing into $dir" }

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('mcp-vault-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        $zip = Join-Path $tmp 'mcp-vault.zip'
        if ($env:MCPVAULT_ZIP) {
            Copy-Item $env:MCPVAULT_ZIP $zip  # local archive, for testing the installer
        } else {
            Say "Downloading $repo ($ref) ..."
            Invoke-WebRequest -Uri "https://github.com/$repo/archive/$ref.zip" -OutFile $zip -UseBasicParsing
        }
        Expand-Archive -Path $zip -DestinationPath (Join-Path $tmp 'x') -Force
        $src = Get-ChildItem (Join-Path $tmp 'x') -Directory | Select-Object -First 1
        if (-not $src -or -not (Test-Path (Join-Path $src.FullName 'vault.py'))) { throw 'the download does not look like MCP Vault' }

        if ($updating) {
            # Stop a running agent so the new code is used; it starts again (locked) on demand.
            $py = Join-Path $dir '.venv\Scripts\python.exe'
            if (Test-Path $py) { try { & $py (Join-Path $dir 'vault.py') stop | Out-Null } catch { } }
            # Replace the code folders wholesale so files removed upstream disappear;
            # .venv, NOTES-local.md and anything else of yours stays.
            foreach ($d in 'mcpvault', 'skills') {
                $p = Join-Path $dir $d
                if (Test-Path $p) { Remove-Item $p -Recurse -Force }
            }
        }
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        & robocopy.exe $src.FullName $dir /E /NFL /NDL /NJH /NJS /NP | Out-Null
        if ($LASTEXITCODE -ge 8) { throw "copying files failed (robocopy exit $LASTEXITCODE)" }
        $global:LASTEXITCODE = 0

        # Files fetched from the internet may carry a "mark of the web" that makes
        # SmartScreen block the .bat; this is the code the user just chose to install.
        Get-ChildItem $dir -Recurse -File | Where-Object { $_.FullName -notlike '*\.venv\*' } | Unblock-File
    } catch {
        Say "Install failed: $($_.Exception.Message)" 'Red'
        return
    } finally {
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Keep installed agent skills in step with the new version.
    $skills = Join-Path $HOME '.claude\skills\mcp-vault\SKILL.md'
    $kimiSkills = Join-Path $env:APPDATA 'kimi-desktop\daimon-share\daimon\skills\mcp-vault\SKILL.md'
    $py = Join-Path $dir '.venv\Scripts\python.exe'
    if ($updating -and ((Test-Path $skills) -or (Test-Path $kimiSkills)) -and (Test-Path $py)) {
        & $py (Join-Path $dir 'vault.py') install-skills --force | Out-Null
        Say 'Updated the agent skills.'
    }

    Say 'Files are in place. Running setup (Python check, dependencies, shortcuts) ...' 'Green'
    $bat = Join-Path $dir 'MCP Vault.bat'
    # Start-Process passes the command line verbatim; PowerShell 5.1's own argument
    # passing breaks the nested quotes a path with spaces needs. Not -Wait: that also
    # waits for every descendant, including the background agent setup leaves running.
    $setup = Start-Process -FilePath $env:ComSpec -ArgumentList "/d /s /c `"`"$bat`" setup`"" -NoNewWindow -PassThru
    $null = $setup.Handle  # keeps ExitCode readable after exit on PowerShell 5.1
    $setup.WaitForExit()
    if ($setup.ExitCode -ne 0) {
        Say "Setup did not finish. Fix the problem above, then run: `"$bat`" setup" 'Yellow'
        return
    }

    Write-Host ''
    Say 'MCP Vault is installed.' 'Green'
    Say "Start it from the Start menu (MCP Vault) or with: `"$bat`""
    Say 'Update later by running the same install command again.'
    Write-Host ''
}
