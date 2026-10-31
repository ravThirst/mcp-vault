@echo off
rem MCP Vault launcher: checks dependencies, sets up on first run, opens the UI.
rem   "MCP Vault.bat"         start (runs setup only when something is missing)
rem   "MCP Vault.bat" setup   force the dependency check / repair
setlocal EnableExtensions
title MCP Vault
cd /d "%~dp0"
set "APP=%~dp0"
set "VENV=%APP%.venv"
set "VPY=%VENV%\Scripts\python.exe"
set "SHORTCUT=%APPDATA%\Microsoft\Windows\Start Menu\Programs\MCP Vault.lnk"

if /i "%~1"=="setup" goto :setup

rem ---- fast path: environment already works ------------------------------
if not exist "%VPY%" goto :setup
"%VPY%" -c "import cryptography, paramiko" >nul 2>&1
if errorlevel 1 goto :setup
goto :launch

rem ---- setup -----------------------------------------------------------------
:setup
echo.
echo  MCP Vault setup
echo  ===============
call :find_python
if not defined PY goto :no_python
echo  Python found:
%PY% --version
%PY% -c "import tkinter" >nul 2>&1
if errorlevel 1 echo  WARNING: this Python has no tkinter, so the unlock pop-up will not work. You can still unlock in the browser.

if not exist "%VENV%" goto :make_venv
if not exist "%VPY%" goto :rebuild_venv
"%VPY%" -c "import sys" >nul 2>&1
if not errorlevel 1 goto :install
:rebuild_venv
echo  The existing .venv is broken (copied from another PC or Python was removed). Recreating it...
rem A running agent keeps .venv files open; stop it first (this command only needs the standard library).
%PY% "%APP%vault.py" stop >nul 2>&1
set /a TRIES=0
:remove_venv
rmdir /s /q "%VENV%" 2>nul
if not exist "%VENV%" goto :make_venv
set /a TRIES+=1
if %TRIES% geq 10 goto :venv_locked
rem The agent needs a moment to exit after "stop"; ping is a delay that works without a console.
ping -n 2 127.0.0.1 >nul
goto :remove_venv

:make_venv
echo  Creating the app environment in .venv ...
%PY% -m venv "%VENV%"
if errorlevel 1 goto :fail

:install
echo  Installing dependencies (cryptography, paramiko) ...
"%VPY%" -m pip install --disable-pip-version-check --quiet -r "%APP%requirements.txt"
if errorlevel 1 goto :fail
"%VPY%" -c "import cryptography, paramiko" >nul 2>&1
if errorlevel 1 goto :fail
echo  Dependencies OK.

rem Already chose shortcuts earlier: refresh them (adds ones new versions bring, like Stop MCP Vault).
if not exist "%SHORTCUT%" goto :ask_shortcut
"%VPY%" "%APP%vault.py" install-shortcut --quiet
goto :skills

:ask_shortcut
echo.
choice /c YN /n /m " Add MCP Vault (and Stop MCP Vault) to the Start menu? [Y/N] "
if errorlevel 2 goto :skills
"%VPY%" "%APP%vault.py" install-shortcut

:skills
rem Offer the skills only where a supported client is installed and they are missing.
set "SKILLS_NEEDED="
if exist "%USERPROFILE%\.claude" if not exist "%USERPROFILE%\.claude\skills\mcp-vault\SKILL.md" set "SKILLS_NEEDED=1"
if exist "%APPDATA%\kimi-desktop\daimon-share\daimon\skills" if not exist "%APPDATA%\kimi-desktop\daimon-share\daimon\skills\mcp-vault\SKILL.md" set "SKILLS_NEEDED=1"
if not defined SKILLS_NEEDED goto :launch
echo.
choice /c YN /n /m " Install the MCP Vault skills for Claude Code / Kimi Work? [Y/N] "
if errorlevel 2 goto :launch
"%VPY%" "%APP%vault.py" install-skills

rem ---- launch ----------------------------------------------------------------
:launch
"%VPY%" "%APP%vault.py" ui
if errorlevel 1 goto :fail_launch
exit /b 0

rem ---- helpers ---------------------------------------------------------------
:find_python
set "PY="
for %%c in ("py -3" "python" "python3") do call :try_command %%c
rem A fresh winget/python.org install is not on this window's PATH yet.
for /d %%d in ("%LOCALAPPDATA%\Programs\Python\Python3*") do call :try_path "%%d\python.exe"
exit /b 0

:try_command
if defined PY exit /b 0
%~1 -c "import sys; v = sys.version_info; assert v.major == 3 and v.minor >= 10" >nul 2>&1
if not errorlevel 1 set "PY=%~1"
exit /b 0

:try_path
if defined PY exit /b 0
if not exist "%~1" exit /b 0
"%~1" -c "import sys; v = sys.version_info; assert v.major == 3 and v.minor >= 10" >nul 2>&1
if not errorlevel 1 set PY="%~1"
exit /b 0

:no_python
echo.
echo  Python 3.10 or newer is required but was not found.
where winget >nul 2>&1
if errorlevel 1 goto :manual_python
choice /c YN /n /m " Install Python 3.12 for your user account with winget now? [Y/N] "
if errorlevel 2 goto :manual_python
winget install -e --id Python.Python.3.12 --scope user
call :find_python
if defined PY goto :setup
echo.
echo  Python was installed. Close this window and start "MCP Vault.bat" again.
pause
exit /b 1

:manual_python
echo  Install it from https://www.python.org/downloads/ (tick "Add python.exe to PATH"),
echo  then start "MCP Vault.bat" again.
pause
exit /b 1

:fail
echo.
echo  Setup failed; see the messages above. Run "MCP Vault.bat" setup to retry.
pause
exit /b 1

:venv_locked
echo.
echo  Could not delete "%VENV%" because files in it are in use.
echo  Close Claude and any MCP Vault windows, or sign out and back in, then run "MCP Vault.bat" setup.
pause
exit /b 1

:fail_launch
echo.
echo  MCP Vault could not start. Details: %APPDATA%\mcp-vault\agent.log
pause
exit /b 1
