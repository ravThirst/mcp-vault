@echo off
rem Starts the WinMCP agent hidden in the background. Nothing is installed: it runs
rem until "Stop WinMCP Agent.bat", logoff or reboot, and the firewall is opened only
rem while it runs. Asks for administrator rights (UAC) when needed.
rem
rem Who may connect: set ALLOW_FROM to your workstation address (comma-separated list
rem or subnet such as 192.168.0.0/24), or pass it on the command line.
set "PORT=5990"
set "ALLOW_FROM=Any"
rem %* rather than %1: cmd splits arguments at commas.
if not "%~1"=="" set "ALLOW_FROM=%*"
set "ALLOW_FROM=%ALLOW_FROM:"=%"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0winmcp-agent.ps1" -Background -Port %PORT% -AllowFrom "%ALLOW_FROM%"
pause
