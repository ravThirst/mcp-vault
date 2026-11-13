@echo off
rem Stops the WinMCP agent and closes its temporary firewall rule.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0winmcp-agent.ps1" -Stop
pause
