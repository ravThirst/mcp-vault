@echo off
rem Stops the MCP Vault agent, which locks the vault.
rem MCP servers that are already running keep working; the next server start
rem brings the agent back and asks for the master password.
setlocal EnableExtensions
title Stop MCP Vault
cd /d "%~dp0"
set "VPY=%~dp0.venv\Scripts\python.exe"
if exist "%VPY%" goto :stop
echo  MCP Vault is not set up in this folder, so no agent from here can be running.
goto :done

:stop
rem --force also ends agent processes that no longer answer (e.g. a stale copy).
"%VPY%" "%~dp0vault.py" stop --force
if errorlevel 1 echo  Stopping failed; see the message above.

:done
rem Keep the window up briefly so the result can be read; ping works without a console.
ping -n 3 127.0.0.1 >nul
