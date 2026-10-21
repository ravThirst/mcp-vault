@echo off
rem Builds mcp-vault-<version>.zip with the app's source files only.
rem Vaults, passwords, backups and logs live in %APPDATA%\mcp-vault and are never included.
setlocal EnableExtensions
cd /d "%~dp0"
set "VPY=%~dp0.venv\Scripts\python.exe"
if exist "%VPY%" goto :run
echo Run "MCP Vault.bat" once first so the app environment exists.
pause
exit /b 1

:run
"%VPY%" "%~dp0vault.py" package
echo.
echo Send the zip. The recipient extracts it anywhere and double-clicks "MCP Vault.bat".
pause
