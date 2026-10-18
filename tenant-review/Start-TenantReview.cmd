@echo off
setlocal
set "HERE=%~dp0"
set "PSEXE=powershell.exe"
where pwsh.exe >nul 2>&1 && set "PSEXE=pwsh.exe"
%PSEXE% -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath $env:HERE -Recurse -File | Unblock-File" >nul 2>&1
start "" %PSEXE% -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%HERE%Start-TenantReview.ps1" -NoRelaunch
endlocal
