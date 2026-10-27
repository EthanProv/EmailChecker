@echo off
if /I "%~1"=="install" goto instalar
if not exist "%~dp0datos\cuentas\instalacion.json" goto instalar
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0programa\inicio.ps1" %*
exit /b %errorlevel%
:instalar
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0programa\instalar.ps1"
if errorlevel 1 (
  echo.
  echo La instalacion no ha terminado. Revisa el mensaje anterior y vuelve a intentarlo.
  pause
  exit /b 1
)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0programa\inicio.ps1"
exit /b %errorlevel%
