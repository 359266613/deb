param(
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Venv = Join-Path $Root ".venv"
$PythonExe = Join-Path $Venv "Scripts\python.exe"

if (!(Test-Path $PythonExe)) {
    & $Python -m venv $Venv
}

& $PythonExe -m pip install --upgrade pip
& $PythonExe -m pip install -r (Join-Path $Root "requirements.txt")
& $PythonExe -m pip install -e $Root

Write-Host "Environment ready: $PythonExe"