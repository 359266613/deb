param(
    [Parameter(Mandatory=$true)]
    [string]$Old,
    [Parameter(Mandatory=$true)]
    [string]$New,
    [string]$Out = ".\outputs\diff"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$PythonExe = Join-Path $Root ".venv\Scripts\python.exe"
if (!(Test-Path $PythonExe)) { $PythonExe = "python" }

$env:PYTHONPATH = Join-Path $Root "src"
& $PythonExe -m deb_analyzer.cli diff --old $Old --new $New --out $Out