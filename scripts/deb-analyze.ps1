param(
    [Parameter(Mandatory=$true)]
    [Alias("Input")]
    [string]$DebInput,
    [string]$Out = ".\outputs",
    [int]$Jobs = 1,
    [switch]$DryRun,
    [string]$Config = "",
    [string]$Keywords = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$PythonExe = Join-Path $Root ".venv\Scripts\python.exe"
if (!(Test-Path $PythonExe)) { $PythonExe = "python" }

$ArgsList = @("-m", "deb_analyzer.cli", "analyze", "--input", $DebInput, "--out", $Out, "--jobs", "$Jobs")
if ($DryRun) { $ArgsList += "--dry-run" }
if ($Config) { $ArgsList += @("--config", $Config) }
if ($Keywords) { $ArgsList += @("--keywords", $Keywords) }

$env:PYTHONPATH = Join-Path $Root "src"
& $PythonExe @ArgsList