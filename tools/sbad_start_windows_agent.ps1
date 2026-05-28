param(
    [ValidateSet("pc01", "fs01")]
    [string]$Role = "pc01",
    [ValidateSet("simulation", "real")]
    [string]$Mode = "simulation",
    [string]$ProjectDir = "C:\SpacebarBAS\spacebar-BAS-bas-operation-builder",
    [switch]$AllowRealExecution
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $ProjectDir)) {
    throw "Project directory not found: $ProjectDir"
}

Set-Location -LiteralPath $ProjectDir

if (-not (Test-Path -LiteralPath ".\.venv\Scripts\python.exe")) {
    py -3 -m venv .venv
}

.\.venv\Scripts\python.exe -m pip install -r requirements.txt

$env:BAS_AGENT_ROLE = $Role

if ($AllowRealExecution) {
    $env:BAS_ALLOW_REAL_EXECUTION = "1"
}

$config = "agent_runtime\config.sbad-$Role.yaml"
if (-not (Test-Path -LiteralPath $config)) {
    throw "Agent config not found: $config"
}

Write-Host "[+] Starting SB-AD $Role BasAgent mode=$Mode"
Write-Host "[+] Config: $config"
Write-Host "[!] Secrets such as BAS_SVC_FILE_PASSWORD must be set in this PowerShell session before real WinRM steps."

.\.venv\Scripts\python.exe agent_runtime\bas_agent.py --config $config --execution-mode $Mode
