param(
    [ValidateSet("pc01", "fs01")]
    [string]$Role = "pc01",
    [ValidateSet("simulation", "real")]
    [string]$Mode = "real",
    [string]$ProjectDir = "C:\SpacebarBAS\spacebar-BAS-bas-operation-builder",
    [string]$ElkUrl = "http://10.0.4.30:9200",
    [string]$ElkUsername = "elastic",
    [string]$ElkPassword,
    [string]$SvcFilePassword,
    [int]$AlertWaitSeconds = 45,
    [switch]$AllowRealExecution,
    [switch]$EnableCredentialTests
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
$env:BAS_ELK_URL = $ElkUrl
$env:BAS_ELK_USERNAME = $ElkUsername
$env:BAS_STEP_ALERT_WAIT_SECONDS = [string]$AlertWaitSeconds

if ($ElkPassword) {
    $env:BAS_ELK_PASSWORD = $ElkPassword
}

if ($SvcFilePassword) {
    $env:BAS_SVC_FILE_PASSWORD = $SvcFilePassword
}

if ($AllowRealExecution -or $Mode -eq "real") {
    $env:BAS_ALLOW_REAL_EXECUTION = "1"
}

if ($EnableCredentialTests) {
    $env:BAS_ENABLE_CREDENTIAL_TESTS = "1"
}

$config = "agent_runtime\config.sbad-$Role.yaml"
if (-not (Test-Path -LiteralPath $config)) {
    throw "Agent config not found: $config"
}

Write-Host "[+] Starting SB-AD $Role BasAgent mode=$Mode"
Write-Host "[+] Config: $config"
Write-Host "[+] ELK: $ElkUrl"
Write-Host "[!] Secrets such as BAS_SVC_FILE_PASSWORD and BAS_ELK_PASSWORD must be set before real validation."

.\.venv\Scripts\python.exe agent_runtime\bas_agent.py --config $config --execution-mode $Mode
