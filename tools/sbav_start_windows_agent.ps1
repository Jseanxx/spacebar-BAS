param(
    [ValidateSet("win01", "dc01")]
    [string]$Role = "win01",
    [ValidateSet("simulation", "real")]
    [string]$Mode = "real",
    [string]$ProjectDir = "C:\SpacebarBAS",
    [string]$ElkUrl = "http://10.60.40.10:9200",
    [string]$LogstashUrl = "http://10.60.40.10:8088",
    [string]$ElkUsername,
    [string]$ElkPassword,
    [int]$AlertWaitSeconds = 0,
    [switch]$AllowDcRemoteAccess,
    [switch]$AllowLoaderArtifacts,
    [switch]$AllowLsassTest,
    [switch]$AllowAuthMaterialTest
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
$env:BAS_AV_LOGSTASH_URL = $LogstashUrl
$env:BAS_STEP_ALERT_WAIT_SECONDS = [string]$AlertWaitSeconds
$env:BAS_DEFER_ELK_CHECKS = "1"

if ($ElkUsername) {
    $env:BAS_ELK_USERNAME = $ElkUsername
}

if ($ElkPassword) {
    $env:BAS_ELK_PASSWORD = $ElkPassword
}

if ($Mode -eq "real") {
    $env:BAS_ALLOW_REAL_EXECUTION = "1"
}

if ($AllowDcRemoteAccess) {
    $env:BAS_AV_ALLOW_DC_REMOTE_ACCESS = "1"
}

if ($AllowLoaderArtifacts) {
    $env:BAS_AV_ALLOW_LOADER_ARTIFACTS = "1"
}

if ($AllowLsassTest) {
    $env:BAS_AV_ALLOW_LSASS_TEST = "1"
}

if ($AllowAuthMaterialTest) {
    $env:BAS_AV_ALLOW_AUTH_MATERIAL_TEST = "1"
}

$config = "agent_runtime\config.sbav-$Role.yaml"
if (-not (Test-Path -LiteralPath $config)) {
    throw "Agent config not found: $config"
}

Write-Host "[+] Starting SB-AV $Role BasAgent mode=$Mode"
Write-Host "[+] Config: $config"
Write-Host "[+] Controller: http://10.60.0.10:8000"
Write-Host "[+] ELK: $ElkUrl"
Write-Host "[!] Deferred loader/LSASS/auth-material gates stay disabled unless switches are set explicitly."

.\.venv\Scripts\python.exe agent_runtime\bas_agent.py --config $config --execution-mode $Mode
