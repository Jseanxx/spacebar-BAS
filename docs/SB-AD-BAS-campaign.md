# SB-AD BAS Campaign

This document summarizes the active Spacebar AWS AD BAS campaign.

The BAS campaign now exposes all 23 SB-03 / SB-AD techniques in the dashboard. Safe discovery and staging steps can be executed through the proper BasAgent role, while credential dumping and domain-compromise steps are present but blocked by explicit safety gates unless an approved validation window is used.

## Files

- `campaigns/SB-AD.yaml`: 23 detection validation steps.
- `targets/SB-AD.yaml`: host metadata, ELK source queries, and alert queries.
- `modules/attack/sb_ad_technique.py`: shared execution module for SB-AD command templates.
- `tools/sb_ad_detection_rules.py`: Kibana detection rule sync helper for the SB-AD rules managed by this repo. Existing manual Kibana rules are referenced by rule ID instead of duplicated.
- `tools/sbad_support_server.py`: Attacker-side support server for benign file download and upload validation.
- `tools/sbad_start_attacker_support.sh`: Starts the attacker file and upload support servers.
- `tools/sbad_start_windows_agent.ps1`: Starts PC01/FS01 BasAgent from RDP or remote PowerShell.
- `agent_runtime/config.sbad-pc01.yaml`: PC01 BasAgent config template.
- `agent_runtime/config.sbad-fs01.yaml`: FS01 BasAgent config template.
- `agent_runtime/config.sbad-attacker.yaml`: Attacker Ubuntu BasAgent config template.

## Active Campaign Flow

| Scenario Order | Technique | Behavior key | Primary host | Severity | Source rule |
| --- | --- | --- | --- | --- | --- |
| 1 | T1204.002 | `user_execution_malicious_file` | PC01 | High | repo-managed |
| 2 | T1059.003 | `windows_command_shell` | PC01 | High | existing manual |
| 3 | T1095 | `non_application_tcp_connection` | PC01 | High | existing manual |
| 4 | T1087.002 | `domain_account_discovery` | PC01 | Low | existing manual |
| 5 | T1018 | `remote_system_discovery` | PC01 | Low | existing manual |
| 6 | T1033 | `system_owner_user_discovery` | PC01 | Low | existing manual |
| 7 | T1135 | `network_share_discovery` | PC01 | Low | repo-managed |
| 8 | T1069 | `permission_groups_discovery` | PC01 | Low | repo-managed |
| 9 | T1558.003 | `kerberoasting_tgs_request` | PC01/DC01 | Medium | repo-managed |
| 10 | T1021.006 | `winrm_remote_execution` | PC01 to FS01 | High | existing manual |
| 11 | T1059.001 | `powershell_over_winrm` | FS01 | High | existing manual |
| 12 | T1105 | `ingress_tool_transfer` | FS01 | Medium | existing manual |
| 13 | T1003.001 | `lsass_memory_dump` | FS01 | Critical | existing manual, gated |
| 14 | T1218.011 | `rundll32_comsvcs_proxy` | FS01 | Critical | repo-managed, gated |
| 15 | T1074.001 | `local_data_staging` | FS01 | High | repo-managed |
| 16 | T1041 | `exfiltration_over_c2` | FS01 | High | repo-managed |
| 17 | T1036.005 | `masquerading_legitimate_name` | FS01 | Medium | repo-managed |
| 18 | T1560.001 | `archive_collected_data` | FS01 | Medium | repo-managed |
| 19 | T1003.006 | `dcsync_replication` | Attacker/DC01 | Critical | repo-managed, gated |
| 20 | T1558.001 | `golden_ticket_service_ticket` | Attacker/DC01 | Critical | repo-managed, gated |
| 21 | T1078.002 | `valid_domain_account_remote_logon` | Attacker/DC01 | Critical | repo-managed, gated |
| 22 | T1569.002 | `service_execution` | Attacker/DC01 | Critical | repo-managed, gated |
| 23 | T1003.003 | `ntds_dump` | Attacker/DC01 | Critical | repo-managed, gated |

## Gated High-Risk Steps

The following steps are intentionally present in the dashboard but blocked in real mode unless dedicated environment variables are set:

- 13, 14: `BAS_ENABLE_CREDENTIAL_TESTS=1`
- 19: `BAS_ENABLE_DOMAIN_COMPROMISE_TESTS=1`
- 20, 21: `BAS_ENABLE_DOMAIN_COMPROMISE_TESTS=1` and `BAS_ENABLE_GOLDEN_TICKET_TESTS=1`
- 22: also requires `BAS_ENABLE_SERVICE_EXECUTION_TESTS=1`
- 23: also requires `BAS_ENABLE_NTDS_DUMP_TESTS=1`

This keeps the BAS useful for coverage visualization without accidentally running LSASS dumping, Golden Ticket usage, service execution, or NTDS dumping in Gahyun's AWS environment.

## Safety Model

Simulation mode never executes commands. It only returns the planned command templates and ELK query mappings.

Real mode is blocked unless all required safety gates are set. The shared module also checks `BAS_AGENT_ROLE`, so a PC01 command will not run on the attacker host or on the operator laptop by mistake.

Common real-mode gates:

- `BAS_ALLOW_REAL_EXECUTION=1`: required for any real command.
- `BAS_AGENT_ROLE=pc01|fs01|attacker`: required role for the current agent host.
- `BAS_ENABLE_CREDENTIAL_TESTS=1`: required for credential dumping.
- `BAS_ENABLE_DOMAIN_COMPROMISE_TESTS=1`: required for DCSync.
- `BAS_ENABLE_GOLDEN_TICKET_TESTS=1`: required for Golden Ticket creation/use.
- `BAS_ENABLE_SERVICE_EXECUTION_TESTS=1`: required for psexec-style service execution.
- `BAS_ENABLE_NTDS_DUMP_TESTS=1`: required for NTDS dump validation.

Secrets are not stored in the repo. Use environment variables on the relevant agent host:

- `BAS_SVC_FILE_PASSWORD`
- `BAS_DA_NTLM_HASH`
- `BAS_KRBTGT_AES256`
- `BAS_DOMAIN_SID`

## Run Examples

Simulation:

```powershell
python main.py --campaign SB-AD
```

PC01 real-mode agent example:

```powershell
$env:BAS_AGENT_ROLE = "pc01"
$env:BAS_ALLOW_REAL_EXECUTION = "1"
$env:BAS_SVC_FILE_PASSWORD = "<set locally>"
python agent_runtime\bas_agent.py --config agent_runtime\config.sbad-pc01.yaml --execution-mode real
```

Attacker real-mode agent example for DCSync:

```bash
export BAS_AGENT_ROLE=attacker
export BAS_ALLOW_REAL_EXECUTION=1
export BAS_ENABLE_DOMAIN_COMPROMISE_TESTS=1
export BAS_DA_NTLM_HASH="<set locally>"
python3 agent_runtime/bas_agent.py --config agent_runtime/config.sbad-attacker.yaml --execution-mode real
```

Attacker support servers for T1105/T1041:

```bash
cd /opt/spacebar-BAS
bash tools/sbad_start_attacker_support.sh
```

## Kibana Rule Management

Dry run:

```powershell
python tools\sb_ad_detection_rules.py --dry-run
```

Create/update repo-managed active rules:

```powershell
$env:KIBANA_URL = "http://<kibana-host>:5601"
$env:KIBANA_USERNAME = "<user>"
$env:KIBANA_PASSWORD = "<password>"
python tools\sb_ad_detection_rules.py
```

Current BAS rule mapping:

- Active BAS flow: 23 steps.
- Rule display names: scenario order plus MITRE technique ID, such as `13.T1003.001`.
- Existing manual Kibana rules are referenced by rule ID for orders 2-6 and 10-13.
- Repo-managed `sb-ad-*` rules are used for the remaining BAS-managed coverage checks.
