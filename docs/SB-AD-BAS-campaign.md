# SB-AD BAS Campaign

This document summarizes the active Spacebar AWS AD BAS campaign.

The BAS campaign is limited to the detection rules that currently exist in Kibana for SB-AD. It includes Gahyun's existing 2-6 rules, Junseo's confirmed 10-13, 15, 16, and 19 rules, and excludes missing, postponed, duplicate, and not-yet-implemented steps.

## Files

- `campaigns/SB-AD.yaml`: 12 detection validation steps.
- `targets/SB-AD.yaml`: host metadata, ELK source queries, and alert queries.
- `modules/attack/sb_ad_technique.py`: shared execution module for SB-AD command templates.
- `tools/sb_ad_detection_rules.py`: Kibana detection rule sync helper for the SB-AD rules managed by this repo. Existing manual Kibana rules are referenced by rule ID instead of duplicated.
- `agent_runtime/config.sbad-pc01.yaml`: PC01 BasAgent config template.
- `agent_runtime/config.sbad-fs01.yaml`: FS01 BasAgent config template.
- `agent_runtime/config.sbad-attacker.yaml`: Attacker Ubuntu BasAgent config template.

## Active Campaign Flow

| Scenario Order | Technique | Behavior key | Primary host | Severity | Source rule |
| --- | --- | --- | --- | --- | --- |
| 2 | T1059.003 | `windows_command_shell` | PC01 | High | existing manual |
| 3 | T1095 | `non_application_tcp_connection` | PC01 | High | existing manual |
| 4 | T1087.002 | `domain_account_discovery` | PC01 | Low | existing manual |
| 5 | T1018 | `remote_system_discovery` | PC01 | Low | existing manual |
| 6 | T1033 | `system_owner_user_discovery` | PC01 | Low | existing manual |
| 10 | T1021.006 | `winrm_remote_execution` | PC01 to FS01 | High | existing manual |
| 11 | T1059.001 | `powershell_over_winrm` | FS01 | High | existing manual |
| 12 | T1105 | `ingress_tool_transfer` | FS01 | Medium | existing manual |
| 13 | T1003.001 | `lsass_memory_dump` | FS01 | Critical | existing manual |
| 15 | T1074.001 | `local_data_staging` | FS01 | High | repo-managed |
| 16 | T1041 | `exfiltration_over_c2` | FS01 | High | repo-managed |
| 19 | T1003.006 | `dcsync_replication` | Attacker/DC01 | Critical | repo-managed |

## Disabled/Excluded Rules

The following scenario steps are excluded from the active BAS campaign:

- Original orders 1, 7, 8, 9: no current Kibana rule was found.
- Original orders 14, 17, 18: postponed or supporting evidence, not active BAS steps.
- Original orders 20, 21, 22: not implemented by the operator yet, so they are excluded from SB-AD BAS for now.
- `T1218.011`: supporting evidence for `T1003.001`, not a separate active validation rule.
- `T1036.005`: postponed.
- `T1560.001`: postponed.
- `T1003.003`: not a separate active validation rule in the current campaign.

## Safety Model

Simulation mode never executes commands. It only returns the planned command templates and ELK query mappings.

Real mode is blocked unless all required safety gates are set. The shared module also checks `BAS_AGENT_ROLE`, so a PC01 command will not run on the attacker host or on the operator laptop by mistake.

Common real-mode gates:

- `BAS_ALLOW_REAL_EXECUTION=1`: required for any real command.
- `BAS_AGENT_ROLE=pc01|fs01|attacker`: required role for the current agent host.
- `BAS_ENABLE_CREDENTIAL_TESTS=1`: required for credential dumping.
- `BAS_ENABLE_DOMAIN_COMPROMISE_TESTS=1`: required for DCSync.

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

- Active BAS flow: 12 steps.
- Rule display names: scenario order plus MITRE technique ID, such as `13.T1003.001`.
- Existing manual Kibana rules are referenced by rule ID for orders 2-6 and 10-13.
- Repo-managed `sb-ad-*` rules are used for orders 15, 16, and 19.
