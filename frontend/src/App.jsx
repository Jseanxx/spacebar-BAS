// 화면 로직 
// API 상태 확인 , 캠페인 목록, 캠페인 상세 표시, Run Campaign 버튼 처리
// 실행 결과 목록 표시, 실행 결과 상세 표시 

import { useEffect, useState } from "react";
import spacebarLogo from "./assets/spacebar-logo.png";
import "./styles.css";

const API_BASE = "http://127.0.0.1:8000";
const REPORT_MOCKUP_URL = "/mockups/sb-ad-report.html";
const JOB_POLL_INTERVAL_MS = 800;
const JOB_POLL_ATTEMPTS = 40;
const RUNS_PER_PAGE = 5;
const VALID_VIEWS = new Set(["summary", "validation", "scope", "assets", "history", "evidence"]);
const TECHNIQUE_NAMES = {
  "T1003.001": "OS Credential Dumping: LSASS Memory",
  "T1003.006": "DCSync",
  "T1003.003": "NTDS",
  "T1018": "Remote System Discovery",
  "T1033": "System Owner/User Discovery",
  "T1036.005": "Masquerading: Match Legitimate Name or Location",
  "T1041": "Exfiltration Over C2 Channel",
  "T1059.001": "Command and Scripting Interpreter: PowerShell",
  "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
  "T1069": "Permission Groups Discovery",
  "T1074.001": "Local Data Staging",
  "T1078.002": "Valid Accounts: Domain Accounts",
  "T1087.002": "Account Discovery: Domain Account",
  "T1095": "Non-Application Layer Protocol",
  "T1105": "Ingress Tool Transfer",
  "T1135": "Network Share Discovery",
  "T1204.002": "User Execution: Malicious File",
  "T1218.011": "System Binary Proxy Execution: Rundll32",
  "T1021.004": "Remote Services: SSH",
  "T1021.006": "Remote Services: Windows Remote Management",
  "T1558.001": "Golden Ticket",
  "T1558.003": "Kerberoasting",
  "T1560.001": "Archive via Utility",
  "T1569.002": "Service Execution",
  "T1083": "File and Directory Discovery",
  "T1098.006": "Additional Container and Cloud Roles",
  "T1552.007": "Container and Resource Discovery Credentials",
  "T1567.002": "Exfiltration to Cloud Storage",
  "T1609": "Container and Resource Discovery",
  "T1610": "Deploy Container",
  "T1613": "Container and Resource Discovery",
};
const TECHNIQUE_EVIDENCE_KEYS = {
  "T1003.001": "lsass_memory_dump",
  "T1003.003": "ntds_dump",
  "T1003.006": "dcsync_replication",
  "T1018": "remote_system_discovery",
  "T1021.006": "winrm_remote_execution",
  "T1033": "system_owner_user_discovery",
  "T1036.005": "masquerading_legitimate_name",
  "T1041": "exfiltration_over_c2",
  "T1059.001": "powershell_over_winrm",
  "T1059.003": "windows_command_shell",
  "T1069": "permission_groups_discovery",
  "T1074.001": "local_data_staging",
  "T1078.002": "valid_domain_account_remote_logon",
  "T1087.002": "domain_account_discovery",
  "T1095": "non_application_tcp_connection",
  "T1105": "ingress_tool_transfer",
  "T1135": "network_share_discovery",
  "T1204.002": "user_execution_malicious_file",
  "T1218.011": "rundll32_comsvcs_proxy",
  "T1558.001": "golden_ticket_service_ticket",
  "T1558.003": "kerberoasting_tgs_request",
  "T1560.001": "archive_collected_data",
  "T1569.002": "service_execution",
};

function getInitialView() {
  if (typeof window === "undefined") {
    return "summary";
  }

  const hashView = window.location.hash.replace("#", "");
  return VALID_VIEWS.has(hashView) ? hashView : "summary";
}

export default function App() {
  const [health, setHealth] = useState(null);
  const [campaigns, setCampaigns] = useState([]);
  const [selectedCampaignId, setSelectedCampaignId] = useState("SB-AD");
  const [campaignDetail, setCampaignDetail] = useState(null);
  const [targetDetail, setTargetDetail] = useState(null);
  const [techniqueCompatibility, setTechniqueCompatibility] = useState({});
  const [runs, setRuns] = useState([]);
  const [jobs, setJobs] = useState([]);
  const [operations, setOperations] = useState([]);
  const [selectedOperation, setSelectedOperation] = useState(null);
  const [agents, setAgents] = useState([]);
  const [selectedAgentId, setSelectedAgentId] = useState("");
  const [selectedRun, setSelectedRun] = useState(null);
  const [techniqueLibrary, setTechniqueLibrary] = useState([]);
  const [selectedTechniqueIds, setSelectedTechniqueIds] = useState([]);
  const [techniqueInputs, setTechniqueInputs] = useState({});
  const [expandedTechniqueInputIds, setExpandedTechniqueInputIds] = useState([]);
  const [techniqueQuery, setTechniqueQuery] = useState("");
  const [techniquePhaseFilter, setTechniquePhaseFilter] = useState("all");
  const [techniqueSourceFilter, setTechniqueSourceFilter] = useState("SB-05");
  const [notice, setNotice] = useState("");
  const [isRunning, setIsRunning] = useState(false);
  const [error, setError] = useState("");
  const [runPage, setRunPage] = useState(0);
  const [activeView, setActiveView] = useState(getInitialView);
  const [selectedAttackPathIndex, setSelectedAttackPathIndex] = useState(0);

  async function fetchJson(path, options) {
    const response = await fetch(`${API_BASE}${path}`, options);

    if (!response.ok) {
      let detail;
      try {
        detail = await response.json();
      } catch {
        detail = null;
      }

      const message = typeof detail?.detail === "string"
        ? detail.detail
        : detail?.detail?.message || `API error: ${response.status}`;

      throw new Error(message);
    }

    return response.json();
  }

  function sleep(milliseconds) {
    return new Promise((resolve) => {
      window.setTimeout(resolve, milliseconds);
    });
  }

  function findAgentForCampaign(agentList, campaignId) {
    return agentList.find((agent) => agent.campaign_agent_id === campaignId);
  }

  async function refreshDashboardData() {
    const agentData = await fetchJson("/agents");
    const loadedAgents = agentData.agents || [];
    setAgents(loadedAgents);

    const campaignAgent = findAgentForCampaign(loadedAgents, selectedCampaignId);
    if (campaignAgent) {
      setSelectedAgentId(campaignAgent.agent_id);
    } else if (!selectedAgentId) {
      setSelectedAgentId("");
    }

    const jobData = await fetchJson("/jobs");
    setJobs(jobData.jobs || []);

    const operationData = await fetchJson("/operations");
    setOperations(operationData.operations || []);

    const runData = await fetchJson("/runs");
    setRuns(runData.runs || []);

    return {
      agents: loadedAgents,
      jobs: jobData.jobs || [],
      operations: operationData.operations || [],
      runs: runData.runs || [],
    };
  }

  async function pollOperationUntilFinished(operationId) {
    for (let attempt = 0; attempt < JOB_POLL_ATTEMPTS; attempt += 1) {
      const operation = await fetchJson(`/operations/${operationId}`);
      setSelectedOperation(operation);

      if (["completed", "simulated"].includes(operation.status)) {
        setNotice(operation.status === "simulated" ? `Operation simulated: ${operationId}` : `Operation completed: ${operationId}`);
        await refreshDashboardData();
        return operation;
      }

      if (["blocked", "failed", "cancelled"].includes(operation.status)) {
        await refreshDashboardData();
        const blockedRoles = Array.isArray(operation.blocked_roles) ? operation.blocked_roles.join(", ") : "";
        throw new Error(blockedRoles ? `Operation ${operation.status}: ${blockedRoles}` : `Operation ${operation.status}`);
      }

      const running = operation.summary?.running || 0;
      const queued = operation.summary?.queued || 0;
      const success = operation.summary?.success || 0;
      const total = operation.summary?.total || 0;
      setNotice(`Operation running: ${success}/${total} 완료, running ${running}, queued ${queued}`);
      await sleep(JOB_POLL_INTERVAL_MS);
    }

    setNotice(`Operation is still running: ${operationId}`);
    return null;
  }

  async function loadInitialData() {
    try {
      setError("");

      const healthData = await fetchJson("/health");
      setHealth(healthData);

      const campaignData = await fetchJson("/campaigns");
      setCampaigns(campaignData.campaigns || []);

      const techniqueData = await fetchJson("/techniques");
      setTechniqueLibrary(techniqueData.techniques || []);

      await refreshDashboardData();

    } catch (err) {
      setError(err.message);
    }
  }

  async function loadCampaignDetail(campaignId) {
    try {
      setError("");
      setNotice("");

      const data = await fetchJson(`/campaigns/${campaignId}`);
      const targetData = await fetchJson(`/targets/${campaignId}`);
      let discoveredTargetData = targetData;

      try {
        const discoveryData = await fetchJson(`/targets/${campaignId}/asset-discovery`);
        discoveredTargetData = {
          ...targetData,
          assets: discoveryData.assets || targetData.assets,
          segments: discoveryData.segments || targetData.segments,
          security_controls: discoveryData.security_controls || targetData.security_controls,
          attack_paths: discoveryData.attack_paths || targetData.attack_paths,
          asset_discovery: discoveryData,
        };
      } catch {
        discoveredTargetData = targetData;
      }

      const compatibilityData = await fetchJson(`/campaigns/${campaignId}/technique-compatibility`);
      const agentData = await fetchJson("/agents");
      const loadedAgents = agentData.agents || [];
      setCampaignDetail(data);
      setTargetDetail(discoveredTargetData);
      setTechniqueCompatibility(compatibilityData.compatibility || {});
      setSelectedCampaignId(campaignId);
      setAgents(loadedAgents);
      setSelectedOperation(null);
      setSelectedRun(null);
      const campaignAgent = findAgentForCampaign(loadedAgents, campaignId);
      setSelectedAgentId(campaignAgent?.agent_id || "");
      setTechniqueSourceFilter(campaignId);
      setTechniquePhaseFilter("all");
      setTechniqueQuery("");
    } catch (err) {
      setError(err.message);
    }
  }

  async function selectCampaignAndShow(campaignId, view = "summary") {
    await loadCampaignDetail(campaignId);
    if (view) {
      showView(view);
    }
  }

  function getTechniqueSelectionId(step) {
    return step.selection_id || `${step.source_campaign_id || selectedCampaignId}:${step.order}`;
  }

  function getTechniqueSourceId(step) {
    return step.source_campaign_id || selectedCampaignId;
  }

  function getRequiredAgentRole(step) {
    const commands = Array.isArray(step.params?.commands) ? step.params.commands : [];
    return commands[0]?.agent_role
      || step.params?.agent_role
      || step.agent_role
      || "campaign_agent";
  }

  function getAgentRoleLabel(role) {
    const labels = {
      campaign_agent: "campaign",
      manual_operator: "manual",
    };

    return labels[role] || role;
  }

  function buildSelectedStepPayload(steps) {
    return steps.map((step) => ({
      campaign_id: getTechniqueSourceId(step),
      order: step.order,
      inputs: techniqueInputs[getTechniqueSelectionId(step)] || {},
    }));
  }

  function getTechniqueCompatibility(step) {
    const dryRun = techniqueCompatibility[getTechniqueSelectionId(step)];
    if (dryRun) {
      return {
        status: dryRun.status,
        label: dryRun.label,
        matched: [],
        missing: dryRun.missing_capabilities || [],
        querySource: dryRun.query_source,
      };
    }

    const requires = Array.isArray(step.requires) ? step.requires : [];
    const capabilities = new Set(Array.isArray(targetDetail?.capabilities) ? targetDetail.capabilities : []);
    const matched = requires.filter((item) => capabilities.has(item));
    const missing = requires.filter((item) => !capabilities.has(item));

    if (requires.length === 0) {
      return {
        status: "incompatible",
        label: "비호환",
        matched,
        missing,
      };
    }

    if (missing.length === 0) {
      return {
        status: "compatible",
        label: "호환",
        matched,
        missing,
      };
    }

    if (matched.length > 0) {
      return {
        status: "partial",
        label: "비호환",
        matched,
        missing,
      };
    }

    return {
      status: "incompatible",
      label: "비호환",
      matched,
      missing,
    };
  }

  function getOperationReadiness(step) {
    const compatibility = getTechniqueCompatibility(step);

    if (compatibility.status === "compatible") {
      return {
        status: "compatible",
        label: "호환",
        compatibility,
      };
    }

    if (compatibility.status === "partial" || compatibility.status === "incompatible") {
      return {
        status: "incompatible",
        label: "비호환",
        compatibility,
      };
    }

    return {
      status: "incompatible",
      label: "비호환",
      compatibility,
    };
  }

  function getTechniqueInputDefinitions(step) {
    return Array.isArray(step.inputs) ? step.inputs : [];
  }

  function getNestedValue(data, path) {
    if (!path) {
      return undefined;
    }

    return String(path).split(".").reduce((current, key) => {
      if (!current || typeof current !== "object") {
        return undefined;
      }

      return current[key];
    }, data);
  }

  function getDefaultTechniqueInputs(step) {
    return getTechniqueInputDefinitions(step).reduce((values, input) => {
      if (!input.name) {
        return values;
      }

      const params = step.params || {};
      const targetValue = getNestedValue(targetDetail, input.source);
      const defaultValue = targetValue ?? input.default ?? params[input.name] ?? "";
      values[input.name] = String(defaultValue);
      return values;
    }, {});
  }

  function initializeTechniqueInputs(steps) {
    const nextInputs = {};

    steps.forEach((step) => {
      const selectionId = getTechniqueSelectionId(step);
      nextInputs[selectionId] = {};
    });

    setTechniqueInputs(nextInputs);
  }

  function updateTechniqueInput(selectionId, name, value) {
    setTechniqueInputs((currentInputs) => ({
      ...currentInputs,
      [selectionId]: {
        ...(currentInputs[selectionId] || {}),
        [name]: value,
      },
    }));
  }

  function toggleTechniqueInputs(selectionId) {
    setExpandedTechniqueInputIds((currentIds) => (
      currentIds.includes(selectionId)
        ? currentIds.filter((id) => id !== selectionId)
        : [...currentIds, selectionId]
    ));
  }

  function getTechniqueInputSummary(step, selectionId) {
    const definitions = getTechniqueInputDefinitions(step);
    const values = techniqueInputs[selectionId] || getDefaultTechniqueInputs(step);

    return definitions
      .slice(0, 2)
      .map((input) => `${input.label || input.name} ${values[input.name] ?? ""}`)
      .join(" · ");
  }

  function toggleTechnique(step) {
    const selectionId = getTechniqueSelectionId(step);

    setSelectedTechniqueIds((currentIds) => {
      if (currentIds.includes(selectionId)) {
        setTechniqueInputs((currentInputs) => {
          const nextInputs = { ...currentInputs };
          delete nextInputs[selectionId];
          return nextInputs;
        });
        setExpandedTechniqueInputIds((currentIds) => currentIds.filter((id) => id !== selectionId));
        return currentIds.filter((id) => id !== selectionId);
      }

      setTechniqueInputs((currentInputs) => ({
        ...currentInputs,
        [selectionId]: currentInputs[selectionId] || {},
      }));
      return [...currentIds, selectionId];
    });

    setNotice("");
  }

  function removeQueuedTechnique(selectionId) {
    setSelectedTechniqueIds((currentIds) => currentIds.filter((id) => id !== selectionId));
    setTechniqueInputs((currentInputs) => {
      const nextInputs = { ...currentInputs };
      delete nextInputs[selectionId];
      return nextInputs;
    });
    setExpandedTechniqueInputIds((currentIds) => currentIds.filter((id) => id !== selectionId));
  }

  function moveQueuedTechnique(selectionId, direction) {
    setSelectedTechniqueIds((currentIds) => {
      const index = currentIds.indexOf(selectionId);
      const nextIndex = index + direction;

      if (index < 0 || nextIndex < 0 || nextIndex >= currentIds.length) {
        return currentIds;
      }

      const nextIds = [...currentIds];
      [nextIds[index], nextIds[nextIndex]] = [nextIds[nextIndex], nextIds[index]];
      return nextIds;
    });
  }

  function loadCampaignPreset() {
    const presetSteps = campaignDetail?.flow || [];
    const presetIds = presetSteps.map((step) => `${selectedCampaignId}:${step.order}`);
    setSelectedTechniqueIds(presetIds);
    initializeTechniqueInputs(presetSteps);
    setNotice(`${selectedCampaignId} 기본 시나리오를 실행 큐에 담았습니다.`);
  }

  function loadCampaignAttacksOnly() {
    const attackSteps = (campaignDetail?.flow || [])
      .filter((step) => step.phase === "attack");
    const attackIds = attackSteps.map((step) => `${selectedCampaignId}:${step.order}`);

    setSelectedTechniqueIds(attackIds);
    initializeTechniqueInputs(attackSteps);
    setNotice(`${selectedCampaignId} 공격 테크닉만 실행 큐에 담았습니다.`);
  }

  function clearOperationQueue() {
    setSelectedTechniqueIds([]);
    setTechniqueInputs({});
    setExpandedTechniqueInputIds([]);
    setNotice("");
  }

  function showView(view) {
    setActiveView(view);

    if (typeof window !== "undefined" && VALID_VIEWS.has(view)) {
      window.history.replaceState(null, "", `#${view}`);
    }
  }

  function getDetectionStatus(step) {
    if (step?.detection_status) {
      return step.detection_status;
    }

    if (["blocked"].includes(step?.status)) {
      return "blocked";
    }

    if (["failed", "manual_required", "not_supported"].includes(step?.status)) {
      return "execution_failed";
    }

    if (step?.status === "simulated") {
      return "not_checked";
    }

    const elkCheck = step?.elk_check;
    const alertCheck = elkCheck?.alert_check;

    if (!elkCheck?.checked && !alertCheck?.checked) {
      return "not_checked";
    }

    if (elkCheck?.matched && alertCheck?.matched) {
      return "detected";
    }

    if (elkCheck?.matched && !alertCheck?.matched) {
      return "logged_only";
    }

    if (!elkCheck?.matched && alertCheck?.matched) {
      return "alert_without_source_sample";
    }

    return "missed";
  }

  function getDetectionLabel(step) {
    const status = getDetectionStatus(step);
    const labels = {
      detected: "탐지됨",
      logged_only: "로그만",
      missed: "미탐지",
      not_checked: "미확인",
      blocked: "차단됨",
      execution_failed: "실패",
      alert_without_source_sample: "Alert만",
      not_run: "대기",
    };

    if (labels[status]) {
      return labels[status];
    }

    if (!step?.elk_check) {
      return "쿼리 없음";
    }

    if (!step.elk_check.checked && step.elk_check.query) {
      return "미확인";
    }

    if (!step.elk_check.checked) {
      return "미설정";
    }

    return status;
  }

  function getRiskLevel(step) {
    const detectionStatus = getDetectionStatus(step);
    const executed = ["success", "completed", "simulated"].includes(step.status);

    if (!executed) {
      return "low";
    }

    if (["missed", "execution_failed"].includes(detectionStatus)) {
      return "high";
    }

    if (detectionStatus === "detected") {
      return "medium";
    }

    return step.phase === "attack" ? "medium" : "low";
  }

  function getDetectionGapType(step) {
    if (step?.gap_type) {
      return step.gap_type;
    }

    const status = getDetectionStatus(step);
    const gapTypes = {
      logged_only: "no_alert",
      missed: "no_telemetry",
      not_checked: "not_checked",
      execution_failed: "agent_or_execution_failed",
      blocked: "blocked_or_prevented",
      alert_without_source_sample: "query_too_narrow",
    };

    return gapTypes[status] || "-";
  }

  function getRecommendedAction(step) {
    if (step?.recommendation?.action) {
      return step.recommendation.action;
    }

    const status = getDetectionStatus(step);
    const actions = {
      detected: "keep",
      logged_only: "tune_or_create_rule",
      missed: "fix_telemetry_then_rule",
      not_checked: "fix_validation_pipeline",
      execution_failed: "fix_agent_or_execution",
      blocked: "review_safety_or_prevention_control",
      alert_without_source_sample: "fix_source_query",
    };

    return actions[status] || "review_detection_logic";
  }

  function getBacklogPriority(step) {
    const status = getDetectionStatus(step);
    const risk = getRiskLevel(step);

    if (status === "missed" && risk === "high") {
      return "P0";
    }

    if (["missed", "execution_failed", "logged_only"].includes(status)) {
      return "P1";
    }

    if (["not_checked", "alert_without_source_sample"].includes(status)) {
      return "P2";
    }

    return "P3";
  }

  function buildDashboardSummary(run) {
    const steps = run?.steps || [];
    const attackSteps = steps.filter((step) => step.phase === "attack");
    const successfulAttacks = attackSteps.filter((step) => ["success", "simulated"].includes(step.status));
    const failedAttacks = attackSteps.filter((step) => !["success", "simulated"].includes(step.status));
    const successSteps = steps.filter((step) => step.status === "success");
    const simulatedSteps = steps.filter((step) => step.status === "simulated");
    const failedSteps = steps.filter((step) => step.status && !["success", "simulated"].includes(step.status));
    const detectedSteps = successfulAttacks.filter((step) => getDetectionStatus(step) === "detected");
    const loggedOnlySteps = successfulAttacks.filter((step) => getDetectionStatus(step) === "logged_only");
    const missedSteps = successfulAttacks.filter((step) => getDetectionStatus(step) === "missed");
    const notCheckedSteps = successfulAttacks.filter((step) => getDetectionStatus(step) === "not_checked");

    const penalty = (missedSteps.length * 25)
      + (loggedOnlySteps.length * 12)
      + (failedAttacks.length * 15)
      + (notCheckedSteps.length * 8);

    return {
      totalSteps: steps.length,
      attackCount: attackSteps.length,
      successCount: successSteps.length,
      simulatedCount: simulatedSteps.length,
      failedCount: failedSteps.length,
      successfulAttackCount: successfulAttacks.length,
      failedAttackCount: failedAttacks.length,
      detectedCount: detectedSteps.length,
      loggedOnlyCount: loggedOnlySteps.length,
      missedCount: missedSteps.length,
      notCheckedCount: notCheckedSteps.length,
      penalty,
      score: steps.length > 0 ? Math.max(0, 100 - penalty) : null,
    };
  }

  function buildDonutStyle(segments, hasData) {
    if (!hasData) {
      return { background: "conic-gradient(#cbd5e1 0 360deg)" };
    }

    const total = Math.max(1, segments.reduce((sum, segment) => sum + segment.value, 0));
    let cursor = 0;
    const gradientStops = segments.map((segment) => {
      const next = cursor + ((segment.value / total) * 360);
      const stop = `${segment.color} ${cursor}deg ${next}deg`;
      cursor = next;
      return stop;
    });

    return {
      background: `conic-gradient(${gradientStops.join(", ")})`,
    };
  }

  function normalizeList(value) {
    if (Array.isArray(value)) {
      return value;
    }

    if (typeof value === "string") {
      return value
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean);
    }

    return [];
  }

  function getAgentForAsset(asset) {
    const assetId = String(asset.asset_id || "").toLowerCase();
    const agentRole = String(asset.agent_role || assetId).toLowerCase();

    return agents.find((agent) => {
      const candidateValues = [
        agent.asset_id,
        agent.agent_role,
        agent.campaign_agent_id,
        agent.agent_id,
      ].map((value) => String(value || "").toLowerCase());

      return (
        candidateValues.includes(assetId)
        || candidateValues.includes(agentRole)
        || String(agent.agent_id || "").toLowerCase().includes(assetId)
      );
    });
  }

  function getAgentStatus(asset, agent) {
    if (!asset.agent_required) {
      return "observe";
    }

    if (!agent) {
      return "offline";
    }

    return agent.status || "registered";
  }

  function getAgentStatusLabel(status) {
    const labels = {
      online: "Online",
      registered: "Registered",
      running: "Running",
      offline: "Agent 필요",
      observe: "Log source",
    };

    return labels[status] || status;
  }

  function getCriticalityLabel(criticality) {
    const labels = {
      critical: "Critical",
      high: "High",
      medium: "Medium",
      low: "Low",
    };

    return labels[criticality] || criticality || "Medium";
  }

  function buildAssetInventory() {
    const configuredAssets = Array.isArray(targetDetail?.assets) ? targetDetail.assets : [];
    const discoveredAgentAssets = agents
      .filter((agent) => agent.campaign_agent_id === selectedCampaignId)
      .map((agent) => ({
        asset_id: agent.asset_id || agent.agent_role || agent.agent_id,
        name: agent.display_name || agent.hostname || agent.agent_id,
        hostname: agent.hostname,
        private_ip: agent.private_ip,
        platform: agent.platform,
        role: agent.agent_role || "BAS Agent discovered asset",
        segment_id: agent.segment_id || "unassigned-segment",
        agent_role: agent.agent_role,
        agent_required: true,
        criticality: agent.criticality || "medium",
        controls: normalizeList(agent.controls),
        capabilities: normalizeList(agent.capabilities),
        discovery_source: "agent_registration",
      }));
    const sourceAssets = configuredAssets.length > 0 ? configuredAssets : discoveredAgentAssets;

    return sourceAssets.map((asset) => {
      const agent = getAgentForAsset(asset);
      const agentStatus = getAgentStatus(asset, agent);

      return {
        ...asset,
        controls: normalizeList(asset.controls),
        agent,
        agentStatus,
        agentLabel: getAgentStatusLabel(agentStatus),
        criticalityLabel: getCriticalityLabel(asset.criticality),
      };
    });
  }

  function buildSegmentInventory(assets) {
    const configuredSegments = Array.isArray(targetDetail?.segments) ? targetDetail.segments : [];
    const discoveredSegmentIds = Array.from(
      new Set(assets.map((asset) => asset.segment_id || "unassigned-segment")),
    );
    const fallbackSegments = discoveredSegmentIds.map((segmentId) => ({
      segment_id: segmentId,
      name: segmentId === "unassigned-segment" ? "Unassigned Assets" : segmentId,
      type: segmentId.includes("external") || segmentId.includes("attacker") ? "external" : "internal",
    }));

    return (configuredSegments.length > 0 ? configuredSegments : fallbackSegments).map((segment) => ({
      ...segment,
      assets: assets.filter((asset) => asset.segment_id === segment.segment_id),
    }));
  }

  function buildSecurityControls(assets) {
    const configuredControls = Array.isArray(targetDetail?.security_controls)
      ? targetDetail.security_controls
      : [];
    const controlIds = new Set();

    assets.forEach((asset) => {
      asset.controls.forEach((controlId) => controlIds.add(controlId));
    });

    const fallbackControls = Array.from(controlIds).map((controlId) => ({
      control_id: controlId,
      name: controlId,
      category: "configured control",
      status: "configured",
    }));

    return (configuredControls.length > 0 ? configuredControls : fallbackControls).map((control) => {
      const coveredAssets = assets.filter((asset) => asset.controls.includes(control.control_id));

      return {
        ...control,
        coveredAssets,
      };
    });
  }

  function buildAttackPaths(assets) {
    const configuredPaths = Array.isArray(targetDetail?.attack_paths) ? targetDetail.attack_paths : [];
    const assetById = new Map(assets.map((asset) => [asset.asset_id, asset]));

    return configuredPaths.map((path) => ({
      ...path,
      sourceAsset: assetById.get(path.source_asset_id),
      targetAsset: assetById.get(path.target_asset_id),
      techniques: normalizeList(path.techniques),
    }));
  }

  function findRunStepForTechnique(techniqueId, run) {
    return (run?.steps || []).find((step) => step.technique_id === techniqueId);
  }

  function findFlowStepsForTechnique(techniqueId) {
    return (campaignDetail?.flow || []).filter((step) => step.technique_id === techniqueId);
  }

  function getBehaviorKeyForEvidence(techniqueId, flowStep, runStep) {
    return runStep?.module_result?.behavior
      || flowStep?.params?.behavior
      || runStep?.module_result?.evidence_key
      || TECHNIQUE_EVIDENCE_KEYS[techniqueId]
      || flowStep?.module
      || "";
  }

  function getAttackPathTelemetry(path, run, queuedSteps) {
    const runSteps = run?.steps || [];
    const relatedRunSteps = runSteps.filter((step) => path.techniques.includes(step.technique_id));
    const relatedQueuedSteps = queuedSteps.filter((step) => path.techniques.includes(step.technique_id));
    const detected = relatedRunSteps.filter((step) => getDetectionStatus(step) === "detected").length;
    const missed = relatedRunSteps.filter((step) => getDetectionStatus(step) === "missed").length;
    const notChecked = relatedRunSteps.filter((step) => getDetectionStatus(step) === "not_checked").length;
    const executed = relatedRunSteps.filter((step) => ["success", "simulated"].includes(step.status)).length;

    if (missed > 0) {
      return {
        status: "gap",
        label: "탐지 갭",
        detected,
        missed,
        notChecked,
        executed,
      };
    }

    if (detected > 0) {
      return {
        status: "detected",
        label: "탐지됨",
        detected,
        missed,
        notChecked,
        executed,
      };
    }

    if (executed > 0) {
      return {
        status: "executed",
        label: "실행됨",
        detected,
        missed,
        notChecked,
        executed,
      };
    }

    if (relatedQueuedSteps.length > 0) {
      return {
        status: "queued",
        label: "큐 대기",
        detected,
        missed,
        notChecked,
        executed,
      };
    }

    return {
      status: "planned",
      label: "계획됨",
      detected,
      missed,
      notChecked,
      executed,
    };
  }

  function buildAttackPathEvidence(path, run) {
    if (!path) {
      return [];
    }

    return path.techniques.map((techniqueId) => {
      const flowSteps = findFlowStepsForTechnique(techniqueId);
      const primaryFlowStep = flowSteps[0];
      const runStep = findRunStepForTechnique(techniqueId, run);
      const behaviorKey = getBehaviorKeyForEvidence(techniqueId, primaryFlowStep, runStep);
      const logQuery = behaviorKey ? targetDetail?.log_queries?.[behaviorKey] : "";
      const alertQuery = behaviorKey ? targetDetail?.alert_queries?.[behaviorKey] : "";
      const sampleEvents = Array.isArray(runStep?.elk_check?.sample_events)
        ? runStep.elk_check.sample_events
        : [];

      return {
        techniqueId,
        techniqueName: TECHNIQUE_NAMES[techniqueId] || primaryFlowStep?.name || "Technique",
        flowStep: primaryFlowStep,
        runStep,
        behaviorKey,
        logQuery,
        alertQuery,
        sampleEvents,
      };
    });
  }

  function getControlById(controls) {
    return new Map(controls.map((control) => [control.control_id, control]));
  }

  function getPathValidationStatus(path) {
    const sourceStatus = path.sourceAsset?.agentStatus || "offline";
    const targetStatus = path.targetAsset?.agentStatus || "observe";

    if (sourceStatus === "online" && ["online", "observe"].includes(targetStatus)) {
      return {
        status: "ready",
        label: "검증 가능",
      };
    }

    if (sourceStatus === "offline" || targetStatus === "offline") {
      return {
        status: "blocked",
        label: "Agent 필요",
      };
    }

    return {
      status: "partial",
      label: "수동 확인",
    };
  }

  function buildValidationGates(controls) {
    const controlById = getControlById(controls);
    const resolve = (controlIds) => controlIds
      .map((controlId) => controlById.get(controlId))
      .filter(Boolean);

    return [
      {
        gate_id: "external-entry",
        name: "External Entry Gate",
        between: "Attacker → PC01",
        objective: "외부 공격자 위치에서 내부 사용자 PC로 공격 페이로드가 도달하는지 검증",
        controlIds: ["aws_security_group", "sysmon", "kibana_rules"],
        controls: resolve(["aws_security_group", "sysmon", "kibana_rules"]),
      },
      {
        gate_id: "lateral-movement",
        name: "Lateral Movement Gate",
        between: "PC01 → FS01",
        objective: "WinRM, PowerShell, 파일 전송 행위가 서버 구간에서 관찰되는지 검증",
        controlIds: ["powershell_logging", "windows_security_log", "winlogbeat", "kibana_rules"],
        controls: resolve(["powershell_logging", "windows_security_log", "winlogbeat", "kibana_rules"]),
      },
      {
        gate_id: "identity-core",
        name: "Identity Core Gate",
        between: "Attacker/FS01 → DC01",
        objective: "도메인 복제, Kerberos, AD 객체 접근 로그가 핵심 인증 구간에서 탐지되는지 검증",
        controlIds: ["windows_security_log", "winlogbeat", "kibana_rules"],
        controls: resolve(["windows_security_log", "winlogbeat", "kibana_rules"]),
      },
      {
        gate_id: "egress",
        name: "Egress Gate",
        between: "FS01 → Attacker",
        objective: "내부 파일 서버에서 외부 공격자 서버로 나가는 데이터 이동을 식별하는지 검증",
        controlIds: ["sysmon", "aws_security_group", "kibana_rules"],
        controls: resolve(["sysmon", "aws_security_group", "kibana_rules"]),
      },
    ];
  }

  function getTechniqueDisplayName(step) {
    if (!step.technique_id) {
      return step.phase === "attack" ? "Attack Step" : "Normal Baseline";
    }

    return `${step.technique_id} ${TECHNIQUE_NAMES[step.technique_id] || ""}`.trim();
  }

  function getStepBehavior(step) {
    return step.module_result?.behavior || step.module || "unknown";
  }

  function getExecutionMode(step) {
    return step.module_result?.execution_mode || selectedRun?.bas_agent?.mode || "simulation";
  }

  function getCommandStatus(command) {
    if (command.returncode === 0) {
      return "success";
    }

    if (typeof command.returncode === "number") {
      return "failed";
    }

    return "unknown";
  }

  function renderModuleEvidence(step) {
    const result = step.module_result || {};
    const elkCheck = step.elk_check || {};
    const commands = Array.isArray(result.commands) ? result.commands : [];
    const artifacts = Array.isArray(result.artifacts) ? result.artifacts : [];
    const secrets = Array.isArray(result.secrets) ? result.secrets : [];
    const sampleEvents = Array.isArray(elkCheck.sample_events) ? elkCheck.sample_events : [];
    const inputEntries = Object.entries(step.inputs_used || {});

    return (
      <div className="evidence-block">
        <div className="evidence-grid">
          <div>
            <span>행위 유형</span>
            <strong>{getStepBehavior(step)}</strong>
          </div>
          <div>
            <span>실행 모드</span>
            <strong>{getExecutionMode(step)}</strong>
          </div>
          <div>
            <span>증거 키</span>
            <strong>{result.evidence_key || "없음"}</strong>
          </div>
        </div>

        {inputEntries.length > 0 && (
          <div className="evidence-inputs">
            <div className="evidence-title">Input values</div>
            <div className="evidence-input-grid">
              {inputEntries.map(([name, value]) => (
                <span key={`${step.order}-${name}`}>
                  <em>{name}</em>
                  <strong>{String(value)}</strong>
                </span>
              ))}
            </div>
          </div>
        )}

        {commands.length > 0 && (
          <div className="command-list">
            <div className="evidence-title">명령 실행 결과</div>

            {commands.map((command, index) => (
              <div key={`${step.order}-command-${index}`} className="command-item">
                <div className="command-header">
                  <code>{command.command}</code>
                  <span className={`result-badge ${getCommandStatus(command)}`}>
                    rc {command.returncode}
                  </span>
                </div>

                {command.stdout && (
                  <pre>{command.stdout}</pre>
                )}

                {command.stderr && (
                  <pre className="stderr">{command.stderr}</pre>
                )}
              </div>
            ))}
          </div>
        )}

        {artifacts.length > 0 && (
          <div className="artifact-list">
            <div className="evidence-title">아티팩트</div>
            {artifacts.map((artifact, index) => (
              <code key={`${step.order}-artifact-${index}`}>
                {typeof artifact === "string" ? artifact : JSON.stringify(artifact)}
              </code>
            ))}
          </div>
        )}

        {secrets.length > 0 && (
          <div className="secret-list">
            <div className="evidence-title">Decoded Secrets</div>
            {secrets.map((secret, index) => (
              <div key={`${step.order}-secret-${index}`} className="secret-item">
                <div className="secret-header">
                  <strong>{secret.name}</strong>
                  <span>{secret.namespace} / {secret.type}</span>
                </div>
                <div className="secret-values">
                  {Object.entries(secret.decoded_values || {}).map(([key, value]) => (
                    <div key={`${secret.name}-${key}`}>
                      <span>{key}</span>
                      <code>{value}</code>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

        <div className="query-box">
          <span>ELK 탐지 검증</span>
          <div className="elk-validation-card">
            <div>
              <span>결과</span>
              <strong>{getDetectionLabel(step)}</strong>
            </div>
            <div>
              <span>인덱스</span>
              <strong>{elkCheck.index || "설정 안 됨"}</strong>
            </div>
            <div>
              <span>매칭 이벤트</span>
              <strong>{typeof elkCheck.event_count === "number" ? elkCheck.event_count : "미확인"}</strong>
            </div>
          </div>
          <code>{elkCheck.query || "ELK 쿼리 없음"}</code>
          {elkCheck.message && <p className="elk-message">{elkCheck.message}</p>}
          {sampleEvents.length > 0 && (
            <div className="sample-log-list">
              <div className="evidence-title">샘플 로그</div>
              {sampleEvents.map((event, index) => (
                <pre key={`${step.order}-sample-${index}`}>
                  {typeof event === "string" ? event : JSON.stringify(event, null, 2)}
                </pre>
              ))}
            </div>
          )}
        </div>
      </div>
    );
  }

  const latestRunsByCampaign = new Map();
  runs.forEach((run) => {
    const currentRun = latestRunsByCampaign.get(run.campaign_id);
    const currentTime = currentRun?.started_at ? new Date(currentRun.started_at).getTime() : 0;
    const runTime = run.started_at ? new Date(run.started_at).getTime() : 0;

    if (!currentRun || runTime >= currentTime) {
      latestRunsByCampaign.set(run.campaign_id, run);
    }
  });

  const selectedRunMatchesCampaign = selectedRun?.campaign_id === selectedCampaignId;
  const visibleSummaryRun = latestRunsByCampaign.get(selectedCampaignId);
  const validationRun = selectedRunMatchesCampaign ? selectedRun : visibleSummaryRun;
  const dashboardSummary = buildDashboardSummary(visibleSummaryRun);
  const executionChartStyle = buildDonutStyle(
    [
      { value: dashboardSummary.successCount, color: "#16a34a" },
      { value: dashboardSummary.simulatedCount, color: "#2563eb" },
      { value: dashboardSummary.failedCount, color: "#dc2626" },
    ],
    Boolean(visibleSummaryRun)
  );
  const detectionChartStyle = buildDonutStyle(
    [
      { value: dashboardSummary.detectedCount, color: "#16a34a" },
      { value: dashboardSummary.loggedOnlyCount, color: "#eab308" },
      { value: dashboardSummary.missedCount, color: "#dc2626" },
      { value: dashboardSummary.notCheckedCount, color: "#f59e0b" },
    ],
    Boolean(visibleSummaryRun) && dashboardSummary.successfulAttackCount > 0
  );
  const campaignSummaryCards = campaigns
  .filter((campaign) => campaign.campaign_id === selectedCampaignId)
  .map((campaign) => {
    const latestRun = latestRunsByCampaign.get(campaign.campaign_id);
    const isSelectedCampaign = campaign.campaign_id === selectedCampaignId;
    const summaryRun = latestRun;
    const summary = buildDashboardSummary(summaryRun);
    const flowCount = isSelectedCampaign ? (campaignDetail?.flow || []).length : campaign.step_count;
    const techniqueCount = flowCount || summaryRun?.steps?.length || 0;
    const defenseRate = summary.successfulAttackCount > 0
      ? Math.round((summary.detectedCount / summary.successfulAttackCount) * 100)
      : 0;

    return {
      campaign,
      latestRun: summaryRun,
      summary,
      techniqueCount,
      defenseRate,
      isSelectedCampaign,
    };
  });
  const techniqueById = new Map();
  techniqueLibrary.forEach((step) => {
    techniqueById.set(getTechniqueSelectionId(step), step);
  });
  const selectedOperationSteps = selectedTechniqueIds
    .map((selectionId) => techniqueById.get(selectionId))
    .filter(Boolean);
  const queuedAttackCount = selectedOperationSteps.filter((step) => step.phase === "attack").length;
  const librarySourceIds = Array.from(
    new Set(techniqueLibrary.map((step) => getTechniqueSourceId(step)))
  ).sort();
  const normalizedTechniqueQuery = techniqueQuery.trim().toLowerCase();
  const filteredTechniqueLibrary = techniqueLibrary.filter((step) => {
    const sourceId = getTechniqueSourceId(step);
    const matchesSource = techniqueSourceFilter === "all" || sourceId === techniqueSourceFilter;
    const matchesPhase = techniquePhaseFilter === "all" || step.phase === techniquePhaseFilter;
    const searchableText = [
      step.name,
      step.technique_id,
      step.module,
      sourceId,
      step.source_campaign_name,
    ].filter(Boolean).join(" ").toLowerCase();
    const matchesQuery = !normalizedTechniqueQuery || searchableText.includes(normalizedTechniqueQuery);

    return matchesSource && matchesPhase && matchesQuery;
  });
  const latestOperation = selectedOperation || operations.find((operation) => operation.campaign_id === selectedCampaignId) || null;
  const visibleOperationSteps = latestOperation?.final_steps || [];
  const operationDisplaySteps = visibleOperationSteps.map((step) => ({
    ...step,
    source_campaign_id: latestOperation?.campaign_id || selectedCampaignId,
    phase: step.phase || (step.technique_id ? "attack" : "normal"),
  }));
  const attackPathSteps = selectedRunMatchesCampaign ? selectedRun.steps : (operationDisplaySteps.length > 0 ? operationDisplaySteps : selectedOperationSteps);
  const latestJob = jobs[0] || null;
  const recentJobs = jobs.slice(0, 4);
  const plannedRoutes = selectedOperationSteps.reduce((routes, step) => {
    const role = getRequiredAgentRole(step);
    return {
      ...routes,
      [role]: [...(routes[role] || []), step],
    };
  }, {});
  const routingRoles = Array.from(new Set([
    ...Object.keys(plannedRoutes),
    ...visibleOperationSteps.map((step) => step.agent_role).filter(Boolean),
    ...(selectedCampaignId === "SB-AD" ? ["pc01", "fs01", "attacker"] : []),
  ]));
  const runPageCount = Math.max(1, Math.ceil(runs.length / RUNS_PER_PAGE));
  const visibleRuns = runs.slice(
    runPage * RUNS_PER_PAGE,
    runPage * RUNS_PER_PAGE + RUNS_PER_PAGE
  );
  const visibleSummarySteps = visibleSummaryRun?.steps || [];
  const visibleExecutedStepCount = visibleSummarySteps.filter((step) => ["success", "simulated"].includes(step.status)).length;
  const visibleExecutionRate = dashboardSummary.totalSteps > 0
    ? Math.round((visibleExecutedStepCount / dashboardSummary.totalSteps) * 100)
    : null;
  const visibleDetectionRate = dashboardSummary.successfulAttackCount > 0
    ? Math.round((dashboardSummary.detectedCount / dashboardSummary.successfulAttackCount) * 100)
    : null;
  const selectedRunSteps = selectedRunMatchesCampaign ? selectedRun.steps : [];
  const recentVerificationSteps = selectedRunMatchesCampaign ? selectedRunSteps : operationDisplaySteps;
  const recentVerificationAttackSteps = recentVerificationSteps.filter((step) => step.phase === "attack" || step.technique_id);
  const recentVerificationExecutedCount = recentVerificationSteps.filter((step) => ["success", "completed", "simulated"].includes(step.status)).length;
  const recentVerificationDetectedCount = recentVerificationAttackSteps.filter((step) => getDetectionStatus(step) === "detected").length;
  const recentVerificationLoggedOnlyCount = recentVerificationAttackSteps.filter((step) => getDetectionStatus(step) === "logged_only").length;
  const recentVerificationMissedCount = recentVerificationAttackSteps.filter((step) => getDetectionStatus(step) === "missed").length;
  const recentVerificationNotCheckedCount = recentVerificationAttackSteps.filter((step) => getDetectionStatus(step) === "not_checked").length;
  const remediationBacklogRows = recentVerificationAttackSteps
    .filter((step) => getDetectionStatus(step) !== "detected")
    .map((step) => ({
      priority: getBacklogPriority(step),
      techniqueId: step.technique_id || "-",
      order: step.order,
      name: step.name,
      gapType: getDetectionGapType(step),
      action: getRecommendedAction(step),
      status: getDetectionStatus(step),
    }))
    .sort((first, second) => first.priority.localeCompare(second.priority));
  const recentVerificationTitle = selectedRunMatchesCampaign
    ? selectedRun.execution_id
    : latestOperation?.operation_id || "선택된 실행 없음";
  const selectedScopeLabel = selectedOperationSteps.length > 0
    ? `${selectedOperationSteps.length}개 큐에 있음`
    : "큐 비어 있음";
  const assetInventory = buildAssetInventory();
  const segmentInventory = buildSegmentInventory(assetInventory);
  const securityControlInventory = buildSecurityControls(assetInventory);
  const attackPathInventory = buildAttackPaths(assetInventory);
  const agentRequiredAssets = assetInventory.filter((asset) => asset.agent_required);
  const onlineAgentAssetCount = agentRequiredAssets.filter((asset) => asset.agentStatus === "online").length;
  const criticalAssetCount = assetInventory.filter((asset) => asset.criticality === "critical").length;
  const topologyNodes = assetInventory;
  const getMapNodeStyle = (index, total) => {
    const safeTotal = Math.max(total, 1);
    const column = safeTotal === 1 ? 0.5 : index / (safeTotal - 1);
    const left = 6 + column * 74;
    const top = safeTotal <= 3 ? 42 : 28 + (index % 2) * 28;

    return {
      left: `${left}%`,
      top: `${top}%`,
    };
  };
  const getSegmentStyle = (index, total) => {
    const width = 100 / Math.max(total, 1);

    return {
      left: `${index * width}%`,
      width: `${width}%`,
    };
  };
  const validationGates = buildValidationGates(securityControlInventory);
  const attackPathTelemetry = attackPathInventory.map((path) => getAttackPathTelemetry(path, validationRun, selectedOperationSteps));
  const activeAttackPath = attackPathInventory[selectedAttackPathIndex] || attackPathInventory[0] || null;
  const activeAttackPathTelemetry = activeAttackPath
    ? getAttackPathTelemetry(activeAttackPath, validationRun, selectedOperationSteps)
    : null;
  const activeAttackPathEvidence = buildAttackPathEvidence(activeAttackPath, validationRun);
  const readyPathCount = attackPathInventory.filter((path) => getPathValidationStatus(path).status === "ready").length;
  const blockedPathCount = attackPathInventory.filter((path) => getPathValidationStatus(path).status === "blocked").length;
  const configuredControlCount = securityControlInventory.filter((control) => control.status === "configured").length;
  const detectionRuleCount = campaignDetail?.flow?.length || 0;

  async function runCampaign() {
    try {
        setIsRunning(true);
        setError("");

        if (!selectedCampaignId) {
            throw new Error("Select a campaign before queueing a job.");
        }

        if (selectedOperationSteps.length === 0) {
            throw new Error("실행 큐에 테크닉을 먼저 담아주세요.");
        }

        const selectedStepPayload = buildSelectedStepPayload(selectedOperationSteps);
        const payload = {
          campaign_id: selectedCampaignId,
          selected_steps: selectedStepPayload,
          include_normal: false,
          execution_mode: "real",
        };

        const data = await fetchJson("/operations", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(payload),
        });
        const operation = data.operation;
        setSelectedRun(null);
        setSelectedOperation(operation);
        setOperations((currentOperations) => {
          const withoutCurrentOperation = currentOperations.filter((item) => item.operation_id !== operation.operation_id);
          return [operation, ...withoutCurrentOperation];
        });

        if (operation.status === "simulated") {
          const simulatedRoles = Array.isArray(operation.blocked_roles) ? operation.blocked_roles.join(", ") : "";
          setNotice(`Operation simulated: ${simulatedRoles || "Agent offline"} 역할은 실제 job 없이 예상 라우팅만 표시합니다.`);
          await refreshDashboardData();
          return;
        }

        setNotice(`Operation started: ${operation.operation_id}`);
        await refreshDashboardData();
        await pollOperationUntilFinished(operation.operation_id);
    } catch (err) {
        setError(err.message);
    } finally {
        setIsRunning(false);
    }
    }

  async function loadRun(executionId) {
    try {
      setError("");
      const data = await fetchJson(`/runs/${executionId}`);
      setSelectedRun(data);
      setNotice(`Run detail opened: ${executionId}`);
      showView("evidence");
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    loadInitialData();
    loadCampaignDetail(selectedCampaignId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setSelectedAttackPathIndex(0);
  }, [selectedCampaignId]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return undefined;
    }

    function syncViewFromHash() {
      const hashView = window.location.hash.replace("#", "");
      if (VALID_VIEWS.has(hashView)) {
        setActiveView(hashView);
      }
    }

    window.addEventListener("hashchange", syncViewFromHash);
    syncViewFromHash();

    return () => {
      window.removeEventListener("hashchange", syncViewFromHash);
    };
  }, []);

  useEffect(() => {
    if (!notice) {
      return undefined;
    }

    const timeoutId = window.setTimeout(() => {
      setNotice("");
    }, 3200);

    return () => {
      window.clearTimeout(timeoutId);
    };
  }, [notice]);

  return (
    <main className="app-shell">
      <section className="topbar product-topbar">
        <div className="brand-heading">
          <button
            type="button"
            className="brand-home-button"
            onClick={() => showView("summary")}
            aria-label="요약 페이지로 이동"
            title="요약 페이지로 이동"
          >
            <img src={spacebarLogo} alt="Spacebar" />
          </button>
          <div>
            <p className="eyebrow">Spacebar BAS</p>
            <h1>SpaceBaS</h1>
            <p className="topbar-copy">
              SpaceBar 팀의 공격 시뮬레이션 도구입니다. 캠페인 Technique을 실행하고,
              예상 로그·Alert·증거가 수집됐는지 한 화면에서 검증합니다.
            </p>
          </div>
        </div>

        <div className="topbar-status">
          <div className={`status-pill ${health ? "online" : "offline"}`}>
            {health ? "API 연결됨" : "API 연결 안 됨"}
          </div>
        </div>
      </section>

      {error && <div className="alert">{error}</div>}
      {notice && (
        <div className="toast-region" aria-live="polite" aria-atomic="true">
          <div className="notice-toast">{notice}</div>
        </div>
      )}

      <section className="workspace-frame">
        <div className="workspace-topnav">
          <div className="topnav-primary">
            <label className="topnav-campaign">
              <span>검증 캠페인</span>
            <select
              aria-label="Campaign"
              value={selectedCampaignId}
              onChange={(event) => loadCampaignDetail(event.target.value)}
            >
              {campaigns.map((campaign) => (
                <option key={campaign.campaign_id} value={campaign.campaign_id}>
                  {campaign.campaign_id} - {campaign.campaign_name}
                </option>
              ))}
            </select>
            </label>

            <div className="topnav-context">
              <strong>{campaignDetail?.campaign_name || selectedCampaignId}</strong>
              <small>{selectedScopeLabel}</small>
            </div>

            <div className="topnav-score">
              <span>Score</span>
              <strong>{visibleSummaryRun ? `${dashboardSummary.score ?? "--"}` : "--"}</strong>
              <small>탐지율 {visibleDetectionRate === null ? "--" : `${visibleDetectionRate}%`} · 갭 {dashboardSummary.missedCount}</small>
            </div>

            <button
              className="run-button topnav-run-button"
              onClick={runCampaign}
              disabled={isRunning || !selectedCampaignId || selectedOperationSteps.length === 0}
            >
              {isRunning ? "실행 중..." : "검증 실행"}
            </button>
          </div>

          <nav className="workspace-tabs" aria-label="Dashboard sections">
            <button
              type="button"
              className={activeView === "summary" ? "active-view" : ""}
              onClick={() => showView("summary")}
            >
              <span>요약</span>
              <small>점검 현황과 그래프</small>
            </button>
            <button
              type="button"
              className={activeView === "scope" ? "active-view" : ""}
              onClick={() => showView("scope")}
            >
              <span>실행하기</span>
              <small>검증할 기법 선택</small>
            </button>
            <button
              type="button"
              className={activeView === "validation" ? "active-view" : ""}
              onClick={() => showView("validation")}
            >
              <span>검증 맵</span>
              <small>경로·통제 평가</small>
            </button>
            <button
              type="button"
              className={activeView === "assets" ? "active-view" : ""}
              onClick={() => showView("assets")}
            >
              <span>자산 파악</span>
              <small>망·자산·통제 현황</small>
            </button>
            <button
              type="button"
              className={activeView === "history" ? "active-view" : ""}
              onClick={() => showView("history")}
            >
              <span>결과 기록</span>
              <small>이전 실행 열람</small>
            </button>
            <button
              type="button"
              className={activeView === "evidence" ? "active-view" : ""}
              onClick={() => showView("evidence")}
            >
              <span>증거 확인</span>
              <small>명령과 ELK 근거</small>
            </button>
          </nav>
        </div>

        <section className="workspace-main">
      {activeView === "summary" && (
      <>
      <section className="view-header">
        <div>
          <span>요약</span>
          <h2>{campaignDetail?.campaign_name || selectedCampaignId} 보안 검증 현황</h2>
          <p>캠페인별 탐지 상태와 현재 선택한 캠페인의 실행률, 탐지율을 한 번에 확인합니다.</p>
        </div>
        <div className="view-header-metrics">
          <span>Score <strong>{visibleSummaryRun ? dashboardSummary.score ?? "--" : "--"}</strong></span>
          <span>Detection <strong>{visibleDetectionRate === null ? "--" : `${visibleDetectionRate}%`}</strong></span>
          <span>Gap <strong>{dashboardSummary.missedCount}</strong></span>
        </div>
      </section>
      <section className="campaign-health-grid">
        <div className="panel campaign-health-panel">
          <div className="panel-title-row">
            <div>
              <div className="section-title">캠페인별 점검 현황</div>
              <h3>보안 검증 요약</h3>
            </div>
            <span className="scope-pill">{selectedCampaignId || "--"}</span>
          </div>

          <div className="campaign-summary-list">
            {campaignSummaryCards.map((card) => {
              const hasRun = Boolean(card.latestRun);
              const missed = card.summary.missedCount;
              const detected = card.summary.detectedCount;
              const checkedAttackCount = card.summary.successfulAttackCount;
              const detectedWidth = checkedAttackCount > 0
                ? (card.summary.detectedCount / checkedAttackCount) * 100
                : 0;
              const missedWidth = checkedAttackCount > 0
                ? (card.summary.missedCount / checkedAttackCount) * 100
                : 0;
              const notCheckedWidth = checkedAttackCount > 0
                ? (card.summary.notCheckedCount / checkedAttackCount) * 100
                : 0;
              const cardLabel = !hasRun
                ? "미점검"
                : missed > 0
                  ? "탐지 갭"
                  : detected > 0
                    ? "탐지 양호"
                    : "탐지 미확인";

              return (
                <button
                  key={card.campaign.campaign_id}
                  type="button"
                  className={[
                    "campaign-summary-card",
                    card.isSelectedCampaign ? "selected-campaign-summary" : "",
                    missed > 0 ? "has-gap" : "",
                  ].join(" ")}
                  onClick={() => selectCampaignAndShow(card.campaign.campaign_id, null)}
                >
                  <span className="campaign-summary-head">
                    <strong>{card.campaign.campaign_id}</strong>
                    <span className={`status-tag ${missed > 0 ? "missed" : detected > 0 ? "detected" : "not_checked"}`}>
                      {cardLabel}
                    </span>
                  </span>
                  <small>{card.campaign.campaign_name}</small>
                  <span className="campaign-summary-metrics">
                    <span>
                      <em>테크닉</em>
                      <strong>{card.techniqueCount || "--"}</strong>
                    </span>
                    <span>
                      <em>탐지율</em>
                      <strong>{hasRun && checkedAttackCount > 0 ? `${card.defenseRate}%` : "--"}</strong>
                    </span>
                    <span>
                      <em>탐지 갭</em>
                      <strong>{card.summary.missedCount}</strong>
                    </span>
                    <span>
                      <em>미확인</em>
                      <strong>{card.summary.notCheckedCount}</strong>
                    </span>
                  </span>
                  <span className="campaign-card-footer">
                    <span>
                      점수 <strong>{card.summary.score ?? "--"}</strong>
                    </span>
                    <span>
                      검증 대상 <strong>{checkedAttackCount || "--"}</strong>
                    </span>
                  </span>
                  <span
                    className="detection-stack"
                    aria-label={`탐지 ${card.summary.detectedCount}, 탐지 갭 ${card.summary.missedCount}, 미확인 ${card.summary.notCheckedCount}`}
                  >
                    <span className="detected-segment" style={{ width: `${detectedWidth}%` }} />
                    <span className="missed-segment" style={{ width: `${missedWidth}%` }} />
                    <span className="unknown-segment" style={{ width: `${notCheckedWidth}%` }} />
                  </span>
                  <span className="stack-caption">초록 탐지 / 빨강 갭 / 주황 미확인</span>
                </button>
              );
            })}
          </div>
        </div>

        <div className="panel execution-chart-panel">
          <div className="section-title">실행 결과 그래프</div>
          <h3>{visibleSummaryRun ? visibleSummaryRun.campaign_id : selectedCampaignId}</h3>
          <p className="chart-helper">
            선택한 캠페인에서 실제로 실행된 단계 비율입니다.
          </p>
          <div className="chart-content">
            <div className="donut-chart" style={executionChartStyle}>
              <div>
                <strong>{visibleExecutionRate === null ? "--" : `${visibleExecutionRate}%`}</strong>
                <span>실행률</span>
              </div>
            </div>

            <div className="chart-legend">
              <span><i className="legend-total" />전체 단계 <strong>{dashboardSummary.totalSteps || "--"}</strong></span>
              <span><i className="legend-success" />성공 <strong>{dashboardSummary.successCount}</strong></span>
              <span><i className="legend-simulated" />시뮬레이션 <strong>{dashboardSummary.simulatedCount}</strong></span>
              <span><i className="legend-failed" />실패 <strong>{dashboardSummary.failedCount}</strong></span>
            </div>
          </div>
        </div>

        <div className="panel detection-chart-panel">
          <div className="section-title">탐지 검증 그래프</div>
          <h3>{dashboardSummary.successfulAttackCount}개 공격 검증</h3>
          <p className="chart-helper">
            실행된 공격 중 ELK에서 잡힌 것과 놓친 것을 나눠 보여줍니다.
          </p>
          <div className="chart-content">
            <div className="donut-chart" style={detectionChartStyle}>
              <div>
                <strong>{visibleDetectionRate === null ? "--" : `${visibleDetectionRate}%`}</strong>
                <span>탐지율</span>
              </div>
            </div>

            <div className="chart-legend">
              <span><i className="legend-detected" />탐지됨 <strong>{dashboardSummary.detectedCount}</strong></span>
              <span><i className="legend-missed" />미탐지 <strong>{dashboardSummary.missedCount}</strong></span>
              <span><i className="legend-ready" />미확인 <strong>{dashboardSummary.notCheckedCount}</strong></span>
            </div>
          </div>
        </div>
      </section>
      </>
      )}

      {activeView === "validation" && (
      <>
      <section className="view-header validation-hero">
        <div>
          <span>BAS Validation Map</span>
          <h2>공격 경로와 보안 통제 검증</h2>
          <p>멘토 피드백 기준으로 자산, 네트워크 구간, Agent, 로그 수집, Kibana 탐지룰을 하나의 검증 맵으로 연결합니다.</p>
        </div>
        <div className="view-header-metrics">
          <span>Detected <strong>{recentVerificationDetectedCount}</strong></span>
          <span>Logged <strong>{recentVerificationLoggedOnlyCount}</strong></span>
          <span>Gap <strong>{recentVerificationMissedCount}</strong></span>
          <span>Backlog <strong>{remediationBacklogRows.length}</strong></span>
        </div>
      </section>

      <section className="bas-validation-layout">
        <section className="panel validation-map-panel">
          <div className="panel-title-row">
            <div>
              <div className="section-title">Enterprise Validation Canvas</div>
              <h3>SB-AD 공격 경로</h3>
            </div>
            <span className="scope-pill">상용 BAS형 데모</span>
          </div>

          <div className="enterprise-map">
            {segmentInventory.map((segment, index) => (
              <div
                key={`enterprise-zone-${segment.segment_id}`}
                className={`enterprise-zone enterprise-zone-${segment.type || "internal"}`}
                style={getSegmentStyle(index, segmentInventory.length)}
              >
                <span>{segment.type || "segment"}</span>
                <strong>{segment.name || segment.segment_id}</strong>
              </div>
            ))}

            <svg className="enterprise-map-links" viewBox="0 0 1000 480" aria-hidden="true">
              <defs>
                <marker id="enterprise-arrow-orange" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto">
                  <path d="M0,0 L10,5 L0,10 Z" />
                </marker>
                <marker id="enterprise-arrow-blue" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto">
                  <path d="M0,0 L10,5 L0,10 Z" />
                </marker>
                <marker id="enterprise-arrow-red" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto">
                  <path d="M0,0 L10,5 L0,10 Z" />
                </marker>
                <marker id="enterprise-arrow-green" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto">
                  <path d="M0,0 L10,5 L0,10 Z" />
                </marker>
              </defs>
              <path
                className={`enterprise-link link-orange status-${attackPathTelemetry[0]?.status || "planned"}`}
                d="M170 240 C230 210 285 210 345 240"
                markerEnd="url(#enterprise-arrow-orange)"
              />
              <path
                className={`enterprise-link link-blue status-${attackPathTelemetry[1]?.status || "planned"}`}
                d="M455 240 C515 210 570 210 630 240"
                markerEnd="url(#enterprise-arrow-blue)"
              />
              <path
                className={`enterprise-link link-red status-${attackPathTelemetry[3]?.status || "planned"}`}
                d="M720 205 C780 120 830 110 885 145"
                markerEnd="url(#enterprise-arrow-red)"
              />
              <path
                className={`enterprise-link link-green status-${attackPathTelemetry[2]?.status || "planned"}`}
                d="M665 300 C520 430 300 420 165 290"
                markerEnd="url(#enterprise-arrow-green)"
              />
            </svg>

            <div className="validation-gate gate-entry">
              <strong>Gate 1</strong>
              <span>SG + Endpoint</span>
            </div>
            <div className="validation-gate gate-lateral">
              <strong>Gate 2</strong>
              <span>PowerShell + WinRM</span>
            </div>
            <div className="validation-gate gate-domain">
              <strong>Gate 3</strong>
              <span>AD Audit + SIEM</span>
            </div>
            <div className="validation-gate gate-egress">
              <strong>Gate 4</strong>
              <span>Egress + SIEM</span>
            </div>

            {topologyNodes.map((asset, index) => (
              <div
                key={`enterprise-${asset.asset_id}`}
                className={[
                  "enterprise-node",
                  `enterprise-${asset.asset_id}`,
                  `criticality-${asset.criticality || "medium"}`,
                ].join(" ")}
                style={getMapNodeStyle(index, topologyNodes.length)}
              >
                <div className="enterprise-device" aria-hidden="true">
                  <span>
                    {asset.platform?.toLowerCase().includes("windows")
                      ? "WIN"
                      : asset.asset_id === "elk"
                        ? "SIEM"
                        : "LNX"}
                  </span>
                </div>
                <div>
                  <strong>{asset.name || asset.asset_id}</strong>
                  <small>{asset.private_ip || asset.hostname}</small>
                  <em className={`asset-agent-badge ${asset.agentStatus}`}>{asset.agentLabel}</em>
                </div>
              </div>
            ))}
          </div>
        </section>

        <aside className="validation-side-stack">
          <section className="panel remediation-backlog-panel">
            <div className="panel-title-row">
              <div>
                <div className="section-title">Remediation Backlog</div>
                <h3>자동 생성 조치 목록</h3>
              </div>
              <span className="page-indicator">{remediationBacklogRows.length} items</span>
            </div>

            <div className="backlog-list">
              {remediationBacklogRows.slice(0, 6).map((item) => (
                <div key={`${item.order}-${item.techniqueId}-${item.gapType}`} className={`backlog-item ${item.priority.toLowerCase()}`}>
                  <span className="backlog-priority">{item.priority}</span>
                  <div>
                    <strong>{item.techniqueId} · {item.gapType}</strong>
                    <small>{item.order}. {item.name}</small>
                    <em>{item.action}</em>
                  </div>
                  <span className={`status-tag ${item.status}`}>{getDetectionLabel({ detection_status: item.status })}</span>
                </div>
              ))}

              {remediationBacklogRows.length === 0 && (
                <p className="empty">현재 선택된 실행에서 자동 조치 항목이 없습니다.</p>
              )}
            </div>
          </section>

        </aside>
      </section>
      </>
      )}

      {activeView === "assets" && (
      <>
      <section className="view-header">
        <div>
          <span>Asset Exposure Context</span>
          <h2>자산 파악 및 검증 범위</h2>
          <p>상용 BAS처럼 공격 실행 전에 어떤 자산, 네트워크 구간, 논리적 보안 통제를 검증 대상으로 삼는지 보여주는 데모 화면입니다.</p>
        </div>
        <div className="view-header-metrics">
          <span>Assets <strong>{assetInventory.length}</strong></span>
          <span>Segments <strong>{segmentInventory.length}</strong></span>
          <span>Agents <strong>{onlineAgentAssetCount}/{agentRequiredAssets.length}</strong></span>
          <span>Critical <strong>{criticalAssetCount}</strong></span>
        </div>
      </section>

      <section className="asset-dashboard-grid">
        <section className="panel asset-map-panel">
          <div className="panel-title-row">
            <div>
              <div className="section-title">Environment Map</div>
              <h3>{selectedCampaignId} 네트워크 구간</h3>
            </div>
            <span className="scope-pill">Demo inventory</span>
          </div>

          <div className="topology-board" aria-label="SB-AD asset topology">
            <div className="topology-zones" aria-hidden="true">
              {segmentInventory.map((segment) => (
                <div key={segment.segment_id} className={`topology-zone zone-${segment.type || "internal"}`}>
                  <span>{segment.name || segment.segment_id}</span>
                </div>
              ))}
            </div>

            <svg className="topology-links" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
              <defs>
                <marker id="topology-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
                  <path d="M0,0 L8,4 L0,8 Z" />
                </marker>
                <marker id="topology-arrow-critical" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
                  <path d="M0,0 L8,4 L0,8 Z" />
                </marker>
              </defs>
              <path className="topology-link initial" d="M18 50 L33 50" markerEnd="url(#topology-arrow)" />
              <path className="topology-link lateral" d="M42 50 L56 50" markerEnd="url(#topology-arrow)" />
              <path className="topology-link exfil" d="M62 59 C50 82 30 80 18 58" markerEnd="url(#topology-arrow)" />
              <path className="topology-link critical" d="M62 43 C68 28 74 25 80 26" markerEnd="url(#topology-arrow-critical)" />
            </svg>

            <div className="topology-label label-initial">Initial Access</div>
            <div className="topology-label label-winrm">WinRM</div>
            <div className="topology-label label-dcsync">DCSync</div>
            <div className="topology-label label-exfil">Exfil</div>

            {topologyNodes.map((asset, index) => (
              <div
                key={asset.asset_id}
                className={[
                  "topology-node",
                  `topology-${asset.asset_id}`,
                  `criticality-${asset.criticality || "medium"}`,
                  asset.agent_required ? "requires-agent" : "observe-only",
                ].join(" ")}
                style={getMapNodeStyle(index, topologyNodes.length)}
              >
                <div className="node-device" aria-hidden="true">
                  <span className="device-screen">
                    {asset.platform?.toLowerCase().includes("windows")
                      ? "WIN"
                      : asset.asset_id === "elk"
                        ? "SIEM"
                        : "LNX"}
                  </span>
                  <span className="device-stand" />
                </div>
                <div className="node-copy">
                  <strong>{asset.name || asset.asset_id}</strong>
                  <small>{asset.private_ip || asset.hostname || "IP 미정"}</small>
                  <span>{asset.role || asset.segment_id}</span>
                </div>
                <em className={`asset-agent-badge ${asset.agentStatus}`}>
                  {asset.agentLabel}
                </em>
              </div>
            ))}
          </div>

          <div className="segment-summary-strip">
            {segmentInventory.map((segment) => (
              <div key={segment.segment_id}>
                <span>{segment.type || "segment"}</span>
                <strong>{segment.name || segment.segment_id}</strong>
                <small>{segment.assets.length} assets</small>
              </div>
            ))}
          </div>
        </section>

        <section className="panel attack-route-panel">
          <div className="panel-title-row">
            <div>
              <div className="section-title">Attack Path</div>
              <h3>검증 경로</h3>
            </div>
            <span className="page-indicator">{attackPathInventory.length} paths</span>
          </div>

          <div className="attack-route-list">
            {attackPathInventory.map((path, index) => (
              <div key={`${path.source_asset_id}-${path.target_asset_id}-${index}`} className="attack-route-item">
                <div className="route-order">{index + 1}</div>
                <div>
                  <strong>
                    {path.sourceAsset?.name || path.source_asset_id}
                    <span>→</span>
                    {path.targetAsset?.name || path.target_asset_id}
                  </strong>
                  <small>{path.label}</small>
                  <p>{path.techniques.join(", ")}</p>
                </div>
              </div>
            ))}

            {attackPathInventory.length === 0 && (
              <p className="empty">이 캠페인에는 공격 경로 메타데이터가 아직 없습니다.</p>
            )}
          </div>
        </section>

        <section className="panel asset-inventory-panel">
          <div className="panel-title-row">
            <div>
              <div className="section-title">Asset Inventory</div>
              <h3>검증 대상 자산</h3>
            </div>
            <span className="page-indicator">{assetInventory.length} assets</span>
          </div>

          <div className="asset-table">
            <div className="asset-table-row asset-table-header">
              <span>Asset</span>
              <span>Segment</span>
              <span>Role</span>
              <span>Criticality</span>
              <span>Agent</span>
            </div>

            {assetInventory.map((asset) => (
              <div key={asset.asset_id} className="asset-table-row">
                <span>
                  <strong>{asset.name || asset.asset_id}</strong>
                  <small>{asset.private_ip || asset.hostname || "-"}</small>
                </span>
                <span>{asset.segment_id || "-"}</span>
                <span>{asset.role || "-"}</span>
                <span>
                  <em className={`criticality-pill criticality-${asset.criticality || "medium"}`}>
                    {asset.criticalityLabel}
                  </em>
                </span>
                <span>
                  <em className={`asset-agent-badge ${asset.agentStatus}`}>
                    {asset.agentLabel}
                  </em>
                </span>
              </div>
            ))}
          </div>
        </section>

        <section className="panel control-coverage-panel">
          <div className="panel-title-row">
            <div>
              <div className="section-title">Security Controls</div>
              <h3>논리적 통제 매핑</h3>
            </div>
            <span className="page-indicator">{securityControlInventory.length} controls</span>
          </div>

          <div className="control-card-grid">
            {securityControlInventory.map((control) => (
              <div key={control.control_id} className="control-card">
                <div>
                  <strong>{control.name || control.control_id}</strong>
                  <small>{control.category}</small>
                </div>
                <span className={`control-status ${String(control.status || "configured").replaceAll(" ", "-")}`}>
                  {control.status || "configured"}
                </span>
                <p>{control.coveredAssets.map((asset) => asset.name || asset.asset_id).join(", ") || "매핑 자산 없음"}</p>
              </div>
            ))}
          </div>
        </section>
      </section>
      </>
      )}

      {activeView === "scope" && (
      <>
      <section className="view-header">
        <div>
          <span>Operation Builder</span>
          <h2>캠페인 컨텍스트와 테크닉을 조합</h2>
          <p>선택한 캠페인의 Technique을 기본으로 보여주고, 필요한 검증 항목을 큐에 담아 실행합니다.</p>
        </div>
        <button
          className="run-button"
          onClick={runCampaign}
          disabled={isRunning || !selectedCampaignId || selectedOperationSteps.length === 0}
        >
          {isRunning ? "실행 중..." : "큐 실행"}
        </button>
      </section>
      <section className="operator-grid">
        <section className="panel technique-panel">
          <div className="panel-title-row">
            <div>
              <div className="section-title">Technique Library</div>
              <h3>Technique Selection</h3>
            </div>
            <div className="selection-actions compact-actions">
              <button type="button" className="secondary-button" onClick={loadCampaignPreset}>
                캠페인 기본값
              </button>
              <button type="button" className="secondary-button normal-action" onClick={loadCampaignAttacksOnly}>
                공격만
              </button>
              <button type="button" className="ghost-button" onClick={clearOperationQueue}>
                큐 비우기
              </button>
            </div>
          </div>

          <div className="library-toolbar">
            <input
              type="search"
              value={techniqueQuery}
              onChange={(event) => setTechniqueQuery(event.target.value)}
              placeholder="T1609, secret, kube..."
            />
            <select
              value={techniqueSourceFilter}
              onChange={(event) => setTechniqueSourceFilter(event.target.value)}
              aria-label="Technique source campaign"
            >
              <option value="all">All campaigns</option>
              {librarySourceIds.map((sourceId) => (
                <option key={sourceId} value={sourceId}>{sourceId}</option>
              ))}
            </select>
            <select
              value={techniquePhaseFilter}
              onChange={(event) => setTechniquePhaseFilter(event.target.value)}
            >
              <option value="all">전체 단계</option>
              <option value="attack">Attack</option>
              <option value="normal">Normal</option>
            </select>
          </div>

          <div className="technique-list library-list">
            {filteredTechniqueLibrary.map((step) => {
              const selectionId = getTechniqueSelectionId(step);
              const isSelectedStep = selectedTechniqueIds.includes(selectionId);
              const sourceId = getTechniqueSourceId(step);
              const readiness = getOperationReadiness(step);
              const compatibility = readiness.compatibility;
              return (
                <button
                  key={selectionId}
                  type="button"
                  className={[
                    "technique-row",
                    step.phase,
                    isSelectedStep ? "selected-step" : "",
                  ].join(" ")}
                  onClick={() => toggleTechnique(step)}
                >
                  <span className="step-index">{sourceId.replace("SB-", "")}.{step.order}</span>
                  <span className="technique-main">
                    <strong>{step.name}</strong>
                    <small>{sourceId} · {getTechniqueDisplayName(step)}</small>
                  </span>
                  <span className="technique-tags">
                    <span
                      className={`readiness-chip ${readiness.status}`}
                      title={[
                        compatibility.missing.length > 0 ? `환경에서 확인할 항목: ${compatibility.missing.join(", ")}` : "",
                      ].filter(Boolean).join(" / ") || "선택한 환경에서 바로 검증할 수 있습니다."}
                    >
                      {readiness.label}
                    </span>
                    <span className={step.phase === "attack" ? "chip attack-chip" : "chip normal-chip"}>
                      {step.phase === "attack" ? "Attack" : "Normal"}
                    </span>
                    {step.technique_id && (
                      <span className="chip technique-chip">{step.technique_id}</span>
                    )}
                  </span>
                </button>
              );
            })}
            {filteredTechniqueLibrary.length === 0 && <p className="empty">조건에 맞는 테크닉이 없습니다.</p>}
          </div>
        </section>

        <section className="panel operation-queue-panel">
          <div className="panel-title-row">
            <div>
              <div className="section-title">Execution Queue</div>
              <h3>{selectedOperationSteps.length}개 테크닉</h3>
            </div>
            <span className="page-indicator">Attack {queuedAttackCount}</span>
          </div>

          <div className="queue-context-strip">
            <div>
              <span>컨텍스트</span>
              <strong>{selectedCampaignId}</strong>
            </div>
            <div>
              <span>실행 방식</span>
              <strong>사용자 조합</strong>
            </div>
            <div>
              <span>검증 대상</span>
              <strong>{selectedOperationSteps.length || "--"}</strong>
            </div>
          </div>

          <section className="routing-status-card">
            <div className="panel-title-row">
              <div>
                <div className="section-title">Multi-Agent Routing</div>
                <h3>{latestOperation ? latestOperation.operation_id : "실행 전 라우팅 계획"}</h3>
              </div>
              <span className={`job-badge ${latestOperation?.status || "planned"}`}>
                {latestOperation?.status || "planned"}
              </span>
            </div>

            <div className="routing-role-grid">
              {routingRoles.map((role) => {
                const plannedCount = plannedRoutes[role]?.length || 0;
                const operationSteps = visibleOperationSteps.filter((step) => step.agent_role === role);
                const displayCount = operationSteps.length || plannedCount;
                const roleStatus = operationSteps.find((step) => step.status === "running")?.status
                  || operationSteps.find((step) => step.status === "queued")?.status
                  || operationSteps.find((step) => step.status === "completed")?.status
                  || operationSteps.find((step) => step.status === "simulated")?.status
                  || operationSteps.find((step) => step.status === "blocked")?.status
                  || (displayCount > 0 ? "planned" : "empty");

                return (
                  <div key={`route-${role}`} className={`routing-role-card ${roleStatus}`}>
                    <span>{getAgentRoleLabel(role)}</span>
                    <strong>{displayCount}</strong>
                    <small>{roleStatus === "empty" ? "배정 없음" : roleStatus}</small>
                  </div>
                );
              })}
            </div>

            <div className="routing-step-list">
              {(visibleOperationSteps.length > 0 ? visibleOperationSteps : selectedOperationSteps.map((step) => ({
                order: step.order,
                name: step.name,
                technique_id: step.technique_id,
                agent_role: getRequiredAgentRole(step),
                status: "planned",
              }))).map((step) => (
                <div key={`route-step-${step.agent_role}-${step.order}`} className="routing-step-row">
                  <span>{getAgentRoleLabel(step.agent_role)}</span>
                  <strong>{step.order}. {step.technique_id || step.name}</strong>
                  <em className={`job-badge ${step.status || "planned"}`}>{step.status || "planned"}</em>
                </div>
              ))}
              {selectedOperationSteps.length === 0 && visibleOperationSteps.length === 0 && (
                <p className="empty">큐에 담은 테크닉이 생기면 역할별 라우팅 계획이 여기에 표시됩니다.</p>
              )}
            </div>
          </section>

          <div className="queue-list">
            {selectedOperationSteps.map((step, index) => {
              const selectionId = getTechniqueSelectionId(step);
              const sourceId = getTechniqueSourceId(step);
              const readiness = getOperationReadiness(step);
              const compatibility = readiness.compatibility;
              const inputDefinitions = getTechniqueInputDefinitions(step);
              const hasInputs = inputDefinitions.length > 0;
              const isInputExpanded = expandedTechniqueInputIds.includes(selectionId);
              const inputSummary = getTechniqueInputSummary(step, selectionId);

              return (
                <div key={selectionId} className={`queue-item ${step.phase} readiness-${readiness.status}`}>
                  <span className="queue-order">{index + 1}</span>
                  <div className="queue-main">
                    <strong>{step.name}</strong>
                    <small>{sourceId} · 실행 target {selectedCampaignId} · {getTechniqueDisplayName(step)}</small>
                    {compatibility.missing.length > 0 && (
                      <small className="compatibility-note">현재 환경에 없는 구성: {compatibility.missing.join(", ")}</small>
                    )}
                    {hasInputs && (
                      <div className="queue-input-summary">
                        <span>자동 설정</span>
                        <strong>{inputSummary}</strong>
                        <button
                          type="button"
                          className="inline-tune-button"
                          onClick={() => toggleTechniqueInputs(selectionId)}
                        >
                          {isInputExpanded ? "닫기" : "조정"}
                        </button>
                      </div>
                    )}
                    {hasInputs && isInputExpanded && (
                      <div className="queue-input-grid">
                        {inputDefinitions.map((input) => {
                          const inputValue = techniqueInputs[selectionId]?.[input.name] ?? String(input.default ?? step.params?.[input.name] ?? "");

                          return (
                            <label key={`${selectionId}-${input.name}`} className="queue-input-field">
                              <span>{input.label || input.name}</span>
                              {Array.isArray(input.options) ? (
                                <select
                                  value={inputValue}
                                  onChange={(event) => updateTechniqueInput(selectionId, input.name, event.target.value)}
                                >
                                  {input.options.map((option) => (
                                    <option key={option} value={option}>{option}</option>
                                  ))}
                                </select>
                              ) : (
                                <input
                                  type={input.type === "number" || input.type === "integer" ? "number" : "text"}
                                  value={inputValue}
                                  placeholder={input.placeholder || ""}
                                  onChange={(event) => updateTechniqueInput(selectionId, input.name, event.target.value)}
                                />
                              )}
                            </label>
                          );
                        })}
                      </div>
                    )}
                  </div>
                  <div className="queue-actions">
                    <span className={`readiness-chip ${readiness.status}`}>
                      {readiness.label}
                    </span>
                    <button
                      type="button"
                      className="icon-action"
                      onClick={() => moveQueuedTechnique(selectionId, -1)}
                      disabled={index === 0}
                      aria-label="위로 이동"
                    >
                      ↑
                    </button>
                    <button
                      type="button"
                      className="icon-action"
                      onClick={() => moveQueuedTechnique(selectionId, 1)}
                      disabled={index === selectedOperationSteps.length - 1}
                      aria-label="아래로 이동"
                    >
                      ↓
                    </button>
                    <button
                      type="button"
                      className="icon-action danger"
                      onClick={() => removeQueuedTechnique(selectionId)}
                      aria-label="큐에서 제거"
                    >
                      ×
                    </button>
                  </div>
                </div>
              );
            })}
            {selectedOperationSteps.length === 0 && (
              <p className="empty">왼쪽 라이브러리에서 테크닉을 클릭하면 실행 큐에 들어갑니다.</p>
            )}
          </div>

          <div className="queue-result-preview">
            <div className="panel-title-row">
              <div>
                <div className="section-title">최근 검증</div>
                <h3>{recentVerificationTitle}</h3>
              </div>
              <span className="page-indicator">{recentVerificationExecutedCount}개 반영됨</span>
            </div>

            <div className="validation-metrics">
              <div>
                <span>공격</span>
                <strong>{recentVerificationAttackSteps.length}</strong>
              </div>
              <div>
                <span>탐지</span>
                <strong>{recentVerificationDetectedCount}</strong>
              </div>
              <div>
                <span>로그만</span>
                <strong>{recentVerificationLoggedOnlyCount}</strong>
              </div>
              <div>
                <span>미탐</span>
                <strong>{recentVerificationMissedCount}</strong>
              </div>
              <div>
                <span>미확인</span>
                <strong>{recentVerificationNotCheckedCount}</strong>
              </div>
            </div>

            <div className="execution-backlog-strip">
              <div className="panel-title-row">
                <div>
                  <div className="section-title">자동 조치 목록</div>
                  <h3>{remediationBacklogRows.length}개 개선 항목</h3>
                </div>
              </div>

              <div className="execution-backlog-list">
                {remediationBacklogRows.slice(0, 4).map((item) => (
                  <div key={`execution-backlog-${item.order}-${item.techniqueId}-${item.gapType}`} className="execution-backlog-item">
                    <span className="backlog-priority">{item.priority}</span>
                    <strong>{item.techniqueId} · {item.gapType}</strong>
                    <small>{item.action}</small>
                  </div>
                ))}

                {remediationBacklogRows.length === 0 && (
                  <p className="empty">최근 검증에서 자동 조치 항목이 없습니다.</p>
                )}
              </div>
            </div>
          </div>

          <div className="path-map compact-path-map">
            {attackPathSteps.map((step) => {
              const hasRunResult = Boolean(step.status);
              const executionStatus = step.status || "queued";
              const detectionStatus = hasRunResult ? getDetectionStatus(step) : "not_run";
              const riskLevel = hasRunResult ? getRiskLevel(step) : "not_run";
              const selectionId = step.selection_id || `${step.source_campaign_id || selectedCampaignId}:${step.order}`;
              const isSelectedPath = selectedTechniqueIds.includes(selectionId)
                || selectedRun?.requested_steps?.some((item) => `${item.campaign_id}:${item.order}` === selectionId);

              return (
                <div
                  key={selectionId}
                  className={[
                    "validation-row",
                    step.phase,
                    isSelectedPath ? "selected-path-node" : "",
                  ].join(" ")}
                >
                  <div>
                    <strong>{step.source_campaign_id || selectedCampaignId}.{step.order} {step.name}</strong>
                    <small>{getTechniqueDisplayName(step)}</small>
                  </div>
                  <div className="validation-badges">
                    <span className={`result-badge ${executionStatus}`}>{executionStatus}</span>
                    <span className={`status-tag ${detectionStatus}`}>{hasRunResult ? getDetectionLabel(step) : "대기"}</span>
                    <span className={`status-tag risk-${riskLevel}`}>{riskLevel}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      </section>
      </>
      )}

      {activeView === "history" && (
      <>
      <section className="view-header">
        <div>
          <span>결과 기록</span>
          <h2>이전 실행 결과</h2>
          <p>완료된 실행을 열면 증거 확인 화면에서 상세 로그와 ELK 검증 결과를 볼 수 있습니다.</p>
        </div>
      </section>
      <section className="panel activity-panel">
        <div className="panel-title-row">
          <div>
            <div className="section-title">실행 내역</div>
            <h3>Jobs / Runs</h3>
          </div>
          <span className="scope-pill">{jobs.length} jobs / {runs.length} runs</span>
        </div>

        <div className="activity-grid">
          <section>
          <div className="panel-title-row">
            <div>
              <div className="section-title">Jobs</div>
              <h3>대기열</h3>
            </div>
            {latestJob && <span className={`job-badge ${latestJob.status}`}>{latestJob.status}</span>}
          </div>

          <div className="job-stack">
            {recentJobs.map((job) => (
              <button
                key={job.job_id}
                type="button"
                className="job-row"
                onClick={() => job.execution_id && loadRun(job.execution_id)}
              >
                <span>
                  <strong>{job.campaign_id}</strong>
                  <small>{job.job_id}</small>
                </span>
                <span className={`job-badge ${job.status}`}>{job.status}</span>
              </button>
            ))}
            {recentJobs.length === 0 && <p className="empty">아직 실행 대기 중인 Job이 없습니다.</p>}
          </div>
          </section>

          <section>
          <div className="panel-title-row">
            <div>
              <div className="section-title">Runs</div>
              <h3>기록</h3>
            </div>
            <span className="page-indicator">
              {runs.length === 0 ? "0 / 0" : `${runPage + 1} / ${runPageCount}`}
            </span>
          </div>

          <div className="run-list compact-run-list">
            {visibleRuns.map((run) => (
              <button
                key={run.execution_id}
                className={
                  selectedRun?.execution_id === run.execution_id
                    ? "run-item selected-run"
                    : "run-item"
                }
                onClick={() => loadRun(run.execution_id)}
              >
                <strong>{run.execution_id}</strong>
                <span>{run.campaign_id}</span>
                <small>{run.started_at}</small>
              </button>
            ))}
            {runs.length === 0 && <p className="empty">아직 실행 기록이 없습니다.</p>}
          </div>

          <div className="run-pager">
            <button
              type="button"
              className="ghost-button"
              onClick={() => setRunPage((page) => Math.max(0, page - 1))}
              disabled={runPage === 0}
            >
              이전
            </button>
            <button
              type="button"
              className="ghost-button"
              onClick={() => setRunPage((page) => Math.min(runPageCount - 1, page + 1))}
              disabled={runPage >= runPageCount - 1}
            >
              다음
            </button>
          </div>
          </section>
        </div>
      </section>
      </>
      )}

      {activeView === "evidence" && (
      <>
      <section className="view-header">
        <div>
          <span>증거 확인</span>
          <h2>{selectedRun ? "실행 증거" : "확인할 실행 선택"}</h2>
          <p>명령 결과, 수집된 아티팩트, ELK 쿼리와 샘플 로그를 확인합니다.</p>
        </div>
      </section>
      <section className="panel evidence-panel">
        <div className="panel-title-row">
          <div>
            <div className="section-title">증거</div>
            <h3>{selectedRun ? selectedRun.execution_id : "실행 결과를 선택하거나 새로 실행하세요"}</h3>
          </div>
          {selectedRun && (
            <div className="run-detail-actions">
              <span className="scope-pill">{selectedRun.campaign_id}</span>
              <a
                className="report-link-button"
                href={REPORT_MOCKUP_URL}
                target="_blank"
                rel="noreferrer"
              >
                HTML 보고서 보기
              </a>
            </div>
          )}
        </div>

        {!selectedRun && <p className="empty">실행 상세에는 명령, 생성 아티팩트, 탐지 근거가 표시됩니다.</p>}

        {selectedRun && (
          <div className="result-steps evidence-list">
            {(selectedRun.steps || []).map((step) => (
              <div key={`${step.order}-${step.module}`} className="result-step evidence-step">
                <div>
                  <div className="evidence-step-header">
                    <strong>{step.order}. {step.name}</strong>
                    <span className={`result-badge ${step.status}`}>{step.status}</span>
                  </div>

                  <div className="step-meta">
                    <span className={step.phase === "attack" ? "chip attack-chip" : "chip normal-chip"}>
                      {step.phase === "attack" ? "Attack" : "Normal"}
                    </span>
                    {step.technique_id && <span className="chip technique-chip">{step.technique_id}</span>}
                    <span className={`status-tag ${getDetectionStatus(step)}`}>{getDetectionLabel(step)}</span>
                  </div>

                  <p>{step.module_result?.message}</p>
                  {renderModuleEvidence(step)}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
      </>
      )}
        </section>
      </section>
    </main>
  );
}
