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
  "T1021.004": "Remote Services: SSH",
  "T1083": "File and Directory Discovery",
  "T1098.006": "Additional Container and Cloud Roles",
  "T1552.007": "Container and Resource Discovery Credentials",
  "T1560.001": "Archive via Utility",
  "T1567.002": "Exfiltration to Cloud Storage",
  "T1609": "Container and Resource Discovery",
  "T1610": "Deploy Container",
  "T1613": "Container and Resource Discovery",
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
  const [agents, setAgents] = useState([]);
  const [selectedAgentId, setSelectedAgentId] = useState("");
  const [selectedRun, setSelectedRun] = useState(null);
  const [selectedOrders, setSelectedOrders] = useState([]);
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

  async function fetchJson(path, options) {
    const response = await fetch(`${API_BASE}${path}`, options);

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
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

    const runData = await fetchJson("/runs");
    setRuns(runData.runs || []);

    return {
      agents: loadedAgents,
      jobs: jobData.jobs || [],
      runs: runData.runs || [],
    };
  }

  async function pollJobUntilFinished(jobId) {
    for (let attempt = 0; attempt < JOB_POLL_ATTEMPTS; attempt += 1) {
      const job = await fetchJson(`/jobs/${jobId}`);
      setJobs((currentJobs) => {
        const withoutCurrentJob = currentJobs.filter((item) => item.job_id !== job.job_id);
        return [job, ...withoutCurrentJob];
      });

      if (job.status === "completed") {
        setNotice(`Job completed: ${jobId}`);
        setIsRunning(false);

        if (job.execution_id) {
          const run = await fetchJson(`/runs/${job.execution_id}`);
          setSelectedRun(run);
          setRuns((currentRuns) => {
            const withoutCurrentRun = currentRuns.filter((item) => item.execution_id !== run.execution_id);
            return [run, ...withoutCurrentRun];
          });
        }

        await refreshDashboardData();
        return job;
      }

      if (job.status === "failed") {
        throw new Error(job.error || `Job failed: ${jobId}`);
      }

      setNotice(`Job ${job.status}: ${jobId}`);
      await sleep(JOB_POLL_INTERVAL_MS);
    }

    setNotice(`Job is still running: ${jobId}`);
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
      const compatibilityData = await fetchJson(`/campaigns/${campaignId}/technique-compatibility`);
      const agentData = await fetchJson("/agents");
      const loadedAgents = agentData.agents || [];
      setCampaignDetail(data);
      setTargetDetail(targetData);
      setTechniqueCompatibility(compatibilityData.compatibility || {});
      setSelectedCampaignId(campaignId);
      setAgents(loadedAgents);
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
    setSelectedOrders([]);
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

  function resolveDependencies(order, flow) {
    const stepByOrder = new Map(flow.map((step) => [step.order, step]));
    const resolved = new Set([order]);

    function visit(currentOrder) {
      const step = stepByOrder.get(currentOrder);
      if (!step) return;

      (step.depends_on_orders || []).forEach((dependency) => {
        if (!resolved.has(dependency)) {
          resolved.add(dependency);
          visit(dependency);
        }
      });
    }

    visit(order);
    return Array.from(resolved).sort((a, b) => a - b);
  }

  function getStepLabel(order) {
    const step = (campaignDetail?.flow || []).find((item) => item.order === order);
    if (!step) return `${order}`;
    return step.technique_id ? `${order} (${step.technique_id})` : `${order}`;
  }

  function toggleStep(step) {
    const flow = campaignDetail?.flow || [];
    const requiredOrders = resolveDependencies(step.order, flow);
    const current = new Set(selectedOrders);
    const alreadySelected = current.has(step.order);

    if (alreadySelected) {
      current.delete(step.order);
      setSelectedOrders(Array.from(current).sort((a, b) => a - b));
      setNotice("");
      return;
    }

    requiredOrders.forEach((order) => current.add(order));

    const autoIncluded = requiredOrders.filter((order) => order !== step.order);
    setSelectedOrders(Array.from(current).sort((a, b) => a - b));

    if (autoIncluded.length > 0) {
      const labels = autoIncluded.map(getStepLabel).join(", ");
      setNotice(`${step.technique_id || step.name} also selected required steps: ${labels}`);
    } else {
      setNotice("");
    }
  }

  function selectAllAttacks() {
    const attackOrders = (campaignDetail?.flow || [])
      .filter((step) => step.phase === "attack")
      .map((step) => step.order)
      .sort((a, b) => a - b);

    setSelectedOrders((currentOrders) => {
      const mergedOrders = new Set(currentOrders);
      const allAttacksSelected = attackOrders.every((order) => mergedOrders.has(order));

      if (allAttacksSelected) {
        attackOrders.forEach((order) => mergedOrders.delete(order));
        setNotice("All attack steps cleared.");
      } else {
        attackOrders.forEach((order) => mergedOrders.add(order));
        setNotice("All attack steps selected.");
      }

      return Array.from(mergedOrders).sort((a, b) => a - b);
    });
  }

  function selectAllNormal() {
    const normalOrders = (campaignDetail?.flow || [])
      .filter((step) => step.phase === "normal")
      .map((step) => step.order)
      .sort((a, b) => a - b);

    setSelectedOrders((currentOrders) => {
      const mergedOrders = new Set(currentOrders);
      const allNormalSelected = normalOrders.every((order) => mergedOrders.has(order));

      if (allNormalSelected) {
        normalOrders.forEach((order) => mergedOrders.delete(order));
        setNotice("All normal steps cleared.");
      } else {
        normalOrders.forEach((order) => mergedOrders.add(order));
        setNotice("All normal steps selected.");
      }

      return Array.from(mergedOrders).sort((a, b) => a - b);
    });
  }

  function clearSelection() {
    setSelectedOrders([]);
    setNotice("");
  }

  function getDetectionStatus(step) {
    if (!step?.elk_check?.checked) {
      return "not_checked";
    }

    return step.elk_check.matched ? "detected" : "missed";
  }

  function getDetectionLabel(step) {
    if (!step?.elk_check) {
      return "쿼리 없음";
    }

    if (!step.elk_check.checked && step.elk_check.query) {
      return "미확인";
    }

    if (!step.elk_check.checked) {
      return "미설정";
    }

    return step.elk_check.matched ? "탐지됨" : "미탐지";
  }

  function getRiskLevel(step) {
    const detectionStatus = getDetectionStatus(step);
    const executed = ["success", "simulated"].includes(step.status);

    if (!executed) {
      return "low";
    }

    if (detectionStatus === "missed") {
      return "high";
    }

    if (detectionStatus === "detected") {
      return "medium";
    }

    return step.phase === "attack" ? "medium" : "low";
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
    const missedSteps = successfulAttacks.filter((step) => getDetectionStatus(step) === "missed");
    const notCheckedSteps = successfulAttacks.filter((step) => getDetectionStatus(step) === "not_checked");

    const penalty = (missedSteps.length * 25)
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
    const hosts = targetDetail?.hosts || {};
    const fallbackAssets = [
      {
        asset_id: "attacker",
        name: "Attacker",
        hostname: "Attacker-Ubuntu",
        private_ip: hosts.attacker_private_ip,
        public_ip: hosts.attacker_public_ip,
        segment_id: "attacker-subnet",
        platform: "Linux",
        role: "공격자 서버",
        agent_role: "attacker",
        agent_required: true,
        criticality: "medium",
        controls: ["aws_security_group", "manual_response"],
      },
      {
        asset_id: "pc01",
        name: "PC01",
        hostname: hosts.pc01,
        private_ip: hosts.pc01_private_ip,
        segment_id: "user-subnet",
        platform: "Windows",
        role: "직원 PC",
        agent_role: "pc01",
        agent_required: true,
        criticality: "high",
        controls: ["sysmon", "windows_security_log", "powershell_logging", "winlogbeat", "kibana_rules"],
      },
      {
        asset_id: "fs01",
        name: "FS01",
        hostname: hosts.fs01,
        private_ip: hosts.fs01_private_ip,
        segment_id: "server-subnet",
        platform: "Windows",
        role: "파일 서버",
        agent_role: "fs01",
        agent_required: true,
        criticality: "critical",
        controls: ["sysmon", "windows_security_log", "winlogbeat", "kibana_rules"],
      },
      {
        asset_id: "dc01",
        name: "DC01",
        hostname: hosts.dc01,
        private_ip: hosts.dc01_private_ip,
        segment_id: "domain-subnet",
        platform: "Windows",
        role: "도메인 컨트롤러",
        agent_role: "log_source",
        agent_required: false,
        criticality: "critical",
        controls: ["windows_security_log", "winlogbeat", "kibana_rules"],
      },
      {
        asset_id: "elk",
        name: "ELK",
        hostname: "elk-gh",
        private_ip: hosts.elk_private_ip,
        segment_id: "server-subnet",
        platform: "Linux",
        role: "탐지 백엔드",
        agent_role: "detection_backend",
        agent_required: false,
        criticality: "high",
        controls: ["kibana_rules"],
      },
    ];

    return (configuredAssets.length > 0 ? configuredAssets : fallbackAssets).map((asset) => {
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
    const fallbackSegments = [
      { segment_id: "attacker-subnet", name: "Attacker Zone", type: "external" },
      { segment_id: "user-subnet", name: "User Endpoint Zone", type: "internal" },
      { segment_id: "server-subnet", name: "Server Zone", type: "internal" },
      { segment_id: "domain-subnet", name: "Domain Core Zone", type: "critical" },
    ];

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

  function formatCommandStatus(command) {
    const status = getCommandStatus(command);

    if (status === "success") {
      return "성공";
    }

    if (status === "failed") {
      return "실패";
    }

    return "알 수 없음";
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
  const attackPathSteps = selectedRunMatchesCampaign ? selectedRun.steps : selectedOperationSteps;
  const latestJob = jobs[0] || null;
  const recentJobs = jobs.slice(0, 4);
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
  const selectedRunSummary = buildDashboardSummary(selectedRunMatchesCampaign ? selectedRun : null);
  const selectedRunAttackSteps = selectedRunSteps.filter((step) => step.phase === "attack");
  const selectedScopeLabel = selectedOperationSteps.length > 0
    ? `${selectedOperationSteps.length}개 큐에 있음`
    : "큐 비어 있음";
  const executedStepCount = selectedRunSteps.filter((step) => ["success", "simulated"].includes(step.status)).length;
  const assetInventory = buildAssetInventory();
  const segmentInventory = buildSegmentInventory(assetInventory);
  const securityControlInventory = buildSecurityControls(assetInventory);
  const attackPathInventory = buildAttackPaths(assetInventory);
  const agentRequiredAssets = assetInventory.filter((asset) => asset.agent_required);
  const onlineAgentAssetCount = agentRequiredAssets.filter((asset) => asset.agentStatus === "online").length;
  const criticalAssetCount = assetInventory.filter((asset) => asset.criticality === "critical").length;
  const assetById = new Map(assetInventory.map((asset) => [asset.asset_id, asset]));
  const topologyNodes = ["attacker", "pc01", "fs01", "dc01", "elk"]
    .map((assetId) => assetById.get(assetId))
    .filter(Boolean);
  const validationGates = buildValidationGates(securityControlInventory);
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

        if (!selectedAgentId) {
            throw new Error("Select a BasAgent before queueing a job.");
        }

        if (selectedOperationSteps.length === 0) {
            throw new Error("실행 큐에 테크닉을 먼저 담아주세요.");
        }

        const data = await fetchJson("/jobs", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            agent_id: selectedAgentId,
            campaign_id: selectedCampaignId,
            selected_steps: selectedOperationSteps.map((step) => ({
              campaign_id: getTechniqueSourceId(step),
              order: step.order,
              inputs: techniqueInputs[getTechniqueSelectionId(step)] || {},
            })),
            include_normal: false
        })
        });

        setNotice(`Job queued: ${data.job.job_id}`);
        setJobs((currentJobs) => [data.job, ...currentJobs]);
        await pollJobUntilFinished(data.job.job_id);
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
    loadInitialData();
    loadCampaignDetail(selectedCampaignId);
  }, []);

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
            <h1>Security Control Validation Console</h1>
            <p className="topbar-copy">
              캠페인 Technique을 실행하고, 예상 로그가 수집됐는지 확인하며, 실행 증거를 한 화면에서 검토합니다.
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
              disabled={isRunning || !selectedAgentId || !selectedCampaignId || selectedOperationSteps.length === 0}
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
          <span>Assets <strong>{assetInventory.length}</strong></span>
          <span>Agents <strong>{onlineAgentAssetCount}/{agentRequiredAssets.length}</strong></span>
          <span>Controls <strong>{configuredControlCount}/{securityControlInventory.length}</strong></span>
          <span>Rules <strong>{detectionRuleCount}</strong></span>
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
            <div className="enterprise-zone enterprise-zone-external">
              <span>External</span>
              <strong>Attacker Zone</strong>
            </div>
            <div className="enterprise-zone enterprise-zone-user">
              <span>Internal</span>
              <strong>User Endpoint</strong>
            </div>
            <div className="enterprise-zone enterprise-zone-server">
              <span>Internal</span>
              <strong>Server Zone</strong>
            </div>
            <div className="enterprise-zone enterprise-zone-domain">
              <span>Critical</span>
              <strong>Domain Core</strong>
            </div>

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
              <path className="enterprise-link link-orange" d="M170 240 C230 210 285 210 345 240" markerEnd="url(#enterprise-arrow-orange)" />
              <path className="enterprise-link link-blue" d="M455 240 C515 210 570 210 630 240" markerEnd="url(#enterprise-arrow-blue)" />
              <path className="enterprise-link link-red" d="M720 205 C780 120 830 110 885 145" markerEnd="url(#enterprise-arrow-red)" />
              <path className="enterprise-link link-green" d="M665 300 C520 430 300 420 165 290" markerEnd="url(#enterprise-arrow-green)" />
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

            {topologyNodes.map((asset) => (
              <div
                key={`enterprise-${asset.asset_id}`}
                className={[
                  "enterprise-node",
                  `enterprise-${asset.asset_id}`,
                  `criticality-${asset.criticality || "medium"}`,
                ].join(" ")}
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
          <section className="panel posture-panel">
            <div className="section-title">Validation Posture</div>
            <h3>검증 준비 상태</h3>
            <div className="posture-score">
              <strong>{agentRequiredAssets.length > 0 ? Math.round((onlineAgentAssetCount / agentRequiredAssets.length) * 100) : 0}</strong>
              <span>Agent Coverage</span>
            </div>
            <div className="posture-metrics">
              <div>
                <span>Ready paths</span>
                <strong>{readyPathCount}</strong>
              </div>
              <div>
                <span>Blocked paths</span>
                <strong>{blockedPathCount}</strong>
              </div>
              <div>
                <span>Critical assets</span>
                <strong>{criticalAssetCount}</strong>
              </div>
            </div>
          </section>

          <section className="panel objective-panel">
            <div className="section-title">검증 목적</div>
            <h3>이 화면이 보여줘야 하는 것</h3>
            <div className="objective-list">
              <div>
                <strong>1. 어느 자산을 검증하는가</strong>
                <span>PC01, FS01, DC01, Attacker, ELK를 역할과 중요도로 식별</span>
              </div>
              <div>
                <strong>2. 어느 구간을 통과하는가</strong>
                <span>외부, 사용자, 서버, 도메인 핵심 구간의 이동 경로 확인</span>
              </div>
              <div>
                <strong>3. 어떤 통제가 봐야 하는가</strong>
                <span>Sysmon, PowerShell Logging, Winlogbeat, Kibana Rule 매핑</span>
              </div>
              <div>
                <strong>4. 어디가 미검증인가</strong>
                <span>Agent 미설치, 로그 미수집, 룰 미탐지를 backlog로 전환</span>
              </div>
            </div>
          </section>
        </aside>

        <section className="panel validation-gate-panel">
          <div className="panel-title-row">
            <div>
              <div className="section-title">Security Control Gates</div>
              <h3>구간별 보안 통제 검증</h3>
            </div>
            <span className="page-indicator">{validationGates.length} gates</span>
          </div>

          <div className="gate-grid">
            {validationGates.map((gate) => (
              <div key={gate.gate_id} className="gate-card">
                <span>{gate.between}</span>
                <strong>{gate.name}</strong>
                <p>{gate.objective}</p>
                <div className="gate-control-list">
                  {gate.controls.map((control) => (
                    <em key={`${gate.gate_id}-${control.control_id}`} className={`control-status ${String(control.status || "configured").replaceAll(" ", "-")}`}>
                      {control.name}
                    </em>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="panel validation-path-panel">
          <div className="panel-title-row">
            <div>
              <div className="section-title">Attack Path Validation</div>
              <h3>경로별 실행 가능성</h3>
            </div>
            <span className="page-indicator">{attackPathInventory.length} paths</span>
          </div>

          <div className="path-validation-table">
            <div className="path-validation-row path-validation-header">
              <span>Path</span>
              <span>Techniques</span>
              <span>Agent</span>
              <span>Status</span>
            </div>
            {attackPathInventory.map((path) => {
              const validation = getPathValidationStatus(path);
              const sourceAgent = path.sourceAsset?.agentLabel || "-";
              const targetAgent = path.targetAsset?.agentLabel || "-";

              return (
                <div key={`${path.source_asset_id}-${path.target_asset_id}`} className="path-validation-row">
                  <span>
                    <strong>{path.sourceAsset?.name || path.source_asset_id} → {path.targetAsset?.name || path.target_asset_id}</strong>
                    <small>{path.label}</small>
                  </span>
                  <span>{path.techniques.join(", ")}</span>
                  <span>{sourceAgent} / {targetAgent}</span>
                  <span>
                    <em className={`path-status ${validation.status}`}>{validation.label}</em>
                  </span>
                </div>
              );
            })}
          </div>
        </section>
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

            {topologyNodes.map((asset) => (
              <div
                key={asset.asset_id}
                className={[
                  "topology-node",
                  `topology-${asset.asset_id}`,
                  `criticality-${asset.criticality || "medium"}`,
                  asset.agent_required ? "requires-agent" : "observe-only",
                ].join(" ")}
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
          disabled={isRunning || !selectedAgentId || !selectedCampaignId || selectedOperationSteps.length === 0}
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
                <h3>{selectedRun ? selectedRun.execution_id : "선택된 실행 없음"}</h3>
              </div>
              <span className="page-indicator">{executedStepCount}개 실행됨</span>
            </div>

            <div className="validation-metrics">
              <div>
                <span>공격</span>
                <strong>{selectedRunAttackSteps.length}</strong>
              </div>
              <div>
                <span>탐지</span>
                <strong>{selectedRunSummary.detectedCount}</strong>
              </div>
              <div>
                <span>미탐</span>
                <strong>{selectedRunSummary.missedCount}</strong>
              </div>
              <div>
                <span>미확인</span>
                <strong>{selectedRunSummary.notCheckedCount}</strong>
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
