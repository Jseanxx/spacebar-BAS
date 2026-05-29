import { useEffect, useMemo, useRef, useState } from "react";
import spacebarLogo from "./assets/spacebar-logo.png";
import "./styles.css";

const API_BASE = "http://127.0.0.1:8000";
const POLL_INTERVAL_MS = 900;
const POLL_LIMIT = 70;

const PANELS = [
  { id: "overview", label: "Summary", hint: "자산과 상태" },
  { id: "library", label: "Technique", hint: "선택과 실행" },
  { id: "queue", label: "Queue", hint: "순서와 입력값" },
  { id: "evidence", label: "Evidence", hint: "결과와 로그" },
];

const ASSET_POSITIONS = {
  attacker: { left: 14, top: 48 },
  pc01: { left: 33, top: 42 },
  fs01: { left: 59, top: 52 },
  dc01: { left: 80, top: 28 },
  elk: { left: 82, top: 68 },
};

const ASSET_FALLBACKS = [
  { asset_id: "attacker", name: "Attacker Ubuntu", segment_id: "attacker-subnet", criticality: "medium", platform: "Ubuntu" },
  { asset_id: "pc01", name: "PC01", segment_id: "user-subnet", criticality: "high", platform: "Windows Server" },
  { asset_id: "fs01", name: "FS01", segment_id: "server-subnet", criticality: "critical", platform: "Windows Server" },
  { asset_id: "dc01", name: "DC01", segment_id: "domain-subnet", criticality: "critical", platform: "Windows Server" },
  { asset_id: "elk", name: "ELK", segment_id: "server-subnet", criticality: "high", platform: "Linux" },
];

function normalizeList(value) {
  return Array.isArray(value) ? value : [];
}

function getStepRole(step) {
  const commands = normalizeList(step?.params?.commands);
  return commands[0]?.agent_role || step?.params?.agent_role || step?.agent_role || "campaign_agent";
}

function getStepAssetId(step) {
  const role = getStepRole(step);
  const explicitAssetId = step?.target_asset_id || step?.asset_id || step?.params?.target_asset_id || step?.params?.asset_id;
  const host = String(step?.execution_host || step?.params?.execution_host || "").toLowerCase();

  if (explicitAssetId) return String(explicitAssetId).toLowerCase();

  if (host.includes("fs01")) return "fs01";
  if (host.includes("dc01")) return "dc01";
  if (host.includes("pc01")) return "pc01";
  if (host.includes("attacker")) return "attacker";
  if (role === "pc01") return "pc01";
  if (role === "fs01") return "fs01";
  if (role === "attacker") return "attacker";
  if (role === "log_source") return "dc01";
  return role;
}

function inferAgentAssetKey(agent) {
  if (!agent) return "";
  if (agent.asset_id) return String(agent.asset_id).toLowerCase();
  if (agent.agent_role && !["campaign_agent", "log_source", "detection_backend"].includes(agent.agent_role)) {
    return String(agent.agent_role).toLowerCase();
  }

  const searchable = [
    agent.agent_id,
    agent.display_name,
    agent.hostname,
    agent.agent_role,
  ].filter(Boolean).join(" ").toLowerCase();

  return ["attacker", "pc01", "fs01", "dc01", "elk"].find((assetId) => searchable.includes(assetId)) || "";
}

function getStepSelectionId(step, fallbackCampaignId) {
  return step.selection_id || `${step.source_campaign_id || fallbackCampaignId}:${step.order}`;
}

function getStepSourceId(step, fallbackCampaignId) {
  return step.source_campaign_id || step.campaign_id || fallbackCampaignId;
}

function getTechniqueLabel(step) {
  return step.technique_id ? `${step.technique_id} · ${step.name}` : step.name;
}

function getStatusLabel(status) {
  const labels = {
    online: "온라인",
    offline: "오프라인",
    observe: "관찰",
    registered: "등록",
    running: "실행 중",
    queued: "대기",
    completed: "완료",
    simulated: "시뮬레이션",
    failed: "실패",
    blocked: "차단",
    cancelled: "취소됨",
    success: "성공",
  };
  return labels[status] || status || "대기";
}

function getLogCollectionStatus(asset) {
  if (asset?.log_collection_status) return asset.log_collection_status;

  const controls = normalizeList(asset?.controls);
  if (controls.includes("winlogbeat")) return "Active";
  if (controls.includes("kibana_rules")) return "Detection Backend";
  return "Manual";
}

function getLogCollectionClass(status) {
  return String(status || "manual").toLowerCase().replace(/[^a-z0-9]+/g, "-");
}

function getDetectionStatus(step) {
  if (!step) return "not_run";
  if (step.detection_status) return step.detection_status;
  if (step.status === "blocked") return "blocked";
  if (["failed", "manual_required", "not_supported"].includes(step.status)) return "execution_failed";
  if (step.status === "simulated") return "not_checked";

  const elkCheck = step.elk_check;
  const alertCheck = elkCheck?.alert_check;

  if (!elkCheck?.checked && !alertCheck?.checked) return "not_checked";
  if (elkCheck?.matched && alertCheck?.matched) return "detected";
  if (elkCheck?.matched && !alertCheck?.matched) return "logged_only";
  if (!elkCheck?.matched && alertCheck?.matched) return "alert_only";
  return "missed";
}

function getDetectionLabel(status) {
  const labels = {
    detected: "탐지",
    logged_only: "로그만",
    alert_only: "알림만",
    missed: "미탐",
    not_checked: "미확인",
    blocked: "차단",
    execution_failed: "실패",
    not_run: "대기",
  };
  return labels[status] || status;
}

function formatCoverage(value) {
  if (value === null || value === undefined || value === "") return "-";
  const numeric = Number(value);
  if (Number.isNaN(numeric)) return value;
  return `${Math.round((numeric <= 1 ? numeric * 100 : numeric))}%`;
}

function getExecutionLabel(status) {
  const labels = {
    success: "공격 성공",
    completed: "공격 성공",
    simulated: "시뮬레이션",
    failed: "공격 실패",
    blocked: "실행 차단",
    running: "실행 중",
    queued: "대기",
    pending: "대기",
    manual_required: "수동 필요",
  };
  return labels[status] || getStatusLabel(status);
}

function getStepEvidenceText(step) {
  const executionStatus = step?.execution_status || step?.status;
  const detectionStatus = getDetectionStatus(step);
  const eventCount = step?.source_event_count ?? step?.elk_check?.event_count ?? 0;
  const alertCount = step?.alert_count ?? step?.elk_check?.alert_check?.alert_count ?? 0;
  const missingGates = step?.module_result?.missing_safety_gates || [];
  const commandResults = step?.module_result?.command_results || [];
  const failedCommand = commandResults.find((item) => item?.returncode || item?.status === "failed");

  if (executionStatus === "simulated") {
    return "Simulation mode: 실제 공격 명령과 ELK 조회는 수행하지 않았습니다.";
  }

  if (executionStatus === "blocked") {
    if (missingGates.length > 0) {
      return `안전 게이트가 열리지 않아 실행이 차단되었습니다: ${missingGates.join(", ")}`;
    }
    return step?.error || step?.module_result?.message || "안전 게이트 또는 Agent 상태 때문에 실행이 차단되었습니다.";
  }

  if (executionStatus === "failed") {
    if (failedCommand) {
      const reason = failedCommand.stderr || failedCommand.stdout || failedCommand.error || "명령 반환 코드가 0이 아닙니다.";
      return `공격 실행 실패: ${String(reason).slice(0, 260)}`;
    }
    return step?.error || step?.module_result?.message || "공격 실행 단계에서 실패했습니다.";
  }

  if (step?.elk_check?.checked === false) {
    return step.elk_check.message || "ELK 조회가 수행되지 않았습니다.";
  }

  return `ELK source events ${eventCount}건 · detection alerts ${alertCount}건 · ${getDetectionLabel(detectionStatus)}`;
}

export default function App() {
  const [health, setHealth] = useState(null);
  const [campaigns, setCampaigns] = useState([]);
  const [campaignId, setCampaignId] = useState("SB-AD");
  const [campaign, setCampaign] = useState(null);
  const [target, setTarget] = useState(null);
  const [agents, setAgents] = useState([]);
  const [operations, setOperations] = useState([]);
  const [runs, setRuns] = useState([]);
  const [library, setLibrary] = useState([]);
  const [selectedIds, setSelectedIds] = useState([]);
  const [techniqueInputs, setTechniqueInputs] = useState({});
  const [openInputIds, setOpenInputIds] = useState([]);
  const [activePanel, setActivePanel] = useState("overview");
  const [query, setQuery] = useState("");
  const [phaseFilter, setPhaseFilter] = useState("all");
  const [sourceFilter, setSourceFilter] = useState("SB-AD");
  const [executionMode, setExecutionMode] = useState("real");
  const [selectedRun, setSelectedRun] = useState(null);
  const [selectedOperation, setSelectedOperation] = useState(null);
  const [isRunning, setIsRunning] = useState(false);
  const [isCancelling, setIsCancelling] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const cancelRequestedRef = useRef(false);

  async function fetchJson(path, options) {
    const response = await fetch(`${API_BASE}${path}`, options);

    if (!response.ok) {
      let detail;
      try {
        detail = await response.json();
      } catch {
        detail = null;
      }
      throw new Error(detail?.detail?.message || detail?.detail || `API error ${response.status}`);
    }

    return response.json();
  }

  async function refreshRuntime() {
    const [agentData, operationData, runData] = await Promise.all([
      fetchJson("/agents"),
      fetchJson("/operations"),
      fetchJson("/runs"),
    ]);
    setAgents(agentData.agents || []);
    setOperations(operationData.operations || []);
    setRuns(runData.runs || []);
    return {
      agents: agentData.agents || [],
      operations: operationData.operations || [],
      runs: runData.runs || [],
    };
  }

  async function loadCampaign(nextCampaignId) {
    setError("");
    setNotice("");

    const [campaignData, targetData] = await Promise.all([
      fetchJson(`/campaigns/${nextCampaignId}`),
      fetchJson(`/targets/${nextCampaignId}`),
    ]);

    try {
      const discoveryData = await fetchJson(`/targets/${nextCampaignId}/asset-discovery`);
      setTarget({
        ...targetData,
        assets: discoveryData.assets || targetData.assets,
        segments: discoveryData.segments || targetData.segments,
        security_controls: discoveryData.security_controls || targetData.security_controls,
        attack_paths: discoveryData.attack_paths || targetData.attack_paths,
      });
    } catch {
      setTarget(targetData);
    }

    setCampaign(campaignData);
    setCampaignId(nextCampaignId);
    setSourceFilter(nextCampaignId);
    setSelectedRun(null);
    setSelectedOperation(null);
  }

  useEffect(() => {
    let ignore = false;

    async function boot() {
      try {
        setError("");
        const [healthData, campaignListData, techniqueData] = await Promise.all([
          fetchJson("/health"),
          fetchJson("/campaigns"),
          fetchJson("/techniques"),
        ]);

        if (ignore) return;

        setHealth(healthData);
        setCampaigns(campaignListData.campaigns || []);
        setLibrary(techniqueData.techniques || []);
        await loadCampaign(campaignId);
        await refreshRuntime();
      } catch (err) {
        if (!ignore) {
          setError(err.message);
        }
      }
    }

    boot();

    return () => {
      ignore = true;
    };
  }, []);

  useEffect(() => {
    if (!notice) return undefined;
    const timeoutId = window.setTimeout(() => setNotice(""), 3600);
    return () => window.clearTimeout(timeoutId);
  }, [notice]);

  const agentByAsset = useMemo(() => {
    const map = new Map();
    agents.forEach((agent) => {
      [
        inferAgentAssetKey(agent),
        agent.asset_id,
        agent.agent_role,
        agent.campaign_agent_id,
        agent.display_name,
        agent.hostname,
      ].forEach((value) => {
        if (!value) return;
        const key = String(value).toLowerCase();
        const existing = map.get(key);
        if (existing?.status === "online" && agent.status !== "online") return;
        if (existing?.status !== "online" || agent.status === "online") map.set(key, agent);
      });
    });
    return map;
  }, [agents]);

  const assets = useMemo(() => {
    const sourceAssets = normalizeList(target?.assets).length > 0 ? target.assets : ASSET_FALLBACKS;
    return sourceAssets.map((asset, index) => {
      const id = String(asset.asset_id || `asset-${index}`).toLowerCase();
      const agent = agentByAsset.get(id) || agentByAsset.get(String(asset.agent_role || "").toLowerCase()) || asset.agent;
      return {
        ...asset,
        asset_id: id,
        agent,
        agentStatus: asset.agent_required ? (agent?.status || "offline") : "observe",
        position: ASSET_POSITIONS[id] || {
          left: 12 + (index % 4) * 22,
          top: 24 + Math.floor(index / 4) * 28,
        },
      };
    });
  }, [target, agentByAsset]);

  const selectedSteps = useMemo(() => {
    const byId = new Map();
    library.forEach((step) => byId.set(getStepSelectionId(step, campaignId), step));
    normalizeList(campaign?.flow).forEach((step) => byId.set(getStepSelectionId(step, campaignId), step));
    return selectedIds.map((id) => byId.get(id)).filter(Boolean);
  }, [library, campaign, campaignId, selectedIds]);

  const latestOperation = selectedOperation || operations[0] || null;
  const canCancelLatestOperation = Boolean(
    latestOperation?.operation_id && ["pending", "queued", "running"].includes(latestOperation.status),
  );
  const latestRun = selectedRun || runs[0] || null;
  const operationSteps = normalizeList(latestOperation?.final_steps || latestOperation?.steps);
  const evidenceSteps = operationSteps.length > 0 ? operationSteps : normalizeList(latestRun?.steps);
  const visibleSteps = operationSteps.length > 0 ? operationSteps : selectedSteps;
  const runningStep = operationSteps.find((step) => step.status === "running")
    || operationSteps.find((step) => step.status === "queued")
    || null;
  const activeAssetId = runningStep ? getStepAssetId(runningStep) : (isRunning && selectedSteps[0] ? getStepAssetId(selectedSteps[0]) : "");
  const completedCount = operationSteps.filter((step) => ["completed", "success", "simulated"].includes(step.status)).length;
  const totalOperationSteps = latestOperation?.summary?.total || operationSteps.length || selectedSteps.length;
  const requiredAssets = assets.filter((asset) => asset.agent_required);
  const onlineRequiredAssets = requiredAssets.filter((asset) => asset.agentStatus === "online");
  const detectionCounts = evidenceSteps.reduce((counts, step) => {
    const status = getDetectionStatus(step);
    return { ...counts, [status]: (counts[status] || 0) + 1 };
  }, {});
  const operationSummary = latestOperation?.summary || {};
  const reportSummary = latestOperation?.report?.summary || {};
  const executionTotal = operationSummary.total || evidenceSteps.length || selectedSteps.length || 0;
  const executionSucceeded = (operationSummary.success || 0) + (operationSummary.completed || 0);
  const executionFailed = (operationSummary.failed || 0) + (operationSummary.blocked || 0);
  const executionSimulated = operationSummary.simulated || 0;
  const detectionChecked = (detectionCounts.detected || 0)
    + (detectionCounts.logged_only || 0)
    + (detectionCounts.alert_only || 0)
    + (detectionCounts.missed || 0);
  const elkConfigured = Boolean(target?.elk?.enabled);
  const elkVerified = normalizeList(latestRun?.steps).some((step) => (
    step.elk_check?.checked || step.elk_check?.alert_check?.checked
  ));
  const elkStatus = elkVerified ? "verified" : (elkConfigured ? "configured" : "missing");

  const filteredLibrary = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return library.filter((step) => {
      const sourceId = getStepSourceId(step, campaignId);
      const haystack = `${step.name || ""} ${step.technique_id || ""} ${step.params?.behavior || ""}`.toLowerCase();
      const matchesSource = sourceFilter === "all" || sourceId === sourceFilter;
      const matchesPhase = phaseFilter === "all" || (step.phase || "attack") === phaseFilter;
      const matchesQuery = !normalizedQuery || haystack.includes(normalizedQuery);
      return matchesSource && matchesPhase && matchesQuery;
    });
  }, [library, campaignId, query, phaseFilter, sourceFilter]);
  const libraryEmptyMessage = error
    ? `Technique 데이터를 불러오지 못했습니다: ${error}`
    : library.length === 0
      ? "Technique 데이터가 아직 로드되지 않았습니다. API 서버 연결을 확인해 주세요."
      : "조건에 맞는 Technique이 없습니다.";

  const sourceOptions = useMemo(() => (
    Array.from(new Set(library.map((step) => getStepSourceId(step, campaignId)))).sort()
  ), [library, campaignId]);

  const filteredSelectionIds = useMemo(() => (
    filteredLibrary.map((step) => getStepSelectionId(step, campaignId))
  ), [filteredLibrary, campaignId]);

  const selectedFilteredCount = useMemo(() => (
    filteredSelectionIds.filter((id) => selectedIds.includes(id)).length
  ), [filteredSelectionIds, selectedIds]);

  function toggleStep(step) {
    const selectionId = getStepSelectionId(step, campaignId);
    setSelectedIds((currentIds) => {
      if (currentIds.includes(selectionId)) {
        setTechniqueInputs((currentInputs) => {
          const nextInputs = { ...currentInputs };
          delete nextInputs[selectionId];
          return nextInputs;
        });
        setOpenInputIds((current) => current.filter((id) => id !== selectionId));
        return currentIds.filter((id) => id !== selectionId);
      }
      return [...currentIds, selectionId];
    });
  }

  function selectFilteredTechniques() {
    setSelectedIds((currentIds) => {
      const nextIds = [...currentIds];
      filteredSelectionIds.forEach((id) => {
        if (!nextIds.includes(id)) nextIds.push(id);
      });
      return nextIds;
    });
    setNotice(`현재 필터의 Technique ${filteredSelectionIds.length}개를 Queue에 담았습니다.`);
  }

  function clearFilteredTechniques() {
    const idSet = new Set(filteredSelectionIds);
    setSelectedIds((currentIds) => currentIds.filter((id) => !idSet.has(id)));
    setTechniqueInputs((currentInputs) => {
      const nextInputs = { ...currentInputs };
      filteredSelectionIds.forEach((id) => delete nextInputs[id]);
      return nextInputs;
    });
    setOpenInputIds((current) => current.filter((id) => !idSet.has(id)));
    setNotice("현재 필터의 Technique을 Queue에서 제거했습니다.");
  }

  function clearAllTechniques() {
    setSelectedIds([]);
    setTechniqueInputs({});
    setOpenInputIds([]);
    setNotice("Queue를 초기화했습니다.");
  }

  function loadPreset() {
    const presetSteps = normalizeList(campaign?.flow);
    setSelectedIds(presetSteps.map((step) => getStepSelectionId(step, campaignId)));
    setTechniqueInputs({});
    setOpenInputIds([]);
    setActivePanel("queue");
    setNotice("캠페인 기본 흐름을 런 큐에 올렸습니다.");
  }

  function updateInput(selectionId, name, value) {
    setTechniqueInputs((current) => ({
      ...current,
      [selectionId]: {
        ...(current[selectionId] || {}),
        [name]: value,
      },
    }));
  }

  function moveStep(selectionId, direction) {
    setSelectedIds((currentIds) => {
      const index = currentIds.indexOf(selectionId);
      const nextIndex = index + direction;
      if (index < 0 || nextIndex < 0 || nextIndex >= currentIds.length) return currentIds;
      const nextIds = [...currentIds];
      [nextIds[index], nextIds[nextIndex]] = [nextIds[nextIndex], nextIds[index]];
      return nextIds;
    });
  }

  async function pollOperation(operationId) {
    for (let attempt = 0; attempt < POLL_LIMIT; attempt += 1) {
      if (cancelRequestedRef.current) {
        await refreshRuntime();
        return;
      }

      const operation = await fetchJson(`/operations/${operationId}`);
      setSelectedOperation(operation);

      if (["completed", "simulated"].includes(operation.status)) {
        setNotice(operation.status === "simulated" ? "시뮬레이션으로 완료되었습니다." : "검증 런이 완료되었습니다.");
        await refreshRuntime();
        return;
      }

      if (operation.status === "cancelled") {
        setNotice("런 취소 요청이 반영되었습니다.");
        await refreshRuntime();
        return;
      }

      if (["blocked", "failed"].includes(operation.status)) {
        await refreshRuntime();
        throw new Error(`Operation ${operation.status}`);
      }

      const success = operation.summary?.success || 0;
      const total = operation.summary?.total || 0;
      setNotice(`런 진행 중: ${success}/${total} 완료`);
      await new Promise((resolve) => window.setTimeout(resolve, POLL_INTERVAL_MS));
    }
  }

  async function runQueue() {
    try {
      cancelRequestedRef.current = false;
      setIsRunning(true);
      setError("");

      if (selectedSteps.length === 0) {
        throw new Error("먼저 Technique 패널에서 실행할 항목을 선택해 주세요.");
      }

      const payload = {
        campaign_id: campaignId,
        include_normal: false,
        execution_mode: executionMode,
        selected_steps: selectedSteps.map((step) => {
          const selectionId = getStepSelectionId(step, campaignId);
          return {
            campaign_id: getStepSourceId(step, campaignId),
            order: step.order,
            inputs: techniqueInputs[selectionId] || {},
          };
        }),
      };

      const operationResponse = await fetchJson("/operations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const operation = operationResponse.operation || operationResponse;

      setSelectedOperation(operation);
      setNotice(`런을 시작했습니다: ${operation.operation_id}`);
      await pollOperation(operation.operation_id);
    } catch (err) {
      setError(err.message);
    } finally {
      setIsRunning(false);
    }
  }

  async function cancelOperation(operationId = latestOperation?.operation_id) {
    if (!operationId) return;

    try {
      cancelRequestedRef.current = true;
      setIsCancelling(true);
      setError("");
      setNotice("런 취소 요청 중...");

      const response = await fetchJson(`/operations/${operationId}/cancel`, { method: "POST" });
      const operation = response.operation || response;

      setSelectedOperation(operation);
      setIsRunning(false);
      setNotice("런 취소 요청을 보냈습니다. 현재 실행 중인 step은 끝날 수 있습니다.");
      await refreshRuntime();
    } catch (err) {
      setError(err.message);
    } finally {
      setIsCancelling(false);
    }
  }

  async function chooseCampaign(nextCampaignId) {
    try {
      await loadCampaign(nextCampaignId);
      await refreshRuntime();
    } catch (err) {
      setError(err.message);
    }
  }

  async function loadRun(executionId) {
    try {
      const data = await fetchJson(`/runs/${executionId}`);
      setSelectedRun(data);
      setActivePanel("evidence");
    } catch (err) {
      setError(err.message);
    }
  }

  const renderActivePanel = () => {
    if (activePanel === "overview") {
      return (
        <div className="side-section overview-section">
          <div className="panel-heading">
            <span>Mission</span>
            <strong>{campaign?.campaign_name || campaignId}</strong>
          </div>
          <label className="field-label">
            캠페인
            <select value={campaignId} onChange={(event) => chooseCampaign(event.target.value)}>
              {campaigns.map((item) => (
                <option key={item.campaign_id} value={item.campaign_id}>
                  {item.campaign_id}
                </option>
              ))}
            </select>
          </label>
          <div className="summary-stack">
            <div><span>Assets</span><strong>{assets.length}</strong></div>
            <div><span>Agents</span><strong>{onlineRequiredAssets.length}/{requiredAssets.length}</strong></div>
            <div><span>Queue</span><strong>{selectedSteps.length}</strong></div>
            <div><span>Runs</span><strong>{runs.length}</strong></div>
          </div>
          <div className={`elk-status-card ${elkStatus}`}>
            <span>ELK 연동</span>
            <strong>{elkStatus === "verified" ? "검증됨" : elkStatus === "configured" ? "설정됨" : "미설정"}</strong>
            <small>
              {elkStatus === "verified"
                ? "최근 런에서 ELK 확인이 수행되었습니다."
                : elkStatus === "configured"
                  ? "타깃 설정에 ELK가 활성화되어 있습니다."
                  : "타깃 설정에서 ELK 활성 정보를 찾지 못했습니다."}
            </small>
          </div>
          <label className="field-label mode-field">
            실행 방식
            <select value={executionMode} onChange={(event) => setExecutionMode(event.target.value)}>
              <option value="real">Real gated - Agent 실행 + ELK 검증</option>
              <option value="simulation">Simulation - 명령 미실행</option>
            </select>
          </label>
          <button type="button" className="secondary-button" onClick={loadPreset}>
            기본 흐름 올리기
          </button>
        </div>
      );
    }

    if (activePanel === "library") {
      return (
        <div className="side-section library-section">
          <div className="panel-heading">
            <span>Technique Library</span>
            <strong>{filteredLibrary.length} Techniques</strong>
          </div>
          <div className="filter-grid">
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="T1059, WinRM, shell..." />
            <select value={sourceFilter} onChange={(event) => setSourceFilter(event.target.value)}>
              <option value="all">전체 소스</option>
              {sourceOptions.map((sourceId) => <option key={sourceId} value={sourceId}>{sourceId}</option>)}
            </select>
            <select value={phaseFilter} onChange={(event) => setPhaseFilter(event.target.value)}>
              <option value="all">전체 단계</option>
              <option value="attack">Attack</option>
              <option value="normal">Normal</option>
            </select>
          </div>
          <div className="library-run-strip">
            <div>
              <span>선택됨</span>
              <strong>{selectedFilteredCount}/{filteredLibrary.length}</strong>
            </div>
            <button type="button" className="secondary-button" onClick={runQueue} disabled={isRunning || selectedSteps.length === 0}>
              {isRunning ? "실행 중" : "선택 실행"}
            </button>
          </div>
          <div className="library-bulk-actions">
            <button type="button" className="ghost-button" onClick={selectFilteredTechniques} disabled={filteredLibrary.length === 0 || selectedFilteredCount === filteredLibrary.length}>
              전체 선택
            </button>
            <button type="button" className="ghost-button" onClick={clearFilteredTechniques} disabled={selectedFilteredCount === 0}>
              전체 해제
            </button>
            <button type="button" className="ghost-button" onClick={clearAllTechniques} disabled={selectedIds.length === 0}>
              초기화
            </button>
          </div>
          <div className="technique-list">
            {filteredLibrary.map((step) => {
              const selectionId = getStepSelectionId(step, campaignId);
              const selected = selectedIds.includes(selectionId);
              const phase = step.phase || "attack";
              return (
                <button
                  key={selectionId}
                  type="button"
                  className={`technique-card ${phase} ${selected ? "selected" : ""}`}
                  onClick={() => toggleStep(step)}
                >
                  <span className="phase-line">
                    <em>{phase === "normal" ? "Normal" : "Attack"}</em>
                    <b>{step.technique_id || "STEP"}</b>
                  </span>
                  <strong>{step.name}</strong>
                  <small>{getStepSourceId(step, campaignId)} · {getStepRole(step)}</small>
                </button>
              );
            })}
            {filteredLibrary.length === 0 && <p className="empty">{libraryEmptyMessage}</p>}
          </div>
        </div>
      );
    }

    if (activePanel === "queue") {
      return (
        <div className="side-section queue-section">
          <div className="panel-heading">
            <span>Queue</span>
            <strong>{selectedSteps.length}개 선택</strong>
          </div>
          <div className="queue-actions-bar">
            <button type="button" className="secondary-button" onClick={runQueue} disabled={isRunning || selectedSteps.length === 0}>
              {isRunning ? "실행 중" : "런 실행"}
            </button>
            <button type="button" className="ghost-button" onClick={clearAllTechniques} disabled={selectedSteps.length === 0}>
              초기화
            </button>
          </div>
          <label className="field-label mode-field compact">
            실행 방식
            <select value={executionMode} onChange={(event) => setExecutionMode(event.target.value)}>
              <option value="real">Real gated</option>
              <option value="simulation">Simulation</option>
            </select>
          </label>
          <div className="queue-stack">
            {selectedSteps.map((step, index) => {
              const selectionId = getStepSelectionId(step, campaignId);
              const inputDefs = normalizeList(step.inputs);
              const isOpen = openInputIds.includes(selectionId);
              return (
                <div key={selectionId} className="queue-card">
                  <div className="queue-card-head">
                    <span>{index + 1}</span>
                    <div>
                      <strong>{getTechniqueLabel(step)}</strong>
                      <small>{getStepAssetId(step).toUpperCase()} · {getStepRole(step)}</small>
                    </div>
                  </div>
                  {inputDefs.length > 0 && (
                    <button
                      type="button"
                      className="input-toggle"
                      onClick={() => setOpenInputIds((current) => (
                        current.includes(selectionId)
                          ? current.filter((id) => id !== selectionId)
                          : [...current, selectionId]
                      ))}
                    >
                      파라미터 {isOpen ? "접기" : "열기"}
                    </button>
                  )}
                  {isOpen && (
                    <div className="input-grid">
                      {inputDefs.map((input) => (
                        <label key={`${selectionId}-${input.name}`} className="field-label">
                          {input.label || input.name}
                          <input
                            value={techniqueInputs[selectionId]?.[input.name] || input.default || ""}
                            onChange={(event) => updateInput(selectionId, input.name, event.target.value)}
                          />
                        </label>
                      ))}
                    </div>
                  )}
                  <div className="queue-move-row">
                    <button type="button" onClick={() => moveStep(selectionId, -1)} disabled={index === 0}>위</button>
                    <button type="button" onClick={() => moveStep(selectionId, 1)} disabled={index === selectedSteps.length - 1}>아래</button>
                    <button type="button" onClick={() => toggleStep(step)}>제거</button>
                  </div>
                </div>
              );
            })}
            {selectedSteps.length === 0 && <p className="empty queue-empty">Technique 탭에서 항목을 선택하면 Queue에 추가됩니다.</p>}
          </div>
        </div>
      );
    }

    return (
      <div className="side-section evidence-side-section">
        <div className="panel-heading">
          <span>Evidence</span>
          <strong>{latestOperation?.operation_id || latestRun?.execution_id || "선택된 결과 없음"}</strong>
        </div>
        <div className="evidence-callout">
          <span>현재 결과</span>
          <strong>{latestOperation?.status ? getStatusLabel(latestOperation.status) : "런 선택 전"}</strong>
          <small>
            {(latestOperation?.execution_mode || executionMode) === "simulation"
              ? "Simulation은 공격과 ELK 조회를 실행하지 않아 탐지 결과가 미확인으로 표시됩니다."
              : "Real 모드에서 Agent가 명령을 실행한 뒤 ELK source/alert 조회 결과가 채워집니다."}
          </small>
        </div>
        <div className="result-meter execution-meter">
          <div><span>전체</span><strong>{executionTotal}</strong></div>
          <div><span>성공</span><strong>{executionSucceeded}</strong></div>
          <div><span>시뮬</span><strong>{executionSimulated}</strong></div>
          <div><span>실패/차단</span><strong>{executionFailed}</strong></div>
        </div>
        <div className="result-meter detection-meter">
          <div><span>ELK 확인</span><strong>{detectionChecked}</strong></div>
          <div><span>탐지</span><strong>{detectionCounts.detected || 0}</strong></div>
          <div><span>로그만</span><strong>{detectionCounts.logged_only || 0}</strong></div>
          <div><span>미탐</span><strong>{detectionCounts.missed || 0}</strong></div>
          <div><span>미확인</span><strong>{detectionCounts.not_checked || 0}</strong></div>
        </div>
        {latestOperation?.report?.report_id && (
          <div className="report-card">
            <span>Report</span>
            <strong>{latestOperation.report.report_id}</strong>
            <small>
              Score {reportSummary.final_score ?? "-"} · Detection {formatCoverage(reportSummary.detection_coverage)}
            </small>
            <a
              className="artifact-link"
              href={`${API_BASE}/reports/${latestOperation.report.report_id}/summary.md`}
              target="_blank"
              rel="noreferrer"
            >
              Summary 열기
            </a>
          </div>
        )}
        <div className="run-list operation-list">
          {operations.slice(0, 6).map((operation) => (
            <button key={operation.operation_id} type="button" onClick={() => setSelectedOperation(operation)}>
              <strong>{operation.operation_id}</strong>
              <span>{operation.campaign_id} · {getStatusLabel(operation.status)} · {operation.created_at || "-"}</span>
            </button>
          ))}
          {operations.length === 0 && <p className="empty">아직 Operation 기록이 없습니다.</p>}
        </div>
        <div className="run-list legacy-run-list">
          {runs.slice(0, 8).map((run) => (
            <button key={run.execution_id} type="button" onClick={() => loadRun(run.execution_id)}>
              <strong>{run.execution_id}</strong>
              <span>{run.campaign_id} · {run.started_at || "-"}</span>
            </button>
          ))}
          {runs.length === 0 && <p className="empty">아직 실행 기록이 없습니다.</p>}
        </div>
      </div>
    );
  };

  return (
    <main className="bas-shell">
      <aside className="left-rail">
        <div className="rail-top">
          <button type="button" className="brand-mark" onClick={() => setActivePanel("overview")}>
            <img src={spacebarLogo} alt="Spacebar" />
          </button>
          <div className="panel-tabs" role="tablist" aria-label="BAS workspace panels">
            {PANELS.map((panel) => (
              <button
                key={panel.id}
                type="button"
                className={`panel-trigger ${activePanel === panel.id ? "active" : ""}`}
                onClick={() => setActivePanel(panel.id)}
                title={panel.hint}
              >
                <span>{panel.label}</span>
                <small>{panel.hint}</small>
              </button>
            ))}
          </div>
        </div>
        <div className="rail-panel">
          {renderActivePanel()}
        </div>
        <div className="api-state">
          <span>
            <i className={`status-dot ${health?.status === "ok" ? "online" : "offline"}`} />
            API {health?.status === "ok" ? "연결됨" : "확인 필요"}
          </span>
          <span>
            <i className={`status-dot elk-dot ${elkStatus}`} />
            ELK {elkStatus === "verified" ? "검증됨" : elkStatus === "configured" ? "설정됨" : "미설정"}
          </span>
        </div>
      </aside>

      <section className="map-stage">
        {(error || notice) && (
          <div className={`toast ${error ? "error" : ""}`}>
            {error || notice}
          </div>
        )}

        <header className="stage-header">
          <div>
            <span>Breach and Attack Simulation</span>
            <h1>Attack Map</h1>
          </div>
          <div className="stage-actions">
            <button type="button" className="run-button" onClick={runQueue} disabled={isRunning || selectedSteps.length === 0}>
              {isRunning ? "실행 중" : "Run"}
            </button>
            <button
              type="button"
              className="danger-button"
              onClick={() => cancelOperation()}
              disabled={!canCancelLatestOperation || isCancelling}
            >
              {isCancelling ? "취소 중" : "Cancel"}
            </button>
          </div>
        </header>

        <section className="asset-map-card">
          <div className="map-toolbar">
            <div>
              <span>Asset Map</span>
              <strong>{campaignId} · {latestOperation?.status ? getStatusLabel(latestOperation.status) : "수동 구성"}</strong>
            </div>
            <div className="progress-chip">
              {completedCount}/{totalOperationSteps || 0}
            </div>
          </div>

          <div className={`asset-map ${isRunning ? "running" : ""}`}>
            <svg className="map-links" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
              <path d="M12 51 C22 42, 24 41, 35 45" />
              <path d="M39 45 C47 47, 50 52, 59 55" />
              <path d="M61 53 C70 48, 73 36, 82 31" />
              <path d="M60 58 C69 65, 74 68, 82 70" />
              <path className={activeAssetId ? "active-link" : ""} d="M12 51 C33 24, 64 18, 82 31" />
            </svg>

            <div className="map-zone attacker-zone">Attacker</div>
            <div className="map-zone user-zone">User</div>
            <div className="map-zone server-zone">Server</div>
            <div className="map-zone domain-zone">Domain</div>

            {assets.map((asset) => {
              const isActive = activeAssetId === asset.asset_id;
              const isCompleted = operationSteps.some((step) => getStepAssetId(step) === asset.asset_id && ["completed", "success", "simulated"].includes(step.status));
              const logStatus = getLogCollectionStatus(asset);
              return (
                <button
                  key={asset.asset_id}
                  type="button"
                  className={[
                    "asset-node",
                    `risk-${asset.criticality || "medium"}`,
                    `agent-${asset.agentStatus}`,
                    isActive ? "active" : "",
                    isCompleted ? "completed" : "",
                  ].join(" ")}
                  style={{ left: `${asset.position.left}%`, top: `${asset.position.top}%` }}
                  onClick={() => setNotice(`${asset.name || asset.asset_id}: ${asset.private_ip || asset.hostname || "수동 자산"} · ${asset.role || asset.segment_id || "역할 미정"}`)}
                >
                  <span className="node-ring" />
                  <strong>{asset.name || asset.asset_id}</strong>
                  <div className="asset-facts">
                    <span><b>IP</b>{asset.private_ip || "N/A"}</span>
                    <span><b>OS</b>{asset.os || asset.platform || "N/A"}</span>
                    <span><b>Type</b>{asset.role || asset.segment_id || "N/A"}</span>
                  </div>
                  <div className="asset-state-row">
                    <em>Agent {getStatusLabel(asset.agentStatus)}</em>
                    <em className={`log-pill log-${getLogCollectionClass(logStatus)}`}>Log {logStatus}</em>
                  </div>
                  {asset.log_collection_detail && <small className="log-detail">{asset.log_collection_detail}</small>}
                </button>
              );
            })}
          </div>
        </section>

        <section className="lower-grid">
          <div className="timeline-panel">
            <div className="panel-heading horizontal">
              <div>
                <span>Live Tactics</span>
                <strong>{visibleSteps.length || "대기 중"}</strong>
              </div>
              <button type="button" className="ghost-button" onClick={refreshRuntime}>새로고침</button>
            </div>
            <div className="timeline-list">
              {visibleSteps.map((step, index) => {
                const status = step.status || (selectedIds.includes(getStepSelectionId(step, campaignId)) ? "queued" : "planned");
                return (
                  <div key={`${step.order}-${step.technique_id || index}`} className={`timeline-row ${status}`}>
                    <span>{String(index + 1).padStart(2, "0")}</span>
                    <div>
                      <strong>{getTechniqueLabel(step)}</strong>
                      <small>{getStepAssetId(step).toUpperCase()} · {getExecutionLabel(status)} · {getDetectionLabel(getDetectionStatus(step))}</small>
                    </div>
                  </div>
                );
              })}
              {visibleSteps.length === 0 && <p className="empty">좌측에서 쿼리를 선택하면 런 순서가 여기에 표시됩니다.</p>}
            </div>
          </div>

          <div className="evidence-panel">
            <div className="panel-heading horizontal">
              <div>
                <span>Run Result</span>
                <strong>{latestOperation?.operation_id || latestRun?.execution_id || "결과 없음"}</strong>
              </div>
            </div>
            <div className="result-overview">
              <div>
                <span>Execution</span>
                <strong>{latestOperation?.status ? getStatusLabel(latestOperation.status) : "대기"}</strong>
                <small>{executionSucceeded} success · {executionSimulated} simulation · {executionFailed} failed/blocked</small>
              </div>
              <div>
                <span>ELK Detection</span>
                <strong>{detectionChecked}/{executionTotal}</strong>
                <small>{detectionCounts.detected || 0} detected · {detectionCounts.logged_only || 0} logged · {detectionCounts.missed || 0} missed · {detectionCounts.not_checked || 0} not checked</small>
              </div>
              {latestOperation?.report?.report_id && (
                <div>
                  <span>Report</span>
                  <strong>{reportSummary.final_score ?? "-"} / 100</strong>
                  <small>{latestOperation.report.report_id}</small>
                  <a
                    className="artifact-link compact"
                    href={`${API_BASE}/reports/${latestOperation.report.report_id}/summary.md`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    Summary 보기
                  </a>
                </div>
              )}
            </div>
            <div className="evidence-feed">
              {evidenceSteps.map((step) => {
                const detectionStatus = getDetectionStatus(step);
                const executionStatus = step.execution_status || step.status;
                return (
                  <div key={`${step.order}-${step.technique_id}`} className="evidence-row">
                    <div className="result-pill-stack">
                      <span className={`execution-pill ${executionStatus}`}>{getExecutionLabel(executionStatus)}</span>
                      <span className={`detection-pill ${detectionStatus}`}>{getDetectionLabel(detectionStatus)}</span>
                    </div>
                    <div>
                      <strong>{getTechniqueLabel(step)}</strong>
                      <small>{getStepAssetId(step).toUpperCase()} · {getStepEvidenceText(step)}</small>
                    </div>
                  </div>
                );
              })}
              {evidenceSteps.length === 0 && <p className="empty">런 완료 후 탐지 결과가 표시됩니다.</p>}
            </div>
          </div>
        </section>
      </section>
    </main>
  );
}
