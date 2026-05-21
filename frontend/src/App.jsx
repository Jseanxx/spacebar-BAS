// 화면 로직 
// API 상태 확인 , 캠페인 목록, 캠페인 상세 표시, Run Campaign 버튼 처리
// 실행 결과 목록 표시, 실행 결과 상세 표시 

import { useEffect, useRef, useState } from "react";
import "./styles.css";

const API_BASE = "http://127.0.0.1:8000";
const JOB_POLL_INTERVAL_MS = 1500;
const JOB_POLL_ATTEMPTS = 40;
const RUNS_PER_PAGE = 5;
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

export default function App() {
  const [health, setHealth] = useState(null);
  const [campaigns, setCampaigns] = useState([]);
  const [selectedCampaignId, setSelectedCampaignId] = useState("SB-05");
  const [campaignDetail, setCampaignDetail] = useState(null);
  const [runs, setRuns] = useState([]);
  const [jobs, setJobs] = useState([]);
  const [agents, setAgents] = useState([]);
  const [selectedAgentId, setSelectedAgentId] = useState("");
  const [selectedRun, setSelectedRun] = useState(null);
  const [selectedOrders, setSelectedOrders] = useState([]);
  const [notice, setNotice] = useState("");
  const [isRunning, setIsRunning] = useState(false);
  const [error, setError] = useState("");
  const [runPage, setRunPage] = useState(0);
  const detailRef = useRef(null);

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
      await refreshDashboardData();

      if (job.status === "completed") {
        setNotice(`Job completed: ${jobId}`);

        if (job.execution_id) {
          const run = await fetchJson(`/runs/${job.execution_id}`);
          setSelectedRun(run);
        }

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

      await refreshDashboardData();

    } catch (err) {
      setError(err.message);
    }
  }

  async function loadCampaignDetail(campaignId) {
    try {
      setError("");
      setSelectedOrders([]);
      setNotice("");

      const data = await fetchJson(`/campaigns/${campaignId}`);
      setCampaignDetail(data);
      setSelectedCampaignId(campaignId);
      const campaignAgent = findAgentForCampaign(agents, campaignId);
      setSelectedAgentId(campaignAgent?.agent_id || "");
    } catch (err) {
      setError(err.message);
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
      return "No query";
    }

    if (!step.elk_check.checked && step.elk_check.query) {
      return "Query ready";
    }

    if (!step.elk_check.checked) {
      return "Not configured";
    }

    return step.elk_check.matched ? "Detected" : "Missed";
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
    const detectedSteps = attackSteps.filter((step) => getDetectionStatus(step) === "detected");
    const missedSteps = attackSteps.filter((step) => getDetectionStatus(step) === "missed");
    const notCheckedSteps = attackSteps.filter((step) => getDetectionStatus(step) === "not_checked");

    const penalty = attackSteps.reduce((total, step) => {
      const risk = getRiskLevel(step);

      if (risk === "high") return total + 25;
      if (risk === "medium") return total + 10;
      return total + 3;
    }, 0);

    return {
      totalSteps: steps.length,
      attackCount: attackSteps.length,
      successfulAttackCount: successfulAttacks.length,
      detectedCount: detectedSteps.length,
      missedCount: missedSteps.length,
      notCheckedCount: notCheckedSteps.length,
      penalty,
      score: steps.length > 0 ? Math.max(0, 100 - penalty) : null,
    };
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

  const dashboardSummary = buildDashboardSummary(selectedRun);
  const attackPathSteps = selectedRun?.steps || campaignDetail?.flow || [];
  const latestJob = jobs[0] || null;
  const recentJobs = jobs.slice(0, 4);
  const selectedAgent = agents.find((agent) => agent.agent_id === selectedAgentId);
  const runPageCount = Math.max(1, Math.ceil(runs.length / RUNS_PER_PAGE));
  const visibleRuns = runs.slice(
    runPage * RUNS_PER_PAGE,
    runPage * RUNS_PER_PAGE + RUNS_PER_PAGE
  );
  const selectedRunSteps = selectedRun?.steps || [];
  const selectedRunAttackSteps = selectedRunSteps.filter((step) => step.phase === "attack");
  const campaignAttackCount = (campaignDetail?.flow || []).filter((step) => step.phase === "attack").length;
  const campaignNormalCount = (campaignDetail?.flow || []).filter((step) => step.phase === "normal").length;
  const selectedScopeCount = selectedOrders.length || campaignDetail?.flow?.length || 0;
  const selectedScopeLabel = selectedOrders.length > 0 ? `${selectedOrders.length}개 선택됨` : "전체 캠페인";
  const executedStepCount = selectedRunSteps.filter((step) => ["success", "simulated"].includes(step.status)).length;
  const nextActionText = selectedAgent
    ? "실행할 Technique을 선택하거나 전체 캠페인을 실행한 뒤, 탐지 검증과 증거 로그를 확인하세요."
    : "Job을 실행하기 전에 이 캠페인에 맞는 BasAgent를 먼저 실행해야 합니다.";
  const scoreExplanation = selectedRun
    ? `100점에서 위험 패널티 ${dashboardSummary.penalty}점을 차감했습니다. 미탐지는 가장 큰 패널티로 계산하고, ELK 연동 전 항목은 쿼리 준비 상태로 표시합니다.`
    : "아직 점수가 없습니다. 캠페인 Job을 실행하면 실행 결과와 탐지 커버리지를 기준으로 점수를 계산합니다.";

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

        const data = await fetchJson("/jobs", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            agent_id: selectedAgentId,
            campaign_id: selectedCampaignId,
            selected_orders: selectedOrders.length > 0 ? selectedOrders : null,
            include_normal: selectedOrders.length === 0
        })
        });

        setNotice(`Job queued: ${data.job.job_id}`);
        await refreshDashboardData();
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
      window.setTimeout(() => {
        detailRef.current?.scrollIntoView({
          behavior: "smooth",
          block: "start",
        });
      }, 0);
    } catch (err) {
      setError(err.message);
    }
  }

  async function refreshAgentJobs() {
    try {
        setError("");

        const { jobs: loadedJobs } = await refreshDashboardData();

        const completedJob = loadedJobs.find((job) => job.execution_id);
        if (completedJob?.execution_id) {
        const run = await fetchJson(`/runs/${completedJob.execution_id}`);
        setSelectedRun(run);
        }
    } catch (err) {
        setError(err.message);
    }
    }

  useEffect(() => {
    loadInitialData();
    loadCampaignDetail(selectedCampaignId);
  }, []);

  return (
    <main className="app-shell">
      <section className="topbar product-topbar">
        <div>
          <p className="eyebrow">Spacebar BAS</p>
          <h1>캠페인 검증 콘솔</h1>
          <p className="topbar-copy">
            캠페인 Technique을 실행하고, 예상 로그가 수집됐는지 확인하며, 실행 증거를 한 화면에서 검토합니다.
          </p>
        </div>

        <div className="topbar-status">
          <div className={`status-pill ${health ? "online" : "offline"}`}>
            {health ? "API 연결됨" : "API 연결 안 됨"}
          </div>
          <button type="button" className="ghost-button" onClick={refreshAgentJobs}>
            새로고침
          </button>
        </div>
      </section>

      {error && <div className="alert">{error}</div>}

      <section className="operator-next-step">
        <div>
          <div className="section-title">다음 작업</div>
          <strong>{selectedAgent ? "검증 준비 완료" : "Agent 필요"}</strong>
          <p>{nextActionText}</p>
        </div>
        <button
          className="run-button"
          onClick={runCampaign}
          disabled={isRunning || !selectedAgentId || !selectedCampaignId}
        >
          {isRunning ? "Job 실행 중..." : "캠페인 Job 실행"}
        </button>
      </section>

      <section className="overview-grid">
        <div className="panel campaign-overview">
          <div className="section-title">캠페인</div>
          <div className="campaign-selector-row">
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
            <span className="scope-pill">{selectedScopeLabel}</span>
          </div>

          <h2>{campaignDetail?.campaign_name || "선택된 캠페인 없음"}</h2>
          <p>{campaignDetail?.description || "캠페인을 선택하면 실행 범위를 불러옵니다."}</p>

          <div className="overview-facts">
            <div>
              <span>공격 단계</span>
              <strong>{campaignAttackCount}</strong>
            </div>
            <div>
              <span>정상 단계</span>
              <strong>{campaignNormalCount}</strong>
            </div>
            <div>
              <span>실행 범위</span>
              <strong>{selectedScopeCount}</strong>
            </div>
          </div>
        </div>

        <div className="panel agent-card">
          <div className="section-title">BasAgent</div>
          <div className="agent-state-row">
            <div>
              <h3>{selectedAgent?.display_name || "매칭되는 BasAgent 없음"}</h3>
              <p>{selectedAgent?.agent_id || `${selectedCampaignId} agent가 등록되지 않았습니다`}</p>
            </div>
            <span className={`job-badge ${selectedAgent?.status || "offline"}`}>
              {selectedAgent?.status || "offline"}
            </span>
          </div>

          <div className="agent-meta-grid">
            <div>
              <span>캠페인</span>
              <strong>{selectedAgent?.campaign_agent_id || selectedCampaignId}</strong>
            </div>
            <div>
              <span>수집기</span>
              <strong>{selectedAgent?.collector_type || "unknown"}</strong>
            </div>
            <div>
              <span>상태 수신</span>
              <strong>{selectedAgent?.last_heartbeat_at || "none"}</strong>
            </div>
          </div>
        </div>

        <div className="panel score-panel">
          <div className="section-title">검증 점수</div>
          <div className="score-value">
            {dashboardSummary.score === null ? "--" : dashboardSummary.score}
            <span>/100</span>
          </div>
          <p>
            {selectedRun
              ? `${selectedRun.campaign_id} 선택된 최근 실행 결과`
              : "Job을 실행하면 검증 점수를 계산합니다."}
          </p>
          <div className="score-explain">
            {scoreExplanation}
          </div>
        </div>
      </section>

      {notice && <div className="notice notice-wide">{notice}</div>}

      <section className="operator-grid">
        <section className="panel technique-panel">
          <div className="panel-title-row">
            <div>
              <div className="section-title">실행 범위</div>
              <h3>Techniques</h3>
            </div>
            <div className="selection-actions compact-actions">
              <button type="button" className="secondary-button" onClick={selectAllAttacks}>
                Attacks
              </button>
              <button type="button" className="secondary-button normal-action" onClick={selectAllNormal}>
                Normal
              </button>
              <button type="button" className="ghost-button" onClick={clearSelection}>
                선택 해제
              </button>
            </div>
          </div>

          <div className="technique-list">
            {(campaignDetail?.flow || []).map((step) => {
              const isSelectedStep = selectedOrders.includes(step.order);

              return (
                <button
                  key={step.order}
                  type="button"
                  className={[
                    "technique-row",
                    step.phase,
                    isSelectedStep ? "selected-step" : "",
                  ].join(" ")}
                  onClick={() => toggleStep(step)}
                >
                  <span className="step-index">{step.order}</span>
                  <span className="technique-main">
                    <strong>{step.name}</strong>
                    <small>{getTechniqueDisplayName(step)}</small>
                  </span>
                  <span className="technique-tags">
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
          </div>
        </section>

        <section className="panel validation-panel">
          <div className="panel-title-row">
            <div>
              <div className="section-title">탐지 검증</div>
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
              <strong>{dashboardSummary.detectedCount}</strong>
            </div>
            <div>
              <span>미탐</span>
              <strong>{dashboardSummary.missedCount}</strong>
            </div>
            <div>
              <span>쿼리 준비</span>
              <strong>{dashboardSummary.notCheckedCount}</strong>
            </div>
          </div>

          <div className="path-map compact-path-map">
            {attackPathSteps.map((step) => {
              const hasRunResult = Boolean(step.status);
              const executionStatus = step.status || "not_run";
              const detectionStatus = hasRunResult ? getDetectionStatus(step) : "not_run";
              const riskLevel = hasRunResult ? getRiskLevel(step) : "not_run";
              const isSelectedPath = selectedOrders.includes(step.order)
                || selectedRun?.final_orders?.includes(step.order);

              return (
                <div
                  key={step.order}
                  className={[
                    "validation-row",
                    step.phase,
                    isSelectedPath ? "selected-path-node" : "",
                  ].join(" ")}
                >
                  <div>
                    <strong>{step.order}. {step.name}</strong>
                    <small>{getTechniqueDisplayName(step)}</small>
                  </div>
                  <div className="validation-badges">
                    <span className={`result-badge ${executionStatus}`}>{executionStatus}</span>
                    <span className={`status-tag ${detectionStatus}`}>{getDetectionLabel(step)}</span>
                    <span className={`status-tag risk-${riskLevel}`}>{riskLevel}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
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

      <section className="panel evidence-panel" ref={detailRef}>
        <div className="panel-title-row">
          <div>
            <div className="section-title">증거</div>
            <h3>{selectedRun ? selectedRun.execution_id : "실행 결과를 선택하거나 새로 실행하세요"}</h3>
          </div>
          {selectedRun && <span className="scope-pill">{selectedRun.campaign_id}</span>}
        </div>

        {!selectedRun && <p className="empty">실행 상세에는 명령, 생성 아티팩트, 예상 탐지 쿼리가 표시됩니다.</p>}

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
    </main>
  );
}
