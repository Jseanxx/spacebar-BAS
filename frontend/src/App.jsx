// 화면 로직 
// API 상태 확인 , 캠페인 목록, 캠페인 상세 표시, Run Campaign 버튼 처리
// 실행 결과 목록 표시, 실행 결과 상세 표시 

import { useEffect, useState } from "react";
import "./styles.css";

const API_BASE = "http://127.0.0.1:8000";
const JOB_POLL_INTERVAL_MS = 1500;
const JOB_POLL_ATTEMPTS = 40;

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

  function toggleAttackStep(step) {
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
      setNotice(
        `${step.technique_id} 실행을 위해 선행 단계 ${labels}가 자동 포함되었습니다.`
      );
    } else {
      setNotice("");
    }
  }

  function selectAllAttacks() {
    const attackOrders = (campaignDetail?.flow || [])
      .filter((step) => step.phase === "attack")
      .map((step) => step.order)
      .sort((a, b) => a - b);

    setSelectedOrders(attackOrders);
    setNotice("모든 공격 단계가 선택되었습니다.");
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

  function getRiskLevel(step) {
    const detectionStatus = getDetectionStatus(step);

    if (step.status !== "success") {
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
    const successfulAttacks = attackSteps.filter((step) => step.status === "success");
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
      score: steps.length > 0 ? Math.max(0, 100 - penalty) : null,
    };
  }

  function getStepBehavior(step) {
    return step.module_result?.behavior || step.module || "unknown";
  }

  function getExecutionMode(step) {
    return step.module_result?.execution_mode || selectedRun?.bas_agent?.mode || "simulation";
  }

  function formatCommandStatus(command) {
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
    const commands = Array.isArray(result.commands) ? result.commands : [];
    const artifacts = Array.isArray(result.artifacts) ? result.artifacts : [];

    return (
      <div className="evidence-block">
        <div className="evidence-grid">
          <div>
            <span>Behavior</span>
            <strong>{getStepBehavior(step)}</strong>
          </div>
          <div>
            <span>Mode</span>
            <strong>{getExecutionMode(step)}</strong>
          </div>
          <div>
            <span>Evidence Key</span>
            <strong>{result.evidence_key || "none"}</strong>
          </div>
        </div>

        {commands.length > 0 && (
          <div className="command-list">
            <div className="evidence-title">Command Results</div>

            {commands.map((command, index) => (
              <div key={`${step.order}-command-${index}`} className="command-item">
                <div className="command-header">
                  <code>{command.command}</code>
                  <span className={`result-badge ${formatCommandStatus(command)}`}>
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
            <div className="evidence-title">Artifacts</div>
            {artifacts.map((artifact, index) => (
              <code key={`${step.order}-artifact-${index}`}>
                {typeof artifact === "string" ? artifact : JSON.stringify(artifact)}
              </code>
            ))}
          </div>
        )}

        <div className="query-box">
          <span>Detection Query</span>
          <code>{step.elk_check?.query || "No ELK query"}</code>
        </div>
      </div>
    );
  }

  const dashboardSummary = buildDashboardSummary(selectedRun);
  const attackPathSteps = campaignDetail?.flow || [];
  const latestJob = jobs[0] || null;
  const selectedAgent = agents.find((agent) => agent.agent_id === selectedAgentId);

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
            include_normal: true
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
      <section className="topbar">
        <div>
          <p className="eyebrow">Mini BAS Console</p>
          <h1>Campaign Runner</h1>
        </div>

        <div className={`status-pill ${health ? "online" : "offline"}`}>
          {health ? "API Online" : "API Offline"}
        </div>
      </section>

      {error && <div className="alert">{error}</div>}

      <section className="dashboard-grid">
        <div className="panel score-panel">
          <div className="section-title">Security Score</div>
          <div className="score-value">
            {dashboardSummary.score === null ? "--" : dashboardSummary.score}
            <span>/100</span>
          </div>
          <p>
            {selectedRun
              ? `${selectedRun.campaign_id} campaign run 기준 점수`
              : "Run 결과를 선택하면 점수가 계산됩니다."}
          </p>
        </div>

        <div className="panel metric-panel">
          <div className="section-title">TTP Execution</div>
          <strong>{dashboardSummary.successfulAttackCount}</strong>
          <span>successful attack steps</span>
          <small>{dashboardSummary.attackCount} attack steps in selected run</small>
        </div>

        <div className="panel metric-panel">
          <div className="section-title">Detection</div>
          <strong>{dashboardSummary.detectedCount}</strong>
          <span>detected attack steps</span>
          <small>{dashboardSummary.notCheckedCount} not checked</small>
        </div>

        <div className="panel metric-panel">
          <div className="section-title">Missed</div>
          <strong>{dashboardSummary.missedCount}</strong>
          <span>missed attack steps</span>
          <small>successful + missed is high risk</small>
        </div>
      </section>

      <section className="panel run-control-panel">
        <div className="control-group">
          <label>
            Campaign
            <select
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

          <div className="inferred-agent">
            <span>BasAgent</span>
            <strong>{selectedAgent?.display_name || selectedAgentId || "No matching BasAgent"}</strong>
            <small>{selectedAgent?.agent_id || `${selectedCampaignId} agent is not registered`}</small>
          </div>
        </div>

        <div className="control-actions">
          <button
            className="run-button"
            onClick={runCampaign}
            disabled={isRunning || !selectedAgentId || !selectedCampaignId}
          >
            {isRunning ? "Running Job..." : "Queue Job"}
          </button>

          <button
            type="button"
            className="ghost-button"
            onClick={refreshAgentJobs}
          >
            Refresh
          </button>
        </div>
      </section>

      <section className="layout execution-layout">
        <section className="panel main-panel">
          <div className="panel-header">
            <div>
              <div className="section-title">Technique Selection</div>
              <h2>{campaignDetail?.campaign_name || "No campaign selected"}</h2>

              <div className="selection-actions">
                <button
                  type="button"
                  className="secondary-button"
                  onClick={selectAllAttacks}
                >
                  Select All Attacks
                </button>

                <button
                  type="button"
                  className="ghost-button"
                  onClick={clearSelection}
                >
                  Clear Selection
                </button>
              </div>

              {notice && <div className="notice">{notice}</div>}
            </div>

          </div>

          <div className="flow-list">
            {(campaignDetail?.flow || []).map((step) => {
              const isAttack = step.phase === "attack";
              const isSelectedAttack = selectedOrders.includes(step.order);

              return (
                <button
                  key={step.order}
                  type="button"
                  className={[
                    "flow-step",
                    step.phase,
                    isSelectedAttack ? "selected-step" : ""
                  ].join(" ")}
                  onClick={() => {
                    if (isAttack) {
                      toggleAttackStep(step);
                    }
                  }}
                  disabled={!isAttack}
                >
                  <div className="step-index">{step.order}</div>

                  <div className="step-content">
                    <div className="step-title-row">
                      <div>
                        <div className="step-title">{step.name}</div>

                        <div className="step-meta">
                          <span
                            className={
                              isAttack
                                ? "chip attack-chip"
                                : "chip normal-chip"
                            }
                          >
                            {isAttack ? "Attack" : "Normal"}
                          </span>

                          {step.technique_id && (
                            <span className="chip technique-chip">
                              {step.technique_id}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        </section>

        <section className="panel latest-job-panel">
          <div className="panel-title-row">
            <div>
              <div className="section-title">Latest Job</div>
              <h3>{latestJob ? latestJob.status : "No job yet"}</h3>
            </div>

            {latestJob && (
              <span className={`job-badge ${latestJob.status}`}>
                {latestJob.status}
              </span>
            )}
          </div>

          {!latestJob && (
            <p className="empty">Select a campaign and BasAgent, then queue a job.</p>
          )}

          {latestJob && (
            <div className="latest-job-card">
              <div>
                <span>Job ID</span>
                <strong>{latestJob.job_id}</strong>
              </div>

              <div>
                <span>Campaign</span>
                <strong>{latestJob.campaign_id}</strong>
              </div>

              <div>
                <span>BasAgent</span>
                <strong>{latestJob.agent_id}</strong>
              </div>

              <div>
                <span>Created</span>
                <strong>{latestJob.created_at}</strong>
              </div>

              {latestJob.execution_id && (
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() => loadRun(latestJob.execution_id)}
                >
                  Open Run Detail
                </button>
              )}
            </div>
          )}
        </section>
      </section>

      <section className="layout analysis-layout">
        <section className="panel">
          <div className="section-title">TTP Execution Status</div>

          {!selectedRun && (
            <p className="empty">Run을 선택하거나 실행하면 TTP 현황이 표시됩니다.</p>
          )}

          {selectedRun && (
            <div className="ttp-table">
              <div className="ttp-row ttp-header">
                <span>Technique</span>
                <span>Step</span>
                <span>Execution</span>
                <span>Detection</span>
                <span>Risk</span>
              </div>

              {(selectedRun.steps || []).map((step) => {
                const detectionStatus = getDetectionStatus(step);
                const riskLevel = getRiskLevel(step);

                return (
                  <div key={`${step.order}-${step.module}`} className="ttp-row">
                    <span>{step.technique_id || "baseline"}</span>
                    <span>{step.order}. {step.name}</span>
                    <span className={`result-badge ${step.status}`}>
                      {step.status}
                    </span>
                    <span className={`status-tag ${detectionStatus}`}>
                      {detectionStatus}
                    </span>
                    <span className={`status-tag risk-${riskLevel}`}>
                      {riskLevel}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        <section className="panel">
          <div className="section-title">Attack Path Map</div>

          <div className="path-map">
            {attackPathSteps.map((step) => (
              <div
                key={step.order}
                className={[
                  "path-node",
                  step.phase,
                  selectedOrders.includes(step.order) ? "selected-path-node" : "",
                ].join(" ")}
              >
                <strong>{step.order}</strong>
                <span>{step.name}</span>
                <small>{step.technique_id || step.phase}</small>
              </div>
            ))}
          </div>
        </section>
      </section>
      
      <section className="layout bottom-layout">
        <section className="panel">
          <div className="section-title">Recent Runs</div>

          <div className="run-list">
            {runs.map((run) => (
              <button
                key={run.execution_id}
                className="run-item"
                onClick={() => loadRun(run.execution_id)}
              >
                <strong>{run.execution_id}</strong>
                <span>{run.campaign_id}</span>
                <small>
                    {run.bas_agent?.type || "bas_agent"} · {run.started_at}
                </small>
              </button>
            ))}
          </div>
        </section>

        <section className="panel">
          <div className="section-title">Run Detail</div>

          {!selectedRun && <p className="empty">Select or execute a run.</p>}

          {selectedRun && (
            <div className="detail">
              <h3>{selectedRun.execution_id}</h3>
              <p>
                {selectedRun.campaign_id} · {selectedRun.started_at}
              </p>

              {selectedRun.bas_agent && (
                <div className="run-summary">
                    <strong>BasAgent</strong>
                    <span>
                    {selectedRun.bas_agent.type} · {selectedRun.bas_agent.runner}
                    </span>
                </div>
                )}

              {selectedRun.final_orders && (
                <div className="run-summary">
                  <strong>Final execution orders</strong>
                  <span>{selectedRun.final_orders.join(", ")}</span>
                </div>
              )}

              <div className="result-steps">
                {(selectedRun.steps || []).map((step) => (
                  <div
                    key={`${step.order}-${step.module}`}
                    className="result-step"
                  >
                    <div>
                      <strong>
                        {step.order}. {step.name}
                      </strong>

                      <div className="step-meta">
                        <span
                          className={
                            step.phase === "attack"
                              ? "chip attack-chip"
                              : "chip normal-chip"
                          }
                        >
                          {step.phase === "attack" ? "Attack" : "Normal"}
                        </span>

                        {step.technique_id && (
                          <span className="chip technique-chip">
                            {step.technique_id}
                          </span>
                        )}
                      </div>

                      <p>{step.module_result?.message}</p>
                      {renderModuleEvidence(step)}
                    </div>

                    <span className={`result-badge ${step.status}`}>
                      {step.status}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </section>
      </section>
    </main>
  );
}
