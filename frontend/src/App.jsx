// 화면 로직 
// API 상태 확인 , 캠페인 목록, 캠페인 상세 표시, Run Campaign 버튼 처리
// 실행 결과 목록 표시, 실행 결과 상세 표시 

import { useEffect, useState } from "react";
import "./styles.css";

const API_BASE = "http://127.0.0.1:8000";

export default function App() {
  const [health, setHealth] = useState(null);
  const [campaigns, setCampaigns] = useState([]);
  const [selectedCampaignId, setSelectedCampaignId] = useState("SB-05");
  const [campaignDetail, setCampaignDetail] = useState(null);
  const [runs, setRuns] = useState([]);
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

  async function loadInitialData() {
    try {
      setError("");

      const healthData = await fetchJson("/health");
      setHealth(healthData);

      const campaignData = await fetchJson("/campaigns");
      setCampaigns(campaignData.campaigns || []);

      const runData = await fetchJson("/runs");
      setRuns(runData.runs || []);
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

  async function runCampaign() {
    try {
      setIsRunning(true);
      setError("");

      const data = await fetchJson("/runs", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          campaign_id: selectedCampaignId,
          selected_orders: selectedOrders.length > 0 ? selectedOrders : null,
          include_normal: true
        })
      });

      setSelectedRun(data.result);

      const runData = await fetchJson("/runs");
      setRuns(runData.runs || []);
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

      <section className="layout">
        <aside className="panel sidebar">
          <div className="section-title">Campaigns</div>

          <div className="campaign-list">
            {campaigns.map((campaign) => (
              <button
                key={campaign.campaign_id}
                className={
                  campaign.campaign_id === selectedCampaignId
                    ? "campaign-item selected"
                    : "campaign-item"
                }
                onClick={() => loadCampaignDetail(campaign.campaign_id)}
              >
                <strong>{campaign.campaign_id}</strong>
                <span>{campaign.campaign_name}</span>
                <small>{campaign.step_count} steps</small>
              </button>
            ))}
          </div>
        </aside>

        <section className="panel main-panel">
          <div className="panel-header">
            <div>
              <div className="section-title">Selected Campaign</div>
              <h2>{campaignDetail?.campaign_name || "No campaign selected"}</h2>
              <p>{campaignDetail?.description}</p>

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

            <button
              className="run-button"
              onClick={runCampaign}
              disabled={isRunning}
            >
              {isRunning ? "Running..." : "Run Campaign"}
            </button>
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
                <small>{run.started_at}</small>
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
                      <code>{step.elk_check?.query || "No ELK query"}</code>
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
