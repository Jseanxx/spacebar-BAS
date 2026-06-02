import { useEffect, useMemo, useRef, useState } from "react";
import spacebarLogo from "./assets/spacebar-logo.png";
import "./styles.css";

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";
const POLL_INTERVAL_MS = 900;
const POLL_LIMIT = 240;
const DASHBOARD_CACHE_KEY = "bas-dashboard-cache-v2";

const PANELS = [
  { id: "overview", label: "Summary", hint: "자산과 상태" },
  { id: "library", label: "Technique", hint: "선택과 실행" },
  { id: "queue", label: "Queue", hint: "순서와 입력값" },
  { id: "evidence", label: "Evidence", hint: "결과와 로그" },
];

const ASSET_POSITIONS = {
  attacker: { left: 14, top: 50 },
  pc01: { left: 33, top: 48 },
  fs01: { left: 59, top: 52 },
  dc01: { left: 80, top: 34 },
  elk: { left: 82, top: 76 },
};

const MAP_POSITION_OVERRIDES = {
  "SB-AD": {
    fs01: { left: 61.5, top: 34 },
    elk: { left: 61.5, top: 77.5 },
  },
  "SB-05": {
    "sb05-kubernetes": { left: 37.5, top: 34 },
    "prod-platform": { left: 37.5, top: 78 },
    "sb05-elk": { left: 85.5, top: 34 },
    "cloudtrail-sqs-pipeline": { left: 85.5, top: 78 },
  },
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

function getMapPositionOverride(targetId, assetId, fallbackPosition) {
  const campaignId = String(targetId || "").toUpperCase();
  const normalizedAssetId = String(assetId || "").toLowerCase();
  return MAP_POSITION_OVERRIDES[campaignId]?.[normalizedAssetId] || fallbackPosition;
}

function readDashboardCache() {
  try {
    return JSON.parse(window.localStorage.getItem(DASHBOARD_CACHE_KEY) || "{}");
  } catch {
    return {};
  }
}

function writeDashboardCache(partial) {
  try {
    const current = readDashboardCache();
    window.localStorage.setItem(DASHBOARD_CACHE_KEY, JSON.stringify({
      ...current,
      ...partial,
      cached_at: new Date().toISOString(),
    }));
  } catch {
    // Cache is a convenience for offline viewing; ignore storage failures.
  }
}

function getUrlCampaignId() {
  try {
    return new URLSearchParams(window.location.search).get("campaign") || "";
  } catch {
    return "";
  }
}

function getInitialCampaignId() {
  const urlCampaignId = getUrlCampaignId();
  if (urlCampaignId) return urlCampaignId;

  const cachedCampaignId = readDashboardCache().campaignId;
  return cachedCampaignId || "SB-AD";
}

function syncCampaignUrl(nextCampaignId) {
  try {
    const url = new URL(window.location.href);
    url.searchParams.set("campaign", nextCampaignId);
    window.history.replaceState({}, "", url);
  } catch {
    // URL persistence is a convenience for refresh/deep-link behavior.
  }
}

function getStepRole(step) {
  const commands = normalizeList(step?.params?.commands);
  return commands[0]?.agent_role || step?.params?.agent_role || step?.agent_role || "campaign_agent";
}

function getStepAssetId(step) {
  const role = getStepRole(step);
  const explicitAssetId = step?.target_asset_id || step?.asset_id || step?.params?.target_asset_id || step?.params?.asset_id;
  const host = String(step?.execution_host || step?.params?.execution_host || "").toLowerCase();
  const behavior = [
    step?.name,
    step?.module,
    step?.target,
    step?.params?.behavior,
    step?.params?.evidence_key,
    step?.params?.message,
  ].filter(Boolean).join(" ").toLowerCase();

  if (explicitAssetId) return String(explicitAssetId).toLowerCase();

  if (host.includes("fs01")) return "fs01";
  if (host.includes("dc01")) return "dc01";
  if (host.includes("pc01")) return "pc01";
  if (host.includes("attacker")) return "attacker";
  if (behavior.includes("postgresql") || behavior.includes("database") || behavior.includes("db_")) return "postgresql-db";
  if (behavior.includes("jenkins_to_app") || behavior.includes("app_directory") || behavior.includes("app_local") || behavior.includes("outbound") || behavior.includes("exfiltration")) return "nginx-app";
  if (behavior.includes("jenkins")) return "jenkins-controller";
  if (role === "pc01") return "pc01";
  if (role === "fs01") return "fs01";
  if (role === "attacker") return "attacker";
  if (role === "log_source") return "dc01";
  if (String(step?.target || "").toUpperCase() === "SB-01" && role === "campaign_agent") return "jenkins-controller";
  return role;
}

function inferAgentAssetKey(agent) {
  if (!agent) return "";
  if (String(agent.campaign_agent_id || "").toUpperCase() === "SB-01") return "jenkins-controller";
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

  return ["jenkins-controller", "nginx-app", "postgresql-db", "elk-siem", "jenkins", "postgresql", "nginx", "attacker", "bastion", "pms", "win01", "pc01", "fs01", "dc01", "soc01", "elk"].find((assetId) => searchable.includes(assetId)) || "";
}

function getStepSelectionId(step, fallbackCampaignId) {
  return step.selection_id || `${step.source_campaign_id || fallbackCampaignId}:${step.order}`;
}

function getStepSourceId(step, fallbackCampaignId) {
  return step.source_campaign_id || step.campaign_id || fallbackCampaignId;
}

function getAssetDisplayIp(asset) {
  return asset?.public_ip || asset?.elastic_ip || asset?.private_ip || asset?.hostname || "N/A";
}

function getAssetNodeKind(asset) {
  const combined = [
    asset?.platform,
    asset?.os,
    asset?.role,
    asset?.asset_id,
    asset?.name,
    asset?.hostname,
    ...normalizeList(asset?.tags),
  ].filter(Boolean).join(" ").toLowerCase();
  if (combined.includes("jenkins")) return "jenkins";
  if (combined.includes("postgresql") || combined.includes("postgres") || combined.includes("database")) return "postgresql";
  if (combined.includes("nginx")) return "nginx";
  if (combined.includes("kubernetes") || combined.includes("k3s") || combined.includes("namespace")) return "k8s";
  if (combined.includes("aws") || combined.includes("s3") || combined.includes("cloudtrail")) return "cloud";
  if (combined.includes("elk") || combined.includes("monitoring") || combined.includes("log")) return "log";
  if (combined.includes("windows")) return "windows";
  if (combined.includes("ubuntu") || combined.includes("linux")) return "linux";
  return "host";
}

function renderAssetOsMark(nodeKind) {
  if (nodeKind === "log") {
    return <i className="os-mark log-mark">ELK</i>;
  }

  const iconUrls = {
    windows: "https://api.iconify.design/devicon/windows8.svg",
    linux: "https://api.iconify.design/devicon/linux.svg",
    k8s: "https://api.iconify.design/devicon/kubernetes.svg",
    cloud: "https://api.iconify.design/devicon/amazonwebservices-wordmark.svg",
    jenkins: "https://api.iconify.design/devicon/jenkins.svg",
    postgresql: "https://api.iconify.design/devicon/postgresql.svg",
    nginx: "https://api.iconify.design/devicon/nginx.svg",
  };
  const labels = {
    windows: "Windows",
    linux: "Linux",
    k8s: "Kubernetes",
    cloud: "AWS",
    jenkins: "Jenkins",
    postgresql: "PostgreSQL",
    nginx: "Nginx",
  };
  const iconUrl = iconUrls[nodeKind];

  if (!iconUrl) {
    return <i className="os-mark host-mark">PC</i>;
  }

  return (
    <img
      className={`os-mark os-icon-image os-icon-${nodeKind}`}
      src={iconUrl}
      alt={labels[nodeKind]}
      loading="lazy"
      referrerPolicy="no-referrer"
    />
  );
}

function shouldShowMapPath(path) {
  if (path?.map_visible === true) return true;
  if (path?.map_visible === false) return false;

  const sourceId = String(path?.source_asset_id || "").toLowerCase();
  const targetId = String(path?.target_asset_id || "").toLowerCase();
  if (!sourceId || !targetId || sourceId === targetId) return false;

  const label = String(path?.label || "").toLowerCase();
  return !/(discovery|credential|staging|exfiltration|domain compromise|dump|collection)/.test(label);
}

function getTargetCapabilities(target) {
  return new Set(normalizeList(target?.capabilities).map((item) => String(item).toLowerCase()));
}

function getStepCompatibility(step, target, currentCampaignId) {
  const sourceId = getStepSourceId(step, currentCampaignId);
  if (sourceId === currentCampaignId) {
    return {
      compatible: true,
      reason: "현재 환경 기본 Technique",
      missing: [],
    };
  }

  const required = normalizeList(step?.requires).map((item) => String(item).toLowerCase());
  if (required.length === 0) {
    return {
      compatible: false,
      reason: "현재 환경에서 필요한 실행 조건을 확인할 수 없음",
      missing: [],
    };
  }

  const capabilities = getTargetCapabilities(target);
  const missing = required.filter((item) => !capabilities.has(item));
  if (missing.length > 0) {
    return {
      compatible: false,
      reason: `현재 환경에 없는 조건: ${missing.join(", ")}`,
      missing,
    };
  }

  return {
    compatible: true,
    reason: "현재 환경 capability와 실행 조건이 일치",
    missing: [],
  };
}

function getTechniqueLabel(step) {
  return step.technique_id ? `${step.technique_id} · ${step.name}` : step.name;
}

function isSubTechnique(step) {
  return /^T\d{4}\.\d{3}$/.test(String(step?.technique_id || ""));
}

function isNormalStep(step) {
  return String(step?.phase || "").toLowerCase() === "normal";
}

function isScoredStep(step) {
  return step && !isNormalStep(step);
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

function isOperationSettled(operation) {
  if (!operation) return false;
  const finalStatus = ["completed", "simulated", "cancelled", "blocked", "failed"].includes(operation.status);
  if (!finalStatus) return false;

  const validationStatus = operation.elk_validation_status;
  const validationPending = ["waiting", "running"].includes(validationStatus);
  if (validationPending) return false;

  if (operation.status === "completed" && !operation.report && !operation.report_error) return false;
  return true;
}

function isLiveOperation(operation) {
  if (!operation || !["pending", "queued", "running"].includes(operation.status)) return false;

  const timestamp = Date.parse(operation.started_at || operation.created_at || "");
  if (!timestamp) return true;

  return Date.now() - timestamp < 15 * 60 * 1000;
}

function reportScore(report) {
  const score = Number(report?.summary?.final_score);
  return Number.isFinite(score) ? score : -1;
}

function reportDetectionCoverage(report) {
  const coverage = Number(report?.summary?.detection_coverage);
  return Number.isFinite(coverage) ? coverage : -1;
}

function reportGeneratedTime(report) {
  return Date.parse(report?.generated_at || report?.created_at || "") || 0;
}

function getToastTone(error, notice) {
  if (error) return "error";
  if (!notice) return "neutral";

  const progressMatch = String(notice).match(/(\d+)\/(\d+)/);
  if (progressMatch) {
    const current = Number(progressMatch[1]);
    const total = Number(progressMatch[2]);
    if (total > 0 && current >= total) return "success";
    return "progress";
  }

  if (/(완료|반영|제외했습니다|담았습니다|올렸습니다)/.test(notice)) return "success";
  if (/(진행 중|검증 중|생성 중|시작했습니다)/.test(notice)) return "progress";
  if (/(불안정|취소|초기화)/.test(notice)) return "warning";
  return "neutral";
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
  if (isNormalStep(step)) return "baseline";
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
    baseline: "기준",
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

  if (isNormalStep(step)) {
    return "정상 기준선 확인 단계입니다. 공격 탐지 점수와 미탐 분모에서는 제외됩니다.";
  }

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

function getStepQueries(step) {
  const elkCheck = step?.elk_check || step?.result_step?.elk_check || {};
  const alertCheck = elkCheck?.alert_check || step?.alert_check || {};
  const queries = step?.queries || {};

  return {
    source: queries.source || step?.source_query || elkCheck?.query || "",
    alert: queries.alert || step?.alert_query || alertCheck?.query || "",
  };
}

function getCoverageFields(step, detectionStatus) {
  const recommendation = step?.recommendation || {};
  const fallbackAction = recommendation.action || "review_detection_logic";

  return [
    ["Technique ID", step?.technique_id || "-"],
    ["Attack Name", step?.attack_name || step?.name || "-"],
    ["Target Asset", step?.target_asset || getStepAssetId(step).toUpperCase()],
    ["Required Condition", step?.required_condition || "-"],
    ["Expected Log", step?.expected_log || "Source telemetry from the mapped log source"],
    ["Detection Rule", step?.detection_rule || "-"],
    ["Detection Result", step?.detection_result || getDetectionLabel(detectionStatus)],
    ["Coverage Status", step?.coverage_status || getDetectionLabel(detectionStatus)],
    ["System Impact", step?.system_impact || "-"],
    ["Risk Level", step?.risk_level || step?.risk || "-"],
    ["Recommended Sensor", step?.recommended_sensor || "-"],
    ["Improvement Plan", step?.improvement_plan || fallbackAction],
  ];
}

function getStepRiskLevel(step) {
  const deleteImpactLevel = getDeleteImpactLevel(step);
  if (deleteImpactLevel) {
    const rank = { low: 1, medium: 2, high: 3, critical: 4 };
    const rawRisk = String(step?.risk || step?.params?.risk || "medium").toLowerCase();
    return rank[deleteImpactLevel] > rank[rawRisk] ? deleteImpactLevel : rawRisk;
  }
  if (step?.phase === "normal") return "low";
  return String(step?.risk || step?.params?.risk || "medium").toLowerCase();
}

function getSafetyGates(step) {
  return normalizeList(step?.params?.safety_gates || step?.safety_gates);
}

function stepHasDeleteAction(step) {
  return Boolean(getDeleteImpactLevel(step));
}

function getDeleteImpactLevel(step) {
  const params = step?.params || {};
  const commandText = JSON.stringify([
    params.commands,
    params.cleanup,
    step?.commands,
    step?.cleanup,
    params.behavior,
    step?.name,
  ] || []).toLowerCase();

  const hasDeleteCommand = /remove-item|\brm\s+-[a-z]*f|\bdel\s+|kubectl\s+delete|aws\s+s3\s+rm|\brmdir\b|remove-scheduledtask|schtasks\b.*\bdelete\b/.test(commandText);
  if (!hasDeleteCommand) return null;

  const sourceId = String(step?.source_campaign_id || step?.campaign_id || step?.target || "").toUpperCase();
  const order = Number(step?.order ?? params.scenario_order);
  if (sourceId === "SB-AD" && order === 17) return "critical";
  if (/lsass|sam|credential|dump|reg save|comsvcs/.test(commandText)) return "high";
  return "medium";
}

function clampPercent(value) {
  return Math.max(0, Math.min(95, Math.round(value)));
}

function getSafetyProfile(step) {
  const deleteImpactLevel = getDeleteImpactLevel(step);
  const deleteAction = Boolean(deleteImpactLevel);

  if (step?.phase === "normal" && !deleteAction) {
    return {
      risk: "low",
      impact: "Low",
      failurePossibility: "없음",
      networkLoad: "없음",
      serviceDownPossibility: "N/A",
      serviceImpactPercent: 2,
      networkImpactPercent: 1,
      warningRequired: "불필요",
      executionRecommendation: "안전",
      className: "safe",
      gates: [],
    };
  }

  const risk = getStepRiskLevel(step);
  const gates = getSafetyGates(step);
  const behavior = String(step?.params?.behavior || step?.behavior || "").toLowerCase();
  const requires = normalizeList(step?.requires).join(" ").toLowerCase();
  const name = String(step?.name || "").toLowerCase();
  const combined = `${behavior} ${requires} ${name} ${gates.join(" ")}`.toLowerCase();

  const domainCompromise = /dcsync|golden|ntds|domain_compromise|krbtgt|secretsdump/.test(combined);
  const credentialDump = /lsass|credential|dump|comsvcs|sam|ntds/.test(combined);
  const serviceExecution = /service_execution|psexec|service/.test(combined);
  const networkHeavy = /dos|scan|sweep|flood|spoof/.test(combined);
  const networkTouch = /network|tcp|c2|exfiltration|tool_transfer|winrm|remote/.test(combined);

  const criticalImpact = deleteImpactLevel === "critical";
  const highImpact = deleteImpactLevel === "high" || risk === "critical" || domainCompromise || credentialDump || serviceExecution || networkHeavy;
  const mediumImpact = risk === "high" || risk === "medium" || gates.length > 0 || networkTouch;
  const impact = criticalImpact ? "Critical" : highImpact ? "High" : mediumImpact ? "Medium" : "Low";
  const failurePossibility = criticalImpact || highImpact ? "있음" : mediumImpact ? "낮음" : "없음";
  const networkLoad = networkHeavy ? "높음" : networkTouch ? "낮음" : "없음";
  const serviceDownPossibility = networkHeavy || serviceExecution || domainCompromise || deleteImpactLevel === "critical" || deleteImpactLevel === "high" ? "있음" : "N/A";
  const baseRiskPercent = {
    low: 5,
    medium: 15,
    high: 32,
    critical: 58,
  }[risk] || 15;
  const serviceImpactPercent = clampPercent(
    baseRiskPercent
    + (domainCompromise ? 18 : 0)
    + (credentialDump ? 12 : 0)
    + (serviceExecution ? 16 : 0)
    + (networkHeavy ? 20 : 0)
    + (deleteImpactLevel === "critical" ? 45 : deleteImpactLevel === "high" ? 24 : deleteImpactLevel === "medium" ? 10 : 0)
    + (gates.length > 1 ? 6 : 0),
  );
  const networkImpactPercent = clampPercent(
    (networkHeavy ? 62 : networkTouch ? 22 : 3)
    + (risk === "critical" ? 8 : risk === "high" ? 5 : 0),
  );
  const warningRequired = impact === "Critical" || impact === "High" || risk === "high" || risk === "critical" || gates.length > 1 ? "필요" : "불필요";
  const executionRecommendation = criticalImpact
    ? "운영환경 금지"
    : highImpact || networkHeavy
    ? "위험 테크닉"
    : mediumImpact
      ? "테스트환경 권장"
      : "안전";
  const className = executionRecommendation === "운영환경 금지" || executionRecommendation === "위험 테크닉"
    ? "danger"
    : executionRecommendation === "테스트환경 권장"
      ? "warn"
      : "safe";

  return {
    risk,
    impact,
    failurePossibility,
    networkLoad,
    serviceDownPossibility,
    serviceImpactPercent,
    networkImpactPercent,
    warningRequired,
    executionRecommendation,
    className,
    gates,
  };
}

function getImpactLabel(value) {
  return { Critical: "치명", High: "높음", Medium: "중간", Low: "낮음" }[value] || value;
}

function getRecommendationShort(value) {
  return {
    "운영환경 금지": "금지",
    "위험 테크닉": "위험",
    "테스트환경 권장": "주의",
    "안전": "안전",
  }[value] || value;
}

function summarizeSafetyProfiles(steps) {
  const profiles = steps.map(getSafetyProfile);
  const severity = { safe: 1, warn: 2, danger: 3 };
  const highest = profiles.reduce((current, profile) => (
    !current || severity[profile.className] > severity[current.className] ? profile : current
  ), null);
  const maxServiceImpactPercent = Math.max(0, ...profiles.map((profile) => profile.serviceImpactPercent || 0));
  const maxNetworkImpactPercent = Math.max(0, ...profiles.map((profile) => profile.networkImpactPercent || 0));

  return {
    highest,
    maxServiceImpactPercent,
    maxNetworkImpactPercent,
    safe: profiles.filter((profile) => profile.className === "safe").length,
    warn: profiles.filter((profile) => profile.className === "warn").length,
    danger: profiles.filter((profile) => profile.className === "danger").length,
  };
}

function summarizeStepStatuses(steps) {
  return normalizeList(steps).reduce((summary, step) => {
    const status = step?.status || step?.execution_status || "unknown";
    return {
      ...summary,
      total: summary.total + 1,
      [status]: (summary[status] || 0) + 1,
    };
  }, { total: 0 });
}

function hasSuccessfulStep(item) {
  return normalizeList(item?.steps || item?.final_steps).some((step) => (
    isScoredStep(step) && ["success", "completed"].includes(step?.status || step?.execution_status)
  ));
}

export default function App() {
  const [health, setHealth] = useState(null);
  const [campaigns, setCampaigns] = useState([]);
  const [campaignId, setCampaignId] = useState(getInitialCampaignId);
  const [campaign, setCampaign] = useState(null);
  const [target, setTarget] = useState(null);
  const [agents, setAgents] = useState([]);
  const [operations, setOperations] = useState([]);
  const [runs, setRuns] = useState([]);
  const [reports, setReports] = useState([]);
  const [library, setLibrary] = useState([]);
  const [selectedIds, setSelectedIds] = useState([]);
  const [techniqueInputs, setTechniqueInputs] = useState({});
  const [openInputIds, setOpenInputIds] = useState([]);
  const [activePanel, setActivePanel] = useState("overview");
  const [query, setQuery] = useState("");
  const [phaseFilter, setPhaseFilter] = useState("all");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [executionMode, setExecutionMode] = useState("real");
  const [selectedRun, setSelectedRun] = useState(null);
  const [selectedOperation, setSelectedOperation] = useState(null);
  const [expandedEvidenceKey, setExpandedEvidenceKey] = useState("");
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
    const cached = readDashboardCache();
    const [agentResult, operationResult, runResult, reportResult] = await Promise.allSettled([
      fetchJson("/agents"),
      fetchJson("/operations"),
      fetchJson("/runs"),
      fetchJson("/reports"),
    ]);
    const agentData = agentResult.status === "fulfilled" ? agentResult.value : { agents: cached.agents || [] };
    const operationData = operationResult.status === "fulfilled" ? operationResult.value : { operations: cached.operations || [] };
    const runData = runResult.status === "fulfilled" ? runResult.value : { runs: cached.runs || [] };
    const reportData = reportResult.status === "fulfilled" ? reportResult.value : { reports: cached.reports || [] };

    setAgents(agentData.agents || []);
    setOperations(operationData.operations || []);
    setRuns(runData.runs || []);
    setReports(reportData.reports || []);
    writeDashboardCache({
      agents: agentData.agents || [],
      operations: operationData.operations || [],
      runs: runData.runs || [],
      reports: reportData.reports || [],
    });

    const failed = [agentResult, operationResult, runResult, reportResult].some((result) => result.status === "rejected");
    if (failed) {
      setNotice("API 연결이 불안정해서 마지막으로 불러온 기록을 표시합니다.");
    }

    return {
      agents: agentData.agents || [],
      operations: operationData.operations || [],
      runs: runData.runs || [],
      reports: reportData.reports || [],
    };
  }

  async function loadCampaign(nextCampaignId) {
    setError("");
    setNotice("");

    const cached = readDashboardCache();
    const cachedCampaigns = cached.campaignsById || {};
    const cachedTargets = cached.targetsById || {};
    const [campaignResult, targetResult] = await Promise.allSettled([
      fetchJson(`/campaigns/${nextCampaignId}`),
      fetchJson(`/targets/${nextCampaignId}`),
    ]);

    if (campaignResult.status === "rejected" && targetResult.status === "rejected") {
      const cachedCampaign = cachedCampaigns[nextCampaignId];
      const cachedTarget = cachedTargets[nextCampaignId];
      if (!cachedCampaign && !cachedTarget) throw campaignResult.reason;

      setCampaign(cachedCampaign || null);
      setTarget(cachedTarget || null);
      setCampaignId(nextCampaignId);
      setSourceFilter(nextCampaignId);
      syncCampaignUrl(nextCampaignId);
      setSelectedRun(null);
      setSelectedOperation(null);
      setNotice("API 연결이 불안정해서 마지막으로 불러온 캠페인 정보를 표시합니다.");
      return;
    }

    const campaignData = campaignResult.status === "fulfilled" ? campaignResult.value : cachedCampaigns[nextCampaignId];
    const targetData = targetResult.status === "fulfilled" ? targetResult.value : cachedTargets[nextCampaignId];

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
    syncCampaignUrl(nextCampaignId);
    setSelectedRun(null);
    setSelectedOperation(null);
    writeDashboardCache({
      campaignId: nextCampaignId,
      campaignsById: {
        ...cachedCampaigns,
        [nextCampaignId]: campaignData,
      },
      targetsById: {
        ...cachedTargets,
        [nextCampaignId]: targetData,
      },
    });
  }

  useEffect(() => {
    let ignore = false;

    async function boot() {
      const cached = readDashboardCache();
      const urlCampaignId = getUrlCampaignId();
      const bootCampaignId = urlCampaignId || cached.campaignId || campaignId;

      if (cached.health) setHealth(cached.health);
      if (cached.campaigns) setCampaigns(cached.campaigns);
      if (cached.library) setLibrary(cached.library);
      if (cached.agents) setAgents(cached.agents);
      if (cached.operations) setOperations(cached.operations);
      if (cached.runs) setRuns(cached.runs);
      if (cached.reports) setReports(cached.reports);
      if (cached.campaignsById?.[bootCampaignId]) setCampaign(cached.campaignsById[bootCampaignId]);
      if (cached.targetsById?.[bootCampaignId]) setTarget(cached.targetsById[bootCampaignId]);
      setCampaignId(bootCampaignId);
      setSourceFilter(bootCampaignId);
      syncCampaignUrl(bootCampaignId);

      try {
        setError("");
        const [healthResult, campaignListResult, techniqueResult] = await Promise.allSettled([
          fetchJson("/health"),
          fetchJson("/campaigns"),
          fetchJson("/techniques"),
        ]);

        if (ignore) return;

        const healthData = healthResult.status === "fulfilled" ? healthResult.value : cached.health;
        const campaignListData = campaignListResult.status === "fulfilled" ? campaignListResult.value : { campaigns: cached.campaigns || [] };
        const techniqueData = techniqueResult.status === "fulfilled" ? techniqueResult.value : { techniques: cached.library || [] };

        setHealth(healthData);
        setCampaigns(campaignListData.campaigns || []);
        setLibrary(techniqueData.techniques || []);
        writeDashboardCache({
          health: healthData,
          campaigns: campaignListData.campaigns || [],
          library: techniqueData.techniques || [],
          campaignId: bootCampaignId,
        });
        await refreshRuntime();
        await loadCampaign(bootCampaignId);
        if ([healthResult, campaignListResult, techniqueResult].some((result) => result.status === "rejected")) {
          setNotice("API 연결이 불안정해서 마지막으로 불러온 데이터를 함께 표시합니다.");
        }
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
      const basePosition = asset.position || ASSET_POSITIONS[id] || {
        left: 12 + (index % 4) * 22,
        top: 24 + Math.floor(index / 4) * 28,
      };
      return {
        ...asset,
        asset_id: id,
        agent,
        agentStatus: asset.agent_required ? (agent?.status || "offline") : "observe",
        position: getMapPositionOverride(target?.target_id || campaignId, id, basePosition),
      };
    });
  }, [target, campaignId, agentByAsset]);

  const assetPositionById = useMemo(() => {
    const map = new Map();
    assets.forEach((asset) => {
      const position = asset.position;
      map.set(asset.asset_id, {
        ...position,
        top: Math.max(8, Number(position?.top || 0) - 7),
      });
    });
    return map;
  }, [assets]);

  const mapLinks = useMemo(() => {
    const configuredPaths = normalizeList(target?.attack_paths).filter(shouldShowMapPath);
    const displayPaths = configuredPaths.length > 0
      ? configuredPaths
      : assets.slice(0, -1).map((asset, index) => ({
        source_asset_id: asset.asset_id,
        target_asset_id: assets[index + 1]?.asset_id,
        label: "Default topology flow",
      }));

    return displayPaths.map((path, index) => {
      const sourceId = String(path.source_asset_id || "").toLowerCase();
      const targetId = String(path.target_asset_id || "").toLowerCase();
      const source = assetPositionById.get(sourceId);
      const destination = assetPositionById.get(targetId);

      if (!source || !destination) return null;

      if (sourceId === targetId) {
        const x = source.left;
        const y = source.top;
        return {
          id: `${sourceId}-${targetId}-${index}`,
          sourceId,
          targetId,
          label: path.label,
          tone: ["red", "blue", "amber"][index % 3],
          d: `M ${x} ${y} C ${x + 6} ${y - 12}, ${x + 18} ${y - 10}, ${x + 14} ${y + 2}`,
        };
      }

      const deltaX = destination.left - source.left;
      const directionX = deltaX >= 0 ? 1 : -1;
      const edgeOffset = Math.min(8, Math.max(4, Math.abs(deltaX) * 0.28));
      const start = {
        left: source.left + directionX * edgeOffset,
        top: source.top - 3.5,
      };
      const end = {
        left: destination.left - directionX * edgeOffset,
        top: destination.top - 3.5,
      };
      const laneTop = Math.max(9, Math.min(start.top, end.top) - 10 - (index % 2) * 4);
      return {
        id: `${sourceId}-${targetId}-${index}`,
        sourceId,
        targetId,
        label: path.label,
        tone: ["red", "blue", "amber"][index % 3],
        d: `M ${start.left} ${start.top} C ${start.left} ${laneTop}, ${end.left} ${laneTop}, ${end.left} ${end.top}`,
      };
    }).filter(Boolean);
  }, [target, assets, assetPositionById]);

  const mapZones = useMemo(() => {
    const segments = normalizeList(target?.segments);
    if (segments.length === 0) {
      return [
        { segment_id: "attacker-zone", name: "Attacker", left: 2, width: 20 },
        { segment_id: "user-zone", name: "User", left: 24, width: 22 },
        { segment_id: "server-zone", name: "Server", left: 49, width: 22 },
        { segment_id: "domain-zone", name: "Domain", left: 74, width: 22 },
      ];
    }

    const width = 96 / segments.length;
    return segments.map((segment, index) => ({
      segment_id: segment.segment_id || `segment-${index}`,
      name: segment.name || segment.segment_id || `Segment ${index + 1}`,
      left: 2 + index * width,
      width: Math.max(12, width - 1),
    }));
  }, [target]);

  const selectedSteps = useMemo(() => {
    const byId = new Map();
    library.forEach((step) => byId.set(getStepSelectionId(step, campaignId), step));
    normalizeList(campaign?.flow).forEach((step) => byId.set(getStepSelectionId(step, campaignId), step));
    return selectedIds.map((id) => byId.get(id)).filter(Boolean);
  }, [library, campaign, campaignId, selectedIds]);

  const stepLookup = useMemo(() => {
    const byId = new Map();
    const byCampaignOrder = new Map();

    [...library, ...normalizeList(campaign?.flow)].forEach((step) => {
      const sourceId = getStepSourceId(step, campaignId);
      const selectionId = getStepSelectionId(step, campaignId);
      byId.set(selectionId, step);
      byCampaignOrder.set(`${sourceId}:${step.order}`, step);
    });

    return { byId, byCampaignOrder };
  }, [library, campaign, campaignId]);

  const dependencyIdsBySelectedId = useMemo(() => {
    const map = new Map();

    function collectDependencySteps(step) {
      const sourceId = getStepSourceId(step, campaignId);
      const collected = [];
      const visited = new Set();

      function visit(currentStep) {
        normalizeList(currentStep?.depends_on_orders).forEach((order) => {
          const key = `${sourceId}:${order}`;
          if (visited.has(key)) return;
          visited.add(key);

          const dependencyStep = stepLookup.byCampaignOrder.get(key);
          if (!dependencyStep) return;

          visit(dependencyStep);
          collected.push(dependencyStep);
        });
      }

      visit(step);
      return collected;
    }

    selectedIds.forEach((selectionId) => {
      const step = stepLookup.byId.get(selectionId);
      if (!step) return;
      collectDependencySteps(step).forEach((dependencyStep) => {
        map.set(getStepSelectionId(dependencyStep, campaignId), selectionId);
      });
    });

    return map;
  }, [selectedIds, stepLookup, campaignId]);

  const campaignOperations = useMemo(() => (
    operations.filter((operation) => !operation.campaign_id || operation.campaign_id === campaignId)
  ), [operations, campaignId]);
  const campaignRuns = useMemo(() => (
    runs.filter((run) => !run.campaign_id || run.campaign_id === campaignId)
  ), [runs, campaignId]);
  const campaignReports = useMemo(() => (
    reports.filter((report) => !report.campaign_id || report.campaign_id === campaignId)
  ), [reports, campaignId]);
  const operationById = useMemo(() => {
    const map = new Map();
    campaignOperations.forEach((operation) => {
      if (operation.operation_id) map.set(operation.operation_id, operation);
    });
    return map;
  }, [campaignOperations]);
  const liveOperation = useMemo(() => (
    campaignOperations.find(isLiveOperation) || null
  ), [campaignOperations]);
  const representativeReport = useMemo(() => (
    [...campaignReports].sort((left, right) => (
      reportScore(right) - reportScore(left)
      || reportDetectionCoverage(right) - reportDetectionCoverage(left)
      || reportGeneratedTime(right) - reportGeneratedTime(left)
    ))[0] || null
  ), [campaignReports]);
  const representativeOperation = representativeReport?.source_id
    ? operationById.get(representativeReport.source_id) || null
    : null;
  const latestOperation = selectedRun ? null : (
    selectedOperation || liveOperation || representativeOperation || campaignOperations[0] || null
  );
  const canCancelLatestOperation = Boolean(
    latestOperation?.operation_id && ["pending", "queued", "running"].includes(latestOperation.status),
  );
  const latestRun = selectedRun || campaignRuns[0] || null;
  const operationSteps = normalizeList(latestOperation?.final_steps || latestOperation?.steps);
  const shouldShowOperationTimeline = Boolean(
    selectedOperation || (latestOperation?.operation_id && ["pending", "queued", "running"].includes(latestOperation.status)),
  );
  const timelineOperationSteps = shouldShowOperationTimeline ? operationSteps : [];
  const evidenceSteps = operationSteps.length > 0 ? operationSteps : normalizeList(latestRun?.steps);
  const scoredEvidenceSteps = evidenceSteps.filter(isScoredStep);
  const visibleSteps = timelineOperationSteps.length > 0 ? timelineOperationSteps : selectedSteps;
  const runningStep = timelineOperationSteps.find((step) => step.status === "running")
    || timelineOperationSteps.find((step) => step.status === "queued")
    || null;
  const activeAssetId = runningStep ? getStepAssetId(runningStep) : (isRunning && selectedSteps[0] ? getStepAssetId(selectedSteps[0]) : "");
  const completedCount = timelineOperationSteps.filter((step) => ["completed", "success", "simulated"].includes(step.status)).length;
  const totalOperationSteps = shouldShowOperationTimeline
    ? (latestOperation?.summary?.total || timelineOperationSteps.length)
    : selectedSteps.length;
  const requiredAssets = assets.filter((asset) => asset.agent_required);
  const onlineRequiredAssets = requiredAssets.filter((asset) => asset.agentStatus === "online");
  const detectionCounts = scoredEvidenceSteps.reduce((counts, step) => {
    const status = getDetectionStatus(step);
    return { ...counts, [status]: (counts[status] || 0) + 1 };
  }, {});
  const stepStatusSummary = summarizeStepStatuses(scoredEvidenceSteps);
  const operationSummary = evidenceSteps.length > 0 ? stepStatusSummary : (latestOperation?.summary || stepStatusSummary);
  const operationReport = latestOperation?.report
    || (latestOperation?.operation_id
      ? campaignReports.find((report) => report.source_id === latestOperation.operation_id)
      : null);
  const latestReport = operationReport || representativeReport || campaignReports[0] || reports[0] || null;
  const reportSummary = latestReport?.summary || {};
  const selectedOperationKey = latestOperation?.operation_id || "";
  const operationSelectOptions = useMemo(() => {
    const options = campaignOperations.slice(0, 12);
    if (!latestOperation?.operation_id) return options;
    if (options.some((operation) => operation.operation_id === latestOperation.operation_id)) return options;
    return [latestOperation, ...options];
  }, [campaignOperations, latestOperation]);
  const resultExecutionMode = latestOperation?.status === "simulated"
    ? "simulation"
    : (latestOperation?.execution_mode || executionMode);
  const executionTotal = operationSummary.total || scoredEvidenceSteps.length || selectedSteps.filter(isScoredStep).length || 0;
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

  useEffect(() => {
    setExpandedEvidenceKey("");
  }, [selectedOperationKey, selectedRun?.execution_id]);

  useEffect(() => {
    if (!target || library.length === 0) return;

    const byId = new Map();
    library.forEach((step) => byId.set(getStepSelectionId(step, campaignId), step));
    normalizeList(campaign?.flow).forEach((step) => byId.set(getStepSelectionId(step, campaignId), step));

    setSelectedIds((currentIds) => currentIds.filter((id) => {
      const step = byId.get(id);
      return step && getStepCompatibility(step, target, campaignId).compatible;
    }));
  }, [target, library, campaign, campaignId]);

  const filteredLibrary = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return library.filter((step) => {
      const selectionId = getStepSelectionId(step, campaignId);
      const isSelected = selectedIds.includes(selectionId);
      const sourceId = getStepSourceId(step, campaignId);
      const haystack = `${step.name || ""} ${step.technique_id || ""} ${step.params?.behavior || ""}`.toLowerCase();
      const matchesSource = sourceFilter === "all" || sourceId === sourceFilter;
      const matchesPhase = phaseFilter === "all" || (step.phase || "attack") === phaseFilter;
      const matchesQuery = !normalizedQuery || haystack.includes(normalizedQuery);
      return isSelected || (matchesSource && matchesPhase && matchesQuery);
    }).sort((left, right) => {
      const leftCompatibility = getStepCompatibility(left, target, campaignId);
      const rightCompatibility = getStepCompatibility(right, target, campaignId);
      if (leftCompatibility.compatible !== rightCompatibility.compatible) {
        return leftCompatibility.compatible ? -1 : 1;
      }

      const leftSource = getStepSourceId(left, campaignId);
      const rightSource = getStepSourceId(right, campaignId);
      if (leftSource === campaignId && rightSource !== campaignId) return -1;
      if (leftSource !== campaignId && rightSource === campaignId) return 1;
      if (leftSource !== rightSource) return leftSource.localeCompare(rightSource);
      return (left.order || 0) - (right.order || 0);
    });
  }, [library, target, campaignId, query, phaseFilter, sourceFilter, selectedIds]);
  const libraryEmptyMessage = error
    ? `Technique 데이터를 불러오지 못했습니다: ${error}`
    : library.length === 0
      ? "Technique 데이터가 아직 로드되지 않았습니다. API 서버 연결을 확인해 주세요."
      : "조건에 맞는 Technique이 없습니다.";

  const sourceOptions = useMemo(() => (
    Array.from(new Set(library.map((step) => getStepSourceId(step, campaignId)))).sort()
  ), [library, campaignId]);

  const selectableFilteredSelectionIds = useMemo(() => (
    filteredLibrary
      .filter((step) => getStepCompatibility(step, target, campaignId).compatible)
      .map((step) => getStepSelectionId(step, campaignId))
  ), [filteredLibrary, target, campaignId]);
  const filteredSelectionIds = selectableFilteredSelectionIds;

  const selectedFilteredCount = useMemo(() => (
    selectableFilteredSelectionIds.filter((id) => selectedIds.includes(id)).length
  ), [selectableFilteredSelectionIds, selectedIds]);
  const safetySummary = useMemo(() => summarizeSafetyProfiles(selectedSteps), [selectedSteps]);
  const successfulRuns = useMemo(() => campaignRuns.filter(hasSuccessfulStep), [campaignRuns]);
  const successfulOperations = useMemo(() => campaignOperations.filter((operation) => (
    hasSuccessfulStep(operation) || (operation.summary?.success || operation.summary?.completed || 0) > 0
  )), [campaignOperations]);

  function getDependencyStepsForStep(step) {
    const sourceId = getStepSourceId(step, campaignId);
    const collected = [];
    const visited = new Set();

    function visit(currentStep) {
      normalizeList(currentStep?.depends_on_orders).forEach((order) => {
        const key = `${sourceId}:${order}`;
        if (visited.has(key)) return;
        visited.add(key);

        const dependencyStep = stepLookup.byCampaignOrder.get(key);
        if (!dependencyStep) return;

        visit(dependencyStep);
        collected.push(dependencyStep);
      });
    }

    visit(step);
    return collected;
  }

  function expandSelectionIdsWithDependencies(selectionIds) {
    const expandedIds = [];

    selectionIds.forEach((selectionId) => {
      const step = stepLookup.byId.get(selectionId);
      if (!step) return;

      [...getDependencyStepsForStep(step), step].forEach((candidateStep) => {
        const candidateId = getStepSelectionId(candidateStep, campaignId);
        if (!expandedIds.includes(candidateId)) expandedIds.push(candidateId);
      });
    });

    return expandedIds;
  }

  function toggleStep(step) {
    const compatibility = getStepCompatibility(step, target, campaignId);
    if (!compatibility.compatible) {
      setNotice(compatibility.reason);
      return;
    }

    const selectionId = getStepSelectionId(step, campaignId);
    setSelectedIds((currentIds) => {
      if (currentIds.includes(selectionId)) {
        if (dependencyIdsBySelectedId.has(selectionId)) {
          setNotice("다른 선택 항목의 선행 조건입니다. 먼저 해당 공격 Technique을 해제해 주세요.");
          return currentIds;
        }

        setTechniqueInputs((currentInputs) => {
          const nextInputs = { ...currentInputs };
          delete nextInputs[selectionId];
          return nextInputs;
        });
        setOpenInputIds((current) => current.filter((id) => id !== selectionId));
        return currentIds.filter((id) => id !== selectionId);
      }

      const dependencySteps = getDependencyStepsForStep(step).filter((dependencyStep) => (
        getStepCompatibility(dependencyStep, target, campaignId).compatible
      ));
      const nextIds = [...currentIds];

      [...dependencySteps, step].forEach((candidateStep) => {
        const candidateId = getStepSelectionId(candidateStep, campaignId);
        if (!nextIds.includes(candidateId)) nextIds.push(candidateId);
      });

      if (dependencySteps.length > 0) {
        setNotice(`선행 Technique ${dependencySteps.length}개를 Queue에 함께 추가했습니다.`);
      }

      return nextIds;
    });
  }

  function selectFilteredTechniques() {
    setSelectedIds((currentIds) => {
      const nextIds = [...currentIds];
      expandSelectionIdsWithDependencies(selectableFilteredSelectionIds).forEach((id) => {
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

      if (isOperationSettled(operation) && ["completed", "simulated"].includes(operation.status)) {
        setNotice(operation.status === "simulated" ? "시뮬레이션으로 완료되었습니다." : "검증 런이 완료되었습니다.");
        await refreshRuntime();
        const latest = await fetchJson(`/operations/${operationId}`);
        setSelectedOperation(latest);
        return;
      }

      if (isOperationSettled(operation) && operation.status === "cancelled") {
        setNotice("런 취소 요청이 반영되었습니다.");
        await refreshRuntime();
        return;
      }

      if (isOperationSettled(operation) && ["blocked", "failed"].includes(operation.status)) {
        await refreshRuntime();
        throw new Error(`Operation ${operation.status}`);
      }

      const success = operation.summary?.success || 0;
      const total = operation.summary?.total || 0;
      const validationStatus = operation.elk_validation_status;
      if (["waiting", "running"].includes(validationStatus)) {
        setNotice(`ELK 검증 중: ${success}/${total} 실행 완료`);
      } else if (operation.status === "completed" && !operation.report && !operation.report_error) {
        setNotice(`리포트 생성 중: ${success}/${total} 실행 완료`);
      } else {
        setNotice(`런 진행 중: ${success}/${total} 완료`);
      }
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

  async function cancelOperationStep(stepIndex, operationId = latestOperation?.operation_id) {
    if (!operationId) return;

    try {
      setError("");
      const response = await fetchJson(`/operations/${operationId}/steps/${stepIndex}/cancel`, { method: "POST" });
      const operation = response.operation || response;
      setSelectedOperation(operation);
      setNotice("선택한 Technique을 이번 런에서 제외했습니다.");
      await refreshRuntime();
    } catch (err) {
      setError(err.message);
    }
  }

  async function chooseOperation(operationId) {
    if (!operationId) {
      setSelectedOperation(null);
      return;
    }

    try {
      const operation = await fetchJson(`/operations/${operationId}`);
      if (operation.campaign_id && operation.campaign_id !== campaignId) {
        await loadCampaign(operation.campaign_id);
      }
      setSelectedOperation(operation);
      setSelectedRun(null);
      setActivePanel("evidence");
    } catch (err) {
      const cachedOperation = operations.find((operation) => operation.operation_id === operationId);
      if (cachedOperation) {
        if (cachedOperation.campaign_id && cachedOperation.campaign_id !== campaignId) {
          await loadCampaign(cachedOperation.campaign_id);
        }
        setSelectedOperation(cachedOperation);
        setSelectedRun(null);
        setActivePanel("evidence");
        setNotice("API 연결이 불안정해서 저장된 Operation 기록을 표시합니다.");
        return;
      }
      setError(err.message);
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
      setSelectedOperation(null);
      setActivePanel("evidence");
    } catch (err) {
      const cachedRun = runs.find((run) => run.execution_id === executionId);
      if (cachedRun) {
        setSelectedRun(cachedRun);
        setSelectedOperation(null);
        setActivePanel("evidence");
        setNotice("API 연결이 불안정해서 저장된 실행 기록을 표시합니다.");
        return;
      }
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
            <div><span>BAS Agents</span><strong>{onlineRequiredAssets.length}/{requiredAssets.length}</strong></div>
            <div><span>Queue</span><strong>{selectedSteps.length}</strong></div>
            <div><span>Operations</span><strong>{campaignOperations.length}</strong></div>
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
              <option value="all">전체 캠페인</option>
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
              <strong>{selectedFilteredCount}/{selectableFilteredSelectionIds.length}</strong>
            </div>
            <button type="button" className="secondary-button" onClick={runQueue} disabled={isRunning || selectedSteps.length === 0}>
              {isRunning ? "실행 중" : "선택 실행"}
            </button>
          </div>
          <div className="library-bulk-actions">
            <button type="button" className="ghost-button" onClick={selectFilteredTechniques} disabled={selectableFilteredSelectionIds.length === 0 || selectedFilteredCount === selectableFilteredSelectionIds.length}>
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
              const autoIncluded = selected && dependencyIdsBySelectedId.has(selectionId);
              const phase = step.phase || "attack";
              const safety = getSafetyProfile(step);
              const compatibility = getStepCompatibility(step, target, campaignId);
              return (
                <button
                  key={selectionId}
                  type="button"
                  className={`technique-card ${phase} ${selected ? "selected" : ""} ${autoIncluded ? "auto-included" : ""} ${compatibility.compatible ? "" : "unavailable"}`}
                  onClick={() => toggleStep(step)}
                  disabled={!compatibility.compatible}
                  title={compatibility.compatible ? "" : compatibility.reason}
                >
                  <span className="phase-line">
                    <em>{phase === "normal" ? "Normal" : "Attack"}</em>
                    <b>{step.technique_id || "STEP"}</b>
                    {autoIncluded && <i className="dependency-badge">선행 조건</i>}
                    {!compatibility.compatible && <i className="unavailable-badge">적용 불가</i>}
                    {isSubTechnique(step) && <i className="subtechnique-badge">서브테크닉</i>}
                  </span>
                  <strong>{step.name}</strong>
                  <small>{getStepSourceId(step, campaignId)} · {getStepRole(step)}</small>
                  <span className={`safety-mini ${safety.className}`}>
                    영향도 {safety.impact} · {safety.executionRecommendation}
                  </span>
                  {!compatibility.compatible && <span className="compatibility-reason">{compatibility.reason}</span>}
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
          {selectedSteps.length > 0 && (
            <div className={`safety-summary ${safetySummary.highest?.className || "safe"}`}>
              <div>
                <span>실행 전 안전성</span>
                <strong>{safetySummary.highest?.executionRecommendation || "안전"}</strong>
              </div>
              <div className="safety-percent-summary">
                <span>추정 장애 {safetySummary.maxServiceImpactPercent}%</span>
                <span>추정 지연 {safetySummary.maxNetworkImpactPercent}%</span>
              </div>
              <div className="safety-counts">
                <b className="danger">위험 {safetySummary.danger}</b>
                <b className="warn">주의 {safetySummary.warn}</b>
                <b className="safe">안전 {safetySummary.safe}</b>
              </div>
            </div>
          )}
          <div className="queue-stack">
            {selectedSteps.map((step, index) => {
              const selectionId = getStepSelectionId(step, campaignId);
              const inputDefs = normalizeList(step.inputs);
              const isOpen = openInputIds.includes(selectionId);
              const safety = getSafetyProfile(step);
              const autoIncluded = dependencyIdsBySelectedId.has(selectionId);
              return (
                <div key={selectionId} className={`queue-card ${autoIncluded ? "auto-included" : ""}`}>
                  <div className="queue-card-head">
                    <span>{index + 1}</span>
                    <div>
                      <strong>
                        {getTechniqueLabel(step)}
                        {autoIncluded && <i className="dependency-badge inline">선행 조건</i>}
                        {isSubTechnique(step) && <i className="subtechnique-badge inline">서브테크닉</i>}
                      </strong>
                      <small>{getStepAssetId(step).toUpperCase()} · {getStepRole(step)}</small>
                    </div>
                  </div>
                  <div className={`safety-strip ${safety.className}`}>
                    <span><small>영향</small><strong>{getImpactLabel(safety.impact)}</strong></span>
                    <span><small>장애</small><strong>{safety.serviceImpactPercent}%</strong></span>
                    <span><small>지연</small><strong>{safety.networkImpactPercent}%</strong></span>
                    <b>{getRecommendationShort(safety.executionRecommendation)}</b>
                  </div>
                  <div className="safety-risk-bars" aria-label="추정 영향도">
                    <span>
                      <small>서비스 장애/다운 추정</small>
                      <i><b style={{ width: `${safety.serviceImpactPercent}%` }} /></i>
                      <strong>{safety.serviceImpactPercent}%</strong>
                    </span>
                    <span>
                      <small>네트워크 지연 추정</small>
                      <i><b style={{ width: `${safety.networkImpactPercent}%` }} /></i>
                      <strong>{safety.networkImpactPercent}%</strong>
                    </span>
                  </div>
                  <details className="safety-details">
                    <summary>세부 안전성</summary>
                    <div className={`safety-checklist ${safety.className}`}>
                      <div><span>시스템 영향도</span><strong>{safety.impact}</strong></div>
                      <div><span>장애 가능성</span><strong>{safety.failurePossibility}</strong></div>
                      <div><span>네트워크 부하</span><strong>{safety.networkLoad}</strong></div>
                      <div><span>서비스 다운</span><strong>{safety.serviceDownPossibility}</strong></div>
                      <div><span>장애/다운 추정</span><strong>{safety.serviceImpactPercent}%</strong></div>
                      <div><span>네트워크 지연 추정</span><strong>{safety.networkImpactPercent}%</strong></div>
                      <div><span>사전 경고</span><strong>{safety.warningRequired}</strong></div>
                      <div><span>실행 권장</span><strong>{safety.executionRecommendation}</strong></div>
                    </div>
                  </details>
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
                    <button
                      type="button"
                      className="queue-arrow-button"
                      onClick={() => moveStep(selectionId, -1)}
                      disabled={index === 0}
                      aria-label="위로 이동"
                      title="위로 이동"
                    >
                      ↑
                    </button>
                    <button
                      type="button"
                      className="queue-arrow-button"
                      onClick={() => moveStep(selectionId, 1)}
                      disabled={index === selectedSteps.length - 1}
                      aria-label="아래로 이동"
                      title="아래로 이동"
                    >
                      ↓
                    </button>
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
          <strong>{latestOperation?.operation_id || selectedRun?.execution_id || latestRun?.execution_id || "선택된 결과 없음"}</strong>
        </div>
        <label className="result-select-field">
          <span>결과 선택</span>
          <select value={selectedOperationKey} onChange={(event) => chooseOperation(event.target.value)}>
            <option value="">대표 결과</option>
            {operationSelectOptions.map((operation) => (
              <option key={operation.operation_id} value={operation.operation_id}>
                {operation.operation_id} · {operation.campaign_id} · {getStatusLabel(operation.status)}
              </option>
            ))}
          </select>
        </label>
        <div className="evidence-callout">
          <span>대표/선택 결과</span>
          <strong>{latestOperation?.status ? getStatusLabel(latestOperation.status) : selectedRun ? "이전 실행 기록" : "Operation 선택 전"}</strong>
          <small>
            {resultExecutionMode === "simulation"
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
        {latestReport?.report_id && (
          <div className="report-card">
            <span>Report</span>
            <strong>{latestReport.report_id}</strong>
            <small>
              Score {reportSummary.final_score ?? "-"} · Detection {formatCoverage(reportSummary.detection_coverage)}
            </small>
            <a
              className="artifact-link"
              href={`${API_BASE}/reports/${latestReport.report_id}/summary.html`}
              target="_blank"
              rel="noreferrer"
            >
              Summary 열기
            </a>
          </div>
        )}
        <div className="run-list operation-list">
          {successfulOperations.length > 0 && (
            <>
              <div className="record-section-title">
                <span>성공 Operation</span>
                <strong>{successfulOperations.length}</strong>
              </div>
              {successfulOperations.slice(0, 4).map((operation) => (
                <button key={`success-${operation.operation_id}`} type="button" onClick={() => { setSelectedOperation(operation); setSelectedRun(null); }}>
                  <strong>{operation.operation_id}</strong>
                  <span>{operation.campaign_id} · {getStatusLabel(operation.status)} · 성공 {(operation.summary?.success || 0) + (operation.summary?.completed || 0)}</span>
                </button>
              ))}
            </>
          )}
          {successfulRuns.length > 0 && (
            <>
              <div className="record-section-title">
                <span>이전 성공 기록</span>
                <strong>{successfulRuns.length}</strong>
              </div>
              {successfulRuns.slice(0, 6).map((run) => {
                const runSummary = summarizeStepStatuses(run.steps);
                return (
                  <button key={`success-${run.execution_id}`} type="button" onClick={() => loadRun(run.execution_id)}>
                    <strong>{run.execution_id}</strong>
                    <span>{run.campaign_id} · 성공 {(runSummary.success || 0) + (runSummary.completed || 0)} · {run.started_at || "-"}</span>
                  </button>
                );
              })}
            </>
          )}
          <div className="record-section-title muted">
            <span>최근 Operation</span>
            <strong>{campaignOperations.length}</strong>
          </div>
          {campaignOperations.slice(0, 6).map((operation) => (
            <button key={operation.operation_id} type="button" onClick={() => { setSelectedOperation(operation); setSelectedRun(null); }}>
              <strong>{operation.operation_id}</strong>
              <span>{operation.campaign_id} · {getStatusLabel(operation.status)} · {operation.created_at || "-"}</span>
            </button>
          ))}
          {campaignOperations.length === 0 && <p className="empty">아직 Operation 기록이 없습니다.</p>}
        </div>
        <div className="run-list legacy-run-list">
          <div className="record-section-title muted">
            <span>이전 Runner 기록</span>
            <strong>{campaignRuns.length}</strong>
          </div>
          {campaignRuns.slice(0, 8).map((run) => (
            <button key={run.execution_id} type="button" onClick={() => loadRun(run.execution_id)}>
              <strong>{run.execution_id}</strong>
              <span>{run.campaign_id} · {run.started_at || "-"}</span>
            </button>
          ))}
          {campaignRuns.length === 0 && <p className="empty">아직 이전 Runner 기록이 없습니다.</p>}
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
          <div className={`toast ${getToastTone(error, notice)}`}>
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
              <defs>
                <marker
                  id="map-arrow"
                  viewBox="0 0 10 10"
                  refX="8.2"
                  refY="5"
                  markerWidth="8"
                  markerHeight="8"
                  orient="auto"
                  markerUnits="strokeWidth"
                >
                  <path d="M 2 2 L 8 5 L 2 8" />
                </marker>
              </defs>
              {mapLinks.length > 0 ? mapLinks.map((link) => {
                const isActiveLink = activeAssetId && [link.sourceId, link.targetId].includes(activeAssetId);
                return (
                  <path
                    key={link.id}
                    className={`map-link tone-${link.tone || "red"} ${isActiveLink ? "active-link" : ""}`}
                    d={link.d}
                    markerEnd="url(#map-arrow)"
                  />
                );
              }) : (
                <>
                  <path d="M12 50 L34 50" markerEnd="url(#map-arrow)" />
                  <path d="M34 50 L56 50" markerEnd="url(#map-arrow)" />
                </>
              )}
            </svg>

            {mapZones.map((zone) => (
              <div
                key={zone.segment_id}
                className="map-zone"
                style={{ left: `${zone.left}%`, width: `${zone.width}%` }}
              >
                {zone.name}
              </div>
            ))}

            {assets.map((asset) => {
              const isActive = activeAssetId === asset.asset_id;
              const isCompleted = timelineOperationSteps.some((step) => getStepAssetId(step) === asset.asset_id && ["completed", "success", "simulated"].includes(step.status));
              const logStatus = getLogCollectionStatus(asset);
              const nodeKind = getAssetNodeKind(asset);
              return (
                <button
                  key={asset.asset_id}
                  type="button"
                  className={[
                    "asset-node",
                    `node-${nodeKind}`,
                    `risk-${asset.criticality || "medium"}`,
                    `agent-${asset.agentStatus}`,
                    isActive ? "active" : "",
                    isCompleted ? "completed" : "",
                  ].join(" ")}
                  style={{ left: `${asset.position.left}%`, top: `${asset.position.top}%` }}
                  onClick={() => setNotice(`${asset.name || asset.asset_id}: ${asset.private_ip || asset.hostname || "수동 자산"} · ${asset.role || asset.segment_id || "역할 미정"}`)}
                >
                  <span className="node-ring" />
                  <span className="topology-device" aria-hidden="true">
                    {renderAssetOsMark(nodeKind)}
                  </span>
                  <strong>{asset.name || asset.asset_id}</strong>
                  <small className="asset-ip-label">{getAssetDisplayIp(asset)}</small>
                  <div className="asset-facts">
                    <span><b>IP</b>{getAssetDisplayIp(asset)}</span>
                    <span><b>OS</b>{asset.os || asset.platform || "N/A"}</span>
                    <span><b>Type</b>{asset.role || asset.segment_id || "N/A"}</span>
                  </div>
                  {normalizeList(asset.tags).length > 0 && (
                    <div className="asset-tags">
                      {normalizeList(asset.tags).slice(0, 4).map((tag) => (
                        <span key={`${asset.asset_id}-${tag}`}>{tag}</span>
                      ))}
                    </div>
                  )}
                  <div className="asset-state-row">
                    <em className="agent-pill" title={`BAS Agent ${getStatusLabel(asset.agentStatus)}`}>
                      <span className="agent-status-dot" aria-hidden="true" />
                      Agent {getStatusLabel(asset.agentStatus)}
                    </em>
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
            </div>
            <div className="timeline-list">
              {visibleSteps.map((step, index) => {
                const status = step.status || (selectedIds.includes(getStepSelectionId(step, campaignId)) ? "queued" : "planned");
                const canCancelStep = Boolean(latestOperation?.operation_id && ["pending", "queued"].includes(status));
                const isRunningStep = status === "running";
                return (
                  <div key={`${step.order}-${step.technique_id || index}`} className={`timeline-row ${status}`}>
                    <span>{String(index + 1).padStart(2, "0")}</span>
                    <div>
                      <strong>{getTechniqueLabel(step)}</strong>
                      <small>{getStepAssetId(step).toUpperCase()} · {getExecutionLabel(status)} · {getDetectionLabel(getDetectionStatus(step))}</small>
                    </div>
                    <button
                      type="button"
                      className="timeline-cancel-button"
                      onClick={() => cancelOperationStep(index)}
                      disabled={!canCancelStep}
                      title={isRunningStep ? "이미 Agent가 실행 중인 Technique은 여기서 중단할 수 없습니다." : "아직 실행되지 않은 Technique을 이번 런에서 제외"}
                    >
                      취소
                    </button>
                  </div>
                );
              })}
              {visibleSteps.length === 0 && <p className="empty">좌측에서 쿼리를 선택하면 런 순서가 여기에 표시됩니다.</p>}
            </div>
          </div>

          <div className="evidence-panel">
            <div className="panel-heading horizontal">
              <div>
                <span>Operation Result</span>
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
              {latestReport?.report_id && (
                <div>
                  <span>Report</span>
                  <strong>{reportSummary.final_score ?? "-"} / 100</strong>
                  <small>{latestReport.report_id}</small>
                  <a
                    className="artifact-link compact"
                    href={`${API_BASE}/reports/${latestReport.report_id}/summary.html`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    Summary 보기
                  </a>
                </div>
              )}
            </div>
            <div className="evidence-feed">
              {evidenceSteps.map((step, index) => {
                const detectionStatus = getDetectionStatus(step);
                const executionStatus = step.execution_status || step.status;
                const queries = getStepQueries(step);
                const hasQuery = queries.source || queries.alert;
                const coverageFields = getCoverageFields(step, detectionStatus);
                const evidenceKey = step.job_id || step.execution_id || `${step.order}-${step.technique_id || index}`;
                const isExpanded = expandedEvidenceKey === evidenceKey;
                const executionLabel = isNormalStep(step) ? "기준 성공" : getExecutionLabel(executionStatus);
                return (
                  <div key={evidenceKey} className={`evidence-row ${isExpanded ? "expanded" : ""}`}>
                    <button
                      type="button"
                      className="evidence-summary-button"
                      onClick={() => setExpandedEvidenceKey((current) => (current === evidenceKey ? "" : evidenceKey))}
                      aria-expanded={isExpanded}
                    >
                      <div className="result-pill-stack">
                        <span className={`execution-pill ${isNormalStep(step) ? "baseline" : executionStatus}`}>{executionLabel}</span>
                        <span className={`detection-pill ${detectionStatus}`}>{getDetectionLabel(detectionStatus)}</span>
                      </div>
                      <div className="evidence-summary-content">
                        <strong>{getTechniqueLabel(step)}</strong>
                        <small>{getStepAssetId(step).toUpperCase()} · {getStepEvidenceText(step)}</small>
                      </div>
                      <span className="evidence-toggle">{isExpanded ? "접기" : "상세"}</span>
                    </button>
                    {isExpanded && (
                      <div className="evidence-details">
                        <div className="coverage-stack">
                          {coverageFields.map(([label, value]) => (
                            <div key={`${step.order}-${label}`}>
                              <span>{label}</span>
                              <strong>{value || "-"}</strong>
                            </div>
                          ))}
                        </div>
                        <div className="query-stack">
                          {queries.source && (
                            <div>
                              <span>Source Query</span>
                              <code>{queries.source}</code>
                            </div>
                          )}
                          {queries.alert && (
                            <div>
                              <span>Alert Query</span>
                              <code>{queries.alert}</code>
                            </div>
                          )}
                          {!hasQuery && (
                            <div className="query-empty">
                              <span>Query</span>
                              <code>{executionStatus === "blocked" ? "Agent 실행 전 차단되어 ELK query가 수행되지 않았습니다." : "표시할 ELK query가 없습니다."}</code>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
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
