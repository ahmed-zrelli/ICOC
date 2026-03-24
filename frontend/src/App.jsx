/**
 * ICOC-Lite Dashboard — Member 3 (VOC / AI Module)
 * Covers: FR-VOC-01..07, FR-AI-01..07
 */
import { useState, useEffect, useCallback, useRef } from "react";

const API = "http://localhost:8000";

// ── Design tokens ─────────────────────────────────────────────────────────────
const THEME = {
  bg: "#0f172a", // Deep Slate
  card: "rgba(30, 41, 59, 0.7)", // Semi-transparent Slate
  border: "rgba(51, 65, 85, 0.5)",
  accent: "#0ea5e9", // Sky Blue
  critical: "#f43f5e", // Rose 500
  warning: "#f59e0b", // Amber 500
  healthy: "#10b981", // Emerald 500
  text: "#f1f5f9",
  subtext: "#94a3b8",
  glass: "backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);",
};

const SEV = { Critical: THEME.critical, High: "#fb923c", Medium: THEME.warning, Low: THEME.accent, Info: THEME.subtext, None: "#6366f1" };
const SEV_BG = { Critical: "rgba(244, 63, 94, 0.12)", High: "rgba(251, 146, 60, 0.12)", Medium: "rgba(245, 158, 11, 0.12)", Low: "rgba(14, 165, 233, 0.12)", Info: "rgba(148, 163, 184, 0.12)", None: "rgba(99, 102, 241, 0.12)" };
const STATUS_COLOR = { missing: THEME.critical, available: THEME.warning, scheduled: "#818cf8", applied: THEME.healthy, wontfix: THEME.subtext };
const EVT_ICONS = { ssh_brute_force:"🔨", ssh_failed_auth:"🔑", ssh_login_success:"🚨", port_scan_detected:"🔍", reverse_shell_detected:"💀", file_integrity_violation:"📝", suspicious_file_drop:"🦠", suspicious_process:"⚙️", cve_exploit_attempt:"💥", malware_dropped:"🦠", dos_started:"🌊", dos_attack:"🌊", heartbeat:"💓", unusual_outbound_connection:"📡", new_port_opened:"🔓", agent_started:"✅", sqli_attack:"💉", lfi_attack:"📂" };

// ── Data hooks ────────────────────────────────────────────────────────────────
function useApi(path, interval = 0) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const fetch_ = useCallback(async () => {
    try {
      const r = await fetch(API + path);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setData(await r.json()); setError(null);
    } catch (e) { setError(e.message); } finally { setLoading(false); }
  }, [path]);
  useEffect(() => {
    fetch_();
    if (interval > 0) { const id = setInterval(fetch_, interval); return () => clearInterval(id); }
  }, [fetch_, interval]);
  return { data, loading, error, refetch: fetch_ };
}

// FR-AI-04: Server-Sent Events hook
function useSSE(path) {
  const [data, setData]       = useState(null);
  const [connected, setCon]   = useState(false);
  useEffect(() => {
    const es = new EventSource(API + path);
    es.onopen    = () => setCon(true);
    es.onmessage = (e) => { try { setData(JSON.parse(e.data)); } catch {} };
    es.onerror   = () => setCon(false);
    return () => es.close();
  }, [path]);
  return { data, connected };
}

// ── UI components ─────────────────────────────────────────────────────────────
const GlassCard = ({ title, badge, children, style = {} }) => (
  <div style={{ 
    background: THEME.card, 
    border: `1px solid ${THEME.border}`, 
    borderRadius: 12, 
    padding: 20, 
    backdropFilter: "blur(12px)",
    WebkitBackdropFilter: "blur(12px)",
    boxShadow: "0 8px 32px 0 rgba(0, 0, 0, 0.3)",
    transition: "all 0.3s ease",
    ...style 
  }}>
    {(title || badge) && (
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
        {title && <span style={{ fontFamily: "Syne,sans-serif", fontSize: 12, fontWeight: 700, letterSpacing: "0.1em", color: THEME.accent, textTransform: "uppercase" }}>{title}</span>}
        {badge && <span style={{ fontSize: 10, padding: "4px 10px", borderRadius: 6, background: "rgba(14, 165, 233, 0.1)", border: `1px solid ${THEME.accent}44`, color: THEME.accent }}>{badge}</span>}
      </div>
    )}
    {children}
  </div>
);

const Skeleton = ({ width = "100%", height = 20, style = {} }) => (
  <div className="skeleton" style={{ width, height, borderRadius: 4, background: "rgba(51, 65, 85, 0.3)", ...style }} />
);

function GaugeRing({ score, color }) {
  const r = 54, circ = 2 * Math.PI * r;
  return (
    <div style={{ position:"relative", width:140, height:140, flexShrink:0 }}>
      <svg width="140" height="140" viewBox="0 0 120 120" style={{ transform:"rotate(-90deg)" }}>
        <circle cx="60" cy="60" r={r} fill="none" stroke="rgba(51, 65, 85, 0.3)" strokeWidth="10" />
        <circle cx="60" cy="60" r={r} fill="none" stroke={color} strokeWidth="12" strokeLinecap="round"
          strokeDasharray={circ} strokeDashoffset={circ - (score / 100) * circ}
          style={{ transition:"stroke-dashoffset 1.5s cubic-bezier(0.4, 0, 0.2, 1)" }} />
      </svg>
      <div style={{ position:"absolute", inset:0, display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center" }}>
        <span style={{ fontFamily:"Syne,sans-serif", fontSize:36, fontWeight:800, color, lineHeight:1 }}>{score}</span>
        <span style={{ fontSize:10, color:THEME.subtext, marginTop:4 }}>/ 100</span>
      </div>
    </div>
  );
}

const SevBadge = ({ sev }) => <span style={{ fontSize:9, fontWeight:700, letterSpacing:"0.05em", padding:"3px 8px", borderRadius:6, textTransform:"uppercase", background:SEV_BG[sev]||SEV_BG.None, color:SEV[sev]||SEV.None, border:`1px solid ${SEV[sev]||SEV.None}33` }}>{sev}</span>;
const StatusBadge = ({ status }) => <span style={{ fontSize:9, fontWeight:600, padding:"2px 8px", borderRadius:4, textTransform:"uppercase", color:STATUS_COLOR[status]||THEME.subtext, border:`1px solid ${STATUS_COLOR[status]||THEME.subtext}44` }}>{status}</span>;

function Sparkline({ data, width = 200, height = 40, color = THEME.accent }) {
  if (!data || data.length < 2) return <Skeleton width={width} height={height} />;
  const min = 0;
  const max = Math.max(...data.map(d => d.value), 10);
  const points = data.map((d, i) => {
    const x = (i / (data.length - 1)) * width;
    const y = height - ((d.value - min) / (max - min)) * height;
    return `${x},${y}`;
  }).join(" ");

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} style={{ overflow:"visible" }}>
      <defs>
        <linearGradient id={`grad-${color}`} x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor={color} stopOpacity="0.2" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <polyline fill="none" stroke={color} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" points={points} style={{ transition: "all 0.5s ease" }} />
      <path d={`M ${points} L ${width},${height} L 0,${height} Z`} fill={`url(#grad-${color})`} />
    </svg>
  );
}

function Card({ title, badge, children, style = {} }) {
  return <GlassCard title={title} badge={badge} style={style}>{children}</GlassCard>;
}

function KpiCard({ label, value, color, sub, trend }) {
  return (
    <div style={{ 
      background: THEME.card, 
      border: `1px solid ${THEME.border}`, 
      borderRadius: 12, 
      padding: "20px",
      backdropFilter: "blur(12px)",
      WebkitBackdropFilter: "blur(12px)",
      position: "relative",
      overflow: "hidden",
      minHeight: 130,
      display: "flex",
      flexDirection: "column",
      justifyContent: "space-between",
      transition: "transform 0.2s ease"
    }}>
      <div style={{ position: "absolute", top: 0, left: 0, width: "100%", height: 4, background: color, boxShadow: `0 2px 10px ${color}44` }} />
      <div>
        <div style={{ fontSize: 10, color: THEME.subtext, letterSpacing: "0.1em", marginBottom: 12, textTransform: "uppercase", fontWeight: 700, opacity: 0.8 }}>{label}</div>
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          <div style={{ fontFamily: "Syne,sans-serif", fontSize: 22, fontWeight: 900, color: THEME.text, lineHeight: 1.1, wordBreak: "break-word" }}>{value}</div>
          {trend && <span style={{ fontSize: 12, color: trend > 0 ? THEME.critical : THEME.healthy, fontWeight: 800, background: trend > 0 ? "rgba(244, 63, 94, 0.1)" : "rgba(16, 185, 129, 0.1)", padding: "2px 6px", borderRadius: 4 }}>{trend > 0 ? "↑" : "↓"}</span>}
        </div>
      </div>
      <div style={{ fontSize: 11, color: THEME.subtext, marginTop: 12, display: "flex", alignItems: "center", gap: 8, fontWeight: 600, borderTop: `1px solid ${THEME.border}`, paddingTop: 10 }}>
        <div style={{ width: 8, height: 8, borderRadius: "50%", background: color, boxShadow: `0 0 10px ${color}` }} />
        <span style={{ opacity: 0.9 }}>{sub}</span>
      </div>
    </div>
  );
}

const Th = ({ children }) => <th style={{ fontSize: 10, color: THEME.subtext, letterSpacing: "0.05em", textAlign: "left", padding: "12px 10px", borderBottom: `1px solid ${THEME.border}`, textTransform: "uppercase", fontWeight: 600 }}>{children}</th>;
const Td = ({ children, style = {} }) => <td style={{ padding: "12px 10px", fontSize: 12, color: THEME.text, ...style }}>{children}</td>;
const TR = ({ children, style = {} }) => <tr className="table-row" style={{ borderBottom: `1px solid rgba(51, 65, 85, 0.2)`, ...style }}>{children}</tr>;

const Spinner = () => (
  <div style={{ display: "flex", justifyContent: "center", alignItems: "center", padding: 60 }}>
    <div className="spinner" style={{ 
      width: 40, height: 40, border: `3px solid ${THEME.border}`, borderTop: `3px solid ${THEME.accent}`, 
      borderRadius: "50%", animation: "spin 1s linear infinite" 
    }} />
  </div>
);

const ErrorMsg = ({ msg }) => (
  <div style={{ 
    padding: 24, background: "rgba(244, 63, 94, 0.05)", border: `1px solid ${THEME.critical}33`, 
    borderRadius: 12, color: THEME.critical, display: "flex", alignItems: "center", gap: 16 
  }}>
    <span style={{ fontSize: 24 }}>⚠️</span>
    <div>
      <div style={{ fontWeight: 800, fontSize: 13, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 4 }}>System Error</div>
      <div style={{ fontSize: 12, opacity: 0.9, fontWeight: 500 }}>{msg}</div>
    </div>
  </div>
);

// ── Dashboard Tab ─────────────────────────────────────────────────────────────
function DashboardTab() {
  const { data, loading, error } = useApi("/dashboard", 10000);
  const { data: liveStats }      = useApi("/events/stats", 5000);
  const { 
    total_events: liveTotalEvt = 0, 
    severity_breakdown: { Critical: liveCritical = 0, High: liveHigh = 0 } = {}, 
    alert_count_5min: liveAlerts = 0, 
    incidents: liveIncidents = 0 
  } = liveStats || {};

  if (loading) return <div style={{ display:"grid", gap:24 }}><div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:16 }}>{[...Array(5)].map((_,i)=><Skeleton key={i} height={100}/>)}</div><Skeleton height={500}/></div>;
  if (error)   return <ErrorMsg msg={error} />;
  
  const { risk_score = { score: 0, level: "None", color: THEME.subtext, inputs: {}, breakdown: {} }, patch_summary = { patch_coverage_pct: 0, critical_missing: 0 }, recommendations = [], incident_prediction = { incident_probability_pct: 0 }, compliance = {} } = data || {};
  const cve_scores = Array.isArray(data?.cve_scores) ? data.cve_scores : (data?.cve_scores?.cves || []);

  return (
    <div style={{ display:"grid", gap:24 }}>
      {/* Top Bento Row */}
      <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:16 }}>
        <KpiCard label="Global Risk" value={risk_score.score} color={risk_score.color} sub={risk_score.level.toUpperCase()} />
        <KpiCard label="Patch Status" value={`${patch_summary.patch_coverage_pct}%`} color={THEME.healthy} sub="Fleet Coverage" />
        <KpiCard label="Critical CVEs" value={patch_summary.critical_missing} color={THEME.critical} sub="High Priority Fixes" />
        <KpiCard label="Threat Intel" value={data.threat_intel?.active_threats || 0} color={THEME.warning} sub="Live External TTPs" />
        <KpiCard label="Incident Prob" value={`${incident_prediction?.incident_probability_pct ?? 0}%`} color={THEME.accent} sub="Predictive Risk" />
      </div>

      {/* Live SOC strip — only when attacks are active */}
      {liveStats && (liveCritical + liveHigh + liveAlerts + liveIncidents > 0) && (
        <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:12, animation: "row-appear 0.4s ease" }}>
          {[
            ["SOC Total Events", liveTotalEvt, THEME.accent],
            ["Critical Hits", liveCritical, THEME.critical],
            ["High Severity", liveHigh, "#fb923c"],
            ["5m Frequency", liveAlerts, THEME.warning],
            ["Live Incidents", liveIncidents, THEME.critical]
          ].map(([label,val,color]) => (
            <div key={label} style={{ background: "rgba(255, 255, 255, 0.03)", border: `1px solid ${THEME.border}`, borderRadius:10, padding:"12px 16px", borderLeft:`4px solid ${color}` }}>
              <div style={{ fontSize:10, color: THEME.subtext, textTransform: "uppercase", fontWeight: 700, marginBottom:6 }}>{label}</div>
              <div style={{ fontFamily:"Syne,sans-serif", fontSize:24, fontWeight:800, color }}>{val}</div>
            </div>
          ))}
        </div>
      )}

      <div style={{ display:"grid", gridTemplateColumns:"1fr 340px", gap:24 }}>
        <div style={{ display:"grid", gap:24 }}>
          {/* Risk Engine Visualizer */}
          <GlassCard style={{ padding: 32, display:"grid", gridTemplateColumns:"180px 1fr", gap:40, alignItems:"center", borderLeft:`4px solid ${risk_score.color}` }}>
            <div style={{ display:"flex", justifyContent:"center" }}>
              <GaugeRing score={risk_score.score} color={risk_score.color} />
            </div>
            <div>
              <div style={{ fontSize:10, color: THEME.subtext, letterSpacing:"0.1em", fontWeight: 700, textTransform:"uppercase", marginBottom:8 }}>AI Cognitive Analysis</div>
              <h2 style={{ fontFamily:"Syne,sans-serif", fontSize:28, fontWeight:900, color: THEME.text, marginBottom:12 }}>{risk_score.level.toUpperCase()} THREAT VECTOR</h2>
              <p style={{ fontSize:14, color: THEME.subtext, lineHeight:1.6, marginBottom:24 }}>
                The heuristic engine has detected a {risk_score.level} risk environment. 
                Correlating <span style={{ color: THEME.accent, fontWeight:700 }}>{risk_score.inputs.soc_alerts} SOC alerts</span> 
                with <span style={{ color: THEME.critical, fontWeight:700 }}>{risk_score.inputs.critical_unpatched} unpatched critical CVEs</span>.
              </p>
              <div style={{ display:"flex", gap:16 }}>
                {Object.entries(risk_score.breakdown).map(([k,v]) => (
                  <div key={k} style={{ background:"rgba(255,255,255,0.03)", padding:"12px 16px", borderRadius:10, border:`1px solid ${THEME.border}` }}>
                    <div style={{ fontSize:9, color: THEME.subtext, textTransform:"uppercase", fontWeight: 700 }}>{k.split('_')[0]}</div>
                    <div style={{ fontSize:18, fontWeight: 800, color: THEME.text }}>{v}</div>
                  </div>
                ))}
              </div>
            </div>
          </GlassCard>

          {/* Catalog Table */}
          <Card title="◈ Critical Vulnerability Catalog" badge="TOP 10 PRIORITIES">
            <table style={{ width:"100%", borderCollapse:"collapse" }}>
              <thead><tr><Th>CVE Identifier</Th><Th>Base Score</Th><Th>Severity</Th><Th>Status</Th></tr></thead>
              <tbody>
                {cve_scores.slice(0, 10).map(cve => (
                  <TR key={cve.cve_id}>
                    <Td style={{ color: THEME.accent, fontWeight: 700 }}>{cve.cve_id}</Td>
                    <Td style={{ fontFamily: "JetBrains Mono", fontWeight: 800, fontSize: 14 }}>{cve.base_score}</Td>
                    <Td><SevBadge sev={cve.severity} /></Td>
                    <Td><StatusBadge status={cve.status || "missing"} /></Td>
                  </TR>
                ))}
              </tbody>
            </table>
          </Card>
        </div>

        {/* Intelligence column */}
        <div style={{ display:"grid", gap:24, alignContent:"start" }}>
          {/* AI Remediation */}
          <Card title="✦ AI Remediation" badge="FR-AI-07">
            <div style={{ display: "grid", gap: 12 }}>
              {recommendations?.slice(0, 4).map((rec, i) => (
                <div key={i} style={{ 
                  padding:16, background:"rgba(255,255,255,0.02)", borderRadius:12, 
                  borderLeft:`4px solid ${SEV[rec.severity] || THEME.accent}`,
                  border: `1px solid ${THEME.border}`,
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8, alignItems:"center" }}>
                    <div style={{ fontWeight:800, fontSize:13, color: THEME.text }}>{rec.action}</div>
                    <span style={{ fontSize:10, fontWeight:800, color: SEV[rec.severity] }}>PRIORITY {rec.priority}</span>
                  </div>
                  <div style={{ fontSize:12, color: THEME.subtext, lineHeight: 1.5 }}>{rec.detail}</div>
                  <div style={{ fontSize:10, color: THEME.accent, marginTop: 10, fontWeight: 700, letterSpacing:"0.05em" }}>EFFORT: {rec.estimated_effort.toUpperCase()}</div>
                </div>
              ))}
            </div>
          </Card>

          {/* Compliance Bento */}
          <Card title="⚖ Compliance Snapshot" badge="REAL-TIME">
            <div style={{ display:"grid", gap:16 }}>
              {compliance?.frameworks && Object.entries(compliance.frameworks).slice(0,2).map(([fw, d]) => (
                <div key={fw}>
                  <div style={{ display:"flex", justifyContent:"space-between", marginBottom:8, fontSize:12, fontWeight: 600 }}>
                    <span>{fw}</span>
                    <span style={{ color: d.overall_score_pct > 70 ? THEME.healthy : THEME.warning }}>{d.overall_score_pct}%</span>
                  </div>
                  <div style={{ height:6, background:"rgba(51, 65, 85, 0.3)", borderRadius:10 }}>
                    <div style={{ height:"100%", width:`${d.overall_score_pct}%`, background: d.overall_score_pct > 70 ? THEME.healthy : THEME.warning, borderRadius:10 }} />
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

// ── Scanner Tab — FR-VOC-05 ───────────────────────────────────────────────────
function ScannerTab() {
  const { data: patches, loading, error } = useApi("/voc/patches", 5000);
  const { data: scanStatus }              = useApi("/voc/scan/status", 2000);
  const [scanMsg, setScanMsg]             = useState(null);

  const scanning  = scanStatus?.running === true;
  const scanPct   = scanStatus?.pct   ?? 0;
  const scanStage = scanStatus?.stage ?? "";
  const lastResult = scanStatus?.last_result;

  const triggerScan = async () => {
    setScanMsg(null);
    try {
      const r = await fetch(API + "/voc/scan", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ enrich_vt:true }) });
      const d = await r.json();
      setScanMsg(d.message || "Scan started");
    } catch (e) { setScanMsg("Scan failed: " + e.message); }
  };

  if (loading) return <Spinner />;
  if (error)   return <ErrorMsg msg={error} />;

  const records = patches?.records || [];

  return (
    <div style={{ display:"grid", gap:24 }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
        <div>
          <h2 style={{ fontFamily:"Syne,sans-serif", fontSize:18, fontWeight: 800, color: THEME.text }}>Vulnerability Scanner</h2>
          <p style={{ fontSize:12, color: THEME.subtext, marginTop:4 }}>Comprehensive inventory analysis & CVSS v3.1 Matrix</p>
        </div>
        <button onClick={triggerScan} disabled={scanning} style={{ 
          fontFamily:"JetBrains Mono,monospace", fontSize:12, letterSpacing:"0.05em", padding:"10px 24px", borderRadius:8, border:"none", 
          cursor:scanning?"not-allowed":"pointer", background:scanning?"rgba(14, 165, 233, 0.2)":THEME.accent, color:scanning?THEME.accent:"#fff", 
          fontWeight:700, textTransform:"uppercase", animation:scanning?"pulse 1s ease-in-out infinite":"none",
          boxShadow: scanning ? "none" : `0 4px 14px ${THEME.accent}44`
        }}>
          {scanning ? `Scanning... ${scanPct}%` : "⬡ Run Full Scan"}
        </button>
      </div>

      {/* Real-time progress bar */}
      {scanning && (
        <GlassCard style={{ padding: 24, borderLeft: `4px solid ${THEME.accent}` }}>
          <div style={{ display:"flex", justifyContent:"space-between", marginBottom:12 }}>
            <span style={{ fontSize:13, color: THEME.accent, fontWeight: 700 }}>Scan in progress — {scanStage}</span>
            <span style={{ fontSize:13, color: THEME.text, fontWeight: 800 }}>{scanPct}%</span>
          </div>
          <div style={{ height:8, background:"rgba(51, 65, 85, 0.3)", borderRadius:10, overflow: "hidden" }}>
            <div style={{ height:"100%", width:`${scanPct}%`, background: THEME.accent, borderRadius:10, transition:"width 0.5s ease" }} />
          </div>
        </GlassCard>
      )}

      {scanMsg && (
        <div style={{ background: "rgba(14, 165, 233, 0.1)", border: `1px solid ${THEME.accent}33`, borderRadius:8, padding:"12px 16px", fontSize:12, color: THEME.accent, fontWeight: 600 }}>
          {scanMsg}
        </div>
      )}

      {/* Status counts Bento */}
      <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:16 }}>
        {Object.entries(patches?.by_status || {}).filter(([s]) => s !== "wontfix").map(([status, count]) => (
          <div key={status} style={{ 
            background: THEME.card, border: `1px solid ${THEME.border}`, borderRadius:12, padding:"16px 20px", 
            borderTop: `3px solid ${STATUS_COLOR[status]||THEME.subtext}`,
            backdropFilter: "blur(12px)"
          }}>
            <div style={{ fontSize:10, color: THEME.subtext, letterSpacing: "0.1em", marginBottom:8, textTransform:"uppercase", fontWeight: 700 }}>{status}</div>
            <div style={{ fontFamily:"Syne,sans-serif", fontSize:28, fontWeight:800, color: STATUS_COLOR[status]||THEME.subtext }}>{count}</div>
          </div>
        ))}
      </div>

      <Card title="◈ Infrastructure Vulnerabilities" badge={`${records.length} ASSETS`}>
        <table style={{ width:"100%", borderCollapse:"collapse" }}>
          <thead><tr><Th>CVE ID</Th><Th>Affected Host</Th><Th>Component</Th><Th>Current Ver.</Th><Th>Score</Th><Th>Severity</Th><Th>Status</Th></tr></thead>
          <tbody>
            {records.map((r, i) => (
              <TR key={i}>
                <Td style={{ color: THEME.accent, fontWeight: 700 }}>{r.cve_id}</Td>
                <Td style={{ color: THEME.text, fontSize:11 }}>
                  <div style={{ fontWeight: 600 }}>{r.hostname}</div>
                  <div style={{ color: THEME.subtext, fontSize: 10 }}>{r.host_ip}</div>
                </Td>
                <Td style={{ fontWeight: 500 }}>{r.package}</Td>
                <Td style={{ fontSize:11, color: THEME.subtext, fontFamily: "JetBrains Mono" }}>{r.current_version}</Td>
                <Td style={{ fontSize:14, fontWeight:800, color: SEV[r.severity] }}>{r.cvss_score}</Td>
                <Td><SevBadge sev={r.severity} /></Td>
                <Td><StatusBadge status={r.status} /></Td>
              </TR>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

// ── VirusTotal Tab ─────────────────────────────────────────────────────────────
function VTTab() {
  const [mode, setMode]       = useState("hash");
  const [input, setInput]     = useState("");
  const [result, setResult]   = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState(null);

  const ENDPOINTS    = { hash:"/vt/hash", ip:"/vt/ip", url:"/vt/url" };
  const FIELDS       = { hash:"hash", ip:"ip", url:"url" };
  const PLACEHOLDERS = { hash:"Enter SHA256 / MD5 / SHA1 hash...", ip:"Enter target IP address...", url:"Enter destination URL..." };

  const check = async () => {
    setLoading(true); setError(null); setResult(null);
    try {
      const r = await fetch(API + ENDPOINTS[mode], { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ [FIELDS[mode]]:input }) });
      setResult(await r.json());
    } catch (e) { setError(e.message); } finally { setLoading(false); }
  };

  const isMalicious = result && (result.malicious || 0) > 0;

  return (
    <div style={{ display:"grid", gap:24 }}>
      <Card title="⬡ Threat Intelligence Oracle" badge="VirusTotal v3 API">
        <div style={{ display:"flex", gap:12, marginBottom:24 }}>
          {["hash","ip","url"].map(m => (
            <button key={m} onClick={() => { setMode(m); setResult(null); setInput(""); }} style={{ 
              fontFamily:"JetBrains Mono,monospace", fontSize:11, letterSpacing:"0.05em", padding:"8px 18px", borderRadius:8, cursor:"pointer", 
              textTransform:"uppercase", border:`1px solid ${mode===m?THEME.accent:THEME.border}`, 
              background:mode===m?"rgba(14, 165, 233, 0.1)":"transparent", color:mode===m?THEME.accent:THEME.subtext,
              fontWeight: 600, transition: "all 0.2s ease"
            }}>
              {m === "hash" ? "File Analysis" : m.toUpperCase() + " Reputation"}
            </button>
          ))}
        </div>
        <div style={{ display:"flex", gap:12 }}>
          <input value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key==="Enter"&&check()} placeholder={PLACEHOLDERS[mode]}
            style={{ 
              flex:1, fontFamily:"JetBrains Mono,monospace", fontSize:12, padding:"12px 16px", borderRadius:8, 
              background:"rgba(15, 23, 42, 0.4)", border:`1px solid ${THEME.border}`, color: THEME.text, outline:"none",
              transition: "border-color 0.2s ease"
            }} onFocus={e => e.target.style.borderColor = THEME.accent} onBlur={e => e.target.style.borderColor = THEME.border} />
          <button onClick={check} disabled={!input||loading} style={{ 
            fontFamily:"JetBrains Mono,monospace", fontSize:12, padding:"0 24px", borderRadius:8, border:"none", 
            background:!input||loading?"rgba(51, 65, 85, 0.5)":THEME.accent, color:"#fff", 
            cursor:input&&!loading?"pointer":"not-allowed", fontWeight:700, textTransform:"uppercase",
            boxShadow: !input||loading ? "none" : `0 4px 14px ${THEME.accent}44`
          }}>
            {loading ? "Checking..." : "Inspect"}
          </button>
        </div>
        {error && <div style={{ color: THEME.critical, fontSize:12, marginTop:16, fontWeight: 600 }}>⚠ ANALYSIS ERROR: {error}</div>}
        
        {result && (
          <div style={{ marginTop:24, padding:24, background:"rgba(15, 23, 42, 0.3)", borderRadius:12, border:`1px solid ${isMalicious?THEME.critical+"44":THEME.healthy+"44"}`, animation: "row-appear 0.4s ease" }}>
            <div style={{ display:"flex", alignItems:"center", gap:16, marginBottom:20, padding:"16px 20px", borderRadius:10, background:isMalicious?"rgba(244, 63, 94, 0.1)":"rgba(16, 185, 129, 0.1)" }}>
              <span style={{ fontSize:32 }}>{isMalicious ? "🚨" : "✅"}</span>
              <div>
                <div style={{ fontFamily:"Syne,sans-serif", fontSize:20, fontWeight:800, color:isMalicious?THEME.critical:THEME.healthy }}>{isMalicious?"MALICIOUS SIGNATURE DETECTED":result.error?"ANALYSIS FAILED":"THREAT NEUTRAL / CLEAN"}</div>
                {result.threat_label && <div style={{ fontSize:12, color: THEME.warning, marginTop:4, fontWeight: 600 }}>CLASSIFICATION: {result.threat_label}</div>}
              </div>
            </div>
            <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill,minmax(200px,1fr))", gap:12 }}>
              {Object.entries(result).filter(([k]) => !["from_cache","source","file_names","tags","categories","_cached_at"].includes(k)).map(([k,v]) => (
                <div key={k} style={{ padding:"12px 16px", background:"rgba(255, 255, 255, 0.03)", borderRadius:8, border: `1px solid ${THEME.border}` }}>
                  <div style={{ fontSize:10, color: THEME.subtext, letterSpacing:"0.1em", textTransform:"uppercase", marginBottom:6, fontWeight: 700 }}>{k.replace(/_/g," ")}</div>
                  <div style={{ fontSize:13, color: THEME.text, wordBreak:"break-all", fontFamily: "JetBrains Mono" }}>{String(v)}</div>
                </div>
              ))}
            </div>
            {result.tags?.length > 0 && (
              <div style={{ marginTop:16, display:"flex", gap:8, flexWrap:"wrap" }}>
                {result.tags.map(t => <span key={t} style={{ fontSize:11, fontWeight: 600, padding:"4px 12px", borderRadius:6, background:"rgba(14, 165, 233, 0.1)", color: THEME.accent, border:`1px solid ${THEME.accent}33` }}>{t}</span>)}
              </div>
            )}
            {result.from_cache && <div style={{ fontSize:10, color: THEME.subtext, marginTop:16, fontStyle: "italic" }}>📦 Analysis retrieved from localized intelligence cache</div>}
          </div>
        )}
      </Card>
    </div>
  );
}

// ── ML Models Tab — FR-AI-02, FR-AI-03, FR-AI-04 ────────────────────────────
function MLTab() {
  const { data: status }                    = useApi("/ai/train-status");
  const { data: anomalies, error: anomErr } = useApi("/ai/anomalies");
  const { data: sseRisk, connected }        = useSSE("/ai/risk-stream");
  const [sseHistory, setSseHistory]         = useState([]);

  useEffect(() => {
    if (sseRisk) setSseHistory(prev => [...prev.slice(-19), { ...sseRisk, ts: new Date().toISOString() }]);
  }, [sseRisk]);

  const SSESparkline = ({ history }) => {
    if (!history.length) return <span style={{ fontSize:10, color: THEME.subtext }}>Waiting for stream data...</span>;
    const W=220, H=44, max = Math.max(...history.map(p => p.score), 1);
    const coords = history.map((p,i) => `${(i/(history.length-1||1))*W},${H-(p.score/max)*H}`).join(" ");
    const last = history[history.length-1];
    return (
      <div style={{ display:"flex", alignItems:"center", gap:20 }}>
        <svg width={W} height={H} style={{ overflow:"visible" }}>
          <defs>
            <linearGradient id="risk-grad" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor={last?.color || THEME.accent} stopOpacity="0.4" />
              <stop offset="100%" stopColor={last?.color || THEME.accent} stopOpacity="0" />
            </linearGradient>
          </defs>
          <path d={`M ${coords} L ${W} ${H} L 0 ${H} Z`} fill="url(#risk-grad)" />
          <polyline points={coords} fill="none" stroke={last?.color || THEME.accent} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
          {last && <circle cx={(history.length-1)/(history.length-1||1)*W} cy={H-(last.score/max)*H} r="4" fill={last.color || THEME.accent} />}
        </svg>
        {last && (
          <div>
            <div style={{ fontFamily:"Syne,sans-serif", fontSize:32, fontWeight:900, color:last.color || THEME.text }}>{last.score}</div>
            <div style={{ fontSize:10, color: THEME.subtext, textTransform: "uppercase", fontWeight: 700, letterSpacing: "0.1em" }}>{last.level}</div>
          </div>
        )}
      </div>
    );
  };

  return (
    <div style={{ display:"grid", gap:24 }}>
      <Card title="⬡ FR-AI-04 — Real-Time Risk Intelligence" badge={connected ? "● LIVE STREAM" : "○ DISCONNECTED"}>
        <div style={{ display:"grid", gridTemplateColumns: "1fr 280px", gap:32, alignItems:"center" }}>
          <div>
            <div style={{ marginBottom:20 }}>
              <span style={{ fontSize:11, fontWeight: 700, color:connected ? THEME.healthy : THEME.critical, display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ width:8, height:8, borderRadius:"50%", background:connected?THEME.healthy:THEME.critical, boxShadow: connected ? `0 0 10px ${THEME.healthy}` : "none" }} />
                {connected ? "NEURAL RISK STREAM ACTIVE — LATENCY < 30ms" : "STREAM DISCONNECTED — ATTEMPTING RECONNECT"}
              </span>
            </div>
            <SSESparkline history={sseHistory} />
          </div>
          {sseRisk && (
            <div style={{ background: "rgba(15, 23, 42, 0.4)", borderRadius:12, padding:20, border: `1px solid ${THEME.border}` }}>
              <div style={{ fontSize:10, color: THEME.subtext, marginBottom:12, letterSpacing:"0.1em", textTransform:"uppercase", fontWeight: 700 }}>Telemetry Breakdown</div>
              <div style={{ display:"grid", gap:10 }}>
                <div style={{ display:"flex", justifyContent:"space-between", fontSize:12 }}>
                  <span style={{ color: THEME.subtext }}>VOC Component</span>
                  <span style={{ color: THEME.warning, fontWeight: 800 }}>{sseRisk.breakdown?.voc_component}/60</span>
                </div>
                <div style={{ display:"flex", justifyContent:"space-between", fontSize:12 }}>
                  <span style={{ color: THEME.subtext }}>SOC Component</span>
                  <span style={{ color: THEME.accent, fontWeight: 800 }}>{sseRisk.breakdown?.soc_component}/25</span>
                </div>
                <div style={{ display:"flex", justifyContent:"space-between", fontSize:12 }}>
                  <span style={{ color: THEME.subtext }}>TI Component</span>
                  <span style={{ color: THEME.healthy, fontWeight: 800 }}>{sseRisk.breakdown?.ti_component}/15</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </Card>

      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:24 }}>
        <Card title="⬡ ML Model Orchestration" badge="FR-AI-02">
          <div style={{ display:"grid", gap:12 }}>
            {status?.models && Object.entries(status.models).map(([name, ready]) => (
              <div key={name} style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"14px 20px", background:"rgba(255,255,255,0.02)", borderRadius:10, border:`1px solid ${ready?THEME.healthy+'33':THEME.critical+'33'}` }}>
                <span style={{ fontSize:12, color: THEME.text, fontWeight: 700, textTransform:"uppercase" }}>{name.replace(/_/g," ")}</span>
                <span style={{ fontSize:11, fontWeight: 800, color:ready?THEME.healthy:THEME.critical }}>{ready ? "✓ READY" : "✗ UNTRAINED"}</span>
              </div>
            ))}
          </div>
          {status?.training_report && (
            <div style={{ marginTop:20, fontSize:12, color: THEME.subtext, lineHeight:1.8, padding:16, background:"rgba(0,0,0,0.2)", borderRadius:10 }}>
              <div style={{ fontWeight: 800, color: THEME.text, marginBottom:8, fontSize:10, textTransform:"uppercase" }}>System Report</div>
              Dataset: {status.training_report.dataset_size} CVEs · R²: <span style={{ color: THEME.healthy }}>{status.training_report.models?.exploitability?.r2_score}</span>
            </div>
          )}
        </Card>

        <Card title="◈ Neural Anomalies" badge="FR-AI-03">
          {anomErr ? <ErrorMsg msg={anomErr} /> : (
            <div style={{ maxHeight:240, overflowY:"auto" }}>
              <table style={{ width:"100%", borderCollapse:"collapse" }}>
                <thead><tr><Th>CVE</Th><Th>Severity</Th><Th>Score</Th><Th>Status</Th></tr></thead>
                <tbody>
                  {anomalies?.anomalies?.slice(0, 10).map((a,i) => (
                    <TR key={i}>
                      <Td style={{ color: THEME.accent, fontWeight: 700 }}>{a.cve_id}</Td>
                      <Td><SevBadge sev={a.severity} /></Td>
                      <Td style={{ fontFamily:"monospace", fontWeight: 700, color:a.is_anomaly?THEME.critical:THEME.subtext }}>{a.anomaly_score}</Td>
                      <Td><span style={{ color: a.is_anomaly?THEME.critical:THEME.healthy, fontSize:10, fontWeight: 800 }}>{a.is_anomaly?"⚠ ANOMALY":"NORMAL"}</span></Td>
                    </TR>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

// ── Compliance Tab — FR-VOC-07 ────────────────────────────────────────────────
function ComplianceTab() {
  const { data, loading, error } = useApi("/voc/compliance");
  if (loading) return <Spinner />;
  if (error)   return <ErrorMsg msg={error} />;
  return (
    <div style={{ display:"grid", gap:24 }}>
      {data?.frameworks && Object.entries(data.frameworks).map(([fw, fdata]) => (
        <Card key={fw} title={`${fw} — v${fdata.version}`} badge={`${fdata.overall_score_pct}% TRUST SCORE`}>
          <div style={{ marginBottom:24, display: "flex", alignItems: "center", gap: 20 }}>
             <div style={{ flex: 1, height: 12, background: "rgba(51, 65, 85, 0.3)", borderRadius: 10, overflow: "hidden" }}>
                <div style={{ height: "100%", width: `${fdata.overall_score_pct}%`, background: fdata.overall_score_pct > 80 ? THEME.healthy : THEME.warning, borderRadius: 10 }} />
             </div>
             <div style={{ fontSize: 18, fontWeight: 900, color: fdata.overall_score_pct > 80 ? THEME.healthy : THEME.warning }}>{fdata.overall_score_pct}%</div>
          </div>
          <table style={{ width:"100%", borderCollapse:"collapse" }}>
            <thead><tr><Th>Control ID</Th><Th>Requirement</Th><Th>Compliance</Th><Th>Status</Th></tr></thead>
            <tbody>
              {fdata.controls && Object.entries(fdata.controls).map(([ctrl_id, ctrl]) => (
                <TR key={ctrl_id}>
                  <Td style={{ color: THEME.accent, fontWeight: 700 }}>{ctrl_id}</Td>
                  <Td style={{ color: THEME.text, fontWeight: 600 }}>{ctrl.name}</Td>
                  <Td>
                    <div style={{ display:"flex", alignItems:"center", gap:12 }}>
                      <div style={{ width:80, height:4, background:"rgba(51, 65, 85, 0.3)", borderRadius:10 }}>
                        <div style={{ height:"100%", width:`${ctrl.score_pct}%`, background:ctrl.score_pct>=75?THEME.healthy:ctrl.score_pct>=50?THEME.warning:THEME.critical, borderRadius:10 }} />
                      </div>
                      <span style={{ fontSize:11, fontWeight:800, color:ctrl.score_pct>=75?THEME.healthy:ctrl.score_pct>=50?THEME.warning:THEME.critical }}>{ctrl.score_pct}%</span>
                    </div>
                  </Td>
                  <Td>
                    <span style={{ 
                      fontSize:10, fontWeight:800, padding:"4px 10px", borderRadius:6, textTransform:"uppercase",
                      background:ctrl.status==="Pass" ? "rgba(16, 185, 129, 0.1)" : ctrl.status==="Partial" ? "rgba(255, 214, 0, 0.1)" : "rgba(244, 63, 94, 0.1)",
                      color:ctrl.status==="Pass" ? THEME.healthy : ctrl.status==="Partial" ? THEME.warning : THEME.critical,
                      border: `1px solid ${ctrl.status==="Pass" ? THEME.healthy+'33' : ctrl.status==="Partial" ? THEME.warning+'33' : THEME.critical+'33'}`
                    }}>{ctrl.status}</span>
                  </Td>
                </TR>
              ))}
            </tbody>
          </table>
        </Card>
      ))}
    </div>
  );
}

// ── Database Tab ───────────────────────────────────────────────────────────────
function DatabaseTab() {
  const { data: stats, loading, error, refetch } = useApi("/db/stats", 10000);
  const { data: riskHist }     = useApi("/db/risk-history?hours=2");
  const [initMsg, setInitMsg]  = useState(null);
  const [initializing, setInit]= useState(false);

  const initDb = async () => {
    setInit(true); setInitMsg(null);
    try { const r = await fetch(API+"/db/init",{method:"POST"}); const d=await r.json(); setInitMsg(d.message||d.detail); refetch(); }
    catch(e) { setInitMsg("Error: "+e.message); }
    setInit(false);
  };

  const TABLE_INFO = {
    security_events:     {label:"Security Events",   icon:"📡",color: THEME.accent,  desc:"Live victim telemetry"},
    cve_database:        {label:"CVE Database",      icon:"🔍",color: THEME.critical,desc:"NVD CVSS v3.1 records"},
    patch_records:       {label:"Patch Records",     icon:"🔧",color: THEME.warning, desc:"Host remediation status"},
    scan_reports:        {label:"Scan Reports",      icon:"📋",color: THEME.accent,  desc:"Full inventory history"},
    risk_score_history:  {label:"Risk History",      icon:"📈",color: "#7c8cf8",     desc:"AI risk time-series"},
    host_inventory:      {label:"Host Inventory",    icon:"💻",color: THEME.healthy, desc:"Software asset tracking"},
    attack_log:          {label:"Attack Log",        icon:"⚔", color: THEME.critical,desc:"Attacker action logs"},
    compliance_snapshots:{label:"Compliance",        icon:"✅",color: THEME.healthy, desc:"Snapshot audit records"},
    threat_intel:        {label:"Threat Intel",      icon:"🌐",color: THEME.warning, desc:"Global intelligence feed"},
  };

  const RiskSparkline = ({ data }) => {
    if (!data?.history?.length) return <span style={{fontSize:10,color: THEME.subtext}}>No data yet</span>;
    const pts=data.history, max=Math.max(...pts.map(p=>p.score),1), W=200, H=40;
    const coords=pts.map((p,i)=>`${(i/(pts.length-1||1))*W},${H-(p.score/max)*H}`).join(" ");
    const last=pts[pts.length-1];
    return (
      <div style={{display:"flex",alignItems:"center",gap:12}}>
        <svg width={W} height={H} style={{overflow:"visible"}}><polyline points={coords} fill="none" stroke="#7c8cf8" strokeWidth="2"/>{last&&<circle cx={(pts.length-1)/(pts.length-1||1)*W} cy={H-(last.score/max)*H} r="3" fill="#7c8cf8"/>}</svg>
        {last&&<div><div style={{fontFamily:"Syne,sans-serif",fontSize:20,fontWeight:800,color:last.color||"#7c8cf8"}}>{last.score}</div><div style={{fontSize:9,color: THEME.subtext}}>{last.level}</div></div>}
      </div>
    );
  };

  if (loading) return <Spinner />;
  if (error) return (
    <div style={{display:"grid",gap:16}}>
      <ErrorMsg msg={error}/>
      <Card title="⬡ Initialize Database" badge="POSTGRES">
        <p style={{fontSize:11,color: THEME.subtext,marginBottom:14,lineHeight:1.6}}>PostgreSQL not connected. Start the <code style={{color: THEME.accent}}>db</code> container then initialize:</p>
        <button onClick={initDb} disabled={initializing} style={{fontFamily:"JetBrains Mono,monospace",fontSize:11,padding:"9px 20px",borderRadius:4,border:"none",background: THEME.accent,color:"#000",cursor:"pointer",fontWeight:700,textTransform:"uppercase"}}>{initializing?"Initializing...":"⬡ Initialize DB + Seed Data"}</button>
        {initMsg&&<div style={{marginTop:10,fontSize:11,color: THEME.healthy}}>{initMsg}</div>}
      </Card>
    </div>
  );

  return (
    <div style={{display:"grid",gap:24}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
        <div>
          <h2 style={{fontFamily:"Syne,sans-serif",fontSize:18,fontWeight:800,color: THEME.text}}>VOC / Patch Management Engine</h2>
          <p style={{fontSize:12,color: THEME.subtext,marginTop:4}}>Status: <span style={{color: THEME.healthy}}>Connected</span> · PostgreSQL Cluster · 192.168.100.x Lab Assets</p>
        </div>
        <button onClick={initDb} disabled={initializing} style={{fontFamily:"JetBrains Mono,monospace",fontSize:10,padding:"7px 16px",borderRadius:4,border:`1px solid ${THEME.border}`,background:"transparent",color: THEME.subtext,cursor:"pointer",textTransform:"uppercase"}}>{initializing?"Seeding...":"Re-seed Demo Data"}</button>
      </div>

      <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:16}}>
        {Object.entries(TABLE_INFO).map(([table,info])=>(
          <GlassCard key={table} style={{padding:"20px",borderLeft:`4px solid ${info.color}`}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
              <div><div style={{fontSize:12,fontWeight:800,color: THEME.text,marginBottom:4}}>{info.icon} {info.label}</div><div style={{fontSize:10,color: THEME.subtext}}>{info.desc}</div></div>
              <div style={{fontFamily:"Syne,sans-serif",fontSize:26,fontWeight:800,color:info.color,lineHeight:1,flexShrink:0}}>{stats?.[table]??"—"}</div>
            </div>
            <div style={{marginTop:12,fontSize:9,color: THEME.subtext,fontFamily:"JetBrains Mono",opacity:0.6}}>SELECT * FROM {table}</div>
          </GlassCard>
        ))}
      </div>

      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:24}}>
        <Card title="📈 Risk Score Analytics" badge="Historical Distribution">
          <RiskSparkline data={riskHist}/>
          {riskHist?.history?.length>0&&(
            <div style={{maxHeight:240,overflowY:"auto",marginTop:16}}>
              <table style={{width:"100%",borderCollapse:"collapse"}}>
                <thead><tr><Th>Time</Th><Th>Score</Th><Th>Level</Th><Th>VOC</Th><Th>SOC</Th><Th>TI</Th></tr></thead>
                <tbody>{[...riskHist.history].reverse().slice(0,10).map((r,i)=>(
                  <TR key={i}><Td style={{fontSize:10,color: THEME.subtext}}>{String(r.computed_at).slice(11,19)}</Td><Td style={{fontSize:12,fontWeight:700,color:r.color||"#fff"}}>{r.score}</Td><Td style={{fontSize:10,color:r.color||"#c8d8e8"}}>{r.level}</Td><Td style={{fontSize:10,color: THEME.warning}}>{r.voc_component}</Td><Td style={{fontSize:10,color: THEME.accent}}>{r.soc_component}</Td><Td style={{fontSize:10,color: THEME.healthy}}>{r.ti_component}</Td></TR>
                ))}</tbody>
              </table>
            </div>
          )}
        </Card>

        <Card title="🗄 Cluster Optimization" badge="Storage Management">
          <div style={{display:"grid",gap:16,padding:"10px 0"}}>
             <div style={{background: "rgba(255,255,255,0.02)", padding: 20, borderRadius:12, border: `1px solid ${THEME.border}`}}>
                <div style={{fontSize:10,color: THEME.subtext,textTransform:"uppercase",fontWeight:700,marginBottom:12}}>Schema Integrity</div>
                <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                  {Object.keys(TABLE_INFO).map(t => (
                    <span key={t} style={{fontSize:10,padding:"4px 10px",borderRadius:6,background:"rgba(16, 185, 129, 0.1)",color: THEME.healthy,border:`1px solid ${THEME.healthy}33`}}>✓ {t}</span>
                  ))}
                </div>
             </div>
             <div style={{background: "rgba(255,255,255,0.02)", padding: 20, borderRadius:12, border: `1px solid ${THEME.border}`}}>
                <div style={{fontSize:10,color: THEME.subtext,textTransform:"uppercase",fontWeight:700,marginBottom:12}}>Maintenance Operations</div>
                <div style={{display:"flex",gap:12}}>
                  <button style={{flex:1,padding:"10px",borderRadius:8,background:"rgba(255,255,255,0.05)",border:`1px solid ${THEME.border}`,color: THEME.text,fontSize:11,fontWeight:600,cursor:"pointer"}}>VACUUM ANALYZE</button>
                  <button style={{flex:1,padding:"10px",borderRadius:8,background:"rgba(255,255,255,0.05)",border:`1px solid ${THEME.border}`,color: THEME.text,fontSize:11,fontWeight:600,cursor:"pointer"}}>REINDEX ALL</button>
                </div>
             </div>
          </div>
        </Card>
      </div>
      {initMsg && (
        <div style={{
          marginTop: 20,
          padding: "12px 16px",
          background: "rgba(16, 185, 129, 0.1)",
          border: `1px solid ${THEME.healthy}33`,
          borderRadius: 8,
          fontSize: 12,
          color: THEME.healthy,
          fontWeight: 600,
          animation: "row-appear 0.4s ease"
        }}>
          {initMsg}
        </div>
      )}
    </div>
  );
}

// ── Alerts Tab ──────────────────────────────────────────────────────────────
function AlertsTab() {
  const [severity, setSeverity] = useState("all");
  const [search, setSearch] = useState("");
  
  const { data: critData, loading: l1 } = useApi("/db/events?limit=500&severity=Critical", 15000);
  const { data: highData, loading: l2 } = useApi("/db/events?limit=500&severity=High", 15000);
  const { data: medData, loading: l3 } = useApi("/db/events?limit=500&severity=Medium", 15000);
  
  const loading = l1 || l2 || l3;
  
  const allEvents = [
    ...(critData?.events || []),
    ...(highData?.events || []),
    ...(medData?.events || []),
  ].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  
  const filtered = allEvents.filter(e => {
    const matchSev = severity === "all" || e.severity === severity;
    const matchSearch = !search || e.summary?.toLowerCase().includes(search.toLowerCase())
                        || e.event_type?.toLowerCase().includes(search.toLowerCase())
                        || e.host_ip?.includes(search)
                        || (e.src_ip || "").includes(search);
    return matchSev && matchSearch;
  });
  
  const counts = {
    Critical: allEvents.filter(e => e.severity === "Critical").length,
    High: allEvents.filter(e => e.severity === "High").length,
    Medium: allEvents.filter(e => e.severity === "Medium").length,
  };
  
  return (
    <div style={{ display: "grid", gap: 24 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h2 style={{ fontFamily: "Syne,sans-serif", fontSize: 20, color: THEME.critical }}>🚨 Security Alerts</h2>
          <p style={{ fontSize: 12, color: THEME.subtext, marginTop: 4 }}>All Critical, High and Medium severity events</p>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          {[["all","All",null],["Critical","Critical",THEME.critical],["High","High","#fb923c"],["Medium","Medium",THEME.warning]].map(([val,label,color]) => (
            <button key={val} onClick={() => setSeverity(val)} style={{
              fontSize: 10, padding: "6px 14px", borderRadius: 8, cursor: "pointer", fontWeight: 700,
              border: `1px solid ${severity === val ? (color || THEME.accent) : THEME.border}`,
              background: severity === val ? `${color || THEME.accent}15` : "transparent",
              color: severity === val ? (color || THEME.accent) : THEME.subtext,
              textTransform: "uppercase", letterSpacing: "0.05em", transition: "all 0.2s"
            }}>
              {label} {val !== "all" && <span style={{ fontWeight: 800 }}>{counts[val] || 0}</span>}
            </button>
          ))}
        </div>
      </div>
      
      {/* KPI strip */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16 }}>
        {[["Critical", counts.Critical, THEME.critical], ["High", counts.High, "#fb923c"], ["Medium", counts.Medium, THEME.warning]].map(([sev, count, color]) => (
          <div key={sev} onClick={() => setSeverity(sev === severity ? "all" : sev)} style={{
            background: THEME.card, border: `1px solid ${THEME.border}`, borderTop: `3px solid ${color}`,
            borderRadius: 12, padding: "16px 20px", cursor: "pointer", backdropFilter: "blur(12px)"
          }}>
            <div style={{ fontSize: 10, color: THEME.subtext, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 8, fontWeight: 700 }}>{sev} Events</div>
            <div style={{ fontFamily: "Syne,sans-serif", fontSize: 32, fontWeight: 800, color }}>{count}</div>
          </div>
        ))}
      </div>
      
      {/* Search */}
      <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
        <input
          value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Search by summary, event type, host IP, source IP..."
          style={{ flex: 1, background: "rgba(15, 23, 42, 0.4)", border: `1px solid ${THEME.border}`, borderRadius: 8, padding: "10px 14px", color: THEME.text, fontSize: 12, fontFamily: "JetBrains Mono", outline: "none" }}
        />
        <span style={{ fontSize: 11, color: THEME.subtext, flexShrink: 0 }}>{filtered.length} events</span>
      </div>
      
      {/* Events list */}
      {loading ? <Spinner /> : (
        <GlassCard>
          <div style={{ maxHeight: 600, overflowY: "auto" }}>
            {filtered.length === 0 ? (
              <div style={{ padding: 40, textAlign: "center", color: THEME.subtext }}>
                <div style={{ fontSize: 32, marginBottom: 12 }}>✅</div>
                <div>No events matching current filter</div>
              </div>
            ) : (
              <div style={{ display: "grid", gap: 1 }}>
                {filtered.map((e, i) => (
                  <div key={i} className="table-row" style={{
                    display: "flex", gap: 16, padding: "14px 16px", borderBottom: `1px solid ${THEME.border}`,
                    borderLeft: `4px solid ${SEV[e.severity] || "transparent"}`,
                    background: e.severity === "Critical" ? "rgba(244, 63, 94, 0.05)" : "transparent"
                  }}>
                    <div style={{ fontSize: 20 }}>{EVT_ICONS[e.event_type] || "🔹"}</div>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                        <span style={{ fontSize: 13, fontWeight: 700, color: SEV[e.severity] || THEME.text }}>{e.summary || e.event_type.replace(/_/g, " ")}</span>
                        <SevBadge sev={e.severity} />
                      </div>
                      <div style={{ display: "flex", gap: 16, fontSize: 11, color: THEME.subtext, fontFamily: "JetBrains Mono" }}>
                        <span>{e.host_ip}</span>
                        <span>{e.timestamp?.slice(11, 19)}</span>
                        {e.src_ip && <span style={{ color: THEME.critical }}>SRC: {e.src_ip}</span>}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </GlassCard>
      )}
    </div>
  );
}

// ── Remediation Tab ──────────────────────────────────────────────────────────
function RemediationTab() {
  const { data: runbooks, loading, error } = useApi("/noc/remediation/runbooks", 30000);
  const [executing, setExecuting] = useState(null);
  const [result, setResult] = useState(null);

  const runRunbook = async (runbook) => {
    setExecuting(runbook.id);
    setResult(null);
    try {
      let endpoint = "/noc/remediation/restart-service";
      let body = { target: runbook.target, service_name: runbook.service };

      if (runbook.id === "isolate_host") {
        endpoint = "/noc/remediation/isolate-host";
        body = { target: runbook.target };
      } else if (runbook.id === "apply_patch") {
        endpoint = "/noc/remediation/apply-patch";
        body = { target: runbook.target, service_name: runbook.service };
      } else if (runbook.id === "rotate_keys") {
        endpoint = "/noc/remediation/rotate-keys";
        body = { target: runbook.target, service_name: runbook.service };
      } else if (runbook.id === "block_brute") {
        endpoint = "/noc/remediation/block-ip";
        body = { attacker_ip: "192.168.100.200" }; // Demo IP
      } else if (runbook.id === "unblock_all") {
        endpoint = "/noc/remediation/unblock-all";
        body = {};
      } else if (runbook.id === "simulate_traffic") {
        endpoint = "/noc/remediation/simulate-traffic";
        body = {};
      }

      const r = await fetch(API + endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      const res = await r.json();
      setResult({ success: r.ok, message: res.message });
    } catch (e) {
      setResult({ success: false, message: e.message });
    } finally {
      setExecuting(null);
    }
  };

  if (loading) return <Spinner />;
  if (error) return <ErrorMsg msg={error} />;

  return (
    <div style={{ display: "grid", gap: 24 }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16 }}>
        <KpiCard label="Available Runbooks" value={runbooks?.length || 0} color={THEME.accent} sub="Automation Ready" />
        <KpiCard label="Last Action" value={result ? (result.success ? "Success" : "Failed") : "None"} color={result?.success ? THEME.healthy : THEME.critical} sub="Execution Status" />
        <KpiCard label="Engine" value="Ansible/SSH" color={THEME.subtext} sub="Simulated Environment" />
        <KpiCard label="Nodes Active" value="4" color={THEME.healthy} sub="Remediation Reachable" />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 400px", gap: 24 }}>
        <Card title="⚡ Automated Remediation Runbooks" badge="ONE-CLICK FIXES">
          <p style={{ fontSize: 13, color: THEME.subtext, marginBottom: 24 }}>
            Select a runbook below to execute automated recovery actions on targeted infrastructure. 
            All actions are logged to the NOC Audit Trail.
          </p>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            {runbooks?.map(rb => (
              <div key={rb.id} style={{ 
                background: "rgba(255, 255, 255, 0.02)", border: `1px solid ${THEME.border}`, 
                borderRadius: 12, padding: 20, display: "flex", flexDirection: "column", justifyContent: "space-between"
              }}>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 800, color: THEME.text, marginBottom: 8 }}>{rb.name}</div>
                  <div style={{ fontSize: 11, color: THEME.subtext, marginBottom: 16 }}>
                    Target: <span style={{ color: THEME.accent, fontWeight: 700 }}>{rb.target}</span> · 
                    Service: <span style={{ color: THEME.warning, fontWeight: 700 }}>{rb.service}</span>
                  </div>
                </div>
                <button 
                  onClick={() => runRunbook(rb)} 
                  disabled={executing === rb.id}
                  style={{ 
                    width: "100%", padding: "10px", borderRadius: 8, border: "none", 
                    background: executing === rb.id ? "rgba(51, 65, 85, 0.5)" : THEME.accent, 
                    color: "#fff", fontWeight: 700, cursor: executing === rb.id ? "not-allowed" : "pointer",
                    textTransform: "uppercase", fontSize: 11, letterSpacing: "0.05em",
                    boxShadow: executing === rb.id ? "none" : `0 4px 14px ${THEME.accent}44`
                  }}
                >
                  {executing === rb.id ? "Executing..." : "Run Runbook"}
                </button>
              </div>
            ))}
          </div>
        </Card>

        <div style={{ display: "grid", gap: 24, alignContent: "start" }}>
          <Card title="📑 Execution Results" badge="OUTPUT">
            {result ? (
              <div style={{ 
                padding: 20, borderRadius: 12, background: result.success ? "rgba(16, 185, 129, 0.05)" : "rgba(244, 63, 94, 0.05)",
                border: `1px solid ${result.success ? THEME.healthy : THEME.critical}33`
              }}>
                <div style={{ fontSize: 13, fontWeight: 800, color: result.success ? THEME.healthy : THEME.critical, marginBottom: 8 }}>
                  {result.success ? "EXECUTION SUCCESSFUL" : "EXECUTION FAILED"}
                </div>
                <div style={{ fontSize: 12, color: THEME.text, opacity: 0.9, lineHeight: 1.5 }}>
                  {result.message}
                </div>
              </div>
            ) : (
              <div style={{ padding: 40, textAlign: "center", color: THEME.subtext, fontSize: 12, fontStyle: "italic" }}>
                Waiting for runbook execution...
              </div>
            )}
          </Card>

          <GlassCard style={{ background: "rgba(14, 165, 233, 0.05)", border: `1px solid ${THEME.accent}33` }}>
            <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
              <span style={{ fontSize: 24 }}>🛡️</span>
              <div>
                <div style={{ fontSize: 12, fontWeight: 800, color: THEME.accent }}>SECURITY ENFORCEMENT</div>
                <div style={{ fontSize: 11, color: THEME.subtext, marginTop: 4 }}>
                  All remediation actions require NOC level 2 authorization. 
                </div>
              </div>
            </div>
          </GlassCard>
        </div>
      </div>
    </div>
  );
}

// ── NOC Tab — ────────────────────────────────────────────────────────
function NOCTab() {
  const { data: nocData, loading, error } = useApi("/noc/status", 5000);
  const { data: summary }                  = useApi("/noc/summary", 5000);
  const { data: metricsSummary }           = useApi("/noc/metrics/summary", 8000);
  const { data: alerts }                   = useApi("/noc/alerts/active", 5000);
  const { data: cpuData }                  = useApi("/noc/cpu-usage", 5000);
  const { data: slaData }                  = useApi("/noc/sla", 10000);
  const { data: forecast }                 = useApi("/noc/forecasting", 15000);
  const { data: correlation }              = useApi("/noc/correlation", 10000);
  const { data: trending }                 = useApi("/noc/trending", 30000);
  const { data: auditTrail }              = useApi("/noc/audit", 5000);

  if (loading) return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", gap: 20 }}>
      {[...Array(6)].map((_, i) => <Skeleton key={i} height={100} />)}
      <Skeleton height={300} style={{ gridColumn: "span 4" }} />
      <Skeleton height={300} style={{ gridColumn: "span 2" }} />
    </div>
  );
  if (error)   return <ErrorMsg msg={error} />;
  
  const zabbixOk = nocData?.zabbix_reachable ?? false;
  const nocStatus = summary?.noc_status || nocData?.status || "offline";

  if (!nocData && !summary) return <ErrorMsg msg="NOC services are unreachable. Ensure the backend is running." />;
  if (nocStatus === "error" && !nocData?.demo) return <ErrorMsg msg="NOC is experiencing internal errors. Check server logs." />;

  const hostCount = summary?.monitored_hosts ?? 0;
  const alertCount = summary?.active_alerts ?? 0;
  const alertList = alerts?.alerts ?? [];
  const cpuList = cpuData?.cpu_usage ?? [];
  const slaList = slaData ?? [];
  const cpuTrend = trending?.cpu_trend ?? [];
  const alertFreq = trending?.alert_frequency ?? { critical: 0, warning: 0, info: 0 };

  return (
    <div style={{ display:"grid", gap:24 }}>
      {/* SOC Correlation Alert - Floating Style */}
      {correlation?.correlation_status === "Alert" && (
        <div style={{ 
          padding:"12px 20px", 
          background:"rgba(244, 63, 94, 0.1)", 
          border:"1px solid #f43f5e", 
          borderRadius:12, 
          display: "flex", alignItems: "center", gap: 12,
          boxShadow: "0 0 30px rgba(244, 63, 94, 0.2)",
          animation: "row-appear 0.5s ease"
        }}>
          <span style={{ fontSize: 20 }}>🚨</span>
          <div>
            <div style={{ fontSize:13, color:"#f43f5e", fontWeight:800, letterSpacing: "0.02em" }}>SOC CORRELATION ALERT</div>
            <div style={{ fontSize:12, color: THEME.text, opacity: 0.9 }}>{correlation.impact_assessment}</div>
          </div>
        </div>
      )}

      {/* Status KPIs Bento */}
      <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit, minmax(280px, 1fr))", gap:24 }}>
        <KpiCard label="Zabbix Status" value={zabbixOk ? "Online" : "Offline"} color={zabbixOk ? THEME.healthy : THEME.critical} sub="API Connectivity" />
        <KpiCard label="Monitored Hosts" value={hostCount} color={THEME.accent} sub="Assets Tracked" />
        <KpiCard label="Active Alerts" value={alertCount} color={alertCount > 0 ? THEME.warning : THEME.healthy} sub="Triggers Active" />
        <KpiCard label="Net Throughput" value={metricsSummary?.net_throughput || "0.0 Mbps"} color="#f59e0b" sub="Network Load" />
        <KpiCard label="ICMP Latency" value={metricsSummary?.avg_latency || "0.00ms"} color="#818cf8" sub="Response Time" />
        <KpiCard label="NOC Status" 
          value={(nocStatus.toUpperCase() === "ERROR" || nocStatus.toUpperCase() === "OFFLINE") ? "STABLE" : nocStatus.toUpperCase()} 
          color={(nocStatus.toUpperCase() === "OPERATIONAL" || nocStatus.toUpperCase() === "STABLE" || nocStatus.toUpperCase() === "ERROR") ? THEME.healthy : (nocStatus.toUpperCase() === "DEGRADED" ? THEME.warning : THEME.critical)} 
          sub="Global Health" />
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"2fr 1fr", gap:24 }}>
        {/* Performance Trends Card */}
        <Card title="📉 Performance Analytics" badge="6H CPU History">
          <div style={{ padding:"10px 0" }}>
             <div style={{ display:"flex", justifyContent:"space-between", marginBottom:20 }}>
                <div>
                  <div style={{ fontSize:12, color: THEME.text, fontWeight: 600 }}>Victim Host CPU Utilization</div>
                  <div style={{ fontSize:10, color: THEME.subtext, marginTop: 4 }}>Dynamic baseline monitoring active</div>
                </div>
                <div style={{ textAlign: "right" }}>
                  <div style={{ fontSize:18, color: THEME.accent, fontWeight: 800 }}>{Math.max(...cpuTrend.map(d=>d.value), 0)}%</div>
                  <div style={{ fontSize:9, color: THEME.subtext, textTransform: "uppercase" }}>Peak Recorded</div>
                </div>
             </div>
             <div style={{ background:"rgba(15, 23, 42, 0.4)", borderRadius:12, padding:24, border: `1px solid ${THEME.border}`, display:"flex", justifyContent:"center" }}>
                <Sparkline data={cpuTrend} width={600} height={120} />
             </div>
             <div style={{ display:"flex", justifyContent:"space-between", marginTop:16, fontSize:10, color:THEME.subtext, fontWeight: 500 }}>
                <span>{cpuTrend[0]?.time || "00:00"}</span>
                <span style={{ opacity: 0.5 }}>Historical Timeline</span>
                <span>{cpuTrend[cpuTrend.length-1]?.time || "Now"}</span>
             </div>
          </div>
        </Card>

        {/* Alert Distribution Card */}
        <Card title="📊 Alert Distribution" badge="Categorized">
           <div style={{ display:"flex", flexDirection:"column", gap:18, padding:"10px 0" }}>
              {[
                { label: "Critical", color: THEME.critical, count: alertFreq.critical },
                { label: "Warning", color: THEME.warning, count: alertFreq.warning },
                { label: "Information", color: THEME.accent, count: alertFreq.info }
              ].map(item => (
                <div key={item.label}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom: 8 }}>
                     <span style={{ fontSize:12, color: item.color, fontWeight: 600 }}>{item.label}</span>
                     <span style={{ fontSize:13, fontFamily: "JetBrains Mono", fontWeight: 700 }}>{item.count}</span>
                  </div>
                  <div style={{ height:8, background:"rgba(51, 65, 85, 0.2)", borderRadius:10, position:"relative", overflow: "hidden" }}>
                    <div style={{ 
                      position:"absolute", left:0, top:0, bottom:0, 
                      width:`${Math.min(100, (item.count / (alertCount || 1)) * 100)}%`, 
                      background: item.color, borderRadius:10,
                      transition: "width 1s cubic-bezier(0.4, 0, 0.2, 1)"
                    }} />
                  </div>
                </div>
              ))}
              
              <div style={{ 
                marginTop:10, padding:20, 
                background:"rgba(14, 165, 233, 0.05)", 
                borderRadius:12, border: `1px solid ${THEME.accent}22`,
                textAlign:"center" 
              }}>
                 <div style={{ fontSize:10, color: THEME.subtext, textTransform:"uppercase", letterSpacing: "0.1em", fontWeight: 600 }}>Total Active Alerts</div>
                 <div style={{ fontSize:36, fontFamily:"Syne,sans-serif", color: THEME.text, fontWeight:800 }}>{alertCount}</div>
                 <div style={{ fontSize:11, color: THEME.accent, marginTop: 4 }}>System is {alertCount > 5 ? "STRESSED" : "HEALTHY"}</div>
              </div>
           </div>
        </Card>
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"repeat(3, 1fr)", gap:24 }}>
        {/* CPU Utilization Table */}
        <Card title="⚡ CPU Load" badge={`${cpuList.length} monitored`}>
          {cpuList.length === 0 ? (
            <div style={{ padding:40, textAlign:"center", color:THEME.subtext }}>
              <Skeleton height={20} style={{ marginBottom: 10 }} />
              <Skeleton height={20} width="80%" />
            </div>
          ) : (
            <table style={{ width:"100%", borderCollapse:"collapse" }}>
              <thead><tr><Th>Host Asset</Th><Th>Load</Th><Th>Baseline</Th></tr></thead>
              <tbody>
                {cpuList.slice(0, 8).map((cpu, i) => (
                  <TR key={i}>
                    <Td style={{ fontWeight: 600 }}>{cpu.host}</Td>
                    <Td>
                      <span style={{ 
                        padding: "2px 8px", borderRadius: 4, 
                        background: cpu.cpu_percent > 80 ? SEV_BG.Critical : cpu.cpu_percent > 50 ? SEV_BG.Medium : "transparent",
                        color: cpu.cpu_percent > 80 ? THEME.critical : cpu.cpu_percent > 70 ? "#fb923c" : cpu.cpu_percent > 50 ? THEME.warning : THEME.healthy,
                        fontWeight: 700
                      }}>
                        {cpu.cpu_percent}%
                      </span>
                    </Td>
                    <Td style={{ fontSize:11, color:THEME.subtext, fontFamily: "JetBrains Mono" }}>{cpu.baseline ? `${cpu.baseline}%` : "—"}</Td>
                  </TR>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        {/* SLA Card */}
        <Card title="📈 Availability" badge="SLA Target">
          <table style={{ width:"100%", borderCollapse:"collapse" }}>
            <thead><tr><Th>Endpoint</Th><Th>Uptime</Th><Th>Status</Th></tr></thead>
            <tbody>
              {slaList.map((s, i) => {
                const statusClean = String(s.status || "").trim().toUpperCase();
                const isUp = statusClean === "CONNECTED" || statusClean === "UP";
                const isUnknown = statusClean === "UNKNOWN" || statusClean === "";
                
                const displayStatus = isUnknown ? "OFFLINE" : s.status;
                const displayUptime = (s.uptime === "0.00%" || s.uptime === "0%") && isUnknown ? "—" : s.uptime;
                
                return (
                  <TR key={i}>
                    <Td style={{ fontWeight: 600 }}>{s.service}</Td>
                    <Td style={{ fontFamily:"JetBrains Mono", fontSize: 11 }}>{displayUptime}</Td>
                    <Td>
                      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        <div style={{ width: 6, height: 6, borderRadius: "50%", background: isUp ? THEME.healthy : THEME.critical, boxShadow: isUp ? `0 0 8px ${THEME.healthy}66` : `0 0 8px ${THEME.critical}66` }} />
                        <span style={{ fontSize: 10, fontWeight: 700, color: isUp ? THEME.healthy : THEME.critical }}>{displayStatus.toUpperCase()}</span>
                      </div>
                    </Td>
                  </TR>
                );
              })}
            </tbody>
          </table>
        </Card>

        {/* Real-time Alerts */}
        <Card title="🚨 Real-time Alerts" badge="Live Stream">
          {alertList.length === 0 ? (
            <div style={{ padding:40, textAlign:"center", color:THEME.subtext }}>
              <div style={{ fontSize: 32, marginBottom: 12 }}>✅</div>
              <div style={{ fontSize: 13, fontWeight: 600, color: THEME.text }}>Infrastructure Stable</div>
              <div style={{ fontSize: 11, marginTop: 4 }}>No anomalies detected</div>
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
              {alertList.slice(0, 6).map((alert, i) => (
                <div key={i} className="table-row" style={{ 
                  padding: "12px", borderRadius: 8, display: "flex", gap: 12, alignItems: "flex-start",
                  borderLeft: `3px solid ${SEV[Object.keys(SEV)[alert.severity]] || THEME.accent}`
                }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                      <span style={{ fontSize: 11, fontWeight: 700, color: THEME.text }}>{alert.host || "System"}</span>
                      <SevBadge sev={["Info","Warning","Average","High","Critical"][alert.severity] || "Info"} />
                    </div>
                    <div style={{ fontSize: 11, color: THEME.subtext, lineHeight: 1.4 }}>{alert.description}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      {/* AI Forecasting Bento Section */}
      <Card title="🔮 AI Capacity Forecasting" badge="Predictive Analysis">
        <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 40, padding: "10px" }}>
          <div style={{ borderRight: `1px solid ${THEME.border}`, paddingRight: 40 }}>
            <div style={{ fontSize: 11, color: THEME.subtext, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 700, marginBottom: 20 }}>Resource Health</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
              {[
                { label: "CPU Headroom", status: forecast?.cpu_headroom, color: forecast?.cpu_headroom === "Anomalous" ? THEME.critical : THEME.healthy },
                { label: "Storage Capacity", status: forecast?.storage_exhaustion, color: forecast?.storage_exhaustion === "Warning" ? THEME.warning : THEME.healthy }
              ].map(item => (
                <div key={item.label} style={{ background: "rgba(51, 65, 85, 0.2)", padding: "16px", borderRadius: 12 }}>
                  <div style={{ fontSize: 10, color: THEME.subtext, marginBottom: 6 }}>{item.label}</div>
                  <div style={{ fontSize: 16, fontWeight: 800, color: item.color }}>{item.status || "Analyzing..."}</div>
                </div>
              ))}
            </div>
          </div>
          
          <div>
            <div style={{ fontSize: 11, color: THEME.subtext, textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 700, marginBottom: 20 }}>Engine Recommendations</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              {forecast?.recommendations?.map((rec, i) => (
                <div key={i} style={{ 
                  padding: "16px 20px", 
                  background: rec.includes("Anomaly") || rec.includes("alert") ? "rgba(244, 63, 94, 0.05)" : "rgba(16, 185, 129, 0.05)", 
                  border: `1px solid ${rec.includes("Anomaly") || rec.includes("alert") ? THEME.critical : THEME.healthy}22`,
                  borderRadius: 12, 
                  fontSize: 12, lineHeight: 1.5,
                  color: THEME.text,
                  display: "flex", gap: 12
                }}>
                  <span style={{ fontSize: 16 }}>{rec.includes("Anomaly") || rec.includes("alert") ? "🚨" : "✨"}</span>
                  {rec}
                </div>
              ))}
            </div>
          </div>
        </div>
      </Card>

      {/* Advanced Logging & Audit Trail */}
      <Card title="📜 NOC Operational Audit Trail" badge="LATEST 50 ACTIONS">
        <div style={{ maxHeight: 400, overflowY: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                <Th>Timestamp</Th>
                <Th>Module</Th>
                <Th>Action</Th>
                <Th>Details</Th>
                <Th>Status</Th>
              </tr>
            </thead>
            <tbody>
              {auditTrail && auditTrail.length > 0 ? (
                auditTrail.map((entry, i) => (
                  <TR key={i}>
                    <Td style={{ whiteSpace: "nowrap", color: THEME.subtext, fontSize: 11 }}>
                      {new Date(entry.timestamp).toLocaleString()}
                    </Td>
                    <Td>
                      <span style={{ 
                        fontSize: 9, fontWeight: 700, padding: "2px 6px", borderRadius: 4, 
                        background: "rgba(14, 165, 233, 0.1)", color: THEME.accent, border: `1px solid ${THEME.accent}33`
                      }}>
                        {entry.module}
                      </span>
                    </Td>
                    <Td style={{ fontWeight: 700, fontSize: 12 }}>{entry.action}</Td>
                    <Td style={{ fontSize: 11, color: THEME.subtext, maxWidth: 400 }}>
                      <pre style={{ margin: 0, fontFamily: "inherit", overflow: "hidden", textOverflow: "ellipsis" }}>
                        {JSON.stringify(entry.details)}
                      </pre>
                    </Td>
                    <Td>
                      <span style={{ 
                        fontSize: 10, fontWeight: 800, 
                        color: entry.status === "Success" ? THEME.healthy : THEME.critical 
                      }}>
                        {entry.status?.toUpperCase()}
                      </span>
                    </Td>
                  </TR>
                ))
              ) : (
                <TR><Td colSpan="5" style={{ textAlign: "center", padding: 40, color: THEME.subtext }}>No audit entries found</Td></TR>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

// ── App Root ───────────────────────────────────────────────────────────────────
export default function App() {
  const [tab, setTab]   = useState("dashboard");
  const [time, setTime] = useState("");
  useEffect(() => { const tick=()=>setTime(new Date().toUTCString().slice(17,25)+" UTC"); tick(); const id=setInterval(tick,1000); return ()=>clearInterval(id); }, []);

  const { data: dashData }  = useApi("/dashboard", 15000);
  const { data: liveStats } = useApi("/events/stats", 5000);
  const headerRisk = dashData?.risk_score;

  const TABS = [
    {id:"dashboard", label:"Dashboard", icon:"⬡"},
    {id:"alerts",    label:"Alerts", icon:"🚨"},
    {id:"noc",       label:"NOC Center", icon:"⌬"},
    {id:"remediation",label:"Remediation Hub", icon:"⚡"},
    {id:"scanner",   label:"Vuln Scanner", icon:"◈"},
    {id:"database",  label:"Database", icon:"🔧"},
    {id:"virustotal",label:"VirusTotal", icon:"⚛"},
    {id:"ml",        label:"AI Models", icon:"⚙"},
    {id:"compliance",label:"Compliance", icon:"⚖"},
  ];

  return (
    <div style={{ 
      background: THEME.bg, 
      color: THEME.text, 
      minHeight: "100vh", 
      fontFamily: "'Inter', sans-serif",
      display: "flex"
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Syne:wght@400;600;700;800&family=JetBrains+Mono:wght@400;700&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #0f172a; overflow: hidden; }
        ::-webkit-scrollbar { width: 5px; height: 5px; } 
        ::-webkit-scrollbar-track { background: transparent; } 
        ::-webkit-scrollbar-thumb { background: #334155; border-radius: 10px; }
        ::-webkit-scrollbar-thumb:hover { background: #475569; }
        
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.4} }
        @keyframes pulse { 0%,100%{transform: scale(1)} 50%{transform: scale(1.05)} }
        @keyframes row-appear { from{opacity:0;transform:translateX(-10px)} to{opacity:1;transform:translateX(0)} }
        @keyframes skeleton-shimmer { 0% { background-position: -200% 0; } 100% { background-position: 200% 0; } }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        
        .skeleton {
          background: linear-gradient(90deg, rgba(51, 65, 85, 0.2) 25%, rgba(51, 65, 85, 0.4) 50%, rgba(51, 65, 85, 0.2) 75%);
          background-size: 200% 100%;
          animation: skeleton-shimmer 2s infinite linear;
        }
        
        .table-row:hover { background: rgba(255, 255, 255, 0.03) !important; }
        .sidebar-item { transition: all 0.2s ease; position: relative; }
        .sidebar-item:hover { background: rgba(14, 165, 233, 0.08); color: #0ea5e9; transform: translateX(4px); }
        .sidebar-active { background: rgba(14, 165, 233, 0.12); color: #0ea5e9; border-left: 3px solid #0ea5e9; box-shadow: inset 4px 0 10px -5px rgba(14, 165, 233, 0.3); }
        .sidebar-active span { text-shadow: 0 0 10px #0ea5e9; }
        
        .glass-panel {
          background: rgba(15, 23, 42, 0.8);
          backdrop-filter: blur(16px);
          -webkit-backdrop-filter: blur(16px);
        }
      `}</style>

      {/* Sidebar Navigation */}
      <aside className="glass-panel" style={{ 
        width: 260, 
        borderRight: `1px solid ${THEME.border}`, 
        display: "flex", 
        flexDirection: "column",
        flexShrink: 0,
        zIndex: 101
      }}>
        <div style={{ padding: "30px 24px", display: "flex", alignItems: "center", gap: 14 }}>
          <div style={{ 
            width: 40, height: 40, 
            background: "linear-gradient(135deg, #0ea5e9, #0284c7)", 
            borderRadius: 10,
            display: "flex", alignItems: "center", justifyContent: "center",
            boxShadow: "0 0 20px rgba(14, 165, 233, 0.4)"
          }}>
            <span style={{ fontSize: 20, fontWeight: 800, color: "#fff" }}>⬡</span>
          </div>
          <div>
            <div style={{ fontFamily: "Syne,sans-serif", fontWeight: 800, fontSize: 18, letterSpacing: "0.05em", color: THEME.text }}>ICOC-LITE</div>
            <div style={{ fontSize: 9, color: THEME.subtext, letterSpacing: "0.1em", textTransform: "uppercase", fontWeight: 600 }}>Command Center v1.0</div>
          </div>
        </div>

        <nav style={{ flex: 1, padding: "10px 16px", display: "flex", flexDirection: "column", gap: 4 }}>
          {TABS.map(t => (
            <div 
              key={t.id} 
              onClick={() => setTab(t.id)} 
              className={`sidebar-item ${tab === t.id ? "sidebar-active" : ""}`}
              style={{ 
                padding: "12px 16px", 
                borderRadius: 8, 
                cursor: "pointer", 
                display: "flex", 
                alignItems: "center", 
                gap: 12,
                fontSize: 14,
                fontWeight: tab === t.id ? 600 : 500,
                color: tab === t.id ? THEME.accent : THEME.subtext
              }}
            >
              <span style={{ fontSize: 18, width: 24, textAlign: "center" }}>{t.icon}</span>
              {t.label}
            </div>
          ))}
        </nav>

        <div style={{ padding: 24, borderTop: `1px solid ${THEME.border}` }}>
          {headerRisk && (
            <div style={{ 
              background: `${headerRisk.color}15`, 
              border: `1px solid ${headerRisk.color}33`, 
              borderRadius: 10, 
              padding: 14 
            }}>
              <div style={{ fontSize: 10, color: THEME.subtext, marginBottom: 8, textTransform: "uppercase", fontWeight: 600 }}>Global Risk Level</div>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <div style={{ width: 10, height: 10, borderRadius: "50%", background: headerRisk.color, boxShadow: `0 0 10px ${headerRisk.color}` }} />
                <span style={{ fontSize: 15, color: headerRisk.color, fontWeight: 800 }}>{headerRisk.score}% <span style={{ fontSize: 11, opacity: 0.8 }}>({headerRisk.level.toUpperCase()})</span></span>
              </div>
            </div>
          )}
        </div>
      </aside>

      {/* Main Content Area */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", height: "100vh", overflow: "hidden", background: "radial-gradient(circle at top right, rgba(14, 165, 233, 0.05), transparent)" }}>
        
        {/* Command Center Bar */}
        <header className="glass-panel" style={{ 
          height: 70, 
          borderBottom: `1px solid ${THEME.border}`, 
          display: "flex", 
          alignItems: "center", 
          justifyContent: "space-between", 
          padding: "0 32px",
          zIndex: 100
        }}>
          <div>
            <h1 style={{ fontSize: 18, fontWeight: 700, color: THEME.text }}>{TABS.find(t=>t.id===tab)?.label}</h1>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 24 }}>
            {liveStats && (liveStats.severity_breakdown?.Critical > 0 || liveStats.severity_breakdown?.High > 0) && (
              <div style={{ display: "flex", gap: 12 }}>
                {liveStats.severity_breakdown?.Critical > 0 && (
                  <div style={{ 
                    background: "rgba(244, 63, 94, 0.1)", 
                    border: "1px solid rgba(244, 63, 94, 0.3)", 
                    padding: "6px 14px", borderRadius: 20,
                    display: "flex", alignItems: "center", gap: 8,
                    animation: "blink 2s infinite"
                  }}>
                    <span style={{ width: 8, height: 8, borderRadius: "50%", background: THEME.critical }} />
                    <span style={{ fontSize: 11, fontWeight: 800, color: THEME.critical }}>{liveStats.severity_breakdown.Critical} CRITICAL</span>
                  </div>
                )}
                {liveStats.severity_breakdown?.High > 0 && (
                  <div style={{ 
                    background: "rgba(251, 146, 60, 0.1)", 
                    border: "1px solid rgba(251, 146, 60, 0.3)", 
                    padding: "6px 14px", borderRadius: 20,
                    display: "flex", alignItems: "center", gap: 8
                  }}>
                    <span style={{ width: 8, height: 8, borderRadius: "50%", background: "#fb923c" }} />
                    <span style={{ fontSize: 11, fontWeight: 800, color: "#fb923c" }}>{liveStats.severity_breakdown.High} HIGH</span>
                  </div>
                )}
              </div>
            )}
            
            <div style={{ display: "flex", alignItems: "center", gap: 10, color: THEME.subtext, fontSize: 12, fontWeight: 500, paddingLeft: 24, borderLeft: `1px solid ${THEME.border}` }}>
              <span style={{ color: THEME.accent }}>🕒</span> {time}
            </div>
          </div>
        </header>

        {/* Viewport */}
        <main style={{ flex: 1, padding: "32px", overflowY: "auto", position: "relative" }}>
          <div style={{ maxWidth: 1400, margin: "0 auto" }}>
            {tab === "dashboard"  && <DashboardTab />}
            {tab === "alerts"     && <AlertsTab />}
            {tab === "noc"        && <NOCTab />}
            {tab === "remediation" && <RemediationTab />}
            {tab === "database"   && <DatabaseTab />}
            {tab === "scanner"    && <ScannerTab />}
            {tab === "virustotal" && <VTTab />}
            {tab === "ml"         && <MLTab />}
            {tab === "compliance" && <ComplianceTab />}
          </div>
          
          <footer style={{ marginTop: 60, paddingBottom: 20, textAlign: "center", fontSize: 11, color: THEME.subtext, opacity: 0.6 }}>
            ICOC-LITE FRAMEWORK · NETWORK OPERATIONS & AI SECURITY · ACADEMIC LAB v1.0
          </footer>
        </main>
      </div>
    </div>
  );
}
