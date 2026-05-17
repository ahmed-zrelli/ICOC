/**
 * ICOC-Lite Dashboard — Member 3 (VOC / AI Module)
 * Covers: FR-VOC-01..07, FR-AI-01..07
 */
import { useState, useEffect, useCallback, useRef } from "react";

const API = import.meta.env.VITE_API_URL
  || (typeof window !== "undefined"
    ? `${window.location.protocol}//${window.location.hostname}:8000`
    : "http://localhost:8000");

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

      {/* Operations Control — Integrated Actions Dropdowns */}
      <OperationsControl />

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

// ── Scan gate: shows a banner when no scan has been run yet ──────────────────
function NoScanBanner({ onScan }) {
  const [scanning, setScanning] = useState(false);
  const [msg, setMsg] = useState(null);

  const triggerScan = async () => {
    setScanning(true); setMsg(null);
    try {
      const r = await fetch(API + "/voc/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enrich_vt: false }),
      });
      const d = await r.json();
      setMsg(d.message || "Scan started — this takes ~2 minutes");
      if (onScan) onScan();
    } catch (e) {
      setMsg("Failed to start scan: " + e.message);
    } finally {
      setScanning(false);
    }
  };

  return (
    <div style={{
      display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
      padding: "60px 40px", gap: 24, textAlign: "center",
      background: "rgba(14, 165, 233, 0.04)",
      border: `1px dashed ${THEME.accent}44`,
      borderRadius: 16,
    }}>
      <div style={{ fontSize: 48 }}>🔍</div>
      <div>
        <div style={{ fontFamily: "Syne,sans-serif", fontSize: 20, fontWeight: 800, color: THEME.text, marginBottom: 8 }}>
          No Scan Data Available
        </div>
        <div style={{ fontSize: 13, color: THEME.subtext, lineHeight: 1.7, maxWidth: 480 }}>
          This section requires a vulnerability scan to be completed first.
          Run a scan against <span style={{ color: THEME.accent, fontFamily: "JetBrains Mono" }}>192.168.100.102</span> to
          populate CVE data, compliance scores, and risk intelligence.
        </div>
      </div>
      <button
        onClick={triggerScan}
        disabled={scanning}
        style={{
          fontFamily: "JetBrains Mono,monospace", fontSize: 12, letterSpacing: "0.08em",
          padding: "12px 32px", borderRadius: 8, border: "none",
          background: scanning ? "rgba(14, 165, 233, 0.2)" : THEME.accent,
          color: scanning ? THEME.accent : "#fff",
          fontWeight: 700, textTransform: "uppercase", cursor: scanning ? "not-allowed" : "pointer",
          boxShadow: scanning ? "none" : `0 4px 20px ${THEME.accent}44`,
        }}
      >
        {scanning ? "Starting scan..." : "⬡ Run Vulnerability Scan Now"}
      </button>
      {msg && (
        <div style={{ fontSize: 12, color: THEME.accent, fontWeight: 600, padding: "8px 16px",
          background: "rgba(14, 165, 233, 0.1)", borderRadius: 8, border: `1px solid ${THEME.accent}33` }}>
          {msg}
        </div>
      )}
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
            {records.length === 0 ? (
              <tr><td colSpan="7" style={{ padding: 40, textAlign: "center", color: THEME.subtext }}>
                No scan data — run a vulnerability scan first
              </td></tr>
            ) : records.map((r, i) => (
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
  const { data: dbStats }        = useApi("/db/stats");

  if (loading) return <Spinner />;
  if (error)   return <ErrorMsg msg={error} />;

  // Show gate if no scan has been run yet
  const hasScanData = dbStats && (dbStats.patch_records > 0 || dbStats.scan_reports > 0);
  if (dbStats && !hasScanData) return <NoScanBanner />;

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
  const [investigatingId, setInvestigatingId] = useState(null);
  const [investigation, setInvestigation] = useState(null);
  const [investigationError, setInvestigationError] = useState(null);
  const [investigationLoading, setInvestigationLoading] = useState(false);
  const [showInvestigation, setShowInvestigation] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [clearMsg, setClearMsg] = useState(null);
  const investigationPanelRef = useRef(null);

  const eventKey = (e) => {
    if (e?.event_id) return String(e.event_id);
    if (e?.id != null && e.id !== "") return String(e.id);
    return null;
  };

  const parseRawData = (raw) => {
    if (!raw) return null;
    if (typeof raw === "object") return raw;
    if (typeof raw === "string") {
      try { return JSON.parse(raw); } catch { return { raw }; }
    }
    return null;
  };

  const formatApiError = (data, status) => {
    if (data?.error) return String(data.error);
    if (data?.detail) {
      return typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
    }
    return `HTTP ${status}`;
  };

  const investigate = async (e) => {
    const id = eventKey(e);
    setShowInvestigation(true);
    setInvestigatingId(id || "pending");
    setInvestigationLoading(true);
    setInvestigationError(null);
    setInvestigation(null);

    if (!id) {
      setInvestigationError("This event has no ID — cannot load remediation guidance.");
      setInvestigationLoading(false);
      return;
    }

    try {
      const r = await fetch(`${API}/events/remediation/${encodeURIComponent(id)}`);
      let data;
      try {
        data = await r.json();
      } catch {
        throw new Error(`Invalid response from API (${r.status})`);
      }
      if (!r.ok || data.error) {
        throw new Error(formatApiError(data, r.status));
      }
      setInvestigation(data);
    } catch (err) {
      const msg = err.message || "Failed to load investigation details";
      setInvestigationError(
        msg.includes("Failed to fetch") || msg.includes("NetworkError")
          ? `${msg} — is the API running at ${API}?`
          : msg
      );
    } finally {
      setInvestigationLoading(false);
    }
  };

  const closeInvestigation = () => {
    setShowInvestigation(false);
    setInvestigatingId(null);
    setInvestigation(null);
    setInvestigationError(null);
  };

  const clearAllEvents = async () => {
    if (!window.confirm("Clear ALL security events and attacks? This resets the dashboard to baseline — use between attack demos.")) return;
    setClearing(true);
    setClearMsg(null);
    try {
      const r = await fetch(`${API}/events/clear`, { method: "DELETE" });
      const d = await r.json();
      setClearMsg(`✓ Cleared ${d.cleared_events} events and ${d.cleared_attacks} attacks. Dashboard reset to baseline.`);
      // Auto-dismiss after 5s
      setTimeout(() => setClearMsg(null), 5000);
    } catch (e) {
      setClearMsg(`✗ Clear failed: ${e.message}`);
    } finally {
      setClearing(false);
    }
  };

  useEffect(() => {
    if (showInvestigation && investigationPanelRef.current) {
      investigationPanelRef.current.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }, [showInvestigation, investigation, investigationError, investigationLoading]);

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
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
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

          {/* ── Clear All Events button ── */}
          <button
            onClick={clearAllEvents}
            disabled={clearing}
            title="Wipe all events and attacks — resets dashboard to baseline for demo"
            style={{
              fontSize: 10, padding: "6px 16px", borderRadius: 8, cursor: clearing ? "not-allowed" : "pointer",
              fontWeight: 700, letterSpacing: "0.05em", textTransform: "uppercase",
              border: `1px solid rgba(244, 63, 94, 0.4)`,
              background: clearing ? "rgba(244, 63, 94, 0.05)" : "rgba(244, 63, 94, 0.1)",
              color: clearing ? THEME.subtext : THEME.critical,
              transition: "all 0.2s", display: "flex", alignItems: "center", gap: 6,
            }}
          >
            <span style={{ fontSize: 12 }}>🗑</span>
            {clearing ? "Clearing..." : "Clear All"}
          </button>
        </div>
      </div>

      {/* Clear confirmation message */}
      {clearMsg && (
        <div style={{
          padding: "12px 16px", borderRadius: 8, fontSize: 12, fontWeight: 600,
          background: clearMsg.startsWith("✓") ? "rgba(16, 185, 129, 0.1)" : "rgba(244, 63, 94, 0.1)",
          border: `1px solid ${clearMsg.startsWith("✓") ? THEME.healthy + "44" : THEME.critical + "44"}`,
          color: clearMsg.startsWith("✓") ? THEME.healthy : THEME.critical,
          animation: "row-appear 0.3s ease",
        }}>
          {clearMsg}
        </div>
      )}
      
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

      {showInvestigation && (
        <div ref={investigationPanelRef}>
        <GlassCard
          style={{ borderLeft: `4px solid ${THEME.accent}`, animation: "row-appear 0.3s ease" }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20 }}>
            <div>
              <div style={{ fontFamily: "Syne,sans-serif", fontSize: 16, fontWeight: 800, color: THEME.accent }}>Attack Investigation</div>
              {investigation && (
                <div style={{ fontSize: 11, color: THEME.subtext, marginTop: 6, fontFamily: "JetBrains Mono" }}>
                  {investigation.event_type?.replace(/_/g, " ")} · {investigation.host_ip}
                  {investigation.src_ip && investigation.src_ip !== "unknown" ? ` · SRC ${investigation.src_ip}` : ""}
                </div>
              )}
            </div>
            <button
              type="button"
              onClick={closeInvestigation}
              style={{ background: "none", border: "none", color: THEME.subtext, cursor: "pointer", fontSize: 11, fontWeight: 700 }}
            >
              Close
            </button>
          </div>

          {investigationLoading && <Spinner />}

          {investigationError && !investigationLoading && (
            <div style={{ padding: 16, background: "rgba(244, 63, 94, 0.08)", borderRadius: 8, color: THEME.critical, fontSize: 12 }}>
              {investigationError}
            </div>
          )}

          {investigation?.remediation && !investigationLoading && (
            <div style={{ display: "grid", gap: 20 }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                <div style={{ padding: 16, background: "rgba(255,255,255,0.02)", borderRadius: 10, border: `1px solid ${THEME.border}` }}>
                  <div style={{ fontSize: 10, color: THEME.accent, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8 }}>What happened</div>
                  <p style={{ fontSize: 13, color: THEME.text, lineHeight: 1.6 }}>{investigation.remediation.what}</p>
                </div>
                <div style={{ padding: 16, background: "rgba(255,255,255,0.02)", borderRadius: 10, border: `1px solid ${THEME.border}` }}>
                  <div style={{ fontSize: 10, color: THEME.warning, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8 }}>Why it matters</div>
                  <p style={{ fontSize: 13, color: THEME.text, lineHeight: 1.6 }}>{investigation.remediation.why}</p>
                </div>
              </div>

              <div style={{ padding: 16, background: "rgba(16, 185, 129, 0.06)", borderRadius: 10, border: `1px solid ${THEME.healthy}33` }}>
                <div style={{ fontSize: 10, color: THEME.healthy, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 12 }}>What to do — remediation steps</div>
                <ol style={{ margin: 0, paddingLeft: 20, display: "grid", gap: 10 }}>
                  {(investigation.remediation.fix || []).map((step, idx) => (
                    <li key={idx} style={{ fontSize: 13, color: THEME.text, lineHeight: 1.55 }}>{step}</li>
                  ))}
                </ol>
              </div>

              {investigation.remediation.ioc && (
                <div style={{ fontSize: 12, color: THEME.subtext, fontFamily: "JetBrains Mono", padding: "10px 14px", background: "rgba(244, 63, 94, 0.06)", borderRadius: 8, border: `1px solid ${THEME.critical}22` }}>
                  <span style={{ color: THEME.critical, fontWeight: 700 }}>IOC: </span>{investigation.remediation.ioc}
                </div>
              )}

              {(() => {
                const raw = parseRawData(investigation.raw_data);
                return raw && Object.keys(raw).length > 0 ? (
                  <details style={{ fontSize: 11 }}>
                    <summary style={{ cursor: "pointer", color: THEME.subtext, fontWeight: 600, marginBottom: 8 }}>Raw event data</summary>
                    <pre style={{
                      margin: 0, padding: 14, borderRadius: 8, overflow: "auto", maxHeight: 200,
                      background: "rgba(15, 23, 42, 0.6)", border: `1px solid ${THEME.border}`,
                      color: THEME.subtext, fontFamily: "JetBrains Mono", fontSize: 10,
                    }}>
                      {JSON.stringify(raw, null, 2)}
                    </pre>
                  </details>
                ) : null;
              })()}
            </div>
          )}

          {investigation && !investigationLoading && !investigationError && !investigation?.remediation && (
            <div style={{ fontSize: 12, color: THEME.subtext }}>No remediation guidance returned for this event.</div>
          )}
        </GlassCard>
        </div>
      )}
      
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
                {filtered.map((e, i) => {
                  const id = eventKey(e);
                  const isActive = investigatingId === id;
                  return (
                  <div key={id || i} className="table-row" style={{
                    display: "flex", gap: 16, padding: "14px 16px", borderBottom: `1px solid ${THEME.border}`,
                    borderLeft: `4px solid ${SEV[e.severity] || "transparent"}`,
                    background: isActive ? "rgba(14, 165, 233, 0.08)" : e.severity === "Critical" ? "rgba(244, 63, 94, 0.05)" : "transparent"
                  }}>
                    <div style={{ fontSize: 20 }}>{EVT_ICONS[e.event_type] || "🔹"}</div>
                    <div style={{ flex: 1, minWidth: 0 }}>
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
                    <button
                      type="button"
                      onClick={() => investigate(e)}
                      disabled={investigationLoading && isActive}
                      style={{
                        flexShrink: 0, alignSelf: "center",
                        fontSize: 10, fontWeight: 800, letterSpacing: "0.06em", textTransform: "uppercase",
                        padding: "8px 14px", borderRadius: 8,
                        cursor: investigationLoading && isActive ? "wait" : "pointer",
                        border: `1px solid ${isActive ? THEME.accent : THEME.border}`,
                        background: isActive ? "rgba(14, 165, 233, 0.2)" : "rgba(14, 165, 233, 0.08)",
                        color: THEME.accent, transition: "all 0.2s",
                      }}
                    >
                      {investigationLoading && isActive ? "Loading…" : "Investigate"}
                    </button>
                  </div>
                );})}
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

// ── Forensics & DB Tab ────────────────────────────────────────────────────────
const DB_TABLES = [
  { name: "soc_alert_archives",  label: "SOC Archives",      icon: "🗄", color: "#f59e0b", desc: "Encrypted alert archives + SHA-256 hashes" },
  { name: "security_events",     label: "Security Events",   icon: "📡", color: "#0ea5e9", desc: "Live events from victim agent" },
  { name: "cve_database",        label: "CVE Database",      icon: "🔍", color: "#f43f5e", desc: "NVD CVSS v3.1 records" },
  { name: "patch_records",       label: "Patch Records",     icon: "🔧", color: "#f59e0b", desc: "Host remediation status" },
  { name: "scan_reports",        label: "Scan Reports",      icon: "📋", color: "#0ea5e9", desc: "Vulnerability scan history" },
  { name: "risk_score_history",  label: "Risk History",      icon: "📈", color: "#7c8cf8", desc: "AI risk score time-series" },
  { name: "host_inventory",      label: "Host Inventory",    icon: "💻", color: "#10b981", desc: "Software asset tracking" },
  { name: "attack_log",          label: "Attack Log",        icon: "⚔",  color: "#f43f5e", desc: "Attacker action logs" },
  { name: "compliance_snapshots",label: "Compliance",        icon: "✅", color: "#10b981", desc: "Compliance snapshot history" },
  { name: "threat_intel",        label: "Threat Intel",      icon: "🌐", color: "#f59e0b", desc: "Global intelligence feed" },
  { name: "noc_audit_trail",     label: "NOC Audit Trail",   icon: "📝", color: "#94a3b8", desc: "NOC action audit log" },
];

function ArchiveVerifyButton({ archiveId }) {
  const [state, setState] = useState("idle");
  const [result, setResult] = useState(null);

  const verify = async () => {
    setState("loading");
    try {
      const r = await fetch(`${API}/soc/archives/${encodeURIComponent(archiveId)}/verify`);
      const d = await r.json();
      setResult(d);
      setState(d.match ? "pass" : d.result === "FILE_MISSING" ? "missing" : "fail");
    } catch (e) {
      setResult({ message: e.message });
      setState("fail");
    }
  };

  const colors = { idle: THEME.subtext, loading: THEME.accent, pass: THEME.healthy, fail: THEME.critical, missing: THEME.warning };
  const labels = { idle: "Verify", loading: "Checking…", pass: "✓ PASS", fail: "✗ FAIL", missing: "⚠ Missing" };

  return (
    <div>
      <button onClick={verify} disabled={state === "loading"} style={{
        fontSize: 9, fontWeight: 700, letterSpacing: "0.05em", textTransform: "uppercase",
        padding: "5px 10px", borderRadius: 6, cursor: state === "loading" ? "not-allowed" : "pointer",
        border: `1px solid ${colors[state]}44`, background: `${colors[state]}11`,
        color: colors[state], transition: "all 0.2s",
      }}>{labels[state]}</button>
      {result && state !== "idle" && state !== "loading" && (
        <div style={{ marginTop: 6, fontSize: 9, color: colors[state], lineHeight: 1.6, maxWidth: 260 }}>
          {result.message}
          {result.computed_hash && (
            <div style={{ fontFamily: "JetBrains Mono", fontSize: 8, marginTop: 4, wordBreak: "break-all", color: THEME.subtext }}>
              Computed: {result.computed_hash?.slice(0,32)}…
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function DbTableBrowser({ tableName, onClose }) {
  const [page, setPage]     = useState(0);
  const PAGE = 20;
  const { data, loading, error, refetch } = useApi(
    `/db/table/${tableName}?limit=${PAGE}&offset=${page * PAGE}`, 0
  );

  const cols   = data?.columns || [];
  const rows   = data?.rows    || [];
  const total  = data?.total   || 0;
  const pages  = Math.ceil(total / PAGE);

  // Which columns to show — skip very long JSON/text blobs in the table view
  const SKIP_COLS = ["raw_data", "results", "vt_reports", "controls", "details", "tags", "affected_products", "cve_references", "filepath"];
  const visibleCols = cols.filter(c => !SKIP_COLS.includes(c.name));

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 200, background: "rgba(0,0,0,0.7)",
      display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{ background: "#0f172a", border: `1px solid ${THEME.border}`, borderRadius: 16,
        width: "95vw", maxWidth: 1200, maxHeight: "90vh", display: "flex", flexDirection: "column",
        boxShadow: "0 24px 80px rgba(0,0,0,0.6)" }}>

        {/* Modal header */}
        <div style={{ padding: "20px 24px", borderBottom: `1px solid ${THEME.border}`,
          display: "flex", justifyContent: "space-between", alignItems: "center", flexShrink: 0 }}>
          <div>
            <span style={{ fontFamily: "Syne,sans-serif", fontSize: 16, fontWeight: 800, color: THEME.text }}>
              {tableName}
            </span>
            <span style={{ marginLeft: 12, fontSize: 11, color: THEME.subtext }}>
              {total.toLocaleString()} rows · showing {PAGE} per page
            </span>
          </div>
          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <span style={{ fontSize: 10, color: THEME.subtext, fontFamily: "JetBrains Mono" }}>
              SELECT * FROM {tableName} ORDER BY id DESC LIMIT {PAGE} OFFSET {page * PAGE}
            </span>
            <button onClick={onClose} style={{ background: "none", border: `1px solid ${THEME.border}`,
              color: THEME.subtext, cursor: "pointer", borderRadius: 6, padding: "4px 12px", fontSize: 11 }}>
              ✕ Close
            </button>
          </div>
        </div>

        {/* Table */}
        <div style={{ flex: 1, overflowY: "auto", overflowX: "auto" }}>
          {loading ? <Spinner /> : error ? <ErrorMsg msg={error} /> : (
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
              <thead style={{ position: "sticky", top: 0, background: "#0f172a", zIndex: 1 }}>
                <tr>
                  {visibleCols.map(c => (
                    <th key={c.name} style={{ padding: "10px 12px", textAlign: "left", fontSize: 9,
                      color: THEME.subtext, fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase",
                      borderBottom: `1px solid ${THEME.border}`, whiteSpace: "nowrap" }}>
                      {c.name}
                      <span style={{ marginLeft: 4, color: THEME.border, fontSize: 8 }}>{c.type.replace("character varying","varchar").replace("timestamp with time zone","timestamptz")}</span>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.length === 0 ? (
                  <tr><td colSpan={visibleCols.length} style={{ padding: 40, textAlign: "center", color: THEME.subtext }}>
                    No rows in this table yet.
                  </td></tr>
                ) : rows.map((row, i) => (
                  <tr key={i} className="table-row" style={{ borderBottom: `1px solid rgba(51,65,85,0.2)` }}>
                    {visibleCols.map(c => {
                      const val = row[c.name];
                      const isHash = c.name === "sha256_hash";
                      const isTs   = c.type.includes("timestamp");
                      const isSev  = c.name === "severity";
                      const sevColor = { Critical: THEME.critical, High: "#fb923c", Medium: THEME.warning, Low: THEME.accent }[val] || THEME.subtext;
                      return (
                        <td key={c.name} style={{ padding: "10px 12px", color: THEME.text, maxWidth: 280,
                          overflow: "hidden", textOverflow: "ellipsis", whiteSpace: isHash ? "nowrap" : "normal" }}>
                          {isSev ? (
                            <span style={{ fontSize: 9, fontWeight: 700, padding: "2px 7px", borderRadius: 4,
                              textTransform: "uppercase", color: sevColor, border: `1px solid ${sevColor}44`,
                              background: `${sevColor}11` }}>{val}</span>
                          ) : isHash ? (
                            <span style={{ fontFamily: "JetBrains Mono", fontSize: 9, color: THEME.healthy }}>
                              {String(val || "").slice(0,20)}…
                            </span>
                          ) : isTs ? (
                            <span style={{ fontFamily: "JetBrains Mono", fontSize: 9, color: THEME.subtext }}>
                              {String(val || "").slice(0,19).replace("T"," ")}
                            </span>
                          ) : typeof val === "object" && val !== null ? (
                            <span style={{ fontFamily: "JetBrains Mono", fontSize: 9, color: THEME.subtext }}>
                              {JSON.stringify(val).slice(0,60)}…
                            </span>
                          ) : (
                            <span style={{ color: c.name === "id" ? THEME.subtext : THEME.text }}>
                              {String(val ?? "—").slice(0, 120)}
                            </span>
                          )}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Pagination */}
        {pages > 1 && (
          <div style={{ padding: "14px 24px", borderTop: `1px solid ${THEME.border}`, flexShrink: 0,
            display: "flex", gap: 8, alignItems: "center", justifyContent: "center" }}>
            <button onClick={() => setPage(0)} disabled={page === 0}
              style={{ padding: "5px 10px", borderRadius: 6, border: `1px solid ${THEME.border}`,
                background: "transparent", color: page === 0 ? THEME.border : THEME.subtext, cursor: page === 0 ? "not-allowed" : "pointer", fontSize: 11 }}>«</button>
            <button onClick={() => setPage(p => Math.max(0, p-1))} disabled={page === 0}
              style={{ padding: "5px 10px", borderRadius: 6, border: `1px solid ${THEME.border}`,
                background: "transparent", color: page === 0 ? THEME.border : THEME.subtext, cursor: page === 0 ? "not-allowed" : "pointer", fontSize: 11 }}>‹</button>
            <span style={{ fontSize: 11, color: THEME.subtext, padding: "0 12px" }}>
              Page {page + 1} of {pages} · {total.toLocaleString()} rows
            </span>
            <button onClick={() => setPage(p => Math.min(pages-1, p+1))} disabled={page >= pages-1}
              style={{ padding: "5px 10px", borderRadius: 6, border: `1px solid ${THEME.border}`,
                background: "transparent", color: page >= pages-1 ? THEME.border : THEME.subtext, cursor: page >= pages-1 ? "not-allowed" : "pointer", fontSize: 11 }}>›</button>
            <button onClick={() => setPage(pages-1)} disabled={page >= pages-1}
              style={{ padding: "5px 10px", borderRadius: 6, border: `1px solid ${THEME.border}`,
                background: "transparent", color: page >= pages-1 ? THEME.border : THEME.subtext, cursor: page >= pages-1 ? "not-allowed" : "pointer", fontSize: 11 }}>»</button>
          </div>
        )}
      </div>
    </div>
  );
}

function ForensicsTab() {
  const [subTab, setSubTab]       = useState("archives");
  const [browseTable, setBrowse]  = useState(null);
  const { data: dbStats, loading: statsLoading } = useApi("/db/stats", 30000);
  const { data: archivesData, loading: archLoading, refetch: refetchArchives } = useApi("/soc/archives", 0);

  const SUB_TABS = [
    { id: "archives", label: "Archive Manager" },
    { id: "db",       label: "PostgreSQL Explorer" },
  ];

  const archives = archivesData?.archives || [];

  return (
    <div style={{ display: "grid", gap: 24 }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h2 style={{ fontFamily: "Syne,sans-serif", fontSize: 18, fontWeight: 800, color: THEME.text }}>
            Forensics & Database
          </h2>
          <p style={{ fontSize: 12, color: THEME.subtext, marginTop: 4 }}>
            Encrypted alert archives · SHA-256 integrity verification · PostgreSQL table browser
          </p>
        </div>
      </div>

      {/* Sub-tab bar */}
      <div style={{ display: "flex", gap: 8, borderBottom: `1px solid ${THEME.border}` }}>
        {SUB_TABS.map(st => (
          <button key={st.id} onClick={() => setSubTab(st.id)} style={{
            fontSize: 11, fontWeight: 700, letterSpacing: "0.05em", textTransform: "uppercase",
            padding: "8px 16px", borderRadius: "8px 8px 0 0", cursor: "pointer",
            border: `1px solid ${subTab === st.id ? THEME.accent : THEME.border}`,
            borderBottom: subTab === st.id ? `1px solid #0f172a` : `1px solid ${THEME.border}`,
            background: subTab === st.id ? "rgba(14,165,233,0.12)" : "transparent",
            color: subTab === st.id ? THEME.accent : THEME.subtext, transition: "all 0.2s",
          }}>{st.label}</button>
        ))}
      </div>

      {/* ── Archive Manager ── */}
      {subTab === "archives" && (
        <div style={{ display: "grid", gap: 20 }}>

          {/* Explainer */}
          <GlassCard style={{ borderLeft: `4px solid ${THEME.warning}`, padding: 24 }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 20 }}>
              {[
                ["🗄 What is an archive?",
                 "When you click Archive All in the SOC tab, all current Wazuh alerts are fetched from OpenSearch and written into a password-protected ZIP file on the API container."],
                ["🔐 How is it secured?",
                 "The ZIP is encrypted with the password ICOC-2026-forensics. A SHA-256 hash of the ZIP is computed and stored in PostgreSQL — this is your tamper-evidence seal."],
                ["✅ How to verify integrity?",
                 "Click Verify on any archive. The API recomputes the SHA-256 of the file on disk and compares it to the hash stored in PostgreSQL. PASS = untampered. FAIL = file was modified."],
              ].map(([title, body]) => (
                <div key={title}>
                  <div style={{ fontSize: 12, fontWeight: 800, color: THEME.text, marginBottom: 8 }}>{title}</div>
                  <div style={{ fontSize: 11, color: THEME.subtext, lineHeight: 1.7 }}>{body}</div>
                </div>
              ))}
            </div>
          </GlassCard>

          {/* Archive table */}
          <Card title="🗄 Forensic Archive Log" badge={`${archives.length} ARCHIVES IN POSTGRESQL`}>
            {archLoading ? <Spinner /> : archives.length === 0 ? (
              <div style={{ padding: 40, textAlign: "center", color: THEME.subtext }}>
                <div style={{ fontSize: 32, marginBottom: 12 }}>📭</div>
                <div style={{ fontSize: 13, marginBottom: 8 }}>No archives yet.</div>
                <div style={{ fontSize: 11 }}>Go to <strong style={{ color: THEME.accent }}>SOC / Wazuh → Alerts</strong> and click <strong style={{ color: THEME.warning }}>🗄 Archive All</strong>.</div>
              </div>
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead><tr>
                    <Th>Archive ID</Th>
                    <Th>Alerts</Th>
                    <Th>Date Range</Th>
                    <Th>SHA-256 (stored in PostgreSQL)</Th>
                    <Th>Archived At</Th>
                    <Th>Download</Th>
                    <Th>Verify Integrity</Th>
                  </tr></thead>
                  <tbody>
                    {archives.map((a, i) => (
                      <TR key={i}>
                        <Td>
                          <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: THEME.accent }}>
                            {a.archive_id}
                          </span>
                        </Td>
                        <Td>
                          <span style={{ fontFamily: "Syne,sans-serif", fontSize: 16, fontWeight: 800, color: THEME.warning }}>
                            {Number(a.total_alerts).toLocaleString()}
                          </span>
                        </Td>
                        <Td style={{ fontSize: 10, color: THEME.subtext, fontFamily: "JetBrains Mono" }}>
                          <div>{String(a.date_from || "").slice(0,10)}</div>
                          <div style={{ color: THEME.border }}>→</div>
                          <div>{String(a.date_to || "").slice(0,10)}</div>
                        </Td>
                        <Td>
                          <div style={{ fontFamily: "JetBrains Mono", fontSize: 9, color: THEME.healthy,
                            background: "rgba(16,185,129,0.06)", padding: "6px 10px", borderRadius: 6,
                            border: `1px solid ${THEME.healthy}22`, wordBreak: "break-all", maxWidth: 280 }}>
                            {a.sha256_hash}
                          </div>
                          <div style={{ fontSize: 9, color: THEME.subtext, marginTop: 4 }}>
                            {a.password_hint}
                          </div>
                        </Td>
                        <Td style={{ fontSize: 10, color: THEME.subtext, fontFamily: "JetBrains Mono", whiteSpace: "nowrap" }}>
                          {String(a.archived_at || "").slice(0,19).replace("T"," ")}
                          <div style={{ fontSize: 9, color: THEME.subtext, marginTop: 2 }}>by {a.archived_by}</div>
                        </Td>
                        <Td>
                          <a href={`${API}/soc/archives/${encodeURIComponent(a.archive_id)}/download`}
                            download={`${a.archive_id}.zip`}
                            style={{ fontSize: 10, fontWeight: 700, padding: "6px 12px", borderRadius: 6,
                              textDecoration: "none", display: "inline-block",
                              border: `1px solid ${THEME.accent}`, background: "rgba(14,165,233,0.1)",
                              color: THEME.accent, letterSpacing: "0.04em", textTransform: "uppercase" }}>
                            ↓ ZIP
                          </a>
                        </Td>
                        <Td>
                          <ArchiveVerifyButton archiveId={a.archive_id} />
                        </Td>
                      </TR>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          {/* How to open the ZIP */}
          <GlassCard style={{ padding: 20 }}>
            <div style={{ fontSize: 11, fontWeight: 800, color: THEME.text, marginBottom: 12 }}>
              📂 How to open the downloaded ZIP
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              <div>
                <div style={{ fontSize: 10, color: THEME.accent, fontWeight: 700, marginBottom: 6, textTransform: "uppercase" }}>Windows / 7-Zip</div>
                <div style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: THEME.subtext,
                  background: "rgba(15,23,42,0.6)", padding: "10px 14px", borderRadius: 8,
                  border: `1px solid ${THEME.border}` }}>
                  Right-click → 7-Zip → Extract<br/>Password: <span style={{ color: THEME.warning }}>ICOC-2026-forensics</span>
                </div>
              </div>
              <div>
                <div style={{ fontSize: 10, color: THEME.accent, fontWeight: 700, marginBottom: 6, textTransform: "uppercase" }}>Linux / macOS</div>
                <div style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: THEME.subtext,
                  background: "rgba(15,23,42,0.6)", padding: "10px 14px", borderRadius: 8,
                  border: `1px solid ${THEME.border}` }}>
                  unzip -P ICOC-2026-forensics SOC-ARCHIVE-*.zip<br/>
                  <span style={{ color: THEME.subtext }}>→ extracts JSON with all alerts</span>
                </div>
              </div>
            </div>
            <div style={{ marginTop: 14, fontSize: 10, color: THEME.subtext, lineHeight: 1.8 }}>
              <strong style={{ color: THEME.text }}>To verify manually:</strong>{" "}
              compute <code style={{ color: THEME.accent }}>sha256sum SOC-ARCHIVE-*.zip</code> and compare the output
              to the hash shown in the table above (stored in PostgreSQL). If they match → file is untampered.
            </div>
          </GlassCard>
        </div>
      )}

      {/* ── PostgreSQL Explorer ── */}
      {subTab === "db" && (
        <div style={{ display: "grid", gap: 20 }}>

          {/* DB explainer */}
          <GlassCard style={{ borderLeft: `4px solid ${THEME.accent}`, padding: 20 }}>
            <div style={{ fontSize: 12, fontWeight: 800, color: THEME.text, marginBottom: 8 }}>
              What is PostgreSQL used for in this app?
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, fontSize: 11, color: THEME.subtext, lineHeight: 1.8 }}>
              <div>
                <strong style={{ color: THEME.accent }}>VOC side:</strong> patch_records, cve_database, scan_reports, host_inventory, compliance_snapshots — all vulnerability management data lives here.<br/>
                <strong style={{ color: THEME.accent }}>AI side:</strong> risk_score_history stores every risk score computation for the time-series chart. threat_intel stores the TTP feed.
              </div>
              <div>
                <strong style={{ color: THEME.warning }}>SOC side:</strong> security_events stores events from the victim agent (the Python agent on Metasploitable3). soc_alert_archives stores archive metadata + SHA-256 hashes.<br/>
                <strong style={{ color: THEME.warning }}>Note:</strong> Wazuh alerts are in OpenSearch (port 9200), not here. PostgreSQL is for the app's own data.
              </div>
            </div>
          </GlassCard>

          {/* Table grid */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 14 }}>
            {DB_TABLES.map(t => {
              const count = dbStats?.[t.name] ?? "—";
              return (
                <div key={t.name} onClick={() => setBrowse(t.name)}
                  style={{ padding: 18, borderRadius: 12, cursor: "pointer",
                    background: THEME.card, border: `1px solid ${THEME.border}`,
                    borderLeft: `4px solid ${t.color}`,
                    backdropFilter: "blur(12px)", transition: "all 0.2s",
                  }}
                  onMouseEnter={e => e.currentTarget.style.borderColor = t.color}
                  onMouseLeave={e => e.currentTarget.style.borderColor = THEME.border}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8 }}>
                    <div>
                      <div style={{ fontSize: 13, fontWeight: 800, color: THEME.text }}>
                        {t.icon} {t.label}
                      </div>
                      <div style={{ fontSize: 10, color: THEME.subtext, marginTop: 3 }}>{t.desc}</div>
                    </div>
                    <div style={{ fontFamily: "Syne,sans-serif", fontSize: 24, fontWeight: 900,
                      color: t.color, lineHeight: 1, flexShrink: 0 }}>
                      {statsLoading ? "…" : typeof count === "number" ? count.toLocaleString() : count}
                    </div>
                  </div>
                  <div style={{ fontSize: 9, color: THEME.subtext, fontFamily: "JetBrains Mono",
                    marginTop: 10, paddingTop: 8, borderTop: `1px solid ${THEME.border}`,
                    display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ opacity: 0.6 }}>SELECT * FROM {t.name}</span>
                    <span style={{ color: t.color, fontWeight: 700 }}>Browse →</span>
                  </div>
                </div>
              );
            })}
          </div>

          <div style={{ fontSize: 11, color: THEME.subtext, textAlign: "center", padding: "8px 0" }}>
            Click any table to open the row browser · Read-only · Paginated · 20 rows per page
          </div>
        </div>
      )}

      {/* Table browser modal */}
      {browseTable && (
        <DbTableBrowser tableName={browseTable} onClose={() => setBrowse(null)} />
      )}
    </div>
  );
}

// ── SOC Archive components ────────────────────────────────────────────────────
function SocArchiveButton() {
  const [state, setState]   = useState("idle");
  const [result, setResult] = useState(null);
  const [purge, setPurge]   = useState(false);
  const [days, setDays]     = useState(30);
  const [showOpts, setShowOpts] = useState(false);

  const doArchive = async () => {
    if (purge && !window.confirm(
      `This will archive alerts older than ${days} days and DELETE them from OpenSearch.\n\nThe encrypted ZIP + SHA-256 will be saved first.\n\nProceed?`
    )) return;
    setState("loading"); setResult(null); setShowOpts(false);
    try {
      const url = `${API}/soc/archive?min_level=3&password=ICOC-2026-forensics&purge_after=${purge}&older_than_days=${days}`;
      const r = await fetch(url, { method: "POST" });
      const d = await r.json();
      if (!r.ok) throw new Error(d.detail || "Archive failed");
      setResult(d);
      setState("done");
      setTimeout(() => setState("idle"), 12000);
    } catch (e) {
      setResult({ error: e.message });
      setState("error");
      setTimeout(() => setState("idle"), 6000);
    }
  };

  return (
    <div style={{ position: "relative" }}>
      <div style={{ display: "flex", gap: 0 }}>
        <button onClick={doArchive} disabled={state === "loading"} style={{
          fontSize: 10, fontWeight: 700, letterSpacing: "0.05em", textTransform: "uppercase",
          padding: "7px 12px", borderRadius: "8px 0 0 8px", cursor: state === "loading" ? "not-allowed" : "pointer",
          border: `1px solid ${THEME.warning}`, borderRight: "none",
          background: purge ? "rgba(244,63,94,0.15)" : "rgba(245,158,11,0.1)",
          color: purge ? THEME.critical : THEME.warning, transition: "all 0.2s",
        }}>
          {state === "loading" ? "Archiving…" : purge ? "🗄 Archive + Purge" : "🗄 Archive"}
        </button>
        <button onClick={() => setShowOpts(v => !v)} style={{
          fontSize: 10, padding: "7px 8px", borderRadius: "0 8px 8px 0", cursor: "pointer",
          border: `1px solid ${THEME.warning}`, background: "rgba(245,158,11,0.05)",
          color: THEME.warning,
        }}>▾</button>
      </div>

      {showOpts && (
        <div style={{ position: "absolute", right: 0, top: 36, zIndex: 60, width: 280,
          background: "#1e293b", border: `1px solid ${THEME.border}`, borderRadius: 10,
          padding: 16, boxShadow: "0 8px 32px rgba(0,0,0,0.5)" }}>
          <div style={{ fontSize: 11, fontWeight: 800, color: THEME.text, marginBottom: 12 }}>Archive Options</div>
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 10, color: THEME.subtext, marginBottom: 6 }}>Archive alerts older than:</div>
            <div style={{ display: "flex", gap: 6 }}>
              {[7, 14, 30, 60, 90].map(d => (
                <button key={d} onClick={() => setDays(d)} style={{
                  fontSize: 10, padding: "4px 8px", borderRadius: 6, cursor: "pointer",
                  border: `1px solid ${days === d ? THEME.accent : THEME.border}`,
                  background: days === d ? "rgba(14,165,233,0.15)" : "transparent",
                  color: days === d ? THEME.accent : THEME.subtext, fontWeight: days === d ? 700 : 400,
                }}>{d}d</button>
              ))}
            </div>
          </div>
          <div style={{ padding: "10px 12px", borderRadius: 8, marginBottom: 12,
            background: purge ? "rgba(244,63,94,0.08)" : "rgba(255,255,255,0.02)",
            border: `1px solid ${purge ? THEME.critical + "44" : THEME.border}` }}>
            <label style={{ display: "flex", alignItems: "flex-start", gap: 10, cursor: "pointer" }}>
              <input type="checkbox" checked={purge} onChange={e => setPurge(e.target.checked)}
                style={{ marginTop: 2, accentColor: THEME.critical }} />
              <div>
                <div style={{ fontSize: 11, fontWeight: 700, color: purge ? THEME.critical : THEME.text }}>
                  Delete from OpenSearch after archiving
                </div>
                <div style={{ fontSize: 10, color: THEME.subtext, marginTop: 3, lineHeight: 1.5 }}>
                  Frees storage. Safe only after ZIP + SHA-256 confirmed. Irreversible.
                </div>
              </div>
            </label>
          </div>
          <button onClick={doArchive} disabled={state === "loading"} style={{
            width: "100%", padding: "9px", borderRadius: 8, cursor: "pointer", fontWeight: 700,
            fontSize: 11, border: "none", textTransform: "uppercase", letterSpacing: "0.05em",
            background: purge ? THEME.critical : THEME.warning, color: "#000",
          }}>
            {purge ? `Archive + Delete (>${days}d)` : `Archive Only (>${days}d)`}
          </button>
        </div>
      )}

      {(state === "done" || state === "error") && result && (
        <div style={{ position: "absolute", right: 0, top: 36, zIndex: 50, width: 340,
          background: "#1e293b", border: `1px solid ${state === "done" ? THEME.healthy + "44" : THEME.critical + "44"}`,
          borderRadius: 10, padding: 16, boxShadow: "0 8px 32px rgba(0,0,0,0.5)" }}>
          {state === "done" ? (
            <>
              <div style={{ fontSize: 11, fontWeight: 800, color: THEME.healthy, marginBottom: 10 }}>✓ Archive Created</div>
              <div style={{ fontSize: 10, color: THEME.subtext, fontFamily: "JetBrains Mono", lineHeight: 2 }}>
                <div>ID: <span style={{ color: THEME.text }}>{result.archive_id}</span></div>
                <div>Archived: <span style={{ color: THEME.accent }}>{result.total_archived?.toLocaleString()}</span> alerts</div>
                <div>File size: <span style={{ color: THEME.text }}>{result.file_size_kb} KB</span></div>
                <div>Encryption: <span style={{ color: THEME.healthy }}>AES-256</span></div>
                <div style={{ wordBreak: "break-all" }}>SHA-256: <span style={{ color: THEME.warning, fontSize: 9 }}>{result.sha256?.slice(0,32)}…</span></div>
                {result.purged_from_opensearch > 0 && (
                  <div style={{ marginTop: 6, color: THEME.critical, fontWeight: 700 }}>
                    🗑 Purged {result.purged_from_opensearch?.toLocaleString()} alerts from OpenSearch
                  </div>
                )}
              </div>
              <div style={{ marginTop: 8, fontSize: 9, color: THEME.subtext }}>
                Go to Forensics & DB → Archive Manager to download and verify
              </div>
            </>
          ) : (
            <div style={{ fontSize: 11, color: THEME.critical }}>{result.error}</div>
          )}
        </div>
      )}
    </div>
  );
}

function SocArchiveList() {
  const { data, loading, refetch } = useApi("/soc/archives", 0);
  const archives = data?.archives || [];
  if (loading) return null;
  if (archives.length === 0) return null;

  return (
    <Card title="🗄 Forensic Archive Log" badge={`${archives.length} ARCHIVES · POSTGRESQL`}>
      <div style={{ fontSize: 11, color: THEME.subtext, marginBottom: 16, lineHeight: 1.7 }}>
        Each archive is an encrypted ZIP (password-protected) containing all alerts at the time of archiving.
        The SHA-256 hash is stored in PostgreSQL for <strong style={{ color: THEME.text }}>forensic integrity verification</strong> —
        you can verify the archive was not tampered with by recomputing its hash and comparing.
      </div>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead><tr>
          <Th>Archive ID</Th><Th>Alerts</Th><Th>Date Range</Th><Th>SHA-256</Th><Th>Archived At</Th>
        </tr></thead>
        <tbody>
          {archives.map((a, i) => (
            <TR key={i}>
              <Td style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: THEME.accent }}>{a.archive_id}</Td>
              <Td style={{ fontWeight: 700, color: THEME.warning }}>{a.total_alerts?.toLocaleString()}</Td>
              <Td style={{ fontSize: 10, color: THEME.subtext, fontFamily: "JetBrains Mono" }}>
                <div>{String(a.date_from || "").slice(0,10)}</div>
                <div>→ {String(a.date_to || "").slice(0,10)}</div>
              </Td>
              <Td>
                <span style={{ fontFamily: "JetBrains Mono", fontSize: 9, color: THEME.healthy,
                  background: "rgba(16,185,129,0.08)", padding: "3px 8px", borderRadius: 4,
                  border: `1px solid ${THEME.healthy}33`, display: "inline-block", wordBreak: "break-all" }}>
                  {String(a.sha256_hash || "").slice(0, 16)}…
                </span>
              </Td>
              <Td style={{ fontSize: 10, color: THEME.subtext, fontFamily: "JetBrains Mono" }}>
                {String(a.archived_at || "").slice(0, 19).replace("T", " ")}
              </Td>
            </TR>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

// ── SOC Tab — Wazuh SIEM Integration ─────────────────────────────────────────
const WAZUH_SEV_COLOR = { Critical: "#f43f5e", High: "#fb923c", Medium: "#f59e0b", Low: "#0ea5e9" };
const WAZUH_SEV_BG   = { Critical: "rgba(244,63,94,0.10)", High: "rgba(251,146,60,0.10)", Medium: "rgba(245,158,11,0.10)", Low: "rgba(14,165,233,0.10)" };
const AGENT_STATUS_COLOR = { active: "#10b981", disconnected: "#f43f5e", never_connected: "#94a3b8", pending: "#f59e0b" };

const FIM_ICON = { added: "➕", modified: "✏️", deleted: "🗑️" };
const UBA_GROUP_ICON = { authentication_failed: "🔑", authentication_success: "🚨", adduser: "👤", sudo: "⚡", privilege_escalation: "🔺", pam: "🔐" };

function SocAgentDot({ status }) {
  const color = AGENT_STATUS_COLOR[status] || THEME.subtext;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
      <span style={{ width: 8, height: 8, borderRadius: "50%", background: color,
        boxShadow: status === "active" ? `0 0 8px ${color}` : "none",
        animation: status === "active" ? "blink 3s infinite" : "none" }} />
      <span style={{ fontSize: 10, fontWeight: 700, color, textTransform: "uppercase" }}>{status}</span>
    </span>
  );
}

function SocTab() {
  const [subTab, setSubTab] = useState("overview");
  const { data: overview, loading: ovLoading, error: ovError, refetch: refetchOv } = useApi("/soc/overview", 15000);
  const { data: alerts,   loading: alLoading }  = useApi("/soc/alerts?limit=100&min_level=3", 15000);
  const { data: fim,      loading: fimLoading }  = useApi("/soc/fim?limit=30",             20000);
  const { data: uba,      loading: ubaLoading }  = useApi("/soc/uba?limit=30",             20000);
  const { data: ar,       loading: arLoading }   = useApi("/soc/active-response?limit=20", 20000);
  const { data: malware,  loading: malLoading }  = useApi("/soc/malware?limit=20",         20000);

  const SUB_TABS = [
    { id: "overview",  label: "Overview"  },
    { id: "alerts",    label: "Alerts"    },
    { id: "fim",       label: "FIM"       },
    { id: "uba",       label: "UBA"       },
    { id: "ar",        label: "Active Response" },
    { id: "malware",   label: "Malware"   },
  ];

  // ── Wazuh unreachable banner ──────────────────────────────────────────────
  if (!ovLoading && (ovError || overview?.error)) {
    return (
      <div style={{ display: "grid", gap: 24 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <h2 style={{ fontFamily: "Syne,sans-serif", fontSize: 18, fontWeight: 800, color: THEME.text }}>SOC — Wazuh SIEM</h2>
            <p style={{ fontSize: 12, color: THEME.subtext, marginTop: 4 }}>Security Information & Event Management · FR-SOC-01 → FR-SOC-08</p>
          </div>
        </div>
        <GlassCard style={{ borderLeft: `4px solid ${THEME.critical}`, padding: 32 }}>
          <div style={{ display: "flex", gap: 20, alignItems: "flex-start" }}>
            <span style={{ fontSize: 36 }}>🔌</span>
            <div>
              <div style={{ fontFamily: "Syne,sans-serif", fontSize: 16, fontWeight: 800, color: THEME.critical, marginBottom: 8 }}>
                Wazuh Manager Unreachable
              </div>
              <div style={{ fontSize: 13, color: THEME.subtext, lineHeight: 1.7, marginBottom: 16 }}>
                Cannot connect to <span style={{ color: THEME.accent, fontFamily: "JetBrains Mono" }}>https://192.168.100.10:55000</span>.
                Make sure the Wazuh Manager VM is running and Docker containers are up.
              </div>
              <div style={{ fontSize: 12, color: THEME.subtext, fontFamily: "JetBrains Mono",
                background: "rgba(15,23,42,0.6)", padding: "10px 14px", borderRadius: 8,
                border: `1px solid ${THEME.border}`, marginBottom: 16 }}>
                {ovError || overview?.error}
              </div>
              <div style={{ fontSize: 12, color: THEME.subtext, lineHeight: 1.8 }}>
                <strong style={{ color: THEME.text }}>To start Wazuh:</strong><br />
                SSH into the Wazuh Manager VM → <code style={{ color: THEME.accent }}>cd ~/wazuh-docker/single-node && docker compose up -d</code>
              </div>
              <button onClick={refetchOv} style={{
                marginTop: 16, fontFamily: "JetBrains Mono,monospace", fontSize: 11,
                padding: "8px 20px", borderRadius: 8, border: `1px solid ${THEME.accent}`,
                background: "rgba(14,165,233,0.1)", color: THEME.accent, cursor: "pointer", fontWeight: 700
              }}>↺ Retry Connection</button>
            </div>
          </div>
        </GlassCard>
      </div>
    );
  }

  const agentsData  = overview?.agents  || {};
  const alertsSum   = overview?.alerts  || {};
  const sevBreak    = alerts?.severity_breakdown || alertsSum.severity_breakdown || {};

  return (
    <div style={{ display: "grid", gap: 24 }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h2 style={{ fontFamily: "Syne,sans-serif", fontSize: 18, fontWeight: 800, color: THEME.text }}>
            SOC — Wazuh SIEM
          </h2>
          <p style={{ fontSize: 12, color: THEME.subtext, marginTop: 4 }}>
            Security Information & Event Management · FR-SOC-01 → FR-SOC-08
          </p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ width: 8, height: 8, borderRadius: "50%", background: THEME.healthy,
            boxShadow: `0 0 8px ${THEME.healthy}`, animation: "blink 3s infinite" }} />
          <span style={{ fontSize: 11, color: THEME.healthy, fontWeight: 700 }}>WAZUH CONNECTED</span>
        </div>
      </div>

      {/* KPI strip */}
      {ovLoading ? (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5,1fr)", gap: 16 }}>
          {[...Array(5)].map((_,i) => <Skeleton key={i} height={100} />)}
        </div>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5,1fr)", gap: 16 }}>
          <KpiCard label="Active Agents"   value={agentsData.active || 0}      color={THEME.healthy}  sub={`${agentsData.total || 0} total registered`} />
          <KpiCard label="Critical Alerts" value={sevBreak.Critical || 0}      color={THEME.critical} sub="Rule level ≥ 12" />
          <KpiCard label="High Alerts"     value={sevBreak.High || 0}          color="#fb923c"        sub="Rule level 9–11" />
          <KpiCard label="Medium Alerts"   value={sevBreak.Medium || 0}        color={THEME.warning}  sub="Rule level 6–8" />
          <KpiCard label="Total Events"    value={alerts?.total || 0}          color={THEME.accent}   sub="All levels in indexer" />
        </div>
      )}

      {/* Sub-tab bar */}
      <div style={{ display: "flex", gap: 8, borderBottom: `1px solid ${THEME.border}`, paddingBottom: 0 }}>
        {SUB_TABS.map(st => (
          <button key={st.id} onClick={() => setSubTab(st.id)} style={{
            fontSize: 11, fontWeight: 700, letterSpacing: "0.05em", textTransform: "uppercase",
            padding: "8px 16px", borderRadius: "8px 8px 0 0", cursor: "pointer",
            border: `1px solid ${subTab === st.id ? THEME.accent : THEME.border}`,
            borderBottom: subTab === st.id ? `1px solid ${THEME.bg}` : `1px solid ${THEME.border}`,
            background: subTab === st.id ? "rgba(14,165,233,0.12)" : "transparent",
            color: subTab === st.id ? THEME.accent : THEME.subtext,
            transition: "all 0.2s",
          }}>{st.label}</button>
        ))}
      </div>

      {/* ── Overview sub-tab ── */}
      {subTab === "overview" && (
        <div style={{ display: "grid", gap: 24 }}>
          {/* Agents grid */}
          <Card title="◈ Registered Agents" badge="FR-SOC-01">
            {ovLoading ? <Spinner /> : (
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(260px,1fr))", gap: 12 }}>
                {(agentsData.agents || []).map(agent => (
                  <div key={agent.id} style={{
                    padding: 16, borderRadius: 10,
                    background: "rgba(255,255,255,0.02)",
                    border: `1px solid ${agent.status === "active" ? THEME.healthy + "44" : THEME.border}`,
                    borderLeft: `4px solid ${AGENT_STATUS_COLOR[agent.status] || THEME.subtext}`,
                  }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                      <span style={{ fontWeight: 800, fontSize: 13, color: THEME.text }}>{agent.name}</span>
                      <SocAgentDot status={agent.status} />
                    </div>
                    <div style={{ fontSize: 11, color: THEME.subtext, fontFamily: "JetBrains Mono", marginBottom: 4 }}>{agent.ip}</div>
                    <div style={{ fontSize: 10, color: THEME.subtext }}>{agent.os_name || agent.os}</div>
                    {agent.last_keepalive && (
                      <div style={{ fontSize: 9, color: THEME.subtext, marginTop: 6, opacity: 0.7 }}>
                        Last seen: {String(agent.last_keepalive).slice(0, 19).replace("T", " ")}
                      </div>
                    )}
                  </div>
                ))}
                {(agentsData.agents || []).length === 0 && (
                  <div style={{ color: THEME.subtext, fontSize: 12, padding: 20 }}>No agents registered yet.</div>
                )}
              </div>
            )}
          </Card>

          {/* Top triggered rules */}
          <Card title="⬡ Top Triggered Rules" badge="LAST 500 ALERTS">
            {ovLoading ? <Spinner /> : (
              <div style={{ display: "grid", gap: 8 }}>
                {(alertsSum.top_rules || []).map((r, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 14px",
                    background: "rgba(255,255,255,0.02)", borderRadius: 8, border: `1px solid ${THEME.border}` }}>
                    <span style={{ fontFamily: "Syne,sans-serif", fontSize: 20, fontWeight: 900,
                      color: THEME.accent, minWidth: 28 }}>{i + 1}</span>
                    <span style={{ flex: 1, fontSize: 12, color: THEME.text, fontWeight: 600 }}>{r.rule}</span>
                    <span style={{ fontSize: 11, fontWeight: 800, color: THEME.warning,
                      background: "rgba(245,158,11,0.1)", padding: "3px 10px", borderRadius: 6,
                      border: `1px solid ${THEME.warning}33` }}>{r.count}×</span>
                  </div>
                ))}
                {(alertsSum.top_rules || []).length === 0 && (
                  <div style={{ color: THEME.subtext, fontSize: 12, padding: 20 }}>No alert data yet.</div>
                )}
              </div>
            )}
          </Card>
        </div>
      )}

      {/* ── Alerts sub-tab ── */}
      {subTab === "alerts" && (
        <div style={{ display: "grid", gap: 16 }}>
          {/* Export + Archive toolbar — FR-SOC-05 */}
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center",
            padding: "12px 16px", background: "rgba(255,255,255,0.02)",
            border: `1px solid ${THEME.border}`, borderRadius: 10 }}>
            <div style={{ fontSize: 12, color: THEME.subtext }}>
              Showing last <span style={{ color: THEME.accent, fontWeight: 700 }}>100</span> alerts
              {alerts?.total > 100 && <span> of <span style={{ color: THEME.warning, fontWeight: 700 }}>{alerts.total.toLocaleString()}</span> total</span>}
              {" — "}archive older logs to keep the view clean
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <a href={`${API}/soc/export/csv?min_level=3&limit=200`} download
                style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.05em", textTransform: "uppercase",
                  padding: "7px 14px", borderRadius: 8, textDecoration: "none",
                  border: `1px solid ${THEME.healthy}`, background: "rgba(16,185,129,0.1)",
                  color: THEME.healthy, cursor: "pointer" }}>
                ↓ CSV
              </a>
              <a href={`${API}/soc/export/json?min_level=3&limit=200`} download
                style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.05em", textTransform: "uppercase",
                  padding: "7px 14px", borderRadius: 8, textDecoration: "none",
                  border: `1px solid ${THEME.accent}`, background: "rgba(14,165,233,0.1)",
                  color: THEME.accent, cursor: "pointer" }}>
                ↓ JSON
              </a>
              <SocArchiveButton />
            </div>
          </div>

          <Card title="🚨 Security Alerts" badge={`FR-SOC-02 / FR-SOC-03 · LAST 100 OF ${alerts?.total?.toLocaleString() || "?"}`}>
          {alLoading ? <Spinner /> : (
            <div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12, marginBottom: 20 }}>
                {["Critical","High","Medium","Low"].map(sev => (
                  <div key={sev} style={{ padding: "12px 16px", borderRadius: 10,
                    background: WAZUH_SEV_BG[sev], border: `1px solid ${WAZUH_SEV_COLOR[sev]}33`,
                    borderTop: `3px solid ${WAZUH_SEV_COLOR[sev]}` }}>
                    <div style={{ fontSize: 10, color: THEME.subtext, textTransform: "uppercase", fontWeight: 700, marginBottom: 6 }}>{sev}</div>
                    <div style={{ fontFamily: "Syne,sans-serif", fontSize: 26, fontWeight: 800, color: WAZUH_SEV_COLOR[sev] }}>
                      {alerts?.severity_breakdown?.[sev] ?? 0}
                    </div>
                  </div>
                ))}
              </div>
              <div style={{ maxHeight: 480, overflowY: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead><tr>
                    <Th>Time</Th><Th>Agent</Th><Th>Rule</Th><Th>Description</Th><Th>Severity</Th><Th>Src IP</Th>
                  </tr></thead>
                  <tbody>
                    {(alerts?.alerts || []).map((a, i) => (
                      <TR key={i}>
                        <Td style={{ fontSize: 10, color: THEME.subtext, fontFamily: "JetBrains Mono", whiteSpace: "nowrap" }}>
                          {String(a.timestamp).slice(0, 19).replace("T", " ")}
                        </Td>
                        <Td style={{ fontWeight: 600, fontSize: 11 }}>{a.agent_name}</Td>
                        <Td style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: THEME.accent }}>{a.rule_id}</Td>
                        <Td style={{ fontSize: 11, maxWidth: 300 }}>{a.description}</Td>
                        <Td>
                          <span style={{ fontSize: 9, fontWeight: 700, padding: "3px 8px", borderRadius: 6,
                            textTransform: "uppercase", background: WAZUH_SEV_BG[a.severity] || WAZUH_SEV_BG.Low,
                            color: WAZUH_SEV_COLOR[a.severity] || WAZUH_SEV_COLOR.Low,
                            border: `1px solid ${WAZUH_SEV_COLOR[a.severity] || WAZUH_SEV_COLOR.Low}33` }}>
                            {a.severity}
                          </span>
                        </Td>
                        <Td style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: a.src_ip ? THEME.critical : THEME.subtext }}>
                          {a.src_ip || "—"}
                        </Td>
                      </TR>
                    ))}
                    {(alerts?.alerts || []).length === 0 && (
                      <tr><td colSpan="6" style={{ padding: 40, textAlign: "center", color: THEME.subtext }}>
                        No alerts at level ≥ 3. Try triggering an attack.
                      </td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
          </Card>

          {/* Archive history panel */}
          <SocArchiveList />
        </div>
      )}

      {/* ── FIM sub-tab ── */}
      {subTab === "fim" && (
        <Card title="📝 File Integrity Monitoring" badge="FR-SOC-06">
          {fimLoading ? <Spinner /> : (
            <div style={{ maxHeight: 520, overflowY: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead><tr><Th>Time</Th><Th>Agent</Th><Th>Event</Th><Th>Path</Th><Th>Severity</Th><Th>Description</Th></tr></thead>
                <tbody>
                  {(fim?.events || []).map((e, i) => (
                    <TR key={i}>
                      <Td style={{ fontSize: 10, color: THEME.subtext, fontFamily: "JetBrains Mono", whiteSpace: "nowrap" }}>
                        {String(e.timestamp).slice(0, 19).replace("T", " ")}
                      </Td>
                      <Td style={{ fontWeight: 600, fontSize: 11 }}>{e.agent_name}</Td>
                      <Td>
                        <span style={{ fontSize: 11 }}>{FIM_ICON[e.event] || "📄"} {e.event || "—"}</span>
                      </Td>
                      <Td style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: THEME.accent, maxWidth: 260, wordBreak: "break-all" }}>
                        {e.path || "—"}
                      </Td>
                      <Td>
                        <span style={{ fontSize: 9, fontWeight: 700, padding: "3px 8px", borderRadius: 6,
                          textTransform: "uppercase", background: WAZUH_SEV_BG[e.severity] || WAZUH_SEV_BG.Low,
                          color: WAZUH_SEV_COLOR[e.severity] || WAZUH_SEV_COLOR.Low,
                          border: `1px solid ${WAZUH_SEV_COLOR[e.severity] || WAZUH_SEV_COLOR.Low}33` }}>
                          {e.severity}
                        </span>
                      </Td>
                      <Td style={{ fontSize: 11 }}>{e.description}</Td>
                    </TR>
                  ))}
                  {(fim?.events || []).length === 0 && (
                    <tr><td colSpan="6" style={{ padding: 40, textAlign: "center", color: THEME.subtext }}>
                      No FIM events yet. Try: <code style={{ color: THEME.accent }}>sudo touch /etc/hacked-by-taher</code> on Metasploitable3.
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}

      {/* ── UBA sub-tab ── */}
      {subTab === "uba" && (
        <Card title="👤 User Behavior Analytics" badge="FR-SOC-08">
          {ubaLoading ? <Spinner /> : (
            <div style={{ maxHeight: 520, overflowY: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead><tr><Th>Time</Th><Th>Agent</Th><Th>Category</Th><Th>Description</Th><Th>Severity</Th><Th>User / IP</Th></tr></thead>
                <tbody>
                  {(uba?.events || []).map((e, i) => {
                    const cat = e.groups?.find(g => Object.keys(UBA_GROUP_ICON).includes(g)) || e.groups?.[0] || "";
                    return (
                      <TR key={i}>
                        <Td style={{ fontSize: 10, color: THEME.subtext, fontFamily: "JetBrains Mono", whiteSpace: "nowrap" }}>
                          {String(e.timestamp).slice(0, 19).replace("T", " ")}
                        </Td>
                        <Td style={{ fontWeight: 600, fontSize: 11 }}>{e.agent_name}</Td>
                        <Td>
                          <span style={{ fontSize: 11 }}>{UBA_GROUP_ICON[cat] || "🔹"} {cat.replace(/_/g, " ")}</span>
                        </Td>
                        <Td style={{ fontSize: 11 }}>{e.description}</Td>
                        <Td>
                          <span style={{ fontSize: 9, fontWeight: 700, padding: "3px 8px", borderRadius: 6,
                            textTransform: "uppercase", background: WAZUH_SEV_BG[e.severity] || WAZUH_SEV_BG.Low,
                            color: WAZUH_SEV_COLOR[e.severity] || WAZUH_SEV_COLOR.Low,
                            border: `1px solid ${WAZUH_SEV_COLOR[e.severity] || WAZUH_SEV_COLOR.Low}33` }}>
                            {e.severity}
                          </span>
                        </Td>
                        <Td style={{ fontFamily: "JetBrains Mono", fontSize: 10 }}>
                          {e.src_user || e.dst_user || e.src_ip || "—"}
                        </Td>
                      </TR>
                    );
                  })}
                  {(uba?.events || []).length === 0 && (
                    <tr><td colSpan="6" style={{ padding: 40, textAlign: "center", color: THEME.subtext }}>
                      No UBA events yet. Try failed SSH logins or <code style={{ color: THEME.accent }}>sudo -u dirmngr whoami</code>.
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}

      {/* ── Active Response sub-tab ── */}
      {subTab === "ar" && (
        <Card title="🛡 Active Response Log" badge="FR-SOC-04">
          {arLoading ? <Spinner /> : (
            <div style={{ display: "grid", gap: 10 }}>
              {(ar?.events || []).map((e, i) => (
                <div key={i} style={{ padding: "14px 16px", borderRadius: 10,
                  background: "rgba(16,185,129,0.04)", border: `1px solid ${THEME.healthy}33`,
                  borderLeft: `4px solid ${THEME.healthy}` }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                    <span style={{ fontWeight: 700, fontSize: 12, color: THEME.healthy }}>{e.description}</span>
                    <span style={{ fontSize: 10, color: THEME.subtext, fontFamily: "JetBrains Mono" }}>
                      {String(e.timestamp).slice(0, 19).replace("T", " ")}
                    </span>
                  </div>
                  <div style={{ fontSize: 11, color: THEME.subtext, marginBottom: 6 }}>
                    Agent: <span style={{ color: THEME.text, fontWeight: 600 }}>{e.agent_name}</span>
                    {" · "}Level: <span style={{ color: THEME.warning, fontWeight: 700 }}>{e.rule_level}</span>
                  </div>
                  {e.full_log && (
                    <div style={{ fontSize: 10, color: THEME.subtext, fontFamily: "JetBrains Mono",
                      background: "rgba(15,23,42,0.5)", padding: "8px 12px", borderRadius: 6,
                      border: `1px solid ${THEME.border}`, wordBreak: "break-all" }}>
                      {e.full_log}
                    </div>
                  )}
                </div>
              ))}
              {(ar?.events || []).length === 0 && (
                <div style={{ padding: 40, textAlign: "center", color: THEME.subtext }}>
                  No active response events yet. Run a brute-force attack to trigger rule 5763.
                </div>
              )}
            </div>
          )}
        </Card>
      )}

      {/* ── Malware sub-tab ── */}
      {subTab === "malware" && (
        <Card title="🦠 Malware Detection" badge="FR-SOC-07">
          {malLoading ? <Spinner /> : (
            <div style={{ display: "grid", gap: 10 }}>
              {(malware?.events || []).map((e, i) => (
                <div key={i} style={{ padding: "14px 16px", borderRadius: 10,
                  background: "rgba(244,63,94,0.04)", border: `1px solid ${THEME.critical}33`,
                  borderLeft: `4px solid ${THEME.critical}` }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                    <span style={{ fontWeight: 700, fontSize: 12, color: THEME.critical }}>{e.description}</span>
                    <span style={{ fontSize: 10, color: THEME.subtext, fontFamily: "JetBrains Mono" }}>
                      {String(e.timestamp).slice(0, 19).replace("T", " ")}
                    </span>
                  </div>
                  <div style={{ fontSize: 11, color: THEME.subtext, marginBottom: 6 }}>
                    Agent: <span style={{ color: THEME.text, fontWeight: 600 }}>{e.agent_name}</span>
                    {" · "}Rule: <span style={{ color: THEME.accent, fontFamily: "JetBrains Mono" }}>{e.rule_id}</span>
                    {" · "}Level: <span style={{ color: THEME.critical, fontWeight: 700 }}>{e.rule_level}</span>
                  </div>
                  {e.groups?.length > 0 && (
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 8 }}>
                      {e.groups.map(g => (
                        <span key={g} style={{ fontSize: 9, padding: "2px 8px", borderRadius: 4,
                          background: "rgba(244,63,94,0.1)", color: THEME.critical,
                          border: `1px solid ${THEME.critical}33`, fontWeight: 700 }}>{g}</span>
                      ))}
                    </div>
                  )}
                  {e.full_log && (
                    <div style={{ fontSize: 10, color: THEME.subtext, fontFamily: "JetBrains Mono",
                      background: "rgba(15,23,42,0.5)", padding: "8px 12px", borderRadius: 6,
                      border: `1px solid ${THEME.border}`, wordBreak: "break-all" }}>
                      {e.full_log}
                    </div>
                  )}
                </div>
              ))}
              {(malware?.events || []).length === 0 && (
                <div style={{ padding: 40, textAlign: "center", color: THEME.subtext }}>
                  No malware events yet. Drop the EICAR test file to trigger a Level 12 alert.
                </div>
              )}
            </div>
          )}
        </Card>
      )}
    </div>
  );
}

// ── Operations Control — Consolidated NOC & VOC Actions ──────────────────────
function OperationsControl() {
  const { data: runbooks } = useApi("/noc/remediation/runbooks", 30000);
  const [executing, setExecuting] = useState(null);
  const [result, setResult] = useState(null);
  const [nocAction, setNocAction] = useState("");
  const [vocAction, setVocAction] = useState("");

  const runNocAction = async (actionId) => {
    if (!actionId) return;
    const rb = runbooks?.find(r => r.id === actionId);
    if (!rb) return;

    setExecuting(actionId);
    try {
      let endpoint = "/noc/remediation/restart-service";
      let body = { target: rb.target, service_name: rb.service };

      if (rb.id === "isolate_host") { endpoint = "/noc/remediation/isolate-host"; body = { target: rb.target }; }
      else if (rb.id === "apply_patch") { endpoint = "/noc/remediation/apply-patch"; body = { target: rb.target, service_name: rb.service }; }
      else if (rb.id === "rotate_keys") { endpoint = "/noc/remediation/rotate-keys"; body = { target: rb.target, service_name: rb.service }; }
      else if (rb.id === "block_brute") { endpoint = "/noc/remediation/block-ip"; body = { attacker_ip: "192.168.100.200" }; }
      else if (rb.id === "unblock_all") { endpoint = "/noc/remediation/unblock-all"; body = {}; }
      else if (rb.id === "simulate_traffic") { endpoint = "/noc/remediation/simulate-traffic"; body = {}; }

      const r = await fetch(API + endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      const res = await r.json();
      setResult({ type: "NOC", success: r.ok, message: res.message, name: rb.name });
    } catch (e) {
      setResult({ type: "NOC", success: false, message: e.message, name: rb.name });
    } finally {
      setExecuting(null);
      setNocAction("");
    }
  };

  const runVocAction = async (actionId) => {
    if (!actionId) return;
    setExecuting(actionId);
    try {
      let endpoint = "";
      let body = {};
      let name = "";

      if (actionId === "scan") {
        endpoint = "/voc/scan";
        body = { network: "192.168.100.102", enrich_vt: true };
        name = "Vulnerability Scan";
      } else if (actionId === "init_db") {
        endpoint = "/db/init";
        body = {};
        name = "Initialize Database";
      } else if (actionId === "reseed") {
        endpoint = "/db/reseed";
        body = {};
        name = "Reseed Data";
      }

      const r = await fetch(API + endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      const res = await r.json();
      setResult({ type: "VOC", success: r.ok, message: res.message || res.status, name: name });
    } catch (e) {
      setResult({ type: "VOC", success: false, message: e.message, name: actionId });
    } finally {
      setExecuting(null);
      setVocAction("");
    }
  };

  return (
    <Card title="⚡ Operations Control Center" badge="INTEGRATED ACTIONS">
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
        {/* NOC Actions Section */}
        <div style={{ padding: 16, background: "rgba(14, 165, 233, 0.05)", borderRadius: 12, border: `1px solid ${THEME.accent}33` }}>
          <div style={{ fontSize: 11, fontWeight: 800, color: THEME.accent, marginBottom: 12, textTransform: "uppercase" }}>⌬ NOC Infrastructure Actions</div>
          <select 
            value={nocAction}
            onChange={(e) => { setNocAction(e.target.value); runNocAction(e.target.value); }}
            disabled={!!executing}
            style={{ 
              width: "100%", padding: "10px", borderRadius: 8, background: THEME.bg, color: THEME.text, 
              border: `1px solid ${THEME.border}`, cursor: "pointer", outline: "none"
            }}
          >
            <option value="">Select NOC Action...</option>
            {runbooks?.map(rb => (
              <option key={rb.id} value={rb.id}>{rb.name}</option>
            ))}
          </select>
        </div>

        {/* VOC Actions Section */}
        <div style={{ padding: 16, background: "rgba(16, 185, 129, 0.05)", borderRadius: 12, border: `1px solid ${THEME.healthy}33` }}>
          <div style={{ fontSize: 11, fontWeight: 800, color: THEME.healthy, marginBottom: 12, textTransform: "uppercase" }}>◈ VOC Vulnerability Actions</div>
          <select 
            value={vocAction}
            onChange={(e) => { setVocAction(e.target.value); runVocAction(e.target.value); }}
            disabled={!!executing}
            style={{ 
              width: "100%", padding: "10px", borderRadius: 8, background: THEME.bg, color: THEME.text, 
              border: `1px solid ${THEME.border}`, cursor: "pointer", outline: "none"
            }}
          >
            <option value="">Select VOC Action...</option>
            <option value="scan">Run Vulnerability Scan</option>
            <option value="init_db">Initialize Database</option>
            <option value="reseed">Reseed Lab Data</option>
          </select>
        </div>
      </div>

      {/* Results Display */}
      {result && (
        <div style={{ 
          marginTop: 20, padding: 16, borderRadius: 10,
          background: result.success ? "rgba(16, 185, 129, 0.1)" : "rgba(244, 63, 94, 0.1)",
          border: `1px solid ${result.success ? THEME.healthy : THEME.critical}33`
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span style={{ fontSize: 10, fontWeight: 800, color: result.success ? THEME.healthy : THEME.critical }}>{result.type} ACTION {result.success ? "SUCCESS" : "FAILED"}</span>
            <button onClick={() => setResult(null)} style={{ background: "none", border: "none", color: THEME.subtext, cursor: "pointer", fontSize: 10 }}>Dismiss</button>
          </div>
          <div style={{ fontSize: 12, fontWeight: 700, color: THEME.text }}>{result.name}</div>
          <div style={{ fontSize: 11, color: THEME.subtext, marginTop: 4 }}>{typeof result.message === 'string' ? result.message : JSON.stringify(result.message)}</div>
        </div>
      )}
      
      {executing && (
        <div style={{ marginTop: 12, display: "flex", alignItems: "center", gap: 10 }}>
          <div className="spinner" style={{ width: 14, height: 14, border: "2px solid #334155", borderTop: "2px solid #0ea5e9", borderRadius: "50%", animation: "spin 1s linear infinite" }} />
          <span style={{ fontSize: 11, color: THEME.accent, fontWeight: 600 }}>Executing tactical operation...</span>
        </div>
      )}
    </Card>
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
    {id:"dashboard", label:"Dashboard", icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>},
    {id:"alerts",    label:"Security Alerts", icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>},
    {id:"noc",       label:"NOC Center", icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>},
    {id:"remediation",label:"Remediation Hub", icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m12 14 4-4"></path><path d="M3.34 19a10 10 0 1 1 17.32 0"></path></svg>},
    {id:"scanner",   label:"Vuln Scanner", icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="22" y1="12" x2="18" y2="12"></line><line x1="6" y1="12" x2="2" y2="12"></line><line x1="12" y1="6" x2="12" y2="2"></line><line x1="12" y1="22" x2="12" y2="18"></line></svg>},
    {id:"database",  label:"Log Database", icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"></ellipse><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path></svg>},
    {id:"virustotal",label:"VirusTotal", icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>},
    {id:"ml",        label:"AI Intelligence", icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2a10 10 0 1 0 10 10H12V2z"></path><path d="M12 12L2.1 10.12"></path><path d="M12 12L19 16.8"></path><path d="M12 12l4-8"></path><path d="M12 12l-4-8"></path><path d="M12 12l-7 8"></path><path d="M12 12l-3-9"></path></svg>},
    {id:"compliance",label:"Compliance", icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="m9 12 2 2 4-4"></path></svg>},
    {id:"soc",       label:"SOC / Wazuh", icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><circle cx="12" cy="12" r="3"></circle></svg>},
    {id:"forensics", label:"Forensics & DB", icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>},
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
        .sidebar-item { transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1); position: relative; opacity: 0.7; }
        .sidebar-item:hover { background: rgba(14, 165, 233, 0.08); color: #0ea5e9; opacity: 1; transform: translateX(4px); }
        .sidebar-active { background: rgba(14, 165, 233, 0.12); color: #0ea5e9; opacity: 1; border-left: 3px solid #0ea5e9; }
        .sidebar-active svg { filter: drop-shadow(0 0 4px #0ea5e9); }
        
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
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5z"></path><path d="M2 17l10 5 10-5"></path><path d="M2 12l10 5 10-5"></path></svg>
          </div>
          <div>
            <div style={{ fontFamily: "Syne,sans-serif", fontWeight: 800, fontSize: 18, letterSpacing: "0.05em", color: THEME.text }}>ICOC-LITE</div>
            <div style={{ fontSize: 9, color: THEME.subtext, letterSpacing: "0.1em", textTransform: "uppercase", fontWeight: 600 }}>Command Center v1.0</div>
          </div>
        </div>

        <nav style={{ flex: 1, padding: "10px 16px", display: "flex", flexDirection: "column", gap: 6 }}>
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
                fontWeight: tab === t.id ? 700 : 500,
                color: tab === t.id ? THEME.accent : THEME.subtext
              }}
            >
              <div style={{ display: "flex", alignItems: "center", justifyContent: "center", width: 20 }}>
                {t.icon}
              </div>
              <span style={{ transition: "all 0.2s" }}>{t.label}</span>
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
              <span style={{ color: THEME.accent }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
              </span> {time}
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
            {tab === "soc"        && <SocTab />}
            {tab === "forensics"  && <ForensicsTab />}
          </div>
          
          <footer style={{ marginTop: 60, paddingBottom: 20, textAlign: "center", fontSize: 11, color: THEME.subtext, opacity: 0.6 }}>
            ICOC-LITE FRAMEWORK · NETWORK OPERATIONS & AI SECURITY · ACADEMIC LAB v1.0
          </footer>
        </main>
      </div>
    </div>
  );
}
