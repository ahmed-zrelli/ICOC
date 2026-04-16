/**
 * ICOC-Lite Dashboard — Member 3 (VOC / AI Module)
 * Covers: FR-VOC-01..07, FR-AI-01..07
 */
import { useState, useEffect, useCallback, useRef } from "react";

const API = "http://localhost:8000";

// ── Design tokens ─────────────────────────────────────────────────────────────
const SEV = { Critical:"#ff1a4b", High:"#ff6b35", Medium:"#ffd600", Low:"#00e5ff", Info:"#4a6070", None:"#7c8cf8" };
const SEV_BG = { Critical:"rgba(255,26,75,0.12)", High:"rgba(255,107,53,0.12)", Medium:"rgba(255,214,0,0.12)", Low:"rgba(0,229,255,0.08)", Info:"rgba(74,96,112,0.12)", None:"rgba(124,140,248,0.12)" };
const STATUS_COLOR = { missing:"#ff1a4b", available:"#ffd600", scheduled:"#7c8cf8", applied:"#00e676", wontfix:"#4a6070" };
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
function GaugeRing({ score, color }) {
  const r = 54, circ = 2 * Math.PI * r;
  return (
    <div style={{ position:"relative", width:140, height:140, flexShrink:0 }}>
      <svg width="140" height="140" viewBox="0 0 120 120" style={{ transform:"rotate(-90deg)" }}>
        <circle cx="60" cy="60" r={r} fill="none" stroke="#1a2530" strokeWidth="12" />
        <circle cx="60" cy="60" r={r} fill="none" stroke={color} strokeWidth="12" strokeLinecap="round"
          strokeDasharray={circ} strokeDashoffset={circ - (score / 100) * circ}
          style={{ transition:"stroke-dashoffset 1s ease" }} />
      </svg>
      <div style={{ position:"absolute", inset:0, display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center" }}>
        <span style={{ fontFamily:"Syne,sans-serif", fontSize:34, fontWeight:800, color, lineHeight:1 }}>{score}</span>
        <span style={{ fontSize:10, color:"#4a6070" }}>/ 100</span>
      </div>
    </div>
  );
}

const SevBadge = ({ sev }) => <span style={{ fontSize:9, fontWeight:700, letterSpacing:"0.1em", padding:"3px 8px", borderRadius:3, textTransform:"uppercase", background:SEV_BG[sev]||SEV_BG.None, color:SEV[sev]||SEV.None, border:`1px solid ${SEV[sev]||SEV.None}44` }}>{sev}</span>;
const StatusBadge = ({ status }) => <span style={{ fontSize:9, fontWeight:600, letterSpacing:"0.1em", padding:"2px 8px", borderRadius:2, textTransform:"uppercase", color:STATUS_COLOR[status]||"#4a6070", border:`1px solid ${STATUS_COLOR[status]||"#4a6070"}55` }}>{status}</span>;
const Spinner = () => <div style={{ color:"#4a6070", fontSize:12, padding:20 }}>Loading...</div>;
const ErrorMsg = ({ msg }) => <div style={{ color:"#ff6b35", fontSize:11, padding:12 }}>⚠ {msg} — ensure API is running on :8000</div>;

function Card({ title, badge, children, style = {} }) {
  return (
    <div style={{ background:"#0d1318", border:"1px solid #1a2530", borderRadius:8, padding:18, ...style }}>
      {(title || badge) && (
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:16 }}>
          {title && <span style={{ fontFamily:"Syne,sans-serif", fontSize:11, fontWeight:700, letterSpacing:"0.2em", color:"#00e5ff", textTransform:"uppercase" }}>{title}</span>}
          {badge && <span style={{ fontSize:9, padding:"3px 8px", borderRadius:3, background:"rgba(0,229,255,0.08)", border:"1px solid rgba(0,229,255,0.25)", color:"#00e5ff", letterSpacing:"0.1em" }}>{badge}</span>}
        </div>
      )}
      {children}
    </div>
  );
}

function KpiCard({ label, value, color, sub }) {
  return (
    <div style={{ background:"#0d1318", border:"1px solid #1a2530", borderRadius:8, padding:"14px 16px", borderTop:`2px solid ${color}` }}>
      <div style={{ fontSize:9, color:"#4a6070", letterSpacing:"0.2em", marginBottom:8, textTransform:"uppercase" }}>{label}</div>
      <div style={{ fontFamily:"Syne,sans-serif", fontSize:30, fontWeight:800, color, lineHeight:1 }}>{value}</div>
      <div style={{ fontSize:10, color:"#4a6070", marginTop:6 }}>{sub}</div>
    </div>
  );
}

const Th = ({ children }) => <th style={{ fontSize:9, color:"#4a6070", letterSpacing:"0.15em", textAlign:"left", padding:"7px 10px", borderBottom:"1px solid #1a2530", textTransform:"uppercase" }}>{children}</th>;
const Td = ({ children, style={} }) => <td style={{ padding:"9px 10px", fontSize:11, color:"#c8d8e8", ...style }}>{children}</td>;
const TR = ({ children, style={} }) => <tr style={{ borderBottom:"1px solid rgba(26,37,48,0.5)", ...style }}>{children}</tr>;

// ── Dashboard Tab ─────────────────────────────────────────────────────────────
function DashboardTab() {
  const { data, loading, error } = useApi("/dashboard", 10000);
  const { data: liveStats }      = useApi("/events/stats", 5000);

  if (loading) return <Spinner />;
  if (error)   return <ErrorMsg msg={error} />;
  if (!data)   return <ErrorMsg msg="No data from API" />;

  const { risk_score, patch_summary, threat_intel, recommendations, incident_prediction, compliance } = data;
  if (!risk_score || !patch_summary) return <ErrorMsg msg="Incomplete API response" />;

  const cve_scores    = Array.isArray(data.cve_scores) ? data.cve_scores : (data.cve_scores?.cves || []);
  const liveCritical  = liveStats?.severity_breakdown?.Critical || 0;
  const liveHigh      = liveStats?.severity_breakdown?.High     || 0;
  const liveAlerts    = liveStats?.alert_count_5min             || 0;
  const liveIncidents = liveStats?.incidents                    || 0;
  const liveTotalEvt  = liveStats?.total_events                 || 0;

  return (
    <div style={{ display:"grid", gap:20 }}>
      {/* KPI strip */}
      <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:12 }}>
        <KpiCard label="Global Risk"    value={risk_score.score}                                            color={risk_score.color} sub={risk_score.level} />
        <KpiCard label="Critical CVEs"  value={patch_summary.critical_missing}                              color="#ff1a4b"          sub="unpatched" />
        <KpiCard label="Total Vulns"    value={patch_summary.total_vulnerabilities}                          color="#ff6b35"          sub="tracked" />
        <KpiCard label="Patch Coverage" value={`${patch_summary.patch_coverage_pct}%`}                      color="#00e676"          sub="applied" />
        <KpiCard label="Incident Prob"  value={`${incident_prediction?.incident_probability_pct ?? "—"}%`} color="#ffd600"          sub="24h window" />
      </div>

      {/* Live SOC strip — only when attacks are active */}
      {liveStats && (liveCritical + liveHigh + liveAlerts + liveIncidents > 0) && (
        <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:10 }}>
          {[["Total Events",liveTotalEvt,"#00e5ff"],["Critical",liveCritical,"#ff1a4b"],["High",liveHigh,"#ff6b35"],["Alerts (5min)",liveAlerts,"#ffd600"],["Incidents",liveIncidents,"#ff1a4b"]].map(([label,val,color]) => (
            <div key={label} style={{ background:"#0d1318", border:"1px solid #1a2530", borderRadius:8, padding:"10px 14px", borderTop:`2px solid ${color}` }}>
              <div style={{ fontSize:9, color:"#4a6070", letterSpacing:"0.2em", textTransform:"uppercase", marginBottom:4 }}>{label}</div>
              <div style={{ fontFamily:"Syne,sans-serif", fontSize:22, fontWeight:800, color }}>{val}</div>
            </div>
          ))}
        </div>
      )}

      <div style={{ display:"grid", gridTemplateColumns:"1fr 340px", gap:20 }}>
        <div style={{ display:"grid", gap:16 }}>
          {/* AI Risk Engine — FR-AI-01..07 */}
          <Card title="⬡ AI Risk Engine" badge="FR-AI-01..07">
            <div style={{ display:"flex", gap:28, alignItems:"center", background:"rgba(0,0,0,0.3)", borderRadius:8, padding:20 }}>
              <GaugeRing score={risk_score.score} color={risk_score.color} />
              <div>
                <h3 style={{ fontFamily:"Syne,sans-serif", fontSize:20, fontWeight:700, color:risk_score.color }}>{risk_score.level.toUpperCase()} RISK</h3>
                <p style={{ fontSize:11, color:"#7a9aaa", marginTop:6, lineHeight:1.6 }}>VOC: {risk_score.breakdown.voc_component}/60 · SOC: {risk_score.breakdown.soc_component}/25 · TI: {risk_score.breakdown.ti_component}/15</p>
                <p style={{ fontSize:10, color:"#4a6070", marginTop:8 }}>{risk_score.inputs.critical_unpatched} critical unpatched · {risk_score.inputs.soc_alerts} SOC alerts · {risk_score.inputs.threat_intel_hits} TI hits</p>
                {liveCritical + liveHigh > 0 && <p style={{ fontSize:10, color:"#ff6b35", marginTop:6, fontWeight:700 }}>⚠ LIVE: {liveCritical} Critical · {liveHigh} High · {liveIncidents} Incidents</p>}
              </div>
            </div>
            {/* Compliance bars — FR-VOC-07 */}
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:10, marginTop:16 }}>
              {compliance?.frameworks && Object.entries(compliance.frameworks).map(([fw, d]) => (
                <div key={fw} style={{ padding:"10px 12px", background:"rgba(0,0,0,0.2)", borderRadius:6, border:"1px solid #1a2530" }}>
                  <div style={{ display:"flex", justifyContent:"space-between", marginBottom:6 }}>
                    <span style={{ fontSize:10, color:"#c8d8e8" }}>{fw}</span>
                    <span style={{ fontSize:11, fontWeight:700, color: d.overall_score_pct >= 70 ? "#00e676" : "#ffd600" }}>{d.overall_score_pct}%</span>
                  </div>
                  <div style={{ height:3, background:"#1a2530", borderRadius:2 }}>
                    <div style={{ height:"100%", width:`${d.overall_score_pct}%`, background: d.overall_score_pct >= 70 ? "#00e676" : "#ffd600", borderRadius:2, transition:"width 1s ease" }} />
                  </div>
                </div>
              ))}
            </div>
          </Card>

          {/* CVE Scores — FR-VOC-02 */}
          <Card title="◈ CVE Scores" badge="CVSS v3.1">
            <table style={{ width:"100%", borderCollapse:"collapse" }}>
              <thead><tr><Th>CVE ID</Th><Th>Description</Th><Th>Score</Th><Th>Severity</Th><Th>Vector</Th></tr></thead>
              <tbody>
                {cve_scores.map(cve => (
                  <TR key={cve.cve_id}>
                    <Td style={{ color:"#00e5ff" }}>{cve.cve_id}</Td>
                    <Td style={{ maxWidth:200 }}>{cve.description}</Td>
                    <Td style={{ fontSize:13, fontWeight:700, color:SEV[cve.severity]||"#fff" }}>{cve.base_score}</Td>
                    <Td><SevBadge sev={cve.severity} /></Td>
                    <Td style={{ fontSize:9, color:"#4a6070", fontFamily:"monospace" }}>{cve.vector_string?.replace("CVSS:3.1/","")}</Td>
                  </TR>
                ))}
              </tbody>
            </table>
          </Card>
        </div>

        {/* Right column */}
        <div style={{ display:"flex", flexDirection:"column", gap:14 }}>
          {/* AI Recommendations — FR-AI-07 */}
          <Card title="✦ AI Recommendations" badge="FR-AI-07">
            {recommendations?.map((rec, i) => (
              <div key={i} style={{ display:"flex", gap:10, padding:"10px 12px", background:"rgba(0,0,0,0.2)", borderRadius:6, marginBottom:8, borderLeft:`3px solid ${SEV[rec.severity]||"#00e5ff"}`, fontSize:11, lineHeight:1.5, color:"#c8d8e8" }}>
                <span style={{ flexShrink:0 }}>{rec.priority===1?"🔴":rec.priority===2?"🟠":"🟡"}</span>
                <div>
                  <div style={{ fontWeight:600, marginBottom:3 }}>{rec.action}</div>
                  <div style={{ fontSize:10, color:"#4a6070" }}>{rec.detail} · {rec.estimated_effort}</div>
                </div>
              </div>
            ))}
          </Card>

          {/* Threat Intel — FR-AI-05 */}
          <Card title="⬡ Threat Intel" badge="FR-AI-05">
            {threat_intel?.map((ti, i) => (
              <div key={i} style={{ display:"flex", gap:10, padding:"9px 0", borderBottom:"1px solid rgba(26,37,48,0.6)" }}>
                <div style={{ width:6, height:6, borderRadius:"50%", background:SEV[ti.severity]||"#4a6070", marginTop:4, flexShrink:0 }} />
                <div>
                  <div style={{ fontSize:11, color:"#c8d8e8", lineHeight:1.4 }}>{ti.indicator} — {ti.description}</div>
                  <div style={{ fontSize:9, color:"#4a6070", marginTop:3 }}>{ti.source} · {ti.tags?.join(", ")}</div>
                </div>
              </div>
            ))}
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
    <div style={{ display:"grid", gap:20 }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
        <div>
          <h2 style={{ fontFamily:"Syne,sans-serif", fontSize:16, color:"#00e5ff" }}>Vulnerability Scanner</h2>
          <p style={{ fontSize:11, color:"#4a6070", marginTop:4 }}>FR-VOC-05 · CVSS v3.1 · VT enrichment · results saved to DB</p>
        </div>
        <button onClick={triggerScan} disabled={scanning} style={{ fontFamily:"JetBrains Mono,monospace", fontSize:11, letterSpacing:"0.1em", padding:"8px 18px", borderRadius:4, border:"none", cursor:scanning?"not-allowed":"pointer", background:scanning?"rgba(0,229,255,0.2)":"#00e5ff", color:scanning?"#00e5ff":"#000", fontWeight:700, textTransform:"uppercase", animation:scanning?"pulse 1s ease-in-out infinite":"none" }}>
          {scanning ? `Scanning... ${scanPct}%` : "⬡ Run Scan"}
        </button>
      </div>

      {/* Real-time progress bar */}
      {scanning && (
        <div style={{ background:"#0d1318", border:"1px solid #1a2530", borderRadius:8, padding:"14px 18px" }}>
          <div style={{ display:"flex", justifyContent:"space-between", marginBottom:8 }}>
            <span style={{ fontSize:11, color:"#00e5ff" }}>Scan in progress — {scanStage}</span>
            <span style={{ fontSize:11, color:"#7a9aaa" }}>{scanPct}%</span>
          </div>
          <div style={{ height:4, background:"#1a2530", borderRadius:2 }}>
            <div style={{ height:"100%", width:`${scanPct}%`, background:"#00e5ff", borderRadius:2, transition:"width 0.5s ease" }} />
          </div>
        </div>
      )}

      {scanMsg && <div style={{ background:"rgba(0,229,255,0.08)", border:"1px solid rgba(0,229,255,0.3)", borderRadius:6, padding:"10px 14px", fontSize:11, color:"#00e5ff" }}>{scanMsg}</div>}

      {/* Last scan summary */}
      {lastResult && !scanning && (
        <div style={{ background:"rgba(0,0,0,0.2)", border:"1px solid #1a2530", borderRadius:8, padding:"14px 18px" }}>
          <div style={{ fontSize:10, color:"#4a6070", marginBottom:8 }}>Last scan: <span style={{ color:"#00e5ff" }}>{lastResult.scan_id}</span> · Mode: <span style={{ color:"#7a9aaa" }}>{lastResult.mode}</span> · {lastResult.completed_at?.slice(11,19)} UTC</div>
          <div style={{ display:"flex", gap:20 }}>
            {Object.entries(lastResult.severity_summary || {}).map(([sev, cnt]) => (
              <span key={sev} style={{ fontSize:11, color:SEV[sev]||"#fff" }}><strong>{cnt}</strong> {sev}</span>
            ))}
            <span style={{ fontSize:11, color:"#00e5ff" }}><strong>{lastResult.total_vulns}</strong> total</span>
          </div>
        </div>
      )}

      {/* Status counts */}
      <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:12 }}>
        {Object.entries(patches?.by_status || {}).filter(([s]) => s !== "wontfix").map(([status, count]) => (
          <div key={status} style={{ background:"#0d1318", border:"1px solid #1a2530", borderRadius:8, padding:"14px 16px", borderTop:`2px solid ${STATUS_COLOR[status]||"#4a6070"}` }}>
            <div style={{ fontSize:9, color:"#4a6070", letterSpacing:"0.2em", marginBottom:6, textTransform:"uppercase" }}>{status}</div>
            <div style={{ fontFamily:"Syne,sans-serif", fontSize:28, fontWeight:800, color:STATUS_COLOR[status]||"#4a6070" }}>{count}</div>
          </div>
        ))}
      </div>

      {/* Full vuln table — auto-refreshes every 5s */}
      <Card title="◈ All Vulnerabilities" badge={`${records.length} TRACKED`}>
        <table style={{ width:"100%", borderCollapse:"collapse" }}>
          <thead><tr><Th>CVE ID</Th><Th>Host</Th><Th>Package</Th><Th>Current Ver.</Th><Th>CVSS</Th><Th>Severity</Th><Th>Status</Th><Th>Fix Version</Th></tr></thead>
          <tbody>
            {records.map((r, i) => (
              <TR key={i}>
                <Td style={{ color:"#00e5ff" }}>{r.cve_id}</Td>
                <Td style={{ color:"#7a9aaa", fontSize:10 }}>{r.host_ip}<br/><span style={{ color:"#4a6070" }}>{r.hostname}</span></Td>
                <Td>{r.package}</Td>
                <Td style={{ fontSize:10, color:"#4a6070", fontFamily:"monospace" }}>{r.current_version}</Td>
                <Td style={{ fontSize:13, fontWeight:700, color:SEV[r.severity] }}>{r.cvss_score}</Td>
                <Td><SevBadge sev={r.severity} /></Td>
                <Td><StatusBadge status={r.status} /></Td>
                <Td style={{ color:"#00e676", fontFamily:"monospace", fontSize:10 }}>{r.fixed_version || "—"}</Td>
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
  const PLACEHOLDERS = { hash:"SHA256 / MD5 / SHA1 (e.g. 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f)", ip:"IP address (e.g. 45.33.32.156)", url:"URL (e.g. https://example.com)" };

  const check = async () => {
    setLoading(true); setError(null); setResult(null);
    try {
      const r = await fetch(API + ENDPOINTS[mode], { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ [FIELDS[mode]]:input }) });
      setResult(await r.json());
    } catch (e) { setError(e.message); } finally { setLoading(false); }
  };

  const isMalicious = result && (result.malicious || 0) > 0;

  return (
    <div style={{ display:"grid", gap:20 }}>
      <Card title="⬡ VirusTotal Intelligence" badge="LIVE API">
        <div style={{ display:"flex", gap:10, marginBottom:16 }}>
          {["hash","ip","url"].map(m => (
            <button key={m} onClick={() => { setMode(m); setResult(null); setInput(""); }} style={{ fontFamily:"JetBrains Mono,monospace", fontSize:10, letterSpacing:"0.1em", padding:"6px 14px", borderRadius:4, cursor:"pointer", textTransform:"uppercase", border:`1px solid ${mode===m?"#00e5ff":"#1a2530"}`, background:mode===m?"rgba(0,229,255,0.1)":"transparent", color:mode===m?"#00e5ff":"#4a6070" }}>
              {m === "hash" ? "File Hash" : m.toUpperCase()}
            </button>
          ))}
        </div>
        <div style={{ display:"flex", gap:10 }}>
          <input value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key==="Enter"&&check()} placeholder={PLACEHOLDERS[mode]}
            style={{ flex:1, fontFamily:"JetBrains Mono,monospace", fontSize:11, padding:"10px 14px", borderRadius:4, background:"rgba(0,0,0,0.4)", border:"1px solid #1a2530", color:"#c8d8e8", outline:"none" }} />
          <button onClick={check} disabled={!input||loading} style={{ fontFamily:"JetBrains Mono,monospace", fontSize:11, padding:"10px 18px", borderRadius:4, border:"none", background:"#00e5ff", color:"#000", cursor:input&&!loading?"pointer":"not-allowed", fontWeight:700, textTransform:"uppercase" }}>
            {loading ? "Checking..." : "Check"}
          </button>
        </div>
        {error && <div style={{ color:"#ff6b35", fontSize:11, marginTop:10 }}>⚠ {error}</div>}
        {result && (
          <div style={{ marginTop:20, padding:20, background:"rgba(0,0,0,0.3)", borderRadius:8, border:`1px solid ${isMalicious?"#ff1a4b44":"#00e67644"}` }}>
            <div style={{ display:"flex", alignItems:"center", gap:12, marginBottom:16, padding:"10px 14px", borderRadius:6, background:isMalicious?"rgba(255,26,75,0.1)":"rgba(0,230,118,0.1)" }}>
              <span style={{ fontSize:24 }}>{isMalicious ? "🚨" : "✅"}</span>
              <div>
                <div style={{ fontFamily:"Syne,sans-serif", fontSize:16, fontWeight:700, color:isMalicious?"#ff1a4b":"#00e676" }}>{isMalicious?"MALICIOUS DETECTED":result.error?"NOT FOUND / ERROR":"CLEAN"}</div>
                {result.threat_label && <div style={{ fontSize:11, color:"#ff6b35", marginTop:2 }}>{result.threat_label}</div>}
              </div>
            </div>
            <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill,minmax(160px,1fr))", gap:10 }}>
              {Object.entries(result).filter(([k]) => !["from_cache","source","file_names","tags","categories","_cached_at"].includes(k)).map(([k,v]) => (
                <div key={k} style={{ padding:"8px 10px", background:"rgba(0,0,0,0.2)", borderRadius:4 }}>
                  <div style={{ fontSize:9, color:"#4a6070", letterSpacing:"0.15em", textTransform:"uppercase", marginBottom:4 }}>{k.replace(/_/g," ")}</div>
                  <div style={{ fontSize:12, color:"#c8d8e8", wordBreak:"break-all" }}>{String(v)}</div>
                </div>
              ))}
            </div>
            {result.tags?.length > 0 && (
              <div style={{ marginTop:10, display:"flex", gap:6, flexWrap:"wrap" }}>
                {result.tags.map(t => <span key={t} style={{ fontSize:10, padding:"2px 8px", borderRadius:3, background:"rgba(124,140,248,0.15)", color:"#7c8cf8", border:"1px solid rgba(124,140,248,0.3)" }}>{t}</span>)}
              </div>
            )}
            {result.from_cache && <div style={{ fontSize:9, color:"#4a6070", marginTop:8 }}>📦 Served from local cache</div>}
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
  const { data: sseRisk, connected }        = useSSE("/ai/risk-stream");  // FR-AI-04
  const [sseHistory, setSseHistory]         = useState([]);

  useEffect(() => {
    if (sseRisk) setSseHistory(prev => [...prev.slice(-19), { ...sseRisk, ts: new Date().toISOString() }]);
  }, [sseRisk]);

  const SSESparkline = ({ history }) => {
    if (!history.length) return <span style={{ fontSize:10, color:"#4a6070" }}>Waiting for stream data...</span>;
    const W=220, H=44, max = Math.max(...history.map(p => p.score), 1);
    const coords = history.map((p,i) => `${(i/(history.length-1||1))*W},${H-(p.score/max)*H}`).join(" ");
    const last = history[history.length-1];
    return (
      <div style={{ display:"flex", alignItems:"center", gap:16 }}>
        <svg width={W} height={H} style={{ overflow:"visible" }}>
          <polyline points={coords} fill="none" stroke="#7c8cf8" strokeWidth="2" />
          {last && <circle cx={(history.length-1)/(history.length-1||1)*W} cy={H-(last.score/max)*H} r="3" fill="#7c8cf8" />}
        </svg>
        {last && <div><div style={{ fontFamily:"Syne,sans-serif", fontSize:26, fontWeight:800, color:last.color||"#7c8cf8" }}>{last.score}</div><div style={{ fontSize:9, color:"#4a6070" }}>{last.level}</div></div>}
      </div>
    );
  };

  return (
    <div style={{ display:"grid", gap:20 }}>
      {/* FR-AI-04 — SSE real-time risk stream */}
      <Card title="⬡ FR-AI-04 — Real-Time Risk Stream" badge={connected ? "● LIVE SSE · 15s" : "○ CONNECTING"}>
        <div style={{ display:"flex", gap:20, alignItems:"flex-start", marginBottom: sseHistory.length > 1 ? 16 : 0 }}>
          <div style={{ flex:1 }}>
            <div style={{ marginBottom:12 }}>
              <span style={{ fontSize:10, color:connected?"#00e676":"#ff6b35" }}>
                {connected ? "✓ SSE stream connected — risk score pushed every 15s (latency <30s, FR-AI-04)" : "⚠ SSE stream not connected — API server must be running"}
              </span>
            </div>
            <SSESparkline history={sseHistory} />
          </div>
          {sseRisk && (
            <div style={{ minWidth:200, background:"rgba(0,0,0,0.25)", borderRadius:8, padding:"14px 16px", border:"1px solid #1a2530" }}>
              <div style={{ fontSize:9, color:"#4a6070", marginBottom:8, letterSpacing:"0.15em", textTransform:"uppercase" }}>Latest Push</div>
              <div style={{ fontSize:12, color:"#c8d8e8", lineHeight:2 }}>
                <div>VOC: <span style={{ color:"#ff6b35" }}>{sseRisk.breakdown?.voc_component}/60</span></div>
                <div>SOC: <span style={{ color:"#ffd600" }}>{sseRisk.breakdown?.soc_component}/25</span></div>
                <div>TI:  <span style={{ color:"#00e5ff" }}>{sseRisk.breakdown?.ti_component}/15</span></div>
                <div style={{ marginTop:4, fontSize:9, color:"#4a6070" }}>{sseRisk.computed_at?.slice(11,19)} UTC</div>
              </div>
            </div>
          )}
        </div>
        {sseHistory.length > 1 && (
          <div style={{ maxHeight:140, overflowY:"auto" }}>
            <table style={{ width:"100%", borderCollapse:"collapse" }}>
              <thead><tr><Th>Time</Th><Th>Score</Th><Th>Level</Th><Th>VOC</Th><Th>SOC</Th><Th>TI</Th></tr></thead>
              <tbody>
                {[...sseHistory].reverse().map((r,i) => (
                  <TR key={i}>
                    <Td style={{ fontSize:10, color:"#4a6070" }}>{r.ts?.slice(11,19)}</Td>
                    <Td style={{ fontSize:13, fontWeight:700, color:r.color||"#fff" }}>{r.score}</Td>
                    <Td style={{ fontSize:10, color:r.color||"#c8d8e8" }}>{r.level}</Td>
                    <Td style={{ fontSize:10, color:"#ff6b35" }}>{r.breakdown?.voc_component}</Td>
                    <Td style={{ fontSize:10, color:"#ffd600" }}>{r.breakdown?.soc_component}</Td>
                    <Td style={{ fontSize:10, color:"#00e5ff" }}>{r.breakdown?.ti_component}</Td>
                  </TR>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* FR-AI-02 — ML Model status */}
      <Card title="⬡ ML Model Status" badge="FR-AI-02 · 3 MODELS">
        <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12, marginBottom:16 }}>
          {status?.models && Object.entries(status.models).map(([name, ready]) => (
            <div key={name} style={{ padding:"14px 16px", background:"rgba(0,0,0,0.2)", borderRadius:6, border:`1px solid ${ready?"#00e67644":"#ff6b3544"}` }}>
              <div style={{ fontSize:9, color:"#4a6070", letterSpacing:"0.15em", marginBottom:8, textTransform:"uppercase" }}>{name.replace(/_/g," ")}</div>
              <div style={{ fontSize:14, fontWeight:700, color:ready?"#00e676":"#ff6b35" }}>{ready ? "✓ TRAINED" : "✗ NOT READY"}</div>
            </div>
          ))}
        </div>
        {status?.training_report && (
          <div style={{ fontSize:11, color:"#7a9aaa", lineHeight:1.8, padding:"10px 12px", background:"rgba(0,0,0,0.2)", borderRadius:6 }}>
            <strong>Training Report</strong> — {status.training_report.dataset_size} CVEs · {status.training_report.valid_samples} valid · source: {status.training_report.data_source}<br />
            {!status.training_report.models?.exploitability?.error && <>Exploitability R²: <span style={{ color:"#00e676" }}>{status.training_report.models?.exploitability?.r2_score}</span> · RMSE: {status.training_report.models?.exploitability?.rmse}<br/></>}
            {!status.training_report.models?.severity_classifier?.error && <>Classifier Accuracy: <span style={{ color:"#00e676" }}>{status.training_report.models?.severity_classifier?.accuracy}</span><br/></>}
            {!status.training_report.models?.anomaly_detector?.error && <>Anomaly samples: <span style={{ color:"#00e676" }}>{status.training_report.models?.anomaly_detector?.training_samples}</span><br/></>}
          </div>
        )}
        {!status?.all_ready && (
          <div style={{ marginTop:12, padding:"10px 14px", background:"rgba(255,107,53,0.1)", borderRadius:6, border:"1px solid rgba(255,107,53,0.3)", fontSize:11, color:"#ff6b35" }}>
            ⚠ Models not trained. Run inside the container:<br />
            <code style={{ background:"rgba(0,0,0,0.3)", padding:"2px 6px", borderRadius:2, fontSize:10 }}>docker exec icoc-api python ai/train.py --synthetic</code>
          </div>
        )}
      </Card>

      {/* FR-AI-03 — Anomaly Detection */}
      <Card title="◈ Anomaly Detection" badge="ISOLATION FOREST · FR-AI-03">
        {anomErr ? <ErrorMsg msg={anomErr} /> : anomalies?.anomalies ? (
          <table style={{ width:"100%", borderCollapse:"collapse" }}>
            <thead><tr><Th>CVE ID</Th><Th>Host</Th><Th>CVSS</Th><Th>Severity</Th><Th>Status</Th><Th>Score</Th><Th>Level</Th><Th>Reason</Th></tr></thead>
            <tbody>
              {anomalies.anomalies.map((a,i) => (
                <TR key={i} style={{ background:a.is_anomaly?"rgba(255,26,75,0.04)":"transparent" }}>
                  <Td style={{ color:"#00e5ff" }}>{a.cve_id}</Td>
                  <Td style={{ color:"#7a9aaa", fontSize:10 }}>{a.host_ip}</Td>
                  <Td style={{ fontSize:12, fontWeight:700, color:SEV[a.severity] }}>{a.cvss_score}</Td>
                  <Td><SevBadge sev={a.severity} /></Td>
                  <Td><StatusBadge status={a.status} /></Td>
                  <Td style={{ fontFamily:"monospace", color:a.is_anomaly?"#ff1a4b":"#4a6070" }}>{a.anomaly_score}</Td>
                  <Td style={{ fontSize:10, color:a.anomaly_level==="severe"?"#ff1a4b":a.anomaly_level==="moderate"?"#ff6b35":"#4a6070" }}>{a.is_anomaly?`⚠ ${a.anomaly_level}`:"normal"}</Td>
                  <Td style={{ color:"#7a9aaa", maxWidth:200, fontSize:10 }}>{a.reason||"—"}</Td>
                </TR>
              ))}
            </tbody>
          </table>
        ) : <Spinner />}
      </Card>
    </div>
  );
}

// ── Compliance Tab — FR-VOC-07 ────────────────────────────────────────────────
function ComplianceTab() {
  const { data, loading, error } = useApi("/voc/compliance");
  if (loading) return <Spinner />;
  if (error)   return <ErrorMsg msg={error} />;
  return (
    <div style={{ display:"grid", gap:20 }}>
      {data?.frameworks && Object.entries(data.frameworks).map(([fw, fdata]) => (
        <Card key={fw} title={`${fw} (${fdata.version})`} badge={`${fdata.overall_score_pct}% · ${fdata.status}`}>
          <table style={{ width:"100%", borderCollapse:"collapse" }}>
            <thead><tr><Th>Control</Th><Th>Name</Th><Th>Score</Th><Th>Weight</Th><Th>Status</Th><Th>Findings</Th></tr></thead>
            <tbody>
              {Object.entries(fdata.controls).map(([ctrl_id, ctrl]) => (
                <TR key={ctrl_id}>
                  <Td style={{ color:"#00e5ff", fontWeight:600 }}>{ctrl_id}</Td>
                  <Td>{ctrl.name}</Td>
                  <Td>
                    <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                      <div style={{ width:60, height:4, background:"#1a2530", borderRadius:2 }}>
                        <div style={{ height:"100%", width:`${ctrl.score_pct}%`, background:ctrl.score_pct>=75?"#00e676":ctrl.score_pct>=50?"#ffd600":"#ff1a4b", borderRadius:2 }} />
                      </div>
                      <span style={{ fontSize:11, fontWeight:700, color:ctrl.score_pct>=75?"#00e676":ctrl.score_pct>=50?"#ffd600":"#ff1a4b" }}>{ctrl.score_pct}%</span>
                    </div>
                  </Td>
                  <Td style={{ color:"#4a6070", fontSize:10 }}>{ctrl.weight}</Td>
                  <Td><span style={{ fontSize:9, padding:"2px 8px", borderRadius:3, background:ctrl.status==="Pass"?"rgba(0,230,118,0.12)":ctrl.status==="Partial"?"rgba(255,214,0,0.12)":"rgba(255,26,75,0.12)", color:ctrl.status==="Pass"?"#00e676":ctrl.status==="Partial"?"#ffd600":"#ff1a4b", border:`1px solid ${ctrl.status==="Pass"?"#00e676":ctrl.status==="Partial"?"#ffd600":"#ff1a4b"}44` }}>{ctrl.status}</span></Td>
                  <Td style={{ color:"#7a9aaa", fontSize:10 }}>{ctrl.findings?.join("; ")||"—"}</Td>
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
// ── Event Detail Modal ────────────────────────────────────────────────────────
function EventDetailModal({ event, onClose }) {
  const [rem, setRem] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!event) return;
    setLoading(true);
    fetch(`${API}/events/remediation/${event.id}`)
      .then(r => r.json())
      .then(d => { setRem(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [event]);

  if (!event) return null;
  const sev = event.severity;
  return (
    <div onClick={onClose} style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.75)", zIndex:1000, display:"flex", alignItems:"center", justifyContent:"center", backdropFilter:"blur(4px)" }}>
      <div onClick={e => e.stopPropagation()} style={{ background:"#0d1318", border:`1px solid ${SEV[sev]||"#1a2530"}`, borderTop:`3px solid ${SEV[sev]||"#00e5ff"}`, borderRadius:10, padding:28, width:640, maxWidth:"95vw", maxHeight:"85vh", overflowY:"auto", position:"relative" }}>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:20 }}>
          <div>
            <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:6 }}>
              <span style={{ fontSize:22 }}>{EVT_ICONS[event.event_type]||"🔹"}</span>
              <SevBadge sev={sev} />
              <span style={{ fontFamily:"Syne,sans-serif", fontSize:13, fontWeight:700, color:SEV[sev]||"#c8d8e8" }}>{event.event_type}</span>
            </div>
            <div style={{ fontSize:12, color:"#c8d8e8", lineHeight:1.5 }}>{event.summary}</div>
            <div style={{ fontSize:10, color:"#4a6070", marginTop:5 }}>
              {String(event.timestamp).slice(0,19).replace("T"," ")} UTC · Host: {event.host_ip}
              {event.src_ip && <> · Source: <span style={{ color:"#ff6b35" }}>{event.src_ip}</span></>}
            </div>
          </div>
          <button onClick={onClose} style={{ background:"none", border:"none", color:"#4a6070", fontSize:20, cursor:"pointer", padding:4 }}>✕</button>
        </div>
        {loading && <div style={{ color:"#4a6070", fontSize:11, padding:20, textAlign:"center" }}>⟳ Loading remediation advice...</div>}
        {rem && rem.remediation && (
          <div style={{ display:"grid", gap:14 }}>
            <div style={{ background:"rgba(0,0,0,0.3)", borderRadius:8, padding:14, borderLeft:`3px solid ${SEV[sev]||"#00e5ff"}` }}>
              <div style={{ fontSize:10, fontWeight:700, color:"#00e5ff", letterSpacing:"0.15em", marginBottom:8, textTransform:"uppercase" }}>⚡ What Happened</div>
              <div style={{ fontSize:11, color:"#c8d8e8", lineHeight:1.7 }}>{rem.remediation.what}</div>
            </div>
            <div style={{ background:"rgba(255,107,53,0.06)", borderRadius:8, padding:14, borderLeft:"3px solid #ff6b35" }}>
              <div style={{ fontSize:10, fontWeight:700, color:"#ff6b35", letterSpacing:"0.15em", marginBottom:8, textTransform:"uppercase" }}>⚠ Why It Matters</div>
              <div style={{ fontSize:11, color:"#c8d8e8", lineHeight:1.7 }}>{rem.remediation.why}</div>
            </div>
            <div style={{ background:"rgba(0,230,118,0.06)", borderRadius:8, padding:14, borderLeft:"3px solid #00e676" }}>
              <div style={{ fontSize:10, fontWeight:700, color:"#00e676", letterSpacing:"0.15em", marginBottom:10, textTransform:"uppercase" }}>🔧 How to Fix</div>
              {rem.remediation.fix.map((step, i) => (
                <div key={i} style={{ display:"flex", gap:10, marginBottom:8, alignItems:"flex-start" }}>
                  <span style={{ fontFamily:"Syne,sans-serif", fontSize:11, fontWeight:800, color:"#00e676", flexShrink:0, minWidth:18 }}>{i+1}.</span>
                  <span style={{ fontSize:11, color:"#c8d8e8", lineHeight:1.6 }}>
                    {step.split(/(`[^`]+`)/g).map((part, j) =>
                      part.startsWith("`") && part.endsWith("`")
                        ? <code key={j} style={{ background:"rgba(0,229,255,0.1)", color:"#00e5ff", padding:"1px 5px", borderRadius:3, fontSize:10, fontFamily:"JetBrains Mono,monospace" }}>{part.slice(1,-1)}</code>
                        : part
                    )}
                  </span>
                </div>
              ))}
            </div>
            {rem.remediation.ioc && (
              <div style={{ background:"rgba(0,0,0,0.3)", borderRadius:6, padding:10, fontFamily:"JetBrains Mono,monospace", fontSize:10, color:"#ffd600" }}>
                🔎 IOC: {rem.remediation.ioc}
              </div>
            )}
            {rem.remediation.mitre_technique && (
              <div style={{ background:"rgba(124,140,248,0.08)", borderRadius:6, padding:10, fontSize:10, color:"#7c8cf8", border:"1px solid rgba(124,140,248,0.2)" }}>
                🛡 MITRE ATT&CK: {rem.remediation.mitre_technique}
              </div>
            )}
            <div style={{ fontSize:9, color:"#4a6070", textAlign:"right" }}>
              {rem.ai_enabled ? "⚡ AI-powered analysis by Gemini" : "⚠ Add GEMINI_API_KEY to .env for AI analysis"}
            </div>
            {rem.raw_data && Object.keys(rem.raw_data).length > 0 && (
              <details style={{ fontSize:10, color:"#4a6070" }}>
                <summary style={{ cursor:"pointer", marginBottom:6 }}>Raw Event Data</summary>
                <pre style={{ background:"rgba(0,0,0,0.4)", padding:10, borderRadius:6, fontSize:9, color:"#4a6070", overflowX:"auto" }}>
                  {JSON.stringify(rem.raw_data, null, 2)}
                </pre>
              </details>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function DatabaseTab() {
  const { data: stats, loading, error, refetch } = useApi("/db/stats", 10000);
  const { data: riskHist }     = useApi("/db/risk-history?hours=2");
  const { data: cveData }      = useApi("/db/cves?limit=10&min_score=7");
  const { data: recentEvents } = useApi("/db/events?limit=15");
  const [initMsg, setInitMsg]  = useState(null);
  const [initializing, setInit]= useState(false);
  const [selectedEvent, setSelectedEvent] = useState(null);

  const initDb = async () => {
    setInit(true); setInitMsg(null);
    try { const r = await fetch(API+"/db/init",{method:"POST"}); const d=await r.json(); setInitMsg(d.message||d.detail); refetch(); }
    catch(e) { setInitMsg("Error: "+e.message); }
    setInit(false);
  };

  const TABLE_INFO = {
    security_events:     {label:"Security Events",   icon:"📡",color:"#ff6b35",desc:"Live events from victim agent"},
    cve_database:        {label:"CVE Database",      icon:"🔍",color:"#ff1a4b",desc:"NVD CVE records (CVSS v3.1)"},
    patch_records:       {label:"Patch Records",     icon:"🔧",color:"#ffd600",desc:"Patch status per CVE per host"},
    scan_reports:        {label:"Scan Reports",      icon:"📋",color:"#00e5ff",desc:"Full scan result history"},
    risk_score_history:  {label:"Risk History",      icon:"📈",color:"#7c8cf8",desc:"AI risk score time-series"},
    host_inventory:      {label:"Host Inventory",    icon:"💻",color:"#00e676",desc:"Software inventory per host"},
    attack_log:          {label:"Attack Log",        icon:"⚔", color:"#ff1a4b",desc:"Attacker actions (lab)"},
    compliance_snapshots:{label:"Compliance",        icon:"✅",color:"#00e676",desc:"Compliance score history"},
    threat_intel:        {label:"Threat Intel",      icon:"🌐",color:"#ffd600",desc:"Threat intelligence feed"},
  };

  const RiskSparkline = ({ data }) => {
    if (!data?.history?.length) return <span style={{fontSize:10,color:"#4a6070"}}>No data yet</span>;
    const pts=data.history, max=Math.max(...pts.map(p=>p.score),1), W=200, H=40;
    const coords=pts.map((p,i)=>`${(i/(pts.length-1||1))*W},${H-(p.score/max)*H}`).join(" ");
    const last=pts[pts.length-1];
    return (
      <div style={{display:"flex",alignItems:"center",gap:12}}>
        <svg width={W} height={H} style={{overflow:"visible"}}><polyline points={coords} fill="none" stroke="#7c8cf8" strokeWidth="2"/>{last&&<circle cx={(pts.length-1)/(pts.length-1||1)*W} cy={H-(last.score/max)*H} r="3" fill="#7c8cf8"/>}</svg>
        {last&&<div><div style={{fontFamily:"Syne,sans-serif",fontSize:20,fontWeight:800,color:last.color||"#7c8cf8"}}>{last.score}</div><div style={{fontSize:9,color:"#4a6070"}}>{last.level}</div></div>}
      </div>
    );
  };

  if (loading) return <Spinner />;
  if (error) return (
    <div style={{display:"grid",gap:16}}>
      <ErrorMsg msg={error}/>
      <Card title="⬡ Initialize Database" badge="POSTGRES">
        <p style={{fontSize:11,color:"#7a9aaa",marginBottom:14,lineHeight:1.6}}>PostgreSQL not connected. Start the <code style={{color:"#00e5ff"}}>db</code> container then initialize:</p>
        <button onClick={initDb} disabled={initializing} style={{fontFamily:"JetBrains Mono,monospace",fontSize:11,padding:"9px 20px",borderRadius:4,border:"none",background:"#00e5ff",color:"#000",cursor:"pointer",fontWeight:700,textTransform:"uppercase"}}>{initializing?"Initializing...":"⬡ Initialize DB + Seed Data"}</button>
        {initMsg&&<div style={{marginTop:10,fontSize:11,color:"#00e676"}}>{initMsg}</div>}
      </Card>
    </div>
  );

  return (
    <div style={{display:"grid",gap:20}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
        <div>
          <h2 style={{fontFamily:"Syne,sans-serif",fontSize:16,color:"#00e5ff"}}>PostgreSQL Database</h2>
          <p style={{fontSize:11,color:"#4a6070",marginTop:4}}>Size: <span style={{color:"#00e676"}}>{stats?.db_size||"—"}</span> · Connected · icoc@db:5432/icoc</p>
        </div>
        <button onClick={initDb} disabled={initializing} style={{fontFamily:"JetBrains Mono,monospace",fontSize:10,padding:"7px 16px",borderRadius:4,border:"1px solid #1a2530",background:"transparent",color:"#4a6070",cursor:"pointer",textTransform:"uppercase"}}>{initializing?"Seeding...":"Re-seed Demo Data"}</button>
      </div>

      <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:12}}>
        {Object.entries(TABLE_INFO).map(([table,info])=>(
          <div key={table} style={{background:"#0d1318",border:"1px solid #1a2530",borderRadius:8,padding:"14px 16px",borderLeft:`3px solid ${info.color}`}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
              <div><div style={{fontSize:11,fontWeight:700,color:"#c8d8e8",marginBottom:3}}>{info.icon} {info.label}</div><div style={{fontSize:9,color:"#4a6070"}}>{info.desc}</div></div>
              <div style={{fontFamily:"Syne,sans-serif",fontSize:26,fontWeight:800,color:info.color,lineHeight:1,flexShrink:0}}>{stats?.[table]??"—"}</div>
            </div>
            <div style={{marginTop:10,fontSize:9,color:"#4a6070",fontFamily:"monospace"}}>SELECT * FROM {table}</div>
          </div>
        ))}
      </div>

      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:20}}>
        <Card title="📈 Risk Score History" badge="risk_score_history">
          <RiskSparkline data={riskHist}/>
          {riskHist?.history?.length>0&&(
            <table style={{width:"100%",borderCollapse:"collapse",marginTop:14}}>
              <thead><tr><Th>Time</Th><Th>Score</Th><Th>Level</Th><Th>VOC</Th><Th>SOC</Th><Th>TI</Th></tr></thead>
              <tbody>{[...riskHist.history].reverse().slice(0,6).map((r,i)=>(
                <TR key={i}><Td style={{fontSize:10,color:"#4a6070"}}>{String(r.computed_at).slice(11,19)}</Td><Td style={{fontSize:12,fontWeight:700,color:r.color||"#fff"}}>{r.score}</Td><Td style={{fontSize:10,color:r.color||"#c8d8e8"}}>{r.level}</Td><Td style={{fontSize:10,color:"#ff6b35"}}>{r.voc_component}</Td><Td style={{fontSize:10,color:"#ffd600"}}>{r.soc_component}</Td><Td style={{fontSize:10,color:"#00e5ff"}}>{r.ti_component}</Td></TR>
              ))}</tbody>
            </table>
          )}
        </Card>

        <Card title="📡 Recent Events" badge="security_events">
          <div style={{fontSize:9,color:"#4a6070",marginBottom:8}}>Click any event to see what happened and how to fix it</div>
          <div style={{maxHeight:280,overflowY:"auto"}}>
            {recentEvents?.events?.map((e,i)=>(
              <div key={i} onClick={()=>setSelectedEvent(e)} style={{padding:"8px 6px",borderBottom:"1px solid rgba(26,37,48,0.5)",display:"flex",gap:10,alignItems:"flex-start",cursor:"pointer",borderRadius:4,transition:"background 0.15s"}} onMouseEnter={ev=>ev.currentTarget.style.background="rgba(0,229,255,0.04)"} onMouseLeave={ev=>ev.currentTarget.style.background="transparent"}>
                <div style={{width:6,height:6,borderRadius:"50%",background:SEV[e.severity]||"#4a6070",marginTop:4,flexShrink:0}}/>
                <div style={{flex:1,minWidth:0}}>
                  <div style={{fontSize:10,color:"#c8d8e8",lineHeight:1.4}}>{e.summary||e.event_type}</div>
                  <div style={{fontSize:9,color:"#4a6070",marginTop:2}}>{e.event_type} · {String(e.timestamp).slice(11,19)} · {e.host_ip}{e.fail_count>0&&<span style={{color:"#ffd600"}}> · {e.fail_count} attempts</span>}{e.auto_blocked&&<span style={{color:"#ff1a4b",fontWeight:700}}> · BLOCKED</span>}</div>
                </div>
                <span style={{fontSize:9,padding:"2px 6px",borderRadius:2,flexShrink:0,background:SEV_BG[e.severity]||"transparent",color:SEV[e.severity]||"#4a6070"}}>{e.severity}</span>
              </div>
            ))}
          </div>
          {selectedEvent && <EventDetailModal event={selectedEvent} onClose={()=>setSelectedEvent(null)} />}
        </Card>

        <Card title="🔍 CVE Database" badge="cve_database · CVSS ≥7.0">
          <table style={{width:"100%",borderCollapse:"collapse"}}>
            <thead><tr><Th>CVE ID</Th><Th>Score</Th><Th>Severity</Th><Th>Source</Th></tr></thead>
            <tbody>{cveData?.cves?.map((c,i)=>(
              <TR key={i}><Td style={{color:"#00e5ff"}}>{c.cve_id}</Td><Td style={{fontSize:13,fontWeight:700,color:SEV[c.severity]||"#fff"}}>{c.cvss_score}</Td><Td><SevBadge sev={c.severity}/></Td><Td style={{color:"#4a6070",fontSize:9}}>{c.source}</Td></TR>
            ))}</tbody>
          </table>
        </Card>

        <Card title="🗄 Schema Reference" badge="PostgreSQL">
          <div style={{fontFamily:"JetBrains Mono,monospace",fontSize:9,color:"#4a6070",lineHeight:2}}>
            {[["security_events","id, event_id, host_ip, event_type, severity, summary, timestamp"],["cve_database","id, cve_id, cvss_score, cvss_vector, severity, published"],["patch_records","id, cve_id, host_ip, status, cvss_score, applied_at"],["risk_score_history","id, score, level, voc_component, soc_component, computed_at"],["scan_reports","id, scan_id, total_vulns, critical_count, completed_at"],["host_inventory","id, host_ip, package, version, scanned_at"],["attack_log","id, attacker_ip, victim_ip, attack_type, launched_at"],["compliance_snapshots","id, framework, overall_score, status, computed_at"]].map(([t,c])=>(
              <div key={t} style={{marginBottom:6}}><span style={{color:"#00e5ff"}}>{t}</span><span style={{color:"#1a2530",marginLeft:8}}>{c}</span></div>
            ))}
          </div>
        </Card>
      </div>
      {initMsg&&<div style={{padding:"10px 14px",background:"rgba(0,230,118,0.1)",borderRadius:6,border:"1px solid rgba(0,230,118,0.3)",fontSize:11,color:"#00e676"}}>{initMsg}</div>}
    </div>
  );
}

// ── Attack Console Tab ─────────────────────────────────────────────────────────
const ATTACK_DEFS = {
  "1":  {label:"SSH Brute Force",       color:"#ff1a4b",icon:"🔨",desc:"Dictionary attack on SSH port 22",              cvss:"N/A", mitre:"T1110.001"},
  "2":  {label:"Port Scan",             color:"#ff6b35",icon:"🔍",desc:"TCP scan of all common ports",                  cvss:"N/A", mitre:"T1046"},
  "3":  {label:"CVE-2024-6387 Exploit", color:"#ff1a4b",icon:"💥",desc:"OpenSSH regreSSHion RCE probe",                  cvss:"8.1", mitre:"T1190"},
  "4":  {label:"SQL Injection",         color:"#ff6b35",icon:"💉",desc:"7 SQLi payloads on /login",                     cvss:"9.1", mitre:"T1190"},
  "5":  {label:"LFI / Path Traversal",  color:"#ff6b35",icon:"📂",desc:"Read /etc/passwd, /etc/shadow",                cvss:"7.5", mitre:"T1083"},
  "6":  {label:"Reverse Shell",         color:"#ff1a4b",icon:"💀",desc:"bash -i reverse shell to :4444",               cvss:"9.8", mitre:"T1059.004"},
  "7":  {label:"Malware Drop",          color:"#ff1a4b",icon:"🦠",desc:"Drop persistence scripts in /tmp",              cvss:"N/A", mitre:"T1547"},
  "8":  {label:"DoS / Flood",           color:"#ffd600",icon:"🌊",desc:"Connection flood on SSH port",                  cvss:"7.5", mitre:"T1499"},
  "all":{label:"Full Kill Chain",       color:"#ff1a4b",icon:"☠️",desc:"All phases: Recon→Access→Exploit→Persist→Impact",cvss:"10.0",mitre:"Multiple"},
};

function AttackTab() {
  const [events, setEvents]   = useState([]);
  const [attacks, setAttacks] = useState([]);
  const [stats, setStats]     = useState(null);
  const [launching, setLaunch]= useState(null);
  const [filter, setFilter]   = useState("all");

  const fetchData = useCallback(async () => {
    try {
      const [evtR,atkR,statR] = await Promise.all([fetch(API+"/events/live?limit=80"),fetch(API+"/events/attacks?limit=30"),fetch(API+"/events/stats")]);
      if (evtR.ok)  { const d=await evtR.json();  setEvents(d.events||[]); }
      if (atkR.ok)  { const d=await atkR.json();  setAttacks(d.attacks||[]); }
      if (statR.ok) setStats(await statR.json());
    } catch {}
  }, []);

  useEffect(() => { fetchData(); const id=setInterval(fetchData,2000); return ()=>clearInterval(id); }, [fetchData]);

  const launchAttack = async (id) => {
    setLaunch(id);
    try { await fetch(API+"/attacks/run",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({attack_id:id})}); setTimeout(()=>{setLaunch(null);fetchData();},3000); }
    catch { setLaunch(null); }
  };

  const filteredEvts = filter==="all" ? events : events.filter(e=>e.severity===filter);

  return (
    <div style={{display:"grid",gap:20}}>
      {stats&&(
        <div style={{display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:10}}>
          {[["Total Events",stats.total_events,"#00e5ff"],["Critical",stats.severity_breakdown?.Critical||0,"#ff1a4b"],["High",stats.severity_breakdown?.High||0,"#ff6b35"],["Alerts (5min)",stats.alert_count_5min,"#ffd600"],["Incidents",stats.incidents,"#ff1a4b"]].map(([label,val,color])=>(
            <div key={label} style={{background:"#0d1318",border:"1px solid #1a2530",borderRadius:8,padding:"12px 14px",borderTop:`2px solid ${color}`}}>
              <div style={{fontSize:9,color:"#4a6070",letterSpacing:"0.2em",textTransform:"uppercase",marginBottom:6}}>{label}</div>
              <div style={{fontFamily:"Syne,sans-serif",fontSize:26,fontWeight:800,color}}>{val}</div>
            </div>
          ))}
        </div>
      )}

      <div style={{display:"grid",gridTemplateColumns:"360px 1fr",gap:20}}>
        <div>
          <Card title="⚔ Attack Launcher" badge={`ATTACKER: ${import.meta.env.VITE_ATTACKER_IP || "192.168.237.131"}`}>
            <div style={{fontSize:10,color:"#4a6070",marginBottom:14}}>Target: <span style={{color:"#ff6b35"}}>{import.meta.env.VITE_VICTIM_IP || "192.168.237.129"} (victim)</span> · Events appear in SOC in real-time</div>
            <div style={{display:"flex",flexDirection:"column",gap:8}}>
              {Object.entries(ATTACK_DEFS).map(([id,atk])=>(
                <button key={id} onClick={()=>launchAttack(id)} disabled={launching===id} style={{display:"flex",alignItems:"flex-start",gap:10,background:launching===id?`${atk.color}22`:"rgba(0,0,0,0.25)",border:`1px solid ${launching===id?atk.color:"#1a2530"}`,borderRadius:6,padding:"10px 12px",cursor:launching===id?"not-allowed":"pointer",textAlign:"left",transition:"all 0.2s",animation:launching===id?"pulse 0.8s ease-in-out infinite":"none"}}>
                  <span style={{fontSize:16,flexShrink:0}}>{launching===id?"⏳":atk.icon}</span>
                  <div style={{flex:1}}>
                    <div style={{fontSize:11,fontWeight:700,color:atk.color,fontFamily:"JetBrains Mono,monospace"}}>{atk.label}</div>
                    <div style={{fontSize:9,color:"#4a6070",marginTop:3}}>{atk.desc}</div>
                    <div style={{fontSize:9,marginTop:2}}>{atk.cvss!=="N/A"&&<span style={{color:"#ff6b35"}}>CVSS {atk.cvss} · </span>}<span style={{color:"#7c8cf8"}}>MITRE {atk.mitre}</span></div>
                  </div>
                  {launching===id&&<span style={{fontSize:9,color:atk.color,alignSelf:"center"}}>RUNNING...</span>}
                </button>
              ))}
            </div>
            <div style={{marginTop:14,padding:"10px 12px",background:"rgba(255,107,53,0.08)",borderRadius:6,border:"1px solid rgba(255,107,53,0.3)",fontSize:10,color:"#ff6b35"}}>
              💡 To run inside Docker:<br/><code style={{fontSize:9,color:"#ffd600"}}>docker exec -it icoc-attacker python /attacker/attacks.py --menu</code>
            </div>
          </Card>

          {stats?.active_brute_force&&Object.keys(stats.active_brute_force).length>0&&(
            <Card title="🔨 Active Brute Force" badge="FR-SOC-02" style={{marginTop:14}}>
              {Object.entries(stats.active_brute_force).map(([ip,count])=>(
                <div key={ip} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"8px 0",borderBottom:"1px solid #1a2530"}}>
                  <div><div style={{fontSize:11,color:"#ff1a4b",fontWeight:700}}>{ip}</div><div style={{fontSize:9,color:"#4a6070"}}>SSH brute-force in progress</div></div>
                  <div style={{fontSize:22,fontWeight:800,color:count>=5?"#ff1a4b":"#ffd600",fontFamily:"Syne,sans-serif"}}>{count}</div>
                </div>
              ))}
              {Object.values(stats.active_brute_force).some(c=>c>=5)&&<div style={{marginTop:10,padding:"8px 10px",background:"rgba(255,26,75,0.1)",borderRadius:4,fontSize:10,color:"#ff1a4b",border:"1px solid rgba(255,26,75,0.3)"}}>🚨 FR-SOC-02 TRIGGERED — Auto-block initiated</div>}
            </Card>
          )}

          {attacks.length>0&&(
            <Card title="⚔ Attack Log" badge={`${attacks.length} ATTACKS`} style={{marginTop:14}}>
              {attacks.slice(0,6).map((atk,i)=>(
                <div key={i} style={{padding:"7px 0",borderBottom:"1px solid rgba(26,37,48,0.5)",fontSize:10}}>
                  <div style={{color:"#ff6b35",fontWeight:600}}>{ATTACK_DEFS[atk.details?.attack_id]?.icon||"⚔"} {atk.attack_type}</div>
                  <div style={{color:"#4a6070",marginTop:2}}>{atk.timestamp?.slice(11,19)} · {atk.attacker_ip} → {atk.victim_ip}</div>
                </div>
              ))}
            </Card>
          )}
        </div>

        <Card title="📡 Live Event Feed" badge="REAL-TIME · 2s REFRESH">
          <div style={{display:"flex",gap:8,marginBottom:14}}>
            {["all","Critical","High","Medium","Low","Info"].map(f=>(
              <button key={f} onClick={()=>setFilter(f)} style={{fontSize:9,padding:"4px 10px",borderRadius:3,cursor:"pointer",border:`1px solid ${filter===f?(SEV[f]||"#00e5ff"):"#1a2530"}`,background:filter===f?`${SEV[f]||"#00e5ff"}18`:"transparent",color:filter===f?(SEV[f]||"#00e5ff"):"#4a6070",textTransform:"uppercase",letterSpacing:"0.1em",fontFamily:"JetBrains Mono,monospace"}}>{f}</button>
            ))}
            <span style={{marginLeft:"auto",fontSize:9,color:"#4a6070",alignSelf:"center"}}>{filteredEvts.length} events</span>
          </div>
          {filteredEvts.length===0 ? (
            <div style={{textAlign:"center",padding:"40px 20px",color:"#4a6070",fontSize:11}}>
              <div style={{fontSize:32,marginBottom:10}}>📡</div>No events yet — launch an attack or wait for victim agent heartbeat
            </div>
          ) : (
            <div style={{maxHeight:560,overflowY:"auto"}}>
              {filteredEvts.map((evt,i)=>(
                <div key={i} style={{display:"flex",gap:12,padding:"9px 10px",borderBottom:"1px solid rgba(26,37,48,0.5)",background:evt.severity==="Critical"?"rgba(255,26,75,0.04)":evt.severity==="High"?"rgba(255,107,53,0.03)":"transparent",borderLeft:evt.severity==="Critical"?"3px solid #ff1a4b":evt.severity==="High"?"3px solid #ff6b35":"3px solid transparent",animation:i===0?"row-appear 0.3s ease":"none"}}>
                  <div style={{fontSize:16,flexShrink:0,marginTop:1}}>{EVT_ICONS[evt.event_type]||"🔹"}</div>
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",gap:8}}>
                      <div style={{fontSize:11,fontWeight:600,color:SEV[evt.severity]||"#c8d8e8"}}>{evt.data?.summary||evt.event_type}</div>
                      <span style={{fontSize:9,padding:"2px 7px",borderRadius:2,flexShrink:0,background:`${SEV[evt.severity]||"#4a6070"}18`,color:SEV[evt.severity]||"#4a6070",border:`1px solid ${SEV[evt.severity]||"#4a6070"}44`}}>{evt.severity}</span>
                    </div>
                    <div style={{fontSize:9,color:"#4a6070",marginTop:3,display:"flex",gap:12,flexWrap:"wrap"}}>
                      <span>{evt.event_type}</span><span>{evt.host_ip}</span><span>{evt.timestamp?.slice(11,19)} UTC</span>
                      {evt.data?.fail_count_5min&&<span style={{color:"#ffd600"}}>attempts: {evt.data.fail_count_5min}</span>}
                      {evt.data?.auto_block_triggered&&<span style={{color:"#ff1a4b",fontWeight:700}}>AUTO-BLOCKED ✓</span>}
                      {evt.data?.rule_triggered&&<span style={{color:"#7c8cf8"}}>{evt.data.rule_triggered}</span>}
                    </div>
                    {evt.data?.path&&<div style={{fontSize:9,color:"#ff6b35",marginTop:2,fontFamily:"monospace"}}>📁 {evt.data.path}</div>}
                    {evt.data?.src_ip&&evt.data.src_ip!=="unknown"&&<div style={{fontSize:9,color:"#4a6070",marginTop:2}}>src: {evt.data.src_ip}</div>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

// ── App Root ───────────────────────────────────────────────────────────────────
// ── Alerts Tab ────────────────────────────────────────────────────────────────
function AlertsTab() {
  const [severity, setSeverity]     = useState("all");
  const [selectedEvent, setSelected] = useState(null);
  const [search, setSearch]          = useState("");

  // Fetch all Critical, High, Medium events
  const { data: critData, loading: l1 } = useApi("/db/events?limit=500&severity=Critical", 15000);
  const { data: highData, loading: l2 } = useApi("/db/events?limit=500&severity=High",     15000);
  const { data: medData,  loading: l3 } = useApi("/db/events?limit=500&severity=Medium",   15000);

  const loading = l1 || l2 || l3;

  const allEvents = [
    ...(critData?.events || []),
    ...(highData?.events || []),
    ...(medData?.events  || []),
  ].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  const filtered = allEvents.filter(e => {
    const matchSev    = severity === "all" || e.severity === severity;
    const matchSearch = !search  || e.summary?.toLowerCase().includes(search.toLowerCase())
                                 || e.event_type?.toLowerCase().includes(search.toLowerCase())
                                 || e.host_ip?.includes(search)
                                 || (e.src_ip||"").includes(search);
    return matchSev && matchSearch;
  });

  const counts = {
    Critical: allEvents.filter(e => e.severity === "Critical").length,
    High:     allEvents.filter(e => e.severity === "High").length,
    Medium:   allEvents.filter(e => e.severity === "Medium").length,
  };

  return (
    <div style={{ display:"grid", gap:16 }}>
      {/* Header strip */}
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
        <div>
          <h2 style={{ fontFamily:"Syne,sans-serif", fontSize:16, color:"#ff1a4b" }}>🚨 Security Alerts</h2>
          <p style={{ fontSize:11, color:"#4a6070", marginTop:4 }}>All Critical, High and Medium events — click any to investigate</p>
        </div>
        <div style={{ display:"flex", gap:10 }}>
          {[["all","All",null],["Critical","Critical","#ff1a4b"],["High","High","#ff6b35"],["Medium","Medium","#ffd600"]].map(([val,label,color])=>(
            <button key={val} onClick={()=>setSeverity(val)} style={{
              fontFamily:"JetBrains Mono,monospace", fontSize:10, padding:"6px 14px",
              borderRadius:4, cursor:"pointer", textTransform:"uppercase",
              border:`1px solid ${severity===val?(color||"#00e5ff"):"#1a2530"}`,
              background: severity===val?`${(color||"#00e5ff")}18`:"transparent",
              color: severity===val?(color||"#00e5ff"):"#4a6070"
            }}>
              {label} {val!=="all" && <span style={{fontWeight:800}}>{counts[val]||0}</span>}
            </button>
          ))}
        </div>
      </div>

      {/* KPI strip */}
      <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12 }}>
        {[["Critical",counts.Critical,"#ff1a4b"],["High",counts.High,"#ff6b35"],["Medium",counts.Medium,"#ffd600"]].map(([sev,count,color])=>(
          <div key={sev} onClick={()=>setSeverity(sev===severity?"all":sev)} style={{ background:"#0d1318", border:`1px solid #1a2530`, borderTop:`2px solid ${color}`, borderRadius:8, padding:"14px 18px", cursor:"pointer" }}>
            <div style={{ fontSize:9, color:"#4a6070", letterSpacing:"0.2em", textTransform:"uppercase", marginBottom:6 }}>{sev} Events</div>
            <div style={{ fontFamily:"Syne,sans-serif", fontSize:36, fontWeight:800, color, lineHeight:1 }}>{count}</div>
          </div>
        ))}
      </div>

      {/* Search bar */}
      <div style={{ display:"flex", gap:10, alignItems:"center" }}>
        <input
          value={search} onChange={e=>setSearch(e.target.value)}
          placeholder="Search by summary, event type, host IP, source IP..."
          style={{ flex:1, background:"#0d1318", border:"1px solid #1a2530", borderRadius:6, padding:"9px 14px", color:"#c8d8e8", fontSize:11, fontFamily:"JetBrains Mono,monospace", outline:"none" }}
        />
        {search && <button onClick={()=>setSearch("")} style={{ background:"none", border:"none", color:"#4a6070", cursor:"pointer", fontSize:16 }}>×</button>}
        <span style={{ fontSize:10, color:"#4a6070", flexShrink:0 }}>{filtered.length} events</span>
      </div>

      {/* Events table */}
      {loading ? <Spinner /> : (
        <div style={{ background:"#0d1318", border:"1px solid #1a2530", borderRadius:8, overflow:"hidden" }}>
          <table style={{ width:"100%", borderCollapse:"collapse" }}>
            <thead>
              <tr style={{ background:"rgba(0,0,0,0.3)" }}>
                <Th>Severity</Th>
                <Th>Event Type</Th>
                <Th>Summary</Th>
                <Th>Host</Th>
                <Th>Source IP</Th>
                <Th>Time</Th>
                <Th>Action</Th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr><td colSpan={7} style={{ padding:24, textAlign:"center", color:"#4a6070", fontSize:11 }}>No events matching current filter</td></tr>
              )}
              {filtered.map((e, i) => (
                <TR key={i} style={{ borderBottom:"1px solid rgba(26,37,48,0.5)", background: i%2===0?"transparent":"rgba(0,0,0,0.15)" }}>
                  <Td><SevBadge sev={e.severity} /></Td>
                  <Td style={{ fontSize:10 }}>
                    <span style={{ marginRight:6 }}>{EVT_ICONS[e.event_type]||"🔹"}</span>
                    {e.event_type}
                  </Td>
                  <Td style={{ maxWidth:280, fontSize:10, color:"#c8d8e8" }}>{e.summary || "—"}</Td>
                  <Td style={{ fontFamily:"JetBrains Mono,monospace", fontSize:10, color:"#00e5ff" }}>{e.host_ip || "—"}</Td>
                  <Td style={{ fontFamily:"JetBrains Mono,monospace", fontSize:10, color: e.src_ip?"#ff6b35":"#4a6070" }}>{e.src_ip || "—"}</Td>
                  <Td style={{ fontSize:10, color:"#4a6070", whiteSpace:"nowrap" }}>
                    {String(e.timestamp).slice(0,10)}<br/>
                    <span style={{ color:"#c8d8e8" }}>{String(e.timestamp).slice(11,19)}</span>
                  </Td>
                  <Td>
                    <button onClick={()=>setSelected(e)} style={{
                      fontFamily:"JetBrains Mono,monospace", fontSize:9, padding:"4px 10px",
                      borderRadius:4, border:`1px solid ${SEV[e.severity]||"#00e5ff"}44`,
                      background:`${SEV[e.severity]||"#00e5ff"}11`, color:SEV[e.severity]||"#00e5ff",
                      cursor:"pointer", textTransform:"uppercase", letterSpacing:"0.08em"
                    }}>Investigate</button>
                  </Td>
                </TR>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {selectedEvent && <EventDetailModal event={selectedEvent} onClose={()=>setSelected(null)} />}
    </div>
  );
}

export default function App() {
  const [tab, setTab]   = useState("dashboard");
  const [time, setTime] = useState("");
  useEffect(() => { const tick=()=>setTime(new Date().toUTCString().slice(17,25)+" UTC"); tick(); const id=setInterval(tick,1000); return ()=>clearInterval(id); }, []);

  // Header risk — reuses /dashboard data (same call, cached by browser, no extra API hit)
  const { data: dashData }  = useApi("/dashboard", 15000);
  const { data: liveStats } = useApi("/events/stats", 5000);
  const headerRisk = dashData?.risk_score;

  const TABS = [
    {id:"dashboard", label:"Dashboard"},
    {id:"alerts",    label:"🚨 Alerts"},
    {id:"database",  label:"🗄 Database"},
    {id:"scanner",   label:"Scanner"},
    {id:"virustotal",label:"VirusTotal"},
    {id:"ml",        label:"ML Models"},
    {id:"compliance",label:"Compliance"},
  ];

  return (
    <div style={{background:"#080c10",color:"#c8d8e8",minHeight:"100vh",fontFamily:"JetBrains Mono, monospace",backgroundImage:"linear-gradient(rgba(0,229,255,0.025) 1px,transparent 1px),linear-gradient(90deg,rgba(0,229,255,0.025) 1px,transparent 1px)",backgroundSize:"40px 40px"}}>
      <header style={{display:"flex",alignItems:"center",justifyContent:"space-between",padding:"14px 28px",borderBottom:"1px solid #1a2530",background:"rgba(13,19,24,0.96)",backdropFilter:"blur(10px)",position:"sticky",top:0,zIndex:100}}>
        <div style={{display:"flex",alignItems:"center",gap:12}}>
          <div style={{width:34,height:34,background:"linear-gradient(135deg,#00e5ff,#0088aa)",clipPath:"polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:12,fontWeight:700,color:"#000"}}>⬡</div>
          <div><div style={{fontFamily:"Syne,sans-serif",fontWeight:800,fontSize:15,letterSpacing:"0.1em"}}>ICOC-LITE</div><div style={{fontSize:9,color:"#4a6070",letterSpacing:"0.2em"}}>VOC / AI MODULE · MEMBER 3</div></div>
        </div>

        <div style={{display:"flex",gap:6}}>
          {TABS.map(t=>(
            <button key={t.id} onClick={()=>setTab(t.id)} style={{fontFamily:"JetBrains Mono,monospace",fontSize:10,letterSpacing:"0.12em",padding:"6px 12px",borderRadius:4,cursor:"pointer",textTransform:"uppercase",border:`1px solid ${tab===t.id?"rgba(0,229,255,0.4)":"transparent"}`,background:tab===t.id?"rgba(0,229,255,0.07)":"transparent",color:tab===t.id?"#00e5ff":"#4a6070"}}>{t.label}</button>
          ))}
        </div>

        <div style={{display:"flex",alignItems:"center",gap:14}}>
          {liveStats&&(liveStats.severity_breakdown?.Critical>0||liveStats.severity_breakdown?.High>0)&&(
            <div style={{display:"flex",gap:8}}>
              {liveStats.severity_breakdown?.Critical>0&&<span style={{fontSize:10,color:"#ff1a4b",fontWeight:700,padding:"3px 8px",borderRadius:4,background:"rgba(255,26,75,0.1)",border:"1px solid rgba(255,26,75,0.3)",animation:"blink 1s ease-in-out infinite"}}>🚨 {liveStats.severity_breakdown.Critical} CRITICAL</span>}
              {liveStats.severity_breakdown?.High>0&&<span style={{fontSize:10,color:"#ff6b35",fontWeight:700,padding:"3px 8px",borderRadius:4,background:"rgba(255,107,53,0.1)",border:"1px solid rgba(255,107,53,0.3)"}}>⚠ {liveStats.severity_breakdown.High} HIGH</span>}
            </div>
          )}
          {headerRisk&&(
            <div style={{display:"flex",alignItems:"center",gap:8,padding:"5px 12px",borderRadius:6,background:`${headerRisk.color}18`,border:`1px solid ${headerRisk.color}55`}}>
              <div style={{width:7,height:7,borderRadius:"50%",background:headerRisk.color,animation:"blink 1s ease-in-out infinite"}}/>
              <span style={{fontSize:10,color:headerRisk.color,fontWeight:700,letterSpacing:"0.1em"}}>RISK: {headerRisk.level.toUpperCase()} · {headerRisk.score}/100</span>
            </div>
          )}
          <span style={{fontSize:10,color:"#4a6070"}}>{time}</span>
        </div>
      </header>

      <main style={{padding:"24px 28px"}}>
        {tab==="dashboard"  && <DashboardTab />}
        {tab==="alerts"     && <AlertsTab />}
        {tab==="database"   && <DatabaseTab />}

        {tab==="scanner"    && <ScannerTab />}
        {tab==="virustotal" && <VTTab />}
        {tab==="ml"         && <MLTab />}
        {tab==="compliance" && <ComplianceTab />}
      </main>

      <footer style={{textAlign:"center",padding:18,fontSize:9,color:"#1a2530",letterSpacing:"0.15em",borderTop:"1px solid #1a2530"}}>
        ICOC-LITE · VOC/AI MODULE · MEMBER 3 · ACADEMIC LAB · v1.0 · 2026
      </footer>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Syne:wght@400;600;700;800&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 4px; } ::-webkit-scrollbar-track { background: #080c10; } ::-webkit-scrollbar-thumb { background: #1a2530; border-radius: 2px; }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.6} }
        @keyframes row-appear { from{opacity:0;transform:translateY(-4px)} to{opacity:1;transform:translateY(0)} }
        input:focus { border-color: rgba(0,229,255,0.5) !important; }
      `}</style>
    </div>
  );
}
