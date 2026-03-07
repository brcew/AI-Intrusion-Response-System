"""
AI Intrusion Response System — Upgraded Streamlit Dashboard
Includes: Explainability, Threat Intelligence, Attack Map, Report Generator, SQL Injection Detection
Run: streamlit run dashboard/app.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
import time
import pandas as pd
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
from collections import deque

from app.services.intrusion_service import IntrusionService
from app.core.log_generator import generate_log
from app.core.explainability import ExplainabilityEngine
from app.core.threat_intelligence import ThreatIntelligence
from app.core.phishing_detector import PhishingDetector
from app.utils.report_generator import generate_excel_report

st.set_page_config(
    page_title="AI Intrusion Response System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .main { background-color: #0e1117; }
    .stMetric { background-color: #1e2130; border-radius: 8px; padding: 12px; }
    div[data-testid="stSidebarNav"] { display: none; }
    h1 { color: #00d4ff; }
</style>
""", unsafe_allow_html=True)

# ── SQL Injection Detection Engine ──
SQL_INJECTION_PATTERNS = [
    (r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|TRUNCATE|REPLACE)\b", "SQL Keyword"),
    (r"(--|#|/\*|\*/|;--)", "SQL Comment / Terminator"),
    (r"('\s*(OR|AND)\s*'[\s\d=])", "OR/AND Bypass"),
    (r"(\bOR\b\s+[\w'\"]+\s*=\s*[\w'\"]+)", "Always-True Condition"),
    (r"(1\s*=\s*1|'1'\s*=\s*'1'|1\s*=\s*'1')", "Tautology (1=1)"),
    (r"(;\s*(DROP|DELETE|INSERT|UPDATE|CREATE)\b)", "Chained Query"),
    (r"\b(SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY|PG_SLEEP\s*\()", "Time-Based Blind Injection"),
    (r"\b(xp_cmdshell|sp_executesql|OPENROWSET|BULK\s+INSERT)\b", "Stored Procedure / MSSQL Attack"),
    (r"(CHAR\s*\(\d+\)|CONCAT\s*\(|GROUP_CONCAT\s*\()", "Encoding / Obfuscation"),
    (r"(INFORMATION_SCHEMA|SYS\.TABLES|SYSOBJECTS|PG_TABLES)", "Schema Enumeration"),
    (r"(LOAD_FILE\s*\(|INTO\s+OUTFILE|INTO\s+DUMPFILE)", "File Read/Write Attempt"),
    (r"(\bUNION\b.{0,30}\bSELECT\b)", "UNION SELECT Attack"),
]

def detect_sql_injection(payload: str) -> dict:
    if not payload or not payload.strip():
        return {"detected": False, "risk": "None", "matches": [], "categories": []}

    matches = []
    categories = []
    for pattern, category in SQL_INJECTION_PATTERNS:
        found = re.findall(pattern, payload, re.IGNORECASE)
        if found:
            matches.extend([str(f) for f in found])
            if category not in categories:
                categories.append(category)

    unique_matches = list(dict.fromkeys(matches))

    if len(categories) >= 3:
        risk = "Critical"
    elif len(categories) == 2:
        risk = "High"
    elif len(categories) == 1:
        risk = "Medium"
    else:
        risk = "None"

    return {
        "detected": len(categories) > 0,
        "risk": risk,
        "matches": unique_matches,
        "categories": categories,
        "payload": payload,
    }

def scan_batch_payloads(payloads: list) -> list:
    results = []
    for p in payloads:
        r = detect_sql_injection(p)
        results.append({**r, "payload": p})
    return results

# ── Session state ──
def _init_state():
    defaults = {
        "service": None, "explainer": None, "intel": None,
        "phishing_detector": None,
        "initialized": False, "running": False,
        "log_buffer": deque(maxlen=200), "result_buffer": deque(maxlen=200),
        "explain_buffer": deque(maxlen=200), "ts_buffer": deque(maxlen=60),
        "metrics_df": None, "best_model": None,
        "phishing_metrics": None, "phishing_best_model": None,
        "traffic_mode": "mixed", "total_processed": 0,
        "total_anomalies": 0, "total_blocked": 0,
        "sqli_history": [],
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

_init_state()

# ── Sidebar ──
with st.sidebar:
    st.markdown("## 🛡️ AI Intrusion Response")
    st.markdown("---")
    st.markdown("### ⚙️ Configuration")
    traffic_mode = st.selectbox("Traffic Mode",
        options=["mixed","normal","brute_force","ddos"], index=0,
        format_func=lambda x: {"mixed":"🔀 Mixed (Realistic)","normal":"✅ Normal Only",
            "brute_force":"🔐 Brute Force Attack","ddos":"💥 DDoS Attack"}[x])
    st.session_state["traffic_mode"] = traffic_mode
    interval = st.slider("Simulation Speed (sec/tick)", 0.1, 2.0, 0.5, 0.1)
    st.markdown("---")
    st.markdown("### 🚀 Controls")
    col_start, col_stop = st.columns(2)
    start_clicked = col_start.button("▶ Start", use_container_width=True, type="primary")
    stop_clicked = col_stop.button("⏹ Stop", use_container_width=True)
    st.markdown("---")
    reset_clicked = st.button("🔄 Reset System", use_container_width=True)
    if reset_clicked:
        if st.session_state["service"] and st.session_state["initialized"]:
            st.session_state["service"].reset()
            st.session_state["intel"].reset()
        for key in ["log_buffer","result_buffer","explain_buffer","ts_buffer"]:
            st.session_state[key].clear()
        st.session_state.update({"running":False,"total_processed":0,
                                  "total_anomalies":0,"total_blocked":0,
                                  "sqli_history":[]})
        st.rerun()
    st.markdown("---")
    st.markdown("### 📥 Export Report")
    if st.session_state["initialized"] and st.session_state["total_processed"] > 0:
        svc_dl = st.session_state["service"]
        intel_dl = st.session_state["intel"]
        excel_bytes = generate_excel_report(
            results=list(st.session_state["result_buffer"]),
            blocked_ips=[b.to_dict() for b in svc_dl.firewall.get_blocked_ips()],
            threat_records=[r.to_dict() for r in svc_dl.threat_engine.get_all_records().values()],
            intel_records=[v.to_dict() for v in intel_dl.get_all_cached().values()],
            model_metrics=st.session_state["metrics_df"],
            best_model=st.session_state["best_model"],
        )
        st.download_button("📊 Download Excel Report", data=excel_bytes,
            file_name=f"intrusion_report_{int(time.time())}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            use_container_width=True)
    else:
        st.info("Run simulation first")
    if st.session_state["initialized"]:
        st.markdown("---")
        st.success(f"✅ Model: **{st.session_state['best_model']}**")

# ── Initialization ──
if not st.session_state["initialized"]:
    st.markdown("# 🛡️ AI-Powered Intrusion Response System")
    st.markdown("---")
    with st.spinner("🔧 Initializing — training & benchmarking models..."):
        try:
            svc = IntrusionService()
            init_result = svc.initialize()
            st.session_state.update({
                "service": svc,
                "explainer": ExplainabilityEngine(),
                "intel": ThreatIntelligence(),
                "initialized": True,
                "best_model": init_result["best_model"],
                "metrics_df": pd.DataFrame(init_result["metrics"]),
            })
            phishing = PhishingDetector()
            phishing_metrics = phishing.train()
            st.session_state["phishing_detector"] = phishing
            st.session_state["phishing_metrics"] = phishing_metrics.reset_index()
            st.session_state["phishing_best_model"] = phishing.get_best_model()
            st.success(f"✅ Ready. Best model: **{init_result['best_model']}**")
            time.sleep(0.5)
            st.rerun()
        except Exception as e:
            st.error(f"Initialization failed: {e}")
            st.stop()

# ── Simulation tick ──
if start_clicked: st.session_state["running"] = True
if stop_clicked: st.session_state["running"] = False

if st.session_state["running"] and st.session_state["initialized"]:
    svc = st.session_state["service"]
    explainer = st.session_state["explainer"]
    intel = st.session_state["intel"]

    log = generate_log(st.session_state["traffic_mode"])
    result = svc.process(log)
    features = svc.feature_store.extract(log)
    explanation = explainer.explain(log.ip, features, result.status)
    intel.lookup(log.ip, is_attacker=log.traffic_type in ("brute_force","ddos"))

    st.session_state["result_buffer"].append(result.to_dict())
    st.session_state["explain_buffer"].append({
        "ip": log.ip, "verdict": result.status,
        "confidence": explanation.confidence,
        "summary": explanation.summary,
        "top_reasons": explanation.top_reasons,
        "contributions": [(c.feature_label, c.actual_value, c.normal_baseline,
                           c.deviation_ratio, c.contribution_pct)
                          for c in explanation.contributions],
    })

    ts = result.timestamp[-8:]
    buf = st.session_state["ts_buffer"]
    if not buf or buf[-1][0] != ts:
        buf.append([ts, 0, 0, 0])
    entry = buf[-1]
    if result.status == "NORMAL": entry[1] += 1
    elif result.status == "ANOMALY": entry[2] += 1
    else: entry[3] += 1

    st.session_state["total_processed"] += 1
    if result.status in ("ANOMALY","BLOCKED"): st.session_state["total_anomalies"] += 1
    if result.status == "BLOCKED": st.session_state["total_blocked"] += 1

    time.sleep(interval)
    st.rerun()

# ── Layout ──
svc = st.session_state["service"]
intel = st.session_state["intel"]

st.markdown("# 🛡️ AI Intrusion Response System")
st.markdown("---")

total = st.session_state["total_processed"]
anomalies = st.session_state["total_anomalies"]
n_blocked = len(svc.firewall.get_blocked_ips())
detection_rate = f"{(anomalies/total*100):.1f}%" if total > 0 else "—"
sim_status = "🟢 RUNNING" if st.session_state["running"] else "🔴 STOPPED"

k1,k2,k3,k4,k5 = st.columns(5)
k1.metric("System Status", sim_status)
k2.metric("Logs Processed", f"{total:,}")
k3.metric("Anomalies Detected", f"{anomalies:,}")
k4.metric("IPs Blocked", f"{n_blocked}")
k5.metric("Detection Rate", detection_rate)
st.markdown("---")

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📊 Live Monitor", "🧠 AI Explainability",
    "🌍 Attack Map & Intel", "🤖 Model Benchmark",
    "🎣 Phishing URL Scanner", "💉 SQL Injection Detector"
])

# ════════ TAB 1 — Live Monitor ════════
with tab1:
    col_chart, col_threats = st.columns([2,1])
    with col_chart:
        st.markdown("### 📈 Real-Time Traffic")
        ts_buf = list(st.session_state["ts_buffer"])
        if ts_buf:
            df_ts = pd.DataFrame(ts_buf, columns=["time","normal","anomaly","blocked"])
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=df_ts["time"], y=df_ts["normal"], name="Normal",
                line=dict(color="#2ecc71",width=2), fill="tozeroy", fillcolor="rgba(46,204,113,0.1)"))
            fig.add_trace(go.Scatter(x=df_ts["time"], y=df_ts["anomaly"], name="Anomaly",
                line=dict(color="#e67e22",width=2)))
            fig.add_trace(go.Scatter(x=df_ts["time"], y=df_ts["blocked"], name="Blocked",
                line=dict(color="#e74c3c",width=2)))
            fig.update_layout(template="plotly_dark", height=280, margin=dict(l=0,r=0,t=10,b=0),
                legend=dict(orientation="h",yanchor="bottom",y=1.02))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Start simulation to see traffic data.")

    with col_threats:
        st.markdown("### 🎯 Threat Scores")
        threat_records = svc.threat_engine.get_all_records()
        if threat_records:
            df_t = pd.DataFrame([r.to_dict() for r in threat_records.values()])
            df_t = df_t.sort_values("score", ascending=False).head(12)
            fig_t = go.Figure(go.Bar(
                x=df_t["score"], y=df_t["ip"], orientation="h",
                marker_color=["#e74c3c" if s>=8 else "#e67e22" if s>=4 else "#2ecc71"
                              for s in df_t["score"]],
                text=df_t["score"], textposition="outside"))
            fig_t.update_layout(template="plotly_dark", height=280,
                margin=dict(l=0,r=0,t=10,b=0), yaxis=dict(autorange="reversed"))
            st.plotly_chart(fig_t, use_container_width=True)
        else:
            st.info("No threat data yet.")

    st.markdown("### 📋 Live Log Feed")
    result_buf = list(st.session_state["result_buffer"])
    if result_buf:
        recent = result_buf[-20:][::-1]
        df_logs = pd.DataFrame(recent)[["timestamp","ip","status","threat_score","reason","model_used"]]
        def _cs(val):
            return {"NORMAL":"color:#2ecc71","ANOMALY":"color:#e67e22;font-weight:bold",
                    "BLOCKED":"color:#e74c3c;font-weight:bold"}.get(val,"")
        st.dataframe(df_logs.style.map(_cs, subset=["status"]),
                     hide_index=True, use_container_width=True, height=280)
    else:
        st.info("No logs yet.")

    st.markdown("### 🚫 Blocked IPs")
    blocked = svc.firewall.get_blocked_ips()
    if blocked:
        st.dataframe(pd.DataFrame([b.to_dict() for b in blocked]),
                     hide_index=True, use_container_width=True)
        col_u, _ = st.columns([1,3])
        ip_unblock = col_u.text_input("Unblock IP", placeholder="e.g. 10.0.0.1")
        if col_u.button("Unblock") and ip_unblock:
            if svc.firewall.unblock_ip(ip_unblock.strip()):
                st.success(f"Unblocked {ip_unblock}")
                st.rerun()
    else:
        st.info("No IPs currently blocked.")

# ════════ TAB 2 — Explainability ════════
with tab2:
    st.markdown("### 🧠 AI Decision Explainability")
    st.markdown("*Understand exactly WHY the AI flagged or blocked each IP*")
    explain_buf = list(st.session_state["explain_buffer"])

    if not explain_buf:
        st.info("Start the simulation to see AI explanations.")
    else:
        all_ips = list(dict.fromkeys([e["ip"] for e in reversed(explain_buf)]))
        anomaly_ips = list(dict.fromkeys([e["ip"] for e in reversed(explain_buf)
                                          if e["verdict"] in ("ANOMALY","BLOCKED")]))
        col_sel1, col_sel2 = st.columns([1,2])
        filter_type = col_sel1.radio("Show", ["All IPs","Anomalies Only"], horizontal=True)
        ip_list = (anomaly_ips if filter_type == "Anomalies Only" else all_ips)[:20]

        if ip_list:
            selected_ip = col_sel2.selectbox("Select IP to inspect", ip_list)
            ip_explains = [e for e in reversed(explain_buf) if e["ip"] == selected_ip]
            if ip_explains:
                exp = ip_explains[0]
                color = {"NORMAL":"#2ecc71","ANOMALY":"#e67e22","BLOCKED":"#e74c3c"}.get(exp["verdict"],"#aaa")
                conf_color = {"HIGH":"#e74c3c","MEDIUM":"#e67e22","LOW":"#3498db"}.get(exp["confidence"],"#aaa")
                cv1, cv2, cv3 = st.columns(3)
                cv1.markdown(f"**IP:** `{selected_ip}`")
                cv2.markdown(f"**Verdict:** <span style='color:{color};font-weight:bold'>{exp['verdict']}</span>", unsafe_allow_html=True)
                cv3.markdown(f"**Confidence:** <span style='color:{conf_color};font-weight:bold'>{exp['confidence']}</span>", unsafe_allow_html=True)
                st.markdown(f"> 📝 **{exp['summary']}**")
                st.markdown("---")
                col_r, col_c = st.columns([1,1])
                with col_r:
                    st.markdown("#### 🔍 Top Reasons")
                    for i, reason in enumerate(exp["top_reasons"], 1):
                        st.markdown(f"**{i}.** {reason}")
                with col_c:
                    st.markdown("#### 📊 Feature Contributions")
                    if exp["contributions"]:
                        labels = [c[0] for c in exp["contributions"]]
                        values = [c[4] for c in exp["contributions"]]
                        fig_exp = go.Figure(go.Bar(
                            x=values, y=labels, orientation="h",
                            marker_color=["#e74c3c" if v>30 else "#e67e22" if v>15 else "#3498db" for v in values],
                            text=[f"{v:.0f}%" for v in values], textposition="outside"))
                        fig_exp.update_layout(template="plotly_dark", height=250,
                            margin=dict(l=0,r=40,t=10,b=0),
                            xaxis_title="Contribution %", yaxis=dict(autorange="reversed"))
                        st.plotly_chart(fig_exp, use_container_width=True)

                st.markdown("#### 📋 Feature Values vs Normal Baseline")
                if exp["contributions"]:
                    df_feat = pd.DataFrame(exp["contributions"],
                        columns=["Feature","Actual","Baseline","Deviation Ratio","Contribution %"])
                    df_feat["Deviation Ratio"] = df_feat["Deviation Ratio"].apply(lambda x: f"{x:.1f}x")
                    df_feat["Actual"] = df_feat["Actual"].apply(lambda x: f"{x:.2f}")
                    df_feat["Baseline"] = df_feat["Baseline"].apply(lambda x: f"{x:.2f}")
                    df_feat["Contribution %"] = df_feat["Contribution %"].apply(lambda x: f"{x:.1f}%")
                    st.dataframe(df_feat, hide_index=True, use_container_width=True)

        st.markdown("---")
        st.markdown("#### 🕐 Recent Decisions")
        df_recent = pd.DataFrame([{"IP":e["ip"],"Verdict":e["verdict"],
            "Confidence":e["confidence"],
            "Summary": e["summary"][:80]+"..." if len(e["summary"])>80 else e["summary"]}
            for e in explain_buf[-10:][::-1]])
        def _cv(val):
            return {"NORMAL":"color:#2ecc71","ANOMALY":"color:#e67e22;font-weight:bold",
                    "BLOCKED":"color:#e74c3c;font-weight:bold"}.get(val,"")
        st.dataframe(df_recent.style.map(_cv, subset=["Verdict"]),
                     hide_index=True, use_container_width=True)

# ════════ TAB 3 — Attack Map & Intel ════════
with tab3:
    st.markdown("### 🌍 Live Attack Origin Map")
    all_intel = intel.get_all_cached()

    if not all_intel:
        st.info("Start the simulation to see attack origins on the map.")
    else:
        result_dict = {r["ip"]: r for r in list(st.session_state["result_buffer"])}
        map_rows = []
        for ip, info in all_intel.items():
            status = result_dict.get(ip, {}).get("status", "NORMAL")
            threat_score = svc.threat_engine.get_threat_score(ip)
            map_rows.append({
                "ip": ip, "country": info.country, "city": info.city,
                "lat": info.latitude, "lon": info.longitude,
                "status": status, "threat_score": threat_score,
                "reputation_score": info.reputation_score, "isp": info.isp,
                "tags": ", ".join(info.tags) if info.tags else "None",
                "size": max(5, min(30, threat_score * 3 + 5)),
            })

        df_map = pd.DataFrame(map_rows)
        color_map = {"NORMAL":"#2ecc71","ANOMALY":"#e67e22","BLOCKED":"#e74c3c"}
        fig_map = go.Figure()
        for st_type in ["NORMAL","ANOMALY","BLOCKED"]:
            df_sub = df_map[df_map["status"] == st_type]
            if not df_sub.empty:
                fig_map.add_trace(go.Scattergeo(
                    lat=df_sub["lat"], lon=df_sub["lon"], mode="markers", name=st_type,
                    marker=dict(size=df_sub["size"], color=color_map[st_type],
                                opacity=0.8, line=dict(width=1, color="white")),
                    text=df_sub.apply(lambda r:
                        f"IP: {r['ip']}<br>Status: {r['status']}<br>Country: {r['country']}<br>"
                        f"City: {r['city']}<br>ISP: {r['isp']}<br>"
                        f"Threat Score: {r['threat_score']}<br>Tags: {r['tags']}", axis=1),
                    hoverinfo="text"))
        fig_map.update_layout(
            template="plotly_dark", height=450, margin=dict(l=0,r=0,t=0,b=0),
            legend=dict(orientation="h", yanchor="bottom", y=1.02),
            geo=dict(showframe=False, showcoastlines=True, coastlinecolor="#444",
                     showland=True, landcolor="#1a1f2e", showocean=True,
                     oceancolor="#0e1117", showcountries=True, countrycolor="#333",
                     bgcolor="#0e1117", projection_type="natural earth"))
        st.plotly_chart(fig_map, use_container_width=True)
        st.caption("🔴 Blocked  🟠 Anomaly  🟢 Normal — bubble size = threat score")

        st.markdown("---")
        st.markdown("### 🔍 IP Threat Intelligence")
        c1, c2, c3 = st.columns(3)
        c1.metric("Unique IPs Tracked", len(df_map))
        c2.metric("High Risk IPs", int(df_map["reputation_score"].gt(50).sum()))
        c3.metric("Countries of Origin", int(df_map["country"].nunique()))

        col_country, col_table = st.columns([1,2])
        with col_country:
            st.markdown("#### 🌐 Attacks by Country")
            country_counts = df_map[df_map["status"].isin(["ANOMALY","BLOCKED"])]["country"].value_counts().head(8)
            if not country_counts.empty:
                fig_c = go.Figure(go.Bar(x=country_counts.values, y=country_counts.index,
                    orientation="h", marker_color="#e74c3c"))
                fig_c.update_layout(template="plotly_dark", height=280,
                    margin=dict(l=0,r=0,t=10,b=0), yaxis=dict(autorange="reversed"))
                st.plotly_chart(fig_c, use_container_width=True)
            else:
                st.info("No attack data yet.")

        with col_table:
            st.markdown("#### 📋 Intelligence Report")
            intel_display = df_map[["ip","status","country","city","isp",
                "threat_score","reputation_score","tags"]].sort_values("threat_score",ascending=False)
            def _csi(val):
                return {"NORMAL":"color:#2ecc71","ANOMALY":"color:#e67e22;font-weight:bold",
                        "BLOCKED":"color:#e74c3c;font-weight:bold"}.get(val,"")
            st.dataframe(intel_display.style.map(_csi, subset=["status"]),
                         hide_index=True, use_container_width=True, height=280)

# ════════ TAB 4 — Model Benchmark ════════
with tab4:
    st.markdown("### 🤖 ML Model Benchmark Results")
    st.markdown("*Models trained on normal traffic only — proper unsupervised anomaly detection*")
    metrics_df = st.session_state.get("metrics_df")
    best = st.session_state["best_model"]

    if metrics_df is not None:
        col_t, col_c = st.columns([1,1])
        with col_t:
            st.markdown("#### 📊 Performance Metrics")
            st.dataframe(metrics_df[["Model","Precision","Recall","F1-Score","Accuracy"]],
                         hide_index=True, use_container_width=True)
            st.success(f"🏆 Auto-selected: **{best}** (highest F1-Score)")
            st.markdown("---")
            st.markdown("""
| Metric | Meaning |
|--------|---------|
| **Precision** | Of IPs flagged, % that were real attacks |
| **Recall** | Of all attacks, % that were caught |
| **F1-Score** | Balance of Precision & Recall |
| **Accuracy** | Overall correct predictions |
""")
        with col_c:
            st.markdown("#### 📈 Visual Comparison")
            metrics_long = metrics_df[["Model","Precision","Recall","F1-Score","Accuracy"]].melt(
                id_vars="Model", var_name="Metric", value_name="Score")
            fig_m = px.bar(metrics_long, x="Metric", y="Score", color="Model",
                barmode="group", template="plotly_dark",
                color_discrete_sequence=["#3498db","#e67e22","#2ecc71"])
            fig_m.update_layout(height=350, margin=dict(l=0,r=0,t=10,b=0), yaxis_range=[0,1.1])
            st.plotly_chart(fig_m, use_container_width=True)

        st.markdown("---")
        st.markdown("### 🔬 How Each Model Works")
        mc1, mc2, mc3 = st.columns(3)
        with mc1:
            st.markdown("#### 🌲 Isolation Forest")
            st.markdown("Randomly isolates data points. Anomalies get isolated faster because they are rare and different. **Best for:** large datasets.")
        with mc2:
            st.markdown("#### ⚙️ One-Class SVM")
            st.markdown("Learns a boundary around normal data. Anything outside = anomaly. **Best for:** tight, well-defined normal behavior.")
        with mc3:
            st.markdown("#### 👥 Local Outlier Factor")
            st.markdown("Compares point density to neighbors. Low-density points = anomalies. **Best for:** subtle local outliers.")

# ════════ TAB 5 — Phishing URL Scanner ════════
with tab5:
    st.markdown("### 🎣 Phishing URL Detection")
    st.markdown("*Hybrid ML + Rule-based scanner — protects against email phishing attacks*")

    detector: PhishingDetector = st.session_state.get("phishing_detector")

    if detector is None:
        st.warning("Phishing detector not initialized. Please restart the app.")
    else:
        st.markdown("#### 🔍 Scan a URL")
        col_input, col_btn = st.columns([4, 1])
        url_input = col_input.text_input(
            "Enter URL to scan",
            placeholder="e.g. http://paypal-secure-login.tk/verify or https://google.com",
            label_visibility="collapsed",
        )
        scan_clicked = col_btn.button("🔍 Scan", type="primary", use_container_width=True)

        with st.expander("🧪 Try example URLs"):
            ex_col1, ex_col2 = st.columns(2)
            with ex_col1:
                st.markdown("**Safe URLs:**")
                safe_examples = [
                    "https://www.google.com/search?q=python",
                    "https://github.com/user/repo",
                    "https://stackoverflow.com/questions/123",
                ]
                for u in safe_examples:
                    st.code(u, language=None)
            with ex_col2:
                st.markdown("**Phishing URLs:**")
                phish_examples = [
                    "http://paypal-secure-login.tk/verify/account",
                    "http://192.168.1.1/apple-id/signin",
                    "http://amazon-update-account.xyz/login.php",
                ]
                for u in phish_examples:
                    st.code(u, language=None)

        if scan_clicked and url_input.strip():
            url = url_input.strip()
            with st.spinner("Analyzing URL..."):
                result = detector.analyze(url)

            verdict_colors = {"SAFE": "#2ecc71", "SUSPICIOUS": "#e67e22", "PHISHING": "#e74c3c"}
            verdict_icons = {"SAFE": "✅", "SUSPICIOUS": "⚠️", "PHISHING": "🚨"}
            color = verdict_colors[result.verdict]
            icon = verdict_icons[result.verdict]

            st.markdown("---")
            st.markdown(f"## {icon} Verdict: <span style='color:{color}'>{result.verdict}</span>",
                        unsafe_allow_html=True)

            r1, r2, r3, r4 = st.columns(4)
            r1.metric("Verdict", result.verdict)
            r2.metric("Confidence", f"{result.confidence:.0%}")
            r3.metric("ML Probability", f"{result.ml_probability:.0%}")
            r4.metric("Rule Score", f"{result.rule_score:.1f}/8.0")

            st.markdown(f"> 📝 **{result.reason}**")
            st.markdown("---")

            col_rules, col_feat = st.columns([1, 1])
            with col_rules:
                st.markdown("#### 🔎 Rule-Based Analysis")
                for rule in result.triggered_rules:
                    st.markdown(f"- {rule}")
                st.markdown("#### 🤖 ML Model Used")
                st.info(f"**{result.model_used}** — trained on 1,200 labeled URLs")

            with col_feat:
                st.markdown("#### 📊 Top URL Features")
                feat_names = [f[0] for f in result.top_features]
                feat_vals = [f[1] for f in result.top_features]
                fig_feat = go.Figure(go.Bar(
                    x=feat_vals, y=feat_names, orientation="h",
                    marker_color=["#e74c3c" if v > 5 else "#e67e22" if v > 2 else "#3498db"
                                  for v in feat_vals],
                    text=[f"{v:.1f}" for v in feat_vals], textposition="outside",
                ))
                fig_feat.update_layout(template="plotly_dark", height=220,
                    margin=dict(l=0, r=40, t=10, b=0), yaxis=dict(autorange="reversed"))
                st.plotly_chart(fig_feat, use_container_width=True)

        st.markdown("---")
        history = detector.get_history()
        if history:
            st.markdown("#### 🕐 Scan History")
            c_clear, _ = st.columns([1, 4])
            if c_clear.button("🗑️ Clear History"):
                detector.clear_history()
                st.rerun()

            df_hist = pd.DataFrame([r.to_dict() for r in reversed(history)])
            def _color_verdict_p(val):
                return {"SAFE": "color:#2ecc71",
                        "SUSPICIOUS": "color:#e67e22;font-weight:bold",
                        "PHISHING": "color:#e74c3c;font-weight:bold"}.get(val, "")
            st.dataframe(
                df_hist[["url","verdict","confidence","ml_probability","rule_score","reason"]
                        ].style.map(_color_verdict_p, subset=["verdict"]),
                hide_index=True, use_container_width=True, height=250,
            )

            st.markdown("#### 📈 Detection Statistics")
            total_scanned = len(history)
            phishing_count = sum(1 for r in history if r.verdict == "PHISHING")
            suspicious_count = sum(1 for r in history if r.verdict == "SUSPICIOUS")
            safe_count = sum(1 for r in history if r.verdict == "SAFE")

            s1, s2, s3, s4 = st.columns(4)
            s1.metric("Total Scanned", total_scanned)
            s2.metric("🚨 Phishing", phishing_count)
            s3.metric("⚠️ Suspicious", suspicious_count)
            s4.metric("✅ Safe", safe_count)

            if total_scanned > 0:
                fig_pie = go.Figure(go.Pie(
                    labels=["SAFE", "SUSPICIOUS", "PHISHING"],
                    values=[safe_count, suspicious_count, phishing_count],
                    marker_colors=["#2ecc71", "#e67e22", "#e74c3c"], hole=0.4,
                ))
                fig_pie.update_layout(template="plotly_dark", height=280,
                    margin=dict(l=0, r=0, t=10, b=0))
                st.plotly_chart(fig_pie, use_container_width=True)

        st.markdown("---")
        st.markdown("#### 🤖 Phishing ML Model Benchmark")
        phishing_metrics = st.session_state.get("phishing_metrics")
        best_phish = st.session_state.get("phishing_best_model")
        if phishing_metrics is not None:
            col_pm, col_pc = st.columns([1, 1])
            with col_pm:
                st.dataframe(phishing_metrics, hide_index=True, use_container_width=True)
                st.success(f"🏆 Selected: **{best_phish}**")
            with col_pc:
                metrics_long = phishing_metrics.melt(
                    id_vars="Model", var_name="Metric", value_name="Score")
                fig_pm = px.bar(metrics_long, x="Metric", y="Score", color="Model",
                    barmode="group", template="plotly_dark",
                    color_discrete_sequence=["#3498db", "#e67e22", "#2ecc71"])
                fig_pm.update_layout(height=280, margin=dict(l=0,r=0,t=10,b=0),
                                     yaxis_range=[0, 1.1])
                st.plotly_chart(fig_pm, use_container_width=True)

        st.markdown("---")
        st.markdown("""
#### 🔬 How It Works

The phishing detector uses **20 URL features** extracted from each link:

| Feature Category | Examples |
|-----------------|----------|
| **Structure** | URL length, domain length, dot count, hyphen count |
| **Content** | Suspicious keywords, brand impersonation, @ symbol |
| **Security** | HTTPS presence, IP-based URL, suspicious TLD (.tk, .xyz) |
| **Entropy** | Randomness score (phishing URLs often look random) |
| **Context** | Subdomain count, query string length, port number |

The **ML layer** (Random Forest) learns patterns from 1,200 labeled URLs.
The **Rule layer** applies 8 specific phishing heuristics with weighted scores.
The **Hybrid score** = 60% ML + 40% Rules → final verdict.
""")

# ════════ TAB 6 — SQL Injection Detector ════════
with tab6:
    st.markdown("### 💉 SQL Injection Detection")
    st.markdown("*Pattern-based + heuristic engine — detects malicious SQL payloads in real time*")

    sqli_tab1, sqli_tab2, sqli_tab3 = st.tabs(["🔍 Single Payload", "📋 Batch Scanner", "📊 History & Stats"])

    # ── Single Payload ──
    with sqli_tab1:
        st.markdown("#### Enter a payload to analyze")
        sqli_input = st.text_area(
            "Payload",
            placeholder="e.g.  ' OR '1'='1 --   |   UNION SELECT * FROM users   |   normal search",
            height=100,
            label_visibility="collapsed",
        )

        with st.expander("🧪 Try example payloads"):
            ex1, ex2 = st.columns(2)
            with ex1:
                st.markdown("**Malicious:**")
                st.code("' OR '1'='1' --")
                st.code("1; DROP TABLE users;")
                st.code("UNION SELECT username, password FROM users")
                st.code("admin'--")
                st.code("1' AND SLEEP(5)--")
            with ex2:
                st.markdown("**Safe:**")
                st.code("john.doe@email.com")
                st.code("SELECT a product from our range")
                st.code("normal search query")
                st.code("hello world")

        sqli_scan = st.button("🔍 Analyze Payload", type="primary")

        if sqli_scan and sqli_input.strip():
            result = detect_sql_injection(sqli_input.strip())

            risk_color = {
                "Critical": "#e74c3c",
                "High": "#e67e22",
                "Medium": "#f1c40f",
                "None": "#2ecc71",
            }.get(result["risk"], "#aaa")

            risk_icon = {
                "Critical": "🚨",
                "High": "⚠️",
                "Medium": "🔶",
                "None": "✅",
            }.get(result["risk"], "❓")

            st.markdown("---")
            if result["detected"]:
                st.markdown(
                    f"## {risk_icon} <span style='color:{risk_color}'>SQL Injection Detected — Risk: {result['risk']}</span>",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown("## ✅ <span style='color:#2ecc71'>No SQL Injection Detected — Payload is Safe</span>",
                            unsafe_allow_html=True)

            m1, m2, m3 = st.columns(3)
            m1.metric("Detection", "🚨 DETECTED" if result["detected"] else "✅ CLEAN")
            m2.metric("Risk Level", result["risk"])
            m3.metric("Attack Categories", len(result["categories"]))

            if result["detected"]:
                st.markdown("---")
                col_cat, col_match = st.columns([1, 1])

                with col_cat:
                    st.markdown("#### 🏷️ Attack Categories Matched")
                    for cat in result["categories"]:
                        st.error(f"🔴 {cat}")

                with col_match:
                    st.markdown("#### 🔎 Matched Patterns")
                    for m in result["matches"][:10]:
                        st.code(m)

                # Bar chart of categories
                st.markdown("#### 📊 Category Severity Weights")
                severity_map = {
                    "SQL Keyword": 3,
                    "SQL Comment / Terminator": 4,
                    "OR/AND Bypass": 7,
                    "Always-True Condition": 8,
                    "Tautology (1=1)": 8,
                    "Chained Query": 9,
                    "Time-Based Blind Injection": 10,
                    "Stored Procedure / MSSQL Attack": 10,
                    "Encoding / Obfuscation": 6,
                    "Schema Enumeration": 7,
                    "File Read/Write Attempt": 10,
                    "UNION SELECT Attack": 9,
                }
                cat_scores = [(c, severity_map.get(c, 5)) for c in result["categories"]]
                df_cat = pd.DataFrame(cat_scores, columns=["Category", "Severity"])
                fig_cat = go.Figure(go.Bar(
                    x=df_cat["Severity"], y=df_cat["Category"], orientation="h",
                    marker_color=["#e74c3c" if s >= 8 else "#e67e22" if s >= 5 else "#f1c40f"
                                  for s in df_cat["Severity"]],
                    text=df_cat["Severity"], textposition="outside",
                ))
                fig_cat.update_layout(
                    template="plotly_dark", height=max(150, len(cat_scores) * 50),
                    margin=dict(l=0, r=40, t=10, b=0),
                    xaxis=dict(range=[0, 11], title="Severity Score (1–10)"),
                    yaxis=dict(autorange="reversed"),
                )
                st.plotly_chart(fig_cat, use_container_width=True)

            # Save to history
            st.session_state["sqli_history"].append({
                "payload": sqli_input.strip()[:80],
                "detected": result["detected"],
                "risk": result["risk"],
                "categories": ", ".join(result["categories"]) if result["categories"] else "None",
                "match_count": len(result["matches"]),
            })

    # ── Batch Scanner ──
    with sqli_tab2:
        st.markdown("#### Paste multiple payloads (one per line)")
        batch_input = st.text_area(
            "Batch payloads",
            value="' OR '1'='1' --\nSELECT * FROM users\nnormal search query\n1; DROP TABLE logs;\nUNION SELECT username,password FROM admin\nhello world\n1' AND SLEEP(5)--\nlegitimate@email.com",
            height=200,
            label_visibility="collapsed",
        )
        batch_scan = st.button("🔍 Scan All Payloads", type="primary")

        if batch_scan and batch_input.strip():
            payloads = [p.strip() for p in batch_input.strip().split("\n") if p.strip()]
            results = scan_batch_payloads(payloads)

            total_p = len(results)
            detected_p = sum(1 for r in results if r["detected"])
            clean_p = total_p - detected_p
            critical_p = sum(1 for r in results if r["risk"] == "Critical")

            st.markdown("---")
            b1, b2, b3, b4 = st.columns(4)
            b1.metric("Total Scanned", total_p)
            b2.metric("🚨 Malicious", detected_p)
            b3.metric("✅ Clean", clean_p)
            b4.metric("💀 Critical", critical_p)

            st.markdown("#### 📋 Scan Results")
            df_batch = pd.DataFrame([{
                "Payload": r["payload"][:60] + ("..." if len(r["payload"]) > 60 else ""),
                "Detected": "🚨 YES" if r["detected"] else "✅ NO",
                "Risk": r["risk"],
                "Categories": ", ".join(r["categories"]) if r["categories"] else "—",
                "Matches": len(r["matches"]),
            } for r in results])

            def _color_risk(val):
                return {
                    "Critical": "color:#e74c3c;font-weight:bold",
                    "High": "color:#e67e22;font-weight:bold",
                    "Medium": "color:#f1c40f",
                    "None": "color:#2ecc71",
                }.get(val, "")

            st.dataframe(df_batch.style.map(_color_risk, subset=["Risk"]),
                         hide_index=True, use_container_width=True)

            if detected_p > 0:
                st.markdown("#### 🔴 Detected Injections Only")
                for r in results:
                    if r["detected"]:
                        risk_color = {"Critical":"#e74c3c","High":"#e67e22","Medium":"#f1c40f"}.get(r["risk"],"#aaa")
                        st.markdown(
                            f"<div style='border-left:4px solid {risk_color};padding:8px 12px;"
                            f"margin:6px 0;background:#1e2130;border-radius:4px'>"
                            f"<b style='color:{risk_color}'>[{r['risk']}]</b> "
                            f"<code>{r['payload'][:80]}</code><br>"
                            f"<small style='color:#888'>Categories: {', '.join(r['categories'])}</small>"
                            f"</div>",
                            unsafe_allow_html=True,
                        )

            # Add to history
            for r in results:
                st.session_state["sqli_history"].append({
                    "payload": r["payload"][:80],
                    "detected": r["detected"],
                    "risk": r["risk"],
                    "categories": ", ".join(r["categories"]) if r["categories"] else "None",
                    "match_count": len(r["matches"]),
                })

    # ── History & Stats ──
    with sqli_tab3:
        sqli_history = st.session_state.get("sqli_history", [])

        if not sqli_history:
            st.info("No scans yet. Use the Single Payload or Batch Scanner tabs.")
        else:
            h_total = len(sqli_history)
            h_detected = sum(1 for h in sqli_history if h["detected"])
            h_clean = h_total - h_detected
            h_critical = sum(1 for h in sqli_history if h["risk"] == "Critical")

            hs1, hs2, hs3, hs4 = st.columns(4)
            hs1.metric("Total Analyzed", h_total)
            hs2.metric("🚨 Injections Found", h_detected)
            hs3.metric("✅ Clean", h_clean)
            hs4.metric("💀 Critical", h_critical)

            # Pie chart
            if h_total > 0:
                st.markdown("#### 📊 Detection Overview")
                cp1, cp2 = st.columns([1, 1])
                with cp1:
                    fig_h_pie = go.Figure(go.Pie(
                        labels=["Clean", "Detected"],
                        values=[h_clean, h_detected],
                        marker_colors=["#2ecc71", "#e74c3c"],
                        hole=0.45,
                    ))
                    fig_h_pie.update_layout(template="plotly_dark", height=250,
                        margin=dict(l=0, r=0, t=10, b=0))
                    st.plotly_chart(fig_h_pie, use_container_width=True)

                with cp2:
                    risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "None": 0}
                    for h in sqli_history:
                        risk_counts[h["risk"]] = risk_counts.get(h["risk"], 0) + 1
                    fig_risk = go.Figure(go.Bar(
                        x=list(risk_counts.keys()),
                        y=list(risk_counts.values()),
                        marker_color=["#e74c3c", "#e67e22", "#f1c40f", "#2ecc71"],
                    ))
                    fig_risk.update_layout(template="plotly_dark", height=250,
                        margin=dict(l=0, r=0, t=10, b=0), yaxis_title="Count")
                    st.plotly_chart(fig_risk, use_container_width=True)

            st.markdown("#### 🕐 Scan History")
            hclear, _ = st.columns([1, 4])
            if hclear.button("🗑️ Clear SQL History"):
                st.session_state["sqli_history"] = []
                st.rerun()

            df_hist = pd.DataFrame(sqli_history[::-1])
            df_hist["detected"] = df_hist["detected"].map({True: "🚨 YES", False: "✅ NO"})

            def _color_risk_h(val):
                return {
                    "Critical": "color:#e74c3c;font-weight:bold",
                    "High": "color:#e67e22;font-weight:bold",
                    "Medium": "color:#f1c40f",
                    "None": "color:#2ecc71",
                }.get(val, "")

            st.dataframe(df_hist.style.map(_color_risk_h, subset=["risk"]),
                         hide_index=True, use_container_width=True, height=300)

    st.markdown("---")
    st.markdown("""
#### 🔬 How SQL Injection Detection Works

This engine uses **12 regex patterns** across multiple attack categories:

| Category | What It Catches |
|----------|----------------|
| **SQL Keywords** | SELECT, DROP, UNION, EXEC, etc. |
| **Comment Injection** | `--`, `#`, `/* */` used to truncate queries |
| **OR/AND Bypass** | Classic `' OR '1'='1` authentication bypass |
| **Tautology** | Always-true conditions like `1=1` |
| **Chained Queries** | `;DROP TABLE` style multi-statement attacks |
| **Time-Based Blind** | SLEEP(), WAITFOR DELAY — used to infer data |
| **Stored Procedures** | xp_cmdshell, sp_executesql (server takeover) |
| **Obfuscation** | CHAR(), CONCAT() encoding to evade filters |
| **Schema Enumeration** | INFORMATION_SCHEMA, SYS.TABLES recon |
| **File Access** | LOAD_FILE, INTO OUTFILE — filesystem attacks |
| **UNION SELECT** | Data extraction via combined queries |

**Risk Scoring:** 1 category = Medium · 2 = High · 3+ = Critical
""")

# ── Footer ──
st.markdown("---")
st.markdown("<div style='text-align:center;color:#666;font-size:12px'>"
    "AI Intrusion Response System · Explainability · Threat Intelligence · Attack Map · Phishing Detection · SQL Injection Detection · Excel Reports"
    "</div>", unsafe_allow_html=True)
