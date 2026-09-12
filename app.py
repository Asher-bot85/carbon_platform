"""
app.py

EcoCapture OS - Primary Streamlit Application Entry Point.

A secure, Kubernetes-native climate infrastructure platform dashboard
with four primary tabs:
    1. Carbon Capture Operations  - live IoT metrics, asset location logs, live logs
    2. ESG Climate Report Auditor - footprint stats with crypto signatures
    3. DevSecOps Pipeline Manifest Scanner - K8s YAML privilege-escalation audit
    4. AI Anomaly Detection Training - trains an Isolation Forest model on
       simulated telemetry and surfaces training metrics/anomalies

A persistent sidebar + embedded panels provide a real-time Security Audit
Trail view, tailing the shared audit log file that attack_sim/attacker.py
writes CRITICAL alerts into (both application-layer IDS detections and
network-layer Suricata OT-IDS detections relayed from the sidecar).

Simulated telemetry is also published live to a ThingsBoard IoT platform
instance via MQTT (see iot/thingsboard_client.py), so the same readings
shown in this dashboard are simultaneously visible/manageable in
ThingsBoard's own device-management UI.
"""

import time
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from config import settings
from config.audit import read_log_lines, AuditLogger
from security.ids import inspect_traffic
from iot import sensor_simulator
from iot import thingsboard_client
from ot_security import ot_monitor
from devsecops import pipeline as devsecops_pipeline
from esg import reporter as esg_reporter
from blockchain.ledger import get_global_ledger
from ai_training import anomaly_model

_logger = AuditLogger(source="StreamlitUI")

# ---------------------------------------------------------------------------
# Page Configuration & Premium Enterprise Dark Theme Styling
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="EcoCapture OS | Climate Infrastructure Platform",
    page_icon="🌍",
    layout="wide",
    initial_sidebar_state="expanded",
)

CUSTOM_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    * {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    html, body, .stApp {
        background: radial-gradient(circle at 15% 0%, #10192e 0%, #0b0f19 45%, #0a0d15 100%);
        color: #e2e8f0;
    }

    [data-testid="stAppViewContainer"] {
        background: transparent;
    }

    [data-testid="stHeader"] {
        background: transparent;
    }

    /* ------------------------- Sidebar ------------------------- */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d1420 0%, #0a0f18 100%);
        border-right: 1px solid rgba(148, 163, 184, 0.12);
    }
    section[data-testid="stSidebar"] .stMarkdown, 
    section[data-testid="stSidebar"] label,
    section[data-testid="stSidebar"] p {
        color: #cbd5e1 !important;
    }
    section[data-testid="stSidebar"] h1,
    section[data-testid="stSidebar"] h2,
    section[data-testid="stSidebar"] h3 {
        color: #f1f5f9 !important;
        font-weight: 700 !important;
    }

    /* ------------------------- Typography ------------------------- */
    h1, h2, h3, h4 { color: #f8fafc !important; font-weight: 700 !important; letter-spacing: -0.01em; }
    h4 { font-size: 1.05rem !important; }
    p, span, label, .stMarkdown, div { color: #cbd5e1; }
    .stCaption, [data-testid="stCaptionContainer"] { color: #64748b !important; }

    /* ------------------------- Metric Cards (Glassmorphism) ------------------------- */
    .metric-card {
        background: linear-gradient(145deg, rgba(30, 41, 59, 0.65), rgba(15, 23, 42, 0.85));
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid rgba(148, 163, 184, 0.14);
        border-radius: 14px;
        padding: 20px 22px;
        margin-bottom: 12px;
        box-shadow: 0 4px 24px rgba(0, 0, 0, 0.28), inset 0 1px 0 rgba(255, 255, 255, 0.03);
        transition: all 0.25s ease;
        position: relative;
        overflow: hidden;
    }
    .metric-card::before {
        content: "";
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 2px;
        background: linear-gradient(90deg, #10b981, #06b6d4);
        opacity: 0.85;
    }
    .metric-card:hover {
        border-color: rgba(16, 185, 129, 0.35);
        box-shadow: 0 8px 32px rgba(16, 185, 129, 0.12), inset 0 1px 0 rgba(255, 255, 255, 0.04);
        transform: translateY(-2px);
    }
    .metric-label {
        font-size: 0.72rem;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: #64748b;
        margin-bottom: 6px;
        font-weight: 600;
    }
    .metric-value {
        font-size: 1.85rem;
        font-weight: 800;
        color: #f1f5f9;
        letter-spacing: -0.02em;
    }

    /* ------------------------- Status Pills ------------------------- */
    .status-pill {
        display: inline-block;
        padding: 3px 12px;
        border-radius: 999px;
        font-size: 0.68rem;
        font-weight: 700;
        letter-spacing: 0.05em;
        vertical-align: middle;
        margin-left: 4px;
    }
    .status-NORMAL {
        background: rgba(16, 185, 129, 0.14);
        color: #34d399;
        border: 1px solid rgba(16, 185, 129, 0.3);
    }
    .status-WARNING {
        background: rgba(245, 158, 11, 0.14);
        color: #fbbf24;
        border: 1px solid rgba(245, 158, 11, 0.3);
    }
    .status-CRITICAL {
        background: rgba(239, 68, 68, 0.16);
        color: #f87171;
        border: 1px solid rgba(239, 68, 68, 0.35);
    }

    /* ------------------------- Log Lines ------------------------- */
    .log-line-INFO {
        color: #64748b;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        padding: 2px 0;
    }
    .log-line-WARNING {
        color: #fbbf24;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        padding: 2px 0;
    }
    .log-line-HIGH {
        color: #fb923c;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        font-weight: 600;
        padding: 3px 8px;
        border-left: 2px solid #fb923c;
        background: rgba(251, 146, 60, 0.06);
        margin: 2px 0;
    }
    .log-line-CRITICAL {
        color: #f87171;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.82rem;
        font-weight: 700;
        background: rgba(239, 68, 68, 0.08);
        padding: 5px 10px;
        border-radius: 6px;
        border-left: 3px solid #ef4444;
        margin: 3px 0;
        box-shadow: 0 0 12px rgba(239, 68, 68, 0.08);
    }

    /* ------------------------- Header Banner ------------------------- */
    .platform-header {
        background: linear-gradient(120deg, #0d3b2e 0%, #0b2436 55%, #0b0f19 100%);
        border: 1px solid rgba(16, 185, 129, 0.25);
        border-radius: 16px;
        padding: 26px 32px;
        margin-bottom: 24px;
        box-shadow: 0 8px 40px rgba(16, 185, 129, 0.08), inset 0 1px 0 rgba(255,255,255,0.04);
        position: relative;
        overflow: hidden;
    }
    .platform-header::after {
        content: "";
        position: absolute;
        top: -50%; right: -10%;
        width: 320px; height: 320px;
        background: radial-gradient(circle, rgba(6, 182, 212, 0.18) 0%, transparent 70%);
        pointer-events: none;
    }
    .platform-header h1, .platform-header p {
        color: #ffffff !important;
        position: relative;
        z-index: 1;
    }
    .platform-header p {
        color: #94a3b8 !important;
        font-weight: 500;
    }

    /* ------------------------- Streamlit Native Metrics ------------------------- */
    div[data-testid="stMetricValue"] {
        color: #10b981 !important;
        font-weight: 800 !important;
    }
    div[data-testid="stMetricLabel"] {
        color: #64748b !important;
    }

    /* ------------------------- Tabs (Sleek Pill Style) ------------------------- */
    .stTabs [data-baseweb="tab-list"] {
        gap: 4px;
        background: rgba(15, 23, 42, 0.5);
        padding: 6px;
        border-radius: 14px;
        border: 1px solid rgba(148, 163, 184, 0.1);
    }
    .stTabs [data-baseweb="tab"] {
        background-color: transparent;
        border-radius: 10px;
        padding: 10px 20px;
        border: none;
        color: #94a3b8;
        font-weight: 600;
        font-size: 0.88rem;
        transition: all 0.2s ease;
    }
    .stTabs [data-baseweb="tab"]:hover {
        background-color: rgba(148, 163, 184, 0.08);
        color: #e2e8f0;
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #10b981, #06b6d4) !important;
        color: #05221c !important;
        font-weight: 700 !important;
        box-shadow: 0 4px 16px rgba(16, 185, 129, 0.28);
    }
    .stTabs [data-baseweb="tab-highlight"] { display: none; }
    .stTabs [data-baseweb="tab-border"] { display: none; }

    /* ------------------------- Buttons ------------------------- */
    .stButton > button {
        border-radius: 10px;
        font-weight: 600;
        font-size: 0.88rem;
        transition: all 0.2s ease;
        border: 1px solid rgba(148, 163, 184, 0.18);
        background: rgba(30, 41, 59, 0.6);
        color: #e2e8f0;
    }
    .stButton > button:hover {
        border-color: rgba(6, 182, 212, 0.4);
        background: rgba(6, 182, 212, 0.08);
        color: #67e8f9;
        transform: translateY(-1px);
    }
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #10b981, #059669);
        border: none;
        color: #ffffff;
        box-shadow: 0 4px 16px rgba(16, 185, 129, 0.3);
    }
    .stButton > button[kind="primary"]:hover {
        background: linear-gradient(135deg, #0ea975, #047c5c);
        box-shadow: 0 6px 22px rgba(16, 185, 129, 0.42);
        transform: translateY(-1px);
    }

    /* ------------------------- DataFrames & Tables ------------------------- */
    .stDataFrame {
        border: 1px solid rgba(148, 163, 184, 0.14);
        border-radius: 12px;
        overflow: hidden;
        background: rgba(15, 23, 42, 0.5);
    }
    [data-testid="stDataFrameResizable"] {
        border-radius: 12px;
    }

    /* ------------------------- Code Blocks ------------------------- */
    .stCodeBlock, pre {
        background: rgba(10, 15, 24, 0.85) !important;
        border: 1px solid rgba(148, 163, 184, 0.14) !important;
        border-radius: 10px !important;
    }
    code {
        font-family: 'JetBrains Mono', monospace !important;
        color: #67e8f9 !important;
    }

    /* ------------------------- Alerts ------------------------- */
    .stAlert {
        border-radius: 10px;
        border: 1px solid rgba(148, 163, 184, 0.14);
        backdrop-filter: blur(8px);
    }
    div[data-baseweb="notification"] {
        border-radius: 10px;
    }

    /* ------------------------- Inputs ------------------------- */
    .stTextInput input, .stTextArea textarea, .stSelectbox [data-baseweb="select"] {
        background: rgba(15, 23, 42, 0.6) !important;
        border: 1px solid rgba(148, 163, 184, 0.18) !important;
        border-radius: 10px !important;
        color: #e2e8f0 !important;
    }
    .stTextInput input:focus, .stTextArea textarea:focus {
        border-color: #10b981 !important;
        box-shadow: 0 0 0 1px rgba(16, 185, 129, 0.3) !important;
    }
    .stSlider [data-baseweb="slider"] { color: #10b981; }

    /* ------------------------- Expanders ------------------------- */
    .streamlit-expanderHeader {
        background: rgba(15, 23, 42, 0.5) !important;
        border-radius: 10px !important;
        border: 1px solid rgba(148, 163, 184, 0.14) !important;
        color: #e2e8f0 !important;
        font-weight: 600 !important;
    }
    .streamlit-expanderContent {
        background: rgba(10, 15, 24, 0.4) !important;
        border-radius: 0 0 10px 10px !important;
        border: 1px solid rgba(148, 163, 184, 0.1) !important;
        border-top: none !important;
    }

    /* ------------------------- Divider ------------------------- */
    hr {
        border-color: rgba(148, 163, 184, 0.12);
        margin: 1.5rem 0;
    }

    /* ------------------------- Scrollbar ------------------------- */
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb {
        background: rgba(148, 163, 184, 0.25);
        border-radius: 8px;
    }
    ::-webkit-scrollbar-thumb:hover { background: rgba(16, 185, 129, 0.4); }

    /* ------------------------- Toast ------------------------- */
    [data-testid="stToast"] {
        background: rgba(15, 23, 42, 0.95) !important;
        border: 1px solid rgba(239, 68, 68, 0.3) !important;
        border-radius: 10px !important;
        backdrop-filter: blur(12px);
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Session State Initialization
# ---------------------------------------------------------------------------
if "fleet_readings" not in st.session_state:
    st.session_state.fleet_readings = sensor_simulator.generate_fleet_readings()
if "asset_locations" not in st.session_state:
    st.session_state.asset_locations = sensor_simulator.generate_asset_locations()
if "live_log_feed" not in st.session_state:
    st.session_state.live_log_feed = [sensor_simulator.generate_live_log_line() for _ in range(8)]
if "esg_report_history" not in st.session_state:
    st.session_state.esg_report_history = []
if "last_refresh" not in st.session_state:
    st.session_state.last_refresh = datetime.now(timezone.utc)
if "last_suricata_count" not in st.session_state:
    st.session_state.last_suricata_count = 0

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.markdown(
    f"""
    <div class="platform-header">
        <h1 style="margin-bottom:4px; font-size:2.1rem;">🌍 EcoCapture OS</h1>
        <p style="margin-top:0; font-size:0.95rem;">
            Secure, Kubernetes-native climate infrastructure platform &nbsp;·&nbsp;
            v{settings.PLATFORM_VERSION} &nbsp;·&nbsp; {settings.ORG_NAME}
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Sidebar: Global Controls + Live Security Audit Trail Summary
# ---------------------------------------------------------------------------
with st.sidebar:
    st.subheader("⚙️ Platform Controls")

    if st.button("🔄 Refresh Simulated Telemetry", use_container_width=True):
        st.session_state.fleet_readings = sensor_simulator.generate_fleet_readings()
        thingsboard_client.publish_fleet(st.session_state.fleet_readings)
        st.session_state.asset_locations = sensor_simulator.generate_asset_locations()
        st.session_state.live_log_feed = (
            [sensor_simulator.generate_live_log_line() for _ in range(3)]
            + st.session_state.live_log_feed
        )[:40]
        st.session_state.last_refresh = datetime.now(timezone.utc)
        st.rerun()

    auto_refresh = st.checkbox("Enable Live Monitoring Mode (auto-refresh)", value=False)

    st.markdown("---")
    st.subheader("🛡️ Security Audit Trail")
    st.caption(f"Tailing: `{settings.LOG_FILE_PATH}`")

    all_logs = read_log_lines(max_lines=500)
    critical_count = sum(1 for entry in all_logs if entry["level"] == "CRITICAL")
    high_count = sum(1 for entry in all_logs if entry["level"] == "HIGH")
    warning_count = sum(1 for entry in all_logs if entry["level"] == "WARNING")

    # Detect and surface Suricata OT-IDS network-layer alerts (relayed by
    # attack_sim/attacker.py from the Suricata sidecar's eve.json log)
    # with a toast popup whenever the count increases since last render.
    suricata_critical_logs = [
        entry for entry in all_logs
        if "Suricata-OT" in entry["message"] and entry["level"] == "CRITICAL"
    ]
    current_suricata_count = len(suricata_critical_logs)
    if current_suricata_count > st.session_state.last_suricata_count:
        new_alerts = current_suricata_count - st.session_state.last_suricata_count
        st.toast(
            f"🚨 Suricata OT-IDS: {new_alerts} new CRITICAL alert(s) detected on the network!",
            icon="🚨",
        )
    st.session_state.last_suricata_count = current_suricata_count

    c1, c2, c3 = st.columns(3)
    c1.metric("CRITICAL", critical_count)
    c2.metric("HIGH", high_count)
    c3.metric("WARN", warning_count)

    if critical_count > 0:
        st.error(f"⚠️ {critical_count} CRITICAL alert(s) recorded in the audit trail.")
    else:
        st.success("✅ No CRITICAL alerts recorded.")

    if current_suricata_count > 0:
        st.warning(f"🛰️ {current_suricata_count} network-layer Suricata OT-IDS alert(s) detected.")

    st.markdown("---")
    st.caption(
        "Run `python attack_sim/attacker.py` from the project root or as the "
        "`ecocapture-attack-sim` K8s Job to exercise the IDS and Suricata OT-IDS "
        "sidecar, populating this audit trail with live CRITICAL detections."
    )

# ---------------------------------------------------------------------------
# Helper Rendering Functions
# ---------------------------------------------------------------------------
def render_metric_card(label: str, value: str, status: str = None):
    status_html = ""
    if status:
        status_html = f'<span class="status-pill status-{status}">{status}</span>'
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value} {status_html}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_audit_log_panel(max_lines: int = 100, key_prefix: str = "main"):
    logs = read_log_lines(max_lines=max_lines)
    if not logs:
        st.info("No audit trail entries recorded yet.")
        return

    logs_reversed = list(reversed(logs))  # most recent first

    filter_level = st.multiselect(
        "Filter by severity",
        options=["INFO", "WARNING", "HIGH", "CRITICAL"],
        default=["WARNING", "HIGH", "CRITICAL"],
        key=f"{key_prefix}_filter",
    )

    filtered = [entry for entry in logs_reversed if entry["level"] in filter_level] if filter_level else logs_reversed

    log_html = "<div style='max-height:420px; overflow-y:auto; padding:14px; background: rgba(10, 15, 24, 0.6); border:1px solid rgba(148, 163, 184, 0.14); border-radius:12px;'>"
    for entry in filtered[:200]:
        log_html += (
            f"<div class='log-line-{entry['level']}'>"
            f"[{entry['timestamp']}] [{entry['level']}] [{entry['source']}] {entry['message']}"
            f"</div>"
        )
    log_html += "</div>"
    st.markdown(log_html, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Primary Tab Navigation
# ---------------------------------------------------------------------------
tab1, tab2, tab3, tab4 = st.tabs(
    [
        "🏭 Carbon Capture Operations",
        "📊 ESG Climate Report Auditor",
        "🔐 DevSecOps Pipeline Manifest Scanner",
        "🤖 AI Anomaly Detection Training",
    ]
)

# ===========================================================================
# TAB 1: CARBON CAPTURE OPERATIONS
# ===========================================================================
with tab1:
    st.subheader("Live Facility Metrics")

    readings = st.session_state.fleet_readings
    avg_co2 = round(sum(r["co2_ppm"] for r in readings) / len(readings), 1)
    avg_temp = round(sum(r["temperature_c"] for r in readings) / len(readings), 1)
    critical_sensors = sum(1 for r in readings if r["status"] == "CRITICAL")
    warning_sensors = sum(1 for r in readings if r["status"] == "WARNING")
    online_assets = sum(1 for a in st.session_state.asset_locations if a["operational_status"] == "ONLINE")
    total_capture_tons = round(sum(a["capture_tons_month"] for a in st.session_state.asset_locations), 1)

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        render_metric_card("Avg CO2 Concentration", f"{avg_co2} ppm")
    with m2:
        render_metric_card("Avg Facility Temp", f"{avg_temp} °C")
    with m3:
        render_metric_card("Sensors Nominal", f"{len(readings) - critical_sensors - warning_sensors}/{len(readings)}")
    with m4:
        render_metric_card("Total Monthly Capture", f"{total_capture_tons} tons CO2")

    m5, m6, m7, m8 = st.columns(4)
    with m5:
        render_metric_card("Assets Online", f"{online_assets}/{len(st.session_state.asset_locations)}")
    with m6:
        render_metric_card("Warning Sensors", f"{warning_sensors}", "WARNING" if warning_sensors else "NORMAL")
    with m7:
        render_metric_card("Critical Sensors", f"{critical_sensors}", "CRITICAL" if critical_sensors else "NORMAL")
    with m8:
        render_metric_card("Sensor Fleet Size", f"{len(readings)}")

    st.markdown("---")

    col_left, col_right = st.columns([1.3, 1])

    with col_left:
        st.markdown("#### 📡 IoT Sensor Telemetry")
        df_readings = pd.DataFrame(readings)
        st.dataframe(
            df_readings,
            use_container_width=True,
            hide_index=True,
            column_config={
                "co2_ppm": st.column_config.NumberColumn("CO2 (ppm)", format="%.2f"),
                "temperature_c": st.column_config.NumberColumn("Temp (°C)", format="%.2f"),
                "humidity_pct": st.column_config.NumberColumn("Humidity (%)", format="%.1f"),
                "pressure_kpa": st.column_config.NumberColumn("Pressure (kPa)", format="%.2f"),
            },
        )

        st.markdown("#### 📍 Asset Location Log")
        df_assets = pd.DataFrame(st.session_state.asset_locations)
        st.dataframe(
            df_assets[
                ["asset_id", "site_name", "operational_status", "capture_tons_month", "last_inspection", "lat", "lon"]
            ],
            use_container_width=True,
            hide_index=True,
        )

        map_df = df_assets.rename(columns={"lat": "latitude", "lon": "longitude"})[["latitude", "longitude"]]
        st.map(map_df, size=20)

    with col_right:
        st.markdown("#### 🖥️ Live Operational Logs")
        if st.button("➕ Generate New Log Entry"):
            st.session_state.live_log_feed.insert(0, sensor_simulator.generate_live_log_line())
            st.session_state.live_log_feed = st.session_state.live_log_feed[:40]

        log_feed_html = "<div style='max-height:300px; overflow-y:auto; padding:14px; background: rgba(10, 15, 24, 0.6); border:1px solid rgba(148, 163, 184, 0.14); border-radius:12px; font-family: JetBrains Mono, monospace; font-size:0.8rem; color:#34d399;'>"
        for line in st.session_state.live_log_feed:
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            log_feed_html += f"<div style='padding:2px 0;'>[{ts}] {line}</div>"
        log_feed_html += "</div>"
        st.markdown(log_feed_html, unsafe_allow_html=True)

        st.markdown("#### 🛡️ Real-Time Intrusion Monitoring Timeline")
        render_audit_log_panel(max_lines=60, key_prefix="ops_tab")

# ===========================================================================
# TAB 2: ESG CLIMATE REPORT AUDITOR
# ===========================================================================
with tab2:
    st.subheader("ESG Climate Footprint Reporting & Cryptographic Signing")
    st.caption(
        "Compiles carbon footprint statistics from simulated fleet telemetry and "
        "anchors each report to a local hash-chained ledger for tamper-evident "
        "audit tracking."
    )

    col_a, col_b = st.columns([1, 1])
    with col_a:
        sample_size = st.slider("Telemetry sample size for this report", min_value=5, max_value=50, value=20)
    with col_b:
        reporting_label = st.text_input("Reporting period label", value=datetime.now(timezone.utc).strftime("%Y-%m"))

    if st.button("📑 Generate ESG Climate Report", type="primary"):
        sample_readings = [sensor_simulator.generate_reading() for _ in range(sample_size)]
        report = esg_reporter.compile_report(sample_readings, reporting_period=reporting_label)
        st.session_state.esg_report_history.insert(0, report)
        st.success("ESG report compiled and cryptographically signed successfully.")

    if st.session_state.esg_report_history:
        latest = st.session_state.esg_report_history[0]

        st.markdown("#### 📈 Latest Report Summary")
        r1, r2, r3, r4 = st.columns(4)
        with r1:
            render_metric_card("Avg CO2 (ppm)", f"{latest['average_co2_ppm']}")
        with r2:
            render_metric_card("Est. Tons Captured", f"{latest['estimated_tons_captured_month']}")
        with r3:
            render_metric_card("Net Carbon Benefit", f"{latest['net_carbon_benefit_tons_co2e']} t CO2e")
        with r4:
            render_metric_card("Facility Energy Use", f"{latest['facility_energy_consumed_kwh']} kWh")

        st.markdown("#### 🔏 Cryptographic Tracking Metadata")
        st.code(
            f"SHA-256 Signature : {latest['crypto_signature_sha256']}\n"
            f"Ledger Block Index: {latest['ledger_block_index']}\n"
            f"Block Hash        : {latest['ledger_block_hash']}\n"
            f"Previous Hash     : {latest['ledger_previous_hash']}",
            language="text",
        )

        is_valid = esg_reporter.verify_report_signature(latest)
        if is_valid:
            st.success("✅ Signature verification PASSED - report integrity confirmed.")
        else:
            st.error("❌ Signature verification FAILED - possible tampering detected.")

        st.markdown("#### 📜 Full Report Payload")
        st.json(latest)

        st.markdown("#### ⛓️ Blockchain Ledger (Full Chain)")
        ledger = get_global_ledger()
        ledger_df = pd.DataFrame(ledger.to_list())
        if not ledger_df.empty:
            ledger_df["data"] = ledger_df["data"].apply(
                lambda d: (d[:80] + "...") if isinstance(d, str) and len(d) > 80 else d
            )
        st.dataframe(ledger_df, use_container_width=True, hide_index=True)
        st.caption(f"Chain validity check: {'✅ VALID' if ledger.is_chain_valid() else '❌ INVALID / TAMPERED'}")

        st.markdown("#### 🗂️ Report History")
        history_summary = [
            {
                "period": r["reporting_period"],
                "generated_at": r["generated_at"],
                "net_benefit_tons": r["net_carbon_benefit_tons_co2e"],
                "ledger_block": r["ledger_block_index"],
            }
            for r in st.session_state.esg_report_history
        ]
        st.dataframe(pd.DataFrame(history_summary), use_container_width=True, hide_index=True)
    else:
        st.info("No ESG reports generated yet. Click the button above to compile your first report.")

    st.markdown("---")
    st.markdown("#### 🧪 Raw ESG Data Submission Validator")
    st.caption(
        "Simulates submitting a raw ESG data payload through the platform's IDS "
        "validation layer (security.ids.inspect_traffic) before it would be "
        "accepted into a report."
    )
    esg_raw_input = st.text_area(
        "Paste a raw ESG data payload to validate",
        placeholder='e.g. {"facility": "SITE-001", "co2_ppm": 420, "notes": "routine submission"}',
        height=100,
    )
    if st.button("🔍 Validate ESG Payload"):
        verdict = inspect_traffic(esg_raw_input, source="esg_upload")
        if verdict["status"] == "BLOCKED":
            st.error(f"🚨 BLOCKED - {verdict['details']}")
        else:
            st.success(f"✅ ALLOWED - {verdict['details']}")

# ===========================================================================
# TAB 3: DEVSECOPS PIPELINE MANIFEST SCANNER
# ===========================================================================
with tab3:
    st.subheader("Kubernetes Manifest Privilege Escalation Scanner")
    st.caption(
        "Paste any Kubernetes YAML manifest below to statically scan it for "
        "privilege escalation and container hardening risks before it reaches "
        "your CI/CD pipeline or cluster admission controller."
    )

    example_manifest = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: risky-carbon-worker
spec:
  replicas: 1
  selector:
    matchLabels:
      app: risky-carbon-worker
  template:
    metadata:
      labels:
        app: risky-carbon-worker
    spec:
      hostNetwork: true
      hostPID: true
      containers:
        - name: worker
          image: example/worker:latest
          securityContext:
            privileged: true
            runAsUser: 0
            allowPrivilegeEscalation: true
            capabilities:
              add: ["SYS_ADMIN", "NET_ADMIN"]
            readOnlyRootFilesystem: false
"""

    manifest_input = st.text_area(
        "Paste Kubernetes manifest YAML",
        value=example_manifest,
        height=320,
        key="manifest_input",
    )

    scan_col1, scan_col2 = st.columns([1, 4])
    with scan_col1:
        run_scan = st.button("🔎 Scan Manifest", type="primary")

    if run_scan:
        scan_result = devsecops_pipeline.scan_manifest(manifest_input)

        if scan_result["parse_error"]:
            st.warning(scan_result["parse_error"])

        risk_level = scan_result["risk_level"]
        risk_colors = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "CLEAN": "✅",
        }
        st.markdown(f"### Overall Risk Level: {risk_colors.get(risk_level, '')} `{risk_level}`")

        s1, s2, s3, s4 = st.columns(4)
        with s1:
            render_metric_card("Total Findings", f"{scan_result['threat_count']}")
        with s2:
            render_metric_card("Critical", f"{scan_result['critical_count']}", "CRITICAL" if scan_result["critical_count"] else "NORMAL")
        with s3:
            render_metric_card("High", f"{scan_result['high_count']}", "WARNING" if scan_result["high_count"] else "NORMAL")
        with s4:
            render_metric_card("Medium", f"{scan_result['medium_count']}")

        if scan_result["findings"]:
            st.markdown("#### 📋 Findings Detail")
            findings_df = pd.DataFrame(scan_result["findings"])
            st.dataframe(findings_df, use_container_width=True, hide_index=True)

            if scan_result["critical_count"] > 0:
                st.error(
                    f"🚨 {scan_result['critical_count']} CRITICAL privilege-escalation risk(s) "
                    "detected. This manifest should be BLOCKED from deployment until remediated."
                )
                _logger.critical(
                    f"DevSecOps scan flagged manifest as CRITICAL risk | "
                    f"findings={scan_result['threat_count']} | "
                    f"critical={scan_result['critical_count']}, high={scan_result['high_count']}"
                )
            elif scan_result["high_count"] > 0:
                st.warning(
                    f"⚠️ {scan_result['high_count']} HIGH-severity finding(s) detected. "
                    "Review before promoting to production."
                )
        else:
            st.success("✅ No privilege escalation or hardening risks detected in this manifest.")
    else:
        st.info("Click 'Scan Manifest' to run the DevSecOps static analysis scan.")

    st.markdown("---")
    st.markdown("#### 🏗️ Purdue Model OT Zone Compliance Checker")
    st.caption(
        "Checks whether traffic between two Purdue Enterprise Reference "
        "Architecture zones complies with standard ICS/OT segmentation policy."
    )

    zone_options = ot_monitor.PURDUE_ZONES
    zone_labels = {k: f"{k} - {v}" for k, v in zone_options.items()}

    z1, z2 = st.columns(2)
    with z1:
        source_zone = st.selectbox(
            "Source Zone", options=list(zone_labels.keys()), format_func=lambda k: zone_labels[k], index=1
        )
    with z2:
        dest_zone = st.selectbox(
            "Destination Zone", options=list(zone_labels.keys()), format_func=lambda k: zone_labels[k], index=5
        )

    if st.button("🧭 Check Zone Compliance"):
        result = ot_monitor.check_zone_compliance(source_zone, dest_zone)
        if result["compliant"]:
            st.success(f"✅ COMPLIANT - {result['reason']}")
        else:
            st.error(f"🚨 NON-COMPLIANT - {result['reason']}")
            if result["recommended_path"]:
                st.info(f"Recommended path: {result['recommended_path']}")

    with st.expander("View Full Purdue Zone Compliance Matrix"):
        if st.button("🔄 Run Zone Matrix Audit", key="run_matrix_audit"):
            matrix = ot_monitor.audit_zone_matrix()
            st.session_state["zone_matrix_result"] = matrix
        if "zone_matrix_result" in st.session_state:
            matrix_df = pd.DataFrame(st.session_state["zone_matrix_result"])
            st.dataframe(matrix_df, use_container_width=True, hide_index=True)
        else:
            st.info("Click 'Run Zone Matrix Audit' to compute the full compliance matrix.")

# ===========================================================================
# TAB 4: AI ANOMALY DETECTION TRAINING
# ===========================================================================
with tab4:
    st.subheader("AI-Powered Anomaly Detection — Model Training Results")
    st.caption(
        "Trains an Isolation Forest model on simulated IoT sensor telemetry "
        "to detect anomalous carbon-capture readings. Retrain anytime to see "
        "fresh training metrics against newly simulated data."
    )

    training_sample_size = st.slider(
        "Number of simulated readings to train on", min_value=50, max_value=500, value=200
    )

    if st.button("🧠 Train Anomaly Detection Model", type="primary"):
        with st.spinner("Training Isolation Forest model..."):
            training_readings = [sensor_simulator.generate_reading() for _ in range(training_sample_size)]
            training_results = anomaly_model.train_anomaly_model(training_readings)
            st.session_state["ai_training_results"] = training_results
        st.success("Model training complete.")

    if "ai_training_results" in st.session_state:
        results = st.session_state["ai_training_results"]

        st.markdown("#### 📈 Training Summary")
        a1, a2, a3, a4 = st.columns(4)
        with a1:
            render_metric_card("Total Samples", f"{results['total_samples']}")
        with a2:
            render_metric_card("Training Time", f"{results['training_duration_seconds']}s")
        with a3:
            render_metric_card("Test Anomaly Rate", f"{results['test_anomaly_rate_pct']}%")
        with a4:
            render_metric_card(
                "Anomalies Flagged",
                f"{results['test_anomalies_detected']}",
                "CRITICAL" if results["test_anomalies_detected"] > 0 else "NORMAL",
            )

        st.markdown("#### 🔬 Model Configuration")
        st.code(
            f"Model Type       : {results['model_type']}\n"
            f"Estimators       : {results['n_estimators']}\n"
            f"Contamination    : {results['contamination_rate']}\n"
            f"Train Samples    : {results['train_samples']}\n"
            f"Test Samples     : {results['test_samples']}",
            language="text",
        )

        st.markdown("#### 📊 Feature Statistics (Training Data)")
        feature_df = pd.DataFrame(results["feature_ranges"]).T
        st.dataframe(feature_df, use_container_width=True)

        if results["flagged_readings"]:
            st.markdown("#### 🚨 Flagged Anomalous Readings")
            flagged_df = pd.DataFrame(results["flagged_readings"])
            st.dataframe(flagged_df, use_container_width=True, hide_index=True)
        else:
            st.info("No anomalies detected in this training run.")

        st.markdown("#### 📋 Full Scored Dataset")
        with st.expander("View all readings with anomaly scores"):
            scored_df = pd.DataFrame(results["all_readings_scored"])
            st.dataframe(scored_df, use_container_width=True, hide_index=True)
    else:
        st.info("Click 'Train Anomaly Detection Model' above to run your first training pass.")

# ---------------------------------------------------------------------------
# Global Footer: Full Security Audit Trail (persistent across all tabs)
# ---------------------------------------------------------------------------
st.markdown("---")
with st.expander("🛡️ Global Security Audit Trail (Full Intrusion Monitoring Timeline)", expanded=False):
    render_audit_log_panel(max_lines=500, key_prefix="global_footer")

st.caption(
    f"EcoCapture OS v{settings.PLATFORM_VERSION} | Last dashboard refresh: "
    f"{st.session_state.last_refresh.strftime('%Y-%m-%d %H:%M:%S UTC')}"
)

# ---------------------------------------------------------------------------
# Live Monitoring Mode: lightweight auto-refresh loop
# ---------------------------------------------------------------------------
if auto_refresh:
    time.sleep(3)
    st.session_state.fleet_readings = sensor_simulator.generate_fleet_readings()
    st.session_state.live_log_feed = (
        [sensor_simulator.generate_live_log_line()] + st.session_state.live_log_feed
    )[:40]
    st.session_state.last_refresh = datetime.now(timezone.utc)
    st.rerun()
