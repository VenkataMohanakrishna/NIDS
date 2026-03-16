import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import subprocess
import time
import os
import sys

# ----------------------------------------------------
# Page Configuration
# ----------------------------------------------------
st.set_page_config(
    page_title="Deep Learning NIDS",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ----------------------------------------------------
# Custom CSS for Premium UI & Animations
# ----------------------------------------------------
st.markdown("""
    <style>
    /* Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');

    /* Global Styles */
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    /* Main Background & Text */
    .stApp {
        background: #111111;
        color: #e2e8f0;
    }

    /* Top Banner Animation */
    @keyframes slideDown {
        from { transform: translateY(-50px); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
    }

    .main-header {
        animation: slideDown 0.8s cubic-bezier(0.16, 1, 0.3, 1) ease-out;
        text-align: center;
        padding: 2rem 0 1rem 0;
    }

    .main-header h1 {
        font-size: 2.2rem;
        font-weight: 600;
        color: #f8fafc;
        margin-bottom: 0.5rem;
        display: inline-block;
    }

    .main-header p {
        font-size: 1.2rem;
        color: #94a3b8;
        font-weight: 300;
        letter-spacing: 1px;
    }

    /* Custom Metric Cards */
    @keyframes fadeInUp {
        from { transform: translateY(20px); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
    }

    .metric-card-container {
        display: flex;
        justify-content: space-between;
        gap: 1.5rem;
        margin: 2rem 0;
        animation: fadeInUp 1s ease-out forwards;
    }

    .metric-card {
        background: rgba(30, 41, 59, 0.7);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border-radius: 16px;
        padding: 1.5rem;
        flex: 1;
        border: 1px solid rgba(255, 255, 255, 0.05);
        box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.5);
        transition: transform 0.3s ease, border-color 0.3s ease;
        position: relative;
        overflow: hidden;
    }

    .metric-card::before {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0; height: 3px;
    }

    .metric-card.total-flows::before { background: #3b82f6; }
    .metric-card.attacks::before { background: #ef4444; }
    .metric-card.duration::before { background: #10b981; }
    .metric-card.packets::before { background: #8b5cf6; }

    .metric-card:hover {
        transform: translateY(-5px);
        border-color: rgba(255, 255, 255, 0.1);
    }

    .metric-title {
        font-size: 0.875rem;
        color: #94a3b8;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 0.5rem;
    }

    .metric-value {
        font-size: 2.2rem;
        font-weight: 700;
        color: #ffffff;
    }

    .metric-value.danger { color: #f87171; }

    /* Alert Banner */
    @keyframes pulse-red {
        0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4); }
        70% { box-shadow: 0 0 0 15px rgba(239, 68, 68, 0); }
        100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
    }

    .alert-banner {
        border-radius: 12px;
        padding: 1.5rem;
        margin: 2rem 0;
        display: flex;
        align-items: center;
        gap: 1rem;
        animation: fadeInUp 1s ease-out 0.2s forwards;
        opacity: 0;
    }

    .alert-banner.safe {
        background: rgba(16, 185, 129, 0.1);
        border: 1px solid rgba(16, 185, 129, 0.2);
    }

    .alert-banner.safe .alert-icon { color: #10b981; }

    .alert-banner.danger {
        background: rgba(239, 68, 68, 0.1);
        border: 1px solid rgba(239, 68, 68, 0.3);
        animation: fadeInUp 1s ease-out 0.2s forwards, pulse-red 2s infinite;
    }

    .alert-banner.danger .alert-icon {
        color: #ef4444;
        animation: shake 0.5s infinite;
    }

    @keyframes shake {
        0% { transform: translateX(0); }
        25% { transform: translateX(-2px); }
        50% { transform: translateX(2px); }
        75% { transform: translateX(-2px); }
        100% { transform: translateX(0); }
    }

    .alert-content h3 {
        margin: 0;
        font-size: 1.25rem;
        font-weight: 600;
    }

    .alert-content p {
        margin: 0.25rem 0 0 0;
        color: #94a3b8;
        font-size: 0.9rem;
    }

    /* Subheaders */
    .section-title {
        font-size: 1.5rem;
        font-weight: 600;
        margin: 2.5rem 0 1.5rem 0;
        color: #e2e8f0;
        border-bottom: 1px solid rgba(255,255,255,0.1);
        padding-bottom: 0.5rem;
        animation: fadeInUp 1s ease-out 0.4s forwards;
        opacity: 0;
    }

    /* Hide default Streamlit elements */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}

    /* Sidebar Styling */
    .css-1d391kg {
        background-color: #11141e;
        border-right: 1px solid rgba(255,255,255,0.05);
    }
    
    /* Plotly Chart Containers */
    .stPlotlyChart {
        background: rgba(30, 41, 59, 0.4);
        border-radius: 16px;
        padding: 1rem;
        border: 1px solid rgba(255, 255, 255, 0.05);
        animation: fadeInUp 1s ease-out 0.6s forwards;
        opacity: 0;
        transition: all 0.3s ease;
    }
    
    .stPlotlyChart:hover {
        background: rgba(30, 41, 59, 0.6);
        border-color: rgba(255, 255, 255, 0.1);
    }

    /* DataFrame Table Styling */
    .stDataFrame {
        animation: fadeInUp 1s ease-out 0.8s forwards;
        opacity: 0;
    }

    div[data-testid="stDataFrame"] > div {
        border-radius: 12px;
        border: 1px solid rgba(255,255,255,0.05);
        background: rgba(30, 41, 59, 0.4);
    }
    </style>
""", unsafe_allow_html=True)

# ----------------------------------------------------
# Header Section
# ----------------------------------------------------
st.markdown("""
<div class="main-header">
    <h1>Real time automatic network intrusion detection system</h1>
</div>
""", unsafe_allow_html=True)

# ----------------------------------------------------
# Sidebar Controls
# ----------------------------------------------------
if "is_monitoring" not in st.session_state:
    st.session_state.is_monitoring = False

with st.sidebar:
    st.markdown("## ⚙️ Control Panel")
    st.markdown("---")
    
    button_label = "🔴 Stop Monitoring" if st.session_state.is_monitoring else "🟢 Start Monitoring"
    if st.button(button_label, use_container_width=True):
        st.session_state.is_monitoring = not st.session_state.is_monitoring
        st.rerun()
    
    st.markdown("---")
    refresh_rate = st.slider("🔄 Refresh Interval (sec)", min_value=1, max_value=30, value=5, step=1)
    
    st.markdown("---")
    
    st.markdown("""
    <div style='background:#1e293b; padding:1rem; border-radius:8px; border:1px solid #334155;'>
        <h4 style='color:#cbd5e1; margin-top:0;'>Status</h4>
        <p style='color:#94a3b8; font-size:0.9rem; margin-bottom:0;'>
            Engine: <strong>LSTM Multi-class</strong><br>
            Mode: <strong>Live Packet Capture</strong>
        </p>
    </div>
    """, unsafe_allow_html=True)

# ----------------------------------------------------
# Data Pipeline Execution
# ----------------------------------------------------
if st.session_state.is_monitoring:
    # We use a placeholder so the UI doesn't jump too much
    status_text = st.sidebar.empty()
    status_text.info("⏳ Capturing and analyzing...")
    
    try:
        subprocess.run([sys.executable, "flow_extractor.py"], check=True)
        subprocess.run([sys.executable, "predict_live.py"], check=True)
        status_text.success("✅ Analysis Complete")
    except Exception as e:
        status_text.error(f"❌ Pipeline Error: {e}")
        
    time.sleep(refresh_rate)
    st.rerun() # Use standard st.rerun() available in newer Streamlit

# Ensure baseline prediction results exist
if not os.path.exists("prediction_results.csv"):
    with st.spinner("⏳ Initializing First Scan..."):
        subprocess.run([sys.executable, "flow_extractor.py"])
        subprocess.run([sys.executable, "predict_live.py"])

# ----------------------------------------------------
# Load Data
# ----------------------------------------------------
try:
    df = pd.read_csv("live_flows_basic.csv")
    pred = pd.read_csv("prediction_results.csv")
    
    if df.empty or pred.empty:
        st.info("🟢 Monitoring active. Waiting for the first network flows to be captured...")
        st.stop()
        
except pd.errors.EmptyDataError:
    st.info("🟢 Monitoring active. Waiting for the first network flows to be captured...")
    st.stop()
except Exception as e:
    st.error(f"Data files are missing or corrupted. Restart monitoring. Error: {e}")
    st.stop()

attack_flows = pred[pred["Prediction"] != "BENIGN"]
attack_count = len(attack_flows)

total_flows = len(df)
avg_duration = round(df["Flow Duration"].mean(), 3)
avg_packets = round(df["Total Fwd Packets"].mean(), 2)

# ----------------------------------------------------
# Responsive Metric Cards HTML
# ----------------------------------------------------
attacks_class = "danger" if attack_count > 0 else ""

metrics_html = f"""
<div class="metric-card-container">
    <div class="metric-card total-flows">
        <div class="metric-title">📡 Network Flows</div>
        <div class="metric-value">{total_flows}</div>
    </div>
    <div class="metric-card attacks">
        <div class="metric-title">⚔️ Detected Threats</div>
        <div class="metric-value {attacks_class}">{attack_count}</div>
    </div>
    <div class="metric-card duration">
        <div class="metric-title">⏱️ Avg Duration (s)</div>
        <div class="metric-value">{avg_duration}</div>
    </div>
    <div class="metric-card packets">
        <div class="metric-title">📦 Fwd Packets Avg</div>
        <div class="metric-value">{avg_packets}</div>
    </div>
</div>
"""
st.markdown(metrics_html, unsafe_allow_html=True)

# ----------------------------------------------------
# Alert Banner
# ----------------------------------------------------
if attack_count == 0:
    st.markdown("""
    <div class="alert-banner safe">
        <div class="alert-icon" style="font-size: 2rem;">✅</div>
        <div class="alert-content">
            <h3 style="color:#10b981;">Network Secure</h3>
            <p>Monitored traffic is benign. No malicious activity detected.</p>
        </div>
    </div>
    """, unsafe_allow_html=True)
else:
    st.markdown(f"""
    <div class="alert-banner danger">
        <div class="alert-icon" style="font-size: 2rem;">🚨</div>
        <div class="alert-content">
            <h3 style="color:#ef4444;">CRITICAL THREAT DETECTED</h3>
            <p>Identified <strong>{attack_count}</strong> malicious network flows attempting intrusion.</p>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("<div class='section-title'>🔍 Explained Threat Details</div>", unsafe_allow_html=True)
    # Filter the columns so we display the XAI Reason and features
    display_cols = ["Flow", "Prediction", "Confidence", "Severity", "Reason", "Key_Features"]
    
    # Check if XAI columns exist (in case of old CSV)
    if all(col in attack_flows.columns for col in display_cols):
        output_df = attack_flows[display_cols]
    else:
        output_df = attack_flows

    st.dataframe(
        output_df.style.applymap(lambda x: "background-color: #7f1d1d; color: #fca5a5;", subset=['Prediction']),
        use_container_width=True,
        hide_index=True
    )

# ----------------------------------------------------
# Visual Analytics Graphics Configuration
# ----------------------------------------------------
PLOTLY_THEME = {
    'layout': {
        'paper_bgcolor': 'rgba(0,0,0,0)',
        'plot_bgcolor': 'rgba(0,0,0,0)',
        'font': {'color': '#94a3b8', 'family': 'Inter'},
        'xaxis': {'gridcolor': 'rgba(255,255,255,0.05)', 'zerolinecolor': 'rgba(255,255,255,0.05)'},
        'yaxis': {'gridcolor': 'rgba(255,255,255,0.05)', 'zerolinecolor': 'rgba(255,255,255,0.05)'},
        'margin': dict(t=40, b=40, l=40, r=40)
    }
}

st.markdown("<div class='section-title'>📊 Traffic Telemetry Analysis</div>", unsafe_allow_html=True)

col1, col2 = st.columns(2)

with col1:
    fig1 = px.histogram(
        df, x="Flow Bytes/s", nbins=40,
        title="Byte Rate Distribution",
        color_discrete_sequence=['#3b82f6']
    )
    fig1.update_layout(**PLOTLY_THEME['layout'])
    # Add a slight gradient fill
    fig1.update_traces(marker={"line": {"width": 1, "color": '#60a5fa'}})
    st.plotly_chart(fig1, use_container_width=True, config={'displayModeBar': False})

with col2:
    fig2 = px.scatter(
        df, x="Flow Duration", y="Flow Bytes/s", size="Total Fwd Packets",
        title="Duration vs Byte Rate Topology",
        color_discrete_sequence=['#8b5cf6'],
        opacity=0.7
    )
    fig2.update_layout(**PLOTLY_THEME['layout'])
    st.plotly_chart(fig2, use_container_width=True, config={'displayModeBar': False})

st.markdown("<div class='section-title'>📈 Real-time Network Fingerprint</div>", unsafe_allow_html=True)

df["Flow Sequence"] = range(len(df))

# Merge prediction into main dataframe for coloring the scatter/line charts
df_merged = df.copy()
df_merged['Prediction'] = pred['Prediction']

# Traffic Trend Line Chart
fig3 = px.line(
    df, x="Flow Sequence", y="Flow Bytes/s",
    title="Throughput Over Sequence",
    color_discrete_sequence=['#ec4899']
)
# Make the line smoother and glowy
fig3.update_traces(line={"width": 3, "shape": 'spline'}, fill='tozeroy', fillcolor='rgba(236, 72, 153, 0.1)')
fig3.update_layout(**PLOTLY_THEME['layout'])
st.plotly_chart(fig3, use_container_width=True, config={'displayModeBar': False})

# Threat Classification Scatter Map
st.markdown("<div class='section-title'>🌐 Threat Classification Map</div>", unsafe_allow_html=True)

# Color mapping: Benign = Green/Blue, others = Red/Orange
color_map = {
    "BENIGN": "#10b981",
    "FLOODING": "#ef4444",
    "SCANNING": "#f59e0b",
    "BRUTE_FORCE": "#ec4899",
    "BOTNET": "#8b5cf6",
    "WEB_ATTACK": "#f43f5e"
}

fig4 = px.scatter(
    df_merged,
    x="Flow Sequence",
    y="Total Fwd Packets",
    color="Prediction",
    color_discrete_map=color_map,
    title="Packet Burst Analysis & Threat ID",
    size_max=15
)
fig4.update_traces(marker={"size": 10, "line": {"width": 1, "color": 'rgba(255,255,255,0.2)'}})
fig4.update_layout(**PLOTLY_THEME['layout'])
st.plotly_chart(fig4, use_container_width=True, config={'displayModeBar': False})

# ----------------------------------------------------
# Flow Data Table
# ----------------------------------------------------
st.markdown("<div class='section-title'>🖧 Raw Network Telemetry</div>", unsafe_allow_html=True)
st.dataframe(df_merged, use_container_width=True, height=400)