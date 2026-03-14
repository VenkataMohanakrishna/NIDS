import streamlit as st
import pandas as pd
import plotly.express as px
import subprocess
import time
import os

st.set_page_config(page_title="Deep Learning NIDS", layout="wide")

st.title("🛡 Deep Learning Network Intrusion Detection System")
st.markdown("### Real-Time Network Security Monitoring")

# ----------------------------------------------------
# Sidebar Controls
# ----------------------------------------------------

st.sidebar.title("NIDS Controls")

monitor = st.sidebar.checkbox("Enable Monitoring")

refresh_rate = st.sidebar.slider("Refresh Interval (seconds)", 2, 15, 5)

# ----------------------------------------------------
# Run monitoring if enabled
# ----------------------------------------------------

if monitor:

    with st.spinner("Capturing and analyzing traffic..."):

        subprocess.run(["python", "flow_extractor.py"])
        subprocess.run(["python", "predict_live.py"])

        time.sleep(refresh_rate)

# ----------------------------------------------------
# Ensure prediction results exist
# ----------------------------------------------------

if not os.path.exists("prediction_results.csv"):

    st.warning("Prediction results not found. Running detection pipeline...")

    subprocess.run(["python", "flow_extractor.py"])
    subprocess.run(["python", "predict_live.py"])

# ----------------------------------------------------
# Load flow data
# ----------------------------------------------------

try:
    df = pd.read_csv("live_flows_basic.csv")
except:
    st.error("Flow data not available.")
    st.stop()

# ----------------------------------------------------
# Load predictions
# ----------------------------------------------------

try:
    pred = pd.read_csv("prediction_results.csv")
except:
    st.error("Prediction results missing.")
    st.stop()

# ----------------------------------------------------
# Attack detection
# ----------------------------------------------------

attack_flows = pred[pred["Prediction"] != "BENIGN"]
attack_count = len(attack_flows)

# ----------------------------------------------------
# Top Metrics
# ----------------------------------------------------

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Flows", len(df))
col2.metric("Detected Attacks", attack_count)
col3.metric("Avg Flow Duration", round(df["Flow Duration"].mean(),3))
col4.metric("Avg Packets", round(df["Total Fwd Packets"].mean(),2))

# ----------------------------------------------------
# Alert Panel
# ----------------------------------------------------

st.subheader("🚨 Live Security Alerts")

if attack_count == 0:
    st.success("No active threats detected")

else:
    st.error("⚠ Suspicious flows detected")

    st.dataframe(attack_flows)

# ----------------------------------------------------
# Traffic Analysis Charts
# ----------------------------------------------------

st.subheader("Network Traffic Analysis")

col1, col2 = st.columns(2)

fig1 = px.histogram(
    df,
    x="Flow Bytes/s",
    nbins=40,
    title="Traffic Volume Distribution"
)

col1.plotly_chart(fig1, use_container_width=True)

fig2 = px.scatter(
    df,
    x="Flow Duration",
    y="Flow Bytes/s",
    size="Total Fwd Packets",
    title="Flow Behavior Map"
)

col2.plotly_chart(fig2, use_container_width=True)

# ----------------------------------------------------
# Traffic Trend
# ----------------------------------------------------

st.subheader("Traffic Trend")

df["Flow Index"] = range(len(df))

fig3 = px.line(
    df,
    x="Flow Index",
    y="Flow Bytes/s",
    title="Traffic Trend Over Time"
)

st.plotly_chart(fig3, use_container_width=True)

# ----------------------------------------------------
# Packet Distribution
# ----------------------------------------------------

st.subheader("Packet Distribution")

fig4 = px.bar(
    df,
    y="Total Fwd Packets",
    title="Forward Packet Count per Flow"
)

st.plotly_chart(fig4, use_container_width=True)

# ----------------------------------------------------
# Flow Table
# ----------------------------------------------------

st.subheader("Captured Network Flows")

st.dataframe(df, use_container_width=True)

st.success("Dashboard Updated Successfully")