import os
import re
import pandas as pd
import streamlit as st

DEFENSE_LOG = os.path.expanduser("~/ai_server_defense/defense_log.txt")
BLOCKED_FILE = os.path.expanduser("~/ai_server_defense/blocked_ips.txt")

st.set_page_config(page_title="AI Security Command Center", layout="wide")
st.title("🛡️ AI Security Monitoring Dashboard")

def parse_logs():
    parsed_logs = []
    if os.path.exists(DEFENSE_LOG):
        with open(DEFENSE_LOG, "r") as f:
            lines = f.readlines()

        log_pattern = re.compile(r'(\S+) - - \[.*?\] "(?:GET|POST) (\S+) HTTP/\d\.\d" (\d{3})')
        for line in lines[-100:]:
            match = log_pattern.search(line)
            if match:
                ip, endpoint, status = match.groups()
                parsed_logs.append({"Client IP": ip, "Endpoint": endpoint, "Status": status})

    return pd.DataFrame(parsed_logs)

# 1. Active Threat Alerts Section
if os.path.exists(BLOCKED_FILE):
    with open(BLOCKED_FILE, "r") as bf:
        blocked_ips = [line.strip() for line in bf if line.strip()]
        if blocked_ips:
            st.error(f"🚨 **ACTIVE THREAT ALERT:** {len(blocked_ips)} IP(s) currently blocked by AI Defense Engine: {', '.join(blocked_ips)}")

# 2. Metrics Setup
df = parse_logs()

if not df.empty:
    total_requests = len(df)
    success_count = len(df[df["Status"] == "200"])
    blocked_count = len(df[df["Status"] == "429"])

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Requests", total_requests)
    col2.metric("Successful (200 OK)", success_count)
    col3.metric("Blocked (429 Denied)", blocked_count)

    # 3. Layout: Logs & Visualizations
    col_left, col_right = st.columns([2, 1])

    with col_left:
        st.subheader("Recent Traffic Logs")
        st.dataframe(df, use_container_width=True)

    with col_right:
        st.subheader("Traffic Breakdown")
        chart_data = pd.DataFrame({
            "Status": ["200 OK", "429 Blocked"],
            "Count": [success_count, blocked_count]
        })
        st.bar_chart(chart_data.set_index("Status"))
else:
    st.info("No traffic logs detected yet. Run a traffic test to populate the dashboard.")
