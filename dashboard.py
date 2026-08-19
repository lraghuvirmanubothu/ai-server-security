import os
import time
import pandas as pd
import plotly.express as px
import streamlit as st

st.set_page_config(page_title="AI Cyber Defense Dashboard", page_icon="🛡️", layout="wide")

LOG_FILE_PATH = "/var/log/apache2/access.log"
st.title("🛡️ Real-Time Security & Traffic Monitor")

# Empty container to overwrite UI cleanly every cycle (Prevents stacking)
ui_container = st.empty()

with ui_container.container():
    if not os.path.exists(LOG_FILE_PATH):
        st.error(f"❌ File missing: {LOG_FILE_PATH}")
    else:
        try:
            with open(LOG_FILE_PATH, "r") as f:
                lines = [line.strip() for line in f.readlines()[-300:] if line.strip()]

            if not lines:
                st.info("Waiting for web traffic... Run a curl request to view activity.")
            else:
                records = []
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 1:
                        ip = parts[0]
                        if ip in ["::1", "127.0.0.1"]:
                            ip = "localhost"
                        
                        endpoint = parts[6] if len(parts) > 6 else "/"
                        status = parts[8] if len(parts) > 8 else "200"
                        records.append({"Client IP": ip, "Endpoint": endpoint, "HTTP Status": status, "Raw Log": line})

                df = pd.DataFrame(records)

                if not df.empty:
                    st.subheader("📊 Live Request Volume")
                    counts = df["Client IP"].value_counts().reset_index()
                    counts.columns = ["Client IP", "Total Requests"]

                    fig = px.bar(
                        counts, x="Client IP", y="Total Requests", 
                        color="Total Requests", color_continuous_scale="Reds", text="Total Requests"
                    )
                    st.plotly_chart(fig, use_container_width=True)
                    st.dataframe(df[["Client IP", "Endpoint", "HTTP Status", "Raw Log"]].tail(10), use_container_width=True)

        except Exception as e:
            st.error(f"❌ Read Error: {e}")

time.sleep(2)
st.rerun()
