import streamlit as st
import plotly.express as px
import pandas as pd
from ai_defense import defense_engine

st.set_page_config(page_title="AI Server Security Dashboard", layout="centered")

st.title("Traffic Breakdown")

# Sync data from defense engine metrics
metrics_data = defense_engine.metrics
df = pd.DataFrame({
    "Status": list(metrics_data.keys()),
    "Count": list(metrics_data.values())
})

# Recreate blue vertical bar chart matching progress report
fig = px.bar(
    df,
    x="Status",
    y="Count",
    text="Count",
    color_discrete_sequence=["#0066CC"]
)

fig.update_layout(
    xaxis_title="",
    yaxis_title="",
    plot_bgcolor="white",
    yaxis=dict(showgrid=True, gridcolor="#E5E5E5", range=[0, 22]),
    xaxis=dict(tickangle=90),
    font=dict(size=14)
)

fig.update_traces(textposition="outside")

st.plotly_chart(fig, use_container_width=True)
