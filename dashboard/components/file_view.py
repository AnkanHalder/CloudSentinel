import pandas as pd
import plotly.express as px
import streamlit as st

from dashboard.api_client import APIClient
from dashboard.utils.styling import SEVERITY_COLORS, severity_badge


def render_file_view(filename):
    st.header(f"File Analysis: {filename}")

    with st.spinner(f"Loading history for {filename}..."):
        data = APIClient.get_file_history(filename)

    if not data or not data["history"]:
        st.warning("Could not retrieve history for this file.")
        return

    history = data["history"]
    latest = history[-1]

    # Latest Status Header
    col1, col2 = st.columns([1, 3])
    with col1:
        st.metric("Latest Score", f"{latest['security_score']}/10")
        st.markdown(
            severity_badge(latest["severity_classification"]), unsafe_allow_html=True
        )
    with col2:
        st.write(f"**Total Scans:** {len(history)}")
        st.write(f"**Latest Vulnerabilities:** {latest['vulnerability_count']}")
        st.write(f"**Last Scanned:** {latest['scan_time'].replace('T', ' ')[:16]}")

    st.divider()

    # History Charts
    df = pd.DataFrame(
        [
            {
                "Time": h["scan_time"],
                "Score": h["security_score"],
                "Vulns": h["vulnerability_count"],
                "Label": h["severity_classification"],
            }
            for h in history
        ]
    )
    df["Time"] = pd.to_datetime(df["Time"])

    c1, c2 = st.columns(2)

    with c1:
        st.subheader("Security Score Evolution")
        fig = px.line(df, x="Time", y="Score", markers=True, range_y=[0, 10.5])
        fig.update_layout(margin=dict(t=0, b=0, l=0, r=0))
        st.plotly_chart(fig, use_container_width=True)

    with c2:
        st.subheader("Vulnerability Trend")
        fig = px.bar(
            df, x="Time", y="Vulns", color="Vulns", color_continuous_scale="OrRd"
        )
        fig.update_layout(margin=dict(t=0, b=0, l=0, r=0), showlegend=False)
        st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # Latest Findings Table
    st.subheader("Latest Security Findings")
    findings = latest.get("vulnerabilities", [])
    if findings:
        # Create a display-friendly dataframe
        findings_data = []
        for f in findings:
            findings_data.append(
                {
                    "Resource": f["resource_name"],
                    "Severity": f["severity_score"],
                    "Impact": f["score_deduction"],
                    "Finding": f["message"],
                    "Remediation": f["remediation"] or "N/A",
                }
            )

        df_findings = pd.DataFrame(findings_data)

        # Display as a clean table with highlighting
        st.dataframe(
            df_findings,
            column_config={
                "Severity": st.column_config.NumberColumn(format="%d/10"),
                "Impact": st.column_config.NumberColumn(format="-%.1f"),
            },
            hide_index=True,
            use_container_width=True,
        )
    else:
        st.success("No vulnerabilities found in the latest scan! This file is secure.")

    st.divider()

    # Detail table
    with st.expander("Historical Score Log"):
        st.table(df[["Time", "Score", "Vulns", "Label"]])
