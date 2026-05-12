import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from dashboard.api_client import APIClient
from dashboard.utils.styling import SEVERITY_COLORS


def render_global_view():
    st.header("Security Command Center")

    with st.spinner("Fetching global metrics..."):
        data = APIClient.get_global_analytics()

    if not data or data["total_scans"] == 0:
        st.info(
            "No prior scans detected. Initialize a scan via CLI or API to populate the command center."
        )
        return

    # Top Metrics Row
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Scans", data["total_scans"])
    m2.metric("Total Vulnerabilities", data["total_vulnerabilities"], delta=None)
    m3.metric("Avg Security Score", f"{data['average_security_score']}/10")
    m4.metric("Top Provider", data["most_affected_cloud_provider"])

    st.divider()

    # Charts Row 1
    c1, c2, c3 = st.columns(3)

    with c1:
        st.subheader("Severity Distribution")
        dist = data["severity_distribution"]
        labels = ["Critical", "High Risk", "Medium Risk", "Low Risk"]
        values = [dist["critical"], dist["high"], dist["medium"], dist["low"]]

        fig = px.pie(
            names=labels,
            values=values,
            color=labels,
            color_discrete_map={
                "Critical": SEVERITY_COLORS["Critical"],
                "High Risk": SEVERITY_COLORS["High Risk"],
                "Medium Risk": SEVERITY_COLORS["Medium Risk"],
                "Low Risk": SEVERITY_COLORS["Low Risk"],
            },
            hole=0.4,
        )
        fig.update_layout(margin=dict(t=0, b=0, l=0, r=0), showlegend=False)
        st.plotly_chart(fig, use_container_width=True)

    with c2:
        st.subheader("Provider Split")
        p_dist = data["provider_distribution"]
        p_labels = ["AWS", "Azure", "Other"]
        p_values = [p_dist["aws"], p_dist["azure"], p_dist["other"]]

        fig_p = px.pie(
            names=p_labels,
            values=p_values,
            color=p_labels,
            color_discrete_map={
                "AWS": "#FF9900",
                "Azure": "#0089D6",
                "Other": "#888888",
            },
            hole=0.4,
        )
        fig_p.update_layout(margin=dict(t=0, b=0, l=0, r=0), showlegend=False)
        st.plotly_chart(fig_p, use_container_width=True)

    with c3:
        st.subheader("Top Categories")
        cats = data["most_common_vulnerability_categories"]
        if cats:
            df_cats = {
                "Category": [c["category"] for c in cats],
                "Count": [c["count"] for c in cats],
            }
            fig_c = px.bar(
                df_cats,
                x="Count",
                y="Category",
                orientation="h",
                color="Count",
                color_continuous_scale="Reds",
            )
            fig_c.update_layout(margin=dict(t=0, b=0, l=0, r=0), showlegend=False)
            st.plotly_chart(fig_c, use_container_width=True)
        else:
            st.info("No categories available.")

    st.divider()

    # Trend Analysis
    st.subheader("Organization-Wide Security Trend")
    trends = data["trends"]
    if trends:
        df_trends = pd.DataFrame(
            [
                {
                    "Date": t["date"],
                    "Avg Score": t["avg_score"],
                    "Total Vulns": t["vulnerability_count"],
                }
                for t in trends
            ]
        )
        df_trends["Date"] = pd.to_datetime(df_trends["Date"])

        t1, t2 = st.columns(2)
        with t1:
            fig_t1 = px.line(
                df_trends,
                x="Date",
                y="Avg Score",
                markers=True,
                title="Average Security Score over Time",
            )
            fig_t1.update_layout(yaxis_range=[0, 10.5])
            st.plotly_chart(fig_t1, use_container_width=True)
        with t2:
            fig_t2 = px.area(
                df_trends,
                x="Date",
                y="Total Vulns",
                title="Total Vulnerabilities over Time",
                color_discrete_sequence=["#FF4B4B"],
            )
            st.plotly_chart(fig_t2, use_container_width=True)
    else:
        st.info("Insufficient historical data to render trends.")
