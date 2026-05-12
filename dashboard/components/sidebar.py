import streamlit as st

from dashboard.api_client import APIClient
from dashboard.utils.styling import severity_badge


def render_sidebar():
    with st.sidebar:
        st.title("🛡️ CloudSentinel")
        st.write(f"Logged in as: **{st.session_state.get('user_email', 'User')}**")

        if st.button("Logout", use_container_width=True):
            st.session_state.clear()
            st.rerun()

        st.divider()
        st.subheader("Scan Explorer")

        with st.spinner("Loading scans..."):
            files = APIClient.get_files()

        if not files:
            st.info("No scans found")
            if st.button("🏠 Global Overview", use_container_width=True):
                st.session_state["selected_file"] = None
                st.rerun()
            return

        if st.button(
            "🏠 Global Overview",
            use_container_width=True,
            type="primary"
            if st.session_state.get("selected_file") is None
            else "secondary",
        ):
            st.session_state["selected_file"] = None
            st.rerun()

        st.write("---")

        for file in files:
            label = file["severity_classification"]
            score = file["latest_security_score"]

            # Simple button based selection
            btn_label = f"{file['filename']} ({score}/10)"
            if st.button(btn_label, key=file["filename"], use_container_width=True):
                st.session_state["selected_file"] = file["filename"]
                st.rerun()

            # Show small badge under button
            st.markdown(f"{severity_badge(label)}", unsafe_allow_html=True)
            st.caption(f"Last scan: {file['latest_scan_time'][:16].replace('T', ' ')}")
            st.divider()
