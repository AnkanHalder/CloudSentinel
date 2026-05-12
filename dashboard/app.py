import os
import sys

import streamlit as st

# Add project root to sys.path to allow 'from dashboard.xxx' imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dashboard.components.auth import render_login
from dashboard.components.file_view import render_file_view
from dashboard.components.global_view import render_global_view
from dashboard.components.sidebar import render_sidebar
from dashboard.utils.styling import apply_custom_css

# Page Config
st.set_page_config(
    page_title="CloudSentinel Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Apply posh styling
apply_custom_css()

# Session State Initialisation
if "token" not in st.session_state:
    st.session_state["token"] = None
if "selected_file" not in st.session_state:
    st.session_state["selected_file"] = None

# Main Logic
if not st.session_state["token"]:
    render_login()
else:
    # Sidebar
    render_sidebar()

    # Main Content Area
    selected = st.session_state.get("selected_file")

    if selected:
        render_file_view(selected)
    else:
        render_global_view()
