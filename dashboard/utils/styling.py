import streamlit as st

# Enterprise Security Color Palette
SEVERITY_COLORS = {
    "Critical": "#D32F2F",  # Material Red 700
    "High Risk": "#ED6C02",  # Material Orange 800
    "Medium Risk": "#FF9800",  # Material Orange 500
    "Low Risk": "#0288D1",  # Material Light Blue 700
    "Secure": "#2E7D32",  # Material Green 800
}


# Mapping for 0-10 scores
def get_severity_for_score(score: int) -> str:
    if score <= 2:
        return "Critical"
    if score <= 4:
        return "High Risk"
    if score <= 7:
        return "Medium Risk"
    if score <= 9:
        return "Low Risk"
    return "Secure"


def apply_custom_css():
    st.markdown(
        """
        <style>
        .main {
            background-color: #F8F9FA;
        }
        .stMetric {
            background-color: white;
            padding: 15px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            border: 1px solid #E9ECEF;
        }
        .severity-badge {
            padding: 4px 8px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
            font-size: 0.8rem;
        }
        .sidebar-file-item {
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 5px;
            border-left: 4px solid transparent;
        }
        .sidebar-file-item:hover {
            background-color: #E9ECEF;
        }
        </style>
    """,
        unsafe_allow_html=True,
    )


def severity_badge(label: str):
    color = SEVERITY_COLORS.get(label, "#6c757d")
    return f'<span class="severity-badge" style="background-color: {color};">{label}</span>'
