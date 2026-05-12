import streamlit as st

from dashboard.api_client import APIClient


def render_login():
    st.markdown(
        "<h1 style='text-align: center;'>CloudSentinel</h1>", unsafe_allow_html=True
    )
    st.markdown(
        "<p style='text-align: center; color: #6c757d;'>Enterprise Security Guardrail Auditor</p>",
        unsafe_allow_html=True,
    )

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        with st.form("login_form"):
            st.subheader("Sign In")
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Authenticate", use_container_width=True)

            if submit:
                if email and password:
                    with st.spinner("Authenticating..."):
                        result = APIClient.login(email, password)
                        if result:
                            st.session_state["token"] = result["token"]
                            st.session_state["user_email"] = email
                            st.rerun()
                        else:
                            st.error("Invalid credentials or server error")
                else:
                    st.warning("Please provide both email and password")
