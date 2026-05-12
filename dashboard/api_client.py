import requests
import streamlit as st

BASE_URL = "http://localhost:8000"


class APIClient:
    @staticmethod
    def login(email, password):
        try:
            response = requests.post(
                f"{BASE_URL}/user", json={"email": email, "password": password}
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            st.error(f"Connection failed: {e}")
            return None

    @staticmethod
    def get_headers():
        token = st.session_state.get("token")
        return {"Authorization": f"Bearer {token}"} if token else {}

    @classmethod
    def get_files(cls):
        try:
            response = requests.get(f"{BASE_URL}/files", headers=cls.get_headers())
            return response.json() if response.status_code == 200 else []
        except:
            return []

    @classmethod
    def get_global_analytics(cls):
        try:
            response = requests.get(
                f"{BASE_URL}/analytics/global", headers=cls.get_headers()
            )
            return response.json() if response.status_code == 200 else None
        except:
            return None

    @classmethod
    def get_file_history(cls, filename):
        try:
            # Note: filename might need encoding if it has special characters
            response = requests.get(
                f"{BASE_URL}/files/{filename}/history", headers=cls.get_headers()
            )
            return response.json() if response.status_code == 200 else None
        except:
            return None
