import os


class Config:
    # Project Base Directory
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Policy Directory
    POLICY_DIR = os.path.join(BASE_DIR, "OPAPolicies")

    # Dataset Directories (For testing and reference)
    VULNERABLE_FILES_DIR = os.path.join(BASE_DIR, "VulnerableFiles")


config = Config()
