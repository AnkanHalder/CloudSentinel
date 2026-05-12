import os
import sys
from datetime import datetime
from unittest.mock import MagicMock

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.models.vulnerability import Vulnerability
from backend.services.analytics_service import calculate_security_score


def test_calculate_security_score():
    print("Testing calculate_security_score...")

    # Case 1: No vulnerabilities
    score, label = calculate_security_score([])
    assert score == 10
    assert label == "Secure"
    print("  - Case 1 (Empty): Pass")

    # Case 2: Low severity (1-3 -> -0.5)
    v1 = Vulnerability(severity_score=2)
    score, label = calculate_security_score([v1])
    # 10 - 0.5 = 9.5 -> round(10)
    assert score == 10
    assert label == "Secure"  # Score 10 is Secure
    print("  - Case 2 (Low): Pass")

    # Case 3: Medium severity (4-6 -> -1.0)
    v2 = Vulnerability(severity_score=5)
    score, label = calculate_security_score([v2])
    # 10 - 1.0 = 9.0 -> round(9)
    assert score == 9
    assert label == "Low Risk"  # 8-9 is Low Risk
    print("  - Case 3 (Medium): Pass")

    # Case 4: Multiple vulnerabilities
    v3 = Vulnerability(severity_score=9)  # -4.0
    v4 = Vulnerability(severity_score=7)  # -2.0
    v5 = Vulnerability(severity_score=5)  # -1.0
    v6 = Vulnerability(severity_score=2)  # -0.5
    # 10 - 4.0 - 2.0 - 1.0 - 0.5 = 2.5 -> round(3)
    score, label = calculate_security_score([v3, v4, v5, v6])
    assert score == 3
    assert label == "High Risk"  # 3-4 is High Risk
    print("  - Case 4 (Mixed): Pass")

    # Case 5: Many criticals
    v7 = Vulnerability(severity_score=10)  # -4.0
    v8 = Vulnerability(severity_score=10)  # -4.0
    v9 = Vulnerability(severity_score=10)  # -4.0
    # 10 - 12 = -2 -> capped at 0
    score, label = calculate_security_score([v7, v8, v9])
    assert score == 0
    assert label == "Critical"  # <= 2 is Critical
    print("  - Case 5 (Capped): Pass")


if __name__ == "__main__":
    try:
        test_calculate_security_score()
        print("\nAll analytics logic tests passed!")
    except AssertionError as e:
        print(f"\nTest failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        sys.exit(1)
