"""
core/opa.py
-----------
Defines the OPAEngine for executing Rego policies against parsed IaC data.
"""

import json
import os
import subprocess
from typing import Any, Dict, List


class OPAEngine:
    """
    Executes OPA policies using the local `opa` CLI binary.
    """

    def __init__(self, policy_dir: str):
        self.policy_dir = policy_dir

    def evaluate(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Applies Rego policies against the parsed infrastructure data.
        Returns a list of normalized vulnerability findings.
        """
        # Convert parsed data to JSON string to feed to OPA via stdin
        input_json = json.dumps(parsed_data)

        # Run OPA eval
        # Querying 'data.cloudsentinel.vulnerabilities' assuming policies define
        # package cloudsentinel
        # vulnerabilities[vuln] { ... }
        # Or more simply, just query 'data' and extract

        # We'll use a generic query 'data.policies' or let the Rego define a specific rule.
        # Let's assume policies use: package cloud.security
        # and define: deny[msg] { ... }
        # For our unified format, let's assume the rego outputs an object:
        # { "severity": 8, "resource": "aws_s3_bucket.my_bucket", "issue": "...", "remediation": "..." }
        # We query 'data.cloud_security.deny'

        cmd = [
            "opa",
            "eval",
            "--data",
            self.policy_dir,
            "--format",
            "json",
            "--stdin-input",
            "data.cloud_security.deny",
        ]

        try:
            result = subprocess.run(
                cmd, input=input_json, text=True, capture_output=True, check=True
            )
        except subprocess.CalledProcessError as e:
            # If OPA fails to run (e.g. syntax error in rego)
            print("OPA Error Output:", e.stderr)
            raise RuntimeError(f"OPA evaluation failed: {e.stderr}")
        except FileNotFoundError:
            raise RuntimeError(
                "OPA executable not found. Please ensure 'opa' is installed and on the PATH."
            )

        # Parse OPA JSON output
        output = json.loads(result.stdout)

        # 'opa eval' output structure: {"result": [{"expressions": [{"value": [...]}]}]}
        findings = []
        if "result" in output and len(output["result"]) > 0:
            expressions = output["result"][0].get("expressions", [])
            if expressions and "value" in expressions[0]:
                raw_denies = expressions[0]["value"]
                # raw_denies should be a list of vulnerability objects from the rego
                if isinstance(raw_denies, list):
                    findings.extend(raw_denies)
                elif raw_denies:
                    # sometimes it might return an object depending on rego structure, but usually lists for deny[...]
                    findings.append(raw_denies)

        return findings
