"""
hooks/scanner.py
----------------
Git staging detection, scan submission, and result evaluation logic.
Reads staged file content from the git index (not from disk) to accurately
reflect what will actually be committed.
"""

import subprocess
from typing import Any, Dict, List, Tuple

import requests

from hooks import api_client
from hooks.config import (BLOCK_ON_SEVERITY, IAC_EXCLUDE_PATTERNS,
                          IAC_EXTENSIONS)


def get_staged_iac_files() -> List[str]:
    """
    Return a list of newly Added, Copied, or Modified (ACM) staged files
    that match known IaC extensions.
    Deleted files are intentionally excluded — there is nothing to scan.
    """
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True,
        text=True,
    )
    all_staged = [f.strip() for f in result.stdout.splitlines() if f.strip()]

    iac_files = []
    for f in all_staged:
        lower = f.lower()
        if not any(lower.endswith(ext) for ext in IAC_EXTENSIONS):
            continue
        if any(pat in lower for pat in IAC_EXCLUDE_PATTERNS):
            continue
        iac_files.append(f)

    return iac_files


def get_staged_file_content(filepath: str) -> bytes:
    """
    Read a file's content from the git index (staged version), not from disk.
    This ensures we scan exactly what will be committed.
    """
    result = subprocess.run(
        ["git", "show", f":{filepath}"],
        capture_output=True,
    )
    return result.stdout


def run_scans(
    token: str,
    files: List[str],
    progress_cb=None,
) -> List[Dict[str, Any]]:
    """
    Submit each staged IaC file to the CloudSentinel scan API.
    Returns a list of scan result dicts (ScanOut format).

    progress_cb: optional callable(index, total, filepath, status_str)
    """
    results = []
    total = len(files)

    for idx, filepath in enumerate(files):
        if progress_cb:
            progress_cb(idx, total, filepath, "scanning")

        try:
            content = get_staged_file_content(filepath)
            scan_result = api_client.submit_scan(token, filepath, content)

            if scan_result is None:
                result = {"filepath": filepath, "error": "empty_response", "scan": None}
            else:
                result = {"filepath": filepath, "error": None, "scan": scan_result}

        except PermissionError:
            result = {"filepath": filepath, "error": "token_invalid", "scan": None}
        except requests.exceptions.ConnectionError:
            result = {"filepath": filepath, "error": "connection_refused", "scan": None}
        except requests.exceptions.Timeout:
            result = {"filepath": filepath, "error": "timeout", "scan": None}
        except Exception as e:
            result = {"filepath": filepath, "error": f"unexpected: {e}", "scan": None}

        if progress_cb:
            status = "error" if result["error"] else "done"
            progress_cb(idx, total, filepath, status, result)

        results.append(result)

    return results


def evaluate_results(
    scan_results: List[Dict[str, Any]]
) -> Tuple[bool, List[Dict], Dict]:
    """
    Evaluate a list of scan results and return:
      (commit_approved: bool, blocked_files: list, summary_stats: dict)

    A commit is BLOCKED if any vulnerability has severity_score >= BLOCK_ON_SEVERITY.
    Non-critical findings produce warnings but do not block.
    """
    total_findings = 0
    total_score_sum = 0
    score_count = 0
    sev_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    blocked_files = []
    commit_approved = True
    error_count = sum(1 for r in scan_results if r["error"])

    for result in scan_results:
        if result["error"] or not result["scan"]:
            continue

        scan = result["scan"]
        vulns = scan.get("vulnerabilities", [])
        total_findings += len(vulns)
        max_sev = 0

        for v in vulns:
            sev = v.get("severity_score", 0)
            if sev > max_sev:
                max_sev = sev
            if sev >= 8:
                sev_dist["critical"] += 1
            elif sev >= 6:
                sev_dist["high"] += 1
            elif sev >= 3:
                sev_dist["medium"] += 1
            else:
                sev_dist["low"] += 1

        # Compute security score (inverted from max severity)
        if max_sev == 0:
            file_score = 10
        else:
            file_score = max(0, 10 - max_sev)

        total_score_sum += file_score
        score_count += 1

        # Check for blocking findings
        blocking_vulns = [
            v for v in vulns if v.get("severity_score", 0) >= BLOCK_ON_SEVERITY
        ]
        if blocking_vulns:
            commit_approved = False
            blocked_files.append(
                {
                    "filepath": result["filepath"],
                    "vulnerabilities": blocking_vulns,
                }
            )

    avg_score = round(total_score_sum / score_count, 1) if score_count > 0 else 10.0

    summary = {
        "total_files": len(scan_results),
        "error_count": error_count,
        "total_findings": total_findings,
        "avg_score": avg_score,
        "severity_distribution": sev_dist,
        "blocked_count": len(blocked_files),
    }

    return commit_approved, blocked_files, summary
