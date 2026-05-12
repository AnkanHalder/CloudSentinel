"""
hooks/run_scan.py
-----------------
Entry point for the CloudSentinel pre-commit security guardrail.

Called by the pre-commit framework as a local hook.
Orchestrates: file detection → auth check → scanning → evaluation → reporting.
"""

import sys

import requests

from hooks import api_client, renderer, scanner
from hooks.config import API_BASE_URL


def main() -> int:
    renderer.print_banner()

    # 1. Detect staged IaC files (Added/Copied/Modified only)
    iac_files = scanner.get_staged_iac_files()
    if not iac_files:
        renderer.print_no_iac_files()
        return 0

    print(f"  Scanning {len(iac_files)} infrastructure file(s)...\n")

    # 2. Load token — non-interactive; never prompt inside the hook
    token = api_client.load_token()
    if token is None:
        renderer.print_no_token()
        return 1

    # 3. Run scans with per-file progress
    scan_results = []

    def _progress(idx, total, filepath, status, result=None):
        renderer.print_scan_progress(idx, total, filepath, status, result or {})

    try:
        scan_results = scanner.run_scans(token, iac_files, progress_cb=_progress)
    except Exception as e:
        print(f"\n  {renderer.red('✗')}  Unexpected error during scanning: {e}")
        return 1

    print()  # newline after progress lines

    # 4. Check for token_invalid errors
    if any(r.get("error") == "token_invalid" for r in scan_results):
        renderer.print_token_invalid()
        return 1

    # 5. Check for connection errors
    if any(r.get("error") == "connection_refused" for r in scan_results):
        renderer.print_server_unreachable(API_BASE_URL)
        return 1

    # 6. Evaluate results
    approved, blocked_files, summary = scanner.evaluate_results(scan_results)

    # 7. Print full report
    renderer.print_summary(summary)

    if not approved:
        renderer.print_blocked_files(blocked_files)
        renderer.print_warning_findings(scan_results)
        renderer.print_commit_blocked()
        return 1

    renderer.print_warning_findings(scan_results)
    renderer.print_commit_approved(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
