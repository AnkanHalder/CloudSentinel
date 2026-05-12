"""
hooks/renderer.py
-----------------
All terminal output for the CloudSentinel pre-commit security guardrail.
All non-ASCII characters are intentionally avoided for Windows CP1252 compat.
"""

import re
import sys
from typing import Any, Dict, List

try:
    import colorama

    colorama.init(autoreset=True)
    F = colorama.Fore
    S = colorama.Style
    COLORS = True
except ImportError:
    COLORS = False

    class _Noop:
        def __getattr__(self, _):
            return ""

    F = S = _Noop()


def _c(text: str, color: str) -> str:
    return f"{color}{text}{S.RESET_ALL}" if COLORS else text


def red(t):
    return _c(t, F.RED)


def yellow(t):
    return _c(t, F.YELLOW)


def cyan(t):
    return _c(t, F.CYAN)


def green(t):
    return _c(t, F.GREEN)


def white(t):
    return _c(t, F.WHITE)


def dim(t):
    return _c(t, S.DIM)


def bold(t):
    return _c(t, S.BRIGHT)


def _sev_label(score: int) -> str:
    if score >= 8:
        return "CRITICAL"
    if score >= 6:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    return "LOW"


def _sev_color(score: int):
    if score >= 8:
        return red
    if score >= 6:
        return yellow
    if score >= 3:
        return yellow
    return cyan


WIDTH = 58
DIVIDER = dim("-" * WIDTH)


def _center(text: str) -> str:
    clean = re.sub(r"\x1b\[[0-9;]*m", "", text)
    pad = max(0, (WIDTH - len(clean)) // 2)
    return " " * pad + text


def print_banner():
    print()
    print(dim("+" + "=" * (WIDTH - 2) + "+"))
    print(dim("|") + _center(bold("  [*] CloudSentinel Security Guardrail")) + dim("|"))
    print(dim("|") + _center(dim("  Pre-Commit Infrastructure Scan")) + dim("|"))
    print(dim("+" + "=" * (WIDTH - 2) + "+"))
    print()


def print_no_iac_files():
    print(f"  [i]  No staged infrastructure files detected.")
    print(f"  {dim('Skipping security scan - commit proceeding normally.')}")
    print()


def print_no_token():
    print(DIVIDER)
    print(f"  {red('[X]')}  No authentication token found.")
    print()
    print(f"  {dim('Run the following command to authenticate once:')}")
    print(f"  {bold('  python -m hooks.cli login')}")
    print(DIVIDER)
    print()


def print_token_invalid():
    print(DIVIDER)
    print(f"  {red('[X]')}  API token is invalid or has expired.")
    print()
    print(f"  {dim('Re-authenticate by running:')}")
    print(f"  {bold('  python -m hooks.cli login')}")
    print(DIVIDER)
    print()


def print_server_unreachable(url: str):
    print(DIVIDER)
    print(f"  {red('[X]')}  Cannot connect to CloudSentinel backend.")
    print(f"  {dim(f'Expected at: {url}')}")
    print()
    print(f"  {dim('Start the backend with:')}")
    print(f"  {bold('  uvicorn backend.main:app --reload')}")
    print(DIVIDER)
    print()


def print_scan_progress(
    idx: int, total: int, filepath: str, status: str, result: dict = None
):
    result = result or {}
    tag = f"[{idx + 1}/{total}]"
    short = filepath if len(filepath) <= 35 else "..." + filepath[-33:]
    name_col = f"{short:<36}"
    scan = result.get("scan") or {}

    if status == "scanning":
        line = f"  {dim(tag)}  {name_col}  {dim('scanning...')}"
    elif status == "done":
        n = len(scan.get("vulnerabilities", []))
        finding_str = f"{n} finding{'s' if n != 1 else ''}"
        check = green("[OK]") if n == 0 else yellow("[!] ")
        line = f"  {dim(tag)}  {name_col}  {check}  {dim(finding_str)}"
    else:
        err = result.get("error", "unknown")
        line = f"  {dim(tag)}  {name_col}  {red('[ERR]')}  {red(err)}"

    if status != "scanning":
        sys.stdout.write(f"\r{line}\n")
    else:
        sys.stdout.write(f"\r{line}")
    sys.stdout.flush()


def print_summary(summary: Dict[str, Any]):
    print()
    print(DIVIDER)
    print(f"  {bold('SCAN SUMMARY')}")
    print(DIVIDER)
    print(f"  Files Scanned    : {summary['total_files']}")
    print(f"  Total Findings   : {summary['total_findings']}")
    print(f"  Avg Score        : {summary['avg_score']} / 10")

    dist = summary["severity_distribution"]
    parts = []
    if dist["critical"]:
        parts.append(red(f"{dist['critical']} Critical"))
    if dist["high"]:
        parts.append(yellow(f"{dist['high']} High"))
    if dist["medium"]:
        parts.append(yellow(f"{dist['medium']} Medium"))
    if dist["low"]:
        parts.append(cyan(f"{dist['low']} Low"))
    sev_str = "  |  ".join(parts) if parts else green("None")
    print(f"  Severity Split   : {sev_str}")
    if summary.get("error_count"):
        print(f"  Scan Errors      : {red(str(summary['error_count']))}")
    print()


def print_blocked_files(blocked_files: List[Dict]):
    print(DIVIDER)
    print(f"  {bold(red('BLOCKED FILES'))}")
    print(DIVIDER)

    for bf in blocked_files:
        print(f"\n  {red('[X]')}  {bold(bf['filepath'])}")
        for v in bf["vulnerabilities"]:
            score = v.get("severity_score", 0)
            label = _sev_label(score)
            color = _sev_color(score)
            resource = v.get("resource_name", "unknown")
            message = v.get("message", "")
            remediation = v.get("remediation", "")
            vuln_id = v.get("vulnerability_id", "")

            print()
            print(f"    {color(f'[{label} - {score}/10]')}  {white(resource)}")
            if vuln_id:
                print(f"    {dim('Policy')}     : {dim(vuln_id[:45])}")
            print(f"    {dim('Issue')}      : {message}")
            if remediation:
                print(f"    {dim('Fix')}        : {dim(remediation)}")

    print()


def print_warning_findings(scan_results: List[Dict]):
    warnings = []
    for result in scan_results:
        if result.get("error") or not result.get("scan"):
            continue
        non_critical = [
            v
            for v in result["scan"].get("vulnerabilities", [])
            if v.get("severity_score", 0) < 8
        ]
        if non_critical:
            warnings.append(
                {"filepath": result["filepath"], "vulnerabilities": non_critical}
            )

    if not warnings:
        return

    print(DIVIDER)
    print(f"  {bold(yellow('ADVISORY FINDINGS'))}  {dim('(non-blocking)')}")
    print(DIVIDER)

    for w in warnings:
        print(f"\n  {yellow('[!]')}  {w['filepath']}")
        for v in w["vulnerabilities"]:
            score = v.get("severity_score", 0)
            label = _sev_label(score)
            print(
                f"    {yellow(f'[{label} - {score}/10]')}  {v.get('resource_name', '')} - {dim(v.get('message', ''))}"
            )
    print()


def print_commit_blocked():
    print(DIVIDER)
    print(f"  {bold(red('[X]  COMMIT BLOCKED'))}")
    print(f"  {dim('Resolve critical issues above before committing.')}")
    print(DIVIDER)
    print()


def print_commit_approved(summary: Dict[str, Any]):
    print(DIVIDER)
    print(f"  {bold(green('[OK] COMMIT APPROVED'))}")
    print(f"  {dim('All scanned files passed security checks.')}")
    print(DIVIDER)
    print()
