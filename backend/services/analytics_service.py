from datetime import datetime
from typing import Any, Dict, List, Tuple

from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.models.scan import Scan
from backend.models.vulnerability import Vulnerability
from backend.schemas.analytics import (DetailedVulnerabilityOut,
                                       FileHistoryOut, FileSummaryOut,
                                       GlobalAnalyticsOut, GlobalTrendItem,
                                       ProviderDistribution, ScanHistoryItem,
                                       SeverityDistribution,
                                       VulnerabilityCategoryCount)


def calculate_security_score(vulnerabilities: List[Vulnerability]) -> Tuple[int, str]:
    """
    Returns (security_score 0-10, classification_label)
    Calculates score based on strict deductions:
    - Severity 9-10: -4.0 points
    - Severity 7-8: -2.0 points
    - Severity 4-6: -1.0 points
    - Severity 1-3: -0.5 points
    """
    if not vulnerabilities:
        return 10, "Secure"

    score = 10.0
    for v in vulnerabilities:
        sev = v.severity_score
        # Deductions
        if sev >= 9:
            score -= 4.0
        elif sev >= 7:
            score -= 2.0
        elif sev >= 4:
            score -= 1.0
        else:
            score -= 0.5

    final_score = max(0, int(score + 0.5))

    # Classification based on final computed score
    if final_score <= 2:
        label = "Critical"
    elif final_score <= 4:
        label = "High Risk"
    elif final_score <= 7:
        label = "Medium Risk"
    elif final_score <= 9:
        label = "Low Risk"
    else:
        label = "Secure"

    return final_score, label


def get_all_files(db: Session, user_id: str) -> List[FileSummaryOut]:
    """Fetch lightweight file listing with metadata for the authenticated user."""
    # Find all distinct files for user
    files = db.query(Scan.filename).filter(Scan.user_id == user_id).distinct().all()

    summaries = []
    for (filename,) in files:
        scans = (
            db.query(Scan)
            .filter(Scan.user_id == user_id, Scan.filename == filename)
            .order_by(Scan.scan_time.desc())
            .all()
        )
        if not scans:
            continue

        latest_scan = scans[0]
        scan_count = len(scans)

        # Get vulnerabilities for the latest scan
        latest_vulns = (
            db.query(Vulnerability)
            .filter(Vulnerability.scan_id == latest_scan.scan_id)
            .all()
        )
        score, label = calculate_security_score(latest_vulns)

        summaries.append(
            FileSummaryOut(
                filename=filename,
                latest_scan_time=latest_scan.scan_time,
                latest_security_score=score,
                scan_count=scan_count,
                severity_classification=label,
            )
        )

    return summaries


def get_global_analytics(db: Session, user_id: str) -> GlobalAnalyticsOut:
    """Fetch global security statistics focused on the LATEST scan state of each file."""
    # Find all distinct files for user
    filenames = db.query(Scan.filename).filter(Scan.user_id == user_id).distinct().all()

    if not filenames:
        return GlobalAnalyticsOut(
            total_scans=0,
            total_vulnerabilities=0,
            average_security_score=10.0,
            severity_distribution=SeverityDistribution(
                critical=0, high=0, medium=0, low=0
            ),
            provider_distribution=ProviderDistribution(aws=0, azure=0, other=0),
            most_common_vulnerability_categories=[],
            most_affected_cloud_provider="None",
            trends=[],
        )

    latest_scans = []
    for (fname,) in filenames:
        ls = (
            db.query(Scan)
            .filter(Scan.user_id == user_id, Scan.filename == fname)
            .order_by(Scan.scan_time.desc())
            .first()
        )
        if ls:
            latest_scans.append(ls)

    total_scans = len(latest_scans)
    total_vulns = 0
    total_score = 0
    sev_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    category_counts: Dict[str, int] = {}
    provider_counts: Dict[str, int] = {"aws": 0, "azure": 0, "other": 0}

    for scan in latest_scans:
        vulns = (
            db.query(Vulnerability).filter(Vulnerability.scan_id == scan.scan_id).all()
        )
        total_vulns += len(vulns)

        for v in vulns:
            sev = v.severity_score
            # Distribution
            if sev >= 9:
                sev_dist["critical"] += 1
            elif sev >= 7:
                sev_dist["high"] += 1
            elif sev >= 4:
                sev_dist["medium"] += 1
            else:
                sev_dist["low"] += 1

            # Categories
            msg = v.message.lower()
            cat = "General"
            if "s3" in msg or "blob" in msg or "storage" in msg:
                cat = "Storage"
            elif "ssh" in msg or "rdp" in msg or "port" in msg or "firewall" in msg:
                cat = "Network"
            elif "iam" in msg or "policy" in msg or "permission" in msg:
                cat = "Access Control"
            elif "encryption" in msg or "encrypted" in msg:
                cat = "Encryption"
            category_counts[cat] = category_counts.get(cat, 0) + 1

            # Provider
            res = v.resource_name.lower()
            if res.startswith("aws"):
                provider_counts["aws"] += 1
            elif res.startswith("azurerm") or res.startswith("azure"):
                provider_counts["azure"] += 1
            else:
                provider_counts["other"] += 1

        score, _ = calculate_security_score(vulns)
        total_score += score

    avg_score = total_score / total_scans if total_scans > 0 else 10.0

    # Sort categories
    top_cats = [
        VulnerabilityCategoryCount(category=cat, count=count)
        for cat, count in sorted(
            category_counts.items(), key=lambda x: x[1], reverse=True
        )[:5]
    ]

    # Most affected provider
    most_affected = (
        max(provider_counts, key=provider_counts.get)
        if any(provider_counts.values())
        else "None"
    )

    # Trends (group by day) - Historical scan data is still relevant for trends
    trend_data: Dict[str, Dict[str, Any]] = {}
    all_scans = db.query(Scan).filter(Scan.user_id == user_id).all()
    for scan in all_scans:
        day = scan.scan_time.strftime("%Y-%m-%d")
        if day not in trend_data:
            trend_data[day] = {"total_score": 0, "count": 0, "vulns": 0}

        # Calculate score for this scan
        scan_vulns = (
            db.query(Vulnerability).filter(Vulnerability.scan_id == scan.scan_id).all()
        )
        s, _ = calculate_security_score(scan_vulns)

        trend_data[day]["total_score"] += s
        trend_data[day]["count"] += 1
        trend_data[day]["vulns"] += len(scan_vulns)

    sorted_days = sorted(trend_data.keys())
    trends = []
    for d in sorted_days:
        trends.append(
            GlobalTrendItem(
                date=datetime.strptime(d, "%Y-%m-%d"),
                avg_score=round(
                    trend_data[d]["total_score"] / trend_data[d]["count"], 1
                ),
                vulnerability_count=trend_data[d]["vulns"],
            )
        )

    return GlobalAnalyticsOut(
        total_scans=total_scans,
        total_vulnerabilities=total_vulns,
        average_security_score=round(avg_score, 1),
        severity_distribution=SeverityDistribution(
            critical=sev_dist["critical"],
            high=sev_dist["high"],
            medium=sev_dist["medium"],
            low=sev_dist["low"],
        ),
        provider_distribution=ProviderDistribution(
            aws=provider_counts["aws"],
            azure=provider_counts["azure"],
            other=provider_counts["other"],
        ),
        most_common_vulnerability_categories=top_cats,
        most_affected_cloud_provider=most_affected.upper(),
        trends=trends,
    )


def get_file_history(db: Session, user_id: str, filename: str) -> FileHistoryOut:
    """Fetch historical scan timeline for a specific file with detailed findings."""
    from backend.schemas.analytics import DetailedVulnerabilityOut

    scans = (
        db.query(Scan)
        .filter(Scan.user_id == user_id, Scan.filename == filename)
        .order_by(Scan.scan_time.asc())
        .all()
    )

    history_items = []
    for scan in scans:
        vulns = (
            db.query(Vulnerability).filter(Vulnerability.scan_id == scan.scan_id).all()
        )
        detailed_vulns = []

        for v in vulns:
            # Deduction mapping
            deduction = (
                4.0
                if v.severity_score >= 9
                else (
                    2.0
                    if v.severity_score >= 7
                    else (1.0 if v.severity_score >= 4 else 0.5)
                )
            )

            detailed_vulns.append(
                DetailedVulnerabilityOut(
                    vulnerability_id=v.vulnerability_id,
                    severity_score=v.severity_score,
                    resource_name=v.resource_name,
                    message=v.message,
                    remediation=v.remediation,
                    score_deduction=deduction,
                )
            )

        score, label = calculate_security_score(vulns)

        history_items.append(
            ScanHistoryItem(
                scan_id=scan.scan_id,
                scan_time=scan.scan_time,
                vulnerability_count=len(vulns),
                security_score=score,
                severity_classification=label,
                vulnerabilities=detailed_vulns,
            )
        )

    return FileHistoryOut(filename=filename, history=history_items)
