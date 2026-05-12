from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class FileSummaryOut(BaseModel):
    filename: str
    latest_scan_time: datetime
    latest_security_score: int
    scan_count: int
    severity_classification: str


class VulnerabilityCategoryCount(BaseModel):
    category: str
    count: int


class SeverityDistribution(BaseModel):
    critical: int
    high: int
    medium: int
    low: int


class ProviderDistribution(BaseModel):
    aws: int
    azure: int
    other: int


class GlobalTrendItem(BaseModel):
    date: datetime
    avg_score: float
    vulnerability_count: int


class GlobalAnalyticsOut(BaseModel):
    total_scans: int
    total_vulnerabilities: int
    average_security_score: float
    severity_distribution: SeverityDistribution
    provider_distribution: ProviderDistribution
    most_common_vulnerability_categories: List[VulnerabilityCategoryCount]
    most_affected_cloud_provider: str
    trends: List[GlobalTrendItem]


class DetailedVulnerabilityOut(BaseModel):
    vulnerability_id: str
    severity_score: int
    resource_name: str
    message: str
    remediation: Optional[str]
    score_deduction: float


class ScanHistoryItem(BaseModel):
    scan_id: str
    scan_time: datetime
    vulnerability_count: int
    security_score: int
    severity_classification: str
    vulnerabilities: List[DetailedVulnerabilityOut]


class FileHistoryOut(BaseModel):
    filename: str
    history: List[ScanHistoryItem]
