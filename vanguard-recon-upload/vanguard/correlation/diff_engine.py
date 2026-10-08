"""
Attack Surface Drift & Scan Differential Engine.

Compares consecutive audits of the same target to detect:
- Newly exposed ports or unexpected decommissioned services
- Newly introduced CVE vulnerabilities
- Remediated / patched security findings
- Risk Score trajectory delta
"""

from typing import Dict, Any, List
from pydantic import BaseModel, Field


class AttackSurfaceDelta(BaseModel):
    target: str
    previous_scan_id: str
    current_scan_id: str
    new_open_ports: List[int] = Field(default_factory=list)
    closed_ports: List[int] = Field(default_factory=list)
    new_vulnerabilities: List[str] = Field(default_factory=list)
    resolved_vulnerabilities: List[str] = Field(default_factory=list)
    risk_score_delta: int = 0
    drift_status: str = "UNCHANGED"  # "IMPROVED", "DEGRADED", "UNCHANGED"


class ScanDiffEngine:
    """Calculates differentials between two historical scans."""

    @staticmethod
    def compare_scans(old_scan: Dict[str, Any], new_scan: Dict[str, Any]) -> AttackSurfaceDelta:
        old_ports = set(p.get("port") for p in old_scan.get("open_ports", []))
        new_ports = set(p.get("port") for p in new_scan.get("open_ports", []))

        added_ports = sorted(list(new_ports - old_ports))
        removed_ports = sorted(list(old_ports - new_ports))

        old_cves = set(v.get("cve_id") for v in old_scan.get("vulns", []))
        new_cves = set(v.get("cve_id") for v in new_scan.get("vulns", []))

        added_cves = sorted(list(new_cves - old_cves))
        removed_cves = sorted(list(old_cves - new_cves))

        old_score = old_scan.get("risk", {}).get("overall_score", 0)
        new_score = new_scan.get("risk", {}).get("overall_score", 0)
        score_delta = new_score - old_score

        if score_delta > 0 or added_cves or added_ports:
            status = "DEGRADED (RISK INCREASED)"
        elif score_delta < 0 or removed_cves:
            status = "IMPROVED (RISK REDUCED)"
        else:
            status = "UNCHANGED"

        return AttackSurfaceDelta(
            target=new_scan.get("target", ""),
            previous_scan_id=old_scan.get("id", ""),
            current_scan_id=new_scan.get("id", ""),
            new_open_ports=added_ports,
            closed_ports=removed_ports,
            new_vulnerabilities=added_cves,
            resolved_vulnerabilities=removed_cves,
            risk_score_delta=score_delta,
            drift_status=status
        )
