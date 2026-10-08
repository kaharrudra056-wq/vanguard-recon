"""
Automated CVE Correlation Engine & Risk Scoring Algorithm.

Matches service fingerprints against vulnerability datasets, evaluates version
ranges, checks CISA KEV exploitation catalogs, and calculates risk scores.
"""

import re
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from vanguard.core.fingerprinter import ServiceFingerprint
from vanguard.correlation.vuln_database import VULN_KNOWLEDGE_BASE


class VulnerabilityFinding(BaseModel):
    """Enriched vulnerability finding associated with an open port/service."""
    cve_id: str
    title: str
    product: str
    detected_version: str
    port: int
    service: str
    cvss: float
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    cisa_kev: bool = False
    epss: float = 0.0
    exploit_available: bool = False
    exploit_ref: str = ""
    description: str = ""
    remediation: str = ""


class RiskScoreAssessment(BaseModel):
    """Aggregated risk posture of the audited host."""
    overall_score: int = 0  # 0 (Hardened) to 100 (Compromise Imminent)
    severity_label: str = "LOW"
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    cisa_kev_active: bool = False
    max_cvss: float = 0.0


class CVECorrelationEngine:
    """Matches identified services against vulnerability catalogs."""

    @staticmethod
    def _parse_version_tuple(v_str: str) -> tuple:
        """Converts strings like '2.4.49' or '8.2p1' to comparable tuple."""
        clean = re.sub(r"[^\d\.]", "", v_str.replace("p", "."))
        parts = []
        for p in clean.split("."):
            if p.isdigit():
                parts.append(int(p))
        return tuple(parts)

    @classmethod
    def is_version_affected(cls, detected_version: str, entry: Dict[str, Any]) -> bool:
        """Determines if the detected version falls into the vulnerable range."""
        if not detected_version:
            return False

        detected_clean = detected_version.strip()

        # Exact match in listed vulnerable versions
        if detected_clean in entry.get("affected_versions", []):
            return True

        # Range comparison
        min_v = entry.get("min_version")
        max_v = entry.get("max_version")
        if min_v and max_v:
            try:
                target_tup = cls._parse_version_tuple(detected_clean)
                min_tup = cls._parse_version_tuple(min_v)
                max_tup = cls._parse_version_tuple(max_v)
                if min_tup <= target_tup <= max_tup:
                    return True
            except Exception:
                pass

        return False

    @classmethod
    def correlate(
        cls,
        port: int,
        fingerprint: ServiceFingerprint
    ) -> List[VulnerabilityFinding]:
        """Correlates a service fingerprint against known CVE entries."""
        findings: List[VulnerabilityFinding] = []

        if not fingerprint.product and not fingerprint.service:
            return findings

        prod_query = fingerprint.product.lower()
        service_query = fingerprint.service.lower()

        for entry in VULN_KNOWLEDGE_BASE:
            entry_prod = entry["product"].lower()

            # Product match condition
            product_matched = (
                entry_prod in prod_query or
                prod_query in entry_prod or
                entry_prod == service_query
            )

            if not product_matched:
                continue

            # Check version vulnerability
            if fingerprint.version:
                if cls.is_version_affected(fingerprint.version, entry):
                    findings.append(
                        VulnerabilityFinding(
                            cve_id=entry["cve_id"],
                            title=entry["title"],
                            product=entry["product"],
                            detected_version=fingerprint.version,
                            port=port,
                            service=fingerprint.service,
                            cvss=entry["cvss"],
                            severity=entry["severity"],
                            cisa_kev=entry["cisa_kev"],
                            epss=entry["epss"],
                            exploit_available=entry["exploit_available"],
                            exploit_ref=entry.get("exploit_ref", ""),
                            description=entry["description"],
                            remediation=entry["remediation"]
                        )
                    )

        # Sort findings by CVSS descending
        findings.sort(key=lambda f: (f.cvss, f.cisa_kev), reverse=True)
        return findings

    @classmethod
    def calculate_risk_posture(cls, findings: List[VulnerabilityFinding]) -> RiskScoreAssessment:
        """
        Calculates holistic risk score (0-100) based on CVSS severity,
        active CISA KEV exploitation, and exploit availability.
        """
        if not findings:
            return RiskScoreAssessment(overall_score=5, severity_label="LOW")

        crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")
        med_count = sum(1 for f in findings if f.severity == "MEDIUM")
        low_count = sum(1 for f in findings if f.severity == "LOW")

        max_cvss = max((f.cvss for f in findings), default=0.0)
        has_cisa_kev = any(f.cisa_kev for f in findings)
        has_public_exploit = any(f.exploit_available for f in findings)

        # Baseline from max CVSS: e.g. 9.8 -> 70 pts
        base = (max_cvss / 10.0) * 70

        # Cumulative findings weighting
        volume_pts = (crit_count * 8) + (high_count * 4) + (med_count * 1.5)

        # Threat intel modifiers
        threat_mod = 0.0
        if has_cisa_kev:
            threat_mod += 15.0  # Actively weaponized in wild
        if has_public_exploit:
            threat_mod += 10.0  # Public exploit code exists

        total = min(100, int(base + volume_pts + threat_mod))

        if total >= 80 or crit_count > 0:
            label = "CRITICAL"
        elif total >= 60 or high_count > 0:
            label = "HIGH"
        elif total >= 35 or med_count > 0:
            label = "MEDIUM"
        else:
            label = "LOW"

        return RiskScoreAssessment(
            overall_score=total,
            severity_label=label,
            critical_count=crit_count,
            high_count=high_count,
            medium_count=med_count,
            low_count=low_count,
            cisa_kev_active=has_cisa_kev,
            max_cvss=max_cvss
        )
