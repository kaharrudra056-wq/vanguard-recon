"""
Unit tests for CVE correlation and risk scoring engine.
"""

from vanguard.core.fingerprinter import ServiceFingerprint
from vanguard.correlation.cve_engine import CVECorrelationEngine


def test_correlate_apache_path_traversal():
    fp = ServiceFingerprint(
        service="http",
        product="Apache HTTP Server",
        version="2.4.49",
        confidence=0.9
    )
    findings = CVECorrelationEngine.correlate(80, fp)
    assert len(findings) > 0

    cve_ids = [f.cve_id for f in findings]
    assert "CVE-2021-41773" in cve_ids

    # Find the CVE-2021-41773 finding
    rce_vuln = next(f for f in findings if f.cve_id == "CVE-2021-41773")
    assert rce_vuln.severity == "CRITICAL"
    assert rce_vuln.cvss >= 9.0
    assert rce_vuln.cisa_kev is True
    assert rce_vuln.exploit_available is True


def test_correlate_openssh_regresshion():
    fp = ServiceFingerprint(
        service="ssh",
        product="OpenSSH",
        version="9.2p1",
        confidence=0.9
    )
    findings = CVECorrelationEngine.correlate(22, fp)
    cve_ids = [f.cve_id for f in findings]
    assert "CVE-2024-6387" in cve_ids


def test_risk_score_calculation():
    fp = ServiceFingerprint(
        service="http",
        product="Apache HTTP Server",
        version="2.4.49"
    )
    findings = CVECorrelationEngine.correlate(80, fp)
    risk = CVECorrelationEngine.calculate_risk_posture(findings)

    assert risk.severity_label == "CRITICAL"
    assert risk.overall_score >= 80
    assert risk.cisa_kev_active is True
    assert risk.critical_count >= 1
