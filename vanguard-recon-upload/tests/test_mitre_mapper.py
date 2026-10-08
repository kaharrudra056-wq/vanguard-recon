"""
Unit tests for MITRE ATT&CK framework mapping.
"""

from vanguard.correlation.mitre_mapper import MitreAttackMapper


def test_mitre_mapping_with_cves_and_ssh():
    open_ports = [{"port": 22, "service": "ssh"}]
    vulns = [{"cve_id": "CVE-2024-6387", "severity": "HIGH"}]

    techniques = MitreAttackMapper.map_findings(open_ports, vulns)
    tech_ids = [t.technique_id for t in techniques]

    # Must map Active Reconnaissance (T1595.001)
    assert "T1595.001" in tech_ids

    # Must map Remote Services: SSH (T1021.004)
    assert "T1021.004" in tech_ids

    # Must map Exploit Public-Facing Application (T1190)
    assert "T1190" in tech_ids


def test_mitre_mapping_with_secret_leak():
    open_ports = [{"port": 80, "service": "http"}]
    vulns = []
    sensitive_files = [{"path": "/.env", "severity": "CRITICAL"}]

    techniques = MitreAttackMapper.map_findings(open_ports, vulns, sensitive_files=sensitive_files)
    tech_ids = [t.technique_id for t in techniques]

    # Must map Unsecured Credentials in Files (T1552.001)
    assert "T1552.001" in tech_ids
