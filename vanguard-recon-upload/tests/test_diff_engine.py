"""
Unit tests for Attack Surface Drift and scan differential engine.
"""

from vanguard.correlation.diff_engine import ScanDiffEngine


def test_scan_diff_degraded():
    old_scan = {
        "id": "scan_01",
        "target": "127.0.0.1",
        "open_ports": [{"port": 80}],
        "vulns": [],
        "risk": {"overall_score": 10}
    }
    new_scan = {
        "id": "scan_02",
        "target": "127.0.0.1",
        "open_ports": [{"port": 80}, {"port": 22}],
        "vulns": [{"cve_id": "CVE-2024-6387"}],
        "risk": {"overall_score": 85}
    }

    delta = ScanDiffEngine.compare_scans(old_scan, new_scan)

    assert delta.new_open_ports == [22]
    assert delta.new_vulnerabilities == ["CVE-2024-6387"]
    assert delta.risk_score_delta == 75
    assert "DEGRADED" in delta.drift_status


def test_scan_diff_improved():
    old_scan = {
        "id": "scan_01",
        "target": "127.0.0.1",
        "open_ports": [{"port": 80}, {"port": 3389}],
        "vulns": [{"cve_id": "CVE-2021-41773"}],
        "risk": {"overall_score": 95}
    }
    new_scan = {
        "id": "scan_02",
        "target": "127.0.0.1",
        "open_ports": [{"port": 80}],
        "vulns": [],
        "risk": {"overall_score": 10}
    }

    delta = ScanDiffEngine.compare_scans(old_scan, new_scan)

    assert delta.closed_ports == [3389]
    assert delta.resolved_vulnerabilities == ["CVE-2021-41773"]
    assert delta.risk_score_delta == -85
    assert "IMPROVED" in delta.drift_status
