"""
Unit tests for JSON and HTML report generation.
"""

import json
from vanguard.reporting.json_reporter import JSONReporter
from vanguard.reporting.html_reporter import HTMLReporter


def test_json_reporting(tmp_path):
    dummy_data = {
        "target": "127.0.0.1",
        "timestamp": "2026-10-08 22:00:00",
        "risk": {"overall_score": 10, "severity_label": "LOW"},
        "open_ports": [{"port": 80, "state": "open", "service": "http", "banner": "Apache"}],
        "vulns": []
    }
    report_file = tmp_path / "report.json"
    content = JSONReporter.generate(dummy_data, str(report_file))

    assert json.loads(content)["target"] == "127.0.0.1"
    assert report_file.exists()


def test_html_reporting(tmp_path):
    dummy_data = {
        "target": "example.com",
        "target_ip": "93.184.216.34",
        "timestamp": "2026-10-08 22:00:00",
        "risk": {
            "overall_score": 85,
            "severity_label": "CRITICAL",
            "cisa_kev_active": True
        },
        "open_ports": [
            {"port": 80, "state": "open", "service": "http", "banner": "Apache/2.4.49", "latency_ms": 12.4}
        ],
        "vulns": [
            {
                "cve_id": "CVE-2021-41773",
                "title": "Apache Path Traversal RCE",
                "product": "Apache HTTP Server",
                "detected_version": "2.4.49",
                "port": 80,
                "service": "http",
                "cvss": 9.8,
                "severity": "CRITICAL",
                "cisa_kev": True,
                "exploit_available": True,
                "description": "Path normalization bug",
                "remediation": "Upgrade Apache"
            }
        ],
        "web_audit": None,
        "subdomains": []
    }
    report_file = tmp_path / "report.html"
    content = HTMLReporter.generate(dummy_data, str(report_file))

    assert "<title>Vanguard Security Audit Report - example.com</title>" in content
    assert "CVE-2021-41773" in content
    assert "CISA KEV" in content
    assert report_file.exists()
