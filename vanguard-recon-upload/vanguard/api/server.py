"""
FastAPI Server providing RESTful endpoints and Web Dashboard for VanguardRecon.
"""

import os
import uuid
from datetime import datetime
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel, Field

from vanguard.scope import ScopeManager, ScopeViolationError
from vanguard.core.scanner import AsyncPortScanner
from vanguard.core.fingerprinter import ServiceFingerprinter
from vanguard.core.web_analyzer import WebAnalyzer
from vanguard.core.dns_enumerator import DNSEnumerator
from vanguard.core.sensitive_files import SensitiveFilesProber
from vanguard.correlation.cve_engine import CVECorrelationEngine
from vanguard.correlation.mitre_mapper import MitreAttackMapper
from vanguard.correlation.diff_engine import ScanDiffEngine
from vanguard.reporting.html_reporter import HTMLReporter
from vanguard.correlation.vuln_database import VULN_KNOWLEDGE_BASE


app = FastAPI(
    title="VanguardRecon API",
    description="Next-Gen Attack Surface Discovery & Automated CVE Intelligence Framework",
    version="1.0.0"
)

# In-memory scan store for session management
SCAN_STORAGE: Dict[str, Dict[str, Any]] = {}


class ScanRequest(BaseModel):
    target: str
    ports: str = "21,22,25,80,110,443,445,1433,3306,3389,5432,6379,8000,8080,8443,27017"
    timeout: float = 1.5
    concurrency: int = 50
    web_audit: bool = True
    dns_enum: bool = False
    allow_internal: bool = True


async def execute_full_scan(scan_id: str, req: ScanRequest):
    """Background task executing the complete reconnaissance pipeline."""
    record = SCAN_STORAGE[scan_id]
    record["status"] = "running"

    try:
        # 1. Scope validation
        target_ip, target_host, is_private = ScopeManager.resolve_target(req.target)
        if is_private and not req.allow_internal:
            raise ScopeViolationError(f"Target '{req.target}' is in private RFC1918 space and allow_internal is False.")

        record["target_ip"] = target_ip
        record["is_private"] = is_private
        port_list = ScopeManager.parse_ports(req.ports)

        # 2. Port scanning
        scanner = AsyncPortScanner(
            target_ip=target_ip,
            ports=port_list,
            timeout=req.timeout,
            concurrency=req.concurrency,
            banner_grab=True
        )
        open_ports = await scanner.run()
        record["open_ports"] = [p.dict() for p in open_ports]

        # 3. Fingerprinting & CVE correlation
        all_findings = []
        for p in open_ports:
            fp = ServiceFingerprinter.fingerprint(p.service, p.banner)
            findings = CVECorrelationEngine.correlate(p.port, fp)
            all_findings.extend([f.dict() for f in findings])

        record["vulns"] = all_findings

        # 4. Risk Posture Assessment
        from vanguard.correlation.cve_engine import VulnerabilityFinding
        findings_objects = [VulnerabilityFinding(**f) for f in all_findings]
        risk_posture = CVECorrelationEngine.calculate_risk_posture(findings_objects)
        record["risk"] = risk_posture.dict()

        # 5. Web Analysis & Sensitive Files Disclosure
        web_ports = [p.port for p in open_ports if p.port in (80, 443, 8000, 8080, 8443)]
        sensitive_findings = []
        if req.web_audit and web_ports:
            probe_port = 443 if 443 in web_ports else web_ports[0]
            web_res = await WebAnalyzer.analyze(req.target, port=probe_port, timeout=3.0)
            record["web_audit"] = web_res.dict()

            # Sensitive Files Probe
            base_url = f"{'https' if probe_port in (443, 8443) else 'http'}://{req.target}:{probe_port}"
            sf_prober = SensitiveFilesProber(base_url=base_url, timeout=2.5)
            sf_results = await sf_prober.run()
            sensitive_findings = [s.dict() for s in sf_results]

        record["sensitive_files"] = sensitive_findings

        # 6. Optional DNS Enumeration
        if req.dns_enum and not is_private:
            dns_engine = DNSEnumerator(req.target, timeout=2.5)
            dns_records = await dns_engine.run(max_subdomains=30)
            record["subdomains"] = [d.dict() for d in dns_records]

        # 7. MITRE ATT&CK Framework Mapping
        mitre_techs = MitreAttackMapper.map_findings(
            open_ports=record["open_ports"],
            vulns=record["vulns"],
            sensitive_files=record["sensitive_files"],
            subdomains=record.get("subdomains", [])
        )
        record["mitre_techniques"] = [m.dict() for m in mitre_techs]

        record["status"] = "completed"

    except Exception as e:
        record["status"] = "failed"
        record["error"] = str(e)


@app.post("/api/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Initiates an attack surface reconnaissance scan."""
    scan_id = str(uuid.uuid4())[:8]
    SCAN_STORAGE[scan_id] = {
        "id": scan_id,
        "target": request.target,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "status": "queued",
        "open_ports": [],
        "vulns": [],
        "risk": {"overall_score": 0, "severity_label": "PENDING"},
        "web_audit": None,
        "sensitive_files": [],
        "subdomains": [],
        "mitre_techniques": []
    }
    background_tasks.add_task(execute_full_scan, scan_id, request)
    return {"scan_id": scan_id, "status": "queued", "target": request.target}


@app.get("/api/scans/compare")
async def compare_scans(scan_a: str, scan_b: str):
    """Calculates Attack Surface Drift between two historical audits."""
    if scan_a not in SCAN_STORAGE or scan_b not in SCAN_STORAGE:
        raise HTTPException(status_code=404, detail="One or both scan IDs not found")
    return ScanDiffEngine.compare_scans(SCAN_STORAGE[scan_a], SCAN_STORAGE[scan_b])


@app.get("/api/scans")
async def list_scans():
    """Returns list of recent scans."""
    return list(SCAN_STORAGE.values())


@app.get("/api/scans/{scan_id}")
async def get_scan_details(scan_id: str):
    """Retrieves full scan results for a specific scan ID."""
    if scan_id not in SCAN_STORAGE:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    return SCAN_STORAGE[scan_id]


@app.get("/api/scans/{scan_id}/report.html", response_class=HTMLResponse)
async def get_html_report(scan_id: str):
    """Renders printable, standalone HTML pentest deliverable."""
    if scan_id not in SCAN_STORAGE:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    scan_data = SCAN_STORAGE[scan_id]
    if scan_data["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan is still in progress")
    return HTMLResponse(content=HTMLReporter.generate(scan_data))


@app.get("/api/cve/database")
async def get_cve_database():
    """Returns the offline CVE intelligence and CISA KEV catalog."""
    return {"total": len(VULN_KNOWLEDGE_BASE), "cves": VULN_KNOWLEDGE_BASE}


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serves the primary UI dashboard."""
    static_file = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(static_file):
        with open(static_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>VanguardRecon API is Running. Static UI not found.</h1>")
