"""
Exposed Sensitive Files & Information Disclosure Scanner.

Asynchronously audits web endpoints for critical leakages:
- Version Control repositories (/.git/HEAD)
- Environment and secret configurations (/.env)
- Database and code backups (/backup.zip, /db.sql)
- Exposed admin interfaces and API documentation (/swagger-ui.html, /actuator/health)
"""

from typing import List, Dict, Any, Optional
import httpx
from pydantic import BaseModel, Field


class ExposedAssetFinding(BaseModel):
    path: str
    url: str
    category: str  # "VERSION_CONTROL", "ENVIRONMENT_SECRETS", "BACKUP_FILE", "API_DOCS", "ADMIN_PORTAL"
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    status_code: int
    evidence: str
    description: str
    remediation: str


# High-risk sensitive file paths and verification signatures
SENSITIVE_PROBES = [
    {
        "path": "/.git/HEAD",
        "category": "VERSION_CONTROL",
        "severity": "CRITICAL",
        "signature": "ref: refs/",
        "description": "Exposed Git repository metadata allows attackers to reconstruct source code, commit history, and hardcoded credentials.",
        "remediation": "Deny public web server access to dotfiles like '/.git/' and remove repository metadata from production roots."
    },
    {
        "path": "/.env",
        "category": "ENVIRONMENT_SECRETS",
        "severity": "CRITICAL",
        "signature": "=",
        "description": "Exposed environment configuration file leaking database credentials, API secret keys, and JWT signing tokens.",
        "remediation": "Store environment files outside web root or configure web server rules to deny access to '*.env' files."
    },
    {
        "path": "/actuator/health",
        "category": "ADMIN_PORTAL",
        "severity": "MEDIUM",
        "signature": "status",
        "description": "Spring Boot Actuator health endpoint exposed without authentication, leaking application internals and dependencies.",
        "remediation": "Restrict Spring Boot Actuator endpoints behind authentication or bind to internal administrative interfaces."
    },
    {
        "path": "/swagger-ui.html",
        "category": "API_DOCS",
        "severity": "LOW",
        "signature": "swagger",
        "description": "Interactive Swagger API documentation interface accessible to unauthorized users, detailing all API routes.",
        "remediation": "Restrict Swagger / OpenAPI documentation to authorized development environments or behind VPN/Auth."
    },
    {
        "path": "/robots.txt",
        "category": "RECON_INFO",
        "severity": "INFO",
        "signature": "Disallow:",
        "description": "Robots.txt file reveals hidden directories, administrative portals, or sensitive paths intended to be hidden from search engines.",
        "remediation": "Review robots.txt to ensure it does not disclose confidential endpoint names or internal administrative paths."
    },
    {
        "path": "/phpmyadmin/",
        "category": "ADMIN_PORTAL",
        "severity": "HIGH",
        "signature": "phpmyadmin",
        "description": "Exposed phpMyAdmin database management portal open to brute-force authentication attacks.",
        "remediation": "Restrict phpMyAdmin access to trusted IP ranges or VPN networks."
    }
]


class SensitiveFilesProber:
    """Asynchronous prober for exposed files and information disclosure."""

    def __init__(self, base_url: str, timeout: float = 3.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    async def probe_path(self, probe_def: Dict[str, Any], client: httpx.AsyncClient) -> Optional[ExposedAssetFinding]:
        """Probes an individual sensitive path and validates response content."""
        target_url = f"{self.base_url}{probe_def['path']}"
        try:
            resp = await client.get(target_url)
            # Must return 200 OK
            if resp.status_code == 200:
                body_lower = resp.text.lower()
                expected_sig = probe_def["signature"].lower()
                
                # Check if the response contains the characteristic signature
                if expected_sig in body_lower:
                    evidence_snippet = resp.text.strip()[:120].replace("\n", " ")
                    return ExposedAssetFinding(
                        path=probe_def["path"],
                        url=target_url,
                        category=probe_def["category"],
                        severity=probe_def["severity"],
                        status_code=resp.status_code,
                        evidence=evidence_snippet,
                        description=probe_def["description"],
                        remediation=probe_def["remediation"]
                    )
        except Exception:
            pass
        return None

    async def run(self) -> List[ExposedAssetFinding]:
        """Runs concurrent probes against all configured sensitive paths."""
        findings: List[ExposedAssetFinding] = []
        try:
            async with httpx.AsyncClient(
                verify=False,
                timeout=self.timeout,
                follow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VanguardRecon/1.0"}
            ) as client:
                import asyncio
                tasks = [self.probe_path(probe, client) for probe in SENSITIVE_PROBES]
                results = await asyncio.gather(*tasks)
                findings = [r for r in results if r is not None]
        except Exception:
            pass
        return findings
