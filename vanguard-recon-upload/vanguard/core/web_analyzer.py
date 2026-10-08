"""
Asynchronous Web Reconnaissance & Technology Stack Analyzer.

Features:
- HTTP Security Header Auditing (OWASP Secure Headers Project)
- Technology Stack Fingerprinting (Wappalyzer-style heuristics)
- Information Disclosure / Leaked Headers detection (Server, X-Powered-By)
- TLS / SSL Certificate Inspection (Subject, SANs, Issuer, Expiration)
"""

import ssl
import socket
from datetime import datetime
from typing import Dict, List, Optional
import httpx
from pydantic import BaseModel, Field


class HeaderAuditItem(BaseModel):
    header: str
    present: bool
    value: str = ""
    status: str = "PASS"  # "PASS", "WARN", "FAIL"
    recommendation: str = ""


class TLSCertInfo(BaseModel):
    subject_cn: str = ""
    san_list: List[str] = Field(default_factory=list)
    issuer: str = ""
    valid_from: str = ""
    valid_to: str = ""
    is_expired: bool = False
    days_until_expiry: int = 0


class WebAnalysisResult(BaseModel):
    url: str
    status_code: int = 0
    title: str = ""
    server: str = ""
    powered_by: str = ""
    detected_tech: List[str] = Field(default_factory=list)
    security_headers: List[HeaderAuditItem] = Field(default_factory=list)
    header_score: int = 100  # 0 to 100 security score
    tls_cert: Optional[TLSCertInfo] = None
    error: str = ""


class WebAnalyzer:
    """Performs deep asynchronous inspection on HTTP/HTTPS endpoints."""

    RECOMMENDED_HEADERS = {
        "Strict-Transport-Security": {
            "severity": "HIGH",
            "desc": "Enforces secure HTTPS connections and guards against SSL stripping attacks.",
            "rec": "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
        },
        "Content-Security-Policy": {
            "severity": "HIGH",
            "desc": "Prevents Cross-Site Scripting (XSS) and code injection by restricting script sources.",
            "rec": "Define a robust Content-Security-Policy restricting unauthorized script-src and object-src."
        },
        "X-Frame-Options": {
            "severity": "MEDIUM",
            "desc": "Prevents Clickjacking by disallowing embedding within iframes.",
            "rec": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'."
        },
        "X-Content-Type-Options": {
            "severity": "MEDIUM",
            "desc": "Prevents MIME-sniffing attacks by instructing browsers to adhere to declared Content-Type.",
            "rec": "Set 'X-Content-Type-Options: nosniff'."
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "desc": "Governs how much referrer information is sent with outbound requests.",
            "rec": "Set 'Referrer-Policy: strict-origin-when-cross-origin'."
        },
        "Permissions-Policy": {
            "severity": "LOW",
            "desc": "Restricts browser features like camera, microphone, geolocation.",
            "rec": "Configure 'Permissions-Policy: camera=(), microphone=(), geolocation=()'."
        }
    }

    @staticmethod
    def get_tls_info(hostname: str, port: int = 443, timeout: float = 3.0) -> Optional[TLSCertInfo]:
        """Extracts and parses SSL/TLS certificate details directly from socket."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if not cert:
                        # Fallback for CERT_NONE returning empty dict
                        der = ssock.getpeercert(binary_form=True)
                        return TLSCertInfo(subject_cn=hostname, issuer="Unknown (Self-signed or internal)")

                    # Extract Subject Common Name
                    subject = dict(x[0] for x in cert.get("subject", []))
                    cn = subject.get("commonName", hostname)

                    # Extract Issuer
                    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                    issuer_org = issuer_dict.get("organizationName", issuer_dict.get("commonName", "Unknown"))

                    # Extract SANs
                    sans = [entry[1] for entry in cert.get("subjectAltName", []) if entry[0] == "DNS"]

                    # Extract Validity
                    not_after = cert.get("notAfter", "")
                    not_before = cert.get("notBefore", "")

                    is_expired = False
                    days_left = 0
                    if not_after:
                        # Format: 'May 15 12:00:00 2025 GMT'
                        try:
                            expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days_left = (expiry_dt - datetime.utcnow()).days
                            is_expired = days_left < 0
                        except Exception:
                            pass

                    return TLSCertInfo(
                        subject_cn=cn,
                        san_list=sans,
                        issuer=issuer_org,
                        valid_from=not_before,
                        valid_to=not_after,
                        is_expired=is_expired,
                        days_until_expiry=days_left
                    )
        except Exception:
            return None

    @classmethod
    async def analyze(cls, host: str, port: int = 80, timeout: float = 5.0) -> WebAnalysisResult:
        """Inspects HTTP service, headers, tech stack, and TLS."""
        protocol = "https" if port in (443, 8443, 9443) else "http"
        url = f"{protocol}://{host}:{port}" if port not in (80, 443) else f"{protocol}://{host}"

        result = WebAnalysisResult(url=url)

        # Retrieve TLS cert info if HTTPS
        if protocol == "https":
            result.tls_cert = cls.get_tls_info(host, port, timeout=timeout)

        try:
            async with httpx.AsyncClient(
                verify=False,
                timeout=timeout,
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VanguardRecon/1.0"}
            ) as client:
                response = await client.get(url)
                result.status_code = response.status_code
                headers = response.headers
                body_lower = response.text.lower() if response.text else ""

                # Extract Title
                import re
                title_match = re.search(r"<title>(.*?)</title>", response.text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    result.title = title_match.group(1).strip()[:100]

                # Server headers
                result.server = headers.get("server", "")
                result.powered_by = headers.get("x-powered-by", "")

                # Technology Heuristics
                techs = set()
                if result.server:
                    techs.add(result.server)
                if result.powered_by:
                    techs.add(result.powered_by)

                # Check headers & body fingerprints
                if "wp-content" in body_lower or "wordpress" in body_lower:
                    techs.add("WordPress")
                if "laravel" in body_lower or "laravel_session" in headers.get("set-cookie", ""):
                    techs.add("Laravel")
                if "django" in body_lower or "csrftoken" in headers.get("set-cookie", ""):
                    techs.add("Django")
                if "react" in body_lower or "react-root" in body_lower or "_next" in body_lower:
                    techs.add("React / Next.js")
                if "vue" in body_lower or "vuejs" in body_lower:
                    techs.add("Vue.js")
                if "express" in result.powered_by.lower():
                    techs.add("Express.js")
                if "php" in result.powered_by.lower() or ".php" in response.text:
                    techs.add("PHP")
                if "asp.net" in result.powered_by.lower() or "viewstate" in body_lower:
                    techs.add("ASP.NET")

                result.detected_tech = sorted(list(techs))

                # Audit Security Headers
                score_deductions = 0
                for header_name, meta in cls.RECOMMENDED_HEADERS.items():
                    val = headers.get(header_name)
                    if val:
                        result.security_headers.append(
                            HeaderAuditItem(
                                header=header_name,
                                present=True,
                                value=val,
                                status="PASS",
                                recommendation="Header is properly configured."
                            )
                        )
                    else:
                        weight = 20 if meta["severity"] == "HIGH" else (10 if meta["severity"] == "MEDIUM" else 5)
                        score_deductions += weight
                        result.security_headers.append(
                            HeaderAuditItem(
                                header=header_name,
                                present=False,
                                status="FAIL",
                                recommendation=meta["rec"]
                            )
                        )

                result.header_score = max(0, 100 - score_deductions)

        except Exception as e:
            result.error = str(e)

        return result
