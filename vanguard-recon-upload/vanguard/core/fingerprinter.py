"""
Service & Banner Fingerprinting Engine.

Extracts normalized product names, exact versions, OS signatures, and CPEs
from raw banners and network responses.
"""

import re
from typing import Optional, Dict
from pydantic import BaseModel


class ServiceFingerprint(BaseModel):
    """Normalized fingerprint extracted from a port/banner."""
    service: str
    product: str = ""
    version: str = ""
    os: str = ""
    cpe: str = ""
    raw_banner: str = ""
    confidence: float = 0.5


class ServiceFingerprinter:
    """Heuristic rule-based banner analyzer."""

    # Regex patterns for common network service banners
    SIGNATURES = [
        # SSH: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
        {
            "name": "OpenSSH",
            "pattern": r"SSH-2\.0-OpenSSH_([0-9\.\_p]+)(?:\s+([A-Za-z0-9\.\_\-]+))?",
            "service": "ssh",
            "cpe_vendor": "openbsd",
            "cpe_product": "openssh"
        },
        # Dropbear SSH
        {
            "name": "Dropbear SSH",
            "pattern": r"SSH-2\.0-dropbear_([0-9\.]+)",
            "service": "ssh",
            "cpe_vendor": "matt_johnston",
            "cpe_product": "dropbear_ssh"
        },
        # Apache HTTP Server: Apache/2.4.49 (Unix)
        {
            "name": "Apache HTTP Server",
            "pattern": r"Apache\/([0-9\.]+)(?:\s*\((.*?)\))?",
            "service": "http",
            "cpe_vendor": "apache",
            "cpe_product": "http_server"
        },
        # Nginx: nginx/1.18.0
        {
            "name": "Nginx",
            "pattern": r"nginx\/([0-9\.]+)",
            "service": "http",
            "cpe_vendor": "f5",
            "cpe_product": "nginx"
        },
        # Microsoft IIS: Microsoft-IIS/10.0
        {
            "name": "Microsoft IIS",
            "pattern": r"Microsoft-IIS\/([0-9\.]+)",
            "service": "http",
            "cpe_vendor": "microsoft",
            "cpe_product": "internet_information_services"
        },
        # ProFTPD: 220 ProFTPD 1.3.5 Server
        {
            "name": "ProFTPD",
            "pattern": r"ProFTPD\s+([0-9\.\_a-zA-Z]+)",
            "service": "ftp",
            "cpe_vendor": "proftpd",
            "cpe_product": "proftpd"
        },
        # vsftpd: 220 (vsFTPd 3.0.3)
        {
            "name": "vsftpd",
            "pattern": r"vsFTPd\s+([0-9\.]+)",
            "service": "ftp",
            "cpe_vendor": "vsftpd_project",
            "cpe_product": "vsftpd"
        },
        # Pure-FTPd
        {
            "name": "Pure-FTPd",
            "pattern": r"Pure-FTPd\s*\[?([0-9\.]*)\]?",
            "service": "ftp",
            "cpe_vendor": "pureftpd",
            "cpe_product": "pure-ftpd"
        },
        # Redis: redis_version:6.2.6
        {
            "name": "Redis",
            "pattern": r"redis_version:([0-9\.]+)",
            "service": "redis",
            "cpe_vendor": "redis",
            "cpe_product": "redis"
        },
        # MySQL: 5.7.34-log or 8.0.28
        {
            "name": "MySQL",
            "pattern": r"(?:mysql|mariadb)?\s*([0-9]+\.[0-9]+\.[0-9]+)(?:-[a-zA-Z0-9_\.]+)?",
            "service": "mysql",
            "cpe_vendor": "oracle",
            "cpe_product": "mysql"
        },
        # Postfix: 220 mail.example.com ESMTP Postfix
        {
            "name": "Postfix",
            "pattern": r"ESMTP\s+Postfix(?:\s*\(([a-zA-Z0-9\.\_\-]+)\))?",
            "service": "smtp",
            "cpe_vendor": "postfix",
            "cpe_product": "postfix"
        },
        # Exim: 220 mail.example.com ESMTP Exim 4.94
        {
            "name": "Exim",
            "pattern": r"ESMTP\s+Exim\s+([0-9\.]+)",
            "service": "smtp",
            "cpe_vendor": "exim",
            "cpe_product": "exim"
        }
    ]

    @classmethod
    def fingerprint(cls, service_hint: str, banner: str) -> ServiceFingerprint:
        """Analyzes banner against known signature rules."""
        if not banner:
            return ServiceFingerprint(
                service=service_hint,
                raw_banner="",
                confidence=0.3
            )

        for sig in cls.SIGNATURES:
            match = re.search(sig["pattern"], banner, re.IGNORECASE)
            if match:
                version = match.group(1) if match.groups() else ""
                os_info = match.group(2) if len(match.groups()) > 1 and match.group(2) else ""
                cpe = f"cpe:2.3:a:{sig['cpe_vendor']}:{sig['cpe_product']}:{version}:*:*:*:*:*:*:*" if version else ""

                return ServiceFingerprint(
                    service=sig["service"],
                    product=sig["name"],
                    version=version,
                    os=os_info or "",
                    cpe=cpe,
                    raw_banner=banner,
                    confidence=0.95 if version else 0.8
                )

        # Fallback heuristic if no strict regex matched
        return ServiceFingerprint(
            service=service_hint,
            product=service_hint.capitalize() if service_hint != "unknown" else "Unknown Service",
            version="",
            raw_banner=banner,
            confidence=0.4
        )
