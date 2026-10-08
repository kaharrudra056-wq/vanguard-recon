"""
Ethical Scope Enforcement & Target Validation Module.

Enforces penetration testing Rules of Engagement (RoE):
- Validates targets against forbidden cloud metadata endpoints (AWS/GCP/Azure IMDS)
- Detects RFC 1918 private / loopback IP spaces
- Resolves domain names to IP addresses
- Parses flexible port strings (e.g. '80,443,8000-8080')
"""

import ipaddress
import socket
import re
from typing import List, Tuple
from vanguard.config import CLOUD_METADATA_IPS


class ScopeViolationError(Exception):
    """Raised when a target violates ethical scanning guardrails."""
    pass


class ScopeManager:
    """Manages target validation and scope verification."""

    @staticmethod
    def is_cloud_metadata(target: str) -> bool:
        """Detects attempts to probe cloud instance metadata endpoints."""
        target_lower = target.strip().lower()
        if target_lower in [ip.lower() for ip in CLOUD_METADATA_IPS]:
            return True
        try:
            ip = ipaddress.ip_address(target)
            # Link-local address block 169.254.0.0/16
            if ip.is_link_local:
                return True
        except ValueError:
            pass
        return False

    @staticmethod
    def resolve_target(target: str) -> Tuple[str, str, bool]:
        """
        Resolves a hostname or IP address.
        Returns: (resolved_ip, hostname_or_ip, is_private)
        """
        target = target.strip()
        # Remove any protocol prefix if accidentally passed (e.g., http://)
        target = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]

        if not target:
            raise ScopeViolationError("Empty target supplied.")

        if ScopeManager.is_cloud_metadata(target):
            raise ScopeViolationError(
                f"Target '{target}' is a protected Cloud Metadata / Link-Local address. "
                "Scanning cloud IMDS endpoints is restricted for ethical safety."
            )

        try:
            # Check if it's already an IP
            ip_obj = ipaddress.ip_address(target)
            ip_str = str(ip_obj)
            is_private = ip_obj.is_private or ip_obj.is_loopback
            return ip_str, target, is_private
        except ValueError:
            # It's a hostname / domain
            try:
                ip_str = socket.gethostbyname(target)
                ip_obj = ipaddress.ip_address(ip_str)
                is_private = ip_obj.is_private or ip_obj.is_loopback
                if ScopeManager.is_cloud_metadata(ip_str):
                    raise ScopeViolationError(
                        f"Resolved IP {ip_str} for domain '{target}' points to a protected Cloud Metadata endpoint."
                    )
                return ip_str, target, is_private
            except socket.gaierror as e:
                raise ScopeViolationError(f"Failed to resolve target domain '{target}': {e}")

    @staticmethod
    def parse_ports(port_input: str) -> List[int]:
        """
        Parses comma-separated and hyphen-separated port specifications.
        Example: '22,80,443,8000-8005' -> [22, 80, 443, 8000, 8001, 8002, 8003, 8004, 8005]
        """
        ports = set()
        parts = [p.strip() for p in port_input.split(",") if p.strip()]

        for part in parts:
            if "-" in part:
                try:
                    start_str, end_str = part.split("-", 1)
                    start, end = int(start_str), int(end_str)
                    if start < 1 or end > 65535 or start > end:
                        raise ValueError()
                    ports.update(range(start, end + 1))
                except ValueError:
                    raise ValueError(f"Invalid port range format: '{part}'. Ports must be between 1 and 65535.")
            else:
                try:
                    port = int(part)
                    if port < 1 or port > 65535:
                        raise ValueError()
                    ports.add(port)
                except ValueError:
                    raise ValueError(f"Invalid port number: '{part}'. Ports must be between 1 and 65535.")

        return sorted(list(ports))
