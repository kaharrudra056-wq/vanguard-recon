"""
Subdomain Discovery & Subdomain Takeover Vulnerability Detector.

Features:
- Passive Subdomain Enumeration via crt.sh Certificate Transparency logs
- Asynchronous DNS A & CNAME record resolution via dnspython
- Dangling DNS / Subdomain Takeover fingerprint detection (AWS S3, GitHub Pages, Heroku, Azure, Shopify)
"""

import asyncio
from typing import List, Dict, Optional
import dns.asyncresolver
import dns.resolver
import httpx
from pydantic import BaseModel, Field


class SubdomainRecord(BaseModel):
    subdomain: str
    ip_addresses: List[str] = Field(default_factory=list)
    cname: Optional[str] = None
    takeover_vulnerable: bool = False
    takeover_provider: str = ""
    takeover_evidence: str = ""


# Signatures for dangling CNAME takeover candidates
TAKEOVER_SIGNATURES = [
    {
        "provider": "GitHub Pages",
        "cname_suffix": ".github.io",
        "fingerprint": "There isn't a GitHub Pages site here"
    },
    {
        "provider": "AWS S3 Bucket",
        "cname_suffix": ".s3.amazonaws.com",
        "fingerprint": "NoSuchBucket"
    },
    {
        "provider": "Heroku",
        "cname_suffix": ".herokudns.com",
        "fingerprint": "No such app"
    },
    {
        "provider": "Heroku",
        "cname_suffix": ".herokuapp.com",
        "fingerprint": "No such app"
    },
    {
        "provider": "Microsoft Azure",
        "cname_suffix": ".azurewebsites.net",
        "fingerprint": "404 Web Site not found"
    },
    {
        "provider": "Shopify",
        "cname_suffix": ".myshopify.com",
        "fingerprint": "Sorry, this shop is currently unavailable"
    },
    {
        "provider": "Bitbucket",
        "cname_suffix": ".bitbucket.io",
        "fingerprint": "Repository not found"
    }
]


class DNSEnumerator:
    """Asynchronous subdomain discovery and takeover scanner."""

    def __init__(self, domain: str, timeout: float = 3.0):
        self.domain = domain.strip().lower()
        self.timeout = timeout
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    async def fetch_crtsh_subdomains(self) -> List[str]:
        """Queries crt.sh Certificate Transparency logs for passive subdomains."""
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        subdomains = set()

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data:
                        name_value = item.get("name_value", "")
                        for line in name_value.split("\n"):
                            clean_sub = line.strip().lower()
                            if clean_sub.endswith(self.domain) and "*" not in clean_sub:
                                subdomains.add(clean_sub)
        except Exception:
            # Fallback to apex domain if crt.sh is slow or throttled
            subdomains.add(self.domain)

        return sorted(list(subdomains))

    async def resolve_subdomain(self, subdomain: str) -> SubdomainRecord:
        """Resolves A and CNAME records, then evaluates takeover risks."""
        record = SubdomainRecord(subdomain=subdomain)

        # 1. Resolve CNAME
        try:
            cname_answers = await self.resolver.resolve(subdomain, "CNAME")
            for rdata in cname_answers:
                record.cname = str(rdata.target).rstrip(".")
                break
        except Exception:
            record.cname = None

        # 2. Resolve A records
        try:
            a_answers = await self.resolver.resolve(subdomain, "A")
            for rdata in a_answers:
                record.ip_addresses.append(str(rdata))
        except Exception:
            pass

        # 3. Check for Subdomain Takeover if CNAME matches a vulnerable provider
        if record.cname:
            for sig in TAKEOVER_SIGNATURES:
                if record.cname.endswith(sig["cname_suffix"]):
                    # If CNAME exists but no A record resolved, or check HTTP body
                    is_vuln, evidence = await self._verify_takeover(subdomain, sig["fingerprint"])
                    if is_vuln:
                        record.takeover_vulnerable = True
                        record.takeover_provider = sig["provider"]
                        record.takeover_evidence = evidence
                    break

        return record

    async def _verify_takeover(self, subdomain: str, fingerprint: str) -> tuple[bool, str]:
        """Probes HTTP endpoint to verify dangling service fingerprint."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=3.0) as client:
                resp = await client.get(f"http://{subdomain}")
                if fingerprint.lower() in resp.text.lower():
                    return True, f"Matched HTTP fingerprint: '{fingerprint}'"
        except Exception:
            pass
        return False, ""

    async def run(self, max_subdomains: int = 50) -> List[SubdomainRecord]:
        """Discovers subdomains and inspects DNS records concurrently."""
        discovered = await self.fetch_crtsh_subdomains()
        if not discovered:
            discovered = [self.domain]

        # Limit to avoid overloading during scans
        targets = discovered[:max_subdomains]
        tasks = [self.resolve_subdomain(sub) for sub in targets]
        results = await asyncio.gather(*tasks)

        # Sort so vulnerable ones appear first, then resolved ones
        results.sort(key=lambda r: (not r.takeover_vulnerable, len(r.ip_addresses) == 0))
        return results
