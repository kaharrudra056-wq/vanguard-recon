"""
MITRE ATT&CK Framework Mapping Engine for VanguardRecon.

Maps detected attack surface assets, service openings, web vulnerabilities,
and exploited CVEs to standardized MITRE ATT&CK tactics, techniques, and IDs.
"""

from typing import List, Dict, Any
from pydantic import BaseModel


class MitreTechnique(BaseModel):
    tactic: str             # e.g., "Initial Access", "Reconnaissance", "Credential Access"
    technique_id: str       # e.g., "T1190"
    technique_name: str     # e.g., "Exploit Public-Facing Application"
    context: str            # e.g., "Matched via Apache 2.4.49 (CVE-2021-41773)"
    reference_url: str


class MitreAttackMapper:
    """Correlates vulnerabilities, open services, and misconfigurations with MITRE ATT&CK."""

    TACTIC_MAPPINGS = {
        # Remote Service Exploits
        "cve": MitreTechnique(
            tactic="Initial Access",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            context="Publicly reachable application with known exploitable CVE",
            reference_url="https://attack.mitre.org/techniques/T1190/"
        ),
        # Remote Administrative Access
        "ssh": MitreTechnique(
            tactic="Lateral Movement / Initial Access",
            technique_id="T1021.004",
            technique_name="Remote Services: SSH",
            context="Exposed SSH remote management interface (Port 22)",
            reference_url="https://attack.mitre.org/techniques/T1021/004/"
        ),
        "rdp": MitreTechnique(
            tactic="Lateral Movement / Initial Access",
            technique_id="T1021.001",
            technique_name="Remote Services: Remote Desktop Protocol",
            context="Exposed RDP remote management interface (Port 3389)",
            reference_url="https://attack.mitre.org/techniques/T1021/001/"
        ),
        "smb": MitreTechnique(
            tactic="Lateral Movement",
            technique_id="T1021.002",
            technique_name="Remote Services: SMB/Windows Admin Shares",
            context="Exposed SMB file sharing service (Port 445)",
            reference_url="https://attack.mitre.org/techniques/T1021/002/"
        ),
        # Credential / File Leaks
        "secret_leak": MitreTechnique(
            tactic="Credential Access",
            technique_id="T1552.001",
            technique_name="Unsecured Credentials: Credentials In Files",
            context="Exposed .env / .git repository leaking authentication secrets",
            reference_url="https://attack.mitre.org/techniques/T1552/001/"
        ),
        # Subdomain Takeover
        "subdomain_takeover": MitreTechnique(
            tactic="Resource Development",
            technique_id="T1584.001",
            technique_name="Compromise Infrastructure: Domains",
            context="Dangling DNS CNAME pointing to unclaimed cloud resource",
            reference_url="https://attack.mitre.org/techniques/T1584/001/"
        ),
        # Active Network Reconnaissance
        "recon": MitreTechnique(
            tactic="Reconnaissance",
            technique_id="T1595.001",
            technique_name="Active Scanning: Scanning IP Blocks",
            context="Network attack surface enumeration and open port discovery",
            reference_url="https://attack.mitre.org/techniques/T1595/001/"
        )
    }

    @classmethod
    def map_findings(
        cls,
        open_ports: List[Dict[str, Any]],
        vulns: List[Dict[str, Any]],
        sensitive_files: List[Dict[str, Any]] = None,
        subdomains: List[Dict[str, Any]] = None
    ) -> List[MitreTechnique]:
        """Consolidates all audit findings into mapped MITRE ATT&CK techniques."""
        techniques: Dict[str, MitreTechnique] = {}

        # 1. Base Active Scanning
        recon_tech = cls.TACTIC_MAPPINGS["recon"]
        techniques[recon_tech.technique_id] = recon_tech

        # 2. Port mappings
        for p in open_ports:
            port_num = p.get("port")
            service = p.get("service", "").lower()
            if port_num == 22 or "ssh" in service:
                t = cls.TACTIC_MAPPINGS["ssh"]
                techniques[t.technique_id] = t
            elif port_num == 3389 or "rdp" in service:
                t = cls.TACTIC_MAPPINGS["rdp"]
                techniques[t.technique_id] = t
            elif port_num == 445 or "smb" in service:
                t = cls.TACTIC_MAPPINGS["smb"]
                techniques[t.technique_id] = t

        # 3. CVE findings -> T1190
        if vulns:
            cve_tech = cls.TACTIC_MAPPINGS["cve"]
            # Enriched with actual count
            cve_copy = cve_tech.model_copy(update={"context": f"{len(vulns)} exploitable public-facing vulnerabilities detected"})
            techniques[cve_tech.technique_id] = cve_copy

        # 4. Sensitive files -> T1552.001
        if sensitive_files:
            crit_files = [f for f in sensitive_files if f.get("severity") in ("CRITICAL", "HIGH")]
            if crit_files:
                leak_tech = cls.TACTIC_MAPPINGS["secret_leak"]
                techniques[leak_tech.technique_id] = leak_tech

        # 5. Subdomain takeovers -> T1584.001
        if subdomains:
            vuln_subs = [s for s in subdomains if s.get("takeover_vulnerable")]
            if vuln_subs:
                takeover_tech = cls.TACTIC_MAPPINGS["subdomain_takeover"]
                techniques[takeover_tech.technique_id] = takeover_tech

        return list(techniques.values())
