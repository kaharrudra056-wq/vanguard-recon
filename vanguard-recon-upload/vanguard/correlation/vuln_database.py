"""
Enriched Vulnerability Knowledge Base (CVE, CISA KEV, Exploit-DB, and CVSS).

Provides structured records of verified high-impact vulnerabilities for common
network daemons, web servers, databases, and enterprise services.
"""

from typing import List, Dict, Any

VULN_KNOWLEDGE_BASE: List[Dict[str, Any]] = [
    # --- OpenSSH ---
    {
        "cve_id": "CVE-2024-6387",
        "title": "OpenSSH regreSSHion - Remote Unauthenticated Code Execution",
        "product": "OpenSSH",
        "affected_versions": ["8.5p1", "8.6p1", "8.7p1", "8.8p1", "8.9p1", "9.0p1", "9.1p1", "9.2p1", "9.3p1", "9.4p1", "9.5p1", "9.6p1", "9.7p1"],
        "min_version": "8.5p1",
        "max_version": "9.7p1",
        "cvss": 8.1,
        "severity": "HIGH",
        "cisa_kev": True,
        "epss": 0.92,
        "exploit_available": True,
        "exploit_ref": "EDB-52059",
        "description": "Signal handler race condition in OpenSSH server (sshd) allows unauthenticated remote code execution as root on glibc-based Linux systems.",
        "remediation": "Upgrade OpenSSH to version 9.8p1 or newer immediately, or set 'LoginGraceTime 0' as temporary workaround."
    },
    {
        "cve_id": "CVE-2023-38408",
        "title": "OpenSSH PKCS#11 Provider Remote Code Execution",
        "product": "OpenSSH",
        "affected_versions": ["5.5p1", "6.0p1", "7.0p1", "8.0p1", "9.0p1", "9.1p1", "9.2p1", "9.3p1"],
        "min_version": "5.5p1",
        "max_version": "9.3p1",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "cisa_kev": True,
        "epss": 0.88,
        "exploit_available": True,
        "exploit_ref": "https://www.qualys.com/2023/07/19/cve-2023-38408/rce-openssh-forwarded-ssh-agent.txt",
        "description": "Remote code execution in ssh-agent via PKCS#11 provider libraries when SSH agent forwarding is enabled.",
        "remediation": "Upgrade OpenSSH to version 9.3p2 or newer. Disable SSH Agent forwarding when connecting to untrusted hosts."
    },
    {
        "cve_id": "CVE-2021-41617",
        "title": "OpenSSH Privilege Escalation via Supplementary Groups",
        "product": "OpenSSH",
        "affected_versions": ["6.2p1", "7.0p1", "8.0p1", "8.2p1", "8.4p1", "8.6p1", "8.7p1"],
        "min_version": "6.2p1",
        "max_version": "8.7p1",
        "cvss": 7.0,
        "severity": "HIGH",
        "cisa_kev": False,
        "epss": 0.05,
        "exploit_available": False,
        "exploit_ref": "",
        "description": "OpenSSH failed to properly initialize supplementary groups when executing AuthorizedKeysCommand or AuthorizedPrincipalsCommand.",
        "remediation": "Upgrade OpenSSH to version 8.8p1 or higher."
    },
    {
        "cve_id": "CVE-2018-15473",
        "title": "OpenSSH User Enumeration Vulnerability",
        "product": "OpenSSH",
        "affected_versions": ["7.2p1", "7.3p1", "7.4p1", "7.5p1", "7.6p1", "7.7p1"],
        "min_version": "5.0p1",
        "max_version": "7.7p1",
        "cvss": 5.3,
        "severity": "MEDIUM",
        "cisa_kev": True,
        "epss": 0.74,
        "exploit_available": True,
        "exploit_ref": "EDB-45233",
        "description": "OpenSSH is prone to a user enumeration vulnerability due not properly handling authentication requests for nonexistent users.",
        "remediation": "Upgrade OpenSSH to 7.8p1 or newer."
    },

    # --- Apache HTTP Server ---
    {
        "cve_id": "CVE-2021-41773",
        "title": "Apache HTTP Server Path Traversal & Remote Code Execution",
        "product": "Apache HTTP Server",
        "affected_versions": ["2.4.49"],
        "min_version": "2.4.49",
        "max_version": "2.4.49",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "cisa_kev": True,
        "epss": 0.97,
        "exploit_available": True,
        "exploit_ref": "EDB-50383",
        "description": "Flaw in path normalization in Apache 2.4.49 allows unauthenticated remote attackers to map URLs to files outside the document root (Path Traversal) and execute CGI scripts.",
        "remediation": "Immediately upgrade Apache HTTP Server to version 2.4.51 or higher."
    },
    {
        "cve_id": "CVE-2021-42013",
        "title": "Apache HTTP Server Path Traversal & RCE (Incomplete Fix for CVE-2021-41773)",
        "product": "Apache HTTP Server",
        "affected_versions": ["2.4.49", "2.4.50"],
        "min_version": "2.4.49",
        "max_version": "2.4.50",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "cisa_kev": True,
        "epss": 0.96,
        "exploit_available": True,
        "exploit_ref": "EDB-50406",
        "description": "Incomplete fix for CVE-2021-41773 allows path traversal and remote code execution via double-encoded dot segments (%%32%65).",
        "remediation": "Upgrade Apache HTTP Server to version 2.4.51 or newer."
    },
    {
        "cve_id": "CVE-2019-0211",
        "title": "Apache HTTP Server CARPE (DIEM) Root Privilege Escalation",
        "product": "Apache HTTP Server",
        "affected_versions": ["2.4.17", "2.4.20", "2.4.25", "2.4.30", "2.4.34", "2.4.37", "2.4.38"],
        "min_version": "2.4.17",
        "max_version": "2.4.38",
        "cvss": 8.8,
        "severity": "HIGH",
        "cisa_kev": False,
        "epss": 0.42,
        "exploit_available": True,
        "exploit_ref": "EDB-46676",
        "description": "Scoreboard manipulation vulnerability allows local worker processes (e.g. www-data running PHP) to gain root privileges via graceful restart.",
        "remediation": "Upgrade Apache HTTP Server to version 2.4.39 or newer."
    },

    # --- Nginx ---
    {
        "cve_id": "CVE-2021-23017",
        "title": "Nginx DNS Resolver 1-Byte Memory Overwrite RCE",
        "product": "Nginx",
        "affected_versions": ["0.6.18", "1.18.0", "1.19.0", "1.20.0"],
        "min_version": "0.6.18",
        "max_version": "1.20.0",
        "cvss": 7.7,
        "severity": "HIGH",
        "cisa_kev": False,
        "epss": 0.35,
        "exploit_available": True,
        "exploit_ref": "https://github.com/vulhub/vulhub/tree/master/nginx/CVE-2021-23017",
        "description": "1-byte memory overwrite flaw in the DNS resolver module of Nginx allows remote attackers to cause worker crash or execute arbitrary code.",
        "remediation": "Upgrade Nginx to version 1.20.1, 1.21.0 or newer."
    },
    {
        "cve_id": "CVE-2017-7529",
        "title": "Nginx Range Filter Integer Overflow Information Disclosure",
        "product": "Nginx",
        "affected_versions": ["0.5.6", "1.12.0", "1.13.0", "1.13.2"],
        "min_version": "0.5.6",
        "max_version": "1.13.2",
        "cvss": 7.5,
        "severity": "HIGH",
        "cisa_kev": True,
        "epss": 0.81,
        "exploit_available": True,
        "exploit_ref": "EDB-42354",
        "description": "Integer overflow in the standard range filter module of Nginx results in sensitive cache information disclosure.",
        "remediation": "Upgrade Nginx to 1.13.3 or 1.12.1."
    },

    # --- ProFTPD ---
    {
        "cve_id": "CVE-2015-3306",
        "title": "ProFTPD mod_copy Unauthenticated Remote File Copy / RCE",
        "product": "ProFTPD",
        "affected_versions": ["1.3.5"],
        "min_version": "1.3.5",
        "max_version": "1.3.5",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "cisa_kev": True,
        "epss": 0.98,
        "exploit_available": True,
        "exploit_ref": "EDB-36742",
        "description": "mod_copy in ProFTPD 1.3.5 allows remote attackers to read and write arbitrary files on the server via SITE CPFR and SITE CPTO commands without authentication.",
        "remediation": "Upgrade ProFTPD to 1.3.5a or disable mod_copy in proftpd.conf."
    },

    # --- vsftpd ---
    {
        "cve_id": "CVE-2011-2523",
        "title": "vsftpd 2.3.4 Backdoor Command Execution",
        "product": "vsftpd",
        "affected_versions": ["2.3.4"],
        "min_version": "2.3.4",
        "max_version": "2.3.4",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "cisa_kev": True,
        "epss": 0.96,
        "exploit_available": True,
        "exploit_ref": "EDB-17491",
        "description": "Malicious backdoor inserted into vsftpd-2.3.4.tar.gz opens an interactive root shell on port 6200 when a username containing ':)' is supplied.",
        "remediation": "Replace compromised binary with official verified vsftpd 3.0.3 release immediately."
    },

    # --- Redis ---
    {
        "cve_id": "CVE-2022-0543",
        "title": "Redis Lua Sandbox Escape Remote Code Execution",
        "product": "Redis",
        "affected_versions": ["5.0.0", "5.0.14", "6.0.0", "6.0.15", "6.2.0", "6.2.6"],
        "min_version": "5.0.0",
        "max_version": "6.2.6",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "cisa_kev": True,
        "epss": 0.97,
        "exploit_available": True,
        "exploit_ref": "https://github.com/vulhub/vulhub/tree/master/redis/CVE-2022-0543",
        "description": "Packaging issue in Debian/Ubuntu packages allows remote attackers to escape the Lua sandbox via loadlib and execute arbitrary commands on the underlying host.",
        "remediation": "Upgrade Redis and debian packages, bind Redis to localhost only, and set strong requirepass."
    },

    # --- MySQL ---
    {
        "cve_id": "CVE-2016-6662",
        "title": "MySQL Remote Root Code Execution / Privilege Escalation",
        "product": "MySQL",
        "affected_versions": ["5.5.0", "5.5.51", "5.6.0", "5.6.32", "5.7.0", "5.7.14"],
        "min_version": "5.5.0",
        "max_version": "5.7.14",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "cisa_kev": True,
        "epss": 0.89,
        "exploit_available": True,
        "exploit_ref": "EDB-40360",
        "description": "Vulnerability in my.cnf parsing allows attackers with SELECT privileges or SQL injection to execute arbitrary code as root during mysqld restarts.",
        "remediation": "Upgrade MySQL to 5.7.15, 5.6.33, or 5.5.52."
    }
]
