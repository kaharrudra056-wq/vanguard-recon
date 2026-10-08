"""
Configuration settings, port definitions, and global profiles for VanguardRecon.
"""

from typing import List, Dict
from pydantic import BaseModel, Field, ConfigDict

# High-priority port profiles
PORT_PROFILES: Dict[str, List[int]] = {
    "top20": [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1723, 3306, 3389, 5900, 8080
    ],
    "top100": [
        20, 21, 22, 23, 25, 53, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139,
        143, 161, 162, 179, 389, 443, 445, 465, 500, 514, 515, 587, 636, 873,
        990, 993, 995, 1080, 1194, 1433, 1434, 1521, 1723, 2049, 2082, 2083,
        2086, 2087, 2181, 2222, 2375, 2376, 2483, 3000, 3128, 3306, 3389, 3690,
        4000, 4243, 4369, 4443, 4500, 5000, 5432, 5601, 5672, 5900, 5984, 6379,
        6443, 7001, 7077, 8000, 8008, 8080, 8081, 8443, 8500, 8888, 9000, 9042,
        9092, 9200, 9300, 9418, 9999, 10000, 11211, 15672, 27017, 27018, 28017,
        50000, 50070
    ],
    "web": [80, 81, 3000, 4443, 5000, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9443],
    "databases": [1433, 1521, 3306, 5432, 5984, 6379, 7000, 7001, 9042, 9200, 27017, 27018],
    "management": [22, 23, 3389, 5900, 5985, 5986]
}

DEFAULT_USER_AGENT = "VanguardRecon/1.0 (Security-Audit-Engine; +https://github.com/security-portfolio/vanguard)"

CLOUD_METADATA_IPS = [
    "169.254.169.254",            # AWS / GCP / Azure Instance Metadata Service (IMDS)
    "metadata.google.internal",   # GCP internal metadata host
    "100.100.100.200",            # Alibaba Cloud metadata
    "169.254.169.253"             # AWS DNS
]

class ScanConfig(BaseModel):
    """Runtime scan configuration with safe defaults."""
    model_config = ConfigDict(arbitrary_types_allowed=True)
    target: str
    ports: List[int] = Field(default_factory=lambda: PORT_PROFILES["top20"])
    timeout: float = Field(default=1.5, description="Socket connect timeout in seconds")
    concurrency: int = Field(default=50, description="Max concurrent async probe workers")
    rate_limit: int = Field(default=100, description="Max packets/probes per second")
    banner_grab: bool = True
    dns_enum: bool = False
    cve_correlation: bool = True
    allow_internal: bool = False
    output_format: str = "json"
    output_path: str = ""
