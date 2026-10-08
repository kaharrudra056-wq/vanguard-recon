"""
JSON Report Exporter for SIEM and Automation Pipeline Ingestion.
"""

import json
from typing import Dict, Any


class JSONReporter:
    """Exports structured scan data into formatted JSON."""

    @staticmethod
    def generate(scan_data: Dict[str, Any], filepath: str = "") -> str:
        """Serializes scan data to JSON string or writes to disk if path given."""
        json_output = json.dumps(scan_data, indent=2, default=str)
        if filepath:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(json_output)
        return json_output
