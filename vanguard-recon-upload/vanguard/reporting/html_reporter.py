"""
Publication-Quality HTML Penetration Testing Report Generator.

Creates comprehensive, standalone security deliverables featuring executive summaries,
risk scoring meters, CVSS breakdown tables, and remediation roadmaps.
"""

from typing import Dict, Any
from jinja2 import Template


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vanguard Security Audit Report - {{ target }}</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #111827;
      --border: #1f2937;
      --text-main: #f3f4f6;
      --text-muted: #9ca3af;
      --accent: #3b82f6;
      --crit: #ef4444;
      --high: #f97316;
      --med: #eab308;
      --low: #3b82f6;
      --pass: #10b981;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
    body { background: var(--bg); color: var(--text-main); line-height: 1.5; padding: 40px 20px; }
    .container { max-width: 1100px; margin: 0 auto; }
    
    /* Header */
    .header { border-bottom: 2px solid var(--border); padding-bottom: 24px; margin-bottom: 32px; display: flex; justify-content: space-between; align-items: flex-end; }
    .title-group h1 { font-size: 28px; font-weight: 800; color: #fff; letter-spacing: -0.5px; }
    .title-group p { color: var(--text-muted); font-size: 14px; margin-top: 4px; }
    .badge { display: inline-block; padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: 700; text-transform: uppercase; }
    .badge-crit { background: rgba(239, 68, 68, 0.2); color: var(--crit); border: 1px solid var(--crit); }
    .badge-high { background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }
    .badge-med { background: rgba(234, 179, 8, 0.2); color: var(--med); border: 1px solid var(--med); }
    .badge-low { background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }

    /* Summary Metrics Grid */
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 32px; }
    .stat-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 20px; }
    .stat-card .label { color: var(--text-muted); font-size: 13px; font-weight: 500; }
    .stat-card .val { font-size: 32px; font-weight: 800; margin-top: 6px; }
    
    /* Sections */
    .section { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-bottom: 24px; }
    .section-title { font-size: 18px; font-weight: 700; color: #fff; margin-bottom: 16px; display: flex; align-items: center; justify-content: space-between; }
    
    /* Tables */
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th { text-align: left; padding: 12px; color: var(--text-muted); font-size: 12px; text-transform: uppercase; border-bottom: 1px solid var(--border); }
    td { padding: 12px; border-bottom: 1px solid rgba(255,255,255,0.05); }
    tr:last-child td { border-bottom: none; }
    
    .cve-id { font-family: monospace; font-weight: 700; color: var(--accent); }
    .pill { display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; }
    .pill-cisa { background: #dc2626; color: #fff; }
    .pill-exp { background: #8b5cf6; color: #fff; }
    
    /* Code block */
    .code-box { background: #000; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 13px; color: #10b981; overflow-x: auto; margin-top: 8px; }
    
    /* Print Styles */
    @media print {
      body { background: #fff; color: #000; padding: 0; }
      .section, .stat-card { background: #fff; border: 1px solid #ccc; color: #000; }
      .title-group h1, .section-title { color: #000; }
      th { color: #555; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="title-group">
        <h1>Vanguard Security Assessment Report</h1>
        <p>Target: <strong>{{ target }}</strong> | Scanned at: {{ timestamp }}</p>
      </div>
      <div>
        <span class="badge badge-{{ risk.severity_label.lower() }}">Risk Level: {{ risk.severity_label }} ({{ risk.overall_score }}/100)</span>
      </div>
    </div>

    <!-- Quick Stats -->
    <div class="stats-grid">
      <div class="stat-card">
        <div class="label">Target IP Address</div>
        <div class="val" style="font-size: 22px; font-family: monospace;">{{ target_ip }}</div>
      </div>
      <div class="stat-card">
        <div class="label">Open Ports Discovered</div>
        <div class="val">{{ open_ports|length }}</div>
      </div>
      <div class="stat-card">
        <div class="label">Correlated CVEs</div>
        <div class="val" style="color: {% if vulns|length > 0 %}var(--crit){% else %}var(--pass){% endif %};">{{ vulns|length }}</div>
      </div>
      <div class="stat-card">
        <div class="label">CISA KEV Wild Exploits</div>
        <div class="val" style="color: {% if risk.cisa_kev_active %}var(--crit){% else %}var(--pass){% endif %};">
          {{ "ACTIVE" if risk.cisa_kev_active else "None" }}
        </div>
      </div>
    </div>

    <!-- High Risk Vulnerability Findings -->
    <div class="section">
      <div class="section-title">
        <span>Identified CVEs & Weaponized Exploits</span>
        <span style="font-size: 13px; color: var(--text-muted);">{{ vulns|length }} total findings</span>
      </div>
      {% if vulns %}
      <table>
        <thead>
          <tr>
            <th>CVE / Identifier</th>
            <th>Severity</th>
            <th>Service / Port</th>
            <th>Weaponization</th>
            <th>Description & Remediation</th>
          </tr>
        </thead>
        <tbody>
          {% for v in vulns %}
          <tr>
            <td>
              <span class="cve-id">{{ v.cve_id }}</span><br>
              <small style="color: var(--text-muted);">{{ v.product }} v{{ v.detected_version }}</small>
            </td>
            <td>
              <span class="badge badge-{{ v.severity.lower() }}">{{ v.severity }} {{ v.cvss }}</span>
            </td>
            <td>Port {{ v.port }} ({{ v.service }})</td>
            <td>
              {% if v.cisa_kev %}<span class="pill pill-cisa">CISA KEV</span>{% endif %}
              {% if v.exploit_available %}<span class="pill pill-exp">PoC Exploit</span>{% endif %}
              {% if not v.cisa_kev and not v.exploit_available %}<span style="color: var(--text-muted);">Theoretical</span>{% endif %}
            </td>
            <td>
              <strong>{{ v.title }}</strong>
              <p style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">{{ v.description }}</p>
              <div class="code-box">Fix: {{ v.remediation }}</div>
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
      <p style="color: var(--pass);">No known CVE signatures identified in tested services.</p>
      {% endif %}
    </div>

    <!-- Attack Surface & Open Ports -->
    <div class="section">
      <div class="section-title">Open Ports & Service Fingerprints</div>
      <table>
        <thead>
          <tr>
            <th>Port</th>
            <th>Protocol</th>
            <th>Detected Service</th>
            <th>Banner & Version Details</th>
            <th>Latency</th>
          </tr>
        </thead>
        <tbody>
          {% for p in open_ports %}
          <tr>
            <td><strong>{{ p.port }}</strong></td>
            <td>TCP</td>
            <td><span style="text-transform: uppercase; font-size: 12px; font-weight: 700;">{{ p.service }}</span></td>
            <td>
              {% if p.banner %}
              <code style="font-size: 12px; color: var(--text-muted);">{{ p.banner }}</code>
              {% else %}
              <span style="color: var(--text-muted);">[No banner received]</span>
              {% endif %}
            </td>
            <td>{{ p.latency_ms }} ms</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>

    <!-- Web Security Posture (if audited) -->
    {% if web_audit %}
    <div class="section">
      <div class="section-title">
        <span>Web Application Security Audit</span>
        <span class="badge" style="background: rgba(59,130,246,0.2); color: var(--accent);">Score: {{ web_audit.header_score }}/100</span>
      </div>
      <p style="margin-bottom: 12px; font-size: 14px; color: var(--text-muted);">
        Audited Endpoint: <code>{{ web_audit.url }}</code> | Technologies: <strong>{{ web_audit.detected_tech|join(', ') if web_audit.detected_tech else 'Standard HTTP' }}</strong>
      </p>
      <table>
        <thead>
          <tr>
            <th>Security Header</th>
            <th>Status</th>
            <th>Finding & Guidance</th>
          </tr>
        </thead>
        <tbody>
          {% for h in web_audit.security_headers %}
          <tr>
            <td><code>{{ h.header }}</code></td>
            <td>
              <span class="badge badge-{% if h.status == 'PASS' %}pass{% else %}high{% endif %}">{{ h.status }}</span>
            </td>
            <td>
              {% if h.present %}
              <code style="font-size: 12px; color: #10b981;">{{ h.value }}</code>
              {% else %}
              <span style="color: var(--text-muted); font-size: 13px;">{{ h.recommendation }}</span>
              {% endif %}
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% endif %}

    <!-- Discovered Subdomains (if audited) -->
    {% if subdomains %}
    <div class="section">
      <div class="section-title">Discovered Subdomains & DNS Takeover Checks</div>
      <table>
        <thead>
          <tr>
            <th>Subdomain</th>
            <th>CNAME Target</th>
            <th>IP Address(es)</th>
            <th>Takeover Risk</th>
          </tr>
        </thead>
        <tbody>
          {% for sub in subdomains %}
          <tr>
            <td><strong>{{ sub.subdomain }}</strong></td>
            <td>{{ sub.cname if sub.cname else '-' }}</td>
            <td>{{ sub.ip_addresses|join(', ') if sub.ip_addresses else 'Unresolved' }}</td>
            <td>
              {% if sub.takeover_vulnerable %}
              <span class="badge badge-crit">TAKEOVER: {{ sub.takeover_provider }}</span>
              {% else %}
              <span class="badge badge-pass">SECURE</span>
              {% endif %}
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% endif %}

    <!-- Exposed Sensitive Files / Leaks (if detected) -->
    {% if sensitive_files %}
    <div class="section">
      <div class="section-title">
        <span>Exposed Sensitive Files & Information Disclosures</span>
        <span class="badge badge-crit">{{ sensitive_files|length }} Leaks Detected</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Path</th>
            <th>Category</th>
            <th>Severity</th>
            <th>Evidence Snippet</th>
            <th>Remediation</th>
          </tr>
        </thead>
        <tbody>
          {% for sf in sensitive_files %}
          <tr>
            <td><code style="color: var(--crit); font-weight: 700;">{{ sf.path }}</code></td>
            <td>{{ sf.category }}</td>
            <td><span class="badge badge-{{ sf.severity.lower() }}">{{ sf.severity }}</span></td>
            <td><code style="font-size: 11px; color: var(--text-muted);">{{ sf.evidence }}</code></td>
            <td>{{ sf.remediation }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% endif %}

    <!-- MITRE ATT&CK Matrix Alignment -->
    {% if mitre_techniques %}
    <div class="section">
      <div class="section-title">
        <span>MITRE ATT&CK Framework Mapping</span>
        <span style="font-size: 12px; color: var(--text-muted);">Adversary TTP Alignment</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Tactic</th>
            <th>Technique ID</th>
            <th>Technique Name</th>
            <th>Detected Audit Context</th>
          </tr>
        </thead>
        <tbody>
          {% for m in mitre_techniques %}
          <tr>
            <td><strong style="color: var(--accent);">{{ m.tactic }}</strong></td>
            <td><a href="{{ m.reference_url }}" target="_blank" style="color: #60a5fa; font-family: monospace; text-decoration: none;">{{ m.technique_id }}</a></td>
            <td><strong>{{ m.technique_name }}</strong></td>
            <td><span style="color: var(--text-muted); font-size: 13px;">{{ m.context }}</span></td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% endif %}

    <!-- Regulatory Compliance Matrix -->
    <div class="section">
      <div class="section-title">Regulatory Compliance & Governance Impact</div>
      <table>
        <thead>
          <tr>
            <th>Standard / Framework</th>
            <th>Control Reference</th>
            <th>Compliance Status</th>
            <th>Audit Assessment</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>PCI-DSS v4.0</strong></td>
            <td>Req 6.3.3 & 11.3.1</td>
            <td>
              {% if risk.critical_count|default(0) > 0 %}
              <span class="badge badge-crit">NON-COMPLIANT</span>
              {% else %}
              <span class="badge badge-pass">COMPLIANT</span>
              {% endif %}
            </td>
            <td>Known exploitable vulnerabilities on internet-facing systems require immediate patch cycles within 30 days.</td>
          </tr>
          <tr>
            <td><strong>ISO/IEC 27001:2022</strong></td>
            <td>Control A.8.8 (Mgmt of Tech Vulns)</td>
            <td>
              {% if risk.overall_score|default(0) > 60 %}
              <span class="badge badge-high">REQUIRES ACTION</span>
              {% else %}
              <span class="badge badge-pass">SATISFIED</span>
              {% endif %}
            </td>
            <td>Asset exposure and service patch lifecycle must be reviewed according to information security policy.</td>
          </tr>
          <tr>
            <td><strong>SOC 2 Type II</strong></td>
            <td>CC6.6 & CC7.1</td>
            <td>
              {% if risk.cisa_kev_active|default(false) %}
              <span class="badge badge-crit">AT RISK</span>
              {% else %}
              <span class="badge badge-pass">SATISFIED</span>
              {% endif %}
            </td>
            <td>Network perimeter defense controls must detect and mitigate unauthorized services and known threat vectors.</td>
          </tr>
        </tbody>
      </table>
    </div>

  </div>
</body>
</html>
"""


class HTMLReporter:
    """Renders standalone HTML penetration testing report."""

    @staticmethod
    def generate(scan_data: Dict[str, Any], filepath: str = "") -> str:
        """Fills Jinja2 template and writes to disk if path given."""
        template = Template(HTML_TEMPLATE)
        rendered_html = template.render(**scan_data)
        if filepath:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(rendered_html)
        return rendered_html
