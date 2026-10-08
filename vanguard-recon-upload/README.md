# 🛡️ VanguardRecon
### Next-Gen Attack Surface Discovery & Automated CVE Intelligence Framework

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests: Pytest](https://img.shields.io/badge/Tests-Passing-brightgreen.svg)](https://docs.pytest.org/)
[![FastAPI](https://img.shields.io/badge/Dashboard-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)

---

## 🌟 Executive Summary

**VanguardRecon** is an asynchronous attack surface mapping and vulnerability correlation framework designed for Red Team operators, penetration testers, and security automation engineers. 

Unlike basic port scanners that stop at socket connectivity, **VanguardRecon** automates the entire Phase 1 (Reconnaissance) and Phase 2 (Vulnerability Analysis) lifecycle of the **Penetration Testing Execution Standard (PTES)**:
1. **High-Concurrency Async Network Discovery**: Bounded `asyncio` non-blocking socket multiplexing with banner grabbing.
2. **Service & Protocol Fingerprinting**: Heuristic banner parsing and Common Platform Enumeration (CPE) extraction.
3. **Automated Threat Intelligence Correlation**: Maps detected services and versions against enriched vulnerability datasets, **CISA Known Exploited Vulnerabilities (KEV)**, **Exploit-DB** proof-of-concept references, and **CVSS v3.1 / EPSS** risk scores.
4. **Web Security & Attack Surface Auditing**: Fast async HTTP/HTTPS inspection, OWASP security headers grading, technology stack detection, and TLS certificate extraction.
5. **Subdomain Discovery & Takeover Detection**: Passive Certificate Transparency (`crt.sh`) logging and dangling CNAME takeover identification (AWS S3, GitHub Pages, Heroku, Azure).
6. **Dual-Interface Presentation**:
   - **Rich Interactive CLI**: Animated progress bars, colored risk matrices, and styled tables.
   - **Modern Web Dashboard**: Real-time audit launcher, vulnerability explorer, and one-click exportable HTML pentest reports.

---

## 🏗️ System Architecture

```mermaid
flowchart TD
    Target[Target Domain / IP] --> ScopeMgr[Ethical Scope & Guardrails Engine]
    ScopeMgr -->|IMDS / Out-of-Scope Filter| Blocked[Blocked / Safety Exception]
    ScopeMgr -->|Validated In-Scope| AsyncScanner[Async Port Scanner (asyncio / Semaphore)]

    AsyncScanner -->|Open Ports & Banners| Fingerprinter[Service & CPE Fingerprinter]
    AsyncScanner -->|HTTP / HTTPS Ports| WebAnalyzer[Web Security & Header Auditor]
    Target -->|Domain Targets| DNSEnum[DNS & Subdomain Takeover Engine]

    Fingerprinter --> CVECorrelator[CVE & Threat Intelligence Engine]
    CVECorrelator --> KEV[CISA KEV & Exploit-DB Catalog]
    CVECorrelator --> Scorer[CVSS v3.1 & EPSS Risk Posture Evaluator]

    Scorer --> Aggregator[Consolidated Audit Findings]
    WebAnalyzer --> Aggregator
    DNSEnum --> Aggregator

    Aggregator --> OutputCLI[Rich Interactive CLI]
    Aggregator --> OutputAPI[FastAPI & Glassmorphism Web UI]
    Aggregator --> OutputReport[Executive HTML & JSON Pentest Deliverables]
```

---

## 🚀 Key Features & Differentiators

| Feature | VanguardRecon | Traditional Port Scanners |
| :--- | :--- | :--- |
| **Concurrency Model** | Non-blocking `asyncio` multiplexing | Sequential threads / heavy process spawning |
| **CVE Correlation** | **Automated** version matching to CVE & CISA KEV | None (Requires manual research) |
| **Weaponization Intel** | Flags active wild exploitation (KEV) & PoCs | None |
| **Web Security Auditing** | OWASP Secure Headers + Tech Stack detection | Requires separate tool |
| **Subdomain Takeover** | Dangling CNAME inspection (S3, GitHub, Azure) | Requires separate tool |
| **Ethical Guardrails** | Blocks IMDS (`169.254.169.254`) & scope checking | Raw socket binding without safeguards |
| **Reporting** | Standalone publication-ready HTML + JSON | Raw terminal stdout |
| **Web UI** | Embedded zero-setup dark-mode dashboard | CLI only |

---

## 🛠️ Quickstart Installation & Usage

### 1. Installation

Ensure Python 3.10+ is installed:

```bash
# Clone or navigate to the project directory
git clone https://github.com/your-username/vanguard-recon.git
cd vanguard-recon

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.\.venv\Scripts\Activate.ps1
# Linux / macOS:
# source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Command-Line Interface (CLI)

#### Rapid Scan with Top Ports & Web Audit
```bash
python -m vanguard scan scanme.nmap.org -p top20 --web
```

#### Custom Port Range with Standalone HTML Pentest Deliverable
```bash
python -m vanguard scan 127.0.0.1 -p "22,80,443,8000-8080" --html reports/audit.html -o reports/audit.json
```

#### High-Speed Concurrency Scan
```bash
python -m vanguard scan 192.168.1.1 -p top100 --concurrency 100 --timeout 1.0
```

---

### 3. Interactive Web Dashboard

Launch the embedded web server and dashboard:

```bash
python -m vanguard serve --host 127.0.0.1 --port 8000
```
Open your browser at **`http://127.0.0.1:8000`** to access the real-time vulnerability auditor and generate instant PDF/HTML pentest deliverables.

---

### 4. Docker Deployment

Run VanguardRecon in an isolated container with zero system footprint:

```bash
# Build and run with Docker Compose
docker compose up -d

# Or run with standalone Docker
docker build -t vanguard-recon .
docker run -p 8000:8000 vanguard-recon
```

---

## 🧪 Automated Test Suite

VanguardRecon includes full unit and integration test coverage across all subsystems:

```bash
pytest -v
```

```
tests/test_cve_engine.py::test_correlate_apache_path_traversal PASSED
tests/test_cve_engine.py::test_correlate_openssh_regresshion PASSED
tests/test_cve_engine.py::test_risk_score_calculation PASSED
tests/test_fingerprinter.py::test_fingerprint_openssh PASSED
tests/test_fingerprinter.py::test_fingerprint_apache PASSED
tests/test_fingerprinter.py::test_fingerprint_nginx PASSED
tests/test_fingerprinter.py::test_fingerprint_proftpd PASSED
tests/test_fingerprinter.py::test_fingerprint_vsftpd PASSED
tests/test_reporter.py::test_json_reporting PASSED
tests/test_reporter.py::test_html_reporting PASSED
tests/test_scanner.py::test_async_port_scanner_mock PASSED
tests/test_scope.py::test_cloud_metadata_detection PASSED
tests/test_scope.py::test_scope_manager_cloud_metadata_violation PASSED
tests/test_scope.py::test_port_parsing_valid PASSED
tests/test_scope.py::test_port_parsing_invalid PASSED

======================== 15 passed in 3.5s ========================
```

---

## 🎯 Hiring & Interview Preparation Guide
*(Use these exact talking points during Penetration Testing & Red Team interviews)*

### 1. Resume Project Description
> **VanguardRecon — Attack Surface Discovery & Automated CVE Intelligence Framework (Python, Asyncio, FastAPI)**
> - Engineered a high-performance asynchronous reconnaissance engine using Python `asyncio` and bounded semaphores to scan network ports and banner-grab services with low packet loss.
> - Implemented heuristic banner parsing and CPE extraction, automating real-time CVE correlation against CISA Known Exploited Vulnerabilities (KEV) and Exploit-DB repositories.
> - Designed an algorithmic risk calculator combining CVSS v3.1 severity metrics and EPSS exploitation probabilities.
> - Developed dual delivery interfaces: a Rich CLI with animated terminal telemetry and a FastAPI web dashboard producing client-ready executive HTML penetration testing reports.
> - Integrated defensive guardrails to block unauthorized scanning of Cloud Metadata endpoints (`169.254.169.254`) and out-of-scope ranges, enforcing strict Rules of Engagement (RoE).

---

### 2. Common Technical Interview Questions & Answers

#### Q1: "Why did you choose `asyncio` instead of Python's `threading` or `multiprocessing` for network scanning?"
> **Answer:**  
> "Network scanning is an **I/O-bound** operation characterized by socket connection waits and high latency fluctuations. Threading incurs heavy OS context-switching overhead and thread-stack memory footprints (typically 8MB per thread), which limits concurrency to a few hundred threads before degrading performance.  
> With Python's single-threaded event loop and `asyncio.Semaphore`, we can multiplex thousands of socket descriptors efficiently using OS event notification primitives (`epoll` on Linux, `IOCP` on Windows) while maintaining lightweight co-routine frames and deterministic concurrency control without race conditions."

#### Q2: "How does your tool prevent false positives during CVE matching?"
> **Answer:**  
> "Traditional vulnerability scanners often alert based on generic port mappings alone. VanguardRecon employs a two-tier verification mechanism:
> 1. It extracts exact banner strings using protocol-specific handshakes (e.g. `HEAD` for HTTP, version strings for SSH/FTP).
> 2. It normalizes product names and performs semantic version tuple comparisons against explicit version boundary brackets `[min_version, max_version]`.
> 3. It correlates findings with the CISA KEV catalog to differentiate between theoretical CVEs and weaponized exploits actively used in adversary campaigns."

#### Q3: "What ethical and legal precautions are built into the framework?"
> **Answer:**  
> "In penetration testing, adhering to the agreed Rules of Engagement (RoE) is paramount. VanguardRecon integrates a dedicated `ScopeManager` that:
> - Blocks calls targeting Cloud Instance Metadata endpoints (such as AWS/GCP/Azure IMDS at `169.254.169.254` or `metadata.google.internal`) to protect cloud environments.
> - Inspects private RFC 1918 and loopback IP spaces, requiring explicit confirmation (`--allow-internal`) to prevent unintended scans on internal networks."

---

## 📜 License
Distributed under the **MIT License**. Created for cybersecurity engineering portfolio demonstration and authorized security testing.
