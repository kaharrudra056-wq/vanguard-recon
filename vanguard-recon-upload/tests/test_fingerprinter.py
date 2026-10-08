"""
Unit tests for service and banner fingerprinting.
"""

from vanguard.core.fingerprinter import ServiceFingerprinter


def test_fingerprint_openssh():
    raw = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    fp = ServiceFingerprinter.fingerprint("ssh", raw)
    assert fp.product == "OpenSSH"
    assert fp.version == "8.2p1"
    assert fp.os == "Ubuntu-4ubuntu0.5"
    assert "cpe:2.3:a:openbsd:openssh:8.2p1" in fp.cpe
    assert fp.confidence > 0.8


def test_fingerprint_apache():
    raw = "Apache/2.4.49 (Unix) OpenSSL/1.1.1d"
    fp = ServiceFingerprinter.fingerprint("http", raw)
    assert fp.product == "Apache HTTP Server"
    assert fp.version == "2.4.49"
    assert "cpe:2.3:a:apache:http_server:2.4.49" in fp.cpe


def test_fingerprint_nginx():
    raw = "nginx/1.18.0"
    fp = ServiceFingerprinter.fingerprint("http", raw)
    assert fp.product == "Nginx"
    assert fp.version == "1.18.0"


def test_fingerprint_proftpd():
    raw = "220 ProFTPD 1.3.5 Server (Debian)"
    fp = ServiceFingerprinter.fingerprint("ftp", raw)
    assert fp.product == "ProFTPD"
    assert fp.version == "1.3.5"


def test_fingerprint_vsftpd():
    raw = "220 (vsFTPd 3.0.3)"
    fp = ServiceFingerprinter.fingerprint("ftp", raw)
    assert fp.product == "vsftpd"
    assert fp.version == "3.0.3"
