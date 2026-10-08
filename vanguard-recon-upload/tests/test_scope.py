"""
Unit tests for ethical scope validation and port parsing.
"""

import pytest
from vanguard.scope import ScopeManager, ScopeViolationError


def test_cloud_metadata_detection():
    # Cloud IMDS endpoints must be blocked
    assert ScopeManager.is_cloud_metadata("169.254.169.254") is True
    assert ScopeManager.is_cloud_metadata("169.254.1.1") is True  # link-local
    assert ScopeManager.is_cloud_metadata("metadata.google.internal") is True
    assert ScopeManager.is_cloud_metadata("100.100.100.200") is True

    # Normal hosts should not be flagged as cloud metadata
    assert ScopeManager.is_cloud_metadata("127.0.0.1") is False
    assert ScopeManager.is_cloud_metadata("8.8.8.8") is False
    assert ScopeManager.is_cloud_metadata("example.com") is False


def test_scope_manager_cloud_metadata_violation():
    with pytest.raises(ScopeViolationError):
        ScopeManager.resolve_target("169.254.169.254")


def test_port_parsing_valid():
    # Single ports
    assert ScopeManager.parse_ports("80") == [80]
    assert ScopeManager.parse_ports("80,443,22") == [22, 80, 443]

    # Port ranges
    assert ScopeManager.parse_ports("80-83") == [80, 81, 82, 83]

    # Mixed ranges and individual ports with spaces and duplicates
    assert ScopeManager.parse_ports("22, 80-82, 443, 22") == [22, 80, 81, 82, 443]


def test_port_parsing_invalid():
    with pytest.raises(ValueError):
        ScopeManager.parse_ports("70000")  # Beyond 65535

    with pytest.raises(ValueError):
        ScopeManager.parse_ports("0")  # Less than 1

    with pytest.raises(ValueError):
        ScopeManager.parse_ports("80-70")  # Inverted range

    with pytest.raises(ValueError):
        ScopeManager.parse_ports("abc")
