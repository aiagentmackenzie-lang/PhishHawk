"""Tests for auth module with DNS mocking."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from phishhawk.auth import (
    check_alignment,
    check_free_email,
    parse_auth_header,
    validate_dkim,
    validate_dmarc,
    validate_spf,
)
from phishhawk.auth_models import AlignmentCheck, DMARCResult, SPFResult
import checkdmarc
import dns.resolver


def test_parse_auth_header_all_pass() -> None:
    result = parse_auth_header("spf=pass; dkim=pass; dmarc=pass")
    assert result["spf"] == "pass"
    assert result["dkim"] == "pass"
    assert result["dmarc"] == "pass"


def test_parse_auth_header_none() -> None:
    assert parse_auth_header(None) == {}


def test_parse_auth_header_mixed() -> None:
    result = parse_auth_header("spf=fail; dkim=pass; dmarc=fail")
    assert result["spf"] == "fail"
    assert result["dkim"] == "pass"
    assert result["dmarc"] == "fail"


def test_check_alignment_spf_aligned() -> None:
    result = check_alignment("example.com", "example.com", [], None)
    assert result.spf_aligned is True
    assert result.dmarc_pass is True


def test_check_alignment_neither_aligned() -> None:
    result = check_alignment("example.com", "evil.com", ["other.com"], "reject")
    assert result.spf_aligned is False
    assert result.dkim_aligned is False
    assert result.dmarc_pass is False
    assert result.reason is not None


def test_check_alignment_dkim_aligned() -> None:
    result = check_alignment("example.com", "evil.com", ["example.com"], None)
    assert result.dkim_aligned is True
    assert result.dmarc_pass is True


def test_check_free_email() -> None:
    flagged = check_free_email(["support@gmail.com", "admin@company.com"])
    assert len(flagged) == 1
    assert "gmail.com" in flagged[0]


def test_check_free_email_none() -> None:
    assert check_free_email([None, None]) == []


def test_validate_spf_mocked() -> None:
    """Validate SPF with mocked checkdmarc."""
    with patch.object(checkdmarc, "check_spf", return_value={
        "record": "v=spf1 include:_spf.google.com ~all",
        "valid": True,
        "warnings": [],
    }):
        result = validate_spf("gmail.com")
        assert result.valid is True
        assert "v=spf1" in result.record


def test_validate_spf_mocked_invalid() -> None:
    """Invalid SPF should be reported."""
    with patch.object(checkdmarc, "check_spf", return_value={
        "record": "",
        "valid": False,
        "errors": ["No SPF record found"],
    }):
        result = validate_spf("nonexistent.invalid")
        assert result.valid is False


def test_validate_spf_exception() -> None:
    """Exception during SPF check should be handled gracefully."""
    with patch.object(checkdmarc, "check_spf", side_effect=Exception("DNS timeout")):
        result = validate_spf("evil.com")
        assert result.dns_available is False
        assert len(result.errors) > 0


def test_validate_dmarc_mocked() -> None:
    """Validate DMARC with mocked checkdmarc."""
    with patch.object(checkdmarc, "check_dmarc", return_value={
        "record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        "valid": True,
        "tags": {
            "p": {"value": "reject"},
            "pct": {"value": 100},
            "rua": {"value": "mailto:dmarc@example.com"},
        },
        "warnings": [],
    }):
        result = validate_dmarc("example.com")
        assert result.valid is True
        assert result.policy == "reject"
        assert result.alignment_required is True


def test_validate_dmarc_none_policy() -> None:
    """DMARC policy=none should not require alignment."""
    with patch.object(checkdmarc, "check_dmarc", return_value={
        "record": "v=DMARC1; p=none",
        "valid": True,
        "tags": {
            "p": {"value": "none"},
            "pct": {"value": 100},
        },
        "warnings": [],
    }):
        result = validate_dmarc("example.com")
        assert result.policy == "none"
        assert result.alignment_required is False


def test_validate_dkim_mocked() -> None:
    """Validate DKIM with mocked DNS resolver."""
    from dns.resolver import NXDOMAIN, NoAnswer
    mock_answers = MagicMock()
    mock_answers.__iter__ = lambda self: iter([MagicMock(strings=[b"v=DKIM1; k=rsa; p=MIGf"] )])
    with patch.object(dns.resolver, "resolve") as mock_resolve:
        # First two selectors: NXDOMAIN / NoAnswer, third succeeds
        mock_resolve.side_effect = [
            NXDOMAIN(),
            NoAnswer(),
            mock_answers,
        ]
        result = validate_dkim("example.com", selectors=["default", "selector1", "google"])
        assert len(result) == 3
        assert result[0].valid is False
        assert result[1].valid is False
        assert result[2].valid is True
        assert "DKIM1" in result[2].record


def test_validate_dkim_all_fail() -> None:
    """All DKIM selectors fail gracefully."""
    from dns.resolver import NXDOMAIN
    with patch.object(dns.resolver, "resolve", side_effect=NXDOMAIN()):
        result = validate_dkim("example.com", selectors=["default"])
        assert len(result) == 1
        assert result[0].valid is False