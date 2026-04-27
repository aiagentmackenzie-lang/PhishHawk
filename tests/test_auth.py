"""Tests for authentication analysis engine."""

from __future__ import annotations

import pytest

from phishhawk.auth import (
    check_alignment,
    check_free_email,
    check_timestamp_drift,
    parse_auth_header,
    ptr_lookup,
    validate_dmarc,
    validate_spf,
)
from phishhawk.headers import ReceivedHop


def test_parse_auth_header_pass() -> None:
    header = "spf=pass dkim=pass dmarc=pass"
    result = parse_auth_header(header)
    assert result == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}


def test_parse_auth_header_fail() -> None:
    header = "spf=fail dkim=fail dmarc=fail"
    result = parse_auth_header(header)
    assert result == {"spf": "fail", "dkim": "fail", "dmarc": "fail"}


def test_parse_auth_header_none() -> None:
    assert parse_auth_header(None) == {}
    assert parse_auth_header("") == {}


def test_check_alignment_spf_aligned() -> None:
    result = check_alignment(
        from_domain="example.com",
        spf_domain="example.com",
        dkim_domains=["other.com"],
        dmarc_policy="reject",
    )
    assert result.spf_aligned is True
    assert result.dmarc_pass is True


def test_check_alignment_dkim_aligned() -> None:
    result = check_alignment(
        from_domain="example.com",
        spf_domain="other.com",
        dkim_domains=["example.com"],
        dmarc_policy="reject",
    )
    assert result.dkim_aligned is True
    assert result.dmarc_pass is True


def test_check_alignment_fails() -> None:
    result = check_alignment(
        from_domain="example.com",
        spf_domain="other.com",
        dkim_domains=["another.com"],
        dmarc_policy="reject",
    )
    assert result.spf_aligned is False
    assert result.dkim_aligned is False
    assert result.dmarc_pass is False
    assert result.reason is not None


def test_check_free_email() -> None:
    flagged = check_free_email(["user@gmail.com", "boss@company.com"])
    assert len(flagged) == 1
    assert "gmail.com" in flagged[0]


def test_check_timestamp_drift_within_threshold() -> None:
    from datetime import datetime, timezone
    date = datetime(2026, 4, 25, 8, 30, 0, tzinfo=timezone.utc)
    received = ReceivedHop(timestamp=datetime(2026, 4, 25, 8, 29, 0, tzinfo=timezone.utc))
    flagged, drift = check_timestamp_drift(date, received, threshold_seconds=1800)
    assert flagged is False
    assert drift == 60


def test_check_timestamp_drift_exceeds() -> None:
    from datetime import datetime, timezone
    date = datetime(2026, 4, 25, 8, 30, 0, tzinfo=timezone.utc)
    received = ReceivedHop(timestamp=datetime(2026, 4, 25, 7, 0, 0, tzinfo=timezone.utc))
    flagged, drift = check_timestamp_drift(date, received, threshold_seconds=1800)
    assert flagged is True
    assert drift == 5400


def test_check_timestamp_drift_none() -> None:
    assert check_timestamp_drift(None, None) == (False, None)


@pytest.mark.skip(reason="Requires live DNS — run manually with network")
def test_validate_spf_live() -> None:
    result = validate_spf("google.com")
    assert result.domain == "google.com"
    assert result.valid is True


@pytest.mark.skip(reason="Requires live DNS — run manually with network")
def test_validate_dmarc_live() -> None:
    result = validate_dmarc("google.com")
    assert result.domain == "google.com"
    assert result.policy is not None
    assert result.valid is True


def test_ptr_lookup_localhost() -> None:
    result = ptr_lookup("127.0.0.1")
    assert result.ip == "127.0.0.1"
