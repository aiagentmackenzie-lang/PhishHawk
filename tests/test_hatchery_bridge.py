"""Tests for hatchery_bridge module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from phishhawk.hatchery_bridge import (
    detonate_attachments,
    get_report,
    submit_attachment,
)
from phishhawk.models import AttachmentInfo


def _att() -> AttachmentInfo:
    return AttachmentInfo(
        filename="malware.exe",
        mime_type="application/octet-stream",
        size=1024,
        is_dangerous=True,
        sha256="abc123",
    )


def test_submit_attachment_connection_error() -> None:
    """Connection error should return error dict."""
    with patch("phishhawk.hatchery_bridge.requests") as mock_req:
        import requests as _req
        mock_req.exceptions.ConnectionError = _req.exceptions.ConnectionError
        mock_req.post.side_effect = _req.exceptions.ConnectionError("Refused")
        result = submit_attachment(_att(), b"\x00" * 100)
        assert "error" in result
        assert "unavailable" in result["error"]


def test_submit_attachment_timeout() -> None:
    """Timeout should return error dict."""
    with patch("phishhawk.hatchery_bridge.requests") as mock_req:
        mock_req.exceptions.Timeout = TimeoutError
        mock_req.exceptions.ConnectionError = ConnectionError
        mock_req.post.side_effect = TimeoutError("Timed out")
        result = submit_attachment(_att(), b"\x00" * 100)
        assert "error" in result


def test_submit_attachment_success() -> None:
    """Successful submission should return task dict."""
    with patch("phishhawk.hatchery_bridge.requests") as mock_req:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"task_id": "abc123", "status": "queued"}
        mock_resp.raise_for_status = MagicMock()
        mock_req.post.return_value = mock_resp
        result = submit_attachment(_att(), b"\x00" * 100)
        assert result["task_id"] == "abc123"


def test_get_report_connection_error() -> None:
    """Connection error in get_report should return error dict."""
    with patch("phishhawk.hatchery_bridge.requests") as mock_req:
        import requests as _req
        mock_req.exceptions.ConnectionError = _req.exceptions.ConnectionError
        mock_req.get.side_effect = _req.exceptions.ConnectionError("Refused")
        result = get_report("abc123")
        assert "error" in result


def test_get_report_success() -> None:
    """Successful report retrieval."""
    with patch("phishhawk.hatchery_bridge.requests") as mock_req:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"task_id": "abc123", "score": 85, "behavior": "malicious"}
        mock_resp.raise_for_status = MagicMock()
        mock_req.get.return_value = mock_resp
        result = get_report("abc123")
        assert result["score"] == 85


def test_detonate_attachments_empty() -> None:
    """No attachments should return empty list."""
    result = detonate_attachments([], {})
    assert result == []


def test_detonate_attachments_no_payload() -> None:
    """Attachment without matching payload should be skipped."""
    att = _att()
    result = detonate_attachments([att], {})
    assert result == []


def test_detonate_attachments_success() -> None:
    """Detonation with matching payload and successful submission."""
    att = _att()
    payloads = {"malware.exe": b"\x00" * 100}
    with patch("phishhawk.hatchery_bridge.requests") as mock_req:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"task_id": "t1", "status": "queued"}
        mock_resp.raise_for_status = MagicMock()
        mock_req.post.return_value = mock_resp
        result = detonate_attachments([att], payloads)
        assert len(result) == 1
        assert result[0]["status"] == "submitted"


def test_endpoint_env_override() -> None:
    """HATCHERY_ENDPOINT env var should override default."""
    import os
    from phishhawk.hatchery_bridge import _endpoint
    original = os.environ.get("HATCHERY_ENDPOINT")
    try:
        os.environ["HATCHERY_ENDPOINT"] = "http://custom:9999/api"
        assert _endpoint() == "http://custom:9999/api"
    finally:
        if original:
            os.environ["HATCHERY_ENDPOINT"] = original
        else:
            os.environ.pop("HATCHERY_ENDPOINT", None)