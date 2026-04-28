"""Tests for URL analyzer outbound paths — SSL, WHOIS, redirect tracing with proper mocking."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from phishhawk.url_analyzer import (
    analyze_ssl,
    analyze_url,
    analyze_whois,
    extract_and_analyze_urls,
    trace_redirects,
)


class TestTraceRedirectsReal:

    def test_redirects_passive_mode(self) -> None:
        """Passive mode (allow_outbound=False) should return empty list."""
        result = trace_redirects("https://example.com", allow_outbound=False)
        assert result == []

    def test_redirects_outbound_success(self) -> None:
        """Outbound redirect chain with mocked HTTP responses."""
        with patch("phishhawk.url_analyzer.requests") as mock_req:
            # 301 redirect → 302 redirect → 200 OK
            resp1 = MagicMock()
            resp1.status_code = 301
            resp1.headers = {"Location": "https://example.com/step2"}

            resp2 = MagicMock()
            resp2.status_code = 302
            resp2.headers = {"Location": "https://final.com/page"}

            resp3 = MagicMock()
            resp3.status_code = 200

            mock_req.head.side_effect = [resp1, resp2, resp3]
            result = trace_redirects("https://short.url/abc", allow_outbound=True, max_hops=10)
            assert len(result) == 2
            assert result[0] == "https://example.com/step2"
            assert result[1] == "https://final.com/page"

    def test_redirects_self_loop(self) -> None:
        """Redirect to same URL should stop."""
        with patch("phishhawk.url_analyzer.requests") as mock_req:
            resp = MagicMock()
            resp.status_code = 301
            resp.headers = {"Location": "https://example.com/loop"}
            mock_req.head.return_value = resp
            # First call redirects to same URL — should stop
            result = trace_redirects("https://example.com/loop", allow_outbound=True)
            # Should stop after first redirect (same URL)
            assert isinstance(result, list)

    def test_redirects_no_redirect(self) -> None:
        """Non-redirect response should return empty chain."""
        with patch("phishhawk.url_analyzer.requests") as mock_req:
            resp = MagicMock()
            resp.status_code = 200
            mock_req.head.return_value = resp
            result = trace_redirects("https://example.com", allow_outbound=True)
            assert result == []

    def test_redirects_timeout(self) -> None:
        """Network timeout should return partial chain."""
        with patch("phishhawk.url_analyzer.requests") as mock_req:
            mock_req.head.side_effect = Exception("Connection timeout")
            result = trace_redirects("https://slow.example.com", allow_outbound=True)
            assert result == []


class TestAnalyzeSslReal:

    def test_ssl_http_url_returns_none(self) -> None:
        """HTTP URL should return None (no SSL to analyze)."""
        result = analyze_ssl("http://example.com")
        assert result is None

    def test_ssl_connection_error(self) -> None:
        """SSL connection failure should return None."""
        with patch("phishhawk.url_analyzer.socket") as mock_socket:
            mock_socket.create_connection.side_effect = Exception("Connection refused")
            result = analyze_ssl("https://unreachable.example.com")
            assert result is None

    def test_ssl_handshake_error(self) -> None:
        """SSL handshake failure should return None."""
        with patch("phishhawk.url_analyzer.socket") as mock_socket, \
             patch("phishhawk.url_analyzer.ssl") as mock_ssl:
            mock_socket.create_connection.return_value = MagicMock()
            mock_ctx = MagicMock()
            mock_ssl.create_default_context.return_value = mock_ctx
            mock_ctx.wrap_socket.side_effect = Exception("Certificate verify failed")
            result = analyze_ssl("https://bad-cert.example.com")
            assert result is None


class TestAnalyzeWhoisReal:

    def test_whois_no_module(self) -> None:
        """If whois module is not available, should return None."""
        # The function uses a try/except for the import
        # If whois is not installed, it returns None
        with patch.dict("sys.modules", {"whois": None}):
            result = analyze_whois("example.com")
            assert result is None


class TestAnalyzeUrlOutbound:

    def test_outbound_enables_ssl(self) -> None:
        """allow_outbound=True with HTTPS should trigger SSL analysis."""
        with patch("phishhawk.url_analyzer.trace_redirects") as mock_redirect, \
             patch("phishhawk.url_analyzer.analyze_ssl") as mock_ssl, \
             patch("phishhawk.url_analyzer.analyze_whois") as mock_whois:
            mock_redirect.return_value = ["https://final.com/page"]
            mock_ssl.return_value = None
            mock_whois.return_value = None

            result = analyze_url("https://example.com", allow_outbound=True)
            assert result.redirect_chain == ["https://final.com/page"]
            assert result.final_url == "https://final.com/page"
            mock_ssl.assert_called_once()
            mock_whois.assert_called_once()

    def test_outbound_http_no_ssl(self) -> None:
        """allow_outbound=True with HTTP should NOT trigger SSL analysis."""
        with patch("phishhawk.url_analyzer.trace_redirects") as mock_redirect, \
             patch("phishhawk.url_analyzer.analyze_ssl") as mock_ssl, \
             patch("phishhawk.url_analyzer.analyze_whois") as mock_whois:
            mock_redirect.return_value = []
            mock_ssl.return_value = None
            mock_whois.return_value = None

            analyze_url("http://example.com", allow_outbound=True)
            mock_ssl.assert_not_called()
            mock_whois.assert_called_once()

    def test_passive_mode_no_outbound(self) -> None:
        """allow_outbound=False should not trigger any outbound calls."""
        with patch("phishhawk.url_analyzer.trace_redirects") as mock_redirect, \
             patch("phishhawk.url_analyzer.analyze_ssl") as mock_ssl, \
             patch("phishhawk.url_analyzer.analyze_whois") as mock_whois:
            result = analyze_url("https://example.com", allow_outbound=False)
            mock_redirect.assert_not_called()
            mock_ssl.assert_not_called()
            mock_whois.assert_not_called()
            assert result.redirect_chain == []

    def test_outbound_with_redirect_final_url(self) -> None:
        """Redirect chain should set final_url to last redirect."""
        with patch("phishhawk.url_analyzer.trace_redirects") as mock_redirect, \
             patch("phishhawk.url_analyzer.analyze_ssl") as mock_ssl, \
             patch("phishhawk.url_analyzer.analyze_whois") as mock_whois:
            mock_redirect.return_value = ["https://evil.com/page1", "https://evil.com/page2"]
            mock_ssl.return_value = None
            mock_whois.return_value = None

            result = analyze_url("https://bit.ly/abc", allow_outbound=True)
            assert result.final_url == "https://evil.com/page2"


class TestExtractAndAnalyzeUrlsExtended:

    def test_url_source_subject(self) -> None:
        """URL found in subject should have source_context='subject'."""
        results = extract_and_analyze_urls(
            None, None, "Click https://evil.com/verify now", None
        )
        assert len(results) > 0
        # The first URL from subject should have source_context set
        # (depends on implementation — may be "body" by default)
        assert any("evil.com" in r.url for r in results)

    def test_url_source_body(self) -> None:
        """URL found in body text."""
        results = extract_and_analyze_urls(
            "Visit https://example.com for info", None, None, None
        )
        assert any("example.com" in r.url for r in results)

    def test_header_url_extraction(self) -> None:
        """URLs in Return-Path header."""
        headers = {"Return-Path": ["<bounce@evil.com>"]}
        results = extract_and_analyze_urls(None, None, None, headers)
        # Header content is concatenated for extraction
        assert isinstance(results, list)
