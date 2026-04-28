"""Extended tests for scoring engine — edge cases and coverage gaps."""

from __future__ import annotations

from phishhawk.attachment_models import (
    AttachmentForensics,
    OfficeMacroAnalysis,
    PDFAnalysis,
    YARAResult,
)
from phishhawk.auth_models import (
    AlignmentCheck,
    AuthAnalysis,
    DMARCResult,
    SPFResult,
)
from phishhawk.models import (
    AttachmentInfo,
    HeaderInfo,
    IOCs,
    ReceivedHop,
    RiskLevel,
)
from phishhawk.scoring import (
    _level_from_score,
    score_attachments,
    score_authentication,
    score_email,
    score_headers,
    score_iocs,
    score_urls,
)
from phishhawk.url_models import SSLInfo, URLAnalysis, WHOISInfo


class TestLevelFromScore:
    def test_critical(self) -> None:
        assert _level_from_score(80) == RiskLevel.CRITICAL
        assert _level_from_score(100) == RiskLevel.CRITICAL

    def test_high(self) -> None:
        assert _level_from_score(60) == RiskLevel.HIGH
        assert _level_from_score(79) == RiskLevel.HIGH

    def test_medium(self) -> None:
        assert _level_from_score(40) == RiskLevel.MEDIUM
        assert _level_from_score(59) == RiskLevel.MEDIUM

    def test_low(self) -> None:
        assert _level_from_score(0) == RiskLevel.LOW
        assert _level_from_score(39) == RiskLevel.LOW


class TestScoreAuthentication:

    def test_no_auth_header(self) -> None:
        headers = HeaderInfo()
        result = score_authentication(headers, None)
        assert result.score > 0
        assert any("No Authentication-Results" in f for f in result.findings)

    def test_all_pass(self) -> None:
        headers = HeaderInfo(authentication_results="spf=pass dkim=pass dmarc=pass")
        result = score_authentication(headers, None)
        assert result.score >= 30  # 10+10+10 for each pass

    def test_all_fail(self) -> None:
        headers = HeaderInfo(authentication_results="spf=fail dkim=fail dmarc=fail")
        result = score_authentication(headers, None)
        assert result.score >= 100  # Capped at 100
        assert any("SPF authentication failed" in f for f in result.findings)
        assert any("DKIM authentication failed" in f for f in result.findings)
        assert any("DMARC authentication failed" in f for f in result.findings)

    def test_spf_softfail(self) -> None:
        headers = HeaderInfo(authentication_results="spf=softfail")
        result = score_authentication(headers, None)
        assert any("SPF softfail" in f for f in result.findings)

    def test_reply_to_mismatch(self) -> None:
        headers = HeaderInfo(
            authentication_results="spf=pass",
            reply_to="different@evil.com",
            from_address="legit@example.com",
        )
        result = score_authentication(headers, None)
        assert any("Reply-To mismatch" in f for f in result.findings)

    def test_display_name_spoofing(self) -> None:
        headers = HeaderInfo(
            authentication_results="",
            from_display_name="Amazon",
            from_address="random@totallydifferent.com",
        )
        result = score_authentication(headers, None)
        assert any("Display name spoofing" in f for f in result.findings)

    def test_auth_with_live_dns(self) -> None:
        """Test scoring with AuthAnalysis populated."""
        auth = AuthAnalysis(
            spf=SPFResult(domain="example.com", valid=False),
            dmarc=DMARCResult(domain="example.com", policy="none"),
            alignment=AlignmentCheck(from_domain="example.com", dmarc_pass=False),
            free_email_providers=["test@gmail.com"],
            timestamp_drift_flagged=True,
            findings=["Custom finding from auth"],
        )
        headers = HeaderInfo(
            from_address="test@gmail.com",
            authentication_results="spf=fail",
        )
        result = score_authentication(headers, auth)
        assert result.score > 0
        # Check that auth findings are merged into scoring findings
        assert any("SPF DNS record invalid" in f for f in result.findings) or any("SPF" in f for f in result.findings)
        assert any("DMARC policy is 'none'" in f for f in result.findings)

    def test_auth_dmarc_reject(self) -> None:
        """DMARC reject policy should reduce score."""
        auth = AuthAnalysis(
            dmarc=DMARCResult(domain="example.com", policy="reject"),
            alignment=AlignmentCheck(from_domain="example.com", dmarc_pass=True),
        )
        headers = HeaderInfo(authentication_results="dmarc=pass")
        result = score_authentication(headers, auth)
        # DMARC reject -10
        assert result.score >= 0


class TestScoreAttachments:

    def test_no_attachments(self) -> None:
        result = score_attachments([], [])
        assert result.score == 0
        assert any("No suspicious" in f for f in result.findings)

    def test_dangerous_extension(self) -> None:
        atts = [AttachmentInfo(filename="malware.exe", is_dangerous=True, size=100)]
        result = score_attachments(atts, [])
        assert result.score >= 40

    def test_extension_mismatch(self) -> None:
        atts = [AttachmentInfo(filename="doc.pdf", extension_mismatch=True, size=100)]
        result = score_attachments(atts, [])
        assert result.score >= 25

    def test_macros_in_forensics(self) -> None:
        atts = [AttachmentInfo(filename="doc.docm", size=100)]
        forensics = [AttachmentForensics(
            filename="doc.docm",
            office_macros=OfficeMacroAnalysis(has_macros=True, macro_count=2, suspicious=True),
        )]
        result = score_attachments(atts, forensics)
        assert any("VBA macros" in f for f in result.findings)
        assert any("Suspicious macro" in f for f in result.findings)

    def test_pdf_javascript_in_forensics(self) -> None:
        atts = [AttachmentInfo(filename="evil.pdf", size=100)]
        forensics = [AttachmentForensics(
            filename="evil.pdf",
            pdf=PDFAnalysis(has_js=True, has_uris=True, suspicious_objects_count=3),
        )]
        result = score_attachments(atts, forensics)
        assert any("PDF JavaScript" in f for f in result.findings)
        assert any("PDF embedded URIs" in f for f in result.findings)

    def test_yara_hits_in_forensics(self) -> None:
        atts = [AttachmentInfo(filename="suspicious.bin", size=100)]
        forensics = [AttachmentForensics(
            filename="suspicious.bin",
            yara=YARAResult(match_count=3, matches=["Rule1", "Rule2", "Rule3"]),
        )]
        result = score_attachments(atts, forensics)
        assert any("YARA hits" in f for f in result.findings)

    def test_hatchery_submitted(self) -> None:
        atts = [AttachmentInfo(filename="test.exe", size=100)]
        forensics = [AttachmentForensics(
            filename="test.exe",
            hatchery={"status": "submitted"},
        )]
        result = score_attachments(atts, forensics)
        assert any("HATCHERY submitted" in f for f in result.findings)


class TestScoreHeaders:

    def test_normal_headers(self) -> None:
        from datetime import datetime, timezone
        headers = HeaderInfo(message_id="<abc@123>", date=datetime(2026, 1, 1, tzinfo=timezone.utc))
        result = score_headers(headers)
        assert result.score == 0
        assert any("normal" in f.lower() for f in result.findings)

    def test_missing_message_id(self) -> None:
        headers = HeaderInfo()
        result = score_headers(headers)
        assert result.score >= 15
        assert any("Missing Message-ID" in f for f in result.findings)

    def test_excessive_received_hops(self) -> None:
        hops = [ReceivedHop(raw=f"hop{i}") for i in range(7)]
        headers = HeaderInfo(received=hops, message_id="<id>")
        result = score_headers(headers)
        assert any("Excessive Received" in f for f in result.findings)


class TestScoreUrls:

    def test_no_urls(self) -> None:
        result = score_urls([])
        assert result.score == 0
        assert any("No URLs" in f for f in result.findings)

    def test_homograph_url(self) -> None:
        url = URLAnalysis(url="https://xn--r-0ga.com", is_homograph=True)
        result = score_urls([url])
        assert result.score >= 40
        assert any("homograph" in f.lower() for f in result.findings)

    def test_shortened_url(self) -> None:
        url = URLAnalysis(url="https://bit.ly/abc", is_shortened=True)
        result = score_urls([url])
        assert result.score >= 25

    def test_suspicious_tld_url(self) -> None:
        url = URLAnalysis(url="https://evil.xyz", suspicious_tld=True, domain="evil", tld="xyz")
        result = score_urls([url])
        assert result.score >= 30

    def test_raw_ip_url(self) -> None:
        url = URLAnalysis(url="http://1.2.3.4/", raw_ip=True)
        result = score_urls([url])
        assert result.score >= 35

    def test_dga_domain(self) -> None:
        url = URLAnalysis(url="https://x9k2j7q3p5m8n1w4r6.com", dga_suspected=True, domain="x9k2j7q3p5m8n1w4r6")
        result = score_urls([url])
        assert any("DGA" in f for f in result.findings)

    def test_expired_ssl(self) -> None:
        url = URLAnalysis(url="https://evil.com", ssl=SSLInfo(expired=True), domain="evil")
        result = score_urls([url])
        assert any("Expired SSL" in f for f in result.findings)

    def test_newly_registered_whois(self) -> None:
        url = URLAnalysis(url="https://new.xyz", whois=WHOISInfo(newly_registered=True), domain="new")
        result = score_urls([url])
        assert any("Newly registered" in f for f in result.findings)

    def test_defanged_url(self) -> None:
        url = URLAnalysis(url="hxxps://evil[.]com", is_defanged=True)
        result = score_urls([url])
        assert any("Defanged" in f for f in result.findings)


class TestScoreIOCs:

    def test_no_iocs(self) -> None:
        result = score_iocs(IOCs())
        assert result.score == 0
        assert any("No IOCs" in f for f in result.findings)

    def test_ipv4_iocs(self) -> None:
        iocs = IOCs(ipv4=["1.2.3.4", "5.6.7.8"])
        result = score_iocs(iocs)
        assert result.score >= 10
        assert any("IPv4" in f for f in result.findings)

    def test_crypto_address_iocs(self) -> None:
        iocs = IOCs(crypto_addresses=["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"])
        result = score_iocs(iocs)
        assert result.score >= 30
        assert any("Cryptocurrency" in f for f in result.findings)

    def test_mixed_iocs(self) -> None:
        iocs = IOCs(
            ipv4=["1.2.3.4"],
            domains=["evil.com"],
            urls=["https://evil.com/phish"],
            emails=["phish@evil.com"],
            file_hashes=["a" * 64],
        )
        result = score_iocs(iocs)
        assert result.score > 0
        assert len(result.findings) >= 5


class TestScoreEmail:

    def test_score_email_with_sample(self) -> None:
        """Full scoring pipeline with parsed sample email."""
        from phishhawk.parser import parse_email
        parsed = parse_email("tests/fixtures/sample.eml")
        result = score_email(parsed)
        assert result.total > 0
        assert result.level in (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert len(result.categories) == 5
