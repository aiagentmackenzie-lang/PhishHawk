"""PhishHawk CLI entry point (Typer)."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from phishhawk.attachment_analyzer import analyze_all_attachments
from phishhawk.attachment_models import AttachmentForensics
from phishhawk.auth import analyze_authentication
from phishhawk.auth_models import AuthAnalysis
from phishhawk.models import EmailAnalysis
from phishhawk.output.json_out import export_json
from phishhawk.output.terminal import render_terminal
from phishhawk.parser import parse_email
from phishhawk.scoring import score_email
from phishhawk.url_analyzer import extract_and_analyze_urls

app = typer.Typer(
    name="phishhawk",
    help="Forensic-grade email security analyzer for SOC analysts",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


def _mitre_map(
    categories: list,
    auth: AuthAnalysis | None = None,
) -> tuple[list[str], list[str]]:
    """Map findings to MITRE techniques and recommendations."""
    mitre: list[str] = []
    recs: list[str] = []

    for cat in categories:
        for finding in cat.findings:
            f_lower = finding.lower()
            if ("display name spoofing" in f_lower or "reply-to mismatch" in f_lower) and "T1656" not in mitre:
                mitre.append("T1656")
                recs.append("Investigate impersonation / display name spoofing")
            if ("spf=fail" in f_lower or "dkim=fail" in f_lower or "dmarc=fail" in f_lower) and "T1566.001" not in mitre:
                mitre.append("T1566.001")
                recs.append("Validate sender via secondary channel")
            if "dangerous extension" in f_lower and "T1566.001" not in mitre:
                mitre.append("T1566.001")
                recs.append("Quarantine attachment; submit to sandbox")
            if ("macros" in f_lower or "vba" in f_lower) and "T1204.002" not in mitre:
                mitre.append("T1204.002")
                recs.append("Malicious macro attachment — disable Office macros")
            if "pdf javascript" in f_lower and "T1204.002" not in mitre:
                mitre.append("T1204.002")
                recs.append("PDF with embedded JS — inspect and sandbox")
            if "yara" in f_lower and "T1204.002" not in mitre:
                mitre.append("T1204.002")
                recs.append("YARA match on attachment — isolate and analyze")
            if ("homograph" in f_lower or "idn" in f_lower) and "T1566.002" not in mitre:
                mitre.append("T1566.002")
                recs.append("IDN homograph URL detected — possible phishing")
            if "raw ip" in f_lower and "T1566.002" not in mitre:
                mitre.append("T1566.002")
                recs.append("Raw IP URL — suspicious delivery mechanism")
            if "shortened" in f_lower and "T1566.003" not in mitre:
                mitre.append("T1566.003")
                recs.append("URL shortener used — inspect destination")
            if ("authentication failed" in f_lower or "no authentication-results" in f_lower) and "T1566.002" not in mitre:
                mitre.append("T1566.002")
                recs.append("Treat embedded links with extreme caution")
            if ("alignment failed" in f_lower or "dmarc alignment" in f_lower) and "T1566.002" not in mitre:
                mitre.append("T1566.002")
                recs.append("DMARC alignment failed — possible spoofing")
            if "timestamp drift" in f_lower and "T1078" not in mitre:
                mitre.append("T1078")
                recs.append("Investigate timestamp manipulation")

    if (auth and isinstance(auth, AuthAnalysis) and auth.free_email_providers) and "T1589" not in mitre:
        mitre.append("T1589")
        recs.append("Free email provider detected — possible reconnaissance")

    return mitre, recs if recs else ["No immediate action required"]


@app.command()
def analyze(
    file: str = typer.Argument(..., help="Path to email file (.eml, .msg, .mbox)"),
    output: str = typer.Option(
        "terminal", "--output", "-o", help="Output format: terminal, json, markdown"
    ),
    outfile: str | None = typer.Option(
        None, "--outfile", "-f", help="Write output to file"
    ),
    sandbox_urls: bool = typer.Option(
        False, "--sandbox-urls", help="Enable outbound URL analysis (redirects, SSL, WHOIS)"
    ),
    detonate_attachments_flag: bool = typer.Option(
        False, "--detonate-attachments", help="Submit attachments to HATCHERY sandbox"
    ),
    yara_rules: str | None = typer.Option(
        None, "--yara-rules", help="Directory containing YARA rules"
    ),
) -> None:
    """Analyze a single email file."""
    try:
        parsed = parse_email(file)
    except FileNotFoundError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc
    except Exception as exc:
        console.print(f"[red]Parse error:[/red] {exc}")
        raise typer.Exit(1) from exc

    # Auth analysis
    auth = analyze_authentication(parsed.headers)

    # URL analysis
    urls = extract_and_analyze_urls(
        parsed.body_text,
        parsed.body_html,
        parsed.headers.subject,
        parsed.headers.raw_headers,
        allow_outbound=sandbox_urls,
    )

    # Attachment forensics
    forensics_raw = analyze_all_attachments(parsed.attachments, parsed.raw_payloads, yara_rules)
    forensics: list[AttachmentForensics] = []
    for fr in forensics_raw:
        # Convert dict to AttachmentForensics model
        f = AttachmentForensics(
            filename=fr.get("filename", ""),
            sha256=fr.get("sha256"),
            mime_type=fr.get("mime_type"),
            is_dangerous=fr.get("is_dangerous", False),
            office_macros=fr.get("office_macros"),
            pdf=fr.get("pdf"),
            yara=fr.get("yara"),
            archive_extracted=fr.get("archive_extracted", []),
            findings=fr.get("findings", []),
        ) if isinstance(fr, dict) else fr

        # HATCHERY detonation (placeholder — HATCHERY spec-stage)
        if detonate_attachments_flag:
            f.hatchery = {"status": "unavailable", "note": "HATCHERY not yet running"}
            f.findings.append("HATCHERY: unavailable — sandbox not yet running")

        forensics.append(f)

    # Scoring
    risk = score_email(parsed, auth, urls, forensics)
    mitre, recs = _mitre_map(risk.categories, auth)

    analysis = EmailAnalysis(
        file=parsed.file_path,
        file_hash=parsed.file_sha256,
        risk=risk,
        headers=parsed.headers,
        authentication=auth,
        urls=urls,
        attachments=parsed.attachments,
        attachment_forensics=forensics,
        mitre=mitre,
        recommendations=recs,
        body_text=parsed.body_text,
        body_html=parsed.body_html,
    )

    if output == "json":
        result = export_json(analysis, outfile)
        if not outfile:
            console.print(result)
    elif output == "markdown":
        console.print("[yellow]Markdown output coming in Phase 5[/yellow]")
    else:
        render_terminal(analysis)


@app.command()
def batch(
    directory: str = typer.Argument(..., help="Directory containing email files"),
    output: str = typer.Option(
        "json", "--output", "-o", help="Output format: json, ndjson"
    ),
    outfile: str = typer.Option(
        "batch.ndjson", "--outfile", "-f", help="Output file"
    ),
    recursive: bool = typer.Option(
        False, "--recursive", "-r", help="Recursively scan subdirectories"
    ),
) -> None:
    """Batch analyze a directory of email files."""
    path = Path(directory)
    if not path.is_dir():
        console.print(f"[red]Not a directory: {directory}[/red]")
        raise typer.Exit(1)

    pattern = "**/*" if recursive else "*"
    extensions = {".eml", ".msg", ".mbox"}
    files = [f for f in path.glob(pattern) if f.suffix.lower() in extensions]

    if not files:
        console.print("[yellow]No email files found.[/yellow]")
        raise typer.Exit(0)

    results: list[str] = []
    for f in files:
        try:
            parsed = parse_email(str(f))
            auth = analyze_authentication(parsed.headers)
            urls = extract_and_analyze_urls(
                parsed.body_text,
                parsed.body_html,
                parsed.headers.subject,
                parsed.headers.raw_headers,
                allow_outbound=False,
            )
            forensics_raw = analyze_all_attachments(parsed.attachments, parsed.raw_payloads)
            forensics = []
            for fr in forensics_raw:
                fobj = AttachmentForensics(
                    filename=fr.get("filename", ""),
                    sha256=fr.get("sha256"),
                    mime_type=fr.get("mime_type"),
                    is_dangerous=fr.get("is_dangerous", False),
                    office_macros=fr.get("office_macros"),
                    pdf=fr.get("pdf"),
                    yara=fr.get("yara"),
                    findings=fr.get("findings", []),
                ) if isinstance(fr, dict) else fr
                forensics.append(fobj)

            risk = score_email(parsed, auth, urls, forensics)
            analysis = EmailAnalysis(
                file=parsed.file_path,
                file_hash=parsed.file_sha256,
                risk=risk,
                headers=parsed.headers,
                authentication=auth,
                urls=urls,
                attachments=parsed.attachments,
                attachment_forensics=forensics,
            )
            results.append(export_json(analysis))
        except Exception as exc:
            console.print(f"[yellow]Skipping {f.name}: {exc}[/yellow]")

    if outfile:
        content = "\n".join(results) + "\n" if results else ""
        Path(outfile).write_text(content)
        console.print(
            f"[green]Wrote {len(results)} analysis(es) to {outfile}[/green]"
        )
    else:
        for r in results:
            print(r)


if __name__ == "__main__":
    app()
