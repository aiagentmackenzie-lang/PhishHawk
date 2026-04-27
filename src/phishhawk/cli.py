"""PhishHawk CLI entry point (Typer)."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from phishhawk.attachment_analyzer import analyze_all_attachments
from phishhawk.attachment_models import AttachmentForensics
from phishhawk.auth import analyze_authentication
from phishhawk.iocs import extract_iocs
from phishhawk.mitre import build_recommendations, map_findings_to_mitre
from phishhawk.models import EmailAnalysis
from phishhawk.output.json_out import export_json, export_ndjson
from phishhawk.output.markdown_out import export_markdown
from phishhawk.output.stix_out import export_misp_json, export_stix_json
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


def _run_analysis(
    file: str,
    *,
    sandbox_urls: bool = False,
    detonate_attachments_flag: bool = False,
    yara_rules: str | None = None,
) -> EmailAnalysis:
    """Core analysis pipeline shared across commands."""
    parsed = parse_email(file)

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
    forensics_raw = analyze_all_attachments(
        parsed.attachments, parsed.raw_payloads, yara_rules
    )
    forensics: list[AttachmentForensics] = []
    for fr in forensics_raw:
        f = (
            AttachmentForensics(
                filename=fr.get("filename", ""),
                sha256=fr.get("sha256"),
                mime_type=fr.get("mime_type"),
                is_dangerous=fr.get("is_dangerous", False),
                office_macros=fr.get("office_macros"),
                pdf=fr.get("pdf"),
                yara=fr.get("yara"),
                archive_extracted=fr.get("archive_extracted", []),
                findings=fr.get("findings", []),
            )
            if isinstance(fr, dict)
            else fr
        )

        if detonate_attachments_flag:
            f.hatchery = {"status": "unavailable", "note": "HATCHERY not yet running"}
            f.findings.append("HATCHERY: unavailable — sandbox not yet running")

        forensics.append(f)

    # IOC extraction (Phase 5)
    iocs = extract_iocs(parsed)

    # Scoring
    risk = score_email(parsed, auth, urls, forensics, iocs)

    # MITRE mapping (Phase 5 — auto-map from all findings)
    all_findings: list[str] = []
    for cat in risk.categories:
        all_findings.extend(cat.findings)
    mitre_ids = map_findings_to_mitre(all_findings)
    recs = build_recommendations(mitre_ids)
    if not recs:
        recs = ["No immediate action required"]

    return EmailAnalysis(
        file=parsed.file_path,
        file_hash=parsed.file_sha256,
        risk=risk,
        headers=parsed.headers,
        authentication=auth,
        urls=urls,
        attachments=parsed.attachments,
        attachment_forensics=forensics,
        iocs=iocs,
        mitre=mitre_ids,
        recommendations=recs,
        body_text=parsed.body_text,
        body_html=parsed.body_html,
    )


@app.command()
def analyze(
    file: str = typer.Argument(..., help="Path to email file (.eml, .msg, .mbox)"),
    output: str = typer.Option(
        "terminal",
        "--output",
        "-o",
        help="Output format: terminal, json, markdown, misp, stix",
    ),
    outfile: str | None = typer.Option(
        None, "--outfile", "-f", help="Write output to file"
    ),
    sandbox_urls: bool = typer.Option(
        False,
        "--sandbox-urls",
        help="Enable outbound URL analysis (redirects, SSL, WHOIS)",
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
        analysis = _run_analysis(
            file,
            sandbox_urls=sandbox_urls,
            detonate_attachments_flag=detonate_attachments_flag,
            yara_rules=yara_rules,
        )
    except FileNotFoundError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc
    except Exception as exc:
        console.print(f"[red]Parse error:[/red] {exc}")
        raise typer.Exit(1) from exc

    if output == "json":
        result = export_json(analysis, outfile)
        if not outfile:
            print(result)
    elif output == "markdown":
        result = export_markdown(analysis, outfile)
        if not outfile:
            print(result)
    elif output == "misp":
        result = export_misp_json(analysis, outfile)
        if not outfile:
            print(result)
    elif output == "stix":
        result = export_stix_json(analysis, outfile)
        if not outfile:
            print(result)
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

    analyses: list[EmailAnalysis] = []
    for f in files:
        try:
            analysis = _run_analysis(str(f))
            analyses.append(analysis)
        except Exception as exc:
            console.print(f"[yellow]Skipping {f.name}: {exc}[/yellow]")

    if output == "ndjson":
        export_ndjson(analyses, outfile)
        console.print(
            f"[green]Wrote {len(analyses)} analysis(es) to {outfile}[/green]"
        )
    else:
        # JSON array
        import json as _json

        arr = [a.model_dump(mode="json", exclude_none=False) for a in analyses]
        text = _json.dumps(arr, indent=2, default=str)
        Path(outfile).write_text(text)
        console.print(
            f"[green]Wrote {len(analyses)} analysis(es) to {outfile}[/green]"
        )


@app.command()
def compare(
    file1: str = typer.Argument(..., help="First email file"),
    file2: str = typer.Argument(..., help="Second email file"),
    output: str = typer.Option(
        "terminal", "--output", "-o", help="Output format: terminal, json, markdown"
    ),
    outfile: str | None = typer.Option(
        None, "--outfile", "-f", help="Write output to file"
    ),
) -> None:
    """Compare two email analyses (campaign variant diff)."""
    try:
        analysis1 = _run_analysis(file1)
        analysis2 = _run_analysis(file2)
    except FileNotFoundError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc
    except Exception as exc:
        console.print(f"[red]Parse error:[/red] {exc}")
        raise typer.Exit(1) from exc

    if output == "json":
        import json as _json

        result = {
            "campaign_comparison": {
                "file1": analysis1.model_dump(mode="json"),
                "file2": analysis2.model_dump(mode="json"),
                "diff": _build_diff(analysis1, analysis2),
            }
        }
        text = _json.dumps(result, indent=2, default=str)
        if outfile:
            Path(outfile).write_text(text)
        console.print(text)
    elif output == "markdown":
        md = _render_compare_markdown(analysis1, analysis2)
        if outfile:
            Path(outfile).write_text(md)
        console.print(md)
    else:
        _render_compare_terminal(analysis1, analysis2)


def _build_diff(a1: EmailAnalysis, a2: EmailAnalysis) -> dict:
    """Build a structured diff dict for two analyses."""
    def _set(items):
        return set(items)

    return {
        "risk_delta": a2.risk.total - a1.risk.total,
        "subject_match": (a1.headers.subject or "") == (a2.headers.subject or ""),
        "from_match": (a1.headers.from_address or "") == (a2.headers.from_address or ""),
        "shared_urls": list(_set(u.url for u in a1.urls) & _set(u.url for u in a2.urls)),
        "unique_urls_file1": list(_set(u.url for u in a1.urls) - _set(u.url for u in a2.urls)),
        "unique_urls_file2": list(_set(u.url for u in a2.urls) - _set(u.url for u in a1.urls)),
        "shared_domains": list(_set(a1.iocs.domains) & _set(a2.iocs.domains)),
        "unique_domains_file1": list(_set(a1.iocs.domains) - _set(a2.iocs.domains)),
        "unique_domains_file2": list(_set(a2.iocs.domains) - _set(a1.iocs.domains)),
        "shared_attachments": list(
            _set(a.sha256 for a in a1.attachments if a.sha256)
            & _set(a.sha256 for a in a2.attachments if a.sha256)
        ),
        "shared_mitre": list(_set(a1.mitre) & _set(a2.mitre)),
        "shared_emails": list(_set(a1.iocs.emails) & _set(a2.iocs.emails)),
    }


def _render_compare_terminal(a1: EmailAnalysis, a2: EmailAnalysis) -> None:
    diff = _build_diff(a1, a2)

    console.print(
        Panel.fit(
            "[bold blue]PhishHawk[/bold blue]  —  Campaign Comparison\n"
            f"[dim]{Path(a1.file).name}  vs  {Path(a2.file).name}[/dim]",
            title="🔍",
            border_style="blue",
        )
    )

    # Risk comparison
    risk_table = Table(title="Risk Comparison")
    risk_table.add_column("Metric")
    risk_table.add_column(a1.file, justify="right")
    risk_table.add_column(a2.file, justify="right")
    risk_table.add_row("Score", str(a1.risk.total), str(a2.risk.total))
    risk_table.add_row("Level", a1.risk.level.value, a2.risk.level.value)
    risk_table.add_row(
        "Delta",
        "",
        f"{'+' if diff['risk_delta'] > 0 else ''}{diff['risk_delta']}",
    )
    console.print(risk_table)

    # Subject / From
    meta_table = Table(title="Metadata")
    meta_table.add_column("Field")
    meta_table.add_column("Match")
    meta_table.add_row("Subject", "✅" if diff["subject_match"] else "❌")
    meta_table.add_row("From", "✅" if diff["from_match"] else "❌")
    console.print(meta_table)

    # Shared / Unique IOCs
    console.print(f"\n[bold]Shared URLs:[/bold] {len(diff['shared_urls'])}")
    for u in diff["shared_urls"][:5]:
        console.print(f"  • {u}")
    console.print(f"\n[bold]Unique URLs (file 1):[/bold] {len(diff['unique_urls_file1'])}")
    for u in diff["unique_urls_file1"][:5]:
        console.print(f"  • {u}")
    console.print(f"\n[bold]Unique URLs (file 2):[/bold] {len(diff['unique_urls_file2'])}")
    for u in diff["unique_urls_file2"][:5]:
        console.print(f"  • {u}")

    console.print(f"\n[bold]Shared MITRE:[/bold] {', '.join(diff['shared_mitre']) or 'None'}")
    console.print(f"[bold]Shared Attachment Hashes:[/bold] {len(diff['shared_attachments'])}")


def _render_compare_markdown(a1: EmailAnalysis, a2: EmailAnalysis) -> str:
    diff = _build_diff(a1, a2)
    lines = [
        "# PhishHawk Campaign Comparison Report\n",
        f"| | **{Path(a1.file).name}** | **{Path(a2.file).name}** |",
        "|---|---|---|",
        f"| Risk Score | {a1.risk.total} | {a2.risk.total} |",
        f"| Risk Level | {a1.risk.level.value} | {a2.risk.level.value} |",
        f"| Delta | — | {'+' if diff['risk_delta'] > 0 else ''}{diff['risk_delta']} |",
        f"| Subject Match | {'✅' if diff['subject_match'] else '❌'} | {'✅' if diff['subject_match'] else '❌'} |",
        f"| From Match | {'✅' if diff['from_match'] else '❌'} | {'✅' if diff['from_match'] else '❌'} |",
        "",
        "## Shared URLs\n",
    ]
    if diff["shared_urls"]:
        for u in diff["shared_urls"]:
            lines.append(f"- {u}")
    else:
        lines.append("_None_")
    lines.append("")

    lines.append("## Unique URLs (File 1)\n")
    if diff["unique_urls_file1"]:
        for u in diff["unique_urls_file1"]:
            lines.append(f"- {u}")
    else:
        lines.append("_None_")
    lines.append("")

    lines.append("## Unique URLs (File 2)\n")
    if diff["unique_urls_file2"]:
        for u in diff["unique_urls_file2"]:
            lines.append(f"- {u}")
    else:
        lines.append("_None_")
    lines.append("")

    lines.append("## Shared MITRE ATT&CK Techniques\n")
    if diff["shared_mitre"]:
        for m in diff["shared_mitre"]:
            lines.append(f"- {m}")
    else:
        lines.append("_None_")
    lines.append("")

    lines.append("## Shared Attachment Hashes\n")
    if diff["shared_attachments"]:
        for h in diff["shared_attachments"]:
            lines.append(f"- `{h}`")
    else:
        lines.append("_None_")
    lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    app()
