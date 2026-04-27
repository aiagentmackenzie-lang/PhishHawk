"""Rich terminal output formatter."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from phishhawk.models import EmailAnalysis, RiskLevel


def render_terminal(analysis: EmailAnalysis) -> None:
    """Render a full analysis report to the terminal using Rich."""
    console = Console()

    # Title banner
    console.print(
        Panel.fit(
            "[bold blue]PhishHawk[/bold blue]  —  Email Security Analysis\n"
            f"[dim]{analysis.file}[/dim]",
            title="🔍",
            border_style="blue",
        )
    )

    # Risk score banner
    risk_color = _risk_color(analysis.risk.level)
    console.print(
        Panel(
            f"[bold {risk_color}]"
            f"Risk Score: {analysis.risk.total}/100 — {analysis.risk.level.value}"
            f"[/bold {risk_color}]",
            border_style=risk_color,
        )
    )

    # Category breakdown table
    if analysis.risk.categories:
        table = Table(title="Category Breakdown")
        table.add_column("Category", style="cyan")
        table.add_column("Score", justify="right")
        table.add_column("Key Findings")
        for cat in analysis.risk.categories:
            color = _risk_color(_level_from_score(cat.score))
            findings_text = "\n".join(cat.findings[:3])
            table.add_row(
                cat.category,
                f"[{color}]{cat.score}/{cat.max_score}[/{color}]",
                findings_text,
            )
        console.print(table)

    # Headers summary
    if analysis.headers:
        console.print(
            Panel(
                f"[bold]Subject:[/bold]  {analysis.headers.subject or 'N/A'}\n"
                f"[bold]From:[/bold]     {analysis.headers.from_address or 'N/A'}"
                f"{' (' + analysis.headers.from_display_name + ')' if analysis.headers.from_display_name else ''}\n"
                f"[bold]To:[/bold]       {', '.join(analysis.headers.to_addresses) or 'N/A'}\n"
                f"[bold]Reply-To:[/bold] {analysis.headers.reply_to or 'N/A'}\n"
                f"[bold]Return-Path:[/bold] {analysis.headers.return_path or 'N/A'}\n"
                f"[bold]Received:[/bold]  {len(analysis.headers.received)} hop(s)",
                title="[bold]Headers[/bold]",
                border_style="dim",
            )
        )

    # Authentication panel (Phase 2)
    if analysis.authentication:
        auth = analysis.authentication
        lines: list[str] = []
        if auth.spf and auth.spf.domain:
            status = "[green]valid[/green]" if auth.spf.valid else "[red]invalid/missing[/red]"
            lines.append(f"[bold]SPF[/bold]  {auth.spf.domain} — {status}")
        if auth.dmarc and auth.dmarc.domain:
            policy = auth.dmarc.policy or "none"
            status = "[green]valid[/green]" if auth.dmarc.valid else "[red]invalid[/red]"
            color = "green" if auth.dmarc.alignment_required else "yellow"
            lines.append(
                f"[bold]DMARC[/bold] {auth.dmarc.domain} — policy=[{color}]{policy}[/{color}], {status}"
            )
        if auth.alignment:
            spf_a = "[green]✓[/green]" if auth.alignment.spf_aligned else "[red]✗[/red]"
            dkim_a = "[green]✓[/green]" if auth.alignment.dkim_aligned else "[red]✗[/red]"
            lines.append(
                f"[bold]Alignment[/bold] SPF={spf_a}  DKIM={dkim_a}"
            )
            if auth.alignment.reason:
                lines.append(f"[dim]{auth.alignment.reason}[/dim]")
        if auth.ptr:
            for p in auth.ptr[:3]:
                host = p.hostname or "[dim]no PTR[/dim]"
                lines.append(f"[bold]PTR[/bold] {p.ip} → {host}")
        if auth.free_email_providers:
            lines.append(
                f"[bold yellow]Free Email:[/bold yellow] {', '.join(auth.free_email_providers)}"
            )
        if auth.timestamp_drift_flagged:
            lines.append(
                f"[yellow]Timestamp drift:[/yellow] {auth.timestamp_drift_seconds}s"
            )
        if lines:
            console.print(
                Panel(
                    "\n".join(lines),
                    title="[bold]Authentication (DNS)[/bold]",
                    border_style="cyan",
                )
            )

    # URLs panel (Phase 3)
    if analysis.urls:
        url_table = Table(title="URLs")
        url_table.add_column("URL")
        url_table.add_column("Flags", style="dim")
        for u in analysis.urls:
            flags: list[str] = []
            style = "white"
            if u.is_homograph:
                flags.append("[red]homograph[/red]")
                style = "red"
            if u.is_shortened:
                flags.append("[yellow]shortened[/yellow]")
            if u.suspicious_tld:
                flags.append("[yellow]suspicious-TLD[/yellow]")
            if u.raw_ip:
                flags.append("[red]raw-IP[/red]")
                style = "red"
            if u.dga_suspected:
                flags.append("[yellow]DGA[/yellow]")
            if u.is_defanged:
                flags.append("[cyan]defanged[/cyan]")
            if u.whois and u.whois.newly_registered:
                flags.append("[yellow]new-domain[/yellow]")
            if not flags:
                flags.append("[green]clean[/green]")
            display_url = u.url[:60] + "..." if len(u.url) > 60 else u.url
            url_table.add_row(f"[{style}]{display_url}[/{style}]", " ".join(flags))
        console.print(url_table)

    # Attachments panel + forensics (Phase 4)
    if analysis.attachments:
        att_table = Table(title="Attachments")
        att_table.add_column("Filename")
        att_table.add_column("MIME Type")
        att_table.add_column("Size", justify="right")
        att_table.add_column("Forensics", style="dim")
        for att in analysis.attachments:
            style = "red" if att.is_dangerous else "green"
            forensics_line = ""
            if analysis.attachment_forensics:
                f = next(
                    (af for af in analysis.attachment_forensics if af.filename == att.filename),
                    None,
                )
                if f:
                    forensic_flags: list[str] = []
                    if f.office_macros and f.office_macros.has_macros:
                        forensic_flags.append("[red]macros[/red]")
                    if f.pdf and f.pdf.has_js:
                        forensic_flags.append("[red]PDF-JS[/red]")
                    if f.yara and f.yara.match_count > 0:
                        forensic_flags.append(f"[yellow]YARA×{f.yara.match_count}[/yellow]")
                    if f.hatchery and f.hatchery.get("status") == "submitted":
                        forensic_flags.append("[cyan]HATCHERY[/cyan]")
                    if f.archive_extracted:
                        forensic_flags.append(f"[yellow]ZIP+{len(f.archive_extracted)}[/yellow]")
                    forensics_line = " ".join(forensic_flags) if forensic_flags else "clean"
            att_table.add_row(
                f"[{style}]{att.filename}[/{style}]",
                att.mime_type,
                f"{att.size:,}",
                forensics_line or "",
            )
        console.print(att_table)

        # Attachment findings panel
        all_findings: list[str] = []
        for af in analysis.attachment_forensics:
            all_findings.extend(af.findings)
        if all_findings:
            console.print(
                Panel(
                    "\n".join(f"• {f}" for f in all_findings[:6]),
                    title="[bold]Attachment Findings[/bold]",
                    border_style="red" if any("macro" in f.lower() or "js" in f.lower() or "yara" in f.lower() for f in all_findings) else "yellow",
                )
            )

    # MITRE mapping
    if analysis.mitre:
        console.print(
            f"\n[bold yellow]MITRE ATT&CK:[/bold yellow]  {', '.join(analysis.mitre)}"
        )

    # Recommendations
    if analysis.recommendations:
        console.print(
            Panel(
                "\n".join(f"• {r}" for r in analysis.recommendations),
                title="[bold]Recommendations[/bold]",
                border_style="yellow",
            )
        )

    console.print(f"\n[dim]Analysis completed at {analysis.analysis_timestamp.isoformat()}[/dim]")


def _risk_color(level: RiskLevel) -> str:
    return {
        RiskLevel.LOW: "green",
        RiskLevel.MEDIUM: "yellow",
        RiskLevel.HIGH: "red",
        RiskLevel.CRITICAL: "bright_red",
    }.get(level, "white")


def _level_from_score(score: int) -> RiskLevel:
    if score >= 80:
        return RiskLevel.CRITICAL
    if score >= 60:
        return RiskLevel.HIGH
    if score >= 40:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW
