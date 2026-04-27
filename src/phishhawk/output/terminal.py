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

    # Attachments table
    if analysis.attachments:
        att_table = Table(title="Attachments")
        att_table.add_column("Filename")
        att_table.add_column("MIME Type")
        att_table.add_column("Size", justify="right")
        att_table.add_column("SHA256 (short)", style="dim")
        for att in analysis.attachments:
            style = "red" if att.is_dangerous else "green"
            att_table.add_row(
                f"[{style}]{att.filename}[/{style}]",
                att.mime_type,
                f"{att.size:,}",
                (att.sha256 or "N/A")[:16] + "...",
            )
        console.print(att_table)

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
