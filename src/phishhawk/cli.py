"""PhishHawk CLI entry point (Typer)."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from phishhawk.config import get_config
from phishhawk.engine import run_analysis
from phishhawk.models import EmailAnalysis
from phishhawk.output.json_out import export_json, export_ndjson
from phishhawk.output.markdown_out import export_markdown, render_compare_markdown
from phishhawk.output.stix_out import export_misp_json, export_stix_json
from phishhawk.output.terminal import render_terminal

app = typer.Typer(
    name="phishhawk",
    help="Forensic-grade email security analyzer for SOC analysts",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


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
        analysis = run_analysis(
            file,
            sandbox_urls=sandbox_urls,
            detonate_attachments=detonate_attachments_flag,
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
            analysis = run_analysis(str(f))
            analyses.append(analysis)
        except Exception as exc:
            console.print(f"[yellow]Skipping {f.name}: {exc}[/yellow]")

    if output == "ndjson":
        export_ndjson(analyses, outfile)
        console.print(
            f"[green]Wrote {len(analyses)} analysis(es) to {outfile}[/green]"
        )
    else:
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
        analysis1 = run_analysis(file1)
        analysis2 = run_analysis(file2)
    except FileNotFoundError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc
    except Exception as exc:
        console.print(f"[red]Parse error:[/red] {exc}")
        raise typer.Exit(1) from exc

    if output == "json":
        import json as _json

        from phishhawk.output.markdown_out import _build_diff

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
        md = render_compare_markdown(analysis1, analysis2)
        if outfile:
            Path(outfile).write_text(md)
        console.print(md)
    else:
        _render_compare_terminal(analysis1, analysis2)


def _render_compare_terminal(a1: EmailAnalysis, a2: EmailAnalysis) -> None:
    from phishhawk.output.markdown_out import _build_diff

    diff = _build_diff(a1, a2)

    console.print(
        Panel.fit(
            "[bold blue]PhishHawk[/bold blue]  —  Campaign Comparison\n"
            f"[dim]{Path(a1.file).name}  vs  {Path(a2.file).name}[/dim]",
            title="\U0001f50d",
            border_style="blue",
        )
    )

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

    meta_table = Table(title="Metadata")
    meta_table.add_column("Field")
    meta_table.add_column("Match")
    meta_table.add_row("Subject", "\u2705" if diff["subject_match"] else "\u274c")
    meta_table.add_row("From", "\u2705" if diff["from_match"] else "\u274c")
    console.print(meta_table)

    console.print(f"\n[bold]Shared URLs:[/bold] {len(diff['shared_urls'])}")
    for u in diff["shared_urls"][:5]:
        console.print(f"  \u2022 {u}")
    console.print(f"\n[bold]Unique URLs (file 1):[/bold] {len(diff['unique_urls_file1'])}")
    for u in diff["unique_urls_file1"][:5]:
        console.print(f"  \u2022 {u}")
    console.print(f"\n[bold]Unique URLs (file 2):[/bold] {len(diff['unique_urls_file2'])}")
    for u in diff["unique_urls_file2"][:5]:
        console.print(f"  \u2022 {u}")

    console.print(f"\n[bold]Shared MITRE:[/bold] {', '.join(diff['shared_mitre']) or 'None'}")
    console.print(f"[bold]Shared Attachment Hashes:[/bold] {len(diff['shared_attachments'])}")


@app.command()
def config(
    show: bool = typer.Option(True, "--show", help="Show current configuration"),
    init: bool = typer.Option(False, "--init", help="Create default config at ~/.phishhawk/config.toml"),
) -> None:
    """View or initialise PhishHawk configuration."""
    if init:
        cfg_dir = Path.home() / ".phishhawk"
        cfg_dir.mkdir(exist_ok=True)
        cfg_path = cfg_dir / "config.toml"
        if cfg_path.exists():
            console.print(f"[yellow]Config already exists at {cfg_path}[/yellow]")
            raise typer.Exit(0)
        default_content = """# PhishHawk Configuration
# See: https://github.com/aiagentmackenzie-lang/PhishHawk

[hatchery]
endpoint = "http://localhost:8000/api"
timeout = 30

[dns]
timeout = 10
retries = 2

[scoring.weights]
authentication = 30
headers = 15
urls = 25
attachments = 15
iocs = 15

[output]
terminal_width = 100
color = true

[dkim]
selectors = ["default", "google", "selector1", "selector2"]
"""
        cfg_path.write_text(default_content)
        console.print(f"[green]Created default config at {cfg_path}[/green]")
        raise typer.Exit(0)

    if show:
        cfg = get_config()
        table = Table(title="PhishHawk Configuration")
        table.add_column("Setting")
        table.add_column("Value")
        for k, v in cfg.__dict__.items():
            table.add_row(k, str(v))
        console.print(table)


if __name__ == "__main__":
    app()
