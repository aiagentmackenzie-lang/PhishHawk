"""PhishHawk CLI entry point (Typer)."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from phishhawk.auth import analyze_authentication
from phishhawk.auth_models import AuthAnalysis
from phishhawk.models import EmailAnalysis
from phishhawk.output.json_out import export_json
from phishhawk.output.terminal import render_terminal
from phishhawk.parser import parse_email
from phishhawk.scoring import score_email

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

    auth = analyze_authentication(parsed.headers)
    risk = score_email(parsed, auth)
    mitre, recs = _mitre_map(risk.categories, auth)

    analysis = EmailAnalysis(
        file=parsed.file_path,
        file_hash=parsed.file_sha256,
        risk=risk,
        headers=parsed.headers,
        authentication=auth,
        attachments=parsed.attachments,
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
            risk = score_email(parsed, auth)
            analysis = EmailAnalysis(
                file=parsed.file_path,
                file_hash=parsed.file_sha256,
                risk=risk,
                headers=parsed.headers,
                authentication=auth,
                attachments=parsed.attachments,
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
