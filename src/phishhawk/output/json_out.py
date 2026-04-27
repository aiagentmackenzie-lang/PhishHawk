"""JSON / NDJSON output formatter (schema v1)."""

from __future__ import annotations

import json
from pathlib import Path

from phishhawk.models import EmailAnalysis


def export_json(analysis: EmailAnalysis, outfile: str | None = None) -> str:
    """Serialize analysis to pretty-printed JSON. Optionally write to file."""
    data = analysis.model_dump(mode="json", exclude_none=False)
    # convert datetime via default=str fallback for any remaining non-JSON types
    json_str = json.dumps(data, indent=2, default=str)
    if outfile:
        Path(outfile).write_text(json_str)
    return json_str


def export_ndjson(analyses: list[EmailAnalysis], outfile: str | None = None) -> str:
    """Serialize analyses to NDJSON (one JSON object per line). Optionally write to file."""
    lines: list[str] = []
    for analysis in analyses:
        data = analysis.model_dump(mode="json", exclude_none=False)
        lines.append(json.dumps(data, default=str))
    ndjson_str = "\n".join(lines) + "\n" if lines else ""
    if outfile:
        Path(outfile).write_text(ndjson_str)
    return ndjson_str
