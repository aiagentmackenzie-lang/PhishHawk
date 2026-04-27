"""JSON output formatter (schema v1)."""

from __future__ import annotations

import json
from pathlib import Path

from phishhawk.models import EmailAnalysis


def export_json(analysis: EmailAnalysis, outfile: str | None = None) -> str:
    """Serialize analysis to JSON. Optionally write to file."""
    data = analysis.model_dump(mode="json", exclude_none=False)
    # convert datetime via default=str fallback for any remaining non-JSON types
    json_str = json.dumps(data, indent=2, default=str)
    if outfile:
        Path(outfile).write_text(json_str)
    return json_str
