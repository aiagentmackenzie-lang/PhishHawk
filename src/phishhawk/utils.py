"""Utility functions."""

from __future__ import annotations

import hashlib


def compute_hashes(data: bytes) -> dict[str, str]:
    """Compute MD5, SHA1, SHA256 hashes of a byte payload."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def file_type_from_path(path: str) -> str:
    """Determine email file type from extension."""
    ext = path.lower().rsplit(".", 1)[-1] if "." in path else ""
    if ext == "msg":
        return "msg"
    if ext == "mbox":
        return "mbox"
    return "eml"
