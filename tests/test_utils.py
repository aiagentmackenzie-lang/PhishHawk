"""Tests for utility functions."""

from __future__ import annotations

import pytest

from phishhawk.utils import compute_hashes, file_type_from_path


def test_compute_hashes() -> None:
    data = b"hello world"
    hashes = compute_hashes(data)
    assert hashes["md5"] == "5eb63bbbe01eeed093cb22bb8f5acdc3"
    assert hashes["sha1"] == "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
    assert hashes["sha256"] == (
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    )


@pytest.mark.parametrize(
    "path,expected",
    [
        ("email.eml", "eml"),
        ("email.msg", "msg"),
        ("email.mbox", "mbox"),
        ("/some/path/file.EML", "eml"),
        ("noextension", "eml"),
    ],
)
def test_file_type_from_path(path: str, expected: str) -> None:
    assert file_type_from_path(path) == expected
