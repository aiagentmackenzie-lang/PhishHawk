"""HATCHERY sandbox bridge — REST API client for dynamic analysis."""

from __future__ import annotations

import os

import requests

from phishhawk.models import AttachmentInfo

HATCHERY_DEFAULT_ENDPOINT = "http://localhost:8000/api/v1"


def _endpoint() -> str:
    return os.environ.get("HATCHERY_ENDPOINT", HATCHERY_DEFAULT_ENDPOINT)


def _api_key() -> str | None:
    return os.environ.get("HATCHERY_API_KEY")


def submit_attachment(att: AttachmentInfo, payload: bytes) -> dict[str, object]:
    """Submit an attachment to HATCHERY for detonation.

    Returns task dict with task_id on success, or error dict on failure.
    """
    endpoint = _endpoint()
    api_key = _api_key()
    headers: dict[str, str] = {}
    if api_key:
        headers["X-API-Key"] = api_key

    try:
        files = {"file": (att.filename, payload, att.mime_type or "application/octet-stream")}
        data = {"timeout": "120", "source": "phishhawk"}
        resp = requests.post(
            f"{endpoint}/submit",
            files=files,
            data=data,
            headers=headers,
            timeout=30,
        )
        resp.raise_for_status()
        result: dict[str, object] = resp.json()
        return result
    except requests.exceptions.ConnectionError:
        return {"error": "HATCHERY unavailable — sandbox not running", "hatchery_endpoint": endpoint}
    except requests.exceptions.Timeout:
        return {"error": "HATCHERY submission timed out", "hatchery_endpoint": endpoint}
    except requests.exceptions.HTTPError as exc:
        return {"error": f"HATCHERY HTTP error: {exc.response.status_code}", "detail": str(exc)}
    except Exception as exc:
        return {"error": f"HATCHERY submission failed: {exc}", "hatchery_endpoint": endpoint}


def get_report(task_id: str) -> dict[str, object]:
    """Retrieve a HATCHERY analysis report by task ID.

    Returns report dict or error dict.
    """
    endpoint = _endpoint()
    api_key = _api_key()
    headers: dict[str, str] = {}
    if api_key:
        headers["X-API-Key"] = api_key

    try:
        resp = requests.get(
            f"{endpoint}/report/{task_id}",
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        result: dict[str, object] = resp.json()
        return result
    except requests.exceptions.ConnectionError:
        return {"error": "HATCHERY unavailable — sandbox not running", "hatchery_endpoint": endpoint}
    except requests.exceptions.Timeout:
        return {"error": "HATCHERY report request timed out", "hatchery_endpoint": endpoint}
    except Exception as exc:
        return {"error": f"HATCHERY report failed: {exc}", "hatchery_endpoint": endpoint}


def detonate_attachments(
    attachments: list[AttachmentInfo],
    raw_payloads: dict[str, bytes],
) -> list[dict[str, object]]:
    """Submit all attachments to HATCHERY and collect report references.

    Returns list of result dicts (task or error).
    """
    results: list[dict[str, object]] = []
    for att in attachments:
        payload = raw_payloads.get(att.filename)
        if not payload:
            continue
        result = submit_attachment(att, payload)
        if "error" not in result:
            result = {
                **result,
                "filename": att.filename,
                "sha256": att.sha256,
                "status": "submitted",
            }
        else:
            result = {
                **result,
                "filename": att.filename,
                "sha256": att.sha256,
                "status": "failed",
            }
        results.append(result)
    return results
