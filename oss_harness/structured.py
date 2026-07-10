from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


_FENCE_RE = re.compile(r"\A\s*```(?:json)?\s*\n(?P<body>.*)\n```\s*\Z", re.DOTALL | re.IGNORECASE)


def load_json_response(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"missing response file: {path}") from exc
    text = text.strip()
    fence = _FENCE_RE.fullmatch(text)
    if fence:
        text = fence.group("body").strip()
    if not text:
        raise ValueError("Codex returned an empty response")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Codex response is not exact JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Codex response must be a JSON object")
    return payload


def require_nonempty_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()
