from __future__ import annotations

from copy import deepcopy
import re
from typing import Any


REVIEW_SCHEMA_VERSION = "2.0"


def normalize_review_record(payload: dict[str, Any]) -> dict[str, Any]:
    item = deepcopy(payload)
    item["schema_version"] = str(item.get("schema_version", REVIEW_SCHEMA_VERSION) or REVIEW_SCHEMA_VERSION)

    item["finding_file"] = str(item.get("finding_file", "") or "")
    item["title"] = str(item.get("title", "") or "")
    item["tier"] = str(item.get("tier", "") or "")
    item["confidence"] = str(item.get("confidence", "") or "")
    item["disposition"] = str(item.get("disposition", "") or "")
    item["summary"] = str(item.get("summary", "") or "")
    item["impact"] = str(item.get("impact", "") or "")
    item["key_evidence"] = _string_list(item.get("key_evidence"))
    item["blocking_gaps"] = _string_list(item.get("blocking_gaps"))
    item["next_actions"] = _string_list(item.get("next_actions"))

    item["attacker_control"] = _normalize_attacker_control(item.get("attacker_control"))
    item["reachability"] = _normalize_reachability(item.get("reachability"))
    item["entrypoints"] = _normalize_entrypoints_or_sinks(item.get("entrypoints"), privilege_key=None)
    item["sinks"] = _normalize_entrypoints_or_sinks(item.get("sinks"), privilege_key="privilege")
    item["evidence_locations"] = _normalize_evidence_locations(item.get("evidence_locations"))
    item["candidate_components"] = _normalize_candidate_components(item.get("candidate_components"))
    item["candidate_boundaries"] = _normalize_candidate_boundaries(item.get("candidate_boundaries"))

    item["capabilities"] = _normalize_named_string_objects(item.get("capabilities"), key_name="name")
    item["preconditions"] = _normalize_string_or_object_list(item.get("preconditions"))
    item["affected_assets"] = _normalize_string_or_object_list(item.get("affected_assets"))
    item["candidate_policies"] = _normalize_string_or_object_list(item.get("candidate_policies"))
    item["candidate_invariants"] = _normalize_string_or_object_list(item.get("candidate_invariants"))
    item["exploit_path"] = _normalize_exploit_path(item.get("exploit_path"))
    item["confidence_breakdown"] = _normalize_confidence_breakdown(item.get("confidence_breakdown"))

    if not item["evidence_locations"]:
        item["evidence_locations"] = _derive_evidence_locations(item)
    if not item["entrypoints"]:
        item["entrypoints"] = _derive_entrypoints(item)
    if not item["sinks"]:
        item["sinks"] = _derive_sinks(item)
    if not item["candidate_components"]["source"] and not item["candidate_components"]["target"]:
        item["candidate_components"] = _derive_candidate_components(item)
    if not item["candidate_boundaries"]:
        item["candidate_boundaries"] = _derive_candidate_boundaries(item)
    if not item["confidence_breakdown"]["overall"]:
        item["confidence_breakdown"] = _derive_confidence_breakdown(item)
    return item


def structured_review_schema_text() -> str:
    return """{
  "schema_version": "2.0",
  "finding_file": "finding-123.txt",
  "title": "",
  "tier": "S|A|B|C|D",
  "confidence": "high|medium|low",
  "disposition": "confirmed|strong|plausible|weak|reject",
  "summary": "",
  "impact": "",
  "attacker_control": {
    "summary": "",
    "controlled_inputs": [
      {"name": "", "kind": "", "scope": "", "notes": ""}
    ]
  },
  "reachability": {
    "summary": "",
    "trigger": "",
    "entry_condition": "",
    "path_hint": ["componentA", "componentB"]
  },
  "entrypoints": [
    {
      "name": "",
      "kind": "",
      "surface": "",
      "location": {"file": "", "symbol": "", "lines": ""}
    }
  ],
  "sinks": [
    {
      "name": "",
      "kind": "",
      "privilege": "",
      "location": {"file": "", "symbol": "", "lines": ""}
    }
  ],
  "evidence_locations": [
    {"file": "", "symbol": "", "lines": "", "role": ""}
  ],
  "candidate_components": {
    "source": ["component.renderer"],
    "target": ["component.main_process"],
    "intermediate": ["component.cache_manager"]
  },
  "candidate_boundaries": [
    {
      "id": "",
      "kind": "",
      "crossing_reason": "",
      "confidence": "high|medium|low"
    }
  ],
  "capabilities": [
    {"name": "", "kind": "", "scope": "", "notes": ""}
  ],
  "preconditions": [{"name": "", "kind": "", "notes": ""}],
  "affected_assets": [{"name": "", "kind": "", "notes": ""}],
  "candidate_policies": [{"name": "", "kind": "", "notes": ""}],
  "candidate_invariants": [{"name": "", "kind": "", "notes": ""}],
  "exploit_path": [
    {"step": 1, "name": "", "kind": "", "notes": ""}
  ],
  "confidence_breakdown": {
    "overall": "high|medium|low",
    "attacker_control": "high|medium|low",
    "reachability": "high|medium|low",
    "impact": "high|medium|low",
    "notes": ""
  },
  "key_evidence": ["..."],
  "blocking_gaps": ["..."],
  "next_actions": ["..."]
}"""


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _normalize_attacker_control(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        return {"summary": value.strip(), "controlled_inputs": []}
    if not isinstance(value, dict):
        return {"summary": "", "controlled_inputs": []}
    inputs = []
    for item in value.get("controlled_inputs", []):
        if not isinstance(item, dict):
            continue
        inputs.append(
            {
                "name": str(item.get("name", "") or ""),
                "kind": str(item.get("kind", "") or ""),
                "scope": str(item.get("scope", "") or ""),
                "notes": str(item.get("notes", "") or ""),
            }
        )
    return {"summary": str(value.get("summary", "") or ""), "controlled_inputs": inputs}


def _normalize_reachability(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        return {"summary": value.strip(), "trigger": "", "entry_condition": "", "path_hint": []}
    if not isinstance(value, dict):
        return {"summary": "", "trigger": "", "entry_condition": "", "path_hint": []}
    return {
        "summary": str(value.get("summary", "") or ""),
        "trigger": str(value.get("trigger", "") or ""),
        "entry_condition": str(value.get("entry_condition", "") or ""),
        "path_hint": _string_list(value.get("path_hint")),
    }


def _normalize_entrypoints_or_sinks(value: Any, *, privilege_key: str | None) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    items = []
    for item in value:
        if not isinstance(item, dict):
            continue
        location = item.get("location", {})
        if not isinstance(location, dict):
            location = {}
        file_path = _normalize_repo_file_hint(str(location.get("file", "") or ""))
        if file_path and not _is_valid_repo_file_hint(file_path):
            file_path = ""
        if not file_path:
            continue
        name = str(item.get("name", "") or "")
        if "/" in name and "." in name:
            name = ""
        symbol = str(location.get("symbol", "") or "")
        fallback_name = symbol or _basename_without_extension(file_path)
        row = {
            "name": name or fallback_name,
            "kind": str(item.get("kind", "") or ""),
            "surface": str(item.get("surface", "") or ""),
            "location": {
                "file": file_path,
                "symbol": symbol,
                "lines": str(location.get("lines", "") or ""),
            },
        }
        if privilege_key is not None:
            row["privilege"] = str(item.get(privilege_key, "") or "")
            row.pop("surface", None)
        items.append(row)
    return items


def _normalize_evidence_locations(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    items = []
    for item in value:
        if not isinstance(item, dict):
            continue
        file_path = _normalize_repo_file_hint(str(item.get("file", "") or ""))
        if not _is_valid_repo_file_hint(file_path):
            continue
        items.append({"file": file_path, "symbol": str(item.get("symbol", "") or ""), "lines": str(item.get("lines", "") or ""), "role": str(item.get("role", "") or "")})
    return items


def _normalize_candidate_components(value: Any) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        return {"source": [], "target": [], "intermediate": []}
    return {
        "source": _string_list(value.get("source")),
        "target": _string_list(value.get("target")),
        "intermediate": _string_list(value.get("intermediate")),
    }


def _normalize_candidate_boundaries(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    items = []
    for item in value:
        if not isinstance(item, dict):
            continue
        items.append(
            {
                "id": str(item.get("id", "") or ""),
                "kind": str(item.get("kind", "") or ""),
                "crossing_reason": str(item.get("crossing_reason", "") or ""),
                "confidence": str(item.get("confidence", "") or ""),
            }
        )
    return items


def _normalize_named_string_objects(value: Any, *, key_name: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    items = []
    for item in value:
        if isinstance(item, str):
            items.append({key_name: item.strip(), "kind": "", "scope": "", "notes": ""})
            continue
        if not isinstance(item, dict):
            continue
        items.append(
            {
                key_name: str(item.get(key_name, "") or ""),
                "kind": str(item.get("kind", "") or ""),
                "scope": str(item.get("scope", "") or ""),
                "notes": str(item.get("notes", "") or ""),
            }
        )
    return items


def _normalize_string_or_object_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    items = []
    for item in value:
        if isinstance(item, str):
            items.append({"name": item.strip(), "kind": "", "notes": ""})
            continue
        if not isinstance(item, dict):
            continue
        items.append(
            {
                "name": str(item.get("name", "") or ""),
                "kind": str(item.get("kind", "") or ""),
                "notes": str(item.get("notes", "") or ""),
            }
        )
    return items


def _normalize_exploit_path(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    items = []
    for index, item in enumerate(value, start=1):
        if isinstance(item, str):
            items.append({"step": index, "name": item.strip(), "kind": "", "notes": ""})
            continue
        if not isinstance(item, dict):
            continue
        step = item.get("step", index)
        try:
            step = int(step)
        except Exception:
            step = index
        items.append(
            {
                "step": step,
                "name": str(item.get("name", "") or ""),
                "kind": str(item.get("kind", "") or ""),
                "notes": str(item.get("notes", "") or ""),
            }
        )
    return items


def _normalize_confidence_breakdown(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        return {
            "overall": value.strip(),
            "attacker_control": "",
            "reachability": "",
            "impact": "",
            "notes": "",
        }
    if not isinstance(value, dict):
        return {
            "overall": "",
            "attacker_control": "",
            "reachability": "",
            "impact": "",
            "notes": "",
        }
    return {
        "overall": str(value.get("overall", "") or ""),
        "attacker_control": str(value.get("attacker_control", "") or ""),
        "reachability": str(value.get("reachability", "") or ""),
        "impact": str(value.get("impact", "") or ""),
        "notes": str(value.get("notes", "") or ""),
    }


_FILE_LOC_RE = re.compile(
    r"((?:[A-Za-z0-9_@.-]+/)+[A-Za-z0-9_@.-]+\.(?:ts|tsx|js|jsx|py|go|rs|java|kt|c|cc|cpp|h|hpp))(?:[:](\d+(?:-\d+)?))?"
)
_SYMBOL_RE = re.compile(r"`([A-Za-z_][A-Za-z0-9_.$-]*)\(\)`|`([A-Za-z_][A-Za-z0-9_.$-]*)`")


def _derive_evidence_locations(item: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for text in [item.get("summary", ""), item.get("impact", ""), *_string_list(item.get("key_evidence"))]:
        rows.extend(_locations_from_text(str(text), role=_role_from_text(str(text))))
    return _dedupe_locations(rows)


def _derive_entrypoints(item: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for text in [item.get("summary", ""), item.get("reachability", {}).get("summary", ""), *_string_list(item.get("key_evidence"))]:
        lower = str(text).lower()
        if not any(token in lower for token in ("entry", "ingest", "accept", "request", "reachable", "processsessionrequest", "trigger")):
            continue
        for location in _locations_from_text(str(text), role="entrypoint"):
            rows.append(
                {
                    "name": _entrypoint_name_from_text(str(text), location),
                    "kind": _entrypoint_kind_from_text(str(text)),
                    "surface": _surface_from_file(location["file"]),
                    "location": {
                        "file": location["file"],
                        "symbol": location["symbol"],
                        "lines": location["lines"],
                    },
                }
            )
    return _dedupe_entrypoints_or_sinks(rows, key="surface")


def _derive_sinks(item: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for text in [item.get("impact", ""), *_string_list(item.get("key_evidence"))]:
        lower = str(text).lower()
        if not any(token in lower for token in ("dispatch", "invoke", "call", "bypass", "fetch", "write", "read", "api", "confirm")):
            continue
        for location in _locations_from_text(str(text), role="sink"):
            rows.append(
                {
                    "name": _sink_name_from_text(str(text), location),
                    "kind": _sink_kind_from_text(str(text)),
                    "privilege": _privilege_from_text(str(text), location["file"]),
                    "location": {
                        "file": location["file"],
                        "symbol": location["symbol"],
                        "lines": location["lines"],
                    },
                }
            )
    return _dedupe_entrypoints_or_sinks(rows, key="privilege")


def _derive_candidate_components(item: dict[str, Any]) -> dict[str, list[str]]:
    source = []
    target = []
    intermediate = []
    for entry in item.get("entrypoints", []):
        component = _component_from_file(entry.get("location", {}).get("file", ""))
        if component:
            source.append(component)
    for sink in item.get("sinks", []):
        component = _component_from_file(sink.get("location", {}).get("file", ""))
        if component:
            target.append(component)
    for location in item.get("evidence_locations", []):
        component = _component_from_file(location.get("file", ""))
        if component and component not in source and component not in target:
            intermediate.append(component)
    return {
        "source": _dedupe_strings(source),
        "target": _dedupe_strings(target),
        "intermediate": _dedupe_strings(intermediate),
    }


def _derive_candidate_boundaries(item: dict[str, Any]) -> list[dict[str, Any]]:
    source = item.get("candidate_components", {}).get("source", [])
    target = item.get("candidate_components", {}).get("target", [])
    if any("renderer" in value for value in source) and any("main_process" in value for value in target):
        return [
            {
                "id": "boundary.renderer_to_main_process",
                "kind": "authority",
                "crossing_reason": "Renderer-controlled input appears to reach a main-process capability or privileged helper.",
                "confidence": item.get("confidence", ""),
            }
        ]
    if source and target and source != target:
        return [
            {
                "id": "boundary.cross_component_flow",
                "kind": "trust",
                "crossing_reason": "The finding appears to propagate attacker-controlled input across distinct components.",
                "confidence": item.get("confidence", ""),
            }
        ]
    return []


def _derive_confidence_breakdown(item: dict[str, Any]) -> dict[str, Any]:
    overall = str(item.get("confidence", "") or "")
    return {
        "overall": overall,
        "attacker_control": overall if item.get("attacker_control", {}).get("summary") else "",
        "reachability": overall if item.get("reachability", {}).get("summary") else "",
        "impact": overall if item.get("impact") else "",
        "notes": "",
    }


def _locations_from_text(text: str, *, role: str) -> list[dict[str, Any]]:
    files = list(_FILE_LOC_RE.finditer(text))
    symbols = [match.group(1) or match.group(2) or "" for match in _SYMBOL_RE.finditer(text)]
    rows = []
    for index, match in enumerate(files):
        file_path = _normalize_repo_file_hint(match.group(1) or "")
        lines = match.group(2) or ""
        symbol = symbols[index] if index < len(symbols) else ""
        rows.append({"file": file_path, "symbol": symbol, "lines": lines, "role": role})
    return rows


def _role_from_text(text: str) -> str:
    lower = text.lower()
    if any(token in lower for token in ("entry", "ingest", "accept", "request", "reachable")):
        return "entrypoint"
    if any(token in lower for token in ("dispatch", "invoke", "fetch", "write", "read", "sink", "api")):
        return "sink"
    return "evidence"


def _entrypoint_name_from_text(text: str, location: dict[str, Any]) -> str:
    lower = text.lower()
    if "walletconnect" in lower:
        return "WalletConnect request handling"
    if "preview" in lower:
        return "preview ingestion"
    return location.get("symbol") or location.get("file") or "entrypoint"


def _entrypoint_kind_from_text(text: str) -> str:
    lower = text.lower()
    if "walletconnect" in lower:
        return "walletconnect_request"
    if "metadata" in lower or "preview" in lower:
        return "metadata_ingestion"
    if "request" in lower:
        return "request_handler"
    return "code_path"


def _sink_name_from_text(text: str, location: dict[str, Any]) -> str:
    lower = text.lower()
    if "confirm" in lower:
        return "confirmation bypass path"
    if "fetch" in lower:
        return "fetch helper"
    if "dispatch" in lower or "invoke" in lower:
        return "command dispatch"
    return location.get("symbol") or location.get("file") or "sink"


def _sink_kind_from_text(text: str) -> str:
    lower = text.lower()
    if "fetch" in lower or "network" in lower:
        return "network_sink"
    if "confirm" in lower or "permission" in lower:
        return "authorization_sink"
    if "dispatch" in lower or "invoke" in lower or "api" in lower:
        return "rpc_sink"
    return "sensitive_operation"


def _privilege_from_text(text: str, file_path: str) -> str:
    lower = text.lower()
    if "network" in lower or "fetch" in lower:
        return "outbound_network"
    if "confirm" in lower or "permission" in lower or "bypass" in lower:
        return "authorization_state"
    if "wallet api" in lower or "rpc" in lower or "command" in lower:
        return "wallet_rpc"
    if "/electron/" in file_path.replace("\\", "/"):
        return "main_process_capability"
    return "sensitive_capability"


def _surface_from_file(file_path: str) -> str:
    normalized = file_path.replace("\\", "/")
    if "/electron/" in normalized:
        return "main_process"
    if "/components/" in normalized or "/hooks/" in normalized or "/gui/" in normalized:
        return "renderer"
    return "application"


def _component_from_file(file_path: str) -> str:
    normalized = file_path.replace("\\", "/")
    if "/electron/" in normalized:
        return "component.main_process"
    if "/hooks/" in normalized:
        return "component.hooks"
    if "/components/" in normalized:
        return "component.renderer"
    if "/api/" in normalized:
        return "component.api"
    if normalized:
        parts = normalized.split("/")
        if len(parts) >= 3:
            return "component." + ".".join(parts[:3]).replace("@", "at")
    return ""


def _dedupe_locations(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    out = []
    for row in rows:
        key = (row.get("file", ""), row.get("symbol", ""), row.get("lines", ""), row.get("role", ""))
        if not row.get("file") or key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def _dedupe_entrypoints_or_sinks(rows: list[dict[str, Any]], *, key: str) -> list[dict[str, Any]]:
    seen = set()
    out = []
    for row in rows:
        location = row.get("location", {})
        dedupe_key = (row.get("name", ""), row.get("kind", ""), row.get(key, ""), location.get("file", ""), location.get("symbol", ""))
        if not location.get("file"):
            continue
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        out.append(row)
    return out


def _dedupe_strings(values: list[str]) -> list[str]:
    seen = set()
    out = []
    for value in values:
        normalized = str(value).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        out.append(normalized)
    return out


def _is_valid_repo_file_hint(value: str) -> bool:
    text = str(value or "").strip()
    return "/" in text and bool(_FILE_LOC_RE.fullmatch(text))


def _normalize_repo_file_hint(value: str) -> str:
    text = str(value or "").strip().replace("\\", "/")
    if not text:
        return ""
    for marker in ("packages/", "src/", "crates/", "python/"):
        idx = text.find(marker)
        if idx != -1:
            return text[idx:]
    return text


def _basename_without_extension(path: str) -> str:
    name = str(path).replace("\\", "/").rsplit("/", 1)[-1]
    if "." in name:
        return name.rsplit(".", 1)[0]
    return name
