from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from oss_harness.ingest import parse_response

AUTOPILOT_FINDINGS_DIRNAME = 'autopilot/findings'


def finding_dir(session_dir: Path) -> Path:
    return session_dir / AUTOPILOT_FINDINGS_DIRNAME


def list_finding_files(session_dir: Path) -> list[Path]:
    base = finding_dir(session_dir)
    if not base.exists():
        return []
    return sorted(path for path in base.glob('finding-*.txt') if path.is_file() and not path.is_symlink())


def select_finding_files(session_dir: Path, selectors: list[str] | None = None) -> list[Path]:
    files = list_finding_files(session_dir)
    base = finding_dir(session_dir).resolve()
    if not selectors:
        return files
    selected: list[Path] = []
    for selector in selectors:
        selector_path = Path(selector)
        if selector_path.exists():
            resolved = selector_path.expanduser().resolve()
            try:
                resolved.relative_to(base)
            except ValueError:
                continue
            if not selector_path.is_symlink() and resolved.is_file():
                selected.append(resolved)
            continue
        for candidate in files:
            if selector == candidate.name or selector == candidate.stem or selector in candidate.name:
                selected.append(candidate)
    deduped: list[Path] = []
    seen: set[str] = set()
    for path in selected:
        key = str(path.resolve())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)
    return deduped


def finding_slug(path: Path) -> str:
    stem = re.sub(r'[^a-zA-Z0-9._-]+', '-', path.stem).strip('-').lower() or 'finding'
    suffix = hashlib.sha1(str(path).encode('utf-8')).hexdigest()[:8]
    return f'{stem}-{suffix}'


def finding_verdict(path: Path) -> str:
    metadata_path = path.with_suffix('.json')
    if metadata_path.exists():
        try:
            metadata = json.loads(metadata_path.read_text(encoding='utf-8'))
            verdict = str(metadata.get('verdict', '') or '')
            content_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            if metadata.get('content_sha256') == content_hash and verdict in {'cve_candidate', 'plausible_security_bug', 'latent_bug', 'discarding', 'needs_more_context'}:
                return verdict
        except (OSError, ValueError, TypeError):
            pass
    try:
        text = path.read_text(encoding='utf-8')
    except OSError:
        return ''
    try:
        return str(parse_response(text)['verdict'])
    except ValueError:
        return ''


def filter_finding_files_by_verdict(finding_files: list[Path], allowed_verdicts: set[str]) -> list[Path]:
    return [path for path in finding_files if finding_verdict(path) in allowed_verdicts]
