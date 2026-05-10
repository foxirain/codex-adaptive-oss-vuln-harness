from __future__ import annotations

import hashlib
import re
from pathlib import Path

AUTOPILOT_FINDINGS_DIRNAME = 'autopilot/findings'


def finding_dir(session_dir: Path) -> Path:
    return session_dir / AUTOPILOT_FINDINGS_DIRNAME


def list_finding_files(session_dir: Path) -> list[Path]:
    base = finding_dir(session_dir)
    if not base.exists():
        return []
    return sorted(path for path in base.glob('finding-*.txt') if path.is_file())


def select_finding_files(session_dir: Path, selectors: list[str] | None = None) -> list[Path]:
    files = list_finding_files(session_dir)
    if not selectors:
        return files
    selected: list[Path] = []
    for selector in selectors:
        selector_path = Path(selector)
        if selector_path.exists():
            selected.append(selector_path.expanduser().resolve())
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
    try:
        text = path.read_text(encoding='utf-8')
    except OSError:
        return ''
    for line in text.splitlines()[:8]:
        lowered = line.strip().strip('`').lower()
        if lowered.startswith('strict verdict:'):
            lowered = lowered.split(':', 1)[1].strip().strip('`')
        if lowered.startswith('- '):
            lowered = lowered[2:].strip().strip('`')
        if lowered == 'cve_candidate':
            return 'cve_candidate'
        if lowered == 'plausible_security_bug':
            return 'plausible_security_bug'
        if lowered == 'latent_bug':
            return 'latent_bug'
        if lowered == 'discarding':
            return 'discarding'
        if lowered == 'needs_more_context':
            return 'needs_more_context'
        if lowered == 'not_cve_candidate':
            return 'discarding'
    return ''


def filter_finding_files_by_verdict(finding_files: list[Path], allowed_verdicts: set[str]) -> list[Path]:
    return [path for path in finding_files if finding_verdict(path) in allowed_verdicts]
