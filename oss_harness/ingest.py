from __future__ import annotations

import re
from pathlib import Path

VERDICT_RULES = [
    ('cve_candidate', 'cve_candidate'),
    ('cve candidate', 'cve_candidate'),
    ('plausible_security_bug', 'plausible_security_bug'),
    ('plausible security bug', 'plausible_security_bug'),
    ('latent_bug', 'latent_bug'),
    ('latent bug but not currently reachable', 'latent_bug'),
    ('latent bug', 'latent_bug'),
    ('needs_more_context', 'needs_more_context'),
    ('needs more context', 'needs_more_context'),
    ('discarding', 'discarding'),
    ('discarded', 'discarding'),
    ('discard', 'discarding'),
    ('not a cve candidate', 'discarding'),
    ('not_a_cve_candidate', 'discarding'),
    ('not_cve_candidate', 'discarding'),
    ('not a security issue', 'discarding'),
]

VERDICT_PATTERNS = [
    re.compile(r'strict verdict\s*:\s*[-*]?\s*(?P<value>[^\n]*)', re.IGNORECASE),
    re.compile(r'final verdict\s*:\s*[-*]?\s*(?P<value>[^\n]*)', re.IGNORECASE),
]

NEXT_PATTERNS = [
    re.compile(r'single best next (?:target|file|function)\s*:\s*[-*]?\s*(?P<value>[^\n]*)', re.IGNORECASE),
    re.compile(r'single next (?:target|file|function)\s*:\s*[-*]?\s*(?P<value>[^\n]*)', re.IGNORECASE),
]

BULLET_VALUE_PATTERNS = [re.compile(r'^\s*[-*]\s*(?P<value>.+?)\s*$')]


def load_response(path: Path | None, stdin_text: str) -> str:
    if path is not None:
        return path.read_text(encoding='utf-8')
    return stdin_text


def parse_response(text: str) -> dict:
    verdict = _extract_verdict(text)
    next_target = _extract_next_target(text)
    notes = _extract_notes(text)
    should_continue = bool(next_target) and verdict not in {'cve_candidate', 'plausible_security_bug'}
    return {
        'verdict': verdict,
        'next_target': next_target,
        'notes': notes,
        'should_continue': should_continue,
    }


def _extract_verdict(text: str) -> str:
    lines = text.splitlines()
    verdicts: list[str] = []
    for pattern in VERDICT_PATTERNS:
        for index, line in enumerate(lines):
            match = pattern.search(line)
            if not match:
                continue
            value = _normalize_inline_value(match.group('value'))
            if not value and index + 1 < len(lines):
                value = _extract_bullet_value(lines[index + 1])
            mapped = _map_verdict(value)
            if not mapped:
                raise ValueError(f'invalid strict verdict: {value!r}')
            verdicts.append(mapped)
    if len(verdicts) != 1:
        raise ValueError(f'expected exactly one strict verdict, found {len(verdicts)}')
    return verdicts[0]


def _extract_next_target(text: str) -> str:
    lines = text.splitlines()
    values: list[str] = []
    for pattern in NEXT_PATTERNS:
        for index, line in enumerate(lines):
            match = pattern.search(line)
            if not match:
                continue
            value = _normalize_inline_value(match.group('value'))
            if not value and index + 1 < len(lines):
                value = _extract_bullet_value(lines[index + 1])
            values.append(value)
    if len(values) > 1:
        raise ValueError(f'expected at most one next target, found {len(values)}')
    if not values or values[0].lower() in {'none', 'n/a', 'na', '없음'}:
        return ''
    return values[0]


def _extract_notes(text: str, limit: int = 320) -> str:
    compact = ' '.join(line.strip() for line in text.splitlines() if line.strip())
    compact = re.sub(r'\s+', ' ', compact)
    return compact[:limit]


def _normalize_inline_value(value: str) -> str:
    value = value.strip()
    if value in {'', '-', '*'}:
        return ''
    return value.strip('` ')


def _extract_bullet_value(line: str) -> str:
    for pattern in BULLET_VALUE_PATTERNS:
        match = pattern.match(line)
        if match:
            return match.group('value').strip().strip('`')
    return ''


def _map_verdict(value: str) -> str:
    if not value:
        return ''
    lowered = value.lower().strip()
    for needle, mapped in VERDICT_RULES:
        if lowered == needle:
            return mapped
    return ''
