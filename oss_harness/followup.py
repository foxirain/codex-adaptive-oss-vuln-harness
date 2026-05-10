from __future__ import annotations

import re
from pathlib import Path


def render_followup_snippet(repo_root: Path, target: str, *, radius: int = 4, body_lines: int = 28) -> str:
    rel_path, symbol = _split_target(target)
    if not rel_path:
        return ''
    source_path = repo_root / rel_path
    if not source_path.exists() or not source_path.is_file():
        return ''
    try:
        lines = source_path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except OSError:
        return ''
    if not lines:
        return ''

    symbol_name = _symbol_leaf(symbol)
    line_no = _find_symbol_line(lines, symbol_name) if symbol_name else None
    if line_no is None:
        if symbol:
            line_no = _find_symbol_line(lines, symbol)
        if line_no is None:
            line_no = 1
    start = max(1, line_no - radius)
    end = min(len(lines), max(line_no + body_lines, start + body_lines))
    header = f'## follow-up snippet {rel_path}'
    if symbol:
        header += f' :: {symbol}'
    body = '\n'.join(f"{idx:>6} {lines[idx - 1]}" for idx in range(start, end + 1))
    return f'{header}\n{body}\n'


def _split_target(target: str) -> tuple[str, str]:
    text = str(target or '').strip().strip('`')
    if not text:
        return '', ''
    text = text.replace('` / `', '::')
    text = re.sub(r'`\s*/\s*`', '::', text)
    text = re.sub(r'\s*::\s*', '::', text)
    if '/' in text and '::' not in text:
        left, right = text.rsplit('/', 1)
        if '.' in left.rsplit('/', 1)[-1] and right and '/' not in right and ' ' not in right:
            text = f'{left}::{right}'
    match = re.match(r'^(.*\.[A-Za-z0-9_+-]+):([A-Za-z_][A-Za-z0-9_.$-]*)$', text)
    if match:
        text = f"{match.group(1)}::{match.group(2)}"
    for sep in ('::', '#'):
        if sep in text:
            left, right = text.split(sep, 1)
            return left.strip(), right.strip()
    return text.strip(), ''


def _symbol_leaf(symbol: str) -> str:
    text = symbol.strip().strip('`')
    if not text:
        return ''
    for sep in ('.', '::', '#'):
        if sep in text:
            text = text.split(sep)[-1]
    return text.strip()


def _find_symbol_line(lines: list[str], symbol: str) -> int | None:
    if not symbol:
        return None
    escaped = re.escape(symbol)
    patterns = [
        re.compile(rf'^\s*(?:export\s+)?(?:async\s+)?function\s+{escaped}\b'),
        re.compile(rf'^\s*(?:export\s+)?(?:const|let|var)\s+{escaped}\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_][A-Za-z0-9_]*\s*=>)'),
        re.compile(rf'^\s*(?:async\s+)?def\s+{escaped}\b'),
        re.compile(rf'^\s*(?:pub\s+)?fn\s+{escaped}\b'),
        re.compile(rf'^\s*func\s+(?:\([^)]*\)\s*)?{escaped}\b'),
        re.compile(rf'^\s*{escaped}\s*\([^)]*\)\s*\{{?\s*$'),
        re.compile(rf'^\s*{escaped}\s*:\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>)'),
    ]
    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        for pattern in patterns:
            if pattern.search(line):
                return index
    fallback = re.compile(rf'\b{escaped}\b')
    for index, line in enumerate(lines, start=1):
        if fallback.search(line):
            return index
    return None
