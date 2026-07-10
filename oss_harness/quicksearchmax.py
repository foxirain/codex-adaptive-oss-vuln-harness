from __future__ import annotations

import argparse
import json
import re
from copy import deepcopy
from pathlib import Path

from oss_harness.findings import finding_verdict
from oss_harness.paths import normalize_repo_target
from oss_harness.review_schema import normalize_and_validate_review_record
from oss_harness.reviewing import TIER_ORDER

HOT_PUBLIC_SOURCES = {
    'advisory',
    'clusterfuzz',
    'crash',
    'cve',
    'issue',
    'oss-fuzz',
    'pr',
    'sanitizer',
    'syzbot',
}
HOTRISK_ALLOWED_SOURCES = HOT_PUBLIC_SOURCES | {'git', 'hardening'}
COLDRISK_PREFERRED_SOURCES = {'git', 'hardening', 'manual'}
COLDRISK_PREFERRED_EVIDENCE = {
    'auth_boundary',
    'archive_sink',
    'sink',
    'manifest_boundary',
    'entrypoint_hot_path',
}
COLDRISK_UNDERWATCHED_PATH_HINTS = {
    'runtime',
    'cron',
    'crons',
    'init',
    'download',
    'run-user-scripts',
    'stream',
    'utils',
    'bootstrap',
    'vc_init',
}
COLDRISK_OBVIOUS_HOT_PATH_HINTS = {
    'detect',
    'detector',
    'resolve',
    'resolver',
    'entrypoint',
    'routing',
    'router',
}
RISK_KEYWORDS = {
    'acl',
    'auth',
    'authorize',
    'bounds',
    'credentials',
    'csrf',
    'deserialize',
    'deserialization',
    'file write',
    'handshake',
    'header',
    'jwt',
    'memory',
    'overflow',
    'panic',
    'parser',
    'path traversal',
    'permission',
    'privilege',
    'request smuggling',
    'route',
    'rpc',
    'sandbox',
    'signature',
    'sql',
    'ssrf',
    'tls',
    'token',
    'transport',
    'traversal',
    'trust boundary',
    'uaf',
    'unsafe',
    'upload',
    'xss',
    'xxe',
}
CONFIDENCE_ORDER = {'high': 3, 'medium': 2, 'low': 1}
DEFAULT_SESSION_ORDER = ['default', 'nosignal', 'coldrisk', 'hotrisk']


def build_variant_signals(input_path: Path, output_path: Path, variant: str) -> dict[str, object]:
    input_path = input_path.expanduser().resolve()
    output_path = output_path.expanduser().resolve()
    payload = json.loads(input_path.read_text(encoding='utf-8'))
    signals = payload.get('signals', [])
    transformed = []
    for item in signals:
        if not isinstance(item, dict):
            continue
        adapted = _adapt_signal(item, variant)
        if adapted is not None:
            transformed.append(adapted)
    if not transformed:
        transformed = _fallback_variant_signals(signals, variant)
    transformed = _dedupe_signals(transformed)
    output = {'signals': transformed}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2), encoding='utf-8')
    return {'variant': variant, 'input': str(input_path), 'output': str(output_path), 'count': len(transformed)}


def ensure_empty_review(session_dir: Path) -> dict[str, object]:
    session_dir = session_dir.expanduser().resolve()
    review_dir = session_dir / 'review'
    review_dir.mkdir(parents=True, exist_ok=True)
    index_path = review_dir / 'review_index.json'
    summary_path = review_dir / 'REVIEW_SUMMARY.md'
    payload = {'reviews': []}
    index_path.write_text(json.dumps(payload, indent=2), encoding='utf-8')
    summary_path.write_text('# Review Summary\n', encoding='utf-8')
    return {'review_dir': str(review_dir), 'summary': str(summary_path), 'index': str(index_path), 'count': 0}


def merge_chain_indexes(session_dirs: dict[str, Path], output_dir: Path) -> dict[str, object]:
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    session_order = [name for name in DEFAULT_SESSION_ORDER if name in session_dirs] + sorted(
        name for name in session_dirs if name not in DEFAULT_SESSION_ORDER
    )
    merged_batches: list[dict[str, object]] = []
    target_counts: dict[str, int] = {}
    promotion_counts: dict[str, int] = {}
    total_clusters = 0
    invalid_batches: list[dict[str, str]] = []

    for session_name in session_order:
        session_dir = session_dirs[session_name].expanduser().resolve()
        chain_index_path = session_dir / 'chain' / 'chain_index.json'
        if not chain_index_path.exists():
            continue
        try:
            chain_index = json.loads(chain_index_path.read_text(encoding='utf-8'))
            if not isinstance(chain_index, dict) or not isinstance(chain_index.get('batches'), list):
                raise ValueError('chain_index.batches must be an array')
            repo_root = _session_repo_root(session_dir)
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            invalid_batches.append({'session': session_name, 'error': str(exc)})
            continue
        for position, batch in enumerate(chain_index['batches'], start=1):
            try:
                _validate_merged_chain_batch(batch)
            except ValueError as exc:
                invalid_batches.append({'session': session_name, 'batch': str(position), 'error': str(exc)})
                continue
            item = deepcopy(batch)
            item['session'] = session_name
            item['session_batch'] = position
            item['session_dir'] = str(session_dir)
            item['chain_json'] = str(batch.get('_path', ''))
            try:
                top_targets = [normalize_repo_target(repo_root, value) for value in item['top_chain_targets'] if value.strip()]
                promotion_targets = [normalize_repo_target(repo_root, value) for value in item['top_promotion_candidates'] if value.strip()]
            except ValueError as exc:
                invalid_batches.append({'session': session_name, 'batch': str(position), 'error': str(exc)})
                continue
            item['top_chain_targets'] = top_targets
            item['top_promotion_candidates'] = promotion_targets
            item['cluster_count'] = len(item.get('clusters', []))
            total_clusters += int(item['cluster_count'])
            for target in top_targets:
                target_counts[target] = target_counts.get(target, 0) + 1
            for target in promotion_targets:
                promotion_counts[target] = promotion_counts.get(target, 0) + 1
            merged_batches.append(item)

    merged_batches.sort(
        key=lambda item: (
            -int(item.get('cluster_count', 0)),
            -len(item.get('top_chain_targets', [])),
            _session_sort_index(str(item.get('session', '')), session_order),
            int(item.get('session_batch', 10_000) or 10_000),
        )
    )
    for index, item in enumerate(merged_batches, start=1):
        item['merged_rank'] = index

    top_chain_targets = _sorted_count_rows(target_counts)
    top_promotion_candidates = _sorted_count_rows(promotion_counts)
    index_payload = {
        'session_order': session_order,
        'batch_count': len(merged_batches),
        'cluster_count': total_clusters,
        'top_chain_targets': top_chain_targets,
        'top_promotion_candidates': top_promotion_candidates,
        'batches': merged_batches,
        'invalid_batches': invalid_batches,
    }
    index_path = output_dir / 'chain_index.json'
    summary_path = output_dir / 'CHAIN_SUMMARY.md'
    index_path.write_text(json.dumps(index_payload, indent=2), encoding='utf-8')
    summary_path.write_text(
        _render_merged_chain_summary(
            merged_batches,
            top_chain_targets=top_chain_targets,
            top_promotion_candidates=top_promotion_candidates,
        ),
        encoding='utf-8',
    )
    return {'chain_dir': str(output_dir), 'summary': str(summary_path), 'index': str(index_path), 'count': len(merged_batches), 'failed': len(invalid_batches)}


def merge_review_indexes(session_dirs: dict[str, Path], output_dir: Path) -> dict[str, object]:
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    session_order = [name for name in DEFAULT_SESSION_ORDER if name in session_dirs] + sorted(
        name for name in session_dirs if name not in DEFAULT_SESSION_ORDER
    )
    merged_items: list[dict[str, object]] = []
    latent_items: list[dict[str, object]] = []
    invalid_reviews: list[dict[str, str]] = []

    for session_name in session_order:
        session_dir = session_dirs[session_name].expanduser().resolve()
        review_index_path = session_dir / 'review' / 'review_index.json'
        if review_index_path.exists():
            try:
                review_index = json.loads(review_index_path.read_text(encoding='utf-8'))
                if not isinstance(review_index, dict) or not isinstance(review_index.get('reviews'), list):
                    raise ValueError('review_index.reviews must be an array')
                repo_root = _session_repo_root(session_dir)
            except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
                invalid_reviews.append({'session': session_name, 'error': str(exc)})
                continue
            for position, review in enumerate(review_index['reviews'], start=1):
                try:
                    item = normalize_and_validate_review_record(deepcopy(review), repo_root=repo_root)
                except ValueError as exc:
                    invalid_reviews.append({'session': session_name, 'position': str(position), 'error': str(exc)})
                    continue
                item['session'] = session_name
                item['session_rank'] = position
                item['session_dir'] = str(session_dir)
                item['review_json'] = str(review.get('_path', ''))
                item['sessions'] = [session_name]
                item['session_hits'] = [
                    {
                        'session': session_name,
                        'tier': item.get('tier'),
                        'confidence': item.get('confidence'),
                        'disposition': item.get('disposition'),
                        'session_rank': position,
                        'finding_file': item.get('finding_file'),
                        'summary': item.get('summary', ''),
                        'review_json': item.get('review_json', ''),
                        'session_dir': item.get('session_dir', ''),
                    }
                ]
                item['merged_score'] = _merged_score(item)
                merged_items.append(item)

        findings_dir = session_dir / 'autopilot' / 'findings'
        if findings_dir.exists():
            for finding_file in sorted(findings_dir.glob('finding-*.txt')):
                if finding_verdict(finding_file) != 'latent_bug':
                    continue
                latent_items.append(
                    {
                        'session': session_name,
                        'session_dir': str(session_dir),
                        'finding_file': finding_file.name,
                        'finding_path': str(finding_file),
                        'title': _latent_title(finding_file),
                        'summary': _latent_summary(finding_file),
                    }
                )

    raw_review_count = len(merged_items)
    grouped: dict[tuple, dict[str, object]] = {}
    for item in merged_items:
        identity = _review_identity(item)
        existing = grouped.get(identity)
        if existing is None:
            grouped[identity] = item
            continue
        combined_hits = list(existing.get('session_hits', [])) + list(item.get('session_hits', []))
        combined_sessions = list(dict.fromkeys([str(hit.get('session', '')) for hit in combined_hits if isinstance(hit, dict)]))
        if int(item.get('merged_score', 0)) > int(existing.get('merged_score', 0)):
            representative = item
        else:
            representative = existing
        representative['session_hits'] = combined_hits
        representative['sessions'] = combined_sessions
        representative['duplicate_count'] = len(combined_hits)
        grouped[identity] = representative
    merged_items = list(grouped.values())

    merged_items.sort(
        key=lambda item: (
            -int(item.get('merged_score', 0)),
            _session_sort_index(str(item.get('session', '')), session_order),
            int(item.get('session_rank', 10_000) or 10_000),
            str(item.get('title', '')).lower(),
            str(item.get('summary', '')).lower(),
        )
    )
    for index, item in enumerate(merged_items, start=1):
        item['merged_rank'] = index

    unique_review_count = len(merged_items)

    index_payload = {
        'session_order': session_order,
        'review_count': unique_review_count,
        'raw_review_count': raw_review_count,
        'unique_review_count': unique_review_count,
        'reviews': merged_items,
        'latent_findings': latent_items,
        'invalid_reviews': invalid_reviews,
    }
    index_path = output_dir / 'review_index.json'
    summary_path = output_dir / 'REVIEW_SUMMARY.md'
    index_path.write_text(json.dumps(index_payload, indent=2), encoding='utf-8')
    summary_path.write_text(_render_merged_review_summary(merged_items, latent_items=latent_items), encoding='utf-8')
    return {
        'review_dir': str(output_dir),
        'summary': str(summary_path),
        'index': str(index_path),
        'count': len(merged_items),
        'raw_count': raw_review_count,
        'unique_count': unique_review_count,
        'failed': len(invalid_reviews),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='python -m oss_harness.quicksearchmax')
    subparsers = parser.add_subparsers(dest='command', required=True)

    build_parser = subparsers.add_parser('build-signals', help='Build a quicksearchmax signal variant from bootstrap output.')
    build_parser.add_argument('--variant', choices=['coldrisk', 'hotrisk'], required=True)
    build_parser.add_argument('--input', type=Path, required=True)
    build_parser.add_argument('--output', type=Path, required=True)

    empty_review_parser = subparsers.add_parser('init-empty-review', help='Create empty review artifacts for a session with no findings.')
    empty_review_parser.add_argument('--session-dir', type=Path, required=True)

    merge_parser = subparsers.add_parser('merge-reviews', help='Merge per-session review indexes into one ranking.')
    merge_parser.add_argument('--out', type=Path, required=True)
    merge_parser.add_argument(
        '--session',
        action='append',
        default=[],
        metavar='NAME=DIR',
        help='Session review source in NAME=DIR form. Repeatable.',
    )
    chain_merge_parser = subparsers.add_parser('merge-chains', help='Merge per-session chain indexes into one summary.')
    chain_merge_parser.add_argument('--out', type=Path, required=True)
    chain_merge_parser.add_argument(
        '--session',
        action='append',
        default=[],
        metavar='NAME=DIR',
        help='Session chain source in NAME=DIR form. Repeatable.',
    )

    args = parser.parse_args(argv)
    if args.command == 'build-signals':
        result = build_variant_signals(args.input, args.output, args.variant)
        for key, value in result.items():
            print(f'{key}={value}')
        return 0
    if args.command == 'init-empty-review':
        result = ensure_empty_review(args.session_dir)
        for key, value in result.items():
            print(f'{key}={value}')
        return 0
    if args.command == 'merge-reviews':
        session_dirs = _parse_session_dirs(args.session)
        result = merge_review_indexes(session_dirs, args.out)
        for key, value in result.items():
            print(f'{key}={value}')
        return 1 if int(result.get('failed', 0) or 0) else 0
    if args.command == 'merge-chains':
        session_dirs = _parse_session_dirs(args.session)
        result = merge_chain_indexes(session_dirs, args.out)
        for key, value in result.items():
            print(f'{key}={value}')
        return 1 if int(result.get('failed', 0) or 0) else 0
    parser.error(f'unknown command: {args.command}')
    return 2


def _parse_session_dirs(raw_values: list[str]) -> dict[str, Path]:
    session_dirs: dict[str, Path] = {}
    for raw in raw_values:
        if '=' not in raw:
            raise SystemExit(f'invalid --session value: {raw}')
        name, directory = raw.split('=', 1)
        session_dirs[name.strip()] = Path(directory.strip())
    return session_dirs


def _session_repo_root(session_dir: Path) -> Path:
    manifest_path = session_dir / 'targets.json'
    if not manifest_path.exists():
        raise ValueError(f'missing session manifest: {manifest_path}')
    payload = json.loads(manifest_path.read_text(encoding='utf-8'))
    if not isinstance(payload, dict) or not isinstance(payload.get('repo_root'), str) or not payload['repo_root'].strip():
        raise ValueError(f'invalid repo_root in session manifest: {manifest_path}')
    repo_root = Path(payload['repo_root']).expanduser().resolve()
    if not repo_root.is_dir():
        raise ValueError(f'session repository is unavailable: {repo_root}')
    return repo_root


def _validate_merged_chain_batch(batch: object) -> None:
    if not isinstance(batch, dict):
        raise ValueError('chain batch must be an object')
    clusters = batch.get('clusters')
    if not isinstance(clusters, list) or any(not isinstance(item, dict) for item in clusters):
        raise ValueError('chain batch clusters must be an array of objects')
    for field in ('top_chain_targets', 'top_promotion_candidates'):
        values = batch.get(field)
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            raise ValueError(f'chain batch {field} must be an array of strings')
    for index, cluster in enumerate(clusters):
        for field in ('finding_files', 'shared_entrypoints', 'shared_sinks', 'shared_boundaries', 'promote_first', 'chain_next', 'duplicates_or_near_duplicates', 'notes'):
            values = cluster.get(field)
            if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                raise ValueError(f'clusters[{index}].{field} must be an array of strings')


def _review_identity(item: dict[str, object]) -> tuple[tuple[tuple[str, str, str], ...], str]:
    locations: list[tuple[str, str, str]] = []
    for value in item.get('evidence_locations', []):
        if not isinstance(value, dict):
            continue
        locations.append(('evidence', str(value.get('file', '')).lower(), str(value.get('symbol', '')).lower()))
    for field, role in (('entrypoints', 'entrypoint'), ('sinks', 'sink')):
        for value in item.get(field, []):
            if not isinstance(value, dict) or not isinstance(value.get('location'), dict):
                continue
            location = value['location']
            locations.append((role, str(location.get('file', '')).lower(), str(location.get('symbol', '')).lower()))
    canonical_locations = tuple(sorted(set(location for location in locations if location[1])))
    normalized_title = _normalize_text(str(item.get('title', '')))
    return canonical_locations, normalized_title


def _adapt_signal(item: dict[str, object], variant: str) -> dict[str, object] | None:
    signal = deepcopy(item)
    path = str(signal.get('path', '')).strip().replace('\\', '/')
    source = str(signal.get('source', 'external')).strip().lower()
    summary = str(signal.get('summary', '')).strip()
    metadata = dict(signal.get('metadata', {}) or {})
    weight = int(signal.get('weight', 0) or 0)
    context = _signal_context(path, summary, metadata)
    is_risky = _contains_risk_keywords(context)
    if variant == 'hotrisk':
        if source not in HOTRISK_ALLOWED_SOURCES:
            return None
        if weight < 8 and not is_risky:
            return None
        signal['weight'] = min(15, weight + (2 if source in HOT_PUBLIC_SOURCES else 1))
    elif variant == 'coldrisk':
        cold_score = _coldrisk_score(path, source=source, summary=summary, metadata=metadata, weight=weight, is_risky=is_risky)
        if cold_score <= 0:
            return None
        signal['weight'] = max(4, min(12, cold_score))
    else:
        raise ValueError(f'unsupported variant: {variant}')
    metadata['quicksearchmax_variant'] = variant
    signal['metadata'] = metadata
    signal['source'] = source or 'external'
    signal['path'] = path
    signal['summary'] = summary
    return signal


def _coldrisk_score(path: str, *, source: str, summary: str, metadata: dict[str, object], weight: int, is_risky: bool) -> int:
    if source not in COLDRISK_PREFERRED_SOURCES:
        return 0

    path_lower = path.lower()
    evidence = str(metadata.get('evidence', '')).strip().lower()
    bug_classes = [str(item).lower() for item in metadata.get('bug_classes', []) if isinstance(item, str)]
    sinks = [str(item).lower() for item in metadata.get('sinks', []) if isinstance(item, str)]
    underwatched = any(hint in path_lower for hint in COLDRISK_UNDERWATCHED_PATH_HINTS)
    obvious_hot = any(hint in path_lower for hint in COLDRISK_OBVIOUS_HOT_PATH_HINTS)

    score = weight
    if source == 'manual':
        score += 3
    elif source == 'hardening':
        score += 1
    elif source == 'git':
        score -= 3

    if evidence in COLDRISK_PREFERRED_EVIDENCE:
        score += 3
    if underwatched:
        score += 2
    if obvious_hot:
        score -= 4
    if metadata.get('adjacent_to_fix'):
        score -= 2
    if evidence == 'recent_fix':
        score -= 2
    if evidence == 'entrypoint_hot_path' and source == 'manual':
        score += 1
    if any('auth' in item or 'header' in item or 'archive' in item or 'ipc' in item for item in bug_classes + sinks):
        score += 2
    if any('command injection' in item for item in bug_classes):
        score += 1
    if is_risky:
        score += 1

    if source == 'git' and not underwatched:
        score -= 2
    if source == 'git' and obvious_hot:
        return 0
    if source == 'hardening' and not (underwatched or is_risky):
        score -= 2

    return score


def _fallback_variant_signals(signals: list[object], variant: str) -> list[dict[str, object]]:
    fallback: list[dict[str, object]] = []
    for raw in signals:
        if not isinstance(raw, dict):
            continue
        signal = deepcopy(raw)
        source = str(signal.get('source', 'external')).strip().lower()
        weight = int(signal.get('weight', 0) or 0)
        path = str(signal.get('path', '')).strip().replace('\\', '/')
        summary = str(signal.get('summary', '')).strip()
        metadata = dict(signal.get('metadata', {}) or {})
        is_risky = _contains_risk_keywords(_signal_context(path, summary, metadata))
        if variant == 'hotrisk':
            if source not in HOTRISK_ALLOWED_SOURCES:
                continue
            if weight < 6:
                continue
            signal['weight'] = min(15, weight + 1)
        else:
            cold_score = _coldrisk_score(path, source=source, summary=summary, metadata=metadata, weight=weight, is_risky=is_risky)
            if cold_score <= 0:
                continue
            signal['weight'] = max(4, min(12, cold_score))
        metadata['quicksearchmax_variant'] = variant
        signal['metadata'] = metadata
        fallback.append(signal)
    return sorted(fallback, key=_signal_sort_key)


def _dedupe_signals(signals: list[dict[str, object]]) -> list[dict[str, object]]:
    deduped: list[dict[str, object]] = []
    seen: set[tuple[str, str, str]] = set()
    for signal in sorted(signals, key=_signal_sort_key):
        key = (
            str(signal.get('path', '')),
            str(signal.get('source', '')),
            _normalize_text(str(signal.get('summary', ''))),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(signal)
    return deduped


def _signal_sort_key(signal: dict[str, object]) -> tuple[int, str, str, str]:
    return (
        -int(signal.get('weight', 0) or 0),
        str(signal.get('path', '')),
        str(signal.get('source', '')),
        str(signal.get('summary', '')),
    )


def _signal_context(path: str, summary: str, metadata: dict[str, object]) -> str:
    pieces = [path, summary]
    for key, value in metadata.items():
        if isinstance(value, (str, int, float)):
            pieces.append(f'{key} {value}')
        elif isinstance(value, list):
            pieces.extend(str(item) for item in value)
    return ' '.join(pieces)


def _contains_risk_keywords(text: str) -> bool:
    lowered = text.lower()
    return any(keyword in lowered for keyword in RISK_KEYWORDS)


def _merged_score(item: dict[str, object]) -> int:
    tier_score = TIER_ORDER.get(str(item.get('tier', 'D')).upper(), 0)
    confidence_score = CONFIDENCE_ORDER.get(str(item.get('confidence', 'low')).lower(), 0)
    session_rank = int(item.get('session_rank', 10_000) or 10_000)
    return tier_score * 100_000 + confidence_score * 10_000 + max(0, 1000 - min(session_rank, 1000))


def _session_sort_index(session: str, session_order: list[str]) -> int:
    try:
        return session_order.index(session)
    except ValueError:
        return len(session_order)


def _sorted_count_rows(counts: dict[str, int]) -> list[dict[str, object]]:
    rows = [{'target': target, 'count': count} for target, count in counts.items()]
    rows.sort(key=lambda item: (-int(item['count']), str(item['target']).lower()))
    return rows


def _render_merged_review_summary(items: list[dict[str, object]], *, latent_items: list[dict[str, object]] | None = None) -> str:
    lines = ['# Merged Review Summary', '', '## Merged Ranking', '']
    for item in items:
        title = item.get('title') or item.get('finding_file') or 'untitled finding'
        session = str(item.get('session', ''))
        session_rank = item.get('session_rank', '?')
        summary = str(item.get('summary', '')).strip()
        lines.append(f"{item.get('merged_rank', '?')}. [{item.get('tier', 'D')}] {title} (session: {session}, session_rank: {session_rank})")
        if summary:
            lines.append(f'   {summary}')
    for tier in ['S', 'A', 'B', 'C', 'D']:
        tier_items = [item for item in items if str(item.get('tier', '')).upper() == tier]
        if not tier_items:
            continue
        lines.extend(['', f'## {tier} Tier', ''])
        for item in tier_items:
            title = item.get('title') or item.get('finding_file') or 'untitled finding'
            session = str(item.get('session', ''))
            session_rank = item.get('session_rank', '?')
            lines.append(f"- #{item.get('merged_rank', '?')} {title} (session: {session}, session_rank: {session_rank})")
    latent_items = latent_items or []
    if latent_items:
        lines.extend(['', '## Chain: latent_bug', ''])
        for item in latent_items:
            title = item.get('title') or item.get('finding_file') or 'untitled latent finding'
            session = str(item.get('session', ''))
            summary = str(item.get('summary', '')).strip()
            lines.append(f"- {title} (session: {session})")
            if summary:
                lines.append(f'  {summary}')
    return '\n'.join(lines).rstrip() + '\n'


def _latent_title(finding_file: Path) -> str:
    for line in finding_file.read_text(encoding='utf-8').splitlines():
        stripped = line.strip()
        lowered = stripped.lower()
        if lowered.startswith('title:'):
            return stripped.split(':', 1)[1].strip()
        if lowered.startswith('# '):
            return stripped[2:].strip()
        if lowered.startswith('summary:'):
            candidate = stripped.split(':', 1)[1].strip()
            if candidate:
                return candidate
    return finding_file.name


def _latent_summary(finding_file: Path) -> str:
    lines = finding_file.read_text(encoding='utf-8').splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        lowered = stripped.lower()
        if lowered.startswith('summary:'):
            candidate = stripped.split(':', 1)[1].strip()
            if candidate:
                return candidate
            for follow in lines[index + 1:index + 4]:
                follow_stripped = follow.strip().lstrip('-').strip()
                if follow_stripped:
                    return follow_stripped
    for line in lines:
        stripped = line.strip().lstrip('-').strip()
        if stripped and not stripped.lower().startswith('strict verdict'):
            return stripped
    return ''


def _render_merged_chain_summary(
    items: list[dict[str, object]],
    *,
    top_chain_targets: list[dict[str, object]],
    top_promotion_candidates: list[dict[str, object]],
) -> str:
    lines = ['# Merged Chain Summary', '']
    if top_chain_targets:
        lines.extend(['## Top Chain Targets', ''])
        for row in top_chain_targets[:10]:
            lines.append(f"- {row['target']} ({row['count']} batches)")
        lines.append('')
    if top_promotion_candidates:
        lines.extend(['## Top Promotion Candidates', ''])
        for row in top_promotion_candidates[:10]:
            lines.append(f"- {row['target']} ({row['count']} batches)")
        lines.append('')
    lines.extend(['## Batch Ranking', ''])
    for item in items:
        session = str(item.get('session', ''))
        session_batch = item.get('session_batch', '?')
        cluster_count = int(item.get('cluster_count', 0) or 0)
        top_targets = ', '.join(item.get('top_chain_targets', [])[:5]) or 'none'
        lines.append(
            f"{item.get('merged_rank', '?')}. session={session} batch={session_batch} "
            f"clusters={cluster_count} top_chain_targets={top_targets}"
        )
    return '\n'.join(lines).rstrip() + '\n'


def _normalize_text(text: str) -> str:
    lowered = text.strip().lower()
    lowered = re.sub(r'[^a-z0-9]+', ' ', lowered)
    lowered = re.sub(r'\s+', ' ', lowered).strip()
    return lowered


if __name__ == '__main__':
    raise SystemExit(main())
