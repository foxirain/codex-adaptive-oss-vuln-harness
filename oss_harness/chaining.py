from __future__ import annotations

import json
from pathlib import Path

from oss_harness.executor import parse_duration, run_codex_exec
from oss_harness.paths import normalize_repo_target
from oss_harness.structured import load_json_response, require_nonempty_text


def run_chain_analysis(
    session_dir: Path,
    *,
    repo_root: Path,
    finding_files: list[Path],
    timeout_spec: str,
    model: str,
    reasoning_effort: str,
    sandbox: str,
    full_auto: bool,
    unsafe_bypass: bool,
    batch_size: int,
) -> dict[str, str]:
    session_dir = session_dir.expanduser().resolve()
    chain_dir = session_dir / 'chain'
    chain_dir.mkdir(parents=True, exist_ok=True)
    batches = [finding_files[index:index + batch_size] for index in range(0, len(finding_files), batch_size)]
    succeeded = 0
    failures: list[dict] = []
    completed_summaries: list[Path] = []

    for index, batch in enumerate(batches, start=1):
        item_dir = chain_dir / f'batch-{index:03d}'
        item_dir.mkdir(parents=True, exist_ok=True)
        summary_json = item_dir / 'chain_summary.json'
        summary_md = item_dir / 'chain_summary.md'
        response_file = item_dir / 'codex-response.txt'
        stdout_file = item_dir / 'codex.stdout.txt'
        stderr_file = item_dir / 'codex.stderr.txt'
        for stale in (summary_json, summary_md):
            stale.unlink(missing_ok=True)
        prompt = _chain_prompt(session_dir, repo_root, batch, summary_json, summary_md)
        artifacts = run_codex_exec(
            repo_root=repo_root,
            prompt_text=prompt,
            response_file=response_file,
            stdout_file=stdout_file,
            stderr_file=stderr_file,
            timeout_seconds=parse_duration(timeout_spec),
            model=model,
            reasoning_effort=reasoning_effort,
            sandbox=sandbox,
            full_auto=full_auto,
            unsafe_bypass=unsafe_bypass,
        )
        try:
            if artifacts.returncode != 0:
                raise ValueError(f'codex exited with status {artifacts.returncode}')
            envelope = load_json_response(response_file)
            summary = _validate_chain_summary(envelope.get('summary'), repo_root=repo_root, finding_files=batch)
            markdown = require_nonempty_text(envelope.get('markdown'), 'markdown')
            summary_json.write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
            summary_md.write_text(markdown.rstrip() + '\n', encoding='utf-8')
            succeeded += 1
            completed_summaries.append(summary_json)
        except (OSError, ValueError, TypeError) as exc:
            failures.append({'batch': index, 'error': str(exc), 'returncode': artifacts.returncode})

    index_path = chain_dir / 'chain_index.json'
    summary_path = chain_dir / 'CHAIN_SUMMARY.md'
    _write_chain_index(chain_dir, index_path, summary_path, summary_files=completed_summaries)
    (chain_dir / 'failures.json').write_text(json.dumps({'failures': failures}, indent=2) + '\n', encoding='utf-8')
    return {
        'chain_dir': str(chain_dir),
        'summary': str(summary_path),
        'index': str(index_path),
        'requested': str(len(batches)),
        'succeeded': str(succeeded),
        'failed': str(len(failures)),
        'count': str(succeeded),
        'findings': str(len(finding_files)),
    }


def _chain_prompt(session_dir: Path, repo_root: Path, finding_files: list[Path], summary_json: Path, summary_md: Path) -> str:
    finding_lines = '\n'.join(f'- {path}' for path in finding_files)
    return f'''You are analyzing a batch of latent bug findings to support follow-up chaining and variant hunting.

Repository root: {repo_root}
Session directory: {session_dir}

Latent finding files:
{finding_lines}

Read every finding file and inspect the repository code only as needed to connect them.

Goal:
- do not assign S/A/B/C/D tiers
- do not re-review each finding independently as if it were a final report
- organize these latent findings into chaining material for future exploration

Do not modify files. Return one exact JSON object with this envelope:
{{
  "summary": <the chain summary object described below>,
  "markdown": "the concise Markdown summary"
}}

JSON schema:
{{
  "batch_size": {len(finding_files)},
  "clusters": [
    {{
      "cluster_id": "cluster-1",
      "theme": "",
      "finding_files": ["..."],
      "shared_entrypoints": ["..."],
      "shared_sinks": ["..."],
      "shared_boundaries": ["..."],
      "priority": "high|medium|low",
      "why_it_matters": "",
      "promote_first": ["..."],
      "chain_next": ["..."],
      "duplicates_or_near_duplicates": ["..."],
      "notes": ["..."]
    }}
  ],
  "top_chain_targets": ["..."],
  "top_promotion_candidates": ["..."],
  "drop_or_deprioritize": ["..."]
}}

Markdown requirements:
- short batch overview
- cluster sections
- top chain targets
- top promotion candidates
- duplicate or low-value findings to deprioritize

Be pragmatic. Prefer grouping by shared trust boundary, sink family, or code adjacency. The output should help a future agent decide what to inspect next, not score each finding like a report review.
Return only the JSON object. Do not use a Markdown code fence or add commentary.
'''


def _validate_chain_summary(value: object, *, repo_root: Path, finding_files: list[Path]) -> dict:
    if not isinstance(value, dict):
        raise ValueError('summary must be a JSON object')
    if value.get('batch_size') != len(finding_files):
        raise ValueError('summary.batch_size does not match the requested batch')
    clusters = value.get('clusters')
    if not isinstance(clusters, list) or any(not isinstance(item, dict) for item in clusters):
        raise ValueError('summary.clusters must be an array of objects')
    allowed_findings = {path.name for path in finding_files}
    normalized_clusters: list[dict] = []
    for index, cluster in enumerate(clusters):
        normalized = dict(cluster)
        for field in ('cluster_id', 'theme', 'priority', 'why_it_matters'):
            normalized[field] = require_nonempty_text(cluster.get(field), f'clusters[{index}].{field}')
        if normalized['priority'] not in {'high', 'medium', 'low'}:
            raise ValueError(f'clusters[{index}].priority is invalid')
        for field in ('finding_files', 'shared_entrypoints', 'shared_sinks', 'shared_boundaries', 'promote_first', 'chain_next', 'duplicates_or_near_duplicates', 'notes'):
            raw = cluster.get(field)
            if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
                raise ValueError(f'clusters[{index}].{field} must be an array of strings')
            normalized[field] = [item.strip() for item in raw if item.strip()]
        if not set(normalized['finding_files']).issubset(allowed_findings):
            raise ValueError(f'clusters[{index}].finding_files contains an unknown finding')
        normalized_clusters.append(normalized)
    normalized_targets: dict[str, list[str]] = {}
    for field in ('top_chain_targets', 'top_promotion_candidates', 'drop_or_deprioritize'):
        raw = value.get(field)
        if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
            raise ValueError(f'summary.{field} must be an array of strings')
        if field == 'drop_or_deprioritize':
            normalized_targets[field] = [item.strip() for item in raw if item.strip()]
        else:
            normalized_targets[field] = [normalize_repo_target(repo_root, item) for item in raw if item.strip()]
    return {'batch_size': len(finding_files), 'clusters': normalized_clusters, **normalized_targets}


def _write_chain_index(chain_dir: Path, index_path: Path, summary_path: Path, *, summary_files: list[Path] | None = None) -> None:
    items: list[dict] = []
    sources = sorted(summary_files) if summary_files is not None else sorted(chain_dir.glob('batch-*/chain_summary.json'))
    for summary_json in sources:
        try:
            data = json.loads(summary_json.read_text(encoding='utf-8'))
        except Exception:
            continue
        data['_path'] = str(summary_json)
        items.append(data)
    index_path.write_text(json.dumps({'batches': items}, indent=2), encoding='utf-8')

    lines = ['# Chain Summary', '']
    for index, item in enumerate(items, start=1):
        cluster_count = len(item.get('clusters', []))
        top_targets = ', '.join(item.get('top_chain_targets', [])[:5]) or 'none'
        lines.append(f'- Batch {index}: clusters={cluster_count} top_chain_targets={top_targets}')
    summary_path.write_text('\n'.join(lines).rstrip() + '\n', encoding='utf-8')
