from __future__ import annotations

import json
from pathlib import Path

from oss_harness.executor import parse_duration, run_codex_exec


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

    for index, batch in enumerate(batches, start=1):
        item_dir = chain_dir / f'batch-{index:03d}'
        item_dir.mkdir(parents=True, exist_ok=True)
        summary_json = item_dir / 'chain_summary.json'
        summary_md = item_dir / 'chain_summary.md'
        response_file = item_dir / 'codex-response.txt'
        stdout_file = item_dir / 'codex.stdout.txt'
        stderr_file = item_dir / 'codex.stderr.txt'
        prompt = _chain_prompt(session_dir, repo_root, batch, summary_json, summary_md)
        run_codex_exec(
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
            add_dirs=[session_dir, chain_dir, item_dir],
        )

    index_path = chain_dir / 'chain_index.json'
    summary_path = chain_dir / 'CHAIN_SUMMARY.md'
    _write_chain_index(chain_dir, index_path, summary_path)
    return {'chain_dir': str(chain_dir), 'summary': str(summary_path), 'index': str(index_path), 'count': str(len(finding_files)), 'batches': str(len(batches))}


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

Output requirements:
1. Write JSON to {summary_json}
2. Write concise markdown to {summary_md}

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
After writing both files, print a short confirmation with the number of clusters and top chain targets.
'''


def _write_chain_index(chain_dir: Path, index_path: Path, summary_path: Path) -> None:
    items: list[dict] = []
    for summary_json in sorted(chain_dir.glob('batch-*/chain_summary.json')):
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
