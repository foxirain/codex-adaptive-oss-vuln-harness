from __future__ import annotations

import json
from pathlib import Path

from oss_harness.executor import parse_duration, run_codex_exec
from oss_harness.findings import finding_slug
from oss_harness.review_schema import normalize_and_validate_review_record, structured_review_schema_text
from oss_harness.structured import load_json_response, require_nonempty_text

TIER_ORDER = {'S': 5, 'A': 4, 'B': 3, 'C': 2, 'D': 1}


def run_review(
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
) -> dict[str, str]:
    session_dir = session_dir.expanduser().resolve()
    review_dir = session_dir / 'review'
    review_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []
    failures: list[dict] = []

    for finding_file in finding_files:
        slug = finding_slug(finding_file)
        item_dir = review_dir / slug
        item_dir.mkdir(parents=True, exist_ok=True)
        result_json = item_dir / 'review.json'
        result_md = item_dir / 'review.md'
        response_file = item_dir / 'codex-response.txt'
        stdout_file = item_dir / 'codex.stdout.txt'
        stderr_file = item_dir / 'codex.stderr.txt'
        for stale in (result_json, result_md):
            stale.unlink(missing_ok=True)
        prompt = _review_prompt(session_dir, repo_root, finding_file, result_json, result_md)
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
            review = normalize_and_validate_review_record(envelope.get('review'), repo_root=repo_root)
            if review['finding_file'] != finding_file.name:
                raise ValueError(f"review finding_file must be {finding_file.name}")
            markdown = require_nonempty_text(envelope.get('markdown'), 'markdown')
            result_json.write_text(json.dumps(review, indent=2) + '\n', encoding='utf-8')
            result_md.write_text(markdown.rstrip() + '\n', encoding='utf-8')
            results.append({'finding': str(finding_file), 'returncode': artifacts.returncode, 'json': str(result_json), 'markdown': str(result_md)})
        except (OSError, ValueError, TypeError) as exc:
            failures.append({'finding': str(finding_file), 'returncode': artifacts.returncode, 'error': str(exc)})

    summary_path = review_dir / 'REVIEW_SUMMARY.md'
    index_path = review_dir / 'review_index.json'
    completed_reviews = [Path(item['json']) for item in results]
    _write_review_summary(review_dir, summary_path, index_path, repo_root=repo_root, review_files=completed_reviews)
    (review_dir / 'failures.json').write_text(json.dumps({'failures': failures}, indent=2) + '\n', encoding='utf-8')
    return {
        'review_dir': str(review_dir),
        'summary': str(summary_path),
        'index': str(index_path),
        'requested': str(len(finding_files)),
        'succeeded': str(len(results)),
        'failed': str(len(failures)),
        'count': str(len(results)),
    }


def _review_prompt(session_dir: Path, repo_root: Path, finding_file: Path, result_json: Path, result_md: Path) -> str:
    return f'''You are reviewing one vulnerability finding for realism and quality.

Repository root: {repo_root}
Session directory: {session_dir}
Finding file: {finding_file}

Read the finding file, inspect the repository code, and decide how strong the claim is.

Tier definitions:
- S: confirmed or near-confirmed; the finding is well-supported and report-ready
- A: strong; probably valid but missing one or two supporting details
- B: plausible; worth keeping, but major proof gaps remain
- C: weak; likely overstated or too incomplete for reporting
- D: reject; not a credible vulnerability finding

Do not modify files. Return one exact JSON object with this envelope:
{{
  "review": <the review object described below>,
  "markdown": "the concise Markdown review"
}}

JSON schema:
{structured_review_schema_text()}

Structured review requirements:
- Keep the existing flat summary fields (`summary`, `impact`, `key_evidence`, `blocking_gaps`, `next_actions`).
- Also fill the structured fields. Dual-write is required.
- `attacker_control`, `reachability`, `entrypoints`, `sinks`, and `evidence_locations` are required.
- `candidate_components` and `candidate_boundaries` should be filled whenever the code evidence supports them.
- `capabilities`, `preconditions`, `affected_assets`, `candidate_policies`, `candidate_invariants`, `exploit_path`, and `confidence_breakdown` are strongly preferred; use empty arrays/empty strings when unknown.
- `entrypoints`, `sinks`, and `evidence_locations` must use exact repo-relative files when possible.
- Do not use `null` for any field. Use `[]`, `""`, or an object with empty-string fields instead.
- Do not collapse `attacker_control` or `reachability` into flat strings. They must be JSON objects matching the schema.
- If you cannot find a sink or entrypoint confidently, still emit an empty array; do not omit the key.
- Treat missing structured fields as an invalid answer.

Markdown review requirements:
- title
- tier
- one-paragraph verdict
- evidence bullets
- gaps bullets
- recommended next action bullets

Be strict. Do not rubber-stamp. Downgrade findings that lack a concrete attacker-controlled entrypoint, a sensitive sink, or a realistic impact path.
Return only the JSON object. Do not use a Markdown code fence or add commentary.
'''


def _write_review_summary(review_dir: Path, summary_path: Path, index_path: Path, *, repo_root: Path | None = None, review_files: list[Path] | None = None) -> None:
    items: list[dict] = []
    sources = sorted(review_files) if review_files is not None else sorted(review_dir.glob('*/review.json'))
    for review_json in sources:
        try:
            data = normalize_and_validate_review_record(json.loads(review_json.read_text(encoding='utf-8')), repo_root=repo_root)
        except Exception:
            continue
        review_json.write_text(json.dumps(data, indent=2), encoding='utf-8')
        data['_path'] = str(review_json)
        items.append(data)
    items.sort(key=lambda item: (-TIER_ORDER.get(str(item.get('tier', 'D')).upper(), 0), str(item.get('title', ''))))
    index_path.write_text(json.dumps({'reviews': items}, indent=2), encoding='utf-8')

    lines = ['# Review Summary', '']
    for tier in ['S', 'A', 'B', 'C', 'D']:
        tier_items = [item for item in items if str(item.get('tier', '')).upper() == tier]
        if not tier_items:
            continue
        lines.extend([f'## {tier} Tier', ''])
        for item in tier_items:
            lines.append(f"- {item.get('title') or item.get('finding_file')}: {item.get('summary', '')}")
        lines.append('')
    summary_path.write_text('\n'.join(lines).rstrip() + '\n', encoding='utf-8')


def _normalize_review_json_file(path: Path, *, repo_root: Path | None = None) -> dict:
    payload = json.loads(path.read_text(encoding='utf-8'))
    normalized = normalize_and_validate_review_record(payload, repo_root=repo_root)
    path.write_text(json.dumps(normalized, indent=2) + '\n', encoding='utf-8')
    return normalized
