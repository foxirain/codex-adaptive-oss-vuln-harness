from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path

from oss_harness.executor import parse_duration, run_codex_exec
from oss_harness.paths import safe_repo_file
from oss_harness.structured import load_json_response, require_nonempty_text


ALLOWED_SIGNAL_SOURCES = {'syzbot', 'oss-fuzz', 'clusterfuzz', 'sanitizer', 'advisory', 'cve', 'issue', 'pr', 'git', 'hardening', 'manual'}


def run_bootstrap(
    repo_root: Path,
    *,
    policy_path: Path,
    signals_path: Path,
    out_dir: Path,
    timeout_spec: str,
    model: str,
    reasoning_effort: str,
    sandbox: str,
    full_auto: bool,
    unsafe_bypass: bool,
) -> dict[str, str]:
    repo_root = repo_root.expanduser().resolve()
    policy_path = policy_path.expanduser().resolve()
    signals_path = signals_path.expanduser().resolve()
    out_dir = out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / 'BOOTSTRAP_SUMMARY.md'
    response_file = out_dir / 'bootstrap-response.txt'
    stdout_file = out_dir / 'bootstrap.stdout.txt'
    stderr_file = out_dir / 'bootstrap.stderr.txt'
    failure_path = out_dir / 'bootstrap.failure.txt'
    failure_path.unlink(missing_ok=True)

    prompt = _bootstrap_prompt(repo_root)
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
    failure = ''
    if artifacts.returncode != 0:
        failure = f'codex exited with status {artifacts.returncode}'
    else:
        try:
            payload = load_json_response(response_file)
            policy_markdown = require_nonempty_text(payload.get('policy_markdown'), 'policy_markdown')
            summary_markdown = require_nonempty_text(payload.get('summary_markdown'), 'summary_markdown')
            signals = _validate_signals(repo_root, payload.get('signals'))
            policy_path.parent.mkdir(parents=True, exist_ok=True)
            signals_path.parent.mkdir(parents=True, exist_ok=True)
            policy_path.write_text(policy_markdown.rstrip() + '\n', encoding='utf-8')
            signals_path.write_text(json.dumps({'signals': signals}, indent=2) + '\n', encoding='utf-8')
            summary_path.write_text(summary_markdown.rstrip() + '\n', encoding='utf-8')
        except (OSError, ValueError, TypeError) as exc:
            failure = str(exc)
    if failure:
        failure_path.write_text(failure + '\n', encoding='utf-8')
    return {
        'policy': str(policy_path),
        'signals': str(signals_path),
        'summary': str(summary_path),
        'response_file': str(response_file),
        'stdout_file': str(stdout_file),
        'stderr_file': str(stderr_file),
        'returncode': str(artifacts.returncode),
        'requested': '1',
        'succeeded': '0' if failure else '1',
        'failed': '1' if failure else '0',
        'failure': failure,
    }


def _bootstrap_prompt(repo_root: Path) -> str:
    today = datetime.now(UTC).strftime('%Y-%m-%d')
    return f'''You are preparing a Codex OSS vulnerability-hunting harness bootstrap for a repository.

Repository root: {repo_root}
Today (UTC): {today}

You must use both:
1. web search for latest project policy / advisory / security-process data
2. local repository analysis for actual attack surface, entrypoints, hot paths, and likely sinks

Do not modify the repository or create files. Return one exact JSON object as your final response.

Requirements for the policy file:
- Write a final `.codex-harness.md` ready for direct harness use.
- Use the exact section structure below and fill every section with concrete content.
- Keep section semantics strict:
  - `In Scope`: vulnerability classes and security boundaries only, no paths
  - `Out of Scope`: excluded bug classes / operational exclusions only, no paths
  - `Entry Points`: real attacker-controlled inputs only
  - `Include Paths` / `Exclude Paths`: repository paths only
  - `Hot Paths`: high-priority paths or files only
  - `Preferred Sinks`: sink categories only
  - `Preferred Bug Classes`: bug classes only
- Keep the scope narrow enough for reachable, CVE-quality hunting.
- Use absolute dates when summarizing policy, releases, or advisories.

Exact policy file structure:
# Project Policy

## Project Summary
## In Scope
## Out of Scope
## Focus Areas
## Forbidden Findings
## Entry Points
## Include Paths
## Exclude Paths
## Languages
## Framework Hints
## Hot Paths
## Preferred Sinks
## Preferred Bug Classes
## Ignore Patterns
## Notes

Final response schema:
{{
  "policy_markdown": "complete policy Markdown",
  "signals": [
      {{
        "path": "...",
        "source": "...",
        "weight": 9,
        "summary": "...",
        "metadata": {{...}}
      }}
  ],
  "summary_markdown": "short bootstrap summary Markdown"
}}

Requirements for `signals`:
- Use only repository-internal paths.
- Exclude tests, examples, docs, generated code, and vendor dependencies.
- Identify the project type first, then prioritize the strongest matching artifact sources.
- Include high-signal evidence only:
  - recent security / fix / hardening / follow-up / revert commits
  - advisory / CVE / security bulletin references
  - crash / sanitizer / fuzz artifacts
  - panic / overflow / use-after-free / OOB / traversal / auth bypass issues or PRs
  - files adjacent to recent fixes or on the same trust boundary
- Allowed source labels: syzbot, oss-fuzz, clusterfuzz, sanitizer, advisory, cve, issue, pr, git, hardening, manual
- Each signal should reflect confidence through weight and metadata.

Requirements for `summary_markdown`:
- Keep it short.
- Include:
  - project_type
  - best_external_sources
  - policy_basis
  - ambiguous_areas
  - output_files

Return only the JSON object. Do not use a Markdown code fence or add commentary.
'''


def _validate_signals(repo_root: Path, value: object) -> list[dict]:
    if not isinstance(value, list):
        raise ValueError('signals must be a JSON array')
    validated: list[dict] = []
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise ValueError(f'signals[{index}] must be an object')
        path = require_nonempty_text(raw.get('path'), f'signals[{index}].path').replace('\\', '/')
        if safe_repo_file(repo_root, path) is None:
            raise ValueError(f'signals[{index}].path is not a repository-internal file: {path}')
        source = require_nonempty_text(raw.get('source'), f'signals[{index}].source').lower()
        if source not in ALLOWED_SIGNAL_SOURCES:
            raise ValueError(f'signals[{index}].source is not allowed: {source}')
        weight = raw.get('weight')
        if isinstance(weight, bool) or not isinstance(weight, int) or not 1 <= weight <= 15:
            raise ValueError(f'signals[{index}].weight must be an integer from 1 to 15')
        summary = require_nonempty_text(raw.get('summary'), f'signals[{index}].summary')
        metadata = raw.get('metadata', {})
        if not isinstance(metadata, dict):
            raise ValueError(f'signals[{index}].metadata must be an object')
        validated.append({'path': path, 'source': source, 'weight': weight, 'summary': summary, 'metadata': metadata})
    return validated
