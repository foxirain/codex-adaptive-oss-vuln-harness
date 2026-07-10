from __future__ import annotations

import json
import shutil
from pathlib import Path

from oss_harness.executor import parse_duration, run_codex_exec
from oss_harness.findings import finding_slug
from oss_harness.paths import safe_output_relative
from oss_harness.structured import load_json_response, require_nonempty_text


REPRO_STATUSES = {'success', 'partial', 'physically_impossible'}


def run_repro(
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
    repro_dir = session_dir / 'repro'
    repro_dir.mkdir(parents=True, exist_ok=True)
    succeeded = 0
    failures: list[dict] = []

    for finding_file in finding_files:
        slug = finding_slug(finding_file)
        item_dir = repro_dir / slug
        if item_dir.exists():
            shutil.rmtree(item_dir)
        item_dir.mkdir(parents=True, exist_ok=True)
        response_file = item_dir / 'codex-response.txt'
        stdout_file = item_dir / 'codex.stdout.txt'
        stderr_file = item_dir / 'codex.stderr.txt'
        prompt = _repro_prompt(session_dir, repo_root, finding_file, item_dir)
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
            files = _validate_repro_envelope(envelope)
            for relative, content in files.items():
                destination = item_dir.joinpath(*relative.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                resolved_parent = destination.parent.resolve()
                resolved_root = item_dir.resolve()
                if destination.is_symlink() or (resolved_parent != resolved_root and resolved_root not in resolved_parent.parents):
                    raise ValueError(f'unsafe repro output destination: {relative}')
                destination.write_text(content.rstrip() + '\n', encoding='utf-8')
            repro_script = item_dir / 'repro.sh'
            repro_script.chmod(repro_script.stat().st_mode | 0o100)
            succeeded += 1
        except (OSError, ValueError, TypeError) as exc:
            failures.append({'finding': str(finding_file), 'returncode': artifacts.returncode, 'error': str(exc)})
    (repro_dir / 'failures.json').write_text(json.dumps({'failures': failures}, indent=2) + '\n', encoding='utf-8')
    return {
        'repro_dir': str(repro_dir),
        'requested': str(len(finding_files)),
        'succeeded': str(succeeded),
        'failed': str(len(failures)),
        'count': str(succeeded),
    }


def _repro_prompt(session_dir: Path, repo_root: Path, finding_file: Path, item_dir: Path) -> str:
    review_json = session_dir / 'review' / finding_slug(finding_file) / 'review.json'
    return f'''You are building a realistic reproduction package for one vulnerability finding.

Repository root: {repo_root}
Session directory: {session_dir}
Finding file: {finding_file}
Optional review json: {review_json}
Do not modify the repository or create files. Return one exact JSON object:
{{
  "status": "success|partial|physically_impossible",
  "files": [
    {{"path": "repro.sh", "content": "..."}},
    {{"path": "result.md", "content": "..."}}
  ]
}}

You may add text helper files under relative paths in `files`. Never use absolute paths or `..`.

Rules:
- Try to produce the strongest realistic reproduction or PoC path possible.
- Use the repository's real build, test, demo, or runtime surfaces when practical.
- If exact end-to-end reproduction is blocked, still produce the best achievable harness and explain the blockers.
- Mark `physically_impossible` only if reproduction truly requires unavailable hardware or impossible external conditions.
- A missing dependency, local setup gap, or lack of time is not enough to mark impossible.
- If QEMU, containers, local fixtures, crafted payloads, or config files would help, generate the closest realistic repro assets you can.

Requirements for repro.sh:
- one-shot shell script
- use bash
- be as automated as practical
- create or reuse any helper files in the same directory
- include comments only when they materially clarify a tricky setup step

Requirements for result.md:
- begin with: `Status: success`, `Status: partial`, or `Status: physically_impossible`
- explain exactly what was reproduced or what remains blocked
- list the command to run repro.sh
- describe expected output or observable security effect

Return only the JSON object. Do not use a Markdown code fence or add commentary.
'''


def _validate_repro_envelope(envelope: dict) -> dict:
    status = require_nonempty_text(envelope.get('status'), 'status').lower()
    if status not in REPRO_STATUSES:
        raise ValueError(f'invalid repro status: {status}')
    raw_files = envelope.get('files')
    if not isinstance(raw_files, list) or not 2 <= len(raw_files) <= 32:
        raise ValueError('files must contain between 2 and 32 file objects')
    files: dict = {}
    total_bytes = 0
    for index, raw in enumerate(raw_files):
        if not isinstance(raw, dict):
            raise ValueError(f'files[{index}] must be an object')
        relative = safe_output_relative(require_nonempty_text(raw.get('path'), f'files[{index}].path'))
        content = require_nonempty_text(raw.get('content'), f'files[{index}].content')
        if relative in files:
            raise ValueError(f'duplicate repro file: {relative}')
        total_bytes += len(content.encode('utf-8'))
        if total_bytes > 2_000_000:
            raise ValueError('repro output exceeds the 2 MB limit')
        files[relative] = content
    required = {safe_output_relative('repro.sh'), safe_output_relative('result.md')}
    if not required.issubset(files):
        raise ValueError('repro output must include repro.sh and result.md')
    first_line = files[safe_output_relative('result.md')].splitlines()[0].strip().lower()
    if first_line != f'status: {status}':
        raise ValueError('result.md status must match the envelope status')
    return files
