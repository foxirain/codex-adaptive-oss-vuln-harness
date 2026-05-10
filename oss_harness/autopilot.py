from __future__ import annotations

import json
import math
import re
import subprocess
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from oss_harness.bundle import ensure_prompt_bundle
from oss_harness.followup import render_followup_snippet
from oss_harness.ingest import parse_response
from oss_harness.session import (
    completed_ranks,
    load_state,
    record_review,
    response_archive_dir,
    response_path,
    save_state,
    set_pending_review,
)

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
MAX_MANUAL_FOLLOWUPS = 3
MAX_SAME_TARGET_ATTEMPTS = 3
STRONG_FINDING_VERDICTS = {'cve_candidate', 'plausible_security_bug', 'latent_bug'}
AUTOPILOT_DIRNAME = 'autopilot'
WATCHDOG_INTERVAL_SECONDS = 300
BANDIT_HALF_LIFE_STEPS = 8.0
SUBSYSTEM_EXPLORATION_WEIGHT = 0.85
TARGET_EXPLORATION_WEIGHT = 0.35
COST_WEIGHT = 0.35
EXPLORATION_FLOOR = 3
TARGET_RETRY_PENALTY = 0.35
TARGET_TIMEOUT_PENALTY = 0.80
SUBSYSTEM_TIMEOUT_PENALTY = 0.15
CREDIT_DECAY = 0.70
MAX_CREDIT_DEPTH = 3
PARSE_ERROR_REWARD = -0.60
FIXED_PREFIX_RANKS = 30
DYNAMIC_TAIL_SHORTLIST_SIZE = 15
TIMEOUT_REWARD = -0.80
VERDICT_REWARDS = {
    'cve_candidate': 1.00,
    'plausible_security_bug': 0.70,
    'latent_bug': 0.35,
    'needs_more_context': -0.15,
    'discarding': -0.25,
    'timeout': TIMEOUT_REWARD,
}


def run_autopilot(
    session_dir: Path,
    *,
    include_snippet: bool,
    duration_spec: str,
    per_run_timeout_spec: str,
    model: str,
    reasoning_effort: str,
    sandbox: str,
    full_auto: bool,
    unsafe_bypass: bool,
    stop_on_finding: bool,
) -> int:
    session_dir = session_dir.expanduser().resolve()
    manifest = _load_manifest(session_dir)
    autopilot_dir = session_dir / AUTOPILOT_DIRNAME
    prompts_dir = autopilot_dir / 'prompts'
    exec_dir = autopilot_dir / 'exec'
    findings_dir = autopilot_dir / 'findings'
    for path in (autopilot_dir, prompts_dir, exec_dir, findings_dir):
        path.mkdir(parents=True, exist_ok=True)

    progress_path = autopilot_dir / 'AUTOPILOT_PROGRESS.txt'
    findings_path = autopilot_dir / 'AUTOPILOT_FINDINGS.txt'
    status_path = autopilot_dir / 'AUTOPILOT_STATUS.txt'
    trace_path = autopilot_dir / 'AUTOPILOT_TRACE.tsv'
    watchdog_path = autopilot_dir / 'AUTOPILOT_WATCHDOG.txt'
    duration_seconds = _parse_duration(duration_spec)
    per_run_timeout_seconds = _parse_duration(per_run_timeout_spec)
    started_at = datetime.now(UTC)
    deadline = time.monotonic() + duration_seconds
    run_index = _existing_run_count(prompts_dir)

    _append_text(
        progress_path,
        f"\n== AUTOPILOT START {started_at.strftime('%Y-%m-%d %H:%M:%SZ')} ==\n"
        f"session={session_dir}\nrepo_root={manifest.get('repo_root', '')}\n"
        f"duration={duration_spec}\nper_run_timeout={per_run_timeout_spec}\n"
        f"include_snippet={int(include_snippet)}\nmodel={model or '<default>'}\n"
        f"reasoning_effort={reasoning_effort or '<default>'}\n",
    )
    _trace_event(
        trace_path,
        'autopilot_start',
        session_dir=str(session_dir),
        repo_root=str(manifest.get('repo_root', '')),
        duration=duration_spec,
        per_run_timeout=per_run_timeout_spec,
        include_snippet=int(include_snippet),
        model=model or '<default>',
        reasoning_effort=reasoning_effort or '<default>',
    )
    _write_bandit_artifacts(session_dir)
    _write_status(
        status_path,
        stage='starting',
        session_dir=session_dir,
        repo_root=manifest.get('repo_root', ''),
        started_at=started_at,
        duration_spec=duration_spec,
        runs=run_index,
        candidate_count=manifest.get('candidate_count', 0),
        bandit_step=load_state(session_dir).get('bandit', {}).get('global_step', 0),
    )

    while time.monotonic() < deadline:
        ingest_started = time.monotonic()
        result = _ingest_pending_response(
            session_dir,
            manifest,
            findings_dir,
            findings_path,
            progress_path,
            trace_path=trace_path,
        )
        _trace_event(trace_path, 'ingest_cycle', duration_ms=_duration_ms(ingest_started))
        if result is not None:
            _write_bandit_artifacts(session_dir)
            state = load_state(session_dir)
            _write_status(
                status_path,
                stage='ingested',
                session_dir=session_dir,
                repo_root=manifest.get('repo_root', ''),
                started_at=started_at,
                duration_spec=duration_spec,
                runs=run_index,
                last_target=result['target'],
                last_verdict=result['verdict'],
                last_next_target=result['next_target'],
                completed=len(state.get('history', [])),
                bandit_step=state.get('bandit', {}).get('global_step', 0),
            )
            if stop_on_finding and result['verdict'] in STRONG_FINDING_VERDICTS:
                _append_text(progress_path, 'stop_reason=strong_finding_detected\n')
                _trace_event(trace_path, 'stop', reason='strong_finding_detected', target=result['target'], verdict=result['verdict'])
                return 0

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break

        try:
            render_started = time.monotonic()
            next_prompt = _render_next_prompt(session_dir, include_snippet=include_snippet, trace_path=trace_path)
            _trace_event(
                trace_path,
                'render_next_prompt',
                duration_ms=_duration_ms(render_started),
                target=next_prompt['target'],
                rank=next_prompt['rank'],
                prompt_source=next_prompt['prompt_source'],
            )
        except SystemExit as exc:
            _append_text(progress_path, f'stop_reason={exc}\n')
            _trace_event(trace_path, 'stop', reason=str(exc))
            _write_status(
                status_path,
                stage='finished',
                session_dir=session_dir,
                repo_root=manifest.get('repo_root', ''),
                started_at=started_at,
                duration_spec=duration_spec,
                runs=run_index,
                bandit_step=load_state(session_dir).get('bandit', {}).get('global_step', 0),
            )
            return 0

        run_index += 1
        prompt_path = prompts_dir / f'run-{run_index:04d}.prompt.txt'
        stdout_path = exec_dir / f'run-{run_index:04d}.stdout.txt'
        stderr_path = exec_dir / f'run-{run_index:04d}.stderr.txt'
        prompt_text = _build_autopilot_prompt(next_prompt)
        prompt_path.write_text(prompt_text, encoding='utf-8')
        _append_text(
            progress_path,
            f"\n== RUN {run_index:04d} {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%SZ')} ==\n"
            f"rank={next_prompt['rank']}\n"
            f"target={next_prompt['target']}\n"
            f"prompt_source={next_prompt['prompt_source']}\n"
            f"fixed_response_file={response_path(session_dir)}\n",
        )
        _write_status(
            status_path,
            stage='running',
            session_dir=session_dir,
            repo_root=manifest.get('repo_root', ''),
            started_at=started_at,
            duration_spec=duration_spec,
            runs=run_index,
            current_target=next_prompt['target'],
            current_rank=next_prompt['rank'],
            target_attempts=_target_attempts(load_state(session_dir), next_prompt['target']),
            bandit_step=load_state(session_dir).get('bandit', {}).get('global_step', 0),
        )

        exec_started = time.monotonic()
        timeout_seconds = max(1, min(int(remaining), per_run_timeout_seconds))
        proc = _run_codex_exec(
            repo_root=next_prompt['repo_root'],
            prompt_text=prompt_text,
            response_file=response_path(session_dir),
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            timeout_seconds=timeout_seconds,
            model=model,
            reasoning_effort=reasoning_effort,
            sandbox=sandbox,
            full_auto=full_auto,
            unsafe_bypass=unsafe_bypass,
            watchdog_path=watchdog_path,
            watchdog_target=next_prompt['target'],
            watchdog_rank=next_prompt['rank'],
        )
        runtime_ms = _duration_ms(exec_started)
        _set_pending_execution_metadata(
            session_dir,
            target=next_prompt['target'],
            subsystem=next_prompt['subsystem'],
            runtime_ms=runtime_ms,
        )
        _trace_event(
            trace_path,
            'codex_exec',
            duration_ms=runtime_ms,
            target=next_prompt['target'],
            rank=next_prompt['rank'],
            exit_code=proc.returncode,
            timeout_seconds=timeout_seconds,
        )
        _append_text(progress_path, f'codex_exit_code={proc.returncode}\nstdout_file={stdout_path}\nstderr_file={stderr_path}\n')
        if proc.returncode != 0 and not _has_nonempty_response(response_path(session_dir)):
            failure = _classify_exec_failure(_read_text_file(stderr_path), proc.returncode)
            if failure['kind'] == 'timeout':
                timeout_result = _record_timeout_result(
                    session_dir,
                    manifest,
                    next_prompt,
                    runtime_ms,
                    progress_path,
                    trace_path=trace_path,
                )
                _write_bandit_artifacts(session_dir)
                _write_status(
                    status_path,
                    stage='timeout_recovered',
                    session_dir=session_dir,
                    repo_root=manifest.get('repo_root', ''),
                    started_at=started_at,
                    duration_spec=duration_spec,
                    runs=run_index,
                    last_target=timeout_result['target'],
                    last_verdict=timeout_result['verdict'],
                    completed=len(load_state(session_dir).get('history', [])),
                    bandit_step=load_state(session_dir).get('bandit', {}).get('global_step', 0),
                )
                continue

            stop_stage = failure['kind']
            stop_reason = failure['kind']
            state = load_state(session_dir)
            _append_text(
                progress_path,
                f"{stop_reason}_target={next_prompt['target']}\n"
                f"{stop_reason}_runtime_ms={runtime_ms}\n"
                f"stop_reason={stop_reason}\n"
                f"failure_detail={failure['detail']}\n",
            )
            _trace_event(
                trace_path,
                stop_stage,
                target=next_prompt['target'],
                rank=next_prompt['rank'],
                runtime_ms=runtime_ms,
                exit_code=proc.returncode,
                detail=failure['detail'],
            )
            _write_status(
                status_path,
                stage=stop_stage,
                stop_reason=stop_reason,
                session_dir=session_dir,
                repo_root=manifest.get('repo_root', ''),
                started_at=started_at,
                duration_spec=duration_spec,
                runs=run_index,
                current_target=next_prompt['target'],
                current_rank=next_prompt['rank'],
                pending_target=state.get('pending_target', ''),
                pending_rank=state.get('pending_rank'),
                failure_detail=failure['detail'],
                bandit_step=state.get('bandit', {}).get('global_step', 0),
            )
            return 75 if stop_stage == 'auth_expired' else (proc.returncode or 1)

    final_ingest_started = time.monotonic()
    _ingest_pending_response(
        session_dir,
        manifest,
        findings_dir,
        findings_path,
        progress_path,
        trace_path=trace_path,
    )
    _trace_event(trace_path, 'final_ingest_cycle', duration_ms=_duration_ms(final_ingest_started))
    _write_bandit_artifacts(session_dir)
    _write_status(
        status_path,
        stage='finished',
        session_dir=session_dir,
        repo_root=manifest.get('repo_root', ''),
        started_at=started_at,
        duration_spec=duration_spec,
        runs=run_index,
        bandit_step=load_state(session_dir).get('bandit', {}).get('global_step', 0),
    )
    _append_text(progress_path, f"== AUTOPILOT END {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%SZ')} ==\n")
    _trace_event(trace_path, 'autopilot_end', runs=run_index)
    return 0


def _run_codex_exec(
    *,
    repo_root: str,
    prompt_text: str,
    response_file: Path,
    stdout_path: Path,
    stderr_path: Path,
    timeout_seconds: int,
    model: str,
    reasoning_effort: str,
    sandbox: str,
    full_auto: bool,
    unsafe_bypass: bool,
    watchdog_path: Path,
    watchdog_target: str,
    watchdog_rank: int | None,
) -> subprocess.CompletedProcess[str]:
    cmd = ['codex', 'exec', '-C', repo_root, '--skip-git-repo-check', '--add-dir', str(PACKAGE_ROOT), '-o', str(response_file), '--color', 'never']
    if unsafe_bypass:
        cmd.append('--dangerously-bypass-approvals-and-sandbox')
    else:
        if full_auto:
            cmd.append('--full-auto')
        cmd.extend(['--sandbox', sandbox])
    if model:
        cmd.extend(['-m', model])
    if reasoning_effort:
        cmd.extend(['-c', f'model_reasoning_effort="{reasoning_effort}"'])

    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    stdout_path.write_text('', encoding='utf-8')
    stderr_path.write_text('', encoding='utf-8')

    started = time.monotonic()
    next_watchdog = WATCHDOG_INTERVAL_SECONDS
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(PACKAGE_ROOT),
    )
    if proc.stdin is not None:
        proc.stdin.write(prompt_text)
        proc.stdin.close()

    stdout_thread = threading.Thread(target=_stream_pipe_to_file, args=(proc.stdout, stdout_path), daemon=True)
    stderr_thread = threading.Thread(target=_stream_pipe_to_file, args=(proc.stderr, stderr_path), daemon=True)
    stdout_thread.start()
    stderr_thread.start()

    while True:
        elapsed = time.monotonic() - started
        remaining = timeout_seconds - elapsed
        if remaining <= 0:
            proc.kill()
            proc.wait()
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)
            with stderr_path.open('a', encoding='utf-8') as handle:
                handle.write('\nTIMEOUT\n')
            _write_watchdog_snapshot(
                watchdog_path,
                pid=proc.pid,
                target=watchdog_target,
                rank=watchdog_rank,
                elapsed_seconds=timeout_seconds,
                response_file=response_file,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                timed_out=True,
            )
            return subprocess.CompletedProcess(cmd, 124, _read_text_file(stdout_path), _read_text_file(stderr_path))

        exit_code = proc.poll()
        if exit_code is not None:
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)
            return subprocess.CompletedProcess(cmd, exit_code, _read_text_file(stdout_path), _read_text_file(stderr_path))

        if elapsed >= next_watchdog:
            _write_watchdog_snapshot(
                watchdog_path,
                pid=proc.pid,
                target=watchdog_target,
                rank=watchdog_rank,
                elapsed_seconds=int(elapsed),
                response_file=response_file,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                timed_out=False,
            )
            next_watchdog += WATCHDOG_INTERVAL_SECONDS
        time.sleep(5)


def _ingest_pending_response(
    session_dir: Path,
    manifest: dict,
    findings_dir: Path,
    findings_path: Path,
    progress_path: Path,
    *,
    trace_path: Path | None = None,
) -> dict | None:
    fixed_response = response_path(session_dir)
    state = load_state(session_dir)
    pending_target = (state.get('pending_target') or '').strip()
    if not pending_target or not fixed_response.exists() or fixed_response.stat().st_size == 0:
        return None
    text = fixed_response.read_text(encoding='utf-8')
    runtime_ms = int(state.get('pending_runtime_ms', 0) or 0)
    try:
        parsed = parse_response(text)
    except ValueError as exc:
        archive_path = _archive_response_file(session_dir, fixed_response)
        updated_state = record_review(
            session_dir=session_dir,
            rank=state.get('pending_rank'),
            target=pending_target,
            verdict='needs_more_context',
            notes=f'parse_error: {exc}',
            next_target='',
            next_prompt='',
            auto_advance=True,
        )
        summary = _record_bandit_outcome(
            updated_state,
            manifest,
            {
                'target': pending_target,
                'rank': state.get('pending_rank'),
                'verdict': 'needs_more_context',
                'notes': f'parse_error: {exc}',
                'accepted_next_target': '',
                'runtime_ms': runtime_ms,
            },
            trace_path=trace_path,
        )
        save_state(session_dir, updated_state)
        _append_text(progress_path, f'ingested_target={pending_target}\ningested_verdict=needs_more_context\nresponse_archive={archive_path}\n')
        _trace_event(
            trace_path,
            'ingest_parse_error',
            target=pending_target,
            rank=state.get('pending_rank'),
            fallback_verdict='needs_more_context',
            archive=str(archive_path),
            error=str(exc),
            reward=summary['immediate_reward'],
        )
        return {'target': pending_target, 'rank': state.get('pending_rank'), 'verdict': 'needs_more_context', 'next_target': ''}

    next_target = _normalize_target_reference(parsed['next_target']) if parsed['should_continue'] else ''
    current_attempts = _target_attempts(state, pending_target)
    if next_target and int(state.get('manual_followup_depth', 0)) >= MAX_MANUAL_FOLLOWUPS:
        _trace_event(trace_path, 'drop_next_target', pending_target=pending_target, proposed_next=next_target, reason='manual_followup_limit', depth=int(state.get('manual_followup_depth', 0)))
        next_target = ''
    if next_target and next_target == pending_target:
        _trace_event(trace_path, 'drop_next_target', pending_target=pending_target, proposed_next=next_target, reason='same_target')
        next_target = ''
    if next_target:
        next_attempts = _target_attempts(state, next_target)
        if next_attempts >= MAX_SAME_TARGET_ATTEMPTS:
            _trace_event(trace_path, 'drop_next_target', pending_target=pending_target, proposed_next=next_target, reason='same_target_attempt_limit', attempts=next_attempts)
            next_target = ''
    if parsed['verdict'] in {'needs_more_context', 'latent_bug'} and current_attempts >= MAX_SAME_TARGET_ATTEMPTS:
        _trace_event(trace_path, 'drop_next_target', pending_target=pending_target, proposed_next=next_target or parsed['next_target'], reason='stalling_attempt_limit', attempts=current_attempts, verdict=parsed['verdict'])
        next_target = ''
    updated_state = record_review(
        session_dir=session_dir,
        rank=state.get('pending_rank'),
        target=pending_target,
        verdict=parsed['verdict'],
        notes=parsed['notes'],
        next_target=next_target,
        next_prompt='',
        auto_advance=True,
    )
    summary = _record_bandit_outcome(
        updated_state,
        manifest,
        {
            'target': pending_target,
            'rank': state.get('pending_rank'),
            'verdict': parsed['verdict'],
            'notes': parsed['notes'],
            'accepted_next_target': next_target,
            'runtime_ms': runtime_ms,
        },
        trace_path=trace_path,
    )
    save_state(session_dir, updated_state)
    archive_path = _archive_response_file(session_dir, fixed_response)
    _append_text(progress_path, f"ingested_target={pending_target}\ningested_verdict={parsed['verdict']}\ningested_next_target={next_target}\nresponse_archive={archive_path}\n")
    _trace_event(
        trace_path,
        'ingest_result',
        target=pending_target,
        rank=state.get('pending_rank'),
        verdict=parsed['verdict'],
        proposed_next=parsed['next_target'],
        accepted_next=next_target,
        archive=str(archive_path),
        reward=summary['immediate_reward'],
    )
    if parsed['verdict'] in STRONG_FINDING_VERDICTS:
        finding_path = findings_dir / f"finding-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}.txt"
        finding_path.write_text(text, encoding='utf-8')
        _append_text(findings_path, f"\n== FINDING {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%SZ')} ==\ntarget={pending_target}\nverdict={parsed['verdict']}\ndetails={finding_path}\narchive={archive_path}\n")
        _trace_event(trace_path, 'finding_saved', target=pending_target, verdict=parsed['verdict'], finding=str(finding_path))
    return {'target': pending_target, 'rank': state.get('pending_rank'), 'verdict': parsed['verdict'], 'next_target': next_target}


def _classify_exec_failure(stderr_text: str, returncode: int) -> dict[str, str]:
    lowered = (stderr_text or '').lower()
    if returncode == 124 or 'timeout' in lowered:
        return {'kind': 'timeout', 'detail': 'process timed out before producing a response'}

    auth_patterns = [
        r'token expired',
        r'access token',
        r'credentials? expired',
        r'login required',
        r'not logged in',
        r'please run [`\']?codex login[`\']?',
        r'run [`\']?codex login[`\']?',
        r'authentication failed',
        r'authentication error',
        r'unauthorized',
        r'invalid credentials',
        r'api key expired',
        r'session expired',
    ]
    for pattern in auth_patterns:
        if re.search(pattern, lowered):
            detail = _first_nonempty_line(stderr_text) or 'codex authentication/token expired'
            return {'kind': 'auth_expired', 'detail': detail[:240]}

    detail = _first_nonempty_line(stderr_text) or f'codex exited with return code {returncode} before producing a response'
    return {'kind': 'exec_failed', 'detail': detail[:240]}


def _first_nonempty_line(text: str) -> str:
    for raw_line in (text or '').splitlines():
        line = raw_line.strip()
        if line:
            return line
    return ''


def _record_timeout_result(
    session_dir: Path,
    manifest: dict,
    rendered: dict,
    runtime_ms: int,
    progress_path: Path,
    *,
    trace_path: Path | None = None,
) -> dict:
    target = rendered['target']
    rank = rendered['rank']
    updated_state = record_review(
        session_dir=session_dir,
        rank=rank,
        target=target,
        verdict='timeout',
        notes='autopilot_timeout: codex exec exited without response',
        next_target='',
        next_prompt='',
        auto_advance=True,
    )
    summary = _record_bandit_outcome(
        updated_state,
        manifest,
        {
            'target': target,
            'rank': rank,
            'verdict': 'timeout',
            'notes': 'autopilot_timeout: codex exec exited without response',
            'accepted_next_target': '',
            'runtime_ms': runtime_ms,
        },
        trace_path=trace_path,
    )
    save_state(session_dir, updated_state)
    _append_text(progress_path, f'timeout_target={target}\ntimeout_runtime_ms={runtime_ms}\ntimeout_recovered=1\n')
    _trace_event(trace_path, 'timeout_recovered', target=target, rank=rank, runtime_ms=runtime_ms, reward=summary['immediate_reward'])
    return {'target': target, 'rank': rank, 'verdict': 'timeout', 'next_target': ''}


def _archive_response_file(session_dir: Path, fixed_response: Path) -> Path:
    archive_dir = response_archive_dir(session_dir)
    archive_dir.mkdir(parents=True, exist_ok=True)
    archive_path = archive_dir / f"response-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}.txt"
    fixed_response.replace(archive_path)
    return archive_path


def _render_next_prompt(session_dir: Path, *, include_snippet: bool, trace_path: Path | None = None) -> dict:
    manifest = _load_manifest(session_dir)
    state = load_state(session_dir)
    candidate_map = {item.get('path', ''): item for item in manifest.get('candidates', [])}

    resumed = _resume_pending_prompt(session_dir, manifest, state, candidate_map, include_snippet=include_snippet, trace_path=trace_path)
    if resumed is not None:
        return resumed

    manual_target = _normalize_target_reference(state.get('manual_next_target', ''))
    manual_prompt = (state.get('manual_next_prompt') or '').strip()
    depth = int(state.get('manual_followup_depth', 0))
    if manual_target and depth >= MAX_MANUAL_FOLLOWUPS:
        _trace_event(trace_path, 'clear_manual_target', target=manual_target, reason='manual_followup_limit', depth=depth)
        state['manual_next_target'] = ''
        state['manual_next_prompt'] = ''
        state['manual_followup_depth'] = 0
        save_state(session_dir, state)
        manual_target = ''
        manual_prompt = ''
    if manual_target:
        attempts = _target_attempts(state, manual_target)
        if attempts >= MAX_SAME_TARGET_ATTEMPTS:
            _trace_event(trace_path, 'clear_manual_target', target=manual_target, reason='same_target_attempt_limit', attempts=attempts)
            state['manual_next_target'] = ''
            state['manual_next_prompt'] = ''
            state['manual_followup_depth'] = 0
            save_state(session_dir, state)
            manual_target = ''
            manual_prompt = ''
    if manual_target:
        prompt_source = session_dir / 'review_state.json'
        prompt = _manual_followup_prompt(state, Path(manifest['repo_root']).expanduser().resolve(), manual_target, manual_prompt)
        set_pending_review(session_dir, None, manual_target, str(prompt_source))
        subsystem = _target_subsystem(manual_target, candidate_map)
        _trace_event(trace_path, 'select_manual_target', target=manual_target, prompt_source=str(prompt_source), depth=depth, subsystem=subsystem)
        return {
            'repo_root': manifest['repo_root'],
            'prompt': prompt,
            'prompt_source': prompt_source,
            'snippet_path': None,
            'include_snippet': False,
            'target': manual_target,
            'rank': None,
            'subsystem': subsystem,
        }

    rank, candidate, scoring = _next_pending_rank(session_dir, state, manifest, trace_path=trace_path)
    prompt_path, snippet_path = ensure_prompt_bundle(session_dir, manifest, rank)
    prompt = prompt_path.read_text(encoding='utf-8')
    set_pending_review(session_dir, rank, candidate['path'], str(prompt_path))
    _trace_event(
        trace_path,
        'select_ranked_target',
        target=candidate['path'],
        rank=rank,
        prompt_source=str(prompt_path),
        subsystem=scoring['subsystem'],
        total_score=round(scoring['total_score'], 6),
        base_score=round(scoring['base_score'], 6),
        subsystem_score=round(scoring['subsystem_score'], 6),
        target_score=round(scoring['target_score'], 6),
        retry_penalty=round(scoring['retry_penalty'], 6),
        timeout_penalty=round(scoring['timeout_penalty'], 6),
    )
    return {
        'repo_root': manifest['repo_root'],
        'prompt': prompt,
        'prompt_source': prompt_path,
        'snippet_path': snippet_path,
        'include_snippet': include_snippet,
        'target': candidate['path'],
        'rank': rank,
        'subsystem': scoring['subsystem'],
    }


def _resume_pending_prompt(
    session_dir: Path,
    manifest: dict,
    state: dict,
    candidate_map: dict[str, dict],
    *,
    include_snippet: bool,
    trace_path: Path | None = None,
) -> dict | None:
    pending_target = _normalize_target_reference(state.get('pending_target', ''))
    if not pending_target:
        return None
    pending_response = Path(state.get('pending_response_file') or response_path(session_dir))
    if _has_nonempty_response(pending_response):
        return None

    pending_rank = state.get('pending_rank')
    pending_source_text = (state.get('pending_prompt_source') or '').strip()
    prompt_source = Path(pending_source_text) if pending_source_text else None

    if pending_rank is None:
        manual_prompt = (state.get('manual_next_prompt') or '').strip()
        if prompt_source is None:
            prompt_source = session_dir / 'review_state.json'
        prompt = _manual_followup_prompt(state, Path(manifest['repo_root']).expanduser().resolve(), pending_target, manual_prompt)
        subsystem = _target_subsystem(pending_target, candidate_map)
        _trace_event(trace_path, 'resume_manual_target', target=pending_target, prompt_source=str(prompt_source), depth=int(state.get('manual_followup_depth', 0)), subsystem=subsystem)
        return {
            'repo_root': manifest['repo_root'],
            'prompt': prompt,
            'prompt_source': prompt_source,
            'snippet_path': None,
            'include_snippet': False,
            'target': pending_target,
            'rank': None,
            'subsystem': subsystem,
        }

    if prompt_source is None or not prompt_source.exists():
        prompt_source, snippet_path = ensure_prompt_bundle(session_dir, manifest, int(pending_rank))
    else:
        snippet_path = None
    prompt = prompt_source.read_text(encoding='utf-8')
    subsystem = _target_subsystem(pending_target, candidate_map)
    _trace_event(trace_path, 'resume_ranked_target', target=pending_target, rank=pending_rank, prompt_source=str(prompt_source), subsystem=subsystem)
    return {
        'repo_root': manifest['repo_root'],
        'prompt': prompt,
        'prompt_source': prompt_source,
        'snippet_path': snippet_path,
        'include_snippet': include_snippet,
        'target': pending_target,
        'rank': pending_rank,
        'subsystem': subsystem,
    }


def _build_autopilot_prompt(rendered: dict) -> str:
    parts = [rendered['prompt'].rstrip()]
    if rendered.get('include_snippet') and rendered.get('snippet_path') and Path(rendered['snippet_path']).exists():
        snippet = Path(rendered['snippet_path']).read_text(encoding='utf-8').rstrip()
        if snippet:
            parts.extend(['', 'Supplemental snippet from the harness:', snippet])
    parts.extend(
        [
            '',
            'Final response contract:',
            'Strict verdict:',
            '- one of: cve_candidate, plausible_security_bug, latent_bug, discarding, needs_more_context',
            '',
            'Single best next target:',
            '- output exactly ONE target only',
            '- format must be exactly `<file>` or `<file>::<symbol>`',
            '- do NOT list alternatives, siblings, multiple symbols, explanations, commas, `and`, `/`, or backticks',
            '- if several nearby symbols seem relevant, choose the single best one and mention the others only in Summary',
            '- use `none` if this branch should stop and the harness should move to the next ranked target',
            '',
            'Summary:',
            '- 3 to 8 short lines only',
            '- include exact entrypoint, attacker control, sensitive sink or invariant break, and impact reasoning',
        ]
    )
    return '\n'.join(parts) + '\n'


def _manual_followup_prompt(state: dict, repo_root: Path, manual_target: str, manual_prompt: str) -> str:
    history = state.get('history', [])
    previous = history[-1] if history else {}
    lines = [
        'Continue from the previous audit.',
        'Do not restart broad review.',
        '',
        f"Previous verdict: {previous.get('verdict', '')}",
        f"Previous target: {previous.get('target', '')}",
    ]
    notes = (previous.get('notes') or '').strip()
    if notes:
        lines.append(f'Previous notes: {notes}')
    lines.extend(['', f'Now focus only on: {manual_target}'])
    snippet = render_followup_snippet(repo_root, manual_target)
    if snippet:
        lines.extend(['', 'Target-local snippet:', snippet.rstrip()])
    if manual_prompt:
        lines.extend(['', manual_prompt.strip()])
    else:
        lines.extend(
            [
                '',
                'Requirements:',
                '1. Stay anchored to the target-local snippet first; only expand outward if needed to confirm reachability.',
                '2. Confirm the exact attacker-reachable path into this target.',
                '3. Validate concrete attacker control, trust-boundary crossing, and security impact.',
                '4. If nothing concrete exists, give a strict verdict and exactly one best next target.',
                '5. Output that target in `<file>` or `<file>::<symbol>` form only; do not list alternatives or multiple symbols.',
            ]
        )
    return '\n'.join(lines) + '\n'


def _next_pending_rank(session_dir: Path, state: dict, manifest: dict, *, trace_path: Path | None = None) -> tuple[int, dict, dict]:
    done = completed_ranks(state)
    candidates = manifest.get('candidates', [])
    candidate_map = {item.get('path', ''): item for item in candidates}
    max_raw_score = max((float(item.get('score', 0.0) or 0.0) for item in candidates), default=0.0)
    scored: list[tuple[float, int, dict, dict]] = []
    for rank, candidate in enumerate(candidates, start=1):
        if rank in done:
            _trace_event(trace_path, 'skip_candidate', rank=rank, reason='already_completed')
            continue
        target = candidate.get('path', '')
        if not _is_actionable_candidate(target):
            _trace_event(trace_path, 'skip_candidate', rank=rank, target=target, reason='not_actionable')
            continue
        attempts = _target_attempts(state, target)
        if attempts >= MAX_SAME_TARGET_ATTEMPTS:
            _trace_event(trace_path, 'skip_candidate', rank=rank, target=target, reason='same_target_attempt_limit', attempts=attempts)
            continue
        scoring = _score_candidate(state, candidate_map, candidate, rank, len(candidates), max_raw_score=max_raw_score)
        scoring['attempts'] = attempts
        scored.append((scoring['total_score'], rank, candidate, scoring))
    if not scored:
        raise SystemExit('all ranked targets in this session have already been reviewed')

    fixed_candidates = [item for item in scored if item[1] <= FIXED_PREFIX_RANKS]
    if fixed_candidates:
        fixed_candidates.sort(key=lambda item: item[1])
        state['dynamic_tail_shortlist'] = []
        save_state(session_dir, state)
        best_total, best_rank, best_candidate, best_scoring = fixed_candidates[0]
        top_candidates = ' | '.join(f"{rank}:{candidate.get('path', '')}" for _, rank, candidate, _ in fixed_candidates[:5])
        _trace_event(trace_path, 'candidate_ranking_fixed_prefix', selected_rank=best_rank, selected_target=best_candidate.get('path', ''), top_candidates=top_candidates)
        return best_rank, best_candidate, best_scoring

    scored.sort(key=lambda item: (-item[0], item[1]))
    shortlist = [int(value) for value in state.get('dynamic_tail_shortlist', []) if int(value or 0) > FIXED_PREFIX_RANKS]
    available_ranks = {rank for _, rank, _, _ in scored}
    shortlist = [rank for rank in shortlist if rank in available_ranks]
    eligible = [item for item in scored if item[1] in shortlist]
    if not eligible:
        shortlist = [rank for _, rank, _, _ in scored[:DYNAMIC_TAIL_SHORTLIST_SIZE]]
        state['dynamic_tail_shortlist'] = shortlist
        save_state(session_dir, state)
        eligible = [item for item in scored if item[1] in set(shortlist)]
        _trace_event(trace_path, 'dynamic_tail_shortlist_refresh', shortlist=' | '.join(str(rank) for rank in shortlist))
    eligible.sort(key=lambda item: (-item[0], item[1]))
    best_total, best_rank, best_candidate, best_scoring = eligible[0]
    top_candidates = ' | '.join(f"{rank}:{candidate.get('path', '')}@{total:.3f}" for total, rank, candidate, _ in eligible[:5])
    _trace_event(trace_path, 'candidate_ranking_dynamic_tail', selected_rank=best_rank, selected_target=best_candidate.get('path', ''), selected_score=round(best_total, 6), top_candidates=top_candidates, shortlist=' | '.join(str(rank) for rank in shortlist))
    return best_rank, best_candidate, best_scoring


def _score_candidate(
    state: dict,
    candidate_map: dict[str, dict],
    candidate: dict,
    rank: int,
    total_candidates: int,
    *,
    max_raw_score: float,
) -> dict:
    target = candidate.get('path', '')
    subsystem = _target_subsystem(target, candidate_map)
    base_score = _base_candidate_score(candidate, rank, total_candidates, max_raw_score=max_raw_score)
    subsystem_score = _subsystem_priority_score(state, subsystem)
    target_score = _target_priority_score(state, target)
    attempts = _target_attempts(state, target)
    retry_penalty = attempts * TARGET_RETRY_PENALTY
    timeout_penalty = _timeout_penalty(state, subsystem, target)
    total_score = base_score + subsystem_score + target_score - retry_penalty - timeout_penalty
    return {
        'target': target,
        'subsystem': subsystem,
        'base_score': base_score,
        'subsystem_score': subsystem_score,
        'target_score': target_score,
        'retry_penalty': retry_penalty,
        'timeout_penalty': timeout_penalty,
        'total_score': total_score,
    }


def _base_candidate_score(candidate: dict, rank: int, total_candidates: int, *, max_raw_score: float) -> float:
    raw_score = float(candidate.get('score', 0.0) or 0.0)
    normalized_raw = (raw_score / max_raw_score) if max_raw_score > 0 else 0.0
    rank_component = 1.0 - ((rank - 1) / max(1, total_candidates - 1))
    return 0.65 * rank_component + 0.35 * normalized_raw


def _subsystem_priority_score(state: dict, subsystem: str) -> float:
    if not subsystem:
        return 0.0
    bandit = _bandit_state(state)
    step = max(1, int(bandit.get('global_step', 0) or 0))
    stats = _decayed_stats(_bandit_bucket(state, 'subsystems').get(subsystem, {}), step)
    plays = max(0.0, float(stats.get('discounted_plays', 0.0) or 0.0))
    mean_reward = _safe_div(float(stats.get('discounted_reward', 0.0) or 0.0), plays)
    mean_cost = _safe_div(float(stats.get('discounted_cost', 0.0) or 0.0), plays)
    exploration = SUBSYSTEM_EXPLORATION_WEIGHT * math.sqrt(math.log(step + 2.0) / (plays + 1.0))
    floor_bonus = 0.75 if plays < EXPLORATION_FLOOR else 0.0
    timeout_drag = SUBSYSTEM_TIMEOUT_PENALTY * _safe_div(float(stats.get('timeout_count', 0) or 0), plays + 1.0)
    return mean_reward - (COST_WEIGHT * mean_cost) + exploration + floor_bonus - timeout_drag


def _target_priority_score(state: dict, target: str) -> float:
    if not target:
        return 0.0
    bandit = _bandit_state(state)
    step = max(1, int(bandit.get('global_step', 0) or 0))
    stats = _decayed_stats(_bandit_bucket(state, 'targets').get(target, {}), step)
    plays = max(0.0, float(stats.get('discounted_plays', 0.0) or 0.0))
    mean_reward = _safe_div(float(stats.get('discounted_reward', 0.0) or 0.0), plays)
    exploration = TARGET_EXPLORATION_WEIGHT * math.sqrt(math.log(step + 2.0) / (plays + 1.0))
    return mean_reward + exploration


def _timeout_penalty(state: dict, subsystem: str, target: str) -> float:
    bandit = _bandit_state(state)
    step = max(1, int(bandit.get('global_step', 0) or 0))
    target_stats = _decayed_stats(_bandit_bucket(state, 'targets').get(target, {}), step)
    subsystem_stats = _decayed_stats(_bandit_bucket(state, 'subsystems').get(subsystem, {}), step)
    exact_penalty = TARGET_TIMEOUT_PENALTY * _safe_div(float(target_stats.get('timeout_count', 0) or 0), float(target_stats.get('discounted_plays', 0.0) or 0.0) + 1.0)
    subsystem_penalty = SUBSYSTEM_TIMEOUT_PENALTY * _safe_div(float(subsystem_stats.get('timeout_count', 0) or 0), float(subsystem_stats.get('discounted_plays', 0.0) or 0.0) + 1.0)
    return exact_penalty + subsystem_penalty


def _record_bandit_outcome(state: dict, manifest: dict, outcome: dict, *, trace_path: Path | None = None) -> dict:
    bandit = _bandit_state(state)
    bandit['global_step'] = int(bandit.get('global_step', 0) or 0) + 1
    step = bandit['global_step']
    target = str(outcome.get('target', '') or '').strip()
    verdict = str(outcome.get('verdict', '') or '').strip()
    notes = str(outcome.get('notes', '') or '')
    accepted_next_target = str(outcome.get('accepted_next_target', '') or '').strip()
    runtime_ms = int(outcome.get('runtime_ms', 0) or 0)
    candidate_map = {item.get('path', ''): item for item in manifest.get('candidates', [])}
    immediate_reward = _immediate_reward(verdict, notes=notes, accepted_next_target=accepted_next_target, runtime_ms=runtime_ms)
    credits = [(target, 1.0)]
    for depth, upstream in enumerate(_upstream_credit_targets(state), start=1):
        credits.append((upstream, CREDIT_DECAY ** depth))
    for index, (credited_target, factor) in enumerate(credits):
        subsystem = _target_subsystem(credited_target, candidate_map)
        _update_bandit_stats(
            _bandit_bucket(state, 'targets'),
            credited_target,
            step=step,
            reward_delta=immediate_reward * factor,
            cost_delta=_runtime_cost(runtime_ms) if index == 0 else 0.0,
            play_delta=1.0 if index == 0 else 0.0,
            timeout_delta=1 if verdict == 'timeout' and index == 0 else 0,
        )
        if subsystem:
            _update_bandit_stats(
                _bandit_bucket(state, 'subsystems'),
                subsystem,
                step=step,
                reward_delta=immediate_reward * factor,
                cost_delta=_runtime_cost(runtime_ms) if index == 0 else 0.0,
                play_delta=1.0 if index == 0 else 0.0,
                timeout_delta=1 if verdict == 'timeout' and index == 0 else 0,
            )
        _trace_event(trace_path, 'reward_update', target=credited_target, subsystem=subsystem, verdict=verdict, reward=round(immediate_reward * factor, 6), factor=round(factor, 6), play_delta=(1.0 if index == 0 else 0.0), timeout_delta=(1 if verdict == 'timeout' and index == 0 else 0))
    state['bandit'] = bandit
    return {'step': step, 'immediate_reward': immediate_reward, 'credit_targets': credits}


def _immediate_reward(verdict: str, *, notes: str, accepted_next_target: str, runtime_ms: int) -> float:
    if notes.startswith('parse_error:'):
        base = PARSE_ERROR_REWARD
    elif verdict == 'needs_more_context' and accepted_next_target:
        base = 0.10
    else:
        base = VERDICT_REWARDS.get(verdict, -0.10)
    return base - _runtime_cost(runtime_ms)


def _runtime_cost(runtime_ms: int) -> float:
    if runtime_ms <= 0:
        return 0.0
    runtime_minutes = max(0.0, runtime_ms / 60000.0)
    return 0.05 * math.log1p(runtime_minutes)


def _upstream_credit_targets(state: dict) -> list[str]:
    history = state.get('history', [])
    if len(history) < 2:
        return []
    credits: list[str] = []
    downstream_target = str(history[-1].get('target', '') or '').strip()
    for item in reversed(history[:-1]):
        next_target = str(item.get('next_target', '') or '').strip()
        target = str(item.get('target', '') or '').strip()
        if not target or next_target != downstream_target:
            break
        credits.append(target)
        downstream_target = target
        if len(credits) >= MAX_CREDIT_DEPTH:
            break
        if item.get('rank') is not None:
            break
    return credits


def _bandit_state(state: dict) -> dict:
    bandit = state.setdefault('bandit', {'global_step': 0, 'subsystems': {}, 'targets': {}})
    bandit.setdefault('global_step', 0)
    bandit.setdefault('subsystems', {})
    bandit.setdefault('targets', {})
    return bandit


def _bandit_bucket(state: dict, bucket_name: str) -> dict[str, dict]:
    bandit = _bandit_state(state)
    return bandit.setdefault(bucket_name, {})


def _update_bandit_stats(
    bucket: dict[str, dict],
    key: str,
    *,
    step: int,
    reward_delta: float,
    cost_delta: float,
    play_delta: float,
    timeout_delta: int,
) -> None:
    if not key:
        return
    stats = _decayed_stats(bucket.get(key, {}), step)
    stats['plays'] = int(stats.get('plays', 0) or 0) + int(play_delta)
    stats['discounted_plays'] = float(stats.get('discounted_plays', 0.0) or 0.0) + play_delta
    stats['discounted_reward'] = float(stats.get('discounted_reward', 0.0) or 0.0) + reward_delta
    stats['discounted_cost'] = float(stats.get('discounted_cost', 0.0) or 0.0) + cost_delta
    stats['timeout_count'] = int(stats.get('timeout_count', 0) or 0) + int(timeout_delta)
    stats['last_step'] = step
    bucket[key] = stats


def _decayed_stats(stats: dict | None, current_step: int) -> dict:
    current = {
        'plays': int((stats or {}).get('plays', 0) or 0),
        'discounted_plays': float((stats or {}).get('discounted_plays', 0.0) or 0.0),
        'discounted_reward': float((stats or {}).get('discounted_reward', 0.0) or 0.0),
        'discounted_cost': float((stats or {}).get('discounted_cost', 0.0) or 0.0),
        'timeout_count': int((stats or {}).get('timeout_count', 0) or 0),
        'last_step': int((stats or {}).get('last_step', 0) or 0),
    }
    last_step = current['last_step']
    if current_step <= 0 or last_step <= 0 or current_step <= last_step:
        current['last_step'] = max(last_step, current_step)
        return current
    factor = 0.5 ** ((current_step - last_step) / BANDIT_HALF_LIFE_STEPS)
    current['discounted_plays'] *= factor
    current['discounted_reward'] *= factor
    current['discounted_cost'] *= factor
    current['last_step'] = current_step
    return current


def _set_pending_execution_metadata(session_dir: Path, *, target: str, subsystem: str, runtime_ms: int) -> None:
    state = load_state(session_dir)
    if state.get('pending_target') != target:
        return
    state['pending_subsystem'] = subsystem
    state['pending_runtime_ms'] = int(runtime_ms or 0)
    save_state(session_dir, state)


def _target_subsystem(target: str, candidate_map: dict[str, dict]) -> str:
    if not target:
        return ''
    if target in candidate_map:
        candidate_subsystem = str(candidate_map[target].get('subsystem', '') or '').strip()
        if candidate_subsystem and candidate_subsystem not in {'packages', 'src', 'crates'}:
            return candidate_subsystem
    path = _target_source_path(target)
    if not path:
        return ''
    parts = [part for part in path.split('/') if part]
    if not parts:
        return ''
    if parts[0] == 'packages' and len(parts) >= 4 and parts[2] == 'src':
        return '/'.join(parts[:4])
    if parts[0] == 'packages' and len(parts) >= 2:
        return '/'.join(parts[:2])
    if parts[0] == 'src' and len(parts) >= 3:
        return '/'.join(parts[:3])
    if parts[0] == 'crates' and len(parts) >= 3:
        return '/'.join(parts[:3])
    return '/'.join(parts[: min(3, len(parts))])


def _target_source_path(target: str) -> str:
    text = target.strip().strip('`')
    if not text:
        return ''
    text = text.split('::', 1)[0].strip()
    text = text.split(' / ', 1)[0].strip()
    if ' ' in text and '/' in text:
        text = text.split(' ', 1)[0].strip()
    return text


def _normalize_target_reference(target: str) -> str:
    text = str(target or '').strip()
    if not text:
        return ''
    lowered = text.lower().strip('` ')
    if lowered in {'none', 'n/a', 'na', '(none)'}:
        return ''
    for line in text.splitlines():
        candidate = line.strip()
        if candidate:
            text = candidate
            break
    text = text.strip().lstrip('-').strip().strip('`').strip()
    if ':' in text and text.lower().startswith('single best next target'):
        text = text.split(':', 1)[1].strip()
    text = text.replace('` / `', '::')
    text = re.sub(r'`\s*/\s*`', '::', text)
    text = re.sub(r'\s*::\s*', '::', text)
    text = re.sub(r'\s+', ' ', text).strip()
    if '/' in text and '::' not in text:
        left, right = text.rsplit('/', 1)
        if '.' in left.rsplit('/', 1)[-1] and right and '/' not in right and ' ' not in right:
            text = f'{left}::{right}'
    match = re.match(r'^(.*\.[A-Za-z0-9_+-]+):([A-Za-z_][A-Za-z0-9_.$-]*)$', text)
    if match:
        text = f"{match.group(1)}::{match.group(2)}"
    return text.strip().strip('`')


def _target_attempts(state: dict, target: str) -> int:
    if not target:
        return 0
    return sum(1 for item in state.get('history', []) if str(item.get('target', '')).strip() == target)


def _is_actionable_candidate(path: str) -> bool:
    lowered = path.lower()
    if lowered.startswith(('docs/', 'examples/', 'samples/', 'vendor/', 'third_party/')):
        return False
    if '/test/' in lowered or '/tests/' in lowered or '/spec/' in lowered or '/specs/' in lowered:
        return False
    if lowered.endswith(('_test.go', '.spec.js', '.test.js', '.spec.ts', '.test.ts')):
        return False
    return True


def _bundle_paths(session_dir: Path, rank: int, rel_path: str) -> tuple[Path, Path]:
    bundle_dir = session_dir / 'bundles'
    prefix = f"{rank:02d}-{rel_path.replace('/', '__')}"
    return bundle_dir / f'{prefix}.md', bundle_dir / f'{prefix}.snippet.txt'


def _load_manifest(session_dir: Path) -> dict:
    manifest_path = session_dir / 'targets.json'
    if not manifest_path.exists():
        raise SystemExit(f'missing session manifest: {manifest_path}')
    return json.loads(manifest_path.read_text(encoding='utf-8'))


def _existing_run_count(prompts_dir: Path) -> int:
    return len(list(prompts_dir.glob('run-*.prompt.txt')))


def _append_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as handle:
        handle.write(text)


def _write_bandit_artifacts(session_dir: Path) -> None:
    autopilot_dir = session_dir / AUTOPILOT_DIRNAME
    autopilot_dir.mkdir(parents=True, exist_ok=True)
    state = load_state(session_dir)
    bandit = _bandit_state(state)
    (autopilot_dir / 'BANDIT_STATE.json').write_text(json.dumps(bandit, indent=2), encoding='utf-8')
    subsystem_lines = []
    step = max(1, int(bandit.get('global_step', 0) or 0))
    subsystem_bucket = _bandit_bucket(state, 'subsystems')
    ranked_subsystems = []
    for subsystem in subsystem_bucket:
        score = _subsystem_priority_score(state, subsystem)
        stats = _decayed_stats(subsystem_bucket.get(subsystem, {}), step)
        ranked_subsystems.append((score, subsystem, stats))
    ranked_subsystems.sort(key=lambda item: (-item[0], item[1]))
    for score, subsystem, stats in ranked_subsystems[:12]:
        subsystem_lines.append(f"- `{subsystem}` score={score:.3f} plays={stats['plays']} discounted_plays={stats['discounted_plays']:.2f} discounted_reward={stats['discounted_reward']:.3f} timeout_count={stats['timeout_count']}")
    summary = ['# Bandit Summary', '', f"global_step={bandit.get('global_step', 0)}", '', '## Top Subsystems']
    if subsystem_lines:
        summary.extend(subsystem_lines)
    else:
        summary.append('- none yet')
    (autopilot_dir / 'BANDIT_SUMMARY.md').write_text('\n'.join(summary) + '\n', encoding='utf-8')


def _write_watchdog_snapshot(
    path: Path,
    *,
    pid: int,
    target: str,
    rank: int | None,
    elapsed_seconds: int,
    response_file: Path,
    stdout_path: Path,
    stderr_path: Path,
    timed_out: bool,
) -> None:
    lines = [
        '',
        f"== WATCHDOG {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%SZ')} ==",
        f'target={target}',
        f'rank={rank}',
        f'pid={pid}',
        f'elapsed_seconds={elapsed_seconds}',
        f'timed_out={int(timed_out)}',
        f'response_exists={int(response_file.exists())}',
        f'response_size={_file_size(response_file)}',
        f'stdout_size={_file_size(stdout_path)}',
        f'stderr_size={_file_size(stderr_path)}',
    ]
    process_snapshot = _process_snapshot(pid)
    if process_snapshot:
        lines.append('ps_snapshot:')
        lines.extend(process_snapshot)
    for label, file_path in [('response_tail', response_file), ('stdout_tail', stdout_path), ('stderr_tail', stderr_path)]:
        tail_text = _tail_text(file_path)
        if tail_text:
            lines.append(f'{label}:')
            lines.extend(tail_text.splitlines())
    _append_text(path, '\n'.join(lines) + '\n')


def _stream_pipe_to_file(stream, path: Path) -> None:
    if stream is None:
        return
    try:
        with path.open('a', encoding='utf-8') as handle:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    break
                handle.write(chunk)
                handle.flush()
    finally:
        try:
            stream.close()
        except Exception:
            pass


def _read_text_file(path: Path) -> str:
    try:
        return path.read_text(encoding='utf-8')
    except OSError:
        return ''


def _tail_text(path: Path, max_chars: int = 4000) -> str:
    text = _read_text_file(path)
    if len(text) <= max_chars:
        return text.strip()
    return text[-max_chars:].strip()


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return -1


def _process_snapshot(pid: int) -> list[str]:
    lines: list[str] = []
    commands = [
        ['ps', '-o', 'pid=,ppid=,etime=,%cpu=,%mem=,state=,command=', '-p', str(pid)],
        ['ps', '-o', 'pid=,ppid=,etime=,%cpu=,%mem=,state=,command=', '--ppid', str(pid)],
    ]
    for cmd in commands:
        try:
            proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
        except OSError:
            continue
        process_text = (proc.stdout or '').strip()
        if not process_text:
            continue
        lines.extend(process_text.splitlines())
    return lines


def _trace_event(path: Path | None, event: str, **fields: object) -> None:
    if path is None:
        return
    timestamp = datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    parts = [timestamp, event]
    for key, value in fields.items():
        if value in {None, ''}:
            continue
        text = str(value).replace('\t', ' ').replace('\n', ' ')
        parts.append(f'{key}={text}')
    _append_text(path, '\t'.join(parts) + '\n')


def _duration_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))


def _write_status(path: Path, **fields: object) -> None:
    path.write_text('\n'.join(f"{key}={value}" for key, value in fields.items() if value not in {None, ''}) + '\n', encoding='utf-8')


def _parse_duration(spec: str) -> int:
    spec = spec.strip().lower()
    units = {'s': 1, 'm': 60, 'h': 3600}
    if spec[-1] in units:
        return max(1, int(float(spec[:-1]) * units[spec[-1]]))
    return max(1, int(float(spec)))


def _has_nonempty_response(path: Path) -> bool:
    return path.exists() and path.stat().st_size > 0


def _safe_div(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0
    return numerator / denominator
