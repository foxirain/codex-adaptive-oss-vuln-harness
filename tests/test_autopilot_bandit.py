import json
import tempfile
import unittest
from pathlib import Path

from oss_harness.autopilot import (
    _classify_exec_failure,
    _next_pending_rank,
    _record_bandit_outcome,
    _render_next_prompt,
    _register_pending_failure,
    _subsystem_priority_score,
    _target_subsystem,
)
from oss_harness.session import load_state, record_review, save_state


class AutopilotBanditTests(unittest.TestCase):
    def test_target_subsystem_uses_deeper_packages_path(self) -> None:
        subsystem = _target_subsystem('packages/gui/src/electron/CacheManager.ts::prepareProtocol', {})
        self.assertEqual(subsystem, 'packages/gui/src/electron')

    def test_target_subsystem_never_uses_root_filename_as_bucket(self) -> None:
        self.assertEqual(_target_subsystem('Makefile', {}), '<root>')
        self.assertEqual(_target_subsystem('main.py', {}), '<root>')

    def test_strong_reward_can_outweigh_base_rank(self) -> None:
        manifest = {
            'candidates': [
                {'path': 'src/api/request.ts', 'score': 10.0},
                {'path': 'packages/gui/src/electron/ProtocolBridge.ts', 'score': 9.5},
            ]
        }
        state = {'history': [], 'bandit': {'global_step': 0, 'subsystems': {}, 'targets': {}}}
        for _ in range(3):
            state['history'].append({'rank': 9, 'target': 'src/api/old.ts', 'verdict': 'discarding', 'notes': '', 'next_target': '', 'next_prompt': ''})
            _record_bandit_outcome(
                state,
                manifest,
                {
                    'target': 'src/api/old.ts',
                    'rank': 9,
                    'verdict': 'discarding',
                    'notes': '',
                    'accepted_next_target': '',
                    'runtime_ms': 60_000,
                },
            )
        for _ in range(3):
            state['history'].append({'rank': 8, 'target': 'packages/gui/src/electron/CacheManager.ts', 'verdict': 'plausible_security_bug', 'notes': '', 'next_target': '', 'next_prompt': ''})
            _record_bandit_outcome(
                state,
                manifest,
                {
                    'target': 'packages/gui/src/electron/CacheManager.ts',
                    'rank': 8,
                    'verdict': 'plausible_security_bug',
                    'notes': '',
                    'accepted_next_target': '',
                    'runtime_ms': 60_000,
                },
            )
        gui_score = _subsystem_priority_score(state, 'packages/gui/src/electron')
        api_score = _subsystem_priority_score(state, 'src/api')
        self.assertGreater(gui_score, api_score)

    def test_timeout_penalty_pushes_target_down(self) -> None:
        manifest = {
            'candidates': [
                {'path': 'packages/gui/src/electron/slow.ts', 'score': 10.0},
                {'path': 'packages/gui/src/electron/fast.ts', 'score': 9.5},
            ]
        }
        state = {'history': [], 'bandit': {'global_step': 0, 'subsystems': {}, 'targets': {}}, 'dynamic_tail_shortlist': []}
        state['history'].append({'rank': 1, 'target': 'packages/gui/src/electron/slow.ts', 'verdict': 'timeout', 'notes': '', 'next_target': '', 'next_prompt': ''})
        _record_bandit_outcome(
            state,
            manifest,
            {
                'target': 'packages/gui/src/electron/slow.ts',
                'rank': 1,
                'verdict': 'timeout',
                'notes': '',
                'accepted_next_target': '',
                'runtime_ms': 120_000,
            },
        )
        with tempfile.TemporaryDirectory() as tmp:
            session_dir = Path(tmp)
            rank, candidate, _ = _next_pending_rank(session_dir, state, manifest)
        self.assertEqual(rank, 2)
        self.assertEqual(candidate['path'], 'packages/gui/src/electron/fast.ts')

    def test_fixed_prefix_is_taken_before_dynamic_tail(self) -> None:
        manifest = {
            'candidates': [
                {'path': 'src/one.ts', 'score': 1.0},
                {'path': 'src/two.ts', 'score': 0.9},
                {'path': 'src/late.ts', 'score': 50.0},
            ]
        }
        state = {'history': [], 'bandit': {'global_step': 0, 'subsystems': {}, 'targets': {}}, 'dynamic_tail_shortlist': []}
        with tempfile.TemporaryDirectory() as tmp:
            session_dir = Path(tmp)
            rank, candidate, _ = _next_pending_rank(session_dir, state, manifest)
        self.assertEqual(rank, 1)
        self.assertEqual(candidate['path'], 'src/one.ts')

    def test_classify_exec_failure_detects_auth_expiry(self) -> None:
        failure = _classify_exec_failure('Error: Login required. Please run codex login again.', 1)
        self.assertEqual(failure['kind'], 'auth_expired')

    def test_render_next_prompt_resumes_pending_ranked_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session_dir = Path(tmp)
            repo_root = session_dir / 'repo'
            repo_root.mkdir()
            prompt_path = session_dir / 'bundles' / '01-src__one.ts.md'
            prompt_path.parent.mkdir(parents=True, exist_ok=True)
            prompt_path.write_text('prompt body', encoding='utf-8')
            (session_dir / 'targets.json').write_text(
                json.dumps(
                    {
                        'repo_root': str(repo_root),
                        'candidate_count': 1,
                        'candidates': [
                            {'path': 'src/one.ts', 'score': 1.0},
                        ],
                    }
                ),
                encoding='utf-8',
            )
            save_state(
                session_dir,
                {
                    'current_rank': 1,
                    'history': [],
                    'pending_rank': 1,
                    'pending_target': 'src/one.ts',
                    'pending_prompt_source': str(prompt_path),
                    'pending_response_file': str(session_dir / 'codex_response.txt'),
                    'bandit': {'global_step': 0, 'subsystems': {}, 'targets': {}},
                },
            )
            rendered = _render_next_prompt(session_dir, include_snippet=True)

        self.assertEqual(rendered['rank'], 1)
        self.assertEqual(rendered['target'], 'src/one.ts')
        self.assertEqual(rendered['prompt'], 'prompt body')


class SessionBanditStateTests(unittest.TestCase):
    def test_success_after_two_operational_failures_clears_retry_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_dir = Path(tmpdir)
            save_state(
                session_dir,
                {
                    'current_rank': 1,
                    'history': [],
                    'pending_rank': 1,
                    'pending_target': 'src/a.py',
                    'bandit': {'global_step': 0, 'subsystems': {}, 'targets': {}},
                },
            )
            _register_pending_failure(session_dir, 'timeout', 'timed out')
            _register_pending_failure(session_dir, 'parse_error', 'invalid response')
            record_review(
                session_dir,
                rank=1,
                target='src/a.py',
                verdict='discarding',
                notes='valid response',
                next_target='',
                next_prompt='',
                auto_advance=True,
            )
            state = load_state(session_dir)

        self.assertEqual(len(state['history']), 1)
        self.assertEqual(state['history'][0]['verdict'], 'discarding')
        self.assertEqual(state['pending_retry_count'], 0)
        self.assertEqual(state['pending_failures'], [])
        self.assertEqual(state['bandit']['global_step'], 0)

    def test_operational_retries_do_not_complete_or_reward_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_dir = Path(tmpdir)
            save_state(
                session_dir,
                {
                    'current_rank': 1,
                    'history': [],
                    'pending_rank': 1,
                    'pending_target': 'src/a.py',
                    'bandit': {'global_step': 0, 'subsystems': {}, 'targets': {}},
                },
            )
            first = _register_pending_failure(session_dir, 'timeout', 'timed out')
            second = _register_pending_failure(session_dir, 'parse_error', 'invalid response')
            third = _register_pending_failure(session_dir, 'timeout', 'timed out again')
            state = load_state(session_dir)

        self.assertFalse(first['retry_exhausted'])
        self.assertFalse(second['retry_exhausted'])
        self.assertTrue(third['retry_exhausted'])
        self.assertEqual(state['history'], [])
        self.assertEqual(state['bandit']['global_step'], 0)
        self.assertEqual(state['pending_target'], 'src/a.py')
    def test_session_state_preserves_bandit_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            session_dir = Path(tmpdir)
            save_state(
                session_dir,
                {
                    'current_rank': 3,
                    'history': [],
                    'bandit': {
                        'global_step': 7,
                        'subsystems': {
                            'packages/gui/src/electron': {
                                'plays': 2,
                                'discounted_plays': 1.5,
                                'discounted_reward': 0.4,
                                'discounted_cost': 0.1,
                                'timeout_count': 1,
                                'last_step': 7,
                            }
                        },
                        'targets': {},
                    },
                },
            )
            state = load_state(session_dir)
            self.assertEqual(state['bandit']['global_step'], 7)
            self.assertEqual(state['bandit']['subsystems']['packages/gui/src/electron']['plays'], 2)
            self.assertEqual(state['bandit']['subsystems']['packages/gui/src/electron']['timeout_count'], 1)


if __name__ == '__main__':
    unittest.main()
