import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from oss_harness.autopilot import _run_codex_exec as run_autopilot_codex_exec
from oss_harness.executor import run_codex_exec


class CodexExecArgsTests(unittest.TestCase):
    def test_executor_passes_model_and_reasoning_effort(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch('oss_harness.executor.subprocess.run') as mocked_run:
                mocked_run.return_value = subprocess.CompletedProcess([], 0, stdout='', stderr='')
                run_codex_exec(
                    repo_root=root,
                    prompt_text='prompt',
                    response_file=root / 'response.txt',
                    stdout_file=root / 'stdout.txt',
                    stderr_file=root / 'stderr.txt',
                    timeout_seconds=1,
                    model='gpt-5.5',
                    reasoning_effort='xhigh',
                    sandbox='workspace-write',
                    full_auto=True,
                    unsafe_bypass=False,
                )

            cmd = mocked_run.call_args.args[0]
            self.assertNotIn('--add-dir', cmd)
            self.assertEqual(mocked_run.call_args.kwargs['cwd'], str(root))
            self.assertIn('--full-auto', cmd)
            self.assertIn('-m', cmd)
            self.assertEqual(cmd[cmd.index('-m') + 1], 'gpt-5.5')
            self.assertIn('-c', cmd)
            self.assertEqual(cmd[cmd.index('-c') + 1], 'model_reasoning_effort="xhigh"')

    def test_autopilot_passes_model_and_reasoning_effort(self) -> None:
        class FakeProcess:
            pid = 12345

            def __init__(self) -> None:
                self.stdin = io.StringIO()
                self.stdout = io.StringIO('')
                self.stderr = io.StringIO('')

            def poll(self) -> int:
                return 0

            def kill(self) -> None:
                raise AssertionError('unexpected kill')

            def wait(self) -> int:
                return 0

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch('oss_harness.autopilot.subprocess.Popen') as mocked_popen:
                mocked_popen.return_value = FakeProcess()
                run_autopilot_codex_exec(
                    repo_root=str(root),
                    prompt_text='prompt',
                    response_file=root / 'response.txt',
                    stdout_path=root / 'stdout.txt',
                    stderr_path=root / 'stderr.txt',
                    timeout_seconds=1,
                    model='gpt-5.5',
                    reasoning_effort='xhigh',
                    sandbox='workspace-write',
                    full_auto=True,
                    unsafe_bypass=False,
                    watchdog_path=root / 'watchdog.txt',
                    watchdog_target='target',
                    watchdog_rank=1,
                )

            cmd = mocked_popen.call_args.args[0]
            self.assertNotIn('--add-dir', cmd)
            self.assertEqual(mocked_popen.call_args.kwargs['cwd'], str(root))
            self.assertIn('-m', cmd)
            self.assertEqual(cmd[cmd.index('-m') + 1], 'gpt-5.5')
            self.assertIn('-c', cmd)
            self.assertEqual(cmd[cmd.index('-c') + 1], 'model_reasoning_effort="xhigh"')

    def test_executor_truncates_stale_response_before_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            response = root / 'response.txt'
            response.write_text('stale response', encoding='utf-8')
            with patch('oss_harness.executor.subprocess.run') as mocked_run:
                mocked_run.return_value = subprocess.CompletedProcess([], 1, stdout='', stderr='failed')
                result = run_codex_exec(
                    repo_root=root,
                    prompt_text='prompt',
                    response_file=response,
                    stdout_file=root / 'stdout.txt',
                    stderr_file=root / 'stderr.txt',
                    timeout_seconds=1,
                    model='',
                    reasoning_effort='',
                    sandbox='read-only',
                    full_auto=False,
                    unsafe_bypass=False,
                )

            self.assertEqual(result.returncode, 1)
            self.assertEqual(response.read_text(encoding='utf-8'), '')
            cmd = mocked_run.call_args.args[0]
            self.assertNotIn('--full-auto', cmd)
            self.assertEqual(cmd[cmd.index('--sandbox') + 1], 'read-only')

    def test_full_auto_cannot_be_combined_with_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(ValueError, 'cannot be combined'):
                run_codex_exec(
                    repo_root=root,
                    prompt_text='prompt',
                    response_file=root / 'response.txt',
                    stdout_file=root / 'stdout.txt',
                    stderr_file=root / 'stderr.txt',
                    timeout_seconds=1,
                    model='',
                    reasoning_effort='',
                    sandbox='read-only',
                    full_auto=True,
                    unsafe_bypass=False,
                )


if __name__ == '__main__':
    unittest.main()
